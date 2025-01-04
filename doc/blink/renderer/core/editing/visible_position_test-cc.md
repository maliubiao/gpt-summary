Response:
Let's break down the thought process for analyzing the `visible_position_test.cc` file.

1. **Understand the Purpose:** The file name itself, `visible_position_test.cc`, strongly suggests it's a test file for a class or functionality related to "visible positions."  The location within the Chromium Blink engine (`blink/renderer/core/editing`) further hints that this is related to text editing and how the engine represents the user's cursor position or selection within editable content.

2. **Identify the Tested Class:** The `#include` statements at the top of the file are crucial. The primary include is `"third_party/blink/renderer/core/editing/visible_position.h"`. This immediately tells us that the core functionality being tested is within the `VisiblePosition` class.

3. **Analyze the Test Structure:**  The file uses the Google Test framework (`TEST_F`). Each `TEST_F` block represents a specific test case for the `VisiblePosition` class. The `VisiblePositionTest` class inherits from `EditingTestBase`, which provides a setup for creating and manipulating DOM content within a controlled testing environment.

4. **Examine Individual Test Cases:**  Go through each `TEST_F` and try to understand what aspect of `VisiblePosition` is being tested. Look for the following:

    * **Setup:** How is the DOM structure being created (`SetBodyContent`)? What are the key elements or nodes involved?
    * **Input:** What `Position` objects are being created and passed to `CreateVisiblePosition`? `Position` represents a specific point within the DOM tree. Pay attention to the different ways `Position` objects are created (e.g., `Position(target, 0)`, `Position::FirstPositionInNode(target)`, `Position::BeforeNode(br)`).
    * **Expected Output:** What is the expected `DeepEquivalent()` of the `VisiblePosition`? This method likely returns a normalized or canonical `Position` that represents the same visible location.
    * **Assertions:**  The `EXPECT_EQ` macros are the core of the tests. They compare the actual result of `CreateVisiblePosition(...).DeepEquivalent()` with the expected `Position`.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**  As you analyze the test cases, think about how these scenarios manifest in a real web page:

    * **`contenteditable`:**  Several tests use `<div contenteditable>`. This immediately connects to HTML's ability to make elements editable by the user.
    * **Empty Elements:** Tests with empty `<div>` and `<span>` elements relate to how the cursor behaves when there's no text content.
    * **`<br>`:** The `<br>` element for line breaks is a common HTML element. The tests involving `<br>` show how `VisiblePosition` handles forced line breaks.
    * **Spaces and Line Breaks:** Tests with spaces around line breaks demonstrate how whitespace is handled in terms of cursor positioning.
    * **CSS Styling:** The `NormalizationAroundLineBreak` and `SpacesAroundLineBreak` tests, and especially the tests with `DCHECK_IS_ON()`, involve applying CSS styles (width, font, word-wrap, color, display). This shows how styling impacts the calculation of visible positions.
    * **JavaScript Interaction (Implicit):** While the test file itself is C++, the scenarios being tested are directly relevant to how JavaScript interacts with the DOM for editing purposes. For example, when a user clicks in an editable area, JavaScript uses underlying mechanisms like `VisiblePosition` to determine the precise insertion point.

6. **Identify Logic and Assumptions:**

    * **Normalization:** The core logic being tested is the normalization of `Position` objects to their "visible" equivalent. This involves handling cases where the raw DOM `Position` might not directly correspond to a user-perceived cursor location (e.g., positions within empty elements, around `<br>` tags).
    * **Assumptions:** The tests implicitly assume that `DeepEquivalent()` correctly implements the logic for finding the canonical visible position. They also assume the underlying rendering engine and layout algorithms are working correctly.

7. **Consider User and Programming Errors:**

    * **User Errors:**  While not directly testing error *handling*, the tests reveal potential edge cases where a user might expect the cursor to be in a certain place, but the underlying DOM structure might lead to a different interpretation. For example, the behavior within empty editable elements or around `<br>` tags might not be immediately obvious to a user.
    * **Programming Errors:**  A common programming error would be to manipulate the DOM without considering how it affects existing `VisiblePosition` objects. The `NonNullInvalidatedAfterDOMChange` and `NonNullInvalidatedAfterStyleChange` tests highlight the importance of invalidating `VisiblePosition` when the DOM or styling changes.

8. **Trace User Actions:** Think about how a user's actions in a browser might lead to the code being tested:

    * **Clicking in Editable Areas:**  The most direct way to interact with the functionality being tested is by clicking within a `contenteditable` element. This sets the document's selection, which relies on `VisiblePosition`.
    * **Moving the Caret:** Using the arrow keys or other navigation methods within editable content will trigger calculations involving `VisiblePosition`.
    * **Inserting or Deleting Content:**  Any modification to the DOM within an editable region will involve updating and potentially invalidating `VisiblePosition` objects.
    * **Applying Styles:** Changing CSS styles, especially those affecting layout (like `display`, `width`, `word-wrap`), can also trigger recalculations related to `VisiblePosition`.

9. **Synthesize and Structure the Answer:**  Organize your findings into logical sections as requested by the prompt:

    * **Functionality:**  Summarize the main purpose of the test file and the `VisiblePosition` class.
    * **Relationship to Web Technologies:**  Provide concrete examples of how the tests relate to HTML, CSS, and JavaScript.
    * **Logic and Assumptions:** Explain the core logic being tested and any underlying assumptions.
    * **User/Programming Errors:**  Give examples of common errors related to the functionality.
    * **User Actions and Debugging:** Describe how user actions lead to the tested code and how the tests can be used for debugging.

By following these steps, you can effectively analyze the provided C++ test file and understand its purpose and relevance within the broader context of a web browser engine.
这个文件 `visible_position_test.cc` 是 Chromium Blink 引擎中用于测试 `VisiblePosition` 类的功能。`VisiblePosition` 类在 Blink 引擎的编辑模块中扮演着重要的角色，它代表了用户在文档中**可见**的插入点或选区的起始/结束位置。这个测试文件的主要目的是验证 `VisiblePosition` 类的各种操作和转换是否正确，确保在各种复杂的 DOM 结构和编辑场景下，能准确地确定和表示用户可见的位置。

**功能列举:**

1. **创建 `VisiblePosition` 对象:** 测试从不同的 `Position` 对象创建 `VisiblePosition` 对象是否正确。`Position` 是 Blink 中更底层的表示 DOM 树中某个点的类。
2. **`DeepEquivalent()` 方法的验证:** 测试 `VisiblePosition` 的 `DeepEquivalent()` 方法，该方法返回与可见位置等价的、规范化的 `Position` 对象。这有助于确保在不同的 DOM 表示下，最终的可见位置是统一的。
3. **处理可编辑元素 (contenteditable):** 测试在不同类型的可编辑元素（例如，空的、包含块级子元素、包含内联子元素）中，`VisiblePosition` 的行为。
4. **处理占位符 `<br>` 标签:** 测试当内容为空，只包含一个 `<br>` 标签时，`VisiblePosition` 如何定位。
5. **处理围绕换行符的空格:** 测试在换行符前后存在空格时，`VisiblePosition` 如何处理这些空格，例如，是否会将空格视为一个可见位置。
6. **测试 `IsValid()` 方法:** (在 `DCHECK_IS_ON()` 宏开启的情况下) 测试 `VisiblePosition` 对象在 DOM 结构或样式改变后是否仍然有效。这有助于发现因 DOM 变化而导致的 `VisiblePosition` 对象失效的问题。
7. **处理行尾规范化:** 测试在行尾附近的位置，`VisiblePosition` 如何进行规范化，确保在逻辑上相邻但物理上处于不同行的位置能被正确处理。
8. **处理文本组合 (Text Combine):** 测试对于使用了 `text-combine-upright` CSS 属性的文本，`VisiblePosition` 如何正确表示其位置。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`VisiblePosition` 类虽然是 C++ 代码，但它直接服务于浏览器引擎处理 HTML 文档、渲染 CSS 样式以及响应 JavaScript 操作的能力，尤其是在处理用户编辑行为时。

* **HTML (`contenteditable`):**  `VisiblePosition` 的核心应用场景之一就是处理带有 `contenteditable` 属性的 HTML 元素。当用户在可编辑区域点击或移动光标时，浏览器引擎会使用 `VisiblePosition` 来确定光标的准确位置。
    * **举例:** 在测试用例 `EmptyEditable` 中，设置了 `<div id=target contenteditable></div>`。`VisiblePosition` 需要能正确表示这个空的可编辑 div 的起始和结束位置。当用户点击这个 div 时，浏览器会创建一个 `VisiblePosition` 对象来表示光标的位置。
* **CSS (布局和渲染):** CSS 的布局和渲染会直接影响哪些位置是“可见”的。例如，元素的 `display` 属性为 `none` 时，其内部的任何位置都不可见。换行、空格的处理也受到 CSS 的影响。
    * **举例:** 在 `NormalizationAroundLineBreak` 测试中，设置了 `word-wrap: break-word` 和固定的宽度，导致文本会在特定位置换行。`VisiblePosition` 需要能正确处理这种换行，将逻辑上连续但在不同行的文本位置正确映射。
    * **举例:** 在 `TextCombine` 测试中，使用了 `text-combine-upright: all`。这个 CSS 属性会影响文本的渲染方式，将多个字符组合成一个垂直的字符。`VisiblePosition` 需要能理解这种特殊的渲染，并能正确地定位到每个组合字符内部的位置。
* **JavaScript (DOM 操作和编辑 API):** JavaScript 可以通过 DOM API 读取和修改文档内容，也可以使用 Selection API 来获取或设置用户的选区。Selection API 的底层实现就依赖于 `VisiblePosition`。
    * **举例:** 当 JavaScript 代码通过 `document.getSelection()` 获取用户选区时，返回的选区对象的起始和结束位置就是由 `VisiblePosition` 对象表示的。
    * **用户操作:** 用户在浏览器中进行文本选择、光标移动、输入删除等操作，最终都会通过事件传递到 Blink 引擎，引擎会使用 `VisiblePosition` 来更新内部的选区状态。

**逻辑推理、假设输入与输出:**

以 `TEST_F(VisiblePositionTest, EmptyEditable)` 为例：

* **假设输入:** 一个空的、`contenteditable` 的 `<div>` 元素。
* **执行的操作:** 创建位于该 `<div>` 元素不同位置的 `Position` 对象，并将其转换为 `VisiblePosition`，然后获取其 `DeepEquivalent()`。
* **逻辑推理:**  对于一个空的 `contenteditable` 元素，其起始、结束以及内部的任何 "虚拟" 位置都应该等价于元素开始的位置。
* **预期输出:**  `CreateVisiblePosition(Position(target, 0)).DeepEquivalent()` 应该返回 `Position(target, 0)`。同理，`CreateVisiblePosition(Position::FirstPositionInNode(target)).DeepEquivalent()` 和 `CreateVisiblePosition(Position::LastPositionInNode(target)).DeepEquivalent()` 也应该返回 `Position(target, 0)`。

以 `TEST_F(VisiblePositionTest, PlaceholderBR)` 为例：

* **假设输入:** 一个包含一个 `<br>` 标签的 `<div>` 元素。
* **执行的操作:** 创建位于该 `<div>` 元素和 `<br>` 元素不同位置的 `Position` 对象，并将其转换为 `VisiblePosition`，然后获取其 `DeepEquivalent()`。
* **逻辑推理:**  当一个块级元素只包含一个 `<br>` 标签时，这个 `<br>` 标签充当一个占位符，表示一个换行。所有指向该容器内部的位置都应该等价于 `<br>` 标签之前的位置。
* **预期输出:** 所有的 `CreateVisiblePosition(...)` 调用，例如 `CreateVisiblePosition(Position(target, 0)).DeepEquivalent()`，都应该返回 `Position::BeforeNode(br)`。

**用户或编程常见的使用错误:**

1. **假设 `VisiblePosition` 在 DOM 修改后仍然有效:** 这是一个常见的编程错误。DOM 结构或样式改变后，之前的 `VisiblePosition` 对象可能会失效。
    * **例子:** 在 `NonNullInvalidatedAfterDOMChange` 和 `NonNullInvalidatedAfterStyleChange` 测试中，演示了在 DOM 结构或样式发生变化后，之前创建的 `VisiblePosition` 对象 `IsValid()` 返回 `false`。
    * **用户操作:** 用户在一个可编辑区域输入或删除文本，或者通过 JavaScript 修改 DOM 结构，都可能导致之前的 `VisiblePosition` 失效。开发者需要重新计算或更新相关的 `VisiblePosition`。
2. **没有考虑到不可见元素:** 开发者可能会错误地使用 `Position` 对象，而没有将其转换为 `VisiblePosition`，导致在处理不可见元素时出现问题。
    * **例子:** 如果一个元素设置了 `display: none;`，其内部的 `Position` 对象仍然存在，但对应的 `VisiblePosition` 可能表示一个不同的位置（例如，紧邻着该不可见元素的可见元素）。
    * **用户操作:** 用户可能点击了一个实际上因为 CSS 规则而不可见的元素，开发者需要确保通过 `VisiblePosition` 来判断用户交互的实际目标。
3. **对空格和换行的处理不当:** 在处理文本编辑时，空格和换行符的位置可能会让人困惑。`VisiblePosition` 帮助规范化这些位置，但开发者需要理解其行为。
    * **例子:** 在 `SpacesAroundLineBreak` 测试中，展示了空格在换行前后的 `VisiblePosition` 如何被规范化。开发者在处理用户输入或光标位置时，需要注意这些规范化规则。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个包含可编辑区域的网页:** 例如，一个带有 `<div contenteditable="true">` 的元素。
2. **用户点击该可编辑区域:**  当用户点击时，浏览器引擎会创建一个 `VisiblePosition` 对象来表示鼠标点击的位置，并将光标定位到该位置。这个过程会涉及到 `CreateVisiblePosition` 函数的调用，类似于测试用例中的操作。
3. **用户在该区域输入文本:** 每次输入字符，浏览器都需要确定插入点。这依赖于当前的 `VisiblePosition`，并可能在插入后更新 `VisiblePosition`.
4. **用户移动光标 (使用方向键、鼠标拖拽):**  移动光标的操作会触发浏览器重新计算光标的 `VisiblePosition`。例如，在跨越多行或包含特殊元素（如 `<br>`）时移动光标，就会涉及到测试用例中针对这些场景的逻辑。
5. **用户进行文本选择:** 当用户拖拽鼠标选择文本时，浏览器会创建表示选区起始和结束位置的 `VisiblePosition` 对象。
6. **JavaScript 与选区交互:** 如果网页上的 JavaScript 代码使用了 `document.getSelection()` 或 `document.createRange()` 等 API 来获取或操作用户的选区，这些 API 的底层实现会依赖于 `VisiblePosition`。

**作为调试线索:**

* **当编辑相关的 bug 出现时 (例如，光标位置不正确，选区不符合预期):**  开发者可以查看 `VisiblePosition` 相关的代码，例如这个测试文件，来理解 Blink 引擎是如何处理可见位置的。
* **测试用例可以作为参考:** 测试用例覆盖了各种常见的编辑场景和 DOM 结构，开发者可以通过阅读测试用例来理解在特定情况下 `VisiblePosition` 的预期行为。
* **断点调试:** 开发者可以在 Blink 引擎的源代码中，例如 `visible_position.cc` 文件中设置断点，跟踪用户操作引起的 `VisiblePosition` 对象的创建和更新过程，从而定位问题。
* **理解 `DeepEquivalent()` 的作用:** 当需要比较两个可能位于不同 DOM 结构中的逻辑位置是否相同时，可以使用 `DeepEquivalent()` 方法进行比较，这在调试过程中非常有用。

总而言之，`visible_position_test.cc` 文件是确保 Blink 引擎正确处理用户在可编辑内容中的位置的关键组成部分。理解其功能和测试用例有助于开发者理解浏览器引擎的内部工作原理，并能更好地调试与编辑相关的 bug。

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_position_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_position.h"

#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"

namespace blink {

class VisiblePositionTest : public EditingTestBase {};

TEST_F(VisiblePositionTest, EmptyEditable) {
  SetBodyContent("<div id=target contenteditable></div>");
  const Element& target = *GetElementById("target");

  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position(target, 0)).DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position::FirstPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position::LastPositionInNode(target))
                .DeepEquivalent());
}

TEST_F(VisiblePositionTest, EmptyEditableWithBlockChild) {
  // Note: Placeholder <br> is needed to have non-zero editable.
  SetBodyContent("<div id=target contenteditable><div><br></div></div>");
  const Element& target = *GetElementById("target");
  const Node& div = *target.firstChild();
  const Node& br = *div.firstChild();

  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(target, 0)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::FirstPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::LastPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(target, 1)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(div, 0)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::BeforeNode(div)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::AfterNode(div)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::BeforeNode(br)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::AfterNode(br)).DeepEquivalent());
}

TEST_F(VisiblePositionTest, EmptyEditableWithInlineChild) {
  SetBodyContent("<div id=target contenteditable><span></span></div>");
  const Element& target = *GetElementById("target");
  const Node& span = *target.firstChild();

  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position(target, 0)).DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position::FirstPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position::LastPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position(target, 1)).DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position(span, 0)).DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position::BeforeNode(span)).DeepEquivalent());
  EXPECT_EQ(Position(target, 0),
            CreateVisiblePosition(Position::AfterNode(span)).DeepEquivalent());
}

TEST_F(VisiblePositionTest, PlaceholderBR) {
  SetBodyContent("<div id=target><br id=br></div>");
  const Element& target = *GetElementById("target");
  const Element& br = *GetElementById("br");

  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(target, 0)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::FirstPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::LastPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(target, 1)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(br, 0)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::BeforeNode(br)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::AfterNode(br)).DeepEquivalent());
}

TEST_F(VisiblePositionTest, PlaceholderBRWithCollapsedSpace) {
  SetBodyContent("<div id=target> <br id=br> </div>");
  const Element& target = *GetElementById("target");
  const Element& br = *GetElementById("br");

  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(target, 0)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::FirstPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::LastPositionInNode(target))
                .DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(target, 1)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(target, 2)).DeepEquivalent());
  EXPECT_EQ(
      Position::BeforeNode(br),
      CreateVisiblePosition(Position(target.firstChild(), 0)).DeepEquivalent());
  EXPECT_EQ(
      Position::BeforeNode(br),
      CreateVisiblePosition(Position(target.firstChild(), 1)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position(br, 0)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::BeforeNode(br)).DeepEquivalent());
  EXPECT_EQ(Position::BeforeNode(br),
            CreateVisiblePosition(Position::AfterNode(br)).DeepEquivalent());
  EXPECT_EQ(
      Position::BeforeNode(br),
      CreateVisiblePosition(Position(target.lastChild(), 0)).DeepEquivalent());
  EXPECT_EQ(
      Position::BeforeNode(br),
      CreateVisiblePosition(Position(target.lastChild(), 1)).DeepEquivalent());
}

#if DCHECK_IS_ON()

TEST_F(VisiblePositionTest, NullIsValid) {
  EXPECT_TRUE(VisiblePosition().IsValid());
}

TEST_F(VisiblePositionTest, NonNullIsValidBeforeMutation) {
  SetBodyContent("<p>one</p>");

  Element* paragraph = GetDocument().QuerySelector(AtomicString("p"));
  Position position(paragraph->firstChild(), 1);
  EXPECT_TRUE(CreateVisiblePosition(position).IsValid());
}

TEST_F(VisiblePositionTest, NonNullInvalidatedAfterDOMChange) {
  SetBodyContent("<p>one</p>");

  Element* paragraph = GetDocument().QuerySelector(AtomicString("p"));
  Position position(paragraph->firstChild(), 1);
  VisiblePosition null_visible_position;
  VisiblePosition non_null_visible_position = CreateVisiblePosition(position);

  Element* div = GetDocument().CreateRawElement(html_names::kDivTag);
  GetDocument().body()->AppendChild(div);

  EXPECT_TRUE(null_visible_position.IsValid());
  EXPECT_FALSE(non_null_visible_position.IsValid());

  UpdateAllLifecyclePhasesForTest();

  // Invalid VisiblePosition can never become valid again.
  EXPECT_FALSE(non_null_visible_position.IsValid());
}

TEST_F(VisiblePositionTest, NonNullInvalidatedAfterStyleChange) {
  SetBodyContent("<div>one</div><p>two</p>");

  Element* paragraph = GetDocument().QuerySelector(AtomicString("p"));
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Position position(paragraph->firstChild(), 1);

  VisiblePosition visible_position1 = CreateVisiblePosition(position);
  div->style()->setProperty(GetDocument().GetExecutionContext(), "color", "red",
                            "important", ASSERT_NO_EXCEPTION);
  EXPECT_FALSE(visible_position1.IsValid());

  UpdateAllLifecyclePhasesForTest();

  VisiblePosition visible_position2 = CreateVisiblePosition(position);
  div->style()->setProperty(GetDocument().GetExecutionContext(), "display",
                            "none", "important", ASSERT_NO_EXCEPTION);
  EXPECT_FALSE(visible_position2.IsValid());

  UpdateAllLifecyclePhasesForTest();

  // Invalid VisiblePosition can never become valid again.
  EXPECT_FALSE(visible_position1.IsValid());
  EXPECT_FALSE(visible_position2.IsValid());
}

#endif

TEST_F(VisiblePositionTest, NormalizationAroundLineBreak) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "width: 5.5ch;"
      "font: 10px/10px Ahem;"
      "word-wrap: break-word;"
      "}");
  SetBodyContent(
      "<div>line1line2</div>"
      "<div>line1<br>line2</div>"
      "<div>line1<wbr>line2</div>"
      "<div>line1<span></span>line2</div>"
      "<div>line1<span></span><span></span>line2</div>");

  StaticElementList* tests =
      GetDocument().QuerySelectorAll(AtomicString("div"));
  for (unsigned i = 0; i < tests->length(); ++i) {
    Element* test = tests->item(i);
    Node* node1 = test->firstChild();
    Node* node2 = test->lastChild();
    PositionWithAffinity line1_end(Position(node1, 5), TextAffinity::kUpstream);
    PositionWithAffinity line2_start(Position(node2, node1 == node2 ? 5 : 0),
                                     TextAffinity::kDownstream);
    PositionWithAffinity line1_end_normalized =
        CreateVisiblePosition(line1_end).ToPositionWithAffinity();
    PositionWithAffinity line2_start_normalized =
        CreateVisiblePosition(line2_start).ToPositionWithAffinity();

    EXPECT_FALSE(InSameLine(line1_end, line2_start));
    EXPECT_FALSE(InSameLine(line1_end_normalized, line2_start_normalized));
    EXPECT_TRUE(InSameLine(line1_end, line1_end_normalized));
    EXPECT_TRUE(InSameLine(line2_start, line2_start_normalized));
  }
}

TEST_F(VisiblePositionTest, SpacesAroundLineBreak) {
  // Narrow <body> forces "a" and "b" to be in different lines.
  InsertStyleElement("body { width: 1px }");
  {
    SetBodyContent("a b");
    Node* ab = GetDocument().body()->firstChild();
    EXPECT_EQ(Position(ab, 0),
              CreateVisiblePosition(Position(ab, 0)).DeepEquivalent());
    EXPECT_EQ(Position(ab, 1),
              CreateVisiblePosition(Position(ab, 1)).DeepEquivalent());
    EXPECT_EQ(Position(ab, 2),
              CreateVisiblePosition(Position(ab, 2)).DeepEquivalent());
  }
  {
    SetBodyContent("a<span> b</span>");
    Node* a = GetDocument().body()->firstChild();
    Node* b = a->nextSibling()->firstChild();
    EXPECT_EQ(Position(a, 0),
              CreateVisiblePosition(Position(a, 0)).DeepEquivalent());
    EXPECT_EQ(Position(a, 1),
              CreateVisiblePosition(Position(a, 1)).DeepEquivalent());
    EXPECT_EQ(Position(a, 1),
              CreateVisiblePosition(Position(b, 0)).DeepEquivalent());
    EXPECT_EQ(Position(b, 1),
              CreateVisiblePosition(Position(b, 1)).DeepEquivalent());
    EXPECT_EQ(Position(b, 2),
              CreateVisiblePosition(Position(b, 2)).DeepEquivalent());
  }
  {
    SetBodyContent("<span>a</span> b");
    Node* b = GetDocument().body()->lastChild();
    Node* a = b->previousSibling()->firstChild();
    EXPECT_EQ(Position(a, 0),
              CreateVisiblePosition(Position(a, 0)).DeepEquivalent());
    EXPECT_EQ(Position(a, 1),
              CreateVisiblePosition(Position(a, 1)).DeepEquivalent());
    EXPECT_EQ(Position(a, 1),
              CreateVisiblePosition(Position(b, 0)).DeepEquivalent());
    EXPECT_EQ(Position(b, 1),
              CreateVisiblePosition(Position(b, 1)).DeepEquivalent());
    EXPECT_EQ(Position(b, 2),
              CreateVisiblePosition(Position(b, 2)).DeepEquivalent());
  }
  {
    SetBodyContent("a <span>b</span>");
    Node* a = GetDocument().body()->firstChild();
    Node* b = a->nextSibling()->firstChild();
    EXPECT_EQ(Position(a, 0),
              CreateVisiblePosition(Position(a, 0)).DeepEquivalent());
    EXPECT_EQ(Position(a, 1),
              CreateVisiblePosition(Position(a, 1)).DeepEquivalent());
    EXPECT_EQ(Position(a, 2),
              CreateVisiblePosition(Position(a, 2)).DeepEquivalent());
    EXPECT_EQ(Position(a, 2),
              CreateVisiblePosition(Position(b, 0)).DeepEquivalent());
    EXPECT_EQ(Position(b, 1),
              CreateVisiblePosition(Position(b, 1)).DeepEquivalent());
  }
  {
    SetBodyContent("<span>a </span>b");
    Node* b = GetDocument().body()->lastChild();
    Node* a = b->previousSibling()->firstChild();
    EXPECT_EQ(Position(a, 0),
              CreateVisiblePosition(Position(a, 0)).DeepEquivalent());
    EXPECT_EQ(Position(a, 1),
              CreateVisiblePosition(Position(a, 1)).DeepEquivalent());
    EXPECT_EQ(Position(a, 2),
              CreateVisiblePosition(Position(a, 2)).DeepEquivalent());
    EXPECT_EQ(Position(a, 2),
              CreateVisiblePosition(Position(b, 0)).DeepEquivalent());
    EXPECT_EQ(Position(b, 1),
              CreateVisiblePosition(Position(b, 1)).DeepEquivalent());
  }
}

TEST_F(VisiblePositionTest, TextCombine) {
  InsertStyleElement(
      "div {"
      "  font: 100px/110px Ahem;"
      "  writing-mode: vertical-rl;"
      "}"
      "tcy { text-combine-upright: all; }");
  SetBodyInnerHTML("<div>a<tcy id=target>01234</tcy>b</div>");
  const auto& target = *GetElementById("target");
  const auto& text_a = *To<Text>(target.previousSibling());
  const auto& text_01234 = *To<Text>(target.firstChild());
  const auto& text_b = *To<Text>(target.nextSibling());

  EXPECT_EQ(Position(text_a, 0),
            CreateVisiblePosition(Position(text_a, 0)).DeepEquivalent());
  EXPECT_EQ(Position(text_a, 1),
            CreateVisiblePosition(Position(text_a, 1)).DeepEquivalent());

  if (text_01234.GetLayoutObject()->Parent()->IsLayoutTextCombine()) {
    EXPECT_EQ(Position(text_01234, 0),
              CreateVisiblePosition(Position(text_01234, 0)).DeepEquivalent());
  } else {
    EXPECT_EQ(Position(text_a, 1),
              CreateVisiblePosition(Position(text_01234, 0)).DeepEquivalent());
  }
  EXPECT_EQ(Position(text_01234, 1),
            CreateVisiblePosition(Position(text_01234, 1)).DeepEquivalent());
  EXPECT_EQ(Position(text_01234, 2),
            CreateVisiblePosition(Position(text_01234, 2)).DeepEquivalent());
  EXPECT_EQ(Position(text_01234, 3),
            CreateVisiblePosition(Position(text_01234, 3)).DeepEquivalent());
  EXPECT_EQ(Position(text_01234, 4),
            CreateVisiblePosition(Position(text_01234, 4)).DeepEquivalent());
  EXPECT_EQ(Position(text_01234, 5),
            CreateVisiblePosition(Position(text_01234, 5)).DeepEquivalent());

  if (text_01234.GetLayoutObject()->Parent()->IsLayoutTextCombine()) {
    EXPECT_EQ(Position(text_b, 0),
              CreateVisiblePosition(Position(text_b, 0)).DeepEquivalent());
  } else {
    EXPECT_EQ(Position(text_01234, 5),
              CreateVisiblePosition(Position(text_b, 0)).DeepEquivalent());
  }
  EXPECT_EQ(Position(text_b, 1),
            CreateVisiblePosition(Position(text_b, 1)).DeepEquivalent());
}

}  // namespace blink

"""

```