Response:
My thinking process to analyze the `surrounding_text_test.cc` file and answer the user's request goes like this:

1. **Understand the Core Purpose of the File:**  The file name itself, `surrounding_text_test.cc`, is a strong indicator. The `_test.cc` suffix clearly signifies it's a test file. The `surrounding_text` part suggests it's testing the functionality related to extracting text surrounding a given point or range in a document.

2. **Identify Key Classes and Functions Under Test:**  I look for the class being tested. The `#include "third_party/blink/renderer/core/editing/surrounding_text.h"` line is the giveaway. This tells me the `SurroundingText` class is the primary focus. Within the test file, I see various `TEST_F` macros, each defining a specific test case. These test names (e.g., `BasicCaretSelection`, `BasicRangeSelection`, `TreeCaretSelection`) provide hints about the scenarios being tested.

3. **Analyze Test Case Structure:** Each `TEST_F` function typically follows a pattern:
    * **Setup:**  Call `SetHTML()` to create a DOM structure.
    * **Action:** Create an `EphemeralRange` (representing a selection) and then a `SurroundingText` object based on that selection and a maximum length.
    * **Assertion:** Use `EXPECT_EQ` or `EXPECT_TRUE` to verify the properties of the `SurroundingText` object, such as `TextContent()`, `StartOffsetInTextContent()`, and `EndOffsetInTextContent()`.

4. **Infer Functionality from Test Cases:** By examining the HTML set up in each test and the expected output, I can deduce what aspects of `SurroundingText` are being checked. For example:
    * `BasicCaretSelection` and `BasicRangeSelection` test simple text node scenarios.
    * `TreeCaretSelection` and `TreeRangeSelection` test cases involving more complex DOM structures with multiple elements.
    * `TextAreaSelection` checks how `SurroundingText` works with `<textarea>` elements.
    * Other tests cover edge cases like empty input fields, buttons, select elements, fieldsets, scripts, comments, and single-dot paragraphs.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:**  The test cases heavily rely on HTML to create the document structure. The `SetHTML()` function directly manipulates the DOM. I can identify how different HTML elements (paragraphs, divs, textareas, buttons, selects, fieldsets, etc.) affect the surrounding text extraction.
    * **CSS:** While not explicitly tested, I know that CSS affects the *rendering* of the HTML, but `SurroundingText` operates on the underlying DOM structure and text content. Therefore, CSS is less directly relevant, but I should acknowledge its role in the overall web page.
    * **JavaScript:** The test case `ButtonScriptAndComment` hints at how `SurroundingText` handles `<script>` tags. Generally, scripts are not considered part of the visible text content. JavaScript can dynamically modify the DOM, which could subsequently affect the results of `SurroundingText`.

6. **Identify Logic and Assumptions:** The core logic revolves around determining the boundaries of the surrounding text based on the provided selection and the maximum length. The tests implicitly assume that the `SurroundingText` class correctly traverses the DOM tree and extracts the relevant text. The `maxlength` parameter passed to the `SurroundingText` constructor is crucial.

7. **Pinpoint Potential User/Developer Errors:**  Based on the tests, I can anticipate common issues:
    * Incorrectly calculating offsets.
    * Assuming `maxlength` behaves in a specific way (e.g., not understanding how it's split between left and right context).
    * Not handling different types of DOM nodes correctly.
    * Issues with empty elements or elements without text content.

8. **Trace User Actions to the Code:** I need to connect the functionality being tested to real-world user interactions. Text selection is the key. Users select text in various ways (clicking and dragging, double-clicking, using keyboard shortcuts). These actions eventually trigger the browser's internal mechanisms, potentially involving the `SurroundingText` functionality when features like copy/paste, text suggestions, or accessibility tools are used. Debugging might involve setting breakpoints within the `SurroundingText` class or related selection code.

9. **Structure the Answer:** Finally, I organize the information into clear sections as requested by the user, covering:
    * Functionality
    * Relationship to HTML, CSS, JavaScript (with examples)
    * Logic and Assumptions (with input/output examples)
    * Common errors (with examples)
    * User actions and debugging.

By following these steps, I can systematically analyze the test file and provide a comprehensive answer to the user's request. The process involves code comprehension, logical deduction, and connecting the technical details to the broader context of web development and user interaction.
这个文件 `surrounding_text_test.cc` 是 Chromium Blink 引擎中用于测试 `SurroundingText` 类的功能。`SurroundingText` 类的作用是获取给定文本选择（或光标位置）周围的文本内容。这个测试文件通过创建不同的 DOM 结构和文本选择，然后断言 `SurroundingText` 对象返回的周围文本是否符合预期。

以下是该文件的功能的详细说明：

**主要功能:**

1. **测试 `SurroundingText` 类的核心功能:**  验证 `SurroundingText` 类在各种场景下是否能正确提取目标文本选择周围的文本。这些场景包括：
    * **光标选择 (Caret Selection):**  测试当选择是一个插入符（没有选中文本）时，如何提取周围的文本。
    * **范围选择 (Range Selection):** 测试当有选中文本范围时，如何提取周围的文本。
    * **跨越 DOM 树的文本选择 (Tree Selection):** 测试当选择跨越不同的 HTML 元素时，如何提取周围的文本。
    * **在 `<textarea>` 元素中的选择:** 测试在多行文本输入框中选择文本时，如何提取周围的文本。
    * **包含不同类型元素的场景:**  测试在包含按钮、段落、选择框、字段集等元素的复杂 HTML 结构中，如何提取周围的文本。
    * **处理特殊节点:** 测试如何处理脚本、注释等非文本节点。

2. **定义测试用例 (Test Cases):** 文件中包含多个以 `TEST_F` 开头的函数，每个函数定义了一个具体的测试用例。每个测试用例会：
    * **设置 HTML 内容 (`SetHTML`):**  创建一个包含特定 HTML 结构的 DOM 树。
    * **模拟文本选择 (`Select` 或直接设置 `SelectionRange`):**  在创建的 DOM 树中模拟用户的文本选择或光标位置。
    * **创建 `SurroundingText` 对象:**  使用模拟的文本选择和最大字符数限制来创建一个 `SurroundingText` 对象。
    * **进行断言 (`EXPECT_EQ`, `EXPECT_TRUE`):**  验证 `SurroundingText` 对象返回的周围文本内容、起始偏移量和结束偏移量是否与预期一致。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML (密切相关):**  这个测试文件直接操作和测试 HTML 结构。每个测试用例都会通过 `SetHTML` 函数创建一个特定的 HTML 片段，然后在这个片段上模拟文本选择。`SurroundingText` 的核心功能就是分析 HTML 结构中的文本内容。
    * **举例说明:**
        ```c++
        SetHTML(String("<p id='selection'>foo bar</p>"));
        EphemeralRange selection = Select(0); // 光标在 'f' 前面
        SurroundingText surrounding_text(selection, 1);
        EXPECT_EQ("f", surrounding_text.TextContent());
        ```
        在这个例子中，HTML `<p id='selection'>foo bar</p>` 被创建，选择被设置为在 "foo bar" 的开头。`SurroundingText` 被期望提取以光标位置为中心的 1 个字符，结果是 "f"。

* **JavaScript (间接相关):**  虽然这个测试文件本身是用 C++ 编写的，并且测试的是 Blink 引擎的 C++ 代码，但 `SurroundingText` 的功能最终会被用于处理用户在浏览器中与网页的交互，而这些交互很多是通过 JavaScript 实现的。例如，当用户在网页上进行文本编辑或选择时，JavaScript 代码可能会调用 Blink 引擎提供的接口来获取周围的文本。
    * **举例说明:**  一个富文本编辑器可能会使用类似 `SurroundingText` 的功能来获取光标周围的文本，以便实现自动补全、拼写检查等功能。这些功能通常由 JavaScript 代码驱动。

* **CSS (关系较弱):** CSS 主要负责网页的样式和布局。`SurroundingText` 的功能侧重于提取文本内容，与 CSS 的渲染没有直接关系。即使网页的样式发生变化，`SurroundingText` 提取的文本内容应该保持一致。

**逻辑推理与假设输入输出:**

假设输入：一个包含文本的 HTML 结构，以及一个表示文本选择或光标位置的 `EphemeralRange` 对象，和一个最大周围字符数 `max_length`。

假设输出：一个 `SurroundingText` 对象，包含以下信息：

* `TextContent()`:  目标选择周围的文本内容，长度不超过 `max_length`。
* `StartOffsetInTextContent()`: 目标选择在 `TextContent()` 中的起始偏移量。
* `EndOffsetInTextContent()`: 目标选择在 `TextContent()` 中的结束偏移量。

**例如 (基于 `BasicCaretSelection` 测试用例):**

* **假设输入:**
    * HTML: `<p id='selection'>foo bar</p>`
    * `EphemeralRange`:  光标在 'f' 前面 (offset 0)。
    * `max_length`: 1
* **逻辑推理:**  以光标为中心，提取最多 1 个字符。由于光标在开头，所以提取到的是 'f'。选择的起始和结束位置都在 'f' 的开头，所以偏移量都是 0。
* **预期输出:**
    * `TextContent()`: "f"
    * `StartOffsetInTextContent()`: 0
    * `EndOffsetInTextContent()`: 0

* **假设输入:**
    * HTML: `<p id='selection'>foo bar</p>`
    * `EphemeralRange`: 光标在 'f' 前面 (offset 0)。
    * `max_length`: 5
* **逻辑推理:** 以光标为中心，提取最多 5 个字符。由于光标在开头，会尽可能向右提取，直到达到 `max_length` 或文本结尾。简化空白后，得到 "foo"。选择的起始和结束位置都在 "foo" 的第二个字符之前（因为原文本偏移量为 0），所以偏移量都是 1。
* **预期输出:**
    * `TextContent()`: "foo"
    * `StartOffsetInTextContent()`: 1
    * `EndOffsetInTextContent()`: 1

**用户或编程常见的使用错误:**

1. **错误地计算偏移量:**  开发者在使用 `SurroundingText` 返回的 `StartOffsetInTextContent()` 和 `EndOffsetInTextContent()` 时，可能会错误地将其应用于原始 HTML 文本，而不是 `TextContent()` 返回的截取后的文本。
    * **举例:**  如果 `TextContent()` 返回 "bar"，`StartOffsetInTextContent()` 是 1，这意味着原始选择的起始位置对应于 "bar" 中的第二个字符。

2. **假设 `max_length` 是硬性限制:**  `SurroundingText` 可能会返回少于 `max_length` 的字符，例如当选择靠近文本的开头或结尾时。开发者不应该假设返回的文本长度总是等于 `max_length`。

3. **未考虑不同类型的 DOM 节点:**  开发者可能没有考虑到 `SurroundingText` 在处理包含各种 HTML 元素的复杂结构时的行为。例如，换行符、按钮、或其他非文本元素可能会影响周围文本的提取。

**用户操作如何一步步到达这里 (调试线索):**

`SurroundingText` 的功能通常在用户与网页进行交互时被间接调用。以下是一些可能导致 `SurroundingText` 功能被触发的用户操作：

1. **文本选择:** 用户通过鼠标拖拽或使用 Shift + 方向键在网页上选择文本。
2. **光标移动:** 用户点击网页上的某个位置或使用方向键移动光标。
3. **复制粘贴:** 用户选择文本后进行复制操作，浏览器可能需要获取周围的文本信息用于某些上下文分析。
4. **自动完成/建议:** 在输入框或可编辑区域，当用户输入文本时，浏览器可能会使用 `SurroundingText` 来获取周围的文本，以便提供更准确的自动完成或建议。
5. **拼写检查/语法检查:** 浏览器在进行拼写或语法检查时，可能需要获取错误单词周围的文本上下文。
6. **辅助功能 (Accessibility):** 屏幕阅读器等辅助技术可能使用类似 `SurroundingText` 的功能来获取当前焦点或选择周围的文本，以便向用户提供上下文信息。

**调试线索:**

当涉及到与文本选择和周围文本相关的 Bug 时，可以考虑以下调试步骤：

1. **确定用户操作:**  复现用户导致问题的具体操作步骤。
2. **检查文本选择:**  使用浏览器的开发者工具查看当前的文本选择范围（可以使用 `window.getSelection()` 在控制台中查看）。
3. **断点调试:** 在 Blink 引擎的源代码中，特别是 `core/editing/surrounding_text.cc` 和相关的选择代码中设置断点，跟踪代码的执行流程，查看 `SurroundingText` 对象是如何被创建和调用的，以及其返回的值。
4. **分析 DOM 结构:**  检查目标文本所在的 HTML 结构，特别是其父节点、子节点以及兄弟节点，查看是否存在影响文本提取的特殊元素或属性。
5. **查看日志:**  Blink 引擎可能会有相关的日志输出，可以帮助理解文本提取的过程。

总而言之，`surrounding_text_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎的 `SurroundingText` 类能够在各种复杂的场景下正确地提取目标文本选择周围的文本，这对于许多浏览器功能（如文本编辑、辅助功能等）的正常运行至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/surrounding_text_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/surrounding_text.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

class SurroundingTextTest : public PageTestBase {
 protected:
  Document& GetDocument() const { return dummy_page_holder_->GetDocument(); }
  void SetHTML(const String&);
  EphemeralRange Select(int offset) { return Select(offset, offset); }
  EphemeralRange Select(int start, int end);

 private:
  void SetUp() override;

  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
};

void SurroundingTextTest::SetUp() {
  dummy_page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
}

void SurroundingTextTest::SetHTML(const String& content) {
  GetDocument().body()->setInnerHTML(content);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
}

EphemeralRange SurroundingTextTest::Select(int start, int end) {
  Element* element = GetDocument().getElementById(AtomicString("selection"));
  return EphemeralRange(Position(element->firstChild(), start),
                        Position(element->firstChild(), end));
}

TEST_F(SurroundingTextTest, BasicCaretSelection) {
  SetHTML(String("<p id='selection'>foo bar</p>"));

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 1);

    EXPECT_EQ("f", surrounding_text.TextContent());
    EXPECT_EQ(0u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(0u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 5);

    // maxlength/2 is used on the left and right.
    EXPECT_EQ("foo",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 42);

    EXPECT_EQ("foo bar",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(7);
    SurroundingText surrounding_text(selection, 42);

    EXPECT_EQ("foo bar",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(8u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(8u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(6);
    SurroundingText surrounding_text(selection, 2);

    EXPECT_EQ("ar", surrounding_text.TextContent());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(6);
    SurroundingText surrounding_text(selection, 42);

    EXPECT_EQ("foo bar",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(7u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(7u, surrounding_text.EndOffsetInTextContent());
  }
}

TEST_F(SurroundingTextTest, BasicRangeSelection) {
  SetHTML(String("<p id='selection'>Lorem ipsum dolor sit amet</p>"));

  {
    EphemeralRange selection = Select(0, 5);
    SurroundingText surrounding_text(selection, 1);

    EXPECT_EQ("Lorem ", surrounding_text.TextContent());
    EXPECT_EQ(0u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(5u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0, 5);
    SurroundingText surrounding_text(selection, 5);

    EXPECT_EQ("Lorem ip",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(6u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0, 5);
    SurroundingText surrounding_text(selection, 42);

    EXPECT_EQ("Lorem ipsum dolor sit amet",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(6u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(6, 11);
    SurroundingText surrounding_text(selection, 2);

    EXPECT_EQ(" ipsum ", surrounding_text.TextContent());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(6u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(6, 11);
    SurroundingText surrounding_text(selection, 42);

    EXPECT_EQ("Lorem ipsum dolor sit amet",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(7u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(12u, surrounding_text.EndOffsetInTextContent());
  }

  {
    // Last word.
    EphemeralRange selection = Select(22, 26);
    SurroundingText surrounding_text(selection, 8);

    EXPECT_EQ("sit amet", surrounding_text.TextContent());
    EXPECT_EQ(4u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(8u, surrounding_text.EndOffsetInTextContent());
  }
}

TEST_F(SurroundingTextTest, TreeCaretSelection) {
  SetHTML(
      String("<div>This is outside of <p id='selection'>foo bar</p> the "
             "selected node</div>"));

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 1);

    EXPECT_EQ("f", surrounding_text.TextContent());
    EXPECT_EQ(0u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(0u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 5);

    EXPECT_EQ("foo",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 1337);

    EXPECT_EQ("This is outside of foo bar the selected node",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(20u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(20u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(6);
    SurroundingText surrounding_text(selection, 2);

    EXPECT_EQ("ar", surrounding_text.TextContent());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(6);
    SurroundingText surrounding_text(selection, 1337);

    EXPECT_EQ("This is outside of foo bar the selected node",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(26u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(26u, surrounding_text.EndOffsetInTextContent());
  }
}

TEST_F(SurroundingTextTest, TreeRangeSelection) {
  SetHTML(
      String("<div>This is outside of <p id='selection'>foo bar</p> the "
             "selected node</div>"));

  {
    EphemeralRange selection = Select(0, 1);
    SurroundingText surrounding_text(selection, 1);

    EXPECT_EQ("fo",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(0u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0, 3);
    SurroundingText surrounding_text(selection, 12);

    EXPECT_EQ("e of foo bar",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(5u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(8u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0, 3);
    SurroundingText surrounding_text(selection, 1337);

    EXPECT_EQ("This is outside of foo bar the selected node",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(20u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(23u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(4, 7);
    SurroundingText surrounding_text(selection, 12);

    EXPECT_EQ("foo bar the se",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(5u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(8u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0, 7);
    SurroundingText surrounding_text(selection, 1337);

    EXPECT_EQ("This is outside of foo bar the selected node",
              String(surrounding_text.TextContent()).SimplifyWhiteSpace());
    EXPECT_EQ(20u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(27u, surrounding_text.EndOffsetInTextContent());
  }
}

TEST_F(SurroundingTextTest, TextAreaSelection) {
  SetHTML(
      String("<p>First paragraph</p>"
             "<textarea id='selection'>abc def ghi</textarea>"
             "<p>Second paragraph</p>"));

  TextControlElement* text_ctrl = reinterpret_cast<TextControlElement*>(
      GetDocument().getElementById(AtomicString("selection")));

  text_ctrl->SetSelectionRange(4, 7);
  EphemeralRange selection = text_ctrl->Selection().ComputeRange();

  SurroundingText surrounding_text(selection, 20);

  EXPECT_EQ("abc def ghi",
            String(surrounding_text.TextContent()).SimplifyWhiteSpace());
  EXPECT_EQ(4u, surrounding_text.StartOffsetInTextContent());
  EXPECT_EQ(7u, surrounding_text.EndOffsetInTextContent());
}

TEST_F(SurroundingTextTest, EmptyInputElementWithChild) {
  SetHTML(String("<input type=\"text\" id=\"input_name\"/>"));

  TextControlElement* input_element = reinterpret_cast<TextControlElement*>(
      GetDocument().getElementById(AtomicString("input_name")));
  input_element->SetInnerEditorValue("John Smith");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // BODY
  //   INPUT
  //     #shadow-root
  // *      DIV id="inner-editor" (editable)
  //          #text "John Smith"

  const Element* inner_editor = input_element->InnerEditorElement();
  const Position start = Position(inner_editor, 0);
  const Position end = Position(inner_editor, 0);

  // Surrounding text should not crash. See http://crbug.com/758438.
  SurroundingText surrounding_text(EphemeralRange(start, end), 8);
  EXPECT_TRUE(surrounding_text.TextContent().empty());
}

TEST_F(SurroundingTextTest, ButtonsAndParagraph) {
  SetHTML(
      String("<button>.</button>12345"
             "<p id='selection'>6789 12345</p>"
             "6789<button>.</button>"));

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 100);

    EXPECT_EQ("12345\n6789 12345\n\n6789", surrounding_text.TextContent());
    EXPECT_EQ(6u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(6u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(5);
    SurroundingText surrounding_text(selection, 6);

    EXPECT_EQ("89 123", surrounding_text.TextContent());
    EXPECT_EQ(3u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(3u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(0);
    SurroundingText surrounding_text(selection, 0);

    EXPECT_TRUE(surrounding_text.TextContent().empty());
  }

  {
    EphemeralRange selection = Select(5);
    SurroundingText surrounding_text(selection, 1);

    EXPECT_EQ("1", surrounding_text.TextContent());
    EXPECT_EQ(0u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(0u, surrounding_text.EndOffsetInTextContent());
  }

  {
    EphemeralRange selection = Select(6);
    SurroundingText surrounding_text(selection, 2);

    EXPECT_EQ("12", surrounding_text.TextContent());
    EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
    EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
  }
}

TEST_F(SurroundingTextTest, SelectElementAndText) {
  SetHTML(String(
      "<select>.</select>"
      "<div>57th Street and Lake Shore Drive</div>"
      " <span>Chicago</span> <span id='selection'>IL</span> <span>60637</span>"
      "<select>.</select>"));

  EphemeralRange selection = Select(0);
  SurroundingText surrounding_text(selection, 100);

  EXPECT_EQ("\xEF\xBF\xBC\n57th Street and Lake Shore Drive\nChicago IL 60637",
            surrounding_text.TextContent().Utf8());
  EXPECT_EQ(43u, surrounding_text.StartOffsetInTextContent());
  EXPECT_EQ(43u, surrounding_text.EndOffsetInTextContent());
}

TEST_F(SurroundingTextTest, FieldsetElementAndText) {
  SetHTML(
      String("<fieldset>.</fieldset>12345<button>abc</button>"
             "<p>6789<br><span id='selection'>12345</span></p>"
             "6789<textarea>abc</textarea>0123<fieldset>.</fieldset>"));

  EphemeralRange selection = Select(0);
  SurroundingText surrounding_text(selection, 100);

  EXPECT_EQ("\n6789\n12345\n\n6789", surrounding_text.TextContent());
  EXPECT_EQ(6u, surrounding_text.StartOffsetInTextContent());
  EXPECT_EQ(6u, surrounding_text.EndOffsetInTextContent());
}

TEST_F(SurroundingTextTest, ButtonScriptAndComment) {
  SetHTML(
      String("<button>.</button>"
             "<div id='selection'>This is <!-- comment --!>a test "
             "<script language='javascript'></script>"
             "example<button>.</button>"));

  EphemeralRange selection = Select(0);
  SurroundingText surrounding_text(selection, 100);

  EXPECT_EQ("\nThis is a test example", surrounding_text.TextContent());
  EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
  EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
}

TEST_F(SurroundingTextTest, ButtonAndLongDiv) {
  SetHTML(
      String("<button>.</button>"
             "<div id='selection'>012345678901234567890123456789</div>"
             "<button>.</button>"));

  EphemeralRange selection = Select(15);
  SurroundingText surrounding_text(selection, 12);

  EXPECT_EQ("901234567890", surrounding_text.TextContent());
  EXPECT_EQ(6u, surrounding_text.StartOffsetInTextContent());
  EXPECT_EQ(6u, surrounding_text.EndOffsetInTextContent());
}

TEST_F(SurroundingTextTest, EmptySurroundingTextInOptionsAndButton) {
  SetHTML(
      String("<option>.</option>12345"
             "<button id='selection'>test</button>"
             "<option>.</option>"));

  {
    EphemeralRange selection = Select(1);
    SurroundingText surrounding_text(selection, 100);

    EXPECT_TRUE(surrounding_text.TextContent().empty());
  }

  {
    EphemeralRange selection = Select(3);
    SurroundingText surrounding_text(selection, 100);

    EXPECT_TRUE(surrounding_text.TextContent().empty());
  }
}

TEST_F(SurroundingTextTest, SingleDotParagraph) {
  SetHTML(String("<p id='selection'>.</p>"));

  EphemeralRange selection = Select(0);
  SurroundingText surrounding_text(selection, 2);

  EXPECT_EQ("\n.", surrounding_text.TextContent());
  EXPECT_EQ(1u, surrounding_text.StartOffsetInTextContent());
  EXPECT_EQ(1u, surrounding_text.EndOffsetInTextContent());
}

}  // namespace blink
```