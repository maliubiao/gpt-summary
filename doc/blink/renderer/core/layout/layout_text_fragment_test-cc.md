Response:
The user wants to understand the functionality of the `layout_text_fragment_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relation to web technologies, and potential user/developer errors it tests.

**Plan:**

1. **Identify the main class being tested:** `LayoutTextFragment`.
2. **Understand the purpose of `LayoutTextFragment`:** Based on its name and the tests, it seems to be responsible for handling fragments of text within the layout tree, particularly focusing on how these fragments interact with features like `::first-letter` and caret positioning.
3. **Analyze each test case:**  Determine what specific aspect of `LayoutTextFragment` is being tested (e.g., `CaretMinOffset`, `CaretMaxOffset`, `ResolvedTextLength`, `ContainsCaretOffset`, `IsBeforeAfterNonCollapsedCharacter`).
4. **Relate to web technologies:** Connect the tested functionalities to HTML, CSS, and JavaScript concepts (e.g., CSS `::first-letter` pseudo-element, text selection and caret behavior).
5. **Identify logical deductions and assumptions:** Look for test cases that set up specific input (HTML structure, text content) and assert specific output (property values of `LayoutTextFragment`).
6. **Identify potential user/developer errors:**  Consider what kind of mistakes developers might make when dealing with text layout and how these tests might catch them (e.g., incorrect assumptions about caret positioning around spaces, the behavior of `::first-letter`).
这个文件 `layout_text_fragment_test.cc` 是 Chromium Blink 引擎中用于测试 `LayoutTextFragment` 类的单元测试文件。`LayoutTextFragment` 类负责表示布局树中一段连续的文本。这个测试文件的主要功能是验证 `LayoutTextFragment` 类的各种方法是否按照预期工作，特别是在处理文本偏移、插入符位置和与 CSS `::first-letter` 伪元素交互时的行为。

以下是这个文件中的主要功能以及与 JavaScript、HTML、CSS 的关系，逻辑推理和常见错误示例：

**功能列表:**

1. **`CaretMinOffset()` 和 `CaretMaxOffset()` 测试:**  测试获取文本片段中插入符的最小和最大可能偏移量。这对于实现文本编辑和选择功能至关重要。
2. **`ResolvedTextLength()` 测试:** 测试获取文本片段解析后的长度，这可能与实际字符串长度不同，例如，考虑了空格的折叠等情况。
3. **`ContainsCaretOffset()` 测试:** 测试判断给定的插入符偏移量是否位于文本片段内部。
4. **`IsBeforeNonCollapsedCharacter()` 和 `IsAfterNonCollapsedCharacter()` 测试:** 测试判断在给定的偏移量之前或之后是否存在非折叠的字符。这对于处理空格和换行符的布局至关重要。
5. **与 `::first-letter` 伪元素交互测试:** 测试当文本节点关联有 `::first-letter` 伪元素时，`LayoutTextFragment` 的行为，例如如何分割文本片段以及更新布局树。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:** 测试用例通过 `SetBodyInnerHTML()` 函数设置 HTML 结构，例如创建包含特定文本内容的 `div` 元素。
    *   **例子:**  `<div id='target' style='font-size: 10px;'>foo</div>`  这个 HTML 代码定义了一个包含文本 "foo" 的 `div` 元素，并设置了字体大小。测试用例会基于这个 HTML 结构来测试 `LayoutTextFragment` 的行为。
*   **CSS:** 测试用例使用了 CSS 的 `::first-letter` 伪元素来测试 `LayoutTextFragment` 如何处理首字母的特殊样式。
    *   **例子:** `<style>#target::first-letter{color:red}</style>` 这个 CSS 规则将 id 为 `target` 的元素的第一个字母设置为红色。测试用例会验证 `LayoutTextFragment` 是否正确地将首字母和剩余文本分割，并且首字母的样式是否被正确应用。
*   **JavaScript:** 虽然这个测试文件本身是 C++ 代码，用于测试 Blink 引擎的内部实现，但 `LayoutTextFragment` 的功能直接影响 JavaScript 中与文本操作相关的 API 的行为，例如：
    *   **Selection API:**  `CaretMinOffset()` 和 `CaretMaxOffset()` 的测试直接关系到用户在网页上进行文本选择时的起始和结束位置的计算。JavaScript 的 `Selection` 对象依赖于这些底层的布局信息。
    *   **Range API:** JavaScript 的 `Range` 对象也需要知道文本节点中字符的偏移量，`LayoutTextFragment` 提供的这些信息是构建 `Range` 的基础。
    *   **`textContent` 和 `innerText`:** 当 JavaScript 代码修改元素的文本内容时，Blink 引擎会更新布局树，这可能涉及到创建或修改 `LayoutTextFragment` 对象。测试用例 `SetTextWithFirstLetter` 就模拟了这种场景。

**逻辑推理 (假设输入与输出):**

*   **假设输入:**  HTML 内容为 `<div id='target'>(f)oo</div>`，并且存在针对 `#target::first-letter` 的 CSS 样式。
*   **输出:**
    *   `GetFirstLetter()->CaretMinOffset()` 应该返回 `0` (插入符在 '(' 之前)。
    *   `GetFirstLetter()->CaretMaxOffset()` 应该返回 `3` (插入符在 ')' 之后)。
    *   `GetRemainingText()->CaretMinOffset()` 应该返回 `0` (剩余文本的起始偏移量)。
    *   `GetRemainingText()->CaretMaxOffset()` 应该返回 `2` (剩余文本 "oo" 的长度)。
    *   `GetFirstLetter()->ResolvedTextLength()` 应该返回 `3` (包含括号的第一个字母片段的长度)。
    *   `GetRemainingText()->ResolvedTextLength()` 应该返回 `2` ("oo" 的长度)。
    *   `GetFirstLetter()->ContainsCaretOffset(1)` 应该返回 `true` (插入符在 'f' 之前)。
    *   `GetRemainingText()->ContainsCaretOffset(0)` 应该返回 `true` (插入符在 'o' 之前)。

**用户或编程常见的使用错误举例说明:**

*   **错误地假设空格总是被保留:**  用户可能认为 `ResolvedTextLength()` 总是返回字符串的实际长度，但实际上，某些情况下空格可能会被折叠。测试用例 `ResolvedTextLengthCollapsedRemainingText` 验证了在剩余文本完全折叠的情况下，`ResolvedTextLength()` 返回 `0`。开发者在处理文本布局时需要注意这种行为。
*   **错误地计算插入符在有 `::first-letter` 时的偏移:**  开发者可能会错误地认为插入符的偏移量是相对于整个文本节点的，而没有考虑到 `::first-letter` 伪元素的存在会将文本分割成多个 `LayoutTextFragment`。测试用例通过检查 `CaretMinOffset` 和 `CaretMaxOffset` 确保在有 `::first-letter` 时，偏移量是相对于各自的文本片段计算的。
*   **在 JavaScript 中操作 DOM 后，没有考虑到布局的更新:**  例如，JavaScript 代码动态地修改了元素的文本内容，开发者可能没有意识到这会导致 `LayoutTextFragment` 对象的创建或销毁。测试用例 `SetTextWithFirstLetter` 模拟了这种情况，确保在文本内容改变后，与 `::first-letter` 相关的 `LayoutTextFragment` 能够正确更新。如果开发者依赖于旧的布局信息，可能会导致错误。
*   **在处理 `white-space` 属性时，对空格和换行的处理不当:**  `white-space` 属性会影响空格和换行的处理方式。测试用例 `ContainsCaretOffsetPreLine` 测试了 `white-space: pre-line` 的情况，确保插入符偏移的计算在这种情况下也是正确的。开发者需要正确理解不同 `white-space` 属性值的含义。

总而言之，`layout_text_fragment_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎在处理文本布局时的正确性，特别是涉及到插入符位置、文本长度以及与 CSS `::first-letter` 伪元素的交互。这些测试对于保证网页的文本渲染和交互行为符合预期至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_text_fragment_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class LayoutTextFragmentTest : public RenderingTest {
 protected:
  void SetUp() override {
    RenderingTest::SetUp();
    GetDocument().head()->setInnerHTML(
        "<style>#target::first-letter{color:red}</style>");
  }

  void SetBasicBody(const char* message) {
    SetBodyInnerHTML(String::Format(
        "<div id='target' style='font-size: 10px;'>%s</div>", message));
  }

  void SetAhemBody(const char* message, const unsigned width) {
    SetBodyInnerHTML(String::Format(
        "<div id='target' style='font: 10px Ahem; width: %uem'>%s</div>", width,
        message));
  }

  const LayoutTextFragment* GetRemainingText() const {
    return To<LayoutTextFragment>(
        GetElementById("target")->firstChild()->GetLayoutObject());
  }

  const LayoutTextFragment* GetFirstLetter() const {
    return To<LayoutTextFragment>(
        AssociatedLayoutObjectOf(*GetElementById("target")->firstChild(), 0));
  }
};

TEST_F(LayoutTextFragmentTest, Basics) {
  SetBasicBody("foo");

  EXPECT_EQ(0, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(1, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(1u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(0));

  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(2, GetRemainingText()->CaretMaxOffset());
  EXPECT_EQ(2u, GetRemainingText()->ResolvedTextLength());
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(0));
}

TEST_F(LayoutTextFragmentTest, CaretMinMaxOffset) {
  SetBasicBody("(f)oo");
  EXPECT_EQ(0, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(3, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(2, GetRemainingText()->CaretMaxOffset());

  SetBasicBody("  (f)oo");
  EXPECT_EQ(2, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(5, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(2, GetRemainingText()->CaretMaxOffset());

  SetBasicBody("(f)oo  ");
  EXPECT_EQ(0, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(3, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(2, GetRemainingText()->CaretMaxOffset());

  SetBasicBody(" (f)oo  ");
  EXPECT_EQ(1, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(4, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(2, GetRemainingText()->CaretMaxOffset());
}

TEST_F(LayoutTextFragmentTest, CaretMinMaxOffsetSpacesInBetween) {
  SetBasicBody("(f)  oo");
  EXPECT_EQ(0, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(3, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(4, GetRemainingText()->CaretMaxOffset());

  SetBasicBody("  (f)  oo");
  EXPECT_EQ(2, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(5, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(4, GetRemainingText()->CaretMaxOffset());

  SetBasicBody("(f)  oo  ");
  EXPECT_EQ(0, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(3, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(4, GetRemainingText()->CaretMaxOffset());

  SetBasicBody(" (f)  oo  ");
  EXPECT_EQ(1, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(4, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(4, GetRemainingText()->CaretMaxOffset());
}

TEST_F(LayoutTextFragmentTest, CaretMinMaxOffsetCollapsedRemainingText) {
  // Tests if the NG implementation matches the legacy behavior that, when the
  // remaining text is fully collapsed, its CaretMin/MaxOffset() return 0 and
  // FragmentLength().

  SetBasicBody("(f)  ");
  EXPECT_EQ(0, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(3, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(2, GetRemainingText()->CaretMaxOffset());

  SetBasicBody("  (f)  ");
  EXPECT_EQ(2, GetFirstLetter()->CaretMinOffset());
  EXPECT_EQ(5, GetFirstLetter()->CaretMaxOffset());
  EXPECT_EQ(0, GetRemainingText()->CaretMinOffset());
  EXPECT_EQ(2, GetRemainingText()->CaretMaxOffset());
}

TEST_F(LayoutTextFragmentTest, ResolvedTextLength) {
  SetBasicBody("(f)oo");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(2u, GetRemainingText()->ResolvedTextLength());

  SetBasicBody("  (f)oo");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(2u, GetRemainingText()->ResolvedTextLength());

  SetBasicBody("(f)oo  ");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(2u, GetRemainingText()->ResolvedTextLength());

  SetBasicBody(" (f)oo  ");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(2u, GetRemainingText()->ResolvedTextLength());
}

TEST_F(LayoutTextFragmentTest, ResolvedTextLengthSpacesInBetween) {
  SetBasicBody("(f)  oo");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(3u, GetRemainingText()->ResolvedTextLength());

  SetBasicBody("  (f)  oo");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(3u, GetRemainingText()->ResolvedTextLength());

  SetBasicBody("(f)  oo  ");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(3u, GetRemainingText()->ResolvedTextLength());

  SetBasicBody(" (f)  oo  ");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(3u, GetRemainingText()->ResolvedTextLength());
}

TEST_F(LayoutTextFragmentTest, ResolvedTextLengthCollapsedRemainingText) {
  SetBasicBody("(f)  ");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(0u, GetRemainingText()->ResolvedTextLength());

  SetBasicBody("  (f)  ");
  EXPECT_EQ(3u, GetFirstLetter()->ResolvedTextLength());
  EXPECT_EQ(0u, GetRemainingText()->ResolvedTextLength());
}

TEST_F(LayoutTextFragmentTest, ContainsCaretOffset) {
  SetBasicBody("(f)oo");
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(0));     // "|(f)oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(1));     // "(|f)oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(2));     // "(f|)oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(3));     // "(f)|oo"
  EXPECT_FALSE(GetFirstLetter()->ContainsCaretOffset(4));    // out of range
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(0));   // "(f)|oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(1));   // "(f)o|o"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(2));   // "(f)oo|"
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(3));  // out of range

  SetBasicBody("  (f)oo");
  EXPECT_FALSE(GetFirstLetter()->ContainsCaretOffset(0));   // "|  (f)oo"
  EXPECT_FALSE(GetFirstLetter()->ContainsCaretOffset(1));   // " | (f)oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(2));    // "  |(f)oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(3));    // "  (|f)oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(4));    // "  (f|)oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(5));    // "  (f)|oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(0));  // "  (f)|oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(1));  // "  (f)o|o"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(2));  // "  (f)oo|"

  SetBasicBody("(f)oo  ");
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(0));     // "|(f)oo  "
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(1));     // "(|f)oo  "
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(2));     // "(f|)oo  "
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(3));     // "(f)|oo  "
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(0));   // "(f)|oo  "
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(1));   // "(f)o|o  "
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(2));   // "(f)oo|  "
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(3));  // "(f)oo | "
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(4));  // "(f)oo  |"

  SetBasicBody(" (f)oo  ");
  EXPECT_FALSE(GetFirstLetter()->ContainsCaretOffset(0));    // "| (f)oo  "
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(1));     // " |(f)oo  "
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(2));     // " (|f)oo  "
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(3));     // " (f|)oo  "
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(4));     // " (f)|oo  "
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(0));   // " (f)|oo  "
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(1));   // " (f)o|o  "
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(2));   // " (f)oo|  "
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(3));  // " (f)oo | "
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(4));  // " (f)oo  |"
}

TEST_F(LayoutTextFragmentTest, ContainsCaretOffsetSpacesInBetween) {
  SetBasicBody("(f)   oo");
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(0));     // "|(f)   oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(1));     // "(|f)   oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(2));     // "(f|)   oo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(3));     // "(f)|   oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(0));   // "(f)|   oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(1));   // "(f) |  oo"
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(2));  // "(f)  | oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(3));   // "(f)   |oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(4));   // "(f)   o|o"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(5));   // "(f)   oo|"
}

TEST_F(LayoutTextFragmentTest, ContainsCaretOffsetPre) {
  SetBodyInnerHTML("<pre id='target'>(f)   oo\n</pre>");
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(0));     // "|(f)   oo\n"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(1));     // "(|f)   oo\n"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(2));     // "(f|)   oo\n"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(3));     // "(f)|   oo\n"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(0));   // "(f)|   oo\n"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(1));   // "(f) |  oo\n"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(2));   // "(f)  | oo\n"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(3));   // "(f)   |oo\n"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(4));   // "(f)   o|o\n"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(5));   // "(f)   oo|\n"
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(6));  // "(f)   oo\n|"
}

TEST_F(LayoutTextFragmentTest, ContainsCaretOffsetPreLine) {
  SetBodyInnerHTML("<div id='target' style='white-space: pre-line'>F \n \noo");
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(0));     // "|F \n \noo"
  EXPECT_TRUE(GetFirstLetter()->ContainsCaretOffset(1));     // "F| \n \noo"

  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(0));  // "F| \n \noo"

  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(1));   // "F |\n \noo"
  EXPECT_FALSE(GetRemainingText()->ContainsCaretOffset(2));  // "F \n| \noo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(3));   // "F \n |\noo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(4));   // "F \n \n|oo"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(5));   // "F \n \no|o"
  EXPECT_TRUE(GetRemainingText()->ContainsCaretOffset(6));   // "F \n \noo|"
}

TEST_F(LayoutTextFragmentTest, IsBeforeAfterNonCollapsedCharacterNoLineWrap) {
  // Basic tests
  SetBasicBody("foo");
  EXPECT_TRUE(GetFirstLetter()->IsBeforeNonCollapsedCharacter(0));    // "|foo"
  EXPECT_TRUE(GetFirstLetter()->IsAfterNonCollapsedCharacter(1));     // "f|oo"
  EXPECT_TRUE(GetRemainingText()->IsBeforeNonCollapsedCharacter(0));  // "f|oo"
  EXPECT_TRUE(GetRemainingText()->IsAfterNonCollapsedCharacter(2));   // "foo|"

  // Return false at layout object end/start, respectively
  EXPECT_FALSE(GetFirstLetter()->IsAfterNonCollapsedCharacter(0));     // "|foo"
  EXPECT_FALSE(GetFirstLetter()->IsBeforeNonCollapsedCharacter(1));    // "f|oo"
  EXPECT_FALSE(GetRemainingText()->IsAfterNonCollapsedCharacter(0));   // "f|oo"
  EXPECT_FALSE(GetRemainingText()->IsBeforeNonCollapsedCharacter(2));  // "foo|"

  // Consecutive spaces between first letter and remaining text
  SetBasicBody("f   bar");
  EXPECT_TRUE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(0));  // "f|   bar"
  EXPECT_FALSE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(1));  // "f |  bar"
  EXPECT_FALSE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(2));  // "f  | bar"
  EXPECT_TRUE(
      GetRemainingText()->IsAfterNonCollapsedCharacter(1));  // "f |  bar"
  EXPECT_FALSE(
      GetRemainingText()->IsAfterNonCollapsedCharacter(2));  // "f  | bar"
  EXPECT_FALSE(
      GetRemainingText()->IsAfterNonCollapsedCharacter(3));  // "f   |bar"

  // Leading spaces in first letter are collapsed
  SetBasicBody("  foo");
  EXPECT_FALSE(GetFirstLetter()->IsBeforeNonCollapsedCharacter(0));  // "|  foo"
  EXPECT_FALSE(GetFirstLetter()->IsBeforeNonCollapsedCharacter(1));  // " | foo"
  EXPECT_FALSE(GetFirstLetter()->IsAfterNonCollapsedCharacter(1));   // " | foo"
  EXPECT_FALSE(GetFirstLetter()->IsAfterNonCollapsedCharacter(2));   // "  |foo"

  // Trailing spaces in remaining text, when at the end of block, are collapsed
  SetBasicBody("foo  ");
  EXPECT_FALSE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(2));  // "foo|  "
  EXPECT_FALSE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(3));  // "foo | "
  EXPECT_FALSE(
      GetRemainingText()->IsAfterNonCollapsedCharacter(3));  // "foo | "
  EXPECT_FALSE(GetRemainingText()->IsAfterNonCollapsedCharacter(4));  // "foo |"

  // Non-collapsed space at remaining text end
  SetBasicBody("foo <span>bar</span>");
  EXPECT_TRUE(GetRemainingText()->IsBeforeNonCollapsedCharacter(
      2));  // "foo| <span>bar</span>"
  EXPECT_TRUE(GetRemainingText()->IsAfterNonCollapsedCharacter(
      3));  // "foo |<span>bar</span>"

  // Non-collapsed space as remaining text
  SetBasicBody("f <span>bar</span>");
  EXPECT_TRUE(GetRemainingText()->IsBeforeNonCollapsedCharacter(
      0));  // "f| <span>bar</span>"
  EXPECT_TRUE(GetRemainingText()->IsAfterNonCollapsedCharacter(
      1));  // "f |<span>bar</span>"

  // Collapsed space as remaining text
  SetBasicBody("f <br>");
  EXPECT_FALSE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(0));  // "f| <br>"
  EXPECT_FALSE(
      GetRemainingText()->IsAfterNonCollapsedCharacter(1));  // "f |<br>"
}

TEST_F(LayoutTextFragmentTest, IsBeforeAfterNonCollapsedLineWrapSpace) {
  LoadAhem();

  // Line wrapping in the middle of remaining text
  SetAhemBody("xx xx", 2);
  EXPECT_TRUE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(1));         // "xx| xx"
  EXPECT_TRUE(GetRemainingText()->IsAfterNonCollapsedCharacter(2));  // "xx |xx"

  // Line wrapping at remaining text start
  SetAhemBody("(x xx", 2);
  EXPECT_TRUE(
      GetRemainingText()->IsBeforeNonCollapsedCharacter(0));         // "(x| xx"
  EXPECT_TRUE(GetRemainingText()->IsAfterNonCollapsedCharacter(1));  // "(x |xx"

  // Line wrapping at remaining text end
  SetAhemBody("xx <span>xx</span>", 2);
  EXPECT_TRUE(GetRemainingText()->IsBeforeNonCollapsedCharacter(
      1));  // "xx| <span>xx</span>"
  EXPECT_TRUE(GetRemainingText()->IsAfterNonCollapsedCharacter(
      2));  // "xx |<span>xx</span>"

  // Entire remaining text as line wrapping
  SetAhemBody("(x <span>xx</span>", 2);
  EXPECT_TRUE(GetRemainingText()->IsBeforeNonCollapsedCharacter(
      0));  // "(x| <span>xx</span>"
  EXPECT_TRUE(GetRemainingText()->IsAfterNonCollapsedCharacter(
      1));  // "(x |<span>xx</span>"
}

TEST_F(LayoutTextFragmentTest, SetTextWithFirstLetter) {
  // Note: |V8TestingScope| is needed for |Text::splitText()|.
  V8TestingScope scope;

  SetBodyInnerHTML(
      "<style>div::first-letter {color: red;}</style>"
      "<div id=sample>a</div>");
  const Element& sample = *GetElementById("sample");
  // |letter_x| is "a" then "" finally "x"
  Text& letter_x = *To<Text>(sample.firstChild());
  ASSERT_TRUE(letter_x.GetLayoutObject()->IsTextFragment());
  EXPECT_TRUE(letter_x.GetLayoutObject()->GetFirstLetterPart());
  EXPECT_TRUE(To<LayoutTextFragment>(letter_x.GetLayoutObject())
                  ->IsRemainingTextLayoutObject());
  ASSERT_TRUE(letter_x.GetLayoutObject()->GetFirstLetterPart());
  EXPECT_EQ(
      "a", letter_x.GetLayoutObject()->GetFirstLetterPart()->TransformedText());

  // Make <div>"" "a"</div>
  Text& letter_a = *letter_x.splitText(0, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(letter_a.GetLayoutObject()->IsTextFragment())
      << "'a' is still first-letter";
  EXPECT_TRUE(letter_a.GetLayoutObject()->GetFirstLetterPart());
  EXPECT_TRUE(To<LayoutTextFragment>(letter_a.GetLayoutObject())
                  ->IsRemainingTextLayoutObject());
  ASSERT_TRUE(letter_a.GetLayoutObject()->GetFirstLetterPart());
  EXPECT_EQ(
      "a", letter_a.GetLayoutObject()->GetFirstLetterPart()->TransformedText());
  EXPECT_FALSE(letter_x.GetLayoutObject())
      << "We don't have layout text for empty Text node.";

  // Make <div>"x" "a"</div>
  letter_x.setTextContent("x");
  UpdateAllLifecyclePhasesForTest();

  // See |FirstLetterPseudoElement::DetachLayoutTree()| which updates remaining
  // part |LayoutTextFragment|.
  EXPECT_TRUE(letter_a.GetLayoutObject()->IsTextFragment())
      << "We still use LayoutTextFragment for 'a'";
  EXPECT_FALSE(letter_a.GetLayoutObject()->GetFirstLetterPart());
  EXPECT_FALSE(To<LayoutTextFragment>(letter_a.GetLayoutObject())
                   ->IsRemainingTextLayoutObject());
  EXPECT_FALSE(To<LayoutTextFragment>(letter_a.GetLayoutObject())
                   ->GetFirstLetterPseudoElement());
  ASSERT_TRUE(letter_x.GetLayoutObject()->IsTextFragment())
      << "'x' is first letter-part";
  EXPECT_TRUE(To<LayoutTextFragment>(letter_x.GetLayoutObject())
                  ->IsRemainingTextLayoutObject());
  ASSERT_TRUE(letter_x.GetLayoutObject()->GetFirstLetterPart());
  EXPECT_EQ(
      "x", letter_x.GetLayoutObject()->GetFirstLetterPart()->TransformedText());
}

// For http://crbug.com/984389
TEST_F(LayoutTextFragmentTest, SplitTextWithZero) {
  // Note: |V8TestingScope| is needed for |Text::splitText()|.
  V8TestingScope scope;

  SetBodyInnerHTML(
      "<style>div::first-letter {color: red;}</style>"
      "<div><b id=sample> x y</b></div>");
  const Element& sample = *GetElementById("sample");
  // Make " " "x y"
  To<Text>(sample.firstChild())->splitText(1, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  // Make "" " " "x y"
  To<Text>(sample.firstChild())->splitText(0, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  Text& xy = To<Text>(*sample.lastChild());
  FirstLetterPseudoElement& first_letter_element =
      *To<LayoutTextFragment>(xy.GetLayoutObject())
           ->GetFirstLetterPseudoElement();
  EXPECT_EQ(first_letter_element.GetLayoutObject(),
            xy.GetLayoutObject()->PreviousSibling())
      << "first-letter remaining part should be next to first-letter part";
}

}  // namespace blink

"""

```