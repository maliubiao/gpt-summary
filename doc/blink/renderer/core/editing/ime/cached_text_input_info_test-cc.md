Response:
My thinking process to analyze the given C++ test file goes like this:

1. **Understand the Goal:** The request asks for a functional description of the `cached_text_input_info_test.cc` file in the Chromium Blink engine. It also requests connections to web technologies (HTML, CSS, JavaScript), logical reasoning examples, common user errors, and debugging information.

2. **Identify the Core Functionality:**  The filename itself, `cached_text_input_info_test.cc`, strongly suggests this file contains tests for the `CachedTextInputInfo` class. Looking at the includes confirms this. The `#include "third_party/blink/renderer/core/editing/ime/cached_text_input_info.h"` is the most important clue. The other includes hint at what aspects of `CachedTextInputInfo` are being tested (DOM elements, editing, selections, input methods, layout).

3. **Analyze the Test Structure:** The file uses the Google Test framework (`TEST_F`). Each `TEST_F` defines an individual test case. The `CachedTextInputInfoTest` class inherits from `EditingTestBase`, indicating it's a unit test for editing-related functionality. The protected methods `GetCachedTextInputInfo()` and `GetInputMethodController()` are helpers to access the class under test and its dependencies.

4. **Examine Individual Test Cases:**  I will go through each `TEST_F` and determine what it's testing:

    * **`Basic`:**  Tests basic text retrieval and selection within a `contenteditable` div. It checks if the cached text and selection offsets are correctly updated after adding text.
    * **`InlineElementEditable`:** Tests handling of inline editable elements (`<span>`) containing other elements (`<img>`). It specifically checks the replacement character (`\uFFFC`) for the image and updates after replacing the image with text.
    * **`PlaceholderBRInTextArea`:** Focuses on `<textarea>` elements and how placeholder `<br>` tags are handled. It verifies that the newline from a placeholder `<br>` isn't included in the cached text.
    * **`PlaceholderBROnlyInTextArea`:** Similar to the previous test, but when the `<textarea>` *only* contains a placeholder `<br>`. It verifies an empty string is returned as the cached text.
    * **`RelayoutBoundary`:** Tests the impact of layout boundaries (using `contain: strict`) on text input information. It ensures that changes within a relayout boundary are correctly reflected.
    * **`PositionAbsolute`:** Tests elements with `position: absolute`. It verifies the correct text and selection offsets, including updates after inserting text.
    * **`ShadowTree`:** Tests scenarios involving shadow DOM. It checks if selection and text retrieval work correctly across shadow boundaries, especially after modifications to the shadow tree.
    * **`VisibilityHiddenToVisible`:** Tests the effect of changing the `visibility` CSS property from `hidden` to `visible`. It confirms that initially hidden text is excluded and then included after becoming visible.
    * **`VisibilityVisibleToHidden`:** Tests the opposite of the previous case, changing `visibility` from `visible` to `hidden`. It verifies that initially visible text is excluded after being hidden.

5. **Identify Connections to Web Technologies:**

    * **HTML:** The tests heavily use HTML elements like `<div>`, `<span>`, `<img>`, `<textarea>`, `<p>`, `<b>`, `<template>`. The `contenteditable` attribute is central to many tests, representing user-editable areas.
    * **CSS:**  The `InlineElementEditable`, `RelayoutBoundary`, `PositionAbsolute`, and the visibility tests directly interact with CSS properties (or the lack thereof, implicitly).
    * **JavaScript:** While the test file is C++, it tests functionality directly related to how a web browser handles text input and manipulation, which are common tasks triggered by JavaScript interactions on a web page. For instance, the `execCommand` calls are JavaScript-like actions.

6. **Develop Logical Reasoning Examples:**  For each relevant test, I can create a hypothetical input (HTML structure and user interaction) and the expected output (cached text and selection range). This clarifies the test's purpose.

7. **Consider Common User Errors:** I will think about what mistakes a web developer might make when dealing with text input or dynamic content that these tests might be implicitly guarding against. This often involves assumptions about how the browser handles specific edge cases.

8. **Outline Debugging Steps:** I will consider how a developer might end up looking at this code during debugging. This often involves understanding the user's actions that led to an unexpected behavior related to text input or IME.

9. **Structure the Answer:**  Finally, I organize the information logically, starting with a general overview of the file's purpose and then diving into specifics for each test case, connecting them to web technologies, providing examples, and considering user errors and debugging. I use headings and bullet points for clarity.

By following these steps, I can comprehensively analyze the given C++ test file and provide a detailed explanation of its functionality and its relevance to web technologies.
这个文件 `cached_text_input_info_test.cc` 是 Chromium Blink 引擎中用于测试 `CachedTextInputInfo` 类的单元测试文件。`CachedTextInputInfo` 类的主要功能是**缓存与当前文本输入相关的各种信息，以便在 IME（Input Method Editor，输入法编辑器）交互过程中高效地访问这些信息，而无需每次都重新计算。**

让我们分解一下它的功能，并解释它与 JavaScript、HTML 和 CSS 的关系，以及一些逻辑推理、用户错误和调试线索。

**文件功能：**

1. **测试 `CachedTextInputInfo` 类的核心功能:**  这个文件中的各个 `TEST_F` 用例旨在验证 `CachedTextInputInfo` 类能否正确地捕获和更新以下信息：
   - **当前可编辑元素的文本内容 (`GetText()`):**  获取用户正在编辑的文本内容。
   - **当前选区的偏移量 (`GetSelectionOffsets()`):**  获取当前光标或选区的起始和结束位置，以字符为单位。

2. **测试在不同 DOM 结构和样式下的行为:**  测试用例覆盖了各种 HTML 结构和 CSS 样式，以确保 `CachedTextInputInfo` 在复杂场景下也能正常工作，例如：
   - `contenteditable` 属性的元素。
   - 内联元素中的可编辑内容。
   - `<textarea>` 元素及其占位符。
   - 包含 relayout boundary 的元素。
   - 具有 `position: absolute` 样式的元素。
   - 涉及 Shadow DOM 的场景。
   - `visibility` CSS 属性变化的影响。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  `CachedTextInputInfo` 的核心作用是理解和处理 HTML 结构中的文本内容和选区。测试用例大量使用了 HTML 元素，如 `<div>`, `<span>`, `<img>`, `<textarea>`, `<p>`, `<b>`, `<template>` 等，以及 `contenteditable` 属性，这些都是用户在网页上进行文本输入的基础。
    * **举例:**  `SetSelectionTextToBody("<div contenteditable id=\"sample\">a|b</div>")`  这段代码设置了测试页面的 HTML 结构，创建了一个可编辑的 `div` 元素，并设置了初始的选区（`|` 表示光标位置）。

* **CSS:**  CSS 样式会影响元素的布局和渲染，进而影响文本内容的呈现方式和选区的计算。`CachedTextInputInfo` 需要能够正确处理这些样式带来的影响。
    * **举例:**  `TEST_F(CachedTextInputInfoTest, PositionAbsolute)` 测试用例涉及到 `position: absolute` 样式，验证了在绝对定位元素中插入文本后，缓存的文本和选区偏移量是否正确。
    * **举例:**  `TEST_F(CachedTextInputInfoTest, VisibilityHiddenToVisible)` 和 `TEST_F(CachedTextInputInfoTest, VisibilityVisibleToHidden)` 测试用例验证了 `visibility` CSS 属性的变化如何影响 `CachedTextInputInfo` 捕获的文本内容。当元素被设置为 `visibility: hidden` 时，其包含的文本应该被排除在外。

* **JavaScript:**  虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能与 JavaScript 在网页上处理文本输入息息相关。JavaScript 可以通过 DOM API 修改 HTML 结构和 CSS 样式，这些修改会影响到文本内容和选区，而 `CachedTextInputInfo` 需要能够反映这些变化。
    * **举例:**  JavaScript 可以动态地向 `contenteditable` 元素中插入或删除文本，修改元素的 `visibility` 属性等。这些操作会触发 Blink 引擎内部对 `CachedTextInputInfo` 的更新。
    * **间接关系:** 当用户在网页上使用 IME 输入时，浏览器的输入法处理逻辑（通常是 C++ 代码）会与渲染引擎中的 `CachedTextInputInfo` 交互。JavaScript 代码可能会监听用户的输入事件，但最终的文本处理和状态维护涉及到 `CachedTextInputInfo`。

**逻辑推理的例子（假设输入与输出）：**

**假设输入 (针对 `Basic` 测试用例):**

1. **初始 HTML:** `<div contenteditable id="sample">ab</div>`
2. **用户操作:** 将光标移动到 'a' 和 'b' 之间。
3. **Blink 引擎内部调用:**  `GetInputMethodController().GetSelectionOffsets()` 和 `GetCachedTextInputInfo().GetText()`

**预期输出:**

* `GetInputMethodController().GetSelectionOffsets()` 返回 `PlainTextRange(1, 1)`  (光标在索引 1 的位置，起始和结束相同)。
* `GetCachedTextInputInfo().GetText()` 返回 `"ab"`。

**假设输入 (针对 `VisibilityHiddenToVisible` 测试用例):**

1. **初始 HTML:** `<div contenteditable id=sample><b id=target style='visibility: hidden'>A</b><b>Z</b></div>`，光标在 'Z' 的起始位置。
2. **Blink 引擎内部调用:** `GetCachedTextInputInfo().GetText()` 在 `visibility: hidden` 时。
3. **用户操作:** JavaScript 代码将 `target` 元素的 `visibility` 属性设置为 `visible`。
4. **Blink 引擎内部调用:** `GetCachedTextInputInfo().GetText()` 在 `visibility: visible` 之后。

**预期输出:**

* 在 `visibility: hidden` 时，`GetCachedTextInputInfo().GetText()` 返回 `"Z"` (隐藏的 'A' 被排除)。
* 在 `visibility: visible` 后，`GetCachedTextInputInfo().GetText()` 返回 `"AZ"`。

**涉及用户或编程常见的使用错误：**

1. **误判可见性:**  开发者可能错误地认为 `display: none` 和 `visibility: hidden` 对 `CachedTextInputInfo` 的影响相同。`CachedTextInputInfo` 会排除 `visibility: hidden` 的内容，但通常也会排除 `display: none` 的内容（因为它们不参与布局）。理解这两种属性的区别对于正确处理 IME 输入至关重要。

2. **动态修改 DOM 但未触发更新:** 如果 JavaScript 代码动态地修改了 `contenteditable` 元素的内容或结构，但 Blink 引擎没有及时更新 `CachedTextInputInfo`，可能会导致 IME 输入出现异常。通常，用户的光标移动或输入操作会触发必要的更新。

3. **在 Shadow DOM 中处理输入时的上下文错误:** 在使用 Shadow DOM 的组件中，开发者可能错误地认为可以直接访问 Shadow Host 外部的文本内容。`CachedTextInputInfo` 需要能够正确地处理 Shadow DOM 的边界，确保只缓存与当前焦点元素相关的文本。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用某个网页时遇到 IME 输入问题，例如：输入的字符没有正确显示，或者选区位置不正确。作为调试线索，我们可以追溯用户的操作：

1. **用户在网页的某个可编辑区域（例如，`input` 元素、`textarea` 元素或 `contenteditable` 元素）点击或移动光标。** 这一步会设置当前页面的焦点和选区。

2. **用户激活输入法并开始输入字符。** 操作系统会将用户的输入事件传递给浏览器。

3. **Blink 引擎的 IME 处理模块（InputMethodController）接收到输入事件。**  为了处理 IME 输入，`InputMethodController` 需要知道当前的文本内容和选区状态。

4. **`InputMethodController` 会访问 `CachedTextInputInfo` 来获取缓存的文本内容和选区信息。** 如果缓存的信息是过时的或不正确的，就会导致 IME 输入出现问题。

5. **在某些情况下，例如 DOM 结构或样式发生变化后，`CachedTextInputInfo` 需要被更新。**  这个更新过程可能涉及到遍历 DOM 树来重新计算文本内容和选区偏移量。

**调试线索：**

* **检查用户的操作路径:** 了解用户是如何一步步地聚焦到可编辑元素并开始输入的。
* **检查 DOM 结构和样式:**  确认当前可编辑元素的 HTML 结构和 CSS 样式是否符合预期，特别是 `contenteditable` 属性、`visibility`、`display` 和 `position` 等属性。
* **断点调试 C++ 代码:**  在 `blink/renderer/core/editing/ime/cached_text_input_info.cc` 文件中的相关函数（例如 `GetText()`, `GetSelectionOffsets()`, 以及更新缓存的函数）设置断点，查看在用户操作的不同阶段，`CachedTextInputInfo` 中缓存的数据是否正确。
* **查看日志输出:** Blink 引擎可能会有与 IME 相关的日志输出，可以帮助理解输入处理的流程。
* **模拟测试用例:**  如果问题可以在特定的 HTML 结构和用户操作下复现，可以尝试编写类似的单元测试用例添加到 `cached_text_input_info_test.cc` 中，以便更方便地调试和修复问题。

总而言之，`cached_text_input_info_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎能够正确地处理各种复杂场景下的文本输入，并为 IME 功能的稳定性和可靠性提供了保障。理解这个文件的功能和测试用例可以帮助开发者更好地理解浏览器内部的文本输入处理机制，并有助于调试相关的 bug。

### 提示词
```
这是目录为blink/renderer/core/editing/ime/cached_text_input_info_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/ime/cached_text_input_info.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"

namespace blink {

class CachedTextInputInfoTest : public EditingTestBase {
 protected:
  CachedTextInputInfo& GetCachedTextInputInfo() {
    return GetInputMethodController().GetCachedTextInputInfoForTesting();
  }

  InputMethodController& GetInputMethodController() {
    return GetFrame().GetInputMethodController();
  }
};

TEST_F(CachedTextInputInfoTest, Basic) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable id=\"sample\">a|b</div>"),
      SetSelectionOptions());
  const Element& sample = *GetElementById("sample");

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(1, 1),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("ab", GetCachedTextInputInfo().GetText());

  To<Text>(sample.firstChild())->appendData("X");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(1, 1),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("abX", GetCachedTextInputInfo().GetText());
}

// http://crbug.com/1382425
TEST_F(CachedTextInputInfoTest, InlineElementEditable) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<span contenteditable><img>|a</img></span>"),
      SetSelectionOptions());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(1, 1),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ(String(u"\uFFFCa"), GetCachedTextInputInfo().GetText());

  auto& span = *GetDocument().QuerySelector(AtomicString("span"));
  span.replaceChild(Text::Create(GetDocument(), "12345"), span.firstChild());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(5, 5),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("12345a", GetCachedTextInputInfo().GetText());
}

// http://crbug.com/1194349
TEST_F(CachedTextInputInfoTest, PlaceholderBRInTextArea) {
  SetBodyContent("<textarea id=target>abc\n</textarea>");
  auto& target = *To<TextControlElement>(GetElementById("target"));

  // Inner editor is <div>abc<br></div>.
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position::LastPositionInNode(*target.InnerEditorElement()))
          .Build(),
      SetSelectionOptions());

  EXPECT_EQ(PlainTextRange(4, 4),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("abc\n", GetCachedTextInputInfo().GetText())
      << "We should not emit a newline for placeholder <br>";
}

// http://crbug.com/1197801
TEST_F(CachedTextInputInfoTest, PlaceholderBROnlyInTextArea) {
  SetBodyContent("<textarea id=target></textarea>");
  auto& target = *To<TextControlElement>(GetElementById("target"));
  target.Focus();
  GetDocument().execCommand("insertparagraph", false, "", ASSERT_NO_EXCEPTION);
  GetDocument().execCommand("delete", false, "", ASSERT_NO_EXCEPTION);

  // Inner editor is <div><br></div>.
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position::LastPositionInNode(*target.InnerEditorElement()))
          .Build(),
      SetSelectionOptions());

  EXPECT_EQ(PlainTextRange(0, 0),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("", GetCachedTextInputInfo().GetText());
}

TEST_F(CachedTextInputInfoTest, RelayoutBoundary) {
  InsertStyleElement(
      "#sample { contain: strict; width: 100px; height: 100px; }");
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody(
          "<div contenteditable><div id=\"sample\">^a|b</div>"),
      SetSelectionOptions());
  const Element& sample = *GetElementById("sample");
  ASSERT_TRUE(sample.GetLayoutObject()->IsRelayoutBoundary());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(0, 1),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("ab", GetCachedTextInputInfo().GetText());

  To<Text>(sample.firstChild())->appendData("X");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(0, 1),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("abX", GetCachedTextInputInfo().GetText());
}

// http://crbug.com/1292516
TEST_F(CachedTextInputInfoTest, PositionAbsolute) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody(
          "<div contenteditable>"
          "<p id=sample style='position:absolute'>ab|<b>cd</b></p>"
          "</div>"),
      SetSelectionOptions());

  const auto& sample = *GetElementById("sample");
  auto& text_ab = *To<Text>(sample.firstChild());
  const auto& text_cd = *To<Text>(sample.lastChild()->firstChild());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(2, 2),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("abcd", GetCachedTextInputInfo().GetText());

  // Insert "AB" after "ab"
  text_ab.appendData("AB");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(2, 2),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("abABcd", GetCachedTextInputInfo().GetText());

  // Move caret after "cd"
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(text_cd, 2)).Build(),
      SetSelectionOptions());

  // Insert "CD" after "cd"
  GetDocument().execCommand("insertText", false, "CD", ASSERT_NO_EXCEPTION);

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(8, 8),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("abABcdCD", GetCachedTextInputInfo().GetText());
}

// http://crbug.com/1228373
TEST_F(CachedTextInputInfoTest, ShadowTree) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<div id=host><template data-mode=open>"
                             "<a>012</a><b>3^45</b>67|8"
                             "</template></div>"),
      SetSelectionOptions());

  EXPECT_EQ(PlainTextRange(4, 8),
            GetInputMethodController().GetSelectionOffsets());

  // Change shadow tree to "XYZ<a>012</a><b>345</b>678"
  auto& shadow_root = *GetElementById("host")->GetShadowRoot();
  shadow_root.insertBefore(Text::Create(GetDocument(), "XYZ"),
                           shadow_root.firstChild());

  // Ask |CachedTextInputInfo| to compute |PlainTextRange| for selection.
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(*To<Text>(shadow_root.lastChild()), 0))
          .Build(),
      SetSelectionOptions());

  EXPECT_EQ(PlainTextRange(9, 9),
            GetInputMethodController().GetSelectionOffsets());
}

// http://crbug.com/1228635
TEST_F(CachedTextInputInfoTest, VisibilityHiddenToVisible) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody(
          "<div contenteditable id=sample>"
          "<b id=target style='visibility: hidden'>A</b><b>^Z|</b></div>"),
      SetSelectionOptions());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(0, 1),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("Z", GetCachedTextInputInfo().GetText())
      << "Texts within visibility:hidden are excluded";

  Element& target = *GetElementById("target");
  target.style()->setProperty(GetDocument().GetExecutionContext(), "visibility",
                              "visible", "", ASSERT_NO_EXCEPTION);

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(1, 2),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("AZ", GetCachedTextInputInfo().GetText());
}

// http://crbug.com/1228635
TEST_F(CachedTextInputInfoTest, VisibilityVisibleToHidden) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody(
          "<div contenteditable id=sample>"
          "<b id=target style='visibility: visible'>A</b><b>^Z|</b></div>"),
      SetSelectionOptions());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(1, 2),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("AZ", GetCachedTextInputInfo().GetText());

  Element& target = *GetElementById("target");
  target.style()->setProperty(GetDocument().GetExecutionContext(), "visibility",
                              "hidden", "", ASSERT_NO_EXCEPTION);

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  EXPECT_EQ(PlainTextRange(0, 1),
            GetInputMethodController().GetSelectionOffsets());
  EXPECT_EQ("Z", GetCachedTextInputInfo().GetText())
      << "Texts within visibility:hidden are excluded";
}

}  // namespace blink
```