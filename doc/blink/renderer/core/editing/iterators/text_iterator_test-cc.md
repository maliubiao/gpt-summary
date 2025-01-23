Response:
My goal is to analyze the provided C++ code snippet from Chromium's Blink rendering engine and extract its functionality, relating it to web technologies where applicable, and identifying potential usage errors. Since this is part 1 of 2, I also need to summarize its overall purpose.

Here's a breakdown of the thinking process:

1. **Identify the Core File:** The file name `text_iterator_test.cc` immediately suggests this is a unit test file for something related to iterating over text. The path `blink/renderer/core/editing/iterators/` confirms it's specifically testing text iterators within the editing context of Blink.

2. **Analyze Includes:** The included headers provide valuable clues about the functionality being tested:
    * `text_iterator.h`:  This is the main subject under test.
    * `document.h`, `ephemeral_range.h`, `position.h`, `selection_template.h`: These relate to the DOM structure and selection/range concepts, which are fundamental to text manipulation in a browser.
    * `editing_test_base.h`: Indicates this is a test file using Blink's testing framework.
    * `local_frame_view.h`:  Deals with the rendering frame, suggesting a connection to how text is laid out and displayed.
    * `text_control_element.h`: Points to interaction with form elements like `<input>` and `<textarea>`, which handle user text input.
    * `string_builder.h`: Used for efficient string manipulation within the tests.
    * `flat_tree_traversal.h` and `node_traversal.h`: These hints at different strategies for traversing the DOM tree, one including Shadow DOM (FlatTree) and one without (DOMTree).

3. **Examine Namespace and Helper Functions:** The `blink::text_iterator_test` namespace encapsulates the test code. The helper functions like `EmitsImageAltTextBehavior()`, `EntersTextControlsBehavior()`, etc., define different configurations for the `TextIterator`, controlling how it behaves when encountering specific elements or situations (like images, text inputs, shadow DOM). The `DOMTree` and `FlatTree` structs using type aliases further reinforce the idea of testing different tree traversal strategies.

4. **Analyze the `TextIteratorTest` Class:** This is the main test fixture. The `Iterate` and `IteratePartial` template methods are key. They take a `TextIteratorBehavior` and a traversal strategy (`DOMTree` or `FlatTree`) and iterate through the DOM, accumulating the text content into a string. The `IterateWithIterator` helper performs the actual iteration. `GetBodyRange` and `TestRangeLength` are utility functions for setting up test scenarios and measuring text lengths.

5. **Scrutinize the `TEST_F` Macros:** These are the individual test cases. By examining the names and the code within each test, I can infer the specific features being tested:
    * `BasicIteration`: Simple traversal of text nodes.
    * `EmitsSmallXForTextSecurity`:  Tests how text with `text-security` style is handled.
    * `IgnoreAltTextInTextControls`/`DisplayAltTextInImageControls`: Tests handling of `alt` text in different input types.
    * `NotEnteringTextControls`/`EnteringTextControlsWithOption`: Tests whether the iterator enters the content of text input elements.
    * `NotEnteringShadowTree`/`EnteringShadowTreeWithOption`: Tests how Shadow DOM is handled.
    * `StartingAtNodeInShadowRoot`/`FinishingAtNodeInShadowRoot`: Tests starting and ending iteration within Shadow DOM.
    * `FullyClipsContents`/`IgnoresContainerClip`: Tests how CSS `overflow: hidden` affects text visibility during iteration.
    * `PlaceholderBRInTextArea`: Tests a specific edge case with `<textarea>` placeholders.
    * `EmitsReplacementCharForInput`: Tests how replaced elements (like `<img>`) are represented.
    * `RangeLength...`: Tests the accuracy of calculating the length of a text range in various scenarios (with replaced elements, multi-line text, CSS first-letter).
    * `TrainlingSpace`/`WhitespaceCollapseForReplacedElements`: Tests whitespace handling.
    * `characterAt`: Tests retrieving individual characters during iteration.
    * `EndingConditionWithDisplayNone`/`EndingConditionWithDisplayNoneInShadowTree`: Tests iterator behavior when encountering `display: none`.
    * `PreserveLeadingSpace...`: Tests handling of leading spaces.
    * `StartAtFirstLetter...`: Tests iteration starting at the `::first-letter` pseudo-element.

6. **Relate to Web Technologies:**  Based on the tested features, I can connect them to JavaScript, HTML, and CSS:
    * **JavaScript:**  JavaScript can use DOM APIs to access and manipulate text content. The `TextIterator` provides a low-level mechanism that JavaScript engines might utilize or expose indirectly. For example, methods like `textContent` or `innerText` might rely on similar iteration logic internally.
    * **HTML:** The tests extensively use HTML elements like `<p>`, `<div>`, `<span>`, `<input>`, `<textarea>`, `<img>`, and Shadow DOM constructs (`<slot>`). The `TextIterator` needs to correctly traverse and extract text from these elements.
    * **CSS:**  The tests consider CSS properties like `-webkit-text-security`, `overflow`, `display`, and pseudo-elements like `::first-letter`. This indicates the `TextIterator` is aware of styling and how it affects text rendering and visibility.

7. **Identify Potential Errors:**  By analyzing the test scenarios, I can infer potential errors developers might encounter:
    * Incorrectly calculating text range lengths, especially with replaced elements or special CSS.
    * Failing to handle Shadow DOM correctly when iterating over content.
    * Issues with whitespace normalization and handling of special characters.
    * Incorrectly determining text visibility based on CSS properties like `display: none` or `overflow: hidden`.

8. **Trace User Operations (Debugging Clues):** To understand how a user might trigger this code, I consider actions that involve text manipulation in a browser:
    * Selecting text with the mouse or keyboard.
    * Copying and pasting text.
    * Using assistive technologies that read screen content.
    * Interacting with form fields.
    * Rendering web pages with complex layouts or Shadow DOM.

9. **Summarize Functionality (Part 1):**  Finally, I synthesize the information gathered to create a concise summary of the file's purpose: testing the `TextIterator` class, which is responsible for traversing and extracting text content from the DOM, taking into account various factors like element types, CSS styling, and Shadow DOM.

By following these steps, I can systematically analyze the code and generate a comprehensive explanation of its functionality, its relation to web technologies, and potential usage scenarios.
这是 Chromium Blink 引擎源代码文件 `text_iterator_test.cc` 的第一部分，它的主要功能是**测试 `TextIterator` 及其相关类的功能**。`TextIterator` 是一个用于在 DOM 树中迭代文本内容的类，它允许按照一定的规则遍历文本节点、处理特殊元素（如图片、表单控件）以及考虑 CSS 样式的影响。

**功能归纳：**

1. **`TextIterator` 的核心功能测试:**  测试 `TextIterator` 能否正确地遍历 DOM 树并提取文本内容。这包括：
    * 基本的文本节点遍历。
    * 处理换行符。
    * 处理 `<br>` 标签。
2. **`TextIteratorBehavior` 的各种选项测试:**  `TextIteratorBehavior` 类允许配置 `TextIterator` 的行为。测试涵盖了各种选项，例如：
    * `EmitsImageAltTextBehavior()`: 是否输出图片的 `alt` 属性值。
    * `EntersTextControlsBehavior()`: 是否进入表单控件（如 `<input>`, `<textarea>`）内部。
    * `EntersOpenShadowRootsBehavior()`: 是否进入 Shadow DOM。
    * `EmitsObjectReplacementCharacterBehavior()`: 是否对可替换元素（如 `<img>`）输出 U+FFFC 对象替换字符。
    * `EmitsSmallXForTextSecurityBehavior()`: 是否对应用了 `text-security` 样式的文本输出 'x'。
    * `EmitsCharactersBetweenAllVisiblePositionsBehavior()`:  （在第一部分中未直接测试，但有定义）
    * `EmitsSpaceForNbspBehavior()`: （在第一部分中未直接测试，但有定义）
3. **不同 DOM 树遍历策略的测试:** 提供了两种遍历策略：`DOMTree` (标准的 DOM 树) 和 `FlatTree` (包含 Shadow DOM 的扁平树)。测试会针对这两种策略进行。
4. **边界情况和特殊情况的测试:**  涵盖了一些可能出现特殊行为的场景，例如：
    * 包含 `<input type='image'>` 元素。
    * 嵌套的 Shadow DOM。
    * 带有 `<slot>` 元素的 Shadow DOM。
    * CSS `overflow: hidden` 导致的元素不可见。
    * `<textarea>` 元素及其 placeholder。
    * 带有 `contenteditable` 属性的元素。
    * 带有 `::first-letter` 伪元素的元素。
5. **`TextIterator::RangeLength` 的测试:**  测试计算指定 Range 内文本长度的功能，需要考虑各种因素，如：
    * 替换元素。
    * 多行文本。
    * `::first-letter` 伪元素。
    * 前导空格。
6. **`TextIteratorAlgorithm::CharacterAt` 的测试:**  测试获取指定偏移量字符的功能。
7. **特定 Bug 的回归测试:**  例如针对 `crbug.com/630921` 的测试，确保之前修复的 bug 不会再次出现。
8. **保持空格的测试:**  测试在特定情况下（例如，带有内联元素的 `div`）能否正确地保留前导空格。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:** `TextIterator` 的核心作用是遍历 HTML 结构并提取文本。测试中大量使用了 HTML 元素，例如：
    * `<p>Hello, text</p>`: 测试基本的文本内容提取。
    * `<input type='text' value='input'>`: 测试处理表单控件及其 `value` 属性。
    * `<img src='foo.png' alt='alt'>`: 测试处理图片及其 `alt` 属性。
    * `<div id='host'>...</div><template shadowroot><span>shadow</span></template>` (虽然代码中未使用 `<template shadowroot>`, 但测试了通过 JavaScript 创建的 Shadow DOM): 测试处理 Shadow DOM 的能力。
* **CSS:** `TextIterator` 的行为会受到 CSS 样式的影响。测试中包含了以下与 CSS 相关的例子：
    * `InsertStyleElement("s {-webkit-text-security:disc;}")`:  测试 `-webkit-text-security` 属性对文本输出的影响，例如将文本替换为圆点或 'x'。
    * `<div style='overflow: hidden; width: 200px; height: 0;'>`: 测试 `overflow: hidden` 导致元素不可见时 `TextIterator` 的行为。
    * `InsertStyleElement("p::first-letter {font-size:200%;}")`: 测试 `::first-letter` 伪元素对文本长度计算的影响。
* **JavaScript:** 虽然这个 C++ 文件本身不包含 JavaScript 代码，但 `TextIterator` 的功能是为浏览器引擎服务的，而 JavaScript 可以通过 DOM API (例如 `textContent`, `innerText`, `Range` 对象等) 间接地使用到 `TextIterator` 的底层逻辑。例如：
    * 当 JavaScript 代码获取一个元素或 Range 的文本内容时，浏览器引擎内部可能就会使用类似 `TextIterator` 的机制来完成。
    * 编辑器功能（例如富文本编辑器）在处理文本插入、删除、选择等操作时，也可能依赖于类似的文本迭代和定位机制。

**逻辑推理、假设输入与输出：**

以 `TEST_F(TextIteratorTest, BasicIteration)` 为例：

* **假设输入 (HTML):** `<p>Hello, \ntext</p><p>iterator.</p>`
* **逻辑推理:** `TextIterator` 应该遍历这两个 `<p>` 元素内的文本节点，并正确地输出文本内容和换行符。
* **预期输出 (使用默认行为):** `"[Hello, ][text][\n][\n][iterator.]"`

以 `TEST_F(TextIteratorTest, EnteringTextControlsWithOption)` 为例：

* **假设输入 (HTML):** `<p>Hello <input type='text' value='input'>!</p>`
* **配置:** 使用 `EntersTextControlsBehavior()`，指示 `TextIterator` 进入表单控件。
* **逻辑推理:** `TextIterator` 应该遍历 `<p>` 元素，当遇到 `<input>` 元素时，由于配置了 `EntersTextControlsBehavior()`，它会进入 `<input>` 元素内部，并输出其 `value` 属性值。
* **预期输出 (DOMTree):** `"[Hello ][\n][input][!]"` (注意 `FlatTree` 的输出略有不同，因为它还会添加额外的换行符)。

**用户或编程常见的使用错误：**

1. **错误地假设 `TextIterator` 总是返回渲染后的最终文本:**  开发者可能会错误地认为 `TextIterator` 输出的文本总是用户在屏幕上看到的最终文本。但实际上，`TextIterator` 的行为可以通过 `TextIteratorBehavior` 进行配置，例如，可以选择是否输出图片的 `alt` 属性，是否进入表单控件等。如果开发者没有正确理解这些选项，可能会得到意料之外的结果。

    * **举例:** 开发者想获取用户在屏幕上看到的文本，但没有启用 `EmitsImageAltTextBehavior()`，那么图片的 `alt` 属性值就不会被包含在结果中，这可能不是开发者期望的。

2. **在处理 Shadow DOM 时没有考虑遍历策略:**  如果不清楚使用的是 `DOMTree` 还是 `FlatTree` 遍历，在包含 Shadow DOM 的页面上，可能会得到不同的结果。

    * **举例:**  开发者使用默认的 `DOMTree` 遍历，它不会进入 Shadow DOM，因此无法获取 Shadow DOM 内部的文本内容。如果开发者期望获取所有文本内容，就应该使用 `FlatTree` 遍历或配置 `EntersOpenShadowRootsBehavior()`。

3. **没有意识到 CSS 样式对 `TextIterator` 的影响:**  某些 CSS 样式会影响 `TextIterator` 的行为，例如 `text-security` 会导致文本被替换，`overflow: hidden` 会导致部分内容被忽略。

    * **举例:**  开发者想要获取元素的原始文本内容，但该元素应用了 `text-security: disc;`，如果没有意识到这一点，`TextIterator` 可能会返回替换后的字符（如 '●' 或 'x'），而不是原始文本。

**用户操作是如何一步步的到达这里，作为调试线索：**

`text_iterator_test.cc` 是一个单元测试文件，用户操作不会直接触发它。它是由开发者在进行 Blink 引擎的开发和测试时运行的。但是，`TextIterator` 类本身在浏览器引擎中被广泛使用，用户的各种操作可能会间接地触发 `TextIterator` 的相关逻辑：

1. **用户选择文本:** 当用户在网页上用鼠标拖拽或使用键盘选择文本时，浏览器引擎需要确定选择的范围和内容。这个过程可能会用到类似 `TextIterator` 的机制来遍历 DOM 树，确定选择的起始和结束位置，并提取选中的文本。

2. **用户进行复制/粘贴操作:** 当用户复制网页上的文本时，浏览器需要提取选中的文本内容。粘贴时，浏览器可能需要将粘贴板上的文本插入到 DOM 树的合适位置。这些操作都可能涉及到文本的遍历和处理。

3. **屏幕阅读器等辅助技术读取网页内容:** 辅助技术需要按照一定的顺序读取网页上的文本内容。浏览器引擎会使用类似 `TextIterator` 的机制来遍历 DOM 树，并按照视觉顺序或 DOM 顺序将文本内容提供给辅助技术。

4. **浏览器渲染网页:**  虽然 `TextIterator` 主要关注文本内容的提取，但它也需要考虑渲染信息（例如，哪些元素是可见的），这与浏览器的渲染过程是紧密相关的。

5. **开发者工具的使用:**  开发者在使用浏览器开发者工具查看元素属性、调试 JavaScript 代码时，某些操作（例如，查看元素的文本内容）可能会间接地触发 `TextIterator` 的相关逻辑。

**调试线索:** 如果在浏览器开发过程中，涉及到文本选择、复制粘贴、辅助功能或渲染等方面出现 bug，开发者可能会通过分析 `TextIterator` 的实现和测试用例来定位问题。例如：

* 如果发现文本选择的范围不正确，可以检查 `TextIterator` 在计算文本边界时的逻辑是否正确。
* 如果辅助功能读取的文本顺序或内容有误，可以检查 `TextIterator` 的遍历顺序和文本提取逻辑。
* 如果在特定 CSS 样式下文本处理出现异常，可以查看 `TextIterator` 是否正确地考虑了这些样式的影响。

总而言之，`text_iterator_test.cc` 通过大量的单元测试用例，确保 `TextIterator` 类在各种场景下都能正确地遍历和提取文本内容，这对于浏览器引擎的文本处理功能至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/iterators/text_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace text_iterator_test {

TextIteratorBehavior EmitsImageAltTextBehavior() {
  return TextIteratorBehavior::Builder().SetEmitsImageAltText(true).Build();
}

TextIteratorBehavior EntersTextControlsBehavior() {
  return TextIteratorBehavior::Builder().SetEntersTextControls(true).Build();
}

TextIteratorBehavior EntersOpenShadowRootsBehavior() {
  return TextIteratorBehavior::Builder().SetEntersOpenShadowRoots(true).Build();
}

TextIteratorBehavior EmitsObjectReplacementCharacterBehavior() {
  return TextIteratorBehavior::Builder()
      .SetEmitsObjectReplacementCharacter(true)
      .Build();
}

TextIteratorBehavior EmitsSmallXForTextSecurityBehavior() {
  return TextIteratorBehavior::Builder()
      .SetEmitsSmallXForTextSecurity(true)
      .Build();
}

TextIteratorBehavior EmitsCharactersBetweenAllVisiblePositionsBehavior() {
  return TextIteratorBehavior::Builder()
      .SetEmitsCharactersBetweenAllVisiblePositions(true)
      .Build();
}

TextIteratorBehavior EmitsSpaceForNbspBehavior() {
  return TextIteratorBehavior::Builder().SetEmitsSpaceForNbsp(true).Build();
}

struct DOMTree : NodeTraversal {
  using PositionType = Position;
  using TextIteratorType = TextIterator;
};

struct FlatTree : FlatTreeTraversal {
  using PositionType = PositionInFlatTree;
  using TextIteratorType = TextIteratorInFlatTree;
};

class TextIteratorTest : public EditingTestBase {
 protected:
  TextIteratorTest() = default;

  template <typename Tree>
  std::string Iterate(const TextIteratorBehavior& = TextIteratorBehavior());

  template <typename Tree>
  std::string IteratePartial(
      const typename Tree::PositionType& start,
      const typename Tree::PositionType& end,
      const TextIteratorBehavior& = TextIteratorBehavior());

  Range* GetBodyRange() const;

  int TestRangeLength(const std::string& selection_text) {
    return TextIterator::RangeLength(
        SetSelectionTextToBody(selection_text).ComputeRange());
  }

 private:
  template <typename Tree>
  std::string IterateWithIterator(typename Tree::TextIteratorType&);
};

template <typename Tree>
std::string TextIteratorTest::Iterate(
    const TextIteratorBehavior& iterator_behavior) {
  Element* body = GetDocument().body();
  using PositionType = typename Tree::PositionType;
  auto start = PositionType(body, 0);
  auto end = PositionType(body, Tree::CountChildren(*body));
  typename Tree::TextIteratorType iterator(start, end, iterator_behavior);
  return IterateWithIterator<Tree>(iterator);
}

template <typename Tree>
std::string TextIteratorTest::IteratePartial(
    const typename Tree::PositionType& start,
    const typename Tree::PositionType& end,
    const TextIteratorBehavior& iterator_behavior) {
  typename Tree::TextIteratorType iterator(start, end, iterator_behavior);
  return IterateWithIterator<Tree>(iterator);
}

template <typename Tree>
std::string TextIteratorTest::IterateWithIterator(
    typename Tree::TextIteratorType& iterator) {
  StringBuilder text_chunks;
  for (; !iterator.AtEnd(); iterator.Advance()) {
    text_chunks.Append('[');
    text_chunks.Append(iterator.GetTextState().GetTextForTesting());
    text_chunks.Append(']');
  }
  return text_chunks.ToString().Utf8();
}

Range* TextIteratorTest::GetBodyRange() const {
  Range* range = Range::Create(GetDocument());
  range->selectNode(GetDocument().body());
  return range;
}

TEST_F(TextIteratorTest, BitStackOverflow) {
  const unsigned kBitsInWord = sizeof(unsigned) * 8;
  BitStack bs;

  for (unsigned i = 0; i < kBitsInWord + 1u; i++)
    bs.Push(true);

  bs.Pop();

  EXPECT_TRUE(bs.Top());
}

TEST_F(TextIteratorTest, BasicIteration) {
  static const char* input = "<p>Hello, \ntext</p><p>iterator.</p>";
  SetBodyContent(input);
  EXPECT_EQ("[Hello, ][text][\n][\n][iterator.]", Iterate<DOMTree>());
  EXPECT_EQ("[Hello, ][text][\n][\n][iterator.]", Iterate<FlatTree>());
}

TEST_F(TextIteratorTest, EmitsSmallXForTextSecurity) {
  InsertStyleElement("s {-webkit-text-security:disc;}");
  SetBodyContent("abc<s>foo</s>baz");
  // E2 80 A2 is U+2022 BULLET
  EXPECT_EQ("[abc][xxx][baz]",
            Iterate<DOMTree>(EmitsSmallXForTextSecurityBehavior()));
  EXPECT_EQ("[abc][\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2][baz]",
            Iterate<DOMTree>(TextIteratorBehavior()));
  EXPECT_EQ("[abc][xxx][baz]",
            Iterate<FlatTree>(EmitsSmallXForTextSecurityBehavior()));
  EXPECT_EQ("[abc][\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2][baz]",
            Iterate<FlatTree>(TextIteratorBehavior()));
}

TEST_F(TextIteratorTest, IgnoreAltTextInTextControls) {
  static const char* input = "<p>Hello <input type='text' value='value'>!</p>";
  SetBodyContent(input);
  EXPECT_EQ("[Hello ][][!]", Iterate<DOMTree>(EmitsImageAltTextBehavior()));
  EXPECT_EQ("[Hello ][][!]", Iterate<FlatTree>(EmitsImageAltTextBehavior()));
}

TEST_F(TextIteratorTest, DisplayAltTextInImageControls) {
  static const char* input = "<p>Hello <input type='image' alt='alt'>!</p>";
  SetBodyContent(input);
  EXPECT_EQ("[Hello ][alt][!]", Iterate<DOMTree>(EmitsImageAltTextBehavior()));
  EXPECT_EQ("[Hello ][alt][!]", Iterate<FlatTree>(EmitsImageAltTextBehavior()));
}

TEST_F(TextIteratorTest, NotEnteringTextControls) {
  static const char* input = "<p>Hello <input type='text' value='input'>!</p>";
  SetBodyContent(input);
  EXPECT_EQ("[Hello ][][!]", Iterate<DOMTree>());
  EXPECT_EQ("[Hello ][][!]", Iterate<FlatTree>());
}

TEST_F(TextIteratorTest, EnteringTextControlsWithOption) {
  static const char* input = "<p>Hello <input type='text' value='input'>!</p>";
  SetBodyContent(input);
  EXPECT_EQ("[Hello ][\n][input][!]",
            Iterate<DOMTree>(EntersTextControlsBehavior()));
  EXPECT_EQ("[Hello ][\n][input][\n][!]",
            Iterate<FlatTree>(EntersTextControlsBehavior()));
}

TEST_F(TextIteratorTest, EnteringTextControlsWithOptionComplex) {
  static const char* input =
      "<input type='text' value='Beginning of range'><div><div><input "
      "type='text' value='Under DOM nodes'></div></div><input type='text' "
      "value='End of range'>";
  SetBodyContent(input);
  EXPECT_EQ("[\n][Beginning of range][\n][Under DOM nodes][\n][End of range]",
            Iterate<DOMTree>(EntersTextControlsBehavior()));
  EXPECT_EQ("[Beginning of range][\n][Under DOM nodes][\n][End of range]",
            Iterate<FlatTree>(EntersTextControlsBehavior()));
}

TEST_F(TextIteratorTest, NotEnteringShadowTree) {
  static const char* body_content =
      "<div>Hello, <span id='host'>text</span> iterator.</div>";
  static const char* shadow_content = "<span>shadow</span>";
  SetBodyContent(body_content);
  CreateShadowRootForElementWithIDAndSetInnerHTML(GetDocument(), "host",
                                                  shadow_content);
  // TextIterator doesn't emit "text" since its layoutObject is not created. The
  // shadow tree is ignored.
  EXPECT_EQ("[Hello, ][ iterator.]", Iterate<DOMTree>());
  EXPECT_EQ("[Hello, ][shadow][ iterator.]", Iterate<FlatTree>());
}

TEST_F(TextIteratorTest, NotEnteringShadowTreeWithNestedShadowTrees) {
  static const char* body_content =
      "<div>Hello, <span id='host-in-document'>text</span> iterator.</div>";
  static const char* shadow_content1 =
      "<span>first <span id='host-in-shadow'>shadow</span></span>";
  static const char* shadow_content2 = "<span>second shadow</span>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root1 = CreateShadowRootForElementWithIDAndSetInnerHTML(
      GetDocument(), "host-in-document", shadow_content1);
  CreateShadowRootForElementWithIDAndSetInnerHTML(
      *shadow_root1, "host-in-shadow", shadow_content2);
  EXPECT_EQ("[Hello, ][ iterator.]", Iterate<DOMTree>());
  EXPECT_EQ("[Hello, ][first ][second shadow][ iterator.]",
            Iterate<FlatTree>());
}

TEST_F(TextIteratorTest, NotEnteringShadowTreeWithContentInsertionPoint) {
  static const char* body_content =
      "<div>Hello, <span id='host'>text</span> iterator.</div>";
  static const char* shadow_content =
      "<span>shadow <slot>content</slot></span>";
  SetBodyContent(body_content);
  CreateShadowRootForElementWithIDAndSetInnerHTML(GetDocument(), "host",
                                                  shadow_content);
  // In this case a layoutObject for "text" is created, so it shows up here.
  EXPECT_EQ("[Hello, ][text][ iterator.]", Iterate<DOMTree>());
  EXPECT_EQ("[Hello, ][shadow ][text][ iterator.]", Iterate<FlatTree>());
}

TEST_F(TextIteratorTest, EnteringShadowTreeWithOption) {
  static const char* body_content =
      "<div>Hello, <span id='host'>text</span> iterator.</div>";
  static const char* shadow_content = "<span>shadow</span>";
  SetBodyContent(body_content);
  CreateShadowRootForElementWithIDAndSetInnerHTML(GetDocument(), "host",
                                                  shadow_content);
  // TextIterator emits "shadow" since entersOpenShadowRootsBehavior() is
  // specified.
  EXPECT_EQ("[Hello, ][shadow][ iterator.]",
            Iterate<DOMTree>(EntersOpenShadowRootsBehavior()));
  EXPECT_EQ("[Hello, ][shadow][ iterator.]",
            Iterate<FlatTree>(EntersOpenShadowRootsBehavior()));
}

TEST_F(TextIteratorTest, EnteringShadowTreeWithNestedShadowTreesWithOption) {
  static const char* body_content =
      "<div>Hello, <span id='host-in-document'>text</span> iterator.</div>";
  static const char* shadow_content1 =
      "<span>first <span id='host-in-shadow'>shadow</span></span>";
  static const char* shadow_content2 = "<span>second shadow</span>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root1 = CreateShadowRootForElementWithIDAndSetInnerHTML(
      GetDocument(), "host-in-document", shadow_content1);
  CreateShadowRootForElementWithIDAndSetInnerHTML(
      *shadow_root1, "host-in-shadow", shadow_content2);
  EXPECT_EQ("[Hello, ][first ][second shadow][ iterator.]",
            Iterate<DOMTree>(EntersOpenShadowRootsBehavior()));
  EXPECT_EQ("[Hello, ][first ][second shadow][ iterator.]",
            Iterate<FlatTree>(EntersOpenShadowRootsBehavior()));
}

TEST_F(TextIteratorTest,
       EnteringShadowTreeWithContentInsertionPointWithOption) {
  static const char* body_content =
      "<div>Hello, <span id='host'>text</span> iterator.</div>";
  static const char* shadow_content =
      "<span><slot>content</slot> shadow</span>";
  // In this case a layoutObject for "text" is created, and emitted AFTER any
  // nodes in the shadow tree. This order does not match the order of the
  // rendered texts, but at this moment it's the expected behavior.
  // FIXME: Fix this. We probably need pure-renderer-based implementation of
  // TextIterator to achieve this.
  SetBodyContent(body_content);
  CreateShadowRootForElementWithIDAndSetInnerHTML(GetDocument(), "host",
                                                  shadow_content);
  EXPECT_EQ("[Hello, ][ shadow][text][ iterator.]",
            Iterate<DOMTree>(EntersOpenShadowRootsBehavior()));
  EXPECT_EQ("[Hello, ][text][ shadow][ iterator.]",
            Iterate<FlatTree>(EntersOpenShadowRootsBehavior()));
}

TEST_F(TextIteratorTest, StartingAtNodeInShadowRoot) {
  static const char* body_content =
      "<div id='outer'>Hello, <span id='host'>text</span> iterator.</div>";
  static const char* shadow_content =
      "<span><slot>content</slot> shadow</span>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = CreateShadowRootForElementWithIDAndSetInnerHTML(
      GetDocument(), "host", shadow_content);
  Node* outer_div = GetDocument().getElementById(AtomicString("outer"));
  Node* span_in_shadow = shadow_root->firstChild();
  Position start = Position::FirstPositionInNode(*span_in_shadow);
  Position end = Position::LastPositionInNode(*outer_div);
  EXPECT_EQ(
      "[ shadow][text][ iterator.]",
      IteratePartial<DOMTree>(start, end, EntersOpenShadowRootsBehavior()));

  PositionInFlatTree start_in_flat_tree =
      PositionInFlatTree::FirstPositionInNode(*span_in_shadow);
  PositionInFlatTree end_in_flat_tree =
      PositionInFlatTree::LastPositionInNode(*outer_div);
  EXPECT_EQ("[text][ shadow][ iterator.]",
            IteratePartial<FlatTree>(start_in_flat_tree, end_in_flat_tree,
                                     EntersOpenShadowRootsBehavior()));
}

TEST_F(TextIteratorTest, FinishingAtNodeInShadowRoot) {
  static const char* body_content =
      "<div id='outer'>Hello, <span id='host'>text</span> iterator.</div>";
  static const char* shadow_content =
      "<span><slot>content</slot> shadow</span>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = CreateShadowRootForElementWithIDAndSetInnerHTML(
      GetDocument(), "host", shadow_content);
  Node* outer_div = GetDocument().getElementById(AtomicString("outer"));
  Node* span_in_shadow = shadow_root->firstChild();
  Position start = Position::FirstPositionInNode(*outer_div);
  Position end = Position::LastPositionInNode(*span_in_shadow);
  EXPECT_EQ(
      "[Hello, ][ shadow]",
      IteratePartial<DOMTree>(start, end, EntersOpenShadowRootsBehavior()));

  PositionInFlatTree start_in_flat_tree =
      PositionInFlatTree::FirstPositionInNode(*outer_div);
  PositionInFlatTree end_in_flat_tree =
      PositionInFlatTree::LastPositionInNode(*span_in_shadow);
  EXPECT_EQ("[Hello, ][text][ shadow]",
            IteratePartial<FlatTree>(start_in_flat_tree, end_in_flat_tree,
                                     EntersOpenShadowRootsBehavior()));
}

TEST_F(TextIteratorTest, FullyClipsContents) {
  static const char* body_content =
      "<div style='overflow: hidden; width: 200px; height: 0;'>"
      "I'm invisible"
      "</div>";
  SetBodyContent(body_content);
  EXPECT_EQ("", Iterate<DOMTree>());
  EXPECT_EQ("", Iterate<FlatTree>());
}

// http://crbug.com/1194349
// See also CachedTextInputInfoTest.PlaceholderBRInTextArea
TEST_F(TextIteratorTest, PlaceholderBRInTextArea) {
  SetBodyContent("<textarea id=target>abc\n</textarea>");
  auto& target = *To<TextControlElement>(GetElementById("target"));

  // innerEditor is "<div>abc\n<br></div>"
  const auto& range =
      EphemeralRange::RangeOfContents(*target.InnerEditorElement());
  EXPECT_EQ("[abc\n][\n]",
            IteratePartial<DOMTree>(range.StartPosition(), range.EndPosition()))
      << "The placeholder <br> emits [\\n].";
}

TEST_F(TextIteratorTest, IgnoresContainerClip) {
  static const char* body_content =
      "<div style='overflow: hidden; width: 200px; height: 0;'>"
      "<div>I'm not visible</div>"
      "<div style='position: absolute; width: 200px; height: 200px; top: 0; "
      "right: 0;'>"
      "but I am!"
      "</div>"
      "</div>";
  SetBodyContent(body_content);
  EXPECT_EQ("[but I am!]", Iterate<DOMTree>());
  EXPECT_EQ("[but I am!]", Iterate<FlatTree>());
}

TEST_F(TextIteratorTest, FullyClippedContentsDistributed) {
  static const char* body_content =
      "<div id='host'>"
      "<div>Am I visible?</div>"
      "</div>";
  static const char* shadow_content =
      "<div style='overflow: hidden; width: 200px; height: 0;'>"
      "<slot></slot>"
      "</div>";
  SetBodyContent(body_content);
  CreateShadowRootForElementWithIDAndSetInnerHTML(GetDocument(), "host",
                                                  shadow_content);
  // FIXME: The text below is actually invisible but TextIterator currently
  // thinks it's visible.
  EXPECT_EQ("[\n][Am I visible?]",
            Iterate<DOMTree>(EntersOpenShadowRootsBehavior()));
  EXPECT_EQ("", Iterate<FlatTree>(EntersOpenShadowRootsBehavior()));
}

TEST_F(TextIteratorTest, IgnoresContainersClipDistributed) {
  static const char* body_content =
      "<div id='host' style='overflow: hidden; width: 200px; height: 0;'>"
      "<div>Nobody can find me!</div>"
      "</div>";
  static const char* shadow_content =
      "<div style='position: absolute; width: 200px; height: 200px; top: 0; "
      "right: 0;'>"
      "<slot></slot>"
      "</div>";
  SetBodyContent(body_content);
  CreateShadowRootForElementWithIDAndSetInnerHTML(GetDocument(), "host",
                                                  shadow_content);
  // FIXME: The text below is actually visible but TextIterator currently thinks
  // it's invisible.
  // [\n][Nobody can find me!]
  EXPECT_EQ("", Iterate<DOMTree>(EntersOpenShadowRootsBehavior()));
  EXPECT_EQ("[Nobody can find me!]",
            Iterate<FlatTree>(EntersOpenShadowRootsBehavior()));
}

TEST_F(TextIteratorTest, EmitsReplacementCharForInput) {
  static const char* body_content =
      "<div contenteditable='true'>"
      "Before"
      "<img src='foo.png'>"
      "After"
      "</div>";
  SetBodyContent(body_content);
  EXPECT_EQ("[Before][\xEF\xBF\xBC][After]",
            Iterate<DOMTree>(EmitsObjectReplacementCharacterBehavior()));
  EXPECT_EQ("[Before][\xEF\xBF\xBC][After]",
            Iterate<FlatTree>(EmitsObjectReplacementCharacterBehavior()));
}

TEST_F(TextIteratorTest, RangeLengthWithReplacedElements) {
  static const char* body_content =
      "<div id='div' contenteditable='true'>1<img src='foo.png'>3</div>";
  SetBodyContent(body_content);
  UpdateAllLifecyclePhasesForTest();

  Node* div_node = GetDocument().getElementById(AtomicString("div"));
  const EphemeralRange range(Position(div_node, 0), Position(div_node, 3));

  EXPECT_EQ(3, TextIterator::RangeLength(range));
}

TEST_F(TextIteratorTest, RangeLengthInMultilineSpan) {
  static const char* body_content =
      "<table style='width:5em'>"
      "<tbody>"
      "<tr>"
      "<td>"
      "<span id='span1'>one two three four five</span>"
      "</td>"
      "</tr>"
      "</tbody>"
      "</table>";

  SetBodyContent(body_content);
  UpdateAllLifecyclePhasesForTest();

  Node* span_node = GetDocument().getElementById(AtomicString("span1"));
  Node* text_node = span_node->firstChild();

  // Select the word "two", this is the last word on the line.

  const EphemeralRange range(Position(text_node, 4), Position(text_node, 7));

  EXPECT_EQ(3, TextIterator::RangeLength(range));
  EXPECT_EQ(3, TextIterator::RangeLength(
                   range,
                   TextIteratorBehavior::NoTrailingSpaceRangeLengthBehavior()));
}

TEST_F(TextIteratorTest, RangeLengthBasic) {
  EXPECT_EQ(0, TestRangeLength("<p>^| (1) abc def</p>"));
  EXPECT_EQ(0, TestRangeLength("<p>^ |(1) abc def</p>"));
  EXPECT_EQ(1, TestRangeLength("<p>^ (|1) abc def</p>"));
  EXPECT_EQ(2, TestRangeLength("<p>^ (1|) abc def</p>"));
  EXPECT_EQ(3, TestRangeLength("<p>^ (1)| abc def</p>"));
  EXPECT_EQ(4, TestRangeLength("<p>^ (1) |abc def</p>"));
  EXPECT_EQ(5, TestRangeLength("<p>^ (1) a|bc def</p>"));
  EXPECT_EQ(6, TestRangeLength("<p>^ (1) ab|c def</p>"));
  EXPECT_EQ(7, TestRangeLength("<p>^ (1) abc| def</p>"));
  EXPECT_EQ(8, TestRangeLength("<p>^ (1) abc |def</p>"));
  EXPECT_EQ(9, TestRangeLength("<p>^ (1) abc d|ef</p>"));
  EXPECT_EQ(10, TestRangeLength("<p>^ (1) abc de|f</p>"));
  EXPECT_EQ(11, TestRangeLength("<p>^ (1) abc def|</p>"));
}

TEST_F(TextIteratorTest, RangeLengthWithFirstLetter) {
  InsertStyleElement("p::first-letter {font-size:200%;}");
  // Expectation should be as same as |RangeLengthBasic|
  EXPECT_EQ(0, TestRangeLength("<p>^| (1) abc def</p>"));
  EXPECT_EQ(0, TestRangeLength("<p>^ |(1) abc def</p>"));
  EXPECT_EQ(1, TestRangeLength("<p>^ (|1) abc def</p>"));
  EXPECT_EQ(2, TestRangeLength("<p>^ (1|) abc def</p>"));
  EXPECT_EQ(3, TestRangeLength("<p>^ (1)| abc def</p>"));
  EXPECT_EQ(4, TestRangeLength("<p>^ (1) |abc def</p>"));
  EXPECT_EQ(5, TestRangeLength("<p>^ (1) a|bc def</p>"));
  EXPECT_EQ(6, TestRangeLength("<p>^ (1) ab|c def</p>"));
  EXPECT_EQ(7, TestRangeLength("<p>^ (1) abc| def</p>"));
  EXPECT_EQ(8, TestRangeLength("<p>^ (1) abc |def</p>"));
  EXPECT_EQ(9, TestRangeLength("<p>^ (1) abc d|ef</p>"));
  EXPECT_EQ(10, TestRangeLength("<p>^ (1) abc de|f</p>"));
  EXPECT_EQ(11, TestRangeLength("<p>^ (1) abc def|</p>"));
}

TEST_F(TextIteratorTest, RangeLengthWithFirstLetterMultipleLeadingSpaces) {
  InsertStyleElement("p::first-letter {font-size:200%;}");
  EXPECT_EQ(0, TestRangeLength("<p>^|   foo</p>"));
  EXPECT_EQ(0, TestRangeLength("<p>^ |  foo</p>"));
  EXPECT_EQ(0, TestRangeLength("<p>^  | foo</p>"));
  EXPECT_EQ(0, TestRangeLength("<p>^   |foo</p>"));
  EXPECT_EQ(1, TestRangeLength("<p>^   f|oo</p>"));
  EXPECT_EQ(2, TestRangeLength("<p>^   fo|o</p>"));
  EXPECT_EQ(3, TestRangeLength("<p>^   foo|</p>"));
}

TEST_F(TextIteratorTest, TrainlingSpace) {
  // text_content = "ab\ncd"
  // offset mapping units:
  //   [0] I DOM:0-2 TC:0-2 "ab"
  //   [1] C DOM:2-4 TC:2-2 " " spaces after "ab"
  //   [2] I DOM:0-1 TC:2-3 <br>
  //   [3] I DOM:0-2 TC:3-5 "cd"
  // Note: InlineTextBox has trailing spaces which we should get rid from
  // inline layout tree as LayoutNG.
  SetBodyContent("ab  <br>  cd");
  EXPECT_EQ("[ab][\n][cd]", Iterate<DOMTree>());
}

TEST_F(TextIteratorTest, WhitespaceCollapseForReplacedElements) {
  static const char* body_content =
      "<span>Some text </span> <input type='button' value='Button "
      "text'/><span>Some more text</span>";
  SetBodyContent(body_content);
  // text_content = "Some text \uFFFCSome more text"
  // offset mapping units:
  //   [0] I DOM:0-10 TC:0-10 "Some text "
  //   [1] C DOM:0-1  TC:10-10 " " (A space between </span> and <input>
  //   [2] I DOM:0-1  TC:10-11 <input> as U+FFFC (ORC)
  //   [3] I DOM:0-14 TC:11-25 "Some more text"
  // Note: InlineTextBox has a collapsed space which we should get rid from
  // inline layout tree as LayoutNG.
  EXPECT_EQ("[Some text ][][Some more text]", Iterate<DOMTree>());
  // <input type=button> is not text control element
  EXPECT_EQ("[Some text ][][Button text][Some more text]", Iterate<FlatTree>());
}

TEST_F(TextIteratorTest, characterAt) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>one</b> not appeared <b slot='#two' "
      "id=two>two</b></span>";
  const char* shadow_content =
      "three <slot name=#two></slot> <slot name=#one></slot> "
      "zero";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* host = GetDocument().getElementById(AtomicString("host"));

  EphemeralRangeTemplate<EditingStrategy> range1(
      EphemeralRangeTemplate<EditingStrategy>::RangeOfContents(*host));
  TextIteratorAlgorithm<EditingStrategy> iter1(range1.StartPosition(),
                                               range1.EndPosition());
  const char* message1 = "|iter1| should emit 'one' and 'two'.";
  EXPECT_EQ('o', iter1.CharacterAt(0)) << message1;
  EXPECT_EQ('n', iter1.CharacterAt(1)) << message1;
  EXPECT_EQ('e', iter1.CharacterAt(2)) << message1;
  iter1.Advance();
  EXPECT_EQ('t', iter1.CharacterAt(0)) << message1;
  EXPECT_EQ('w', iter1.CharacterAt(1)) << message1;
  EXPECT_EQ('o', iter1.CharacterAt(2)) << message1;

  EphemeralRangeTemplate<EditingInFlatTreeStrategy> range2(
      EphemeralRangeTemplate<EditingInFlatTreeStrategy>::RangeOfContents(
          *host));
  TextIteratorAlgorithm<EditingInFlatTreeStrategy> iter2(range2.StartPosition(),
                                                         range2.EndPosition());
  const char* message2 =
      "|iter2| should emit 'three ', 'two', ' ', 'one' and ' zero'.";
  EXPECT_EQ('t', iter2.CharacterAt(0)) << message2;
  EXPECT_EQ('h', iter2.CharacterAt(1)) << message2;
  EXPECT_EQ('r', iter2.CharacterAt(2)) << message2;
  EXPECT_EQ('e', iter2.CharacterAt(3)) << message2;
  EXPECT_EQ('e', iter2.CharacterAt(4)) << message2;
  EXPECT_EQ(' ', iter2.CharacterAt(5)) << message2;
  iter2.Advance();
  EXPECT_EQ('t', iter2.CharacterAt(0)) << message2;
  EXPECT_EQ('w', iter2.CharacterAt(1)) << message2;
  EXPECT_EQ('o', iter2.CharacterAt(2)) << message2;
  iter2.Advance();
  EXPECT_EQ(' ', iter2.CharacterAt(0)) << message2;
  iter2.Advance();
  EXPECT_EQ('o', iter2.CharacterAt(0)) << message2;
  EXPECT_EQ('n', iter2.CharacterAt(1)) << message2;
  EXPECT_EQ('e', iter2.CharacterAt(2)) << message2;
  iter2.Advance();
  EXPECT_EQ(' ', iter2.CharacterAt(0)) << message2;
  EXPECT_EQ('z', iter2.CharacterAt(1)) << message2;
  EXPECT_EQ('e', iter2.CharacterAt(2)) << message2;
  EXPECT_EQ('r', iter2.CharacterAt(3)) << message2;
  EXPECT_EQ('o', iter2.CharacterAt(4)) << message2;
}

// Regression test for crbug.com/630921
TEST_F(TextIteratorTest, EndingConditionWithDisplayNone) {
  SetBodyContent(
      "<div style='display: none'><span>hello</span>world</div>Lorem ipsum "
      "dolor sit amet.");
  Position start(&GetDocument(), 0);
  Position end(GetDocument().QuerySelector(AtomicString("span")), 0);
  TextIterator iter(start, end);
  EXPECT_TRUE(iter.AtEnd());
}

// Trickier regression test for crbug.com/630921
TEST_F(TextIteratorTest, EndingConditionWithDisplayNoneInShadowTree) {
  const char* body_content =
      "<div style='display: none'><span id=host><a></a></span>world</div>Lorem "
      "ipsum dolor sit amet.";
  const char* shadow_content = "<i><b id=end>he</b></i>llo";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  ShadowRoot* shadow_root =
      GetDocument().getElementById(AtomicString("host"))->OpenShadowRoot();
  Node* b_in_shadow_tree = shadow_root->getElementById(AtomicString("end"));

  Position start(&GetDocument(), 0);
  Position end(b_in_shadow_tree, 0);
  TextIterator iter(start, end);
  EXPECT_TRUE(iter.AtEnd());
}

TEST_F(TextIteratorTest, PreserveLeadingSpace) {
  SetBodyContent("<div style='width: 2em;'><b><i>foo</i></b> bar</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Position start(div->firstChild()->firstChild()->firstChild(), 0);
  Position end(div->lastChild(), 4);
  EXPECT_EQ("foo bar",
            PlainText(EphemeralRange(start, end), EmitsImageAltTextBehavior()));
}

// We used to have a bug where the leading space was duplicated if we didn't
// emit alt text, this tests for that bug
TEST_F(TextIteratorTest, PreserveLeadingSpaceWithoutEmittingAltText) {
  SetBodyContent("<div style='width: 2em;'><b><i>foo</i></b> bar</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Position start(div->firstChild()->firstChild()->firstChild(), 0);
  Position end(div->lastChild(), 4);
  EXPECT_EQ("foo bar", PlainText(EphemeralRange(start, end)));
}

TEST_F(TextIteratorTest, PreserveOnlyLeadingSpace) {
  SetBodyContent(
      "<div style='width: 2em;'><b><i id='foo'>foo </i></b> bar</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Position start(
      GetDocument().getElementById(AtomicString("foo"))->firstChild(), 0);
  Position end(div->lastChild(), 4);
  EXPECT_EQ("foo bar",
            PlainText(EphemeralRange(start, end), EmitsImageAltTextBehavior()));
}

TEST_F(TextIteratorTest, StartAtFirstLetter) {
  SetBodyContent("<style>div:first-letter {color:red;}</style><div>Axyz</div>");

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  Position start(text, 0);
  Position end(text, 4);
  TextIterator iter(start, end);

  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ("A", iter.GetTextState().GetTextForTesting());
  EXPECT_EQ(text, iter.CurrentContainer());
  EXPECT_EQ(Position(text, 0), iter.StartPositionInCurrentContainer());
  EXPECT_EQ(Position(text, 1), iter.EndPositionInCurrentContainer());

  iter.Advance();
  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ("xyz", iter.GetTextState().GetTextForTesting());
  EXPECT_EQ(text, iter.CurrentContainer());
  EXPECT_EQ(Position(text, 1), iter.StartPositionInCurrentContainer());
  EXPECT_EQ(Position(text, 4), iter.EndPositionInCurrentContainer());

  iter.Advance();
  EXPECT_TRUE(iter.AtEnd());
}

TEST_F(TextIteratorTest, StartInMultiCharFirstLetterWithCollapsedSpace) {
  SetBodyContent(
      "<style>div:first-letter {color:red;}</style><div>  (A)  xyz</div>");

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  Position start(text, 3);
  Position end(text, 10);
  TextIterator iter(start, end);

  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ("A)", iter.GetTextState().GetTextForTesting());
  EXPECT_EQ(text, iter.CurrentContainer());
  EXPECT_EQ(Position(text, 3), iter.StartPositionInCurrentContainer());
  EXPECT_EQ(Position(text, 5), iter.EndPositionInCurrentContainer());

  iter.Advance();
  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ(" ", iter.GetTextState().GetTextForTesting());
  EXPECT_EQ(text, iter.CurrentContainer());
  EXPECT_EQ(Position(text, 5), iter.StartPositionInCurrentContainer());
  EXPECT_EQ(Position(text, 6), iter.EndPositionInCurrentContainer());

  iter.Advance();
  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ("xyz", iter.GetTextState().GetTextForTesting());
  EXPECT_EQ(text, iter.CurrentContainer());
  EXPECT_EQ(Position(text, 7), iter.StartPositionInCurrentContainer());
  EXPECT_EQ(Position(text, 10), iter.EndPositionInCurrentContainer());

  iter.Advance();
  EXPECT_TRUE(iter.AtEnd());
}

TEST_F(TextIteratorTest, StartAndEndInMultiCharFirstLetterWithCollapsedSpace) {
  SetBodyContent(
      "<style>div:first-letter {color:red;}</style><div>  (A)  xyz</div>");

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  Position start(text, 3);
  Position end(text, 4);
  TextIterator iter(start, end);

  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ("A", iter.GetTextState().GetTextForTesting());
  EXPECT_EQ(text, iter.CurrentContainer());
  EXPECT_EQ(Position(text, 3), iter.StartPositionInCurrentContainer());
  EXPECT_EQ(Position(text, 4), iter.EndPositionInCurrentContainer());

  iter.Advance();
  EXPECT_TRUE(iter.AtEnd());
}

TEST_F(TextIteratorTest, StartAtRemainingText) {
  SetBodyContent("<style>div:first-letter {color:red;}</style><div>Axyz</div>");

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  Position start(text, 1);
  Position end(text, 4);
  TextIterator iter(start, end);

  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ("xyz", iter.GetTextState().GetTextForTesting());
  EXPECT_EQ(text, iter.CurrentContainer());
  EXPECT_EQ(Position(text, 1), iter.StartPositionInCurrentContainer());
  EXPECT_EQ(Position(text, 4), iter.EndPositionInCurrentContainer());

  iter.Advance();
  EXPECT_TRUE(iter.AtEnd());
}

TEST_F(TextIteratorTest, StartAtFirstLetterInPre) {
  SetBodyContent("<style>pre:first-letter {color:red;}</style><pre>Axyz</pre>");

  Element* pre = GetDocument().QuerySelector(AtomicString("pre"));
  Node* text = pre->firstChild();
  Position start(text, 0);
  Position end(text, 4);
  TextIterator iter(start, end);

  EXPECT_FALSE(iter.AtEnd());
  EXPECT_EQ("A", iter.GetTextState
```