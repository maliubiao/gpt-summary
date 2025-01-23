Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The first step is to understand what this file *is* and what its purpose is. The filename `same_block_word_iterator_test.cc` immediately suggests it's a test file for something called `SameBlockWordIterator`. The location in the `blink/renderer/core/fragment_directive` directory hints at its role in handling fragment directives (the part of a URL after the `#`). The term "word iterator" implies it's about iterating through words within a specific context. The "same block" part is the most crucial detail and tells us it's likely confined to the same HTML block element.

**2. High-Level Overview of the Code:**

Quickly scan the code for key elements:

* **Includes:**  Look at the included headers. `gtest/gtest.h` confirms it's a Google Test file. Other includes like `Position.h`, and the iterator's own header confirm the core functionality. `SimTest` indicates it's using Blink's simulation testing framework.
* **Namespace:**  The `blink` namespace confirms it's Blink-specific code.
* **Test Fixture:** The `SameBlockWordIteratorTest` class, inheriting from `SimTest`, sets up the testing environment. The `SetUp()` method suggests basic browser initialization.
* **Test Cases:** The `TEST_F` macros define individual test cases with descriptive names like `GetNextWord`, `GetPreviousWord`, and variations covering different HTML structures.

**3. Analyzing Individual Test Cases:**

Now, delve into each test case, focusing on the following:

* **HTML Structure:**  Examine the `R"HTML(...)HTML"` block. What is the HTML being loaded?  Pay attention to the `id` attributes, as they're used to locate elements.
* **Iterator Initialization:**  How is the iterator being created?  Which iterator type (forward or backward)?  What `PositionInFlatTree` is used as the starting point?  This is crucial for understanding where the iteration begins.
* **`AdvanceNextWord()` Calls:** How many times is `AdvanceNextWord()` called?  This determines how many "words" the iterator is expected to move through.
* **`EXPECT_EQ()` Assertions:** What strings are being compared in the `EXPECT_EQ()` calls? The `iterator->TextFromStart()` method is retrieving the accumulated text, so the assertions verify if the iterator has correctly captured the intended sequence of words.
* **Variations:**  Note how the test case names indicate different scenarios: `ExtraSpace`, `WithComment`, `NestedTextNode`, `NestedBlock`, `NestedInvisibleBlock`, `HalfWord`. This helps understand the robustness of the iterator.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **HTML:** The tests directly manipulate and analyze HTML structure. The iterator's purpose is to traverse and understand the textual content within HTML elements. The use of block-level elements (`<p>`, `<div>`) is central to the "same block" concept. The tests explore how the iterator handles inline elements (`<b>`), comments (`<!-- -->`), and invisible elements (`style='display:none'`).
* **JavaScript:** While this specific test file is C++, the functionality it tests is directly relevant to JavaScript's ability to interact with the DOM. JavaScript can use APIs to traverse the DOM tree, select elements, and extract text content. The `SameBlockWordIterator` likely provides a more specialized and efficient way for the browser engine to handle text selection and analysis within a block, which could be exposed or utilized by JavaScript APIs indirectly. Imagine a JavaScript function that needs to select or highlight words within a paragraph – the underlying engine might use a similar mechanism.
* **CSS:** The test case involving `style='display:none'` directly relates to CSS's ability to control element visibility. The iterator's behavior of skipping invisible blocks demonstrates its awareness of the rendered layout, which is heavily influenced by CSS.

**5. Logical Reasoning and Assumptions:**

* **Assumption:** The core assumption is that "same block" means the iterator will not cross the boundaries of block-level HTML elements (like `<p>` or `<div>`). This is confirmed by the test cases involving nested blocks.
* **Input/Output:**  For each test case, the *input* is the HTML structure and the starting `PositionInFlatTree`. The *output* is the sequence of strings returned by `iterator->TextFromStart()` after each `AdvanceNextWord()` call. We can infer the expected output by mentally stepping through the HTML and the iterator's movement.

**6. Identifying Potential Usage Errors:**

Consider how a developer *using* this iterator (or a similar concept in other contexts) might make mistakes:

* **Incorrect Starting Position:**  Providing a `PositionInFlatTree` that points to the wrong element or offset could lead to unexpected results. The "HalfWord" test case highlights this.
* **Assuming Iteration Across Blocks:**  A user might incorrectly expect the iterator to continue into the next or previous block element. The tests with nested blocks demonstrate that this doesn't happen.
* **Not Handling Edge Cases:**  Forgetting about the impact of comments, inline elements, or invisible elements could lead to inaccurate text extraction. The dedicated test cases for these scenarios emphasize their importance.

**Self-Correction/Refinement during the thought process:**

Initially, I might have focused too much on the C++ specifics. Realizing the prompt asks about connections to web technologies, I would then shift focus to how this low-level functionality relates to the higher-level concepts of HTML, CSS, and JavaScript's DOM interaction. Also, initially, I might just describe what the tests *do*. The prompt asks for *functionality*. This requires generalizing from the specific tests to the overall purpose of the `SameBlockWordIterator`. Finally, explicitly addressing assumptions, inputs/outputs, and potential errors makes the analysis more complete and insightful.
好的，让我们来分析一下 `blink/renderer/core/fragment_directive/same_block_word_iterator_test.cc` 文件的功能。

**功能概述**

这个文件是 Chromium Blink 引擎中用于测试 `SameBlockWordIterator` 类的单元测试文件。`SameBlockWordIterator` 的主要功能是**在一个 HTML 块级元素（block-level element）内部，按照单词进行迭代**。它可以向前或向后遍历文本内容，并返回从起始位置到当前位置的文本片段。

**与 JavaScript, HTML, CSS 的关系及举例**

虽然这个文件是 C++ 代码，用于测试 Blink 引擎的内部实现，但它所测试的功能与 Web 前端技术（JavaScript, HTML, CSS）息息相关，特别是在处理页面内的文本定位和操作方面。

1. **HTML (结构):**
   - `SameBlockWordIterator` 的核心概念是 "same block"。这里的 "block" 指的是 HTML 中的块级元素，例如 `<p>`, `<div>`, `<h1>` 等。测试用例中大量使用了这些标签来构建不同的 HTML 结构。
   - **举例:** 测试用例会创建包含不同文本内容的 `<p>` 或 `<div>` 元素，然后使用迭代器在这些元素的文本内容中移动。例如，`GetNextWord` 测试用例加载了一个包含两个 `<p>` 元素的 HTML，并测试迭代器在第一个 `<p>` 元素内部的移动。

2. **JavaScript (DOM 操作和文本处理):**
   - 虽然这个 C++ 类不直接暴露给 JavaScript，但 Blink 引擎内部的许多功能，包括与文本选择、高亮、查找等相关的操作，可能会用到类似的迭代器或文本处理逻辑。JavaScript 可以通过 DOM API 获取和操作文本节点，而 `SameBlockWordIterator` 提供了引擎内部一种高效的方式来处理块级元素内的文本。
   - **假设输入与输出 (逻辑推理):** 假设一个 JavaScript 函数需要高亮一个段落中的 "paragraph text" 这部分文本。引擎内部可能会使用类似 `SameBlockWordIterator` 的机制，从段落的起始位置开始，逐个单词向前迭代，直到找到包含 "paragraph text" 的文本片段。
     - **假设输入:**  一个指向 `<p id='first'>First paragraph text</p>` 元素的起始位置的指针。
     - **内部迭代过程:** 引擎创建一个 `ForwardSameBlockWordIterator`，并逐步调用 `AdvanceNextWord()`。
     - **预期输出:**  当迭代器的 `TextFromStart()` 返回 "First paragraph text" 时，引擎确定找到了目标文本片段。

3. **CSS (渲染和布局):**
   - 测试用例中涉及到 `style='display:none'`，这表明迭代器需要考虑元素的可见性。一个 `display: none` 的元素及其内容应该被迭代器忽略。
   - **举例:** `GetNextWord_NestedInvisibleBlock` 测试用例验证了迭代器是否会跳过 `display:none` 的 `<div>` 元素内的文本。这反映了 CSS 的渲染规则如何影响文本的逻辑结构。

**逻辑推理、假设输入与输出**

让我们更详细地分析一个测试用例：

**测试用例:** `GetNextWord`

**假设输入:**
   - HTML 结构:
     ```html
     <!DOCTYPE html>
     <p id='first'>First paragraph text</p>
     <p>new block</p>
     ```
   - 迭代器起始位置: `PositionInFlatTree(*node, 0)`，其中 `node` 是 id 为 'first' 的 `<p>` 元素的第一个子节点（文本节点），偏移量为 0，即文本的开始。

**逻辑推理和迭代过程:**

1. 创建一个 `ForwardSameBlockWordIterator`，起始位置在 "First paragraph text" 的开头。
2. 第一次调用 `iterator->AdvanceNextWord()`: 迭代器前进到第一个单词的末尾，`TextFromStart()` 返回 "First"。
3. 第二次调用 `iterator->AdvanceNextWord()`: 迭代器前进到第二个单词的末尾，`TextFromStart()` 返回 "First paragraph"。
4. 第三次调用 `iterator->AdvanceNextWord()`: 迭代器前进到第三个单词的末尾，`TextFromStart()` 返回 "First paragraph text"。
5. 第四次调用 `iterator->AdvanceNextWord()`: 迭代器已经到达块级元素的末尾，不会再前进，`TextFromStart()` 仍然返回 "First paragraph text"。

**预期输出:**
   - 第一次断言 `EXPECT_EQ("First", iterator->TextFromStart());` 通过。
   - 第二次断言 `EXPECT_EQ("First paragraph", iterator->TextFromStart());` 通过。
   - 第三次断言 `EXPECT_EQ("First paragraph text", iterator->TextFromStart());` 通过。
   - 第四次断言 `EXPECT_EQ("First paragraph text", iterator->TextFromStart());` 通过。

**用户或编程常见的使用错误举例**

虽然用户不会直接使用 `SameBlockWordIterator` 这个 C++ 类，但理解其背后的逻辑有助于避免与文本处理相关的错误。

1. **错误地假设迭代会跨越块级元素:**  开发者可能会错误地认为，如果从一个段落的末尾开始迭代，会直接跳到下一个段落的开头。然而，`SameBlockWordIterator` 的设计限制了它在同一个块级元素内部工作。
   - **示例:**  如果一个用户想选取两个相邻段落的文本，他们不能依赖于一个简单的 "下一个单词" 的迭代器跨越段落边界。需要进行更复杂的逻辑处理。

2. **忽略不可见元素的影响:**  在某些情况下，开发者可能会忘记考虑 `display: none` 或 `visibility: hidden` 等 CSS 属性对文本迭代的影响。`SameBlockWordIterator` 的测试用例表明，它会跳过不可见元素的内容。
   - **示例:**  如果一个隐藏的 `<div>` 元素内部包含一些文本，依赖于简单的文本迭代可能会遗漏这些内容，导致不期望的结果。

3. **未处理空格和换行符:**  测试用例 `GetNextWord_ExtraSpace` 和 `GetPreviousWord_ExtraSpace` 验证了迭代器如何处理额外的空格和换行符。开发者在处理文本时，需要注意这些空白字符可能会影响单词的边界和迭代结果。
   - **示例:**  如果文本中有多个连续的空格，简单的按空格分割单词的方法可能会得到空字符串。`SameBlockWordIterator` 提供了更精确的单词边界定义。

**总结**

`same_block_word_iterator_test.cc` 文件通过一系列单元测试，详细验证了 `SameBlockWordIterator` 类在各种 HTML 结构和文本布局下的行为。这对于确保 Blink 引擎在处理页面内文本时的准确性和可靠性至关重要，并间接地影响了 JavaScript 文本操作、CSS 渲染效果以及用户与网页的交互体验。这些测试用例覆盖了常见的文本结构，包括嵌套元素、注释、空白符以及不可见元素，有助于开发者理解引擎内部的文本处理机制，并避免在前端开发中可能出现的与文本迭代相关的错误。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/same_block_word_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fragment_directive/same_block_word_iterator.h"

#include <gtest/gtest.h>

#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/fragment_directive/same_block_word_iterator.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

class SameBlockWordIteratorTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }
};

// Basic case for forward iterator->
TEST_F(SameBlockWordIteratorTest, GetNextWord) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
    <p>new block</p>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  ForwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<ForwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 0));
  iterator->AdvanceNextWord();
  EXPECT_EQ("First", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph text", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph text", iterator->TextFromStart());
}

// Check the case when following text contains collapsible space.
TEST_F(SameBlockWordIteratorTest, GetNextWord_ExtraSpace) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph


     text</p>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  ForwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<ForwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 6));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph text", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph text", iterator->TextFromStart());
}

// Check the case when there is a commented block which should be skipped.
TEST_F(SameBlockWordIteratorTest, GetNextWord_WithComment) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>new block</p>
    <div id='first'>
      <span>First</span>
      <!--
      multiline comment that should be ignored.
      //-->
      <span id='span'>paragraph text</span>
    </div>
    <p>new block</p>
  )HTML");
  Node* node = GetDocument().getElementById(AtomicString("span"))->firstChild();
  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 9));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());
}

// Check the case when following text contains non-block tag(e.g. <b>).
TEST_F(SameBlockWordIteratorTest, GetNextWord_NestedTextNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First <b>bold text</b> paragraph text</p>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  ForwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<ForwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 5));
  iterator->AdvanceNextWord();
  EXPECT_EQ("bold", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold text", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold text paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold text paragraph text", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold text paragraph text", iterator->TextFromStart());
}

// Check the case when following text is interrupted by a nested block.
TEST_F(SameBlockWordIteratorTest, GetNextWord_NestedBlock) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First paragraph <div id='div'>div</div> text</div>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  ForwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<ForwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 5));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());
}

// Check the case when following text includes non-block element but is
// interrupted by a nested block.
TEST_F(SameBlockWordIteratorTest, GetNextWord_NestedBlockInNestedText) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <b>bold<div id='div'>div</div></b> paragraph text</div>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  ForwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<ForwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 5));
  iterator->AdvanceNextWord();
  EXPECT_EQ("bold", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold", iterator->TextFromStart());
}

// Check the case when following text includes invisible block.
TEST_F(SameBlockWordIteratorTest, GetNextWord_NestedInvisibleBlock) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <div id='div' style='display:none'>invisible</div> paragraph text</div>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  ForwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<ForwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 5));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph text", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph text", iterator->TextFromStart());
}

// Basic case for backward iterator->
TEST_F(SameBlockWordIteratorTest, GetPreviousWord) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>new block</p>
    <p id='first'>First paragraph next word</p>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();

  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 16));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());
}

// Check the case when available text has extra space.
TEST_F(SameBlockWordIteratorTest, GetPreviousWord_ExtraSpace) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>new block</p>
    <p id='first'>First

         paragraph text</p>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 25));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());
}

// Check the case when there is a commented block which should be skipped.
TEST_F(SameBlockWordIteratorTest, GetPreviousWord_WithComment) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>new block</p>
    <div id='first'>
      <span>First</span>
      <!--
        multiline comment that should be ignored.
      //-->
      <span id='span'>paragraph text</span>
    </div>
    <p>new block</p>
  )HTML");
  Node* node = GetDocument().getElementById(AtomicString("span"))->firstChild();
  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 9));
  iterator->AdvanceNextWord();
  iterator->TextFromStart();

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First paragraph", iterator->TextFromStart());
}

// Check the case when available text contains non-block tag(e.g. <b>).
TEST_F(SameBlockWordIteratorTest, GetPreviousWord_NestedTextNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First <b>bold text</b> paragraph text</p>
  )HTML");
  Node* node = GetDocument().getElementById(AtomicString("first"))->lastChild();
  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 11));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("text paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold text paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First bold text paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First bold text paragraph", iterator->TextFromStart());
}

// Check the case when available text is interrupted by a nested block.
TEST_F(SameBlockWordIteratorTest, GetPreviousWord_NestedBlock) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <div id='div'>div</div> paragraph text</div>
  )HTML");
  Node* node = GetDocument().getElementById(AtomicString("div"))->nextSibling();
  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 11));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());
}

// Check the case when available text includes non-block element but is
// interrupted by a nested block.
TEST_F(SameBlockWordIteratorTest, GetPreviousWord_NestedBlockInNestedText) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <b><div id='div'>div</div>bold</b> paragraph text</div>
  )HTML");
  Node* node = GetDocument().getElementById(AtomicString("first"))->lastChild();
  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 11));
  iterator->AdvanceNextWord();
  EXPECT_EQ("paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold paragraph", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("bold paragraph", iterator->TextFromStart());
}

// Check the case when available text includes invisible block.
TEST_F(SameBlockWordIteratorTest, GetPreviousWord_NestedInvisibleBlock) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <div id='div' style='display:none'>invisible</div> paragraph text</div>
  )HTML");
  Node* node = GetDocument().getElementById(AtomicString("div"))->nextSibling();
  BackwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<BackwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 0));
  iterator->AdvanceNextWord();
  EXPECT_EQ("First", iterator->TextFromStart());

  iterator->AdvanceNextWord();
  EXPECT_EQ("First", iterator->TextFromStart());
}

// Check the case when given start position is in a middle of a word.
TEST_F(SameBlockWordIteratorTest, GetNextWord_HalfWord) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
    <p>new block</p>
  )HTML");
  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  ForwardSameBlockWordIterator* iterator =
      MakeGarbageCollected<ForwardSameBlockWordIterator>(
          PositionInFlatTree(*node, 2));
  iterator->AdvanceNextWord();
  EXPECT_EQ("rst", iterator->TextFromStart());
}

}  // namespace blink
```