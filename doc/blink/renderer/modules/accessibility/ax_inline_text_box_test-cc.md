Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive response.

**1. Initial Skim and Goal Identification:**

*   The file name `ax_inline_text_box_test.cc` immediately tells us this is a test file specifically for the `AXInlineTextBox` class within the Accessibility module of the Blink rendering engine.
*   The `#include` statements confirm this and show dependencies on testing frameworks (`gtest`), core editing classes (`EphemeralRange`, `DocumentMarker`), and other accessibility classes (`AXBlockFlowIterator`, `AXObjectCacheImpl`).
*   The primary goal of this file is to test the functionality of `AXInlineTextBox`.

**2. Analyzing Individual Test Cases (Mental or Actual Code Execution):**

*   Go through each `TEST_F(AccessibilityTest, ...)` block. For each test:
    *   **Identify the Setup:** Look for `SetBodyInnerHTML(...)`. This reveals the HTML structure being tested. Pay attention to IDs and specific HTML elements.
    *   **Identify the Target `AXObject`:**  Look for `GetAXObjectByElementId(...)`. This tells us which accessibility object is the focus of the test.
    *   **Identify the Core Assertion:** What is the test *actually* checking? This often involves calls to `ASSERT_EQ`, `EXPECT_EQ`, and sometimes `ASSERT_NE`. Focus on the methods of `AXInlineTextBox` being called (e.g., `GetWordBoundaries`, `TextOffsetInContainer`, `GetTextDirection`).
    *   **Connect to Web Concepts:**  Mentally link the HTML structure and the `AXInlineTextBox` methods being tested to their corresponding web functionalities (text layout, line breaks, spans, word wrapping, text direction, etc.).
    *   **Consider Edge Cases:** Are there unusual HTML structures or CSS properties being used?  (e.g., `<br>`, `<span>`, `word-wrap: break-word`, `text-overflow: ellipsis`, `<ruby>`).
    *   **For `AXBlockFlowIterator` tests:** Understand the iteration logic. What text is expected at each step? How are line breaks (soft and hard) handled? How are elements like `<ruby>` and ellipsis represented in the iteration?

**3. Categorizing and Summarizing Functionality:**

*   Based on the individual test cases, group the functionalities being tested:
    *   Word boundaries
    *   Document markers (spellcheck, grammar)
    *   Text offsets (within containers, handling spans, line breaks, word wrapping)
    *   Text direction
    *   `AXBlockFlowIterator` (iterating through text, handling line breaks, ellipsis, ruby annotations, character offsets, ligatures).

**4. Relating to JavaScript, HTML, and CSS:**

*   For each tested functionality, explicitly explain its connection to web technologies:
    *   **JavaScript:** Accessibility APIs are often used by assistive technologies, which might be implemented or interacted with via JavaScript. Mention dynamic updates and event handling.
    *   **HTML:**  The structure of the HTML directly influences the creation and organization of `AXInlineTextBox` objects. Provide examples of how different HTML elements impact the tests.
    *   **CSS:**  CSS properties like `width`, `font-size`, `word-wrap`, `text-overflow`, `writing-mode` directly affect text layout and thus the behavior of `AXInlineTextBox`. Point out specific examples from the test cases.

**5. Logical Reasoning (Input/Output Examples):**

*   For tests that involve calculations or specific data transformations (like `GetWordBoundaries` and `GetDocumentMarkers`), provide concrete examples:
    *   **Input:** The HTML snippet.
    *   **Process:** Briefly explain the logic being tested (e.g., how word boundaries are determined, how markers are associated with text).
    *   **Output:** The expected results (e.g., the vectors of word starts and ends, the marker types and ranges).

**6. Common User/Programming Errors:**

*   Think about how developers might misuse or misunderstand accessibility concepts:
    *   Incorrect ARIA attributes (though this test file doesn't directly focus on ARIA).
    *   Assuming a 1:1 mapping between DOM elements and accessibility objects.
    *   Not considering how CSS affects accessibility.
    *   Misunderstanding how assistive technologies consume accessibility data.
    *   Issues related to dynamic content updates.

**7. Debugging Walkthrough (User Operations):**

*   Construct a plausible user journey that leads to the code being executed. Start with a user action and trace the flow through the browser:
    *   User opens a webpage.
    *   Browser parses HTML/CSS.
    *   Layout engine calculates text layout, creating inline text boxes.
    *   Accessibility tree is built, using information from the layout.
    *   Assistive technology (or developer tools) requests accessibility information, potentially triggering the methods being tested.

**8. Refinement and Organization:**

*   Organize the information logically with clear headings and bullet points.
*   Use precise terminology.
*   Provide code snippets from the test file to illustrate your points.
*   Review for clarity, accuracy, and completeness.

**Self-Correction/Refinement Example During the Process:**

*   **Initial thought:** "This file just tests `AXInlineTextBox`."
*   **Realization (after seeing `AXBlockFlowIterator` tests):** "Oh, it also tests how `AXInlineTextBox` interacts with the `AXBlockFlowIterator` for more complex text traversal."  *Correction: Expand the scope of the analysis to include the iterator tests.*
*   **Initial thought (for `GetCharacterOffsets`):** "Just checking pixel offsets."
*   **Realization (after seeing the ligature test):** "The test highlights how font rendering (ligatures) can impact character offset calculations in accessibility." *Correction:  Emphasize the ligature aspect and the platform-dependent nature of the metrics.*

By following this structured approach, combining code analysis with an understanding of web technologies and accessibility principles, you can generate a comprehensive and insightful explanation of the test file's purpose and functionality.
这个C++源代码文件 `ax_inline_text_box_test.cc` 是 Chromium Blink 引擎中用于测试 `AXInlineTextBox` 类的功能的单元测试文件。 `AXInlineTextBox` 类是 Accessibility (辅助功能) 模块中的一个重要组成部分，它代表了渲染文本内容时的一行或部分行的文本框。

以下是该文件主要的功能和相关的解释：

**主要功能：**

1. **测试 `AXInlineTextBox` 对象的创建和属性:** 虽然测试代码本身没有直接创建 `AXInlineTextBox` 对象，但它通过加载包含文本的 HTML 结构，间接地触发了 Blink 渲染引擎创建这些对象。测试会断言创建出的 `AXInlineTextBox` 对象的角色是 `ax::mojom::Role::kInlineTextBox`。

2. **测试获取单词边界 (`GetWordBoundaries`):**  测试了 `AXInlineTextBox` 对象是否能够正确识别并返回文本中各个单词的起始和结束位置。这对于屏幕阅读器和其他辅助技术导航文本非常重要。

3. **测试获取文档标记 (`GetDocumentMarkers`):**  测试了 `AXInlineTextBox` 对象是否能够正确识别和报告应用于文本的文档标记，例如拼写错误和语法错误标记。这些标记由 `DocumentMarkerController` 添加，并与文本范围关联。测试验证了在不同的 `AXInlineTextBox` 中，哪些标记在哪个偏移量开始和结束。

4. **测试在容器中的文本偏移量 (`TextOffsetInContainer`):**  测试了在包含多个 `AXInlineTextBox` 的容器（例如 `AXStaticText`）中，每个 `AXInlineTextBox` 的文本起始偏移量是否正确计算。测试考虑了 `<span>` 标签和 `<br>` 换行符对偏移量的影响。

5. **测试获取文本方向 (`GetTextDirection`):** 测试了 `AXInlineTextBox` 对象是否能够正确报告文本的阅读方向，例如从左到右或从右到左。这涉及到 CSS 的 `writing-mode` 属性。

6. **测试 `AXBlockFlowIterator` API:**  测试了一个用于遍历文本块的迭代器 `AXBlockFlowIterator` 在与 `AXInlineTextBox` 相关的场景下的行为。这包括：
    *   简单文本的迭代。
    *   处理软换行符（由容器宽度引起）。
    *   处理硬换行符 (`<br>`)。
    *   处理省略号 (`text-overflow: ellipsis`)。
    *   处理 `<ruby>` 标签（用于日文注音）。
    *   获取字符级别的像素偏移量 (`GetCharacterLayoutPixelOffsets`)，这对于精确地定位屏幕上的文本位置很重要。
    *   处理连字 (ligature)。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

*   **HTML:** 测试代码通过 `SetBodyInnerHTML` 方法设置 HTML 内容，这是测试的基础。HTML 的结构直接影响了 `AXInlineTextBox` 对象的生成和文本的布局。
    *   **例子:**  在 `GetWordBoundaries` 测试中，HTML 包含了各种字符和标点符号，用于验证单词边界的识别逻辑。
    *   **例子:** 在 `GetDocumentMarkers` 测试中，HTML 定义了一个段落，测试针对这个段落中的文本内容及其标记。
    *   **例子:** 在 `TextOffsetInContainerWithASpan` 测试中，`<span>` 标签被用来测试如何影响文本偏移量的计算。
    *   **例子:** 在 `TextOffsetInContainerWithLineBreak` 测试中，`<br>` 标签被用来测试换行符对文本偏移量的影响。
    *   **例子:** 在 `AXBlockFlowIteratorAPI_Ruby` 测试中，`<ruby>` 标签用于测试辅助功能树对复杂文本结构的处理。

*   **CSS:** CSS 样式影响文本的渲染方式，从而影响 `AXInlineTextBox` 的创建和属性。
    *   **例子:** 在 `GetDocumentMarkers` 和其他测试中，`font-size` 样式被用来控制文本的渲染大小，虽然在这个特定测试中不是核心关注点，但它是页面渲染的基础。
    *   **例子:** 在 `TextOffsetInContainerWithMultipleInlineTextBoxes` 和 `TextOffsetInContainerWithBreakWord` 测试中，`width` 样式被用来限制容器的宽度，从而导致文本被分成多个 `AXInlineTextBox`。`word-wrap: break-word` 样式则影响长单词的断行方式。
    *   **例子:** 在 `GetTextDirection` 测试中，`writing-mode: sideways-lr;` 样式被用来改变文本的阅读方向，测试验证了 `AXInlineTextBox` 能否正确报告。
    *   **例子:** 在 `AXBlockFlowIteratorAPI_Ellipsis` 测试中，`text-overflow: ellipsis;` 和 `white-space: nowrap;` 样式导致文本溢出时显示省略号，测试验证了 `AXBlockFlowIterator` 对这种情况的处理。

*   **JavaScript:**  虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部功能，但 `AXInlineTextBox` 最终服务于 Web 内容的辅助功能需求。JavaScript 可以通过 Accessibility APIs (如 ARIA 属性) 来影响辅助功能树的构建和属性。例如，JavaScript 可以动态地修改 DOM 结构和文本内容，这将导致重新计算和更新 `AXInlineTextBox` 对象。  虽然这个测试没有直接涉及到 JavaScript 的交互，但理解 `AXInlineTextBox` 的目的是为了让辅助技术（通常由 JavaScript 驱动）能够更好地理解和呈现 Web 内容。

**逻辑推理 (假设输入与输出):**

以 `GetWordBoundaries` 测试为例：

*   **假设输入 (HTML):**
    ```html
    <p id="paragraph">
      &quot;This, &#9728; &#2460; is ... a---+++test. &lt;p&gt;word&lt;/p&gt;&quot;
    </p>
    ```
*   **逻辑推理:**  `GetWordBoundaries` 方法应该根据空格、标点符号等规则，将文本分割成不同的“单词”。
*   **预期输出:**
    *   `word_starts`: `{0, 1, 5, 7, 9, 11, 14, 18, 19, 22, 23, 24, 25, 29, 31, 32, 33, 34, 38, 40, 41}`
    *   `word_ends`: `{1, 5, 6, 8, 10, 13, 17, 19, 22, 23, 24, 25, 29, 30, 32, 33, 34, 38, 40, 41, 43}`
    这些向量分别表示每个识别出的“单词”在文本中的起始和结束索引。

以 `GetDocumentMarkers` 测试为例：

*   **假设输入 (HTML):**
    ```html
    <p id="paragraph">
      Misspelled text with a grammar error.
    </p>
    ```
*   **假设操作:** 通过 `DocumentMarkerController` 添加了拼写错误标记和语法错误标记。
*   **逻辑推理:**  `AXInlineTextBox` 对象应该能够识别出哪些标记覆盖了它的文本范围，并报告标记的类型、起始和结束偏移量（相对于 `AXInlineTextBox` 的文本）。
*   **预期输出 (针对第一个 `AXInlineTextBox`):**
    *   `kMarkerTypes`: `{kSpelling}`
    *   `kMarkerStarts`: `{0}`
    *   `kMarkerEnds`: `{11}`
    这表示第一个 `AXInlineTextBox` 包含了一个拼写错误标记，从它的文本起始位置 0 开始，到位置 11 结束。

**用户或编程常见的使用错误 (如果涉及):**

虽然这个测试文件是底层引擎的测试，但其测试的功能与用户和开发者息息相关。以下是一些可能的使用错误：

1. **开发者错误地假设文本布局与 DOM 结构一一对应:** 开发者可能会认为 DOM 中的一个文本节点总是对应一个 `AXInlineTextBox`，但实际上，由于布局和渲染的原因，一个文本节点可能会被分割成多个 `AXInlineTextBox`。测试中的 `TextOffsetInContainer` 系列测试就体现了这一点。

2. **辅助技术或自动化工具错误地依赖字符索引:** 如果一个辅助技术错误地假设字符索引是全局的，而没有考虑到 `AXInlineTextBox` 的边界，可能会导致在跨越多个 `AXInlineTextBox` 的文本中定位错误。`TextOffsetInContainer` 测试验证了引擎是否能提供相对于每个 `AXInlineTextBox` 的正确偏移量。

3. **开发者没有考虑到 CSS 对辅助功能的影响:** 例如，使用 CSS 隐藏文本可能会导致辅助功能树中仍然存在相应的 `AXInlineTextBox`，但用户不可见。开发者需要正确使用 ARIA 属性来指示辅助技术应该如何处理这些隐藏的内容。虽然这个测试没有直接测试这种情况，但 `AXInlineTextBox` 作为辅助功能树的一部分，其行为与 CSS 渲染密切相关。

4. **处理动态内容更新时的错误:** 如果 JavaScript 动态修改了页面内容，开发者需要确保辅助功能树也得到了相应的更新。如果更新不及时或不正确，可能导致 `AXInlineTextBox` 的信息过时或不准确。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个包含文本的网页:**  这是最基本的操作。网页的 HTML 结构和 CSS 样式决定了文本的布局方式。

2. **浏览器解析 HTML 和 CSS:**  浏览器引擎（如 Blink）会解析 HTML 结构，构建 DOM 树，并解析 CSS 样式。

3. **布局引擎计算文本布局:**  布局引擎会根据 DOM 结构和 CSS 样式计算每个文本元素应该如何渲染，包括断行、换行等。在这个过程中，会创建 `LayoutInline` 对象，并根据需要将其分割成多个 `LayoutInlineTextBox`。

4. **辅助功能树构建:**  当辅助功能被启用（例如，用户使用了屏幕阅读器），或者开发者工具请求辅助功能信息时，Blink 引擎会根据 DOM 树和布局信息构建辅助功能树。`AXInlineTextBox` 对象会在这个阶段被创建，它们代表了渲染后的文本行的片段。

5. **辅助技术请求信息:** 屏幕阅读器等辅助技术会通过操作系统提供的 Accessibility APIs 与浏览器进行交互，请求页面元素的辅助功能信息，包括文本内容、角色、位置等。当请求涉及到文本内容时，可能会遍历 `AXInlineTextBox` 对象来获取详细的文本信息，包括单词边界、标记等。

6. **开发者使用辅助功能调试工具:** 开发者可以使用 Chrome DevTools 的 Accessibility 面板来检查页面的辅助功能树结构，查看 `AXInlineTextBox` 对象的属性和关系。这可能触发对 `AXInlineTextBox` 对象的属性查询，从而间接地执行到测试中涉及的代码。

**调试线索:**

*   如果在屏幕阅读器中阅读网页时，遇到单词边界识别错误、拼写或语法错误标记未正确报告、或者文本内容顺序混乱等问题，可能与 `AXInlineTextBox` 的实现有关。
*   开发者在使用辅助功能调试工具时，如果发现 `AXInlineTextBox` 的属性值不符合预期（例如，文本偏移量错误，错误的标记信息），可以作为调试的起点，查看 Blink 引擎中 `AXInlineTextBox` 的相关代码。
*   当排查特定 CSS 样式对辅助功能的影响时，可以关注 `AXInlineTextBox` 的创建和属性是否受到这些样式的影响。

总而言之，`ax_inline_text_box_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎能够正确地表示和处理渲染后的文本行的辅助功能信息，这对于确保所有用户都能访问和理解 Web 内容至关重要。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_inline_text_box_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/accessibility/ax_inline_text_box.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/modules/accessibility/ax_block_flow_iterator.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_range.h"
#include "third_party/blink/renderer/modules/accessibility/testing/accessibility_test.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using AXIntListAttribute = ax::mojom::blink::IntListAttribute;
using AXMarkerType = ax::mojom::blink::MarkerType;

namespace blink {
namespace test {

TEST_F(AccessibilityTest, GetWordBoundaries) {
  // &#9728; is the sun emoji symbol.
  // &#2460; is circled digit one.
  // Full string: "This, ☀ জ is ... a---+++test. <p>word</p>"
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph">
        &quot;This, &#9728; &#2460; is ... a---+++test. &lt;p&gt;word&lt;/p&gt;&quot;
      </p>)HTML");

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  ax_paragraph->LoadInlineTextBoxes();

  const AXObject* ax_inline_text_box =
      ax_paragraph->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());

  VectorOf<int> expected_word_starts{0,  1,  5,  7,  9,  11, 14, 18, 19, 22, 23,
                                     24, 25, 29, 31, 32, 33, 34, 38, 40, 41};
  VectorOf<int> expected_word_ends{1,  5,  6,  8,  10, 13, 17, 19, 22, 23, 24,
                                   25, 29, 30, 32, 33, 34, 38, 40, 41, 43};
  VectorOf<int> word_starts, word_ends;
  ax_inline_text_box->GetWordBoundaries(word_starts, word_ends);
  EXPECT_EQ(expected_word_starts, word_starts);
  EXPECT_EQ(expected_word_ends, word_ends);
}

TEST_F(AccessibilityTest, GetDocumentMarkers) {
  // There should be four inline text boxes in the following paragraph.
  SetBodyInnerHTML(R"HTML(
      <style>* { font-size: 10px; }</style>
      <p id="paragraph" style="width: 10ch;">
        Misspelled text with a grammar error.
      </p>)HTML");

  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());

  // Mark the part of the paragraph that says "Misspelled text" with a spelling
  // marker, and the part that says "a grammar error" with a grammar marker.
  //
  // Note that the inline text boxes and the markers do not occupy the same text
  // range. The ranges simply overlap. Also note that the marker ranges include
  // non-collapsed white space found in the DOM.
  DocumentMarkerController& marker_controller = GetDocument().Markers();
  const EphemeralRange misspelled_range(Position(text, 9), Position(text, 24));
  marker_controller.AddSpellingMarker(misspelled_range);
  const EphemeralRange grammar_range(Position(text, 30), Position(text, 45));
  marker_controller.AddGrammarMarker(grammar_range);

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  ax_paragraph->LoadInlineTextBoxes();

  // kStaticText: "Misspelled text with a grammar error.".
  const AXObject* ax_text = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text->RoleValue());
  ASSERT_EQ(4, ax_text->ChildCountIncludingIgnored());

  // For each inline text box, angle brackets indicate where the marker starts
  // and ends respectively.

  // kInlineTextBox: "<Misspelled >".
  AXObject* ax_inline_text_box = ax_text->ChildAtIncludingIgnored(0);
  ASSERT_NE(nullptr, ax_inline_text_box);
  {
    ScopedFreezeAXCache freeze(ax_inline_text_box->AXObjectCache());
    ui::AXNodeData node_data;
    ax_inline_text_box->Serialize(&node_data, ui::kAXModeComplete);

    EXPECT_EQ(std::vector<int32_t>{int32_t(AXMarkerType::kSpelling)},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerTypes));
    EXPECT_EQ(std::vector<int32_t>{0},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerStarts));
    EXPECT_EQ(std::vector<int32_t>{11},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerEnds));
  }

  // kInlineTextBox: "<text> with <a >".
  ax_inline_text_box = ax_text->ChildAtIncludingIgnored(1);
  ASSERT_NE(nullptr, ax_inline_text_box);
  {
    ScopedFreezeAXCache freeze(ax_inline_text_box->AXObjectCache());
    ui::AXNodeData node_data;
    ax_inline_text_box->Serialize(&node_data, ui::kAXModeComplete);
    EXPECT_EQ((std::vector<int32_t>{int32_t(AXMarkerType::kSpelling),
                                    int32_t(AXMarkerType::kGrammar)}),
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerTypes));
    EXPECT_EQ((std::vector<int32_t>{0, 10}),
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerStarts));
    EXPECT_EQ((std::vector<int32_t>{4, 12}),
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerEnds));
  }

  // kInlineTextBox: "<grammar >".
  ax_inline_text_box = ax_text->ChildAtIncludingIgnored(2);
  ASSERT_NE(nullptr, ax_inline_text_box);
  {
    ScopedFreezeAXCache freeze(ax_inline_text_box->AXObjectCache());
    ui::AXNodeData node_data;
    ax_inline_text_box->Serialize(&node_data, ui::kAXModeComplete);
    EXPECT_EQ(std::vector<int32_t>{int32_t(AXMarkerType::kGrammar)},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerTypes));
    EXPECT_EQ(std::vector<int32_t>{0},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerStarts));
    EXPECT_EQ(std::vector<int32_t>{8},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerEnds));
  }

  // kInlineTextBox: "<error>.".
  ax_inline_text_box = ax_text->ChildAtIncludingIgnored(3);
  ASSERT_NE(nullptr, ax_inline_text_box);
  {
    ScopedFreezeAXCache freeze(ax_inline_text_box->AXObjectCache());
    ui::AXNodeData node_data;
    ax_inline_text_box->Serialize(&node_data, ui::kAXModeComplete);
    EXPECT_EQ(std::vector<int32_t>{int32_t(AXMarkerType::kGrammar)},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerTypes));
    EXPECT_EQ(std::vector<int32_t>{0},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerStarts));
    EXPECT_EQ(std::vector<int32_t>{5},
              node_data.GetIntListAttribute(AXIntListAttribute::kMarkerEnds));
  }
}

TEST_F(AccessibilityTest, TextOffsetInContainerWithASpan) {
  // There should be three inline text boxes in the following paragraph. The
  // span should reset the text start offset of all of them to 0.
  SetBodyInnerHTML(R"HTML(
      <style>* { font-size: 10px; }</style>
      <p id="paragraph">
        Hello <span>world </span>there.
      </p>)HTML");

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  ax_paragraph->LoadInlineTextBoxes();

  const AXObject* ax_inline_text_box =
      ax_paragraph->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(1, ax_inline_text_box->TextOffsetInContainer(1));

  ax_inline_text_box = ax_inline_text_box->NextInPreOrderIncludingIgnored()
                           ->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(2, ax_inline_text_box->TextOffsetInContainer(2));

  ax_inline_text_box = ax_inline_text_box->NextInPreOrderIncludingIgnored()
                           ->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(3, ax_inline_text_box->TextOffsetInContainer(3));

  ASSERT_EQ(nullptr, ax_inline_text_box->NextInPreOrderIncludingIgnored());
}

TEST_F(AccessibilityTest, TextOffsetInContainerWithMultipleInlineTextBoxes) {
  // There should be four inline text boxes in the following paragraph. The span
  // should not affect the text start offset of the text outside the span.
  SetBodyInnerHTML(R"HTML(
      <style>* { font-size: 10px; }</style>
      <p id="paragraph" style="width: 5ch;">
        <span>Offset</span>Hello world there.
      </p>)HTML");

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  ax_paragraph->LoadInlineTextBoxes();

  const AXObject* ax_inline_text_box =
      ax_paragraph->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(1, ax_inline_text_box->TextOffsetInContainer(1));

  ax_inline_text_box = ax_inline_text_box->NextInPreOrderIncludingIgnored()
                           ->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(1, ax_inline_text_box->TextOffsetInContainer(1));

  ax_inline_text_box = ax_inline_text_box->NextSiblingIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(6, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(8, ax_inline_text_box->TextOffsetInContainer(2));

  ax_inline_text_box = ax_inline_text_box->NextSiblingIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(12, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(15, ax_inline_text_box->TextOffsetInContainer(3));

  ASSERT_EQ(nullptr, ax_inline_text_box->NextInPreOrderIncludingIgnored());
}

TEST_F(AccessibilityTest, TextOffsetInContainerWithLineBreak) {
  // There should be three inline text boxes in the following paragraph. The
  // line break should reset the text start offset to 0 of both the inline text
  // box inside the line break, as well as the text start ofset of the second
  // line.
  SetBodyInnerHTML(R"HTML(
      <style>* { font-size: 10px; }</style>
      <p id="paragraph">
        Line one.<br>
        Line two.
      </p>)HTML");

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  ax_paragraph->LoadInlineTextBoxes();

  const AXObject* ax_inline_text_box =
      ax_paragraph->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(1, ax_inline_text_box->TextOffsetInContainer(1));

  ax_inline_text_box = ax_inline_text_box->NextInPreOrderIncludingIgnored()
                           ->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));

  ax_inline_text_box = ax_inline_text_box->NextInPreOrderIncludingIgnored()
                           ->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());
  EXPECT_EQ(0, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(2, ax_inline_text_box->TextOffsetInContainer(2));

  ASSERT_EQ(nullptr, ax_inline_text_box->NextInPreOrderIncludingIgnored());
}

TEST_F(AccessibilityTest, TextOffsetInContainerWithBreakWord) {
  // There should be three inline text boxes in the following paragraph because
  // of the narrow width and the long word, coupled with the CSS "break-word"
  // property. Each inline text box should have a different offset in container.
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
      <style>* { font: 10px/10px Ahem; }</style>
      <p id="paragraph" style="width: 5ch; word-wrap: break-word;">
        VeryLongWord
      </p>)HTML");

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  ax_paragraph->LoadInlineTextBoxes();

  const AXObject* ax_inline_text_box =
      ax_paragraph->DeepestFirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());

  int text_start_offset = 0;
  int text_end_offset = ax_inline_text_box->TextLength();
  EXPECT_EQ(text_start_offset, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(text_end_offset, ax_inline_text_box->TextOffsetInContainer(
                                 ax_inline_text_box->TextLength()));

  ax_inline_text_box = ax_inline_text_box->NextSiblingIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());

  text_start_offset = text_end_offset;
  text_end_offset = text_start_offset + ax_inline_text_box->TextLength();
  EXPECT_EQ(text_start_offset, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(text_end_offset, ax_inline_text_box->TextOffsetInContainer(
                                 ax_inline_text_box->TextLength()));

  ax_inline_text_box = ax_inline_text_box->NextSiblingIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_inline_text_box->RoleValue());

  text_start_offset = text_end_offset;
  text_end_offset = text_start_offset + ax_inline_text_box->TextLength();
  EXPECT_EQ(text_start_offset, ax_inline_text_box->TextOffsetInContainer(0));
  EXPECT_EQ(text_end_offset, ax_inline_text_box->TextOffsetInContainer(
                                 ax_inline_text_box->TextLength()));

  ASSERT_EQ(nullptr, ax_inline_text_box->NextSiblingIncludingIgnored());
}

TEST_F(AccessibilityTest, GetTextDirection) {
  using WritingDirection = ax::mojom::blink::WritingDirection;
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph" style="writing-mode:sideways-lr;">
        Text.
      </p>)HTML");
  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ax_paragraph->LoadInlineTextBoxes();

  const AXObject* ax_text_box =
      ax_paragraph->DeepestFirstChildIncludingIgnored();
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox, ax_text_box->RoleValue());
  // AXInlineTextBox::GetTextDirection() is used.
  EXPECT_EQ(WritingDirection::kBtt, ax_text_box->GetTextDirection());

  const AXObject* ax_static_text = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());
  // AXNodeObject::GetTextDirection() is used.
  EXPECT_EQ(WritingDirection::kBtt, ax_static_text->GetTextDirection());
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_Simple) {
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph">Hello <em>World</em></p>)HTML");

  // id#=3249 rootWebArea
  // ++id#=3250 genericContainer ignored
  // ++++id#=3251 genericContainer ignored
  // ++++++id#=3252 paragraph
  // ++++++++id#=3247 staticText name='Hello '
  //     nextOnLineId=inlineTextBox:"World"
  // ++++++++++id#=-1000002414 inlineTextBox name='Hello '
  //     nextOnLineId=inlineTextBox:"World"
  // ++++++++id#=3257 emphasis
  // ++++++++++id#=3248 staticText name='World'
  // ++++++++++++id#=-1000002415 inlineTextBox name='World'

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  const AXObject* ax_static_text = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("Hello ", it.GetText());
  std::optional<AXBlockFlowIterator::MapKey> previous_on_line =
      it.PreviousOnLine();
  ASSERT_FALSE(previous_on_line.has_value());
  std::optional<AXBlockFlowIterator::MapKey> next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());
  ASSERT_EQ("World", it.GetTextForTesting(next_on_line.value()));

  // 'World' is not part of the same LayoutText object.
  ASSERT_FALSE(it.Next());
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_SoftLinebreak) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      p, textarea {
        width: 16ch;
        font: 16px/16px Ahem;
      }
      textarea {
        height: 100px;
      }
    </style>
    <p id="paragraph">
      Antidisestablishmentarianism is a really long English word!
    </p>
    <textarea id="textarea">Antidisestablishmentarianism is really long!
    </textarea>)HTML");

  // id#=1673 rootWebArea
  // ++id#=1674 genericContainer ignored
  // ++++id#=1675 genericContainer ignored
  // ++++++id#=1676 paragraph
  // ++++++++id#=1670 staticText
  //    name='Antidisestablishmentarianism is a really long English word!'
  // ++++++++++id#=-1000001399 inlineTextBox
  //    name='Antidisestablishmentarianism '
  // ++++++++++id#=-1000001400 inlineTextBox name='is a really long '
  // ++++++++++id#=-1000001401 inlineTextBox name='English word!'
  // ++++++id#=812 textField
  // ++++++++id#=816 genericContainer
  // ++++++++++id#=809 staticText
  //     name='Antidisestablishmentarianism is really long!<newline>'
  // ++++++++++++id#=-1000000613 inlineTextBox name='Antidisestablish'
  // ++++++++++++id#=-1000000614 inlineTextBox
  //     name='mentarianism is' nextOnLineId=inlineTextBox:" "
  // ++++++++++++id#=-1000000615 inlineTextBox name=' '
  // ++++++++++++id#=-1000000616 inlineTextBox
  //     name='really long!' ...
  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  const AXObject* ax_static_text = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);

  ASSERT_TRUE(it.Next());
  // Trailing whitespace expected since a soft linebreak.
  ASSERT_EQ("Antidisestablishmentarianism ", it.GetText());
  std::optional<AXBlockFlowIterator::MapKey> previous_on_line =
      it.PreviousOnLine();
  ASSERT_FALSE(previous_on_line.has_value());
  // Wraps to next line so no next on line fragment.
  std::optional<AXBlockFlowIterator::MapKey> next_on_line = it.NextOnLine();
  ASSERT_FALSE(next_on_line.has_value());

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("is a really long ", it.GetText());
  previous_on_line = it.PreviousOnLine();
  ASSERT_FALSE(previous_on_line.has_value());
  next_on_line = it.NextOnLine();
  ASSERT_FALSE(next_on_line.has_value());

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("English word!", it.GetText());
  previous_on_line = it.PreviousOnLine();
  ASSERT_FALSE(previous_on_line.has_value());
  next_on_line = it.NextOnLine();
  ASSERT_FALSE(next_on_line.has_value());

  ASSERT_FALSE(it.Next());

  AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());
  const AXObject* ax_textarea_container =
      ax_textarea->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_textarea_container);
  const AXObject* ax_text_box_static_text =
      ax_textarea_container->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text_box_static_text);
  it = AXBlockFlowIterator(ax_text_box_static_text);

  ASSERT_TRUE(it.Next());
  // No trailing whitespace since breaking mid word.
  ASSERT_EQ("Antidisestablish", it.GetText());
  previous_on_line = it.PreviousOnLine();
  ASSERT_FALSE(previous_on_line.has_value());
  next_on_line = it.NextOnLine();
  ASSERT_FALSE(next_on_line.has_value());

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("mentarianism is", it.GetText());
  previous_on_line = it.PreviousOnLine();
  ASSERT_FALSE(previous_on_line.has_value());
  next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());

  // trailing whitespace on the second line is in its own fragment.
  ASSERT_TRUE(it.Next());
  ASSERT_EQ(" ", it.GetText());
  previous_on_line = it.PreviousOnLine();
  ASSERT_TRUE(previous_on_line.has_value());
  ASSERT_EQ("mentarianism is", it.GetTextForTesting(previous_on_line.value()));
  next_on_line = it.NextOnLine();
  ASSERT_FALSE(next_on_line.has_value());

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("really long!", it.GetText());

  // Trailing whitespace at the end due to test formatting.
  // Skipping further assertion checking since not really pertinent to
  // testing soft-line-breaking.
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_HardtLinebreak) {
  SetBodyInnerHTML(R"HTML(
    <p id="paragraph">Hello <br>World!</p>)HTML");

  // id#=1604 rootWebArea name='Forced linebreak'
  // ++id#=1605 genericContainer ignored
  // ++++id#=1606 genericContainer ignored
  // ++++++id#=1607 paragraph
  // ++++++++id#=1601 staticText name='Hello'
  //                  nextOnLineId=inlineTextBox:"<newline>"
  // ++++++++++id#=-1000001191 inlineTextBox name='Hello'
  //                           nextOnLineId=inlineTextBox:"<newline>"
  // ++++++++id#=1602 lineBreak name='<newline>'
  // ++++++++++id#=-1000001187 inlineTextBox name='<newline>'
  // ++++++++id#=1603 staticText name='World!'
  // ++++++++++id#=-1000001192 inlineTextBox name='World!'

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  const AXObject* ax_static_text = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);
  ASSERT_TRUE(it.Next());
  // Trailing whitespace suppressed even though there is whitespace before the
  // linebreak since using a hard linebreak.
  ASSERT_EQ("Hello", it.GetText());
  // Hard linebreak token is on the same line.
  std::optional<AXBlockFlowIterator::MapKey> next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());
  ASSERT_EQ("\n", it.GetTextForTesting(next_on_line.value()));

  // Linebreak token is not part of the text node. Subsequent text is in a
  // separate node.
  ASSERT_FALSE(it.Next());
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_Ellipsis) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        width: 400px;
      }

      div, span {
        outline: 1px solid;
        font-size: 40px;
        font-family: Ahem;
      }
    </style>
    <div><span id="span">SPAN NESTED INSIDE DIV</span> CONTAINER DIV</div>
 )HTML");

  // id#=1621 rootWebArea
  // ++id#=1622 genericContainer ignored
  // ++++id#=1623 genericContainer ignored
  // ++++++id#=1624 genericContainer
  // ++++++++id#=1619 staticText name='SPAN NESTED INSIDE DIV'
  // ++++++++++id#=-1000001207 inlineTextBox name='SPAN NESTED INSIDE DIV'
  //    nextOnLineId=inlineTextBox:"SPAN NESTED INS"
  // ++++++++++id#=-1000001208 inlineTextBox name='SPAN NEST'
  //    nextOnLineId=inlineTextBox:" CONTAINER DIV"
  // ++++++++++id#=-1000001209 inlineTextBox name='…'
  // ++++++++id#=1620 staticText name=' CONTAINER DIV'
  // ++++++++++id#=-1000001210 inlineTextBox name=' CONTAINER DIV'

  AXObject* ax_span = GetAXObjectByElementId("span");
  ASSERT_NE(nullptr, ax_span);
  const AXObject* ax_static_text = ax_span->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);
  ASSERT_TRUE(it.Next());
  ASSERT_EQ("SPAN NESTED INSIDE DIV", it.GetText());

  // Though the following behavior is correct insofar as it agrees with
  // our AbstractInlineTextBox based algorithm, it breaks detection of
  // bounding boxes for text selections, since that code assumes that the
  // sum of the lengths of the inline text boxes aligns with the length
  // of the parent static text object.
  // TODO (accessibility): Revisit how inline text boxes are computed for
  // ellipsis.
  std::optional<AXBlockFlowIterator::MapKey> next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());
  ASSERT_EQ("SPAN NEST", it.GetTextForTesting(next_on_line.value()));

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("SPAN NEST", it.GetText());

  // Next on line skips over the ellipsis.
  next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());
  ASSERT_EQ(" CONTAINER DIV", it.GetTextForTesting(next_on_line.value()));

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("\u2026", it.GetText().Utf8());  // Horizontal ellipsis.

  // " CONTAINER DIV" is outside of the span.
  ASSERT_FALSE(it.Next());
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_Ruby) {
  SetBodyInnerHTML(R"HTML(
    <ruby id="ruby">Ruby base<rt>ruby text</rt></ruby>)HTML");

  // id#=1 rootWebArea
  // ++id#=4 genericContainer ignored
  // ++++id#=5 genericContainer ignored
  // ++++++id#=6 paragraph
  // ++++++++id#=8 ruby description="ruby text"
  // ++++++++++id#=2 staticText name='ruby base' nextOnLineId=staticText
  // ++++++++++++id#=-1000000004 inlineTextBox name='ruby base'
  //                             nextOnLineId=staticText
  // ++++++++++id#=9 rubyAnnotation ignored
  // ++++++++++++id#=3 staticText ignored

  AXObject* ax_ruby = GetAXObjectByElementId("ruby");
  ASSERT_NE(nullptr, ax_ruby);
  ASSERT_EQ(ax::mojom::Role::kRuby, ax_ruby->RoleValue());
  const AXObject* ax_static_text = ax_ruby->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);
  ASSERT_TRUE(it.Next());
  ASSERT_EQ("Ruby base", it.GetText());

  // Ruby annotation is next on line despite being rendered above the base text.
  // Note: Inline text boxes for the annotation do not get serialized due to the
  // static text being marked as ignored. Nonetheless, the next on line ID
  // points to the annotation.
  std::optional<AXBlockFlowIterator::MapKey> next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());
  ASSERT_EQ("ruby text",
            AXBlockFlowIterator::GetTextForTesting(next_on_line.value()));

  ASSERT_FALSE(it.Next());
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_Ruby2) {
  SetBodyInnerHTML(R"HTML(
    <p style="font-family:monospace; width:5ch;">
      <ruby id="ruby">ruby base<rt>ruby text</rt></ruby>
    </p>)HTML");

  // id#=798 rootWebArea
  // ++id#=799 genericContainer ignored
  // ++++id#=800 genericContainer ignored
  // ++++++id#=801 paragraph
  // ++++++++id#=803 ruby description='ruby text'
  // ++++++++++id#=796 staticText name='ruby base' nextOnLineId=staticText
  // ++++++++++++id#=-1000000986 inlineTextBox name='ruby '
  // ++++++++++++id#=-1000000987 inlineTextBox name='base'
  //                             nextOnLineId=staticText
  // ++++++++++id#=804 rubyAnnotation ignored
  // ++++++++++++id#=797 staticText ignored

  AXObject* ax_ruby = GetAXObjectByElementId("ruby");
  ASSERT_NE(nullptr, ax_ruby);
  ASSERT_EQ(ax::mojom::Role::kRuby, ax_ruby->RoleValue());
  const AXObject* ax_static_text = ax_ruby->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);
  ASSERT_TRUE(it.Next());
  ASSERT_EQ("ruby ", it.GetText());

  // Ruby annotation is next on line despite being rendered above the base text.
  std::optional<AXBlockFlowIterator::MapKey> next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());
  ASSERT_EQ("ruby",
            AXBlockFlowIterator::GetTextForTesting(next_on_line.value()));
  ASSERT_TRUE(it.Next());
  ASSERT_EQ("base", it.GetText());
  next_on_line = it.NextOnLine();
  ASSERT_TRUE(next_on_line.has_value());
  ASSERT_EQ("text",
            AXBlockFlowIterator::GetTextForTesting(next_on_line.value()));
  ASSERT_FALSE(it.Next());
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_CharacterOffsets) {
  // Then Ahem font has consistent font metrics across platforms.
  LoadAhem();

  SetBodyInnerHTML(R"HTML(
    <style>
      p, textarea {
        width: 5ch;
        font: 16px/16px Ahem;
      }
      textarea {
        height: 100px;
      }
    </style>
    <p id="paragraph">Hello world!</p>)HTML");

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  const AXObject* ax_static_text = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);
  ASSERT_TRUE(it.Next());
  ASSERT_EQ("Hello ", it.GetText());

  // The trailing whitespace in "Hello " is not part of the actual text fragment
  // since not rendered. When extracting the glyphs, the length of the vector
  // padded to include the trailing space a zero-width glyph.
  std::vector<int> expected_character_offsets = {16, 32, 48, 64, 80, 80};
  ASSERT_EQ(expected_character_offsets, it.GetCharacterLayoutPixelOffsets());

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("world!", it.GetText());
  expected_character_offsets = {16, 32, 48, 64, 80, 96};

  ASSERT_FALSE(it.Next());
}

TEST_F(AccessibilityTest, AXBlockFlowIteratorAPI_CharacterOffsets_Ligature) {
  // Google Sans supports ligatures (e.g. "fi" being rendered as a single glyph.
  LoadFontFromFile(GetFrame(), test::CoreTestDataPath("GoogleSans-Regular.ttf"),
                   AtomicString("Google Sans"));

  SetBodyInnerHTML(R"HTML(
    <style>
      p {
       font: 16px Google Sans;
      }
      span {
        color: red;
      }
    </style>
    <p id="paragraph">f<span id="span">ire</span></p>)HTML");

  AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());
  const AXObject* ax_static_text = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  AXBlockFlowIterator it(ax_static_text);
  ASSERT_TRUE(it.Next());
  ASSERT_EQ("f", it.GetText());
  // The offset will be for the "fi" ligature and not for "f" since the
  // "Google Sans" font uses ligatures. Metrics are not platform agnostic, so we
  // cannot assert the actual reported offsets unless we have expectations on a
  // per-platform basis. The important thing is how "i" is handled at the start
  // of the next fragment.
  ASSERT_EQ(1u, it.GetCharacterLayoutPixelOffsets().size());

  ASSERT_TRUE(it.NextOnLine().has_value());
  ASSERT_FALSE(it.Next());

  const AXObject* ax_span = GetAXObjectByElementId("span");
  ax_static_text = ax_span->FirstChildIncludingIgnored();
  it = AXBlockFlowIterator(ax_static_text);

  ASSERT_TRUE(it.Next());
  ASSERT_EQ("ire", it.GetText());

  const std::vector<int> offsets = it.GetCharacterLayoutPixelOffsets();
  ASSERT_EQ(3u, offsets.size());
  // "i"  was rendered as part of the "fi" ligature and is a reported as a
  // zero width glyph, to preserve character alignment.
  ASSERT_EQ(0, offsets[0]);

  ASSERT_FALSE(it.Next());
}

}  // namespace test

}  // namespace blink
```