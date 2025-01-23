Response:
The user wants to understand the functionality of the `granularity_strategy_test.cc` file in the Chromium Blink engine.

Here's a breakdown of how to address the request:

1. **Identify the core purpose of the file:** The file name strongly suggests it's testing different selection granularity strategies. The presence of `EditingTestBase` reinforces this.

2. **Analyze the included headers:**  The headers give clues about the functionalities being tested:
    - DOM manipulation (`document.h`, `element.h`, `text.h`)
    - Selection management (`frame_selection.h`, `selection_template.h`, `visible_selection.h`)
    - Positioning and layout (`local_caret_rect.h`, `visible_position.h`, `local_frame_view.h`)
    - Test framework (`testing/gtest/include/gtest/gtest.h`)

3. **Examine the class `GranularityStrategyTest`:**
    - The `SetUp()` method indicates that the tests configure the selection strategy.
    - Helper methods like `AppendTextNode`, `SetInnerHTML`, `ParseText`, `Setup...` are for creating test scenarios.
    - `TestDirectionExpand`, `TestDirectionShrink`, `TestDirectionSwitchSide` point to specific tests for the "Direction" selection strategy.
    - The `letter_pos_` and `word_middles_` members are used to simulate mouse interactions for selection.

4. **Analyze the individual test cases:** Each `TEST_F` function focuses on a specific aspect of selection granularity. Pay attention to:
    - The setup of the HTML content.
    - How the initial selection is created.
    - How `MoveRangeSelectionExtent` is used with specific `gfx::Point` values (often derived from `letter_pos_` and `word_middles_`).
    - The expected selected text after each operation.

5. **Connect to web technologies (JavaScript, HTML, CSS):**
    - **HTML:** The tests manipulate HTML structure (`div`, `span`, text nodes). The scenarios test how selection behaves across these elements.
    - **CSS:** Some tests specifically set CSS properties (`transform`, `vertical-align`, `font-size`) to see how these affect selection granularity.
    - **JavaScript:** While this test file is C++, it directly tests the underlying selection mechanisms that JavaScript APIs like `window.getSelection()` rely on. User interactions in a web page (like dragging the mouse) would eventually trigger these C++ selection algorithms.

6. **Identify logical reasoning and assumptions:** The tests make assumptions about how the "Direction" strategy should behave when the mouse moves across character and word boundaries. The input is the mouse position (represented by `gfx::Point`), and the output is the updated selection (specifically the `SelectedText`).

7. **Pinpoint potential user errors:** Incorrectly implementing selection logic or not accounting for different CSS properties could lead to unexpected selection behavior.

8. **Trace user actions to the code:** Think about the sequence of user actions that would lead to this code being executed. Selecting text with the mouse is the primary trigger.

9. **Structure the explanation:** Organize the findings into clear sections addressing each part of the user's request. Provide concrete examples where applicable.

**Self-Correction/Refinement during thought process:**

- Initially, I might focus too much on the code details. It's important to step back and explain the *purpose* of the file first.
-  Need to be explicit about the relationship with JavaScript, HTML, and CSS, even though the file itself is C++. It's testing the engine that powers these technologies.
- Ensure the examples of user errors and debugging steps are practical and easy to understand.
-  The explanation of the logical reasoning needs to clearly connect the input (mouse position) to the output (selection).
这个文件 `granularity_strategy_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件，其主要功能是 **测试不同的文本选择粒度策略 (Granularity Strategy) 的行为**。

更具体地说，它测试了在用户进行文本选择时，引擎如何根据不同的策略来扩展或收缩选择范围。这些策略决定了选择是按字符、按单词还是按其他逻辑单元进行。

下面分别列举其与 JavaScript, HTML, CSS 的关系，逻辑推理，用户错误和用户操作的调试线索：

**1. 与 JavaScript, HTML, CSS 的关系：**

这个测试文件虽然是用 C++ 编写的，但它直接测试了 Blink 引擎中处理用户与网页交互的核心逻辑，这些交互最终会通过 JavaScript API 反映出来，并受到 HTML 结构和 CSS 样式的影响。

* **HTML:**
    * 测试用例会创建不同的 HTML 结构，例如包含 `<div>` 和 `<span>` 元素的文本内容。
    * 测试目标是选择这些 HTML 结构中的文本内容，验证在不同的 HTML 结构下，选择策略是否按预期工作。
    * **举例:**  `SetupTextSpan` 函数创建了一个包含 `<span>` 元素的 HTML 结构，用于测试在跨越不同 HTML 元素时的选择行为。
    * **HTML 示例:**
      ```html
      <div id='mytext'>
        Text before <span>Text inside</span> Text after
      </div>
      ```

* **CSS:**
    * 测试用例会应用不同的 CSS 样式，例如 `transform`, `vertical-align`, `font-size`，来观察这些样式如何影响文本的布局以及选择策略的行为。
    * 例如，`DirectionRotate` 测试用例测试了当文本被旋转时，选择策略是否能正确工作，或者是否会退回到基于字符的选择。
    * **举例:** `SetupTransform` 函数设置了 `transform: scale(1,-1) translate(0,-100px);` 的 CSS 样式，来测试在应用了变换的情况下，选择策略的准确性。
    * **CSS 示例:**
      ```css
      div {
        transform: translateZ(0);
      }
      span {
        vertical-align: 20px;
        font-size: 200%;
      }
      ```

* **JavaScript:**
    *  这个测试文件测试的底层选择逻辑是 JavaScript `window.getSelection()` API 的基础。当用户在网页上用鼠标拖动选择文本时，浏览器引擎内部会调用类似的逻辑来确定选择范围。
    *  测试验证了当用户通过鼠标操作（最终转化为屏幕坐标）来扩展或收缩选择时，引擎内部的粒度策略是否正确地更新了选择范围。
    * **举例:**  虽然测试本身没有直接的 JavaScript 代码，但其测试的 `Selection().MoveRangeSelectionExtent()` 方法模拟了用户通过鼠标拖动来改变选择范围的操作，这与 JavaScript 中处理 `mouseup` 和 `mousemove` 事件的逻辑密切相关。

**2. 逻辑推理 (假设输入与输出):**

这些测试用例主要基于逻辑推理来验证选择策略的行为。它们模拟了用户在不同位置点击和拖动鼠标，并断言最终的选择范围是否符合预期。

* **假设输入:** 用户在文本 "abcdef ghij kl mno pqr stuvwi inm mnii," 中，首先点击 'p' 字符（作为选择的起始点），然后拖动鼠标到不同的位置。
* **输出 (取决于选择策略和拖动到的位置):**
    * **字符粒度策略 (CharacterGranularityStrategy):** 如果拖动到 'q'，则选择 "pq"。如果拖动到 'r'，则选择 "pqr"。
    * **方向粒度策略 (DirectionGranularityStrategy):**  这种策略会根据拖动方向和跨越的边界（如单词边界）来调整选择粒度。
        * 如果拖动到 'q'，可能仍然选择 "p"。
        * 如果继续拖动到 'r'，可能选择 "pq"。
        * 如果拖动到空格之后，可能会选择整个单词 "pqr "。
        * 如果拖动到下一个单词的中间，可能会选择两个完整的单词。

* **具体测试用例 `TestDirectionExpand()` 的假设输入与输出:**
    * **假设输入:**
        * 初始选择：光标在 'o' 和 'p' 之间 (`^` 表示基点 base, `|` 表示终点 extent)。
        * 连续调用 `Selection().MoveRangeSelectionExtent()` 并传入 `letter_pos_` 中不同字符的坐标。
    * **预期输出:**
        * 移动到 'q' 的位置：选择 "pq"。
        * 再次移动到 'q' 的位置：选择 "pq" (相同位置不改变选择)。
        * 移动到 'r' 的位置：选择 "pqr"。
        * 移动到 ' ' (空格) 的位置：选择 "pqr "。
        * 移动到下一个单词 's' 的位置：选择 "pqr " (在单词中间不会立即扩展到整个单词)。
        * 移动到下一个单词的中间位置 (`word_middles_`)：选择 "pqr stuvwi"。

**3. 涉及用户或者编程常见的使用错误:**

虽然这个文件是测试代码，但它反映了在实现选择功能时可能遇到的错误：

* **没有正确处理单词边界:**  如果选择策略没有正确判断单词的起始和结束，用户在拖动鼠标时可能会遇到不符合预期的选择行为，例如，选择了半个单词或者没有包含预期的空格。
* **没有考虑 CSS 样式的影响:**  忽略 CSS 样式（如 `transform`，`vertical-align`）可能导致计算出的文本位置不准确，从而影响选择的范围。例如，旋转后的文本的像素位置与原始位置不同，如果没有考虑到这一点，选择可能会错位。
* **在复杂的 HTML 结构中选择错误:**  当文本跨越不同的 HTML 元素时，选择逻辑需要正确处理这些边界。例如，用户可能期望选择 `<span>` 标签内部的整个文本，但如果逻辑错误，可能只会选择部分文本或者包含外部的文本。
* **编程错误:**  例如，在计算鼠标位置与文本位置的对应关系时出现 off-by-one 错误，或者在更新选择范围时逻辑判断错误。

**4. 说明用户操作是如何一步步的到达这里，作为调试线索:**

当在 Chromium 浏览器中进行文本选择时，用户的操作会触发一系列事件，最终会调用到 Blink 引擎中的选择逻辑，而 `granularity_strategy_test.cc` 测试的就是这部分核心逻辑。

以下是一个简化的用户操作到代码执行的路径：

1. **用户操作:** 用户在浏览器渲染的网页上，用鼠标**按下**并**拖动**以选择文本。
2. **浏览器事件:** 用户的鼠标操作会触发浏览器事件，例如 `mousedown`, `mousemove`, `mouseup`。
3. **事件处理:** 浏览器接收到这些事件后，会将这些事件传递给渲染引擎 (Blink)。
4. **命中测试 (Hit Testing):**  当鼠标移动时，Blink 引擎会执行命中测试，确定鼠标光标当前指向的 DOM 节点和文本位置。
5. **选择逻辑调用:**
    * 当 `mousedown` 事件发生时，会确定选择的起始位置。
    * 当 `mousemove` 事件发生时，会调用选择相关的逻辑来更新选择的终点。  `Selection().MoveRangeSelectionExtent()` 方法在测试中模拟的就是这个过程。
    * **`GranularityStrategy` 的参与:**  此时，Blink 引擎会根据当前设置的选择策略（例如，方向粒度策略）来决定如何扩展或收缩选择范围。`granularity_strategy_test.cc` 中的测试用例正是为了验证这些策略的实现是否正确。
6. **更新 UI:**  选择范围确定后，浏览器会更新用户界面，高亮显示选中的文本。

**调试线索:**

如果用户报告了文本选择方面的问题（例如，选择不准确、行为不符合预期），开发者可以通过以下方式进行调试，并可能需要参考类似 `granularity_strategy_test.cc` 的测试用例：

* **复现用户操作:**  尝试完全按照用户描述的步骤操作，在相同的网页和浏览器环境下复现问题。
* **检查 DOM 结构和 CSS 样式:**  查看出现问题的网页的 HTML 结构和 CSS 样式，特别是影响文本布局的样式，例如 `transform`, `position`, `float` 等。
* **使用开发者工具:**  使用浏览器的开发者工具，例如 "Elements" 面板查看 DOM 结构和应用的样式，"Performance" 面板查看事件触发和函数调用。
* **断点调试 Blink 引擎代码:**  如果怀疑是 Blink 引擎的选择逻辑有问题，可以设置断点在相关的 C++ 代码中进行调试，例如 `FrameSelection::MoveRangeSelectionExtent()`, `DirectionGranularityStrategy::AlterSelection()`, 等等。`granularity_strategy_test.cc` 中的测试用例可以作为参考，理解这些函数的输入和预期输出。
* **查看测试用例:**  如果问题与特定的选择粒度策略相关，可以查看 `granularity_strategy_test.cc` 中相应的测试用例，看是否有类似的场景被测试到，或者是否可以添加新的测试用例来覆盖该场景。

总而言之，`granularity_strategy_test.cc` 是 Blink 引擎中用于确保文本选择功能正确性的关键测试文件，它模拟了用户与网页的交互，并验证了不同的选择粒度策略在各种场景下的行为。理解这个文件有助于理解浏览器引擎如何处理文本选择，并为调试相关的 bug 提供线索。

### 提示词
```
这是目录为blink/renderer/core/editing/granularity_strategy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

#define EXPECT_EQ_SELECTED_TEXT(text) \
  EXPECT_EQ(text, Selection().SelectedText().Utf8())

gfx::Point VisiblePositionToContentsPoint(const VisiblePosition& pos) {
  gfx::Point result = AbsoluteSelectionBoundsOf(pos).bottom_left();
  // Need to move the point at least by 1 - caret's minXMaxYCorner is not
  // evaluated to the same line as the text by hit testing.
  result.Offset(0, -1);
  return result;
}

using TextNodeVector = HeapVector<Member<Text>>;

class GranularityStrategyTest : public EditingTestBase {
 protected:
  void SetUp() override;

  Text* AppendTextNode(const String& data);
  void SetInnerHTML(const char*);
  // Parses the text node, appending the info to letter_pos_ and word_middles_.
  void ParseText(Text*);
  void ParseText(const TextNodeVector&);

  Text* SetupTranslateZ(String);
  Text* SetupTransform(String);
  Text* SetupRotate(String);
  void SetupTextSpan(String str1,
                     String str2,
                     String str3,
                     wtf_size_t sel_begin,
                     wtf_size_t sel_end);
  void SetupVerticalAlign(String str1,
                          String str2,
                          String str3,
                          wtf_size_t sel_begin,
                          wtf_size_t sel_end);
  void SetupFontSize(String str1,
                     String str2,
                     String str3,
                     wtf_size_t sel_begin,
                     wtf_size_t sel_end);

  void TestDirectionExpand();
  void TestDirectionShrink();
  void TestDirectionSwitchSide();

  // Pixel coordinates of the positions for each letter within the text being
  // tested.
  Vector<gfx::Point> letter_pos_;
  // Pixel coordinates of the middles of the words in the text being tested.
  // (y coordinate is based on y coordinates of letter_pos_)
  Vector<gfx::Point> word_middles_;
};

void GranularityStrategyTest::SetUp() {
  PageTestBase::SetUp();
  GetFrame().GetSettings()->SetDefaultFontSize(12);
  GetFrame().GetSettings()->SetSelectionStrategy(SelectionStrategy::kDirection);
}

Text* GranularityStrategyTest::AppendTextNode(const String& data) {
  Text* text = GetDocument().createTextNode(data);
  GetDocument().body()->AppendChild(text);
  return text;
}

void GranularityStrategyTest::SetInnerHTML(const char* html_content) {
  GetDocument().documentElement()->setInnerHTML(String::FromUTF8(html_content));
  UpdateAllLifecyclePhasesForTest();
}

void GranularityStrategyTest::ParseText(Text* text) {
  TextNodeVector text_nodes;
  text_nodes.push_back(text);
  ParseText(text_nodes);
}

void GranularityStrategyTest::ParseText(const TextNodeVector& text_nodes) {
  bool word_started = false;
  int word_start_index = 0;
  for (auto& text : text_nodes) {
    wtf_size_t word_start_index_offset = letter_pos_.size();
    String str = text->wholeText();
    for (wtf_size_t i = 0; i < str.length(); i++) {
      letter_pos_.push_back(VisiblePositionToContentsPoint(
          CreateVisiblePosition(Position(text, i))));
      char c = str[i];
      if (IsASCIIAlphanumeric(c) && !word_started) {
        word_start_index = i + word_start_index_offset;
        word_started = true;
      } else if (!IsASCIIAlphanumeric(c) && word_started) {
        gfx::Point word_middle((letter_pos_[word_start_index].x() +
                                letter_pos_[i + word_start_index_offset].x()) /
                                   2,
                               letter_pos_[word_start_index].y());
        word_middles_.push_back(word_middle);
        word_started = false;
      }
    }
  }
  if (word_started) {
    const auto& last_node = text_nodes.back();
    int x_end = VisiblePositionToContentsPoint(
                    CreateVisiblePosition(
                        Position(last_node, last_node->wholeText().length())))
                    .x();
    gfx::Point word_middle((letter_pos_[word_start_index].x() + x_end) / 2,
                           letter_pos_[word_start_index].y());
    word_middles_.push_back(word_middle);
  }
}

Text* GranularityStrategyTest::SetupTranslateZ(String str) {
  SetInnerHTML(
      "<html>"
      "<head>"
      "<style>"
      "div {"
      "transform: translateZ(0);"
      "}"
      "</style>"
      "</head>"
      "<body>"
      "<div id='mytext'></div>"
      "</body>"
      "</html>");

  Text* text = GetDocument().createTextNode(str);
  Element* div = GetDocument().getElementById(AtomicString("mytext"));
  div->AppendChild(text);

  UpdateAllLifecyclePhasesForTest();

  ParseText(text);
  return text;
}

Text* GranularityStrategyTest::SetupTransform(String str) {
  SetInnerHTML(
      "<html>"
      "<head>"
      "<style>"
      "div {"
      "transform: scale(1,-1) translate(0,-100px);"
      "}"
      "</style>"
      "</head>"
      "<body>"
      "<div id='mytext'></div>"
      "</body>"
      "</html>");

  Text* text = GetDocument().createTextNode(str);
  Element* div = GetDocument().getElementById(AtomicString("mytext"));
  div->AppendChild(text);

  UpdateAllLifecyclePhasesForTest();

  ParseText(text);
  return text;
}

Text* GranularityStrategyTest::SetupRotate(String str) {
  SetInnerHTML(
      "<html>"
      "<head>"
      "<style>"
      "div {"
      "transform: translate(0px,600px) rotate(90deg);"
      "}"
      "</style>"
      "</head>"
      "<body>"
      "<div id='mytext'></div>"
      "</body>"
      "</html>");

  Text* text = GetDocument().createTextNode(str);
  Element* div = GetDocument().getElementById(AtomicString("mytext"));
  div->AppendChild(text);

  UpdateAllLifecyclePhasesForTest();

  ParseText(text);
  return text;
}

void GranularityStrategyTest::SetupTextSpan(String str1,
                                            String str2,
                                            String str3,
                                            wtf_size_t sel_begin,
                                            wtf_size_t sel_end) {
  Text* text1 = GetDocument().createTextNode(str1);
  Text* text2 = GetDocument().createTextNode(str2);
  Text* text3 = GetDocument().createTextNode(str3);
  auto* span = MakeGarbageCollected<HTMLSpanElement>(GetDocument());
  Element* div = GetDocument().getElementById(AtomicString("mytext"));
  div->AppendChild(text1);
  div->AppendChild(span);
  span->AppendChild(text2);
  div->AppendChild(text3);

  UpdateAllLifecyclePhasesForTest();

  Vector<gfx::Point> letter_pos;
  Vector<gfx::Point> word_middle_pos;

  TextNodeVector text_nodes;
  text_nodes.push_back(text1);
  text_nodes.push_back(text2);
  text_nodes.push_back(text3);
  ParseText(text_nodes);

  Position p1;
  Position p2;
  if (sel_begin < str1.length())
    p1 = Position(text1, sel_begin);
  else if (sel_begin < str1.length() + str2.length())
    p1 = Position(text2, sel_begin - str1.length());
  else
    p1 = Position(text3, sel_begin - str1.length() - str2.length());
  if (sel_end < str1.length())
    p2 = Position(text1, sel_end);
  else if (sel_end < str1.length() + str2.length())
    p2 = Position(text2, sel_end - str1.length());
  else
    p2 = Position(text3, sel_end - str1.length() - str2.length());

  Selection().SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(p1, p2).Build(),
      SetSelectionOptions());
}

void GranularityStrategyTest::SetupVerticalAlign(String str1,
                                                 String str2,
                                                 String str3,
                                                 wtf_size_t sel_begin,
                                                 wtf_size_t sel_end) {
  SetInnerHTML(
      "<html>"
      "<head>"
      "<style>"
      "span {"
      "vertical-align:20px;"
      "}"
      "</style>"
      "</head>"
      "<body>"
      "<div id='mytext'></div>"
      "</body>"
      "</html>");

  SetupTextSpan(str1, str2, str3, sel_begin, sel_end);
}

void GranularityStrategyTest::SetupFontSize(String str1,
                                            String str2,
                                            String str3,
                                            wtf_size_t sel_begin,
                                            wtf_size_t sel_end) {
  SetInnerHTML(
      "<html>"
      "<head>"
      "<style>"
      "span {"
      "font-size: 200%;"
      "}"
      "</style>"
      "</head>"
      "<body>"
      "<div id='mytext'></div>"
      "</body>"
      "</html>");

  SetupTextSpan(str1, str2, str3, sel_begin, sel_end);
}

// Tests expanding selection on text "abcdef ghij kl mno^p|>qr stuvwi inm mnii,"
// (^ means base, | means extent, < means start, and > means end). Text needs to
// be laid out on a single line with no rotation.
void GranularityStrategyTest::TestDirectionExpand() {
  // Expand selection using character granularity until the end of the word
  // is reached.
  // "abcdef ghij kl mno^pq|>r stuvwi inm  mnii,"
  Selection().MoveRangeSelectionExtent(letter_pos_[20]);
  EXPECT_EQ_SELECTED_TEXT("pq");
  // Move to the same postion shouldn't change anything.
  Selection().MoveRangeSelectionExtent(letter_pos_[20]);
  EXPECT_EQ_SELECTED_TEXT("pq");
  // "abcdef ghij kl mno^pqr|> stuvwi inm  mnii,"
  Selection().MoveRangeSelectionExtent(letter_pos_[21]);
  EXPECT_EQ_SELECTED_TEXT("pqr");
  // Selection should stay the same until the middle of the word is passed.
  // "abcdef ghij kl mno^pqr |>stuvwi inm  mnii," -
  Selection().MoveRangeSelectionExtent(letter_pos_[22]);
  EXPECT_EQ_SELECTED_TEXT("pqr ");
  // "abcdef ghij kl mno^pqr >st|uvwi inm  mnii,"
  Selection().MoveRangeSelectionExtent(letter_pos_[24]);
  EXPECT_EQ_SELECTED_TEXT("pqr ");
  gfx::Point p = word_middles_[4];
  p.Offset(-1, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr ");
  p.Offset(1, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr stuvwi");
  // Selection should stay the same until the end of the word is reached.
  // "abcdef ghij kl mno^pqr stuvw|i> inm  mnii,"
  Selection().MoveRangeSelectionExtent(letter_pos_[27]);
  EXPECT_EQ_SELECTED_TEXT("pqr stuvwi");
  // "abcdef ghij kl mno^pqr stuvwi|> inm  mnii,"
  Selection().MoveRangeSelectionExtent(letter_pos_[28]);
  EXPECT_EQ_SELECTED_TEXT("pqr stuvwi");
  // "abcdef ghij kl mno^pqr stuvwi |>inm  mnii,"
  Selection().MoveRangeSelectionExtent(letter_pos_[29]);
  EXPECT_EQ_SELECTED_TEXT("pqr stuvwi ");
  // Now expand slowly to the middle of word #5.
  int y = letter_pos_[29].y();
  for (int x = letter_pos_[29].x() + 1; x < word_middles_[5].x(); x++) {
    Selection().MoveRangeSelectionExtent(gfx::Point(x, y));
    Selection().MoveRangeSelectionExtent(gfx::Point(x, y));
    EXPECT_EQ_SELECTED_TEXT("pqr stuvwi ");
  }
  Selection().MoveRangeSelectionExtent(word_middles_[5]);
  EXPECT_EQ_SELECTED_TEXT("pqr stuvwi inm");
  // Jump over quickly to just before the middle of the word #6 and then
  // move over it.
  p = word_middles_[6];
  p.Offset(-1, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr stuvwi inm ");
  p.Offset(1, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr stuvwi inm mnii");
}

// Tests shrinking selection on text "abcdef ghij kl mno^pqr|> iiinmni, abc"
// (^ means base, | means extent, < means start, and > means end).
// Text needs to be laid out on a single line with no rotation.
void GranularityStrategyTest::TestDirectionShrink() {
  // Move to the middle of word #4 to it and then move back, confirming
  // that the selection end is moving with the extent. The offset between the
  // extent and the selection end will be equal to half the width of "iiinmni".
  Selection().MoveRangeSelectionExtent(word_middles_[4]);
  EXPECT_EQ_SELECTED_TEXT("pqr iiinmni");
  gfx::Point p = word_middles_[4];
  p.Offset(letter_pos_[28].x() - letter_pos_[29].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr iiinmn");
  p.Offset(letter_pos_[27].x() - letter_pos_[28].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr iiinm");
  p.Offset(letter_pos_[26].x() - letter_pos_[27].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr iiin");
  // Move right by the width of char 30 ('m'). Selection shouldn't change,
  // but offset should be reduced.
  p.Offset(letter_pos_[27].x() - letter_pos_[26].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr iiin");
  // Move back a couple of character widths and confirm the selection still
  // updates accordingly.
  p.Offset(letter_pos_[25].x() - letter_pos_[26].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr iii");
  p.Offset(letter_pos_[24].x() - letter_pos_[25].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr ii");
  // "Catch up" with the handle - move the extent to where the handle is.
  // "abcdef ghij kl mno^pqr ii|>inmni, abc"
  Selection().MoveRangeSelectionExtent(letter_pos_[24]);
  EXPECT_EQ_SELECTED_TEXT("pqr ii");
  // Move ahead and confirm the selection expands accordingly
  // "abcdef ghij kl mno^pqr iii|>nmni, abc"
  Selection().MoveRangeSelectionExtent(letter_pos_[25]);
  EXPECT_EQ_SELECTED_TEXT("pqr iii");

  // Confirm we stay in character granularity if the user moves within a word.
  // "abcdef ghij kl mno^pqr |>iiinmni, abc"
  Selection().MoveRangeSelectionExtent(letter_pos_[22]);
  EXPECT_EQ_SELECTED_TEXT("pqr ");
  // It's possible to get a move when position doesn't change.
  // It shouldn't affect anything.
  p = letter_pos_[22];
  p.Offset(1, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("pqr ");
  // "abcdef ghij kl mno^pqr i|>iinmni, abc"
  Selection().MoveRangeSelectionExtent(letter_pos_[23]);
  EXPECT_EQ_SELECTED_TEXT("pqr i");
}

// Tests moving selection extent over to the other side of the base
// on text "abcd efgh ijkl mno^pqr|> iiinmni, abc"
// (^ means base, | means extent, < means start, and > means end).
// Text needs to be laid out on a single line with no rotation.
void GranularityStrategyTest::TestDirectionSwitchSide() {
  // Move to the middle of word #4, selecting it - this will set the offset to
  // be half the width of "iiinmni.
  Selection().MoveRangeSelectionExtent(word_middles_[4]);
  EXPECT_EQ_SELECTED_TEXT("pqr iiinmni");
  // Move back leaving only one letter selected.
  gfx::Point p = word_middles_[4];
  p.Offset(letter_pos_[19].x() - letter_pos_[29].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("p");
  // Confirm selection doesn't change if extent is positioned at base.
  p.Offset(letter_pos_[18].x() - letter_pos_[19].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("p");
  // Move over to the other side of the base. Confirm the offset is preserved.
  // (i.e. the selection start stays on the right of the extent)
  // Confirm we stay in character granularity until the beginning of the word
  // is passed.
  p.Offset(letter_pos_[17].x() - letter_pos_[18].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("o");
  p.Offset(letter_pos_[16].x() - letter_pos_[17].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("no");
  p.Offset(letter_pos_[14].x() - letter_pos_[16].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT(" mno");
  // Move to just one pixel on the right before the middle of the word #2.
  // We should switch to word granularity, so the selection shouldn't change.
  p.Offset(word_middles_[2].x() - letter_pos_[14].x() + 1, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT(" mno");
  // Move over the middle of the word. The word should get selected.
  // This should reduce the offset, but it should still stay greated than 0,
  // since the width of "iiinmni" is greater than the width of "ijkl".
  p.Offset(-2, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("ijkl mno");
  // Move to just one pixel on the right of the middle of word #1.
  // The selection should now include the space between the words.
  p.Offset(word_middles_[1].x() - letter_pos_[10].x() + 1, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT(" ijkl mno");
  // Move over the middle of the word. The word should get selected.
  p.Offset(-2, 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("efgh ijkl mno");
}

// Test for the default CharacterGranularityStrategy
TEST_F(GranularityStrategyTest, Character) {
  GetDummyPageHolder().GetFrame().GetSettings()->SetSelectionStrategy(
      SelectionStrategy::kCharacter);
  GetDummyPageHolder().GetFrame().GetSettings()->SetDefaultFontSize(12);
  // "Foo Bar Baz,"
  Text* text = AppendTextNode("Foo Bar Baz,");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // "Foo B^a|>r Baz," (^ means base, | means extent, , < means start, and >
  // means end).
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 5), Position(text, 6))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("a");
  // "Foo B^ar B|>az,"
  Selection().MoveRangeSelectionExtent(
      VisiblePositionToContentsPoint(CreateVisiblePosition(Position(text, 9))));
  EXPECT_EQ_SELECTED_TEXT("ar B");
  // "F<|oo B^ar Baz,"
  Selection().MoveRangeSelectionExtent(
      VisiblePositionToContentsPoint(CreateVisiblePosition(Position(text, 1))));
  EXPECT_EQ_SELECTED_TEXT("oo B");
}

// DirectionGranularityStrategy strategy on rotated text should revert to the
// same behavior as CharacterGranularityStrategy
TEST_F(GranularityStrategyTest, DirectionRotate) {
  Text* text = SetupRotate("Foo Bar Baz,");
  // "Foo B^a|>r Baz," (^ means base, | means extent, , < means start, and >
  // means end).
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 5), Position(text, 6))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("a");
  gfx::Point p = letter_pos_[9];
  // Need to move by one pixel, otherwise this point is not evaluated
  // to the same line as the text by hit testing.
  p.Offset(1, 0);
  // "Foo B^ar B|>az,"
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("ar B");
  p = letter_pos_[1];
  p.Offset(1, 0);
  // "F<|oo B^ar Baz,"
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("oo B");
}

TEST_F(GranularityStrategyTest, DirectionExpandTranslateZ) {
  Text* text = SetupTranslateZ("abcdef ghij kl mnopqr stuvwi inm mnii,");
  // "abcdef ghij kl mno^p|>qr stuvwi inm  mnii," (^ means base, | means extent,
  // < means start, and > means end).
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 18), Position(text, 19))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("p");
  TestDirectionExpand();
}

TEST_F(GranularityStrategyTest, DirectionExpandTransform) {
  Text* text = SetupTransform("abcdef ghij kl mnopqr stuvwi inm mnii,");
  // "abcdef ghij kl mno^p|>qr stuvwi inm  mnii," (^ means base, | means extent,
  // < means start, and > means end).
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 18), Position(text, 19))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("p");
  TestDirectionExpand();
}

TEST_F(GranularityStrategyTest, DirectionExpandVerticalAlign) {
  // "abcdef ghij kl mno^p|>qr stuvwi inm  mnii," (^ means base, | means extent,
  // < means start, and > means end).
  SetupVerticalAlign("abcdef ghij kl m", "nopq", "r stuvwi inm mnii,", 18, 19);
  EXPECT_EQ_SELECTED_TEXT("p");
  TestDirectionExpand();
}

TEST_F(GranularityStrategyTest, DirectionExpandFontSizes) {
  SetupFontSize("abcdef ghij kl mnopqr st", "uv", "wi inm mnii,", 18, 19);
  EXPECT_EQ_SELECTED_TEXT("p");
  TestDirectionExpand();
}

TEST_F(GranularityStrategyTest, DirectionShrinkTranslateZ) {
  Text* text = SetupTranslateZ("abcdef ghij kl mnopqr iiinmni, abc");
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 18), Position(text, 21))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionShrink();
}

TEST_F(GranularityStrategyTest, DirectionShrinkTransform) {
  Text* text = SetupTransform("abcdef ghij kl mnopqr iiinmni, abc");
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 18), Position(text, 21))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionShrink();
}

TEST_F(GranularityStrategyTest, DirectionShrinkVerticalAlign) {
  SetupVerticalAlign("abcdef ghij kl mnopqr ii", "inm", "ni, abc", 18, 21);
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionShrink();
}

TEST_F(GranularityStrategyTest, DirectionShrinkFontSizes) {
  SetupFontSize("abcdef ghij kl mnopqr ii", "inm", "ni, abc", 18, 21);
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionShrink();
}

TEST_F(GranularityStrategyTest, DirectionSwitchSideTranslateZ) {
  Text* text = SetupTranslateZ("abcd efgh ijkl mnopqr iiinmni, abc");
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 18), Position(text, 21))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionSwitchSide();
}

TEST_F(GranularityStrategyTest, DirectionSwitchSideTransform) {
  Text* text = SetupTransform("abcd efgh ijkl mnopqr iiinmni, abc");
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 18), Position(text, 21))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionSwitchSide();
}

TEST_F(GranularityStrategyTest, DirectionSwitchSideVerticalAlign) {
  SetupVerticalAlign("abcd efgh ijkl", " mnopqr", " iiinmni, abc", 18, 21);
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionSwitchSide();
}

TEST_F(GranularityStrategyTest, DirectionSwitchSideFontSizes) {
  SetupFontSize("abcd efgh i", "jk", "l mnopqr iiinmni, abc", 18, 21);
  EXPECT_EQ_SELECTED_TEXT("pqr");
  TestDirectionSwitchSide();
}

// Tests moving extent over to the other side of the vase and immediately
// passing the word boundary and going into word granularity.
TEST_F(GranularityStrategyTest, DirectionSwitchSideWordGranularityThenShrink) {
  GetDummyPageHolder().GetFrame().GetSettings()->SetDefaultFontSize(12);
  String str = "ab cd efghijkl mnopqr iiin, abc";
  Text* text = GetDocument().createTextNode(str);
  GetDocument().body()->AppendChild(text);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  GetDummyPageHolder().GetFrame().GetSettings()->SetSelectionStrategy(
      SelectionStrategy::kDirection);

  ParseText(text);

  // "abcd efgh ijkl mno^pqr|> iiin, abc" (^ means base, | means extent, < means
  // start, and > means end).
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 18), Position(text, 21))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("pqr");
  // Move to the middle of word #4 selecting it - this will set the offset to
  // be half the width of "iiin".
  Selection().MoveRangeSelectionExtent(word_middles_[4]);
  EXPECT_EQ_SELECTED_TEXT("pqr iiin");
  // Move to the middle of word #2 - extent will switch over to the other
  // side of the base, and we should enter word granularity since we pass
  // the word boundary. The offset should become negative since the width
  // of "efghjkkl" is greater than that of "iiin".
  int offset = letter_pos_[26].x() - word_middles_[4].x();
  gfx::Point p =
      gfx::Point(word_middles_[2].x() - offset - 1, word_middles_[2].y());
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("efghijkl mno");
  p.Offset(letter_pos_[7].x() - letter_pos_[6].x(), 0);
  Selection().MoveRangeSelectionExtent(p);
  EXPECT_EQ_SELECTED_TEXT("fghijkl mno");
}

// Make sure we switch to word granularity right away when starting on a
// word boundary and extending.
TEST_F(GranularityStrategyTest, DirectionSwitchStartOnBoundary) {
  GetDummyPageHolder().GetFrame().GetSettings()->SetDefaultFontSize(12);
  String str = "ab cd efghijkl mnopqr iiin, abc";
  Text* text = GetDocument().createTextNode(str);
  GetDocument().body()->AppendChild(text);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  GetDummyPageHolder().GetFrame().GetSettings()->SetSelectionStrategy(
      SelectionStrategy::kDirection);

  ParseText(text);

  // "ab cd efghijkl ^mnopqr |>stuvwi inm," (^ means base and | means extent,
  // > means end).
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 15), Position(text, 22))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("mnopqr ");
  Selection().MoveRangeSelectionExtent(word_middles_[4]);
  EXPECT_EQ_SELECTED_TEXT("mnopqr iiin");
}

// For http://crbug.com/704529
TEST_F(GranularityStrategyTest, UpdateExtentWithNullPositionForCharacter) {
  GetDummyPageHolder().GetFrame().GetSettings()->SetSelectionStrategy(
      SelectionStrategy::kCharacter);
  GetDocument().body()->setInnerHTML(
      "<div id=host></div><div id=sample>ab</div>");
  // Simulate VIDEO element which has a RANGE as slider of video time.
  Element* const host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<input type=range>");
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  const SelectionInDOMTree& selection_in_dom_tree =
      SelectionInDOMTree::Builder()
          .Collapse(Position(sample->firstChild(), 2))
          .Build();
  Selection().SetSelection(selection_in_dom_tree,
                           SetSelectionOptions::Builder()
                               .SetShouldCloseTyping(true)
                               .SetShouldClearTypingStyle(true)
                               .SetShouldShowHandle(true)
                               .SetIsDirectional(true)
                               .Build());

  // Since, it is not obvious that
  // |PositionForContentsPointRespectingEditingBoundary()| returns null
  // position, we verify here.
  ASSERT_EQ(Position(), CreateVisiblePosition(
                            PositionForContentsPointRespectingEditingBoundary(
                                gfx::Point(0, 0), &GetFrame()))
                            .DeepEquivalent())
      << "This test requires null position.";

  // Point to RANGE inside shadow root to get null position from
  // |visiblePositionForContentsPoint()|.
  Selection().MoveRangeSelectionExtent(gfx::Point(0, 0));
  EXPECT_EQ(selection_in_dom_tree, Selection().GetSelectionInDOMTree());
}

// For http://crbug.com/704529
TEST_F(GranularityStrategyTest, UpdateExtentWithNullPositionForDirectional) {
  GetDocument().body()->setInnerHTML(
      "<div id=host></div><div id=sample>ab</div>");
  // Simulate VIDEO element which has a RANGE as slider of video time.
  Element* const host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<input type=range>");
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  const SelectionInDOMTree& selection_in_dom_tree =
      SelectionInDOMTree::Builder()
          .Collapse(Position(sample->firstChild(), 2))
          .Build();
  Selection().SetSelection(selection_in_dom_tree,
                           SetSelectionOptions::Builder()
                               .SetShouldCloseTyping(true)
                               .SetShouldClearTypingStyle(true)
                               .SetShouldShowHandle(true)
                               .SetIsDirectional(true)
                               .Build());

  // Since, it is not obvious that
  // |PositionForContentsPointRespectingEditingBoundary()| returns null
  // position, we verify here.
  ASSERT_EQ(Position(), CreateVisiblePosition(
                            PositionForContentsPointRespectingEditingBoundary(
                                gfx::Point(0, 0), &GetFrame()))
                            .DeepEquivalent())
      << "This test requires null position.";

  // Point to RANGE inside shadow root to get null position from
  // |visiblePositionForContentsPoint()|.
  Selection().MoveRangeSelectionExtent(gfx::Point(0, 0));

  EXPECT_EQ(selection_in_dom_tree, Selection().GetSelectionInDOMTree());
}

// For http://crbug.com/974728
TEST_F(GranularityStrategyTest, UpdateExtentWithNullNextWordBound) {
  const SelectionInDOMTree selection = SetSelectionTextToBody(
      "<style>body { margin: 0; padding: 0; font: 10px monospace; }</style>"
      "<div contenteditable id=target></div>|def^");
  Selection().SetSelection(selection, SetSelectionOptions());

  // Move inside content editable
  ASSERT_EQ(
      Position(*GetDocument().getElementById(AtomicString("target")), 0),
      CreateVisiblePosition(PositionForContentsPointRespectingEditingBoundary(
                                gfx::Point(0, 0), &GetFrame()))
          .DeepEquivalent())
      << "We extend selection inside content editable.";
  Selection().MoveRangeSelectionExtent(gfx::Point(0, 0));

  EXPECT_EQ(selection, Selection().GetSelectionInDOMTree());
}

}  // namespace blink
```