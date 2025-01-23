Response:
Let's break down the thought process for analyzing this C++ test file and generating the explanation.

1. **Identify the Core Purpose:** The filename `highlight_painter_test.cc` immediately suggests this file contains tests for the `HighlightPainter` class. The `#include "third_party/blink/renderer/core/paint/highlight_painter.h"` confirms this. The primary goal is to verify the correct behavior of `HighlightPainter`.

2. **Understand the Test Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` and the use of `TEST_P` and `INSTANTIATE_PAINT_TEST_SUITE_P` indicate that Google Test is being used for unit testing. This means we're looking at individual test cases that exercise specific aspects of `HighlightPainter`.

3. **Examine the Test Structure:** The code defines a test fixture class `HighlightPainterTest` which inherits from `PaintControllerPaintTest`. This inheritance likely provides a testing environment with necessary setup and teardown for paint-related testing (e.g., creating a document, layout). The `TEST_P` macro defines parameterized tests, although in this specific instance, it's not clear what parameters are being used (likely default paint settings provided by the base class).

4. **Analyze the Key Test Case: `FastSpellingGrammarPaintCase`:** This is the main focus of the file. Let's break it down further:

   * **`test` Lambda:**  This helper function sets the HTML content of the body, applies CSS (passed as a string), and triggers layout updates. It returns an `EphemeralRange` representing the first character of the text node. This suggests the tests are focused on highlighting a single character.

   * **`expect` Lambda:** This is the core assertion logic. It simulates the painting process for a single line of text. It sets up an `InlinePaintContext`, `InlineCursor`, and other paint-related objects. Crucially, it creates a `HighlightPainter` instance. The `EXPECT_EQ(highlight_painter.PaintCase(), expected)` line is the heart of the test. It compares the `PaintCase` returned by the `HighlightPainter` with an `expected` value. The `PaintCase` enum (though not explicitly defined in this snippet) likely represents different strategies the `HighlightPainter` might use depending on the highlighting scenario.

   * **Test Scenarios:** The rest of the `FastSpellingGrammarPaintCase` function consists of a series of calls to `test` and `expect` with different CSS styles and document markers. The comments (like "// kFastSpellingGrammar only if...") are vital for understanding the intent of each test case.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**

   * **HTML:** The `SetBodyInnerHTML` function clearly interacts with HTML. The test cases manipulate the structure and content of the HTML body.
   * **CSS:** The `stylesheet` parameter in the `test` lambda directly applies CSS styles to the document. The test focuses on how different CSS properties (like `color`, `background-color`, `text-decoration`, etc.) influence the highlighting behavior, particularly for spelling and grammar errors.
   * **JavaScript (Indirect):** While no explicit JavaScript code is present, the features being tested (spelling/grammar highlighting, selection) are often triggered or controlled by JavaScript in a real browser. The test implicitly verifies the correctness of the underlying rendering logic that would be used in such scenarios.

6. **Infer Logical Reasoning and Examples:**  The test case names and the comments provide clues about the logic being tested. For example, the test around overlapping spelling and grammar highlights shows the system can handle both simultaneously. The tests involving specific CSS properties demonstrate how the `HighlightPainter` reacts to different styling of spelling/grammar errors. By analyzing the `expect` calls with different CSS, we can infer the expected output (`HighlightPainter::kFastSpellingGrammar` vs. `HighlightPainter::kOverlay`).

7. **Identify Potential User/Programming Errors:** The tests implicitly reveal potential errors. If the `HighlightPainter` incorrectly classified a scenario, leading to the wrong `PaintCase`, it could result in visual glitches. For example, if a custom `background-color` for spelling errors wasn't handled correctly, the background might not be painted as expected.

8. **Trace User Actions (Debugging Clues):** To understand how a user might reach this code, consider the features being tested: spelling and grammar checking, and text selection. A user typing text in a browser might trigger the spelling/grammar checkers. A user dragging their mouse to select text would involve the selection highlighting logic. The test setup simulates these actions at a low level.

9. **Synthesize the Explanation:**  Combine the observations from the above steps into a coherent explanation. Start with the main purpose, explain the test structure, and then delve into the details of the key test case. Explicitly link the code to web technologies and provide concrete examples. Finally, consider potential errors and how a user might trigger this code. Organize the information logically with clear headings.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  "This is just a simple unit test."  **Correction:**  Realized it's testing a complex rendering component, so need to understand the paint pipeline concepts.
* **Initial thought:** "The `TEST_P` parameters are important." **Correction:**  While parameterized, the specific parameters aren't immediately obvious from the code and likely relate to the base class setup. Focus on the core logic within the test case.
* **Stuck on the meaning of `PaintCase`:**  Recognized that without the `highlight_painter.h` file, the exact enum values are unknown. Infer their meaning from the test scenarios (e.g., `kFastSpellingGrammar` implies an optimized path for simple spelling/grammar highlighting).
* **Overemphasis on code details:** Initially focused too much on the low-level paint objects. Shifted focus to the *purpose* of these objects within the test scenario and their connection to web technologies.
这个文件 `highlight_painter_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `HighlightPainter` 类的功能。`HighlightPainter` 负责在网页上绘制各种高亮效果，例如文本选择、拼写/语法错误、搜索匹配等等。

下面是这个文件的功能分解，以及它与 JavaScript、HTML、CSS 的关系，逻辑推理，常见错误和调试线索：

**1. 功能概述:**

* **测试 `HighlightPainter` 类的各种高亮绘制场景:**  该文件包含多个测试用例，用于验证 `HighlightPainter` 在不同情况下是否能正确绘制高亮效果。
* **模拟不同的高亮类型:** 测试用例覆盖了拼写错误、语法错误以及文本选择等高亮类型。
* **验证 CSS 样式对高亮的影响:** 测试用例会设置不同的 CSS 样式，检查 `HighlightPainter` 是否能正确地根据样式绘制高亮。
* **确保性能优化路径的正确性:**  测试用例中包含了对 `FastSpellingGrammarPaintCase` 的测试，这表明 `HighlightPainter` 存在针对拼写和语法高亮的优化路径，测试会验证这些优化路径是否正常工作。

**2. 与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 方法设置 HTML 内容，这是创建网页结构的基础。例如，测试用例会创建包含文本的 HTML 结构，然后在其上应用高亮。
    ```c++
    SetBodyInnerHTML("x<style>" + stylesheet + "</style>");
    ```
    这里 `"x"` 就是 HTML 文本内容。
* **CSS:** 测试用例使用 `<style>` 标签在 HTML 中内联 CSS 样式。这些样式会影响高亮的绘制方式。例如，测试用例会设置 `::spelling-error` 和 `::grammar-error` 伪元素的样式，来模拟浏览器对拼写和语法错误的处理。
    ```c++
    auto test = [&](String stylesheet) {
      SetBodyInnerHTML("x<style>" + stylesheet + "</style>");
      // ...
    };
    ```
    测试用例会测试诸如 `background-color`, `color`, `-webkit-text-fill-color`, `text-decoration` 等 CSS 属性对拼写和语法错误高亮的影响。
* **JavaScript (间接关系):**  虽然这个测试文件本身不包含 JavaScript 代码，但 `HighlightPainter` 所实现的功能通常是响应 JavaScript 的操作而发生的。例如：
    * **拼写和语法检查:** 当用户在输入框中输入文本时，浏览器可能会运行 JavaScript 代码进行拼写和语法检查，如果发现错误，会通过某种机制（可能涉及到 C++ 代码）调用 `HighlightPainter` 来绘制错误高亮。
    * **文本选择:** 当用户通过鼠标拖拽选择文本时，浏览器也会执行 JavaScript 代码来记录选择范围，并调用 `HighlightPainter` 来绘制选中文本的背景高亮。
    * **查找功能 (Ctrl+F):**  当用户使用查找功能时，JavaScript 代码会找到匹配的文本，并指示浏览器使用 `HighlightPainter` 高亮这些匹配项。

**3. 逻辑推理 (假设输入与输出):**

我们以 `FastSpellingGrammarPaintCase` 测试用例中的一个片段为例进行逻辑推理：

**假设输入:**

* **HTML:**  包含一个字符 "x"。
* **CSS:**  没有为 `::spelling-error` 或 `::grammar-error` 设置任何特殊样式。
* **操作:**  在 "x" 上添加一个拼写错误标记。

**代码片段:**

```c++
  auto test = [&](String stylesheet) {
    SetBodyInnerHTML("x<style>" + stylesheet + "</style>");
    UpdateAllLifecyclePhasesForTest();
    const Node& text = *GetDocument().body()->firstChild();
    return EphemeralRange{Position{text, 0}, Position{text, 1}};
  };

  auto expect = [&](HighlightPainter::Case expected, unsigned line) {
    // ... (创建 HighlightPainter 的过程) ...
    EXPECT_EQ(highlight_painter.PaintCase(), expected)
        << "(line " << line << ")";
  };

  // ...
  test(""); // 没有额外 CSS 样式
  expect(HighlightPainter::kNoHighlights, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test("")); // 添加拼写错误标记
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
```

**逻辑推理:**

1. **初始状态:** 当没有添加拼写或语法错误标记时，`HighlightPainter` 应该不会进行特殊的高亮绘制，因此 `PaintCase` 应该是 `HighlightPainter::kNoHighlights`。
2. **添加拼写错误标记:** 当使用 `GetDocument().Markers().AddSpellingMarker()` 在文本 "x" 上添加一个拼写错误标记后，`HighlightPainter` 应该识别出需要进行拼写错误高亮。
3. **预期输出:** 在这种简单情况下，如果没有额外的 CSS 样式干扰，`HighlightPainter` 可能会选择一种快速的绘制路径来高亮拼写错误，因此预期 `PaintCase` 是 `HighlightPainter::kFastSpellingGrammar`。

**4. 用户或编程常见的使用错误:**

* **CSS 样式冲突导致高亮显示异常:** 用户或开发者可能会编写与浏览器默认拼写/语法错误高亮样式冲突的 CSS 样式，导致高亮显示不符合预期。
    * **示例:**  用户设置了全局的 `background-color` 样式，可能会覆盖掉拼写错误默认的红色波浪线背景。
    * **用户操作到达这里:** 用户在网页上输入了错误的单词，并且该网页的 CSS 样式中存在可能影响拼写错误高亮的规则。
* **JavaScript 操作错误地移除了高亮标记:** 开发者可能编写了错误的 JavaScript 代码，意外地移除了应该显示的高亮标记。
    * **示例:**  一个 JavaScript 脚本错误地清除了所有应用于文本节点的 CSS 类或属性，包括用于显示拼写错误高亮的类。
    * **用户操作到达这里:** 用户在网页上进行了某些操作，触发了错误的 JavaScript 代码执行，导致高亮标记丢失。
* **浏览器扩展或插件干扰高亮显示:**  浏览器扩展或插件可能会修改网页的 CSS 或 DOM 结构，从而影响 `HighlightPainter` 的工作。
    * **示例:**  一个修改网页样式的浏览器扩展可能会覆盖拼写错误高亮的样式。
    * **用户操作到达这里:** 用户安装了特定的浏览器扩展，并在浏览包含拼写错误的网页时，该扩展的样式规则生效，干扰了默认的高亮显示。

**5. 用户操作是如何一步步的到达这里 (作为调试线索):**

假设我们正在调试一个拼写错误高亮显示不正确的 bug。以下是用户操作可能如何一步步到达 `HighlightPainter` 的：

1. **用户在网页的 `<textarea>` 或 `contenteditable` 元素中输入文本。**
2. **浏览器内置的拼写检查功能 (通常是操作系统提供的) 检测到拼写错误。**
3. **浏览器会将该拼写错误标记为需要高亮显示。** 这可能涉及到调用 Blink 引擎中处理文本标记的相关代码 (`DocumentMarkerController` 在这个测试文件中被引用)。
4. **当浏览器需要渲染页面时，布局引擎会确定文本的布局信息。**
5. **当渲染到包含拼写错误的文本时，绘制引擎会创建 `HighlightPainter` 对象。**
6. **`HighlightPainter` 会根据当前的样式信息 (包括来自 CSS 样式表和浏览器默认样式) 决定如何绘制高亮。**
7. **测试文件中的 `FastSpellingGrammarPaintCase` 就是为了验证在不同 CSS 样式下，`HighlightPainter` 是否选择了正确的绘制策略 (`PaintCase`)。**

**调试线索:**

* **检查浏览器的开发者工具 (Elements 面板):**  查看拼写错误文本节点的样式，确认是否有预期的 `::spelling-error` 伪元素样式应用。检查是否有其他 CSS 样式覆盖了拼写错误的默认样式。
* **检查浏览器的开发者工具 (Console 面板):**  查看是否有 JavaScript 错误，这些错误可能导致高亮标记没有被正确添加或被意外移除。
* **禁用浏览器扩展:**  尝试禁用所有浏览器扩展，看问题是否消失，以确定是否有扩展干扰了高亮显示。
* **查看 Blink 引擎的渲染流程日志:**  在 Chromium 的开发者版本中，可以启用详细的渲染流程日志，查看 `HighlightPainter` 的创建和绘制过程，以及相关的样式计算信息。
* **运行 `highlight_painter_test.cc` 中的相关测试用例:**  修改测试用例的 CSS 样式或添加新的测试用例，来复现和隔离 bug。

总而言之，`highlight_painter_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎能够正确地绘制各种网页高亮效果，并且能够正确地处理 CSS 样式的影响。理解这个文件的功能和它测试的场景，对于理解浏览器如何渲染高亮以及调试相关问题非常有帮助。

### 提示词
```
这是目录为blink/renderer/core/paint/highlight_painter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/highlight_painter.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/core/paint/line_relative_rect.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/text_decoration_painter.h"
#include "third_party/blink/renderer/core/paint/text_paint_style.h"
#include "third_party/blink/renderer/core/paint/text_painter.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"

namespace blink {

class HighlightPainterTest : public PaintControllerPaintTest {
 public:
  explicit HighlightPainterTest(LocalFrameClient* local_frame_client = nullptr)
      : PaintControllerPaintTest(local_frame_client) {}
};

INSTANTIATE_PAINT_TEST_SUITE_P(HighlightPainterTest);

TEST_P(HighlightPainterTest, FastSpellingGrammarPaintCase) {
  auto test = [&](String stylesheet) {
    SetBodyInnerHTML("x<style>" + stylesheet + "</style>");
    UpdateAllLifecyclePhasesForTest();
    const Node& text = *GetDocument().body()->firstChild();
    return EphemeralRange{Position{text, 0}, Position{text, 1}};
  };

  auto expect = [&](HighlightPainter::Case expected, unsigned line) {
    LayoutObject& body = *GetDocument().body()->GetLayoutObject();
    const auto& block_flow = To<LayoutBlockFlow>(body);
    InlinePaintContext inline_context{};
    InlineCursor cursor{block_flow};
    cursor.MoveToFirstLine();
    inline_context.SetLineBox(cursor);
    cursor.MoveTo(*block_flow.FirstChild());

    CullRect cull_rect{};
    gfx::Rect rect{};
    PhysicalOffset physical_offset{};
    PhysicalRect physical_rect{};
    const FragmentItem& text_item = *cursor.CurrentItem();
    const ComputedStyle& style = text_item.Style();
    std::optional<HighlightPainter::SelectionPaintState> maybe_selection;
    HighlightPainter::SelectionPaintState* selection = nullptr;
    if (text_item.GetLayoutObject()->IsSelected()) {
      maybe_selection.emplace(cursor, physical_offset);
      if (maybe_selection->Status().HasValidRange())
        selection = &*maybe_selection;
    }

    PaintController controller;
    GraphicsContext graphics_context(controller);
    PaintInfo paint_info(graphics_context, cull_rect, PaintPhase::kForeground,
                         /*descendant_painting_blocked=*/false);
    TextPaintStyle text_style =
        TextPainter::TextPaintingStyle(GetDocument(), style, paint_info);
    if (selection) {
      selection->ComputeSelectionStyle(GetDocument(), style,
                                       text_item.GetLayoutObject()->GetNode(),
                                       paint_info, text_style);
    }
    LineRelativeRect rotated_rect =
        LineRelativeRect::CreateFromLineBox(physical_rect, true);
    TextPainter text_painter(
        graphics_context, /*svg_context_paints*/ nullptr,
        text_item.ScaledFont(), rect,
        LineRelativeOffset::CreateFromBoxOrigin(physical_offset), true);
    TextDecorationPainter decoration_painter(text_painter, &inline_context,
                                             paint_info, style, text_style,
                                             rotated_rect, selection);
    HighlightPainter highlight_painter(
        cursor.Current()->TextPaintInfo(cursor.Items()), text_painter,
        decoration_painter, paint_info, cursor, text_item, physical_offset,
        style, text_style, selection);

    EXPECT_EQ(highlight_painter.PaintCase(), expected)
        << "(line " << line << ")";
  };

  // kFastSpellingGrammar only if there are spelling and/or grammar highlights.
  test("");
  expect(HighlightPainter::kNoHighlights, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(""));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
  GetDocument().Markers().AddGrammarMarker(test(""));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // Overlapping spelling and grammar highlights is ok.
  EphemeralRange range = test("");
  GetDocument().Markers().AddSpellingMarker(range);
  GetDocument().Markers().AddGrammarMarker(range);
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // Overlapping selection highlight is not ok.
  Selection().SelectAll();
  range = test("");
  GetDocument().Markers().AddSpellingMarker(range);
  GetDocument().Markers().AddGrammarMarker(range);
  expect(HighlightPainter::kOverlay, __LINE__);
  Selection().Clear();

  // Non-trivial spelling style is still ok if there are no spelling highlights.
  range = test("::spelling-error { background-color: green; }");
  GetDocument().Markers().AddGrammarMarker(range);
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // Non-trivial grammar style is still ok if there are no grammar highlights.
  range = test("::grammar-error { background-color: green; }");
  GetDocument().Markers().AddSpellingMarker(range);
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // ‘color’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: green; }
      ::spelling-error { color: red; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: green; }
      ::spelling-error { color: green; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // ‘-webkit-text-fill-color’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; -webkit-text-fill-color: green; }
      ::spelling-error { /* -webkit-text-fill-color = blue */ }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; -webkit-text-fill-color: green; }
      ::spelling-error { -webkit-text-fill-color: red; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; -webkit-text-fill-color: green; }
      ::spelling-error { -webkit-text-fill-color: green; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // ‘-webkit-text-stroke-color’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; -webkit-text-stroke-color: green; }
      ::spelling-error { /* -webkit-text-stroke-color = blue */ }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; -webkit-text-stroke-color: green; }
      ::spelling-error { -webkit-text-stroke-color: red; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; -webkit-text-stroke-color: green; }
      ::spelling-error { -webkit-text-stroke-color: green; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // ‘-webkit-text-stroke-width’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { -webkit-text-stroke-width: 1px; }
      ::spelling-error { /* -webkit-text-stroke-width = 0 */ }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { -webkit-text-stroke-width: 1px; }
      ::spelling-error { -webkit-text-stroke-width: 2px; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { -webkit-text-stroke-width: 1px; }
      ::spelling-error { -webkit-text-stroke-width: 1px; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // ‘background-color’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      ::spelling-error { background-color: red; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: red; }
      ::spelling-error { background-color: currentColor; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      ::spelling-error { background-color: #66339900; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: #66339900; }
      ::spelling-error { background-color: currentColor; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // ‘text-shadow’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      ::spelling-error { text-shadow: 0 0 currentColor; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);

  // ‘text-decoration’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      ::spelling-error { text-decoration: none; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      ::spelling-error { text-decoration: grammar-error; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddGrammarMarker(test(R"HTML(
      ::grammar-error { text-decoration: spelling-error; }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      ::spelling-error { text-decoration: spelling-error; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
  GetDocument().Markers().AddGrammarMarker(test(R"HTML(
      ::grammar-error { text-decoration: grammar-error; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);

  // originating ‘text-decoration’
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; text-decoration: underline; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      html { color: blue; text-decoration: underline; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: red; text-decoration: blue underline; }
      ::spelling-error { /* decoration recolored to red */ }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      html { color: red; text-decoration: blue underline; }
      ::spelling-error { /* decoration recolored to red */ }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);

  // ‘text-emphasis-color’
  // TODO(crbug.com/1147859) clean up when spec issue is resolved again
  // https://github.com/w3c/csswg-drafts/issues/7101
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; text-emphasis: circle; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: blue; }
      ::spelling-error { /* no emphasis */ text-emphasis-color: green; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: red; text-emphasis: blue circle; }
      ::spelling-error { /* emphasis recolored to red */ }
  )HTML"));
  expect(HighlightPainter::kOverlay, __LINE__);
  GetDocument().Markers().AddSpellingMarker(test(R"HTML(
      body { color: red; text-emphasis: blue circle; }
      ::spelling-error { text-emphasis-color: blue; }
  )HTML"));
  expect(HighlightPainter::kFastSpellingGrammar, __LINE__);
}

}  // namespace blink
```