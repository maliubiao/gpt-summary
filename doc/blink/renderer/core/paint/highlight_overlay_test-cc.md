Response:
The user wants a summary of the provided C++ code file, `highlight_overlay_test.cc`, which is part of the Chromium Blink rendering engine.

Here's a breakdown of the request and a plan to generate the answer:

1. **Functionality:**  Identify the core purpose of the test file. It likely tests the `HighlightOverlay` class.
2. **Relationship to Web Technologies:** Analyze if the tested functionality relates to JavaScript, HTML, or CSS. This involves understanding what "highlight overlay" signifies in a web browser context.
3. **Logical Reasoning with Input/Output:** Examine the test cases provided. Each `TEST_F` block represents a test with a setup (input) and assertions (expected output).
4. **Common Usage Errors:** Consider scenarios where developers might misuse the highlighted functionality or misunderstand its behavior.
5. **User Operation to Reach This Code:**  Trace back the user actions that would trigger the execution of the code being tested. This will involve thinking about how highlighting is initiated in a browser.
6. **Summary of Functionality:**  Provide a concise overview of the file's role.

**Mental Sandbox/Pre-computation:**

* **Highlighting in Browsers:**  Highlighting is used for various features like text selection, search results, spelling/grammar errors, and custom highlights defined by web developers.
* **`HighlightOverlay` Class:** This class likely handles the visual representation of these highlights.
* **Test Structure:** The `TEST_F` macros indicate unit tests. The assertions (`EXPECT_EQ`) compare actual output with expected output.
* **Key Classes:**  Pay attention to classes like `Text`, `Range`, `DocumentMarker`, `HighlightRegistry`, and `PaintInfo`. These represent the data structures and systems involved in highlighting.

**Step-by-step thought process for generating the answer:**

1. **Identify the core class under test:** The filename and the `#include "third_party/blink/renderer/core/paint/highlight_overlay.h"` clearly indicate that `HighlightOverlay` is the main subject. The `HighlightOverlayTest` class confirms this.

2. **Determine the purpose of the test file:** It's a test file, so its purpose is to verify the correct functionality of `HighlightOverlay`.

3. **Analyze the individual test functions:**
    * `ComputeLayers`: This test focuses on determining which "layers" of highlighting should be active based on different conditions (selection, spelling errors, custom highlights, etc.). The output is a `HeapVector<HighlightLayer>`.
    * `ComputeEdges`: This test checks how the highlighting regions are broken down into "edges" with specific start and end points, considering different types of highlights. The output is a `Vector<HighlightEdge>`.
    * `ComputeParts`: This test examines how the overlapping highlight edges are combined to create visual "parts" with specific styling information. The output is a `HeapVector<HighlightPart>`.

4. **Relate to Web Technologies:**
    * **JavaScript:**  JavaScript APIs like `Selection` and the Custom Highlight API can trigger the creation of highlights.
    * **HTML:** The content being highlighted is within HTML elements.
    * **CSS:** CSS is used to style the highlights (colors, backgrounds, etc.). The test code even includes setting up `TextPaintStyle`.

5. **Provide Input/Output Examples:**  Extract examples from the existing test cases. Focus on the setup (e.g., adding a spelling marker) and the expected output (e.g., the `kSpelling` layer being present).

6. **Identify Potential Usage Errors:** Think about what could go wrong when implementing or using highlighting:
    * Incorrectly defining ranges.
    * Conflicting highlight styles.
    * Not considering the order of highlights.

7. **Describe User Actions:**  Think about how a user initiates highlighting in a browser:
    * Selecting text with the mouse.
    * The browser automatically highlighting search terms.
    * Spellchecking underlining errors.
    * Web developers using the Custom Highlight API.

8. **Summarize the Functionality:** Combine the insights from the previous steps into a concise summary.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the technical details of the C++ code. I need to ensure the explanation is also understandable from a web development perspective.
*  The "layers," "edges," and "parts" terminology might be specific to the Blink implementation. I need to explain these concepts clearly in relation to the broader idea of highlighting.
*  The examples should be concrete and easy to follow. I should pick the most illustrative test cases.

By following this structured approach, I can generate a comprehensive and informative answer to the user's request.
这是对位于 `blink/renderer/core/paint/highlight_overlay_test.cc` 的 Chromium Blink 引擎源代码文件的功能进行分析。该文件主要用于测试 `HighlightOverlay` 类的功能。`HighlightOverlay` 类负责在渲染过程中管理和绘制各种高亮效果，例如文本选择、拼写错误、语法错误、搜索结果高亮以及自定义高亮等。

**该文件的主要功能可以归纳为：**

1. **测试高亮图层的计算 (`ComputeLayers`)：**
   - 该部分测试 `HighlightOverlay::ComputeLayers` 函数，该函数负责根据当前文档的状态（例如，是否有文本选择，是否存在拼写/语法错误标记，是否存在自定义高亮等）来决定需要绘制哪些高亮图层。
   - 这些图层包括：
     - `kOriginating`: 原始文本层。
     - `kSelection`: 文本选择高亮层。
     - `kGrammar`: 语法错误高亮层。
     - `kSpelling`: 拼写错误高亮层。
     - `kTargetText`: 用于锚点链接或文本片段导航的目标文本高亮层。
     - `kSearchText`: 搜索匹配文本高亮层（包括激活和非激活状态）。
     - `kCustom`: 自定义高亮层。

2. **测试高亮边缘的计算 (`ComputeEdges`)：**
   - 该部分测试 `HighlightOverlay::ComputeEdges` 函数，该函数负责计算每个高亮图层的起始和结束“边缘”。这些边缘定义了高亮效果在文本中的具体范围和类型。
   - 它会考虑不同类型的高亮标记和文本选择，并生成一个包含 `HighlightEdge` 对象的向量。每个 `HighlightEdge` 包含高亮范围、图层类型、Z-index 和边缘类型（起始或结束）。

3. **测试高亮部分的计算 (`ComputeParts`)：**
   - 该部分测试 `HighlightOverlay::ComputeParts` 函数，该函数负责将重叠的高亮边缘组合成不同的“部分”，每个部分代表一个具有特定样式的高亮区域。
   - 它会根据激活的高亮图层以及它们的样式信息，生成一个包含 `HighlightPart` 对象的向量。每个 `HighlightPart` 包含图层类型、Z-index、高亮范围以及应用于该部分的文本样式。

**与 JavaScript, HTML, CSS 的功能关系及举例说明：**

该文件虽然是 C++ 代码，但它直接影响着浏览器如何渲染由 JavaScript, HTML, CSS 定义的高亮效果。

* **JavaScript:**
    - **`window.getSelection()`:** 当用户通过鼠标或键盘选择文本时，JavaScript 的 `window.getSelection()` API 可以获取选中文本的范围。这个范围信息会被传递到 Blink 渲染引擎，最终会影响 `HighlightOverlay::ComputeLayers` 函数，使得 `kSelection` 图层被包含在返回的图层列表中。
        ```javascript
        // 假设用户在网页上选择了 "example" 这段文本
        let selection = window.getSelection();
        console.log(selection.toString()); // 输出 "example"
        // 这个选择会导致 blink 渲染引擎计算出 selection 的高亮
        ```
    - **Custom Highlight API (`CSS ::highlight()` pseudo-element 和 `Highlight` API):**  Web 开发者可以使用 Custom Highlight API 来创建自定义的高亮效果。例如，使用 JavaScript 的 `Highlight` 对象创建一个高亮，并使用 CSS 的 `::highlight()` 伪元素为其设置样式。这些信息会被 Blink 引擎处理，`HighlightOverlay::ComputeLayers` 会识别出自定义高亮并添加 `kCustom` 图层。
        ```javascript
        // JavaScript 代码
        const highlight = new Highlight();
        highlight.addRanges(new Range(...)); // 设置高亮范围
        CSS.highlights.set('my-highlight', highlight);

        // CSS 代码
        ::highlight(my-highlight) {
          background-color: yellow;
          color: black;
        }
        ```
    - **`document.querySelectorAll(':target')`:** 当 URL 中包含锚点时，`:target` CSS 伪类会被激活，指向目标元素。Blink 渲染引擎会识别出目标元素，并可能使用 `HighlightOverlay` 来高亮显示该元素或其相关的文本内容，对应 `kTargetText` 图层。

* **HTML:**
    - **文本内容：**  `HighlightOverlay` 的目标是 HTML 文档中的文本内容。测试用例中通过 `SetBodyInnerHTML()` 设置 HTML 内容，例如 `"foo"` 或 `"brown fxo oevr lazy dgo today"`，这些文本是高亮效果应用的基础。
    - **`<br>` 元素:** 测试用例中包含了 `<br>` 元素，用于测试 `HighlightOverlay` 在处理包含换行符的文本时的行为。

* **CSS:**
    - **文本颜色和背景色：** CSS 样式会影响高亮的渲染效果。测试用例中的 `CreatePaintStyle()` 函数模拟了创建文本绘制样式，其中包含了颜色信息。这些颜色最终会应用于 `HighlightPart` 对象中，指导浏览器的绘制过程。
    - **`::selection` 伪元素：** 浏览器默认的文本选择高亮样式可以通过 `::selection` 伪元素进行自定义。`HighlightOverlay` 需要处理这些样式，并将它们应用到 `kSelection` 图层。
    - **拼写和语法错误样式：** 浏览器会根据内置的或扩展的拼写/语法检查器，对错误的单词应用特定的样式（例如，红色波浪线）。`HighlightOverlay` 需要将这些样式信息与 `kSpelling` 和 `kGrammar` 图层关联起来。

**逻辑推理的假设输入与输出：**

**测试 `ComputeLayers` 的例子：**

**假设输入：**
- HTML 内容: `"foo"`
- 用户没有进行任何文本选择。
- 文档中没有拼写或语法错误。
- 没有自定义高亮。
- 没有匹配的搜索结果。

**预期输出：**
```
HeapVector<HighlightLayer>{
    HighlightLayer{HighlightLayerType::kOriginating}
}
```
**推理：** 由于没有任何高亮事件发生，只需要绘制原始文本层。

**假设输入：**
- HTML 内容: `"example"`
- 用户选择了 "exam" 这段文本。

**预期输出：**
```
HeapVector<HighlightLayer>{
    HighlightLayer{HighlightLayerType::kOriginating},
    HighlightLayer{HighlightLayerType::kSelection},
}
```
**推理：** 除了原始文本层，还需要绘制文本选择高亮层。

**测试 `ComputeEdges` 的例子：**

**假设输入：**
- 文本节点内容: `"   foo"`
- 原始文本范围: `{3, 6}` (对应 "foo")
- 用户选择了 "oo" 这段文本 (对应文本内容偏移 `{1, 3}`)。

**预期输出（部分）：**
```
Vector<HighlightEdge>{
    HighlightEdge{{1, 3}, HighlightLayerType::kSelection, 1, HighlightEdgeType::kStart},
    HighlightEdge{{1, 3}, HighlightLayerType::kSelection, 1, HighlightEdgeType::kEnd},
}
```
**推理：** 选择高亮覆盖了文本内容偏移 `1` 到 `3`，因此生成起始和结束边缘。

**测试 `ComputeParts` 的例子：**

**假设输入：**
- 文本内容: `"brown fxo oevr lazy dgo today"`
- 激活的图层包括 `kOriginating`, `kCustom` (名为 "foo" 和 "bar"), `kSpelling`, `kTargetText`, `kSelection`。
- 不同的图层覆盖了不同的文本范围，可能存在重叠。

**预期输出（部分）：**
-  输出会是一个 `HighlightPart` 对象的向量，每个对象描述了一个连续的、具有相同高亮组合的文本片段及其样式。例如，如果 "oevr" 同时被拼写错误高亮和自定义高亮 "bar" 覆盖，则会生成一个 `HighlightPart` 对象，其样式结合了拼写错误和 "bar" 的样式。

**涉及用户或编程常见的使用错误：**

虽然这个文件是测试代码，但它可以帮助理解可能出现的错误：

1. **自定义高亮范围定义错误：** 开发者在使用 Custom Highlight API 时，可能会错误地定义高亮的范围，导致高亮效果不正确地应用到文本上。例如，起始偏移量大于结束偏移量，或者范围超出了文本的长度。
2. **高亮样式冲突：** 当多个高亮效果重叠时，它们的样式可能会发生冲突。开发者可能没有考虑到不同高亮类型的样式优先级，导致最终渲染的样式不是预期的。`HighlightOverlay::ComputeParts` 的测试就涉及到处理这种重叠和样式合并的情况。
3. **忽略文本节点和 DOM 偏移的差异：**  测试用例中特别提到了 DOM 偏移和文本内容偏移的差异。开发者在处理文本高亮时，需要正确理解和转换这两种偏移，否则会导致高亮范围错误。
4. **性能问题：**  如果页面上有大量的高亮效果或非常复杂的重叠情况，`HighlightOverlay` 的计算可能会影响渲染性能。虽然这不是一个直接的使用错误，但理解其工作原理有助于开发者避免创建过于复杂的高亮场景。

**用户操作是如何一步步的到达这里，作为调试线索：**

当用户在浏览器中执行以下操作时，可能会触发 `HighlightOverlay` 相关的代码执行：

1. **选择文本：** 用户通过鼠标拖拽或双击/三击文本来选择内容。这会触发浏览器的文本选择机制，`window.getSelection()` 会获取选择范围，并通知渲染引擎更新高亮状态。
2. **浏览包含锚点的链接或文本片段：** 当用户点击包含 `#` 的链接或者浏览器自动滚动到文本片段时，浏览器需要高亮显示目标内容。
3. **使用浏览器的查找功能 (Ctrl+F 或 Cmd+F)：** 当用户在页面上搜索关键词时，浏览器会高亮显示匹配的文本。
4. **触发拼写或语法检查：** 当用户在可编辑的文本区域输入内容时，浏览器可能会进行拼写和语法检查，并使用高亮来标记错误。
5. **使用开发者工具检查元素：** 在开发者工具中选中某个元素时，浏览器可能会高亮显示该元素在页面上的位置。
6. **网页使用了 Custom Highlight API：** 如果网页的 JavaScript 代码使用了 Custom Highlight API 来创建自定义的高亮效果，用户的浏览行为可能会触发这些高亮的显示和更新。

**作为调试线索，理解 `HighlightOverlay` 的工作原理可以帮助开发者：**

- 检查高亮效果是否正确显示在预期的文本范围内。
- 理解为什么某些高亮的样式会覆盖其他高亮的样式。
- 分析由于高亮导致的性能问题。
- 调试自定义高亮 API 的使用是否正确。

**总结 `highlight_overlay_test.cc` 的功能 (第 1 部分)：**

`highlight_overlay_test.cc` 文件的主要功能是**测试 Chromium Blink 引擎中 `HighlightOverlay` 类的核心逻辑，包括如何计算需要绘制的高亮图层 (`ComputeLayers`)、如何确定每个高亮图层的边缘范围 (`ComputeEdges`) 以及如何将重叠的边缘组合成具有特定样式的高亮部分 (`ComputeParts`)**。这些测试覆盖了文本选择、拼写/语法错误、搜索结果高亮以及自定义高亮等多种场景，确保 `HighlightOverlay` 能够正确地管理和渲染各种高亮效果。

Prompt: 
```
这是目录为blink/renderer/core/paint/highlight_overlay_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/highlight_overlay.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/abstract_range.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/grammar_marker.h"
#include "third_party/blink/renderer/core/editing/markers/spelling_marker.h"
#include "third_party/blink/renderer/core/editing/markers/text_fragment_marker.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/highlight/highlight_registry.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"

namespace blink {

namespace {

using HighlightLayerType = HighlightOverlay::HighlightLayerType;
using HighlightEdgeType = HighlightOverlay::HighlightEdgeType;
using HighlightLayer = HighlightOverlay::HighlightLayer;
using HighlightEdge = HighlightOverlay::HighlightEdge;
using HighlightPart = HighlightOverlay::HighlightPart;

}  // namespace

class HighlightOverlayTest : public PageTestBase {
 public:
  TextPaintStyle CreatePaintStyle(Color color) {
    return TextPaintStyle{color,   color,
                          color,   color,
                          2,       ::blink::mojom::blink::ColorScheme::kLight,
                          nullptr, TextDecorationLine::kNone,
                          color,   kPaintOrderNormal};
  }
};

TEST_F(HighlightOverlayTest, ComputeLayers) {
  SetBodyInnerHTML(R"HTML(foo)HTML");
  auto* text = DynamicTo<Text>(GetDocument().body()->firstChild());
  UpdateAllLifecyclePhasesForTest();

  LayoutSelectionStatus selection{0, 0, SelectSoftLineBreak::kNotSelected};
  auto* none = MakeGarbageCollected<DocumentMarkerVector>();
  const ComputedStyle& style = text->GetLayoutObject()->StyleRef();
  TextPaintStyle text_style;
  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);

  EXPECT_EQ(HighlightOverlay::ComputeLayers(GetDocument(), text, style,
                                            text_style, paint_info, nullptr,
                                            *none, *none, *none, *none, *none),
            HeapVector<HighlightLayer>{
                HighlightLayer{HighlightLayerType::kOriginating}})
      << "should return kOriginating when nothing is highlighted";

  EXPECT_EQ(HighlightOverlay::ComputeLayers(GetDocument(), text, style,
                                            text_style, paint_info, &selection,
                                            *none, *none, *none, *none, *none),
            (HeapVector<HighlightLayer>{
                HighlightLayer{HighlightLayerType::kOriginating},
                HighlightLayer{HighlightLayerType::kSelection},
            }))
      << "should return kSelection when a selection is given";

  auto* grammar = MakeGarbageCollected<DocumentMarkerVector>();
  auto* spelling = MakeGarbageCollected<DocumentMarkerVector>();
  auto* target = MakeGarbageCollected<DocumentMarkerVector>();
  auto* search = MakeGarbageCollected<DocumentMarkerVector>();
  grammar->push_back(MakeGarbageCollected<GrammarMarker>(1, 2, ""));
  grammar->push_back(MakeGarbageCollected<GrammarMarker>(2, 3, ""));
  spelling->push_back(MakeGarbageCollected<SpellingMarker>(1, 2, ""));
  spelling->push_back(MakeGarbageCollected<SpellingMarker>(2, 3, ""));
  target->push_back(MakeGarbageCollected<TextFragmentMarker>(1, 2));
  target->push_back(MakeGarbageCollected<TextFragmentMarker>(2, 3));
  search->push_back(MakeGarbageCollected<TextMatchMarker>(
      1, 2, TextMatchMarker::MatchStatus::kActive));
  search->push_back(MakeGarbageCollected<TextMatchMarker>(
      2, 3, TextMatchMarker::MatchStatus::kInactive));

  EXPECT_EQ(HighlightOverlay::ComputeLayers(
                GetDocument(), text, style, text_style, paint_info, nullptr,
                *none, *grammar, *spelling, *target, *search),
            (HeapVector<HighlightLayer>{
                HighlightLayer{HighlightLayerType::kOriginating},
                HighlightLayer{HighlightLayerType::kGrammar},
                HighlightLayer{HighlightLayerType::kSpelling},
                HighlightLayer{HighlightLayerType::kTargetText},
                HighlightLayer{HighlightLayerType::kSearchText},
                HighlightLayer{HighlightLayerType::kSearchTextActiveMatch},
            }))
      << "should return kGrammar + kSpelling + kTargetText + kSearchText no "
         "more than once each";

  HighlightRegistry* registry =
      HighlightRegistry::From(*text->GetDocument().domWindow());
  Range* highlight_range_1 = Range::Create(GetDocument());
  highlight_range_1->setStart(text, 0);
  highlight_range_1->setEnd(text, 1);
  Range* highlight_range_2 = Range::Create(GetDocument());
  highlight_range_2->setStart(text, 2);
  highlight_range_2->setEnd(text, 3);
  HeapVector<Member<AbstractRange>>* range_vector =
      MakeGarbageCollected<HeapVector<Member<AbstractRange>>>();
  range_vector->push_back(highlight_range_1);
  range_vector->push_back(highlight_range_2);
  Highlight* foo = Highlight::Create(*range_vector);
  Highlight* bar = Highlight::Create(*range_vector);
  registry->SetForTesting(AtomicString("foo"), foo);
  registry->SetForTesting(AtomicString("bar"), bar);
  registry->ScheduleRepaint();
  registry->ValidateHighlightMarkers();

  DocumentMarkerController& marker_controller = GetDocument().Markers();
  DocumentMarkerVector custom = marker_controller.MarkersFor(
      *text, DocumentMarker::MarkerTypes::CustomHighlight());
  EXPECT_EQ(
      HighlightOverlay::ComputeLayers(GetDocument(), text, style, text_style,
                                      paint_info, nullptr, custom, *none, *none,
                                      *none, *none),
      (HeapVector<HighlightLayer>{
          HighlightLayer{HighlightLayerType::kOriginating},
          HighlightLayer{HighlightLayerType::kCustom, AtomicString("foo")},
          HighlightLayer{HighlightLayerType::kCustom, AtomicString("bar")},
      }))
      << "should return kCustom layers no more than once each";
}

TEST_F(HighlightOverlayTest, ComputeEdges) {
  // #text "   foo" has two offset mapping units:
  // • DOM [0,3), text content [1,1)
  // • DOM [3,6), text content [1,4)
  SetBodyInnerHTML(R"HTML(<br>   foo<br>)HTML");
  Node* br = GetDocument().body()->firstChild();
  Node* text = br->nextSibling();
  UpdateAllLifecyclePhasesForTest();
  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);

  const ComputedStyle& br_style = br->GetLayoutObject()->StyleRef();
  const ComputedStyle& text_style = text->GetLayoutObject()->StyleRef();
  TextPaintStyle paint_style;

  TextOffsetRange originating{3, 6};
  LayoutSelectionStatus selection{1, 3, SelectSoftLineBreak::kNotSelected};
  auto* none = MakeGarbageCollected<DocumentMarkerVector>();

  HeapVector<HighlightLayer> layers;

  layers = HighlightOverlay::ComputeLayers(GetDocument(), text, text_style,
                                           paint_style, paint_info, nullptr,
                                           *none, *none, *none, *none, *none);
  EXPECT_EQ(
      HighlightOverlay::ComputeEdges(text, false, originating, layers, nullptr,
                                     *none, *none, *none, *none, *none),
      (Vector<HighlightEdge>{}))
      << "should return no edges when nothing is highlighted";

  layers = HighlightOverlay::ComputeLayers(GetDocument(), text, text_style,
                                           paint_style, paint_info, &selection,
                                           *none, *none, *none, *none, *none);
  EXPECT_EQ(HighlightOverlay::ComputeEdges(nullptr, false, originating, layers,
                                           &selection, *none, *none, *none,
                                           *none, *none),
            (Vector<HighlightEdge>{
                HighlightEdge{{1, 3},
                              HighlightLayerType::kSelection,
                              1,
                              HighlightEdgeType::kStart},
                HighlightEdge{{1, 3},
                              HighlightLayerType::kSelection,
                              1,
                              HighlightEdgeType::kEnd},
            }))
      << "should still return non-marker edges when node is nullptr";

  layers = HighlightOverlay::ComputeLayers(GetDocument(), br, br_style,
                                           paint_style, paint_info, &selection,
                                           *none, *none, *none, *none, *none);
  EXPECT_EQ(
      HighlightOverlay::ComputeEdges(br, false, originating, layers, &selection,
                                     *none, *none, *none, *none, *none),
      (Vector<HighlightEdge>{
          HighlightEdge{{1, 3},
                        HighlightLayerType::kSelection,
                        1,
                        HighlightEdgeType::kStart},
          HighlightEdge{{1, 3},
                        HighlightLayerType::kSelection,
                        1,
                        HighlightEdgeType::kEnd},
      }))
      << "should still return non-marker edges when node is <br>";

  auto* grammar = MakeGarbageCollected<DocumentMarkerVector>();
  auto* spelling = MakeGarbageCollected<DocumentMarkerVector>();
  auto* target = MakeGarbageCollected<DocumentMarkerVector>();
  auto* search = MakeGarbageCollected<DocumentMarkerVector>();
  grammar->push_back(MakeGarbageCollected<GrammarMarker>(3, 4, ""));
  grammar->push_back(MakeGarbageCollected<GrammarMarker>(4, 5, ""));
  target->push_back(MakeGarbageCollected<TextFragmentMarker>(4, 5));
  search->push_back(MakeGarbageCollected<TextMatchMarker>(
      4, 5, TextMatchMarker::MatchStatus::kActive));
  spelling->push_back(MakeGarbageCollected<SpellingMarker>(4, 5, ""));
  spelling->push_back(MakeGarbageCollected<SpellingMarker>(5, 6, ""));

  layers = HighlightOverlay::ComputeLayers(
      GetDocument(), text, text_style, paint_style, paint_info, &selection,
      *none, *grammar, *spelling, *target, *search);
  EXPECT_EQ(
      HighlightOverlay::ComputeEdges(text, false, originating, layers,
                                     &selection, *none, *grammar, *spelling,
                                     *target, *search),
      (Vector<HighlightEdge>{
          HighlightEdge{{1, 2},
                        HighlightLayerType::kGrammar,
                        1,
                        HighlightEdgeType::kStart},
          HighlightEdge{{1, 3},
                        HighlightLayerType::kSelection,
                        6,
                        HighlightEdgeType::kStart},
          HighlightEdge{
              {1, 2}, HighlightLayerType::kGrammar, 1, HighlightEdgeType::kEnd},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kGrammar,
                        1,
                        HighlightEdgeType::kStart},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSpelling,
                        2,
                        HighlightEdgeType::kStart},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kTargetText,
                        3,
                        HighlightEdgeType::kStart},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSearchTextActiveMatch,
                        5,
                        HighlightEdgeType::kStart},
          HighlightEdge{
              {2, 3}, HighlightLayerType::kGrammar, 1, HighlightEdgeType::kEnd},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSpelling,
                        2,
                        HighlightEdgeType::kEnd},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kTargetText,
                        3,
                        HighlightEdgeType::kEnd},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSearchTextActiveMatch,
                        5,
                        HighlightEdgeType::kEnd},
          HighlightEdge{{1, 3},
                        HighlightLayerType::kSelection,
                        6,
                        HighlightEdgeType::kEnd},
          HighlightEdge{{3, 4},
                        HighlightLayerType::kSpelling,
                        2,
                        HighlightEdgeType::kStart},
          HighlightEdge{{3, 4},
                        HighlightLayerType::kSpelling,
                        2,
                        HighlightEdgeType::kEnd},
      }))
      << "should return edges in correct order";

  TextOffsetRange originating2{4, 5};

  EXPECT_EQ(
      HighlightOverlay::ComputeEdges(text, false, originating2, layers,
                                     &selection, *none, *grammar, *spelling,
                                     *target, *search),
      (Vector<HighlightEdge>{
          HighlightEdge{{1, 3},
                        HighlightLayerType::kSelection,
                        6,
                        HighlightEdgeType::kStart},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kGrammar,
                        1,
                        HighlightEdgeType::kStart},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSpelling,
                        2,
                        HighlightEdgeType::kStart},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kTargetText,
                        3,
                        HighlightEdgeType::kStart},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSearchTextActiveMatch,
                        5,
                        HighlightEdgeType::kStart},
          HighlightEdge{
              {2, 3}, HighlightLayerType::kGrammar, 1, HighlightEdgeType::kEnd},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSpelling,
                        2,
                        HighlightEdgeType::kEnd},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kTargetText,
                        3,
                        HighlightEdgeType::kEnd},
          HighlightEdge{{2, 3},
                        HighlightLayerType::kSearchTextActiveMatch,
                        5,
                        HighlightEdgeType::kEnd},
          HighlightEdge{{1, 3},
                        HighlightLayerType::kSelection,
                        6,
                        HighlightEdgeType::kEnd},
      }))
      << "should skip edge pairs that are completely outside fragment";
}

TEST_F(HighlightOverlayTest, ComputeParts) {
  SetBodyInnerHTML(R"HTML(brown fxo oevr lazy dgo today)HTML");
  auto* text = DynamicTo<Text>(GetDocument().body()->firstChild());
  UpdateAllLifecyclePhasesForTest();

  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);

  const ComputedStyle& text_style = text->GetLayoutObject()->StyleRef();
  TextPaintStyle paint_style;

  auto* none = MakeGarbageCollected<DocumentMarkerVector>();
  auto* grammar = MakeGarbageCollected<DocumentMarkerVector>();
  auto* spelling = MakeGarbageCollected<DocumentMarkerVector>();
  auto* target = MakeGarbageCollected<DocumentMarkerVector>();

  HighlightRegistry* registry =
      HighlightRegistry::From(*text->GetDocument().domWindow());
  Range* foo_range = Range::Create(GetDocument());
  foo_range->setStart(text, 0);
  foo_range->setEnd(text, 14);
  Range* bar_range = Range::Create(GetDocument());
  bar_range->setStart(text, 10);
  bar_range->setEnd(text, 19);
  HeapVector<Member<AbstractRange>>* foo_range_vector =
      MakeGarbageCollected<HeapVector<Member<AbstractRange>>>();
  foo_range_vector->push_back(foo_range);
  HeapVector<Member<AbstractRange>>* bar_range_vector =
      MakeGarbageCollected<HeapVector<Member<AbstractRange>>>();
  bar_range_vector->push_back(bar_range);
  Highlight* foo = Highlight::Create(*foo_range_vector);
  Highlight* bar = Highlight::Create(*bar_range_vector);
  registry->SetForTesting(AtomicString("foo"), foo);
  registry->SetForTesting(AtomicString("bar"), bar);
  registry->ScheduleRepaint();
  registry->ValidateHighlightMarkers();
  DocumentMarkerController& marker_controller = GetDocument().Markers();
  DocumentMarkerVector custom = marker_controller.MarkersFor(
      *text, DocumentMarker::MarkerTypes::CustomHighlight());

  TextFragmentPaintInfo originating{"", 0, 25};
  TextOffsetRange originating_dom_offsets{0, 25};
  spelling->push_back(MakeGarbageCollected<SpellingMarker>(6, 9, ""));
  spelling->push_back(MakeGarbageCollected<SpellingMarker>(10, 14, ""));
  spelling->push_back(MakeGarbageCollected<SpellingMarker>(20, 23, ""));
  target->push_back(MakeGarbageCollected<TextFragmentMarker>(15, 23));
  LayoutSelectionStatus selection{13, 19, SelectSoftLineBreak::kNotSelected};

  HeapVector<HighlightLayer> layers = HighlightOverlay::ComputeLayers(
      GetDocument(), text, text_style, paint_style, paint_info, &selection,
      custom, *grammar, *spelling, *target, *none);

  // Set up paint styles for each layer
  Color originating_color(0, 0, 0);
  Color originating_background(1, 0, 0);
  HighlightStyleUtils::HighlightColorPropertySet originating_current_colors;
  HighlightStyleUtils::HighlightTextPaintStyle originating_text_style{
      CreatePaintStyle(originating_color), originating_color,
      Color::kTransparent, originating_current_colors};
  layers[0].text_style = originating_text_style;

  Color foo_color(0, 0, 1);
  Color foo_background(1, 0, 1);
  HighlightStyleUtils::HighlightColorPropertySet foo_current_colors;
  HighlightStyleUtils::HighlightTextPaintStyle foo_text_style{
      CreatePaintStyle(foo_color), foo_color, foo_background,
      foo_current_colors};
  layers[1].text_style = foo_text_style;

  Color bar_color(0, 0, 2);
  Color bar_background(1, 0, 2);
  HighlightStyleUtils::HighlightColorPropertySet bar_current_colors{
      HighlightStyleUtils::HighlightColorProperty::kCurrentColor,
      HighlightStyleUtils::HighlightColorProperty::kFillColor,
      HighlightStyleUtils::HighlightColorProperty::kStrokeColor,
      HighlightStyleUtils::HighlightColorProperty::kEmphasisColor,
      HighlightStyleUtils::HighlightColorProperty::kSelectionDecorationColor,
      HighlightStyleUtils::HighlightColorProperty::kTextDecorationColor,
      HighlightStyleUtils::HighlightColorProperty::kBackgroundColor};
  HighlightStyleUtils::HighlightTextPaintStyle bar_text_style{
      CreatePaintStyle(bar_color), bar_color, bar_background,
      bar_current_colors};
  layers[2].text_style = bar_text_style;

  Color spelling_color(0, 0, 3);
  Color spelling_background(1, 0, 3);
  HighlightStyleUtils::HighlightColorPropertySet spelling_current_colors;
  HighlightStyleUtils::HighlightTextPaintStyle spelling_text_style{
      CreatePaintStyle(spelling_color), spelling_color, spelling_background,
      spelling_current_colors};
  layers[3].text_style = spelling_text_style;

  Color target_color(0, 0, 4);
  Color target_background(1, 0, 4);
  HighlightStyleUtils::HighlightColorPropertySet target_current_colors{
      HighlightStyleUtils::HighlightColorProperty::kCurrentColor,
      HighlightStyleUtils::HighlightColorProperty::kFillColor,
      HighlightStyleUtils::HighlightColorProperty::kStrokeColor,
      HighlightStyleUtils::HighlightColorProperty::kEmphasisColor,
      HighlightStyleUtils::HighlightColorProperty::kSelectionDecorationColor,
      HighlightStyleUtils::HighlightColorProperty::kTextDecorationColor,
      HighlightStyleUtils::HighlightColorProperty::kBackgroundColor};
  HighlightStyleUtils::HighlightTextPaintStyle target_text_style{
      CreatePaintStyle(target_color), target_color, target_background,
      target_current_colors};
  layers[4].text_style = target_text_style;

  Color selection_color(0, 0, 5);
  Color selection_background(1, 0, 5);
  HighlightStyleUtils::HighlightColorPropertySet selection_current_colors;
  HighlightStyleUtils::HighlightTextPaintStyle selection_text_style{
      CreatePaintStyle(selection_color), selection_color, selection_background,
      selection_current_colors};
  layers[5].text_style = selection_text_style;

  // 0     6   10   15   20  24
  // brown fxo oevr lazy dgo today
  // [                       ]        originating
  //                                  ::highlight(foo), not active
  //                                  ::highlight(bar), not active
  //                                  ::spelling-error, not active
  //                                  ::target-text, not active
  //                                  ::selection, not active
  //                                  ::search-text, not active

  Vector<HighlightEdge> edges = HighlightOverlay::ComputeEdges(
      text, false, originating_dom_offsets, layers, nullptr, *none, *none,
      *none, *none, *none);

  // clang-format off
  EXPECT_EQ(HighlightOverlay::ComputeParts(originating, layers, edges),
            (HeapVector<HighlightPart>{
                HighlightPart{HighlightLayerType::kOriginating, 0, {0,25}, originating_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color}}},
            }))
      << "should return correct kOriginating part when nothing is highlighted";

  // 0     6   10   15   20  24
  // brown fxo oevr lazy dgo today
  // [                       ]        originating, as above
  // [            ]                   ::highlight(foo), changed!
  //           [       ]              ::highlight(bar), changed!
  //       [ ] [  ]      [ ]          ::spelling-error, changed!
  //                [      ]          ::target-text, changed!
  //              [    ]              ::selection, changed!
  //                                  ::search-text, not active

  Vector<HighlightEdge> edges2 = HighlightOverlay::ComputeEdges(
      text, false, originating_dom_offsets, layers, &selection, custom,
      *grammar, *spelling, *target, *none);

  EXPECT_EQ(HighlightOverlay::ComputeParts(originating, layers, edges2),
            (HeapVector<HighlightPart>{
                HighlightPart{HighlightLayerType::kCustom, 1, {0,6}, foo_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 1, {0,14}, foo_color}},
                              {{HighlightLayerType::kCustom, 1, foo_background}},
                              {{HighlightLayerType::kCustom, 1, foo_color}}},
                HighlightPart{HighlightLayerType::kSpelling, 3, {6,9}, spelling_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 1, {0,14}, foo_color},
                               {HighlightLayerType::kSpelling, 3, {6,9}, spelling_color}},
                              {{HighlightLayerType::kCustom, 1, foo_background},
                               {HighlightLayerType::kSpelling, 3, spelling_background}},
                              {{HighlightLayerType::kCustom, 1, foo_color},
                               {HighlightLayerType::kSpelling, 3, spelling_color}}},
                HighlightPart{HighlightLayerType::kCustom, 1, {9,10}, foo_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 1, {0,14}, foo_color}},
                              {{HighlightLayerType::kCustom, 1, foo_background}},
                              {{HighlightLayerType::kCustom, 1, foo_color}}},
                HighlightPart{HighlightLayerType::kSpelling, 3, {10,13}, spelling_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 1, {0,14}, foo_color},
                               {HighlightLayerType::kCustom, 2, {10,19}, foo_color},
                               {HighlightLayerType::kSpelling, 3, {10,14}, spelling_color}},
                              {{HighlightLayerType::kCustom, 1, foo_background},
                               {HighlightLayerType::kCustom, 2, foo_color},
                               {HighlightLayerType::kSpelling, 3, spelling_background}},
                              {{HighlightLayerType::kCustom, 1, foo_color},
                               {HighlightLayerType::kCustom, 2, foo_color},
                               {HighlightLayerType::kSpelling, 3, spelling_color}}},
                HighlightPart{HighlightLayerType::kSelection, 5, {13,14}, selection_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 1, {0,14}, foo_color},
                               {HighlightLayerType::kCustom, 2, {10,19}, foo_color},
                               {HighlightLayerType::kSpelling, 3, {10,14}, spelling_color},
                               {HighlightLayerType::kSelection, 5, {13,19}, selection_color}},
                              {{HighlightLayerType::kCustom, 1, foo_background},
                               {HighlightLayerType::kCustom, 2, foo_color},
                               {HighlightLayerType::kSpelling, 3, spelling_background},
                               {HighlightLayerType::kSelection, 5, selection_background}},
                              {{HighlightLayerType::kCustom, 1, foo_color},
                               {HighlightLayerType::kCustom, 2, foo_color},
                               {HighlightLayerType::kSpelling, 3, spelling_color},
                               {HighlightLayerType::kSelection, 5, selection_color}}},
                HighlightPart{HighlightLayerType::kSelection, 5, {14,15}, selection_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 2, {10,19}, originating_color},
                               {HighlightLayerType::kSelection, 5, {13,19}, selection_color}},
                              {{HighlightLayerType::kCustom, 2, originating_color},
                               {HighlightLayerType::kSelection, 5, selection_background}},
                              {{HighlightLayerType::kCustom, 2, originating_color},
                               {HighlightLayerType::kSelection, 5, selection_color}}},
                HighlightPart{HighlightLayerType::kSelection, 5, {15,19}, selection_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 2, {10,19}, originating_color},
                               {HighlightLayerType::kTargetText, 4, {15,23}, originating_color},
                               {HighlightLayerType::kSelection, 5, {13,19}, selection_color}},
                              {{HighlightLayerType::kCustom, 2, originating_color},
                               {HighlightLayerType::kTargetText, 4, originating_color},
                               {HighlightLayerType::kSelection, 5, selection_background}},
                              {{HighlightLayerType::kCustom, 2, originating_color},
                               {HighlightLayerType::kTargetText, 4, originating_color},
                               {HighlightLayerType::kSelection, 5, selection_color}}},
                HighlightPart{HighlightLayerType::kTargetText, 4, {19,20}, originating_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kTargetText, 4, {15,23}, originating_color}},
                              {{HighlightLayerType::kTargetText, 4, originating_color}},
                              {{HighlightLayerType::kTargetText, 4, originating_color}}},
                HighlightPart{HighlightLayerType::kTargetText, 4, {20,23}, spelling_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kSpelling, 3, {20,23}, spelling_color},
                               {HighlightLayerType::kTargetText, 4, {15,23}, spelling_color}},
                              {{HighlightLayerType::kSpelling, 3, spelling_background},
                               {HighlightLayerType::kTargetText, 4, spelling_color}},
                              {{HighlightLayerType::kSpelling, 3, spelling_color},
                               {HighlightLayerType::kTargetText, 4, spelling_color}}},
                HighlightPart{HighlightLayerType::kOriginating, 0, {23,25}, originating_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color}}},
            }))
      << "should return correct parts given several active highlights";

  // 0     6   10   15   20  24
  // brown fxo oevr lazy dgo today
  // [                       ]        originating, as above
  //       [      ]                   ::highlight(foo), changed!
  //           [       ]              ::highlight(bar), as above
  //       [ ] [  ]      [ ]          ::spelling-error, as above
  //                [      ]          ::target-text, as above
  //              [    ]              ::selection, as above
  //                                  ::search-text, not active

  foo_range->setStart(text, 6);
  registry->ScheduleRepaint();
  registry->ValidateHighlightMarkers();
  custom = marker_controller.MarkersFor(*text, DocumentMarker::MarkerTypes::CustomHighlight());
  Vector<HighlightEdge> edges3 = HighlightOverlay::ComputeEdges(
      text, false, originating_dom_offsets, layers, &selection, custom,
      *grammar, *spelling, *target, *none);

  EXPECT_EQ(HighlightOverlay::ComputeParts(originating, layers, edges3),
            (HeapVector<HighlightPart>{
                HighlightPart{HighlightLayerType::kOriginating, 0, {0,6}, originating_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color}}},
                HighlightPart{HighlightLayerType::kSpelling, 3, {6,9}, spelling_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 1, {6,14}, foo_color},
                               {HighlightLayerType::kSpelling, 3, {6,9}, spelling_color}},
                              {{HighlightLayerType::kCustom, 1, foo_background},
                               {HighlightLayerType::kSpelling, 3, spelling_background}},
                              {{HighlightLayerType::kCustom, 1, foo_color},
                               {HighlightLayerType::kSpelling, 3, spelling_color}}},
                HighlightPart{HighlightLayerType::kCustom, 1, {9,10}, foo_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               {HighlightLayerType::kCustom, 1, {6,14}, foo_color}},
                              {{HighlightLayerType::kCustom, 1, foo_background}},
                              {{HighlightLayerType::kCustom, 1, foo_color}}},
                HighlightPart{HighlightLayerType::kSpelling, 3, {10,13}, spelling_text_style.style, 0,
                              {{HighlightLayerType::kOriginating, 0, {0,25}, originating_color},
                               
"""


```