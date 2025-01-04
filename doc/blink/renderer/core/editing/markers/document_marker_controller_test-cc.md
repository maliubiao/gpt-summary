Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding - What is this file about?**

The filename `document_marker_controller_test.cc` immediately suggests this is a unit test file. The `DocumentMarkerController` part indicates it tests a component responsible for managing "markers" within a document. Markers likely represent visual annotations or flags associated with specific parts of the document.

**2. Examining Includes - What are the dependencies?**

The `#include` directives give clues about the functionalities being tested:

* `"third_party/blink/renderer/core/editing/markers/document_marker_controller.h"`:  Confirms we are testing the `DocumentMarkerController` class itself.
* `"testing/gtest/include/gtest/gtest.h"`:  Indicates the use of the Google Test framework for writing tests.
* `"third_party/blink/renderer/core/dom/document.h"`:  Suggests interaction with the DOM (Document Object Model).
* `"third_party/blink/renderer/core/dom/range.h"`:  Implies working with ranges of content within the document.
* `"third_party/blink/renderer/core/dom/text.h"`:  Indicates manipulation of text nodes.
* `"third_party/blink/renderer/core/editing/ephemeral_range.h"`:  Points to a lightweight representation of document ranges, likely used for efficiency in editing operations.
* `"third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"`, `"third_party/blink/renderer/core/editing/markers/suggestion_marker.h"`, `"third_party/blink/renderer/core/editing/markers/suggestion_marker_properties.h"`: These reveal specific types of markers being managed: custom highlights and suggestions (likely for spellchecking, grammar, etc.).
* `"third_party/blink/renderer/core/editing/testing/editing_test_base.h"`:  Suggests a base class providing common setup and utilities for editing-related tests.
* `"third_party/blink/renderer/core/highlight/highlight.h"`:  Indicates interaction with the highlighting system.
* `"third_party/blink/renderer/core/html/html_element.h"`:  Shows manipulation of HTML elements.
* `"third_party/blink/renderer/core/layout/layout_object.h"`:  Implies testing scenarios involving the layout and rendering of the document.
* `"third_party/blink/renderer/core/testing/dummy_page_holder.h"`, `"third_party/blink/renderer/core/testing/null_execution_context.h"`:  These are likely test utilities for creating isolated document environments.
* `"third_party/blink/renderer/platform/bindings/exception_state.h"`, `"third_party/blink/renderer/platform/heap/garbage_collected.h"`, `"third_party/blink/renderer/platform/heap/thread_state.h"`: These relate to memory management and the Blink rendering engine's internal workings.

**3. Analyzing the Test Fixture - Common Setup**

The `DocumentMarkerControllerTest` class inherits from `EditingTestBase`, which suggests a standard test setup. The `MarkerController()` method provides easy access to the `DocumentMarkerController` instance being tested. The helper methods `CreateTextNode`, `MarkNodeContents`, and `MarkNodeContentsTextMatch` suggest common actions performed in the tests: creating text, and adding different types of markers to node content.

**4. Deconstructing Individual Tests - Core Functionality**

Now, the real work begins: examining each `TEST_F` function. For each test, ask:

* **What is the scenario being tested?** Look at the `SetBodyContent`, the actions performed (adding/removing markers, modifying the DOM), and the `EXPECT_...` assertions.
* **What is the expected outcome?**  The assertions reveal what the test expects to happen.
* **Are there any interesting edge cases or specific behaviors being verified?** For example, tests involving moving nodes between documents, node removal through various DOM operations, interaction with garbage collection, and the merging/non-merging of markers.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Based on the understood functionalities, consider the connections to web technologies:

* **Markers and Visual Feedback:** Markers directly relate to how browsers provide visual cues to users. Spelling and grammar errors, search results, and custom highlights are all implemented using marker-like mechanisms.
* **JavaScript Interaction:**  While the test is in C++, the functionality being tested is likely exposed to JavaScript. JavaScript APIs would allow web developers to:
    * Query and retrieve markers.
    * Potentially add custom markers (though this might be more internal).
    * React to changes in markers.
* **HTML Structure:** The tests heavily rely on manipulating HTML elements (`<div>`, `<b>`, `<i>`, etc.). The structure of the HTML directly affects how markers are applied and managed.
* **CSS Styling (Indirect):** While not explicitly tested, markers often have associated default styles or can be styled via CSS (e.g., the wavy underline for spelling errors). The `UpdateRenderedRects` test shows how layout changes (influenced by CSS) affect marker positioning.

**6. Logical Reasoning and Examples:**

For tests involving logic (like `SetMarkerActiveTest`, `Remove...Marker` tests), try to infer the underlying logic of the `DocumentMarkerController`. Imagine the data structures and algorithms needed to manage markers efficiently. Think about the inputs (ranges, marker types) and the expected outputs (marker existence, state).

**7. Identifying Potential User/Programming Errors:**

Consider how a web developer might misuse the APIs related to markers or how the browser's internal logic could have errors. Examples include:

* Incorrectly calculating ranges for markers.
* Expecting markers to persist after their associated nodes are removed from the DOM.
* Conflicting logic when dealing with overlapping markers.

**8. Tracing User Actions (Debugging Clues):**

Think about the user actions that could lead to the execution of the `DocumentMarkerController` code:

* Typing text in an editable area (triggers spellchecking).
* Performing a search on a page (highlights matching text).
* Using browser extensions that add annotations.
* JavaScript code that dynamically manipulates the DOM and adds visual cues.

**Self-Correction/Refinement During Analysis:**

* **Initial Misinterpretations:**  You might initially think a marker is *only* visual. However, some markers (like suggestion markers) might have associated data or actions.
* **Granularity:** Start with a high-level understanding and then dive into the details of individual tests.
* **Context:** Remember this is *part* of a larger rendering engine. The `DocumentMarkerController` doesn't exist in isolation.

By following these steps, you can systematically analyze the C++ test file and understand its purpose, its connections to web technologies, and its implications for browser functionality.
这个文件 `document_marker_controller_test.cc` 是 Chromium Blink 引擎的一部分，它专门用于测试 `DocumentMarkerController` 类的功能。`DocumentMarkerController` 负责管理文档中的各种标记（markers），这些标记用于在用户界面上提供视觉提示，例如拼写错误、语法建议、搜索结果高亮等。

以下是 `document_marker_controller_test.cc` 的主要功能点，并结合了与 JavaScript、HTML 和 CSS 的关系进行说明：

**1. 测试 `DocumentMarkerController` 的核心功能：**

* **添加和移除不同类型的标记:**  测试文件涵盖了添加和移除各种类型的 `DocumentMarker`，例如：
    * **Spelling Marker (拼写标记):**  用于指示拼写错误。
    * **Text Match Marker (文本匹配标记):** 用于高亮显示搜索结果或其他文本匹配项。
    * **Composition Marker (输入法组合标记):**  用于在输入法组合文字时提供视觉反馈。
    * **Suggestion Marker (建议标记):** 用于提供拼写或语法建议。
    * **Custom Highlight Marker (自定义高亮标记):** 用于应用自定义的高亮效果。

* **管理标记的生命周期:** 测试了当 DOM 结构发生变化时，标记是否能够正确地被更新或移除，例如：
    * 当包含标记的节点被移动到新的文档时 (`DidMoveToNewDocument`)。
    * 当包含标记的节点被移除时，通过 `normalize()`, `removeChildren()`, `removeChild()`, `replaceChild()`, `innerHTML` 等操作 (`NodeWillBeRemovedMarkedByNormalize`, `NodeWillBeRemovedMarkedByRemoveChildren` 等)。

* **更新标记的渲染矩形 (`UpdateRenderedRects`):** 测试了当包含标记的元素的布局发生变化时（例如，通过修改 CSS 样式），标记的渲染位置是否能够正确更新。 这直接关系到用户在屏幕上看到的高亮位置是否准确。

* **处理标记的激活状态 (`SetMarkerActiveTest`):** 测试了如何激活或停用文本匹配标记，这可能用于指示当前选中的搜索结果。

* **处理标记的范围操作 (`RemoveStartOfMarker`, `RemoveMiddleOfMarker`, `RemoveEndOfMarker`):** 测试了当移除或修改文本时，如何正确地移除或调整与这些文本相关的标记。

* **根据特定条件移除标记 (`RemoveSpellingMarkersUnderWords`, `RemoveSuggestionMarkerByTag`, `RemoveSuggestionMarkerByType`):** 测试了根据单词、标签或类型移除标记的功能，这对于实现拼写检查的自动修复或取消建议等功能至关重要。

* **查询特定位置或范围内的标记 (`FirstMarkerIntersectingOffsetRange`, `MarkersAroundPosition`, `MarkersIntersectingRange`):** 测试了如何有效地查找与特定文本位置或范围重叠的标记，这对于实现上下文菜单、悬停提示等功能很有用。

* **处理包含 Shadow DOM 的情况 (`MarkersIntersectingRangeWithShadowDOM`):** 测试了标记管理在 Shadow DOM 环境下的正确性，确保标记能够跨越 Shadow DOM 的边界进行管理。

* **确保建议标记具有唯一标签 (`SuggestionMarkersHaveUniqueTags`):**  这对于唯一标识和操作特定的建议标记非常重要。

* **合并重叠的自定义高亮标记 (`HighlightsAreNonOverlappingAndSorted`):** 测试了如何将重叠的自定义高亮标记合并成非重叠的、排序的标记，以优化渲染和数据管理。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** `DocumentMarkerController` 的功能最终会影响到 JavaScript 可以通过 Blink 提供的 API 访问和操作的内容。 例如：
    * **假设输入:** 用户在 contenteditable 的 div 中输入 "teh"。
    * **逻辑推理:**  拼写检查模块会检测到错误，并调用 `DocumentMarkerController::AddSpellingMarker` 来添加一个标记。 这个标记可能会通过 JavaScript API 暴露出来，让开发者可以获取错误的位置和建议。
    * **输出:** JavaScript 可以查询到这个拼写错误标记，并可能提供修复建议的 UI。

* **HTML:**  标记是附加在 HTML 元素或文本节点上的。 测试用例中大量使用了 HTML 结构来模拟不同的场景。
    * **举例说明:** 在测试 `NodeWillBeRemovedMarkedBySetInnerHTML` 中，设置了包含标记的 HTML 内容，然后通过 `SetBodyContent("")` 移除了所有内容。 测试验证了与这些被移除节点相关的标记也被正确清理。

* **CSS:** 虽然 `DocumentMarkerController` 本身不直接处理 CSS，但标记的呈现方式通常会受到 CSS 的影响。 例如，拼写错误的下划线、搜索结果的高亮颜色等都可以通过 CSS 进行定制。 `UpdateRenderedRects` 测试确保了当元素的布局（受 CSS 影响）变化时，标记的渲染位置能够随之更新，保证视觉效果的正确性。

**逻辑推理的假设输入与输出：**

* **假设输入:**  用户在搜索框中输入 "hello"，页面上 "Hello World" 中的 "Hello" 被匹配。
* **逻辑推理:** 搜索功能会调用 `DocumentMarkerController::AddTextMatchMarker` 来高亮显示 "Hello"。
* **输出:**  屏幕上 "Hello" 这部分文本会被高亮显示。

**用户或编程常见的使用错误举例说明：**

* **用户错误:** 用户可能会在 JavaScript 中尝试操作已经不存在的标记，例如在节点被移除后仍然尝试访问该节点上的标记。
* **编程错误:** 开发者在实现富文本编辑器时，可能没有正确地更新或移除与被修改或删除的文本相关的标记，导致界面上出现错误的标记。 例如，在删除一段包含拼写错误标记的文本后，旧的拼写错误标记可能仍然残留在页面上。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在可编辑区域输入文本:**  这是最常见的情况，输入法组合、拼写检查、语法检查等功能都可能触发标记的添加。
2. **用户执行搜索操作:** 浏览器的搜索功能会在页面上添加文本匹配标记。
3. **网页 JavaScript 代码动态添加标记:**  网页开发者可以使用 JavaScript API 来添加自定义的标记，用于实现特定的 UI 效果。
4. **用户与浏览器提供的辅助功能交互:** 例如，用户右键点击拼写错误的单词，浏览器会查询相关的建议标记。
5. **开发者进行性能分析或调试:** 开发者可能需要查看当前页面上的标记信息，以了解页面状态或进行性能优化。

当出现与标记相关的 bug 时，开发者可以按照以下步骤进行调试：

1. **重现用户的操作步骤:** 尝试复现导致问题的用户操作流程。
2. **检查 DOM 结构:**  查看相关的 HTML 元素和文本节点，确认标记是否附加在正确的节点上。
3. **使用开发者工具查看标记:**  虽然浏览器可能没有直接显示所有类型的标记，但开发者可以通过审查元素或使用特定的调试工具来查看某些类型的标记信息。
4. **断点调试 `DocumentMarkerController` 的相关代码:**  在 `document_marker_controller_test.cc` 中找到相关的测试用例，理解其逻辑，然后在实际运行的代码中设置断点，跟踪标记的添加、移除和更新过程。
5. **查看日志输出:** Blink 引擎可能会输出与标记相关的日志信息，帮助开发者了解标记的状态变化。

总而言之，`document_marker_controller_test.cc` 通过大量的单元测试用例，确保了 Blink 引擎中负责管理文档标记的 `DocumentMarkerController` 类的功能正确性和稳定性，这对于提供良好的用户体验至关重要，特别是在涉及文本编辑、搜索和辅助功能等方面。

Prompt: 
```
这是目录为blink/renderer/core/editing/markers/document_marker_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"

#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_properties.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/highlight/highlight.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"

namespace blink {

class DocumentMarkerControllerTest : public EditingTestBase {
 protected:
  DocumentMarkerController& MarkerController() const {
    return GetDocument().Markers();
  }

  Text* CreateTextNode(const char*);
  void MarkNodeContents(Node*);
  void MarkNodeContentsTextMatch(Node*);
};

Text* DocumentMarkerControllerTest::CreateTextNode(const char* text_contents) {
  return GetDocument().createTextNode(String::FromUTF8(text_contents));
}

void DocumentMarkerControllerTest::MarkNodeContents(Node* node) {
  // Force layoutObjects to be created; TextIterator, which is used in
  // DocumentMarkerControllerTest::addMarker(), needs them.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  auto range = EphemeralRange::RangeOfContents(*node);
  MarkerController().AddSpellingMarker(range);
}

void DocumentMarkerControllerTest::MarkNodeContentsTextMatch(Node* node) {
  // Force layoutObjects to be created; TextIterator, which is used in
  // DocumentMarkerControllerTest::addMarker(), needs them.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  auto range = EphemeralRange::RangeOfContents(*node);
  MarkerController().AddTextMatchMarker(range,
                                        TextMatchMarker::MatchStatus::kActive);
}

TEST_F(DocumentMarkerControllerTest, DidMoveToNewDocument) {
  SetBodyContent("<b><i>foo</i></b>");
  auto* parent = To<Element>(GetDocument().body()->firstChild()->firstChild());
  MarkNodeContents(parent);
  EXPECT_EQ(1u, MarkerController().Markers().size());
  ScopedNullExecutionContext execution_context;
  Persistent<Document> another_document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  another_document->adoptNode(parent, ASSERT_NO_EXCEPTION);

  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());
  EXPECT_EQ(0u, another_document->Markers().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, NodeWillBeRemovedMarkedByNormalize) {
  SetBodyContent("<b><i>foo</i></b>");
  {
    auto* parent =
        To<Element>(GetDocument().body()->firstChild()->firstChild());
    parent->AppendChild(CreateTextNode("bar"));
    MarkNodeContents(parent);
    EXPECT_EQ(2u, MarkerController().Markers().size());
    parent->normalize();
    UpdateAllLifecyclePhasesForTest();
  }
  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(1u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, NodeWillBeRemovedMarkedByRemoveChildren) {
  SetBodyContent("<b><i>foo</i></b>");
  auto* parent = To<Element>(GetDocument().body()->firstChild()->firstChild());
  MarkNodeContents(parent);
  EXPECT_EQ(1u, MarkerController().Markers().size());
  parent->RemoveChildren();
  UpdateAllLifecyclePhasesForTest();
  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, NodeWillBeRemovedByRemoveMarked) {
  SetBodyContent("<b><i>foo</i></b>");
  {
    auto* parent =
        To<Element>(GetDocument().body()->firstChild()->firstChild());
    MarkNodeContents(parent);
    EXPECT_EQ(1u, MarkerController().Markers().size());
    parent->RemoveChild(parent->firstChild());
    UpdateAllLifecyclePhasesForTest();
  }
  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, NodeWillBeRemovedMarkedByRemoveAncestor) {
  SetBodyContent("<b><i>foo</i></b>");
  {
    auto* parent =
        To<Element>(GetDocument().body()->firstChild()->firstChild());
    MarkNodeContents(parent);
    EXPECT_EQ(1u, MarkerController().Markers().size());
    parent->parentNode()->parentNode()->RemoveChild(parent->parentNode());
    UpdateAllLifecyclePhasesForTest();
  }
  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, NodeWillBeRemovedMarkedByRemoveParent) {
  SetBodyContent("<b><i>foo</i></b>");
  {
    auto* parent =
        To<Element>(GetDocument().body()->firstChild()->firstChild());
    MarkNodeContents(parent);
    EXPECT_EQ(1u, MarkerController().Markers().size());
    parent->parentNode()->RemoveChild(parent);
    UpdateAllLifecyclePhasesForTest();
  }
  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, NodeWillBeRemovedMarkedByReplaceChild) {
  SetBodyContent("<b><i>foo</i></b>");
  {
    auto* parent =
        To<Element>(GetDocument().body()->firstChild()->firstChild());
    MarkNodeContents(parent);
    EXPECT_EQ(1u, MarkerController().Markers().size());
    parent->ReplaceChild(CreateTextNode("bar"), parent->firstChild());
    UpdateAllLifecyclePhasesForTest();
  }
  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, NodeWillBeRemovedBySetInnerHTML) {
  SetBodyContent("<b><i>foo</i></b>");
  {
    auto* parent =
        To<Element>(GetDocument().body()->firstChild()->firstChild());
    MarkNodeContents(parent);
    EXPECT_EQ(1u, MarkerController().Markers().size());
    SetBodyContent("");
    UpdateAllLifecyclePhasesForTest();
  }
  // No more reference to marked node.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

// For http://crbug.com/862900
TEST_F(DocumentMarkerControllerTest, SynchronousMutationNotificationAfterGC) {
  SetBodyContent("<b><i>foo</i></b>");
  Persistent<Text> sibling_text = CreateTextNode("bar");
  {
    auto* parent =
        To<Element>(GetDocument().body()->firstChild()->firstChild());
    parent->parentNode()->AppendChild(sibling_text);
    MarkNodeContents(parent);
    EXPECT_EQ(1u, MarkerController().Markers().size());
    parent->parentNode()->RemoveChild(parent);
    UpdateAllLifecyclePhasesForTest();
  }

  // GC the marked node, so it disappears from WeakMember collections.
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, MarkerController().Markers().size());

  // Trigger SynchronousMutationNotifier::NotifyUpdateCharacterData().
  // This matches the conditions for the crashes in crbug.com/862960.
  sibling_text->setData("baz");
}

TEST_F(DocumentMarkerControllerTest, UpdateRenderedRects) {
  SetBodyContent("<div style='margin: 100px'>foo</div>");
  auto* div = To<Element>(GetDocument().body()->firstChild());
  MarkNodeContentsTextMatch(div);
  Vector<gfx::Rect> rendered_rects =
      MarkerController().LayoutRectsForTextMatchMarkers();
  EXPECT_EQ(1u, rendered_rects.size());

  div->setAttribute(html_names::kStyleAttr, AtomicString("margin: 200px"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Vector<gfx::Rect> new_rendered_rects =
      MarkerController().LayoutRectsForTextMatchMarkers();
  EXPECT_EQ(1u, new_rendered_rects.size());
  EXPECT_NE(rendered_rects[0], new_rendered_rects[0]);
}

TEST_F(DocumentMarkerControllerTest, CompositionMarkersNotMerged) {
  SetBodyContent("<div style='margin: 100px'>foo</div>");
  Node* text = GetDocument().body()->firstChild()->firstChild();
  MarkerController().AddCompositionMarker(
      EphemeralRange(Position(text, 0), Position(text, 1)), Color::kTransparent,
      ui::mojom::ImeTextSpanThickness::kThin,
      ui::mojom::ImeTextSpanUnderlineStyle::kSolid, Color::kBlack,
      Color::kBlack);
  MarkerController().AddCompositionMarker(
      EphemeralRange(Position(text, 1), Position(text, 3)), Color::kTransparent,
      ui::mojom::ImeTextSpanThickness::kThick,
      ui::mojom::ImeTextSpanUnderlineStyle::kSolid, Color::kBlack,
      Color::kBlack);

  EXPECT_EQ(2u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, SetMarkerActiveTest) {
  SetBodyContent("<b>foo</b>");
  auto* b_element = To<Element>(GetDocument().body()->firstChild());
  EphemeralRange ephemeral_range = EphemeralRange::RangeOfContents(*b_element);
  Position start_b_element =
      ToPositionInDOMTree(ephemeral_range.StartPosition());
  Position end_b_element = ToPositionInDOMTree(ephemeral_range.EndPosition());
  const EphemeralRange range(start_b_element, end_b_element);
  // Try to make active a marker that doesn't exist.
  EXPECT_FALSE(MarkerController().SetTextMatchMarkersActive(range, true));

  // Add a marker and try it once more.
  MarkerController().AddTextMatchMarker(
      range, TextMatchMarker::MatchStatus::kInactive);
  EXPECT_EQ(1u, MarkerController().Markers().size());
  EXPECT_TRUE(MarkerController().SetTextMatchMarkersActive(range, true));
}

TEST_F(DocumentMarkerControllerTest, RemoveStartOfMarker) {
  SetBodyContent("<b>abc</b>");
  Node* b_element = GetDocument().body()->firstChild();
  Node* text = b_element->firstChild();

  // Add marker under "abc"
  EphemeralRange marker_range =
      EphemeralRange(Position(text, 0), Position(text, 3));
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Remove markers that overlap "a"
  marker_range = EphemeralRange(Position(text, 0), Position(text, 1));
  GetDocument().Markers().RemoveMarkersInRange(
      marker_range, DocumentMarker::MarkerTypes::All());

  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, RemoveMiddleOfMarker) {
  SetBodyContent("<b>abc</b>");
  Node* b_element = GetDocument().body()->firstChild();
  Node* text = b_element->firstChild();

  // Add marker under "abc"
  EphemeralRange marker_range =
      EphemeralRange(Position(text, 0), Position(text, 3));
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Remove markers that overlap "b"
  marker_range = EphemeralRange(Position(text, 1), Position(text, 2));
  GetDocument().Markers().RemoveMarkersInRange(
      marker_range, DocumentMarker::MarkerTypes::All());

  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, RemoveEndOfMarker) {
  SetBodyContent("<b>abc</b>");
  Node* b_element = GetDocument().body()->firstChild();
  Node* text = b_element->firstChild();

  // Add marker under "abc"
  EphemeralRange marker_range =
      EphemeralRange(Position(text, 0), Position(text, 3));
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Remove markers that overlap "c"
  marker_range = EphemeralRange(Position(text, 2), Position(text, 3));
  GetDocument().Markers().RemoveMarkersInRange(
      marker_range, DocumentMarker::MarkerTypes::All());

  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, RemoveSpellingMarkersUnderWords) {
  SetBodyContent("<div contenteditable>foo</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Add a spelling marker and a text match marker to "foo".
  const EphemeralRange marker_range(Position(text, 0), Position(text, 3));
  MarkerController().AddSpellingMarker(marker_range);
  MarkerController().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  MarkerController().RemoveSpellingMarkersUnderWords({"foo"});

  // RemoveSpellingMarkersUnderWords does not remove text match marker.
  ASSERT_EQ(1u, MarkerController().Markers().size());
  const DocumentMarker& marker = *MarkerController().Markers()[0];
  EXPECT_EQ(0u, marker.StartOffset());
  EXPECT_EQ(3u, marker.EndOffset());
  EXPECT_EQ(DocumentMarker::kTextMatch, marker.GetType());
}

TEST_F(DocumentMarkerControllerTest, RemoveSpellingMarkersUnderAllWords) {
  SetBodyContent("<div contenteditable>foo</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  ASSERT_NE(text->GetLayoutObject(), nullptr);

  const EphemeralRange marker_range(Position(text, 0), Position(text, 3));
  text->GetLayoutObject()->ClearPaintInvalidationFlags();
  MarkerController().AddSpellingMarker(marker_range);
  EXPECT_TRUE(text->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  ASSERT_EQ(1u, MarkerController().Markers().size());

  text->GetLayoutObject()->ClearPaintInvalidationFlags();
  MarkerController().RemoveSpellingMarkersUnderWords({"foo"});
  EXPECT_TRUE(text->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  ASSERT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, RemoveSuggestionMarkerByTag) {
  SetBodyContent("<div contenteditable>foo</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  MarkerController().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 1)),
      SuggestionMarkerProperties());

  ASSERT_EQ(1u, MarkerController().Markers().size());
  auto* marker = To<SuggestionMarker>(MarkerController().Markers()[0].Get());
  MarkerController().RemoveSuggestionMarkerByTag(*To<Text>(text),
                                                 marker->Tag());
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, RemoveSuggestionMarkerByTypeWithRange) {
  SetBodyContent("<div contenteditable>foo</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  EphemeralRange range(Position(text, 0), Position(text, 1));
  MarkerController().AddSuggestionMarker(range, SuggestionMarkerProperties());

  ASSERT_EQ(1u, MarkerController().Markers().size());
  auto* marker = To<SuggestionMarker>(MarkerController().Markers()[0].Get());
  MarkerController().RemoveSuggestionMarkerByType(
      ToEphemeralRangeInFlatTree(range), marker->GetSuggestionType());
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, RemoveSuggestionMarkerByType) {
  SetBodyContent("<div contenteditable>123 456</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Add an autocorrect marker on "123"
  MarkerController().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)),
      SuggestionMarkerProperties::Builder()
          .SetType(SuggestionMarker::SuggestionType::kAutocorrect)
          .Build());
  // Add a misspelling suggestion marker on "123"
  MarkerController().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)),
      SuggestionMarkerProperties::Builder()
          .SetType(SuggestionMarker::SuggestionType::kMisspelling)
          .Build());

  EXPECT_EQ(2u, MarkerController().Markers().size());
  MarkerController().RemoveSuggestionMarkerByType(
      SuggestionMarker::SuggestionType::kAutocorrect);

  EXPECT_EQ(1u, MarkerController().Markers().size());
  EXPECT_EQ(SuggestionMarker::SuggestionType::kMisspelling,
            To<SuggestionMarker>(MarkerController().Markers()[0].Get())
                ->GetSuggestionType());
}

TEST_F(DocumentMarkerControllerTest, RemoveSuggestionMarkerInRangeOnFinish) {
  SetBodyContent("<div contenteditable>foo</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Add a regular suggestion marker, RemoveSuggestionMarkerInRangeOnFinish()
  // should not remove it.
  MarkerController().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 2)),
      SuggestionMarkerProperties());

  ASSERT_EQ(1u, MarkerController().Markers().size());
  MarkerController().RemoveSuggestionMarkerInRangeOnFinish(
      EphemeralRangeInFlatTree(PositionInFlatTree(text, 0),
                               PositionInFlatTree(text, 2)));

  EXPECT_EQ(1u, MarkerController().Markers().size());

  const auto* marker =
      To<SuggestionMarker>(MarkerController().Markers()[0].Get());
  MarkerController().RemoveSuggestionMarkerByTag(*To<Text>(text),
                                                 marker->Tag());
  ASSERT_EQ(0u, MarkerController().Markers().size());

  // Add a suggestion marker which need to be removed after finish composing,
  // RemoveSuggestionMarkerInRangeOnFinish() should remove it.
  MarkerController().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 2)),
      SuggestionMarkerProperties::Builder()
          .SetRemoveOnFinishComposing(true)
          .Build());

  ASSERT_EQ(1u, MarkerController().Markers().size());

  MarkerController().RemoveSuggestionMarkerInRangeOnFinish(
      EphemeralRangeInFlatTree(PositionInFlatTree(text, 0),
                               PositionInFlatTree(text, 2)));
  EXPECT_EQ(0u, MarkerController().Markers().size());
}

TEST_F(DocumentMarkerControllerTest, FirstMarkerIntersectingOffsetRange) {
  SetBodyContent("<div contenteditable>123456789</div>");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  auto* text = To<Text>(div->firstChild());

  // Add a spelling marker on "123"
  MarkerController().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)));

  // Query for a spellcheck marker intersecting "3456"
  const DocumentMarker* const result =
      MarkerController().FirstMarkerIntersectingOffsetRange(
          *text, 2, 6, DocumentMarker::MarkerTypes::Misspelling());

  EXPECT_EQ(DocumentMarker::kSpelling, result->GetType());
  EXPECT_EQ(0u, result->StartOffset());
  EXPECT_EQ(3u, result->EndOffset());
}

TEST_F(DocumentMarkerControllerTest,
       FirstMarkerIntersectingOffsetRange_collapsed) {
  SetBodyContent("<div contenteditable>123456789</div>");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  auto* text = To<Text>(div->firstChild());

  // Add a spelling marker on "123"
  MarkerController().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)));

  // Query for a spellcheck marker containing the position between "1" and "2"
  const DocumentMarker* const result =
      MarkerController().FirstMarkerIntersectingOffsetRange(
          *text, 1, 1, DocumentMarker::MarkerTypes::Misspelling());

  EXPECT_EQ(DocumentMarker::kSpelling, result->GetType());
  EXPECT_EQ(0u, result->StartOffset());
  EXPECT_EQ(3u, result->EndOffset());
}

TEST_F(DocumentMarkerControllerTest, MarkersAroundPosition) {
  SetBodyContent("<div contenteditable>123 456</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Add a spelling marker on "123"
  MarkerController().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)));
  // Add a text match marker on "123"
  MarkerController().AddTextMatchMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)),
      TextMatchMarker::MatchStatus::kInactive);
  // Add a grammar marker on "456"
  MarkerController().AddSpellingMarker(
      EphemeralRange(Position(text, 4), Position(text, 7)));

  // Query for spellcheck markers at the start of "123".
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      result1 = MarkerController().MarkersAroundPosition(
          PositionInFlatTree(text, 0),
          DocumentMarker::MarkerTypes::Misspelling());

  EXPECT_EQ(1u, result1.size());
  EXPECT_EQ(DocumentMarker::kSpelling, result1[0].second->GetType());
  EXPECT_EQ(0u, result1[0].second->StartOffset());
  EXPECT_EQ(3u, result1[0].second->EndOffset());

  // Query for spellcheck markers in the middle of "123".
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      result2 = MarkerController().MarkersAroundPosition(
          PositionInFlatTree(text, 3),
          DocumentMarker::MarkerTypes::Misspelling());

  EXPECT_EQ(1u, result2.size());
  EXPECT_EQ(DocumentMarker::kSpelling, result2[0].second->GetType());
  EXPECT_EQ(0u, result2[0].second->StartOffset());
  EXPECT_EQ(3u, result2[0].second->EndOffset());

  // Query for spellcheck markers at the end of "123".
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      result3 = MarkerController().MarkersAroundPosition(
          PositionInFlatTree(text, 3),
          DocumentMarker::MarkerTypes::Misspelling());

  EXPECT_EQ(1u, result3.size());
  EXPECT_EQ(DocumentMarker::kSpelling, result3[0].second->GetType());
  EXPECT_EQ(0u, result3[0].second->StartOffset());
  EXPECT_EQ(3u, result3[0].second->EndOffset());
}

TEST_F(DocumentMarkerControllerTest, MarkersIntersectingRange) {
  SetBodyContent("<div contenteditable>123456789</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Add a spelling marker on "123"
  MarkerController().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)));
  // Add a text match marker on "456"
  MarkerController().AddTextMatchMarker(
      EphemeralRange(Position(text, 3), Position(text, 6)),
      TextMatchMarker::MatchStatus::kInactive);
  // Add a grammar marker on "789"
  MarkerController().AddSpellingMarker(
      EphemeralRange(Position(text, 6), Position(text, 9)));

  // Query for spellcheck markers intersecting "3456". The text match marker
  // should not be returned, nor should the spelling marker touching the range.
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      results = MarkerController().MarkersIntersectingRange(
          EphemeralRangeInFlatTree(PositionInFlatTree(text, 2),
                                   PositionInFlatTree(text, 6)),
          DocumentMarker::MarkerTypes::Misspelling());

  EXPECT_EQ(1u, results.size());
  EXPECT_EQ(DocumentMarker::kSpelling, results[0].second->GetType());
  EXPECT_EQ(0u, results[0].second->StartOffset());
  EXPECT_EQ(3u, results[0].second->EndOffset());
}

TEST_F(DocumentMarkerControllerTest, MarkersIntersectingCollapsedRange) {
  SetBodyContent("<div contenteditable>123456789</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Add a spelling marker on "123"
  MarkerController().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 3)));

  // Query for spellcheck markers containing the position between "1" and "2"
  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      results = MarkerController().MarkersIntersectingRange(
          EphemeralRangeInFlatTree(PositionInFlatTree(text, 1),
                                   PositionInFlatTree(text, 1)),
          DocumentMarker::MarkerTypes::Misspelling());

  EXPECT_EQ(1u, results.size());
  EXPECT_EQ(DocumentMarker::kSpelling, results[0].second->GetType());
  EXPECT_EQ(0u, results[0].second->StartOffset());
  EXPECT_EQ(3u, results[0].second->EndOffset());
}

TEST_F(DocumentMarkerControllerTest, MarkersIntersectingRangeWithShadowDOM) {
  // Set up some shadow elements in a way we know doesn't work properly when
  // using EphemeralRange instead of EphemeralRangeInFlatTree:
  // <div>not shadow</div>
  // <div> (shadow DOM host)
  //   #shadow-root
  //     <div>shadow1</div>
  //     <div>shadow2</div>
  // Caling MarkersIntersectingRange with an EphemeralRange starting in the
  // "not shadow" text and ending in the "shadow1" text will crash.
  SetBodyContent(
      "<div id=\"not_shadow\">not shadow</div><div id=\"shadow_root\" />");
  ShadowRoot* shadow_root = SetShadowContent(
      "<div id=\"shadow1\">shadow1</div><div id=\"shadow2\">shadow2</div>",
      "shadow_root");

  Element* not_shadow_div =
      GetDocument().QuerySelector(AtomicString("#not_shadow"));
  Node* not_shadow_text = not_shadow_div->firstChild();

  Element* shadow1 = shadow_root->QuerySelector(AtomicString("#shadow1"));
  Node* shadow1_text = shadow1->firstChild();

  MarkerController().AddTextMatchMarker(
      EphemeralRange(Position(not_shadow_text, 0),
                     Position(not_shadow_text, 10)),
      TextMatchMarker::MatchStatus::kInactive);

  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      results = MarkerController().MarkersIntersectingRange(
          EphemeralRangeInFlatTree(PositionInFlatTree(not_shadow_text, 9),
                                   PositionInFlatTree(shadow1_text, 1)),
          DocumentMarker::MarkerTypes::TextMatch());
  EXPECT_EQ(1u, results.size());
}

TEST_F(DocumentMarkerControllerTest, SuggestionMarkersHaveUniqueTags) {
  SetBodyContent("<div contenteditable>foo</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  MarkerController().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 1)),
      SuggestionMarkerProperties());
  MarkerController().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 1)),
      SuggestionMarkerProperties());

  EXPECT_EQ(2u, MarkerController().Markers().size());
  EXPECT_NE(To<SuggestionMarker>(MarkerController().Markers()[0].Get())->Tag(),
            To<SuggestionMarker>(MarkerController().Markers()[1].Get())->Tag());
}

TEST_F(DocumentMarkerControllerTest, HighlightsAreNonOverlappingAndSorted) {
  SetBodyContent("<div>012345678901234567890123456789</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Text* text = To<Text>(div->firstChild());

  HeapVector<Member<AbstractRange>> highlight_ranges;
  Highlight* highlight1 = Highlight::Create(highlight_ranges);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)), "highlight1",
      highlight1);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 10), Position(text, 15)), "highlight1",
      highlight1);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 12), Position(text, 14)), "highlight1",
      highlight1);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 14), Position(text, 20)), "highlight1",
      highlight1);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 25), Position(text, 30)), "highlight1",
      highlight1);

  Highlight* highlight2 = Highlight::Create(highlight_ranges);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)), "highlight2",
      highlight2);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 0), Position(text, 15)), "highlight2",
      highlight2);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 15), Position(text, 30)), "highlight2",
      highlight2);
  MarkerController().AddCustomHighlightMarker(
      EphemeralRange(Position(text, 20), Position(text, 30)), "highlight2",
      highlight2);

  MarkerController().MergeOverlappingMarkers(DocumentMarker::kCustomHighlight);
  DocumentMarkerVector markers = MarkerController().MarkersFor(
      *text, DocumentMarker::MarkerTypes::CustomHighlight());
  EXPECT_EQ(5u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());
  EXPECT_EQ("highlight1", To<CustomHighlightMarker>(markers[0].Get())
                              ->GetHighlightName()
                              .GetString());
  EXPECT_EQ(0u, markers[1]->StartOffset());
  EXPECT_EQ(15u, markers[1]->EndOffset());
  EXPECT_EQ("highlight2", To<CustomHighlightMarker>(markers[1].Get())
                              ->GetHighlightName()
                              .GetString());
  EXPECT_EQ(10u, markers[2]->StartOffset());
  EXPECT_EQ(20u, markers[2]->EndOffset());
  EXPECT_EQ("highlight1", To<CustomHighlightMarker>(markers[2].Get())
                              ->GetHighlightName()
                              .GetString());
  EXPECT_EQ(15u, markers[3]->StartOffset());
  EXPECT_EQ(30u, markers[3]->EndOffset());
  EXPECT_EQ("highlight2", To<CustomHighlightMarker>(markers[3].Get())
                              ->GetHighlightName()
                              .GetString());
  EXPECT_EQ(25u, markers[4]->StartOffset());
  EXPECT_EQ(30u, markers[4]->EndOffset());
  EXPECT_EQ("highlight1", To<CustomHighlightMarker>(markers[4].Get())
                              ->GetHighlightName()
                              .GetString());
}

}  // namespace blink

"""

```