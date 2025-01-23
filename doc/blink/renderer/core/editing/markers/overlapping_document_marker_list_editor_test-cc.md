Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understanding the Core Purpose:** The filename `overlapping_document_marker_list_editor_test.cc` immediately suggests this file is a test suite for a class named `OverlappingDocumentMarkerListEditor`. The "overlapping" part hints that the editor deals with scenarios where document markers might have overlapping spans. The `_test.cc` suffix is a standard convention for C++ unit tests.

2. **Identifying Key Components:**  Scanning the `#include` directives and the namespace `blink` reveals the context: This is part of the Chromium Blink rendering engine, specifically within the `core/editing/markers` directory. The included headers tell us about:
    * `OverlappingDocumentMarkerListEditor.h`: The class being tested.
    * `testing/gtest/include/gtest/gtest.h`: The Google Test framework used for writing the tests.
    * `marker_test_utilities.h`: Likely contains helper functions for creating or manipulating markers in tests.
    * `suggestion_marker.h`, `suggestion_marker_list_impl.h`, `suggestion_marker_properties.h`:  Indicates that the markers being manipulated are likely related to suggestions (like spellcheck or grammar suggestions).
    * `platform/heap/persistent.h`:  Deals with memory management within Blink.

3. **Analyzing the Test Fixture:**  The `OverlappingDocumentMarkerListEditorTest` class inherits from `testing::Test`. This is the standard way to group related tests in Google Test. The constructor initializes a `marker_list_`, which is a `Persistent` (Blink's smart pointer) to a `HeapVector` of `DocumentMarker`s. This tells us that the `OverlappingDocumentMarkerListEditor` likely operates on a list of `DocumentMarker` objects. The `CreateMarker` helper function simplifies the creation of `SuggestionMarker` instances for testing.

4. **Dissecting Individual Tests:**  Each `TEST_F` macro defines an individual test case. The naming of the tests is crucial:
    * `AddMarkersOverlapping`: Tests the functionality of adding markers that overlap each other.
    * `MoveMarkers`: Tests moving markers based on a certain offset.
    * `RemoveMarkersNestedOverlap`, `RemoveMarkersTouchingEndpoints`, `RemoveMarkersOneCharacterIntoInterior`: Test different scenarios for removing markers, focusing on overlapping and boundary conditions.
    * `ShiftMarkers_*`:  A series of tests focusing on how markers are adjusted when text is inserted or deleted around them. These are further broken down by the position of the edit relative to the marker (start, end, within, etc.).
    * `MarkersIntersectingRange_*`: Tests the ability to find markers that intersect a given range.

5. **Connecting to Web Technologies (JavaScript, HTML, CSS):** This is where we infer how these low-level C++ components relate to the user-facing web. `DocumentMarker`s are used to represent things like spellcheck errors, grammar suggestions, find-in-page matches, etc. These are all features that interact with the document content (HTML) and can be styled (CSS). JavaScript is the scripting language that often triggers or interacts with these features. Examples:
    * **Spellcheck:**  When a user types in an HTML `<textarea>` or a `contenteditable` element, the browser's spellcheck functionality (implemented in C++) uses `DocumentMarker`s to highlight misspelled words.
    * **Find in Page:** When a user presses Ctrl+F and searches for text, the browser uses `DocumentMarker`s to highlight the matching occurrences in the HTML document. JavaScript could be used to programmatically trigger or interact with the find functionality.
    * **Grammar Suggestions:** Similar to spellcheck, grammar checking would also use `DocumentMarker`s.
    * **Accessibility Features:** Assistive technologies might use information from `DocumentMarker`s to provide feedback to users.

6. **Inferring Logic and Assumptions:** For each test, we can infer the expected behavior of the `OverlappingDocumentMarkerListEditor`. For example, in `AddMarkersOverlapping`, the assumption is that the editor will correctly insert and maintain the order of overlapping markers in the list. The `EXPECT_EQ` assertions verify these assumptions.

7. **Identifying Potential User Errors and Debugging Clues:**  The tests themselves highlight potential edge cases and error scenarios that developers need to consider. For example, the `ShiftMarkers` tests cover various scenarios of text insertion and deletion, showing how the marker positions should be adjusted to maintain their relevance. If a user reports that spellcheck highlighting is incorrect after editing text, this type of test would be relevant for debugging.

8. **Tracing User Actions:**  To understand how a user might end up triggering the code being tested, we need to consider the user interactions that lead to the creation or manipulation of `DocumentMarker`s:
    * Typing text in an editable area.
    * Using the "Find in Page" feature.
    * Right-clicking on text to access spellcheck/grammar suggestions.
    * Potentially through JavaScript APIs that programmatically interact with the document.

By following these steps, we can systematically analyze the C++ test file and understand its purpose, its connections to web technologies, and its implications for user experience and debugging. The focus is on understanding the *what*, *why*, and *how* of the code in the context of a larger system.
这是一个C++的测试文件，其路径 `blink/renderer/core/editing/markers/overlapping_document_marker_list_editor_test.cc` 揭示了它的功能是 **测试 `OverlappingDocumentMarkerListEditor` 类**。 这个类很可能负责管理和编辑一个文档中可能重叠的标记（markers）列表。

让我们更详细地分析一下它的功能以及与Web技术的关系：

**功能列表:**

1. **添加重叠的标记 (Add Markers Overlapping):** 测试向标记列表中添加多个可能在位置上重叠的标记，并验证列表是否正确地包含了所有标记，并且标记的起始和结束位置是否正确。
2. **移动标记 (Move Markers):** 测试将满足特定条件的标记从一个列表移动到另一个列表的功能。这涉及到根据标记的起始和结束位置与给定的偏移量进行比较。
3. **移除标记 (Remove Markers):** 测试从标记列表中移除位于指定范围内的标记。测试了多种移除场景，包括嵌套重叠、端点接触以及在标记内部的情况。
4. **移动标记 (Shift Markers):**  这是一个更复杂的测试集，测试当文档内容发生变化（插入或删除文本）时，如何调整标记的位置。它覆盖了各种情况，例如：
    * 替换标记的起始部分、包含起始部分的文本。
    * 替换标记的结束部分、包含结束部分的文本。
    * 替换整个标记。
    * 替换与标记起始或结束位置重合的文本。
    * 删除操作，包括删除部分标记、包含整个标记的范围。
    * 插入操作，包括在标记内部插入和在标记之间插入。
5. **查找与范围相交的标记 (Markers Intersecting Range):** 测试查找与给定范围相交的所有标记的功能。测试了各种相交情况，包括接触起始/结束点、完全包含、被包含以及没有相交标记的情况。

**与 JavaScript, HTML, CSS 的关系:**

`DocumentMarker` 是 Blink 引擎中用于表示文档中特定范围的视觉或语义标记的抽象。 这些标记可以与以下 Web 技术的功能相关联：

* **拼写检查和语法检查 (Spellcheck and Grammar Check):**
    * **例子:** 当用户在 HTML 的 `<textarea>` 或 `contenteditable` 元素中输入文本时，浏览器可能会使用 `DocumentMarker` 来标记拼写错误或语法问题。这些标记的位置（起始和结束偏移量）与错误单词或短语在文本中的位置对应。
    * **用户操作:** 用户输入错误单词 "teh"。
    * **假设输入:** `marker_list_` 当前为空。
    * **输出:** `OverlappingDocumentMarkerListEditor::AddMarker` 会添加一个新的 `DocumentMarker`，其起始和结束偏移量对应 "teh" 在文本中的位置。
    * **CSS:** 浏览器可以使用 CSS 来渲染这些标记，例如使用红色波浪线来突出显示拼写错误。
    * **JavaScript:** JavaScript 可以访问和操作这些标记，例如在用户右键点击错误单词时显示建议。

* **查找功能 (Find in Page):**
    * **例子:** 当用户使用浏览器的 "查找" 功能 (Ctrl+F 或 Cmd+F) 时，Blink 引擎会使用 `DocumentMarker` 来高亮显示所有匹配的文本。
    * **用户操作:** 用户在页面中查找 "example"。
    * **假设输入:** 页面中有多个 "example" 实例。
    * **输出:** `OverlappingDocumentMarkerListEditor::AddMarker` 会为每个 "example" 实例添加一个 `DocumentMarker`，记录其在文档中的位置。
    * **CSS:** 可以使用 CSS 为这些标记添加背景色，以便在页面上突出显示。

* **文本选择 (Text Selection):**
    * 虽然 `DocumentMarker` 主要用于非选择性的标记，但选择操作可能会影响现有标记的位置。 `ShiftMarkers` 测试中模拟的文本插入和删除操作就反映了这种情况。
    * **用户操作:** 用户选中一段文本并删除。
    * **假设输入:** `marker_list_` 中存在一些标记。删除操作发生在其中一个标记之前。
    * **输出:** `OverlappingDocumentMarkerListEditor::ShiftMarkers` 会调整受影响标记的起始和结束偏移量，使其反映文本删除后的新位置。

* **内容编辑 (Content Editing):**
    * 任何对 `contenteditable` 元素内容的修改都可能触发 `OverlappingDocumentMarkerListEditor` 的功能。
    * **用户操作:** 用户在一个 `contenteditable` 的 `<div>` 中插入一段新的文本。
    * **假设输入:** `marker_list_` 中存在一些标记。插入操作发生在其中一个标记的中间。
    * **输出:** `OverlappingDocumentMarkerListEditor::ShiftMarkers` 会更新该标记的结束偏移量，以适应插入的新文本。

**逻辑推理、假设输入与输出:**

以 `TEST_F(OverlappingDocumentMarkerListEditorTest, AddMarkersOverlapping)` 为例：

* **假设输入:**  一个空的 `marker_list_`，以及一系列要添加的标记，这些标记的起始和结束位置如下：
    * (40, 60)
    * (0, 30)
    * (70, 100)
    * (0, 20)
    * (0, 40)
    * (45, 70)
    * (35, 65)
    * (90, 100)
* **输出:** `marker_list_` 将包含 8 个 `DocumentMarker` 对象，并且它们的顺序和起始/结束偏移量与测试代码中的 `EXPECT_EQ` 断言一致：
    * (0, 30)
    * (0, 20)
    * (0, 40)
    * (35, 65)
    * (40, 60)
    * (45, 70)
    * (70, 100)
    * (90, 100)
    * **注意:**  添加顺序可能不保证，但最终列表的内容和排序（基于起始位置）是确定的。

以 `TEST_F(OverlappingDocumentMarkerListEditorTest, MoveMarkers)` 为例：

* **假设输入:** `marker_list_` 包含多个标记，偏移量 cutoff 为 11。
* **输出:**
    * 原 `marker_list_` 中起始和结束偏移量都小于 11 的标记将被移动到 `dst_list`。
    * 原 `marker_list_` 中起始偏移量小于 11 但结束偏移量大于等于 11 的标记将被**移除**。
    * 原 `marker_list_` 中起始偏移量大于等于 11 的标记将保留在 `marker_list_` 中。
    * `dst_list` 将包含被移动的标记。

**用户或编程常见的使用错误:**

* **添加标记时没有考虑重叠:** 如果代码在添加标记时没有正确处理重叠的情况，可能会导致一些标记被忽略或错误地覆盖。 `AddMarkersOverlapping` 测试就验证了 `OverlappingDocumentMarkerListEditor` 能否正确处理这种情况。
* **在编辑文本后没有更新标记位置:** 当用户插入或删除文本时，与这些编辑相关的标记的位置也需要相应地调整。 如果没有正确更新，会导致标记指向错误的文本范围，例如拼写错误的下划线出现在正确的单词上。 `ShiftMarkers` 测试覆盖了这类场景，确保编辑器能够正确地移动和调整标记。
* **移除标记时范围不准确:**  如果移除标记的范围计算不正确，可能会错误地移除不应该被移除的标记，或者留下应该被移除的标记。 `RemoveMarkers` 的各种测试用例旨在验证在不同情况下移除操作的正确性。
* **移动标记的条件判断错误:** 在 `MoveMarkers` 测试中，如果移动标记的条件判断（基于偏移量）有误，可能会导致错误的标记被移动或遗漏。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在可编辑区域输入文本 (HTML `<textarea>` 或 `contenteditable` 元素):**  当用户输入文本时，浏览器可能会启动拼写检查或语法检查功能。
2. **拼写/语法检查器发现错误:** 浏览器底层的拼写或语法检查模块（可能是 Hunspell 或其他引擎）会识别出错误。
3. **创建 `DocumentMarker` 对象:**  Blink 引擎会创建 `DocumentMarker` 对象来标记这些错误。 这些标记的起始和结束偏移量对应错误文本的位置。
4. **调用 `OverlappingDocumentMarkerListEditor::AddMarker`:** 为了管理这些标记，`OverlappingDocumentMarkerListEditor::AddMarker` 函数会被调用，将新的错误标记添加到文档的标记列表中。由于用户可能连续输入，新的错误标记可能会与现有的标记重叠，因此需要这个编辑器来处理。
5. **用户继续编辑文本 (插入、删除、替换):** 当用户编辑文本时，例如修正拼写错误或修改句子结构，文档的内容会发生变化。
6. **调用 `OverlappingDocumentMarkerListEditor::ShiftMarkers` 或 `RemoveMarkers`:**  为了保持标记与文档内容的同步，Blink 引擎会调用 `OverlappingDocumentMarkerListEditor::ShiftMarkers` 来调整现有标记的位置（如果编辑发生在标记之前或之后），或者调用 `RemoveMarkers` 来移除与编辑区域重叠的标记。
7. **用户执行 "查找" 操作:** 当用户使用 "查找" 功能时，浏览器会搜索匹配的文本。
8. **创建 `DocumentMarker` 并调用 `AddMarker`:**  对于找到的每个匹配项，Blink 引擎会创建一个 `DocumentMarker` 并调用 `OverlappingDocumentMarkerListEditor::AddMarker` 将其添加到标记列表中，以便高亮显示。
9. **用户移动光标或进行文本选择:**  虽然这些操作本身不直接调用这个编辑器，但它们可能会触发重新评估标记的需求，例如当光标移动到有拼写错误的单词上时，可能需要显示上下文菜单。

因此，这个测试文件所覆盖的代码功能是浏览器编辑和渲染流程中非常核心的部分，它确保了文档标记（例如拼写错误提示、查找结果高亮等）能够正确地被管理和更新，从而为用户提供准确的反馈和功能。

### 提示词
```
这是目录为blink/renderer/core/editing/markers/overlapping_document_marker_list_editor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/markers/overlapping_document_marker_list_editor.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/markers/marker_test_utilities.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_list_impl.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_properties.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"

namespace blink {

class OverlappingDocumentMarkerListEditorTest : public testing::Test {
 public:
  OverlappingDocumentMarkerListEditorTest()
      : marker_list_(
            MakeGarbageCollected<HeapVector<Member<DocumentMarker>>>()) {}

 protected:
  DocumentMarker* CreateMarker(unsigned start_offset, unsigned end_offset) {
    return MakeGarbageCollected<SuggestionMarker>(start_offset, end_offset,
                                                  SuggestionMarkerProperties());
  }

  Persistent<HeapVector<Member<DocumentMarker>>> marker_list_;
};

TEST_F(OverlappingDocumentMarkerListEditorTest, AddMarkersOverlapping) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(40, 60));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 30));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(70, 100));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 20));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 40));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(45, 70));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(35, 65));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(90, 100));

  EXPECT_EQ(8u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(30u, marker_list_->at(0)->EndOffset());
  EXPECT_EQ(0u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(20u, marker_list_->at(1)->EndOffset());
  EXPECT_EQ(0u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(40u, marker_list_->at(2)->EndOffset());
  EXPECT_EQ(35u, marker_list_->at(3)->StartOffset());
  EXPECT_EQ(65u, marker_list_->at(3)->EndOffset());
  EXPECT_EQ(40u, marker_list_->at(4)->StartOffset());
  EXPECT_EQ(60u, marker_list_->at(4)->EndOffset());
  EXPECT_EQ(45u, marker_list_->at(5)->StartOffset());
  EXPECT_EQ(70u, marker_list_->at(5)->EndOffset());
  EXPECT_EQ(70u, marker_list_->at(6)->StartOffset());
  EXPECT_EQ(100u, marker_list_->at(6)->EndOffset());
  EXPECT_EQ(90u, marker_list_->at(7)->StartOffset());
  EXPECT_EQ(100u, marker_list_->at(7)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest, MoveMarkers) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(30, 40));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 30));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 40));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 20));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 40));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(20, 40));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(20, 30));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 30));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 20));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(11, 21));

  DocumentMarkerList* dst_list =
      MakeGarbageCollected<SuggestionMarkerListImpl>();
  // The markers with start and end offset < 11 should be moved to dst_list.
  // Markers that start before 11 and end at 11 or later should be removed.
  // Markers that start at 11 or later should not be moved.
  OverlappingDocumentMarkerListEditor::MoveMarkers(marker_list_, 11, dst_list);

  EXPECT_EQ(4u, marker_list_->size());

  EXPECT_EQ(11u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(21u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(20u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(40u, marker_list_->at(1)->EndOffset());

  EXPECT_EQ(20u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(30u, marker_list_->at(2)->EndOffset());

  EXPECT_EQ(30u, marker_list_->at(3)->StartOffset());
  EXPECT_EQ(40u, marker_list_->at(3)->EndOffset());

  DocumentMarkerVector dst_list_markers = dst_list->GetMarkers();

  // Markers
  EXPECT_EQ(1u, dst_list_markers.size());

  EXPECT_EQ(0u, dst_list_markers[0]->StartOffset());
  EXPECT_EQ(10u, dst_list_markers[0]->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest, RemoveMarkersNestedOverlap) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 30));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(15, 20));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(20, 30));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(30, 40));

  EXPECT_TRUE(
      OverlappingDocumentMarkerListEditor::RemoveMarkers(marker_list_, 20, 10));

  EXPECT_EQ(3u, marker_list_->size());

  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(15u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(20u, marker_list_->at(1)->EndOffset());

  EXPECT_EQ(30u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(40u, marker_list_->at(2)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       RemoveMarkersTouchingEndpoints) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(30, 40));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(40, 50));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 20));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(20, 30));

  EXPECT_TRUE(
      OverlappingDocumentMarkerListEditor::RemoveMarkers(marker_list_, 20, 10));

  EXPECT_EQ(4u, marker_list_->size());

  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(10u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(20u, marker_list_->at(1)->EndOffset());

  EXPECT_EQ(30u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(40u, marker_list_->at(2)->EndOffset());

  EXPECT_EQ(40u, marker_list_->at(3)->StartOffset());
  EXPECT_EQ(50u, marker_list_->at(3)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       RemoveMarkersOneCharacterIntoInterior) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(30, 40));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(40, 50));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 20));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(20, 30));

  EXPECT_TRUE(
      OverlappingDocumentMarkerListEditor::RemoveMarkers(marker_list_, 19, 12));

  EXPECT_EQ(2u, marker_list_->size());

  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(40u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(50u, marker_list_->at(1)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_ReplaceStartOfMarker) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));

  // Replace with shorter text
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 5, 4);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(9u, marker_list_->at(0)->EndOffset());

  // Replace with longer text
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 4, 5);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());

  // Replace with text of same length
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 5, 5);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_ReplaceContainsStartOfMarker) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 15));

  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 10, 10);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(10u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(15u, marker_list_->at(0)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_ReplaceEndOfMarker) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));

  // Replace with shorter text
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 5, 5, 4);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(9u, marker_list_->at(0)->EndOffset());

  // Replace with longer text
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 5, 4, 5);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());

  // Replace with text of same length
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 5, 5, 5);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_ReplaceContainsEndOfMarker) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));

  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 5, 10, 10);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(5u, marker_list_->at(0)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_ReplaceEntireMarker) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));

  // Replace with shorter text
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 10, 9);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(9u, marker_list_->at(0)->EndOffset());

  // Replace with longer text
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 9, 10);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());

  // Replace with text of same length
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 10, 10);

  EXPECT_EQ(1u, marker_list_->size());
  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(0)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_ReplaceTextWithMarkerAtBeginning) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));

  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 15, 15);

  EXPECT_EQ(0u, marker_list_->size());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_ReplaceTextWithMarkerAtEnd) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 15));

  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 15, 15);

  EXPECT_EQ(0u, marker_list_->size());
}

TEST_F(OverlappingDocumentMarkerListEditorTest, ShiftMarkers_Deletions) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 5));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 15));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(15, 20));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(20, 25));

  // Delete range containing the end of the second marker, the entire third
  // marker, and the start of the fourth marker
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 8, 9, 0);

  EXPECT_EQ(4u, marker_list_->size());

  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(5u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(5u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(8u, marker_list_->at(1)->EndOffset());

  EXPECT_EQ(8u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(11u, marker_list_->at(2)->EndOffset());

  EXPECT_EQ(11u, marker_list_->at(3)->StartOffset());
  EXPECT_EQ(16u, marker_list_->at(3)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_DeletionWithinNested) {
  // A marker that overlaps the range with markers that do not overlap
  // nested within it.
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 35));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(7, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(15, 25));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(30, 32));

  // Delete range overlapping the outermost marker and containing the
  // third marker.
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 15, 10, 0);

  EXPECT_EQ(3u, marker_list_->size());

  EXPECT_EQ(5u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(25u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(7u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(10u, marker_list_->at(1)->EndOffset());

  EXPECT_EQ(20u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(22u, marker_list_->at(2)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_DeleteExactlyOnMarker) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));

  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 0, 10, 0);

  EXPECT_EQ(0u, marker_list_->size());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_InsertInMarkerInterior) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 5));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 15));

  // insert in middle of second marker
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 7, 0, 5);

  EXPECT_EQ(3u, marker_list_->size());

  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(5u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(5u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(15u, marker_list_->at(1)->EndOffset());

  EXPECT_EQ(15u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(20u, marker_list_->at(2)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       ShiftMarkers_InsertBetweenMarkers) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 5));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(10, 15));

  // insert before second marker
  OverlappingDocumentMarkerListEditor::ShiftMarkers(marker_list_, 5, 0, 5);

  EXPECT_EQ(3u, marker_list_->size());

  EXPECT_EQ(0u, marker_list_->at(0)->StartOffset());
  EXPECT_EQ(5u, marker_list_->at(0)->EndOffset());

  EXPECT_EQ(10u, marker_list_->at(1)->StartOffset());
  EXPECT_EQ(15u, marker_list_->at(1)->EndOffset());

  EXPECT_EQ(15u, marker_list_->at(2)->StartOffset());
  EXPECT_EQ(20u, marker_list_->at(2)->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       MarkersIntersectingRange_RangeContainingNoMarkers) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));

  OverlappingDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      OverlappingDocumentMarkerListEditor::MarkersIntersectingRange(
          *marker_list_, 10, 15);
  EXPECT_EQ(0u, markers_intersecting_range.size());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       MarkersIntersectingRange_TouchingStart) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 9));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(1, 9));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(1, 10));

  OverlappingDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      OverlappingDocumentMarkerListEditor::MarkersIntersectingRange(
          *marker_list_, 0, 1);

  EXPECT_EQ(2u, markers_intersecting_range.size());

  EXPECT_EQ(0u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(9u, markers_intersecting_range[0]->EndOffset());

  EXPECT_EQ(0u, markers_intersecting_range[1]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[1]->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       MarkersIntersectingRange_TouchingEnd) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 9));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(1, 9));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(0, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(1, 10));

  OverlappingDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      OverlappingDocumentMarkerListEditor::MarkersIntersectingRange(
          *marker_list_, 9, 10);

  EXPECT_EQ(2u, markers_intersecting_range.size());

  EXPECT_EQ(0u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[0]->EndOffset());

  EXPECT_EQ(1u, markers_intersecting_range[1]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[1]->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       MarkersIntersectingRange_CollapsedRange) {
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 10));

  OverlappingDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      OverlappingDocumentMarkerListEditor::MarkersIntersectingRange(
          *marker_list_, 7, 7);
  EXPECT_EQ(1u, markers_intersecting_range.size());

  EXPECT_EQ(5u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[0]->EndOffset());
}

TEST_F(OverlappingDocumentMarkerListEditorTest,
       MarkersIntersectingRange_NestedMarkers) {
  // A marker that overlaps the range with markers that do not overlap
  // nested within it.
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(5, 35));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(7, 10));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(15, 25));
  OverlappingDocumentMarkerListEditor::AddMarker(marker_list_,
                                                 CreateMarker(30, 32));

  OverlappingDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      OverlappingDocumentMarkerListEditor::MarkersIntersectingRange(
          *marker_list_, 15, 25);
  EXPECT_EQ(2u, markers_intersecting_range.size());

  EXPECT_EQ(5u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(35u, markers_intersecting_range[0]->EndOffset());
  EXPECT_EQ(15u, markers_intersecting_range[1]->StartOffset());
  EXPECT_EQ(25u, markers_intersecting_range[1]->EndOffset());
}

}  // namespace blink
```