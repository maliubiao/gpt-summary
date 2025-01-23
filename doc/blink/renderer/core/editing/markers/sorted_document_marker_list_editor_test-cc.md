Response:
Let's break down the thought process for analyzing this C++ test file and generating the explanation.

1. **Understand the Goal:** The request is to understand the purpose of the given C++ test file, its relation to web technologies (JavaScript, HTML, CSS), provide examples, explain logical reasoning (input/output), discuss potential user/programming errors, and trace user actions leading to this code.

2. **Identify the Core Functionality:** The file name `sorted_document_marker_list_editor_test.cc` immediately suggests that it's testing a component related to managing a sorted list of "document markers." The `_test.cc` suffix confirms it's a unit test file.

3. **Examine the Includes:**
    * `#include "third_party/blink/renderer/core/editing/markers/sorted_document_marker_list_editor.h"`: This is the crucial include. It tells us the file is testing the `SortedDocumentMarkerListEditor` class.
    * `#include "testing/gtest/include/gtest/gtest.h"`: This indicates the use of the Google Test framework for writing tests.
    * `#include "third_party/blink/renderer/core/editing/markers/text_match_marker.h"`: This reveals that the tests are using `TextMatchMarker` as a concrete type of `DocumentMarker`.

4. **Analyze the Test Structure:** The file defines a test fixture `SortedDocumentMarkerListEditorTest` inheriting from `testing::Test`. This provides a setup for the tests. The `CreateMarker` helper function simplifies the creation of `TextMatchMarker` instances. Each `TEST_F` block defines an individual test case.

5. **Decipher Individual Test Cases:** Go through each `TEST_F` and understand what it's testing. Look for the actions being performed and the assertions (`EXPECT_EQ`, `EXPECT_NE`). For example:
    * `RemoveMarkersEmptyList`: Tests removing markers from an empty list.
    * `RemoveMarkersTouchingEndpoints`: Tests removing markers where the removal range touches the marker boundaries.
    * `ShiftMarkersContentDependent` and `ShiftMarkersContentIndependent`: These are key. They test how markers are adjusted when content around them changes (insertion, deletion, replacement). The "content-dependent" vs. "content-independent" distinction is important and needs to be highlighted.

6. **Connect to Web Technologies:**  This is where we bridge the gap to JavaScript, HTML, and CSS.
    * **Markers and Selection/Text Editing:**  Think about how the browser might use markers. Selection highlighting, find-in-page results, spell-checking suggestions, grammar errors, and even accessibility hints are all possibilities. These directly relate to how users interact with text in a web page (HTML content).
    * **JavaScript Interaction:**  Consider that JavaScript APIs might allow developers to programmatically access or manipulate selections or get information about text ranges. This could involve the underlying marker system.
    * **CSS Styling (Indirectly):** While CSS doesn't directly manipulate markers, it styles the *visual representation* of elements. Markers might influence how things are rendered (e.g., highlighting a matched word).

7. **Formulate Examples:** Based on the connections above, create concrete examples.
    * **Find-in-Page:** A very clear example of text matching and highlighting.
    * **Spell Checking:** Demonstrates markers indicating potential errors.
    * **Grammar Checking:** Similar to spell checking, but for grammatical issues.
    * **Selection Highlighting:**  The browser internally uses mechanisms to track and highlight selections, which could involve markers.

8. **Explain Logical Reasoning (Input/Output):** For a few key tests (especially `ShiftMarkersContentDependent` and `ShiftMarkersContentIndependent`), create simple "before" and "after" scenarios. Visualize the text and the marker positions. This helps to understand the logic being tested. *Initially, I might just think about one or two of these, then realize the value of including more to showcase the different scenarios.*

9. **Identify Potential Errors:** Consider common mistakes developers might make when using or implementing marker-related functionality.
    * **Off-by-one errors:**  Common when dealing with ranges and offsets.
    * **Incorrect handling of edge cases:**  Empty lists, markers at the beginning/end of the text, etc.
    * **Forgetting to update markers:**  If the underlying text changes, markers need to be adjusted.

10. **Trace User Actions (Debugging Clues):** Think about how a user's interaction with a web page could trigger the code being tested.
    * **Typing:** Inserts or deletes text, requiring marker adjustments.
    * **Selecting text:**  Might involve creating or updating selection markers.
    * **Using "Find":**  Clearly triggers the creation of text match markers.
    * **Right-clicking for spell/grammar check:**  Initiates processes that use markers.

11. **Structure the Explanation:** Organize the information logically. Start with the core functionality, then connect to web technologies, provide examples, explain reasoning, discuss errors, and finally trace user actions. Use clear headings and bullet points for readability.

12. **Refine and Review:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check for any jargon that needs clarification. Make sure the examples are easy to understand. *Perhaps I would initially make the connection to web technologies too abstract, and then realize I need to provide more specific and relatable examples.*

By following these steps, combining code analysis with knowledge of web technologies and potential user interactions, we can arrive at a comprehensive explanation like the example provided in the initial prompt. The process involves both top-down (understanding the overall purpose) and bottom-up (examining individual test cases) analysis.
这个文件 `sorted_document_marker_list_editor_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件。它的主要功能是测试 `SortedDocumentMarkerListEditor` 类的各种方法。`SortedDocumentMarkerListEditor` 类的作用是管理和操作一个排序的文档标记（Document Marker）列表。

**具体功能分解:**

1. **测试 `RemoveMarkers` 方法:**
   - 测试从标记列表中移除指定范围内的标记。
   - 覆盖了各种边界情况，例如空列表、移除范围与标记端点重合、移除范围完全包含标记等。

2. **测试 `ShiftMarkersContentDependent` 方法:**
   - 测试当文档内容发生变化（插入、删除、替换）时，如何调整**内容依赖型**标记的位置。
   - 内容依赖型标记的含义是，如果它所标记的内容被修改或删除，则该标记可能需要被移除或失效。

3. **测试 `ShiftMarkersContentIndependent` 方法:**
   - 测试当文档内容发生变化时，如何调整**内容独立型**标记的位置。
   - 内容独立型标记的含义是，即使它所标记的内容被修改，该标记仍然有效，但其起始和结束位置可能需要调整。

4. **测试 `FirstMarkerIntersectingRange` 方法:**
   - 测试查找列表中第一个与给定范围相交的标记。
   - 覆盖了各种相交情况，例如完全不相交、端点接触、部分相交等。

5. **测试 `MarkersIntersectingRange` 方法:**
   - 测试查找列表中所有与给定范围相交的标记。
   - 同样覆盖了各种相交情况。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件本身不包含 JavaScript, HTML 或 CSS 代码，但它测试的 `SortedDocumentMarkerListEditor` 类在 Blink 引擎中被用于实现与这些技术相关的功能。

**举例说明:**

* **JavaScript 和 HTML (文本选择):** 当用户在网页上用鼠标选择一段文本时，浏览器内部会创建表示该选择范围的标记。`SortedDocumentMarkerListEditor` 可以被用来管理这些选择标记。
    * **假设输入:** 用户在 HTML 文档中选择了 "hello world" 中的 "world"。
    * **内部处理:**  Blink 引擎可能会创建一个 `TextMatchMarker` (或其他类型的标记) 来标记从偏移量 6 到 11 的范围。
    * **`SortedDocumentMarkerListEditor` 的作用:**  如果之后用户在 "hello " 和 "world" 之间插入了文本，`SortedDocumentMarkerListEditor` 的 `ShiftMarkersContentIndependent` 方法会被调用来更新选择标记的起始和结束位置，以保持选择的文本仍然是用户期望的那部分。

* **JavaScript 和 HTML (查找功能):** 当用户在浏览器中使用 "查找 (Ctrl+F)" 功能时，浏览器会高亮所有匹配的文本。
    * **假设输入:** 用户在页面上查找 "example"。
    * **内部处理:** Blink 引擎会创建多个 `TextMatchMarker` 来标记所有 "example" 出现的范围，并将状态设置为激活状态（例如，高亮显示）。
    * **`SortedDocumentMarkerListEditor` 的作用:**  `SortedDocumentMarkerListEditor` 可以用来存储和管理这些表示查找结果的标记。如果用户修改了文本，`ShiftMarkersContentDependent` 或 `ShiftMarkersContentIndependent` 方法会被调用来更新或移除不再有效的匹配标记。

* **CSS (样式应用):** 虽然 CSS 不直接操作这些标记，但标记可以影响元素的渲染方式。例如，查找结果的标记可能会触发应用特定的 CSS 样式来高亮显示匹配的文本。

**逻辑推理与假设输入输出:**

**例子：`ShiftMarkersContentIndependent` 测试**

* **假设输入:**
    * 标记列表 `markers` 包含一个标记，起始偏移量为 0，结束偏移量为 10。
    * 调用 `ShiftMarkersContentIndependent(&markers, 0, 5, 4)`，表示从偏移量 0 开始，替换长度为 5 的文本，替换为长度为 4 的文本 (文本变短了)。
* **预期输出:**
    * 标记列表 `markers` 仍然包含一个标记。
    * 该标记的起始偏移量仍然是 0。
    * 该标记的结束偏移量变为 9 (因为内容缩短了 1 个字符)。

**用户或编程常见的使用错误:**

1. **偏移量错误:**  在调用 `RemoveMarkers` 或 `ShiftMarkers...` 方法时，传递错误的起始或结束偏移量可能导致意外的标记被移除或移动。例如，如果一个标记的范围是 [5, 10]，但用户错误地使用范围 [0, 5] 来移除，则该标记不会被移除。

2. **对内容依赖型和内容独立型标记的混淆:**  错误地使用 `ShiftMarkersContentDependent` 来处理应该使用 `ShiftMarkersContentIndependent` 的标记，或反之，会导致标记状态不正确。例如，对于一个表示书签的标记（内容独立型），如果使用 `ShiftMarkersContentDependent` 处理文本插入，可能会导致书签意外消失。

3. **未考虑排序:** `SortedDocumentMarkerListEditor` 假设标记列表是排序的。如果传入的列表未排序，某些方法可能无法正常工作。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者正在调试一个与文本编辑或查找功能相关的 bug，并且怀疑问题可能与文档标记的管理有关。以下是可能的步骤：

1. **用户报告 Bug:** 用户在浏览器中执行某个操作（例如，在查找到的文本中进行编辑），导致查找高亮显示不正确或消失。

2. **开发者重现 Bug:** 开发者尝试按照用户的步骤重现该 bug。

3. **代码审查:** 开发者查看与文本编辑和查找功能相关的代码，可能会发现涉及到 `SortedDocumentMarkerListEditor` 的使用。

4. **怀疑标记管理问题:** 开发者怀疑在文本编辑过程中，文档标记的更新可能存在问题。

5. **查看单元测试:** 为了验证 `SortedDocumentMarkerListEditor` 的行为是否符合预期，开发者会查看相关的单元测试文件，例如 `sorted_document_marker_list_editor_test.cc`。

6. **运行单元测试:** 开发者可以运行这些单元测试来确认 `SortedDocumentMarkerListEditor` 的基本功能是否正常工作。如果某些测试失败，则表明 `SortedDocumentMarkerListEditor` 的实现可能存在 bug。

7. **调试 `SortedDocumentMarkerListEditor` 的实现:** 如果单元测试通过，但 bug 仍然存在，开发者可能需要更深入地调试 `SortedDocumentMarkerListEditor` 类的实现，或者查看其在更高级别的代码中的使用方式。

8. **添加或修改单元测试:** 如果开发者发现了一个新的 bug 或需要覆盖更多的边界情况，他们可能会添加新的测试用例到 `sorted_document_marker_list_editor_test.cc` 文件中。

总而言之，`sorted_document_marker_list_editor_test.cc` 是一个基础的测试文件，用于确保 Blink 引擎中用于管理文档标记的关键组件 `SortedDocumentMarkerListEditor` 的功能正确可靠，这对于诸如文本选择、查找、拼写检查等与用户交互密切的功能至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/markers/sorted_document_marker_list_editor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/editing/markers/sorted_document_marker_list_editor.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/markers/text_match_marker.h"

namespace blink {

class SortedDocumentMarkerListEditorTest : public testing::Test {
 protected:
  DocumentMarker* CreateMarker(unsigned startOffset, unsigned endOffset) {
    return MakeGarbageCollected<TextMatchMarker>(
        startOffset, endOffset, TextMatchMarker::MatchStatus::kInactive);
  }
};

TEST_F(SortedDocumentMarkerListEditorTest, RemoveMarkersEmptyList) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  SortedDocumentMarkerListEditor::RemoveMarkers(&markers, 0, 10);
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest, RemoveMarkersTouchingEndpoints) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));
  markers.push_back(CreateMarker(10, 20));
  markers.push_back(CreateMarker(20, 30));

  SortedDocumentMarkerListEditor::RemoveMarkers(&markers, 10, 10);

  EXPECT_EQ(2u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());

  EXPECT_EQ(20u, markers[1]->StartOffset());
  EXPECT_EQ(30u, markers[1]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       RemoveMarkersOneCharacterIntoInterior) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));
  markers.push_back(CreateMarker(10, 20));
  markers.push_back(CreateMarker(20, 30));

  SortedDocumentMarkerListEditor::RemoveMarkers(&markers, 9, 12);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_ReplaceStartOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 0, 5,
                                                               5);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_ReplaceStartOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  // Replace with shorter text
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0, 5,
                                                                 4);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(9u, markers[0]->EndOffset());

  // Replace with longer text
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0, 4,
                                                                 5);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());

  // Replace with text of same length
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0, 5,
                                                                 5);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_ReplaceContainsStartOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 15));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 0, 10,
                                                               10);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_ReplaceContainsStartOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 15));

  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0,
                                                                 10, 10);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(10u, markers[0]->StartOffset());
  EXPECT_EQ(15u, markers[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_ReplaceEndOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 5, 5,
                                                               5);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_ReplaceEndOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  // Replace with shorter text
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 5, 5,
                                                                 4);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(9u, markers[0]->EndOffset());

  // Replace with longer text
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 5, 4,
                                                                 5);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());

  // Replace with text of same length
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 5, 5,
                                                                 5);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_ReplaceContainsEndOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 5, 10,
                                                               10);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_ReplaceContainsEndOfMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 5,
                                                                 10, 10);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_ReplaceEntireMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 0, 10,
                                                               10);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_ReplaceEntireMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  // Replace with shorter text
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0,
                                                                 10, 9);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(9u, markers[0]->EndOffset());

  // Replace with longer text
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0, 9,
                                                                 10);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());

  // Replace with text of same length
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0,
                                                                 10, 10);

  EXPECT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_ReplaceTextWithMarkerAtBeginning) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 0, 15,
                                                               15);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_ReplaceTextWithMarkerAtBeginning) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0,
                                                                 15, 15);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_ReplaceTextWithMarkerAtEnd) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 15));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 0, 15,
                                                               15);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_ReplaceTextWithMarkerAtEnd) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 15));

  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0,
                                                                 15, 15);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest, ContentDependentMarker_Deletions) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));
  markers.push_back(CreateMarker(15, 20));
  markers.push_back(CreateMarker(20, 25));

  // Delete range containing the end of the second marker, the entire third
  // marker, and the start of the fourth marker
  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 8, 9,
                                                               0);

  EXPECT_EQ(2u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());

  EXPECT_EQ(11u, markers[1]->StartOffset());
  EXPECT_EQ(16u, markers[1]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest, ContentIndependentMarker_Deletions) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));
  markers.push_back(CreateMarker(15, 20));
  markers.push_back(CreateMarker(20, 25));

  // Delete range containing the end of the second marker, the entire third
  // marker, and the start of the fourth marker
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 8, 9,
                                                                 0);

  EXPECT_EQ(4u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());

  EXPECT_EQ(5u, markers[1]->StartOffset());
  EXPECT_EQ(8u, markers[1]->EndOffset());

  EXPECT_EQ(8u, markers[2]->StartOffset());
  EXPECT_EQ(11u, markers[2]->EndOffset());

  EXPECT_EQ(11u, markers[3]->StartOffset());
  EXPECT_EQ(16u, markers[3]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_DeleteExactlyOnMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 0, 10,
                                                               0);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_DeleteExactlyOnMarker) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 10));

  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 0,
                                                                 10, 0);

  EXPECT_EQ(0u, markers.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_InsertInMarkerInterior) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));

  // insert in middle of second marker
  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 7, 0,
                                                               5);

  EXPECT_EQ(2u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());

  EXPECT_EQ(15u, markers[1]->StartOffset());
  EXPECT_EQ(20u, markers[1]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_InsertInMarkerInterior) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));

  // insert in middle of second marker
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 7, 0,
                                                                 5);

  EXPECT_EQ(3u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());

  EXPECT_EQ(5u, markers[1]->StartOffset());
  EXPECT_EQ(15u, markers[1]->EndOffset());

  EXPECT_EQ(15u, markers[2]->StartOffset());
  EXPECT_EQ(20u, markers[2]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentDependentMarker_InsertBetweenMarkers) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));

  // insert before second marker
  SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(&markers, 5, 0,
                                                               5);

  EXPECT_EQ(3u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());

  EXPECT_EQ(10u, markers[1]->StartOffset());
  EXPECT_EQ(15u, markers[1]->EndOffset());

  EXPECT_EQ(15u, markers[2]->StartOffset());
  EXPECT_EQ(20u, markers[2]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       ContentIndependentMarker_InsertBetweenMarkers) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));

  // insert before second marker
  SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(&markers, 5, 0,
                                                                 5);

  EXPECT_EQ(3u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());

  EXPECT_EQ(10u, markers[1]->StartOffset());
  EXPECT_EQ(15u, markers[1]->EndOffset());

  EXPECT_EQ(15u, markers[2]->StartOffset());
  EXPECT_EQ(20u, markers[2]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest, FirstMarkerIntersectingRange_Empty) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));

  DocumentMarker* marker =
      SortedDocumentMarkerListEditor::FirstMarkerIntersectingRange(markers, 10,
                                                                   15);
  EXPECT_EQ(nullptr, marker);
}

TEST_F(SortedDocumentMarkerListEditorTest,
       FirstMarkerIntersectingRange_TouchingAfter) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));

  DocumentMarker* marker =
      SortedDocumentMarkerListEditor::FirstMarkerIntersectingRange(markers, 5,
                                                                   10);
  EXPECT_EQ(nullptr, marker);
}

TEST_F(SortedDocumentMarkerListEditorTest,
       FirstMarkerIntersectingRange_TouchingBefore) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 10));

  DocumentMarker* marker =
      SortedDocumentMarkerListEditor::FirstMarkerIntersectingRange(markers, 0,
                                                                   5);
  EXPECT_EQ(nullptr, marker);
}

TEST_F(SortedDocumentMarkerListEditorTest,
       FirstMarkerIntersectingRange_IntersectingAfter) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 10));

  DocumentMarker* marker =
      SortedDocumentMarkerListEditor::FirstMarkerIntersectingRange(markers, 0,
                                                                   6);
  EXPECT_NE(nullptr, marker);

  EXPECT_EQ(5u, marker->StartOffset());
  EXPECT_EQ(10u, marker->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       FirstMarkerIntersectingRange_IntersectingBefore) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 10));

  DocumentMarker* marker =
      SortedDocumentMarkerListEditor::FirstMarkerIntersectingRange(markers, 9,
                                                                   15);
  EXPECT_NE(nullptr, marker);

  EXPECT_EQ(5u, marker->StartOffset());
  EXPECT_EQ(10u, marker->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       FirstMarkerIntersectingRange_MultipleMarkers) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));
  markers.push_back(CreateMarker(15, 20));
  markers.push_back(CreateMarker(20, 25));

  DocumentMarker* marker =
      SortedDocumentMarkerListEditor::FirstMarkerIntersectingRange(markers, 7,
                                                                   17);
  EXPECT_NE(nullptr, marker);

  EXPECT_EQ(5u, marker->StartOffset());
  EXPECT_EQ(10u, marker->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest, MarkersIntersectingRange_Empty) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));

  SortedDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      SortedDocumentMarkerListEditor::MarkersIntersectingRange(markers, 10, 15);
  EXPECT_EQ(0u, markers_intersecting_range.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       MarkersIntersectingRange_TouchingAfter) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));

  SortedDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      SortedDocumentMarkerListEditor::MarkersIntersectingRange(markers, 5, 10);
  EXPECT_EQ(0u, markers_intersecting_range.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       MarkersIntersectingRange_TouchingBefore) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 10));

  SortedDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      SortedDocumentMarkerListEditor::MarkersIntersectingRange(markers, 0, 5);
  EXPECT_EQ(0u, markers_intersecting_range.size());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       MarkersIntersectingRange_IntersectingAfter) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 10));

  SortedDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      SortedDocumentMarkerListEditor::MarkersIntersectingRange(markers, 0, 6);
  EXPECT_EQ(1u, markers_intersecting_range.size());

  EXPECT_EQ(5u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       MarkersIntersectingRange_IntersectingBefore) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 10));

  SortedDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      SortedDocumentMarkerListEditor::MarkersIntersectingRange(markers, 9, 15);
  EXPECT_EQ(1u, markers_intersecting_range.size());

  EXPECT_EQ(5u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       MarkersIntersectingRange_CollapsedRange) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(5, 10));

  SortedDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      SortedDocumentMarkerListEditor::MarkersIntersectingRange(markers, 7, 7);
  EXPECT_EQ(1u, markers_intersecting_range.size());

  EXPECT_EQ(5u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[0]->EndOffset());
}

TEST_F(SortedDocumentMarkerListEditorTest,
       MarkersIntersectingRange_MultipleMarkers) {
  SortedDocumentMarkerListEditor::MarkerList markers;
  markers.push_back(CreateMarker(0, 5));
  markers.push_back(CreateMarker(5, 10));
  markers.push_back(CreateMarker(10, 15));
  markers.push_back(CreateMarker(15, 20));
  markers.push_back(CreateMarker(20, 25));

  SortedDocumentMarkerListEditor::MarkerList markers_intersecting_range =
      SortedDocumentMarkerListEditor::MarkersIntersectingRange(markers, 7, 17);
  EXPECT_EQ(3u, markers_intersecting_range.size());

  EXPECT_EQ(5u, markers_intersecting_range[0]->StartOffset());
  EXPECT_EQ(10u, markers_intersecting_range[0]->EndOffset());

  EXPECT_EQ(10u, markers_intersecting_range[1]->StartOffset());
  EXPECT_EQ(15u, markers_intersecting_range[1]->EndOffset());

  EXPECT_EQ(15u, markers_intersecting_range[2]->StartOffset());
  EXPECT_EQ(20u, markers_intersecting_range[2]->EndOffset());
}

}  // namespace blink
```