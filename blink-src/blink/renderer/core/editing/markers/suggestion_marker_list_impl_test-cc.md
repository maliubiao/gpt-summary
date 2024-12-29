Response:
My thought process for analyzing the C++ test file went through these stages:

1. **Identify the Core Purpose:** The filename `suggestion_marker_list_impl_test.cc` immediately suggests this file contains unit tests for a class named `SuggestionMarkerListImpl`. The `.cc` extension confirms it's C++ source code.

2. **Understand the Tested Class:**  Reading through the `#include` directives reveals dependencies on classes like `SuggestionMarker`, `SuggestionMarkerProperties`, and `DocumentMarker`. This hints that `SuggestionMarkerListImpl` is likely responsible for managing a list of `SuggestionMarker` objects, which represent some kind of suggestions within a document.

3. **Analyze the Test Structure:**  The presence of `TEST_F` macros indicates the use of the Google Test framework. Each `TEST_F` function tests a specific aspect of `SuggestionMarkerListImpl`. The test fixture `SuggestionMarkerListImplTest` provides a controlled environment for these tests, including the instantiation of the `marker_list_` under test.

4. **Decipher Individual Tests:** I went through each `TEST_F` function and tried to understand what it's verifying:
    * `MarkerType`: Checks if the list correctly identifies its marker type as `DocumentMarker::kSuggestion`.
    * `AddOverlapping`: Tests how the list handles adding markers that have overlapping ranges. It verifies the correct number of markers and their start/end offsets after adding and sorting.
    * `ShiftMarkersForSuggestionReplacement_*`:  These tests examine the behavior of a `ShiftMarkers` method when a suggestion is applied (likely involving text replacement). They check if markers are correctly shifted, removed, or kept based on their position relative to the replacement range. The `SuggestionMarkerReplacementScope` likely signals that a suggestion-related operation is in progress.
    * `ShiftMarkersForNonSuggestionEditingOperation_*`:  These tests investigate the `ShiftMarkers` method's behavior during regular text editing operations (insertions and deletions). They differentiate between alphanumeric and non-alphanumeric character insertions/deletions and their impact on markers. The tests focus on how markers are adjusted or removed when the underlying text changes.
    * `RemoveMarkerByTag_*`: Tests the functionality of removing markers based on a unique tag.
    * `RemoveMarkerByType_*`: Tests the functionality of removing markers based on their suggestion type (e.g., `kAutocorrect`).

5. **Identify Connections to Web Technologies:**  The term "suggestion" immediately links to features found in web browsers' text editing capabilities, such as spell checking, grammar suggestions, and auto-correction.

6. **Infer Relationships with JavaScript, HTML, and CSS:**
    * **JavaScript:**  JavaScript code running in a web page could trigger actions that lead to the creation or modification of these suggestion markers. For instance, a spell-checking feature implemented in JavaScript might identify potential errors and request the browser to create suggestion markers. JavaScript could also listen for events related to applying suggestions.
    * **HTML:**  The text content within HTML elements is where these suggestions would be relevant. The markers define ranges within this text. The editing actions that trigger these tests are likely performed on HTML text content.
    * **CSS:** While less direct, CSS could be involved in visually representing these suggestions to the user (e.g., underlining misspelled words). However, this file primarily deals with the *data model* of the suggestions, not their visual presentation.

7. **Formulate Examples and Scenarios:** Based on the test names and their logic, I constructed scenarios that illustrate how a user might interact with the browser to trigger the tested functionalities. This involved imagining user typing, making corrections, and how the underlying marker system would respond.

8. **Consider Potential Errors:** I thought about common mistakes developers might make when working with this kind of system, such as incorrect offset calculations, failing to handle overlapping markers, or not properly updating markers during text edits. The tests themselves highlight areas where errors could occur.

9. **Outline Debugging Steps:** I considered how a developer might use these tests to debug issues. If a bug related to suggestion markers arises, these tests would be the first place to look to see if the expected behavior is being violated.

10. **Structure the Output:** Finally, I organized the information into clear categories (Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors, Debugging) to make the explanation comprehensive and easy to understand.

Essentially, I approached the problem by dissecting the code, understanding its purpose within the larger Blink/Chromium context, connecting it to user-facing features, and then synthesizing that information into a coherent explanation.
这个文件 `suggestion_marker_list_impl_test.cc` 是 Chromium Blink 引擎中用于测试 `SuggestionMarkerListImpl` 类的单元测试文件。  单元测试的目的是验证代码的特定单元（这里是 `SuggestionMarkerListImpl` 类）是否按照预期工作。

**功能列举:**

1. **测试 `SuggestionMarkerListImpl` 的基本功能:**
   - **添加标记 (Add):** 测试添加多个可能重叠的 `SuggestionMarker` 对象到列表中，并验证列表是否正确存储和排序这些标记。
   - **获取标记 (GetMarkers):** 测试从列表中获取所有标记，并验证获取到的标记数量和属性是否正确。
   - **标记类型 (MarkerType):** 验证 `SuggestionMarkerListImpl` 正确报告其标记类型为 `DocumentMarker::kSuggestion`。
   - **根据标签移除标记 (RemoveMarkerByTag):** 测试根据唯一的标签移除特定标记的功能。
   - **根据类型移除标记 (RemoveMarkerByType):** 测试根据标记的建议类型移除标记的功能。

2. **测试在文本编辑操作后标记的更新和移除:**
   - **针对建议替换的标记移动 (ShiftMarkersForSuggestionReplacement):** 模拟应用建议替换文本的情况，测试 `ShiftMarkers` 方法是否正确更新或移除受影响的标记。这包括测试各种边界情况，例如标记与替换范围重叠、包含或被包含在替换范围内的情形。
   - **针对非建议编辑操作的标记移动 (ShiftMarkersForNonSuggestionEditingOperation):** 模拟用户进行普通文本编辑操作（插入、删除）的情况，测试 `ShiftMarkers` 方法是否正确更新或移除受影响的标记。 这细分了不同的插入和删除场景，包括：
     - 在中间删除字符
     - 在中间插入字符
     - 在开头添加字母、数字、非字母数字字符 (包括单字节和 surrogate pair)
     - 在结尾添加字母、数字、非字母数字字符 (包括单字节和 surrogate pair)

**与 JavaScript, HTML, CSS 的关系举例:**

这个测试文件本身是 C++ 代码，不直接包含 JavaScript, HTML 或 CSS 代码。但是，它测试的 `SuggestionMarkerListImpl` 类是 Blink 渲染引擎的一部分，该引擎负责将 HTML、CSS 和 JavaScript 转换为用户可见的网页。  `SuggestionMarkerListImpl` 管理的建议标记直接关联到用户在浏览器中看到的文本编辑功能，例如拼写检查、语法建议等。

**举例说明:**

* **HTML:** 当用户在一个 `contenteditable` 的 HTML 元素中输入文本时，Blink 引擎可能会进行拼写或语法检查。 如果发现错误，就会创建一个或多个 `SuggestionMarker` 对象来标记错误的范围。 `SuggestionMarkerListImpl` 负责存储和管理这些标记。
   ```html
   <div contenteditable="true">Thiss is a example.</div>
   ```
   在这个例子中，"Thiss" 可能会被标记为一个拼写错误的建议。

* **JavaScript:** JavaScript 可以通过 DOM API 与 `contenteditable` 元素交互，并可能触发创建或移除建议标记的操作。 例如，一个 JavaScript 库可能会实现自定义的拼写检查功能，并调用 Blink 引擎的接口来添加建议标记。
   ```javascript
   const editableDiv = document.querySelector('div');
   // 一些 JavaScript 代码可能会调用 Blink 接口来添加针对 "Thiss" 的建议标记
   ```

* **CSS:** CSS 可以用于控制建议标记的视觉呈现方式。例如，可以使用不同的下划线样式或颜色来突出显示拼写错误或语法建议。
   ```css
   /* 可能的 CSS 样式，用于显示拼写错误建议 */
   ::spelling-error {
     text-decoration: underline red wavy;
   }
   ```

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `AddOverlapping` 测试):**

添加以下 `SuggestionMarker` 对象到 `marker_list_` 中，顺序任意：
- [40, 50]
- [10, 40]
- [20, 50]
- [10, 30]
- [10, 50]
- [30, 50]
- [30, 40]
- [10, 20]
- [20, 40]
- [20, 30]

**预期输出:**

调用 `GetMarkers()` 方法后，返回的 `DocumentMarkerVector` 将包含 10 个 `SuggestionMarker` 对象，并按照起始偏移量和结束偏移量排序（由 `compare_markers` 函数定义）。具体顺序和偏移量如下：

- [10, 20]
- [10, 30]
- [10, 40]
- [10, 50]
- [20, 30]
- [20, 40]
- [20, 50]
- [30, 40]
- [30, 50]
- [40, 50]

**假设输入 (针对 `ShiftMarkersForSuggestionReplacement_MarkersUpdateProperly` 测试):**

初始 `marker_list_` 包含以下 `SuggestionMarker` 对象：
- [10, 20]
- [0, 10]
- [0, 11]
- [20, 30]
- [19, 30]
- [11, 19]
- [9, 21]

然后调用 `ShiftMarkers("", 10, 10, 5)`，模拟将从偏移量 10 开始的 10 个字符替换为 5 个字符。

**预期输出:**

`marker_list_` 将包含以下 `SuggestionMarker` 对象（已更新偏移量和移除部分重叠的标记）：
- [0, 10]  (保持不变)
- [9, 16]  (偏移量调整：起始偏移量不变，结束偏移量 21 - (10 - 5) = 16)
- [10, 15] (偏移量调整：起始偏移量 10 变为 10，结束偏移量 20 变为 15)
- [15, 25] (偏移量调整：起始偏移量 20 变为 10 + (20-10) - (10-5) = 15，结束偏移量 30 变为 20 + (30-20) - (10-5) = 25)

标记 [0, 11]，[19, 30]，[11, 19] 被移除，因为它们部分或完全位于被替换的范围内。

**用户或编程常见的使用错误举例:**

1. **偏移量计算错误:** 在创建或操作标记时，错误的起始或结束偏移量会导致标记错误地覆盖文本范围。
   * **例子:**  程序员在 JavaScript 中计算拼写错误的范围时，可能因为字符串索引错误而导致偏移量不准确。

2. **未能处理重叠标记:**  在某些情况下，可能会有多个建议标记覆盖相同的文本范围。如果代码没有正确处理这种情况，可能会导致显示或操作建议时出现问题。
   * **例子:**  一个文本可能既有拼写错误又有语法错误，导致两个重叠的建议标记。

3. **在文本编辑后未能更新标记:**  当用户编辑文本时，相关的建议标记的偏移量需要同步更新。如果更新逻辑有误，标记可能会指向错误的文本位置，或者根本不再存在。
   * **例子:** 用户删除了一个拼写错误的词语的一部分，但相关的拼写建议标记没有被正确移除或调整。

4. **错误地假设标记的唯一性:**  虽然某些类型的标记可能有唯一的约束（例如，一个拼写错误通常只有一个建议操作），但不能假设所有类型的建议标记都是唯一的。可能会有多个不同类型的建议覆盖相同的范围。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个支持拼写检查的 `contenteditable` 元素中输入了 "teh"。

1. **用户输入:** 用户在浏览器中打开一个网页，该网页包含一个允许编辑的文本区域（例如，使用 `<textarea>` 标签或者带有 `contenteditable` 属性的 `div` 标签）。 用户开始输入文本，敲击键盘输入 "teh"。

2. **拼写检查触发:**  Blink 渲染引擎中的拼写检查模块（通常在用户停止输入或输入空格后触发）会分析输入的文本。

3. **识别拼写错误:** 拼写检查模块识别出 "teh" 是一个可能的拼写错误，并建议更正为 "the"。

4. **创建 `SuggestionMarker`:**  Blink 引擎会创建一个 `SuggestionMarker` 对象，用于标记 "teh" 的范围。这个标记会包含一些属性，例如建议的更正文本 ("the") 和建议的类型 (拼写检查)。

5. **添加到 `SuggestionMarkerListImpl`:**  新创建的 `SuggestionMarker` 对象会被添加到与该文本区域关联的 `SuggestionMarkerListImpl` 实例中。

6. **视觉呈现:** 浏览器可能会使用 CSS 样式来高亮显示 "teh"，例如添加一个红色的波浪下划线，以提示用户这是一个拼写错误。

7. **用户交互 (可选):** 当用户点击或悬停在被标记的文本 "teh" 上时，浏览器可能会显示建议的更正 ("the")。

8. **应用建议 (可选):** 如果用户选择应用建议，Blink 引擎会执行文本替换操作（将 "teh" 替换为 "the"）。

9. **`ShiftMarkers` 调用:**  在执行文本替换操作后，`SuggestionMarkerListImpl` 的 `ShiftMarkers` 方法会被调用，以更新或移除可能与被替换文本范围重叠的其他建议标记。

**调试线索:**

如果 `suggestion_marker_list_impl_test.cc` 中的某个测试失败了，这可能意味着在上述用户操作流程中的某个环节出现了问题。例如：

* **`AddOverlapping` 测试失败:**  可能意味着在添加多个拼写或语法错误标记时，列表的存储或排序逻辑有误。这可能导致在用户界面上显示错误的标记或建议。
* **`ShiftMarkersForSuggestionReplacement` 测试失败:**  可能意味着在用户应用拼写或语法建议后，其他相关的标记没有被正确更新或移除。这可能导致旧的错误标记仍然存在，或者新的标记没有被正确创建。
* **`ShiftMarkersForNonSuggestionEditingOperation` 测试失败:**  可能意味着当用户进行常规的文本编辑操作时，建议标记的更新逻辑有误。这可能导致标记指向错误的文本位置，或者在用户删除错误后标记仍然存在。

通过仔细分析失败的测试用例，开发者可以定位到 Blink 引擎中处理建议标记的具体代码逻辑，并找出潜在的 bug。 这些测试覆盖了各种边界情况和用户操作场景，有助于确保建议标记功能的正确性和稳定性。

Prompt: 
```
这是目录为blink/renderer/core/editing/markers/suggestion_marker_list_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_list_impl.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/markers/marker_test_utilities.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_properties.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_replacement_scope.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"

namespace blink {

class SuggestionMarkerListImplTest : public testing::Test {
 protected:
  SuggestionMarkerListImplTest()
      : marker_list_(MakeGarbageCollected<SuggestionMarkerListImpl>()) {}

  SuggestionMarker* CreateMarker(unsigned start_offset, unsigned end_offset) {
    return MakeGarbageCollected<SuggestionMarker>(start_offset, end_offset,
                                                  SuggestionMarkerProperties());
  }

  SuggestionMarker* CreateMarker(unsigned start_offset,
                                 unsigned end_offset,
                                 const SuggestionMarkerProperties& properties) {
    return MakeGarbageCollected<SuggestionMarker>(start_offset, end_offset,
                                                  properties);
  }

  Persistent<SuggestionMarkerListImpl> marker_list_;
};

TEST_F(SuggestionMarkerListImplTest, MarkerType) {
  EXPECT_EQ(DocumentMarker::kSuggestion, marker_list_->MarkerType());
}

TEST_F(SuggestionMarkerListImplTest, AddOverlapping) {
  // Add some overlapping markers in an arbitrary order and verify that the
  // list stores them properly
  marker_list_->Add(CreateMarker(40, 50));
  marker_list_->Add(CreateMarker(10, 40));
  marker_list_->Add(CreateMarker(20, 50));
  marker_list_->Add(CreateMarker(10, 30));
  marker_list_->Add(CreateMarker(10, 50));
  marker_list_->Add(CreateMarker(30, 50));
  marker_list_->Add(CreateMarker(30, 40));
  marker_list_->Add(CreateMarker(10, 20));
  marker_list_->Add(CreateMarker(20, 40));
  marker_list_->Add(CreateMarker(20, 30));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  std::sort(markers.begin(), markers.end(), compare_markers);

  EXPECT_EQ(10u, markers.size());

  EXPECT_EQ(10u, markers[0]->StartOffset());
  EXPECT_EQ(20u, markers[0]->EndOffset());

  EXPECT_EQ(10u, markers[1]->StartOffset());
  EXPECT_EQ(30u, markers[1]->EndOffset());

  EXPECT_EQ(10u, markers[2]->StartOffset());
  EXPECT_EQ(40u, markers[2]->EndOffset());

  EXPECT_EQ(10u, markers[3]->StartOffset());
  EXPECT_EQ(50u, markers[3]->EndOffset());

  EXPECT_EQ(20u, markers[4]->StartOffset());
  EXPECT_EQ(30u, markers[4]->EndOffset());

  EXPECT_EQ(20u, markers[5]->StartOffset());
  EXPECT_EQ(40u, markers[5]->EndOffset());

  EXPECT_EQ(20u, markers[6]->StartOffset());
  EXPECT_EQ(50u, markers[6]->EndOffset());

  EXPECT_EQ(30u, markers[7]->StartOffset());
  EXPECT_EQ(40u, markers[7]->EndOffset());

  EXPECT_EQ(30u, markers[8]->StartOffset());
  EXPECT_EQ(50u, markers[8]->EndOffset());

  EXPECT_EQ(40u, markers[9]->StartOffset());
  EXPECT_EQ(50u, markers[9]->EndOffset());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForSuggestionReplacement_ReturnsFalseWhenNoShift) {
  marker_list_->Add(CreateMarker(0, 10));

  {
    SuggestionMarkerReplacementScope scope;
    // Replace range 0 to 10 with a ten character string.
    // Text is ignored for suggestion replacement, so we can just pass an empty
    // string.
    EXPECT_FALSE(marker_list_->ShiftMarkers("", 0, 10, 10));
  }

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(1u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForSuggestionReplacement_MarkersUpdateProperly) {
  // Marker with suggestion to apply.
  // Should be kept (and shifted).
  marker_list_->Add(CreateMarker(10, 20));

  // Marker touching start of replacement range.
  // Should be kept.
  marker_list_->Add(CreateMarker(0, 10));

  // Marker partially overlapping start of replacement range.
  // Should be removed,
  marker_list_->Add(CreateMarker(0, 11));

  // Marker touching end of replacement range.
  // Should be kept (and shifted).
  marker_list_->Add(CreateMarker(20, 30));

  // Marker partially overlapping end of replacement range
  // Should be removed.
  marker_list_->Add(CreateMarker(19, 30));

  // Marker contained inside replacement range
  // Should be removed.
  marker_list_->Add(CreateMarker(11, 19));

  // Marker containing replacement range
  // Should be kept (and shifted).
  marker_list_->Add(CreateMarker(9, 21));

  {
    SuggestionMarkerReplacementScope scope;
    // Replace range 10 to 20 with a five character string.
    // Text is ignored for suggestion replacement, so we can just pass an empty
    // string.
    EXPECT_TRUE(marker_list_->ShiftMarkers("", 10, 10, 5));
  }

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  std::sort(markers.begin(), markers.end(), compare_markers);

  EXPECT_EQ(4u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(10u, markers[0]->EndOffset());

  EXPECT_EQ(9u, markers[1]->StartOffset());
  EXPECT_EQ(16u, markers[1]->EndOffset());

  EXPECT_EQ(10u, markers[2]->StartOffset());
  EXPECT_EQ(15u, markers[2]->EndOffset());

  EXPECT_EQ(15u, markers[3]->StartOffset());
  EXPECT_EQ(25u, markers[3]->EndOffset());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_DeleteFromMiddle) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_TRUE(marker_list_->ShiftMarkers("hello", 2, 1, 0));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_InsertIntoMiddle) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_TRUE(marker_list_->ShiftMarkers("hello", 2, 0, 1));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_PrependLetter) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_TRUE(marker_list_->ShiftMarkers("ahello", 0, 0, 1));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(
    SuggestionMarkerListImplTest,
    ShiftMarkersForNonSuggestionEditingOperation_PrependSurrogatePairLetter) {
  marker_list_->Add(CreateMarker(0, 5));

  // Prepending MATHEMATICAL SCRIPT CAPITAL C
  EXPECT_TRUE(marker_list_->ShiftMarkers(u"\U0001d49ehello", 0, 0, 2));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_PrependDigit) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_TRUE(marker_list_->ShiftMarkers("0hello", 0, 0, 1));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_PrependSurrogatePairDigit) {
  marker_list_->Add(CreateMarker(0, 5));

  // Prepending MATHEMATICAL DOUBLE-STRUCK DIGIT ONE
  EXPECT_TRUE(marker_list_->ShiftMarkers(u"\U0001d7d9hello", 0, 0, 2));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_PrependNonAlphanumeric) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_TRUE(marker_list_->ShiftMarkers(".hello", 0, 0, 1));

  DocumentMarkerVector markers = marker_list_->GetMarkers();

  EXPECT_EQ(1u, markers.size());

  EXPECT_EQ(1u, markers[0]->StartOffset());
  EXPECT_EQ(6u, markers[0]->EndOffset());
}

TEST_F(
    SuggestionMarkerListImplTest,
    ShiftMarkersForNonSuggestionEditingOperation_PrependSurrogatePairNonAlphanumeric) {
  marker_list_->Add(CreateMarker(0, 5));

  // Prepending FACE WITH TEARS OF JOY
  EXPECT_TRUE(marker_list_->ShiftMarkers(u"\U0001f602hello", 0, 0, 2));

  DocumentMarkerVector markers = marker_list_->GetMarkers();

  EXPECT_EQ(1u, markers.size());

  EXPECT_EQ(2u, markers[0]->StartOffset());
  EXPECT_EQ(7u, markers[0]->EndOffset());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_AppendLetter) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_TRUE(marker_list_->ShiftMarkers("helloa", 5, 0, 1));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_AppendSurrogatePairLetter) {
  marker_list_->Add(CreateMarker(0, 5));

  // Appending MATHEMATICAL SCRIPT CAPITAL C
  EXPECT_TRUE(marker_list_->ShiftMarkers(u"hello\U0001d49e", 5, 0, 2));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_AppendDigit) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_TRUE(marker_list_->ShiftMarkers("hello0", 5, 0, 1));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_AppendSurrogatePairDigit) {
  marker_list_->Add(CreateMarker(0, 5));

  // Appending MATHEMATICAL DOUBLE-STRUCK DIGIT ONE
  EXPECT_TRUE(marker_list_->ShiftMarkers(u"hello\U0001d7d9", 5, 0, 2));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(0u, markers.size());
}

TEST_F(SuggestionMarkerListImplTest,
       ShiftMarkersForNonSuggestionEditingOperation_AppendNonAlphanumeric) {
  marker_list_->Add(CreateMarker(0, 5));

  EXPECT_FALSE(marker_list_->ShiftMarkers("hello.", 5, 0, 1));

  DocumentMarkerVector markers = marker_list_->GetMarkers();

  EXPECT_EQ(1u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());
}

TEST_F(
    SuggestionMarkerListImplTest,
    ShiftMarkersForNonSuggestionEditingOperation_AppendSurrogatePairNonAlphanumeric) {
  marker_list_->Add(CreateMarker(0, 5));

  // Appending FACE WITH TEARS OF JOY
  EXPECT_FALSE(marker_list_->ShiftMarkers(u"hello\U0001f602", 5, 0, 2));

  DocumentMarkerVector markers = marker_list_->GetMarkers();

  EXPECT_EQ(1u, markers.size());

  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());
}

TEST_F(SuggestionMarkerListImplTest, RemoveMarkerByTag_NotFound) {
  SuggestionMarker* const marker = CreateMarker(0, 10);
  marker_list_->Add(marker);

  EXPECT_FALSE(marker_list_->RemoveMarkerByTag(marker->Tag() + 1));
}

TEST_F(SuggestionMarkerListImplTest, RemoveMarkerByTag_Found) {
  SuggestionMarker* const marker1 = CreateMarker(0, 10);
  SuggestionMarker* const marker2 = CreateMarker(10, 20);

  marker_list_->Add(marker1);
  marker_list_->Add(marker2);

  EXPECT_TRUE(marker_list_->RemoveMarkerByTag(marker1->Tag()));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(1u, markers.size());

  EXPECT_EQ(10u, markers[0]->StartOffset());
  EXPECT_EQ(20u, markers[0]->EndOffset());
}

TEST_F(SuggestionMarkerListImplTest, RemoveMarkerByType_NotFound) {
  SuggestionMarker* const marker = CreateMarker(0, 10);
  marker_list_->Add(marker);
  EXPECT_TRUE(marker->GetSuggestionType() !=
              SuggestionMarker::SuggestionType::kAutocorrect);
  EXPECT_FALSE(marker_list_->RemoveMarkerByType(
      SuggestionMarker::SuggestionType::kAutocorrect));
}

TEST_F(SuggestionMarkerListImplTest, RemoveMarkerByType_Found) {
  SuggestionMarker* const marker1 = CreateMarker(0, 10);
  SuggestionMarker* const marker2 =
      CreateMarker(10, 20,
                   SuggestionMarkerProperties::Builder()
                       .SetType(SuggestionMarker::SuggestionType::kAutocorrect)
                       .Build());

  marker_list_->Add(marker1);
  marker_list_->Add(marker2);

  EXPECT_TRUE(marker1->GetSuggestionType() !=
              SuggestionMarker::SuggestionType::kAutocorrect);
  EXPECT_TRUE(marker_list_->RemoveMarkerByType(marker1->GetSuggestionType()));

  DocumentMarkerVector markers = marker_list_->GetMarkers();
  EXPECT_EQ(1u, markers.size());

  EXPECT_EQ(10u, markers[0]->StartOffset());
  EXPECT_EQ(20u, markers[0]->EndOffset());
}

}  // namespace blink

"""

```