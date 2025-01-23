Response:
Let's break down the thought process for analyzing this test file.

1. **Understand the Core Purpose:** The first step is to read the initial comments and the file name (`static_range_test.cc`). This immediately tells us this file contains tests specifically for the `StaticRange` class in Blink. The "test" suffix is a clear indicator.

2. **Identify Key Classes and Includes:**  Look at the included header files. These reveal the classes `StaticRange` interacts with:
    * `StaticRange.h`:  The class under test.
    * `Range.h`:  A related DOM concept. The tests seem to be converting `StaticRange` to `Range`.
    * DOM nodes (`Element`, `Text`, `NodeList`):  Indicates `StaticRange` deals with parts of the DOM tree.
    * HTML specific elements (`HTMLBodyElement`, `HTMLDocument`, etc.):  Confirms it's testing in the context of HTML.
    * Testing frameworks (`gtest/gtest.h`): Confirms it's a unit test file.
    * V8 bindings (`v8_binding_for_testing.h`): Suggests interactions with JavaScript or the underlying JavaScript engine.

3. **Analyze the Test Fixture (`StaticRangeTest`):**  The `StaticRangeTest` class sets up the testing environment. Key observations:
    * `SetUp()`:  Creates a basic HTML document (`<html><body></body></html>`). This is the foundation for all the tests.
    * `GetDocument()`: A helper method to access the created document.

4. **Examine Individual Test Cases (Functions starting with `TEST_F`):** This is where the specific functionality of `StaticRange` is tested. For each test:
    * **Name:** The name usually hints at the scenario being tested (e.g., `SplitTextNodeRangeWithinText`, `SplitTextNodeRangeOutsideText`).
    * **Setup:** How is the DOM structure being initialized within the test? (e.g., setting `innerHTML`).
    * **Creating `StaticRange` instances:** Pay attention to the arguments used to create `StaticRange` objects (container nodes and offsets). This tells us what parts of the DOM are being targeted.
    * **Converting to `Range`:** The tests consistently convert `StaticRange` to `Range` using `toRange()`. This suggests a primary function of `StaticRange` might be to represent a fixed selection that can be converted to a live `Range`.
    * **Performing DOM manipulations:** Look for actions that modify the DOM structure *after* the `StaticRange` objects are created (e.g., `old_text->splitText()`).
    * **Assertions (`EXPECT_...`):** These are the core of the tests. They verify the expected behavior:
        * How does the `Range` object change after DOM manipulation?
        * Crucially, how does the `StaticRange` object *not* change? This is the key differentiator between `StaticRange` and `Range`.
    * **`InvalidToRange` Test:** This test specifically focuses on what happens when the underlying DOM structure is changed in a way that makes the `StaticRange` invalid. It verifies that converting an invalid `StaticRange` to a `Range` throws an exception.

5. **Identify the Core Functionality of `StaticRange`:** Based on the tests, we can deduce the main purpose of `StaticRange`:
    * **Immutable Representation:** It captures a specific section of the DOM at a particular point in time. Unlike a `Range`, it doesn't dynamically update when the DOM changes.
    * **Conversion to `Range`:** It can be converted to a live `Range` object. This allows for operations that require a live range.
    * **Maintaining Integrity:** It's designed to become "invalid" if the underlying DOM structure is modified in a way that its boundaries no longer make sense.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  The `StaticRange` API is exposed to JavaScript. Developers can create `StaticRange` objects using JavaScript and interact with them. The tests involving `toRange()` are directly relevant to this, as JavaScript can call this method.
    * **HTML:** `StaticRange` operates on HTML DOM elements. The test setup explicitly creates HTML structures. The concept of selections in HTML (for copy/paste, highlighting, etc.) is related.
    * **CSS:** While not directly tested here, CSS can influence the layout and rendering of the elements within a `StaticRange`. However, `StaticRange` itself is primarily concerned with the DOM structure, not the visual presentation.

7. **Infer Logical Reasoning and Examples:**  The tests provide concrete examples of how `StaticRange` behaves. We can generalize from these:
    * **Input/Output:**  Consider the state of the DOM and the parameters used to create the `StaticRange` as input. The output is the state of the `Range` object after conversion and whether the `StaticRange` remains unchanged.
    * **User Errors:**  Trying to use a `StaticRange` after the DOM has been significantly altered (making its boundaries invalid) is a common error. The `InvalidToRange` test highlights this.

8. **Trace User Operations:**  Think about how a user's actions in a web browser might lead to the creation and use of `StaticRange`:
    * **Selecting Text:** When a user selects text on a webpage, the browser internally represents this selection. `StaticRange` could be used to capture the *initial* state of this selection.
    * **Copying Text:** When copying, the selected range is determined, and `StaticRange` could be involved in preserving the original selection boundaries.
    * **Using JavaScript APIs:** JavaScript code can directly create and manipulate ranges and potentially static ranges using APIs like `document.createRange()` or selection APIs.

9. **Debugging Clues:** The tests themselves serve as excellent debugging clues. If a bug related to selections or ranges arises, these tests can be run to see if the expected behavior of `StaticRange` is being violated. The specific scenarios in the tests (splitting text nodes inside and outside the range) are common edge cases to consider.

10. **Refine and Organize:** Finally, structure the analysis logically, starting with the overall purpose and drilling down into specifics. Use clear language and provide concrete examples.

By following these steps, we can thoroughly understand the purpose, functionality, and context of the `static_range_test.cc` file.
这个文件 `blink/renderer/core/dom/static_range_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `StaticRange` 类的行为和功能是否符合预期**。

`StaticRange` 是一个表示文档中不可变的区域的类。与 `Range` 对象不同，`StaticRange` 在其边界节点或偏移量因 DOM 更改而发生变化时 **不会自动更新**。

让我们详细列举一下它的功能和相关性：

**1. 测试 `StaticRange` 的基本创建和属性访问:**

   - 文件中创建了多个 `StaticRange` 对象，并使用 `EXPECT_EQ` 等断言来验证其 `startContainer`, `startOffset`, `endContainer`, `endOffset` 等属性是否被正确设置。

   ```c++
   auto* static_range04 = MakeGarbageCollected<StaticRange>(
       GetDocument(), old_text, 0u, old_text, 4u);
   EXPECT_EQ(old_text, static_range04->startContainer());
   EXPECT_EQ(0u, static_range04->startOffset());
   EXPECT_EQ(old_text, static_range04->endContainer());
   EXPECT_EQ(4u, static_range04->endOffset());
   ```

**2. 测试 `StaticRange` 与 `Range` 之间的转换:**

   - `StaticRange` 提供了 `toRange()` 方法将其转换为一个可变的 `Range` 对象。测试用例验证了转换后的 `Range` 对象是否正确反映了 `StaticRange` 的边界。

   ```c++
   Range* range04 = static_range04->toRange(ASSERT_NO_EXCEPTION);
   EXPECT_EQ(old_text, range04->startContainer());
   EXPECT_EQ(0u, range04->startOffset());
   EXPECT_EQ(old_text, range04->endContainer());
   EXPECT_EQ(4u, range04->endOffset());
   ```

**3. 测试 DOM 结构变化对 `StaticRange` 和 `Range` 的影响:**

   - **核心功能：验证 `StaticRange` 的不可变性**。测试用例会先创建一个 `StaticRange` 对象，然后修改 DOM 结构（例如使用 `splitText` 分割文本节点）。
   - 随后，测试用例会断言：
     - **`Range` 对象会随着 DOM 的变化而更新其边界**。
     - **`StaticRange` 对象的边界保持不变**，即使其原始边界在 DOM 改变后变得无效。

   **举例说明 (与 JavaScript, HTML 关系):**

   假设 HTML 中有如下文本节点：`<div>Hello World</div>`

   ```html
   <div>Hello World</div>
   ```

   JavaScript 代码可能先创建一个覆盖整个文本节点的 `StaticRange`：

   ```javascript
   const div = document.querySelector('div');
   const textNode = div.firstChild;
   const staticRange = new StaticRange({
       startContainer: textNode,
       startOffset: 0,
       endContainer: textNode,
       endOffset: textNode.textContent.length // 11
   });
   ```

   然后，JavaScript 代码修改了文本节点：

   ```javascript
   textNode.textContent = 'Hello New World';
   ```

   - **`Range` 的行为:** 如果之前从 `staticRange` 创建了一个 `Range` 对象，那么这个 `Range` 对象的边界可能会根据浏览器的实现进行调整，以反映新的文本节点内容。
   - **`StaticRange` 的行为:**  `staticRange` 仍然会指向原始的文本节点和偏移量 (0 到 11)，即使该文本节点的内容已经改变。这意味着 `staticRange.endOffset` 仍然是 11，但此时文本节点的长度可能是 15。

**4. 测试无效的 `StaticRange` 转换到 `Range` 的情况:**

   - `InvalidToRange` 测试用例模拟了 DOM 结构发生变化，使得 `StaticRange` 的边界不再有效的情况（例如，其结束偏移量超出了文本节点的长度）。
   - 它验证了在这种情况下，尝试将 `StaticRange` 转换为 `Range` 会抛出异常。

**逻辑推理和假设输入/输出 (基于 `SplitTextNodeRangeWithinText` 测试用例):**

**假设输入:**

- HTML 结构: `<body>1234</body>`
- 创建一个 `StaticRange` `static_range04`，起始于文本节点 "1234" 的偏移量 0，结束于偏移量 4。
- 创建一个 `StaticRange` `static_range24`，起始于文本节点 "1234" 的偏移量 2，结束于偏移量 4。
- 对文本节点 "1234" 在偏移量 2 处进行 `splitText` 操作。

**预期输出:**

- `static_range04` 保持不变：`startContainer` 为原始文本节点，`startOffset` 为 0，`endContainer` 为原始文本节点，`endOffset` 为 4。
- `static_range24` 保持不变：`startContainer` 为原始文本节点，`startOffset` 为 2，`endContainer` 为原始文本节点，`endOffset` 为 4。
- 将 `static_range04` 转换为 `Range` 后，`Range` 的 `endContainer` 会变为新的文本节点，`endOffset` 会变为 2。
- 将 `static_range24` 转换为 `Range` 后，`Range` 的 `startContainer` 仍然是原始文本节点，`startOffset` 为 2，`endContainer` 会变为新的文本节点，`endOffset` 会变为 2。

**用户或编程常见的使用错误 (基于 `InvalidToRange` 测试用例):**

- **错误:** 在保存了一个 `StaticRange` 对象后，程序修改了 DOM 结构，使得 `StaticRange` 的边界不再有效，然后尝试将该 `StaticRange` 转换为 `Range` 并进行操作。

- **举例:** 用户可能在 JavaScript 中保存了用户选中文本的 `StaticRange`，然后页面上的某些脚本删除了选中文本的一部分。之后，尝试使用之前保存的 `StaticRange` 可能会导致错误。

  ```javascript
  let myStaticRange;

  function onTextSelected() {
      const selection = window.getSelection();
      if (selection.rangeCount > 0) {
          myStaticRange = new StaticRange(selection.getRangeAt(0));
          console.log("StaticRange saved:", myStaticRange);
      }
  }

  function modifyText() {
      const div = document.querySelector('div');
      div.textContent = 'New Text'; // 这可能使之前保存的 StaticRange 无效
  }

  function useStaticRange() {
      if (myStaticRange) {
          try {
              const range = myStaticRange.toRange(); // 如果 DOM 已被修改，这里可能抛出异常
              console.log("Converted StaticRange to Range:", range);
              // 对 range 进行操作
          } catch (error) {
              console.error("Error converting StaticRange:", error);
          }
      }
  }
  ```

**用户操作如何一步步地到达这里，作为调试线索:**

1. **用户在网页上进行文本选择:** 当用户在浏览器中拖动鼠标选择文本时，浏览器内部会创建一个 `Selection` 对象，其中包含了表示所选区域的 `Range` 对象。
2. **JavaScript 代码获取选择:**  网页上的 JavaScript 代码可以使用 `window.getSelection()` 获取当前的 `Selection` 对象。
3. **创建 `StaticRange` (可能):**  为了保存用户选择的快照，Blink 引擎的内部代码或者某些 JavaScript API 的实现可能会基于当前的 `Range` 创建一个 `StaticRange` 对象。
4. **DOM 发生变化:** 在用户选择文本之后，网页的 DOM 结构可能由于各种原因发生变化，例如：
   - 用户通过编辑器修改了文本。
   - JavaScript 代码动态更新了页面内容。
   - 网页加载了新的内容。
5. **尝试使用之前的 `StaticRange`:**  如果系统尝试使用之前创建的 `StaticRange` 对象，可能会触发与 `static_range_test.cc` 中测试的类似场景，例如尝试将其转换为 `Range`。

**调试线索:**

- 如果在 Blink 渲染引擎中涉及到用户选择、复制粘贴、或者某些需要记录 DOM 区域的功能出现 Bug，可以查看是否涉及到 `StaticRange` 的使用。
- 当涉及到 DOM 结构变化后，之前保存的区域信息是否仍然有效时，`StaticRange` 的行为是关键的。
- 观察在 DOM 变化前后，与 `StaticRange` 相关的属性值和转换行为，可以帮助定位问题。
- 该测试文件中的用例，特别是关于 `splitText` 的测试，暗示了在文本节点被分割等操作后，`StaticRange` 的行为特性是需要重点关注的。

总而言之，`blink/renderer/core/dom/static_range_test.cc` 是一个确保 `StaticRange` 类功能正确性的重要测试文件，它揭示了 `StaticRange` 在 DOM 结构变化时的关键特性——不可变性，以及与可变的 `Range` 对象之间的转换关系。理解这个测试文件有助于理解 Blink 引擎如何处理文档中的静态区域表示，并能帮助开发者避免因 DOM 变化而导致的与范围相关的错误。

### 提示词
```
这是目录为blink/renderer/core/dom/static_range_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/static_range.h"

#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class StaticRangeTest : public testing::Test {
 protected:
  void SetUp() override;

  HTMLDocument& GetDocument() const;

 private:
  test::TaskEnvironment task_environment_;
  ScopedNullExecutionContext execution_context_;
  Persistent<HTMLDocument> document_;
};

void StaticRangeTest::SetUp() {
  document_ =
      HTMLDocument::CreateForTest(execution_context_.GetExecutionContext());
  auto* html = MakeGarbageCollected<HTMLHtmlElement>(*document_);
  html->AppendChild(MakeGarbageCollected<HTMLBodyElement>(*document_));
  document_->AppendChild(html);
}

HTMLDocument& StaticRangeTest::GetDocument() const {
  return *document_;
}

TEST_F(StaticRangeTest, SplitTextNodeRangeWithinText) {
  V8TestingScope scope;
  GetDocument().body()->setInnerHTML("1234");
  auto* old_text = To<Text>(GetDocument().body()->firstChild());

  auto* static_range04 = MakeGarbageCollected<StaticRange>(
      GetDocument(), old_text, 0u, old_text, 4u);
  auto* static_range02 = MakeGarbageCollected<StaticRange>(
      GetDocument(), old_text, 0u, old_text, 2u);
  auto* static_range22 = MakeGarbageCollected<StaticRange>(
      GetDocument(), old_text, 2u, old_text, 2u);
  auto* static_range24 = MakeGarbageCollected<StaticRange>(
      GetDocument(), old_text, 2u, old_text, 4u);

  Range* range04 = static_range04->toRange(ASSERT_NO_EXCEPTION);
  Range* range02 = static_range02->toRange(ASSERT_NO_EXCEPTION);
  Range* range22 = static_range22->toRange(ASSERT_NO_EXCEPTION);
  Range* range24 = static_range24->toRange(ASSERT_NO_EXCEPTION);

  old_text->splitText(2, ASSERT_NO_EXCEPTION);
  auto* new_text = To<Text>(old_text->nextSibling());

  // Range should mutate.
  EXPECT_TRUE(range04->BoundaryPointsValid());
  EXPECT_EQ(old_text, range04->startContainer());
  EXPECT_EQ(0u, range04->startOffset());
  EXPECT_EQ(new_text, range04->endContainer());
  EXPECT_EQ(2u, range04->endOffset());

  EXPECT_TRUE(range02->BoundaryPointsValid());
  EXPECT_EQ(old_text, range02->startContainer());
  EXPECT_EQ(0u, range02->startOffset());
  EXPECT_EQ(old_text, range02->endContainer());
  EXPECT_EQ(2u, range02->endOffset());

  // Our implementation always moves the boundary point at the separation point
  // to the end of the original text node.
  EXPECT_TRUE(range22->BoundaryPointsValid());
  EXPECT_EQ(old_text, range22->startContainer());
  EXPECT_EQ(2u, range22->startOffset());
  EXPECT_EQ(old_text, range22->endContainer());
  EXPECT_EQ(2u, range22->endOffset());

  EXPECT_TRUE(range24->BoundaryPointsValid());
  EXPECT_EQ(old_text, range24->startContainer());
  EXPECT_EQ(2u, range24->startOffset());
  EXPECT_EQ(new_text, range24->endContainer());
  EXPECT_EQ(2u, range24->endOffset());

  // StaticRange shouldn't mutate.
  EXPECT_EQ(old_text, static_range04->startContainer());
  EXPECT_EQ(0u, static_range04->startOffset());
  EXPECT_EQ(old_text, static_range04->endContainer());
  EXPECT_EQ(4u, static_range04->endOffset());

  EXPECT_EQ(old_text, static_range02->startContainer());
  EXPECT_EQ(0u, static_range02->startOffset());
  EXPECT_EQ(old_text, static_range02->endContainer());
  EXPECT_EQ(2u, static_range02->endOffset());

  EXPECT_EQ(old_text, static_range22->startContainer());
  EXPECT_EQ(2u, static_range22->startOffset());
  EXPECT_EQ(old_text, static_range22->endContainer());
  EXPECT_EQ(2u, static_range22->endOffset());

  EXPECT_EQ(old_text, static_range24->startContainer());
  EXPECT_EQ(2u, static_range24->startOffset());
  EXPECT_EQ(old_text, static_range24->endContainer());
  EXPECT_EQ(4u, static_range24->endOffset());
}

TEST_F(StaticRangeTest, SplitTextNodeRangeOutsideText) {
  V8TestingScope scope;
  GetDocument().body()->setInnerHTML(
      "<span id=\"outer\">0<span id=\"inner-left\">1</span>SPLITME<span "
      "id=\"inner-right\">2</span>3</span>");

  Element* outer =
      GetDocument().getElementById(AtomicString::FromUTF8("outer"));
  Element* inner_left =
      GetDocument().getElementById(AtomicString::FromUTF8("inner-left"));
  Element* inner_right =
      GetDocument().getElementById(AtomicString::FromUTF8("inner-right"));
  auto* old_text = To<Text>(outer->childNodes()->item(2));

  auto* static_range_outer_outside =
      MakeGarbageCollected<StaticRange>(GetDocument(), outer, 0u, outer, 5u);
  auto* static_range_outer_inside =
      MakeGarbageCollected<StaticRange>(GetDocument(), outer, 1u, outer, 4u);
  auto* static_range_outer_surrounding_text =
      MakeGarbageCollected<StaticRange>(GetDocument(), outer, 2u, outer, 3u);
  auto* static_range_inner_left = MakeGarbageCollected<StaticRange>(
      GetDocument(), inner_left, 0u, inner_left, 1u);
  auto* static_range_inner_right = MakeGarbageCollected<StaticRange>(
      GetDocument(), inner_right, 0u, inner_right, 1u);
  auto* static_range_from_text_to_middle_of_element =
      MakeGarbageCollected<StaticRange>(GetDocument(), old_text, 6u, outer, 3u);

  Range* range_outer_outside =
      static_range_outer_outside->toRange(ASSERT_NO_EXCEPTION);
  Range* range_outer_inside =
      static_range_outer_inside->toRange(ASSERT_NO_EXCEPTION);
  Range* range_outer_surrounding_text =
      static_range_outer_surrounding_text->toRange(ASSERT_NO_EXCEPTION);
  Range* range_inner_left =
      static_range_inner_left->toRange(ASSERT_NO_EXCEPTION);
  Range* range_inner_right =
      static_range_inner_right->toRange(ASSERT_NO_EXCEPTION);
  Range* range_from_text_to_middle_of_element =
      static_range_from_text_to_middle_of_element->toRange(ASSERT_NO_EXCEPTION);

  old_text->splitText(3, ASSERT_NO_EXCEPTION);
  auto* new_text = To<Text>(old_text->nextSibling());

  // Range should mutate.
  EXPECT_TRUE(range_outer_outside->BoundaryPointsValid());
  EXPECT_EQ(outer, range_outer_outside->startContainer());
  EXPECT_EQ(0u, range_outer_outside->startOffset());
  EXPECT_EQ(outer, range_outer_outside->endContainer());
  EXPECT_EQ(6u,
            range_outer_outside
                ->endOffset());  // Increased by 1 since a new node is inserted.

  EXPECT_TRUE(range_outer_inside->BoundaryPointsValid());
  EXPECT_EQ(outer, range_outer_inside->startContainer());
  EXPECT_EQ(1u, range_outer_inside->startOffset());
  EXPECT_EQ(outer, range_outer_inside->endContainer());
  EXPECT_EQ(5u, range_outer_inside->endOffset());

  EXPECT_TRUE(range_outer_surrounding_text->BoundaryPointsValid());
  EXPECT_EQ(outer, range_outer_surrounding_text->startContainer());
  EXPECT_EQ(2u, range_outer_surrounding_text->startOffset());
  EXPECT_EQ(outer, range_outer_surrounding_text->endContainer());
  EXPECT_EQ(4u, range_outer_surrounding_text->endOffset());

  EXPECT_TRUE(range_inner_left->BoundaryPointsValid());
  EXPECT_EQ(inner_left, range_inner_left->startContainer());
  EXPECT_EQ(0u, range_inner_left->startOffset());
  EXPECT_EQ(inner_left, range_inner_left->endContainer());
  EXPECT_EQ(1u, range_inner_left->endOffset());

  EXPECT_TRUE(range_inner_right->BoundaryPointsValid());
  EXPECT_EQ(inner_right, range_inner_right->startContainer());
  EXPECT_EQ(0u, range_inner_right->startOffset());
  EXPECT_EQ(inner_right, range_inner_right->endContainer());
  EXPECT_EQ(1u, range_inner_right->endOffset());

  EXPECT_TRUE(range_from_text_to_middle_of_element->BoundaryPointsValid());
  EXPECT_EQ(new_text, range_from_text_to_middle_of_element->startContainer());
  EXPECT_EQ(3u, range_from_text_to_middle_of_element->startOffset());
  EXPECT_EQ(outer, range_from_text_to_middle_of_element->endContainer());
  EXPECT_EQ(4u, range_from_text_to_middle_of_element->endOffset());

  // StaticRange shouldn't mutate.
  EXPECT_EQ(outer, static_range_outer_outside->startContainer());
  EXPECT_EQ(0u, static_range_outer_outside->startOffset());
  EXPECT_EQ(outer, static_range_outer_outside->endContainer());
  EXPECT_EQ(5u, static_range_outer_outside->endOffset());

  EXPECT_EQ(outer, static_range_outer_inside->startContainer());
  EXPECT_EQ(1u, static_range_outer_inside->startOffset());
  EXPECT_EQ(outer, static_range_outer_inside->endContainer());
  EXPECT_EQ(4u, static_range_outer_inside->endOffset());

  EXPECT_EQ(outer, static_range_outer_surrounding_text->startContainer());
  EXPECT_EQ(2u, static_range_outer_surrounding_text->startOffset());
  EXPECT_EQ(outer, static_range_outer_surrounding_text->endContainer());
  EXPECT_EQ(3u, static_range_outer_surrounding_text->endOffset());

  EXPECT_EQ(inner_left, static_range_inner_left->startContainer());
  EXPECT_EQ(0u, static_range_inner_left->startOffset());
  EXPECT_EQ(inner_left, static_range_inner_left->endContainer());
  EXPECT_EQ(1u, static_range_inner_left->endOffset());

  EXPECT_EQ(inner_right, static_range_inner_right->startContainer());
  EXPECT_EQ(0u, static_range_inner_right->startOffset());
  EXPECT_EQ(inner_right, static_range_inner_right->endContainer());
  EXPECT_EQ(1u, static_range_inner_right->endOffset());

  EXPECT_EQ(old_text,
            static_range_from_text_to_middle_of_element->startContainer());
  EXPECT_EQ(6u, static_range_from_text_to_middle_of_element->startOffset());
  EXPECT_EQ(outer, static_range_from_text_to_middle_of_element->endContainer());
  EXPECT_EQ(3u, static_range_from_text_to_middle_of_element->endOffset());
}

TEST_F(StaticRangeTest, InvalidToRange) {
  V8TestingScope scope;
  GetDocument().body()->setInnerHTML("1234");
  auto* old_text = To<Text>(GetDocument().body()->firstChild());

  auto* static_range04 = MakeGarbageCollected<StaticRange>(
      GetDocument(), old_text, 0u, old_text, 4u);

  // Valid StaticRange.
  static_range04->toRange(ASSERT_NO_EXCEPTION);

  old_text->splitText(2, ASSERT_NO_EXCEPTION);
  // StaticRange shouldn't mutate, endOffset() become invalid after splitText().
  EXPECT_EQ(old_text, static_range04->startContainer());
  EXPECT_EQ(0u, static_range04->startOffset());
  EXPECT_EQ(old_text, static_range04->endContainer());
  EXPECT_EQ(4u, static_range04->endOffset());

  // Invalid StaticRange.
  DummyExceptionStateForTesting exception_state;
  static_range04->toRange(exception_state);
  EXPECT_TRUE(exception_state.HadException());
}

}  // namespace blink
```