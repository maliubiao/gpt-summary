Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `whitespace_attacher_test.cc` immediately suggests it's testing something related to whitespace handling within the rendering engine. The `WhitespaceAttacher` class mentioned in the includes confirms this.

2. **Understand the Testing Framework:** The `#include <gtest/gtest.h>` tells us this uses the Google Test framework. The `TEST_F` macros indicate individual test cases within a test fixture (`WhitespaceAttacherTest`).

3. **Analyze the Test Fixture:**  `WhitespaceAttacherTest` inherits from `PageTestBase`. This is a strong clue that these tests involve manipulating the DOM and triggering layout updates within a simulated browser environment. The `AdvanceToRebuildLayoutTree()` method further confirms this, as it advances the document lifecycle to a point where layout recalculation occurs.

4. **Examine Individual Test Cases (Iterative Process):**

   * **Initial Scan:** Quickly read through the names of the test cases. This gives a high-level overview of what aspects of whitespace attachment are being tested (e.g., "WhitespaceAfterReattachedBlock", "WhitespaceAfterReattachedInline", "SlottedWhitespaceAfterReattachedBlock", etc.). The terms "reattached," "slotted," and "display: contents" are important keywords to note.

   * **Detailed Analysis of a Representative Test (e.g., `WhitespaceAfterReattachedBlock`):**
      * **Setup:** `GetDocument().body()->setInnerHTML("<div id=block></div> ");`  This sets up the initial DOM structure. A `div` followed by a space.
      * **Initial State:** `UpdateAllLifecyclePhasesForTest();` likely performs initial layout. The assertion `EXPECT_FALSE(text->GetLayoutObject());` checks that the whitespace initially doesn't have a layout object (meaning it's likely collapsed or not yet relevant for layout).
      * **Triggering Reattachment:** `AdvanceToRebuildLayoutTree();` forces a layout rebuild.
      * **Forcing Layout Object (Important!):** `text->SetLayoutObject(text->CreateTextLayoutObject());` This is a key step. The test *forces* the creation of a layout object for the text node, probably to simulate a scenario where it might have one under different conditions.
      * **Action Under Test:** `WhitespaceAttacher attacher; attacher.DidVisitText(text); attacher.DidReattachElement(div, div->GetLayoutObject());` This is where the `WhitespaceAttacher` is used. It visits the text node and then indicates that the `div` element has been "reattached."
      * **Verification:** `EXPECT_FALSE(text->GetLayoutObject());`  The crucial check: after the `WhitespaceAttacher` acts, the whitespace *no longer* has a layout object. This suggests the `WhitespaceAttacher`'s role is to potentially detach or manage the layout object of whitespace in certain reattachment scenarios.

   * **Identify Patterns:** As you analyze more tests, look for recurring patterns:
      * **`setInnerHTML` for DOM setup.**
      * **`UpdateAllLifecyclePhasesForTest()` to trigger layout.**
      * **`AdvanceToRebuildLayoutTree()` to simulate layout updates.**
      * **`WhitespaceAttacher` being instantiated and methods like `DidVisitText`, `DidReattachElement`, `DidReattachText`, `DidVisitElement` being called.**
      * **`EXPECT_TRUE`/`EXPECT_FALSE` to check the presence or absence of layout objects (`GetLayoutObject()`).**
      * **Focus on different element types (block, inline, display: contents) and scenarios (reattachment, slotting).**

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**

   * **HTML:** The tests directly manipulate HTML structures using `setInnerHTML`. The elements (`div`, `span`), attributes (`id`, `style`), and concepts like Shadow DOM (`<slot>`) are all HTML-related.
   * **CSS:**  The `style` attribute is used for inline CSS (`display: contents`, `float: right`). The test involving `scroll-marker-group` explicitly uses CSS properties. The layout behavior being tested is fundamentally influenced by CSS.
   * **JavaScript:** While the tests are in C++, the *purpose* is to ensure correct rendering behavior that would be triggered by JavaScript DOM manipulations. JavaScript code might dynamically add, remove, or modify elements, potentially leading to the reattachment scenarios being tested.

6. **Infer Functionality of `WhitespaceAttacher`:** Based on the test cases, we can infer that `WhitespaceAttacher` is responsible for:
   * Determining whether whitespace nodes should have layout objects during layout rebuilds, especially after elements are reattached or when dealing with Shadow DOM and `display: contents`.
   * Optimizing rendering by potentially collapsing or hiding whitespace that isn't visually significant.

7. **Consider User Actions and Debugging:** Think about how a user's interaction with a web page could lead to the scenarios tested:
   * **Dynamic Content Updates:** JavaScript frameworks frequently update parts of the DOM. Adding or removing elements, which the tests simulate, are common operations.
   * **Showing/Hiding Elements:**  Changing the `display` property via JavaScript or CSS can trigger layout recalculations.
   * **Shadow DOM:** Websites using Web Components and Shadow DOM will encounter the slotting scenarios tested.

8. **Hypothesize Inputs and Outputs:** For specific tests, imagine the state of the DOM before and after the `WhitespaceAttacher` acts. The input is the DOM structure and the element/text nodes being visited/reattached. The output is whether the whitespace nodes have layout objects.

9. **Identify Potential Errors:**  Think about common mistakes developers might make that could expose bugs related to whitespace handling:
   * **Incorrect assumptions about whitespace:**  Developers might expect whitespace to always be rendered, but the browser collapses it in certain contexts.
   * **Dynamic DOM manipulation without considering layout implications:** Adding/removing elements without understanding how it affects surrounding whitespace.
   * **Issues with Shadow DOM boundaries:**  Not understanding how whitespace is handled between the light DOM and the shadow DOM.

By following these steps, we can systematically analyze the C++ test file and understand its purpose, its relation to web technologies, and its implications for developers and users.
这个文件 `whitespace_attacher_test.cc` 是 Chromium Blink 引擎中用于测试 `WhitespaceAttacher` 类的单元测试文件。 `WhitespaceAttacher` 类的主要功能是**在布局树重建过程中管理和调整空白字符（whitespace）节点的布局对象（LayoutObject）的创建和连接**。

更具体地说，它负责处理以下情况：

* **元素被重新附加（reattached）到 DOM 树后，其相邻的空白字符节点的布局对象状态。**  例如，一个块级元素或行内元素被移动或重新插入到文档中，它旁边的空格是否应该重新创建或保持其布局对象状态。
* **在 Shadow DOM 中，特别是涉及 `<slot>` 元素时，空白字符节点的布局对象状态。**  当内容被插入到 slot 中时，需要正确处理周围的空白。
* **当元素具有 `display: contents` 样式时，其内部或周围的空白字符节点的布局对象状态。** `display: contents` 会使元素本身不生成盒子，因此其子节点和相邻节点的布局需要特殊处理。
* **在特定的布局阶段（例如，布局树重建），决定是否需要为某些空白字符节点创建布局对象。**  为了性能优化，并非所有空白字符都需要立即创建布局对象。

**与 JavaScript, HTML, CSS 的关系：**

`WhitespaceAttacher` 的功能与这三者都有密切关系，因为它处理的是浏览器渲染引擎中关于内容布局的关键方面。

* **HTML:**  `WhitespaceAttacher` 处理的是 HTML 结构中空白字符（例如空格、制表符、换行符）的渲染。测试用例中大量使用 `setInnerHTML` 来创建不同的 HTML 结构，正是为了模拟各种包含空白字符的场景。例如，`<div id=block></div> ` 中的空格。
* **CSS:** CSS 的 `white-space` 属性（虽然这个测试文件没有直接涉及 `white-space` 属性的测试，但 `WhitespaceAttacher` 的工作与它密切相关）以及 `display` 属性（特别是 `display: contents`) 会影响空白字符的渲染方式。测试用例中使用了 `display: contents` 来验证 `WhitespaceAttacher` 在这种特殊布局模式下的行为。
* **JavaScript:** JavaScript 可以动态地修改 DOM 结构，例如添加、删除、移动元素。这些操作可能会导致元素被重新附加，从而触发 `WhitespaceAttacher` 的工作。测试用例模拟了这些重新附加的场景。

**举例说明：**

1. **HTML 结构与空白：**
   假设 HTML 代码是 `<span>Hello</span> World`。 在 `<span>` 和 `World` 之间存在一个空格。`WhitespaceAttacher` 的职责之一就是决定这个空格是否需要创建独立的布局对象，以及在周围元素布局发生变化时如何处理它。

2. **CSS `display: contents`：**
   假设 HTML 代码是 `<div style="display: contents"> Hello <span>World</span> </div>`。由于 `div` 的 `display` 属性为 `contents`，它本身不会生成布局盒子。`WhitespaceAttacher` 需要确保 " Hello " 这个空白字符以及 `<span>` 元素能够正确地与 `div` 的父元素进行布局。

3. **JavaScript 动态修改 DOM：**
   假设 JavaScript 代码将一个 `<div>` 元素从一个位置移动到另一个位置：
   ```javascript
   const container1 = document.getElementById('container1');
   const container2 = document.getElementById('container2');
   const divToMove = document.getElementById('myDiv');

   container2.appendChild(divToMove);
   ```
   如果 `myDiv` 前后有空白字符，`WhitespaceAttacher` 需要处理这些空白字符在 `myDiv` 被重新附加到 `container2` 后的布局状态。

**逻辑推理、假设输入与输出：**

以下是一个基于测试用例 `WhitespaceAfterReattachedBlock` 的逻辑推理：

**假设输入：**

* **初始 HTML 结构：** `<div id=block></div> ` (一个 `div` 元素，后面跟着一个空格文本节点)
* **操作：**
    1. 初始化布局。
    2. 进入布局树重建阶段。
    3. 强制空格文本节点创建布局对象（`text->SetLayoutObject(text->CreateTextLayoutObject());`，这是一种模拟场景）。
    4. 调用 `WhitespaceAttacher` 的方法，模拟访问了空格文本节点和重新附加了 `div` 元素。

**预期输出：**

* 在调用 `attacher.DidReattachElement(div, div->GetLayoutObject());` 后，空格文本节点的布局对象应该被移除（`EXPECT_FALSE(text->GetLayoutObject());`）。

**推理：**

`WhitespaceAttacher` 的设计意图是，当一个块级元素被重新附加后，紧随其后的空白字符如果还没有必要渲染出来，其布局对象可以被移除，以便进行优化。 强制空格创建布局对象是为了测试 `WhitespaceAttacher` 是否能在重新附加元素时正确地管理这些空白字符的布局对象。

**用户或编程常见的使用错误：**

* **过度依赖空白字符进行布局:**  一些开发者可能会错误地依赖 HTML 中的空格来进行元素间的细微定位或分隔。然而，浏览器对空白字符的处理有其自身的规则，不同情况下可能会折叠或忽略空白。 `WhitespaceAttacher` 的存在就是为了处理这些复杂情况。
* **动态 DOM 操作后未考虑空白的影响:** 当使用 JavaScript 动态添加或删除元素时，可能会意外地引入或移除空白字符，导致布局变化。开发者需要意识到这些潜在的影响。例如，以下 JavaScript 代码可能会引入额外的空白节点：
  ```javascript
  const newDiv = document.createElement('div');
  newDiv.textContent = 'Hello';
  container.innerHTML = ''; // 清空容器，可能删除原有空白
  container.appendChild(newDiv); // 添加新元素，可能在其前后产生新的空白节点
  ```

**用户操作如何一步步到达这里，作为调试线索：**

虽然用户不会直接与 `WhitespaceAttacher` 交互，但他们的操作会触发浏览器的渲染引擎执行相关逻辑。以下是一个可能的步骤：

1. **用户访问一个网页:**  浏览器开始解析 HTML、CSS 并构建 DOM 树和 CSSOM 树。
2. **JavaScript 交互导致 DOM 变化:** 用户与网页进行交互，例如点击按钮，触发 JavaScript 代码执行。
3. **JavaScript 修改 DOM 结构:** JavaScript 代码可能会添加、删除或移动 DOM 元素。例如，一个动画效果将一个 `div` 元素从屏幕的一侧移动到另一侧（这涉及到元素的重新附加）。
4. **触发布局树重建:** DOM 的修改会使当前的布局树失效，浏览器需要重新构建布局树。
5. **`WhitespaceAttacher` 介入:** 在布局树重建过程中，遍历 DOM 树时会遇到空白字符节点和被重新附加的元素。`WhitespaceAttacher` 会根据其内部逻辑判断是否需要为这些空白字符节点创建或保留布局对象。
6. **渲染结果:**  最终的布局树决定了网页的渲染结果，用户在屏幕上看到更新后的页面。

**调试线索：**

如果开发者在 Chromium 浏览器中遇到与空白字符渲染相关的 bug，例如：

* 空白字符意外消失或出现。
* 元素间距异常。
* 布局在动态 DOM 操作后发生错误。

调试 `WhitespaceAttacher` 的测试用例可以帮助理解浏览器是如何处理空白字符的，从而定位 bug 的原因。 开发者可能会：

* **查看 `whitespace_attacher_test.cc` 中的相关测试用例:**  找到与自己遇到的问题相似的场景，了解 `WhitespaceAttacher` 在这些情况下的预期行为。
* **使用 Chromium 的开发者工具:**  检查元素的 DOM 结构，查看是否有意外的空白文本节点。
* **在渲染流程中设置断点:**  如果需要深入了解 `WhitespaceAttacher` 的具体执行过程，可以在 Blink 渲染引擎的源代码中相关的位置设置断点进行调试。

总而言之，`whitespace_attacher_test.cc` 文件通过一系列单元测试，确保 `WhitespaceAttacher` 类能够正确地处理各种场景下的空白字符布局，从而保证网页的正确渲染。

### 提示词
```
这是目录为blink/renderer/core/dom/whitespace_attacher_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/dom/whitespace_attacher.h"

#include <gtest/gtest.h>

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class WhitespaceAttacherTest : public PageTestBase {
 protected:
  void AdvanceToRebuildLayoutTree() {
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
    GetDocument().GetStyleEngine().in_layout_tree_rebuild_ = true;
  }
};

TEST_F(WhitespaceAttacherTest, WhitespaceAfterReattachedBlock) {
  GetDocument().body()->setInnerHTML("<div id=block></div> ");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("block"));
  auto* text = To<Text>(div->nextSibling());
  EXPECT_FALSE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Force LayoutText to see that the reattach works.
  text->SetLayoutObject(text->CreateTextLayoutObject());

  WhitespaceAttacher attacher;
  attacher.DidVisitText(text);
  attacher.DidReattachElement(div, div->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, WhitespaceAfterReattachedInline) {
  GetDocument().body()->setInnerHTML("<span id=inline></span> ");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  auto* text = To<Text>(span->nextSibling());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidVisitText(text);
  attacher.DidReattachElement(span, span->GetLayoutObject());
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, WhitespaceAfterReattachedWhitespace) {
  GetDocument().body()->setInnerHTML("<span id=inline></span> <!-- --> ");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  auto* first_whitespace = To<Text>(span->nextSibling());
  auto* second_whitespace =
      To<Text>(first_whitespace->nextSibling()->nextSibling());
  EXPECT_TRUE(first_whitespace->GetLayoutObject());
  EXPECT_FALSE(second_whitespace->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Force LayoutText on the second whitespace to see that the reattach works.
  second_whitespace->SetLayoutObject(
      second_whitespace->CreateTextLayoutObject());

  WhitespaceAttacher attacher;
  attacher.DidVisitText(second_whitespace);
  EXPECT_TRUE(second_whitespace->GetLayoutObject());

  attacher.DidReattachText(first_whitespace);
  EXPECT_TRUE(first_whitespace->GetLayoutObject());
  EXPECT_FALSE(second_whitespace->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, VisitBlockAfterReattachedWhitespace) {
  GetDocument().body()->setInnerHTML("<div id=block></div> ");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("block"));
  auto* text = To<Text>(div->nextSibling());
  EXPECT_FALSE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  WhitespaceAttacher attacher;
  attacher.DidReattachText(text);
  EXPECT_FALSE(text->GetLayoutObject());

  attacher.DidVisitElement(div);
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, VisitInlineAfterReattachedWhitespace) {
  GetDocument().body()->setInnerHTML("<span id=inline></span> ");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  auto* text = To<Text>(span->nextSibling());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidReattachText(text);
  EXPECT_FALSE(text->GetLayoutObject());

  attacher.DidVisitElement(span);
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, VisitTextAfterReattachedWhitespace) {
  GetDocument().body()->setInnerHTML("Text<!-- --> ");
  UpdateAllLifecyclePhasesForTest();

  auto* text = To<Text>(GetDocument().body()->firstChild());
  auto* whitespace = To<Text>(text->nextSibling()->nextSibling());
  EXPECT_TRUE(text->GetLayoutObject());
  EXPECT_TRUE(whitespace->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  whitespace->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidReattachText(whitespace);
  EXPECT_FALSE(whitespace->GetLayoutObject());

  attacher.DidVisitText(text);
  EXPECT_TRUE(text->GetLayoutObject());
  EXPECT_TRUE(whitespace->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, ReattachWhitespaceInsideBlockExitingScope) {
  GetDocument().body()->setInnerHTML("<div id=block> </div>");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("block"));
  auto* text = To<Text>(div->firstChild());
  EXPECT_FALSE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  {
    WhitespaceAttacher attacher;
    attacher.DidReattachText(text);
    EXPECT_FALSE(text->GetLayoutObject());

    // Force LayoutText to see that the reattach works.
    text->SetLayoutObject(text->CreateTextLayoutObject());
  }
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, ReattachWhitespaceInsideInlineExitingScope) {
  GetDocument().body()->setInnerHTML("<span id=inline> </span>");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  auto* text = To<Text>(span->firstChild());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  {
    WhitespaceAttacher attacher;
    attacher.DidReattachText(text);
    EXPECT_FALSE(text->GetLayoutObject());
  }
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, SlottedWhitespaceAfterReattachedBlock) {
  GetDocument().body()->setInnerHTML("<div id=host> </div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div id=block></div><slot></slot>");
  UpdateAllLifecyclePhasesForTest();

  Element* div = shadow_root.getElementById(AtomicString("block"));
  auto* text = To<Text>(host->firstChild());
  EXPECT_FALSE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Force LayoutText to see that the reattach works.
  text->SetLayoutObject(text->CreateTextLayoutObject());

  WhitespaceAttacher attacher;
  attacher.DidVisitText(text);
  EXPECT_TRUE(text->GetLayoutObject());

  attacher.DidReattachElement(div, div->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, SlottedWhitespaceAfterReattachedInline) {
  GetDocument().body()->setInnerHTML("<div id=host> </div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<span id=inline></span><slot></slot>");
  UpdateAllLifecyclePhasesForTest();

  Element* span = shadow_root.getElementById(AtomicString("inline"));
  auto* text = To<Text>(host->firstChild());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidVisitText(text);
  EXPECT_FALSE(text->GetLayoutObject());

  attacher.DidReattachElement(span, span->GetLayoutObject());
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest,
       WhitespaceInDisplayContentsAfterReattachedBlock) {
  GetDocument().body()->setInnerHTML(
      "<div id=block></div><span style='display:contents'> </span>");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("block"));
  auto* contents = To<Element>(div->nextSibling());
  auto* text = To<Text>(contents->firstChild());
  EXPECT_FALSE(contents->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Force LayoutText to see that the reattach works.
  text->SetLayoutObject(text->CreateTextLayoutObject());

  WhitespaceAttacher attacher;
  attacher.DidVisitElement(contents);
  EXPECT_TRUE(text->GetLayoutObject());

  attacher.DidReattachElement(div, div->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest,
       WhitespaceInDisplayContentsAfterReattachedInline) {
  GetDocument().body()->setInnerHTML(
      "<span id=inline></span><span style='display:contents'> </span>");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  auto* contents = To<Element>(span->nextSibling());
  auto* text = To<Text>(contents->firstChild());
  EXPECT_FALSE(contents->GetLayoutObject());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidVisitElement(contents);
  EXPECT_FALSE(text->GetLayoutObject());

  attacher.DidReattachElement(span, span->GetLayoutObject());
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest,
       WhitespaceAfterEmptyDisplayContentsAfterReattachedBlock) {
  GetDocument().body()->setInnerHTML(
      "<div id=block></div><span style='display:contents'></span> ");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("block"));
  auto* contents = To<Element>(div->nextSibling());
  auto* text = To<Text>(contents->nextSibling());
  EXPECT_FALSE(contents->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Force LayoutText to see that the reattach works.
  text->SetLayoutObject(text->CreateTextLayoutObject());

  WhitespaceAttacher attacher;
  attacher.DidVisitText(text);
  attacher.DidVisitElement(contents);
  EXPECT_TRUE(text->GetLayoutObject());

  attacher.DidReattachElement(div, div->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest,
       WhitespaceAfterDisplayContentsWithDisplayNoneChildAfterReattachedBlock) {
  GetDocument().body()->setInnerHTML(
      "<div id=block></div><span style='display:contents'>"
      "<span style='display:none'></span></span> ");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("block"));
  auto* contents = To<Element>(div->nextSibling());
  auto* text = To<Text>(contents->nextSibling());
  EXPECT_FALSE(contents->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Force LayoutText to see that the reattach works.
  text->SetLayoutObject(text->CreateTextLayoutObject());

  WhitespaceAttacher attacher;
  attacher.DidVisitText(text);
  attacher.DidVisitElement(contents);
  EXPECT_TRUE(text->GetLayoutObject());

  attacher.DidReattachElement(div, div->GetLayoutObject());
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, WhitespaceDeepInsideDisplayContents) {
  GetDocument().body()->setInnerHTML(
      "<span id=inline></span><span style='display:contents'>"
      "<span style='display:none'></span>"
      "<span id=inner style='display:contents'> </span></span>");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  auto* contents = To<Element>(span->nextSibling());
  auto* text = To<Text>(
      GetDocument().getElementById(AtomicString("inner"))->firstChild());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidVisitElement(contents);
  EXPECT_FALSE(text->GetLayoutObject());

  attacher.DidReattachElement(span, span->GetLayoutObject());
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, MultipleDisplayContents) {
  GetDocument().body()->setInnerHTML(
      "<span id=inline></span>"
      "<span style='display:contents'></span>"
      "<span style='display:contents'></span>"
      "<span style='display:contents'> </span>");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  auto* first_contents = To<Element>(span->nextSibling());
  auto* second_contents = To<Element>(first_contents->nextSibling());
  auto* last_contents = To<Element>(second_contents->nextSibling());
  auto* text = To<Text>(last_contents->firstChild());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidVisitElement(last_contents);
  attacher.DidVisitElement(second_contents);
  attacher.DidVisitElement(first_contents);
  EXPECT_FALSE(text->GetLayoutObject());

  attacher.DidReattachElement(span, span->GetLayoutObject());
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, SlottedWhitespaceInsideDisplayContents) {
  GetDocument().body()->setInnerHTML("<div id=host> </div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(
      "<span id=inline></span>"
      "<div style='display:contents'><slot></slot></div>");
  UpdateAllLifecyclePhasesForTest();

  Element* span = shadow_root.getElementById(AtomicString("inline"));
  auto* contents = To<Element>(span->nextSibling());
  auto* text = To<Text>(host->firstChild());
  EXPECT_TRUE(text->GetLayoutObject());

  AdvanceToRebuildLayoutTree();

  // Clear LayoutText to see that the reattach works.
  text->SetLayoutObject(nullptr);

  WhitespaceAttacher attacher;
  attacher.DidVisitElement(contents);
  EXPECT_FALSE(text->GetLayoutObject());

  attacher.DidReattachElement(span, span->GetLayoutObject());
  EXPECT_TRUE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, RemoveInlineBeforeSpace) {
  GetDocument().body()->setInnerHTML("<span id=inline></span> ");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  ASSERT_TRUE(span);
  EXPECT_TRUE(span->GetLayoutObject());

  Node* text = span->nextSibling();
  ASSERT_TRUE(text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_TRUE(text->GetLayoutObject());

  span->remove();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(text->previousSibling());
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_FALSE(text->nextSibling());
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, RemoveInlineBeforeOutOfFlowBeforeSpace) {
  GetDocument().body()->setInnerHTML(
      "<span id=inline></span><div id=float style='float:right'></div> ");
  UpdateAllLifecyclePhasesForTest();

  Element* span = GetDocument().getElementById(AtomicString("inline"));
  ASSERT_TRUE(span);
  EXPECT_TRUE(span->GetLayoutObject());

  Element* floated = GetDocument().getElementById(AtomicString("float"));
  ASSERT_TRUE(floated);
  EXPECT_TRUE(floated->GetLayoutObject());

  Node* text = floated->nextSibling();
  ASSERT_TRUE(text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_TRUE(text->GetLayoutObject());

  span->remove();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(text->IsTextNode());
  EXPECT_FALSE(text->nextSibling());
  EXPECT_FALSE(text->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, RemoveSpaceBeforeSpace) {
  GetDocument().body()->setInnerHTML("<span> <!-- --> </span>");
  UpdateAllLifecyclePhasesForTest();

  Node* span = GetDocument().body()->firstChild();
  ASSERT_TRUE(span);

  Node* space1 = span->firstChild();
  ASSERT_TRUE(space1);
  EXPECT_TRUE(space1->IsTextNode());
  EXPECT_TRUE(space1->GetLayoutObject());

  Node* space2 = span->lastChild();
  ASSERT_TRUE(space2);
  EXPECT_TRUE(space2->IsTextNode());
  EXPECT_FALSE(space2->GetLayoutObject());

  space1->remove();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(space2->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, CreateSpaceForScrollMarkerGroup) {
  GetDocument().body()->setInnerHTML(
      "<span>x</span> <span id=test></span> <span>y</span>"
      "<style>"
      "#test { scroll-marker-group: before; overflow: auto; }"
      "#test::scroll-marker-group { background: green; display: inline-flex; "
      "width: 100px; height: 100px; }"
      "</style>");
  UpdateAllLifecyclePhasesForTest();

  Node* span = GetDocument().body()->firstChild();
  Node* first_space = LayoutTreeBuilderTraversal::NextLayoutSibling(*span);
  ASSERT_TRUE(first_space);
  EXPECT_TRUE(first_space->IsTextNode());
  EXPECT_TRUE(first_space->GetLayoutObject());

  Node* scroll_marker_group =
      LayoutTreeBuilderTraversal::NextLayoutSibling(*first_space);
  ASSERT_TRUE(scroll_marker_group);
  EXPECT_TRUE(scroll_marker_group->IsScrollMarkerGroupBeforePseudoElement());
  EXPECT_TRUE(scroll_marker_group->GetLayoutObject());

  Node* scroller =
      LayoutTreeBuilderTraversal::NextLayoutSibling(*scroll_marker_group);
  ASSERT_TRUE(scroller);

  Node* space2 = LayoutTreeBuilderTraversal::NextLayoutSibling(*scroller);
  ASSERT_TRUE(space2);
  EXPECT_TRUE(space2->IsTextNode());
  EXPECT_TRUE(space2->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, RemoveSpaceForScrollMarkerGroup) {
  GetDocument().body()->setInnerHTML(
      "<span>x</span> <span id=test></span> <span>y</span>"
      "<style>"
      "#test { scroll-marker-group: after; overflow: auto; }"
      "#test::scroll-marker-group { background: green; display: inline-flex; "
      "width: 100px; height: 100px; }"
      "</style>");
  UpdateAllLifecyclePhasesForTest();

  Node* span = GetDocument().body()->firstChild();
  Node* first_space = LayoutTreeBuilderTraversal::NextLayoutSibling(*span);
  ASSERT_TRUE(first_space);
  EXPECT_TRUE(first_space->IsTextNode());
  EXPECT_TRUE(first_space->GetLayoutObject());

  Node* scroller = LayoutTreeBuilderTraversal::NextLayoutSibling(*first_space);

  ASSERT_TRUE(scroller);
  Node* scroll_marker_group =
      LayoutTreeBuilderTraversal::NextLayoutSibling(*scroller);
  ASSERT_TRUE(scroll_marker_group);
  EXPECT_TRUE(scroll_marker_group->IsScrollMarkerGroupAfterPseudoElement());
  EXPECT_TRUE(scroll_marker_group->GetLayoutObject());

  Node* space2 =
      LayoutTreeBuilderTraversal::NextLayoutSibling(*scroll_marker_group);
  ASSERT_TRUE(space2);
  EXPECT_TRUE(space2->IsTextNode());
  EXPECT_TRUE(space2->GetLayoutObject());

  To<Element>(scroller)->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                                CSSValueID::kFlex);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(space2->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, RemoveInlineBeforeDisplayContentsWithSpace) {
  GetDocument().body()->setInnerHTML(
      "<style>div { display: contents }</style>"
      "<div><span id=inline></span></div>"
      "<div><div><div id=innerdiv> </div></div></div>text");
  UpdateAllLifecyclePhasesForTest();

  Node* span = GetDocument().getElementById(AtomicString("inline"));
  ASSERT_TRUE(span);

  Node* space =
      GetDocument().getElementById(AtomicString("innerdiv"))->firstChild();
  ASSERT_TRUE(space);
  EXPECT_TRUE(space->IsTextNode());
  EXPECT_TRUE(space->GetLayoutObject());

  span->remove();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(space->GetLayoutObject());
}

TEST_F(WhitespaceAttacherTest, RemoveBlockBeforeSpace) {
  GetDocument().body()->setInnerHTML("A<div id=block></div> <span>B</span>");
  UpdateAllLifecyclePhasesForTest();

  Node* div = GetDocument().getElementById(AtomicString("block"));
  ASSERT_TRUE(div);

  Node* space = div->nextSibling();
  ASSERT_TRUE(space);
  EXPECT_TRUE(space->IsTextNode());
  EXPECT_FALSE(space->GetLayoutObject());

  div->remove();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(space->GetLayoutObject());
}

}  // namespace blink
```