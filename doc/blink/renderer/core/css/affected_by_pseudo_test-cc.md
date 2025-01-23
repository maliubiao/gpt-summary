Response:
The user wants a summary of the provided C++ code file. I need to identify the main purpose of the code and its relationship to web technologies.

**Code Analysis:**

1. **Headers:** The included headers (`testing/gtest/include/gtest/gtest.h`, `third_party/blink/...`) indicate this is a unit test file for the Blink rendering engine. Specific headers like `core/css/properties/longhands.h`, `core/css/style_engine.h`, `core/dom/document.h`, and `core/html/...` strongly suggest it tests CSS styling and its interaction with the DOM.

2. **Test Fixture:** The `AffectedByPseudoTest` class inherits from `PageTestBase`, a common base class for Blink layout tests.

3. **Helper Functions:**  The class defines several helper functions:
    - `SetHtmlInnerHTML`:  Sets the HTML content of the page.
    - `CheckElementsForFocus`: Checks if elements have the expected `children_or_siblings_affected_by_focus` flag.
    - `CheckAffectedByFlagsForHas`: Checks various "affected by" flags related to the `:has()` CSS pseudo-class.
    - `CheckAffectedByFlagsForHasInShadowTree`: Similar to the above, but for elements within shadow DOM.
    - `GetShadowTreeElementById`: Gets an element within a shadow DOM.

4. **AffectedByFlagName Enum:** This enum lists different flags related to how elements are affected by the `:has()` pseudo-class. This is a key indicator of the test's focus.

5. **Test Cases:** The `TEST_F` macros define individual test cases, many of which involve the `:focus` and `:focus-within` pseudo-classes. Some also involve the `:hover` pseudo-class within `:has()`.

**Relationship to Web Technologies:**

- **CSS:** The tests directly deal with CSS pseudo-classes like `:focus`, `:focus-within`, `:hover`, and `:has()`. They verify how these selectors affect the styling and layout invalidation of elements.
- **HTML:** The tests use HTML to create the DOM structure being tested. The `SetHtmlInnerHTML` function manipulates the HTML.
- **JavaScript (Indirect):** While no explicit JavaScript code is in this file, the functionality being tested (CSS selectors and how they trigger style recalculations) directly impacts how JavaScript interacts with the DOM and styling. For example, JavaScript might focus an element, and these tests ensure the correct elements are restyled as a result.

**Logical Reasoning and Examples:**

The tests verify assumptions about how the Blink rendering engine handles style invalidation based on pseudo-class selectors. For instance, when an element receives focus, certain other elements might need their styles recalculated. The tests define scenarios and check if the correct elements are marked for recalculation.

**User/Programming Errors:**

Understanding these "affected by" flags is crucial for performance. Incorrect assumptions about when styles are recalculated can lead to janky animations or slow interactions. For example, a developer might assume that only the focused element is restyled when using `:focus`, but these tests show that ancestor elements might also be affected depending on the CSS rules.

**User Operations and Debugging:**

A user's interaction, like clicking on an element to give it focus or hovering the mouse over an element, can trigger the code being tested. When debugging styling issues related to pseudo-classes, understanding these "affected by" flags and how they propagate through the DOM tree is essential. A developer might set breakpoints within the Blink rendering engine's style calculation code to see which elements are being marked for restyling and why.

**Summary:**

This C++ file is a unit test for the Blink rendering engine, specifically focusing on how CSS pseudo-classes (like `:focus`, `:focus-within`, `:hover`, and `:has()`) affect the styling and layout invalidation of DOM elements. It verifies the correctness of the engine's logic in determining which elements need to be restyled when the state of these pseudo-classes changes.

这是 `blink/renderer/core/css/affected_by_pseudo_test.cc` 文件的第一部分，主要功能是 **定义了一个用于测试 CSS 伪类对 DOM 元素影响的测试框架和一些基础的辅助方法。**  其核心目的是验证当元素的伪类状态发生变化时，Blink 引擎是否正确地标记了受影响的元素，并触发了必要的样式重算。

以下是更详细的归纳：

**主要功能:**

1. **定义测试框架 `AffectedByPseudoTest`:**
   - 继承自 `PageTestBase`，提供了一个用于创建和管理测试页面的基础环境。
   - 包含用于断言测试结果的辅助方法。
   - 定义了 `ElementResult` 结构体，用于描述期望的元素标签名和其 `children_or_siblings_affected_by_focus` 状态。
   - 定义了 `AffectedByFlagName` 枚举，列出了与 `:has()` 伪类相关的各种影响标志，例如是否作为 `:has()` 的主体被影响、是否作为非主体被影响等等。

2. **提供辅助方法用于设置 HTML 和检查元素状态:**
   - `SetHtmlInnerHTML()`:  允许测试用例动态设置测试页面的 HTML 内容。
   - `CheckElementsForFocus()`: 接收一个 `ElementResult` 的列表，遍历当前页面的元素，并断言每个元素的标签名和 `ChildrenOrSiblingsAffectedByFocus()` 的返回值是否与预期一致。
   - `CheckAffectedByFlagsForHas()` 和 `CheckAffectedByFlagsForHasInShadowTree()`:  用于检查特定元素（可能在 Shadow DOM 中）的各种与 `:has()` 相关的影响标志是否符合预期。
   - `GetShadowTreeElementById()`:  用于获取 Shadow DOM 中的元素。
   - `CheckAffectedByFlagsForHasInternal()`:  是 `CheckAffectedByFlagsForHas` 和 `CheckAffectedByFlagsForHasInShadowTree` 的内部实现，根据 `AffectedByFlagName` 检查对应的标志位。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联 HTML 和 CSS，并间接影响 JavaScript 的行为。

* **HTML:**  `SetHtmlInnerHTML()` 函数用于设置测试所需的 HTML 结构。测试用例通过构建不同的 HTML 结构来验证在不同场景下伪类的影响。
   * **举例:**  测试用例中会使用 `<div>`、`<span>` 等 HTML 元素来构建测试 DOM 树。

* **CSS:**  测试文件专注于验证 CSS 伪类选择器的行为，特别是 `:focus` 和 `:has()`。测试用例通过嵌入 `<style>` 标签来定义 CSS 规则，并观察这些规则如何影响元素的 `AffectedBy` 状态。
   * **举例:**  测试用例中会使用 `:focus div { background-color: pink }` 这样的 CSS 规则来测试当某个元素获得焦点时，其后代 `div` 元素是否被标记为受影响。对于 `:has()`，会使用 `.a:has(.b) { background-color: lime; }` 这样的规则来测试当类名为 `a` 的元素包含类名为 `b` 的子元素时，其自身以及相关的祖先或兄弟元素是否被正确标记。

* **JavaScript:**  虽然这个文件本身不包含 JavaScript 代码，但它测试的功能直接影响 JavaScript 与 DOM 的交互。JavaScript 可以通过修改元素的属性、添加/删除元素、触发事件等方式来改变元素的伪类状态，而这些状态的变化会触发 Blink 引擎的样式重算。这个测试文件保证了在这些情况下，Blink 引擎能够正确地识别和处理受影响的元素。
   * **举例:**  JavaScript 代码可能会使用 `element.focus()` 方法来使一个元素获得焦点，从而触发 `:focus` 伪类的激活。这个测试文件会验证在这种情况下，哪些元素会被标记为受影响，并进行样式重算。

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个包含 CSS 规则和 HTML 结构的字符串，例如：
  ```html
  <head>
  <style>:focus div { background-color: pink }</style>
  </head>
  <body>
  <div><div></div></div>
  </body>
  ```
* **输出:**  `CheckElementsForFocus` 函数会断言特定的 DOM 元素（例如 `<body>` 和外层的 `<div>`）的 `ChildrenOrSiblingsAffectedByFocus()` 方法返回 `true`，表示它们受到了 `:focus` 伪类的影响。

**涉及用户或编程常见的使用错误 (虽然本文件是测试代码，但可以引申):**

* **用户错误 (编写 CSS 时):**  用户可能错误地假设某个 CSS 规则只会影响特定的元素，而忽略了伪类选择器可能会导致父元素或兄弟元素也受到影响。
   * **举例:** 用户可能认为 `:focus + div` 只会影响紧跟在获得焦点的元素后面的 `div` 元素，但实际上，获得焦点的元素本身也可能被标记为 `childrenOrSiblingsAffectedByFocus`。

* **编程错误 (编写 JavaScript 时):**  开发者可能在 JavaScript 中动态修改 DOM 结构或元素状态，而没有考虑到 CSS 伪类可能带来的样式重算开销，导致性能问题。理解这些 "affected by" 标志可以帮助开发者更好地优化性能。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中与网页交互:** 用户可能点击了一个可以获得焦点的元素（例如一个输入框或设置了 `tabindex` 的 `div`），从而激活了 `:focus` 伪类。
2. **浏览器解析 HTML 和 CSS:** Blink 引擎解析网页的 HTML 和 CSS，构建 DOM 树和 CSSOM 树。
3. **样式计算和匹配:** 当元素的伪类状态发生变化时，Blink 引擎会重新计算样式，并根据 CSS 选择器匹配规则找到受影响的元素。
4. **标记受影响的元素:**  `affected_by_pseudo_test.cc` 中测试的核心就在于验证 Blink 引擎是否正确地标记了哪些元素受到了伪类的影响，例如设置了 `childrenOrSiblingsAffectedByFocus` 标志或与 `:has()` 相关的标志。
5. **触发布局和渲染:**  被标记为受影响的元素会触发后续的布局和渲染流程，以便将新的样式应用到页面上。

**总结来说，`affected_by_pseudo_test.cc` 的第一部分为测试 Blink 引擎如何追踪 CSS 伪类对 DOM 元素的影响奠定了基础，定义了测试框架和一些关键的辅助工具，用于验证在各种场景下，Blink 引擎是否正确地识别了需要进行样式重算的元素。**

### 提示词
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class AffectedByPseudoTest : public PageTestBase {
 protected:
  struct ElementResult {
    const blink::HTMLQualifiedName tag;
    bool children_or_siblings_affected_by;
  };

  void SetHtmlInnerHTML(const char* html_content);
  void CheckElementsForFocus(const base::span<ElementResult> expected) const;

  enum AffectedByFlagName {
    kAffectedBySubjectHas,
    kAffectedByNonSubjectHas,
    kAncestorsOrAncestorSiblingsAffectedByHas,
    kSiblingsAffectedByHas,
    kSiblingsAffectedByHasForSiblingRelationship,
    kSiblingsAffectedByHasForSiblingDescendantRelationship,
    kAffectedByPseudoInHas,
    kAncestorsOrSiblingsAffectedByHoverInHas,
    kAffectedByLogicalCombinationsInHas
  };
  void CheckAffectedByFlagsForHas(
      const char* element_id,
      std::map<AffectedByFlagName, bool> expected) const;
  void CheckAffectedByFlagsForHasInShadowTree(
      const char* shadow_host_id,
      const char* element_id,
      std::map<AffectedByFlagName, bool> expected) const;
  Element* GetShadowTreeElementById(const char* shadow_host_id,
                                    const char* element_id) const;

 private:
  void CheckAffectedByFlagsForHasInternal(
      const char* shadow_host_id,
      const char* element_id,
      std::map<AffectedByFlagName, bool> expected) const;
};

void AffectedByPseudoTest::SetHtmlInnerHTML(const char* html_content) {
  GetDocument().documentElement()->setInnerHTML(String::FromUTF8(html_content));
  UpdateAllLifecyclePhasesForTest();
}

void AffectedByPseudoTest::CheckElementsForFocus(
    const base::span<ElementResult> expected) const {
  HTMLElement* element = GetDocument().body();

  for (const ElementResult& result : expected) {
    ASSERT_TRUE(element);
    EXPECT_TRUE(element->HasTagName(result.tag));
    EXPECT_TRUE(element->GetComputedStyle());
    EXPECT_EQ(result.children_or_siblings_affected_by,
              element->ChildrenOrSiblingsAffectedByFocus());
    element = Traversal<HTMLElement>::Next(*element);
  }
}

Element* AffectedByPseudoTest::GetShadowTreeElementById(
    const char* shadow_host_id,
    const char* element_id) const {
  ShadowRoot* shadow_root = GetElementById(shadow_host_id)->GetShadowRoot();
  DCHECK(shadow_root) << "#" << shadow_host_id << " must have shadow root";
  return shadow_root->getElementById(AtomicString(element_id));
}

void AffectedByPseudoTest::CheckAffectedByFlagsForHas(
    const char* element_id,
    std::map<AffectedByFlagName, bool> expected) const {
  CheckAffectedByFlagsForHasInternal(/* shadow_host_id */ nullptr, element_id,
                                     std::move(expected));
}

void AffectedByPseudoTest::CheckAffectedByFlagsForHasInShadowTree(
    const char* shadow_host_id,
    const char* element_id,
    std::map<AffectedByFlagName, bool> expected) const {
  CheckAffectedByFlagsForHasInternal(shadow_host_id, element_id,
                                     std::move(expected));
}

void AffectedByPseudoTest::CheckAffectedByFlagsForHasInternal(
    const char* shadow_host_id,
    const char* element_id,
    std::map<AffectedByFlagName, bool> expected) const {
  Element* element;
  if (shadow_host_id) {
    element = GetShadowTreeElementById(shadow_host_id, element_id);
  } else {
    element = GetElementById(element_id);
  }
  bool actual;
  const char* flag_name = nullptr;
  for (auto iter : expected) {
    switch (iter.first) {
      case kAffectedBySubjectHas:
        actual = element->AffectedBySubjectHas();
        flag_name = "AffectedBySubjectHas";
        break;
      case kAffectedByNonSubjectHas:
        actual = element->AffectedByNonSubjectHas();
        flag_name = "AffectedByNonSubjectHas";
        break;
      case kAncestorsOrAncestorSiblingsAffectedByHas:
        actual = element->AncestorsOrAncestorSiblingsAffectedByHas();
        flag_name = "AncestorsOrAncestorSiblingsAffectedByHas";
        break;
      case kSiblingsAffectedByHas:
        actual = element->GetSiblingsAffectedByHasFlags();
        flag_name = "SiblingsAffectedByHas";
        break;
      case kSiblingsAffectedByHasForSiblingRelationship:
        actual = element->HasSiblingsAffectedByHasFlags(
            SiblingsAffectedByHasFlags::kFlagForSiblingRelationship);
        flag_name = "SiblingsAffectedByHasForSiblingRelationship";
        break;
      case kSiblingsAffectedByHasForSiblingDescendantRelationship:
        actual = element->HasSiblingsAffectedByHasFlags(
            SiblingsAffectedByHasFlags::kFlagForSiblingDescendantRelationship);
        flag_name = "SiblingsAffectedByHasForSiblingDescendantRelationship";
        break;
      case kAffectedByPseudoInHas:
        actual = element->AffectedByPseudoInHas();
        flag_name = "AffectedByPseudoInHas";
        break;
      case kAncestorsOrSiblingsAffectedByHoverInHas:
        actual = element->AncestorsOrSiblingsAffectedByHoverInHas();
        flag_name = "AncestorsOrSiblingsAffectedByHoverInHas";
        break;
      case kAffectedByLogicalCombinationsInHas:
        actual = element->AffectedByLogicalCombinationsInHas();
        flag_name = "AffectedByLogicalCombinationsInHas";
        break;
    }
    DCHECK(flag_name);
    if (iter.second == actual) {
      continue;
    }

    ADD_FAILURE() << "#" << element_id << " : " << flag_name << " should be "
                  << (iter.second ? "true" : "false") << " but "
                  << (actual ? "true" : "false");
  }
}

// ":focus div" will mark ascendants of all divs with
// childrenOrSiblingsAffectedByFocus.
TEST_F(AffectedByPseudoTest, FocusedAscendant) {
  ElementResult expected[] = {{html_names::kBodyTag, true},
                              {html_names::kDivTag, true},
                              {html_names::kDivTag, false},
                              {html_names::kDivTag, false},
                              {html_names::kSpanTag, false}};

  SetHtmlInnerHTML(R"HTML(
    <head>
    <style>:focus div { background-color: pink }</style>
    </head>
    <body>
    <div><div></div></div>
    <div><span></span></div>
    </body>
  )HTML");

  CheckElementsForFocus(expected);
}

// "body:focus div" will mark the body element with
// childrenOrSiblingsAffectedByFocus.
TEST_F(AffectedByPseudoTest, FocusedAscendantWithType) {
  ElementResult expected[] = {{html_names::kBodyTag, true},
                              {html_names::kDivTag, false},
                              {html_names::kDivTag, false},
                              {html_names::kDivTag, false},
                              {html_names::kSpanTag, false}};

  SetHtmlInnerHTML(R"HTML(
    <head>
    <style>body:focus div { background-color: pink }</style>
    </head>
    <body>
    <div><div></div></div>
    <div><span></span></div>
    </body>
  )HTML");

  CheckElementsForFocus(expected);
}

// ":not(body):focus div" should not mark the body element with
// childrenOrSiblingsAffectedByFocus.
// Note that currently ":focus:not(body)" does not do the same. Then the :focus
// is checked and the childrenOrSiblingsAffectedByFocus flag set before the
// negated type selector is found.
TEST_F(AffectedByPseudoTest, FocusedAscendantWithNegatedType) {
  ElementResult expected[] = {{html_names::kBodyTag, false},
                              {html_names::kDivTag, true},
                              {html_names::kDivTag, false},
                              {html_names::kDivTag, false},
                              {html_names::kSpanTag, false}};

  SetHtmlInnerHTML(R"HTML(
    <head>
    <style>:not(body):focus div { background-color: pink }</style>
    </head>
    <body>
    <div><div></div></div>
    <div><span></span></div>
    </body>
  )HTML");

  CheckElementsForFocus(expected);
}

// Checking current behavior for ":focus + div", but this is a BUG or at best
// sub-optimal. The focused element will also in this case get
// childrenOrSiblingsAffectedByFocus even if it's really a sibling. Effectively,
// the whole sub-tree of the focused element will have styles recalculated even
// though none of the children are affected. There are other mechanisms that
// makes sure the sibling also gets its styles recalculated.
TEST_F(AffectedByPseudoTest, FocusedSibling) {
  ElementResult expected[] = {{html_names::kBodyTag, false},
                              {html_names::kDivTag, true},
                              {html_names::kSpanTag, false},
                              {html_names::kDivTag, false}};

  SetHtmlInnerHTML(R"HTML(
    <head>
    <style>:focus + div { background-color: pink }</style>
    </head>
    <body>
    <div>
      <span></span>
    </div>
    <div></div>
    </body>
  )HTML");

  CheckElementsForFocus(expected);
}

TEST_F(AffectedByPseudoTest, AffectedByFocusUpdate) {
  // Check that when focussing the outer div in the document below, you only
  // get a single element style recalc.

  SetHtmlInnerHTML(R"HTML(
    <style>:focus { border: 1px solid lime; }</style>
    <div id=d tabIndex=1>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  unsigned start_count = GetStyleEngine().StyleForElementCount();

  GetElementById("d")->Focus();
  UpdateAllLifecyclePhasesForTest();

  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;

  ASSERT_EQ(1U, element_count);
}

TEST_F(AffectedByPseudoTest, ChildrenOrSiblingsAffectedByFocusUpdate) {
  // Check that when focussing the outer div in the document below, you get a
  // style recalc for the whole subtree.

  SetHtmlInnerHTML(R"HTML(
    <style>:focus div { border: 1px solid lime; }</style>
    <div id=d tabIndex=1>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  unsigned start_count = GetStyleEngine().StyleForElementCount();

  GetElementById("d")->Focus();
  UpdateAllLifecyclePhasesForTest();

  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;

  ASSERT_EQ(11U, element_count);
}

TEST_F(AffectedByPseudoTest, InvalidationSetFocusUpdate) {
  // Check that when focussing the outer div in the document below, you get a
  // style recalc for the outer div and the class=a div only.

  SetHtmlInnerHTML(R"HTML(
    <style>:focus .a { border: 1px solid lime; }</style>
    <div id=d tabIndex=1>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div class='a'></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  unsigned start_count = GetStyleEngine().StyleForElementCount();

  GetElementById("d")->Focus();
  UpdateAllLifecyclePhasesForTest();

  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;

  ASSERT_EQ(2U, element_count);
}

TEST_F(AffectedByPseudoTest, NoInvalidationSetFocusUpdate) {
  // Check that when focussing the outer div in the document below, you get a
  // style recalc for the outer div only. The invalidation set for :focus will
  // include 'a', but the id=d div should be affectedByFocus, not
  // childrenOrSiblingsAffectedByFocus.

  SetHtmlInnerHTML(R"HTML(
    <style>#nomatch:focus .a { border: 1px solid lime; }</style>
    <div id=d tabIndex=1>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div></div>
    <div class='a'></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  unsigned start_count = GetStyleEngine().StyleForElementCount();

  GetElementById("d")->Focus();
  UpdateAllLifecyclePhasesForTest();

  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;

  ASSERT_EQ(1U, element_count);
}

TEST_F(AffectedByPseudoTest, FocusWithinCommonAncestor) {
  // Check that when changing the focus between 2 elements we don't need a style
  // recalc for all the ancestors affected by ":focus-within".

  SetHtmlInnerHTML(R"HTML(
    <style>div:focus-within { background-color: lime; }</style>
    <div>
      <div>
        <div id=focusme1 tabIndex=1></div>
        <div id=focusme2 tabIndex=2></div>
      <div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  unsigned start_count = GetStyleEngine().StyleForElementCount();

  GetElementById("focusme1")->Focus();
  UpdateAllLifecyclePhasesForTest();

  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;

  EXPECT_EQ(3U, element_count);

  start_count += element_count;

  GetElementById("focusme2")->Focus();
  UpdateAllLifecyclePhasesForTest();

  element_count = GetStyleEngine().StyleForElementCount() - start_count;

  // Only "focusme1" & "focusme2" elements need a recalc thanks to the common
  // ancestor strategy.
  EXPECT_EQ(2U, element_count);
}

TEST_F(AffectedByPseudoTest, HoverScrollbar) {
  SetHtmlInnerHTML(
      "<style>div::-webkit-scrollbar:hover { color: pink; }</style>"
      "<div id=div1></div>");

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetElementById("div1")->GetComputedStyle()->AffectedByHover());
}

TEST_F(AffectedByPseudoTest,
       AffectedBySubjectHasAndAncestorsOrAncestorSiblingsAffectedByHas) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(.b) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4></div>
      </div>
      <div id=div5 class='a'>
        <div id=div6></div>
        <div id=div7 class='b'></div>
      </div>
      <div id=div8>
        <div id=div9></div>
        <div id=div10></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div8", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedBySubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div10")->setAttribute(html_names::kClassAttr,
                                        AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div7")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
}

TEST_F(AffectedByPseudoTest,
       AffectedByPseudoInHasAndAncestorsOrSiblingsAffectedByHoverInHas1) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(.b:hover) { background-color: lime; }
      .c:has(:hover) { background-color: green; }
      .d:has(.e) { background-color: blue }
    </style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4></div>
      </div>
      <div id=div5 class='a'>
        <div id=div6></div>
        <div id=div7 class='b'></div>
      </div>
      <div id=div8 class='c'>
        <div id=div9></div>
        <div id=div10></div>
      </div>
      <div id=div11 class='d'>
        <div id=div12></div>
        <div id=div13></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div8", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div3")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div4")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div3")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div4")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div6")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div7")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div7")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div9")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div9")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div10")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div10")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div12")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div12")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div13")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div13")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(AffectedByPseudoTest,
       AffectedByPseudoInHasAndAncestorsOrSiblingsAffectedByHoverInHas2) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(.b:hover) .f { background-color: lime; }
      .c:has(:hover) .g { background-color: green; }
      .d:has(.e) .h { background-color: blue }
    </style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4></div>
        <div><div class='f'></div></div>
      </div>
      <div id=div5 class='a'>
        <div id=div6></div>
        <div id=div7 class='b'></div>
        <div><div class='f'></div></div>
      </div>
      <div id=div8 class='c'>
        <div id=div9></div>
        <div id=div10></div>
        <div><div class='g'></div></div>
      </div>
      <div id=div11 class='d'>
        <div id=div12></div>
        <div id=div13></div>
        <div><div class='h'></div></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div8", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div10", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedByPseudoInHas, false},
                {kAncestorsOrSiblingsAffectedByHoverInHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div3")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div4")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div3")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div4")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngi
```