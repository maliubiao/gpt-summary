Response:
Let's break down the thought process for analyzing the `focus_controller_test.cc` file.

**1. Initial Understanding of the File:**

* **File Name:** `focus_controller_test.cc` strongly suggests this file contains tests for the `FocusController` class. The `.cc` extension indicates C++ source code.
* **Copyright and Includes:** The initial lines confirm it's a Chromium Blink engine file and includes necessary headers like `<memory>`, `gtest/gtest.h`, and Blink-specific headers. These inclusions hint at the types of functionalities being tested (memory management, unit testing framework, and Blink core components).

**2. Identifying the Core Class Under Test:**

* The filename and the inclusion of `"third_party/blink/renderer/core/page/focus_controller.h"` clearly identify `FocusController` as the main subject.

**3. Analyzing the Test Structure:**

* **Test Fixture:** The presence of `class FocusControllerTest : public PageTestBase` immediately tells us that a test fixture is being used. This provides a controlled environment for running tests, likely with a pre-configured `Document` and `Page` object.
* **`TEST_F` Macro:** The frequent use of `TEST_F(FocusControllerTest, ...)` indicates individual test cases within the fixture. Each `TEST_F` aims to verify a specific aspect of the `FocusController`.

**4. Deconstructing Individual Test Cases (Iterative Process):**

For each test case, I would follow a similar pattern:

* **Test Name:**  The name itself often gives a good clue about the functionality being tested. For example, `SetInitialFocus`, `DoNotCrash1`, `SVGFocusableElementInForm`, `NextFocusableElementForImeAndAutofill`, etc.
* **`GetDocument().body()->setInnerHTML(...)`:** This is a common pattern for setting up the DOM structure for the test. I would analyze the HTML string to understand the elements involved and their attributes (like `id`, `tabindex`, `type`).
* **Element Selection:**  Lines like `GetElementById("...")` or `To<Element>(GetDocument().body()->firstChild())` show how specific elements are being targeted for manipulation or assertion.
* **`GetFocusController()...`:** This is the primary way the test interacts with the `FocusController`. I would note the specific methods being called (e.g., `SetInitialFocus`, `AdvanceFocus`, `NextFocusableElementForImeAndAutofill`, `FindFocusableElementAfter`).
* **`EXPECT_EQ(...)`:**  These are the assertions that verify the expected behavior. I would focus on what is being compared and what the expected outcome is.
* **Specific Focus Areas:**
    * **Focus Navigation:** Tests involving `AdvanceFocus`, `FindFocusableElementAfter`, and `NextFocusableElementForImeAndAutofill` directly relate to how focus moves between elements.
    * **Initial Focus:** `SetInitialFocus` tests how the initial focus on a page is handled.
    * **IME and Autofill:**  Tests with "ImeAndAutofill" in the name focus on how the focus controller interacts with input methods and autofill functionalities.
    * **Form Submission:** Tests involving forms and input types like `text`, `password`, `submit`, `checkbox`, and `select` indicate the focus controller's role in form navigation and submission.
    * **Shadow DOM:** Tests like `DoNotCrash1`, `DoNotCrash2`, and `FindScopeOwnerSlotOrReadingFlowContainer` that use `AttachShadowRootForTesting` demonstrate the handling of focus within Shadow DOM.
    * **SVG and Iframes:** Tests specifically mentioning `SVGFocusableElementInForm` and `NextFocusableElementForImeAndAutofill_Captcha` (involving iframes) highlight the handling of focus in these specific contexts.
    * **Pseudo-elements:**  The tests involving `ScrollMarkerGroupPseudoElement` and scrollbar buttons demonstrate how the focus controller interacts with focusable pseudo-elements.
* **"DoNotCrash" Tests:** These tests are important for robustness, ensuring the `FocusController` doesn't crash in specific edge cases.

**5. Identifying Relationships with Web Technologies:**

* **JavaScript:**  The tests manipulate the DOM (setting `innerHTML`, getting elements), which is a fundamental part of JavaScript's interaction with web pages. Focus changes trigger JavaScript events (like `focus` and `blur`).
* **HTML:** The tests heavily rely on HTML structure to define focusable elements (`input`, elements with `tabindex`), forms, and the order of elements.
* **CSS:** The `FocusHasChangedShouldInvalidateFocusStyle` test directly relates to CSS `:focus` styles. The scrollbar button and marker tests also use CSS pseudo-elements.

**6. Inferring Functionality and Potential Issues:**

Based on the test cases, I could infer the following about the `FocusController`:

* Manages the currently focused element.
* Implements logic for moving focus forward and backward (sequential navigation).
* Handles initial focus on a page.
* Has special logic for form navigation, potentially skipping certain elements (like checkboxes) for IME/autofill.
* Considers Shadow DOM boundaries when moving focus.
* Needs to avoid crashes in certain scenarios (hence the "DoNotCrash" tests).
* Interacts with pseudo-elements (scroll markers, scroll buttons).

Potential User/Programming Errors:

* Incorrectly setting `tabindex` can lead to unexpected focus order.
* Not handling focus changes in JavaScript event handlers can lead to accessibility issues.
* Assuming a specific focus order without considering the underlying logic of the `FocusController`.

**7. Debugging Scenario:**

To construct the debugging scenario, I thought about a common user interaction with a form and how focus moves through it. Then, I linked that interaction back to the specific test cases in the file.

**8. Structuring the Output:**

Finally, I organized the information into the requested categories: functionality, relationships with web technologies, logical reasoning, common errors, and debugging scenario. I tried to provide concrete examples from the code within each category.
这个文件 `blink/renderer/core/page/focus_controller_test.cc` 是 Chromium Blink 渲染引擎中 `FocusController` 类的单元测试文件。它的主要功能是 **验证 `FocusController` 类的各种功能是否正常工作**。

下面分别列举它的功能，以及与 JavaScript, HTML, CSS 的关系，逻辑推理，常见错误和调试线索：

**1. 功能列举:**

这个测试文件涵盖了 `FocusController` 的多个核心功能，包括但不限于：

* **设置初始焦点 (SetInitialFocus):** 测试在页面加载时如何设置初始的焦点元素。
* **焦点前进和后退 (AdvanceFocus):** 测试在页面中向前或向后移动焦点的功能，包括处理文本节点作为焦点起始点的情况。
* **激活/停用焦点控制器 (SetActiveOnInactiveDocument):** 测试在文档不活跃的情况下设置焦点控制器的状态。
* **处理 SVG 元素焦点 (SVGFocusableElementInForm):** 测试在表单中含有可聚焦的 SVG 元素时，焦点控制器的行为，特别是在 IME (输入法) 和自动填充场景下。
* **查找焦点元素 (FindFocusableAfterElement):** 测试在给定元素之后查找下一个或上一个可聚焦元素的功能。
* **IME 和自动填充的焦点元素查找 (NextFocusableElementForImeAndAutofill):** 测试在 IME 和自动填充场景下，如何查找下一个或上一个需要用户输入的焦点元素，并考虑表单结构、特定类型的输入元素（如 checkbox, select, submit）以及 iframe 的影响。
* **查找作用域所有者 Slot 或 ReadingFlowContainer (FindScopeOwnerSlotOrReadingFlowContainer):** 测试在 Shadow DOM 环境下，如何找到焦点作用域的所有者。
* **焦点改变时刷新样式 (FocusHasChangedShouldInvalidateFocusStyle):** 测试当焦点改变时，是否会触发样式的重新计算，例如 `:focus` 伪类的应用。
* **处理 iframe 中的焦点 (NextFocusableElementForImeAndAutofill_Captcha):** 测试在包含 iframe 的表单中，焦点控制器的行为，特别是对于像验证码这样的元素。
* **处理滚动条标记的焦点 (ScrollMarkersAreFocusable):** 测试滚动条的标记是否可以获得焦点。
* **处理滚动按钮的焦点 (ScrollButtonsAreFocusable):** 测试滚动容器的滚动按钮是否可以获得焦点。
* **防止崩溃 (DoNotCrash1, DoNotCrash2):**  这些测试旨在覆盖一些可能导致程序崩溃的边界情况，确保 `FocusController` 的鲁棒性。

**2. 与 JavaScript, HTML, CSS 的关系:**

`FocusController` 的功能与 JavaScript, HTML, CSS 紧密相关：

* **HTML:** `FocusController` 的核心功能是管理页面中元素的焦点状态。HTML 结构定义了页面中的元素以及它们是否可以通过 `tabindex` 属性获得焦点。测试用例中大量使用 `GetDocument().body()->setInnerHTML(...)` 来构建 HTML 结构，例如：
    ```c++
    GetDocument().body()->setInnerHTML("<input id='first'><div id='second'></div><input id='third'><div id='fourth' tabindex='0'></div>");
    ```
    这个 HTML 结构定义了四个元素，其中两个 `<input>` 元素默认可以获得焦点，而最后一个 `<div>` 元素通过 `tabindex='0'` 也变得可以获得焦点。
* **JavaScript:**  JavaScript 可以通过 DOM API 来操作焦点，例如使用 `element.focus()` 和 `element.blur()` 方法。`FocusController` 内部的逻辑会影响这些 JavaScript API 的行为。虽然这个测试文件主要是 C++ 代码，但它测试的功能最终会影响 JavaScript 与页面焦点的交互。例如，测试 `SetInitialFocus` 时，最终浏览器会根据 `FocusController` 的逻辑来决定哪个元素获得初始焦点，这可以通过 JavaScript 代码 `document.activeElement` 来观察。
* **CSS:** CSS 的 `:focus` 伪类允许开发者为获得焦点的元素应用特定的样式。`FocusController` 负责管理哪个元素获得焦点，从而影响 `:focus` 伪类的应用。测试用例 `FocusHasChangedShouldInvalidateFocusStyle` 就验证了当焦点改变时，相关的 CSS 样式是否会正确更新。例如：
    ```c++
    SetBodyInnerHTML(
        "<style>#host:focus { color:#A0A0A0; }</style>"
        "<div id=host></div>");
    ```
    这个 CSS 规则定义了当 id 为 `host` 的元素获得焦点时，其颜色会变为 `#A0A0A0`。测试会验证 `FocusController` 的焦点改变是否会触发这个样式的应用。

**3. 逻辑推理 (假设输入与输出):**

以下是一些测试用例的逻辑推理示例：

* **测试用例 `SetInitialFocus`:**
    * **假设输入:**  HTML 结构包含 `<input>` 和 `<textarea>` 元素。在调用 `SetInitialFocus` 之前，通过 `input->Focus()` 和 `input->blur()` 模拟用户点击了第一个输入框，然后移开了焦点。
    * **预期输出:** 调用 `GetFocusController().SetInitialFocus(mojom::blink::FocusType::kForward)` 后，第一个 `<input>` 元素应该获得焦点，即使之前用户曾点击过它。这是因为 `SetInitialFocus` 应该忽略之前的手动焦点设置。
* **测试用例 `FindFocusableAfterElement`:**
    * **假设输入:**  HTML 结构 `<input id='first'><div id='second'></div><input id='third'><div id='fourth' tabindex='0'></div>`。
    * **预期输出:**
        * `GetFocusController().FindFocusableElementAfter(*first, mojom::blink::FocusType::kForward)` 应该返回 `third` (下一个可聚焦的元素)。
        * `GetFocusController().FindFocusableElementAfter(*fourth, mojom::blink::FocusType::kBackward)` 应该返回 `third` (上一个可聚焦的元素)。
* **测试用例 `NextFocusableElementForImeAndAutofill` (在表单中):**
    * **假设输入:** HTML 表单包含 `<input type='text' id='username'>`, `<input type='password' id='password'>`, `<input type='submit' value='Login'>`。
    * **预期输出:**
        * 从 `username` 元素向前查找 (`kForward`)，应该返回 `password` 元素。
        * 从 `password` 元素向后查找 (`kBackward`)，应该返回 `username` 元素。
        * 从 `password` 元素向前查找，因为遇到了 submit 按钮，应该返回 `nullptr`，表示这是表单中需要用户输入的最后一个字段。

**4. 用户或编程常见的使用错误:**

* **错误地设置 `tabindex`:**
    * **举例:**  用户可能将 `tabindex` 设置为负数，期望元素不可聚焦，但实际上负数的 `tabindex` 仍然可以使元素通过编程方式获得焦点。
    * **测试如何体现:** 测试用例会检查各种 `tabindex` 值对焦点顺序的影响，例如 `tabindex="0"` 和 `tabindex` 为正数的情况。
* **忘记处理焦点事件:**
    * **举例:** 开发者可能创建了一个自定义的可聚焦元素，但忘记监听 `focus` 和 `blur` 事件来更新其内部状态或样式。
    * **测试如何体现:** 虽然这个测试文件不直接测试 JavaScript 事件，但它验证了 `FocusController` 的核心逻辑是否正确，这会间接影响焦点事件的触发和目标。
* **假设固定的焦点顺序:**
    * **举例:** 开发者可能假设焦点会按照 DOM 树的顺序移动，但实际上浏览器会根据一定的规则（例如 `tabindex` 的值）来确定焦点顺序。
    * **测试如何体现:** 多个测试用例旨在验证焦点移动的正确顺序，包括向前和向后移动，以及在不同类型的元素和结构中（如 Shadow DOM）的焦点移动。
* **在不活跃的文档上操作焦点:**
    * **举例:**  在某些复杂的 Web 应用中，可能会在文档被卸载或隐藏时尝试设置焦点，这可能导致错误。
    * **测试如何体现:** `SetActiveOnInactiveDocument` 测试用例专门验证了在文档不活跃的情况下设置焦点控制器的状态，以确保不会出现崩溃或其他错误。

**5. 用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在调试与页面焦点相关的问题时，可能会发现代码执行到了 `FocusController` 相关的逻辑。以下是一些可能的用户操作和代码路径：

* **用户按下 Tab 键:** 这是最常见的触发焦点移动的操作。当用户按下 Tab 键时，浏览器会调用 `FocusController::AdvanceFocus(kForward)` 来将焦点移动到下一个可聚焦的元素。测试用例 `AdvanceFocus` 就模拟了这种场景。
* **用户按下 Shift + Tab 键:**  这会将焦点向后移动，浏览器会调用 `FocusController::AdvanceFocus(kBackward)`。
* **用户点击鼠标:**  当用户点击一个可以获得焦点的元素时，浏览器会调用相关方法将焦点设置到该元素。
* **JavaScript 代码调用 `element.focus()`:** JavaScript 可以通过编程方式设置元素的焦点，这会触发 `FocusController` 的相关逻辑。
* **页面加载完成:** 在页面加载完成后，浏览器会根据一定的规则设置初始焦点，这涉及到 `FocusController::SetInitialFocus` 的调用。

**调试线索:**

* **断点:** 在 `FocusController` 的关键方法（例如 `AdvanceFocus`, `FindFocusableElementAfter`, `SetFocused`）中设置断点，可以观察焦点移动的流程和状态变化。
* **日志输出:**  可以在 `FocusController` 的代码中添加日志输出，记录焦点移动的目标元素、原因等信息。
* **使用浏览器的开发者工具:**
    * **Elements 面板:** 可以查看当前获得焦点的元素 (通常会高亮显示)。
    * **Event Listeners 面板:** 可以查看与焦点相关的事件监听器 (如 `focus`, `blur`)。
    * **Performance 面板:**  可以分析焦点操作引起的性能问题。
* **检查 `tabindex` 属性:**  确认页面中元素的 `tabindex` 属性是否设置正确，是否符合预期的焦点顺序。
* **检查 Shadow DOM 结构:** 如果涉及到 Shadow DOM，需要理解焦点如何在 Shadow DOM 边界之间移动。
* **查看错误日志:**  如果 `FocusController` 遇到了异常情况，可能会在浏览器的错误日志中输出相关信息。

总而言之，`blink/renderer/core/page/focus_controller_test.cc` 是一个非常重要的测试文件，它确保了 Blink 渲染引擎中焦点管理功能的正确性和稳定性。通过分析这个文件，我们可以深入了解浏览器是如何处理页面焦点的，以及各种用户操作和代码是如何触发相关逻辑的。

### 提示词
```
这是目录为blink/renderer/core/page/focus_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/page/focus_controller.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class FocusControllerTest : public PageTestBase {
 private:
  void SetUp() override { PageTestBase::SetUp(gfx::Size()); }
};

TEST_F(FocusControllerTest, SetInitialFocus) {
  GetDocument().body()->setInnerHTML("<input><textarea>");
  auto* input = To<Element>(GetDocument().body()->firstChild());
  // Set sequential focus navigation point before the initial focus.
  input->Focus();
  input->blur();
  GetFocusController().SetInitialFocus(mojom::blink::FocusType::kForward);
  EXPECT_EQ(input, GetDocument().FocusedElement())
      << "We should ignore sequential focus navigation starting point in "
         "setInitialFocus().";
}

TEST_F(FocusControllerTest, DoNotCrash1) {
  GetDocument().body()->setInnerHTML(
      "<div id='host'></div>This test is for crbug.com/609012<p id='target' "
      "tabindex='0'></p>");
  // <div> with shadow root
  auto* host = To<Element>(GetDocument().body()->firstChild());
  host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  // "This test is for crbug.com/609012"
  Node* text = host->nextSibling();
  // <p>
  auto* target = To<Element>(text->nextSibling());

  // Set sequential focus navigation point at text node.
  GetDocument().SetSequentialFocusNavigationStartingPoint(text);

  GetFocusController().AdvanceFocus(mojom::blink::FocusType::kForward);
  EXPECT_EQ(target, GetDocument().FocusedElement())
      << "This should not hit assertion and finish properly.";
}

TEST_F(FocusControllerTest, DoNotCrash2) {
  GetDocument().body()->setInnerHTML(
      "<p id='target' tabindex='0'></p>This test is for crbug.com/609012<div "
      "id='host'></div>");
  // <p>
  auto* target = To<Element>(GetDocument().body()->firstChild());
  // "This test is for crbug.com/609012"
  Node* text = target->nextSibling();
  // <div> with shadow root
  auto* host = To<Element>(text->nextSibling());
  host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  // Set sequential focus navigation point at text node.
  GetDocument().SetSequentialFocusNavigationStartingPoint(text);

  GetFocusController().AdvanceFocus(mojom::blink::FocusType::kBackward);
  EXPECT_EQ(target, GetDocument().FocusedElement())
      << "This should not hit assertion and finish properly.";
}

TEST_F(FocusControllerTest, SetActiveOnInactiveDocument) {
  // Test for crbug.com/700334
  GetDocument().Shutdown();
  // Document::shutdown() detaches document from its frame, and thus
  // document().page() becomes nullptr.
  // Use DummyPageHolder's page to retrieve FocusController.
  GetPage().GetFocusController().SetActive(true);
}

// This test is for crbug.com/733218
TEST_F(FocusControllerTest, SVGFocusableElementInForm) {
  GetDocument().body()->setInnerHTML(
      "<form>"
      "<input id='first'>"
      "<svg width='100px' height='100px' tabindex='0'>"
      "<circle cx='50' cy='50' r='30' />"
      "</svg>"
      "<input id='last'>"
      "</form>");

  auto* form = To<Element>(GetDocument().body()->firstChild());
  auto* first = To<Element>(form->firstChild());
  auto* last = To<Element>(form->lastChild());

  Element* next = GetFocusController().NextFocusableElementForImeAndAutofill(
      first, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next, last)
      << "SVG Element should be skipped even when focusable in form.";

  Element* prev = GetFocusController().NextFocusableElementForImeAndAutofill(
      next, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(prev, first)
      << "SVG Element should be skipped even when focusable in form.";
}

TEST_F(FocusControllerTest, FindFocusableAfterElement) {
  GetDocument().body()->setInnerHTML(
      "<input id='first'><div id='second'></div><input id='third'><div "
      "id='fourth' tabindex='0'></div>");
  Element* first = GetElementById("first");
  Element* second = GetElementById("second");
  Element* third = GetElementById("third");
  Element* fourth = GetElementById("fourth");
  EXPECT_EQ(third, GetFocusController().FindFocusableElementAfter(
                       *first, mojom::blink::FocusType::kForward));
  EXPECT_EQ(third, GetFocusController().FindFocusableElementAfter(
                       *second, mojom::blink::FocusType::kForward));
  EXPECT_EQ(fourth, GetFocusController().FindFocusableElementAfter(
                        *third, mojom::blink::FocusType::kForward));
  EXPECT_EQ(nullptr, GetFocusController().FindFocusableElementAfter(
                         *fourth, mojom::blink::FocusType::kForward));

  EXPECT_EQ(nullptr, GetFocusController().FindFocusableElementAfter(
                         *first, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(first, GetFocusController().FindFocusableElementAfter(
                       *second, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(first, GetFocusController().FindFocusableElementAfter(
                       *third, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(third, GetFocusController().FindFocusableElementAfter(
                       *fourth, mojom::blink::FocusType::kBackward));

  EXPECT_EQ(nullptr, GetFocusController().FindFocusableElementAfter(
                         *first, mojom::blink::FocusType::kNone));
}

TEST_F(FocusControllerTest, NextFocusableElementForImeAndAutofill) {
  GetDocument().body()->setInnerHTML(
      "<form>"
      "  <input type='text' id='username'>"
      "  <input type='password' id='password'>"
      "  <input type='submit' value='Login'>"
      "</form>");
  Element* username = GetElementById("username");
  Element* password = GetElementById("password");
  ASSERT_TRUE(username);
  ASSERT_TRUE(password);

  EXPECT_EQ(password,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                username, mojom::blink::FocusType::kForward));
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         username, mojom::blink::FocusType::kBackward));

  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         password, mojom::blink::FocusType::kForward));
  EXPECT_EQ(username,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                password, mojom::blink::FocusType::kBackward));
}

TEST_F(FocusControllerTest, NextFocusableElementForImeAndAutofill_NoFormTag) {
  GetDocument().body()->setInnerHTML(
      "  <input type='text' id='username'>"
      "  <input type='password' id='password'>"
      "  <input type='submit' value='Login'>");
  Element* username = GetElementById("username");
  Element* password = GetElementById("password");
  ASSERT_TRUE(username);
  ASSERT_TRUE(password);

  EXPECT_EQ(password,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                username, mojom::blink::FocusType::kForward));
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         username, mojom::blink::FocusType::kBackward));

  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         password, mojom::blink::FocusType::kForward));
  EXPECT_EQ(username,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                password, mojom::blink::FocusType::kBackward));
}

// Ignore a checkbox to streamline form submission.
TEST_F(FocusControllerTest, NextFocusableElementForImeAndAutofill_Checkbox) {
  GetDocument().body()->setInnerHTML(
      "<form>"
      "  <input type='text' id='username'>"
      "  <input type='password' id='password'>"
      "  <input type='checkbox' id='remember-me'>"
      "  <input type='submit' value='Login'>"
      "</form>");
  Element* username = GetElementById("username");
  Element* password = GetElementById("password");
  ASSERT_TRUE(username);
  ASSERT_TRUE(password);

  EXPECT_EQ(password,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                username, mojom::blink::FocusType::kForward));
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         username, mojom::blink::FocusType::kBackward));

  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         password, mojom::blink::FocusType::kForward));
  EXPECT_EQ(username,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                password, mojom::blink::FocusType::kBackward));
}

// A <select> element should block a form submission.
TEST_F(FocusControllerTest, NextFocusableElementForImeAndAutofill_Select) {
  GetDocument().body()->setInnerHTML(
      "<form>"
      "  <input type='text' id='username'>"
      "  <input type='password' id='password'>"
      "  <select id='login_type'>"
      "    <option value='regular'>Regular</option>"
      "    <option value='invisible'>Invisible</option>"
      "  </select>"
      "  <input type='submit' value='Login'>"
      "</form>");
  Element* username = GetElementById("username");
  Element* password = GetElementById("password");
  Element* login_type = GetElementById("login_type");
  ASSERT_TRUE(username);
  ASSERT_TRUE(password);
  ASSERT_TRUE(login_type);

  EXPECT_EQ(password,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                username, mojom::blink::FocusType::kForward));
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         username, mojom::blink::FocusType::kBackward));

  EXPECT_EQ(login_type,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                password, mojom::blink::FocusType::kForward));
  EXPECT_EQ(username,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                password, mojom::blink::FocusType::kBackward));
}

// A submit button is used to detect the end of a user form within a combined
// form. Combined form is a <form> element that encloses several user form (e.g.
// signin and signup). See the HTML in the test for clarity.
TEST_F(FocusControllerTest,
       NextFocusableElementForImeAndAutofill_SubmitButton) {
  GetDocument().body()->setInnerHTML(
      "<form>"
      "  <div>Login</div>"
      "    <input type='email' id='login_username'>"
      "    <input type='password' id='login_password'>"
      "    <input type='submit' id='login_submit'>"
      "  <div>Create an account</div>"
      "    <input type='email' id='signup_username'>"
      "    <input type='text' id='signup_full_name'>"
      "    <input type='password' id='signup_password'>"
      "    <button type='submit' id='signup_submit'>"
      "  <div>Forgot password?</div>"
      "    <input type='email' id='recover_username'>"
      "    <span>Request a recovery link</span>"
      "</form>");
  // "login_submit" closes the signin form.
  Element* login_password = GetElementById("login_password");
  ASSERT_TRUE(login_password);
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         login_password, mojom::blink::FocusType::kForward));
  Element* signup_username = GetElementById("signup_username");
  ASSERT_TRUE(signup_username);
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         signup_username, mojom::blink::FocusType::kBackward));

  // "signup_password" closes the signup form.
  Element* signup_password = GetElementById("signup_password");
  ASSERT_TRUE(signup_password);
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         signup_password, mojom::blink::FocusType::kForward));
  Element* recover_username = GetElementById("recover_username");
  ASSERT_TRUE(recover_username);
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         recover_username, mojom::blink::FocusType::kBackward));

  // The end of the recovery form is detected just because it the end of <form>.
  EXPECT_EQ(nullptr, GetFocusController().NextFocusableElementForImeAndAutofill(
                         recover_username, mojom::blink::FocusType::kForward));
}

// Test for FocusController::FindScopeOwnerSlotOrReadingFlowContainer().
TEST_F(FocusControllerTest, FindScopeOwnerSlotOrReadingFlowContainer) {
  const char* main_html =
      "<div id='host'>"
      "<div id='inner1'></div>"
      "<div id='inner2'></div>"
      "</div>";

  GetDocument().body()->setInnerHTML(String::FromUTF8(main_html));
  auto* host = To<Element>(GetDocument().body()->firstChild());
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(String::FromUTF8("<slot></slot>"));

  Element* inner1 = GetDocument().QuerySelector(AtomicString("#inner1"));
  Element* inner2 = GetDocument().QuerySelector(AtomicString("#inner2"));
  auto* slot =
      To<HTMLSlotElement>(shadow_root.QuerySelector(AtomicString("slot")));

  EXPECT_EQ(nullptr,
            FocusController::FindScopeOwnerSlotOrReadingFlowContainer(*host));
  EXPECT_EQ(nullptr,
            FocusController::FindScopeOwnerSlotOrReadingFlowContainer(*slot));
  EXPECT_EQ(slot,
            FocusController::FindScopeOwnerSlotOrReadingFlowContainer(*inner1));
  EXPECT_EQ(slot,
            FocusController::FindScopeOwnerSlotOrReadingFlowContainer(*inner2));
}

// crbug.com/1508258
TEST_F(FocusControllerTest, FocusHasChangedShouldInvalidateFocusStyle) {
  SetBodyInnerHTML(
      "<style>#host:focus { color:#A0A0A0; }</style>"
      "<div id=host></div>");
  auto& controller = GetFocusController();
  controller.SetFocused(false);

  auto* host = GetElementById("host");
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div tabindex=0></div>");
  To<Element>(shadow_root.firstChild())->Focus();

  controller.SetActive(true);
  controller.SetFocused(true);
  GetDocument().UpdateStyleAndLayoutTree();
  const auto* style = host->GetComputedStyle();
  EXPECT_EQ(Color(0xA0, 0xA0, 0xA0),
            style->VisitedDependentColor(GetCSSPropertyColor()));
}

class FocusControllerTestWithIframes : public RenderingTest {
 public:
  FocusControllerTestWithIframes()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
};

// A captcha should block a form submission.
TEST_F(FocusControllerTestWithIframes,
       NextFocusableElementForImeAndAutofill_Captcha) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<form>"
      "  <input type='text' id='username'>"
      "  <input type='password' id='password'>"
      "  <iframe id='captcha' src='https://captcha.com'></iframe>"
      "  <button type='submit' value='Login'>"
      "</form>");
  SetChildFrameHTML(
      "<!DOCTYPE html>"
      "<div id='checkbox' tabindex='0'>");
  UpdateAllLifecyclePhasesForTest();

  Element* password = GetElementById("password");
  ASSERT_TRUE(password);

  LocalFrame* child_frame = To<LocalFrame>(GetFrame().Tree().FirstChild());
  ASSERT_TRUE(child_frame);
  Document* child_document = child_frame->GetDocument();
  ASSERT_TRUE(child_document);
  Element* checkbox = child_document->getElementById(AtomicString("checkbox"));
  ASSERT_TRUE(checkbox);

  // |NextFocusableElementForImeAndAutofill| finds another element that needs
  // user input - don't auto-submit after filling in the username and password
  // fields.
  EXPECT_EQ(checkbox,
            GetFocusController().NextFocusableElementForImeAndAutofill(
                password, mojom::blink::FocusType::kForward));
}

TEST_F(FocusControllerTest, ScrollMarkersAreFocusable) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #scroller {
        overflow-y: scroll;
        width: 200px;
        height: 200px;
        scroll-marker-group: after;
        &::scroll-marker-group {
          display: block;
          height: 100px;
        }
        div { height: 200px; }
        div::scroll-marker { content: '-'; }
        div::scroll-marker:focus { opacity: 0.5; }
      }
    </style>
    <input id="pre-input">
    <div id="scroller">
      <div>X</div>
      <div>Y</div>
      <div>Z</div>
    </div>
    <input id="post-input">
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  Element* scroller = GetElementById("scroller");
  Element* pre_input = GetElementById("pre-input");
  Element* post_input = GetElementById("post-input");

  auto* scroll_marker_group = To<ScrollMarkerGroupPseudoElement>(
      scroller->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter));
  ASSERT_TRUE(scroll_marker_group);

  Element* first_scroll_marker =
      scroller->firstElementChild()->GetPseudoElement(kPseudoIdScrollMarker);
  ASSERT_TRUE(first_scroll_marker);

  Element* second_scroll_marker =
      scroller->firstElementChild()->nextElementSibling()->GetPseudoElement(
          kPseudoIdScrollMarker);
  ASSERT_TRUE(second_scroll_marker);

  Element* last_scroll_marker =
      scroller->lastElementChild()->GetPseudoElement(kPseudoIdScrollMarker);
  ASSERT_TRUE(last_scroll_marker);

  EXPECT_EQ(scroller, GetFocusController().FindFocusableElementAfter(
                          *pre_input, mojom::blink::FocusType::kForward));
  EXPECT_EQ(first_scroll_marker,
            GetFocusController().FindFocusableElementAfter(
                *scroller, mojom::blink::FocusType::kForward));
  EXPECT_EQ(post_input,
            GetFocusController().FindFocusableElementAfter(
                *first_scroll_marker, mojom::blink::FocusType::kForward));

  EXPECT_EQ(pre_input, GetFocusController().FindFocusableElementAfter(
                           *scroller, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(scroller,
            GetFocusController().FindFocusableElementAfter(
                *first_scroll_marker, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(first_scroll_marker,
            GetFocusController().FindFocusableElementAfter(
                *post_input, mojom::blink::FocusType::kBackward));

  second_scroll_marker->Focus();
  GetFocusController().SetActive(true);
  GetFocusController().SetFocused(true);
  scroll_marker_group->SetSelected(
      *To<ScrollMarkerPseudoElement>(second_scroll_marker));
  const auto* style = second_scroll_marker->GetComputedStyle();
  EXPECT_TRUE(second_scroll_marker->IsFocused());
  EXPECT_EQ(0.5, style->Opacity());

  // Focusgroup restores last focused element.
  EXPECT_EQ(scroller, GetFocusController().FindFocusableElementAfter(
                          *pre_input, mojom::blink::FocusType::kForward));
  EXPECT_EQ(second_scroll_marker,
            GetFocusController().FindFocusableElementAfter(
                *scroller, mojom::blink::FocusType::kForward));
  EXPECT_EQ(second_scroll_marker,
            GetFocusController().FindFocusableElementAfter(
                *post_input, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(post_input,
            GetFocusController().FindFocusableElementAfter(
                *second_scroll_marker, mojom::blink::FocusType::kForward));
  EXPECT_EQ(scroller,
            GetFocusController().FindFocusableElementAfter(
                *second_scroll_marker, mojom::blink::FocusType::kBackward));
}

TEST_F(FocusControllerTest, ScrollButtonsAreFocusable) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #scroller {
        overflow: scroll;
        width: 200px;
        height: 200px;
        &::scroll-next-button, &::scroll-prev-button { content: "-" }
        &::scroll-next-button:focus,&::scroll-prev-button:focus { opacity: 0.5 }
      }
      #spacer { width: 400px; height: 400px; }
    </style>
    <input id="pre-input">
    <div id="scroller">
      <div id="spacer"></div>
    </div>
    <input id='post-input'>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* scroller = GetElementById("scroller");
  Element* pre_input = GetElementById("pre-input");
  Element* post_input = GetElementById("post-input");

  PseudoElement* scroll_button_next =
      scroller->GetPseudoElement(kPseudoIdScrollNextButton);
  ASSERT_TRUE(scroll_button_next);
  PseudoElement* scroll_button_prev =
      scroller->GetPseudoElement(kPseudoIdScrollPrevButton);
  ASSERT_TRUE(scroll_button_prev);

  EXPECT_EQ(scroller, GetFocusController().FindFocusableElementAfter(
                          *pre_input, mojom::blink::FocusType::kForward));
  EXPECT_EQ(scroll_button_prev,
            GetFocusController().FindFocusableElementAfter(
                *scroller, mojom::blink::FocusType::kForward));
  EXPECT_EQ(scroll_button_next,
            GetFocusController().FindFocusableElementAfter(
                *scroll_button_prev, mojom::blink::FocusType::kForward));
  EXPECT_EQ(post_input,
            GetFocusController().FindFocusableElementAfter(
                *scroll_button_next, mojom::blink::FocusType::kForward));

  EXPECT_EQ(pre_input, GetFocusController().FindFocusableElementAfter(
                           *scroller, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(scroller,
            GetFocusController().FindFocusableElementAfter(
                *scroll_button_prev, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(scroll_button_prev,
            GetFocusController().FindFocusableElementAfter(
                *scroll_button_next, mojom::blink::FocusType::kBackward));
  EXPECT_EQ(scroll_button_next,
            GetFocusController().FindFocusableElementAfter(
                *post_input, mojom::blink::FocusType::kBackward));

  scroll_button_prev->Focus();
  GetFocusController().SetActive(true);
  GetFocusController().SetFocused(true);

  const ComputedStyle* style = scroll_button_prev->GetComputedStyle();
  EXPECT_TRUE(scroll_button_prev->IsFocused());
  EXPECT_EQ(0.5, style->Opacity());
}

}  // namespace blink
```