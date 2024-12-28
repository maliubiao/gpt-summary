Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to understand the functionality tested by `html_select_element_test.cc`. This means identifying what aspects of the `HTMLSelectElement` are being verified.

2. **High-Level Structure Scan:**  First, I'd scan the file for key elements:
    * **Includes:**  These give hints about what other parts of the Blink engine are involved. I see includes for `HTMLSelectElement`, `HTMLOptionElement`, `Document`, `CSS`, `LayoutTheme`, etc. This immediately tells me the tests are about the `select` HTML element and its related components.
    * **Test Fixture:** The `HTMLSelectElementTest` class, inheriting from `PageTestBase`, signals this is a unit test environment interacting with a simulated web page. The `SetUp` and `TearDown` methods suggest initialization and cleanup.
    * **Helper Functions:**  Functions like `GetSelectType`, `FirstSelectableOption`, etc., indicate common operations being tested on the `HTMLSelectElement`.
    * **`TEST_F` Macros:**  These are the actual test cases. Each `TEST_F` focuses on a specific aspect of `HTMLSelectElement` functionality.

3. **Analyzing Individual Tests:** This is the core of the analysis. I'd go through each `TEST_F` and try to understand its purpose. Here's how I'd approach a few examples:

    * **`SetAutofillValuePreservesEditedState`:**  The name is quite descriptive. The test sets up a `select` element, then calls `SetAutofillValue` in different states (user edited, not edited) and checks the `UserHasEditedTheField` flag. This clearly tests the interaction between autofill and user interaction tracking.

    * **`SaveRestoreSelectSingleFormControlState` and `SaveRestoreSelectMultipleFormControlState`:** The names suggest testing the saving and restoring of the `select` element's state. Looking at the code, it creates a `select` element, saves its state using `SaveFormControlState`, potentially modifies the `select` (e.g., deselecting options), and then uses `RestoreFormControlState`. The assertions verify that the original state is correctly restored. This relates to form submission and page navigation where state needs to be preserved.

    * **`FirstSelectableOption`, `LastSelectableOption`, `NextSelectableOption`, `PreviousSelectableOption`:** These tests use various HTML structures (disabled options, `optgroup`, hidden options) and verify the correct logic for finding the "selectable" options in a `select` element. This is crucial for keyboard navigation and accessibility.

    * **Tests with "Crash" in the name (e.g., `ScrollToOptionAfterLayoutCrash`, `CrashOnAttachingMenuList`):** These are regression tests. They target specific bugs that caused crashes in the past. The test itself usually sets up a scenario that previously triggered the crash. The "pass" condition is the absence of a crash.

    * **`SelectMultipleOptionsByPopup`:** This test interacts with JavaScript (the `onchange` handler) and simulates user interaction with the popup (through `SelectMultipleOptionsByPopup`). It verifies that the `onchange` event is fired correctly based on changes in selection.

4. **Connecting to Web Technologies (HTML, CSS, JavaScript):**  As I analyze each test, I explicitly think about how it relates to the front-end technologies:

    * **HTML:** The tests directly manipulate HTML structure (creating `<select>`, `<option>`, `<optgroup>`). The `SetHtmlInnerHTML` function is central to this.
    * **CSS:** Some tests involve CSS styling (e.g., `position:fixed`, `display:none`). This tests how styling affects the behavior and rendering of the `select` element.
    * **JavaScript:** Tests like `SelectMultipleOptionsByPopup` explicitly involve JavaScript event handlers (`onchange`). The tests verify the correct execution of these handlers.

5. **Identifying Logic and Assumptions:** For tests involving logical operations (like finding selectable options), I try to understand the underlying assumptions and how the logic works. For instance, the tests for `NextSelectableOption` and `PreviousSelectableOption` implicitly assume a certain order of options within the `select` element.

6. **Finding Potential User/Programming Errors:** I look for test cases that highlight common mistakes developers might make when using the `<select>` element. For example:
    * Incorrectly assuming `SetAutofillValue` will trigger `onchange` events or modify the "user edited" state.
    * Not handling cases where options are dynamically added or removed.
    * Issues with saving and restoring form state, which can lead to unexpected behavior when navigating back and forth in the browser history.

7. **Synthesizing the Information:** Finally, I organize the information gathered from the individual test analyses into a comprehensive summary that covers the functionality, relationships to web technologies, logic/assumptions, and potential errors. This involves grouping related tests and summarizing their findings concisely. For example, grouping the tests related to selectable options together.

By following this process, I can systematically analyze the C++ test file and extract the relevant information in a structured way. The key is to connect the low-level C++ code to the higher-level concepts of web development.
这个C++源代码文件 `html_select_element_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `blink::HTMLSelectElement` 类的功能。 `HTMLSelectElement` 类对应于HTML中的 `<select>` 元素。

以下是该文件的主要功能以及与 JavaScript, HTML, CSS 的关系和示例：

**主要功能:**

1. **测试 `<select>` 元素的核心功能:** 该文件包含了大量的单元测试，用于验证 `HTMLSelectElement` 类的各种方法和属性是否按预期工作。 这包括：
    * **状态管理:**  测试保存和恢复 `<select>` 元素的状态，包括选中的选项。
    * **选项选择逻辑:**  测试选择选项的各种方法，包括通过代码设置 `selectedIndex` 和模拟用户在下拉列表中的选择。
    * **可选择选项的查找:** 测试查找第一个、最后一个、下一个和上一个可选择的选项的逻辑（排除禁用的或隐藏的选项）。
    * **弹出窗口行为:** 测试弹出选择列表的显示和隐藏。
    * **自动填充:** 测试自动填充值时的行为，并确保不会意外更改用户编辑状态。
    * **工具提示 (Tooltip):** 测试 `<select>` 元素的默认工具提示，特别是当它是 `required` 并且/或者在 `<form>` 中时。
    * **多选 (multiple) 支持:** 测试多选 `<select>` 元素的行为，包括通过弹出窗口选择多个选项。
    * **错误处理和崩溃预防:** 包含了一些测试用例，用于模拟可能导致崩溃的场景，例如在布局或样式计算过程中移除选项或修改属性。

**与 JavaScript, HTML, CSS 的关系和示例:**

* **HTML:**  该测试文件通过 `SetHtmlInnerHTML` 函数动态创建 HTML 结构，包含 `<select>` 元素及其子元素 `<option>` 和 `<optgroup>`。 这些 HTML 结构是测试的基础。

   ```c++
   SetHtmlInnerHTML(
       "<!DOCTYPE HTML><select id='sel'>"
       "<option value='111' selected>111</option>"
       "<option value='222'>222</option></select>");
   ```
   这个例子创建了一个带有两个选项的 `<select>` 元素，其中第一个选项被默认选中。

* **JavaScript:**  某些测试用例涉及到 JavaScript 的交互，特别是通过 `onchange` 事件处理程序。测试会验证在特定操作后是否触发了 `onchange` 事件。

   ```c++
   SetHtmlInnerHTML(
       "<select multiple onchange='this.remove();'>"
       "<option>o0</option><option>o1</option></select>");
   EXPECT_TRUE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{}))
       << "Onchange handler should not be executed.";
   ```
   在这个例子中，当多选 `<select>` 元素的值发生变化时，会执行 JavaScript 代码 `this.remove()`，将该 `<select>` 元素从 DOM 中移除。测试验证了在特定选择操作后，`onchange` 事件是否被触发。

* **CSS:** 测试文件中会设置 `<select>` 元素的 CSS 样式，以验证样式对元素行为的影响。 例如，测试固定定位的 `<select>` 元素的边界。

   ```c++
   SetHtmlInnerHTML(
       "<select style='position:fixed; top:12.3px; height:24px; "
       "-webkit-appearance:none;'><option>o1</select>");
   ```
   这个例子设置了 `<select>` 元素的 `position`, `top`, `height` 和 `-webkit-appearance` 样式，并测试了其可见边界。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一个包含多个 `<option>` 元素的 `<select>` 元素，其中一些选项被禁用或通过 CSS 隐藏。
* **输出:**  `FirstSelectableOption` 函数应该返回第一个既没有被禁用也没有被隐藏的 `<option>` 元素。 `LastSelectableOption`，`NextSelectableOption` 和 `PreviousSelectableOption` 函数也会根据禁用和隐藏状态返回相应的可选择选项。

   例如，对于以下 HTML：
   ```html
   <select>
     <option id="o1" disabled>Option 1</option>
     <option id="o2" style="display:none">Option 2</option>
     <option id="o3">Option 3</option>
   </select>
   ```
   * `FirstSelectableOption` 的输出应该是 ID 为 "o3" 的 `<option>` 元素。
   * `LastSelectableOption` 的输出应该是 ID 为 "o3" 的 `<option>` 元素。
   * `NextSelectableOption` 在 `nullptr` 输入的情况下输出应该是 ID 为 "o3" 的 `<option>` 元素。
   * `PreviousSelectableOption` 在 `nullptr` 输入的情况下输出应该是 ID 为 "o3" 的 `<option>` 元素。

**用户或者编程常见的使用错误举例:**

1. **错误地假设 `SetAutofillValue` 会触发 `onchange` 事件:**  开发者可能会认为通过代码设置自动填充值会像用户手动选择一样触发 `onchange` 事件。但测试用例 `SetAutofillValuePreservesEditedState` 表明 `SetAutofillValue` 不会改变用户的编辑状态，通常也不会触发 `onchange` (除非内部逻辑有其他触发机制)。

2. **在 JavaScript 中手动操作 `<option>` 元素的 `selected` 属性，而没有考虑到 `<select>` 元素的逻辑:**  开发者可能会直接修改 `<option>` 的 `selected` 属性，而没有意识到 `<select>` 元素自身可能维护着选中状态。这可能导致状态不一致。测试用例 `SaveRestoreSelectSingleFormControlState` 和 `SaveRestoreSelectMultipleFormControlState` 强调了应该通过 `<select>` 元素的方法来管理选项的选中状态。

3. **假设禁用的或隐藏的选项会被算作可选择的选项:**  开发者在编写与 `<select>` 元素交互的 JavaScript 代码时，可能会错误地遍历所有 `<option>` 元素，而没有考虑到 `disabled` 或 `style="display:none"` 的选项。测试用例 `FirstSelectableOption`, `LastSelectableOption`, `NextSelectableOption`, 和 `PreviousSelectableOption` 验证了引擎正确处理了这些情况。

4. **在动态添加或移除 `<option>` 元素后，没有刷新 `<select>` 元素的状态或重新渲染:**  如果通过 JavaScript 动态修改了 `<select>` 元素的子元素，开发者可能需要确保浏览器的渲染引擎能够正确地更新显示。 某些崩溃测试用例（例如 `SetRecalcListItemsByOptgroupRemoval` 和 `SlotAssignmentRecalcDuringOptionRemoval`)  旨在防止在这些动态修改场景下出现问题。

总而言之，`html_select_element_test.cc` 是一个至关重要的测试文件，它确保了 Chromium 渲染引擎中 `<select>` 元素功能的正确性和稳定性，并覆盖了与 HTML、CSS 和 JavaScript 的多种交互场景，同时也帮助避免了开发者在使用 `<select>` 元素时可能遇到的常见错误。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/html_select_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/forms/html_select_element.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/select_type.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

class HTMLSelectElementTest : public PageTestBase {
 protected:
  void SetUp() override;
  void TearDown() override;

  SelectType& GetSelectType(const HTMLSelectElement& select) {
    return *select.select_type_;
  }

  HTMLOptionElement* FirstSelectableOption(const HTMLSelectElement& select) {
    return GetSelectType(select).FirstSelectableOption();
  }
  HTMLOptionElement* LastSelectableOption(const HTMLSelectElement& select) {
    return GetSelectType(select).LastSelectableOption();
  }
  HTMLOptionElement* NextSelectableOption(const HTMLSelectElement& select,
                                          HTMLOptionElement* option) {
    return GetSelectType(select).NextSelectableOption(option);
  }
  HTMLOptionElement* PreviousSelectableOption(const HTMLSelectElement& select,
                                              HTMLOptionElement* option) {
    return GetSelectType(select).PreviousSelectableOption(option);
  }

  bool FirstSelectIsConnectedAfterSelectMultiple(const Vector<int>& indices) {
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    select->Focus();
    select->SelectMultipleOptionsByPopup(indices);
    return select->isConnected();
  }

  String MenuListLabel() const {
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    return select->InnerElement().textContent();
  }

 private:
  bool original_delegates_flag_;
};

void HTMLSelectElementTest::SetUp() {
  PageTestBase::SetUp();
  GetDocument().SetMimeType(AtomicString("text/html"));
  original_delegates_flag_ =
      LayoutTheme::GetTheme().DelegatesMenuListRendering();
}

void HTMLSelectElementTest::TearDown() {
  LayoutTheme::GetTheme().SetDelegatesMenuListRenderingForTesting(
      original_delegates_flag_);
  PageTestBase::TearDown();
}

// Tests that HtmlSelectElement::SetAutofillValue() doesn't change the
// `user_has_edited_the_field_` attribute of the field.
TEST_F(HTMLSelectElementTest, SetAutofillValuePreservesEditedState) {
  SetHtmlInnerHTML(
      "<!DOCTYPE HTML><select id='sel'>"
      "<option value='111' selected>111</option>"
      "<option value='222'>222</option></select>");
  HTMLSelectElement* select = To<HTMLSelectElement>(GetElementById("sel"));

  select->ClearUserHasEditedTheField();
  select->SetAutofillValue("222", WebAutofillState::kAutofilled);
  EXPECT_EQ(select->UserHasEditedTheField(), false);

  select->SetUserHasEditedTheField();
  select->SetAutofillValue("111", WebAutofillState::kAutofilled);
  EXPECT_EQ(select->UserHasEditedTheField(), true);
}

TEST_F(HTMLSelectElementTest, SaveRestoreSelectSingleFormControlState) {
  SetHtmlInnerHTML(
      "<!DOCTYPE HTML><select id='sel'>"
      "<option value='111' id='0'>111</option>"
      "<option value='222'>222</option>"
      "<option value='111' selected id='2'>!666</option>"
      "<option value='999'>999</option></select>");
  Element* element = GetElementById("sel");
  auto* opt0 = To<HTMLOptionElement>(GetElementById("0"));
  auto* opt2 = To<HTMLOptionElement>(GetElementById("2"));

  // Save the select element state, and then restore again.
  // Test passes if the restored state is not changed.
  EXPECT_EQ(2, To<HTMLSelectElement>(element)->selectedIndex());
  EXPECT_FALSE(opt0->Selected());
  EXPECT_TRUE(opt2->Selected());
  HTMLFormControlElementWithState* select = To<HTMLSelectElement>(element);
  FormControlState select_state = select->SaveFormControlState();
  EXPECT_EQ(2U, select_state.ValueSize());

  // Clear the selected state, to be restored by restoreFormControlState.
  To<HTMLSelectElement>(select)->setSelectedIndex(-1);
  ASSERT_FALSE(opt2->Selected());

  // Restore
  select->RestoreFormControlState(select_state);
  EXPECT_EQ(2, To<HTMLSelectElement>(element)->selectedIndex());
  EXPECT_FALSE(opt0->Selected());
  EXPECT_TRUE(opt2->Selected());
  EXPECT_EQ("!666",
            To<HTMLSelectElement>(element)->InnerElement().textContent());
}

TEST_F(HTMLSelectElementTest, SaveRestoreSelectMultipleFormControlState) {
  SetHtmlInnerHTML(
      "<!DOCTYPE HTML><select id='sel' multiple>"
      "<option value='111' id='0'>111</option>"
      "<option value='222'>222</option>"
      "<option value='111' selected id='2'>!666</option>"
      "<option value='999' selected id='3'>999</option></select>");

  auto* opt0 = To<HTMLOptionElement>(GetElementById("0"));
  auto* opt2 = To<HTMLOptionElement>(GetElementById("2"));
  auto* opt3 = To<HTMLOptionElement>(GetElementById("3"));

  // Save the select element state, and then restore again.
  // Test passes if the selected options are not changed.
  EXPECT_FALSE(opt0->Selected());
  EXPECT_TRUE(opt2->Selected());
  EXPECT_TRUE(opt3->Selected());
  HTMLFormControlElementWithState* select =
      To<HTMLSelectElement>(GetElementById("sel"));
  FormControlState select_state = select->SaveFormControlState();
  EXPECT_EQ(4U, select_state.ValueSize());

  // Clear the selected state, to be restored by restoreFormControlState.
  opt2->SetSelected(false);
  opt3->SetSelected(false);
  ASSERT_FALSE(opt2->Selected());
  ASSERT_FALSE(opt3->Selected());

  // Restore
  select->RestoreFormControlState(select_state);
  EXPECT_FALSE(opt0->Selected());
  EXPECT_TRUE(opt2->Selected());
  EXPECT_TRUE(opt3->Selected());
}

TEST_F(HTMLSelectElementTest, RestoreUnmatchedFormControlState) {
  // We had a bug that SelectedOption() and last_on_change_option_ were
  // mismatched in OptionToBeShown(). It happened when
  // RestoreFormControlState() couldn't find matched OPTIONs.
  // crbug.com/627833.

  SetHtmlInnerHTML(R"HTML(
    <select id='sel'>
    <option selected>Default</option>
    <option id='2'>222</option>
    </select>
  )HTML");
  Element* element = GetElementById("sel");
  auto* opt2 = To<HTMLOptionElement>(GetElementById("2"));

  To<HTMLSelectElement>(element)->setSelectedIndex(1);
  // Save the current state.
  HTMLFormControlElementWithState* select = To<HTMLSelectElement>(element);
  FormControlState select_state = select->SaveFormControlState();
  EXPECT_EQ(2U, select_state.ValueSize());

  // Reset the status.
  select->Reset();
  ASSERT_FALSE(opt2->Selected());
  element->RemoveChild(opt2);

  // Restore
  select->RestoreFormControlState(select_state);
  EXPECT_EQ(-1, To<HTMLSelectElement>(element)->selectedIndex());
  EXPECT_EQ(nullptr, To<HTMLSelectElement>(element)->OptionToBeShown());
}

TEST_F(HTMLSelectElementTest, VisibleBoundsInLocalRoot) {
  SetHtmlInnerHTML(
      "<select style='position:fixed; top:12.3px; height:24px; "
      "-webkit-appearance:none;'><option>o1</select>");
  auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
  ASSERT_NE(select, nullptr);
  gfx::Rect bounds = select->VisibleBoundsInLocalRoot();
  EXPECT_EQ(24, bounds.height());
}

TEST_F(HTMLSelectElementTest, PopupIsVisible) {
  SetHtmlInnerHTML("<select><option>o1</option></select>");
  auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
  ASSERT_NE(select, nullptr);
  EXPECT_FALSE(select->PopupIsVisible());
  select->ShowPopup();
  EXPECT_TRUE(select->PopupIsVisible());
  GetDocument().Shutdown();
  EXPECT_FALSE(select->PopupIsVisible());
}

TEST_F(HTMLSelectElementTest, FirstSelectableOption) {
  {
    SetHtmlInnerHTML("<select></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ(nullptr, FirstSelectableOption(*select));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", FirstSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1 disabled></option><option "
        "id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", FirstSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1 style='display:none'></option><option "
        "id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", FirstSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><optgroup><option id=o1></option><option "
        "id=o2></option></optgroup></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", FirstSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
}

TEST_F(HTMLSelectElementTest, LastSelectableOption) {
  {
    SetHtmlInnerHTML("<select></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ(nullptr, LastSelectableOption(*select));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", LastSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2 "
        "disabled></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", LastSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2 "
        "style='display:none'></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", LastSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><optgroup><option id=o1></option><option "
        "id=o2></option></optgroup></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", LastSelectableOption(*select)->FastGetAttribute(
                        html_names::kIdAttr));
  }
}

TEST_F(HTMLSelectElementTest, NextSelectableOption) {
  {
    SetHtmlInnerHTML("<select></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ(nullptr, NextSelectableOption(*select, nullptr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", NextSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1 disabled></option><option "
        "id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", NextSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1 style='display:none'></option><option "
        "id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", NextSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><optgroup><option id=o1></option><option "
        "id=o2></option></optgroup></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", NextSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    auto* option = To<HTMLOptionElement>(GetElementById("o1"));
    EXPECT_EQ("o2", NextSelectableOption(*select, option)
                        ->FastGetAttribute(html_names::kIdAttr));

    EXPECT_EQ(nullptr,
              NextSelectableOption(
                  *select, To<HTMLOptionElement>(GetElementById("o2"))));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><optgroup><option "
        "id=o2></option></optgroup></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    auto* option = To<HTMLOptionElement>(GetElementById("o1"));
    EXPECT_EQ("o2", NextSelectableOption(*select, option)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
}

TEST_F(HTMLSelectElementTest, PreviousSelectableOption) {
  {
    SetHtmlInnerHTML("<select></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ(nullptr, PreviousSelectableOption(*select, nullptr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", PreviousSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2 "
        "disabled></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", PreviousSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2 "
        "style='display:none'></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o1", PreviousSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><optgroup><option id=o1></option><option "
        "id=o2></option></optgroup></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    EXPECT_EQ("o2", PreviousSelectableOption(*select, nullptr)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><option id=o2></option></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    auto* option = To<HTMLOptionElement>(GetElementById("o2"));
    EXPECT_EQ("o1", PreviousSelectableOption(*select, option)
                        ->FastGetAttribute(html_names::kIdAttr));

    EXPECT_EQ(nullptr,
              PreviousSelectableOption(
                  *select, To<HTMLOptionElement>(GetElementById("o1"))));
  }
  {
    SetHtmlInnerHTML(
        "<select><option id=o1></option><optgroup><option "
        "id=o2></option></optgroup></select>");
    auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
    auto* option = To<HTMLOptionElement>(GetElementById("o2"));
    EXPECT_EQ("o1", PreviousSelectableOption(*select, option)
                        ->FastGetAttribute(html_names::kIdAttr));
  }
}

TEST_F(HTMLSelectElementTest, ActiveSelectionEndAfterOptionRemoval) {
  SetHtmlInnerHTML(
      "<select size=4>"
      "<optgroup><option selected>o1</option></optgroup></select>");
  auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
  // ActiveSelectionEnd*() work only in the listbox mode, which Android
  // doesn't have.
  if (select->UsesMenuList())
    return;
  auto* option = To<HTMLOptionElement>(select->firstChild()->firstChild());
  EXPECT_EQ(1, select->ActiveSelectionEndListIndex());
  select->firstChild()->removeChild(option);
  EXPECT_EQ(-1, select->ActiveSelectionEndListIndex());
  select->AppendChild(option);
  EXPECT_EQ(1, select->ActiveSelectionEndListIndex());
}

TEST_F(HTMLSelectElementTest, DefaultToolTip) {
  SetHtmlInnerHTML(
      "<select size=4><option value="
      ">Placeholder</option><optgroup><option>o2</option></optgroup></select>");
  auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
  auto* option = To<Element>(select->firstChild());
  auto* optgroup = To<Element>(option->nextSibling());

  EXPECT_EQ(String(), select->DefaultToolTip())
      << "defaultToolTip for SELECT without FORM and without required "
         "attribute should return null string.";
  EXPECT_EQ(select->DefaultToolTip(), option->DefaultToolTip());
  EXPECT_EQ(select->DefaultToolTip(), optgroup->DefaultToolTip());

  select->SetBooleanAttribute(html_names::kRequiredAttr, true);
  EXPECT_EQ("<<ValidationValueMissingForSelect>>", select->DefaultToolTip())
      << "defaultToolTip for SELECT without FORM and with required attribute "
         "should return a valueMissing message.";
  EXPECT_EQ(select->DefaultToolTip(), option->DefaultToolTip());
  EXPECT_EQ(select->DefaultToolTip(), optgroup->DefaultToolTip());

  auto* form = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  GetDocument().body()->AppendChild(form);
  form->AppendChild(select);
  EXPECT_EQ("<<ValidationValueMissingForSelect>>", select->DefaultToolTip())
      << "defaultToolTip for SELECT with FORM and required attribute should "
         "return a valueMissing message.";
  EXPECT_EQ(select->DefaultToolTip(), option->DefaultToolTip());
  EXPECT_EQ(select->DefaultToolTip(), optgroup->DefaultToolTip());

  form->SetBooleanAttribute(html_names::kNovalidateAttr, true);
  EXPECT_EQ(String(), select->DefaultToolTip())
      << "defaultToolTip for SELECT with FORM[novalidate] and required "
         "attribute should return null string.";
  EXPECT_EQ(select->DefaultToolTip(), option->DefaultToolTip());
  EXPECT_EQ(select->DefaultToolTip(), optgroup->DefaultToolTip());

  option->remove();
  optgroup->remove();
  EXPECT_EQ(String(), option->DefaultToolTip());
  EXPECT_EQ(String(), optgroup->DefaultToolTip());
}

TEST_F(HTMLSelectElementTest, SetRecalcListItemsByOptgroupRemoval) {
  SetHtmlInnerHTML(
      "<select><optgroup><option>sub1</option><option>sub2</option></"
      "optgroup></select>");
  auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
  select->setInnerHTML("");
  // PASS if setInnerHTML didn't have a check failure.
}

TEST_F(HTMLSelectElementTest, ScrollToOptionAfterLayoutCrash) {
  // crbug.com/737447
  // This test passes if no crash.
  SetHtmlInnerHTML(R"HTML(
    <style>*:checked { position:fixed; }</style>
    <select multiple><<option>o1</option><option
    selected>o2</option></select>
  )HTML");
}

TEST_F(HTMLSelectElementTest, CrashOnAttachingMenuList) {
  // crbug.com/1044834
  // This test passes if no crash.
  SetHtmlInnerHTML("<select><option selected style='direction:rtl'>o1");
  GetDocument().UpdateStyleAndLayoutTree();
  auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
  ASSERT_TRUE(select->GetLayoutObject());

  // Detach LayoutMenuList.
  select->setAttribute(html_names::kStyleAttr, AtomicString("display:none;"));
  GetDocument().UpdateStyleAndLayoutTree();
  ASSERT_FALSE(select->GetLayoutObject());

  // Attach LayoutMenuList again.  It triggered null-dereference in
  // LayoutMenuList::AdjustInnerStyle().
  select->removeAttribute(html_names::kStyleAttr);
  GetDocument().UpdateStyleAndLayoutTree();
  ASSERT_TRUE(select->GetLayoutObject());
}

TEST_F(HTMLSelectElementTest, CrashOnAttachingMenuList2) {
  // crbug.com/1065125
  // This test passes if no crash.
  SetHtmlInnerHTML("<select><optgroup><option>o1</select>");
  auto* select = To<HTMLSelectElement>(GetDocument().body()->firstChild());
  select->setTextContent("foo");

  // Detach LayoutObject.
  select->setAttribute(html_names::kStyleAttr, AtomicString("display:none;"));
  GetDocument().UpdateStyleAndLayoutTree();

  // Attach LayoutObject.  It triggered a DCHECK failure in
  // MenuListSelectType::OptionToBeShown()
  select->removeAttribute(html_names::kStyleAttr);
  GetDocument().UpdateStyleAndLayoutTree();
}

TEST_F(HTMLSelectElementTest, SlotAssignmentRecalcDuringOptionRemoval) {
  // crbug.com/1056094
  // This test passes if no CHECK failure about IsSlotAssignmentRecalcForbidden.
  SetHtmlInnerHTML("<div dir=auto><select><option>option0");
  auto* select = GetDocument().body()->firstChild()->firstChild();
  auto* option = select->firstChild();
  select->appendChild(option);
  option->remove();
}

// crbug.com/1060039
TEST_F(HTMLSelectElementTest, SelectMultipleOptionsByPopup) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  LayoutTheme::GetTheme().SetDelegatesMenuListRenderingForTesting(true);

  // Select the same set of options.
  {
    SetHtmlInnerHTML(
        "<select multiple onchange='this.remove();'>"
        "<option>o0</option><option>o1</option></select>");
    EXPECT_TRUE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{}))
        << "Onchange handler should not be executed.";
  }
  {
    SetHtmlInnerHTML(
        "<select multiple onchange='this.remove();'>"
        "<option>o0</option><option selected>o1</option></select>");
    EXPECT_TRUE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{1}))
        << "Onchange handler should not be executed.";
  }

  // 0 old selected options -> 1+ selected options
  {
    SetHtmlInnerHTML(
        "<select multiple onchange='this.remove();'>"
        "<option>o0</option><option>o1</option></select>");
    EXPECT_FALSE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{0}))
        << "Onchange handler should be executed.";
  }

  // 1+ old selected options -> more selected options
  {
    SetHtmlInnerHTML(
        "<select multiple onchange='this.remove();'>"
        "<option>o0</option><option selected>o1</option></select>");
    EXPECT_FALSE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{0, 1}))
        << "Onchange handler should be executed.";
  }

  // 1+ old selected options -> 0 selected options
  {
    SetHtmlInnerHTML(
        "<select multiple onchange='this.remove();'>"
        "<option>o0</option><option selected>o1</option></select>");
    EXPECT_FALSE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{}))
        << "Onchange handler should be executed.";
  }

  // Multiple old selected options -> less selected options
  {
    SetHtmlInnerHTML(
        "<select multiple onchange='this.remove();'>"
        "<option selected>o0</option><option selected>o1</option></select>");
    EXPECT_FALSE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{1}))
        << "Onchange handler should be executed.";
  }

  // Check if the label is correctly updated.
  {
    SetHtmlInnerHTML(
        "<select multiple>"
        "<option selected>o0</option><option selected>o1</option></select>");
    EXPECT_EQ("2 selected", MenuListLabel());
    EXPECT_TRUE(FirstSelectIsConnectedAfterSelectMultiple(Vector<int>{1}));
    EXPECT_EQ("o1", MenuListLabel());
  }
}

TEST_F(HTMLSelectElementTest, IntrinsicInlineSizeOverflow) {
  // crbug.com/1068338
  // This test passes if UBSAN doesn't complain.
  SetHtmlInnerHTML(
      "<select style='word-spacing:1073741824em;'>"
      "<option>abc def</option></select>");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
}

TEST_F(HTMLSelectElementTest, AddingNotOwnedOption) {
  // crbug.com/1077556
  auto& doc = GetDocument();
  SetHtmlInnerHTML("<select>");
  auto* select = To<HTMLSelectElement>(doc.body()->firstChild());
  // Append <div><optgroup></optgroup></div> to the SELECT.
  // We can't do it with the HTML parser.
  auto* optgroup = doc.CreateRawElement(html_names::kOptgroupTag);
  select->appendChild(doc.CreateRawElement(html_names::kDivTag))
      ->appendChild(optgroup);
  optgroup->appendChild(doc.CreateRawElement(html_names::kOptionTag));
  // This test passes if the above appendChild() doesn't cause a DCHECK failure.
}

TEST_F(HTMLSelectElementTest, ChangeRenderingCrash) {
  SetHtmlInnerHTML(R"HTML(
    <select id="sel">
      <option id="opt"></option>
    </select>
  )HTML");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // Make the option element the style recalc root.
  GetElementById("opt")->SetInlineStyleProperty(CSSPropertyID::kColor, "green");
  // Changing the size attribute changes the rendering. This should not trigger
  // a DCHECK failure updating the style recalc root.
  GetElementById("sel")->setAttribute(html_names::kSizeAttr, AtomicString("2"));
}

TEST_F(HTMLSelectElementTest, ChangeRenderingCrash2) {
  SetHtmlInnerHTML(R"HTML(
    <select id="sel">
      <optgroup id="grp">
        <option id="opt"></option>
      </optgroup>
    </select>
  )HTML");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // Make the select UA slot the style recalc root.
  GetElementById("opt")->SetInlineStyleProperty(CSSPropertyID::kColor, "green");
  GetElementById("grp")->SetInlineStyleProperty(CSSPropertyID::kColor, "green");
  // Changing the multiple attribute changes the rendering. This should not
  // trigger a DCHECK failure updating the style recalc root.
  GetElementById("sel")->setAttribute(html_names::kMultipleAttr,
                                      AtomicString("true"));
}

TEST_F(HTMLSelectElementTest, ChangeRenderingCrash3) {
  SetHtmlInnerHTML(R"HTML(
    <div id="host">
      <select id="select">
        <option></option>
      </select>
    </div>
    <div id="green">Green</div>
  )HTML");

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* select = GetDocument().getElementById(AtomicString("select"));
  auto* green = GetDocument().getElementById(AtomicString("green"));

  // Make sure the select is outside the flat tree.
  host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // Changing the select rendering should not clear the style recalc root set by
  // the color change on #green.
  green->SetInlineStyleProperty(CSSPropertyID::kColor, "green");
  select->setAttribute(html_names::kMultipleAttr, AtomicString("true"));

  EXPECT_TRUE(GetDocument().GetStyleEngine().NeedsStyleRecalc());
  EXPECT_TRUE(green->NeedsStyleRecalc());
}

TEST_F(HTMLSelectElementTest, ChangeRenderingSelectRoot) {
  // This test exercises the path in StyleEngine::ChangeRenderingForHTMLSelect()
  // where the select does not have a GetStyleRecalcParent().
  SetHtmlInnerHTML(R"HTML(
    <select id="sel">
      <option></option>
    </select>
  )HTML");

  auto* select = GetElementById("sel");

  // Make the select the root element.
  select->remove();
  GetDocument().documentElement()->remove();
  GetDocument().appendChild(select);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // Changing the multiple attribute changes the rendering.
  select->setAttribute(html_names::kMultipleAttr, AtomicString("true"));
  EXPECT_TRUE(GetDocument().GetStyleEngine().NeedsStyleRecalc());
  EXPECT_TRUE(select->NeedsStyleRecalc());
}

}  // namespace blink

"""

```