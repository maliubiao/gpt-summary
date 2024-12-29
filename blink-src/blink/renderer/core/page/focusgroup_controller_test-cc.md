Response:
The user wants to understand the functionality of the `focusgroup_controller_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relation to web technologies (JavaScript, HTML, CSS), provide examples of its logic, highlight potential user/developer errors, and explain how a user's action can lead to this code being executed.

**Plan:**

1. **Overall Purpose:** Determine the primary goal of this test file. It seems to be testing the `FocusgroupController` class.
2. **Individual Tests:** Analyze each `TEST_F` function to understand what specific functionality of the `FocusgroupController` is being tested.
3. **Relation to Web Technologies:** Identify how the tested functionalities relate to concepts in HTML (focus management, tabindex), and how they might be influenced by JavaScript or CSS.
4. **Logic and Examples:** For tests involving logical operations, provide hypothetical inputs and expected outputs to illustrate the logic.
5. **Common Errors:**  Infer potential user or developer errors based on the test cases, especially those testing error conditions.
6. **User Actions and Debugging:** Explain how a user's interaction with a webpage could trigger the code paths tested here and how this file can aid in debugging focus-related issues.
这个文件 `focusgroup_controller_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `FocusgroupController` 类的功能。 `FocusgroupController` 负责管理页面中的焦点组，这是一种允许用户使用键盘箭头键在特定区域内导航焦点的机制。

**主要功能:**

该测试文件通过一系列的单元测试来验证 `FocusgroupController` 的各种功能，主要包括：

1. **判断按键事件对应的焦点组导航方向:**  测试 `FocusgroupControllerUtils::FocusgroupDirectionForEvent()` 函数，判断按下的键盘事件（特别是箭头键）应该在焦点组中向哪个方向移动焦点（向前/向后，行内/块级）。
2. **判断导航方向:** 测试 `FocusgroupControllerUtils::IsDirectionBackward()`, `IsDirectionForward()`, `IsDirectionInline()`, `IsDirectionBlock()` 等函数，用于判断给定的焦点组导航方向是向前还是向后，是行内还是块级。
3. **判断焦点组是否支持特定轴向的导航:** 测试 `FocusgroupControllerUtils::IsAxisSupported()` 函数，判断一个焦点组是否允许在行内或块级方向上进行导航。这与 HTML 属性 `focusgroup` 的值有关。
4. **判断焦点组是否允许在特定方向上循环:** 测试 `FocusgroupControllerUtils::WrapsInDirection()` 函数，判断焦点在到达焦点组的边界时是否会循环到另一端。这与 HTML 属性 `focusgroup` 的 `wrap` 值有关。
5. **判断扩展焦点组是否在特定轴向上扩展:** 测试 `FocusgroupControllerUtils::FocusgroupExtendsInAxis()` 函数，用于判断一个声明为 `focusgroup=extend` 的元素是否允许焦点跳出其边界，并根据方向继续查找焦点。
6. **查找最近的焦点组祖先元素:** 测试 `FocusgroupControllerUtils::FindNearestFocusgroupAncestor()` 函数，给定一个元素和焦点组类型（线性或网格），查找其最近的指定类型的焦点组祖先元素。
7. **查找下一个/上一个元素:** 测试 `FocusgroupControllerUtils::NextElement()` 和 `PreviousElement()` 函数，用于在一个焦点组中查找下一个或上一个可聚焦的元素。
8. **查找焦点组内的最后一个元素:** 测试 `FocusgroupControllerUtils::LastElementWithin()` 函数，查找一个焦点组内最后一个可聚焦的元素。
9. **判断元素是否是焦点组的条目:** 测试 `FocusgroupControllerUtils::IsFocusgroupItem()` 函数，判断一个元素是否属于某个焦点组（直接子元素或可聚焦的元素）。
10. **在网格焦点组中查找特定位置的单元格:** 测试 `FocusgroupControllerUtils::CellAtIndexInRow()` 函数，在网格焦点组中根据索引查找特定行的单元格，并测试在找不到单元格时的不同行为。
11. **在没有聚焦元素或修饰键存在时不移动焦点:** 测试在没有元素被聚焦或按下修饰键（Shift, Ctrl, Meta）时，箭头键导航不会导致焦点移动。
12. **当焦点已经移动时不再次移动焦点:**  测试当因为某些原因焦点在处理箭头键事件之前已经移动到其他元素时，焦点组控制器不会再次尝试移动焦点。

**与 JavaScript, HTML, CSS 的关系:**

*   **HTML:**  该测试文件直接关联 HTML 的焦点管理机制和新的 `focusgroup` 属性。`focusgroup` 属性用于定义焦点组，并可以设置 `extend`（允许焦点跳出）和 `grid`（定义为网格焦点组）等值。测试用例中会动态创建包含不同 `focusgroup` 属性的 HTML 结构，以验证焦点的正确导航。`tabindex` 属性也用于控制元素的聚焦顺序，并在测试中用于模拟不同的可聚焦元素。
    *   **举例:**  测试用例中使用了如下 HTML 结构来创建一个焦点组：
        ```html
        <div id=fg1 focusgroup>
          <span id=item1></span>
          <span id=item2 tabindex=-1></span>
        </div>
        ```
        这里 `focusgroup` 属性将 `div` 元素标记为一个焦点组。
    *   **举例:** 测试用例中使用了 `focusgroup=extend` 来测试扩展焦点组的功能：
        ```html
        <div id=fg2 focusgroup=extend>
          <span id=item3 tabindex=-1></span>
          <div>
            <span id=item4></span>
          </div>
        </div>
        ```
    *   **举例:** 测试用例中使用了 `focusgroup=grid` 来测试网格焦点组的功能：
        ```html
        <table id=table focusgroup=grid>
          <tr>
            <td id=r1c1></td>
            <td id=r1c2></td>
          </tr>
        </table>
        ```
*   **JavaScript:** 虽然测试文件本身是用 C++ 编写的，但它测试的功能直接影响 JavaScript 中与焦点相关的 API 和事件行为。当用户通过键盘导航焦点时，浏览器内部的逻辑（由 `FocusgroupController` 管理）会影响哪个元素最终接收焦点，这会触发 JavaScript 中的 `focus` 和 `blur` 事件。开发者可以使用 JavaScript 来监听和处理这些事件，从而实现自定义的焦点行为。
    *   **举例:** 当用户在一个焦点组内按下箭头键时，`FocusgroupController` 决定下一个被聚焦的元素，然后浏览器会触发该元素的 `focus` 事件。
*   **CSS:** CSS 可以影响元素的可聚焦性和焦点样式，但 `FocusgroupController` 主要关注的是焦点的 *逻辑* 移动，而不是 *视觉* 呈现。CSS 的 `outline` 属性或 `:focus` 伪类可以用来指示哪个元素当前拥有焦点，但这与 `FocusgroupController` 的核心功能无关。

**逻辑推理 (假设输入与输出):**

*   **假设输入:**  一个键盘事件 `KeyDownEvent(ui::DomKey::ARROW_RIGHT)`。
*   **输出:** `FocusgroupControllerUtils::FocusgroupDirectionForEvent()` 函数应该返回 `FocusgroupDirection::kForwardInline`。

*   **假设输入:**  一个键盘事件 `KeyDownEvent(ui::DomKey::ARROW_UP, nullptr, WebInputEvent::kShiftKey)` (按下 Shift 键的同时按下向上箭头键)。
*   **输出:** `FocusgroupControllerUtils::FocusgroupDirectionForEvent()` 函数应该返回 `FocusgroupDirection::kNone`，因为按下了修饰键。

*   **假设输入:**  一个 HTML 结构如下：
    ```html
    <div id=fg focusgroup>
      <span id=item1 tabindex=0></span>
      <span id=item2 tabindex=0></span>
    </div>
    ```
    当前焦点在 `item1` 上，并且触发了一个 `KeyDownEvent(ui::DomKey::ARROW_DOWN)` 事件。
*   **输出:**  `FocusgroupController` 应该将焦点移动到 `item2`。

**用户或编程常见的使用错误:**

*   **错误地嵌套网格焦点组:**  测试用例中提到 "The following is an error" 并创建了一个嵌套的网格焦点组：
    ```html
    <table id=fg3 focusgroup=grid>
      <tr>
        <td id=item5 tabindex=-1>
          <!-- The following is an error. -->
          <div id=fg4 focusgroup=grid>
            <span id=item6 tabindex=-1></span>
            <div id=fg5 focusgroup>
              <span id=item7 tabindex=-1></span>
            </div>
          </div>
        </td>
      </tr>
    </table>
    ```
    这种嵌套可能会导致焦点管理行为不明确或出现意外。用户或开发者可能会误以为这种嵌套结构能够像预期的那样工作。
*   **在不需要的时候使用 `tabindex=-1`:**  在焦点组内部，通常不需要显式地为所有元素设置 `tabindex=-1`。焦点组的目的是使用箭头键进行导航。过度使用 `tabindex=-1` 可能会干扰默认的 Tab 键顺序。
*   **忘记在焦点组中使用可聚焦的元素:**  如果焦点组内没有可聚焦的元素（例如，所有元素都设置了 `tabindex=-1` 并且不是默认可聚焦的元素），那么使用箭头键导航将不会有任何效果。
*   **假设焦点总是停留在触发事件的元素上:**  开发者可能会错误地假设，如果一个元素触发了键盘事件，即使焦点策略应该移动焦点，焦点仍然会停留在该元素上。`FocusgroupController` 的测试用例明确地测试了当焦点在事件处理前被移动后，控制器不会再次移动焦点的情况，这强调了在处理焦点相关事件时需要考虑焦点可能已经发生变化。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户与网页交互:** 用户在一个启用了焦点组功能的网页上进行操作。例如，这个网页可能包含使用 `focusgroup` 属性定义的区域。
2. **按下箭头键:** 用户在焦点位于焦点组内的某个元素上时，按下向上、向下、向左或向右箭头键。
3. **浏览器事件处理:** 浏览器捕获到键盘事件，并将其传递给 Blink 渲染引擎进行处理.
4. **`FocusgroupController` 介入:**  Blink 引擎中的 `FocusgroupController` 会接收到这个键盘事件。它会检查当前聚焦的元素是否在一个焦点组内，以及按下的按键是否是箭头键。
5. **判断导航方向:** `FocusgroupController` 会使用 `FocusgroupControllerUtils::FocusgroupDirectionForEvent()` 等函数来确定焦点应该朝哪个方向移动。
6. **查找下一个聚焦元素:**  根据焦点组的类型 (线性或网格) 和导航方向，`FocusgroupController` 会查找下一个应该被聚焦的元素。这可能涉及到调用 `NextElement()`, `PreviousElement()`, 或网格相关的查找函数。
7. **移动焦点:** 找到下一个目标元素后，`FocusgroupController` 会更新浏览器的焦点状态，将焦点移动到目标元素上。
8. **调试线索:** 当开发者在调试与焦点导航相关的问题时，例如：
    *   按下箭头键后焦点没有按预期移动。
    *   焦点跳到了错误的元素上。
    *   焦点在焦点组的边界处没有正确循环。
    *   使用了 `focusgroup` 属性但似乎没有生效。
    开发者可以使用以下步骤进行调试，并可能最终追溯到 `focusgroup_controller_test.cc` 中的测试用例，以理解 `FocusgroupController` 的预期行为：
    *   **检查 HTML 结构:** 确认相关的 HTML 元素是否正确地使用了 `focusgroup` 属性，以及 `extend` 或 `grid` 等值是否设置正确。
    *   **检查 `tabindex` 属性:**  确认焦点组内的元素 `tabindex` 属性是否按预期设置。
    *   **使用浏览器的开发者工具:**  查看元素的属性，特别是与焦点相关的属性。可以使用 "Elements" 面板和 "Event Listeners" 面板来检查焦点事件的处理。
    *   **阅读 Blink 源代码:**  如果问题比较复杂，开发者可能需要查看 Blink 引擎的源代码，包括 `FocusgroupController` 相关的代码，以及相关的测试用例（如 `focusgroup_controller_test.cc`），来理解内部的焦点管理逻辑和预期行为。测试用例可以作为理解代码功能的 "活文档"。
    *   **断点调试:**  在 Blink 引擎的源代码中设置断点，逐步执行代码，观察 `FocusgroupController` 如何处理键盘事件和移动焦点。

总而言之，`focusgroup_controller_test.cc` 这个文件是理解 Blink 引擎中焦点组功能及其工作原理的关键资源。它展示了各种焦点组配置下的预期行为，并为开发者提供了调试焦点相关问题的线索。

Prompt: 
```
这是目录为blink/renderer/core/page/focusgroup_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/focusgroup_controller.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/page/focusgroup_controller_utils.h"
#include "third_party/blink/renderer/core/page/grid_focusgroup_structure_info.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "ui/events/keycodes/dom/dom_key.h"

namespace blink {

using utils = FocusgroupControllerUtils;
using NoCellFoundAtIndexBehavior =
    GridFocusgroupStructureInfo::NoCellFoundAtIndexBehavior;

class FocusgroupControllerTest : public PageTestBase {
 public:
  KeyboardEvent* KeyDownEvent(
      int dom_key,
      Element* target = nullptr,
      WebInputEvent::Modifiers modifiers = WebInputEvent::kNoModifiers) {
    WebKeyboardEvent web_event = {WebInputEvent::Type::kRawKeyDown, modifiers,
                                  WebInputEvent::GetStaticTimeStampForTests()};
    web_event.dom_key = dom_key;
    auto* event = KeyboardEvent::Create(web_event, nullptr);
    if (target)
      event->SetTarget(target);

    return event;
  }

  void SendEvent(KeyboardEvent* event) {
    GetDocument().GetFrame()->GetEventHandler().DefaultKeyboardEventHandler(
        event);
  }

 private:
  void SetUp() override { PageTestBase::SetUp(gfx::Size()); }

  ScopedFocusgroupForTest focusgroup_enabled{true};
};

TEST_F(FocusgroupControllerTest, FocusgroupDirectionForEventValid) {
  // Arrow right should be forward and inline.
  auto* event = KeyDownEvent(ui::DomKey::ARROW_RIGHT);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kForwardInline);

  // Arrow down should be forward and block.
  event = KeyDownEvent(ui::DomKey::ARROW_DOWN);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kForwardBlock);

  // Arrow left should be backward and inline.
  event = KeyDownEvent(ui::DomKey::ARROW_LEFT);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kBackwardInline);

  // Arrow up should be backward and block.
  event = KeyDownEvent(ui::DomKey::ARROW_UP);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kBackwardBlock);

  // When the shift key is pressed, even when combined with a valid arrow key,
  // it should return kNone.
  event = KeyDownEvent(ui::DomKey::ARROW_UP, nullptr, WebInputEvent::kShiftKey);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kNone);

  // When the ctrl key is pressed, even when combined with a valid arrow key, it
  // should return kNone.
  event =
      KeyDownEvent(ui::DomKey::ARROW_UP, nullptr, WebInputEvent::kControlKey);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kNone);

  // When the meta key (e.g.: CMD on mac) is pressed, even when combined with a
  // valid arrow key, it should return kNone.
  event = KeyDownEvent(ui::DomKey::ARROW_UP, nullptr, WebInputEvent::kMetaKey);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kNone);

  // Any other key than an arrow key should return kNone.
  event = KeyDownEvent(ui::DomKey::TAB);
  EXPECT_EQ(utils::FocusgroupDirectionForEvent(event),
            FocusgroupDirection::kNone);
}

TEST_F(FocusgroupControllerTest, IsDirectionBackward) {
  ASSERT_FALSE(utils::IsDirectionBackward(FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::IsDirectionBackward(FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::IsDirectionBackward(FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::IsDirectionBackward(FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::IsDirectionBackward(FocusgroupDirection::kForwardBlock));
}

TEST_F(FocusgroupControllerTest, IsDirectionForward) {
  ASSERT_FALSE(utils::IsDirectionForward(FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::IsDirectionForward(FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::IsDirectionForward(FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::IsDirectionForward(FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::IsDirectionForward(FocusgroupDirection::kForwardBlock));
}

TEST_F(FocusgroupControllerTest, IsDirectionInline) {
  ASSERT_FALSE(utils::IsDirectionInline(FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::IsDirectionInline(FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::IsDirectionInline(FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::IsDirectionInline(FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::IsDirectionInline(FocusgroupDirection::kForwardBlock));
}

TEST_F(FocusgroupControllerTest, IsDirectionBlock) {
  ASSERT_FALSE(utils::IsDirectionBlock(FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::IsDirectionBlock(FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::IsDirectionBlock(FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::IsDirectionBlock(FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::IsDirectionBlock(FocusgroupDirection::kForwardBlock));
}

TEST_F(FocusgroupControllerTest, IsAxisSupported) {
  FocusgroupFlags flags_inline_only = FocusgroupFlags::kInline;
  ASSERT_FALSE(
      utils::IsAxisSupported(flags_inline_only, FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::IsAxisSupported(flags_inline_only,
                                     FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::IsAxisSupported(flags_inline_only,
                                      FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::IsAxisSupported(flags_inline_only,
                                     FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::IsAxisSupported(flags_inline_only,
                                      FocusgroupDirection::kForwardBlock));

  FocusgroupFlags flags_block_only = FocusgroupFlags::kBlock;
  ASSERT_FALSE(
      utils::IsAxisSupported(flags_block_only, FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::IsAxisSupported(flags_block_only,
                                      FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::IsAxisSupported(flags_block_only,
                                     FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::IsAxisSupported(flags_block_only,
                                      FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::IsAxisSupported(flags_block_only,
                                     FocusgroupDirection::kForwardBlock));

  FocusgroupFlags flags_both_directions =
      FocusgroupFlags::kInline | FocusgroupFlags::kBlock;
  ASSERT_FALSE(utils::IsAxisSupported(flags_both_directions,
                                      FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::IsAxisSupported(flags_both_directions,
                                     FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::IsAxisSupported(flags_both_directions,
                                     FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::IsAxisSupported(flags_both_directions,
                                     FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::IsAxisSupported(flags_both_directions,
                                     FocusgroupDirection::kForwardBlock));
}

TEST_F(FocusgroupControllerTest, WrapsInDirection) {
  FocusgroupFlags flags_no_wrap = FocusgroupFlags::kNone;
  ASSERT_FALSE(
      utils::WrapsInDirection(flags_no_wrap, FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::WrapsInDirection(flags_no_wrap,
                                       FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::WrapsInDirection(flags_no_wrap,
                                       FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::WrapsInDirection(flags_no_wrap,
                                       FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::WrapsInDirection(flags_no_wrap,
                                       FocusgroupDirection::kForwardBlock));

  FocusgroupFlags flags_wrap_inline = FocusgroupFlags::kWrapInline;
  ASSERT_FALSE(
      utils::WrapsInDirection(flags_wrap_inline, FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_inline,
                                      FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::WrapsInDirection(flags_wrap_inline,
                                       FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_inline,
                                      FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::WrapsInDirection(flags_wrap_inline,
                                       FocusgroupDirection::kForwardBlock));

  FocusgroupFlags flags_wrap_block = FocusgroupFlags::kWrapBlock;
  ASSERT_FALSE(
      utils::WrapsInDirection(flags_wrap_block, FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::WrapsInDirection(flags_wrap_block,
                                       FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_block,
                                      FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::WrapsInDirection(flags_wrap_block,
                                       FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_block,
                                      FocusgroupDirection::kForwardBlock));

  FocusgroupFlags flags_wrap_both =
      FocusgroupFlags::kWrapInline | FocusgroupFlags::kWrapBlock;
  ASSERT_FALSE(
      utils::WrapsInDirection(flags_wrap_both, FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_both,
                                      FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_both,
                                      FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_both,
                                      FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::WrapsInDirection(flags_wrap_both,
                                      FocusgroupDirection::kForwardBlock));
}

TEST_F(FocusgroupControllerTest, FocusgroupExtendsInAxis) {
  FocusgroupFlags focusgroup = FocusgroupFlags::kNone;
  FocusgroupFlags extending_focusgroup = FocusgroupFlags::kNone;

  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                              FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  focusgroup |= FocusgroupFlags::kInline | FocusgroupFlags::kBlock;

  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                              FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  extending_focusgroup |= FocusgroupFlags::kInline | FocusgroupFlags::kBlock;

  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                              FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  extending_focusgroup = FocusgroupFlags::kExtend;

  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                             FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  extending_focusgroup |= FocusgroupFlags::kInline;

  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                             FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  extending_focusgroup |= FocusgroupFlags::kBlock;

  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                             FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  focusgroup = FocusgroupFlags::kNone;
  extending_focusgroup = FocusgroupFlags::kExtend | FocusgroupFlags::kInline |
                         FocusgroupFlags::kBlock;

  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                              FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  focusgroup |= FocusgroupFlags::kBlock;

  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                             FocusgroupDirection::kNone));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_FALSE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));

  focusgroup |= FocusgroupFlags::kInline;

  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(extending_focusgroup, focusgroup,
                                             FocusgroupDirection::kNone));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardInline));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kBackwardBlock));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardInline));
  ASSERT_TRUE(utils::FocusgroupExtendsInAxis(
      extending_focusgroup, focusgroup, FocusgroupDirection::kForwardBlock));
}

TEST_F(FocusgroupControllerTest, FindNearestFocusgroupAncestor) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div>
      <span id=item1 tabindex=0></span>
    </div>
    <div id=fg1 focusgroup>
      <span id=item2 tabindex=-1></span>
      <div>
        <div id=fg2 focusgroup=extend>
          <span id=item3 tabindex=-1></span>
          <div>
            <span id=item4></span>
          </div>
          <table id=fg3 focusgroup=grid>
            <tr>
              <td id=item5 tabindex=-1>
                <!-- The following is an error. -->
                <div id=fg4 focusgroup=grid>
                  <span id=item6 tabindex=-1></span>
                  <div id=fg5 focusgroup>
                    <span id=item7 tabindex=-1></span>
                  </div>
                </div>
              </td>
            </tr>
          </table>
          <div id=fg6-container>
            <template shadowrootmode=open>
              <div id=fg6 focusgroup=extend>
                <span id=item8 tabindex=-1></span>
              </div>
            </template>
          </div>
        </div>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* fg6_container = GetElementById("fg6-container");
  ASSERT_TRUE(fg6_container);

  auto* item1 = GetElementById("item1");
  auto* item2 = GetElementById("item2");
  auto* item3 = GetElementById("item3");
  auto* item4 = GetElementById("item4");
  auto* item5 = GetElementById("item5");
  auto* item6 = GetElementById("item6");
  auto* item7 = GetElementById("item7");
  auto* item8 =
      fg6_container->GetShadowRoot()->getElementById(AtomicString("item8"));
  auto* fg1 = GetElementById("fg1");
  auto* fg2 = GetElementById("fg2");
  auto* fg3 = GetElementById("fg3");
  auto* fg4 = GetElementById("fg4");
  auto* fg5 = GetElementById("fg5");
  auto* fg6 =
      fg6_container->GetShadowRoot()->getElementById(AtomicString("fg6"));
  ASSERT_TRUE(item1);
  ASSERT_TRUE(item2);
  ASSERT_TRUE(item3);
  ASSERT_TRUE(item4);
  ASSERT_TRUE(item5);
  ASSERT_TRUE(item6);
  ASSERT_TRUE(item7);
  ASSERT_TRUE(item8);
  ASSERT_TRUE(fg1);
  ASSERT_TRUE(fg2);
  ASSERT_TRUE(fg3);
  ASSERT_TRUE(fg4);
  ASSERT_TRUE(fg5);
  ASSERT_TRUE(fg6);

  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item1, FocusgroupType::kLinear),
      nullptr);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item1, FocusgroupType::kGrid),
            nullptr);
  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item2, FocusgroupType::kLinear),
      fg1);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item2, FocusgroupType::kGrid),
            nullptr);
  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item3, FocusgroupType::kLinear),
      fg2);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item3, FocusgroupType::kGrid),
            nullptr);
  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item4, FocusgroupType::kLinear),
      fg2);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item4, FocusgroupType::kGrid),
            nullptr);
  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item5, FocusgroupType::kLinear),
      nullptr);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item5, FocusgroupType::kGrid),
            fg3);
  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item6, FocusgroupType::kLinear),
      nullptr);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item6, FocusgroupType::kGrid),
            nullptr);
  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item7, FocusgroupType::kLinear),
      fg5);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item7, FocusgroupType::kGrid),
            nullptr);
  EXPECT_EQ(
      utils::FindNearestFocusgroupAncestor(item8, FocusgroupType::kLinear),
      fg6);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(item8, FocusgroupType::kGrid),
            nullptr);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(fg6, FocusgroupType::kLinear),
            fg2);
  EXPECT_EQ(utils::FindNearestFocusgroupAncestor(fg6, FocusgroupType::kGrid),
            nullptr);
}

TEST_F(FocusgroupControllerTest, NextElement) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id=fg1 focusgroup>
      <span id=item1></span>
      <span id=item2 tabindex=-1></span>
    </div>
    <div id=fg2 focusgroup>
      <span id=item3 tabindex=-1></span>
    </div>
    <div id=fg3 focusgroup>
        <template shadowrootmode=open>
          <span id=item4 tabindex=-1></span>
        </template>
    </div>
    <span id=item5 tabindex=-1></span>
  )HTML");
  auto* fg1 = GetElementById("fg1");
  auto* fg2 = GetElementById("fg2");
  auto* fg3 = GetElementById("fg3");
  ASSERT_TRUE(fg1);
  ASSERT_TRUE(fg2);
  ASSERT_TRUE(fg3);

  auto* item1 = GetElementById("item1");
  auto* item4 = fg3->GetShadowRoot()->getElementById(AtomicString("item4"));
  auto* item5 = GetElementById("item5");
  ASSERT_TRUE(item1);
  ASSERT_TRUE(item4);
  ASSERT_TRUE(item5);

  ASSERT_EQ(utils::NextElement(fg1, /* skip_subtree */ false), item1);
  ASSERT_EQ(utils::NextElement(fg1, /* skip_subtree */ true), fg2);
  ASSERT_EQ(utils::NextElement(fg3, /* skip_subtree */ false), item4);
  ASSERT_EQ(utils::NextElement(item4, /* skip_subtree */ false), item5);
}

TEST_F(FocusgroupControllerTest, PreviousElement) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id=fg1 focusgroup>
      <span id=item1></span>
      <span id=item2 tabindex=-1></span>
    </div>
    <div id=fg2 focusgroup>
      <span id=item3 tabindex=-1></span>
    </div>
    <div id=fg3 focusgroup>
        <template shadowrootmode=open>
          <span id=item4 tabindex=-1></span>
        </template>
    </div>
    <span id=item5 tabindex=-1></span>
  )HTML");
  auto* fg3 = GetElementById("fg3");
  ASSERT_TRUE(fg3);

  auto* item3 = GetElementById("item3");
  auto* item4 = fg3->GetShadowRoot()->getElementById(AtomicString("item4"));
  auto* item5 = GetElementById("item5");
  ASSERT_TRUE(item3);
  ASSERT_TRUE(item4);
  ASSERT_TRUE(item5);

  ASSERT_EQ(utils::PreviousElement(item5), item4);
  ASSERT_EQ(utils::PreviousElement(item4), fg3);
  ASSERT_EQ(utils::PreviousElement(fg3), item3);
}

TEST_F(FocusgroupControllerTest, LastElementWithin) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id=fg1 focusgroup>
      <span id=item1></span>
      <span id=item2 tabindex=-1></span>
    </div>
    <div id=fg2 focusgroup>
        <template shadowrootmode=open>
          <span id=item3 tabindex=-1></span>
          <span id=item4></span>
        </template>
    </div>
    <span id=item5 tabindex=-1></span>
  )HTML");
  auto* fg1 = GetElementById("fg1");
  auto* fg2 = GetElementById("fg2");
  ASSERT_TRUE(fg1);
  ASSERT_TRUE(fg2);

  auto* item2 = GetElementById("item2");
  auto* item4 = fg2->GetShadowRoot()->getElementById(AtomicString("item4"));
  ASSERT_TRUE(item2);
  ASSERT_TRUE(item4);

  ASSERT_EQ(utils::LastElementWithin(fg1), item2);
  ASSERT_EQ(utils::LastElementWithin(fg2), item4);
  ASSERT_EQ(utils::LastElementWithin(item4), nullptr);
}

TEST_F(FocusgroupControllerTest, IsFocusgroupItem) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=fg1 focusgroup>
      <span id=item1 tabindex=0></span>
      <span id=item2></span>
      <div id=fg2 focusgroup=extend>
        <span tabindex=-1></span>
        <div id=non-fg1 tabindex=-1>
          <span id=item3 tabindex=-1></span>
        </div>
      </div>
      <button id=button1></button>
    </div>
  )HTML");
  auto* item1 = GetElementById("item1");
  auto* item2 = GetElementById("item2");
  auto* item3 = GetElementById("item3");
  auto* fg1 = GetElementById("fg1");
  auto* fg2 = GetElementById("fg2");
  auto* non_fg1 = GetElementById("non-fg1");
  auto* button1 = GetElementById("button1");
  ASSERT_TRUE(item1);
  ASSERT_TRUE(item2);
  ASSERT_TRUE(item3);
  ASSERT_TRUE(fg1);
  ASSERT_TRUE(fg2);
  ASSERT_TRUE(non_fg1);
  ASSERT_TRUE(button1);

  ASSERT_TRUE(utils::IsFocusgroupItem(item1));
  ASSERT_FALSE(utils::IsFocusgroupItem(item2));
  ASSERT_FALSE(utils::IsFocusgroupItem(item3));
  ASSERT_FALSE(utils::IsFocusgroupItem(fg1));
  ASSERT_FALSE(utils::IsFocusgroupItem(fg2));
  ASSERT_TRUE(utils::IsFocusgroupItem(non_fg1));
  ASSERT_TRUE(utils::IsFocusgroupItem(button1));
}

TEST_F(FocusgroupControllerTest, CellAtIndexInRowBehaviorOnNoCellFound) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <table id=table focusgroup=grid>
      <tr>
        <td id=r1c1></td>
        <td id=r1c2></td>
        <td id=r1c3 rowspan=2></td>
      </tr>
      <tr id=row2>
        <td id=r2c1></td>
        <!-- r2c2 doesn't exist, but r2c3 exists because of the rowspan on the
             previous row. -->
      </tr>
      <tr>
        <td id=r3c1></td>
        <td id=r3c2></td>
        <td id=r3c3></td>
      </tr>
    </table>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* table = GetElementById("table");
  auto* row2 = GetElementById("row2");
  auto* r1c2 = GetElementById("r1c2");
  auto* r1c3 = GetElementById("r1c3");
  auto* r2c1 = GetElementById("r2c1");
  auto* r3c2 = GetElementById("r3c2");
  ASSERT_TRUE(table);
  ASSERT_TRUE(row2);
  ASSERT_TRUE(r1c2);
  ASSERT_TRUE(r1c3);
  ASSERT_TRUE(r2c1);
  ASSERT_TRUE(r3c2);

  ASSERT_TRUE(table->GetFocusgroupFlags() & FocusgroupFlags::kGrid);
  auto* helper = utils::CreateGridFocusgroupStructureInfoForGridRoot(table);

  // The first column starts at index 0.
  unsigned no_cell_index = 1;

  EXPECT_EQ(helper->CellAtIndexInRow(no_cell_index, row2,
                                     NoCellFoundAtIndexBehavior::kReturn),
            nullptr);
  EXPECT_EQ(helper->CellAtIndexInRow(
                no_cell_index, row2,
                NoCellFoundAtIndexBehavior::kFindPreviousCellInRow),
            r2c1);
  EXPECT_EQ(
      helper->CellAtIndexInRow(no_cell_index, row2,
                               NoCellFoundAtIndexBehavior::kFindNextCellInRow),
      r1c3);
  EXPECT_EQ(helper->CellAtIndexInRow(
                no_cell_index, row2,
                NoCellFoundAtIndexBehavior::kFindPreviousCellInColumn),
            r1c2);
  EXPECT_EQ(helper->CellAtIndexInRow(
                no_cell_index, row2,
                NoCellFoundAtIndexBehavior::kFindNextCellInColumn),
            r3c2);
}

TEST_F(FocusgroupControllerTest, DontMoveFocusWhenNoFocusedElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div focusgroup>
      <span id=item1 tabindex=0></span>
      <span id=item2 tabindex=0></span>
      <span tabindex=-1></span>
    </div>
  )HTML");
  ASSERT_EQ(GetDocument().FocusedElement(), nullptr);

  // Since there are no focused element, the arrow down event shouldn't move the
  // focus.
  auto* event = KeyDownEvent(ui::DomKey::ARROW_DOWN);
  SendEvent(event);

  ASSERT_EQ(GetDocument().FocusedElement(), nullptr);
}

TEST_F(FocusgroupControllerTest, DontMoveFocusWhenModifierKeyIsSet) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div focusgroup>
      <span id=item1 tabindex=0></span>
      <span id=item2 tabindex=0></span>
      <span tabindex=-1></span>
    </div>
  )HTML");
  // 1. Set the focus on an item of the focusgroup.
  auto* item1 = GetElementById("item1");
  ASSERT_TRUE(item1);
  item1->Focus();

  // 2. Send an "ArrowDown" event from that element.
  auto* event =
      KeyDownEvent(ui::DomKey::ARROW_DOWN, item1, WebInputEvent::kShiftKey);
  SendEvent(event);

  // 3. The focus shouldn't have moved because of the shift key.
  ASSERT_EQ(GetDocument().FocusedElement(), item1);
}

TEST_F(FocusgroupControllerTest, DontMoveFocusWhenItAlreadyMoved) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div focusgroup>
      <span id=item1 tabindex=0></span>
      <span id=item2 tabindex=0></span>
      <span tabindex=-1></span>
    </div>
  )HTML");
  // 1. Set the focus on an item of the focusgroup.
  auto* item2 = GetElementById("item2");
  ASSERT_TRUE(item2);
  item2->Focus();

  // 2. Create the "ArrowDown" event from that element.
  auto* event = KeyDownEvent(ui::DomKey::ARROW_DOWN, item2);

  // 3. Move the focus to a different element before we send the event.
  auto* item1 = GetElementById("item1");
  ASSERT_TRUE(item1);
  item1->Focus();

  // 4. Pass the event we created earlier to our FocusgroupController. The
  // controller shouldn't even try to move the focus since the focus isn't on
  // the element that triggered the arrow key press event.
  SendEvent(event);

  ASSERT_EQ(GetDocument().FocusedElement(), item1);
}

}  // namespace blink

"""

```