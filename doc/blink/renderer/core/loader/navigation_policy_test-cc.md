Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Understand the Goal:** The request asks for the functionality of `navigation_policy_test.cc`, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common usage errors, and debugging clues. The key is to understand what aspects of a browser's navigation are being tested here.

2. **Identify the Core Subject:** The filename `navigation_policy_test.cc` and the included header `navigation_policy.h` immediately point to the core subject: how the browser decides *where* to open a link or new window based on user interactions and window features. This involves things like opening in the current tab, a new tab (foreground or background), a new window, or a popup.

3. **Recognize the Test Framework:** The inclusion of `testing/gtest/include/gtest/gtest.h` reveals that this is a unit test file using the Google Test framework. This means the file contains individual tests (`TEST_F`) that verify the behavior of the `NavigationPolicy` logic.

4. **Analyze the Test Structure:**  Skim through the test cases. Notice patterns like `LeftClick`, `ShiftLeftClick`, `ControlOrMetaLeftClick`, `MiddleClick`, and tests involving `WebWindowFeatures` like `popup`, `noopener`, and `resizable`. This gives a high-level understanding of the scenarios being tested.

5. **Focus on Key Functions:**  Identify the primary functions being tested:
    * `NavigationPolicyForCreateWindow(features)`: This likely determines the navigation policy when a script tries to open a new window (e.g., using `window.open()`). The `WebWindowFeatures` argument strongly suggests this.
    * `NavigationPolicyFromEvent(event)`: This likely determines the navigation policy when a user clicks on a link (or performs other navigation-related mouse events). The `Event*` argument points to user interaction.

6. **Connect to Web Technologies:**  Now, consider how these functions relate to web technologies:

    * **JavaScript:** `window.open()` in JavaScript directly uses the features being tested in `NavigationPolicyForCreateWindow`. The arguments passed to `window.open()` correspond to the `WebWindowFeatures`. JavaScript event handlers can trigger navigation.
    * **HTML:**  The `<a>` tag with its `target` attribute and the various event handlers (like `onclick`) are the primary ways HTML initiates navigation. The modifiers (Shift, Ctrl/Meta, Alt) used in the tests directly correspond to how users interact with links.
    * **CSS:** While CSS doesn't directly *control* navigation policy, it can *influence* user behavior that leads to navigation. For instance, styling a link might make it more or less likely the user will click it. However, CSS is less directly relevant to *this specific test file*.

7. **Infer Logical Reasoning:** Examine the test cases and the expected outcomes (`EXPECT_EQ`). The logic is based on:

    * **Mouse Button:** Left-click is the default. Middle-click often opens in a background tab.
    * **Modifier Keys:** Shift usually means "new window." Ctrl/Meta usually means "new background tab." Alt might have special meanings (like download or link preview).
    * **Window Features:**  The presence or absence of features like `popup`, `noopener`, and `resizable` in the `window.open()` call affects the navigation policy.

8. **Develop Input/Output Examples:** Based on the test cases, create concrete examples:

    * **Input:** Left-click on a link. **Output:** Open in the current tab.
    * **Input:** Ctrl+Click on a link. **Output:** Open in a new background tab.
    * **Input:** `window.open("...", "...", "popup")`. **Output:** Open as a popup.

9. **Consider User Errors:** Think about common mistakes developers or users might make:

    * **Developers:** Incorrectly specifying window features in `window.open()`. Misunderstanding how modifier keys affect link behavior. Not handling different browser behaviors.
    * **Users:** Unintentionally pressing modifier keys. Being surprised by where a link opens.

10. **Trace User Actions:**  Imagine a user interacting with a webpage and how that leads to the execution of the tested code:

    * User clicks a link. This generates a `MouseEvent`.
    * The browser's event handling code (likely in `blink/renderer/core/frame/local_frame.cc` or similar) will call `NavigationPolicyFromEvent` to determine what to do.
    * A JavaScript call to `window.open()` will trigger `NavigationPolicyForCreateWindow`.

11. **Address Debugging:** Explain how the tests act as debugging clues. If a particular navigation behavior is wrong, looking at the relevant test case can help pinpoint the issue. Running these tests during development ensures the navigation policy logic is correct.

12. **Refine and Organize:** Structure the answer logically, using clear headings and bullet points. Provide specific examples and connect the concepts to the provided code snippets. Ensure the language is accessible and explains the technical details clearly. For instance, when mentioning `BUILDFLAG(IS_MAC)`, briefly explain its purpose.

By following these steps, you can systematically analyze the provided C++ test file and generate a comprehensive and accurate explanation of its functionality and relevance. The key is to connect the code to the user experience and the underlying web technologies.
这个文件 `blink/renderer/core/loader/navigation_policy_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件。它的主要功能是 **测试 `blink::NavigationPolicy` 相关的逻辑**。`NavigationPolicy` 类负责决定当用户或者脚本尝试导航到一个新的 URL 时，浏览器应该如何处理，例如是在当前标签页打开，在新标签页打开，还是在新窗口打开等等。

以下是更详细的分析：

**1. 功能列举:**

* **测试 `NavigationPolicyForCreateWindow` 函数:**  这个函数根据提供的 `WebWindowFeatures` (窗口特性，例如 `popup`, `noopener`, `noreferrer` 等) 和当前的输入事件（例如鼠标点击时的修饰键）来决定新窗口的导航策略。
* **测试 `NavigationPolicyFromEvent` 函数:** 这个函数根据触发导航的事件 (例如鼠标点击事件) 的属性 (例如按下的鼠标按键和修饰键) 来决定导航策略。
* **覆盖多种用户交互场景:**  测试了用户通过不同方式点击链接时的导航行为，例如：
    * 左键点击
    * Shift + 左键点击
    * Control/Meta + 左键点击
    * 中键点击
    * Alt + 左键点击
* **测试 `window.open()` 的不同特性组合:** 测试了 `window.open()` 方法中使用不同特性字符串时的导航策略，例如是否声明为 `popup`，是否设置 `noopener` 或 `noreferrer` 等。
* **使用 Google Test 框架:**  该文件使用了 `testing/gtest/include/gtest/gtest.h`，表明它是一个单元测试文件，用于自动化验证 `NavigationPolicy` 的行为是否符合预期。
* **针对不同操作系统进行测试:** 使用宏 `BUILDFLAG(IS_MAC)` 来区分 macOS 和其他操作系统在 Control/Meta 键上的行为。
* **测试 Link Preview 功能:**  包含一个名为 `NavigationPolicyWithLinkPreviewEnabledTest` 的测试类，专门测试启用了 Link Preview 功能时的导航策略。

**2. 与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关联到 JavaScript 和 HTML 的功能，而与 CSS 的关系较间接。

* **JavaScript:**
    * **`window.open()`:**  `NavigationPolicyForCreateWindow` 的主要目的是处理 JavaScript 代码中调用 `window.open()` 时的导航策略。`WebWindowFeatures` 对象正是从 `window.open()` 的特性字符串中解析出来的。
    * **示例:**  如果 JavaScript 代码执行 `window.open('https://example.com', '_blank', 'popup')`，那么 `NavigationPolicyForCreateWindow` 函数会被调用，并且传入的 `WebWindowFeatures` 对象会包含 `is_popup = true`。这个测试文件中的 `TEST_F(NavigationPolicyTest, LeftClickPopup)` 就是在模拟这种情况，并验证应该返回 `kNavigationPolicyNewPopup`。
* **HTML:**
    * **`<a>` 标签的 `target` 属性:** 虽然这个测试文件本身不直接测试 `target` 属性，但 `NavigationPolicy` 的逻辑会影响 `target="_blank"` 的行为。例如，用户按住 Ctrl 或 Meta 键点击带有 `target="_blank"` 的链接，通常会在新后台标签页打开，这正是这个测试文件所覆盖的场景。
    * **用户点击事件:** `NavigationPolicyFromEvent` 函数处理的是用户点击链接 (或其他可能触发导航的元素) 时的事件。鼠标按键和修饰键的状态直接来自于用户的操作。
    * **示例:** 当用户按住 Shift 键点击一个链接时，浏览器会创建一个 `MouseEvent`，其中包含 `shiftKey = true`。`NavigationPolicyFromEvent` 函数会根据这个信息返回 `kNavigationPolicyNewWindow`。 `TEST_F(NavigationPolicyTest, EventShiftLeftClick)` 就验证了这种情况。
* **CSS:**
    * **间接关系:** CSS 可以影响页面的布局和用户的交互方式，从而间接地影响导航行为。例如，CSS 可以让一个元素看起来像一个链接，用户点击它可能会触发导航。然而，`navigation_policy_test.cc` 并不直接测试 CSS 的效果。它的关注点在于用户已经发起了导航请求之后，浏览器如何处理。

**3. 逻辑推理的假设输入与输出:**

以下是一些基于测试用例的逻辑推理示例：

* **假设输入:** 用户在 Windows 系统下，没有按下任何修饰键，用鼠标左键点击了一个链接。
    * **预期输出:** `NavigationPolicyFromEvent` 函数应该返回 `kNavigationPolicyCurrentTab`，表示在当前标签页打开链接。 (对应 `TEST_F(NavigationPolicyTest, EventLeftClick)`)
* **假设输入:** 用户在 macOS 系统下，按下 Command 键 (对应 Meta 键)，用鼠标左键点击了一个链接。
    * **预期输出:** `NavigationPolicyFromEvent` 函数应该返回 `kNavigationPolicyNewForegroundTab`。 (对应 `TEST_F(NavigationPolicyTest, EventControlOrMetaLeftClick)`)  注意，由于是 `FromEvent` 且没有用户事件覆盖，这里会倾向于前台标签页。
* **假设输入:** JavaScript 代码执行 `window.open('https://example.com', '_blank', 'noopener')`。
    * **预期输出:** `NavigationPolicyForCreateWindow` 函数应该返回 `kNavigationPolicyNewForegroundTab`，即使是在新窗口打开，也会阻止新窗口访问 opener。 (对应 `TEST_F(NavigationPolicyTest, NoOpener)`)
* **假设输入:** 用户按下 Alt 键并点击链接，并且启用了 Link Preview 功能。
    * **预期输出:** `NavigationPolicyFromEvent` 函数应该返回 `kNavigationPolicyLinkPreview`。 (对应 `TEST_F(NavigationPolicyWithLinkPreviewEnabledTest, EventAltClickWithUserEvent)`)

**4. 用户或编程常见的使用错误:**

* **用户错误:**
    * **误触修饰键:** 用户可能无意中按下了 Shift、Ctrl 或 Alt 键，导致链接在非预期的位置打开 (例如，本来想在当前标签页打开，结果在新窗口打开)。这个测试文件通过覆盖各种修饰键组合来确保这些情况的处理是正确的。
    * **不理解中键点击的行为:** 许多用户可能不清楚中键点击通常是在新后台标签页打开链接。测试用例 `TEST_F(NavigationPolicyTest, MiddleClick)` 和 `TEST_F(NavigationPolicyTest, EventMiddleClickWithUserEvent)` 验证了这种行为。
* **编程错误 (JavaScript):**
    * **错误地使用 `window.open()` 的特性字符串:** 开发者可能拼写错误或者不理解某些特性（如 `noopener` 或 `noreferrer`）的作用，导致导航行为不符合预期。例如，错误地写成 `"popupFoo"` 而不是 `"popup"`，测试用例 `TEST_F(NavigationPolicyTest, NoOpener)` 中有类似的测试。
    * **假设所有浏览器行为一致:**  不同的浏览器在某些细节上可能有所不同。Chromium 的测试确保其行为符合规范和预期。
    * **没有考虑到用户修饰键的影响:** 开发者可能只测试了简单的左键点击场景，而忽略了用户可能使用修饰键的情况。这个测试文件覆盖了这些情况，提醒开发者注意。

**5. 用户操作如何一步步到达这里 (调试线索):**

假设用户想要调试一个网页链接在新窗口打开行为异常的问题，以下是可能的步骤，最终可能会涉及到 `navigation_policy_test.cc`：

1. **用户操作:** 用户点击了一个网页上的链接。
2. **浏览器事件:** 浏览器捕获到用户的点击事件 (通常是一个 `mouseup` 事件)。
3. **事件处理:** Blink 渲染引擎的事件处理代码会识别这是一个潜在的导航事件。
4. **`NavigationPolicyFromEvent` 调用:**  根据事件的属性 (鼠标按键、修饰键等)，会调用 `blink::NavigationPolicyFromEvent` 函数来确定导航策略。这个函数位于 `blink/renderer/core/loader/navigation_policy.cc` 中，而测试文件 `navigation_policy_test.cc` 就是用来验证这个函数的逻辑是否正确。
5. **导航策略确定:** `NavigationPolicyFromEvent` 返回一个 `NavigationPolicy` 枚举值 (例如 `kNavigationPolicyNewWindow`, `kNavigationPolicyNewBackgroundTab` 等)。
6. **页面导航:** 浏览器根据确定的导航策略执行相应的操作，例如创建一个新的浏览器窗口或标签页，并加载链接指向的 URL。

**调试线索:**

* **如果用户报告点击链接后打开的位置不正确:** 开发者可以查看 `navigation_policy_test.cc` 中相关的测试用例，例如涉及特定修饰键组合的测试。
* **如果涉及到 `window.open()` 的行为异常:** 可以查看测试 `NavigationPolicyForCreateWindow` 的用例，特别是那些涉及到窗口特性 (如 `popup`, `noopener`) 的测试。
* **运行测试:** 开发者可以运行 `navigation_policy_test.cc` 中的相关测试，来验证 `NavigationPolicy` 的行为是否符合预期。如果测试失败，说明 `NavigationPolicy` 的实现存在 bug。
* **断点调试:**  在开发或调试 Blink 引擎时，可以在 `blink/renderer/core/loader/navigation_policy.cc` 中的 `NavigationPolicyFromEvent` 或 `NavigationPolicyForCreateWindow` 函数中设置断点，跟踪用户操作和 `WebWindowFeatures` 的值，观察导航策略是如何被确定的。

总而言之，`blink/renderer/core/loader/navigation_policy_test.cc` 是 Blink 引擎中一个关键的测试文件，它确保了浏览器在处理各种导航场景时的行为符合预期，涵盖了用户交互和 JavaScript API 调用的多种情况，对于保证浏览器的稳定性和用户体验至关重要。

### 提示词
```
这是目录为blink/renderer/core/loader/navigation_policy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/loader/navigation_policy.h"

#include "base/auto_reset.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/public/web/web_window_features.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mouse_event_init.h"
#include "third_party/blink/renderer/core/events/current_input_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/page/create_window.h"

namespace blink {

class NavigationPolicyTest : public testing::Test {
 protected:
  void SetUp() override {
    // Default
    scoped_feature_list_.InitAndDisableFeature(features::kLinkPreview);
  }

  NavigationPolicy GetPolicyForCreateWindow(int modifiers,
                                            WebMouseEvent::Button button,
                                            bool as_popup) {
    WebMouseEvent event(WebInputEvent::Type::kMouseUp, modifiers,
                        WebInputEvent::GetStaticTimeStampForTests());
    event.button = button;
    if (as_popup)
      features.is_popup = true;
    base::AutoReset<const WebInputEvent*> current_event_change(
        &CurrentInputEvent::current_input_event_, &event);
    return NavigationPolicyForCreateWindow(features);
  }

  Event* GetEvent(int modifiers, WebMouseEvent::Button button) {
    MouseEventInit* mouse_initializer = MouseEventInit::Create();
    if (button == WebMouseEvent::Button::kLeft)
      mouse_initializer->setButton(0);
    if (button == WebMouseEvent::Button::kMiddle)
      mouse_initializer->setButton(1);
    if (button == WebMouseEvent::Button::kRight)
      mouse_initializer->setButton(2);
    if (modifiers & WebInputEvent::kShiftKey)
      mouse_initializer->setShiftKey(true);
    if (modifiers & WebInputEvent::kControlKey)
      mouse_initializer->setCtrlKey(true);
    if (modifiers & WebInputEvent::kAltKey)
      mouse_initializer->setAltKey(true);
    if (modifiers & WebInputEvent::kMetaKey)
      mouse_initializer->setMetaKey(true);
    return MouseEvent::Create(nullptr, event_type_names::kClick,
                              mouse_initializer);
  }

  NavigationPolicy GetPolicyFromEvent(int modifiers,
                                      WebMouseEvent::Button button,
                                      int user_modifiers,
                                      WebMouseEvent::Button user_button) {
    WebMouseEvent event(WebInputEvent::Type::kMouseUp, user_modifiers,
                        WebInputEvent::GetStaticTimeStampForTests());
    event.button = user_button;
    base::AutoReset<const WebInputEvent*> current_event_change(
        &CurrentInputEvent::current_input_event_, &event);
    return NavigationPolicyFromEvent(GetEvent(modifiers, button));
  }

  WebWindowFeatures features;
  base::test::ScopedFeatureList scoped_feature_list_;
};

class NavigationPolicyWithLinkPreviewEnabledTest : public NavigationPolicyTest {
 protected:
  void SetUp() override {
    scoped_feature_list_.InitAndEnableFeatureWithParameters(
        features::kLinkPreview, {{"trigger_type", "alt_click"}});
  }
};

TEST_F(NavigationPolicyTest, LeftClick) {
  int modifiers = 0;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = false;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, LeftClickPopup) {
  int modifiers = 0;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = true;
  EXPECT_EQ(kNavigationPolicyNewPopup,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, ShiftLeftClick) {
  int modifiers = WebInputEvent::kShiftKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = false;
  EXPECT_EQ(kNavigationPolicyNewWindow,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, ShiftLeftClickPopup) {
  int modifiers = WebInputEvent::kShiftKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = true;
  EXPECT_EQ(kNavigationPolicyNewPopup,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, ControlOrMetaLeftClick) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey;
#else
  int modifiers = WebInputEvent::kControlKey;
#endif
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = false;
  EXPECT_EQ(kNavigationPolicyNewBackgroundTab,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, ControlOrMetaLeftClickPopup) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey;
#else
  int modifiers = WebInputEvent::kControlKey;
#endif
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = true;
  EXPECT_EQ(kNavigationPolicyNewBackgroundTab,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, ControlOrMetaAndShiftLeftClick) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey;
#else
  int modifiers = WebInputEvent::kControlKey;
#endif
  modifiers |= WebInputEvent::kShiftKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = false;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, ControlOrMetaAndShiftLeftClickPopup) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey;
#else
  int modifiers = WebInputEvent::kControlKey;
#endif
  modifiers |= WebInputEvent::kShiftKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  bool as_popup = true;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, MiddleClick) {
  int modifiers = 0;
  bool as_popup = false;
  WebMouseEvent::Button button = WebMouseEvent::Button::kMiddle;
  EXPECT_EQ(kNavigationPolicyNewBackgroundTab,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, MiddleClickPopup) {
  int modifiers = 0;
  bool as_popup = true;
  WebMouseEvent::Button button = WebMouseEvent::Button::kMiddle;
  EXPECT_EQ(kNavigationPolicyNewBackgroundTab,
            GetPolicyForCreateWindow(modifiers, button, as_popup));
}

TEST_F(NavigationPolicyTest, ForcePopup) {
  features.is_popup = true;
  EXPECT_EQ(kNavigationPolicyNewPopup,
            NavigationPolicyForCreateWindow(features));
  features.is_popup = false;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            NavigationPolicyForCreateWindow(features));

  static const struct {
    const char* feature_string;
    NavigationPolicy policy;
  } kCases[] = {
      {"", kNavigationPolicyNewForegroundTab},
      {"popup", kNavigationPolicyNewPopup},
      {"location,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewForegroundTab},
      {"toolbar,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewForegroundTab},
      {"popup,location,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewPopup},
      {"menubar,resizable,scrollbars,status", kNavigationPolicyNewPopup},
      {"location,menubar,resizable,scrollbars", kNavigationPolicyNewPopup},
      {"location,resizable,scrollbars,status", kNavigationPolicyNewPopup},
      {"location,menubar,resizable,status", kNavigationPolicyNewPopup},
      {"location,menubar,scrollbars,status", kNavigationPolicyNewForegroundTab},
      {"popup=0,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewForegroundTab},
  };

  for (const auto& test : kCases) {
    EXPECT_EQ(test.policy,
              NavigationPolicyForCreateWindow(GetWindowFeaturesFromString(
                  test.feature_string, /*dom_window=*/nullptr)))
        << "Testing '" << test.feature_string << "'";
  }
}

TEST_F(NavigationPolicyTest, NoOpener) {
  static const struct {
    const char* feature_string;
    NavigationPolicy policy;
  } kCases[] = {
      {"", kNavigationPolicyNewForegroundTab},
      {"location,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewForegroundTab},
      {"popup,location,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewPopup},
      {"PoPuP,location,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewPopup},
      {"popupFoo,location,menubar,resizable,scrollbars,status",
       kNavigationPolicyNewForegroundTab},
      {"something", kNavigationPolicyNewPopup},
      {"something, something", kNavigationPolicyNewPopup},
      {"notnoopener", kNavigationPolicyNewPopup},
      {"noopener", kNavigationPolicyNewForegroundTab},
      {"something, noopener", kNavigationPolicyNewPopup},
      {"noopener, something", kNavigationPolicyNewPopup},
      {"NoOpEnEr", kNavigationPolicyNewForegroundTab},
  };

  for (const auto& test : kCases) {
    EXPECT_EQ(test.policy,
              NavigationPolicyForCreateWindow(GetWindowFeaturesFromString(
                  test.feature_string, /*dom_window=*/nullptr)))
        << "Testing '" << test.feature_string << "'";
  }
}

TEST_F(NavigationPolicyTest, NoOpenerAndNoReferrer) {
  static const struct {
    const char* feature_string;
    NavigationPolicy policy;
  } kCases[] = {
      {"", kNavigationPolicyNewForegroundTab},
      {"noopener, noreferrer", kNavigationPolicyNewForegroundTab},
      {"noopener, notreferrer", kNavigationPolicyNewPopup},
      {"noopener, notreferrer, popup", kNavigationPolicyNewPopup},
      {"notopener, noreferrer", kNavigationPolicyNewPopup},
      {"notopener, noreferrer, popup", kNavigationPolicyNewPopup},
      {"notopener, noreferrer, popup=0", kNavigationPolicyNewForegroundTab},
      {"popup, noopener, noreferrer", kNavigationPolicyNewPopup},
      {"noopener, noreferrer, popup", kNavigationPolicyNewPopup},
      {"noopener, popup, noreferrer", kNavigationPolicyNewPopup},
      {"NoOpEnEr, NoReFeRrEr", kNavigationPolicyNewForegroundTab},
  };

  for (const auto& test : kCases) {
    EXPECT_EQ(test.policy,
              NavigationPolicyForCreateWindow(GetWindowFeaturesFromString(
                  test.feature_string, /*dom_window=*/nullptr)))
        << "Testing '" << test.feature_string << "'";
  }
}

TEST_F(NavigationPolicyTest, NoReferrer) {
  static const struct {
    const char* feature_string;
    NavigationPolicy policy;
  } kCases[] = {
      {"", kNavigationPolicyNewForegroundTab},
      {"popup", kNavigationPolicyNewPopup},
      {"popup, something", kNavigationPolicyNewPopup},
      {"notreferrer", kNavigationPolicyNewPopup},
      {"notreferrer,popup", kNavigationPolicyNewPopup},
      {"notreferrer,popup=0", kNavigationPolicyNewForegroundTab},
      {"noreferrer", kNavigationPolicyNewForegroundTab},
      {"popup, noreferrer", kNavigationPolicyNewPopup},
      {"noreferrer, popup", kNavigationPolicyNewPopup},
      {"NoReFeRrEr", kNavigationPolicyNewForegroundTab},
  };

  for (const auto& test : kCases) {
    EXPECT_EQ(test.policy,
              NavigationPolicyForCreateWindow(GetWindowFeaturesFromString(
                  test.feature_string, /*dom_window=*/nullptr)))
        << "Testing '" << test.feature_string << "'";
  }
}

TEST_F(NavigationPolicyTest, NotResizableForcesPopup) {
  features.resizable = false;
  EXPECT_EQ(kNavigationPolicyNewPopup,
            NavigationPolicyForCreateWindow(features));
  features.resizable = true;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            NavigationPolicyForCreateWindow(features));
}

TEST_F(NavigationPolicyTest, EventLeftClick) {
  int modifiers = 0;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyCurrentTab,
            NavigationPolicyFromEvent(GetEvent(modifiers, button)));
}

TEST_F(NavigationPolicyTest, EventShiftLeftClick) {
  int modifiers = WebInputEvent::kShiftKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyNewWindow,
            NavigationPolicyFromEvent(GetEvent(modifiers, button)));
}

TEST_F(NavigationPolicyTest, EventControlOrMetaLeftClick) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey;
#else
  int modifiers = WebInputEvent::kControlKey;
#endif
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            NavigationPolicyFromEvent(GetEvent(modifiers, button)));
}

TEST_F(NavigationPolicyTest, EventControlOrMetaLeftClickWithUserEvent) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey;
#else
  int modifiers = WebInputEvent::kControlKey;
#endif
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyNewBackgroundTab,
            GetPolicyFromEvent(modifiers, button, modifiers, button));
}

TEST_F(NavigationPolicyTest,
       EventControlOrMetaLeftClickWithDifferentUserEvent) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey;
#else
  int modifiers = WebInputEvent::kControlKey;
#endif
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            GetPolicyFromEvent(modifiers, button, 0, button));
}

TEST_F(NavigationPolicyTest, EventShiftControlOrMetaLeftClick) {
#if BUILDFLAG(IS_MAC)
  int modifiers = WebInputEvent::kMetaKey | WebInputEvent::kShiftKey;
#else
  int modifiers = WebInputEvent::kControlKey | WebInputEvent::kShiftKey;
#endif
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            NavigationPolicyFromEvent(GetEvent(modifiers, button)));
}

TEST_F(NavigationPolicyTest, EventMiddleClick) {
  int modifiers = 0;
  WebMouseEvent::Button button = WebMouseEvent::Button::kMiddle;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            NavigationPolicyFromEvent(GetEvent(modifiers, button)));
}

TEST_F(NavigationPolicyTest, EventMiddleClickWithUserEvent) {
  int modifiers = 0;
  WebMouseEvent::Button button = WebMouseEvent::Button::kMiddle;
  EXPECT_EQ(kNavigationPolicyNewBackgroundTab,
            GetPolicyFromEvent(modifiers, button, modifiers, button));
}

TEST_F(NavigationPolicyTest, EventMiddleClickWithDifferentUserEvent) {
  int modifiers = 0;
  WebMouseEvent::Button button = WebMouseEvent::Button::kMiddle;
  WebMouseEvent::Button user_button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyNewForegroundTab,
            GetPolicyFromEvent(modifiers, button, modifiers, user_button));
}

TEST_F(NavigationPolicyTest, EventAltClick) {
  int modifiers = WebInputEvent::kAltKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyCurrentTab,
            NavigationPolicyFromEvent(GetEvent(modifiers, button)));
}

TEST_F(NavigationPolicyTest, EventAltClickWithUserEvent) {
  int modifiers = WebInputEvent::kAltKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyDownload,
            GetPolicyFromEvent(modifiers, button, modifiers, button));
}

TEST_F(NavigationPolicyTest, EventAltClickWithDifferentUserEvent) {
  int modifiers = WebInputEvent::kAltKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyCurrentTab,
            GetPolicyFromEvent(modifiers, button, 0, button));
}

TEST_F(NavigationPolicyWithLinkPreviewEnabledTest, EventAltClick) {
  int modifiers = WebInputEvent::kAltKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyCurrentTab,
            NavigationPolicyFromEvent(GetEvent(modifiers, button)));
}

TEST_F(NavigationPolicyWithLinkPreviewEnabledTest, EventAltClickWithUserEvent) {
  int modifiers = WebInputEvent::kAltKey;
  WebMouseEvent::Button button = WebMouseEvent::Button::kLeft;
  EXPECT_EQ(kNavigationPolicyLinkPreview,
            GetPolicyFromEvent(modifiers, button, modifiers, button));
}

}  // namespace blink
```