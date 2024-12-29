Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `touch_action_test.cc` and the `#include` directives (like `web_touch_event.h`) immediately suggest this file is about testing touch interaction behavior within the Blink rendering engine. The phrase "touch action" is also a strong hint.

2. **Scan for Key Classes and Functions:** Look for the main test fixture (`TouchActionTest`) and any helper classes or functions. Notice `TouchActionWidgetInputHandlerHost` and `TouchActionTrackingWebFrameWidget`. Their names imply they are involved in simulating or tracking touch actions. The `RunTouchActionTest`, `RunShadowDOMTest`, and `RunIFrameTest` functions stand out as the main test runners.

3. **Understand the Testing Framework:**  The `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test. This means we'll be looking for `TEST_F` macros defining individual test cases.

4. **Analyze Helper Classes:**
    * `TouchActionWidgetInputHandlerHost`:  The key method is `SetTouchActionFromMain`. This strongly suggests it's observing or intercepting the setting of `touch-action` styles. The `action_set_count_` and `action_` members are used to verify how many times and what the `touch-action` was set to.
    * `TouchActionTrackingWebFrameWidget`: This appears to be a specialized version of `TestWebFrameWidget`. It holds an instance of `TouchActionWidgetInputHandlerHost` and provides accessors to its data. This structure suggests the test setup involves creating a custom frame widget to track touch actions.

5. **Analyze Test Runner Functions:**
    * `RunTouchActionTest`: This function loads an HTML file and then iterates through elements with the `expected-action` attribute. It simulates touch events on these elements and verifies the resulting `touch-action` value.
    * `RunShadowDOMTest`: Similar to `RunTouchActionTest`, but it specifically targets elements within Shadow DOM trees.
    * `RunIFrameTest`:  This handles testing `touch-action` within iframes.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The tests rely on HTML files (`touch-action-simple.html`, etc.) containing elements with the `expected-action` attribute. This attribute is clearly used to define the expected behavior of the `touch-action` CSS property.
    * **CSS:** The core of the testing is the `touch-action` CSS property. The tests verify that applying different `touch-action` values in CSS results in the expected behavior within the Blink engine.
    * **JavaScript:** While not directly interacting with JavaScript code in *this specific test file*, the setup process might involve loading JavaScript (see the `url_test_helpers::RegisterMockedURLLoadFromBase` calls). The behavior being tested (how `touch-action` affects scrolling and panning) would certainly be relevant to JavaScript event handling.

7. **Infer the Underlying Logic:**  The tests aim to verify the correct implementation of the `touch-action` CSS property. This involves the following logical steps within Blink:
    * When a touch event occurs, identify the target element.
    * Determine the computed `touch-action` style for that element (considering CSS inheritance and specificity).
    * Based on the `touch-action` value, decide how the browser should handle the touch interaction (e.g., allow scrolling, prevent scrolling, allow panning in a specific direction).

8. **Consider User Actions and Debugging:** Think about how a developer or a user might encounter the code being tested. A developer implementing a web page with specific scrolling behavior would use the `touch-action` CSS property. If the behavior isn't as expected, they might need to debug, and these tests provide a way to verify the underlying engine logic.

9. **Formulate Examples and Assumptions:**  Based on the code, create concrete examples of how the tests work and what kind of input/output to expect. Think about common mistakes developers might make when using `touch-action`.

10. **Structure the Explanation:** Organize the findings into logical sections covering functionality, relationships to web technologies, logic, user errors, and debugging. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This is just about testing touch events."
* **Correction:**  "It's specifically testing the *`touch-action` CSS property* and its effects on touch event handling."

* **Initial thought:** "The tests directly execute JavaScript."
* **Correction:** "The tests load HTML and CSS, and the *Blink engine* handles the touch events according to the `touch-action` style. JavaScript might be involved in setting up the page, but the core of the test is the engine's behavior."

* **Realization:** The `expected-action` attribute is the crucial link between the HTML and the test's expectations.

By following these steps, and iteratively refining the understanding, one can arrive at a comprehensive and accurate description of the provided C++ test file.
这个文件 `blink/renderer/core/input/touch_action_test.cc` 是 Chromium Blink 渲染引擎的源代码，其主要功能是**测试 `touch-action` CSS 属性的实现和行为**。

`touch-action` 属性用于指定触摸操作在特定元素上是否以及如何触发默认的浏览器行为，例如滚动和缩放。此测试文件确保 Blink 引擎正确地解析、应用和处理 `touch-action` 属性的不同值。

下面对其功能进行详细列举和解释：

**1. 功能概述:**

* **单元测试:** 该文件包含了一系列单元测试用例，用于验证 `touch-action` 属性在各种场景下的预期行为。
* **测试不同的 `touch-action` 值:**  测试用例涵盖了 `touch-action` 的各种可能值，例如 `auto`, `none`, `pan-x`, `pan-y`, `manipulation` 等。
* **测试不同的 DOM 结构:** 测试用例涵盖了不同的 DOM 结构，包括：
    * 简单的 HTML 元素。
    * 包含溢出内容的元素。
    * `<iframe>` 元素。
    * Shadow DOM。
* **模拟触摸事件:** 测试代码模拟触摸事件（例如 `pointerdown`, `pointercancel`），并检查 Blink 引擎对这些事件的响应是否符合预期的 `touch-action` 设置。
* **验证 `TouchAction` 的设置:** 测试代码验证了在触摸元素时，Blink 引擎是否正确地为该元素设置了相应的 `TouchAction` 枚举值。
* **使用 Google Test 框架:** 该文件使用了 Google Test 框架来编写和运行测试用例。

**2. 与 JavaScript, HTML, CSS 的关系:**

* **CSS:** 该测试文件直接测试 `touch-action` 这个 CSS 属性的功能。测试用例会加载包含不同 `touch-action` 样式的 HTML 文件。例如：
    * **HTML:**
      ```html
      <div style="touch-action: none;">阻止滚动和缩放</div>
      <div style="touch-action: pan-y;">只允许垂直滚动</div>
      ```
    * **CSS (外部样式表):**
      ```css
      #element-with-pan-x {
        touch-action: pan-x; /* 只允许水平滚动 */
      }
      ```
* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，但它测试的功能与 JavaScript 事件处理密切相关。当用户在屏幕上进行触摸操作时，浏览器会生成相应的触摸事件（例如 `touchstart`, `touchmove`, `touchend`）。 `touch-action` 属性会影响浏览器如何处理这些事件的默认行为，这可能会影响 JavaScript 事件处理程序的触发和行为。 例如：
    * 如果一个元素设置了 `touch-action: none;`，浏览器可能会阻止默认的滚动行为，即使 JavaScript 中有监听滚动事件的代码，也可能无法触发或表现出不同的行为。
* **HTML:** 测试用例加载 HTML 文件来创建需要测试的 DOM 结构。HTML 元素可以通过内联样式或外部 CSS 文件设置 `touch-action` 属性。测试会针对不同的 HTML 结构进行，例如包含 `<iframe>` 或使用 Shadow DOM 的情况。

**举例说明:**

假设一个 HTML 文件 `touch-action-simple.html` 包含以下代码：

```html
<!DOCTYPE html>
<html>
<head>
<style>
  #no-action { touch-action: none; }
  #pan-x { touch-action: pan-x; }
  #auto-action { touch-action: auto; }
</style>
</head>
<body>
  <div id="no-action" expected-action="none">不能滚动</div>
  <div id="pan-x" expected-action="pan-x">只能水平滚动</div>
  <div id="auto-action" expected-action="auto">默认滚动行为</div>
</body>
</html>
```

`touch_action_test.cc` 中的测试用例会加载这个 HTML 文件，然后模拟触摸事件发生在这些 `div` 元素上。测试会验证：

* 当触摸 `#no-action` 元素时，Blink 引擎设置的 `TouchAction` 是 `kNone`，这意味着默认的滚动和缩放行为应该被阻止。
* 当触摸 `#pan-x` 元素时，Blink 引擎设置的 `TouchAction` 是 `kPanX`，意味着只允许水平滚动。
* 当触摸 `#auto-action` 元素时，Blink 引擎设置的 `TouchAction` 是 `kAuto`，意味着使用浏览器的默认触摸行为。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入:**
    * 加载一个包含设置了 `touch-action: pan-y;` 的 `<div>` 元素的 HTML 页面。
    * 用户在该 `<div>` 元素上进行触摸并尝试垂直滑动。
    * 用户在该 `<div>` 元素上进行触摸并尝试水平滑动。
* **逻辑推理:**
    * Blink 引擎会解析 CSS，识别 `touch-action: pan-y;` 的设置。
    * 当用户触摸该 `<div>` 元素时，Blink 引擎会为该元素设置 `TouchAction::kPanY`。
    * 当用户尝试垂直滑动时，Blink 引擎会允许默认的垂直滚动行为。
    * 当用户尝试水平滑动时，Blink 引擎会阻止默认的水平滚动行为。
* **预期输出 (通过测试验证):**
    * `TouchActionWidgetInputHandlerHost::SetTouchActionFromMain` 方法会被调用，并将 `TouchAction::kPanY` 传递进去。
    * 垂直滑动操作会被允许，页面会发生垂直滚动。
    * 水平滑动操作会被阻止，页面不会发生水平滚动。

**4. 涉及的用户或编程常见使用错误:**

* **误解 `touch-action` 的继承性:** 开发者可能认为父元素的 `touch-action` 会自动应用于所有子元素，但实际情况是，`touch-action` 属性是可以被子元素覆盖的。
    * **示例:**
      ```html
      <div style="touch-action: none;">
        <div id="inner" style="touch-action: auto;">内部元素可以滚动</div>
      </div>
      ```
      用户可能期望外部 `div` 阻止所有滚动，但内部 `div` 设置了 `touch-action: auto;`，所以内部元素是可以滚动的。测试用例会验证这种继承和覆盖的正确性。
* **不理解不同 `touch-action` 值的含义:** 开发者可能不清楚 `pan-x` 和 `pan-y` 的区别，或者不明白 `manipulation` 的具体效果。测试用例可以帮助澄清这些概念，并确保 Blink 引擎的行为符合规范。
* **在不需要时过度使用 `touch-action: none;`:**  开发者可能会为了防止某些意外的滚动行为而过度使用 `touch-action: none;`，这可能会导致用户无法进行正常的交互，例如无法滚动包含大量内容的区域。测试鼓励开发者更精细地控制触摸行为，而不是简单地禁用所有默认行为。

**5. 用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中与网页进行交互时，例如在触摸屏设备上进行触摸、滑动或捏合缩放操作时，会产生一系列的事件，这些事件最终可能会触发 `touch_action_test.cc` 中测试的代码逻辑。以下是可能的步骤：

1. **用户触摸屏幕:** 用户的手指或触控笔接触到屏幕。
2. **操作系统识别触摸事件:** 操作系统接收到硬件信号，并将其转换为触摸事件（例如，Windows 的 Pointer Events，Android 的 Touch Events）。
3. **浏览器进程接收触摸事件:** 操作系统将触摸事件传递给浏览器的渲染进程。
4. **Blink 引擎处理触摸事件:** Blink 引擎的输入处理模块接收到触摸事件。
5. **事件分发和目标确定:** Blink 引擎会根据触摸的位置，进行 hit testing，确定触摸事件的目标元素。
6. **`touch-action` 属性的评估:**  Blink 引擎会查找目标元素及其祖先元素的 `touch-action` CSS 属性。根据 CSS 级联规则，计算出最终应用于目标元素的 `touch-action` 值.
7. **设置 `TouchAction`:**  基于计算出的 `touch-action` 值，Blink 引擎会设置该元素的 `TouchAction` 内部状态。这部分逻辑就可能涉及到 `TouchActionWidgetInputHandlerHost::SetTouchActionFromMain` 方法，这是 `touch_action_test.cc` 中测试的关键部分。
8. **后续事件处理:**  根据 `TouchAction` 的设置，Blink 引擎会决定如何处理后续的触摸移动和结束事件。例如，如果 `TouchAction` 是 `kNone`，则可能会阻止默认的滚动或缩放行为。
9. **页面渲染更新:**  根据触摸操作和 `TouchAction` 的影响，浏览器可能会重新渲染页面，例如滚动页面的内容。

**作为调试线索:**

如果开发者在实现涉及触摸交互的网页时遇到问题，例如滚动行为不符合预期，可以按照以下步骤进行调试，`touch_action_test.cc` 的测试用例可以作为参考：

1. **检查元素的 `touch-action` 样式:** 使用浏览器的开发者工具检查目标元素及其父元素的 `touch-action` 样式，确认样式是否设置正确，是否存在样式覆盖的情况。
2. **模拟触摸事件:** 使用浏览器的开发者工具或编写 JavaScript 代码模拟触摸事件，观察浏览器的行为。
3. **参考 `touch_action_test.cc` 中的测试用例:**  查看 `touch_action_test.cc` 中类似的测试用例，了解 Blink 引擎在特定 `touch-action` 设置下的预期行为。这可以帮助开发者理解 `touch-action` 的工作原理，并找到问题所在。
4. **断点调试 Blink 引擎代码 (高级):** 如果需要深入了解 Blink 引擎的处理逻辑，可以在相关的 C++ 代码（例如 `blink/renderer/core/input/EventHandler.cc` 或 `blink/renderer/core/dom/Element.cc`）中设置断点，跟踪触摸事件的处理流程和 `TouchAction` 的设置过程。 `touch_action_test.cc` 本身就是测试这些代码逻辑的，因此可以作为理解代码行为的起点。

总而言之，`blink/renderer/core/input/touch_action_test.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎正确实现了 `touch-action` CSS 属性，从而保证了 Web 开发者能够可靠地控制网页在触摸设备上的交互行为。

Prompt: 
```
这是目录为blink/renderer/core/input/touch_action_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "base/functional/callback_helpers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_hit_test_result.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_list.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_tree_as_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

using blink::test::RunPendingTasks;

namespace blink {

class TouchActionWidgetInputHandlerHost
    : public frame_test_helpers::TestWidgetInputHandlerHost {
 public:
  void SetTouchActionFromMain(TouchAction touch_action) override {
    action_set_count_++;
    action_ = touch_action;
  }

  void ResetTouchAction() {
    action_set_count_ = 0;
    action_ = TouchAction::kAuto;
  }

  int action_set_count() const { return action_set_count_; }

  TouchAction action() const { return action_; }

 private:
  int action_set_count_ = 0;
  TouchAction action_ = TouchAction::kAuto;
};

class TouchActionTrackingWebFrameWidget
    : public frame_test_helpers::TestWebFrameWidget {
 public:
  template <typename... Args>
  explicit TouchActionTrackingWebFrameWidget(Args&&... args)
      : frame_test_helpers::TestWebFrameWidget(std::forward<Args>(args)...) {}

  // frame_test_helpers::TestWebFrameWidget overrides.
  frame_test_helpers::TestWidgetInputHandlerHost* GetInputHandlerHost()
      override {
    return &input_handler_host_;
  }

  void Reset() { input_handler_host_.ResetTouchAction(); }

  int TouchActionSetCount() { return input_handler_host_.action_set_count(); }

  TouchAction LastTouchAction() { return input_handler_host_.action(); }

 private:
  TouchActionWidgetInputHandlerHost input_handler_host_;
};

class TouchActionTest : public testing::Test {
 public:
  TouchActionTest()
      : base_url_("http://www.test.com/"),
        web_view_helper_(WTF::BindRepeating(
            &frame_test_helpers::WebViewHelper::CreateTestWebFrameWidget<
                TouchActionTrackingWebFrameWidget>)) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |web_view_helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString(base_url_), test::CoreTestDataPath(),
        "touch-action-tests.css", "text/css");
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |web_view_helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString(base_url_), test::CoreTestDataPath(), "touch-action-tests.js",
        "text/javascript");
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |web_view_helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString(base_url_), test::CoreTestDataPath(), "white-1x1.png",
        "image/png");
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

 protected:
  void RunTouchActionTest(String file);
  void RunShadowDOMTest(String file);
  void RunIFrameTest(String file);
  void SendTouchEvent(WebView*, WebInputEvent::Type, gfx::Point client_point);
  WebViewImpl* SetupTest(String file);
  void RunTestOnTree(ContainerNode* root, WebView*);

  test::TaskEnvironment task_environment_;

  String base_url_;
  frame_test_helpers::WebViewHelper web_view_helper_;
};

void TouchActionTest::RunTouchActionTest(String file) {
  // runTouchActionTest() loads a document in a frame, setting up a
  // nested run loop. Should any Oilpan GC happen while it is in
  // effect, the implicit assumption that we're outside any event
  // loop (=> there being no pointers on the stack needing scanning)
  // when that GC strikes will no longer hold.
  //
  // To ensure that the references on the stack are also traced, we
  // turn them into persistent, stack allocated references. This
  // workaround is sufficient to handle this artificial test
  // scenario.
  WebViewImpl* web_view = SetupTest(file);

  Persistent<Document> document =
      static_cast<Document*>(web_view->MainFrameImpl()->GetDocument());
  RunTestOnTree(document.Get(), web_view);

  // Explicitly reset to break dependency on locally scoped client.
  web_view_helper_.Reset();
}

void TouchActionTest::RunShadowDOMTest(String file) {
  WebViewImpl* web_view = SetupTest(file);

  DummyExceptionStateForTesting es;

  // Oilpan: see runTouchActionTest() comment why these are persistent
  // references.
  Persistent<Document> document =
      static_cast<Document*>(web_view->MainFrameImpl()->GetDocument());
  Persistent<StaticElementList> host_nodes =
      document->QuerySelectorAll(AtomicString("[shadow-host]"), es);
  ASSERT_FALSE(es.HadException());
  ASSERT_GE(host_nodes->length(), 1u);

  for (unsigned index = 0; index < host_nodes->length(); index++) {
    ShadowRoot* shadow_root = host_nodes->item(index)->OpenShadowRoot();
    RunTestOnTree(shadow_root, web_view);
  }

  // Projections show up in the main document.
  RunTestOnTree(document.Get(), web_view);

  // Explicitly reset to break dependency on locally scoped client.
  web_view_helper_.Reset();
}

void TouchActionTest::RunIFrameTest(String file) {
  WebViewImpl* web_view = SetupTest(file);
  WebFrame* cur_frame = web_view->MainFrame()->FirstChild();
  ASSERT_TRUE(cur_frame);

  for (; cur_frame; cur_frame = cur_frame->NextSibling()) {
    // Oilpan: see runTouchActionTest() comment why these are persistent
    // references.
    Persistent<Document> content_doc =
        static_cast<Document*>(cur_frame->ToWebLocalFrame()->GetDocument());
    RunTestOnTree(content_doc.Get(), web_view);
  }

  // Explicitly reset to break dependency on locally scoped client.
  web_view_helper_.Reset();
}

WebViewImpl* TouchActionTest::SetupTest(String file) {
  // TODO(crbug.com/751425): We should use the mock functionality
  // via |web_view_helper_|.
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString(base_url_), test::CoreTestDataPath(), WebString(file));
  // Note that JavaScript must be enabled for shadow DOM tests.
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_.Utf8() + file.Utf8(), nullptr, nullptr);

  // Set size to enable hit testing, and avoid line wrapping for consistency
  // with browser.
  web_view->MainFrameViewWidget()->Resize(gfx::Size(900, 1600));
  web_view->MainFrameWidget()->UpdateLifecycle(WebLifecycleUpdate::kAll,
                                               DocumentUpdateReason::kTest);

  // Scroll to verify the code properly transforms windows to client co-ords.
  const int kScrollOffset = 100;
  Document* document =
      static_cast<Document*>(web_view->MainFrameImpl()->GetDocument());
  document->GetFrame()->View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, kScrollOffset), mojom::blink::ScrollType::kProgrammatic);

  return web_view;
}

gfx::Rect WindowClipRect(const LocalFrameView& frame_view) {
  PhysicalRect clip_rect(PhysicalOffset(), PhysicalSize(frame_view.Size()));
  frame_view.GetLayoutView()->MapToVisualRectInAncestorSpace(nullptr,
                                                             clip_rect);
  return ToEnclosingRect(clip_rect);
}

void TouchActionTest::RunTestOnTree(ContainerNode* root, WebView* web_view) {
  // Find all elements to test the touch-action of in the document.
  DummyExceptionStateForTesting es;

  // Oilpan: see runTouchActionTest() comment why these are persistent
  // references.
  Persistent<StaticElementList> elements =
      root->QuerySelectorAll(AtomicString("[expected-action]"), es);
  ASSERT_FALSE(es.HadException());

  for (unsigned index = 0; index < elements->length(); index++) {
    Element* element = elements->item(index);
    element->scrollIntoViewIfNeeded();

    StringBuilder failure_context;
    failure_context.Append("Test case: ");
    if (element->HasID()) {
      failure_context.Append(element->GetIdAttribute());
    } else if (element->firstChild()) {
      failure_context.Append("\"");
      failure_context.Append(element->firstChild()
                                 ->textContent(false)
                                 .StripWhiteSpace()
                                 .Ascii()
                                 .data());
      failure_context.Append("\"");
    } else {
      failure_context.Append("<missing ID>");
    }

    // Run each test three times at different positions in the element.
    // Note that we don't want the bounding box because our tests sometimes have
    // elements with multiple border boxes with other elements in between. Use
    // the first border box (which we can easily visualize in a browser for
    // debugging).
    Persistent<DOMRectList> rects = element->getClientRects();
    ASSERT_GE(rects->length(), 0u) << failure_context.ToString();
    if (!rects->length())
      continue;
    Persistent<DOMRect> r = rects->item(0);
    gfx::RectF client_float_rect =
        gfx::RectF(r->left(), r->top(), r->width(), r->height());
    gfx::Rect client_rect = ToEnclosedRect(client_float_rect);
    for (int loc_idx = 0; loc_idx < 3; loc_idx++) {
      gfx::Point frame_point;
      std::stringstream context_stream;
      context_stream << failure_context.ToString() << " (";
      switch (loc_idx) {
        case 0:
          frame_point = client_rect.CenterPoint();
          context_stream << "center";
          break;
        case 1:
          frame_point = client_rect.origin();
          context_stream << "top-left";
          break;
        case 2:
          frame_point = client_rect.bottom_right();
          frame_point.Offset(-1, -1);
          context_stream << "bottom-right";
          break;
        default:
          FAIL() << "Invalid location index.";
      }

      gfx::Point window_point =
          root->GetDocument().GetFrame()->View()->ConvertToRootFrame(
              frame_point);
      context_stream << "=" << window_point.x() << "," << window_point.y()
                     << ").";
      String failure_context_pos = String::FromUTF8(context_stream.str());

      LocalFrame* main_frame =
          To<LocalFrame>(WebFrame::ToCoreFrame(*web_view->MainFrame()));
      LocalFrameView* main_frame_view = main_frame->View();
      gfx::Rect visible_rect = WindowClipRect(*main_frame_view);
      ASSERT_TRUE(visible_rect.Contains(window_point))
          << failure_context_pos
          << " Test point not contained in visible area: " << visible_rect.x()
          << "," << visible_rect.y() << "-" << visible_rect.right() << ","
          << visible_rect.bottom();

      // First validate that a hit test at this point will really hit the
      // element we intended. This is the easiest way for a test to be broken,
      // but has nothing really to do with touch action.  Note that we can't use
      // WebView's hit test API because it doesn't look into shadow DOM.
      HitTestLocation location(window_point);
      HitTestResult result =
          main_frame->GetEventHandler().HitTestResultAtLocation(
              location, HitTestRequest::kReadOnly | HitTestRequest::kActive);
      ASSERT_EQ(element, result.InnerElement())
          << "Unexpected hit test result " << failure_context_pos
          << "  Got element: \""
          << result.InnerElement()
                 ->outerHTML()
                 .StripWhiteSpace()
                 .Left(80)
                 .Ascii()
                 .data()
          << "\"" << std::endl
          << "Document render tree:" << std::endl
          << ExternalRepresentation(root->GetDocument().GetFrame()).Utf8();

      // Now send the touch event and check any touch action result.
      SendTouchEvent(web_view, WebInputEvent::Type::kPointerDown, window_point);
      RunPendingTasks();

      TouchActionTrackingWebFrameWidget* widget =
          static_cast<TouchActionTrackingWebFrameWidget*>(
              web_view->MainFrameWidget());

      AtomicString expected_action =
          element->getAttribute(AtomicString("expected-action"));
      // Should have received exactly one touch action, even for auto.
      EXPECT_EQ(1, widget->TouchActionSetCount()) << failure_context_pos;
      if (widget->TouchActionSetCount()) {
        if (expected_action == "auto") {
          EXPECT_EQ(TouchAction::kAuto, widget->LastTouchAction())
              << failure_context_pos;
        } else if (expected_action == "none") {
          EXPECT_EQ(TouchAction::kNone, widget->LastTouchAction() &
                                            ~TouchAction::kInternalNotWritable)
              << failure_context_pos;
        } else if (expected_action == "pan-x") {
          EXPECT_EQ(TouchAction::kPanX, widget->LastTouchAction() &
                                            ~TouchAction::kInternalPanXScrolls &
                                            ~TouchAction::kInternalNotWritable)
              << failure_context_pos;
        } else if (expected_action == "pan-y") {
          EXPECT_EQ(TouchAction::kPanY, widget->LastTouchAction() &
                                            ~TouchAction::kInternalNotWritable)
              << failure_context_pos;
        } else if (expected_action == "pan-x-y") {
          EXPECT_EQ(TouchAction::kPan, widget->LastTouchAction() &
                                           ~TouchAction::kInternalPanXScrolls &
                                           ~TouchAction::kInternalNotWritable)
              << failure_context_pos;
        } else if (expected_action == "manipulation") {
          EXPECT_EQ(TouchAction::kManipulation,
                    widget->LastTouchAction() &
                        ~TouchAction::kInternalPanXScrolls &
                        ~TouchAction::kInternalNotWritable)
              << failure_context_pos;
        } else {
          FAIL() << "Unrecognized expected-action " << expected_action << " "
                 << failure_context_pos;
        }
      }

      // Reset webview touch state.
      widget->Reset();
      SendTouchEvent(web_view, WebInputEvent::Type::kPointerCancel,
                     window_point);
      EXPECT_EQ(0, widget->TouchActionSetCount());
    }
  }
}
void TouchActionTest::SendTouchEvent(WebView* web_view,
                                     WebInputEvent::Type type,
                                     gfx::Point client_point) {
  ASSERT_TRUE(type == WebInputEvent::Type::kPointerDown ||
              type == WebInputEvent::Type::kPointerCancel);

  WebPointerEvent event(
      type,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                           WebPointerProperties::Button::kLeft,
                           gfx::PointF(client_point.x(), client_point.y()),
                           gfx::PointF(client_point.x(), client_point.y())),
      10.0f, 10.0f);
  if (type == WebInputEvent::Type::kPointerCancel)
    event.dispatch_type = WebInputEvent::DispatchType::kEventNonBlocking;
  else
    event.touch_start_or_first_touch_move = true;

  web_view->MainFrameWidget()->ProcessInputEventSynchronouslyForTesting(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  web_view->MainFrameWidget()->DispatchBufferedTouchEvents();
  RunPendingTasks();
}

// crbug.com/411038
TEST_F(TouchActionTest, Simple) {
  RunTouchActionTest("touch-action-simple.html");
}

TEST_F(TouchActionTest, Overflow) {
  RunTouchActionTest("touch-action-overflow.html");
}

TEST_F(TouchActionTest, IFrame) {
  RunIFrameTest("touch-action-iframe.html");
}

TEST_F(TouchActionTest, ShadowDOM) {
  RunShadowDOMTest("touch-action-shadow-dom.html");
}

TEST_F(TouchActionTest, Pan) {
  RunTouchActionTest("touch-action-pan.html");
}

}  // namespace blink

"""

```