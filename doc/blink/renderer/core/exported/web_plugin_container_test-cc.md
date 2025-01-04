Response:
The user has provided the first part of a C++ test file for Chromium's Blink rendering engine, specifically focusing on testing the `WebPluginContainer`. They want me to summarize the functionality of this part of the file, and point out connections to web technologies like JavaScript, HTML, and CSS. I also need to provide examples of logical reasoning, potential user errors, and how a user might reach this code.

Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The file name `web_plugin_container_test.cc` immediately tells me this is a test file. The "test" suffix is a strong indicator. The class name `WebPluginContainerTest` confirms it's specifically testing the `WebPluginContainer`.

2. **Analyze Includes:** The included headers provide clues about the functionality being tested. Key includes include:
    * `third_party/blink/public/web/web_plugin_container.h`: This is the primary class being tested.
    * `testing/gtest/include/gtest/gtest.h`: Indicates the use of Google Test framework for testing.
    * `third_party/blink/public/common/input/...`:  Suggests input event handling is being tested.
    * `third_party/blink/public/web/...`:  Includes various web API interfaces, hinting at interactions with the web platform.
    * `third_party/blink/renderer/core/...`: Includes internal Blink components, indicating lower-level testing.
    * `third_party/blink/renderer/core/testing/...`:  Confirms the file is part of the testing infrastructure.

3. **Examine the Test Fixture:** The `WebPluginContainerTest` class inherits from `PageTestBase`. This setup is common in Blink tests and provides a controlled environment for loading and interacting with web pages. The `SetUp` and `TearDown` methods further confirm this, handling initialization and cleanup.

4. **Identify Helper Functions:** The `CalculateGeometry`, `RegisterMockedURL`, and `UpdateAllLifecyclePhases` functions are utilities for setting up test scenarios. `RegisterMockedURL` suggests simulating network requests, crucial for testing plugin interactions with external resources.

5. **Analyze Test Cases:** The `namespace {` block contains the actual test logic. I can see various `TEST_F` macros, which define individual test cases. Reading the names of these tests reveals the specific functionalities being tested:
    * `WindowToLocalPointTest`, `LocalToWindowPointTest`: Testing coordinate transformations.
    * `Copy`, `CopyWithoutPermission`, `CopyFromContextMenu`, etc.: Testing clipboard interaction.
    * `CopyInsertKeyboardEventsTest`, `CutDeleteKeyboardEventsTest`, `PasteInsertKeyboardEventsTest`, etc.: Testing keyboard event handling.
    * `CutFromContextMenu`, `PasteFromContextMenu`, etc.: Testing context menu interactions.
    * `GestureLongPressReachesPlugin`: Testing gesture event handling.

6. **Connect to Web Technologies:** Based on the test names and included headers, I can identify the connections to JavaScript, HTML, and CSS:
    * **HTML:** The tests load HTML files (`plugin_container.html`). The tests manipulate DOM elements (`GetElementById`). Plugins are embedded within HTML using `<embed>` or `<object>` tags (implied).
    * **CSS:** CSS is used to style the plugin containers (translation, rotation). The coordinate transformation tests directly relate to how CSS transforms affect plugin positioning.
    * **JavaScript:** While not explicitly tested in *this part* of the file, the functionality being tested (plugin interaction, event handling) is often triggered or controlled by JavaScript. Plugins can expose APIs that JavaScript can interact with.

7. **Logical Reasoning Examples:** I can create hypothetical scenarios based on the tests:
    * **Input:** A user clicks inside a plugin. **Output:** The plugin receives mouse events with correct local coordinates.
    * **Input:** A user presses Ctrl+C while a plugin has focus. **Output:** The plugin's selected content is copied to the clipboard.

8. **User/Programming Errors:** I can think of common mistakes:
    * **User Error:**  Right-clicking outside the plugin's bounds and expecting the plugin's context menu.
    * **Programming Error:**  Incorrectly calculating plugin coordinates, leading to misdirected input events. Forgetting to handle specific keyboard shortcuts in the plugin.

9. **Debugging Clues:** The file itself serves as a debugging clue. If a bug is reported related to plugin behavior (e.g., incorrect event handling, clipboard issues), a developer might look at these tests to understand how the intended behavior is implemented and to potentially reproduce the bug. The steps to reach this code during debugging involve:
    1. Identifying the buggy behavior (e.g., "copy doesn't work in this plugin").
    2. Suspecting the `WebPluginContainer` is involved.
    3. Looking for relevant tests in `web_plugin_container_test.cc` (e.g., `CopyWithoutPermission`).
    4. Running the test to see if it fails, indicating a regression.
    5. Stepping through the test code and the `WebPluginContainer` implementation to pinpoint the issue.

10. **Summarize Functionality (Part 1):**  Based on the above analysis, I can summarize that this part of the file primarily focuses on testing the basic functionality of `WebPluginContainer`, including:
    * Coordinate transformations between the plugin and the page.
    * Clipboard operations (copy, cut, paste) triggered by menu actions and keyboard shortcuts.
    * Basic input event handling (keyboard and mouse).
    * Setup and utilities for creating plugin test scenarios.
这是chromium blink引擎源代码文件`web_plugin_container_test.cc`的第一部分，它的主要功能是**为`WebPluginContainer`类编写单元测试**。

**更具体地说，这部分测试代码主要关注以下功能：**

* **坐标转换：** 测试插件容器的坐标系统与页面坐标系统之间的转换，包括 `WindowToLocalPoint` 和 `LocalToWindowPoint` 方法的正确性。
* **剪贴板操作：** 测试与剪贴板相关的操作，例如 "复制" (Copy) 功能，包括通过菜单和键盘快捷键触发的情况，以及在没有复制权限时的行为。
* **键盘事件处理：** 测试插件容器如何处理各种键盘事件，特别是与编辑相关的快捷键，例如 "复制" (Ctrl+C, Ctrl+Insert), "剪切" (Ctrl+X, Shift+Delete), "粘贴" (Ctrl+V, Shift+Insert), "粘贴并匹配样式" (Ctrl+Shift+V)。
* **上下文菜单操作：** 测试通过右键点击上下文菜单触发的 "复制"、"剪切" 和 "粘贴" 等编辑命令。
* **事件传递：** 引入一个专门的 `EventTestPlugin` 来测试手势事件 (例如长按) 是否能正确传递到插件。

**与 javascript, html, css 的功能关系及举例说明：**

* **HTML:**
    * **关系：**  `WebPluginContainer` 对应于HTML文档中的 `<embed>` 或 `<object>` 元素，这些元素用于嵌入插件。测试代码中通过加载 `plugin_container.html` 文件来创建包含插件的页面。
    * **举例：** 测试代码中使用了 `web_view->MainFrameImpl()->GetDocument().GetElementById(WebString::FromUTF8("translated-plugin"))` 来获取HTML文档中 ID 为 "translated-plugin" 的元素，该元素通常会对应一个插件容器。
* **CSS:**
    * **关系：** CSS 可以用来定位和变换插件容器。测试代码中的 `WindowToLocalPointTest` 和 `LocalToWindowPointTest` 涉及到插件容器的 CSS `transform` 属性（例如 `translate` 和 `rotate`）对坐标转换的影响。
    * **举例：**  测试用例创建了带有 `translated-plugin` 和 `rotated-plugin` ID 的插件，这暗示了HTML中可能存在对应的CSS样式来应用平移和旋转变换。测试代码验证了在这些变换下，坐标转换是否仍然正确。
* **JavaScript:**
    * **关系：** 虽然这部分测试代码本身没有直接涉及 JavaScript，但 `WebPluginContainer` 是 JavaScript 与插件交互的重要桥梁。JavaScript 可以通过 DOM API 操作插件容器，或者调用插件暴露的接口。
    * **举例：**  假设 HTML 中有一个按钮，通过 JavaScript 绑定了点击事件，点击后会调用插件的某个方法。虽然这里没有直接测试 JavaScript 交互，但 `WebPluginContainer` 的正确性对于这种场景至关重要。

**逻辑推理及假设输入与输出：**

* **假设输入：** 用户在页面上平移了 10 像素的插件容器，然后在页面坐标 (100, 100) 处点击。
* **逻辑推理：** `WindowToLocalPointTest` 测试了插件容器的 `RootFrameToLocalPoint` 方法。该方法应该能够根据插件容器的平移量，将页面坐标转换为插件内部的局部坐标。
* **输出：**  如果插件容器向右平移了 10 像素，那么 `plugin_container_one->RootFrameToLocalPoint(gfx::Point(100, 100))` 应该返回 (90, 100)。

**用户或编程常见的使用错误及举例说明：**

* **用户错误：**  用户可能在没有选中插件内容的情况下尝试复制，或者在插件不支持编辑的情况下尝试粘贴。
    * **举例：**  如果用户在一个只显示视频的插件上按下 Ctrl+C，但插件本身没有实现复制功能，那么剪贴板应该不会有任何内容。`CopyWithoutPermission` 测试用例模拟了插件没有复制权限的情况，验证了此时复制操作不会成功。
* **编程错误：**  开发者可能错误地计算了插件的局部坐标，导致事件处理逻辑错误。
    * **举例：** 如果插件开发者在处理鼠标点击事件时，没有正确使用 `RootFrameToLocalPoint` 将全局坐标转换为插件局部坐标，那么点击事件可能无法触发插件内部的正确操作。 `WindowToLocalPointTest` 和 `LocalToWindowPointTest` 可以帮助开发者验证坐标转换的正确性，避免此类错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户报告了一个关于插件功能的 bug。** 例如，用户反馈在一个嵌入的 Flash 插件中无法使用复制粘贴功能。
2. **开发者怀疑是 `WebPluginContainer` 的实现有问题。** 因为 `WebPluginContainer` 负责处理插件的事件和剪贴板交互。
3. **开发者查看 `blink/renderer/core/exported/web_plugin_container_test.cc`。**  他们希望通过阅读和运行相关的测试用例来理解 `WebPluginContainer` 的预期行为，并尝试复现用户报告的 bug。
4. **开发者可能会运行与剪贴板操作相关的测试用例。** 例如，他们会运行 `Copy`、`CopyWithoutPermission`、`CutFromContextMenu` 等测试用例，看是否能找到与用户反馈一致的错误。
5. **如果测试用例失败，开发者可以深入研究测试代码和 `WebPluginContainerImpl` 的实现。**  他们可能会设置断点，单步执行代码，查看变量的值，以找出导致 bug 的原因。
6. **如果测试用例没有失败，开发者可能会需要编写新的测试用例来覆盖用户报告的特定场景。** 这有助于更精确地定位问题。

**功能归纳 (第1部分)：**

这部分 `web_plugin_container_test.cc` 文件主要**测试了 `WebPluginContainer` 的基本功能，包括坐标转换、剪贴板操作、键盘事件处理和上下文菜单交互。** 它通过创建包含插件的页面，并模拟用户操作（例如点击、键盘输入、右键点击），来验证 `WebPluginContainer` 是否按照预期工作。这些测试对于确保插件能够正确地与页面进行交互至关重要。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_plugin_container_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
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

#include "third_party/blink/public/web/web_plugin_container.h"

#include <memory>
#include <string>

#include "build/build_config.h"
#include "cc/layers/layer.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_plugin_params.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/testing/fake_web_plugin.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/scoped_fake_plugin_registry.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_recorder.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

using blink::test::RunPendingTasks;

namespace blink {

class WebPluginContainerTest : public PageTestBase {
 public:
  WebPluginContainerTest() : base_url_("http://www.test.com/") {}

  void SetUp() override {
    PageTestBase::SetUp();
    mock_clipboard_host_provider_.Install(
        GetFrame().GetBrowserInterfaceBroker());
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
    PageTestBase::TearDown();
  }

  void CalculateGeometry(WebPluginContainerImpl* plugin_container_impl,
                         gfx::Rect& window_rect,
                         gfx::Rect& clip_rect,
                         gfx::Rect& unobscured_rect) {
    plugin_container_impl->CalculateGeometry(window_rect, clip_rect,
                                             unobscured_rect);
  }

  void RegisterMockedURL(
      const std::string& file_name,
      const std::string& mime_type = std::string("text/html")) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper in each test case.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name), WebString::FromUTF8(mime_type));
  }

  void UpdateAllLifecyclePhases(WebViewImpl* web_view) {
    web_view->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

 protected:
  ScopedFakePluginRegistry fake_plugins_;
  std::string base_url_;

 private:
  PageTestBase::MockClipboardHostProvider mock_clipboard_host_provider_;
};

namespace {

#if BUILDFLAG(IS_MAC)
const WebInputEvent::Modifiers kEditingModifier = WebInputEvent::kMetaKey;
#else
const WebInputEvent::Modifiers kEditingModifier = WebInputEvent::kControlKey;
#endif

template <typename T>
class CustomPluginWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  WebPlugin* CreatePlugin(const WebPluginParams& params) override {
    return new T(params);
  }
};

class TestPluginWebFrameClient;

// Subclass of FakeWebPlugin that has a selection of 'x' as plain text and 'y'
// as markup text.
class TestPlugin : public FakeWebPlugin {
 public:
  TestPlugin(const WebPluginParams& params,
             TestPluginWebFrameClient* test_client)
      : FakeWebPlugin(params), test_client_(test_client) {}

  bool HasSelection() const override { return true; }
  WebString SelectionAsText() const override { return WebString("x"); }
  WebString SelectionAsMarkup() const override { return WebString("y"); }
  bool CanCopy() const override;
  bool SupportsPaginatedPrint() override { return true; }
  int PrintBegin(const WebPrintParams& print_params) override { return 1; }
  void PrintPage(int page_index, cc::PaintCanvas* canvas) override;

 private:
  ~TestPlugin() override = default;

  TestPluginWebFrameClient* const test_client_;
};

// Subclass of FakeWebPlugin used for testing edit commands, so HasSelection()
// and CanEditText() return true by default.
class TestPluginWithEditableText : public FakeWebPlugin {
 public:
  static TestPluginWithEditableText* FromContainer(WebElement* element) {
    WebPlugin* plugin =
        To<WebPluginContainerImpl>(element->PluginContainer())->Plugin();
    return static_cast<TestPluginWithEditableText*>(plugin);
  }

  explicit TestPluginWithEditableText(const WebPluginParams& params)
      : FakeWebPlugin(params), cut_called_(false), paste_called_(false) {}

  bool HasSelection() const override { return true; }
  bool CanEditText() const override { return true; }
  bool ExecuteEditCommand(const WebString& name,
                          const WebString& value) override {
    if (name == "Cut") {
      cut_called_ = true;
      return true;
    }
    if (name == "Paste" || name == "PasteAndMatchStyle") {
      paste_called_ = true;
      return true;
    }
    return false;
  }

  bool IsCutCalled() const { return cut_called_; }
  bool IsPasteCalled() const { return paste_called_; }
  void ResetEditCommandState() {
    cut_called_ = false;
    paste_called_ = false;
  }

 private:
  ~TestPluginWithEditableText() override = default;

  bool cut_called_;
  bool paste_called_;
};

class TestPluginWebFrameClient : public frame_test_helpers::TestWebFrameClient {
  WebLocalFrame* CreateChildFrame(
      mojom::blink::TreeScopeType scope,
      const WebString& name,
      const WebString& fallback_name,
      const FramePolicy&,
      const WebFrameOwnerProperties&,
      FrameOwnerElementType owner_type,
      WebPolicyContainerBindParams policy_container_bind_params,
      ukm::SourceId document_ukm_source_id,
      FinishChildFrameCreationFn finish_creation) override {
    return CreateLocalChild(
        *Frame(), scope, std::make_unique<TestPluginWebFrameClient>(),
        std::move(policy_container_bind_params), finish_creation);
  }

  WebPlugin* CreatePlugin(const WebPluginParams& params) override {
    if (params.mime_type == "application/x-webkit-test-webplugin" ||
        params.mime_type == "application/pdf") {
      if (has_editable_text_)
        return new TestPluginWithEditableText(params);

      return new TestPlugin(params, this);
    }
    return WebLocalFrameClient::CreatePlugin(params);
  }

 public:
  TestPluginWebFrameClient() = default;

  void OnPrintPage() { printed_page_ = true; }
  bool PrintedAtLeastOnePage() const { return printed_page_; }
  void SetHasEditableText(bool has_editable_text) {
    has_editable_text_ = has_editable_text;
  }
  void SetCanCopy(bool can_copy) { can_copy_ = can_copy; }
  bool CanCopy() const { return can_copy_; }

 private:
  bool printed_page_ = false;
  bool has_editable_text_ = false;
  bool can_copy_ = true;
};

bool TestPlugin::CanCopy() const {
  DCHECK(test_client_);
  return test_client_->CanCopy();
}

void TestPlugin::PrintPage(int page_index, cc::PaintCanvas* canvas) {
  DCHECK(test_client_);
  test_client_->OnPrintPage();
}

void EnablePlugins(WebView* web_view, const gfx::Size& size) {
  DCHECK(web_view);
  web_view->GetSettings()->SetPluginsEnabled(true);
  web_view->MainFrameWidget()->Resize(size);
  web_view->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();
}

WebPluginContainer* GetWebPluginContainer(WebViewImpl* web_view,
                                          const WebString& id) {
  WebElement element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(id);
  return element.PluginContainer();
}

String ReadClipboard(LocalFrame& frame) {
  // Run all tasks in a message loop to allow asynchronous clipboard writing
  // to happen before reading from it synchronously.
  test::RunPendingTasks();
  return frame.GetSystemClipboard()->ReadPlainText();
}

void ClearClipboardBuffer(LocalFrame& frame) {
  frame.GetSystemClipboard()->WritePlainText(String(""));
  frame.GetSystemClipboard()->CommitWrite();
  EXPECT_EQ(String(""), ReadClipboard(frame));
}

void CreateAndHandleKeyboardEvent(WebElement* plugin_container_one_element,
                                  WebInputEvent::Modifiers modifier_key,
                                  int key_code) {
  WebKeyboardEvent web_keyboard_event(
      WebInputEvent::Type::kRawKeyDown, modifier_key,
      WebInputEvent::GetStaticTimeStampForTests());
  web_keyboard_event.windows_key_code = key_code;
  KeyboardEvent* key_event = KeyboardEvent::Create(web_keyboard_event, nullptr);
  To<WebPluginContainerImpl>(plugin_container_one_element->PluginContainer())
      ->HandleEvent(*key_event);
}

void ExecuteContextMenuCommand(WebViewImpl* web_view,
                               const WebString& command_name) {
  auto event = frame_test_helpers::CreateMouseEvent(
      WebMouseEvent::Type::kMouseDown, WebMouseEvent::Button::kRight,
      gfx::Point(30, 30), 0);
  event.click_count = 1;

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  EXPECT_TRUE(
      web_view->MainFrame()->ToWebLocalFrame()->ExecuteCommand(command_name));
}

}  // namespace

TEST_F(WebPluginContainerTest, WindowToLocalPointTest) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebPluginContainer* plugin_container_one =
      GetWebPluginContainer(web_view, WebString::FromUTF8("translated-plugin"));
  DCHECK(plugin_container_one);
  gfx::Point point1 =
      plugin_container_one->RootFrameToLocalPoint(gfx::Point(10, 10));
  ASSERT_EQ(0, point1.x());
  ASSERT_EQ(0, point1.y());
  gfx::Point point2 =
      plugin_container_one->RootFrameToLocalPoint(gfx::Point(100, 100));
  ASSERT_EQ(90, point2.x());
  ASSERT_EQ(90, point2.y());

  WebPluginContainer* plugin_container_two =
      GetWebPluginContainer(web_view, WebString::FromUTF8("rotated-plugin"));
  DCHECK(plugin_container_two);
  gfx::Point point3 =
      plugin_container_two->RootFrameToLocalPoint(gfx::Point(0, 10));
  ASSERT_EQ(10, point3.x());
  ASSERT_EQ(0, point3.y());
  gfx::Point point4 =
      plugin_container_two->RootFrameToLocalPoint(gfx::Point(-10, 10));
  ASSERT_EQ(10, point4.x());
  ASSERT_EQ(10, point4.y());
}

TEST_F(WebPluginContainerTest, LocalToWindowPointTest) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebPluginContainer* plugin_container_one =
      GetWebPluginContainer(web_view, WebString::FromUTF8("translated-plugin"));
  DCHECK(plugin_container_one);
  gfx::Point point1 =
      plugin_container_one->LocalToRootFramePoint(gfx::Point(0, 0));
  ASSERT_EQ(10, point1.x());
  ASSERT_EQ(10, point1.y());
  gfx::Point point2 =
      plugin_container_one->LocalToRootFramePoint(gfx::Point(90, 90));
  ASSERT_EQ(100, point2.x());
  ASSERT_EQ(100, point2.y());

  WebPluginContainer* plugin_container_two =
      GetWebPluginContainer(web_view, WebString::FromUTF8("rotated-plugin"));
  DCHECK(plugin_container_two);
  gfx::Point point3 =
      plugin_container_two->LocalToRootFramePoint(gfx::Point(10, 0));
  ASSERT_EQ(0, point3.x());
  ASSERT_EQ(10, point3.y());
  gfx::Point point4 =
      plugin_container_two->LocalToRootFramePoint(gfx::Point(10, 10));
  ASSERT_EQ(-10, point4.x());
  ASSERT_EQ(10, point4.y());
}

// Verifies executing the command 'Copy' results in copying to the clipboard.
TEST_F(WebPluginContainerTest, Copy) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive `web_view_helper`.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  web_view->MainFrameImpl()
      ->GetDocument()
      .Unwrap<Document>()
      ->body()
      ->getElementById(AtomicString("translated-plugin"))
      ->Focus();
  EXPECT_TRUE(web_view->MainFrame()->ToWebLocalFrame()->ExecuteCommand("Copy"));

  LocalFrame* local_frame = web_view->MainFrameImpl()->GetFrame();
  EXPECT_EQ(String("x"), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);
}

// Verifies executing the command 'Copy' results in copying nothing to the
// clipboard when the plugin does not have the copy permission.
TEST_F(WebPluginContainerTest, CopyWithoutPermission) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive `web_view_helper`.
  TestPluginWebFrameClient plugin_web_frame_client;
  // Make sure to create a plugin without the copy permission.
  plugin_web_frame_client.SetCanCopy(false);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  web_view->MainFrameImpl()
      ->GetDocument()
      .Unwrap<Document>()
      ->body()
      ->getElementById(AtomicString("translated-plugin"))
      ->Focus();
  EXPECT_TRUE(web_view->MainFrame()->ToWebLocalFrame()->ExecuteCommand("Copy"));

  LocalFrame* local_frame = web_view->MainFrameImpl()->GetFrame();
  EXPECT_EQ(String(""), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);
}

TEST_F(WebPluginContainerTest, CopyFromContextMenu) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive `web_view_helper`.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  // Make sure the right-click + command works in common scenario.
  ExecuteContextMenuCommand(web_view, "Copy");

  LocalFrame* local_frame = web_view->MainFrameImpl()->GetFrame();
  EXPECT_EQ(String("x"), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);

  auto event = frame_test_helpers::CreateMouseEvent(
      WebMouseEvent::Type::kMouseDown, WebMouseEvent::Button::kRight,
      gfx::Point(30, 30), 0);
  event.click_count = 1;

  // Now, let's try a more complex scenario:
  // 1) open the context menu. This will focus the plugin.
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  // 2) document blurs the plugin, because it can.
  web_view->FocusedElement()->blur();
  // 3) Copy should still operate on the context node, even though the focus had
  //    shifted.
  EXPECT_TRUE(web_view->MainFrameImpl()->ExecuteCommand("Copy"));

  EXPECT_EQ(String("x"), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);
}

TEST_F(WebPluginContainerTest, CopyFromContextMenuWithoutCopyPermission) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive `web_view_helper`.
  TestPluginWebFrameClient plugin_web_frame_client;
  // Make sure to create a plugin without the copy permission.
  plugin_web_frame_client.SetCanCopy(false);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  // Make sure the right-click + command copies nothing in common scenario.
  ExecuteContextMenuCommand(web_view, "Copy");
  LocalFrame* local_frame = web_view->MainFrameImpl()->GetFrame();
  EXPECT_EQ(String(""), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);

  auto event = frame_test_helpers::CreateMouseEvent(
      WebMouseEvent::Type::kMouseDown, WebMouseEvent::Button::kRight,
      gfx::Point(30, 30), 0);
  event.click_count = 1;

  // Now, make sure the context menu copies nothing in a more complex scenario.
  // 1) open the context menu. This will focus the plugin.
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  // 2) document blurs the plugin, because it can.
  web_view->FocusedElement()->blur();
  // 3) Copy should still operate on the context node, even though the focus had
  //    shifted.
  EXPECT_TRUE(web_view->MainFrameImpl()->ExecuteCommand("Copy"));
  EXPECT_EQ(String(""), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);
}

// Verifies `Ctrl-C` and `Ctrl-Insert` keyboard events, results in copying to
// the clipboard.
TEST_F(WebPluginContainerTest, CopyInsertKeyboardEventsTest) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive `web_view_helper`.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));
  WebInputEvent::Modifiers modifier_key = static_cast<WebInputEvent::Modifiers>(
      kEditingModifier | WebInputEvent::kNumLockOn | WebInputEvent::kIsLeft);
  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_C);
  LocalFrame* local_frame = web_view->MainFrameImpl()->GetFrame();
  EXPECT_EQ(String("x"), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);

  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_INSERT);
  EXPECT_EQ(String("x"), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);
}

// Verifies `Ctrl-C` and `Ctrl-Insert` keyboard events, results in copying
// nothing to the clipboard.
TEST_F(WebPluginContainerTest,
       CopyInsertKeyboardEventsTestWithoutCopyPermission) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive `web_view_helper`.
  TestPluginWebFrameClient plugin_web_frame_client;
  // Make sure to create a plugin without the copy permission.
  plugin_web_frame_client.SetCanCopy(false);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));
  WebInputEvent::Modifiers modifier_key = static_cast<WebInputEvent::Modifiers>(
      kEditingModifier | WebInputEvent::kNumLockOn | WebInputEvent::kIsLeft);
  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_C);
  LocalFrame* local_frame = web_view->MainFrameImpl()->GetFrame();
  EXPECT_EQ(String(""), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);

  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_INSERT);
  EXPECT_EQ(String(""), ReadClipboard(*local_frame));
  ClearClipboardBuffer(*local_frame);
}

// Verifies |Ctrl-X| and |Shift-Delete| keyboard events, results in the "Cut"
// command being invoked.
TEST_F(WebPluginContainerTest, CutDeleteKeyboardEventsTest) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;

  // Use TestPluginWithEditableText for testing "Cut".
  plugin_web_frame_client.SetHasEditableText(true);

  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));

  WebInputEvent::Modifiers modifier_key = static_cast<WebInputEvent::Modifiers>(
      kEditingModifier | WebInputEvent::kNumLockOn | WebInputEvent::kIsLeft);
  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_X);

  // Check that "Cut" command is invoked.
  auto* test_plugin =
      TestPluginWithEditableText::FromContainer(&plugin_container_one_element);
  EXPECT_TRUE(test_plugin->IsCutCalled());

  // Reset Cut status for next time.
  test_plugin->ResetEditCommandState();

  modifier_key = static_cast<WebInputEvent::Modifiers>(
      WebInputEvent::kShiftKey | WebInputEvent::kNumLockOn |
      WebInputEvent::kIsLeft);

  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_DELETE);

  // Check that "Cut" command is invoked.
  EXPECT_TRUE(test_plugin->IsCutCalled());
}

// Verifies |Ctrl-V| and |Shift-Insert| keyboard events, results in the "Paste"
// command being invoked.
TEST_F(WebPluginContainerTest, PasteInsertKeyboardEventsTest) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;

  // Use TestPluginWithEditableText for testing "Paste".
  plugin_web_frame_client.SetHasEditableText(true);

  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));

  WebInputEvent::Modifiers modifier_key = static_cast<WebInputEvent::Modifiers>(
      kEditingModifier | WebInputEvent::kNumLockOn | WebInputEvent::kIsLeft);
  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_V);

  // Check that "Paste" command is invoked.
  auto* test_plugin =
      TestPluginWithEditableText::FromContainer(&plugin_container_one_element);
  EXPECT_TRUE(test_plugin->IsPasteCalled());

  // Reset Paste status for next time.
  test_plugin->ResetEditCommandState();

  modifier_key = static_cast<WebInputEvent::Modifiers>(
      WebInputEvent::kShiftKey | WebInputEvent::kNumLockOn |
      WebInputEvent::kIsLeft);

  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_INSERT);

  // Check that "Paste" command is invoked.
  EXPECT_TRUE(test_plugin->IsPasteCalled());
}

// Verifies |Ctrl-Shift-V| keyboard event results in the "PasteAndMatchStyle"
// command being invoked.
TEST_F(WebPluginContainerTest, PasteAndMatchStyleKeyboardEventsTest) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;

  // Use TestPluginWithEditableText for testing "PasteAndMatchStyle".
  plugin_web_frame_client.SetHasEditableText(true);

  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));

  WebInputEvent::Modifiers modifier_key = static_cast<WebInputEvent::Modifiers>(
      kEditingModifier | WebInputEvent::kShiftKey | WebInputEvent::kNumLockOn |
      WebInputEvent::kIsLeft);
  CreateAndHandleKeyboardEvent(&plugin_container_one_element, modifier_key,
                               VKEY_V);

  // Check that "PasteAndMatchStyle" command is invoked.
  auto* test_plugin =
      TestPluginWithEditableText::FromContainer(&plugin_container_one_element);
  EXPECT_TRUE(test_plugin->IsPasteCalled());
}

TEST_F(WebPluginContainerTest, CutFromContextMenu) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;

  // Use TestPluginWithEditableText for testing "Cut".
  plugin_web_frame_client.SetHasEditableText(true);

  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));

  ExecuteContextMenuCommand(web_view, "Cut");
  auto* test_plugin =
      TestPluginWithEditableText::FromContainer(&plugin_container_one_element);
  EXPECT_TRUE(test_plugin->IsCutCalled());
}

TEST_F(WebPluginContainerTest, PasteFromContextMenu) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;

  // Use TestPluginWithEditableText for testing "Paste".
  plugin_web_frame_client.SetHasEditableText(true);

  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));

  ExecuteContextMenuCommand(web_view, "Paste");
  auto* test_plugin =
      TestPluginWithEditableText::FromContainer(&plugin_container_one_element);
  EXPECT_TRUE(test_plugin->IsPasteCalled());
}

TEST_F(WebPluginContainerTest, PasteAndMatchStyleFromContextMenu) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;

  // Use TestPluginWithEditableText for testing "Paste".
  plugin_web_frame_client.SetHasEditableText(true);

  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));

  ExecuteContextMenuCommand(web_view, "PasteAndMatchStyle");
  auto* test_plugin =
      TestPluginWithEditableText::FromContainer(&plugin_container_one_element);
  EXPECT_TRUE(test_plugin->IsPasteCalled());
}

// A class to facilitate testing that events are correctly received by plugins.
class EventTestPlugin : public FakeWebPlugin {
 public:
  explicit EventTestPlugin(const WebPluginParams& params)
      : FakeWebPlugin(params),
        last_event_type_(WebInputEvent::Type::kUndefined),
        last_event_modifiers_(WebInputEvent::kNoModifiers) {}

  WebInputEventResult HandleInputEvent(
      const WebCoalescedInputEvent& coalesced_event,
      ui::Cursor*) override {
    const WebInputEvent& event = coalesced_event.Event();
    coalesced_event_count_ = coalesced_event.CoalescedEventSize();
    last_event_type_ = event.GetType();
    last_event_modifiers_ = event.GetModifiers();
    if (WebInputEvent::IsMouseEventType(event.GetType()) ||
        event.GetType() == WebInputEvent::Type::kMouseWheel) {
      const WebMouseEvent& mouse_event =
          static_cast<const WebMouseEvent&>(event);
      last_event_location_ = gfx::Point(mouse_event.PositionInWidget().x(),
                                        mouse_event.PositionInWidget().y());
    } else if (WebInputEvent::IsTouchEventType(event.GetType())) {
      const WebTouchEvent& touch_event =
          static_cast<const WebTouchEvent&>(event);
      if (touch_event.touches_length == 1) {
        last_event_location_ =
            gfx::Point(touch_event.touches[0].PositionInWidget().x(),
                       touch_event.touches[0].PositionInWidget().y());
      } else {
        last_event_location_ = gfx::Point();
      }
    }

    return WebInputEventResult::kHandledSystem;
  }
  WebInputEvent::Type GetLastInputEventType() { return last_event_type_; }

  gfx::Point GetLastEventLocation() { return last_event_location_; }

  int GetLastEventModifiers() { return last_event_modifiers_; }

  void ClearLastEventType() {
    last_event_type_ = WebInputEvent::Type::kUndefined;
  }

  size_t GetCoalescedEventCount() { return coalesced_event_count_; }

 private:
  ~EventTestPlugin() override = default;

  size_t coalesced_event_count_;
  WebInputEvent::Type last_event_type_;
  gfx::Point last_event_location_;
  int last_event_modifiers_;
};

TEST_F(WebPluginContainerTest, GestureLongPressReachesPlugin) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_con
"""


```