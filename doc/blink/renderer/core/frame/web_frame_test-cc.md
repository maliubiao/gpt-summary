Response:
The user wants a summary of the functionality of the provided C++ source code file `web_frame_test.cc`.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The file name `web_frame_test.cc` strongly suggests this file contains unit tests for the `WebFrame` class (or related frame classes) in the Blink rendering engine.

2. **Scan the includes:**  The included headers provide clues about the areas being tested. Look for categories of includes:
    * **Public Blink API:** Headers under `third_party/blink/public/web/` like `WebFrame.h`, `WebLocalFrame.h`, `WebView.h`, `WebDocument.h`, etc. These indicate the file tests the public interface of Blink's frame-related classes.
    * **Core Blink Internals:** Headers under `third_party/blink/renderer/core/` like `frame/LocalFrame.h`, `dom/Document.h`, `editing/FrameSelection.h`, etc. This implies the tests go beyond the public API and interact with the internal workings of Blink's frame implementation.
    * **Testing Frameworks:** Headers like `testing/gtest/include/gtest/gtest.h` and `third_party/blink/renderer/core/testing/page_test_base.h` confirm this is a test file.
    * **Mojo Bindings:** Headers including `mojo/public/cpp/bindings/` indicate testing of inter-process communication related to frames.
    * **Platform Abstraction:** Headers under `third_party/blink/renderer/platform/` point to tests involving platform-specific functionalities or abstractions.
    * **Chromium Specific:** Headers like `build/build_config.h` and `base/` suggest integration with the broader Chromium environment.

3. **Look for common test patterns:** Unit test files often follow a structure of setting up test environments, performing actions on the class under test, and then asserting expected outcomes. The presence of `TEST_F` macros strongly confirms this.

4. **Analyze specific test names and setup methods:** Even without seeing the full test implementations, the names of the included classes and some helper functions (like `RegisterMockedHttpURLLoad`) suggest the types of functionalities being tested. For example:
    * Tests involving loading HTML (`iframes_test.html`, `foo.html`)
    * Tests related to JavaScript execution (`RequestExecuteScript`, `ExecuteScriptWithError`)
    * Tests concerning frame hierarchy and navigation (implied by the presence of `WebFrame` and `WebLocalFrame`)
    * Tests involving text selection (`InitializeTextSelectionWebView`)
    * Tests related to drag and drop (`NodeImageTestSetup`)
    * Tests involving scrolling and viewport (`OverscrollBehavior`)

5. **Identify connections to web technologies (JavaScript, HTML, CSS):**  The inclusion of headers like `WebDocument.h`, `WebFormElement.h`, `CSSPageRule.h`, and the presence of script execution tests directly link the tests to these technologies.

6. **Infer potential logical reasoning and error scenarios:**  Since it's a testing file, the logic will involve setting up different states and verifying behavior. Error scenarios would involve incorrect usage of the `WebFrame` API or unexpected behavior in different situations.

7. **Formulate the summary:** Combine the observations from the previous steps to create a concise description of the file's purpose and the areas it tests. Specifically mention the relationship to JavaScript, HTML, and CSS, and hint at the testing of error conditions and logical behavior.

8. **Address specific requirements in the prompt:**
    * **List functionalities:** Explicitly list the key areas being tested.
    * **JavaScript, HTML, CSS relation:** Provide concrete examples based on the included headers and test names.
    * **Logical reasoning (input/output):**  Offer a generalized example as the actual test logic isn't fully visible.
    * **User/programming errors:** Provide common examples based on the nature of the API being tested.
    * **Part 1 of 19:** Acknowledge this information.

By following this process, we can effectively analyze the provided source code snippet and generate the desired summary even without examining the detailed implementation of each test case.
这个 blink 引擎源代码文件 `web_frame_test.cc` 的主要功能是**对 `blink::WebFrame` 类及其相关功能进行单元测试**。`WebFrame` 是 Blink 引擎中表示一个网页框架的核心接口，它封装了与网页框架相关的各种操作和状态。

具体来说，从代码的引入头文件和测试用例命名可以推断出以下功能正在被测试：

**核心框架功能测试:**

* **框架创建和层级关系:** 测试框架的创建、父子框架的关系、框架的查找等。例如，代码中包含了对 `FirstChild()` 等方法的测试。
* **内容访问:** 测试获取框架内容（例如文本内容）的功能。`TestWebFrameContentDumper::DumpWebViewAsText`  用于将 WebView 内容转储为文本，这可以用于验证框架中渲染的内容。
* **脚本执行:**  测试在框架中执行 JavaScript 代码的功能，包括同步和异步执行，处理执行错误，以及处理 Promise。例如，`RequestExecuteScript` 相关测试。
* **导航:**  虽然这段代码中没有明显的导航测试，但 `WebNavigationType` 等头文件的存在暗示了可能在后续部分会测试框架的导航功能。
* **生命周期管理:**  测试框架的加载、卸载等生命周期事件。
* **设置和属性:** 测试框架相关的设置，例如字体大小、Viewport 设置等。
* **与其他 Blink 组件的交互:**  测试 `WebFrame` 如何与其他 Blink 组件（如 `WebView`，`WebDocument`，`WebLocalFrameClient` 等）进行交互。

**与 JavaScript, HTML, CSS 的关系及其举例说明:**

这个测试文件与 JavaScript, HTML, CSS 的关系非常密切，因为它测试的是渲染引擎的核心组件之一，而渲染引擎的主要任务就是解析和渲染这三种技术构建的网页。

* **JavaScript:**
    * **功能关系:** 测试在框架中执行 JavaScript 代码的能力，包括调用 JavaScript 函数，获取 JavaScript 变量的值等。
    * **举例说明:**
        * `TEST_F(WebFrameTest, RequestExecuteScript)` 测试了使用 `RequestExecuteScript` 方法执行 JavaScript 代码 `'hello;'` 并获取返回值的过程。
        * `TEST_F(WebFrameTest, ExecuteScriptWithError)` 测试了执行包含错误的 JavaScript 代码并验证错误处理机制。
        * `TEST_F(WebFrameTest, ExecuteScriptWithPromiseWithoutWait)` 测试了执行返回 Promise 的 JavaScript 代码，并且可以选择是否等待 Promise resolve。
* **HTML:**
    * **功能关系:** 测试框架加载和解析 HTML 文档，并操作 HTML 元素的能力。
    * **举例说明:**
        * `RegisterMockedHttpURLLoad("iframes_test.html")` 表明测试涉及加载包含 iframe 的 HTML 文件。
        * `web_view_helper.InitializeAndLoad(base_url_ + "foo.html");` 用于加载一个 HTML 文件进行后续的脚本执行等测试。
        * `InitializeWithHTML(LocalFrame& frame, const String& html_content)` 函数用于在框架中设置 HTML 内容。
* **CSS:**
    * **功能关系:** 虽然这段代码中没有直接操作 CSS 的测试，但框架的渲染和布局功能依赖于 CSS 的解析和应用。例如，测试框架内容转储的功能 (`TestWebFrameContentDumper::DumpWebViewAsText`) 的结果会受到 CSS 样式的影响。
    * **举例说明:**  虽然没有直接的 CSS 操作测试，但可以假设一个测试用例会加载一个包含特定 CSS 样式的 HTML 文件，然后验证渲染后的文本内容是否符合 CSS 样式预期。例如，验证某个元素的颜色或字体是否按照 CSS 规则渲染。

**逻辑推理及其假设输入与输出:**

考虑 `TEST_F(WebFrameTest, ContentText)` 这个测试用例：

* **假设输入:** 加载一个名为 `iframes_test.html` 的 HTML 文件，该文件包含可见和不可见的文本内容以及 iframe。不同的 iframe 也有可见和不可见的。
* **预期输出:** 使用 `TestWebFrameContentDumper::DumpWebViewAsText` 获取的文本内容应该只包含可见的文本和可见的 iframe 的内容，而不包含被 CSS 或其他方式隐藏的内容。

**用户或者编程常见的使用错误及其举例说明:**

虽然这是一个测试文件，但它可以揭示 `WebFrame` 接口可能出现的常见使用错误：

* **错误地假设脚本立即执行并返回结果:**  `RequestExecuteScript` 是异步的，需要等待执行完成才能获取结果。如果开发者没有正确处理回调，可能会在结果返回之前就尝试使用，导致错误。例如，在 `TEST_F(WebFrameTest, RequestExecuteScript)` 中，需要 `RunPendingTasks()` 来等待脚本执行完成。
* **在框架销毁后尝试访问框架对象:** 如果在框架被销毁后仍然尝试调用其方法，会导致崩溃或未定义行为。`TEST_F(WebFrameTest, SuspendedRequestExecuteScript)`  展示了在页面暂停后执行脚本，然后销毁 WebView，验证了回调的行为。
* **不正确的脚本执行上下文:**  需要在正确的执行上下文中执行脚本。例如，需要在主世界 (main world) 执行脚本才能访问页面的 DOM。

**归纳总结 (第1部分的功能):**

这部分 `web_frame_test.cc` 文件的主要功能是**对 `blink::WebFrame` 接口的基础核心功能进行测试，重点包括框架的创建、内容访问和 JavaScript 的执行。**  它通过加载不同的 HTML 页面，执行 JavaScript 代码，并验证预期结果来确保 `WebFrame` 的行为符合预期。  测试覆盖了同步和异步脚本执行，以及错误处理等场景。  虽然没有直接测试 CSS 相关功能，但其与 HTML 和 JavaScript 的交互是测试的基础。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/public/web/web_frame.h"

#include <array>
#include <initializer_list>
#include <limits>
#include <memory>
#include <optional>
#include <tuple>

#include "base/functional/callback_helpers.h"
#include "base/ranges/algorithm.h"
#include "base/strings/stringprintf.h"
#include "base/test/bind.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/input/overscroll_behavior.h"
#include "cc/layers/picture_layer.h"
#include "cc/paint/paint_op.h"
#include "cc/paint/paint_op_buffer_iterator.h"
#include "cc/paint/paint_recorder.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/scroll_node.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "mojo/public/cpp/system/data_pipe_drainer.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "skia/public/mojom/skcolor.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/context_menu_data/context_menu_data.h"
#include "third_party/blink/public/common/context_menu_data/edit_flags.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/common/messaging/transferable_message.h"
#include "third_party/blink/public/common/navigation/navigation_params.h"
#include "third_party/blink/public/common/page/launching_process_state.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/common/widget/device_emulation_params.h"
#include "third_party/blink/public/mojom/blob/blob.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/data_element.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/find_in_page.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/viewport_intersection_state.mojom-blink.h"
#include "third_party/blink/public/mojom/page/draggable_region.mojom-blink.h"
#include "third_party/blink/public/mojom/page_state/page_state.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scrollbar_mode.mojom-blink.h"
#include "third_party/blink/public/mojom/webpreferences/web_preferences.mojom-blink.h"
#include "third_party/blink/public/mojom/window_features/window_features.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/web_cache.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/test/test_web_frame_content_dumper.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_document_loader.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_history_item.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_navigation_timings.h"
#include "third_party/blink/public/web/web_navigation_type.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/public/web/web_remote_frame.h"
#include "third_party/blink/public/web/web_script_execution_callback.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_searchable_form_data.h"
#include "third_party/blink/public/web/web_security_policy.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_text_check_client.h"
#include "third_party/blink/public/web/web_text_checking_completion.h"
#include "third_party/blink/public/web/web_text_checking_result.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_pointer_event_init.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/css/css_page_rule.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/viewport_style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/spellcheck/idle_spell_check_controller.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/image_document.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/messaging/blink_cloneable_message.h"
#include "third_party/blink/renderer/core/messaging/blink_transferable_message.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/drag_image.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scoped_page_pauser.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_test_suite.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/fake_local_frame_host.h"
#include "third_party/blink/renderer/core/testing/fake_remote_frame_host.h"
#include "third_party/blink/renderer/core/testing/fake_remote_main_frame_host.h"
#include "third_party/blink/renderer/core/testing/mock_clipboard_host.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/scoped_fake_plugin_registry.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/core/testing/wait_for_event.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/blob/testing/fake_blob.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_context.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/runtime_feature_state/runtime_feature_state_override_context.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl_hash.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/skia/include/core/SkTextBlob.h"
#include "ui/base/ime/mojom/text_input_state.mojom-blink.h"
#include "ui/base/mojom/menu_source_type.mojom-blink.h"
#include "ui/events/keycodes/dom/dom_key.h"
#include "ui/gfx/geometry/test/geometry_util.h"
#include "ui/gfx/geometry/transform.h"
#include "v8/include/v8.h"

using blink::mojom::SelectionMenuBehavior;
using blink::test::RunPendingTasks;
using blink::url_test_helpers::ToKURL;
using testing::_;
using testing::ElementsAre;
using testing::Mock;
using testing::Return;
using testing::UnorderedElementsAre;

namespace blink {

namespace {

const ScrollPaintPropertyNode* GetScrollNode(const LayoutObject& scroller) {
  if (auto* properties = scroller.FirstFragment().PaintProperties())
    return properties->Scroll();
  return nullptr;
}

std::string GetHTMLStringForReferrerPolicy(const std::string& meta_policy,
                                           const std::string& referrer_policy) {
  std::string meta_tag =
      meta_policy.empty()
          ? ""
          : base::StringPrintf("<meta name='referrer' content='%s'>",
                               meta_policy.c_str());
  std::string referrer_policy_attr =
      referrer_policy.empty()
          ? ""
          : base::StringPrintf("referrerpolicy='%s'", referrer_policy.c_str());
  return base::StringPrintf(
      "<!DOCTYPE html>"
      "%s"
      "<a id='dl' href='download_test' download='foo' %s>Click me</a>"
      "<script>"
      "(function () {"
      "  var evt = document.createEvent('MouseEvent');"
      "  evt.initMouseEvent('click', true, true);"
      "  document.getElementById('dl').dispatchEvent(evt);"
      "})();"
      "</script>",
      meta_tag.c_str(), referrer_policy_attr.c_str());
}

// A helper function to execute the given `scripts` in the main world of the
// specified `frame`.
void ExecuteScriptsInMainWorld(
    WebLocalFrame* frame,
    base::span<const String> scripts,
    WebScriptExecutionCallback callback,
    mojom::blink::PromiseResultOption wait_for_promise =
        mojom::blink::PromiseResultOption::kAwait,
    mojom::blink::UserActivationOption user_gesture =
        mojom::blink::UserActivationOption::kDoNotActivate) {
  Vector<WebScriptSource> sources;
  for (auto script : scripts)
    sources.push_back(WebScriptSource(script));
  frame->RequestExecuteScript(
      DOMWrapperWorld::kMainWorldId, sources, user_gesture,
      mojom::blink::EvaluationTiming::kSynchronous,
      mojom::blink::LoadEventBlockingOption::kDoNotBlock, std::move(callback),
      BackForwardCacheAware::kAllow,
      mojom::blink::WantResultOption::kWantResult, wait_for_promise);
}

// Same as above, but for a single script.
void ExecuteScriptInMainWorld(
    WebLocalFrame* frame,
    String script_string,
    WebScriptExecutionCallback callback,
    mojom::blink::PromiseResultOption wait_for_promise =
        mojom::blink::PromiseResultOption::kAwait,
    mojom::blink::UserActivationOption user_gesture =
        mojom::blink::UserActivationOption::kDoNotActivate) {
  ExecuteScriptsInMainWorld(frame, base::span_from_ref(script_string),
                            std::move(callback), wait_for_promise,
                            user_gesture);
}

}  // namespace

const int kTouchPointPadding = 32;

const cc::OverscrollBehavior kOverscrollBehaviorAuto =
    cc::OverscrollBehavior(cc::OverscrollBehavior::Type::kAuto);

const cc::OverscrollBehavior kOverscrollBehaviorContain =
    cc::OverscrollBehavior(cc::OverscrollBehavior::Type::kContain);

const cc::OverscrollBehavior kOverscrollBehaviorNone =
    cc::OverscrollBehavior(cc::OverscrollBehavior::Type::kNone);

class WebFrameTest : public PageTestBase {
 protected:
  WebFrameTest()
      : base_url_("http://internal.test/"),
        not_base_url_("http://external.test/"),
        chrome_url_("chrome://test/") {
    // This is needed so that a chrome: URL's origin is computed correctly,
    // which is needed for Javascript URL security checks to work properly in
    // tests below.
    url::AddStandardScheme("chrome", url::SCHEME_WITH_HOST);
  }

  ~WebFrameTest() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void DisableRendererSchedulerThrottling() {
    // Make sure that the RendererScheduler is foregrounded to avoid getting
    // throttled.
    if (kLaunchingProcessIsBackgrounded) {
      ThreadScheduler::Current()
          ->ToMainThreadScheduler()
          ->SetRendererBackgroundedForTesting(false);
    }
  }

  void RegisterMockedHttpURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    RegisterMockedURLLoadFromBase(base_url_, file_name);
  }

  void RegisterMockedChromeURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    RegisterMockedURLLoadFromBase(chrome_url_, file_name);
  }

  void RegisterMockedURLLoadFromBase(const std::string& base_url,
                                     const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void RegisterMockedURLLoadWithCustomResponse(const WebURL& full_url,
                                               const WebString& file_path,
                                               WebURLResponse response) {
    url_test_helpers::RegisterMockedURLLoadWithCustomResponse(
        full_url, file_path, response);
  }

  void RegisterMockedHttpURLLoadWithCSP(const std::string& file_name,
                                        const std::string& csp,
                                        bool report_only = false) {
    std::string full_string = base_url_ + file_name;
    KURL url = ToKURL(full_string);
    WebURLResponse response = WebURLResponse(url);
    response.SetMimeType("text/html");
    response.AddHttpHeaderField(
        report_only ? WebString("Content-Security-Policy-Report-Only")
                    : WebString("Content-Security-Policy"),
        WebString::FromUTF8(csp));
    RegisterMockedURLLoadWithCustomResponse(
        url, test::CoreTestDataPath(WebString::FromUTF8(file_name)), response);
  }

  void RegisterMockedHttpURLLoadWithMimeType(const std::string& file_name,
                                             const std::string& mime_type) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name), WebString::FromUTF8(mime_type));
  }

  static void ConfigureAndroid(WebSettings* settings) {
    frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(
        settings);
    settings->SetViewportStyle(mojom::blink::ViewportStyle::kMobile);
  }

  static void ConfigureLoadsImagesAutomatically(WebSettings* settings) {
    settings->SetLoadsImagesAutomatically(true);
  }

  void InitializeTextSelectionWebView(
      const std::string& url,
      frame_test_helpers::WebViewHelper* web_view_helper) {
    web_view_helper->InitializeAndLoad(url);
    web_view_helper->GetWebView()->GetSettings()->SetDefaultFontSize(12);
    web_view_helper->GetWebView()->MainFrameWidget()->SetFocus(true);
    web_view_helper->Resize(gfx::Size(640, 480));
  }

  std::unique_ptr<DragImage> NodeImageTestSetup(
      frame_test_helpers::WebViewHelper* web_view_helper,
      const std::string& testcase) {
    RegisterMockedHttpURLLoad("nodeimage.html");
    web_view_helper->InitializeAndLoad(base_url_ + "nodeimage.html");
    web_view_helper->Resize(gfx::Size(640, 480));
    auto* frame =
        To<LocalFrame>(web_view_helper->GetWebView()->GetPage()->MainFrame());
    DCHECK(frame);
    Element* element =
        frame->GetDocument()->getElementById(AtomicString(testcase.c_str()));
    return DataTransfer::NodeImage(*frame, *element);
  }

  void RemoveElementById(WebLocalFrameImpl* frame, const AtomicString& id) {
    Element* element = frame->GetFrame()->GetDocument()->getElementById(id);
    DCHECK(element);
    element->remove();
  }

  // Both sets the inner html and runs the document lifecycle.
  void InitializeWithHTML(LocalFrame& frame, const String& html_content) {
    frame.GetDocument()->body()->setInnerHTML(html_content);
    frame.GetDocument()->View()->UpdateAllLifecyclePhasesForTest();
  }

  void SwapAndVerifyFirstChildConsistency(const char* const message,
                                          WebFrame* parent,
                                          WebFrame* new_child);
  void SwapAndVerifyMiddleChildConsistency(const char* const message,
                                           WebFrame* parent,
                                           WebFrame* new_child);
  void SwapAndVerifyLastChildConsistency(const char* const message,
                                         WebFrame* parent,
                                         WebFrame* new_child);
  void SwapAndVerifySubframeConsistency(const char* const message,
                                        WebFrame* parent,
                                        WebFrame* new_child);

  int NumMarkersInRange(const Document* document,
                        const EphemeralRange& range,
                        DocumentMarker::MarkerTypes marker_types) {
    Node* start_container = range.StartPosition().ComputeContainerNode();
    unsigned start_offset = static_cast<unsigned>(
        range.StartPosition().ComputeOffsetInContainerNode());

    Node* end_container = range.EndPosition().ComputeContainerNode();
    unsigned end_offset = static_cast<unsigned>(
        range.EndPosition().ComputeOffsetInContainerNode());

    int node_count = 0;
    for (Node& node : range.Nodes()) {
      const DocumentMarkerVector& markers_in_node =
          document->Markers().MarkersFor(To<Text>(node), marker_types);
      node_count += base::ranges::count_if(
          markers_in_node, [start_offset, end_offset, &node, &start_container,
                            &end_container](const DocumentMarker* marker) {
            if (node == start_container && marker->EndOffset() <= start_offset)
              return false;
            if (node == end_container && marker->StartOffset() >= end_offset)
              return false;
            return true;
          });
    }

    return node_count;
  }

  void UpdateAllLifecyclePhases(WebViewImpl* web_view) {
    web_view->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  static void GetElementAndCaretBoundsForFocusedEditableElement(
      frame_test_helpers::WebViewHelper& helper,
      gfx::Rect& element_bounds,
      gfx::Rect& caret_bounds) {
    Element* element = helper.GetWebView()->FocusedElement();
    gfx::Rect caret_in_viewport, unused;
    helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
        caret_in_viewport, unused);
    caret_bounds =
        helper.GetWebView()->GetPage()->GetVisualViewport().ViewportToRootFrame(
            caret_in_viewport);
    element_bounds = element->GetDocument().View()->ConvertToRootFrame(
        ToPixelSnappedRect(element->Node::BoundingBox()));
  }

  std::string base_url_;
  std::string not_base_url_;
  std::string chrome_url_;

  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
  url::ScopedSchemeRegistryForTests scoped_registry_;
};

TEST_F(WebFrameTest, ContentText) {
  RegisterMockedHttpURLLoad("iframes_test.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");
  RegisterMockedHttpURLLoad("invisible_iframe.html");
  RegisterMockedHttpURLLoad("zero_sized_iframe.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframes_test.html");

  // Now retrieve the frames text and test it only includes visible elements.
  std::string content = TestWebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_NE(std::string::npos, content.find(" visible paragraph"));
  EXPECT_NE(std::string::npos, content.find(" visible iframe"));
  EXPECT_EQ(std::string::npos, content.find(" invisible pararaph"));
  EXPECT_EQ(std::string::npos, content.find(" invisible iframe"));
  EXPECT_EQ(std::string::npos, content.find("iframe with zero size"));
}

TEST_F(WebFrameTest, FrameForEnteredContext) {
  RegisterMockedHttpURLLoad("iframes_test.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");
  RegisterMockedHttpURLLoad("invisible_iframe.html");
  RegisterMockedHttpURLLoad("zero_sized_iframe.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframes_test.html");

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  EXPECT_EQ(web_view_helper.GetWebView()->MainFrame(),
            WebLocalFrame::FrameForContext(web_view_helper.GetWebView()
                                               ->MainFrameImpl()
                                               ->MainWorldScriptContext()));
  EXPECT_EQ(web_view_helper.GetWebView()->MainFrame()->FirstChild(),
            WebLocalFrame::FrameForContext(web_view_helper.GetWebView()
                                               ->MainFrame()
                                               ->FirstChild()
                                               ->ToWebLocalFrame()
                                               ->MainWorldScriptContext()));
}

class ScriptExecutionCallbackHelper final {
 public:
  // Returns true if the callback helper was ever invoked.
  bool DidComplete() const { return did_complete_; }

  WebScriptExecutionCallback Callback() {
    return WTF::BindOnce(&ScriptExecutionCallbackHelper::Completed,
                         WTF::Unretained(this));
  }

  // Returns true if any results (even if they were empty) were passed to the
  // callback helper. This is generally false if the execution context was
  // invalidated while running the script.
  bool HasAnyResults() const { return !!result_; }

  // Returns the single value returned from the execution.
  String SingleStringValue() const {
    if (!result_) {
      ADD_FAILURE() << "Expected a single result, but found nullopt";
      return String();
    }
    if (const std::string* str = result_->GetIfString())
      return String(*str);

    ADD_FAILURE() << "Type mismatch (not string)";
    return String();
  }
  bool SingleBoolValue() const {
    if (!result_) {
      ADD_FAILURE() << "Expected a single result, but found nullopt";
      return false;
    }
    if (std::optional<bool> b = result_->GetIfBool()) {
      return *b;
    }

    ADD_FAILURE() << "Type mismatch (not bool)";
    return false;
  }

 private:
  void Completed(std::optional<base::Value> value, base::TimeTicks start_time) {
    did_complete_ = true;
    result_ = std::move(value);
  }

 private:
  bool did_complete_ = false;
  std::optional<base::Value> result_;
};

TEST_F(WebFrameTest, RequestExecuteScript) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                           "'hello';", callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("hello", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, SuspendedRequestExecuteScript) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;

  // Suspend scheduled tasks so the script doesn't run.
  web_view_helper.GetWebView()->GetPage()->SetPaused(true);
  ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                           "'hello';", callback_helper.Callback());
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  web_view_helper.Reset();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_FALSE(callback_helper.HasAnyResults());
}

TEST_F(WebFrameTest, ExecuteScriptWithError) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  v8::Isolate* isolate = web_view_helper.GetAgentGroupScheduler().Isolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                           "foo = bar; 'hello';", callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  // Even though an error is thrown here, it's swallowed by one of the
  // script runner classes, so the caller never sees it. Instead, the error
  // is represented by an empty V8Value (stringified to an empty string).
  EXPECT_FALSE(try_catch.HasCaught());
  EXPECT_FALSE(callback_helper.HasAnyResults());
}

TEST_F(WebFrameTest, ExecuteScriptWithPromiseWithoutWait) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  constexpr char kScript[] = R"(Promise.resolve('hello');)";

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                           kScript, callback_helper.Callback(),
                           mojom::blink::PromiseResultOption::kDoNotWait);
  RunPendingTasks();
  // Since the caller specified the script shouldn't wait for the promise to
  // be resolved, the callback should have completed normally and the result
  // value should be the promise.
  // As `V8ValueConver
```