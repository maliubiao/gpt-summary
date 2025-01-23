Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The goal is to analyze a C++ source file (`web_view_test.cc`) from the Chromium Blink engine. The request asks about its functionality, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning within the code (requiring hypothetical inputs/outputs), common user/programming errors it might help uncover, and how a user's actions might lead to this code being executed. Finally, for this *first part* of the file, a summary is needed.

2. **Identify the File's Purpose:** The filename `web_view_test.cc` strongly suggests this is a *test file*. The `test` suffix and the location within the `exported` directory (indicating interaction with public APIs) point towards integration or functional tests for the `WebView` component.

3. **Scan for Key Imports and Classes:**  I'll look for `#include` statements and class definitions to understand the components and functionalities being tested. Immediately, I see includes like:
    * `third_party/blink/public/web/web_view.h`: The primary interface being tested.
    * `testing/gtest/include/gtest/gtest.h`:  Confirms it's using Google Test for unit testing.
    * Includes for various web-related classes like `WebFrame`, `WebElement`, `WebSettings`, `WebInputEvent`, etc. This reinforces the idea that it's testing how `WebView` interacts with web content.
    * Includes for core Blink classes like `Document`, `Element`, `CSSStyleDeclaration`, etc.
    * Includes for platform-level components like `cc/trees/layer_tree_host.h`, indicating testing of compositing.

4. **Analyze Test Fixtures and Test Cases:**  The `WebViewTest` class, inheriting from `testing::Test`, is a test fixture. The functions starting with `TEST_F(WebViewTest, ...)` are individual test cases. I need to examine the names of these test cases to get an idea of what specific features are being tested. Examples from the provided snippet:
    * `HitTestContentEditableImageMaps`: Testing hit-testing behavior for image maps within editable content.
    * `ImageMapUrls`:  Testing how URLs are resolved for image map areas.
    * `BrokenImage`: Testing the behavior when images fail to load.
    * `SetBaseBackgroundColor`: Testing setting and blending the background color of the `WebView`.
    * `FocusIsInactive`, `DocumentHasFocus`: Testing focus-related behaviors.
    * `PlatformColorsChangedOnDeviceEmulation`: Testing how platform colors are handled during device emulation.

5. **Relate to Web Technologies:** Based on the test case names and included headers, I can connect the file's functionality to JavaScript, HTML, and CSS:
    * **HTML:**  The tests load and manipulate HTML content (e.g., `content-editable-image-maps.html`, `image-map.html`). They interact with elements by ID (`GetElementById`).
    * **CSS:**  Tests like `SetBaseBackgroundColor` and `PlatformColorsChangedOnDeviceEmulation` directly deal with CSS properties (background color, outline color). The code accesses computed styles (`GetComputedStyle`).
    * **JavaScript:** The `DocumentHasFocus` test case includes inline JavaScript code that interacts with the DOM and reports `document.hasFocus()`. This suggests the test file can set up scenarios that involve JavaScript execution and verify its effects.

6. **Infer Logical Reasoning (Hypothetical Inputs/Outputs):** For each test case, I can imagine the setup, the action being performed, and the expected outcome. For example:
    * **`HitTestContentEditableImageMaps`:**
        * **Input:**  Load an HTML page with different combinations of editable and non-editable image maps. Simulate mouse clicks at specific coordinates.
        * **Output:**  Verify that `HitTestElementId` and `HitTestIsContentEditable` return the correct element IDs and editability status based on the click coordinates.
    * **`SetBaseBackgroundColor`:**
        * **Input:** Set different background colors using `SetPageBaseBackgroundColor`. Load HTML with inline styles that also set background colors.
        * **Output:** Verify that `BackgroundColor()` returns the correctly blended or overridden background color.

7. **Identify Potential User/Programming Errors:** This file helps catch errors like:
    * **Incorrect hit-testing:**  If the hit-testing logic is flawed, clicking on an image map area might incorrectly identify a different element or its editability.
    * **Broken image handling:**  If the browser doesn't gracefully handle broken image URLs, it could lead to crashes or unexpected behavior.
    * **Background color inconsistencies:**  Errors in how background colors are set, blended, or overridden could result in incorrect rendering.
    * **Focus management issues:**  Problems with focus logic could lead to unexpected behavior when interacting with forms or other interactive elements.
    * **Device emulation bugs:** Incorrect handling of platform colors during device emulation could lead to visual inconsistencies.

8. **Trace User Actions (Debugging Clues):** How might a developer end up looking at this test file?
    * **Debugging a rendering bug:** If a user reports a problem with how a specific web page element is rendered (e.g., incorrect background color, broken image link), a developer might look at relevant test files like this one to understand how that feature *should* work and to see if there are existing tests that cover the scenario.
    * **Developing a new feature:** When adding new functionality to `WebView`, developers write new tests in files like this to ensure the feature works as expected and to prevent regressions in the future.
    * **Investigating a crash or unexpected behavior:** If the browser crashes or behaves unexpectedly when interacting with specific web content, developers might examine test files to see if there are tests that reproduce the issue or provide clues about the root cause.
    * **Code review:** Other developers might review this file to ensure the tests are well-written and cover the necessary functionality.

9. **Summarize the Functionality (for Part 1):** Based on the analysis of the included code and the initial test cases, I can summarize the file's purpose for this first part:  This section of `web_view_test.cc` focuses on testing core functionalities of the `WebView` class related to rendering and basic user interaction. It includes tests for hit-testing, handling image maps (including broken images), setting and blending background colors, and basic focus management. The tests cover scenarios involving both HTML structure and CSS styling.

By following these steps, I can systematically break down the source code, understand its purpose, relate it to web technologies, infer its logic, identify potential errors it helps prevent, and explain its relevance in a debugging context. This allows me to generate a comprehensive and informative answer to the user's request.
好的，让我们来分析一下 `blink/renderer/core/exported/web_view_test.cc` 文件的功能，特别是代码的前一部分。

**功能归纳 (针对提供的第一部分代码):**

这个C++文件 `web_view_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `blink::WebView` 类功能的单元测试文件。它使用了 Google Test 框架来编写和执行测试用例。

具体来说，从提供的代码片段来看，这个文件的主要功能是：

1. **测试 `WebView` 的基本属性和方法:**  它创建和操作 `WebView` 实例，并验证其各种属性和方法的行为是否符合预期。例如，测试设置背景颜色、调整大小、处理焦点、以及进行 hit-test 等功能。

2. **模拟用户交互和浏览器行为:**  它模拟用户的操作，如鼠标点击，来测试 `WebView` 对这些交互的响应。例如，测试点击图片映射的不同区域是否能正确识别。

3. **验证与 HTML、CSS 相关的渲染和行为:**  它加载包含 HTML 和 CSS 代码的测试页面，并验证 `WebView` 对这些内容的渲染和交互是否正确。例如，测试背景颜色的设置和混合，以及如何处理图片加载失败的情况。

4. **测试 `WebView` 的生命周期和状态变化:**  它测试 `WebView` 在不同状态下的行为，例如，当窗口获得或失去焦点时，文档的焦点状态是否正确。

5. **测试设备模拟相关功能:** 它测试在设备模拟场景下，平台颜色是否能正确更改。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**
    * **例子:**  `TEST_F(WebViewTest, HitTestContentEditableImageMaps)` 加载了 `content-editable-image-maps.html` 文件，这个 HTML 文件定义了包含可编辑和不可编辑区域的图片映射。测试代码通过模拟点击不同坐标，验证 `WebView` 能否正确识别点击位置的元素及其可编辑性。
    * **涉及功能:**  测试 `WebView` 解析和处理 HTML 结构（例如 `<img>`, `<map>`, `<area>` 标签）的能力，以及判断元素是否可编辑。

* **CSS:**
    * **例子:** `TEST_F(WebViewTest, SetBaseBackgroundColor)` 测试了设置 `WebView` 的背景颜色，以及当 HTML 中定义了 `body` 的背景颜色时，`WebView` 如何处理颜色的覆盖和混合。
    * **涉及功能:** 测试 `WebView` 应用 CSS 样式（例如 `background-color` 属性）的能力，以及背景颜色的合成逻辑。
    * **例子:** `TEST_F(WebViewTest, PlatformColorsChangedOnDeviceEmulation)` 测试了设备模拟器如何影响 `-webkit-focus-ring-color` 这个 CSS 系统颜色。
    * **涉及功能:** 测试 `WebView` 如何处理和应用 CSS 系统颜色，尤其是在设备模拟场景下。

* **JavaScript:**
    * **例子:** `TEST_F(WebViewTest, DocumentHasFocus)` 加载的 HTML 代码包含 JavaScript，该脚本监听了输入框的 `focus` 和 `blur` 事件，并更新页面上的文本内容来显示 `document.hasFocus()` 的返回值。测试代码验证了当 `WebView` 获得和失去焦点时，JavaScript 代码中的 `document.hasFocus()` 返回值是否正确。
    * **涉及功能:**  测试 `WebView` 的焦点状态与 JavaScript 中 `document.hasFocus()` 的同步性，以及 `WebView` 的状态变化是否能触发 JavaScript 事件。

**逻辑推理的假设输入与输出:**

让我们以 `TEST_F(WebViewTest, HitTestContentEditableImageMaps)` 为例：

* **假设输入:**
    * 加载的 HTML 内容 (`content-editable-image-maps.html`) 包含带有不同 `coords` 属性的 `<area>` 标签，这些标签位于不同的 `<div>` 元素内，有的 `<div>` 设置了 `contenteditable` 属性。
    * 测试代码模拟在特定的像素坐标上进行点击 (例如 `(25, 25)`, `(75, 125)` 等)。

* **逻辑推理:**  `WebView` 的 hit-test 逻辑会根据点击坐标，遍历渲染树，判断哪个元素位于该点下方。对于图片映射，它会检查点击坐标是否落在某个 `<area>` 标签定义的区域内。同时，它还会考虑元素的 `contenteditable` 属性。

* **预期输出:**
    * `HitTestElementId(web_view, x, y)` 应该返回被点击元素的 `id` 属性值。
    * `HitTestIsContentEditable(web_view, x, y)` 应该返回一个布尔值，指示被点击的元素或其父元素是否可编辑。
    * 例如，当点击坐标为 `(25, 325)` 时，预期 `HitTestElementId` 返回 `"areaDEditable"`，`HitTestIsContentEditable` 返回 `true`。

**涉及用户或编程常见的使用错误:**

* **Hit-test 逻辑错误:** 如果 `WebView` 的 hit-test 逻辑有 bug，用户点击一个链接或可编辑区域时，可能会错误地触发其他元素的行为，或者无法正确识别点击的元素。这个测试文件能帮助开发者发现这类错误。
* **背景颜色处理错误:** 开发者在实现背景颜色功能时，可能没有考虑到各种 CSS 规则的优先级和混合模式，导致页面背景颜色显示不正确。这个测试文件可以验证背景颜色逻辑的正确性。
* **焦点管理错误:** 当用户在页面上进行操作（例如点击输入框）时，焦点应该正确地转移。如果 `WebView` 的焦点管理逻辑有误，可能会导致用户无法正常输入或者与页面元素进行交互。 `FocusIsInactive` 和 `DocumentHasFocus` 这类测试可以帮助发现这些问题.
* **设备模拟配置错误:** 如果设备模拟功能的实现有误，可能会导致在模拟特定设备时，页面样式（例如系统颜色）没有正确应用，影响用户体验。 `PlatformColorsChangedOnDeviceEmulation` 可以帮助检查这类问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接 "到达" 这个测试文件。这个文件是开发和测试阶段使用的。但是，用户的操作可能会触发 Blink 引擎中的相关代码，而这些代码正是这个测试文件所覆盖的。

1. **用户访问包含特定 HTML 和 CSS 的网页:** 例如，一个网页使用了图片映射，或者设置了特定的背景颜色。
2. **用户与网页进行交互:** 例如，用户点击图片映射的不同区域，或者点击页面上的输入框。
3. **Blink 引擎处理用户交互:**  当用户点击时，Blink 引擎会执行 hit-test 逻辑来确定用户点击了哪个元素。当页面需要渲染时，Blink 引擎会应用 CSS 样式并绘制页面。
4. **如果出现 bug:**  如果用户遇到与上述交互相关的 bug（例如，点击图片映射没有反应，或者页面背景颜色显示不正确），开发者可能会开始调试 Blink 引擎的代码。
5. **开发者查找相关代码和测试:** 开发者可能会定位到 `blink/renderer/core/exported/web_view_impl.cc` 中处理 hit-test 或渲染的代码，并查看相关的测试文件 `web_view_test.cc`，来理解这些功能的工作原理，并尝试复现和修复 bug。

**总结提供的第一部分代码的功能:**

总而言之，提供的 `web_view_test.cc` 的第一部分主要关注 `blink::WebView` 类在处理基本渲染、用户交互（特别是 hit-test）、背景颜色和焦点管理方面的功能测试。它通过加载不同的 HTML 和 CSS 组合，并模拟用户操作，来验证 `WebView` 的行为是否符合预期。这些测试对于确保 Blink 引擎的稳定性和正确性至关重要。

希望这个详细的分析对您有所帮助! 如果您想了解后续部分的代码，请随时提供。

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011, 2012 Google Inc. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/public/web/web_view.h"

#include <limits>
#include <memory>
#include <optional>
#include <string>

#include "base/functional/callback_helpers.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/test/test_ukm_recorder_factory.h"
#include "cc/trees/layer_tree_host.h"
#include "gin/handle.h"
#include "gin/object_template_builder.h"
#include "gin/wrappable.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/page/drag_operation.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/common/widget/device_emulation_params.h"
#include "third_party/blink/public/mojom/frame/tree_scope_type.mojom-blink.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/mojom/input/touch_event.mojom-blink.h"
#include "third_party/blink/public/mojom/manifest/display_mode.mojom-shared.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_drag_data.h"
#include "third_party/blink/public/public_buildflags.h"
#include "third_party/blink/public/test/test_web_frame_content_dumper.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_hit_test_result.h"
#include "third_party/blink/public/web/web_input_method_controller.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_non_composited_widget_client.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/public/web/web_widget.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_document.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/css/media_query_list_listener.h"
#include "third_party/blink/renderer/core/css/media_query_matcher.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/exported/web_page_popup_impl.h"
#include "third_party/blink/renderer/core/exported/web_settings_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/forms/external_date_time_chooser.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/forms/internal_popup_menu.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_hidden_state.h"
#include "third_party/blink/renderer/core/page/page_popup_client.h"
#include "third_party/blink/renderer/core/page/print_context.h"
#include "third_party/blink/renderer/core/page/scoped_browsing_context_group_pauser.h"
#include "third_party/blink/renderer/core/page/scoped_page_pauser.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/fake_web_plugin.h"
#include "third_party/blink/renderer/core/testing/mock_clipboard_host.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/event_timing.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/cursors.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "ui/base/cursor/cursor.h"
#include "ui/base/cursor/mojom/cursor_type.mojom-blink.h"
#include "ui/base/dragdrop/mojom/drag_drop_types.mojom-blink.h"
#include "ui/base/mojom/menu_source_type.mojom-blink.h"
#include "ui/events/keycodes/dom/dom_key.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"
#include "v8/include/v8.h"

#if BUILDFLAG(ENABLE_UNHANDLED_TAP)
#include "third_party/blink/public/mojom/unhandled_tap_notifier/unhandled_tap_notifier.mojom-blink.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#endif  // BUILDFLAG(ENABLE_UNHANDLED_TAP)

using blink::frame_test_helpers::LoadFrame;
using blink::test::RunPendingTasks;
using blink::url_test_helpers::RegisterMockedURLLoad;
using blink::url_test_helpers::ToKURL;

namespace blink {

enum HorizontalScrollbarState {
  kNoHorizontalScrollbar,
  kVisibleHorizontalScrollbar,
};

enum VerticalScrollbarState {
  kNoVerticalScrollbar,
  kVisibleVerticalScrollbar,
};

class TestData {
 public:
  void SetWebView(WebView* web_view) { web_view_ = To<WebViewImpl>(web_view); }
  void SetSize(const gfx::Size& new_size) { size_ = new_size; }
  HorizontalScrollbarState GetHorizontalScrollbarState() const {
    return web_view_->HasHorizontalScrollbar() ? kVisibleHorizontalScrollbar
                                               : kNoHorizontalScrollbar;
  }
  VerticalScrollbarState GetVerticalScrollbarState() const {
    return web_view_->HasVerticalScrollbar() ? kVisibleVerticalScrollbar
                                             : kNoVerticalScrollbar;
  }
  int Width() const { return size_.width(); }
  int Height() const { return size_.height(); }

 private:
  gfx::Size size_;
  WebViewImpl* web_view_;
};

class AutoResizeWebViewClient : public WebViewClient {
 public:
  // WebViewClient methods
  void DidAutoResize(const gfx::Size& new_size) override {
    test_data_.SetSize(new_size);
  }

  // Local methods
  TestData& GetTestData() { return test_data_; }

 private:
  TestData test_data_;
};

class WebViewTest : public testing::Test {
 public:
  // Observer that remembers the most recent visibility callback, if any.
  class MockWebViewObserver : public WebViewObserver {
   public:
    explicit MockWebViewObserver(WebView* web_view)
        : WebViewObserver(web_view) {}
    ~MockWebViewObserver() override = default;

    blink::mojom::PageVisibilityState page_visibility_and_clear() {
      auto t = *page_visibility_;
      page_visibility_.reset();
      return t;
    }

    // WebViewObserver
    void OnPageVisibilityChanged(
        blink::mojom::PageVisibilityState page_visibility) override {
      page_visibility_ = page_visibility;
    }

    // We live on the stack, so do nothing here.
    void OnDestruct() override {}

   private:
    std::optional<blink::mojom::PageVisibilityState> page_visibility_;
  };

  explicit WebViewTest(frame_test_helpers::CreateTestWebFrameWidgetCallback
                           create_web_frame_callback = base::NullCallback())
      : web_view_helper_(std::move(create_web_frame_callback)) {}

  void SetUp() override {
    test_task_runner_ = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
    // Advance clock so time is not 0.
    test_task_runner_->FastForwardBy(base::Seconds(1));
    EventTiming::SetTickClockForTesting(test_task_runner_->GetMockTickClock());
  }

  void TearDown() override {
    EventTiming::SetTickClockForTesting(nullptr);
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
    web_view_helper_.Reset();
    MemoryCache::Get()->EvictResources();
    // Clear lazily loaded style sheets.
    CSSDefaultStyleSheets::Instance().PrepareForLeakDetection();
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

 protected:
  void SetViewportSize(const gfx::Size& size) {
    cc::LayerTreeHost* layer_tree_host = web_view_helper_.GetLayerTreeHost();
    layer_tree_host->SetViewportRectAndScale(
        gfx::Rect(size), /*device_scale_factor=*/1.f,
        layer_tree_host->local_surface_id_from_parent());
  }

  std::string RegisterMockedHttpURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |web_view_helper_|.
    return url_test_helpers::RegisterMockedURLLoadFromBase(
               WebString::FromUTF8(base_url_), test::CoreTestDataPath(),
               WebString::FromUTF8(file_name))
        .GetString()
        .Utf8();
  }

  void TestAutoResize(const gfx::Size& min_auto_resize,
                      const gfx::Size& max_auto_resize,
                      const std::string& page_width,
                      const std::string& page_height,
                      int expected_width,
                      int expected_height,
                      HorizontalScrollbarState expected_horizontal_state,
                      VerticalScrollbarState expected_vertical_state);

  void TestTextInputType(WebTextInputType expected_type,
                         const std::string& html_file);
  void TestInputMode(WebTextInputMode expected_input_mode,
                     const std::string& html_file);
  void TestInputAction(ui::TextInputAction expected_input_action,
                       const std::string& html_file);
  bool SimulateGestureAtElement(WebInputEvent::Type, Element*);
  bool SimulateGestureAtElementById(WebInputEvent::Type, const WebString& id);
  WebGestureEvent BuildTapEvent(WebInputEvent::Type,
                                int tap_event_count,
                                const gfx::PointF& position_in_widget);
  bool SimulateTapEventAtElement(WebInputEvent::Type,
                                 int tap_event_count,
                                 Element*);
  bool SimulateTapEventAtElementById(WebInputEvent::Type,
                                     int tap_event_count,
                                     const WebString& id);

  ExternalDateTimeChooser* GetExternalDateTimeChooser(
      WebViewImpl* web_view_impl);

  void UpdateAllLifecyclePhases() {
    web_view_helper_.GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  InteractiveDetector* GetTestInteractiveDetector(Document& document) {
    InteractiveDetector* detector(InteractiveDetector::From(document));
    EXPECT_NE(nullptr, detector);
    detector->SetTaskRunnerForTesting(test_task_runner_);
    detector->SetTickClockForTesting(test_task_runner_->GetMockTickClock());
    return detector;
  }

  std::string base_url_{"http://www.test.com/"};
  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper web_view_helper_;
  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;
};

static bool HitTestIsContentEditable(WebView* view, int x, int y) {
  gfx::PointF hit_point(x, y);
  WebHitTestResult hit_test_result =
      view->MainFrameWidget()->HitTestResultAt(hit_point);
  return hit_test_result.IsContentEditable();
}

static std::string HitTestElementId(WebView* view, int x, int y) {
  gfx::PointF hit_point(x, y);
  WebHitTestResult hit_test_result =
      view->MainFrameWidget()->HitTestResultAt(hit_point);
  return hit_test_result.GetNode().To<WebElement>().GetAttribute("id").Utf8();
}

static Color OutlineColor(Element* element) {
  return element->GetComputedStyle()->VisitedDependentColor(
      GetCSSPropertyOutlineColor());
}

TEST_F(WebViewTest, HitTestContentEditableImageMaps) {
  std::string url =
      RegisterMockedHttpURLLoad("content-editable-image-maps.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 500));

  EXPECT_EQ("areaANotEditable", HitTestElementId(web_view, 25, 25));
  EXPECT_FALSE(HitTestIsContentEditable(web_view, 25, 25));
  EXPECT_EQ("imageANotEditable", HitTestElementId(web_view, 75, 25));
  EXPECT_FALSE(HitTestIsContentEditable(web_view, 75, 25));

  EXPECT_EQ("areaBNotEditable", HitTestElementId(web_view, 25, 125));
  EXPECT_FALSE(HitTestIsContentEditable(web_view, 25, 125));
  EXPECT_EQ("imageBEditable", HitTestElementId(web_view, 75, 125));
  EXPECT_TRUE(HitTestIsContentEditable(web_view, 75, 125));

  EXPECT_EQ("areaCNotEditable", HitTestElementId(web_view, 25, 225));
  EXPECT_FALSE(HitTestIsContentEditable(web_view, 25, 225));
  EXPECT_EQ("imageCNotEditable", HitTestElementId(web_view, 75, 225));
  EXPECT_FALSE(HitTestIsContentEditable(web_view, 75, 225));

  EXPECT_EQ("areaDEditable", HitTestElementId(web_view, 25, 325));
  EXPECT_TRUE(HitTestIsContentEditable(web_view, 25, 325));
  EXPECT_EQ("imageDNotEditable", HitTestElementId(web_view, 75, 325));
  EXPECT_FALSE(HitTestIsContentEditable(web_view, 75, 325));
}

static std::string HitTestAbsoluteUrl(WebView* view, int x, int y) {
  gfx::PointF hit_point(x, y);
  WebHitTestResult hit_test_result =
      view->MainFrameWidget()->HitTestResultAt(hit_point);
  return hit_test_result.AbsoluteImageURL().GetString().Utf8();
}

static WebElement HitTestUrlElement(WebView* view, int x, int y) {
  gfx::PointF hit_point(x, y);
  WebHitTestResult hit_test_result =
      view->MainFrameWidget()->HitTestResultAt(hit_point);
  return hit_test_result.UrlElement();
}

TEST_F(WebViewTest, ImageMapUrls) {
  std::string url = RegisterMockedHttpURLLoad("image-map.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(400, 400));

  std::string image_url =
      "data:image/gif;base64,R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=";

  EXPECT_EQ("area", HitTestElementId(web_view, 25, 25));
  EXPECT_EQ("area",
            HitTestUrlElement(web_view, 25, 25).GetAttribute("id").Utf8());
  EXPECT_EQ(image_url, HitTestAbsoluteUrl(web_view, 25, 25));

  EXPECT_EQ("image", HitTestElementId(web_view, 75, 25));
  EXPECT_TRUE(HitTestUrlElement(web_view, 75, 25).IsNull());
  EXPECT_EQ(image_url, HitTestAbsoluteUrl(web_view, 75, 25));
}

TEST_F(WebViewTest, BrokenImage) {
  url_test_helpers::RegisterMockedErrorURLLoad(
      KURL(ToKURL(base_url_), "non_existent.png"));
  std::string url = RegisterMockedHttpURLLoad("image-broken.html");

  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->GetSettings()->SetLoadsImagesAutomatically(true);
  LoadFrame(web_view->MainFrameImpl(), url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(400, 400));

  std::string image_url = "http://www.test.com/non_existent.png";

  EXPECT_EQ("image", HitTestElementId(web_view, 25, 25));
  EXPECT_TRUE(HitTestUrlElement(web_view, 25, 25).IsNull());
  EXPECT_EQ(image_url, HitTestAbsoluteUrl(web_view, 25, 25));
}

TEST_F(WebViewTest, BrokenInputImage) {
  url_test_helpers::RegisterMockedErrorURLLoad(
      KURL(ToKURL(base_url_), "non_existent.png"));
  std::string url = RegisterMockedHttpURLLoad("input-image-broken.html");

  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->GetSettings()->SetLoadsImagesAutomatically(true);
  LoadFrame(web_view->MainFrameImpl(), url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(400, 400));

  std::string image_url = "http://www.test.com/non_existent.png";

  EXPECT_EQ("image", HitTestElementId(web_view, 25, 25));
  EXPECT_TRUE(HitTestUrlElement(web_view, 25, 25).IsNull());
  EXPECT_EQ(image_url, HitTestAbsoluteUrl(web_view, 25, 25));
}

TEST_F(WebViewTest, SetBaseBackgroundColor) {
  const SkColor kDarkCyan = SkColorSetARGB(0xFF, 0x22, 0x77, 0x88);
  const SkColor kTranslucentPutty = SkColorSetARGB(0x80, 0xBF, 0xB1, 0x96);

  WebViewImpl* web_view = web_view_helper_.Initialize();
  EXPECT_EQ(SK_ColorWHITE, web_view->BackgroundColor());

  web_view->SetPageBaseBackgroundColor(SK_ColorBLUE);
  EXPECT_EQ(SK_ColorBLUE, web_view->BackgroundColor());

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view->MainFrameImpl(),
      "<html><head><style>body "
      "{background-color:#227788}</style></head></"
      "html>",
      base_url);
  EXPECT_EQ(kDarkCyan, web_view->BackgroundColor());

  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<html><head><style>body "
                                     "{background-color:rgba(255,0,0,0.5)}</"
                                     "style></head></html>",
                                     base_url);
  // Expected: red (50% alpha) blended atop base of SK_ColorBLUE.
  EXPECT_EQ(0xFF80007F, web_view->BackgroundColor());

  web_view->SetPageBaseBackgroundColor(kTranslucentPutty);
  // Expected: red (50% alpha) blended atop kTranslucentPutty. Note the alpha.
  EXPECT_EQ(0xBFE93A31, web_view->BackgroundColor());

  web_view->SetPageBaseBackgroundColor(SK_ColorTRANSPARENT);
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<html><head><style>body "
                                     "{background-color:transparent}</style></"
                                     "head></html>",
                                     base_url);
  // Expected: transparent on top of transparent will still be transparent.
  EXPECT_EQ(SK_ColorTRANSPARENT, web_view->BackgroundColor());

  LocalFrame* frame = web_view->MainFrameImpl()->GetFrame();
  // The shutdown() calls are a hack to prevent this test
  // from violating invariants about frame state during navigation/detach.
  frame->GetDocument()->Shutdown();

  // Creating a new frame view with the background color having 0 alpha.
  frame->CreateView(gfx::Size(1024, 768), Color::kTransparent);
  EXPECT_EQ(Color::kTransparent, frame->View()->BaseBackgroundColor());
  frame->View()->Dispose();

  const Color transparent_red(100, 0, 0, 0);
  frame->CreateView(gfx::Size(1024, 768), transparent_red);
  EXPECT_EQ(transparent_red, frame->View()->BaseBackgroundColor());
  frame->View()->Dispose();
}

TEST_F(WebViewTest, SetBaseBackgroundColorBeforeMainFrame) {
  // Note: this test doesn't use WebViewHelper since it intentionally runs
  // initialization code between WebView and WebLocalFrame creation.
  WebViewClient web_view_client;
  WebViewImpl* web_view = web_view_helper_.CreateWebView(
      &web_view_client, /*compositing_enabled=*/true);
  EXPECT_NE(SK_ColorBLUE, web_view->BackgroundColor());
  // WebView does not have a frame yet; while it's possible to set the page
  // background color, it won't have any effect until a local main frame is
  // attached.
  web_view->SetPageBaseBackgroundColor(SK_ColorBLUE);
  EXPECT_NE(SK_ColorBLUE, web_view->BackgroundColor());

  frame_test_helpers::TestWebFrameClient web_frame_client;
  WebLocalFrame* frame = WebLocalFrame::CreateMainFrame(
      web_view, &web_frame_client, nullptr, mojo::NullRemote(),
      LocalFrameToken(), DocumentToken(), nullptr);
  web_frame_client.Bind(frame);

  frame_test_helpers::TestWebFrameWidget* widget =
      web_view_helper_.CreateFrameWidgetAndInitializeCompositing(frame);
  web_view->DidAttachLocalMainFrame();

  // The color should be passed to the compositor.
  cc::LayerTreeHost* host = widget->LayerTreeHostForTesting();
  EXPECT_EQ(SK_ColorBLUE, web_view->BackgroundColor());
  EXPECT_EQ(SkColors::kBlue, host->background_color());

  web_view->Close();
}

TEST_F(WebViewTest, SetBaseBackgroundColorAndBlendWithExistingContent) {
  const SkColor kAlphaRed = SkColorSetARGB(0x80, 0xFF, 0x00, 0x00);
  const SkColor kAlphaGreen = SkColorSetARGB(0x80, 0x00, 0xFF, 0x00);
  const int kWidth = 100;
  const int kHeight = 100;

  WebViewImpl* web_view = web_view_helper_.Initialize();

  // Set WebView background to green with alpha.
  web_view->SetPageBaseBackgroundColor(kAlphaGreen);
  web_view->GetSettings()->SetShouldClearDocumentBackground(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(kWidth, kHeight));
  UpdateAllLifecyclePhases();

  // Set canvas background to red with alpha.
  SkBitmap bitmap;
  bitmap.allocN32Pixels(kWidth, kHeight);
  SkCanvas canvas(bitmap, SkSurfaceProps{});
  canvas.clear(kAlphaRed);

  PaintRecordBuilder builder;

  // Paint the root of the main frame in the way that CompositedLayerMapping
  // would.
  LocalFrameView* view = web_view_helper_.LocalMainFrame()->GetFrameView();
  PaintLayer* root_layer = view->GetLayoutView()->Layer();

  view->GetLayoutView()->GetDocument().Lifecycle().AdvanceTo(
      DocumentLifecycle::kInPaint);
  PaintLayerPainter(*root_layer).Paint(builder.Context());
  view->GetLayoutView()->GetDocument().Lifecycle().AdvanceTo(
      DocumentLifecycle::kPaintClean);
  builder.EndRecording().Playback(&canvas);

  // The result should be a blend of red and green.
  SkColor color = bitmap.getColor(kWidth / 2, kHeight / 2);
  EXPECT_TRUE(SkColorGetR(color));
  EXPECT_TRUE(SkColorGetG(color));
}

TEST_F(WebViewTest, SetBaseBackgroundColorWithColorScheme) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  ColorSchemeHelper color_scheme_helper(*(web_view->GetPage()));
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  web_view->SetPageBaseBackgroundColor(SK_ColorBLUE);

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view->MainFrameImpl(),
      "<style>:root { color-scheme: light dark }<style>", base_url);
  UpdateAllLifecyclePhases();

  LocalFrameView* frame_view = web_view->MainFrameImpl()->GetFrame()->View();
  EXPECT_EQ(Color(0, 0, 255), frame_view->BaseBackgroundColor());

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color(0x12, 0x12, 0x12), frame_view->BaseBackgroundColor());

  // Don't let dark color-scheme override a transparent background.
  web_view->SetPageBaseBackgroundColor(SK_ColorTRANSPARENT);
  EXPECT_EQ(Color::kTransparent, frame_view->BaseBackgroundColor());
  web_view->SetPageBaseBackgroundColor(SK_ColorBLUE);
  EXPECT_EQ(Color(0x12, 0x12, 0x12), frame_view->BaseBackgroundColor());

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  Document* document = frame->GetFrame()->GetDocument();
  CHECK(document);
  color_scheme_helper.SetInForcedColors(*document, /*in_forced_colors=*/true);
  UpdateAllLifecyclePhases();

  mojom::blink::ColorScheme color_scheme = mojom::blink::ColorScheme::kLight;
  Color system_background_color = LayoutTheme::GetTheme().SystemColor(
      CSSValueID::kCanvas, color_scheme,
      web_view->GetPage()->GetColorProviderForPainting(
          color_scheme, /*in_forced_colors=*/true),
      document->IsInWebAppScope());
  EXPECT_EQ(system_background_color, frame_view->BaseBackgroundColor());

  color_scheme_helper.SetInForcedColors(*document, /*in_forced_colors=*/false);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color(0x12, 0x12, 0x12), frame_view->BaseBackgroundColor());

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color(0, 0, 255), frame_view->BaseBackgroundColor());
}

TEST_F(WebViewTest, FocusIsInactive) {
  RegisterMockedHttpURLLoad("visible_iframe.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "visible_iframe.html");

  web_view->MainFrameWidget()->SetFocus(true);
  web_view->SetIsActive(true);
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  EXPECT_TRUE(IsA<HTMLDocument>(frame->GetFrame()->GetDocument()));

  Document* document = frame->GetFrame()->GetDocument();
  EXPECT_TRUE(document->hasFocus());
  web_view->MainFrameWidget()->SetFocus(false);
  web_view->SetIsActive(false);
  EXPECT_FALSE(document->hasFocus());
  web_view->MainFrameWidget()->SetFocus(true);
  web_view->SetIsActive(true);
  EXPECT_TRUE(document->hasFocus());
  web_view->MainFrameWidget()->SetFocus(true);
  web_view->SetIsActive(false);
  EXPECT_FALSE(document->hasFocus());
  web_view->MainFrameWidget()->SetFocus(false);
  web_view->SetIsActive(true);
  EXPECT_FALSE(document->hasFocus());
  web_view->SetIsActive(false);
  web_view->MainFrameWidget()->SetFocus(true);
  EXPECT_TRUE(document->hasFocus());
  web_view->SetIsActive(true);
  web_view->MainFrameWidget()->SetFocus(false);
  EXPECT_FALSE(document->hasFocus());
}

TEST_F(WebViewTest, DocumentHasFocus) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->MainFrameWidget()->SetFocus(true);

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view->MainFrameImpl(),
      "<input id=input></input>"
      "<div id=log></div>"
      "<script>"
      "  document.getElementById('input').addEventListener('focus', () => {"
      "    document.getElementById('log').textContent = 'document.hasFocus(): "
      "' + document.hasFocus();"
      "  });"
      "  document.getElementById('input').addEventListener('blur', () => {"
      "    document.getElementById('log').textContent = '';"
      "  });"
      "  document.getElementById('input').focus();"
      "</script>",
      base_url);

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  Document* document = frame->GetFrame()->GetDocument();
  WebElement log_element = frame->GetDocument().GetElementById("log");
  EXPECT_TRUE(document->hasFocus());
  EXPECT_EQ("document.hasFocus(): true", log_element.TextContent());

  web_view->SetIsActive(false);
  web_view->MainFrameWidget()->SetFocus(false);
  EXPECT_FALSE(document->hasFocus());
  EXPECT_TRUE(log_element.TextContent().IsEmpty());

  web_view->MainFrameWidget()->SetFocus(true);
  EXPECT_TRUE(document->hasFocus());
  EXPECT_EQ("document.hasFocus(): true", log_element.TextContent());
}

TEST_F(WebViewTest, PlatformColorsChangedOnDeviceEmulation) {
  WebViewImpl* web_view_impl = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view_impl->MainFrameImpl(),
      "<style>"
      "  span { outline-color: -webkit-focus-ring-color; }"
      "</style>"
      "<span id='span1'></span>",
      base_url);
  UpdateAllLifecyclePhases();

  DeviceEmulationParams params;
  params.screen_type = mojom::EmulatedScreenType::kMobile;

  Document& document =
      *web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();

  Element* span1 = document.getElementById(AtomicString("span1"));
  ASSERT_TRUE(span1);

  // Check non-MobileLayoutTheme color.
  Color original = LayoutTheme::GetTheme().FocusRingColor(
      span1->ComputedStyleRef().UsedColorScheme());
  EXPECT_EQ(original, OutlineColor(span1));

  // Set the focus ring color for the mobile theme to something known.
  Color custom_color = Color::FromRGB(123, 145, 167);
  {
    ScopedMo
```