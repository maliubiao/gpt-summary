Response:
The user wants me to analyze the provided C++ code snippet from `local_frame.cc`, which is part of the Chromium Blink rendering engine. I need to identify its functionalities, explain its relationship with web technologies (JavaScript, HTML, CSS) with examples, illustrate logical reasoning with hypothetical inputs and outputs, point out common user or programming errors, and finally, summarize the functionality of this specific code section as it's the first part of a larger file.

Here's a breakdown of the steps:

1. **Identify Core Functionalities:** Scan the included headers and the code within the provided snippet to understand the primary responsibilities of the `LocalFrame` class. Keywords like "navigation", "document", "script", "style", "view", and interactions with other classes like `DocumentLoader`, `LocalFrameView`, `ScriptController` will be important.

2. **Relate to Web Technologies:**
    - **HTML:**  `LocalFrame` is responsible for loading and managing HTML documents within a frame. Think about how it handles parsing, rendering, and the DOM.
    - **CSS:** The code mentions style sheets, layout, and visual aspects. `LocalFrame` plays a role in applying CSS styles and triggering layout calculations.
    - **JavaScript:** The interaction with `ScriptController` is a key indicator. Consider how `LocalFrame` manages the execution of JavaScript within its context.

3. **Illustrate with Examples:** Provide concrete scenarios showing how `LocalFrame` interacts with these web technologies.

4. **Logical Reasoning:** Look for code snippets that involve decision-making (if/else statements, etc.). Create hypothetical inputs and predict the outputs based on the logic.

5. **Common Errors:**  Think about potential pitfalls related to frame management, navigation, or resource loading that developers might encounter.

6. **Summarize the First Part:** Concisely describe the primary responsibilities covered in the provided code section. Since this is the beginning of the file, focus on initialization, setup, basic navigation concepts, and the establishment of core relationships with other components.
```
功能列表:
1. **框架的创建和初始化:** `LocalFrame` 对象的创建和初始化，包括设置 opener 框架，初始化文档令牌、策略容器、存储键等。
2. **视图管理:**  负责 `LocalFrameView` 的创建和设置，`LocalFrameView` 负责框架的可视化渲染。
3. **导航控制:**  处理框架的导航请求，包括 `Navigate` 函数，决定是否替换当前历史记录项。
4. **生命周期管理:**  包含框架的析构函数，以及与框架分离相关的操作 (`DetachImpl`，尽管代码中未展示)。
5. **关联组件管理:**  管理与 `LocalFrame` 关联的各种子组件，如 `DocumentLoader` (资源加载)，`ScriptController` (JavaScript 执行)，`LocalFrameView` (视图)，`Editor` (编辑功能)，`EventHandler` (事件处理) 等。
6. **特性标志:**  使用宏和特性标志 (如 `BUILDFLAG(IS_MAC)`) 来包含或排除特定平台的代码。
7. **性能监控:**  包含与性能监控相关的成员，如 `performance_monitor_`。
8. **调试和诊断:**  包含用于调试和诊断的工具，如 `probe::FrameScheduledNavigation` 和 `TRACE_EVENT2`。
9. **Mojo 集成:**  使用 Mojo 进行进程间通信，例如创建 `LocalFrameMojoHandler`。
10. **后退/前进缓存 (BFCache) 支持:** 涉及与 BFCache 相关的接口和逻辑。
11. **最大内容绘制 (LCP) 预测:** 包含与 LCP 预测相关的成员 `lcpp_`。
12. **用户激活:**  处理用户激活状态。
13. **内容安全策略 (CSP):**  涉及到 `PolicyContainer` 和 CSP 的管理。
14. **插件支持:**  与插件相关的接口。
15. **全屏支持:**  与全屏功能相关的类。
16. **滚动管理:**  与滚动相关的类，如 `smooth_scroll_sequencer_`。

与 javascript, html, css 的功能关系及举例说明:

1. **HTML (文档加载和解析):**
   - **功能关系:** `LocalFrame` 负责加载和管理 HTML 文档。当浏览器加载一个网页时，会创建一个或多个 `LocalFrame` 来显示 HTML 内容。
   - **举例说明:**  `loader_.StartNavigation(request, frame_load_type)`  会触发 `DocumentLoader` 开始加载 HTML 资源。HTML 解析器（未在代码中直接展示，但由 `DocumentLoader` 管理）会将 HTML 转化为 DOM 树，而 `LocalFrame` 持有这个 DOM 树的根节点（`Document`）。

2. **JavaScript (脚本执行):**
   - **功能关系:** `LocalFrame` 拥有 `ScriptController`，负责执行 JavaScript 代码。
   - **举例说明:** 当 HTML 中包含 `<script>` 标签或内联的 JavaScript 代码时，`ScriptController` 会解析并执行这些代码。`LocalFrame` 中的 `DomWindow()` 提供了 JavaScript 的全局对象 `window`。

3. **CSS (样式应用和布局):**
   - **功能关系:** `LocalFrame` 的 `LocalFrameView` 负责渲染内容，这涉及到 CSS 样式的应用和布局计算。
   - **举例说明:** 当 CSS 样式表被加载并解析后，`LocalFrameView` 会根据这些样式信息来布局和绘制 HTML 元素。例如，CSS 可以控制元素的颜色、大小、位置等，而 `LocalFrameView` 会根据这些信息进行渲染。 `background_color_paint_image_generator_` 等成员暗示了与 CSS 视觉效果相关的处理。

逻辑推理的假设输入与输出:

假设输入:
- `request.GetResourceRequest().Url()` 返回一个表示新 URL 的 `KURL` 对象，例如 "https://example.com/new_page.html"。
- `GetDocument()->Url()` 返回当前框架的 URL，例如 "https://example.com/current_page.html"。
- `frame_load_type` 是 `WebFrameLoadType::kStandard`。
- `ShouldReplaceForSameUrlNavigation(request)` 返回 `false` (例如，因为这是一个表单提交)。
- `GetDocument()->LoadEventFinished()` 返回 `false` (页面尚未加载完成)。
- `HasTransientUserActivation(this)` 返回 `false` (没有用户交互触发导航)。
- `request.GetClientNavigationReason()` 是 `ClientNavigationReason::kLinkClicked`。

逻辑推理过程 (在 `NavigationShouldReplaceCurrentHistoryEntry` 函数中):
1. `frame_load_type != WebFrameLoadType::kStandard` 为假。
2. `ShouldMaintainTrivialSessionHistory()`  假设为 `false`。
3. `ShouldReplaceForSameUrlNavigation(request)` 返回 `false`。
4. `request.Form()` 假设为真 (表单提交)。因此，`request.Form() && request.GetOriginWindow() != DomWindow()` 也可能为真，具体取决于 `request.GetOriginWindow()` 的值。如果目标窗口是自身，则该条件为假。假设目标窗口不是自身。
5. `GetDocument()->LoadEventFinished()` 为假。
6. `HasTransientUserActivation(this)` 为假。
7. `request.GetClientNavigationReason() == ClientNavigationReason::kNone` 为假。
8. `request.GetClientNavigationReason() == ClientNavigationReason::kLinkClicked` 为真，因此 `!(request.GetClientNavigationReason() == ClientNavigationReason::kAnchorClick)` 为真。

输出:
- `NavigationShouldReplaceCurrentHistoryEntry` 函数将返回 `false`，意味着这次导航应该创建一个新的历史记录项，而不是替换当前的。

涉及用户或者编程常见的使用错误，举例说明:

1. **错误地假设框架总是存在的:**  在尝试访问子框架的属性或方法之前，没有检查子框架是否存在。
   - **举例:**  JavaScript 代码尝试访问 `window.frames[0].document`，但如果第一个子框架尚未加载或不存在，则会导致错误。在 C++ 代码中，类似的错误可能发生在尝试访问 `Tree().Parent()` 或 `Tree().FirstChild()` 而没有先检查是否为空。

2. **在不正确的时机进行导航:**  在某些生命周期事件中尝试导航可能会导致意外行为或错误。
   - **举例:**  在 `beforeunload` 事件处理程序中尝试同步导航可能会被浏览器阻止或导致页面卸载过程中的问题。

3. **混淆本地和远程框架:**  在处理嵌套框架时，错误地假设所有框架都是本地的，而没有考虑跨域 iframe 的情况。
   - **举例:**  尝试直接访问跨域 iframe 的 `document` 对象会导致安全错误。在 C++ 代码中，需要区分 `LocalFrame` 和 `RemoteFrame` 的操作。

4. **不正确地处理导航结果:**  没有正确处理导航失败或重定向的情况。
   - **举例:**  表单提交失败或发生 HTTP 重定向时，没有适当的错误处理逻辑。

5. **滥用或误解 `WebFrameLoadType`:**  错误地使用 `WebFrameLoadType` 参数可能导致不期望的历史记录行为。
   - **举例:**  本应替换当前历史记录的导航被错误地设置为创建新的历史记录项。

归纳一下它的功能 (第1部分):

这个代码片段主要负责 `LocalFrame` 类的**初始化、基本属性管理和核心导航流程的初步处理**。它定义了 `LocalFrame` 的创建过程，关联了重要的子组件（如视图和加载器），并包含了处理基本导航请求的逻辑，特别是关于是否应该替换当前历史记录项的初步判断。 此外，它还涉及到与 JavaScript 执行环境和页面渲染视图的关联。 这部分代码是 `LocalFrame` 核心功能的基础，为后续的文档加载、脚本执行和页面渲染等操作奠定了基础。
```
Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1998, 1999 Torben Weis <weis@kde.org>
 *                     1999 Lars Knoll <knoll@kde.org>
 *                     1999 Antti Koivisto <koivisto@kde.org>
 *                     2000 Simon Hausmann <hausmann@kde.org>
 *                     2000 Stefan Schimanski <1Stein@gmx.de>
 *                     2001 George Staikos <staikos@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2005 Alexey Proskuryakov <ap@nypop.com>
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008 Google Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/frame/local_frame.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

#include "base/check_deref.h"
#include "base/debug/dump_without_crashing.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "base/values.h"
#include "build/build_config.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "services/network/public/mojom/source_location.mojom-blink.h"
#include "skia/public/mojom/skcolor.mojom-blink.h"
#include "third_party/abseil-cpp/absl/cleanup/cleanup.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/chrome_debug_urls.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/loader/lcp_critical_path_predictor_util.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/back_forward_cache_not_restored_reasons.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/blob_url_store.mojom-blink.h"
#include "third_party/blink/public/mojom/favicon/favicon_url.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/back_forward_cache_controller.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/blocked_navigation_types.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/media_player_action.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/reporting_observer.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-shared.h"
#include "third_party/blink/public/mojom/lcp_critical_path_predictor/lcp_critical_path_predictor.mojom-blink.h"
#include "third_party/blink/public/mojom/script_source_location.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scrollbar_mode.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_background_resource_fetch_assets.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_content_capture_client.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_link_preview_triggerer.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_producer.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy_manager.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/content_capture/content_capture_manager.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/core_probe_sink.h"
#include "third_party/blink/renderer/core/css/background_color_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/box_shadow_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/clip_path_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/document_style_environment_variables.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/child_frame_disconnector.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/document_parser.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/ignore_opens_during_unload_count_incrementer.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/serializers/create_markup_options.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/suggestion/text_suggestion_controller.h"
#include "third_party/blink/renderer/core/editing/surrounding_text.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/execution_context/window_agent.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/fileapi/public_url_manager.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/frame/ad_tracker.h"
#include "third_party/blink/renderer/core/frame/attribution_src_loader.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/frame_overlay.h"
#include "third_party/blink/renderer/core/frame/frame_serializer.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_mojo_handler.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/pausable_script_executor.h"
#include "third_party/blink/renderer/core/frame/performance_monitor.h"
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_owner.h"
#include "third_party/blink/renderer/core/frame/report.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/smart_clip.h"
#include "third_party/blink/renderer/core/frame/user_activation.h"
#include "third_party/blink/renderer/core/frame/virtual_keyboard_overlay_changed_observer.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/fullscreen/scoped_allow_fullscreen.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_reporter.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_storage.h"
#include "third_party/blink/renderer/core/inspector/inspector_task_runner.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_controller.h"
#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"
#include "third_party/blink/renderer/core/layout/anchor_position_visibility_observer.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/prerender_handle.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/drag_controller.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/plugin_data.h"
#include "third_party/blink/renderer/core/page/plugin_script_forbidden_scope.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/scroll/scroll_snapshot_client.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/platform/back_forward_cache_utils.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_histogram_accumulator.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/graphics/image_data_buffer.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/image-encoders/image_encoder_utils.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/mhtml/serialized_resource.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/transform.h"

#if BUILDFLAG(IS_MAC)
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/substring_util.h"
#include "third_party/blink/renderer/platform/fonts/mac/attributed_string_type_converter.h"
#include "ui/base/mojom/attributed_string.mojom-blink.h"
#include "ui/gfx/range/range.h"
#endif

#if !BUILDFLAG(IS_ANDROID)
#include "third_party/blink/renderer/core/frame/window_controls_overlay_changed_delegate.h"
#endif

namespace blink {

namespace {

// Max size in bytes of the Vector used in ForceSynchronousDocumentInstall to
// buffer data before sending it to the HTML parser.
constexpr unsigned kMaxDocumentChunkSize = 1000000;

// Maintain a global (statically-allocated) hash map indexed by the the result
// of hashing the |frame_token| passed on creation of a LocalFrame object.
using LocalFramesByTokenMap = HeapHashMap<uint64_t, WeakMember<LocalFrame>>;
static LocalFramesByTokenMap& GetLocalFramesMap() {
  DEFINE_STATIC_LOCAL(Persistent<LocalFramesByTokenMap>, map,
                      (MakeGarbageCollected<LocalFramesByTokenMap>()));
  return *map;
}

// Maximum number of burst download requests allowed.
const int kBurstDownloadLimit = 10;

inline float ParentLayoutZoomFactor(LocalFrame* frame) {
  auto* parent_local_frame = DynamicTo<LocalFrame>(frame->Tree().Parent());
  return parent_local_frame ? parent_local_frame->LayoutZoomFactor() : 1;
}

inline float ParentTextZoomFactor(LocalFrame* frame) {
  auto* parent_local_frame = DynamicTo<LocalFrame>(frame->Tree().Parent());
  return parent_local_frame ? parent_local_frame->TextZoomFactor() : 1;
}

// Convert a data url to a message pipe handle that corresponds to a remote
// blob, so that it can be passed across processes.
mojo::PendingRemote<mojom::blink::Blob> DataURLToBlob(const String& data_url) {
  auto blob_data = std::make_unique<BlobData>();
  StringUTF8Adaptor data_url_utf8(data_url);
  blob_data->AppendBytes(base::as_byte_span(data_url_utf8));
  scoped_refptr<BlobDataHandle> blob_data_handle =
      BlobDataHandle::Create(std::move(blob_data), data_url_utf8.size());
  return blob_data_handle->CloneBlobRemote();
}

RemoteFrame* SourceFrameForOptionalToken(
    const std::optional<RemoteFrameToken>& source_frame_token) {
  if (!source_frame_token)
    return nullptr;
  return RemoteFrame::FromFrameToken(source_frame_token.value());
}

void SetViewportSegmentVariablesForRect(StyleEnvironmentVariables& vars,
                                        gfx::Rect segment_rect,
                                        unsigned first_dimension,
                                        unsigned second_dimension,
                                        const ExecutionContext* context) {
  vars.SetVariable(UADefinedTwoDimensionalVariable::kViewportSegmentTop,
                   first_dimension, second_dimension,
                   StyleEnvironmentVariables::FormatPx(segment_rect.y()),
                   context);
  vars.SetVariable(UADefinedTwoDimensionalVariable::kViewportSegmentRight,
                   first_dimension, second_dimension,
                   StyleEnvironmentVariables::FormatPx(segment_rect.right()),
                   context);
  vars.SetVariable(UADefinedTwoDimensionalVariable::kViewportSegmentBottom,
                   first_dimension, second_dimension,
                   StyleEnvironmentVariables::FormatPx(segment_rect.bottom()),
                   context);
  vars.SetVariable(UADefinedTwoDimensionalVariable::kViewportSegmentLeft,
                   first_dimension, second_dimension,
                   StyleEnvironmentVariables::FormatPx(segment_rect.x()),
                   context);
  vars.SetVariable(UADefinedTwoDimensionalVariable::kViewportSegmentWidth,
                   first_dimension, second_dimension,
                   StyleEnvironmentVariables::FormatPx(segment_rect.width()),
                   context);
  vars.SetVariable(UADefinedTwoDimensionalVariable::kViewportSegmentHeight,
                   first_dimension, second_dimension,
                   StyleEnvironmentVariables::FormatPx(segment_rect.height()),
                   context);
}

mojom::blink::BlockingDetailsPtr CreateBlockingDetailsMojom(
    const FeatureAndJSLocationBlockingBFCache& blocking_details) {
  auto feature_location_to_report = mojom::blink::BlockingDetails::New();
  feature_location_to_report->feature =
      static_cast<uint32_t>(blocking_details.Feature());
  // Zero line number and column number means no source location found.
  if (blocking_details.LineNumber() > 0 &&
      blocking_details.ColumnNumber() > 0) {
    // `Url()` and `Function()` may return nullptr.
    auto source_location = mojom::blink::ScriptSourceLocation::New(
        blocking_details.Url() ? KURL(blocking_details.Url()) : KURL(),
        blocking_details.Function() ? blocking_details.Function() : "",
        blocking_details.LineNumber(), blocking_details.ColumnNumber());
    feature_location_to_report->source = std::move(source_location);
  }
  return feature_location_to_report;
}

bool IsNavigationBlockedByCoopRestrictProperties(
    const LocalFrame& accessing_frame,
    const Frame& target_frame) {
  // If the two windows are not in the same CoopRelatedGroup, we should not
  // block one window from navigating the other. This prevents restricting
  // things that were not meant to. These are the cross browsing context group
  // accesses that already existed before COOP: restrict-properties.
  // TODO(https://crbug.com/1464618): Is there actually any scenario where cross
  // browsing context group was allowed before COOP: restrict-properties? Verify
  // that we need to have this check.
  if (accessing_frame.GetPage()->CoopRelatedGroupToken() !=
      target_frame.GetPage()->CoopRelatedGroupToken()) {
    return false;
  }

  // If we're dealing with an actual COOP: restrict-properties case, then
  // compare the browsing context group tokens. If they are different, the
  // navigation should not be permitted.
  if (accessing_frame.GetPage()->BrowsingContextGroupToken() !=
      target_frame.GetPage()->BrowsingContextGroupToken()) {
    return true;
  }

  return false;
}

// TODO: b/338175253 - remove the need for this conversion
mojom::blink::StorageTypeAccessed ToMojoStorageType(
    blink::WebContentSettingsClient::StorageType storage_type) {
  switch (storage_type) {
    case blink::WebContentSettingsClient::StorageType::kDatabase:
      return mojom::blink::StorageTypeAccessed::kDatabase;
    case blink::WebContentSettingsClient::StorageType::kCacheStorage:
      return mojom::blink::StorageTypeAccessed::kCacheStorage;
    case blink::WebContentSettingsClient::StorageType::kIndexedDB:
      return mojom::blink::StorageTypeAccessed::kIndexedDB;
    case blink::WebContentSettingsClient::StorageType::kFileSystem:
      return mojom::blink::StorageTypeAccessed::kFileSystem;
    case blink::WebContentSettingsClient::StorageType::kWebLocks:
      return mojom::blink::StorageTypeAccessed::kWebLocks;
    case blink::WebContentSettingsClient::StorageType::kLocalStorage:
      return mojom::blink::StorageTypeAccessed::kLocalStorage;
    case blink::WebContentSettingsClient::StorageType::kSessionStorage:
      return mojom::blink::StorageTypeAccessed::kSessionStorage;
  }
}

}  // namespace

template class CORE_TEMPLATE_EXPORT Supplement<LocalFrame>;

// static
LocalFrame* LocalFrame::FromFrameToken(const LocalFrameToken& frame_token) {
  LocalFramesByTokenMap& local_frames_map = GetLocalFramesMap();
  auto it = local_frames_map.find(LocalFrameToken::Hasher()(frame_token));
  return it == local_frames_map.end() ? nullptr : it->value.Get();
}

void LocalFrame::Init(Frame* opener,
                      const DocumentToken& document_token,
                      std::unique_ptr<PolicyContainer> policy_container,
                      const StorageKey& storage_key,
                      ukm::SourceId document_ukm_source_id,
                      const KURL& creator_base_url) {
  if (!policy_container)
    policy_container = PolicyContainer::CreateEmpty();

  CoreInitializer::GetInstance().InitLocalFrame(*this);

  GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &LocalFrame::BindTextFragmentReceiver, WrapWeakPersistent(this)));
  DCHECK(!mojo_handler_);
  mojo_handler_ = MakeGarbageCollected<LocalFrameMojoHandler>(*this);

  SetOpenerDoNotNotify(opener);
  loader_.Init(document_token, std::move(policy_container), storage_key,
               document_ukm_source_id, creator_base_url);
}

void LocalFrame::SetView(LocalFrameView* view) {
  DCHECK(!view_ || view_ != view);
  DCHECK(!GetDocument() || !GetDocument()->IsActive());
  if (view_)
    view_->WillBeRemovedFromFrame();
  view_ = view;
}

void LocalFrame::CreateView(const gfx::Size& viewport_size,
                            const Color& background_color) {
  DCHECK(this);
  DCHECK(GetPage());

  bool is_local_root = IsLocalRoot();

  if (is_local_root && View())
    View()->SetParentVisible(false);

  SetView(nullptr);

  LocalFrameView* frame_view = nullptr;
  if (is_local_root) {
    frame_view = MakeGarbageCollected<LocalFrameView>(*this, viewport_size);

    // The layout size is set by WebViewImpl to support meta viewport
    frame_view->SetLayoutSizeFixedToFrameSize(false);
  } else {
    frame_view = MakeGarbageCollected<LocalFrameView>(*this);
  }

  SetView(frame_view);

  frame_view->UpdateBaseBackgroundColorRecursively(background_color);

  if (is_local_root)
    frame_view->SetParentVisible(true);

  // FIXME: Not clear what the right thing for OOPI is here.
  if (OwnerLayoutObject()) {
    HTMLFrameOwnerElement* owner = DeprecatedLocalOwner();
    DCHECK(owner);
    // FIXME: OOPI might lead to us temporarily lying to a frame and telling it
    // that it's owned by a FrameOwner that knows nothing about it. If we're
    // lying to this frame, don't let it clobber the existing
    // EmbeddedContentView.
    if (owner->ContentFrame() == this)
      owner->SetEmbeddedContentView(frame_view);
  }

  if (Owner()) {
    View()->SetCanHaveScrollbars(Owner()->ScrollbarMode() !=
                                 mojom::blink::ScrollbarMode::kAlwaysOff);
  }
}

LocalFrame::~LocalFrame() {
  // Verify that the LocalFrameView has been cleared as part of detaching
  // the frame owner.
  DCHECK(!view_);
  DCHECK(!frame_color_overlay_);
  if (IsAdFrame())
    InstanceCounters::DecrementCounter(InstanceCounters::kAdSubframeCounter);

  // Before this destructor runs, `DetachImpl()` must have been run.
  CHECK(did_run_detach_impl_);
}

void LocalFrame::Trace(Visitor* visitor) const {
  visitor->Trace(ad_tracker_);
  visitor->Trace(script_observer_);
  visitor->Trace(attribution_src_loader_);
  visitor->Trace(probe_sink_);
  visitor->Trace(performance_monitor_);
  visitor->Trace(idleness_detector_);
  visitor->Trace(inspector_issue_reporter_);
  visitor->Trace(inspector_trace_events_);
  visitor->Trace(loader_);
  visitor->Trace(view_);
  visitor->Trace(dom_window_);
  visitor->Trace(page_popup_owner_);
  visitor->Trace(editor_);
  visitor->Trace(selection_);
  visitor->Trace(event_handler_);
  visitor->Trace(console_);
  visitor->Trace(smooth_scroll_sequencer_);
  visitor->Trace(content_capture_manager_);
  visitor->Trace(system_clipboard_);
  visitor->Trace(virtual_keyboard_overlay_changed_observers_);
  visitor->Trace(widget_creation_observers_);
  visitor->Trace(pause_handle_receivers_);
  visitor->Trace(frame_color_overlay_);
  visitor->Trace(mojo_handler_);
  visitor->Trace(text_fragment_handler_);
  visitor->Trace(scroll_snapshot_clients_);
  visitor->Trace(saved_scroll_offsets_);
  visitor->Trace(background_color_paint_image_generator_);
  visitor->Trace(box_shadow_paint_image_generator_);
  visitor->Trace(clip_path_paint_image_generator_);
  visitor->Trace(lcpp_);
  visitor->Trace(v8_local_compile_hints_producer_);
  visitor->Trace(browser_interface_broker_proxy_);
#if !BUILDFLAG(IS_ANDROID)
  visitor->Trace(window_controls_overlay_changed_delegate_);
#endif
  Frame::Trace(visitor);
  Supplementable<LocalFrame>::Trace(visitor);
}

bool LocalFrame::IsLocalRoot() const {
  if (!Tree().Parent())
    return true;

  return Tree().Parent()->IsRemoteFrame();
}

void LocalFrame::Navigate(FrameLoadRequest& request,
                          WebFrameLoadType frame_load_type) {
  if (HTMLFrameOwnerElement* element = DeprecatedLocalOwner())
    element->CancelPendingLazyLoad();

  if (!navigation_rate_limiter().CanProceed())
    return;

  TRACE_EVENT2("navigation", "LocalFrame::Navigate", "url",
               request.GetResourceRequest().Url().GetString().Utf8(),
               "load_type", static_cast<int>(frame_load_type));

  if (request.GetClientNavigationReason() != ClientNavigationReason::kNone &&
      request.GetClientNavigationReason() !=
          ClientNavigationReason::kInitialFrameNavigation) {
    probe::FrameScheduledNavigation(this, request.GetResourceRequest().Url(),
                                    base::TimeDelta(),
                                    request.GetClientNavigationReason());
  }

  if (NavigationShouldReplaceCurrentHistoryEntry(request, frame_load_type))
    frame_load_type = WebFrameLoadType::kReplaceCurrentItem;

  const ClientNavigationReason client_redirect_reason =
      request.GetClientNavigationReason();
  loader_.StartNavigation(request, frame_load_type);

  if (client_redirect_reason != ClientNavigationReason::kNone &&
      client_redirect_reason !=
          ClientNavigationReason::kInitialFrameNavigation) {
    probe::FrameClearedScheduledNavigation(this);
  }
}

// Much of this function is redundant with the browser process
// (NavigationRequest::ShouldReplaceCurrentEntryForSameUrlNavigation), but in
// the event that this navigation is handled synchronously because it is
// same-document, we need to apply it immediately. Also, we will synchronously
// fire the NavigateEvent, which exposes whether the navigation will push or
// replace to JS.
bool LocalFrame::ShouldReplaceForSameUrlNavigation(
    const FrameLoadRequest& request) {
  const KURL& request_url = request.GetResourceRequest().Url();
  if (request_url != GetDocument()->Url()) {
    return false;
  }

  // Forms should push even to the same URL.
  if (request.Form()) {
    return false;
  }

  // Don't replace if the navigation originated from a cross-origin iframe (so
  // that cross-origin iframes can't guess the URL of this frame based on
  // whether a history entry was added).
  if (request.GetOriginWindow() &&
      !request.GetOriginWindow()->GetSecurityOrigin()->CanAccess(
          DomWindow()->GetSecurityOrigin())) {
    return false;
  }

  // WebUI URLs and non-current-tab navigations go through the OpenURL path
  // rather than the BeginNavigation path, which converts same-URL navigations
  // to reloads if not already marked replacing. Defer to the browser process
  // in those cases.
  if (SchemeRegistry::IsWebUIScheme(request_url.Protocol()) ||
      request.GetNavigationPolicy() != kNavigationPolicyCurrentTab) {
    return false;
  }

  return true;
}

bool LocalFrame::NavigationShouldReplaceCurrentHistoryEntry(
    const FrameLoadRequest& request,
    WebFrameLoadType frame_load_type) {
  if (frame_load_type != WebFrameLoadType::kStandard) {
    return false;
  }

  // When a navigation is requested via the navigation API with
  // { history: "push" } specified, this should override all implicit
  // conversions to a replacing navigation.
  if (request.ForceHistoryPush() == mojom::blink::ForceHistoryPush::kYes) {
    CHECK(!ShouldMaintainTrivialSessionHistory());
    return false;
  }

  if (ShouldMaintainTrivialSessionHistory()) {
    // TODO(http://crbug.com/1197384): We may want to assert that
    // WebFrameLoadType is never kStandard in prerendered pages before
    // commit. DCHECK can be in FrameLoader::CommitNavigation or somewhere
    // similar.
    return true;
  }

  // In most cases, we will treat a navigation to the current URL as replacing.
  if (ShouldReplaceForSameUrlNavigation(request)) {
    return true;
  }

  // Form submissions targeting another window should not replace.
  if (request.Form() && request.GetOriginWindow() != DomWindow()) {
    return false;
  }

  // If the load event has finished or the user initiated the navigation,
  // don't replace.
  if (GetDocument()->LoadEventFinished() || HasTransientUserActivation(this)) {
    return false;
  }

  // Most non-user-initiated navigations before the load event replace. The
  // exceptions are "internal" navigations (e.g., drag-and-drop triggered
  // navigations), and anchor clicks.
  if (request.GetClientNavigationReason() == ClientNavigationReason::kNone ||
      request.GetClientNavigationReaso
"""


```