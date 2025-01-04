Response:
The user wants to understand the functionality of the `web_view_impl.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet to identify its core responsibilities. I should pay attention to the included headers and the methods implemented within the provided section.

Here's a breakdown of how to approach the request:

1. **Identify Core Functionality:** Look for keywords, class names, and method names that suggest the primary purpose of the file. `WebViewImpl` is a strong indicator. The included headers also provide clues about the features it interacts with.

2. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Examine how the functionality might interact with these core web technologies. Consider things like rendering, user input, DOM manipulation, and styling.

3. **Logical Reasoning (Input/Output):**  Where applicable, think about how the code might process input (e.g., user actions, network responses) and what output it might produce (e.g., visual changes on the screen, data being sent).

4. **Common User/Programming Errors:**  Consider scenarios where incorrect usage or unexpected events might lead to issues related to this code.

5. **User Operation to Reach This Code (Debugging):**  Trace back the user actions that would trigger the execution of the code in this file.

6. **Summarize Functionality:**  Based on the above analysis, provide a concise summary of the file's purpose.

**Pre-computation/Pre-analysis:**

* **`WebViewImpl` Class:** This class likely implements the `WebView` interface, which is a core abstraction for displaying web content. It acts as a container and manager for a web page.
* **Included Headers:** Many of the included headers relate to fundamental browser functionalities like rendering (`cc/layers/picture_layer.h`), input handling (`third_party/blink/public/common/input/web_input_event.h`), frames (`third_party/blink/public/web/web_frame.h`), settings (`third_party/blink/public/common/web_preferences/web_preferences.h`), and more.
* **Methods in Snippet:**  The provided snippet focuses on the creation and initialization of `WebViewImpl`, handling visibility changes, managing prerendering, and setting up basic configurations.

**Constraint Checklist & Confidence Score:**

* Provide the file's functions: Yes
* Explain relations to JS, HTML, CSS: Yes
* Give examples for JS, HTML, CSS relations: Yes
* Provide logical reasoning: Yes
* Give input/output examples: Yes
* Explain common user/programming errors: Yes
* Give examples for user/programming errors: Yes
* Explain user steps to reach the code: Yes
* Explain as debugging clues: Yes
* Summarize functionality (for part 1): Yes

Confidence Score: 5/5 - I am confident I can address all aspects of the request based on the code snippet.
```
这是目录为blink/renderer/core/exported/web_view_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

根据提供的代码片段，`blink/renderer/core/exported/web_view_impl.cc` 文件的主要功能是 **实现 `blink::WebView` 接口**。`WebViewImpl` 类是 `WebView` 的具体实现，它在 Blink 渲染引擎中扮演着核心角色，负责管理和控制网页的显示和交互。

以下是其更具体的功能，并与 JavaScript、HTML、CSS 的关系以及其他方面的说明：

**功能列举：**

1. **`WebView` 的创建和初始化:**  提供了 `WebView::Create` 和 `WebViewImpl` 的构造函数，负责创建和初始化 `WebViewImpl` 实例。这包括设置客户端 (`WebViewClient`)、页面可见性、预渲染参数、合成状态等。
2. **页面生命周期管理:** 负责管理页面的创建 (`Page::CreateOrdinary`)、关联必要的模块 (`CoreInitializer::GetInstance().ProvideModulesToPage`) 以及处理页面的关闭 (`CloseWindow`, `MojoDisconnected`)。
3. **渲染和合成控制:**  通过 `does_composite_` 成员变量控制是否启用硬件加速合成。 当 `does_composite_` 为 true 时，会调用 `page_->GetSettings().SetAcceleratedCompositingEnabled(true)`。
4. **缩放功能:** 提供了设置最小/最大缩放级别 (`minimum_zoom_level_`, `maximum_zoom_level_`) 以及启动页面缩放动画 (`StartPageScaleAnimation`) 的功能。
5. **与浏览器进程的通信:** 通过 Mojo 接口 (`receiver_`) 与浏览器进程进行通信，例如处理关闭窗口的请求 (`local_main_frame_host_remote_->RequestClose()` 或 `remote_main_frame_host_remote_->RouteCloseEvent()`)。
6. **预渲染支持:**  处理预渲染相关的逻辑，例如设置预渲染状态 (`page_->SetIsPrerendering`) 和相关的性能指标后缀 (`page_->SetPrerenderMetricSuffix`)。
7. **无状态预取客户端管理:** 提供了设置无状态预取客户端的功能 (`SetNoStatePrefetchClient`)。
8. **设置标签键行为:** 允许设置 Tab 键是否在页面元素间循环切换焦点 (`SetTabKeyCyclesThroughElements`)。
9. **DevTools 集成:**  关联了 DevTools 模拟器 (`dev_tools_emulator_`).
10. **管理视口锚点:**  管理调整大小时的视口锚点 (`resize_viewport_anchor_`).
11. **管理全屏控制器:** 关联了全屏控制器 (`fullscreen_controller_`).
12. **管理页面背景色:** 存储页面的基础背景颜色 (`page_base_background_color_`).
13. **管理会话存储命名空间 ID:** 存储会话存储命名空间 ID (`session_storage_namespace_id_`).

**与 JavaScript, HTML, CSS 的关系及举例：**

* **HTML:** `WebViewImpl` 负责加载、解析和渲染 HTML 文档。
    * **举例:** 当浏览器加载一个包含 `<div>Hello</div>` 的 HTML 页面时，`WebViewImpl` 会创建相应的 DOM 树，并指示布局引擎进行布局计算。
* **CSS:** `WebViewImpl` 将 CSS 样式应用于 HTML 元素，影响其视觉呈现。
    * **举例:** 如果 CSS 规则定义了 `.highlight { color: red; }`，当 HTML 中有 `<span class="highlight">Text</span>` 时，`WebViewImpl` 会根据 CSS 规则将 "Text" 显示为红色。
* **JavaScript:** `WebViewImpl` 提供了 JavaScript 运行时的宿主环境，并处理 JavaScript 与页面内容的交互。
    * **举例:** 当 JavaScript 代码执行 `document.getElementById('myButton').textContent = 'Clicked!';` 时，`WebViewImpl` 会接收到 JavaScript 的指令，并更新 HTML 元素的内容，最终导致页面显示的变化。`WebViewImpl` 也负责处理 JavaScript 触发的事件，例如点击事件。

**逻辑推理（假设输入与输出）：**

假设输入：

* 用户在地址栏输入 URL 并按下回车键。
* 浏览器进程接收到请求，并指示渲染进程创建一个新的 `WebViewImpl` 来加载该 URL。
* 加载的 HTML 文档包含一些文本和图片。
* CSS 定义了文本的颜色和大小。
* JavaScript 绑定了一个按钮的点击事件，点击后会修改页面上的文本。

输出：

* `WebViewImpl` 会创建对应的 `Page` 对象和主框架。
* HTML 被解析成 DOM 树。
* CSS 被解析并应用到 DOM 树上，生成渲染树。
* 页面内容被布局和绘制到屏幕上，用户可以看到带有特定颜色和大小的文本和图片。
* 当用户点击按钮时，JavaScript 代码执行，`WebViewImpl` 更新 DOM 树，并触发重新渲染，页面上的文本会发生变化。

**用户或编程常见的使用错误举例：**

* **用户操作错误:** 用户可能会在页面加载过程中关闭窗口。`WebViewImpl` 需要正确处理这种情况，释放资源并停止未完成的加载。
* **编程错误 (嵌入式环境):**  如果嵌入式开发者在没有正确初始化 Blink 环境或者 `WebViewClient` 的情况下创建 `WebViewImpl`，可能会导致程序崩溃或功能异常。例如，如果 `WebViewClient` 没有正确处理页面请求，可能会导致页面无法加载。
* **JavaScript 错误:**  JavaScript 代码中的错误可能会导致页面行为异常，但这些错误通常在 JavaScript 引擎中处理，并可能通过 `WebConsoleMessage` 传递给 `WebViewClient` 进行报告。`WebViewImpl` 本身主要负责提供 JavaScript 的运行环境。

**用户操作如何一步步的到达这里 (调试线索)：**

1. **用户启动浏览器:** 浏览器进程启动。
2. **用户导航到某个网页:** 用户在地址栏输入 URL 或点击链接。
3. **浏览器进程创建渲染进程 (如果需要):** 如果是新的 Tab 或窗口，浏览器进程可能会创建一个新的渲染进程。
4. **渲染进程创建 `WebView` 对象:**  渲染进程中的主线程会创建一个 `WebViewImpl` 对象来承载要加载的网页。
5. **加载和解析 HTML:**  `WebViewImpl` 开始请求并接收 HTML 内容，然后由 HTML 解析器解析成 DOM 树。
6. **加载和解析 CSS:**  `WebViewImpl` 加载 CSS 样式表，并由 CSS 解析器解析。
7. **样式计算和布局:**  Blink 的样式引擎和布局引擎根据 DOM 树和 CSS 规则计算元素的样式和布局。
8. **JavaScript 执行:** 如果页面包含 JavaScript，JavaScript 引擎会执行这些代码，并可能通过 DOM API 与页面内容进行交互。
9. **用户交互:** 用户与页面进行交互，例如点击按钮、滚动页面、输入文本等。这些交互事件会被 `WebViewImpl` 捕获并分发给相应的处理程序。

**作为调试线索:**  当开发者在调试 Blink 渲染引擎相关问题时，例如页面加载异常、渲染错误、JavaScript 交互问题等，`web_view_impl.cc` 是一个重要的入口点。通过断点调试，开发者可以跟踪 `WebViewImpl` 的创建过程、页面生命周期的管理、事件处理流程等，从而定位问题的根源。

**归纳一下它的功能 (第 1 部分):**

在提供的第一部分代码中，`blink/renderer/core/exported/web_view_impl.cc` 的主要功能是 **`blink::WebView` 接口的具体实现，负责 `WebView` 实例的创建、初始化和一些基本的生命周期管理，并初步建立了与浏览器进程的通信机制和一些核心功能模块的关联 (如渲染合成、缩放、预渲染等)**。它为后续的页面加载、渲染和交互奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_view_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
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
#include "third_party/blink/renderer/core/exported/web_view_impl.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/command_line.h"
#include "base/debug/crash_logging.h"
#include "base/debug/dump_without_crashing.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/observer_list.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/layers/picture_layer.h"
#include "components/viz/common/features.h"
#include "media/base/media_switches.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/history/session_history_constants.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_menu_source_type.h"
#include "third_party/blink/public/common/page/color_provider_color_maps.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/common/renderer_preferences/renderer_preferences.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/public/common/web_preferences/web_preferences.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom-blink.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/mojom/page/draggable_region.mojom-blink.h"
#include "third_party/blink/public/mojom/page/prerender_page_param.mojom.h"
#include "third_party/blink/public/mojom/partitioned_popins/partitioned_popin_params.mojom.h"
#include "third_party/blink/public/mojom/window_features/window_features.mojom-blink.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_media_player.h"
#include "third_party/blink/public/platform/web_network_state_notifier.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/platform/web_text_input_info.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_hit_test_result.h"
#include "third_party/blink/public/web/web_input_element.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_meaningful_layout.h"
#include "third_party/blink/public/web/web_navigation_type.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/public/web/web_render_theme.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/public/web/web_window_features.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/content_capture/content_capture_manager.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/html_interchange.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/events/current_input_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/ui_event_with_key_state.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/exported/web_settings_impl.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/dom_window.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/fullscreen_controller.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/resize_viewport_anchor.h"
#include "third_party/blink/renderer/core/frame/rotation_viewport_anchor.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/touch_action_util.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/loader/no_state_prefetch_client.h"
#include "third_party/blink/renderer/core/page/chrome_client_impl.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/context_menu_provider.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/link_highlight.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_popup_client.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/generic_font_family_settings.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/page_scheduler.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/icu/source/common/unicode/uscript.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/skia_conversions.h"

#if BUILDFLAG(IS_CHROMEOS)
#include "ui/native_theme/native_theme.h"
#endif

#if !BUILDFLAG(IS_MAC)
#include "skia/ext/legacy_display_globals.h"
#include "third_party/blink/public/platform/web_font_render_style.h"
#include "ui/gfx/font_render_params.h"
#endif

#if BUILDFLAG(IS_WIN)
#include "third_party/blink/public/web/win/web_font_rendering.h"
#endif

// Get rid of WTF's pow define so we can use std::pow.
#undef pow
#include <cmath>  // for std::pow

#include "build/chromeos_buildflags.h"

// The following constants control parameters for automated scaling of webpages
// (such as due to a double tap gesture or find in page etc.). These are
// experimentally determined.
static const int touchPointPadding = 32;
static const int nonUserInitiatedPointPadding = 11;
static const float minScaleDifference = 0.01f;
static const float doubleTapZoomContentDefaultMargin = 5;
static const float doubleTapZoomContentMinimumMargin = 2;
static constexpr base::TimeDelta kDoubleTapZoomAnimationDuration =
    base::Milliseconds(250);
static const float doubleTapZoomAlreadyLegibleRatio = 1.2f;

static constexpr base::TimeDelta kFindInPageAnimationDuration;

// Constants for viewport anchoring on resize.
static const float viewportAnchorCoordX = 0.5f;
static const float viewportAnchorCoordY = 0;

// Constants for zooming in on a focused text field.
static constexpr base::TimeDelta kScrollAndScaleAnimationDuration =
    base::Milliseconds(200);
static const int minReadableCaretHeight = 16;
static const int minReadableCaretHeightForTextArea = 13;
static const float minScaleChangeToTriggerZoom = 1.5f;
static const float leftBoxRatio = 0.3f;
static const int caretPadding = 10;

namespace blink {

using mojom::blink::EffectiveConnectionType;

// Historically, these values came from Webkit in
// WebKitLegacy/mac/WebView/WebView.mm (named MinimumZoomMultiplier and
// MaximumZoomMultiplier there).
const double WebView::kMinTextSizeMultiplier = 0.5;
const double WebView::kMaxTextSizeMultiplier = 3.0;

// static
HashSet<WebViewImpl*>& WebViewImpl::AllInstances() {
  DEFINE_STATIC_LOCAL(HashSet<WebViewImpl*>, all_instances, ());
  return all_instances;
}

static bool g_should_use_external_popup_menus = false;

void WebView::SetUseExternalPopupMenus(bool use_external_popup_menus) {
  g_should_use_external_popup_menus = use_external_popup_menus;
}

bool WebViewImpl::UseExternalPopupMenus() {
  return g_should_use_external_popup_menus;
}

namespace {

class EmptyEventListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext* execution_context, Event*) override {}
};

typedef void (*SetFontFamilyWrapper)(blink::WebSettings*,
                                     const std::u16string&,
                                     UScriptCode);

void SetStandardFontFamilyWrapper(WebSettings* settings,
                                  const std::u16string& font,
                                  UScriptCode script) {
  settings->SetStandardFontFamily(WebString::FromUTF16(font), script);
}

void SetFixedFontFamilyWrapper(WebSettings* settings,
                               const std::u16string& font,
                               UScriptCode script) {
  settings->SetFixedFontFamily(WebString::FromUTF16(font), script);
}

void SetSerifFontFamilyWrapper(WebSettings* settings,
                               const std::u16string& font,
                               UScriptCode script) {
  settings->SetSerifFontFamily(WebString::FromUTF16(font), script);
}

void SetSansSerifFontFamilyWrapper(WebSettings* settings,
                                   const std::u16string& font,
                                   UScriptCode script) {
  settings->SetSansSerifFontFamily(WebString::FromUTF16(font), script);
}

void SetCursiveFontFamilyWrapper(WebSettings* settings,
                                 const std::u16string& font,
                                 UScriptCode script) {
  settings->SetCursiveFontFamily(WebString::FromUTF16(font), script);
}

void SetFantasyFontFamilyWrapper(WebSettings* settings,
                                 const std::u16string& font,
                                 UScriptCode script) {
  settings->SetFantasyFontFamily(WebString::FromUTF16(font), script);
}

void SetMathFontFamilyWrapper(WebSettings* settings,
                              const std::u16string& font,
                              UScriptCode script) {
  settings->SetMathFontFamily(WebString::FromUTF16(font), script);
}

// If |scriptCode| is a member of a family of "similar" script codes, returns
// the script code in that family that is used by WebKit for font selection
// purposes.  For example, USCRIPT_KATAKANA_OR_HIRAGANA and USCRIPT_JAPANESE are
// considered equivalent for the purposes of font selection.  WebKit uses the
// script code USCRIPT_KATAKANA_OR_HIRAGANA.  So, if |scriptCode| is
// USCRIPT_JAPANESE, the function returns USCRIPT_KATAKANA_OR_HIRAGANA.  WebKit
// uses different scripts than the ones in Chrome pref names because the version
// of ICU included on certain ports does not have some of the newer scripts.  If
// |scriptCode| is not a member of such a family, returns |scriptCode|.
UScriptCode GetScriptForWebSettings(UScriptCode scriptCode) {
  switch (scriptCode) {
    case USCRIPT_HIRAGANA:
    case USCRIPT_KATAKANA:
    case USCRIPT_JAPANESE:
      return USCRIPT_KATAKANA_OR_HIRAGANA;
    case USCRIPT_KOREAN:
      return USCRIPT_HANGUL;
    default:
      return scriptCode;
  }
}

void ApplyFontsFromMap(const web_pref::ScriptFontFamilyMap& map,
                       SetFontFamilyWrapper setter,
                       WebSettings* settings) {
  for (auto& it : map) {
    int32_t script = u_getPropertyValueEnum(UCHAR_SCRIPT, (it.first).c_str());
    if (script >= 0 && script < USCRIPT_CODE_LIMIT) {
      UScriptCode code = static_cast<UScriptCode>(script);
      (*setter)(settings, it.second, GetScriptForWebSettings(code));
    }
  }
}

void ApplyCommandLineToSettings(WebSettings* settings) {
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  std::string touch_text_selection_strategy =
      command_line.GetSwitchValueASCII(switches::kTouchTextSelectionStrategy);
  if (touch_text_selection_strategy ==
      switches::kTouchTextSelectionStrategy_Character) {
    settings->SetSelectionStrategy(
        WebSettings::SelectionStrategyType::kCharacter);
  } else if (touch_text_selection_strategy ==
             switches::kTouchTextSelectionStrategy_Direction) {
    settings->SetSelectionStrategy(
        WebSettings::SelectionStrategyType::kDirection);
  }

  WebString network_quiet_timeout = WebString::FromUTF8(
      command_line.GetSwitchValueASCII(switches::kNetworkQuietTimeout));
  if (!network_quiet_timeout.IsEmpty()) {
    bool ok;
    double network_quiet_timeout_seconds =
        String(network_quiet_timeout).ToDouble(&ok);
    if (ok)
      settings->SetNetworkQuietTimeout(network_quiet_timeout_seconds);
  }

  if (command_line.HasSwitch(switches::kBlinkSettings)) {
    Vector<String> blink_settings;
    String command_line_settings =
        command_line.GetSwitchValueASCII(switches::kBlinkSettings).c_str();
    command_line_settings.Split(",", blink_settings);
    for (const String& setting : blink_settings) {
      wtf_size_t pos = setting.find('=');
      settings->SetFromStrings(
          WebString(setting.Substring(0, pos)),
          WebString(pos == kNotFound ? "" : setting.Substring(pos + 1)));
    }
  }
}

ui::mojom::blink::WindowOpenDisposition NavigationPolicyToDisposition(
    NavigationPolicy policy) {
  switch (policy) {
    case kNavigationPolicyDownload:
      return ui::mojom::blink::WindowOpenDisposition::SAVE_TO_DISK;
    case kNavigationPolicyCurrentTab:
      return ui::mojom::blink::WindowOpenDisposition::CURRENT_TAB;
    case kNavigationPolicyNewBackgroundTab:
      return ui::mojom::blink::WindowOpenDisposition::NEW_BACKGROUND_TAB;
    case kNavigationPolicyNewForegroundTab:
      return ui::mojom::blink::WindowOpenDisposition::NEW_FOREGROUND_TAB;
    case kNavigationPolicyNewWindow:
      return ui::mojom::blink::WindowOpenDisposition::NEW_WINDOW;
    case kNavigationPolicyNewPopup:
      return ui::mojom::blink::WindowOpenDisposition::NEW_POPUP;
    case kNavigationPolicyPictureInPicture:
      return ui::mojom::blink::WindowOpenDisposition::NEW_PICTURE_IN_PICTURE;
    case kNavigationPolicyLinkPreview:
      NOTREACHED();
  }
  NOTREACHED() << "Unexpected NavigationPolicy";
}

// Records the queuing duration for activation IPC.
void RecordPrerenderActivationSignalDelay(const String& metric_suffix) {
  auto* task = base::TaskAnnotator::CurrentTaskForThread();

  // It should be a Mojo call, so `RunTask` executes it as a non-delayed task.
  CHECK(task);
  CHECK(task->delayed_run_time.is_null());
  base::TimeDelta queueing_time =
      !task->queue_time.is_null() ? base::TimeTicks::Now() - task->queue_time
                                  : base::TimeDelta();
  base::UmaHistogramTimes(
      "Prerender.Experimental.ActivationIPCDelay" + metric_suffix.Ascii(),
      queueing_time);
}

#if !BUILDFLAG(IS_MAC) && !BUILDFLAG(IS_WIN)
SkFontHinting RendererPreferencesToSkiaHinting(
    const blink::RendererPreferences& prefs) {
#if BUILDFLAG(IS_LINUX)
  if (!prefs.should_antialias_text) {
    // When anti-aliasing is off, GTK maps all non-zero hinting settings to
    // 'Normal' hinting so we do the same. Otherwise, folks who have 'Slight'
    // hinting selected will see readable text in everything expect Chromium.
    switch (prefs.hinting) {
      case gfx::FontRenderParams::HINTING_NONE:
        return SkFontHinting::kNone;
      case gfx::FontRenderParams::HINTING_SLIGHT:
      case gfx::FontRenderParams::HINTING_MEDIUM:
      case gfx::FontRenderParams::HINTING_FULL:
        return SkFontHinting::kNormal;
      default:
        NOTREACHED();
    }
  }
#endif

  switch (prefs.hinting) {
    case gfx::FontRenderParams::HINTING_NONE:
      return SkFontHinting::kNone;
    case gfx::FontRenderParams::HINTING_SLIGHT:
      return SkFontHinting::kSlight;
    case gfx::FontRenderParams::HINTING_MEDIUM:
      return SkFontHinting::kNormal;
    case gfx::FontRenderParams::HINTING_FULL:
      return SkFontHinting::kFull;
    default:
      NOTREACHED();
  }
}
#endif  // !BUILDFLAG(IS_MAC) && !BUILDFLAG(IS_WIN)

void ForEachFrameWidgetControlledByView(
    WebViewImpl& web_view,
    base::FunctionRef<void(WebFrameWidgetImpl*)> callback) {
  for (WebFrame* frame = web_view.MainFrame(); frame;
       frame = frame->TraverseNext()) {
    if (auto* frame_impl = DynamicTo<WebLocalFrameImpl>(frame)) {
      if (frame_impl->GetFrame()->IsLocalRoot()) {
        if (auto* widget = frame_impl->FrameWidgetImpl()) {
          callback(widget);
        }
      }
    }
  }
}

void MaybePreloadSystemFonts(Page* page) {
  static bool is_first_run = true;
  if (!is_first_run) {
    return;
  }
  is_first_run = false;

  page->GetAgentGroupScheduler().DefaultTaskRunner()->PostTask(
      FROM_HERE, WTF::BindOnce([]() { FontCache::MaybePreloadSystemFonts(); }));
}

}  // namespace

// WebView ----------------------------------------------------------------

WebView* WebView::Create(
    WebViewClient* client,
    bool is_hidden,
    blink::mojom::PrerenderParamPtr prerender_param,
    std::optional<blink::FencedFrame::DeprecatedFencedFrameMode>
        fenced_frame_mode,
    bool compositing_enabled,
    bool widgets_never_composited,
    WebView* opener,
    CrossVariantMojoAssociatedReceiver<mojom::PageBroadcastInterfaceBase>
        page_handle,
    scheduler::WebAgentGroupScheduler& agent_group_scheduler,
    const SessionStorageNamespaceId& session_storage_namespace_id,
    std::optional<SkColor> page_base_background_color,
    const BrowsingContextGroupInfo& browsing_context_group_info,
    const ColorProviderColorMaps* color_provider_colors,
    blink::mojom::PartitionedPopinParamsPtr partitioned_popin_params) {
  return WebViewImpl::Create(
      client,
      is_hidden ? mojom::blink::PageVisibilityState::kHidden
                : mojom::blink::PageVisibilityState::kVisible,
      std::move(prerender_param), fenced_frame_mode, compositing_enabled,
      widgets_never_composited, To<WebViewImpl>(opener), std::move(page_handle),
      agent_group_scheduler, session_storage_namespace_id,
      std::move(page_base_background_color), browsing_context_group_info,
      color_provider_colors, std::move(partitioned_popin_params));
}

WebViewImpl* WebViewImpl::Create(
    WebViewClient* client,
    mojom::blink::PageVisibilityState visibility,
    blink::mojom::PrerenderParamPtr prerender_param,
    std::optional<blink::FencedFrame::DeprecatedFencedFrameMode>
        fenced_frame_mode,
    bool compositing_enabled,
    bool widgets_never_composited,
    WebViewImpl* opener,
    mojo::PendingAssociatedReceiver<mojom::blink::PageBroadcast> page_handle,
    blink::scheduler::WebAgentGroupScheduler& agent_group_scheduler,
    const SessionStorageNamespaceId& session_storage_namespace_id,
    std::optional<SkColor> page_base_background_color,
    const BrowsingContextGroupInfo& browsing_context_group_info,
    const ColorProviderColorMaps* color_provider_colors,
    blink::mojom::PartitionedPopinParamsPtr partitioned_popin_params) {
  return new WebViewImpl(
      client, visibility, std::move(prerender_param), fenced_frame_mode,
      compositing_enabled, widgets_never_composited, opener,
      std::move(page_handle), agent_group_scheduler,
      session_storage_namespace_id, std::move(page_base_background_color),
      browsing_context_group_info, color_provider_colors,
      std::move(partitioned_popin_params));
}

size_t WebView::GetWebViewCount() {
  return WebViewImpl::AllInstances().size();
}

void WebView::UpdateVisitedLinkState(uint64_t link_hash) {
  Page::VisitedStateChanged(link_hash);
}

void WebView::ResetVisitedLinkState(bool invalidate_visited_link_hashes) {
  Page::AllVisitedStateChanged(invalidate_visited_link_hashes);
}

void WebViewImpl::SetNoStatePrefetchClient(
    WebNoStatePrefetchClient* no_state_prefetch_client) {
  DCHECK(page_);
  ProvideNoStatePrefetchClientTo(*page_,
                                 MakeGarbageCollected<NoStatePrefetchClient>(
                                     *page_, no_state_prefetch_client));
}

void WebViewImpl::CloseWindow() {
#if !(BUILDFLAG(IS_ANDROID) || \
      (BUILDFLAG(IS_CHROMEOS) && defined(ARCH_CPU_ARM64)))
  auto close_task_trace = close_task_posted_stack_trace_;
  base::debug::Alias(&close_task_trace);
  auto close_trace = close_called_stack_trace_;
  base::debug::Alias(&close_trace);
  auto prev_close_window_trace = close_window_called_stack_trace_;
  base::debug::Alias(&prev_close_window_trace);
  close_window_called_stack_trace_.emplace();
  auto cur_close_window_trace = close_window_called_stack_trace_;
  base::debug::Alias(&cur_close_window_trace);
#endif
  SCOPED_CRASH_KEY_BOOL("Bug1499519", "page_exists", !!page_);

  // Have the browser process a close request. We should have either a
  // |local_main_frame_host_remote_| or |remote_main_frame_host_remote_|.
  // This method will not execute if Close has been called as WeakPtrs
  if (GetPage()->MainFrame()->IsLocalFrame()) {
    DCHECK(local_main_frame_host_remote_);
    local_main_frame_host_remote_->RequestClose();
  } else {
    DCHECK(remote_main_frame_host_remote_);
    remote_main_frame_host_remote_->RouteCloseEvent();
  }
}

WebViewImpl::WebViewImpl(
    WebViewClient* client,
    mojom::blink::PageVisibilityState visibility,
    blink::mojom::PrerenderParamPtr prerender_param,
    std::optional<blink::FencedFrame::DeprecatedFencedFrameMode>
        fenced_frame_mode,
    bool does_composite,
    bool widgets_never_composited,
    WebViewImpl* opener,
    mojo::PendingAssociatedReceiver<mojom::blink::PageBroadcast> page_handle,
    blink::scheduler::WebAgentGroupScheduler& agent_group_scheduler,
    const SessionStorageNamespaceId& session_storage_namespace_id,
    std::optional<SkColor> page_base_background_color,
    const BrowsingContextGroupInfo& browsing_context_group_info,
    const ColorProviderColorMaps* color_provider_colors,
    blink::mojom::PartitionedPopinParamsPtr partitioned_popin_params)
    : widgets_never_composited_(widgets_never_composited),
      web_view_client_(client),
      chrome_client_(MakeGarbageCollected<ChromeClientImpl>(this)),
      minimum_zoom_level_(
          blink::ZoomFactorToZoomLevel(kMinimumBrowserZoomFactor)),
      maximum_zoom_level_(
          blink::ZoomFactorToZoomLevel(kMaximumBrowserZoomFactor)),
      does_composite_(does_composite),
      fullscreen_controller_(std::make_unique<FullscreenController>(this)),
      page_base_background_color_(
          page_base_background_color.value_or(SK_ColorWHITE)),
      receiver_(this,
                std::move(page_handle),
                agent_group_scheduler.DefaultTaskRunner()),
      session_storage_namespace_id_(session_storage_namespace_id),
      web_agent_group_scheduler_(agent_group_scheduler) {
  if (receiver_) {
    // Typically, the browser process closes the corresponding peer handle
    // to signal the renderer process to destroy `this`. In certain
    // situations where the lifetime of `this` is not controlled by a
    // corresponding browser-side `RenderViewHostImpl` (e.g. tests or
    // printing), call `Close()` directly instead to delete `this`.
    receiver_.set_disconnect_handler(
        WTF::BindOnce(&WebViewImpl::MojoDisconnected, WTF::Unretained(this)));
  }
  if (!web_view_client_)
    DCHECK(!does_composite_);
  page_ = Page::CreateOrdinary(
      *chrome_client_, opener ? opener->GetPage() : nullptr,
      agent_group_scheduler.GetAgentGroupScheduler(),
      browsing_context_group_info, color_provider_colors,
      std::move(partitioned_popin_params));
  CoreInitializer::GetInstance().ProvideModulesToPage(
      *page_, session_storage_namespace_id_);

  SetVisibilityState(visibility, /*is_initial_state=*/true);
  if (prerender_param) {
    page_->SetIsPrerendering(true);
    page_->SetPrerenderMetricSuffix(
        String(prerender_param->page_metric_suffix));
    page_->SetShouldWarmUpCompositorOnPrerender(
        prerender_param->should_warm_up_compositor);
    page_->SetShouldPreparePaintTreeOnPrerender(
        prerender_param->should_prepare_paint_tree);
  }

  if (fenced_frame_mode && features::IsFencedFramesEnabled()) {
    page_->SetIsMainFrameFencedFrameRoot();
    page_->SetDeprecatedFencedFrameMode(*fenced_frame_mode);
  } else {
    // `fenced_frame_mode` should only be set if creating an MPArch
    // fenced frame.
    DCHECK(!fenced_frame_mode);
  }

  // When not compositing, keep the Page in the loop so that it will paint all
  // content into the root layer, as multiple layers can only be used when
  // compositing them together later.
  if (does_composite_)
    page_->GetSettings().SetAcceleratedCompositingEnabled(true);

  dev_tools_emulator_ = MakeGarbageCollected<DevToolsEmulator>(this);

  AllInstances().insert(this);

  resize_viewport_anchor_ = MakeGarbageCollected<ResizeViewportAnchor>(*page_);

  // Ensure we have valid page scale constraints even if the embedder never
  // changes defaults.
  GetPageScaleConstraintsSet().ComputeFinalConstraints();
}

WebViewImpl::~WebViewImpl() {
  DCHECK(!page_);
}

void WebViewImpl::SetTabKeyCyclesThroughElements(bool value) {
  if (page_)
    page_->SetTabKeyCyclesThroughElements(value);
}

bool WebViewImpl::StartPageScaleAnimation(const gfx::Point& target_position,
                                          bool use_anchor,
                                          float new_scale,
                                          base::TimeDelta duration) {
  // PageScaleFactor is a property of the main frame only, and only exists when
  // compositing.
  DCHECK(MainFrameImpl());
  DCHECK(does_composite_);

  VisualViewport& visual_viewport = GetPage()->GetVisualViewport();
  DCHECK(visual_viewport.IsActiveViewport());

  gfx::Point clamped_point = target_position;
  if (!use_anchor) {
    clamped_point =
        visual_viewport.ClampDocumentOffsetAtScale(target_position, new_scale);

    // TODO(bokan): Why special case duration zero? PageScaleAnimation should
    // work ok for that.
    if (duration.is_zero()) {
      SetPageScaleFactor(new_scale);

      LocalFrameView* view = MainFrameImpl()->GetFrameView();
      if (view && view->GetScrollableArea()) {
        view->GetScrollableArea()->SetScrollOffset(
            ScrollOffset(gfx::Vector2dF(clamped_point.OffsetFromOrigin())),
            mojom::blink::
"""


```