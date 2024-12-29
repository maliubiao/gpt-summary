Response:
My thinking process to summarize the `DocumentLoader` functionality went through these steps:

1. **Identify the Core Purpose:** The file name `document_loader.cc` and the inclusion of headers like `#include "third_party/blink/renderer/core/loader/document_loader.h"` strongly suggest this class is responsible for loading documents. The copyright notices also indicate a mature piece of code involved in core browser functionality.

2. **Scan for Key Responsibilities:** I looked for keywords and patterns in the code and comments that reveal the class's duties. Terms like "load," "navigation," "resource," "parser," "history," "security," and various HTTP-related concepts jumped out.

3. **Categorize Functionality:** To organize the information, I started grouping related tasks together. This involved noticing patterns in the member variables, included headers, and constructor logic.

    * **Initialization and Configuration:**  The constructor takes a `WebNavigationParams` object, hinting at the importance of setting up the loading process with parameters like URL, HTTP method, headers, etc. The inclusion of `PolicyContainer` and permissions-related headers points to security configuration.
    * **Resource Fetching and Handling:**  The presence of `ResourceResponse`, `WebURLRequest`, and mentions of caching and service workers suggested a role in fetching the document's resources.
    * **Parsing and Processing:** The inclusion of `DocumentParser`, `HTMLDocument`, and mentions of encoding point to handling the downloaded data and converting it into a usable document structure.
    * **Navigation Management:**  The `WebNavigationType` parameter and interaction with `HistoryItem` clearly indicated involvement in managing the browser's navigation history.
    * **Security and Policies:** The inclusion of CSP (Content Security Policy), permissions policies, and mentions of sandboxing highlight the class's role in enforcing security restrictions.
    * **Performance Measurement:** The presence of `DocumentLoadTiming` and mentions of various timing-related events suggested responsibility for tracking the loading performance.
    * **Integration with Other Components:**  The inclusion of headers related to frames, pages, and other core Blink components indicated that `DocumentLoader` acts as a central coordinator.

4. **Elaborate with Examples (based on headers and member variables):**  For each category, I tried to provide specific examples of how the `DocumentLoader` interacts with HTML, CSS, and JavaScript. This involved connecting the high-level functionality to specific code elements:

    * **HTML:** Loading and parsing HTML content using `DocumentParser`, creating `HTMLDocument`, handling elements like `HTMLHtmlElement`, `HTMLHeadElement`, `HTMLBodyElement`.
    * **CSS:** Processing CSS through the loading of resources, although this file might not directly *parse* CSS, it orchestrates the process. The `PolicyContainer` might contain information related to CSS features.
    * **JavaScript:**  While not directly executing JavaScript, the `DocumentLoader` manages the lifecycle where JavaScript will eventually be executed. It sets up the environment, considers CSP which impacts JavaScript execution, and interacts with service workers that can intercept JavaScript requests.

5. **Consider Logic and Assumptions:**  I looked for areas where the code makes decisions or handles different scenarios. The handling of different navigation types and the checks for error conditions are examples. I thought about potential inputs and outputs for some core functions, even without seeing the function implementations. For instance, given a URL, the output would be the loaded document.

6. **Identify Potential User/Programming Errors:** Based on my understanding of web development and browser behavior, I considered common errors that might lead to issues handled by `DocumentLoader`. Incorrect URLs, network errors, and security policy violations are typical examples.

7. **Trace User Actions (Debugging Perspective):** I envisioned a typical user browsing scenario and how their actions would trigger the loading process, eventually reaching the `DocumentLoader`. Clicking links, typing in the address bar, and using back/forward buttons are the primary triggers.

8. **Focus on the "Part 1" Request:**  The prompt specifically asked for a summary of the *first part*. This meant focusing on the information present in the provided code snippet (headers, copyright, and the beginning of the constructor). I avoided speculating too much on functionality that might be implemented later in the file.

9. **Refine and Organize:** I structured the information logically, using headings and bullet points to make it easier to read and understand. I aimed for clarity and conciseness in my explanations. I made sure to explicitly state the limitations based on only having "Part 1".

By following these steps, I could systematically analyze the provided code snippet and generate a comprehensive summary of the `DocumentLoader`'s functionality, including its relationship with HTML, CSS, and JavaScript, along with potential errors and user interaction tracing.
这是 `blink/renderer/core/loader/document_loader.cc` 文件的第一部分，其主要功能是**负责加载和管理文档**。 它充当了获取网页资源、解析内容并将其转化为浏览器可以理解和渲染的文档的关键组件。

**具体功能归纳:**

1. **初始化文档加载过程:**
   - 接收来自浏览器或其他组件的导航请求，并存储相关的加载参数，例如 URL、HTTP 方法、请求头、POST 数据等。
   - 创建和管理与特定文档加载相关的状态信息，例如加载状态、加载时间、安全策略等。
   - 关联加载器与特定的 `LocalFrame` (本地框架)，表明该加载器负责该框架内文档的加载。

2. **处理导航参数:**
   - 存储并处理 `WebNavigationParams` 对象，该对象包含了导航的所有必要信息，例如目标 URL、导航类型（链接点击、后退/前进、刷新等）、历史记录状态、客户端提示等。
   - 从 `WebNavigationParams` 中提取并保存关键信息，例如请求的 `URL`、原始 `URL`、HTTP 方法、referrer、请求体、内容类型等。

3. **管理加载状态:**
   - 维护文档加载的不同阶段状态 (例如 `kNotStarted`)。
   - 跟踪是否接收到数据 (`data_received_`)。
   - 记录加载是否为客户端重定向 (`is_client_redirect_`)。
   - 标记是否为失败导航的错误页面 (`is_error_page_for_failed_navigation_`)。

4. **处理安全和策略:**
   - 存储和管理与加载相关的安全策略 (`PolicyContainer`)，包括内容安全策略 (CSP)、权限策略等。
   - 记录是否因为文档策略而被阻止 (`was_blocked_by_document_policy_`)。
   - 处理和存储初始的权限策略覆盖 (`initial_permissions_policy_`).
   - 存储与跨域隔离相关的标志 (`origin_agent_cluster_`, `origin_agent_cluster_left_as_default_`, `is_cross_site_cross_browsing_context_group_`).

5. **与网络请求交互:**
   - 存储和管理与网络请求相关的元数据，例如 `ResourceResponse`。
   - 存储请求发起方的 Origin (`requestor_origin_`).
   - 存储无法访问的 URL (`unreachable_url_`).
   - 可以设置强制的缓存模式 (`force_fetch_cache_mode_`).

6. **处理历史记录:**
   - 关联 `HistoryItem`，用于后退/前进导航。
   - 记录是否替换当前历史记录项 (`replaces_current_history_item_`).
   - 存储 Navigation API 相关的历史记录条目 (`navigation_api_back_entries_`, `navigation_api_forward_entries_`, `navigation_api_previous_entry_`).

7. **管理 Service Worker:**
   - 存储和管理与 Service Worker 相关的状态和提供器 (`service_worker_initial_controller_mode_`, `service_worker_network_provider_`).

8. **处理性能数据:**
   - 使用 `DocumentLoadTiming` 记录文档加载的各个阶段的时间戳。

9. **处理 Origin Trials:**
   - 存储和管理与 Origin Trials 相关的信息，包括发起方的 Origin Trials 和强制启用的 Origin Trials。

10. **处理浏览上下文组信息:**
    - 存储浏览上下文组信息 (`browsing_context_group_info_`).

11. **处理运行时 Feature 的修改:**
    - 存储导航期间修改的运行时 Feature (`modified_runtime_features_`).

12. **处理 Cookie 弃用标签:**
    - 存储 Cookie 弃用标签 (`cookie_deprecation_label_`).

13. **处理内容设置:**
    - 存储渲染器内容设置 (`content_settings_`).

**与 JavaScript, HTML, CSS 的关系 (初步，后续部分可能会有更详细的交互):**

* **HTML:** `DocumentLoader` 的核心任务是加载 HTML 文档。它接收 HTML 内容，并将其交给解析器进行解析，最终构建 DOM 树。在初始化阶段，它会考虑是否需要加载一个空的 HTML 文档 (`loading_url_as_empty_document_`).
    * **举例:** 当用户在浏览器地址栏输入一个 URL 并按下回车键时，`DocumentLoader` 会被创建并开始加载该 URL 指向的 HTML 文档。
* **JavaScript:**  虽然这个文件不直接执行 JavaScript，但 `DocumentLoader` 为 JavaScript 的执行奠定了基础。它处理与 JavaScript 执行相关的安全策略 (CSP)，并且在后续的加载过程中，会触发 JavaScript 的解析和执行。
    * **举例:**  如果在 HTML 文档中包含 `<script>` 标签，`DocumentLoader` 会确保在合适的时机加载和执行这些脚本。同时，CSP 策略的设置会影响哪些 JavaScript 可以被执行。
* **CSS:**  `DocumentLoader` 负责加载 HTML 文档以及与 HTML 关联的 CSS 资源（通过 `<link>` 标签等）。它本身不解析 CSS，但它会触发 CSS 资源的下载，并将其传递给渲染引擎进行处理。
    * **举例:**  当 HTML 文档中包含 `<link rel="stylesheet" href="style.css">` 时，`DocumentLoader` 会负责发起对 `style.css` 文件的请求并接收其内容。

**逻辑推理 (基于已有的信息):**

* **假设输入:** 一个包含 URL 的 `WebNavigationParams` 对象，该 URL 指向一个有效的 HTML 文件。
* **输出:**  `DocumentLoader` 对象被创建，并开始进行网络请求以获取 HTML 内容。相关的加载状态被设置为 "Not Started"。与该加载相关的基本信息（URL、方法等）被存储在 `DocumentLoader` 的成员变量中。

**用户或编程常见的使用错误 (基于已有的信息):**

* **错误的 URL:**  如果 `WebNavigationParams` 中包含无效或无法访问的 URL，`DocumentLoader` 可能会进入错误状态，并可能显示错误页面。
* **安全策略冲突:**  如果服务器返回的响应头与预期的安全策略（例如 CSP）冲突，`DocumentLoader` 可能会阻止某些资源的加载或 JavaScript 的执行。
* **不正确的 HTTP 方法或请求体:**  对于需要特定 HTTP 方法（例如 POST）或请求体的请求，如果 `WebNavigationParams` 中的信息不正确，可能导致服务器拒绝请求或返回意外结果。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在地址栏输入 URL 并按下回车键。**
2. **浏览器进程接收到用户的输入，并创建一个新的导航请求。**
3. **浏览器进程根据导航请求的信息，创建一个 `WebNavigationParams` 对象，其中包含了目标 URL、导航类型等信息。**
4. **浏览器进程将 `WebNavigationParams` 对象传递给渲染器进程。**
5. **渲染器进程接收到 `WebNavigationParams` 对象，并根据该对象创建一个 `DocumentLoader` 实例。**
6. **`DocumentLoader` 实例开始执行加载过程，例如发起网络请求。**

**总结 (针对第 1 部分):**

`blink/renderer/core/loader/document_loader.cc` 的第一部分定义了 `DocumentLoader` 类的基本结构和初始化过程。 它负责接收和存储导航请求的参数，管理加载状态，处理安全和策略信息，并为后续的资源获取和文档解析做好准备。 它是 Blink 渲染引擎中负责文档加载的核心组件，为后续的 HTML、CSS 和 JavaScript 的处理奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/loader/document_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/loader/document_loader.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/auto_reset.h"
#include "base/containers/flat_map.h"
#include "base/debug/dump_without_crashing.h"
#include "base/feature_list.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/time/default_tick_clock.h"
#include "base/types/optional_util.h"
#include "base/uuid.h"
#include "build/chromeos_buildflags.h"
#include "net/storage_access_api/status.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/network/public/cpp/client_hints.h"
#include "services/network/public/cpp/header_util.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/url_response_head.mojom-shared.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/client_hints/client_hints.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/javascript_framework_detection.h"
#include "third_party/blink/public/common/loader/loading_behavior_flag.h"
#include "third_party/blink/public/common/metrics/accept_language_and_content_language_usage.h"
#include "third_party/blink/public/common/page/browsing_context_group_info.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/common/scheme_registry.h"
#include "third_party/blink/public/mojom/commit_result/commit_result.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/same_document_navigation_type.mojom-shared.h"
#include "third_party/blink/public/mojom/origin_trials/origin_trial_feature.mojom-shared.h"
#include "third_party/blink/public/mojom/page/page.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_fetch_handler_bypass_option.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_fetch_handler_type.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_network_provider.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_content_security_policy_struct.h"
#include "third_party/blink/public/platform/web_navigation_body_loader.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/public/web/web_navigation_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/document_parser.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/dom/visited_link_state.h"
#include "third_party/blink/renderer/core/dom/weak_identifier_map.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/security_context_init.h"
#include "third_party/blink/renderer/core/execution_context/window_agent.h"
#include "third_party/blink/renderer/core/execution_context/window_agent_factory.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_anchor.h"
#include "third_party/blink/renderer/core/frame/cached_permission_status.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/intervention.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder_builder.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/alternate_signed_exchange_resource_info.h"
#include "third_party/blink/renderer/core/loader/frame_client_hints_preferences_context.h"
#include "third_party/blink/renderer/core/loader/frame_fetch_context.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/loader/old_document_info_for_commit.h"
#include "third_party/blink/renderer/core/loader/prefetched_signed_exchange_manager.h"
#include "third_party/blink/renderer/core/loader/preload_helper.h"
#include "third_party/blink/renderer/core/loader/progress_tracker.h"
#include "third_party/blink/renderer/core/loader/subresource_filter.h"
#include "third_party/blink/renderer/core/mobile_metrics/mobile_friendliness_checker.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/permissions_policy/document_policy_parser.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/speculation_rules/auto_speculation_rules_config.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rule_set.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rules_header.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/profiler_group.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/xml/document_xslt.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/fonts/font_performance.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/background_code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/loader_freeze_mode.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/navigation_body_loader.h"
#include "third_party/blink/renderer/platform/loader/static_data_navigation_body_loader.h"
#include "third_party/blink/renderer/platform/mhtml/archive_resource.h"
#include "third_party/blink/renderer/platform/mhtml/mhtml_archive.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_response_headers.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/runtime_feature_state/runtime_feature_state_override_context.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_info.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/storage/blink_storage_key.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

Vector<mojom::blink::OriginTrialFeature> CopyInitiatorOriginTrials(
    const WebVector<int>& initiator_origin_trial_features) {
  Vector<mojom::blink::OriginTrialFeature> result;
  for (auto feature : initiator_origin_trial_features) {
    // Convert from int to OriginTrialFeature. These values are passed between
    // blink navigations. OriginTrialFeature isn't visible outside of blink (and
    // doesn't need to be) so the values are transferred outside of blink as
    // ints and casted to OriginTrialFeature once being processed in blink.
    result.push_back(static_cast<mojom::blink::OriginTrialFeature>(feature));
  }
  return result;
}

WebVector<int> CopyInitiatorOriginTrials(
    const Vector<mojom::blink::OriginTrialFeature>&
        initiator_origin_trial_features) {
  WebVector<int> result;
  for (auto feature : initiator_origin_trial_features) {
    // Convert from OriginTrialFeature to int. These values are passed between
    // blink navigations. OriginTrialFeature isn't visible outside of blink (and
    // doesn't need to be) so the values are transferred outside of blink as
    // ints and casted to OriginTrialFeature once being processed in blink.
    result.emplace_back(static_cast<int>(feature));
  }
  return result;
}

Vector<String> CopyForceEnabledOriginTrials(
    const WebVector<WebString>& force_enabled_origin_trials) {
  Vector<String> result;
  result.ReserveInitialCapacity(
      base::checked_cast<wtf_size_t>(force_enabled_origin_trials.size()));
  for (const auto& trial : force_enabled_origin_trials)
    result.push_back(trial);
  return result;
}

WebVector<WebString> CopyForceEnabledOriginTrials(
    const Vector<String>& force_enabled_origin_trials) {
  WebVector<String> result;
  for (const auto& trial : force_enabled_origin_trials)
    result.emplace_back(trial);
  return result;
}

bool IsPagePopupRunningInWebTest(LocalFrame* frame) {
  return frame && frame->GetPage()->GetChromeClient().IsPopup() &&
         WebTestSupport::IsRunningWebTest();
}

struct SameSizeAsDocumentLoader
    : public GarbageCollected<SameSizeAsDocumentLoader>,
      public WebDocumentLoader,
      public UseCounter,
      public WebNavigationBodyLoader::Client {
  Member<MHTMLArchive> archive;
  std::unique_ptr<WebNavigationParams> params;
  std::unique_ptr<PolicyContainer> policy_container;
  std::optional<ParsedPermissionsPolicy> isolated_app_permissions_policy;
  DocumentToken token;
  KURL url;
  KURL original_url;
  AtomicString http_method;
  AtomicString referrer;
  scoped_refptr<EncodedFormData> http_body;
  AtomicString http_content_type;
  scoped_refptr<const SecurityOrigin> requestor_origin;
  KURL unreachable_url;
  KURL pre_redirect_url_for_failed_navigations;
  std::unique_ptr<WebNavigationBodyLoader> body_loader;
  bool grant_load_local_resources;
  std::optional<blink::mojom::FetchCacheMode> force_fetch_cache_mode;
  FramePolicy frame_policy;
  std::optional<uint64_t> visited_link_salt;
  Member<LocalFrame> frame;
  Member<HistoryItem> history_item;
  Member<DocumentParser> parser;
  Member<SubresourceFilter> subresource_filter;
  AtomicString original_referrer;
  ResourceResponse response;
  mutable WrappedResourceResponse response_wrapper;
  WebFrameLoadType load_type;
  bool is_client_redirect;
  bool replaces_current_history_item;
  bool data_received;
  bool is_error_page_for_failed_navigation;
  HeapMojoRemote<mojom::blink::ContentSecurityNotifier>
      content_security_notifier_;
  scoped_refptr<SecurityOrigin> origin_to_commit;
  AtomicString origin_calculation_debug_info;
  BlinkStorageKey storage_key;
  WebNavigationType navigation_type;
  DocumentLoadTiming document_load_timing;
  base::TimeTicks time_of_last_data_received;
  mojom::blink::ControllerServiceWorkerMode
      service_worker_initial_controller_mode;
  std::unique_ptr<WebServiceWorkerNetworkProvider>
      service_worker_network_provider;
  DocumentPolicy::ParsedDocumentPolicy document_policy;
  bool was_blocked_by_document_policy;
  Vector<PolicyParserMessageBuffer::Message> document_policy_parsing_messages;
  ClientHintsPreferences client_hints_preferences;
  DocumentLoader::InitialScrollState initial_scroll_state;
  DocumentLoader::State state;
  int parser_blocked_count;
  bool finish_loading_when_parser_resumed;
  bool in_commit_data;
  scoped_refptr<SharedBuffer> data_buffer;
  Vector<DocumentLoader::DecodedBodyData> decoded_data_buffer_;
  base::UnguessableToken devtools_navigation_token;
  base::Uuid base_auction_nonce;
  LoaderFreezeMode defers_loading;
  bool last_navigation_had_transient_user_activation;
  bool had_sticky_activation;
  bool is_browser_initiated;
  bool is_prerendering;
  bool is_same_origin_navigation;
  bool has_text_fragment_token;
  bool was_discarded;
  bool loading_main_document_from_mhtml_archive;
  bool loading_srcdoc;
  KURL fallback_base_url;
  bool loading_url_as_empty_document;
  bool is_static_data;
  CommitReason commit_reason;
  uint64_t main_resource_identifier;
  mojom::blink::ResourceTimingInfoPtr resource_timing_info_for_parent;
  WebScopedVirtualTimePauser virtual_time_pauser;
  Member<PrefetchedSignedExchangeManager> prefetched_signed_exchange_manager;
  ukm::SourceId ukm_source_id;
  UseCounterImpl use_counter;
  const base::TickClock* clock;
  const Vector<mojom::blink::OriginTrialFeature>
      initiator_origin_trial_features;
  const Vector<String> force_enabled_origin_trials;
  bool navigation_scroll_allowed;
  bool origin_agent_cluster;
  bool origin_agent_cluster_left_as_default;
  bool is_cross_site_cross_browsing_context_group;
  bool should_have_sticky_user_activation;
  WebVector<WebHistoryItem> navigation_api_back_entries;
  WebVector<WebHistoryItem> navigation_api_forward_entries;
  Member<HistoryItem> navigation_api_previous_entry;
  std::unique_ptr<CodeCacheHost> code_cache_host;
  mojo::PendingRemote<mojom::blink::CodeCacheHost>
      pending_code_cache_host_for_background;
  HashMap<KURL, EarlyHintsPreloadEntry> early_hints_preloaded_resources;
  std::optional<Vector<KURL>> ad_auction_components;
  std::unique_ptr<ExtraData> extra_data;
  AtomicString reduced_accept_language;
  network::mojom::NavigationDeliveryType navigation_delivery_type;
  std::optional<ViewTransitionState> view_transition_state;
  std::optional<FencedFrame::RedactedFencedFrameProperties>
      fenced_frame_properties;
  net::StorageAccessApiStatus storage_access_api_status;
  mojom::blink::ParentResourceTimingAccess parent_resource_timing_access;
  const std::optional<BrowsingContextGroupInfo> browsing_context_group_info;
  const base::flat_map<mojom::blink::RuntimeFeature, bool>
      modified_runtime_features;
  AtomicString cookie_deprecation_label;
  mojom::RendererContentSettingsPtr content_settings;
  int64_t body_size_from_service_worker;
  const std::optional<
      HashMap<mojom::blink::PermissionName, mojom::blink::PermissionStatus>>
      initial_permission_statuses;
};

// Asserts size of DocumentLoader, so that whenever a new attribute is added to
// DocumentLoader, the assert will fail. When hitting this assert failure,
// please ensure that the attribute is copied correctly (if appropriate) in
// DocumentLoader::CreateWebNavigationParamsToCloneDocument().
ASSERT_SIZE(DocumentLoader, SameSizeAsDocumentLoader);

void WarnIfSandboxIneffective(LocalDOMWindow* window) {
  if (window->document()->IsInitialEmptyDocument())
    return;

  if (window->IsInFencedFrame())
    return;

  const Frame* frame = window->GetFrame();
  if (!frame)
    return;

  using WebSandboxFlags = network::mojom::blink::WebSandboxFlags;
  const WebSandboxFlags& sandbox =
      window->GetSecurityContext().GetSandboxFlags();

  auto allow = [sandbox](WebSandboxFlags flag) {
    return (sandbox & flag) == WebSandboxFlags::kNone;
  };

  if (allow(WebSandboxFlags::kAll))
    return;

  // "allow-scripts" + "allow-same-origin" allows escaping the sandbox, by
  // accessing the parent via `eval` or `document.open`.
  //
  // Similarly to Firefox, warn only when this is a simply nested same-origin
  // iframe
  if (allow(WebSandboxFlags::kOrigin) && allow(WebSandboxFlags::kScripts) &&
      window->parent() && window->parent()->GetFrame()->IsMainFrame() &&
      !frame->IsCrossOriginToNearestMainFrame()) {
    window->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "An iframe which has both allow-scripts and allow-same-origin for its "
        "sandbox attribute can escape its sandboxing."));
    window->CountUse(WebFeature::kSandboxIneffectiveAllowOriginAllowScript);
  }

  // Note: It would be interesting to add additional warning. For instance,
  // Firefox warn that "allow-top-navigation-by-user-activation" is useless if
  // "allow-top-navigation" is set.
}

bool ShouldEmitNewNavigationHistogram(WebNavigationType navigation_type) {
  switch (navigation_type) {
    case kWebNavigationTypeBackForward:
    case kWebNavigationTypeReload:
    case kWebNavigationTypeRestore:
    case kWebNavigationTypeFormResubmittedBackForward:
    case kWebNavigationTypeFormResubmittedReload:
      return false;
    case kWebNavigationTypeLinkClicked:
    case kWebNavigationTypeFormSubmitted:
    case kWebNavigationTypeOther:
      return true;
  }
}

// Helpers to convert between base::flat_map and WTF::HashMap
std::optional<
    HashMap<mojom::blink::PermissionName, mojom::blink::PermissionStatus>>
ConvertPermissionStatusFlatMapToHashMap(
    const std::optional<base::flat_map<mojom::blink::PermissionName,
                                       mojom::blink::PermissionStatus>>&
        flat_map) {
  if (!flat_map) {
    return std::nullopt;
  }

  HashMap<mojom::blink::PermissionName, mojom::blink::PermissionStatus>
      hash_map;
  for (const auto& it : *flat_map) {
    hash_map.insert(it.first, it.second);
  }
  return hash_map;
}

base::flat_map<mojom::blink::PermissionName, mojom::blink::PermissionStatus>
ConvertPermissionStatusHashMapToFlatMap(
    const HashMap<mojom::blink::PermissionName, mojom::blink::PermissionStatus>&
        hash_map) {
  base::flat_map<mojom::blink::PermissionName, mojom::blink::PermissionStatus>
      flat_map;
  for (const auto& it : hash_map) {
    flat_map.try_emplace(it.key, it.value);
  }
  return flat_map;
}

}  // namespace

// Base class for body data received by the loader. This allows abstracting away
// whether encoded or decoded data was received by the loader.
class DocumentLoader::BodyData {
 public:
  virtual ~BodyData() = default;
  virtual void AppendToParser(DocumentLoader* loader) = 0;
  virtual void Buffer(DocumentLoader* loader) = 0;
  virtual base::SpanOrSize<const char> EncodedData() const = 0;
};

// Wraps encoded data received by the loader.
class DocumentLoader::EncodedBodyData : public BodyData {
 public:
  explicit EncodedBodyData(base::span<const char> data) : data_(data) {
    DCHECK(data.data());
    DCHECK(data.size());
  }

  void AppendToParser(DocumentLoader* loader) override {
    loader->parser_->AppendBytes(base::as_bytes(data_));
  }

  void Buffer(DocumentLoader* loader) override {
    loader->data_buffer_->Append(data_.data(), data_.size());
  }

  base::SpanOrSize<const char> EncodedData() const override {
    return base::SpanOrSize(data_);
  }

 private:
  base::span<const char> data_;
};

// Wraps decoded data received by the loader.
class DocumentLoader::DecodedBodyData : public BodyData {
 public:
  DecodedBodyData(const String& data,
                  const DocumentEncodingData& encoding_data,
                  base::SpanOrSize<const char> encoded_data)
      : data_(data),
        encoding_data_(encoding_data),
        encoded_data_(encoded_data) {}

  void AppendToParser(DocumentLoader* loader) override {
    loader->parser_->AppendDecodedData(data_, encoding_data_);
  }

  void Buffer(DocumentLoader* loader) override {
    loader->decoded_data_buffer_.push_back(*this);
  }

  base::SpanOrSize<const char> EncodedData() const override {
    return encoded_data_;
  }

 private:
  String data_;
  DocumentEncodingData encoding_data_;
  base::SpanOrSize<const char> encoded_data_;
};

DocumentLoader::DocumentLoader(
    LocalFrame* frame,
    WebNavigationType navigation_type,
    std::unique_ptr<WebNavigationParams> navigation_params,
    std::unique_ptr<PolicyContainer> policy_container,
    std::unique_ptr<ExtraData> extra_data)
    : params_(std::move(navigation_params)),
      policy_container_(std::move(policy_container)),
      initial_permissions_policy_(params_->permissions_policy_override),
      token_(params_->document_token),
      url_(params_->url),
      original_url_(params_->url),
      http_method_(static_cast<String>(params_->http_method)),
      referrer_(static_cast<String>(params_->referrer)),
      http_body_(params_->http_body),
      http_content_type_(static_cast<String>(params_->http_content_type)),
      requestor_origin_(params_->requestor_origin),
      unreachable_url_(params_->unreachable_url),
      pre_redirect_url_for_failed_navigations_(
          params_->pre_redirect_url_for_failed_navigations),
      grant_load_local_resources_(params_->grant_load_local_resources),
      force_fetch_cache_mode_(params_->force_fetch_cache_mode),
      frame_policy_(params_->frame_policy.value_or(FramePolicy())),
      visited_link_salt_(params_->visited_link_salt),
      frame_(frame),
      // For back/forward navigations, the browser passed a history item to use
      // at commit time in |params_|. Set it as the current history item of this
      // DocumentLoader. For other navigations, |history_item_| will be created
      // when the FrameLoader calls SetHistoryItemStateForCommit.
      history_item_(params_->history_item),
      original_referrer_(referrer_),
      response_(params_->response.ToResourceResponse()),
      response_wrapper_(response_),
      load_type_(params_->frame_load_type),
      is_client_redirect_(params_->is_client_redirect),
      replaces_current_history_item_(load_type_ ==
                                     WebFrameLoadType::kReplaceCurrentItem),
      data_received_(false),
      is_error_page_for_failed_navigation_(
          SchemeRegistry::ShouldTreatURLSchemeAsError(
              response_.ResponseUrl().Protocol())),
      content_security_notifier_(nullptr),
      origin_to_commit_(params_->origin_to_commit.IsNull()
                            ? nullptr
                            : params_->origin_to_commit.Get()->IsolatedCopy()),
      storage_key_(std::move(params_->storage_key)),
      navigation_type_(navigation_type),
      document_load_timing_(*this),
      service_worker_network_provider_(
          std::move(params_->service_worker_network_provider)),
      was_blocked_by_document_policy_(false),
      state_(kNotStarted),
      in_commit_data_(false),
      data_buffer_(SharedBuffer::Create()),
      devtools_navigation_token_(params_->devtools_navigation_token),
      base_auction_nonce_(params_->base_auction_nonce),
      last_navigation_had_transient_user_activation_(
          params_->had_transient_user_activation),
      had_sticky_activation_(params_->is_user_activated),
      is_browser_initiated_(params_->is_browser_initiated),
      was_discarded_(params_->was_discarded),
      loading_srcdoc_(url_.IsAboutSrcdocURL()),
      fallback_base_url_(params_->fallback_base_url),
      loading_url_as_empty_document_(!params_->is_static_data &&
                                     WillLoadUrlAsEmpty(url_)),
      is_static_data_(params_->is_static_data),
      ukm_source_id_(params_->document_ukm_source_id),
      clock_(params_->tick_clock ? params_->tick_clock.get()
                                 : base::DefaultTickClock::GetInstance()),
      initiator_origin_trial_features_(
          CopyInitiatorOriginTrials(params_->initiator_origin_trial_features)),
      force_enabled_origin_trials_(
          CopyForceEnabledOriginTrials(params_->force_enabled_origin_trials)),
      origin_agent_cluster_(params_->origin_agent_cluster),
      origin_agent_cluster_left_as_default_(
          params_->origin_agent_cluster_left_as_default),
      is_cross_site_cross_browsing_context_group_(
          params_->is_cross_site_cross_browsing_context_group),
      should_have_sticky_user_activation_(
          params_->should_have_sticky_user_activation),
      navigation_api_back_entries_(params_->navigation_api_back_entries),
      navigation_api_forward_entries_(params_->navigation_api_forward_entries),
      navigation_api_previous_entry_(params_->navigation_api_previous_entry),
      extra_data_(std::move(extra_data)),
      reduced_accept_language_(params_->reduced_accept_language),
      navigation_delivery_type_(params_->navigation_delivery_type),
      view_transition_state_(std::move(params_->view_transition_state)),
      storage_access_api_status_(params_->load_with_storage_access),
      browsing_context_group_info_(params_->browsing_context_group_info),
      modified_runtime_features_(std::move(params_->modified_runtime_features)),
      cookie_deprecation_label_(params_->cookie_deprecation_label),
      content_settings_(std::move(params_->content_settings)),
      initial_permission_statuses_(ConvertPermissionStatusFlatMapToHashMap(
          params_->initial_permission_statuses)) {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::DocumentLoader",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(frame_);
  DCHECK(params_);

  // See `archive_` attribute documentation.
  if (!frame_->IsMainFrame()) {
    if (auto* parent = DynamicTo<LocalFrame>(frame_->Tree().Parent()))
      archive_ = parent->Loader().GetDocumentLoader()->archive_;
  }

  // Determine if this document should have a text fragment permission token.
  // We can either generate a new one from this navigation, if it's user
  // activated, or receive one propagated from the prior navigation that didn't
  // consume its token.
  has_text_fragment_token_ = TextFragmentAnchor::GenerateNewToken(*this) ||
                             params_->has_text_fragment_token;

  document_policy_ = CreateDocumentPolicy();

  WebNavigationTimings& timings = params_->navigation_timings;
  parent_resource_timing_access_ = timings.parent_resource_timing_access;

  if (!timings.input_start.is_null())
    document_load_timing_.SetInputStart(timings.input_start);
  if (timings.navigation_start.is_null()) {
    // If we don't have any navigation timings yet, it starts now.
    document_load_timing_.SetNavigationStart(clock_->NowTicks());
  } else {
    document_load_timing_.SetNavigationStart(timings.navigation_start);
    if (!timings.redirect_start.is_null()) {
      document_load_timing_.SetRedirectStart(timings.redirect_start);
      document_load_timing_.SetRedirectEnd(timings.redirect_end);
    }
    if (!timings.fetch_start.is_null()) {
      // If we started fetching, we should have started the navigation.
      DCHECK(!timings.navigation_start.is_null());
      document_load_timing_.SetFetchStart(timings.fetch_start);
    }
  }
  document_load_timing_.SetSystemEntropyAtNavigationStart(
      params_->navigation_timings.system_entropy_at_navigation_start);

  document_load_timing_.SetCriticalCHRestart(
      params_->navigation_timings.critical_ch_restart);

  if (was_blocked_by_document_policy_)
    ReplaceWithEmptyDocument();

  for (const auto& resource : params_->early_hints_preloaded_resources)
    early_hints_preloaded_resources_.insert(resource, EarlyHintsPreloadEntry());

  CHECK_EQ(IsBackForwardOrRestore(params_->frame_load_type), !!history_item_);

  if (params_->ad_auction_components) {
    ad_auction_components_.emplace();
    for (const WebURL& url : *params_->ad_auction_components) {
      ad_auction_components_->emplace_back(KURL(url));
    }
 
"""


```