Response:
The user wants me to analyze the provided C++ code snippet from `blink/renderer/core/loader/frame_loader.cc`.

My plan is to:
1. **Identify the primary purpose of `FrameLoader`**: Based on the file path and code, it seems to be responsible for handling the loading process of frames in Blink.
2. **List its functionalities**: Go through the code and identify key methods and their roles in the frame loading process.
3. **Relate to JavaScript, HTML, and CSS**:  Analyze how `FrameLoader` interacts with these web technologies during loading. Provide concrete examples.
4. **Infer logic and provide examples**: Identify conditional logic within the code and create hypothetical input and output scenarios.
5. **Identify potential user/programming errors**: Look for error handling or situations where incorrect usage might occur.
6. **Explain user actions leading to this code**: Describe typical user interactions that would trigger the `FrameLoader` logic.
7. **Summarize the functionalities**: Condense the findings into a concise summary for part 1.
这是`blink/renderer/core/loader/frame_loader.cc`文件的第一部分，主要功能是负责**控制和管理 frame（框架）的加载过程**。它包含了处理各种加载场景、与浏览器的其他组件交互以及处理导航相关的逻辑。

以下是该部分代码功能的归纳：

**核心功能：**

* **管理 Frame 的加载状态:**  `FrameLoader` 维护着 frame 的加载状态，例如是否正在加载、是否完成加载等。
* **处理导航请求:**  接收并处理各种导航请求，例如用户点击链接、通过 JavaScript 修改 `location.href`、表单提交等。
* **创建和管理 `DocumentLoader`:**  `FrameLoader` 会为每次新的导航创建一个 `DocumentLoader` 对象，`DocumentLoader` 负责实际的资源获取和文档解析工作。
* **处理不同类型的加载:**  区分并处理不同类型的加载，例如首次加载、刷新、后退/前进、替换当前页面等。
* **与历史记录交互:**  保存和恢复浏览历史记录，包括滚动位置和页面状态。
* **处理客户端重定向:**  识别和处理客户端发起的重定向。
* **执行 unload 事件:**  在页面卸载前触发 `unload` 事件。
* **处理 `document.open()`:**  响应 `document.open()` 调用。
* **分发 DOMContentLoaded 事件:**  在 HTML 文档解析完成后分发 `DOMContentLoaded` 事件。
* **处理锚点链接 (Fragment Navigation):**  处理页面内的锚点跳转。
* **权限和安全检查:**  执行一些基本的权限和安全检查，例如检查 JavaScript URL 的执行权限、阻止加载本地资源等。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    * **`LogJavaScriptUrlHistogram` 函数:**  当执行 `javascript:` 类型的 URL 时，会调用此函数记录相关的使用情况。 例如，用户在地址栏输入 `javascript:alert('hello')` 或页面 JavaScript 代码执行 `window.location.href = 'javascript:void(0)'`。
    * **`DispatchDidDispatchDOMContentLoadedEvent` 函数:**  在 HTML 文档被解析并且所有的 script 标签（带有 `defer` 属性的除外）都被执行后，会触发此函数，通知 JavaScript 环境 DOM 结构已经准备好。
    * **检查 JavaScript URL 权限:**  `AllowRequestForThisFrame` 函数会检查尝试加载 `javascript:` URL 的脚本是否有权限执行。例如，一个沙盒化的 iframe 可能不允许执行 `javascript:` URL。
* **HTML:**
    * **处理表单提交:** `DetermineNavigationType` 函数会根据是否是表单提交来判断导航类型。当用户点击 `<form>` 元素的提交按钮时，会触发相应的逻辑。
    * **处理锚点链接:**  `ProcessFragment` 函数负责处理 URL 中的 `#` 符号后的片段标识符，实现页面内的滚动跳转。 例如，用户点击 `<a href="#section2">` 链接。
    * **`DidExplicitOpen` 函数:** 当 JavaScript 调用 `document.open()` 方法时，会触发此函数，这通常用于动态生成 HTML 内容。
* **CSS:**  虽然这部分代码没有直接处理 CSS 的解析或应用，但 `FrameLoader` 负责加载 HTML 文档，而 HTML 文档中会包含或链接到 CSS 文件。  `FrameLoader` 的加载过程是 CSS 能够被下载和解析的基础。

**逻辑推理与假设输入输出：**

**假设输入:** 用户点击了一个指向同一页面内不同锚点的链接 `<a href="#footer">`。

**输出:**

1. `StartNavigation` 函数会被调用，`frame_load_type` 可能为 `kStandard`。
2. `DetermineNavigationType` 函数会判断这是一个站内导航。
3. `ShouldPerformFragmentNavigation` 会返回 `true`。
4. `CommitSameDocumentNavigation` 函数会被调用，指示这是一个相同的文档内的导航。
5. `ProcessScrollForSameDocumentNavigation` 函数会被调用。
6. `ProcessFragment` 函数会解析 URL 中的 `#footer` 并滚动到对应的元素。

**用户或编程常见的使用错误举例：**

* **在不允许执行 JavaScript 的环境下执行 `javascript:` URL:** 用户可能在一个设置了安全策略禁止执行内联 JavaScript 的页面中，尝试通过 `javascript:` URL 执行脚本，这将导致 `AllowRequestForThisFrame` 返回 `false`，并显示安全错误信息。
* **错误地处理客户端重定向:** 开发者可能没有正确理解客户端重定向的含义，导致在某些本不应该被认为是客户端重定向的场景下，使用了错误的 `ClientRedirectPolicy`，可能会影响浏览器的历史记录管理。

**用户操作如何一步步的到达这里作为调试线索：**

1. **用户在地址栏输入 URL 并按下回车键:** 这会触发一个顶层 frame 的导航。
2. **用户点击页面上的一个链接:**  这会触发一个 frame 的导航。
3. **用户点击浏览器的前进或后退按钮:** 这会触发一个 `kBackForward` 类型的加载。
4. **页面上的 JavaScript 代码修改了 `window.location.href`:** 这会触发一个客户端导航。
5. **用户提交了一个表单:** 这会触发一个表单提交的导航。
6. **页面上的 JavaScript 代码调用了 `document.open()`:** 这会触发 `DidExplicitOpen` 函数。

通过查看调用栈，可以追踪用户操作触发的具体路径，例如，如果调试器停在 `StartNavigation` 函数，可以向上查找调用者，判断是用户点击了链接还是 JavaScript 代码发起的导航。如果停在 `DispatchDidDispatchDOMContentLoadedEvent`，则说明浏览器已经完成了 HTML 的解析。

**本部分功能归纳：**

总而言之，`blink/renderer/core/loader/frame_loader.cc` 的第一部分主要负责处理 frame 的导航和加载的初始化阶段，包括接收导航请求、判断导航类型、创建 `DocumentLoader`、执行基本的安全检查以及处理与 JavaScript 和 HTML 相关的事件。它是 Blink 引擎中负责页面加载流程控制的核心组件之一。

Prompt: 
```
这是目录为blink/renderer/core/loader/frame_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2008 Alp Toker <alp@atoker.com>
 * Copyright (C) Research In Motion Limited 2009. All rights reserved.
 * Copyright (C) 2011 Kris Jordan <krisjordan@gmail.com>
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

#include "third_party/blink/renderer/core/loader/frame_loader.h"

#include <memory>
#include <utility>

#include "base/auto_reset.h"
#include "base/trace_event/typed_macros.h"
#include "base/unguessable_token.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/metrics/public/cpp/metrics_utils.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/common/user_agent/user_agent_metadata.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_network_provider.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/web_frame_load_type.h"
#include "third_party/blink/public/web/web_history_item.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/public/web/web_navigation_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/ignore_opens_during_unload_count_incrementer.h"
#include "third_party/blink/renderer/core/events/page_transition_event.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_anchor.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/csp/csp_source.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/policy_container.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/document_load_timing.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/form_submission.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader_types.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/idna_util.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/loader/navigation_policy.h"
#include "third_party/blink/renderer/core/loader/progress_tracker.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/plugin_data.h"
#include "third_party/blink/renderer/core/page/plugin_script_forbidden_scope.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_activity_logger.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/mhtml/archive_resource.h"
#include "third_party/blink/renderer/platform/mhtml/mhtml_archive.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/runtime_feature_state/runtime_feature_state_override_context.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "url/url_features.h"

namespace blink {

namespace {

void LogJavaScriptUrlHistogram(LocalDOMWindow* origin_window,
                               const StringView& script) {
  origin_window->CountUse(WebFeature::kExecutedJavaScriptURLFromFrame);
  if (script.length() > 6) {
    return;
  }

  String stripped_script = script.ToString().StripWhiteSpace().Replace(";", "");
  if (stripped_script == "''" || stripped_script == "\"\"") {
    origin_window->CountUse(WebFeature::kExecutedEmptyJavaScriptURLFromFrame);
  }
}

}  // namespace

bool IsBackForwardLoadType(WebFrameLoadType type) {
  return type == WebFrameLoadType::kBackForward;
}

bool IsBackForwardOrRestore(WebFrameLoadType type) {
  return type == WebFrameLoadType::kBackForward ||
         type == WebFrameLoadType::kRestore;
}

bool IsRestoreLoadType(WebFrameLoadType type) {
  return type == WebFrameLoadType::kRestore;
}

bool IsReloadLoadType(WebFrameLoadType type) {
  return type == WebFrameLoadType::kReload ||
         type == WebFrameLoadType::kReloadBypassingCache;
}

bool FrameLoader::NeedsHistoryItemRestore(WebFrameLoadType type) {
  return IsBackForwardOrRestore(type) || IsReloadLoadType(type);
}

ResourceRequest FrameLoader::ResourceRequestForReload(
    WebFrameLoadType frame_load_type,
    ClientRedirectPolicy client_redirect_policy) {
  DCHECK(IsReloadLoadType(frame_load_type));
  const auto cache_mode =
      frame_load_type == WebFrameLoadType::kReloadBypassingCache
          ? mojom::FetchCacheMode::kBypassCache
          : mojom::FetchCacheMode::kValidateCache;
  if (!document_loader_ || !document_loader_->GetHistoryItem())
    return ResourceRequest();

  ResourceRequest request =
      document_loader_->GetHistoryItem()->GenerateResourceRequest(cache_mode);

  // ClientRedirectPolicy is an indication that this load was triggered by some
  // direct interaction with the page. If this reload is not a client redirect,
  // we should reuse the referrer from the original load of the current
  // document. If this reload is a client redirect (e.g., location.reload()), it
  // was initiated by something in the current document and should therefore
  // show the current document's url as the referrer.
  if (client_redirect_policy == ClientRedirectPolicy::kClientRedirect) {
    LocalDOMWindow* window = frame_->DomWindow();
    Referrer referrer = SecurityPolicy::GenerateReferrer(
        window->GetReferrerPolicy(), window->Url(), window->OutgoingReferrer());
    request.SetReferrerString(referrer.referrer);
    request.SetReferrerPolicy(referrer.referrer_policy);
  }

  request.SetSkipServiceWorker(frame_load_type ==
                               WebFrameLoadType::kReloadBypassingCache);
  return request;
}

FrameLoader::FrameLoader(LocalFrame* frame)
    : frame_(frame),
      progress_tracker_(MakeGarbageCollected<ProgressTracker>(frame)),
      dispatching_did_clear_window_object_in_main_world_(false),
      virtual_time_pauser_(
          frame_->GetFrameScheduler()->CreateWebScopedVirtualTimePauser(
              "FrameLoader",
              WebScopedVirtualTimePauser::VirtualTaskDuration::kInstant)) {
  DCHECK(frame_);

  TRACE_EVENT_OBJECT_CREATED_WITH_ID("loading", "FrameLoader", this);
  TakeObjectSnapshot();
}

FrameLoader::~FrameLoader() {
  DCHECK_EQ(state_, State::kDetached);
}

void FrameLoader::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(progress_tracker_);
  visitor->Trace(document_loader_);
}

void FrameLoader::Init(const DocumentToken& document_token,
                       std::unique_ptr<PolicyContainer> policy_container,
                       const StorageKey& storage_key,
                       ukm::SourceId document_ukm_source_id,
                       const KURL& creator_base_url) {
  DCHECK(policy_container);
  ScriptForbiddenScope forbid_scripts;

  // Load the initial empty document:
  auto navigation_params = std::make_unique<WebNavigationParams>();
  navigation_params->url = KURL(g_empty_string);
  if (!creator_base_url.IsEmpty()) {
    navigation_params->fallback_base_url = creator_base_url;
  }
  navigation_params->storage_key = storage_key;
  navigation_params->document_token = document_token;
  navigation_params->frame_policy =
      frame_->Owner() ? frame_->Owner()->GetFramePolicy() : FramePolicy();
  navigation_params->document_ukm_source_id = document_ukm_source_id;

  DocumentLoader* new_document_loader = MakeGarbageCollected<DocumentLoader>(
      frame_, kWebNavigationTypeOther, std::move(navigation_params),
      std::move(policy_container), nullptr /* extra_data */);

  CommitDocumentLoader(new_document_loader, nullptr,
                       CommitReason::kInitialization);

  frame_->GetDocument()->CancelParsing();

  // Suppress finish notifications for initial empty documents, since they don't
  // generate start notifications.
  document_loader_->SetSentDidFinishLoad();
  // Ensure that the frame sees the correct page lifecycle state.
  frame_->OnPageLifecycleStateUpdated();

  TakeObjectSnapshot();

  state_ = State::kInitialized;
}

LocalFrameClient* FrameLoader::Client() const {
  return frame_->Client();
}

ClientRedirectPolicy CalculateClientRedirectPolicy(
    ClientNavigationReason client_navigation_reason,
    WebFrameLoadType frame_load_type,
    bool is_on_initial_empty_document) {
  if (is_on_initial_empty_document ||
      client_navigation_reason == ClientNavigationReason::kNone ||
      client_navigation_reason ==
          ClientNavigationReason::kInitialFrameNavigation ||
      client_navigation_reason == ClientNavigationReason::kFormSubmissionGet ||
      client_navigation_reason == ClientNavigationReason::kFormSubmissionPost ||
      client_navigation_reason == ClientNavigationReason::kAnchorClick) {
    // Navigations away from the initial empty document and some types of
    // navigations like form submission shouldn't be considered as client
    // redirects, because they're not actually caused by a script redirecting to
    // a different URL.
    return ClientRedirectPolicy::kNotClientRedirect;
  }
  // If the ClientRedirectReason is kFrameNavigation, only treat as a client
  // redirect if the WebFrameLoadType is kReplaceCurrentItem. If this check is
  // not applied, an anchor location change is classified as client redirect
  // and an incorrect redirect chain is formed. On deleting one entry of this
  // redirect chain, the whole chain gets deleted. This result in
  // deletion of multiple items on deleting one item in history.
  // https://crbug.com/1138096
  if (client_navigation_reason == ClientNavigationReason::kFrameNavigation &&
      frame_load_type != WebFrameLoadType::kReplaceCurrentItem)
    return ClientRedirectPolicy::kNotClientRedirect;
  return ClientRedirectPolicy::kClientRedirect;
}

void FrameLoader::SetDefersLoading(LoaderFreezeMode mode) {
  if (frame_->GetDocument())
    frame_->GetDocument()->Fetcher()->SetDefersLoading(mode);
  if (document_loader_)
    document_loader_->SetDefersLoading(mode);
}

void FrameLoader::SaveScrollAnchor() {
  if (!document_loader_ || !document_loader_->GetHistoryItem() ||
      !frame_->View())
    return;

  // Shouldn't clobber anything if we might still restore later.
  if (NeedsHistoryItemRestore(document_loader_->LoadType()) &&
      !document_loader_->GetInitialScrollState().was_scrolled_by_user)
    return;

  HistoryItem* history_item = document_loader_->GetHistoryItem();
  if (ScrollableArea* layout_scrollable_area =
          frame_->View()->LayoutViewport()) {
    ScrollAnchor* scroll_anchor = layout_scrollable_area->GetScrollAnchor();
    DCHECK(scroll_anchor);

    const SerializedAnchor& serialized_anchor =
        scroll_anchor->GetSerializedAnchor();
    if (serialized_anchor.IsValid()) {
      auto offset = serialized_anchor.GetScrollOffset(*layout_scrollable_area);
      history_item->SetScrollAnchorData({serialized_anchor.selector,
                                         gfx::PointF(offset.x(), offset.y()),
                                         serialized_anchor.simhash});
    }
  }
}

void FrameLoader::SaveScrollState() {
  if (!document_loader_ || !document_loader_->GetHistoryItem() ||
      !frame_->View())
    return;

  // Shouldn't clobber anything if we might still restore later.
  if (NeedsHistoryItemRestore(document_loader_->LoadType()) &&
      !document_loader_->GetInitialScrollState().was_scrolled_by_user)
    return;

  HistoryItem* history_item = document_loader_->GetHistoryItem();
  // For performance reasons, we don't save scroll anchors as often as we save
  // scroll offsets. In order to avoid keeping around a stale anchor, we clear
  // it when the saved scroll offset changes.
  history_item->SetScrollAnchorData(ScrollAnchorData());
  if (ScrollableArea* layout_scrollable_area = frame_->View()->LayoutViewport())
    history_item->SetScrollOffset(layout_scrollable_area->GetScrollOffset());

  VisualViewport& visual_viewport = frame_->GetPage()->GetVisualViewport();
  if (frame_->IsMainFrame() && visual_viewport.IsActiveViewport()) {
    history_item->SetVisualViewportScrollOffset(
        visual_viewport.VisibleRect().OffsetFromOrigin());
    history_item->SetPageScaleFactor(visual_viewport.Scale());
  }

  Client()->DidUpdateCurrentHistoryItem();
}

void FrameLoader::DispatchUnloadEventAndFillOldDocumentInfoIfNeeded(
    bool will_commit_new_document_in_this_frame) {
  TRACE_EVENT0("navigation",
               "FrameLoader::DispatchUnloadEventAndFillOldDocInfo");
  const std::string_view histogram_suffix =
      will_commit_new_document_in_this_frame ? "CommitInFrame" : "Other";
  base::ScopedUmaHistogramTimer histogram_timer(base::StrCat(
      {"Navigation.FrameLoader.DispatchUnloadEventAndFillOldDocInfo.",
       histogram_suffix}));
  FrameNavigationDisabler navigation_disabler(*frame_);
  SaveScrollState();

  if (SVGImage::IsInSVGImage(frame_->GetDocument()))
    return;

  // Only fill in the info of the unloading document if it is needed for a new
  // document committing in this frame (either due to frame swap or committing
  // a new document in the same FrameLoader). This avoids overwriting the info
  // saved of a parent frame that's already saved in
  // ScopedOldDocumentInfoForCommitCapturer when a child frame is being
  // destroyed due to the parent frame committing. In that case, only the parent
  // frame needs should fill in the info.
  OldDocumentInfoForCommit* old_document_info =
      ScopedOldDocumentInfoForCommitCapturer::CurrentInfo();
  if (!old_document_info || !will_commit_new_document_in_this_frame ||
      !GetDocumentLoader()) {
    frame_->GetDocument()->DispatchUnloadEvents(nullptr);
    return;
  }
  old_document_info->history_item = GetDocumentLoader()->GetHistoryItem();
  old_document_info->had_sticky_activation_before_navigation =
      frame_->HadStickyUserActivationBeforeNavigation();
  if (auto* scheduler = frame_->GetFrameScheduler()) {
    old_document_info->frame_scheduler_unreported_task_time =
        scheduler->UnreportedTaskTime();
  }
  old_document_info->was_focused_frame =
      (frame_->GetPage()->GetFocusController().FocusedFrame() == frame_);

  frame_->GetDocument()->DispatchUnloadEvents(
      &old_document_info->unload_timing_info);
}

void FrameLoader::DidExplicitOpen() {
  probe::DidOpenDocument(frame_.Get(), GetDocumentLoader());
  if (initial_empty_document_status_ ==
      InitialEmptyDocumentStatus::kInitialOrSynchronousAboutBlank) {
    initial_empty_document_status_ = InitialEmptyDocumentStatus::
        kInitialOrSynchronousAboutBlankButExplicitlyOpened;
  }

  // Only model a document.open() as part of a navigation if its parent is not
  // done or in the process of completing.
  if (Frame* parent = frame_->Tree().Parent()) {
    auto* parent_local_frame = DynamicTo<LocalFrame>(parent);
    if ((parent_local_frame &&
         parent_local_frame->GetDocument()->LoadEventStillNeeded()) ||
        (parent->IsRemoteFrame() && parent->IsLoading())) {
      progress_tracker_->ProgressStarted();
    }
  }
}

void FrameLoader::FinishedParsing() {
  if (state_ == State::kUninitialized)
    return;

  progress_tracker_->FinishedParsing();

  frame_->GetLocalFrameHostRemote().DidDispatchDOMContentLoadedEvent();

  if (Client()) {
    ScriptForbiddenScope forbid_scripts;
    Client()->DispatchDidDispatchDOMContentLoadedEvent();
  }

  if (Client()) {
    Client()->RunScriptsAtDocumentReady(
        document_loader_ ? document_loader_->IsCommittedButEmpty() : true);
  }

  if (frame_->View()) {
    ProcessFragment(frame_->GetDocument()->Url(), document_loader_->LoadType(),
                    kNavigationToDifferentDocument);
  }

  frame_->GetDocument()->CheckCompleted();
}

// TODO(dgozman): we are calling this method too often, hoping that it
// does not do anything when navigation is in progress, or when loading
// has finished already. We should call it at the right times.
void FrameLoader::DidFinishNavigation(NavigationFinishState state) {
  if (document_loader_) {
    // Only declare the whole frame finished if the committed navigation is done
    // and there is no provisional navigation in progress.
    // The navigation API may prevent a navigation from completing while waiting
    // for a JS-provided promise to resolve, so check it as well.
    if (!document_loader_->SentDidFinishLoad() || HasProvisionalNavigation())
      return;
    if (frame_->DomWindow()->navigation()->HasNonDroppedOngoingNavigation())
      return;
  }

  // This code in this block is meant to prepare a document for display, but
  // this code may also run when swapping out a provisional frame. In that case,
  // skip the display work.
  if (frame_->IsLoading() && !frame_->IsProvisional()) {
    progress_tracker_->ProgressCompleted();
    // Retry restoring scroll offset since finishing loading disables content
    // size clamping.
    RestoreScrollPositionAndViewState();
    if (document_loader_)
      document_loader_->SetLoadType(WebFrameLoadType::kStandard);
    frame_->FinishedLoading(state);
  }

  // When a subframe finishes loading, the parent should check if *all*
  // subframes have finished loading (which may mean that the parent can declare
  // that the parent itself has finished loading).  This local-subframe-focused
  // code has a remote-subframe equivalent in
  // WebRemoteFrameImpl::DidStopLoading.
  Frame* parent = frame_->Tree().Parent();
  if (parent)
    parent->CheckCompleted();
}

bool FrameLoader::AllowPlugins() {
  // With Oilpan, a FrameLoader might be accessed after the Page has been
  // detached. FrameClient will not be accessible, so bail early.
  if (!Client())
    return false;
  Settings* settings = frame_->GetSettings();
  return settings && settings->GetPluginsEnabled();
}

void FrameLoader::DetachDocumentLoader(Member<DocumentLoader>& loader,
                                       bool flush_microtask_queue) {
  if (!loader)
    return;

  FrameNavigationDisabler navigation_disabler(*frame_);
  loader->DetachFromFrame(flush_microtask_queue);
  loader = nullptr;
}

void FrameLoader::ProcessScrollForSameDocumentNavigation(
    const KURL& url,
    WebFrameLoadType frame_load_type,
    std::optional<HistoryItem::ViewState> view_state,
    mojom::blink::ScrollRestorationType scroll_restoration_type,
    mojom::blink::ScrollBehavior scroll_behavior) {
  if (view_state) {
    RestoreScrollPositionAndViewState(frame_load_type, *view_state,
                                      scroll_restoration_type, scroll_behavior);
  }

  // We need to scroll to the fragment whether or not a hash change occurred,
  // since the user might have scrolled since the previous navigation.
  ProcessFragment(url, frame_load_type, kNavigationWithinSameDocument);

  TakeObjectSnapshot();
}

bool FrameLoader::AllowRequestForThisFrame(const FrameLoadRequest& request) {
  // If no origin Document* was specified, skip remaining security checks and
  // assume the caller has fully initialized the FrameLoadRequest.
  if (!request.GetOriginWindow())
    return true;

  const KURL& url = request.GetResourceRequest().Url();
  if (url.ProtocolIsJavaScript()) {
    if (request.GetOriginWindow()
            ->CheckAndGetJavascriptUrl(request.JavascriptWorld(), url,
                                       frame_->DeprecatedLocalOwner())
            .empty()) {
      return false;
    }

    if (frame_->Owner() && ((frame_->Owner()->GetFramePolicy().sandbox_flags &
                             network::mojom::blink::WebSandboxFlags::kOrigin) !=
                            network::mojom::blink::WebSandboxFlags::kNone)) {
      return false;
    }
  }

  if (!request.CanDisplay(url)) {
    request.GetOriginWindow()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kSecurity,
            mojom::ConsoleMessageLevel::kError,
            "Not allowed to load local resource: " + url.ElidedString()));
    return false;
  }
  return true;
}

static WebNavigationType DetermineNavigationType(
    WebFrameLoadType frame_load_type,
    bool is_form_submission,
    bool have_event) {
  bool is_reload = IsReloadLoadType(frame_load_type);
  bool is_back_forward = IsBackForwardLoadType(frame_load_type);
  bool is_restore = IsRestoreLoadType(frame_load_type);
  if (is_form_submission) {
    if (is_reload)
      return kWebNavigationTypeFormResubmittedReload;
    if (is_back_forward)
      return kWebNavigationTypeFormResubmittedBackForward;
    return kWebNavigationTypeFormSubmitted;
  }
  if (have_event)
    return kWebNavigationTypeLinkClicked;
  if (is_reload)
    return kWebNavigationTypeReload;
  if (is_back_forward)
    return kWebNavigationTypeBackForward;
  if (is_restore) {
    return kWebNavigationTypeRestore;
  }
  return kWebNavigationTypeOther;
}

static mojom::blink::RequestContextType
DetermineRequestContextFromNavigationType(
    const WebNavigationType navigation_type) {
  switch (navigation_type) {
    case kWebNavigationTypeLinkClicked:
      return mojom::blink::RequestContextType::HYPERLINK;

    case kWebNavigationTypeOther:
      return mojom::blink::RequestContextType::LOCATION;

    case kWebNavigationTypeFormResubmittedBackForward:
    case kWebNavigationTypeFormResubmittedReload:
    case kWebNavigationTypeFormSubmitted:
      return mojom::blink::RequestContextType::FORM;

    case kWebNavigationTypeBackForward:
    case kWebNavigationTypeReload:
    case kWebNavigationTypeRestore:
      return mojom::blink::RequestContextType::INTERNAL;
  }
  NOTREACHED();
}

static network::mojom::RequestDestination
DetermineRequestDestinationFromNavigationType(
    const WebNavigationType navigation_type) {
  switch (navigation_type) {
    case kWebNavigationTypeLinkClicked:
    case kWebNavigationTypeOther:
    case kWebNavigationTypeFormResubmittedBackForward:
    case kWebNavigationTypeFormResubmittedReload:
    case kWebNavigationTypeFormSubmitted:
      return network::mojom::RequestDestination::kDocument;
    case kWebNavigationTypeBackForward:
    case kWebNavigationTypeReload:
    case kWebNavigationTypeRestore:
      return network::mojom::RequestDestination::kEmpty;
  }
  NOTREACHED();
}

void FrameLoader::StartNavigation(FrameLoadRequest& request,
                                  WebFrameLoadType frame_load_type) {
  CHECK(!IsBackForwardOrRestore(frame_load_type));
  DCHECK(request.GetTriggeringEventInfo() !=
         mojom::blink::TriggeringEventInfo::kUnknown);
  DCHECK(frame_->GetDocument());
  if (HTMLFrameOwnerElement* element = frame_->DeprecatedLocalOwner())
    element->CancelPendingLazyLoad();

  ResourceRequest& resource_request = request.GetResourceRequest();
  const KURL& url = resource_request.Url();
  LocalDOMWindow* origin_window = request.GetOriginWindow();

  TRACE_EVENT2("navigation", "FrameLoader::StartNavigation", "url",
               url.GetString().Utf8(), "load_type",
               static_cast<int>(frame_load_type));

  resource_request.SetHasUserGesture(
      LocalFrame::HasTransientUserActivation(frame_.Get()));

  if (!AllowRequestForThisFrame(request))
    return;

  // Block renderer-initiated loads of filesystem: URLs not in a Chrome App.
  if (!base::FeatureList::IsEnabled(
          features::kFileSystemUrlNavigationForChromeAppsOnly) &&
      url.ProtocolIs("filesystem") &&
      !base::FeatureList::IsEnabled(features::kFileSystemUrlNavigation)) {
    frame_->GetDocument()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kSecurity,
            mojom::blink::ConsoleMessageLevel::kError,
            "Not allowed to navigate to " + url.Protocol() +
                " URL: " + url.ElidedString()));
    return;
  }

  // Block renderer-initiated loads of data: and filesystem: URLs in the top
  // frame (unless they are reload requests).
  //
  // If the mime type of the data URL is supported, the URL will
  // eventually be rendered, so block it here. Otherwise, the load might be
  // handled by a plugin or end up as a download, so allow it to let the
  // embedder figure out what to do with it. Navigations to filesystem URLs are
  // always blocked here.
  if (frame_->IsMainFrame() && origin_window &&
      request.GetClientNavigationReason() != ClientNavigationReason::kReload &&
      !frame_->Client()->AllowContentInitiatedDataUrlNavigations(
          origin_window->Url()) &&
      (url.ProtocolIs("filesystem") ||
       (url.ProtocolIsData() &&
        network_utils::IsDataURLMimeTypeSupported(url)))) {
    frame_->GetDocument()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kSecurity,
            mojom::blink::ConsoleMessageLevel::kError,
            "Not allowed to navigate top frame to " + url.Protocol() +
                " URL: " + url.ElidedString()));
    return;
  }

  // TODO(dgozman): merge page dismissal check and FrameNavigationDisabler.
  if (!frame_->IsNavigationAllowed() ||
      frame_->GetDocument()->PageDismissalEventBeingDispatched() !=
          Document::kNoDismissal) {
    return;
  }

  if (url.ProtocolIs("filesystem")) {
    document_loader_->CountUse(
        mojom::blink::WebFeature::kFileSystemUrlNavigation);
  }

  // Convert navigations from the initial empty document to do replacement if
  // needed. Note that we don't convert reloads or history navigations (so only
  // kStandard navigations can get converted to do replacement).
  if (frame_load_type == WebFrameLoadType::kStandard &&
      IsOnInitialEmptyDocument()) {
    frame_load_type = WebFrameLoadType::kReplaceCurrentItem;
  }

  bool same_document_navigation =
      request.GetNavigationPolicy() == kNavigationPolicyCurrentTab &&
      ShouldPerformFragmentNavigation(
          request.Form(), resource_request.HttpMethod(), frame_load_type, url);

  // Perform same document navigation.
  if (same_document_navigation) {
    DCHECK(origin_window);
    document_loader_->CommitSameDocumentNavigation(
        url, frame_load_type, nullptr,
        CalculateClientRedirectPolicy(request.GetClientNavigationReason(),
                                      frame_load_type,
                                      IsOnInitialEmptyDocument()),
        resource_request.HasUserGesture(), origin_window->GetSecurityOrigin(),
        /*is_synchronously_committed=*/true, request.GetSourceElement(),
        request.GetTriggeringEventInfo(), /*is_browser_initiated=*/false,
        /*has_ua_visual_transition*/false,
        /*soft_navigation_heuristics_task_id=*/std::nullopt);
    return;
  }

  // If we're navigating and there's still a text fragment permission token on
  // the document loader, it means this navigation didn't try to invoke a text
  // fragment. In this case, we want to propagate this to the next document to
  // allow text-fragments across client-side redirects.
  bool text_fragment_token = GetDoc
"""


```