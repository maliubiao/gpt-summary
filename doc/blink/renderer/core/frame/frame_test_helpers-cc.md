Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request involves these steps:

1. **Understand the Goal:** The core request is to analyze the `frame_test_helpers.cc` file, identify its purpose, relate it to web technologies (JavaScript, HTML, CSS), provide examples, discuss potential errors, and summarize its function.

2. **Initial Scan and Keyword Identification:** I start by quickly scanning the `#include` directives and the namespace declaration (`blink::frame_test_helpers`). This immediately tells me that this file is part of the Blink rendering engine and is likely involved in testing the frame functionality. Keywords like "test," "helpers," and the included headers (e.g., `WebLocalFrame.h`, `WebNavigationParams.h`) reinforce this.

3. **Deconstruct the Code by Functionality:** I then proceed to examine the code section by section, grouping related functionalities together.

    * **Load Handling (Key Feature):**  I notice functions like `LoadFrameDontWait`, `LoadFrame`, `LoadHTMLString`, `LoadHistoryItem`, `ReloadFrame`, `ReloadFrameBypassingCache`, and `PumpPendingRequestsForFrameToLoad`. The comments within these functions explicitly mention managing asynchronous requests and ensuring the completion of frame loads. This is a central theme.

    * **Frame Creation and Management:**  Functions like `CreateLocalChild`, `CreateRemote`, `CreateRemoteChild`, and `SwapRemoteFrame` clearly deal with creating and manipulating different types of frames (local and remote). The parameters of these functions (e.g., `TreeScopeType`, `FrameReplicationState`) provide further clues about their role.

    * **Event Handling:** The presence of `CreateMouseEvent` suggests the file provides tools for simulating user interactions.

    * **WebView Management:** The `WebViewHelper` class is a significant part. Its methods like `Initialize`, `InitializeWithOpener`, `InitializeRemote`, `Resize`, and `Reset` indicate its responsibility in setting up and managing `WebView` instances for testing.

    * **Widget Management:**  Functions like `CreateFrameWidget` and `CreateFrameWidgetAndInitializeCompositing` highlight the management of `WebFrameWidget` objects, which are responsible for the visual rendering of frames.

    * **Settings Manipulation:**  The `update_settings_func` parameters in some `WebViewHelper` methods and the `UpdateAndroidCompositingSettings` function indicate the ability to customize web settings during testing.

4. **Relate to Web Technologies:**  Once I have identified the functionalities, I connect them to JavaScript, HTML, and CSS:

    * **HTML:**  The `LoadHTMLString` function directly deals with loading HTML content. The creation of different frame types (`iframe`, nested frames) also relates to HTML structure.
    * **JavaScript:** The `LoadFrame` function handles "javascript:" URLs, indicating support for executing JavaScript. The ability to simulate events is crucial for testing JavaScript interactions.
    * **CSS:**  While not explicitly loading CSS files, the act of rendering frames and the mention of `LayerTreeHost` and compositing imply that the helpers are used in tests that indirectly involve CSS styling and layout. The `Resize` function, which affects the viewport, can also influence how CSS is applied.

5. **Provide Examples and Logic Inference:** For each relationship, I try to construct simple but illustrative examples. For instance, showing how `LoadHTMLString` would load a basic HTML snippet. For logic inference, I consider the sequence of actions within a function, like how `PumpPendingRequestsForFrameToLoad` uses a run loop to ensure asynchronous operations complete.

6. **Identify Potential Errors:** I look for patterns that might lead to common mistakes in using these helpers:

    * **Incorrect URL:**  Passing an invalid URL to `LoadFrame`.
    * **Missing `PumpPendingRequests`:**  Forgetting to call `PumpPendingRequestsForFrameToLoad` after initiating a load.
    * **Incorrect Frame Relationships:** Issues with parent-child frame creation.
    * **Resource Loading Failures:** Although not explicitly shown in the code, I know from general web development that resource loading can fail, so I mention this as a potential area where tests might use these helpers to simulate such failures.

7. **Summarize the Functionality:** Finally, I condense the findings into a concise summary that captures the core purpose of the `frame_test_helpers.cc` file. The key takeaway is that it provides a set of tools to facilitate controlled and predictable testing of frame-related functionalities in the Blink rendering engine.

8. **Structure and Refine:**  I organize the information logically, using headings and bullet points to improve readability. I review the text for clarity, accuracy, and completeness, ensuring it directly addresses all aspects of the original request. I also pay attention to the "part 1 of 2" instruction, ensuring the summary is appropriate for this context.
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "cc/test/test_ukm_recorder_factory.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_settings.h"
#include "cc/trees/render_frame_metadata_observer.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink-forward.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h"
#include "third_party/blink/public/common/frame/frame_policy.h"
#include "third_party/blink/public/common/page/browsing_context_group_info.h"
#include "third_party/blink/public/common/page/color_provider_color_maps.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom.h"
#include "third_party/blink/public/mojom/frame/intrinsic_sizing_info.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/tree_scope_type.mojom-blink.h"
#include "third_party/blink/public/mojom/input/touch_event.mojom-blink.h"
#include "third_party/blink/public/mojom/page/prerender_page_param.mojom.h"
#include "third_party/blink/public/mojom/page/widget.mojom-blink.h"
#include "third_party/blink/public/mojom/partitioned_popins/partitioned_popin_params.mojom.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/test/test_web_frame_helper.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/frame/csp/conversion_util.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/fake_web_plugin.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/widget/input/widget_input_handler_manager.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/base/ime/mojom/text_input_state.mojom-blink.h"

namespace blink {
namespace frame_test_helpers {

namespace {

// The frame test helpers coordinate frame loads in a carefully choreographed
// dance. Since the parser is threaded, simply spinning the run loop once is not
// enough to ensure completion of a load. Instead, the following pattern is
// used to ensure that tests see the final state:
// 1. Starts a load.
// 2. Enter the run loop.
// 3. Posted task triggers the load, and starts pumping pending resource
//    requests using runServeAsyncRequestsTask().
// 4. TestWebFrameClient watches for DidStartLoading/DidStopLoading calls,
//    keeping track of how many loads it thinks are in flight.
// 5. While RunServeAsyncRequestsTask() observes TestWebFrameClient to still
//    have loads in progress, it posts itself back to the run loop.
// 6. When RunServeAsyncRequestsTask() notices there are no more loads in
//    progress, it exits the run loop.
// 7. At this point, all parsing, resource loads, and layout should be finished.

void RunServeAsyncRequestsTask(scoped_refptr<base::TaskRunner> task_runner,
                               base::OnceClosure quit_closure) {
  // TODO(kinuko,toyoshim): Create a mock factory and use it instead of
  // getting the platform's one. (crbug.com/751425)
  URLLoaderMockFactory::GetSingletonInstance()->ServeAsynchronousRequests();
  if (TestWebFrameClient::IsLoading()) {
    task_runner->PostTask(FROM_HERE,
                          WTF::BindOnce(&RunServeAsyncRequestsTask, task_runner,
                                        std::move(quit_closure)));
  } else {
    std::move(quit_closure).Run();
  }
}

// Helper to create a default test client if the supplied client pointer is
// null. The |owned_client| is used to store the client if it must be created.
// In both cases the client to be used is returned.
template <typename T>
T* CreateDefaultClientIfNeeded(T* client, std::unique_ptr<T>& owned_client) {
  if (client)
    return client;
  owned_client = std::make_unique<T>();
  return owned_client.get();
}

template <typename T>
mojo::PendingAssociatedRemote<T> CreateStubRemoteIfNeeded(
    mojo::PendingAssociatedRemote<T> remote) {
  if (remote.is_valid())
    return remote;
  mojo::AssociatedRemote<T> stub_remote;
  std::ignore = stub_remote.BindNewEndpointAndPassDedicatedReceiver();
  return stub_remote.Unbind();
}

viz::FrameSinkId AllocateFrameSinkId() {
  // A static increasing count of frame sinks created so they are all unique.
  static uint32_t s_frame_sink_count = 0;
  return viz::FrameSinkId(++s_frame_sink_count, 1);
}

// Installs a create hook and uninstalls it when this object is
// destroyed.
class ScopedCreateWebFrameWidget {
 public:
  explicit ScopedCreateWebFrameWidget(CreateWebFrameWidgetCallback* hook) {
    InstallCreateWebFrameWidgetHook(hook);
  }

  ~ScopedCreateWebFrameWidget() { InstallCreateWebFrameWidgetHook(nullptr); }
};

}  // namespace

cc::LayerTreeSettings GetSynchronousSingleThreadLayerTreeSettings() {
  cc::LayerTreeSettings settings;
  // Use synchronous compositing so that the MessageLoop becomes idle and the
  // test makes progress.
  settings.single_thread_proxy_scheduler = false;
  settings.use_layer_lists = true;
#if BUILDFLAG(IS_MAC)
  settings.enable_elastic_overscroll = true;
#endif
  return settings;
}

void LoadFrameDontWait(WebLocalFrame* frame, const WebURL& url) {
  auto* impl = To<WebLocalFrameImpl>(frame);
  if (url.ProtocolIs("javascript")) {
    impl->GetFrame()->LoadJavaScriptURL(url);
  } else {
    auto params = std::make_unique<WebNavigationParams>();
    params->url = url;
    params->storage_key =
        BlinkStorageKey::CreateFirstParty(SecurityOrigin::Create(url));
    params->navigation_timings.navigation_start = base::TimeTicks::Now();
    params->navigation_timings.fetch_start = base::TimeTicks::Now();
    params->is_browser_initiated = true;
    MockPolicyContainerHost mock_policy_container_host;
    params->policy_container = std::make_unique<WebPolicyContainer>(
        WebPolicyContainerPolicies(),
        mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
    params->policy_container->policies.sandbox_flags =
        static_cast<TestWebFrameClient*>(frame->Client())->sandbox_flags();
    FillNavigationParamsResponse(params.get());
    impl->CommitNavigation(std::move(params), nullptr /* extra_data */);
  }
}

void LoadFrame(WebLocalFrame* frame, const std::string& url) {
  LoadFrameDontWait(frame, url_test_helpers::ToKURL(url));
  PumpPendingRequestsForFrameToLoad(frame);
}

void LoadHTMLString(WebLocalFrame* frame,
                    const std::string& html,
                    const WebURL& base_url,
                    const base::TickClock* clock) {
  auto* impl = To<WebLocalFrameImpl>(frame);
  std::unique_ptr<WebNavigationParams> navigation_params =
      WebNavigationParams::CreateWithHTMLStringForTesting(html, base_url);
  navigation_params->tick_clock = clock;
  impl->CommitNavigation(std::move(navigation_params),
                         nullptr /* extra_data */);
  PumpPendingRequestsForFrameToLoad(frame);
}

void LoadHistoryItem(WebLocalFrame* frame,
                     const WebHistoryItem& item,
                     mojom::FetchCacheMode cache_mode) {
  auto* impl = To<WebLocalFrameImpl>(frame);
  HistoryItem* history_item = item;
  auto params = std::make_unique<WebNavigationParams>();
  params->url = history_item->Url();
  params->frame_load_type = WebFrameLoadType::kBackForward;
  params->history_item = item;
  params->navigation_timings.navigation_start = base::TimeTicks::Now();
  params->navigation_timings.fetch_start = base::TimeTicks::Now();
  FillNavigationParamsResponse(params.get());
  impl->CommitNavigation(std::move(params), nullptr /* extra_data */);
  PumpPendingRequestsForFrameToLoad(frame);
}

void ReloadFrame(WebLocalFrame* frame) {
  frame->StartReload(WebFrameLoadType::kReload);
  PumpPendingRequestsForFrameToLoad(frame);
}

void ReloadFrameBypassingCache(WebLocalFrame* frame) {
  frame->StartReload(WebFrameLoadType::kReloadBypassingCache);
  PumpPendingRequestsForFrameToLoad(frame);
}

void PumpPendingRequestsForFrameToLoad(WebLocalFrame* frame) {
  base::RunLoop loop;
  scoped_refptr<base::TaskRunner> task_runner =
      frame->GetTaskRunner(blink::TaskType::kInternalTest);
  task_runner->PostTask(FROM_HERE,
                        WTF::BindOnce(&RunServeAsyncRequestsTask, task_runner,
                                      loop.QuitClosure()));
  loop.Run();
}

void FillNavigationParamsResponse(WebNavigationParams* params) {
  KURL kurl(params->url);
  // Empty documents and srcdoc will be handled by DocumentLoader.
  if (DocumentLoader::WillLoadUrlAsEmpty(kurl) || kurl.IsAboutSrcdocURL())
    return;
  URLLoaderMockFactory::GetSingletonInstance()->FillNavigationParamsResponse(
      params);

  // Parse Content Security Policy response headers into the policy container,
  // simulating what the browser does.
  for (auto& csp : ParseContentSecurityPolicies(
           params->response.HttpHeaderField("Content-Security-Policy"),
           network::mojom::blink::ContentSecurityPolicyType::kEnforce,
           network::mojom::blink::ContentSecurityPolicySource::kHTTP,
           params->response.ResponseUrl())) {
    params->policy_container->policies.sandbox_flags |= csp->sandbox;
    params->policy_container->policies.content_security_policies.emplace_back(
        ConvertToPublic(std::move(csp)));
  }
}

WebMouseEvent CreateMouseEvent(WebInputEvent::Type type,
                               WebMouseEvent::Button button,
                               const gfx::Point& point,
                               int modifiers) {
  WebMouseEvent result(type, modifiers,
                       WebInputEvent::GetStaticTimeStampForTests());
  result.pointer_type = WebPointerProperties::PointerType::kMouse;
  result.SetPositionInWidget(point.x(), point.y());
  result.SetPositionInScreen(point.x(), point.y());
  result.button = button;
  result.click_count = 1;
  return result;
}

WebLocalFrameImpl* CreateLocalChild(
    WebLocalFrame& parent,
    mojom::blink::TreeScopeType scope,
    TestWebFrameClient* client,
    WebPolicyContainerBindParams policy_container_bind_params,
    WebLocalFrameClient::FinishChildFrameCreationFn finish_creation) {
  MockPolicyContainerHost mock_policy_container_host;
  mock_policy_container_host.BindWithNewEndpoint(
      std::move(policy_container_bind_params.receiver));
  std::unique_ptr<TestWebFrameClient> owned_client;
  client = CreateDefaultClientIfNeeded(client, owned_client);
  auto* frame = To<WebLocalFrameImpl>(
      parent.CreateLocalChild(scope, client, nullptr, LocalFrameToken()));
  client->Bind(frame, std::move(owned_client));
  finish_creation(frame, DocumentToken(), mojo::NullRemote());
  return frame;
}

WebLocalFrameImpl* CreateLocalChild(
    WebLocalFrame& parent,
    mojom::blink::TreeScopeType scope,
    std::unique_ptr<TestWebFrameClient> self_owned,
    WebPolicyContainerBindParams policy_container_bind_params,
    WebLocalFrameClient::FinishChildFrameCreationFn finish_creation) {
  MockPolicyContainerHost mock_policy_container_host;
  mock_policy_container_host.BindWithNewEndpoint(
      std::move(policy_container_bind_params.receiver));
  DCHECK(self_owned);
  TestWebFrameClient* client = self_owned.get();
  auto* frame = To<WebLocalFrameImpl>(
      parent.CreateLocalChild(scope, client, nullptr, LocalFrameToken()));
  client->Bind(frame, std::move(self_owned));
  finish_creation(frame, DocumentToken(), mojo::NullRemote());
  return frame;
}

WebRemoteFrameImpl* CreateRemote() {
  auto* frame = MakeGarbageCollected<WebRemoteFrameImpl>(
      mojom::blink::TreeScopeType::kDocument, RemoteFrameToken());
  return frame;
}

WebRemoteFrameImpl* CreateRemoteChild(
    WebRemoteFrame& parent,
    const WebString& name,
    scoped_refptr<SecurityOrigin> security_origin) {
  mojom::blink::FrameReplicationStatePtr replicated_state =
      mojom::blink::FrameReplicationState::New();
  replicated_state->name = name;
  if (!security_origin)
    security_origin = SecurityOrigin::CreateUniqueOpaque();
  replicated_state->origin = std::move(security_origin);

  auto* frame = To<WebRemoteFrameImpl>(parent).CreateRemoteChild(
      mojom::blink::TreeScopeType::kDocument, RemoteFrameToken(),
      /*is_loading=*/false,
      /*devtools_frame_token=*/base::UnguessableToken(),
      /*opener=*/nullptr,
      CreateStubRemoteIfNeeded<mojom::blink::RemoteFrameHost>(
          mojo::NullAssociatedRemote()),
      mojo::AssociatedRemote<mojom::blink::RemoteFrame>()
          .BindNewEndpointAndPassDedicatedReceiver(),
      std::move(replicated_state), mojom::blink::FrameOwnerProperties::New());
  return frame;
}

void SwapRemoteFrame(
    WebFrame* old_frame,
    WebRemoteFrame* new_remote_frame,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost> frame_host) {
  mojom::FrameReplicationStatePtr replicated_state =
      mojom::blink::FrameReplicationState::New();
  // Preserve the frame's name on swap.
  replicated_state->name =
      WebFrame::ToCoreFrame(*old_frame)->Tree().GetName().Utf8();

  old_frame->Swap(new_remote_frame,
                  CreateStubRemoteIfNeeded<mojom::blink::RemoteFrameHost>(
                      std::move(frame_host)),
                  mojo::AssociatedRemote<mojom::blink::RemoteFrame>()
                      .BindNewEndpointAndPassDedicatedReceiver(),
                  std::move(replicated_state));
}

WebViewHelper::WebViewHelper(
    CreateTestWebFrameWidgetCallback create_web_frame_callback)
    : web_view_(nullptr),
      agent_group_scheduler_(
          std::make_unique<blink::scheduler::WebAgentGroupScheduler>(
              ThreadScheduler::Current()
                  ->ToMainThreadScheduler()
                  ->CreateAgentGroupScheduler())),
      platform_(Platform::Current()) {
  DocumentLoader::DisableCodeCacheForTesting();
  CreateTestWebFrameWidgetCallback create_callback =
      std::move(create_web_frame_callback);
  if (!create_callback) {
    create_callback =
        WTF::BindRepeating(&WebViewHelper::CreateTestWebFrameWidget<>);
  }
  // Due to return type differences we need to bind the RepeatingCallback
  // in a wrapper.
  create_widget_callback_wrapper_ = WTF::BindRepeating(
      [](const CreateTestWebFrameWidgetCallback& create_test_web_widget,
         base::PassKey<WebLocalFrame> pass_key,
         CrossVariantMojoAssociatedRemote<
             mojom::blink::FrameWidgetHostInterfaceBase> frame_widget_host,
         CrossVariantMojoAssociatedReceiver<
             mojom::blink::FrameWidgetInterfaceBase> frame_widget,
         CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
             widget_host,
         CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
             widget,
         scoped_refptr<base::SingleThreadTaskRunner> task_runner,
         const viz::FrameSinkId& frame_sink_id, bool hidden,
         bool never_composited, bool is_for_child_local_root,
         bool is_for_nested_main_frame,
         bool is_for_scalable_page) -> WebFrameWidget* {
        return create_test_web_widget.Run(
            std::move(pass_key), std::move(frame_widget_host),
            std::move(frame_widget), std::move(widget_host), std::move(widget),
            std::move(task_runner), frame_sink_id, hidden, never_composited,
            is_for_child_local_root, is_for_nested_main_frame,
            is_for_scalable_page);
      },
      std::move(create_callback));
}

WebViewHelper::~WebViewHelper() {
  // Close the WebViewImpl before the WebViewClient is destroyed.
  Reset();
}

WebViewImpl* WebViewHelper::InitializeWithOpener(
    WebFrame* opener,
    TestWebFrameClient* web_frame_client,
    WebViewClient* web_view_client,
    void (*update_settings_func)(WebSettings*),
    std::optional<blink::FencedFrame::DeprecatedFencedFrameMode>
        fenced_frame_mode,
    bool is_prerendering) {
  Reset();

  InitializeWebView(web_view_client, opener ? opener->View() : nullptr,
                    fenced_frame_mode, is_prerendering);
  if (update_settings_func)
    update_settings_func(web_view_->GetSettings());

  std::unique_ptr<TestWebFrameClient> owned_web_frame_client;
  web_frame_client =
      CreateDefaultClientIfNeeded(web_frame_client, owned_web_frame_client);
  WebLocalFrame* frame = WebLocalFrame::CreateMainFrame(
      web_view_, web_frame_client, nullptr, mojo::NullRemote(),
      LocalFrameToken(), DocumentToken(),
      // Passing a null policy_container will create an empty, default policy
      // container.
      /*policy_container=*/nullptr, opener,
      /*name=*/WebString(),
      fenced_frame_mode ? kFencedFrameForcedSandboxFlags
                        : network::mojom::WebSandboxFlags::kNone);
  web_frame_client->Bind(frame, std::move(owned_web_frame_client));

  TestWebFrameWidget* frame_widget =
      CreateFrameWidgetAndInitializeCompositing(frame);

  // We inform the WebView when it has a local main frame attached once the
  // WebFrame is fully set up and the WebFrameWidget is initialized (which is
  // the case by this point).
  web_view_->DidAttachLocalMainFrame();

  // Set an initial size for subframes.
  if (frame->Parent())
    frame_widget->Resize(gfx::Size());
  return web_view_;
}

WebViewImpl* WebViewHelper::Initialize(
    TestWebFrameClient* web_frame_client,
    WebViewClient* web_view_client,
    void (*update_settings_func)(WebSettings*)) {
  return InitializeWithOpener(nullptr, web_frame_client, web_view_client,
                              update_settings_func);
}

WebViewImpl* WebViewHelper::InitializeWithSettings(
    void (*update_settings_func)(WebSettings*)) {
  return InitializeWithOpener(nullptr, nullptr, nullptr, update_settings_func);
}

// static
void WebViewHelper::UpdateAndroidCompositingSettings(WebSettings* settings) {
  settings->SetLCDTextPreference(LCDTextPreference::kIgnored);
  settings->SetViewportMetaEnabled(true);
  settings->SetViewportEnabled(true);
  settings->SetMainFrameResizesAreOrientationChanges(true);
  settings->SetShrinksViewportContentToFit(true);
}

WebViewImpl* WebViewHelper::InitializeAndLoad(
    const std::string& url,
    TestWebFrameClient* web_frame_client,
    WebViewClient* web_view_client,
    void (*update_settings_func)(WebSettings*)) {
  DocumentLoader::DisableCodeCacheForTesting();
  Initialize(web_frame_client, web_view_client, update_settings_func);

  LoadFrame(GetWebView()->MainFrameImpl(), url);

  return GetWebView();
}

WebViewImpl* WebViewHelper::InitializePlaceholderRemote() {
  return InitializeRemoteWithOpenerAndAssociatedRemoteAndReceivers(
      nullptr, nullptr, nullptr, mojo::NullAssociatedRemote(),
      mojo::NullAssociatedReceiver());
}

WebViewImpl* WebViewHelper::InitializeRemote(
    scoped_refptr<SecurityOrigin> security_origin,
    WebViewClient* web_view_client) {
  return InitializeRemoteWithOpener(nullptr, security_origin, web_view_client);
}

WebViewImpl* WebViewHelper::InitializeRemoteWithOpener(
    WebFrame* opener,
    scoped_refptr<SecurityOrigin> security_origin,
    WebViewClient* web_view_client) {
  return InitializeRemoteWithOpenerAndAssociatedRemoteAndReceivers(
      opener, security_origin, web_view_client,
      CreateStubRemoteIfNeeded<mojom::blink::RemoteFrameHost>(
          mojo::NullAssociatedRemote()),
      mojo::AssociatedRemote<mojom::blink::RemoteFrame>()
          .BindNewEndpointAndPassDedicatedReceiver());
}

WebViewImpl*
WebViewHelper::InitializeRemoteWithOpenerAndAssociatedRemoteAndReceivers(
    WebFrame* opener,
    scoped_refptr<SecurityOrigin> security_origin,
    WebViewClient* web_view_client,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
        remote_frame_host,
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame> receiver) {
  Reset();

  InitializeWebView(web_view_client, /*opener=*/nullptr,
                    /*fenced_frame_mode=*/std::nullopt,
                    /*is_prerendering=*/false);

  if (!security_origin)
    security_origin = SecurityOrigin::CreateUniqueOpaque();
  auto replication_state = mojom::blink::FrameReplicationState::New();
  replication_state->origin = security_origin;

  WebRemoteFrameImpl::CreateMainFrame(
      web_view_, RemoteFrameToken(), /*is_loading=*/false,
      /*devtools_frame_token=*/base::UnguessableToken(), opener,
      std::move(remote_frame_host), std::move(receiver),
      std::move(replication_state));
  return web_view_;
}

void WebViewHelper::CheckFrameIsAssociatedWithWebView(WebFrame* frame) {
  // Find the main frame and assert that it is the same.
  while (frame->Parent()) {
    frame = frame->Parent();
  }
  CHECK_EQ(web_view_->MainFrame(), frame);
}

WebLocalFrameImpl* WebViewHelper::CreateLocalChild(
    WebRemoteFrame& parent,
    const WebString& name,
    const WebFrameOwnerProperties& properties,
    WebFrame* previous_sibling,
    TestWebFrameClient* client) {
  CheckFrameIsAssociatedWithWebView(&parent);
  std::unique_ptr<TestWebFrameClient> owned_client;
  client = CreateDefaultClientIfNeeded(client, owned_client);
  MockPolicyContainerHost mock_policy_container_host;
  auto* frame = To<WebLocalFrameImpl>(parent.CreateLocalChild(
      mojom::blink::TreeScopeType::kDocument, name, FramePolicy(), client,
      nullptr, previous_sibling, properties, LocalFrameToken(), nullptr,
      DocumentToken(), mojo::NullRemote(),
      std::make_
### 提示词
```
这是目录为blink/renderer/core/frame/frame_test_helpers.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "cc/test/test_ukm_recorder_factory.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_settings.h"
#include "cc/trees/render_frame_metadata_observer.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink-forward.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h"
#include "third_party/blink/public/common/frame/frame_policy.h"
#include "third_party/blink/public/common/page/browsing_context_group_info.h"
#include "third_party/blink/public/common/page/color_provider_color_maps.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom.h"
#include "third_party/blink/public/mojom/frame/intrinsic_sizing_info.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/tree_scope_type.mojom-blink.h"
#include "third_party/blink/public/mojom/input/touch_event.mojom-blink.h"
#include "third_party/blink/public/mojom/page/prerender_page_param.mojom.h"
#include "third_party/blink/public/mojom/page/widget.mojom-blink.h"
#include "third_party/blink/public/mojom/partitioned_popins/partitioned_popin_params.mojom.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/test/test_web_frame_helper.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/frame/csp/conversion_util.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/fake_web_plugin.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/widget/input/widget_input_handler_manager.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/base/ime/mojom/text_input_state.mojom-blink.h"

namespace blink {
namespace frame_test_helpers {

namespace {

// The frame test helpers coordinate frame loads in a carefully choreographed
// dance. Since the parser is threaded, simply spinning the run loop once is not
// enough to ensure completion of a load. Instead, the following pattern is
// used to ensure that tests see the final state:
// 1. Starts a load.
// 2. Enter the run loop.
// 3. Posted task triggers the load, and starts pumping pending resource
//    requests using runServeAsyncRequestsTask().
// 4. TestWebFrameClient watches for DidStartLoading/DidStopLoading calls,
//    keeping track of how many loads it thinks are in flight.
// 5. While RunServeAsyncRequestsTask() observes TestWebFrameClient to still
//    have loads in progress, it posts itself back to the run loop.
// 6. When RunServeAsyncRequestsTask() notices there are no more loads in
//    progress, it exits the run loop.
// 7. At this point, all parsing, resource loads, and layout should be finished.

void RunServeAsyncRequestsTask(scoped_refptr<base::TaskRunner> task_runner,
                               base::OnceClosure quit_closure) {
  // TODO(kinuko,toyoshim): Create a mock factory and use it instead of
  // getting the platform's one. (crbug.com/751425)
  URLLoaderMockFactory::GetSingletonInstance()->ServeAsynchronousRequests();
  if (TestWebFrameClient::IsLoading()) {
    task_runner->PostTask(FROM_HERE,
                          WTF::BindOnce(&RunServeAsyncRequestsTask, task_runner,
                                        std::move(quit_closure)));
  } else {
    std::move(quit_closure).Run();
  }
}

// Helper to create a default test client if the supplied client pointer is
// null. The |owned_client| is used to store the client if it must be created.
// In both cases the client to be used is returned.
template <typename T>
T* CreateDefaultClientIfNeeded(T* client, std::unique_ptr<T>& owned_client) {
  if (client)
    return client;
  owned_client = std::make_unique<T>();
  return owned_client.get();
}

template <typename T>
mojo::PendingAssociatedRemote<T> CreateStubRemoteIfNeeded(
    mojo::PendingAssociatedRemote<T> remote) {
  if (remote.is_valid())
    return remote;
  mojo::AssociatedRemote<T> stub_remote;
  std::ignore = stub_remote.BindNewEndpointAndPassDedicatedReceiver();
  return stub_remote.Unbind();
}

viz::FrameSinkId AllocateFrameSinkId() {
  // A static increasing count of frame sinks created so they are all unique.
  static uint32_t s_frame_sink_count = 0;
  return viz::FrameSinkId(++s_frame_sink_count, 1);
}

// Installs a create hook and uninstalls it when this object is
// destroyed.
class ScopedCreateWebFrameWidget {
 public:
  explicit ScopedCreateWebFrameWidget(CreateWebFrameWidgetCallback* hook) {
    InstallCreateWebFrameWidgetHook(hook);
  }

  ~ScopedCreateWebFrameWidget() { InstallCreateWebFrameWidgetHook(nullptr); }
};

}  // namespace

cc::LayerTreeSettings GetSynchronousSingleThreadLayerTreeSettings() {
  cc::LayerTreeSettings settings;
  // Use synchronous compositing so that the MessageLoop becomes idle and the
  // test makes progress.
  settings.single_thread_proxy_scheduler = false;
  settings.use_layer_lists = true;
#if BUILDFLAG(IS_MAC)
  settings.enable_elastic_overscroll = true;
#endif
  return settings;
}

void LoadFrameDontWait(WebLocalFrame* frame, const WebURL& url) {
  auto* impl = To<WebLocalFrameImpl>(frame);
  if (url.ProtocolIs("javascript")) {
    impl->GetFrame()->LoadJavaScriptURL(url);
  } else {
    auto params = std::make_unique<WebNavigationParams>();
    params->url = url;
    params->storage_key =
        BlinkStorageKey::CreateFirstParty(SecurityOrigin::Create(url));
    params->navigation_timings.navigation_start = base::TimeTicks::Now();
    params->navigation_timings.fetch_start = base::TimeTicks::Now();
    params->is_browser_initiated = true;
    MockPolicyContainerHost mock_policy_container_host;
    params->policy_container = std::make_unique<WebPolicyContainer>(
        WebPolicyContainerPolicies(),
        mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
    params->policy_container->policies.sandbox_flags =
        static_cast<TestWebFrameClient*>(frame->Client())->sandbox_flags();
    FillNavigationParamsResponse(params.get());
    impl->CommitNavigation(std::move(params), nullptr /* extra_data */);
  }
}

void LoadFrame(WebLocalFrame* frame, const std::string& url) {
  LoadFrameDontWait(frame, url_test_helpers::ToKURL(url));
  PumpPendingRequestsForFrameToLoad(frame);
}

void LoadHTMLString(WebLocalFrame* frame,
                    const std::string& html,
                    const WebURL& base_url,
                    const base::TickClock* clock) {
  auto* impl = To<WebLocalFrameImpl>(frame);
  std::unique_ptr<WebNavigationParams> navigation_params =
      WebNavigationParams::CreateWithHTMLStringForTesting(html, base_url);
  navigation_params->tick_clock = clock;
  impl->CommitNavigation(std::move(navigation_params),
                         nullptr /* extra_data */);
  PumpPendingRequestsForFrameToLoad(frame);
}

void LoadHistoryItem(WebLocalFrame* frame,
                     const WebHistoryItem& item,
                     mojom::FetchCacheMode cache_mode) {
  auto* impl = To<WebLocalFrameImpl>(frame);
  HistoryItem* history_item = item;
  auto params = std::make_unique<WebNavigationParams>();
  params->url = history_item->Url();
  params->frame_load_type = WebFrameLoadType::kBackForward;
  params->history_item = item;
  params->navigation_timings.navigation_start = base::TimeTicks::Now();
  params->navigation_timings.fetch_start = base::TimeTicks::Now();
  FillNavigationParamsResponse(params.get());
  impl->CommitNavigation(std::move(params), nullptr /* extra_data */);
  PumpPendingRequestsForFrameToLoad(frame);
}

void ReloadFrame(WebLocalFrame* frame) {
  frame->StartReload(WebFrameLoadType::kReload);
  PumpPendingRequestsForFrameToLoad(frame);
}

void ReloadFrameBypassingCache(WebLocalFrame* frame) {
  frame->StartReload(WebFrameLoadType::kReloadBypassingCache);
  PumpPendingRequestsForFrameToLoad(frame);
}

void PumpPendingRequestsForFrameToLoad(WebLocalFrame* frame) {
  base::RunLoop loop;
  scoped_refptr<base::TaskRunner> task_runner =
      frame->GetTaskRunner(blink::TaskType::kInternalTest);
  task_runner->PostTask(FROM_HERE,
                        WTF::BindOnce(&RunServeAsyncRequestsTask, task_runner,
                                      loop.QuitClosure()));
  loop.Run();
}

void FillNavigationParamsResponse(WebNavigationParams* params) {
  KURL kurl(params->url);
  // Empty documents and srcdoc will be handled by DocumentLoader.
  if (DocumentLoader::WillLoadUrlAsEmpty(kurl) || kurl.IsAboutSrcdocURL())
    return;
  URLLoaderMockFactory::GetSingletonInstance()->FillNavigationParamsResponse(
      params);

  // Parse Content Security Policy response headers into the policy container,
  // simulating what the browser does.
  for (auto& csp : ParseContentSecurityPolicies(
           params->response.HttpHeaderField("Content-Security-Policy"),
           network::mojom::blink::ContentSecurityPolicyType::kEnforce,
           network::mojom::blink::ContentSecurityPolicySource::kHTTP,
           params->response.ResponseUrl())) {
    params->policy_container->policies.sandbox_flags |= csp->sandbox;
    params->policy_container->policies.content_security_policies.emplace_back(
        ConvertToPublic(std::move(csp)));
  }
}

WebMouseEvent CreateMouseEvent(WebInputEvent::Type type,
                               WebMouseEvent::Button button,
                               const gfx::Point& point,
                               int modifiers) {
  WebMouseEvent result(type, modifiers,
                       WebInputEvent::GetStaticTimeStampForTests());
  result.pointer_type = WebPointerProperties::PointerType::kMouse;
  result.SetPositionInWidget(point.x(), point.y());
  result.SetPositionInScreen(point.x(), point.y());
  result.button = button;
  result.click_count = 1;
  return result;
}

WebLocalFrameImpl* CreateLocalChild(
    WebLocalFrame& parent,
    mojom::blink::TreeScopeType scope,
    TestWebFrameClient* client,
    WebPolicyContainerBindParams policy_container_bind_params,
    WebLocalFrameClient::FinishChildFrameCreationFn finish_creation) {
  MockPolicyContainerHost mock_policy_container_host;
  mock_policy_container_host.BindWithNewEndpoint(
      std::move(policy_container_bind_params.receiver));
  std::unique_ptr<TestWebFrameClient> owned_client;
  client = CreateDefaultClientIfNeeded(client, owned_client);
  auto* frame = To<WebLocalFrameImpl>(
      parent.CreateLocalChild(scope, client, nullptr, LocalFrameToken()));
  client->Bind(frame, std::move(owned_client));
  finish_creation(frame, DocumentToken(), mojo::NullRemote());
  return frame;
}

WebLocalFrameImpl* CreateLocalChild(
    WebLocalFrame& parent,
    mojom::blink::TreeScopeType scope,
    std::unique_ptr<TestWebFrameClient> self_owned,
    WebPolicyContainerBindParams policy_container_bind_params,
    WebLocalFrameClient::FinishChildFrameCreationFn finish_creation) {
  MockPolicyContainerHost mock_policy_container_host;
  mock_policy_container_host.BindWithNewEndpoint(
      std::move(policy_container_bind_params.receiver));
  DCHECK(self_owned);
  TestWebFrameClient* client = self_owned.get();
  auto* frame = To<WebLocalFrameImpl>(
      parent.CreateLocalChild(scope, client, nullptr, LocalFrameToken()));
  client->Bind(frame, std::move(self_owned));
  finish_creation(frame, DocumentToken(), mojo::NullRemote());
  return frame;
}

WebRemoteFrameImpl* CreateRemote() {
  auto* frame = MakeGarbageCollected<WebRemoteFrameImpl>(
      mojom::blink::TreeScopeType::kDocument, RemoteFrameToken());
  return frame;
}

WebRemoteFrameImpl* CreateRemoteChild(
    WebRemoteFrame& parent,
    const WebString& name,
    scoped_refptr<SecurityOrigin> security_origin) {
  mojom::blink::FrameReplicationStatePtr replicated_state =
      mojom::blink::FrameReplicationState::New();
  replicated_state->name = name;
  if (!security_origin)
    security_origin = SecurityOrigin::CreateUniqueOpaque();
  replicated_state->origin = std::move(security_origin);

  auto* frame = To<WebRemoteFrameImpl>(parent).CreateRemoteChild(
      mojom::blink::TreeScopeType::kDocument, RemoteFrameToken(),
      /*is_loading=*/false,
      /*devtools_frame_token=*/base::UnguessableToken(),
      /*opener=*/nullptr,
      CreateStubRemoteIfNeeded<mojom::blink::RemoteFrameHost>(
          mojo::NullAssociatedRemote()),
      mojo::AssociatedRemote<mojom::blink::RemoteFrame>()
          .BindNewEndpointAndPassDedicatedReceiver(),
      std::move(replicated_state), mojom::blink::FrameOwnerProperties::New());
  return frame;
}

void SwapRemoteFrame(
    WebFrame* old_frame,
    WebRemoteFrame* new_remote_frame,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost> frame_host) {
  mojom::FrameReplicationStatePtr replicated_state =
      mojom::FrameReplicationState::New();
  // Preserve the frame's name on swap.
  replicated_state->name =
      WebFrame::ToCoreFrame(*old_frame)->Tree().GetName().Utf8();

  old_frame->Swap(new_remote_frame,
                  CreateStubRemoteIfNeeded<mojom::blink::RemoteFrameHost>(
                      std::move(frame_host)),
                  mojo::AssociatedRemote<mojom::blink::RemoteFrame>()
                      .BindNewEndpointAndPassDedicatedReceiver(),
                  std::move(replicated_state));
}

WebViewHelper::WebViewHelper(
    CreateTestWebFrameWidgetCallback create_web_frame_callback)
    : web_view_(nullptr),
      agent_group_scheduler_(
          std::make_unique<blink::scheduler::WebAgentGroupScheduler>(
              ThreadScheduler::Current()
                  ->ToMainThreadScheduler()
                  ->CreateAgentGroupScheduler())),
      platform_(Platform::Current()) {
  DocumentLoader::DisableCodeCacheForTesting();
  CreateTestWebFrameWidgetCallback create_callback =
      std::move(create_web_frame_callback);
  if (!create_callback) {
    create_callback =
        WTF::BindRepeating(&WebViewHelper::CreateTestWebFrameWidget<>);
  }
  // Due to return type differences we need to bind the RepeatingCallback
  // in a wrapper.
  create_widget_callback_wrapper_ = WTF::BindRepeating(
      [](const CreateTestWebFrameWidgetCallback& create_test_web_widget,
         base::PassKey<WebLocalFrame> pass_key,
         CrossVariantMojoAssociatedRemote<
             mojom::blink::FrameWidgetHostInterfaceBase> frame_widget_host,
         CrossVariantMojoAssociatedReceiver<
             mojom::blink::FrameWidgetInterfaceBase> frame_widget,
         CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
             widget_host,
         CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
             widget,
         scoped_refptr<base::SingleThreadTaskRunner> task_runner,
         const viz::FrameSinkId& frame_sink_id, bool hidden,
         bool never_composited, bool is_for_child_local_root,
         bool is_for_nested_main_frame,
         bool is_for_scalable_page) -> WebFrameWidget* {
        return create_test_web_widget.Run(
            std::move(pass_key), std::move(frame_widget_host),
            std::move(frame_widget), std::move(widget_host), std::move(widget),
            std::move(task_runner), frame_sink_id, hidden, never_composited,
            is_for_child_local_root, is_for_nested_main_frame,
            is_for_scalable_page);
      },
      std::move(create_callback));
}

WebViewHelper::~WebViewHelper() {
  // Close the WebViewImpl before the WebViewClient is destroyed.
  Reset();
}

WebViewImpl* WebViewHelper::InitializeWithOpener(
    WebFrame* opener,
    TestWebFrameClient* web_frame_client,
    WebViewClient* web_view_client,
    void (*update_settings_func)(WebSettings*),
    std::optional<blink::FencedFrame::DeprecatedFencedFrameMode>
        fenced_frame_mode,
    bool is_prerendering) {
  Reset();

  InitializeWebView(web_view_client, opener ? opener->View() : nullptr,
                    fenced_frame_mode, is_prerendering);
  if (update_settings_func)
    update_settings_func(web_view_->GetSettings());

  std::unique_ptr<TestWebFrameClient> owned_web_frame_client;
  web_frame_client =
      CreateDefaultClientIfNeeded(web_frame_client, owned_web_frame_client);
  WebLocalFrame* frame = WebLocalFrame::CreateMainFrame(
      web_view_, web_frame_client, nullptr, mojo::NullRemote(),
      LocalFrameToken(), DocumentToken(),
      // Passing a null policy_container will create an empty, default policy
      // container.
      /*policy_container=*/nullptr, opener,
      /*name=*/WebString(),
      fenced_frame_mode ? kFencedFrameForcedSandboxFlags
                        : network::mojom::WebSandboxFlags::kNone);
  web_frame_client->Bind(frame, std::move(owned_web_frame_client));

  TestWebFrameWidget* frame_widget =
      CreateFrameWidgetAndInitializeCompositing(frame);

  // We inform the WebView when it has a local main frame attached once the
  // WebFrame is fully set up and the WebFrameWidget is initialized (which is
  // the case by this point).
  web_view_->DidAttachLocalMainFrame();

  // Set an initial size for subframes.
  if (frame->Parent())
    frame_widget->Resize(gfx::Size());
  return web_view_;
}

WebViewImpl* WebViewHelper::Initialize(
    TestWebFrameClient* web_frame_client,
    WebViewClient* web_view_client,
    void (*update_settings_func)(WebSettings*)) {
  return InitializeWithOpener(nullptr, web_frame_client, web_view_client,
                              update_settings_func);
}

WebViewImpl* WebViewHelper::InitializeWithSettings(
    void (*update_settings_func)(WebSettings*)) {
  return InitializeWithOpener(nullptr, nullptr, nullptr, update_settings_func);
}

// static
void WebViewHelper::UpdateAndroidCompositingSettings(WebSettings* settings) {
  settings->SetLCDTextPreference(LCDTextPreference::kIgnored);
  settings->SetViewportMetaEnabled(true);
  settings->SetViewportEnabled(true);
  settings->SetMainFrameResizesAreOrientationChanges(true);
  settings->SetShrinksViewportContentToFit(true);
}

WebViewImpl* WebViewHelper::InitializeAndLoad(
    const std::string& url,
    TestWebFrameClient* web_frame_client,
    WebViewClient* web_view_client,
    void (*update_settings_func)(WebSettings*)) {
  DocumentLoader::DisableCodeCacheForTesting();
  Initialize(web_frame_client, web_view_client, update_settings_func);

  LoadFrame(GetWebView()->MainFrameImpl(), url);

  return GetWebView();
}

WebViewImpl* WebViewHelper::InitializePlaceholderRemote() {
  return InitializeRemoteWithOpenerAndAssociatedRemoteAndReceivers(
      nullptr, nullptr, nullptr, mojo::NullAssociatedRemote(),
      mojo::NullAssociatedReceiver());
}

WebViewImpl* WebViewHelper::InitializeRemote(
    scoped_refptr<SecurityOrigin> security_origin,
    WebViewClient* web_view_client) {
  return InitializeRemoteWithOpener(nullptr, security_origin, web_view_client);
}

WebViewImpl* WebViewHelper::InitializeRemoteWithOpener(
    WebFrame* opener,
    scoped_refptr<SecurityOrigin> security_origin,
    WebViewClient* web_view_client) {
  return InitializeRemoteWithOpenerAndAssociatedRemoteAndReceivers(
      opener, security_origin, web_view_client,
      CreateStubRemoteIfNeeded<mojom::blink::RemoteFrameHost>(
          mojo::NullAssociatedRemote()),
      mojo::AssociatedRemote<mojom::blink::RemoteFrame>()
          .BindNewEndpointAndPassDedicatedReceiver());
}

WebViewImpl*
WebViewHelper::InitializeRemoteWithOpenerAndAssociatedRemoteAndReceivers(
    WebFrame* opener,
    scoped_refptr<SecurityOrigin> security_origin,
    WebViewClient* web_view_client,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
        remote_frame_host,
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame> receiver) {
  Reset();

  InitializeWebView(web_view_client, /*opener=*/nullptr,
                    /*fenced_frame_mode=*/std::nullopt,
                    /*is_prerendering=*/false);

  if (!security_origin)
    security_origin = SecurityOrigin::CreateUniqueOpaque();
  auto replication_state = mojom::blink::FrameReplicationState::New();
  replication_state->origin = security_origin;

  WebRemoteFrameImpl::CreateMainFrame(
      web_view_, RemoteFrameToken(), /*is_loading=*/false,
      /*devtools_frame_token=*/base::UnguessableToken(), opener,
      std::move(remote_frame_host), std::move(receiver),
      std::move(replication_state));
  return web_view_;
}

void WebViewHelper::CheckFrameIsAssociatedWithWebView(WebFrame* frame) {
  // Find the main frame and assert that it is the same.
  while (frame->Parent()) {
    frame = frame->Parent();
  }
  CHECK_EQ(web_view_->MainFrame(), frame);
}

WebLocalFrameImpl* WebViewHelper::CreateLocalChild(
    WebRemoteFrame& parent,
    const WebString& name,
    const WebFrameOwnerProperties& properties,
    WebFrame* previous_sibling,
    TestWebFrameClient* client) {
  CheckFrameIsAssociatedWithWebView(&parent);
  std::unique_ptr<TestWebFrameClient> owned_client;
  client = CreateDefaultClientIfNeeded(client, owned_client);
  MockPolicyContainerHost mock_policy_container_host;
  auto* frame = To<WebLocalFrameImpl>(parent.CreateLocalChild(
      mojom::blink::TreeScopeType::kDocument, name, FramePolicy(), client,
      nullptr, previous_sibling, properties, LocalFrameToken(), nullptr,
      DocumentToken(), mojo::NullRemote(),
      std::make_unique<WebPolicyContainer>(
          WebPolicyContainerPolicies(),
          mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote())));
  client->Bind(frame, std::move(owned_client));

  TestWebFrameWidget* frame_widget =
      CreateFrameWidgetAndInitializeCompositing(frame);
  // Set an initial size for subframes.
  frame_widget->Resize(gfx::Size());
  return frame;
}

WebLocalFrameImpl* WebViewHelper::CreateProvisional(
    WebFrame& old_frame,
    TestWebFrameClient* client) {
  CheckFrameIsAssociatedWithWebView(&old_frame);
  std::unique_ptr<TestWebFrameClient> owned_client;
  client = CreateDefaultClientIfNeeded(client, owned_client);
  auto* frame = To<WebLocalFrameImpl>(WebLocalFrame::CreateProvisional(
      client, nullptr, mojo::NullRemote(), LocalFrameToken(), &old_frame,
      FramePolicy(), WebFrame::ToCoreFrame(old_frame)->Tree().GetName(),
      old_frame.View()));
  client->Bind(frame, std::move(owned_client));

  // Create a widget, if necessary.
  if (!frame->Parent() || frame->Parent()->IsWebRemoteFrame()) {
    TestWebFrameWidget* frame_widget =
        CreateFrameWidgetAndInitializeCompositing(frame);
    // Set an initial size for subframes.
    if (frame->Parent())
      frame_widget->Resize(gfx::Size());
  }
  return frame;
}

TestWebFrameWidget* WebViewHelper::CreateFrameWidget(WebLocalFrame* frame) {
  ScopedCreateWebFrameWidget create_hook(&create_widget_callback_wrapper_);
  mojo::AssociatedRemote<mojom::blink::FrameWidget> frame_widget_remote;
  mojo::PendingAssociatedReceiver<mojom::blink::FrameWidget>
      frame_widget_receiver =
          frame_widget_remote.BindNewEndpointAndPassDedicatedReceiver();

  mojo::AssociatedRemote<mojom::blink::FrameWidgetHost> frame_widget_host;
  mojo::PendingAssociatedReceiver<mojom::blink::FrameWidgetHost>
      frame_widget_host_receiver =
          frame_widget_host.BindNewEndpointAndPassDedicatedReceiver();

  mojo::AssociatedRemote<mojom::blink::Widget> widget_remote;
  mojo::PendingAssociatedReceiver<mojom::blink::Widget> widget_receiver =
      widget_remote.BindNewEndpointAndPassDedicatedReceiver();

  mojo::AssociatedRemote<mojom::blink::WidgetHost> widget_host;
  mojo::PendingAssociatedReceiver<mojom::blink::WidgetHost>
      widget_host_receiver =
          widget_host.BindNewEndpointAndPassDedicatedReceiver();

  auto* frame_widget =
      static_cast<TestWebFrameWidget*>(frame->InitializeFrameWidget(
          frame_widget_host.Unbind(), std::move(frame_widget_receiver),
          widget_host.Unbind(), std::move(widget_receiver),
          AllocateFrameSinkId()));
  frame_widget->BindWidgetChannels(std::move(widget_remote),
                                   std::move(widget_host_receiver),
                                   std::move(frame_widget_host_receiver));
  return frame_widget;
}

TestWebFrameWidget* WebViewHelper::CreateFrameWidgetAndInitializeCompositing(
    WebLocalFrame* frame) {
  TestWebFrameWidget* frame_widget = CreateFrameWidget(frame);
  // The WebWidget requires the compositor to be set before it is used.
  cc::LayerTreeSettings layer_tree_settings =
      GetSynchronousSingleThreadLayerTreeSettings();
  display::ScreenInfos initial_screen_infos(
      frame_widget->GetInitialScreenInfo());
  frame_widget->InitializeCompositing(initial_screen_infos,
                                      &layer_tree_settings);
  // This runs WidgetInputHandlerManager::InitOnInputHandlingThread, which will
  // set up the InputHandlerProxy.
  frame_widget->FlushInputHandlerTasks();

  frame_widget->SetCompositorVisible(true);
  return frame_widget;
}

void WebViewHelper::LoadAhem() {
  LocalFrame* local_frame =
      To<LocalFrame>(WebFrame::ToCoreFrame(*LocalMainFrame()));
  DCHECK(local_frame);
  RenderingTest::LoadAhem(*local_frame);
}

void WebViewHelper::Reset() {
  DCHECK_EQ(platform_, Platform::Current())
      << "Platform::Current() should be the same for the life of a test, "
         "including shutdown.";

  if (web_view_) {
    // Prune opened windows before this helper resets.
    if (auto* local_main_frame =
            DynamicTo<WebLocalFrameImpl>(web_view_->MainFrame())) {
      static_cast<TestWebFrameClient*>(local_main_frame->Client())
          ->DestroyChildViews();
    }

    DCHECK(!TestWebFrameClient::IsLoading());
    web_view_->Close();
    web_view_ = nullptr;
  }
}

cc::LayerTreeHost* WebViewHelper::GetLayerTreeHost() const {
  return GetMainFrameWidget()->LayerTreeHostForTesting();
}

WebLocalFrameImpl* WebViewHelper::LocalMainFrame() const {
  return To<WebLocalFrameImpl>(web_view_->MainFrame());
}

WebRemoteFrameImpl* WebViewHelper::RemoteMainFrame() const {
  return To<WebRemoteFrameImpl>(web_view_->MainFrame());
}

TestWebFrameWidget* WebViewHelper::GetMainFrameWidget() const {
  return static_cast<TestWebFrameWidget*>(LocalMainFrame()->FrameWidgetImpl());
}

void WebViewHelper::Resize(const gfx::Size& size) {
  // In addition to calling WebFrameWidgetImpl::Resize(), this updates the
  // LayerTreeHost::device_viewport_rect(), which is used to set up the
  // compositor's clip tree.  (In a real browser this would happen through
  // Widget.UpdateVisualProperties).
  GetMainFrameWidget()->SetWindowRectSynchronouslyForTesting(gfx::Rect(size));
}

void WebViewHelper::InitializeWebView(
    WebViewClient* web_view_client,
    class WebView* opener,
    std::optional<blink::FencedFrame::DeprecatedFencedFrameMode>
        fenced_frame_mode,
    bool is_prerendering) {
  auto browsing_context_group_info = BrowsingContextGroupInfo::CreateUnique();
  if (opener) {
    WebViewImpl* opener_impl = To<WebViewImpl>(opener);
    browsing_context_group_info.browsing_context_group_token =
        opener_impl->GetPage()->BrowsingContextGroupToken();
  }
  web_view_client =
      CreateDefaultClientIfNeeded(web_view_client, owned_web_view_client_);
  blink::mojom::PrerenderParamPtr prerender_param = nullptr;
  if (is_prerendering) {
    prerender_param = blink::mojom::PrerenderParam::New();
    prerender_param->page_metric_suffix = "for_testing";
    prerender_param->should_prepare_paint_tree = true;
  }

  web_view_ = To<WebViewImpl>(
      WebView::Create(web_view_client,
                      /*is_hidden=*/is_prerendering, std::move(prerender_param),
                      /*fenced_frame_mode=*/fenced_frame_mode,
                      /*compositing_enabled=*/true,
                      /*widgets_never_composited=*/false,
                      /*opener=*/opener, mojo::NullAssociatedReceiver(),
                      *agent_group_scheduler_,
                      /*session_storage_namespace_id=*/std::string(),
                      /*page_base_background_color=*/std::nullopt,
                      std::move(browsing_context_group_info),
                      /*color_provider_colors=*/nullptr,
                      /*partitioned_popin_params=*/nullptr));
  // This property must be set at initialization time, it is not supported to be
  // changed afterward, and does nothing.
  web_view_->GetSettings()->SetViewportEnabled(viewport_enabled_);
  web_view_->GetSettings()->SetJavaScriptEnabled(true);
  web_view_->GetSettings()->SetPluginsEn
```