Response:
The user wants a summary of the functionalities provided by the code snippet from `frame_test_helpers.cc`. Specifically, I need to identify the purpose of the classes and methods within this file. I also need to highlight any connections to web technologies like JavaScript, HTML, and CSS, providing illustrative examples if such connections exist. Furthermore, I should analyze any logical inferences made within the code, along with their assumed inputs and outputs. Finally, I need to pinpoint any common usage errors that might arise from using this code.

Based on the class names and method signatures, the core functionalities seem to revolve around:

1. **WebView setup and management:** Creating and initializing `WebViewImpl` instances for testing purposes.
2. **Frame client implementation:** Providing a mock implementation (`TestWebFrameClient`) for `WebLocalFrame` interactions, simulating frame lifecycle events, navigation, and resource loading.
3. **Widget handling:** Offering a test implementation (`TestWebFrameWidget`) for `Widget` related functionalities like input handling, rendering, and compositing.
4. **Widget host interaction:** Defining a mock implementation (`TestWebFrameWidgetHost`) for interactions between the widget and its host, covering aspects like cursor management, tooltips, and input events.
5. **Input handling infrastructure:** Providing a test double (`TestWidgetInputHandlerHost`) for managing input events.

Let's break down each part of the code and analyze its contributions to these functionalities.
这是`blink/renderer/core/frame/frame_test_helpers.cc`文件的第二部分，延续了第一部分的功能，主要提供了用于测试`WebFrame`及其相关组件的辅助类和方法。

**归纳其功能如下：**

* **`TestWebFrameClient` 类 (延续第一部分):**
    * **模拟 Frame 的生命周期事件:**  `FrameDetached` 方法模拟 Frame 被分离时的处理，包括运行回调函数和关闭 Frame。
    * **创建子 Frame:** `CreateChildFrame` 方法允许在测试中创建子 Frame，并可以设置子 Frame 的沙盒标志。
    * **模拟加载状态:** `DidStartLoading` 和 `DidStopLoading` 用于跟踪模拟的页面加载进度。
    * **模拟 Frame 交换:** `SwapIn` 方法模拟将一个新的 Frame 替换到当前位置的操作。
    * **创建测试用的 URLLoader:** `CreateURLLoaderForTesting` 使用 `URLLoaderMockFactory` 创建一个用于测试的 URLLoader。这对于模拟网络请求和响应至关重要。
    * **模拟导航:** `BeginNavigation` 和 `CommitNavigation` 方法模拟导航流程，包括处理 `about:srcdoc` 类型的 URL 和填充导航参数。
    * **获取网络连接类型:** `GetEffectiveConnectionType` 和 `SetEffectiveConnectionTypeForTesting` 用于模拟和设置网络连接类型，这可能会影响页面的行为。
    * **捕获控制台消息:** `DidAddMessageToConsole` 方法捕获并存储发送到控制台的消息，方便测试断言。
    * **创建测试插件:** `CreatePlugin` 方法创建一个用于测试的 `FakeWebPlugin`。
    * **获取远程导航接口:** `GetRemoteNavigationAssociatedInterfaces` 返回一个用于处理远程导航的接口提供者。
    * **跟踪有意义的布局事件:** `DidMeaningfulLayout` 记录页面完成不同阶段布局的次数，例如首次绘制、完成解析和完成加载。
    * **创建新窗口:** `CreateNewWindow` 方法模拟通过当前 Frame 创建新窗口的行为，返回一个新的 `WebView` 实例。
    * **销毁子 WebView:** `DestroyChildViews` 用于清理测试中创建的子 WebView。
    * **设置 Frame 分离回调:** `SetFrameDetachedCallback` 允许设置在 Frame 分离时执行的回调函数。

* **`TestWebFrameWidget` 类 (延续第一部分):**
    * **获取和管理输入处理:** `GetInputHandlerHost` 和 `GetWidgetInputHandlerManager` 提供访问和管理输入事件处理器的能力。
    * **刷新输入处理任务:** `FlushInputHandlerTasks` 确保所有待处理的输入事件都被处理。
    * **通过合成器分发输入事件:** `DispatchThroughCcInputHandler` 将输入事件发送到合成器进行处理，并能捕获潜在的滚动溢出信息。
    * **获取和设置初始屏幕信息:** `GetInitialScreenInfo` 和 `SetInitialScreenInfo` 用于模拟和设置窗口的初始屏幕信息。
    * **获取最后创建的 FrameSink:** `LastCreatedFrameSink` 返回最后创建的 `FakeLayerTreeFrameSink`，用于测试渲染流程。
    * **创建 WidgetHost:** `CreateWidgetHost` 创建一个 `TestWebFrameWidgetHost` 的实例。
    * **绑定 Widget 通道:** `BindWidgetChannels` 建立 `Widget` 和 `WidgetHost` 之间的 Mojo 通信通道。
    * **检查是否有滚动事件处理程序:** `HaveScrollEventHandlers` 查询是否有注册滚动事件的处理程序。
    * **分配新的 LayerTreeFrameSink:** `AllocateNewLayerTreeFrameSink` 创建一个新的用于渲染的 Frame Sink。
    * **记录注入的滚动事件:** `WillQueueSyntheticEvent` 记录由测试注入的合成滚动事件。

* **`TestWebFrameWidgetHost` 类:**
    * **模拟光标设置:** `SetCursor` 记录光标被设置的次数。
    * **处理工具提示:**  `UpdateTooltipUnderCursor`, `UpdateTooltipFromKeyboard`, `ClearKeyboardTriggeredTooltip`  模拟工具提示的显示和清除。
    * **处理文本输入状态变化:** `TextInputStateChanged` 监测文本输入状态的变化，例如是否需要显示虚拟键盘。
    * **处理选区边界变化:** `SelectionBoundsChanged` 模拟选区边界的改变。
    * **创建 FrameSink:** `CreateFrameSink`  用于模拟创建合成器 Frame Sink 的过程。
    * **注册渲染 Frame 元数据观察者:** `RegisterRenderFrameMetadataObserver` 模拟注册观察者以接收渲染 Frame 的元数据。
    * **模拟双击缩放和查找结果缩放:** `AnimateDoubleTapZoomInMainFrame` 和 `ZoomToFindInPageRectInMainFrame` 模拟特定的缩放行为。
    * **设置触摸事件消费者:** `SetHasTouchEventConsumers` 用于设置哪些 Frame 消费触摸事件。
    * **处理固有尺寸信息变化:** `IntrinsicSizingInfoChanged` 模拟接收固有尺寸信息的变化。
    * **模拟自动滚动:** `AutoscrollStart`, `AutoscrollFling`, `AutoscrollEnd` 模拟自动滚动的开始、持续和结束。
    * **绑定 WidgetHost 接口:** `BindWidgetHost` 建立与 `Widget` 的通信连接。
    * **绑定渲染输入路由接口:** `BindRenderInputRouterInterfaces` 建立与渲染输入路由器的连接。
    * **获取 WidgetInputHandler:** `GetWidgetInputHandler` 获取用于处理输入事件的接口。

* **`TestWidgetInputHandlerHost` 类:**
    * **绑定新的远程接口:** `BindNewRemote` 用于创建一个新的 `WidgetInputHandlerHost` 远程接口。
    * **设置触摸动作:** `SetTouchActionFromMain` 设置主线程发送的触摸动作。
    * **设置平移动作:** `SetPanAction` 设置平移动作。
    * **处理滚动溢出:** `DidOverscroll` 接收并处理滚动溢出参数。
    * **处理视口滚动开始:** `DidStartScrollingViewport` 记录视口滚动开始的事件。
    * **取消 IME 组合:** `ImeCancelComposition` 模拟取消输入法组合。
    * **处理 IME 组合范围变化:** `ImeCompositionRangeChanged` 接收和处理输入法组合范围的变化。
    * **设置鼠标捕获:** `SetMouseCapture` 模拟设置鼠标捕获状态。
    * **设置自动滚动选区激活状态:** `SetAutoscrollSelectionActiveInMainFrame` 用于设置自动滚动选区是否激活。
    * **请求鼠标锁定:** `RequestMouseLock` 模拟请求鼠标锁定。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    * `DidAddMessageToConsole`:  当 JavaScript 代码中使用 `console.log()` 等方法时，`TestWebFrameClient` 可以捕获这些消息，用于验证 JavaScript 代码的执行结果。
        * **假设输入:** JavaScript 代码执行 `console.log("Hello, world!");`
        * **预期输出:** `console_messages_` 列表中包含 `"Hello, world!"`。
    * `CreateNewWindow`:  模拟 JavaScript 代码中使用 `window.open()` 创建新窗口的行为。
        * **假设输入:** JavaScript 代码执行 `window.open("https://example.com", "_blank");`
        * **预期输出:** `TestWebFrameClient` 的 `child_web_views_` 列表中会添加一个新的 `WebViewHelper` 对象。
    * `DispatchThroughCcInputHandler`: 可以用于测试 JavaScript 注册的事件监听器对特定输入事件（如鼠标点击、滚动）的响应。
        * **假设输入:**  JavaScript 代码注册了一个滚动事件监听器。`TestWebFrameWidget` 模拟发送一个滚动事件。
        * **预期输出:** 如果 JavaScript 代码阻止了默认滚动行为，可能会在 `last_overscroll_` 中记录到滚动溢出信息。

* **HTML:**
    * `CreateChildFrame`:  模拟解析包含 `<iframe>` 标签的 HTML 代码并创建相应的子 Frame。
        * **假设输入:** HTML 代码包含 `<iframe src="child.html"></iframe>`。
        * **预期输出:** `TestWebFrameClient` 的 `CreateChildFrame` 方法会被调用，创建一个新的 `TestWebFrameClient` 来模拟子 Frame。
    * `DidMeaningfulLayout`:  可以用来测试 HTML 结构和资源加载完成后触发的布局事件。
        * **假设输入:**  一个包含图片和文本的简单 HTML 页面被加载。
        * **预期输出:**  `finished_parsing_layout_count_` 和 `finished_loading_layout_count_` 会递增。

* **CSS:**
    * `DidMeaningfulLayout (kVisuallyNonEmpty)`:  CSS 样式会影响页面的渲染结果，`kVisuallyNonEmpty` 事件表明页面至少渲染了一些内容。
        * **假设输入:**  HTML 页面包含一些带有背景色和文本的元素，通过 CSS 设置了样式。
        * **预期输出:** 当页面首次渲染出可见内容时，`visually_non_empty_layout_count_` 会递增。
    * `SetCursor`:  模拟 CSS 样式中 `cursor` 属性的应用。
        * **假设输入:**  CSS 样式设置了鼠标悬停在某个元素上时显示特定的光标，例如 `cursor: pointer;`。
        * **预期输出:** 当模拟鼠标悬停在该元素上时，`TestWebFrameWidgetHost` 的 `cursor_set_count_` 会递增。

**用户或编程常见的使用错误举例说明:**

* **未模拟网络请求导致测试失败:** `WebViewHelper` 启用了图片自动加载，并期望所有外部图片资源都被 mock。如果在测试中加载了未被 mock 的图片，测试可能会因为资源加载挂起而失败。
    * **错误示例:** 测试 HTML 中包含 `<img src="https://example.com/image.png">`，但没有使用 `URLLoaderMockFactory` 提供对该 URL 的模拟响应。
    * **后果:** 测试在关闭时可能会报告资源泄漏或超时。

* **忘记处理异步操作:**  `BeginNavigation` 使用 `PostTask` 将导航提交到加载线程。如果测试期望导航立即完成，可能会因为异步操作尚未执行而产生错误。
    * **错误示例:** 在调用 `BeginNavigation` 后立即断言 Frame 的 URL，而没有等待导航完成。
    * **后果:** 断言可能会失败，因为 Frame 的 URL 尚未更新。

* **不正确的输入事件模拟:** 使用 `DispatchThroughCcInputHandler` 时，如果提供的 `WebInputEvent` 参数不正确或不完整，可能会导致合成器无法正确处理事件，从而导致测试结果不符合预期。
    * **错误示例:**  模拟触摸事件时，缺少必要的触摸点信息。
    * **后果:**  与触摸事件相关的测试逻辑可能无法正常触发。

总而言之，`frame_test_helpers.cc` 的第二部分继续提供了构建可靠的 Blink 渲染引擎 Frame 组件单元测试的基础设施，涵盖了 Frame 的生命周期、导航、渲染、输入处理以及与其他 Web 技术交互的各个方面。 通过使用这些辅助类，开发者可以编写出更加全面和精确的测试用例。

Prompt: 
```
这是目录为blink/renderer/core/frame/frame_test_helpers.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
abled(true);
  // Enable (mocked) network loads of image URLs, as this simplifies
  // the completion of resource loads upon test shutdown & helps avoid
  // dormant loads trigger Resource leaks for image loads.
  //
  // Consequently, all external image resources must be mocked.
  web_view_->GetSettings()->SetLoadsImagesAutomatically(true);

  // Color providers are required for painting, so we ensure they are not null
  // even in unittests.
  web_view_->GetPage()->UpdateColorProvidersForTest();

  // If a test turned off this settings, opened WebViews should propagate that.
  if (opener) {
    web_view_->GetSettings()->SetAllowUniversalAccessFromFileURLs(
        To<WebViewImpl>(opener)
            ->GetPage()
            ->GetSettings()
            .GetAllowUniversalAccessFromFileURLs());
  }

  web_view_->SetDefaultPageScaleLimits(1, 4);
}

WebViewImpl* WebViewHelper::CreateWebView(WebViewClient* web_view_client,
                                          bool compositing_enabled) {
  return To<WebViewImpl>(
      WebView::Create(web_view_client,
                      /*is_hidden=*/false,
                      /*prerender_param=*/nullptr,
                      /*fenced_frame_mode=*/std::nullopt, compositing_enabled,
                      /*widgets_never_composited=*/false,
                      /*opener=*/nullptr, mojo::NullAssociatedReceiver(),
                      *agent_group_scheduler_,
                      /*session_storage_namespace_id=*/std::string(),
                      /*page_base_background_color=*/std::nullopt,
                      BrowsingContextGroupInfo::CreateUnique(),
                      /*color_provider_colors=*/nullptr,
                      /*partitioned_popin_params=*/nullptr));
}

int TestWebFrameClient::loads_in_progress_ = 0;

TestWebFrameClient::TestWebFrameClient()
    : associated_interface_provider_(new AssociatedInterfaceProvider(nullptr)),
      effective_connection_type_(WebEffectiveConnectionType::kTypeUnknown) {}

TestWebFrameClient::~TestWebFrameClient() = default;

void TestWebFrameClient::Bind(WebLocalFrame* frame,
                              std::unique_ptr<TestWebFrameClient> self_owned) {
  DCHECK(!frame_);
  DCHECK(!self_owned || self_owned.get() == this);
  frame_ = To<WebLocalFrameImpl>(frame);
  self_owned_ = std::move(self_owned);
}

void TestWebFrameClient::FrameDetached(DetachReason detach_reason) {
  std::move(frame_detached_callback_).Run();
  frame_->Close(detach_reason);
  self_owned_.reset();
}

WebLocalFrame* TestWebFrameClient::CreateChildFrame(
    mojom::blink::TreeScopeType scope,
    const WebString& name,
    const WebString& fallback_name,
    const FramePolicy& frame_policy,
    const WebFrameOwnerProperties&,
    FrameOwnerElementType,
    WebPolicyContainerBindParams policy_container_bind_params,
    ukm::SourceId document_ukm_source_id,
    FinishChildFrameCreationFn finish_creation) {
  MockPolicyContainerHost mock_policy_container_host;
  mock_policy_container_host.BindWithNewEndpoint(
      std::move(policy_container_bind_params.receiver));
  auto client = std::make_unique<TestWebFrameClient>();
  auto* frame = To<WebLocalFrameImpl>(frame_->CreateLocalChild(
      scope, client.get(), nullptr, LocalFrameToken()));
  client->sandbox_flags_ = frame_policy.sandbox_flags;
  TestWebFrameClient* client_ptr = client.get();
  client_ptr->Bind(frame, std::move(client));
  finish_creation(frame, DocumentToken(), mojo::NullRemote());
  return frame;
}

void TestWebFrameClient::DidStartLoading() {
  ++loads_in_progress_;
}

void TestWebFrameClient::DidStopLoading() {
  DCHECK_GT(loads_in_progress_, 0);
  --loads_in_progress_;
}

bool TestWebFrameClient::SwapIn(WebFrame* previous_frame) {
  bool result = previous_frame->Swap(frame_);

  if (!frame_->Parent())
    frame_->View()->DidAttachLocalMainFrame();

  return result;
}

std::unique_ptr<URLLoader> TestWebFrameClient::CreateURLLoaderForTesting() {
  return URLLoaderMockFactory::GetSingletonInstance()->CreateURLLoader();
}

void TestWebFrameClient::BeginNavigation(
    std::unique_ptr<WebNavigationInfo> info) {
  navigation_callback_.Cancel();
  if (DocumentLoader::WillLoadUrlAsEmpty(info->url_request.Url()) &&
      frame_->IsOnInitialEmptyDocument()) {
    CommitNavigation(std::move(info));
    return;
  }

  if (!frame_->WillStartNavigation(*info))
    return;

  navigation_callback_.Reset(
      WTF::BindOnce(&TestWebFrameClient::CommitNavigation,
                    weak_factory_.GetWeakPtr(), std::move(info)));
  frame_->GetTaskRunner(blink::TaskType::kInternalLoading)
      ->PostTask(FROM_HERE, navigation_callback_.callback());
}

void TestWebFrameClient::CommitNavigation(
    std::unique_ptr<WebNavigationInfo> info) {
  if (!frame_)
    return;
  auto params = WebNavigationParams::CreateFromInfo(*info);

  KURL url = info->url_request.Url();
  if (url.IsAboutSrcdocURL()) {
    params->fallback_base_url = info->requestor_base_url;
    TestWebFrameHelper::FillStaticResponseForSrcdocNavigation(frame_,
                                                              params.get());
  }

  MockPolicyContainerHost mock_policy_container_host;
  params->policy_container = std::make_unique<WebPolicyContainer>(
      WebPolicyContainerPolicies(),
      mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
  if (info->archive_status != WebNavigationInfo::ArchiveStatus::Present)
    FillNavigationParamsResponse(params.get());
  // Merge frame policy sandbox flags in the policy container's sandbox flags.
  // This is required since we are initializing policy container above and it
  // must contain the frame's sandbox flags. This is normally done by the
  // browser process during the navigation when computing the policy container
  // and the included sandbox flags to commit, and then passed on within the
  // WebNavigationParams.
  params->policy_container->policies.sandbox_flags |= sandbox_flags();
  frame_->CommitNavigation(std::move(params), nullptr /* extra_data */);
}

WebEffectiveConnectionType TestWebFrameClient::GetEffectiveConnectionType() {
  return effective_connection_type_;
}

void TestWebFrameClient::SetEffectiveConnectionTypeForTesting(
    WebEffectiveConnectionType effective_connection_type) {
  effective_connection_type_ = effective_connection_type;
}

void TestWebFrameClient::DidAddMessageToConsole(
    const WebConsoleMessage& message,
    const WebString& source_name,
    unsigned source_line,
    const WebString& stack_trace) {
  console_messages_.push_back(message.text);
}

WebPlugin* TestWebFrameClient::CreatePlugin(const WebPluginParams& params) {
  return new FakeWebPlugin(params);
}

AssociatedInterfaceProvider*
TestWebFrameClient::GetRemoteNavigationAssociatedInterfaces() {
  return associated_interface_provider_.get();
}

void TestWebFrameClient::DidMeaningfulLayout(
    WebMeaningfulLayout meaningful_layout) {
  switch (meaningful_layout) {
    case WebMeaningfulLayout::kVisuallyNonEmpty:
      visually_non_empty_layout_count_++;
      break;
    case WebMeaningfulLayout::kFinishedParsing:
      finished_parsing_layout_count_++;
      break;
    case WebMeaningfulLayout::kFinishedLoading:
      finished_loading_layout_count_++;
      break;
  }
}

WebView* TestWebFrameClient::CreateNewWindow(
    const WebURLRequest&,
    const WebWindowFeatures&,
    const WebString& name,
    WebNavigationPolicy,
    network::mojom::blink::WebSandboxFlags,
    const SessionStorageNamespaceId&,
    bool& consumed_user_gesture,
    const std::optional<Impression>&,
    const std::optional<WebPictureInPictureWindowOptions>&,
    const WebURL&) {
  auto webview_helper = std::make_unique<WebViewHelper>();
  WebView* result = webview_helper->InitializeWithOpener(frame_);
  child_web_views_.push_back(std::move(webview_helper));
  return result;
}

void TestWebFrameClient::DestroyChildViews() {
  child_web_views_.clear();
}

void TestWebFrameClient::SetFrameDetachedCallback(base::OnceClosure callback) {
  frame_detached_callback_ = std::move(callback);
}

TestWidgetInputHandlerHost* TestWebFrameWidget::GetInputHandlerHost() {
  if (!widget_input_handler_host_)
    widget_input_handler_host_ = std::make_unique<TestWidgetInputHandlerHost>();
  return widget_input_handler_host_.get();
}

WidgetInputHandlerManager* TestWebFrameWidget::GetWidgetInputHandlerManager()
    const {
  return widget_base_for_testing()->widget_input_handler_manager();
}

void TestWebFrameWidget::FlushInputHandlerTasks() {
  base::RunLoop().RunUntilIdle();
}

void TestWebFrameWidget::DispatchThroughCcInputHandler(
    const WebInputEvent& event) {
  GetWidgetInputHandlerManager()->DispatchEvent(
      std::make_unique<WebCoalescedInputEvent>(event.Clone(),
                                               ui::LatencyInfo()),
      WTF::BindOnce(
          [](TestWebFrameWidget* widget, mojom::blink::InputEventResultSource,
             const ui::LatencyInfo&, mojom::blink::InputEventResultState,
             mojom::blink::DidOverscrollParamsPtr overscroll,
             mojom::blink::TouchActionOptionalPtr) {
            if (widget)
              widget->last_overscroll_ = std::move(overscroll);
          },
          WrapWeakPersistent(this)));
  FlushInputHandlerTasks();
}

display::ScreenInfo TestWebFrameWidget::GetInitialScreenInfo() {
  return initial_screen_info_;
}

void TestWebFrameWidget::SetInitialScreenInfo(
    const display::ScreenInfo& screen_info) {
  initial_screen_info_ = screen_info;
}

cc::FakeLayerTreeFrameSink* TestWebFrameWidget::LastCreatedFrameSink() {
  DCHECK(LayerTreeHostForTesting()->IsSingleThreaded());
  return last_created_frame_sink_;
}

std::unique_ptr<TestWebFrameWidgetHost> TestWebFrameWidget::CreateWidgetHost() {
  return std::make_unique<TestWebFrameWidgetHost>();
}

void TestWebFrameWidget::BindWidgetChannels(
    mojo::AssociatedRemote<mojom::blink::Widget> widget_remote,
    mojo::PendingAssociatedReceiver<mojom::blink::WidgetHost> receiver,
    mojo::PendingAssociatedReceiver<mojom::blink::FrameWidgetHost>
        frame_receiver) {
  widget_host_ = CreateWidgetHost();
  widget_host_->BindWidgetHost(std::move(receiver), std::move(frame_receiver));
  mojo::Remote<mojom::blink::WidgetInputHandler> input_handler;

  mojo::PendingRemote<mojom::blink::RenderInputRouterClient> rir_client_remote;
  // Setup RenderInputRouter mojo connections.
  widget_remote->SetupRenderInputRouterConnections(
      rir_client_remote.InitWithNewPipeAndPassReceiver(),
      /* viz_client= */ mojo::NullReceiver());
  widget_host_->BindRenderInputRouterInterfaces(std::move(rir_client_remote));

  widget_host_->GetWidgetInputHandler(
      input_handler.BindNewPipeAndPassReceiver(),
      GetInputHandlerHost()->BindNewRemote());
}

bool TestWebFrameWidget::HaveScrollEventHandlers() const {
  return LayerTreeHostForTesting()->have_scroll_event_handlers();
}

std::unique_ptr<cc::LayerTreeFrameSink>
TestWebFrameWidget::AllocateNewLayerTreeFrameSink() {
  std::unique_ptr<cc::FakeLayerTreeFrameSink> sink =
      cc::FakeLayerTreeFrameSink::Create3d();
  last_created_frame_sink_ = sink.get();
  return sink;
}

void TestWebFrameWidget::WillQueueSyntheticEvent(
    const WebCoalescedInputEvent& event) {
  injected_scroll_events_.push_back(
      std::make_unique<WebCoalescedInputEvent>(event));
}

void TestWebFrameWidgetHost::SetCursor(const ui::Cursor& cursor) {
  cursor_set_count_++;
}

void TestWebFrameWidgetHost::UpdateTooltipUnderCursor(
    const String& tooltip_text,
    base::i18n::TextDirection text_direction_hint) {}

void TestWebFrameWidgetHost::UpdateTooltipFromKeyboard(
    const String& tooltip_text,
    base::i18n::TextDirection text_direction_hint,
    const gfx::Rect& bounds) {}

void TestWebFrameWidgetHost::ClearKeyboardTriggeredTooltip() {}

void TestWebFrameWidgetHost::TextInputStateChanged(
    ui::mojom::blink::TextInputStatePtr state) {
  if (state->show_ime_if_needed)
    ++virtual_keyboard_request_count_;
}

void TestWebFrameWidgetHost::SelectionBoundsChanged(
    const gfx::Rect& anchor_rect,
    base::i18n::TextDirection anchor_dir,
    const gfx::Rect& focus_rect,
    base::i18n::TextDirection focus_dir,
    const gfx::Rect& bounding_box,
    bool is_anchor_first) {}

void TestWebFrameWidgetHost::CreateFrameSink(
    mojo::PendingReceiver<viz::mojom::blink::CompositorFrameSink>
        compositor_frame_sink_receiver,
    mojo::PendingRemote<viz::mojom::blink::CompositorFrameSinkClient>
        compositor_frame_sink_client) {}

void TestWebFrameWidgetHost::RegisterRenderFrameMetadataObserver(
    mojo::PendingReceiver<cc::mojom::blink::RenderFrameMetadataObserverClient>
        render_frame_metadata_observer_client_receiver,
    mojo::PendingRemote<cc::mojom::blink::RenderFrameMetadataObserver>
        render_frame_metadata_observer) {}

void TestWebFrameWidgetHost::AnimateDoubleTapZoomInMainFrame(
    const gfx::Point& tap_point,
    const gfx::Rect& rect_to_zoom) {}

void TestWebFrameWidgetHost::ZoomToFindInPageRectInMainFrame(
    const gfx::Rect& rect_to_zoom) {}

void TestWebFrameWidgetHost::SetHasTouchEventConsumers(
    mojom::blink::TouchEventConsumersPtr consumers) {}

void TestWebFrameWidgetHost::IntrinsicSizingInfoChanged(
    mojom::blink::IntrinsicSizingInfoPtr sizing_info) {}

void TestWebFrameWidgetHost::AutoscrollStart(const gfx::PointF& position) {}

void TestWebFrameWidgetHost::AutoscrollFling(const gfx::Vector2dF& position) {}

void TestWebFrameWidgetHost::AutoscrollEnd() {}

void TestWebFrameWidgetHost::BindWidgetHost(
    mojo::PendingAssociatedReceiver<mojom::blink::WidgetHost> receiver,
    mojo::PendingAssociatedReceiver<mojom::blink::FrameWidgetHost>
        frame_receiver) {
  receiver_.Bind(std::move(receiver));
  frame_receiver_.Bind(std::move(frame_receiver));
}

void TestWebFrameWidgetHost::BindRenderInputRouterInterfaces(
    mojo::PendingRemote<mojom::blink::RenderInputRouterClient> remote) {
  client_remote_.reset();
  client_remote_.Bind(std::move(remote));
}

void TestWebFrameWidgetHost::GetWidgetInputHandler(
    mojo::PendingReceiver<mojom::blink::WidgetInputHandler> request,
    mojo::PendingRemote<mojom::blink::WidgetInputHandlerHost> host) {
  client_remote_->GetWidgetInputHandler(std::move(request), std::move(host));
}

mojo::PendingRemote<mojom::blink::WidgetInputHandlerHost>
TestWidgetInputHandlerHost::BindNewRemote() {
  receiver_.reset();
  return receiver_.BindNewPipeAndPassRemote();
}

void TestWidgetInputHandlerHost::SetTouchActionFromMain(
    cc::TouchAction touch_action) {}

void TestWidgetInputHandlerHost::SetPanAction(
    mojom::blink::PanAction pan_action) {}

void TestWidgetInputHandlerHost::DidOverscroll(
    mojom::blink::DidOverscrollParamsPtr params) {}

void TestWidgetInputHandlerHost::DidStartScrollingViewport() {}

void TestWidgetInputHandlerHost::ImeCancelComposition() {}

void TestWidgetInputHandlerHost::ImeCompositionRangeChanged(
    const gfx::Range& range,
    const std::optional<WTF::Vector<gfx::Rect>>& character_bounds,
    const std::optional<WTF::Vector<gfx::Rect>>& line_bounds) {}

void TestWidgetInputHandlerHost::SetMouseCapture(bool capture) {}

void TestWidgetInputHandlerHost::SetAutoscrollSelectionActiveInMainFrame(
    bool autoscroll_selection) {}

void TestWidgetInputHandlerHost::RequestMouseLock(
    bool from_user_gesture,
    bool unadjusted_movement,
    RequestMouseLockCallback callback) {}

}  // namespace frame_test_helpers
}  // namespace blink

"""


```