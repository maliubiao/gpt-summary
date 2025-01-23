Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `DocumentLoader` class in Chromium's Blink rendering engine. The request also asks to identify relationships with JavaScript, HTML, and CSS, provide examples, discuss potential user/programming errors, and explain how a user might reach this code during debugging.

**Plan:**

1. **Identify core functions:** Analyze the code to understand its primary tasks and responsibilities.
2. **Relate to web technologies:** Determine how these functionalities interact with JavaScript, HTML, and CSS. Provide concrete examples.
3. **Infer logic and create examples:**  Where the code involves conditional logic, construct hypothetical inputs and outputs to illustrate the behavior.
4. **Spot potential errors:** Identify common mistakes users or developers might make that could lead to this code being executed.
5. **Trace user actions:**  Outline the typical user interactions that trigger the code within the `DocumentLoader`.
6. **Summarize the functionality:**  Concise description of the code's role.
这是 `blink/renderer/core/loader/document_loader.cc` 文件中 `DocumentLoader` 类的部分代码，主要负责在导航过程中提交（commit）新的文档。  这是导航过程中的关键步骤，将从网络加载或本地生成的内容转化为浏览器可以渲染的文档对象。

**功能归纳:**

这段代码主要负责 `DocumentLoader` 在导航提交阶段的核心操作，包括：

* **创建和初始化新的 `Document` 对象:**  根据导航的各种参数（例如 URL、MIME 类型、是否是预渲染等）创建一个新的 `Document` 对象，并将其关联到当前的 `Frame`。
* **处理安全策略:** 应用文档策略 (Document Policy)，检查是否需要强制在顶部加载，并处理权限策略头 (Permissions Policy)。
* **管理用户激活状态:**  决定新的文档是否应该继承或清除之前的用户激活状态 (user activation)。
* **处理窗口名称:**  根据导航类型和安全上下文，决定是否需要清除窗口的名称。
* **设置基础 URL:**  对于 MHTML 档案，设置文档的基础 URL 为档案内主资源的 URL。
* **处理访问链接状态 (Visited Link State):**  如果存在 per-origin salt，则更新新文档的访问链接状态。
* **初始化导航 API:**  如果不是初始的 about:blank 文档或 opaque-origin 文档，则为新的文档初始化导航 API 的状态。
* **处理 XSLT:** 如果是 XSLT 转换的结果，则标记该文档。
* **更新浏览上下文组:**  如果接收到浏览上下文组信息，则更新 `Page` 对象的浏览上下文组。
* **通知观察者:**  通知相关的组件 (例如 `Frame`)  新的文档已经被安装。
* **记录性能指标:**  记录与导航相关的性能指标，例如接受语言和内容语言的使用情况。
* **处理 Paint Holding:**  如果启用了 Paint Holding 功能，并且是 HTTP HTML 文档，则允许延迟提交 Compositor。
* **报告资源和导航时序信息:**  向父框架报告资源时序信息，并创建新的文档的导航时序实例。
* **通知浏览器进程:**  告知浏览器进程文档已提交。
* **记录 Use Counter:**  记录与已提交的文档相关的浏览器特性使用情况。
* **开始加载响应:**  如果需要，启动文档内容的加载过程。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **创建 `Document` 对象:**  这段代码创建的 `Document` 对象是 HTML 文档的基础。后续的 HTML 解析器会将加载的 HTML 内容解析到这个 `Document` 对象中，构建 DOM 树。
    * **`document->SetBaseURLOverride(main_resource_url);` (MHTML):**  当加载 MHTML 档案时，这个操作确保了 HTML 中的相对链接能够正确解析，因为档案本身的 URL 可能是本地文件路径，而内容引用的资源可能需要相对于档案内主资源的 URL 进行解析。
    * **`document->MaybeHandleHttpRefresh(...)`:**  处理 HTML 中的 `<meta http-equiv="refresh">` 标签，这会触发页面的重定向或刷新。

* **JavaScript:**
    * **`frame_->DomWindow()->InstallNewDocument(...)`:**  新的 `Document` 对象会被安装到 `DOMWindow` 对象中，这是 JavaScript 可以访问 `document` 全局变量的基础。
    * **初始化导航 API (`frame_->DomWindow()->navigation()->InitializeForNewWindow(...)`)**:  这段代码初始化了 `window.navigation` 对象，这是 JavaScript 用于操作浏览器历史和导航的 API。 例如，JavaScript 可以调用 `window.navigation.back()` 或 `window.navigation.forward()`。
    * **记录 Use Counter (`use_counter_.DidCommitLoad(frame_)`)**:  Blink 使用 Use Counter 跟踪各种 Web 特性的使用情况，这包括很多 JavaScript API 和功能。例如，如果页面使用了某个新的 JavaScript API，这个操作会记录下来。
    * **`ProfilerGroup::InitializeIfEnabled(frame_->DomWindow());`:** 如果文档策略启用了性能分析，则初始化 JavaScript 性能分析器。

* **CSS:**
    * **处理访问链接状态 (`document->GetVisitedLinkState().UpdateSalt(visited_link_salt_.value());`)**:  CSS 中的 `:visited` 伪类依赖于浏览器维护的访问链接历史。这段代码使用 salt 来增强隐私性，避免网站通过 `:visited` 样式推断用户的浏览历史。
    * **`DispatchLinkHeaderPreloads(...)`:**  处理 HTTP 头部中的 `<link rel="preload">` 等指令，这些指令可以指示浏览器预加载 CSS 或其他资源，以提高页面加载性能。

**逻辑推理及假设输入输出:**

**假设输入:**

* `commit_reason_` 为 `CommitReason::kRegular` (普通的页面加载)。
* `should_have_sticky_user_activation_` 为 `true` (需要保持之前的用户激活状态)。
* 导航是同站导航。

**输出:**

* `frame_->ClearUserActivation()` 不会被调用。
* `frame_->SetStickyUserActivationState()` 会被调用。
* 新的 `Document` 对象会继承之前页面的用户激活状态，用户在之前页面进行的操作（例如点击）产生的影响可能会延续到新页面。

**假设输入:**

* `commit_reason_` 为 `CommitReason::kRegular`。
* 导航是跨站导航。
* `previous_window` 存在，并且与当前窗口的 `SecurityOrigin` 不同。

**输出:**

* `should_clear_window_name` 为 `true`。
* `frame_->Tree().ExperimentalSetNulledName();` 会被调用 (尽管代码中是被注释掉的，但逻辑上会执行)。这将尝试清除窗口的名称，以增强安全性，防止跨站脚本攻击。

**用户或编程常见的使用错误:**

* **编程错误：**  开发者在 Service Worker 中错误地处理了导航请求，导致预加载失败，但在 `DocumentLoader` 中仍然记录了预加载的使用情况。例如，Service Worker 返回了错误的状态码，但 `response_.DidServiceWorkerNavigationPreload()` 仍然返回 `true`。
* **用户操作与预期不符：**  用户在填写表单后点击了浏览器的“后退”按钮，然后又点击了“前进”按钮。如果开发者没有正确处理表单重提交的情况，可能会导致 `DocumentLoader` 以错误的 `CommitReason` (例如 `kFormResubmittedBackForward`) 提交文档，导致一些状态管理错误。
* **开发者错误配置 Document Policy:** 开发者在父页面设置了 `Require-Document-Policy` HTTP 头，但子页面没有满足该策略，导致 `was_blocked_by_document_policy_` 为 `true`。这将导致页面加载被阻止，并在控制台中输出错误信息。用户可能会看到一个空白页面或错误页面，开发者需要在控制台中查看具体错误原因。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在地址栏输入 URL 并按下回车键:**  这会触发一个顶层导航。
2. **用户点击页面上的一个链接:**  这会触发一个同源或跨域的导航。
3. **用户通过 JavaScript 调用 `window.location.href = '...'` 或 `window.open(...)`:**  这会触发一个脚本发起的导航。
4. **用户点击浏览器的“前进”或“后退”按钮:**  这会触发一个历史导航。
5. **用户提交一个表单:**  这会触发一个表单提交的导航。
6. **网站使用了 Service Worker 拦截导航请求并返回响应:**  `DocumentLoader` 会处理来自 Service Worker 的响应。
7. **网站使用了预渲染技术 (Prerendering):**  在预渲染的页面被激活时，`DocumentLoader` 会进行提交操作。

在这些场景下，浏览器内核会创建 `DocumentLoader` 对象来处理导航的各个阶段。当响应头和内容开始到达时，`DocumentLoader` 会执行诸如安全检查、资源加载等操作。最终，当准备好创建实际的文档对象时，就会调用这段代码进行文档的提交。

**作为调试线索:**

如果开发者在调试页面加载或导航相关的问题，并且断点命中了这段代码，那么可能意味着：

* **正在创建一个新的文档对象:**  可以检查 `frame_->DomWindow()->InstallNewDocument(...)` 的参数，例如 URL、MIME 类型等，来确认是否符合预期。
* **安全策略正在被应用:**  可以检查 `security_init.PermissionsPolicyHeader()` 和 `document_policy_.feature_state` 来查看策略是否生效，以及是否阻止了某些功能。
* **用户激活状态正在被处理:**  可以检查 `should_have_sticky_user_activation_` 的值，以及 `frame_->HasStickyUserActivation()` 的状态，来理解用户激活是如何传递的。
* **导航 API 正在被初始化:**  可以检查 `history_item_`、`load_type_` 等变量，来理解导航的类型和历史状态。
* **Use Counter 正在被记录:**  可以留意哪些 `WebFeature` 被计数，这有助于理解页面使用了哪些浏览器特性。

总而言之，这段代码是 Blink 渲染引擎中至关重要的部分，它将网络资源转化为浏览器可以理解和渲染的文档对象，并在此过程中处理各种安全、性能和状态管理相关的任务。

### 提示词
```
这是目录为blink/renderer/core/loader/document_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
DocumentPolicyReportOnly));
  }

  navigation_scroll_allowed_ = !frame_->DomWindow()->IsFeatureEnabled(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop);

  WillCommitNavigation();

  is_prerendering_ = frame_->GetPage()->IsPrerendering();
  Document* document = frame_->DomWindow()->InstallNewDocument(
      DocumentInit::Create()
          .WithWindow(frame_->DomWindow(), owner_document)
          .WithToken(token_)
          .ForInitialEmptyDocument(commit_reason_ ==
                                   CommitReason::kInitialization)
          .ForPrerendering(is_prerendering_)
          .WithURL(Url())
          .WithTypeFrom(MimeType())
          .WithSrcdocDocument(loading_srcdoc_)
          .WithJavascriptURL(commit_reason_ == CommitReason::kJavascriptUrl)
          .ForDiscard(commit_reason_ == CommitReason::kDiscard)
          .WithFallbackBaseURL(fallback_base_url_)
          .WithUkmSourceId(ukm_source_id_)
          .WithBaseAuctionNonce(base_auction_nonce_));

  RecordUseCountersForCommit();
  RecordConsoleMessagesForCommit();
  for (const auto& policy : security_init.PermissionsPolicyHeader()) {
    if (policy.deprecated_feature.has_value()) {
      Deprecation::CountDeprecation(frame_->DomWindow(),
                                    *policy.deprecated_feature);
    }
  }

  frame_->ClearScrollSnapshotClients();

  // Determine whether to give the frame sticky user activation. These checks
  // mirror the check in Navigator::DidNavigate(). Main frame navigations and
  // cross-site navigations should not hold on to the sticky user activation
  // state of the previously navigated page. Same-site navigations should retain
  // the previous document's sticky user activation state, regardless of whether
  // the navigation resulted in a new process being created.
  // See: crbug.com/41493458
  // TODO(crbug.com/736415): Clear this bit unconditionally for all frames.
  if (!should_have_sticky_user_activation_) {
    frame_->ClearUserActivation();
  } else {
    frame_->SetStickyUserActivationState();
  }

  // The DocumentLoader was flagged as activated if it needs to notify the frame
  // that it was activated before navigation. Update the frame state based on
  // the new value.
  OldDocumentInfoForCommit* old_document_info_for_commit =
      (commit_reason_ == CommitReason::kRegular)
          ? ScopedOldDocumentInfoForCommitCapturer::CurrentInfo()
          : nullptr;
  bool had_sticky_activation_before_navigation =
      old_document_info_for_commit
          ? old_document_info_for_commit
                ->had_sticky_activation_before_navigation
          : false;
  if (had_sticky_activation_before_navigation != had_sticky_activation_) {
    frame_->SetHadStickyUserActivationBeforeNavigation(had_sticky_activation_);
    frame_->GetLocalFrameHostRemote()
        .HadStickyUserActivationBeforeNavigationChanged(had_sticky_activation_);
  }
  bool was_focused_frame = old_document_info_for_commit
                               ? old_document_info_for_commit->was_focused_frame
                               : false;
  if (was_focused_frame) {
    frame_->GetPage()->GetFocusController().SetFocusedFrame(frame_);
  }

  bool should_clear_window_name =
      previous_window && frame_->IsOutermostMainFrame() && !frame_->Opener() &&
      !frame_->DomWindow()->GetSecurityOrigin()->IsSameOriginWith(
          previous_window->GetSecurityOrigin());
  if (should_clear_window_name) {
    // TODO(andypaicu): experimentalSetNullName will just record the fact
    // that the name would be nulled and if the name is accessed after we will
    // fire a UseCounter. If we decide to move forward with this change, we'd
    // actually clean the name here.
    // frame_->tree().setName(g_null_atom);
    frame_->Tree().ExperimentalSetNulledName();
  }

  bool should_clear_cross_site_cross_browsing_context_group_window_name =
      previous_window && frame_->IsOutermostMainFrame() &&
      is_cross_site_cross_browsing_context_group_;
  if (should_clear_cross_site_cross_browsing_context_group_window_name) {
    // TODO(shuuran): CrossSiteCrossBrowsingContextGroupSetNulledName will just
    // record the fact that the name would be nulled and if the name is accessed
    // after we will fire a UseCounter.
    frame_->Tree().CrossSiteCrossBrowsingContextGroupSetNulledName();
  }

  // MHTML archive's URL is usually a local file. However the main resource
  // within the archive has a public URL and must be used to resolve all the
  // relative links.
  if (loading_main_document_from_mhtml_archive_) {
    ArchiveResource* main_resource = archive_->MainResource();
    KURL main_resource_url = main_resource ? main_resource->Url() : KURL();
    if (!main_resource_url.IsEmpty())
      document->SetBaseURLOverride(main_resource_url);
  }

  // For any navigations which have a per-origin salt, we need to notify the
  // resulting `document`. The `visited_link_salt_` allows the `document` to
  // hash and identify which links should be styled as :visited. Without the
  // salt, the hashtable is unreadable to the Document.
  if (visited_link_salt_.has_value()) {
    if (base::FeatureList::IsEnabled(
            blink::features::kPartitionVisitedLinkDatabase) ||
        base::FeatureList::IsEnabled(
            blink::features::kPartitionVisitedLinkDatabaseWithSelfLinks)) {
      document->GetVisitedLinkState().UpdateSalt(visited_link_salt_.value());
    }
  }

  // The navigation API is not initialized on the initial about:blank document
  // or opaque-origin documents.
  if (commit_reason_ != CommitReason::kInitialization &&
      !frame_->DomWindow()->GetSecurityOrigin()->IsOpaque()) {
    frame_->DomWindow()->navigation()->InitializeForNewWindow(
        *history_item_, load_type_, commit_reason_,
        previous_window->navigation(), navigation_api_back_entries_,
        navigation_api_forward_entries_, navigation_api_previous_entry_);
    // Now that the navigation API's entries array is initialized, we don't need
    // to retain the state from which it was initialized.
    navigation_api_back_entries_.clear();
    navigation_api_forward_entries_.clear();
    navigation_api_previous_entry_ = WebHistoryItem();
  }

  if (commit_reason_ == CommitReason::kXSLT)
    DocumentXSLT::SetHasTransformSource(*document);

  // If we've received browsing context group information, update the Page's
  // browsing context group. This can only ever happen for a top-level frame,
  // because subframes can never change browsing context group, and the
  // value is omitted by the browser process at commit time.
  if (browsing_context_group_info_.has_value()) {
    CHECK(frame_->IsMainFrame());
    frame_->GetPage()->UpdateBrowsingContextGroup(
        browsing_context_group_info_.value());
  }

  DidInstallNewDocument(document);

  // This must be called before the document is opened, otherwise HTML parser
  // will use stale values from HTMLParserOption.
  DidCommitNavigation();

  // This must be called after DidInstallNewDocument which sets the content
  // language for the document.
  if (url_.ProtocolIsInHTTPFamily()) {
    RecordAcceptLanguageAndContentLanguageMetric();
    RecordParentAndChildContentLanguageMetric();
  }

  bool is_same_origin_initiator = IsSameOriginInitiator();

  // No requestor origin means it's browser-initiated (which includes *all*
  // history navigations, including those initiated from `window.history`
  // API).
  last_navigation_had_trusted_initiator_ =
      !requestor_origin_ || is_same_origin_initiator;

  // The PaintHolding feature defers compositor commits until content has been
  // painted or 500ms have passed, whichever comes first. We require that this
  // be an html document served via http.
  if (base::FeatureList::IsEnabled(blink::features::kPaintHolding) &&
      IsA<HTMLDocument>(document) && Url().ProtocolIsInHTTPFamily()) {
    document->SetDeferredCompositorCommitIsAllowed(true);
  } else {
    document->SetDeferredCompositorCommitIsAllowed(false);
  }

  // We only report resource timing info to the parent if:
  // 1. The navigation is container-initiated (e.g. iframe changed src)
  // 2. TAO passed.
  if ((response_.ShouldPopulateResourceTiming() ||
       is_error_page_for_failed_navigation_) &&
      parent_resource_timing_access_ !=
          mojom::blink::ParentResourceTimingAccess::kDoNotReport &&
      response_.TimingAllowPassed()) {
    ResourceResponse response_for_parent(response_);
    if (parent_resource_timing_access_ ==
        mojom::blink::ParentResourceTimingAccess::
            kReportWithoutResponseDetails) {
      response_for_parent.SetType(network::mojom::FetchResponseType::kOpaque);
    }

    DCHECK(frame_->Owner());
    DCHECK(GetRequestorOrigin());
    resource_timing_info_for_parent_ = CreateResourceTimingInfo(
        GetTiming().NavigationStart(), original_url_, &response_for_parent);

    resource_timing_info_for_parent_->last_redirect_end_time =
        document_load_timing_.RedirectEnd();
  }

  // TimingAllowPassed only applies to resource
  // timing reporting. Navigation timing is always same-origin with the
  // document that holds to the timing entry, as navigation timing represents
  // the timing of that document itself.
  response_.SetTimingAllowPassed(true);
  mojom::blink::ResourceTimingInfoPtr navigation_timing_info =
      CreateResourceTimingInfo(base::TimeTicks(),
                               is_error_page_for_failed_navigation_
                                   ? pre_redirect_url_for_failed_navigations_
                                   : url_,
                               &response_);
  navigation_timing_info->last_redirect_end_time =
      document_load_timing_.RedirectEnd();

  DCHECK(frame_->DomWindow());

  // TODO(crbug.com/1476866): We should check for protocols and not emit
  // performance timeline entries for file protocol navigations.
  DOMWindowPerformance::performance(*frame_->DomWindow())
      ->CreateNavigationTimingInstance(std::move(navigation_timing_info));

  {
    // Notify the browser process about the commit.
    FrameNavigationDisabler navigation_disabler(*frame_);
    if (commit_reason_ == CommitReason::kInitialization) {
      // There's no observers yet so nothing to notify.
    } else if (IsJavaScriptURLOrXSLTCommitOrDiscard()) {
      GetLocalFrameClient().DidCommitDocumentReplacementNavigation(this);
    } else {
      GetLocalFrameClient().DispatchDidCommitLoad(
          history_item_.Get(), LoadTypeToCommitType(load_type_),
          previous_window != frame_->DomWindow(),
          security_init.PermissionsPolicyHeader(),
          document_policy_.feature_state);
    }
    // TODO(dgozman): make DidCreateScriptContext notification call currently
    // triggered by installing new document happen here, after commit.
  }
  // Note: this must be called after DispatchDidCommitLoad() for
  // metrics to be correctly sent to the browser process.
  if (commit_reason_ != CommitReason::kInitialization)
    use_counter_.DidCommitLoad(frame_);
  if (IsBackForwardOrRestore(load_type_)) {
    if (Page* page = frame_->GetPage())
      page->HistoryNavigationVirtualTimePauser().UnpauseVirtualTime();
  }

  // If profiling is enabled by document policy, ensure that profiling metadata
  // is available by tracking the execution context's lifetime.
  ProfilerGroup::InitializeIfEnabled(frame_->DomWindow());

  if (Url().ProtocolIsInHTTPFamily() && frame_->IsOutermostMainFrame() &&
      ShouldEmitNewNavigationHistogram(navigation_type_)) {
    base::UmaHistogramTimes(
        "Blink.DocumentLoader.CommitNavigationToStartLoadingResponse.Time"
        ".OutermostMainFrame.NewNavigation.IsHTTPOrHTTPS",
        timer.Elapsed());
  }

  // Load the document if needed.
  StartLoadingResponse();
}

void DocumentLoader::CreateParserPostCommit() {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::CreateParserPostCommit",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  base::ElapsedTimer timer;
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      response_, *frame_->DomWindow());

  if (navigation_delivery_type_ ==
      network::mojom::NavigationDeliveryType::kNavigationalPrefetch) {
    CountUse(WebFeature::kDocumentLoaderDeliveryTypeNavigationalPrefetch);
  }

  // DidObserveLoadingBehavior() must be called after DispatchDidCommitLoad() is
  // called for the metrics tracking logic to handle it properly.
  if (service_worker_network_provider_ &&
      service_worker_network_provider_->GetControllerServiceWorkerMode() ==
          mojom::blink::ControllerServiceWorkerMode::kControlled) {
    LoadingBehaviorFlag loading_behavior =
        kLoadingBehaviorServiceWorkerControlled;
    if (service_worker_network_provider_->GetFetchHandlerType() !=
        mojom::blink::ServiceWorkerFetchHandlerType::kNotSkippable) {
      DCHECK_NE(service_worker_network_provider_->GetFetchHandlerType(),
                mojom::blink::ServiceWorkerFetchHandlerType::kNoHandler);
      // LoadingBehaviorFlag is a bit stream, and `|` should work.
      loading_behavior = static_cast<LoadingBehaviorFlag>(
          loading_behavior |
          kLoadingBehaviorServiceWorkerFetchHandlerSkippable);
    }
    if (!response_.WasFetchedViaServiceWorker()) {
      loading_behavior = static_cast<LoadingBehaviorFlag>(
          loading_behavior |
          kLoadingBehaviorServiceWorkerMainResourceFetchFallback);
    }
    if (service_worker_network_provider_->GetFetchHandlerBypassOption() ==
            mojom::blink::ServiceWorkerFetchHandlerBypassOption::
                kRaceNetworkRequest ||
        service_worker_network_provider_->GetFetchHandlerBypassOption() ==
            mojom::blink::ServiceWorkerFetchHandlerBypassOption::
                kRaceNetworkRequestHoldback) {
      loading_behavior = static_cast<LoadingBehaviorFlag>(
          loading_behavior | kLoadingBehaviorServiceWorkerRaceNetworkRequest);
    }
    GetLocalFrameClient().DidObserveLoadingBehavior(loading_behavior);
  }

  // Links with media values need more information (like viewport information).
  // This happens after the first chunk is parsed in HTMLDocumentParser.
  DispatchLinkHeaderPreloads(nullptr /* viewport */,
                             PreloadHelper::LoadLinksFromHeaderMode::
                                 kDocumentAfterCommitWithoutViewport);

  // Initializing origin trials might force window proxy initialization,
  // which later triggers CHECK when swapping in via WebFrame::Swap().
  // We can safely omit installing original trials on initial empty document
  // and wait for the real load.
  if (commit_reason_ != CommitReason::kInitialization) {
    LocalDOMWindow* window = frame_->DomWindow();
    if (frame_->GetSettings()
            ->GetForceTouchEventFeatureDetectionForInspector()) {
      window->GetOriginTrialContext()->AddFeature(
          mojom::blink::OriginTrialFeature::kTouchEventFeatureDetection);
    }

#if BUILDFLAG(IS_CHROMEOS)
    // TODO(crbug.com/371971653): Remove the force enabling of
    // getAllScreensMedia once the feature is moved to stable in runtime enabled
    // features.
    if (window->GetExecutionContext()->IsIsolatedContext()) {
      window->GetOriginTrialContext()->AddFeature(
          mojom::blink::OriginTrialFeature::kGetAllScreensMedia);
    }
#endif  // BUILDFLAG(IS_CHROMEOS)

    // Enable any origin trials that have been force enabled for this commit.
    window->GetOriginTrialContext()->AddForceEnabledTrials(
        force_enabled_origin_trials_);

    OriginTrialContext::ActivateNavigationFeaturesFromInitiator(
        window, &initiator_origin_trial_features_);
  }

  ParserSynchronizationPolicy parsing_policy = kAllowDeferredParsing;
  if (IsJavaScriptURLOrXSLTCommitOrDiscard() ||
      Document::ForceSynchronousParsingForTesting()) {
    parsing_policy = kForceSynchronousParsing;
  }
  const AtomicString& encoding = commit_reason_ == CommitReason::kXSLT
                                     ? AtomicString("UTF-8")
                                     : response_.TextEncodingName();

  Document* document = frame_->GetDocument();
  parser_ = document->OpenForNavigation(parsing_policy, MimeType(), encoding);

  // XSLT processing converts the response into UTF-8 before sending it through
  // the DocumentParser, but we should still report the original encoding when
  // script queries it via document.characterSet.
  if (commit_reason_ == CommitReason::kXSLT) {
    DocumentEncodingData data;
    data.SetEncoding(WTF::TextEncoding(response_.TextEncodingName()));
    document->SetEncodingData(data);
  }

  if (frame_ && body_loader_ && !loading_main_document_from_mhtml_archive_ &&
      !loading_url_as_empty_document_ && url_.ProtocolIsInHTTPFamily() &&
      !is_static_data_ && frame_->IsMainFrame() &&
      !document->IsPrefetchOnly() && MimeType() == "text/html") {
    parser_->SetIsPreloading(true);
    body_loader_->StartLoadingBody(this);

    if (!frame_ || !body_loader_)
      return;
  }

  frame_->DomWindow()->GetScriptController().UpdateDocument();

  GetFrameLoader().DispatchDidClearDocumentOfWindowObject();

  parser_->SetDocumentWasLoadedAsPartOfNavigation();
  if (was_discarded_)
    document->SetWasDiscarded(true);
  document->MaybeHandleHttpRefresh(
      response_.HttpHeaderField(http_names::kRefresh),
      Document::kHttpRefreshFromHeader);

  // The parser may have collected preloads in the background, flush them now.
  parser_->FlushPendingPreloads();

  if (Url().ProtocolIsInHTTPFamily() && frame_->IsOutermostMainFrame() &&
      ShouldEmitNewNavigationHistogram(navigation_type_)) {
    base::UmaHistogramTimes(
        "Blink.DocumentLoader.CreateParserPostCommit.Time"
        ".OutermostMainFrame.NewNavigation.IsHTTPOrHTTPS",
        timer.Elapsed());
  }
}

const AtomicString& DocumentLoader::MimeType() const {
  // In the case of mhtml archive, |response_| has an archive mime type,
  // while the document has a different mime type.
  if (loading_main_document_from_mhtml_archive_) {
    if (ArchiveResource* main_resource = archive_->MainResource())
      return main_resource->MimeType();
  }

  return response_.MimeType();
}

void DocumentLoader::BlockParser() {
  parser_blocked_count_++;
}

void DocumentLoader::ResumeParser() {
  parser_blocked_count_--;
  DCHECK_GE(parser_blocked_count_, 0);

  if (parser_blocked_count_ != 0)
    return;

  ProcessDataBuffer();

  if (finish_loading_when_parser_resumed_) {
    finish_loading_when_parser_resumed_ = false;
    parser_->Finish();
    parser_.Clear();
  }
}

void DocumentLoader::CountUse(mojom::WebFeature feature) {
  return use_counter_.Count(feature, GetFrame());
}

void DocumentLoader::CountDeprecation(mojom::WebFeature feature) {
  return use_counter_.Count(feature, GetFrame());
}

void DocumentLoader::CountWebDXFeature(mojom::blink::WebDXFeature feature) {
  return use_counter_.CountWebDXFeature(feature, GetFrame());
}

void DocumentLoader::RecordAcceptLanguageAndContentLanguageMetric() {
  // Get document Content-Language value, which has been set as the top-most
  // content language value from http head.
  constexpr const char language_histogram_name[] =
      "LanguageUsage.AcceptLanguageAndContentLanguageUsage";

  const AtomicString& content_language =
      frame_->GetDocument()->ContentLanguage();
  if (!content_language) {
    base::UmaHistogramEnumeration(
        language_histogram_name,
        AcceptLanguageAndContentLanguageUsage::kContentLanguageEmpty);
    return;
  }

  if (content_language == "*") {
    base::UmaHistogramEnumeration(
        language_histogram_name,
        AcceptLanguageAndContentLanguageUsage::kContentLanguageWildcard);
    return;
  }

  // Get Accept-Language header value from Prefs
  bool is_accept_language_dirty =
      frame_->DomWindow()->navigator()->IsLanguagesDirty();
  const Vector<String>& accept_languages =
      frame_->DomWindow()->navigator()->languages();

  // Match content languages and accept languages list:
  // 1. If any value in content languages matches the top-most accept languages
  // 2. If there are any overlap between content languages and accept languages
  if (accept_languages.front() == content_language) {
    base::UmaHistogramEnumeration(
        language_histogram_name,
        AcceptLanguageAndContentLanguageUsage::
            kContentLanguageMatchesPrimaryAcceptLanguage);
  }

  if (base::Contains(accept_languages, content_language)) {
    base::UmaHistogramEnumeration(language_histogram_name,
                                  AcceptLanguageAndContentLanguageUsage::
                                      kContentLanguageMatchesAnyAcceptLanguage);
  }

  // navigator()->languages() is a potential update operation, it could set
  // |is_dirty_language| to false which causes future override operations
  // can't update the accep_language list. We should reset the language to
  // dirty if accept language is dirty before we read from Prefs.
  if (is_accept_language_dirty) {
    frame_->DomWindow()->navigator()->SetLanguagesDirty();
  }
}

void DocumentLoader::RecordParentAndChildContentLanguageMetric() {
  // Check child frame and parent frame content language value.
  if (auto* parent = DynamicTo<LocalFrame>(frame_->Tree().Parent())) {
    const AtomicString& content_language =
        frame_->GetDocument()->ContentLanguage();

    const AtomicString& parent_content_language =
        parent->GetDocument()->ContentLanguage();

    if (parent_content_language != content_language) {
      base::UmaHistogramEnumeration(
          "LanguageUsage.AcceptLanguageAndContentLanguageUsage",
          AcceptLanguageAndContentLanguageUsage::
              kContentLanguageSubframeDiffers);
    }
  }
}

void DocumentLoader::RecordUseCountersForCommit() {
  TRACE_EVENT_WITH_FLOW0("loading",
                         "DocumentLoader::RecordUseCountersForCommit",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  // Pre-commit state, count usage the use counter associated with "this"
  // (provisional document loader) instead of frame_'s document loader.
  if (response_.DidServiceWorkerNavigationPreload())
    CountUse(WebFeature::kServiceWorkerNavigationPreload);
  if (frame_->DomWindow()->IsFeatureEnabled(
          mojom::blink::DocumentPolicyFeature::kForceLoadAtTop)) {
    CountUse(WebFeature::kForceLoadAtTop);
  }
  AtomicString content_encoding =
      response_.HttpHeaderField(http_names::kContentEncoding);
  if (EqualIgnoringASCIICase(content_encoding, "zstd")) {
    CountUse(WebFeature::kZstdContentEncoding);
    CountUse(WebFeature::kZstdContentEncodingForNavigation);
    if (frame_->IsOutermostMainFrame()) {
      CountUse(WebFeature::kZstdContentEncodingForMainFrameNavigation);
      ukm::builders::MainFrameNavigation_ZstdContentEncoding builder(
          ukm_source_id_);
      builder.SetUsedZstd(true);
      builder.Record(frame_->GetDocument()->UkmRecorder());
    } else {
      CountUse(WebFeature::kZstdContentEncodingForSubFrameNavigation);
    }
  }
  if (response_.DidUseSharedDictionary()) {
    CountUse(WebFeature::kSharedDictionaryUsed);
    CountUse(WebFeature::kSharedDictionaryUsedForNavigation);
    CountUse(frame_->IsOutermostMainFrame()
                 ? WebFeature::kSharedDictionaryUsedForMainFrameNavigation
                 : WebFeature::kSharedDictionaryUsedForSubFrameNavigation);
    if (EqualIgnoringASCIICase(content_encoding, "dcb")) {
      CountUse(WebFeature::kSharedDictionaryUsedWithSharedBrotli);
    } else if (EqualIgnoringASCIICase(content_encoding, "dcz")) {
      CountUse(WebFeature::kSharedDictionaryUsedWithSharedZstd);
    }
  }
  if (response_.IsSignedExchangeInnerResponse()) {
    CountUse(WebFeature::kSignedExchangeInnerResponse);
    CountUse(frame_->IsOutermostMainFrame()
                 ? WebFeature::kSignedExchangeInnerResponseInMainFrame
                 : WebFeature::kSignedExchangeInnerResponseInSubFrame);
  }

  if (!response_.HttpHeaderField(http_names::kRequireDocumentPolicy).IsNull())
    CountUse(WebFeature::kRequireDocumentPolicyHeader);

  if (!response_.HttpHeaderField(http_names::kNoVarySearch).IsNull())
    CountUse(WebFeature::kNoVarySearch);

  if (was_blocked_by_document_policy_)
    CountUse(WebFeature::kDocumentPolicyCausedPageUnload);

  // Required document policy can either come from iframe attribute or HTTP
  // header 'Require-Document-Policy'.
  if (!frame_policy_.required_document_policy.empty())
    CountUse(WebFeature::kRequiredDocumentPolicy);

  FrameClientHintsPreferencesContext hints_context(frame_);
  for (const auto& elem : network::GetClientHintToNameMap()) {
    const auto& type = elem.first;
    if (client_hints_preferences_.ShouldSend(type))
      hints_context.CountClientHints(type);
  }

  if (!early_hints_preloaded_resources_.empty()) {
    CountUse(WebFeature::kEarlyHintsPreload);
  }

  if (frame_->IsOutermostMainFrame() &&
      !(Url().User().empty() && Url().Pass().empty())) {
    // We're only measuring top-level documents here, as embedded documents
    // with credentials are blocked (unless they match the credentials in the
    // top-level document).
    CountUse(WebFeature::kTopLevelDocumentWithEmbeddedCredentials);
  }
#if BUILDFLAG(IS_ANDROID)
  // Record whether this window was requested to be opened as a Popup.
  // Android doesn't treat popup windows any differently from normal windows
  // today, but we might want to change that.
  if (frame_->GetPage()->GetWindowFeatures().is_popup) {
    CountUse(WebFeature::kWindowOpenedAsPopupOnMobile);
  }
#endif
}

void DocumentLoader::RecordConsoleMessagesForCommit() {
  if (was_blocked_by_document_policy_) {
    // TODO(https://crbug.com/340616797): Add which document policy violated in
    // error string, instead of just displaying serialized required document
    // policy.
    ConsoleError(
        "Refused to display '" + response_.CurrentRequestUrl().ElidedString() +
        "' because it violates the following document policy "
        "required by its embedder: '" +
        DocumentPolicy::Serialize(frame_policy_.required_document_policy)
            .value_or("[Serialization Error]")
            .c_str() +
        "'.");
  }

  // Report the ResourceResponse now that the new Document has been created and
  // console messages will be properly displayed.
  frame_->Console().ReportResourceResponseReceived(
      this, main_resource_identifier_, response_);
}

void DocumentLoader::ApplyClientHintsConfig(
    const WebVector<network::mojom::WebClientHintsType>& enabled_client_hints) {
  for (auto ch : enabled_client_hints) {
    client_hints_preferences_.SetShouldSend(ch);
  }
}

void DocumentLoader::InitializePrefetchedSignedExchangeManager() {
  if (params_->prefetched_signed_exchanges.empty())
    return;
  // |prefetched_signed_exchanges| is set only when the page is loaded from a
  // signed exchange.
  DCHECK(GetResponse().IsSignedExchangeInnerResponse());
  // When the page is loaded from a signed exchange, |last_redirect| must be the
  // synthesized redirect for the signed exchange.
  DCHECK(params_->redirects.size());
  const WebNavigationParams::RedirectInfo& last_redirect =
      params_->redirects[params_->redirects.size() - 1];
  prefetched_signed_exchange_manager_ =
      PrefetchedSignedExchangeManager::MaybeCreate(
          GetFrame(),
          last_redirect.redirect_response.HttpHeaderField(http_names::kLink),
          GetResponse().HttpHeaderField(http_names::kLink),
          std::move(params_->prefetched_signed_exchanges));
}

PrefetchedSignedExchangeManager*
DocumentLoader::GetPrefetchedSignedExchangeManager() const {
  return prefetched_signed_exchange_manager_.Get();
}

base::TimeDelta DocumentLoader::RemainingTimeToLCPLimit() const {
  // We shouldn't call this function before navigation start
  DCHECK(!document_load_timing_.NavigationStart().is_null());
  base::TimeTicks lcp_limit =
      document_load_timing_.NavigationStart() + kLCPLimit;
  base::TimeTicks now = clock_->NowTicks();
  if (now < lcp_limit)
    return lcp_limit - now;
  return base::TimeDelta();
}

base::TimeDelta
DocumentLoader::RemainingTimeToRenderBlockingFontMaxBlockingTime() const {
  DCHECK(base::FeatureList::IsEnabled(features::kRenderBlockingFonts));
  // We shouldn't call this function before navigation start
  DCHECK(!document_load_timing_.NavigationStart().is_null());
  base::TimeTicks max_blocking_time =
      document_load_timing_.NavigationStart() +
      base::Milliseconds(
          features::kMaxBlockingTimeMsForRenderBlockingFonts.Get());
  base::TimeTicks now = clock_->NowTicks();
  if (now < max_blocking_time) {
    return max_blocking_time - now;
  }
  return base::TimeDelta();
}

mojom::blink::ContentSecurityNotifier&
DocumentLoader::GetContentSecurityNotifier() {
  CHECK(frame_);

  if (!content_security_notifier_.is_bound()) {
    GetFrame()->GetBrowserInterfaceBroker().GetInterface(
        content_security_notifier_.BindNewPipeAndPassReceiver(
            frame_->GetTaskRunner(TaskType::kInternalLoading)));
  }
  return *content_security_notifier_.get();
}

bool DocumentLoader::ConsumeTextFragmentToken() {
  bool token_value = has_text_fragment_token_;
  has_text_fragment_token_ = false;
  return token_value;
}

void DocumentLoader::NotifyPrerenderingDocumentActivated(
    const mojom::blink::PrerenderPageActivationParams& params) {
  DCHECK(!frame_->GetDocument()->IsPrerendering());
  DCHECK(is_prerendering_);
  is_prerendering_ = false;

  // A prerendered document won't have user activation, but when it gets moved
  // to the primary frame, the primary frame might have sticky user activation.
  // In that case, propagate the sticky user activation to the activated
  // prerendered document
  bool had_sticky_activation =
      params.was_user_activated == mojom::blink::WasActivatedOption::kYes;
  if (frame_->IsMainFrame() && had_sticky_activation) {
    DCHECK(!had_sticky_activation_);
    had_sticky_activation_ = had_sticky_activation;

    // Update Frame::had_sticky_user_activation_before_nav_. On regular
    // navigation, this is updated on DocumentLoader::CommitNavigation, but
    // that function is not called on prerender page activation.
    DCHECK(!frame_->HadStickyUserActivationBeforeNavigation());
    frame_->SetHadStickyUserActivationBeforeNavigation(had_sticky_activation);

    // Unlike CommitNavigation, there's no need to call
    // HadStickyUserActivationBeforeNavigationChanged here as the browser
    // process already knows it.
  }

  GetTiming().SetActivationStart(params.activation_start);

  if (params.view_transition_state) {
    CHECK(!view_transition_state_);
    view_transition_state_ = std::move(params.view_transition_state);
  }
  StartViewTransitionIfNeeded(*frame_->GetDocument());
}

HashMap<KURL, EarlyHintsPreloadEntry>
DocumentLoader::GetEarlyHintsPreloadedResources() {
  return early_hints_preloaded_resources_;
}

bool DocumentLoader::IsReloadedOrFormSubmitted() const {
  switch (navigation_type_) {
    case WebNavigationType::kWebNavigationTypeReload:
    case WebNavigationType::kWebNavigationTypeFormSubmitted:
    case WebNavigationType::kWebNavigationTypeFormResubmittedBackForward:
    case WebNavigationType::kWebNavigationTypeFormResubmittedReload:
      return true;
    default:
      return false;
  }
}

void DocumentLoader::MaybeRecordServiceWorkerFallbackMainResource(
    bool was_subresource_fetched_via_service_worker) {
  if (was_subresource_fetched_via_service_worker &&
      !response_.WasFetchedViaServiceWorker() &&
      service_worker_initial_controller_mode_ ==
          mojom::blink::ControllerServiceWorkerMode::kControlled) {
    CountUse(WebFeature::kSerivceWorkerFallbackMainResource);
  }
}

// static
void DocumentLoader::MaybeStartLoadingBodyInBackground(
    WebNavigationBodyLoader* body_loader,
    LocalFrame* frame,
    const KURL& url,
    const ResourceResponse& response) {
  if (!body_loader ||
      !base::FeatureList::IsEnabled(features::kThreadedBodyLoader) ||
      !EqualIgnoringASCIICase(response.MimeType(), "text/html")) {
    return;
  }

  auto* navigation_body_loader = DynamicTo<NavigationBodyLoader>(*body_loader);
  if (!navigation_body_loader)
    return;

  auto decoder = BuildTextResourceDecoder(frame, url, response.MimeType(),
                                          response.TextEncodingName());
  navigation_body_loader->StartLoadingBodyInBackground(
      std::move(decoder),
      // The network inspector needs the raw data.
      probe::ToCoreProbeSink(frame)->HasInspectorNetworkAgents(
```