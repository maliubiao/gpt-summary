Response:
The user wants a summary of the functionality of the provided C++ code snippet from `local_frame_mojo_handler.cc`. This is the second part of a larger file, so I need to consider the context from the first part (which I don't have). However, I can still analyze the current snippet and infer its purpose.

The code seems to handle various requests related to a frame in the Blink rendering engine, likely triggered by inter-process communication (IPC) via Mojo. It deals with:

1. **JavaScript execution:**  Calling methods and executing arbitrary JavaScript code within the frame, including in isolated worlds.
2. **Text manipulation:** Getting character index at a point, retrieving substrings, and handling text input related functionalities on macOS.
3. **Frame management:** Updating the opener frame, getting savable resource links, handling mixed content.
4. **Developer tools:** Binding a DevTools agent.
5. **Smart clip (Android):** Extracting data for smart clip functionality.
6. **Debug URLs:** Handling special "chrome://" or "javascript:" URLs.
7. **Sharing:** Getting the canonical URL for sharing.
8. **Open Graph metadata:** Extracting Open Graph metadata.
9. **Navigation API:**  Interacting with the Navigation API (setting history entries, handling navigation events).
10. **Zooming:**  Animating double tap zoom, setting scale factor, zooming to a find-in-page rectangle.
11. **Page lifecycle:** Closing the page, getting the full page size.
12. **Plugin interaction:** Handling actions on plugins.
13. **Focus management:** Setting initial focus.
14. **Preferred size:** Enabling preferred size changed mode.
15. **COOP monitoring:** Installing cross-origin opener policy access monitors.
16. **Browser controls:** Updating the state of browser controls.
17. **Resource hints:** Setting V8 compile hints.
18. **View Transitions:** Handling view transition snapshots and abort notifications.
19. **Page Swap Events:** Dispatching page swap events.
20. **Resource timing:** Adding resource timing entries for failed subframe navigations.
21. **Fullscreen:** Requesting fullscreen for a video element.
22. **Prerendering:** Updating the URL for prerendering.

I will group these functionalities and provide a high-level summary, relating them to JavaScript, HTML, and CSS where applicable. I'll also include examples of input/output and potential user errors.
这是`blink/renderer/core/frame/local_frame_mojo_handler.cc` 源代码文件的第二部分，延续了第一部分的功能，主要负责处理通过Mojo接口接收到的、针对特定`LocalFrame`的操作请求。它提供了在渲染器进程中与页面框架进行交互的各种功能。

**归纳一下这部分代码的功能:**

这部分代码主要负责处理以下类型的操作，这些操作通常由浏览器进程或其他渲染器进程通过Mojo接口发起：

1. **JavaScript 执行**:
    * **执行方法**: 允许在指定对象上调用JavaScript方法，并可选择返回结果。
    * **执行代码**: 允许执行任意JavaScript代码，并可选择返回结果。
    * **测试环境执行**:  提供更细粒度的JavaScript执行控制，例如是否模拟用户手势，是否解析Promise，以及在特定的JavaScript世界中执行。

2. **文本操作 (主要针对 macOS)**:
    * **获取字符索引**:  根据屏幕坐标获取文本中的字符索引。
    * **获取范围矩形**: 获取指定文本范围的第一个矩形边界。
    * **获取范围字符串**:  获取指定文本范围的带格式字符串。

3. **Frame 生命周期和属性管理**:
    * **绑定 ReportingObserver**:  允许将 Reporting API 的观察者绑定到当前帧。
    * **更新 Opener**:  设置或更新当前窗口的打开者。
    * **获取可保存资源链接**:  获取当前帧及其子帧中可保存的资源链接。
    * **报告混合内容**:  报告页面中发现的混合内容（例如HTTPS页面加载HTTP资源）。
    * **绑定 DevTools Agent**:  将 DevTools 代理绑定到当前帧，用于调试。
    * **处理渲染器调试 URL**:  处理特定的调试 URL，例如 `chrome://` 或 `javascript:` URL。
    * **获取规范 URL**:  获取页面的规范 URL，用于分享等功能。
    * **获取 Open Graph 元数据**:  解析页面中的 Open Graph 元数据。

4. **导航 API**:
    * **设置导航历史记录**:  用于恢复导航历史记录。
    * **通知已释放的导航条目**:  通知导航 API 哪些历史记录条目已被移除。
    * **分发跨文档导航事件**:  在跨文档导航时触发 `navigate` 事件。
    * **取消导航**:  通知导航 API 导航已取消。

5. **用户交互和视觉效果**:
    * **动画双击缩放**:  触发双击缩放动画。
    * **设置缩放因子**:  设置页面的缩放比例。
    * **关闭页面**:  关闭当前页面。
    * **获取完整页面大小**:  获取页面的完整内容大小。
    * **插件操作**:  执行插件相关的操作，例如旋转。
    * **设置初始焦点**:  设置页面加载完成后的初始焦点。
    * **启用首选大小更改模式**:  启用通知页面首选大小更改的模式。
    * **缩放到页面内查找矩形**:  缩放视图以显示页面内查找的匹配项。

6. **安全和隔离**:
    * **安装 COOP 访问监视器**:  用于监视跨域 opener policy (COOP) 相关的访问。
    * **更新浏览器控件状态**:  更新浏览器控件（例如地址栏）的状态。
    * **丢弃帧**:  释放帧相关的资源。
    * **最终确定导航置信度**:  设置导航操作的置信度。

7. **性能优化**:
    * **设置 V8 编译提示**:  提供 V8 引擎编译优化的提示数据。

8. **视图转换 API**:
    * **为视图转换拍摄文档快照**:  在导航过程中捕获旧文档的快照。
    * **通知旧文档视图转换已中止**:  通知旧文档视图转换已取消。
    * **分发页面交换事件**:  分发 `pageswap` 事件。

9. **资源加载和性能监控**:
    * **为失败的子帧导航添加资源计时条目**:  记录子帧导航失败时的资源加载信息。

10. **多媒体**:
    * **请求全屏视频元素**:  将页面中的第一个视频元素切换到全屏模式。

11. **预渲染**:
    * **更新预渲染 URL**:  在预渲染激活时更新页面的 URL。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

* **JavaScript**:
    * **功能关系**: 代码直接操作 V8 引擎来执行 JavaScript 代码和调用方法。
    * **举例说明**:  `JavaScriptMethodExecuteRequest` 可以执行如下操作：假设一个网页中有一个名为 `myObject` 的 JavaScript 对象，并且该对象有一个名为 `calculateSum` 的方法，接受两个参数。浏览器进程可以通过 Mojo 发送请求，调用 `myObject.calculateSum(5, 10)`，并接收返回值 (如果 `wants_result` 为 true)。
    * **假设输入与输出**:
        * **输入**: `object_name = "myObject"`, `method_name = "calculateSum"`, `arguments = [5, 10]`, `wants_result = true`
        * **输出**:  JavaScript 方法 `calculateSum` 的返回值，例如 `15`。

* **HTML**:
    * **功能关系**: 代码会访问和操作 HTML 文档结构，例如获取 Open Graph 元数据、规范 URL、以及查找特定的 HTML 元素（如视频元素）。
    * **举例说明**: `GetOpenGraphMetadata` 功能会解析 HTML 中 `<meta property="og:title" content="Page Title">` 这样的标签，提取页面的标题信息。
    * **假设输入与输出**:
        * **输入**: 一个包含 `<meta property="og:title" content="Example Page">` 的 HTML 页面。
        * **输出**: `mojom::blink::OpenGraphMetadata` 对象，其 `title` 属性为 "Example Page"。

* **CSS**:
    * **功能关系**: 虽然这段代码没有直接操作 CSS 样式，但像 `GetFullPageSize` 这样的功能会受到 CSS 布局的影响。页面的完整大小是由 HTML 结构和 CSS 样式共同决定的。
    * **举例说明**: 如果一个页面的 CSS 设置了 `body { height: 2000px; }`，那么 `GetFullPageSize` 返回的高度将会反映这个 CSS 样式所定义的滚动区域。
    * **假设输入与输出**:
        * **输入**: 一个 CSS 文件包含 `body { height: 1000px; }` 的网页。
        * **输出**: `GetFullPageSize` 返回的 `gfx::Size` 对象，其高度部分会受到该 CSS 规则的影响。

**用户或编程常见的使用错误举例说明:**

* **JavaScript 执行错误**:
    * **错误**:  调用不存在的 JavaScript 对象或方法。
    * **例子**:  如果 `JavaScriptMethodExecuteRequest` 中 `object_name` 指定了一个不存在的对象，或者 `method_name` 指定了一个该对象上不存在的方法，那么 `CallMethodOnFrame` 将会失败，回调函数 `callback` 会收到一个空结果。
    * **用户可见现象**:  网页功能异常，因为预期的 JavaScript 方法调用没有成功执行。

* **传入无效的 `world_id`**:
    * **错误**: 在 `JavaScriptExecuteRequestInIsolatedWorld` 中，如果 `world_id` 不是一个有效的隔离世界 ID。
    * **例子**: 传递一个负数或超出允许范围的 `world_id`。
    * **后果**:  Mojo 会报告一个坏消息 (`mojo::ReportBadMessage(kInvalidWorldID)`), 并且回调函数会收到一个空的 `base::Value()`。这可以防止在错误的上下文中执行 JavaScript 代码。

* **尝试在非主帧上调用 `ClosePage`**:
    * **错误**: `ClosePage` 方法上有一个 `SECURITY_CHECK(frame_->IsOutermostMainFrame());`。如果在子帧上调用此方法，会导致断言失败。
    * **例子**: 浏览器进程错误地向一个 iframe 的 `LocalFrameMojoHandler` 发送了关闭页面的请求。
    * **后果**: 渲染器进程会因为安全检查失败而终止。

总而言之，这部分 `LocalFrameMojoHandler` 的代码是 Blink 渲染引擎中处理来自浏览器或其他进程的、关于页面框架操作的核心组件，涵盖了 JavaScript 执行、DOM 操作、页面生命周期管理、以及与浏览器进程通信的多个方面。

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame_mojo_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
bject_name,
    const String& method_name,
    base::Value::List arguments,
    bool wants_result,
    JavaScriptMethodExecuteRequestCallback callback) {
  TRACE_EVENT_INSTANT0("test_tracing", "JavaScriptMethodExecuteRequest",
                       TRACE_EVENT_SCOPE_THREAD);

  std::unique_ptr<WebV8ValueConverter> converter =
      Platform::Current()->CreateWebV8ValueConverter();
  converter->SetDateAllowed(true);
  converter->SetRegExpAllowed(true);

  v8::HandleScope handle_scope(ToIsolate(frame_));
  v8::Local<v8::Value> result;
  if (!CallMethodOnFrame(frame_, object_name, method_name, std::move(arguments),
                         converter.get())
           .ToLocal(&result)) {
    std::move(callback).Run({});
  } else if (wants_result) {
    v8::Local<v8::Context> context = MainWorldScriptContext(frame_);
    std::move(callback).Run(
        GetJavaScriptExecutionResult(result, context, converter.get()));
  } else {
    std::move(callback).Run({});
  }
}

void LocalFrameMojoHandler::JavaScriptExecuteRequest(
    const String& javascript,
    bool wants_result,
    JavaScriptExecuteRequestCallback callback) {
  TRACE_EVENT_INSTANT0("test_tracing", "JavaScriptExecuteRequest",
                       TRACE_EVENT_SCOPE_THREAD);

  v8::HandleScope handle_scope(ToIsolate(frame_));
  v8::Local<v8::Value> result =
      ClassicScript::CreateUnspecifiedScript(javascript)
          ->RunScriptAndReturnValue(DomWindow())
          .GetSuccessValueOrEmpty();

  if (wants_result) {
    std::unique_ptr<WebV8ValueConverter> converter =
        Platform::Current()->CreateWebV8ValueConverter();
    converter->SetDateAllowed(true);
    converter->SetRegExpAllowed(true);

    v8::Local<v8::Context> context = MainWorldScriptContext(frame_);
    std::move(callback).Run(
        GetJavaScriptExecutionResult(result, context, converter.get()));
  } else {
    std::move(callback).Run({});
  }
}

void LocalFrameMojoHandler::JavaScriptExecuteRequestForTests(
    const String& javascript,
    bool has_user_gesture,
    bool resolve_promises,
    bool honor_js_content_settings,
    int32_t world_id,
    JavaScriptExecuteRequestForTestsCallback callback) {
  TRACE_EVENT_INSTANT0("test_tracing", "JavaScriptExecuteRequestForTests",
                       TRACE_EVENT_SCOPE_THREAD);

  // A bunch of tests expect to run code in the context of a user gesture, which
  // can grant additional privileges (e.g. the ability to create popups).
  if (has_user_gesture)
    NotifyUserActivation(mojom::blink::UserActivationNotificationType::kTest);

  v8::Isolate* isolate = ToIsolate(frame_);
  ScriptState* script_state =
      (world_id == DOMWrapperWorld::kMainWorldId)
          ? ToScriptStateForMainWorld(frame_)
          : ToScriptState(frame_, *DOMWrapperWorld::EnsureIsolatedWorld(
                                      isolate, world_id));
  ScriptState::Scope script_state_scope(script_state);

  // `kDoNotSanitize` is used because this is only for tests and some tests
  // need `kDoNotSanitize` for dynamic imports.
  ClassicScript* script = ClassicScript::CreateUnspecifiedScript(
      javascript, ScriptSourceLocationType::kUnknown,
      SanitizeScriptErrors::kDoNotSanitize);

  const auto policy =
      honor_js_content_settings
          ? ExecuteScriptPolicy::kDoNotExecuteScriptWhenScriptsDisabled
          : ExecuteScriptPolicy::kExecuteScriptWhenScriptsDisabled;
  ScriptEvaluationResult result =
      script->RunScriptOnScriptStateAndReturnValue(script_state, policy);

  auto* handler = MakeGarbageCollected<JavaScriptExecuteRequestForTestsHandler>(
      std::move(callback));
  v8::Local<v8::Value> error;
  switch (result.GetResultType()) {
    case ScriptEvaluationResult::ResultType::kSuccess: {
      v8::Local<v8::Value> value = result.GetSuccessValue();
      if (resolve_promises && !value.IsEmpty() && value->IsPromise()) {
        auto promise = ScriptPromise<IDLAny>::FromV8Promise(
            script_state->GetIsolate(), value.As<v8::Promise>());
        promise.Then(script_state,
                     handler->CreateResolveCallback(script_state, frame_),
                     handler->CreateRejectCallback(script_state, frame_));
      } else {
        handler->SendSuccess(script_state, value);
      }
      return;
    }

    case ScriptEvaluationResult::ResultType::kException:
      error = result.GetExceptionForClassicForTesting();
      break;

    case ScriptEvaluationResult::ResultType::kAborted:
      error = v8::String::NewFromUtf8Literal(isolate, "Script aborted");
      break;

    case ScriptEvaluationResult::ResultType::kNotRun:
      error = v8::String::NewFromUtf8Literal(isolate, "Script not run");
      break;
  }
  DCHECK_NE(result.GetResultType(),
            ScriptEvaluationResult::ResultType::kSuccess);
  handler->SendException(script_state, error);
}

void LocalFrameMojoHandler::JavaScriptExecuteRequestInIsolatedWorld(
    const String& javascript,
    bool wants_result,
    int32_t world_id,
    JavaScriptExecuteRequestInIsolatedWorldCallback callback) {
  TRACE_EVENT_INSTANT0("test_tracing",
                       "JavaScriptExecuteRequestInIsolatedWorld",
                       TRACE_EVENT_SCOPE_THREAD);

  if (world_id <= DOMWrapperWorld::kMainWorldId ||
      world_id > DOMWrapperWorld::kDOMWrapperWorldEmbedderWorldIdLimit) {
    // Returns if the world_id is not valid. world_id is passed as a plain int
    // over IPC and needs to be verified here, in the IPC endpoint.
    std::move(callback).Run(base::Value());
    mojo::ReportBadMessage(kInvalidWorldID);
    return;
  }

  WebScriptSource web_script_source(javascript);
  frame_->RequestExecuteScript(
      world_id, base::span_from_ref(web_script_source),
      mojom::blink::UserActivationOption::kDoNotActivate,
      mojom::blink::EvaluationTiming::kSynchronous,
      mojom::blink::LoadEventBlockingOption::kDoNotBlock,
      WTF::BindOnce(
          [](JavaScriptExecuteRequestInIsolatedWorldCallback callback,
             std::optional<base::Value> value, base::TimeTicks start_time) {
            std::move(callback).Run(value ? std::move(*value) : base::Value());
          },
          std::move(callback)),
      BackForwardCacheAware::kAllow,
      wants_result
          ? mojom::blink::WantResultOption::kWantResultDateAndRegExpAllowed
          : mojom::blink::WantResultOption::kNoResult,
      mojom::blink::PromiseResultOption::kDoNotWait);
}

#if BUILDFLAG(IS_MAC)
void LocalFrameMojoHandler::GetCharacterIndexAtPoint(const gfx::Point& point) {
  frame_->GetCharacterIndexAtPoint(point);
}

void LocalFrameMojoHandler::GetFirstRectForRange(const gfx::Range& range) {
  gfx::Rect rect;
  WebLocalFrameClient* client = WebLocalFrameImpl::FromFrame(frame_)->Client();
  if (!client)
    return;

  WebPluginContainerImpl* plugin_container = frame_->GetWebPluginContainer();
  if (plugin_container) {
    // Pepper-free PDF will reach here.
    rect = plugin_container->Plugin()->GetPluginCaretBounds();
  } else {
    // TODO(crbug.com/40511450): Remove `pepper_has_caret` once PPAPI is gone.
    bool pepper_has_caret = client->GetCaretBoundsFromFocusedPlugin(rect);
    if (!pepper_has_caret) {
      // When request range is invalid we will try to obtain it from current
      // frame selection. The fallback value will be 0.
      size_t start = range.IsValid()
                           ? range.start()
                           : GetCurrentCursorPositionInFrame(frame_);

      WebLocalFrameImpl::FromFrame(frame_)->FirstRectForCharacterRange(
          base::checked_cast<uint32_t>(start),
          base::checked_cast<uint32_t>(range.length()), rect);
    }
  }

  TextInputHost().GotFirstRectForRange(rect);
}

void LocalFrameMojoHandler::GetStringForRange(
    const gfx::Range& range,
    GetStringForRangeCallback callback) {
  gfx::Point baseline_point;
  ui::mojom::blink::AttributedStringPtr attributed_string = nullptr;
  base::apple::ScopedCFTypeRef<CFAttributedStringRef> string =
      SubstringUtil::AttributedSubstringInRange(
          frame_, base::checked_cast<WTF::wtf_size_t>(range.start()),
          base::checked_cast<WTF::wtf_size_t>(range.length()), baseline_point);
  if (string) {
    attributed_string = ui::mojom::blink::AttributedString::From(string.get());
  }

  std::move(callback).Run(std::move(attributed_string), baseline_point);
}
#endif

void LocalFrameMojoHandler::BindReportingObserver(
    mojo::PendingReceiver<mojom::blink::ReportingObserver> receiver) {
  ReportingContext::From(DomWindow())->Bind(std::move(receiver));
}

void LocalFrameMojoHandler::UpdateOpener(
    const std::optional<blink::FrameToken>& opener_frame_token) {
  if (WebFrame::FromCoreFrame(frame_)) {
    Frame* opener_frame = nullptr;
    if (opener_frame_token)
      opener_frame = Frame::ResolveFrame(opener_frame_token.value());
    frame_->SetOpenerDoNotNotify(opener_frame);
  }
}

void LocalFrameMojoHandler::GetSavableResourceLinks(
    GetSavableResourceLinksCallback callback) {
  Vector<KURL> resources_list;
  Vector<mojom::blink::SavableSubframePtr> subframes;
  SavableResources::Result result(&resources_list, &subframes);

  if (!SavableResources::GetSavableResourceLinksForFrame(frame_, &result)) {
    std::move(callback).Run(nullptr);
    return;
  }

  auto referrer = mojom::blink::Referrer::New(GetDocument()->Url(),
                                              DomWindow()->GetReferrerPolicy());

  auto reply = mojom::blink::GetSavableResourceLinksReply::New();
  reply->resources_list = std::move(resources_list);
  reply->referrer = std::move(referrer);
  reply->subframes = std::move(subframes);

  std::move(callback).Run(std::move(reply));
}

void LocalFrameMojoHandler::MixedContentFound(
    const KURL& main_resource_url,
    const KURL& mixed_content_url,
    mojom::blink::RequestContextType request_context,
    bool was_allowed,
    const KURL& url_before_redirects,
    bool had_redirect,
    network::mojom::blink::SourceLocationPtr source_location) {
  std::unique_ptr<SourceLocation> source;
  if (source_location) {
    source = std::make_unique<SourceLocation>(source_location->url, String(),
                                              source_location->line,
                                              source_location->column, nullptr);
  }
  MixedContentChecker::MixedContentFound(
      frame_, main_resource_url, mixed_content_url, request_context,
      was_allowed, url_before_redirects, had_redirect, std::move(source));
}

void LocalFrameMojoHandler::BindDevToolsAgent(
    mojo::PendingAssociatedRemote<mojom::blink::DevToolsAgentHost> host,
    mojo::PendingAssociatedReceiver<mojom::blink::DevToolsAgent> receiver) {
  DCHECK(frame_->Client());
  frame_->Client()->BindDevToolsAgent(std::move(host), std::move(receiver));
}

#if BUILDFLAG(IS_ANDROID)
void LocalFrameMojoHandler::ExtractSmartClipData(
    const gfx::Rect& rect,
    ExtractSmartClipDataCallback callback) {
  String clip_text;
  String clip_html;
  gfx::Rect clip_rect;
  frame_->ExtractSmartClipDataInternal(rect, clip_text, clip_html, clip_rect);
  std::move(callback).Run(clip_text.IsNull() ? g_empty_string : clip_text,
                          clip_html.IsNull() ? g_empty_string : clip_html,
                          clip_rect);
}
#endif  // BUILDFLAG(IS_ANDROID)

void LocalFrameMojoHandler::HandleRendererDebugURL(const KURL& url) {
  DCHECK(IsRendererDebugURL(GURL(url)));
  if (url.ProtocolIs("javascript")) {
    // JavaScript URLs should be sent to Blink for handling.
    frame_->LoadJavaScriptURL(url);
  } else {
    // This is a Chrome Debug URL. Handle it.
    HandleChromeDebugURL(GURL(url));
  }

  // The browser sets its status as loading before calling this IPC. Inform it
  // that the load stopped if needed, while leaving the debug URL visible in the
  // address bar.
  if (!frame_->IsLoading())
    frame_->Client()->DidStopLoading();
}

void LocalFrameMojoHandler::GetCanonicalUrlForSharing(
    GetCanonicalUrlForSharingCallback callback) {
#if BUILDFLAG(IS_ANDROID)
  base::TimeTicks start_time = base::TimeTicks::Now();
#endif
  KURL canon_url;
  HTMLLinkElement* link_element = GetDocument()->LinkCanonical();
  if (link_element) {
    canon_url = link_element->Href();
    KURL doc_url = GetDocument()->Url();
    // When sharing links to pages, the fragment identifier often serves to mark a specific place
    // within the page that the user wishes to point the recipient to. Canonical URLs generally
    // don't and can't contain this state, so try to match user expectations a little more closely
    // here by splicing the fragment identifier (if there is one) into the shared URL.
    if (doc_url.HasFragmentIdentifier() && !canon_url.HasFragmentIdentifier()) {
      canon_url.SetFragmentIdentifier(doc_url.FragmentIdentifier().ToString());
    }
  }
  std::move(callback).Run(canon_url.IsNull() ? std::nullopt
                                             : std::make_optional(canon_url));
#if BUILDFLAG(IS_ANDROID)
  base::UmaHistogramMicrosecondsTimes("Blink.Frame.GetCanonicalUrlRendererTime",
                                      base::TimeTicks::Now() - start_time);
#endif
}

void LocalFrameMojoHandler::GetOpenGraphMetadata(
    GetOpenGraphMetadataCallback callback) {
  auto metadata = mojom::blink::OpenGraphMetadata::New();
  if (auto* document_element = frame_->GetDocument()->documentElement()) {
    for (const auto& child :
         Traversal<HTMLMetaElement>::DescendantsOf(*document_element)) {
      // If there are multiple OpenGraph tags for the same property, we always
      // take the value from the first one - this is the specified behavior in
      // the OpenGraph spec:
      //   The first tag (from top to bottom) is given preference during
      //   conflicts
      ParseOpenGraphProperty(child, *frame_->GetDocument(), metadata.get());
    }
  }
  std::move(callback).Run(std::move(metadata));
}

void LocalFrameMojoHandler::SetNavigationApiHistoryEntriesForRestore(
    mojom::blink::NavigationApiHistoryEntryArraysPtr entry_arrays,
    mojom::blink::NavigationApiEntryRestoreReason restore_reason) {
  frame_->DomWindow()->navigation()->SetEntriesForRestore(entry_arrays,
                                                          restore_reason);
}

void LocalFrameMojoHandler::NotifyNavigationApiOfDisposedEntries(
    const WTF::Vector<WTF::String>& keys) {
  frame_->DomWindow()->navigation()->DisposeEntriesForSessionHistoryRemoval(
      keys);
}

void LocalFrameMojoHandler::DispatchNavigateEventForCrossDocumentTraversal(
    const KURL& url,
    const std::string& page_state,
    bool is_browser_initiated) {
  auto* params = MakeGarbageCollected<NavigateEventDispatchParams>(
      url, NavigateEventType::kCrossDocument, WebFrameLoadType::kBackForward);
  params->involvement = is_browser_initiated
                            ? UserNavigationInvolvement::kBrowserUI
                            : UserNavigationInvolvement::kNone;
  params->destination_item =
      WebHistoryItem(PageState::CreateFromEncodedData(page_state));
  auto result =
      frame_->DomWindow()->navigation()->DispatchNavigateEvent(params);
  CHECK_EQ(result, NavigationApi::DispatchResult::kContinue);
}

void LocalFrameMojoHandler::TraverseCancelled(
    const String& navigation_api_key,
    mojom::blink::TraverseCancelledReason reason) {
  frame_->DomWindow()->navigation()->TraverseCancelled(navigation_api_key,
                                                       reason);
}

void LocalFrameMojoHandler::AnimateDoubleTapZoom(const gfx::Point& point,
                                                 const gfx::Rect& rect) {
  frame_->GetPage()->GetChromeClient().AnimateDoubleTapZoom(point, rect);
}

void LocalFrameMojoHandler::SetScaleFactor(float scale_factor) {
  frame_->SetScaleFactor(scale_factor);
}

void LocalFrameMojoHandler::ClosePage(
    mojom::blink::LocalMainFrame::ClosePageCallback completion_callback) {
  SECURITY_CHECK(frame_->IsOutermostMainFrame());

  // There are two ways to close a page:
  //
  // 1/ Via webview()->Close() that currently sets the WebView's delegate_ to
  // NULL, and prevent any JavaScript dialogs in the onunload handler from
  // appearing.
  //
  // 2/ Calling the FrameLoader's CloseURL method directly.
  //
  // TODO(creis): Having a single way to close that can run onunload is also
  // useful for fixing http://b/issue?id=753080.

  SubframeLoadingDisabler disabler(frame_->GetDocument());
  // https://html.spec.whatwg.org/C/browsing-the-web.html#unload-a-document
  // The ignore-opens-during-unload counter of a Document must be incremented
  // when unloading itself.
  IgnoreOpensDuringUnloadCountIncrementer ignore_opens_during_unload(
      frame_->GetDocument());
  frame_->Loader().DispatchUnloadEventAndFillOldDocumentInfoIfNeeded(
      false /* need_unload_info_for_new_document */);

  std::move(completion_callback).Run();
}

void LocalFrameMojoHandler::GetFullPageSize(
    mojom::blink::LocalMainFrame::GetFullPageSizeCallback callback) {
  // LayoutZoomFactor takes CSS pixels to device/physical pixels. It includes
  // both browser ctrl+/- zoom as well as the device scale factor for screen
  // density. Note: we don't account for pinch-zoom, even though it scales a
  // CSS pixel, since "device pixels" coming from Blink are also unscaled by
  // pinch-zoom.
  float css_to_physical = frame_->LayoutZoomFactor();
  float physical_to_css = 1.f / css_to_physical;
  gfx::Size full_page_size =
      frame_->View()->GetScrollableArea()->ContentsSize();

  // `content_size` is in physical pixels. Normlisation is needed to convert it
  // to CSS pixels. Details: https://crbug.com/1181313
  gfx::Size css_full_page_size =
      gfx::ScaleToFlooredSize(full_page_size, physical_to_css);
  std::move(callback).Run(
      gfx::Size(css_full_page_size.width(), css_full_page_size.height()));
}

void LocalFrameMojoHandler::PluginActionAt(
    const gfx::Point& location,
    mojom::blink::PluginActionType action) {
  // TODO(bokan): Location is probably in viewport coordinates
  HitTestResult result =
      HitTestResultForRootFramePos(frame_, PhysicalOffset(location));
  Node* node = result.InnerNode();
  if (!IsA<HTMLObjectElement>(*node) && !IsA<HTMLEmbedElement>(*node))
    return;

  auto* embedded = DynamicTo<LayoutEmbeddedContent>(node->GetLayoutObject());
  if (!embedded)
    return;

  WebPluginContainerImpl* plugin_view = embedded->Plugin();
  if (!plugin_view)
    return;

  switch (action) {
    case mojom::blink::PluginActionType::kRotate90Clockwise:
      plugin_view->Plugin()->RotateView(WebPlugin::RotationType::k90Clockwise);
      return;
    case mojom::blink::PluginActionType::kRotate90Counterclockwise:
      plugin_view->Plugin()->RotateView(
          WebPlugin::RotationType::k90Counterclockwise);
      return;
  }
  NOTREACHED();
}

void LocalFrameMojoHandler::SetInitialFocus(bool reverse) {
  frame_->SetInitialFocus(reverse);
}

void LocalFrameMojoHandler::EnablePreferredSizeChangedMode() {
  frame_->GetPage()->GetChromeClient().EnablePreferredSizeChangedMode();
}

void LocalFrameMojoHandler::ZoomToFindInPageRect(
    const gfx::Rect& rect_in_root_frame) {
  frame_->GetPage()->GetChromeClient().ZoomToFindInPageRect(rect_in_root_frame);
}

void LocalFrameMojoHandler::InstallCoopAccessMonitor(
    const FrameToken& accessed_window,
    network::mojom::blink::CrossOriginOpenerPolicyReporterParamsPtr
        coop_reporter_params,
    bool is_in_same_virtual_coop_related_group) {
  blink::Frame* accessed_frame = Frame::ResolveFrame(accessed_window);
  // The Frame might have been deleted during the cross-process communication.
  if (!accessed_frame)
    return;

  accessed_frame->DomWindow()->InstallCoopAccessMonitor(
      frame_, std::move(coop_reporter_params),
      is_in_same_virtual_coop_related_group);
}

void LocalFrameMojoHandler::UpdateBrowserControlsState(
    cc::BrowserControlsState constraints,
    cc::BrowserControlsState current,
    bool animate,
    const std::optional<cc::BrowserControlsOffsetTagsInfo>& offset_tags_info) {
  DCHECK(frame_->IsOutermostMainFrame());
  TRACE_EVENT2("renderer", "LocalFrame::UpdateBrowserControlsState",
               "Constraint", static_cast<int>(constraints), "Current",
               static_cast<int>(current));
  TRACE_EVENT_INSTANT1("renderer", "is_animated", TRACE_EVENT_SCOPE_THREAD,
                       "animated", animate);

  frame_->GetWidgetForLocalRoot()->UpdateBrowserControlsState(
      constraints, current, animate, offset_tags_info);
}

void LocalFrameMojoHandler::Discard() {
  frame_->Discard();
}

void LocalFrameMojoHandler::FinalizeNavigationConfidence(
    double randomized_trigger_rate,
    mojom::blink::ConfidenceLevel confidence) {
  frame_->SetNavigationConfidence(randomized_trigger_rate, confidence);
}

void LocalFrameMojoHandler::SetV8CompileHints(
    base::ReadOnlySharedMemoryRegion data) {
  CHECK(base::FeatureList::IsEnabled(blink::features::kConsumeCompileHints));
  Page* page = GetPage();
  if (page == nullptr) {
    return;
  }
  base::ReadOnlySharedMemoryMapping mapping = data.Map();
  if (!mapping.IsValid()) {
    return;
  }
  const int64_t* memory = mapping.GetMemoryAs<int64_t>();
  if (memory == nullptr) {
    return;
  }

  page->GetV8CrowdsourcedCompileHintsConsumer().SetData(memory,
                                                        mapping.size() / 8);
}

void LocalFrameMojoHandler::SnapshotDocumentForViewTransition(
    const blink::ViewTransitionToken& transition_token,
    mojom::blink::PageSwapEventParamsPtr params,
    SnapshotDocumentForViewTransitionCallback callback) {
  ViewTransitionSupplement::SnapshotDocumentForNavigation(
      *frame_->GetDocument(), transition_token, std::move(params),
      std::move(callback));
}

void LocalFrameMojoHandler::NotifyViewTransitionAbortedToOldDocument() {
  if (auto* transition =
          ViewTransitionUtils::GetOutgoingCrossDocumentTransition(
              *frame_->GetDocument())) {
    transition->SkipTransition();
  }
}

void LocalFrameMojoHandler::DispatchPageSwap(
    mojom::blink::PageSwapEventParamsPtr params) {
  auto* page_swap_event = MakeGarbageCollected<PageSwapEvent>(
      *frame_->GetDocument(), std::move(params), nullptr);
  frame_->GetDocument()->domWindow()->DispatchEvent(*page_swap_event);
}

void LocalFrameMojoHandler::AddResourceTimingEntryForFailedSubframeNavigation(
    const FrameToken& subframe_token,
    const KURL& initial_url,
    base::TimeTicks start_time,
    base::TimeTicks redirect_time,
    base::TimeTicks request_start,
    base::TimeTicks response_start,
    uint32_t response_code,
    const WTF::String& mime_type,
    network::mojom::blink::LoadTimingInfoPtr load_timing_info,
    net::HttpConnectionInfo connection_info,
    const WTF::String& alpn_negotiated_protocol,
    bool is_secure_transport,
    bool is_validated,
    const WTF::String& normalized_server_timing,
    const network::URLLoaderCompletionStatus& completion_status) {
  Frame* subframe = Frame::ResolveFrame(subframe_token);
  if (!subframe || !subframe->Owner()) {
    return;
  }

  ResourceResponse response;
  response.SetAlpnNegotiatedProtocol(AtomicString(alpn_negotiated_protocol));
  response.SetConnectionInfo(connection_info);
  response.SetConnectionReused(load_timing_info->socket_reused);
  response.SetTimingAllowPassed(true);
  response.SetIsValidated(is_validated);
  response.SetDecodedBodyLength(completion_status.decoded_body_length);
  response.SetEncodedBodyLength(completion_status.encoded_body_length);
  response.SetEncodedDataLength(completion_status.encoded_data_length);
  response.SetHttpStatusCode(response_code);
  if (!normalized_server_timing.empty()) {
    response.SetHttpHeaderField(http_names::kServerTiming,
                                AtomicString(normalized_server_timing));
  }

  mojom::blink::ResourceTimingInfoPtr info =
      CreateResourceTimingInfo(start_time, initial_url, &response);
  info->response_end = completion_status.completion_time;
  info->last_redirect_end_time = redirect_time;
  info->is_secure_transport = is_secure_transport;
  info->timing = std::move(load_timing_info);
  subframe->Owner()->AddResourceTiming(std::move(info));
}

void LocalFrameMojoHandler::RequestFullscreenVideoElement() {
  // Find the first video element of the frame.
  for (auto* child = frame_->GetDocument()->documentElement(); child;
       child = Traversal<HTMLElement>::Next(*child)) {
    if (IsA<HTMLVideoElement>(child)) {
      // This is always initiated from browser side (which should require the
      // user interacting with ui) which suffices for a user gesture even though
      // there will have been no input to the frame at this point.
      frame_->NotifyUserActivation(
          mojom::blink::UserActivationNotificationType::kInteraction);

      Fullscreen::RequestFullscreen(*child);
      return;
    }
  }
}

void LocalFrameMojoHandler::UpdatePrerenderURL(
    const KURL& matched_url,
    UpdatePrerenderURLCallback callback) {
  CHECK(SecurityOrigin::Create(matched_url)
            ->IsSameOriginWith(
                &*GetDocument()->GetExecutionContext()->GetSecurityOrigin()));
  auto* params = MakeGarbageCollected<NavigateEventDispatchParams>(
      matched_url, NavigateEventType::kPrerenderNoVarySearchActivation,
      WebFrameLoadType::kReplaceCurrentItem);
  params->is_browser_initiated = true;

  // TODO(crbug.com/41494389): Add test for how the navigation API can intercept
  // this update.
  if (frame_->DomWindow()->navigation()->DispatchNavigateEvent(params) !=
      NavigationApi::DispatchResult::kContinue) {
    std::move(callback).Run();
    return;
  }

  GetDocument()->Loader()->RunURLAndHistoryUpdateSteps(
      matched_url, nullptr,
      mojom::blink::SameDocumentNavigationType::
          kPrerenderNoVarySearchActivation,
      /*data=*/nullptr, WebFrameLoadType::kReplaceCurrentItem,
      FirePopstate::kNo,
      /*is_browser_initiated=*/true);
  std::move(callback).Run();
}

}  // namespace blink
```