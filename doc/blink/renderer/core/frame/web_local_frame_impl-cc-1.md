Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_local_frame_impl.cc`. I need to go through the methods in the code and describe what they do. I also need to identify any relationships to JavaScript, HTML, and CSS, provide examples, and note potential user or programming errors. Since this is part 2 of 5, I should focus on the functionality within this specific snippet.

Here's a plan:
1. **Iterate through each method in the code snippet.**
2. **For each method, describe its purpose in simple terms.**
3. **Identify if the method interacts with JavaScript, HTML, or CSS.**
    - If yes, provide a concrete example of how this interaction occurs.
4. **Look for any logic that involves input and output.**
    - If found, create a hypothetical scenario with an input and the expected output.
5. **Identify potential user or programming errors related to each method.**
    - Provide specific examples of such errors.
6. **Finally, summarize the overall functionality of this code snippet.**
```
这是目录为blink/renderer/core/frame/web_local_frame_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
likely]] {
    return nullptr;
  }
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  if (context.IsEmpty())
    return nullptr;
  return FrameForContext(context);
}

void WebLocalFrameImpl::NotifyUserActivation(
    mojom::blink::UserActivationNotificationType notification_type) {
  LocalFrame::NotifyUserActivation(GetFrame(), notification_type);
}

bool WebLocalFrameImpl::HasStickyUserActivation() {
  return GetFrame()->HasStickyUserActivation();
}

bool WebLocalFrameImpl::HasTransientUserActivation() {
  return LocalFrame::HasTransientUserActivation(GetFrame());
}

bool WebLocalFrameImpl::ConsumeTransientUserActivation(
    UserActivationUpdateSource update_source) {
  return LocalFrame::ConsumeTransientUserActivation(GetFrame(), update_source);
}

bool WebLocalFrameImpl::LastActivationWasRestricted() const {
  return GetFrame()->LastActivationWasRestricted();
}

#if BUILDFLAG(IS_WIN)
WebFontFamilyNames WebLocalFrameImpl::GetWebFontFamilyNames() const {
  FontFamilyNames font_family_names;
  GetFontsUsedByFrame(*GetFrame(), font_family_names);
  WebFontFamilyNames result;
  for (const String& font_family_name : font_family_names.font_names) {
    result.font_names.push_back(font_family_name);
  }
  return result;
}
#endif

WebLocalFrame* WebLocalFrame::FrameForContext(v8::Local<v8::Context> context) {
  return WebLocalFrameImpl::FromFrame(ToLocalFrameIfNotDetached(context));
}

bool WebLocalFrameImpl::IsWebLocalFrame() const {
  return true;
}

WebLocalFrame* WebLocalFrameImpl::ToWebLocalFrame() {
  return this;
}

const WebLocalFrame* WebLocalFrameImpl::ToWebLocalFrame() const {
  return this;
}

bool WebLocalFrameImpl::IsWebRemoteFrame() const {
  return false;
}

WebRemoteFrame* WebLocalFrameImpl::ToWebRemoteFrame() {
  NOTREACHED();
}

const WebRemoteFrame* WebLocalFrameImpl::ToWebRemoteFrame() const {
  NOTREACHED();
}

void WebLocalFrameImpl::Close(DetachReason detach_reason) {
  WebLocalFrame::Close(detach_reason);

  if (frame_widget_) {
    frame_widget_->Close(detach_reason);
    frame_widget_ = nullptr;
  }

  client_ = nullptr;

  if (dev_tools_agent_)
    dev_tools_agent_.Clear();

  self_keep_alive_.Clear();

  if (print_context_)
    PrintEnd();
  print_client_.reset();
#if DCHECK_IS_ON()
  is_in_printing_ = false;
#endif
}

WebString WebLocalFrameImpl::AssignedName() const {
  return GetFrame()->Tree().GetName();
}

ui::AXTreeID WebLocalFrameImpl::GetAXTreeID() const {
  const std::optional<base::UnguessableToken>& embedding_token =
      GetEmbeddingToken();
  if (embedding_token && !embedding_token->is_empty())
    return ui::AXTreeID::FromToken(embedding_token.value());
  return ui::AXTreeIDUnknown();
}

void WebLocalFrameImpl::SetName(const WebString& name) {
  GetFrame()->Tree().SetName(name, FrameTree::kReplicate);
}

WebContentSettingsClient* WebLocalFrameImpl::GetContentSettingsClient() const {
  return content_settings_client_;
}

void WebLocalFrameImpl::SetContentSettingsClient(
    WebContentSettingsClient* client) {
  content_settings_client_ = client;
}

ScrollableArea* WebLocalFrameImpl::LayoutViewport() const {
  if (LocalFrameView* view = GetFrameView())
    return view->LayoutViewport();
  return nullptr;
}

bool WebLocalFrameImpl::IsFocused() const {
  if (!ViewImpl() || !ViewImpl()->GetPage())
    return false;

  return this ==
         WebFrame::FromCoreFrame(
             ViewImpl()->GetPage()->GetFocusController().FocusedFrame());
}

bool WebLocalFrameImpl::DispatchedPagehideAndStillHidden() const {
  // Dispatching pagehide is the first step in unloading, so we must have
  // already dispatched pagehide if unload had started.
  if (GetFrame() && GetFrame()->GetDocument() &&
      GetFrame()->GetDocument()->UnloadStarted()) {
    return true;
  }
  if (!ViewImpl() || !ViewImpl()->GetPage())
    return false;
  // We might have dispatched pagehide without unloading the document.
  return ViewImpl()->GetPage()->DispatchedPagehideAndStillHidden();
}

void WebLocalFrameImpl::CopyToFindPboard() {
#if BUILDFLAG(IS_MAC)
  if (HasSelection())
    GetFrame()->GetSystemClipboard()->CopyToFindPboard(SelectionAsText());
#endif
}

void WebLocalFrameImpl::CenterSelection() {
  if (HasSelection()) {
    GetFrame()->Selection().RevealSelection(ScrollAlignment::CenterAlways());
  }
}

gfx::PointF WebLocalFrameImpl::GetScrollOffset() const {
  if (ScrollableArea* scrollable_area = LayoutViewport())
    return scrollable_area->ScrollPosition();
  return gfx::PointF();
}

void WebLocalFrameImpl::SetScrollOffset(const gfx::PointF& offset) {
  if (ScrollableArea* scrollable_area = LayoutViewport()) {
    scrollable_area->SetScrollOffset(
        scrollable_area->ScrollPositionToOffset(offset),
        mojom::blink::ScrollType::kProgrammatic);
  }
}

gfx::Size WebLocalFrameImpl::DocumentSize() const {
  if (!GetFrameView() || !GetFrameView()->GetLayoutView())
    return gfx::Size();

  return ToPixelSnappedRect(GetFrameView()->GetLayoutView()->DocumentRect())
      .size();
}

bool WebLocalFrameImpl::HasVisibleContent() const {
  auto* layout_object = GetFrame()->OwnerLayoutObject();
  if (layout_object &&
      layout_object->StyleRef().Visibility() != EVisibility::kVisible) {
    return false;
  }

  if (LocalFrameView* view = GetFrameView())
    return view->Width() > 0 && view->Height() > 0;
  return false;
}

gfx::Rect WebLocalFrameImpl::VisibleContentRect() const {
  if (LocalFrameView* view = GetFrameView())
    return view->LayoutViewport()->VisibleContentRect();
  return gfx::Rect();
}

WebView* WebLocalFrameImpl::View() const {
  return ViewImpl();
}

BrowserInterfaceBrokerProxy& WebLocalFrameImpl::GetBrowserInterfaceBroker() {
  return GetFrame()->GetBrowserInterfaceBroker();
}

WebDocument WebLocalFrameImpl::GetDocument() const {
  if (!GetFrame() || !GetFrame()->GetDocument())
    return WebDocument();
  return WebDocument(GetFrame()->GetDocument());
}

WebPerformanceMetricsForReporting
WebLocalFrameImpl::PerformanceMetricsForReporting() const {
  if (!GetFrame())
    return WebPerformanceMetricsForReporting();
  return WebPerformanceMetricsForReporting(
      DOMWindowPerformance::performance(*(GetFrame()->DomWindow())));
}

WebPerformanceMetricsForNestedContexts
WebLocalFrameImpl::PerformanceMetricsForNestedContexts() const {
  if (!GetFrame())
    return WebPerformanceMetricsForNestedContexts();
  return WebPerformanceMetricsForNestedContexts(
      DOMWindowPerformance::performance(*(GetFrame()->DomWindow())));
}

bool WebLocalFrameImpl::IsAdFrame() const {
  DCHECK(GetFrame());
  return GetFrame()->IsAdFrame();
}

bool WebLocalFrameImpl::IsAdScriptInStack() const {
  DCHECK(GetFrame());
  return GetFrame()->IsAdScriptInStack();
}

void WebLocalFrameImpl::SetAdEvidence(
    const blink::FrameAdEvidence& ad_evidence) {
  DCHECK(GetFrame());
  GetFrame()->SetAdEvidence(ad_evidence);
}

const std::optional<blink::FrameAdEvidence>& WebLocalFrameImpl::AdEvidence() {
  DCHECK(GetFrame());
  return GetFrame()->AdEvidence();
}

bool WebLocalFrameImpl::IsFrameCreatedByAdScript() {
  DCHECK(GetFrame());
  return GetFrame()->IsFrameCreatedByAdScript();
}

void WebLocalFrameImpl::ExecuteScript(const WebScriptSource& source) {
  DCHECK(GetFrame());
  ClassicScript::CreateUnspecifiedScript(source)->RunScript(
      GetFrame()->DomWindow());
}

void WebLocalFrameImpl::ExecuteScriptInIsolatedWorld(
    int32_t world_id,
    const WebScriptSource& source_in,
    BackForwardCacheAware back_forward_cache_aware) {
  DCHECK(GetFrame());
  CHECK_GT(world_id, DOMWrapperWorld::kMainWorldId);
  CHECK_LT(world_id, DOMWrapperWorld::kDOMWrapperWorldEmbedderWorldIdLimit);

  if (back_forward_cache_aware == BackForwardCacheAware::kPossiblyDisallow) {
    GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kInjectedJavascript,
        {SchedulingPolicy::DisableBackForwardCache()});
  }

  // Note: An error event in an isolated world will never be dispatched to
  // a foreign world.
  v8::HandleScope handle_scope(ToIsolate(GetFrame()));
  ClassicScript::CreateUnspecifiedScript(source_in,
                                         SanitizeScriptErrors::kDoNotSanitize)
      ->RunScriptInIsolatedWorldAndReturnValue(GetFrame()->DomWindow(),
                                               world_id);
}

v8::Local<v8::Value>
WebLocalFrameImpl::ExecuteScriptInIsolatedWorldAndReturnValue(
    int32_t world_id,
    const WebScriptSource& source_in,
    BackForwardCacheAware back_forward_cache_aware) {
  DCHECK(GetFrame());
  CHECK_GT(world_id, DOMWrapperWorld::kMainWorldId);
  CHECK_LT(world_id, DOMWrapperWorld::kDOMWrapperWorldEmbedderWorldIdLimit);

  if (back_forward_cache_aware == BackForwardCacheAware::kPossiblyDisallow) {
    GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kInjectedJavascript,
        {SchedulingPolicy::DisableBackForwardCache()});
  }

  // Note: An error event in an isolated world will never be dispatched to
  // a foreign world.
  return ClassicScript::CreateUnspecifiedScript(
             source_in, SanitizeScriptErrors::kDoNotSanitize)
      ->RunScriptInIsolatedWorldAndReturnValue(GetFrame()->DomWindow(),
                                               world_id)
      .GetSuccessValueOrEmpty();
}

void WebLocalFrameImpl::ClearIsolatedWorldCSPForTesting(int32_t world_id) {
  if (!GetFrame())
    return;
  if (world_id <= DOMWrapperWorld::kMainWorldId ||
      world_id >= DOMWrapperWorld::kDOMWrapperWorldEmbedderWorldIdLimit) {
    return;
  }

  GetFrame()->DomWindow()->ClearIsolatedWorldCSPForTesting(world_id);
}

void WebLocalFrameImpl::Alert(const WebString& message) {
  DCHECK(GetFrame());
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  GetFrame()->DomWindow()->alert(script_state, message);
}

bool WebLocalFrameImpl::Confirm(const WebString& message) {
  DCHECK(GetFrame());
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  return GetFrame()->DomWindow()->confirm(script_state, message);
}

WebString WebLocalFrameImpl::Prompt(const WebString& message,
                                    const WebString& default_value) {
  DCHECK(GetFrame());
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  return GetFrame()->DomWindow()->prompt(script_state, message, default_value);
}

void WebLocalFrameImpl::GenerateInterventionReport(const WebString& message_id,
                                                   const WebString& message) {
  DCHECK(GetFrame());
  Intervention::GenerateReport(GetFrame(), message_id, message);
}

void WebLocalFrameImpl::CollectGarbageForTesting() {
  if (!GetFrame())
    return;
  if (!GetFrame()->GetSettings()->GetScriptEnabled())
    return;
  ThreadState::Current()->CollectAllGarbageForTesting();
}

v8::MaybeLocal<v8::Value> WebLocalFrameImpl::ExecuteMethodAndReturnValue(
    v8::Local<v8::Function> function,
    v8::Local<v8::Value> receiver,
    int argc,
    v8::Local<v8::Value> argv[]) {
  DCHECK(GetFrame());

  return GetFrame()
      ->DomWindow()
      ->GetScriptController()
      .EvaluateMethodInMainWorld(function, receiver, argc, argv);
}

v8::Local<v8::Value> WebLocalFrameImpl::ExecuteScriptAndReturnValue(
    const WebScriptSource& source) {
  DCHECK(GetFrame());
  return ClassicScript::CreateUnspecifiedScript(source)
      ->RunScriptAndReturnValue(GetFrame()->DomWindow())
      .GetSuccessValueOrEmpty();
}

void WebLocalFrameImpl::RequestExecuteV8Function(
    v8::Local<v8::Context> context,
    v8::Local<v8::Function> function,
    v8::Local<v8::Value> receiver,
    int argc,
    v8::Local<v8::Value> argv[],
    WebScriptExecutionCallback callback) {
  DCHECK(GetFrame());
  const auto want_result_option =
      callback ? mojom::blink::WantResultOption::kWantResult
               : mojom::blink::WantResultOption::kNoResult;
  PausableScriptExecutor::CreateAndRun(context, function, receiver, argc, argv,
                                       want_result_option, std::move(callback));
}

void WebLocalFrameImpl::RequestExecuteScript(
    int32_t world_id,
    base::span<const WebScriptSource> sources,
    mojom::blink::UserActivationOption user_gesture,
    mojom::blink::EvaluationTiming evaluation_timing,
    mojom::blink::LoadEventBlockingOption blocking_option,
    WebScriptExecutionCallback callback,
    BackForwardCacheAware back_forward_cache_aware,
    mojom::blink::WantResultOption want_result_option,
    mojom::blink::PromiseResultOption promise_behavior) {
  DCHECK(GetFrame());
  GetFrame()->RequestExecuteScript(
      world_id, sources, user_gesture, evaluation_timing, blocking_option,
      std::move(callback), back_forward_cache_aware, want_result_option,
      promise_behavior);
}

bool WebLocalFrameImpl::IsInspectorConnected() {
  return LocalRoot()->DevToolsAgentImpl(/*create_if_necessary=*/false);
}

v8::MaybeLocal<v8::Value> WebLocalFrameImpl::CallFunctionEvenIfScriptDisabled(
    v8::Local<v8::Function> function,
    v8::Local<v8::Value> receiver,
    int argc,
    v8::Local<v8::Value> argv[]) {
  DCHECK(GetFrame());
  return V8ScriptRunner::CallFunction(
      function, GetFrame()->DomWindow(), receiver, argc,
      static_cast<v8::Local<v8::Value>*>(argv), ToIsolate(GetFrame()));
}

v8::Local<v8::Context> WebLocalFrameImpl::MainWorldScriptContext() const {
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  return script_state->GetContext();
}

int32_t WebLocalFrameImpl::GetScriptContextWorldId(
    v8::Local<v8::Context> script_context) const {
  DCHECK_EQ(this, FrameForContext(script_context));
  v8::Isolate* isolate = script_context->GetIsolate();
  return DOMWrapperWorld::World(isolate, script_context).GetWorldId();
}

v8::Local<v8::Context> WebLocalFrameImpl::GetScriptContextFromWorldId(
    v8::Isolate* isolate,
    int world_id) const {
  DOMWrapperWorld* world =
      DOMWrapperWorld::EnsureIsolatedWorld(isolate, world_id);
  return ToScriptState(GetFrame(), *world)->GetContext();
}

v8::Local<v8::Object> WebLocalFrameImpl::GlobalProxy(
    v8::Isolate* isolate) const {
  return MainWorldScriptContext()->Global();
}

bool WebFrame::ScriptCanAccess(v8::Isolate* isolate, WebFrame* target) {
  return BindingSecurity::ShouldAllowAccessTo(
      CurrentDOMWindow(isolate), ToCoreFrame(*target)->DomWindow());
}

void WebLocalFrameImpl::StartReload(WebFrameLoadType frame_load_type) {
  // TODO(clamy): Remove this function once RenderFrame calls StartNavigation
  // for all requests.
  DCHECK(GetFrame());
  DCHECK(IsReloadLoadType(frame_load_type));
  TRACE_EVENT1("navigation", "WebLocalFrameImpl::StartReload", "load_type",
               static_cast<int>(frame_load_type));

  ResourceRequest request =
      GetFrame()->Loader().ResourceRequestForReload(frame_load_type);
  if (request.IsNull())
    return;
  if (GetTextFinder())
    GetTextFinder()->ClearActiveFindMatch();

  FrameLoadRequest frame_load_request(GetFrame()->DomWindow(), request);
  GetFrame()->Loader().StartNavigation(frame_load_request, frame_load_type);
}

void WebLocalFrameImpl::ReloadImage(const WebNode& web_node) {
  Node* node = web_node;  // Use implicit WebNode->Node* cast.
  HitTestResult hit_test_result;
  hit_test_result.SetInnerNode(node);
  hit_test_result.SetToShadowHostIfInUAShadowRoot();
  node = hit_test_result.InnerNodeOrImageMapImage();
  if (auto* image_element = DynamicTo<HTMLImageElement>(*node))
    image_element->ForceReload();
}

void WebLocalFrameImpl::ClearActiveFindMatchForTesting() {
  DCHECK(GetFrame());
  if (GetTextFinder())
    GetTextFinder()->ClearActiveFindMatch();
}

WebDocumentLoader* WebLocalFrameImpl::GetDocumentLoader() const {
  DCHECK(GetFrame());
  return GetFrame()->Loader().GetDocumentLoader();
}

void WebLocalFrameImpl::EnableViewSourceMode(bool enable) {
  if (GetFrame())
    GetFrame()->SetInViewSourceMode(enable);
}

bool WebLocalFrameImpl::IsViewSourceModeEnabled() const {
  if (!GetFrame())
    return false;
  return GetFrame()->InViewSourceMode();
}

void WebLocalFrameImpl::SetReferrerForRequest(WebURLRequest& request,
                                              const WebURL& referrer_url) {
  String referrer = referrer_url.IsEmpty()
                        ? GetFrame()->DomWindow()->OutgoingReferrer()
                        : String(referrer_url.GetString());
  ResourceRequest& resource_request = request.ToMutableResourceRequest();
  resource_request.SetReferrerPolicy(
      GetFrame()->DomWindow()->GetReferrerPolicy());
  resource_request.SetReferrerString(referrer);
}

std::unique_ptr<WebAssociatedURLLoader>
WebLocalFrameImpl::CreateAssociatedURLLoader(
    const WebAssociatedURLLoaderOptions& options) {
  return std::make_unique<WebAssociatedURLLoaderImpl>(GetFrame()->DomWindow(),
                                                      options);
}

void WebLocalFrameImpl::DeprecatedStopLoading() {
  if (!GetFrame())
    return;
  // FIXME: Figure out what we should really do here. It seems like a bug
  // that FrameLoader::stopLoading doesn't call stopAllLoaders.
  GetFrame()->Loader().StopAllLoaders(/*abort_client=*/true);
}

void WebLocalFrameImpl::ReplaceSelection(const WebString& text) {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  GetFrame()->GetEditor().ReplaceSelection(text);
}

void WebLocalFrameImpl::UnmarkText() {
  GetFrame()->GetInputMethodController().CancelComposition();
}

bool WebLocalFrameImpl::HasMarkedText() const {
  return GetFrame()->GetInputMethodController().HasComposition();
}

WebRange WebLocalFrameImpl::MarkedRange() const {
  return GetFrame()->GetInputMethodController().CompositionEphemeralRange();
}

bool WebLocalFrameImpl::FirstRectForCharacterRange(
    uint32_t location,
    uint32_t length,
    gfx::Rect& rect_in_viewport) const {
  if ((location + length < location) && (location + length))
    length = 0;

  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    return edit_context->FirstRectForCharacterRange(location, length,
                                                    rect_in_viewport);
  }

  Element* editable =
      GetFrame()->Selection().RootEditableElementOrDocumentElement();
  if (!editable)
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  editable->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  const EphemeralRange range =
      PlainTextRange(location, location + length).CreateRange(*editable);
  if (range.IsNull())
    return false;
  rect_in_viewport =
      GetFrame()->View()->FrameToViewport(FirstRectForRange(range));
  return true;
}

bool WebLocalFrameImpl::ExecuteCommand(const WebString& name) {
  DCHECK(GetFrame());

  if (name.length() <= 2)
    return false;

  // Since we don't have NSControl, we will convert the format of command
  // string and call the function on Editor directly.
  String command = name;

  // Make sure the first letter is upper case.
  command.replace(0, 1, command.Substring(0, 1).UpperASCII());

  // Remove the trailing ':' if existing.
  if (command[command.length() - 1] == UChar(':'))
    command = command.Substring(0, command.length() - 1);

  Node* plugin_lookup_context_node = nullptr;
  if (WebPluginContainerImpl::SupportsCommand(name))
    plugin_lookup_context_node = ContextMenuNodeInner();

  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer(plugin_lookup_context_node);
  if (plugin_container && plugin_container->ExecuteEditCommand(name))
    return true;

  return GetFrame()->GetEditor().ExecuteCommand(command);
}

bool WebLocalFrameImpl::ExecuteCommand(const WebString& name,
                                       const WebString& value) {
  DCHECK(GetFrame());

  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container && plugin_container->ExecuteEditCommand(name, value))
    return true;

  return GetFrame()->GetEditor().ExecuteCommand(name, value);
}

bool WebLocalFrameImpl::IsCommandEnabled(const WebString& name) const {
  DCHECK(GetFrame());
  return GetFrame()->GetEditor().IsCommandEnabled(name);
}

bool WebLocalFrameImpl::SelectionTextDirection(
    base::i18n::TextDirection& start,
    base::i18n::TextDirection& end) const {
  FrameSelection& selection = frame_->Selection();
  if (!selection.IsAvailable()) {
    // plugins/mouse-capture-inside-shadow.html reaches here
    return false;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  if (selection.ComputeVisibleSelectionInDOMTree()
          .ToNormalizedEphemeralRange()
          .IsNull())
    return false;
  start = ToBaseTextDirection(PrimaryDirectionOf(
      *selection.ComputeVisibleSelectionInDOMTree().Start().AnchorNode()));
  end = ToBaseTextDirection(PrimaryDirectionOf(
      *selection.ComputeVisibleSelectionInDOMTree().End().AnchorNode()));
  return true;
}

bool WebLocalFrameImpl::IsSelectionAnchorFirst() const {
  FrameSelection& selection = frame_->Selection();
  if (!selection.IsAvailable()) {
    // plugins/mouse-capture-inside-shadow.html reaches here
    return false;
  }

  return selection.GetSelectionInDOMTree().IsAnchorFirst();
}

void WebLocalFrameImpl::SetTextDirectionForTesting(
    base::i18n::TextDirection direction) {
  frame_->SetTextDirection(direction);
}

void WebLocalFrameImpl::ReplaceMisspelledRange(const WebString& text) {
  // If this caret selection has two or more markers, this function replace the
  // range covered by the first marker with the specified word as Microsoft Word
  // does.
  if (GetFrame()->GetWebPluginContainer())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSpellCheck);

  GetFrame()->GetSpellChecker().ReplaceMisspelledRange(text);
}

void WebLocalFrameImpl::RemoveSpellingMarkers() {
  GetFrame()->GetSpellChecker().RemoveSpellingMarkers();
}

void WebLocalFrameImpl::RemoveSpellingMarkersUnderWords(
    const WebVector<WebString>& words) {
  Vector<String> converted_words;
  converted_words.AppendSpan(base::span(words));
  GetFrame()->RemoveSpellingMarkersUnderWords(converted_words);
}

bool WebLocalFrameImpl::HasSelection() const {
  DCHECK(GetFrame());
  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container)
    return plugin_container->Plugin()->HasSelection();

  // TODO(editing-dev): The use of UpdateStyleAndLayoutIgnorePendingStylesheets
  // needs to be audited. See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);
  return GetFrame()->Selection().ComputeVisibleSelectionInDOMTree().IsRange();
}

WebRange WebLocalFrameImpl::SelectionRange() const {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  return GetFrame()
      ->Selection()
      .ComputeVisibleSelectionInDOMTree()
      .ToNormalizedEphemeralRange();
}

WebString WebLocalFrameImpl::SelectionAsText() const {
  DCHECK(GetFrame());
  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container)
    return plugin_container->Plugin()->SelectionAsText();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  String text;
  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    text = edit_context->text().Substring(
        edit_context->selectionStart(),
        edit_context->selectionEnd() - edit_context->selectionStart());
  } else {
    text = GetFrame()->Selection().SelectedText(
        TextIteratorBehavior::EmitsObjectReplacementCharacterBehavior());
  }
#if BUILDFLAG(IS_WIN)
  ReplaceNewlinesWithWindowsStyleNewlines(text);
#endif
  ReplaceNBSPWithSpace(text);
  return text;
}

WebString WebLocalFrameImpl::SelectionAsMarkup() const {
  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container)
    return plugin_container->Plugin()->SelectionAsMarkup();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  // Selection normalization and markup generation require clean layout.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  return GetFrame()->Selection().SelectedHTMLForClipboard();
}

void WebLocalFrameImpl::TextSelectionChanged(const WebString& selection_text,
                                             uint32_t offset,
                                             const gfx::Range& range) {
  GetFrame()->TextSelectionChanged(selection_text, offset, range);
}

bool WebLocalFrameImpl::SelectAroundCaret(
    mojom::blink::SelectionGranularity granularity,
    bool should_show_handle,
    bool should_show_context_menu) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::selectAroundCaret");

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);
  // TODO(1275801): Add mapping between the enums once it becomes possible to
  // do so.
  blink::TextGranularity text_granularity;
  switch (granularity) {
    case mojom::blink::SelectionGranularity::kWord:
      text_granularity = blink::TextGranularity::kWord;
      break;
    case mojom::blink::SelectionGranularity::kSentence:
      text_granularity = blink::TextGranularity::kSentence;
      break;
  }
  return GetFrame()->Selection().SelectAroundCaret(
      text_granularity,
      should_show_handle ? HandleVisibility::kVisible
                         : HandleVisibility::kNotVisible,
      should_show_context_menu ? ContextMenuVisibility ::kVisible
                               : ContextMenuVisibility ::kNotVisible);
}

EphemeralRange WebLocalFrameImpl::GetWordSelectionRangeAroundCaret() const {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::getWordSelectionRangeAroundCaret");
  return GetFrame()->Selection().GetWordSelectionRangeAroundCaret();
}

void WebLocalFrameImpl::SelectRange(const gfx::Point& base_in_viewport,
                                    const gfx::Point& extent_in_viewport) {
  MoveRangeSelection(base_in_viewport, extent_in_viewport);
}

void WebLocalFrameImpl::SelectRange(
    const WebRange& web_range,
    HandleVisibilityBehavior handle_visibility_behavior,
    blink::mojom::SelectionMenuBehavior selection_menu_behavior,
    SelectionSetFocusBehavior selection_set_focus_behavior) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::selectRange");

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  const EphemeralRange& range = web_range.CreateEphemeralRange(GetFrame());
  if (range.IsNull())
    return;

  FrameSelection& selection = GetFrame()->Selection();
  const bool show_handles =
      handle_visibility_behavior == kShowSelectionHandle ||
      (handle_visibility_behavior == kPreserveHandleVisibility &&
       selection.IsHandleVisible());
  using blink::mojom::SelectionMenuBehavior;
  const bool selection_not_set_focus =
      selection_set_focus_behavior == kSelectionDoNotSetFocus;
  selection.SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(range)
          .SetAffinity(TextAffinity::kDefault
### 提示词
```
这是目录为blink/renderer/core/frame/web_local_frame_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
likely]] {
    return nullptr;
  }
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  if (context.IsEmpty())
    return nullptr;
  return FrameForContext(context);
}

void WebLocalFrameImpl::NotifyUserActivation(
    mojom::blink::UserActivationNotificationType notification_type) {
  LocalFrame::NotifyUserActivation(GetFrame(), notification_type);
}

bool WebLocalFrameImpl::HasStickyUserActivation() {
  return GetFrame()->HasStickyUserActivation();
}

bool WebLocalFrameImpl::HasTransientUserActivation() {
  return LocalFrame::HasTransientUserActivation(GetFrame());
}

bool WebLocalFrameImpl::ConsumeTransientUserActivation(
    UserActivationUpdateSource update_source) {
  return LocalFrame::ConsumeTransientUserActivation(GetFrame(), update_source);
}

bool WebLocalFrameImpl::LastActivationWasRestricted() const {
  return GetFrame()->LastActivationWasRestricted();
}

#if BUILDFLAG(IS_WIN)
WebFontFamilyNames WebLocalFrameImpl::GetWebFontFamilyNames() const {
  FontFamilyNames font_family_names;
  GetFontsUsedByFrame(*GetFrame(), font_family_names);
  WebFontFamilyNames result;
  for (const String& font_family_name : font_family_names.font_names) {
    result.font_names.push_back(font_family_name);
  }
  return result;
}
#endif

WebLocalFrame* WebLocalFrame::FrameForContext(v8::Local<v8::Context> context) {
  return WebLocalFrameImpl::FromFrame(ToLocalFrameIfNotDetached(context));
}

bool WebLocalFrameImpl::IsWebLocalFrame() const {
  return true;
}

WebLocalFrame* WebLocalFrameImpl::ToWebLocalFrame() {
  return this;
}

const WebLocalFrame* WebLocalFrameImpl::ToWebLocalFrame() const {
  return this;
}

bool WebLocalFrameImpl::IsWebRemoteFrame() const {
  return false;
}

WebRemoteFrame* WebLocalFrameImpl::ToWebRemoteFrame() {
  NOTREACHED();
}

const WebRemoteFrame* WebLocalFrameImpl::ToWebRemoteFrame() const {
  NOTREACHED();
}

void WebLocalFrameImpl::Close(DetachReason detach_reason) {
  WebLocalFrame::Close(detach_reason);

  if (frame_widget_) {
    frame_widget_->Close(detach_reason);
    frame_widget_ = nullptr;
  }

  client_ = nullptr;

  if (dev_tools_agent_)
    dev_tools_agent_.Clear();

  self_keep_alive_.Clear();

  if (print_context_)
    PrintEnd();
  print_client_.reset();
#if DCHECK_IS_ON()
  is_in_printing_ = false;
#endif
}

WebString WebLocalFrameImpl::AssignedName() const {
  return GetFrame()->Tree().GetName();
}

ui::AXTreeID WebLocalFrameImpl::GetAXTreeID() const {
  const std::optional<base::UnguessableToken>& embedding_token =
      GetEmbeddingToken();
  if (embedding_token && !embedding_token->is_empty())
    return ui::AXTreeID::FromToken(embedding_token.value());
  return ui::AXTreeIDUnknown();
}

void WebLocalFrameImpl::SetName(const WebString& name) {
  GetFrame()->Tree().SetName(name, FrameTree::kReplicate);
}

WebContentSettingsClient* WebLocalFrameImpl::GetContentSettingsClient() const {
  return content_settings_client_;
}

void WebLocalFrameImpl::SetContentSettingsClient(
    WebContentSettingsClient* client) {
  content_settings_client_ = client;
}

ScrollableArea* WebLocalFrameImpl::LayoutViewport() const {
  if (LocalFrameView* view = GetFrameView())
    return view->LayoutViewport();
  return nullptr;
}

bool WebLocalFrameImpl::IsFocused() const {
  if (!ViewImpl() || !ViewImpl()->GetPage())
    return false;

  return this ==
         WebFrame::FromCoreFrame(
             ViewImpl()->GetPage()->GetFocusController().FocusedFrame());
}

bool WebLocalFrameImpl::DispatchedPagehideAndStillHidden() const {
  // Dispatching pagehide is the first step in unloading, so we must have
  // already dispatched pagehide if unload had started.
  if (GetFrame() && GetFrame()->GetDocument() &&
      GetFrame()->GetDocument()->UnloadStarted()) {
    return true;
  }
  if (!ViewImpl() || !ViewImpl()->GetPage())
    return false;
  // We might have dispatched pagehide without unloading the document.
  return ViewImpl()->GetPage()->DispatchedPagehideAndStillHidden();
}

void WebLocalFrameImpl::CopyToFindPboard() {
#if BUILDFLAG(IS_MAC)
  if (HasSelection())
    GetFrame()->GetSystemClipboard()->CopyToFindPboard(SelectionAsText());
#endif
}

void WebLocalFrameImpl::CenterSelection() {
  if (HasSelection()) {
    GetFrame()->Selection().RevealSelection(ScrollAlignment::CenterAlways());
  }
}

gfx::PointF WebLocalFrameImpl::GetScrollOffset() const {
  if (ScrollableArea* scrollable_area = LayoutViewport())
    return scrollable_area->ScrollPosition();
  return gfx::PointF();
}

void WebLocalFrameImpl::SetScrollOffset(const gfx::PointF& offset) {
  if (ScrollableArea* scrollable_area = LayoutViewport()) {
    scrollable_area->SetScrollOffset(
        scrollable_area->ScrollPositionToOffset(offset),
        mojom::blink::ScrollType::kProgrammatic);
  }
}

gfx::Size WebLocalFrameImpl::DocumentSize() const {
  if (!GetFrameView() || !GetFrameView()->GetLayoutView())
    return gfx::Size();

  return ToPixelSnappedRect(GetFrameView()->GetLayoutView()->DocumentRect())
      .size();
}

bool WebLocalFrameImpl::HasVisibleContent() const {
  auto* layout_object = GetFrame()->OwnerLayoutObject();
  if (layout_object &&
      layout_object->StyleRef().Visibility() != EVisibility::kVisible) {
    return false;
  }

  if (LocalFrameView* view = GetFrameView())
    return view->Width() > 0 && view->Height() > 0;
  return false;
}

gfx::Rect WebLocalFrameImpl::VisibleContentRect() const {
  if (LocalFrameView* view = GetFrameView())
    return view->LayoutViewport()->VisibleContentRect();
  return gfx::Rect();
}

WebView* WebLocalFrameImpl::View() const {
  return ViewImpl();
}

BrowserInterfaceBrokerProxy& WebLocalFrameImpl::GetBrowserInterfaceBroker() {
  return GetFrame()->GetBrowserInterfaceBroker();
}

WebDocument WebLocalFrameImpl::GetDocument() const {
  if (!GetFrame() || !GetFrame()->GetDocument())
    return WebDocument();
  return WebDocument(GetFrame()->GetDocument());
}

WebPerformanceMetricsForReporting
WebLocalFrameImpl::PerformanceMetricsForReporting() const {
  if (!GetFrame())
    return WebPerformanceMetricsForReporting();
  return WebPerformanceMetricsForReporting(
      DOMWindowPerformance::performance(*(GetFrame()->DomWindow())));
}

WebPerformanceMetricsForNestedContexts
WebLocalFrameImpl::PerformanceMetricsForNestedContexts() const {
  if (!GetFrame())
    return WebPerformanceMetricsForNestedContexts();
  return WebPerformanceMetricsForNestedContexts(
      DOMWindowPerformance::performance(*(GetFrame()->DomWindow())));
}

bool WebLocalFrameImpl::IsAdFrame() const {
  DCHECK(GetFrame());
  return GetFrame()->IsAdFrame();
}

bool WebLocalFrameImpl::IsAdScriptInStack() const {
  DCHECK(GetFrame());
  return GetFrame()->IsAdScriptInStack();
}

void WebLocalFrameImpl::SetAdEvidence(
    const blink::FrameAdEvidence& ad_evidence) {
  DCHECK(GetFrame());
  GetFrame()->SetAdEvidence(ad_evidence);
}

const std::optional<blink::FrameAdEvidence>& WebLocalFrameImpl::AdEvidence() {
  DCHECK(GetFrame());
  return GetFrame()->AdEvidence();
}

bool WebLocalFrameImpl::IsFrameCreatedByAdScript() {
  DCHECK(GetFrame());
  return GetFrame()->IsFrameCreatedByAdScript();
}

void WebLocalFrameImpl::ExecuteScript(const WebScriptSource& source) {
  DCHECK(GetFrame());
  ClassicScript::CreateUnspecifiedScript(source)->RunScript(
      GetFrame()->DomWindow());
}

void WebLocalFrameImpl::ExecuteScriptInIsolatedWorld(
    int32_t world_id,
    const WebScriptSource& source_in,
    BackForwardCacheAware back_forward_cache_aware) {
  DCHECK(GetFrame());
  CHECK_GT(world_id, DOMWrapperWorld::kMainWorldId);
  CHECK_LT(world_id, DOMWrapperWorld::kDOMWrapperWorldEmbedderWorldIdLimit);

  if (back_forward_cache_aware == BackForwardCacheAware::kPossiblyDisallow) {
    GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kInjectedJavascript,
        {SchedulingPolicy::DisableBackForwardCache()});
  }

  // Note: An error event in an isolated world will never be dispatched to
  // a foreign world.
  v8::HandleScope handle_scope(ToIsolate(GetFrame()));
  ClassicScript::CreateUnspecifiedScript(source_in,
                                         SanitizeScriptErrors::kDoNotSanitize)
      ->RunScriptInIsolatedWorldAndReturnValue(GetFrame()->DomWindow(),
                                               world_id);
}

v8::Local<v8::Value>
WebLocalFrameImpl::ExecuteScriptInIsolatedWorldAndReturnValue(
    int32_t world_id,
    const WebScriptSource& source_in,
    BackForwardCacheAware back_forward_cache_aware) {
  DCHECK(GetFrame());
  CHECK_GT(world_id, DOMWrapperWorld::kMainWorldId);
  CHECK_LT(world_id, DOMWrapperWorld::kDOMWrapperWorldEmbedderWorldIdLimit);

  if (back_forward_cache_aware == BackForwardCacheAware::kPossiblyDisallow) {
    GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kInjectedJavascript,
        {SchedulingPolicy::DisableBackForwardCache()});
  }

  // Note: An error event in an isolated world will never be dispatched to
  // a foreign world.
  return ClassicScript::CreateUnspecifiedScript(
             source_in, SanitizeScriptErrors::kDoNotSanitize)
      ->RunScriptInIsolatedWorldAndReturnValue(GetFrame()->DomWindow(),
                                               world_id)
      .GetSuccessValueOrEmpty();
}

void WebLocalFrameImpl::ClearIsolatedWorldCSPForTesting(int32_t world_id) {
  if (!GetFrame())
    return;
  if (world_id <= DOMWrapperWorld::kMainWorldId ||
      world_id >= DOMWrapperWorld::kDOMWrapperWorldEmbedderWorldIdLimit) {
    return;
  }

  GetFrame()->DomWindow()->ClearIsolatedWorldCSPForTesting(world_id);
}

void WebLocalFrameImpl::Alert(const WebString& message) {
  DCHECK(GetFrame());
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  GetFrame()->DomWindow()->alert(script_state, message);
}

bool WebLocalFrameImpl::Confirm(const WebString& message) {
  DCHECK(GetFrame());
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  return GetFrame()->DomWindow()->confirm(script_state, message);
}

WebString WebLocalFrameImpl::Prompt(const WebString& message,
                                    const WebString& default_value) {
  DCHECK(GetFrame());
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  return GetFrame()->DomWindow()->prompt(script_state, message, default_value);
}

void WebLocalFrameImpl::GenerateInterventionReport(const WebString& message_id,
                                                   const WebString& message) {
  DCHECK(GetFrame());
  Intervention::GenerateReport(GetFrame(), message_id, message);
}

void WebLocalFrameImpl::CollectGarbageForTesting() {
  if (!GetFrame())
    return;
  if (!GetFrame()->GetSettings()->GetScriptEnabled())
    return;
  ThreadState::Current()->CollectAllGarbageForTesting();
}

v8::MaybeLocal<v8::Value> WebLocalFrameImpl::ExecuteMethodAndReturnValue(
    v8::Local<v8::Function> function,
    v8::Local<v8::Value> receiver,
    int argc,
    v8::Local<v8::Value> argv[]) {
  DCHECK(GetFrame());

  return GetFrame()
      ->DomWindow()
      ->GetScriptController()
      .EvaluateMethodInMainWorld(function, receiver, argc, argv);
}

v8::Local<v8::Value> WebLocalFrameImpl::ExecuteScriptAndReturnValue(
    const WebScriptSource& source) {
  DCHECK(GetFrame());
  return ClassicScript::CreateUnspecifiedScript(source)
      ->RunScriptAndReturnValue(GetFrame()->DomWindow())
      .GetSuccessValueOrEmpty();
}

void WebLocalFrameImpl::RequestExecuteV8Function(
    v8::Local<v8::Context> context,
    v8::Local<v8::Function> function,
    v8::Local<v8::Value> receiver,
    int argc,
    v8::Local<v8::Value> argv[],
    WebScriptExecutionCallback callback) {
  DCHECK(GetFrame());
  const auto want_result_option =
      callback ? mojom::blink::WantResultOption::kWantResult
               : mojom::blink::WantResultOption::kNoResult;
  PausableScriptExecutor::CreateAndRun(context, function, receiver, argc, argv,
                                       want_result_option, std::move(callback));
}

void WebLocalFrameImpl::RequestExecuteScript(
    int32_t world_id,
    base::span<const WebScriptSource> sources,
    mojom::blink::UserActivationOption user_gesture,
    mojom::blink::EvaluationTiming evaluation_timing,
    mojom::blink::LoadEventBlockingOption blocking_option,
    WebScriptExecutionCallback callback,
    BackForwardCacheAware back_forward_cache_aware,
    mojom::blink::WantResultOption want_result_option,
    mojom::blink::PromiseResultOption promise_behavior) {
  DCHECK(GetFrame());
  GetFrame()->RequestExecuteScript(
      world_id, sources, user_gesture, evaluation_timing, blocking_option,
      std::move(callback), back_forward_cache_aware, want_result_option,
      promise_behavior);
}

bool WebLocalFrameImpl::IsInspectorConnected() {
  return LocalRoot()->DevToolsAgentImpl(/*create_if_necessary=*/false);
}

v8::MaybeLocal<v8::Value> WebLocalFrameImpl::CallFunctionEvenIfScriptDisabled(
    v8::Local<v8::Function> function,
    v8::Local<v8::Value> receiver,
    int argc,
    v8::Local<v8::Value> argv[]) {
  DCHECK(GetFrame());
  return V8ScriptRunner::CallFunction(
      function, GetFrame()->DomWindow(), receiver, argc,
      static_cast<v8::Local<v8::Value>*>(argv), ToIsolate(GetFrame()));
}

v8::Local<v8::Context> WebLocalFrameImpl::MainWorldScriptContext() const {
  ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
  DCHECK(script_state);
  return script_state->GetContext();
}

int32_t WebLocalFrameImpl::GetScriptContextWorldId(
    v8::Local<v8::Context> script_context) const {
  DCHECK_EQ(this, FrameForContext(script_context));
  v8::Isolate* isolate = script_context->GetIsolate();
  return DOMWrapperWorld::World(isolate, script_context).GetWorldId();
}

v8::Local<v8::Context> WebLocalFrameImpl::GetScriptContextFromWorldId(
    v8::Isolate* isolate,
    int world_id) const {
  DOMWrapperWorld* world =
      DOMWrapperWorld::EnsureIsolatedWorld(isolate, world_id);
  return ToScriptState(GetFrame(), *world)->GetContext();
}

v8::Local<v8::Object> WebLocalFrameImpl::GlobalProxy(
    v8::Isolate* isolate) const {
  return MainWorldScriptContext()->Global();
}

bool WebFrame::ScriptCanAccess(v8::Isolate* isolate, WebFrame* target) {
  return BindingSecurity::ShouldAllowAccessTo(
      CurrentDOMWindow(isolate), ToCoreFrame(*target)->DomWindow());
}

void WebLocalFrameImpl::StartReload(WebFrameLoadType frame_load_type) {
  // TODO(clamy): Remove this function once RenderFrame calls StartNavigation
  // for all requests.
  DCHECK(GetFrame());
  DCHECK(IsReloadLoadType(frame_load_type));
  TRACE_EVENT1("navigation", "WebLocalFrameImpl::StartReload", "load_type",
               static_cast<int>(frame_load_type));

  ResourceRequest request =
      GetFrame()->Loader().ResourceRequestForReload(frame_load_type);
  if (request.IsNull())
    return;
  if (GetTextFinder())
    GetTextFinder()->ClearActiveFindMatch();

  FrameLoadRequest frame_load_request(GetFrame()->DomWindow(), request);
  GetFrame()->Loader().StartNavigation(frame_load_request, frame_load_type);
}

void WebLocalFrameImpl::ReloadImage(const WebNode& web_node) {
  Node* node = web_node;  // Use implicit WebNode->Node* cast.
  HitTestResult hit_test_result;
  hit_test_result.SetInnerNode(node);
  hit_test_result.SetToShadowHostIfInUAShadowRoot();
  node = hit_test_result.InnerNodeOrImageMapImage();
  if (auto* image_element = DynamicTo<HTMLImageElement>(*node))
    image_element->ForceReload();
}

void WebLocalFrameImpl::ClearActiveFindMatchForTesting() {
  DCHECK(GetFrame());
  if (GetTextFinder())
    GetTextFinder()->ClearActiveFindMatch();
}

WebDocumentLoader* WebLocalFrameImpl::GetDocumentLoader() const {
  DCHECK(GetFrame());
  return GetFrame()->Loader().GetDocumentLoader();
}

void WebLocalFrameImpl::EnableViewSourceMode(bool enable) {
  if (GetFrame())
    GetFrame()->SetInViewSourceMode(enable);
}

bool WebLocalFrameImpl::IsViewSourceModeEnabled() const {
  if (!GetFrame())
    return false;
  return GetFrame()->InViewSourceMode();
}

void WebLocalFrameImpl::SetReferrerForRequest(WebURLRequest& request,
                                              const WebURL& referrer_url) {
  String referrer = referrer_url.IsEmpty()
                        ? GetFrame()->DomWindow()->OutgoingReferrer()
                        : String(referrer_url.GetString());
  ResourceRequest& resource_request = request.ToMutableResourceRequest();
  resource_request.SetReferrerPolicy(
      GetFrame()->DomWindow()->GetReferrerPolicy());
  resource_request.SetReferrerString(referrer);
}

std::unique_ptr<WebAssociatedURLLoader>
WebLocalFrameImpl::CreateAssociatedURLLoader(
    const WebAssociatedURLLoaderOptions& options) {
  return std::make_unique<WebAssociatedURLLoaderImpl>(GetFrame()->DomWindow(),
                                                      options);
}

void WebLocalFrameImpl::DeprecatedStopLoading() {
  if (!GetFrame())
    return;
  // FIXME: Figure out what we should really do here. It seems like a bug
  // that FrameLoader::stopLoading doesn't call stopAllLoaders.
  GetFrame()->Loader().StopAllLoaders(/*abort_client=*/true);
}

void WebLocalFrameImpl::ReplaceSelection(const WebString& text) {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  GetFrame()->GetEditor().ReplaceSelection(text);
}

void WebLocalFrameImpl::UnmarkText() {
  GetFrame()->GetInputMethodController().CancelComposition();
}

bool WebLocalFrameImpl::HasMarkedText() const {
  return GetFrame()->GetInputMethodController().HasComposition();
}

WebRange WebLocalFrameImpl::MarkedRange() const {
  return GetFrame()->GetInputMethodController().CompositionEphemeralRange();
}

bool WebLocalFrameImpl::FirstRectForCharacterRange(
    uint32_t location,
    uint32_t length,
    gfx::Rect& rect_in_viewport) const {
  if ((location + length < location) && (location + length))
    length = 0;

  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    return edit_context->FirstRectForCharacterRange(location, length,
                                                    rect_in_viewport);
  }

  Element* editable =
      GetFrame()->Selection().RootEditableElementOrDocumentElement();
  if (!editable)
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  editable->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  const EphemeralRange range =
      PlainTextRange(location, location + length).CreateRange(*editable);
  if (range.IsNull())
    return false;
  rect_in_viewport =
      GetFrame()->View()->FrameToViewport(FirstRectForRange(range));
  return true;
}

bool WebLocalFrameImpl::ExecuteCommand(const WebString& name) {
  DCHECK(GetFrame());

  if (name.length() <= 2)
    return false;

  // Since we don't have NSControl, we will convert the format of command
  // string and call the function on Editor directly.
  String command = name;

  // Make sure the first letter is upper case.
  command.replace(0, 1, command.Substring(0, 1).UpperASCII());

  // Remove the trailing ':' if existing.
  if (command[command.length() - 1] == UChar(':'))
    command = command.Substring(0, command.length() - 1);

  Node* plugin_lookup_context_node = nullptr;
  if (WebPluginContainerImpl::SupportsCommand(name))
    plugin_lookup_context_node = ContextMenuNodeInner();

  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer(plugin_lookup_context_node);
  if (plugin_container && plugin_container->ExecuteEditCommand(name))
    return true;

  return GetFrame()->GetEditor().ExecuteCommand(command);
}

bool WebLocalFrameImpl::ExecuteCommand(const WebString& name,
                                       const WebString& value) {
  DCHECK(GetFrame());

  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container && plugin_container->ExecuteEditCommand(name, value))
    return true;

  return GetFrame()->GetEditor().ExecuteCommand(name, value);
}

bool WebLocalFrameImpl::IsCommandEnabled(const WebString& name) const {
  DCHECK(GetFrame());
  return GetFrame()->GetEditor().IsCommandEnabled(name);
}

bool WebLocalFrameImpl::SelectionTextDirection(
    base::i18n::TextDirection& start,
    base::i18n::TextDirection& end) const {
  FrameSelection& selection = frame_->Selection();
  if (!selection.IsAvailable()) {
    // plugins/mouse-capture-inside-shadow.html reaches here
    return false;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  if (selection.ComputeVisibleSelectionInDOMTree()
          .ToNormalizedEphemeralRange()
          .IsNull())
    return false;
  start = ToBaseTextDirection(PrimaryDirectionOf(
      *selection.ComputeVisibleSelectionInDOMTree().Start().AnchorNode()));
  end = ToBaseTextDirection(PrimaryDirectionOf(
      *selection.ComputeVisibleSelectionInDOMTree().End().AnchorNode()));
  return true;
}

bool WebLocalFrameImpl::IsSelectionAnchorFirst() const {
  FrameSelection& selection = frame_->Selection();
  if (!selection.IsAvailable()) {
    // plugins/mouse-capture-inside-shadow.html reaches here
    return false;
  }

  return selection.GetSelectionInDOMTree().IsAnchorFirst();
}

void WebLocalFrameImpl::SetTextDirectionForTesting(
    base::i18n::TextDirection direction) {
  frame_->SetTextDirection(direction);
}

void WebLocalFrameImpl::ReplaceMisspelledRange(const WebString& text) {
  // If this caret selection has two or more markers, this function replace the
  // range covered by the first marker with the specified word as Microsoft Word
  // does.
  if (GetFrame()->GetWebPluginContainer())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSpellCheck);

  GetFrame()->GetSpellChecker().ReplaceMisspelledRange(text);
}

void WebLocalFrameImpl::RemoveSpellingMarkers() {
  GetFrame()->GetSpellChecker().RemoveSpellingMarkers();
}

void WebLocalFrameImpl::RemoveSpellingMarkersUnderWords(
    const WebVector<WebString>& words) {
  Vector<String> converted_words;
  converted_words.AppendSpan(base::span(words));
  GetFrame()->RemoveSpellingMarkersUnderWords(converted_words);
}

bool WebLocalFrameImpl::HasSelection() const {
  DCHECK(GetFrame());
  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container)
    return plugin_container->Plugin()->HasSelection();

  // TODO(editing-dev): The use of UpdateStyleAndLayoutIgnorePendingStylesheets
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);
  return GetFrame()->Selection().ComputeVisibleSelectionInDOMTree().IsRange();
}

WebRange WebLocalFrameImpl::SelectionRange() const {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  return GetFrame()
      ->Selection()
      .ComputeVisibleSelectionInDOMTree()
      .ToNormalizedEphemeralRange();
}

WebString WebLocalFrameImpl::SelectionAsText() const {
  DCHECK(GetFrame());
  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container)
    return plugin_container->Plugin()->SelectionAsText();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  String text;
  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    text = edit_context->text().Substring(
        edit_context->selectionStart(),
        edit_context->selectionEnd() - edit_context->selectionStart());
  } else {
    text = GetFrame()->Selection().SelectedText(
        TextIteratorBehavior::EmitsObjectReplacementCharacterBehavior());
  }
#if BUILDFLAG(IS_WIN)
  ReplaceNewlinesWithWindowsStyleNewlines(text);
#endif
  ReplaceNBSPWithSpace(text);
  return text;
}

WebString WebLocalFrameImpl::SelectionAsMarkup() const {
  WebPluginContainerImpl* plugin_container =
      GetFrame()->GetWebPluginContainer();
  if (plugin_container)
    return plugin_container->Plugin()->SelectionAsMarkup();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // Selection normalization and markup generation require clean layout.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  return GetFrame()->Selection().SelectedHTMLForClipboard();
}

void WebLocalFrameImpl::TextSelectionChanged(const WebString& selection_text,
                                             uint32_t offset,
                                             const gfx::Range& range) {
  GetFrame()->TextSelectionChanged(selection_text, offset, range);
}

bool WebLocalFrameImpl::SelectAroundCaret(
    mojom::blink::SelectionGranularity granularity,
    bool should_show_handle,
    bool should_show_context_menu) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::selectAroundCaret");

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);
  // TODO(1275801): Add mapping between the enums once it becomes possible to
  // do so.
  blink::TextGranularity text_granularity;
  switch (granularity) {
    case mojom::blink::SelectionGranularity::kWord:
      text_granularity = blink::TextGranularity::kWord;
      break;
    case mojom::blink::SelectionGranularity::kSentence:
      text_granularity = blink::TextGranularity::kSentence;
      break;
  }
  return GetFrame()->Selection().SelectAroundCaret(
      text_granularity,
      should_show_handle ? HandleVisibility::kVisible
                         : HandleVisibility::kNotVisible,
      should_show_context_menu ? ContextMenuVisibility ::kVisible
                               : ContextMenuVisibility ::kNotVisible);
}

EphemeralRange WebLocalFrameImpl::GetWordSelectionRangeAroundCaret() const {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::getWordSelectionRangeAroundCaret");
  return GetFrame()->Selection().GetWordSelectionRangeAroundCaret();
}

void WebLocalFrameImpl::SelectRange(const gfx::Point& base_in_viewport,
                                    const gfx::Point& extent_in_viewport) {
  MoveRangeSelection(base_in_viewport, extent_in_viewport);
}

void WebLocalFrameImpl::SelectRange(
    const WebRange& web_range,
    HandleVisibilityBehavior handle_visibility_behavior,
    blink::mojom::SelectionMenuBehavior selection_menu_behavior,
    SelectionSetFocusBehavior selection_set_focus_behavior) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::selectRange");

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  const EphemeralRange& range = web_range.CreateEphemeralRange(GetFrame());
  if (range.IsNull())
    return;

  FrameSelection& selection = GetFrame()->Selection();
  const bool show_handles =
      handle_visibility_behavior == kShowSelectionHandle ||
      (handle_visibility_behavior == kPreserveHandleVisibility &&
       selection.IsHandleVisible());
  using blink::mojom::SelectionMenuBehavior;
  const bool selection_not_set_focus =
      selection_set_focus_behavior == kSelectionDoNotSetFocus;
  selection.SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(range)
          .SetAffinity(TextAffinity::kDefault)
          .Build(),
      SetSelectionOptions::Builder()
          .SetShouldShowHandle(show_handles)
          .SetShouldShrinkNextTap(selection_menu_behavior ==
                                  SelectionMenuBehavior::kShow)
          .SetDoNotSetFocus(selection_not_set_focus)
          .Build());

  if (selection_menu_behavior == SelectionMenuBehavior::kShow) {
    ContextMenuAllowedScope scope;
    GetFrame()->GetEventHandler().ShowNonLocatedContextMenu(
        nullptr, kMenuSourceAdjustSelection);
  }
}

WebString WebLocalFrameImpl::RangeAsText(const WebRange& web_range) {
  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    return edit_context->text().Substring(web_range.StartOffset(),
                                          web_range.length());
  } else {
    // TODO(editing-dev): The use of UpdateStyleAndLayout
    // needs to be audited.  see http://crbug.com/590369 for more details.
    GetFrame()->GetDocument()->UpdateStyleAndLayout(
        DocumentUpdateReason::kEditing);

    DocumentLifecycle::DisallowTransitionScope disallow_transition(
        GetFrame()->GetDocument()->Lifecycle());

    return PlainText(
        web_range.CreateEphemeralRange(GetFrame()),
        TextIteratorBehavior::EmitsObjectReplacementCharacterBehavior());
  }
}

void WebLocalFrameImpl::MoveRangeSelectionExtent(const gfx::Point& point) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::moveRangeSelectionExtent");

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  GetFrame()->Selection().MoveRangeSelectionExtent(
      GetFrame()->View()->ViewportToFrame(point));
}

void WebLocalFrameImpl::MoveRangeSelection(
    const gfx::Point& base_in_viewport,
    const gfx::Point& extent_in_viewport,
    WebFrame::TextGranularity granularity) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::moveRangeSelection");

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  blink::TextGranularity blink_granularity = blink::TextGranularity::kCharacter;
  if (granularity == WebFrame::kWordGranularity)
    blink_granularity = blink::TextGranularity::kWord;
  GetFrame()->Selection().MoveRangeSelection(
      GetFrame()->View()->ViewportToFrame(base_in_viewport),
      GetFrame()->View()->ViewportToFrame(extent_in_viewport),
      blink_granularity);
}

void WebLocalFrameImpl::MoveCaretSelection(
    const gfx::Point& point_in_viewport) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::moveCaretSelection");

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);
  const gfx::Point point_in_contents =
      GetFrame()->View()->ViewportToFrame(point_in_viewport);
  GetFrame()->Selection().MoveCaretSelection(point_in_contents);
}

bool WebLocalFrameImpl::SetEditableSelectionOffsets(int start, int end) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::setEditableSelectionOffsets");
  if (EditContext* edit_context =
          GetFrame()->GetInputMethodController().GetActiveEditContext()) {
    edit_context->SetSelection(start, end, /*dispatch_text_update_event=*/true);
    return true;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  return GetFrame()->GetInputMethodController().SetEditableSelectionOffsets(
      PlainTextRange(start, end));
}

bool WebLocalFrameImpl::AddImeTextSpansToExistingText(
    const WebVector<ui::ImeTextSpan>& ime_text_spans,
    unsigned text_start,
    unsigned text_end) {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::AddImeTextSpansToExistingText");

  if (!GetFrame()->GetEditor().CanEdit())
    return false;

  InputMethodController& input_method_controller =
      GetFrame()->GetInputMethodController();

  // TODO(editing-dev): The use of Up
```