Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/dom/document.cc`, which is part of the Chromium Blink rendering engine.

Here's a breakdown of the process to generate the response:

1. **Identify the Core Functionality:**  The code primarily deals with handling "beforeunload" and "unload" events, as well as the `document.write()` method. It also touches upon document URL management and base URL updates.

2. **Analyze "beforeunload" Event Handling:**
    - Look for keywords like `beforeunload_event`, `DispatchEvent`, `defaultPrevented`, `returnValue`, `OpenBeforeUnloadConfirmPanel`.
    - The code checks if the event is cancelled by a script, if a user gesture was involved, and if multiple confirmation panels are being shown for a single navigation.
    - It interacts with `chrome_client` to display a confirmation dialog.

3. **Analyze "unload" Event Handling:**
    - Look for keywords like `DispatchUnloadEvents`, `unload_event`, `pagehide`, `visibilitychange`.
    - The code handles stopping the parser, checking prerendering status, and dispatching `pagehide`, `visibilitychange`, and `unload` events.
    - It also checks for fenced frames and persisted pagehide events.

4. **Analyze `document.write()` Functionality:**
    - Look for the `write` and `writeln` methods.
    - The code includes checks for `InvalidStateError`, security errors (same-origin policy), recursion depth, and whether the parser has an insertion point.
    - It calls the parser's `insert()` method to add content.

5. **Analyze URL and Base URL Handling:**
    - Look for methods like `SetURL`, `UpdateBaseURL`, `FallbackBaseURL`, `ProcessBaseElement`.
    - The code handles setting the document URL, updating the base URL based on `<base>` elements and other factors, and considering fallback base URL logic (especially for `srcdoc` iframes and `about:blank`).

6. **Identify Relationships with JavaScript, HTML, and CSS:**
    - **JavaScript:**  The `beforeunload` and `unload` events are JavaScript events. `document.write()` is a JavaScript method. The code interacts with JavaScript's ability to cancel the `beforeunload` event.
    - **HTML:** The `<base>` element influences the base URL. The `document.write()` method inserts HTML content.
    - **CSS:**  The base URL affects how relative CSS URLs are resolved. The code mentions stylesheet loading and layout.

7. **Infer Logical Reasoning and Potential Issues:**
    - **"beforeunload":**  The logic prevents showing the dialog without a user gesture or multiple times for the same navigation, aiming to improve user experience and prevent abuse. A potential issue is users being confused why the dialog doesn't appear if they haven't interacted with the page.
    - **`document.write()`:** The code protects against excessive recursion and attempts to use `document.write()` after the document has loaded. A common error is using `document.write()` after the page has loaded, which can clear the existing content.

8. **Consider User Actions Leading to This Code:**
    - **"beforeunload":** Closing the browser tab/window, navigating away from the page, clicking a link to leave the page, or submitting a form.
    - **"unload":**  Similar to "beforeunload", but after the user has confirmed they want to leave.
    - **`document.write()`:**  JavaScript code explicitly calling `document.write()` or `document.writeln()`.
    - **Base URL:** Including a `<base>` tag in the HTML, or the browser setting the initial URL for the document.

9. **Synthesize the Information into a Structured Response:**
    - Start with a general summary of the file's purpose.
    - Detail the functionality of each key area (beforeunload, unload, document.write, URLs).
    - Provide specific examples illustrating the relationships with JavaScript, HTML, and CSS.
    - Explain the logical reasoning behind certain checks and the potential user/programming errors.
    - Describe user actions as debugging clues.
    - Finally, provide a concise summary as requested in the prompt.

10. **Review and Refine:** Ensure the explanation is clear, accurate, and addresses all parts of the user's request.
```cpp
has run.
    base::AutoReset<LoadEventProgress> set_in_progress(
        &load_event_progress_, kBeforeUnloadEventInProgress);
    dom_window_->DispatchEvent(before_unload_event, this);
  }

  if (!before_unload_event.defaultPrevented())
    DefaultEventHandler(before_unload_event);

  bool cancelled_by_script = !before_unload_event.returnValue().empty() ||
                             before_unload_event.defaultPrevented();

  if (cancelled_by_script) {
    RecordBeforeUnloadUse(BeforeUnloadUse::kNoDialogNoText);
  }

  if (!GetFrame() || !cancelled_by_script) {
    return true;
  }

  if (!GetFrame()->HasStickyUserActivation()) {
    RecordBeforeUnloadUse(BeforeUnloadUse::kNoDialogNoUserGesture);
    String message =
        "Blocked attempt to show a 'beforeunload' confirmation panel for a "
        "frame that never had a user gesture since its load. "
        "https://www.chromestatus.com/feature/5082396709879808";
    Intervention::GenerateReport(GetFrame(), "BeforeUnloadNoGesture", message);
    return true;
  }

  if (did_allow_navigation) {
    RecordBeforeUnloadUse(
        BeforeUnloadUse::kNoDialogMultipleConfirmationForNavigation);
    String message =
        "Blocked attempt to show multiple 'beforeunload' confirmation panels "
        "for a single navigation.";
    Intervention::GenerateReport(GetFrame(), "BeforeUnloadMultiple", message);
    return true;
  }

  // If |chrome_client| is null simply indicate that the navigation should
  // not proceed.
  if (!chrome_client) {
    RecordBeforeUnloadUse(BeforeUnloadUse::kNoDialogAutoCancelTrue);
    did_allow_navigation = false;
    return false;
  }

  String text = before_unload_event.returnValue();
  RecordBeforeUnloadUse(BeforeUnloadUse::kShowDialog);
  const base::TimeTicks beforeunload_confirmpanel_start =
      base::TimeTicks::Now();
  did_allow_navigation =
      chrome_client->OpenBeforeUnloadConfirmPanel(text, GetFrame(), is_reload);
  const base::TimeTicks beforeunload_confirmpanel_end = base::TimeTicks::Now();
  if (did_allow_navigation) {
    // Only record when a navigation occurs, since we want to understand
    // the impact of the before unload dialog on overall input to navigation.
    DEPRECATED_UMA_HISTOGRAM_MEDIUM_TIMES(
        "DocumentEventTiming.BeforeUnloadDialogDuration.ByNavigation",
        beforeunload_confirmpanel_end - beforeunload_confirmpanel_start);
    return true;
  }

  return false;
}

void Document::DispatchUnloadEvents(UnloadEventTimingInfo* unload_timing_info) {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::DispatchUnloadEvents",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.Document.DispatchUnloadEvents");
  PluginScriptForbiddenScope forbid_plugin_destructor_scripting;
  PageDismissalScope in_page_dismissal;
  if (parser_) {
    parser_->StopParsing();
  }

  if (IsPrerendering()) {
    // We do not dispatch unload event while prerendering.
    return;
  }

  if (load_event_progress_ == kLoadEventNotRun ||
      // TODO(dcheng): We should consider if we can make this conditional check
      // stronger with a DCHECK() that this isn't called if the unload event is
      // already complete.
      load_event_progress_ > kUnloadEventInProgress) {
    return;
  }

  Element* current_focused_element = FocusedElement();
  if (auto* input = DynamicTo<HTMLInputElement>(current_focused_element))
    input->EndEditing();

  // Since we do not allow registering the unload event handlers in
  // fenced frames, it should not be fired by fencedframes.
  DCHECK(!GetFrame() || !GetFrame()->IsInFencedFrameTree() ||
         !GetEventTargetData() ||
         !GetEventTargetData()->event_listener_map.Contains(
             event_type_names::kUnload));

  // If we've dispatched the pagehide event with 'persisted' set to true, it
  // means we've dispatched the visibilitychange event before too. Also, we
  // shouldn't dispatch the unload event because that event should only be
  // fired when the pagehide event's 'persisted' bit is set to false.
  bool dispatched_pagehide_persisted =
      GetPage() && GetPage()->DispatchedPagehidePersistedAndStillHidden();

  if (load_event_progress_ >= kPageHideInProgress ||
      dispatched_pagehide_persisted) {
    load_event_progress_ = kUnloadEventHandled;
    return;
  }

  load_event_progress_ = kPageHideInProgress;
  LocalDOMWindow* window = domWindow();
  // We check for DispatchedPagehideAndStillHidden() here because it's possible
  // to dispatch pagehide with 'persisted' set to false before this and pass the
  // |dispatched_pagehide_persisted| above, if we enable same-site
  // ProactivelySwapBrowsingInstance but not BackForwardCache.
  if (window && !GetPage()->DispatchedPagehideAndStillHidden()) {
    window->DispatchEvent(
        *PageTransitionEvent::Create(event_type_names::kPagehide, false), this);
  }
  if (!dom_window_)
    return;

  // This must be queried before |load_event_progress_| is changed to
  // kUnloadVisibilityChangeInProgress because that would change the result.
  bool page_visible = IsPageVisible();
  load_event_progress_ = kUnloadVisibilityChangeInProgress;
  if (page_visible) {
    // Dispatch visibilitychange event, but don't bother doing
    // other notifications as we're about to be unloaded.
    DispatchEvent(*Event::CreateBubble(event_type_names::kVisibilitychange));
    DispatchEvent(
        *Event::CreateBubble(event_type_names::kWebkitvisibilitychange));
  }
  if (!dom_window_)
    return;

  GetFrame()->Loader().SaveScrollAnchor();

  load_event_progress_ = kUnloadEventInProgress;
  Event& unload_event = *Event::Create(event_type_names::kUnload);
  const base::TimeTicks unload_event_start = base::TimeTicks::Now();
  dom_window_->DispatchEvent(unload_event, this);
  const base::TimeTicks unload_event_end = base::TimeTicks::Now();

  if (unload_timing_info) {
    // Record unload event timing when navigating cross-document.
    auto& timing = unload_timing_info->unload_timing.emplace();
    timing.can_request =
        unload_timing_info->new_document_origin->CanRequest(Url());
    timing.unload_event_start = unload_event_start;
    timing.unload_event_end = unload_event_end;
  }
  load_event_progress_ = kUnloadEventHandled;
}

void Document::DispatchFreezeEvent() {
  SetFreezingInProgress(true);
  DispatchEvent(*Event::Create(event_type_names::kFreeze));
  SetFreezingInProgress(false);
  UseCounter::Count(*this, WebFeature::kPageLifeCycleFreeze);
}

Document::PageDismissalType Document::PageDismissalEventBeingDispatched()
    const {
  switch (load_event_progress_) {
    case kBeforeUnloadEventInProgress:
      return kBeforeUnloadDismissal;
    case kPageHideInProgress:
      return kPageHideDismissal;
    case kUnloadVisibilityChangeInProgress:
      return kUnloadVisibilityChangeDismissal;
    case kUnloadEventInProgress:
      return kUnloadDismissal;

    case kLoadEventNotRun:
    case kLoadEventInProgress:
    case kLoadEventCompleted:
    case kBeforeUnloadEventHandled:
    case kUnloadEventHandled:
      return kNoDismissal;
  }
  NOTREACHED();
}

void Document::SetParsingState(ParsingState parsing_state) {
  ParsingState previous_state = parsing_state_;
  parsing_state_ = parsing_state;

  if (Parsing() && !element_data_cache_)
    element_data_cache_ = MakeGarbageCollected<ElementDataCache>();
  if (previous_state != kFinishedParsing &&
      parsing_state_ == kFinishedParsing) {
    if (form_controller_ && form_controller_->HasControlStates())
      form_controller_->ScheduleRestore();
  }
}

bool Document::ShouldScheduleLayout() const {
  // This function will only be called when LocalFrameView thinks a layout is
  // needed. This enforces a couple extra rules.
  //
  //    (a) Only schedule a layout once the stylesheets are loaded.
  //    (b) Only schedule layout once we have a body element, or parsing has
  //        finished and we don't have a body element (if e.g. a script has
  //        removed the body element, but the root element, and maybe even the
  //        head elements are styled to render, we should allow layout of those
  //        elements).
  if (!IsActive()) {
    return false;
  }
  if (HaveRenderBlockingResourcesLoaded() && (body() || HasFinishedParsing())) {
    return true;
  }
  if (documentElement() && !IsA<HTMLHtmlElement>(documentElement())) {
    return true;
  }
  return false;
}

void Document::write(const String& text,
                     LocalDOMWindow* entered_window,
                     ExceptionState& exception_state) {
  if (!IsA<HTMLDocument>(this)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Only HTML documents support write().");
    return;
  }

  if (throw_on_dynamic_markup_insertion_count_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Custom Element constructor should not use write().");
    return;
  }

  if (entered_window && !entered_window->GetFrame())
    return;

  if (entered_window && GetExecutionContext() &&
      !GetExecutionContext()->GetSecurityOrigin()->IsSameOriginWith(
          entered_window->GetSecurityOrigin())) {
    exception_state.ThrowSecurityError(
        "Can only call write() on same-origin documents.");
    return;
  }

  if (ignore_opens_and_writes_for_abort_)
    return;

  NestingLevelIncrementer nesting_level_incrementer(write_recursion_depth_);

  write_recursion_is_too_deep_ =
      (write_recursion_depth_ > 1) && write_recursion_is_too_deep_;
  write_recursion_is_too_deep_ =
      (write_recursion_depth_ > kCMaxWriteRecursionDepth) ||
      write_recursion_is_too_deep_;

  if (write_recursion_is_too_deep_)
    return;

  bool has_insertion_point = parser_ && parser_->HasInsertionPoint();

  if (!has_insertion_point) {
    if (ignore_destructive_write_count_) {
      AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          ConsoleMessage::Source::kJavaScript, ConsoleMessage::Level::kWarning,
          ExceptionMessages::FailedToExecute(
              "write", "Document",
              "It isn't possible to write into a document "
              "from an asynchronously-loaded external "
              "script unless it is explicitly opened.")));
      return;
    }
    if (ignore_opens_during_unload_count_)
      return;

    if (ignore_destructive_write_module_script_count_) {
      UseCounter::Count(*this,
                        WebFeature::kDestructiveDocumentWriteAfterModuleScript);
    }
    open(entered_window, ASSERT_NO_EXCEPTION);
  }

  DCHECK(parser_);
  PerformanceMonitor::ReportGenericViolation(
      domWindow(), PerformanceMonitor::kDiscouragedAPIUse,
      "Avoid using document.write(). "
      "https://developers.google.com/web/updates/2016/08/"
      "removing-document-write",
      base::TimeDelta(), nullptr);
  probe::BreakableLocation(domWindow(), "Document.write");
  parser_->insert(text);
}

void Document::writeln(const String& text,
                       LocalDOMWindow* entered_window,
                       ExceptionState& exception_state) {
  write(text, entered_window, exception_state);
  if (exception_state.HadException())
    return;
  write("\n", entered_window);
}

void Document::write(v8::Isolate* isolate,
                     const Vector<String>& text,
                     ExceptionState& exception_state) {
  StringBuilder builder;
  for (const String& string : text)
    builder.Append(string);
  String string =
      TrustedTypesCheckForHTML(builder.ReleaseString(), GetExecutionContext(),
                               "Document", "write", exception_state);
  if (exception_state.HadException())
    return;

  write(string, EnteredDOMWindow(isolate), exception_state);
}

void Document::writeln(v8::Isolate* isolate,
                       const Vector<String>& text,
                       ExceptionState& exception_state) {
  StringBuilder builder;
  for (const String& string : text)
    builder.Append(string);
  String string =
      TrustedTypesCheckForHTML(builder.ReleaseString(), GetExecutionContext(),
                               "Document", "writeln", exception_state);
  if (exception_state.HadException())
    return;

  writeln(string, EnteredDOMWindow(isolate), exception_state);
}

void Document::write(v8::Isolate* isolate,
                     TrustedHTML* text,
                     ExceptionState& exception_state) {
  write(text->toString(), EnteredDOMWindow(isolate), exception_state);
}

void Document::writeln(v8::Isolate* isolate,
                       TrustedHTML* text,
                       ExceptionState& exception_state) {
  writeln(text->toString(), EnteredDOMWindow(isolate), exception_state);
}

KURL Document::urlForBinding() const {
  if (!Url().IsNull()) {
    return Url();
  }
  return BlankURL();
}

void Document::SetURL(const KURL& url) {
  KURL new_url = url.IsEmpty() ? BlankURL() : url;
  if (new_url == url_)
    return;

  TRACE_EVENT_WITH_FLOW1("blink", "Document::SetURL", TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "url", new_url.GetString().Utf8());

  // Strip the fragment directive from the URL fragment. E.g. "#id:~:text=a"
  // --> "#id". See https://github.com/WICG/scroll-to-text-fragment.
  new_url = fragment_directive_->ConsumeFragmentDirective(new_url);

  url_ = new_url;
  UpdateBaseURL();

  if (GetFrame()) {
    if (FrameScheduler* frame_scheduler = GetFrame()->GetFrameScheduler())
      frame_scheduler->TraceUrlChange(url_.GetString());
  }
}

KURL Document::ValidBaseElementURL() const {
  if (base_element_url_.IsValid())
    return base_element_url_;

  return KURL();
}

void Document::UpdateBaseURL() {
  KURL old_base_url = base_url_;
  // DOM 3 Core: When the Document supports the feature "HTML" [DOM Level 2
  // HTML], the base URI is computed using first the value of the href attribute
  // of the HTML BASE element if any, and the value of the documentURI attribute
  // from the Document interface otherwise (which we store, preparsed, in
  // |url_|).
  if (!base_element_url_.IsEmpty())
    base_url_ = base_element_url_;
  else if (!base_url_override_.IsEmpty())
    base_url_ = base_url_override_;
  else
    base_url_ = FallbackBaseURL();

  GetSelectorQueryCache().Invalidate();

  if (!base_url_.IsValid())
    base_url_ = KURL();

  if (elem_sheet_) {
    // Element sheet is silly. It never contains anything.
    DCHECK(!elem_sheet_->Contents()->RuleCount());
    elem_sheet_ = nullptr;
  }

  GetStyleEngine().BaseURLChanged();

  if (!EqualIgnoringFragmentIdentifier(old_base_url, base_url_)) {
    // Base URL change changes any relative visited links.
    // FIXME: There are other URLs in the tree that would need to be
    // re-evaluated on dynamic base URL change. Style should be invalidated too.
    // TODO(crbug.com/369219144): Should this be using HTMLAnchorElementBase?
    for (HTMLAnchorElement& anchor :
         Traversal<HTMLAnchorElement>::StartsAfter(*this))
      anchor.InvalidateCachedVisitedLinkHash();
  }

  for (Element* element : *scripts()) {
    auto* script = To<HTMLScriptElement>(element);
    script->Loader()->DocumentBaseURLChanged();
  }

  if (auto* document_rules = DocumentSpeculationRules::FromIfExists(*this)) {
    document_rules->DocumentBaseURLChanged();
  }
}

// [spec] https://html.spec.whatwg.org/C/#fallback-base-url
KURL Document::FallbackBaseURL() const {
  const bool is_parent_cross_origin =
      GetFrame() && GetFrame()->IsCrossOriginToParentOrOuterDocument();
  // TODO(https://crbug.com/751329, https://crbug.com/1336904): Referring to
  // ParentDocument() is not correct.
  // We avoid using it when it is cross-origin, to avoid leaking cross-origin.
  const Document* same_origin_parent =
      is_parent_cross_origin ? nullptr : ParentDocument();

  // TODO(https://github.com/whatwg/html/issues/9025): Don't let a sandboxed
  // iframe (without 'allow-same-origin') inherit a fallback base url.
  // https://chromium-review.googlesource.com/c/chromium/src/+/4324738

  // [spec] 1. If document is an iframe srcdoc document, then return the
  //           document base URL of document's browsing context's container
  //           document.
  if (IsSrcdocDocument()) {
    // Return the base_url value that was sent from the initiator along with the
    // srcdoc attribute's value.
    if (fallback_base_url_.IsValid()) {
      return fallback_base_url_;
    }
    // The fallback base URL can be missing in some cases (e.g., for
    // browser-initiated navigations like
    // NavigationBrowserTest.BlockedSrcDocBrowserInitiated, or for cases where
    // the srcdoc's initiator origin does not match the parent origin, which
    // should be removed in https://crbug.com/1169736).
    //
    // In these cases, only use the parent frame's base URL if it is
    // same-origin.
    // TODO(https://crbug.com/1169736): Enforce that the parent is same-origin,
    // which should already be true.
    if (same_origin_parent) {
      return same_origin_parent->BaseURL();
    }
  }

  // [spec] 2. If document's URL matches about:blank and document's about base
  //           URL is non-null, then return document's about base URL.
  if (urlForBinding().IsAboutBlankURL()) {
    if (!fallback_base_url_.IsEmpty()) {
      // Note: if we get here, it's not worth worrying if
      // same_origin_parent->BaseURL() exists and matches fallback_base_url_,
      // since if the latter exists it's based on the initiator, which won't
      // always be the parent.
      return fallback_base_url_;
    }
  }

  // [spec] 3. Return document's URL.
  return urlForBinding();
}

const KURL& Document::BaseURL() const {
  if (!base_url_.IsNull())
    return base_url_;
  return BlankURL();
}

void Document::SetBaseURLOverride(const KURL& url) {
  base_url_override_ = url;
  UpdateBaseURL();
}

void Document::ProcessBaseElement() {
  UseCounter::Count(*this, WebFeature::kBaseElement);

  // Find the first href attribute in a base element and the first target
  // attribute in a base element.
  const AtomicString* href = nullptr;
  const AtomicString* target = nullptr;
  for (HTMLBaseElement* base = Traversal<HTMLBaseElement>::FirstWithin(*this);
       base && (!href || !target);
       base = Traversal<HTMLBaseElement>::Next(*base)) {
    if (!href) {
      const AtomicString& value = base->FastGetAttribute(html_names::kHrefAttr);
      if (!value.IsNull())
        href = &value;
    }
    if (!target) {
      const AtomicString& value =
          base->FastGetAttribute(html_names::kTargetAttr);
      if (!value.IsNull())
        target = &value;
    }
    if (GetExecutionContext() &&
        GetExecutionContext()->GetContentSecurityPolicy()->IsActive()) {
      UseCounter::Count(*this,
                        WebFeature::kContentSecurityPolicyWithBaseElement);
    }
  }

  // FIXME: Since this doesn't share code with completeURL it may not handle
  // encodings correctly.
  KURL base_element_url;
  if (href) {
    String stripped_href = StripLeadingAndTrailingHTMLSpaces(*href);
    if (!stripped_href.empty())
      base_element_url = KURL(FallbackBaseURL(), stripped_href);
  }

  if (!base_element_url.IsEmpty()) {
    if (base_element_url.ProtocolIsData() ||
        base_element_url.ProtocolIsJavaScript()) {
      UseCounter::Count(*this, WebFeature::kBaseWithDataHref);
      AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
          "'" + base_element_url.Protocol() +
              "' URLs may not be used as base URLs for a document."));
    }
    if (GetExecutionContext() &&
        !GetExecutionContext()->GetSecurityOrigin()->CanRequest(
            base_element_url)) {
      UseCounter::Count(*this, WebFeature::kBaseWithCrossOriginHref);
    }
  }

  if (base_element_url != base_element_url_) {
    // https://html.spec.whatwg.org/multipage/semantics.html#the-base-element
    // > If any of the following are true:
    // > - urlRecord is failure;
    // > - urlRecord's scheme is "data" or "javascript"; or
    // > - running Is base allowed for Document? on urlRecord and document
    // >   returns "Blocked"
    // > then set element's frozen base URL to document's fallback base URL and
    // > return.
    if (!base_element_url.ProtocolIsData() &&
        !base_element_url.ProtocolIsJavaScript() && GetExecutionContext() &&
        GetExecutionContext()->GetContentSecurityPolicy()->AllowBaseURI(
            base_element_url)) {
      base_element_url_ = base_element_url;
    } else {
      base_element_url_ = FallbackBaseURL();
    }
    UpdateBaseURL();
  }

  AtomicString old_base_target = base_target_;
  if (target) {
    if (target->Contains('\n') || target->Contains('\r'))
      UseCounter::Count(*this, WebFeature::kBaseWithNewlinesInTarget);
    if (target->Contains('<'))
      UseCounter::Count(*this, WebFeature::kBaseWithOpenBracketInTarget);
    base_target_ = *target;
  } else {
    base_target_ = g_null_atom;
  }
  if (old_base_target != base_target_) {
    if (auto* document_rules = DocumentSpeculationRules::FromIfExists(*this)) {
      document_rules->DocumentBaseTargetChanged();
    }
  }
}

void Document::DidAddPendingParserBlockingStylesheet() {
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    parser->DidAddPendingParserBlockingStylesheet();
}

void Document::DidRemoveAllPendingStylesheets() {
  DidLoadAllScriptBlockingResources();
}

void Document::DidLoadAllPendingParserBlockingStylesheets() {
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    parser->DidLoadAllPendingParserBlockingStylesheets();
}

void Document::DidLoadAllScriptBlockingResources() {
  // Use wrapWeakPersistent because the task should not keep this Document alive
  // just for executing scripts.
  execute_scripts_waiting_for_resources_task_handle_ = PostCancellableTask(
      *GetTaskRunner(TaskType::kNetworking), FROM_HERE,
      WTF::BindOnce(&Document::ExecuteScriptsWaitingForResources,
                    WrapWeakPersistent(this)));

  if (IsA<HTMLDocument>(this) && body()) {
    // For HTML if we have no more stylesheets to load and we're past the body
    // tag, we should have something to paint so resume.
    BeginLifecycleUpdatesIfRenderingReady();
  } else if (!IsA<HTMLDocument>(this) && documentElement()) {
    // For non-HTML there is no body so resume as soon as the sheets are loaded.
    BeginLifecycleUpdatesIfRenderingReady();
  }
}

void Document::ExecuteScriptsWaitingForResources() {
  if (!IsScriptExecutionReady())
    return;
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    parser->ExecuteScriptsWaitingForResources();
}

CSSStyleSheet& Document::ElementSheet() {
  if (!elem_sheet_)
    elem_sheet_ = CSSStyleSheet::CreateInline(*this, base_url_);
  return *elem_sheet_;
}

bool Document::InvalidationDisallowed() const {
  return View() && View()->InvalidationDisallowed();
}

void Document::MaybeHandleHttpRefresh(const String& content,
                                      HttpRefreshType http_refresh_type) {
  if (is_view_source_ || !dom_window_)
    return;

  base::TimeDelta delay;
  String refresh_url_string;
  if (!ParseHTTPRefresh(content,
                        http_refresh_type == kHttpRefreshFromMetaTag
                            ? IsHTMLSpace<UChar>
                            : nullptr,
                        delay, refresh_url_string))
    return;
  KURL refresh_url =
      refresh_url_string.empty() ? Url() : CompleteURL(refresh_url_string);

  if (refresh_url.ProtocolIsJavaScript()) {
    String message =
        "Refused to refresh " + url_.ElidedString() + " to a javascript: URL";
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        message));
    return;
  }

  if (http_refresh_type == kHttpRefreshFromMetaTag &&
      dom_window_->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kAutomaticFeatures)) {
    String message =
        "Refused to execute the redirect specified via '<meta "
        "http-equiv='refresh' content='...'>'. The document is sandboxed, and "
        "the 'allow-scripts' keyword is not set.";
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        message));
    return;
  }

  // Monitor blocking refresh usage when scripting is disabled.
  // See https://crbug.com/63107
  if (!dom_window_->CanExecuteScripts(kNotAboutToExecuteScript))
    UseCounter::Count(this, WebFeature::kHttpRefreshWhenScriptingDisabled);

  if (http_refresh_type == kHttpRefreshFromHeader) {
    UseCounter::Count(this, WebFeature::kRefreshHeader);
  }
  http_refresh_scheduler_->Schedule(delay, refresh_url, http_refresh_type);
}

bool Document::IsHttpRefreshScheduledWithin(base::TimeDelta interval) {
  return http_refresh_scheduler_->IsScheduledWithin(interval);
}

bool Document::HasDocumentPictureInPictureWindow() const {
  return PictureInPictureController::GetDocumentPictureInPictureWindow(*this);
}

network::mojom::ReferrerPolicy Document::GetReferrerPolicy() const {
  return GetExecutionContext() ? GetExecutionContext()->GetReferrerPolicy()
                               : network::mojom::ReferrerPolicy::kDefault;
}

MouseEventWithHitTestResults Document::PerformMouseEventHitTest(
    const HitTestRequest& request,
    const PhysicalOffset& document_point,
    const WebMouseEvent& event) {
  DCHECK(!GetLayoutView() || IsA<LayoutView>(GetLayoutView()));

  // LayoutView::hitTest causes a layout, and we don't want to hit that until
  // the first layout because until then, there is nothing shown on the screen -
  // the user can't have intentionally clicked on something belonging to this
  // page. Furthermore, mousemove events before the first layout should not
  // lead to a premature layout() happening, which could show a flash of white.
  // See also the similar code in EventHandler::hitTestResultAtPoint.
  if (!GetLayoutView() || !View() || !View()->DidFirstLayout()) {
    HitTestLocation
### 提示词
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
has run.
    base::AutoReset<LoadEventProgress> set_in_progress(
        &load_event_progress_, kBeforeUnloadEventInProgress);
    dom_window_->DispatchEvent(before_unload_event, this);
  }

  if (!before_unload_event.defaultPrevented())
    DefaultEventHandler(before_unload_event);

  bool cancelled_by_script = !before_unload_event.returnValue().empty() ||
                             before_unload_event.defaultPrevented();

  if (cancelled_by_script) {
    RecordBeforeUnloadUse(BeforeUnloadUse::kNoDialogNoText);
  }

  if (!GetFrame() || !cancelled_by_script) {
    return true;
  }

  if (!GetFrame()->HasStickyUserActivation()) {
    RecordBeforeUnloadUse(BeforeUnloadUse::kNoDialogNoUserGesture);
    String message =
        "Blocked attempt to show a 'beforeunload' confirmation panel for a "
        "frame that never had a user gesture since its load. "
        "https://www.chromestatus.com/feature/5082396709879808";
    Intervention::GenerateReport(GetFrame(), "BeforeUnloadNoGesture", message);
    return true;
  }

  if (did_allow_navigation) {
    RecordBeforeUnloadUse(
        BeforeUnloadUse::kNoDialogMultipleConfirmationForNavigation);
    String message =
        "Blocked attempt to show multiple 'beforeunload' confirmation panels "
        "for a single navigation.";
    Intervention::GenerateReport(GetFrame(), "BeforeUnloadMultiple", message);
    return true;
  }

  // If |chrome_client| is null simply indicate that the navigation should
  // not proceed.
  if (!chrome_client) {
    RecordBeforeUnloadUse(BeforeUnloadUse::kNoDialogAutoCancelTrue);
    did_allow_navigation = false;
    return false;
  }

  String text = before_unload_event.returnValue();
  RecordBeforeUnloadUse(BeforeUnloadUse::kShowDialog);
  const base::TimeTicks beforeunload_confirmpanel_start =
      base::TimeTicks::Now();
  did_allow_navigation =
      chrome_client->OpenBeforeUnloadConfirmPanel(text, GetFrame(), is_reload);
  const base::TimeTicks beforeunload_confirmpanel_end = base::TimeTicks::Now();
  if (did_allow_navigation) {
    // Only record when a navigation occurs, since we want to understand
    // the impact of the before unload dialog on overall input to navigation.
    DEPRECATED_UMA_HISTOGRAM_MEDIUM_TIMES(
        "DocumentEventTiming.BeforeUnloadDialogDuration.ByNavigation",
        beforeunload_confirmpanel_end - beforeunload_confirmpanel_start);
    return true;
  }

  return false;
}

void Document::DispatchUnloadEvents(UnloadEventTimingInfo* unload_timing_info) {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::DispatchUnloadEvents",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.Document.DispatchUnloadEvents");
  PluginScriptForbiddenScope forbid_plugin_destructor_scripting;
  PageDismissalScope in_page_dismissal;
  if (parser_) {
    parser_->StopParsing();
  }

  if (IsPrerendering()) {
    // We do not dispatch unload event while prerendering.
    return;
  }

  if (load_event_progress_ == kLoadEventNotRun ||
      // TODO(dcheng): We should consider if we can make this conditional check
      // stronger with a DCHECK() that this isn't called if the unload event is
      // already complete.
      load_event_progress_ > kUnloadEventInProgress) {
    return;
  }

  Element* current_focused_element = FocusedElement();
  if (auto* input = DynamicTo<HTMLInputElement>(current_focused_element))
    input->EndEditing();

  // Since we do not allow registering the unload event handlers in
  // fenced frames, it should not be fired by fencedframes.
  DCHECK(!GetFrame() || !GetFrame()->IsInFencedFrameTree() ||
         !GetEventTargetData() ||
         !GetEventTargetData()->event_listener_map.Contains(
             event_type_names::kUnload));

  // If we've dispatched the pagehide event with 'persisted' set to true, it
  // means we've dispatched the visibilitychange event before too. Also, we
  // shouldn't dispatch the unload event because that event should only be
  // fired when the pagehide event's 'persisted' bit is set to false.
  bool dispatched_pagehide_persisted =
      GetPage() && GetPage()->DispatchedPagehidePersistedAndStillHidden();

  if (load_event_progress_ >= kPageHideInProgress ||
      dispatched_pagehide_persisted) {
    load_event_progress_ = kUnloadEventHandled;
    return;
  }

  load_event_progress_ = kPageHideInProgress;
  LocalDOMWindow* window = domWindow();
  // We check for DispatchedPagehideAndStillHidden() here because it's possible
  // to dispatch pagehide with 'persisted' set to false before this and pass the
  // |dispatched_pagehide_persisted| above, if we enable same-site
  // ProactivelySwapBrowsingInstance but not BackForwardCache.
  if (window && !GetPage()->DispatchedPagehideAndStillHidden()) {
    window->DispatchEvent(
        *PageTransitionEvent::Create(event_type_names::kPagehide, false), this);
  }
  if (!dom_window_)
    return;

  // This must be queried before |load_event_progress_| is changed to
  // kUnloadVisibilityChangeInProgress because that would change the result.
  bool page_visible = IsPageVisible();
  load_event_progress_ = kUnloadVisibilityChangeInProgress;
  if (page_visible) {
    // Dispatch visibilitychange event, but don't bother doing
    // other notifications as we're about to be unloaded.
    DispatchEvent(*Event::CreateBubble(event_type_names::kVisibilitychange));
    DispatchEvent(
        *Event::CreateBubble(event_type_names::kWebkitvisibilitychange));
  }
  if (!dom_window_)
    return;

  GetFrame()->Loader().SaveScrollAnchor();

  load_event_progress_ = kUnloadEventInProgress;
  Event& unload_event = *Event::Create(event_type_names::kUnload);
  const base::TimeTicks unload_event_start = base::TimeTicks::Now();
  dom_window_->DispatchEvent(unload_event, this);
  const base::TimeTicks unload_event_end = base::TimeTicks::Now();

  if (unload_timing_info) {
    // Record unload event timing when navigating cross-document.
    auto& timing = unload_timing_info->unload_timing.emplace();
    timing.can_request =
        unload_timing_info->new_document_origin->CanRequest(Url());
    timing.unload_event_start = unload_event_start;
    timing.unload_event_end = unload_event_end;
  }
  load_event_progress_ = kUnloadEventHandled;
}

void Document::DispatchFreezeEvent() {
  SetFreezingInProgress(true);
  DispatchEvent(*Event::Create(event_type_names::kFreeze));
  SetFreezingInProgress(false);
  UseCounter::Count(*this, WebFeature::kPageLifeCycleFreeze);
}

Document::PageDismissalType Document::PageDismissalEventBeingDispatched()
    const {
  switch (load_event_progress_) {
    case kBeforeUnloadEventInProgress:
      return kBeforeUnloadDismissal;
    case kPageHideInProgress:
      return kPageHideDismissal;
    case kUnloadVisibilityChangeInProgress:
      return kUnloadVisibilityChangeDismissal;
    case kUnloadEventInProgress:
      return kUnloadDismissal;

    case kLoadEventNotRun:
    case kLoadEventInProgress:
    case kLoadEventCompleted:
    case kBeforeUnloadEventHandled:
    case kUnloadEventHandled:
      return kNoDismissal;
  }
  NOTREACHED();
}

void Document::SetParsingState(ParsingState parsing_state) {
  ParsingState previous_state = parsing_state_;
  parsing_state_ = parsing_state;

  if (Parsing() && !element_data_cache_)
    element_data_cache_ = MakeGarbageCollected<ElementDataCache>();
  if (previous_state != kFinishedParsing &&
      parsing_state_ == kFinishedParsing) {
    if (form_controller_ && form_controller_->HasControlStates())
      form_controller_->ScheduleRestore();
  }
}

bool Document::ShouldScheduleLayout() const {
  // This function will only be called when LocalFrameView thinks a layout is
  // needed. This enforces a couple extra rules.
  //
  //    (a) Only schedule a layout once the stylesheets are loaded.
  //    (b) Only schedule layout once we have a body element, or parsing has
  //        finished and we don't have a body element (if e.g. a script has
  //        removed the body element, but the root element, and maybe even the
  //        head elements are styled to render, we should allow layout of those
  //        elements).
  if (!IsActive()) {
    return false;
  }
  if (HaveRenderBlockingResourcesLoaded() && (body() || HasFinishedParsing())) {
    return true;
  }
  if (documentElement() && !IsA<HTMLHtmlElement>(documentElement())) {
    return true;
  }
  return false;
}

void Document::write(const String& text,
                     LocalDOMWindow* entered_window,
                     ExceptionState& exception_state) {
  if (!IsA<HTMLDocument>(this)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Only HTML documents support write().");
    return;
  }

  if (throw_on_dynamic_markup_insertion_count_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Custom Element constructor should not use write().");
    return;
  }

  if (entered_window && !entered_window->GetFrame())
    return;

  if (entered_window && GetExecutionContext() &&
      !GetExecutionContext()->GetSecurityOrigin()->IsSameOriginWith(
          entered_window->GetSecurityOrigin())) {
    exception_state.ThrowSecurityError(
        "Can only call write() on same-origin documents.");
    return;
  }

  if (ignore_opens_and_writes_for_abort_)
    return;

  NestingLevelIncrementer nesting_level_incrementer(write_recursion_depth_);

  write_recursion_is_too_deep_ =
      (write_recursion_depth_ > 1) && write_recursion_is_too_deep_;
  write_recursion_is_too_deep_ =
      (write_recursion_depth_ > kCMaxWriteRecursionDepth) ||
      write_recursion_is_too_deep_;

  if (write_recursion_is_too_deep_)
    return;

  bool has_insertion_point = parser_ && parser_->HasInsertionPoint();

  if (!has_insertion_point) {
    if (ignore_destructive_write_count_) {
      AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          ConsoleMessage::Source::kJavaScript, ConsoleMessage::Level::kWarning,
          ExceptionMessages::FailedToExecute(
              "write", "Document",
              "It isn't possible to write into a document "
              "from an asynchronously-loaded external "
              "script unless it is explicitly opened.")));
      return;
    }
    if (ignore_opens_during_unload_count_)
      return;

    if (ignore_destructive_write_module_script_count_) {
      UseCounter::Count(*this,
                        WebFeature::kDestructiveDocumentWriteAfterModuleScript);
    }
    open(entered_window, ASSERT_NO_EXCEPTION);
  }

  DCHECK(parser_);
  PerformanceMonitor::ReportGenericViolation(
      domWindow(), PerformanceMonitor::kDiscouragedAPIUse,
      "Avoid using document.write(). "
      "https://developers.google.com/web/updates/2016/08/"
      "removing-document-write",
      base::TimeDelta(), nullptr);
  probe::BreakableLocation(domWindow(), "Document.write");
  parser_->insert(text);
}

void Document::writeln(const String& text,
                       LocalDOMWindow* entered_window,
                       ExceptionState& exception_state) {
  write(text, entered_window, exception_state);
  if (exception_state.HadException())
    return;
  write("\n", entered_window);
}

void Document::write(v8::Isolate* isolate,
                     const Vector<String>& text,
                     ExceptionState& exception_state) {
  StringBuilder builder;
  for (const String& string : text)
    builder.Append(string);
  String string =
      TrustedTypesCheckForHTML(builder.ReleaseString(), GetExecutionContext(),
                               "Document", "write", exception_state);
  if (exception_state.HadException())
    return;

  write(string, EnteredDOMWindow(isolate), exception_state);
}

void Document::writeln(v8::Isolate* isolate,
                       const Vector<String>& text,
                       ExceptionState& exception_state) {
  StringBuilder builder;
  for (const String& string : text)
    builder.Append(string);
  String string =
      TrustedTypesCheckForHTML(builder.ReleaseString(), GetExecutionContext(),
                               "Document", "writeln", exception_state);
  if (exception_state.HadException())
    return;

  writeln(string, EnteredDOMWindow(isolate), exception_state);
}

void Document::write(v8::Isolate* isolate,
                     TrustedHTML* text,
                     ExceptionState& exception_state) {
  write(text->toString(), EnteredDOMWindow(isolate), exception_state);
}

void Document::writeln(v8::Isolate* isolate,
                       TrustedHTML* text,
                       ExceptionState& exception_state) {
  writeln(text->toString(), EnteredDOMWindow(isolate), exception_state);
}

KURL Document::urlForBinding() const {
  if (!Url().IsNull()) {
    return Url();
  }
  return BlankURL();
}

void Document::SetURL(const KURL& url) {
  KURL new_url = url.IsEmpty() ? BlankURL() : url;
  if (new_url == url_)
    return;

  TRACE_EVENT_WITH_FLOW1("blink", "Document::SetURL", TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "url", new_url.GetString().Utf8());

  // Strip the fragment directive from the URL fragment. E.g. "#id:~:text=a"
  // --> "#id". See https://github.com/WICG/scroll-to-text-fragment.
  new_url = fragment_directive_->ConsumeFragmentDirective(new_url);

  url_ = new_url;
  UpdateBaseURL();

  if (GetFrame()) {
    if (FrameScheduler* frame_scheduler = GetFrame()->GetFrameScheduler())
      frame_scheduler->TraceUrlChange(url_.GetString());
  }
}

KURL Document::ValidBaseElementURL() const {
  if (base_element_url_.IsValid())
    return base_element_url_;

  return KURL();
}

void Document::UpdateBaseURL() {
  KURL old_base_url = base_url_;
  // DOM 3 Core: When the Document supports the feature "HTML" [DOM Level 2
  // HTML], the base URI is computed using first the value of the href attribute
  // of the HTML BASE element if any, and the value of the documentURI attribute
  // from the Document interface otherwise (which we store, preparsed, in
  // |url_|).
  if (!base_element_url_.IsEmpty())
    base_url_ = base_element_url_;
  else if (!base_url_override_.IsEmpty())
    base_url_ = base_url_override_;
  else
    base_url_ = FallbackBaseURL();

  GetSelectorQueryCache().Invalidate();

  if (!base_url_.IsValid())
    base_url_ = KURL();

  if (elem_sheet_) {
    // Element sheet is silly. It never contains anything.
    DCHECK(!elem_sheet_->Contents()->RuleCount());
    elem_sheet_ = nullptr;
  }

  GetStyleEngine().BaseURLChanged();

  if (!EqualIgnoringFragmentIdentifier(old_base_url, base_url_)) {
    // Base URL change changes any relative visited links.
    // FIXME: There are other URLs in the tree that would need to be
    // re-evaluated on dynamic base URL change. Style should be invalidated too.
    // TODO(crbug.com/369219144): Should this be using HTMLAnchorElementBase?
    for (HTMLAnchorElement& anchor :
         Traversal<HTMLAnchorElement>::StartsAfter(*this))
      anchor.InvalidateCachedVisitedLinkHash();
  }

  for (Element* element : *scripts()) {
    auto* script = To<HTMLScriptElement>(element);
    script->Loader()->DocumentBaseURLChanged();
  }

  if (auto* document_rules = DocumentSpeculationRules::FromIfExists(*this)) {
    document_rules->DocumentBaseURLChanged();
  }
}

// [spec] https://html.spec.whatwg.org/C/#fallback-base-url
KURL Document::FallbackBaseURL() const {
  const bool is_parent_cross_origin =
      GetFrame() && GetFrame()->IsCrossOriginToParentOrOuterDocument();
  // TODO(https://crbug.com/751329, https://crbug.com/1336904): Referring to
  // ParentDocument() is not correct.
  // We avoid using it when it is cross-origin, to avoid leaking cross-origin.
  const Document* same_origin_parent =
      is_parent_cross_origin ? nullptr : ParentDocument();

  // TODO(https://github.com/whatwg/html/issues/9025): Don't let a sandboxed
  // iframe (without 'allow-same-origin') inherit a fallback base url.
  // https://chromium-review.googlesource.com/c/chromium/src/+/4324738

  // [spec] 1. If document is an iframe srcdoc document, then return the
  //           document base URL of document's browsing context's container
  //           document.
  if (IsSrcdocDocument()) {
    // Return the base_url value that was sent from the initiator along with the
    // srcdoc attribute's value.
    if (fallback_base_url_.IsValid()) {
      return fallback_base_url_;
    }
    // The fallback base URL can be missing in some cases (e.g., for
    // browser-initiated navigations like
    // NavigationBrowserTest.BlockedSrcDocBrowserInitiated, or for cases where
    // the srcdoc's initiator origin does not match the parent origin, which
    // should be removed in https://crbug.com/1169736).
    //
    // In these cases, only use the parent frame's base URL if it is
    // same-origin.
    // TODO(https://crbug.com/1169736): Enforce that the parent is same-origin,
    // which should already be true.
    if (same_origin_parent) {
      return same_origin_parent->BaseURL();
    }
  }

  // [spec] 2. If document's URL matches about:blank and document's about base
  //           URL is non-null, then return document's about base URL.
  if (urlForBinding().IsAboutBlankURL()) {
    if (!fallback_base_url_.IsEmpty()) {
      // Note: if we get here, it's not worth worrying if
      // same_origin_parent->BaseURL() exists and matches fallback_base_url_,
      // since if the latter exists it's based on the initiator, which won't
      // always be the parent.
      return fallback_base_url_;
    }
  }

  // [spec] 3. Return document's URL.
  return urlForBinding();
}

const KURL& Document::BaseURL() const {
  if (!base_url_.IsNull())
    return base_url_;
  return BlankURL();
}

void Document::SetBaseURLOverride(const KURL& url) {
  base_url_override_ = url;
  UpdateBaseURL();
}

void Document::ProcessBaseElement() {
  UseCounter::Count(*this, WebFeature::kBaseElement);

  // Find the first href attribute in a base element and the first target
  // attribute in a base element.
  const AtomicString* href = nullptr;
  const AtomicString* target = nullptr;
  for (HTMLBaseElement* base = Traversal<HTMLBaseElement>::FirstWithin(*this);
       base && (!href || !target);
       base = Traversal<HTMLBaseElement>::Next(*base)) {
    if (!href) {
      const AtomicString& value = base->FastGetAttribute(html_names::kHrefAttr);
      if (!value.IsNull())
        href = &value;
    }
    if (!target) {
      const AtomicString& value =
          base->FastGetAttribute(html_names::kTargetAttr);
      if (!value.IsNull())
        target = &value;
    }
    if (GetExecutionContext() &&
        GetExecutionContext()->GetContentSecurityPolicy()->IsActive()) {
      UseCounter::Count(*this,
                        WebFeature::kContentSecurityPolicyWithBaseElement);
    }
  }

  // FIXME: Since this doesn't share code with completeURL it may not handle
  // encodings correctly.
  KURL base_element_url;
  if (href) {
    String stripped_href = StripLeadingAndTrailingHTMLSpaces(*href);
    if (!stripped_href.empty())
      base_element_url = KURL(FallbackBaseURL(), stripped_href);
  }

  if (!base_element_url.IsEmpty()) {
    if (base_element_url.ProtocolIsData() ||
        base_element_url.ProtocolIsJavaScript()) {
      UseCounter::Count(*this, WebFeature::kBaseWithDataHref);
      AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
          "'" + base_element_url.Protocol() +
              "' URLs may not be used as base URLs for a document."));
    }
    if (GetExecutionContext() &&
        !GetExecutionContext()->GetSecurityOrigin()->CanRequest(
            base_element_url)) {
      UseCounter::Count(*this, WebFeature::kBaseWithCrossOriginHref);
    }
  }

  if (base_element_url != base_element_url_) {
    // https://html.spec.whatwg.org/multipage/semantics.html#the-base-element
    // > If any of the following are true:
    // > - urlRecord is failure;
    // > - urlRecord's scheme is "data" or "javascript"; or
    // > - running Is base allowed for Document? on urlRecord and document
    // >   returns "Blocked"
    // > then set element's frozen base URL to document's fallback base URL and
    // > return.
    if (!base_element_url.ProtocolIsData() &&
        !base_element_url.ProtocolIsJavaScript() && GetExecutionContext() &&
        GetExecutionContext()->GetContentSecurityPolicy()->AllowBaseURI(
            base_element_url)) {
      base_element_url_ = base_element_url;
    } else {
      base_element_url_ = FallbackBaseURL();
    }
    UpdateBaseURL();
  }

  AtomicString old_base_target = base_target_;
  if (target) {
    if (target->Contains('\n') || target->Contains('\r'))
      UseCounter::Count(*this, WebFeature::kBaseWithNewlinesInTarget);
    if (target->Contains('<'))
      UseCounter::Count(*this, WebFeature::kBaseWithOpenBracketInTarget);
    base_target_ = *target;
  } else {
    base_target_ = g_null_atom;
  }
  if (old_base_target != base_target_) {
    if (auto* document_rules = DocumentSpeculationRules::FromIfExists(*this)) {
      document_rules->DocumentBaseTargetChanged();
    }
  }
}

void Document::DidAddPendingParserBlockingStylesheet() {
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    parser->DidAddPendingParserBlockingStylesheet();
}

void Document::DidRemoveAllPendingStylesheets() {
  DidLoadAllScriptBlockingResources();
}

void Document::DidLoadAllPendingParserBlockingStylesheets() {
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    parser->DidLoadAllPendingParserBlockingStylesheets();
}

void Document::DidLoadAllScriptBlockingResources() {
  // Use wrapWeakPersistent because the task should not keep this Document alive
  // just for executing scripts.
  execute_scripts_waiting_for_resources_task_handle_ = PostCancellableTask(
      *GetTaskRunner(TaskType::kNetworking), FROM_HERE,
      WTF::BindOnce(&Document::ExecuteScriptsWaitingForResources,
                    WrapWeakPersistent(this)));

  if (IsA<HTMLDocument>(this) && body()) {
    // For HTML if we have no more stylesheets to load and we're past the body
    // tag, we should have something to paint so resume.
    BeginLifecycleUpdatesIfRenderingReady();
  } else if (!IsA<HTMLDocument>(this) && documentElement()) {
    // For non-HTML there is no body so resume as soon as the sheets are loaded.
    BeginLifecycleUpdatesIfRenderingReady();
  }
}

void Document::ExecuteScriptsWaitingForResources() {
  if (!IsScriptExecutionReady())
    return;
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser())
    parser->ExecuteScriptsWaitingForResources();
}

CSSStyleSheet& Document::ElementSheet() {
  if (!elem_sheet_)
    elem_sheet_ = CSSStyleSheet::CreateInline(*this, base_url_);
  return *elem_sheet_;
}

bool Document::InvalidationDisallowed() const {
  return View() && View()->InvalidationDisallowed();
}

void Document::MaybeHandleHttpRefresh(const String& content,
                                      HttpRefreshType http_refresh_type) {
  if (is_view_source_ || !dom_window_)
    return;

  base::TimeDelta delay;
  String refresh_url_string;
  if (!ParseHTTPRefresh(content,
                        http_refresh_type == kHttpRefreshFromMetaTag
                            ? IsHTMLSpace<UChar>
                            : nullptr,
                        delay, refresh_url_string))
    return;
  KURL refresh_url =
      refresh_url_string.empty() ? Url() : CompleteURL(refresh_url_string);

  if (refresh_url.ProtocolIsJavaScript()) {
    String message =
        "Refused to refresh " + url_.ElidedString() + " to a javascript: URL";
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        message));
    return;
  }

  if (http_refresh_type == kHttpRefreshFromMetaTag &&
      dom_window_->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kAutomaticFeatures)) {
    String message =
        "Refused to execute the redirect specified via '<meta "
        "http-equiv='refresh' content='...'>'. The document is sandboxed, and "
        "the 'allow-scripts' keyword is not set.";
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        message));
    return;
  }

  // Monitor blocking refresh usage when scripting is disabled.
  // See https://crbug.com/63107
  if (!dom_window_->CanExecuteScripts(kNotAboutToExecuteScript))
    UseCounter::Count(this, WebFeature::kHttpRefreshWhenScriptingDisabled);

  if (http_refresh_type == kHttpRefreshFromHeader) {
    UseCounter::Count(this, WebFeature::kRefreshHeader);
  }
  http_refresh_scheduler_->Schedule(delay, refresh_url, http_refresh_type);
}

bool Document::IsHttpRefreshScheduledWithin(base::TimeDelta interval) {
  return http_refresh_scheduler_->IsScheduledWithin(interval);
}

bool Document::HasDocumentPictureInPictureWindow() const {
  return PictureInPictureController::GetDocumentPictureInPictureWindow(*this);
}

network::mojom::ReferrerPolicy Document::GetReferrerPolicy() const {
  return GetExecutionContext() ? GetExecutionContext()->GetReferrerPolicy()
                               : network::mojom::ReferrerPolicy::kDefault;
}

MouseEventWithHitTestResults Document::PerformMouseEventHitTest(
    const HitTestRequest& request,
    const PhysicalOffset& document_point,
    const WebMouseEvent& event) {
  DCHECK(!GetLayoutView() || IsA<LayoutView>(GetLayoutView()));

  // LayoutView::hitTest causes a layout, and we don't want to hit that until
  // the first layout because until then, there is nothing shown on the screen -
  // the user can't have intentionally clicked on something belonging to this
  // page.  Furthermore, mousemove events before the first layout should not
  // lead to a premature layout() happening, which could show a flash of white.
  // See also the similar code in EventHandler::hitTestResultAtPoint.
  if (!GetLayoutView() || !View() || !View()->DidFirstLayout()) {
    HitTestLocation location((PhysicalOffset()));
    return MouseEventWithHitTestResults(event, location,
                                        HitTestResult(request, location));
  }

  HitTestLocation location(document_point);
  HitTestResult result(request, location);
  GetLayoutView()->HitTest(location, result);

  if (!request.ReadOnly()) {
    UpdateHoverActiveState(request.Active(), !request.Move(),
                           result.InnerElement());
  }

  return MouseEventWithHitTestResults(event, location, result);
}

// DOM Section 1.1.1
bool Document::ChildTypeAllowed(NodeType type) const {
  switch (type) {
    case kAttributeNode:
    case kCdataSectionNode:
    case kDocumentFragmentNode:
    case kDocumentNode:
    case kTextNode:
      return false;
    case kCommentNode:
    case kProcessingInstructionNode:
      return true;
    case kDocumentTypeNode:
    case kElementNode:
      // Documents may contain no more than one of each of these.
      // (One Element and one DocumentType.)
      for (Node& c : NodeTraversal::ChildrenOf(*this)) {
        if (c.getNodeType() == type)
          return false;
      }
      return true;
  }
  return false;
}

// This is an implementation of step 6 of
// https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
// and https://dom.spec.whatwg.org/#concept-node-replace .
//
// 6. If parent is a document, and any of the statements below, switched on
// node, are true, throw a HierarchyRequestError.
//  -> DocumentFragment node
//     If node has more than one element child or has a Text node child.
//     Otherwise, if node has one element child and either parent has an element
//     child, child is a doctype, or child is not null and a doctype is
//     following child.
//  -> element
//     parent has an element child, child is a doctype, or child is not null and
//     a doctype is following child.
//  -> doctype
//     parent has a doctype child, child is non-null and an element is preceding
//     child, or child is null and parent has an element child.
//
// 6. If parent is a document, and any of the statements below, switched on
// node, are true, throw a HierarchyRequestError.
//  -> DocumentFragment node
//     If node has more than one element child or has a Text node child.
//     Otherwise, if node has one element child and either parent has an element
//     child that is not child or a doctype is following child.
//  -> element
//     parent has an element child that is not child or a doctype is following
//     child.
//  -> doctype
//     parent has a doctype child that is not child, or an element is preceding
//     child.
bool Document::CanAcceptChild(const Node* new_child,
                              const VectorOf<Node>* new_children,
                              const Node* next,
                              const Node* old_child,
                              ExceptionState& exception_state) const {
  DCHECK(!(next && old_child));
  CHECK_NE(!new_child, !new_children);
  if (old_child && new_child &&
      old_child->getNodeType() == new_child->getNodeType()) {
    return true;
  }

  int num_doctypes = 0;
  int num_elements = 0;
  bool has_doctype_after_reference_node = false;
  bool has_element_after_reference_node = false;

  // First, check how many doctypes and elements we have, not counting
  // the child we're about to remove.
  bool saw_reference_node = false;
  for (Node& child : NodeTraversal::ChildrenOf(*this)) {
    if (old_child == &child) {
      saw_reference_node = true;
      continue;
    }
    if (&child == next)
      saw_reference_node = true;

    switch (child.getNodeType()) {
      case kDocumentTypeNode:
        num_doctypes++;
        has_doctype_after_reference_node = saw_reference_node;
        break;
      case kElementNode:
        num_elements++;
        has_element_after_reference_node = saw_reference_node;
        break;
      default:
        break;
    }
  }

  auto process_child = [&](const Node& child) -> bool {
    switch (child.getNodeType()) {
      case kAttributeNode:
      case kCdataSectionNode:
      case kDocumentFragmentNode:
      case kDocumentNode:
      case kTextNode:
        exception_state.ThrowDOMException(
            DOMExceptionCode::kHierarchyRequestError,
            "Nodes of type '" + child.nodeName() +
                "' may not be inserted inside nodes of type '#document'.");
        return false;
      case kCommentNode:
      case kProcessingInstructionNode:
        break;
      case kDocumentTypeNode:
        num_doctypes++;
        if (num_elements > 0 && !has_element_after_reference_node) {
          exception_state.ThrowDOMException(
              DOMExceptionCode::kHierarchyRequestError,
              "Can't insert a doctype after the root element.");
          return false;
        }
        break;
      case kElementNode:
        num_elements++;
        if (has_doctype_after_reference_node) {
          exception_state.ThrowDOMException(
              DOMExceptionCode::kHierarchyRequestError,
              "Can't insert an element before a doctype.");
          return false;
        }
        break;
    }
    return true;
  };

  // Then, see how many doctypes and elements might be added by the new child.
  if (new_children) {
    for (Node* child : *new_children) {
      if (!process_child(*child)) {
        return false;
      }
    }
  } else if (auto* new_child_fragment =
                 DynamicTo<DocumentFragment>(new_child)) {
    for (Node& child : NodeTraversal::ChildrenOf(*new_child_fragment)) {
      if (!process_child(child)) {
        return false;
      }
    }
  } else {
    if (!process_child(*new_child)) {
      return false;
    }
  }

  if (num_elements > 1 || num_doctypes > 1) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        String::Format("Only one %s on document allowed.",
                       num_elements > 1 ? "element" : "doctype"));
    return false;
  }

  return true;
}

Node* Document::Clone(Document& factory,
                      NodeCloningData& data,
                      ContainerNode* append_to,
                      ExceptionState& append_exception_state) const {
  DCHECK_EQ(this, &factory)
      << "Document::Clone() doesn't support importNode mode.";
  DCHECK_EQ(append_to, nullptr)
      << "Document::Clone() doesn't support append_to";
  if (!execution_co
```