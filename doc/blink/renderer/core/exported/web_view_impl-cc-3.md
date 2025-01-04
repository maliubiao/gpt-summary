Response:

Prompt: 
```
这是目录为blink/renderer/core/exported/web_view_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
getControlledByView(*this, [](WebFrameWidgetImpl* widget) {
    widget->SetZoomLevel(widget->GetZoomLevel());
  });
}

void WebViewImpl::UpdateInspectorDeviceScaleFactorOverride() {
  if (compositor_device_scale_factor_override_) {
    page_->SetInspectorDeviceScaleFactorOverride(
        zoom_factor_for_device_scale_factor_ /
        compositor_device_scale_factor_override_);
  } else {
    page_->SetInspectorDeviceScaleFactorOverride(1.0f);
  }
}

float WebViewImpl::PageScaleFactor() const {
  if (!GetPage())
    return 1;

  return GetPage()->GetVisualViewport().Scale();
}

float WebViewImpl::ClampPageScaleFactorToLimits(float scale_factor) const {
  return GetPageScaleConstraintsSet().FinalConstraints().ClampToConstraints(
      scale_factor);
}

void WebViewImpl::SetVisualViewportOffset(const gfx::PointF& offset) {
  DCHECK(GetPage());
  GetPage()->GetVisualViewport().SetLocation(offset);
}

gfx::PointF WebViewImpl::VisualViewportOffset() const {
  DCHECK(GetPage());
  return GetPage()->GetVisualViewport().VisibleRect().origin();
}

gfx::SizeF WebViewImpl::VisualViewportSize() const {
  DCHECK(GetPage());
  return GetPage()->GetVisualViewport().VisibleRect().size();
}

void WebViewImpl::SetPageScaleFactorAndLocation(float scale_factor,
                                                bool is_pinch_gesture_active,
                                                const gfx::PointF& location) {
  DCHECK(GetPage());

  GetPage()->GetVisualViewport().SetScaleAndLocation(
      ClampPageScaleFactorToLimits(scale_factor), is_pinch_gesture_active,
      location);
}

void WebViewImpl::SetPageScaleFactor(float scale_factor) {
  DCHECK(GetPage());
  DCHECK(MainFrameImpl());

  if (LocalFrame* frame = MainFrameImpl()->GetFrame()) {
    frame->SetScaleFactor(scale_factor);
  }
}

void WebViewImpl::SetZoomFactorForDeviceScaleFactor(
    float zoom_factor_for_device_scale_factor) {
  DCHECK(does_composite_);
  if (zoom_factor_for_device_scale_factor_ !=
      zoom_factor_for_device_scale_factor) {
    zoom_factor_for_device_scale_factor_ = zoom_factor_for_device_scale_factor;
    UpdateWidgetZoomFactors();
    UpdateInspectorDeviceScaleFactorOverride();
  }
}

void WebViewImpl::SetPageLifecycleStateFromNewPageCommit(
    mojom::blink::PageVisibilityState visibility,
    mojom::blink::PagehideDispatch pagehide_dispatch) {
  TRACE_EVENT0("navigation",
               "WebViewImpl::SetPageLifecycleStateFromNewPageCommit");
  mojom::blink::PageLifecycleStatePtr state =
      GetPage()->GetPageLifecycleState().Clone();
  state->visibility = visibility;
  state->pagehide_dispatch = pagehide_dispatch;
  SetPageLifecycleStateInternal(std::move(state),
                                /*page_restore_params=*/nullptr);
}

void WebViewImpl::SetPageLifecycleState(
    mojom::blink::PageLifecycleStatePtr state,
    mojom::blink::PageRestoreParamsPtr page_restore_params,
    SetPageLifecycleStateCallback callback) {
  TRACE_EVENT0("navigation", "WebViewImpl::SetPageLifecycleState");
  SetPageLifecycleStateInternal(std::move(state),
                                std::move(page_restore_params));
  // Tell the browser that the lifecycle update was successful.
  std::move(callback).Run();
}

// Returns true if this state update is for the page being restored from
// back-forward cache, causing the pageshow event to fire with persisted=true.
bool IsRestoredFromBackForwardCache(
    const mojom::blink::PageLifecycleStatePtr& old_state,
    const mojom::blink::PageLifecycleStatePtr& new_state) {
  if (!old_state)
    return false;
  bool old_state_hidden = old_state->pagehide_dispatch !=
                          mojom::blink::PagehideDispatch::kNotDispatched;
  bool new_state_shown = new_state->pagehide_dispatch ==
                         mojom::blink::PagehideDispatch::kNotDispatched;
  // It's a pageshow but it can't be the initial pageshow since it was already
  // hidden. So it must be a back-forward cache restore.
  return old_state_hidden && new_state_shown;
}

void WebViewImpl::SetPageLifecycleStateInternal(
    mojom::blink::PageLifecycleStatePtr new_state,
    mojom::blink::PageRestoreParamsPtr page_restore_params) {
  Page* page = GetPage();
  if (!page)
    return;
  auto& old_state = page->GetPageLifecycleState();
  TRACE_EVENT2("navigation", "WebViewImpl::SetPageLifecycleStateInternal",
               "old_state", old_state, "new_state", new_state);

  bool storing_in_bfcache = new_state->is_in_back_forward_cache &&
                            !old_state->is_in_back_forward_cache;
  bool restoring_from_bfcache = !new_state->is_in_back_forward_cache &&
                                old_state->is_in_back_forward_cache;
  // `hiding_page` indicates that the page is switching visibility states in a
  // way that we should treat as a change.  There are two definitions of this
  // (see below), but both require that the new state is not `kVisible`.
  bool hiding_page =
      new_state->visibility != mojom::blink::PageVisibilityState::kVisible;
  if (RuntimeEnabledFeatures::DispatchHiddenVisibilityTransitionsEnabled()) {
    // Dispatch a visibility change from `kVisible` to either hidden state, and
    // also between the two hidden states.
    hiding_page &= (old_state->visibility != new_state->visibility);
  } else {
    // Dispatch a visibility change only when entering or leaving `kVisible` to
    // one of the two hidden states, but not when switching between `kHidden`
    // and `kHiddenButPainting` in either direction.
    hiding_page &=
        (old_state->visibility == mojom::blink::PageVisibilityState::kVisible);
  }
  bool showing_page =
      (new_state->visibility == mojom::blink::PageVisibilityState::kVisible) &&
      (old_state->visibility != mojom::blink::PageVisibilityState::kVisible);
  bool freezing_page = new_state->is_frozen && !old_state->is_frozen;
  bool resuming_page = !new_state->is_frozen && old_state->is_frozen;
  bool dispatching_pagehide =
      (new_state->pagehide_dispatch !=
       mojom::blink::PagehideDispatch::kNotDispatched) &&
      !GetPage()->DispatchedPagehideAndStillHidden();
  bool dispatching_pageshow =
      IsRestoredFromBackForwardCache(old_state, new_state);
  bool eviction_changed =
      new_state->eviction_enabled != old_state->eviction_enabled;

  if (dispatching_pagehide) {
    RemoveFocusAndTextInputState();
  }
  if (dispatching_pagehide) {
    // Note that |dispatching_pagehide| is different than |hiding_page|.
    // |dispatching_pagehide| will only be true when we're navigating away from
    // a page, while |hiding_page| might be true in other cases too such as when
    // the tab containing a page is backgrounded, and might be false even when
    // we're navigating away from a page, if the page is already hidden.
    DispatchPagehide(new_state->pagehide_dispatch);
  }
  if (hiding_page) {
    SetVisibilityState(new_state->visibility, /*is_initial_state=*/false);
  }
  if (storing_in_bfcache) {
    // TODO(https://crbug.com/1378279): Consider moving this to happen earlier
    // and together with other page state updates so that the ordering is clear.
    Scheduler()->SetPageBackForwardCached(new_state->is_in_back_forward_cache);
  }

  if (freezing_page) {
    // Notify all local frames that we are about to freeze.
    for (WebFrame* frame = MainFrame(); frame; frame = frame->TraverseNext()) {
      if (frame->IsWebLocalFrame()) {
        frame->ToWebLocalFrame()->Client()->WillFreezePage();
      }
    }

    // TODO(https://crbug.com/1378279): Consider moving this to happen earlier
    // and together with other page state updates so that the ordering is clear.
    SetPageFrozen(true);
  }

  if (restoring_from_bfcache) {
    DCHECK(page_restore_params);
    // Update the history offset and length value, as pages that are kept in
    // the back-forward cache do not get notified about updates on these
    // values, so the currently saved value might be stale.
    SetHistoryOffsetAndLength(page_restore_params->pending_history_list_offset,
                              page_restore_params->current_history_list_length);
  }
  if (eviction_changed)
    HookBackForwardCacheEviction(new_state->eviction_enabled);
  if (resuming_page) {
    // TODO(https://crbug.com/1378279): Consider moving this to happen earlier
    // and together with other page state updates so that the ordering is clear.
    SetPageFrozen(false);
  }
  if (showing_page) {
    SetVisibilityState(new_state->visibility, /*is_initial_state=*/false);
  }
  if (restoring_from_bfcache) {
    DCHECK(dispatching_pageshow);
    DCHECK(page_restore_params);
    // Increment the navigation counter on the main frame and all nested frames
    // in its frame tree.
    // Navigation Id increment should happen before a
    // BackForwardCacheRestoration instance is created which happens inside the
    // DispatchPageshow method.
    for (Frame* frame = page->MainFrame(); frame;
         frame = frame->Tree().TraverseNext()) {
      auto* local_frame = DynamicTo<LocalFrame>(frame);
      if (local_frame && local_frame->View()) {
        DCHECK(local_frame->DomWindow());
        local_frame->DomWindow()->GenerateNewNavigationId();
      }
    }

    DispatchPersistedPageshow(page_restore_params->navigation_start);

    // TODO(https://crbug.com/1378279): Consider moving this to happen earlier
    // and together with other page state updates so that the ordering is clear.
    Scheduler()->SetPageBackForwardCached(new_state->is_in_back_forward_cache);
    if (MainFrame()->IsWebLocalFrame()) {
      LocalFrame* local_frame = To<LocalFrame>(page->MainFrame());
      probe::DidRestoreFromBackForwardCache(local_frame);

      if (local_frame->IsOutermostMainFrame()) {
        Document* document = local_frame->GetDocument();
        if (auto* document_rules =
                DocumentSpeculationRules::FromIfExists(*document)) {
          document_rules->DocumentRestoredFromBFCache();
        }
      }
    }
  }

  // Make sure no TrackedFeaturesUpdate message is sent after the ACK
  // TODO(carlscab): Do we really need to go through LocalFrame =>
  // platform/scheduler/ => LocalFrame to report the features? We can probably
  // move SchedulerTrackedFeatures to core/ and remove the back and forth.
  ReportActiveSchedulerTrackedFeatures();

  // TODO(https://crbug.com/1378279): Consider moving this to happen earlier
  // and together with other page state updates so that the ordering is clear.
  GetPage()->SetPageLifecycleState(std::move(new_state));

  // Notify all local frames that we've updated the page lifecycle state.
  for (WebFrame* frame = MainFrame(); frame; frame = frame->TraverseNext()) {
    if (frame->IsWebLocalFrame()) {
      frame->ToWebLocalFrame()->Client()->DidSetPageLifecycleState(
          restoring_from_bfcache);
    }
  }

  UpdateViewTransitionState(restoring_from_bfcache, storing_in_bfcache,
                            page_restore_params);

  if (RuntimeEnabledFeatures::PageRevealEventEnabled()) {
    if (restoring_from_bfcache) {
      for (Frame* frame = GetPage()->MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
          CHECK(local_frame->GetDocument());
          local_frame->GetDocument()->EnqueuePageRevealEvent();
        }
      }
    }
  }
}

void WebViewImpl::UpdateViewTransitionState(
    bool restoring_from_bfcache,
    bool storing_in_bfcache,
    const mojom::blink::PageRestoreParamsPtr& page_restore_params) {
  // If we have view_transition_state, then we must be a main frame.
  DCHECK(!page_restore_params || !page_restore_params->view_transition_state ||
         MainFrame()->IsWebLocalFrame());
  // We can't be both restoring and storing things.
  DCHECK(!restoring_from_bfcache || !storing_in_bfcache);

  if (!MainFrame()->IsWebLocalFrame()) {
    return;
  }
  LocalFrame* local_frame = To<LocalFrame>(GetPage()->MainFrame());
  DCHECK(local_frame);

  // When restoring from BFCache, start a transition if we have a view
  // transition state.
  if (restoring_from_bfcache && page_restore_params->view_transition_state) {
    if (auto* document = local_frame->GetDocument()) {
      ViewTransitionSupplement::CreateFromSnapshotForNavigation(
          *document, std::move(*page_restore_params->view_transition_state));
    }
  }

  // If we're storing the page in BFCache, abort any pending transitions. This
  // is important since when we bring the page back from BFCache, we might
  // attempt to create a transition and fail if there is one already happening.
  // Note that even if we won't be creating a transition, it's harmless to abort
  // the main frame transition when going into BFCache.
  if (storing_in_bfcache) {
    if (auto* document = local_frame->GetDocument()) {
      ViewTransitionSupplement::AbortTransition(*document);
    }
  }
}

void WebViewImpl::ReportActiveSchedulerTrackedFeatures() {
  Page* page = GetPage();
  if (!page)
    return;

  for (Frame* frame = page->MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (!frame->IsLocalFrame())
      continue;
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame->GetFrameScheduler())
      continue;
    local_frame->GetFrameScheduler()->ReportActiveSchedulerTrackedFeatures();
  }
}

void WebViewImpl::AudioStateChanged(bool is_audio_playing) {
  GetPage()->GetPageScheduler()->AudioStateChanged(is_audio_playing);
}

void WebViewImpl::RemoveFocusAndTextInputState() {
  auto& focus_controller = GetPage()->GetFocusController();
  auto* focused_frame = focus_controller.FocusedFrame();
  if (!focused_frame)
    return;
  // Remove focus from the currently focused element and frame.
  focus_controller.SetFocusedElement(nullptr, nullptr);
  // Clear composing state, and make sure we send a TextInputState update.
  // Note that the TextInputState itself is cleared when we clear the focus,
  // but no updates to the browser will be triggered until the next animation
  // frame, which won't happen if we're freezing the page.
  if (auto* widget = static_cast<WebFrameWidgetImpl*>(
          focused_frame->GetWidgetForLocalRoot())) {
    widget->FinishComposingText(false /* keep_selection */);
    widget->UpdateTextInputState();
  }
}

void WebViewImpl::DispatchPagehide(
    mojom::blink::PagehideDispatch pagehide_dispatch) {
  DCHECK_NE(pagehide_dispatch, mojom::blink::PagehideDispatch::kNotDispatched);
  bool persisted = (pagehide_dispatch ==
                    mojom::blink::PagehideDispatch::kDispatchedPersisted);
  // Dispatch pagehide on all frames.
  for (Frame* frame = GetPage()->MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (frame->DomWindow() && frame->DomWindow()->IsLocalDOMWindow()) {
      frame->DomWindow()->ToLocalDOMWindow()->DispatchPagehideEvent(
          persisted
              ? PageTransitionEventPersistence::kPageTransitionEventPersisted
              : PageTransitionEventPersistence::
                    kPageTransitionEventNotPersisted);
    }
  }
}

void WebViewImpl::DispatchPersistedPageshow(base::TimeTicks navigation_start) {
  for (Frame* frame = GetPage()->MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    // Record the metics.
    if (local_frame && local_frame->View()) {
      Document* document = local_frame->GetDocument();
      if (document) {
        PaintTiming::From(*document).OnRestoredFromBackForwardCache();
        InteractiveDetector::From(*document)->OnRestoredFromBackForwardCache();
      }
      DocumentLoader* loader = local_frame->Loader().GetDocumentLoader();
      if (loader) {
        loader->GetTiming().SetBackForwardCacheRestoreNavigationStart(
            navigation_start);
      }
    }
    if (frame->DomWindow() && frame->DomWindow()->IsLocalDOMWindow()) {
      auto pageshow_start_time = base::TimeTicks::Now();
      LocalDOMWindow* window = frame->DomWindow()->ToLocalDOMWindow();

      window->DispatchPersistedPageshowEvent(navigation_start);

      if (RuntimeEnabledFeatures::NavigationIdEnabled(window)) {
        auto pageshow_end_time = base::TimeTicks::Now();

        WindowPerformance* performance =
            DOMWindowPerformance::performance(*window);
        DCHECK(performance);

        performance->AddBackForwardCacheRestoration(
            navigation_start, pageshow_start_time, pageshow_end_time);
      }
      if (frame->IsOutermostMainFrame()) {
        UMA_HISTOGRAM_BOOLEAN(
            "BackForwardCache.MainFrameHasPageshowListenersOnRestore",
            window->HasEventListeners(event_type_names::kPageshow));
      }
    }
  }
}

void WebViewImpl::HookBackForwardCacheEviction(bool hook) {
  DCHECK(GetPage());
  for (Frame* frame = GetPage()->MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;
    if (hook)
      local_frame->HookBackForwardCacheEviction();
    else
      local_frame->RemoveBackForwardCacheEviction();
  }
}

void WebViewImpl::EnableAutoResizeMode(const gfx::Size& min_size,
                                       const gfx::Size& max_size) {
  should_auto_resize_ = true;
  min_auto_size_ = min_size;
  max_auto_size_ = max_size;
  ConfigureAutoResizeMode();
}

void WebViewImpl::DisableAutoResizeMode() {
  should_auto_resize_ = false;
  ConfigureAutoResizeMode();
}

bool WebViewImpl::AutoResizeMode() {
  return should_auto_resize_;
}

void WebViewImpl::EnableAutoResizeForTesting(const gfx::Size& min_window_size,
                                             const gfx::Size& max_window_size) {
  EnableAutoResizeMode(web_widget_->DIPsToCeiledBlinkSpace(min_window_size),
                       web_widget_->DIPsToCeiledBlinkSpace(max_window_size));
}

void WebViewImpl::DisableAutoResizeForTesting(
    const gfx::Size& new_window_size) {
  if (!should_auto_resize_)
    return;
  DisableAutoResizeMode();

  // The |new_size| is empty when resetting auto resize in between tests. In
  // this case the current size should just be preserved.
  if (!new_window_size.IsEmpty()) {
    web_widget_->Resize(web_widget_->DIPsToCeiledBlinkSpace(new_window_size));
  }
}

void WebViewImpl::SetDefaultPageScaleLimits(float min_scale, float max_scale) {
  dev_tools_emulator_->SetDefaultPageScaleLimits(min_scale, max_scale);
}

void WebViewImpl::SetInitialPageScaleOverride(
    float initial_page_scale_factor_override) {
  PageScaleConstraints constraints =
      GetPageScaleConstraintsSet().UserAgentConstraints();
  constraints.initial_scale = initial_page_scale_factor_override;

  if (constraints == GetPageScaleConstraintsSet().UserAgentConstraints())
    return;

  GetPageScaleConstraintsSet().SetNeedsReset(true);
  GetPage()->SetUserAgentPageScaleConstraints(constraints);
}

void WebViewImpl::SetMaximumLegibleScale(float maximum_legible_scale) {
  maximum_legible_scale_ = maximum_legible_scale;
}

void WebViewImpl::SetIgnoreViewportTagScaleLimits(bool ignore) {
  PageScaleConstraints constraints =
      GetPageScaleConstraintsSet().UserAgentConstraints();
  if (ignore) {
    constraints.minimum_scale =
        GetPageScaleConstraintsSet().DefaultConstraints().minimum_scale;
    constraints.maximum_scale =
        GetPageScaleConstraintsSet().DefaultConstraints().maximum_scale;
  } else {
    constraints.minimum_scale = -1;
    constraints.maximum_scale = -1;
  }
  GetPage()->SetUserAgentPageScaleConstraints(constraints);
}

gfx::Size WebViewImpl::MainFrameSize() {
  // The frame size should match the viewport size at minimum scale, since the
  // viewport must always be contained by the frame.
  return gfx::ScaleToCeiledSize(size_, 1 / MinimumPageScaleFactor());
}

PageScaleConstraintsSet& WebViewImpl::GetPageScaleConstraintsSet() const {
  return GetPage()->GetPageScaleConstraintsSet();
}

void WebViewImpl::RefreshPageScaleFactor() {
  if (!MainFrame() || !GetPage() || !GetPage()->MainFrame() ||
      !GetPage()->MainFrame()->IsLocalFrame() ||
      !GetPage()->DeprecatedLocalMainFrame()->View())
    return;
  UpdatePageDefinedViewportConstraints(MainFrameImpl()
                                           ->GetFrame()
                                           ->GetDocument()
                                           ->GetViewportData()
                                           .GetViewportDescription());
  GetPageScaleConstraintsSet().ComputeFinalConstraints();

  float new_page_scale_factor = PageScaleFactor();
  if (GetPageScaleConstraintsSet().NeedsReset() &&
      GetPageScaleConstraintsSet().FinalConstraints().initial_scale != -1) {
    new_page_scale_factor =
        GetPageScaleConstraintsSet().FinalConstraints().initial_scale;
    GetPageScaleConstraintsSet().SetNeedsReset(false);
  }
  SetPageScaleFactor(new_page_scale_factor);

  // The constraints may have changed above which affects the page scale limits,
  // so we must update those even though SetPageScaleFactor() may do the same if
  // the scale factor is changed.
  if (does_composite_) {
    auto& viewport = GetPage()->GetVisualViewport();
    MainFrameImpl()->FrameWidgetImpl()->SetPageScaleStateAndLimits(
        viewport.Scale(), viewport.IsPinchGestureActive(),
        MinimumPageScaleFactor(), MaximumPageScaleFactor());
  }
}

void WebViewImpl::UpdatePageDefinedViewportConstraints(
    const ViewportDescription& description) {
  if (!GetPage() || (!size_.width() && !size_.height()))
    return;
  // The viewport is a property of the main frame and its widget, so ignore it
  // when the main frame is remote.
  // TODO(danakj): Remove calls to this method from ChromeClient and DCHECK this
  // instead.
  if (!GetPage()->MainFrame()->IsLocalFrame())
    return;

  if (virtual_keyboard_mode_ != description.virtual_keyboard_mode) {
    DCHECK(MainFrameImpl()->IsOutermostMainFrame());
    virtual_keyboard_mode_ = description.virtual_keyboard_mode;
    mojom::blink::LocalFrameHost& frame_host =
        MainFrameImpl()->GetFrame()->GetLocalFrameHostRemote();

    frame_host.SetVirtualKeyboardMode(virtual_keyboard_mode_);
  }

  if (!GetSettings()->ViewportEnabled()) {
    GetPageScaleConstraintsSet().ClearPageDefinedConstraints();
    UpdateMainFrameLayoutSize();
    return;
  }

  Document* document = GetPage()->DeprecatedLocalMainFrame()->GetDocument();

  Length default_min_width =
      document->GetViewportData().ViewportDefaultMinWidth();
  if (default_min_width.IsAuto())
    default_min_width = Length::ExtendToZoom();

  float old_initial_scale =
      GetPageScaleConstraintsSet().PageDefinedConstraints().initial_scale;
  GetPageScaleConstraintsSet().UpdatePageDefinedConstraints(description,
                                                            default_min_width);

  if (SettingsImpl()->ClobberUserAgentInitialScaleQuirk() &&
      GetPageScaleConstraintsSet().UserAgentConstraints().initial_scale != -1 &&
      GetPageScaleConstraintsSet().UserAgentConstraints().initial_scale <= 1) {
    if (description.max_width == Length::DeviceWidth() ||
        (description.max_width.IsAuto() &&
         GetPageScaleConstraintsSet().PageDefinedConstraints().initial_scale ==
             1.0f))
      SetInitialPageScaleOverride(-1);
  }

  Settings& page_settings = GetPage()->GetSettings();
  GetPageScaleConstraintsSet().AdjustForAndroidWebViewQuirks(
      description, default_min_width.IntValue(),
      SettingsImpl()->SupportDeprecatedTargetDensityDPI(),
      page_settings.GetWideViewportQuirkEnabled(),
      page_settings.GetUseWideViewport(),
      page_settings.GetLoadWithOverviewMode(),
      SettingsImpl()->ViewportMetaNonUserScalableQuirk());
  float new_initial_scale =
      GetPageScaleConstraintsSet().PageDefinedConstraints().initial_scale;
  if (old_initial_scale != new_initial_scale && new_initial_scale != -1) {
    GetPageScaleConstraintsSet().SetNeedsReset(true);
    if (MainFrameImpl() && MainFrameImpl()->GetFrameView())
      MainFrameImpl()->GetFrameView()->SetNeedsLayout();
  }

  if (does_composite_) {
    MainFrameImpl()->FrameWidgetImpl()->UpdateViewportDescription(description);
  }

  UpdateMainFrameLayoutSize();

  if (RuntimeEnabledFeatures::ViewportChangesUpdateTextAutosizingEnabled()) {
    TextAutosizer::UpdatePageInfoInAllFrames(GetPage()->MainFrame());
  }
}

void WebViewImpl::UpdateMainFrameLayoutSize() {
  if (should_auto_resize_ || !MainFrameImpl())
    return;

  LocalFrameView* view = MainFrameImpl()->GetFrameView();
  if (!view)
    return;

  gfx::Size layout_size = size_;

  if (GetSettings()->ViewportEnabled())
    layout_size = GetPageScaleConstraintsSet().GetLayoutSize();

  if (GetPage()->GetSettings().GetForceZeroLayoutHeight())
    layout_size.set_height(0);

  view->SetLayoutSize(layout_size);
}

gfx::Size WebViewImpl::ContentsSize() const {
  if (!GetPage()->MainFrame()->IsLocalFrame())
    return gfx::Size();
  auto* layout_view =
      GetPage()->DeprecatedLocalMainFrame()->ContentLayoutObject();
  if (!layout_view)
    return gfx::Size();
  return ToPixelSnappedRect(layout_view->DocumentRect()).size();
}

gfx::Size WebViewImpl::ContentsPreferredMinimumSize() {
  DCHECK(page_->MainFrame()->IsLocalFrame());

  auto* main_local_frame = DynamicTo<LocalFrame>(page_->MainFrame());
  Document* document = main_local_frame->GetDocument();
  if (!document || !document->GetLayoutView() || !document->documentElement() ||
      !document->documentElement()->GetLayoutBox())
    return gfx::Size();

  // The preferred size requires an up-to-date layout tree.
  DCHECK(!document->NeedsLayoutTreeUpdate() &&
         !document->View()->NeedsLayout());

  // Needed for computing MinPreferredWidth.
  FontCachePurgePreventer fontCachePurgePreventer;
  // Already accounts for zoom.
  int width_scaled = document->GetLayoutView()->ComputeMinimumWidth().Round();
  int height_scaled =
      document->documentElement()->GetLayoutBox()->ScrollHeight().Round();
  return gfx::Size(width_scaled, height_scaled);
}

void WebViewImpl::UpdatePreferredSize() {
  // We don't always want to send the change messages over IPC, only if we've
  // been put in that mode by getting a |ViewMsg_EnablePreferredSizeChangedMode|
  // message.
  if (!send_preferred_size_changes_ || !MainFrameImpl())
    return;

  if (!needs_preferred_size_update_)
    return;
  needs_preferred_size_update_ = false;

  gfx::Size size_in_dips =
      MainFrameImpl()->LocalRootFrameWidget()->BlinkSpaceToFlooredDIPs(
          gfx::Size(ContentsPreferredMinimumSize()));

  if (size_in_dips != preferred_size_in_dips_) {
    preferred_size_in_dips_ = size_in_dips;
    local_main_frame_host_remote_->ContentsPreferredSizeChanged(size_in_dips);
  }
}

void WebViewImpl::EnablePreferredSizeChangedMode() {
  if (send_preferred_size_changes_)
    return;
  send_preferred_size_changes_ = true;
  needs_preferred_size_update_ = true;

  // We need to ensure |UpdatePreferredSize| gets called. If a layout is needed,
  // force an update here which will call |DidUpdateMainFrameLayout|.
  if (MainFrameWidget()) {
    MainFrameWidget()->UpdateLifecycle(WebLifecycleUpdate::kLayout,
                                       DocumentUpdateReason::kSizeChange);
  }

  // If a layout was not needed, |DidUpdateMainFrameLayout| will not be called.
  // We explicitly update the preferred size here to ensure the preferred size
  // notification is sent.
  UpdatePreferredSize();
}

void WebViewImpl::Focus() {
  if (GetPage()->MainFrame()->IsLocalFrame()) {
    DCHECK(local_main_frame_host_remote_);
    local_main_frame_host_remote_->FocusPage();
  } else {
    DCHECK(remote_main_frame_host_remote_);
    remote_main_frame_host_remote_->FocusPage();
  }
}

void WebViewImpl::TakeFocus(bool reverse) {
  if (GetPage()->MainFrame()->IsLocalFrame()) {
    DCHECK(local_main_frame_host_remote_);
    local_main_frame_host_remote_->TakeFocus(reverse);
  } else {
    DCHECK(remote_main_frame_host_remote_);
    remote_main_frame_host_remote_->TakeFocus(reverse);
  }
}

void WebViewImpl::Show(const LocalFrameToken& opener_frame_token,
                       NavigationPolicy policy,
                       const gfx::Rect& requested_rect,
                       const gfx::Rect& adjusted_rect,
                       bool opened_by_user_gesture) {
  // This is only called on local main frames.
  DCHECK(local_main_frame_host_remote_);
  DCHECK(web_widget_);
  web_widget_->SetPendingWindowRect(adjusted_rect);
  const WebWindowFeatures& web_window_features = page_->GetWindowFeatures();
  mojom::blink::WindowFeaturesPtr window_features =
      mojom::blink::WindowFeatures::New();
  window_features->bounds = requested_rect;
  window_features->has_x = web_window_features.x_set;
  window_features->has_y = web_window_features.y_set;
  window_features->has_width = web_window_features.width_set;
  window_features->has_height = web_window_features.height_set;
  window_features->is_popup = web_window_features.is_popup;
  window_features->is_partitioned_popin =
      web_window_features.is_partitioned_popin;
  local_main_frame_host_remote_->ShowCreatedWindow(
      opener_frame_token, NavigationPolicyToDisposition(policy),
      std::move(window_features), opened_by_user_gesture,
      WTF::BindOnce(&WebViewImpl::DidShowCreatedWindow, WTF::Unretained(this)));

  if (auto* dev_tools_agent =
          MainFrameImpl()->DevToolsAgentImpl(/*create_if_necessary=*/false)) {
    dev_tools_agent->DidShowNewWindow();
  }
}

void WebViewImpl::DidShowCreatedWindow() {
  web_widget_->AckPendingWindowRect();
}

void WebViewImpl::SendWindowRectToMainFrameHost(
    const gfx::Rect& bounds,
    base::OnceClosure ack_callback) {
  DCHECK(local_main_frame_host_remote_);
  local_main_frame_host_remote_->SetWindowRect(bounds, std::move(ack_callback));
}

void WebViewImpl::DidAccessInitialMainDocument() {
  DCHECK(local_main_frame_host_remote_);
  local_main_frame_host_remote_->DidAccessInitialMainDocument();
}

void WebViewImpl::Minimize() {
  DCHECK(local_main_frame_host_remote_);
  local_main_frame_host_remote_->Minimize();
}

void WebViewImpl::Maximize() {
  DCHECK(local_main_frame_host_remote_);
  local_main_frame_host_remote_->Maximize();
}

void WebViewImpl::Restore() {
  DCHECK(local_main_frame_host_remote_);
  local_main_frame_host_remote_->Restore();
}

void WebViewImpl::SetResizable(bool resizable) {
  DCHECK(local_main_frame_host_remote_);
  local_main_frame_host_remote_->SetResizable(resizable);
}

void WebViewImpl::UpdateTargetURL(const WebURL& url,
                                  const WebURL& fallback_url) {
  KURL latest_url = KURL(url.IsEmpty() ? fallback_url : url);
  if (latest_url == target_url_)
    return;

  // Tell the browser to display a destination link.
  if (target_url_status_ == TARGET_INFLIGHT ||
      target_url_status_ == TARGET_PENDING) {
    // If we have a request in-flight, save the URL to be sent when we
    // receive an ACK to the in-flight request. We can happily overwrite
    // any existing pending sends.
    pending_target_url_ = latest_url;
    target_url_status_ = TARGET_PENDING;
  } else {
    // URLs larger than |kMaxURLChars| cannot be sent through IPC -
    // see |ParamTraits<GURL>|.
    if (latest_url.GetString().length() > url::kMaxURLChars)
      latest_url = KURL();
    SendUpdatedTargetURLToBrowser(latest_url);
    target_url_ = latest_url;
    target_url_status_ = TARGET_INFLIGHT;
  }
}

void WebViewImpl::SendUpdatedTargetURLToBrowser(const KURL& target_url) {
  // Note: WTF::Unretained() usage below is safe, since `this` owns both
  // `mojo::Remote` objects.
  if (GetPage()->MainFrame()->IsLocalFrame()) {
    DCHECK(local_main_frame_host_remote_);
    local_main_frame_host_remote_->UpdateTargetURL(
        target_url, WTF::BindOnce(&WebViewImpl::TargetURLUpdatedInBrowser,
                                  WTF::Unretained(this)));
  } else {
    DCHECK(remote_main_frame_host_remote_);
    remote_main_frame_host_remote_->UpdateTargetURL(
        target_url, WTF::BindOnce(&WebViewImpl::TargetURLUpdatedInBrowser,
                                  WTF::Unretained(this)));
  }
}

void WebViewImpl::TargetURLUpdatedInBrowser() {
  // Check if there is a targeturl waiting to be sent.
  if (target_url_status_ == TARGET_PENDING)
    SendUpdatedTargetURLToBrowser(pending_target_url_);

  target_url_status_ = TARGET_NONE;
}

float WebViewImpl::DefaultMinimumPageScaleFactor() const {
  return GetPageScaleConstraintsSet().DefaultConstraints().minimum_scale;
}

float WebViewImpl::DefaultMaximumPageScaleFactor() const {
  return GetPageScaleConstraintsSet().DefaultConstraints().maximum_scale;
}

float WebViewImpl::MinimumPageScaleFactor() const {
  return 
"""


```