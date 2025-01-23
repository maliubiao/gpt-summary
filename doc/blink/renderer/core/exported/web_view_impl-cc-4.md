Response:

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
GetPageScaleConstraintsSet().FinalConstraints().minimum_scale;
}

float WebViewImpl::MaximumPageScaleFactor() const {
  return GetPageScaleConstraintsSet().FinalConstraints().maximum_scale;
}

void WebViewImpl::ResetScaleStateImmediately() {
  GetPageScaleConstraintsSet().SetNeedsReset(true);
}

void WebViewImpl::ResetScrollAndScaleState() {
  GetPage()->GetVisualViewport().Reset();

  auto* main_local_frame = DynamicTo<LocalFrame>(GetPage()->MainFrame());
  if (!main_local_frame)
    return;

  if (LocalFrameView* frame_view = main_local_frame->View()) {
    ScrollableArea* scrollable_area = frame_view->LayoutViewport();

    if (!scrollable_area->GetScrollOffset().IsZero()) {
      scrollable_area->SetScrollOffset(ScrollOffset(),
                                       mojom::blink::ScrollType::kProgrammatic);
    }
  }

  if (Document* document = main_local_frame->GetDocument()) {
    if (DocumentLoader* loader = document->Loader()) {
      if (HistoryItem* item = loader->GetHistoryItem())
        item->ClearViewState();
    }
  }

  GetPageScaleConstraintsSet().SetNeedsReset(true);
}

void WebViewImpl::SendResizeEventForMainFrame() {
  // FIXME: This is wrong. The LocalFrameView is responsible sending a
  // resizeEvent as part of layout. Layout is also responsible for sending
  // invalidations to the embedder. This method and all callers may be wrong. --
  // eseidel.
  if (MainFrameImpl()->GetFrameView()) {
    // Enqueues the resize event.
    MainFrameImpl()->GetFrame()->GetDocument()->EnqueueResizeEvent();
  }

  // A resized main frame can change the page scale limits.
  if (does_composite_) {
    auto& viewport = GetPage()->GetVisualViewport();
    MainFrameImpl()->FrameWidgetImpl()->SetPageScaleStateAndLimits(
        viewport.Scale(), viewport.IsPinchGestureActive(),
        MinimumPageScaleFactor(), MaximumPageScaleFactor());
  }
}

void WebViewImpl::ConfigureAutoResizeMode() {
  if (!MainFrameImpl() || !MainFrameImpl()->GetFrame() ||
      !MainFrameImpl()->GetFrame()->View())
    return;

  if (should_auto_resize_) {
    MainFrameImpl()->GetFrame()->View()->EnableAutoSizeMode(min_auto_size_,
                                                            max_auto_size_);
  } else {
    MainFrameImpl()->GetFrame()->View()->DisableAutoSizeMode();
  }
}

void WebViewImpl::SetCompositorDeviceScaleFactorOverride(
    float device_scale_factor) {
  if (compositor_device_scale_factor_override_ != device_scale_factor) {
    compositor_device_scale_factor_override_ = device_scale_factor;
    UpdateWidgetZoomFactors();
    UpdateInspectorDeviceScaleFactorOverride();
  }
}

void WebViewImpl::SetDeviceEmulationTransform(const gfx::Transform& transform) {
  if (transform == device_emulation_transform_)
    return;
  device_emulation_transform_ = transform;
  UpdateDeviceEmulationTransform();
}

gfx::Transform WebViewImpl::GetDeviceEmulationTransform() const {
  return device_emulation_transform_;
}

void WebViewImpl::EnableDeviceEmulation(const DeviceEmulationParams& params) {
  web_widget_->EnableDeviceEmulation(params);
}

void WebViewImpl::ActivateDevToolsTransform(
    const DeviceEmulationParams& params) {
  gfx::Transform device_emulation_transform =
      dev_tools_emulator_->EnableDeviceEmulation(params);
  SetDeviceEmulationTransform(device_emulation_transform);
}

void WebViewImpl::DisableDeviceEmulation() {
  web_widget_->DisableDeviceEmulation();
}

void WebViewImpl::DeactivateDevToolsTransform() {
  dev_tools_emulator_->DisableDeviceEmulation();
  SetDeviceEmulationTransform(gfx::Transform());
}

void WebViewImpl::PerformCustomContextMenuAction(unsigned action) {
  if (page_) {
    page_->GetContextMenuController().CustomContextMenuItemSelected(action);
  }
}

void WebViewImpl::DidCloseContextMenu() {
  LocalFrame* frame = page_->GetFocusController().FocusedFrame();
  if (frame)
    frame->Selection().SetCaretBlinkingSuspended(false);
}

SkColor WebViewImpl::BackgroundColor() const {
  if (background_color_override_for_fullscreen_controller_)
    return background_color_override_for_fullscreen_controller_.value();
  Page* page = page_.Get();
  if (!page)
    return BaseBackgroundColor().Rgb();
  if (auto* main_local_frame = DynamicTo<LocalFrame>(page->MainFrame())) {
    LocalFrameView* view = main_local_frame->View();
    if (view)
      return view->DocumentBackgroundColor().Rgb();
  }
  return BaseBackgroundColor().Rgb();
}

Color WebViewImpl::BaseBackgroundColor() const {
  if (override_base_background_color_to_transparent_)
    return Color::kTransparent;
  // TODO(https://crbug.com/1351544): The base background color override should
  // be an SkColor4f or a Color.
  if (base_background_color_override_for_inspector_) {
    return Color::FromSkColor(
        base_background_color_override_for_inspector_.value());
  }
  // Use the page background color if this is the WebView of the main frame.
  if (MainFrameImpl())
    return Color::FromSkColor(page_base_background_color_);
  return Color::kWhite;
}

void WebViewImpl::SetPageBaseBackgroundColor(std::optional<SkColor> color) {
  SkColor new_color = color.value_or(SK_ColorWHITE);
  if (page_base_background_color_ == new_color)
    return;
  page_base_background_color_ = new_color;
  UpdateBaseBackgroundColor();
}

void WebViewImpl::UpdateColorProviders(
    const ColorProviderColorMaps& color_provider_colors) {
  bool color_providers_did_change =
      page_->UpdateColorProviders(color_provider_colors);
  if (color_providers_did_change) {
    Page::ForcedColorsChanged();
  }
}

void WebViewImpl::SetBaseBackgroundColorOverrideTransparent(
    bool override_to_transparent) {
  DCHECK(does_composite_);
  if (override_base_background_color_to_transparent_ == override_to_transparent)
    return;
  override_base_background_color_to_transparent_ = override_to_transparent;
  UpdateBaseBackgroundColor();
}

void WebViewImpl::SetBaseBackgroundColorOverrideForInspector(
    std::optional<SkColor> optional_color) {
  if (base_background_color_override_for_inspector_ == optional_color)
    return;
  base_background_color_override_for_inspector_ = optional_color;
  UpdateBaseBackgroundColor();
}

void WebViewImpl::UpdateBaseBackgroundColor() {
  if (MainFrameImpl()) {
    // Force lifecycle update to ensure we're good to call
    // LocalFrameView::setBaseBackgroundColor().
    MainFrameImpl()->GetFrame()->View()->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kBaseColor);
  }

  Color color = BaseBackgroundColor();
  if (auto* local_frame = DynamicTo<LocalFrame>(page_->MainFrame())) {
    LocalFrameView* view = local_frame->View();
    view->UpdateBaseBackgroundColorRecursively(color);
  }
}

void WebViewImpl::UpdateFontRenderingFromRendererPrefs() {
#if !BUILDFLAG(IS_MAC)
  skia::LegacyDisplayGlobals::SetCachedParams(
      gfx::FontRenderParams::SubpixelRenderingToSkiaPixelGeometry(
          renderer_preferences_.subpixel_rendering),
      renderer_preferences_.text_contrast, renderer_preferences_.text_gamma);
#if BUILDFLAG(IS_WIN)
  // Cache the system font metrics in blink.
  WebFontRendering::SetMenuFontMetrics(
      WebString::FromUTF16(renderer_preferences_.menu_font_family_name),
      renderer_preferences_.menu_font_height);
  WebFontRendering::SetSmallCaptionFontMetrics(
      WebString::FromUTF16(
          renderer_preferences_.small_caption_font_family_name),
      renderer_preferences_.small_caption_font_height);
  WebFontRendering::SetStatusFontMetrics(
      WebString::FromUTF16(renderer_preferences_.status_font_family_name),
      renderer_preferences_.status_font_height);
  WebFontRendering::SetAntialiasedTextEnabled(
      renderer_preferences_.should_antialias_text);
  WebFontRendering::SetLCDTextEnabled(
      renderer_preferences_.subpixel_rendering !=
      gfx::FontRenderParams::SUBPIXEL_RENDERING_NONE);
#else
  WebFontRenderStyle::SetHinting(
      RendererPreferencesToSkiaHinting(renderer_preferences_));
  WebFontRenderStyle::SetAutoHint(renderer_preferences_.use_autohinter);
  WebFontRenderStyle::SetUseBitmaps(renderer_preferences_.use_bitmaps);
  WebFontRenderStyle::SetAntiAlias(renderer_preferences_.should_antialias_text);
  WebFontRenderStyle::SetSubpixelRendering(
      renderer_preferences_.subpixel_rendering !=
      gfx::FontRenderParams::SUBPIXEL_RENDERING_NONE);
  WebFontRenderStyle::SetSubpixelPositioning(
      renderer_preferences_.use_subpixel_positioning);
#if BUILDFLAG(IS_LINUX)
  if (!renderer_preferences_.system_font_family_name.empty()) {
    WebFontRenderStyle::SetSystemFontFamily(blink::WebString::FromUTF8(
        renderer_preferences_.system_font_family_name));
  }
#endif  // BUILDFLAG(IS_LINUX)
#endif  // BUILDFLAG(IS_WIN)
#endif  // !BUILDFLAG(IS_MAC)
}

#if BUILDFLAG(IS_CHROMEOS)
void WebViewImpl::UpdateUseOverlayScrollbar(bool use_overlay_scrollbar) {
  ui::NativeTheme::GetInstanceForWeb()->set_use_overlay_scrollbar(
      use_overlay_scrollbar);
  if (MainFrameImpl() && MainFrameImpl()->GetFrameView()) {
    MainFrameImpl()->GetFrameView()->UsesOverlayScrollbarsChanged();
  }
}
#endif

void WebViewImpl::ActivatePrerenderedPage(
    mojom::blink::PrerenderPageActivationParamsPtr
        prerender_page_activation_params,
    ActivatePrerenderedPageCallback callback) {
  TRACE_EVENT0("navigation", "WebViewImpl::ActivatePrerenderedPage");

  // From here all new documents will have prerendering false.
  GetPage()->SetIsPrerendering(false);

  // Collect local documents. This is because we are about to run the
  // prerenderchange event and post-prerendering activation steps on each
  // document, which could mutate the frame tree and make iteration over it
  // complicated.
  HeapVector<Member<Document>> child_frame_documents;
  Member<Document> main_frame_document;
  if (auto* local_frame = DynamicTo<LocalFrame>(GetPage()->MainFrame())) {
    main_frame_document = local_frame->GetDocument();
  }
  if (main_frame_document) {
    RecordPrerenderActivationSignalDelay(GetPage()->PrerenderMetricSuffix());
  }

  for (Frame* frame = GetPage()->MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
      if (local_frame->GetDocument() != main_frame_document) {
        child_frame_documents.push_back(local_frame->GetDocument());
      }
    }
  }

  // A null `activation_start` is sent to the WebViewImpl that does not host the
  // main frame, in which case we expect that it does not have any documents
  // since cross-origin documents are not loaded during prerendering.
  DCHECK((!main_frame_document && child_frame_documents.size() == 0) ||
         !prerender_page_activation_params->activation_start.is_null());
  // We also only send view_transition_state to the main frame.
  DCHECK(main_frame_document ||
         !prerender_page_activation_params->view_transition_state);

  if (main_frame_document) {
    main_frame_document->ActivateForPrerendering(
        *prerender_page_activation_params);
    prerender_page_activation_params->view_transition_state.reset();
  }

  // While the spec says to post a task on the networking task source for each
  // document, we don't post a task here for simplicity. This allows dispatching
  // the event on all documents without a chance for other IPCs from the browser
  // to arrive in the intervening time, resulting in an unclear state.
  for (auto& document : child_frame_documents) {
    document->ActivateForPrerendering(*prerender_page_activation_params);
  }

  std::move(callback).Run();
}

void WebViewImpl::RegisterRendererPreferenceWatcher(
    CrossVariantMojoRemote<mojom::RendererPreferenceWatcherInterfaceBase>
        watcher) {
  renderer_preference_watchers_.Add(std::move(watcher));
}

void WebViewImpl::SetRendererPreferences(
    const RendererPreferences& preferences) {
  UpdateRendererPreferences(preferences);
}

const RendererPreferences& WebViewImpl::GetRendererPreferences() const {
  return renderer_preferences_;
}

void WebViewImpl::UpdateRendererPreferences(
    const RendererPreferences& preferences) {
  std::string old_accept_languages = renderer_preferences_.accept_languages;
  renderer_preferences_ = preferences;

  for (auto& watcher : renderer_preference_watchers_)
    watcher->NotifyUpdate(renderer_preferences_);

  WebThemeEngineHelper::DidUpdateRendererPreferences(preferences);
  UpdateFontRenderingFromRendererPrefs();

  blink::SetCaretBlinkInterval(
      renderer_preferences_.caret_blink_interval.has_value()
          ? renderer_preferences_.caret_blink_interval.value()
          : base::Milliseconds(
                mojom::blink::kDefaultCaretBlinkIntervalInMilliseconds));

#if defined(USE_AURA)
  if (renderer_preferences_.use_custom_colors) {
    SetFocusRingColor(renderer_preferences_.focus_ring_color);
    SetSelectionColors(renderer_preferences_.active_selection_bg_color,
                       renderer_preferences_.active_selection_fg_color,
                       renderer_preferences_.inactive_selection_bg_color,
                       renderer_preferences_.inactive_selection_fg_color);
    ThemeChanged();
  }
#endif

  if (renderer_preferences_.use_custom_colors) {
    SetFocusRingColor(renderer_preferences_.focus_ring_color);
  }

  if (old_accept_languages != renderer_preferences_.accept_languages)
    AcceptLanguagesChanged();

  GetSettings()->SetCaretBrowsingEnabled(
      renderer_preferences_.caret_browsing_enabled);

#if BUILDFLAG(IS_OZONE)
  GetSettings()->SetSelectionClipboardBufferAvailable(
      renderer_preferences_.selection_clipboard_buffer_available);
#endif  // BUILDFLAG(IS_OZONE)

  SetExplicitlyAllowedPorts(
      renderer_preferences_.explicitly_allowed_network_ports);

#if BUILDFLAG(IS_CHROMEOS)
  if (!ScrollbarTheme::MockScrollbarsEnabled()) {
    WebRuntimeFeatures::EnableOverlayScrollbars(
        renderer_preferences_.use_overlay_scrollbar);
    UpdateUseOverlayScrollbar(renderer_preferences_.use_overlay_scrollbar);
  }
#endif

  MaybePreloadSystemFonts(GetPage());
}

void WebViewImpl::SetHistoryOffsetAndLength(int32_t history_offset,
                                            int32_t history_length) {
  // -1 <= history_offset < history_length <= kMaxSessionHistoryEntries.
  DCHECK_LE(-1, history_offset);
  DCHECK_LT(history_offset, history_length);
  DCHECK_LE(history_length, kMaxSessionHistoryEntries);

  history_list_offset_ = history_offset;
  history_list_length_ = history_length;
}

void WebViewImpl::SetHistoryListFromNavigation(
    int32_t history_offset,
    std::optional<int32_t> history_length) {
  if (!history_length.has_value()) {
    history_list_offset_ = history_offset;
    return;
  }

  SetHistoryOffsetAndLength(history_offset, *history_length);
}

void WebViewImpl::IncreaseHistoryListFromNavigation() {
  // Advance our offset in session history, applying the length limit.
  // There is now no forward history.
  history_list_offset_ =
      std::min(history_list_offset_ + 1, kMaxSessionHistoryEntries - 1);
  history_list_length_ = history_list_offset_ + 1;
}

int32_t WebViewImpl::HistoryBackListCount() const {
  return std::max(history_list_offset_, 0);
}

int32_t WebViewImpl::HistoryForwardListCount() const {
  return history_list_length_ - HistoryBackListCount() - 1;
}

void WebViewImpl::SetWebPreferences(
    const web_pref::WebPreferences& preferences) {
  UpdateWebPreferences(preferences);
}

const web_pref::WebPreferences& WebViewImpl::GetWebPreferences() {
  return web_preferences_;
}

void WebViewImpl::UpdateWebPreferences(
    const blink::web_pref::WebPreferences& preferences) {
  web_preferences_ = preferences;

  if (IsFencedFrameRoot()) {
    // The main frame of a fenced frame should not behave like a top level
    // frame in terms of viewport behavior. i.e. It shouldn't allow zooming,
    // either explicitly or to fit content, and it should not interpret the
    // viewport <meta> tag. Text autosizing is disabled since it is only
    // determined by the outermost page and having the outermost page pass
    // it into the fenced frame can create a communication channel.
    web_preferences_.viewport_enabled = false;
    web_preferences_.viewport_meta_enabled = false;
    web_preferences_.default_minimum_page_scale_factor = 1.f;
    web_preferences_.default_maximum_page_scale_factor = 1.f;
    web_preferences_.shrinks_viewport_contents_to_fit = false;
    web_preferences_.main_frame_resizes_are_orientation_changes = false;
    web_preferences_.text_autosizing_enabled = false;

    // Insecure content should not be allowed in a fenced frame.
    web_preferences_.allow_running_insecure_content = false;

#if BUILDFLAG(IS_ANDROID)
    // Reusing the global for unowned main frame is only used for
    // Android WebView. Since this is a fenced frame it is not the
    // outermost main frame so we can safely disable this feature.
    web_preferences_.reuse_global_for_unowned_main_frame = false;
#endif
  }

  if (MainFrameImpl()) {
    MainFrameImpl()->FrameWidgetImpl()->SetPrefersReducedMotion(
        web_preferences_.prefers_reduced_motion);
  }

  ApplyWebPreferences(web_preferences_, this);
  ApplyCommandLineToSettings(SettingsImpl());
}

void WebViewImpl::AddObserver(WebViewObserver* observer) {
  observers_.AddObserver(observer);
}

void WebViewImpl::RemoveObserver(WebViewObserver* observer) {
  observers_.RemoveObserver(observer);
}

void WebViewImpl::SetIsActive(bool active) {
  if (GetPage())
    GetPage()->GetFocusController().SetActive(active);
}

bool WebViewImpl::IsActive() const {
  return GetPage() ? GetPage()->GetFocusController().IsActive() : false;
}

void WebViewImpl::SetWindowFeatures(const WebWindowFeatures& features) {
  page_->SetWindowFeatures(features);
}

void WebViewImpl::SetOpenedByDOM() {
  page_->SetOpenedByDOM();
}

void WebViewImpl::DidCommitLoad(bool is_new_navigation,
                                bool is_navigation_within_page) {
  if (!is_navigation_within_page) {
    if (web_widget_)
      web_widget_->ResetMeaningfulLayoutStateForMainFrame();

    if (is_new_navigation)
      GetPageScaleConstraintsSet().SetNeedsReset(true);
  }

  // Give the visual viewport's scroll layer its initial size.
  GetPage()->GetVisualViewport().MainFrameDidChangeSize();
}

void WebViewImpl::DidCommitCompositorFrameForLocalMainFrame() {
  for (auto& observer : observers_)
    observer.DidCommitCompositorFrame();
}

void WebViewImpl::ResizeAfterLayout() {
  DCHECK(MainFrameImpl());

  if (!web_view_client_)
    return;

  if (should_auto_resize_) {
    LocalFrameView* view = MainFrameImpl()->GetFrame()->View();
    gfx::Size frame_size = view->Size();
    if (frame_size != size_) {
      size_ = frame_size;

      GetPage()->GetVisualViewport().SetSize(size_);
      GetPageScaleConstraintsSet().DidChangeInitialContainingBlockSize(size_);

      web_view_client_->DidAutoResize(size_);
      web_widget_->DidAutoResize(size_);
      SendResizeEventForMainFrame();
    }
  }

  if (does_composite_ && GetPageScaleConstraintsSet().ConstraintsDirty())
    RefreshPageScaleFactor();

  resize_viewport_anchor_->ResizeFrameView(MainFrameSize());
}

void WebViewImpl::MainFrameLayoutUpdated() {
  DCHECK(MainFrameImpl());
  if (!web_view_client_)
    return;

  for (auto& observer : observers_)
    observer.DidUpdateMainFrameLayout();
  needs_preferred_size_update_ = true;
}

void WebViewImpl::DidChangeContentsSize() {
  auto* local_frame = DynamicTo<LocalFrame>(GetPage()->MainFrame());
  if (!local_frame)
    return;

  LocalFrameView* view = local_frame->View();

  int vertical_scrollbar_width = 0;
  if (view && view->LayoutViewport()) {
    Scrollbar* vertical_scrollbar = view->LayoutViewport()->VerticalScrollbar();
    if (vertical_scrollbar && !vertical_scrollbar->IsOverlayScrollbar())
      vertical_scrollbar_width = vertical_scrollbar->Width();
  }

  GetPageScaleConstraintsSet().DidChangeContentsSize(
      ContentsSize(), vertical_scrollbar_width, PageScaleFactor());
}

void WebViewImpl::PageScaleFactorChanged() {
  // This is called from the VisualViewport which only is used to control the
  // page scale/scroll viewport for a local main frame, and only when
  // compositing as PageScaleFactor doesn't exist otherwise.
  DCHECK(MainFrameImpl());
  DCHECK(does_composite_);

  GetPageScaleConstraintsSet().SetNeedsReset(false);
  // Set up the compositor and inform the browser of the PageScaleFactor,
  // which is tracked per-view.
  auto& viewport = GetPage()->GetVisualViewport();
  DCHECK(viewport.IsActiveViewport());
  MainFrameImpl()->FrameWidgetImpl()->SetPageScaleStateAndLimits(
      viewport.Scale(), viewport.IsPinchGestureActive(),
      MinimumPageScaleFactor(), MaximumPageScaleFactor());

  local_main_frame_host_remote_->ScaleFactorChanged(viewport.Scale());

  if (dev_tools_emulator_->HasViewportOverride()) {
    // TODO(bokan): Can HasViewportOverride be set on a nested main frame? If
    // not, we can enforce that when setting it and DCHECK IsOutermostMainFrame
    // instead.
    if (MainFrameImpl()->IsOutermostMainFrame()) {
      gfx::Transform device_emulation_transform =
          dev_tools_emulator_->OutermostMainFrameScrollOrScaleChanged();
      SetDeviceEmulationTransform(device_emulation_transform);
    }
  }
}

void WebViewImpl::OutermostMainFrameScrollOffsetChanged() {
  DCHECK(MainFrameImpl());
  DCHECK(MainFrameImpl()->IsOutermostMainFrame());
  if (dev_tools_emulator_->HasViewportOverride()) {
    gfx::Transform device_emulation_transform =
        dev_tools_emulator_->OutermostMainFrameScrollOrScaleChanged();
    SetDeviceEmulationTransform(device_emulation_transform);
  }
}

void WebViewImpl::TextAutosizerPageInfoChanged(
    const mojom::blink::TextAutosizerPageInfo& page_info) {
  DCHECK(MainFrameImpl());
  local_main_frame_host_remote_->TextAutosizerPageInfoChanged(
      page_info.Clone());
}

void WebViewImpl::SetBackgroundColorOverrideForFullscreenController(
    std::optional<SkColor> optional_color) {
  DCHECK(does_composite_);

  background_color_override_for_fullscreen_controller_ = optional_color;
  if (MainFrameImpl()) {
    MainFrameImpl()->FrameWidgetImpl()->SetBackgroundColor(BackgroundColor());
  }
}

void WebViewImpl::SetZoomFactorOverride(float zoom_factor) {
  zoom_factor_override_ = zoom_factor;
  // This only affects the local main frame, so no need to propagate to all
  // frame widgets.
  if (web_widget_) {
    web_widget_->SetZoomLevel(web_widget_->GetZoomLevel());
  }
}

Element* WebViewImpl::FocusedElement() const {
  LocalFrame* frame = page_->GetFocusController().FocusedFrame();
  if (!frame)
    return nullptr;

  Document* document = frame->GetDocument();
  if (!document)
    return nullptr;

  return document->FocusedElement();
}

WebHitTestResult WebViewImpl::HitTestResultForTap(
    const gfx::Point& tap_point_window_pos,
    const gfx::Size& tap_area) {
  auto* main_frame = DynamicTo<LocalFrame>(page_->MainFrame());
  if (!main_frame)
    return HitTestResult();

  WebGestureEvent tap_event(WebInputEvent::Type::kGestureTap,
                            WebInputEvent::kNoModifiers, base::TimeTicks::Now(),
                            WebGestureDevice::kTouchscreen);
  // GestureTap is only ever from a touchscreen.
  tap_event.SetPositionInWidget(gfx::PointF(tap_point_window_pos));
  tap_event.data.tap.tap_count = 1;
  tap_event.data.tap.width = tap_area.width();
  tap_event.data.tap.height = tap_area.height();

  WebGestureEvent scaled_event =
      TransformWebGestureEvent(MainFrameImpl()->GetFrameView(), tap_event);

  HitTestResult result =
      main_frame->GetEventHandler()
          .HitTestResultForGestureEvent(
              scaled_event, HitTestRequest::kReadOnly | HitTestRequest::kActive)
          .GetHitTestResult();

  result.SetToShadowHostIfInUAShadowRoot();
  return result;
}

void WebViewImpl::SetTabsToLinks(bool enable) {
  tabs_to_links_ = enable;
}

bool WebViewImpl::TabsToLinks() const {
  return tabs_to_links_;
}

void WebViewImpl::DidChangeRootLayer(bool root_layer_exists) {
  // The Layer is removed when the main frame's `Document` changes. It also is
  // removed when the whole `LocalFrame` goes away, in which case we don't
  // need to DeferMainFrameUpdate() as we will do so if a local MainFrame is
  // attached in the future.
  if (!MainFrameImpl()) {
    DCHECK(!root_layer_exists);
    return;
  }
  if (root_layer_exists) {
    if (!device_emulation_transform_.IsIdentity())
      UpdateDeviceEmulationTransform();
  } else if (!MainFrameImpl()->FrameWidgetImpl()->WillBeDestroyed()) {
    // When the document in an already-attached main frame is being replaced
    // by a navigation then DidChangeRootLayer(false) will be called. Since we
    // are navigating, defer BeginMainFrames until the new document is ready
    // for them.
    //
    // If WillBeDestroyed() is true, it means we're swapping the frame as well
    // as the document for this navigation. BeginMainFrames are instead
    // deferred for a newly attached frame via DidAttachLocalMainFrame(). See
    // crbug.com/936696.
    scoped_defer_main_frame_update_ =
        MainFrameImpl()->FrameWidgetImpl()->DeferMainFrameUpdate();
  }
}

void WebViewImpl::InvalidateContainer() {
  // This is only for non-composited WebViewPlugin.
  if (!does_composite_ && web_view_client_)
    web_view_client_->InvalidateContainer();
}

void WebViewImpl::ApplyViewportChanges(const ApplyViewportChangesArgs& args) {
  // TODO(https://crbug.com/1160652): Figure out if Page is null.
  CHECK(page_);

  VisualViewport& visual_viewport = GetPage()->GetVisualViewport();
  DCHECK(visual_viewport.IsActiveViewport());

  // Store the desired offsets the visual viewport before setting the top
  // controls ratio since doing so will change the bounds and move the
  // viewports to keep the offsets valid. The compositor may have already
  // done that so we don't want to double apply the deltas here.
  gfx::PointF visual_viewport_offset = visual_viewport.VisibleRect().origin();
  visual_viewport_offset.Offset(args.inner_delta.x(), args.inner_delta.y());

  GetBrowserControls().SetShownRatio(
      GetBrowserControls().TopShownRatio() + args.top_controls_delta,
      GetBrowserControls().BottomShownRatio() + args.bottom_controls_delta);

  SetPageScaleFactorAndLocation(PageScaleFactor() * args.page_scale_delta,
                                args.is_pinch_gesture_active,
                                visual_viewport_offset);

  if (args.page_scale_delta != 1) {
    double_tap_zoom_pending_ = false;
  }

  elastic_overscroll_ += args.elastic_overscroll_delta;
  UpdateBrowserControlsConstraint(args.browser_controls_constraint);

  if (args.scroll_gesture_did_end) {
    // TODO(https://crbug.com/1160652): Figure out if MainFrameImpl is null.
    CHECK(MainFrameImpl());
    MainFrameImpl()->GetFrame()->GetEventHandler().MarkHoverStateDirty();
  }
}

Node* WebViewImpl::FindNodeFromScrollableCompositorElementId(
    cc::ElementId element_id) const {
  if (!GetPage())
    return nullptr;

  if (element_id == GetPage()->GetVisualViewport().GetScrollElementId()) {
    // Return the Document in this case since the window.visualViewport DOM
    // object is not a node.
    if (MainFrameImpl())
      return MainFrameImpl()->GetDocument();
  }

  if (!GetPage()->GetScrollingCoordinator())
    return nullptr;
  ScrollableArea* scrollable_area =
      GetPage()
          ->GetScrollingCoordinator()
          ->ScrollableAreaWithElementIdInAllLocalFrames(element_id);
  if (!scrollable_area || !scrollable_area->GetLayoutBox())
    return nullptr;

  return scrollable_area->GetLayoutBox()->GetNode();
}

void WebViewImpl::UpdateDeviceEmulationTransform() {
  if (GetPage()->GetVisualViewport().IsActiveViewport())
    GetPage()->GetVisualViewport().SetNeedsPaintPropertyUpdate();

  if (auto* main_frame = MainFrameImpl()) {
    // When the device emulation transform is updated, to avoid incorrect
    // scales and fuzzy raster from the compositor, force all content to
    // pick ideal raster scales.
    // TODO(wjmaclean): This is only done on the main frame's widget currently,
    // it should update all local frames.
    main_frame->FrameWidgetImpl()->SetNeedsRecalculateRasterScales();

    // Device emulation transform also affects the overriding visible rect
    // which is used as the overflow rect of the main frame layout view.
    if (auto* view = main_frame->GetFrameView())
      view->SetNeedsPaintPropertyUpdate();
  }
}

PageScheduler* WebViewImpl::Scheduler() const {
  DCHECK(GetPage());
  return GetPage()->GetPageScheduler();
}

void WebViewImpl::SetVisibilityState(
    mojom::blink::PageVisibilityState visibility_state,
    bool is_initial_state) {
  DCHECK(GetPage());
  GetPage()->SetVisibilityState(visibility_state, is_initial_state);
  // Do not throttle if the page should be painting.
  bool is_visible =
      visibility_state == mojom::blink::PageVisibilityState::kVisible;
  if (RuntimeEnabledFeatures::DispatchHiddenVisibilityTransitionsEnabled()) {
    // Treat `kHiddenButPainting` as visible for page scheduling; we don't want
    // to throttle timers, etc.
    is_visible |= visibility_state ==
                  mojom::blink::PageVisibilityState::kHiddenButPainting;
  }
  GetPage()->GetPageScheduler()->SetPageVisible(is_visible);
  // Notify observers of the change.
  if (!is_initial_state) {
    for (auto& observer : observers_)
      observer.OnPageVisibilityChanged(visibility_state);
  }
}

mojom::blink::PageVisibilityState WebViewImpl::GetVisibilityState() {
  DCHECK(GetPage());
  return GetPage()->GetVisibilityState();
}

LocalFrame* WebViewImpl::FocusedLocalFrameInWidget() const {
  if (!MainFrameImpl())
    return nullptr;

  auto* focused_frame = To<LocalFrame>(FocusedCoreFrame());
  if (focused_frame->LocalFrameRoot() != MainFrameImpl()->GetFrame())
    return nullptr;
  return focused_frame;
}

void WebViewImpl::SetPageFrozen(bool frozen) {
  Scheduler()->SetPageFrozen(frozen);
}

WebFrameWidget* WebViewImpl::MainFrameWidget() {
  return web_widget_;
}

void WebViewImpl::AddAutoplayFlags(int32_t value) {
  page_->AddAutoplayFlags(value);
}

void WebViewImpl::ClearAutoplayFlags() {
  page_->ClearAutoplayFlags();
}

int32_t WebViewImpl::AutoplayFlagsForTest() const {
  return page_->AutoplayFlags();
}

gfx::Size WebViewImpl::GetPreferredSizeForTest() {
  return preferred_size_in_dips_;
}

void WebViewImpl::StopDeferringMainFrameUpdate() {
  scoped_defer_main_frame_update_ = nullptr;
}

void WebViewImpl::SetDeviceColorSpaceForTesting(
    const gfx::ColorSpace& color_space) {
  web_widget_->SetDeviceColorSpaceForTesting(color_space);
}

const SessionStorageNamespaceId& WebViewImpl::GetSessionStorageNamespaceId() {
  CHECK(!session_storage_namespace_id_.empty());
  return session_storage_namespace_id_;
}

bool WebViewImpl::IsFencedFrameRoot() const {
  return GetPage()->IsMainFrameFencedFrameRoot();
}

void WebViewImpl::SetSupportsDraggableRegions(bool supports_draggable_regions) {
  supports_draggable_regions_ = supports_draggable_regions;
  if (!MainFrameImpl() || !MainFrameImpl()->GetFrame()) {
    return;
  }

  LocalFrame* local_frame = MainFrameImpl()->GetFrame();

  if (supports_draggable_regions_) {
    local_frame->View()->UpdateDocumentDraggableRegions();
  } else {
    local_frame->GetDocument()->SetDraggableRegions(
        Vector<DraggableRegionValue>());
    chrome_client_->DraggableRegionsChanged();
  }
}

bool WebViewImpl::SupportsDraggableRegions() {
  return supports_draggable_regions_;
}

void WebViewImpl::DraggableRegionsChanged() {
  if (!MainFrameImpl()) {
    return;
  }

  WebVector<WebDraggableRegion> web_regions =
      MainFrameImpl()->GetDocument().DraggableRegions();

  // If |supports_draggable_regions_| is false, the web view should only send
  // empty regions to reset a previously set draggable regions.
  DCHECK(supports_draggable_regions_ || web_regions.empty());

  auto regions = Vector<mojom::blink::DraggableRegionPtr>();
  for (WebDraggableRegion& web_region : web_regions) {
    auto converted_bounds =
        MainFrame()->ToWebLocalFrame()->FrameWidget()->BlinkSpaceToEnclosedDIPs(
            web_region.bounds);

    auto region = mojom::blink::DraggableRegion::New(converted_bounds,
                                                     web_region.draggable);
    regions.emplace_back(std::move(region));
  }

  local_main_frame_host_remote_->DraggableRegionsChanged(std::move(regions));
}

void WebViewImpl::MojoDisconnected() {
#if !(BUILDFLAG(IS_ANDROID) || \
      (BUILDFLAG(IS_CHROMEOS) && defined(ARCH_CPU_ARM64)))
  auto prev_close_task_trace = close_task_posted_stack_trace_;
  base::debug::Alias(&prev_close_task_trace);
  close_task_posted_stack_t
```