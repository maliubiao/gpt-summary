Response:

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
Size(prefs.minimum_logical_font_size);
  settings->SetDefaultTextEncodingName(
      WebString::FromASCII(prefs.default_encoding));
  settings->SetJavaScriptEnabled(prefs.javascript_enabled);
  settings->SetWebSecurityEnabled(prefs.web_security_enabled);
  settings->SetLoadsImagesAutomatically(prefs.loads_images_automatically);
  settings->SetImagesEnabled(prefs.images_enabled);
  settings->SetPluginsEnabled(prefs.plugins_enabled);
  settings->SetDOMPasteAllowed(prefs.dom_paste_enabled);
  settings->SetTextAreasAreResizable(prefs.text_areas_are_resizable);
  settings->SetAllowScriptsToCloseWindows(prefs.allow_scripts_to_close_windows);
  settings->SetDownloadableBinaryFontsEnabled(prefs.remote_fonts_enabled);
  settings->SetJavaScriptCanAccessClipboard(
      prefs.javascript_can_access_clipboard);
  settings->SetDNSPrefetchingEnabled(prefs.dns_prefetching_enabled);
  blink::WebNetworkStateNotifier::SetSaveDataEnabled(prefs.data_saver_enabled);
  settings->SetLocalStorageEnabled(prefs.local_storage_enabled);
  settings->SetSyncXHRInDocumentsEnabled(prefs.sync_xhr_in_documents_enabled);
  settings->SetTargetBlankImpliesNoOpenerEnabledWillBeRemoved(
      prefs.target_blank_implies_no_opener_enabled_will_be_removed);
  settings->SetAllowNonEmptyNavigatorPlugins(
      prefs.allow_non_empty_navigator_plugins);
  RuntimeEnabledFeatures::SetDatabaseEnabled(prefs.databases_enabled);
  settings->SetShouldProtectAgainstIpcFlooding(
      !prefs.disable_ipc_flooding_protection);
  settings->SetHyperlinkAuditingEnabled(prefs.hyperlink_auditing_enabled);
  settings->SetCookieEnabled(prefs.cookie_enabled);

  // By default, allow_universal_access_from_file_urls is set to false and thus
  // we mitigate attacks from local HTML files by not granting file:// URLs
  // universal access. Only test shell will enable this.
  settings->SetAllowUniversalAccessFromFileURLs(
      prefs.allow_universal_access_from_file_urls);
  settings->SetAllowFileAccessFromFileURLs(
      prefs.allow_file_access_from_file_urls);

  settings->SetWebGL1Enabled(prefs.webgl1_enabled);
  settings->SetWebGL2Enabled(prefs.webgl2_enabled);

  // Enable WebGL errors to the JS console if requested.
  settings->SetWebGLErrorsToConsoleEnabled(
      prefs.webgl_errors_to_console_enabled);

  settings->SetHideScrollbars(prefs.hide_scrollbars);

  settings->SetPrefersDefaultScrollbarStyles(
      prefs.prefers_default_scrollbar_styles);

  // Enable gpu-accelerated 2d canvas if requested on the command line.
  RuntimeEnabledFeatures::SetAccelerated2dCanvasEnabled(
      prefs.accelerated_2d_canvas_enabled);

  RuntimeEnabledFeatures::SetCanvas2dLayersEnabled(
      prefs.canvas_2d_layers_enabled);

  // Disable antialiasing for 2d canvas if requested on the command line.
  settings->SetAntialiased2dCanvasEnabled(
      !prefs.antialiased_2d_canvas_disabled);

  // Disable antialiasing of clips for 2d canvas if requested on the command
  // line.
  settings->SetAntialiasedClips2dCanvasEnabled(
      prefs.antialiased_clips_2d_canvas_enabled);

  // Tabs to link is not part of the settings. WebCore calls
  // ChromeClient::tabsToLinks which is part of the glue code.
  web_view_impl->SetTabsToLinks(prefs.tabs_to_links);

  DCHECK(!(web_view_impl->IsFencedFrameRoot() &&
           prefs.allow_running_insecure_content));
  settings->SetAllowRunningOfInsecureContent(
      prefs.allow_running_insecure_content);
  settings->SetDisableReadingFromCanvas(prefs.disable_reading_from_canvas);
  settings->SetStrictMixedContentChecking(prefs.strict_mixed_content_checking);

  settings->SetStrictlyBlockBlockableMixedContent(
      prefs.strictly_block_blockable_mixed_content);

  settings->SetStrictMixedContentCheckingForPlugin(
      prefs.block_mixed_plugin_content);

  settings->SetStrictPowerfulFeatureRestrictions(
      prefs.strict_powerful_feature_restrictions);
  settings->SetAllowGeolocationOnInsecureOrigins(
      prefs.allow_geolocation_on_insecure_origins);
  settings->SetPasswordEchoEnabled(prefs.password_echo_enabled);
  settings->SetShouldPrintBackgrounds(prefs.should_print_backgrounds);
  settings->SetShouldClearDocumentBackground(
      prefs.should_clear_document_background);
  settings->SetEnableScrollAnimator(prefs.enable_scroll_animator);
  settings->SetPrefersReducedMotion(prefs.prefers_reduced_motion);
  settings->SetPrefersReducedTransparency(prefs.prefers_reduced_transparency);
  settings->SetInvertedColors(prefs.inverted_colors);

  RuntimeEnabledFeatures::SetTouchEventFeatureDetectionEnabled(
      prefs.touch_event_feature_detection_enabled);
  settings->SetMaxTouchPoints(prefs.pointer_events_max_touch_points);
  settings->SetAvailablePointerTypes(prefs.available_pointer_types);
  settings->SetPrimaryPointerType(prefs.primary_pointer_type);
  settings->SetAvailableHoverTypes(prefs.available_hover_types);
  settings->SetPrimaryHoverType(prefs.primary_hover_type);
  settings->SetOutputDeviceUpdateAbilityType(
      prefs.output_device_update_ability_type);
  settings->SetBarrelButtonForDragEnabled(prefs.barrel_button_for_drag_enabled);

  settings->SetEditingBehavior(prefs.editing_behavior);

  settings->SetSupportsMultipleWindows(prefs.supports_multiple_windows);

  settings->SetMainFrameClipsContent(!prefs.record_whole_document);

  RuntimeEnabledFeatures::SetStylusHandwritingEnabled(
      prefs.stylus_handwriting_enabled);

  settings->SetSmartInsertDeleteEnabled(prefs.smart_insert_delete_enabled);

  settings->SetSpatialNavigationEnabled(prefs.spatial_navigation_enabled);
  // Spatnav depends on KeyboardFocusableScrollers. The WebUI team has
  // disabled KFS because they need more time to update their custom elements,
  // crbug.com/907284. Meanwhile, we pre-ship KFS to spatnav users.
  if (prefs.spatial_navigation_enabled)
    RuntimeEnabledFeatures::SetKeyboardFocusableScrollersEnabled(true);

  settings->SetSelectionIncludesAltImageText(true);

  settings->SetV8CacheOptions(prefs.v8_cache_options);

  settings->SetImageAnimationPolicy(prefs.animation_policy);

  settings->SetPresentationRequiresUserGesture(
      prefs.user_gesture_required_for_presentation);

  if (prefs.text_tracks_enabled) {
    settings->SetTextTrackKindUserPreference(
        WebSettings::TextTrackKindUserPreference::kCaptions);
  } else {
    settings->SetTextTrackKindUserPreference(
        WebSettings::TextTrackKindUserPreference::kDefault);
  }
  settings->SetTextTrackBackgroundColor(
      WebString::FromASCII(prefs.text_track_background_color));
  settings->SetTextTrackTextColor(
      WebString::FromASCII(prefs.text_track_text_color));
  settings->SetTextTrackTextSize(
      WebString::FromASCII(prefs.text_track_text_size));
  settings->SetTextTrackTextShadow(
      WebString::FromASCII(prefs.text_track_text_shadow));
  settings->SetTextTrackFontFamily(
      WebString::FromASCII(prefs.text_track_font_family));
  settings->SetTextTrackFontStyle(
      WebString::FromASCII(prefs.text_track_font_style));
  settings->SetTextTrackFontVariant(
      WebString::FromASCII(prefs.text_track_font_variant));
  settings->SetTextTrackMarginPercentage(prefs.text_track_margin_percentage);
  settings->SetTextTrackWindowColor(
      WebString::FromASCII(prefs.text_track_window_color));
  settings->SetTextTrackWindowRadius(
      WebString::FromASCII(prefs.text_track_window_radius));

  // Needs to happen before SetDefaultPageScaleLimits below since that'll
  // recalculate the final page scale limits and that depends on this setting.
  settings->SetShrinksViewportContentToFit(
      prefs.shrinks_viewport_contents_to_fit);

  // Needs to happen before SetIgnoreViewportTagScaleLimits below.
  web_view->SetDefaultPageScaleLimits(prefs.default_minimum_page_scale_factor,
                                      prefs.default_maximum_page_scale_factor);

  settings->SetFullscreenSupported(prefs.fullscreen_supported);
  settings->SetTextAutosizingEnabled(prefs.text_autosizing_enabled);
  settings->SetDoubleTapToZoomEnabled(prefs.double_tap_to_zoom_enabled);
  blink::WebNetworkStateNotifier::SetNetworkQualityWebHoldback(
      static_cast<blink::WebEffectiveConnectionType>(
          prefs.network_quality_estimator_web_holdback));

  settings->SetDontSendKeyEventsToJavascript(
      prefs.dont_send_key_events_to_javascript);
  settings->SetWebAppScope(WebString::FromASCII(prefs.web_app_scope.spec()));

#if BUILDFLAG(IS_ANDROID)
  settings->SetAllowCustomScrollbarInMainFrame(false);
  settings->SetAccessibilityFontScaleFactor(prefs.font_scale_factor);
  settings->SetAccessibilityFontWeightAdjustment(prefs.font_weight_adjustment);
  settings->SetAccessibilityTextSizeContrastFactor(
      prefs.text_size_contrast_factor);
  settings->SetDeviceScaleAdjustment(prefs.device_scale_adjustment);
  web_view_impl->SetIgnoreViewportTagScaleLimits(prefs.force_enable_zoom);
  settings->SetDefaultVideoPosterURL(
      WebString::FromASCII(prefs.default_video_poster_url.spec()));
  settings->SetSupportDeprecatedTargetDensityDPI(
      prefs.support_deprecated_target_density_dpi);
  settings->SetWideViewportQuirkEnabled(prefs.wide_viewport_quirk);
  settings->SetUseWideViewport(prefs.use_wide_viewport);
  settings->SetForceZeroLayoutHeight(prefs.force_zero_layout_height);
  settings->SetViewportMetaMergeContentQuirk(
      prefs.viewport_meta_merge_content_quirk);
  settings->SetViewportMetaNonUserScalableQuirk(
      prefs.viewport_meta_non_user_scalable_quirk);
  settings->SetViewportMetaZeroValuesQuirk(
      prefs.viewport_meta_zero_values_quirk);
  settings->SetClobberUserAgentInitialScaleQuirk(
      prefs.clobber_user_agent_initial_scale_quirk);
  settings->SetIgnoreMainFrameOverflowHiddenQuirk(
      prefs.ignore_main_frame_overflow_hidden_quirk);
  settings->SetReportScreenSizeInPhysicalPixelsQuirk(
      prefs.report_screen_size_in_physical_pixels_quirk);
  settings->SetShouldReuseGlobalForUnownedMainFrame(
      prefs.reuse_global_for_unowned_main_frame);
  settings->SetPreferHiddenVolumeControls(true);
  settings->SetSpellCheckEnabledByDefault(prefs.spellcheck_enabled_by_default);

  RuntimeEnabledFeatures::SetVideoFullscreenOrientationLockEnabled(
      prefs.video_fullscreen_orientation_lock_enabled);
  RuntimeEnabledFeatures::SetVideoRotateToFullscreenEnabled(
      prefs.video_rotate_to_fullscreen_enabled);
  settings->SetEmbeddedMediaExperienceEnabled(
      prefs.embedded_media_experience_enabled);
  settings->SetImmersiveModeEnabled(prefs.immersive_mode_enabled);
  settings->SetDoNotUpdateSelectionOnMutatingSelectionRange(
      prefs.do_not_update_selection_on_mutating_selection_range);
  RuntimeEnabledFeatures::SetCSSHexAlphaColorEnabled(
      prefs.css_hex_alpha_color_enabled);
  RuntimeEnabledFeatures::SetScrollTopLeftInteropEnabled(
      prefs.scroll_top_left_interop_enabled);
  RuntimeEnabledFeatures::SetAcceleratedSmallCanvasesEnabled(
      !prefs.disable_accelerated_small_canvases);
  RuntimeEnabledFeatures::SetLongPressLinkSelectTextEnabled(
      prefs.long_press_link_select_text);
#endif  // BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_FUCHSIA)
  RuntimeEnabledFeatures::SetWebAuthEnabled(!prefs.disable_webauthn);
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_FUCHSIA)

  settings->SetForceDarkModeEnabled(prefs.force_dark_mode_enabled);

  settings->SetAccessibilityAlwaysShowFocus(prefs.always_show_focus);
  settings->SetAutoplayPolicy(prefs.autoplay_policy);
  settings->SetRequireTransientActivationForGetDisplayMedia(
      prefs.require_transient_activation_for_get_display_media);
  settings->SetRequireTransientActivationForShowFileOrDirectoryPicker(
      prefs.require_transient_activation_for_show_file_or_directory_picker);
  settings->SetViewportEnabled(prefs.viewport_enabled);
  settings->SetViewportMetaEnabled(prefs.viewport_meta_enabled);
  settings->SetViewportStyle(prefs.viewport_style);
  settings->SetAutoZoomFocusedEditableToLegibleScale(
      prefs.auto_zoom_focused_editable_to_legible_scale);

  settings->SetLoadWithOverviewMode(prefs.initialize_at_minimum_page_scale);
  settings->SetMainFrameResizesAreOrientationChanges(
      prefs.main_frame_resizes_are_orientation_changes);

  settings->SetShowContextMenuOnMouseUp(prefs.context_menu_on_mouse_up);
  settings->SetAlwaysShowContextMenuOnTouch(
      prefs.always_show_context_menu_on_touch);
  settings->SetSmoothScrollForFindEnabled(prefs.smooth_scroll_for_find_enabled);

  settings->SetHideDownloadUI(prefs.hide_download_ui);

  settings->SetPresentationReceiver(prefs.presentation_receiver);

  settings->SetMediaControlsEnabled(prefs.media_controls_enabled);

  settings->SetLowPriorityIframesThreshold(
      static_cast<blink::WebEffectiveConnectionType>(
          prefs.low_priority_iframes_threshold));

  settings->SetPictureInPictureEnabled(prefs.picture_in_picture_enabled &&
                                       ::features::UseSurfaceLayerForVideo());

  settings->SetLazyLoadEnabled(prefs.lazy_load_enabled);
  settings->SetInForcedColors(prefs.in_forced_colors);
  settings->SetIsForcedColorsDisabled(prefs.is_forced_colors_disabled);
  settings->SetPreferredRootScrollbarColorScheme(
      prefs.preferred_root_scrollbar_color_scheme);
  settings->SetPreferredColorScheme(prefs.preferred_color_scheme);
  settings->SetPreferredContrast(prefs.preferred_contrast);

  settings->SetTouchDragDropEnabled(prefs.touch_drag_drop_enabled);
  settings->SetTouchDragEndContextMenu(prefs.touch_dragend_context_menu);
  settings->SetWebXRImmersiveArAllowed(prefs.webxr_immersive_ar_allowed);
  settings->SetModalContextMenu(prefs.modal_context_menu);
  settings->SetRequireTransientActivationAndAuthorizationForSubAppsAPIs(
      prefs.subapps_apis_require_user_gesture_and_authorization);
  if (RuntimeEnabledFeatures::DynamicSafeAreaInsetsEnabled()) {
    settings->SetDynamicSafeAreaInsetsEnabled(
        prefs.dynamic_safe_area_insets_enabled);
  }

#if BUILDFLAG(IS_MAC)
  web_view_impl->SetMaximumLegibleScale(
      prefs.default_maximum_page_scale_factor);
#endif

#if BUILDFLAG(IS_WIN)
  RuntimeEnabledFeatures::SetMiddleClickAutoscrollEnabled(true);
#endif

  RuntimeEnabledFeatures::SetTranslateServiceEnabled(
      prefs.translate_service_available);

#if BUILDFLAG(IS_WIN)
  if (web_view_impl->GetPage() &&
      base::FeatureList::IsEnabled(features::kPrewarmDefaultFontFamilies)) {
    if (auto* prewarmer = WebFontRendering::GetFontPrewarmer()) {
      GenericFontFamilySettings& font_settings =
          web_view_impl->GetPage()
              ->GetSettings()
              .GetGenericFontFamilySettings();
      if (features::kPrewarmStandard.Get())
        prewarmer->PrewarmFamily(font_settings.Standard());
      if (features::kPrewarmFixed.Get())
        prewarmer->PrewarmFamily(font_settings.Fixed());
      if (features::kPrewarmSerif.Get())
        prewarmer->PrewarmFamily(font_settings.Serif());
      if (features::kPrewarmSansSerif.Get())
        prewarmer->PrewarmFamily(font_settings.SansSerif());
      if (features::kPrewarmCursive.Get())
        prewarmer->PrewarmFamily(font_settings.Cursive());
      if (features::kPrewarmFantasy.Get())
        prewarmer->PrewarmFamily(font_settings.Fantasy());
    }
  }
#endif

  // Disabling the StrictMimetypeCheckForWorkerScriptsEnabled enterprise policy
  // overrides the corresponding RuntimeEnabledFeature (via its Pref).
  if (!prefs.strict_mime_type_check_for_worker_scripts_enabled) {
    RuntimeEnabledFeatures::SetStrictMimeTypesForWorkersEnabled(false);
  }
}

void WebViewImpl::ThemeChanged() {
  if (auto* page = GetPage())
    page->InvalidatePaint();
}

void WebViewImpl::EnterFullscreen(LocalFrame& frame,
                                  const FullscreenOptions* options,
                                  FullscreenRequestType request_type) {
  fullscreen_controller_->EnterFullscreen(frame, options, request_type);
}

void WebViewImpl::ExitFullscreen(LocalFrame& frame) {
  fullscreen_controller_->ExitFullscreen(frame);
}

void WebViewImpl::FullscreenElementChanged(Element* old_element,
                                           Element* new_element,
                                           const FullscreenOptions* options,
                                           FullscreenRequestType request_type) {
  fullscreen_controller_->FullscreenElementChanged(old_element, new_element,
                                                   options, request_type);
}

bool WebViewImpl::HasHorizontalScrollbar() {
  return MainFrameImpl()
      ->GetFrameView()
      ->LayoutViewport()
      ->HorizontalScrollbar();
}

bool WebViewImpl::HasVerticalScrollbar() {
  return MainFrameImpl()->GetFrameView()->LayoutViewport()->VerticalScrollbar();
}

void WebViewImpl::SetPageFocus(bool enable) {
  page_->GetFocusController().SetFocused(enable);
  if (enable) {
    LocalFrame* focused_frame = page_->GetFocusController().FocusedFrame();
    if (focused_frame) {
      // TODO(editing-dev): The use of UpdateStyleAndLayout needs to be audited.
      // See http://crbug.com/590369 for more details.
      focused_frame->GetDocument()->UpdateStyleAndLayout(
          DocumentUpdateReason::kFocus);
      Element* element = focused_frame->GetDocument()->FocusedElement();
      if (element && focused_frame->Selection()
                         .ComputeVisibleSelectionInDOMTree()
                         .IsNone()) {
        // If the selection was cleared while the WebView was not
        // focused, then the focus element shows with a focus ring but
        // no caret and does respond to keyboard inputs.
        if (element->IsTextControl()) {
          element->UpdateSelectionOnFocus(SelectionBehaviorOnFocus::kRestore);
        } else if (IsEditable(*element)) {
          // updateFocusAppearance() selects all the text of
          // contentseditable DIVs. So we set the selection explicitly
          // instead. Note that this has the side effect of moving the
          // caret back to the beginning of the text.
          Position position(element, 0);
          focused_frame->Selection().SetSelection(
              SelectionInDOMTree::Builder().Collapse(position).Build(),
              SetSelectionOptions());
        }
      }
    }
  } else {
    CancelPagePopup();

    LocalFrame* focused_frame = page_->GetFocusController().FocusedFrame();
    if (focused_frame) {
      // Finish an ongoing composition to delete the composition node.
      if (focused_frame->GetInputMethodController().GetActiveEditContext()) {
        focused_frame->GetInputMethodController()
            .GetActiveEditContext()
            ->FinishComposingText(WebInputMethodController::kKeepSelection);
      } else if (focused_frame->GetInputMethodController().HasComposition()) {
        // TODO(editing-dev): The use of
        // UpdateStyleAndLayout needs to be audited.
        // See http://crbug.com/590369 for more details.
        focused_frame->GetDocument()->UpdateStyleAndLayout(
            DocumentUpdateReason::kFocus);

        focused_frame->GetInputMethodController().FinishComposingText(
            InputMethodController::kKeepSelection);
      }
    }
  }
}

// WebView --------------------------------------------------------------------

WebSettingsImpl* WebViewImpl::SettingsImpl() {
  if (!web_settings_) {
    web_settings_ = std::make_unique<WebSettingsImpl>(
        &page_->GetSettings(), dev_tools_emulator_.Get());
  }
  DCHECK(web_settings_);
  return web_settings_.get();
}

WebSettings* WebViewImpl::GetSettings() {
  return SettingsImpl();
}

WebString WebViewImpl::PageEncoding() const {
  if (!page_)
    return WebString();

  auto* main_frame = DynamicTo<LocalFrame>(page_->MainFrame());
  if (!main_frame)
    return WebString();

  // FIXME: Is this check needed?
  if (!main_frame->GetDocument()->Loader())
    return WebString();

  return main_frame->GetDocument()->EncodingName();
}

WebFrame* WebViewImpl::MainFrame() {
  Page* page = page_.Get();
  return WebFrame::FromCoreFrame(page ? page->MainFrame() : nullptr);
}

const WebFrame* WebViewImpl::MainFrame() const {
  Page* page = page_.Get();
  return WebFrame::FromCoreFrame(page ? page->MainFrame() : nullptr);
}

WebLocalFrameImpl* WebViewImpl::MainFrameImpl() const {
  Page* page = page_.Get();
  if (!page)
    return nullptr;
  return WebLocalFrameImpl::FromFrame(DynamicTo<LocalFrame>(page->MainFrame()));
}

std::string WebViewImpl::GetNullFrameReasonForBug1139104() const {
  Page* page = page_.Get();
  if (!page)
    return "WebViewImpl::page";
  if (!page->MainFrame())
    return "WebViewImpl::page->MainFrame";
  LocalFrame* local_frame = DynamicTo<LocalFrame>(page->MainFrame());
  if (!local_frame)
    return "WebViewImpl::local_frame";
  return WebLocalFrameImpl::GetNullFrameReasonForBug1139104(local_frame);
}

void WebViewImpl::DidAttachLocalMainFrame() {
  DCHECK(MainFrameImpl());
  DCHECK(!remote_main_frame_host_remote_);

  LocalFrame* local_frame = MainFrameImpl()->GetFrame();
  local_frame->WasAttachedAsLocalMainFrame();

  local_frame->GetRemoteNavigationAssociatedInterfaces()->GetInterface(
      local_main_frame_host_remote_.BindNewEndpointAndPassReceiver(
          GetPage()
              ->GetPageScheduler()
              ->GetAgentGroupScheduler()
              .DefaultTaskRunner()));

  auto& viewport = GetPage()->GetVisualViewport();
  if (does_composite_) {
    // When attaching a local main frame, set up any state on the compositor.
    MainFrameImpl()->FrameWidgetImpl()->SetBackgroundColor(BackgroundColor());
    MainFrameImpl()->FrameWidgetImpl()->SetPrefersReducedMotion(
        web_preferences_.prefers_reduced_motion);
    MainFrameImpl()->FrameWidgetImpl()->SetPageScaleStateAndLimits(
        viewport.Scale(), viewport.IsPinchGestureActive(),
        MinimumPageScaleFactor(), MaximumPageScaleFactor());
    // Prevent main frame updates while the main frame is loading until enough
    // progress is made and BeginMainFrames are explicitly asked for.
    scoped_defer_main_frame_update_ =
        MainFrameImpl()->FrameWidgetImpl()->DeferMainFrameUpdate();
  }

  // It's possible that at the time that `local_frame` attached its document it
  // was provisional so it couldn't initialize the root scroller. Try again now
  // that the frame has been attached; this is a no-op if the root scroller is
  // already initialized.
  if (viewport.IsActiveViewport()) {
    DCHECK(local_frame->GetDocument());
    // DidAttachLocalMainFrame can be called before a new document is attached
    // so ensure we don't try to initialize the root scroller on a stopped
    // document.
    if (local_frame->GetDocument()->IsActive())
      local_frame->View()->InitializeRootScroller();
  }
}

void WebViewImpl::DidAttachRemoteMainFrame(
    CrossVariantMojoAssociatedRemote<
        mojom::blink::RemoteMainFrameHostInterfaceBase> main_frame_host,
    CrossVariantMojoAssociatedReceiver<
        mojom::blink::RemoteMainFrameInterfaceBase> main_frame) {
  DCHECK(!MainFrameImpl());
  DCHECK(!local_main_frame_host_remote_);
  // Note that we didn't DCHECK the `main_frame_host` and `main_frame`, because
  // it's possible for those to be null, in case the remote main frame is a
  // placeholder RemoteFrame that does not have any browser-side counterpart.
  // This is possible when the WebView is created in preparation for a main
  // frame LocalFrame <-> LocalFrame swap. See the comments in
  // `AgentSchedulingGroup::CreateWebView()` for more details.

  RemoteFrame* remote_frame = DynamicTo<RemoteFrame>(GetPage()->MainFrame());
  remote_frame->WasAttachedAsRemoteMainFrame(std::move(main_frame));

  remote_main_frame_host_remote_.Bind(std::move(main_frame_host));

  auto& viewport = GetPage()->GetVisualViewport();
  DCHECK(!viewport.IsActiveViewport());
  viewport.Reset();
}

void WebViewImpl::DidDetachLocalMainFrame() {
  // The WebFrameWidget that generated the |scoped_defer_main_frame_update_|
  // for a local main frame is going away.
  scoped_defer_main_frame_update_ = nullptr;
  local_main_frame_host_remote_.reset();
}

void WebViewImpl::DidDetachRemoteMainFrame() {
  remote_main_frame_host_remote_.reset();
}

WebLocalFrame* WebViewImpl::FocusedFrame() {
  Frame* frame = FocusedCoreFrame();
  // TODO(yabinh): focusedCoreFrame() should always return a local frame, and
  // the following check should be unnecessary.
  // See crbug.com/625068
  return WebLocalFrameImpl::FromFrame(DynamicTo<LocalFrame>(frame));
}

void WebViewImpl::SetFocusedFrame(WebFrame* frame) {
  if (!frame) {
    // Clears the focused frame if any.
    Frame* focused_frame = FocusedCoreFrame();
    if (auto* focused_local_frame = DynamicTo<LocalFrame>(focused_frame))
      focused_local_frame->Selection().SetFrameIsFocused(false);
    return;
  }
  LocalFrame* core_frame = To<WebLocalFrameImpl>(frame)->GetFrame();
  core_frame->GetPage()->GetFocusController().SetFocusedFrame(core_frame);
}

void WebViewImpl::FinishScrollFocusedEditableIntoView(
    const gfx::RectF& caret_rect_in_root_frame,
    mojom::blink::ScrollIntoViewParamsPtr params) {
  DCHECK(MainFrameImpl());
  DCHECK(!IsFencedFrameRoot());
  DCHECK(!caret_rect_in_root_frame.IsEmpty());
  DCHECK(params->for_focused_editable);

  // Zoom if:
  // (1) Zoom to legible scale is enabled (i.e. Android)
  // (2) We're on a non-mobile-friendly page
  // (3) The element doesn't explicitly block pinch-zoom gestures so the user
  //     can zoom back out.
  bool zoom_into_legible_scale =
      web_settings_->AutoZoomFocusedEditableToLegibleScale() &&
      !GetPage()->GetVisualViewport().ShouldDisableDesktopWorkarounds() &&
      params->for_focused_editable->can_zoom;

  // Reconstruct the editable element's absolute rect from the caret-relative
  // location.
  gfx::RectF editable_rect_in_root_frame =
      scroll_into_view_util::FocusedEditableBoundsFromParams(
          caret_rect_in_root_frame, params);

  DCHECK(!editable_rect_in_root_frame.IsEmpty());

  float scale;
  gfx::Point scroll;
  bool need_animation = false;
  ComputeScaleAndScrollForEditableElementRects(
      gfx::ToEnclosedRect(editable_rect_in_root_frame),
      gfx::ToEnclosedRect(caret_rect_in_root_frame), zoom_into_legible_scale,
      scale, scroll, need_animation);

  if (need_animation) {
    StartPageScaleAnimation(scroll, false, scale,
                            kScrollAndScaleAnimationDuration);
  }
}

void WebViewImpl::SmoothScroll(int target_x,
                               int target_y,
                               base::TimeDelta duration) {
  gfx::Point target_position(target_x, target_y);
  StartPageScaleAnimation(target_position, false, PageScaleFactor(), duration);
}

void WebViewImpl::ComputeScaleAndScrollForEditableElementRects(
    const gfx::Rect& element_bounds_in_root_frame,
    const gfx::Rect& caret_bounds_in_root_frame,
    bool zoom_into_legible_scale,
    float& new_scale,
    gfx::Point& new_scroll_position,
    bool& need_animation) {
  VisualViewport& visual_viewport = GetPage()->GetVisualViewport();

  TopDocumentRootScrollerController& controller =
      GetPage()->GlobalRootScrollerController();
  Node* root_scroller = controller.GlobalRootScroller();

  gfx::Rect element_bounds_in_content;
  gfx::Rect caret_bounds_in_content;

  // If the page has a non-default root scroller then we need to put the
  // "in_content" coordinates into that scroller's coordinate space, rather
  // than the root frame's.
  if (root_scroller != MainFrameImpl()->GetFrame()->GetDocument() &&
      controller.RootScrollerArea()) {
    ScrollOffset offset = controller.RootScrollerArea()->GetScrollOffset();

    element_bounds_in_content = element_bounds_in_root_frame;
    caret_bounds_in_content = caret_bounds_in_root_frame;

    element_bounds_in_content.Offset(gfx::ToFlooredVector2d(offset));
    caret_bounds_in_content.Offset(gfx::ToFlooredVector2d(offset));
  } else {
    element_bounds_in_content =
        MainFrameImpl()->GetFrameView()->RootFrameToDocument(
            element_bounds_in_root_frame);
    caret_bounds_in_content =
        MainFrameImpl()->GetFrameView()->RootFrameToDocument(
            caret_bounds_in_root_frame);
  }

  if (!zoom_into_legible_scale) {
    new_scale = PageScaleFactor();
  } else {
    // Pick a scale which is reasonably readable. This is the scale at which
    // the caret height will become minReadableCaretHeightForNode (adjusted
    // for dpi and font scale factor).
    const int min_readable_caret_height_for_node =
        (element_bounds_in_content.height() >=
                 2 * caret_bounds_in_content.height()
             ? minReadableCaretHeightForTextArea
             : minReadableCaretHeight) *
        MainFrameImpl()->GetFrame()->LayoutZoomFactor();
    new_scale = ClampPageScaleFactorToLimits(
        MaximumLegiblePageScale() * min_readable_caret_height_for_node /
        caret_bounds_in_content.height());
    new_scale = std::max(new_scale, PageScaleFactor());
  }
  const float delta_scale = new_scale / PageScaleFactor();

  need_animation = false;

  // If we are at less than the target zoom level, zoom in.
  if (delta_scale > minScaleChangeToTriggerZoom)
    need_animation = true;
  else
    new_scale = PageScaleFactor();

  ScrollableArea* root_viewport =
      MainFrameImpl()->GetFrame()->View()->GetScrollableArea();

  // If the caret is offscreen, then animate.
  if (!root_viewport->VisibleContentRect().Contains(caret_bounds_in_content))
    need_animation = true;

  // If the box is partially offscreen and it's possible to bring it fully
  // onscreen, then animate.
  if (visual_viewport.VisibleRect().width() >=
          element_bounds_in_content.width() &&
      visual_viewport.VisibleRect().height() >=
          element_bounds_in_content.height() &&
      !root_viewport->VisibleContentRect().Contains(element_bounds_in_content))
    need_animation = true;

  if (!need_animation)
    return;

  gfx::SizeF target_viewport_size(visual_viewport.Size());
  target_viewport_size.Scale(1 / new_scale);

  // TODO(bokan): The logic below is all tailored assuming LTR writing mode.
  // Ideally, it'd perform its computations based on writing mode.
  ScrollOffset scroll_offset;
  if (element_bounds_in_content.width() <= target_viewport_size.width()) {
    // Field is narrower than screen. Try to leave padding on left so field's
    // label is visible, but it's more important to ensure entire field is
    // onscreen.
    int ideal_left_padding = target_viewport_size.width() * leftBoxRatio;
    int max_left_padding_keeping_box_onscreen =
        target_viewport_size.width() - element_bounds_in_content.width();
    scroll_offset.set_x(element_bounds_in_content.x() -
                        std::min<int>(ideal_left_padding,
                                      max_left_padding_keeping_box_onscreen));
  } else {
    // Field is wider than screen. Try to left-align field, unless caret would
    // be offscreen, in which case right-align the caret.
    scroll_offset.set_x(std::max<int>(
        element_bounds_in_content.x(),
        caret_bounds_in_content.x() + caret_bounds_in_content.width() +
            caretPadding - target_viewport_size.width()));
  }
  if (element_bounds_in_content.height() <= target_viewport_size.height()) {
    // Field is shorter than screen. Vertically center it.
    scroll_offset.set_y(
        element_bounds_in_content.y() -
        (target_viewport_size.height() - element_bounds_in_content.height()) /
            2);
  } else {
    // Field is taller than screen. Try to top align field, unless caret would
    // be offscreen, in which case bottom-align the caret.
    scroll_offset.set_y(std::max<int>(
        element_bounds_in_content.y(),
        caret_bounds_in_content.y() + caret_bounds_in_content.height() +
            caretPadding - target_viewport_size.height()));
  }

  // The output scroll will be used by the compositor so we must convert the
  // scroll-origin relative (i.e. writing-mode dependent) ScrollOffset with a
  // top-left relative scroll position.
  new_scroll_position =
      ToFlooredPoint(root_viewport->ScrollOffsetToPosition(scroll_offset));
}

void WebViewImpl::AdvanceFocus(bool reverse) {
  GetPage()->GetFocusController().AdvanceFocus(
      reverse ? mojom::blink::FocusType::kBackward
              : mojom::blink::FocusType::kForward);
}

double WebViewImpl::ClampZoomLevel(double zoom_level) const {
  return std::max(minimum_zoom_level_,
                  std::min(maximum_zoom_level_, zoom_level));
}

double WebViewImpl::ZoomLevelToZoomFactor(double zoom_level) const {
  if (zoom_factor_override_) {
    return zoom_factor_override_;
  }
  return blink::ZoomLevelToZoomFactor(zoom_level);
}

void WebViewImpl::UpdateWidgetZoomFactors() {
  ForEachFrameWid
```