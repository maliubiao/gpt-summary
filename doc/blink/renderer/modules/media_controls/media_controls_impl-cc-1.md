Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of the `MediaControlsImpl` class in the Chromium Blink engine. This class seems responsible for managing the display and behavior of media controls for HTML `<video>` and `<audio>` elements.

Here's a breakdown of the code's function:

1. **Updating CSS Classes based on State:** The code snippet focuses on managing the CSS classes applied to the media controls container to reflect the current state of the media (e.g., playing, paused, loading).
2. **Handling "No Source" State:**  Specific logic is included to disable the play button and overflow menu when the media element has no source.
3. **Managing Timeline Disabled State:** The code also handles disabling the timeline when there is no source or the media is not loaded.

I need to synthesize these points into a concise summary, highlighting the core responsibilities of this part of the `MediaControlsImpl` class.
这段代码主要负责根据媒体播放器的状态更新媒体控制栏的CSS类，以及在特定状态下启用或禁用控制按钮和时间轴。

**功能归纳:**

1. **根据媒体状态更新CSS类:**
   -  遍历 `kStateCSSClasses` 数组，根据当前 `state` 值，添加或移除对应的CSS类。这允许通过CSS来控制不同状态下控制栏的视觉样式。
   -  当视频元素没有可用的视频帧，且没有海报图像，并且状态处于加载元数据或播放中时，会添加 `kShowDefaultPosterCSSClass` 类，否则移除。这控制了默认海报图像的显示。

2. **处理无媒体源状态 (kNoSource):**
   - 当媒体状态为 `kNoSource` 时，并且媒体元素已连接 (isConnected)，会禁用播放按钮和溢出菜单 (设置 `disabled` 属性)。
   - 在其他状态下，如果播放按钮或溢出菜单之前被禁用，则会移除 `disabled` 属性，重新启用它们。

3. **控制时间轴的启用/禁用:**
   - 当媒体状态为 `kNoSource` 或 `kNotLoaded` 时，会禁用时间轴 (设置 `disabled` 属性)。
   - 在其他状态下，如果时间轴之前被禁用，则会移除 `disabled` 属性，重新启用它。

**与 Javascript, HTML, CSS 的关系:**

* **CSS:**  `kStateCSSClasses` 中的类名以及 `kShowDefaultPosterCSSClass` 是CSS类，它们被添加到媒体控制栏的HTML元素上，用于控制其样式。例如，可以定义 `.paused` 类来改变播放按钮的图标，或者使用 `.show-default-poster` 类来显示一个默认的占位符图片。
* **HTML:** 代码中操作了HTML元素的属性，例如 `play_button_->setAttribute(html_names::kDisabledAttr, g_empty_atom);`  就是在设置播放按钮的 `disabled` 属性。`classList().add()` 和 `classList().remove()` 方法也直接操作了HTML元素的 `class` 属性。
* **Javascript:**  虽然这段代码是C++，但它影响了Web页面的行为，而Javascript可以读取和操作这些CSS类和HTML属性。开发者可以使用 Javascript 来监听媒体事件，并根据不同的状态来修改或读取这些类和属性，以实现更复杂的交互。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `state` 为 `MediaControlsImpl::ControlsState::kNoSource`
* `MediaElement().isConnected()` 返回 `true`
* 播放按钮和溢出菜单都没有 `disabled` 属性。

**输出:**

* 播放按钮的HTML元素将被添加 `disabled` 属性。
* 溢出菜单的HTML元素将被添加 `disabled` 属性。
* `updated` 变量会被设置为 `true`。

**假设输入:**

* `state` 为 `MediaControlsImpl::ControlsState::kPlaying`
* 播放按钮有 `disabled` 属性。
* 溢出菜单没有 `disabled` 属性。
* 时间轴有 `disabled` 属性。

**输出:**

* 播放按钮的HTML元素将被移除 `disabled` 属性。
* 溢出菜单的HTML元素保持不变。
* 时间轴的HTML元素将被移除 `disabled` 属性。
* `updated` 变量会被设置为 `true`。

**用户或编程常见的使用错误:**

* **手动修改CSS类导致状态不一致:**  如果开发者直接通过 Javascript 修改了媒体控制栏的CSS类，而没有通过 `MediaControlsImpl` 的方法更新状态，可能会导致视觉状态与实际媒体状态不符。例如，即使媒体正在播放，但由于手动移除了 `.playing` 类，播放按钮可能仍然显示为暂停状态。
* **错误地设置或读取 `disabled` 属性:** 开发者可能会尝试直接使用 Javascript 设置或读取播放按钮或时间轴的 `disabled` 属性，而没有考虑到 `MediaControlsImpl` 的内部状态管理，可能导致逻辑错误。应该通过Blink提供的API来间接影响这些属性。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户加载包含 `<video>` 或 `<audio>` 标签的网页。**
2. **浏览器解析HTML，创建对应的 `HTMLMediaElement` 对象。**
3. **Blink 引擎创建与 `HTMLMediaElement` 关联的 `MediaControlsImpl` 对象来管理默认的媒体控件。**
4. **当媒体元素的网络状态或播放状态发生变化时 (例如，开始加载、加载完成、播放、暂停等)，会触发相应的事件。**
5. **这些事件会触发 `MediaControlsImpl` 中的回调函数，例如当网络状态变为 `kNetworkNoSource` 时，`UpdateCSSClassFromState()` 方法会被调用。**
6. **在 `UpdateCSSClassFromState()` 方法中，会根据当前的 `state` 值来添加或移除 CSS 类，并根据状态启用或禁用控制按钮和时间轴。**

因此，用户在网页上与媒体元素进行交互 (例如，尝试播放一个没有源的视频) 会导致媒体元素的状态变化，最终触发这段代码的执行，以更新媒体控制栏的视觉和交互状态。

### 提示词
```
这是目录为blink/renderer/modules/media_controls/media_controls_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ove.push_back(kStateCSSClasses[i]);
  }

  if (MediaElement().ShouldShowControls() && ShouldShowVideoControls() &&
      !VideoElement().HasAvailableVideoFrame() &&
      VideoElement().PosterImageURL().IsEmpty() &&
      state <= ControlsState::kLoadingMetadataPlaying) {
    toAdd.push_back(kShowDefaultPosterCSSClass);
  } else {
    toRemove.push_back(kShowDefaultPosterCSSClass);
  }

  classList().add(toAdd, ASSERT_NO_EXCEPTION);
  classList().remove(toRemove, ASSERT_NO_EXCEPTION);

  if (loading_panel_)
    loading_panel_->UpdateDisplayState();

  // If we are in the "no-source" state we should show the overflow menu on a
  // video element.
  // TODO(https://crbug.org/930001): Reconsider skipping this block when not
  // connected.
  if (MediaElement().isConnected()) {
    bool updated = false;

    if (state == kNoSource) {
      // Check if the play button or overflow menu has the "disabled" attribute
      // set so we avoid unnecessarily resetting it.
      if (!play_button_->FastHasAttribute(html_names::kDisabledAttr)) {
        play_button_->setAttribute(html_names::kDisabledAttr, g_empty_atom);
        updated = true;
      }

      if (ShouldShowVideoControls() &&
          !overflow_menu_->FastHasAttribute(html_names::kDisabledAttr)) {
        overflow_menu_->setAttribute(html_names::kDisabledAttr, g_empty_atom);
        updated = true;
      }
    } else {
      if (play_button_->FastHasAttribute(html_names::kDisabledAttr)) {
        play_button_->removeAttribute(html_names::kDisabledAttr);
        updated = true;
      }

      if (overflow_menu_->FastHasAttribute(html_names::kDisabledAttr)) {
        overflow_menu_->removeAttribute(html_names::kDisabledAttr);
        updated = true;
      }
    }

    if (state == kNoSource || state == kNotLoaded) {
      if (!timeline_->FastHasAttribute(html_names::kDisabledAttr)) {
        timeline_->setAttribute(html_names::kDisabledAttr, g_empty_atom);
        updated = true;
      }
    } else {
      if (timeline_->FastHasAttribute(html_names::kDisabledAttr)) {
        timeline_->removeAttribute(html_names::kDisabledAttr);
        updated = true;
      }
    }

    if (updated)
      UpdateOverflowMenuWanted();
  }
}

void MediaControlsImpl::SetClass(const String& class_name,
                                 bool should_have_class) {
  AtomicString atomic_class = AtomicString(class_name);
  if (should_have_class && !classList().contains(atomic_class)) {
    classList().Add(atomic_class);
  } else if (!should_have_class && classList().contains(atomic_class)) {
    classList().Remove(atomic_class);
  }
}

MediaControlsImpl::ControlsState MediaControlsImpl::State() const {
  HTMLMediaElement::NetworkState network_state =
      MediaElement().getNetworkState();
  HTMLMediaElement::ReadyState ready_state = MediaElement().getReadyState();

  if (is_scrubbing_ && ready_state != HTMLMediaElement::kHaveNothing)
    return ControlsState::kScrubbing;

  switch (network_state) {
    case HTMLMediaElement::kNetworkEmpty:
    case HTMLMediaElement::kNetworkNoSource:
      return ControlsState::kNoSource;
    case HTMLMediaElement::kNetworkLoading:
      if (ready_state == HTMLMediaElement::kHaveNothing) {
        return MediaElement().paused() ? ControlsState::kLoadingMetadataPaused
                                       : ControlsState::kLoadingMetadataPlaying;
      }
      if (!MediaElement().paused() &&
          ready_state < HTMLMediaElement::kHaveFutureData) {
        return ControlsState::kBuffering;
      }
      break;
    case HTMLMediaElement::kNetworkIdle:
      if (ready_state == HTMLMediaElement::kHaveNothing)
        return ControlsState::kNotLoaded;
      break;
  }

  if (!MediaElement().paused())
    return ControlsState::kPlaying;
  return ControlsState::kStopped;
}

void MediaControlsImpl::RemovedFrom(ContainerNode& insertion_point) {
  DCHECK(!MediaElement().isConnected());

  HTMLDivElement::RemovedFrom(insertion_point);

  Hide();

  media_event_listener_->Detach();
  if (orientation_lock_delegate_)
    orientation_lock_delegate_->Detach();
  if (rotate_to_fullscreen_delegate_)
    rotate_to_fullscreen_delegate_->Detach();
  if (display_cutout_delegate_)
    display_cutout_delegate_->Detach();

  if (resize_observer_) {
    resize_observer_->disconnect();
    resize_observer_.Clear();
  }

  if (element_mutation_callback_) {
    element_mutation_callback_->Disconnect();
    element_mutation_callback_.Clear();
  }
}

void MediaControlsImpl::Reset() {
  EventDispatchForbiddenScope::AllowUserAgentEvents allow_events_in_shadow;
  BatchedControlUpdate batch(this);

  OnDurationChange();

  // Show everything that we might hide.
  current_time_display_->SetIsWanted(true);
  timeline_->SetIsWanted(true);

  // If the player has entered an error state, force it into the paused state.
  if (MediaElement().error())
    MediaElement().pause();

  UpdatePlayState();

  UpdateTimeIndicators();

  OnVolumeChange();
  OnTextTracksAddedOrRemoved();

  if (picture_in_picture_button_) {
    picture_in_picture_button_->SetIsWanted(
        ShouldShowPictureInPictureButton(MediaElement()));
  }

  UpdateCSSClassFromState();
  UpdateSizingCSSClass();
  OnControlsListUpdated();
}

void MediaControlsImpl::UpdateTimeIndicators(bool suppress_aria) {
  timeline_->SetPosition(MediaElement().currentTime(), suppress_aria);
  UpdateCurrentTimeDisplay();
}

void MediaControlsImpl::OnControlsListUpdated() {
  BatchedControlUpdate batch(this);

  if (ShouldShowVideoControls()) {
    fullscreen_button_->SetIsWanted(true);
    fullscreen_button_->setAttribute(
        html_names::kDisabledAttr,
        MediaControlsSharedHelpers::ShouldShowFullscreenButton(MediaElement())
            ? AtomicString()
            : AtomicString(""));
  } else {
    fullscreen_button_->SetIsWanted(
        MediaControlsSharedHelpers::ShouldShowFullscreenButton(MediaElement()));
    fullscreen_button_->removeAttribute(html_names::kDisabledAttr);
  }

  RefreshCastButtonVisibilityWithoutUpdate();

  download_button_->SetIsWanted(
      download_button_->ShouldDisplayDownloadButton());

  playback_speed_button_->SetIsWanted(
      ShouldShowPlaybackSpeedButton(MediaElement()));
}

LayoutObject* MediaControlsImpl::PanelLayoutObject() {
  return panel_->GetLayoutObject();
}

LayoutObject* MediaControlsImpl::TimelineLayoutObject() {
  return timeline_->GetLayoutObject();
}

LayoutObject* MediaControlsImpl::ButtonPanelLayoutObject() {
  return media_button_panel_->GetLayoutObject();
}

LayoutObject* MediaControlsImpl::ContainerLayoutObject() {
  return GetLayoutObject();
}

void MediaControlsImpl::SetTestMode(bool enable) {
  is_test_mode_ = enable;
  SetClass(kTestModeCSSClass, enable);
}

void MediaControlsImpl::MaybeShow() {
  panel_->SetIsWanted(true);
  panel_->SetIsDisplayed(true);

  UpdateCurrentTimeDisplay();

  if (overlay_play_button_ && !is_paused_for_scrubbing_)
    overlay_play_button_->UpdateDisplayType();
  // Only make the controls visible if they won't get hidden by OnTimeUpdate.
  if (MediaElement().paused() || !ShouldHideMediaControls())
    MakeOpaque();
  if (loading_panel_)
    loading_panel_->OnControlsShown();

  timeline_->OnControlsShown();
  volume_slider_->OnControlsShown();
  UpdateCSSClassFromState();
  UpdateActingAsAudioControls();
}

void MediaControlsImpl::Hide() {
  base::AutoReset<bool> auto_reset_hiding_controls(&is_hiding_controls_, true);

  panel_->SetIsWanted(false);
  panel_->SetIsDisplayed(false);

  // When we permanently hide the native media controls, we no longer want to
  // hide the cursor, since the video will be using custom controls.
  ShowCursor();

  if (overlay_play_button_)
    overlay_play_button_->SetIsWanted(false);
  if (loading_panel_)
    loading_panel_->OnControlsHidden();

  // Hide any popup menus.
  HidePopupMenu();

  // Cancel scrubbing if necessary.
  if (is_scrubbing_) {
    is_paused_for_scrubbing_ = false;
    EndScrubbing();
  }
  timeline_->OnControlsHidden();
  volume_slider_->OnControlsHidden();

  UpdateCSSClassFromState();

  // Hide is called when the HTMLMediaElement is removed from a document. If we
  // stop acting as audio controls during this removal, we end up inserting
  // nodes during the removal, firing a DCHECK. To avoid this, only update here
  // when the media element is connected.
  if (MediaElement().isConnected())
    UpdateActingAsAudioControls();
}

bool MediaControlsImpl::IsVisible() const {
  return panel_->IsOpaque();
}

void MediaControlsImpl::MaybeShowOverlayPlayButton() {
  if (overlay_play_button_)
    overlay_play_button_->SetIsDisplayed(true);
}

void MediaControlsImpl::MakeOpaque() {
  ShowCursor();
  panel_->MakeOpaque();
  MaybeShowOverlayPlayButton();
}

void MediaControlsImpl::MakeOpaqueFromPointerEvent() {
  // If we have quickly hidden the controls we should always show them when we
  // have a pointer event. If the controls are hidden the play button will
  // remain hidden.
  MaybeShowOverlayPlayButton();

  if (IsVisible())
    return;

  MakeOpaque();
}

void MediaControlsImpl::MakeTransparent() {
  // Only hide the cursor if the controls are enabled.
  if (MediaElement().ShouldShowControls())
    HideCursor();
  panel_->MakeTransparent();
}

bool MediaControlsImpl::ShouldHideMediaControls(unsigned behavior_flags) const {
  // Never hide for a media element without visual representation.
  auto* video_element = DynamicTo<HTMLVideoElement>(MediaElement());
  if (!video_element || !MediaElement().HasVideo() ||
      video_element->IsRemotingInterstitialVisible()) {
    return false;
  }

  if (RemotePlayback::From(MediaElement()).GetState() !=
      mojom::blink::PresentationConnectionState::CLOSED) {
    return false;
  }

  // Keep the controls visible as long as the timer is running.
  const bool ignore_wait_for_timer = behavior_flags & kIgnoreWaitForTimer;
  if (!ignore_wait_for_timer && keep_showing_until_timer_fires_)
    return false;

  // Don't hide if the mouse is over the controls.
  // Touch focus shouldn't affect controls visibility.
  const bool ignore_controls_hover = behavior_flags & kIgnoreControlsHover;
  if (!ignore_controls_hover && AreVideoControlsHovered() &&
      !is_touch_interaction_)
    return false;

  // Don't hide if the mouse is over the video area.
  const bool ignore_video_hover = behavior_flags & kIgnoreVideoHover;
  if (!ignore_video_hover && is_mouse_over_controls_)
    return false;

  // Don't hide if focus is on the HTMLMediaElement or within the
  // controls/shadow tree. (Perform the checks separately to avoid going
  // through all the potential ancestor hosts for the focused element.)
  const bool ignore_focus = behavior_flags & kIgnoreFocus;
  if (!ignore_focus && (MediaElement().IsFocused() ||
                        contains(GetDocument().FocusedElement()))) {
    return false;
  }

  // Don't hide the media controls when a panel is showing.
  if (text_track_list_->IsWanted() || playback_speed_list_->IsWanted() ||
      overflow_list_->IsWanted())
    return false;

  // Don't hide if we have accessiblity focus.
  if (panel_->KeepDisplayedForAccessibility())
    return false;

  if (MediaElement().seeking())
    return false;

  return true;
}

bool MediaControlsImpl::AreVideoControlsHovered() const {
  DCHECK(IsA<HTMLVideoElement>(MediaElement()));

  return media_button_panel_->IsHovered() || timeline_->IsHovered();
}

void MediaControlsImpl::UpdatePlayState() {
  if (is_paused_for_scrubbing_)
    return;

  if (overlay_play_button_)
    overlay_play_button_->UpdateDisplayType();
  play_button_->UpdateDisplayType();
}

HTMLDivElement* MediaControlsImpl::PanelElement() {
  return panel_;
}

HTMLDivElement* MediaControlsImpl::ButtonPanelElement() {
  return media_button_panel_;
}

void MediaControlsImpl::BeginScrubbing(bool is_touch_event) {
  if (!MediaElement().paused()) {
    is_paused_for_scrubbing_ = true;
    MediaElement().pause();
  }

  if (scrubbing_message_ && is_touch_event) {
    scrubbing_message_->SetIsWanted(true);
    if (scrubbing_message_->DoesFit()) {
      panel_->setAttribute(html_names::kClassAttr,
                           AtomicString(kScrubbingMessageCSSClass));
    }
  }

  is_scrubbing_ = true;
  UpdateCSSClassFromState();
}

void MediaControlsImpl::EndScrubbing() {
  if (is_paused_for_scrubbing_) {
    is_paused_for_scrubbing_ = false;
    if (MediaElement().paused())
      MediaElement().Play();
  }

  if (scrubbing_message_) {
    scrubbing_message_->SetIsWanted(false);
    panel_->removeAttribute(html_names::kClassAttr);
  }

  is_scrubbing_ = false;
  UpdateCSSClassFromState();
}

void MediaControlsImpl::UpdateCurrentTimeDisplay() {
  timeline_->SetIsWanted(!IsLivePlayback());
  if (panel_->IsWanted()) {
    current_time_display_->SetCurrentValue(MediaElement().currentTime());
  }
}

void MediaControlsImpl::ToggleTextTrackList() {
  if (!MediaElement().HasClosedCaptions()) {
    text_track_list_->SetIsWanted(false);
    return;
  }

  text_track_list_->SetIsWanted(!text_track_list_->IsWanted());
}

bool MediaControlsImpl::TextTrackListIsWanted() {
  return text_track_list_->IsWanted();
}

void MediaControlsImpl::TogglePlaybackSpeedList() {
  playback_speed_list_->SetIsWanted(!playback_speed_list_->IsWanted());
}

bool MediaControlsImpl::PlaybackSpeedListIsWanted() {
  return playback_speed_list_->IsWanted();
}

MediaControlsTextTrackManager& MediaControlsImpl::GetTextTrackManager() {
  return *text_track_manager_;
}

void MediaControlsImpl::RefreshCastButtonVisibility() {
  RefreshCastButtonVisibilityWithoutUpdate();
  BatchedControlUpdate batch(this);
}

void MediaControlsImpl::RefreshCastButtonVisibilityWithoutUpdate() {
  if (!ShouldShowCastButton(MediaElement())) {
    cast_button_->SetIsWanted(false);
    overlay_cast_button_->SetIsWanted(false);
    return;
  }

  cast_button_->SetIsWanted(MediaElement().ShouldShowControls());

  // On sites with muted autoplaying videos as background, it's unlikely that
  // users want to cast such content and showing a Cast overlay button is
  // distracting.  If a user does want to cast a muted autoplay video then they
  // can still do so by touching or clicking on the video, which will cause the
  // cast button to appear.
  if (!MediaElement().GetAutoplayPolicy().IsOrWillBeAutoplayingMuted() &&
      ShouldShowCastOverlayButton(MediaElement())) {
    // Note that this is a case where we add the overlay cast button
    // without wanting the panel cast button.  We depend on the fact
    // that computeWhichControlsFit() won't change overlay cast button
    // visibility in the case where the cast button isn't wanted.
    // We don't call compute...() here, but it will be called as
    // non-cast changes (e.g., resize) occur.  If the panel button
    // is shown, however, compute...() will take control of the
    // overlay cast button if it needs to hide it from the panel.
      overlay_cast_button_->TryShowOverlay();
  } else {
    overlay_cast_button_->SetIsWanted(false);
  }
}

void MediaControlsImpl::ShowOverlayCastButtonIfNeeded() {
  if (!ShouldShowCastOverlayButton(MediaElement())) {
    overlay_cast_button_->SetIsWanted(false);
    return;
  }

  overlay_cast_button_->TryShowOverlay();
  ResetHideMediaControlsTimer();
}

void MediaControlsImpl::EnterFullscreen() {
  Fullscreen::RequestFullscreen(MediaElement());
}

void MediaControlsImpl::ExitFullscreen() {
  Fullscreen::ExitFullscreen(GetDocument());
}

bool MediaControlsImpl::IsFullscreenEnabled() const {
  return fullscreen_button_->IsWanted() &&
         !fullscreen_button_->FastHasAttribute(html_names::kDisabledAttr);
}

void MediaControlsImpl::RemotePlaybackStateChanged() {
  cast_button_->UpdateDisplayType();
  overlay_cast_button_->UpdateDisplayType();
}

void MediaControlsImpl::UpdateOverflowMenuWanted() const {
  // If the bool is true then the element is "sticky" this means that we will
  // always try and show it unless there is not room for it.
  std::pair<MediaControlElementBase*, bool> row_elements[] = {
      std::make_pair(play_button_.Get(), true),
      std::make_pair(mute_button_.Get(), true),
      std::make_pair(fullscreen_button_.Get(), true),
      std::make_pair(current_time_display_.Get(), true),
      std::make_pair(duration_display_.Get(), true),
      std::make_pair(picture_in_picture_button_.Get(), false),
      std::make_pair(cast_button_.Get(), false),
      std::make_pair(download_button_.Get(), false),
      std::make_pair(toggle_closed_captions_button_.Get(), false),
      std::make_pair(playback_speed_button_.Get(), false),
  };

  // These are the elements in order of priority that take up vertical room.
  MediaControlElementBase* column_elements[] = {
      media_button_panel_.Get(), timeline_.Get(),
  };

  // Current size of the media controls.
  gfx::Size controls_size = size_;

  // The video controls are more than one row so we need to allocate vertical
  // room and hide the overlay play button if there is not enough room.
  if (ShouldShowVideoControls()) {
    // Allocate vertical room for overlay play button if necessary.
    if (overlay_play_button_) {
      gfx::Size overlay_play_button_size =
          overlay_play_button_->GetSizeOrDefault();
      if (controls_size.height() >= overlay_play_button_size.height() &&
          controls_size.width() >= kMinWidthForOverlayPlayButton) {
        overlay_play_button_->SetDoesFit(true);
        controls_size.Enlarge(0, -overlay_play_button_size.height());
      } else {
        overlay_play_button_->SetDoesFit(false);
      }
    }

    controls_size.Enlarge(-kVideoButtonPadding, 0);

    // Allocate vertical room for the column elements.
    for (MediaControlElementBase* element : column_elements) {
      gfx::Size element_size = element->GetSizeOrDefault();
      if (controls_size.height() - element_size.height() >= 0) {
        element->SetDoesFit(true);
        controls_size.Enlarge(0, -element_size.height());
      } else {
        element->SetDoesFit(false);
      }
    }

    // If we cannot show the overlay play button, show the normal one.
    play_button_->SetIsWanted(!overlay_play_button_ ||
                              !overlay_play_button_->DoesFit());
  } else {
    controls_size.Enlarge(-kAudioButtonPadding, 0);

    // Undo any IsWanted/DoesFit changes made in the above block if we're
    // switching to act as audio controls.
    if (is_acting_as_audio_controls_) {
      play_button_->SetIsWanted(true);

      for (MediaControlElementBase* element : column_elements)
        element->SetDoesFit(true);
    }
  }

  // Go through the elements and if they are sticky allocate them to the panel
  // if we have enough room. If not (or they are not sticky) then add them to
  // the overflow menu. Once we have run out of room add_elements will be
  // made false and no more elements will be added.
  MediaControlElementBase* last_element = nullptr;
  bool add_elements = true;
  bool overflow_wanted = false;
  for (std::pair<MediaControlElementBase*, bool> pair : row_elements) {
    MediaControlElementBase* element = pair.first;
    if (!element)
      continue;

    // If the element is wanted then it should take up space, otherwise skip it.
    element->SetOverflowElementIsWanted(false);
    if (!element->IsWanted())
      continue;

    // Get the size of the element and see if we should allocate space to it.
    gfx::Size element_size = element->GetSizeOrDefault();
    bool does_fit = add_elements && pair.second &&
                    ((controls_size.width() - element_size.width()) >= 0);
    element->SetDoesFit(does_fit);

    if (element == mute_button_.Get())
      volume_control_container_->SetIsWanted(does_fit);

    // The element does fit and is sticky so we should allocate space for it. If
    // we cannot fit this element we should stop allocating space for other
    // elements.
    if (does_fit) {
      controls_size.Enlarge(-element_size.width(), 0);
      last_element = element;
    } else {
      add_elements = false;
      if (element->HasOverflowButton() && !element->IsDisabled()) {
        overflow_wanted = true;
        element->SetOverflowElementIsWanted(true);
      }
    }
  }

  // The overflow menu is always wanted if it has the "disabled" attr set.
  overflow_wanted = overflow_wanted ||
                    overflow_menu_->FastHasAttribute(html_names::kDisabledAttr);
  overflow_menu_->SetDoesFit(overflow_wanted);
  overflow_menu_->SetIsWanted(overflow_wanted);

  // If we want to show the overflow button and we do not have any space to show
  // it then we should hide the last shown element.
  int overflow_icon_width = overflow_menu_->GetSizeOrDefault().width();
  if (overflow_wanted && last_element &&
      controls_size.width() < overflow_icon_width) {
    last_element->SetDoesFit(false);
    last_element->SetOverflowElementIsWanted(true);

    if (last_element == mute_button_.Get())
      volume_control_container_->SetIsWanted(false);
  }

  MaybeRecordElementsDisplayed();

  UpdateOverflowMenuItemCSSClass();
}

// This method is responsible for adding css class to overflow menu list
// items to achieve the animation that items appears one after another when
// open the overflow menu.
void MediaControlsImpl::UpdateOverflowMenuItemCSSClass() const {
  unsigned int id = 0;
  for (Element* item = ElementTraversal::LastChild(*overflow_list_); item;
       item = ElementTraversal::PreviousSibling(*item)) {
    const CSSPropertyValueSet* inline_style = item->InlineStyle();
    DOMTokenList& class_list = item->classList();

    // We don't care if the hidden element still have animated-* CSS class
    if (inline_style &&
        inline_style->GetPropertyValue(CSSPropertyID::kDisplay) == "none")
      continue;

    AtomicString css_class =
        AtomicString("animated-") + AtomicString::Number(id++);
    if (!class_list.contains(css_class))
      class_list.setValue(css_class);
  }
}

void MediaControlsImpl::UpdateScrubbingMessageFits() const {
  if (scrubbing_message_)
    scrubbing_message_->SetDoesFit(size_.width() >= kMinScrubbingMessageWidth);
}

void MediaControlsImpl::UpdateSizingCSSClass() {
  MediaControlsSizingClass sizing_class =
      MediaControls::GetSizingClass(size_.width());

  SetClass(kMediaControlsSizingSmallCSSClass,
           ShouldShowVideoControls() &&
               (sizing_class == MediaControlsSizingClass::kSmall ||
                sizing_class == MediaControlsSizingClass::kMedium));
  SetClass(kMediaControlsSizingLargeCSSClass,
           ShouldShowVideoControls() &&
               sizing_class == MediaControlsSizingClass::kLarge);
}

void MediaControlsImpl::MaybeToggleControlsFromTap() {
  if (MediaElement().paused())
    return;

  // If the controls are visible then hide them. If the controls are not visible
  // then show them and start the timer to automatically hide them.
  if (IsVisible()) {
    MakeTransparent();
  } else {
    MakeOpaque();
    // Touch focus shouldn't affect controls visibility.
    if (ShouldHideMediaControls(kIgnoreWaitForTimer | kIgnoreFocus)) {
      keep_showing_until_timer_fires_ = true;
      StartHideMediaControlsTimer();
    }
  }
}

void MediaControlsImpl::OnAccessibleFocus() {
  if (panel_->KeepDisplayedForAccessibility())
    return;

  panel_->SetKeepDisplayedForAccessibility(true);

  if (!MediaElement().ShouldShowControls())
    return;

  OpenVolumeSliderIfNecessary();

  keep_showing_until_timer_fires_ = true;
  StartHideMediaControlsTimer();
  MaybeShow();
}

void MediaControlsImpl::OnAccessibleBlur() {
  panel_->SetKeepDisplayedForAccessibility(false);

  if (MediaElement().ShouldShowControls())
    return;

  CloseVolumeSliderIfNecessary();

  keep_showing_until_timer_fires_ = false;
  ResetHideMediaControlsTimer();
}

void MediaControlsImpl::DefaultEventHandler(Event& event) {
  HTMLDivElement::DefaultEventHandler(event);

  // Do not handle events to not interfere with the rest of the page if no
  // controls should be visible.
  if (!MediaElement().ShouldShowControls())
    return;

  // Add IgnoreControlsHover to m_hideTimerBehaviorFlags when we see a touch
  // event, to allow the hide-timer to do the right thing when it fires.
  // FIXME: Preferably we would only do this when we're actually handling the
  // event here ourselves.
  bool is_touch_event = IsTouchEvent(&event);
  hide_timer_behavior_flags_ |=
      is_touch_event ? kIgnoreControlsHover : kIgnoreNone;

  // Touch events are treated differently to avoid fake mouse events to trigger
  // random behavior. The expect behaviour for touch is that a tap will show the
  // controls and they will hide when the timer to hide fires.
  if (is_touch_event)
    HandleTouchEvent(&event);

  if (event.type() == event_type_names::kMouseover && !is_touch_event)
    is_touch_interaction_ = false;

  if ((event.type() == event_type_names::kPointerover ||
       event.type() == event_type_names::kPointermove ||
       event.type() == event_type_names::kPointerout) &&
      !is_touch_interaction_) {
    HandlePointerEvent(&event);
  }

  if (event.type() == event_type_names::kClick && !is_touch_interaction_)
    HandleClickEvent(&event);

  // If the user is interacting with the controls via the keyboard, don't hide
  // the controls. This will fire when the user tabs between controls (focusin)
  // or when they seek either the timeline or volume sliders (input).
  if (event.type() == event_type_names::kFocusin ||
      event.type() == event_type_names::kInput) {
    ResetHideMediaControlsTimer();
  }

  auto* keyboard_event = DynamicTo<KeyboardEvent>(event);
  if (keyboard_event && !event.defaultPrevented() &&
      !IsSpatialNavigationEnabled(GetDocument().GetFrame())) {
    const AtomicString key(keyboard_event->key());
    if (key == keywords::kCapitalEnter || keyboard_event->keyCode() == ' ') {
      if (overlay_play_button_) {
        overlay_play_button_->OnMediaKeyboardEvent(&event);
      } else {
        play_button_->OnMediaKeyboardEvent(&event);
      }
      return;
    }
    if (key == keywords::kArrowLeft || key == keywords::kArrowRight ||
        key == keywords::kHome || key == keywords::kEnd) {
      timeline_->OnMediaKeyboardEvent(&event);
      return;
    }
    if (volume_slider_ &&
        (key == keywords::kArrowDown || key == keywords::kArrowUp)) {
      for (int i = 0; i < 5; i++)
        volume_slider_->OnMediaKeyboardEvent(&event);
      return;
    }
  }
}

void MediaControlsImpl::HandlePointerEvent(Event* event) {
  if (event->type() == event_type_names::kPointerover) {
    if (!ContainsRelatedTarget(event)) {
      is_mouse_over_controls_ = true;
      if (!MediaElement().paused()) {
        MakeOpaqueFromPointerEvent();
        StartHideMediaControlsIfNecessary();
      }
    }
  } else if (event->type() == event_type_names::kPointerout) {
    if (!ContainsRelatedTarget(event)) {
      is_mouse_over_controls_ = false;
      StopHideMediaControlsTimer();

      // When we get a mouse out, if video is playing and control should
      // hide regardless of focus, hide the control.
      // This will fix the issue that when mouse out event happen while video is
      // focused, control never hides.
      if (!MediaElement().paused() && ShouldHideMediaControls(kIgnoreFocus))
        MakeTransparent();
    }
  } else if (event->type() == event_type_names::kPointermove) {
    // When we get a mouse move, show the media controls, and start a timer
    // that will hide the media controls after a 3 seconds without a mouse move.
    is_mouse_over_controls_ = true;
    MakeOpaqueFromPointerEvent();

    // Start the timer regardless of focus state
    if (ShouldHideMediaControls(kIgnoreVideoHover | kIgnoreFocus))
      StartHideMediaControlsTimer();
  }
}

void MediaControlsImpl::HandleClickEvent(Event* event) {
  if (ContainsRelatedTarget(event) || !IsFullscreenEnabled())
    return;

  if (tap_timer_.IsActive()) {
    tap_timer_.Stop();

    // Toggle fullscreen.
    if (MediaElement().IsFullscreen())
      ExitFullscreen();
    else
      EnterFullscreen();

    // If we paused for the first click of this double-click, then we need to
    // resume playback, since the user was just toggling fullscreen.
    if (is_paused_for_double_tap_) {
      MediaElement().Play();
      is_paused_for_double_tap_ = false;
    }
  } else {
    // If the video is not paused, assume the user is clicking to pause the
    // video. If the user clicks again for a fullscreen-toggling double-tap, we
    // will resume playback.
    if (!MediaElement().paused()) {
      MediaElement().pause();
      is_paused_for_double_tap_ = true;
    }
    tap_timer_.StartOneShot(kDoubleTapDelay, FROM_HERE);
  }
}

void MediaControlsImpl::HandleTouchEvent(Event* event) {
  is_mouse_over_controls_ = false;
  is_touch_interaction_ = true;

  if (event->type() == event_type_names::kGesturetap &&
      !ContainsRelatedTarget(event)) {
    event->SetDefaultHandled();

    if (tap_timer_.IsActive()) {
      // Cancel the visibility toggle event.
      tap_timer_.Stop();

      if (IsOnLeftSide(event)) {
        MaybeJump(kNumberOfSecondsToJump * -1);
      } else {
        MaybeJump(kNumberOfSecondsToJump);
      }
    } else {
      tap_timer_.StartOneShot(kDoubleTapDelay, FROM_HERE);
    }
  }
}

void MediaControlsImpl::EnsureAnimatedArrowContainer() {
  if (!animated_arrow_container_element_) {
    animated_arrow_container_element_ =
        MakeGarbageCollected<MediaControlAnimatedArrowContainerElement>(*this);
    ParserAppendChild(animated_arrow_container_element_);
  }
}

void MediaControlsImpl::MaybeJump(int seconds) {
  // Update the current time.
  double new_time = std::max(0.0, MediaElement().currentTime() + seconds);
  new_time = std::min(new_time, MediaElement().duration());
  MediaElement().setCurrentTime(new_time);

  // Show the arrow animation.
  EnsureAnimatedArrowContainer();
  MediaControlAnimatedArrowContainerElement::ArrowDirection direction =
      (seconds > 0)
          ? MediaControlAnimatedArrowContainerElement::ArrowDirection::kRight
          : MediaControlAnimatedArrowContainerElement::ArrowDirection::kLeft;
  animated_arrow_container_element_->ShowArrowAnimation(direction);
}

bool MediaControlsImpl::IsOnLeftSide(Event* event) {
  auto* gesture_event = DynamicTo<GestureEvent>(event);
  if (!gesture_event)
    return false;

  float tap_x = gesture_event->NativeEvent().PositionInWidget().x();

  DOMRect* rect = GetBoundingClientRect();
  double middle = rect->x() + (rect->width() / 2);
  if (GetDocument().GetFrame())
    middle *= GetDocument().GetFrame()->LayoutZoomFactor();

  return tap_x < middle;
}

void MediaControlsImpl::TapTimerFired(TimerBase*) {
  if (is_touch_interaction_) {
    MaybeToggleControlsFromTap();
  } else if (MediaElement().paused()) {
    // If this is not a touch interaction and the video is paused, then either
    // the user has just paused via click (in which case we've already paused
    // and there's nothing to do), or the user is playing by click (in which
    // case we need to start playing).
    if (is_paused_for_double_tap_) {
      Platform::Current()->RecordAction(
          UserMetricsAction("Media.Controls.ClickAnywhereToPause"));
      // TODO(https://crbug.com/896252): Show overlay pause animation.
      is_paused_for_double_tap_ = false;
    } else {
      Platform::Current()->RecordAction(
          UserMetricsAction("Media.Controls.ClickAnywhereToPlay"));
      // TODO(https://crbug.com/896252): Show overlay play animation.
      MediaElement().Play();
    }
  }
}

void MediaControlsImpl::HideMediaControlsTimerFired(TimerBase*) {
  unsigned behavior_flags =
      hide_timer_behavior_flags_ | kIgnoreFocus | kIgnoreVideoHover;
  hide_timer_behavior_flags_ = kIgnoreNone;
  keep_showing_until_timer_fires_ = false;

  if (MediaElement().paused())
    return;

  if (!ShouldHideMediaControls(behavior_flags))
    return;

  MakeTransparent();
  overlay_cast_button_->SetIsWanted(false);
}

void MediaControlsImpl::StartHideMediaControlsIfNecessary() {
  if (ShouldHideMediaControls())
    StartHideMediaControlsTimer();
}

void MediaControlsImpl::StartHideMediaControlsTimer() {
  hide_media_controls_timer_.StartOneShot(
      GetTimeWithoutMouseMovementBeforeHidingMediaControls(), FROM_HERE);
}

void MediaControlsImpl::StopHideMediaControlsTimer() {
  keep_showing_until_timer_fires_ = false;
  hide_media_controls_timer_.Stop();
}

void MediaControlsImpl::ResetHideMediaControlsTimer() {
  StopHideMediaControlsTimer();
  if (!MediaElement().paused())
    StartHideMediaControlsTimer();
}

void MediaControlsImpl::HideCursor() {
  SetInlineStyleProperty(CSSPropertyID::kCursor, "none", false);
}

void MediaControlsImpl::ShowCursor() {
  RemoveInli
```