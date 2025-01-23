Response:
The user wants a summary of the functionality of the provided C++ code snippet from `html_media_element.cc`. I need to identify the key actions and processes described in this part of the file. Specifically, I need to focus on the methods `selectNextSourceChild`, `SourceWasAdded`, `SourceWasRemoved`, `TimeChanged`, `DurationChanged` (both overloads), `RemotePlaybackCompatibilityChanged`, `HasSelectedVideoTrack`, `GetSelectedVideoTrackId`, `WasAlwaysMuted`, `Repaint`, `SizeChanged`, `BufferedInternal`, `buffered`, `played`, `SeekableInternal`, `seekable`, `PotentiallyPlaying`, `CouldPlayIfEnoughData`, `EndedPlayback`, `StoppedDueToErrors`, `UpdatePlayState`, `StopPeriodicTimers`, `ClearMediaPlayerAndAudioSourceProviderClientWithoutLocking`, `ClearMediaPlayer`, `ContextLifecycleStateChanged`, `ContextDestroyed`, `HasPendingActivityInternal`, `IsFullscreen`, `CcLayer`, `HasClosedCaptions`, `TextTracksVisible`, `AssertShadowRootChildren`, `EnsureTextTrackContainer`, `UpdateTextTrackDisplay`, `SpeechSynthesis`, `MediaControlsDidBecomeVisible`, `SetTextTrackKindUserPreferenceForAllMediaElements`, `AutomaticTrackSelectionForUpdatedUserPreference`, `MarkCaptionAndSubtitleTracksAsUnconfigured`, `webkitAudioDecodedByteCount`, `webkitVideoDecodedByteCount`, `IsURLAttribute`, `SetShouldDelayLoadEvent`, `GetMediaControls`, `EnsureMediaControls`, `UpdateControlsVisibility`, `GetCueTimeline`, `ConfigureTextTrackDisplay`, `ResetMediaPlayerAndMediaSource`, `SetAudioSourceNode`, `CorsMode`, `SetCcLayer`, `MediaSourceOpened`, `IsInteractiveContent`, `BindMediaPlayerReceiver`, `OnSpeakingCompleted`, and `Trace`.

I will then categorize these functionalities and relate them to Javascript, HTML, and CSS where applicable, providing examples. I will also look for logical deductions with assumptions and outputs, and common user/programming errors illustrated in the code.
这段代码是`HTMLMediaElement`类的一部分，主要负责处理媒体元素的资源选择、生命周期管理、播放状态控制、以及与用户界面和底层媒体播放器的交互。以下是其功能的归纳：

**核心功能：**

1. **资源选择 (Source Selection):**
   - `selectNextSourceChild`:  从 `<video>` 或 `<audio>` 元素的 `<source>` 子元素中选择下一个要加载的媒体资源。它会检查 `media` 查询、`src` 属性的有效性、以及 `type` 属性指定的 MIME 类型是否被支持。
   - `SourceWasAdded`: 当新的 `<source>` 元素被添加到媒体元素时触发，根据当前的网络状态和 `src` 属性是否存在，决定是否立即启动资源选择算法。
   - `SourceWasRemoved`: 当 `<source>` 元素被移除时触发，更新内部状态以反映资源的变化。

2. **播放控制和状态管理 (Playback Control and State Management):**
   - `TimeChanged`:  当媒体的当前播放时间发生变化时触发，处理循环播放、播放结束事件，并更新播放状态。
   - `DurationChanged`: 当媒体的持续时间发生变化时触发，更新内部的持续时间，并可能触发 seek 操作。
   - `RemotePlaybackCompatibilityChanged`: 通知远程播放客户端资源 URL 的兼容性状态。
   - `PotentiallyPlaying`, `CouldPlayIfEnoughData`, `EndedPlayback`, `StoppedDueToErrors`:  用于判断媒体元素是否可以播放或已经结束播放，或者因为错误停止。
   - `UpdatePlayState`: 根据当前的播放条件（例如，是否暂停，是否有足够的数据）启动或停止媒体播放器。
   - `StopPeriodicTimers`: 停止用于定期更新播放状态和进度的定时器。

3. **媒体播放器生命周期管理 (Media Player Lifecycle Management):**
   - `ClearMediaPlayerAndAudioSourceProviderClientWithoutLocking`, `ClearMediaPlayer`: 清理底层的媒体播放器资源，包括停止定时器、取消加载等。
   - `ContextLifecycleStateChanged`, `ContextDestroyed`: 响应浏览上下文的生命周期变化，例如冻结或销毁，并相应地暂停或清理媒体资源。

4. **缓冲和 Seek (Buffering and Seeking):**
   - `BufferedInternal`, `buffered`: 获取媒体资源的已缓冲时间范围。
   - `SeekableInternal`, `seekable`: 获取媒体资源的可 seek 时间范围。

5. **用户界面交互 (User Interface Interaction):**
   - `Repaint`, `SizeChanged`: 通知需要重绘或尺寸发生变化，通常用于视频元素。
   - `EnsureTextTrackContainer`, `UpdateTextTrackDisplay`: 管理字幕和 WebVTT 轨道的显示。
   - `EnsureMediaControls`, `UpdateControlsVisibility`: 管理原生媒体控件的显示和隐藏。
   - `HasClosedCaptions`, `TextTracksVisible`:  检查是否有可见的字幕轨道。

6. **音频和视频轨道 (Audio and Video Tracks):**
   - `HasSelectedVideoTrack`, `GetSelectedVideoTrackId`:  获取当前选择的视频轨道信息。

7. **其他 (Miscellaneous):**
   - `WasAlwaysMuted`: 记录媒体元素是否一直处于静音状态。
   - `HasPendingActivityInternal`:  检查媒体元素是否有未完成的操作，例如正在加载或播放。
   - `IsFullscreen`:  检查媒体元素是否处于全屏模式。
   - `CcLayer`: 获取用于合成的 Layer 对象。
   - `SpeechSynthesis`:  获取语音合成接口用于处理音频描述。
   - `SetTextTrackKindUserPreferenceForAllMediaElements`, `AutomaticTrackSelectionForUpdatedUserPreference`, `MarkCaptionAndSubtitleTracksAsUnconfigured`: 处理用户对字幕偏好的设置和自动选择。
   - `webkitAudioDecodedByteCount`, `webkitVideoDecodedByteCount`: 获取已解码的音频和视频字节数。
   - `IsURLAttribute`: 判断给定的属性是否是 URL 属性。
   - `SetShouldDelayLoadEvent`: 设置是否延迟加载事件。
   - `GetCueTimeline`: 获取用于管理媒体 Cues 的时间线对象。
   - `ConfigureTextTrackDisplay`:  配置字幕轨道的显示。
   - `ResetMediaPlayerAndMediaSource`: 重置媒体播放器和 Media Source 相关的状态。
   - `SetAudioSourceNode`: 设置音频源节点，用于 Web Audio API 集成。
   - `CorsMode`: 获取跨域资源请求的 CORS 模式。
   - `SetCcLayer`: 设置用于合成字幕的 Layer 对象。
   - `MediaSourceOpened`: 当 Media Source API 打开时被调用。
   - `IsInteractiveContent`:  判断媒体元素是否是交互式内容（通常通过 `controls` 属性）。
   - `BindMediaPlayerReceiver`: 用于绑定 Mojo 接口，实现进程间通信。
   - `OnSpeakingCompleted`: 当语音合成完成时被调用。
   - `Trace`: 用于 Blink 的垃圾回收机制。

**与 Javascript, HTML, CSS 的关系和举例：**

* **Javascript:**
    - **事件监听:**  `TimeChanged` 和 `DurationChanged` 最终会触发 Javascript 中的 `timeupdate` 和 `durationchange` 事件，允许开发者监听这些事件并执行相应的操作。
    - **DOM 操作:** `SourceWasAdded` 和 `SourceWasRemoved` 响应了 Javascript 对 `<source>` 元素的添加和删除操作。
    - **属性访问:** 代码中多次使用 `FastHasAttribute` 和 `FastGetAttribute` 来检查和获取 HTML 属性的值，这些属性可以通过 Javascript 进行设置和访问（例如 `videoElement.src`，`videoElement.controls`）。
    - **方法调用:**  `UpdatePlayState` 响应了 Javascript 中 `play()` 和 `pause()` 方法的调用。

* **HTML:**
    - **`<video>` 和 `<audio>` 元素:** 这个文件是 `HTMLMediaElement` 的实现，直接关联到 HTML 中的 `<video>` 和 `<audio>` 元素及其子元素 `<source>`。
    - **`src` 属性:** `selectNextSourceChild` 核心处理的是 `<source>` 元素的 `src` 属性，用于指定媒体资源的 URL。
    - **`type` 属性:** `selectNextSourceChild` 也会检查 `<source>` 元素的 `type` 属性，用于指定媒体资源的 MIME 类型，帮助浏览器选择合适的解码器。
    - **`controls` 属性:** `UpdateControlsVisibility` 的逻辑受到 HTML `controls` 属性的影响，决定是否显示原生媒体控件。
    - **`<track>` 元素:**  `EnsureTextTrackContainer` 和 `UpdateTextTrackDisplay` 负责处理与 `<track>` 元素相关的字幕显示。

* **CSS:**
    - **伪类 `:paused` 和 `:playing`:** `UpdatePlayState` 调用了 `PseudoStateChanged` 来更新元素的 `:paused` 和 `:playing` 伪类状态，允许开发者使用 CSS 来定义不同播放状态下的样式。
    - **布局和渲染:** `Repaint` 和 `SizeChanged` 最终会影响元素的布局和渲染。

**逻辑推理和假设输入输出：**

**假设输入：**  一个 `<video>` 元素有多个 `<source>` 子元素，并且浏览器支持 `kVideoSourceMediaQuerySupport` 特性。

```html
<video>
  <source src="video1.mp4" type="video/mp4" media="(min-width: 600px)">
  <source src="video2.webm" type="video/webm">
  <source src="video3.ogg" type="video/ogg">
</video>
```

**`selectNextSourceChild` 的逻辑推理和输出：**

1. **第一次调用：**
   - `source` 指向第一个 `<source>` 元素 (`video1.mp4`)。
   - 假设当前视口宽度大于等于 600px，`source->MediaQueryMatches()` 返回 `true`。
   - `media_url` 解析为 `video1.mp4` 的完整 URL。
   - 假设 `IsSafeToLoadURL` 返回 `true`。
   - 假设浏览器支持 `video/mp4`，`GetSupportsType(ContentType(type))` 返回 `true`。
   - `can_use_source_element` 为 `true`。
   - **输出：** 返回 `video1.mp4` 的完整 URL。

2. **如果第一次调用时视口宽度小于 600px：**
   - `source->MediaQueryMatches()` 返回 `false`。
   - `goto checkAgain;` 会跳过后续检查。
   - `can_use_source_element` 保持 `false`。
   - **输出：**  返回空的 `KURL()`。

3. **如果第一个 `<source>` 不可用，`selectNextSourceChild` 会被再次调用，`next_child_node_to_consider_` 将指向第二个 `<source>` 元素 (`video2.webm`)，并重复上述检查过程。**

**用户或编程常见的使用错误举例：**

1. **MIME 类型错误:**  如果 `<source>` 元素的 `type` 属性指定了一个浏览器不支持的 MIME 类型，`selectNextSourceChild` 中的 `GetSupportsType` 会返回 `false`，导致该 `<source>` 被跳过，可能导致媒体无法播放。

   ```html
   <video>
     <source src="video.mp4" type="video/wrong-mime-type">
   </video>
   ```

2. **`src` 属性路径错误:** 如果 `<source>` 元素的 `src` 属性指向一个不存在的资源，浏览器会尝试加载该资源并最终失败，触发错误事件。

   ```html
   <video>
     <source src="nonexistent-video.mp4" type="video/mp4">
   </video>
   ```

3. **在 `NETWORK_EMPTY` 状态下添加 `<source>` 后未调用 `load()`:**  如果媒体元素在初始状态（没有 `src` 属性）下添加了 `<source>` 元素，浏览器会自动开始资源选择。但如果开发者期望手动控制加载过程，可能会错误地认为需要显式调用 `load()` 方法。

4. **动态修改已插入的 `<source>` 元素：** 代码注释中提到 "Dynamically modifying a source element and its attribute when the element is already inserted in a video or audio element will have no effect."  这是一个常见的误解，开发者可能会尝试在脚本中修改已添加到 DOM 中的 `<source>` 元素的 `src` 或 `type` 属性，期望媒体源发生变化，但这不会生效。需要移除并重新添加 `<source>` 元素。

**功能归纳（第5部分）：**

这段代码主要负责 **HTML媒体元素生命周期中的资源选择和播放控制**。它实现了从 `<source>` 元素中选择合适的媒体资源，并管理媒体元素的播放状态，包括播放、暂停、seek、以及对播放结束和错误的处理。此外，它还涉及与用户界面（如原生控件和字幕显示）的交互，以及响应浏览上下文的生命周期变化。 这部分代码是媒体元素核心逻辑的关键组成部分，确保了媒体资源能够正确加载和播放。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_media_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ts step below.
    if (!source->MediaQueryMatches() &&
        base::FeatureList::IsEnabled(kVideoSourceMediaQuerySupport)) {
      goto checkAgain;
    }

    // 4. Let urlRecord be the result of encoding-parsing a URL given
    // candidate's src attribute's value, relative to candidate's node document
    // when the src attribute was last changed.
    media_url = source->GetDocument().CompleteURL(src_value);

    // 5. If urlRecord is failure, then end the synchronous section, and jump
    // down to the failed with elements step below.
    if (!IsSafeToLoadURL(media_url, action_if_invalid)) {
      goto checkAgain;
    }

    // 6. If candidate has a type attribute whose value, when parsed as a
    // MIME type ...
    type = source->type();
    if (type.empty() && media_url.ProtocolIsData())
      type = MimeTypeFromDataURL(media_url);
    if (!type.empty()) {
      if (should_log) {
        DVLOG(3) << "selectNextSourceChild(" << *this << ") - 'type' is '"
                 << type << "'";
      }
      if (!GetSupportsType(ContentType(type)))
        goto checkAgain;
    }

    // Making it this far means the <source> looks reasonable.
    can_use_source_element = true;

  checkAgain:
    if (!can_use_source_element && action_if_invalid == kComplain && source)
      source->ScheduleErrorEvent();
  }

  if (can_use_source_element) {
    if (content_type)
      *content_type = type;
    current_source_node_ = source;
    next_child_node_to_consider_ = source->nextSibling();
  } else {
    current_source_node_ = nullptr;
    next_child_node_to_consider_ = nullptr;
  }

  if (should_log) {
    DVLOG(3) << "selectNextSourceChild(" << *this << ") -> "
             << current_source_node_.Get() << ", "
             << (can_use_source_element ? UrlForLoggingMedia(media_url) : "");
  }

  return can_use_source_element ? media_url : KURL();
}

void HTMLMediaElement::SourceWasAdded(HTMLSourceElement* source) {
  DVLOG(3) << "sourceWasAdded(" << *this << ", " << source << ")";

  KURL url = source->GetNonEmptyURLAttribute(html_names::kSrcAttr);
  DVLOG(3) << "sourceWasAdded(" << *this << ") - 'src' is "
           << UrlForLoggingMedia(url);

  // We should only consider a <source> element when there is not src attribute
  // at all.
  if (FastHasAttribute(html_names::kSrcAttr))
    return;

  // 4.8.8 - If a source element is inserted as a child of a media element that
  // has no src attribute and whose networkState has the value NETWORK_EMPTY,
  // the user agent must invoke the media element's resource selection
  // algorithm.
  if (getNetworkState() == HTMLMediaElement::kNetworkEmpty) {
    InvokeResourceSelectionAlgorithm();
    // Ignore current |next_child_node_to_consider_| and consider |source|.
    next_child_node_to_consider_ = source;
    return;
  }

  if (current_source_node_ && source == current_source_node_->nextSibling()) {
    DVLOG(3) << "sourceWasAdded(" << *this
             << ") - <source> inserted immediately after current source";
    // Ignore current |next_child_node_to_consider_| and consider |source|.
    next_child_node_to_consider_ = source;
    return;
  }

  // Consider current |next_child_node_to_consider_| as it is already in the
  // middle of processing.
  if (next_child_node_to_consider_)
    return;

  if (load_state_ != kWaitingForSource)
    return;

  // 4.8.9.5, resource selection algorithm, source elements section:
  // 21. Wait until the node after pointer is a node other than the end of the
  // list. (This step might wait forever.)
  // 22. Asynchronously await a stable state...
  // 23. Set the element's delaying-the-load-event flag back to true (this
  // delays the load event again, in case it hasn't been fired yet).
  SetShouldDelayLoadEvent(true);

  // 24. Set the networkState back to NETWORK_LOADING.
  // Changing the network state might trigger media controls to add new nodes
  // to the DOM which is forbidden while source is being inserted into this
  // node. This is a problem as ContainerNode::NotifyNodeInsertedInternal,
  // which is always indirectly triggering this function, prohibits event
  // dispatch and adding new nodes will run
  // blink::DispatchChildInsertionEvents.
  //
  // We still need to update the media controls. This will be done after
  // load_timer_ fires a new event - which is setup in ScheduleNextSourceChild
  // below so skipping that step here should be OK.
  SetNetworkState(kNetworkLoading, false /* update_media_controls */);

  // 25. Jump back to the find next candidate step above.
  next_child_node_to_consider_ = source;
  ScheduleNextSourceChild();
}

void HTMLMediaElement::SourceWasRemoved(HTMLSourceElement* source) {
  DVLOG(3) << "sourceWasRemoved(" << *this << ", " << source << ")";

  KURL url = source->GetNonEmptyURLAttribute(html_names::kSrcAttr);
  DVLOG(3) << "sourceWasRemoved(" << *this << ") - 'src' is "
           << UrlForLoggingMedia(url);

  if (source != current_source_node_ && source != next_child_node_to_consider_)
    return;

  if (source == next_child_node_to_consider_) {
    if (current_source_node_)
      next_child_node_to_consider_ = current_source_node_->nextSibling();
    DVLOG(3) << "sourceWasRemoved(" << *this
             << ") - next_child_node_to_consider_ set to "
             << next_child_node_to_consider_.Get();
  } else if (source == current_source_node_) {
    // Clear the current source node pointer, but don't change the movie as the
    // spec says:
    // 4.8.8 - Dynamically modifying a source element and its attribute when the
    // element is already inserted in a video or audio element will have no
    // effect.
    current_source_node_ = nullptr;
    DVLOG(3) << "SourceWasRemoved(" << *this
             << ") - current_source_node_ set to 0";
  }
}

void HTMLMediaElement::TimeChanged() {
  DVLOG(3) << "timeChanged(" << *this << ")";

  // 4.8.12.9 steps 12-14. Needed if no ReadyState change is associated with the
  // seek.
  if (seeking_ && ready_state_ >= kHaveCurrentData &&
      !web_media_player_->Seeking()) {
    FinishSeek();
  }

  // When the current playback position reaches the end of the media resource
  // when the direction of playback is forwards, then the user agent must follow
  // these steps:
  if (EndedPlayback(LoopCondition::kIgnored)) {
    // If the media element has a loop attribute specified
    if (Loop()) {
      //  then seek to the earliest possible position of the media resource and
      //  abort these steps.
      Seek(EarliestPossiblePosition());
    } else {
      // Queue a task to fire a simple event named timeupdate at the media
      // element.
      ScheduleTimeupdateEvent(false);

      // If the media element has still ended playback, and the direction of
      // playback is still forwards, and paused is false,
      if (!paused_) {
        // Trigger an update to `official_playback_position_` (if necessary)
        // BEFORE setting `paused_ = false`, to ensure a final sync with
        // `WebMediaPlayer()->CurrentPlaybackPosition()`.
        OfficialPlaybackPosition();

        // changes paused to true and fires a simple event named pause at the
        // media element.
        paused_ = true;
        ScheduleNamedEvent(event_type_names::kPause);
        ScheduleRejectPlayPromises(PlayPromiseError::kPaused_EndOfPlayback);
      }
      // Queue a task to fire a simple event named ended at the media element.
      ScheduleNamedEvent(event_type_names::kEnded);
    }
  }
  UpdatePlayState();
}

void HTMLMediaElement::DurationChanged() {
  DVLOG(3) << "durationChanged(" << *this << ")";

  // durationChanged() is triggered by media player.
  CHECK(web_media_player_);
  double new_duration = web_media_player_->Duration();

  // If the duration is changed such that the *current playback position* ends
  // up being greater than the time of the end of the media resource, then the
  // user agent must also seek to the time of the end of the media resource.
  DurationChanged(new_duration, CurrentPlaybackPosition() > new_duration);
}

void HTMLMediaElement::DurationChanged(double duration, bool request_seek) {
  DVLOG(3) << "durationChanged(" << *this << ", " << duration << ", "
           << BoolString(request_seek) << ")";

  // Abort if duration unchanged.
  if (duration_ == duration)
    return;

  DVLOG(3) << "durationChanged(" << *this << ") : " << duration_ << " -> "
           << duration;
  duration_ = duration;
  ScheduleNamedEvent(event_type_names::kDurationchange);

  if (web_media_player_)
    web_media_player_->OnTimeUpdate();

  UpdateLayoutObject();

  if (request_seek)
    Seek(duration);
}

void HTMLMediaElement::RemotePlaybackCompatibilityChanged(const KURL& url,
                                                          bool is_compatible) {
  if (remote_playback_client_) {
    remote_playback_client_->SourceChanged(url, is_compatible);
  }
}

bool HTMLMediaElement::HasSelectedVideoTrack() {
  return video_tracks_ && video_tracks_->selectedIndex() != -1;
}

WebMediaPlayer::TrackId HTMLMediaElement::GetSelectedVideoTrackId() {
  DCHECK(HasSelectedVideoTrack());

  int selected_track_index = video_tracks_->selectedIndex();
  VideoTrack* track =
      video_tracks_->AnonymousIndexedGetter(selected_track_index);
  return track->id();
}

bool HTMLMediaElement::WasAlwaysMuted() {
  return was_always_muted_;
}

// MediaPlayerPresentation methods
void HTMLMediaElement::Repaint() {
  if (cc_layer_)
    cc_layer_->SetNeedsDisplay();

  UpdateLayoutObject();
  if (GetLayoutObject())
    GetLayoutObject()->SetShouldDoFullPaintInvalidation();
}

void HTMLMediaElement::SizeChanged() {
  DVLOG(3) << "sizeChanged(" << *this << ")";

  DCHECK(HasVideo());  // "resize" makes no sense in absence of video.
  if (ready_state_ > kHaveNothing && IsHTMLVideoElement())
    ScheduleNamedEvent(event_type_names::kResize);

  UpdateLayoutObject();
}

WebTimeRanges HTMLMediaElement::BufferedInternal() const {
  if (media_source_attachment_) {
    return media_source_attachment_->BufferedInternal(
        media_source_tracer_.Get());
  }

  if (!web_media_player_)
    return {};

  return web_media_player_->Buffered();
}

TimeRanges* HTMLMediaElement::buffered() const {
  return MakeGarbageCollected<TimeRanges>(BufferedInternal());
}

TimeRanges* HTMLMediaElement::played() {
  if (playing_) {
    double time = currentTime();
    if (time > last_seek_time_)
      AddPlayedRange(last_seek_time_, time);
  }

  if (!played_time_ranges_)
    played_time_ranges_ = MakeGarbageCollected<TimeRanges>();

  return played_time_ranges_->Copy();
}

WebTimeRanges HTMLMediaElement::SeekableInternal() const {
  if (!web_media_player_)
    return {};

  if (media_source_attachment_) {
    return media_source_attachment_->SeekableInternal(
        media_source_tracer_.Get());
  }

  return web_media_player_->Seekable();
}

TimeRanges* HTMLMediaElement::seekable() const {
  return MakeGarbageCollected<TimeRanges>(SeekableInternal());
}

bool HTMLMediaElement::PotentiallyPlaying() const {
  // Once we've reached the metadata state the WebMediaPlayer is ready to accept
  // play state changes.
  return ready_state_ >= kHaveMetadata && CouldPlayIfEnoughData();
}

bool HTMLMediaElement::CouldPlayIfEnoughData() const {
  return !paused() && !EndedPlayback() && !StoppedDueToErrors();
}

bool HTMLMediaElement::EndedPlayback(LoopCondition loop_condition) const {
  // If we have infinite duration, we'll never have played for long enough to
  // have ended playback.
  const double dur = duration();
  if (std::isnan(dur) || dur == std::numeric_limits<double>::infinity())
    return false;

  // 4.8.12.8 Playing the media resource

  // A media element is said to have ended playback when the element's
  // readyState attribute is HAVE_METADATA or greater,
  if (ready_state_ < kHaveMetadata)
    return false;

  DCHECK_EQ(GetDirectionOfPlayback(), kForward);
  if (web_media_player_) {
    return web_media_player_->IsEnded() &&
           (loop_condition == LoopCondition::kIgnored || !Loop() ||
            dur <= std::numeric_limits<double>::epsilon());
  }

  return false;
}

bool HTMLMediaElement::StoppedDueToErrors() const {
  if (ready_state_ >= kHaveMetadata && error_) {
    WebTimeRanges seekable_ranges = SeekableInternal();
    if (!seekable_ranges.Contain(currentTime()))
      return true;
  }

  return false;
}

void HTMLMediaElement::UpdatePlayState(bool pause_speech /* = true */) {
  bool is_playing = web_media_player_ && !web_media_player_->Paused();
  bool should_be_playing = PotentiallyPlaying();

  DVLOG(3) << "updatePlayState(" << *this
           << ") - shouldBePlaying = " << BoolString(should_be_playing)
           << ", isPlaying = " << BoolString(is_playing);

  if (should_be_playing && !muted_)
    was_always_muted_ = false;

  if (should_be_playing) {
    if (!is_playing) {
      // Set rate, muted before calling play in case they were set before the
      // media engine was setup.  The media engine should just stash the rate
      // and muted values since it isn't already playing.
      web_media_player_->SetRate(playbackRate());
      web_media_player_->SetVolume(EffectiveMediaVolume());
      web_media_player_->Play();
      if (::features::IsTextBasedAudioDescriptionEnabled())
        SpeechSynthesis()->Resume();

      // These steps should not be necessary, but if `play()` is called before
      // a source change, we may get into a state where `paused_ == false` and
      // `show_poster_flag_ == true`. My (cassew@google.com) interpretation of
      // the spec is that we should not be playing in this scenario.
      // https://crbug.com/633591
      SetShowPosterFlag(false);
      GetCueTimeline().InvokeTimeMarchesOn();
    }

    StartPlaybackProgressTimer();
    playing_ = true;
  } else {  // Should not be playing right now
    if (is_playing) {
      web_media_player_->Pause();

      if (pause_speech && ::features::IsTextBasedAudioDescriptionEnabled())
        SpeechSynthesis()->Pause();
    }

    playback_progress_timer_.Stop();
    playing_ = false;
    double time = currentTime();
    if (time > last_seek_time_)
      AddPlayedRange(last_seek_time_, time);

    GetCueTimeline().OnPause();
  }

  UpdateLayoutObject();

  if (web_media_player_)
    web_media_player_->OnTimeUpdate();

  ReportCurrentTimeToMediaSource();
  PseudoStateChanged(CSSSelector::kPseudoPaused);
  PseudoStateChanged(CSSSelector::kPseudoPlaying);

  UpdateVideoVisibilityTracker();
}

void HTMLMediaElement::StopPeriodicTimers() {
  progress_event_timer_.Stop();
  playback_progress_timer_.Stop();
  if (lazy_load_intersection_observer_) {
    lazy_load_intersection_observer_->disconnect();
    lazy_load_intersection_observer_ = nullptr;
  }
}

void HTMLMediaElement::
    ClearMediaPlayerAndAudioSourceProviderClientWithoutLocking() {
  GetAudioSourceProvider().SetClient(nullptr);
  if (web_media_player_) {
    audio_source_provider_.Wrap(nullptr);
    web_media_player_.reset();
    // Do not clear `opener_document_` here; new players might still use it.

    // The lifetime of the mojo endpoints are tied to the WebMediaPlayer's, so
    // we need to reset those as well.
    media_player_receiver_set_->Value().Clear();
    media_player_observer_remote_set_->Value().Clear();
  }

  OnWebMediaPlayerCleared();
}

void HTMLMediaElement::ClearMediaPlayer() {
  ForgetResourceSpecificTracks();

  CloseMediaSource();

  CancelDeferredLoad();

  {
    AudioSourceProviderClientLockScope scope(*this);
    ClearMediaPlayerAndAudioSourceProviderClientWithoutLocking();
  }

  StopPeriodicTimers();
  load_timer_.Stop();

  pending_action_flags_ = 0;
  load_state_ = kWaitingForSource;

  if (GetLayoutObject())
    GetLayoutObject()->SetShouldDoFullPaintInvalidation();
}

void HTMLMediaElement::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  if (state == mojom::FrameLifecycleState::kFrozenAutoResumeMedia && playing_) {
    paused_by_context_paused_ = true;
    pause();
    if (web_media_player_) {
      web_media_player_->OnFrozen();
    }
  } else if (state == mojom::FrameLifecycleState::kFrozen && playing_) {
    pause();
    if (web_media_player_) {
      web_media_player_->OnFrozen();
    }
  } else if (state == mojom::FrameLifecycleState::kRunning &&
             paused_by_context_paused_) {
    paused_by_context_paused_ = false;
    Play();
  }
}

void HTMLMediaElement::ContextDestroyed() {
  DVLOG(3) << "contextDestroyed(" << static_cast<void*>(this) << ")";

  // Close the async event queue so that no events are enqueued.
  CancelPendingEventsAndCallbacks();

  // Clear everything in the Media Element
  if (media_source_attachment_)
    media_source_attachment_->OnElementContextDestroyed();
  ClearMediaPlayer();
  ready_state_ = kHaveNothing;
  ready_state_maximum_ = kHaveNothing;
  SetNetworkState(kNetworkEmpty);
  SetShouldDelayLoadEvent(false);
  current_source_node_ = nullptr;
  official_playback_position_ = 0;
  official_playback_position_needs_update_ = true;
  playing_ = false;
  paused_ = true;
  seeking_ = false;
  GetCueTimeline().OnReadyStateReset();

  UpdateLayoutObject();

  StopPeriodicTimers();
  removed_from_document_timer_.Stop();

  UpdateVideoVisibilityTracker();
}

bool HTMLMediaElement::HasPendingActivity() const {
  const auto result = HasPendingActivityInternal();
  // TODO(dalecurtis): Replace c-style casts in followup patch.
  DVLOG(3) << "HasPendingActivity(" << *this << ") = " << result;
  return result;
}

bool HTMLMediaElement::HasPendingActivityInternal() const {
  // The delaying-the-load-event flag is set by resource selection algorithm
  // when looking for a resource to load, before networkState has reached to
  // kNetworkLoading.
  if (should_delay_load_event_)
    return true;

  // When networkState is kNetworkLoading, progress and stalled events may be
  // fired.
  //
  // When connected to a MediaSource, ignore |network_state_|. The rest
  // of this method's logic and the HasPendingActivity() of the various
  // MediaSource API objects more precisely indicate whether or not any pending
  // activity is expected on the group of connected HTMLMediaElement +
  // MediaSource API objects. This lets the group of objects be garbage
  // collected if there is no pending activity nor reachability from a GC root,
  // even while in kNetworkLoading.
  //
  // We use the WebMediaPlayer's network state instead of |network_state_| since
  // it's value is unreliable prior to ready state kHaveMetadata.
  if (!media_source_attachment_) {
    if (!web_media_player_) {
      if (network_state_ == kNetworkLoading)
        return true;
    } else if (web_media_player_->GetNetworkState() ==
               WebMediaPlayer::kNetworkStateLoading) {
      return true;
    }
  }

  {
    // Disable potential updating of playback position, as that will
    // require v8 allocations; not allowed while GCing
    // (hasPendingActivity() is called during a v8 GC.)
    base::AutoReset<bool> scope(&official_playback_position_needs_update_,
                                false);

    // When playing or if playback may continue, timeupdate events may be fired.
    if (CouldPlayIfEnoughData())
      return true;
  }

  // When the seek finishes timeupdate and seeked events will be fired.
  if (seeking_)
    return true;

  // Wait for any pending events to be fired.
  if (async_event_queue_->HasPendingEvents())
    return true;

  return false;
}

bool HTMLMediaElement::IsFullscreen() const {
  return Fullscreen::IsFullscreenElement(*this);
}

cc::Layer* HTMLMediaElement::CcLayer() const {
  return cc_layer_;
}

bool HTMLMediaElement::HasClosedCaptions() const {
  if (!text_tracks_)
    return false;

  for (unsigned i = 0; i < text_tracks_->length(); ++i) {
    if (text_tracks_->AnonymousIndexedGetter(i)->CanBeRendered())
      return true;
  }

  return false;
}

bool HTMLMediaElement::TextTracksVisible() const {
  return text_tracks_visible_;
}

// static
void HTMLMediaElement::AssertShadowRootChildren(ShadowRoot& shadow_root) {
#if DCHECK_IS_ON()
  // There can be up to three children: an interstitial (media remoting or
  // picture in picture), text track container, and media controls. The media
  // controls has to be the last child if present, and has to be the next
  // sibling of the text track container if both present. When present, media
  // remoting interstitial has to be the first child.
  unsigned number_of_children = shadow_root.CountChildren();
  DCHECK_LE(number_of_children, 3u);
  Node* first_child = shadow_root.firstChild();
  Node* last_child = shadow_root.lastChild();
  if (number_of_children == 1) {
    DCHECK(first_child->IsTextTrackContainer() ||
           first_child->IsMediaControls() ||
           first_child->IsMediaRemotingInterstitial() ||
           first_child->IsPictureInPictureInterstitial());
  } else if (number_of_children == 2) {
    DCHECK(first_child->IsTextTrackContainer() ||
           first_child->IsMediaRemotingInterstitial() ||
           first_child->IsPictureInPictureInterstitial());
    DCHECK(last_child->IsTextTrackContainer() || last_child->IsMediaControls());
    if (first_child->IsTextTrackContainer())
      DCHECK(last_child->IsMediaControls());
  } else if (number_of_children == 3) {
    Node* second_child = first_child->nextSibling();
    DCHECK(first_child->IsMediaRemotingInterstitial() ||
           first_child->IsPictureInPictureInterstitial());
    DCHECK(second_child->IsTextTrackContainer());
    DCHECK(last_child->IsMediaControls());
  }
#endif
}

TextTrackContainer& HTMLMediaElement::EnsureTextTrackContainer() {
  UseCounter::Count(GetDocument(), WebFeature::kMediaElementTextTrackContainer);

  ShadowRoot& shadow_root = EnsureUserAgentShadowRoot();
  AssertShadowRootChildren(shadow_root);

  Node* first_child = shadow_root.firstChild();
  if (auto* first_child_text_track = DynamicTo<TextTrackContainer>(first_child))
    return *first_child_text_track;
  Node* to_be_inserted = first_child;

  if (first_child && (first_child->IsMediaRemotingInterstitial() ||
                      first_child->IsPictureInPictureInterstitial())) {
    Node* second_child = first_child->nextSibling();
    if (auto* second_child_text_track =
            DynamicTo<TextTrackContainer>(second_child))
      return *second_child_text_track;
    to_be_inserted = second_child;
  }

  auto* text_track_container = MakeGarbageCollected<TextTrackContainer>(*this);

  // The text track container should be inserted before the media controls,
  // so that they are rendered behind them.
  shadow_root.InsertBefore(text_track_container, to_be_inserted);

  AssertShadowRootChildren(shadow_root);

  return *text_track_container;
}

void HTMLMediaElement::UpdateTextTrackDisplay() {
  DVLOG(3) << "updateTextTrackDisplay(" << *this << ")";

  EnsureTextTrackContainer().UpdateDisplay(
      *this, TextTrackContainer::kDidNotStartExposingControls);
}

SpeechSynthesisBase* HTMLMediaElement::SpeechSynthesis() {
  if (!speech_synthesis_) {
    speech_synthesis_ =
        SpeechSynthesisBase::Create(*(GetDocument().domWindow()));
    speech_synthesis_->SetOnSpeakingCompletedCallback(WTF::BindRepeating(
        &HTMLMediaElement::OnSpeakingCompleted, WrapWeakPersistent(this)));
  }
  return speech_synthesis_.Get();
}

void HTMLMediaElement::MediaControlsDidBecomeVisible() {
  DVLOG(3) << "mediaControlsDidBecomeVisible(" << *this << ")";

  // When the user agent starts exposing a user interface for a video element,
  // the user agent should run the rules for updating the text track rendering
  // of each of the text tracks in the video element's list of text tracks ...
  if (IsHTMLVideoElement() && TextTracksVisible()) {
    EnsureTextTrackContainer().UpdateDisplay(
        *this, TextTrackContainer::kDidStartExposingControls);
  }
}

void HTMLMediaElement::SetTextTrackKindUserPreferenceForAllMediaElements(
    Document* document) {
  auto it = DocumentToElementSetMap().find(document);
  if (it == DocumentToElementSetMap().end())
    return;
  DCHECK(it->value);
  WeakMediaElementSet& elements = *it->value;
  for (const auto& element : elements)
    element->AutomaticTrackSelectionForUpdatedUserPreference();
}

void HTMLMediaElement::AutomaticTrackSelectionForUpdatedUserPreference() {
  if (!text_tracks_ || !text_tracks_->length())
    return;

  MarkCaptionAndSubtitleTracksAsUnconfigured();
  processing_preference_change_ = true;
  text_tracks_visible_ = false;
  HonorUserPreferencesForAutomaticTextTrackSelection();
  processing_preference_change_ = false;

  // If a track is set to 'showing' post performing automatic track selection,
  // set text tracks state to visible to update the CC button and display the
  // track.
  text_tracks_visible_ = text_tracks_->HasShowingTracks();
  UpdateTextTrackDisplay();
}

void HTMLMediaElement::MarkCaptionAndSubtitleTracksAsUnconfigured() {
  if (!text_tracks_)
    return;

  // Mark all tracks as not "configured" so that
  // honorUserPreferencesForAutomaticTextTrackSelection() will reconsider
  // which tracks to display in light of new user preferences (e.g. default
  // tracks should not be displayed if the user has turned off captions and
  // non-default tracks should be displayed based on language preferences if
  // the user has turned captions on).
  for (unsigned i = 0; i < text_tracks_->length(); ++i) {
    TextTrack* text_track = text_tracks_->AnonymousIndexedGetter(i);
    if (text_track->IsVisualKind())
      text_track->SetHasBeenConfigured(false);
  }
}

uint64_t HTMLMediaElement::webkitAudioDecodedByteCount() const {
  if (!web_media_player_)
    return 0;
  return web_media_player_->AudioDecodedByteCount();
}

uint64_t HTMLMediaElement::webkitVideoDecodedByteCount() const {
  if (!web_media_player_)
    return 0;
  return web_media_player_->VideoDecodedByteCount();
}

bool HTMLMediaElement::IsURLAttribute(const Attribute& attribute) const {
  return attribute.GetName() == html_names::kSrcAttr ||
         HTMLElement::IsURLAttribute(attribute);
}

void HTMLMediaElement::SetShouldDelayLoadEvent(bool should_delay) {
  if (should_delay_load_event_ == should_delay)
    return;

  DVLOG(3) << "setShouldDelayLoadEvent(" << *this << ", "
           << BoolString(should_delay) << ")";

  should_delay_load_event_ = should_delay;
  if (should_delay)
    GetDocument().IncrementLoadEventDelayCount();
  else
    GetDocument().DecrementLoadEventDelayCount();
}

MediaControls* HTMLMediaElement::GetMediaControls() const {
  return media_controls_.Get();
}

void HTMLMediaElement::EnsureMediaControls() {
  if (GetMediaControls())
    return;

  ShadowRoot& shadow_root = EnsureUserAgentShadowRoot();
  UseCounterMuteScope scope(*this);
  media_controls_ =
      CoreInitializer::GetInstance().CreateMediaControls(*this, shadow_root);

  // The media controls should be inserted after the text track container,
  // so that they are rendered in front of captions and subtitles. This check
  // is verifying the contract.
  AssertShadowRootChildren(shadow_root);
}

void HTMLMediaElement::UpdateControlsVisibility() {
  if (!isConnected())
    return;

  bool native_controls = ShouldShowControls();

  // When LazyInitializeMediaControls is enabled, initialize the controls only
  // if native controls should be used or if using the cast overlay.
  if (!RuntimeEnabledFeatures::LazyInitializeMediaControlsEnabled() ||
      RuntimeEnabledFeatures::MediaCastOverlayButtonEnabled() ||
      native_controls) {
    EnsureMediaControls();

    // TODO(mlamouri): this doesn't sound needed but the following tests, on
    // Android fails when removed:
    // fullscreen/compositor-touch-hit-rects-fullscreen-video-controls.html
    GetMediaControls()->Reset();
  }

  if (native_controls)
    GetMediaControls()->MaybeShow();
  else if (GetMediaControls())
    GetMediaControls()->Hide();

  if (web_media_player_)
    web_media_player_->OnHasNativeControlsChanged(native_controls);
}

CueTimeline& HTMLMediaElement::GetCueTimeline() {
  if (!cue_timeline_)
    cue_timeline_ = MakeGarbageCollected<CueTimeline>(*this);
  return *cue_timeline_;
}

void HTMLMediaElement::ConfigureTextTrackDisplay() {
  DCHECK(text_tracks_);
  DVLOG(3) << "configureTextTrackDisplay(" << *this << ")";

  if (processing_preference_change_)
    return;

  bool have_visible_text_track = text_tracks_->HasShowingTracks();
  text_tracks_visible_ = have_visible_text_track;

  if (!have_visible_text_track && !GetMediaControls())
    return;

  // Note: The "time marches on" algorithm |CueTimeline::TimeMarchesOn| runs
  // the "rules for updating the text track rendering" (updateTextTrackDisplay)
  // only for "affected tracks", i.e. tracks where the the active cues have
  // changed. This misses cues in tracks that changed mode between hidden and
  // showing. This appears to be a spec bug, which we work around here:
  // https://www.w3.org/Bugs/Public/show_bug.cgi?id=28236
  UpdateTextTrackDisplay();
}

// TODO(srirama.m): Merge it to resetMediaElement if possible and remove it.
void HTMLMediaElement::ResetMediaPlayerAndMediaSource() {
  CloseMediaSource();

  {
    AudioSourceProviderClientLockScope scope(*this);
    ClearMediaPlayerAndAudioSourceProviderClientWithoutLocking();
  }

  if (audio_source_node_)
    GetAudioSourceProvider().SetClient(audio_source_node_);
}

void HTMLMediaElement::SetAudioSourceNode(
    AudioSourceProviderClient* source_node) {
  DCHECK(IsMainThread());
  audio_source_node_ = source_node;

  // No need to lock the |audio_source_node| because it locks itself when
  // setFormat() is invoked.
  GetAudioSourceProvider().SetClient(audio_source_node_);
}

WebMediaPlayer::CorsMode HTMLMediaElement::CorsMode() const {
  const AtomicString& cross_origin_mode =
      FastGetAttribute(html_names::kCrossoriginAttr);
  if (cross_origin_mode.IsNull())
    return WebMediaPlayer::kCorsModeUnspecified;
  if (EqualIgnoringASCIICase(cross_origin_mode, "use-credentials"))
    return WebMediaPlayer::kCorsModeUseCredentials;
  return WebMediaPlayer::kCorsModeAnonymous;
}

void HTMLMediaElement::SetCcLayer(cc::Layer* cc_layer) {
  if (cc_layer == cc_layer_)
    return;

  SetNeedsCompositingUpdate();
  cc_layer_ = cc_layer;
}

void HTMLMediaElement::MediaSourceOpened(
    std::unique_ptr<WebMediaSource> web_media_source) {
  SetShouldDelayLoadEvent(false);
  media_source_attachment_->CompleteAttachingToMediaElement(
      media_source_tracer_, std::move(web_media_source));
}

bool HTMLMediaElement::IsInteractiveContent() const {
  return FastHasAttribute(html_names::kControlsAttr);
}

void HTMLMediaElement::BindMediaPlayerReceiver(
    mojo::PendingAssociatedReceiver<media::mojom::blink::MediaPlayer>
        receiver) {
  media_player_receiver_set_->Value().Add(
      std::move(receiver),
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));
}

void HTMLMediaElement::OnSpeakingCompleted() {
  if (paused())
    Play();
}

void HTMLMediaElement::Trace(Visitor* visitor) const {
  visitor->Trace(audio_source_node_);
  visitor->Trace(speech_synthesis_);
  visitor->Trace(load_timer_);
  visitor->Trace(audio_tracks_timer_);
  visitor->Trace(removed_from_document_timer_);
  visitor->Trace(played_time_ranges_);
  visitor->Trace(async_event_queue_);
  visitor->Trace(error_);
  visitor->Trace(current_source_node_);
  visitor->Trace(next_child_node_to_consider_);
  visitor->Trace(deferred_load_timer_);
  visitor->Trace(media_source_tracer_);
  visitor->Trace(audio_tracks_);
  visitor->Trace(video_tracks_);
  visitor->Trace(cue_timeline_);
  visitor->Trace(text_tracks_);
  visitor->Trace(text_tracks_when_resource_selection_began_);
  visitor->Trace(play_promise_resolvers_);
  visitor->Trace(play_promise_resolve_list_);
  visitor->Trace(play_promise_reject_list_);
  visitor->Trace(audio_source_provider_);
  visitor->Trace(src_object_stream_descriptor_);
  visitor->Trace(src_object_media_source_handle_);
  visitor->Trace(autoplay_policy_);
  visitor->Trace(media_controls_);
  visitor->Trace(controls_list_);
  visitor->Trace(lazy_load_intersection_observer_);
  visitor->Trace(media_player_host_remote_);
  visitor->Trace(media_player_observer_remote_set_);
  visitor->Trace(media_player_receiver_set_);
  visitor->Trace(opener_document_);
  visitor->Trace(opener_context_observer_);
  Supplementable<HTMLMediaElement>::Trace(visitor);
  HTMLElement::Trace(visitor);
  ExecutionContextLifecycleStateObserver::Trace(visitor);
}

void HTMLMediaElement::CreatePlaceholderTracksIfNecessary() {
  // Create a placeholder audio track if the player says it has audio but it
  // didn't explicitly announce the tracks.
  if (HasAudio() && !audioTracks().length()) {
    AddMediaTrack(media::MediaTrack::Cr
```