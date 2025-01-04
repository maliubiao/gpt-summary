Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The core request is to analyze the provided C++ code snippet from `html_media_element.cc` and explain its functionality, relating it to web technologies (JavaScript, HTML, CSS) where applicable, providing examples, and summarizing its purpose within the larger file. The "part 4 of 6" implies this is a section of a larger piece of functionality.

2. **Initial Code Scan and Keyword Identification:** I first read through the code, identifying key terms, function names, and data members. This helps me get a general sense of what the code is doing. I notice things like:
    * `HasAudio`, `IsEncrypted`, `seeking` - basic state checks.
    * `EarliestPossiblePosition`, `CurrentPlaybackPosition`, `OfficialPlaybackPosition` - related to time management.
    * `currentTime`, `setCurrentTime`, `duration` - core media properties.
    * `paused`, `defaultPlaybackRate`, `playbackRate` - playback controls.
    * `ended` - playback completion status.
    * `Autoplay`, `preload` - attributes related to loading behavior.
    * `playForBindings`, `Play`, `PlayInternal`, `pause`, `PauseInternal` - playback initiation and pausing logic, including promises.
    * `volume`, `muted` - audio controls.
    * `audioTracks`, `videoTracks`, `textTracks` - managing different media track types.
    * `addTextTrack`, `DidAddTrackElement`, `DidRemoveTrackElement` - handling text tracks from `<track>` elements.
    * `SelectNextSourceChild` - logic for choosing the correct media source from `<source>` elements.

3. **Group Functionality:**  I start grouping the identified keywords and functions into logical categories. This helps organize the analysis:
    * **Basic Information:**  Audio presence, encryption status, seeking state.
    * **Playback Position and Time:**  Different ways of tracking the current playback time (earliest, current, official).
    * **Core Media Properties:** Current time, duration, paused state.
    * **Playback Rate:** Default and current playback speed.
    * **Playback Control:** Starting and stopping playback (with promise handling), looping.
    * **Loading and Autoplay:** Managing preloading and autoplay behavior.
    * **Audio Control:** Volume and mute status.
    * **Media Tracks:** Handling audio, video, and text tracks.
    * **Source Selection:**  Logic for choosing the appropriate media source.

4. **Analyze Each Group and Function:**  I then analyze the code within each group more deeply. For each function or block of code, I consider:
    * **Purpose:** What is this code trying to achieve?
    * **Inputs and Outputs:** What data does it take in (even implicitly), and what does it return or modify?
    * **Relation to Web Technologies:** How does this relate to HTML attributes, JavaScript APIs, and CSS styling (though less direct in this specific code)?
    * **Logic and Decisions:** What conditions or checks are being made?
    * **Potential Issues and Errors:** What common mistakes might developers make when interacting with this functionality (even indirectly through the browser's API)?

5. **Connect to Web Technologies (HTML, JavaScript, CSS):**  This is a crucial part. I look for direct connections:
    * **HTML Attributes:**  Many of the C++ functions directly correspond to HTML attributes like `autoplay`, `preload`, `controls`, `loop`, `muted`, `volume`, and the `<source>` and `<track>` elements.
    * **JavaScript APIs:**  The C++ code implements the underlying logic for JavaScript APIs like `play()`, `pause()`, `currentTime`, `duration`, `playbackRate`, `defaultPlaybackRate`, `volume`, `muted`, `addTextTrack()`, and the `audioTracks`, `videoTracks`, and `textTracks` properties. The promise handling in `playForBindings` is also a key connection.
    * **CSS:**  The connection to CSS is less direct here but exists in how the browser might visually represent controls or handle styling related to media elements.

6. **Provide Examples:** Concrete examples make the explanation clearer. I think of common scenarios and how the C++ code would behave in those situations. This involves considering user actions and the resulting behavior.

7. **Consider Assumptions and Logic:** Where the code makes decisions (e.g., about preloading or autoplay), I try to identify the underlying logic and any assumptions being made. For example, the logic for `EffectivePreloadType` considers the `autoplay` attribute and autoplay policies.

8. **Identify User/Programming Errors:**  I think about common mistakes developers might make when using the related JavaScript APIs or HTML attributes. For instance, setting an invalid `playbackRate`, or not handling the promise returned by `play()`.

9. **Summarize Functionality:**  Finally, I synthesize the analysis into a concise summary that captures the main purpose of the code section. I emphasize the core responsibilities and the types of operations it handles. Given the "part 4 of 6" instruction, I aim for a summary that reflects a cohesive section of the overall media element implementation.

10. **Review and Refine:** I reread my analysis, ensuring clarity, accuracy, and completeness. I check that I've addressed all parts of the prompt and that the examples and explanations are easy to understand.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive explanation that addresses all the requirements of the prompt. The "part 4 of 6" instruction reinforces the need to focus on the functionality present within this specific snippet and its contribution to the larger `HTMLMediaElement` class.
这是 `blink/renderer/core/html/media/html_media_element.cc` 文件的第 4 部分，主要负责 **媒体元素的播放控制、状态查询、属性设置以及媒体轨道管理** 等核心功能。

**主要功能归纳:**

* **播放状态管理:**
    * 查询和设置播放状态 (播放/暂停): `paused()`, `Play()`, `Pause()`, `PlayInternal()`, `PauseInternal()`.
    * 查询是否播放结束: `ended()`.
    * 查询是否正在跳转: `seeking()`.
* **播放位置管理:**
    * 获取当前播放位置: `currentTime()`, `CurrentPlaybackPosition()`, `OfficialPlaybackPosition()`.
    * 设置当前播放位置: `setCurrentTime()`,  内部使用 `Seek()`。
    * 获取最早可能的播放位置: `EarliestPossiblePosition()`.
* **播放速率管理:**
    * 获取和设置默认播放速率: `defaultPlaybackRate()`, `setDefaultPlaybackRate()`.
    * 获取和设置当前播放速率: `playbackRate()`, `setPlaybackRate()`.
    * 获取播放方向: `GetDirectionOfPlayback()`.
* **加载和预加载控制:**
    * 查询和设置预加载属性: `preload()`, `setPreload()`, `PreloadType()`, `EffectivePreloadType()`.
    * 查询是否自动播放: `Autoplay()`.
* **音频控制:**
    * 查询和设置音量: `volume()`, `setVolume()`.
    * 查询和设置静音状态: `muted()`, `setMuted()`.
    * 获取有效音量（考虑静音）: `EffectiveMediaVolume()`.
* **媒体轨道管理:**
    * 获取音频轨道列表: `audioTracks()`, 并处理音频轨道变化事件 (`AudioTrackChanged`, `AudioTracksTimerFired`).
    * 获取视频轨道列表: `videoTracks()`, 并处理选择的视频轨道变化事件 (`SelectedVideoTrackChanged`).
    * 添加和移除媒体轨道 (来自底层媒体播放器): `AddMediaTrack()`, `RemoveMediaTrack()`, `ForgetResourceSpecificTracks()`.
    * 添加文本轨道: `addTextTrack()`.
    * 处理 `<track>` 元素的添加和移除: `DidAddTrackElement()`, `DidRemoveTrackElement()`, 并进行自动文本轨道选择 (`HonorUserPreferencesForAutomaticTextTrackSelection()`).
* **其他属性和功能:**
    * 查询是否具有音频: `HasAudio()`.
    * 查询是否加密: `IsEncrypted()`.
    * 获取媒体时长: `duration()`.
    * 查询和设置是否循环播放: `Loop()`, `SetLoop()`.
    * 查询和设置是否保持音高: `preservesPitch()`, `setPreservesPitch()`.
    * 查询和设置延迟提示: `latencyHint()`, `setLatencyHint()`.
    * 控制原生全屏播放: `FlingingStarted()`, `FlingingStopped()`.
    * 关闭 MediaSource: `CloseMediaSource()`.
    * 控制是否显示原生控件: `ShouldShowControls()`, `ShouldShowAllControls()`, `controlsList()`, `ControlsListInternal()`, `SetUserWantsControlsVisible()`, `UserWantsControlsVisible()`.
* **定时器和事件:**
    * 使用定时器触发 `timeupdate` 事件: `StartPlaybackProgressTimer()`, `PlaybackProgressTimerFired()`, `ScheduleTimeupdateEvent()`.
    * 触发 `play` 和 `pause` 事件: 在 `PlayInternal()` 和 `PauseInternal()` 中调用 `ScheduleNamedEvent()`.
* **媒体源选择:**
    * 选择下一个有效的 `<source>` 子元素: `SelectNextSourceChild()`, `HavePotentialSourceChild()`.

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 这个文件中的 C++ 代码实现了 HTMLMediaElement 接口的底层逻辑，这些逻辑可以直接通过 JavaScript API 进行访问和控制。
    * **举例:**  在 JavaScript 中调用 `videoElement.play()` 会最终调用到 C++ 的 `HTMLMediaElement::Play()` 方法。
    * **举例:**  JavaScript 中设置 `videoElement.currentTime = 10;` 会调用到 C++ 的 `HTMLMediaElement::setCurrentTime(10)`.
    * **举例:**  `videoElement.playbackRate` 和 `videoElement.defaultPlaybackRate` 属性的读写操作对应着 C++ 中 `playbackRate()`/`setPlaybackRate()` 和 `defaultPlaybackRate()`/`setDefaultPlaybackRate()` 方法。
    * **举例:**  `videoElement.audioTracks`, `videoElement.videoTracks`, `videoElement.textTracks` 属性分别对应着 C++ 中的 `audioTracks()`, `videoTracks()`, `textTracks()` 方法，以及相关的轨道管理逻辑。
    * **举例:**  `videoElement.addTextTrack('captions', 'English', 'en')` 会调用到 C++ 的 `HTMLMediaElement::addTextTrack()` 方法。
    * **举例:**  `videoElement.play().then(() => { console.log('播放成功'); }).catch(error => { console.error('播放失败', error); });`  与 C++ 中 `playForBindings()` 中 Promise 的处理逻辑相关。

* **HTML:**  HTML 的 `<video>` 和 `<audio>` 标签的属性直接映射到这个 C++ 文件中的一些成员变量和方法。
    * **举例:**  HTML 中设置 `<video autoplay>` 会影响 C++ 中 `Autoplay()` 方法的返回值。
    * **举例:**  HTML 中设置 `<video preload="metadata">` 会影响 C++ 中 `PreloadType()` 和 `EffectivePreloadType()` 的返回值。
    * **举例:**  HTML 中设置 `<video controls>` 会影响 C++ 中 `ShouldShowControls()` 的返回值，从而决定是否显示原生控件。
    * **举例:**  HTML 中的 `<source>` 元素会被 C++ 中的 `SelectNextSourceChild()` 方法处理，用于选择合适的媒体资源。
    * **举例:**  HTML 中的 `<track>` 元素会被 C++ 中的 `DidAddTrackElement()` 和 `DidRemoveTrackElement()` 方法处理，用于管理文本轨道。
    * **举例:**  HTML 中设置 `<video loop>` 会影响 C++ 中 `Loop()` 方法的返回值。
    * **举例:**  HTML 中设置 `<video muted>` 和 `<video volume="0.5">` 会分别影响 C++ 中 `muted()` 和 `volume()` 以及 `setMuted()` 和 `setVolume()` 的行为。

* **CSS:**  CSS 可以用来样式化媒体元素，但这个 C++ 文件本身不直接处理 CSS。不过，CSS 的某些特性可能与媒体元素的行为有关。
    * **举例:**  CSS 可以隐藏原生控件，但 C++ 中的逻辑仍然决定了是否 *应该* 显示控件。
    * **举例:**  CSS 的 `:paused` 和 `:playing` 伪类可以根据媒体元素的播放状态应用不同的样式，而这个状态是由 C++ 代码管理的。

**逻辑推理及假设输入与输出:**

* **假设输入:**  一个 `<video>` 元素，没有设置 `autoplay` 属性，`preload` 属性设置为 "auto"。用户点击了播放按钮。
* **输出:**
    1. JavaScript 调用 `videoElement.play()`。
    2. C++ 的 `HTMLMediaElement::Play()` 被调用。
    3. 由于没有 `autoplay` 属性，`autoplay_policy_->RequestPlay()` 可能允许播放（取决于用户的浏览器设置和权限）。
    4. `PlayInternal()` 被调用。
    5. 如果媒体资源尚未加载，可能会触发资源选择算法。
    6. `paused_` 标志位被设置为 `false`。
    7. 触发 `play` 事件。
    8. 如果媒体数据已准备好，可能会触发 `playing` 事件。
    9. 播放开始。

* **假设输入:**  一个正在播放的 `<video>` 元素，用户将 `playbackRate` 设置为 2.0。
* **输出:**
    1. JavaScript 调用 `videoElement.playbackRate = 2.0;`
    2. C++ 的 `HTMLMediaElement::setPlaybackRate(2.0, exception_state)` 被调用。
    3. 检查播放速率是否有效。
    4. `playback_rate_` 被设置为 2.0。
    5. 触发 `ratechange` 事件。
    6. 如果底层媒体播放器存在，调用 `web_media_player_->SetRate(2.0)`。
    7. 播放速度变为两倍。

**用户或编程常见的使用错误举例:**

* **在 `readyState` 为 `kHaveNothing` 时设置 `currentTime`:** 用户可能会尝试在媒体元素尚未加载任何数据时设置播放位置。C++ 代码会先将该时间设置为 `default_playback_start_position_`，直到媒体加载后才会真正进行 seek 操作。
* **设置超出范围的 `volume` 值:**  用户可能会尝试将 `volume` 设置为大于 1 或小于 0 的值。C++ 代码会抛出 `IndexSizeError` 异常。
* **假设 `play()` 方法总是同步返回:** `play()` 方法返回一个 Promise，表示播放操作的最终结果。用户可能会错误地假设 `play()` 会立即开始播放，而没有处理 Promise 的 resolve 或 reject。
* **不理解 `preload` 属性的影响:** 用户可能不理解 `preload` 属性的不同值 (none, metadata, auto) 对资源加载行为的影响，导致不必要的网络请求或播放延迟。
* **在自动播放被阻止时没有处理 Promise 的 rejection:** 如果浏览器的自动播放策略阻止了播放，`play()` 方法返回的 Promise 会被 reject。用户需要捕获这个 rejection 并进行相应的处理，例如显示一个播放按钮。

总而言之，这个代码片段是 HTMLMediaElement 实现的核心部分，负责管理媒体的播放状态、时间控制、属性设置以及媒体轨道。它与 JavaScript、HTML 紧密相关，是实现 Web 页面媒体功能的基础。理解这部分代码的功能有助于开发者更好地理解和使用 HTML5 的媒体 API。

Prompt: 
```
这是目录为blink/renderer/core/html/media/html_media_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""


bool HTMLMediaElement::HasAudio() const {
  return web_media_player_ && web_media_player_->HasAudio();
}

bool HTMLMediaElement::IsEncrypted() const {
  return is_encrypted_media_;
}

bool HTMLMediaElement::seeking() const {
  return seeking_;
}

// https://www.w3.org/TR/html51/semantics-embedded-content.html#earliest-possible-position
// The earliest possible position is not explicitly exposed in the API; it
// corresponds to the start time of the first range in the seekable attribute’s
// TimeRanges object, if any, or the current playback position otherwise.
double HTMLMediaElement::EarliestPossiblePosition() const {
  WebTimeRanges seekable_ranges = SeekableInternal();
  if (!seekable_ranges.empty())
    return seekable_ranges.front().start;

  return CurrentPlaybackPosition();
}

double HTMLMediaElement::CurrentPlaybackPosition() const {
  // "Official" playback position won't take updates from "current" playback
  // position until ready_state_ > kHaveMetadata, but other callers (e.g.
  // pauseInternal) may still request currentPlaybackPosition at any time.
  // From spec: "Media elements have a current playback position, which must
  // initially (i.e., in the absence of media data) be zero seconds."
  if (ready_state_ == kHaveNothing)
    return 0;

  if (web_media_player_)
    return web_media_player_->CurrentTime();

  if (ready_state_ >= kHaveMetadata) {
    DVLOG(3) << __func__ << " readyState = " << ready_state_
             << " but no webMediaPlayer to provide currentPlaybackPosition";
  }

  return 0;
}

double HTMLMediaElement::OfficialPlaybackPosition() const {
  // Hold updates to official playback position while paused or waiting for more
  // data. The underlying media player may continue to make small advances in
  // currentTime (e.g. as samples in the last rendered audio buffer are played
  // played out), but advancing currentTime while paused/waiting sends a mixed
  // signal about the state of playback.
  bool waiting_for_data = ready_state_ <= kHaveCurrentData;
  if (official_playback_position_needs_update_ && !paused_ &&
      !waiting_for_data) {
    SetOfficialPlaybackPosition(CurrentPlaybackPosition());
  }

#if LOG_OFFICIAL_TIME_STATUS
  static const double kMinCachedDeltaForWarning = 0.01;
  double delta =
      std::abs(official_playback_position_ - CurrentPlaybackPosition());
  if (delta > kMinCachedDeltaForWarning) {
    DVLOG(3) << "CurrentTime(" << (void*)this << ") - WARNING, cached time is "
             << delta << "seconds off of media time when paused/waiting";
  }
#endif

  return official_playback_position_;
}

void HTMLMediaElement::SetOfficialPlaybackPosition(double position) const {
#if LOG_OFFICIAL_TIME_STATUS
  DVLOG(3) << "SetOfficialPlaybackPosition(" << (void*)this
           << ") was:" << official_playback_position_ << " now:" << position;
#endif

  // Internal player position may advance slightly beyond duration because
  // many files use imprecise duration. Clamp official position to duration when
  // known. Duration may be unknown when readyState < HAVE_METADATA.
  official_playback_position_ =
      std::isnan(duration()) ? position : std::min(duration(), position);

  if (official_playback_position_ != position) {
    DVLOG(3) << "setOfficialPlaybackPosition(" << *this
             << ") position:" << position
             << " truncated to duration:" << official_playback_position_;
  }

  // Once set, official playback position should hold steady until the next
  // stable state. We approximate this by using a microtask to mark the
  // need for an update after the current (micro)task has completed. When
  // needed, the update is applied in the next call to
  // officialPlaybackPosition().
  official_playback_position_needs_update_ = false;
  GetDocument().GetAgent().event_loop()->EnqueueMicrotask(
      WTF::BindOnce(&HTMLMediaElement::RequireOfficialPlaybackPositionUpdate,
                    WrapWeakPersistent(this)));
}

void HTMLMediaElement::RequireOfficialPlaybackPositionUpdate() const {
  official_playback_position_needs_update_ = true;
}

double HTMLMediaElement::currentTime() const {
  if (default_playback_start_position_)
    return default_playback_start_position_;

  if (seeking_) {
    DVLOG(3) << "currentTime(" << *this << ") - seeking, returning "
             << last_seek_time_;
    return last_seek_time_;
  }

  return OfficialPlaybackPosition();
}

void HTMLMediaElement::setCurrentTime(double time) {
  // If the media element's readyState is kHaveNothing, then set the default
  // playback start position to that time.
  if (ready_state_ == kHaveNothing) {
    default_playback_start_position_ = time;
  } else {
    Seek(time);
  }

  ReportCurrentTimeToMediaSource();
}

double HTMLMediaElement::duration() const {
  return duration_;
}

bool HTMLMediaElement::paused() const {
  return paused_;
}

double HTMLMediaElement::defaultPlaybackRate() const {
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return 1.0;
  return default_playback_rate_;
}

void HTMLMediaElement::setDefaultPlaybackRate(double rate) {
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return;

  if (default_playback_rate_ == rate || !IsValidPlaybackRate(rate))
    return;

  default_playback_rate_ = rate;
  ScheduleNamedEvent(event_type_names::kRatechange);
}

double HTMLMediaElement::playbackRate() const {
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return 1.0;
  return playback_rate_;
}

void HTMLMediaElement::setPlaybackRate(double rate,
                                       ExceptionState& exception_state) {
  DVLOG(3) << "setPlaybackRate(" << *this << ", " << rate << ")";
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return;

  if (!IsValidPlaybackRate(rate)) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kHTMLMediaElementMediaPlaybackRateOutOfRange);

    // When the proposed playbackRate is unsupported, throw a NotSupportedError
    // DOMException and don't update the value.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The provided playback rate (" + String::Number(rate) +
            ") is not in the " + "supported playback range.");

    // Do not update |playback_rate_|.
    return;
  }

  if (playback_rate_ != rate) {
    playback_rate_ = rate;
    ScheduleNamedEvent(event_type_names::kRatechange);
  }

  // FIXME: remove web_media_player_ check once we figure out how
  // web_media_player_ is going out of sync with readystate.
  // web_media_player_ is cleared but readystate is not set to kHaveNothing.
  if (web_media_player_) {
    if (PotentiallyPlaying())
      web_media_player_->SetRate(playbackRate());

    web_media_player_->OnTimeUpdate();
  }

  if (cue_timeline_ && PotentiallyPlaying())
    cue_timeline_->OnPlaybackRateUpdated();
}

HTMLMediaElement::DirectionOfPlayback HTMLMediaElement::GetDirectionOfPlayback()
    const {
  return playback_rate_ >= 0 ? kForward : kBackward;
}

bool HTMLMediaElement::ended() const {
  // 4.8.12.8 Playing the media resource
  // The ended attribute must return true if the media element has ended
  // playback and the direction of playback is forwards, and false otherwise.
  return EndedPlayback() && GetDirectionOfPlayback() == kForward;
}

bool HTMLMediaElement::Autoplay() const {
  return FastHasAttribute(html_names::kAutoplayAttr);
}

String HTMLMediaElement::preload() const {
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return PreloadTypeToString(WebMediaPlayer::kPreloadNone);
  return PreloadTypeToString(PreloadType());
}

void HTMLMediaElement::setPreload(const AtomicString& preload) {
  DVLOG(2) << "setPreload(" << *this << ", " << preload << ")";
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return;
  setAttribute(html_names::kPreloadAttr, preload);
}

WebMediaPlayer::Preload HTMLMediaElement::PreloadType() const {
  const AtomicString& preload = FastGetAttribute(html_names::kPreloadAttr);
  if (EqualIgnoringASCIICase(preload, "none")) {
    UseCounter::Count(GetDocument(), WebFeature::kHTMLMediaElementPreloadNone);
    return WebMediaPlayer::kPreloadNone;
  }

  if (EqualIgnoringASCIICase(preload, "metadata")) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kHTMLMediaElementPreloadMetadata);
    return WebMediaPlayer::kPreloadMetaData;
  }

  // Force preload to 'metadata' on cellular connections.
  if (GetNetworkStateNotifier().IsCellularConnectionType()) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kHTMLMediaElementPreloadForcedMetadata);
    return WebMediaPlayer::kPreloadMetaData;
  }

  // Per HTML spec, "The empty string ... maps to the Automatic state."
  // https://html.spec.whatwg.org/C/#attr-media-preload
  if (EqualIgnoringASCIICase(preload, "auto") ||
      EqualIgnoringASCIICase(preload, "")) {
    UseCounter::Count(GetDocument(), WebFeature::kHTMLMediaElementPreloadAuto);
    return WebMediaPlayer::kPreloadAuto;
  }

  // "The attribute's missing value default is user-agent defined, though the
  // Metadata state is suggested as a compromise between reducing server load
  // and providing an optimal user experience."

  // The spec does not define an invalid value default:
  // https://www.w3.org/Bugs/Public/show_bug.cgi?id=28950
  UseCounter::Count(GetDocument(), WebFeature::kHTMLMediaElementPreloadDefault);
  return WebMediaPlayer::kPreloadMetaData;
}

String HTMLMediaElement::EffectivePreload() const {
  return PreloadTypeToString(EffectivePreloadType());
}

WebMediaPlayer::Preload HTMLMediaElement::EffectivePreloadType() const {
  if (Autoplay() && !autoplay_policy_->IsGestureNeededForPlayback())
    return WebMediaPlayer::kPreloadAuto;

  WebMediaPlayer::Preload preload = PreloadType();
  if (ignore_preload_none_ && preload == WebMediaPlayer::kPreloadNone)
    return WebMediaPlayer::kPreloadMetaData;

  return preload;
}

ScriptPromise<IDLUndefined> HTMLMediaElement::playForBindings(
    ScriptState* script_state) {
  // We have to share the same logic for internal and external callers. The
  // internal callers do not want to receive a Promise back but when ::play()
  // is called, |play_promise_resolvers_| needs to be populated. What this code
  // does is to populate |play_promise_resolvers_| before calling ::play() and
  // remove the Promise if ::play() failed.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  play_promise_resolvers_.push_back(resolver);

  std::optional<DOMExceptionCode> code = Play();
  if (code) {
    DCHECK(!play_promise_resolvers_.empty());
    play_promise_resolvers_.pop_back();

    String message;
    switch (code.value()) {
      case DOMExceptionCode::kNotAllowedError:
        message = autoplay_policy_->GetPlayErrorMessage();
        break;
      case DOMExceptionCode::kNotSupportedError:
        message = "The element has no supported sources.";
        break;
      default:
        NOTREACHED();
    }
    resolver->Reject(MakeGarbageCollected<DOMException>(code.value(), message));
    return promise;
  }

  return promise;
}

std::optional<DOMExceptionCode> HTMLMediaElement::Play() {
  DVLOG(2) << "play(" << *this << ")";

  std::optional<DOMExceptionCode> exception_code =
      autoplay_policy_->RequestPlay();

  if (exception_code == DOMExceptionCode::kNotAllowedError) {
    // If we're already playing, then this play would do nothing anyway.
    // Call playInternal to handle scheduling the promise resolution.
    if (!paused_) {
      PlayInternal();
      return std::nullopt;
    }
    return exception_code;
  }

  autoplay_policy_->StopAutoplayMutedWhenVisible();

  if (error_ && error_->code() == MediaError::kMediaErrSrcNotSupported)
    return DOMExceptionCode::kNotSupportedError;

  DCHECK(!exception_code.has_value());

  PlayInternal();

  return std::nullopt;
}

void HTMLMediaElement::PlayInternal() {
  DVLOG(3) << "playInternal(" << *this << ")";

  if (web_media_player_) {
    web_media_player_->SetWasPlayedWithUserActivationAndHighMediaEngagement(
        LocalFrame::HasTransientUserActivation(GetDocument().GetFrame()) &&
        AutoplayPolicy::DocumentHasHighMediaEngagement(GetDocument()));
  }

  // Playback aborts any lazy loading.
  if (lazy_load_intersection_observer_) {
    lazy_load_intersection_observer_->disconnect();
    lazy_load_intersection_observer_ = nullptr;
  }

  // 4.8.12.8. Playing the media resource
  if (network_state_ == kNetworkEmpty)
    InvokeResourceSelectionAlgorithm();

  // Generally "ended" and "looping" are exclusive. Here, the loop attribute
  // is ignored to seek back to start in case loop was set after playback
  // ended. See http://crbug.com/364442
  if (EndedPlayback(LoopCondition::kIgnored))
    Seek(0);

  if (paused_) {
    paused_ = false;
    SetShowPosterFlag(false);
    GetCueTimeline().InvokeTimeMarchesOn();
    ScheduleNamedEvent(event_type_names::kPlay);

    if (ready_state_ <= kHaveCurrentData)
      ScheduleNamedEvent(event_type_names::kWaiting);
    else if (ready_state_ >= kHaveFutureData)
      ScheduleNotifyPlaying();
  } else if (ready_state_ >= kHaveFutureData) {
    ScheduleResolvePlayPromises();
  }

  can_autoplay_ = false;

  OnPlay();

  SetIgnorePreloadNone();
  UpdatePlayState();
}

void HTMLMediaElement::pause() {
  DVLOG(2) << "pause(" << *this << ")";

  // When updating pause, be sure to update PauseToLetDescriptionFinish().
  autoplay_policy_->StopAutoplayMutedWhenVisible();
  PauseInternal(PlayPromiseError::kPaused_PauseCalled);
}

void HTMLMediaElement::PauseToLetDescriptionFinish() {
  DVLOG(2) << "pauseExceptSpeech(" << *this << ")";

  autoplay_policy_->StopAutoplayMutedWhenVisible();

  // Passing in pause_speech as false to pause everything except the speech.
  PauseInternal(PlayPromiseError::kPaused_PauseCalled, false);
}

void HTMLMediaElement::PauseInternal(PlayPromiseError code,
                                     bool pause_speech /* = true */) {
  DVLOG(3) << "pauseInternal(" << *this << ")";

  if (network_state_ == kNetworkEmpty)
    InvokeResourceSelectionAlgorithm();

  can_autoplay_ = false;

  if (!paused_) {
    paused_ = true;
    ScheduleTimeupdateEvent(false);
    ScheduleNamedEvent(event_type_names::kPause);

    // Force an update to official playback position. Automatic updates from
    // currentPlaybackPosition() will be blocked while paused_ = true. This
    // blocking is desired while paused, but its good to update it one final
    // time to accurately reflect movie time at the moment we paused.
    SetOfficialPlaybackPosition(CurrentPlaybackPosition());

    ScheduleRejectPlayPromises(code);
  }

  UpdatePlayState(pause_speech);
}

bool HTMLMediaElement::preservesPitch() const {
  return preserves_pitch_;
}

void HTMLMediaElement::setPreservesPitch(bool preserves_pitch) {
  preserves_pitch_ = preserves_pitch;

  if (web_media_player_)
    web_media_player_->SetPreservesPitch(preserves_pitch_);
}

double HTMLMediaElement::latencyHint() const {
  // Parse error will fallback to std::numeric_limits<double>::quiet_NaN()
  double seconds = GetFloatingPointAttribute(html_names::kLatencyhintAttr);

  // Return NaN for invalid values.
  if (!std::isfinite(seconds) || seconds < 0)
    return std::numeric_limits<double>::quiet_NaN();

  return seconds;
}

void HTMLMediaElement::setLatencyHint(double seconds) {
  SetFloatingPointAttribute(html_names::kLatencyhintAttr, seconds);
}

void HTMLMediaElement::FlingingStarted() {
  if (web_media_player_)
    web_media_player_->FlingingStarted();
}

void HTMLMediaElement::FlingingStopped() {
  if (web_media_player_)
    web_media_player_->FlingingStopped();
}

void HTMLMediaElement::CloseMediaSource() {
  if (!media_source_attachment_)
    return;

  media_source_attachment_->Close(media_source_tracer_);
  media_source_attachment_.reset();
  media_source_tracer_ = nullptr;
}

bool HTMLMediaElement::Loop() const {
  return FastHasAttribute(html_names::kLoopAttr);
}

void HTMLMediaElement::SetLoop(bool b) {
  DVLOG(3) << "setLoop(" << *this << ", " << BoolString(b) << ")";
  SetBooleanAttribute(html_names::kLoopAttr, b);
}

bool HTMLMediaElement::ShouldShowControls() const {
  // If the document is not active, then we should not show controls.
  if (!GetDocument().IsActive()) {
    return false;
  }

  Settings* settings = GetDocument().GetSettings();
  if (settings && !settings->GetMediaControlsEnabled()) {
    return false;
  }

  // If the user has explicitly shown or hidden the controls, then force that
  // choice.
  if (user_wants_controls_visible_.has_value()) {
    return *user_wants_controls_visible_;
  }

  if (FastHasAttribute(html_names::kControlsAttr) || IsFullscreen()) {
    return true;
  }

  ExecutionContext* context = GetExecutionContext();
  if (context && !context->CanExecuteScripts(kNotAboutToExecuteScript)) {
    return true;
  }
  return false;
}

bool HTMLMediaElement::ShouldShowAllControls() const {
  // If the user has explicitly shown or hidden the controls, then force that
  // choice. Otherwise returns whether controls should be shown and no controls
  // are meant to be hidden.
  return user_wants_controls_visible_.value_or(
      ShouldShowControls() && !ControlsListInternal()->CanShowAllControls());
}

DOMTokenList* HTMLMediaElement::controlsList() const {
  return controls_list_.Get();
}

HTMLMediaElementControlsList* HTMLMediaElement::ControlsListInternal() const {
  return controls_list_.Get();
}

double HTMLMediaElement::volume() const {
  return volume_;
}

void HTMLMediaElement::setVolume(double vol, ExceptionState& exception_state) {
  DVLOG(2) << "setVolume(" << *this << ", " << vol << ")";

  if (volume_ == vol)
    return;

  if (RuntimeEnabledFeatures::MediaElementVolumeGreaterThanOneEnabled()) {
    if (vol < 0.0f) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kIndexSizeError,
          ExceptionMessages::IndexExceedsMinimumBound("volume", vol, 0.0));
      return;
    }
  } else if (vol < 0.0f || vol > 1.0f) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexOutsideRange(
            "volume", vol, 0.0, ExceptionMessages::kInclusiveBound, 1.0,
            ExceptionMessages::kInclusiveBound));
    return;
  }

  volume_ = vol;

  ScheduleNamedEvent(event_type_names::kVolumechange);

  // If it setting volume to audible and AutoplayPolicy doesn't want the
  // playback to continue, pause the playback.
  if (EffectiveMediaVolume() && !autoplay_policy_->RequestAutoplayUnmute())
    pause();

  // If playback was not paused by the autoplay policy and got audible, the
  // element is marked as being allowed to play unmuted.
  if (EffectiveMediaVolume() && PotentiallyPlaying())
    was_always_muted_ = false;

  if (web_media_player_)
    web_media_player_->SetVolume(EffectiveMediaVolume());

  autoplay_policy_->StopAutoplayMutedWhenVisible();
}

bool HTMLMediaElement::muted() const {
  return muted_;
}

void HTMLMediaElement::setMuted(bool muted) {
  DVLOG(2) << "setMuted(" << *this << ", " << BoolString(muted) << ")";

  if (muted_ == muted)
    return;

  muted_ = muted;

  ScheduleNamedEvent(event_type_names::kVolumechange);

  // If it is unmute and AutoplayPolicy doesn't want the playback to continue,
  // pause the playback.
  if (EffectiveMediaVolume() && !autoplay_policy_->RequestAutoplayUnmute())
    pause();

  // If playback was not paused by the autoplay policy and got unmuted, the
  // element is marked as being allowed to play unmuted.
  if (EffectiveMediaVolume() && PotentiallyPlaying())
    was_always_muted_ = false;

  // This is called at the end to make sure the WebMediaPlayer has the right
  // information.
  if (web_media_player_)
    web_media_player_->SetVolume(EffectiveMediaVolume());

  autoplay_policy_->StopAutoplayMutedWhenVisible();
}

void HTMLMediaElement::SetUserWantsControlsVisible(bool visible) {
  user_wants_controls_visible_ = visible;
  UpdateControlsVisibility();
}

bool HTMLMediaElement::UserWantsControlsVisible() const {
  return user_wants_controls_visible_.value_or(false);
}

double HTMLMediaElement::EffectiveMediaVolume() const {
  if (muted_)
    return 0;

  return volume_;
}

// The spec says to fire periodic timeupdate events (those sent while playing)
// every "15 to 250ms", we choose the slowest frequency
static const base::TimeDelta kMaxTimeupdateEventFrequency =
    base::Milliseconds(250);

void HTMLMediaElement::StartPlaybackProgressTimer() {
  if (playback_progress_timer_.IsActive())
    return;

  previous_progress_time_ = base::ElapsedTimer();
  playback_progress_timer_.StartRepeating(kMaxTimeupdateEventFrequency);
}

void HTMLMediaElement::PlaybackProgressTimerFired() {
  if (!std::isnan(fragment_end_time_) && currentTime() >= fragment_end_time_ &&
      GetDirectionOfPlayback() == kForward) {
    fragment_end_time_ = std::numeric_limits<double>::quiet_NaN();
    if (!paused_) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLMediaElementPauseAtFragmentEnd);
      // changes paused to true and fires a simple event named pause at the
      // media element.
      PauseInternal(PlayPromiseError::kPaused_EndOfPlayback);
    }
  }

  if (!seeking_)
    ScheduleTimeupdateEvent(true);

  // Playback progress is chosen here for simplicity as a proxy for a good
  // periodic time to also update the attached MediaSource, if any, with our
  // currentTime so that it can continue to have a "recent media time".
  ReportCurrentTimeToMediaSource();
}

void HTMLMediaElement::ScheduleTimeupdateEvent(bool periodic_event) {
  if (web_media_player_)
    web_media_player_->OnTimeUpdate();

  // Per spec, consult current playback position to check for changing time.
  double media_time = CurrentPlaybackPosition();
  bool media_time_has_progressed =
      std::isnan(last_time_update_event_media_time_)
          ? media_time != 0
          : media_time != last_time_update_event_media_time_;

  if (periodic_event && !media_time_has_progressed)
    return;

  ScheduleNamedEvent(event_type_names::kTimeupdate);

  last_time_update_event_media_time_ = media_time;

  // Restart the timer to ensure periodic event fires 250ms from _this_ event.
  if (!periodic_event && playback_progress_timer_.IsActive()) {
    playback_progress_timer_.Stop();
    playback_progress_timer_.StartRepeating(kMaxTimeupdateEventFrequency);
  }
}

void HTMLMediaElement::TogglePlayState() {
  if (paused())
    Play();
  else
    pause();
}

AudioTrackList& HTMLMediaElement::audioTracks() {
  return *audio_tracks_;
}

void HTMLMediaElement::AudioTrackChanged(AudioTrack* track) {
  DVLOG(3) << "audioTrackChanged(" << *this
           << ") trackId= " << String(track->id())
           << " enabled=" << BoolString(track->enabled())
           << " exclusive=" << BoolString(track->IsExclusive());

  if (track->enabled()) {
    audioTracks().TrackEnabled(track->id(), track->IsExclusive());
  }

  audioTracks().ScheduleChangeEvent();

  if (media_source_attachment_)
    media_source_attachment_->OnTrackChanged(media_source_tracer_, track);

  if (!audio_tracks_timer_.IsActive())
    audio_tracks_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void HTMLMediaElement::AudioTracksTimerFired(TimerBase*) {
  Vector<WebMediaPlayer::TrackId> enabled_track_ids;
  for (unsigned i = 0; i < audioTracks().length(); ++i) {
    AudioTrack* track = audioTracks().AnonymousIndexedGetter(i);
    if (track->enabled())
      enabled_track_ids.push_back(track->id());
  }

  web_media_player_->EnabledAudioTracksChanged(enabled_track_ids);
}

VideoTrackList& HTMLMediaElement::videoTracks() {
  return *video_tracks_;
}

void HTMLMediaElement::SelectedVideoTrackChanged(VideoTrack* track) {
  DVLOG(3) << "selectedVideoTrackChanged(" << *this << ") selectedTrackId="
           << (track->selected() ? String(track->id()) : "none");

  if (track->selected())
    videoTracks().TrackSelected(track->id());

  videoTracks().ScheduleChangeEvent();

  if (media_source_attachment_)
    media_source_attachment_->OnTrackChanged(media_source_tracer_, track);

  if (track->selected()) {
    web_media_player_->SelectedVideoTrackChanged(track->id());
  } else {
    web_media_player_->SelectedVideoTrackChanged(std::nullopt);
  }
}

void HTMLMediaElement::AddMediaTrack(const media::MediaTrack& track) {
  switch (track.type()) {
    case media::MediaTrack::Type::kVideo: {
      bool enabled = track.enabled() && videoTracks().selectedIndex() == -1;
      videoTracks().Add(MakeGarbageCollected<VideoTrack>(
          String::FromUTF8(track.track_id().value()),
          WebString::FromUTF8(track.kind().value()),
          WebString::FromUTF8(track.label().value()),
          WebString::FromUTF8(track.language().value()), enabled));
      break;
    }
    case media::MediaTrack::Type::kAudio: {
      audioTracks().Add(MakeGarbageCollected<AudioTrack>(
          String::FromUTF8(track.track_id().value()),
          WebString::FromUTF8(track.kind().value()),
          WebString::FromUTF8(track.label().value()),
          WebString::FromUTF8(track.language().value()), track.enabled(),
          track.exclusive()));
      break;
    }
  }
}

void HTMLMediaElement::RemoveMediaTrack(const media::MediaTrack& track) {
  switch (track.type()) {
    case media::MediaTrack::Type::kVideo: {
      videoTracks().Remove(String::FromUTF8(track.track_id().value()));
      break;
    }
    case media::MediaTrack::Type::kAudio: {
      audioTracks().Remove(String::FromUTF8(track.track_id().value()));
      break;
    }
  }
}

void HTMLMediaElement::ForgetResourceSpecificTracks() {
  audio_tracks_->RemoveAll();
  video_tracks_->RemoveAll();

  audio_tracks_timer_.Stop();
}

TextTrack* HTMLMediaElement::addTextTrack(const V8TextTrackKind& kind,
                                          const AtomicString& label,
                                          const AtomicString& language,
                                          ExceptionState& exception_state) {
  // https://html.spec.whatwg.org/C/#dom-media-addtexttrack

  // The addTextTrack(kind, label, language) method of media elements, when
  // invoked, must run the following steps:

  // 1. Create a new TextTrack object.
  // 2. Create a new text track corresponding to the new object, and set its
  //    text track kind to kind, its text track label to label, its text
  //    track language to language, ..., and its text track list of cues to
  //    an empty list.
  auto* text_track =
      MakeGarbageCollected<TextTrack>(kind, label, language, *this);
  //    ..., its text track readiness state to the text track loaded state, ...
  text_track->SetReadinessState(TextTrack::kLoaded);

  // 3. Add the new text track to the media element's list of text tracks.
  // 4. Queue a task to fire a trusted event with the name addtrack, that
  //    does not bubble and is not cancelable, and that uses the TrackEvent
  //    interface, with the track attribute initialised to the new text
  //    track's TextTrack object, at the media element's textTracks
  //    attribute's TextTrackList object.
  textTracks()->Append(text_track);

  // Note: Due to side effects when changing track parameters, we have to
  // first append the track to the text track list.
  // FIXME: Since setMode() will cause a 'change' event to be queued on the
  // same task source as the 'addtrack' event (see above), the order is
  // wrong. (The 'change' event shouldn't be fired at all in this case...)

  // ..., its text track mode to the text track hidden mode, ...
  text_track->SetModeEnum(TextTrackMode::kHidden);

  // 5. Return the new TextTrack object.
  return text_track;
}

TextTrackList* HTMLMediaElement::textTracks() {
  if (!text_tracks_) {
    UseCounter::Count(GetDocument(), WebFeature::kMediaElementTextTrackList);
    text_tracks_ = MakeGarbageCollected<TextTrackList>(this);
  }

  return text_tracks_.Get();
}

void HTMLMediaElement::DidAddTrackElement(HTMLTrackElement* track_element) {
  // 4.8.12.11.3 Sourcing out-of-band text tracks
  // When a track element's parent element changes and the new parent is a media
  // element, then the user agent must add the track element's corresponding
  // text track to the media element's list of text tracks ... [continues in
  // TextTrackList::append]
  TextTrack* text_track = track_element->track();
  if (!text_track)
    return;

  textTracks()->Append(text_track);

  // Do not schedule the track loading until parsing finishes so we don't start
  // before all tracks in the markup have been added.
  if (IsFinishedParsingChildren())
    ScheduleTextTrackResourceLoad();
}

void HTMLMediaElement::DidRemoveTrackElement(HTMLTrackElement* track_element) {
  KURL url = track_element->GetNonEmptyURLAttribute(html_names::kSrcAttr);
  DVLOG(3) << "didRemoveTrackElement(" << *this << ") - 'src' is "
           << UrlForLoggingMedia(url);

  TextTrack* text_track = track_element->track();
  if (!text_track)
    return;

  text_track->SetHasBeenConfigured(false);

  if (!text_tracks_)
    return;

  // 4.8.12.11.3 Sourcing out-of-band text tracks
  // When a track element's parent element changes and the old parent was a
  // media element, then the user agent must remove the track element's
  // corresponding text track from the media element's list of text tracks.
  text_tracks_->Remove(text_track);

  wtf_size_t index =
      text_tracks_when_resource_selection_began_.Find(text_track);
  if (index != kNotFound)
    text_tracks_when_resource_selection_began_.EraseAt(index);
}

void HTMLMediaElement::HonorUserPreferencesForAutomaticTextTrackSelection() {
  if (!text_tracks_ || !text_tracks_->length())
    return;

  if (!should_perform_automatic_track_selection_)
    return;

  AutomaticTrackSelection::Configuration configuration;
  if (processing_preference_change_)
    configuration.disable_currently_enabled_tracks = true;
  if (text_tracks_visible_)
    configuration.force_enable_subtitle_or_caption_track = true;

  Settings* settings = GetDocument().GetSettings();
  if (settings) {
    configuration.text_track_kind_user_preference =
        settings->GetTextTrackKindUserPreference();
  }

  AutomaticTrackSelection track_selection(configuration);
  track_selection.Perform(*text_tracks_);
}

bool HTMLMediaElement::HavePotentialSourceChild() {
  // Stash the current <source> node and next nodes so we can restore them after
  // checking to see there is another potential.
  HTMLSourceElement* current_source_node = current_source_node_;
  Node* next_node = next_child_node_to_consider_;

  KURL next_url = SelectNextSourceChild(nullptr, kDoNothing);

  current_source_node_ = current_source_node;
  next_child_node_to_consider_ = next_node;

  return next_url.IsValid();
}

KURL HTMLMediaElement::SelectNextSourceChild(
    String* content_type,
    InvalidURLAction action_if_invalid) {
  // Don't log if this was just called to find out if there are any valid
  // <source> elements.
  bool should_log = action_if_invalid != kDoNothing;
  if (should_log)
    DVLOG(3) << "selectNextSourceChild(" << *this << ")";

  if (!next_child_node_to_consider_) {
    if (should_log) {
      DVLOG(3) << "selectNextSourceChild(" << *this << ") -> 0x0000, \"\"";
    }
    return KURL();
  }

  KURL media_url;
  Node* node;
  HTMLSourceElement* source = nullptr;
  String type;
  bool looking_for_start_node = next_child_node_to_consider_ != nullptr;
  bool can_use_source_element = false;

  NodeVector potential_source_nodes;
  GetChildNodes(*this, potential_source_nodes);

  for (unsigned i = 0;
       !can_use_source_element && i < potential_source_nodes.size(); ++i) {
    node = potential_source_nodes[i].Get();
    if (looking_for_start_node && next_child_node_to_consider_ != node)
      continue;
    looking_for_start_node = false;

    source = DynamicTo<HTMLSourceElement>(node);
    if (!source || node->parentNode() != this) {
      continue;
    }

    // 2. If candidate does not have a src attribute, or if its src
    // attribute's value is the empty string ... jump down to the failed
    // step below
    const AtomicString& src_value =
        source->FastGetAttribute(html_names::kSrcAttr);
    if (should_log) {
      DVLOG(3) << "selectNextSourceChild(" << *this << ") - 'src' is "
               << UrlForLoggingMedia(media_url);
    }
    if (src_value.empty()) {
      goto checkAgain;
    }

    // 3. If candidate has a media attribute whose value does not match the
    // environment, then end the synchronous section, and jump down to the
    // failed with elemen
"""


```