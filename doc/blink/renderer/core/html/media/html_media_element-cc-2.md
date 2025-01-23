Response:
My thinking process to analyze the provided code snippet goes like this:

1. **Understand the Context:** The initial prompt tells me this is part 3 of 6 of the `HTMLMediaElement.cc` file in the Chromium Blink engine. This immediately tells me the code is responsible for the core behavior of HTML `<audio>` and `<video>` elements.

2. **Identify Key Areas/Concepts:**  I scan the code looking for recurring patterns, keywords, and method names. I see things like:
    * `deferred_load_`: This hints at a mechanism for delaying or managing the loading process.
    * `TextTrack`:  This clearly relates to subtitles, captions, and other text-based tracks.
    * `NetworkState`: This likely manages the current network activity status of the media element.
    * `ReadyState`: This tracks how much data is available and the readiness of the media for playback.
    * `Seek`:  This is the functionality for jumping to different points in the media.
    * Event handling (`ScheduleNamedEvent`): This suggests interaction with the browser's event loop.
    * `MediaError`:  This indicates handling of error conditions.
    * `Play`:  While not explicitly in this snippet, the surrounding code and the context suggest playback management is relevant.

3. **Analyze Individual Functions (and group related ones):** I go through each function, trying to understand its purpose.

    * **Deferred Loading (`DeferLoad`, `CancelDeferredLoad`, `ExecuteDeferredLoad`, `StartDeferredLoad`, `DeferredLoadTimerFired`):**  These functions clearly work together to implement a deferred loading strategy. The comments directly reference the "resource fetch algorithm." I pay attention to the state transitions (`kNotDeferred`, `kWaitingForStopDelayingLoadEventTask`, etc.) and the use of a timer. I recognize this as an optimization technique to avoid unnecessary loading until needed.

    * **Load Type (`GetLoadType`):** This function determines the source of the media (URL, MediaSource, MediaStream), which is fundamental for how the media is handled.

    * **Audio Output Sink (`DidAudioOutputSinkChanged`):** This seems like a way to notify observers about changes in the audio output device, indicating support for routing audio.

    * **Text Track Management (`TextTracksAreReady`, `TextTrackReadyStateChanged`, `TextTrackModeChanged`, `DisableAutomaticTextTrackSelection`):** This block of functions is focused on the lifecycle and rendering of text tracks. I note the interactions with the `StyleEngine` (for rendering) and the logic for determining when tracks are "ready."

    * **Security and Policy (`IsSafeToLoadURL`, `IsMediaDataCorsSameOrigin`):** These functions address security concerns related to loading media from different origins and content security policies.

    * **Progress Events (`StartProgressEventTimer`, `WaitForSourceChange`, `ProgressEventTimerFired`):** These functions control the periodic firing of `progress` events, useful for showing loading indicators. `WaitForSourceChange` is about resetting the state when waiting for a new media source.

    * **Error Handling (`NoneSupported`, `MediaEngineError`, `MediaLoadingFailed`):**  These functions handle various error scenarios that can occur during media loading and playback. They set error codes, fire error events, and update the element's state.

    * **Event Cancellation (`CancelPendingEventsAndCallbacks`):** This is a utility function for cleaning up pending asynchronous operations.

    * **State Updates (`NetworkStateChanged`, `SetNetworkState`, `ChangeNetworkStateFromLoadingToIdle`, `ReadyStateChanged`, `SetReadyState`):**  These functions manage the core state variables of the media element (`networkState_`, `readyState_`). I observe the logic for transitioning between states and the events that are fired as a result.

    * **Poster Image (`SetShowPosterFlag`, `UpdateLayoutObject`):** This deals with displaying a placeholder image before the media loads.

    * **Played Ranges (`AddPlayedRange`):** This function keeps track of the portions of the media that have been played.

    * **Feature Support (`SupportsSave`, `SupportsLoop`):** These functions determine if the media element supports actions like saving or looping. I note the conditions that affect this (e.g., MediaStream, infinite duration).

    * **Preload Handling (`SetIgnorePreloadNone`):** This function seems to override the `preload="none"` attribute to initiate loading if necessary.

    * **Seeking (`Seek`, `FinishSeek`):**  These functions implement the seeking functionality. I see the steps involved in updating the `seeking_` flag, validating the target time, and firing `seeking` and `seeked` events.

    * **Getters (`getReadyState`, `HasVideo`):** Simple accessors for read-only properties.

4. **Identify Relationships with Web Technologies:**  Based on the function names and the context of the file, I can identify the relationships with JavaScript, HTML, and CSS:

    * **JavaScript:** Event firing (`progress`, `suspend`, `error`, `seeking`, `seeked`, `timeupdate`, `durationchange`, `resize`, `loadedmetadata`, `loadeddata`, `canplay`, `canplaythrough`, `play`, `waiting`), properties like `networkState`, `readyState`, `currentTime`, `duration`, methods like `play()`, `pause()`, `seek()`.
    * **HTML:**  Attributes like `src`, `preload`, `autoplay`, the `<source>` element, the `<track>` element.
    * **CSS:**  The rendering of text tracks, the display of the poster image.

5. **Infer Logical Reasoning and Examples:** For functions like `DeferLoad`, I can infer the input (a request to load remote media) and the output (the media loading is paused, a `suspend` event is fired). For error handling, I can imagine scenarios (e.g., invalid URL) and the resulting error events and state changes.

6. **Identify Potential User/Programming Errors:**  I think about common mistakes developers make when working with media:
    * Providing an invalid media URL.
    * Not handling error events.
    * Incorrectly using the `preload` attribute.
    * Expecting media to play immediately without checking `readyState`.

7. **Synthesize the Summary:**  Finally, I combine my understanding of the individual functions and their relationships to summarize the overall functionality of this code snippet. I focus on the core responsibilities: managing the media loading process (including deferring), handling different media sources, managing text tracks, ensuring security, and updating the media element's state and firing events appropriately. I also note the connections to JavaScript, HTML, and CSS.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive and informative summary. The decomposition into smaller parts, the identification of key concepts, and the connection to the broader web platform are crucial for understanding the role of this code within the Chromium browser.
好的，我们来归纳一下这段 `HTMLMediaElement.cc` 代码的功能。

**核心功能归纳：**

这段代码主要负责 **HTML `<audio>` 和 `<video>` 元素加载和管理媒体资源的核心逻辑**。 它涉及了以下几个关键方面：

* **延迟加载 (Deferred Load):**  实现了一种可选的延迟加载机制，用于优化远程媒体资源的加载。它允许在用户交互或特定事件发生后才真正开始加载媒体，避免不必要的网络请求。
* **媒体资源加载流程管理:**  控制媒体资源的获取、网络状态的变更（`NETWORK_IDLE`, `NETWORK_LOADING`, `NETWORK_NO_SOURCE` 等），以及加载过程中可能出现的错误处理。
* **文本轨道 (Text Tracks) 管理:**  负责处理媒体元素的字幕、副标题等文本轨道，包括其加载状态、显示模式以及与渲染引擎的交互。
* **安全性和权限控制:**  检查媒体资源的 URL 是否安全，是否符合同源策略 (CORS)，以及内容安全策略 (CSP) 的限制。
* **进度事件 (Progress Events) 控制:**  管理 `progress` 和 `stalled` 事件的触发，用于向用户反馈媒体加载进度。
* **错误处理:**  捕获并处理媒体加载过程中可能发生的各种错误，例如网络错误、解码错误、不支持的格式等。
* **媒体元素状态管理:**  维护和更新媒体元素的各种状态，例如 `readyState` (媒体数据的就绪状态)、`networkState` (网络状态)、`seeking` (是否正在查找) 等。
* **Seek 操作 (查找):**  实现媒体元素的查找功能，允许用户跳转到媒体流的特定时间点。
* **Poster 图片管理:**  控制媒体元素 poster 图片的显示。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * **事件触发:**  代码中大量使用了 `ScheduleNamedEvent` 来触发各种 JavaScript 事件，例如 `suspend`（暂停加载）、`progress`（加载进度）、`error`（加载错误）、`seeking`（开始查找）、`seeked`（查找完成）、`timeupdate`（播放时间更新）、`durationchange`（媒体时长改变）、`loadedmetadata`（媒体元数据加载完成）、`loadeddata`（首帧数据加载完成）、`canplay`（可以开始播放）、`canplaythrough`（可以完整播放）等。
        * **假设输入:**  JavaScript 调用 `videoElement.play()` 尝试播放视频，但视频尚未完全加载。
        * **代码逻辑:** `HTMLMediaElement` 在加载过程中，会根据数据的就绪程度，逐步将 `readyState` 从 `HAVE_NOTHING` 变为 `HAVE_METADATA`、`HAVE_CURRENT_DATA`、`HAVE_FUTURE_DATA` 直到 `HAVE_ENOUGH_DATA`。在 `readyState` 变化时，代码会触发相应的 `canplay` 或 `canplaythrough` 事件，告知 JavaScript 可以开始或完整播放。
    * **属性更新:** 代码会更新媒体元素的各种属性，这些属性可以通过 JavaScript 访问和修改，例如 `networkState`、`readyState`、`duration` 等。
        * **假设输入:** 媒体资源成功加载并获取到时长信息。
        * **代码逻辑:**  `HTMLMediaElement` 会调用 `SetReadyState` 将 `readyState` 更新到 `kHaveMetadata` 或更高，并调用 `ScheduleNamedEvent` 触发 `durationchange` 事件，同时更新 JavaScript 可访问的 `duration` 属性。
    * **方法调用:**  JavaScript 可以调用媒体元素的方法，例如 `play()`、`pause()`、`seek()`。这段代码中的 `Seek` 函数就响应了 JavaScript 的 `seek()` 调用。
        * **假设输入:**  JavaScript 调用 `videoElement.seek(10)` 跳转到第 10 秒。
        * **代码逻辑:**  `HTMLMediaElement` 的 `Seek` 方法会被调用，它会更新内部状态 `seeking_` 为 `true`，然后调用底层的媒体播放器接口 (`web_media_player_->Seek(time)`) 执行查找操作，并触发 `seeking` 事件。

* **HTML:**
    * **`<source>` 元素处理:** 代码中可以看到对 `<source>` 元素的遍历和处理逻辑，当主 `src` 属性加载失败时，会尝试加载 `<source>` 元素指定的其他媒体资源。
        * **假设输入:** HTML 中包含 `<video>` 元素，并且有多个 `<source>` 子元素，指定了不同格式的视频文件。
        * **代码逻辑:** 如果浏览器不支持第一个 `<source>` 元素的媒体格式，`HTMLMediaElement` 的 `MediaLoadingFailed` 方法会被调用，它会检查是否存在更多的 `<source>` 元素，并尝试加载下一个。
    * **`<track>` 元素处理:** 代码中处理了 `<track>` 元素，用于加载字幕或其他文本轨道。`TextTrackReadyStateChanged` 和 `TextTrackModeChanged` 等方法与 `<track>` 元素的加载状态和显示模式变化相关。

* **CSS:**
    * **文本轨道渲染:** `TextTrackModeChanged` 方法中调用了 `GetDocument().GetStyleEngine().AddTextTrack(track)` 和 `RemoveTextTrack(track)`，这表明代码负责将文本轨道信息传递给渲染引擎，以便 CSS 可以控制字幕的样式和布局。
    * **Poster 图片显示:** `SetShowPosterFlag` 方法会更新内部状态，并调用 `UpdateLayoutObject`，最终影响 CSS 对 poster 图片的显示和隐藏。

**逻辑推理与假设输入/输出：**

* **`DeferLoad` 函数:**
    * **假设输入:**  一个 `<video>` 元素的 `src` 属性指向一个远程视频文件，且浏览器的实现决定采用延迟加载策略。
    * **代码逻辑:**  `DeferLoad` 函数会被调用。它会将网络状态设置为 `NETWORK_IDLE`，触发 `suspend` 事件，启动一个定时器，并将 `deferred_load_state_` 设置为 `kWaitingForStopDelayingLoadEventTask`。
    * **预期输出:** 视频文件不会立即开始下载，浏览器会等待用户交互或其他事件触发 `ExecuteDeferredLoad` 函数。
* **`ExecuteDeferredLoad` 函数:**
    * **假设输入:** 在 `DeferLoad` 被调用后，用户点击了视频的播放按钮。
    * **代码逻辑:**  `ExecuteDeferredLoad` 函数会被调用。它会取消延迟加载定时器，将 `delaying-the-load-event` 标志设置为 `true`，将网络状态设置为 `NETWORK_LOADING`，并开始实际的媒体资源加载 (`StartPlayerLoad`)。
    * **预期输出:** 视频文件开始下载，浏览器会触发 `progress` 事件以显示加载进度。

**用户或编程常见的使用错误举例：**

* **未处理 `error` 事件:** 开发者可能没有监听媒体元素的 `error` 事件，导致在媒体加载失败时，用户无法得到任何提示。
    * **错误场景:**  `<video src="invalid_url.mp4"></video>`  由于 URL 错误，视频加载失败。
    * **后果:**  如果 JavaScript 代码没有监听 `error` 事件，开发者可能无法捕获这个错误，并向用户展示友好的错误信息。
* **错误地使用 `preload="none"`:** 开发者可能设置了 `preload="none"`，但又期望媒体能够立即播放，导致播放前出现短暂的卡顿或加载延迟。
    * **错误场景:** `<video preload="none" src="large_video.mp4" autoplay></video>`
    * **后果:**  尽管设置了 `autoplay`，但由于 `preload="none"`，浏览器可能不会提前加载视频数据，导致在尝试自动播放时需要等待加载。
* **在 `readyState` 不正确时尝试播放或操作媒体:** 开发者可能在 `readyState` 处于 `HAVE_NOTHING` 或 `HAVE_METADATA` 等状态时就尝试调用 `play()` 或修改 `currentTime`，导致意料之外的行为或错误。
    * **错误场景:**
    ```javascript
    videoElement.play(); // 假设此时 readyState 还是 HAVE_NOTHING
    ```
    * **后果:** 播放可能失败，或者浏览器会抛出异常。开发者应该监听 `canplay` 或 `canplaythrough` 事件后再进行播放操作。

**总结这段代码的功能：**

这段 `HTMLMediaElement.cc` 代码片段是 Chromium Blink 引擎中处理 HTML 媒体元素（`<audio>` 和 `<video>`）资源加载和管理的核心部分。它实现了延迟加载、管理加载流程和网络状态、处理文本轨道、保障安全性、控制进度事件、处理错误、维护元素状态、支持 seek 操作以及管理 poster 图片的显示。 这段代码是实现 HTML5 媒体规范的关键组成部分，并与 JavaScript、HTML 和 CSS 紧密协作，共同为用户提供丰富的媒体体验。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_media_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// This implements the "optional" step 4 from the resource fetch algorithm
  // "If mode is remote".
  DCHECK(!deferred_load_timer_.IsActive());
  DCHECK_EQ(deferred_load_state_, kNotDeferred);
  // 1. Set the networkState to NETWORK_IDLE.
  // 2. Queue a task to fire a simple event named suspend at the element.
  ChangeNetworkStateFromLoadingToIdle();
  // 3. Queue a task to set the element's delaying-the-load-event
  // flag to false. This stops delaying the load event.
  deferred_load_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
  // 4. Wait for the task to be run.
  deferred_load_state_ = kWaitingForStopDelayingLoadEventTask;
  // Continued in executeDeferredLoad().
}

void HTMLMediaElement::CancelDeferredLoad() {
  deferred_load_timer_.Stop();
  deferred_load_state_ = kNotDeferred;
}

void HTMLMediaElement::ExecuteDeferredLoad() {
  DCHECK_GE(deferred_load_state_, kWaitingForTrigger);

  // resource fetch algorithm step 4 - continued from deferLoad().

  // 5. Wait for an implementation-defined event (e.g. the user requesting that
  // the media element begin playback).  This is assumed to be whatever 'event'
  // ended up calling this method.
  CancelDeferredLoad();
  // 6. Set the element's delaying-the-load-event flag back to true (this
  // delays the load event again, in case it hasn't been fired yet).
  SetShouldDelayLoadEvent(true);
  // 7. Set the networkState to NETWORK_LOADING.
  SetNetworkState(kNetworkLoading);

  StartProgressEventTimer();

  StartPlayerLoad();
}

void HTMLMediaElement::StartDeferredLoad() {
  if (deferred_load_state_ == kWaitingForTrigger) {
    ExecuteDeferredLoad();
    return;
  }
  if (deferred_load_state_ == kExecuteOnStopDelayingLoadEventTask)
    return;
  DCHECK_EQ(deferred_load_state_, kWaitingForStopDelayingLoadEventTask);
  deferred_load_state_ = kExecuteOnStopDelayingLoadEventTask;
}

void HTMLMediaElement::DeferredLoadTimerFired(TimerBase*) {
  SetShouldDelayLoadEvent(false);

  if (deferred_load_state_ == kExecuteOnStopDelayingLoadEventTask) {
    ExecuteDeferredLoad();
    return;
  }
  DCHECK_EQ(deferred_load_state_, kWaitingForStopDelayingLoadEventTask);
  deferred_load_state_ = kWaitingForTrigger;
}

WebMediaPlayer::LoadType HTMLMediaElement::GetLoadType() const {
  if (media_source_attachment_)
    return WebMediaPlayer::kLoadTypeMediaSource;  // Either via src or srcObject

  if (src_object_stream_descriptor_)
    return WebMediaPlayer::kLoadTypeMediaStream;

  return WebMediaPlayer::kLoadTypeURL;
}

void HTMLMediaElement::DidAudioOutputSinkChanged(
    const String& hashed_device_id) {
  for (auto& observer : media_player_observer_remote_set_->Value())
    observer->OnAudioOutputSinkChanged(hashed_device_id);
}

void HTMLMediaElement::SetMediaPlayerHostForTesting(
    mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayerHost> host) {
  media_player_host_remote_->Value().Bind(
      std::move(host), GetDocument().GetTaskRunner(TaskType::kInternalMedia));
}

bool HTMLMediaElement::TextTracksAreReady() const {
  // 4.8.12.11.1 Text track model
  // ...
  // The text tracks of a media element are ready if all the text tracks whose
  // mode was not in the disabled state when the element's resource selection
  // algorithm last started now have a text track readiness state of loaded or
  // failed to load.
  for (const auto& text_track : text_tracks_when_resource_selection_began_) {
    if (text_track->GetReadinessState() == TextTrack::kLoading ||
        text_track->GetReadinessState() == TextTrack::kNotLoaded)
      return false;
  }

  return true;
}

void HTMLMediaElement::TextTrackReadyStateChanged(TextTrack* track) {
  if (web_media_player_ &&
      text_tracks_when_resource_selection_began_.Contains(track)) {
    if (track->GetReadinessState() != TextTrack::kLoading) {
      SetReadyState(
          static_cast<ReadyState>(web_media_player_->GetReadyState()));
    }
  } else {
    // The track readiness state might have changed as a result of the user
    // clicking the captions button. In this case, a check whether all the
    // resources have failed loading should be done in order to hide the CC
    // button.
    // TODO(mlamouri): when an HTMLTrackElement fails to load, it is not
    // propagated to the TextTrack object in a web exposed fashion. We have to
    // keep relying on a custom glue to the controls while this is taken care
    // of on the web side. See https://crbug.com/669977
    if (GetMediaControls() &&
        track->GetReadinessState() == TextTrack::kFailedToLoad) {
      GetMediaControls()->OnTrackElementFailedToLoad();
    }
  }
}

void HTMLMediaElement::TextTrackModeChanged(TextTrack* track) {
  // Mark this track as "configured" so configureTextTracks won't change the
  // mode again.
  if (IsA<LoadableTextTrack>(track))
    track->SetHasBeenConfigured(true);

  if (track->IsRendered()) {
    GetDocument().GetStyleEngine().AddTextTrack(track);
  } else {
    GetDocument().GetStyleEngine().RemoveTextTrack(track);
  }

  ConfigureTextTrackDisplay();

  DCHECK(textTracks()->Contains(track));
  textTracks()->ScheduleChangeEvent();
}

void HTMLMediaElement::DisableAutomaticTextTrackSelection() {
  should_perform_automatic_track_selection_ = false;
}

bool HTMLMediaElement::IsSafeToLoadURL(const KURL& url,
                                       InvalidURLAction action_if_invalid) {
  if (!url.IsValid()) {
    DVLOG(3) << "isSafeToLoadURL(" << *this << ", " << UrlForLoggingMedia(url)
             << ") -> FALSE because url is invalid";
    return false;
  }

  LocalDOMWindow* window = GetDocument().domWindow();
  if (!window || !window->GetSecurityOrigin()->CanDisplay(url)) {
    if (action_if_invalid == kComplain) {
      GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kSecurity,
          mojom::ConsoleMessageLevel::kError,
          "Not allowed to load local resource: " + url.ElidedString()));
    }
    DVLOG(3) << "isSafeToLoadURL(" << *this << ", " << UrlForLoggingMedia(url)
             << ") -> FALSE rejected by SecurityOrigin";
    return false;
  }

  if (!GetExecutionContext()->GetContentSecurityPolicy()->AllowMediaFromSource(
          url)) {
    DVLOG(3) << "isSafeToLoadURL(" << *this << ", " << UrlForLoggingMedia(url)
             << ") -> rejected by Content Security Policy";
    return false;
  }

  return true;
}

bool HTMLMediaElement::IsMediaDataCorsSameOrigin() const {
  if (!web_media_player_)
    return true;

  const auto network_state = web_media_player_->GetNetworkState();
  if (network_state == WebMediaPlayer::kNetworkStateNetworkError)
    return false;

  return !web_media_player_->WouldTaintOrigin();
}

void HTMLMediaElement::StartProgressEventTimer() {
  if (progress_event_timer_.IsActive())
    return;

  previous_progress_time_ = base::ElapsedTimer();
  // 350ms is not magic, it is in the spec!
  progress_event_timer_.StartRepeating(base::Milliseconds(350));
}

void HTMLMediaElement::WaitForSourceChange() {
  DVLOG(3) << "waitForSourceChange(" << *this << ")";

  StopPeriodicTimers();
  load_state_ = kWaitingForSource;

  // 17 - Waiting: Set the element's networkState attribute to the
  // NETWORK_NO_SOURCE value
  SetNetworkState(kNetworkNoSource);

  // 18 - Set the element's show poster flag to true.
  SetShowPosterFlag(true);

  // 19 - Set the element's delaying-the-load-event flag to false. This stops
  // delaying the load event.
  SetShouldDelayLoadEvent(false);

  UpdateLayoutObject();
}

void HTMLMediaElement::NoneSupported(const String& input_message) {
  DVLOG(3) << "NoneSupported(" << *this << ", message='" << input_message
           << "')";

  StopPeriodicTimers();
  load_state_ = kWaitingForSource;
  current_source_node_ = nullptr;

  String empty_string;
  const String& message = MediaShouldBeOpaque() ? empty_string : input_message;

  // 4.8.12.5
  // The dedicated media source failure steps are the following steps:

  // 1 - Set the error attribute to a new MediaError object whose code attribute
  // is set to MEDIA_ERR_SRC_NOT_SUPPORTED.
  SetError(MakeGarbageCollected<MediaError>(
      MediaError::kMediaErrSrcNotSupported, message));

  // 2 - Forget the media element's media-resource-specific text tracks.
  ForgetResourceSpecificTracks();

  // 3 - Set the element's networkState attribute to the NETWORK_NO_SOURCE
  // value.
  SetNetworkState(kNetworkNoSource);

  // 4 - Set the element's show poster flag to true.
  SetShowPosterFlag(true);

  // 5 - Fire a simple event named error at the media element.
  ScheduleNamedEvent(event_type_names::kError);

  // 6 - Reject pending play promises with NotSupportedError.
  ScheduleRejectPlayPromises(PlayPromiseError::kNotSupported);

  CloseMediaSource();

  // 7 - Set the element's delaying-the-load-event flag to false. This stops
  // delaying the load event.
  SetShouldDelayLoadEvent(false);

  UpdateLayoutObject();
}

void HTMLMediaElement::MediaEngineError(MediaError* err) {
  DCHECK_GE(ready_state_, kHaveMetadata);
  DVLOG(3) << "mediaEngineError(" << *this << ", "
           << static_cast<int>(err->code()) << ")";

  // 1 - The user agent should cancel the fetching process.
  StopPeriodicTimers();
  load_state_ = kWaitingForSource;

  // 2 - Set the error attribute to a new MediaError object whose code attribute
  // is set to MEDIA_ERR_NETWORK/MEDIA_ERR_DECODE.
  SetError(err);

  // 3 - Queue a task to fire a simple event named error at the media element.
  ScheduleNamedEvent(event_type_names::kError);

  // 4 - Set the element's networkState attribute to the NETWORK_IDLE value.
  SetNetworkState(kNetworkIdle);

  // 5 - Set the element's delaying-the-load-event flag to false. This stops
  // delaying the load event.
  SetShouldDelayLoadEvent(false);

  // 6 - Abort the overall resource selection algorithm.
  current_source_node_ = nullptr;
}

void HTMLMediaElement::CancelPendingEventsAndCallbacks() {
  DVLOG(3) << "cancelPendingEventsAndCallbacks(" << *this << ")";
  async_event_queue_->CancelAllEvents();

  for (HTMLSourceElement* source =
           Traversal<HTMLSourceElement>::FirstChild(*this);
       source; source = Traversal<HTMLSourceElement>::NextSibling(*source))
    source->CancelPendingErrorEvent();
}

void HTMLMediaElement::NetworkStateChanged() {
  SetNetworkState(web_media_player_->GetNetworkState());
}

void HTMLMediaElement::MediaLoadingFailed(WebMediaPlayer::NetworkState error,
                                          const String& input_message) {
  DVLOG(3) << "MediaLoadingFailed(" << *this << ", " << int{error}
           << ", message='" << input_message << "')";

  bool should_be_opaque = MediaShouldBeOpaque();
  if (should_be_opaque)
    error = WebMediaPlayer::kNetworkStateNetworkError;
  String empty_string;
  const String& message = should_be_opaque ? empty_string : input_message;

  StopPeriodicTimers();

  // If we failed while trying to load a <source> element, the movie was never
  // parsed, and there are more <source> children, schedule the next one
  if (ready_state_ < kHaveMetadata &&
      load_state_ == kLoadingFromSourceElement) {
    // resource selection algorithm
    // Step 9.Otherwise.9 - Failed with elements: Queue a task, using the DOM
    // manipulation task source, to fire a simple event named error at the
    // candidate element.
    if (current_source_node_) {
      current_source_node_->ScheduleErrorEvent();
    } else {
      DVLOG(3) << "mediaLoadingFailed(" << *this
               << ") - error event not sent, <source> was removed";
    }

    // 9.Otherwise.10 - Asynchronously await a stable state. The synchronous
    // section consists of all the remaining steps of this algorithm until the
    // algorithm says the synchronous section has ended.

    // 9.Otherwise.11 - Forget the media element's media-resource-specific
    // tracks.
    ForgetResourceSpecificTracks();

    if (HavePotentialSourceChild()) {
      DVLOG(3) << "mediaLoadingFailed(" << *this
               << ") - scheduling next <source>";
      ScheduleNextSourceChild();
    } else {
      DVLOG(3) << "mediaLoadingFailed(" << *this
               << ") - no more <source> elements, waiting";
      WaitForSourceChange();
    }

    return;
  }

  if (error == WebMediaPlayer::kNetworkStateNetworkError &&
      ready_state_ >= kHaveMetadata) {
    MediaEngineError(MakeGarbageCollected<MediaError>(
        MediaError::kMediaErrNetwork, message));
  } else if (error == WebMediaPlayer::kNetworkStateDecodeError) {
    MediaEngineError(
        MakeGarbageCollected<MediaError>(MediaError::kMediaErrDecode, message));
  } else if ((error == WebMediaPlayer::kNetworkStateFormatError ||
              error == WebMediaPlayer::kNetworkStateNetworkError) &&
             (load_state_ == kLoadingFromSrcAttr ||
              (load_state_ == kLoadingFromSrcObject &&
               src_object_media_source_handle_))) {
    if (message.empty()) {
      // Generate a more meaningful error message to differentiate the two types
      // of MEDIA_SRC_ERR_NOT_SUPPORTED.
      NoneSupported(BuildElementErrorMessage(
          error == WebMediaPlayer::kNetworkStateFormatError ? "Format error"
                                                            : "Network error"));
    } else {
      NoneSupported(message);
    }
  }

  UpdateLayoutObject();
}

void HTMLMediaElement::SetNetworkState(WebMediaPlayer::NetworkState state) {
  DVLOG(3) << "setNetworkState(" << *this << ", " << static_cast<int>(state)
           << ") - current state is " << int{network_state_};

  if (state == WebMediaPlayer::kNetworkStateEmpty) {
    // Just update the cached state and leave, we can't do anything.
    SetNetworkState(kNetworkEmpty);
    return;
  }

  if (state == WebMediaPlayer::kNetworkStateFormatError ||
      state == WebMediaPlayer::kNetworkStateNetworkError ||
      state == WebMediaPlayer::kNetworkStateDecodeError) {
    MediaLoadingFailed(state, web_media_player_->GetErrorMessage());
    return;
  }

  if (state == WebMediaPlayer::kNetworkStateIdle) {
    if (network_state_ > kNetworkIdle) {
      ChangeNetworkStateFromLoadingToIdle();
    } else {
      SetNetworkState(kNetworkIdle);
    }
  }

  if (state == WebMediaPlayer::kNetworkStateLoading) {
    if (network_state_ < kNetworkLoading || network_state_ == kNetworkNoSource)
      StartProgressEventTimer();
    SetNetworkState(kNetworkLoading);
  }

  if (state == WebMediaPlayer::kNetworkStateLoaded) {
    if (network_state_ != kNetworkIdle)
      ChangeNetworkStateFromLoadingToIdle();
  }
}

void HTMLMediaElement::ChangeNetworkStateFromLoadingToIdle() {
  progress_event_timer_.Stop();

  if (!MediaShouldBeOpaque()) {
    // Schedule one last progress event so we guarantee that at least one is
    // fired for files that load very quickly.
    if (web_media_player_ && web_media_player_->DidLoadingProgress())
      ScheduleNamedEvent(event_type_names::kProgress);
    ScheduleNamedEvent(event_type_names::kSuspend);
    SetNetworkState(kNetworkIdle);
  } else {
    // TODO(dalecurtis): Replace c-style casts in follow up patch.
    DVLOG(1) << __func__ << "(" << *this
             << ") - Deferred network state change to idle for opaque media";
  }
}

void HTMLMediaElement::ReadyStateChanged() {
  SetReadyState(static_cast<ReadyState>(web_media_player_->GetReadyState()));
}

void HTMLMediaElement::SetReadyState(ReadyState state) {
  DVLOG(3) << "setReadyState(" << *this << ", " << int{state}
           << ") - current state is " << int{ready_state_};

  // Set "wasPotentiallyPlaying" BEFORE updating ready_state_,
  // potentiallyPlaying() uses it
  bool was_potentially_playing = PotentiallyPlaying();

  ReadyState old_state = ready_state_;
  ReadyState new_state = state;

  bool tracks_are_ready = TextTracksAreReady();

  if (new_state == old_state && tracks_are_ready_ == tracks_are_ready)
    return;

  tracks_are_ready_ = tracks_are_ready;

  if (tracks_are_ready) {
    ready_state_ = new_state;
  } else {
    // If a media file has text tracks the readyState may not progress beyond
    // kHaveFutureData until the text tracks are ready, regardless of the state
    // of the media file.
    if (new_state <= kHaveMetadata)
      ready_state_ = new_state;
    else
      ready_state_ = kHaveCurrentData;
  }

  // If we're transitioning to / past kHaveMetadata, then cache the final URL.
  if (old_state < kHaveMetadata && new_state >= kHaveMetadata &&
      web_media_player_) {
    current_src_after_redirects_ =
        KURL(web_media_player_->GetSrcAfterRedirects());

    // Sometimes WebMediaPlayer may load a URL from an in memory cache, which
    // skips notification of insecure content. Ensure we always notify the
    // MixedContentChecker of what happened, even if the load was skipped.
    if (LocalFrame* frame = GetDocument().GetFrame()) {
      const KURL& current_src_for_check = current_src_.GetSource();
      // We don't care about the return value here. The MixedContentChecker will
      // internally notify for insecure content if it needs to regardless of
      // what the return value ends up being for this call.
      MixedContentChecker::ShouldBlockFetch(
          frame,
          HasVideo() ? mojom::blink::RequestContextType::VIDEO
                     : mojom::blink::RequestContextType::AUDIO,
          network::mojom::blink::IPAddressSpace::kUnknown,
          current_src_for_check,
          // Strictly speaking, this check is an approximation; a request could
          // have have redirected back to its original URL, for example.
          // However, the redirect status is only used to prevent leaking
          // information cross-origin via CSP reports, so comparing URLs is
          // sufficient for that purpose.
          current_src_after_redirects_ == current_src_for_check
              ? ResourceRequest::RedirectStatus::kNoRedirect
              : ResourceRequest::RedirectStatus::kFollowedRedirect,
          current_src_after_redirects_, /* devtools_id= */ String(),
          ReportingDisposition::kReport,
          GetDocument().Loader()->GetContentSecurityNotifier());
    }

    // Prior to kHaveMetadata |network_state_| may be inaccurate to avoid side
    // channel leaks. This be a no-op if nothing has changed.
    NetworkStateChanged();
  }

  if (new_state > ready_state_maximum_)
    ready_state_maximum_ = new_state;

  if (network_state_ == kNetworkEmpty)
    return;

  if (seeking_) {
    // 4.8.12.9, step 9 note: If the media element was potentially playing
    // immediately before it started seeking, but seeking caused its readyState
    // attribute to change to a value lower than kHaveFutureData, then a waiting
    // will be fired at the element.
    if (was_potentially_playing && ready_state_ < kHaveFutureData)
      ScheduleNamedEvent(event_type_names::kWaiting);

    // 4.8.12.9 steps 12-14
    if (ready_state_ >= kHaveCurrentData)
      FinishSeek();
  } else {
    if (was_potentially_playing && ready_state_ < kHaveFutureData) {
      // Force an update to official playback position. Automatic updates from
      // currentPlaybackPosition() will be blocked while ready_state_ remains
      // < kHaveFutureData. This blocking is desired after 'waiting' has been
      // fired, but its good to update it one final time to accurately reflect
      // media time at the moment we ran out of data to play.
      SetOfficialPlaybackPosition(CurrentPlaybackPosition());

      // 4.8.12.8
      ScheduleTimeupdateEvent(false);
      ScheduleNamedEvent(event_type_names::kWaiting);
    }
  }

  // Once enough of the media data has been fetched to determine the duration of
  // the media resource, its dimensions, and other metadata...
  if (ready_state_ >= kHaveMetadata && old_state < kHaveMetadata) {
    CreatePlaceholderTracksIfNecessary();

    MediaFragmentURIParser fragment_parser(current_src_.GetSource());
    fragment_end_time_ = fragment_parser.EndTime();

    // Set the current playback position and the official playback position to
    // the earliest possible position.
    SetOfficialPlaybackPosition(EarliestPossiblePosition());

    duration_ = web_media_player_->Duration();
    ScheduleNamedEvent(event_type_names::kDurationchange);

    if (IsHTMLVideoElement())
      ScheduleNamedEvent(event_type_names::kResize);
    ScheduleNamedEvent(event_type_names::kLoadedmetadata);

    if (RuntimeEnabledFeatures::AudioVideoTracksEnabled()) {
      Vector<String> default_tracks = fragment_parser.DefaultTracks();
      if (!default_tracks.empty()) {
        AudioTrack* default_audio_track = nullptr;
        VideoTrack* default_video_track = nullptr;
        // http://www.w3.org/2008/WebVideo/Fragments/WD-media-fragments-spec/#error-uri-general
        // Multiple occurrences of the same dimension: only the last valid
        // occurrence of a dimension (e.g., t=10 in #t=2&t=10) is interpreted,
        // all previous occurrences (valid or invalid) SHOULD be ignored by the
        // UA. The track dimension is an exception to this rule: multiple track
        // dimensions are allowed (e.g., #track=1&track=2 selects both tracks 1
        // and 2).
        // Because we can't actually play multiple tracks of the same type, we
        // fall back to only selecting the one which is declared last.
        for (const String& track_id : default_tracks) {
          if (AudioTrack* maybe_track = audioTracks().getTrackById(track_id)) {
            default_audio_track = maybe_track;
          }
          if (VideoTrack* maybe_track = videoTracks().getTrackById(track_id)) {
            default_video_track = maybe_track;
          }
        }
        if (default_audio_track) {
          default_audio_track->setEnabled(true);
        }
        if (default_video_track) {
          default_video_track->setSelected(true);
        }
      }
    }

    bool jumped = false;
    if (default_playback_start_position_ > 0) {
      Seek(default_playback_start_position_);
      jumped = true;
    }
    default_playback_start_position_ = 0;

    double initial_playback_position = fragment_parser.StartTime();
    if (std::isnan(initial_playback_position))
      initial_playback_position = 0;

    if (!jumped && initial_playback_position > 0) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLMediaElementSeekToFragmentStart);
      Seek(initial_playback_position);
      jumped = true;
    }

    UpdateLayoutObject();
  }

  bool is_potentially_playing = PotentiallyPlaying();
  if (ready_state_ >= kHaveCurrentData && old_state < kHaveCurrentData &&
      !have_fired_loaded_data_) {
    // Force an update to official playback position to catch non-zero start
    // times that were not known at kHaveMetadata, but are known now that the
    // first packets have been demuxed.
    SetOfficialPlaybackPosition(CurrentPlaybackPosition());

    have_fired_loaded_data_ = true;
    ScheduleNamedEvent(event_type_names::kLoadeddata);
    SetShouldDelayLoadEvent(false);

    OnLoadFinished();
  }

  if (ready_state_ == kHaveFutureData && old_state <= kHaveCurrentData &&
      tracks_are_ready) {
    ScheduleNamedEvent(event_type_names::kCanplay);
    if (is_potentially_playing)
      ScheduleNotifyPlaying();
  }

  if (ready_state_ == kHaveEnoughData && old_state < kHaveEnoughData &&
      tracks_are_ready) {
    if (old_state <= kHaveCurrentData) {
      ScheduleNamedEvent(event_type_names::kCanplay);
      if (is_potentially_playing)
        ScheduleNotifyPlaying();
    }

    if (autoplay_policy_->RequestAutoplayByAttribute()) {
      paused_ = false;
      SetShowPosterFlag(false);
      GetCueTimeline().InvokeTimeMarchesOn();
      ScheduleNamedEvent(event_type_names::kPlay);
      ScheduleNotifyPlaying();
      can_autoplay_ = false;
    }

    ScheduleNamedEvent(event_type_names::kCanplaythrough);
  }

  UpdatePlayState();
}

void HTMLMediaElement::SetShowPosterFlag(bool value) {
  DVLOG(3) << "SetShowPosterFlag(" << *this << ", " << value
           << ") - current state is " << show_poster_flag_;

  if (value == show_poster_flag_)
    return;

  show_poster_flag_ = value;
  UpdateLayoutObject();
}

void HTMLMediaElement::UpdateLayoutObject() {
  if (GetLayoutObject())
    GetLayoutObject()->UpdateFromElement();
}

void HTMLMediaElement::ProgressEventTimerFired() {
  // The spec doesn't require to dispatch the "progress" or "stalled" events
  // when the resource fetch mode is "local".
  // https://html.spec.whatwg.org/multipage/media.html#concept-media-load-resource
  // The mode is "local" for these sources:
  //
  // MediaStream: The timer is stopped below to prevent the "progress" event
  // from being dispatched more than once. It is dispatched once to match
  // Safari's behavior, even though that's not required by the spec.
  //
  // MediaSource: The "stalled" event is not dispatched but a conscious decision
  // was made to periodically dispatch the "progress" event to allow updates to
  // buffering UIs. Therefore, the timer is not stopped below.
  // https://groups.google.com/a/chromium.org/g/media-dev/c/Y8ITyIFmUC0/m/avBYOy_UFwAJ
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream) {
    progress_event_timer_.Stop();
  }

  if (network_state_ != kNetworkLoading) {
    return;
  }

  // If this is an cross-origin request, and we haven't discovered whether
  // the media is actually playable yet, don't fire any progress events as
  // those may let the page know information about the resource that it's
  // not supposed to know.
  if (MediaShouldBeOpaque()) {
    return;
  }

  DCHECK(previous_progress_time_);

  if (web_media_player_ && web_media_player_->DidLoadingProgress()) {
    ScheduleNamedEvent(event_type_names::kProgress);
    previous_progress_time_ = base::ElapsedTimer();
    sent_stalled_event_ = false;
    UpdateLayoutObject();
  } else if (!media_source_attachment_ &&
             previous_progress_time_->Elapsed() >
                 kStalledNotificationInterval &&
             !sent_stalled_event_) {
    // Note the !media_source_attachment_ condition above. The 'stalled' event
    // is not fired when using MSE. MSE's resource is considered 'local' (we
    // don't manage the download - the app does), so the HTML5 spec text around
    // 'stalled' does not apply. See discussion in https://crbug.com/517240 We
    // also don't need to take any action wrt delaying-the-load-event.
    // MediaSource disables the delayed load when first attached.
    ScheduleNamedEvent(event_type_names::kStalled);
    sent_stalled_event_ = true;
    SetShouldDelayLoadEvent(false);
  }
}

void HTMLMediaElement::AddPlayedRange(double start, double end) {
  DVLOG(3) << "addPlayedRange(" << *this << ", " << start << ", " << end << ")";
  if (!played_time_ranges_)
    played_time_ranges_ = MakeGarbageCollected<TimeRanges>();
  played_time_ranges_->Add(start, end);
}

bool HTMLMediaElement::SupportsSave() const {
  // Check if download is disabled per settings.
  if (GetDocument().GetSettings() &&
      GetDocument().GetSettings()->GetHideDownloadUI()) {
    return false;
  }

  // Get the URL that we'll use for downloading.
  const KURL url = downloadURL();

  // URLs that lead to nowhere are ignored.
  if (url.IsNull() || url.IsEmpty())
    return false;

  // If we have no source, we can't download.
  if (network_state_ == kNetworkEmpty || network_state_ == kNetworkNoSource)
    return false;

  // It is not useful to offer a save feature on local files.
  if (url.IsLocalFile())
    return false;

  // MediaStream can't be downloaded.
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return false;

  // MediaSource can't be downloaded.
  if (HasMediaSource())
    return false;

  // HLS stream shouldn't have a download button.
  if (IsHLSURL(url))
    return false;

  // Infinite streams don't have a clear end at which to finish the download.
  if (duration() == std::numeric_limits<double>::infinity())
    return false;

  return true;
}

bool HTMLMediaElement::SupportsLoop() const {
  // MediaStream can't be looped.
  if (GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return false;

  // Infinite streams don't have a clear end at which to loop.
  if (duration() == std::numeric_limits<double>::infinity())
    return false;

  return true;
}

void HTMLMediaElement::SetIgnorePreloadNone() {
  DVLOG(3) << "setIgnorePreloadNone(" << *this << ")";
  ignore_preload_none_ = true;
  SetPlayerPreload();
}

void HTMLMediaElement::Seek(double time) {
  DVLOG(2) << "seek(" << *this << ", " << time << ")";

  // 1 - Set the media element's show poster flag to false.
  SetShowPosterFlag(false);

  // 2 - If the media element's readyState is HAVE_NOTHING, abort these steps.
  // FIXME: remove web_media_player_ check once we figure out how
  // web_media_player_ is going out of sync with readystate.
  // web_media_player_ is cleared but readystate is not set to HAVE_NOTHING.
  if (!web_media_player_ || ready_state_ == kHaveNothing)
    return;

  // Ignore preload none and start load if necessary.
  SetIgnorePreloadNone();

  // Get the current time before setting seeking_, last_seek_time_ is returned
  // once it is set.
  double now = currentTime();

  // 3 - If the element's seeking IDL attribute is true, then another instance
  // of this algorithm is already running. Abort that other instance of the
  // algorithm without waiting for the step that it is running to complete.
  // Nothing specific to be done here.

  // 4 - Set the seeking IDL attribute to true.
  // The flag will be cleared when the engine tells us the time has actually
  // changed.
  seeking_ = true;

  // 6 - If the new playback position is later than the end of the media
  // resource, then let it be the end of the media resource instead.
  time = std::min(time, duration());

  // 7 - If the new playback position is less than the earliest possible
  // position, let it be that position instead.
  time = std::max(time, EarliestPossiblePosition());

  // Ask the media engine for the time value in the movie's time scale before
  // comparing with current time. This is necessary because if the seek time is
  // not equal to currentTime but the delta is less than the movie's time scale,
  // we will ask the media engine to "seek" to the current movie time, which may
  // be a noop and not generate a timechanged callback. This means seeking_
  // will never be cleared and we will never fire a 'seeked' event.
  double media_time = web_media_player_->MediaTimeForTimeValue(time);
  if (time != media_time) {
    DVLOG(3) << "seek(" << *this << ", " << time
             << ") - media timeline equivalent is " << media_time;
    time = media_time;
  }

  // 8 - If the (possibly now changed) new playback position is not in one of
  // the ranges given in the seekable attribute, then let it be the position in
  // one of the ranges given in the seekable attribute that is the nearest to
  // the new playback position. ... If there are no ranges given in the seekable
  // attribute then set the seeking IDL attribute to false and abort these
  // steps.
  WebTimeRanges seekable_ranges = SeekableInternal();

  if (seekable_ranges.empty()) {
    seeking_ = false;
    return;
  }
  time = seekable_ranges.Nearest(time, now);

  if (playing_ && last_seek_time_ < now)
    AddPlayedRange(last_seek_time_, now);

  last_seek_time_ = time;

  // 10 - Queue a task to fire a simple event named seeking at the element.
  ScheduleNamedEvent(event_type_names::kSeeking);

  // 11 - Set the current playback position to the given new playback position.
  web_media_player_->Seek(time);
  web_media_player_->OnTimeUpdate();

  // 14-17 are handled, if necessary, when the engine signals a readystate
  // change or otherwise satisfies seek completion and signals a time change.
}

void HTMLMediaElement::FinishSeek() {
  DVLOG(3) << "finishSeek(" << *this << ")";

  // 14 - Set the seeking IDL attribute to false.
  seeking_ = false;

  // Force an update to officialPlaybackPosition. Periodic updates generally
  // handle this, but may be skipped paused or waiting for data.
  SetOfficialPlaybackPosition(CurrentPlaybackPosition());

  // 15 - Run the time marches on steps.
  GetCueTimeline().InvokeTimeMarchesOn();

  // 16 - Queue a task to fire a simple event named timeupdate at the element.
  ScheduleTimeupdateEvent(false);

  // 17 - Queue a task to fire a simple event named seeked at the element.
  ScheduleNamedEvent(event_type_names::kSeeked);
}

HTMLMediaElement::ReadyState HTMLMediaElement::getReadyState() const {
  return ready_state_;
}

bool HTMLMediaElement::HasVideo() const {
  return web_media_player_ && web_media_player_->HasVideo();
}
```