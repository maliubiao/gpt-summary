Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code, which is a part of the Chromium Blink rendering engine, specifically for media controls. The request asks for:
    * Listing its functions.
    * Identifying relationships with JavaScript, HTML, and CSS.
    * Providing examples for these relationships.
    * Explaining logical reasoning with hypothetical inputs and outputs.
    * Illustrating common usage errors.
    * Describing user interaction leading to this code.
    * Summarizing its overall functionality.

2. **Initial Code Scan (High-Level):**  The code contains numerous methods with names like `OnVolumeChange`, `OnTimeUpdate`, `OnPlay`, etc. This strongly suggests that this class (`MediaControlsImpl`) is responsible for handling events related to media playback and updating the visual representation of the media controls. The presence of member variables like `play_button_`, `timeline_`, `volume_slider_`, etc., reinforces this idea.

3. **Categorizing Functionality (First Pass):** Go through each method and try to group them based on their apparent purpose. Some obvious categories emerge:
    * **Event Handlers:** Methods starting with `On...` (e.g., `OnVolumeChange`, `OnPlay`, `OnSeeking`). These react to media events.
    * **Visibility/Display Control:**  Methods related to showing and hiding controls (e.g., `MaybeShow`, `MakeOpaque`, `MakeTransparent`, `StartHideMediaControlsTimer`, `ResetHideMediaControlsTimer`).
    * **State Updates:**  Methods that change the state of the controls (e.g., `UpdatePlayState`, `UpdateCSSClassFromState`, `UpdateSizingCSSClass`).
    * **Component Interaction:**  Methods interacting with sub-components like buttons and sliders (e.g., `SetIsWanted`, `SetVolume`, `OpenOverflowMenu`).
    * **Sizing and Layout:** Methods dealing with control arrangement (e.g., `NotifyElementSizeChanged`, `ComputeWhichControlsFit`).
    * **Fullscreen:** Methods related to fullscreen transitions (e.g., `OnEnteredFullscreen`, `OnExitedFullscreen`).
    * **Audio/Video Specifics:** Methods handling audio-only or video-only scenarios (e.g., `ShouldActAsAudioControls`, `StartActingAsAudioControls`).
    * **Overflow Menu:** Methods for managing the overflow menu (e.g., `OpenOverflowMenu`, `CloseOverflowMenu`).
    * **Volume Slider:** Methods specifically for the volume slider's behavior (e.g., `OpenVolumeSliderIfNecessary`, `CloseVolumeSliderIfNecessary`).

4. **Identifying Interactions with Web Technologies:**

    * **JavaScript:** Look for methods that are likely called from JavaScript or that interact with JavaScript APIs. Event handlers are prime candidates. The comment about moving code to JS is a big clue. Also, the `MediaElement()` calls strongly suggest interaction with the HTMLMediaElement interface, which is exposed to JavaScript.
    * **HTML:**  Look for methods that manipulate the DOM structure or attributes. Methods like `setAttribute` directly modify HTML attributes. The creation of child elements within the constructor also indicates HTML interaction.
    * **CSS:** Look for methods that manipulate CSS classes or styles. `SetClass`, `UpdateSizingCSSClass`, and the mention of `CSSPropertyID::kCursor` are direct links to CSS.

5. **Generating Examples:** Once the interactions are identified, create specific examples to illustrate them. Think about common media player behaviors and how these C++ methods contribute.

    * **JavaScript:** User clicks play -> JavaScript calls `play()` on the video element -> triggers the `OnPlay()` method in C++.
    * **HTML:** The constructor adds `<div>` elements for the play button, timeline, etc. The `setAttribute` method changes the `disabled` attribute.
    * **CSS:**  The `kVideoControlsVisibleCSSClass` is added or removed to control the overall visibility of the controls.

6. **Logical Reasoning and Hypothetical Scenarios:** Choose a few methods that involve some decision-making logic.

    * **`ContainsRelatedTarget`:**  Think about a mouse hovering over a control. The `relatedTarget` could be a sibling element.
    * **`ShouldHideMediaControls`:**  Consider factors like mouse inactivity and playback state.
    * **`ShouldOpenVolumeSlider`:** Analyze the conditions under which the volume slider should appear.

7. **Common Usage Errors (Debugging Perspective):**  Think about what could go wrong from a developer's point of view.

    * Forgetting to update the UI after a state change.
    * Incorrectly handling timing or event sequences.
    * Not considering different media types (audio vs. video).

8. **User Interaction as a Debugging Clue:** Trace a typical user interaction and see how it leads to this code. Playing a video is a good starting point. Mouse movements, clicks, and keyboard presses are key actions.

9. **Summarization:**  Condense the identified functionalities into a concise overview. Focus on the main responsibilities: handling media events, updating the UI, and managing the behavior of the media controls.

10. **Review and Refine:** Read through the entire analysis. Ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have just listed the functions without grouping them. Realizing the importance of structure leads to categorizing them. Similarly, elaborating on *how* JavaScript, HTML, and CSS are involved is crucial, not just stating that they are related.

By following these steps, moving from a high-level understanding to specific details and examples, a comprehensive analysis of the provided C++ code can be achieved.
这是对 `blink/renderer/modules/media_controls/media_controls_impl.cc` 文件功能的总结，基于您提供的最后一部分代码，并结合前两部分的理解进行归纳。

**总功能归纳:**

`MediaControlsImpl` 类是 Chromium Blink 引擎中负责实现原生媒体控件的核心组件。它的主要职责是：

1. **管理和协调媒体控件的显示和行为:** 它创建、维护和管理各种媒体控件元素（如播放/暂停按钮、时间轴、音量滑块、全屏按钮等），并根据媒体元素的状态和用户交互来更新这些控件的显示状态和行为。
2. **响应媒体事件:**  它监听并响应来自 HTMLMediaElement 的各种事件（如 `play`, `pause`, `timeupdate`, `volumechange`, `fullscreenchange` 等），并根据这些事件更新控件的状态和外观。
3. **处理用户交互:** 它处理用户与媒体控件的交互，例如点击播放/暂停按钮、拖动时间轴、调节音量等，并将这些交互转化为对底层 `HTMLMediaElement` 的操作。
4. **控制控件的可见性:**  它负责控制何时显示和隐藏媒体控件，包括自动隐藏（例如一段时间不活动后）和用户触发的显示/隐藏。
5. **适配不同的媒体类型和状态:**  它可以根据当前媒体是音频还是视频，以及其加载、播放、暂停等状态，调整控件的显示和功能。例如，音频控件可能比视频控件少一些按钮。
6. **处理全屏模式:**  它管理全屏模式下的控件显示和行为。
7. **支持字幕和播放速度控制:**  它集成了字幕和播放速度控制的按钮和逻辑。
8. **处理画中画 (Picture-in-Picture):** 它支持画中画模式的控制。
9. **提供无障碍支持:**  通过设置 ARIA 属性等方式提供一定的无障碍支持。
10. **处理下载:**  显示和管理下载按钮。
11. **处理投屏 (Cast):** 提供投屏功能的支持。
12. **处理溢出菜单:**  管理包含更多功能的溢出菜单。
13. **进行性能优化:**  例如，使用定时器来延迟某些操作，例如音量滑块的显示。
14. **记录指标:**  在适当的时候记录哪些控件被显示出来，用于性能分析和用户行为研究。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`MediaControlsImpl` 作为 C++ 代码，与前端技术有着紧密的联系：

* **JavaScript:**
    * **事件触发:** 当 JavaScript 代码操作 `HTMLMediaElement` (例如调用 `video.play()`) 时，会触发 C++ 端的事件处理函数，如 `OnPlay()`。
        * **假设输入:** 用户点击网页上的一个自定义播放按钮，该按钮对应的 JavaScript 代码调用 `videoElement.play()`.
        * **输出:**  `MediaControlsImpl::OnPlay()` 被调用，更新播放按钮的图标为暂停图标。
    * **属性同步:**  JavaScript 可以读取或设置 `HTMLMediaElement` 的属性（如 `volume`, `currentTime`, `paused`），这些属性的变化会通过事件通知到 C++ 端，从而更新控件的状态。
        * **假设输入:** JavaScript 代码设置 `videoElement.volume = 0.5;`.
        * **输出:** `MediaControlsImpl::OnVolumeChange()` 被调用，音量滑块的位置被更新到 50%。
    * **方法调用 (间接):** 虽然 JavaScript 不能直接调用 `MediaControlsImpl` 的方法，但用户在页面上的操作（例如点击全屏按钮）会触发浏览器事件，最终导致 C++ 代码的执行。

* **HTML:**
    * **DOM 结构:** `MediaControlsImpl` 创建和管理表示媒体控件的 HTML 元素，例如 `<div>` 元素用于包裹按钮、滑块等。在构造函数中可以看到各种控件元素的创建。
    * **属性设置:** C++ 代码通过 `setAttribute` 等方法直接修改 HTML 元素的属性，例如设置按钮的 `disabled` 属性，或设置 ARIA 属性以提供无障碍支持。
        * **假设输入:** 媒体没有音频轨道。
        * **输出:** `mute_button_->setAttribute(html_names::kDisabledAttr, AtomicString(""));`  将静音按钮的 `disabled` 属性设置为 `true`。

* **CSS:**
    * **样式控制:** `MediaControlsImpl` 通过添加或移除 CSS 类来控制控件的样式和布局。例如，`UpdateCSSClassFromState()` 方法根据媒体状态更新 CSS 类。
        * **假设输入:** 视频正在播放。
        * **输出:**  可能会添加一个 CSS 类 (例如 `kPlayingCSSClass`) 到媒体控件的根元素，这个 CSS 类会控制播放/暂停按钮的图标显示为暂停图标。
    * **响应大小变化:** `UpdateSizingCSSClass()` 方法根据控件的大小应用不同的 CSS 类，以适应不同的屏幕尺寸。
    * **光标样式:** `EnsureDefaultCursorStyleProperty()` 设置了默认的光标样式。

**逻辑推理的假设输入与输出:**

* **`ContainsRelatedTarget(Event* event)`:**
    * **假设输入:**  鼠标从播放按钮移动到其相邻的一个装饰性元素上。
    * **输出:** 如果这个装饰性元素是媒体控件的一部分（例如是播放按钮的子元素），则返回 `true`，否则返回 `false`。这用于判断鼠标是否仍然在控件的范围内。

* **`ShouldHideMediaControls()`:** (根据之前的代码推断)
    * **假设输入:** 媒体正在播放，鼠标在 3 秒内没有移动。
    * **输出:** 返回 `true`，表示应该隐藏媒体控件。

* **`ShouldOpenVolumeSlider()`:**
    * **假设输入:**  媒体有音频轨道，用户鼠标悬停在音量控制容器上，并且用户没有明确偏好隐藏音量控制。
    * **输出:** 返回 `true`，表示应该打开音量滑块。

**涉及用户或编程常见的使用错误举例说明:**

* **没有正确处理媒体事件:** 如果开发者在 C++ 代码中没有正确监听和处理某些关键的媒体事件（例如 `ended` 事件），可能导致控件状态与实际媒体状态不一致。例如，视频播放结束后，播放按钮可能仍然显示为暂停状态。
* **CSS 类名冲突:** 如果自定义的 CSS 样式与 Blink 引擎默认的媒体控件 CSS 类名冲突，可能导致控件样式显示异常。
* **JavaScript 操作与 C++ 状态不同步:**  如果 JavaScript 代码直接操作了影响控件显示的 DOM 结构，而 C++ 代码没有感知到这些变化，可能导致状态不一致。例如，JavaScript 错误地移除了某个控制按钮，但 C++ 代码仍然认为该按钮存在。
* **定时器使用不当:**  例如，如果隐藏控件的定时器逻辑有误，可能导致控件过早或过晚隐藏。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个用户播放视频的流程，以及如何触发 `MediaControlsImpl` 的相关代码：

1. **用户在网页上加载包含 `<video>` 标签的页面。**
2. **浏览器解析 HTML，创建 `HTMLVideoElement` 对象。**
3. **Blink 引擎为 `HTMLVideoElement` 创建默认的媒体控件 (由 `MediaControlsImpl` 实现)。**  这会在 C++ 中创建 `MediaControlsImpl` 的实例，并初始化各种控件元素。
4. **用户点击视频的播放按钮 (可能是默认控件，也可能是自定义的)。**
5. **如果点击的是默认控件:**
    * 浏览器事件监听器捕获到点击事件。
    * 事件被传递到 `MediaControlsImpl` 中的相应事件处理函数（例如，某个处理鼠标点击的函数，它会调用 `play_button_->handleClick()`）。
    * `play_button_->handleClick()` 最终会调用 `HTMLVideoElement::play()` 方法。
    * `HTMLVideoElement::play()` 触发 `play` 事件。
    * `MediaControlsImpl::OnPlay()` 方法被调用，更新播放按钮的图标为暂停图标，并启动隐藏控件的定时器。
6. **如果点击的是自定义播放按钮:**
    * 自定义按钮的 JavaScript 事件监听器捕获到点击事件。
    * JavaScript 代码调用 `videoElement.play()`。
    * `HTMLVideoElement::play()` 触发 `play` 事件。
    * `MediaControlsImpl::OnPlay()` 方法被调用。
7. **视频播放过程中，会周期性触发 `timeupdate` 事件。**
    * `MediaControlsImpl::OnTimeUpdate()` 被调用，更新时间显示和时间轴进度。
8. **用户调整音量滑块。**
    * 浏览器事件监听器捕获到滑块的拖动事件。
    * 事件被传递到 `MediaControlsImpl` 中处理音量滑块交互的函数。
    * 该函数调用 `HTMLVideoElement::setVolume()` 方法。
    * `HTMLVideoElement` 触发 `volumechange` 事件。
    * `MediaControlsImpl::OnVolumeChange()` 被调用，更新音量滑块和静音按钮的状态。
9. **用户点击全屏按钮。**
    * 类似播放按钮的流程，最终触发 `fullscreenchange` 事件。
    * `MediaControlsImpl::OnEnteredFullscreen()` 或 `OnExitedFullscreen()` 被调用，调整控件在全屏模式下的显示。

**调试线索:** 如果媒体控件的行为不符合预期，可以按照以下步骤调试：

* **查看控制台日志:**  Blink 引擎可能会输出相关的调试信息。
* **断点调试 C++ 代码:**  在 `MediaControlsImpl` 的相关方法中设置断点，观察代码执行流程和变量值。
* **检查 HTML 结构和 CSS 样式:**  使用开发者工具查看媒体控件的 HTML 结构和应用的 CSS 样式，确认是否符合预期。
* **监听 JavaScript 事件:**  在 JavaScript 中监听 `play`, `pause`, `timeupdate`, `volumechange`, `fullscreenchange` 等事件，确认事件是否按预期触发。
* **检查网络请求:**  对于流媒体，检查网络请求是否正常。

总而言之，`MediaControlsImpl` 是 Blink 引擎中一个复杂且核心的组件，它连接了前端的 HTML 结构、CSS 样式和 JavaScript 交互，以及底层的媒体播放功能，共同为用户提供了原生的媒体控制体验。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
neStyleProperty(CSSPropertyID::kCursor);
}

bool MediaControlsImpl::ContainsRelatedTarget(Event* event) {
  auto* pointer_event = DynamicTo<PointerEvent>(event);
  if (!pointer_event)
    return false;
  EventTarget* related_target = pointer_event->relatedTarget();
  if (!related_target)
    return false;
  return contains(related_target->ToNode());
}

void MediaControlsImpl::OnVolumeChange() {
  mute_button_->UpdateDisplayType();

  // Update visibility of volume controls.
  // TODO(mlamouri): it should not be part of the volumechange handling because
  // it is using audio availability as input.
  if (volume_slider_) {
    volume_slider_->SetVolume(MediaElement().muted() ? 0
                                                     : MediaElement().volume());
    volume_slider_->SetIsWanted(MediaElement().HasAudio() &&
                                !PreferHiddenVolumeControls(GetDocument()));
  }

  mute_button_->SetIsWanted(true);
  mute_button_->setAttribute(
      html_names::kDisabledAttr,
      MediaElement().HasAudio() ? AtomicString() : AtomicString(""));

  // If the volume slider is being used we don't want to update controls
  // visibility, since this can shift the position of the volume slider and make
  // it unusable.
  if (!volume_slider_ || !volume_slider_->IsHovered())
    BatchedControlUpdate batch(this);
}

void MediaControlsImpl::OnFocusIn() {
  // If the tap timer is active, then we will toggle the controls when the timer
  // completes, so we don't want to start showing here.
  if (!MediaElement().ShouldShowControls() || tap_timer_.IsActive())
    return;

  ResetHideMediaControlsTimer();
  MaybeShow();
}

void MediaControlsImpl::OnTimeUpdate() {
  UpdateTimeIndicators(true /* suppress_aria */);

  // 'timeupdate' might be called in a paused state. The controls should not
  // become transparent in that case.
  if (MediaElement().paused()) {
    MakeOpaque();
    return;
  }

  if (IsVisible() && ShouldHideMediaControls())
    MakeTransparent();
}

void MediaControlsImpl::OnDurationChange() {
  BatchedControlUpdate batch(this);

  const double duration = MediaElement().duration();
  bool was_finite_duration = std::isfinite(duration_display_->CurrentValue());

  // Update the displayed current time/duration.
  duration_display_->SetCurrentValue(duration);

  // Show the duration display if we have a duration or if we are showing the
  // audio controls without a source.
  duration_display_->SetIsWanted(
      std::isfinite(duration) ||
      (ShouldShowAudioControls() && State() == kNoSource));

  // TODO(crbug.com/756698): Determine if this is still needed since the format
  // of the current time no longer depends on the duration.
  UpdateCurrentTimeDisplay();

  // Update the timeline (the UI with the seek marker).
  timeline_->SetDuration(duration);
  if (!was_finite_duration && std::isfinite(duration)) {
    download_button_->SetIsWanted(
        download_button_->ShouldDisplayDownloadButton());
  }
}

void MediaControlsImpl::OnPlay() {
  UpdatePlayState();
  UpdateTimeIndicators();
  UpdateCSSClassFromState();
}

void MediaControlsImpl::OnPlaying() {
  StartHideMediaControlsTimer();
  UpdateCSSClassFromState();
  timeline_->OnMediaPlaying();
}

void MediaControlsImpl::OnPause() {
  UpdatePlayState();
  UpdateTimeIndicators();
  timeline_->OnMediaStoppedPlaying();
  MakeOpaque();

  StopHideMediaControlsTimer();

  UpdateCSSClassFromState();
}

void MediaControlsImpl::OnSeeking() {
  UpdateTimeIndicators();
  if (!is_scrubbing_) {
    is_scrubbing_ = true;
    UpdateCSSClassFromState();
  }

  // Don't try to show the controls if the seek was caused by the video being
  // looped.
  if (MediaElement().Loop() && MediaElement().currentTime() == 0)
    return;

  if (!MediaElement().ShouldShowControls())
    return;

  MaybeShow();
  StopHideMediaControlsTimer();
}

void MediaControlsImpl::OnSeeked() {
  StartHideMediaControlsIfNecessary();

  is_scrubbing_ = false;
  UpdateCSSClassFromState();
}

void MediaControlsImpl::OnTextTracksAddedOrRemoved() {
  toggle_closed_captions_button_->UpdateDisplayType();
  toggle_closed_captions_button_->SetIsWanted(
      MediaElement().HasClosedCaptions());
  BatchedControlUpdate batch(this);
}

void MediaControlsImpl::OnTextTracksChanged() {
  toggle_closed_captions_button_->UpdateDisplayType();
}

void MediaControlsImpl::OnError() {
  // TODO(mlamouri): we should only change the aspects of the control that need
  // to be changed.
  Reset();
  UpdateCSSClassFromState();
}

void MediaControlsImpl::OnLoadedMetadata() {
  // TODO(mlamouri): we should only change the aspects of the control that need
  // to be changed.
  Reset();
  UpdateCSSClassFromState();
  UpdateActingAsAudioControls();
}

void MediaControlsImpl::OnEnteredFullscreen() {
  fullscreen_button_->SetIsFullscreen(true);
  if (display_cutout_fullscreen_button_)
    display_cutout_fullscreen_button_->SetIsWanted(true);

  StopHideMediaControlsTimer();
  StartHideMediaControlsTimer();
}

void MediaControlsImpl::OnExitedFullscreen() {
  fullscreen_button_->SetIsFullscreen(false);
  if (display_cutout_fullscreen_button_)
    display_cutout_fullscreen_button_->SetIsWanted(false);

  HidePopupMenu();
  StopHideMediaControlsTimer();
  StartHideMediaControlsTimer();
}

void MediaControlsImpl::OnPictureInPictureChanged() {
  // This will only be called if the media controls are listening to the
  // Picture-in-Picture events which only happen when they provide a
  // Picture-in-Picture button.
  DCHECK(picture_in_picture_button_);
  picture_in_picture_button_->UpdateDisplayType();
}

void MediaControlsImpl::OnPanelKeypress() {
  // If the user is interacting with the controls via the keyboard, don't hide
  // the controls. This is called when the user mutes/unmutes, turns CC on/off,
  // etc.
  ResetHideMediaControlsTimer();
}

void MediaControlsImpl::NotifyElementSizeChanged(DOMRectReadOnly* new_size) {
  // Note that this code permits a bad frame on resize, since it is
  // run after the relayout / paint happens.  It would be great to improve
  // this, but it would be even greater to move this code entirely to
  // JS and fix it there.

  gfx::Size old_size = size_;
  size_.set_width(new_size->width());
  size_.set_height(new_size->height());

  // Don't bother to do any work if this matches the most recent size.
  if (old_size != size_) {
    // Update the sizing CSS class before computing which controls fit so that
    // the element sizes can update from the CSS class change before we start
    // calculating.
    UpdateSizingCSSClass();
    element_size_changed_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
  }
}

void MediaControlsImpl::ElementSizeChangedTimerFired(TimerBase*) {
  if (!MediaElement().isConnected())
    return;

  ComputeWhichControlsFit();

  // Rerender timeline bar segments when size changed.
  timeline_->RenderBarSegments();
}

void MediaControlsImpl::OnLoadingProgress() {
  timeline_->OnProgress();
}

void MediaControlsImpl::ComputeWhichControlsFit() {
  // Hide all controls that don't fit, and show the ones that do.
  // This might be better suited for a layout, but since JS media controls
  // won't benefit from that anwyay, we just do it here like JS will.
  UpdateOverflowMenuWanted();
  UpdateScrubbingMessageFits();
}

void MediaControlsImpl::MaybeRecordElementsDisplayed() const {
  // Record the display state when needed. It is only recorded when the media
  // element is in a state that allows it in order to reduce noise in the
  // metrics.
  if (!MediaControlInputElement::ShouldRecordDisplayStates(MediaElement()))
    return;

  MediaControlElementBase* elements[] = {
      play_button_.Get(),
      fullscreen_button_.Get(),
      download_button_.Get(),
      timeline_.Get(),
      mute_button_.Get(),
      volume_slider_.Get(),
      toggle_closed_captions_button_.Get(),
      playback_speed_button_.Get(),
      picture_in_picture_button_.Get(),
      cast_button_.Get(),
      current_time_display_.Get(),
      duration_display_.Get(),
      overlay_play_button_.Get(),
      overlay_cast_button_.Get(),
  };

  // Record which controls are used.
  for (auto* const element : elements) {
    if (element)
      element->MaybeRecordDisplayed();
  }
  overflow_menu_->MaybeRecordDisplayed();
}

const MediaControlCurrentTimeDisplayElement&
MediaControlsImpl::CurrentTimeDisplay() const {
  return *current_time_display_;
}

const MediaControlRemainingTimeDisplayElement&
MediaControlsImpl::RemainingTimeDisplay() const {
  return *duration_display_;
}

MediaControlToggleClosedCaptionsButtonElement&
MediaControlsImpl::ToggleClosedCaptions() {
  return *toggle_closed_captions_button_;
}

bool MediaControlsImpl::ShouldActAsAudioControls() const {
  // A video element should act like an audio element when it has an audio track
  // but no video track.
  return MediaElement().ShouldShowControls() &&
         IsA<HTMLVideoElement>(MediaElement()) && MediaElement().HasAudio() &&
         !MediaElement().HasVideo();
}

void MediaControlsImpl::StartActingAsAudioControls() {
  DCHECK(ShouldActAsAudioControls());
  DCHECK(!is_acting_as_audio_controls_);

  is_acting_as_audio_controls_ = true;
  SetClass(kActAsAudioControlsCSSClass, true);
  PopulatePanel();
  Reset();
}

void MediaControlsImpl::StopActingAsAudioControls() {
  DCHECK(!ShouldActAsAudioControls());
  DCHECK(is_acting_as_audio_controls_);

  is_acting_as_audio_controls_ = false;
  SetClass(kActAsAudioControlsCSSClass, false);
  PopulatePanel();
  Reset();
}

void MediaControlsImpl::UpdateActingAsAudioControls() {
  if (ShouldActAsAudioControls() != is_acting_as_audio_controls_) {
    if (is_acting_as_audio_controls_)
      StopActingAsAudioControls();
    else
      StartActingAsAudioControls();
  }
}

bool MediaControlsImpl::ShouldShowAudioControls() const {
  return IsA<HTMLAudioElement>(MediaElement()) || is_acting_as_audio_controls_;
}

bool MediaControlsImpl::ShouldShowVideoControls() const {
  return IsA<HTMLVideoElement>(MediaElement()) && !ShouldShowAudioControls();
}

bool MediaControlsImpl::IsLivePlayback() const {
  // It can't be determined whether a player with no source element is a live
  // playback or not, similarly with an unloaded player.
  return MediaElement().seekable()->length() == 0 && (State() >= kStopped);
}

void MediaControlsImpl::NetworkStateChanged() {
  // Update the display state of the download button in case we now have a
  // source or no longer have a source.
  download_button_->SetIsWanted(
      download_button_->ShouldDisplayDownloadButton());

  UpdateCSSClassFromState();
}

void MediaControlsImpl::OpenOverflowMenu() {
  overflow_list_->OpenOverflowMenu();
}

void MediaControlsImpl::CloseOverflowMenu() {
  overflow_list_->CloseOverflowMenu();
}

bool MediaControlsImpl::OverflowMenuIsWanted() {
  return overflow_list_->IsWanted();
}

bool MediaControlsImpl::OverflowMenuVisible() {
  return overflow_list_ ? overflow_list_->IsWanted() : false;
}

void MediaControlsImpl::ToggleOverflowMenu() {
  DCHECK(overflow_list_);

  overflow_list_->SetIsWanted(!overflow_list_->IsWanted());
}

void MediaControlsImpl::HidePopupMenu() {
  if (OverflowMenuVisible())
    ToggleOverflowMenu();

  if (TextTrackListIsWanted())
    ToggleTextTrackList();

  if (PlaybackSpeedListIsWanted())
    TogglePlaybackSpeedList();
}

void MediaControlsImpl::VolumeSliderWantedTimerFired(TimerBase*) {
  volume_slider_->OpenSlider();
  volume_control_container_->OpenContainer();
}

void MediaControlsImpl::OpenVolumeSliderIfNecessary() {
  if (ShouldOpenVolumeSlider()) {
    if (volume_slider_->IsFocused() || mute_button_->IsFocused()) {
      // When we're focusing with the keyboard, we don't need the delay.
      volume_slider_->OpenSlider();
      volume_control_container_->OpenContainer();
    } else {
      volume_slider_wanted_timer_.StartOneShot(
          WebTestSupport::IsRunningWebTest() ? kTimeToShowVolumeSliderTest
                                             : kTimeToShowVolumeSlider,
          FROM_HERE);
    }
  }
}

void MediaControlsImpl::CloseVolumeSliderIfNecessary() {
  if (ShouldCloseVolumeSlider()) {
    volume_slider_->CloseSlider();
    volume_control_container_->CloseContainer();

    if (volume_slider_wanted_timer_.IsActive())
      volume_slider_wanted_timer_.Stop();
  }
}

bool MediaControlsImpl::ShouldOpenVolumeSlider() const {
  if (!volume_slider_) {
    return false;
  }

  if (!MediaElement().HasAudio()) {
    return false;
  }

  return !PreferHiddenVolumeControls(GetDocument());
}

bool MediaControlsImpl::ShouldCloseVolumeSlider() const {
  if (!volume_slider_)
    return false;

  return !(volume_control_container_->IsHovered() ||
           volume_slider_->IsFocused() || mute_button_->IsFocused());
}

const MediaControlOverflowMenuButtonElement& MediaControlsImpl::OverflowButton()
    const {
  return *overflow_menu_;
}

MediaControlOverflowMenuButtonElement& MediaControlsImpl::OverflowButton() {
  return *overflow_menu_;
}

void MediaControlsImpl::OnWaiting() {
  timeline_->OnMediaStoppedPlaying();
  UpdateCSSClassFromState();
}

void MediaControlsImpl::OnLoadedData() {
  UpdateCSSClassFromState();
}

HTMLVideoElement& MediaControlsImpl::VideoElement() {
  return *To<HTMLVideoElement>(&MediaElement());
}

void MediaControlsImpl::Trace(Visitor* visitor) const {
  visitor->Trace(element_mutation_callback_);
  visitor->Trace(element_size_changed_timer_);
  visitor->Trace(tap_timer_);
  visitor->Trace(volume_slider_wanted_timer_);
  visitor->Trace(resize_observer_);
  visitor->Trace(panel_);
  visitor->Trace(overlay_play_button_);
  visitor->Trace(overlay_enclosure_);
  visitor->Trace(play_button_);
  visitor->Trace(current_time_display_);
  visitor->Trace(timeline_);
  visitor->Trace(scrubbing_message_);
  visitor->Trace(mute_button_);
  visitor->Trace(volume_slider_);
  visitor->Trace(picture_in_picture_button_);
  visitor->Trace(animated_arrow_container_element_);
  visitor->Trace(toggle_closed_captions_button_);
  visitor->Trace(playback_speed_button_);
  visitor->Trace(fullscreen_button_);
  visitor->Trace(download_button_);
  visitor->Trace(duration_display_);
  visitor->Trace(enclosure_);
  visitor->Trace(text_track_list_);
  visitor->Trace(playback_speed_list_);
  visitor->Trace(overflow_menu_);
  visitor->Trace(overflow_list_);
  visitor->Trace(cast_button_);
  visitor->Trace(overlay_cast_button_);
  visitor->Trace(media_event_listener_);
  visitor->Trace(orientation_lock_delegate_);
  visitor->Trace(rotate_to_fullscreen_delegate_);
  visitor->Trace(display_cutout_delegate_);
  visitor->Trace(hide_media_controls_timer_);
  visitor->Trace(media_button_panel_);
  visitor->Trace(loading_panel_);
  visitor->Trace(display_cutout_fullscreen_button_);
  visitor->Trace(volume_control_container_);
  visitor->Trace(text_track_manager_);
  MediaControls::Trace(visitor);
  HTMLDivElement::Trace(visitor);
}

}  // namespace blink

"""


```