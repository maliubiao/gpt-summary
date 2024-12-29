Response:
The user wants to understand the functionality of the `media_controls_impl.cc` file in the Chromium Blink engine. I need to analyze the code and identify its main purpose. Since this is part 1 of 3, I should focus on summarizing the overall responsibilities at a high level. I should also pay attention to connections with web technologies like JavaScript, HTML, and CSS, and try to provide illustrative examples based on the provided code snippets.

**Plan:**

1. **Identify the core responsibility:** The file name and the included headers strongly suggest this file implements the behavior and structure of the media controls for `<video>` and `<audio>` elements.
2. **Analyze included headers:**  The headers reveal interactions with DOM elements, events, CSS, and media-related functionalities.
3. **Examine key classes and methods:**  Focus on the `MediaControlsImpl` class and its methods like `InitializeControls`, `PopulatePanel`, and `UpdateCSSClassFromState` to understand how the controls are built and managed.
4. **Look for interactions with web technologies:**  Pay attention to how JavaScript events trigger actions, how HTML elements are created and manipulated, and how CSS classes are used to style the controls.
5. **Formulate a summary:** Condense the findings into a concise description of the file's function.
这是 `blink/renderer/modules/media_controls/media_controls_impl.cc` 文件的第一部分，主要负责实现 HTML `<video>` 和 `<audio>` 元素的原生媒体控制条的逻辑和结构。

**功能归纳:**

1. **媒体控制条的创建和管理:**  该文件定义了 `MediaControlsImpl` 类，负责创建、初始化和管理媒体控制条的各种 UI 元素，例如播放/暂停按钮、时间线、音量控制、全屏按钮等。
2. **状态管理:**  它跟踪媒体元素的不同状态（例如，无来源、加载中、播放、暂停、缓冲等），并根据这些状态更新控制条的 UI，例如禁用/启用按钮，显示/隐藏加载动画。
3. **事件处理:**  它处理用户与控制条的交互事件（例如，点击按钮、拖动时间线）以及媒体元素自身发出的事件（例如，播放、暂停、时间更新），并执行相应的操作。
4. **与媒体元素的交互:**  它与关联的 `HTMLMediaElement` 进行通信，以控制媒体的播放、暂停、音量、当前时间等。
5. **控制条的显示和隐藏:**  它负责根据用户操作和媒体状态来显示和隐藏控制条。
6. **支持不同的控制条布局:**  代码中可以看出它会根据是视频还是音频元素来创建不同的控制条布局。
7. **功能开关:**  它会根据浏览器的特性开关（例如，画中画、投屏）来决定是否显示相应的控制按钮。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

1. **HTML:**
    *   **创建 DOM 结构:**  `InitializeControls()` 方法会创建控制条的各种 HTML 元素，例如 `<div>`、`<button>` 等，并设置它们的类名和属性。
        ```c++
        // 例如创建播放按钮
        play_button_ = MakeGarbageCollected<MediaControlPlayButtonElement>(*this);
        ```
        这对应于在 HTML 中创建类似 `<button class="-webkit-media-controls-play-button"></button>` 的元素。
    *   **作为 Shadow DOM 的宿主:**  `MediaControlsImpl` 实例通常会作为关联的 `<video>` 或 `<audio>` 元素的 Shadow DOM 的一部分插入。

2. **CSS:**
    *   **应用样式:**  `UpdateCSSClassFromState()` 方法会根据媒体状态添加或删除 CSS 类名，从而触发 CSS 规则，改变控制条的外观。
        ```c++
        if (state == kPlaying)
          toAdd.push_back("state-playing");
        else
          toRemove.push_back("state-playing");
        ```
        例如，当媒体播放时，添加 `state-playing` 类，CSS 可以定义 `.state-playing .-webkit-media-controls-play-button::after { content: "Pause"; }` 来改变播放按钮的图标。
    *   **使用预定义的 CSS 类名:**  代码中使用了大量的以 `-webkit-media-controls-` 开头的类名，这些类名与 Blink 引擎预定义的媒体控制条 CSS 样式相关联。

3. **JavaScript:**
    *   **事件监听:**  控制条上的按钮点击等用户交互会触发 JavaScript 事件。例如，点击播放按钮会触发一个事件，`MediaControlsImpl` 会监听这些事件并执行相应的操作，例如调用 `MediaElement().Play()`。 虽然这个 C++ 文件本身不直接编写 JavaScript 代码，但它定义了控制条的行为，这些行为通常是通过 JavaScript 事件驱动的。
    *   **属性交互:**  JavaScript 可以通过 DOM API 获取或设置媒体元素的属性（例如 `currentTime`, `volume`），这些属性的变化可能会影响控制条的状态和显示。

**逻辑推理 (假设输入与输出):**

*   **假设输入:** 用户点击了播放按钮，并且媒体当前处于暂停状态 (`State()` 返回 `kStopped`)。
*   **输出:** `play_button_` 关联的事件处理程序会被触发，该处理程序会调用 `MediaElement().Play()`，并且 `UpdateCSSClassFromState()` 会将控制条状态更新为 `kPlaying`，从而改变播放按钮的图标。

**用户或编程常见的使用错误:**

*   **用户错误:** 用户可能会在视频加载完成前就尝试操作控制条，例如拖动时间线，这可能导致预期之外的行为。控制条的代码需要处理这些情况，例如禁用时间线直到元数据加载完成。
*   **编程错误:**
    *   **错误的事件处理:**  如果控制条的事件处理逻辑不正确，可能会导致点击按钮没有反应或者触发错误的操作。
    *   **状态管理错误:**  如果状态更新不正确，可能会导致控制条的 UI 与实际的媒体状态不符。例如，视频已经播放，但播放按钮仍然显示为“播放”图标。
    *   **CSS 类名使用错误:**  如果在 C++ 代码中使用了错误的 CSS 类名，或者 CSS 样式定义不正确，可能会导致控制条的样式显示异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个包含 `<video>` 或 `<audio>` 元素的网页。**
2. **浏览器解析 HTML，创建对应的 `HTMLVideoElement` 或 `HTMLAudioElement` 对象。**
3. **如果浏览器判断需要显示原生控制条（例如，没有设置 `controls` 属性或者浏览器策略要求），会创建 `MediaControlsImpl` 对象并将其添加到媒体元素的 Shadow DOM 中。**
4. **用户与控制条进行交互，例如点击播放按钮。**
5. **浏览器捕获到点击事件，并将其分发到控制条上的相应元素（例如，`MediaControlPlayButtonElement`）。**
6. **`MediaControlPlayButtonElement` 内部的事件处理逻辑会调用 `MediaControlsImpl` 的方法来处理该事件。**
7. **`MediaControlsImpl` 的方法会更新媒体元素的状态，并调用其他方法来更新控制条的 UI。**

**作为调试线索:**  当媒体控制条出现问题时，开发者可以查看这个文件中的代码，了解控制条是如何响应用户操作和媒体事件的，并检查状态管理和事件处理逻辑是否正确。例如，可以使用断点来跟踪用户点击按钮后，代码的执行流程，查看状态变量的值是否符合预期。

总而言之，`blink/renderer/modules/media_controls/media_controls_impl.cc` 文件的第一部分是构建和管理浏览器原生媒体控制条的核心，它将 HTML 结构、CSS 样式和 JavaScript 事件处理结合在一起，为用户提供与媒体内容交互的界面。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2011, 2012 Apple Inc. All rights reserved.
 * Copyright (C) 2011, 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"

#include "base/auto_reset.h"
#include "media/base/media_switches.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/user_metrics_action.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mutation_observer_init.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/mutation_observer.h"
#include "third_party/blink/renderer/core/dom/mutation_record.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/media/autoplay_policy.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element_controls_list.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/time_ranges.h"
#include "third_party/blink/renderer/core/html/track/text_track.h"
#include "third_party/blink/renderer/core/html/track/text_track_container.h"
#include "third_party/blink/renderer/core/html/track/text_track_list.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_entry.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_animated_arrow_container_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_button_panel_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_cast_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_consts.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_current_time_display_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_display_cutout_fullscreen_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_download_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_elements_helper.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_fullscreen_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_loading_panel_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_mute_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_overflow_menu_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_overflow_menu_list_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_overlay_enclosure_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_overlay_play_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_panel_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_panel_enclosure_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_picture_in_picture_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_play_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_playback_speed_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_playback_speed_list_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_remaining_time_display_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_scrubbing_message_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_text_track_list_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_timeline_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_toggle_closed_captions_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_volume_control_container_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_volume_slider_element.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_display_cutout_delegate.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_media_event_listener.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_resource_loader.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_rotate_to_fullscreen_delegate.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_shared_helper.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_text_track_manager.h"
#include "third_party/blink/renderer/modules/remoteplayback/remote_playback.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

// (2px left border + 6px left padding + 56px button + 6px right padding + 2px
// right border) = 72px.
constexpr int kMinWidthForOverlayPlayButton = 72;

constexpr int kMinScrubbingMessageWidth = 300;

const char* const kStateCSSClasses[8] = {
    "state-no-source",                 // kNoSource
    "state-no-metadata",               // kNotLoaded
    "state-loading-metadata-paused",   // kLoadingMetadataPaused
    "state-loading-metadata-playing",  // kLoadingMetadataPlaying
    "state-stopped",                   // kStopped
    "state-playing",                   // kPlaying
    "state-buffering",                 // kBuffering
    "state-scrubbing",                 // kScrubbing
};

// The padding in pixels inside the button panel.
constexpr int kAudioButtonPadding = 20;
constexpr int kVideoButtonPadding = 26;

const char kShowDefaultPosterCSSClass[] = "use-default-poster";
const char kActAsAudioControlsCSSClass[] = "audio-only";
const char kScrubbingMessageCSSClass[] = "scrubbing-message";
const char kTestModeCSSClass[] = "test-mode";

// The delay between two taps to be recognized as a double tap gesture.
constexpr base::TimeDelta kDoubleTapDelay = base::Milliseconds(300);

// The time user have to hover on mute button to show volume slider.
// If this value is changed, you need to change the corresponding value in
// media_controls_impl_test.cc
constexpr base::TimeDelta kTimeToShowVolumeSlider = base::Milliseconds(200);
constexpr base::TimeDelta kTimeToShowVolumeSliderTest = base::Milliseconds(0);

// The number of seconds to jump when double tapping.
constexpr int kNumberOfSecondsToJump = 10;

void MaybeParserAppendChild(Element* parent, Element* child) {
  DCHECK(parent);
  if (child)
    parent->ParserAppendChild(child);
}

bool ShouldShowPlaybackSpeedButton(HTMLMediaElement& media_element) {
  // The page disabled the button via the controlsList attribute.
  if (media_element.ControlsListInternal()->ShouldHidePlaybackRate() &&
      !media_element.UserWantsControlsVisible()) {
    UseCounter::Count(media_element.GetDocument(),
                      WebFeature::kHTMLMediaElementControlsListNoPlaybackRate);
    return false;
  }

  // A MediaStream is not seekable.
  if (media_element.GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream)
    return false;

  // Don't allow for live infinite streams.
  if (media_element.duration() == std::numeric_limits<double>::infinity() &&
      media_element.getReadyState() > HTMLMediaElement::kHaveNothing) {
    return false;
  }

  return true;
}

bool ShouldShowPictureInPictureButton(HTMLMediaElement& media_element) {
  return media_element.SupportsPictureInPicture();
}

bool ShouldShowCastButton(HTMLMediaElement& media_element) {
  if (media_element.FastHasAttribute(html_names::kDisableremoteplaybackAttr))
    return false;

  // Explicitly do not show cast button when the mediaControlsEnabled setting is
  // false, to make sure the overlay does not appear.
  Document& document = media_element.GetDocument();
  if (document.GetSettings() &&
      (!document.GetSettings()->GetMediaControlsEnabled())) {
    return false;
  }

  // The page disabled the button via the attribute.
  if (media_element.ControlsListInternal()->ShouldHideRemotePlayback() &&
      !media_element.UserWantsControlsVisible()) {
    UseCounter::Count(
        media_element.GetDocument(),
        WebFeature::kHTMLMediaElementControlsListNoRemotePlayback);
    return false;
  }

  return RemotePlayback::From(media_element).RemotePlaybackAvailable();
}

bool ShouldShowCastOverlayButton(HTMLMediaElement& media_element) {
  return !media_element.ShouldShowControls() &&
         RuntimeEnabledFeatures::MediaCastOverlayButtonEnabled() &&
         ShouldShowCastButton(media_element);
}

bool PreferHiddenVolumeControls(const Document& document) {
  return !document.GetSettings() ||
         document.GetSettings()->GetPreferHiddenVolumeControls();
}

// If you change this value, then also update the corresponding value in
// web_tests/media/media-controls.js.
constexpr base::TimeDelta kTimeWithoutMouseMovementBeforeHidingMediaControls =
    base::Seconds(2.5);

base::TimeDelta GetTimeWithoutMouseMovementBeforeHidingMediaControls() {
  return kTimeWithoutMouseMovementBeforeHidingMediaControls;
}

}  // namespace

class MediaControlsImpl::BatchedControlUpdate {
  STACK_ALLOCATED();

 public:
  explicit BatchedControlUpdate(MediaControlsImpl* controls)
      : controls_(controls) {
    DCHECK(IsMainThread());
    DCHECK_GE(batch_depth_, 0);
    ++batch_depth_;
  }

  BatchedControlUpdate(const BatchedControlUpdate&) = delete;
  BatchedControlUpdate& operator=(const BatchedControlUpdate&) = delete;

  ~BatchedControlUpdate() {
    DCHECK(IsMainThread());
    DCHECK_GT(batch_depth_, 0);
    if (!(--batch_depth_))
      controls_->ComputeWhichControlsFit();
  }

 private:
  MediaControlsImpl* controls_;
  static int batch_depth_;
};

// Count of number open batches for controls visibility.
int MediaControlsImpl::BatchedControlUpdate::batch_depth_ = 0;

class MediaControlsImpl::MediaControlsResizeObserverDelegate final
    : public ResizeObserver::Delegate {
 public:
  explicit MediaControlsResizeObserverDelegate(MediaControlsImpl* controls)
      : controls_(controls) {
    DCHECK(controls);
  }
  ~MediaControlsResizeObserverDelegate() override = default;

  void OnResize(
      const HeapVector<Member<ResizeObserverEntry>>& entries) override {
    DCHECK_EQ(1u, entries.size());
    DCHECK_EQ(entries[0]->target(), controls_->MediaElement());
    controls_->NotifyElementSizeChanged(entries[0]->contentRect());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(controls_);
    ResizeObserver::Delegate::Trace(visitor);
  }

 private:
  Member<MediaControlsImpl> controls_;
};

// Observes changes to the HTMLMediaElement attributes that affect controls.
class MediaControlsImpl::MediaElementMutationCallback
    : public MutationObserver::Delegate {
 public:
  explicit MediaElementMutationCallback(MediaControlsImpl* controls)
      : controls_(controls), observer_(MutationObserver::Create(this)) {
    MutationObserverInit* init = MutationObserverInit::Create();
    init->setAttributeOldValue(true);
    init->setAttributes(true);
    init->setAttributeFilter(
        {html_names::kDisableremoteplaybackAttr.ToString(),
         html_names::kDisablepictureinpictureAttr.ToString(),
         html_names::kPosterAttr.ToString()});
    observer_->observe(&controls_->MediaElement(), init, ASSERT_NO_EXCEPTION);
  }

  ExecutionContext* GetExecutionContext() const override {
    return controls_->GetDocument().GetExecutionContext();
  }

  void Deliver(const MutationRecordVector& records,
               MutationObserver&) override {
    for (const auto& record : records) {
      if (record->type() != "attributes")
        continue;

      const auto* element = To<Element>(record->target());
      if (record->oldValue() == element->getAttribute(record->attributeName()))
        continue;

      if (record->attributeName() ==
          html_names::kDisableremoteplaybackAttr.ToString()) {
        controls_->RefreshCastButtonVisibilityWithoutUpdate();
      }

      if (record->attributeName() ==
              html_names::kDisablepictureinpictureAttr.ToString() &&
          controls_->picture_in_picture_button_) {
        controls_->picture_in_picture_button_->SetIsWanted(
            ShouldShowPictureInPictureButton(controls_->MediaElement()));
      }

      if (record->attributeName() == html_names::kPosterAttr.ToString())
        controls_->UpdateCSSClassFromState();

      BatchedControlUpdate batch(controls_);
    }
  }

  void Disconnect() { observer_->disconnect(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(controls_);
    visitor->Trace(observer_);
    MutationObserver::Delegate::Trace(visitor);
  }

 private:
  Member<MediaControlsImpl> controls_;
  Member<MutationObserver> observer_;
};

bool MediaControlsImpl::IsTouchEvent(Event* event) {
  auto* mouse_event = DynamicTo<MouseEvent>(event);
  return IsA<TouchEvent>(event) || IsA<GestureEvent>(event) ||
         (mouse_event && mouse_event->FromTouch());
}

MediaControlsImpl::MediaControlsImpl(HTMLMediaElement& media_element)
    : HTMLDivElement(media_element.GetDocument()),
      MediaControls(media_element),
      overlay_enclosure_(nullptr),
      overlay_play_button_(nullptr),
      overlay_cast_button_(nullptr),
      enclosure_(nullptr),
      panel_(nullptr),
      play_button_(nullptr),
      timeline_(nullptr),
      scrubbing_message_(nullptr),
      current_time_display_(nullptr),
      duration_display_(nullptr),
      mute_button_(nullptr),
      volume_slider_(nullptr),
      volume_control_container_(nullptr),
      toggle_closed_captions_button_(nullptr),
      text_track_list_(nullptr),
      playback_speed_button_(nullptr),
      playback_speed_list_(nullptr),
      overflow_list_(nullptr),
      media_button_panel_(nullptr),
      loading_panel_(nullptr),
      picture_in_picture_button_(nullptr),
      animated_arrow_container_element_(nullptr),
      cast_button_(nullptr),
      fullscreen_button_(nullptr),
      display_cutout_fullscreen_button_(nullptr),
      download_button_(nullptr),
      media_event_listener_(
          MakeGarbageCollected<MediaControlsMediaEventListener>(this)),
      orientation_lock_delegate_(nullptr),
      rotate_to_fullscreen_delegate_(nullptr),
      display_cutout_delegate_(nullptr),
      hide_media_controls_timer_(
          media_element.GetDocument().GetTaskRunner(TaskType::kInternalMedia),
          this,
          &MediaControlsImpl::HideMediaControlsTimerFired),
      hide_timer_behavior_flags_(kIgnoreNone),
      is_mouse_over_controls_(false),
      is_paused_for_scrubbing_(false),
      resize_observer_(ResizeObserver::Create(
          media_element.GetDocument().domWindow(),
          MakeGarbageCollected<MediaControlsResizeObserverDelegate>(this))),
      element_size_changed_timer_(
          media_element.GetDocument().GetTaskRunner(TaskType::kInternalMedia),
          this,
          &MediaControlsImpl::ElementSizeChangedTimerFired),
      keep_showing_until_timer_fires_(false),
      tap_timer_(
          media_element.GetDocument().GetTaskRunner(TaskType::kInternalMedia),
          this,
          &MediaControlsImpl::TapTimerFired),
      volume_slider_wanted_timer_(
          media_element.GetDocument().GetTaskRunner(TaskType::kInternalMedia),
          this,
          &MediaControlsImpl::VolumeSliderWantedTimerFired),
      text_track_manager_(
          MakeGarbageCollected<MediaControlsTextTrackManager>(media_element)) {
  // On touch devices, start with the assumption that the user will interact via
  // touch events.
  Settings* settings = media_element.GetDocument().GetSettings();
  is_touch_interaction_ = settings ? settings->GetMaxTouchPoints() > 0 : false;

  resize_observer_->observe(&media_element);
}

MediaControlsImpl* MediaControlsImpl::Create(HTMLMediaElement& media_element,
                                             ShadowRoot& shadow_root) {
  MediaControlsImpl* controls =
      MakeGarbageCollected<MediaControlsImpl>(media_element);
  controls->SetShadowPseudoId(AtomicString("-webkit-media-controls"));
  controls->InitializeControls();
  controls->Reset();

  if (RuntimeEnabledFeatures::VideoFullscreenOrientationLockEnabled() &&
      IsA<HTMLVideoElement>(media_element)) {
    // Initialize the orientation lock when going fullscreen feature.
    controls->orientation_lock_delegate_ =
        MakeGarbageCollected<MediaControlsOrientationLockDelegate>(
            To<HTMLVideoElement>(media_element));
  }

  if (MediaControlsDisplayCutoutDelegate::IsEnabled() &&
      IsA<HTMLVideoElement>(media_element)) {
    // Initialize the pinch gesture to expand into the display cutout feature.
    controls->display_cutout_delegate_ =
        MakeGarbageCollected<MediaControlsDisplayCutoutDelegate>(
            To<HTMLVideoElement>(media_element));
  }

  if (RuntimeEnabledFeatures::VideoRotateToFullscreenEnabled() &&
      IsA<HTMLVideoElement>(media_element)) {
    // Initialize the rotate-to-fullscreen feature.
    controls->rotate_to_fullscreen_delegate_ =
        MakeGarbageCollected<MediaControlsRotateToFullscreenDelegate>(
            To<HTMLVideoElement>(media_element));
  }

  MediaControlsResourceLoader::InjectMediaControlsUAStyleSheet();

  shadow_root.ParserAppendChild(controls);
  return controls;
}

// The media controls DOM structure looks like:
//
// MediaControlsImpl
//     (-webkit-media-controls)
// +-MediaControlLoadingPanelElement
// |    (-internal-media-controls-loading-panel)
// +-MediaControlOverlayEnclosureElement
// |    (-webkit-media-controls-overlay-enclosure)
// | \-MediaControlCastButtonElement
// |     (-internal-media-controls-overlay-cast-button)
// \-MediaControlPanelEnclosureElement
//   |    (-webkit-media-controls-enclosure)
//   \-MediaControlPanelElement
//     |    (-webkit-media-controls-panel)
//     +-MediaControlScrubbingMessageElement
//     |  (-internal-media-controls-scrubbing-message)
//     |  {if is video element}
//     +-MediaControlOverlayPlayButtonElement
//     |  (-webkit-media-controls-overlay-play-button)
//     |  {if mediaControlsOverlayPlayButtonEnabled}
//     +-MediaControlButtonPanelElement
//     |  |  (-internal-media-controls-button-panel)
//     |  |  <video> only, otherwise children are directly attached to parent
//     |  +-MediaControlPlayButtonElement
//     |  |    (-webkit-media-controls-play-button)
//     |  |    {if !mediaControlsOverlayPlayButtonEnabled}
//     |  +-MediaControlCurrentTimeDisplayElement
//     |  |    (-webkit-media-controls-current-time-display)
//     |  +-MediaControlRemainingTimeDisplayElement
//     |  |    (-webkit-media-controls-time-remaining-display)
//     |  |    {if !IsLivePlayback}
//     |  +-HTMLDivElement
//     |  |    (-internal-media-controls-button-spacer)
//     |  |    {if is video element}
//     |  +-MediaControlVolumeControlContainerElement
//     |  |  |  (-webkit-media-controls-volume-control-container)
//     |  |  +-HTMLDivElement
//     |  |  |    (-webkit-media-controls-volume-control-hover-background)
//     |  |  +-MediaControlMuteButtonElement
//     |  |  |    (-webkit-media-controls-mute-button)
//     |  |  +-MediaControlVolumeSliderElement
//     |  |       (-webkit-media-controls-volume-slider)
//     |  +-MediaControlPictureInPictureButtonElement
//     |  |    (-webkit-media-controls-picture-in-picture-button)
//     |  +-MediaControlFullscreenButtonElement
//     |  |    (-webkit-media-controls-fullscreen-button)
//     \-MediaControlTimelineElement
//          (-webkit-media-controls-timeline)
//          {if !IsLivePlayback}
// +-MediaControlTextTrackListElement
// |    (-internal-media-controls-text-track-list)
// | {for each renderable text track}
//  \-MediaControlTextTrackListItem
//  |   (-internal-media-controls-text-track-list-item)
//  +-MediaControlTextTrackListItemInput
//  |    (-internal-media-controls-text-track-list-item-input)
//  +-MediaControlTextTrackListItemCaptions
//  |    (-internal-media-controls-text-track-list-kind-captions)
//  +-MediaControlTextTrackListItemSubtitles
//       (-internal-media-controls-text-track-list-kind-subtitles)
// +-MediaControlDisplayCutoutFullscreenElement
//       (-internal-media-controls-display-cutout-fullscreen-button)
void MediaControlsImpl::InitializeControls() {
  if (ShouldShowVideoControls()) {
    loading_panel_ =
        MakeGarbageCollected<MediaControlLoadingPanelElement>(*this);
    ParserAppendChild(loading_panel_);
  }

  overlay_enclosure_ =
      MakeGarbageCollected<MediaControlOverlayEnclosureElement>(*this);

  if (RuntimeEnabledFeatures::MediaControlsOverlayPlayButtonEnabled()) {
    overlay_play_button_ =
        MakeGarbageCollected<MediaControlOverlayPlayButtonElement>(*this);
  }

  overlay_cast_button_ =
      MakeGarbageCollected<MediaControlCastButtonElement>(*this, true);
  overlay_enclosure_->ParserAppendChild(overlay_cast_button_);

  ParserAppendChild(overlay_enclosure_);

  // Create an enclosing element for the panel so we can visually offset the
  // controls correctly.
  enclosure_ = MakeGarbageCollected<MediaControlPanelEnclosureElement>(*this);

  panel_ = MakeGarbageCollected<MediaControlPanelElement>(*this);

  // On the video controls, the buttons belong to a separate button panel. This
  // is because they are displayed in two lines.
  if (ShouldShowVideoControls()) {
    media_button_panel_ =
        MakeGarbageCollected<MediaControlButtonPanelElement>(*this);
    scrubbing_message_ =
        MakeGarbageCollected<MediaControlScrubbingMessageElement>(*this);
  }

  play_button_ = MakeGarbageCollected<MediaControlPlayButtonElement>(*this);

  current_time_display_ =
      MakeGarbageCollected<MediaControlCurrentTimeDisplayElement>(*this);
  current_time_display_->SetIsWanted(true);

  duration_display_ =
      MakeGarbageCollected<MediaControlRemainingTimeDisplayElement>(*this);
  timeline_ = MakeGarbageCollected<MediaControlTimelineElement>(*this);
  mute_button_ = MakeGarbageCollected<MediaControlMuteButtonElement>(*this);

  volume_control_container_ =
      MakeGarbageCollected<MediaControlVolumeControlContainerElement>(*this);
  volume_slider_ = MakeGarbageCollected<MediaControlVolumeSliderElement>(
      *this, volume_control_container_.Get());
  if (PreferHiddenVolumeControls(GetDocument()))
    volume_slider_->SetIsWanted(false);

  if (GetDocument().GetSettings() &&
      GetDocument().GetSettings()->GetPictureInPictureEnabled() &&
      IsA<HTMLVideoElement>(MediaElement())) {
    picture_in_picture_button_ =
        MakeGarbageCollected<MediaControlPictureInPictureButtonElement>(*this);
    picture_in_picture_button_->SetIsWanted(
        ShouldShowPictureInPictureButton(MediaElement()));
  }

  if (RuntimeEnabledFeatures::DisplayCutoutAPIEnabled() &&
      IsA<HTMLVideoElement>(MediaElement())) {
    display_cutout_fullscreen_button_ =
        MakeGarbageCollected<MediaControlDisplayCutoutFullscreenButtonElement>(
            *this);
  }

  fullscreen_button_ =
      MakeGarbageCollected<MediaControlFullscreenButtonElement>(*this);
  download_button_ =
      MakeGarbageCollected<MediaControlDownloadButtonElement>(*this);
  cast_button_ =
      MakeGarbageCollected<MediaControlCastButtonElement>(*this, false);
  toggle_closed_captions_button_ =
      MakeGarbageCollected<MediaControlToggleClosedCaptionsButtonElement>(
          *this);
  playback_speed_button_ =
      MakeGarbageCollected<MediaControlPlaybackSpeedButtonElement>(*this);
  playback_speed_button_->SetIsWanted(
      ShouldShowPlaybackSpeedButton(MediaElement()));
  overflow_menu_ =
      MakeGarbageCollected<MediaControlOverflowMenuButtonElement>(*this);

  PopulatePanel();
  enclosure_->ParserAppendChild(panel_);

  ParserAppendChild(enclosure_);

  text_track_list_ =
      MakeGarbageCollected<MediaControlTextTrackListElement>(*this);
  ParserAppendChild(text_track_list_);

  playback_speed_list_ =
      MakeGarbageCollected<MediaControlPlaybackSpeedListElement>(*this);
  ParserAppendChild(playback_speed_list_);

  overflow_list_ =
      MakeGarbageCollected<MediaControlOverflowMenuListElement>(*this);
  ParserAppendChild(overflow_list_);

  // The order in which we append elements to the overflow list is significant
  // because it determines how the elements show up in the overflow menu
  // relative to each other.  The first item appended appears at the top of the
  // overflow menu.
  overflow_list_->ParserAppendChild(play_button_->CreateOverflowElement(
      MakeGarbageCollected<MediaControlPlayButtonElement>(*this)));
  overflow_list_->ParserAppendChild(fullscreen_button_->CreateOverflowElement(
      MakeGarbageCollected<MediaControlFullscreenButtonElement>(*this)));
  overflow_list_->ParserAppendChild(download_button_->CreateOverflowElement(
      MakeGarbageCollected<MediaControlDownloadButtonElement>(*this)));
  overflow_list_->ParserAppendChild(mute_button_->CreateOverflowElement(
      MakeGarbageCollected<MediaControlMuteButtonElement>(*this)));
  overflow_list_->ParserAppendChild(cast_button_->CreateOverflowElement(
      MakeGarbageCollected<MediaControlCastButtonElement>(*this, false)));
  overflow_list_->ParserAppendChild(
      toggle_closed_captions_button_->CreateOverflowElement(
          MakeGarbageCollected<MediaControlToggleClosedCaptionsButtonElement>(
              *this)));
  overflow_list_->ParserAppendChild(
      playback_speed_button_->CreateOverflowElement(
          MakeGarbageCollected<MediaControlPlaybackSpeedButtonElement>(*this)));
  if (picture_in_picture_button_) {
    overflow_list_->ParserAppendChild(
        picture_in_picture_button_->CreateOverflowElement(
            MakeGarbageCollected<MediaControlPictureInPictureButtonElement>(
                *this)));
  }

  // Set the default CSS classes.
  UpdateCSSClassFromState();
}

void MediaControlsImpl::PopulatePanel() {
  // Clear the panels.
  panel_->setInnerHTML("");
  if (media_button_panel_)
    media_button_panel_->setInnerHTML("");

  Element* button_panel = panel_;
  if (ShouldShowVideoControls()) {
    MaybeParserAppendChild(panel_, scrubbing_message_);
    if (display_cutout_fullscreen_button_)
      panel_->ParserAppendChild(display_cutout_fullscreen_button_);

    MaybeParserAppendChild(panel_, overlay_play_button_);
    panel_->ParserAppendChild(media_button_panel_);
    button_panel = media_button_panel_;
  }

  button_panel->ParserAppendChild(play_button_);
  button_panel->ParserAppendChild(current_time_display_);
  button_panel->ParserAppendChild(duration_display_);

  if (ShouldShowVideoControls()) {
    MediaControlElementsHelper::CreateDiv(
        AtomicString("-internal-media-controls-button-spacer"), button_panel);
  }

  panel_->ParserAppendChild(timeline_);

  MaybeParserAppendChild(volume_control_container_, volume_slider_);
  volume_control_container_->ParserAppendChild(mute_button_);
  button_panel->ParserAppendChild(volume_control_container_);

  button_panel->ParserAppendChild(fullscreen_button_);

  button_panel->ParserAppendChild(overflow_menu_);

  // Attach hover background divs.
  AttachHoverBackground(play_button_);
  AttachHoverBackground(fullscreen_button_);
  AttachHoverBackground(overflow_menu_);
}

void MediaControlsImpl::AttachHoverBackground(Element* element) {
  MediaControlElementsHelper::CreateDiv(
      AtomicString("-internal-media-controls-button-hover-background"),
      element->GetShadowRoot());
}

Node::InsertionNotificationRequest MediaControlsImpl::InsertedInto(
    ContainerNode& root) {
  if (!MediaElement().isConnected())
    return HTMLDivElement::InsertedInto(root);

  // TODO(mlamouri): we should show the controls instead of having
  // HTMLMediaElement do it.

  // m_windowEventListener doesn't need to be re-attached as it's only needed
  // when a menu is visible.
  media_event_listener_->Attach();
  if (orientation_lock_delegate_)
    orientation_lock_delegate_->Attach();
  if (rotate_to_fullscreen_delegate_)
    rotate_to_fullscreen_delegate_->Attach();
  if (display_cutout_delegate_)
    display_cutout_delegate_->Attach();

  if (!resize_observer_) {
    resize_observer_ = ResizeObserver::Create(
        MediaElement().GetDocument().domWindow(),
        MakeGarbageCollected<MediaControlsResizeObserverDelegate>(this));
    HTMLMediaElement& html_media_element = MediaElement();
    resize_observer_->observe(&html_media_element);
  }

  if (!element_mutation_callback_) {
    element_mutation_callback_ =
        MakeGarbageCollected<MediaElementMutationCallback>(this);
  }

  return HTMLDivElement::InsertedInto(root);
}

void MediaControlsImpl::UpdateCSSClassFromState() {
  // Skip CSS class updates when not needed in order to avoid triggering
  // unnecessary style calculation.
  if (!MediaElement().ShouldShowControls() && !is_hiding_controls_)
    return;

  const ControlsState state = State();

  Vector<String> toAdd;
  Vector<String> toRemove;

  if (state < kLoadingMetadataPaused)
    toAdd.push_back("phase-pre-ready");
  else
    toRemove.push_back("phase-pre-ready");

  if (state > kLoadingMetadataPlaying)
    toAdd.push_back("phase-ready");
  else
    toRemove.push_back("phase-ready");

  for (int i = 0; i < 8; i++) {
    if (i == state)
      toAdd.push_back(kStateCSSClasses[i]);
    else
      toRem
"""


```