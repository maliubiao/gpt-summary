Response: Let's break down the thought process for analyzing this C++ Chromium source code.

1. **Understand the Goal:** The request asks for the functionality of `watch_time_reporter.cc`, its relation to web technologies, logical inferences, and potential user/programming errors.

2. **Initial Code Scan (Keywords and Structure):**  Quickly skim the code for important keywords: `WatchTimeReporter`, `media`, `playback`, `metrics`, `timer`, `properties`, `background`, `muted`, `visibility`, `volume`, `error`, `underflow`, `controls`, `display`. Notice the inclusion of `<numeric>`, `<vector>`, `base/functional/bind.h`, `base/power_monitor`, `base/task`, `base/time`, and `third_party/blink/public/common/media/watch_time_reporter.h`. This gives an immediate impression that this code is about tracking media playback time under various conditions and reporting it as metrics. The `blink` namespace indicates it's part of the rendering engine.

3. **Core Class Analysis (`WatchTimeReporter`):** Focus on the main class. Look at its constructor. What does it take as input?
    * `media::mojom::PlaybackPropertiesPtr`:  Clearly defines the media being played (audio/video, background, muted, etc.). This is likely populated from higher-level code handling the `<video>` or `<audio>` tags.
    * `gfx::Size natural_size`:  Video dimensions.
    * `GetMediaTimeCB`, `GetPipelineStatsCB`: Function callbacks to get the current playback time and decoding statistics. This is an important point – the reporter *doesn't* manage playback directly, it *observes* it.
    * `media::mojom::MediaMetricsProvider`:  The interface for reporting the collected metrics.
    * `scoped_refptr<base::SequencedTaskRunner>`: For asynchronous operations (like the timer).
    * `const base::TickClock*`:  For timekeeping (useful for testing).

4. **Key Member Variables:** Examine the important member variables:
    * `properties_`: Stores the playback properties.
    * `is_background_`, `is_muted_`: Flags for special reporting modes.
    * `get_media_time_cb_`, `get_pipeline_stats_cb_`: The callbacks again.
    * `reporting_timer_`: The core of the periodic reporting mechanism.
    * `natural_size_`: Video dimensions.
    * `recorder_`:  The object used to actually send the metrics.
    * `base_component_`, `power_component_`, `controls_component_`, `display_type_component_`:  These "component" objects suggest a modular design for tracking watch time under different conditions. Look at their types (`WatchTimeComponent<T>`). This templated class likely manages the logic for tracking watch time based on a specific property.
    * `background_reporter_`, `muted_reporter_`: Nested reporters for specific cases.

5. **Key Methods and Their Functionality:** Go through the public methods and understand what triggers them and what they do:
    * `OnPlaying()`, `OnPaused()`, `OnSeeking()`:  Control the reporting timer based on playback state.
    * `OnVolumeChange()`: Handles muted/unmuted states, interacts with `muted_reporter_`.
    * `OnShown()`, `OnHidden()`: Handles visibility, interacts with `background_reporter_`.
    * `OnError()`: Reports errors immediately.
    * `OnUnderflow()`, `OnUnderflowComplete()`: Tracks buffering events.
    * `OnNativeControlsEnabled()`, `OnNativeControlsDisabled()`: Track native control usage.
    * `OnDisplayTypeInline()`, `OnDisplayTypeFullscreen()`, `OnDisplayTypePictureInPicture()`: Track display modes.
    * `UpdateSecondaryProperties()`: Handles changes like resolution.
    * `SetAutoplayInitiated()`, `OnDurationChanged()`: Pass through to the `recorder_`.
    * `OnBatteryPowerStatusChange()`:  Handles power source changes.
    * `UpdateWatchTime()`: The core method that runs on the timer, records the watch time, and potentially finalizes metrics.
    * `MaybeStartReportingTimer()`, `MaybeFinalizeWatchTime()`: Manage the timer lifecycle.

6. **`WatchTimeComponent` Analysis:** Understand how the `WatchTimeComponent` works. It seems to track time intervals when a specific condition (e.g., on battery power) is met. The `ValueToKeyCB` helps map the boolean or enum value to a specific metric key.

7. **Relationship to Web Technologies:**  Connect the dots:
    * **JavaScript:**  JavaScript code using the HTML5 `<video>` or `<audio>` APIs triggers playback events (play, pause, seeking, volume changes, fullscreen, etc.). These events eventually lead to calls to the methods of `WatchTimeReporter`.
    * **HTML:** The `<video>` and `<audio>` elements themselves are the source of the media. Attributes like `autoplay`, `muted`, `controls`, and entering/exiting fullscreen influence the state tracked by the reporter.
    * **CSS:** CSS can affect the *visual* presentation, but the `WatchTimeReporter` is primarily concerned with the *playback state* and properties. However, CSS *indirectly* relates to fullscreen and PiP as the user interface might trigger these states. The video size tracked is the *natural* size, not necessarily the CSS-rendered size.

8. **Logical Inferences (Input/Output):**  Think about specific scenarios:
    * **Scenario:** User plays a video, pauses, then plays again. Trace the calls: `OnPlaying`, `OnPaused`, `OnPlaying`. How does the timer behave? When are metrics recorded?
    * **Scenario:** Video starts muted, then is unmuted. Trace the `OnVolumeChange` calls and the interaction with the `muted_reporter_`.
    * **Scenario:**  Video goes into fullscreen. Trace the `OnDisplayTypeFullscreen()` call.

9. **Common Errors:** Consider what could go wrong:
    * **Incorrect Call Sequence:** If the JavaScript player implementation doesn't call the `WatchTimeReporter` methods correctly (e.g., missing an `OnPlaying` or `OnPaused`), the metrics will be inaccurate.
    * **Premature Destruction:** If the `WatchTimeReporter` is destroyed before it can finalize, some data might be lost. The destructor tries to mitigate this.
    * **Inconsistent State:** If the internal state of the `WatchTimeReporter` gets out of sync with the actual playback state, metrics will be wrong. The DCHECKs help catch some of these inconsistencies during development.
    * **Forgetting to Update Properties:** If secondary properties like resolution change and `UpdateSecondaryProperties` isn't called, the metrics might be associated with the wrong video size.

10. **Structure and Refinement:** Organize the findings into logical categories (Functionality, Web Technology Relations, Logical Inferences, Common Errors). Use examples to illustrate the concepts. Ensure clarity and conciseness. The use of headings and bullet points makes the information easier to read and understand.

11. **Review and Verification:** Read through the analysis to ensure accuracy and completeness. Double-check the code snippets and explanations.

This detailed thought process, moving from a high-level understanding to a more granular analysis of the code, allows for a comprehensive and accurate description of the `WatchTimeReporter`'s functionality and its context within the Chromium browser.
这个 `watch_time_reporter.cc` 文件是 Chromium Blink 引擎中负责 **跟踪和报告媒体（主要是视频和音频）播放时长的组件**。它的主要目标是收集各种条件下的观看/收听时间，并将这些数据作为指标上报，用于分析用户如何与媒体内容互动。

以下是该文件的主要功能：

**1. 核心功能：跟踪观看/收听时间**

*   **基于状态的跟踪：**  它会根据媒体的播放状态（播放、暂停、缓冲等）、可见性、音量、是否在后台播放等多种因素来判断何时应该开始或停止计算观看时间。
*   **分组件跟踪：**  它使用 `WatchTimeComponent` 模板类来模块化地跟踪不同条件下的观看时间。例如，它可以分别跟踪在前台播放、后台播放、静音播放、非静音播放、电池供电、交流电供电等情况下的时长。
*   **定期上报：**  通过一个定时器 (`reporting_timer_`)，它会定期地记录当前的播放状态和时间，并将收集到的数据发送到 `media::mojom::MediaMetricsProvider` 进行上报。
*   **处理播放状态变化：** 它监听媒体的各种事件，例如 `OnPlaying()`, `OnPaused()`, `OnSeeking()`, `OnVolumeChange()`, `OnShown()`, `OnHidden()`, `OnError()`，并根据这些事件更新内部状态和开始/停止计时。

**2. 处理特殊情况**

*   **后台播放：**  它专门处理媒体在标签页不可见时（后台）的播放情况，创建一个独立的 `background_reporter_` 来跟踪后台播放时长。
*   **静音播放：**  类似地，它会创建一个 `muted_reporter_` 来跟踪音频/视频静音时的播放时长。
*   **缓冲 (Underflow)：**  它可以跟踪媒体播放过程中发生的缓冲事件 (`OnUnderflow()`, `OnUnderflowComplete()`)，并记录缓冲的次数和总时长。
*   **原生控件：**  它可以跟踪是否使用了浏览器的原生媒体控件 (`OnNativeControlsEnabled()`, `OnNativeControlsDisabled()`)。
*   **显示类型：**  对于视频，它可以跟踪不同的显示类型，如内联、全屏、画中画 (`OnDisplayTypeInline()`, `OnDisplayTypeFullscreen()`, `OnDisplayTypePictureInPicture()`)。
*   **媒体属性变化：**  它可以处理媒体的次要属性变化，例如视频的自然尺寸 (`UpdateSecondaryProperties()`)，这会影响是否应该报告观看时间。

**3. 与 Javascript, HTML, CSS 的关系**

虽然这个 C++ 文件本身不直接包含 Javascript, HTML, CSS 代码，但它的功能与这些 Web 技术息息相关：

*   **Javascript:**
    *   **事件触发：** Javascript 代码通过 HTML5 的 `<video>` 或 `<audio>` 元素控制媒体的播放，例如调用 `play()`, `pause()`, 设置 `volume` 属性，以及进入/退出全屏模式。这些操作会触发 Blink 引擎中的相应事件，最终调用 `WatchTimeReporter` 的方法，例如 `OnPlaying()`, `OnPaused()`, `OnVolumeChange()` 等。
    *   **获取播放时间：**  `WatchTimeReporter` 依赖于传入的 `GetMediaTimeCB` 回调函数来获取当前的媒体播放时间。这个回调函数通常会调用 Javascript 提供的 API，如 `HTMLMediaElement.currentTime`。
    *   **获取管道统计信息：**  对于视频，它使用 `GetPipelineStatsCB` 获取解码帧数、丢帧数等信息，这些信息也可能通过 Javascript API 获取或间接影响。

    **举例说明：**

    ```javascript
    const video = document.getElementById('myVideo');

    video.play(); // 这会触发 blink 引擎中视频播放开始的事件，最终调用 WatchTimeReporter::OnPlaying()

    video.pause(); // 这会触发 blink 引擎中视频播放暂停的事件，最终调用 WatchTimeReporter::OnPaused()

    video.muted = true; // 这会触发音量变化的事件，最终调用 WatchTimeReporter::OnVolumeChange(0)

    video.requestFullscreen(); // 这会触发显示类型变化的事件，最终调用 WatchTimeReporter::OnDisplayTypeFullscreen()
    ```

*   **HTML:**
    *   **媒体元素：**  HTML 的 `<video>` 和 `<audio>` 元素是媒体播放的基础。`WatchTimeReporter` 跟踪的就是这些元素产生的播放行为。
    *   **属性影响：**  `<video>` 和 `<audio>` 元素的属性，例如 `autoplay`、`muted`、`controls` 等，会直接影响 `WatchTimeReporter` 的行为和报告的指标。

    **举例说明：**

    ```html
    <video id="myVideo" src="myvideo.mp4" autoplay muted controls></video>
    ```

    在这个例子中，`autoplay` 和 `muted` 属性会影响 `WatchTimeReporter` 初始化时的状态和后续的跟踪逻辑。 `controls` 属性的存在可能会影响是否启用原生控件的报告。

*   **CSS:**
    *   **间接影响：** CSS 可以控制媒体元素的显示和布局，例如视频的大小、是否隐藏等。虽然 CSS 不直接调用 `WatchTimeReporter` 的方法，但用户与 CSS 样式控制的媒体的交互（例如，通过 CSS 控制进入全屏）可能会间接触发 `WatchTimeReporter` 的状态变化。
    *   **不直接关联：**  需要注意的是，`WatchTimeReporter` 主要关注的是媒体的 *播放状态* 和 *属性*，而不是 CSS 样式本身。它跟踪的是逻辑上的播放时长，而不是基于像素可见性的时长。

**4. 逻辑推理 (假设输入与输出)**

假设我们有一个简单的视频播放场景：

**假设输入：**

1. 用户在一个可见的标签页中播放一个非静音的视频。
2. 视频播放了 5 秒。
3. 用户暂停了视频。

**预期输出（部分）：**

*   `WatchTimeReporter::OnPlaying()` 被调用。
*   `WatchTimeReporter` 内部的定时器开始计时。
*   在定时器触发时，或者在 `OnPaused()` 被调用时，`WatchTimeReporter` 会记录大约 5 秒的非静音、前台观看时长。
*   上报的指标中，对应 `kAudioVideo` 或 `kVideo` (取决于是否有音频) 的 `All` key 会增加大约 5 秒。

**更复杂的例子：**

**假设输入：**

1. 用户播放一个视频。
2. 视频播放 2 秒后，用户最小化了浏览器窗口（标签页变为不可见）。
3. 视频在后台播放了 3 秒。
4. 用户恢复了浏览器窗口。
5. 视频又播放了 4 秒。

**预期输出（部分）：**

*   `OnPlaying()` 被调用。
*   `OnHidden()` 被调用。
*   `background_reporter_` 的 `OnPlaying()` 被调用。
*   `background_reporter_` 会记录 3 秒的后台播放时长。
*   `OnShown()` 被调用。
*   `OnPlaying()` 再次被调用。
*   `WatchTimeReporter` 会记录 2 秒的前台播放时长。
*   `WatchTimeReporter` 会记录 4 秒的前台播放时长。
*   最终上报的指标中，`kAudioVideoBackgroundAll` 或 `kVideoBackgroundAll` 会增加 3 秒，而 `kAudioVideoAll` 或 `kVideoAll` 会增加 6 秒。

**5. 用户或编程常见的使用错误**

*   **未正确调用 `WatchTimeReporter` 的方法：**  如果媒体播放器的实现没有正确地将播放状态变化同步到 `WatchTimeReporter`，例如，播放开始时没有调用 `OnPlaying()`，或者暂停时没有调用 `OnPaused()`，那么收集到的观看时长数据将会不准确。
*   **在 `WatchTimeReporter` 被销毁后访问：**  如果在媒体播放结束后，或者在关联的媒体元素被移除后，仍然尝试调用 `WatchTimeReporter` 的方法，会导致程序崩溃或其他未定义的行为。
*   **假设 `WatchTimeReporter` 会自动处理所有情况：**  开发者需要理解 `WatchTimeReporter` 的工作原理，并确保在各种场景下都正确地调用其方法。例如，如果开发者自己实现了全屏控制，他们需要确保在全屏状态变化时调用 `OnDisplayTypeFullscreen()` 和 `OnDisplayTypeInline()`。
*   **忽略错误处理：**  虽然 `WatchTimeReporter` 有 `OnError()` 方法，但上层代码需要正确地处理媒体播放过程中发生的错误，并调用 `OnError()` 将错误信息传递给 `WatchTimeReporter` 以便记录。
*   **不理解后台和静音报告器的作用：**  开发者可能错误地认为主 `WatchTimeReporter` 会处理所有情况，而忽略了 `background_reporter_` 和 `muted_reporter_` 的作用，导致后台或静音播放时长没有被正确记录。
*   **忘记更新次要属性：** 如果视频的自然尺寸发生变化（例如，通过 Media Source Extensions (MSE)），但没有调用 `UpdateSecondaryProperties()`，可能会导致后续的观看时间被错误地关联到旧的尺寸，从而影响指标的准确性。

总而言之，`blink/common/media/watch_time_reporter.cc` 是一个复杂但关键的组件，用于精确地跟踪媒体播放时长，并为 Chromium 的媒体指标收集提供基础数据。它通过监听各种播放事件和状态变化，以及与 Javascript 和 HTML 的交互，来实现其功能。正确地使用和理解这个组件对于准确地分析用户媒体消费行为至关重要。

### 提示词
```
这是目录为blink/common/media/watch_time_reporter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/media/watch_time_reporter.h"

#include <numeric>
#include <vector>

#include "base/functional/bind.h"
#include "base/power_monitor/power_monitor.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "media/base/pipeline_status.h"
#include "media/base/timestamp_constants.h"
#include "media/base/watch_time_keys.h"

namespace blink {

// The minimum width and height of videos to report watch time metrics for.
constexpr gfx::Size kMinimumVideoSize = gfx::Size(200, 140);

static bool IsOnBatteryPower() {
  auto* power_monitor = base::PowerMonitor::GetInstance();
  if (!power_monitor->IsInitialized()) {
    return false;
  }
  return power_monitor->GetBatteryPowerStatus() ==
         base::PowerStateObserver::BatteryPowerStatus::kBatteryPower;
}

// Helper function for managing property changes. If the watch time timer is
// running it sets the pending value otherwise it sets the current value and
// then returns true if the component needs finalize.
enum class PropertyAction { kNoActionRequired, kFinalizeRequired };
template <typename T>
PropertyAction HandlePropertyChange(T new_value,
                                    bool is_timer_running,
                                    WatchTimeComponent<T>* component) {
  if (!component)
    return PropertyAction::kNoActionRequired;

  if (is_timer_running)
    component->SetPendingValue(new_value);
  else
    component->SetCurrentValue(new_value);

  return component->NeedsFinalize() ? PropertyAction::kFinalizeRequired
                                    : PropertyAction::kNoActionRequired;
}

WatchTimeReporter::WatchTimeReporter(
    media::mojom::PlaybackPropertiesPtr properties,
    const gfx::Size& natural_size,
    GetMediaTimeCB get_media_time_cb,
    GetPipelineStatsCB get_pipeline_stats_cb,
    media::mojom::MediaMetricsProvider* provider,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    const base::TickClock* tick_clock)
    : WatchTimeReporter(std::move(properties),
                        false /* is_background */,
                        false /* is_muted */,
                        natural_size,
                        std::move(get_media_time_cb),
                        std::move(get_pipeline_stats_cb),
                        provider,
                        task_runner,
                        tick_clock) {}

WatchTimeReporter::WatchTimeReporter(
    media::mojom::PlaybackPropertiesPtr properties,
    bool is_background,
    bool is_muted,
    const gfx::Size& natural_size,
    GetMediaTimeCB get_media_time_cb,
    GetPipelineStatsCB get_pipeline_stats_cb,
    media::mojom::MediaMetricsProvider* provider,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    const base::TickClock* tick_clock)
    : properties_(std::move(properties)),
      is_background_(is_background),
      is_muted_(is_muted),
      get_media_time_cb_(std::move(get_media_time_cb)),
      get_pipeline_stats_cb_(std::move(get_pipeline_stats_cb)),
      reporting_timer_(tick_clock),
      natural_size_(natural_size) {
  DCHECK(get_media_time_cb_);
  DCHECK(get_pipeline_stats_cb_);
  DCHECK(properties_->has_audio || properties_->has_video);
  DCHECK_EQ(is_background, properties_->is_background);

  // The background reporter receives play/pause events instead of visibility
  // changes, so it must always be visible to function correctly.
  if (is_background_)
    DCHECK(is_visible_);

  // The muted reporter receives play/pause events instead of volume changes, so
  // its volume must always be audible to function correctly.
  if (is_muted_)
    DCHECK_EQ(volume_, 1.0);

  base::PowerMonitor::GetInstance()->AddPowerStateObserver(this);

  provider->AcquireWatchTimeRecorder(properties_->Clone(),
                                     recorder_.BindNewPipeAndPassReceiver());

  reporting_timer_.SetTaskRunner(task_runner);

  base_component_ = CreateBaseComponent();
  power_component_ = CreatePowerComponent();
  if (!is_background_) {
    controls_component_ = CreateControlsComponent();
    if (properties_->has_video)
      display_type_component_ = CreateDisplayTypeComponent();
  }

  // If this is a sub-reporter we're done.
  if (is_background_ || is_muted_)
    return;

  // Background watch time is reported by creating an background only watch time
  // reporter which receives play when hidden and pause when shown. This avoids
  // unnecessary complexity inside the UpdateWatchTime() for handling this case.
  auto prop_copy = properties_.Clone();
  prop_copy->is_background = true;
  background_reporter_.reset(new WatchTimeReporter(
      std::move(prop_copy), true /* is_background */, false /* is_muted */,
      natural_size_, get_media_time_cb_, get_pipeline_stats_cb_, provider,
      task_runner, tick_clock));

  // Muted watch time is only reported for audio+video playback.
  if (!properties_->has_video || !properties_->has_audio)
    return;

  // Similar to the above, muted watch time is reported by creating a muted only
  // watch time reporter which receives play when muted and pause when audible.
  prop_copy = properties_.Clone();
  prop_copy->is_muted = true;
  muted_reporter_.reset(new WatchTimeReporter(
      std::move(prop_copy), false /* is_background */, true /* is_muted */,
      natural_size_, get_media_time_cb_, get_pipeline_stats_cb_, provider,
      task_runner, tick_clock));
}

WatchTimeReporter::~WatchTimeReporter() {
  background_reporter_.reset();
  muted_reporter_.reset();

  // This is our last chance, so finalize now if there's anything remaining.
  in_shutdown_ = true;
  MaybeFinalizeWatchTime(FinalizeTime::IMMEDIATELY);
  base::PowerMonitor::GetInstance()->RemovePowerStateObserver(this);
}

void WatchTimeReporter::OnPlaying() {
  if (background_reporter_ && !is_visible_)
    background_reporter_->OnPlaying();
  if (muted_reporter_ && !volume_)
    muted_reporter_->OnPlaying();

  is_playing_ = true;
  is_seeking_ = false;
  MaybeStartReportingTimer(get_media_time_cb_.Run());
}

void WatchTimeReporter::OnPaused() {
  if (background_reporter_)
    background_reporter_->OnPaused();
  if (muted_reporter_)
    muted_reporter_->OnPaused();

  is_playing_ = false;
  MaybeFinalizeWatchTime(FinalizeTime::ON_NEXT_UPDATE);
}

void WatchTimeReporter::OnSeeking() {
  if (background_reporter_)
    background_reporter_->OnSeeking();
  if (muted_reporter_)
    muted_reporter_->OnSeeking();

  // Seek is a special case that does not have hysteresis, when this is called
  // the seek is imminent, so finalize the previous playback immediately.
  is_seeking_ = true;
  MaybeFinalizeWatchTime(FinalizeTime::IMMEDIATELY);
}

void WatchTimeReporter::OnVolumeChange(double volume) {
  if (background_reporter_)
    background_reporter_->OnVolumeChange(volume);

  // The muted reporter should never receive volume changes.
  DCHECK(!is_muted_);

  const double old_volume = volume_;
  volume_ = volume;

  // We're only interesting in transitions in and out of the muted state.
  if (!old_volume && volume) {
    if (muted_reporter_)
      muted_reporter_->OnPaused();
    MaybeStartReportingTimer(get_media_time_cb_.Run());
  } else if (old_volume && !volume_) {
    if (muted_reporter_ && is_playing_)
      muted_reporter_->OnPlaying();
    MaybeFinalizeWatchTime(FinalizeTime::ON_NEXT_UPDATE);
  }
}

void WatchTimeReporter::OnShown() {
  // The background reporter should never receive visibility changes.
  DCHECK(!is_background_);

  if (background_reporter_)
    background_reporter_->OnPaused();
  if (muted_reporter_)
    muted_reporter_->OnShown();

  is_visible_ = true;
  MaybeStartReportingTimer(get_media_time_cb_.Run());
}

void WatchTimeReporter::OnHidden() {
  // The background reporter should never receive visibility changes.
  DCHECK(!is_background_);

  if (background_reporter_ && is_playing_)
    background_reporter_->OnPlaying();
  if (muted_reporter_)
    muted_reporter_->OnHidden();

  is_visible_ = false;
  MaybeFinalizeWatchTime(FinalizeTime::ON_NEXT_UPDATE);
}

void WatchTimeReporter::OnError(media::PipelineStatus status) {
  // Since playback should have stopped by this point, go ahead and send the
  // error directly instead of on the next timer tick. It won't be recorded
  // until finalization anyways.
  recorder_->OnError(status);
  if (background_reporter_)
    background_reporter_->OnError(status);
  if (muted_reporter_)
    muted_reporter_->OnError(status);
}

void WatchTimeReporter::OnUnderflow() {
  if (background_reporter_)
    background_reporter_->OnUnderflow();
  if (muted_reporter_)
    muted_reporter_->OnUnderflow();

  if (!reporting_timer_.IsRunning())
    return;

  if (!pending_underflow_events_.empty())
    DCHECK_NE(pending_underflow_events_.back().duration, media::kNoTimestamp);

  // In the event of a pending finalize, we don't want to count underflow events
  // that occurred after the finalize time. Yet if the finalize is canceled we
  // want to ensure they are all recorded.
  pending_underflow_events_.push_back(
      {false, get_media_time_cb_.Run(), media::kNoTimestamp});
}

void WatchTimeReporter::OnUnderflowComplete(base::TimeDelta elapsed) {
  if (background_reporter_)
    background_reporter_->OnUnderflowComplete(elapsed);
  if (muted_reporter_)
    muted_reporter_->OnUnderflowComplete(elapsed);

  if (!reporting_timer_.IsRunning())
    return;

  // Drop this underflow completion if we don't have a corresponding underflow
  // start event; this can happen if a finalize occurs between the underflow and
  // the completion.
  if (pending_underflow_events_.empty())
    return;

  // There should only ever be one outstanding underflow, so stick the duration
  // in the last underflow event.
  DCHECK_EQ(pending_underflow_events_.back().duration, media::kNoTimestamp);
  pending_underflow_events_.back().duration = elapsed;
}

void WatchTimeReporter::OnNativeControlsEnabled() {
  OnNativeControlsChanged(true);
}

void WatchTimeReporter::OnNativeControlsDisabled() {
  OnNativeControlsChanged(false);
}

void WatchTimeReporter::OnDisplayTypeInline() {
  OnDisplayTypeChanged(DisplayType::kInline);
}

void WatchTimeReporter::OnDisplayTypeFullscreen() {
  OnDisplayTypeChanged(DisplayType::kFullscreen);
}

void WatchTimeReporter::OnDisplayTypePictureInPicture() {
  OnDisplayTypeChanged(DisplayType::kPictureInPicture);
}

void WatchTimeReporter::UpdateSecondaryProperties(
    media::mojom::SecondaryPlaybackPropertiesPtr secondary_properties) {
  // Flush any unrecorded watch time before updating the secondary properties to
  // ensure the UKM record is finalized with up-to-date watch time information.
  if (reporting_timer_.IsRunning())
    RecordWatchTime();

  recorder_->UpdateSecondaryProperties(secondary_properties.Clone());
  if (background_reporter_) {
    background_reporter_->UpdateSecondaryProperties(
        secondary_properties.Clone());
  }
  if (muted_reporter_)
    muted_reporter_->UpdateSecondaryProperties(secondary_properties.Clone());

  // A change in resolution may affect ShouldReportingTimerRun().
  bool original_should_run = ShouldReportingTimerRun();
  natural_size_ = secondary_properties->natural_size;
  bool should_run = ShouldReportingTimerRun();
  if (original_should_run != should_run) {
    if (should_run) {
      MaybeStartReportingTimer(get_media_time_cb_.Run());
    } else {
      MaybeFinalizeWatchTime(FinalizeTime::ON_NEXT_UPDATE);
    }
  }
}

void WatchTimeReporter::SetAutoplayInitiated(bool autoplay_initiated) {
  recorder_->SetAutoplayInitiated(autoplay_initiated);
  if (background_reporter_)
    background_reporter_->SetAutoplayInitiated(autoplay_initiated);
  if (muted_reporter_)
    muted_reporter_->SetAutoplayInitiated(autoplay_initiated);
}

void WatchTimeReporter::OnDurationChanged(base::TimeDelta duration) {
  recorder_->OnDurationChanged(duration);
  if (background_reporter_)
    background_reporter_->OnDurationChanged(duration);
  if (muted_reporter_)
    muted_reporter_->OnDurationChanged(duration);
}

void WatchTimeReporter::OnBatteryPowerStatusChange(
    base::PowerStateObserver::BatteryPowerStatus battery_power_status) {
  bool battery_power =
      (battery_power_status ==
       base::PowerStateObserver::BatteryPowerStatus::kBatteryPower);
  if (HandlePropertyChange<bool>(battery_power, reporting_timer_.IsRunning(),
                                 power_component_.get()) ==
      PropertyAction::kFinalizeRequired) {
    RestartTimerForHysteresis();
  }
}

void WatchTimeReporter::OnNativeControlsChanged(bool has_native_controls) {
  if (muted_reporter_)
    muted_reporter_->OnNativeControlsChanged(has_native_controls);

  if (HandlePropertyChange<bool>(
          has_native_controls, reporting_timer_.IsRunning(),
          controls_component_.get()) == PropertyAction::kFinalizeRequired) {
    RestartTimerForHysteresis();
  }
}

void WatchTimeReporter::OnDisplayTypeChanged(DisplayType display_type) {
  if (muted_reporter_)
    muted_reporter_->OnDisplayTypeChanged(display_type);

  if (HandlePropertyChange<DisplayType>(
          display_type, reporting_timer_.IsRunning(),
          display_type_component_.get()) == PropertyAction::kFinalizeRequired) {
    RestartTimerForHysteresis();
  }
}

bool WatchTimeReporter::ShouldReportWatchTime() const {
  // Report listen time or watch time for videos of sufficient size.
  return properties_->has_video
             ? (natural_size_.height() >= kMinimumVideoSize.height() &&
                natural_size_.width() >= kMinimumVideoSize.width())
             : properties_->has_audio;
}

bool WatchTimeReporter::ShouldReportingTimerRun() const {
  // TODO(dalecurtis): We should only consider |volume_| when there is actually
  // an audio track; requires updating lots of tests to fix.
  return ShouldReportWatchTime() && is_playing_ && volume_ && is_visible_ &&
         !in_shutdown_ && !is_seeking_ && has_valid_start_timestamp_;
}

void WatchTimeReporter::MaybeStartReportingTimer(
    base::TimeDelta start_timestamp) {
  DCHECK_GE(start_timestamp, base::TimeDelta());

  // It's possible for |current_time| to be kInfiniteDuration here if the page
  // seeks to kInfiniteDuration (2**64 - 1) when Duration() is infinite. There
  // is no possible elapsed watch time when this occurs, so don't start the
  // WatchTimeReporter at this time. If a later seek puts us earlier in the
  // stream this method will be called again after OnSeeking().
  has_valid_start_timestamp_ = start_timestamp != media::kInfiniteDuration;

  // Don't start the timer if our state indicates we shouldn't; this check is
  // important since the various event handlers do not have to care about the
  // state of other events.
  const bool should_start = ShouldReportingTimerRun();
  if (reporting_timer_.IsRunning()) {
    base_component_->SetPendingValue(should_start);
    return;
  }

  base_component_->SetCurrentValue(should_start);
  if (!should_start)
    return;

  if (properties_->has_video) {
    initial_stats_ = get_pipeline_stats_cb_.Run();
    last_stats_ = media::PipelineStatistics();
  }

  ResetUnderflowState();
  base_component_->OnReportingStarted(start_timestamp);
  power_component_->OnReportingStarted(start_timestamp);

  if (controls_component_)
    controls_component_->OnReportingStarted(start_timestamp);
  if (display_type_component_)
    display_type_component_->OnReportingStarted(start_timestamp);

  reporting_timer_.Start(FROM_HERE, reporting_interval_, this,
                         &WatchTimeReporter::UpdateWatchTime);
}

void WatchTimeReporter::MaybeFinalizeWatchTime(FinalizeTime finalize_time) {
  if (HandlePropertyChange<bool>(
          ShouldReportingTimerRun(), reporting_timer_.IsRunning(),
          base_component_.get()) == PropertyAction::kNoActionRequired) {
    return;
  }

  if (finalize_time == FinalizeTime::IMMEDIATELY) {
    UpdateWatchTime();
    return;
  }

  // Always restart the timer when finalizing, so that we allow for the full
  // length of |kReportingInterval| to elapse for hysteresis purposes.
  DCHECK_EQ(finalize_time, FinalizeTime::ON_NEXT_UPDATE);
  RestartTimerForHysteresis();
}

void WatchTimeReporter::RestartTimerForHysteresis() {
  // Restart the reporting timer so the full hysteresis is afforded.
  DCHECK(reporting_timer_.IsRunning());
  reporting_timer_.Start(FROM_HERE, reporting_interval_, this,
                         &WatchTimeReporter::UpdateWatchTime);
}

void WatchTimeReporter::RecordWatchTime() {
  // If we're finalizing, use the media time at time of finalization.
  const base::TimeDelta current_timestamp =
      base_component_->NeedsFinalize() ? base_component_->end_timestamp()
                                       : get_media_time_cb_.Run();

  // Pass along any underflow events which have occurred since the last report.
  if (!pending_underflow_events_.empty()) {
    const int last_underflow_count = total_underflow_count_;
    const int last_completed_underflow_count = total_completed_underflow_count_;

    for (auto& ufe : pending_underflow_events_) {
      // Since the underflow occurred after finalize, ignore the event and mark
      // it for deletion.
      if (ufe.timestamp > current_timestamp) {
        ufe.reported = true;
        ufe.duration = base::TimeDelta();
        continue;
      }

      if (!ufe.reported) {
        ufe.reported = true;
        ++total_underflow_count_;
      }

      // Drop any rebuffer completions that took more than a minute. For our
      // purposes these are considered as timeouts. We want a maximum since
      // rebuffer duration is in real time and not media time, which means if
      // the rebuffer spans a suspend/resume the time can be arbitrarily long.
      constexpr base::TimeDelta kMaximumRebufferDuration = base::Minutes(1);
      if (ufe.duration != media::kNoTimestamp &&
          ufe.duration <= kMaximumRebufferDuration) {
        ++total_completed_underflow_count_;
        total_underflow_duration_ += ufe.duration;
      }
    }

    std::erase_if(pending_underflow_events_, [](const UnderflowEvent& ufe) {
      return ufe.reported && ufe.duration != media::kNoTimestamp;
    });

    if (last_underflow_count != total_underflow_count_)
      recorder_->UpdateUnderflowCount(total_underflow_count_);
    if (last_completed_underflow_count != total_completed_underflow_count_) {
      recorder_->UpdateUnderflowDuration(total_completed_underflow_count_,
                                         total_underflow_duration_);
    }
  }

  if (properties_->has_video) {
    auto stats = get_pipeline_stats_cb_.Run();
    DCHECK_GE(stats.video_frames_decoded, initial_stats_.video_frames_decoded);
    DCHECK_GE(stats.video_frames_dropped, initial_stats_.video_frames_dropped);

    // Offset the stats based on where they were when we started reporting.
    stats.video_frames_decoded -= initial_stats_.video_frames_decoded;
    stats.video_frames_dropped -= initial_stats_.video_frames_dropped;

    // Only send updates.
    if (last_stats_.video_frames_decoded != stats.video_frames_decoded ||
        last_stats_.video_frames_dropped != stats.video_frames_dropped) {
      recorder_->UpdateVideoDecodeStats(stats.video_frames_decoded,
                                        stats.video_frames_dropped);
      last_stats_ = stats;
    }
  }

  // Record watch time for all components.
  base_component_->RecordWatchTime(current_timestamp);
  power_component_->RecordWatchTime(current_timestamp);
  if (display_type_component_)
    display_type_component_->RecordWatchTime(current_timestamp);
  if (controls_component_)
    controls_component_->RecordWatchTime(current_timestamp);
}

void WatchTimeReporter::UpdateWatchTime() {
  // First record watch time.
  RecordWatchTime();

  // Second, process any pending finalize events.
  std::vector<media::WatchTimeKey> keys_to_finalize;
  if (power_component_->NeedsFinalize())
    power_component_->Finalize(&keys_to_finalize);
  if (display_type_component_ && display_type_component_->NeedsFinalize())
    display_type_component_->Finalize(&keys_to_finalize);
  if (controls_component_ && controls_component_->NeedsFinalize())
    controls_component_->Finalize(&keys_to_finalize);

  // Then finalize the base component.
  if (!base_component_->NeedsFinalize()) {
    if (!keys_to_finalize.empty())
      recorder_->FinalizeWatchTime(keys_to_finalize);
    return;
  }

  // Always send finalize, even if we don't currently have any data, it's
  // harmless to send since nothing will be logged if we've already finalized.
  base_component_->Finalize(&keys_to_finalize);
  recorder_->FinalizeWatchTime({});

  // Stop the timer if this is supposed to be our last tick.
  ResetUnderflowState();
  reporting_timer_.Stop();
}

void WatchTimeReporter::ResetUnderflowState() {
  total_underflow_count_ = total_completed_underflow_count_ = 0;
  total_underflow_duration_ = base::TimeDelta();
  pending_underflow_events_.clear();
}

#define NORMAL_KEY(key)                                                     \
  ((properties_->has_video && properties_->has_audio)                       \
       ? (is_background_                                                    \
              ? media::WatchTimeKey::kAudioVideoBackground##key             \
              : (is_muted_ ? media::WatchTimeKey::kAudioVideoMuted##key     \
                           : media::WatchTimeKey::kAudioVideo##key))        \
       : properties_->has_video                                             \
             ? (is_background_ ? media::WatchTimeKey::kVideoBackground##key \
                               : media::WatchTimeKey::kVideo##key)          \
             : (is_background_ ? media::WatchTimeKey::kAudioBackground##key \
                               : media::WatchTimeKey::kAudio##key))

std::unique_ptr<WatchTimeComponent<bool>>
WatchTimeReporter::CreateBaseComponent() {
  std::vector<media::WatchTimeKey> keys_to_finalize;
  keys_to_finalize.emplace_back(NORMAL_KEY(All));

  if (properties_->has_video && properties_->has_audio && !is_background_ &&
      !is_muted_ &&
      properties_->renderer_type == media::RendererType::kMediaFoundation) {
    keys_to_finalize.emplace_back(
        media::WatchTimeKey::kAudioVideoMediaFoundationAll);
    if (properties_->is_eme) {
      keys_to_finalize.emplace_back(
          media::WatchTimeKey::kAudioVideoMediaFoundationEme);
    }
  }

  if (properties_->is_mse)
    keys_to_finalize.emplace_back(NORMAL_KEY(Mse));
  else
    keys_to_finalize.emplace_back(NORMAL_KEY(Src));

  if (properties_->is_eme)
    keys_to_finalize.emplace_back(NORMAL_KEY(Eme));

  if (properties_->is_embedded_media_experience)
    keys_to_finalize.emplace_back(NORMAL_KEY(EmbeddedExperience));

  return std::make_unique<WatchTimeComponent<bool>>(
      false, std::move(keys_to_finalize),
      WatchTimeComponent<bool>::ValueToKeyCB(), get_media_time_cb_,
      recorder_.get());
}

std::unique_ptr<WatchTimeComponent<bool>>
WatchTimeReporter::CreatePowerComponent() {
  std::vector<media::WatchTimeKey> keys_to_finalize{NORMAL_KEY(Battery),
                                                    NORMAL_KEY(Ac)};

  return std::make_unique<WatchTimeComponent<bool>>(
      IsOnBatteryPower(), std::move(keys_to_finalize),
      base::BindRepeating(&WatchTimeReporter::GetPowerKey,
                          base::Unretained(this)),
      get_media_time_cb_, recorder_.get());
}

media::WatchTimeKey WatchTimeReporter::GetPowerKey(bool is_on_battery_power) {
  return is_on_battery_power ? NORMAL_KEY(Battery) : NORMAL_KEY(Ac);
}
#undef NORMAL_KEY

#define FOREGROUND_KEY(key)                                        \
  ((properties_->has_video && properties_->has_audio)              \
       ? (is_muted_ ? media::WatchTimeKey::kAudioVideoMuted##key   \
                    : media::WatchTimeKey::kAudioVideo##key)       \
       : properties_->has_audio ? media::WatchTimeKey::kAudio##key \
                                : media::WatchTimeKey::kVideo##key)

std::unique_ptr<WatchTimeComponent<bool>>
WatchTimeReporter::CreateControlsComponent() {
  DCHECK(!is_background_);

  std::vector<media::WatchTimeKey> keys_to_finalize{
      FOREGROUND_KEY(NativeControlsOn), FOREGROUND_KEY(NativeControlsOff)};

  return std::make_unique<WatchTimeComponent<bool>>(
      false, std::move(keys_to_finalize),
      base::BindRepeating(&WatchTimeReporter::GetControlsKey,
                          base::Unretained(this)),
      get_media_time_cb_, recorder_.get());
}

media::WatchTimeKey WatchTimeReporter::GetControlsKey(
    bool has_native_controls) {
  return has_native_controls ? FOREGROUND_KEY(NativeControlsOn)
                             : FOREGROUND_KEY(NativeControlsOff);
}

#undef FOREGROUND_KEY

#define DISPLAY_TYPE_KEY(key)                                    \
  (properties_->has_audio                                        \
       ? (is_muted_ ? media::WatchTimeKey::kAudioVideoMuted##key \
                    : media::WatchTimeKey::kAudioVideo##key)     \
       : media::WatchTimeKey::kVideo##key)

std::unique_ptr<WatchTimeComponent<DisplayType>>
WatchTimeReporter::CreateDisplayTypeComponent() {
  DCHECK(properties_->has_video);
  DCHECK(!is_background_);

  std::vector<media::WatchTimeKey> keys_to_finalize{
      DISPLAY_TYPE_KEY(DisplayInline), DISPLAY_TYPE_KEY(DisplayFullscreen),
      DISPLAY_TYPE_KEY(DisplayPictureInPicture)};

  return std::make_unique<WatchTimeComponent<DisplayType>>(
      DisplayType::kInline, std::move(keys_to_finalize),
      base::BindRepeating(&WatchTimeReporter::GetDisplayTypeKey,
                          base::Unretained(this)),
      get_media_time_cb_, recorder_.get());
}

media::WatchTimeKey WatchTimeReporter::GetDisplayTypeKey(
    DisplayType display_type) {
  switch (display_type) {
    case DisplayType::kInline:
      return DISPLAY_TYPE_KEY(DisplayInline);
    case DisplayType::kFullscreen:
      return DISPLAY_TYPE_KEY(DisplayFullscreen);
    case DisplayType::kPictureInPicture:
      return DISPLAY_TYPE_KEY(DisplayPictureInPicture);
  }
}

#undef DISPLAY_TYPE_KEY

}  // namespace blink
```