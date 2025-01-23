Response:
Let's break down the thought process for analyzing the `autoplay_uma_helper.cc` file.

1. **Understand the Core Purpose:** The name "autoplay_uma_helper" immediately suggests its main job: collecting and reporting User Metrics Analysis (UMA) related to the autoplay feature of media elements. The file path `blink/renderer/core/html/media/` reinforces this connection to HTML media elements.

2. **Identify Key Components and Data:**  Scan the `#include` directives and member variables in the class definition. This helps identify the core concepts the class interacts with:
    * **UMA/UKM:**  `base/metrics/histogram_functions.h`, `services/metrics/public/cpp/ukm_builders.h`, `services/metrics/public/cpp/ukm_recorder.h`. This confirms the UMA/UKM reporting purpose.
    * **DOM Elements:** `third_party/blink/renderer/core/dom/document.h`, `third_party/blink/renderer/core/html/media/html_media_element.h`, `third_party/blink/renderer/core/html/media/html_video_element.h`. This points to the class working with media elements in the DOM.
    * **Frames and Execution Contexts:** `third_party/blink/renderer/core/frame/local_frame.h`, `third_party/blink/renderer/core/execution_context/execution_context.h`. Indicates interaction within the browser's frame structure.
    * **Autoplay Policy:** `third_party/blink/renderer/core/html/media/autoplay_policy.h`. This is crucial for understanding the context of the metrics being collected.
    * **Intersection Observer:** `third_party/blink/renderer/core/intersection_observer/intersection_observer.h`, `third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h`. This suggests tracking visibility of media elements.
    * **Events:** `third_party/blink/renderer/core/dom/events/event.h`. Implies the class listens for and reacts to events like "playing" and "pause".
    * **Use Counters:** `third_party/blink/renderer/platform/instrumentation/use_counter.h`. Indicates tracking usage of specific features.

3. **Analyze Key Methods:**  Go through the public methods and significant private methods to understand the workflow:
    * **Constructor/Destructor:** Basic initialization and cleanup.
    * **`OnAutoplayInitiated()`:**  Central method for recording when autoplay starts and the source of the initiation. This is a primary entry point for metric collection. Notice the recording of both UMA histograms and UKM events.
    * **`RecordAutoplayUnmuteStatus()`:** Specifically handles recording the outcome of user attempts to unmute autoplayed videos.
    * **`VideoWillBeDrawnToCanvas()`:**  Tracks when a hidden autoplayed video is about to become visible on a canvas.
    * **Intersection Observer related methods (`OnIntersectionChangedForMutedVideoPlayMethodBecomeVisible`, `OnIntersectionChangedForMutedVideoOffscreenDuration`):**  These methods are the core of tracking visibility for muted autoplayed videos. They use the Intersection Observer API.
    * **Event Handlers (`Invoke`, `HandlePlayingEvent`, `HandlePauseEvent`):**  These show how the helper reacts to media playback events. Note how event listeners are added and removed.
    * **Context Management (`DidMoveToNewDocument`, `ContextDestroyed`, `HandleContextDestroyed`):**  Ensures the helper cleans up and re-registers listeners when the document or context changes.
    * **`MaybeStartRecording...` and `MaybeStopRecording...` methods:** These manage the lifecycle of the Intersection Observers, starting them when needed and stopping them to avoid unnecessary overhead.

4. **Identify Relationships with Web Technologies:** Based on the analysis of key components and methods, connect the functionality to HTML, CSS, and JavaScript:
    * **HTML:** The core of the interaction is with `<video>` and `<audio>` elements. Autoplay is an HTML attribute. The Intersection Observer interacts with the layout and rendering of HTML elements.
    * **CSS:** While not directly interacting with CSS properties, the *visibility* tracked by the Intersection Observer is influenced by CSS styles (e.g., `display: none`, `visibility: hidden`, `opacity: 0`).
    * **JavaScript:** JavaScript can trigger autoplay through methods like `play()`. The helper records whether autoplay was initiated by a script. JavaScript can also interact with the Intersection Observer API directly. User gestures, often initiated via JavaScript event listeners, play a crucial role in autoplay policies.

5. **Formulate Examples:** Create concrete examples to illustrate the interactions. These should cover:
    * How autoplay attributes in HTML trigger metric recording.
    * How JavaScript's `play()` method is tracked.
    * How the Intersection Observer interacts with visibility changes caused by scrolling or CSS.
    * Common user errors related to autoplay blocking and the helper's role in tracking these scenarios.

6. **Consider Logical Reasoning and Assumptions:**  Think about the conditions under which certain metrics are recorded. For example, the offscreen duration is only recorded for *muted* videos that started playing via the method. Formulate assumptions and predict the input and output of specific scenarios.

7. **Identify Potential Usage Errors:** Think about common mistakes developers might make regarding autoplay and how this helper helps identify those issues:
    * Not understanding browser autoplay policies.
    * Relying on autoplay without considering user experience.
    * Not handling autoplay blocking gracefully.

8. **Structure the Output:** Organize the information logically with clear headings and bullet points. Start with the main functions, then delve into relationships with web technologies, examples, logical reasoning, and potential errors. This makes the information easier to understand.

9. **Review and Refine:** Read through the analysis to ensure accuracy and clarity. Correct any misinterpretations or omissions. Ensure the language is precise and avoids jargon where possible. For example, initially, I might have focused too heavily on just the UMA part, but realizing the UKM integration is important adds to the completeness of the analysis. Similarly, explicitly connecting the visibility tracking to CSS influence strengthens the explanation.
这个 `autoplay_uma_helper.cc` 文件是 Chromium Blink 引擎中负责收集和上报与 HTML `<video>` 和 `<audio>` 元素的自动播放 (autoplay) 行为相关的用户指标 (User Metrics Analysis, UMA) 和 UKM (User Keyed Metrics) 的辅助类。它的主要目的是帮助开发者了解网页中自动播放功能的使用情况以及用户与自动播放的交互方式。

以下是该文件的主要功能，并结合 JavaScript, HTML, CSS 进行了举例说明：

**主要功能:**

1. **记录自动播放的来源 (Autoplay Source):**  该类会记录导致媒体元素开始自动播放的原因，例如：
    * **HTML 属性 (Attribute):**  `<video autoplay>` 或 `<audio autoplay>` 属性。
    * **JavaScript 方法 (Method):**  通过 JavaScript 调用 `video.play()` 或 `audio.play()` 方法。
    * **双重来源 (Dual Source):**  同时使用了 HTML 属性和 JavaScript 方法。

   **与 HTML 的关系举例:**

   ```html
   <!-- 通过 HTML 属性触发自动播放 -->
   <video src="myvideo.mp4" autoplay muted></video>
   ```

   当上述 HTML 加载时，`AutoplayUmaHelper` 会记录到自动播放的来源是 `AutoplaySource::kAttribute`。

   **与 JavaScript 的关系举例:**

   ```javascript
   const video = document.getElementById('myVideo');
   video.play(); // 通过 JavaScript 方法触发自动播放
   ```

   当 JavaScript 调用 `play()` 方法时，`AutoplayUmaHelper` 会记录到自动播放的来源是 `AutoplaySource::kMethod`。

2. **记录自动播放尝试时的状态:**  该类会记录尝试自动播放时的各种上下文信息，以便进行更精细的分析：
    * **是否需要用户手势 (User Gesture Required):** 根据浏览器的自动播放策略，是否需要用户交互（例如点击、触摸）才能播放。
    * **是否静音 (Muted):** 媒体元素是否被静音。
    * **高媒体参与度 (High Media Engagement):**  用户是否与该网站有较高的互动，这会影响浏览器的自动播放策略。
    * **用户手势状态 (User Gesture Status):**  页面上是否存在用户手势，包括：
        * 当前是否有活跃的用户手势 (transient user activation)。
        * 页面上是否曾有过用户手势 (sticky user activation)。
        * 导航后是否保留了用户手势。

   **与 JavaScript 的关系举例:**

   ```javascript
   // 假设用户点击了一个按钮
   document.getElementById('playButton').addEventListener('click', () => {
       const video = document.getElementById('myVideo');
       video.play(); // 此时 User Gesture Status 中会包含用户手势信息
   });
   ```

3. **记录用户取消静音 (Unmute) 的行为:**  对于静音自动播放的视频，如果用户尝试取消静音，该类会记录取消静音操作的状态：
    * **成功 (Success):**  取消静音操作成功。
    * **失败 (Failure):**  取消静音操作失败（可能是由于浏览器的策略限制）。

   **与 JavaScript 的关系举例:**

   ```javascript
   const video = document.getElementById('myVideo');
   video.muted = true; // 设置为静音
   video.play(); // 自动播放

   // 用户点击取消静音按钮
   document.getElementById('unmuteButton').addEventListener('click', () => {
       video.muted = false; // 尝试取消静音
   });
   ```

4. **记录隐藏的自动播放视频出现在 Canvas 中的情况:** 如果一个自动播放的视频最初是不可见的，但随后被绘制到 `<canvas>` 元素中，该类会记录这一事件。这有助于了解某些特殊场景下的自动播放行为。

   **与 HTML 和 JavaScript 的关系举例:**

   ```html
   <video id="hiddenVideo" src="myvideo.mp4" autoplay muted style="display: none;"></video>
   <canvas id="myCanvas"></canvas>

   <script>
       const video = document.getElementById('hiddenVideo');
       const canvas = document.getElementById('myCanvas');
       const ctx = canvas.getContext('2d');

       // 在某个时刻将隐藏的视频绘制到 canvas 上
       function drawVideoToCanvas() {
           ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
           requestAnimationFrame(drawVideoToCanvas); // 持续绘制
       }
       video.addEventListener('playing', drawVideoToCanvas);
   </script>
   ```

5. **记录静音自动播放视频变为可见的时间:**  使用 Intersection Observer API 监测静音自动播放的视频元素何时进入视口，并记录该事件。

   **与 JavaScript 的关系举例:**

   ```javascript
   const video = document.getElementById('myVideo');
   video.muted = true;
   video.autoplay = true;

   const observer = new IntersectionObserver((entries) => {
       entries.forEach(entry => {
           if (entry.isIntersecting) {
               console.log('静音自动播放视频进入视口');
           }
       });
   });

   observer.observe(video);
   ```

6. **记录静音自动播放视频在不可见状态的持续时间:** 使用 Intersection Observer API 监测静音自动播放的视频元素在不可见状态的时间，并将其记录下来。

   **与 CSS 的关系举例 (影响可见性):**

   ```html
   <video id="myVideo" src="myvideo.mp4" autoplay muted style="opacity: 0;"></video>
   ```

   虽然视频正在播放，但由于 CSS 的 `opacity: 0`，它最初是不可见的。`AutoplayUmaHelper` 会记录这段不可见的时间。 同样，`display: none` 或滚动出视口也会影响视频的可见性。

**逻辑推理与假设输入输出:**

假设输入一个包含以下 HTML 的网页：

```html
<!DOCTYPE html>
<html>
<head>
    <title>Autoplay Test</title>
</head>
<body>
    <video id="myVideo" src="test.mp4" autoplay muted></video>
    <button id="unmuteBtn">Unmute</button>
    <script>
        const video = document.getElementById('myVideo');
        const unmuteBtn = document.getElementById('unmuteBtn');

        unmuteBtn.addEventListener('click', () => {
            video.muted = false;
        });
    </script>
</body>
</html>
```

**假设流程与输出:**

1. **页面加载:** `<video autoplay muted>` 导致视频尝试自动播放。
   * **`OnAutoplayInitiated` 被调用:** 记录 `AutoplaySource::kAttribute`，`muted` 为 true，可能记录用户手势状态（如果之前有用户交互）。
   * **UMA 报告:** "Media.Video.Autoplay" 会记录 `kAttribute`。
   * **UKM 记录:** `Media_Autoplay_Attempt` 事件会记录相关信息，例如 `Source` (true, 因为是属性触发), `Muted` (true)。

2. **用户点击 "Unmute" 按钮:**
   * **`RecordAutoplayUnmuteStatus` 被调用:** 记录 `AutoplayUnmuteActionStatus::kSuccess` (假设取消静音成功)。
   * **UMA 报告:** "Media.Video.Autoplay.Muted.UnmuteAction" 会记录 `kSuccess`。
   * **UKM 记录:** `Media_Autoplay_Muted_UnmuteAction` 事件会记录相关信息，例如 `Source` (指示是属性触发的自动播放), `Result` (true, 表示成功)。

**涉及用户或编程常见的使用错误:**

1. **开发者假设自动播放总能成功:**  没有考虑到浏览器的自动播放策略，例如需要用户手势或高媒体参与度。`AutoplayUmaHelper` 的数据可以帮助开发者了解自动播放被阻止的频率，从而调整策略。

   **举例:**  开发者直接在页面加载时使用 `<video autoplay>`，但用户之前没有与该网站互动，导致浏览器阻止自动播放。`AutoplayUmaHelper` 会记录到自动播放尝试，但可能不会记录到 `playing` 事件。

2. **开发者不了解静音自动播放的限制:**  某些浏览器允许静音自动播放，但对非静音自动播放有更严格的限制。`AutoplayUmaHelper` 可以帮助开发者区分这两种情况的成功率。

   **举例:** 开发者希望视频自动播放且有声音，但由于用户没有与页面互动，导致自动播放被阻止。如果开发者改为静音自动播放，`AutoplayUmaHelper` 会记录到静音自动播放的尝试，并可以监测用户是否会主动取消静音。

3. **过度依赖自动播放影响用户体验:**  不恰当的自动播放可能会 раздражать 用户。`AutoplayUmaHelper` 收集的数据可以帮助开发者评估自动播放的使用是否对用户体验产生了负面影响，例如用户是否频繁地关闭或跳过自动播放的内容。

4. **Intersection Observer 使用不当导致误判:**  如果在复杂的页面布局中错误地配置 Intersection Observer，可能会导致静音自动播放视频可见状态的记录不准确。

**总结:**

`autoplay_uma_helper.cc` 是一个幕后工作者，它不直接参与网页的渲染或功能逻辑，而是默默地收集关于自动播放行为的各种指标，并将这些数据上报给 Chromium 团队。这些数据对于理解 Web 生态系统中自动播放的使用情况、浏览器策略的有效性以及开发者如何使用自动播放功能至关重要。开发者虽然不能直接调用这个类的方法，但可以通过遵循最佳实践，例如合理使用 `autoplay` 属性和 JavaScript 的 `play()` 方法，并考虑用户体验，来间接地影响 `AutoplayUmaHelper` 收集到的数据。

### 提示词
```
这是目录为blink/renderer/core/html/media/autoplay_uma_helper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/autoplay_uma_helper.h"

#include "base/metrics/histogram_functions.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/media/autoplay_policy.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"

namespace blink {

namespace {

constexpr base::TimeDelta kMaxOffscreenDurationUma = base::Hours(1);
constexpr int32_t kOffscreenDurationUmaBucketCount = 50;

// Returns a int64_t with the following structure:
// 0b0001 set if there is a user gesture on the stack.
// 0b0010 set if there was a user gesture on the page.
// 0b0100 set if there was a user gesture propagated after navigation.
int64_t GetUserGestureStatusForUkmMetric(LocalFrame* frame) {
  DCHECK(frame);

  int64_t result = 0;

  if (LocalFrame::HasTransientUserActivation(frame))
    result |= 0x01;
  if (frame->HasStickyUserActivation())
    result |= 0x02;
  if (frame->HadStickyUserActivationBeforeNavigation())
    result |= 0x04;

  return result;
}

}  // namespace

AutoplayUmaHelper::AutoplayUmaHelper(HTMLMediaElement* element)
    : ExecutionContextLifecycleObserver(
          static_cast<ExecutionContext*>(nullptr)),
      element_(element),
      muted_video_play_method_intersection_observer_(nullptr),
      is_visible_(false),
      muted_video_offscreen_duration_intersection_observer_(nullptr) {}

AutoplayUmaHelper::~AutoplayUmaHelper() = default;

static void RecordAutoplaySourceMetrics(HTMLMediaElement* element,
                                        AutoplaySource source) {
  if (IsA<HTMLVideoElement>(element)) {
    base::UmaHistogramEnumeration("Media.Video.Autoplay", source);
    return;
  }
  base::UmaHistogramEnumeration("Media.Audio.Autoplay", source);
}

void AutoplayUmaHelper::OnAutoplayInitiated(AutoplaySource source) {

  // Autoplay already initiated
  if (sources_.Contains(source))
    return;

  sources_.insert(source);

  // Record the source.
  RecordAutoplaySourceMetrics(element_.Get(), source);

  // Record dual source.
  if (sources_.size() == kDualSourceSize)
    RecordAutoplaySourceMetrics(element_.Get(), AutoplaySource::kDualSource);

  element_->addEventListener(event_type_names::kPlaying, this, false);

  // Record UKM autoplay event.
  if (!element_->GetDocument().IsActive())
    return;
  LocalFrame* frame = element_->GetDocument().GetFrame();
  DCHECK(frame);
  DCHECK(element_->GetDocument().GetPage());

  ukm::UkmRecorder* ukm_recorder = element_->GetDocument().UkmRecorder();
  DCHECK(ukm_recorder);
  ukm::builders::Media_Autoplay_Attempt(element_->GetDocument().UkmSourceID())
      .SetSource(source == AutoplaySource::kMethod)
      .SetAudioTrack(element_->HasAudio())
      .SetVideoTrack(element_->HasVideo())
      .SetUserGestureRequired(
          element_->GetAutoplayPolicy().IsGestureNeededForPlayback())
      .SetMuted(element_->muted())
      .SetHighMediaEngagement(AutoplayPolicy::DocumentHasHighMediaEngagement(
          element_->GetDocument()))
      .SetUserGestureStatus(GetUserGestureStatusForUkmMetric(frame))
      .Record(ukm_recorder);
}

void AutoplayUmaHelper::RecordAutoplayUnmuteStatus(
    AutoplayUnmuteActionStatus status) {
  base::UmaHistogramEnumeration("Media.Video.Autoplay.Muted.UnmuteAction",
                                status);

  // Record UKM event for unmute muted autoplay.
  if (element_->GetDocument().IsInOutermostMainFrame()) {
    int source = static_cast<int>(AutoplaySource::kAttribute);
    if (sources_.size() == kDualSourceSize) {
      source = static_cast<int>(AutoplaySource::kDualSource);
    } else if (sources_.Contains(AutoplaySource::kMethod)) {
      source = static_cast<int>(AutoplaySource::kAttribute);
    }

    ukm::UkmRecorder* ukm_recorder = element_->GetDocument().UkmRecorder();
    DCHECK(ukm_recorder);
    ukm::builders::Media_Autoplay_Muted_UnmuteAction(
        element_->GetDocument().UkmSourceID())
        .SetSource(source)
        .SetResult(status == AutoplayUnmuteActionStatus::kSuccess)
        .Record(ukm_recorder);
  }
}

void AutoplayUmaHelper::VideoWillBeDrawnToCanvas() {
  if (HasSource() && !IsVisible()) {
    UseCounter::Count(element_->GetDocument(),
                      WebFeature::kHiddenAutoplayedVideoInCanvas);
  }
}

void AutoplayUmaHelper::DidMoveToNewDocument(Document& old_document) {
  if (!ShouldListenToContextDestroyed())
    return;

  SetExecutionContext(element_->GetExecutionContext());
}

void AutoplayUmaHelper::
    OnIntersectionChangedForMutedVideoPlayMethodBecomeVisible(
        const HeapVector<Member<IntersectionObserverEntry>>& entries) {
  bool is_visible = (entries.back()->intersectionRatio() > 0);
  if (!is_visible || !muted_video_play_method_intersection_observer_)
    return;

  MaybeStopRecordingMutedVideoPlayMethodBecomeVisible(true);
}

void AutoplayUmaHelper::OnIntersectionChangedForMutedVideoOffscreenDuration(
    const HeapVector<Member<IntersectionObserverEntry>>& entries) {
  bool is_visible = (entries.back()->intersectionRatio() > 0);
  if (is_visible == is_visible_)
    return;

  if (is_visible) {
    muted_video_autoplay_offscreen_duration_ +=
        base::TimeTicks::Now() - muted_video_autoplay_offscreen_start_time_;
  } else {
    muted_video_autoplay_offscreen_start_time_ = base::TimeTicks::Now();
  }

  is_visible_ = is_visible;
}

void AutoplayUmaHelper::Invoke(ExecutionContext* execution_context,
                               Event* event) {
  if (event->type() == event_type_names::kPlaying) {
    HandlePlayingEvent();
  } else if (event->type() == event_type_names::kPause) {
    HandlePauseEvent();
  } else {
    NOTREACHED();
  }
}

void AutoplayUmaHelper::HandlePlayingEvent() {
  MaybeStartRecordingMutedVideoPlayMethodBecomeVisible();
  MaybeStartRecordingMutedVideoOffscreenDuration();

  element_->removeEventListener(event_type_names::kPlaying, this, false);
}

void AutoplayUmaHelper::HandlePauseEvent() {
  MaybeStopRecordingMutedVideoOffscreenDuration();
}

void AutoplayUmaHelper::ContextDestroyed() {
  HandleContextDestroyed();
}

void AutoplayUmaHelper::HandleContextDestroyed() {
  MaybeStopRecordingMutedVideoPlayMethodBecomeVisible(false);
  MaybeStopRecordingMutedVideoOffscreenDuration();
}

void AutoplayUmaHelper::MaybeStartRecordingMutedVideoPlayMethodBecomeVisible() {
  if (!sources_.Contains(AutoplaySource::kMethod) ||
      !IsA<HTMLVideoElement>(element_.Get()) || !element_->muted())
    return;

  muted_video_play_method_intersection_observer_ = IntersectionObserver::Create(
      element_->GetDocument(),
      WTF::BindRepeating(
          &AutoplayUmaHelper::
              OnIntersectionChangedForMutedVideoPlayMethodBecomeVisible,
          WrapWeakPersistent(this)),
      LocalFrameUkmAggregator::kMediaIntersectionObserver,
      IntersectionObserver::Params{
          .thresholds = {IntersectionObserver::kMinimumThreshold}});
  muted_video_play_method_intersection_observer_->observe(element_);
  SetExecutionContext(element_->GetExecutionContext());
}

void AutoplayUmaHelper::MaybeStopRecordingMutedVideoPlayMethodBecomeVisible(
    bool visible) {
  if (!muted_video_play_method_intersection_observer_)
    return;

  base::UmaHistogramBoolean(
      "Media.Video.Autoplay.Muted.PlayMethod.BecomesVisible", visible);

  muted_video_play_method_intersection_observer_->disconnect();
  muted_video_play_method_intersection_observer_ = nullptr;
  MaybeUnregisterContextDestroyedObserver();
}

void AutoplayUmaHelper::MaybeStartRecordingMutedVideoOffscreenDuration() {
  if (!IsA<HTMLVideoElement>(element_.Get()) || !element_->muted() ||
      !sources_.Contains(AutoplaySource::kMethod))
    return;

  // Start recording muted video playing offscreen duration.
  muted_video_autoplay_offscreen_start_time_ = base::TimeTicks::Now();
  is_visible_ = false;
  muted_video_offscreen_duration_intersection_observer_ =
      IntersectionObserver::Create(
          element_->GetDocument(),
          WTF::BindRepeating(
              &AutoplayUmaHelper::
                  OnIntersectionChangedForMutedVideoOffscreenDuration,
              WrapWeakPersistent(this)),
          LocalFrameUkmAggregator::kMediaIntersectionObserver,
          IntersectionObserver::Params{
              .thresholds = {IntersectionObserver::kMinimumThreshold}});
  muted_video_offscreen_duration_intersection_observer_->observe(element_);
  element_->addEventListener(event_type_names::kPause, this, false);
  SetExecutionContext(element_->GetExecutionContext());
}

void AutoplayUmaHelper::MaybeStopRecordingMutedVideoOffscreenDuration() {
  if (!muted_video_offscreen_duration_intersection_observer_)
    return;

  if (!is_visible_) {
    muted_video_autoplay_offscreen_duration_ +=
        base::TimeTicks::Now() - muted_video_autoplay_offscreen_start_time_;
  }

  DCHECK(sources_.Contains(AutoplaySource::kMethod));

  UMA_HISTOGRAM_CUSTOM_TIMES(
      "Media.Video.Autoplay.Muted.PlayMethod.OffscreenDuration",
      muted_video_autoplay_offscreen_duration_, base::Milliseconds(1),
      kMaxOffscreenDurationUma, kOffscreenDurationUmaBucketCount);

  muted_video_offscreen_duration_intersection_observer_->disconnect();
  muted_video_offscreen_duration_intersection_observer_ = nullptr;
  muted_video_autoplay_offscreen_duration_ = base::TimeDelta();
  MaybeUnregisterMediaElementPauseListener();
  MaybeUnregisterContextDestroyedObserver();
}

void AutoplayUmaHelper::MaybeUnregisterContextDestroyedObserver() {
  // TODO(keishi): Remove IsIteratingOverObservers() check when
  // HeapObserverList() supports removal while iterating.
  if (!ShouldListenToContextDestroyed() && !GetExecutionContext()
                                                ->ContextLifecycleObserverSet()
                                                .IsIteratingOverObservers()) {
    SetExecutionContext(nullptr);
  }
}

void AutoplayUmaHelper::MaybeUnregisterMediaElementPauseListener() {
  if (muted_video_offscreen_duration_intersection_observer_)
    return;
  element_->removeEventListener(event_type_names::kPause, this, false);
}

bool AutoplayUmaHelper::ShouldListenToContextDestroyed() const {
  return muted_video_play_method_intersection_observer_ ||
         muted_video_offscreen_duration_intersection_observer_;
}

void AutoplayUmaHelper::Trace(Visitor* visitor) const {
  NativeEventListener::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  visitor->Trace(element_);
  visitor->Trace(muted_video_play_method_intersection_observer_);
  visitor->Trace(muted_video_offscreen_duration_intersection_observer_);
}

}  // namespace blink
```