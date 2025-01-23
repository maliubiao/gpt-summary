Response:
Let's break down the thought process to analyze the `cue_timeline.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of a specific Chromium Blink engine source file, `cue_timeline.cc`, focusing on its relationship with web technologies (JavaScript, HTML, CSS), providing examples, inferring logic, highlighting potential errors, and explaining user interaction.

2. **Initial Scan for Keywords and Structure:**  Quickly skim the code for key terms that suggest its purpose. I see:
    * `CueTimeline`:  This is the central class. It likely manages the timing and processing of cues.
    * `TextTrackCue`:  Cues are the core data this class works with. This points to subtitles, captions, and potentially other timed metadata.
    * `HTMLMediaElement`:  The timeline is clearly associated with media elements ( `<video>`, `<audio>`).
    * `TextTrack`: Cues belong to tracks.
    * `enter`, `exit`, `cuechange`: These are event names, suggesting this code is involved in dispatching events related to cues.
    * `TimeMarchesOn`: This intriguing function name strongly suggests a mechanism for advancing through time and triggering actions based on cue timings.
    * `CueIntervalTree`:  Data structure for efficient storage and querying of time intervals (cues).
    * `Timer`:  The code uses timers for scheduling events, crucial for time-based functionalities.

3. **Identify Core Functionality (Decomposition):** Based on the initial scan, I can deduce the primary responsibilities of `CueTimeline`:
    * **Adding and Removing Cues:**  The `AddCues`, `AddCue`, `RemoveCues`, `RemoveCue` functions clearly handle adding and removing cue objects.
    * **Tracking Active Cues:** The `currently_active_cues_` member and the logic in `TimeMarchesOn` strongly suggest tracking which cues are currently "active" based on the media's current time.
    * **Dispatching Cue Events:** The `TimeMarchesOn` function, with its logic for comparing current and previous cues, and the scheduling of `enter` and `exit` events, is key to this.
    * **Handling Time Updates:**  The `TimeMarchesOn` function itself is called in response to time updates in the media.
    * **Optimization:** The use of a `CueIntervalTree` hints at efficiency considerations for handling a potentially large number of cues. The timer logic suggests avoiding constant polling.

4. **Relate to Web Technologies:** Now, connect these functionalities to HTML, CSS, and JavaScript:

    * **HTML:** The `<video>` and `<audio>` elements are the containers for media and the source of the cues (via the `<track>` element). The `HTMLTrackElement` is mentioned, confirming the connection.
    * **CSS:**  While `cue_timeline.cc` doesn't directly *style* cues, it's responsible for making cues active, which then allows the browser's rendering engine to apply CSS styles defined for those cues (e.g., through the `::cue` pseudo-element).
    * **JavaScript:**  JavaScript interacts with cues through the `TextTrack` and `TextTrackCue` APIs. Scripts can add, remove, and modify cues. The `enter`, `exit`, and `cuechange` events are dispatched and can be listened for in JavaScript.

5. **Construct Examples:** Create concrete examples to illustrate the relationships:

    * **HTML:** Show a basic `<video>` with a `<track>` element.
    * **JavaScript:** Demonstrate adding a cue using JavaScript and listening for the `enter` event.
    * **CSS:** Illustrate styling cues using the `::cue` pseudo-element.

6. **Infer Logic and Provide Input/Output:** Focus on the `TimeMarchesOn` function. This function contains the core logic for determining which cues should become active or inactive. Simulate a scenario:

    * **Input:** Media current time, a set of cues with start and end times.
    * **Process (Simplified):**  Cues whose start time is before or equal to the current time, and whose end time is after the current time, become active. Events are fired accordingly.
    * **Output:**  A list of active cues, and the `enter` or `exit` events that would be fired.

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make:

    * Incorrect cue start and end times.
    * Overlapping cues causing unexpected behavior.
    * Not understanding the timing of `enter` and `exit` events.
    * Issues with cue order.

8. **Explain User Interaction:**  Consider how a user's actions lead to this code being executed:

    * Playing a video: This is the primary trigger for the timeline to advance.
    * Seeking: Jumping to a different point in the video triggers recalculation of active cues.
    * Adding/removing tracks: This directly calls the `AddCues`/`RemoveCues` functions.
    * Loading a video with embedded subtitles.

9. **Refine and Structure:** Organize the findings logically, using clear headings and bullet points. Ensure the language is accessible and avoids overly technical jargon where possible. Review the code comments provided in the file itself for hints about the developers' intentions. For example, the comment about negative duration cues is a helpful detail.

10. **Self-Correction/Refinement during analysis:**
    * Initially, I might have focused too much on the individual functions. Realizing that `TimeMarchesOn` is the central orchestrator is key.
    *  I might initially forget to mention the CSS aspect and add it upon realizing the rendering connection.
    *  Thinking about edge cases like seeking or changing playback rate helps to fully understand the purpose of the timers and the `TimeMarchesOn` logic.

By following these steps, I can systematically analyze the source code and generate a comprehensive explanation that addresses all aspects of the request. The process involves understanding the code's structure, inferring its purpose, connecting it to relevant web technologies, creating examples, and considering user interaction and potential errors.
好的， 让我们来分析一下 `blink/renderer/core/html/track/cue_timeline.cc` 这个文件。

**功能概述:**

`CueTimeline` 类的主要功能是 **管理和维护与 HTML `<video>` 或 `<audio>` 元素关联的文本轨道 (TextTrack) 中的提示 (Cue) 的生命周期和事件触发。**  简单来说，它负责在媒体播放过程中，根据当前播放时间，判断哪些字幕、描述或其他类型的文本提示应该进入活跃状态（显示）或退出活跃状态（隐藏），并触发相应的事件。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`CueTimeline` 位于浏览器引擎的底层，但它与 Web 前端技术（JavaScript, HTML, CSS）有着密切的联系：

* **HTML:**
    * **`<video>` 和 `<audio>` 元素:** `CueTimeline` 是为这些媒体元素服务的。当 HTML 中定义了一个 `<video>` 或 `<audio>` 元素，并且包含了 `<track>` 子元素来指定字幕或其他文本轨道时，`CueTimeline` 就开始发挥作用。
    * **`<track>` 元素:**  `<track>` 元素定义了文本轨道的来源、语言等信息。浏览器解析 `<track>` 元素后，会创建 `TextTrack` 对象，并将其与媒体元素关联。`CueTimeline` 负责处理这些 `TextTrack` 中包含的 `TextTrackCue` 对象。

    **例子:**
    ```html
    <video controls>
      <source src="myvideo.mp4" type="video/mp4">
      <track label="English subtitles" kind="subtitles" srclang="en" src="subtitles_en.vtt" default>
    </video>
    ```
    在这个例子中，当视频播放时，`CueTimeline` 会读取 `subtitles_en.vtt` 文件中的字幕信息（即 `TextTrackCue` 对象），并根据播放时间控制字幕的显示与隐藏。

* **JavaScript:**
    * **`TextTrack` API:**  JavaScript 可以通过 `HTMLMediaElement.textTracks` 属性访问到与媒体元素关联的 `TextTrackList` 对象，进而操作其中的 `TextTrack` 对象。
    * **`TextTrackCue` API:**  JavaScript 可以创建、添加、删除和修改 `TextTrackCue` 对象。`CueTimeline` 负责响应这些 JavaScript 操作，并更新其内部的提示管理。
    * **`cuechange` 事件:** 当 `TextTrack` 中活跃的提示发生变化时，`CueTimeline` 会触发 `cuechange` 事件。JavaScript 可以监听这个事件来执行相应的操作。
    * **`enter` 和 `exit` 事件:**  当一个提示进入活跃状态时，`CueTimeline` 会在对应的 `TextTrackCue` 对象上触发 `enter` 事件；当提示退出活跃状态时，会触发 `exit` 事件。

    **例子:**
    ```javascript
    const video = document.querySelector('video');
    const textTrack = video.textTracks[0]; // 获取第一个文本轨道

    textTrack.oncuechange = () => {
      console.log('活跃提示已更改');
      if (textTrack.activeCues) {
        for (let i = 0; i < textTrack.activeCues.length; i++) {
          console.log('当前活跃提示:', textTrack.activeCues[i].text);
        }
      }
    };

    const newCue = new VTTCue(5, 10, '这是一个通过 JavaScript 添加的提示');
    textTrack.addCue(newCue);

    newCue.onenter = () => {
      console.log('新提示进入');
    };

    newCue.onexit = () => {
      console.log('新提示退出');
    };
    ```
    这段代码演示了如何通过 JavaScript 监听 `cuechange` 事件，添加新的提示，并监听提示的 `enter` 和 `exit` 事件。

* **CSS:**
    * **`::cue` 伪元素:** CSS 可以使用 `::cue` 伪元素来样式化文本轨道中的提示。`CueTimeline` 负责确定哪些提示是活跃的，浏览器渲染引擎会根据这些信息应用相应的 CSS 样式。

    **例子:**
    ```css
    video::cue {
      background-color: rgba(0, 0, 0, 0.8);
      color: white;
      font-size: 1.2em;
    }

    video::cue(v) { /* 样式化具有 'v' 类的提示 */
      color: yellow;
    }
    ```
    这段 CSS 代码会使视频字幕拥有黑色背景和白色文字，并且为带有 `v` 类的提示设置黄色文字。当 `CueTimeline` 将一个提示标记为活跃时，如果该提示没有特定的类，则会应用第一个 `::cue` 规则；如果提示有 `v` 类，则会应用第二个更具体的规则。

**逻辑推理 (假设输入与输出):**

假设我们有一个包含以下提示的文本轨道：

* Cue 1: startTime=1, endTime=5, text="First cue"
* Cue 2: startTime=3, endTime=7, text="Second cue"
* Cue 3: startTime=8, endTime=10, text="Third cue"

**假设输入:** 媒体元素的 `currentTime` 为 4 秒。

**逻辑推理过程 (基于代码片段):**

1. **`TimeMarchesOn()` 函数会被调用:**  当媒体的播放时间更新时，这个函数是核心的处理逻辑。
2. **确定 `current_cues`:**  代码会检查所有提示，找出那些开始时间小于等于当前时间 (4 秒) 且结束时间大于当前时间 (4 秒) 的提示。
   * Cue 1: 1 <= 4 && 5 > 4  => True (活跃)
   * Cue 2: 3 <= 4 && 7 > 4  => True (活跃)
   * Cue 3: 8 <= 4  => False (不活跃)
   因此，`current_cues` 将包含 Cue 1 和 Cue 2。
3. **确定 `previous_cues`:**  这是上次运行 `TimeMarchesOn()` 时活跃的提示列表。假设上次运行时的 `currentTime` 为 2 秒，那么 `previous_cues` 可能只包含 Cue 1。
4. **确定需要触发的事件:**
   * Cue 1:  上次活跃，这次也活跃，不需要触发 `enter` 或 `exit`。
   * Cue 2:  上次不活跃，这次活跃，需要触发 Cue 2 的 `enter` 事件。
5. **更新活跃状态:** Cue 1 和 Cue 2 的 "text track cue active" 标志会被设置为 true。
6. **触发 `cuechange` 事件:**  由于活跃提示集合发生了变化，会触发关联 `TextTrack` 和 `HTMLTrackElement` 的 `cuechange` 事件。

**假设输出:**

* Cue 1 和 Cue 2 被标记为活跃。
* Cue 2 的 `enter` 事件被触发。
* `TextTrack` 和可能的 `HTMLTrackElement` 上触发 `cuechange` 事件。

**用户或编程常见的使用错误举例说明:**

1. **提示时间设置错误:**
   * **错误:**  `startTime` 大于或等于 `endTime`。
   * **代码处理:** 代码中 `CreateCueInterval` 函数会使用 `std::max(cue->startTime(), cue->endTime())`，将结束时间至少设置为开始时间，避免区间错误。但在 `TimeMarchesOn` 中，对于这类负持续时间的提示，会同时触发 `enter` 和 `exit` 事件。
   * **后果:** 可能导致提示瞬间显示又消失，或者根本不显示。

2. **提示重叠问题:**
   * **场景:** 多个提示在同一时间段内处于活跃状态。
   * **代码处理:** `CueTimeline` 允许提示重叠，会将所有符合条件的提示都标记为活跃。
   * **后果:**  如果 CSS 样式没有妥善处理重叠，可能会导致字幕显示混乱，互相遮盖。

3. **JavaScript 操作与 `CueTimeline` 的同步问题:**
   * **错误:**  在媒体播放过程中频繁地添加或删除提示，可能导致 `CueTimeline` 的状态与 JavaScript 的预期不同步。
   * **代码处理:** `CueTimeline` 通过 `InvokeTimeMarchesOn()` 来响应提示的添加和删除，并在每次时间更新时重新评估活跃提示。
   * **后果:**  可能出现提示显示延迟、错误显示或不显示的情况。

4. **没有正确设置 `<track>` 元素的 `kind` 属性:**
   * **错误:**  将字幕轨道的 `kind` 设置为 `metadata` 或其他不合适的类型。
   * **代码处理:** `CueTimeline` 会处理所有模式不为 `disabled` 的 `TextTrack`。但是，浏览器对于不同 `kind` 的 `TextTrack` 的默认处理方式可能不同，例如字幕轨道通常会自动显示。
   * **后果:**  字幕可能不会按预期显示。

**用户操作如何一步步到达这里:**

1. **用户打开一个包含 `<video>` 或 `<audio>` 元素的网页。**
2. **网页中的 `<video>` 或 `<audio>` 元素包含一个或多个 `<track>` 元素，指定了字幕或其他文本轨道。**
3. **浏览器解析 HTML，创建 `HTMLMediaElement` 和 `HTMLTrackElement` 对象，并加载文本轨道文件。**
4. **加载的文本轨道文件被解析，创建 `TextTrackCue` 对象，并添加到对应的 `TextTrack` 中。**
5. **用户开始播放媒体 (点击播放按钮)。**
6. **媒体元素的播放时间开始更新。**
7. **每次播放时间更新（例如，通过 `HTMLMediaElement::currentTime()`），都会触发 `CueTimeline::TimeMarchesOn()` 函数的调用。**
8. **`TimeMarchesOn()` 函数根据当前的播放时间，比较当前的活跃提示和之前的活跃提示，决定哪些提示应该进入或退出活跃状态。**
9. **如果活跃提示发生变化，`CueTimeline` 会触发 `enter` 和 `exit` 事件在对应的 `TextTrackCue` 对象上，并触发 `cuechange` 事件在 `TextTrack` 和 `HTMLTrackElement` 上。**
10. **浏览器渲染引擎接收到活跃提示的信息，并根据 CSS 规则渲染相应的提示内容。**
11. **如果网页中有 JavaScript 代码监听了 `cuechange`、`enter` 或 `exit` 事件，这些事件处理函数会被执行。**
12. **当用户暂停、快进、快退或跳转播放位置时，第 7 步开始的流程会重新执行。**

总而言之，`cue_timeline.cc` 是 Blink 引擎中处理媒体元素文本轨道提示的核心组件，它在幕后默默地工作，确保用户在观看视频或收听音频时，能够看到正确的字幕、描述或其他辅助信息。它与 HTML 定义的结构、JavaScript 的动态操作以及 CSS 的样式化紧密配合，共同构建了丰富的媒体体验。

### 提示词
```
这是目录为blink/renderer/core/html/track/cue_timeline.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/track/cue_timeline.h"

#include <algorithm>
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/track/html_track_element.h"
#include "third_party/blink/renderer/core/html/track/loadable_text_track.h"
#include "third_party/blink/renderer/core/html/track/text_track.h"
#include "third_party/blink/renderer/core/html/track/text_track_cue.h"
#include "third_party/blink/renderer/core/html/track/text_track_cue_list.h"
#include "ui/accessibility/accessibility_features.h"

namespace blink {

namespace {

CueInterval CreateCueInterval(TextTrackCue* cue) {
  // Negative duration cues need be treated in the interval tree as
  // zero-length cues.
  double const interval_end_time = std::max(cue->startTime(), cue->endTime());
  return CueIntervalTree::CreateInterval(cue->startTime(), interval_end_time,
                                         cue);
}

base::TimeDelta CalculateEventTimeout(double event_time,
                                      HTMLMediaElement const& media_element) {
  static_assert(HTMLMediaElement::kMinPlaybackRate >= 0,
                "The following code assumes playback rates are never negative");
  DCHECK_NE(media_element.playbackRate(), 0);

  auto const timeout =
      base::Seconds((event_time - media_element.currentTime()) /
                    media_element.playbackRate());

  // Only allow timeouts of multiples of 1ms to prevent "polling-by-timer"
  // and excessive calls to `TimeMarchesOn`.
  constexpr base::TimeDelta kMinTimeoutInterval = base::Milliseconds(1);
  return std::max(timeout.CeilToMultiple(kMinTimeoutInterval),
                  kMinTimeoutInterval);
}

}  // namespace

CueTimeline::CueTimeline(HTMLMediaElement& media_element)
    : media_element_(&media_element),
      last_update_time_(-1),
      cue_event_timer_(
          media_element.GetDocument().GetTaskRunner(TaskType::kInternalMedia),
          this,
          &CueTimeline::CueEventTimerFired),
      cue_timestamp_event_timer_(
          media_element.GetDocument().GetTaskRunner(TaskType::kInternalMedia),
          this,
          &CueTimeline::CueTimestampEventTimerFired),
      ignore_update_(0),
      update_requested_while_ignoring_(false) {}

void CueTimeline::AddCues(TextTrack* track, const TextTrackCueList* cues) {
  DCHECK_NE(track->mode(), TextTrackMode::kDisabled);
  for (wtf_size_t i = 0; i < cues->length(); ++i)
    AddCueInternal(cues->AnonymousIndexedGetter(i));
  if (!MediaElement().IsShowPosterFlagSet()) {
    InvokeTimeMarchesOn();
  }
}

void CueTimeline::AddCue(TextTrack* track, TextTrackCue* cue) {
  DCHECK_NE(track->mode(), TextTrackMode::kDisabled);
  AddCueInternal(cue);
  if (!MediaElement().IsShowPosterFlagSet()) {
    InvokeTimeMarchesOn();
  }
}

void CueTimeline::AddCueInternal(TextTrackCue* cue) {
  CueInterval interval = CreateCueInterval(cue);
  if (!cue_tree_.Contains(interval))
    cue_tree_.Add(interval);
}

void CueTimeline::RemoveCues(TextTrack*, const TextTrackCueList* cues) {
  for (wtf_size_t i = 0; i < cues->length(); ++i)
    RemoveCueInternal(cues->AnonymousIndexedGetter(i));
  if (!MediaElement().IsShowPosterFlagSet()) {
    InvokeTimeMarchesOn();
  }
}

void CueTimeline::RemoveCue(TextTrack*, TextTrackCue* cue) {
  RemoveCueInternal(cue);
  if (!MediaElement().IsShowPosterFlagSet()) {
    InvokeTimeMarchesOn();
  }
}

void CueTimeline::RemoveCueInternal(TextTrackCue* cue) {
  CueInterval interval = CreateCueInterval(cue);
  cue_tree_.Remove(interval);

  wtf_size_t index = currently_active_cues_.Find(interval);
  if (index != kNotFound) {
    DCHECK(cue->IsActive());
    currently_active_cues_.EraseAt(index);
    cue->SetIsActive(false);
    // Since the cue will be removed from the media element and likely the
    // TextTrack might also be destructed, notifying the region of the cue
    // removal shouldn't be done.
    cue->RemoveDisplayTree(TextTrackCue::kDontNotifyRegion);
  }
}

void CueTimeline::HideCues(TextTrack*, const TextTrackCueList* cues) {
  for (wtf_size_t i = 0; i < cues->length(); ++i)
    cues->AnonymousIndexedGetter(i)->RemoveDisplayTree();
}

static bool TrackIndexCompare(TextTrack* a, TextTrack* b) {
  return a->TrackIndex() - b->TrackIndex() < 0;
}

static bool EventTimeCueCompare(const std::pair<double, TextTrackCue*>& a,
                                const std::pair<double, TextTrackCue*>& b) {
  // 12 - Sort the tasks in events in ascending time order (tasks with earlier
  // times first).
  if (a.first != b.first)
    return a.first - b.first < 0;

  // If the cues belong to different text tracks, it doesn't make sense to
  // compare the two tracks by the relative cue order, so return the relative
  // track order.
  if (a.second->track() != b.second->track())
    return TrackIndexCompare(a.second->track(), b.second->track());

  // 12 - Further sort tasks in events that have the same time by the
  // relative text track cue order of the text track cues associated
  // with these tasks.
  return a.second->CueIndex() < b.second->CueIndex();
}

static Event* CreateEventWithTarget(const AtomicString& event_name,
                                    EventTarget* event_target) {
  Event* event = Event::Create(event_name);
  event->SetTarget(event_target);
  return event;
}

void CueTimeline::TimeMarchesOn() {
  DCHECK(!MediaElement().IsShowPosterFlagSet());

  // 4.8.10.8 Playing the media resource

  //  If the current playback position changes while the steps are running,
  //  then the user agent must wait for the steps to complete, and then must
  //  immediately rerun the steps.
  if (InsideIgnoreUpdateScope()) {
    update_requested_while_ignoring_ = true;
    return;
  }

  // Prevent recursive updates
  auto scope = BeginIgnoreUpdateScope();

  HTMLMediaElement& media_element = MediaElement();
  double const movie_time = media_element.currentTime();

  // Don't run the "time marches on" algorithm if the document has been
  // detached. This primarily guards against dispatch of events w/
  // HTMLTrackElement targets.
  if (media_element.GetDocument().IsDetached())
    return;

  // Get the next cue event after this update
  next_cue_event_ = cue_tree_.NextIntervalPoint(movie_time);

  // https://html.spec.whatwg.org/C/#time-marches-on

  // 1 - Let current cues be a list of cues, initialized to contain all the
  // cues of all the hidden, showing, or showing by default text tracks of the
  // media element (not the disabled ones) whose start times are less than or
  // equal to the current playback position and whose end times are greater
  // than the current playback position.
  CueList current_cues;

  // The user agent must synchronously unset [the text track cue active] flag
  // whenever ... the media element's readyState is changed back to
  // kHaveNothing.
  if (media_element.getReadyState() != HTMLMediaElement::kHaveNothing &&
      media_element.GetWebMediaPlayer()) {
    current_cues =
        cue_tree_.AllOverlaps(cue_tree_.CreateInterval(movie_time, movie_time));
  }

  CueList previous_cues;

  // 2 - Let other cues be a list of cues, initialized to contain all the cues
  // of hidden, showing, and showing by default text tracks of the media
  // element that are not present in current cues.
  previous_cues = currently_active_cues_;

  // 3 - Let last time be the current playback position at the time this
  // algorithm was last run for this media element, if this is not the first
  // time it has run.
  double last_time = last_update_time_;
  double last_seek_time = media_element.LastSeekTime();

  // 4 - If the current playback position has, since the last time this
  // algorithm was run, only changed through its usual monotonic increase
  // during normal playback, then let missed cues be the list of cues in other
  // cues whose start times are greater than or equal to last time and whose
  // end times are less than or equal to the current playback position.
  // Otherwise, let missed cues be an empty list.
  CueList missed_cues;
  if (last_time >= 0 && last_seek_time < movie_time) {
    CueList potentially_skipped_cues =
        cue_tree_.AllOverlaps(cue_tree_.CreateInterval(last_time, movie_time));
    missed_cues.ReserveInitialCapacity(potentially_skipped_cues.size());

    for (CueInterval cue : potentially_skipped_cues) {
      // Consider cues that may have been missed since the last seek time.
      if (cue.Low() > std::max(last_seek_time, last_time) &&
          cue.High() < movie_time)
        missed_cues.push_back(cue);
    }
  }

  last_update_time_ = movie_time;

  // 5 - If the time was reached through the usual monotonic increase of the
  // current playback position during normal playback, and if the user agent
  // has not fired a timeupdate event at the element in the past 15 to 250ms...
  // NOTE: periodic 'timeupdate' scheduling is handled by HTMLMediaElement in
  // PlaybackProgressTimerFired().

  // Explicitly cache vector sizes, as their content is constant from here.
  wtf_size_t missed_cues_size = missed_cues.size();
  wtf_size_t previous_cues_size = previous_cues.size();

  // 6 - If all of the cues in current cues have their text track cue active
  // flag set, none of the cues in other cues have their text track cue active
  // flag set, and missed cues is empty, then abort these steps.
  bool active_set_changed = missed_cues_size;

  for (wtf_size_t i = 0; !active_set_changed && i < previous_cues_size; ++i) {
    if (!current_cues.Contains(previous_cues[i]) &&
        previous_cues[i].Data()->IsActive())
      active_set_changed = true;
  }

  for (CueInterval current_cue : current_cues) {
    // Notify any cues that are already active of the current time to mark
    // past and future nodes. Any inactive cues have an empty display state;
    // they will be notified of the current time when the display state is
    // updated.
    if (current_cue.Data()->IsActive())
      current_cue.Data()->UpdatePastAndFutureNodes(movie_time);
    else
      active_set_changed = true;
  }

  if (!active_set_changed)
    return;

  // 7 - If the time was reached through the usual monotonic increase of the
  // current playback position during normal playback, and there are cues in
  // other cues that have their text track cue pause-on-exi flag set and that
  // either have their text track cue active flag set or are also in missed
  // cues, then immediately pause the media element.
  for (wtf_size_t i = 0; !media_element.paused() && i < previous_cues_size;
       ++i) {
    if (previous_cues[i].Data()->pauseOnExit() &&
        previous_cues[i].Data()->IsActive() &&
        !current_cues.Contains(previous_cues[i]))
      media_element.pause();
  }

  for (wtf_size_t i = 0; !media_element.paused() && i < missed_cues_size; ++i) {
    if (missed_cues[i].Data()->pauseOnExit())
      media_element.pause();
  }

  // 8 - Let events be a list of tasks, initially empty. Each task in this
  // list will be associated with a text track, a text track cue, and a time,
  // which are used to sort the list before the tasks are queued.
  HeapVector<std::pair<double, Member<TextTrackCue>>> event_tasks;

  // 8 - Let affected tracks be a list of text tracks, initially empty.
  HeapVector<Member<TextTrack>> affected_tracks;

  for (const auto& missed_cue : missed_cues) {
    // 9 - For each text track cue in missed cues, prepare an event named enter
    // for the TextTrackCue object with the text track cue start time.
    event_tasks.push_back(
        std::make_pair(missed_cue.Data()->startTime(), missed_cue.Data()));

    // 10 - For each text track [...] in missed cues, prepare an event
    // named exit for the TextTrackCue object with the  with the later of
    // the text track cue end time and the text track cue start time.

    // Note: An explicit task is added only if the cue is NOT a zero or
    // negative length cue. Otherwise, the need for an exit event is
    // checked when these tasks are actually queued below. This doesn't
    // affect sorting events before dispatch either, because the exit
    // event has the same time as the enter event.
    if (missed_cue.Data()->startTime() < missed_cue.Data()->endTime()) {
      event_tasks.push_back(
          std::make_pair(missed_cue.Data()->endTime(), missed_cue.Data()));
    }
  }

  for (const auto& previous_cue : previous_cues) {
    // 10 - For each text track cue in other cues that has its text
    // track cue active flag set prepare an event named exit for the
    // TextTrackCue object with the text track cue end time.
    if (!current_cues.Contains(previous_cue)) {
      event_tasks.push_back(
          std::make_pair(previous_cue.Data()->endTime(), previous_cue.Data()));
    }
  }

  for (const auto& current_cue : current_cues) {
    // 11 - For each text track cue in current cues that does not have its
    // text track cue active flag set, prepare an event named enter for the
    // TextTrackCue object with the text track cue start time.
    if (!previous_cues.Contains(current_cue)) {
      event_tasks.push_back(
          std::make_pair(current_cue.Data()->startTime(), current_cue.Data()));
    }
  }

  // 12 - Sort the tasks in events in ascending time order (tasks with earlier
  // times first).
  std::sort(event_tasks.begin(), event_tasks.end(), EventTimeCueCompare);

  for (const auto& task : event_tasks) {
    if (!affected_tracks.Contains(task.second->track()))
      affected_tracks.push_back(task.second->track());

    // 13 - Queue each task in events, in list order.

    // Each event in eventTasks may be either an enterEvent or an exitEvent,
    // depending on the time that is associated with the event. This
    // correctly identifies the type of the event, if the startTime is
    // less than the endTime in the cue.
    if (task.second->startTime() >= task.second->endTime()) {
      media_element.ScheduleEvent(
          CreateEventWithTarget(event_type_names::kEnter, task.second.Get()));
      media_element.ScheduleEvent(
          CreateEventWithTarget(event_type_names::kExit, task.second.Get()));
    } else {
      TextTrackCue* cue = task.second.Get();
      bool is_enter_event = task.first == task.second->startTime();
      AtomicString event_name =
          is_enter_event ? event_type_names::kEnter : event_type_names::kExit;
      media_element.ScheduleEvent(
          CreateEventWithTarget(event_name, task.second.Get()));
      if (features::IsTextBasedAudioDescriptionEnabled()) {
        if (is_enter_event) {
          cue->OnEnter(MediaElement());
        } else {
          cue->OnExit(MediaElement());
        }
      }
    }
  }

  // 14 - Sort affected tracks in the same order as the text tracks appear in
  // the media element's list of text tracks, and remove duplicates.
  std::sort(affected_tracks.begin(), affected_tracks.end(), TrackIndexCompare);

  // 15 - For each text track in affected tracks, in the list order, queue a
  // task to fire a simple event named cuechange at the TextTrack object, and,
  // ...
  for (const auto& track : affected_tracks) {
    media_element.ScheduleEvent(
        CreateEventWithTarget(event_type_names::kCuechange, track.Get()));

    // ... if the text track has a corresponding track element, to then fire a
    // simple event named cuechange at the track element as well.
    if (auto* loadable_text_track = DynamicTo<LoadableTextTrack>(track.Get())) {
      HTMLTrackElement* track_element = loadable_text_track->TrackElement();
      DCHECK(track_element);
      media_element.ScheduleEvent(
          CreateEventWithTarget(event_type_names::kCuechange, track_element));
    }
  }

  // 16 - Set the text track cue active flag of all the cues in the current
  // cues, and unset the text track cue active flag of all the cues in the
  // other cues.
  for (const auto& cue : current_cues)
    cue.Data()->SetIsActive(true);

  for (const auto& previous_cue : previous_cues) {
    if (!current_cues.Contains(previous_cue)) {
      TextTrackCue* cue = previous_cue.Data();
      cue->SetIsActive(false);
      cue->RemoveDisplayTree();
    }
  }

  // Update the current active cues.
  currently_active_cues_ = current_cues;
  media_element.UpdateTextTrackDisplay();
}

void CueTimeline::UpdateActiveCuePastAndFutureNodes() {
  double const movie_time = MediaElement().currentTime();

  for (auto cue : currently_active_cues_) {
    DCHECK(cue.Data()->IsActive());
    if (!cue.Data()->track() || !cue.Data()->track()->IsRendered())
      continue;

    cue.Data()->UpdatePastAndFutureNodes(movie_time);
  }

  SetCueTimestampEventTimer();
}

CueTimeline::IgnoreUpdateScope CueTimeline::BeginIgnoreUpdateScope() {
  DCHECK(!ignore_update_ || !update_requested_while_ignoring_);
  ++ignore_update_;

  IgnoreUpdateScope scope(*this);
  return scope;
}

void CueTimeline::EndIgnoreUpdateScope(base::PassKey<IgnoreUpdateScope>,
                                       IgnoreUpdateScope const& scope) {
  DCHECK(ignore_update_);
  --ignore_update_;

  // If this is the last scope and an update was requested, then perform it
  if (!ignore_update_ && update_requested_while_ignoring_) {
    update_requested_while_ignoring_ = false;
    if (!MediaElement().IsShowPosterFlagSet()) {
      InvokeTimeMarchesOn();
    }
  }
}

void CueTimeline::InvokeTimeMarchesOn() {
  TimeMarchesOn();
  SetCueEventTimer();
  SetCueTimestampEventTimer();
}

void CueTimeline::OnPause() {
  CancelCueEventTimer();
  CancelCueTimestampEventTimer();
}

void CueTimeline::OnPlaybackRateUpdated() {
  SetCueEventTimer();
  SetCueTimestampEventTimer();
}

void CueTimeline::OnReadyStateReset() {
  auto& media_element = MediaElement();
  DCHECK(media_element.getReadyState() == HTMLMediaElement::kHaveNothing);

  // Deactivate all active cues
  // "The user agent must synchronously unset this flag ... whenever the media
  // element's readyState is changed back to HAVE_NOTHING."
  for (auto cue : currently_active_cues_) {
    cue.Data()->SetIsActive(false);
  }
  currently_active_cues_.clear();

  CancelCueEventTimer();
  CancelCueTimestampEventTimer();
  last_update_time_ = -1;

  if (media_element.IsHTMLVideoElement() && media_element.TextTracksVisible()) {
    media_element.UpdateTextTrackDisplay();
  }
}

void CueTimeline::SetCueEventTimer() {
  auto const& media_element = MediaElement();
  if (!next_cue_event_.has_value() || media_element.paused() ||
      media_element.playbackRate() == 0) {
    CancelCueEventTimer();
    return;
  }

  auto const timeout =
      CalculateEventTimeout(next_cue_event_.value(), media_element);
  cue_event_timer_.StartOneShot(timeout, FROM_HERE);
}

void CueTimeline::CancelCueEventTimer() {
  if (cue_event_timer_.IsActive()) {
    cue_event_timer_.Stop();
  }
}

void CueTimeline::CueEventTimerFired(TimerBase*) {
  InvokeTimeMarchesOn();
}

void CueTimeline::CueTimestampEventTimerFired(TimerBase*) {
  UpdateActiveCuePastAndFutureNodes();
  SetCueTimestampEventTimer();
}

void CueTimeline::SetCueTimestampEventTimer() {
  double constexpr kInfinity = std::numeric_limits<double>::infinity();
  auto const& media_element = MediaElement();

  if (media_element.paused() || media_element.playbackRate() == 0) {
    CancelCueTimestampEventTimer();
    return;
  }

  double const movie_time = media_element.currentTime();
  double next_cue_timestamp_event = kInfinity;
  for (auto cue : currently_active_cues_) {
    auto const timestamp = cue.Data()->GetNextIntraCueTime(movie_time);
    next_cue_timestamp_event =
        std::min(next_cue_timestamp_event, timestamp.value_or(kInfinity));
  }

  if (std::isinf(next_cue_timestamp_event)) {
    CancelCueTimestampEventTimer();
    return;
  }

  auto const timeout =
      CalculateEventTimeout(next_cue_timestamp_event, media_element);
  cue_timestamp_event_timer_.StartOneShot(timeout, FROM_HERE);
}

void CueTimeline::CancelCueTimestampEventTimer() {
  if (cue_timestamp_event_timer_.IsActive()) {
    cue_timestamp_event_timer_.Stop();
  }
}

void CueTimeline::DidMoveToNewDocument(Document& /*old_document*/) {
  cue_event_timer_.MoveToNewTaskRunner(
      MediaElement().GetDocument().GetTaskRunner(TaskType::kInternalMedia));
  cue_timestamp_event_timer_.MoveToNewTaskRunner(
      MediaElement().GetDocument().GetTaskRunner(TaskType::kInternalMedia));
}

void CueTimeline::Trace(Visitor* visitor) const {
  visitor->Trace(media_element_);
  visitor->Trace(cue_event_timer_);
  visitor->Trace(cue_timestamp_event_timer_);
}

}  // namespace blink
```