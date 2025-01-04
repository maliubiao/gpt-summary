Response:
Let's break down the thought process for analyzing the `TextTrack.cc` file.

**1. Initial Understanding of the File's Purpose:**

* **File Path:**  `blink/renderer/core/html/track/text_track.cc` immediately suggests this file is part of the Blink rendering engine, specifically dealing with HTML, tracks (likely related to `<track>` elements), and is a C++ implementation. The `.cc` extension confirms this.
* **Copyright Notices:** Indicate the code's origin (Google, Apple) and licensing (BSD-like). This is standard boilerplate and provides context.
* **Includes:** The `#include` statements give crucial hints about dependencies and functionality:
    * `text_track.h`:  The corresponding header file, defining the `TextTrack` class interface.
    * `html_media_element.h`:  Indicates a strong connection to `<video>` and `<audio>` elements.
    * `cue_timeline.h`: Suggests managing the timing and display of cues.
    * `text_track_cue_list.h`:  Implies a container for `TextTrackCue` objects.
    * `text_track_list.h`: Hints at a collection of `TextTrack` objects.
    * `exception_state.h`:  Deals with error handling and exceptions.
    * `accessibility_features.h`:  Points to accessibility considerations.
    * `WebMediaPlayer.h`:  Connects to the underlying media playback engine.
    * `event_target_names.h`:  Related to the event system in Blink.

**2. Core Functionality Identification (Iterative Reading and Analysis):**

* **Static Keyword Definitions:**  The `SubtitlesKeyword()`, `CaptionsKeyword()`, etc., methods reveal the different types of text tracks supported. This is a foundational piece of information.
* **Constructor and Destructor:**  The constructor shows how `TextTrack` objects are initialized (kind, label, language, source element, etc.). The destructor is simple, suggesting no complex resource cleanup within `TextTrack` itself (likely handled by its members).
* **`IsValidKindKeyword()`:** This function checks if a given string is a valid text track kind. This directly relates to the `kind` attribute of the `<track>` element.
* **`SetTrackList()`:** This function establishes the relationship between a `TextTrack` and its containing `TextTrackList`. It also handles removing cues from the timeline when a track is detached from its list.
* **`IsVisualKind()` and `IsSpokenKind()`:** These helpers categorize track types, likely influencing how they are rendered or processed (e.g., visual tracks are displayed, spoken tracks might be used for audio descriptions).
* **`setMode()` and `SetModeEnum()`:** The `mode` attribute (`disabled`, `hidden`, `showing`) is central to controlling whether and how a track is active. The logic within `setMode` manages cue visibility and informs the `HTMLMediaElement`.
* **`cues()`:**  Provides access to the list of cues associated with the track. The crucial point here is the "live" aspect and the null return for disabled tracks.
* **`Reset()`:** Clears all cues and styles, effectively resetting the track.
* **`AddListOfCues()` and `addCue()`:** Methods for adding cues to the track, including managing their association with the timeline.
* **`removeCue()`:** Removes a specific cue from the track. Note the error handling (NotFoundError).
* **`CueWillChange()` and `CueDidChange()`:** These methods handle the lifecycle of a cue modification, ensuring proper updates to the timeline and rendering.
* **`activeCues()`:** Returns a dynamic list of currently active cues based on the media's current time.
* **`SetCSSStyleSheets()`:** Allows associating CSS styles with the track (for styling cues).
* **`TrackIndex()` and `InvalidateTrackIndex()`:**  Manage the track's index within its parent `TextTrackList`.
* **`IsRendered()` and `CanBeRendered()`:** Determine if a track should and can be displayed, considering its mode, kind, and loading status. The accessibility feature check is important.
* **`EnsureTextTrackCueList()`:**  A utility to lazily create the `TextTrackCueList`.
* **`TrackIndexRelativeToRenderedTracks()`:** Calculates the index specifically among the tracks that *are* rendered.
* **`InterfaceName()`:** Returns the name used for identifying this object in the Blink event system.
* **`GetExecutionContext()` and `MediaElement()`:** Accessors to related objects in the Blink structure.
* **`GetCueTimeline()`:** Retrieves the timeline manager.
* **`Owner()`:** Returns the `HTMLMediaElement` that owns the track.
* **`Trace()`:**  Used for Blink's garbage collection and debugging infrastructure.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:**  The code directly implements the behavior of the `TextTrack` interface exposed to JavaScript. The methods like `addCue()`, `removeCue()`, and the `mode` attribute are all part of this API.
* **HTML:**  The `TextTrack` object is created and managed as a result of parsing `<track>` elements within `<video>` or `<audio>`. The `kind` attribute of `<track>` directly corresponds to the `kind_` member.
* **CSS:** The `SetCSSStyleSheets()` method allows CSS rules to be associated with the text track, enabling styling of the displayed cues.

**4. Logical Reasoning and Examples:**

* **Mode Changes:**  The `setMode()` logic is a prime example of logical reasoning. If the mode changes to `disabled`, cues need to be removed. If it changes to `showing`, cues need to be added.
* **Active Cues:** The `activeCues()` method exemplifies filtering based on the current time and cue start/end times.

**5. Common User/Programming Errors:**

* **Adding Cues with Invalid Times:** The `addCue()` method checks for `NaN` start and end times.
* **Removing Non-Existent Cues:** The `removeCue()` method throws an error if the cue isn't part of the track.
* **Incorrect `kind` Attribute:** Using an invalid `kind` attribute on the `<track>` element would likely lead to the track not being processed correctly.

**6. User Operations:**

This requires understanding the chain of events. A user adds a `<track>` element to their HTML. The browser parses this, creates a `TextTrack` object, loads the track data (e.g., a VTT file), parses the cues, and then the JavaScript API on the `<video>`/`<audio>` element allows interaction with these `TextTrack` objects. The user might interact with controls to enable/disable subtitles, which would trigger the `setMode()` method in the C++ code.

**Self-Correction/Refinement During the Process:**

* **Initially, I might have focused too heavily on the individual methods in isolation.**  Realizing the interconnectedness – how `setMode()` affects cue visibility, how `addCue()` interacts with the timeline – is crucial.
* **Understanding the "live" nature of `TextTrackCueList` was important.** This means the list isn't a static copy but reflects the current state.
* **Recognizing the significance of the `CueTimeline`** for managing cue display based on time was a key insight.

By following this structured approach, combining code reading with an understanding of the underlying web technologies and user interactions, a comprehensive analysis of the `TextTrack.cc` file can be achieved.
好的，让我们来分析一下 `blink/renderer/core/html/track/text_track.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概述:**

`text_track.cc` 文件定义了 `TextTrack` 类，这个类是 Blink 渲染引擎中处理文本轨道（Text Tracks）的核心组件。文本轨道通常用于为 HTML5 的 `<video>` 和 `<audio>` 元素提供字幕、副标题、描述、章节等信息。

主要功能包括：

1. **表示文本轨道:** `TextTrack` 类封装了文本轨道的属性，例如：
    * `kind` (字幕、副标题、描述等)
    * `label` (用户可见的轨道名称)
    * `language` (轨道语言)
    * `mode` (轨道的显示模式：禁用、隐藏、显示)
    * 关联的 `TextTrackCue` 列表 (具体的字幕/副标题内容)
    * 关联的 `TextTrackList` (包含该轨道的轨道列表)

2. **管理文本轨道的生命周期:** 包括创建、加载、激活、禁用等状态的管理。

3. **处理文本提示 (Cues):**  `TextTrack` 负责管理与该轨道关联的 `TextTrackCue` 对象。这些 `TextTrackCue` 对象包含了具体的文本内容、开始时间和结束时间等信息。

4. **与媒体元素交互:** `TextTrack` 需要与 `HTMLMediaElement` 交互，以确定何时显示或隐藏文本提示。

5. **实现 JavaScript API:** `TextTrack` 类的方法和属性对应了 Web 开发者可以通过 JavaScript 访问的 `TextTrack` 接口。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML (`<track>` 元素):**
    * **关系:** 当 HTML 中出现 `<track>` 元素时，Blink 引擎会解析这个元素，并创建一个对应的 `TextTrack` 对象。`<track>` 元素的属性（如 `kind`, `label`, `srclang`）会被用来初始化 `TextTrack` 对象的相应属性。
    * **举例:**
      ```html
      <video controls>
        <source src="my-video.mp4" type="video/mp4">
        <track src="subtitles_en.vtt" kind="subtitles" srclang="en" label="English">
      </video>
      ```
      在这个例子中，`<track>` 元素指定了一个英文字幕文件。Blink 会创建一个 `TextTrack` 对象，其 `kind` 属性为 "subtitles"，`language` 属性为 "en"，`label` 属性为 "English"。

* **JavaScript (TextTrack API):**
    * **关系:** `TextTrack` 类实现了 Web 开发者可以通过 JavaScript 访问的 `TextTrack` API。例如，可以通过 JavaScript 获取 `TextTrack` 对象的 `mode` 属性，设置 `mode` 属性来控制字幕的显示，或者访问 `cues` 属性来获取所有的文本提示。
    * **举例:**
      ```javascript
      const video = document.querySelector('video');
      const tracks = video.textTracks;
      const englishSubtitles = tracks.find(track => track.language === 'en');

      if (englishSubtitles) {
        console.log(englishSubtitles.label); // 输出 "English"
        englishSubtitles.mode = 'showing'; // 显示英文字幕
      }
      ```
      这段 JavaScript 代码获取了视频的文本轨道列表，找到了英语字幕轨道，并将其 `mode` 设置为 "showing"，从而显示字幕。

* **CSS (通过 WebVTT 或 JavaScript 操作):**
    * **关系:** 虽然 `text_track.cc` 本身不直接处理 CSS 解析，但它负责管理文本提示，而文本提示的样式可以通过 WebVTT 文件中的 CSS 规则或者通过 JavaScript 来修改。
    * **举例 (WebVTT):**
      ```vtt
      WEBVTT

      STYLE
      ::cue {
        color: yellow;
        background-color: rgba(0, 0, 0, 0.8);
      }
      ```
      这个 WebVTT 文件定义了所有文本提示的默认样式为黄色文字和半透明黑色背景。当 `TextTrack` 加载这个 VTT 文件时，这些样式会应用到显示的字幕上。
    * **举例 (JavaScript):** 可以通过 JavaScript 遍历 `TextTrackCue` 对象，并修改其 `text` 属性中的 HTML 标签，从而应用 CSS 样式。

**逻辑推理、假设输入与输出:**

假设输入一个 `<track>` 元素，其 `kind` 属性为 "subtitles"，并且关联了一个包含以下 WebVTT 内容的文件：

```vtt
WEBVTT

00:00:00.000 --> 00:00:05.000
Hello, world!

00:00:06.000 --> 00:00:10.000
This is another subtitle.
```

**假设输入:** 一个 `HTMLTrackElement` 对象，其属性如下：
* `kind`: "subtitles"
* `src`: 指向上述 WebVTT 文件的 URL
* `srclang`: "en"
* `label`: "English Subtitles"

**逻辑推理过程 (简化):**

1. Blink 引擎解析到 `<track>` 元素。
2. 创建一个 `TextTrack` 对象，并根据 `<track>` 元素的属性进行初始化：
   * `kind_` 将被设置为 `TextTrack::SubtitlesKeyword()`。
   * `label_` 将被设置为 "English Subtitles"。
   * `language_` 将被设置为 "en"。
3. 异步加载 `src` 指向的 WebVTT 文件。
4. 解析 WebVTT 文件内容，创建两个 `TextTrackCue` 对象：
   * 第一个 Cue 的 `startTime` 为 0 秒，`endTime` 为 5 秒，`text` 为 "Hello, world!"。
   * 第二个 Cue 的 `startTime` 为 6 秒，`endTime` 为 10 秒，`text` 为 "This is another subtitle."。
5. 将这两个 `TextTrackCue` 对象添加到 `TextTrack` 对象的内部 Cue 列表 (`cues_`) 中。

**假设输出:**

* 一个 `TextTrack` 对象，其状态为已加载 (`readiness_state_` 为 `kLoaded`)。
* `TextTrack` 对象的 `cues()` 方法将返回一个 `TextTrackCueList` 对象，包含两个 `TextTrackCue` 实例。

**用户或编程常见的使用错误:**

1. **`kind` 属性使用错误:**
   * **错误:** 在 `<track>` 元素中使用了无效的 `kind` 值，例如 `<track kind="wrong">`。
   * **结果:** 浏览器可能无法正确识别轨道类型，导致功能异常或默认处理。
   * **`text_track.cc` 的处理:** `IsValidKindKeyword()` 方法用于检查 `kind` 属性的有效性。

2. **尝试在 `mode` 为 "disabled" 时访问 `cues` 属性:**
   * **错误:**  JavaScript 代码尝试访问一个 `mode` 为 "disabled" 的 `TextTrack` 对象的 `cues` 属性。
   * **结果:** 根据规范，此时 `cues` 属性应该返回 `null`。
   * **`text_track.cc` 的处理:** `TextTrack::cues()` 方法会检查 `mode_` 的值，如果为 `kDisabled` 则返回 `nullptr`。

3. **添加具有无效时间戳的 Cue:**
   * **错误:**  通过 JavaScript 的 `addCue()` 方法添加一个 `startTime` 或 `endTime` 为 `NaN` 的 `TextTrackCue` 对象。
   * **结果:**  该 Cue 将不会被添加到轨道中。
   * **`text_track.cc` 的处理:** `TextTrack::addCue()` 方法会检查 Cue 的 `startTime()` 和 `endTime()` 是否为 `NaN`。

4. **在错误的 `TextTrack` 对象上调用 `removeCue()`:**
   * **错误:** 尝试从一个 `TextTrack` 对象中移除一个不属于该轨道的 `TextTrackCue` 对象。
   * **结果:**  会抛出一个 `NotFoundError` 异常。
   * **`text_track.cc` 的处理:** `TextTrack::removeCue()` 方法会检查要移除的 Cue 是否属于当前轨道。

**用户操作如何一步步到达这里:**

1. **用户在 HTML 文件中添加了 `<video>` 或 `<audio>` 元素，并包含了 `<track>` 子元素。**  例如：
   ```html
   <video controls>
     <source src="my-video.mp4" type="video/mp4">
     <track src="subtitles_en.vtt" kind="subtitles" srclang="en" label="English">
   </video>
   ```

2. **浏览器加载 HTML 页面并解析 DOM 树。**  当解析到 `<track>` 元素时，Blink 引擎会创建对应的 `HTMLTrackElement` 对象。

3. **Blink 引擎会为 `<track>` 元素创建一个关联的 `TextTrack` 对象。**  这个过程涉及到 `HTMLTrackElement` 与 `TextTrack` 的关联。

4. **浏览器开始加载 `<track>` 元素的 `src` 属性指向的文本轨道文件（例如 VTT 文件）。**

5. **加载完成后，Blink 引擎会解析文本轨道文件的内容，并创建 `TextTrackCue` 对象。** 这些 Cue 对象会被添加到 `TextTrack` 对象的内部列表中。

6. **用户与媒体元素交互，例如点击播放按钮。**  随着视频的播放，媒体引擎会通知 Blink 渲染引擎当前的时间。

7. **`TextTrack` 对象会根据当前时间，检查哪些 `TextTrackCue` 应该处于激活状态。**

8. **如果 `TextTrack` 的 `mode` 为 "showing"，并且有激活的 Cue，Blink 渲染引擎会将这些 Cue 的内容渲染到屏幕上。**  这通常涉及到创建或更新 DOM 元素来显示字幕或副标题。

9. **用户可以通过浏览器的媒体控件或自定义 JavaScript 代码来控制文本轨道的显示模式 (`mode`)。** 例如，点击字幕按钮可能会将 `TextTrack` 的 `mode` 从 "hidden" 切换到 "showing"。  这个操作会调用 `TextTrack::setMode()` 方法。

总而言之，`text_track.cc` 文件是 Blink 引擎中处理文本轨道的核心组件，它连接了 HTML 中的 `<track>` 元素、JavaScript 的 `TextTrack` API 以及实际的字幕/副标题数据的加载和显示过程。它负责管理文本轨道的生命周期、文本提示，并与媒体元素协同工作，最终让用户能够看到或听到同步的文本信息。

Prompt: 
```
这是目录为blink/renderer/core/html/track/text_track.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
/*
 * Copyright (C) 2011 Google Inc.  All rights reserved.
 * Copyright (C) 2011, 2012, 2013 Apple Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/track/text_track.h"

#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/track/cue_timeline.h"
#include "third_party/blink/renderer/core/html/track/text_track_cue_list.h"
#include "third_party/blink/renderer/core/html/track/text_track_list.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "ui/accessibility/accessibility_features.h"

namespace blink {

static const int kInvalidTrackIndex = -1;

const AtomicString& TextTrack::SubtitlesKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, subtitles, ("subtitles"));
  return subtitles;
}

const AtomicString& TextTrack::CaptionsKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, captions, ("captions"));
  return captions;
}

const AtomicString& TextTrack::DescriptionsKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, descriptions, ("descriptions"));
  return descriptions;
}

const AtomicString& TextTrack::ChaptersKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, chapters, ("chapters"));
  return chapters;
}

const AtomicString& TextTrack::MetadataKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, metadata, ("metadata"));
  return metadata;
}

TextTrack::TextTrack(const V8TextTrackKind& kind,
                     const AtomicString& label,
                     const AtomicString& language,
                     HTMLElement& source_element,
                     const AtomicString& id,
                     TextTrackType type)
    : TrackBase(WebMediaPlayer::kTextTrack, label, language, id),
      active_cues_(nullptr),
      track_list_(nullptr),
      source_element_(source_element),
      track_type_(type),
      readiness_state_(kNotLoaded),
      track_index_(kInvalidTrackIndex),
      rendered_track_index_(kInvalidTrackIndex),
      has_been_configured_(false),
      kind_(kind.AsEnum()) {}

TextTrack::~TextTrack() = default;

bool TextTrack::IsValidKindKeyword(const String& value) {
  if (value == SubtitlesKeyword())
    return true;
  if (value == CaptionsKeyword())
    return true;
  if (value == DescriptionsKeyword())
    return true;
  if (value == ChaptersKeyword())
    return true;
  if (value == MetadataKeyword())
    return true;

  return false;
}

void TextTrack::SetTrackList(TextTrackList* track_list) {
  if (!track_list && GetCueTimeline() && cues_)
    GetCueTimeline()->RemoveCues(this, cues_.Get());

  track_list_ = track_list;
  InvalidateTrackIndex();
}

bool TextTrack::IsVisualKind() const {
  return kind() == SubtitlesKeyword() || kind() == CaptionsKeyword();
}

bool TextTrack::IsSpokenKind() const {
  return kind() == DescriptionsKeyword();
}

void TextTrack::setMode(const V8TextTrackMode& mode) {
  // On setting, if the new value isn't equal to what the attribute would
  // currently return, the new value must be processed as follows ...
  if (mode_ == mode.AsEnum())
    return;

  if (cues_ && GetCueTimeline()) {
    // If mode changes to disabled, remove this track's cues from the client
    // because they will no longer be accessible from the cues() function.
    if (mode == TextTrackMode::kDisabled)
      GetCueTimeline()->RemoveCues(this, cues_.Get());
    else if (mode != TextTrackMode::kShowing)
      GetCueTimeline()->HideCues(this, cues_.Get());
  }

  mode_ = mode.AsEnum();

  if (mode != TextTrackMode::kDisabled && GetReadinessState() == kLoaded) {
    if (cues_ && GetCueTimeline())
      GetCueTimeline()->AddCues(this, cues_.Get());
  }

  if (MediaElement())
    MediaElement()->TextTrackModeChanged(this);
}

void TextTrack::SetModeEnum(TextTrackMode mode) {
  setMode(V8TextTrackMode(mode));
}

TextTrackCueList* TextTrack::cues() {
  // 4.8.10.12.5 If the text track mode ... is not the text track disabled mode,
  // then the cues attribute must return a live TextTrackCueList object ...
  // Otherwise, it must return null. When an object is returned, the
  // same object must be returned each time.
  // http://www.whatwg.org/specs/web-apps/current-work/#dom-texttrack-cues
  if (mode_ != TextTrackMode::kDisabled)
    return EnsureTextTrackCueList();
  return nullptr;
}

void TextTrack::Reset() {
  if (!cues_)
    return;

  if (GetCueTimeline())
    GetCueTimeline()->RemoveCues(this, cues_.Get());

  for (wtf_size_t i = 0; i < cues_->length(); ++i)
    cues_->AnonymousIndexedGetter(i)->SetTrack(nullptr);

  cues_->RemoveAll();
  if (active_cues_)
    active_cues_->RemoveAll();

  style_sheets_.clear();
}

void TextTrack::AddListOfCues(
    HeapVector<Member<TextTrackCue>>& list_of_new_cues) {
  TextTrackCueList* cues = EnsureTextTrackCueList();

  for (auto& new_cue : list_of_new_cues) {
    new_cue->SetTrack(this);
    cues->Add(new_cue);
  }

  if (GetCueTimeline() && mode() != TextTrackMode::kDisabled)
    GetCueTimeline()->AddCues(this, cues);
}

TextTrackCueList* TextTrack::activeCues() {
  // 4.8.10.12.5 If the text track mode ... is not the text track disabled mode,
  // then the activeCues attribute must return a live TextTrackCueList object
  // ... whose active flag was set when the script started, in text track cue
  // order. Otherwise, it must return null. When an object is returned, the same
  // object must be returned each time.
  // http://www.whatwg.org/specs/web-apps/current-work/#dom-texttrack-activecues
  if (!cues_ || mode_ == TextTrackMode::kDisabled)
    return nullptr;

  if (!active_cues_) {
    active_cues_ = MakeGarbageCollected<TextTrackCueList>();
  }

  cues_->CollectActiveCues(*active_cues_);
  return active_cues_.Get();
}

void TextTrack::addCue(TextTrackCue* cue) {
  DCHECK(cue);

  if (std::isnan(cue->startTime()) || std::isnan(cue->endTime()))
    return;

  // https://html.spec.whatwg.org/C/#dom-texttrack-addcue

  // The addCue(cue) method of TextTrack objects, when invoked, must run the
  // following steps:

  // (Steps 1 and 2 - pertaining to association of rendering rules - are not
  // implemented.)

  // 3. If the given cue is in a text track list of cues, then remove cue
  // from that text track list of cues.
  if (TextTrack* cue_track = cue->track())
    cue_track->removeCue(cue, ASSERT_NO_EXCEPTION);

  // 4. Add cue to the method's TextTrack object's text track's text track list
  // of cues.
  cue->SetTrack(this);
  EnsureTextTrackCueList()->Add(cue);

  if (GetCueTimeline() && mode_ != TextTrackMode::kDisabled)
    GetCueTimeline()->AddCue(this, cue);
}

void TextTrack::SetCSSStyleSheets(
    HeapVector<Member<CSSStyleSheet>> style_sheets) {
  DCHECK(style_sheets_.empty());
  style_sheets_ = std::move(style_sheets);
}

void TextTrack::removeCue(TextTrackCue* cue, ExceptionState& exception_state) {
  DCHECK(cue);

  // https://html.spec.whatwg.org/C/#dom-texttrack-removecue

  // The removeCue(cue) method of TextTrack objects, when invoked, must run the
  // following steps:

  // 1. If the given cue is not currently listed in the method's TextTrack
  // object's text track's text track list of cues, then throw a NotFoundError
  // exception.
  if (cue->track() != this) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The specified cue is not listed in the TextTrack's list of cues.");
    return;
  }

  // cue->track() == this implies that cue is in this track's list of cues,
  // so this track should have a list of cues and the cue being removed
  // should be in it.
  DCHECK(cues_);

  // 2. Remove cue from the method's TextTrack object's text track's text track
  // list of cues.
  bool was_removed = cues_->Remove(cue);
  DCHECK(was_removed);

  // If the cue is active, a timeline needs to be available.
  DCHECK(!cue->IsActive() || GetCueTimeline());

  cue->SetTrack(nullptr);

  if (GetCueTimeline())
    GetCueTimeline()->RemoveCue(this, cue);
}

void TextTrack::CueWillChange(TextTrackCue* cue) {
  // The cue may need to be repositioned in the media element's interval tree,
  // may need to be re-rendered, etc, so remove it before the modification...
  if (GetCueTimeline())
    GetCueTimeline()->RemoveCue(this, cue);
}

void TextTrack::CueDidChange(TextTrackCue* cue, bool update_cue_index) {
  // This method is called through cue->track(), which should imply that this
  // track has a list of cues.
  DCHECK(cues_ && cue->track() == this);

  // Make sure the TextTrackCueList order is up to date.
  if (update_cue_index)
    cues_->UpdateCueIndex(cue);

  // Since a call to cueDidChange is always preceded by a call to
  // cueWillChange, the cue should no longer be active when we reach this
  // point (since it was removed from the timeline in cueWillChange).
  DCHECK(!cue->IsActive());

  if (mode_ == TextTrackMode::kDisabled)
    return;

  // ... and add it back again if the track is enabled.
  if (GetCueTimeline())
    GetCueTimeline()->AddCue(this, cue);
}

int TextTrack::TrackIndex() {
  DCHECK(track_list_);

  if (track_index_ == kInvalidTrackIndex)
    track_index_ = track_list_->GetTrackIndex(this);

  return track_index_;
}

void TextTrack::InvalidateTrackIndex() {
  track_index_ = kInvalidTrackIndex;
  rendered_track_index_ = kInvalidTrackIndex;
}

bool TextTrack::IsRendered() const {
  if (features::IsTextBasedAudioDescriptionEnabled()) {
    return mode_ == TextTrackMode::kShowing &&
           (IsVisualKind() || IsSpokenKind());
  }
  return mode_ == TextTrackMode::kShowing && IsVisualKind();
}

bool TextTrack::CanBeRendered() const {
  // A track can be displayed when it's of kind captions, subtitles, or
  // descriptions and hasn't failed to load.
  if (features::IsTextBasedAudioDescriptionEnabled()) {
    return GetReadinessState() != kFailedToLoad &&
           (IsVisualKind() || IsSpokenKind());
  }
  return GetReadinessState() != kFailedToLoad && IsVisualKind();
}

TextTrackCueList* TextTrack::EnsureTextTrackCueList() {
  if (!cues_) {
    cues_ = MakeGarbageCollected<TextTrackCueList>();
  }

  return cues_.Get();
}

int TextTrack::TrackIndexRelativeToRenderedTracks() {
  DCHECK(track_list_);

  if (rendered_track_index_ == kInvalidTrackIndex)
    rendered_track_index_ =
        track_list_->GetTrackIndexRelativeToRenderedTracks(this);

  return rendered_track_index_;
}

const AtomicString& TextTrack::InterfaceName() const {
  return event_target_names::kTextTrack;
}

ExecutionContext* TextTrack::GetExecutionContext() const {
  DCHECK(source_element_);
  DCHECK(!MediaElement() || source_element_->GetExecutionContext() ==
                                MediaElement()->GetExecutionContext());
  return source_element_->GetExecutionContext();
}

HTMLMediaElement* TextTrack::MediaElement() const {
  return track_list_ ? track_list_->Owner() : nullptr;
}

CueTimeline* TextTrack::GetCueTimeline() const {
  return MediaElement() ? &MediaElement()->GetCueTimeline() : nullptr;
}

Node* TextTrack::Owner() const {
  return MediaElement();
}

void TextTrack::Trace(Visitor* visitor) const {
  visitor->Trace(cues_);
  visitor->Trace(active_cues_);
  visitor->Trace(track_list_);
  visitor->Trace(style_sheets_);
  visitor->Trace(source_element_);
  TrackBase::Trace(visitor);
  EventTarget::Trace(visitor);
}

}  // namespace blink

"""

```