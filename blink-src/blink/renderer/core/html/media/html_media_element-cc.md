Response:
The user wants a summary of the functionality of the provided C++ code snippet from `html_media_element.cc`. They also want to understand how this code interacts with JavaScript, HTML, and CSS, along with examples. Finally, they are looking for potential user or programming errors related to this part of the code.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file is `html_media_element.cc`. The name strongly suggests this code is responsible for the core behavior of HTML media elements (`<video>` and `<audio>`).

2. **Scan for Key Class/Function Names:** Look for prominent classes and functions. `HTMLMediaElement`, `WebMediaPlayer`, `AudioTrackList`, `VideoTrackList`, `MediaControls`, `AutoplayPolicy`, and functions like `load`, `play`, `pause`, and event handlers (e.g., `LoadTimerFired`, `ProgressEventTimerFired`) stand out.

3. **Analyze Includes:** The included headers reveal dependencies and related functionalities. Headers like `<algorithm>`, `<limits>`, `<utility>`, and `<base/...>` provide general utilities. Headers related to `media/`, `cc/layers/`, `public/platform/web_media_player.h`, and those within the `third_party/blink/renderer/core/html/media/` directory are directly relevant to media element implementation. Headers related to `dom`, `css`, `frame`, and `bindings` point to interactions with other web platform features.

4. **Focus on the Provided Snippet:** The provided code initializes several member variables within the `HTMLMediaElement` constructor. This gives a good overview of the state and components managed by the class:
    * Timers for various operations (loading, progress, audio tracks).
    * Queues for asynchronous events.
    * Playback state variables (rate, paused, playing, seeking, muted).
    * Network and ready state variables.
    * Track lists (audio and video).
    * References to media controls and autoplay policy.
    * Mojo-related components for communication with the browser process.

5. **Infer Functionality from Members:** Based on the initialized members, infer the high-level functions:
    * **Loading and Resource Management:** `load_timer_`, network state, ready state.
    * **Playback Control:** `playback_rate_`, `paused_`, `playing_`, `seeking_`.
    * **Track Management:** `audio_tracks_`, `video_tracks_`.
    * **User Interface:** `media_controls_`.
    * **Autoplay Handling:** `autoplay_policy_`.
    * **Communication with the Browser:** Mojo components.

6. **Connect to Web Technologies:**  Think about how these internal functionalities map to user-facing web technologies:
    * **JavaScript:**  JavaScript directly interacts with the media element through its properties and methods (e.g., `video.play()`, `video.pause()`, `video.src`). The events handled in the C++ code (e.g., `loadeddata`, `progress`, `stalled`) are dispatched to JavaScript.
    * **HTML:** The `<video>` and `<audio>` tags in HTML create instances of `HTMLMediaElement`. Attributes like `src`, `controls`, `autoplay`, `preload`, and `muted` are parsed and affect the element's behavior.
    * **CSS:** CSS styles can affect the appearance of the media element and its controls. The code mentions style recalc, indicating CSS changes trigger internal updates.

7. **Provide Concrete Examples:** Illustrate the connections with simple HTML and JavaScript examples. Show how setting attributes or calling methods in JavaScript corresponds to actions within the C++ code.

8. **Consider User/Programming Errors:** Think about common mistakes developers make when working with media elements:
    * Incorrect MIME types leading to loading failures.
    * Issues with autoplay blocking.
    * Not handling media events properly.
    * Setting invalid playback rates.

9. **Address Logical Inference (if any):**  While the current snippet is primarily about initialization, if there were conditional logic, provide hypothetical inputs and outputs to illustrate the flow. For instance, if there was a condition based on the `controls` attribute, you could say "If the `controls` attribute is present, the output will be the display of default media controls."

10. **Structure the Answer:** Organize the information logically with clear headings and bullet points. Start with a general summary, then detail the connections to web technologies, provide examples, discuss potential errors, and finally, summarize the functionality of the provided code snippet.

11. **Refine and Review:** Ensure the language is clear and concise. Double-check the accuracy of the examples and explanations. Make sure the summary directly addresses the "part 1" instruction.
```cpp
/*
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc. All rights
 * reserved.
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
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/media/html_media_element.h"

// ... (includes) ...

namespace blink {

// ... (anonymous namespace) ...

// static
MIMETypeRegistry::SupportsType HTMLMediaElement::GetSupportsType(
    const ContentType& content_type) {
  // ... (implementation for checking media type support) ...
}

bool HTMLMediaElement::IsHLSURL(const KURL& url) {
  // ... (implementation for checking if a URL is an HLS URL) ...
}

// static
void HTMLMediaElement::OnMediaControlsEnabledChange(Document* document) {
  // ... (implementation for updating media controls visibility) ...
}

HTMLMediaElement::HTMLMediaElement(const QualifiedName& tag_name,
                                   Document& document)
    : HTMLElement(tag_name, document),
      ActiveScriptWrappable<HTMLMediaElement>({}),
      ExecutionContextLifecycleStateObserver(GetExecutionContext()),
      load_timer_(document.GetTaskRunner(TaskType::kInternalMedia),
                  this,
                  &HTMLMediaElement::LoadTimerFired),
      audio_tracks_timer_(document.GetTaskRunner(TaskType::kInternalMedia),
                          this,
                          &HTMLMediaElement::AudioTracksTimerFired),
      removed_from_document_timer_(
          document.GetTaskRunner(TaskType::kInternalMedia),
          this,
          &HTMLMediaElement::OnRemovedFromDocumentTimerFired),
      progress_event_timer_(
          document.GetTaskRunner(TaskType::kInternalMedia),
          WTF::BindRepeating(&HTMLMediaElement::ProgressEventTimerFired,
                             WrapWeakPersistent(this))),
      playback_progress_timer_(
          document.GetTaskRunner(TaskType::kInternalMedia),
          WTF::BindRepeating(&HTMLMediaElement::PlaybackProgressTimerFired,
                             WrapWeakPersistent(this))),
      async_event_queue_(
          MakeGarbageCollected<EventQueue>(GetExecutionContext(),
                                           TaskType::kMediaElementEvent)),
      playback_rate_(1.0f),
      default_playback_rate_(1.0f),
      network_state_(kNetworkEmpty),
      ready_state_(kHaveNothing),
      ready_state_maximum_(kHaveNothing),
      volume_(1.0f),
      last_seek_time_(0),
      duration_(std::numeric_limits<double>::quiet_NaN()),
      last_time_update_event_media_time_(
          std::numeric_limits<double>::quiet_NaN()),
      default_playback_start_position_(0),
      load_state_(kWaitingForSource),
      deferred_load_state_(kNotDeferred),
      deferred_load_timer_(document.GetTaskRunner(TaskType::kInternalMedia),
                           this,
                           &HTMLMediaElement::DeferredLoadTimerFired),
      cc_layer_(nullptr),
      official_playback_position_(0),
      official_playback_position_needs_update_(true),
      fragment_end_time_(std::numeric_limits<double>::quiet_NaN()),
      pending_action_flags_(0),
      playing_(false),
      should_delay_load_event_(false),
      have_fired_loaded_data_(false),
      can_autoplay_(true),
      muted_(false),
      paused_(true),
      seeking_(false),
      paused_by_context_paused_(false),
      show_poster_flag_(true),
      sent_stalled_event_(false),
      ignore_preload_none_(false),
      text_tracks_visible_(false),
      should_perform_automatic_track_selection_(true),
      tracks_are_ready_(true),
      processing_preference_change_(false),
      was_always_muted_(true),
      audio_tracks_(MakeGarbageCollected<AudioTrackList>(*this)),
      video_tracks_(MakeGarbageCollected<VideoTrackList>(*this)),
      audio_source_node_(nullptr),
      speech_synthesis_(nullptr),
      autoplay_policy_(MakeGarbageCollected<AutoplayPolicy>(this)),
      media_controls_(nullptr),
      controls_list_(MakeGarbageCollected<HTMLMediaElementControlsList>(this)),
      lazy_load_intersection_observer_(nullptr) {
  DVLOG(1) << "HTMLMediaElement(" << *this << ")";

  ResetMojoState();

  LocalFrame* frame = document.GetFrame();
  if (frame) {
    remote_playback_client_ =
        frame->Client()->CreateRemotePlaybackClient(*this);
  }

  SetHasCustomStyleCallbacks();
  AddElementToDocumentMap(this, &document);

  UseCounter::Count(document, WebFeature::kHTMLMediaElement);
}

HTMLMediaElement::~HTMLMediaElement() {
  DVLOG(1) << "~HTMLMediaElement(" << *this << ")";
}

void HTMLMediaElement::Dispose() {
  // ... (implementation for cleanup) ...
}

void HTMLMediaElement::DidMoveToNewDocument(Document& old_document) {
  // ... (implementation for handling document changes) ...
}

bool HTMLMediaElement::ShouldReusePlayer(Document& old_document,
                                         Document& new_document) const {
  // ... (implementation for determining if the media player can be reused) ...
}

void HTMLMediaElement::AttachToNewFrame() {
  // ... (implementation for attaching to a new frame) ...
}

void HTMLMediaElement::ResetMojoState() {
  // ... (implementation for resetting Mojo communication state) ...
}

FocusableState HTMLMediaElement::SupportsFocus(
    UpdateBehavior update_behavior) const {
  // ... (implementation for determining focusability) ...
}

FocusableState HTMLMediaElement::IsFocusableState(
    UpdateBehavior update_behavior) const {
  // ... (implementation for determining focusable state) ...
}

int HTMLMediaElement::DefaultTabIndex() const {
  return 0;
}

void HTMLMediaElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  if (name == html_names::kSrcAttr) {
    // ... (handling of the 'src' attribute) ...
  } else if (name == html_names::kControlsAttr) {
    // ... (handling of the 'controls' attribute) ...
  } else if (name == html_names::kControlslistAttr) {
    // ... (handling of the 'controlslist' attribute) ...
  } else if (name == html_names::kPreloadAttr) {
    // ... (handling of the 'preload' attribute) ...
  } else if (name == html_names::kDisableremoteplaybackAttr) {
    // ... (handling of the 'disableremoteplayback' attribute) ...
  } else if (name == html_names::kLatencyhintAttr &&
             RuntimeEnabledFeatures::MediaLatencyHintEnabled()) {
    // ... (handling of the 'latencyhint' attribute) ...
  } else if (name == html_names::kMutedAttr) {
    if (params.reason == AttributeModificationReason::kByParser) {
      muted_ = true;
    }
  } else
```

## 功能归纳

这部分代码主要负责 `HTMLMediaElement` 类的**构造、析构、基本属性初始化和一些静态辅助方法**。  更具体地说，它包含了以下功能：

1. **类定义和初始化:**
   - 定义了 `HTMLMediaElement` 类，它是 `<video>` 和 `<audio>` 等 HTML 媒体元素在 Blink 渲染引擎中的核心实现类。
   - 在构造函数 `HTMLMediaElement::HTMLMediaElement` 中初始化了大量的成员变量，这些变量用于存储媒体元素的状态信息，例如：
     - **播放状态:** `playback_rate_`, `paused_`, `playing_`, `seeking_`, `muted_`
     - **网络状态和加载状态:** `network_state_`, `ready_state_`, `load_state_`
     - **时间信息:** `duration_`, `last_seek_time_`
     - **音视频轨道信息:** `audio_tracks_`, `video_tracks_`
     - **控制界面相关:** `media_controls_`, `controls_list_`
     - **定时器:** 用于执行异步操作，例如加载、进度更新、音频轨道更新等。
     - **其他辅助对象:** `autoplay_policy_`, `remote_playback_client_` 等。
   - 初始化了与 Mojo 通信相关的对象 (`media_player_host_remote_`, `media_player_observer_remote_set_`, `media_player_receiver_set_`)，用于和浏览器进程中的媒体播放器进行交互。

2. **静态辅助方法:**
   - `GetSupportsType`:  判断给定的 MIME 类型是否为浏览器支持的媒体类型。
   - `IsHLSURL`: 判断给定的 URL 是否为 HLS (HTTP Live Streaming) 的 URL。
   - `OnMediaControlsEnabledChange`:  当文档的媒体控件启用状态发生变化时，更新所有媒体元素的控件可见性。

3. **生命周期管理:**
   - `~HTMLMediaElement`:  析构函数，负责清理资源。
   - `Dispose`:  执行更彻底的资源释放，例如清除媒体播放器和音频源提供客户端。
   - `DidMoveToNewDocument`:  处理媒体元素从一个文档移动到另一个文档的情况，涉及到资源重新加载和播放器状态的调整。
   - `AttachToNewFrame`: 当关联的 Frame 发生变化时，重新加载媒体资源。

4. **属性解析:**
   - `ParseAttribute`:  当 HTML 属性发生变化时被调用，目前代码片段中只处理了 `src`, `controls`, `controlslist`, `preload`, `disableremoteplayback`, `latencyhint`, 和 `muted` 属性。针对不同的属性，会触发相应的内部逻辑更新。

5. **焦点管理:**
   - `SupportsFocus`: 判断媒体元素是否可以获取焦点。
   - `IsFocusableState`:  判断媒体元素当前是否处于可聚焦状态。
   - `DefaultTabIndex`:  返回媒体元素的默认 Tab 索引。

## 与 JavaScript, HTML, CSS 的关系及举例说明

**1. 与 HTML 的关系:**

- **创建实例:**  HTML 中的 `<video>` 或 `<audio>` 标签在浏览器渲染时，会创建 `HTMLMediaElement` 类的实例。
  ```html
  <video src="myvideo.mp4" controls></video>
  <audio src="myaudio.mp3"></audio>
  ```
- **属性映射:** HTML 标签的属性（如 `src`, `controls`, `autoplay`, `preload`, `muted` 等）会映射到 `HTMLMediaElement` 对象的成员变量，并通过 `ParseAttribute` 方法进行解析和处理。
  - 例如，HTML 中的 `controls` 属性会影响 `ShouldShowControls()` 的返回值，进而决定是否显示默认的媒体控件。
  - `src` 属性的变化会触发 `InvokeLoadAlgorithm()`，开始加载新的媒体资源。

**2. 与 JavaScript 的关系:**

- **API 接口:** JavaScript 可以通过 DOM API 获取 `HTMLMediaElement` 对象，并调用其方法和访问其属性，从而控制媒体的播放行为。
  ```javascript
  const video = document.querySelector('video');
  video.play(); // 调用 play() 方法
  video.pause(); // 调用 pause() 方法
  console.log(video.duration); // 访问 duration 属性
  video.muted = true; // 设置 muted 属性
  ```
- **事件监听:**  `HTMLMediaElement` 会触发各种事件（如 `play`, `pause`, `ended`, `loadedmetadata`, `error` 等），JavaScript 可以监听这些事件并执行相应的操作。这些事件的触发机制很多都与 `HTMLMediaElement` 内部的状态变化相关。
  ```javascript
  video.addEventListener('play', () => {
    console.log('Video started playing');
  });
  ```
- **属性设置:** JavaScript 可以动态地设置媒体元素的属性，这些设置会最终反映到 `HTMLMediaElement` 对象的内部状态。

**3. 与 CSS 的关系:**

- **样式控制:** CSS 可以控制媒体元素的外观，例如尺寸、边框、背景等。
  ```css
  video {
    width: 640px;
    height: 480px;
  }
  ```
- **伪类和伪元素:** CSS 还可以使用伪类（如 `:hover`, `:fullscreen`）和伪元素来为媒体元素添加特定的样式。
- **样式重算:** 代码中 `SetNeedsStyleRecalc` 的调用表明，某些属性的变化（例如 `src`）会触发浏览器的样式重算，以便更新媒体元素的布局和渲染。

## 逻辑推理及假设输入与输出

**假设输入:**  一个带有 `controls` 属性的 `<video>` 标签被添加到 DOM 中。

```html
<video id="myVideo" src="myvideo.mp4" controls></video>
```

**逻辑推理:**

1. 当浏览器解析到 `<video>` 标签时，会创建一个 `HTMLMediaElement` 对象。
2. `ParseAttribute` 方法会被调用，解析 `controls` 属性。
3. 由于 `controls` 属性存在，`UpdateControlsVisibility()` 方法会被调用。
4. `UpdateControlsVisibility()` 可能会根据当前文档的设置决定是否显示默认的媒体控件。

**假设输出:**  浏览器会显示视频的默认播放控件（例如播放/暂停按钮、音量控制条、进度条等）。

**假设输入:**  JavaScript 代码设置了 `video.muted = true;`

**逻辑推理:**

1. JavaScript 代码会调用 `HTMLMediaElement` 对象的 `setMuted()` 方法（虽然这个方法在这个代码片段中没有显示，但它是存在的）。
2. `setMuted()` 方法会更新内部的 `muted_` 成员变量。
3. 可能会触发一个 "mute" 事件。

**假设输出:** 视频的音频会被静音。

## 用户或编程常见的使用错误及举例说明

1. **错误的 MIME 类型:**  如果 `<video>` 或 `<audio>` 标签的 `src` 属性指向一个资源，但服务器返回了错误的 `Content-Type` 头部，浏览器可能无法正确解析和播放媒体。
   ```html
   <!-- 假设 myvideo.mp4 服务器错误地返回了 Content-Type: text/plain -->
   <video src="myvideo.mp4"></video>
   ```
   **结果:**  视频可能无法加载或播放，并可能触发 `error` 事件。

2. **尝试在未加载元数据前访问 `duration`:**  在媒体的元数据（如时长）加载完成之前，尝试在 JavaScript 中访问 `video.duration` 可能会得到 `NaN`。
   ```javascript
   const video = document.querySelector('video');
   console.log(video.duration); // 可能输出 NaN
   video.addEventListener('loadedmetadata', () => {
     console.log(video.duration); // 正确输出视频时长
   });
   ```
   **正确做法:**  在 `loadedmetadata` 事件触发后访问 `duration` 属性。

3. **未处理 `error` 事件:**  媒体加载或播放过程中可能发生错误（例如网络错误、解码错误），开发者应该监听 `error` 事件并提供友好的错误提示。
   ```javascript
   const video = document.querySelector('video');
   video.addEventListener('error', (event) => {
     console.error('Media error:', event.target.error);
     alert('Failed to load or play the video.');
   });
   ```
   **错误后果:** 用户可能看到一个空白的播放器，而没有得到任何错误信息。

4. **不正确的 `preload` 属性使用:**  开发者可能错误地理解 `preload` 属性的作用，例如期望设置为 `none` 就完全不进行任何加载。浏览器会根据自身策略进行优化，实际行为可能与预期不符。

## 第1部分功能归纳

总而言之，这部分 `html_media_element.cc` 代码定义了 `HTMLMediaElement` 类的基本结构和行为，包括对象的创建、关键状态的初始化、与 HTML 属性的关联、以及一些核心的辅助功能。它是实现 HTML 媒体元素功能的基础部分，为后续的媒体加载、播放控制、事件处理等功能提供了必要的支撑。

Prompt: 
```
这是目录为blink/renderer/core/html/media/html_media_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc. All rights
 * reserved.
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

#include "third_party/blink/renderer/core/html/media/html_media_element.h"

#include <algorithm>
#include <limits>
#include <utility>

#include "base/auto_reset.h"
#include "base/debug/crash_logging.h"
#include "base/feature_list.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "cc/layers/layer.h"
#include "media/base/media_content_type.h"
#include "media/base/media_switches.h"
#include "media/base/media_track.h"
#include "services/media_session/public/mojom/media_session.mojom-blink.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-shared.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_media_player.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_can_play_type_result.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/core_probes_inl.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/fileapi/url_file_api.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_source_element.h"
#include "third_party/blink/renderer/core/html/media/audio_output_device_controller.h"
#include "third_party/blink/renderer/core/html/media/autoplay_policy.h"
#include "third_party/blink/renderer/core/html/media/html_media_element_controls_list.h"
#include "third_party/blink/renderer/core/html/media/media_controls.h"
#include "third_party/blink/renderer/core/html/media/media_error.h"
#include "third_party/blink/renderer/core/html/media/media_fragment_uri_parser.h"
#include "third_party/blink/renderer/core/html/media/media_source_attachment.h"
#include "third_party/blink/renderer/core/html/media/media_source_handle.h"
#include "third_party/blink/renderer/core/html/media/media_source_tracer.h"
#include "third_party/blink/renderer/core/html/time_ranges.h"
#include "third_party/blink/renderer/core/html/track/audio_track.h"
#include "third_party/blink/renderer/core/html/track/audio_track_list.h"
#include "third_party/blink/renderer/core/html/track/automatic_track_selection.h"
#include "third_party/blink/renderer/core/html/track/cue_timeline.h"
#include "third_party/blink/renderer/core/html/track/html_track_element.h"
#include "third_party/blink/renderer/core/html/track/loadable_text_track.h"
#include "third_party/blink/renderer/core/html/track/text_track_container.h"
#include "third_party/blink/renderer/core/html/track/text_track_list.h"
#include "third_party/blink/renderer/core/html/track/video_track.h"
#include "third_party/blink/renderer/core/html/track/video_track_list.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"
#include "third_party/blink/renderer/core/layout/layout_media.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/speech/speech_synthesis_base.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/audio/audio_source_provider_client.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/media/remote_playback_client.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_from_url.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/accessibility/accessibility_features.h"
#include "ui/display/screen_info.h"

#ifndef LOG_MEDIA_EVENTS
// Default to not logging events because so many are generated they can
// overwhelm the rest of the logging.
#define LOG_MEDIA_EVENTS 0
#endif

#ifndef LOG_OFFICIAL_TIME_STATUS
// Default to not logging status of official time because it adds a fair amount
// of overhead and logging.
#define LOG_OFFICIAL_TIME_STATUS 0
#endif

namespace blink {

using WeakMediaElementSet = HeapHashSet<WeakMember<HTMLMediaElement>>;
using DocumentElementSetMap =
    HeapHashMap<WeakMember<Document>, Member<WeakMediaElementSet>>;

namespace {

// When enabled, CSS media queries are supported in <source> elements.
BASE_FEATURE(kVideoSourceMediaQuerySupport,
             "VideoSourceMediaQuerySupport",
             base::FEATURE_ENABLED_BY_DEFAULT);

// This enum is used to record histograms. Do not reorder.
enum class MediaControlsShow {
  kAttribute = 0,
  kFullscreen,
  kNoScript,
  kNotShown,
  kDisabledSettings,
  kUserExplicitlyEnabled,
  kUserExplicitlyDisabled,
  kMaxValue = kUserExplicitlyDisabled,
};

// The state of the HTMLMediaElement when ProgressEventTimerFired is invoked.
// These values are histogrammed, so please only add values to the end.
enum class ProgressEventTimerState {
  // networkState is not NETWORK_LOADING.
  kNotLoading,
  // MediaShouldBeOpaque() is true.
  kMediaShouldBeOpaque,
  // "progress" event was scheduled.
  kProgress,
  // No progress. The "stalled" event was scheduled.
  kStalled,
  // No progress. No "stalled" event scheduled because a Media Source Attachment
  // is used.
  kHasMediaSourceAttachment,
  // No progress. No "stalled" event scheduled because there was recent
  // progress.
  kRecentProgress,
  // No progress. No "stalled" event scheduled because it was already scheduled.
  kStalledEventAlreadyScheduled,
  kMaxValue = kStalledEventAlreadyScheduled
};

static const base::TimeDelta kStalledNotificationInterval = base::Seconds(3);

String UrlForLoggingMedia(const KURL& url) {
  static const unsigned kMaximumURLLengthForLogging = 128;

  if (url.GetString().length() < kMaximumURLLengthForLogging)
    return url.GetString();
  return url.GetString().GetString().Substring(0, kMaximumURLLengthForLogging) +
         "...";
}

const char* BoolString(bool val) {
  return val ? "true" : "false";
}

DocumentElementSetMap& DocumentToElementSetMap() {
  DEFINE_STATIC_LOCAL(Persistent<DocumentElementSetMap>, map,
                      (MakeGarbageCollected<DocumentElementSetMap>()));
  return *map;
}

void AddElementToDocumentMap(HTMLMediaElement* element, Document* document) {
  DocumentElementSetMap& map = DocumentToElementSetMap();
  WeakMediaElementSet* set = nullptr;
  auto it = map.find(document);
  if (it == map.end()) {
    set = MakeGarbageCollected<WeakMediaElementSet>();
    map.insert(document, set);
  } else {
    set = it->value;
  }
  set->insert(element);
}

void RemoveElementFromDocumentMap(HTMLMediaElement* element,
                                  Document* document) {
  DocumentElementSetMap& map = DocumentToElementSetMap();
  auto it = map.find(document);
  CHECK(it != map.end(), base::NotFatalUntil::M130);
  WeakMediaElementSet* set = it->value;
  set->erase(element);
  if (set->empty())
    map.erase(it);
}

String BuildElementErrorMessage(const String& error) {
  // Prepend a UA-specific-error code before the first ':', to enable better
  // collection and aggregation of UA-specific-error codes from
  // MediaError.message by web apps. WebMediaPlayer::GetErrorMessage() should
  // similarly conform to this format.
  DEFINE_STATIC_LOCAL(const String, element_error_prefix,
                      ("MEDIA_ELEMENT_ERROR: "));
  StringBuilder builder;
  builder.Append(element_error_prefix);
  builder.Append(error);
  return builder.ToString();
}

class AudioSourceProviderClientLockScope {
  STACK_ALLOCATED();

 public:
  explicit AudioSourceProviderClientLockScope(HTMLMediaElement& element)
      : client_(element.AudioSourceNode()) {
    if (client_)
      client_->lock();
  }
  ~AudioSourceProviderClientLockScope() {
    if (client_)
      client_->unlock();
  }

 private:
  AudioSourceProviderClient* client_;
};

bool CanLoadURL(const KURL& url, const String& content_type_str) {
  DEFINE_STATIC_LOCAL(const String, codecs, ("codecs"));

  ContentType content_type(content_type_str);
  String content_mime_type = content_type.GetType().DeprecatedLower();
  String content_type_codecs = content_type.Parameter(codecs);

  // If the MIME type is missing or is not meaningful, try to figure it out from
  // the URL.
  if (content_mime_type.empty() ||
      content_mime_type == "application/octet-stream" ||
      content_mime_type == "text/plain") {
    if (url.ProtocolIsData())
      content_mime_type = MimeTypeFromDataURL(url.GetString());
  }

  // If no MIME type is specified, always attempt to load.
  if (content_mime_type.empty())
    return true;

  // 4.8.12.3 MIME types - In the absence of a specification to the contrary,
  // the MIME type "application/octet-stream" when used with parameters, e.g.
  // "application/octet-stream;codecs=theora", is a type that the user agent
  // knows it cannot render.
  if (content_mime_type != "application/octet-stream" ||
      content_type_codecs.empty()) {
    return MIMETypeRegistry::SupportsMediaMIMEType(content_mime_type,
                                                   content_type_codecs) !=
           MIMETypeRegistry::kNotSupported;
  }

  return false;
}

String PreloadTypeToString(WebMediaPlayer::Preload preload_type) {
  switch (preload_type) {
    case WebMediaPlayer::kPreloadNone:
      return "none";
    case WebMediaPlayer::kPreloadMetaData:
      return "metadata";
    case WebMediaPlayer::kPreloadAuto:
      return "auto";
  }

  NOTREACHED();
}

bool IsValidPlaybackRate(double rate) {
  return rate == 0.0 || (rate >= HTMLMediaElement::kMinPlaybackRate &&
                         rate <= HTMLMediaElement::kMaxPlaybackRate);
}

std::ostream& operator<<(std::ostream& stream,
                         HTMLMediaElement const& media_element) {
  return stream << static_cast<void const*>(&media_element);
}

}  // anonymous namespace

// static
MIMETypeRegistry::SupportsType HTMLMediaElement::GetSupportsType(
    const ContentType& content_type) {
  // TODO(https://crbug.com/809912): Finding source of mime parsing crash.
  static base::debug::CrashKeyString* content_type_crash_key =
      base::debug::AllocateCrashKeyString("media_content_type",
                                          base::debug::CrashKeySize::Size256);
  base::debug::ScopedCrashKeyString scoped_crash_key(
      content_type_crash_key, content_type.Raw().Utf8().c_str());

  String type = content_type.GetType().DeprecatedLower();
  // The codecs string is not lower-cased because MP4 values are case sensitive
  // per http://tools.ietf.org/html/rfc4281#page-7.
  String type_codecs = content_type.Parameter("codecs");

  if (type.empty())
    return MIMETypeRegistry::kNotSupported;

  // 4.8.12.3 MIME types - The canPlayType(type) method must return the empty
  // string if type is a type that the user agent knows it cannot render or is
  // the type "application/octet-stream"
  if (type == "application/octet-stream")
    return MIMETypeRegistry::kNotSupported;

  // |contentType| could be handled using ParsedContentType, but there are
  // still a lot of sites using codec strings that don't work with the
  // stricter parsing rules.
  MIMETypeRegistry::SupportsType result =
      MIMETypeRegistry::SupportsMediaMIMEType(type, type_codecs);
  return result;
}

bool HTMLMediaElement::IsHLSURL(const KURL& url) {
  // Keep the same logic as in media_codec_util.h.
  if (url.IsNull() || url.IsEmpty())
    return false;

  if (!url.IsLocalFile() && !url.ProtocolIs("http") && !url.ProtocolIs("https"))
    return false;

  return url.GetPath().ToString().EndsWith(".m3u8");
}

// static
void HTMLMediaElement::OnMediaControlsEnabledChange(Document* document) {
  auto it = DocumentToElementSetMap().find(document);
  if (it == DocumentToElementSetMap().end())
    return;
  DCHECK(it->value);
  WeakMediaElementSet& elements = *it->value;
  for (const auto& element : elements) {
    element->UpdateControlsVisibility();
    if (element->GetMediaControls())
      element->GetMediaControls()->OnMediaControlsEnabledChange();
  }
}

HTMLMediaElement::HTMLMediaElement(const QualifiedName& tag_name,
                                   Document& document)
    : HTMLElement(tag_name, document),
      ActiveScriptWrappable<HTMLMediaElement>({}),
      ExecutionContextLifecycleStateObserver(GetExecutionContext()),
      load_timer_(document.GetTaskRunner(TaskType::kInternalMedia),
                  this,
                  &HTMLMediaElement::LoadTimerFired),
      audio_tracks_timer_(document.GetTaskRunner(TaskType::kInternalMedia),
                          this,
                          &HTMLMediaElement::AudioTracksTimerFired),
      removed_from_document_timer_(
          document.GetTaskRunner(TaskType::kInternalMedia),
          this,
          &HTMLMediaElement::OnRemovedFromDocumentTimerFired),
      progress_event_timer_(
          document.GetTaskRunner(TaskType::kInternalMedia),
          WTF::BindRepeating(&HTMLMediaElement::ProgressEventTimerFired,
                             WrapWeakPersistent(this))),
      playback_progress_timer_(
          document.GetTaskRunner(TaskType::kInternalMedia),
          WTF::BindRepeating(&HTMLMediaElement::PlaybackProgressTimerFired,
                             WrapWeakPersistent(this))),
      async_event_queue_(
          MakeGarbageCollected<EventQueue>(GetExecutionContext(),
                                           TaskType::kMediaElementEvent)),
      playback_rate_(1.0f),
      default_playback_rate_(1.0f),
      network_state_(kNetworkEmpty),
      ready_state_(kHaveNothing),
      ready_state_maximum_(kHaveNothing),
      volume_(1.0f),
      last_seek_time_(0),
      duration_(std::numeric_limits<double>::quiet_NaN()),
      last_time_update_event_media_time_(
          std::numeric_limits<double>::quiet_NaN()),
      default_playback_start_position_(0),
      load_state_(kWaitingForSource),
      deferred_load_state_(kNotDeferred),
      deferred_load_timer_(document.GetTaskRunner(TaskType::kInternalMedia),
                           this,
                           &HTMLMediaElement::DeferredLoadTimerFired),
      cc_layer_(nullptr),
      official_playback_position_(0),
      official_playback_position_needs_update_(true),
      fragment_end_time_(std::numeric_limits<double>::quiet_NaN()),
      pending_action_flags_(0),
      playing_(false),
      should_delay_load_event_(false),
      have_fired_loaded_data_(false),
      can_autoplay_(true),
      muted_(false),
      paused_(true),
      seeking_(false),
      paused_by_context_paused_(false),
      show_poster_flag_(true),
      sent_stalled_event_(false),
      ignore_preload_none_(false),
      text_tracks_visible_(false),
      should_perform_automatic_track_selection_(true),
      tracks_are_ready_(true),
      processing_preference_change_(false),
      was_always_muted_(true),
      audio_tracks_(MakeGarbageCollected<AudioTrackList>(*this)),
      video_tracks_(MakeGarbageCollected<VideoTrackList>(*this)),
      audio_source_node_(nullptr),
      speech_synthesis_(nullptr),
      autoplay_policy_(MakeGarbageCollected<AutoplayPolicy>(this)),
      media_controls_(nullptr),
      controls_list_(MakeGarbageCollected<HTMLMediaElementControlsList>(this)),
      lazy_load_intersection_observer_(nullptr) {
  DVLOG(1) << "HTMLMediaElement(" << *this << ")";

  ResetMojoState();

  LocalFrame* frame = document.GetFrame();
  if (frame) {
    remote_playback_client_ =
        frame->Client()->CreateRemotePlaybackClient(*this);
  }

  SetHasCustomStyleCallbacks();
  AddElementToDocumentMap(this, &document);

  UseCounter::Count(document, WebFeature::kHTMLMediaElement);
}

HTMLMediaElement::~HTMLMediaElement() {
  DVLOG(1) << "~HTMLMediaElement(" << *this << ")";
}

void HTMLMediaElement::Dispose() {
  // Destroying the player may cause a resource load to be canceled,
  // which could result in LocalDOMWindow::dispatchWindowLoadEvent() being
  // called via ResourceFetch::didLoadResource(), then
  // FrameLoader::checkCompleted(). But it's guaranteed that the load event
  // doesn't get dispatched during the object destruction.
  // See Document::isDelayingLoadEvent().
  // Also see http://crbug.com/275223 for more details.
  ClearMediaPlayerAndAudioSourceProviderClientWithoutLocking();

  progress_event_timer_.Shutdown();
  playback_progress_timer_.Shutdown();
}

void HTMLMediaElement::DidMoveToNewDocument(Document& old_document) {
  DVLOG(3) << "didMoveToNewDocument(" << *this << ")";

  load_timer_.MoveToNewTaskRunner(
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));
  progress_event_timer_.MoveToNewTaskRunner(
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));
  playback_progress_timer_.MoveToNewTaskRunner(
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));
  audio_tracks_timer_.MoveToNewTaskRunner(
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));
  deferred_load_timer_.MoveToNewTaskRunner(
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));
  removed_from_document_timer_.MoveToNewTaskRunner(
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));

  autoplay_policy_->DidMoveToNewDocument(old_document);

  if (cue_timeline_) {
    cue_timeline_->DidMoveToNewDocument(old_document);
  }

  // Stop speaking and set speech_synthesis_ to nullptr so that it is
  // re-created on-demand when SpeechSynthesis() is called.
  if (speech_synthesis_) {
    speech_synthesis_->Cancel();
    speech_synthesis_.Clear();
  }

  if (should_delay_load_event_) {
    GetDocument().IncrementLoadEventDelayCount();
    // Note: Keeping the load event delay count increment on oldDocument that
    // was added when should_delay_load_event_ was set so that destruction of
    // web_media_player_ can not cause load event dispatching in oldDocument.
  } else {
    // Incrementing the load event delay count so that destruction of
    // web_media_player_ can not cause load event dispatching in oldDocument.
    old_document.IncrementLoadEventDelayCount();
  }

  RemoveElementFromDocumentMap(this, &old_document);
  AddElementToDocumentMap(this, &GetDocument());
  SetExecutionContext(GetExecutionContext());

  // FIXME: This is a temporary fix to prevent this object from causing the
  // MediaPlayer to dereference LocalFrame and FrameLoader pointers from the
  // previous document. This restarts the load, as if the src attribute had been
  // set.  A proper fix would provide a mechanism to allow this object to
  // refresh the MediaPlayer's LocalFrame and FrameLoader references on document
  // changes so that playback can be resumed properly.
  // TODO(liberato): Consider checking that the new document's opener is the old
  // document: GetDocument().GetFrame()->Opener() == old_document.GetFrame().
  ignore_preload_none_ = false;

  // Experimental: Try to avoid destroying the media player when transferring a
  // media element to a new document. This is a work in progress, and may cause
  // security and/or stability issues.
  // Normally, moving a player between documents requires destroying the
  // media player because web media player cannot outlive the render frame that
  // holds the element which creates the player. However, when transferring a
  // media player to a same-origin picture-in-picture window opened by this
  // document, it is safe to reuse because a picture-in-picture window is
  // guaranteed not to outlive its opener document because
  // DocumentPictureInPictureController watches the destruction and navigation
  // of the opener's WebContents.
  if (!ShouldReusePlayer(old_document, GetDocument())) {
    // Don't worry about notifications from any previous document if we're not
    // re-using the player.
    if (opener_context_observer_)
      opener_context_observer_->SetContextLifecycleNotifier(nullptr);
    AttachToNewFrame();
  } else if (opener_document_ == GetDocument()) {
    // The element is moving back to the player's opener, so stop worrying.
    DCHECK(opener_context_observer_);
    opener_context_observer_->SetContextLifecycleNotifier(
        opener_document_->GetExecutionContext());
    opener_context_observer_ = nullptr;
    opener_document_ = nullptr;
  } else {
    // Moving to a new document, so make sure that the player's opener is not
    // closed while we're still using it.
    if (!opener_context_observer_) {
      DCHECK(!opener_document_);
      // Only set this when we're going from "original opener" to "elsewhere",
      // in case we're moved from one same-origin window to another.
      //
      // This assumes that the first move is from the opener to the pip window.
      // If `ShouldReusePlayer()` lets the first move be in the other direction,
      // then we'll get this wrong.  Somebody would have to set
      // `opener_document_` correctly before we get here, so we'd end up in the
      // case above, instead.  They'd also have to create the context observer.
      opener_document_ = old_document;
      CHECK(!opener_document_->domWindow()->IsPictureInPictureWindow());
      opener_context_observer_ =
          MakeGarbageCollected<OpenerContextObserver>(this);
    }
    opener_context_observer_->SetContextLifecycleNotifier(
        opener_document_->GetExecutionContext());
  }

  // Decrement the load event delay count on oldDocument now that
  // web_media_player_ has been destroyed and there is no risk of dispatching a
  // load event from within the destructor.
  old_document.DecrementLoadEventDelayCount();

  HTMLElement::DidMoveToNewDocument(old_document);
}

bool HTMLMediaElement::ShouldReusePlayer(Document& old_document,
                                         Document& new_document) const {
  // A NULL frame implies a NULL domWindow, so just check one of them
  if (!old_document.GetFrame() || !new_document.GetFrame()) {
    return false;
  }

  // Don't reuse player if the Document Picture-in-Picture API is disabled for
  // both documents.
  if (!RuntimeEnabledFeatures::DocumentPictureInPictureAPIEnabled(
          old_document.domWindow()->GetExecutionContext()) &&
      !RuntimeEnabledFeatures::DocumentPictureInPictureAPIEnabled(
          new_document.domWindow()->GetExecutionContext())) {
    return false;
  }

  auto* new_origin = new_document.GetFrame()
                         ->LocalFrameRoot()
                         .GetSecurityContext()
                         ->GetSecurityOrigin();
  auto* old_origin = old_document.GetFrame()
                         ->LocalFrameRoot()
                         .GetSecurityContext()
                         ->GetSecurityOrigin();

  if (!old_origin || !new_origin || !old_origin->IsSameOriginWith(new_origin)) {
    return false;
  }

  // If we're moving from the opener to pip window, then the player is already
  // connected to the opener and should stay connected to prevent jank.
  if (new_document.domWindow()->IsPictureInPictureWindow() &&
      new_document.GetFrame()->Opener() == old_document.GetFrame()) {
    return true;
  }

  // If we're moving from the pip window to the opener, then we should only
  // reuse the player if it's already associated with the opener.  In practice,
  // this means that `opener_document_` has been set, since
  // `LocalFrameForOpener()` uses that to decide which frame owns the player.
  //
  // Since we don't currently check if the original document is a pip window in
  // the ctor, that means that creating a video element in the pip window will
  // not be jankless when moved to the opener the first time.  Once it's in the
  // opener (either by being moved there or being created there), moves in both
  // directions will be jankless.
  //
  // It could be made jankless in both directions if we noticed (e.g., in the
  // ctor) that we're being created in a pip document, and set
  // `opener_document_` correctly and create the context observer for it.
  //
  // This logic works whether or not we make the ctor smarter about pip.
  // However, it can be simiplified to skip the `opener_document_` check if
  // we're guaranteed that it's always set properly.
  return (old_document.domWindow()->IsPictureInPictureWindow() &&
          old_document.GetFrame()->Opener() == new_document.GetFrame()) &&
         opener_document_ == &new_document;
}

void HTMLMediaElement::AttachToNewFrame() {
  // The opener has closed, so definitely nothing else should use this.
  opener_document_ = nullptr;
  // Do not ask it to stop notifying us -- if this is a callback from the
  // listener, then it's ExecutionContext has been destroyed and it's not
  // allowed to unregister.
  opener_context_observer_ = nullptr;
  // Reset mojo state that is coupled to |old_document|'s execution context.
  // NOTE: |media_player_host_remote_| is also coupled to |old_document|'s
  // frame.
  ResetMojoState();
  InvokeLoadAlgorithm();
}

void HTMLMediaElement::ResetMojoState() {
  if (media_player_host_remote_)
    media_player_host_remote_->Value().reset();
  media_player_host_remote_ = MakeGarbageCollected<DisallowNewWrapper<
      HeapMojoAssociatedRemote<media::mojom::blink::MediaPlayerHost>>>(
      GetExecutionContext());
  if (media_player_observer_remote_set_)
    media_player_observer_remote_set_->Value().Clear();
  media_player_observer_remote_set_ = MakeGarbageCollected<DisallowNewWrapper<
      HeapMojoAssociatedRemoteSet<media::mojom::blink::MediaPlayerObserver>>>(
      GetExecutionContext());
  if (media_player_receiver_set_)
    media_player_receiver_set_->Value().Clear();
  media_player_receiver_set_ =
      MakeGarbageCollected<DisallowNewWrapper<HeapMojoAssociatedReceiverSet<
          media::mojom::blink::MediaPlayer, HTMLMediaElement>>>(
          this, GetExecutionContext());
}

FocusableState HTMLMediaElement::SupportsFocus(
    UpdateBehavior update_behavior) const {
  // TODO(https://crbug.com/911882): Depending on result of discussion, remove.
  if (ownerDocument()->IsMediaDocument()) {
    return FocusableState::kNotFocusable;
  }

  // If no controls specified, we should still be able to focus the element if
  // it has tabIndex.
  if (ShouldShowControls()) {
    return FocusableState::kFocusable;
  }
  return HTMLElement::SupportsFocus(update_behavior);
}

FocusableState HTMLMediaElement::IsFocusableState(
    UpdateBehavior update_behavior) const {
  if (!IsFullscreen()) {
    return SupportsFocus(update_behavior);
  }
  return HTMLElement::IsFocusableState(update_behavior);
}

int HTMLMediaElement::DefaultTabIndex() const {
  return 0;
}

void HTMLMediaElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  if (name == html_names::kSrcAttr) {
    DVLOG(2) << "parseAttribute(" << *this
             << ", kSrcAttr, old=" << params.old_value
             << ", new=" << params.new_value << ")";
    // A change to the src attribute can affect intrinsic size, which in turn
    // requires a style recalc.
    SetNeedsStyleRecalc(kLocalStyleChange,
                        StyleChangeReasonForTracing::FromAttribute(name));
    // Trigger a reload, as long as the 'src' attribute is present.
    if (!params.new_value.IsNull()) {
      ignore_preload_none_ = false;
      InvokeLoadAlgorithm();
    }
  } else if (name == html_names::kControlsAttr) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kHTMLMediaElementControlsAttribute);
    UpdateControlsVisibility();
  } else if (name == html_names::kControlslistAttr) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kHTMLMediaElementControlsListAttribute);
    if (params.old_value != params.new_value) {
      controls_list_->DidUpdateAttributeValue(params.old_value,
                                              params.new_value);
      if (GetMediaControls())
        GetMediaControls()->OnControlsListUpdated();
    }
  } else if (name == html_names::kPreloadAttr) {
    SetPlayerPreload();
  } else if (name == html_names::kDisableremoteplaybackAttr) {
    // This attribute is an extension described in the Remote Playback API spec.
    // Please see: https://w3c.github.io/remote-playback
    UseCounter::Count(GetDocument(),
                      WebFeature::kDisableRemotePlaybackAttribute);
    if (params.old_value != params.new_value) {
      if (web_media_player_) {
        web_media_player_->RequestRemotePlaybackDisabled(
            !params.new_value.IsNull());
      }
    }
  } else if (name == html_names::kLatencyhintAttr &&
             RuntimeEnabledFeatures::MediaLatencyHintEnabled()) {
    if (web_media_player_)
      web_media_player_->SetLatencyHint(latencyHint());
  } else if (name == html_names::kMutedAttr) {
    if (params.reason == AttributeModificationReason::kByParser) {
      muted_ = true;
    }
  } else
"""


```