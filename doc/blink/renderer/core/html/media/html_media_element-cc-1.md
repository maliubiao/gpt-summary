Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `html_media_element.cc`. This code represents a portion of the logic for handling media elements in the Chromium Blink rendering engine. I need to identify the key actions and states managed by this part of the code, and highlight any interactions with JavaScript, HTML, and CSS. I should also look for logical deductions, potential user errors, and since this is part 2 of 6, ensure the summary reflects the specific functionality within this section.

**Key Functionality within this Snippet:**

1. **Attribute Parsing and Cloning:** Handling the parsing of HTML attributes, particularly the `muted` attribute during cloning.
2. **Child Element Processing:**  Processing child elements, specifically `<track>` elements, and scheduling their resource loading.
3. **Layout Object Management:** Determining if a layout object is needed (based on controls visibility) and creating the `LayoutMedia` object.
4. **Insertion and Removal from Document:** Handling insertion and removal of the media element from the DOM, including triggering the load algorithm when inserted and setting a timer when removed.
5. **Layout Tree Attachment and Style Recalculation:** Managing updates to the layout object upon attachment to the layout tree and during style recalculations.
6. **Resource Loading Scheduling:** Scheduling loading of text tracks and media resources using timers.
7. **Event Scheduling:** Scheduling both general and named events to be dispatched.
8. **Load Timer Handling:**  Executing actions based on the load timer firing, including loading text tracks and media resources.
9. **Setting and Getting Source:** Providing methods for setting the media source using either a URL (`src` attribute) or a `srcObject` (MediaStream or MediaSourceHandle).
10. **Source Object Management:** Handling different types of `srcObject`, including `MediaStreamDescriptor` and `MediaSourceHandle`.
11. **Network State Management:**  Getting the current network state of the media element.
12. **`canPlayType` Implementation:** Determining if a given MIME type is supported.
13. **`load()` Method:**  Manually triggering the media element load algorithm.
14. **`InvokeLoadAlgorithm()` Implementation:** The core logic for initiating and managing the media loading process, including handling existing play promises, aborting previous loads, resetting state, and triggering resource selection.
15. **`InvokeResourceSelectionAlgorithm()` Implementation:**  Setting the initial network state and flags before the actual resource selection.
16. **`LoadInternal()`:** Preparing for media resource selection by capturing the current active text tracks.
17. **`SelectMediaResource()` Implementation:** Determining the source of the media resource (from `srcObject`, `src` attribute, or `<source>` children) and initiating the appropriate loading process.
18. **Loading from Different Sources:** Implementing `LoadSourceFromObject`, `LoadSourceFromAttribute`, and `LoadNextSourceChild` to handle loading from different source types.
19. **`LoadResource()` Implementation:** The core logic for initiating the actual resource fetch, handling MediaSource attachments, checking URL safety, and conditionally deferring loading based on the `preload` attribute.
20. **Command Handling:** Implementing `HandleCommandInternal` for handling commands like play/pause and mute, considering user activation requirements.
21. **`StartPlayerLoad()` Implementation:** Creating the `WebMediaPlayer` object and setting up its initial parameters and communication channels.
22. **Preload Management:** Setting the `preload` on the `WebMediaPlayer`.
23. **Deferred Load Handling:** Methods for deferring and starting deferred loads.

**Relationships with JavaScript, HTML, and CSS:**

*   **JavaScript:**  Methods like `SetSrc`, `SetSrcObjectVariant`, `load`, `canPlayType` are directly exposed to JavaScript. Events like `loadstart`, `abort`, `emptied`, `timeupdate` are fired and can be listened to in JavaScript. The `play()` and `pause()` methods are called from JavaScript.
*   **HTML:**  The parsing of HTML attributes like `src` and `muted` is handled. The processing of `<source>` and `<track>` child elements is key. The presence of the `controls` attribute influences layout.
*   **CSS:** The `LayoutObjectIsNeeded` function considers the element's `DisplayStyle`, which is influenced by CSS. Style recalculations trigger updates to the layout object.

**Logical Reasoning (Assumptions and Outputs):**

*   **Assumption:**  If the `muted` attribute is present during cloning.
    *   **Input:** An element being cloned has the `muted` attribute.
    *   **Output:** The `muted_` internal state of the cloned `HTMLMediaElement` will be set to `true`.
*   **Assumption:** The media element is inserted into a connected document.
    *   **Input:** `insertion_point.isConnected()` is true.
    *   **Output:** The `WebFeature::kHTMLMediaElementInDocument` use counter is incremented. If a source is available and the network state is empty, the load algorithm is invoked.
*   **Assumption:** The `preload` attribute is set to `none`.
    *   **Input:** `EffectivePreloadType()` returns `WebMediaPlayer::kPreloadNone`.
    *   **Output:** The media resource loading might be deferred.

**Common User/Programming Errors:**

*   Setting an empty string to the `src` attribute. This will result in a `kNetworkStateFormatError`.
*   Attempting to play media without user activation. The `HandleCommandInternal` method explicitly checks for this and may log a warning to the console.
*   Providing an invalid or unsafe URL in the `src` attribute. This will be caught by `IsSafeToLoadURL` and result in a `kNetworkStateFormatError`.
*   Not handling the `abort` event, which is fired when a new load is initiated while a previous one is in progress.

**Summary of Functionality (Part 2):**

This section of `HTMLMediaElement` code focuses on the **lifecycle management and resource loading initiation** of HTML media elements. It handles attribute parsing, especially for the `muted` state during cloning. It manages the integration of text tracks and the creation/updating of the layout object based on the `controls` attribute and CSS styles. Crucially, it implements the core **media element load algorithm**, including handling different source types (`src` attribute, `srcObject`, and `<source>` children), managing network states, and scheduling the actual resource loading. It also addresses user interaction through command handling (like play/pause) and considers user activation requirements for playback. The code interacts heavily with the DOM lifecycle (insertion/removal) and prepares the media element for playback by creating and configuring the underlying `WebMediaPlayer`.

这是 `HTMLMediaElement` 类的部分代码，主要负责处理 HTML 媒体元素（例如 `<video>` 和 `<audio>`）的**属性解析、DOM 生命周期事件、资源加载的初始化和管理**。

以下是具体功能的归纳：

1. **属性处理和克隆:**
    *   在元素被解析时，调用 `ParseAttribute` 处理特定的 HTML 属性。
    *   在节点克隆时，通过 `CloneNonAttributePropertiesFrom` 方法，特别是处理 `muted` 属性，确保克隆后的元素拥有正确的静音状态。

    **与 HTML 的关系:**  直接处理 HTML 属性，例如 `muted` 属性。
    **举例说明:** 当 HTML 中存在 `<video muted>` 时，这段代码会确保在解析或克隆这个元素后，其内部的 `muted_` 状态被设置为 `true`。

2. **子元素处理:**
    *   在完成子元素的解析后 (`FinishParsingChildren`)，会检查是否存在 `<track>` 元素，如果存在则调度文本轨道资源的加载。

    **与 HTML 的关系:** 识别和处理 HTML 中的 `<track>` 元素。
    **举例说明:** 当 `<video>` 标签内包含 `<track src="subtitles.vtt" kind="subtitles" srclang="en">` 时，这段代码会启动 `subtitles.vtt` 文件的加载流程。

3. **布局对象管理:**
    *   `LayoutObjectIsNeeded` 方法根据是否显示控件（`ShouldShowControls()`）来决定是否需要创建布局对象。
    *   `CreateLayoutObject` 方法实际创建 `LayoutMedia` 布局对象。

    **与 CSS 的关系:**  `LayoutObjectIsNeeded` 的判断可能受到 CSS 的影响，因为 CSS 可以控制控件的显示。
    **举例说明:** 如果 CSS 设置了 `video::-webkit-media-controls { display: none; }`，那么 `ShouldShowControls()` 可能会返回 `false`，进而影响布局对象的创建。

4. **DOM 生命周期事件处理:**
    *   `InsertedInto` 方法在元素被插入到 DOM 中时被调用，会检查连接状态，并根据 `src` 属性或 `srcObject` 的存在以及当前网络状态，决定是否启动资源加载 (`InvokeLoadAlgorithm`)。
    *   `DidNotifySubtreeInsertionsToDocument` 方法在子树插入到文档后被调用，用于更新控件的可见性。
    *   `RemovedFrom` 方法在元素从 DOM 中移除时被调用，启动一个定时器。
    *   `AttachLayoutTree` 和 `DidRecalcStyle` 方法在布局树附加和样式重算时被调用，用于更新布局对象。

    **与 JavaScript 的关系:** 这些方法与 JavaScript 操作 DOM 结构密切相关。
    **举例说明:** 当 JavaScript 使用 `document.body.appendChild(videoElement)` 将一个 `<video>` 元素添加到页面时，`InsertedInto` 方法会被调用，并可能触发视频资源的加载。

5. **资源加载调度:**
    *   `ScheduleTextTrackResourceLoad` 和 `ScheduleNextSourceChild` 方法使用定时器来异步调度文本轨道和媒体资源的加载。

6. **事件调度:**
    *   `ScheduleNamedEvent` 和 `ScheduleEvent` 方法用于将事件添加到异步事件队列中，以便稍后触发。

    **与 JavaScript 的关系:** 这些方法调度的事件最终会被 JavaScript 代码捕获和处理。
    **举例说明:** `ScheduleNamedEvent(event_type_names::kLoadstart)` 会调度一个 `loadstart` 事件，JavaScript 可以监听这个事件来执行相应的操作。

7. **加载定时器处理:**
    *   `LoadTimerFired` 方法在加载定时器触发时被调用，根据 `pending_action_flags_` 的值来执行相应的加载操作，例如加载文本轨道或媒体资源。

8. **媒体源设置和获取:**
    *   `SetSrc` 方法用于设置 `src` 属性。
    *   `SetSrcObjectVariant` 方法用于设置 `srcObject`，可以是 `MediaStreamDescriptor` 或 `MediaSourceHandle`。
    *   `GetSrcObjectVariant` 方法用于获取当前的 `srcObject`。

    **与 HTML 和 JavaScript 的关系:**  `SetSrc` 对应 HTML 的 `src` 属性，可以通过 JavaScript 设置。`SetSrcObjectVariant` 对应 JavaScript 中设置 `video.srcObject`。
    **举例说明:**  `videoElement.src = "myvideo.mp4"` 会调用 `SetSrc` 方法。 `videoElement.srcObject = mediaStream` 会调用 `SetSrcObjectVariant` 方法。

9. **网络状态管理:**
    *   `getNetworkState` 方法返回当前的媒体元素网络状态。

    **与 JavaScript 的关系:**  JavaScript 可以调用 `videoElement.networkState` 来获取当前的网络状态。

10. **`canPlayType` 实现:**
    *   `canPlayType` 方法判断指定的 MIME 类型是否支持播放。

    **与 JavaScript 的关系:**  JavaScript 可以调用 `videoElement.canPlayType("video/mp4")` 来检查是否支持播放 MP4 视频。

11. **`load()` 方法:**
    *   `load` 方法手动触发媒体元素的加载算法。

    **与 JavaScript 的关系:**  JavaScript 可以调用 `videoElement.load()` 来强制重新加载媒体资源。

12. **`InvokeLoadAlgorithm()`:**
    *   这是核心的媒体元素加载算法的实现，负责停止之前的加载，清除状态，处理未完成的 Promise，并启动资源选择算法。

13. **`InvokeResourceSelectionAlgorithm()`:**
    *   负责设置初始的网络状态和标志，为后续的资源选择做准备。

14. **`LoadInternal()`:**
    *   在实际选择媒体资源之前，记录当前启用的文本轨道。

15. **`SelectMediaResource()`:**
    *   根据是否存在 `srcObject`，`src` 属性或 `<source>` 子元素来决定如何加载媒体资源。

16. **不同来源的加载方法:**
    *   `LoadSourceFromObject` 处理从 `srcObject` 加载资源的情况。
    *   `LoadSourceFromAttribute` 处理从 `src` 属性加载资源的情况。
    *   `LoadNextSourceChild` 处理从 `<source>` 子元素加载资源的情况。

17. **`LoadResource()`:**
    *   执行实际的资源加载过程，包括检查 URL 安全性，处理 MediaSource 附件，并根据 `preload` 属性决定是否延迟加载。

18. **命令处理:**
    *   `HandleCommandInternal` 方法处理来自 HTML 元素的命令，例如播放/暂停和静音切换。

    **与 HTML 和 JavaScript 的关系:** 与 HTML 的 `invokeaction` 属性以及 JavaScript 的 `HTMLElement.prototype.click()` 等方法触发的命令相关。
    **举例说明:**  一个按钮可能绑定了 `invokeaction="play-pause"`，当点击这个按钮时，`HandleCommandInternal` 会处理播放或暂停的操作。

19. **`StartPlayerLoad()`:**
    *   创建底层的 `WebMediaPlayer` 对象，并设置相关的参数。

20. **预加载管理:**
    *   `SetPlayerPreload` 方法设置 `WebMediaPlayer` 的预加载策略。
    *   `DeferLoad` 方法延迟媒体资源的加载。

**假设输入与输出 (逻辑推理):**

*   **假设输入:**  一个 `<video>` 元素被插入到 DOM 中，并且设置了 `src="myvideo.mp4"`。
    *   **输出:** `InsertedInto` 方法会被调用，因为 `src` 属性存在且网络状态为 `kNetworkEmpty`，`InvokeLoadAlgorithm` 会被调用，最终开始加载 `myvideo.mp4`。
*   **假设输入:**  一个 `<video>` 元素拥有多个 `<source>` 子元素，但没有 `src` 属性。
    *   **输出:** `SelectMediaResource` 方法会被调用，并进入 `kChildren` 模式，`LoadNextSourceChild` 会被调用，尝试加载第一个 `<source>` 元素的资源。

**用户或编程常见的使用错误:**

*   在没有用户手势的情况下尝试播放媒体。这段代码中的 `HandleCommandInternal` 方法会检查用户激活状态，并可能阻止播放。
*   设置空的 `src` 属性。会导致 `MediaLoadingFailed` 被调用，网络状态设置为 `kNetworkStateFormatError`。
*   未能正确处理媒体加载相关的事件（如 `error` 事件）。

总而言之，这部分代码是 `HTMLMediaElement` 实现的核心，负责媒体元素的生命周期管理和资源加载的启动和初步管理，为后续的媒体解码、渲染和播放奠定基础。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_media_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
{
    HTMLElement::ParseAttribute(params);
  }
}

// This method is being used as a way to know that cloneNode finished cloning
// attribute as there is no callback notifying about the end of a cloning
// operation. Indeed, it is required per spec to set the muted state based on
// the content attribute when the object is created.
void HTMLMediaElement::CloneNonAttributePropertiesFrom(const Element& other,
                                                       NodeCloningData& data) {
  HTMLElement::CloneNonAttributePropertiesFrom(other, data);

  if (FastHasAttribute(html_names::kMutedAttr))
    muted_ = true;
}

void HTMLMediaElement::FinishParsingChildren() {
  HTMLElement::FinishParsingChildren();

  if (Traversal<HTMLTrackElement>::FirstChild(*this))
    ScheduleTextTrackResourceLoad();
}

bool HTMLMediaElement::LayoutObjectIsNeeded(const DisplayStyle& style) const {
  return ShouldShowControls() && HTMLElement::LayoutObjectIsNeeded(style);
}

LayoutObject* HTMLMediaElement::CreateLayoutObject(const ComputedStyle&) {
  return MakeGarbageCollected<LayoutMedia>(this);
}

Node::InsertionNotificationRequest HTMLMediaElement::InsertedInto(
    ContainerNode& insertion_point) {
  DVLOG(3) << "insertedInto(" << *this << ", " << insertion_point << ")";

  HTMLElement::InsertedInto(insertion_point);
  if (insertion_point.isConnected()) {
    UseCounter::Count(GetDocument(), WebFeature::kHTMLMediaElementInDocument);
    if ((!FastGetAttribute(html_names::kSrcAttr).empty() ||
         src_object_stream_descriptor_ || src_object_media_source_handle_) &&
        network_state_ == kNetworkEmpty) {
      ignore_preload_none_ = false;
      InvokeLoadAlgorithm();
    }
  }

  return kInsertionShouldCallDidNotifySubtreeInsertions;
}

void HTMLMediaElement::DidNotifySubtreeInsertionsToDocument() {
  UpdateControlsVisibility();
}

void HTMLMediaElement::RemovedFrom(ContainerNode& insertion_point) {
  DVLOG(3) << "removedFrom(" << *this << ", " << insertion_point << ")";

  removed_from_document_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  HTMLElement::RemovedFrom(insertion_point);
}

void HTMLMediaElement::AttachLayoutTree(AttachContext& context) {
  HTMLElement::AttachLayoutTree(context);

  UpdateLayoutObject();
}

void HTMLMediaElement::DidRecalcStyle(const StyleRecalcChange change) {
  if (!change.ReattachLayoutTree())
    UpdateLayoutObject();
}

void HTMLMediaElement::ScheduleTextTrackResourceLoad() {
  DVLOG(3) << "scheduleTextTrackResourceLoad(" << *this << ")";

  pending_action_flags_ |= kLoadTextTrackResource;

  if (!load_timer_.IsActive())
    load_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void HTMLMediaElement::ScheduleNextSourceChild() {
  // Schedule the timer to try the next <source> element WITHOUT resetting state
  // ala invokeLoadAlgorithm.
  pending_action_flags_ |= kLoadMediaResource;
  load_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void HTMLMediaElement::ScheduleNamedEvent(const AtomicString& event_name) {
  Event* event = Event::CreateCancelable(event_name);
  event->SetTarget(this);
  ScheduleEvent(event);
}

void HTMLMediaElement::ScheduleEvent(Event* event) {
#if LOG_MEDIA_EVENTS
  DVLOG(3) << "ScheduleEvent(" << (void*)this << ")"
           << " - scheduling '" << event->type() << "'";
#endif
  async_event_queue_->EnqueueEvent(FROM_HERE, *event);
}

void HTMLMediaElement::LoadTimerFired(TimerBase*) {
  if (pending_action_flags_ & kLoadTextTrackResource)
    HonorUserPreferencesForAutomaticTextTrackSelection();

  if (pending_action_flags_ & kLoadMediaResource) {
    if (load_state_ == kLoadingFromSourceElement)
      LoadNextSourceChild();
    else
      LoadInternal();
  }

  pending_action_flags_ = 0;
}

MediaError* HTMLMediaElement::error() const {
  return error_.Get();
}

void HTMLMediaElement::SetSrc(const AtomicString& url) {
  setAttribute(html_names::kSrcAttr, url);
}

void HTMLMediaElement::SetSrcObjectVariant(
    SrcObjectVariant src_object_variant) {
  DVLOG(1) << __func__ << "(" << *this << ")";
  src_object_stream_descriptor_ = nullptr;
  src_object_media_source_handle_ = nullptr;
  if (auto** desc = absl::get_if<MediaStreamDescriptor*>(&src_object_variant)) {
    src_object_stream_descriptor_ = *desc;
  } else if (auto** handle =
                 absl::get_if<MediaSourceHandle*>(&src_object_variant)) {
    src_object_media_source_handle_ = *handle;
  }

  DVLOG(2) << __func__
           << ": stream_descriptor=" << src_object_stream_descriptor_
           << ", media_source_handle=" << src_object_media_source_handle_;

  InvokeLoadAlgorithm();
}

HTMLMediaElement::SrcObjectVariant HTMLMediaElement::GetSrcObjectVariant()
    const {
  DVLOG(1) << __func__ << "(" << *this << ")"
           << ": stream_descriptor=" << src_object_stream_descriptor_
           << ", media_source_handle=" << src_object_media_source_handle_;

  // At most one is set.
  DCHECK(!(src_object_stream_descriptor_ && src_object_media_source_handle_));

  if (src_object_media_source_handle_)
    return SrcObjectVariant(src_object_media_source_handle_.Get());

  return SrcObjectVariant(src_object_stream_descriptor_.Get());
}

HTMLMediaElement::NetworkState HTMLMediaElement::getNetworkState() const {
  return network_state_;
}

V8CanPlayTypeResult HTMLMediaElement::canPlayType(
    const String& mime_type) const {
  MIMETypeRegistry::SupportsType support =
      GetSupportsType(ContentType(mime_type));

  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kHTMLMediaElement_CanPlayType)) {
    blink::IdentifiabilityMetricBuilder(GetDocument().UkmSourceID())
        .Add(
            blink::IdentifiableSurface::FromTypeAndToken(
                blink::IdentifiableSurface::Type::kHTMLMediaElement_CanPlayType,
                IdentifiabilityBenignStringToken(mime_type)),
            static_cast<uint64_t>(support))
        .Record(GetDocument().UkmRecorder());
  }
  V8CanPlayTypeResult can_play =
      V8CanPlayTypeResult(V8CanPlayTypeResult::Enum::k);

  // 4.8.12.3
  switch (support) {
    case MIMETypeRegistry::kNotSupported:
      break;
    case MIMETypeRegistry::kMaybeSupported:
      can_play = V8CanPlayTypeResult(V8CanPlayTypeResult::Enum::kMaybe);
      break;
    case MIMETypeRegistry::kSupported:
      can_play = V8CanPlayTypeResult(V8CanPlayTypeResult::Enum::kProbably);
      break;
  }

  DVLOG(2) << "canPlayType(" << *this << ", " << mime_type << ") -> "
           << can_play.AsCStr();

  return can_play;
}

void HTMLMediaElement::load() {
  DVLOG(1) << "load(" << *this << ")";

  autoplay_policy_->TryUnlockingUserGesture();

  ignore_preload_none_ = true;
  InvokeLoadAlgorithm();
}

// Implements the "media element load algorithm" as defined by
// https://html.spec.whatwg.org/multipage/media.html#media-element-load-algorithm
// TODO(srirama.m): Currently ignore_preload_none_ is reset before calling
// invokeLoadAlgorithm() in all places except load(). Move it inside here
// once microtask is implemented for "Await a stable state" step
// in resource selection algorithm.
void HTMLMediaElement::InvokeLoadAlgorithm() {
  DVLOG(3) << "invokeLoadAlgorithm(" << *this << ")";

  // Perform the cleanup required for the resource load algorithm to run.
  StopPeriodicTimers();
  load_timer_.Stop();
  CancelDeferredLoad();
  // FIXME: Figure out appropriate place to reset LoadTextTrackResource if
  // necessary and set pending_action_flags_ to 0 here.
  pending_action_flags_ &= ~kLoadMediaResource;
  sent_stalled_event_ = false;
  have_fired_loaded_data_ = false;

  autoplay_policy_->StopAutoplayMutedWhenVisible();

  // 1 - Abort any already-running instance of the resource selection algorithm
  // for this element.
  load_state_ = kWaitingForSource;
  current_source_node_ = nullptr;

  // 2 - Let pending tasks be a list of tasks from the media element's media
  // element task source in one of the task queues.
  //
  // 3 - For each task in the pending tasks that would run resolve pending
  // play promises or project pending play prmoises algorithms, immediately
  // resolve or reject those promises in the order the corresponding tasks
  // were queued.
  //
  // TODO(mlamouri): the promises are first resolved then rejected but the
  // order between resolved/rejected promises isn't respected. This could be
  // improved when the same task is used for both cases.
  //
  // TODO(mlamouri): don't run the callback synchronously if we are not allowed
  // to run scripts. It can happen in some edge cases. https://crbug.com/660382
  if (play_promise_resolve_task_handle_.IsActive() &&
      !ScriptForbiddenScope::IsScriptForbidden()) {
    play_promise_resolve_task_handle_.Cancel();
    ResolveScheduledPlayPromises();
  }
  if (play_promise_reject_task_handle_.IsActive() &&
      !ScriptForbiddenScope::IsScriptForbidden()) {
    play_promise_reject_task_handle_.Cancel();
    RejectScheduledPlayPromises();
  }

  // 4 - Remove each task in pending tasks from its task queue.
  CancelPendingEventsAndCallbacks();

  // 5 - If the media element's networkState is set to NETWORK_LOADING or
  // NETWORK_IDLE, queue a task to fire a simple event named abort at the media
  // element.
  if (network_state_ == kNetworkLoading || network_state_ == kNetworkIdle)
    ScheduleNamedEvent(event_type_names::kAbort);

  ResetMediaPlayerAndMediaSource();

  // 6 - If the media element's networkState is not set to NETWORK_EMPTY, then
  // run these substeps
  if (network_state_ != kNetworkEmpty) {
    // 4.1 - Queue a task to fire a simple event named emptied at the media
    // element.
    ScheduleNamedEvent(event_type_names::kEmptied);

    // 4.2 - If a fetching process is in progress for the media element, the
    // user agent should stop it.
    SetNetworkState(kNetworkEmpty);

    // 4.4 - Forget the media element's media-resource-specific tracks.
    ForgetResourceSpecificTracks();

    // 4.5 - If readyState is not set to kHaveNothing, then set it to that
    // state.
    ready_state_ = kHaveNothing;
    ready_state_maximum_ = kHaveNothing;

    DCHECK(!paused_ || play_promise_resolvers_.empty());

    // 4.6 - If the paused attribute is false, then run these substeps
    if (!paused_) {
      // 4.6.1 - Set the paused attribute to true.
      paused_ = true;

      // 4.6.2 - Take pending play promises and reject pending play promises
      // with the result and an "AbortError" DOMException.
      RejectPlayPromises(DOMExceptionCode::kAbortError,
                         "The play() request was interrupted by a new load "
                         "request. https://goo.gl/LdLk22");
    }

    // 4.7 - If seeking is true, set it to false.
    seeking_ = false;

    // 4.8 - Set the current playback position to 0.
    //       Set the official playback position to 0.
    //       If this changed the official playback position, then queue a task
    //       to fire a simple event named timeupdate at the media element.
    // 4.9 - Set the initial playback position to 0.
    SetOfficialPlaybackPosition(0);
    ScheduleTimeupdateEvent(false);
    GetCueTimeline().OnReadyStateReset();

    // 4.10 - Set the timeline offset to Not-a-Number (NaN).
    // 4.11 - Update the duration attribute to Not-a-Number (NaN).
  } else if (!paused_) {
    // TODO(foolip): There is a proposal to always reset the paused state
    // in the media element load algorithm, to avoid a bogus play() promise
    // rejection: https://github.com/whatwg/html/issues/869
    // This is where that change would have an effect, and it is measured to
    // verify the assumption that it's a very rare situation.
    UseCounter::Count(GetDocument(),
                      WebFeature::kHTMLMediaElementLoadNetworkEmptyNotPaused);
  }

  // 7 - Set the playbackRate attribute to the value of the defaultPlaybackRate
  // attribute.
  setPlaybackRate(defaultPlaybackRate());

  // 8 - Set the error attribute to null and the can autoplay flag to true.
  SetError(nullptr);
  can_autoplay_ = true;

  // 9 - Invoke the media element's resource selection algorithm.
  InvokeResourceSelectionAlgorithm();

  // 10 - Note: Playback of any previously playing media resource for this
  // element stops.
}

void HTMLMediaElement::InvokeResourceSelectionAlgorithm() {
  DVLOG(3) << "invokeResourceSelectionAlgorithm(" << *this << ")";
  // The resource selection algorithm
  // 1 - Set the networkState to NETWORK_NO_SOURCE
  SetNetworkState(kNetworkNoSource);

  // 2 - Set the element's show poster flag to true
  SetShowPosterFlag(true);

  played_time_ranges_ = MakeGarbageCollected<TimeRanges>();

  // FIXME: Investigate whether these can be moved into network_state_ !=
  // kNetworkEmpty block above
  // so they are closer to the relevant spec steps.
  last_seek_time_ = 0;
  duration_ = std::numeric_limits<double>::quiet_NaN();

  // 3 - Set the media element's delaying-the-load-event flag to true (this
  // delays the load event)
  SetShouldDelayLoadEvent(true);
  if (GetMediaControls() && isConnected())
    GetMediaControls()->Reset();

  // 4 - Await a stable state, allowing the task that invoked this algorithm to
  // continue
  // TODO(srirama.m): Remove scheduleNextSourceChild() and post a microtask
  // instead.  See http://crbug.com/593289 for more details.
  ScheduleNextSourceChild();
}

void HTMLMediaElement::LoadInternal() {
  // HTMLMediaElement::textTracksAreReady will need "... the text tracks whose
  // mode was not in the disabled state when the element's resource selection
  // algorithm last started".
  text_tracks_when_resource_selection_began_.clear();
  if (text_tracks_) {
    for (unsigned i = 0; i < text_tracks_->length(); ++i) {
      TextTrack* track = text_tracks_->AnonymousIndexedGetter(i);
      if (track->mode() != TextTrackMode::kDisabled)
        text_tracks_when_resource_selection_began_.push_back(track);
    }
  }

  SelectMediaResource();
}

void HTMLMediaElement::SelectMediaResource() {
  DVLOG(3) << "selectMediaResource(" << *this << ")";

  enum Mode { kObject, kAttribute, kChildren, kNothing };
  Mode mode = kNothing;

  // 6 - If the media element has an assigned media provider object, then let
  //     mode be object.
  if (src_object_stream_descriptor_ || src_object_media_source_handle_) {
    mode = kObject;
  } else if (FastHasAttribute(html_names::kSrcAttr)) {
    // Otherwise, if the media element has no assigned media provider object
    // but has a src attribute, then let mode be attribute.
    mode = kAttribute;
  } else if (HTMLSourceElement* element =
                 Traversal<HTMLSourceElement>::FirstChild(*this)) {
    // Otherwise, if the media element does not have an assigned media
    // provider object and does not have a src attribute, but does have a
    // source element child, then let mode be children and let candidate be
    // the first such source element child in tree order.
    mode = kChildren;
    next_child_node_to_consider_ = element;
    current_source_node_ = nullptr;
  } else {
    // Otherwise the media element has no assigned media provider object and
    // has neither a src attribute nor a source element child: set the
    // networkState to kNetworkEmpty, and abort these steps; the synchronous
    // section ends.
    // TODO(mlamouri): Setting the network state to empty implies that there
    // should be no |web_media_player_|. However, if a previous playback ended
    // due to an error, we can get here and still have one. Decide on a plan
    // to deal with this properly. https://crbug.com/789737
    load_state_ = kWaitingForSource;
    SetShouldDelayLoadEvent(false);
    if (!web_media_player_ || (ready_state_ < kHaveFutureData &&
                               ready_state_maximum_ < kHaveFutureData)) {
      SetNetworkState(kNetworkEmpty);
    } else {
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLMediaElementEmptyLoadWithFutureData);
    }
    UpdateLayoutObject();

    DVLOG(3) << "selectMediaResource(" << *this << "), nothing to load";
    return;
  }

  // 7 - Set the media element's networkState to NETWORK_LOADING.
  SetNetworkState(kNetworkLoading);

  // 8 - Queue a task to fire a simple event named loadstart at the media
  // element.
  ScheduleNamedEvent(event_type_names::kLoadstart);

  // 9 - Run the appropriate steps...
  switch (mode) {
    case kObject:
      LoadSourceFromObject();
      DVLOG(3) << "selectMediaResource(" << *this
               << ", using 'srcObject' attribute";
      break;
    case kAttribute:
      LoadSourceFromAttribute();
      DVLOG(3) << "selectMediaResource(" << *this
               << "), using 'src' attribute url";
      break;
    case kChildren:
      LoadNextSourceChild();
      DVLOG(3) << "selectMediaResource(" << *this << "), using source element";
      break;
    default:
      NOTREACHED();
  }
}

void HTMLMediaElement::LoadSourceFromObject() {
  DCHECK(src_object_stream_descriptor_ || src_object_media_source_handle_);
  load_state_ = kLoadingFromSrcObject;

  if (src_object_media_source_handle_) {
    DCHECK(!src_object_stream_descriptor_);

    // Retrieve the internal blob URL from the handle that was created in the
    // context where the referenced MediaSource is owned, for the purposes of
    // using existing security and logging logic for loading media from a
    // MediaSource with a blob URL.
    const String media_source_handle_url_ =
        src_object_media_source_handle_->GetInternalBlobURL();
    DCHECK(!media_source_handle_url_.empty());

    KURL media_url = GetDocument().CompleteURL(media_source_handle_url_);
    if (!IsSafeToLoadURL(media_url, kComplain)) {
      MediaLoadingFailed(
          WebMediaPlayer::kNetworkStateFormatError,
          BuildElementErrorMessage(
              "Media load from MediaSourceHandle rejected by safety check"));
      return;
    }

    // No type is available when loading from a MediaSourceHandle, via
    // srcObject, even with an internal MediaSource blob URL.
    LoadResource(WebMediaPlayerSource(WebURL(media_url)), String());
    return;
  }

  // No type is available when the resource comes from the 'srcObject'
  // attribute.
  LoadResource(
      WebMediaPlayerSource(WebMediaStream(src_object_stream_descriptor_)),
      String());
}

void HTMLMediaElement::LoadSourceFromAttribute() {
  load_state_ = kLoadingFromSrcAttr;
  const AtomicString& src_value = FastGetAttribute(html_names::kSrcAttr);

  // If the src attribute's value is the empty string ... jump down to the
  // failed step below
  if (src_value.empty()) {
    DVLOG(3) << "LoadSourceFromAttribute(" << *this << "), empty 'src'";
    MediaLoadingFailed(WebMediaPlayer::kNetworkStateFormatError,
                       BuildElementErrorMessage("Empty src attribute"));
    return;
  }

  KURL media_url = GetDocument().CompleteURL(src_value);
  if (!IsSafeToLoadURL(media_url, kComplain)) {
    MediaLoadingFailed(
        WebMediaPlayer::kNetworkStateFormatError,
        BuildElementErrorMessage("Media load rejected by URL safety check"));
    return;
  }

  // No type is available when the url comes from the 'src' attribute so
  // MediaPlayer will have to pick a media engine based on the file extension.
  LoadResource(WebMediaPlayerSource(WebURL(media_url)), String());
}

void HTMLMediaElement::LoadNextSourceChild() {
  String content_type;
  KURL media_url = SelectNextSourceChild(&content_type, kComplain);
  if (!media_url.IsValid()) {
    WaitForSourceChange();
    return;
  }

  // Reset the MediaPlayer and MediaSource if any
  ResetMediaPlayerAndMediaSource();

  load_state_ = kLoadingFromSourceElement;
  LoadResource(WebMediaPlayerSource(WebURL(media_url)), content_type);
}

void HTMLMediaElement::LoadResource(const WebMediaPlayerSource& source,
                                    const String& content_type) {
  DCHECK(IsMainThread());
  KURL url;
  if (source.IsURL()) {
    url = source.GetAsURL();
    DCHECK(IsSafeToLoadURL(url, kComplain));
    DVLOG(3) << "loadResource(" << *this << ", " << UrlForLoggingMedia(url)
             << ", " << content_type << ")";
  }

  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame) {
    MediaLoadingFailed(WebMediaPlayer::kNetworkStateFormatError,
                       BuildElementErrorMessage(
                           "Resource load failure: document has no frame"));
    return;
  }

  // The resource fetch algorithm
  SetNetworkState(kNetworkLoading);

  // Set |current_src_| *before* changing to the cache url, the fact that we are
  // loading from the app cache is an internal detail not exposed through the
  // media element API. If loading from an internal MediaSourceHandle object
  // URL, then do not expose that URL to app, but instead hold it for use later
  // in StartPlayerLoad and elsewhere (for origin, security etc checks normally
  // done on |current_src_|.)
  if (src_object_media_source_handle_) {
    DCHECK(!url.IsEmpty());
    current_src_.SetSource(url,
                           SourceMetadata::SourceVisibility::kInvisibleToApp);
  } else {
    current_src_.SetSource(url,
                           SourceMetadata::SourceVisibility::kVisibleToApp);
  }

  // Default this to empty, so that we use |current_src_| unless the player
  // provides one later.
  current_src_after_redirects_ = KURL();

  if (audio_source_node_)
    audio_source_node_->OnCurrentSrcChanged(current_src_.GetSourceIfVisible());

  // Update remote playback client with the new src and consider it incompatible
  // until proved otherwise.
  RemotePlaybackCompatibilityChanged(current_src_.GetSourceIfVisible(), false);

  DVLOG(3) << "loadResource(" << *this << ") - current src if visible="
           << UrlForLoggingMedia(current_src_.GetSourceIfVisible())
           << ", current src =" << UrlForLoggingMedia(current_src_.GetSource())
           << ", src_object_media_source_handle_="
           << src_object_media_source_handle_
           << ", src_object_stream_descriptor_="
           << src_object_stream_descriptor_;

  StartProgressEventTimer();

  SetPlayerPreload();

  DCHECK(!media_source_attachment_);
  DCHECK(!media_source_tracer_);
  DCHECK(!error_);

  bool attempt_load = true;

  if (src_object_media_source_handle_) {
    media_source_attachment_ =
        src_object_media_source_handle_->TakeAttachment();

    // If the attachment is nullptr, then fail the load.
    if (!media_source_attachment_) {
      attempt_load = false;
    }
  } else {
    media_source_attachment_ =
        MediaSourceAttachment::LookupMediaSource(url.GetString());
  }
  if (media_source_attachment_) {
    bool start_result = false;
    media_source_tracer_ =
        media_source_attachment_->StartAttachingToMediaElement(this,
                                                               &start_result);
    if (start_result) {
      // If the associated feature is enabled, auto-revoke the MediaSource
      // object URL that was used for attachment on successful (start of)
      // attachment. This can help reduce memory bloat later if the app does not
      // revoke the object URL explicitly and the object URL was the only
      // remaining strong reference to an attached HTMLMediaElement+MediaSource
      // cycle of objects that could otherwise be garbage-collectable. Don't
      // auto-revoke the internal, unregistered, object URL used to attach via
      // srcObject with a MediaSourceHandle, though.
      if (base::FeatureList::IsEnabled(
              media::kRevokeMediaSourceObjectURLOnAttach) &&
          !src_object_media_source_handle_) {
        URLFileAPI::revokeObjectURL(GetExecutionContext(), url.GetString());
      }
    } else {
      // Forget our reference to the MediaSourceAttachment, so we leave it alone
      // while processing remainder of load failure.
      media_source_attachment_.reset();
      media_source_tracer_ = nullptr;
      attempt_load = false;
    }
  }

  bool can_load_resource =
      source.IsMediaStream() || CanLoadURL(url, content_type);
  if (attempt_load && can_load_resource) {
    DCHECK(!web_media_player_);

    // Conditionally defer the load if effective preload is 'none'.
    // Skip this optional deferral for MediaStream sources or any blob URL,
    // including MediaSource blob URLs.
    if (!source.IsMediaStream() && !url.ProtocolIs("blob") &&
        EffectivePreloadType() == WebMediaPlayer::kPreloadNone) {
      DVLOG(3) << "loadResource(" << *this
               << ") : Delaying load because preload == 'none'";
      DeferLoad();
    } else {
      StartPlayerLoad();
    }
  } else {
    MediaLoadingFailed(
        WebMediaPlayer::kNetworkStateFormatError,
        BuildElementErrorMessage(attempt_load
                                     ? "Unable to load URL due to content type"
                                     : "Unable to attach MediaSource"));
  }
}

LocalFrame* HTMLMediaElement::LocalFrameForPlayer() {
  return opener_document_ ? opener_document_->GetFrame()
                          : GetDocument().GetFrame();
}

bool HTMLMediaElement::IsValidBuiltinCommand(HTMLElement& invoker,
                                             CommandEventType command) {
  if (!RuntimeEnabledFeatures::HTMLInvokeActionsV2Enabled()) {
    return HTMLElement::IsValidBuiltinCommand(invoker, command);
  }

  return HTMLElement::IsValidBuiltinCommand(invoker, command) ||
         command == CommandEventType::kPlayPause ||
         command == CommandEventType::kPause ||
         command == CommandEventType::kPlay ||
         command == CommandEventType::kToggleMuted;
}

bool HTMLMediaElement::HandleCommandInternal(HTMLElement& invoker,
                                             CommandEventType command) {
  CHECK(IsValidBuiltinCommand(invoker, command));

  if (HTMLElement::HandleCommandInternal(invoker, command)) {
    return true;
  }

  Document& document = GetDocument();
  LocalFrame* frame = document.GetFrame();

  if (command == CommandEventType::kPlayPause) {
    if (paused_) {
      if (LocalFrame::HasTransientUserActivation(frame)) {
        Play();
        return true;
      } else {
        String message = "Media cannot be played without a user gesture.";
        document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kWarning, message));
        return false;
      }
    } else {
      pause();
      return true;
    }
  } else if (command == CommandEventType::kPause) {
    if (!paused_) {
      pause();
    }
    return true;
  } else if (command == CommandEventType::kPlay) {
    if (paused_) {
      if (LocalFrame::HasTransientUserActivation(frame)) {
        Play();
      } else {
        String message = "Media cannot be played without a user gesture.";
        document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kWarning, message));
        return false;
      }
    }
    return true;
  } else if (command == CommandEventType::kToggleMuted) {
    // No user activation check as `setMuted` already handles the autoplay
    // policy check.
    setMuted(!muted_);
    return true;
  }

  return false;
}

void HTMLMediaElement::StartPlayerLoad() {
  DCHECK(!web_media_player_);

  // OOM interventions may destroy the JavaScript context while still allowing
  // the page to operate without JavaScript. The media element is too
  // complicated to continue running in this state, so fail.
  // See https://crbug.com/1345473 for more information.
  if (!GetExecutionContext() ||
      GetDocument().domWindow()->IsContextDestroyed()) {
    MediaLoadingFailed(
        WebMediaPlayer::kNetworkStateFormatError,
        BuildElementErrorMessage(
            "Player load failure: JavaScript context destroyed"));
    return;
  }

  // Due to Document PiP we may have a different execution context than our
  // opener, so we also must check that the LocalFrame of the opener is valid.
  LocalFrame* frame = LocalFrameForPlayer();
  if (!frame) {
    MediaLoadingFailed(
        WebMediaPlayer::kNetworkStateFormatError,
        BuildElementErrorMessage("Player load failure: document has no frame"));
    return;
  }

  WebMediaPlayerSource source;
  if (src_object_stream_descriptor_) {
    source =
        WebMediaPlayerSource(WebMediaStream(src_object_stream_descriptor_));
  } else if (src_object_media_source_handle_) {
    DCHECK(current_src_.GetSourceIfVisible().IsEmpty());
    const KURL& internal_url = current_src_.GetSource();
    DCHECK(!internal_url.IsEmpty());

    source = WebMediaPlayerSource(WebURL(internal_url));
  } else {
    // Filter out user:pass as those two URL components aren't
    // considered for media resource fetches (including for the CORS
    // use-credentials mode.) That behavior aligns with Gecko, with IE
    // being more restrictive and not allowing fetches to such URLs.
    //
    // Spec reference: http://whatwg.org/c/#concept-media-load-resource
    //
    // FIXME: when the HTML spec switches to specifying resource
    // fetches in terms of Fetch (http://fetch.spec.whatwg.org), and
    // along with that potentially also specifying a setting for its
    // 'authentication flag' to control how user:pass embedded in a
    // media resource URL should be treated, then update the handling
    // here to match.
    KURL request_url = current_src_.GetSourceIfVisible();
    if (!request_url.User().empty())
      request_url.SetUser(String());
    if (!request_url.Pass().empty())
      request_url.SetPass(String());

    KURL kurl(request_url);
    source = WebMediaPlayerSource(WebURL(kurl));
  }

  web_media_player_ =
      frame->Client()->CreateWebMediaPlayer(*this, source, this);

  if (!web_media_player_) {
    MediaLoadingFailed(WebMediaPlayer::kNetworkStateFormatError,
                       BuildElementErrorMessage(
                           "Player load failure: error creating media player"));
    return;
  }

  OnWebMediaPlayerCreated();

  // Setup the communication channels between the renderer and browser processes
  // via the MediaPlayer and MediaPlayerObserver mojo interfaces.
  DCHECK(media_player_receiver_set_->Value().empty());
  mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>
      media_player_remote;
  BindMediaPlayerReceiver(
      media_player_remote.InitWithNewEndpointAndPassReceiver());

  GetMediaPlayerHostRemote().OnMediaPlayerAdded(
      std::move(media_player_remote), AddMediaPlayerObserverAndPassReceiver(),
      web_media_player_->GetDelegateId());

  if (GetLayoutObject())
    GetLayoutObject()->SetShouldDoFullPaintInvalidation();
  // Make sure if we create/re-create the WebMediaPlayer that we update our
  // wrapper.
  audio_source_provider_.Wrap(web_media_player_->GetAudioSourceProvider());
  web_media_player_->SetVolume(EffectiveMediaVolume());

  web_media_player_->SetPoster(PosterImageURL());

  const auto preload = EffectivePreloadType();
  web_media_player_->SetPreload(preload);

  web_media_player_->RequestRemotePlaybackDisabled(
      FastHasAttribute(html_names::kDisableremoteplaybackAttr));

  if (RuntimeEnabledFeatures::
          MediaPlaybackWhileNotVisiblePermissionPolicyEnabled()) {
    web_media_player_->SetShouldPauseWhenFrameIsHidden(
        !GetDocument().GetExecutionContext()->IsFeatureEnabled(
            mojom::blink::PermissionsPolicyFeature::
                kMediaPlaybackWhileNotVisible,
            ReportOptions::kDoNotReport));
  }

  bool is_cache_disabled = false;
  probe::IsCacheDisabled(GetDocument().GetExecutionContext(),
                         &is_cache_disabled);
  auto load_timing = web_media_player_->Load(GetLoadType(), source, CorsMode(),
                                             is_cache_disabled);
  if (load_timing == WebMediaPlayer::LoadTiming::kDeferred) {
    // Deferred media loading is not part of the spec, but intuition is that
    // this should not hold up the Window's "load" event (similar to user
    // gesture requirements).
    SetShouldDelayLoadEvent(false);
  }

  if (IsFullscreen())
    web_media_player_->EnteredFullscreen();

  web_media_player_->SetLatencyHint(latencyHint());

  web_media_player_->SetPreservesPitch(preservesPitch());

  OnLoadStarted();
}

void HTMLMediaElement::SetPlayerPreload() {
  if (web_media_player_)
    web_media_player_->SetPreload(EffectivePreloadType());

  if (LoadIsDeferred() &&
      EffectivePreloadType() != WebMediaPlayer::kPreloadNone)
    StartDeferredLoad();
}

bool HTMLMediaElement::LoadIsDeferred() const {
  return deferred_load_state_ != kNotDeferred;
}

void HTMLMediaElement::DeferLoad() {
```