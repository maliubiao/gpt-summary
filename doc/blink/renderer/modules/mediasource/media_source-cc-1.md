Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `blink::MediaSource` class in the Chromium Blink engine. I need to identify the key functionalities within this code and explain how they relate to web technologies like JavaScript, HTML, and CSS. I should also look for logical reasoning within the code and provide examples of inputs and outputs. Furthermore, I need to identify potential user or programming errors and how users might reach this code through their interactions with the browser.

Here's a breakdown of how I'll approach this:

1. **Identify core functionalities:** I'll go through the provided code, function by function, and determine its purpose. Key functions include `BufferedInternal`, `SeekableInternal`, `OnTrackChanged`, `setDuration`, `duration`, `DurationChangeAlgorithm`, `SetReadyState`, `readyState`, `endOfStream`, `setLiveSeekableRange`, `clearLiveSeekableRange`, `handle`, `SetSourceBufferActive`, `AttachmentAndTracer`, `EndOfStreamAlgorithm`, `IsClosed`, `Close`, `StartAttachingToMediaElement`, `StartWorkerAttachingToMainThreadMediaElement`, `OpenIfInEndedState`, `HasPendingActivity`, `ContextDestroyed`, and `DetachWorkerOnContextDestruction_Locked`.

2. **Relate to web technologies:**  I'll analyze how these C++ functions interact with JavaScript APIs (`MediaSource`, `SourceBuffer`, `HTMLMediaElement` attributes like `buffered`, `seekable`, `duration`, and events like `sourceended`). I will also consider any indirect relationship with HTML (through the `<video>` or `<audio>` elements) and CSS (though it's less likely to have a direct relationship here).

3. **Logical reasoning and examples:** I will look for conditional statements and algorithms within the code. For functions like `BufferedInternal` and `SeekableInternal`, I can provide hypothetical inputs (e.g., different `WebTimeRanges` from `SourceBuffer`s) and the corresponding outputs.

4. **User/programming errors:**  I will identify common mistakes users or developers might make when using the JavaScript Media Source Extensions API that would lead to these C++ code paths being executed, potentially triggering exceptions or unexpected behavior.

5. **User operation flow:** I will describe a typical user interaction with a web page using MSE, step-by-step, that could lead to the execution of the code in this snippet. This will involve actions like creating a `MediaSource` object, adding `SourceBuffer`s, appending data, and interacting with the media element's playback controls.

6. **Summarize functionality:**  Finally, I will provide a concise summary of the overall purpose of this part of the `media_source.cc` file.

**Pre-computation/Pre-analysis:**

*   The code deals with managing the buffered and seekable ranges of media content provided through the Media Source Extensions API.
*   It handles changes to the media duration, both explicitly set by the application and implicitly determined by the buffered content.
*   It manages the "ready state" of the `MediaSource` object, which reflects its operational status.
*   It handles the end-of-stream condition, which can be normal or due to errors.
*   It supports the concept of a "live seekable range" for live streams.
*   It handles the attachment and detachment of the `MediaSource` to a media element, considering both same-thread and cross-thread scenarios (for web workers).
*   It includes error handling and checks for invalid states and inputs.

By following these steps, I can provide a comprehensive and accurate explanation of the provided code snippet.
This part of the `media_source.cc` file in the Chromium Blink engine primarily focuses on **managing the buffered and seekable ranges of media data within a MediaSource, handling changes to the media duration, and managing the ready state of the MediaSource.** It also deals with the attachment and detachment of the `MediaSource` to an HTMLMediaElement, particularly considering scenarios involving web workers (MSE-in-Worker).

Here's a breakdown of its functionalities:

**1. Managing Buffered Ranges (`BufferedInternal`)**:

*   **Function:** Calculates the intersection of the buffered ranges from all active SourceBuffers associated with the MediaSource. This represents the continuous time ranges where data is available for playback.
*   **Relation to JavaScript/HTML:**
    *   This function is the backend implementation for the `MediaSource.prototype.activeSourceBuffers` and the `SourceBuffer.prototype.buffered` attributes in JavaScript. When a JavaScript accesses `videoElement.buffered` (or `audioElement.buffered`), and the media source is used, this C++ code is involved in calculating the returned `TimeRanges` object.
    *   The returned `TimeRanges` object can be used by JavaScript to display buffering status to the user or to make decisions about playback.
*   **Logical Reasoning (Hypothetical Input/Output):**
    *   **Input:** Assume two active `SourceBuffer` objects with the following buffered ranges:
        *   SourceBuffer 1: `[0-10, 20-30]`
        *   SourceBuffer 2: `[5-15, 25-35]`
    *   **Output:** `intersection_ranges` would be `[5-10, 25-30]`. This represents the time ranges where *both* source buffers have data.
*   **User/Programming Errors:** A common error is having gaps in the buffered ranges, which can lead to playback stalling. This function helps determine those gaps.
*   **User Operation Flow:**
    1. A user loads a webpage with a `<video>` element.
    2. JavaScript code creates a `MediaSource` object and associates it with the `<video>` element's `src` attribute using `URL.createObjectURL()`.
    3. JavaScript code creates one or more `SourceBuffer` objects from the `MediaSource`.
    4. JavaScript code fetches media segments and appends them to the `SourceBuffer` objects.
    5. The browser, when needing to know the buffered ranges (e.g., when the user hovers over the seek bar), will internally call `BufferedInternal`.

**2. Managing Seekable Ranges (`SeekableInternal`)**:

*   **Function:**  Determines the time ranges within the media that the user can seek to. This depends on the duration of the media and, for live streams, the `liveSeekableRange`.
*   **Relation to JavaScript/HTML:**
    *   This function is the backend implementation for the `HTMLMediaElement.prototype.seekable` attribute in JavaScript. When JavaScript accesses `videoElement.seekable`, this function calculates the `TimeRanges` object.
    *   The browser's seek bar and JavaScript code use this information to limit the seekable range.
*   **Logical Reasoning (Hypothetical Input/Output):**
    *   **Input (for VOD):** `source_duration = 60`
    *   **Output:** `ranges` would be `[0-60]`, meaning the user can seek anywhere within the 60-second duration.
    *   **Input (for Live with liveSeekableRange):** `source_duration = Infinity`, `live_seekable_range = [10-30]`, `buffered = [15-25]`
    *   **Output:** `ranges` would be `[10-30]` (the union of live seekable range and buffered, limited by the live seekable range).
*   **User/Programming Errors:** Setting an incorrect duration or not setting the `liveSeekableRange` appropriately for live streams can lead to unexpected seeking behavior.
*   **User Operation Flow:**  Similar to the buffered range flow, but when the user interacts with the seek bar, the browser relies on the `seekable` ranges calculated by this function.

**3. Handling Track Changes (`OnTrackChanged`)**:

*   **Function:**  Reacts to changes in the selected or enabled audio or video tracks within a SourceBuffer. It updates the active status of the SourceBuffer.
*   **Relation to JavaScript/HTML:**
    *   This function is called internally when JavaScript code manipulates the `audioTracks` or `videoTracks` properties of a `SourceBuffer` (e.g., setting `selected` on a video track or enabling an audio track).
    *   Changes in active tracks can affect which `SourceBuffer`s are considered when calculating buffered ranges.
*   **Logical Reasoning:** If a video track becomes selected, the SourceBuffer containing it becomes active.
*   **User/Programming Errors:**  Incorrectly managing track selections can lead to playback issues or unexpected track switching.
*   **User Operation Flow:**
    1. A user interacts with controls on a webpage to select a different audio language or video track.
    2. JavaScript code updates the `selected` or `enabled` properties of the corresponding tracks.
    3. This triggers internal events that call `OnTrackChanged`.

**4. Setting and Getting Duration (`setDuration`, `duration`, `DurationChangeAlgorithm`)**:

*   **Function:** Allows JavaScript to set the duration of the media. It also includes checks to prevent setting invalid durations (negative or NaN) or durations that would truncate buffered data.
*   **Relation to JavaScript/HTML:**
    *   These functions implement the `MediaSource.prototype.duration` getter and setter in JavaScript.
    *   Setting the duration updates the `duration` attribute of the associated `<video>` or `<audio>` element.
*   **Logical Reasoning:**  The `DurationChangeAlgorithm` ensures that the new duration is valid and handles the deprecated behavior of automatically removing buffered data when the duration is shortened (though this is being phased out).
*   **User/Programming Errors:**
    *   Trying to set a negative or non-finite duration will throw a `TypeError`.
    *   Trying to set a duration while a SourceBuffer is updating will throw an `InvalidStateError`.
    *   Prior to recent changes, setting a duration shorter than the buffered content would trigger data removal. This is now discouraged, and an error is thrown if the new duration is less than the highest presentation timestamp.
*   **User Operation Flow:**
    1. JavaScript code retrieves metadata about the media (e.g., from a manifest file).
    2. JavaScript code sets the `mediaSource.duration` property.

**5. Managing Ready State (`SetReadyState`, `readyState`)**:

*   **Function:**  Manages the internal state of the `MediaSource` (open, closed, ended).
*   **Relation to JavaScript/HTML:**
    *   These functions implement the `MediaSource.prototype.readyState` attribute in JavaScript.
    *   JavaScript code can check the `readyState` to determine the current state of the `MediaSource`.
    *   Changes in `readyState` trigger events like `sourceopen`, `sourceended`, and `sourceclose`.
*   **Logical Reasoning:** The ready state determines which operations are valid on the `MediaSource`.
*   **User/Programming Errors:** Trying to call methods like `addSourceBuffer` or `endOfStream` when the `readyState` is not "open" will result in an `InvalidStateError`.
*   **User Operation Flow:** The `readyState` changes as the `MediaSource` is initialized, receives data, and reaches the end of the stream.

**6. Handling End of Stream (`endOfStream`, `EndOfStreamAlgorithm`)**:

*   **Function:**  Allows JavaScript to signal the end of the media stream, either normally or with an error.
*   **Relation to JavaScript/HTML:**
    *   This function implements the `MediaSource.prototype.endOfStream()` method in JavaScript.
    *   Calling `endOfStream()` with no arguments signals a normal end, while calling it with an error (e.g., 'network' or 'decode') indicates an error.
    *   This triggers the `sourceended` event on the `MediaSource`.
*   **Logical Reasoning:**  The `EndOfStreamAlgorithm` transitions the `readyState` to "ended" and informs the underlying media engine.
*   **User/Programming Errors:** Calling `endOfStream` prematurely or with the wrong error type can lead to playback issues.
*   **User Operation Flow:**
    1. JavaScript code determines that all media data has been appended.
    2. JavaScript code calls `mediaSource.endOfStream()`.

**7. Managing Live Seekable Range (`setLiveSeekableRange`, `clearLiveSeekableRange`)**:

*   **Function:**  Allows JavaScript to define the seekable range for live streams.
*   **Relation to JavaScript/HTML:**
    *   These functions implement the `MediaSource.prototype.setLiveSeekableRange()` and `MediaSource.prototype.clearLiveSeekableRange()` methods in JavaScript.
    *   This is crucial for live streaming scenarios where the entire stream is not available at once.
*   **Logical Reasoning:** The `liveSeekableRange` limits seeking to a specific window of the live stream.
*   **User/Programming Errors:** Setting an invalid `liveSeekableRange` (start greater than end, negative start) will throw a `TypeError`.
*   **User Operation Flow:**
    1. JavaScript code, based on information from a media manifest or server, determines the current seekable window for a live stream.
    2. JavaScript code calls `mediaSource.setLiveSeekableRange()`.

**8. Handling MediaSource Handles for Workers (`handle`)**:

*   **Function:**  Provides a mechanism for transferring a `MediaSource` object from a worker thread to the main thread.
*   **Relation to JavaScript/HTML:**
    *   This function implements the `MediaSource.prototype.handle` attribute in JavaScript, which returns a `MediaSourceHandle`.
    *   This is part of the MSE-in-Workers specification, allowing a `MediaSource` created in a worker to be attached to a `<video>` or `<audio>` element in the main thread.
*   **Logical Reasoning:**  The handle acts as a proxy, allowing the main thread to interact with the worker's `MediaSource`.
*   **User/Programming Errors:** This is a more advanced feature, and improper usage might lead to issues with cross-thread communication.
*   **User Operation Flow:**
    1. JavaScript code in a worker creates a `MediaSource`.
    2. JavaScript code in the worker obtains the `MediaSourceHandle` using `mediaSource.handle`.
    3. The worker sends the `MediaSourceHandle` to the main thread (e.g., using `postMessage`).
    4. JavaScript code in the main thread uses the `MediaSourceHandle` to set the `srcObject` of a media element.

**9. Managing Active Source Buffers (`SetSourceBufferActive`)**:

*   **Function:**  Keeps track of which `SourceBuffer` objects are currently considered "active," based on track selections.
*   **Relation to JavaScript/HTML:**
    *   This function is internally used when tracks are selected or deselected, influencing the `activeSourceBuffers` property.
*   **Logical Reasoning:** Only active source buffers contribute to the calculation of buffered ranges.

**10. Utility for Accessing Attachment and Tracer (`AttachmentAndTracer`)**:

*   **Function:**  Provides a way to retrieve the `MediaSourceAttachmentSupplement` (which connects the `MediaSource` to the media element) and the `MediaSourceTracer` (used for debugging and logging).

**11. Closing the Media Source (`Close`)**:

*   **Function:**  Sets the `readyState` to "closed," indicating the `MediaSource` is no longer usable.
*   **Relation to JavaScript/HTML:**
    *   This is called internally when the associated media element or the `MediaSource` itself is being torn down.

**12. Handling Attachment and Detachment (`StartAttachingToMediaElement`, `StartWorkerAttachingToMainThreadMediaElement`)**:

*   **Function:** Manages the process of associating the `MediaSource` with an HTMLMediaElement, considering both same-thread and worker-to-main-thread scenarios.

**13. Re-opening an Ended Media Source (`OpenIfInEndedState`)**:

*   **Function:**  Allows the `MediaSource` to transition back to the "open" state from the "ended" state, potentially for re-use.

**14. Checking for Pending Asynchronous Operations (`HasPendingActivity`)**:

*   **Function:**  Indicates if there are any pending asynchronous tasks associated with the `MediaSource`.

**15. Handling Context Destruction (`ContextDestroyed`, `DetachWorkerOnContextDestruction_Locked`)**:

*   **Function:**  Manages the cleanup process when the JavaScript execution context (either the main window or a worker) is being destroyed, ensuring proper detachment and resource release. This is crucial to avoid memory leaks and dangling pointers.

**In Summary of Part 2's Functionality:**

This section of the `media_source.cc` file is crucial for the core functionality of the Media Source Extensions API. It manages the temporal aspects of the media stream (buffered and seekable ranges, duration), the operational state of the `MediaSource`, and the connection between the `MediaSource` and the HTMLMediaElement. It also lays the groundwork for more advanced features like MSE-in-Workers by handling cross-thread attachment and handle management. The code prioritizes consistency, error handling, and adherence to the MSE specification.

### 提示词
```
这是目录为blink/renderer/modules/mediasource/media_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
pass_key);
  }

  WebTimeRanges intersection_ranges;

  // 1. If activeSourceBuffers.length equals 0 then return an empty TimeRanges
  //    object and abort these steps.
  if (ranges.empty())
    return intersection_ranges;

  // 2. Let active ranges be the ranges returned by buffered for each
  //    SourceBuffer object in activeSourceBuffers.
  // 3. Let highest end time be the largest range end time in the active ranges.
  double highest_end_time = -1;
  for (const WebTimeRanges& source_ranges : ranges) {
    if (!source_ranges.empty())
      highest_end_time = std::max(highest_end_time, source_ranges.back().end);
  }

  // Return an empty range if all ranges are empty.
  if (highest_end_time < 0)
    return intersection_ranges;

  // 4. Let intersection ranges equal a TimeRange object containing a single
  //    range from 0 to highest end time.
  intersection_ranges.emplace_back(0, highest_end_time);

  // 5. For each SourceBuffer object in activeSourceBuffers run the following
  //    steps:
  bool ended = ready_state_ == ReadyState::kEnded;
  // 5.1 Let source ranges equal the ranges returned by the buffered attribute
  //     on the current SourceBuffer.
  for (WebTimeRanges& source_ranges : ranges) {
    // 5.2 If readyState is "ended", then set the end time on the last range in
    //     source ranges to highest end time.
    if (ended && !source_ranges.empty())
      source_ranges.Add(source_ranges.back().start, highest_end_time);

    // 5.3 Let new intersection ranges equal the the intersection between the
    //     intersection ranges and the source ranges.
    // 5.4 Replace the ranges in intersection ranges with the new intersection
    //     ranges.
    intersection_ranges.IntersectWith(source_ranges);
  }

  return intersection_ranges;
}

WebTimeRanges MediaSource::SeekableInternal(
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) const {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();
  {
    base::AutoLock lock(attachment_link_lock_);
    DCHECK(media_source_attachment_)
        << "Seekable should only be used when attached to HTMLMediaElement";
  }

  // Implements MediaSource algorithm for HTMLMediaElement.seekable.
  // http://w3c.github.io/media-source/#htmlmediaelement-extensions
  WebTimeRanges ranges;

  double source_duration = GetDuration_Locked(pass_key);

  // If duration equals NaN: Return an empty TimeRanges object.
  if (std::isnan(source_duration))
    return ranges;

  // If duration equals positive Infinity:
  if (source_duration == std::numeric_limits<double>::infinity()) {
    WebTimeRanges buffered = BufferedInternal(pass_key);

    // 1. If live seekable range is not empty:
    if (has_live_seekable_range_) {
      // 1.1. Let union ranges be the union of live seekable range and the
      //      HTMLMediaElement.buffered attribute.
      // 1.2. Return a single range with a start time equal to the
      //      earliest start time in union ranges and an end time equal to
      //      the highest end time in union ranges and abort these steps.
      if (buffered.empty()) {
        ranges.emplace_back(live_seekable_range_start_,
                            live_seekable_range_end_);
        return ranges;
      }

      ranges.emplace_back(
          std::min(live_seekable_range_start_, buffered.front().start),
          std::max(live_seekable_range_end_, buffered.back().end));
      return ranges;
    }

    // 2. If the HTMLMediaElement.buffered attribute returns an empty TimeRanges
    //    object, then return an empty TimeRanges object and abort these steps.
    if (buffered.empty())
      return ranges;

    // 3. Return a single range with a start time of 0 and an end time equal to
    //    the highest end time reported by the HTMLMediaElement.buffered
    //    attribute.
    ranges.emplace_back(0, buffered.back().end);
    return ranges;
  }

  // 3. Otherwise: Return a single range with a start time of 0 and an end time
  //    equal to duration.
  ranges.emplace_back(0, source_duration);
  return ranges;
}

void MediaSource::OnTrackChanged(TrackBase* track) {
  // TODO(https://crbug.com/878133): Support this in MSE-in-Worker once
  // TrackBase and TrackListBase are usable on worker and do not explicitly
  // require an HTMLMediaElement. The update to |active_source_buffers_| will
  // also require sending updated buffered and seekable information to the main
  // thread, though the CTMSA itself would best know when to do that since it is
  // this method should only be called by an attachment.
  DCHECK(IsMainThread());

  SourceBuffer* source_buffer =
      SourceBufferTrackBaseSupplement::sourceBuffer(*track);
  if (!source_buffer)
    return;

  DCHECK(source_buffers_->Contains(source_buffer));
  if (track->GetType() == WebMediaPlayer::kAudioTrack) {
    source_buffer->audioTracks().ScheduleChangeEvent();
  } else if (track->GetType() == WebMediaPlayer::kVideoTrack) {
    if (static_cast<VideoTrack*>(track)->selected())
      source_buffer->videoTracks().TrackSelected(track->id());
    source_buffer->videoTracks().ScheduleChangeEvent();
  }

  bool is_active = (source_buffer->videoTracks().selectedIndex() != -1) ||
                   source_buffer->audioTracks().HasEnabledTrack();
  SetSourceBufferActive(source_buffer, is_active);
}

void MediaSource::setDuration(double duration,
                              ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this << " : duration=" << duration;

  // 2.1 https://www.w3.org/TR/media-source/#widl-MediaSource-duration
  // 1. If the value being set is negative or NaN then throw a TypeError
  // exception and abort these steps.
  if (std::isnan(duration)) {
    LogAndThrowTypeError(exception_state, ExceptionMessages::NotAFiniteNumber(
                                              duration, "duration"));
    return;
  }
  if (duration < 0.0) {
    LogAndThrowTypeError(
        exception_state,
        ExceptionMessages::IndexExceedsMinimumBound("duration", duration, 0.0));
    return;
  }

  // 2. If the readyState attribute is not "open" then throw an
  //    InvalidStateError exception and abort these steps.
  // 3. If the updating attribute equals true on any SourceBuffer in
  //    sourceBuffers, then throw an InvalidStateError exception and abort these
  //    steps.
  if (ThrowExceptionIfClosedOrUpdating(IsOpen(), IsUpdating(), exception_state))
    return;

  // 4. Run the duration change algorithm with new duration set to the value
  //    being assigned to this attribute.
  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must be open, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &MediaSource::DurationChangeAlgorithm, WrapPersistent(this), duration,
          WTF::Unretained(&exception_state)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }
}

double MediaSource::duration() {
  double duration_result = std::numeric_limits<float>::quiet_NaN();
  if (IsClosed())
    return duration_result;

  // Note, here we must be open or ended, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          [](MediaSource* self, double* result,
             MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
            *result = self->GetDuration_Locked(pass_key);
          },
          WrapPersistent(this), WTF::Unretained(&duration_result)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, result should be in this case. It seems reasonable
    // to behave is if we are in "closed" readyState and report NaN to the app
    // here.
    DCHECK_EQ(duration_result, std::numeric_limits<float>::quiet_NaN());
  }

  return duration_result;
}

void MediaSource::DurationChangeAlgorithm(
    double new_duration,
    ExceptionState* exception_state,
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // http://w3c.github.io/media-source/#duration-change-algorithm
  // 1. If the current value of duration is equal to new duration, then return.
  double old_duration = GetDuration_Locked(pass_key);
  if (new_duration == old_duration)
    return;

  // 2. If new duration is less than the highest starting presentation
  // timestamp of any buffered coded frames for all SourceBuffer objects in
  // sourceBuffers, then throw an InvalidStateError exception and abort these
  // steps. Note: duration reductions that would truncate currently buffered
  // media are disallowed. When truncation is necessary, use remove() to
  // reduce the buffered range before updating duration.
  double highest_buffered_presentation_timestamp = 0;
  for (unsigned i = 0; i < source_buffers_->length(); ++i) {
    highest_buffered_presentation_timestamp =
        std::max(highest_buffered_presentation_timestamp,
                 source_buffers_->item(i)->HighestPresentationTimestamp());
  }

  if (new_duration < highest_buffered_presentation_timestamp) {
    if (RuntimeEnabledFeatures::MediaSourceNewAbortAndDurationEnabled()) {
      LogAndThrowDOMException(
          *exception_state, DOMExceptionCode::kInvalidStateError,
          "Setting duration below highest presentation timestamp of any "
          "buffered coded frames is disallowed. Instead, first do asynchronous "
          "remove(newDuration, oldDuration) on all sourceBuffers, where "
          "newDuration < oldDuration.");
      return;
    }

    Deprecation::CountDeprecation(
        GetExecutionContext(),
        WebFeature::kMediaSourceDurationTruncatingBuffered);
    // See also deprecated remove(new duration, old duration) behavior below.
  }

  DCHECK_LE(highest_buffered_presentation_timestamp,
            std::isnan(old_duration) ? 0 : old_duration);

  // 3. Set old duration to the current value of duration.
  // Done for step 1 above, already.
  // 4. Update duration to new duration.
  web_media_source_->SetDuration(new_duration);

  if (!RuntimeEnabledFeatures::MediaSourceNewAbortAndDurationEnabled() &&
      new_duration < old_duration) {
    // Deprecated behavior: if the new duration is less than old duration,
    // then call remove(new duration, old duration) on all all objects in
    // sourceBuffers.
    for (unsigned i = 0; i < source_buffers_->length(); ++i) {
      source_buffers_->item(i)->Remove_Locked(new_duration, old_duration,
                                              &ASSERT_NO_EXCEPTION, pass_key);
    }
  }

  // 5. If a user agent is unable to partially render audio frames or text cues
  //    that start before and end after the duration, then run the following
  //    steps:
  //    NOTE: Currently we assume that the media engine is able to render
  //    partial frames/cues. If a media engine gets added that doesn't support
  //    this, then we'll need to add logic to handle the substeps.

  // 6. Update the media controller duration to new duration and run the
  //    HTMLMediaElement duration change algorithm.
  auto [attachment, tracer] = AttachmentAndTracer();
  attachment->NotifyDurationChanged(tracer, new_duration);
}

void MediaSource::SetReadyState(const ReadyState state) {
  DCHECK(state == ReadyState::kOpen || state == ReadyState::kClosed ||
         state == ReadyState::kEnded);

  ReadyState old_state = ready_state_;
  DVLOG(3) << __func__ << " this=" << this << " : "
           << ReadyStateToString(old_state) << " -> "
           << ReadyStateToString(state);

  if (state == ReadyState::kClosed) {
    web_media_source_.reset();
  }

  if (old_state == state)
    return;

  ready_state_ = state;

  OnReadyStateChange(old_state, state);
}

AtomicString MediaSource::readyState() const {
  return ReadyStateToString(ready_state_);
}

void MediaSource::endOfStream(ExceptionState& exception_state) {
  endOfStream(std::nullopt, exception_state);
}

void MediaSource::endOfStream(std::optional<V8EndOfStreamError> error,
                              ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this
           << " : error=" << (error.has_value() ? error->AsCStr() : "");

  // https://www.w3.org/TR/media-source/#dom-mediasource-endofstream
  // 1. If the readyState attribute is not in the "open" state then throw an
  //    InvalidStateError exception and abort these steps.
  // 2. If the updating attribute equals true on any SourceBuffer in
  //    sourceBuffers, then throw an InvalidStateError exception and abort these
  //    steps.
  if (ThrowExceptionIfClosedOrUpdating(IsOpen(), IsUpdating(), exception_state))
    return;

  // 3. Run the end of stream algorithm with the error parameter set to error.
  WebMediaSource::EndOfStreamStatus status =
      WebMediaSource::kEndOfStreamStatusNoError;
  if (error.has_value()) {
    switch (error->AsEnum()) {
      case V8EndOfStreamError::Enum::kNetwork:
        status = WebMediaSource::kEndOfStreamStatusNetworkError;
        break;
      case V8EndOfStreamError::Enum::kDecode:
        status = WebMediaSource::kEndOfStreamStatusDecodeError;
        break;
      default:
        NOTREACHED();
    }
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must be open, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &MediaSource::EndOfStreamAlgorithm, WrapPersistent(this), status))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }
}

void MediaSource::setLiveSeekableRange(double start,
                                       double end,
                                       ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this << " : start=" << start
           << ", end=" << end;

  // http://w3c.github.io/media-source/#widl-MediaSource-setLiveSeekableRange-void-double-start-double-end
  // 1. If the readyState attribute is not "open" then throw an
  //    InvalidStateError exception and abort these steps.
  // 2. If the updating attribute equals true on any SourceBuffer in
  //    SourceBuffers, then throw an InvalidStateError exception and abort
  //    these steps.
  //    Note: https://github.com/w3c/media-source/issues/118, once fixed, will
  //    remove the updating check (step 2). We skip that check here already.
  if (ThrowExceptionIfClosed(IsOpen(), exception_state))
    return;

  // 3. If start is negative or greater than end, then throw a TypeError
  //    exception and abort these steps.
  if (start < 0 || start > end) {
    LogAndThrowTypeError(
        exception_state,
        ExceptionMessages::IndexOutsideRange(
            "start value", start, 0.0, ExceptionMessages::kInclusiveBound, end,
            ExceptionMessages::kInclusiveBound));
    return;
  }

  // Note, here we must be open, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&MediaSource::SetLiveSeekableRange_Locked,
                        WrapPersistent(this), start, end))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }
}

void MediaSource::SetLiveSeekableRange_Locked(
    double start,
    double end,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 4. Set live seekable range to be a new normalized TimeRanges object
  //    containing a single range whose start position is start and end
  //    position is end.
  has_live_seekable_range_ = true;
  live_seekable_range_start_ = start;
  live_seekable_range_end_ = end;

  SendUpdatedInfoToMainThreadCache();
}

void MediaSource::clearLiveSeekableRange(ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this;

  // http://w3c.github.io/media-source/#widl-MediaSource-clearLiveSeekableRange-void
  // 1. If the readyState attribute is not "open" then throw an
  //    InvalidStateError exception and abort these steps.
  // 2. If the updating attribute equals true on any SourceBuffer in
  //    SourceBuffers, then throw an InvalidStateError exception and abort
  //    these steps.
  //    Note: https://github.com/w3c/media-source/issues/118, once fixed, will
  //    remove the updating check (step 2). We skip that check here already.
  if (ThrowExceptionIfClosed(IsOpen(), exception_state))
    return;

  // Note, here we must be open, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &MediaSource::ClearLiveSeekableRange_Locked, WrapPersistent(this)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }
}

void MediaSource::ClearLiveSeekableRange_Locked(
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 3. If live seekable range contains a range, then set live seekable range
  //    to be a new empty TimeRanges object.
  if (!has_live_seekable_range_)
    return;

  has_live_seekable_range_ = false;
  live_seekable_range_start_ = 0.0;
  live_seekable_range_end_ = 0.0;

  SendUpdatedInfoToMainThreadCache();
}

MediaSourceHandleImpl* MediaSource::handle() {
  base::AutoLock lock(attachment_link_lock_);

  DVLOG(3) << __func__;

  // TODO(crbug.com/506273): Support MediaSource srcObject attachment idiom for
  // main-thread-owned MediaSource objects (would need MSE spec updates, too,
  // and might not involve a handle regardless).
  DCHECK(!IsMainThread() &&
         GetExecutionContext()->IsDedicatedWorkerGlobalScope());

  // Per
  // https://www.w3.org/TR/2022/WD-media-source-2-20220921/#dom-mediasource-handle:
  // If the handle for this MediaSource object has not yet been created, then
  // run the following steps:
  // 1.1. Let created handle be the result of creating a new MediaSourceHandle
  //      object and associated resources, linked internally to this
  //      MediaSource.
  // 1.2. Update the attribute to be created handle.
  if (!worker_media_source_handle_) {
    // Lazily create the handle, since it indirectly holds a
    // CrossThreadMediaSourceAttachment (until attachment starts or the handle
    // is transferred) which holds a strong reference to us until attachment is
    // actually started and later closed. PassKey provider usage here ensures
    // that we are allowed to call the attachment constructor.
    scoped_refptr<CrossThreadMediaSourceAttachment> attachment =
        base::MakeRefCounted<CrossThreadMediaSourceAttachment>(
            this, AttachmentCreationPassKeyProvider::GetPassKey());
    scoped_refptr<HandleAttachmentProvider> attachment_provider =
        base::MakeRefCounted<HandleAttachmentProvider>(std::move(attachment));

    // Create, but don't "register" an internal blob URL with the security
    // origin of the worker's execution context for use later in a window thread
    // media element's attachment to the MediaSource leveraging existing URL
    // security checks and logging for legacy MSE object URLs.
    const SecurityOrigin* origin = GetExecutionContext()->GetSecurityOrigin();
    String internal_blob_url = BlobURL::CreatePublicURL(origin).GetString();
    DCHECK(!internal_blob_url.empty());
    worker_media_source_handle_ = MakeGarbageCollected<MediaSourceHandleImpl>(
        std::move(attachment_provider), std::move(internal_blob_url));
  }

  // Per
  // https://www.w3.org/TR/2022/WD-media-source-2-20220921/#dom-mediasource-handle:
  // 2. Return the MediaSourceHandle object that is this attribute's value.
  DCHECK(worker_media_source_handle_);
  return worker_media_source_handle_.Get();
}

bool MediaSource::IsOpen() const {
  return ready_state_ == ReadyState::kOpen;
}

void MediaSource::SetSourceBufferActive(SourceBuffer* source_buffer,
                                        bool is_active) {
  if (!is_active) {
    DCHECK(active_source_buffers_->Contains(source_buffer));
    active_source_buffers_->Remove(source_buffer);
    return;
  }

  if (active_source_buffers_->Contains(source_buffer))
    return;

  // https://dvcs.w3.org/hg/html-media/raw-file/tip/media-source/media-source.html#widl-MediaSource-activeSourceBuffers
  // SourceBuffer objects in SourceBuffer.activeSourceBuffers must appear in
  // the same order as they appear in SourceBuffer.sourceBuffers.
  // SourceBuffer transitions to active are not guaranteed to occur in the
  // same order as buffers in |m_sourceBuffers|, so this method needs to
  // insert |sourceBuffer| into |m_activeSourceBuffers|.
  wtf_size_t index_in_source_buffers = source_buffers_->Find(source_buffer);
  DCHECK(index_in_source_buffers != kNotFound);

  wtf_size_t insert_position = 0;
  while (insert_position < active_source_buffers_->length() &&
         source_buffers_->Find(active_source_buffers_->item(insert_position)) <
             index_in_source_buffers) {
    ++insert_position;
  }

  active_source_buffers_->insert(insert_position, source_buffer);
}

std::pair<scoped_refptr<MediaSourceAttachmentSupplement>, MediaSourceTracer*>
MediaSource::AttachmentAndTracer() const {
  base::AutoLock lock(attachment_link_lock_);
  return std::make_pair(media_source_attachment_, attachment_tracer_.Get());
}

void MediaSource::EndOfStreamAlgorithm(
    const WebMediaSource::EndOfStreamStatus eos_status,
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // https://www.w3.org/TR/media-source/#end-of-stream-algorithm
  // 1. Change the readyState attribute value to "ended".
  // 2. Queue a task to fire a simple event named sourceended at the
  //    MediaSource.
  SetReadyState(ReadyState::kEnded);

  // 3. Do various steps based on |eos_status|.
  web_media_source_->MarkEndOfStream(eos_status);

  if (eos_status == WebMediaSource::kEndOfStreamStatusNoError) {
    // The implementation may not have immediately informed the attached element
    // (known by the |media_source_attachment_| and |attachment_tracer_|) of the
    // potentially reduced duration. Prevent app-visible duration race by
    // synchronously running the duration change algorithm. The MSE spec
    // supports this:
    // https://www.w3.org/TR/media-source/#end-of-stream-algorithm
    // 2.4.7.3 (If error is not set)
    // Run the duration change algorithm with new duration set to the largest
    // track buffer ranges end time across all the track buffers across all
    // SourceBuffer objects in sourceBuffers.
    //
    // Since MarkEndOfStream caused the demuxer to update its duration (similar
    // to the MediaSource portion of the duration change algorithm), all that
    // is left is to notify the element.
    // TODO(wolenetz): Consider refactoring the MarkEndOfStream implementation
    // to just mark end of stream, and move the duration reduction logic to here
    // so we can just run DurationChangeAlgorithm(...) here.
    double new_duration = GetDuration_Locked(pass_key);
    auto [attachment, tracer] = AttachmentAndTracer();
    attachment->NotifyDurationChanged(tracer, new_duration);
  } else {
    // Even though error didn't change duration, the transition to kEnded
    // impacts the buffered ranges calculation, so let the attachment know that
    // a cross-thread media element needs to be sent updated information.
    SendUpdatedInfoToMainThreadCache();
  }
}

bool MediaSource::IsClosed() const {
  return ready_state_ == ReadyState::kClosed;
}

void MediaSource::Close() {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();
  SetReadyState(ReadyState::kClosed);
}

MediaSourceTracer* MediaSource::StartAttachingToMediaElement(
    scoped_refptr<SameThreadMediaSourceAttachment> attachment,
    HTMLMediaElement* element) {
  base::AutoLock lock(attachment_link_lock_);

  DCHECK(IsMainThread());

  if (media_source_attachment_ || attachment_tracer_) {
    return nullptr;
  }

  DCHECK(!context_already_destroyed_);
  DCHECK(IsClosed());

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("media",
                                    "MediaSource::StartAttachingToMediaElement",
                                    TRACE_ID_LOCAL(this));
  media_source_attachment_ = attachment;
  attachment_tracer_ =
      MakeGarbageCollected<SameThreadMediaSourceTracer>(element, this);
  return attachment_tracer_.Get();
}

bool MediaSource::StartWorkerAttachingToMainThreadMediaElement(
    scoped_refptr<CrossThreadMediaSourceAttachment> attachment) {
  base::AutoLock lock(attachment_link_lock_);

  // Even in worker-owned MSE, the CrossThreadMediaSourceAttachment calls this
  // on the main thread.
  DCHECK(IsMainThread());
  DCHECK(!attachment_tracer_);  // A worker-owned MediaSource has no tracer.

  if (context_already_destroyed_) {
    return false;  // See comments in ContextDestroyed().
  }

  if (media_source_attachment_ || attachment_tracer_) {
    return false;  // Already attached.
  }

  DCHECK(IsClosed());
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(
      "media", "MediaSource::StartWorkerAttachingToMainThreadMediaElement",
      TRACE_ID_LOCAL(this));
  media_source_attachment_ = attachment;
  return true;
}

void MediaSource::OpenIfInEndedState() {
  if (ready_state_ != ReadyState::kEnded)
    return;

  // All callers of this method (see SourceBuffer methods) must have already
  // confirmed they are still associated with us, and therefore we must not be
  // closed. In one edge case (!notify_close version of our
  // DetachWorkerOnContextDestruction_Locked), any associated SourceBuffers are
  // not told they're dissociated with us in that method, but it is run on the
  // worker thread that is also synchronously destructing the SourceBuffers'
  // context). Therefore the following should never fail here.
  DCHECK(!IsClosed());

  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  SetReadyState(ReadyState::kOpen);
  web_media_source_->UnmarkEndOfStream();

  // This change impacts buffered and seekable calculations, so let the
  // attachment know to update if cross-thread.
  SendUpdatedInfoToMainThreadCache();
}

bool MediaSource::HasPendingActivity() const {
  // Note that an unrevoked MediaSource objectUrl for an otherwise inactive,
  // unreferenced HTMLME with MSE still attached will prevent GC of the whole
  // group of objects. This is yet further motivation for apps to properly
  // revokeObjectUrl and for the MSE spec, implementations and API users to
  // transition to using HTMLME srcObject for MSE attachment instead of
  // objectUrl. For at least SameThreadMediaSourceAttachments, the
  // RevokeMediaSourceObjectURLOnAttach feature assists in automating this case.
  // But for CrossThreadMediaSourceAttachments, the attachment holds strong
  // references to each side until explicitly detached (or contexts destroyed).
  // The latter applies similarly when using MediaSourceHandle for srcObject
  // attachment of a worker MediaSource: the handle object has a scoped_refptr
  // to the underlying attachment until the handle is GC'ed.
  return async_event_queue_->HasPendingEvents();
}

void MediaSource::ContextDestroyed() {
  DVLOG(1) << __func__ << " this=" << this;

  // In same-thread case, we just close ourselves if not already closed. This is
  // historically the same logic as before MSE-in-Workers. Note that we cannot
  // inspect GetExecutionContext() to determine Window vs Worker here, so we use
  // IsMainThread(). There is no need to RunExclusively() either, because we are
  // on the same thread as the media element.
  if (IsMainThread()) {
    {
      base::AutoLock lock(attachment_link_lock_);
      if (media_source_attachment_) {
        DCHECK(attachment_tracer_);  // Same-thread attachment uses tracer.
        // No need to release |attachment_link_lock_| and RunExclusively(),
        // since it is a same-thread attachment.
        media_source_attachment_->OnMediaSourceContextDestroyed();
      }

      // For consistency, though redundant for same-thread operation, prevent
      // subsequent attachment start from succeeding. This flag is meaningful in
      // cross-thread attachment usage.
      context_already_destroyed_ = true;
    }

    if (!IsClosed()) {
      SetReadyState(ReadyState::kClosed);
    }
    web_media_source_.reset();
    return;
  }

  // Worker context destruction could race CrossThreadMediaSourceAttachment's
  // StartAttachingToMediaElement on the main thread: we could finish
  // ContextDestroyed() here, and in the case of not yet ever having been
  // attached using a particular CrossThreadMediaSourceAttachent, then receive a
  // StartWorkerAttachingToMainThreadMediaElement() call before unregistration
  // of us has completed. Therefore, we use our |attachment_link_lock_| to also
  // protect a flag here that lets us know to fail any future attempt to start
  // attaching to us.
  scoped_refptr<MediaSourceAttachmentSupplement> attachment;
  {
    base::AutoLock lock(attachment_link_lock_);
    context_already_destroyed_ = true;

    // If not yet attached, the flag, above, will prevent us from ever
    // successfully attaching, and we can return. There is no attachment on
    // which we need (or can) call OnMediaSourceContextDestroyed() here. And any
    // attachments owned by this context will soon (or have already been)
    // unregistered.
    attachment = media_source_attachment_;
    if (!attachment) {
      DCHECK(IsClosed());
      DCHECK(!web_media_source_);
      return;
    }
  }

  // We need to let our current attachment know that our context is destroyed.
  // This will let it handle cases like returning sane values for
  // BufferedInternal and SeekableInternal and stop further use of us via the
  // attachment. We need to hold the attachment's |attachment_state_lock_| when
  // doing this detachment.
  bool cb_ran = attachment->RunExclusively(
      true /* abort if unsafe to use underlying demuxer */,
      WTF::BindOnce(&MediaSource::DetachWorkerOnContextDestruction_Locked,
                    WrapPersistent(this),
                    true /* safe to notify underlying demuxer */));

  if (!cb_ran) {
    // Main-thread is already detaching or destructing the underlying demuxer.
    CHECK(attachment->RunExclusively(
        false /* do not abort */,
        WTF::BindOnce(&MediaSource::DetachWorkerOnContextDestruction_Locked,
                      WrapPersistent(this),
                      false /* do not notify underlying demuxer */)));
  }
}

void MediaSource::DetachWorkerOnContextDestruction_Locked(
    bool notify_close,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  {
    base::AutoLock lock(attachment_link_lock_);

    DCHECK(!IsMainThread());  // Called only on the worker thread.

    DVLOG(1) << __func__ << " this=" << this
             << ", notify_close=" << notify_close;

    // Close() could not race our dispatch: it must happen on worker thread, on
    // which we're called synchronously only if we're attached.
    DCHECK(media_source_attachment_);

    // We're only called for CrossThread attachments, which use no tracer.
    DCHECK(!attachment_tracer_);

    // Let the attachment know to prevent further operations on us.
    media_source_attachment_->OnMediaSourceContextDestroyed();

    if (!notify_close) {
      // In this case, not only is our context shutting down, but the media
      // element is also at least tearing down the WebMediaPlayer (and the
      // underlying demuxer owned by it) already. W
```