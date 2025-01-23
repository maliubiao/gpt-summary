Response:
The user wants to understand the functionality of the provided C++ code snippet from `source_buffer.cc`. This is the second part of a four-part code block. I need to analyze this section and summarize its key responsibilities within the `SourceBuffer` class. Specifically, I should look for:

1. **Core Functions:** What actions does this code perform?
2. **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, or CSS concepts (even indirectly)?
3. **Logic and Data Flow:** Can I infer input and output based on the code's logic?
4. **Potential User/Developer Errors:** What mistakes could lead to this code being executed or behaving unexpectedly?
5. **Debugging Context:** How might a user's actions lead to the execution of this code?
6. **Overall Purpose (for this part):** What is the main theme or set of functionalities covered in this specific snippet?

Looking at the code, I see functions related to:

* **Appending data:** `AppendEncodedChunks_Locked`
* **Aborting operations:** `abort`, `Abort_Locked`, `CancelRemove`, `AbortIfUpdating`
* **Removing data:** `remove`, `Remove_Locked`, `RemoveAsyncPart` (though the implementation of the async part isn't here)
* **Changing media type:** `changeType`, `ChangeType_Locked`, `ChangeTypeUsingConfig`
* **Setting track defaults:** `setTrackDefaults`
* **Handling removal from media source:** `RemovedFromMediaSource`, `RemoveMediaTracks`, `AddPlaceholderCrossThreadTracks`
* **Getting media time:** `GetMediaTime`
* **Finding tracks:** `FindExistingTrackById`
* **Retrieving track defaults:** `GetTrackDefault`, `DefaultTrackLabel`, `DefaultTrackLanguage`

It seems this part of the code primarily deals with managing the lifecycle of media data within a `SourceBuffer`, including adding, removing, and modifying it, as well as handling changes to the media type and track information. It also handles the cleanup when a `SourceBuffer` is removed from its parent `MediaSource`.

**Summary of Functionality for Part 2:** This section of `SourceBuffer.cc` focuses on methods for manipulating the buffered media data, such as appending encoded chunks, removing ranges of data, and aborting ongoing operations. It also includes functions for changing the media type of the `SourceBuffer`, setting default track properties, and managing the removal of the `SourceBuffer` from its parent `MediaSource`, including the associated media tracks.
这是 `blink/renderer/modules/mediasource/source_buffer.cc` 文件的第二部分，主要负责实现 `SourceBuffer` 接口中与媒体数据操作、类型变更、以及生命周期管理相关的核心功能。以下是其功能的归纳：

**核心功能：**

1. **追加编码数据 (Append Encoded Chunks):**
   - `AppendEncodedChunks_Locked`: 接收编码后的媒体数据块，并将其加入到待缓冲队列中。这是一个处理异步 Promise 的版本，与直接调用 `appendBuffer` 不同。

2. **中止操作 (Abort):**
   - `abort`:  允许用户主动中止当前正在进行的 `appendBuffer` 或 `remove` 操作。会检查 `SourceBuffer` 的状态以及父 `MediaSource` 的状态，并根据情况抛出异常。
   - `Abort_Locked`: 实际执行中止操作的逻辑，包括重置解析器状态和重置 appendWindow 的范围。
   - `CancelRemove`:  取消正在进行的 `remove` 操作。
   - `AbortIfUpdating`:  检查 `updating_` 状态，如果为 true，则中止当前的追加或删除操作，并触发相应的事件。

3. **移除数据 (Remove):**
   - `remove`: 允许用户指定时间范围来移除已缓冲的媒体数据。会进行参数校验，并异步执行移除操作。
   - `Remove_Locked`:  实际执行移除操作前的准备工作，包括检查父 `MediaSource` 的状态。

4. **变更媒体类型 (Change Type):**
   - `changeType`: 允许用户在 `SourceBuffer` 中更改媒体的 MIME 类型。需要父 `MediaSource` 处于 "open" 状态，并会重置解析器状态。
   - `ChangeTypeUsingConfig`:  使用 `SourceBufferConfig` 对象来变更媒体类型，为 WebCodecs API 提供支持（目前为未实现状态）。
   - `ChangeType_Locked`: 执行变更媒体类型的核心逻辑，包括检查类型是否支持，更新生成时间戳标志等。

5. **设置轨道默认属性 (Set Track Defaults):**
   - `setTrackDefaults`: 允许用户设置轨道（audio 或 video）的默认属性，例如 label 和 language。

6. **处理从 MediaSource 移除 (Removed From MediaSource):**
   - `RemovedFromMediaSource`: 当 `SourceBuffer` 从其父 `MediaSource` 中移除时调用，负责清理资源，包括中止正在进行的操作，移除相关的媒体轨道。

7. **移除媒体轨道 (Remove Media Tracks):**
   - `RemoveMediaTracks`:  负责从 `SourceBuffer` 和关联的 `HTMLMediaElement` 中移除音频和视频轨道。

8. **获取媒体时间 (Get Media Time):**
   - `GetMediaTime`: 获取当前媒体的播放时间。

9. **查找现有轨道 (Find Existing Track By Id):**
   - `FindExistingTrackById`:  根据 ID 在轨道列表中查找现有轨道。

10. **获取轨道默认属性 (Get Track Default):**
    - `GetTrackDefault`:  根据轨道类型和 ByteStreamTrackID，从 `track_defaults_` 中查找并返回对应的 `TrackDefault` 对象。
    - `DefaultTrackLabel`:  获取指定轨道的默认标签。
    - `DefaultTrackLanguage`: 获取指定轨道的默认语言。

11. **添加占位符跨线程轨道 (Add Placeholder Cross Thread Tracks):**
    - `AddPlaceholderCrossThreadTracks`: 在跨线程场景下（例如 MSE-in-Worker），当接收到初始化片段时，为媒体元素添加占位符轨道。

**与 JavaScript, HTML, CSS 的关系：**

- **JavaScript:**  这些方法直接对应了 JavaScript 中 `SourceBuffer` 对象的 API。例如，JavaScript 调用 `sourceBuffer.append()` 最终会触发 C++ 中的 `AppendEncodedChunks_Locked` 或相关的 `appendBuffer` 方法。调用 `sourceBuffer.abort()` 会触发 `SourceBuffer::abort`。
- **HTML:**  `SourceBuffer` 与 HTML 的 `<video>` 或 `<audio>` 元素关联。当 `SourceBuffer` 添加或移除数据时，会影响到媒体元素的播放状态和可播放范围。移除轨道时，会更新 HTMLMediaElement 的 `audioTracks` 和 `videoTracks` 属性。
- **CSS:** 此代码本身不直接涉及 CSS。但通过 JavaScript 和 HTML 的交互，`SourceBuffer` 的操作可能会间接影响到媒体元素的呈现，而呈现样式由 CSS 控制。

**逻辑推理 (假设输入与输出):**

**假设输入 (AppendEncodedChunks_Locked):**
- `buffer_queue`: 包含编码媒体数据的队列。
- `size`: 数据大小。

**假设输出 (AppendEncodedChunks_Locked):**
- 如果准备附加成功，则启动异步附加任务。
- 如果准备附加失败（例如，超出配额），则 Promise 将被拒绝。

**假设输入 (remove):**
- `start`:  移除起始时间。
- `end`: 移除结束时间。

**假设输出 (remove):**
- 如果参数有效且状态允许，则启动异步移除任务，并触发 `updatestart` 事件。
- 如果参数无效或状态不允许，则抛出 `TypeError` 或 `InvalidStateError` 异常。

**用户或编程常见的使用错误:**

1. **在 `updating` 状态下调用 `appendBuffer`, `appendEncodedChunks`, `remove`, `abort`, `changeType`:**  `SourceBuffer` 在进行数据操作时会设置 `updating` 标志。如果在 `updating` 为 true 时再次调用这些方法，会导致抛出 `InvalidStateError` 异常。
   ```javascript
   sourceBuffer.append(data1);
   sourceBuffer.append(data2); // 错误：在 data1 附加完成前调用
   ```

2. **在 `readyState` 不是 "open" 的 `MediaSource` 上调用 `abort`, `remove`:** 只有当 `MediaSource` 处于 "open" 状态时，才能进行这些操作。
   ```javascript
   mediaSource.addEventListener('sourceopen', function() {
       sourceBuffer.remove(0, 10); // 正确
   });
   sourceBuffer.remove(0, 10); // 错误：在 sourceopen 事件触发前调用
   ```

3. **`remove` 方法的 `start` 和 `end` 参数不合法:** `end` 必须大于 `start`，`start` 不能为负，也不能大于 `duration`。
   ```javascript
   sourceBuffer.remove(10, 5); // 错误：end 小于 start
   sourceBuffer.remove(-1, 5); // 错误：start 为负
   ```

4. **`changeType` 方法传入不支持的 MIME 类型:** 浏览器或底层解码器不支持的类型会导致抛出 `NotSupportedError` 异常。
   ```javascript
   sourceBuffer.changeType('invalid/mime'); // 错误：类型不支持
   ```

**用户操作如何到达这里 (调试线索):**

1. 用户在网页上与一个使用了 Media Source Extensions (MSE) 的媒体播放器进行交互。
2. JavaScript 代码创建了一个 `MediaSource` 对象，并通过 `addSourceBuffer()` 方法添加了一个 `SourceBuffer` 对象。
3. **追加数据:**
   - 网站从服务器获取媒体数据片段。
   - JavaScript 调用 `sourceBuffer.append(data)` 或 `sourceBuffer.appendEncodedChunks(data)` 将数据传递给浏览器。
   - 这会触发 C++ 中的 `AppendEncodedChunks_Locked` 或相关的 `appendBuffer` 方法。
4. **移除数据:**
   - 网站逻辑决定需要移除某些已缓冲的数据（例如，为了节省内存）。
   - JavaScript 调用 `sourceBuffer.remove(startTime, endTime)`。
   - 这会触发 C++ 中的 `remove` 方法。
5. **中止操作:**
   - 由于网络问题或用户操作，网站需要停止当前的数据追加或移除操作。
   - JavaScript 调用 `sourceBuffer.abort()`。
   - 这会触发 C++ 中的 `abort` 方法。
6. **更改媒体类型:**
   - 网站可能需要在不重新加载播放器的情况下切换不同的编码格式或容器格式。
   - JavaScript 调用 `sourceBuffer.changeType(newMimeType)`。
   - 这会触发 C++ 中的 `changeType` 方法。
7. **离开页面或移除 SourceBuffer:**
   - 用户关闭标签页或导航到其他页面，或者 JavaScript 代码显式调用 `mediaSource.removeSourceBuffer(sourceBuffer)`.
   - 这会触发 C++ 中的 `RemovedFromMediaSource` 方法。

在调试 MSE 相关问题时，可以关注 JavaScript 中 `SourceBuffer` API 的调用，并在 C++ 代码中设置断点来跟踪这些操作的执行流程。

### 提示词
```
这是目录为blink/renderer/modules/mediasource/source_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
turn promise;
}

void SourceBuffer::AppendEncodedChunks_Locked(
    std::unique_ptr<media::StreamParser::BufferQueue> buffer_queue,
    size_t size,
    ExceptionState* exception_state,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  DVLOG(2) << __func__ << " this=" << this << ", size=" << size;

  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();
  DCHECK(append_encoded_chunks_resolver_);
  DCHECK(buffer_queue);
  DCHECK(!pending_chunks_to_buffer_);

  double media_time = GetMediaTime();
  if (!PrepareAppend(media_time, size, *exception_state)) {
    TRACE_EVENT_NESTABLE_ASYNC_END0(
        "media", "SourceBuffer::appendEncodedChunks", TRACE_ID_LOCAL(this));
    append_encoded_chunks_resolver_ = nullptr;
    return;
  }

  pending_chunks_to_buffer_ = std::move(buffer_queue);
  updating_ = true;

  // Note, this promisified API does not queue for dispatch events like
  // 'updatestart', 'update', 'error', 'abort', nor 'updateend' during the scope
  // of synchronous and asynchronous operation, because the promise's resolution
  // or rejection indicates the same information and lets us not wait until
  // those events are dispatched before resolving them. See verbose reasons in
  // AbortIfUpdating().

  // Asynchronously run the analogue of the buffer append algorithm.
  append_encoded_chunks_async_task_handle_ = PostCancellableTask(
      *GetExecutionContext()->GetTaskRunner(TaskType::kMediaElementEvent),
      FROM_HERE,
      WTF::BindOnce(&SourceBuffer::AppendEncodedChunksAsyncPart,
                    WrapPersistent(this)));

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("media", "delay", TRACE_ID_LOCAL(this),
                                    "type", "initialDelay");
}

void SourceBuffer::abort(ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this;
  // http://w3c.github.io/media-source/#widl-SourceBuffer-abort-void
  // 1. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source then throw an InvalidStateError exception and abort
  //    these steps.
  // 2. If the readyState attribute of the parent media source is not in the
  //    "open" state then throw an InvalidStateError exception and abort these
  //    steps.
  if (IsRemoved()) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "This SourceBuffer has been removed from the parent media source.");
    return;
  }
  if (!source_->IsOpen()) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "The parent media source's readyState is not 'open'.");
    return;
  }

  // 3. If the range removal algorithm is running, then throw an
  //    InvalidStateError exception and abort these steps.
  if (pending_remove_start_ != -1) {
    DCHECK(updating_);
    // Throwing the exception and aborting these steps is new behavior that
    // is implemented behind the MediaSourceNewAbortAndDuration
    // RuntimeEnabledFeature.
    if (RuntimeEnabledFeatures::MediaSourceNewAbortAndDurationEnabled()) {
      MediaSource::LogAndThrowDOMException(
          exception_state, DOMExceptionCode::kInvalidStateError,
          "Aborting asynchronous remove() operation is disallowed.");
      return;
    }

    Deprecation::CountDeprecation(GetExecutionContext(),
                                  WebFeature::kMediaSourceAbortRemove);
    CancelRemove();
  }

  // 4. If the sourceBuffer.updating attribute equals true, then run the
  //    following steps: ...
  AbortIfUpdating();

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must have |source_| and |source_| must have an attachment
  // because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&SourceBuffer::Abort_Locked, WrapPersistent(this)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
  }
}

void SourceBuffer::Abort_Locked(
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 5. Run the reset parser state algorithm.
  web_source_buffer_->ResetParserState();

  // 6. Set appendWindowStart to 0.
  // Note, there can be no exception, since appendWindowEnd can never be 0
  // (appendWindowStart can never be < 0, nor === appendWindowEnd in regular
  // setAppendWindow{Start,End} steps). Therefore, we can elide some checks and
  // reuse the existing internal helpers here that do not throw JS exception.
  SetAppendWindowStart_Locked(0, pass_key);

  // 7. Set appendWindowEnd to positive Infinity.
  // Note, likewise, no possible exception here, so reusing internal helper.
  SetAppendWindowEnd_Locked(std::numeric_limits<double>::infinity(), pass_key);
}

void SourceBuffer::remove(double start,
                          double end,
                          ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this << " start=" << start
           << " end=" << end;

  // Section 3.2 remove() method steps.
  // https://www.w3.org/TR/media-source/#widl-SourceBuffer-remove-void-double-start-unrestricted-double-end
  // 1. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source then throw an InvalidStateError exception and abort
  //    these steps.
  // 2. If the updating attribute equals true, then throw an InvalidStateError
  //    exception and abort these steps.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must have |source_| and |source_| must have an attachment
  // because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&SourceBuffer::Remove_Locked, WrapPersistent(this),
                        start, end, WTF::Unretained(&exception_state)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
  }
}

void SourceBuffer::Remove_Locked(
    double start,
    double end,
    ExceptionState* exception_state,
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 3. If duration equals NaN, then throw a TypeError exception and abort these
  //    steps.
  // 4. If start is negative or greater than duration, then throw a TypeError
  //    exception and abort these steps.
  double duration = source_->GetDuration_Locked(pass_key);
  if (start < 0 || std::isnan(duration) || start > duration) {
    MediaSource::LogAndThrowTypeError(
        *exception_state,
        ExceptionMessages::IndexOutsideRange(
            "start", start, 0.0, ExceptionMessages::kExclusiveBound,
            std::isnan(duration) ? 0 : duration,
            ExceptionMessages::kExclusiveBound));
    return;
  }

  // 5. If end is less than or equal to start or end equals NaN, then throw a
  //    TypeError exception and abort these steps.
  if (end <= start || std::isnan(end)) {
    MediaSource::LogAndThrowTypeError(
        *exception_state,
        "The end value provided (" + String::Number(end) +
            ") must be greater than the start value provided (" +
            String::Number(start) + ").");
    return;
  }

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("media", "SourceBuffer::remove",
                                    TRACE_ID_LOCAL(this));

  // 6. If the readyState attribute of the parent media source is in the "ended"
  //    state then run the following steps:
  // 6.1. Set the readyState attribute of the parent media source to "open"
  // 6.2. Queue a task to fire a simple event named sourceopen at the parent
  //      media source .
  source_->OpenIfInEndedState();

  // 7. Run the range removal algorithm with start and end as the start and end
  //    of the removal range.
  // 7.3. Set the updating attribute to true.
  updating_ = true;

  // 7.4. Queue a task to fire a simple event named updatestart at this
  //      SourceBuffer object.
  ScheduleEvent(event_type_names::kUpdatestart);

  // 7.5. Return control to the caller and run the rest of the steps
  //      asynchronously.
  pending_remove_start_ = start;
  pending_remove_end_ = end;
  remove_async_task_handle_ = PostCancellableTask(
      *GetExecutionContext()->GetTaskRunner(TaskType::kMediaElementEvent),
      FROM_HERE,
      WTF::BindOnce(&SourceBuffer::RemoveAsyncPart, WrapPersistent(this)));
}

void SourceBuffer::changeType(const String& type,
                              ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this << " type=" << type;

  // Per 30 May 2018 Codec Switching feature incubation spec:
  // https://rawgit.com/WICG/media-source/3b3742ea788999bb7ae4a4553ac7d574b0547dbe/index.html#dom-sourcebuffer-changetype
  // 1. If type is an empty string then throw a TypeError exception and abort
  //    these steps.
  if (type.empty()) {
    MediaSource::LogAndThrowTypeError(exception_state,
                                      "The type provided is empty");
    return;
  }

  // 2. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source, then throw an InvalidStateError exception and abort
  //    these steps.
  // 3. If the updating attribute equals true, then throw an InvalidStateError
  //    exception and abort these steps.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must have |source_| and |source_| must have an attachment
  // because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&SourceBuffer::ChangeType_Locked, WrapPersistent(this),
                        type, WTF::Unretained(&exception_state)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
  }
}

void SourceBuffer::ChangeTypeUsingConfig(ExecutionContext* execution_context,
                                         const SourceBufferConfig* config,
                                         ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this;

  UseCounter::Count(execution_context,
                    WebFeature::kMediaSourceExtensionsForWebCodecs);

  // If this object has been removed from the sourceBuffers attribute of the
  //    parent media source, then throw an InvalidStateError exception and abort
  //    these steps.
  // If the updating attribute equals true, then throw an InvalidStateError
  //    exception and abort these steps.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // Before this IDL overload was added, changeType(null) yielded a
  // kNotSupportedError, so preserve that behavior if the bindings resolve us
  // instead of the original changeType(DOMString) when given a null parameter.
  // Fortunately, a null or empty SourceBufferConfig here similarly should yield
  // a kNotSupportedError.
  if (!config || (!config->hasAudioConfig() && !config->hasVideoConfig())) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotSupportedError,
        "Changing to the type provided ('null' config) is not supported.");
    return;
  }

  // TODO(crbug.com/1144908): Further validate allowed in current state (and
  // take lock at appropriate point), unwrap the config, validate it, update
  // internals to new config, etc.
  exception_state.ThrowTypeError(
      "unimplemented - see https://crbug.com/1144908");
}

void SourceBuffer::ChangeType_Locked(
    const String& type,
    ExceptionState* exception_state,
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 4. If type contains a MIME type that is not supported or contains a MIME
  //    type that is not supported with the types specified (currently or
  //    previously) of SourceBuffer objects in the sourceBuffers attribute of
  //    the parent media source, then throw a NotSupportedError exception and
  //    abort these steps.
  ContentType content_type(type);
  String codecs = content_type.Parameter("codecs");
  // TODO(wolenetz): Refactor and use a less-strict version of isTypeSupported
  // here. As part of that, CanChangeType in Chromium should inherit relaxation
  // of impl's StreamParserFactory (since it returns true iff a stream parser
  // can be constructed with |type|). See https://crbug.com/535738.
  if (!MediaSource::IsTypeSupportedInternal(
          GetExecutionContext(), type,
          false /* allow underspecified codecs in |type| */) ||
      !web_source_buffer_->CanChangeType(content_type.GetType(), codecs)) {
    MediaSource::LogAndThrowDOMException(
        *exception_state, DOMExceptionCode::kNotSupportedError,
        "Changing to the type provided ('" + type + "') is not supported.");
    return;
  }

  // 5. If the readyState attribute of the parent media source is in the "ended"
  //    state then run the following steps:
  //    1. Set the readyState attribute of the parent media source to "open"
  //    2. Queue a task to fire a simple event named sourceopen at the parent
  //       media source.
  source_->OpenIfInEndedState();

  // 6. Run the reset parser state algorithm.
  web_source_buffer_->ResetParserState();

  // 7. Update the generate timestamps flag on this SourceBuffer object to the
  //    value in the "Generate Timestamps Flag" column of the byte stream format
  //    registry entry that is associated with type.
  // This call also updates the pipeline to switch bytestream parser and codecs.
  web_source_buffer_->ChangeType(content_type.GetType(), codecs);

  // 8. If the generate timestamps flag equals true: Set the mode attribute on
  //    this SourceBuffer object to "sequence", including running the associated
  //    steps for that attribute being set. Otherwise: keep the previous value
  //    of the mode attribute on this SourceBuffer object, without running any
  //    associated steps for that attribute being set.
  if (web_source_buffer_->GetGenerateTimestampsFlag())
    SetMode_Locked(V8AppendMode::Enum::kSequence, exception_state, pass_key);

  // 9. Set pending initialization segment for changeType flag to true.
  // The logic for this flag is handled by the pipeline (the new bytestream
  // parser will expect an initialization segment first).
}

void SourceBuffer::setTrackDefaults(TrackDefaultList* track_defaults,
                                    ExceptionState& exception_state) {
  // Per 02 Dec 2014 Editor's Draft
  // http://w3c.github.io/media-source/#widl-SourceBuffer-trackDefaults
  // 1. If this object has been removed from the sourceBuffers attribute of
  //    the parent media source, then throw an InvalidStateError exception
  //    and abort these steps.
  // 2. If the updating attribute equals true, then throw an InvalidStateError
  //    exception and abort these steps.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // 3. Update the attribute to the new value.
  track_defaults_ = track_defaults;
}

void SourceBuffer::CancelRemove() {
  DCHECK(updating_);
  DCHECK_NE(pending_remove_start_, -1);
  remove_async_task_handle_.Cancel();
  pending_remove_start_ = -1;
  pending_remove_end_ = -1;
  updating_ = false;

  if (!RuntimeEnabledFeatures::MediaSourceNewAbortAndDurationEnabled()) {
    ScheduleEvent(event_type_names::kAbort);
    ScheduleEvent(event_type_names::kUpdateend);
  }

  TRACE_EVENT_NESTABLE_ASYNC_END0("media", "SourceBuffer::remove",
                                  TRACE_ID_LOCAL(this));
}

void SourceBuffer::AbortIfUpdating() {
  // Section 3.2 abort() method step 4 substeps.
  // http://w3c.github.io/media-source/#widl-SourceBuffer-abort-void

  if (!updating_)
    return;

  DCHECK_EQ(pending_remove_start_, -1);

  // 4.1. Abort the buffer append and stream append loop algorithms if they are
  //      running.
  // 4.2. Set the updating attribute to false.
  updating_ = false;

  if (pending_chunks_to_buffer_) {
    append_encoded_chunks_async_task_handle_.Cancel();
    pending_chunks_to_buffer_.reset();

    // For async Promise resolution/rejection, we do not use events to notify
    // the app, since event dispatch could occur after the promise callback
    // microtask dispatch and violate the design principle, "Events should fire
    // before Promises resolve", unless we introduced unnecessary further
    // latency to enqueue a task to resolve/reject the promise. In this case,
    // the elision of the "abort" and "updateend" events is synonymous with
    // rejection with an AbortError DOMException, enabling faster abort
    // notification. See
    // https://w3ctag.github.io/design-principles/#promises-and-events
    // TODO(crbug.com/1144908): Consider moving this verbosity to eventual
    // specification.
    DCHECK(append_encoded_chunks_resolver_);
    append_encoded_chunks_resolver_->Reject(V8ThrowDOMException::CreateOrDie(
        append_encoded_chunks_resolver_->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kAbortError, "Aborted by explicit abort()"));
    append_encoded_chunks_resolver_ = nullptr;
    TRACE_EVENT_NESTABLE_ASYNC_END0(
        "media", "SourceBuffer::appendEncodedChunks", TRACE_ID_LOCAL(this));
    return;
  }

  DCHECK(!append_encoded_chunks_resolver_);
  append_buffer_async_task_handle_.Cancel();

  // For the regular, non-promisified appendBuffer abort, use events to notify
  // result.
  // 4.3. Queue a task to fire a simple event named abort at this SourceBuffer
  //      object.
  ScheduleEvent(event_type_names::kAbort);

  // 4.4. Queue a task to fire a simple event named updateend at this
  //      SourceBuffer object.
  ScheduleEvent(event_type_names::kUpdateend);

  TRACE_EVENT_NESTABLE_ASYNC_END0("media", "SourceBuffer::appendBuffer",
                                  TRACE_ID_LOCAL(this));
}

void SourceBuffer::RemovedFromMediaSource() {
  if (IsRemoved())
    return;

  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  DVLOG(3) << __func__ << " this=" << this;
  if (pending_remove_start_ != -1) {
    CancelRemove();
  } else {
    AbortIfUpdating();
  }

  DCHECK(source_);
  RemoveMediaTracks();

  // Update the underlying demuxer except in the cross-thread attachment case
  // where detachment or element context destruction may have already begun.
  scoped_refptr<MediaSourceAttachmentSupplement> attachment;
  std::tie(attachment, std::ignore) = source_->AttachmentAndTracer();
  DCHECK(attachment);
  if (attachment->FullyAttachedOrSameThread(
          MediaSourceAttachmentSupplement::SourceBufferPassKey())) {
    web_source_buffer_->RemovedFromMediaSource();
  }

  web_source_buffer_.reset();
  source_ = nullptr;
  async_event_queue_ = nullptr;
}

double SourceBuffer::HighestPresentationTimestamp() {
  DCHECK(!IsRemoved());
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  double pts = web_source_buffer_->HighestPresentationTimestamp();
  DVLOG(3) << __func__ << " this=" << this << ", pts=" << pts;
  return pts;
}

void SourceBuffer::RemoveMediaTracks() {
  // Spec:
  // http://w3c.github.io/media-source/#widl-MediaSource-removeSourceBuffer-void-SourceBuffer-sourceBuffer
  DCHECK(source_);

  auto [attachment, tracer] = source_->AttachmentAndTracer();
  DCHECK(attachment);

  // One path leading to here is from |source_|'s ContextDestroyed(), so we
  // cannot consult GetExecutionContext() here to determine if this is a
  // worker-thread-owned or main-thread-owned SourceBuffer. Rather, we will rely
  // on IsMainThread().
  if (!IsMainThread()) {
    RemovePlaceholderCrossThreadTracks(attachment, tracer);
    return;
  }

  // For safety, ensure we are using SameThreadAttachment behavior. This is just
  // in case we somehow are incorrectly running on the main thread, but are a
  // worker-thread-owned SourceBuffer with a cross-thread attachment.
  CHECK(tracer);  // Only same-thread attachments have a tracer.

  // 3. Let SourceBuffer audioTracks list equal the AudioTrackList object
  //    returned by sourceBuffer.audioTracks.
  // 4. If the SourceBuffer audioTracks list is not empty, then run the
  //    following steps:
  // 4.1 Let HTMLMediaElement audioTracks list equal the AudioTrackList object
  //     returned by the audioTracks attribute on the HTMLMediaElement.
  // 4.2 Let the removed enabled audio track flag equal false.
  bool removed_enabled_audio_track = false;
  Vector<String> audio_track_removal_ids;
  // 4.3 For each AudioTrack object in the SourceBuffer audioTracks list, run
  //     the following steps:
  while (audioTracks().length() > 0) {
    AudioTrack* audio_track = audioTracks().AnonymousIndexedGetter(0);
    // 4.3.1 Set the sourceBuffer attribute on the AudioTrack object to null.
    SourceBufferTrackBaseSupplement::SetSourceBuffer(*audio_track, nullptr);
    // 4.3.2 If the enabled attribute on the AudioTrack object is true, then set
    //       the removed enabled audio track flag to true.
    if (audio_track->enabled())
      removed_enabled_audio_track = true;
    // 4.3.3 Remove the AudioTrack object from the HTMLMediaElement audioTracks
    //       list.
    // 4.3.4 Queue a task to fire a trusted event named removetrack, that does
    //       not bubble and is not cancelable, and that uses the TrackEvent
    //       interface, at the HTMLMediaElement audioTracks list.
    // We compile the list of audio tracks to remove from the media element here
    // and tell the element to remove them, below, with step 4.4.
    audio_track_removal_ids.push_back(audio_track->id());
    // 4.3.5 Remove the AudioTrack object from the SourceBuffer audioTracks
    //       list.
    // 4.3.6 Queue a task to fire a trusted event named removetrack, that does
    //       not bubble and is not cancelable, and that uses the TrackEvent
    //       interface, at the SourceBuffer audioTracks list.
    audioTracks().Remove(audio_track->id());
  }
  // 4.4 If the removed enabled audio track flag equals true, then queue a task
  //     to fire a simple event named change at the HTMLMediaElement audioTracks
  //     list.
  // Here, we perform batch removal of audio tracks, compiled in step 4.3.4,
  // above, along with conditional enqueueing of change event.
  if (!audio_track_removal_ids.empty()) {
    attachment->RemoveAudioTracksFromMediaElement(
        tracer, std::move(audio_track_removal_ids),
        removed_enabled_audio_track /* enqueue_change_event */);
  }

  // 5. Let SourceBuffer videoTracks list equal the VideoTrackList object
  //    returned by sourceBuffer.videoTracks.
  // 6. If the SourceBuffer videoTracks list is not empty, then run the
  //    following steps:
  // 6.1 Let HTMLMediaElement videoTracks list equal the VideoTrackList object
  //     returned by the videoTracks attribute on the HTMLMediaElement.
  // 6.2 Let the removed selected video track flag equal false.
  bool removed_selected_video_track = false;
  Vector<String> video_track_removal_ids;
  // 6.3 For each VideoTrack object in the SourceBuffer videoTracks list, run
  //     the following steps:
  while (videoTracks().length() > 0) {
    VideoTrack* video_track = videoTracks().AnonymousIndexedGetter(0);
    // 6.3.1 Set the sourceBuffer attribute on the VideoTrack object to null.
    SourceBufferTrackBaseSupplement::SetSourceBuffer(*video_track, nullptr);
    // 6.3.2 If the selected attribute on the VideoTrack object is true, then
    //       set the removed selected video track flag to true.
    if (video_track->selected())
      removed_selected_video_track = true;
    // 6.3.3 Remove the VideoTrack object from the HTMLMediaElement videoTracks
    //       list.
    // 6.3.4 Queue a task to fire a trusted event named removetrack, that does
    //       not bubble and is not cancelable, and that uses the TrackEvent
    //       interface, at the HTMLMediaElement videoTracks list.
    // We compile the list of video tracks to remove from the media element here
    // and tell the element to remove them, below, with step 6.4.
    video_track_removal_ids.push_back(video_track->id());
    // 6.3.5 Remove the VideoTrack object from the SourceBuffer videoTracks
    //       list.
    // 6.3.6 Queue a task to fire a trusted event named removetrack, that does
    //       not bubble and is not cancelable, and that uses the TrackEvent
    //       interface, at the SourceBuffer videoTracks list.
    videoTracks().Remove(video_track->id());
  }
  // 6.4 If the removed selected video track flag equals true, then queue a task
  //     to fire a simple event named change at the HTMLMediaElement videoTracks
  //     list.
  // Here, we perform batch removal of video tracks, compiled in step 6.3.4,
  // above, along with conditional enqueueing of change event.
  if (!video_track_removal_ids.empty()) {
    attachment->RemoveVideoTracksFromMediaElement(
        tracer, std::move(video_track_removal_ids),
        removed_selected_video_track /* enqueue_change_event */);
  }

  // 7-8. TODO(servolk): Remove text tracks once SourceBuffer has text tracks.
}

double SourceBuffer::GetMediaTime() {
  DCHECK(source_);
  auto [attachment, tracer] = source_->AttachmentAndTracer();
  DCHECK(attachment);
  return attachment->GetRecentMediaTime(tracer).InSecondsF();
}

template <class T>
T* FindExistingTrackById(const TrackListBase<T>& track_list, const String& id) {
  // According to MSE specification
  // (https://w3c.github.io/media-source/#sourcebuffer-init-segment-received)
  // step 3.1:
  // > If more than one track for a single type are present (ie 2 audio tracks),
  // then the Track IDs match the ones in the first initialization segment.
  // I.e. we only need to search by TrackID if there is more than one track,
  // otherwise we can assume that the only track of the given type is the same
  // one that we had in previous init segments.
  if (track_list.length() == 1)
    return track_list.AnonymousIndexedGetter(0);
  return track_list.getTrackById(id);
}

const TrackDefault* SourceBuffer::GetTrackDefault(
    const AtomicString& track_type,
    const AtomicString& byte_stream_track_id) const {
  // This is a helper for implementation of default track label and default
  // track language algorithms.
  // defaultTrackLabel spec:
  // https://w3c.github.io/media-source/#sourcebuffer-default-track-label
  // defaultTrackLanguage spec:
  // https://w3c.github.io/media-source/#sourcebuffer-default-track-language

  // 1. If trackDefaults contains a TrackDefault object with a type attribute
  //    equal to type and a byteStreamTrackID attribute equal to
  //    byteStreamTrackID, then return the value of the label/language attribute
  //    on this matching object and abort these steps.
  // 2. If trackDefaults contains a TrackDefault object with a type attribute
  //    equal to type and a byteStreamTrackID attribute equal to an empty
  //    string, then return the value of the label/language attribute on this
  //    matching object and abort these steps.
  // 3. Return an empty string to the caller
  const TrackDefault* track_default_with_empty_bytestream_id = nullptr;
  for (unsigned i = 0; i < track_defaults_->length(); ++i) {
    const TrackDefault* track_default = track_defaults_->item(i);
    if (track_default->type() != track_type)
      continue;
    if (track_default->byteStreamTrackID() == byte_stream_track_id)
      return track_default;
    if (!track_default_with_empty_bytestream_id &&
        track_default->byteStreamTrackID() == "")
      track_default_with_empty_bytestream_id = track_default;
  }
  return track_default_with_empty_bytestream_id;
}

AtomicString SourceBuffer::DefaultTrackLabel(
    const AtomicString& track_type,
    const AtomicString& byte_stream_track_id) const {
  // Spec: https://w3c.github.io/media-source/#sourcebuffer-default-track-label
  const TrackDefault* track_default =
      GetTrackDefault(track_type, byte_stream_track_id);
  return track_default ? AtomicString(track_default->label()) : g_empty_atom;
}

AtomicString SourceBuffer::DefaultTrackLanguage(
    const AtomicString& track_type,
    const AtomicString& byte_stream_track_id) const {
  // Spec:
  // https://w3c.github.io/media-source/#sourcebuffer-default-track-language
  const TrackDefault* track_default =
      GetTrackDefault(track_type, byte_stream_track_id);
  return track_default ? AtomicString(track_default->language()) : g_empty_atom;
}

void SourceBuffer::AddPlaceholderCrossThreadTracks(
    const WebVector<MediaTrackInfo>& new_tracks,
    scoped_refptr<MediaSourceAttachmentSupplement> attachment) {
  // TODO(https://crbug.com/878133): Complete the MSE-in-Workers function
  // necessary to enable successful experimental usage of AudioVideoTracks
  // feature when MSE is in worker. Meanwhile, at least notify the attachment
  // to tell the media element to populate appropriately identified tracks so
  // that the BackgroundVideoOptimization feature functions for MSE-in-Workers
  // playbacks.
  DCHECK(!IsMainThread());
  DCHECK(!first_initialization_segment_received_);
  DCHECK(source_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // Perform placeholder track additions on the main thread for each audio
  // and video track in the initialization segment. Note that this depends
  // on the caller already verifying correctness of the track metadata (see
  // SourceBufferState::OnNewConfigs()).
  bool enable_next_audio_track = true;
  bool select_next_video_track = true;
  DCHECK(audio_track_ids_for_crossthread_removal_.empty());
  DCHECK(video_track_ids_for_crossthread_removal_.empty());
  for (const MediaTrackInfo& track_info : new_tracks) {
    if (track_info.track_type == WebMediaPlayer::kAudioTrack) {
      WebString label = track_info.label;
      if (label.IsEmpty()) {
        label = DefaultTrackLabel(TrackDefault::AudioKeyword(),
                                  track_info.byte_stream_track_id);
      }

      WebString language = track_info.language;
      if (language.IsEmpty()) {
        language = DefaultTrackLanguage(TrackDefault::AudioKeyword(),
                                        track_info.byte_stream_track_id);
      }

      attachment->AddMainThreadAudioTrackToMediaElement(
          track_info.id, track_info.kind, std::move(label), std::move(language),
          enable_next_audio_track);

      // Only enable the first audio track for this SourceBuffer.
      enable_next_audio_track = false;

      // Remember to remove this track from the element later.
      audio_track_ids_for_crossthread_removal_.push_back(track_info.id);
    } else if (track_info.track_type == WebMediaPlayer::kVideoTrack) {
      WebString label = track_info.label;
      if (label.IsEmpty()) {
        label = DefaultTrackLabel(TrackDefault::VideoKeyword(),
                                  track_info.byte_stream_track_id);
      }

      WebString language = track_info.language;
      if (language.IsEmpty()) {
        language = DefaultTrackLanguage(TrackDefault::VideoKeyword(),
                                        track_info.byte_stream_track_id);
      }
      attachment->AddMainThreadVideoTrackToMediaElement(
          track_info.id, track_info.kind, std::
```