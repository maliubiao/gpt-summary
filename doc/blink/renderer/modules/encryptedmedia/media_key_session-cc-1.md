Response:
The user wants a summary of the functionality of the provided C++ code snippet from `media_key_session.cc`. This is the second part of a two-part request. I need to:

1. **Summarize the functions:** Describe what each function in the provided code does.
2. **Relate to web technologies:** Explain how these functions connect to JavaScript, HTML, and CSS, providing examples.
3. **Provide logical reasoning examples:** Give examples of function inputs and expected outputs.
4. **Illustrate common user/programming errors:** Show typical mistakes when using this functionality.
5. **Explain user interaction flow:** Describe how user actions in a web browser can lead to this code being executed.
6. **Focus on the functions within the provided snippet:** Since this is part 2, I need to summarize the functions presented in *this* specific snippet, not the entire file.
这是 `blink/renderer/modules/encryptedmedia/media_key_session.cc` 文件的第二部分，主要包含了 `MediaKeySession` 类中与会话关闭 (`close`)、移除 (`remove`)、处理异步任务 (`ActionTimerFired`) 以及处理来自内容解密模块 (CDM) 的事件相关的代码。

**功能归纳:**

这部分代码主要负责管理加密媒体会话的生命周期，处理会话的关闭和移除操作，以及响应来自 CDM 的事件，并将这些事件转化为 JavaScript 可以处理的事件。它维护了会话的状态，并确保异步操作的正确执行。

**具体功能列举:**

* **`close(ScriptState* script_state, ExceptionState& exception_state)`:**
    * Initiates the process of closing the media key session.
    * 检查会话是否已经正在关闭或已关闭，如果是，则返回一个已解决的 Promise。
    * 检查会话是否可调用，如果不可调用，则返回一个被拒绝的 Promise。
    * 创建一个新的 Promise，并在内部启动异步关闭任务。
    * 将会话标记为正在关闭 (`is_closing_ = true`)。
    * 将关闭操作添加到待处理操作队列中，并通过定时器触发异步执行。
    * 返回代表关闭操作的 Promise。

* **`CloseTask(ContentDecryptionModuleResult* result)`:**
    * 实际执行与 CDM 交互的关闭会话操作。
    * 调用 CDM 的 `Close` 方法。
    * 当 CDM 的操作完成时，之前创建的 Promise 将会被解决。

* **`OnClosePromiseResolved()`:**
    * 在关闭 Promise 被解决后执行，用于停止 CDM 为此会话触发更多事件，并调用 `Dispose()` 清理资源。

* **`remove(ScriptState* script_state, ExceptionState& exception_state)`:**
    * 启动移除与会话关联的存储数据的过程。
    * 检查会话是否正在关闭或已关闭，如果是，则返回一个被拒绝的 Promise。
    * 检查会话是否可调用，如果不可调用，则返回一个被拒绝的 Promise。
    * 创建一个新的 Promise，并在内部启动异步移除任务。
    * 将移除操作添加到待处理操作队列中，并通过定时器触发异步执行。
    * 返回代表移除操作的 Promise。

* **`RemoveTask(ContentDecryptionModuleResult* result)`:**
    * 实际执行与 CDM 交互的移除会话数据的操作。
    * 调用 CDM 的 `Remove` 方法。
    * 当 CDM 的操作完成时，之前创建的 Promise 将会被解决。

* **`ActionTimerFired(TimerBase*)`:**
    * 定时器触发时执行，用于处理待处理的操作队列。
    * 从队列中取出待处理的操作，并根据操作类型调用相应的处理函数 (`GenerateRequestTask`, `LoadTask`, `UpdateTask`, `CloseTask`, `RemoveTask`)。

* **`OnSessionMessage(media::CdmMessageType message_type, const unsigned char* message, size_t message_length)`:**
    * 当 CDM 发送消息时被调用。
    * 创建一个 `MediaKeyMessageEvent`，包含消息类型和消息内容。
    * 将该事件添加到异步事件队列中，以便稍后发送给 JavaScript。

* **`OnSessionClosed(media::CdmSessionClosedReason reason)`:**
    * 当 CDM 关闭会话时被调用（可能是由于 `close()` 调用，也可能是 CDM 自身的原因）。
    * 检查 `closed_promise_` 是否已解决，如果已解决则不执行后续操作。
    * 将会话标记为已关闭 (`is_closed_ = true`)。
    * 调用 `OnSessionKeysChange` 和 `OnSessionExpirationUpdate` 更新密钥状态和过期时间。
    * 解决 `closed_promise_`，将关闭原因传递给 JavaScript。
    * 取消所有待处理的非关闭操作，并返回错误。
    * 如果不是因为 `close()` 调用而关闭，则立即调用 `Dispose()` 清理资源。

* **`OnSessionExpirationUpdate(double updated_expiry_time_in_ms)`:**
    * 当 CDM 更新会话过期时间时被调用。
    * 将新的过期时间（毫秒级时间戳）存储到 `expiration_` 属性中。

* **`OnSessionKeysChange(const WebVector<WebEncryptedMediaKeyInformation>& keys, bool has_additional_usable_key)`:**
    * 当 CDM 的密钥状态发生变化时被调用。
    * 清空当前的密钥状态映射 (`key_statuses_map_`)。
    * 遍历新的密钥信息，更新 `key_statuses_map_`。
    * 创建一个 `keystatuseschange` 事件，并添加到异步事件队列中。
    * 触发尝试恢复播放的逻辑（当前代码中为 FIXME）。

* **`InterfaceName()`:** 返回接口名称 `"MediaKeySession"`。

* **`GetExecutionContext()`:** 获取执行上下文。

* **`HasPendingActivity()`:** 检查是否存在待处理的活动，用于判断对象是否应该保持存活。

* **`ContextDestroyed()`:** 当执行上下文被销毁时调用，用于清理资源。

* **`Trace(Visitor* visitor)`:** 用于 Blink 的垃圾回收机制，标记需要追踪的对象。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    * `close()` 和 `remove()` 方法对应 JavaScript 中 `MediaKeySession` 对象的同名方法。当 JavaScript 调用这些方法时，会触发 C++ 端的对应函数执行。
    * `OnSessionMessage` 方法会创建一个 `MediaKeyMessageEvent`，这个事件会被分发到 JavaScript 中，供开发者监听和处理，例如，接收许可证请求信息。
    * `OnSessionClosed` 方法会解决一个 Promise，并将关闭原因传递给 JavaScript。可以通过监听 `MediaKeySession` 对象的 `closed` 属性获取这个 Promise。
    * `OnSessionKeysChange` 方法会创建一个 `keystatuseschange` 事件，这个事件会被分发到 JavaScript 中，开发者可以监听此事件来获取密钥状态的更新。
    * `OnSessionExpirationUpdate` 方法更新的 `expiration_` 属性的值可以在 JavaScript 中通过 `MediaKeySession` 对象的 `expiration` 属性访问。

    **举例:**

    ```javascript
    navigator.requestMediaKeySystemAccess('com.example.drm', [{
        initDataTypes: ['cenc'],
        videoCapabilities: [{
            contentType: 'video/mp4; codecs="avc1.42E01E"'
        }],
        audioCapabilities: [{
            contentType: 'audio/mp4; codecs="mp4a.40.2"'
        }]
    }]).then(function(keySystemAccess) {
        return keySystemAccess.createMediaKeys();
    }).then(function(mediaKeys) {
        videoElement.mediaKeys = mediaKeys;
        return mediaKeys.createSession('temporary');
    }).then(function(mediaKeySession) {
        mediaKeySession.addEventListener('message', function(event) {
            console.log('收到消息:', event.messageType, event.message);
            // 将消息发送到许可证服务器
        });

        mediaKeySession.addEventListener('keystatuseschange', function(event) {
            console.log('密钥状态改变:', mediaKeySession.keyStatuses);
            // 根据密钥状态更新采取相应的行动
        });

        mediaKeySession.closed.then(function(reason) {
            console.log('会话已关闭，原因:', reason);
        });

        // ... 初始化数据生成等操作 ...

        // 关闭会话
        mediaKeySession.close().then(function() {
            console.log('会话关闭成功');
        });

        // 移除会话数据
        mediaKeySession.remove().then(function() {
            console.log('会话数据移除成功');
        });
    });
    ```

* **HTML:**  这段 C++ 代码本身不直接操作 HTML 元素，但它处理的媒体会话是与 HTML 中的 `<video>` 或 `<audio>` 元素关联的。通过 JavaScript 将 `MediaKeys` 对象赋值给媒体元素的 `mediaKeys` 属性，从而建立连接。

* **CSS:**  这段 C++ 代码与 CSS 没有直接关系。

**逻辑推理举例:**

**假设输入 (close):**

* JavaScript 调用 `mediaKeySession.close()`。
* `is_closing_` 和 `is_closed_` 都为 `false`。
* `is_callable_` 为 `true`。

**预期输出 (close):**

* 创建一个新的 Promise 对象，该 Promise 尚未解决。
* `is_closing_` 被设置为 `true`。
* 一个表示关闭操作的 `PendingAction` 被添加到 `pending_actions_` 队列中。
* `action_timer_` 被启动（如果尚未激活）。
* 返回创建的 Promise 对象。

**假设输入 (OnSessionMessage):**

* CDM 发送一个类型为 `LICENSE_REQUEST` 的消息，消息内容为 `[0x01, 0x02, 0x03]`。

**预期输出 (OnSessionMessage):**

* 创建一个 `MediaKeyMessageEvent` 对象。
* `event.messageType` 的值为 `"license-request"`。
* `event.message` 是一个包含 `[0x01, 0x02, 0x03]` 的 `DOMArrayBuffer`。
* 该事件被添加到 `async_event_queue_` 中，等待发送到 JavaScript。

**用户或编程常见的使用错误举例:**

* **在会话关闭后调用 `close()` 或 `remove()`:** 用户或开发者可能会尝试在会话已经关闭或正在关闭时再次调用 `close()` 或 `remove()` 方法。代码会检查 `is_closing_` 和 `is_closed_` 标志，并返回一个已解决或已拒绝的 Promise，避免重复操作或引发错误。
* **在会话不可调用时调用 `close()` 或 `remove()`:** 如果 `is_callable_` 为 `false`，表示会话尚未初始化完成或已失效，此时调用 `close()` 或 `remove()` 会返回一个被 `InvalidStateError` 拒绝的 Promise。这通常发生在会话创建失败或过早操作会话的情况下。
* **未监听 `message` 事件:**  开发者可能忘记监听 `message` 事件，导致无法接收来自 CDM 的重要信息，例如许可证请求，从而导致播放失败。
* **未处理 `keystatuseschange` 事件:**  开发者可能忽略密钥状态的改变，导致在密钥过期或失效时无法采取相应的更新措施，从而中断播放。

**用户操作到达此处的步骤 (调试线索):**

1. **用户访问包含加密媒体内容的网页:** 用户打开一个需要数字版权管理 (DRM) 保护的视频或音频的网页。
2. **网页 JavaScript 发起密钥系统访问请求:** 网页中的 JavaScript 代码使用 `navigator.requestMediaKeySystemAccess()` 方法请求支持特定的 DRM 系统。
3. **创建 MediaKeys 对象和 MediaKeySession 对象:** 如果密钥系统访问成功，JavaScript 代码会创建 `MediaKeys` 对象，并调用其 `createSession()` 方法创建一个 `MediaKeySession` 对象。
4. **JavaScript 调用 `mediaKeySession.close()` 或 `mediaKeySession.remove()`:**  在用户完成观看或出于其他原因，网页 JavaScript 代码可能会调用 `mediaKeySession.close()` 来释放资源，或者调用 `mediaKeySession.remove()` 来清除与会话相关的持久化数据。
5. **CDM 发送消息:** 在媒体播放过程中，或者在会话生命周期的任何阶段，CDM 可能会因为各种原因（例如，需要请求许可证、许可证续订等）发送消息。这些消息会触发 `OnSessionMessage` 函数。
6. **CDM 关闭会话:** CDM 可能由于 `close()` 调用、许可证失效、或自身错误而关闭会话，这会触发 `OnSessionClosed` 函数。
7. **CDM 更新密钥状态或过期时间:** CDM 可能会更新密钥的状态或会话的过期时间，分别触发 `OnSessionKeysChange` 和 `OnSessionExpirationUpdate` 函数。

通过查看浏览器开发者工具中的 Network 面板（检查许可证请求等）、Console 面板（查看 JavaScript 日志和错误）、以及 Media 面板（查看 EME 相关信息），可以帮助开发者追踪用户操作并定位到相关代码的执行。 设置断点在 `MediaKeySession` 的相关方法中可以进行更深入的调试。

### 提示词
```
这是目录为blink/renderer/modules/encryptedmedia/media_key_session.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ySession::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // From https://w3c.github.io/encrypted-media/#close:
  // Indicates that the application no longer needs the session and the CDM
  // should release any resources associated with the session and close it.
  // Persisted data should not be released or cleared.
  // When this method is invoked, the user agent must run the following steps:

  // 1. If this object's closing or closed value is true, return a resolved
  //    promise.
  if (is_closing_ || is_closed_)
    return ToResolvedUndefinedPromise(script_state);

  // 2. If this object's callable value is false, return a promise rejected
  //    with an InvalidStateError.
  if (!is_callable_)
    return CreateRejectedPromiseNotCallable(exception_state);

  // 3. Let promise be a new promise.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  CloseSessionResultPromise* result =
      MakeGarbageCollected<CloseSessionResultPromise>(resolver, config_, this);

  // 4. Set this object's closing or closed value to true.
  is_closing_ = true;

  // 5. Run the following steps in parallel (done in closeTask()).
  pending_actions_.push_back(PendingAction::CreatePendingClose(result));
  if (!action_timer_.IsActive())
    action_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  // 6. Return promise.
  return promise;
}

void MediaKeySession::CloseTask(ContentDecryptionModuleResult* result) {
  // NOTE: Continue step 4 of MediaKeySession::close().
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // close() in Chromium will execute steps 5.1 through 5.3.
  session_->Close(result->Result());

  // Last step (5.3.2 Resolve promise) will be done when |result| is resolved.
}

void MediaKeySession::OnClosePromiseResolved() {
  // Stop the CDM from firing any more events for this session now that it is
  // closed. This was deferred in OnSessionClosed() as the EME spec resolves
  // the promise after firing the event.
  Dispose();
}

ScriptPromise<IDLUndefined> MediaKeySession::remove(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // From https://w3c.github.io/encrypted-media/#remove:
  // Removes stored session data associated with this object. When this
  // method is invoked, the user agent must run the following steps:

  // 1. If this object's closing or closed value is true, return a promise
  //    rejected with an InvalidStateError.
  if (is_closing_ || is_closed_) {
    ThrowAlreadyClosed(exception_state);
    return EmptyPromise();
  }

  // 2. If this object's callable value is false, return a promise rejected
  //    with an InvalidStateError.
  if (!is_callable_)
    return CreateRejectedPromiseNotCallable(exception_state);

  // 3. Let promise be a new promise.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  SimpleResultPromise* result = MakeGarbageCollected<SimpleResultPromise>(
      resolver, config_, this, EmeApiType::kRemove);

  // 4. Run the following steps asynchronously (done in removeTask()).
  pending_actions_.push_back(PendingAction::CreatePendingRemove(result));
  if (!action_timer_.IsActive())
    action_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  // 5. Return promise.
  return promise;
}

void MediaKeySession::RemoveTask(ContentDecryptionModuleResult* result) {
  // NOTE: Continue step 4 of MediaKeySession::remove().
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // remove() in Chromium will execute steps 4.1 through 4.5.
  session_->Remove(result->Result());

  // Last step (4.5.6 Resolve promise) will be done when |result| is resolved.
}

void MediaKeySession::ActionTimerFired(TimerBase*) {
  DCHECK(pending_actions_.size());

  // Resolving promises now run synchronously and may result in additional
  // actions getting added to the queue. As a result, swap the queue to
  // a local copy to avoid problems if this happens.
  HeapDeque<Member<PendingAction>> pending_actions;
  pending_actions.Swap(pending_actions_);

  while (!pending_actions.empty()) {
    PendingAction* action = pending_actions.TakeFirst();
    switch (action->GetType()) {
      case PendingAction::Type::kGenerateRequest:
        GenerateRequestTask(action->Result(), action->InitDataType(),
                            action->Data());
        break;

      case PendingAction::Type::kLoad:
        LoadTask(action->Result(), action->SessionId());
        break;

      case PendingAction::Type::kUpdate:
        UpdateTask(action->Result(), action->Data());
        break;

      case PendingAction::Type::kClose:
        CloseTask(action->Result());
        break;

      case PendingAction::Type::kRemove:
        RemoveTask(action->Result());
        break;

      default:
        NOTREACHED();
    }
  }
}

// Queue a task to fire a simple event named keymessage at the new object.
void MediaKeySession::OnSessionMessage(media::CdmMessageType message_type,
                                       const unsigned char* message,
                                       size_t message_length) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // Verify that 'message' not fired before session initialization is complete.
  DCHECK(is_callable_);

  // From https://w3c.github.io/encrypted-media/#queue-message:
  // The following steps are run:
  // 1. Let the session be the specified MediaKeySession object.
  // 2. Queue a task to fire a simple event named message at the session.
  //    The event is of type MediaKeyMessageEvent and has:
  //    -> messageType = the specified message type
  //    -> message = the specified message

  MediaKeyMessageEventInit* init = MediaKeyMessageEventInit::Create();
  switch (message_type) {
    case media::CdmMessageType::LICENSE_REQUEST:
      init->setMessageType("license-request");
      break;
    case media::CdmMessageType::LICENSE_RENEWAL:
      init->setMessageType("license-renewal");
      break;
    case media::CdmMessageType::LICENSE_RELEASE:
      init->setMessageType("license-release");
      break;
    case media::CdmMessageType::INDIVIDUALIZATION_REQUEST:
      init->setMessageType("individualization-request");
      break;
  }
  init->setMessage(
      DOMArrayBuffer::Create(UNSAFE_TODO(base::span(message, message_length))));

  MediaKeyMessageEvent* event =
      MediaKeyMessageEvent::Create(event_type_names::kMessage, init);
  event->SetTarget(this);
  async_event_queue_->EnqueueEvent(FROM_HERE, *event);
}

void MediaKeySession::OnSessionClosed(media::CdmSessionClosedReason reason) {
  // Note that this is the event from the CDM when this session is actually
  // closed. The CDM can close a session at any time. Normally it would happen
  // as the result of a close() call, but also happens when update() has been
  // called with a record of license destruction or if the CDM crashes or
  // otherwise becomes unavailable.
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // From http://w3c.github.io/encrypted-media/#session-closed
  // 1. Let session be the associated MediaKeySession object.
  // 2. Let promise be the session's closed attribute.
  // 3. If promise is resolved, abort these steps.
  if (closed_promise_->GetState() == ClosedPromise::kResolved)
    return;

  // 4. Set the session's closing or closed value to true.
  is_closed_ = true;

  // 5. Run the Update Key Statuses algorithm on the session, providing
  //    an empty sequence.
  OnSessionKeysChange(WebVector<WebEncryptedMediaKeyInformation>(), false);

  // 6. Run the Update Expiration algorithm on the session, providing NaN.
  OnSessionExpirationUpdate(std::numeric_limits<double>::quiet_NaN());

  // 7. Resolve promise.
  closed_promise_->Resolve(
      V8MediaKeySessionClosedReason(ConvertSessionClosedReason(reason))
          .AsString());

  // Fail any pending events, except if it's a close request.
  action_timer_.Stop();
  while (!pending_actions_.empty()) {
    PendingAction* action = pending_actions_.TakeFirst();
    if (action->GetType() == PendingAction::Type::kClose) {
      action->Result()->Complete();
    } else {
      action->Result()->CompleteWithError(
          kWebContentDecryptionModuleExceptionInvalidStateError, 0,
          "Session has been closed");
    }
  }

  // Stop the CDM from firing any more events for this session. If this
  // session is closed due to close() being called, the close() promise will
  // be resolved after this which will call Dispose().
  // https://w3c.github.io/encrypted-media/#session-closed
  if (!is_closing_) {
    // CDM closed the session for some other reason, so release the CDM
    // immediately.
    Dispose();
  }
}

void MediaKeySession::OnSessionExpirationUpdate(
    double updated_expiry_time_in_ms) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
      << __func__ << "(" << this << ") " << updated_expiry_time_in_ms;

  // From https://w3c.github.io/encrypted-media/#update-expiration:
  // The following steps are run:
  // 1. Let the session be the associated MediaKeySession object.
  // 2. Let expiration time be NaN.
  double expiration_time = std::numeric_limits<double>::quiet_NaN();

  // 3. If the new expiration time is not NaN, let expiration time be the
  //    new expiration time in milliseconds since 01 January 1970 UTC.
  if (!std::isnan(updated_expiry_time_in_ms))
    expiration_time = updated_expiry_time_in_ms;

  // 4. Set the session's expiration attribute to expiration time.
  expiration_ = expiration_time;
}

void MediaKeySession::OnSessionKeysChange(
    const WebVector<WebEncryptedMediaKeyInformation>& keys,
    bool has_additional_usable_key) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
      << __func__ << "(" << this << ") with " << keys.size()
      << " keys and hasAdditionalUsableKey is "
      << (has_additional_usable_key ? "true" : "false");

  // From https://w3c.github.io/encrypted-media/#update-key-statuses:
  // The following steps are run:
  // 1. Let the session be the associated MediaKeySession object.
  // 2. Let the input statuses be the sequence of pairs key ID and
  //    associated MediaKeyStatus pairs.
  // 3. Let the statuses be session's keyStatuses attribute.

  // 4. Run the following steps to replace the contents of statuses:
  // 4.1 Empty statuses.
  key_statuses_map_->Clear();

  auto* ukm_recorder = GetExecutionContext()->UkmRecorder();
  const ukm::SourceId source_id = GetExecutionContext()->UkmSourceID();

  // 4.2 For each pair in input statuses.
  for (size_t i = 0; i < keys.size(); ++i) {
    // 4.2.1 Let pair be the pair.
    const auto& key = keys[i];
    // 4.2.2 Insert an entry for pair's key ID into statuses with the
    //       value of pair's MediaKeyStatus value.
    key_statuses_map_->AddEntry(
        key.Id(), EncryptedMediaUtils::ConvertKeyStatusToString(key.Status()));

    ukm::builders::Media_EME_CdmSystemCode(source_id)
        .SetCdmSystemCode(key.SystemCode())
        .Record(ukm_recorder);
  }

  // 5. Queue a task to fire a simple event named keystatuseschange
  //    at the session.
  Event* event = Event::Create(event_type_names::kKeystatuseschange);
  event->SetTarget(this);
  async_event_queue_->EnqueueEvent(FROM_HERE, *event);

  // 6. Queue a task to run the attempt to resume playback if necessary
  //    algorithm on each of the media element(s) whose mediaKeys attribute
  //    is the MediaKeys object that created the session. The user agent
  //    may choose to skip this step if it knows resuming will fail.
  // FIXME: Attempt to resume playback if |hasAdditionalUsableKey| is true.
  // http://crbug.com/413413
}

const AtomicString& MediaKeySession::InterfaceName() const {
  return event_target_names::kMediaKeySession;
}

ExecutionContext* MediaKeySession::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

bool MediaKeySession::HasPendingActivity() const {
  // Remain around if there are pending events or MediaKeys is still around
  // and we're not closed.
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
      << __func__ << "(" << this << ")"
      << (!pending_actions_.empty() ? " !pending_actions_.IsEmpty()" : "")
      << (async_event_queue_->HasPendingEvents()
              ? " async_event_queue_->HasPendingEvents()"
              : "")
      << ((media_keys_ && !is_closed_) ? " media_keys_ && !is_closed_" : "");

  return !pending_actions_.empty() || async_event_queue_->HasPendingEvents() ||
         (media_keys_ && !is_closed_);
}

void MediaKeySession::ContextDestroyed() {
  // Stop the CDM from firing any more events for this session.
  session_.reset();
  is_closed_ = true;
  action_timer_.Stop();
  pending_actions_.clear();
}

void MediaKeySession::Trace(Visitor* visitor) const {
  visitor->Trace(async_event_queue_);
  visitor->Trace(pending_actions_);
  visitor->Trace(media_keys_);
  visitor->Trace(key_statuses_map_);
  visitor->Trace(closed_promise_);
  visitor->Trace(action_timer_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink
```