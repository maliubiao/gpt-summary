Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ code snippet, specifically focusing on its role within the Chromium Blink engine and its relationship to web technologies (JavaScript, HTML, CSS). It also asks for logical reasoning examples, common usage errors, and debugging clues. The final instruction is to summarize the functionality of this first part of the file.

2. **Initial Scan for Keywords and Structure:** I quickly scan the code for important keywords and structural elements. I see:
    * `#include`: This tells me what other parts of the codebase this file interacts with. I note includes like `media/base/ContentDecryptionModule.h`, `third_party/blink/public/platform/Web...`,  `third_party/blink/renderer/bindings/...`, and `third_party/blink/renderer/modules/encryptedmedia/...`. This gives a high-level idea of the file's domain: Encrypted Media Extensions (EME) within Blink.
    * `namespace blink`:  Confirms this is Blink-specific code.
    * Class definition: `class MediaKeySession`. This is the core of the file.
    * Methods within the class: `generateRequest`, `load`, `update`, `close`, `remove`, `OnMessage`, `OnExpirationChange`, `OnKeyStatusChange`, etc. These are the actions this class can perform.
    * Promise-related types: `ScriptPromise`, `ScriptPromiseResolver`. This indicates asynchronous operations and interaction with JavaScript promises.
    * Event-related types: `Event`, `EventQueue`, `MediaKeyMessageEvent`. This points to event handling within the EME workflow.
    * "InvalidStateError", "TypeError": These suggest error handling and validation.

3. **Identify Core Functionality:** Based on the class name (`MediaKeySession`) and the included files/method names, I deduce that this file implements the core logic for the `MediaKeySession` JavaScript API within the Blink rendering engine. This API is part of the Encrypted Media Extensions (EME) specification. It manages the lifecycle of a media decryption session.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `MediaKeySession` class directly corresponds to the JavaScript `MediaKeySession` object. The methods in the C++ class (e.g., `generateRequest`, `update`) are directly called from the corresponding JavaScript methods. The use of `ScriptPromise` shows how asynchronous operations in C++ are exposed as Promises to JavaScript. The event dispatching (`Queue a "message" Event`) relates to JavaScript event listeners.
    * **HTML:** While this specific C++ file doesn't directly manipulate the HTML DOM, it's triggered by JavaScript code that *is* interacting with HTML `<video>` or `<audio>` elements that require decryption. The `encrypted` event on these elements, handled in JavaScript, is the starting point for EME interactions.
    * **CSS:** CSS has no direct interaction with the core decryption logic handled in this file.

5. **Logical Reasoning Examples (Hypothetical Input/Output):** I focus on the key methods and think about what triggers them and what their expected outcomes are. For `generateRequest`:
    * **Input:** JavaScript calls `mediaKeySession.generateRequest(initDataType, initData)`. `initDataType` is a string, `initData` is an `ArrayBuffer`.
    * **Processing:** The C++ code validates the inputs, creates a promise, and passes the request to the underlying CDM.
    * **Output:**  The promise resolves (successfully creates the session and triggers a 'message' event) or rejects (due to invalid input, unsupported type, or CDM error). A `MediaKeyMessageEvent` is dispatched, containing a request that the application needs to send to a license server.

6. **Common Usage Errors:** I consider the error handling within the code and common pitfalls developers might encounter:
    * Calling methods in the wrong state (`InvalidStateError`). For example, calling `generateRequest` after it's already been called.
    * Providing invalid or empty input data (`TypeError`).
    * Misunderstanding the asynchronous nature of the API (not handling promises correctly).

7. **Debugging Clues (User Actions):** I trace the steps a user would take that eventually lead to this code being executed:
    * The user loads a web page with media content.
    * The media content is encrypted.
    * The browser detects the encryption and fires an `encrypted` event.
    * JavaScript code handles the `encrypted` event.
    * The JavaScript creates a `MediaKeys` object (handled in a related C++ file).
    * The JavaScript calls `mediaKeys.createSession()`, which creates a `MediaKeySession` object (this C++ file).
    * The JavaScript then calls methods like `generateRequest`, `update`, etc. on the `MediaKeySession` object, leading to the execution of the C++ code in this file.

8. **Summarize the Functionality (Part 1):**  Based on the above analysis, I synthesize a concise summary, focusing on the key responsibilities of the `MediaKeySession` class and its interaction with JavaScript and the underlying CDM. I make sure to highlight that this is only the first part of the file and thus incomplete.

9. **Review and Refine:** I review my answer for clarity, accuracy, and completeness, making sure it directly addresses all parts of the prompt. I ensure the examples are relevant and easy to understand. I double-check that my summary accurately reflects the functionality seen in the provided code.
好的，让我们来分析一下 `blink/renderer/modules/encryptedmedia/media_key_session.cc` 文件的功能。

**文件功能归纳：**

这个 C++ 文件 `media_key_session.cc` 定义了 Blink 渲染引擎中 `MediaKeySession` 类的实现。`MediaKeySession` 类是 W3C 加密媒体扩展 (Encrypted Media Extensions, EME) API 的核心组件，负责管理单个加密媒体会话的生命周期。其主要功能包括：

1. **会话生命周期管理:**  创建、初始化、加载、更新、关闭和移除加密媒体会话。
2. **与 Content Decryption Module (CDM) 交互:**  作为 Blink 和 CDM 之间的桥梁，负责将 JavaScript 的请求（例如生成密钥请求、更新密钥）传递给 CDM，并处理 CDM 的响应。
3. **事件派发:**  当 CDM 生成消息（例如密钥请求）或会话状态发生变化时，派发相应的事件（`message` 事件、`keystatuseschange` 事件）到 JavaScript。
4. **状态管理:**  维护会话的各种状态，例如会话 ID、过期时间、密钥状态、是否已关闭等。
5. **Promise 管理:**  使用 JavaScript Promise 来处理异步操作的结果，例如 `generateRequest`、`update`、`close` 和 `remove` 方法都返回 Promise。
6. **错误处理:**  处理来自 CDM 的错误，并将错误信息转换为 JavaScript 异常抛出。
7. **性能监控和指标上报:**  通过 UKM (Usefulness, Keyness, and Metrics) 上报 EME API 的使用情况。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**  `MediaKeySession` 类是 JavaScript `MediaKeySession` 接口在 Blink 引擎中的具体实现。JavaScript 代码可以直接调用 `MediaKeySession` 对象的方法，例如：
    ```javascript
    navigator.requestMediaKeySystemAccess('com.example.drm').then(function(keySystemAccess) {
        return keySystemAccess.createMediaKeys();
    }).then(function(mediaKeys) {
        var video = document.querySelector('video');
        return video.setMediaKeys(mediaKeys);
    }).then(function() {
        var video = document.querySelector('video');
        video.addEventListener('encrypted', function(event) {
            var mediaKeySession = video.mediaKeys.createSession();
            mediaKeySession.generateRequest(event.initDataType, event.initData); // 调用 C++ 的 generateRequest
            mediaKeySession.addEventListener('message', function(event) {
                // 将消息发送到许可证服务器
            });
            mediaKeySession.addEventListener('keystatuseschange', function(event) {
                // 处理密钥状态变化
            });
        });
    });
    ```
    在这个例子中，JavaScript 代码创建了一个 `MediaKeySession` 对象，并调用了 `generateRequest` 方法。这个调用最终会执行 `media_key_session.cc` 中的 `MediaKeySession::generateRequest` 方法。

* **HTML:**  HTML 中的 `<video>` 或 `<audio>` 元素是触发 EME 流程的关键。当浏览器遇到需要解密的加密媒体内容时，会触发 `encrypted` 事件，这个事件在 JavaScript 中被监听，从而启动 `MediaKeySession` 的创建和操作。

* **CSS:** CSS 与 `MediaKeySession` 的功能没有直接关系。CSS 负责控制网页的样式，而 `MediaKeySession` 负责处理媒体内容的解密。

**逻辑推理的假设输入与输出：**

**假设输入:**

1. **JavaScript 调用 `generateRequest`:**
   - `initDataType`: "cenc"
   - `initData`:  一个包含加密信息的 `ArrayBuffer`，例如用于请求许可证的 PSSH 数据。
2. **CDM 处理请求并生成消息:**
   - CDM 生成了一个需要发送到许可证服务器的密钥请求消息。
   - 消息类型可能是 "license-request"。
   - 消息内容是一个包含许可证请求信息的 `ArrayBuffer`。

**逻辑推理与输出:**

1. `MediaKeySession::generateRequest` 方法会被调用，它会：
   - 验证输入参数。
   - 创建一个用于异步操作的 Promise。
   - 调用 CDM 的 `InitializeNewSession` 方法，将 `initDataType` 和 `initData` 传递给 CDM。
2. CDM 处理 `InitializeNewSession` 请求，并生成密钥请求消息。
3. CDM 通过 `MediaKeySession::OnMessage` 回调方法将消息传递回 Blink。
4. `MediaKeySession::OnMessage` 方法会：
   - 创建一个 `MediaKeyMessageEvent` 对象，包含消息类型和消息内容。
   - 将 `MediaKeyMessageEvent` 派发到 JavaScript，触发 `message` 事件监听器。

**用户或编程常见的使用错误举例说明：**

1. **在错误的生命周期阶段调用方法:**  例如，在 `MediaKeySession` 已经关闭后调用 `update` 方法，会导致 `InvalidStateError` 异常。
   ```javascript
   mediaKeySession.close();
   mediaKeySession.update(response); // 错误：会抛出 InvalidStateError
   ```
2. **传递无效的参数:** 例如，传递空的 `initDataType` 或 `initData` 给 `generateRequest` 方法，会导致 `TypeError` 异常。
   ```javascript
   mediaKeySession.generateRequest("", new ArrayBuffer(0)); // 错误：会抛出 TypeError
   ```
3. **未正确处理 Promise:**  `MediaKeySession` 的异步方法返回 Promise，如果开发者没有正确处理 Promise 的 resolve 和 reject，可能会导致程序逻辑错误或未捕获的异常。
   ```javascript
   mediaKeySession.generateRequest(initDataType, initData)
       .then(function() {
           // 操作成功，但没有处理失败的情况
       });
   ```
4. **没有监听必要的事件:**  例如，没有监听 `message` 事件，会导致无法获取 CDM 生成的密钥请求消息，从而无法完成许可证请求流程。
   ```javascript
   mediaKeySession.generateRequest(initDataType, initData);
   // 缺少 mediaKeySession.addEventListener('message', ...);
   ```

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户访问包含加密媒体内容的网页。** 例如，一个视频网站，某些视频需要付费或登录才能观看。
2. **网页加载 `<video>` 或 `<audio>` 元素，其 `src` 指向加密的媒体资源。**
3. **浏览器尝试加载媒体资源，发现需要解密，触发 `encrypted` 事件。**  这个事件表明媒体数据是加密的，需要 EME 进行处理。
4. **JavaScript 代码监听了 `encrypted` 事件。**  事件处理函数会被调用。
5. **在 `encrypted` 事件处理函数中，JavaScript 代码调用 `video.mediaKeys.createSession()` 创建一个 `MediaKeySession` 对象。**  这个操作对应着 `media_key_session.cc` 中 `MediaKeys::CreateSession` 方法的调用 (在另一个文件中，但与此文件紧密相关)。
6. **JavaScript 代码调用 `mediaKeySession.generateRequest(event.initDataType, event.initData)`。**  `event.initDataType` 和 `event.initData` 通常从媒体容器文件中获取，用于告知 CDM 如何生成密钥请求。  **这时，就会执行到 `media_key_session.cc` 文件中的 `MediaKeySession::generateRequest` 方法。**
7. **后续的操作可能包括 JavaScript 监听 `message` 事件，并将 CDM 生成的消息发送到许可证服务器，以及调用 `mediaKeySession.update` 方法处理许可证服务器返回的响应。**

**本部分功能归纳 (第 1 部分)：**

这部分代码主要负责 `MediaKeySession` 类的构造、析构以及 `generateRequest` 和 `load` 方法的实现。

* **构造函数:** 初始化 `MediaKeySession` 对象，包括创建底层的 Chromium CDM 会话对象，设置初始状态，以及创建用于异步事件派发的队列。
* **析构函数和 `Dispose` 方法:**  负责清理资源，释放对 CDM 会话对象的引用。
* **`sessionId()` 方法:**  返回当前会话的 ID。
* **`closed()` 方法:** 返回一个 Promise，当会话关闭时 resolve。
* **`keyStatuses()` 方法:** 返回一个包含当前密钥状态的 Map 对象。
* **`generateRequest()` 方法:**  处理 JavaScript 调用 `generateRequest` 的请求，负责初始化新的加密媒体会话，并将初始化数据传递给 CDM，最终触发 CDM 生成密钥请求消息。
* **`load()` 方法:**  处理 JavaScript 调用 `load` 的请求，用于加载之前持久化存储的会话信息。

总而言之，这部分代码定义了 `MediaKeySession` 类的基础结构和用于创建和加载会话的核心功能，是 EME 流程的起点。它负责与底层的 CDM 交互，并将结果通过 Promise 和事件机制反馈给 JavaScript。

Prompt: 
```
这是目录为blink/renderer/modules/encryptedmedia/media_key_session.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2013 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/encryptedmedia/media_key_session.h"

#include <cmath>
#include <limits>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/numerics/safe_conversions.h"
#include "encrypted_media_utils.h"
#include "media/base/content_decryption_module.h"
#include "media/base/eme_constants.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_decryption_module.h"
#include "third_party/blink/public/platform/web_content_decryption_module_exception.h"
#include "third_party/blink/public/platform/web_content_decryption_module_session.h"
#include "third_party/blink/public/platform/web_encrypted_media_key_information.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/bindings/core/v8/active_script_wrappable_creation_key.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/encryptedmedia/content_decryption_module_result_promise.h"
#include "third_party/blink/renderer/modules/encryptedmedia/encrypted_media_utils.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_key_message_event.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_keys.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/content_decryption_module_result.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"

#define MEDIA_KEY_SESSION_LOG_LEVEL 3

namespace {

// Minimum and maximum length for session ids.
enum { MinSessionIdLength = 1, MaxSessionIdLength = 512 };

}  // namespace

namespace blink {

// Checks that |sessionId| looks correct and returns whether all checks pass.
static bool IsValidSessionId(const String& session_id) {
  if ((session_id.length() < MinSessionIdLength) ||
      (session_id.length() > MaxSessionIdLength))
    return false;

  if (!session_id.ContainsOnlyASCIIOrEmpty())
    return false;

  // Check that |sanitized_session_id| only contains printable characters for
  // easier logging. Note that checking alphanumeric is too strict because there
  // are key systems using Base64 session IDs (which may include spaces). See
  // https://crbug.com/902828.
  for (unsigned i = 0; i < session_id.length(); ++i) {
    if (!IsASCIIPrintable(session_id[i]))
      return false;
  }

  return true;
}

static bool IsPersistentSessionType(WebEncryptedMediaSessionType session_type) {
  // This implements section 5.1.1 Is persistent session type? from
  // https://w3c.github.io/encrypted-media/#is-persistent-session-type
  switch (session_type) {
    case WebEncryptedMediaSessionType::kTemporary:
      return false;
    case WebEncryptedMediaSessionType::kPersistentLicense:
      return true;
    case blink::WebEncryptedMediaSessionType::kUnknown:
      break;
  }

  NOTREACHED();
}

V8MediaKeySessionClosedReason::Enum ConvertSessionClosedReason(
    media::CdmSessionClosedReason reason) {
  switch (reason) {
    case media::CdmSessionClosedReason::kInternalError:
      return V8MediaKeySessionClosedReason::Enum::kInternalError;
    case media::CdmSessionClosedReason::kClose:
      return V8MediaKeySessionClosedReason::Enum::kClosedByApplication;
    case media::CdmSessionClosedReason::kReleaseAcknowledged:
      return V8MediaKeySessionClosedReason::Enum::kReleaseAcknowledged;
    case media::CdmSessionClosedReason::kHardwareContextReset:
      return V8MediaKeySessionClosedReason::Enum::kHardwareContextReset;
    case media::CdmSessionClosedReason::kResourceEvicted:
      return V8MediaKeySessionClosedReason::Enum::kResourceEvicted;
  }
}

static ScriptPromise<IDLUndefined> CreateRejectedPromiseNotCallable(
    ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    "The session is not callable.");
  return EmptyPromise();
}

static void ThrowAlreadyClosed(ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    "The session is already closed.");
}

static void ThrowAlreadyInitialized(ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    "The session is already initialized.");
}

// A class holding a pending action.
class MediaKeySession::PendingAction final
    : public GarbageCollected<MediaKeySession::PendingAction> {
 public:
  using Type = EmeApiType;

  Type GetType() const { return type_; }

  ContentDecryptionModuleResult* Result() const { return result_.Get(); }

  DOMArrayBuffer* Data() const {
    DCHECK(type_ == Type::kGenerateRequest || type_ == Type::kUpdate);
    return data_.Get();
  }

  media::EmeInitDataType InitDataType() const {
    DCHECK_EQ(Type::kGenerateRequest, type_);
    return init_data_type_;
  }

  const String& SessionId() const {
    DCHECK_EQ(Type::kLoad, type_);
    return string_data_;
  }

  static PendingAction* CreatePendingGenerateRequest(
      ContentDecryptionModuleResult* result,
      media::EmeInitDataType init_data_type,
      DOMArrayBuffer* init_data) {
    DCHECK(result);
    DCHECK(init_data);
    return MakeGarbageCollected<PendingAction>(
        Type::kGenerateRequest, result, init_data_type, init_data, String());
  }

  static PendingAction* CreatePendingLoadRequest(
      ContentDecryptionModuleResult* result,
      const String& session_id) {
    DCHECK(result);
    return MakeGarbageCollected<PendingAction>(Type::kLoad, result,
                                               media::EmeInitDataType::UNKNOWN,
                                               nullptr, session_id);
  }

  static PendingAction* CreatePendingUpdate(
      ContentDecryptionModuleResult* result,
      DOMArrayBuffer* data) {
    DCHECK(result);
    DCHECK(data);
    return MakeGarbageCollected<PendingAction>(
        Type::kUpdate, result, media::EmeInitDataType::UNKNOWN, data, String());
  }

  static PendingAction* CreatePendingClose(
      ContentDecryptionModuleResult* result) {
    DCHECK(result);
    return MakeGarbageCollected<PendingAction>(Type::kClose, result,
                                               media::EmeInitDataType::UNKNOWN,
                                               nullptr, String());
  }

  static PendingAction* CreatePendingRemove(
      ContentDecryptionModuleResult* result) {
    DCHECK(result);
    return MakeGarbageCollected<PendingAction>(Type::kRemove, result,
                                               media::EmeInitDataType::UNKNOWN,
                                               nullptr, String());
  }

  PendingAction(Type type,
                ContentDecryptionModuleResult* result,
                media::EmeInitDataType init_data_type,
                DOMArrayBuffer* data,
                const String& string_data)
      : type_(type),
        result_(result),
        init_data_type_(init_data_type),
        data_(data),
        string_data_(string_data) {}
  ~PendingAction() = default;

  void Trace(Visitor* visitor) const {
    visitor->Trace(result_);
    visitor->Trace(data_);
  }

 private:
  const Type type_;
  const Member<ContentDecryptionModuleResult> result_;
  const media::EmeInitDataType init_data_type_;
  const Member<DOMArrayBuffer> data_;
  const String string_data_;
};

// This class wraps the promise resolver used when initializing a new session
// and is passed to Chromium to fullfill the promise. This implementation of
// completeWithSession() will resolve the promise with void, while
// completeWithError() will reject the promise with an exception. complete()
// is not expected to be called, and will reject the promise.
class NewSessionResultPromise : public ContentDecryptionModuleResultPromise {
 public:
  NewSessionResultPromise(ScriptPromiseResolver<IDLUndefined>* resolver,
                          const MediaKeysConfig& config,
                          MediaKeySession* session)
      : ContentDecryptionModuleResultPromise(resolver,
                                             config,
                                             EmeApiType::kGenerateRequest),
        session_(session) {}

  ~NewSessionResultPromise() override = default;

  // ContentDecryptionModuleResult implementation.
  void CompleteWithSession(
      WebContentDecryptionModuleResult::SessionStatus status) override {
    DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
        << "NewSessionResultPromise::" << __func__;

    if (!IsValidToFulfillPromise())
      return;

    DCHECK_EQ(status, WebContentDecryptionModuleResult::kNewSession);
    session_->FinishGenerateRequest();
    Resolve<IDLUndefined>();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(session_);
    ContentDecryptionModuleResultPromise::Trace(visitor);
  }

 private:
  Member<MediaKeySession> session_;
};

// This class wraps the promise resolver used when loading a session
// and is passed to Chromium to fullfill the promise. This implementation of
// completeWithSession() will resolve the promise with true/false, while
// completeWithError() will reject the promise with an exception. complete()
// is not expected to be called, and will reject the promise.
class LoadSessionResultPromise : public ContentDecryptionModuleResultPromise {
 public:
  LoadSessionResultPromise(ScriptPromiseResolver<IDLBoolean>* resolver,
                           const MediaKeysConfig& config,
                           MediaKeySession* session)
      : ContentDecryptionModuleResultPromise(resolver,
                                             config,
                                             EmeApiType::kLoad),
        session_(session) {}

  ~LoadSessionResultPromise() override = default;

  // ContentDecryptionModuleResult implementation.
  void CompleteWithSession(
      WebContentDecryptionModuleResult::SessionStatus status) override {
    DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
        << "LoadSessionResultPromise::" << __func__;

    if (!IsValidToFulfillPromise())
      return;

    if (status == WebContentDecryptionModuleResult::kSessionNotFound) {
      Resolve<IDLBoolean>(false);
      return;
    }

    DCHECK_EQ(status, WebContentDecryptionModuleResult::kNewSession);
    session_->FinishLoad();
    Resolve<IDLBoolean>(true);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(session_);
    ContentDecryptionModuleResultPromise::Trace(visitor);
  }

 private:
  Member<MediaKeySession> session_;
};

// This class wraps the promise resolver used by close. The implementation of
// complete() will resolve the promise with void and call
// OnClosePromiseResolved() on |session_|. All other complete() methods are
// not expected to be called (and will reject the promise).
class CloseSessionResultPromise : public ContentDecryptionModuleResultPromise {
 public:
  CloseSessionResultPromise(ScriptPromiseResolver<IDLUndefined>* resolver,
                            const MediaKeysConfig& config,
                            MediaKeySession* session)
      : ContentDecryptionModuleResultPromise(resolver,
                                             config,
                                             EmeApiType::kClose),
        session_(session) {}

  ~CloseSessionResultPromise() override = default;

  // ContentDecryptionModuleResultPromise implementation.
  void Complete() override {
    DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
        << "CloseSessionResultPromise::" << __func__;

    if (!IsValidToFulfillPromise())
      return;

    session_->OnClosePromiseResolved();
    Resolve<IDLUndefined>();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(session_);
    ContentDecryptionModuleResultPromise::Trace(visitor);
  }

 private:
  // Keep track of the MediaKeySession that created this promise so that it
  // remains reachable as long as this promise is reachable.
  Member<MediaKeySession> session_;
};

// This class wraps the promise resolver used by update/remove. The
// implementation of complete() will resolve the promise with void. All other
// complete() methods are not expected to be called (and will reject the
// promise).
class SimpleResultPromise : public ContentDecryptionModuleResultPromise {
 public:
  SimpleResultPromise(ScriptPromiseResolver<IDLUndefined>* resolver,
                      const MediaKeysConfig& config,
                      MediaKeySession* session,
                      EmeApiType type)
      : ContentDecryptionModuleResultPromise(resolver, config, type),
        session_(session) {}

  ~SimpleResultPromise() override = default;

  // ContentDecryptionModuleResultPromise implementation.
  void Complete() override {
    DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << "SimpleResultPromise::" << __func__;

    if (!IsValidToFulfillPromise())
      return;

    Resolve<IDLUndefined>();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(session_);
    ContentDecryptionModuleResultPromise::Trace(visitor);
  }

 private:
  // Keep track of the MediaKeySession that created this promise so that it
  // remains reachable as long as this promise is reachable.
  Member<MediaKeySession> session_;
};

MediaKeySession::MediaKeySession(ScriptState* script_state,
                                 MediaKeys* media_keys,
                                 WebEncryptedMediaSessionType session_type,
                                 const MediaKeysConfig& config)
    : ActiveScriptWrappable<MediaKeySession>({}),
      ExecutionContextLifecycleObserver(ExecutionContext::From(script_state)),
      async_event_queue_(
          MakeGarbageCollected<EventQueue>(GetExecutionContext(),
                                           TaskType::kMediaElementEvent)),
      media_keys_(media_keys),
      session_type_(session_type),
      config_(config),
      expiration_(std::numeric_limits<double>::quiet_NaN()),
      key_statuses_map_(MakeGarbageCollected<MediaKeyStatusMap>()),
      closed_promise_(MakeGarbageCollected<ClosedPromise>(
          ExecutionContext::From(script_state))),
      action_timer_(ExecutionContext::From(script_state)
                        ->GetTaskRunner(TaskType::kMiscPlatformAPI),
                    this,
                    &MediaKeySession::ActionTimerFired) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";
  InstanceCounters::IncrementCounter(InstanceCounters::kMediaKeySessionCounter);

  // Create the matching Chromium object. It will not be usable until
  // initializeNewSession() is called in response to the user calling
  // generateRequest().
  WebContentDecryptionModule* cdm = media_keys->ContentDecryptionModule();
  session_ = cdm->CreateSession(session_type);
  session_->SetClientInterface(this);

  // From https://w3c.github.io/encrypted-media/#createSession:
  // MediaKeys::createSession(), step 3.
  // 3.1 Let the sessionId attribute be the empty string.
  DCHECK(session_id_.empty());

  // 3.2 Let the expiration attribute be NaN.
  DCHECK(std::isnan(expiration_));

  // 3.3 Let the closed attribute be a new promise.

  // 3.4 Let the keyStatuses attribute be empty.
  DCHECK_EQ(0u, key_statuses_map_->size());

  // 3.5 Let the session type be sessionType.
  DCHECK(session_type_ != WebEncryptedMediaSessionType::kUnknown);

  // 3.6 Let uninitialized be true.
  DCHECK(is_uninitialized_);

  // 3.7 Let callable be false.
  DCHECK(!is_callable_);

  // 3.8 Let the use distinctive identifier value be this object's
  // use distinctive identifier.
  // FIXME: Implement this (http://crbug.com/448922).

  // 3.9 Let the cdm implementation value be this object's cdm implementation.
  // 3.10 Let the cdm instance value be this object's cdm instance.
}

MediaKeySession::~MediaKeySession() {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";
  InstanceCounters::DecrementCounter(InstanceCounters::kMediaKeySessionCounter);
}

void MediaKeySession::Dispose() {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // Drop references to objects from content/ that aren't managed by blink.
  session_.reset();
}

String MediaKeySession::sessionId() const {
  return session_id_;
}

ScriptPromise<V8MediaKeySessionClosedReason> MediaKeySession::closed(
    ScriptState* script_state) {
  return closed_promise_->Promise(script_state->World());
}

MediaKeyStatusMap* MediaKeySession::keyStatuses() {
  return key_statuses_map_.Get();
}

ScriptPromise<IDLUndefined> MediaKeySession::generateRequest(
    ScriptState* script_state,
    const String& init_data_type_string,
    const DOMArrayPiece& init_data,
    ExceptionState& exception_state) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
      << __func__ << "(" << this << ") " << init_data_type_string;

  // From https://w3c.github.io/encrypted-media/#generateRequest:
  // Generates a request based on the initData. When this method is invoked,
  // the user agent must run the following steps:

  // 1. If this object's closing or closed value is true, return a promise
  //    rejected with an InvalidStateError.
  if (is_closing_ || is_closed_) {
    ThrowAlreadyClosed(exception_state);
    return EmptyPromise();
  }

  // 2. If this object's uninitialized value is false, return a promise
  //    rejected with an InvalidStateError.
  if (!is_uninitialized_) {
    ThrowAlreadyInitialized(exception_state);
    return EmptyPromise();
  }

  // 3. Let this object's uninitialized be false.
  is_uninitialized_ = false;

  // 4. If initDataType is the empty string, return a promise rejected
  //    with a newly created TypeError.
  if (init_data_type_string.empty()) {
    exception_state.ThrowTypeError("The initDataType parameter is empty.");
    return EmptyPromise();
  }

  // 5. If initData is an empty array, return a promise rejected with a
  //    newly created TypeError.
  if (!init_data.ByteLength()) {
    exception_state.ThrowTypeError("The initData parameter is empty.");
    return EmptyPromise();
  }

  // 6. If the Key System implementation represented by this object's cdm
  //    implementation value does not support initDataType as an
  //    Initialization Data Type, return a promise rejected with a new
  //    DOMException whose name is NotSupportedError. String comparison
  //    is case-sensitive.
  //    (blink side doesn't know what the CDM supports, so the proper check
  //     will be done on the Chromium side. However, we can verify that
  //     |initDataType| is one of the registered values.)
  media::EmeInitDataType init_data_type =
      EncryptedMediaUtils::ConvertToInitDataType(init_data_type_string);
  if (init_data_type == media::EmeInitDataType::UNKNOWN) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "The initialization data type '" +
                                          init_data_type_string +
                                          "' is not supported.");
    return EmptyPromise();
  }

  // 7. Let init data be a copy of the contents of the initData parameter.
  DOMArrayBuffer* init_data_buffer =
      DOMArrayBuffer::Create(init_data.ByteSpan());

  // 8. Let session type be this object's session type.
  //    (Done in constructor.)

  // 9. Let promise be a new promise.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  NewSessionResultPromise* result =
      MakeGarbageCollected<NewSessionResultPromise>(resolver, config_, this);

  // 10. Run the following steps asynchronously (done in generateRequestTask())
  pending_actions_.push_back(PendingAction::CreatePendingGenerateRequest(
      result, init_data_type, init_data_buffer));
  DCHECK(!action_timer_.IsActive());
  action_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  // 11. Return promise.
  return promise;
}

void MediaKeySession::GenerateRequestTask(ContentDecryptionModuleResult* result,
                                          media::EmeInitDataType init_data_type,
                                          DOMArrayBuffer* init_data_buffer) {
  // NOTE: Continue step 10 of MediaKeySession::generateRequest().
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // initializeNewSession() in Chromium will execute steps 10.1 to 10.9.
  session_->InitializeNewSession(
      init_data_type, static_cast<unsigned char*>(init_data_buffer->Data()),
      init_data_buffer->ByteLength(), result->Result());

  // Remaining steps (10.10) executed in finishGenerateRequest(),
  // called when |result| is resolved.
}

void MediaKeySession::FinishGenerateRequest() {
  // NOTE: Continue step 10.10 of MediaKeySession::generateRequest().
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // 10.10.1 If any of the preceding steps failed, reject promise with a
  //         new DOMException whose name is the appropriate error name.
  //         (Done by CDM calling result.completeWithError() as appropriate.)
  // 10.10.2 Set the sessionId attribute to session id.
  session_id_ = session_->SessionId();
  DCHECK(!session_id_.empty());

  // 10.10.3 Let this object's callable be true.
  is_callable_ = true;

  // 10.10.4 Run the Queue a "message" Event algorithm on the session,
  //         providing message type and message.
  //         (Done by the CDM.)
  // 10.10.5 Resolve promise.
  //         (Done by NewSessionResultPromise.)
}

ScriptPromise<IDLBoolean> MediaKeySession::load(
    ScriptState* script_state,
    const String& session_id,
    ExceptionState& exception_state) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL)
      << __func__ << "(" << this << ") " << session_id;

  // From https://w3c.github.io/encrypted-media/#load:
  // Loads the data stored for the specified session into this object. When
  // this method is invoked, the user agent must run the following steps:

  // 1. If this object's closing or closed value is true, return a promise
  //    rejected with an InvalidStateError.
  if (is_closing_ || is_closed_) {
    ThrowAlreadyClosed(exception_state);
    return EmptyPromise();
  }

  // 2. If this object's uninitialized value is false, return a promise
  //    rejected with an InvalidStateError.
  if (!is_uninitialized_) {
    ThrowAlreadyInitialized(exception_state);
    return EmptyPromise();
  }

  // 3. Let this object's uninitialized value be false.
  is_uninitialized_ = false;

  // 4. If sessionId is the empty string, return a promise rejected with
  //    a newly created TypeError.
  if (session_id.empty()) {
    exception_state.ThrowTypeError("The sessionId parameter is empty.");
    return EmptyPromise();
  }

  // 5. If the result of running the "Is persistent session type?" algorithm
  //    on this object's session type is false, return a promise rejected
  //    with a newly created TypeError.
  if (!IsPersistentSessionType(session_type_)) {
    exception_state.ThrowTypeError("The session type is not persistent.");
    return EmptyPromise();
  }

  // Log the usage of loadSession().
  EncryptedMediaUtils::ReportUsage(EmeApiType::kLoad, GetExecutionContext(),
                                   config_.key_system,
                                   config_.use_hardware_secure_codecs,
                                   /*is_persistent_session=*/true);

  // 6. Let origin be the origin of this object's Document.
  //    (Available as getExecutionContext()->getSecurityOrigin() anytime.)

  // 7. Let promise be a new promise.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  LoadSessionResultPromise* result =
      MakeGarbageCollected<LoadSessionResultPromise>(resolver, config_, this);

  // 8. Run the following steps asynchronously (done in loadTask())
  pending_actions_.push_back(
      PendingAction::CreatePendingLoadRequest(result, session_id));
  DCHECK(!action_timer_.IsActive());
  action_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  // 9. Return promise.
  return promise;
}

void MediaKeySession::LoadTask(ContentDecryptionModuleResult* result,
                               const String& session_id) {
  // NOTE: Continue step 8 of MediaKeySession::load().
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // 8.1 Let sanitized session ID be a validated and/or sanitized
  //     version of sessionId. The user agent should thoroughly
  //     validate the sessionId value before passing it to the CDM.
  //     At a minimum, this should include checking that the length
  //     and value (e.g. alphanumeric) are reasonable.
  // 8.2 If the preceding step failed, or if sanitized session ID
  //     is empty, reject promise with a newly created TypeError.
  if (!IsValidSessionId(session_id)) {
    result->CompleteWithError(kWebContentDecryptionModuleExceptionTypeError, 0,
                              "Invalid sessionId");
    return;
  }

  // 8.3 If there is an unclosed session in the object's Document
  //     whose sessionId attribute is sanitized session ID, reject
  //     promise with a new DOMException whose name is
  //     QuotaExceededError. In other words, do not create a session
  //     if a non-closed session, regardless of type, already exists
  //     for this sanitized session ID in this browsing context.
  //     (Done in the CDM.)

  // 8.4 Let expiration time be NaN.
  //     (Done in the constructor.)
  DCHECK(std::isnan(expiration_));

  // load() in Chromium will execute steps 8.5 through 8.8.
  session_->Load(session_id, result->Result());

  // Remaining step (8.9) executed in finishLoad(), called when |result|
  // is resolved.
}

void MediaKeySession::FinishLoad() {
  // NOTE: Continue step 8.9 of MediaKeySession::load().
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // 8.9.1 If any of the preceding steps failed, reject promise with a new
  //       DOMException whose name is the appropriate error name.
  //       (Done by CDM calling result.completeWithError() as appropriate.)

  // 8.9.2 Set the sessionId attribute to sanitized session ID.
  session_id_ = session_->SessionId();
  DCHECK(!session_id_.empty());

  // 8.9.3 Let this object's callable be true.
  is_callable_ = true;

  // 8.9.4 If the loaded session contains information about any keys (there
  //       are known keys), run the update key statuses algorithm on the
  //       session, providing each key's key ID along with the appropriate
  //       MediaKeyStatus. Should additional processing be necessary to
  //       determine with certainty the status of a key, use the non-"usable"
  //       MediaKeyStatus value that corresponds to the reason for the
  //       additional processing. Once the additional processing for one or
  //       more keys has completed, run the update key statuses algorithm
  //       again if any of the statuses has changed.
  //       (Done by the CDM.)

  // 8.9.5 Run the Update Expiration algorithm on the session,
  //       providing expiration time.
  //       (Done by the CDM.)

  // 8.9.6 If message is not null, run the queue a "message" event algorithm
  //       on the session, providing message type and message.
  //       (Done by the CDM.)

  // 8.9.7 Resolve promise with true.
  //       (Done by LoadSessionResultPromise.)
}

ScriptPromise<IDLUndefined> MediaKeySession::update(
    ScriptState* script_state,
    const DOMArrayPiece& response,
    ExceptionState& exception_state) {
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // From https://w3c.github.io/encrypted-media/#update:
  // Provides messages, including licenses, to the CDM. When this method is
  // invoked, the user agent must run the following steps:

  // 1. If this object's closing or closed value is true, return a promise
  //    rejected with an InvalidStateError.
  if (is_closing_ || is_closed_) {
    ThrowAlreadyClosed(exception_state);
    return EmptyPromise();
  }

  // 2. If this object's callable value is false, return a promise
  //    rejected with an InvalidStateError.
  if (!is_callable_)
    return CreateRejectedPromiseNotCallable(exception_state);

  // 3. If response is an empty array, return a promise rejected with a
  //    newly created TypeError.
  if (!response.ByteLength()) {
    exception_state.ThrowTypeError("The response parameter is empty.");
    return EmptyPromise();
  }

  // 4. Let response copy be a copy of the contents of the response parameter.
  DOMArrayBuffer* response_copy = DOMArrayBuffer::Create(response.ByteSpan());

  // Log the usage of update().
  EncryptedMediaUtils::ReportUsage(EmeApiType::kUpdate, GetExecutionContext(),
                                   config_.key_system,
                                   config_.use_hardware_secure_codecs,
                                   IsPersistentSessionType(session_type_));

  // 5. Let promise be a new promise.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  SimpleResultPromise* result = MakeGarbageCollected<SimpleResultPromise>(
      resolver, config_, this, EmeApiType::kUpdate);

  // 6. Run the following steps asynchronously (done in updateTask())
  pending_actions_.push_back(
      PendingAction::CreatePendingUpdate(result, response_copy));
  if (!action_timer_.IsActive())
    action_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  // 7. Return promise.
  return promise;
}

void MediaKeySession::UpdateTask(ContentDecryptionModuleResult* result,
                                 DOMArrayBuffer* sanitized_response) {
  // NOTE: Continue step 6 of MediaKeySession::update().
  DVLOG(MEDIA_KEY_SESSION_LOG_LEVEL) << __func__ << "(" << this << ")";

  // update() in Chromium will execute steps 6.1 through 6.8.
  session_->Update(static_cast<unsigned char*>(sanitized_response->Data()),
                   sanitized_response->ByteLength(), result->Result());

  // Last step (6.8.2 Resolve promise) will be done when |result| is resolved.
}

ScriptPromise<IDLUndefined> MediaKe
"""


```