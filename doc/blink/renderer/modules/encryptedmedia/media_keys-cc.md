Response:
Let's break down the thought process for analyzing the `media_keys.cc` file.

1. **Understanding the Goal:** The request asks for the functionality of the file, its relation to web technologies, example usage, logical inference examples, common errors, and debugging context.

2. **Initial Code Scan (Keywords and Structure):**  I start by scanning the code for key terms and the overall structure. I see:
    * `#include`: Includes related headers like `encryptedmedia`, `media/base`, `platform`, `bindings`, `core/dom`, `core/html/media`, etc. This immediately signals that the file is related to media decryption and likely interacts with web page elements.
    * `namespace blink`:  Indicates this is part of the Blink rendering engine.
    * Class definition: `class MediaKeys`. This is the central focus.
    * Methods like `createSession`, `setServerCertificate`, `getStatusForPolicy`. These suggest the core actions the class performs.
    * `ScriptPromise`:  Indicates asynchronous operations and interaction with JavaScript.
    * `DOMArrayBuffer`:  Suggests handling binary data, likely keys or certificates.
    * `HTMLMediaElement`:  Explicitly links this to media elements in HTML.
    * Comments referencing the EME (Encrypted Media Extensions) specification. This is crucial for understanding the context.
    * `PendingAction` inner class:  Hints at how asynchronous operations are managed.
    * `SetCertificateResultPromise`, `GetStatusForPolicyResultPromise`: Custom promise implementations, indicating specific handling for these operations.

3. **Identifying Core Functionality:** Based on the method names and EME context, the core functionality is clearly related to the Encrypted Media Extensions (EME) API. This involves:
    * Creating media key sessions (`createSession`).
    * Setting server certificates for secure communication (`setServerCertificate`).
    * Getting the status of policies (like HDCP requirements) (`getStatusForPolicy`).

4. **Relating to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The presence of `ScriptPromise`, the method names mirroring EME API functions, and the use of `DOMArrayBuffer` strongly suggest a direct mapping to the JavaScript EME API. I formulate examples of how a JavaScript developer would use `navigator.requestMediaKeySystemAccess()` to get a `MediaKeys` object and then call methods like `createSession()` and `setServerCertificate()`.
    * **HTML:** The explicit mention of `HTMLMediaElement` points to its integration with `<video>` and `<audio>` tags. The `MediaKeys` object is associated with these elements to enable playback of protected content. I create an example showing the `<video>` tag and the JavaScript code connecting the `MediaKeys` object to the video element using `setMediaKeys()`.
    * **CSS:** While not directly involved in the *functionality* of `media_keys.cc`, I consider how CSS might *indirectly* relate. CSS can style the video player, including controls and error messages. It doesn't influence the core decryption process handled by this file.

5. **Logical Inference Examples:**  I choose the `setServerCertificate` and `getStatusForPolicy` methods as good candidates for logical inference. For each:
    * **Hypothesize Input:** Define a scenario with specific input values (e.g., a valid certificate, a minimum HDCP version).
    * **Trace the Logic (Mentally or by rereading the code):**  Follow the code flow. For `setServerCertificate`, I note the check for an empty certificate and the asynchronous execution. For `getStatusForPolicy`, I see the UKM reporting.
    * **Predict Output:** Based on the code and EME specification knowledge, I predict the success or failure of the operation and the corresponding promise resolution.

6. **Identifying Common User/Programming Errors:**  I focus on common mistakes developers might make when using the EME API:
    * **Incorrect Key System:**  Providing an unsupported key system string.
    * **Empty Server Certificate:**  As explicitly checked in the `setServerCertificate` method.
    * **Incorrect Session Type:** Trying to create a persistent session when not allowed.
    * **Calling methods on a destroyed object:**  The code checks for a valid execution context.

7. **Tracing User Actions to the Code:** I construct a step-by-step user scenario that would lead to the execution of the code in `media_keys.cc`. This involves:
    * User visits a page with protected media.
    * JavaScript uses EME API.
    * Browser interacts with the CDM.
    * CDM calls back into the Blink engine, which includes the code in this file.

8. **Debugging Hints:** I list potential debugging steps, focusing on the information that would be useful when encountering issues:
    * Checking browser console for errors.
    * Examining network requests for license acquisition.
    * Inspecting internal state (if possible).
    * Using browser debugging tools.

9. **Review and Refine:** I reread my analysis, ensuring accuracy, clarity, and completeness. I double-check the examples and the logical inferences. I ensure I've addressed all parts of the original request. For instance, I added the point about CSS for a more comprehensive, though indirect, relationship. I also made sure to explicitly mention the role of the CDM, as it's central to the functionality.

This iterative process of scanning, understanding the context, identifying key components, relating them to web technologies, and then constructing examples and scenarios allows for a thorough analysis of the given code file.
好的，让我们来分析一下 `blink/renderer/modules/encryptedmedia/media_keys.cc` 这个文件。

**文件功能概述：**

`media_keys.cc` 文件是 Chromium Blink 引擎中负责处理 **Encrypted Media Extensions (EME)** API 中 `MediaKeys` 接口的核心实现。  它的主要功能是：

1. **管理 Content Decryption Module (CDM):**  `MediaKeys` 对象与特定的 CDM 实例关联，该文件负责存储和管理这个 CDM 的引用。CDM 是实际进行解密操作的组件。
2. **创建 MediaKeySession:**  `createSession()` 方法允许 JavaScript 创建新的 `MediaKeySession` 对象，用于管理特定媒体内容的密钥和许可。
3. **设置服务器证书:** `setServerCertificate()` 方法允许应用程序向 CDM 提供服务器证书，用于加密与许可服务器的通信。
4. **获取策略状态:** `getStatusForPolicy()` 方法允许应用程序查询 CDM 关于特定策略（例如，最低 HDCP 版本）的状态。
5. **管理异步操作:**  由于与 CDM 的交互通常是异步的，该文件使用 `PendingAction` 类和定时器来管理待处理的 `setServerCertificate` 和 `getStatusForPolicy` 操作。
6. **处理 Promise:**  `setServerCertificate` 和 `getStatusForPolicy` 方法返回 JavaScript Promise，该文件包含用于解析或拒绝这些 Promise 的逻辑。
7. **与 HTMLMediaElement 关联:**  `MediaKeys` 对象可以与特定的 `<video>` 或 `<audio>` 元素关联，以控制该元素的解密行为。
8. **记录 UKM (User Keyed Metrics):**  `getStatusForPolicy` 操作会记录相关的 UKM 指标，用于 Chrome 的遥测数据收集。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:** `MediaKeys` 接口是 EME API 的一部分，直接暴露给 JavaScript 代码使用。

   ```javascript
   navigator.requestMediaKeySystemAccess('com.example.drm') // 请求访问特定 DRM 系统
     .then(function(keySystemAccess) {
       return keySystemAccess.createMediaKeys(); // 创建 MediaKeys 对象
     })
     .then(function(mediaKeys) {
       // 使用 mediaKeys 对象创建会话，设置服务器证书等
       let session = mediaKeys.createSession('temporary');
       let serverCertificate = new Uint8Array([ /* ...证书数据... */ ]);
       return mediaKeys.setServerCertificate(serverCertificate);
     });
   ```

* **HTML:**  `MediaKeys` 对象需要与 HTML 的 `<video>` 或 `<audio>` 元素关联，才能使加密的媒体内容能够播放。

   ```html
   <video id="myVideo" controls src="encrypted_video.mp4"></video>
   <script>
     navigator.requestMediaKeySystemAccess('com.example.drm')
       .then(function(keySystemAccess) {
         return keySystemAccess.createMediaKeys();
       })
       .then(function(mediaKeys) {
         const video = document.getElementById('myVideo');
         return video.setMediaKeys(mediaKeys); // 将 MediaKeys 对象关联到 video 元素
       });
   </script>
   ```

* **CSS:** CSS 本身不直接与 `MediaKeys` 的功能相关。CSS 用于样式化 HTML 元素，包括 `<video>` 和 `<audio>` 元素的播放器控件。然而，CSS 可以间接地影响用户体验，例如，通过隐藏或显示某些控件，可能会影响用户与加密媒体的交互。

**逻辑推理及假设输入与输出：**

**场景：调用 `setServerCertificate`**

* **假设输入:**
    * `server_certificate`: 一个包含有效服务器证书数据的 `DOMArrayBuffer` 对象。
* **逻辑推理:**
    1. `setServerCertificate` 方法被调用。
    2. 检查 `server_certificate` 是否为空。如果为空，抛出 `TypeError`。
    3. 创建一个 `SetCertificateResultPromise` 对象来处理异步结果。
    4. 创建一个 `PendingAction` 对象，记录操作类型和证书数据。
    5. 启动定时器，异步执行 `SetServerCertificateTask`。
    6. `SetServerCertificateTask` 将证书数据传递给关联的 CDM。
    7. CDM 处理证书，并调用 `SetCertificateResultPromise` 的 `Complete()` 或 `CompleteWithError()` 方法。
    8. 如果 CDM 成功处理证书，Promise 将使用 `true` 解析。如果 CDM 不支持服务器证书（返回 `NOTSUPPORTEDERROR`），Promise 将使用 `false` 解析。如果发生其他错误，Promise 将被拒绝。
* **预期输出:**
    * 如果证书有效且 CDM 支持，Promise 将解析为 `true`。
    * 如果证书为空，JavaScript 会捕获到 `TypeError`。
    * 如果 CDM 不支持服务器证书，Promise 将解析为 `false`。
    * 如果发生其他 CDM 错误，Promise 将被拒绝，并带有相应的错误信息。

**场景：调用 `getStatusForPolicy`**

* **假设输入:**
    * `media_keys_policy`: 一个 `MediaKeysPolicy` 对象，其中 `minHdcpVersion` 设置为 "hdcp-2.2"。
* **逻辑推理:**
    1. `getStatusForPolicy` 方法被调用。
    2. 创建一个 `GetStatusForPolicyResultPromise` 对象来处理异步结果。
    3. 创建一个 `PendingAction` 对象，记录操作类型和最小 HDCP 版本。
    4. 启动定时器，异步执行 `GetStatusForPolicyTask`。
    5. `GetStatusForPolicyTask` 将最小 HDCP 版本传递给关联的 CDM。
    6. CDM 查询其策略状态，并调用 `GetStatusForPolicyResultPromise` 的 `CompleteWithKeyStatus()` 方法。
    7. CDM 返回一个 `WebEncryptedMediaKeyInformation::KeyStatus` 枚举值，表示策略状态。
    8. `CompleteWithKeyStatus` 方法将该枚举值转换为 JavaScript 可用的字符串 (例如，"usable", "not-usable", "output-restricted")，并使用该字符串解析 Promise。
    9. 同时，会记录一个 UKM 事件，包含 key system, 是否使用硬件安全解码器，最小 HDCP 版本等信息。
* **预期输出:**
    * Promise 将解析为一个 `MediaKeyStatus` 字符串，例如 "usable"、"not-usable" 或 "output-restricted"，具体取决于 CDM 的策略状态。
    * 一个包含策略查询信息的 UKM 事件被记录。

**用户或编程常见的使用错误及举例说明：**

1. **在未关联到媒体元素的情况下创建会话:** 用户可能会在调用 `video.setMediaKeys(mediaKeys)` 之前就尝试创建 `MediaKeySession`。这可能会导致会话创建失败或行为异常。

   ```javascript
   navigator.requestMediaKeySystemAccess('com.example.drm')
     .then(function(keySystemAccess) {
       return keySystemAccess.createMediaKeys();
     })
     .then(function(mediaKeys) {
       let session = mediaKeys.createSession('temporary'); // 错误：在关联到 video 之前创建会话
       const video = document.getElementById('myVideo');
       video.setMediaKeys(mediaKeys);
       // ...
     });
   ```

2. **提供空的服务器证书:** 如代码所示，如果 `setServerCertificate` 的参数为空，将会抛出 `TypeError`。

   ```javascript
   navigator.requestMediaKeySystemAccess('com.example.drm')
     .then(function(keySystemAccess) {
       return keySystemAccess.createMediaKeys();
     })
     .then(function(mediaKeys) {
       return mediaKeys.setServerCertificate(new Uint8Array([])); // 错误：提供空的证书
     })
     .catch(function(error) {
       console.error("设置服务器证书失败:", error); // 这里会捕获到 TypeError
     });
   ```

3. **尝试创建不支持的会话类型:** 如果尝试创建 `MediaKeySession` 时指定的类型（例如 "persistent-license"）不被 `MediaKeys` 对象支持，`createSession` 方法将会抛出 `NotSupportedError`。

   ```javascript
   navigator.requestMediaKeySystemAccess('com.example.drm')
     .then(function(keySystemAccess) {
       return keySystemAccess.createMediaKeys();
     })
     .then(function(mediaKeys) {
       let session = mediaKeys.createSession('persistent-license'); // 假设不支持此类型
     })
     .catch(function(error) {
       console.error("创建会话失败:", error); // 这里会捕获到 NotSupportedError
     });
   ```

4. **在 `MediaKeys` 对象的执行上下文被销毁后调用方法:**  如果在 `MediaKeys` 对象所属的文档或 frame 被卸载后，JavaScript 尝试调用其方法，将会抛出 `InvalidAccessError`。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户正在观看一个受 DRM 保护的视频：

1. **用户访问包含加密媒体内容的网页:** 用户在浏览器中打开一个包含 `<video>` 标签，且该视频需要特定的 DRM 才能播放的网页。
2. **JavaScript 代码执行:** 网页上的 JavaScript 代码会尝试使用 EME API 来处理加密内容。
3. **请求 MediaKeySystemAccess:**  JavaScript 调用 `navigator.requestMediaKeySystemAccess('com.example.drm')` 来请求访问特定的密钥系统（例如，'com.widevine.alpha'）。
4. **创建 MediaKeys 对象:** 如果密钥系统访问请求成功，JavaScript 调用 `keySystemAccess.createMediaKeys()`，这将会在 Blink 引擎中创建 `MediaKeys` 对象，并加载相应的 CDM。
5. **关联 MediaKeys 到媒体元素:** JavaScript 调用 `video.setMediaKeys(mediaKeys)`，将创建的 `MediaKeys` 对象与 HTML 的 `<video>` 元素关联。
6. **创建 MediaKeySession:** JavaScript 调用 `mediaKeys.createSession('temporary' 或 'persistent-license')` 来创建会话，以便与许可服务器通信。这一步会涉及到 `media_keys.cc` 中的 `createSession` 方法。
7. **生成请求 (generateRequest):**  `MediaKeySession` 对象会触发 `needkey` 事件，JavaScript 监听该事件并调用 `session.generateRequest(initDataType, initData)`，这会导致与许可服务器的通信。
8. **接收许可:** 许可服务器返回许可信息。
9. **加载许可 (update):** JavaScript 调用 `session.update(license)` 将许可加载到 CDM 中。
10. **播放媒体:**  如果许可加载成功，CDM 就可以解密媒体数据，`<video>` 元素就可以开始播放。

**调试线索:**

* **控制台错误:**  如果 JavaScript 代码在使用 EME API 时发生错误（例如，不支持的密钥系统、创建会话失败），浏览器的开发者控制台会显示相应的错误信息。
* **网络请求:** 可以检查浏览器发出的网络请求，查看是否成功连接到许可服务器，以及请求和响应的数据是否正确。
* **`chrome://media-internals`:**  Chrome 浏览器提供了一个内部页面 `chrome://media-internals`，可以查看当前正在播放的媒体信息，包括 EME 相关的信息，例如使用的 CDM、会话状态、密钥信息等。
* **断点调试:**  可以在 `media_keys.cc` 相关的代码中设置断点，例如在 `createSession`、`setServerCertificate` 等方法入口处，以便跟踪代码执行流程，查看变量的值，理解逻辑。
* **EME 相关事件:**  监听 `MediaKeySession` 对象上的事件（例如 `message`、`keystatuseschange`）可以帮助理解密钥和许可的处理流程。

希望这些信息能够帮助你理解 `blink/renderer/modules/encryptedmedia/media_keys.cc` 文件的功能和在 Chromium 中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/encryptedmedia/media_keys.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

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

#include "third_party/blink/renderer/modules/encryptedmedia/media_keys.h"

#include <memory>

#include "base/memory/scoped_refptr.h"
#include "media/base/content_decryption_module.h"
#include "media/base/key_systems.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_decryption_module.h"
#include "third_party/blink/public/platform/web_encrypted_media_key_information.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_key_session_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_keys_policy.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/encryptedmedia/content_decryption_module_result_promise.h"
#include "third_party/blink/renderer/modules/encryptedmedia/encrypted_media_utils.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_key_session.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"

#define MEDIA_KEYS_LOG_LEVEL 3

namespace blink {

// A class holding a pending action.
class MediaKeys::PendingAction final
    : public GarbageCollected<MediaKeys::PendingAction> {
 public:
  using Type = EmeApiType;

  Type GetType() const { return type_; }

  const Persistent<ContentDecryptionModuleResult> Result() const {
    return result_;
  }

  DOMArrayBuffer* Data() const {
    DCHECK_EQ(Type::kSetServerCertificate, type_);
    return data_.Get();
  }

  const String& StringData() const {
    DCHECK_EQ(Type::kGetStatusForPolicy, type_);
    return string_data_;
  }

  static PendingAction* CreatePendingSetServerCertificate(
      ContentDecryptionModuleResult* result,
      DOMArrayBuffer* server_certificate) {
    DCHECK(result);
    DCHECK(server_certificate);
    return MakeGarbageCollected<PendingAction>(
        Type::kSetServerCertificate, result, server_certificate, String());
  }

  static PendingAction* CreatePendingGetStatusForPolicy(
      ContentDecryptionModuleResult* result,
      const String& min_hdcp_version) {
    DCHECK(result);
    return MakeGarbageCollected<PendingAction>(
        Type::kGetStatusForPolicy, result, nullptr, min_hdcp_version);
  }

  PendingAction(Type type,
                ContentDecryptionModuleResult* result,
                DOMArrayBuffer* data,
                const String& string_data)
      : type_(type), result_(result), data_(data), string_data_(string_data) {}

  void Trace(Visitor* visitor) const {
    visitor->Trace(result_);
    visitor->Trace(data_);
  }

 private:
  const Type type_;
  const Member<ContentDecryptionModuleResult> result_;
  const Member<DOMArrayBuffer> data_;
  const String string_data_;
};

// This class wraps the promise resolver used when setting the certificate
// and is passed to Chromium to fullfill the promise. This implementation of
// complete() will resolve the promise with true, while completeWithError()
// will reject the promise with an exception. completeWithSession()
// is not expected to be called, and will reject the promise.
class SetCertificateResultPromise
    : public ContentDecryptionModuleResultPromise {
 public:
  SetCertificateResultPromise(ScriptPromiseResolver<IDLBoolean>* resolver,
                              const MediaKeysConfig& config,
                              MediaKeys* media_keys)
      : ContentDecryptionModuleResultPromise(resolver,
                                             config,
                                             EmeApiType::kSetServerCertificate),
        media_keys_(media_keys) {}

  ~SetCertificateResultPromise() override = default;

  // ContentDecryptionModuleResult implementation.
  void Complete() override {
    if (!IsValidToFulfillPromise())
      return;

    Resolve<IDLBoolean>(true);
  }

  void CompleteWithError(WebContentDecryptionModuleException exception_code,
                         uint32_t system_code,
                         const WebString& error_message) override {
    if (!IsValidToFulfillPromise())
      return;

    // The EME spec specifies that "If the Key System implementation does
    // not support server certificates, return a promise resolved with
    // false." So convert any NOTSUPPORTEDERROR into resolving with false.
    if (exception_code ==
        kWebContentDecryptionModuleExceptionNotSupportedError) {
      Resolve<IDLBoolean>(false);
      return;
    }

    ContentDecryptionModuleResultPromise::CompleteWithError(
        exception_code, system_code, error_message);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(media_keys_);
    ContentDecryptionModuleResultPromise::Trace(visitor);
  }

 private:
  // Keeping a reference to MediaKeys to prevent GC from collecting it while
  // the promise is pending.
  Member<MediaKeys> media_keys_;
};

// This class wraps the promise resolver used when getting the key status for
// policy and is passed to Chromium to fullfill the promise.
class GetStatusForPolicyResultPromise
    : public ContentDecryptionModuleResultPromise {
 public:
  GetStatusForPolicyResultPromise(
      ScriptPromiseResolver<V8MediaKeyStatus>* resolver,
      const MediaKeysConfig& config,
      WebString min_hdcp_version,
      MediaKeys* media_keys)
      : ContentDecryptionModuleResultPromise(resolver,
                                             config,
                                             EmeApiType::kGetStatusForPolicy),
        media_keys_(media_keys),
        min_hdcp_version_(min_hdcp_version) {}

  ~GetStatusForPolicyResultPromise() override = default;

  // ContentDecryptionModuleResult implementation.
  void CompleteWithKeyStatus(
      WebEncryptedMediaKeyInformation::KeyStatus key_status) override {
    if (!IsValidToFulfillPromise())
      return;

    // Report Media.EME.GetStatusForPolicy UKM.
    auto* execution_context = GetExecutionContext();
    if (auto* local_dom_window = DynamicTo<LocalDOMWindow>(execution_context)) {
      Document* document = local_dom_window->document();
      if (document) {
        ukm::builders::Media_EME_GetStatusForPolicy builder(
            document->UkmSourceID());
        builder.SetKeySystem(media::GetKeySystemIntForUKM(
            GetMediaKeysConfig().key_system.Ascii()));
        builder.SetUseHardwareSecureCodecs(
            static_cast<int>(GetMediaKeysConfig().use_hardware_secure_codecs));
        std::optional<media::HdcpVersion> hdcp_version;
        if (min_hdcp_version_.ContainsOnlyASCII()) {
          hdcp_version =
              media::MaybeHdcpVersionFromString(min_hdcp_version_.Ascii());
        }
        builder.SetMinHdcpVersion(static_cast<int>(
            hdcp_version.value_or(media::HdcpVersion::kHdcpVersionNone)));
        LocalFrame* frame = document->GetFrame();
        if (frame) {
          builder.SetIsAdFrame(static_cast<int>(frame->IsAdFrame()));
        }
        builder.Record(document->UkmRecorder());
      }
    }

    Resolve<V8MediaKeyStatus>(
        EncryptedMediaUtils::ConvertKeyStatusToString(key_status));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(media_keys_);
    ContentDecryptionModuleResultPromise::Trace(visitor);
  }

 private:
  // Keeping a reference to MediaKeys to prevent GC from collecting it while
  // the promise is pending.
  Member<MediaKeys> media_keys_;

  WebString min_hdcp_version_;
};

MediaKeys::MediaKeys(
    ExecutionContext* context,
    const WebVector<WebEncryptedMediaSessionType>& supported_session_types,
    std::unique_ptr<WebContentDecryptionModule> cdm,
    const MediaKeysConfig& config)
    : ActiveScriptWrappable<MediaKeys>({}),
      ExecutionContextLifecycleObserver(context),
      supported_session_types_(supported_session_types),
      cdm_(std::move(cdm)),
      config_(config),
      media_element_(nullptr),
      reserved_for_media_element_(false),
      timer_(context->GetTaskRunner(TaskType::kMiscPlatformAPI),
             this,
             &MediaKeys::TimerFired) {
  DVLOG(MEDIA_KEYS_LOG_LEVEL) << __func__ << "(" << this << ")";
  InstanceCounters::IncrementCounter(InstanceCounters::kMediaKeysCounter);
}

MediaKeys::~MediaKeys() {
  DVLOG(MEDIA_KEYS_LOG_LEVEL) << __func__ << "(" << this << ")";
  InstanceCounters::DecrementCounter(InstanceCounters::kMediaKeysCounter);
}

MediaKeySession* MediaKeys::createSession(
    ScriptState* script_state,
    const V8MediaKeySessionType& v8_session_type,
    ExceptionState& exception_state) {
  DVLOG(MEDIA_KEYS_LOG_LEVEL)
      << __func__ << "(" << this << ") " << v8_session_type.AsCStr();

  // If the context for MediaKeys has been destroyed, fail.
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The context provided is invalid.");
    return nullptr;
  }

  // From https://w3c.github.io/encrypted-media/#dom-mediakeys-createsession

  // When this method is invoked, the user agent must run the following steps:
  // 1. If this object's persistent state allowed value is false and
  //    sessionType is not "temporary", throw a new DOMException whose name is
  //    NotSupportedError.
  //    (Chromium ensures that only session types supported by the
  //    configuration are listed in supportedSessionTypes.)
  // 2. If the Key System implementation represented by this object's cdm
  //    implementation value does not support sessionType, throw a new
  //    DOMException whose name is NotSupportedError.
  WebEncryptedMediaSessionType session_type =
      EncryptedMediaUtils::ConvertToSessionType(v8_session_type.AsString());
  if (!SessionTypeSupported(session_type)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Unsupported session type.");
    return nullptr;
  }

  // 3. Let session be a new MediaKeySession object, and initialize it as
  //    follows:
  //    (Initialization is performed in the constructor.)
  // 4. Return session.
  return MakeGarbageCollected<MediaKeySession>(script_state, this, session_type,
                                               config_);
}

ScriptPromise<IDLBoolean> MediaKeys::setServerCertificate(
    ScriptState* script_state,
    const DOMArrayPiece& server_certificate,
    ExceptionState& exception_state) {
  // If the context for MediaKeys has been destroyed, fail.
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The context provided is invalid.");
    return EmptyPromise();
  }

  // From
  // https://w3c.github.io/encrypted-media/#dom-mediakeys-setservercertificate

  // The setServerCertificate(serverCertificate) method provides a server
  // certificate to be used to encrypt messages to the license server.
  // It must run the following steps:
  // 1. If the Key System implementation represented by this object's cdm
  //    implementation value does not support server certificates, return
  //    a promise resolved with false.
  // TODO(jrummell): Provide a way to determine if the CDM supports this.
  // http://crbug.com/647816.
  //
  // 2. If serverCertificate is an empty array, return a promise rejected
  //    with a new a newly created TypeError.
  if (!server_certificate.ByteLength()) {
    exception_state.ThrowTypeError("The serverCertificate parameter is empty.");
    return EmptyPromise();
  }

  // 3. Let certificate be a copy of the contents of the serverCertificate
  //    parameter.
  DOMArrayBuffer* server_certificate_buffer =
      DOMArrayBuffer::Create(server_certificate.ByteSpan());

  // 4. Let promise be a new promise.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  SetCertificateResultPromise* result =
      MakeGarbageCollected<SetCertificateResultPromise>(resolver, config_,
                                                        this);

  // 5. Run the following steps asynchronously. See SetServerCertificateTask().
  pending_actions_.push_back(PendingAction::CreatePendingSetServerCertificate(
      result, server_certificate_buffer));
  if (!timer_.IsActive())
    timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  // 6. Return promise.
  return promise;
}

void MediaKeys::SetServerCertificateTask(
    DOMArrayBuffer* server_certificate,
    ContentDecryptionModuleResult* result) {
  DVLOG(MEDIA_KEYS_LOG_LEVEL) << __func__ << "(" << this << ")";

  // If the context has been destroyed, don't proceed. Try to have the promise
  // be rejected.
  if (!GetExecutionContext()) {
    result->CompleteWithError(
        kWebContentDecryptionModuleExceptionInvalidStateError, 0,
        "The context provided is invalid.");
    return;
  }

  // 5.1 Let cdm be the cdm during the initialization of this object.
  WebContentDecryptionModule* cdm = ContentDecryptionModule();

  // 5.2 Use the cdm to process certificate.
  cdm->SetServerCertificate(
      static_cast<unsigned char*>(server_certificate->Data()),
      server_certificate->ByteLength(), result->Result());

  // 5.3 If any of the preceding steps failed, reject promise with a
  //     new DOMException whose name is the appropriate error name.
  // 5.4 Resolve promise.
  // (These are handled by Chromium and the CDM.)
}

ScriptPromise<V8MediaKeyStatus> MediaKeys::getStatusForPolicy(
    ScriptState* script_state,
    const MediaKeysPolicy* media_keys_policy,
    ExceptionState& exception_state) {
  // If the context for MediaKeys has been destroyed, fail.
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The context provided is invalid.");
    return EmptyPromise();
  }

  // TODO(xhwang): Pass MediaKeysPolicy classes all the way to Chromium when
  // we have more than one policy to check.
  String min_hdcp_version = media_keys_policy->minHdcpVersion();

  // Let promise be a new promise.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8MediaKeyStatus>>(
          script_state, exception_state.GetContext());
  GetStatusForPolicyResultPromise* result =
      MakeGarbageCollected<GetStatusForPolicyResultPromise>(
          resolver, config_, min_hdcp_version, this);
  auto promise = resolver->Promise();

  // Run the following steps asynchronously. See GetStatusForPolicyTask().
  pending_actions_.push_back(
      PendingAction::CreatePendingGetStatusForPolicy(result, min_hdcp_version));
  if (!timer_.IsActive())
    timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  // Return promise.
  return promise;
}

void MediaKeys::GetStatusForPolicyTask(const String& min_hdcp_version,
                                       ContentDecryptionModuleResult* result) {
  DVLOG(MEDIA_KEYS_LOG_LEVEL) << __func__ << ": " << min_hdcp_version;

  // If the context has been destroyed, don't proceed. Try to have the promise
  // be rejected.
  if (!GetExecutionContext()) {
    result->CompleteWithError(
        kWebContentDecryptionModuleExceptionInvalidStateError, 0,
        "The context provided is invalid.");
    return;
  }

  WebContentDecryptionModule* cdm = ContentDecryptionModule();
  cdm->GetStatusForPolicy(min_hdcp_version, result->Result());
}

bool MediaKeys::ReserveForMediaElement(HTMLMediaElement* media_element) {
  // If some other HtmlMediaElement already has a reference to us, fail.
  if (media_element_)
    return false;

  media_element_ = media_element;
  reserved_for_media_element_ = true;
  return true;
}

void MediaKeys::AcceptReservation() {
  reserved_for_media_element_ = false;
}

void MediaKeys::CancelReservation() {
  reserved_for_media_element_ = false;
  media_element_.Clear();
}

void MediaKeys::ClearMediaElement() {
  DCHECK(media_element_);
  media_element_.Clear();
}

bool MediaKeys::SessionTypeSupported(
    WebEncryptedMediaSessionType session_type) {
  for (size_t i = 0; i < supported_session_types_.size(); i++) {
    if (supported_session_types_[i] == session_type)
      return true;
  }

  return false;
}

void MediaKeys::TimerFired(TimerBase*) {
  DCHECK(pending_actions_.size());

  // Swap the queue to a local copy to avoid problems if resolving promises
  // run synchronously.
  HeapDeque<Member<PendingAction>> pending_actions;
  pending_actions.Swap(pending_actions_);

  while (!pending_actions.empty()) {
    PendingAction* action = pending_actions.TakeFirst();

    switch (action->GetType()) {
      case PendingAction::Type::kSetServerCertificate:
        SetServerCertificateTask(action->Data(), action->Result());
        break;

      case PendingAction::Type::kGetStatusForPolicy:
        GetStatusForPolicyTask(action->StringData(), action->Result());
        break;

      default:
        NOTREACHED();
    }
  }
}

WebContentDecryptionModule* MediaKeys::ContentDecryptionModule() {
  return cdm_.get();
}

void MediaKeys::Trace(Visitor* visitor) const {
  visitor->Trace(pending_actions_);
  visitor->Trace(media_element_);
  visitor->Trace(timer_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void MediaKeys::ContextDestroyed() {
  timer_.Stop();
  pending_actions_.clear();

  // We don't need the CDM anymore. Only destroyed after all related
  // ExecutionContextLifecycleObservers have been stopped.
  cdm_.reset();
}

bool MediaKeys::HasPendingActivity() const {
  // Remain around if there are pending events.
  DVLOG(MEDIA_KEYS_LOG_LEVEL)
      << __func__ << "(" << this << ")"
      << (!pending_actions_.empty() ? " !pending_actions_.isEmpty()" : "")
      << (reserved_for_media_element_ ? " reserved_for_media_element_" : "");

  return !pending_actions_.empty() || reserved_for_media_element_;
}

}  // namespace blink

"""

```