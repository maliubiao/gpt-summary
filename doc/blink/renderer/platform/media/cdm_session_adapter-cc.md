Response: Let's break down the thought process for analyzing the `cdm_session_adapter.cc` file.

1. **Understand the Core Purpose:** The filename itself, "cdm_session_adapter.cc," strongly suggests this class is an adapter for managing Content Decryption Module (CDM) sessions. CDMs are fundamental to Encrypted Media Extensions (EME), which is about playing protected content on the web. The "adapter" part implies it bridges between Blink's internal representation and the underlying CDM implementation.

2. **Identify Key Dependencies:** Look at the `#include` directives. These are crucial for understanding the components this class interacts with:
    * `third_party/blink/renderer/platform/media/cdm_session_adapter.h`:  The header file, defining the class interface.
    * `<memory>`, `<utility>`: Standard C++ for memory management.
    * `base/containers/contains.h`:  For checking if a key exists in a container (like a map).
    * `base/functional/bind.h`: For creating function objects (callbacks).
    * `base/logging.h`: For logging messages.
    * `base/metrics/...`: For recording performance data.
    * `base/trace_event/...`: For tracing execution flow.
    * `base/types/pass_key.h`:  A security mechanism to control access.
    * `media/base/...`: Classes related to media and CDMs.
    * `media/cdm/...`: Specific CDM-related classes.
    * `third_party/blink/renderer/platform/media/create_cdm_uma_helper.h`: For reporting CDM creation statistics.
    * `third_party/blink/renderer/platform/media/web_content_decryption_module_session_impl.h`:  Represents a CDM session in Blink's context.

3. **Analyze the Class Structure:** Look at the member variables and methods:
    * **Member Variables:**
        * `key_systems_`: Pointer to a `media::KeySystems` object. Likely holds information about supported key systems.
        * `trace_id_`: For tracking asynchronous operations.
        * `weak_ptr_factory_`: For creating weak pointers to avoid circular dependencies.
        * `web_cdm_created_cb_`: Callback to notify when a CDM is created.
        * `cdm_`:  A `scoped_refptr` to the `media::ContentDecryptionModule`. This is the core CDM object.
        * `sessions_`: A map to store active `WebContentDecryptionModuleSessionImpl` objects, keyed by session ID.
        * `cdm_config_`: Stores the configuration used to create the CDM.
        * `key_system_uma_prefix_`:  Prefix for UMA metrics related to the key system.
    * **Methods:** Group them by functionality:
        * **CDM Creation:** `CreateCdm`, `OnCdmCreated`.
        * **Session Management:** `CreateSession`, `RegisterSession`, `UnregisterSession`, `InitializeNewSession`, `LoadSession`, `UpdateSession`, `CloseSession`, `RemoveSession`, `GetSession`.
        * **CDM Interaction:** `SetServerCertificate`, `GetStatusForPolicy`, `GetCdmContextRef`.
        * **Event Handling (Callbacks from CDM):** `OnSessionMessage`, `OnSessionKeysChange`, `OnSessionExpirationUpdate`, `OnSessionClosed`.
        * **Information Retrieval:** `GetKeySystem`, `GetKeySystemUMAPrefix`, `GetCdmConfig`.

4. **Map Functionality to EME Concepts:** Connect the identified methods to the EME workflow:
    * **`CreateCdm`:** Corresponds to the browser trying to instantiate a CDM for a specific key system.
    * **Session Methods:** Directly relate to the session lifecycle in EME (creating, loading, updating keys, closing, removing).
    * **Event Handlers:** These methods process events fired by the underlying CDM and propagate them to the JavaScript layer. For example, `OnSessionMessage` delivers license requests.

5. **Consider the Interactions with JavaScript/HTML/CSS:**
    * **JavaScript:** The `WebContentDecryptionModuleSessionImpl` is the bridge to the JavaScript `MediaKeySession` object. The events received from the CDM (via the `OnSession*` methods) are ultimately passed to the JavaScript callbacks defined by the website. The `CreateSession` method is used when JavaScript calls `createMediaKeys()` and then `createSession()`.
    * **HTML:** The `<video>` or `<audio>` element is where the protected media is played. EME is used to get the necessary decryption keys.
    * **CSS:**  Generally, CSS is not directly involved in the core EME process. However, CSS might be used to style elements related to error messages or loading indicators during the decryption process.

6. **Identify Potential User/Programming Errors:** Look for areas where incorrect usage could lead to issues:
    * **Incorrect Promise Handling:**  The code uses `std::unique_ptr<...Promise>`. Not resolving or rejecting these promises correctly can lead to stalled operations.
    * **Session ID Mismatches:**  Passing an incorrect `session_id` to methods like `UpdateSession` will fail.
    * **Calling Methods Before CDM is Ready:**  Trying to interact with the CDM before `OnCdmCreated` is called would result in errors (likely a null pointer dereference).
    * **Registering Sessions Multiple Times:** The `RegisterSession` method checks for existing IDs, highlighting this as a potential error.

7. **Infer Logic and Assumptions:**
    * **Assumption:** The code assumes a one-to-many relationship between the `CdmSessionAdapter` and `WebContentDecryptionModuleSessionImpl` objects. One adapter manages multiple sessions.
    * **Input/Output for `RegisterSession`:**  Input: `session_id` (string), `session` (weak pointer). Output: `true` if registered, `false` if already exists.

8. **Structure the Answer:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logic/Assumptions, Common Errors. Use bullet points and code snippets (where relevant but not necessary in this case due to the length of the original code) for clarity.

By following these steps, we can systematically analyze the source code and understand its role within the larger Blink rendering engine and the context of web media playback.
这个 `cdm_session_adapter.cc` 文件是 Chromium Blink 引擎中负责管理 **Content Decryption Module (CDM) 会话** 的一个关键组件。它的主要功能是作为 Blink 和底层的 CDM 实现之间的一个适配器。

以下是它更详细的功能列表，以及与 JavaScript、HTML、CSS 的关系说明、逻辑推理和常见错误示例：

**功能列表:**

1. **CDM 创建和管理:**
   - 负责创建和管理 CDM 实例。`CreateCdm` 方法接收 `media::CdmFactory` 和 `media::CdmConfig`，并异步地创建 CDM。
   - 跟踪 CDM 的创建状态，并通过回调 `OnCdmCreated` 通知上层模块 CDM 是否成功创建。
   - 存储创建成功的 CDM 实例 (`cdm_`) 和其配置信息 (`cdm_config_`)。

2. **CDM 会话生命周期管理:**
   - 提供创建新的 CDM 会话的功能 (`CreateSession`)，返回一个 `WebContentDecryptionModuleSessionImpl` 实例，该实例代表一个 JavaScript 中 `MediaKeySession` 对象。
   - 维护当前激活的 CDM 会话的集合 (`sessions_`)，使用会话 ID 作为键。
   - 允许注册和注销 CDM 会话 (`RegisterSession`, `UnregisterSession`)。

3. **CDM 会话操作的代理:**
   - 将 Blink 发起的会话操作（例如，生成请求、加载会话、更新会话、关闭会话、移除会话）代理到实际的 CDM 实例。这些操作对应于 `InitializeNewSession`, `LoadSession`, `UpdateSession`, `CloseSession`, `RemoveSession` 等方法。

4. **接收和处理 CDM 事件:**
   - 监听来自 CDM 的事件，例如会话消息、密钥改变、会话过期更新和会话关闭。这些事件通过回调方法 `OnSessionMessage`, `OnSessionKeysChange`, `OnSessionExpirationUpdate`, `OnSessionClosed` 接收。
   - 将这些事件转发到相应的 `WebContentDecryptionModuleSessionImpl` 实例，最终这些事件会传递给 JavaScript 中的 `MediaKeySession` 对象。

5. **提供 CDM 上下文:**
   - 提供获取 CDM 上下文的接口 (`GetCdmContextRef`)，这允许其他组件访问底层的 CDM 功能。

6. **设置服务器证书:**
   - 允许设置用于密钥交换的服务器证书 (`SetServerCertificate`)。

7. **获取策略状态:**
   - 允许查询特定 HDCP 版本策略的状态 (`GetStatusForPolicy`)。

8. **记录 UMA 指标:**
   - 在 CDM 创建过程中记录 UMA (User Metrics Analysis) 指标，例如创建状态和耗时。

**与 JavaScript, HTML, CSS 的关系:**

这个 `CdmSessionAdapter` 是实现 **Encrypted Media Extensions (EME)** 规范的关键部分，EME 允许 Web 应用程序与内容解密模块交互，以播放受保护的媒体内容。

* **JavaScript:**
    - `CdmSessionAdapter` 与 JavaScript 中的 `MediaKeys` 和 `MediaKeySession` API 直接相关。
    - 当 JavaScript 代码调用 `navigator.requestMediaKeySystemAccess()` 获取 `MediaKeys` 对象时，Blink 内部会创建 `CdmSessionAdapter`。
    - 当 JavaScript 代码在 `MediaKeys` 对象上调用 `createSession()` 创建新的会话时，`CdmSessionAdapter::CreateSession` 会被调用，并返回一个 `WebContentDecryptionModuleSessionImpl` 对象。
    - 来自 CDM 的事件（例如 `OnSessionMessage`）最终会通过 `WebContentDecryptionModuleSessionImpl` 传递给 JavaScript `MediaKeySession` 对象的 `message` 事件。
    - 密钥状态的改变（`OnSessionKeysChange`）会触发 JavaScript `MediaKeySession` 对象的 `keystatuseschange` 事件。
    - 会话过期更新（`OnSessionExpirationUpdate`）会触发 JavaScript `MediaKeySession` 对象的事件。
    - 会话关闭（`OnSessionClosed`）会触发 JavaScript `MediaKeySession` 对象的 `close` 事件。

    **举例说明:**

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
        var session = mediaKeys.createSession('temporary'); // CdmSessionAdapter::CreateSession 被调用
        session.addEventListener('message', function(event) { // 对应 CdmSessionAdapter::OnSessionMessage
            // 处理 license 请求
            console.log('License request:', event.message);
        });
        session.generateRequest('cenc', new Uint8Array([...])); // 触发 CDM 生成请求
    });
    ```

* **HTML:**
    - `CdmSessionAdapter` 的目的是为了能够解码 HTML 中的 `<video>` 或 `<audio>` 元素中的加密媒体内容。
    - HTML 提供了 `<video>` 标签，并可以使用 JavaScript 和 EME API 来管理媒体的解密过程。

    **举例说明:**

    ```html
    <video id="myVideo" controls src="encrypted_video.mp4"></video>
    <script>
        const video = document.getElementById('myVideo');
        // ... (EME 相关 JavaScript 代码，如上例) ...
    </script>
    ```

* **CSS:**
    - CSS 本身与 `CdmSessionAdapter` 的核心功能没有直接关系。
    - 然而，CSS 可以用于样式化与 EME 相关的 UI 元素，例如加载指示器、错误消息等。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码创建了一个新的会话并生成了一个初始化数据：

**假设输入:**

1. JavaScript 调用 `mediaKeys.createSession('temporary')`。
2. `CdmSessionAdapter::CreateSession` 被调用，创建一个新的 `WebContentDecryptionModuleSessionImpl` 实例。
3. JavaScript 调用 `session.generateRequest('cenc', initData)`，其中 `initData` 是一个包含加密信息的 `Uint8Array`。
4. `CdmSessionAdapter::InitializeNewSession` 被调用，`init_data_type` 为 'cenc'，`init_data` 为该 `Uint8Array`。

**输出:**

1. `CdmSessionAdapter::InitializeNewSession` 会调用底层的 CDM 方法来创建会话并生成一个 license 请求。
2. CDM 生成的 license 请求（一个字节数组）会通过 `CdmSessionAdapter::OnSessionMessage` 回调到 Blink。
3. `OnSessionMessage` 会将该消息传递给对应的 `WebContentDecryptionModuleSessionImpl` 实例。
4. `WebContentDecryptionModuleSessionImpl` 会触发 JavaScript `MediaKeySession` 对象的 `message` 事件，并将 license 请求作为 `event.message` 传递给 JavaScript。

**用户或编程常见的使用错误:**

1. **未正确处理 Promise:** EME API 大量使用 Promise。如果 JavaScript 代码未能正确处理 Promise 的 resolved 或 rejected 状态，可能导致会话创建失败或密钥更新失败。

   **举例说明:**

   ```javascript
   navigator.requestMediaKeySystemAccess(...)
       .then(function(keySystemAccess) { // 忘记处理异常情况，例如用户拒绝权限
           return keySystemAccess.createMediaKeys();
       })
       .then(function(mediaKeys) {
           // ...
       });
   ```

2. **会话 ID 管理错误:**  在某些情况下（例如 persistent-license 会话），需要存储和加载会话 ID。如果开发者未能正确存储或加载会话 ID，可能导致无法恢复之前的会话。

   **举例说明:**

   ```javascript
   // 尝试加载会话，但 session_id 可能为空或不正确
   session.load(session_id)
       .catch(function(error) {
           console.error("Failed to load session:", error); // 可能是因为 session_id 错误
       });
   ```

3. **不正确的初始化数据处理:**  `generateRequest` 方法的 `initData` 必须与 CDM 期望的格式一致。如果初始化数据不正确，CDM 可能无法生成正确的 license 请求。

   **举例说明:**

   ```javascript
   session.generateRequest('cenc', incorrectInitData); // incorrectInitData 格式错误
   ```

4. **过早或过晚调用 EME API:**  必须按照正确的顺序调用 EME API。例如，在创建会话之前不能尝试更新会话。

   **举例说明:**

   ```javascript
   session.update(response); // 在 generateRequest 之前调用 update，可能导致错误
   ```

5. **忘记监听必要的事件:**  开发者需要监听 `message` 和 `keystatuseschange` 等关键事件来处理 license 请求和密钥状态变化。如果忘记监听这些事件，将无法完成解密过程。

   **举例说明:**

   ```javascript
   var session = mediaKeys.createSession('temporary');
   // 忘记添加 'message' 事件监听器
   // ... 后续的 license 请求将无法处理
   ```

总而言之，`cdm_session_adapter.cc` 是 Blink 引擎中处理受保护媒体内容的核心组件，它负责与底层的 CDM 交互，并将 CDM 的状态和事件传递给上层的 JavaScript 代码，从而实现了 Web 上的加密媒体播放功能。理解它的功能对于开发和调试与 EME 相关的 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/platform/media/cdm_session_adapter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/cdm_session_adapter.h"

#include <memory>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_functions.h"
#include "base/trace_event/trace_event.h"
#include "base/types/pass_key.h"
#include "media/base/cdm_factory.h"
#include "media/base/cdm_key_information.h"
#include "media/base/cdm_promise.h"
#include "media/base/key_systems.h"
#include "media/cdm/cdm_context_ref_impl.h"
#include "third_party/blink/renderer/platform/media/create_cdm_uma_helper.h"
#include "third_party/blink/renderer/platform/media/web_content_decryption_module_session_impl.h"

namespace blink {
CdmSessionAdapter::CdmSessionAdapter(media::KeySystems* key_systems)
    : key_systems_(key_systems), trace_id_(0) {
  DCHECK(key_systems_);
}

CdmSessionAdapter::~CdmSessionAdapter() = default;

void CdmSessionAdapter::CreateCdm(media::CdmFactory* cdm_factory,
                                  const media::CdmConfig& cdm_config,
                                  WebCdmCreatedCB web_cdm_created_cb) {
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("media", "CdmSessionAdapter::CreateCdm",
                                    ++trace_id_);

  base::TimeTicks start_time = base::TimeTicks::Now();

  // Note: WebContentDecryptionModuleImpl::Create() calls this method without
  // holding a reference to the CdmSessionAdapter. Bind OnCdmCreated() with
  // |this| instead of |weak_this| to prevent |this| from being destructed.
  base::WeakPtr<CdmSessionAdapter> weak_this = weak_ptr_factory_.GetWeakPtr();

  DCHECK(!web_cdm_created_cb_);
  web_cdm_created_cb_ = std::move(web_cdm_created_cb);

  cdm_factory->Create(
      cdm_config,
      base::BindRepeating(&CdmSessionAdapter::OnSessionMessage, weak_this),
      base::BindRepeating(&CdmSessionAdapter::OnSessionClosed, weak_this),
      base::BindRepeating(&CdmSessionAdapter::OnSessionKeysChange, weak_this),
      base::BindRepeating(&CdmSessionAdapter::OnSessionExpirationUpdate,
                          weak_this),
      base::BindOnce(&CdmSessionAdapter::OnCdmCreated, this, cdm_config,
                     start_time));
}

void CdmSessionAdapter::SetServerCertificate(
    const std::vector<uint8_t>& certificate,
    std::unique_ptr<media::SimpleCdmPromise> promise) {
  cdm_->SetServerCertificate(certificate, std::move(promise));
}

void CdmSessionAdapter::GetStatusForPolicy(
    media::HdcpVersion min_hdcp_version,
    std::unique_ptr<media::KeyStatusCdmPromise> promise) {
  cdm_->GetStatusForPolicy(min_hdcp_version, std::move(promise));
}

std::unique_ptr<WebContentDecryptionModuleSessionImpl>
CdmSessionAdapter::CreateSession(WebEncryptedMediaSessionType session_type) {
  return std::make_unique<WebContentDecryptionModuleSessionImpl>(
      this, session_type, key_systems_);
}

bool CdmSessionAdapter::RegisterSession(
    const std::string& session_id,
    base::WeakPtr<WebContentDecryptionModuleSessionImpl> session) {
  // If this session ID is already registered, don't register it again.
  if (base::Contains(sessions_, session_id))
    return false;

  sessions_[session_id] = session;
  return true;
}

void CdmSessionAdapter::UnregisterSession(const std::string& session_id) {
  DCHECK(base::Contains(sessions_, session_id));
  sessions_.erase(session_id);
}

void CdmSessionAdapter::InitializeNewSession(
    media::EmeInitDataType init_data_type,
    const std::vector<uint8_t>& init_data,
    media::CdmSessionType session_type,
    std::unique_ptr<media::NewSessionCdmPromise> promise) {
  cdm_->CreateSessionAndGenerateRequest(session_type, init_data_type, init_data,
                                        std::move(promise));
}

void CdmSessionAdapter::LoadSession(
    media::CdmSessionType session_type,
    const std::string& session_id,
    std::unique_ptr<media::NewSessionCdmPromise> promise) {
  DVLOG(2) << __func__ << ": session_id = " << session_id;
  cdm_->LoadSession(session_type, session_id, std::move(promise));
}

void CdmSessionAdapter::UpdateSession(
    const std::string& session_id,
    const std::vector<uint8_t>& response,
    std::unique_ptr<media::SimpleCdmPromise> promise) {
  DVLOG(3) << __func__ << ": session_id = " << session_id;
  cdm_->UpdateSession(session_id, response, std::move(promise));
}

void CdmSessionAdapter::CloseSession(
    const std::string& session_id,
    std::unique_ptr<media::SimpleCdmPromise> promise) {
  DVLOG(2) << __func__ << ": session_id = " << session_id;
  cdm_->CloseSession(session_id, std::move(promise));
}

void CdmSessionAdapter::RemoveSession(
    const std::string& session_id,
    std::unique_ptr<media::SimpleCdmPromise> promise) {
  DVLOG(2) << __func__ << ": session_id = " << session_id;
  cdm_->RemoveSession(session_id, std::move(promise));
}

std::unique_ptr<media::CdmContextRef> CdmSessionAdapter::GetCdmContextRef() {
  DVLOG(2) << __func__;

  if (!cdm_->GetCdmContext()) {
    NOTREACHED() << "All CDMs should support CdmContext.";
  }

  return std::make_unique<media::CdmContextRefImpl>(cdm_);
}

const std::string& CdmSessionAdapter::GetKeySystem() const {
  return cdm_config_.key_system;
}

const std::string& CdmSessionAdapter::GetKeySystemUMAPrefix() const {
  DCHECK(!key_system_uma_prefix_.empty());
  return key_system_uma_prefix_;
}

const media::CdmConfig& CdmSessionAdapter::GetCdmConfig() const {
  DCHECK(cdm_);
  return cdm_config_;
}

void CdmSessionAdapter::OnCdmCreated(
    const media::CdmConfig& cdm_config,
    base::TimeTicks start_time,
    const scoped_refptr<media::ContentDecryptionModule>& cdm,
    media::CreateCdmStatus status) {
  DVLOG(1) << __func__ << ": "
           << (cdm ? "success" : "failure (" + base::ToString(status) + ")");
  DCHECK(!cdm_);

  TRACE_EVENT_NESTABLE_ASYNC_END2("media", "CdmSessionAdapter::CreateCdm",
                                  trace_id_, "success",
                                  (cdm ? "true" : "false"), "status", status);

  auto key_system_uma_prefix = GetUMAPrefixForCdm(cdm_config);
  ReportCreateCdmStatusUMA(key_system_uma_prefix, cdm != nullptr, status);

  if (!cdm) {
    std::move(web_cdm_created_cb_).Run(nullptr, status);
    return;
  }

  key_system_uma_prefix_ = std::move(key_system_uma_prefix);

  // Only report time for successful CDM creation.
  ReportCreateCdmTimeUMA(key_system_uma_prefix_,
                         base::TimeTicks::Now() - start_time);

  cdm_config_ = cdm_config;

  cdm_ = cdm;

  std::move(web_cdm_created_cb_)
      .Run(std::make_unique<WebContentDecryptionModuleImpl>(
               base::PassKey<CdmSessionAdapter>(), this, key_systems_),
           media::CreateCdmStatus::kSuccess);
}

void CdmSessionAdapter::OnSessionMessage(const std::string& session_id,
                                         media::CdmMessageType message_type,
                                         const std::vector<uint8_t>& message) {
  WebContentDecryptionModuleSessionImpl* session = GetSession(session_id);
  DLOG_IF(WARNING, !session) << __func__ << " for unknown session "
                             << session_id;
  if (session) {
    DVLOG(3) << __func__ << ": session_id = " << session_id;
    session->OnSessionMessage(message_type, message);
  }
}

void CdmSessionAdapter::OnSessionKeysChange(const std::string& session_id,
                                            bool has_additional_usable_key,
                                            media::CdmKeysInfo keys_info) {
  WebContentDecryptionModuleSessionImpl* session = GetSession(session_id);
  DLOG_IF(WARNING, !session) << __func__ << " for unknown session "
                             << session_id;
  if (session) {
    DVLOG(2) << __func__ << ": session_id = " << session_id;
    DVLOG(2) << "  - has_additional_usable_key = " << has_additional_usable_key;
    for (const auto& info : keys_info)
      DVLOG(2) << "  - " << *(info.get());

    session->OnSessionKeysChange(has_additional_usable_key,
                                 std::move(keys_info));
  }
}

void CdmSessionAdapter::OnSessionExpirationUpdate(const std::string& session_id,
                                                  base::Time new_expiry_time) {
  WebContentDecryptionModuleSessionImpl* session = GetSession(session_id);
  DLOG_IF(WARNING, !session) << __func__ << " for unknown session "
                             << session_id;
  if (session) {
    DVLOG(2) << __func__ << ": session_id = " << session_id;
    if (new_expiry_time.is_null())
      DVLOG(2) << "  - new_expiry_time = NaN";
    else
      DVLOG(2) << "  - new_expiry_time = " << new_expiry_time;

    session->OnSessionExpirationUpdate(new_expiry_time);
  }
}

void CdmSessionAdapter::OnSessionClosed(const std::string& session_id,
                                        media::CdmSessionClosedReason reason) {
  WebContentDecryptionModuleSessionImpl* session = GetSession(session_id);
  DLOG_IF(WARNING, !session)
      << __func__ << " for unknown session " << session_id;
  if (session) {
    DVLOG(2) << __func__ << ": session_id = " << session_id
             << ", reason = " << static_cast<int>(reason);
    session->OnSessionClosed(reason);
  }
}

WebContentDecryptionModuleSessionImpl* CdmSessionAdapter::GetSession(
    const std::string& session_id) {
  // Since session objects may get garbage collected, it is possible that there
  // are events coming back from the CDM and the session has been unregistered.
  // We can not tell if the CDM is firing events at sessions that never existed.
  auto session = sessions_.find(session_id);
  return (session != sessions_.end()) ? session->second.get() : NULL;
}

}  // namespace blink
```