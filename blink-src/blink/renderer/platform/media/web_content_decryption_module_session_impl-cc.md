Response: Let's break down the request and the provided code. The user wants to understand the functionality of the given C++ file, specifically within the context of the Chromium Blink engine's media handling.

**Mental Model of the File:**

This file (`web_content_decryption_module_session_impl.cc`) seems to be a core part of the Encrypted Media Extensions (EME) implementation in Blink. It likely manages the lifecycle and interactions of a single CDM (Content Decryption Module) session. Think of it as a bridge between JavaScript EME API calls and the underlying native CDM implementation.

**Decomposition of the Request:**

1. **List Functionalities:**  The primary goal is to enumerate what this C++ class *does*. This involves examining the methods of the class and their roles.

2. **Relationship to JavaScript, HTML, CSS:** This is crucial. EME is a web API, so understanding how this C++ code interacts with the web platform is key. I need to look for connections to web concepts.

3. **Logical Reasoning (Input/Output):**  For key methods, consider what data goes in and what happens as a result. This will help illustrate the flow of control and data.

4. **Common Usage Errors:** Since this is an implementation detail, user errors might be indirect, often stemming from incorrect usage of the JavaScript EME API. I need to infer potential pitfalls.

**Pre-computation and Pre-analysis:**

* **Class Name:** `WebContentDecryptionModuleSessionImpl` strongly suggests it implements the session aspect of the Web Content Decryption Module.
* **Includes:** The included headers give clues:
    * `media/base/...`:  Indicates interaction with Chromium's media framework.
    * `media/cdm/...`:  Specific to Content Decryption Modules.
    * `third_party/blink/public/platform/...`:  Blink's public platform interfaces, confirming the bridging role.
    * `third_party/blink/renderer/platform/media/...`: Other Blink media components.
* **Methods:**  The class has methods like `InitializeNewSession`, `Load`, `Update`, `Close`, `Remove`, `OnSessionMessage`, `OnSessionKeysChange`, etc. These directly correspond to steps in the EME workflow.
* **Sanitization Functions:** Functions like `SanitizeInitData`, `SanitizeSessionId`, and `SanitizeResponse` point to security and validation practices when interacting with CDM data.
* **UMA Reporting:** The presence of `base::UmaHistogram...` indicates that this code collects metrics about CDM session behavior.

**Step-by-Step Thought Process (Simulating the generation):**

1. **Core Functionality:** Start with the most obvious roles. It manages a CDM session. What does that entail?  Creating, loading, updating, closing, and removing sessions.

2. **Event Handling:**  Notice the `OnSession...` methods. These are clearly event handlers for notifications coming from the underlying CDM. Relate these to the EME specification (message, key change, expiration, close).

3. **Data Handling and Sanitization:** The `Sanitize...` functions are important. Explain *why* sanitization is necessary (security, compatibility). Give examples of what might be sanitized (length, format).

4. **Interaction with Web APIs:** Connect the C++ methods to the corresponding JavaScript EME API calls (`generateRequest`, `load`, `update`, `close`, `remove`, the `message` event, `keystatuseschange` event, etc.). This is the crucial link.

5. **Logical Reasoning (Input/Output Examples):**  For `InitializeNewSession` and `Update`, imagine concrete scenarios. What kind of `initData` might be passed? What kind of `response`?  What are the expected outcomes (success, failure, events)?

6. **Common Errors:** Think about common mistakes developers make when using EME. Incorrect `initData`, invalid responses, calling methods in the wrong order, not handling events properly.

7. **Internal Details (Less User-Facing):** Mention the adapter pattern and the role of `CdmSessionAdapter`. Briefly explain UMA reporting for context.

8. **Structure and Clarity:** Organize the information logically. Use clear headings and bullet points. Explain technical terms where necessary.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus solely on the direct CDM interactions.
* **Correction:** Realize the crucial role as a *bridge* to the web platform. Emphasize the connection to JavaScript APIs.
* **Initial thought:**  Explain the sanitization functions in isolation.
* **Correction:** Explain the *reason* for sanitization within the context of security and data validation between the browser and the CDM.
* **Initial thought:**  Provide very technical input/output examples.
* **Correction:**  Simplify the examples to be more illustrative and easier to understand.

By following this structured thought process and focusing on the key aspects of the code and its relationship to the broader web platform, I can generate a comprehensive and informative answer like the example provided.
这个文件 `web_content_decryption_module_session_impl.cc` 是 Chromium Blink 引擎中处理 **Web Content Decryption Module (CDM) 会话** 的核心实现。它负责管理与特定 CDM 实例的会话生命周期，处理来自 JavaScript 的请求，并转发 CDM 的事件到 JavaScript。

以下是它的主要功能：

**1. CDM 会话管理:**

* **创建和初始化新的 CDM 会话 (`InitializeNewSession`):**  接收来自 JavaScript 的 `generateRequest` 调用，用于请求密钥或许可证。它验证初始化数据类型和数据本身，然后调用底层的 CDM 方法来初始化会话。
* **加载已存在的 CDM 会话 (`Load`):** 接收来自 JavaScript 的 `load` 调用，用于加载之前持久化的会话。它验证会话 ID，并调用底层的 CDM 方法来加载会话。
* **更新 CDM 会话 (`Update`):** 接收来自 JavaScript 的 `update` 调用，提供来自许可证服务器的响应。它验证响应数据，并将其传递给底层的 CDM 进行处理。
* **关闭 CDM 会话 (`Close`):** 接收来自 JavaScript 的 `close` 调用，请求关闭当前会话。它通知底层的 CDM 关闭会话。
* **移除 CDM 会话 (`Remove`):** 接收来自 JavaScript 的 `remove` 调用，请求移除持久化的会话。它通知底层的 CDM 移除会话。

**2. 与 JavaScript 的通信桥梁:**

* **接收来自 JavaScript 的请求:**  上述的 `InitializeNewSession`, `Load`, `Update`, `Close`, `Remove` 方法都是作为接收 JavaScript 中 `MediaKeySession` 对象方法调用的入口点。
* **将 CDM 事件转发到 JavaScript:**
    * **`OnSessionMessage`:**  当 CDM 生成消息（例如，许可证请求）时，此方法被调用，并将消息转发到 JavaScript 的 `message` 事件。
    * **`OnSessionKeysChange`:** 当 CDM 的密钥状态发生变化时（例如，密钥变为可用、过期），此方法被调用，并将密钥信息转发到 JavaScript 的 `keystatuseschange` 事件。
    * **`OnSessionExpirationUpdate`:** 当 CDM 更新会话过期时间时，此方法被调用，并将新的过期时间转发到 JavaScript。
    * **`OnSessionClosed`:** 当 CDM 关闭会话时，此方法被调用，并将关闭原因转发到 JavaScript 的 `close` 事件。
* **设置客户端接口 (`SetClientInterface`):** 允许将一个 `Client` 对象（通常是 `MediaKeySession` 的 Blink 实现）连接到这个 `WebContentDecryptionModuleSessionImpl` 实例，用于事件转发。

**3. 数据验证和清理:**

* **`SanitizeInitData`:** 验证并清理来自 JavaScript 的初始化数据（用于 `generateRequest`）。这包括检查数据长度、格式，并确保数据对指定的初始化数据类型有效。
* **`SanitizeSessionId`:** 验证会话 ID（用于 `load`），确保其格式和长度合理。
* **`SanitizeResponse`:** 验证并清理来自 JavaScript 的响应数据（用于 `update`）。这可能包括检查长度、格式，以及移除无关数据。

**4. 度量和统计 (UMA):**

* 使用 `base::UmaHistogram...` 记录各种操作的成功与否和状态，例如 `GenerateRequest`, `LoadSession`, `UpdateSession` 等。这有助于 Chromium 团队了解 EME 的使用情况和潜在问题。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件本身不直接涉及 HTML 或 CSS 的解析和渲染。它的主要作用是处理与 JavaScript EME API 相关的逻辑。

* **JavaScript:** `WebContentDecryptionModuleSessionImpl` 是 JavaScript 中 `MediaKeySession` 对象在 Blink 渲染引擎中的底层实现。
    * **举例:** 当 JavaScript 代码调用 `mediaKeySession.generateRequest(initDataType, initData)` 时，Blink 会调用 `WebContentDecryptionModuleSessionImpl::InitializeNewSession` 方法，并将 `initDataType` 和 `initData` 传递给它。
    * **举例:** 当 CDM 生成许可证请求消息时，`WebContentDecryptionModuleSessionImpl::OnSessionMessage` 会被调用，然后它会调用 `client_->OnSessionMessage`，最终导致 JavaScript 中 `MediaKeySession` 对象的 `message` 事件被触发。

* **HTML:** HTML 的 `<video>` 或 `<audio>` 元素通过 `HTMLMediaElement` 接口与 EME API 交互。
    * **举例:**  HTML 中定义了一个 `<video>` 元素，并且 JavaScript 代码为该元素创建了 `MediaKeys` 对象并关联了 CDM。当播放加密内容时，JavaScript 使用 `MediaKeySession` 对象来处理密钥交换，这会触发 `WebContentDecryptionModuleSessionImpl` 中的相应方法。

* **CSS:** CSS 与 EME 的交互非常间接。CSS 可能影响视频播放器的外观，但它不直接控制解密过程。

**逻辑推理、假设输入与输出:**

**假设输入 (对于 `InitializeNewSession`):**

* `eme_init_data_type`: `EmeInitDataType::CENC` (Common Encryption)
* `init_data`: 一个包含 PSSH box 的二进制数据，用于标识加密方案和密钥系统。
* `session_type`: `WebEncryptedMediaSessionType::kTemporary`

**逻辑推理:**

1. `InitializeNewSession` 方法首先检查 `CENC` 是否是当前 CDM 支持的初始化数据类型。
2. 它调用 `SanitizeInitData` 来验证和清理 `init_data`，确保 PSSH box 的格式正确。
3. 如果验证通过，它会调用底层的 CDM 方法来初始化一个新的临时会话，并将清理后的初始化数据传递给 CDM。
4. CDM 可能会生成一个许可证请求消息。

**输出 (取决于 CDM 的行为):**

* **成功:** CDM 会创建一个新的会话，并返回一个会话 ID。`OnSessionInitialized` 会被调用，并将新的会话 ID 传递给 `WebContentDecryptionModuleSessionImpl`。
* **失败:** CDM 初始化失败，`WebContentDecryptionModuleResult` 会包含错误信息，并传递回 JavaScript，导致 `generateRequest` 的 Promise 被拒绝。
* **生成消息:** CDM 生成许可证请求消息，`OnSessionMessage` 被调用，并将消息转发到 JavaScript 的 `message` 事件。

**涉及用户或编程常见的使用错误及举例说明:**

1. **传递无效的初始化数据 (`generateRequest`):**
   * **错误:** JavaScript 代码传递了一个格式错误的 PSSH box 或者一个不支持的初始化数据类型。
   * **后果:** `SanitizeInitData` 会返回 `false`，`InitializeNewSession` 会调用 `result.CompleteWithError`，JavaScript 中的 `generateRequest` Promise 会被 `TypeError` 或 `NotSupportedError` 拒绝。

2. **传递无效的许可证响应 (`update`):**
   * **错误:** JavaScript 代码接收到一个来自许可证服务器的响应，但该响应的格式不正确，或者包含无效的数据。
   * **后果:** `SanitizeResponse` 会返回 `false`，`Update` 会调用 `result.CompleteWithError`，JavaScript 中的 `update` Promise 会被 `TypeError` 拒绝。

3. **在会话未创建或已关闭的情况下调用方法 (`update`, `close`, `remove`):**
   * **错误:** JavaScript 代码尝试在 `generateRequest` 成功返回之前调用 `update`，或者在一个已经关闭的会话上调用 `close`。
   * **后果:** 这些方法通常会检查会话状态，并可能直接返回错误或抛出异常（尽管在这个 C++ 文件中，更多的是依赖底层 CDM 的行为）。

4. **未正确处理会话事件 (`message`, `keystatuseschange`):**
   * **错误:** JavaScript 代码没有监听或正确处理 `MediaKeySession` 对象的 `message` 或 `keystatuseschange` 事件。
   * **后果:** 应用程序可能无法获得许可证或无法响应密钥状态的变化，导致播放失败。

5. **会话 ID 处理错误 (`load`):**
   * **错误:**  对于持久化会话，JavaScript 代码尝试加载一个不存在或格式错误的会话 ID。
   * **后果:** `SanitizeSessionId` 可能会返回 `false`，或者底层的 CDM 无法找到对应的会话，导致 `Load` 操作失败。

总而言之，`web_content_decryption_module_session_impl.cc` 是 Blink 引擎中 EME 功能的关键组成部分，它负责与 CDM 的交互，管理会话生命周期，并确保与 JavaScript EME API 的正确通信。它还包含安全相关的逻辑，例如数据验证和清理，以防止恶意或格式错误的数据传递给 CDM。

Prompt: 
```
这是目录为blink/renderer/platform/media/web_content_decryption_module_session_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/media/web_content_decryption_module_session_impl.h"

#include <memory>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "media/base/cdm_key_information.h"
#include "media/base/cdm_promise.h"
#include "media/base/content_decryption_module.h"
#include "media/base/key_system_names.h"
#include "media/base/key_systems.h"
#include "media/base/limits.h"
#include "media/cdm/cenc_utils.h"
#include "media/cdm/json_web_key.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_encrypted_media_key_information.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/renderer/platform/media/cdm_result_promise.h"
#include "third_party/blink/renderer/platform/media/cdm_result_promise_helper.h"
#include "third_party/blink/renderer/platform/media/cdm_session_adapter.h"
#include "third_party/blink/renderer/platform/media/media_player_util.h"

namespace blink {

namespace {

const char kCloseSessionUMAName[] = "CloseSession";
const char kGenerateRequestUMAName[] = "GenerateRequest";
const char kLoadSessionUMAName[] = "LoadSession";
const char kRemoveSessionUMAName[] = "RemoveSession";
const char kUpdateSessionUMAName[] = "UpdateSession";
const char kKeyStatusSystemCodeUMAName[] = "KeyStatusSystemCode";
const char kInitialKeyStatusMixUMAName[] = "InitialKeyStatusMix";

media::CdmSessionType ConvertSessionType(
    WebEncryptedMediaSessionType session_type) {
  switch (session_type) {
    case WebEncryptedMediaSessionType::kTemporary:
      return media::CdmSessionType::kTemporary;
    case WebEncryptedMediaSessionType::kPersistentLicense:
      return media::CdmSessionType::kPersistentLicense;
    case WebEncryptedMediaSessionType::kUnknown:
      break;
  }

  NOTREACHED();
}

bool SanitizeInitData(media::EmeInitDataType init_data_type,
                      const unsigned char* init_data,
                      size_t init_data_length,
                      std::vector<uint8_t>* sanitized_init_data,
                      std::string* error_message) {
  DCHECK_GT(init_data_length, 0u);
  if (init_data_length > media::limits::kMaxInitDataLength) {
    error_message->assign("Initialization data too long.");
    return false;
  }

  switch (init_data_type) {
    case media::EmeInitDataType::WEBM:
      // |init_data| for WebM is a single key.
      if (init_data_length > media::limits::kMaxKeyIdLength) {
        error_message->assign("Initialization data for WebM is too long.");
        return false;
      }
      sanitized_init_data->assign(init_data, init_data + init_data_length);
      return true;

    case media::EmeInitDataType::CENC:
      sanitized_init_data->assign(init_data, init_data + init_data_length);
      if (!media::ValidatePsshInput(*sanitized_init_data)) {
        error_message->assign("Initialization data for CENC is incorrect.");
        return false;
      }
      return true;

    case media::EmeInitDataType::KEYIDS: {
      // Extract the keys and then rebuild the message. This ensures that any
      // extra data in the provided JSON is dropped.
      std::string init_data_string(init_data, init_data + init_data_length);
      media::KeyIdList key_ids;
      if (!media::ExtractKeyIdsFromKeyIdsInitData(init_data_string, &key_ids,
                                                  error_message))
        return false;

      for (const auto& key_id : key_ids) {
        if (key_id.size() < media::limits::kMinKeyIdLength ||
            key_id.size() > media::limits::kMaxKeyIdLength) {
          error_message->assign("Incorrect key size.");
          return false;
        }
      }

      media::CreateKeyIdsInitData(key_ids, sanitized_init_data);
      return true;
    }

    case media::EmeInitDataType::UNKNOWN:
      break;
  }

  NOTREACHED();
}

bool SanitizeSessionId(const WebString& session_id,
                       std::string* sanitized_session_id) {
  // The user agent should thoroughly validate the sessionId value before
  // passing it to the CDM. At a minimum, this should include checking that
  // the length and value (e.g. alphanumeric) are reasonable.
  if (!session_id.ContainsOnlyASCII())
    return false;

  sanitized_session_id->assign(session_id.Ascii());
  if (sanitized_session_id->length() > media::limits::kMaxSessionIdLength)
    return false;

  // Check that |sanitized_session_id| only contains printable characters for
  // easier logging. Note that checking alphanumeric is too strict because there
  // are key systems using Base64 session IDs (which may include spaces). See
  // https://crbug.com/902828.
  for (const char c : *sanitized_session_id) {
    if (!base::IsAsciiPrintable(c))
      return false;
  }

  return true;
}

bool SanitizeResponse(const std::string& key_system,
                      const uint8_t* response,
                      size_t response_length,
                      std::vector<uint8_t>* sanitized_response) {
  // The user agent should thoroughly validate the response before passing it
  // to the CDM. This may include verifying values are within reasonable limits,
  // stripping irrelevant data or fields, pre-parsing it, sanitizing it,
  // and/or generating a fully sanitized version. The user agent should check
  // that the length and values of fields are reasonable. Unknown fields should
  // be rejected or removed.
  if (response_length > media::limits::kMaxSessionResponseLength)
    return false;

  if (media::IsClearKey(key_system) || media::IsExternalClearKey(key_system)) {
    std::string key_string(response, response + response_length);
    media::KeyIdAndKeyPairs keys;
    auto session_type = media::CdmSessionType::kTemporary;
    if (!ExtractKeysFromJWKSet(key_string, &keys, &session_type))
      return false;

    // Must contain at least one key.
    if (keys.empty())
      return false;

    for (const auto& key_pair : keys) {
      if (key_pair.first.size() < media::limits::kMinKeyIdLength ||
          key_pair.first.size() > media::limits::kMaxKeyIdLength) {
        return false;
      }
    }

    std::string sanitized_data = GenerateJWKSet(keys, session_type);
    sanitized_response->assign(sanitized_data.begin(), sanitized_data.end());
    return true;
  }

  // TODO(jrummell): Verify responses for Widevine.
  sanitized_response->assign(response, response + response_length);
  return true;
}

// Reported to UMA. Do NOT change or reuse existing values.
enum class KeyStatusMixForUma {
  kAllUsable = 0,
  kAllInternalError = 1,
  kAllExpired = 2,
  kAllOutputRestricted = 3,
  kAllOutputDownscaled = 4,
  kAllKeyStatusPending = 5,
  kAllReleased = 6,
  kEmpty = 7,
  kMixedWithUsable = 8,
  kMixedWithoutUsable = 9,
  kMaxValue = kMixedWithoutUsable
};

KeyStatusMixForUma GetKeyStatusMixForUma(const media::CdmKeysInfo& keys_info) {
  if (keys_info.empty()) {
    return KeyStatusMixForUma::kEmpty;
  }

  bool has_usable = false;
  bool is_mixed = false;
  auto key_status = keys_info[0]->status;

  for (const auto& key_info : keys_info) {
    if (key_info->status == media::CdmKeyInformation::KeyStatus::USABLE) {
      has_usable = true;
    }
    if (key_info->status != key_status) {
      is_mixed = true;
    }
  }

  if (!is_mixed) {
    switch (key_status) {
      case media::CdmKeyInformation::KeyStatus::USABLE:
        return KeyStatusMixForUma::kAllUsable;
      case media::CdmKeyInformation::KeyStatus::INTERNAL_ERROR:
        return KeyStatusMixForUma::kAllInternalError;
      case media::CdmKeyInformation::KeyStatus::EXPIRED:
        return KeyStatusMixForUma::kAllExpired;
      case media::CdmKeyInformation::KeyStatus::OUTPUT_RESTRICTED:
        return KeyStatusMixForUma::kAllOutputRestricted;
      case media::CdmKeyInformation::KeyStatus::OUTPUT_DOWNSCALED:
        return KeyStatusMixForUma::kAllOutputDownscaled;
      case media::CdmKeyInformation::KeyStatus::KEY_STATUS_PENDING:
        return KeyStatusMixForUma::kAllKeyStatusPending;
      case media::CdmKeyInformation::KeyStatus::RELEASED:
        return KeyStatusMixForUma::kAllReleased;
    }
  } else {
    return has_usable ? KeyStatusMixForUma::kMixedWithUsable
                      : KeyStatusMixForUma::kMixedWithoutUsable;
  }
}

}  // namespace

WebContentDecryptionModuleSessionImpl::WebContentDecryptionModuleSessionImpl(
    const scoped_refptr<CdmSessionAdapter>& adapter,
    WebEncryptedMediaSessionType session_type,
    media::KeySystems* key_systems)
    : adapter_(adapter),
      session_type_(ConvertSessionType(session_type)),
      key_systems_(key_systems),
      has_close_been_called_(false),
      is_closed_(false) {
  DCHECK(key_systems_);
}

WebContentDecryptionModuleSessionImpl::
    ~WebContentDecryptionModuleSessionImpl() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!session_id_.empty()) {
    adapter_->UnregisterSession(session_id_);

    // From http://w3c.github.io/encrypted-media/#mediakeysession-interface
    // "If a MediaKeySession object is not closed when it becomes inaccessible
    // to the page, the CDM shall close the key session associated with the
    // object."
    //
    // This object is destroyed when the corresponding blink object is no
    // longer needed (which may be due to it becoming inaccessible to the
    // page), so if the session is not closed and CloseSession() has not yet
    // been called, call CloseSession() now. Since this object is being
    // destroyed, there is no need for the promise to do anything as this
    // session will be gone.
    if (!is_closed_ && !has_close_been_called_) {
      adapter_->CloseSession(session_id_,
                             std::make_unique<media::DoNothingCdmPromise<>>());
    }
  }
}

void WebContentDecryptionModuleSessionImpl::SetClientInterface(Client* client) {
  client_ = client;
}

WebString WebContentDecryptionModuleSessionImpl::SessionId() const {
  return WebString::FromUTF8(session_id_);
}

void WebContentDecryptionModuleSessionImpl::InitializeNewSession(
    media::EmeInitDataType eme_init_data_type,
    const unsigned char* init_data,
    size_t init_data_length,
    WebContentDecryptionModuleResult result) {
  DCHECK(init_data);
  DCHECK(session_id_.empty());
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // From https://w3c.github.io/encrypted-media/#generateRequest.
  // 6. If the Key System implementation represented by this object's cdm
  //    implementation value does not support initDataType as an Initialization
  //    Data Type, return a promise rejected with a NotSupportedError.
  //    String comparison is case-sensitive.
  if (!key_systems_->IsSupportedInitDataType(adapter_->GetKeySystem(),
                                             eme_init_data_type)) {
    std::string message =
        "The initialization data type is not supported by the key system.";
    result.CompleteWithError(
        kWebContentDecryptionModuleExceptionNotSupportedError, 0,
        WebString::FromUTF8(message));
    return;
  }

  // 10.1 If the init data is not valid for initDataType, reject promise with
  //      a newly created TypeError.
  // 10.2 Let sanitized init data be a validated and sanitized version of init
  //      data. The user agent must thoroughly validate the Initialization Data
  //      before passing it to the CDM. This includes verifying that the length
  //      and values of fields are reasonable, verifying that values are within
  //      reasonable limits, and stripping irrelevant, unsupported, or unknown
  //      data or fields. It is recommended that user agents pre-parse,
  //      sanitize, and/or generate a fully sanitized version of the
  //      Initialization Data. If the Initialization Data format specified by
  //      initDataType supports multiple entries, the user agent should remove
  //      entries that are not needed by the CDM. The user agent must not
  //      re-order entries within the Initialization Data.
  // 10.3 If the preceding step failed, reject promise with a newly created
  //      TypeError.
  std::vector<uint8_t> sanitized_init_data;
  std::string message;
  if (!SanitizeInitData(eme_init_data_type, init_data, init_data_length,
                        &sanitized_init_data, &message)) {
    result.CompleteWithError(kWebContentDecryptionModuleExceptionTypeError, 0,
                             WebString::FromUTF8(message));
    return;
  }

  // 10.4 If sanitized init data is empty, reject promise with a
  //      NotSupportedError.
  if (sanitized_init_data.empty()) {
    result.CompleteWithError(
        kWebContentDecryptionModuleExceptionNotSupportedError, 0,
        "No initialization data provided.");
    return;
  }

  // 10.5 Let session id be the empty string.
  //      (Done in constructor.)

  // 10.6 Let message be null.
  // 10.7 Let message type be null.
  //      (Done by CDM.)

  // 10.8 Let cdm be the CDM instance represented by this object's cdm
  //      instance value.
  // 10.9 Use the cdm to execute the following steps:
  adapter_->InitializeNewSession(
      eme_init_data_type, sanitized_init_data, session_type_,
      std::make_unique<NewSessionCdmResultPromise>(
          result, adapter_->GetKeySystemUMAPrefix(), kGenerateRequestUMAName,
          base::BindOnce(
              &WebContentDecryptionModuleSessionImpl::OnSessionInitialized,
              weak_ptr_factory_.GetWeakPtr()),
          std::vector<SessionInitStatus>{SessionInitStatus::NEW_SESSION}));
}

void WebContentDecryptionModuleSessionImpl::Load(
    const WebString& session_id,
    WebContentDecryptionModuleResult result) {
  DCHECK(!session_id.IsEmpty());
  DCHECK(session_id_.empty());
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(session_type_ == media::CdmSessionType::kPersistentLicense);

  // From https://w3c.github.io/encrypted-media/#load.
  // 8.1 Let sanitized session ID be a validated and/or sanitized version of
  //     sessionId. The user agent should thoroughly validate the sessionId
  //     value before passing it to the CDM. At a minimum, this should include
  //     checking that the length and value (e.g. alphanumeric) are reasonable.
  // 8.2 If the preceding step failed, or if sanitized session ID is empty,
  //     reject promise with a newly created TypeError.
  std::string sanitized_session_id;
  if (!SanitizeSessionId(session_id, &sanitized_session_id)) {
    result.CompleteWithError(kWebContentDecryptionModuleExceptionTypeError, 0,
                             "Invalid session ID.");
    return;
  }

  adapter_->LoadSession(
      session_type_, sanitized_session_id,
      std::make_unique<NewSessionCdmResultPromise>(
          result, adapter_->GetKeySystemUMAPrefix(), kLoadSessionUMAName,
          base::BindOnce(
              &WebContentDecryptionModuleSessionImpl::OnSessionInitialized,
              weak_ptr_factory_.GetWeakPtr()),
          std::vector<SessionInitStatus>{
              SessionInitStatus::NEW_SESSION,
              SessionInitStatus::SESSION_NOT_FOUND}));
}

void WebContentDecryptionModuleSessionImpl::Update(
    const uint8_t* response,
    size_t response_length,
    WebContentDecryptionModuleResult result) {
  DCHECK(response);
  DCHECK(!session_id_.empty());
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // From https://w3c.github.io/encrypted-media/#update.
  // 6.1 Let sanitized response be a validated and/or sanitized version of
  //     response copy. The user agent should thoroughly validate the response
  //     before passing it to the CDM. This may include verifying values are
  //     within reasonable limits, stripping irrelevant data or fields,
  //     pre-parsing it, sanitizing it, and/or generating a fully sanitized
  //     version. The user agent should check that the length and values of
  //     fields are reasonable. Unknown fields should be rejected or removed.
  // 6.2 If the preceding step failed, or if sanitized response is empty,
  //     reject promise with a newly created TypeError.
  std::vector<uint8_t> sanitized_response;
  if (!SanitizeResponse(adapter_->GetKeySystem(), response, response_length,
                        &sanitized_response)) {
    result.CompleteWithError(kWebContentDecryptionModuleExceptionTypeError, 0,
                             "Invalid response.");
    return;
  }

  adapter_->UpdateSession(
      session_id_, sanitized_response,
      std::make_unique<CdmResultPromise<>>(
          result, adapter_->GetKeySystemUMAPrefix(), kUpdateSessionUMAName));
}

void WebContentDecryptionModuleSessionImpl::Close(
    WebContentDecryptionModuleResult result) {
  DCHECK(!session_id_.empty());
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // close() shouldn't be called if the session is already closed. Since the
  // operation is asynchronous, there is a window where close() was called
  // just before the closed event arrives. The CDM should handle the case where
  // close() is called after it has already closed the session. However, if
  // we can tell the session is now closed, simply resolve the promise.
  if (is_closed_) {
    result.Complete();
    return;
  }

  has_close_been_called_ = true;
  adapter_->CloseSession(
      session_id_,
      std::make_unique<CdmResultPromise<>>(
          result, adapter_->GetKeySystemUMAPrefix(), kCloseSessionUMAName));
}

void WebContentDecryptionModuleSessionImpl::Remove(
    WebContentDecryptionModuleResult result) {
  DCHECK(!session_id_.empty());
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  adapter_->RemoveSession(
      session_id_,
      std::make_unique<CdmResultPromise<>>(
          result, adapter_->GetKeySystemUMAPrefix(), kRemoveSessionUMAName));
}

void WebContentDecryptionModuleSessionImpl::OnSessionMessage(
    media::CdmMessageType message_type,
    const std::vector<uint8_t>& message) {
  DCHECK(client_) << "Client not set before message event";
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  client_->OnSessionMessage(message_type, message.data(), message.size());
}

void WebContentDecryptionModuleSessionImpl::OnSessionKeysChange(
    bool has_additional_usable_key,
    media::CdmKeysInfo keys_info) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  WebVector<WebEncryptedMediaKeyInformation> keys(keys_info.size());
  for (size_t i = 0; i < keys_info.size(); ++i) {
    auto& key_info = keys_info[i];
    keys[i].SetId(WebData(reinterpret_cast<char*>(key_info->key_id.data()),
                          key_info->key_id.size()));
    keys[i].SetStatus(ConvertCdmKeyStatus(key_info->status));
    keys[i].SetSystemCode(key_info->system_code);

    base::UmaHistogramSparse(
        adapter_->GetKeySystemUMAPrefix() + kKeyStatusSystemCodeUMAName,
        key_info->system_code);
  }

  // Only report the UMA on the first keys change event per session.
  if (!has_key_status_uma_reported_) {
    has_key_status_uma_reported_ = true;
    auto key_status_mix_for_uma = GetKeyStatusMixForUma(keys_info);
    base::UmaHistogramEnumeration(
        adapter_->GetKeySystemUMAPrefix() + kInitialKeyStatusMixUMAName,
        key_status_mix_for_uma);
  }

  // Now send the event to blink.
  client_->OnSessionKeysChange(keys, has_additional_usable_key);
}

void WebContentDecryptionModuleSessionImpl::OnSessionExpirationUpdate(
    base::Time new_expiry_time) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // The check works around an issue in base::Time that converts null base::Time
  // to |1601-01-01 00:00:00 UTC| in InMillisecondsFSinceUnixEpoch(). See
  // http://crbug.com/679079
  client_->OnSessionExpirationUpdate(
      new_expiry_time.is_null()
          ? std::numeric_limits<double>::quiet_NaN()
          : new_expiry_time.InMillisecondsFSinceUnixEpoch());
}

void WebContentDecryptionModuleSessionImpl::OnSessionClosed(
    media::CdmSessionClosedReason reason) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Only send one closed event to blink.
  if (is_closed_)
    return;

  is_closed_ = true;
  client_->OnSessionClosed(reason);
}

void WebContentDecryptionModuleSessionImpl::OnSessionInitialized(
    const std::string& session_id,
    SessionInitStatus* status) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // CDM will return NULL if the session to be loaded can't be found.
  if (session_id.empty()) {
    *status = SessionInitStatus::SESSION_NOT_FOUND;
    return;
  }

  DCHECK(session_id_.empty()) << "Session ID may not be changed once set.";
  session_id_ = session_id;
  *status =
      adapter_->RegisterSession(session_id_, weak_ptr_factory_.GetWeakPtr())
          ? SessionInitStatus::NEW_SESSION
          : SessionInitStatus::SESSION_ALREADY_EXISTS;
}

}  // namespace blink

"""

```