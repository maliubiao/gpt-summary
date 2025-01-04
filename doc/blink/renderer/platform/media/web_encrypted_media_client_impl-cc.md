Response: Let's break down the request and plan the response.

**1. Understanding the Core Request:**

The user wants a detailed explanation of the `web_encrypted_media_client_impl.cc` file in the Chromium Blink engine. The request emphasizes:

* **Functionality:** What does this file *do*?
* **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
* **Logic and Data Flow:**  Can we infer inputs and outputs based on the code?
* **Common Usage Errors:** What mistakes might developers make when working with this functionality?

**2. Deconstructing the Code:**

I need to analyze the provided C++ code to identify its key components and their interactions. I'll focus on:

* **Includes:** What other parts of the Chromium codebase (and external libraries) does this file rely on? This gives hints about its responsibilities.
* **Namespaces:**  `blink` and the anonymous namespace contain the core logic.
* **Key Classes and Functions:** `WebEncryptedMediaClientImpl`, `RequestMediaKeySystemAccess`, `CreateCdm`, `SelectConfig`, `OnConfigSelected`, and the `Reporter` class are crucial.
* **Data Structures:**  `pending_requests_`, `reporters_`, and the per-process reporter map are important state containers.
* **UMA Reporting:**  The code heavily uses UMA for metrics, so understanding this reporting is key.
* **Asynchronous Operations:**  Callbacks and `base::BindOnce` indicate asynchronous behavior.
* **Error Handling:** Look for how errors are reported (e.g., `CompleteWithError`).

**3. Mapping to User Requirements:**

* **Functionality:** The core purpose seems to be handling requests for access to Encrypted Media Extensions (EME) and creating Content Decryption Modules (CDMs).
* **JavaScript, HTML, CSS Relationship:** This is the trickiest part. This C++ code *implements* the underlying behavior of EME, which is *exposed* to JavaScript. The connection to HTML is through the `<video>` or `<audio>` elements that use EME. CSS doesn't directly interact with this layer.
* **Logic and Data Flow (Input/Output):**
    * **Input:**  `WebEncryptedMediaRequest` (containing key system, configurations), security origin, `CdmConfig`.
    * **Output:** `WebContentDecryptionModuleAccess` (on success), error conditions (via `WebContentDecryptionModuleResult`).
* **Common Usage Errors:** These would likely be on the JavaScript side, misconfiguring EME requests, providing invalid key system strings, etc. However, I can also point out potential backend issues that might surface as errors to the JavaScript.

**4. Structuring the Response:**

I'll organize the response to address each part of the user's request clearly:

* **Overview:** A concise summary of the file's purpose.
* **Key Functionalities (with code snippets):**  Detail the major actions, referencing relevant code sections.
* **Relationship to Web Technologies:** Explain the connection to JavaScript (through the EME API), HTML (through media elements), and the lack of direct connection to CSS. Provide JavaScript examples.
* **Logical Inference (Input/Output):** Describe the typical flow with example inputs and outputs.
* **Common Usage Errors:** Give examples of mistakes developers might make when using EME in their web applications, relating them back to the functionality of this C++ code.

**5. Pre-computation and Pre-analysis (Mental Check):**

* **Key Concepts:** Ensure I understand EME, CDMs, key systems, and how they work.
* **Code Details:**  Pay attention to the `CreateCdmStatus` enum, the role of `KeySystemConfigSelector`, and the different UMA reporting mechanisms.
* **Clarity and Conciseness:** Aim for a clear and understandable explanation, avoiding overly technical jargon where possible.

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on the C++ implementation details. I need to ensure the explanation is accessible to someone who might be more familiar with web development than with Chromium internals.
* I need to be careful not to overstate the direct interaction with HTML and CSS. The connection is through the *usage* of EME in those contexts, not a direct code interaction.
* The "common usage errors" section should focus on *user* errors (web developers) rather than potential bugs within the Chromium code itself.

By following this thought process, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request.
好的，让我们来详细分析一下 `blink/renderer/platform/media/web_encrypted_media_client_impl.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概述:**

`web_encrypted_media_client_impl.cc` 文件的主要功能是 **在 Blink 渲染引擎中实现 Web 平台的加密媒体扩展 (Encrypted Media Extensions, EME) API 的客户端部分。**  它负责处理来自 JavaScript 的 EME 相关请求，并与底层的媒体管道进行交互，以实现受保护内容的播放。

具体来说，这个文件主要负责以下任务：

1. **处理 `requestMediaKeySystemAccess()` 请求:**  当 JavaScript 代码调用 `navigator.requestMediaKeySystemAccess()` 时，这个文件会接收请求，并判断浏览器是否支持指定的密钥系统 (key system) 和配置。
2. **选择合适的配置:**  根据 JavaScript 提供的支持的配置列表，以及浏览器和底层 CDM (Content Decryption Module，内容解密模块) 的能力，选择一个最合适的配置。
3. **创建 `WebContentDecryptionModuleAccess` 对象:** 如果找到了支持的配置，这个文件会创建一个 `WebContentDecryptionModuleAccessImpl` 对象，该对象代表对特定密钥系统的访问权限。这个对象会被返回给 JavaScript。
4. **创建 CDM:**  当需要实际解密内容时，这个文件会负责创建 `WebContentDecryptionModuleImpl` 对象，它封装了底层的 CDM 实例。
5. **UMA (User Metrics Analysis) 报告:**  该文件会收集关于 EME 使用情况的统计信息，例如用户请求了哪些密钥系统，哪些密钥系统被成功支持，并将这些数据上报给 Chromium 的 UMA 系统。
6. **管理 Key Systems 的更新:** 监听底层 Key Systems 信息的更新，并在更新后重新评估待处理的 `requestMediaKeySystemAccess()` 请求。

**与 JavaScript, HTML, CSS 的关系：**

这个文件是 EME 功能在 Blink 渲染引擎中的核心实现，它直接响应 JavaScript 的 EME API 调用，并影响媒体元素的行为。

* **JavaScript:**
    * **交互点:**  `navigator.requestMediaKeySystemAccess()` 是 JavaScript 与此文件交互的主要入口点。当 JavaScript 调用此方法时，会传递密钥系统名称和支持的配置信息。
    * **举例:**  在 JavaScript 中，你可以这样请求访问 Widevine 密钥系统：

      ```javascript
      navigator.requestMediaKeySystemAccess('com.widevine.alpha', [{
          initDataTypes: ['cenc'],
          videoCapabilities: [{
              contentType: 'video/mp4; codecs="avc1.42E01E"'
          }],
          audioCapabilities: [{
              contentType: 'audio/mp4; codecs="mp4a.40.2"'
          }]
      }]).then(function(mediaKeys) {
          // 成功获取 MediaKeys 对象
          console.log("MediaKeys acquired:", mediaKeys);
      }).catch(function(error) {
          // 处理错误
          console.error("Error getting MediaKeys:", error);
      });
      ```
      当这段 JavaScript 代码执行时，`WebEncryptedMediaClientImpl::RequestMediaKeySystemAccess()` 方法会被调用，并处理传入的密钥系统和配置信息。如果成功，JavaScript 的 `then` 回调会被调用，并接收一个 `MediaKeys` 对象（在 Blink 中由 `WebContentDecryptionModuleAccessImpl` 表示）。

* **HTML:**
    * **交互点:**  EME 功能通常与 HTML `<video>` 或 `<audio>` 元素一起使用。当媒体元素需要播放受保护的内容时，会触发 EME 相关的事件和 API 调用。
    * **举例:** 当一个带有 `src` 属性指向加密媒体的 `<video>` 元素加载时，浏览器会检测到需要解密，并触发 `encrypted` 事件。JavaScript 可以监听这个事件，并使用 `MediaKeys` 对象来处理密钥会话和许可证请求。

      ```html
      <video id="myVideo" controls src="encrypted_video.mp4"></video>
      <script>
          const video = document.getElementById('myVideo');
          video.addEventListener('encrypted', function(event) {
              // 使用之前获取的 MediaKeys 对象处理 event.mediaKeySystemAccess
              console.log("Encrypted event:", event);
          });
      </script>
      ```
      在这个场景下，`WebEncryptedMediaClientImpl` 在之前处理 `requestMediaKeySystemAccess()` 时创建的 `WebContentDecryptionModuleAccessImpl` 对象，会被用于后续的密钥会话管理。

* **CSS:**
    * **关系:** CSS 与此文件没有直接的功能性关系。CSS 负责控制页面的样式和布局，而 EME 涉及到媒体内容的解密和播放逻辑。

**逻辑推理（假设输入与输出）：**

假设 JavaScript 代码调用 `navigator.requestMediaKeySystemAccess('com.example.drm', [...])`，并且浏览器和底层 CDM **支持**该密钥系统和其中一个提供的配置。

* **假设输入:**
    * `key_system`: "com.example.drm"
    * `supportedConfigurations`:  一个包含多个 `WebMediaKeySystemConfiguration` 对象的数组，描述了 JavaScript 支持的各种加密配置（例如初始化数据类型、视频和音频能力）。
    * `security_origin`:  发起请求的页面的安全源。

* **逻辑推理过程:**
    1. `WebEncryptedMediaClientImpl::RequestMediaKeySystemAccess()` 被调用，接收上述输入。
    2. `GetReporter()` 和 `GetPerProcessReporter()` 会记录 UMA 统计信息，表明该密钥系统被请求。
    3. `key_systems_->UpdateIfNeeded()` 确保 Key Systems 信息是最新的。
    4. `WebEncryptedMediaClientImpl::OnKeySystemsUpdated()` 被调用。
    5. `WebEncryptedMediaClientImpl::SelectConfig()` 被调用，它会调用 `key_system_config_selector_.SelectConfig()`，尝试在提供的配置中找到浏览器和 CDM 都支持的配置。
    6. 假设 `KeySystemConfigSelector` 成功找到一个匹配的配置。
    7. `WebEncryptedMediaClientImpl::OnConfigSelected()` 被调用，其 `status` 参数为 `KeySystemConfigSelector::Status::kSupported`。
    8. `GetReporter()` 和 `GetPerProcessReporter()` 会记录 UMA 统计信息，表明该密钥系统被成功支持。
    9. `WebContentDecryptionModuleAccessImpl::Create()` 被调用，创建一个 `WebContentDecryptionModuleAccessImpl` 对象，封装了访问该密钥系统的权限。

* **预期输出:**
    * JavaScript 的 `requestMediaKeySystemAccess()` promise 会 resolve (成功)，并返回一个 `MediaKeys` 对象（在 Blink 中由 `WebContentDecryptionModuleAccessImpl` 的实例表示）。

**假设 JavaScript 代码调用 `navigator.requestMediaKeySystemAccess('com.unsupported.drm', [...])`，并且浏览器和底层 CDM **不支持**该密钥系统。**

* **假设输入:**
    * `key_system`: "com.unsupported.drm"
    * `supportedConfigurations`: 一些配置信息。
    * `security_origin`: 发起请求的页面的安全源。

* **逻辑推理过程:**
    1. `WebEncryptedMediaClientImpl::RequestMediaKeySystemAccess()` 被调用。
    2. UMA 统计信息被记录，表明该密钥系统被请求。
    3. `WebEncryptedMediaClientImpl::SelectConfig()` 会调用 `key_system_config_selector_.SelectConfig()`。
    4. 由于该密钥系统不受支持，`KeySystemConfigSelector` 会返回 `KeySystemConfigSelector::Status::kUnsupportedKeySystem`。
    5. `WebEncryptedMediaClientImpl::OnConfigSelected()` 被调用，其 `status` 参数为 `KeySystemConfigSelector::Status::kUnsupportedKeySystem`。
    6. `request.RequestNotSupported()` 被调用，通知 JavaScript 该密钥系统或配置不受支持。
    7. UMA 统计信息被记录，表明该密钥系统的请求被拒绝。

* **预期输出:**
    * JavaScript 的 `requestMediaKeySystemAccess()` promise 会 reject (失败)，并返回一个错误信息，通常包含 "Unsupported keySystem or supportedConfigurations."。

**用户或编程常见的使用错误：**

1. **JavaScript 端请求不支持的密钥系统:**  用户在 JavaScript 中请求了一个浏览器或 CDM 不支持的密钥系统名称。
   * **例子:**  `navigator.requestMediaKeySystemAccess('com.imaginary.drm', ...)`，如果 "com.imaginary.drm" 并非浏览器支持的密钥系统。
   * **后果:** `requestMediaKeySystemAccess()` promise 会 reject，并返回 "Unsupported keySystem or supportedConfigurations." 错误。

2. **JavaScript 端提供的配置与浏览器和 CDM 的能力不匹配:**  用户提供的 `supportedConfigurations` 数组中的所有配置都不被浏览器或 CDM 支持。
   * **例子:**  用户可能只提供了需要特定编解码器或功能（例如硬件安全级别）的配置，而这些在当前环境下不可用。
   * **后果:** `requestMediaKeySystemAccess()` promise 会 reject，并返回 "Unsupported keySystem or supportedConfigurations." 错误。

3. **在不安全的上下文中调用 EME API:**  EME API (特别是 `requestMediaKeySystemAccess()`) 通常需要在安全上下文 (HTTPS) 中才能使用。
   * **例子:**  在一个 HTTP 页面中调用 `navigator.requestMediaKeySystemAccess()`。
   * **后果:**  浏览器可能会阻止该调用，并抛出一个错误，提示需要在安全上下文中使用。

4. **没有正确处理 `encrypted` 事件:**  在 `<video>` 或 `<audio>` 元素触发 `encrypted` 事件后，JavaScript 需要正确地使用之前获取的 `MediaKeys` 对象来创建和管理密钥会话，并处理许可证请求。
   * **例子:**  忘记监听 `encrypted` 事件，或者在事件处理程序中没有正确地调用 `mediaKeys.createSession()` 等方法。
   * **后果:**  媒体内容无法被解密，导致播放失败。

5. **CDM 未安装或禁用:**  用户可能没有安装所需的 CDM (例如 Widevine)，或者在浏览器设置中禁用了 CDM。
   * **后果:**  当请求访问需要该 CDM 的密钥系统时，`requestMediaKeySystemAccess()` 可能会失败，并返回相关的错误信息。

6. **跨域问题:**  如果媒体资源托管在与网页不同的域上，可能需要进行 CORS (跨域资源共享) 配置，以便浏览器允许 JavaScript 获取加密信息。
   * **后果:**  浏览器可能会阻止跨域的请求，导致 EME 初始化失败。

总而言之，`web_encrypted_media_client_impl.cc` 是 Blink 引擎中处理 EME 功能的关键组件，它连接了 JavaScript 的 API 调用和底层的媒体解密能力，并负责关键的决策和对象创建。理解其功能有助于开发者更好地理解和调试 Web 平台的加密媒体播放。

Prompt: 
```
这是目录为blink/renderer/platform/media/web_encrypted_media_client_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/platform/media/web_encrypted_media_client_impl.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/metrics/histogram_functions.h"
#include "base/no_destructor.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "media/base/key_systems.h"
#include "media/base/media_permission.h"
#include "third_party/blink/public/platform/web_content_decryption_module_result.h"
#include "third_party/blink/public/platform/web_encrypted_media_request.h"
#include "third_party/blink/public/platform/web_media_key_system_configuration.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/platform/media/web_content_decryption_module_access_impl.h"
#include "third_party/blink/renderer/platform/media/web_content_decryption_module_impl.h"

namespace blink {

namespace {

// Used to name UMAs in Reporter.
const char kKeySystemSupportUMAPrefix[] =
    "Media.EME.RequestMediaKeySystemAccess.";

std::string ConvertCreateCdmStatusToString(media::CreateCdmStatus status) {
  switch (status) {
    case media::CreateCdmStatus::kSuccess:
      return "Succeeded.";
    case media::CreateCdmStatus::kUnknownError:
      return "Unknown error.";
    case media::CreateCdmStatus::kCdmCreationAborted:
      return "CDM creation aborted.";
    case media::CreateCdmStatus::kCreateCdmFuncNotAvailable:
      return "CreateCdmFunc not available.";
    case media::CreateCdmStatus::kCdmHelperCreationFailed:
      return "CDM helper creation failed.";
    case media::CreateCdmStatus::kGetCdmPrefDataFailed:
      return "Failed to get the CDM preference data.";
    case media::CreateCdmStatus::kGetCdmOriginIdFailed:
      return "Failed to get the CDM origin ID.";
    case media::CreateCdmStatus::kInitCdmFailed:
      return "Failed to initialize CDM.";
    case media::CreateCdmStatus::kCdmFactoryCreationFailed:
      return "CDM Factory creation failed.";
    case media::CreateCdmStatus::kCdmNotSupported:
      return "CDM not supported.";
    case media::CreateCdmStatus::kInvalidCdmConfig:
      return "Invalid CdmConfig.";
    case media::CreateCdmStatus::kUnsupportedKeySystem:
      return "Unsupported key system.";
    case media::CreateCdmStatus::kDisconnectionError:
      return "Disconnection error.";
    case media::CreateCdmStatus::kNotAllowedOnUniqueOrigin:
      return "EME use is not allowed on unique origins.";
#if BUILDFLAG(IS_ANDROID)
    case media::CreateCdmStatus::kMediaDrmBridgeCreationFailed:
      return "MediaDrmBridge creation failed.";
    case media::CreateCdmStatus::kMediaCryptoNotAvailable:
      return "MediaCrypto not available.";
    case media::CreateCdmStatus::kAndroidMediaDrmIllegalArgument:
      return "Illegal argument passed to MediaDrm.";
    case media::CreateCdmStatus::kAndroidMediaDrmIllegalState:
      return "MediaDrm not initialized properly.";
    case media::CreateCdmStatus::kAndroidFailedL1SecurityLevel:
      return "Unable to set L1 security level.";
    case media::CreateCdmStatus::kAndroidFailedL3SecurityLevel:
      return "Unable to set L3 security level.";
    case media::CreateCdmStatus::kAndroidFailedSecurityOrigin:
      return "Unable to set origin.";
    case media::CreateCdmStatus::kAndroidFailedMediaCryptoSession:
      return "Unable to create MediaCrypto session.";
    case media::CreateCdmStatus::kAndroidFailedToStartProvisioning:
      return "Unable to create MediaCrypto session.";
    case media::CreateCdmStatus::kAndroidFailedMediaCryptoCreate:
      return "Unable to create MediaCrypto object.";
    case media::CreateCdmStatus::kAndroidUnsupportedMediaCryptoScheme:
      return "Crypto scheme not supported.";
#elif BUILDFLAG(IS_CHROMEOS)
    case media::CreateCdmStatus::kNoMoreInstances:
      return "Only one instance allowed.";
    case media::CreateCdmStatus::kInsufficientGpuResources:
      return "Insufficient GPU memory available.";
    case media::CreateCdmStatus::kCrOsVerifiedAccessDisabled:
      return "Verified Access is disabled.";
    case media::CreateCdmStatus::kCrOsRemoteFactoryCreationFailed:
      return "Remote factory creation failed.";
#endif  // BUILDFLAG(IS_ANDROID)
    default:
      return base::ToString(status);
  }
}

// A helper function to complete WebContentDecryptionModuleResult. Used
// to convert WebContentDecryptionModuleResult to a callback.
void CompleteWebContentDecryptionModuleResult(
    std::unique_ptr<WebContentDecryptionModuleResult> result,
    std::unique_ptr<WebContentDecryptionModule> cdm,
    media::CreateCdmStatus status) {
  DCHECK(result);

  if (!cdm) {
    result->CompleteWithError(
        kWebContentDecryptionModuleExceptionNotSupportedError, 0,
        WebString::FromASCII(ConvertCreateCdmStatusToString(status)));
    return;
  }

  result->CompleteWithContentDecryptionModule(std::move(cdm));
}

}  // namespace

struct UMAReportStatus {
  bool is_request_reported = false;
  bool is_result_reported = false;
  base::TimeTicks request_start_time;
};

// Report usage of key system to UMA. There are 2 different UMAs logged:
// 1. The resolve time of the key system.
// 2. The reject time of the key system.
// At most one of each will be reported at most once per process.
class PerProcessReporter {
 public:
  explicit PerProcessReporter(const std::string& key_system_for_uma)
      : uma_name_(kKeySystemSupportUMAPrefix + key_system_for_uma) {}
  ~PerProcessReporter() = default;

  void ReportRequested() {
    if (report_status_.is_request_reported) {
      return;
    }

    report_status_.is_request_reported = true;
    report_status_.request_start_time = base::TimeTicks::Now();
  }

  void ReportResolveTime() {
    DCHECK(report_status_.is_request_reported);
    if (report_status_.is_result_reported) {
      return;
    }

    base::UmaHistogramTimes(
        uma_name_ + ".TimeTo.Resolve",
        base::TimeTicks::Now() - report_status_.request_start_time);
    report_status_.is_result_reported = true;
  }

  void ReportRejectTime() {
    if (report_status_.is_result_reported) {
      return;
    }

    base::UmaHistogramTimes(
        uma_name_ + ".TimeTo.Reject",
        base::TimeTicks::Now() - report_status_.request_start_time);
    report_status_.is_result_reported = true;
  }

 private:
  const std::string uma_name_;
  UMAReportStatus report_status_;
};

using PerProcessReporterMap =
    std::unordered_map<std::string, std::unique_ptr<PerProcessReporter>>;

PerProcessReporterMap& GetPerProcessReporterMap() {
  static base::NoDestructor<PerProcessReporterMap> per_process_reporters_map;
  return *per_process_reporters_map;
}

static PerProcessReporter* GetPerProcessReporter(const WebString& key_system) {
  // Assumes that empty will not be found by GetKeySystemNameForUMA().
  std::string key_system_ascii;
  if (key_system.ContainsOnlyASCII()) {
    key_system_ascii = key_system.Ascii();
  }

  std::string uma_name = media::GetKeySystemNameForUMA(key_system_ascii);

  std::unique_ptr<PerProcessReporter>& reporter =
      GetPerProcessReporterMap()[uma_name];

  if (!reporter) {
    reporter = std::make_unique<PerProcessReporter>(uma_name);
  }

  return reporter.get();
}

// Report usage of key system to UMA. There are 2 different counts logged:
// 1. The key system is requested.
// 2. The requested key system and options are supported.
// Each stat is only reported once per renderer frame per key system.
// Note that WebEncryptedMediaClientImpl is only created once by each
// renderer frame.
class WebEncryptedMediaClientImpl::Reporter {
 public:
  enum KeySystemSupportStatus {
    KEY_SYSTEM_REQUESTED = 0,
    KEY_SYSTEM_SUPPORTED = 1,
    KEY_SYSTEM_SUPPORT_STATUS_COUNT
  };

  explicit Reporter(const std::string& key_system_for_uma)
      : uma_name_(kKeySystemSupportUMAPrefix + key_system_for_uma),
        is_request_reported_(false),
        is_support_reported_(false) {}
  ~Reporter() = default;

  void ReportRequested() {
    if (is_request_reported_)
      return;
    Report(KEY_SYSTEM_REQUESTED);
    is_request_reported_ = true;
  }

  void ReportSupported() {
    DCHECK(is_request_reported_);
    if (is_support_reported_)
      return;
    Report(KEY_SYSTEM_SUPPORTED);
    is_support_reported_ = true;
  }

 private:
  void Report(KeySystemSupportStatus status) {
    base::UmaHistogramEnumeration(uma_name_, status,
                                  KEY_SYSTEM_SUPPORT_STATUS_COUNT);
  }

  const std::string uma_name_;
  bool is_request_reported_;
  bool is_support_reported_;
};

WebEncryptedMediaClientImpl::WebEncryptedMediaClientImpl(
    media::KeySystems* key_systems,
    media::CdmFactory* cdm_factory,
    media::MediaPermission* media_permission,
    std::unique_ptr<KeySystemConfigSelector::WebLocalFrameDelegate>
        web_frame_delegate)
    : key_systems_(key_systems),
      cdm_factory_(cdm_factory),
      key_system_config_selector_(key_systems_,
                                  media_permission,
                                  std::move(web_frame_delegate)) {
  DCHECK(cdm_factory_);
}

WebEncryptedMediaClientImpl::~WebEncryptedMediaClientImpl() = default;

void WebEncryptedMediaClientImpl::RequestMediaKeySystemAccess(
    WebEncryptedMediaRequest request) {
  GetReporter(request.KeySystem())->ReportRequested();

  GetPerProcessReporter(request.KeySystem())->ReportRequested();

  pending_requests_.push_back(std::move(request));
  key_systems_->UpdateIfNeeded(
      base::BindOnce(&WebEncryptedMediaClientImpl::OnKeySystemsUpdated,
                     weak_factory_.GetWeakPtr()));
}

void WebEncryptedMediaClientImpl::CreateCdm(
    const WebSecurityOrigin& security_origin,
    const media::CdmConfig& cdm_config,
    std::unique_ptr<WebContentDecryptionModuleResult> result) {
  WebContentDecryptionModuleImpl::Create(
      cdm_factory_, key_systems_, security_origin, cdm_config,
      base::BindOnce(&CompleteWebContentDecryptionModuleResult,
                     std::move(result)));
}

void WebEncryptedMediaClientImpl::OnKeySystemsUpdated() {
  auto requests = std::move(pending_requests_);
  for (const auto& request : requests)
    SelectConfig(request);
}

void WebEncryptedMediaClientImpl::SelectConfig(
    WebEncryptedMediaRequest request) {
  key_system_config_selector_.SelectConfig(
      request.KeySystem(), request.SupportedConfigurations(),
      base::BindOnce(&WebEncryptedMediaClientImpl::OnConfigSelected,
                     weak_factory_.GetWeakPtr(), request));
}

void WebEncryptedMediaClientImpl::OnConfigSelected(
    WebEncryptedMediaRequest request,
    KeySystemConfigSelector::Status status,
    WebMediaKeySystemConfiguration* accumulated_configuration,
    media::CdmConfig* cdm_config) {
  // Update encrypted_media_supported_types_browsertest.cc if updating these
  // strings.
  // TODO(xhwang): Consider using different messages for kUnsupportedKeySystem
  // and kUnsupportedConfigs.
  const char kUnsupportedKeySystemOrConfigMessage[] =
      "Unsupported keySystem or supportedConfigurations.";
  // Handle unsupported cases first.
  switch (status) {
    case KeySystemConfigSelector::Status::kUnsupportedKeySystem:
    case KeySystemConfigSelector::Status::kUnsupportedConfigs:
      request.RequestNotSupported(kUnsupportedKeySystemOrConfigMessage);
      GetPerProcessReporter(request.KeySystem())->ReportRejectTime();
      return;
    case KeySystemConfigSelector::Status::kSupported:
      break;  // Handled below.
  }

  // Use the requested key system to match what's reported in
  // RequestMediaKeySystemAccess().
  DCHECK_EQ(status, KeySystemConfigSelector::Status::kSupported);
  GetReporter(request.KeySystem())->ReportSupported();
  GetPerProcessReporter(request.KeySystem())->ReportResolveTime();

  // If the frame is closed while the permission prompt is displayed,
  // the permission prompt is dismissed and this may result in the
  // requestMediaKeySystemAccess request succeeding. However, the blink
  // objects may have been cleared, so check if this is the case and simply
  // reject the request.
  WebSecurityOrigin origin = request.GetSecurityOrigin();
  if (origin.IsNull()) {
    request.RequestNotSupported("Unable to create MediaKeySystemAccess");
    return;
  }

  // Use the returned key system which should be used for CDM creation.
  request.RequestSucceeded(WebContentDecryptionModuleAccessImpl::Create(
      origin, *accumulated_configuration, *cdm_config,
      weak_factory_.GetWeakPtr()));
}

WebEncryptedMediaClientImpl::Reporter* WebEncryptedMediaClientImpl::GetReporter(
    const WebString& key_system) {
  // Assumes that empty will not be found by GetKeySystemNameForUMA().
  std::string key_system_ascii;
  if (key_system.ContainsOnlyASCII())
    key_system_ascii = key_system.Ascii();

  // Return a per-frame singleton so that UMA reports will be once-per-frame.
  std::string uma_name = media::GetKeySystemNameForUMA(key_system_ascii);
  std::unique_ptr<Reporter>& reporter = reporters_[uma_name];
  if (!reporter)
    reporter = std::make_unique<Reporter>(uma_name);
  return reporter.get();
}
}  // namespace blink

"""

```