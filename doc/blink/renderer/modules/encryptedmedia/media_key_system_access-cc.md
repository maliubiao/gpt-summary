Response:
Let's break down the thought process for analyzing the `media_key_system_access.cc` file.

**1. Initial Reading and Keyword Spotting:**

The first step is to quickly read through the code, paying attention to keywords and familiar patterns. Keywords like `Copyright`, `include`, `namespace blink`, `class`, `public`, `private`, function names like `getConfiguration`, `createMediaKeys`, and type names like `MediaKeys`, `ScriptPromise`, `Web...` stand out.

**2. Identifying the Core Purpose:**

The file name itself, `media_key_system_access.cc`, and the included headers like `media/base/eme_constants.h`, `third_party/blink/public/platform/web_content_decryption_module.h`, and `third_party/blink/renderer/modules/encryptedmedia/media_keys.h` strongly suggest this file deals with the Encrypted Media Extensions (EME) API within the Blink rendering engine. Specifically, it seems responsible for managing access to a specific media key system.

**3. Deconstructing the `MediaKeySystemAccess` Class:**

The central class is `MediaKeySystemAccess`. We should examine its members and methods:

* **Constructor/Destructor:**  The constructor takes a `WebContentDecryptionModuleAccess` which hints at an underlying platform-specific implementation. The destructor is default, suggesting no special cleanup.
* **`getConfiguration()`:** This method returns a `MediaKeySystemConfiguration` object. The code inside converts `WebMediaKeySystemConfiguration` (likely a platform representation) to Blink's internal representation. This suggests it's responsible for exposing the capabilities of the underlying key system.
* **`createMediaKeys()`:** This method returns a `ScriptPromise<MediaKeys>`. This immediately links it to JavaScript's asynchronous nature and the `MediaKeys` object, a core EME component. The implementation involves a `NewCdmResultPromise` and calls `access_->CreateContentDecryptionModule`. This points to the creation of the actual CDM instance and the asynchronous nature of the operation.

**4. Analyzing Helper Structures and Functions:**

* **`NewCdmResultPromise`:** This nested class is a crucial piece. It inherits from `ContentDecryptionModuleResultPromise` and is used as a callback for the asynchronous CDM creation. It resolves the promise with a `MediaKeys` object on success. This clarifies the asynchronous flow of `createMediaKeys`.
* **`Convert...` Functions:**  The `ConvertInitDataTypes`, `ConvertCapabilities`, and `ConvertSessionTypes` functions are clearly responsible for translating between Blink's internal data structures and the platform's `Web...` counterparts. This highlights the abstraction layer provided by this file.
* **`ReportMetrics()`:** This function suggests that usage statistics are being collected for certain key systems. The hardcoded "com.widevine.alpha" is a key detail.

**5. Connecting to Web Standards (JavaScript, HTML, CSS):**

With the understanding of the core functionality, we can now connect it to the web standards:

* **JavaScript:** The `createMediaKeys()` function directly corresponds to the `navigator.requestMediaKeySystemAccess(keySystem, supportedConfigurations)` API in JavaScript. The returned `Promise` is a direct link. The `MediaKeys` object itself is exposed to JavaScript.
* **HTML:** The `<video>` or `<audio>` elements with the `encrypted` event are the triggers for the EME flow, eventually leading to `requestMediaKeySystemAccess`.
* **CSS:**  While CSS doesn't directly interact with EME, the presentation of the video or audio content might be controlled by CSS. There's no direct link in *this specific file*, but understanding the broader context is important.

**6. Logical Reasoning and Assumptions:**

We can start making educated guesses:

* **Input to `createMediaKeys`:**  The key system string (e.g., "com.widevine.alpha") and a configuration object specifying desired capabilities (e.g., supported codecs, session types).
* **Output of `createMediaKeys`:** A `Promise` that resolves with a `MediaKeys` object if successful, or rejects with a `DOMException` on failure.

**7. Identifying Potential User/Programming Errors:**

Based on the code, we can identify potential pitfalls:

* **Incorrect Key System:**  Providing an unsupported key system string to `requestMediaKeySystemAccess`.
* **Invalid Configuration:**  Requesting configurations that the CDM doesn't support.
* **Asynchronous Nature:** Not handling the `Promise` correctly, leading to unhandled rejections or incorrect execution flow.

**8. Tracing User Actions (Debugging Clues):**

We can trace the user's actions back to this code:

1. User visits a webpage with DRM-protected content.
2. The webpage uses JavaScript to call `navigator.requestMediaKeySystemAccess()`.
3. The browser internally selects a matching key system.
4. The browser's implementation (likely involving native code) creates a `WebContentDecryptionModuleAccess` object.
5. This `MediaKeySystemAccess` object is created wrapping the `WebContentDecryptionModuleAccess`.
6. The JavaScript calls `createMediaKeys()` on the `MediaKeySystemAccess` object.
7. The asynchronous creation of the CDM happens, eventually resolving the `Promise`.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file directly implements the CDM loading.
* **Correction:**  The presence of `WebContentDecryptionModuleAccess` and the asynchronous callback mechanism suggests this file acts as an intermediary, managing the access to the underlying CDM implementation.

By following this structured approach of reading, identifying key components, connecting to web standards, reasoning about inputs and outputs, and considering error scenarios, we can effectively analyze and understand the functionality of a complex source code file like `media_key_system_access.cc`.
好的，让我们来分析一下 `blink/renderer/modules/encryptedmedia/media_key_system_access.cc` 这个文件。

**功能概述:**

`media_key_system_access.cc` 文件的主要功能是**实现 `MediaKeySystemAccess` 接口的逻辑**。`MediaKeySystemAccess` 是 W3C 加密媒体扩展 (Encrypted Media Extensions, EME) 规范中的一个核心接口，它代表了对特定密钥系统（Key System，例如 Widevine, PlayReady）的访问权限。

更具体地说，这个文件负责：

1. **存储和提供密钥系统的配置信息 (`getConfiguration`)**:  它持有从底层平台获取的关于特定密钥系统能力的配置信息，例如支持的初始化数据类型、会话类型、是否需要持久化存储等。
2. **创建 `MediaKeys` 对象 (`createMediaKeys`)**: 这是该文件最核心的功能。它负责调用底层的 Content Decryption Module (CDM) 来创建一个 `MediaKeys` 对象。`MediaKeys` 对象是 EME 中用于创建和管理加密会话的关键组件。
3. **处理异步操作**:  `createMediaKeys` 操作是异步的，因为涉及到与 CDM 的交互。该文件使用了 Promise 来处理这种异步性。
4. **数据类型转换**:  在 Blink 的内部表示和平台相关的表示之间转换数据类型，例如初始化数据类型、能力信息、会话类型等。
5. **上报指标**:  收集关于 `createMediaKeys` 调用的指标信息，例如使用的密钥系统、是否在广告帧中、是否跨域等，用于分析和监控。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`media_key_system_access.cc` 文件虽然是用 C++ 编写的，但它直接支持了 JavaScript 中 EME API 的使用，从而间接地与 HTML 和 CSS 相关联：

* **JavaScript**:
    * **`navigator.requestMediaKeySystemAccess(keySystem, supportedConfigurations)`**:  用户在 JavaScript 中调用这个方法时，浏览器会查找对应的 `MediaKeySystemAccess` 实现。如果找到了，就会创建一个 `MediaKeySystemAccess` 对象返回给 JavaScript。这个 C++ 文件就是 `MediaKeySystemAccess` 的具体实现。
    * **`mediaKeySystemAccess.getConfiguration()`**:  JavaScript 可以调用 `MediaKeySystemAccess` 对象的 `getConfiguration()` 方法来获取密钥系统的配置信息。该方法的实现就在这个 C++ 文件中。
    * **`mediaKeySystemAccess.createMediaKeys()`**:  JavaScript 调用这个方法来创建 `MediaKeys` 对象，这是播放加密媒体的关键步骤。这个方法的实现是该 C++ 文件的核心功能。

    **举例说明 (JavaScript):**

    ```javascript
    navigator.requestMediaKeySystemAccess('com.widevine.alpha', [{
        initDataTypes: ['cenc'],
        videoCapabilities: [{
            contentType: 'video/mp4; codecs="avc1.42E01E"'
        }],
        audioCapabilities: [{
            contentType: 'audio/mp4; codecs="mp4a.40.2"'
        }]
    }]).then(function(keySystemAccess) {
        console.log("成功获取 MediaKeySystemAccess 对象", keySystemAccess);
        return keySystemAccess.createMediaKeys();
    }).then(function(mediaKeys) {
        console.log("成功创建 MediaKeys 对象", mediaKeys);
        // ... 使用 mediaKeys 对象创建会话等操作
    }).catch(function(error) {
        console.error("获取 MediaKeySystemAccess 或创建 MediaKeys 失败", error);
    });
    ```

* **HTML**:
    * `<video>` 或 `<audio>` 标签的 `encrypted` 事件：当媒体元素遇到加密数据时，会触发 `encrypted` 事件。JavaScript 通常会在这个事件处理程序中调用 EME API，从而间接地触发 `media_key_system_access.cc` 中的代码。

    **举例说明 (HTML & JavaScript):**

    ```html
    <video id="myVideo" src="encrypted_video.mp4"></video>
    <script>
      const video = document.getElementById('myVideo');
      video.addEventListener('encrypted', function(event) {
        console.log("视频数据加密，需要解密", event);
        // 调用 navigator.requestMediaKeySystemAccess 等 EME API
      });
    </script>
    ```

* **CSS**:
    * CSS 本身与 `media_key_system_access.cc` 没有直接的功能关联。但是，CSS 用于控制 HTML 媒体元素的样式和布局。因此，EME 的使用通常是为了保护通过 HTML 媒体元素播放的内容。

**逻辑推理及假设输入与输出:**

**假设输入 (对于 `createMediaKeys` 方法):**

1. **`script_state`**:  当前的 JavaScript 执行上下文。
2. **隐含输入**:  该 `MediaKeySystemAccess` 对象是在之前通过 `navigator.requestMediaKeySystemAccess` 成功获取的，因此它已经关联了一个特定的密钥系统和配置。

**逻辑推理:**

1. `createMediaKeys` 方法首先获取该 `MediaKeySystemAccess` 对象关联的配置信息 (`access_->GetConfiguration()`)。
2. 创建一个 `ScriptPromiseResolver` 用于管理返回给 JavaScript 的 Promise。
3. 创建一个 `NewCdmResultPromise` 对象，它继承自 `ContentDecryptionModuleResultPromise`，用于处理 CDM 创建的异步结果。这个 Promise 的目的是在 CDM 创建成功后解析（resolve）为 `MediaKeys` 对象。
4. 调用 `access_->CreateContentDecryptionModule`，这是一个异步操作，负责加载和初始化底层的 CDM。传递了 `NewCdmResultPromise` 的 `Result()` 方法返回的对象作为回调，以便在 CDM 完成创建后通知 Blink。
5. 如果 CDM 创建成功，`NewCdmResultPromise::CompleteWithContentDecryptionModule` 方法会被调用，它会创建一个 `MediaKeys` 对象并使用 `resolver->Resolve()` 解析 Promise。
6. 如果 CDM 创建失败，`ContentDecryptionModuleResultPromise` 的错误处理方法会被调用，它会使用 `resolver->Reject()` 拒绝 Promise，并带有相应的错误信息。
7. `createMediaKeys` 方法立即返回创建的 Promise 给 JavaScript。

**假设输出 (对于 `createMediaKeys` 方法):**

* **成功**:  一个 resolved 的 JavaScript Promise，其 value 是一个新创建的 `MediaKeys` 对象。
* **失败**:  一个 rejected 的 JavaScript Promise，其 reason 是一个 `DOMException` 对象，描述了 CDM 创建失败的原因。

**涉及用户或编程常见的使用错误及举例说明:**

1. **用户没有安装或启用所需的 CDM**: 如果用户尝试播放受特定密钥系统保护的内容，但他们的浏览器没有安装或启用相应的 CDM，`createMediaKeys` 调用将会失败，Promise 会被拒绝。

   **错误信息示例**:  可能是一个 `DOMException`，错误名称可能是 "NotSupportedError" 或其他与 CDM 初始化失败相关的错误。

2. **提供的配置与 CDM 不兼容**:  JavaScript 代码中提供的 `supportedConfigurations` 参数可能包含 CDM 不支持的特性（例如不支持的初始化数据类型或编解码器）。这会导致 `navigator.requestMediaKeySystemAccess` 返回的 Promise 被拒绝，或者在调用 `createMediaKeys` 时失败。

   **错误信息示例**:  可能是一个 `DOMException`，错误名称可能是 "NotSupportedError" 或 "InvalidStateError"。

3. **在不安全的上下文中使用 EME API**:  EME API 通常需要在安全上下文（HTTPS）下使用。如果在非安全上下文中使用，`navigator.requestMediaKeySystemAccess` 可能会返回一个被拒绝的 Promise。

   **错误信息示例**:  浏览器可能会抛出一个安全性错误，阻止 API 调用。

4. **不正确地处理 Promise 的 rejection**:  开发者如果没有正确地为 `createMediaKeys` 返回的 Promise 添加 `.catch()` 处理程序，当 CDM 创建失败时，可能会导致 unhandled promise rejection 错误。

   **错误信息示例**:  浏览器的开发者控制台中会显示 "UnhandledPromiseRejectionWarning"。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个包含受 DRM 保护的媒体内容的网页**:  例如，一个在线视频网站上的付费电影。
2. **网页的 JavaScript 代码尝试播放该媒体**:  这通常涉及到创建一个 `<video>` 或 `<audio>` 元素，并设置其 `src` 属性指向加密的媒体资源。
3. **媒体元素触发 `encrypted` 事件**:  当浏览器检测到媒体数据是加密的时，会触发此事件。
4. **`encrypted` 事件处理程序被调用**:  JavaScript 代码在这个处理程序中调用 `navigator.requestMediaKeySystemAccess(keySystem, supportedConfigurations)`，其中 `keySystem` 是媒体内容使用的加密方案（例如 'com.widevine.alpha'），`supportedConfigurations` 描述了应用支持的密钥系统配置。
5. **浏览器查找并实例化对应的 `MediaKeySystemAccess` 对象**:  对于匹配的 `keySystem`，浏览器会创建 `blink::MediaKeySystemAccess` 的实例。
6. **JavaScript 调用 `mediaKeySystemAccess.createMediaKeys()`**:  获取到 `MediaKeySystemAccess` 对象后，JavaScript 代码会调用其 `createMediaKeys()` 方法来请求创建一个 `MediaKeys` 对象，以便开始解密会话。
7. **`blink::MediaKeySystemAccess::createMediaKeys()` 被执行**:  这就是我们分析的这个 C++ 文件中的代码开始执行的地方。它负责与底层的 CDM 交互。

**调试线索**:

* **断点**:  在 `blink::MediaKeySystemAccess::createMediaKeys()` 的入口处设置断点，可以观察该方法是否被调用，以及调用的参数（特别是 `script_state`）。
* **日志输出**:  在关键步骤添加日志输出，例如在调用 CDM 创建函数前后，以及 Promise 的 resolve 和 reject 分支。
* **检查 `keySystem` 和 `supportedConfigurations`**:  确认 JavaScript 传递给 `navigator.requestMediaKeySystemAccess` 的参数是否正确，与预期的密钥系统和配置是否匹配。
* **检查 CDM 是否加载成功**:  查看浏览器控制台或网络面板是否有与 CDM 加载相关的错误。
* **Promise 状态检查**:  使用浏览器的开发者工具检查 `createMediaKeys()` 返回的 Promise 的状态（pending, fulfilled, rejected）以及其 value 或 reason。

希望以上分析能够帮助你理解 `media_key_system_access.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/encryptedmedia/media_key_system_access.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/encryptedmedia/media_key_system_access.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/numerics/safe_conversions.h"
#include "media/base/eme_constants.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/blink/public/platform/web_content_decryption_module.h"
#include "third_party/blink/public/platform/web_encrypted_media_types.h"
#include "third_party/blink/public/platform/web_media_key_system_configuration.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_key_system_media_capability.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/encryptedmedia/content_decryption_module_result_promise.h"
#include "third_party/blink/renderer/modules/encryptedmedia/encrypted_media_utils.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_key_session.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_keys.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/timer.h"

namespace blink {

namespace {

// This class wraps the promise resolver used when creating MediaKeys
// and is passed to Chromium to fullfill the promise. This implementation of
// completeWithCdm() will resolve the promise with a new MediaKeys object,
// while completeWithError() will reject the promise with an exception.
// All other complete methods are not expected to be called, and will
// reject the promise.
class NewCdmResultPromise : public ContentDecryptionModuleResultPromise {
 public:
  NewCdmResultPromise(
      ScriptPromiseResolver<MediaKeys>* resolver,
      const MediaKeysConfig& config,
      const WebVector<WebEncryptedMediaSessionType>& supported_session_types)
      : ContentDecryptionModuleResultPromise(resolver,
                                             config,
                                             EmeApiType::kCreateMediaKeys),
        config_(config),
        supported_session_types_(supported_session_types) {}

  NewCdmResultPromise(const NewCdmResultPromise&) = delete;
  NewCdmResultPromise& operator=(const NewCdmResultPromise&) = delete;

  ~NewCdmResultPromise() override = default;

  // ContentDecryptionModuleResult implementation.
  void CompleteWithContentDecryptionModule(
      std::unique_ptr<WebContentDecryptionModule> cdm) override {
    // NOTE: Continued from step 2.8 of createMediaKeys().

    if (!IsValidToFulfillPromise())
      return;

    // 2.9. Let media keys be a new MediaKeys object.
    auto* media_keys = MakeGarbageCollected<MediaKeys>(GetExecutionContext(),
                                                       supported_session_types_,
                                                       std::move(cdm), config_);

    // 2.10. Resolve promise with media keys.
    Resolve<MediaKeys>(media_keys);
  }

 private:
  MediaKeysConfig config_;
  WebVector<WebEncryptedMediaSessionType> supported_session_types_;
};

// These methods are the inverses of those with the same names in
// NavigatorRequestMediaKeySystemAccess.
Vector<String> ConvertInitDataTypes(
    const WebVector<media::EmeInitDataType>& init_data_types) {
  Vector<String> result(base::checked_cast<wtf_size_t>(init_data_types.size()));
  for (wtf_size_t i = 0; i < result.size(); i++)
    result[i] =
        EncryptedMediaUtils::ConvertFromInitDataType(init_data_types[i]);
  return result;
}

HeapVector<Member<MediaKeySystemMediaCapability>> ConvertCapabilities(
    const WebVector<WebMediaKeySystemMediaCapability>& capabilities) {
  HeapVector<Member<MediaKeySystemMediaCapability>> result(
      base::checked_cast<wtf_size_t>(capabilities.size()));
  for (wtf_size_t i = 0; i < result.size(); i++) {
    MediaKeySystemMediaCapability* capability =
        MediaKeySystemMediaCapability::Create();
    capability->setContentType(capabilities[i].content_type);
    capability->setRobustness(capabilities[i].robustness);

    switch (capabilities[i].encryption_scheme) {
      case WebMediaKeySystemMediaCapability::EncryptionScheme::kNotSpecified:
        // https://w3c.github.io/encrypted-media/#dom-mediakeysystemaccess-getconfiguration
        // "If encryptionScheme was not given by the application, the
        // accumulated configuration MUST still contain a encryptionScheme
        // field with a value of null, so that polyfills can detect the user
        // agent's support for the field without specifying specific values."
        capability->setEncryptionScheme(String());
        break;
      case WebMediaKeySystemMediaCapability::EncryptionScheme::kCenc:
        capability->setEncryptionScheme("cenc");
        break;
      case WebMediaKeySystemMediaCapability::EncryptionScheme::kCbcs:
        capability->setEncryptionScheme("cbcs");
        break;
      case WebMediaKeySystemMediaCapability::EncryptionScheme::kCbcs_1_9:
        capability->setEncryptionScheme("cbcs-1-9");
        break;
      case WebMediaKeySystemMediaCapability::EncryptionScheme::kUnrecognized:
        NOTREACHED()
            << "Unrecognized encryption scheme should never be returned.";
    }

    result[i] = capability;
  }
  return result;
}

Vector<String> ConvertSessionTypes(
    const WebVector<WebEncryptedMediaSessionType>& session_types) {
  Vector<String> result(base::checked_cast<wtf_size_t>(session_types.size()));
  for (wtf_size_t i = 0; i < result.size(); i++)
    result[i] = EncryptedMediaUtils::ConvertFromSessionType(session_types[i]);
  return result;
}

void ReportMetrics(ExecutionContext* execution_context,
                   const String& key_system) {
  // TODO(xhwang): Report other key systems here and for
  // requestMediaKeySystemAccess().
  const char kWidevineKeySystem[] = "com.widevine.alpha";
  if (key_system != kWidevineKeySystem)
    return;

  auto* local_dom_window = To<LocalDOMWindow>(execution_context);
  if (!local_dom_window)
    return;

  Document* document = local_dom_window->document();
  if (!document)
    return;

  LocalFrame* frame = document->GetFrame();
  if (!frame)
    return;

  ukm::builders::Media_EME_CreateMediaKeys builder(document->UkmSourceID());
  builder.SetKeySystem(KeySystemForUkmLegacy::kWidevine);
  builder.SetIsAdFrame(static_cast<int>(frame->IsAdFrame()));
  builder.SetIsCrossOrigin(
      static_cast<int>(frame->IsCrossOriginToOutermostMainFrame()));
  builder.SetIsTopFrame(static_cast<int>(frame->IsOutermostMainFrame()));
  builder.Record(document->UkmRecorder());
}

}  // namespace

MediaKeySystemAccess::MediaKeySystemAccess(
    std::unique_ptr<WebContentDecryptionModuleAccess> access)
    : access_(std::move(access)) {}

MediaKeySystemAccess::~MediaKeySystemAccess() = default;

MediaKeySystemConfiguration* MediaKeySystemAccess::getConfiguration() const {
  WebMediaKeySystemConfiguration configuration = access_->GetConfiguration();
  MediaKeySystemConfiguration* result = MediaKeySystemConfiguration::Create();
  // |initDataTypes|, |audioCapabilities|, and |videoCapabilities| can only be
  // empty if they were not present in the requested configuration.
  if (!configuration.init_data_types.empty())
    result->setInitDataTypes(
        ConvertInitDataTypes(configuration.init_data_types));
  if (!configuration.audio_capabilities.empty())
    result->setAudioCapabilities(
        ConvertCapabilities(configuration.audio_capabilities));
  if (!configuration.video_capabilities.empty())
    result->setVideoCapabilities(
        ConvertCapabilities(configuration.video_capabilities));

  // |distinctiveIdentifier|, |persistentState|, and |sessionTypes| are always
  // set by requestMediaKeySystemAccess().
  result->setDistinctiveIdentifier(
      EncryptedMediaUtils::ConvertMediaKeysRequirementToEnum(
          configuration.distinctive_identifier));
  result->setPersistentState(
      EncryptedMediaUtils::ConvertMediaKeysRequirementToEnum(
          configuration.persistent_state));
  result->setSessionTypes(ConvertSessionTypes(configuration.session_types));

  // |label| will (and should) be a null string if it was not set.
  result->setLabel(configuration.label);
  return result;
}

ScriptPromise<MediaKeys> MediaKeySystemAccess::createMediaKeys(
    ScriptState* script_state) {
  // From http://w3c.github.io/encrypted-media/#createMediaKeys
  // (Reordered to be able to pass values into the promise constructor.)
  // 2.4 Let configuration be the value of this object's configuration value.
  // 2.5-2.8. [Set use distinctive identifier and persistent state allowed
  //          based on configuration.]
  WebMediaKeySystemConfiguration configuration = access_->GetConfiguration();

  // 1. Let promise be a new promise.
  MediaKeysConfig config = {keySystem(), UseHardwareSecureCodecs()};
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<MediaKeys>>(script_state);
  NewCdmResultPromise* helper = MakeGarbageCollected<NewCdmResultPromise>(
      resolver, config, configuration.session_types);
  auto promise = resolver->Promise();

  // 2. Asynchronously create and initialize the MediaKeys object.
  // 2.1 Let cdm be the CDM corresponding to this object.
  // 2.2 Load and initialize the cdm if necessary.
  // 2.3 If cdm fails to load or initialize, reject promise with a new
  //     DOMException whose name is the appropriate error name.
  //     (Done if completeWithException() called).
  auto* execution_context = ExecutionContext::From(script_state);
  access_->CreateContentDecryptionModule(
      helper->Result(),
      execution_context->GetTaskRunner(TaskType::kInternalMedia));

  ReportMetrics(execution_context, keySystem());

  // 3. Return promise.
  return promise;
}

}  // namespace blink
```