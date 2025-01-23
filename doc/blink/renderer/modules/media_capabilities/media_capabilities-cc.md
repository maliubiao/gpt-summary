Response:
The user wants a summary of the functionality of the provided C++ source code file `media_capabilities.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file is named `media_capabilities.cc` and resides in the `media_capabilities` directory within the Blink renderer. This strongly suggests it's responsible for handling queries about the media capabilities of the browser.

2. **Scan the includes:** The included headers provide clues about the functionalities:
    - `media/base/...`: Media-related base classes and utilities (codecs, MIME types, supported types).
    - `media/learning/...`:  Machine learning components likely used for predicting media playback smoothness.
    - `media/mojo/...`: Mojo interfaces for communication with the browser process.
    - `third_party/blink/public/mojom/...`:  Blink's Mojo interfaces, including Permissions Policy and use counters.
    - `third_party/blink/public/platform/...`: Platform abstractions for encrypted media, browser interface, and tasks.
    - `third_party/blink/renderer/bindings/...`:  Integration with JavaScript and V8.
    - `third_party/blink/renderer/core/...`: Core Blink functionalities, including DOM, execution context, and HTML parsing.
    - `third_party/blink/renderer/modules/encryptedmedia/...`: Encrypted Media Extensions (EME) support.
    - `third_party/blink/renderer/modules/media_capabilities/...`:  Likely contains related classes.
    - `third_party/blink/renderer/platform/...`:  Platform-level utilities for media capabilities and network.
    - `third_party/blink/renderer/platform/peerconnection/...`: WebRTC related functionalities.
    - `third_party/webrtc/...`: WebRTC library headers.

3. **Analyze the class definition:** The file defines the `MediaCapabilities` class, a Navigator supplement. This means it's accessible through the `navigator` object in JavaScript.

4. **Examine public methods:** Look for the main entry points and functionalities exposed by the class. The `queryDecodingCapabilities` and `queryEncodingCapabilities` methods stand out as core functionalities.

5. **Identify key data structures:**  Note the usage of `MediaDecodingConfiguration`, `MediaEncodingConfiguration`, `MediaKeySystemConfiguration`, and the corresponding "Info" objects. These represent the input and output structures for capability queries.

6. **Look for interactions with other components:** The presence of EME-related includes and the `MediaKeySystemAccessInitializer` class indicate interaction with encrypted media. The WebRTC includes and the handling of WebRTC-specific configurations show WebRTC integration. The `media::learning` namespace points to machine learning usage.

7. **Identify connections to web technologies:** The use of `ScriptPromise`, the presence of V8-related includes, and the association with `NavigatorBase` indicate a strong connection to JavaScript. The ability to query decoding and encoding capabilities directly relates to HTML's `<video>` and `<audio>` elements, as well as media recording and streaming APIs. CSS might be indirectly involved if media playback performance impacts rendering.

8. **Consider error handling and user mistakes:** Look for validation logic (`IsValid...Configuration`) and how invalid configurations are handled. This can reveal potential user errors.

9. **Think about the user journey:** How does a user's action trigger these capabilities checks? Interacting with media elements or using media-related JavaScript APIs are likely triggers.

10. **Formulate a summary:** Combine the observations into a concise description of the file's purpose and key functionalities.

**Self-Correction/Refinement:**

- Initially, I might focus too much on individual includes. It's important to group them by their functional area (e.g., media base, EME, WebRTC) to get a higher-level understanding.
-  The prompt specifically asks for relationships with JavaScript, HTML, and CSS. It's crucial to explicitly connect the code's functionalities to these technologies.
-  For logic and error examples,  generating concrete scenarios makes the explanation clearer.
- The request is for the *first* part of the analysis. The summary should reflect the understanding gained from this specific section of the code.
这是 `blink/renderer/modules/media_capabilities/media_capabilities.cc` 文件的第一部分，其主要功能可以归纳为：

**核心功能：提供查询浏览器媒体编解码能力的功能。**

该文件实现了 `MediaCapabilities` 类，这个类作为 `NavigatorBase` 的一个补充（Supplement），允许网页通过 JavaScript 查询浏览器对特定媒体格式（音频和视频）的解码和编码能力。这包括：

1. **支持性查询 (Supported):**  判断浏览器是否支持给定的媒体配置（例如，特定的 MIME 类型、编解码器、分辨率、帧率等）。
2. **流畅性查询 (Smooth):**  判断在给定的媒体配置下，浏览器是否能够流畅地播放或录制媒体。这可能涉及到硬件加速等因素。
3. **节能性查询 (Power Efficient):** 判断在给定的媒体配置下，浏览器在播放或录制媒体时是否节能。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `MediaCapabilities` 类通过 `NavigatorBase` 暴露给 JavaScript。开发者可以使用 `navigator.mediaCapabilities` 对象来调用其方法，例如 `decodingInfo()` 和 `encodingInfo()`，传入 `MediaDecodingConfiguration` 或 `MediaEncodingConfiguration` 对象来查询媒体能力。

   **举例说明:**
   ```javascript
   const config = {
     video: {
       contentType: 'video/mp4; codecs="avc1.42E01E"',
       width: 1920,
       height: 1080,
       framerate: 30
     }
   };

   navigator.mediaCapabilities.decodingInfo(config)
     .then(info => {
       console.log('Decoding support:', info.supported);
       console.log('Decoding smooth:', info.smooth);
       console.log('Decoding power efficient:', info.powerEfficient);
     });
   ```

* **HTML:**  `MediaCapabilities` 的查询结果可以影响网页如何选择和播放媒体资源。例如，网页可以使用查询结果来选择浏览器最擅长解码的视频格式，从而提高播放体验。这与 `<video>` 和 `<audio>` 元素密切相关。

   **举例说明:**  网页可能会根据 `decodingInfo` 的结果，选择播放 H.264 编码的 MP4 文件，而不是 HEVC 编码的 MP4 文件，如果前者被报告为更流畅或更节能。

* **CSS:**  CSS 本身与 `MediaCapabilities` 没有直接的功能性关联。但是，媒体播放的流畅性和性能（由 `MediaCapabilities` 报告）可能会间接影响页面的整体渲染性能，从而可能影响到 CSS 动画或其他视觉效果的表现。如果媒体播放卡顿，可能会影响用户对网页的感知。

**逻辑推理与假设输入输出：**

假设输入一个 `MediaDecodingConfiguration` 对象，描述了一个 H.264 编码的 1080p 视频：

```javascript
const config = {
  video: {
    contentType: 'video/mp4; codecs="avc1.42E01E"',
    width: 1920,
    height: 1080,
    framerate: 30
  }
};
```

**可能的输出 (MediaCapabilitiesDecodingInfo):**

* **假设浏览器支持硬件加速解码 H.264:**
   ```json
   {
     "supported": true,
     "smooth": true,
     "powerEfficient": true
   }
   ```

* **假设浏览器不支持硬件加速，但可以软件解码，性能一般:**
   ```json
   {
     "supported": true,
     "smooth": false,
     "powerEfficient": false
   }
   ```

* **假设浏览器完全不支持 H.264 解码:**
   ```json
   {
     "supported": false,
     "smooth": false,
     "powerEfficient": false
   }
   ```

**用户或编程常见的使用错误：**

1. **传入无效的配置对象:**  例如，缺少 `contentType` 字段，或者 `contentType` 的格式不正确。该文件中有 `IsValidMediaDecodingConfiguration` 和 `IsValidMediaEncodingConfiguration` 等函数进行校验。如果传入无效的配置，Promise 可能会 reject，或者返回一个表示不支持的结果。

   **举例说明:**
   ```javascript
   const invalidConfig = {
     video: {
       // Missing contentType
       width: 1920,
       height: 1080
     }
   };

   navigator.mediaCapabilities.decodingInfo(invalidConfig)
     .catch(error => {
       console.error('Error querying decoding info:', error); // 可能会捕获到错误
     });
   ```

2. **假设浏览器能力而没有进行查询:**  开发者可能会错误地假设所有浏览器都支持某种特定的编解码器，而没有使用 `MediaCapabilities` 进行查询，导致在某些浏览器上播放失败。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户访问一个包含媒体内容的网页。**
2. **网页的 JavaScript 代码尝试播放媒体。**
3. **为了优化播放体验，或者为了处理不同浏览器支持的格式，网页的 JavaScript 代码调用了 `navigator.mediaCapabilities.decodingInfo()` 或 `navigator.mediaCapabilities.encodingInfo()` 方法。**
4. **浏览器接收到 JavaScript 的调用，Blink 渲染引擎开始处理这个请求。**
5. **Blink 内部会创建 `MediaCapabilities` 对象（如果尚未创建）。**
6. **`queryDecodingCapabilities` 或 `queryEncodingCapabilities` 方法会被调用，参数是 JavaScript 传递过来的配置对象。**
7. **这些方法会解析配置对象，并调用底层的媒体能力查询接口，例如 `media::IsDecoderSupportedAudioType` 和 `media::IsDecoderSupportedVideoType`。**
8. **查询结果会被封装成 `MediaCapabilitiesDecodingInfo` 或 `MediaCapabilitiesInfo` 对象。**
9. **这个结果会通过 Promise 返回给 JavaScript 代码。**

在调试过程中，如果发现媒体播放出现问题，可以检查是否正确使用了 `MediaCapabilities` API，传入的配置是否正确，以及根据返回的结果是否做了合理的媒体选择。也可以在 `media_capabilities.cc` 中设置断点，查看配置的解析过程和底层能力查询的结果。

**第一部分功能归纳：**

总而言之，该文件的第一部分主要负责定义 `MediaCapabilities` 类，并实现了与 JavaScript 交互的接口，用于接收媒体解码能力查询请求，对输入配置进行基本的验证，并为后续的底层媒体能力查询做准备。它定义了核心的数据结构和流程，是实现媒体能力查询功能的基础。

### 提示词
```
这是目录为blink/renderer/modules/media_capabilities/media_capabilities.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/media_capabilities/media_capabilities.h"

#include <memory>
#include <optional>
#include <sstream>
#include <utility>

#include "base/feature_list.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "media/base/media_switches.h"
#include "media/base/media_util.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/supported_video_decoder_config.h"
#include "media/base/video_decoder_config.h"
#include "media/filters/stream_parser_factory.h"
#include "media/learning/common/media_learning_tasks.h"
#include "media/learning/common/target_histogram.h"
#include "media/learning/mojo/public/mojom/learning_task_controller.mojom-blink.h"
#include "media/mojo/mojom/media_metrics_provider.mojom-blink.h"
#include "media/mojo/mojom/media_types.mojom-blink.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_encrypted_media_client.h"
#include "third_party/blink/public/platform/web_encrypted_media_request.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_key_system_track_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_capabilities_decoding_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_capabilities_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_capabilities_key_system_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_decoding_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_encoding_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_key_system_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_key_system_media_capability.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/encryptedmedia/encrypted_media_utils.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_key_system_access.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_key_system_access_initializer_base.h"
#include "third_party/blink/renderer/modules/media_capabilities/media_capabilities_identifiability_metrics.h"
#include "third_party/blink/renderer/modules/media_capabilities_names.h"
#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_handler.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/media_capabilities/web_media_capabilities_info.h"
#include "third_party/blink/renderer/platform/media_capabilities/web_media_configuration.h"
#include "third_party/blink/renderer/platform/network/parsed_content_type.h"
#include "third_party/blink/renderer/platform/peerconnection/webrtc_decoding_info_handler.h"
#include "third_party/blink/renderer/platform/peerconnection/webrtc_encoding_info_handler.h"
#include "third_party/blink/renderer/platform/peerconnection/webrtc_util.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_utils.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/webrtc/api/audio_codecs/audio_format.h"
#include "third_party/webrtc/api/video_codecs/sdp_video_format.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

const double kLearningBadWindowThresholdDefault = 2;
const double kLearningNnrThresholdDefault = 3;
const bool kWebrtcDecodeSmoothIfPowerEfficientDefault = true;
const bool kWebrtcEncodeSmoothIfPowerEfficientDefault = true;

constexpr const char* kApplicationMimeTypePrefix = "application/";
constexpr const char* kAudioMimeTypePrefix = "audio/";
constexpr const char* kVideoMimeTypePrefix = "video/";
constexpr const char* kCodecsMimeTypeParam = "codecs";
constexpr const char* kSmpteSt2086HdrMetadataType = "smpteSt2086";
constexpr const char* kSmpteSt209410HdrMetadataType = "smpteSt2094-10";
constexpr const char* kSmpteSt209440HdrMetadataType = "smpteSt2094-40";
constexpr const char* kSrgbColorGamut = "srgb";
constexpr const char* kP3ColorGamut = "p3";
constexpr const char* kRec2020ColorGamut = "rec2020";
constexpr const char* kSrgbTransferFunction = "srgb";
constexpr const char* kPqTransferFunction = "pq";
constexpr const char* kHlgTransferFunction = "hlg";

// Gets parameters for kMediaLearningSmoothnessExperiment field trial. Will
// provide sane defaults when field trial not enabled. Values of -1 indicate
// predictions from a given task should be ignored.

// static
double GetLearningBadWindowThreshold() {
  return base::GetFieldTrialParamByFeatureAsDouble(
      media::kMediaLearningSmoothnessExperiment,
      MediaCapabilities::kLearningBadWindowThresholdParamName,
      kLearningBadWindowThresholdDefault);
}

// static
double GetLearningNnrThreshold() {
  return base::GetFieldTrialParamByFeatureAsDouble(
      media::kMediaLearningSmoothnessExperiment,
      MediaCapabilities::kLearningNnrThresholdParamName,
      kLearningNnrThresholdDefault);
}

// static
bool WebrtcDecodeForceSmoothIfPowerEfficient() {
  return base::GetFieldTrialParamByFeatureAsBool(
      media::kWebrtcMediaCapabilitiesParameters,
      MediaCapabilities::kWebrtcDecodeSmoothIfPowerEfficientParamName,
      kWebrtcDecodeSmoothIfPowerEfficientDefault);
}

// static
bool WebrtcEncodeForceSmoothIfPowerEfficient() {
  return base::GetFieldTrialParamByFeatureAsBool(
      media::kWebrtcMediaCapabilitiesParameters,
      MediaCapabilities::kWebrtcEncodeSmoothIfPowerEfficientParamName,
      kWebrtcEncodeSmoothIfPowerEfficientDefault);
}

// static
bool UseGpuFactoriesForPowerEfficient(
    ExecutionContext* execution_context,
    const MediaKeySystemAccess* key_system_access) {
  // TODO(1105258): GpuFactories isn't available in worker scope yet.
  if (!execution_context || execution_context->IsWorkerGlobalScope())
    return false;

  // TODO(1105258): Decoding w/ EME often means we can't use the GPU accelerated
  // path. Add additional logic to detect when GPU acceleration is really
  // available.
  if (key_system_access)
    return false;

  return base::FeatureList::IsEnabled(
      media::kMediaCapabilitiesQueryGpuFactories);
}

// Utility function that will create a MediaCapabilitiesDecodingInfo object with
// all the values set to either true or false.
MediaCapabilitiesDecodingInfo* CreateDecodingInfoWith(bool value) {
  MediaCapabilitiesDecodingInfo* info = MediaCapabilitiesDecodingInfo::Create();
  info->setSupported(value);
  info->setSmooth(value);
  info->setPowerEfficient(value);
  return info;
}

// Utility function that will create a MediaCapabilitiesInfo object with
// all the values set to either true or false.
MediaCapabilitiesInfo* CreateEncodingInfoWith(bool value) {
  MediaCapabilitiesInfo* info = MediaCapabilitiesInfo::Create();
  info->setSupported(value);
  info->setSmooth(value);
  info->setPowerEfficient(value);
  return info;
}

ScriptPromise<MediaCapabilitiesDecodingInfo>
CreateResolvedPromiseToDecodingInfoWith(
    bool value,
    ScriptState* script_state,
    const MediaDecodingConfiguration* config) {
  MediaCapabilitiesDecodingInfo* info = CreateDecodingInfoWith(value);
  media_capabilities_identifiability_metrics::ReportDecodingInfoResult(
      ExecutionContext::From(script_state), config, info);
  return ToResolvedPromise<MediaCapabilitiesDecodingInfo>(script_state, info);
}

MediaCapabilitiesDecodingInfo* CreateEncryptedDecodingInfoWith(
    bool value,
    MediaKeySystemAccess* access) {
  MediaCapabilitiesDecodingInfo* info = CreateDecodingInfoWith(value);
  info->setKeySystemAccess(access);
  return info;
}

class MediaCapabilitiesKeySystemAccessInitializer final
    : public MediaKeySystemAccessInitializerBase {
 public:
  using GetPerfCallback = base::OnceCallback<void(
      ScriptPromiseResolver<MediaCapabilitiesDecodingInfo>*,
      MediaKeySystemAccess*)>;

  MediaCapabilitiesKeySystemAccessInitializer(
      ExecutionContext* context,
      ScriptPromiseResolverBase* resolver,
      const String& key_system,
      const HeapVector<Member<MediaKeySystemConfiguration>>&
          supported_configurations,
      GetPerfCallback get_perf_callback)
      : MediaKeySystemAccessInitializerBase(
            context,
            resolver,
            key_system,
            supported_configurations,
            /*is_from_media_capabilities=*/true),
        get_perf_callback_(std::move(get_perf_callback)) {}

  MediaCapabilitiesKeySystemAccessInitializer(
      const MediaCapabilitiesKeySystemAccessInitializer&) = delete;
  MediaCapabilitiesKeySystemAccessInitializer& operator=(
      const MediaCapabilitiesKeySystemAccessInitializer&) = delete;

  ~MediaCapabilitiesKeySystemAccessInitializer() override = default;

  void RequestSucceeded(
      std::unique_ptr<WebContentDecryptionModuleAccess> access) override {
    DVLOG(3) << __func__;

    if (!IsExecutionContextValid())
      return;

    // Query the client for smoothness and power efficiency of the video. It
    // will resolve the promise.
    std::move(get_perf_callback_)
        .Run(resolver_->DowncastTo<MediaCapabilitiesDecodingInfo>(),
             MakeGarbageCollected<MediaKeySystemAccess>(std::move(access)));
  }

  void RequestNotSupported(const WebString& error_message) override {
    DVLOG(3) << __func__ << " error: " << error_message.Ascii();

    if (!IsExecutionContextValid())
      return;

    MediaCapabilitiesDecodingInfo* info =
        CreateEncryptedDecodingInfoWith(false, nullptr);

    resolver_->DowncastTo<MediaCapabilitiesDecodingInfo>()->Resolve(info);
  }

  void Trace(Visitor* visitor) const override {
    MediaKeySystemAccessInitializerBase::Trace(visitor);
  }

 private:
  GetPerfCallback get_perf_callback_;
};

bool IsValidFrameRate(double framerate) {
  return std::isfinite(framerate) && framerate > 0;
}

bool IsValidMimeType(const String& content_type,
                     const String& prefix,
                     bool is_webrtc) {
  ParsedContentType parsed_content_type(content_type);

  if (!parsed_content_type.IsValid())
    return false;

  // Valid ParsedContentType implies we have a mime type.
  DCHECK(parsed_content_type.MimeType());
  if (!parsed_content_type.MimeType().StartsWith(prefix) &&
      (is_webrtc ||
       !parsed_content_type.MimeType().StartsWith(kApplicationMimeTypePrefix)))
    return false;

  // No requirement on parameters for RTP MIME types.
  if (is_webrtc)
    return true;

  const auto& parameters = parsed_content_type.GetParameters();

  if (parameters.ParameterCount() > 1)
    return false;

  if (parameters.ParameterCount() == 0)
    return true;

  return EqualIgnoringASCIICase(parameters.begin()->name, kCodecsMimeTypeParam);
}

bool IsValidMediaConfiguration(const MediaConfiguration* configuration) {
  return configuration->hasAudio() || configuration->hasVideo();
}

bool IsValidVideoConfiguration(const VideoConfiguration* configuration,
                               bool is_decode,
                               bool is_webrtc) {
  DCHECK(configuration->hasContentType());
  if (!IsValidMimeType(configuration->contentType(), kVideoMimeTypePrefix,
                       is_webrtc))
    return false;

  DCHECK(configuration->hasFramerate());
  if (!IsValidFrameRate(configuration->framerate()))
    return false;

  // scalabilityMode only valid for WebRTC encode configuration.
  if ((!is_webrtc || is_decode) && configuration->hasScalabilityMode())
    return false;
  // spatialScalability only valid for WebRTC decode configuration.
  if ((!is_webrtc || !is_decode) && configuration->hasSpatialScalability())
    return false;

  return true;
}

bool IsValidAudioConfiguration(const AudioConfiguration* configuration,
                               bool is_webrtc) {
  DCHECK(configuration->hasContentType());

  if (!IsValidMimeType(configuration->contentType(), kAudioMimeTypePrefix,
                       is_webrtc))
    return false;

  return true;
}

bool IsValidMediaDecodingConfiguration(
    const MediaDecodingConfiguration* configuration,
    bool is_webrtc,
    String* message) {
  if (!IsValidMediaConfiguration(configuration)) {
    *message =
        "The configuration dictionary has neither |video| nor |audio| "
        "specified and needs at least one of them.";
    return false;
  }

  if (configuration->hasKeySystemConfiguration()) {
    if (is_webrtc) {
      *message =
          "The keySystemConfiguration object cannot be set for webrtc "
          "MediaDecodingType.";
      return false;
    }

    if (configuration->keySystemConfiguration()->hasAudio() &&
        !configuration->hasAudio()) {
      *message =
          "The keySystemConfiguration object contains an audio property but "
          "the root configuration has no audio configuration.";
      return false;
    }

    if (configuration->keySystemConfiguration()->hasVideo() &&
        !configuration->hasVideo()) {
      *message =
          "The keySystemConfiguration object contains a video property but the "
          "root configuration has no video configuration.";
      return false;
    }
  }

  if (configuration->hasVideo() &&
      !IsValidVideoConfiguration(configuration->video(), /*is_decode=*/true,
                                 is_webrtc)) {
    *message = "The video configuration dictionary is not valid.";
    return false;
  }

  if (configuration->hasAudio() &&
      !IsValidAudioConfiguration(configuration->audio(), is_webrtc)) {
    *message = "The audio configuration dictionary is not valid.";
    return false;
  }

  return true;
}

bool IsValidMediaEncodingConfiguration(
    const MediaEncodingConfiguration* configuration,
    bool is_webrtc,
    String* message) {
  if (!IsValidMediaConfiguration(configuration)) {
    *message =
        "The configuration dictionary has neither |video| nor |audio| "
        "specified and needs at least one of them.";
    return false;
  }

  if (configuration->hasVideo() &&
      !IsValidVideoConfiguration(configuration->video(), /*is_decode=*/false,
                                 is_webrtc)) {
    *message = "The video configuration dictionary is not valid.";
    return false;
  }

  if (configuration->hasAudio() &&
      !IsValidAudioConfiguration(configuration->audio(), is_webrtc)) {
    *message = "The audio configuration dictionary is not valid.";
    return false;
  }

  return true;
}

WebAudioConfiguration ToWebAudioConfiguration(
    const AudioConfiguration* configuration) {
  WebAudioConfiguration web_configuration;

  // |contentType| is mandatory.
  DCHECK(configuration->hasContentType());
  ParsedContentType parsed_content_type(configuration->contentType());
  DCHECK(parsed_content_type.IsValid());
  DCHECK(!parsed_content_type.GetParameters().HasDuplicatedNames());

  web_configuration.mime_type = parsed_content_type.MimeType().LowerASCII();
  web_configuration.codec = parsed_content_type.ParameterValueForName(
      media_capabilities_names::kCodecs);

  // |channels| is optional and will be set to a null WebString if not present.
  web_configuration.channels = configuration->hasChannels()
                                   ? WebString(configuration->channels())
                                   : WebString();

  if (configuration->hasBitrate())
    web_configuration.bitrate = configuration->bitrate();

  if (configuration->hasSamplerate())
    web_configuration.samplerate = configuration->samplerate();

  return web_configuration;
}

WebVideoConfiguration ToWebVideoConfiguration(
    const VideoConfiguration* configuration) {
  WebVideoConfiguration web_configuration;

  // All the properties are mandatory.
  DCHECK(configuration->hasContentType());
  ParsedContentType parsed_content_type(configuration->contentType());
  DCHECK(parsed_content_type.IsValid());
  DCHECK(!parsed_content_type.GetParameters().HasDuplicatedNames());
  web_configuration.mime_type = parsed_content_type.MimeType().LowerASCII();
  web_configuration.codec = parsed_content_type.ParameterValueForName(
      media_capabilities_names::kCodecs);

  DCHECK(configuration->hasWidth());
  web_configuration.width = configuration->width();

  DCHECK(configuration->hasHeight());
  web_configuration.height = configuration->height();

  DCHECK(configuration->hasBitrate());
  web_configuration.bitrate = configuration->bitrate();

  DCHECK(configuration->hasFramerate());
  web_configuration.framerate = configuration->framerate();

  return web_configuration;
}

WebMediaConfiguration ToWebMediaConfiguration(
    const MediaEncodingConfiguration* configuration) {
  WebMediaConfiguration web_configuration;

  // |type| is required.
  DCHECK(configuration->hasType());
  if (configuration->type() == "record") {
    web_configuration.type = MediaConfigurationType::kRecord;
  } else if (configuration->type() == "transmission") {
    web_configuration.type = MediaConfigurationType::kTransmission;
  } else {
    NOTREACHED();
  }

  if (configuration->hasAudio()) {
    web_configuration.audio_configuration =
        ToWebAudioConfiguration(configuration->audio());
  }

  if (configuration->hasVideo()) {
    web_configuration.video_configuration =
        ToWebVideoConfiguration(configuration->video());
  }

  return web_configuration;
}

webrtc::SdpAudioFormat ToSdpAudioFormat(
    const AudioConfiguration* configuration) {
  DCHECK(configuration->hasContentType());
  // Convert audio_configuration to SdpAudioFormat.
  ParsedContentType parsed_content_type(configuration->contentType());
  DCHECK(parsed_content_type.IsValid());
  const String codec_name =
      WebrtcCodecNameFromMimeType(parsed_content_type.MimeType(), "audio");
  // TODO(https://crbug.com/1187565): Deal with the special case where the clock
  // rate is not the same as the sample rate.
  const int clockrate_hz =
      configuration->hasSamplerate() ? configuration->samplerate() : 0;
  const size_t channels = configuration->hasChannels()
                              ? configuration->channels().ToUIntStrict()
                              : 0;
  return {codec_name.Utf8(), clockrate_hz, channels};
}

webrtc::SdpVideoFormat ToSdpVideoFormat(
    const VideoConfiguration* configuration) {
  DCHECK(configuration->hasContentType());
  // Convert video_configuration to SdpVideoFormat.
  ParsedContentType parsed_content_type(configuration->contentType());
  DCHECK(parsed_content_type.IsValid());
  const String codec_name =
      WebrtcCodecNameFromMimeType(parsed_content_type.MimeType(), "video");
  const std::map<std::string, std::string> parameters =
      ConvertToSdpVideoFormatParameters(parsed_content_type.GetParameters());
  return {codec_name.Utf8(), parameters};
}

bool CheckMseSupport(const String& mime_type, const String& codec) {
  // For MSE queries, we assume the queried audio and video streams will be
  // placed into separate source buffers.
  // TODO(chcunningham): Clarify this assumption in the spec.

  // Media MIME API expects a vector of codec strings. We query audio and video
  // separately, so |codec_string|.size() should always be 1 or 0 (when no
  // codecs parameter is required for the given mime type).
  base::span<const std::string> codecs;

  const std::string codec_ascii = codec.Ascii();
  if (!codec.Ascii().empty())
    codecs = base::span_from_ref(codec_ascii);

  if (media::SupportsType::kSupported !=
      media::StreamParserFactory::IsTypeSupported(mime_type.Ascii(), codecs)) {
    DVLOG(2) << __func__
             << " MSE does not support the content type: " << mime_type.Ascii()
             << " " << (codecs.empty() ? "" : codecs.front());
    return false;
  }

  return true;
}

void ParseDynamicRangeConfigurations(
    const blink::VideoConfiguration* video_config,
    media::VideoColorSpace* color_space,
    gfx::HdrMetadataType* hdr_metadata) {
  DCHECK(color_space);
  DCHECK(hdr_metadata);

  // TODO(1066628): Follow up on MediaCapabilities spec regarding reconciling
  // discrepancies between mime type and colorGamut/transferFunction; for now,
  // give precedence to the latter.

  if (video_config->hasHdrMetadataType()) {
    const auto& hdr_metadata_type = video_config->hdrMetadataType();
    // TODO(crbug.com/1092328): Switch by V8HdrMetadataType::Enum.
    if (hdr_metadata_type == kSmpteSt2086HdrMetadataType) {
      *hdr_metadata = gfx::HdrMetadataType::kSmpteSt2086;
    } else if (hdr_metadata_type == kSmpteSt209410HdrMetadataType) {
      *hdr_metadata = gfx::HdrMetadataType::kSmpteSt2094_10;
    } else if (hdr_metadata_type == kSmpteSt209440HdrMetadataType) {
      *hdr_metadata = gfx::HdrMetadataType::kSmpteSt2094_40;
    } else {
      NOTREACHED();
    }
  } else {
    *hdr_metadata = gfx::HdrMetadataType::kNone;
  }

  if (video_config->hasColorGamut()) {
    const auto& color_gamut = video_config->colorGamut();
    // TODO(crbug.com/1092328): Switch by V8ColorGamut::Enum.
    if (color_gamut == kSrgbColorGamut) {
      color_space->primaries = media::VideoColorSpace::PrimaryID::BT709;
    } else if (color_gamut == kP3ColorGamut) {
      color_space->primaries = media::VideoColorSpace::PrimaryID::SMPTEST431_2;
    } else if (color_gamut == kRec2020ColorGamut) {
      color_space->primaries = media::VideoColorSpace::PrimaryID::BT2020;
    } else {
      NOTREACHED();
    }
  }

  if (video_config->hasTransferFunction()) {
    const auto& transfer_function = video_config->transferFunction();
    // TODO(crbug.com/1092328): Switch by V8TransferFunction::Enum.
    if (transfer_function == kSrgbTransferFunction) {
      color_space->transfer = media::VideoColorSpace::TransferID::BT709;
    } else if (transfer_function == kPqTransferFunction) {
      color_space->transfer = media::VideoColorSpace::TransferID::SMPTEST2084;
    } else if (transfer_function == kHlgTransferFunction) {
      color_space->transfer = media::VideoColorSpace::TransferID::ARIB_STD_B67;
    } else {
      NOTREACHED();
    }
  }
}

// Returns whether the audio codec associated with the audio configuration is
// valid and non-ambiguous.
// |console_warning| is an out param containing a message to be printed in the
//                   console.
bool IsAudioCodecValid(const String& mime_type,
                       const String& codec,
                       String* console_warning) {
  media::AudioCodec audio_codec = media::AudioCodec::kUnknown;
  bool is_audio_codec_ambiguous = true;

  if (!media::ParseAudioCodecString(mime_type.Ascii(), codec.Ascii(),
                                    &is_audio_codec_ambiguous, &audio_codec)) {
    *console_warning = StringView("Failed to parse audio contentType: ") +
                       String{mime_type} + StringView("; codecs=") +
                       String{codec};

    return false;
  }

  if (is_audio_codec_ambiguous) {
    *console_warning = StringView("Invalid (ambiguous) audio codec string: ") +
                       String{mime_type} + StringView("; codecs=") +
                       String{codec};
    return false;
  }

  return true;
}

// Returns whether the video codec associated with the video configuration is
// valid and non-ambiguous.
// |out_video_profile| is an out param containing the video codec profile if the
//                     codec is valid.
// |console_warning| is an out param containing a message to be printed in the
//                   console.
bool IsVideoCodecValid(const String& mime_type,
                       const String& codec,
                       media::VideoCodec* out_video_codec,
                       media::VideoCodecProfile* out_video_profile,
                       String* console_warning) {
  auto result = media::ParseVideoCodecString(mime_type.Ascii(), codec.Ascii(),
                                             /*allow_ambiguous_matches=*/false);
  if (result) {
    *out_video_codec = result->codec;
    *out_video_profile = result->profile;
    return true;
  }

  if (media::ParseVideoCodecString(mime_type.Ascii(), codec.Ascii(),
                                   /*allow_ambiguous_matches=*/true)) {
    *console_warning = StringView("Invalid (ambiguous) video codec string: ") +
                       String{mime_type} + StringView("; codecs=") +
                       String{codec};
    return false;
  }

  *console_warning = StringView("Failed to parse video contentType: ") +
                     String{mime_type} + StringView("; codecs=") +
                     String{codec};
  return false;
}

// Returns whether the AudioConfiguration is supported.
// IsAudioCodecValid() MUST be called before.
bool IsAudioConfigurationSupported(
    const blink::AudioConfiguration* audio_config,
    const String& mime_type,
    const String& codec) {
  media::AudioCodec audio_codec = media::AudioCodec::kUnknown;
  media::AudioCodecProfile audio_profile = media::AudioCodecProfile::kUnknown;
  bool is_audio_codec_ambiguous = true;
  bool is_spatial_rendering = false;

  // Must succeed as IsAudioCodecValid() should have been called before.
  bool parsed =
      media::ParseAudioCodecString(mime_type.Ascii(), codec.Ascii(),
                                   &is_audio_codec_ambiguous, &audio_codec);
  DCHECK(parsed && !is_audio_codec_ambiguous);

  if (audio_config->hasSpatialRendering())
    is_spatial_rendering = audio_config->spatialRendering();

  return media::IsDecoderSupportedAudioType(
      {audio_codec, audio_profile, is_spatial_rendering});
}

// Returns whether the VideoConfiguration is supported.
// IsVideoCodecValid() MUST be called before.
bool IsVideoConfigurationSupported(const String& mime_type,
                                   const String& codec,
                                   media::VideoColorSpace video_color_space,
                                   gfx::HdrMetadataType hdr_metadata_type) {
  // Must succeed as IsVideoCodecValid() should have been called before.
  auto result = media::ParseVideoCodecString(mime_type.Ascii(), codec.Ascii(),
                                             /*allow_ambiguous_matches=*/false);
  DCHECK(result);

  // ParseVideoCodecString will fill in a default of REC709 for every codec, but
  // only some codecs actually have color space information that we can use
  // to validate against provided colorGamut and transferFunction fields.
  const bool codec_string_has_non_default_color_space =
      result->color_space.IsSpecified() &&
      (result->codec == media::VideoCodec::kVP9 ||
       result->codec == media::VideoCodec::kAV1);

  if (video_color_space.IsSpecified() &&
      codec_string_has_non_default_color_space) {
    // Per spec, report unsupported if color space information is mismatched.
    if (video_color_space.transfer != result->color_space.transfer ||
        video_color_space.primaries != result->color_space.primaries) {
      DLOG(ERROR) << "Mismatched color spaces between config and codec string.";
      return false;
    }
    // Prefer color space from codec string since it'll be more specified.
    video_color_space = result->color_space;
  } else if (video_color_space.IsSpecified()) {
    // Prefer color space from the config.
  } else {
    // There's no color space in the config and only a default one from codec.
    video_color_space = result->color_space;
  }

  return media::IsDecoderSupportedVideoType({result->codec, result->profile,
                                             result->level, video_color_space,
                                             hdr_metadata_type});
}

void OnMediaCapabilitiesEncodingInfo(
    ScriptPromiseResolver<MediaCapabilitiesInfo>* resolver,
    std::unique_ptr<WebMediaCapabilitiesInfo> result) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed()) {
    return;
  }

  Persistent<MediaCapabilitiesInfo> info(MediaCapabilitiesInfo::Create());
  info->setSupported(result->supported);
  info->setSmooth(result->smooth);
  info->setPowerEfficient(result->power_efficient);

  resolver->Resolve(std::move(info));
}

bool ParseContentType(const String& content_type,
                      String* mime_type,
                      String* codec) {
  DCHECK(mime_type);
  DCHECK(codec);

  ParsedContentType parsed_content_type(content_type);
  if (!parsed_content_type.IsValid() ||
      parsed_content_type.GetParameters().HasDuplicatedNames()) {
    return false;
  }

  *mime_type = parsed_content_type.MimeType().LowerASCII();
  *codec = parsed_content_type.ParameterValueForName(
      media_capabilities_names::kCodecs);
  return true;
}

}  // anonymous namespace

const char MediaCapabilities::kLearningBadWindowThresholdParamName[] =
    "bad_window_threshold";

const char MediaCapabilities::kLearningNnrThresholdParamName[] =
    "nnr_threshold";

const char MediaCapabilities::kWebrtcDecodeSmoothIfPowerEfficientParamName[] =
    "webrtc_decode_smooth_if_power_efficient";

const char MediaCapabilities::kWebrtcEncodeSmoothIfPowerEfficientParamName[] =
    "webrtc_encode_smooth_if_power_efficient";

// static
const char MediaCapabilities::kSupplementName[] = "MediaCapabilities";

MediaCapabilities* MediaCapabilities::mediaCapabilities(
    NavigatorBase& navigator) {
  MediaCapabilities* supplement =
      Supplement<NavigatorBase>::From<MediaCapabilities>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<MediaCapabilities>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

MediaCapabilities::MediaCapabilities(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      decode_history_service_(navigator.GetExecutionContext()),
      bad_window_predictor_(navigator.GetExecutionContext()),
      nnr_predictor_(navigator.GetExecutionContext()),
      webrtc_history_service_(navigator.GetExecutionContext()) {}

void MediaCapabilities::Trace(blink::Visitor* visitor) const {
  visitor->Trace(decode_history_service_);
  visitor->Trace(bad_window_predictor_);
  visitor->Trace(nnr_predictor_);
  visitor->Trace(webrtc_history_service_);
  visitor->Trace(pending_cb_map_);
  ScriptWrappable::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
}

MediaCapabilities::PendingCallbackState::PendingCallbackState(
    ScriptPromiseResolverBase* resolver,
    MediaKeySystemAccess* access,
    const base::TimeTicks& request_time,
    std::optional<IdentifiableToken> input_token)
    : resolver(resolver),
      key_system_access(access),
      request_time(request_time),
      input_token(input_token) {}

void MediaCapabilities::PendingCallbac
```