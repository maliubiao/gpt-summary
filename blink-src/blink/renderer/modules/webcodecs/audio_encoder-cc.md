Response:
Let's break down the thought process for analyzing this `audio_encoder.cc` file.

1. **Understand the Goal:** The primary request is to understand the *functionality* of this C++ file within the Chromium/Blink context. This means identifying what it *does*, how it interacts with other parts of the system, and what errors users might encounter.

2. **High-Level Overview (Code Reading Strategy):**  The first step is a quick scan of the `#include` directives and the namespace. This immediately tells us:
    * It's part of the `blink` renderer.
    * It's within the `webcodecs` module, specifically dealing with audio encoding.
    * It uses several media-related headers (`media/audio/`, `media/base/`, `media/mojo/`). This strongly suggests it's the backend implementation of the WebCodecs `AudioEncoder` API.
    * It interacts with JavaScript bindings (`renderer/bindings/modules/v8/`).

3. **Identify Key Classes and Functions:** Look for class definitions and significant function names. In this file, `AudioEncoder` is the central class. Then, examine its methods: `Create`, the constructor, destructor, `ProcessConfigure`, `ProcessEncode`, `isConfigSupported`, `CallOutputCallback`, etc. These function names provide clues about the workflow.

4. **Analyze Core Functionality (Step-by-Step):**

    * **`AudioEncoder::Create`:**  This is likely the entry point from JavaScript. It creates an instance of the `AudioEncoder`.
    * **Constructor:** Initializes the base class and registers a use counter (indicating this feature is being tracked).
    * **`ProcessConfigure`:**  This is triggered when the JavaScript `AudioEncoder` is configured with encoder settings. Key actions here include:
        * Parsing the configuration from JavaScript (`ParseConfigStatic`).
        * Validating the configuration (`VerifyCodecSupport`).
        * Creating the actual media encoder (either platform-specific or software).
        * Setting up callbacks for output (`CallOutputCallback`) and completion.
    * **`ProcessEncode`:**  This handles the encoding of audio data passed from JavaScript. It:
        * Receives `AudioData`.
        * Validates the input data against the configuration.
        * Converts the `AudioData` to a `media::AudioBus`.
        * Calls the underlying media encoder's `Encode` method.
    * **`CallOutputCallback`:**  This is the crucial function for returning encoded audio data to JavaScript. It:
        * Receives the encoded data from the media encoder.
        * Creates an `EncodedAudioChunk` (the JavaScript representation of encoded data).
        * Creates `EncodedAudioChunkMetadata` which includes the decoder configuration (sent on the first output or when the codec description changes).
        * Invokes the JavaScript callback with the encoded chunk and metadata.
    * **`isConfigSupported`:**  This static method allows JavaScript to query if a given encoder configuration is supported by the browser. It uses `ParseConfigStatic` and `VerifyCodecSupportStatic`.

5. **Trace Data Flow:** Follow the path of data:
    * JavaScript config object -> `ParseConfigStatic` -> `AudioEncoderTraits::ParsedConfig` (internal representation).
    * `AudioData` from JavaScript -> `ProcessEncode` -> `media::AudioBus` -> underlying media encoder.
    * Encoded data from media encoder -> `CallOutputCallback` -> `EncodedAudioChunk` -> JavaScript callback.

6. **Identify Relationships with JavaScript, HTML, CSS:**

    * **JavaScript:**  This file directly implements the backend for the JavaScript `AudioEncoder` API. The parsing of configuration objects (like `AudioEncoderConfig`, `OpusEncoderConfig`, `AacEncoderConfig`) directly corresponds to the JavaScript API. The `CallOutputCallback` sends data back to JavaScript. The `isConfigSupported` method is called from JavaScript.
    * **HTML:** While this file doesn't directly interact with HTML parsing, the WebCodecs API, which this file implements, is used by JavaScript within web pages loaded via HTML.
    * **CSS:**  No direct relationship with CSS. CSS is for styling.

7. **Analyze Logic and Error Handling:**

    * **Configuration Parsing:** The `ParseConfigStatic` and related `Parse...ConfigStatic` functions handle the conversion from JavaScript configuration objects to internal C++ structures. They perform validation and throw exceptions if the input is invalid.
    * **Codec Support Verification:** `VerifyCodecSupportStatic` checks if the requested codec and its parameters are supported by the underlying media libraries.
    * **Error Handling:**  The code uses `ExceptionState` to report errors back to JavaScript. It also handles errors from the underlying media encoder through callbacks. Specific error messages are generated to provide useful information.

8. **Consider User and Programming Errors:** Think about how a developer might misuse the `AudioEncoder` API, leading to errors handled by this C++ code. Examples include:
    * Providing an invalid codec string.
    * Using unsupported sample rates or channel counts.
    * Setting out-of-range values for codec-specific parameters (like Opus complexity).
    * Passing `AudioData` with mismatched parameters.

9. **Debugging Hints (User Operations):**  Think about how a user action in a web browser could lead to this code being executed. The sequence would involve:
    * A web page using the WebCodecs API.
    * JavaScript code creating an `AudioEncoder` instance.
    * Configuring the encoder using `configure()`.
    * Providing `AudioData` to the `encode()` method.

10. **Review and Refine:** After the initial analysis, go back and review the code more closely. Look for edge cases, specific parameter validation, and how different codecs (Opus, AAC) are handled. Ensure the explanations are clear and concise.

By following this structured approach, we can systematically understand the functionality of a complex C++ file like `audio_encoder.cc` and relate it to the broader web development context. The key is to break the problem down into smaller, manageable parts.
好的，让我们详细分析一下 `blink/renderer/modules/webcodecs/audio_encoder.cc` 这个文件。

**文件功能概述：**

`audio_encoder.cc` 文件是 Chromium Blink 引擎中 `WebCodecs API` 的一部分，它负责实现音频编码器的核心逻辑。简单来说，它的主要功能是将未经压缩的原始音频数据（例如，从麦克风捕获的音频流）编码成指定格式的压缩音频数据，以便于存储、传输或进一步处理。

**主要功能点：**

1. **音频编码器类的实现 (`AudioEncoder`):**  这是文件中的核心类，它封装了音频编码的整个流程。它负责接收配置信息、处理音频数据、调用底层的编码器以及将编码后的数据返回给 JavaScript。

2. **配置处理 (`ProcessConfigure`, `ParseConfigStatic`):**
   - 接收并解析来自 JavaScript 的 `AudioEncoderConfig` 对象，该对象包含了编码器所需的各种参数，例如编解码器类型（如 Opus, AAC）、采样率、通道数、比特率等。
   - 对配置参数进行验证，确保其在允许的范围内，并检查是否支持所请求的编解码器和配置。

3. **音频数据编码 (`ProcessEncode`):**
   - 接收来自 JavaScript 的 `AudioData` 对象，该对象包含了需要编码的原始音频数据。
   - 将 `AudioData` 转换为底层编码器可以处理的格式。
   - 调用实际的音频编码器（例如 `media::AudioOpusEncoder`, `media::MojoAudioEncoder`）进行编码。

4. **编码结果回调 (`CallOutputCallback`):**
   - 当底层编码器完成编码后，该函数会被调用。
   - 它将编码后的音频数据封装成 `EncodedAudioChunk` 对象，并将其传递给 JavaScript 中通过 `output` 事件注册的回调函数。
   - 如果是首次输出或者编解码器描述信息发生变化，还会生成 `EncodedAudioChunkMetadata`，包含解码器配置信息。

5. **编解码器支持查询 (`isConfigSupported`):**
   - 提供一个静态方法，允许 JavaScript 查询给定的 `AudioEncoderConfig` 是否被当前浏览器支持。

6. **错误处理:**
   - 文件中包含了各种错误处理逻辑，例如处理无效的配置参数、编码过程中发生的错误等。这些错误会以 `DOMException` 的形式抛给 JavaScript。

**与 JavaScript, HTML, CSS 的关系：**

`audio_encoder.cc` 是 WebCodecs API 的底层实现，它与 JavaScript 紧密相连。

* **JavaScript:**
    - JavaScript 代码会创建 `AudioEncoder` 的实例。
    - JavaScript 通过 `configure()` 方法向 `AudioEncoder` 传递配置信息 (`AudioEncoderConfig`)。
    - JavaScript 通过 `encode()` 方法向 `AudioEncoder` 传递需要编码的 `AudioData`。
    - JavaScript 通过监听 `output` 事件接收编码后的 `EncodedAudioChunk`。
    - JavaScript 可以调用 `AudioEncoder.isConfigSupported()` 来检查配置支持情况。

    **举例说明:**

    ```javascript
    const encoder = new AudioEncoder({
      output: (chunk, metadata) => {
        console.log('Encoded chunk:', chunk);
        if (metadata && metadata.decoderConfig) {
          console.log('Decoder config:', metadata.decoderConfig);
        }
      },
      error: (e) => {
        console.error('Encoding error:', e);
      }
    });

    encoder.configure({
      codec: 'opus',
      samplerate: 48000,
      numberOfChannels: 2,
      bitrate: 128000
    });

    // 从 AudioTrack 获取 AudioData
    const audioData = ...;
    encoder.encode(audioData);

    AudioEncoder.isConfigSupported({
      codec: 'aac',
      samplerate: 44100,
      numberOfChannels: 1
    }).then(support => {
      console.log('AAC support:', support);
    });
    ```

* **HTML:**
    - HTML 负责加载包含使用 WebCodecs API 的 JavaScript 代码的网页。
    - HTML 中可能包含 `<audio>` 或 `<video>` 元素，虽然 `AudioEncoder` 本身不直接操作这些元素，但编码后的音频数据可能会被用于这些元素。

* **CSS:**
    - CSS 与 `audio_encoder.cc` 没有直接关系。CSS 负责网页的样式和布局。

**逻辑推理（假设输入与输出）：**

假设 JavaScript 代码创建了一个 Opus 编码器并传入了一段音频数据：

**假设输入:**

1. **配置 (JavaScript `AudioEncoderConfig`):**
   ```javascript
   {
     codec: 'opus',
     samplerate: 48000,
     numberOfChannels: 2,
     bitrate: 128000
   }
   ```
2. **音频数据 (JavaScript `AudioData`):**
   - `sampleRate`: 48000
   - `numberOfChannels`: 2
   - `format`: "f32-planar" (浮点数，平面排列)
   - `timestamp`: 某个 `DOMHighResTimeStamp` 值
   - `data`: 包含实际音频数据的 `Float32Array` 数组

**逻辑推理过程 (C++ `audio_encoder.cc` 内部):**

1. **`ProcessConfigure`:** 接收到配置，`ParseConfigStatic` 将 JavaScript 对象转换为 C++ 结构体。`VerifyCodecSupport` 检查 Opus 编码是否支持 48000Hz 采样率和 2 个通道。
2. **`CreateMediaAudioEncoder`:** 创建一个 `media::AudioOpusEncoder` 实例。
3. **`ProcessEncode`:** 接收到 `AudioData`，检查其采样率和通道数是否与配置匹配。
4. **音频数据转换:** 将 `AudioData` 的 `Float32Array` 数据转换为 `media::AudioBus` 对象，以便底层编码器处理。
5. **底层编码:** 调用 `media::AudioOpusEncoder::Encode()` 方法，将音频数据编码成 Opus 格式的字节流。
6. **`CallOutputCallback`:** `media::AudioOpusEncoder` 完成编码后，将编码后的数据传递给 `CallOutputCallback`。
7. **`EncodedAudioChunk` 创建:**  `CallOutputCallback` 将编码后的字节流封装到 `EncodedAudioChunk` 对象中，并设置时间戳等信息。
8. **输出:** 调用 JavaScript 中注册的 `output` 回调函数，将 `EncodedAudioChunk` 对象传递回去。

**假设输出 (传递给 JavaScript 的 `EncodedAudioChunk`):**

- `type`: "opus"
- `timestamp`: 与输入 `AudioData` 的时间戳对应
- `duration`:  根据编码数据的长度计算出的持续时间
- `data`: 一个 `ArrayBuffer`，包含编码后的 Opus 音频数据。

**用户或编程常见的使用错误：**

1. **配置错误:**
   - **错误示例:** JavaScript 配置了不支持的编解码器，例如 `'unknown-codec'`。
   - **C++ 错误处理:** `ParseConfigStatic` 或 `VerifyCodecSupportStatic` 会检测到不支持的编解码器，并抛出 `DOMException` (NotSupportedError)。
   - **用户表现:** JavaScript 的 `error` 回调函数会被调用，并收到相应的错误信息。

2. **无效的配置参数:**
   - **错误示例:** JavaScript 配置了超出范围的采样率，例如 `samplerate: 999999`。
   - **C++ 错误处理:** `ParseConfigStatic` 中的参数校验逻辑会检测到超出范围的值，并抛出 `DOMException` (TypeError)。
   - **用户表现:** JavaScript 的 `error` 回调函数会被调用，并收到关于无效采样率的错误信息。

3. **编码器初始化失败:**
   - **错误示例:** 某些硬件加速的编码器可能由于资源不足或其他原因初始化失败。
   - **C++ 错误处理:** `CreateMediaAudioEncoder` 创建编码器失败时，会调用 `QueueHandleError` 抛出 `DOMException` (OperationError)。
   - **用户表现:** JavaScript 的 `error` 回调函数会被调用，并收到编码器初始化失败的错误信息。

4. **输入音频数据不匹配:**
   - **错误示例:** JavaScript 传递的 `AudioData` 的采样率或通道数与配置不一致。
   - **C++ 错误处理:** `ProcessEncode` 中会检查输入 `AudioData` 的参数，如果不匹配，会抛出 `DOMException` (EncodingError)。
   - **用户表现:** JavaScript 的 `error` 回调函数会被调用，并收到关于输入音频数据不匹配的错误信息。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户访问包含 WebCodecs 功能的网页:** 用户在浏览器中打开一个使用了 WebCodecs API 进行音频编码的网页。
2. **JavaScript 代码执行:** 网页加载后，JavaScript 代码开始执行。
3. **创建 `AudioEncoder` 实例:** JavaScript 代码创建了一个 `AudioEncoder` 对象。这会触发 C++ 中 `AudioEncoder::Create` 方法的调用。
4. **配置编码器:** JavaScript 代码调用 `encoder.configure(config)`，将配置信息传递给编码器。这会触发 C++ 中 `AudioEncoder::ProcessConfigure` 方法的调用。
5. **获取音频数据:** JavaScript 代码通过某种方式获取原始音频数据，例如从用户的麦克风 (`MediaStreamTrack`) 或者从 `<audio>` 元素中读取。
6. **编码音频数据:** JavaScript 代码调用 `encoder.encode(audioData)`，将 `AudioData` 对象传递给编码器。这会触发 C++ 中 `AudioEncoder::ProcessEncode` 方法的调用.
7. **底层编码器工作:** C++ 代码调用底层的音频编码器（如 Opus 或 AAC 的实现）进行实际的编码工作。
8. **接收编码后的数据:** 底层编码器完成编码后，会调用 C++ 中 `AudioEncoder::CallOutputCallback` 方法。
9. **传递给 JavaScript:** `CallOutputCallback` 将编码后的数据封装成 `EncodedAudioChunk`，并通过 JavaScript 的 `output` 事件回调函数传递回 JavaScript 代码。

**作为调试线索:**

* **断点设置:** 在 `AudioEncoder::ProcessConfigure`, `AudioEncoder::ProcessEncode`, `AudioEncoder::CallOutputCallback` 等关键函数中设置断点，可以跟踪配置信息、输入音频数据以及编码结果的流动。
* **日志输出:** 在 C++ 代码中添加日志输出，可以记录关键变量的值，例如配置参数、音频数据的属性、编码器的状态等。
* **WebCodecs API 的使用情况:** 检查 JavaScript 代码中 `AudioEncoder` 的配置和使用方式，确保参数正确，并且正确处理了 `output` 和 `error` 事件。
* **浏览器内部工具:** 使用 Chrome 浏览器的 `chrome://webrtc-internals` 工具可以查看 WebRTC 相关的统计信息，包括 MediaStreamTrack 的信息，这可能有助于诊断音频源的问题。
* **性能分析工具:** 使用浏览器的性能分析工具可以查看编码过程的性能瓶颈。

希望以上分析能够帮助你理解 `blink/renderer/modules/webcodecs/audio_encoder.cc` 文件的功能和它在 WebCodecs API 中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/audio_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/audio_encoder.h"

#include <cinttypes>
#include <limits>

#include "base/containers/contains.h"
#include "base/metrics/histogram_functions.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "media/audio/audio_opus_encoder.h"
#include "media/base/audio_parameters.h"
#include "media/base/limits.h"
#include "media/base/mime_util.h"
#include "media/base/offloading_audio_encoder.h"
#include "media/mojo/clients/mojo_audio_encoder.h"
#include "media/mojo/mojom/interface_factory.mojom.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_aac_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_encoder_support.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_audio_chunk_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_opus_application.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_opus_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_opus_signal.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_audio_chunk.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

constexpr const char kCategory[] = "media";

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
constexpr uint32_t kDefaultOpusComplexity = 5;
#else
constexpr uint32_t kDefaultOpusComplexity = 9;
#endif

template <typename T>
bool VerifyParameterValues(const T& value,
                           String error_message_base_base,
                           WTF::Vector<T> supported_values,
                           String* js_error_message) {
  if (base::Contains(supported_values, value)) {
    return true;
  }

  WTF::StringBuilder error_builder;
  error_builder.Append(error_message_base_base);
  error_builder.Append(" Supported values: ");
  for (auto i = 0u; i < supported_values.size(); i++) {
    if (i != 0) {
      error_builder.Append(", ");
    }
    error_builder.AppendNumber(supported_values[i]);
  }
  *js_error_message = error_builder.ToString();
  return false;
}

AudioEncoderTraits::ParsedConfig* ParseAacConfigStatic(
    const AacEncoderConfig* aac_config,
    AudioEncoderTraits::ParsedConfig* result,
    ExceptionState& exception_state) {
  result->options.aac = media::AudioEncoder::AacOptions();
  switch (aac_config->format().AsEnum()) {
    case V8AacBitstreamFormat::Enum::kAac:
      result->options.aac->format = media::AudioEncoder::AacOutputFormat::AAC;
      return result;
    case V8AacBitstreamFormat::Enum::kAdts:
      result->options.aac->format = media::AudioEncoder::AacOutputFormat::ADTS;
      return result;
  }
  return result;
}

AudioEncoderTraits::ParsedConfig* ParseOpusConfigStatic(
    const OpusEncoderConfig* opus_config,
    AudioEncoderTraits::ParsedConfig* result,
    ExceptionState& exception_state) {
  constexpr uint32_t kComplexityUpperBound = 10;
  uint32_t complexity = opus_config->getComplexityOr(kDefaultOpusComplexity);
  if (complexity > kComplexityUpperBound) {
    exception_state.ThrowTypeError(
        ExceptionMessages::IndexExceedsMaximumBound<uint32_t>(
            "Opus complexity", complexity, kComplexityUpperBound));
    return nullptr;
  }

  constexpr uint32_t kPacketLossPercUpperBound = 100;
  uint32_t packet_loss_perc = opus_config->packetlossperc();
  if (packet_loss_perc > kPacketLossPercUpperBound) {
    exception_state.ThrowTypeError(
        ExceptionMessages::IndexExceedsMaximumBound<uint32_t>(
            "Opus packetlossperc", packet_loss_perc,
            kPacketLossPercUpperBound));
    return nullptr;
  }

  // `frame_duration` must be a valid frame duration, defined in section 2.1.4.
  // of RFC6716.
  constexpr base::TimeDelta kFrameDurationLowerBound = base::Microseconds(2500);
  constexpr base::TimeDelta kFrameDurationUpperBound = base::Milliseconds(120);
  uint64_t frame_duration = opus_config->frameDuration();
  if (frame_duration < kFrameDurationLowerBound.InMicroseconds() ||
      frame_duration > kFrameDurationUpperBound.InMicroseconds()) {
    exception_state.ThrowTypeError(
        ExceptionMessages::IndexOutsideRange<uint64_t>(
            "Opus frameDuration", frame_duration,
            kFrameDurationLowerBound.InMicroseconds(),
            ExceptionMessages::BoundType::kInclusiveBound,
            kFrameDurationUpperBound.InMicroseconds(),
            ExceptionMessages::BoundType::kInclusiveBound));
    return nullptr;
  }

  // Any multiple of a frame duration is allowed by RFC6716. Concretely, this
  // means any multiple of 2500 microseconds.
  if (frame_duration % kFrameDurationLowerBound.InMicroseconds() != 0) {
    exception_state.ThrowTypeError(String::Format(
        "Invalid Opus frameDuration; expected a multiple of %" PRIu64
        ", received %" PRIu64 ".",
        kFrameDurationLowerBound.InMicroseconds(), frame_duration));
    return nullptr;
  }

  if (opus_config->format().AsEnum() == V8OpusBitstreamFormat::Enum::kOgg) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Opus Ogg format is unsupported");
    return nullptr;
  }

  media::AudioEncoder::OpusSignal opus_signal;
  switch (opus_config->signal().AsEnum()) {
    case blink::V8OpusSignal::Enum::kAuto:
      opus_signal = media::AudioEncoder::OpusSignal::kAuto;
      break;
    case blink::V8OpusSignal::Enum::kMusic:
      opus_signal = media::AudioEncoder::OpusSignal::kMusic;
      break;
    case blink::V8OpusSignal::Enum::kVoice:
      opus_signal = media::AudioEncoder::OpusSignal::kVoice;
      break;
  }

  media::AudioEncoder::OpusApplication opus_application;
  switch (opus_config->application().AsEnum()) {
    case blink::V8OpusApplication::Enum::kVoip:
      opus_application = media::AudioEncoder::OpusApplication::kVoip;
      break;
    case blink::V8OpusApplication::Enum::kAudio:
      opus_application = media::AudioEncoder::OpusApplication::kAudio;
      break;
    case blink::V8OpusApplication::Enum::kLowdelay:
      opus_application = media::AudioEncoder::OpusApplication::kLowDelay;
      break;
  }

  result->options.opus = {
      .frame_duration = base::Microseconds(frame_duration),
      .signal = opus_signal,
      .application = opus_application,
      .complexity = complexity,
      .packet_loss_perc = packet_loss_perc,
      .use_in_band_fec = opus_config->useinbandfec(),
      .use_dtx = opus_config->usedtx(),
  };

  return result;
}

AudioEncoderTraits::ParsedConfig* ParseConfigStatic(
    const AudioEncoderConfig* config,
    ExceptionState& exception_state) {
  if (!config) {
    exception_state.ThrowTypeError("No config provided");
    return nullptr;
  }

  if (config->codec().LengthWithStrippedWhiteSpace() == 0) {
    exception_state.ThrowTypeError("Invalid codec; codec is required.");
    return nullptr;
  }

  auto* result = MakeGarbageCollected<AudioEncoderTraits::ParsedConfig>();

  result->options.codec = media::AudioCodec::kUnknown;
  bool is_codec_ambiguous = true;
  bool parse_succeeded = ParseAudioCodecString(
      "", config->codec().Utf8(), &is_codec_ambiguous, &result->options.codec);

  if (!parse_succeeded || is_codec_ambiguous) {
    result->options.codec = media::AudioCodec::kUnknown;
    return result;
  }

  result->options.channels = config->numberOfChannels();
  if (result->options.channels == 0) {
    exception_state.ThrowTypeError(String::Format(
        "Invalid channel count; channel count must be non-zero, received %d.",
        result->options.channels));
    return nullptr;
  }

  result->options.sample_rate = config->sampleRate();
  if (result->options.sample_rate == 0) {
    exception_state.ThrowTypeError(String::Format(
        "Invalid sample rate; sample rate must be non-zero, received %d.",
        result->options.sample_rate));
    return nullptr;
  }

  result->codec_string = config->codec();
  if (config->hasBitrate()) {
    if (config->bitrate() > std::numeric_limits<int>::max()) {
      exception_state.ThrowTypeError(String::Format(
          "Bitrate is too large; expected at most %d, received %" PRIu64,
          std::numeric_limits<int>::max(), config->bitrate()));
      return nullptr;
    }
    result->options.bitrate = static_cast<int>(config->bitrate());
  }

  if (config->hasBitrateMode()) {
    result->options.bitrate_mode =
        config->bitrateMode().AsEnum() == V8BitrateMode::Enum::kConstant
            ? media::AudioEncoder::BitrateMode::kConstant
            : media::AudioEncoder::BitrateMode::kVariable;
  }

  switch (result->options.codec) {
    case media::AudioCodec::kOpus:
      return ParseOpusConfigStatic(
          config->hasOpus() ? config->opus() : OpusEncoderConfig::Create(),
          result, exception_state);
    case media::AudioCodec::kAAC: {
      auto* aac_config =
          config->hasAac() ? config->aac() : AacEncoderConfig::Create();
      return ParseAacConfigStatic(aac_config, result, exception_state);
    }
    default:
      return result;
  }
}

bool VerifyCodecSupportStatic(AudioEncoderTraits::ParsedConfig* config,
                              String* js_error_message) {
  if (config->options.channels < 1 ||
      config->options.channels > media::limits::kMaxChannels) {
    *js_error_message = String::Format(
        "Unsupported channel count; expected range from %d to "
        "%d, received %d.",
        1, media::limits::kMaxChannels, config->options.channels);
    return false;
  }

  if (config->options.sample_rate < media::limits::kMinSampleRate ||
      config->options.sample_rate > media::limits::kMaxSampleRate) {
    *js_error_message = String::Format(
        "Unsupported sample rate; expected range from %d to %d, "
        "received %d.",
        media::limits::kMinSampleRate, media::limits::kMaxSampleRate,
        config->options.sample_rate);
    return false;
  }

  switch (config->options.codec) {
    case media::AudioCodec::kOpus: {
      // TODO(crbug.com/1378399): Support all multiples of basic frame
      // durations.
      if (!VerifyParameterValues(
              config->options.opus->frame_duration.InMicroseconds(),
              "Unsupported Opus frameDuration.",
              {2500, 5000, 10000, 20000, 40000, 60000}, js_error_message)) {
        return false;
      }
      if (config->options.channels > 2) {
        // Our Opus implementation only supports up to 2 channels
        *js_error_message = String::Format(
            "Too many channels for Opus encoder; "
            "expected at most 2, received %d.",
            config->options.channels);
        return false;
      }
      if (config->options.bitrate.has_value() &&
          config->options.bitrate.value() <
              media::AudioOpusEncoder::kMinBitrate) {
        *js_error_message = String::Format(
            "Opus bitrate is too low; expected at least %d, received %d.",
            media::AudioOpusEncoder::kMinBitrate,
            config->options.bitrate.value());
        return false;
      }
      return true;
    }
    case media::AudioCodec::kAAC: {
      if (media::MojoAudioEncoder::IsSupported(media::AudioCodec::kAAC)) {
        if (!VerifyParameterValues(config->options.channels,
                                   "Unsupported number of channels.", {1, 2, 6},
                                   js_error_message)) {
          return false;
        }
        if (config->options.bitrate.has_value()) {
          if (!VerifyParameterValues(
                  config->options.bitrate.value(), "Unsupported bitrate.",
                  {96000, 128000, 160000, 192000}, js_error_message)) {
            return false;
          }
        }
        if (!VerifyParameterValues(config->options.sample_rate,
                                   "Unsupported sample rate.", {44100, 48000},
                                   js_error_message)) {
          return false;
        }
        return true;
      }
      [[fallthrough]];
    }
    default:
      *js_error_message = "Unsupported codec type.";
      return false;
  }
}

AacEncoderConfig* CopyAacConfig(const AacEncoderConfig& config) {
  auto* result = AacEncoderConfig::Create();
  result->setFormat(config.format());
  return result;
}

OpusEncoderConfig* CopyOpusConfig(const OpusEncoderConfig& config) {
  auto* opus_result = OpusEncoderConfig::Create();
  opus_result->setFormat(config.format());
  opus_result->setSignal(config.signal());
  opus_result->setApplication(config.application());
  opus_result->setFrameDuration(config.frameDuration());
  opus_result->setComplexity(config.getComplexityOr(kDefaultOpusComplexity));
  opus_result->setPacketlossperc(config.packetlossperc());
  opus_result->setUseinbandfec(config.useinbandfec());
  opus_result->setUsedtx(config.usedtx());
  return opus_result;
}

AudioEncoderConfig* CopyConfig(const AudioEncoderConfig& config) {
  auto* result = AudioEncoderConfig::Create();
  result->setCodec(config.codec());
  result->setSampleRate(config.sampleRate());
  result->setNumberOfChannels(config.numberOfChannels());
  if (config.hasBitrate())
    result->setBitrate(config.bitrate());

  if (config.hasBitrateMode()) {
    result->setBitrateMode(config.bitrateMode());
  }

  if (config.hasOpus()) {
    result->setOpus(CopyOpusConfig(*config.opus()));
  }
  if (config.hasAac()) {
    result->setAac(CopyAacConfig(*config.aac()));
  }

  return result;
}

std::unique_ptr<media::AudioEncoder> CreateSoftwareAudioEncoder(
    media::AudioCodec codec) {
  if (codec != media::AudioCodec::kOpus)
    return nullptr;
  auto software_encoder = std::make_unique<media::AudioOpusEncoder>();
  return std::make_unique<media::OffloadingAudioEncoder>(
      std::move(software_encoder));
}

std::unique_ptr<media::AudioEncoder> CreatePlatformAudioEncoder(
    media::AudioCodec codec) {
  if (codec != media::AudioCodec::kAAC)
    return nullptr;

  mojo::PendingRemote<media::mojom::InterfaceFactory> pending_interface_factory;
  mojo::Remote<media::mojom::InterfaceFactory> interface_factory;
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      pending_interface_factory.InitWithNewPipeAndPassReceiver());
  interface_factory.Bind(std::move(pending_interface_factory));

  mojo::PendingRemote<media::mojom::AudioEncoder> encoder_remote;
  interface_factory->CreateAudioEncoder(
      encoder_remote.InitWithNewPipeAndPassReceiver());
  return std::make_unique<media::MojoAudioEncoder>(std::move(encoder_remote));
}

}  // namespace

// static
const char* AudioEncoderTraits::GetName() {
  return "AudioEncoder";
}

AudioEncoder* AudioEncoder::Create(ScriptState* script_state,
                                   const AudioEncoderInit* init,
                                   ExceptionState& exception_state) {
  auto* result =
      MakeGarbageCollected<AudioEncoder>(script_state, init, exception_state);
  return exception_state.HadException() ? nullptr : result;
}

AudioEncoder::AudioEncoder(ScriptState* script_state,
                           const AudioEncoderInit* init,
                           ExceptionState& exception_state)
    : Base(script_state, init, exception_state) {
  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kWebCodecs);
}

AudioEncoder::~AudioEncoder() = default;

std::unique_ptr<media::AudioEncoder> AudioEncoder::CreateMediaAudioEncoder(
    const ParsedConfig& config) {
  if (auto result = CreatePlatformAudioEncoder(config.options.codec)) {
    is_platform_encoder_ = true;
    return result;
  }
  is_platform_encoder_ = false;
  return CreateSoftwareAudioEncoder(config.options.codec);
}

void AudioEncoder::ProcessConfigure(Request* request) {
  DCHECK_NE(state_.AsEnum(), V8CodecState::Enum::kClosed);
  DCHECK_EQ(request->type, Request::Type::kConfigure);
  DCHECK(request->config);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  request->StartTracing();

  active_config_ = request->config;
  String js_error_message;
  if (!VerifyCodecSupport(active_config_, &js_error_message)) {
    blocking_request_in_progress_ = request;
    QueueHandleError(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError, js_error_message));
    request->EndTracing();
    return;
  }

  media_encoder_ = CreateMediaAudioEncoder(*active_config_);
  if (!media_encoder_) {
    blocking_request_in_progress_ = request;
    QueueHandleError(MakeOperationError(
        "Encoder creation error.",
        media::EncoderStatus(
            media::EncoderStatus::Codes::kEncoderInitializationError,
            "Unable to create encoder (most likely unsupported "
            "codec/acceleration requirement combination)")));
    request->EndTracing();
    return;
  }

  auto output_cb = ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
      &AudioEncoder::CallOutputCallback,
      MakeUnwrappingCrossThreadWeakHandle(this),
      // We can't use |active_config_| from |this| because it can change by
      // the time the callback is executed.
      MakeUnwrappingCrossThreadHandle(active_config_.Get()), reset_count_));

  auto done_callback = [](AudioEncoder* self, media::AudioCodec codec,
                          Request* req, media::EncoderStatus status) {
    if (!self || self->reset_count_ != req->reset_count) {
      req->EndTracing(/*aborted=*/true);
      return;
    }
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    if (!status.is_ok()) {
      self->HandleError(
          self->MakeOperationError("Encoding error.", std::move(status)));
    } else {
      base::UmaHistogramEnumeration("Blink.WebCodecs.AudioEncoder.Codec",
                                    codec);
    }

    req->EndTracing();
    self->blocking_request_in_progress_ = nullptr;
    self->ProcessRequests();
  };

  blocking_request_in_progress_ = request;
  first_output_after_configure_ = true;
  media_encoder_->Initialize(
      active_config_->options, std::move(output_cb),
      ConvertToBaseOnceCallback(CrossThreadBindOnce(
          done_callback, MakeUnwrappingCrossThreadWeakHandle(this),
          active_config_->options.codec,
          MakeUnwrappingCrossThreadHandle(request))));
}

void AudioEncoder::ProcessEncode(Request* request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(state_, V8CodecState::Enum::kConfigured);
  DCHECK(media_encoder_);
  DCHECK_EQ(request->type, Request::Type::kEncode);
  DCHECK_GT(requested_encodes_, 0u);

  request->StartTracing();

  auto* audio_data = request->input.Release();

  auto data = audio_data->data();

  // The data shouldn't be closed at this point.
  DCHECK(data);

  auto done_callback = [](AudioEncoder* self, Request* req,
                          media::EncoderStatus status) {
    if (!self || self->reset_count_ != req->reset_count) {
      req->EndTracing(/*aborted=*/true);
      return;
    }
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    if (!status.is_ok()) {
      self->HandleError(
          self->MakeEncodingError("Encoding error.", std::move(status)));
    }

    req->EndTracing();
    self->ProcessRequests();
  };

  if (data->channel_count() != active_config_->options.channels ||
      data->sample_rate() != active_config_->options.sample_rate) {
    // Per spec we must queue a task for error handling.
    QueueHandleError(MakeEncodingError(
        "Input audio buffer is incompatible with codec parameters",
        media::EncoderStatus(media::EncoderStatus::Codes::kEncoderFailedEncode)
            .WithData("channels", data->channel_count())
            .WithData("sampleRate", data->sample_rate())));

    request->EndTracing();

    audio_data->close();
    return;
  }

  // If |data|'s memory layout allows it, |audio_bus| will be a simple wrapper
  // around it. Otherwise, |audio_bus| will contain a converted copy of |data|.
  auto audio_bus = media::AudioBuffer::WrapOrCopyToAudioBus(data);

  base::TimeTicks timestamp = base::TimeTicks() + data->timestamp();

  --requested_encodes_;
  ScheduleDequeueEvent();
  media_encoder_->Encode(
      std::move(audio_bus), timestamp,
      ConvertToBaseOnceCallback(CrossThreadBindOnce(
          done_callback, MakeUnwrappingCrossThreadWeakHandle(this),
          MakeUnwrappingCrossThreadHandle(request))));

  audio_data->close();
}

void AudioEncoder::ProcessReconfigure(Request* request) {
  // Audio decoders don't currently support any meaningful reconfiguring
}

AudioEncoder::ParsedConfig* AudioEncoder::ParseConfig(
    const AudioEncoderConfig* opts,
    ExceptionState& exception_state) {
  return ParseConfigStatic(opts, exception_state);
}

bool AudioEncoder::CanReconfigure(ParsedConfig& original_config,
                                  ParsedConfig& new_config) {
  return original_config.options.codec == new_config.options.codec &&
         original_config.options.channels == new_config.options.channels &&
         original_config.options.bitrate == new_config.options.bitrate &&
         original_config.options.sample_rate == new_config.options.sample_rate;
}

bool AudioEncoder::VerifyCodecSupport(ParsedConfig* config,
                                      String* js_error_message) {
  return VerifyCodecSupportStatic(config, js_error_message);
}

void AudioEncoder::CallOutputCallback(
    ParsedConfig* active_config,
    uint32_t reset_count,
    media::EncodedAudioBuffer encoded_buffer,
    std::optional<media::AudioEncoder::CodecDescription> codec_desc) {
  DCHECK(active_config);
  if (!script_state_->ContextIsValid() || !output_callback_ ||
      state_.AsEnum() != V8CodecState::Enum::kConfigured ||
      reset_count != reset_count_) {
    return;
  }

  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  MarkCodecActive();

  auto buffer =
      media::DecoderBuffer::FromArray(std::move(encoded_buffer.encoded_data));
  buffer->set_timestamp(encoded_buffer.timestamp - base::TimeTicks());
  buffer->set_is_key_frame(true);
  buffer->set_duration(encoded_buffer.duration);
  auto* chunk = MakeGarbageCollected<EncodedAudioChunk>(std::move(buffer));

  auto* metadata = MakeGarbageCollected<EncodedAudioChunkMetadata>();
  if (first_output_after_configure_ || codec_desc.has_value()) {
    first_output_after_configure_ = false;
    auto* decoder_config = MakeGarbageCollected<AudioDecoderConfig>();
    decoder_config->setCodec(active_config->codec_string);
    decoder_config->setSampleRate(encoded_buffer.params.sample_rate());
    decoder_config->setNumberOfChannels(active_config->options.channels);
    if (codec_desc.has_value()) {
      auto* desc_array_buf = DOMArrayBuffer::Create(codec_desc.value());
      decoder_config->setDescription(
          MakeGarbageCollected<AllowSharedBufferSource>(desc_array_buf));
    }
    metadata->setDecoderConfig(decoder_config);
  }

  TRACE_EVENT_BEGIN1(kCategory, GetTraceNames()->output.c_str(), "timestamp",
                     chunk->timestamp());

  ScriptState::Scope scope(script_state_);
  output_callback_->InvokeAndReportException(nullptr, chunk, metadata);

  TRACE_EVENT_END0(kCategory, GetTraceNames()->output.c_str());
}

// static
ScriptPromise<AudioEncoderSupport> AudioEncoder::isConfigSupported(
    ScriptState* script_state,
    const AudioEncoderConfig* config,
    ExceptionState& exception_state) {
  auto* parsed_config = ParseConfigStatic(config, exception_state);
  if (!parsed_config) {
    DCHECK(exception_state.HadException());
    return EmptyPromise();
  }

  String unused_js_error_message;
  auto* support = AudioEncoderSupport::Create();
  support->setSupported(
      VerifyCodecSupportStatic(parsed_config, &unused_js_error_message));
  support->setConfig(CopyConfig(*config));
  return ToResolvedPromise<AudioEncoderSupport>(script_state, support);
}

const AtomicString& AudioEncoder::InterfaceName() const {
  return event_target_names::kAudioEncoder;
}

DOMException* AudioEncoder::MakeOperationError(std::string error_msg,
                                               media::EncoderStatus status) {
  if (is_platform_encoder_) {
    return logger_->MakeOperationError(std::move(error_msg), std::move(status));
  }
  return logger_->MakeSoftwareCodecOperationError(std::move(error_msg),
                                                  std::move(status));
}

DOMException* AudioEncoder::MakeEncodingError(std::string error_msg,
                                              media::EncoderStatus status) {
  if (is_platform_encoder_) {
    return logger_->MakeEncodingError(std::move(error_msg), std::move(status));
  }
  return logger_->MakeSoftwareCodecEncodingError(std::move(error_msg),
                                                 std::move(status));
}

}  // namespace blink

"""

```