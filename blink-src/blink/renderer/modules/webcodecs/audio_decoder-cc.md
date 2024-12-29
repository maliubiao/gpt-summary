Response:
Let's break down the thought process for analyzing the `audio_decoder.cc` file.

**1. Initial Understanding - Context and Purpose:**

* **Filename and Directory:** `blink/renderer/modules/webcodecs/audio_decoder.cc` immediately tells us this is part of the Blink rendering engine (Chrome's rendering engine), specifically within the WebCodecs API. The `audio_decoder` part clearly indicates its core function.
* **Copyright and License:**  The header confirms it's a Chromium file under a BSD license. This is standard boilerplate.
* **Includes:** The included headers provide valuable clues about the file's dependencies and functionalities. We see:
    * `base/metrics/histogram_functions.h`: Likely used for performance tracking.
    * `media/base/...`:  Strong indication of interaction with Chromium's media framework (audio decoding, codecs, etc.).
    * `third_party/blink/public/mojom/...`: Interaction with the Mojo IPC system, specifically for feature usage counting.
    * `third_party/blink/renderer/bindings/...`:  Code related to binding C++ to JavaScript (V8). This is a crucial clue about its Web API interface.
    * `third_party/blink/renderer/modules/webaudio/...`: Hints at potential integration with the Web Audio API.
    * `third_party/blink/renderer/modules/webcodecs/...`:  Other WebCodecs components this file interacts with.
    * Standard C++ headers like `<memory>` and `<vector>`.

**2. Core Functionality Identification - Deciphering the Code:**

* **Class Definition:** The primary class is `AudioDecoder`. This is the central point of the file.
* **`Create()` (static):** A factory method for creating `AudioDecoder` instances. This is common practice for managing object creation.
* **`isConfigSupported()` (static):** This function clearly checks if a given `AudioDecoderConfig` is supported by the browser. This is a key feature for the WebCodecs API, allowing developers to query capabilities.
* **`IsValidAudioDecoderConfig()` (static):**  A validation function for the `AudioDecoderConfig`. It checks various parameters like codec, sample rate, channel count, and description.
* **`MakeMediaAudioDecoderConfig()` (static):** This converts the WebCodecs `AudioDecoderConfig` into Chromium's internal `media::AudioDecoderConfig`. This is the bridge between the Web API and the underlying media framework.
* **Decoder Traits (`AudioDecoderTraits`):**  This pattern is common in Chromium's media framework. It likely defines an interface or set of operations for different decoder implementations. The `CreateDecoder` function points to the actual decoder implementation (`AudioDecoderBroker`).
* **`Decode()` (Implicit):**  While not explicitly a method in `AudioDecoder`, the presence of `MakeInput()` and `MakeOutput()` methods within the `DecoderTemplate` suggests the class inherits decoding functionality. It takes `EncodedAudioChunk` as input and produces `AudioData` as output.
* **Configuration Handling:** The code extensively deals with `AudioDecoderConfig` and its validation, indicating a focus on proper setup before decoding.
* **Error Handling:** The use of `ExceptionState` and returning `std::optional` with error messages suggests robust error reporting to JavaScript.
* **Metrics:** The use of `UseCounter` and histograms indicates tracking of feature usage and performance.

**3. Relating to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript API:** The presence of V8 binding headers (`v8_audio_decoder_config.h`, `v8_audio_decoder_init.h`, etc.) makes it clear that `AudioDecoder` is exposed as a JavaScript API. The `isConfigSupported` function directly maps to a JavaScript method.
* **HTML Integration (Indirect):** While not directly manipulating HTML, the `AudioDecoder` is used to process audio data, which is often sourced from `<audio>` or `<video>` elements or fetched via JavaScript.
* **CSS (No Direct Relation):**  Audio decoding has no direct relationship with CSS styling.

**4. Logic and Reasoning (Hypothetical Inputs and Outputs):**

* **`isConfigSupported()` Example:**
    * **Input:** A JavaScript object like `{ codec: 'opus', sampleRate: 48000, numberOfChannels: 2 }`.
    * **Output:** A JavaScript Promise that resolves with an `AudioDecoderSupport` object, likely `{ supported: true, config: { codec: 'opus', sampleRate: 48000, numberOfChannels: 2 } }`.
* **`decode()` Example:**
    * **Input:** An `EncodedAudioChunk` object in JavaScript containing compressed audio data.
    * **Output:**  An event fired by the `AudioDecoder` (likely the `dequeue` event) containing an `AudioData` object representing the decoded audio frames.

**5. Common User/Programming Errors:**

* **Invalid Codec:** Specifying an unsupported or misspelled codec string (e.g., `'mp3'` instead of `'mpeg-4 aac'`).
* **Missing Description (for certain codecs):**  For codecs like FLAC or multi-channel Opus, forgetting to provide the description data.
* **Incorrect Sample Rate or Channel Count:** Providing values that are not supported by the decoder or the codec.
* **Detached Description Buffer:**  Accidentally detaching the `ArrayBuffer` containing the codec description before passing it to the `AudioDecoder`.
* **Using an unsupported encryption scheme.**

**6. Debugging Clues - User Operations to Reach the Code:**

* **Playing Media:** The most common path is a user playing audio content on a webpage. This involves:
    1. **Loading the Page:** The browser fetches and parses the HTML.
    2. **Encountering `<audio>` or `<video>`:**  The browser starts fetching the media resource.
    3. **Using WebCodecs API:**  JavaScript code on the page might explicitly create an `AudioDecoder` instance to decode audio streams. This is becoming increasingly common for advanced media processing.
    4. **Starting Playback:** The media element or the JavaScript code initiates playback.
    5. **Decoding:** The browser uses the `AudioDecoder` to process the audio data for playback.
* **Explicit WebCodecs Usage:** A developer might be directly using the `AudioDecoder` API for tasks like:
    1. **Creating an `AudioDecoder` instance:**  Using the JavaScript constructor.
    2. **Configuring the decoder:** Passing an `AudioDecoderConfig` object.
    3. **Queueing `EncodedAudioChunk` objects:** Providing the compressed audio data.
    4. **Handling the decoded `AudioData`:** Processing the output.

**Self-Correction/Refinement during Analysis:**

* **Initial thought:**  Maybe this file directly implements the decoding logic.
* **Correction:** The inclusion of `AudioDecoderBroker` and the `AudioDecoderTraits` pattern suggests this file is more of a facade or interface, delegating the actual decoding to other components.
* **Initial thought:** The file might be heavily involved in UI rendering.
* **Correction:**  Given its location in `blink/renderer/modules/webcodecs` and its focus on audio processing, its primary concern is the media pipeline, not direct UI rendering (though the decoded audio eventually contributes to the user experience).

By following this structured approach, combining code analysis with an understanding of Web technologies and the underlying architecture, we can effectively understand the purpose and functionality of the `audio_decoder.cc` file.
这个文件 `blink/renderer/modules/webcodecs/audio_decoder.cc` 是 Chromium Blink 引擎中负责 **WebCodecs API 中音频解码器 (AudioDecoder)** 功能的核心实现。它将 JavaScript 中对音频解码器的操作转化为底层的媒体处理流程。

以下是它的功能列表：

**核心功能：**

1. **提供 JavaScript 接口 `AudioDecoder`:**  该文件实现了 `AudioDecoder` 类，这个类直接对应了 WebCodecs API 中暴露给 JavaScript 的 `AudioDecoder` 接口。
2. **配置音频解码器:**  接收并验证 JavaScript 传递的 `AudioDecoderConfig` 对象，该对象包含了音频的编解码器类型、采样率、声道数等信息。
3. **创建底层媒体解码器:**  根据配置信息，利用 Chromium 的媒体框架（`media::AudioDecoder`）创建实际的音频解码器实例。
4. **解码音频数据:**  接收 JavaScript 传递的 `EncodedAudioChunk` 对象，其中包含待解码的音频数据，并将其传递给底层的媒体解码器进行解码。
5. **输出解码后的音频数据:**  将底层媒体解码器解码后的音频数据封装成 `AudioData` 对象，并通过事件或其他机制返回给 JavaScript。
6. **支持查询配置支持性:**  实现 `isConfigSupported` 静态方法，允许 JavaScript 查询给定的 `AudioDecoderConfig` 是否被当前浏览器支持。
7. **处理错误:**  在配置验证、解码过程中发生错误时，生成相应的 JavaScript 错误信息并抛出异常。
8. **使用性能指标:**  通过 `base::metrics::histogram_functions` 记录音频解码器的使用情况和性能指标。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `audio_decoder.cc` 实现了 WebCodecs API 的 JavaScript 接口 `AudioDecoder`。JavaScript 代码可以通过创建 `AudioDecoder` 实例，配置解码器，并调用 `decode()` 方法来解码音频数据。
    * **示例:**  JavaScript 代码可以这样使用 `AudioDecoder`:
      ```javascript
      const decoder = new AudioDecoder({
        output: (audioData) => {
          // 处理解码后的音频数据
          console.log('Decoded audio data:', audioData);
        },
        error: (e) => {
          console.error('解码错误:', e);
        }
      });

      const config = {
        codec: 'opus',
        sampleRate: 48000,
        numberOfChannels: 2
      };

      AudioDecoder.isConfigSupported(config).then((support) => {
        if (support.supported) {
          decoder.configure(config);
          // 获取 encodedAudioChunk 并解码
          fetch('audio.opus')
            .then(response => response.arrayBuffer())
            .then(buffer => {
              const chunk = new EncodedAudioChunk({
                type: 'key',
                timestamp: 0,
                duration: 100000,
                data: buffer
              });
              decoder.decode(chunk);
            });
        } else {
          console.error('当前配置不支持');
        }
      });
      ```
* **HTML:**  `AudioDecoder` 通常用于处理 `<audio>` 或 `<video>` 元素或其他来源的音频数据。例如，可以从 `<audio>` 元素中提取音频流，然后使用 `AudioDecoder` 进行解码。
    * **示例:**  虽然 `audio_decoder.cc` 本身不直接操作 HTML，但其解码的音频数据可以用于播放到 HTML 的 `<audio>` 元素或通过 Web Audio API 进行进一步处理和渲染。
* **CSS:**  `audio_decoder.cc` 与 CSS 没有直接关系。CSS 负责页面的样式和布局，而音频解码器专注于音频数据的处理。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码创建了一个 `AudioDecoder` 实例，并使用以下配置进行配置：

**假设输入：**

* **配置 (`AudioDecoderConfig`)：**
  ```javascript
  {
    codec: 'opus',
    sampleRate: 48000,
    numberOfChannels: 2
  }
  ```
* **待解码数据 (`EncodedAudioChunk`)：**  一个包含 Opus 编码音频数据的 `EncodedAudioChunk` 对象，假设其 `data` 属性是一个包含有效 Opus 数据的 `ArrayBuffer`。

**逻辑推理过程：**

1. `AudioDecoder.isConfigSupported()` 会被调用，`IsValidAudioDecoderConfig` 函数会检查 `codec`、`sampleRate` 和 `numberOfChannels` 是否有效，并尝试解析编解码器字符串。
2. 如果配置有效，`AudioDecoder` 实例会调用 `configure()` 方法，该方法会将配置信息传递给底层的媒体解码器。
3. 当调用 `decode()` 方法并传入 `EncodedAudioChunk` 时，`MakeInput` 方法会将 `EncodedAudioChunk` 转换为底层的 `media::DecoderBuffer`。
4. 底层的媒体解码器会解码 `media::DecoderBuffer` 中的数据。
5. 解码成功后，`MakeOutput` 方法会将解码后的 `media::AudioBuffer` 转换为 `AudioData` 对象。
6. `output` 回调函数会被调用，并传入 `AudioData` 对象。

**假设输出：**

* **成功解码：** `output` 回调函数会被调用，并接收到一个 `AudioData` 对象。该对象包含了解码后的音频帧数据，例如：
  ```javascript
  {
    format: 'f32-planar', // 或其他格式
    numberOfChannels: 2,
    sampleRate: 48000,
    numberOfFrames: /* 解码后的帧数 */,
    data: [/* Float32Array 数组，包含左右声道的音频数据 */]
  }
  ```
* **解码失败：** `error` 回调函数会被调用，并接收到一个描述错误的 `DOMException` 对象。

**用户或编程常见的使用错误：**

1. **不支持的编解码器:**  配置了浏览器不支持的 `codec` 值，例如拼写错误的编解码器名称或实验性的编解码器。
   * **示例:**  `{ codec: 'mp3', sampleRate: 44100, numberOfChannels: 2 }` (尽管 `mp3` 很常见，但 WebCodecs 更倾向于使用更现代的编解码器)。
2. **缺少必要的配置信息:**  对于某些编解码器，可能需要提供额外的 `description` 数据。
   * **示例:**  对于 FLAC 或 Vorbis，如果没有提供 `description`，解码器可能无法初始化。
3. **无效的采样率或声道数:**  提供了超出合理范围或编解码器不支持的 `sampleRate` 或 `numberOfChannels` 值。
   * **示例:**  `{ codec: 'opus', sampleRate: 0, numberOfChannels: 2 }` (采样率不能为 0)。
4. **解码数据格式错误:**  传递给 `decode()` 方法的 `EncodedAudioChunk` 中的 `data` 不是预期的编码格式或已损坏。
5. **在配置之前尝试解码:**  在调用 `configure()` 方法之前就调用 `decode()` 方法。
6. **忘记处理 `error` 回调:**  没有正确处理 `error` 回调，导致解码失败时无法得知原因。
7. **在不支持的浏览器中使用 WebCodecs API:**  WebCodecs API 并非所有浏览器都支持。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户正在观看一个网页上的视频，该视频使用了 WebCodecs API 来解码音频流：

1. **用户打开网页:**  浏览器加载 HTML、CSS 和 JavaScript 代码。
2. **JavaScript 代码创建 `AudioDecoder` 实例:**  网页的 JavaScript 代码使用 `new AudioDecoder(...)` 创建了一个音频解码器实例，并设置了 `output` 和 `error` 回调函数。
3. **JavaScript 代码获取音频流数据:**  可能通过 `<video>` 元素、`fetch API` 或其他方式获取了编码后的音频数据。
4. **JavaScript 代码配置 `AudioDecoder`:**  调用 `decoder.configure(config)` 方法，传入包含视频音频轨道的编解码器、采样率等信息的配置对象。
5. **JavaScript 代码创建 `EncodedAudioChunk` 对象:**  将获取到的音频流数据封装成 `EncodedAudioChunk` 对象，包含 `type` (例如 'key' 或 'delta')、`timestamp`、`duration` 和 `data` (包含编码后的音频数据)。
6. **JavaScript 代码调用 `decoder.decode(chunk)`:**  将 `EncodedAudioChunk` 对象传递给解码器进行解码。
7. **Blink 引擎处理 `decode` 调用:**  在 `audio_decoder.cc` 中，`AudioDecoder::Decode()` 方法会被调用（虽然代码中没有显式展示 `Decode` 方法，但它是 `DecoderTemplate` 的一部分）。
8. **数据传递到底层解码器:**  `MakeInput()` 方法将 `EncodedAudioChunk` 转换为底层解码器需要的格式，并传递给实际的媒体解码器进行解码。
9. **解码结果处理:**
   * **解码成功:** 底层解码器解码成功后，`MakeOutput()` 方法将解码后的音频数据转换为 `AudioData` 对象，并通过 `output` 回调函数返回给 JavaScript 代码。
   * **解码失败:** 底层解码器解码失败，会触发 `error` 回调函数，并将错误信息传递给 JavaScript 代码。

**调试线索:**

* 如果用户报告音频播放问题，可以检查浏览器的开发者工具中的 Console 面板，查看是否有与 `AudioDecoder` 相关的错误信息。
* 可以通过在 `audio_decoder.cc` 中添加日志输出来跟踪配置信息、解码过程和错误情况。
* 使用 Chromium 的 `chrome://media-internals` 工具可以查看更详细的媒体 pipeline 信息，包括音频解码器的状态和事件。
* 检查 JavaScript 代码中传递给 `AudioDecoder` 的配置和 `EncodedAudioChunk` 数据是否正确。
* 确保用户的浏览器支持所使用的音频编解码器。

总而言之，`blink/renderer/modules/webcodecs/audio_decoder.cc` 是 WebCodecs API 中音频解码器的桥梁，它连接了 JavaScript API 和底层的媒体处理框架，负责配置、解码和输出音频数据，并在发生错误时提供反馈。 理解这个文件的功能对于调试 WebCodecs 相关的音频问题至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/audio_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webcodecs/audio_decoder.h"

#include "base/metrics/histogram_functions.h"
#include "media/base/audio_codecs.h"
#include "media/base/audio_decoder.h"
#include "media/base/audio_decoder_config.h"
#include "media/base/channel_layout.h"
#include "media/base/encryption_scheme.h"
#include "media/base/media_util.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/waiting.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_support.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_audio_chunk.h"
#include "third_party/blink/renderer/modules/webaudio/base_audio_context.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_decoder_broker.h"
#include "third_party/blink/renderer/modules/webcodecs/decrypt_config_util.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_audio_chunk.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

#include <memory>
#include <vector>

namespace blink {

bool VerifyDescription(const AudioDecoderConfig& config,
                       String* js_error_message) {
  // https://www.w3.org/TR/webcodecs-flac-codec-registration
  // https://www.w3.org/TR/webcodecs-vorbis-codec-registration
  bool description_required = false;
  if (config.codec() == "flac" || config.codec() == "vorbis") {
    description_required = true;
  }

  if (description_required && !config.hasDescription()) {
    *js_error_message = "Invalid config; description is required.";
    return false;
  }

  // For Opus with more than 2 channels, we need a description. While we can
  // guess a channel mapping for up to 8 channels, we don't know whether the
  // encoded Opus streams will be mono or stereo streams.
  if (config.codec() == "opus" && config.numberOfChannels() > 2 &&
      !config.hasDescription()) {
    *js_error_message =
        "Invalid config; description is required for multi-channel Opus.";
    return false;
  }

  if (config.hasDescription()) {
    auto desc_wrapper = AsSpan<const uint8_t>(config.description());

    if (!desc_wrapper.data()) {
      *js_error_message = "Invalid config; description is detached.";
      return false;
    }
  }

  return true;
}

AudioDecoderConfig* CopyConfig(const AudioDecoderConfig& config) {
  AudioDecoderConfig* copy = AudioDecoderConfig::Create();
  copy->setCodec(config.codec());
  copy->setSampleRate(config.sampleRate());
  copy->setNumberOfChannels(config.numberOfChannels());
  if (config.hasDescription()) {
    auto desc_wrapper = AsSpan<const uint8_t>(config.description());
    if (!desc_wrapper.empty()) {
      DOMArrayBuffer* buffer_copy = DOMArrayBuffer::Create(desc_wrapper);
      copy->setDescription(
          MakeGarbageCollected<AllowSharedBufferSource>(buffer_copy));
    }
  }
  return copy;
}

// static
std::unique_ptr<AudioDecoderTraits::MediaDecoderType>
AudioDecoderTraits::CreateDecoder(
    ExecutionContext& execution_context,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    media::MediaLog* media_log) {
  return std::make_unique<AudioDecoderBroker>(media_log, execution_context);
}

// static
void AudioDecoderTraits::UpdateDecoderLog(const MediaDecoderType& decoder,
                                          const MediaConfigType& media_config,
                                          media::MediaLog* media_log) {
  media_log->SetProperty<media::MediaLogProperty::kAudioDecoderName>(
      decoder.GetDecoderType());
  media_log->SetProperty<media::MediaLogProperty::kIsPlatformAudioDecoder>(
      decoder.IsPlatformDecoder());
  media_log->SetProperty<media::MediaLogProperty::kAudioTracks>(
      std::vector<MediaConfigType>{media_config});
  MEDIA_LOG(INFO, media_log)
      << "Initialized AudioDecoder: " << media_config.AsHumanReadableString();
  base::UmaHistogramEnumeration("Blink.WebCodecs.AudioDecoder.Codec",
                                media_config.codec());
}

// static
void AudioDecoderTraits::InitializeDecoder(
    MediaDecoderType& decoder,
    bool /*low_delay*/,
    const MediaConfigType& media_config,
    MediaDecoderType::InitCB init_cb,
    MediaDecoderType::OutputCB output_cb) {
  decoder.Initialize(media_config, nullptr /* cdm_context */,
                     std::move(init_cb), output_cb, media::WaitingCB());
}

// static
int AudioDecoderTraits::GetMaxDecodeRequests(const MediaDecoderType& decoder) {
  return 1;
}

// static
const char* AudioDecoderTraits::GetName() {
  return "AudioDecoder";
}

// static
AudioDecoder* AudioDecoder::Create(ScriptState* script_state,
                                   const AudioDecoderInit* init,
                                   ExceptionState& exception_state) {
  auto* result =
      MakeGarbageCollected<AudioDecoder>(script_state, init, exception_state);
  return exception_state.HadException() ? nullptr : result;
}

// static
ScriptPromise<AudioDecoderSupport> AudioDecoder::isConfigSupported(
    ScriptState* script_state,
    const AudioDecoderConfig* config,
    ExceptionState& exception_state) {
  String js_error_message;
  std::optional<media::AudioType> audio_type =
      IsValidAudioDecoderConfig(*config, &js_error_message);

  if (!audio_type) {
    exception_state.ThrowTypeError(js_error_message);
    return EmptyPromise();
  }

  AudioDecoderSupport* support = AudioDecoderSupport::Create();
  support->setSupported(media::IsDecoderSupportedAudioType(*audio_type));
  support->setConfig(CopyConfig(*config));
  return ToResolvedPromise<AudioDecoderSupport>(script_state, support);
}

// static
std::optional<media::AudioType> AudioDecoder::IsValidAudioDecoderConfig(
    const AudioDecoderConfig& config,
    String* js_error_message) {
  media::AudioType audio_type;

  if (config.numberOfChannels() == 0) {
    *js_error_message = String::Format(
        "Invalid channel count; channel count must be non-zero, received %d.",
        config.numberOfChannels());
    return std::nullopt;
  }

  if (config.sampleRate() == 0) {
    *js_error_message = String::Format(
        "Invalid sample rate; sample rate must be non-zero, received %d.",
        config.sampleRate());
    return std::nullopt;
  }

  if (config.codec().LengthWithStrippedWhiteSpace() == 0) {
    *js_error_message = "Invalid codec; codec is required.";
    return std::nullopt;
  }
  // Match codec strings from the codec registry:
  // https://www.w3.org/TR/webcodecs-codec-registry/#audio-codec-registry
  if (config.codec() == "ulaw") {
    audio_type = {media::AudioCodec::kPCM_MULAW};
    return audio_type;
  } else if (config.codec() == "alaw") {
    audio_type = {media::AudioCodec::kPCM_ALAW};
    return audio_type;
  }

  if (!VerifyDescription(config, js_error_message)) {
    CHECK(!js_error_message->empty());
    return std::nullopt;
  }

  media::AudioCodec codec = media::AudioCodec::kUnknown;
  bool is_codec_ambiguous = true;
  const bool parse_succeeded = ParseAudioCodecString(
      "", config.codec().Utf8(), &is_codec_ambiguous, &codec);

  if (!parse_succeeded || is_codec_ambiguous) {
    *js_error_message = "Unknown or ambiguous codec name.";
    audio_type = {media::AudioCodec::kUnknown};
    return audio_type;
  }

  audio_type = {codec};
  return audio_type;
}

// static
std::optional<media::AudioDecoderConfig>
AudioDecoder::MakeMediaAudioDecoderConfig(const ConfigType& config,
                                          String* js_error_message) {
  std::optional<media::AudioType> audio_type =
      IsValidAudioDecoderConfig(config, js_error_message);
  if (!audio_type) {
    // Checked by IsValidConfig().
    NOTREACHED();
  }
  if (audio_type->codec == media::AudioCodec::kUnknown) {
    return std::nullopt;
  }

  std::vector<uint8_t> extra_data;
  if (config.hasDescription()) {
    auto desc_wrapper = AsSpan<const uint8_t>(config.description());

    if (!desc_wrapper.data()) {
      // We should never get here, since this should be caught in
      // IsValidAudioDecoderConfig().
      *js_error_message = "Invalid config; description is detached.";
      return std::nullopt;
    }

    if (!desc_wrapper.empty()) {
      const uint8_t* start = desc_wrapper.data();
      const size_t size = desc_wrapper.size();
      extra_data.assign(start, start + size);
    }
  }

  media::ChannelLayout channel_layout =
      config.numberOfChannels() > 8
          // GuesschannelLayout() doesn't know how to guess above 8 channels.
          ? media::CHANNEL_LAYOUT_DISCRETE
          : media::GuessChannelLayout(config.numberOfChannels());

  auto encryption_scheme = media::EncryptionScheme::kUnencrypted;
  if (config.hasEncryptionScheme()) {
    auto scheme = ToMediaEncryptionScheme(config.encryptionScheme());
    if (!scheme) {
      *js_error_message = "Unsupported encryption scheme";
      return std::nullopt;
    }
    encryption_scheme = scheme.value();
  }

  // TODO(chcunningham): Add sample format to IDL.
  media::AudioDecoderConfig media_config;
  media_config.Initialize(
      audio_type->codec, media::kSampleFormatPlanarF32, channel_layout,
      config.sampleRate(), extra_data, encryption_scheme,
      base::TimeDelta() /* seek preroll */, 0 /* codec delay */);
  if (!media_config.IsValidConfig()) {
    *js_error_message = "Unsupported config.";
    return std::nullopt;
  }

  return media_config;
}

AudioDecoder::AudioDecoder(ScriptState* script_state,
                           const AudioDecoderInit* init,
                           ExceptionState& exception_state)
    : DecoderTemplate<AudioDecoderTraits>(script_state, init, exception_state) {
  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kWebCodecs);
}

bool AudioDecoder::IsValidConfig(const ConfigType& config,
                                 String* js_error_message) {
  return IsValidAudioDecoderConfig(config, js_error_message /* out */)
      .has_value();
}

std::optional<media::AudioDecoderConfig> AudioDecoder::MakeMediaConfig(
    const ConfigType& config,
    String* js_error_message) {
  DCHECK(js_error_message);
  return MakeMediaAudioDecoderConfig(config, js_error_message /* out */);
}

media::DecoderStatus::Or<scoped_refptr<media::DecoderBuffer>>
AudioDecoder::MakeInput(const InputType& chunk, bool verify_key_frame) {
  if (verify_key_frame && !chunk.buffer()->is_key_frame())
    return media::DecoderStatus::Codes::kKeyFrameRequired;
  return chunk.buffer();
}

media::DecoderStatus::Or<AudioDecoder::OutputType*> AudioDecoder::MakeOutput(
    scoped_refptr<MediaOutputType> output,
    ExecutionContext* context) {
  if (!blink::audio_utilities::IsValidAudioBufferSampleRate(
          output->sample_rate())) {
    return media::DecoderStatus(
        media::DecoderStatus::Codes::kInvalidArgument,
        String::Format("Invalid decoded audio output sample rate. Got %u, "
                       "which is outside [%f, %f]",
                       output->sample_rate(),
                       blink::audio_utilities::MinAudioBufferSampleRate(),
                       blink::audio_utilities::MaxAudioBufferSampleRate())
            .Ascii());
  }

  if (static_cast<uint32_t>(output->channel_count()) >
      BaseAudioContext::MaxNumberOfChannels()) {
    return media::DecoderStatus(
        media::DecoderStatus::Codes::kInvalidArgument,
        String::Format("Invalid decoded audio output channel "
                       "count. Got %u, which exceeds %u",
                       output->channel_count(),
                       BaseAudioContext::MaxNumberOfChannels())
            .Ascii());
  }

  return MakeGarbageCollected<AudioDecoderTraits::OutputType>(
      std::move(output));
}

const AtomicString& AudioDecoder::InterfaceName() const {
  return event_target_names::kAudioDecoder;
}

}  // namespace blink

"""

```