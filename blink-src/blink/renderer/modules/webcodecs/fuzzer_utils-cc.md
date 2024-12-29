Response:
Let's break down the thought process for analyzing the `fuzzer_utils.cc` file.

1. **Understand the Context:** The filename `fuzzer_utils.cc` immediately suggests this file is related to *fuzzing*. Knowing it's within the `blink/renderer/modules/webcodecs/` directory tells us it's specifically about fuzzing the WebCodecs API in the Chromium rendering engine.

2. **Identify Core Purpose:** Fuzzing involves providing a program with unexpected or malformed inputs to find bugs. This utility file likely provides functions to generate or manipulate these inputs for the WebCodecs API.

3. **Examine Includes:**  The `#include` directives are crucial for understanding dependencies and functionalities. We see includes for:
    * Standard library headers (`<algorithm>`, `<string>`) for basic operations.
    * `base/containers/span.h`, `base/functional/callback_helpers.h`: Chromium base library utilities.
    * `media/base/limits.h`, `media/base/sample_format.h`:  Media-related definitions.
    * `third_party/blink/renderer/bindings/...`: A significant number of headers related to Blink's JavaScript bindings. Specifically, many `v8_...` files for converting between JavaScript objects and C++ structures, especially for WebCodecs types (like `AudioDecoderConfig`, `VideoEncoderConfig`, etc.).
    * `third_party/blink/renderer/core/...`: Core Blink rendering engine components, including `ImageData`, `ImageBitmap`.
    * `third_party/blink/renderer/modules/webaudio/audio_buffer.h`: Related to the WebAudio API.
    * `third_party/blink/renderer/modules/webcodecs/fuzzer_inputs.pb.h`: Defines the protobuf messages used for specifying fuzzer inputs. This is a key include.
    * `third_party/blink/renderer/modules/webcodecs/video_frame.h`:  Represents video frames in WebCodecs.
    * `third_party/blink/renderer/platform/...`: Platform-level utilities.

4. **Analyze Key Functions:**  Go through the functions defined in the file, noting their names and parameters:
    * `MakeScopedGarbageCollectionRequest`:  Forces garbage collection – important for memory management during fuzzing.
    * `FakeFunction`:  A placeholder or stub function, likely used for callbacks in fuzzer scenarios.
    * `MakeVideoDecoderConfig`, `MakeAudioDecoderConfig`, `MakeVideoEncoderConfig`, `MakeAudioEncoderConfig`:  These functions are central. They take protobuf messages (`wc_fuzzer::Configure...`) as input and construct the corresponding WebCodecs configuration objects. This is a direct link to how fuzzer inputs are translated into API parameters.
    * `ToAccelerationType`, `ToBitrateMode`, etc.:  These "To..." functions convert enum values from the protobuf definitions into string literals used by the WebCodecs API.
    * `MakeEncodedVideoChunk`, `MakeEncodedAudioChunk`: Create `EncodedVideoChunk` and `EncodedAudioChunk` objects from protobuf inputs.
    * `MakeEncodeOptions`: Creates encoding options.
    * `MakeAllowSharedBufferSource`:  Handles the creation of `ArrayBuffer` or `SharedArrayBuffer` objects based on fuzzer input, including different views (e.g., `Int8Array`, `Uint32Array`). This is crucial for providing data to codecs.
    * `MakePlaneLayout`, `MakeDOMRectInit`, `MakeVideoColorSpaceInit`:  Helper functions to create specific configuration objects.
    * `MakeVideoFrame` (multiple overloads): Creates `VideoFrame` objects from different sources (buffer data, `ImageBitmap`).
    * `MakeAudioData`: Creates `AudioData` objects.
    * `MakeAudioDataCopyToOptions`: Creates options for copying audio data.

5. **Identify Relationships to Web Technologies:**
    * **JavaScript:**  The numerous `v8_...` includes and the functions creating WebCodecs API objects strongly indicate a close relationship with JavaScript. These functions are used to construct objects that are exposed to JavaScript in the browser.
    * **HTML:**  The inclusion of `HTMLCanvasElement`, `HTMLImageElement`, `HTMLVideoElement` in the `UNION_CSSIMAGEVALUE_HTMLCANVASELEMENT...` include suggests that these HTML elements can be sources for video frames (e.g., capturing from a `<canvas>` or `<video>`). The `MakeVideoFrame` overload taking `wc_fuzzer::VideoFrameBitmapInit` and using `ImageData` reinforces the connection with the `<canvas>` element.
    * **CSS:** The `UNION_CSSIMAGEVALUE...` also includes `CSSImageValue`, suggesting that CSS image values might be indirectly involved as potential sources for video frame data.

6. **Infer Fuzzing Scenarios and Error Potential:**
    * **Configuration Errors:** The `Make...Config` functions are prime candidates for introducing errors. Fuzzers will supply various combinations of codec, bitrate, resolution, etc., some of which might be invalid or unsupported.
    * **Data Errors:**  The `MakeEncoded...Chunk` and `MakeAllowSharedBufferSource` functions deal with raw data. Fuzzers will provide data with incorrect sizes, formats, or corrupt content.
    * **Resource Exhaustion:** Creating very large buffers or video frames could lead to memory issues. The `kMaxBufferLength` and `kMaxVideoFrameDimension` constants suggest an attempt to mitigate this.
    * **Type Mismatches:**  Incorrectly specifying data types or view types when creating `ArrayBuffer` views can cause errors.

7. **Consider the Debugging Perspective:**
    * **Entry Points:**  A developer debugging an issue triggered by the fuzzer would likely start by examining the fuzzer input that caused the crash. This input would be in the format defined by `fuzzer_inputs.pb`.
    * **Function Call Stack:**  Tracing the execution flow through the `Make...` functions would reveal how the fuzzer input was translated into API calls.
    * **Object Inspection:**  Inspecting the constructed WebCodecs objects (configurations, chunks, frames) would show the exact values generated by the fuzzer.

8. **Structure the Explanation:**  Organize the findings into logical categories: functionality, relationships with web technologies, logical reasoning (input/output), common errors, and debugging information. Provide concrete examples where possible.

This methodical approach, starting with understanding the overall context and gradually diving into the details of the code, allows for a comprehensive analysis of the file's purpose and its implications.
`blink/renderer/modules/webcodecs/fuzzer_utils.cc` 是 Chromium Blink 引擎中专门为 WebCodecs API 进行模糊测试而编写的实用工具代码文件。它的主要功能是 **将模糊测试框架生成的随机或半随机输入数据转换为 WebCodecs API 可以接受的 C++ 对象和数据结构**。  这使得模糊测试能够有效地探索 WebCodecs API 的各种状态和输入组合，以发现潜在的漏洞、崩溃或错误。

以下是该文件的详细功能分解，并结合其与 JavaScript、HTML 和 CSS 的关系进行说明：

**主要功能:**

1. **Protobuf 到 C++ 对象的转换:**
   - 该文件使用 Protocol Buffers (protobuf) 定义的结构 (`third_party/blink/renderer/modules/webcodecs/fuzzer_inputs.pb.h`) 来表示模糊测试的输入。
   - 它包含了大量的 `Make...` 函数，例如 `MakeVideoDecoderConfig`, `MakeAudioEncoderConfig`, `MakeEncodedVideoChunk` 等，这些函数负责将 protobuf 消息转换为对应的 WebCodecs C++ 对象，如 `VideoDecoderConfig`, `AudioEncoderConfig`, `EncodedVideoChunk`。

   **例子:**
   - 如果模糊测试输入包含一个 `wc_fuzzer::ConfigureVideoDecoder` 类型的 protobuf 消息，`MakeVideoDecoderConfig` 函数会解析这个消息，提取出 `codec`（编解码器）、`description`（描述数据）等字段，并创建一个 `VideoDecoderConfig` 对象。

2. **枚举类型转换:**
   - 许多 WebCodecs API 使用枚举类型来表示选项或状态。该文件包含 `To...` 形式的函数，用于将 protobuf 中定义的枚举值转换为 WebCodecs API 中使用的字符串或枚举值。

   **例子:**
   - `ToAccelerationType(proto.acceleration())` 将 `wc_fuzzer::ConfigureVideoEncoder_EncoderAccelerationPreference` 枚举值（如 `ALLOW`, `DENY`, `REQUIRE`）转换为 WebCodecs API 期望的字符串值（如 `"no-preference"`, `"prefer-software"`, `"prefer-hardware"`）。

3. **创建 WebCodecs 数据结构:**
   - 文件中还包含创建 `VideoFrame`, `AudioData`, `EncodedVideoChunk`, `EncodedAudioChunk` 等 WebCodecs 核心数据结构的函数。这些函数根据模糊测试输入的数据填充这些结构。

   **例子:**
   - `MakeEncodedVideoChunk` 函数接收一个 `wc_fuzzer::EncodedVideoChunk` protobuf 消息，提取出时间戳 (`timestamp`)、类型 (`type`) 和数据 (`data`)，然后创建一个 `EncodedVideoChunk` 对象。

4. **处理 ArrayBuffer 和 SharedArrayBuffer:**
   - `MakeAllowSharedBufferSource` 函数根据模糊测试输入创建 `DOMArrayBuffer` 或 `DOMSharedArrayBuffer` 对象，并可以创建不同类型的视图（如 `DOMInt8Array`, `DOMUint32Array`, `DOMDataView`）。这对于提供编解码器所需的输入数据至关重要。

**与 JavaScript, HTML, CSS 的关系:**

虽然此 C++ 文件本身不直接涉及 JavaScript、HTML 或 CSS 的语法，但它的功能是 **为了测试那些通过 JavaScript API 暴露给 Web 开发者的 WebCodecs 功能**。

- **JavaScript:** WebCodecs API 是通过 JavaScript 暴露的。开发者使用 JavaScript 代码来创建和配置解码器 (`VideoDecoder`, `AudioDecoder`) 和编码器 (`VideoEncoder`, `AudioEncoder`)，并操作 `VideoFrame`, `AudioData`, `EncodedChunk` 等对象。 `fuzzer_utils.cc` 中创建的 C++ 对象正是这些 JavaScript API 背后的实现。

   **举例说明:**  假设一个模糊测试用例旨在测试 `VideoDecoder.configure()` 方法。模糊测试框架会生成一个 `wc_fuzzer::ConfigureVideoDecoder` protobuf 消息，`MakeVideoDecoderConfig` 函数会将其转换为 `VideoDecoderConfig` 对象。这个对象会被传递给 Blink 内部的 `VideoDecoder` 实现，模拟 JavaScript 调用 `videoDecoder.configure(config)` 的场景，其中 `config` 的内容来源于模糊测试。

- **HTML:**  WebCodecs API 可以与 HTML 元素（如 `<canvas>`, `<video>`, `<img>`）进行交互，例如从这些元素中获取图像数据作为 `VideoFrame` 的输入。

   **举例说明:** `MakeVideoFrame` 函数有一个重载版本 `MakeVideoFrame(ScriptState* script_state, const wc_fuzzer::VideoFrameBitmapInit& proto)`，它可以根据模糊测试输入创建一个基于 `ImageData` 的 `VideoFrame`。`ImageData` 通常是从 `<canvas>` 元素获取的像素数据。模糊测试可能会提供各种尺寸、内容的“假” `ImageData` 来测试 `VideoFrame` 的处理。

- **CSS:**  CSS 间接地可能与 WebCodecs 有关，例如，CSS 可以控制视频或图像的显示大小和裁剪。虽然 `fuzzer_utils.cc` 不直接操作 CSS，但模糊测试可能会生成导致 WebCodecs 处理与 CSS 渲染相关的边界情况的输入。

   **举例说明:** 模糊测试可能会生成一个非常小的视频帧，然后通过 JavaScript 将其传递给解码器。解码器在处理这个帧时，需要考虑到浏览器可能使用 CSS 来放大显示这个小帧的情况。 `fuzzer_utils.cc` 能够创建各种尺寸的视频帧，从而帮助测试解码器在这些场景下的行为。

**逻辑推理（假设输入与输出）:**

假设模糊测试输入一个 `wc_fuzzer::ConfigureAudioEncoder` protobuf 消息，内容如下：

```protobuf
codec: "opus"
bitrate: 128000
number_of_channels: 2
sample_rate: 48000
opus {
  complexity: 10
  packetlossperc: 5
}
```

**假设输入:**  上述 protobuf 消息。

**输出 (通过 `MakeAudioEncoderConfig` 函数):**  一个 `AudioEncoderConfig` C++ 对象，其成员变量被设置为以下值：

```c++
config->setCodec("opus");
config->setBitrate(128000);
config->setNumberOfChannels(2);
config->setSampleRate(48000);
// ...
config->opus()->setComplexity(10);
config->opus()->setPacketlossperc(5);
```

这个 `AudioEncoderConfig` 对象随后会被传递给音频编码器的配置逻辑进行进一步处理。

**用户或编程常见的使用错误（调试线索）:**

`fuzzer_utils.cc` 的存在本身就是为了发现用户或程序员在使用 WebCodecs API 时可能出现的错误，或者 API 实现本身存在的缺陷。一些潜在的错误包括：

1. **配置错误:**  用户可能提供无效的编解码器配置参数，例如不支持的编解码器名称、负的比特率、通道数超过限制等。`Make...Config` 函数接收来自模糊测试的各种配置组合，包括这些错误的组合，以测试 API 的健壮性。

   **举例:**  用户 JavaScript 代码尝试配置一个比特率为 -1000 的音频编码器。模糊测试可以模拟这种情况，`MakeAudioEncoderConfig` 会创建一个 `bitrate` 为 -1000 的 `AudioEncoderConfig` 对象，然后测试编码器如何处理这个无效值（可能会抛出异常或返回错误）。

2. **数据格式错误:** 用户可能提供不符合编解码器要求的输入数据格式或大小。

   **举例:** 用户 JavaScript 代码将一个不完整的或损坏的 H.264 码流传递给 `VideoDecoder.decode()`。模糊测试可以通过 `MakeEncodedVideoChunk` 创建包含各种异常数据的 `EncodedVideoChunk` 对象，来测试解码器的错误处理能力。

3. **资源泄漏或内存错误:**  不正确的资源管理可能导致内存泄漏或崩溃。模糊测试通过生成大量的对象和操作，可以暴露这些问题。

   **举例:** 模糊测试可能会创建大量的 `VideoFrame` 对象而不正确地释放它们，以检测是否存在内存泄漏。

**用户操作如何一步步到达这里（调试线索）:**

当开发者在 Chromium 中调试与 WebCodecs 相关的崩溃或错误，并且怀疑问题可能与 API 的输入处理有关时，`fuzzer_utils.cc` 可以提供调试线索：

1. **识别崩溃时的 WebCodecs 函数:**  首先需要确定崩溃发生在哪个 WebCodecs API 的内部实现中，例如 `VideoDecoder::Decode()`, `AudioEncoder::Encode()`, `VideoFrame::Create()` 等。

2. **查看崩溃时的输入参数:**  调试器可以用于检查导致崩溃的 WebCodecs 函数的输入参数。例如，如果崩溃发生在 `VideoDecoder::Decode()` 中，需要查看传递给该函数的 `EncodedVideoChunk` 对象的内容。

3. **追溯输入参数的来源:**  如果怀疑输入参数存在问题，需要追溯这些参数的创建过程。在 Chromium 的代码中，如果这些参数来源于 JavaScript API 调用，那么它们最终会通过 Blink 的绑定层传递到 C++ 代码。

4. **关注模糊测试相关的代码:**  如果发现问题可能与输入数据的格式或值有关，并且是在一个被模糊测试覆盖的区域，那么 `fuzzer_utils.cc` 中的 `Make...` 函数就成为了关键的入口点。

5. **模拟模糊测试输入:**  开发者可以尝试理解导致崩溃的模糊测试用例（如果可以获取到）以及对应的 protobuf 输入。然后，手动编写 C++ 代码或使用测试工具，模拟 `fuzzer_utils.cc` 中的逻辑，创建与崩溃时类似的 WebCodecs 对象和数据结构。

6. **单步调试 `Make...` 函数:**  通过单步调试 `fuzzer_utils.cc` 中相关的 `Make...` 函数，开发者可以观察模糊测试输入是如何被解析和转换为 C++ 对象的，从而找到可能导致问题的转换逻辑或输入值的组合。

总之，`blink/renderer/modules/webcodecs/fuzzer_utils.cc` 是一个幕后英雄，它使得对 WebCodecs API 进行有效的模糊测试成为可能。虽然普通用户不会直接接触到这个文件，但它对于确保 WebCodecs API 的稳定性和安全性至关重要，同时也为开发者提供了重要的调试线索。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/fuzzer_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/webcodecs/fuzzer_utils.h"

#include <algorithm>
#include <string>

#include "base/containers/span.h"
#include "base/functional/callback_helpers.h"
#include "media/base/limits.h"
#include "media/base/sample_format.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_aac_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_copy_to_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_audio_chunk_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_opus_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_plane_layout.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_color_space_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_av_1.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_vp_9.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_buffer_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_init.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_data_view.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_shared_array_buffer.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/fuzzer_inputs.pb.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// 16 MiB ought to be enough for anybody.
constexpr size_t kMaxBufferLength = 16 * 1024 * 1024;

// Override for maximum frame dimensions to avoid huge allocations.
constexpr uint32_t kMaxVideoFrameDimension = 1024;

}  // namespace

base::ScopedClosureRunner MakeScopedGarbageCollectionRequest(
    v8::Isolate* isolate) {
  return base::ScopedClosureRunner(WTF::BindOnce(
      [](v8::Isolate* isolate) {
        // Request a V8 GC. Oilpan will be invoked by the GC epilogue.
        //
        // Multiple GCs may be required to ensure everything is collected (due
        // to a chain of persistent handles), so some objects may not be
        // collected until a subsequent iteration. This is slow enough as is, so
        // we compromise on one major GC, as opposed to the 5 used in
        // V8GCController for unit tests.
        isolate->RequestGarbageCollectionForTesting(
            v8::Isolate::kFullGarbageCollection);
      },
      WTF::Unretained(isolate)));
}

FakeFunction::FakeFunction(std::string name) : name_(std::move(name)) {}

ScriptValue FakeFunction::Call(ScriptState*, ScriptValue) {
  return ScriptValue();
}

VideoDecoderConfig* MakeVideoDecoderConfig(
    const wc_fuzzer::ConfigureVideoDecoder& proto) {
  auto* config = VideoDecoderConfig::Create();
  config->setCodec(proto.codec().c_str());
  DOMArrayBuffer* data_copy = DOMArrayBuffer::Create(
      proto.description().data(), proto.description().size());
  config->setDescription(
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy));
  return config;
}

AudioDecoderConfig* MakeAudioDecoderConfig(
    const wc_fuzzer::ConfigureAudioDecoder& proto) {
  AudioDecoderConfig* config = AudioDecoderConfig::Create();
  config->setCodec(proto.codec().c_str());
  config->setSampleRate(proto.sample_rate());
  config->setNumberOfChannels(proto.number_of_channels());

  DOMArrayBuffer* data_copy = DOMArrayBuffer::Create(
      proto.description().data(), proto.description().size());
  config->setDescription(
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy));

  return config;
}

VideoEncoderConfig* MakeVideoEncoderConfig(
    const wc_fuzzer::ConfigureVideoEncoder& proto) {
  VideoEncoderConfig* config = VideoEncoderConfig::Create();
  config->setCodec(proto.codec().c_str());
  config->setHardwareAcceleration(ToAccelerationType(proto.acceleration()));
  config->setFramerate(proto.framerate());
  config->setWidth(std::min(proto.width(), kMaxVideoFrameDimension));
  config->setHeight(std::min(proto.height(), kMaxVideoFrameDimension));
  config->setDisplayWidth(proto.display_width());
  config->setDisplayHeight(proto.display_height());

  if (proto.has_alpha()) {
    config->setAlpha(ToAlphaOption(proto.alpha()));
  }
  if (proto.has_bitrate_mode()) {
    config->setBitrateMode(ToBitrateMode(proto.bitrate_mode()));
  }
  if (proto.has_scalability_mode()) {
    config->setScalabilityMode(ToScalabilityMode(proto.scalability_mode()));
  }
  if (proto.has_latency_mode()) {
    config->setLatencyMode(ToLatencyMode(proto.latency_mode()));
  }

  if (proto.has_content_hint()) {
    config->setContentHint(ToContentHint(proto.content_hint()));
  }

  // Bitrate is truly optional, so don't just take the proto default value.
  if (proto.has_bitrate())
    config->setBitrate(proto.bitrate());

  return config;
}

AudioEncoderConfig* MakeAudioEncoderConfig(
    const wc_fuzzer::ConfigureAudioEncoder& proto) {
  auto* config = AudioEncoderConfig::Create();
  config->setCodec(proto.codec().c_str());
  config->setBitrate(proto.bitrate());
  config->setNumberOfChannels(proto.number_of_channels());
  config->setSampleRate(proto.sample_rate());

  if (proto.has_bitrate_mode()) {
    config->setBitrateMode(ToBitrateMode(proto.bitrate_mode()));
  }

  if (proto.has_aac()) {
    auto* aac = AacEncoderConfig::Create();
    config->setAac(aac);
    if (proto.aac().has_format()) {
      aac->setFormat(ToAacFormat(proto.aac().format()));
    }
  }

  if (proto.has_opus()) {
    auto* opus = OpusEncoderConfig::Create();
    config->setOpus(opus);
    if (proto.opus().has_frame_duration()) {
      opus->setFrameDuration(proto.opus().frame_duration());
    }
    if (proto.opus().has_complexity()) {
      opus->setComplexity(proto.opus().complexity());
    }
    if (proto.opus().has_packetlossperc()) {
      opus->setPacketlossperc(proto.opus().packetlossperc());
    }
    if (proto.opus().has_useinbandfec()) {
      opus->setUseinbandfec(proto.opus().useinbandfec());
    }
    if (proto.opus().has_usedtx()) {
      opus->setUsedtx(proto.opus().usedtx());
    }
    if (proto.opus().has_signal()) {
      opus->setSignal(ToOpusSignal(proto.opus().signal()));
    }
    if (proto.opus().has_application()) {
      opus->setApplication(ToOpusApplication(proto.opus().application()));
    }
  }

  return config;
}

String ToAccelerationType(
    wc_fuzzer::ConfigureVideoEncoder_EncoderAccelerationPreference type) {
  switch (type) {
    case wc_fuzzer::ConfigureVideoEncoder_EncoderAccelerationPreference_ALLOW:
      return "no-preference";
    case wc_fuzzer::ConfigureVideoEncoder_EncoderAccelerationPreference_DENY:
      return "prefer-software";
    case wc_fuzzer::ConfigureVideoEncoder_EncoderAccelerationPreference_REQUIRE:
      return "prefer-hardware";
  }
}

String ToBitrateMode(
    wc_fuzzer::ConfigureVideoEncoder_VideoEncoderBitrateMode mode) {
  switch (mode) {
    case wc_fuzzer::ConfigureVideoEncoder_VideoEncoderBitrateMode_CONSTANT:
      return "constant";
    case wc_fuzzer::ConfigureVideoEncoder_VideoEncoderBitrateMode_VARIABLE:
      return "variable";
    case wc_fuzzer::ConfigureVideoEncoder_VideoEncoderBitrateMode_QUANTIZER:
      return "quantizer";
  }
}

String ToScalabilityMode(
    wc_fuzzer::ConfigureVideoEncoder_ScalabilityMode mode) {
  switch (mode) {
    case wc_fuzzer::ConfigureVideoEncoder_ScalabilityMode_L1T1:
      return "L1T1";
    case wc_fuzzer::ConfigureVideoEncoder_ScalabilityMode_L1T2:
      return "L1T2";
    case wc_fuzzer::ConfigureVideoEncoder_ScalabilityMode_L1T3:
      return "L1T3";
  }
}

String ToLatencyMode(wc_fuzzer::ConfigureVideoEncoder_LatencyMode mode) {
  switch (mode) {
    case wc_fuzzer::ConfigureVideoEncoder_LatencyMode_QUALITY:
      return "quality";
    case wc_fuzzer::ConfigureVideoEncoder_LatencyMode_REALTIME:
      return "realtime";
  }
}

String ToContentHint(wc_fuzzer::ConfigureVideoEncoder_ContentHint hint) {
  switch (hint) {
    case wc_fuzzer::ConfigureVideoEncoder_ContentHint_NONE:
      return "";
    case wc_fuzzer::ConfigureVideoEncoder_ContentHint_TEXT:
      return "text";
    case wc_fuzzer::ConfigureVideoEncoder_ContentHint_MOTION:
      return "motion";
    case wc_fuzzer::ConfigureVideoEncoder_ContentHint_DETAIL:
      return "detail";
  }
}

String ToAlphaOption(wc_fuzzer::ConfigureVideoEncoder_AlphaOption option) {
  switch (option) {
    case wc_fuzzer::ConfigureVideoEncoder_AlphaOption_KEEP:
      return "keep";
    case wc_fuzzer::ConfigureVideoEncoder_AlphaOption_DISCARD:
      return "discard";
  }
}

String ToAacFormat(wc_fuzzer::AacFormat format) {
  switch (format) {
    case wc_fuzzer::AAC:
      return "aac";
    case wc_fuzzer::ADTS:
      return "adts";
  }
}

String ToBitrateMode(wc_fuzzer::BitrateMode bitrate_mode) {
  switch (bitrate_mode) {
    case wc_fuzzer::VARIABLE:
      return "variable";
    case wc_fuzzer::CONSTANT:
      return "constant";
  }
}

String ToOpusSignal(wc_fuzzer::OpusSignal opus_signal) {
  switch (opus_signal) {
    case wc_fuzzer::AUTO:
      return "auto";
    case wc_fuzzer::MUSIC:
      return "music";
    case wc_fuzzer::VOICE:
      return "voice";
  }
}

String ToOpusApplication(wc_fuzzer::OpusApplication opus_application) {
  switch (opus_application) {
    case wc_fuzzer::VOIP:
      return "voip";
    case wc_fuzzer::AUDIO:
      return "audio";
    case wc_fuzzer::LOWDELAY:
      return "lowdelay";
  }
}

String ToChunkType(wc_fuzzer::EncodedChunkType type) {
  switch (type) {
    case wc_fuzzer::EncodedChunkType::KEY:
      return "key";
    case wc_fuzzer::EncodedChunkType::DELTA:
      return "delta";
  }
}

String ToAudioSampleFormat(wc_fuzzer::AudioSampleFormat format) {
  switch (format) {
    case wc_fuzzer::AudioSampleFormat::U8:
      return "u8";
    case wc_fuzzer::AudioSampleFormat::S16:
      return "s16";
    case wc_fuzzer::AudioSampleFormat::S32:
      return "s32";
    case wc_fuzzer::AudioSampleFormat::F32:
      return "f32";
    case wc_fuzzer::AudioSampleFormat::U8_PLANAR:
      return "u8-planar";
    case wc_fuzzer::AudioSampleFormat::S16_PLANAR:
      return "s16-planar";
    case wc_fuzzer::AudioSampleFormat::S32_PLANAR:
      return "s32-planar";
    case wc_fuzzer::AudioSampleFormat::F32_PLANAR:
      return "f32-planar";
  }
}

int SampleFormatToSampleSize(V8AudioSampleFormat format) {
  using FormatEnum = V8AudioSampleFormat::Enum;

  switch (format.AsEnum()) {
    case FormatEnum::kU8:
    case FormatEnum::kU8Planar:
      return 1;

    case FormatEnum::kS16:
    case FormatEnum::kS16Planar:
      return 2;

    case FormatEnum::kS32:
    case FormatEnum::kS32Planar:
    case FormatEnum::kF32:
    case FormatEnum::kF32Planar:
      return 4;
  }
}

EncodedVideoChunk* MakeEncodedVideoChunk(
    ScriptState* script_state,
    const wc_fuzzer::EncodedVideoChunk& proto) {
  auto* data = MakeGarbageCollected<AllowSharedBufferSource>(
      DOMArrayBuffer::Create(proto.data().data(), proto.data().size()));

  auto* init = EncodedVideoChunkInit::Create();
  init->setTimestamp(proto.timestamp());
  init->setType(ToChunkType(proto.type()));
  init->setData(data);

  if (proto.has_duration())
    init->setDuration(proto.duration());

  return EncodedVideoChunk::Create(script_state, init,
                                   IGNORE_EXCEPTION_FOR_TESTING);
}

EncodedAudioChunk* MakeEncodedAudioChunk(
    ScriptState* script_state,
    const wc_fuzzer::EncodedAudioChunk& proto) {
  auto* data = MakeGarbageCollected<AllowSharedBufferSource>(
      DOMArrayBuffer::Create(proto.data().data(), proto.data().size()));

  auto* init = EncodedAudioChunkInit::Create();
  init->setTimestamp(proto.timestamp());
  init->setType(ToChunkType(proto.type()));
  init->setData(data);

  if (proto.has_duration())
    init->setDuration(proto.duration());

  return EncodedAudioChunk::Create(script_state, init,
                                   IGNORE_EXCEPTION_FOR_TESTING);
}

VideoEncoderEncodeOptions* MakeEncodeOptions(
    const wc_fuzzer::EncodeVideo_EncodeOptions& proto) {
  VideoEncoderEncodeOptions* options = VideoEncoderEncodeOptions::Create();

  // Truly optional, so don't set it if its just a proto default value.
  if (proto.has_key_frame())
    options->setKeyFrame(proto.key_frame());

  if (proto.has_av1() && proto.av1().has_quantizer()) {
    auto* av1 = VideoEncoderEncodeOptionsForAv1::Create();
    av1->setQuantizer(proto.av1().quantizer());
    options->setAv1(av1);
  }

  if (proto.has_vp9() && proto.vp9().has_quantizer()) {
    auto* vp9 = VideoEncoderEncodeOptionsForVp9::Create();
    vp9->setQuantizer(proto.vp9().quantizer());
    options->setVp9(vp9);
  }

  return options;
}

BufferAndSource MakeAllowSharedBufferSource(
    const wc_fuzzer::AllowSharedBufferSource& proto) {
  BufferAndSource result = {};
  size_t length =
      std::min(static_cast<size_t>(proto.length()), kMaxBufferLength);

  DOMArrayBufferBase* buffer = nullptr;
  if (proto.shared()) {
    buffer = DOMSharedArrayBuffer::Create(static_cast<unsigned>(length), 1);
  } else {
    auto* array_buffer = DOMArrayBuffer::Create(length, 1);
    buffer = array_buffer;
    if (proto.transfer()) {
      result.buffer = array_buffer;
    }
  }
  DCHECK(buffer);

  size_t view_offset =
      std::min(static_cast<size_t>(proto.view_offset()), length);
  size_t view_length =
      std::min(static_cast<size_t>(proto.view_length()), length - view_offset);
  switch (proto.view_type()) {
    case wc_fuzzer::AllowSharedBufferSource_ViewType_NONE:
      result.source = MakeGarbageCollected<AllowSharedBufferSource>(buffer);
      break;
    case wc_fuzzer::AllowSharedBufferSource_ViewType_INT8:
      result.source = MakeGarbageCollected<AllowSharedBufferSource>(
          MaybeShared<DOMInt8Array>(
              DOMInt8Array::Create(buffer, view_offset, view_length)));
      break;
    case wc_fuzzer::AllowSharedBufferSource_ViewType_UINT32:
      // View must be element-aligned and is sized by element count.
      view_offset = std::min(view_offset, length / 4) * 4;
      view_length = std::min(view_length, length / 4 - view_offset / 4);
      result.source = MakeGarbageCollected<AllowSharedBufferSource>(
          MaybeShared<DOMUint32Array>(
              DOMUint32Array::Create(buffer, view_offset, view_length)));
      break;
    case wc_fuzzer::AllowSharedBufferSource_ViewType_DATA:
      result.source = MakeGarbageCollected<AllowSharedBufferSource>(
          MaybeShared<DOMDataView>(
              DOMDataView::Create(buffer, view_offset, view_length)));
  }

  return result;
}

PlaneLayout* MakePlaneLayout(const wc_fuzzer::PlaneLayout& proto) {
  PlaneLayout* plane_layout = PlaneLayout::Create();
  plane_layout->setOffset(proto.offset());
  plane_layout->setStride(proto.stride());
  return plane_layout;
}

DOMRectInit* MakeDOMRectInit(const wc_fuzzer::DOMRectInit& proto) {
  DOMRectInit* init = DOMRectInit::Create();
  init->setX(proto.x());
  init->setY(proto.y());
  init->setWidth(proto.width());
  init->setHeight(proto.height());
  return init;
}

VideoColorSpaceInit* MakeVideoColorSpaceInit(
    const wc_fuzzer::VideoColorSpaceInit& proto) {
  VideoColorSpaceInit* init = VideoColorSpaceInit::Create();

  if (proto.has_primaries()) {
    switch (proto.primaries()) {
      case wc_fuzzer::VideoColorSpaceInit_VideoColorPrimaries_VCP_BT709:
        init->setPrimaries("bt709");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoColorPrimaries_VCP_BT470BG:
        init->setPrimaries("bt470bg");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoColorPrimaries_VCP_SMPTE170M:
        init->setPrimaries("smpte170m");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoColorPrimaries_VCP_BT2020:
        init->setPrimaries("bt2020");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoColorPrimaries_VCP_SMPTE432:
        init->setPrimaries("smpte432");
        break;
    }
  }

  if (proto.has_transfer()) {
    switch (proto.transfer()) {
      case wc_fuzzer::
          VideoColorSpaceInit_VideoTransferCharacteristics_VTC_BT709:
        init->setTransfer("bt709");
        break;
      case wc_fuzzer::
          VideoColorSpaceInit_VideoTransferCharacteristics_VTC_SMPTE170M:
        init->setTransfer("smpte170m");
        break;
      case wc_fuzzer::
          VideoColorSpaceInit_VideoTransferCharacteristics_VTC_IEC61966_2_1:
        init->setTransfer("iec61966-2-1");
        break;
      case wc_fuzzer::
          VideoColorSpaceInit_VideoTransferCharacteristics_VTC_LINEAR:
        init->setTransfer("linear");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoTransferCharacteristics_VTC_PQ:
        init->setTransfer("pq");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoTransferCharacteristics_VTC_HLG:
        init->setTransfer("hlg");
        break;
    }
  }

  if (proto.has_matrix()) {
    switch (proto.matrix()) {
      case wc_fuzzer::VideoColorSpaceInit_VideoMatrixCoefficients_VMC_RGB:
        init->setMatrix("rgb");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoMatrixCoefficients_VMC_BT709:
        init->setMatrix("bt709");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoMatrixCoefficients_VMC_BT470BG:
        init->setMatrix("bt470bg");
        break;
      case wc_fuzzer::VideoColorSpaceInit_VideoMatrixCoefficients_VMC_SMPTE170M:
        init->setMatrix("smpte170m");
        break;
      case wc_fuzzer::
          VideoColorSpaceInit_VideoMatrixCoefficients_VMC_BT2020_NCL:
        init->setMatrix("bt2020-ncl");
        break;
    }
  }

  if (proto.has_full_range()) {
    init->setFullRange(proto.full_range());
  }

  return init;
}

VideoFrame* MakeVideoFrame(
    ScriptState* script_state,
    const wc_fuzzer::VideoFrameBufferInitInvocation& proto) {
  BufferAndSource data = MakeAllowSharedBufferSource(proto.data());
  VideoFrameBufferInit* init = VideoFrameBufferInit::Create();

  switch (proto.init().format()) {
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_I420:
      init->setFormat("I420");
      break;
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_I420A:
      init->setFormat("I420A");
      break;
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_I444:
      init->setFormat("I444");
      break;
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_NV12:
      init->setFormat("NV12");
      break;
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_RGBA:
      init->setFormat("RGBA");
      break;
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_RGBX:
      init->setFormat("RGBX");
      break;
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_BGRA:
      init->setFormat("BGRA");
      break;
    case wc_fuzzer::VideoFrameBufferInit_VideoPixelFormat_BGRX:
      init->setFormat("BGRX");
      break;
  }

  if (proto.init().layout_size()) {
    HeapVector<Member<PlaneLayout>> layout{};
    for (const auto& plane_proto : proto.init().layout())
      layout.push_back(MakePlaneLayout(plane_proto));
    init->setLayout(layout);
  }

  init->setTimestamp(proto.init().timestamp());
  if (proto.init().has_duration())
    init->setDuration(proto.init().duration());

  init->setCodedWidth(
      std::min(proto.init().coded_width(), kMaxVideoFrameDimension));
  init->setCodedHeight(
      std::min(proto.init().coded_height(), kMaxVideoFrameDimension));

  if (proto.init().has_visible_rect())
    init->setVisibleRect(MakeDOMRectInit(proto.init().visible_rect()));

  if (proto.init().has_display_width())
    init->setDisplayWidth(proto.init().display_width());
  if (proto.init().has_display_height())
    init->setDisplayHeight(proto.init().display_height());

  if (proto.init().has_color_space()) {
    init->setColorSpace(MakeVideoColorSpaceInit(proto.init().color_space()));
  }

  if (data.buffer) {
    HeapVector<Member<DOMArrayBuffer>> transfer;
    transfer.push_back(data.buffer);
    init->setTransfer(std::move(transfer));
  }

  return VideoFrame::Create(script_state, data.source, init,
                            IGNORE_EXCEPTION_FOR_TESTING);
}

VideoFrame* MakeVideoFrame(ScriptState* script_state,
                           const wc_fuzzer::VideoFrameBitmapInit& proto) {
  constexpr size_t kBytesPerPixel = 4;
  auto bitmap_size = proto.rgb_bitmap().size();
  // ImageData::Create() rejects inputs if data size is not a multiple of
  // width * 4.
  // Round down bitmap size to width * 4, it makes more fuzzer inputs
  // acceptable and incresease fuzzing penetration.
  if (proto.bitmap_width() > 0 && proto.bitmap_width() < bitmap_size)
    bitmap_size -= bitmap_size % (proto.bitmap_width() * kBytesPerPixel);
  NotShared<DOMUint8ClampedArray> data_u8(DOMUint8ClampedArray::Create(
      base::as_byte_span(proto.rgb_bitmap()).first(bitmap_size)));

  ImageData* image_data = ImageData::Create(data_u8, proto.bitmap_width(),
                                            IGNORE_EXCEPTION_FOR_TESTING);

  if (!image_data)
    return nullptr;

  ImageBitmap* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      image_data, std::nullopt, ImageBitmapOptions::Create());

  VideoFrameInit* video_frame_init = VideoFrameInit::Create();
  video_frame_init->setTimestamp(proto.timestamp());
  video_frame_init->setDuration(proto.duration());

  auto* source = MakeGarbageCollected<V8CanvasImageSource>(image_bitmap);

  return VideoFrame::Create(script_state, source, video_frame_init,
                            IGNORE_EXCEPTION_FOR_TESTING);
}

AudioData* MakeAudioData(ScriptState* script_state,
                         const wc_fuzzer::AudioDataInit& proto) {
  if (!proto.channels().size() ||
      proto.channels().size() > media::limits::kMaxChannels)
    return nullptr;

  if (!proto.length() ||
      proto.length() > media::limits::kMaxSamplesPerPacket / 4) {
    return nullptr;
  }

  V8AudioSampleFormat format =
      V8AudioSampleFormat::Create(ToAudioSampleFormat(proto.format())).value();

  int size_per_sample = SampleFormatToSampleSize(format);
  int number_of_samples = proto.channels().size() * proto.length();

  auto* buffer = DOMArrayBuffer::Create(number_of_samples, size_per_sample);

  memset(buffer->Data(), 0, number_of_samples * size_per_sample);

  for (int i = 0; i < proto.channels().size(); i++) {
    size_t max_plane_size = proto.length() * size_per_sample;

    auto* data = proto.channels().Get(i).data();
    auto size = std::min(proto.channels().Get(i).size(), max_plane_size);

    void* plane_start =
        reinterpret_cast<uint8_t*>(buffer->Data()) + i * max_plane_size;
    memcpy(plane_start, data, size);
  }

  auto* init = AudioDataInit::Create();
  init->setTimestamp(proto.timestamp());
  init->setNumberOfFrames(proto.length());
  init->setNumberOfChannels(proto.channels().size());
  init->setSampleRate(proto.sample_rate());
  init->setFormat(format);
  init->setData(MakeGarbageCollected<AllowSharedBufferSource>(buffer));

  if (proto.transfer()) {
    HeapVector<Member<DOMArrayBuffer>> transfer;
    transfer.push_back(buffer);
    init->setTransfer(std::move(transfer));
  }

  return AudioData::Create(script_state, init, IGNORE_EXCEPTION_FOR_TESTING);
}

AudioDataCopyToOptions* MakeAudioDataCopyToOptions(
    const wc_fuzzer::AudioDataCopyToOptions& options_proto) {
  AudioDataCopyToOptions* options = AudioDataCopyToOptions::Create();
  options->setPlaneIndex(options_proto.plane_index());
  if (options_proto.has_frame_offset())
    options->setFrameOffset(options_proto.frame_offset());
  if (options_proto.has_frame_count())
    options->setFrameCount(options_proto.frame_count());
  if (options_proto.has_format())
    options->setFormat(ToAudioSampleFormat(options_proto.format()));
  return options;
}

}  // namespace blink

"""

```