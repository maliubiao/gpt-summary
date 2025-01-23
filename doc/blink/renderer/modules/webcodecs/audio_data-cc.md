Response:
Let's break down the thought process for analyzing the `audio_data.cc` file.

1. **Understand the Goal:** The core request is to understand the functionality of this C++ file within the Chromium Blink rendering engine, specifically as it relates to `AudioData`. This includes its interactions with JavaScript, HTML, CSS, potential errors, and debugging.

2. **Initial Scan for Key Concepts:**  The first step is to quickly scan the file for recognizable keywords and structures:
    * `#include`:  This tells us about dependencies. We see includes related to:
        * Standard C++ (`<optional>`, `<vector>`)
        * Chromium base libraries (`base/compiler_specific.h`, `base/notreached.h`, etc.)
        * Media-related libraries (`media/base/audio_buffer.h`, `media/base/audio_bus.h`, etc.)
        * Blink-specific bindings (`third_party/blink/renderer/bindings/...`)
        * Blink platform (`third_party/blink/renderer/platform/...`)
        * WebAudio (`third_party/blink/renderer/modules/webaudio/...`)
    * `namespace blink`: This confirms it's part of the Blink rendering engine.
    * `class AudioData`: This is the central class we need to analyze.
    * Member variables: `format_`, `timestamp_`, `data_`, `data_as_f32_bus_`. These hold the audio data and related information.
    * Methods: `Create`, constructor, destructor, `clone`, `close`, `timestamp`, `format`, `sampleRate`, `numberOfFrames`, `numberOfChannels`, `duration`, `allocationSize`, `copyTo`, `CopyConvert`, `CopyToInterleaved`, `CopyToPlanar`, `Trace`. These are the actions `AudioData` can perform.
    * Static helper functions: `MediaFormatToBlinkFormat`, `BlinkFormatToMediaFormat`, `CopyToInterleaved` (template), `CopyToPlanar` (template), `RemovePlanar`. These perform format conversions and data copying.
    * The `ArrayBufferContentsAsAudioExternalMemory` class.

3. **Deconstruct the Class Functionality:** Now, let's examine the key methods of the `AudioData` class:

    * **Constructor (`AudioData::AudioData(ScriptState*, AudioDataInit*, ExceptionState&)`):** This is crucial for understanding how `AudioData` objects are created. We see it takes `AudioDataInit` (likely from JavaScript) and performs several important checks and operations:
        * Validates input parameters (`numberOfChannels`, `numberOfFrames`, `sampleRate`).
        * Calculates the required buffer size.
        * Handles transferring the underlying `ArrayBuffer` (using `TransferArrayBufferForSpan`). This directly links it to JavaScript `ArrayBuffer` objects.
        * Creates a `media::AudioBuffer` to store the actual audio data. It tries to optimize by using external memory if the `ArrayBuffer` is aligned and transferable. Otherwise, it copies the data.

    * **`Create` (static):**  A simple factory method for creating `AudioData` instances.

    * **`clone`:** Creates a copy of the `AudioData` object.

    * **`close`:** Releases the underlying audio buffer, effectively making the `AudioData` unusable.

    * **Getter methods (`timestamp`, `format`, `sampleRate`, `numberOfFrames`, `numberOfChannels`, `duration`):** These provide access to the `AudioData`'s properties.

    * **`allocationSize`:**  Calculates the required size for copying a portion of the `AudioData` based on provided options. This is important for pre-allocating buffers in JavaScript.

    * **`copyTo`:** The core method for copying audio data into a destination buffer. It handles different scenarios:
        * Conversion between sample formats (`CopyConvert`).
        * Interleaving and deinterleaving.
        * Simple memory copying.

    * **`CopyConvert`, `CopyToInterleaved`, `CopyToPlanar`:** These are helper methods for `copyTo` that handle the specific data manipulation tasks. The template versions of `CopyToInterleaved` and `CopyToPlanar` handle the actual byte-level copying for different sample types.

4. **Analyze Relationships with JavaScript, HTML, and CSS:**

    * **JavaScript:** The connection is strong. The constructor takes an `AudioDataInit` object, which directly maps to a JavaScript object used to initialize `AudioData`. The `copyTo` method takes an `AllowSharedBufferSource`, which can be a JavaScript `ArrayBuffer` or `SharedArrayBuffer`. The getter methods expose properties that JavaScript can read. The `clone` operation creates a new JavaScript-accessible object.
    * **HTML:**  While this C++ code doesn't directly manipulate HTML elements, it's part of the rendering pipeline that *processes* media loaded via HTML elements (e.g., `<audio>`, `<video>`). It also supports the WebCodecs API, which is used in JavaScript and can be triggered by user interactions with HTML.
    * **CSS:**  This code has minimal direct relation to CSS. CSS controls the *presentation* of web content, while this code deals with the *data* of audio. Indirectly, CSS might influence user actions that lead to audio processing (e.g., clicking a button that starts playback).

5. **Identify Potential Errors and Usage Mistakes:**  The code includes error handling using `ExceptionState`. We can infer potential errors by looking at the checks performed in the constructor and `copyTo` methods:
    * Invalid input parameters in the constructor (e.g., `numberOfChannels` being zero).
    * Detached `ArrayBuffer`s.
    * Insufficient size of the destination buffer in `copyTo`.
    * Incorrect `planeIndex`.
    * `frameOffset` and `frameCount` exceeding bounds.

6. **Infer User Operations and Debugging:**  Consider how a user's actions might lead to this code being executed. The WebCodecs API is the primary entry point:

    * A web page uses JavaScript to create an `AudioDecoder` or `AudioEncoder`.
    * The decoder/encoder emits or consumes `AudioData` objects.
    * The JavaScript code might call methods like `copyTo` on an `AudioData` object to get the raw audio data.
    * Debugging would involve inspecting the properties of the `AudioData` object in the JavaScript console or setting breakpoints in the C++ code to examine the internal state.

7. **Structure the Output:** Finally, organize the findings into logical sections, as demonstrated in the example answer. Use clear headings and bullet points to make the information easy to read and understand. Provide concrete examples to illustrate the concepts. For logical reasoning, explicitly state the assumptions and the derived outputs.

By following these steps, we can systematically analyze the provided C++ code and extract the relevant information to answer the given prompt comprehensively.
好的，让我们详细分析一下 `blink/renderer/modules/webcodecs/audio_data.cc` 文件的功能。

**文件功能总览:**

`audio_data.cc` 文件是 Chromium Blink 引擎中 `WebCodecs API` 的一部分，它实现了 `AudioData` 接口。`AudioData` 接口在 Web 平台上表示原始音频数据块，允许开发者以高效的方式访问和操作音频样本。

**核心功能:**

1. **音频数据封装:**  `AudioData` 对象封装了底层的音频数据，这些数据可以来自不同的来源，例如：
   - 音频解码器（`AudioDecoder`）的输出。
   - 用户通过麦克风捕获的音频。
   - 使用 `AudioEncoder` 进行编码的音频。

2. **音频数据属性访问:**  `AudioData` 类提供了访问音频数据基本属性的方法：
   - `format()`: 获取音频样本的格式 (例如: `U8`, `S16`, `F32`，以及是否为 planar 格式)。
   - `sampleRate()`: 获取音频的采样率（每秒钟的样本数）。
   - `numberOfFrames()`: 获取音频数据中的帧数（每个通道的样本数）。
   - `numberOfChannels()`: 获取音频的通道数（例如：单声道、立体声）。
   - `duration()`: 获取音频数据的持续时间。
   - `timestamp()`: 获取与此音频数据关联的时间戳。

3. **音频数据复制:** 提供了将 `AudioData` 中的数据复制到 `ArrayBuffer` 或 `SharedArrayBuffer` 的功能 (`copyTo`)，允许 JavaScript 代码直接访问和操作音频样本。

4. **音频数据克隆:**  允许创建一个 `AudioData` 对象的副本 (`clone`)。

5. **音频数据关闭:**  提供了释放与 `AudioData` 对象关联的底层资源的方法 (`close`)。

6. **格式转换和数据排布:**  `copyTo` 方法支持在复制过程中进行音频格式的转换（例如，从 `S16` 转换为 `F32`）以及数据排布方式的转换（从 interleaved 到 planar，反之亦然）。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** `AudioData` 对象直接在 JavaScript 中被创建和使用。`WebCodecs API` 是一个 JavaScript API，开发者通过 JavaScript 代码来创建 `AudioDecoder`、`AudioEncoder`，并接收或发送 `AudioData` 对象。
    * **例子:**
      ```javascript
      const decoder = new AudioDecoder({
        output(audioData) {
          console.log("Received audio data:", audioData);
          const format = audioData.format;
          const sampleRate = audioData.sampleRate;
          const numberOfFrames = audioData.numberOfFrames;
          const numberOfChannels = audioData.numberOfChannels;
          const buffer = new ArrayBuffer(audioData.allocationSize());
          audioData.copyTo(buffer);
          // ... 对 buffer 中的音频数据进行处理 ...
          audioData.close();
        },
        error(e) {
          console.error("Decoder error:", e);
        }
      });

      decoder.configure({
        codec: 'opus',
        sampleRate: 48000,
        numberOfChannels: 2
      });

      // 将包含编码音频数据的 Uint8Array 传入解码器
      decoder.decode(new EncodedAudioChunk({
        timestamp: 0,
        data: encodedData // Uint8Array
      }));
      ```
* **HTML:**  `AudioData` 对象通常用于处理通过 HTML5 的媒体元素 (`<audio>`, `<video>`) 或 WebRTC 获取的音频流。例如，从 `<video>` 元素解码出的音频帧可能会表示为 `AudioData` 对象。
    * **例子:**  虽然 HTML 本身不直接操作 `AudioData`，但媒体元素的事件（如 `ended`）或通过 `MediaStreamTrack` 获取的音频数据可能会最终转化为 `AudioData` 对象进行处理。
* **CSS:** CSS 与 `AudioData` 没有直接的功能关系。CSS 主要负责网页的样式和布局，而 `AudioData` 涉及的是音频数据的处理。

**逻辑推理 (假设输入与输出):**

假设我们创建了一个 `AudioData` 对象，包含 1000 帧，采样率为 48000 Hz，双声道，格式为 `S16` (16位有符号整数)。

* **假设输入:**
    * `format`: `V8AudioSampleFormat::kS16`
    * `sampleRate`: 48000
    * `numberOfFrames`: 1000
    * `numberOfChannels`: 2
    * `data`: 一个包含 1000 * 2 * 2 字节数据的 `ArrayBuffer` (因为 `S16` 每个样本 2 字节)

* **逻辑推理 (基于代码中的转换和计算):**
    * `BlinkFormatToMediaFormat(init->format())` 会将 `V8AudioSampleFormat::kS16` 转换为 `media::SampleFormat::kSampleFormatS16`。
    * `media::SampleFormatToBytesPerChannel(media::SampleFormat::kSampleFormatS16)` 返回 2。
    * `total_bytes` 的计算为 `2 * 2 * 1000 = 4000` 字节。
    * 如果提供的 `data` `ArrayBuffer` 的大小小于 4000 字节，构造函数会抛出 `TypeError` 异常。
    * `allocationSize()` 方法在没有指定 `copy_to_options` 的情况下，会返回 4000。
    * `duration()` 方法会计算出持续时间：`1000 帧 / 48000 帧/秒 * 1,000,000 微秒/秒`，大约为 `20833` 微秒。

* **可能的输出 (方法调用结果):**
    * `audioData.format()` 返回一个表示 `S16` 的枚举值。
    * `audioData.sampleRate()` 返回 `48000`。
    * `audioData.numberOfFrames()` 返回 `1000`。
    * `audioData.numberOfChannels()` 返回 `2`。
    * `audioData.duration()` 返回一个接近 `20833` 的整数。
    * `audioData.allocationSize()` 返回 `4000`。

**用户或编程常见的使用错误：**

1. **创建 `AudioData` 时数据大小不匹配:**
   ```javascript
   const init = {
     format: 's16',
     sampleRate: 44100,
     numberOfFrames: 512,
     numberOfChannels: 1,
     data: new ArrayBuffer(100) // 错误：应该至少是 512 * 1 * 2 = 1024 字节
   };
   const audioData = new AudioData(init); // 将会抛出 TypeError
   ```
   **错误说明:**  用户提供的 `ArrayBuffer` 的大小不足以容纳指定帧数、通道数和格式的音频数据。

2. **`copyTo` 时目标缓冲区过小:**
   ```javascript
   const audioData = ...; // 假设 audioData 包含 4000 字节的数据
   const destinationBuffer = new ArrayBuffer(100);
   audioData.copyTo(destinationBuffer); // 将会抛出 RangeError
   ```
   **错误说明:** 目标 `ArrayBuffer` 的大小小于 `AudioData` 中需要复制的数据量。

3. **在 `AudioData` 关闭后尝试访问其属性或调用方法:**
   ```javascript
   const audioData = ...;
   audioData.close();
   console.log(audioData.format); // 尝试访问已释放的资源，可能导致错误或未定义行为
   audioData.copyTo(new ArrayBuffer(100)); // 将会抛出 DOMException: InvalidStateError
   ```
   **错误说明:**  用户在调用 `close()` 释放 `AudioData` 的底层资源后，仍然尝试使用该对象。

4. **`copyTo` 时 `planeIndex` 超出范围 (对于 planar 格式):**
   ```javascript
   const init = {
     format: 'f32-planar',
     sampleRate: 48000,
     numberOfFrames: 100,
     numberOfChannels: 2,
     data: new ArrayBuffer(100 * 4 * 2)
   };
   const audioData = new AudioData(init);
   const destinationBuffer = new ArrayBuffer(100 * 4);
   audioData.copyTo(destinationBuffer, { planeIndex: 2 }); // 错误：planeIndex 只能是 0 或 1
   ```
   **错误说明:**  对于 planar 格式的音频数据，`planeIndex` 必须在 `0` 到 `numberOfChannels - 1` 之间。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户正在使用一个网页，该网页使用了 `WebCodecs API` 来处理音频：

1. **用户操作 (触发音频处理):**
   - 用户点击了网页上的一个“开始录音”按钮。
   - 网页上的 JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` 获取了麦克风的音频流。
   - 音频流的 `MediaStreamTrack` 被传递给一个 `AudioEncoder` 进行编码。
   - 或者，用户正在观看一个视频，视频的音频轨道被解码器处理。

2. **JavaScript 代码调用 WebCodecs API:**
   - `AudioDecoder` 的 `output` 回调函数接收到一个 `AudioData` 对象，该对象包含了已解码的音频帧。
   - `AudioEncoder` 的输出可能是 `EncodedAudioChunk`，其中可能包含了创建新的 `AudioData` 的信息。

3. **JavaScript 代码尝试操作 `AudioData`:**
   - 开发者可能想要分析音频数据，例如计算音量或者进行频谱分析。
   - 开发者会调用 `audioData.allocationSize()` 来确定需要分配的缓冲区大小。
   - 开发者会调用 `audioData.copyTo(buffer)` 将音频数据复制到一个 `ArrayBuffer` 中。

4. **进入 `audio_data.cc` 的相关逻辑:**
   - 当 JavaScript 代码创建 `AudioData` 对象时 (例如，通过 `AudioDecoder` 输出)，`AudioData::Create` 方法会被调用。
   - 当 JavaScript 调用 `audioData.format`、`audioData.sampleRate` 等属性时，会调用 `AudioData` 类中对应的 getter 方法。
   - 当 JavaScript 调用 `audioData.copyTo(buffer, options)` 时，`AudioData::copyTo` 方法会被调用，该方法会根据 `options` 参数进行数据复制、格式转换等操作。

**调试线索:**

* **断点:** 在 `audio_data.cc` 中设置断点，例如在 `AudioData::Create`、`AudioData::copyTo` 等方法入口，可以观察 `AudioData` 对象的创建和数据复制过程中的参数和状态。
* **日志输出:** 在关键路径上添加 `DLOG` 或 `DVLOG` 输出，记录 `AudioData` 对象的属性值、分配的大小、复制的数据量等信息。
* **JavaScript 控制台:** 使用 `console.log` 输出 JavaScript 中 `AudioData` 对象的信息，例如 `format`、`sampleRate`、`allocationSize()` 等，与 C++ 端的日志进行对比。
* **内存检查工具:**  使用 AddressSanitizer (ASan) 或 MemorySanitizer (MSan) 等工具来检测内存访问错误，例如缓冲区溢出或使用已释放的内存。这对于调试 `copyTo` 操作中的错误非常有用。
* **WebCodecs API 的事件监听:** 监听 `AudioDecoder` 和 `AudioEncoder` 的 `error` 事件，以及其他相关事件，可以帮助定位 `AudioData` 对象创建或处理过程中发生的错误。

总而言之，`blink/renderer/modules/webcodecs/audio_data.cc` 文件是 WebCodecs API 中处理音频数据的核心组件，它连接了底层的音频数据表示和上层的 JavaScript API，使得开发者能够在 Web 平台上高效地操作音频。理解其功能和潜在的错误场景对于开发和调试 Web 音频应用至关重要。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/audio_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"

#include "base/compiler_specific.h"
#include "base/notreached.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "media/base/audio_buffer.h"
#include "media/base/audio_bus.h"
#include "media/base/limits.h"
#include "media/base/sample_format.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_copy_to_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_init.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"

namespace blink {

namespace {

std::optional<V8AudioSampleFormat> MediaFormatToBlinkFormat(
    media::SampleFormat media_format) {
  using FormatEnum = V8AudioSampleFormat::Enum;

  DCHECK(media_format != media::SampleFormat::kUnknownSampleFormat);

  switch (media_format) {
    case media::SampleFormat::kSampleFormatU8:
      return V8AudioSampleFormat(FormatEnum::kU8);

    case media::SampleFormat::kSampleFormatS16:
      return V8AudioSampleFormat(FormatEnum::kS16);

    case media::SampleFormat::kSampleFormatS24:
      // TODO(crbug.com/1231633): ffmpeg automatically converts kSampleFormatS24
      // to kSampleFormatS32, but we do not update our labelling. It's ok to
      // treat the kSampleFormatS24 as kSampleFormatS32 until we update the
      // labelling, since our code already treats S24 as S32.
      [[fallthrough]];
    case media::SampleFormat::kSampleFormatS32:
      return V8AudioSampleFormat(FormatEnum::kS32);

    case media::SampleFormat::kSampleFormatF32:
      return V8AudioSampleFormat(FormatEnum::kF32);

    case media::SampleFormat::kSampleFormatPlanarU8:
      return V8AudioSampleFormat(FormatEnum::kU8Planar);

    case media::SampleFormat::kSampleFormatPlanarS16:
      return V8AudioSampleFormat(FormatEnum::kS16Planar);

    case media::SampleFormat::kSampleFormatPlanarS32:
      return V8AudioSampleFormat(FormatEnum::kS32Planar);

    case media::SampleFormat::kSampleFormatPlanarF32:
      return V8AudioSampleFormat(FormatEnum::kF32Planar);

    case media::SampleFormat::kSampleFormatAc3:
    case media::SampleFormat::kSampleFormatEac3:
    case media::SampleFormat::kSampleFormatMpegHAudio:
    case media::SampleFormat::kUnknownSampleFormat:
    case media::SampleFormat::kSampleFormatDts:
    case media::SampleFormat::kSampleFormatDtsxP2:
    case media::SampleFormat::kSampleFormatIECDts:
    case media::SampleFormat::kSampleFormatDtse:
      return std::nullopt;
  }
}

media::SampleFormat BlinkFormatToMediaFormat(V8AudioSampleFormat blink_format) {
  using FormatEnum = V8AudioSampleFormat::Enum;

  DCHECK(!blink_format.IsEmpty());

  switch (blink_format.AsEnum()) {
    case FormatEnum::kU8:
      return media::SampleFormat::kSampleFormatU8;

    case FormatEnum::kS16:
      return media::SampleFormat::kSampleFormatS16;

    case FormatEnum::kS32:
      return media::SampleFormat::kSampleFormatS32;

    case FormatEnum::kF32:
      return media::SampleFormat::kSampleFormatF32;

    case FormatEnum::kU8Planar:
      return media::SampleFormat::kSampleFormatPlanarU8;

    case FormatEnum::kS16Planar:
      return media::SampleFormat::kSampleFormatPlanarS16;

    case FormatEnum::kS32Planar:
      return media::SampleFormat::kSampleFormatPlanarS32;

    case FormatEnum::kF32Planar:
      return media::SampleFormat::kSampleFormatPlanarF32;
  }
}

template <typename SampleType>
void CopyToInterleaved(uint8_t* dest_data,
                       const std::vector<uint8_t*>& src_channels_data,
                       const int frame_offset,
                       const int frames_to_copy) {
  const int channels = static_cast<int>(src_channels_data.size());

  SampleType* dest = reinterpret_cast<SampleType*>(dest_data);
  for (int ch = 0; ch < channels; ++ch) {
    const SampleType* src_start =
        reinterpret_cast<SampleType*>(src_channels_data[ch]) + frame_offset;
    for (int i = 0; i < frames_to_copy; ++i) {
      dest[i * channels + ch] = src_start[i];
    }
  }
}

template <typename SampleType>
void CopyToPlanar(uint8_t* dest_data,
                  const uint8_t* src_data,
                  const int src_channel_count,
                  const int dest_channel_index,
                  const int frame_offset,
                  const int frames_to_copy,
                  ExceptionState& exception_state) {
  SampleType* dest = reinterpret_cast<SampleType*>(dest_data);

  uint32_t offset_in_samples = 0;
  bool overflow = false;
  if (!base::CheckMul(frame_offset, src_channel_count)
           .AssignIfValid(&offset_in_samples)) {
    overflow = true;
    return;
  }

  // Check for potential overflows in the index calculation of the for-loop
  // below.
  if (overflow ||
      !base::CheckMul(frames_to_copy, src_channel_count).IsValid()) {
    exception_state.ThrowTypeError(String::Format(
        "Provided options cause overflow when calculating offset."));
    return;
  }

  const SampleType* src_start =
      reinterpret_cast<const SampleType*>(src_data) + offset_in_samples;
  for (int i = 0; i < frames_to_copy; ++i) {
    dest[i] = src_start[i * src_channel_count + dest_channel_index];
  }
}

media::SampleFormat RemovePlanar(media::SampleFormat format) {
  switch (format) {
    case media::kSampleFormatPlanarU8:
    case media::kSampleFormatU8:
      return media::kSampleFormatU8;

    case media::kSampleFormatPlanarS16:
    case media::kSampleFormatS16:
      return media::kSampleFormatS16;

    case media::kSampleFormatPlanarS32:
    case media::kSampleFormatS32:
      return media::kSampleFormatS32;

    case media::kSampleFormatPlanarF32:
    case media::kSampleFormatF32:
      return media::kSampleFormatF32;

    default:
      NOTREACHED();
  }
}

class ArrayBufferContentsAsAudioExternalMemory
    : public media::AudioBuffer::ExternalMemory {
 public:
  explicit ArrayBufferContentsAsAudioExternalMemory(
      ArrayBufferContents contents,
      base::span<uint8_t> span)
      : media::AudioBuffer::ExternalMemory(span),
        contents_(std::move(contents)) {
    // Check that `span` refers to the memory inside `contents`.
    auto* contents_data = static_cast<uint8_t*>(contents_.Data());
    CHECK_GE(span.data(), contents_data);
    CHECK_LE(span.data() + span.size(), contents_data + contents_.DataLength());
  }

 private:
  ArrayBufferContents contents_;
};

}  // namespace

// static
AudioData* AudioData::Create(ScriptState* script_state,
                             AudioDataInit* init,
                             ExceptionState& exception_state) {
  return MakeGarbageCollected<AudioData>(script_state, init, exception_state);
}

AudioData::AudioData(ScriptState* script_state,
                     AudioDataInit* init,
                     ExceptionState& exception_state)
    : format_(std::nullopt), timestamp_(init->timestamp()) {
  media::SampleFormat media_format = BlinkFormatToMediaFormat(init->format());

  if (init->numberOfChannels() == 0) {
    exception_state.ThrowTypeError("numberOfChannels must be greater than 0.");
    return;
  }

  if (init->numberOfChannels() > media::limits::kMaxChannels) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        String::Format("numberOfChannels exceeds supported implementation "
                       "limits: %u vs %u.",
                       init->numberOfChannels(), media::limits::kMaxChannels));
    return;
  }

  if (init->numberOfFrames() == 0) {
    exception_state.ThrowTypeError("numberOfFrames must be greater than 0.");
    return;
  }

  uint32_t bytes_per_sample =
      media::SampleFormatToBytesPerChannel(media_format);

  uint32_t total_bytes;
  if (!base::CheckMul(bytes_per_sample, base::CheckMul(init->numberOfChannels(),
                                                       init->numberOfFrames()))
           .AssignIfValid(&total_bytes)) {
    exception_state.ThrowTypeError(
        "AudioData allocation size exceeds implementation limits.");
    return;
  }

  auto array_span = AsSpan<uint8_t>(init->data());
  if (!array_span.data()) {
    exception_state.ThrowTypeError("data is detached.");
    return;
  }
  if (total_bytes > array_span.size()) {
    exception_state.ThrowTypeError(
        String::Format("data is too small: needs %u bytes, received %zu.",
                       total_bytes, array_span.size()));
    return;
  }

  // Try if we can transfer `init.data` into `buffer_contents`.
  // We do to make the ctor behave in a spec compliant way regarding transfers,
  // even though we copy the span contents later anyway.
  // TODO(crbug.com/1446808) Modify `media::AudioBuffer` to allow moving
  // `buffer_contents` into it without copying.
  auto* isolate = script_state->GetIsolate();
  auto buffer_contents = TransferArrayBufferForSpan(
      init->transfer(), array_span, exception_state, isolate);
  if (exception_state.HadException()) {
    return;
  }

  int sample_rate = base::saturated_cast<int>(init->sampleRate());
  if (sample_rate < media::limits::kMinSampleRate ||
      sample_rate > media::limits::kMaxSampleRate) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        String::Format("sampleRate is outside of supported implementation "
                       "limits: need between %u and %u, received %d.",
                       media::limits::kMinSampleRate,
                       media::limits::kMaxSampleRate, sample_rate));
    return;
  }

  format_ = init->format();
  auto channel_layout =
      init->numberOfChannels() > 8
          // GuesschannelLayout() doesn't know how to guess above 8 channels.
          ? media::CHANNEL_LAYOUT_DISCRETE
          : media::GuessChannelLayout(init->numberOfChannels());

  bool sample_aligned = base::IsAligned(array_span.data(), bytes_per_sample);
  if (buffer_contents.IsValid() && sample_aligned) {
    // The buffer is properly aligned and allowed to be transferred,
    // wrap it as external-memory object and move without a copy.
    auto external_memory =
        std::make_unique<ArrayBufferContentsAsAudioExternalMemory>(
            std::move(buffer_contents), array_span);
    data_ = media::AudioBuffer::CreateFromExternalMemory(
        media_format, channel_layout, init->numberOfChannels(), sample_rate,
        init->numberOfFrames(), base::Microseconds(timestamp_),
        std::move(external_memory));
    CHECK(data_);
    return;
  }

  std::vector<const uint8_t*> channel_ptrs;
  if (media::IsInterleaved(media_format)) {
    // Interleaved data can directly added.
    channel_ptrs.push_back(array_span.data());
  } else {
    // Planar data needs one pointer per channel.
    channel_ptrs.resize(init->numberOfChannels());

    uint32_t plane_size_in_bytes =
        init->numberOfFrames() *
        media::SampleFormatToBytesPerChannel(media_format);

    const uint8_t* plane_start =
        reinterpret_cast<const uint8_t*>(array_span.data());

    for (unsigned ch = 0; ch < init->numberOfChannels(); ++ch) {
      channel_ptrs[ch] = plane_start + ch * plane_size_in_bytes;
    }
  }

  data_ = media::AudioBuffer::CopyFrom(
      media_format, channel_layout, init->numberOfChannels(), sample_rate,
      init->numberOfFrames(), channel_ptrs.data(),
      base::Microseconds(timestamp_));
  CHECK(data_);
}

AudioData::AudioData(scoped_refptr<media::AudioBuffer> buffer)
    : data_(std::move(buffer)),
      timestamp_(data_->timestamp().InMicroseconds()) {
  media::SampleFormat media_format = data_->sample_format();

  DCHECK(!media::IsBitstream(media_format));

  format_ = MediaFormatToBlinkFormat(media_format);

  if (!format_.has_value())
    close();
}

AudioData::~AudioData() = default;

AudioData* AudioData::clone(ExceptionState& exception_state) {
  if (!data_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot clone closed AudioData.");
    return nullptr;
  }

  return MakeGarbageCollected<AudioData>(data_);
}

void AudioData::close() {
  data_.reset();
  data_as_f32_bus_.reset();
  format_ = std::nullopt;
}

int64_t AudioData::timestamp() const {
  return timestamp_;
}

std::optional<V8AudioSampleFormat> AudioData::format() const {
  return format_;
}

float AudioData::sampleRate() const {
  if (!data_)
    return 0;

  return data_->sample_rate();
}

uint32_t AudioData::numberOfFrames() const {
  if (!data_)
    return 0;

  return data_->frame_count();
}

uint32_t AudioData::numberOfChannels() const {
  if (!data_)
    return 0;

  return data_->channel_count();
}

uint64_t AudioData::duration() const {
  if (!data_)
    return 0;

  return data_->duration().InMicroseconds();
}

uint32_t AudioData::allocationSize(AudioDataCopyToOptions* copy_to_options,
                                   ExceptionState& exception_state) {
  if (!data_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "AudioData is closed.");
    return 0;
  }

  auto format = copy_to_options->hasFormat()
                    ? BlinkFormatToMediaFormat(copy_to_options->format())
                    : data_->sample_format();

  // Interleaved formats only have one plane, despite many channels.
  uint32_t max_plane_index =
      media::IsInterleaved(format) ? 0 : data_->channel_count() - 1;

  // The channel isn't used in calculating the allocationSize, but we still
  // validate it here. This prevents a failed copyTo() call following a
  // successful allocationSize() call.
  if (copy_to_options->planeIndex() > max_plane_index) {
    exception_state.ThrowRangeError("Invalid planeIndex.");
    return 0;
  }

  const uint32_t offset = copy_to_options->frameOffset();
  const uint32_t total_frames = static_cast<uint32_t>(data_->frame_count());

  if (offset >= total_frames) {
    exception_state.ThrowRangeError(String::Format(
        "Frame offset exceeds total frames (%u >= %u).", offset, total_frames));
    return 0;
  }

  const uint32_t available_frames = total_frames - offset;
  const uint32_t frame_count = copy_to_options->hasFrameCount()
                                   ? copy_to_options->frameCount()
                                   : available_frames;

  if (frame_count > available_frames) {
    exception_state.ThrowRangeError(
        String::Format("Frame count exceeds available_frames frames (%u > %u).",
                       frame_count, available_frames));
    return 0;
  }

  uint32_t sample_count = frame_count;

  // For interleaved formats, frames are stored as blocks of samples. Each block
  // has 1 sample per channel, and |sample_count| needs to be adjusted.
  bool overflow = false;
  if (media::IsInterleaved(format) &&
      !base::CheckMul(frame_count, data_->channel_count())
           .AssignIfValid(&sample_count)) {
    overflow = true;
  }

  uint32_t allocation_size;
  if (overflow || !base::CheckMul(sample_count,
                                  media::SampleFormatToBytesPerChannel(format))
                       .AssignIfValid(&allocation_size)) {
    exception_state.ThrowTypeError(String::Format(
        "Provided options cause overflow when calculating allocation size."));
    return 0;
  }

  return allocation_size;
}

void AudioData::copyTo(const AllowSharedBufferSource* destination,
                       AudioDataCopyToOptions* copy_to_options,
                       ExceptionState& exception_state) {
  if (!data_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot copy closed AudioData.");
    return;
  }

  uint32_t copy_size_in_bytes =
      allocationSize(copy_to_options, exception_state);

  if (exception_state.HadException())
    return;

  // Validate destination buffer.
  auto dest_wrapper = AsSpan<uint8_t>(destination);
  if (!dest_wrapper.data()) {
    exception_state.ThrowRangeError("destination is detached.");
    return;
  }
  if (dest_wrapper.size() < static_cast<size_t>(copy_size_in_bytes)) {
    exception_state.ThrowRangeError("destination is not large enough.");
    return;
  }

  const auto dest_format =
      copy_to_options->hasFormat()
          ? BlinkFormatToMediaFormat(copy_to_options->format())
          : data_->sample_format();

  const auto src_format = data_->sample_format();

  // Ignore (de)interleaving, and verify whether we need to convert between
  // sample types.
  const bool needs_conversion =
      RemovePlanar(src_format) != RemovePlanar(dest_format);

  if (needs_conversion) {
    CopyConvert(dest_wrapper, copy_to_options);
    return;
  }

  // Interleave data.
  if (!media::IsInterleaved(src_format) && media::IsInterleaved(dest_format)) {
    CopyToInterleaved(dest_wrapper, copy_to_options);
    return;
  }

  // Deinterleave data.
  if (media::IsInterleaved(src_format) && !media::IsInterleaved(dest_format)) {
    CopyToPlanar(dest_wrapper, copy_to_options, exception_state);
    return;
  }

  // Simple copy, without conversion or (de)interleaving.
  CHECK_LE(copy_to_options->planeIndex(),
           static_cast<uint32_t>(data_->channel_count()));

  size_t src_data_size = 0;
  if (media::IsInterleaved(src_format)) {
    src_data_size = data_->data_size();
  } else {
    src_data_size =
        media::SampleFormatToBytesPerChannel(src_format) * data_->frame_count();
  }

  // Copy data.
  uint32_t offset_in_samples = copy_to_options->frameOffset();

  bool overflow = false;
  // Interleaved frames have 1 sample per channel for each block of samples.
  if (media::IsInterleaved(dest_format) &&
      !base::CheckMul(copy_to_options->frameOffset(), data_->channel_count())
           .AssignIfValid(&offset_in_samples)) {
    overflow = true;
  }

  uint32_t offset_in_bytes = 0;
  if (overflow ||
      !base::CheckMul(offset_in_samples,
                      media::SampleFormatToBytesPerChannel(dest_format))
           .AssignIfValid(&offset_in_bytes)) {
    exception_state.ThrowTypeError(String::Format(
        "Provided options cause overflow when calculating offset."));
    return;
  }

  const uint8_t* src_data =
      data_->channel_data()[copy_to_options->planeIndex()];
  const uint8_t* data_start = src_data + offset_in_bytes;
  CHECK_LE(data_start + copy_size_in_bytes, src_data + src_data_size);
  memcpy(dest_wrapper.data(), data_start, copy_size_in_bytes);
}

void AudioData::CopyConvert(base::span<uint8_t> dest,
                            AudioDataCopyToOptions* copy_to_options) {
  const media::SampleFormat dest_format =
      BlinkFormatToMediaFormat(copy_to_options->format());

  // We should only convert when needed.
  CHECK_NE(data_->sample_format(), dest_format);

  // Convert the entire AudioBuffer at once and save it for future copy calls.
  if (!data_as_f32_bus_) {
    data_as_f32_bus_ = media::AudioBuffer::WrapOrCopyToAudioBus(data_);
  }

  // An invalid offset or too many requested frames should have already been
  // caught in allocationSize().
  const uint32_t offset = copy_to_options->frameOffset();
  const uint32_t total_frames =
      static_cast<uint32_t>(data_as_f32_bus_->frames());
  CHECK_LT(offset, total_frames);

  const uint32_t available_frames = total_frames - offset;
  const uint32_t frame_count = copy_to_options->hasFrameCount()
                                   ? copy_to_options->frameCount()
                                   : available_frames;
  CHECK_LE(frame_count, available_frames);

  if (media::IsInterleaved(dest_format)) {
    CHECK_EQ(0u, copy_to_options->planeIndex());

    switch (dest_format) {
      case media::kSampleFormatU8: {
        data_as_f32_bus_
            ->ToInterleavedPartial<media::UnsignedInt8SampleTypeTraits>(
                offset, frame_count, dest.data());
        return;
      }

      case media::kSampleFormatS16: {
        int16_t* dest_data = reinterpret_cast<int16_t*>(dest.data());

        data_as_f32_bus_
            ->ToInterleavedPartial<media::SignedInt16SampleTypeTraits>(
                offset, frame_count, dest_data);
        return;
      }

      case media::kSampleFormatS32: {
        int32_t* dest_data = reinterpret_cast<int32_t*>(dest.data());

        data_as_f32_bus_
            ->ToInterleavedPartial<media::SignedInt32SampleTypeTraits>(
                offset, frame_count, dest_data);
        return;
      }

      case media::kSampleFormatF32: {
        float* dest_data = reinterpret_cast<float*>(dest.data());

        data_as_f32_bus_->ToInterleavedPartial<media::Float32SampleTypeTraits>(
            offset, frame_count, dest_data);
        return;
      }

      default:
        NOTREACHED();
    }
  }

  // Planar conversion.
  const int channel = copy_to_options->planeIndex();

  CHECK_LT(channel, data_as_f32_bus_->channels());
  float* src_data = data_as_f32_bus_->channel(channel);
  float* offset_src_data = src_data + offset;
  CHECK_LE(offset_src_data + frame_count,
           src_data + data_as_f32_bus_->frames());
  switch (dest_format) {
    case media::kSampleFormatPlanarU8: {
      uint8_t* dest_data = dest.data();
      for (uint32_t i = 0; i < frame_count; ++i) {
        dest_data[i] =
            media::UnsignedInt8SampleTypeTraits::FromFloat(offset_src_data[i]);
      }
      return;
    }
    case media::kSampleFormatPlanarS16: {
      int16_t* dest_data = reinterpret_cast<int16_t*>(dest.data());
      for (uint32_t i = 0; i < frame_count; ++i) {
        dest_data[i] =
            media::SignedInt16SampleTypeTraits::FromFloat(offset_src_data[i]);
      }
      return;
    }
    case media::kSampleFormatPlanarS32: {
      int32_t* dest_data = reinterpret_cast<int32_t*>(dest.data());
      for (uint32_t i = 0; i < frame_count; ++i) {
        dest_data[i] =
            media::SignedInt32SampleTypeTraits::FromFloat(offset_src_data[i]);
      }
      return;
    }
    case media::kSampleFormatPlanarF32: {
      int32_t* dest_data = reinterpret_cast<int32_t*>(dest.data());
      CHECK_LE(offset_src_data + frame_count,
               src_data + data_as_f32_bus_->frames());
      memcpy(dest_data, offset_src_data, sizeof(float) * frame_count);
      return;
    }
    default:
      NOTREACHED();
  }
}

void AudioData::CopyToInterleaved(base::span<uint8_t> dest,
                                  AudioDataCopyToOptions* copy_to_options) {
  const media::SampleFormat src_format = data_->sample_format();
  const media::SampleFormat dest_format =
      BlinkFormatToMediaFormat(copy_to_options->format());
  CHECK_EQ(RemovePlanar(src_format), RemovePlanar(dest_format));
  CHECK(!media::IsInterleaved(src_format));
  CHECK(media::IsInterleaved(dest_format));
  CHECK_EQ(0u, copy_to_options->planeIndex());

  const int frame_offset = copy_to_options->frameOffset();
  const int available_frames = data_->frame_count() - frame_offset;
  const int frames_to_copy = copy_to_options->hasFrameCount()
                                 ? copy_to_options->frameCount()
                                 : available_frames;
  const auto& channel_data = data_->channel_data();

  CHECK_LE(frame_offset + frames_to_copy, data_->frame_count());

  switch (dest_format) {
    case media::kSampleFormatU8:
      ::blink::CopyToInterleaved<uint8_t>(dest.data(), channel_data,
                                          frame_offset, frames_to_copy);
      return;
    case media::kSampleFormatS16:
      ::blink::CopyToInterleaved<int16_t>(dest.data(), channel_data,
                                          frame_offset, frames_to_copy);
      return;
    case media::kSampleFormatS32:
      ::blink::CopyToInterleaved<int32_t>(dest.data(), channel_data,
                                          frame_offset, frames_to_copy);
      return;
    case media::kSampleFormatF32:
      ::blink::CopyToInterleaved<float>(dest.data(), channel_data, frame_offset,
                                        frames_to_copy);
      return;
    default:
      NOTREACHED();
  }
}

void AudioData::CopyToPlanar(base::span<uint8_t> dest,
                             AudioDataCopyToOptions* copy_to_options,
                             ExceptionState& exception_state) {
  const media::SampleFormat src_format = data_->sample_format();
  const media::SampleFormat dest_format =
      BlinkFormatToMediaFormat(copy_to_options->format());
  CHECK_EQ(RemovePlanar(src_format), RemovePlanar(dest_format));
  CHECK(media::IsInterleaved(src_format));
  CHECK(!media::IsInterleaved(dest_format));

  const int frame_offset = copy_to_options->frameOffset();
  const int available_frames = data_->frame_count() - frame_offset;
  const int frames_to_copy = copy_to_options->hasFrameCount()
                                 ? copy_to_options->frameCount()
                                 : available_frames;
  const int channels = data_->channel_count();
  const int channel_index = copy_to_options->planeIndex();

  // Interleaved data could all be in the same plane.
  CHECK_EQ(1u, data_->channel_data().size());
  const uint8_t* src_data = data_->channel_data()[0];

  CHECK_LE(frame_offset + frames_to_copy, data_->frame_count());

  switch (dest_format) {
    case media::kSampleFormatPlanarU8:
      ::blink::CopyToPlanar<uint8_t>(dest.data(), src_data, channels,
                                     channel_index, frame_offset,
                                     frames_to_copy, exception_state);
      return;
    case media::kSampleFormatPlanarS16:
      ::blink::CopyToPlanar<int16_t>(dest.data(), src_data, channels,
                                     channel_index, frame_offset,
                                     frames_to_copy, exception_state);
      return;
    case media::kSampleFormatPlanarS32:
      ::blink::CopyToPlanar<int32_t>(dest.data(), src_data, channels,
                                     channel_index, frame_offset,
                                     frames_to_copy, exception_state);
      return;
    case media::kSampleFormatPlanarF32:
      ::blink::CopyToPlanar<float>(dest.data(), src_data, channels,
                                   channel_index, frame_offset, frames_to_copy,
                                   exception_state);
      return;
    default:
      NOTREACHED();
  }
}

void AudioData::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
```