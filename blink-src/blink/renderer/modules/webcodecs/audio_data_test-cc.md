Response:
The user wants me to analyze the C++ source code file `audio_data_test.cc` from the Chromium Blink engine. Specifically, they want me to:

1. **Summarize the file's functionality.**
2. **Explain its relationship to JavaScript, HTML, and CSS**, providing examples if any.
3. **Describe any logical reasoning** within the code, including hypothetical inputs and outputs.
4. **Identify common usage errors**, illustrating with examples.
5. **Explain how a user's actions might lead to this code being executed** (debugging context).
6. **Provide a high-level summary of the file's purpose** as this is part 1 of 2.

Let's break down the code to understand its functionality and then address each of the user's points.

**Code Analysis:**

- The file includes headers for `audio_data.h`, standard library components, `media/base` components (like `audio_sample_types.h` and `test_helpers.h`), Google Test (`gtest`), and Blink-specific headers related to bindings (V8), typed arrays, WebAudio, and testing.
- The code defines a namespace `blink` and an anonymous namespace within it.
- It defines constants for default test values like timestamp, number of channels/frames, sample rate, and duration.
- It declares a test fixture class `AudioDataTest` inheriting from `testing::Test`.
- The test fixture includes helper methods like `VerifyPlanarData`, `CreateDefaultData`, `CreateCustomData`, `CreateDefaultAudioDataInit`, `CreateDefaultAudioData`, `CreateCopyToOptions`, and `VerifyAllocationSize`. These methods are used to set up and verify test scenarios.
- Several `TEST_F` macros define individual test cases. These tests cover various aspects of the `AudioData` class:
    - Construction from `media::AudioBuffer`.
    - Construction from `AudioDataInit`.
    - Handling high channel counts.
    - Calculating allocation size.
    - Copying data using `copyTo`.
    - Transferring `ArrayBuffer` data.
    - Handling unaligned `ArrayBuffer` transfers.
    - Copying with offsets and partial frames.
    - Handling interleaved audio data.
- The code also defines a set of traits structures (`U8Traits`, `S16Traits`, `S32Traits`, `F32Traits`) and a template structure `ConversionConfig` to facilitate testing of audio format conversions.
- Another template test fixture `AudioDataConversionTest` is defined for testing audio data format conversions (planar to planar, interleaved to planar, planar to interleaved, interleaved to interleaved).

**Addressing User's Points:**

1. **Functionality:** This file contains unit tests for the `AudioData` class in the Chromium Blink engine. It tests the creation, manipulation, and data transfer capabilities of `AudioData` objects. It specifically focuses on testing different ways of constructing `AudioData`, calculating memory allocation sizes, copying data to different buffers with various options (offset, frame count), and handling different audio sample formats (planar and interleaved). The latter part of the file extensively tests conversions between various audio formats.

2. **Relationship to JavaScript, HTML, CSS:**
    - **JavaScript:** This C++ code directly supports the WebCodecs API in JavaScript. The `AudioData` class is likely exposed to JavaScript, allowing developers to create, manipulate, and access audio data. The tests use V8 bindings, which are the mechanism for exposing C++ functionality to JavaScript. For instance, a JavaScript developer might use the `AudioData` constructor with an `ArrayBuffer` or create it in other ways supported by the WebCodecs API.
        ```javascript
        // Example of creating AudioData in JavaScript
        const audioData = new AudioData({
          format: 'f32-planar',
          sampleRate: 48000,
          numberOfChannels: 2,
          numberOfFrames: 1024,
          timestamp: 0,
          data: audioBuffer // an ArrayBuffer containing audio data
        });

        // Example of copying data from AudioData
        const outputBuffer = new Float32Array(audioData.allocationSize({ planeIndex: 0 }));
        audioData.copyTo(outputBuffer.buffer, { planeIndex: 0 });
        ```
    - **HTML:**  While this specific C++ code doesn't directly interact with HTML, the WebCodecs API it supports is used in web applications built with HTML. For example, a `<video>` or `<audio>` element's media stream might be processed using WebCodecs, indirectly involving this code.
    - **CSS:** This C++ code has no direct relationship with CSS, which is for styling web pages.

3. **Logical Reasoning:** The code uses logical reasoning within its test cases to verify the behavior of the `AudioData` class.
    - **Assumption:** If `AudioData` is constructed with `kFrames` frames, copying all frames should result in a buffer of the expected size and content.
    - **Input:** Construct an `AudioData` object with default settings. Create a destination `ArrayBuffer` of size `kFrames * sizeof(float)`. Call `copyTo` without specifying an offset or frame count.
    - **Output:** The `allocationSize` should return the size of the destination buffer, and the content of the destination buffer after the copy should match the source data, verified by `VerifyPlanarData`.
    - **Assumption:** If an offset is specified in `copyTo`, the copied data should start from that offset in the source.
    - **Input:** Construct an `AudioData` object. Call `copyTo` with an offset of `kOffset`.
    - **Output:** The copied data should start from the `kOffset`-th frame of the source, verified by checking the starting value in the destination buffer.

4. **Common Usage Errors:**
    - **Destination buffer too small:** If the `copyTo` method is called with a destination buffer that is smaller than the amount of data being copied, it should throw an exception. The test `CopyTo_DestinationTooSmall` verifies this.
        ```javascript
        // JavaScript example leading to this error
        const audioData = new AudioData({...});
        const smallBuffer = new Float32Array(audioData.numberOfFrames - 1);
        // This copy operation will likely throw an error in the C++ backend
        audioData.copyTo(smallBuffer.buffer, { planeIndex: 0 });
        ```
    - **Invalid plane index:** When dealing with planar audio, providing an invalid `planeIndex` to `copyTo` or `allocationSize` will result in an error. The test `AllocationSize` covers this.
        ```javascript
        // JavaScript example
        const audioData = new AudioData({ format: 'f32-planar', numberOfChannels: 2, ... });
        // Accessing a non-existent plane
        audioData.copyTo(outputBuffer.buffer, { planeIndex: 2 }); // Error!
        ```
    - **Offset or count exceeding bounds:** Specifying an offset or count in `copyTo` that goes beyond the available frames will cause an error. The `AllocationSize` test includes checks for this.
        ```javascript
        // JavaScript example
        const audioData = new AudioData({ numberOfFrames: 10, ... });
        // Trying to copy beyond the available frames
        audioData.copyTo(outputBuffer.buffer, { frameOffset: 10 }); // Error!
        audioData.copyTo(outputBuffer.buffer, { frameCount: 11 }); // Error!
        ```
    - **Transferring unaligned buffers:**  When attempting to transfer the underlying buffer of an `AudioData` object, the buffer needs to be sample-aligned. If it's not, a copy will occur instead of a transfer. The `FailToTransferUnAlignedBuffer` test demonstrates this scenario. A user might unintentionally create a `DataView` with an offset, leading to this.

5. **User Operations Leading to This Code:** A user interacting with a website or application that uses the WebCodecs API can trigger the execution of this code. Here's a possible sequence:
    1. The user interacts with a web page that uses JavaScript to capture audio from a microphone or load an audio file.
    2. The JavaScript code uses the `AudioEncoder` or `AudioDecoder` interfaces from the WebCodecs API to process the audio.
    3. As part of the encoding or decoding process, `AudioData` objects are created to represent the audio samples. This might involve constructing `AudioData` from `ArrayBuffer`s or `media::AudioBuffer`s.
    4. The JavaScript code might need to access or manipulate the raw audio data within the `AudioData` object, potentially using the `copyTo` method. This is where the code in `audio_data_test.cc` (specifically the tested methods of the `AudioData` class) would be executed in the browser's rendering engine.
    5. If the JavaScript code makes mistakes, such as providing an incorrect buffer size or plane index to `copyTo`, the error handling logic within the C++ `AudioData` implementation (which is being tested here) would be invoked.

6. **Summary of Functionality (Part 1):** This part of the `audio_data_test.cc` file focuses on testing the fundamental functionalities of the `AudioData` class. It verifies its construction from different sources, its ability to calculate memory allocation sizes for copying, and its core data copying mechanisms, including handling offsets, partial frames, and different memory layouts (planar and interleaved). It also includes tests for transferring and handling unaligned ArrayBuffers. The later tests introduce more complex scenarios involving audio format conversions.

这是文件 `blink/renderer/modules/webcodecs/audio_data_test.cc` 的第一部分，主要功能是**对 `AudioData` 类进行单元测试**。`AudioData` 类是 Chromium Blink 引擎中 WebCodecs API 的一部分，用于表示和操作原始音频数据。

**主要功能归纳：**

1. **`AudioData` 对象的创建和初始化测试:**
   - 测试从 `media::AudioBuffer` 对象创建 `AudioData`。
   - 测试从 `AudioDataInit` 字典创建 `AudioData`，涵盖了各种参数，如数据、时间戳、声道数、帧数、采样率和格式。
   - 特别测试了高声道数的情况。

2. **内存分配大小计算测试 (`allocationSize`):**
   - 测试在不同参数下 (`planeIndex`, `frameOffset`, `frameCount`) 计算 `AudioData` 中指定平面的内存分配大小。
   - 涵盖了正常情况、指定偏移量和帧数的情况，以及错误情况（无效的索引、偏移量过大、帧数过大）。

3. **数据复制测试 (`copyTo`):**
   - 测试将 `AudioData` 中的数据复制到 `AllowSharedBufferSource` (通常是 `ArrayBuffer`)。
   - 测试了完整帧复制、指定平面索引复制、指定偏移量复制、复制部分帧以及指定偏移量和部分帧的复制。

4. **数据转移测试 (`TransferBuffer` 和 `FailToTransferUnAlignedBuffer`):**
   - 测试当 `AudioData` 使用的 `ArrayBuffer` 可以安全转移所有权时（例如，sample-aligned），数据是否被转移（而不是复制）。
   - 测试当 `ArrayBuffer` 无法安全转移所有权时（例如，不是 sample-aligned），数据是否被复制。

5. **交错 (Interleaved) 音频数据测试:**
   - 测试 `AudioData` 如何处理交错格式的音频数据。
   - 测试了在交错格式下 `allocationSize` 的行为，以及数据复制的正确性。

6. **音频格式转换测试 (在第二部分开始):**
   - 设置了用于测试不同音频格式之间转换的框架，包括 planar 和 interleaved 格式之间的转换，以及不同位深和符号类型的格式之间的转换 (例如 u8, s16, f32)。

**与 JavaScript, HTML, CSS 的关系：**

`AudioData` 类是 WebCodecs API 的一部分，这个 API 暴露给 JavaScript。因此，这个 C++ 测试文件间接地与 JavaScript 有着密切的关系。

* **JavaScript:**  JavaScript 代码可以使用 WebCodecs API 中的 `AudioData` 接口来创建和操作音频数据。例如：
   ```javascript
   // 创建一个 AudioData 对象
   const audioData = new AudioData({
       format: 'f32-planar',
       sampleRate: 48000,
       numberOfChannels: 2,
       numberOfFrames: 1024,
       timestamp: 0,
       data: audioBuffer // 一个包含音频数据的 ArrayBuffer
   });

   // 从 AudioData 对象复制数据
   const outputBuffer = new Float32Array(audioData.allocationSize({ planeIndex: 0 }));
   audioData.copyTo(outputBuffer.buffer, { planeIndex: 0 });
   ```
   这个测试文件中的各种测试用例，例如测试 `AudioData` 的构造函数和 `copyTo` 方法，直接验证了 JavaScript 中可以调用的 `AudioData` API 的行为是否符合预期。

* **HTML:**  HTML 本身不直接与 `AudioData` 交互。但是，WebCodecs API 通常用于在 Web 应用中处理音视频，这些应用通常是用 HTML 构建的。例如，一个 `<video>` 或 `<audio>` 元素可能使用 WebCodecs 来解码或编码音频流。

* **CSS:** CSS 与 `AudioData` 类没有直接关系，CSS 用于样式化网页。

**逻辑推理举例：**

* **假设输入:** 创建一个包含 10 帧，双声道，采样率为 8000 的 `AudioData` 对象，格式为 `f32-planar`。
* **预期输出 (基于 `AllocationSize` 测试):** 如果调用 `allocationSize` 并指定 `planeIndex` 为 0，不指定 `frameOffset` 和 `frameCount`，则返回的分配大小应该是 `10 * sizeof(float)` 字节。如果指定 `frameOffset` 为 5，则返回的分配大小应该是 `5 * sizeof(float)` 字节。

**用户或编程常见的使用错误举例：**

* **错误地计算目标缓冲区大小:** 用户可能在调用 `copyTo` 之前错误地计算了目标缓冲区的大小，导致缓冲区太小，无法容纳复制的数据。 `CopyTo_DestinationTooSmall` 测试用例就模拟了这种情况。
   ```javascript
   const audioData = new AudioData({...});
   const smallBuffer = new Float32Array(audioData.numberOfFrames - 1); // 缓冲区太小
   audioData.copyTo(smallBuffer.buffer, { planeIndex: 0 }); // 这将导致错误
   ```
* **访问不存在的平面索引:** 对于 planar 格式的音频，用户可能尝试访问不存在的平面索引。 `AllocationSize` 测试用例检查了这种情况。
   ```javascript
   const audioData = new AudioData({ format: 'f32-planar', numberOfChannels: 2, ... });
   audioData.copyTo(outputBuffer.buffer, { planeIndex: 2 }); // 如果只有两个声道，索引 2 无效
   ```
* **偏移量或帧数超出范围:** 用户可能在 `copyTo` 中指定了超出 `AudioData` 实际帧数的偏移量或帧数。 `AllocationSize` 测试用例也涵盖了这些错误情况。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户打开一个使用了 WebCodecs API 的网页。**
2. **网页中的 JavaScript 代码尝试解码音频数据。** 这可能涉及到从网络接收音频数据，或者从本地文件读取音频数据。
3. **JavaScript 代码使用 `AudioDecoder` 接口解码音频流。**
4. **解码器会生成 `AudioData` 对象来表示解码后的音频帧。**
5. **JavaScript 代码可能需要访问 `AudioData` 对象中的原始音频数据，例如进行进一步处理或渲染。**
6. **为了访问数据，JavaScript 代码可能会调用 `audioData.copyTo()` 方法，将数据复制到一个 `ArrayBuffer` 中。**
7. **如果在这个过程中出现了错误，例如目标缓冲区太小，或者指定的平面索引不正确，那么 `AudioData` 类的 C++ 代码 (包括这个测试文件测试的代码) 中的错误处理逻辑就会被触发。**
8. **开发者在调试时可能会查看 Chromium 的日志或使用调试器来追踪错误的来源，最终可能会定位到 `blink/renderer/modules/webcodecs/audio_data.cc` 中的 `copyTo` 实现，以及这个测试文件 `audio_data_test.cc` 中相关的测试用例，以理解代码的行为和如何修复错误。**

**总结 (第 1 部分功能):**

总而言之，`blink/renderer/modules/webcodecs/audio_data_test.cc` 的第一部分主要负责测试 `AudioData` 类的基本创建、内存管理和数据复制功能，确保该类在各种参数和使用场景下都能正常工作，为 WebCodecs API 在 JavaScript 中的正确使用提供保障。它涵盖了从不同来源创建 `AudioData` 对象，计算内存分配大小，以及将数据复制到外部缓冲区的各种情况。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/audio_data_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"

#include <optional>

#include "base/containers/span.h"
#include "media/base/audio_sample_types.h"
#include "media/base/test_helpers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_copy_to_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_sample_format.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_data_view.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {
// Default test values
constexpr int64_t kTimestampInMicroSeconds = 1234;
constexpr int kChannels = 2;
constexpr int kFrames = 20;
constexpr int kSampleRate = 8000;
constexpr int kPartialFrameCount = 5;
constexpr int kOffset = 5;

constexpr int kMicrosecondPerSecond = 1E6;
constexpr uint64_t kExpectedDuration =
    static_cast<int64_t>(kFrames * kMicrosecondPerSecond / kSampleRate);

constexpr float kIncrement = 1.0f / 1000;
constexpr float kEpsilon = kIncrement / 100;
}  // namespace

class AudioDataTest : public testing::Test {
 protected:
  void VerifyPlanarData(float* data, float start_value, int count) {
    for (int i = 0; i < count; ++i)
      ASSERT_NEAR(data[i], start_value + i * kIncrement, kEpsilon) << "i=" << i;
  }

  AllowSharedBufferSource* CreateDefaultData() {
    return CreateCustomData(kChannels, kFrames);
  }

  AllowSharedBufferSource* CreateCustomData(int channels, int frames) {
    auto* buffer = DOMArrayBuffer::Create(channels * frames, sizeof(float));
    for (int ch = 0; ch < channels; ++ch) {
      float* plane_start =
          reinterpret_cast<float*>(buffer->Data()) + ch * frames;
      for (int i = 0; i < frames; ++i) {
        plane_start[i] = static_cast<float>((i + ch * frames) * kIncrement);
      }
    }
    return MakeGarbageCollected<AllowSharedBufferSource>(buffer);
  }

  AudioDataInit* CreateDefaultAudioDataInit(AllowSharedBufferSource* data) {
    auto* audio_data_init = AudioDataInit::Create();
    audio_data_init->setData(data);
    audio_data_init->setTimestamp(kTimestampInMicroSeconds);
    audio_data_init->setNumberOfChannels(kChannels);
    audio_data_init->setNumberOfFrames(kFrames);
    audio_data_init->setSampleRate(kSampleRate);
    audio_data_init->setFormat("f32-planar");
    return audio_data_init;
  }

  AudioData* CreateDefaultAudioData(ScriptState* script_state,
                                    ExceptionState& exception_state) {
    auto* data = CreateDefaultData();
    auto* audio_data_init = CreateDefaultAudioDataInit(data);
    return MakeGarbageCollected<AudioData>(script_state, audio_data_init,
                                           exception_state);
  }

  AudioDataCopyToOptions* CreateCopyToOptions(int index,
                                              std::optional<uint32_t> offset,
                                              std::optional<uint32_t> count) {
    auto* copy_to_options = AudioDataCopyToOptions::Create();
    copy_to_options->setPlaneIndex(index);

    if (offset.has_value())
      copy_to_options->setFrameOffset(offset.value());

    if (count.has_value())
      copy_to_options->setFrameCount(count.value());

    return copy_to_options;
  }

  void VerifyAllocationSize(int plane_index,
                            std::optional<uint32_t> frame_offset,
                            std::optional<uint32_t> frame_count,
                            bool should_throw,
                            int expected_size,
                            std::string description) {
    V8TestingScope scope;
    auto* frame = CreateDefaultAudioData(scope.GetScriptState(),
                                         scope.GetExceptionState());

    auto* options = CreateCopyToOptions(plane_index, frame_offset, frame_count);
    {
      SCOPED_TRACE(description);
      int allocations_size =
          frame->allocationSize(options, scope.GetExceptionState());

      EXPECT_EQ(should_throw, scope.GetExceptionState().HadException());
      EXPECT_EQ(allocations_size, expected_size);
    }
  }
  test::TaskEnvironment task_environment_;
};

TEST_F(AudioDataTest, ConstructFromMediaBuffer) {
  const media::ChannelLayout channel_layout =
      media::ChannelLayout::CHANNEL_LAYOUT_STEREO;
  const int channels = ChannelLayoutToChannelCount(channel_layout);
  constexpr base::TimeDelta timestamp =
      base::Microseconds(kTimestampInMicroSeconds);
  constexpr int kValueStart = 1;
  constexpr int kValueIncrement = 1;
  scoped_refptr<media::AudioBuffer> media_buffer =
      media::MakeAudioBuffer<int16_t>(
          media::SampleFormat::kSampleFormatS16, channel_layout, channels,
          kSampleRate, kValueStart, kValueIncrement, kFrames, timestamp);

  auto* frame = MakeGarbageCollected<AudioData>(media_buffer);

  EXPECT_EQ(frame->format(), "s16");
  EXPECT_EQ(frame->sampleRate(), static_cast<uint32_t>(kSampleRate));
  EXPECT_EQ(frame->numberOfFrames(), static_cast<uint32_t>(kFrames));
  EXPECT_EQ(frame->numberOfChannels(), static_cast<uint32_t>(kChannels));
  EXPECT_EQ(frame->duration(), kExpectedDuration);
  EXPECT_EQ(frame->timestamp(), kTimestampInMicroSeconds);

  // The media::AudioBuffer we receive should match the original |media_buffer|.
  EXPECT_EQ(frame->data(), media_buffer);

  frame->close();
  EXPECT_EQ(frame->data(), nullptr);
  EXPECT_EQ(frame->format(), std::nullopt);
  EXPECT_EQ(frame->sampleRate(), 0u);
  EXPECT_EQ(frame->numberOfFrames(), 0u);
  EXPECT_EQ(frame->numberOfChannels(), 0u);
  EXPECT_EQ(frame->duration(), 0u);

  // Timestamp is preserved even after closing.
  EXPECT_EQ(frame->timestamp(), kTimestampInMicroSeconds);
}

TEST_F(AudioDataTest, ConstructFromAudioDataInit) {
  V8TestingScope scope;
  auto* buffer_source = CreateDefaultData();

  auto* audio_data_init = CreateDefaultAudioDataInit(buffer_source);

  auto* frame = MakeGarbageCollected<AudioData>(
      scope.GetScriptState(), audio_data_init, scope.GetExceptionState());

  EXPECT_EQ(frame->format(), "f32-planar");
  EXPECT_EQ(frame->sampleRate(), static_cast<uint32_t>(kSampleRate));
  EXPECT_EQ(frame->numberOfFrames(), static_cast<uint32_t>(kFrames));
  EXPECT_EQ(frame->numberOfChannels(), static_cast<uint32_t>(kChannels));
  EXPECT_EQ(frame->duration(), kExpectedDuration);
  EXPECT_EQ(frame->timestamp(), kTimestampInMicroSeconds);
}

TEST_F(AudioDataTest, ConstructFromAudioDataInit_HighChannelCount) {
  V8TestingScope scope;
  constexpr int kHighChannelCount = 25;
  auto* buffer_source = CreateCustomData(kHighChannelCount, kFrames);

  auto* audio_data_init = CreateDefaultAudioDataInit(buffer_source);
  audio_data_init->setNumberOfChannels(kHighChannelCount);

  auto* frame = MakeGarbageCollected<AudioData>(
      scope.GetScriptState(), audio_data_init, scope.GetExceptionState());

  EXPECT_EQ(frame->format(), "f32-planar");
  EXPECT_EQ(frame->sampleRate(), static_cast<uint32_t>(kSampleRate));
  EXPECT_EQ(frame->numberOfFrames(), static_cast<uint32_t>(kFrames));
  EXPECT_EQ(frame->numberOfChannels(),
            static_cast<uint32_t>(kHighChannelCount));
  EXPECT_EQ(frame->duration(), kExpectedDuration);
  EXPECT_EQ(frame->timestamp(), kTimestampInMicroSeconds);
}

TEST_F(AudioDataTest, AllocationSize) {
  // We only support the "FLTP" format for now.
  constexpr int kTotalSizeInBytes = kFrames * sizeof(float);

  // Basic cases.
  VerifyAllocationSize(0, std::nullopt, std::nullopt, false, kTotalSizeInBytes,
                       "Default");
  VerifyAllocationSize(1, std::nullopt, std::nullopt, false, kTotalSizeInBytes,
                       "Valid index.");
  VerifyAllocationSize(0, 0, kFrames, false, kTotalSizeInBytes,
                       "Specifying defaults");

  // Cases where we cover a subset of samples.
  VerifyAllocationSize(0, kFrames / 2, std::nullopt, false,
                       kTotalSizeInBytes / 2, "Valid offset, no count");
  VerifyAllocationSize(0, kFrames / 2, kFrames / 4, false,
                       kTotalSizeInBytes / 4, "Valid offset and count");
  VerifyAllocationSize(0, std::nullopt, kFrames / 2, false,
                       kTotalSizeInBytes / 2, "No offset, valid count");

  // Copying 0 frames is technically valid.
  VerifyAllocationSize(0, std::nullopt, 0, false, 0, "Frame count is 0");

  // Failures
  VerifyAllocationSize(2, std::nullopt, std::nullopt, true, 0,
                       "Invalid index.");
  VerifyAllocationSize(0, kFrames, std::nullopt, true, 0, "Offset too big");
  VerifyAllocationSize(0, std::nullopt, kFrames + 1, true, 0, "Count too big");
  VerifyAllocationSize(0, 1, kFrames, true, 0, "Count too big, with offset");
}

TEST_F(AudioDataTest, CopyTo_DestinationTooSmall) {
  V8TestingScope scope;
  auto* frame =
      CreateDefaultAudioData(scope.GetScriptState(), scope.GetExceptionState());
  auto* options = CreateCopyToOptions(/*index=*/0, /*offset=*/std::nullopt,
                                      /*count=*/std::nullopt);

  AllowSharedBufferSource* small_dest =
      MakeGarbageCollected<AllowSharedBufferSource>(
          DOMArrayBuffer::Create(kFrames - 1, sizeof(float)));

  frame->copyTo(small_dest, options, scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
}

TEST_F(AudioDataTest, CopyTo_FullFrames) {
  V8TestingScope scope;
  auto* frame =
      CreateDefaultAudioData(scope.GetScriptState(), scope.GetExceptionState());
  auto* options = CreateCopyToOptions(/*index=*/0, /*offset=*/std::nullopt,
                                      /*count=*/std::nullopt);

  DOMArrayBuffer* data_copy = DOMArrayBuffer::Create(kFrames, sizeof(float));
  AllowSharedBufferSource* dest =
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

  // All frames should have been copied.
  frame->copyTo(dest, options, scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  VerifyPlanarData(static_cast<float*>(data_copy->Data()), /*start_value=*/0,
                   /*count=*/kFrames);
}

TEST_F(AudioDataTest, CopyTo_PlaneIndex) {
  V8TestingScope scope;
  auto* frame =
      CreateDefaultAudioData(scope.GetScriptState(), scope.GetExceptionState());
  auto* options = CreateCopyToOptions(/*index=*/1, /*offset=*/std::nullopt,
                                      /*count=*/std::nullopt);

  DOMArrayBuffer* data_copy = DOMArrayBuffer::Create(kFrames, sizeof(float));
  AllowSharedBufferSource* dest =
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

  // All frames should have been copied.
  frame->copyTo(dest, options, scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  // The channel 1's start value is kFrames*in.
  VerifyPlanarData(static_cast<float*>(data_copy->Data()),
                   /*start_value=*/kFrames * kIncrement,
                   /*count=*/kFrames);
}

// Check that sample-aligned ArrayBuffers can be transferred to AudioData
TEST_F(AudioDataTest, TransferBuffer) {
  V8TestingScope scope;
  std::string data = "audio data";
  auto* buffer = DOMArrayBuffer::Create(base::as_byte_span(data));
  auto* buffer_source = MakeGarbageCollected<AllowSharedBufferSource>(buffer);
  const void* buffer_data_ptr = buffer->Data();

  auto* audio_data_init = AudioDataInit::Create();
  audio_data_init->setData(buffer_source);
  audio_data_init->setTimestamp(0);
  audio_data_init->setNumberOfChannels(1);
  audio_data_init->setNumberOfFrames(static_cast<uint32_t>(data.size()));
  audio_data_init->setSampleRate(kSampleRate);
  audio_data_init->setFormat("u8");
  HeapVector<Member<DOMArrayBuffer>> transfer;
  transfer.push_back(Member<DOMArrayBuffer>(buffer));
  audio_data_init->setTransfer(std::move(transfer));

  auto* audio_data = MakeGarbageCollected<AudioData>(
      scope.GetScriptState(), audio_data_init, scope.GetExceptionState());

  EXPECT_EQ(audio_data->format(), "u8");
  EXPECT_EQ(audio_data->numberOfFrames(), data.size());
  EXPECT_EQ(audio_data->numberOfChannels(), 1u);

  EXPECT_EQ(audio_data->data()->channel_data()[0], buffer_data_ptr);
  auto* options = CreateCopyToOptions(0, 0, {});
  uint32_t allocations_size =
      audio_data->allocationSize(options, scope.GetExceptionState());

  EXPECT_TRUE(buffer->IsDetached());
  EXPECT_EQ(allocations_size, data.size());
}

// Check that not-sample-aligned ArrayBuffers are copied AudioData
TEST_F(AudioDataTest, FailToTransferUnAlignedBuffer) {
  V8TestingScope scope;
  const uint32_t frames = 3;
  std::vector<float> data{0.0, 1.0, 2.0, 3.0, 4.0};
  auto* buffer = DOMArrayBuffer::Create(base::as_byte_span(data));
  auto* view = DOMDataView::Create(
      buffer, 1 /* offset one byte from the float ptr, that how we are sure that
                   the view is not aligned to sizeof(float) */
      ,
      frames * sizeof(float));
  auto* buffer_source = MakeGarbageCollected<AllowSharedBufferSource>(
      MaybeShared<DOMArrayBufferView>(view));

  MakeGarbageCollected<AllowSharedBufferSource>(buffer);
  const void* buffer_data_ptr = buffer->Data();

  auto* audio_data_init = AudioDataInit::Create();
  audio_data_init->setData(buffer_source);
  audio_data_init->setTimestamp(0);
  audio_data_init->setNumberOfChannels(1);
  audio_data_init->setNumberOfFrames(frames);
  audio_data_init->setSampleRate(kSampleRate);
  audio_data_init->setFormat("f32");
  HeapVector<Member<DOMArrayBuffer>> transfer;
  transfer.push_back(Member<DOMArrayBuffer>(buffer));
  audio_data_init->setTransfer(std::move(transfer));

  auto* audio_data = MakeGarbageCollected<AudioData>(
      scope.GetScriptState(), audio_data_init, scope.GetExceptionState());

  // Making sure that the data was copied, not just aliased.
  EXPECT_NE(audio_data->data()->channel_data()[0], buffer_data_ptr);
  EXPECT_EQ(audio_data->numberOfFrames(), frames);
  auto* options = CreateCopyToOptions(0, 0, {});
  uint32_t allocations_size =
      audio_data->allocationSize(options, scope.GetExceptionState());

  // Even though we copied the data, the buffer still needs to be aligned.
  EXPECT_TRUE(buffer->IsDetached());
  EXPECT_EQ(allocations_size, frames * sizeof(float));
}

TEST_F(AudioDataTest, CopyTo_Offset) {
  V8TestingScope scope;

  auto* frame =
      CreateDefaultAudioData(scope.GetScriptState(), scope.GetExceptionState());
  auto* options =
      CreateCopyToOptions(/*index=*/0, kOffset, /*count=*/std::nullopt);

  // |data_copy| is bigger than what we need, and that's ok.
  DOMArrayBuffer* data_copy = DOMArrayBuffer::Create(kFrames, sizeof(float));
  AllowSharedBufferSource* dest =
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

  // All frames should have been copied.
  frame->copyTo(dest, options, scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  VerifyPlanarData(static_cast<float*>(data_copy->Data()),
                   /*start_value=*/kOffset * kIncrement,
                   /*count=*/kFrames - kOffset);
}

TEST_F(AudioDataTest, CopyTo_PartialFrames) {
  V8TestingScope scope;

  auto* frame =
      CreateDefaultAudioData(scope.GetScriptState(), scope.GetExceptionState());
  auto* options = CreateCopyToOptions(/*index=*/0, /*offset=*/std::nullopt,
                                      kPartialFrameCount);

  DOMArrayBuffer* data_copy =
      DOMArrayBuffer::Create(kPartialFrameCount, sizeof(float));
  AllowSharedBufferSource* dest =
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

  // All frames should have been copied.
  frame->copyTo(dest, options, scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  VerifyPlanarData(static_cast<float*>(data_copy->Data()),
                   /*start_value=*/0, kPartialFrameCount);
}

TEST_F(AudioDataTest, CopyTo_PartialFramesAndOffset) {
  V8TestingScope scope;

  auto* frame =
      CreateDefaultAudioData(scope.GetScriptState(), scope.GetExceptionState());
  auto* options = CreateCopyToOptions(/*index=*/0, kOffset, kPartialFrameCount);

  DOMArrayBuffer* data_copy =
      DOMArrayBuffer::Create(kPartialFrameCount, sizeof(float));
  AllowSharedBufferSource* dest =
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

  // All frames should have been copied.
  frame->copyTo(dest, options, scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  VerifyPlanarData(static_cast<float*>(data_copy->Data()),
                   /*start_value=*/kOffset * kIncrement, kPartialFrameCount);
}

TEST_F(AudioDataTest, Interleaved) {
  V8TestingScope scope;

  // Do not use a power of 2, to make it easier to verify the allocationSize()
  // results.
  constexpr int kInterleavedChannels = 3;

  std::vector<int16_t> samples(kFrames * kInterleavedChannels);

  // Populate samples.
  for (int i = 0; i < kFrames; ++i) {
    int block_index = i * kInterleavedChannels;

    samples[block_index] = i;                    // channel 0
    samples[block_index + 1] = i + kFrames;      // channel 1
    samples[block_index + 2] = i + 2 * kFrames;  // channel 2
  }

  const uint8_t* data[] = {reinterpret_cast<const uint8_t*>(samples.data())};

  auto media_buffer = media::AudioBuffer::CopyFrom(
      media::SampleFormat::kSampleFormatS16,
      media::GuessChannelLayout(kInterleavedChannels), kInterleavedChannels,
      kSampleRate, kFrames, data, base::TimeDelta());

  auto* frame = MakeGarbageCollected<AudioData>(media_buffer);

  EXPECT_EQ("s16", frame->format());

  auto* options = CreateCopyToOptions(/*index=*/1, kOffset, kPartialFrameCount);

  // Verify that plane indexes > 1 throw, for interleaved formats.
  {
    DummyExceptionStateForTesting exception_state;
    frame->allocationSize(options, exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }

  // Verify that copy conversion to a planar format supports indexes > 1,
  // even if the source is interleaved.
  options->setFormat(V8AudioSampleFormat::Enum::kF32Planar);
  int allocations_size =
      frame->allocationSize(options, scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  // Verify we get the expected allocation size, for valid formats.
  options = CreateCopyToOptions(/*index=*/0, kOffset, kPartialFrameCount);
  allocations_size = frame->allocationSize(options, scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  // Interleaved formats take into account the number of channels.
  EXPECT_EQ(static_cast<unsigned int>(allocations_size),
            kPartialFrameCount * kInterleavedChannels * sizeof(uint16_t));

  DOMArrayBuffer* data_copy = DOMArrayBuffer::Create(
      kPartialFrameCount * kInterleavedChannels, sizeof(uint16_t));
  AllowSharedBufferSource* dest =
      MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

  // All frames should have been copied.
  frame->copyTo(dest, options, scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  // Verify we retrieved the right samples.
  int16_t* copy = static_cast<int16_t*>(data_copy->Data());
  for (int i = 0; i < kPartialFrameCount; ++i) {
    int block_index = i * kInterleavedChannels;
    int16_t base_value = kOffset + i;

    EXPECT_EQ(copy[block_index], base_value);                    // channel 0
    EXPECT_EQ(copy[block_index + 1], base_value + kFrames);      // channel 1
    EXPECT_EQ(copy[block_index + 2], base_value + 2 * kFrames);  // channel 2
  }
}

struct U8Traits {
  static constexpr std::string Format = "u8";
  static constexpr std::string PlanarFormat = "u8-planar";
  using Traits = media::UnsignedInt8SampleTypeTraits;
};

struct S16Traits {
  static constexpr std::string Format = "s16";
  static constexpr std::string PlanarFormat = "s16-planar";
  using Traits = media::SignedInt16SampleTypeTraits;
};

struct S32Traits {
  static constexpr std::string Format = "s32";
  static constexpr std::string PlanarFormat = "s32-planar";
  using Traits = media::SignedInt32SampleTypeTraits;
};

struct F32Traits {
  static constexpr std::string Format = "f32";
  static constexpr std::string PlanarFormat = "f32-planar";
  using Traits = media::Float32SampleTypeTraits;
};

template <typename SourceTraits, typename TargetTraits>
struct ConversionConfig {
  using From = SourceTraits;
  using To = TargetTraits;
  static std::string config_name() {
    return From::Format + "_to_" + To::Format;
  }
};

template <typename TestConfig>
class AudioDataConversionTest : public testing::Test {
 protected:
  AudioDataInit* CreateAudioDataInit(AllowSharedBufferSource* data,
                                     std::string format) {
    auto* audio_data_init = AudioDataInit::Create();
    audio_data_init->setData(data);
    audio_data_init->setTimestamp(kTimestampInMicroSeconds);
    audio_data_init->setNumberOfChannels(kChannels);
    audio_data_init->setNumberOfFrames(kFrames);
    audio_data_init->setSampleRate(kSampleRate);
    audio_data_init->setFormat(String(format));
    return audio_data_init;
  }

  // Creates test AudioData with kMinValue in channel 0 and kMaxValue in
  // channel 1. If `use_offset`, the first sample of every channel will be
  // kZeroPointValue; if `use_frame_count`, the last sample of every channel
  // will be kZeroPointValue. This allows us to verify that we respect bounds
  // when copying.
  AudioData* CreateAudioData(std::string format,
                             bool planar,
                             bool use_offset,
                             bool use_frame_count,
                             ScriptState* script_state,
                             ExceptionState& exception_state) {
    auto* data = planar ? CreatePlanarData(use_offset, use_frame_count)
                        : CreateInterleavedData(use_offset, use_frame_count);
    auto* audio_data_init = CreateAudioDataInit(data, format);
    return MakeGarbageCollected<AudioData>(script_state, audio_data_init,
                                           exception_state);
  }

  // Creates CopyToOptions. If `use_offset` is true, we exclude the first
  // sample. If `use_frame_count`, we exclude the last sample.
  AudioDataCopyToOptions* CreateCopyToOptions(int plane_index,
                                              std::string format,
                                              bool use_offset,
                                              bool use_frame_count) {
    auto* copy_to_options = AudioDataCopyToOptions::Create();
    copy_to_options->setPlaneIndex(plane_index);
    copy_to_options->setFormat(String(format));
    int total_frames = kFrames;

    if (use_offset) {
      copy_to_options->setFrameOffset(1);
      --total_frames;
    }

    if (use_frame_count) {
      copy_to_options->setFrameCount(total_frames - 1);
    }

    return copy_to_options;
  }

  // Returns planar data with the source sample type's min value in
  // channel 0, and its max value in channel 1.
  // If `use_offset` is true, the first sample of every channel will be 0.
  // If `use_frame_count` is true, the last sample of every channel will be 0.
  AllowSharedBufferSource* CreatePlanarData(bool use_offset,
                                            bool use_frame_count) {
    static_assert(kChannels == 2, "CreatePlanarData() assumes 2 channels");
    using SourceTraits = TestConfig::From::Traits;
    using ValueType = SourceTraits::ValueType;
    auto* buffer =
        DOMArrayBuffer::Create(kChannels * kFrames, sizeof(ValueType));

    ValueType* plane_start = reinterpret_cast<ValueType*>(buffer->Data());
    for (int i = 0; i < kFrames; ++i) {
      plane_start[i] = SourceTraits::kMinValue;
    }

    if (use_offset) {
      plane_start[0] = SourceTraits::kZeroPointValue;
    }
    if (use_frame_count) {
      plane_start[kFrames - 1] = SourceTraits::kZeroPointValue;
    }

    plane_start += kFrames;

    for (int i = 0; i < kFrames; ++i) {
      plane_start[i] = SourceTraits::kMaxValue;
    }

    if (use_offset) {
      plane_start[0] = SourceTraits::kZeroPointValue;
    }
    if (use_frame_count) {
      plane_start[kFrames - 1] = SourceTraits::kZeroPointValue;
    }

    return MakeGarbageCollected<AllowSharedBufferSource>(buffer);
  }

  // Returns interleaved data the source sample type's min value in channel 0,
  // and its max value in channel 1.
  // If `use_offset` is true, the first sample of every channel will be 0.
  // If `use_frame_count` is true, the last sample of every channel will be 0.
  AllowSharedBufferSource* CreateInterleavedData(bool use_offset,
                                                 bool use_frame_count) {
    static_assert(kChannels == 2,
                  "CreateInterleavedData() assumes 2 channels.");
    using SourceTraits = TestConfig::From::Traits;
    using ValueType = SourceTraits::ValueType;
    constexpr int kTotalSamples = kChannels * kFrames;
    auto* buffer = DOMArrayBuffer::Create(kTotalSamples, sizeof(ValueType));

    ValueType* plane_start = reinterpret_cast<ValueType*>(buffer->Data());
    for (int i = 0; i < kTotalSamples; i += 2) {
      plane_start[i] = SourceTraits::kMinValue;
      plane_start[i + 1] = SourceTraits::kMaxValue;
    }

    if (use_offset) {
      plane_start[0] = SourceTraits::kZeroPointValue;
      plane_start[1] = SourceTraits::kZeroPointValue;
    }

    if (use_frame_count) {
      plane_start[kTotalSamples - 2] = SourceTraits::kZeroPointValue;
      plane_start[kTotalSamples - 1] = SourceTraits::kZeroPointValue;
    }

    return MakeGarbageCollected<AllowSharedBufferSource>(buffer);
  }

  int GetFramesToCopy(bool use_offset, bool use_frame_count) {
    int frames_to_copy = kFrames;
    if (use_offset) {
      --frames_to_copy;
    }
    if (use_frame_count) {
      --frames_to_copy;
    }
    return frames_to_copy;
  }

  void TestConversionToPlanar(bool source_is_planar,
                              bool use_offset,
                              bool use_frame_count) {
    using Config = TestConfig;
    using TargetType = Config::To::Traits::ValueType;
    constexpr int kChannelToCopy = 1;

    std::string source_format =
        source_is_planar ? Config::From::PlanarFormat : Config::From::Format;

    // Create original data. The first and last frame will be zero'ed, if
    // `use_offset` or `use_frame_count` are set, respectively.
    V8TestingScope scope;
    auto* audio_data = CreateAudioData(
        source_format, source_is_planar, use_offset, use_frame_count,
        scope.GetScriptState(), scope.GetExceptionState());
    ASSERT_FALSE(scope.GetExceptionState().HadException())
        << scope.GetExceptionState().Message();

    // Prepare to copy.
    auto* copy_to_options = CreateCopyToOptions(
        kChannelToCopy, Config::To::PlanarFormat, use_offset, use_frame_count);

    const int frames_to_copy = GetFramesToCopy(use_offset, use_frame_count);
    DOMArrayBuffer* data_copy =
        DOMArrayBuffer::Create(frames_to_copy, sizeof(TargetType));
    AllowSharedBufferSource* dest =
        MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

    // Copy frames, potentially excluding the first and last frame if
    // `use_offset` or `use_frame_count` are set, respectively.
    audio_data->copyTo(dest, copy_to_options, scope.GetExceptionState());
    EXPECT_FALSE(scope.GetExceptionState().HadException())
        << scope.GetExceptionState().Message();

    TargetType* copied_data = static_cast<TargetType*>(data_copy->Data());

    // `kChannelToCopy` should only contain kMaxValue
    for (int i = 0; i < frames_to_copy; ++i) {
      ASSERT_EQ(copied_data[i], Config::To::Traits::kMaxValue);
    }
  }

  void TestConversionToInterleaved(bool source_is_planar,
                                   bool use_offset,
                                   bool use_frame_count) {
    using Config = TestConfig;
    using TargetType = Config::To::Traits::ValueType;

    std::string source_format =
        source_is_planar ? Config::From::PlanarFormat : Config::From::Format;

    // Create original data. The first and last frame will be zero'ed, if
    // `use_offset` or `use_frame_count` are set, respectively.
    V8TestingScope scope;
    auto* audio_data = CreateAudioData(
        source_format, source_is_planar, use_offset, use_frame_count,
        scope.GetScriptState(), scope.GetExceptionState());
    ASSERT_FALSE(scope.GetExceptionState().HadException())
        << scope.GetExceptionState().Message();

    // Prepare to copy.
    auto* copy_to_options =
        CreateCopyToOptions(0, Config::To::Format, use_offset, use_frame_count);

    const int total_frames =
        GetFramesToCopy(use_offset, use_frame_count) * kChannels;
    DOMArrayBuffer* data_copy =
        DOMArrayBuffer::Create(total_frames, sizeof(TargetType));
    AllowSharedBufferSource* dest =
        MakeGarbageCollected<AllowSharedBufferSource>(data_copy);

    // Copy frames, potentially excluding the first and last frame if
    // `use_offset` or `use_frame_count` are set, respectively.
    audio_data->copyTo(dest, copy_to_options, scope.GetExceptionState());
    EXPECT_FALSE(scope.GetExceptionState().HadException())
        << scope.GetExceptionState().Message();

    TargetType* copied_data = static_cast<TargetType*>(data_copy->Data());

    // The interleaved data should have kMinValue in
    // channel 0 and kMaxValue in channel 1.
    for (int i = 0; i < total_frames; i += 2) {
      ASSERT_EQ(copied_data[i], Config::To::Traits::kMinValue);
      ASSERT_EQ(copied_data[i + 1], Config::To::Traits::kMaxValue);
    }
  }

  test::TaskEnvironment task_environment_;
};

TYPED_TEST_SUITE_P(AudioDataConversionTest);

TYPED_TEST_P(AudioDataConversionTest, PlanarToPlanar) {
  const bool source_is_planar = true;

  {
    SCOPED_TRACE(TypeParam::config_name() + "_all_frames");
    this->TestConversionToPlanar(source_is_planar, false, false);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_offset");
    this->TestConversionToPlanar(source_is_planar, true, false);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_frame_count");
    this->TestConversionToPlanar(source_is_planar, false, true);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_offset_and_frame_count");
    this->TestConversionToPlanar(source_is_planar, true, true);
  }
}

TYPED_TEST_P(AudioDataConversionTest, InterleavedToPlanar) {
  const bool source_is_planar = false;

  {
    SCOPED_TRACE(TypeParam::config_name() + "_all_frames");
    this->TestConversionToPlanar(source_is_planar, false, false);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_offset");
    this->TestConversionToPlanar(source_is_planar, true, false);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_frame_count");
    this->TestConversionToPlanar(source_is_planar, false, true);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_offset_and_frame_count");
    this->TestConversionToPlanar(source_is_planar, true, true);
  }
}

TYPED_TEST_P(AudioDataConversionTest, PlanarToInterleaved) {
  const bool source_is_planar = true;

  {
    SCOPED_TRACE(TypeParam::config_name() + "_all_frames");
    this->TestConversionToInterleaved(source_is_planar, false, false);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_offset");
    this->TestConversionToInterleaved(source_is_planar, true, false);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_frame_count");
    this->TestConversionToInterleaved(source_is_planar, false, true);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_offset_and_frame_count");
    this->TestConversionToInterleaved(source_is_planar, true, true);
  }
}

TYPED_TEST_P(AudioDataConversionTest, InterleavedToInterleaved) {
  const bool source_is_planar = false;

  {
    SCOPED_TRACE(TypeParam::config_name() + "_all_frames");
    this->TestConversionToInterleaved(source_is_planar, false, false);
  }

  {
    SCOPED_TRACE(TypeParam::config_name() + "_with_offset");
    this->TestConversionToInterleaved(source_is_planar, true, false);
  }

  {
    SCOPED_TRACE(Ty
"""


```