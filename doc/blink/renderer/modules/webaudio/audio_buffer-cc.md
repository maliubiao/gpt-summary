Response:
Let's break down the thought process for analyzing the `audio_buffer.cc` file.

1. **Understand the Goal:** The request is to understand the functionality of this specific file within the Chromium Blink rendering engine, particularly concerning Web Audio. Key aspects to identify are its purpose, relationships to web technologies (JavaScript, HTML, CSS), logical behavior, potential user errors, and debugging context.

2. **Initial Code Scan - High Level:**  The first step is to quickly skim the code, noting the included headers and the namespace (`blink`). The headers like `v8_audio_buffer_options.h`, `base_audio_context.h`, `audio_bus.h`, and `exception_state.h` immediately point towards Web Audio functionality and interaction with JavaScript (V8). The `blink` namespace confirms this is part of the Blink rendering engine.

3. **Identify the Core Class:** The primary class in this file is `AudioBuffer`. This is the central entity we need to understand.

4. **Analyze Key Methods - Creation:** The file has multiple `Create` methods. This strongly suggests that the primary purpose of this file is to *create* `AudioBuffer` objects. Let's examine them:
    * `Create(unsigned, uint32_t, float)`: Basic creation with number of channels, frames, and sample rate. Includes validation.
    * `Create(unsigned, uint32_t, float, ExceptionState&)`: Similar to the above, but with exception handling for invalid inputs. This signifies an interface exposed to JavaScript where errors need to be reported.
    * `Create(const AudioBufferOptions*, ExceptionState&)`: Takes an `AudioBufferOptions` object, which is likely a representation of options passed from JavaScript.
    * `CreateUninitialized(unsigned, uint32_t, float)`: Creates without initializing the audio data, suggesting optimization for specific use cases.
    * `CreateFromAudioBus(AudioBus*)`: Creates an `AudioBuffer` from an existing `AudioBus` object, indicating potential internal data transfer or conversion.

5. **Analyze Key Methods - Data Handling:** After creation, how is the data managed?
    * `getChannelData(unsigned, ExceptionState&)` and `getChannelData(unsigned)`: These methods provide access to the underlying audio data for a specific channel as a `DOMFloat32Array`. This is the crucial link to JavaScript, as `DOMFloat32Array` is a JavaScript-accessible typed array.
    * `copyFromChannel(...)` and `copyToChannel(...)`: These methods facilitate copying data between `AudioBuffer` channels and `DOMFloat32Array` objects. This is important for modifying or inspecting audio data from JavaScript.
    * `Zero()`:  Sets all the audio data in the buffer to zero.

6. **Analyze Key Methods - Sharing:**
    * `CreateSharedAudioBuffer()`:  Creates a `SharedAudioBuffer`, suggesting a mechanism for sharing audio data, possibly for inter-process communication or asynchronous operations.

7. **Identify Potential User Errors:**  The `Create` methods with `ExceptionState` are the key here. The code explicitly throws `DOMException` for invalid inputs:
    * Incorrect number of channels (too many or zero).
    * Invalid sample rate.
    * Zero number of frames.
    * Out-of-bounds channel index in `getChannelData`, `copyFromChannel`, and `copyToChannel`.

8. **Connect to Web Technologies:**
    * **JavaScript:** The presence of `DOMFloat32Array`, `AudioBufferOptions`, and the exception handling mechanism directly links to the JavaScript Web Audio API. JavaScript code uses methods like `AudioContext.createBuffer()` to create `AudioBuffer` objects, passing parameters that are validated in this C++ code. JavaScript can then access and modify the audio data via `getChannelData()`, `copyFromChannel()`, and `copyToChannel()`.
    * **HTML:**  HTML triggers the execution of JavaScript. An `<audio>` tag or user interaction could lead to JavaScript code that utilizes the Web Audio API.
    * **CSS:** CSS itself doesn't directly interact with `AudioBuffer`. However, CSS can style UI elements that trigger JavaScript actions related to audio.

9. **Construct Examples and Scenarios:** Based on the analysis, create concrete examples:
    * **JavaScript Interaction:** Demonstrate how `AudioContext.createBuffer()` in JavaScript maps to the C++ `AudioBuffer::Create` methods.
    * **User Errors:** Show examples of invalid parameters passed to `createBuffer()` and how the C++ code throws exceptions.
    * **Debugging Scenario:** Outline the steps a user might take in a web application that leads to the execution of this C++ code, highlighting the role of the JavaScript API.

10. **Structure the Answer:** Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logical Reasoning (input/output), User Errors, and Debugging. Use clear and concise language. Provide code snippets for illustration where appropriate.

11. **Refine and Review:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. For instance, double-check the error handling and the connection between user actions and the code.

By following these steps, we can systematically analyze the `audio_buffer.cc` file and provide a comprehensive and informative answer. The key is to start with a high-level understanding and then progressively delve into the details of the code, always keeping the context of the Web Audio API and the interaction with JavaScript in mind.
好的，让我们来分析一下 `blink/renderer/modules/webaudio/audio_buffer.cc` 这个文件。

**文件功能：**

`audio_buffer.cc` 文件定义了 Blink 渲染引擎中 Web Audio API 的核心类 `AudioBuffer`。`AudioBuffer` 对象用于存储和操作音频数据。主要功能包括：

1. **创建 `AudioBuffer` 对象:**
   - 提供多种静态 `Create` 方法，用于创建不同配置的 `AudioBuffer` 实例。这些方法允许指定声道数、帧数（音频数据的长度）和采样率。
   - 提供了从现有的 `AudioBus` 对象创建 `AudioBuffer` 的方法。`AudioBus` 是 Blink 中用于音频处理的内部表示。
   - 提供了创建未初始化的 `AudioBuffer` 的方法，允许后续手动填充数据。

2. **管理音频数据:**
   - 使用 `DOMFloat32Array` 对象来存储每个声道的音频数据。`DOMFloat32Array` 是 JavaScript 中 `Float32Array` 的 C++ 表示，允许在 C++ 和 JavaScript 之间共享内存。
   - 提供了 `getChannelData` 方法，用于获取指定声道的音频数据 `DOMFloat32Array`，以便 JavaScript 可以访问和修改音频数据。

3. **数据复制:**
   - 提供了 `copyFromChannel` 方法，用于将 `AudioBuffer` 中指定声道的数据复制到传入的 `DOMFloat32Array` 中。
   - 提供了 `copyToChannel` 方法，用于将传入的 `DOMFloat32Array` 中的数据复制到 `AudioBuffer` 的指定声道中。

4. **数据清零:**
   - 提供了 `Zero` 方法，将 `AudioBuffer` 中所有声道的音频数据设置为零。

5. **共享音频缓冲区:**
   - 提供了 `CreateSharedAudioBuffer` 方法，创建一个 `SharedAudioBuffer` 对象。`SharedAudioBuffer` 可以用来在不同的线程或进程之间共享音频数据。

**与 JavaScript, HTML, CSS 的关系：**

`AudioBuffer` 是 Web Audio API 的核心组成部分，它直接与 JavaScript 交互。

* **JavaScript:**
    - JavaScript 代码通过 `AudioContext.createBuffer()` 方法创建 `AudioBuffer` 对象。这个 JavaScript 方法最终会调用 `audio_buffer.cc` 中的 `AudioBuffer::Create` 方法。
    ```javascript
    const audioContext = new AudioContext();
    const numberOfChannels = 2;
    const lengthInSamples = audioContext.sampleRate * 5; // 5秒
    const sampleRate = audioContext.sampleRate;
    const audioBuffer = audioContext.createBuffer(numberOfChannels, lengthInSamples, sampleRate);
    ```
    - JavaScript 代码可以使用 `AudioBuffer.getChannelData(channelIndex)` 方法获取指定声道的音频数据（`Float32Array`），并进行读写操作。
    ```javascript
    const leftChannel = audioBuffer.getChannelData(0);
    for (let i = 0; i < leftChannel.length; i++) {
      leftChannel[i] = Math.sin(2 * Math.PI * 440 * i / audioContext.sampleRate); // 生成一个 440Hz 的正弦波
    }
    ```
    - JavaScript 代码可以使用 `AudioBuffer.copyFromChannel()` 和 `AudioBuffer.copyToChannel()` 方法在 `AudioBuffer` 和 `Float32Array` 之间复制数据。

* **HTML:**
    - HTML 中的 `<audio>` 或 `<video>` 元素可以作为 Web Audio API 的音频源。通过 JavaScript，可以将这些元素的音频流解码并加载到 `AudioBuffer` 中进行进一步处理。
    ```html
    <audio id="myAudio" src="audio.mp3"></audio>
    <script>
      const audioContext = new AudioContext();
      const audioElement = document.getElementById('myAudio');
      const track = audioContext.createMediaElementSource(audioElement);
      audioElement.oncanplaythrough = async () => {
        await audioContext.decodeAudioData(await audioElement.src.arrayBuffer()).then(buffer => {
          // buffer 就是一个 AudioBuffer 对象
          console.log(buffer);
        });
      };
    </script>
    ```

* **CSS:**
    - CSS 本身不直接与 `AudioBuffer` 交互。但 CSS 可以用来控制用户界面，用户与界面的交互（例如点击按钮）可能会触发 JavaScript 代码，从而创建或操作 `AudioBuffer`。

**逻辑推理 (假设输入与输出)：**

假设我们有以下 JavaScript 代码：

```javascript
const audioContext = new AudioContext();
const buffer = audioContext.createBuffer(2, 44100, audioContext.sampleRate);
const leftChannelData = buffer.getChannelData(0);
leftChannelData[0] = 0.5;
leftChannelData[1000] = -0.5;
```

**假设输入：**

- `audioContext.createBuffer(2, 44100, audioContext.sampleRate)` 被调用。

**C++ 代码执行的逻辑：**

1. `AudioBuffer::Create(2, 44100, audioContext.sampleRate)` (或类似的重载) 被调用。
2. 代码会验证输入参数（声道数、帧数、采样率是否合法）。
3. 会分配内存来存储 44100 帧，两个声道的音频数据。
4. 返回一个指向新创建的 `AudioBuffer` 对象的指针。

**假设输出：**

- `buffer` 变量在 JavaScript 中指向一个新创建的 `AudioBuffer` 对象。

**假设输入：**

- `buffer.getChannelData(0)` 被调用。

**C++ 代码执行的逻辑：**

1. `AudioBuffer::getChannelData(0)` 被调用。
2. 代码会检查声道索引 (0) 是否在有效范围内 (0 到 1)。
3. 返回指向第一个声道数据 `DOMFloat32Array` 的指针。

**假设输出：**

- `leftChannelData` 变量在 JavaScript 中指向一个 `Float32Array`，其底层数据对应于 `AudioBuffer` 对象中第一个声道的音频数据。此时 `leftChannelData[0]` 的值为 0.5，`leftChannelData[1000]` 的值为 -0.5。

**用户或编程常见的使用错误：**

1. **创建 `AudioBuffer` 时使用无效的参数:**
   ```javascript
   // 错误：声道数不能为 0
   const buffer1 = audioContext.createBuffer(0, 44100, audioContext.sampleRate);

   // 错误：帧数不能为 0
   const buffer2 = audioContext.createBuffer(2, 0, audioContext.sampleRate);

   // 错误：采样率必须是正数
   const buffer3 = audioContext.createBuffer(2, 44100, 0);
   ```
   在 C++ 代码中，`AudioBuffer::Create` 方法会检查这些错误，并可能返回 `nullptr` 或抛出异常。

2. **访问不存在的声道:**
   ```javascript
   const buffer = audioContext.createBuffer(1, 44100, audioContext.sampleRate);
   // 错误：尝试访问索引为 1 的声道，但 buffer 只有 1 个声道（索引为 0）
   const rightChannelData = buffer.getChannelData(1);
   ```
   在 C++ 代码中，`AudioBuffer::getChannelData` 方法会检查 `channel_index` 是否越界，如果越界会抛出 `DOMException`。

3. **在 `copyFromChannel` 或 `copyToChannel` 中使用越界的索引或偏移量:**
   ```javascript
   const buffer = audioContext.createBuffer(1, 10, audioContext.sampleRate);
   const data = new Float32Array(5);

   // 错误：bufferOffset 超出 buffer 长度
   buffer.copyFromChannel(data, 0, 10);

   // 错误：channelNumber 越界
   buffer.copyToChannel(data, 1);
   ```
   C++ 代码中的 `copyFromChannel` 和 `copyToChannel` 方法会进行边界检查，并在出错时抛出 `DOMException`.

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在一个网页上播放一段音频，并且该网页使用了 Web Audio API 来进行音频处理。以下是可能到达 `audio_buffer.cc` 的步骤：

1. **用户访问网页:** 用户在浏览器中打开包含 Web Audio API 代码的网页。
2. **JavaScript 代码执行:** 网页加载后，JavaScript 代码开始执行。
3. **创建 `AudioContext`:** JavaScript 代码创建了一个 `AudioContext` 对象。
   ```javascript
   const audioContext = new AudioContext();
   ```
4. **加载音频数据:**  JavaScript 代码可能通过以下方式加载音频数据：
   - 使用 `<audio>` 或 `<video>` 元素并使用 `createMediaElementSource`。
   - 使用 `fetch` 或 `XMLHttpRequest` 获取音频文件，然后使用 `audioContext.decodeAudioData` 解码音频数据。
     ```javascript
     fetch('audio.mp3')
       .then(response => response.arrayBuffer())
       .then(arrayBuffer => audioContext.decodeAudioData(arrayBuffer))
       .then(audioBuffer => {
         // audioBuffer 就是一个 AudioBuffer 对象
         console.log(audioBuffer);
       });
     ```
   - 手动创建并填充 `AudioBuffer` 的数据。
     ```javascript
     const buffer = audioContext.createBuffer(2, audioContext.sampleRate * 2, audioContext.sampleRate);
     const left = buffer.getChannelData(0);
     const right = buffer.getChannelData(1);
     for (let i = 0; i < buffer.length; i++) {
       left[i] = Math.random() * 2 - 1; // 生成随机噪声
       right[i] = Math.random() * 2 - 1;
     }
     ```
5. **`audioContext.createBuffer` 调用:**  当 JavaScript 调用 `audioContext.createBuffer()` 时，Blink 渲染引擎会将这个调用路由到 `audio_buffer.cc` 文件中的 `AudioBuffer::Create` 方法。
6. **数据访问和操作:**  如果 JavaScript 代码进一步调用 `audioBuffer.getChannelData()`, `audioBuffer.copyFromChannel()`, 或 `audioBuffer.copyToChannel()`，则会执行 `audio_buffer.cc` 中相应的 C++ 方法。

**作为调试线索：**

- 如果在 Web Audio 应用中遇到与音频数据加载、处理或播放相关的错误，可以查看浏览器的开发者工具的控制台，看是否有与 `AudioBuffer` 相关的错误消息或异常。
- 可以使用断点调试 JavaScript 代码，查看 `AudioBuffer` 对象的属性（如 `numberOfChannels`, `length`, `sampleRate`）以及其包含的音频数据。
- 如果怀疑是 Blink 引擎内部的错误，开发者可能需要使用 Chromium 的调试工具（如 gdb）来跟踪 C++ 代码的执行，并在 `audio_buffer.cc` 文件中设置断点，检查 `AudioBuffer` 对象的创建、数据访问和操作过程中的变量值和内存状态。例如，可以检查 `channels_` 向量的大小和内容，以及 `DOMFloat32Array` 对象是否被正确创建和初始化。

总而言之，`audio_buffer.cc` 是 Web Audio API 在 Blink 渲染引擎中的核心实现之一，负责管理音频数据的存储和访问，并与 JavaScript 层紧密协作，实现 Web 页面上的音频处理功能。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"

#include <memory>

#include "base/containers/span.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_buffer_options.h"
#include "third_party/blink/renderer/modules/webaudio/base_audio_context.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

AudioBuffer* AudioBuffer::Create(unsigned number_of_channels,
                                 uint32_t number_of_frames,
                                 float sample_rate) {
  if (!audio_utilities::IsValidAudioBufferSampleRate(sample_rate) ||
      number_of_channels > BaseAudioContext::MaxNumberOfChannels() ||
      !number_of_channels || !number_of_frames) {
    return nullptr;
  }

  AudioBuffer* buffer = MakeGarbageCollected<AudioBuffer>(
      number_of_channels, number_of_frames, sample_rate);

  if (!buffer->CreatedSuccessfully(number_of_channels)) {
    return nullptr;
  }
  return buffer;
}

AudioBuffer* AudioBuffer::Create(unsigned number_of_channels,
                                 uint32_t number_of_frames,
                                 float sample_rate,
                                 ExceptionState& exception_state) {
  if (!number_of_channels ||
      number_of_channels > BaseAudioContext::MaxNumberOfChannels()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        ExceptionMessages::IndexOutsideRange(
            "number of channels", number_of_channels, 1u,
            ExceptionMessages::kInclusiveBound,
            BaseAudioContext::MaxNumberOfChannels(),
            ExceptionMessages::kInclusiveBound));
    return nullptr;
  }

  if (!audio_utilities::IsValidAudioBufferSampleRate(sample_rate)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        ExceptionMessages::IndexOutsideRange(
            "sample rate", sample_rate,
            audio_utilities::MinAudioBufferSampleRate(),
            ExceptionMessages::kInclusiveBound,
            audio_utilities::MaxAudioBufferSampleRate(),
            ExceptionMessages::kInclusiveBound));
    return nullptr;
  }

  if (!number_of_frames) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        ExceptionMessages::IndexExceedsMinimumBound("number of frames",
                                                    number_of_frames, 0u));
    return nullptr;
  }

  AudioBuffer* audio_buffer =
      Create(number_of_channels, number_of_frames, sample_rate);

  if (!audio_buffer) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "createBuffer(" + String::Number(number_of_channels) + ", " +
            String::Number(number_of_frames) + ", " +
            String::Number(sample_rate) + ") failed.");
  }

  return audio_buffer;
}

AudioBuffer* AudioBuffer::Create(const AudioBufferOptions* options,
                                 ExceptionState& exception_state) {
  return Create(options->numberOfChannels(), options->length(),
                options->sampleRate(), exception_state);
}

AudioBuffer* AudioBuffer::CreateUninitialized(unsigned number_of_channels,
                                              uint32_t number_of_frames,
                                              float sample_rate) {
  if (!audio_utilities::IsValidAudioBufferSampleRate(sample_rate) ||
      number_of_channels > BaseAudioContext::MaxNumberOfChannels() ||
      !number_of_channels || !number_of_frames) {
    return nullptr;
  }

  AudioBuffer* buffer = MakeGarbageCollected<AudioBuffer>(
      number_of_channels, number_of_frames, sample_rate, kDontInitialize);

  if (!buffer->CreatedSuccessfully(number_of_channels)) {
    return nullptr;
  }
  return buffer;
}

AudioBuffer* AudioBuffer::CreateFromAudioBus(AudioBus* bus) {
  if (!bus) {
    return nullptr;
  }
  AudioBuffer* buffer = MakeGarbageCollected<AudioBuffer>(bus);
  if (buffer->CreatedSuccessfully(bus->NumberOfChannels())) {
    return buffer;
  }
  return nullptr;
}

bool AudioBuffer::CreatedSuccessfully(
    unsigned desired_number_of_channels) const {
  return numberOfChannels() == desired_number_of_channels;
}

DOMFloat32Array* AudioBuffer::CreateFloat32ArrayOrNull(
    uint32_t length,
    InitializationPolicy policy) {
  return policy == kZeroInitialize
             ? DOMFloat32Array::CreateOrNull(length)
             : DOMFloat32Array::CreateUninitializedOrNull(length);
}

AudioBuffer::AudioBuffer(unsigned number_of_channels,
                         uint32_t number_of_frames,
                         float sample_rate,
                         InitializationPolicy policy)
    : sample_rate_(sample_rate), length_(number_of_frames) {
  channels_.reserve(number_of_channels);

  for (unsigned i = 0; i < number_of_channels; ++i) {
    DOMFloat32Array* channel_data_array =
        CreateFloat32ArrayOrNull(length_, policy);
    // If the channel data array could not be created, just return. The caller
    // will need to check that the desired number of channels were created.
    if (!channel_data_array) {
      return;
    }

    channels_.push_back(channel_data_array);
  }
}

AudioBuffer::AudioBuffer(AudioBus* bus)
    : sample_rate_(bus->SampleRate()), length_(bus->length()) {
  // Copy audio data from the bus to the Float32Arrays we manage.
  unsigned number_of_channels = bus->NumberOfChannels();
  channels_.reserve(number_of_channels);
  for (unsigned i = 0; i < number_of_channels; ++i) {
    DOMFloat32Array* channel_data_array =
        CreateFloat32ArrayOrNull(length_, kDontInitialize);
    // If the channel data array could not be created, just return. The caller
    // will need to check that the desired number of channels were created.
    if (!channel_data_array) {
      return;
    }

    const float* src = bus->Channel(i)->Data();
    float* dst = channel_data_array->Data();
    memmove(dst, src, length_ * sizeof(*dst));
    channels_.push_back(channel_data_array);
  }
}

NotShared<DOMFloat32Array> AudioBuffer::getChannelData(
    unsigned channel_index,
    ExceptionState& exception_state) {
  if (channel_index >= channels_.size()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "channel index (" + String::Number(channel_index) +
            ") exceeds number of channels (" +
            String::Number(channels_.size()) + ")");
    return NotShared<DOMFloat32Array>(nullptr);
  }

  return getChannelData(channel_index);
}

NotShared<DOMFloat32Array> AudioBuffer::getChannelData(unsigned channel_index) {
  if (channel_index >= channels_.size()) {
    return NotShared<DOMFloat32Array>(nullptr);
  }

  return NotShared<DOMFloat32Array>(channels_[channel_index].Get());
}

void AudioBuffer::copyFromChannel(NotShared<DOMFloat32Array> destination,
                                  int32_t channel_number,
                                  ExceptionState& exception_state) {
  return copyFromChannel(destination, channel_number, 0, exception_state);
}

void AudioBuffer::copyFromChannel(NotShared<DOMFloat32Array> destination,
                                  int32_t channel_number,
                                  size_t buffer_offset,
                                  ExceptionState& exception_state) {
  if (channel_number < 0 ||
      static_cast<uint32_t>(channel_number) >= channels_.size()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexOutsideRange(
            "channelNumber", channel_number, 0,
            ExceptionMessages::kInclusiveBound,
            static_cast<int32_t>(channels_.size() - 1),
            ExceptionMessages::kInclusiveBound));

    return;
  }

  base::span<const float> src = channels_[channel_number].Get()->AsSpan();
  base::span<float> dst = destination->AsSpan();

  // We don't need to copy anything if a) the buffer offset is past the end of
  // the AudioBuffer or b) the internal `Data()` of is a zero-length
  // `Float32Array`, which can result a nullptr.
  if (buffer_offset >= src.size() || dst.size() <= 0) {
    return;
  }

  size_t count = std::min(dst.size(), src.size() - buffer_offset);

  DCHECK(src.data());
  DCHECK(dst.data());

  dst.first(count).copy_from(src.subspan(buffer_offset, count));
}

void AudioBuffer::copyToChannel(NotShared<DOMFloat32Array> source,
                                int32_t channel_number,
                                ExceptionState& exception_state) {
  return copyToChannel(source, channel_number, 0, exception_state);
}

void AudioBuffer::copyToChannel(NotShared<DOMFloat32Array> source,
                                int32_t channel_number,
                                size_t buffer_offset,
                                ExceptionState& exception_state) {
  if (channel_number < 0 ||
      static_cast<uint32_t>(channel_number) >= channels_.size()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexOutsideRange(
            "channelNumber", channel_number, 0,
            ExceptionMessages::kInclusiveBound,
            static_cast<int32_t>(channels_.size() - 1),
            ExceptionMessages::kInclusiveBound));
    return;
  }

  base::span<float> dst = channels_[channel_number].Get()->AsSpan();

  if (buffer_offset >= dst.size()) {
    // Nothing to copy if the buffer offset is past the end of the AudioBuffer.
    return;
  }

  size_t count = dst.size() - buffer_offset;

  base::span<const float> src = source->AsSpan();
  count = std::min(src.size(), count);

  DCHECK(src.data());
  DCHECK(dst.data());

  dst.subspan(buffer_offset, count).copy_from(src.first(count));
}

void AudioBuffer::Zero() {
  for (unsigned i = 0; i < channels_.size(); ++i) {
    if (NotShared<DOMFloat32Array> array = getChannelData(i)) {
      float* data = array->Data();
      memset(data, 0, length() * sizeof(*data));
    }
  }
}

std::unique_ptr<SharedAudioBuffer> AudioBuffer::CreateSharedAudioBuffer() {
  return std::make_unique<SharedAudioBuffer>(this);
}

SharedAudioBuffer::SharedAudioBuffer(AudioBuffer* buffer)
    : sample_rate_(buffer->sampleRate()), length_(buffer->length()) {
  channels_.resize(buffer->numberOfChannels());
  for (unsigned int i = 0; i < buffer->numberOfChannels(); ++i) {
    buffer->getChannelData(i)->buffer()->ShareNonSharedForInternalUse(
        channels_[i]);
  }
}

void SharedAudioBuffer::Zero() {
  for (auto& channel : channels_) {
    float* data = static_cast<float*>(channel.Data());
    memset(data, 0, length() * sizeof(*data));
  }
}

}  // namespace blink
```