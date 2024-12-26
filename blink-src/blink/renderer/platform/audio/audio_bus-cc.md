Response:
Let's break down the thought process to analyze the `audio_bus.cc` file and generate the comprehensive response.

**1. Understanding the Core Purpose:**

The filename `audio_bus.cc` immediately suggests a class or set of functionalities related to handling audio data. The presence of "bus" often implies a channel or pathway for data. Reading the initial comments and includes confirms this suspicion – it's about managing multi-channel audio data in a structured way.

**2. Identifying Key Data Structures:**

The code includes `AudioBus` and `AudioChannel`. This points to a hierarchical structure where an `AudioBus` is composed of multiple `AudioChannel` objects. The `channels_` member in `AudioBus` being a vector of `AudioChannel` further reinforces this.

**3. Pinpointing Core Functionalities (Methods):**

I would then scan the class definition of `AudioBus` for its public methods. This reveals the core set of actions it can perform:

* **Creation:** `Create`, constructor
* **Modification:** `SetChannelMemory`, `ResizeSmaller`, `Zero`, `Scale`, `Normalize`
* **Access:** `Channel`, `ChannelByType`, `NumberOfChannels`, `length`, `SampleRate`, `IsSilent`
* **Copying/Combining:** `CopyFrom`, `SumFrom`, `DiscreteSumFrom`, `SumFromByUpMixing`, `SumFromByDownMixing`, `CopyWithGainFrom`, `CopyWithSampleAccurateGainValuesFrom`, `CreateBufferFromRange`
* **Conversion/Decoding:** `CreateBySampleRateConverting`, `CreateByMixingToMono`, `DecodeAudioFileData`, `GetDataResource`, `CreateBusFromInMemoryAudioFile`

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

This requires understanding how audio processing in the browser works. The `blink` namespace and mentions of `WebAudioBus` immediately suggest connections to the Web Audio API.

* **JavaScript:**  The Web Audio API is a JavaScript API. Therefore, methods like `Create`, `CopyFrom`, `SumFrom`, `CreateBySampleRateConverting` would likely be invoked indirectly by JavaScript code using the Web Audio API. The creation of an `AudioBus` is analogous to creating `AudioBuffer` objects in JavaScript. Operations like mixing, gain control, and sample rate conversion are also core features of the Web Audio API.
* **HTML:** The `<audio>` and `<video>` elements are the primary ways to embed audio and video content in HTML. The browser's audio processing pipeline, where `AudioBus` plays a role, handles the audio data associated with these elements.
* **CSS:** CSS doesn't directly interact with the *data* of an audio stream. However, CSS can control the *presentation* of audio controls (play/pause buttons, volume sliders, etc.) and potentially affect the layout or visibility of elements related to audio playback.

**5. Logical Reasoning (Assumptions and Outputs):**

For each relevant method, I consider:

* **Input:** What are the parameters? What kind of `AudioBus` is being operated on?
* **Process:** What is the method's core logic?
* **Output:** What is the resulting `AudioBus` (if applicable)?  What state changes occur?

For example, for `CreateBufferFromRange`:

* **Input:** `source_buffer`, `start_frame`, `end_frame`
* **Process:** Extracts a portion of the `source_buffer`.
* **Output:** A new `AudioBus` containing the extracted range.

For mixing methods, the assumptions about channel layouts and the mixing algorithms are crucial. I look for the `switch` statements and specific channel combinations to understand the logic.

**6. Identifying Common User/Programming Errors:**

This requires thinking about how developers might misuse the `AudioBus` class.

* **Mismatched sizes:** Providing incorrect lengths or sample rates to methods.
* **Incorrect channel counts:**  Trying to copy from a bus with a different number of channels without understanding the mixing rules.
* **Accessing out-of-bounds channels:**  Trying to access a channel index that doesn't exist.
* **Not understanding channel interpretation:** Using `kSpeakers` when `kDiscrete` is intended, or vice versa.
* **Forgetting to set sample rate:**  Crucial for sample rate conversion.

**7. Structuring the Response:**

Finally, I organize the findings into a clear and readable format, using headings and bullet points for better organization. I make sure to cover all aspects requested in the prompt:

* Core functionalities
* Relationships to JavaScript, HTML, and CSS (with examples)
* Logical reasoning (with input/output examples)
* Common usage errors (with examples)

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe focus on individual low-level operations.
* **Correction:**  Elevate to the higher-level purpose of `AudioBus` in the context of the Web Audio API.
* **Initial thought:** Provide a code walkthrough.
* **Correction:**  Focus on the functional aspects and their implications, rather than getting bogged down in implementation details, unless directly relevant to understanding the functionality.
* **Initial thought:**  Assume deep knowledge of Web Audio API.
* **Correction:** Explain concepts clearly, assuming a general understanding of web development but not necessarily audio processing internals.

By following this structured thought process, combining code analysis with knowledge of web technologies, and focusing on the user's perspective, I can generate a comprehensive and helpful explanation of the `audio_bus.cc` file.
这是一个位于 Chromium Blink 引擎中 `blink/renderer/platform/audio/audio_bus.cc` 的源代码文件。它定义了 `AudioBus` 类，这个类是 Web Audio API 中用于表示多通道音频数据的核心数据结构。

以下是 `AudioBus` 类的主要功能以及它与 JavaScript, HTML, CSS 的关系、逻辑推理和常见错误：

**`AudioBus` 的功能：**

1. **存储和管理多通道音频数据:** `AudioBus` 内部包含一个或多个 `AudioChannel` 对象，每个 `AudioChannel` 存储着单个音频通道的采样数据（浮点数）。它可以表示单声道、立体声或多声道音频。
2. **创建和初始化音频缓冲区:** 提供静态方法 `Create` 用于创建指定通道数和帧长度的 `AudioBus` 对象。可以选择是否立即分配内存。
3. **设置和获取通道数据:** 允许直接设置或获取特定通道的内存 (`SetChannelMemory`)。
4. **调整缓冲区大小:**  `ResizeSmaller` 方法可以缩小音频缓冲区的长度。
5. **清零缓冲区:** `Zero` 方法将所有通道的采样数据设置为 0。
6. **按通道类型访问:** `ChannelByType` 方法允许根据预定义的通道类型（例如 `kChannelLeft`, `kChannelRight`, `kChannelCenter`）获取对应的 `AudioChannel` 对象。这对于处理不同声道布局的音频非常有用。
7. **拓扑结构匹配检查:** `TopologyMatches` 方法检查两个 `AudioBus` 对象的通道数和帧长度是否相同。
8. **创建子缓冲区:** `CreateBufferFromRange` 方法可以从现有的 `AudioBus` 对象中提取指定范围的音频数据创建一个新的 `AudioBus` 对象。
9. **计算最大绝对值:** `MaxAbsValue` 方法返回所有通道中采样点的最大绝对值。
10. **归一化和缩放:** `Normalize` 方法将所有采样值缩放到 [-1, 1] 范围内，`Scale` 方法将所有采样值乘以一个指定的比例因子。
11. **复制和混合音频数据:**
    * `CopyFrom`: 将源 `AudioBus` 的数据复制到当前 `AudioBus`。
    * `SumFrom`: 将源 `AudioBus` 的数据加到当前 `AudioBus` 的数据上。
    * `DiscreteSumFrom`:  根据通道数进行离散的加法，多余的通道会被忽略或补零。
    * `SumFromByUpMixing`: 将低通道数的音频混合到高通道数的音频，例如从单声道混合到立体声。
    * `SumFromByDownMixing`: 将高通道数的音频混合到低通道数的音频，例如从立体声混合到单声道。
12. **带增益复制:** `CopyWithGainFrom` 方法在复制音频数据的同时应用一个全局增益。
13. **带采样精度增益值复制:** `CopyWithSampleAccurateGainValuesFrom` 方法允许对每个采样点应用不同的增益值。
14. **采样率转换:** `CreateBySampleRateConverting` 方法可以创建一个新的 `AudioBus`，其采样率与源 `AudioBus` 不同。它使用 `SincResampler` 进行重采样。
15. **混合到单声道:** `CreateByMixingToMono` 方法将多声道音频混合成单声道音频。
16. **静音检测:** `IsSilent` 方法检查 `AudioBus` 是否所有通道都静音。
17. **清除静音标记:** `ClearSilentFlag` 方法清除 `AudioChannel` 的静音标记。
18. **解码音频文件数据:** `DecodeAudioFileData` 函数（非 `AudioBus` 的成员函数，但与 `AudioBus` 相关）用于解码二进制音频文件数据并创建 `AudioBus` 对象。
19. **获取资源音频数据:** `GetDataResource` 方法用于获取指定 ID 的音频资源并将其解码为 `AudioBus`。
20. **从内存中的音频文件创建:** `CreateBusFromInMemoryAudioFile` 方法从内存中的音频文件数据创建 `AudioBus` 对象，并可以选择进行混合到单声道和采样率转换。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** `AudioBus` 是 Web Audio API 在底层表示音频数据的核心结构。在 JavaScript 中，当你使用 Web Audio API 创建 `AudioBuffer` 对象或者处理音频节点（如 `AudioBufferSourceNode`, `GainNode`, `ChannelSplitter`, `ChannelMerger` 等）时，Blink 引擎会在内部使用 `AudioBus` 来存储和操作音频数据。
    * **例子:** 当你使用 JavaScript 的 `audioContext.decodeAudioData()` 方法解码音频文件时，引擎最终会创建一个 `AudioBus` 对象来保存解码后的音频数据。当你创建一个 `AudioBufferSourceNode` 并设置其 `buffer` 属性为一个 `AudioBuffer` 时，该 `AudioBuffer` 的数据在 Blink 内部是以 `AudioBus` 的形式存在的。

* **HTML:** HTML 的 `<audio>` 和 `<video>` 元素用于嵌入音频和视频内容。当浏览器解析这些元素并开始播放媒体时，Blink 引擎会负责解码音频流，并将解码后的音频数据存储在 `AudioBus` 对象中进行处理，最终输出到音频设备。
    * **例子:** 当用户播放一个 `<audio>` 元素时，浏览器会解码音频文件，并创建一个 `AudioBus` 来表示该音频的音频数据。

* **CSS:** CSS 本身不直接操作音频数据。但是，CSS 可以用于控制与音频相关的用户界面元素的外观和行为，例如播放按钮、音量滑块等。这些 UI 元素的操作可能会触发 JavaScript 代码，进而通过 Web Audio API 操作底层的 `AudioBus` 数据。
    * **例子:**  一个自定义的音量滑块，通过 JavaScript 监听滑块的拖动事件，并使用 Web Audio API 的 `GainNode` 来改变音频的音量。`GainNode` 内部会操作其输入和输出 `AudioBus` 上的采样数据。

**逻辑推理和假设输入/输出：**

以 `SumFromByUpMixing` 方法为例：

* **假设输入:**
    * **源 `AudioBus`:** 单声道音频，通道数为 1，采样数据为 `[0.1, 0.2, 0.3]`。
    * **目标 `AudioBus`:** 立体声音频，通道数为 2，初始采样数据为 `[[0, 0, 0], [0, 0, 0]]`。
* **逻辑推理:** `SumFromByUpMixing` 检测到源是单声道，目标是立体声，会按照预定的规则进行上混。对于单声道到立体声，左声道和右声道都将复制单声道的数据。
* **输出:** 目标 `AudioBus` 的采样数据变为 `[[0.1, 0.2, 0.3], [0.1, 0.2, 0.3]]`。

以 `CreateBySampleRateConverting` 方法为例：

* **假设输入:**
    * **源 `AudioBus`:** 采样率为 48000 Hz 的立体声音频，帧长度为 100。
    * **目标采样率:** 24000 Hz。
* **逻辑推理:** `CreateBySampleRateConverting` 会使用 `SincResampler` 将源 `AudioBus` 的每个通道的采样率从 48000 Hz 转换到 24000 Hz。由于目标采样率是源采样率的一半，新的 `AudioBus` 的帧长度将大约是源 `AudioBus` 的一半。
* **输出:** 一个新的 `AudioBus` 对象，采样率为 24000 Hz，通道数为 2，帧长度约为 50，其中的采样值经过了重采样。

**用户或编程常见的使用错误：**

1. **尝试访问超出通道范围的通道:**
   ```c++
   AudioBus* bus = AudioBus::Create(2, 128); // 创建一个双声道音频缓冲区
   AudioChannel* channel = bus->Channel(2); // 错误：索引超出范围 (0 和 1)
   ```
   **后果:** 可能导致程序崩溃或未定义的行为。

2. **在拓扑结构不匹配的情况下进行复制或混合，并且没有理解通道解释的影响:**
   ```c++
   scoped_refptr<AudioBus> bus1 = AudioBus::Create(1, 128); // 单声道
   scoped_refptr<AudioBus> bus2 = AudioBus::Create(2, 128); // 立体声
   bus2->CopyFrom(*bus1, kDiscrete); // 使用 kDiscrete 解释
   ```
   **后果:**  如果使用 `kDiscrete`，单声道数据只会复制到立体声的左声道，右声道保持静音。如果没有理解 `kSpeakers` 和 `kDiscrete` 的区别，可能会得到意想不到的混合结果。

3. **在未设置采样率的情况下进行采样率转换:**
   ```c++
   scoped_refptr<AudioBus> bus = AudioBus::Create(1, 128);
   // 忘记设置 bus->SetSampleRate(44100);
   scoped_refptr<AudioBus> converted_bus =
       AudioBus::CreateBySampleRateConverting(bus.get(), false, 22050);
   ```
   **后果:** 采样率转换可能无法正确进行，因为源 `AudioBus` 的采样率未知。通常 `CreateBySampleRateConverting` 会检查源采样率，如果为 0 会返回 `nullptr`。

4. **假设 `ChannelByType` 总是返回非空指针:**
   ```c++
   scoped_refptr<AudioBus> bus = AudioBus::Create(1, 128); // 单声道
   AudioChannel* right_channel = bus->ChannelByType(kChannelRight);
   if (right_channel) {
       // ... 使用 right_channel ... // 错误：对于单声道音频，kChannelRight 为空
   }
   ```
   **后果:**  访问空指针会导致程序崩溃。应该在使用 `ChannelByType` 返回的指针之前进行空指针检查。

5. **在多线程环境下不安全地访问或修改 `AudioBus` 的数据:**  `AudioBus` 本身可能不是线程安全的。如果在多个线程中同时访问或修改其内部的音频数据，可能会导致数据竞争和不一致性。

总而言之，`blink/renderer/platform/audio/audio_bus.cc` 文件定义了 Chromium 中用于处理音频数据的核心类，它与 Web Audio API 的功能紧密相关，并在浏览器处理 HTML 音频和视频元素时发挥着关键作用。理解 `AudioBus` 的功能和正确使用方式对于开发高性能的 Web 音频应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/audio/audio_bus.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/audio/audio_bus.h"

#include <assert.h>
#include <math.h>
#include <algorithm>
#include <memory>
#include <utility>

#include "base/ranges/algorithm.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_audio_bus.h"
#include "third_party/blink/renderer/platform/audio/denormal_disabler.h"
#include "third_party/blink/renderer/platform/audio/sinc_resampler.h"
#include "third_party/blink/renderer/platform/audio/vector_math.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

using vector_math::Vadd;
using vector_math::Vsma;

const unsigned kMaxBusChannels = 32;

scoped_refptr<AudioBus> AudioBus::Create(unsigned number_of_channels,
                                         uint32_t length,
                                         bool allocate) {
  DCHECK_LE(number_of_channels, kMaxBusChannels);
  if (number_of_channels > kMaxBusChannels) {
    return nullptr;
  }

  return base::AdoptRef(new AudioBus(number_of_channels, length, allocate));
}

AudioBus::AudioBus(unsigned number_of_channels, uint32_t length, bool allocate)
    : length_(length), sample_rate_(0) {
  channels_.ReserveInitialCapacity(number_of_channels);

  for (unsigned i = 0; i < number_of_channels; ++i) {
    if (allocate) {
      channels_.emplace_back(length);
    } else {
      channels_.emplace_back(nullptr, length);
    }
  }

  layout_ = kLayoutCanonical;  // for now this is the only layout we define
}

void AudioBus::SetChannelMemory(unsigned channel_index,
                                float* storage,
                                uint32_t length) {
  if (channel_index < channels_.size()) {
    Channel(channel_index)->Set(storage, length);
    // FIXME: verify that this length matches all the other channel lengths
    length_ = length;
  }
}

void AudioBus::ResizeSmaller(uint32_t new_length) {
  DCHECK_LE(new_length, length_);
  if (new_length <= length_) {
    length_ = new_length;
  }

  for (AudioChannel& channel : channels_) {
    channel.ResizeSmaller(new_length);
  }
}

void AudioBus::Zero() {
  for (AudioChannel& channel : channels_) {
    channel.Zero();
  }
}

AudioChannel* AudioBus::ChannelByType(unsigned channel_type) {
  // For now we only support canonical channel layouts...
  if (layout_ != kLayoutCanonical) {
    return nullptr;
  }

  switch (NumberOfChannels()) {
    case 1:  // mono
      if (channel_type == kChannelMono || channel_type == kChannelLeft) {
        return Channel(0);
      }
      return nullptr;

    case 2:  // stereo
      switch (channel_type) {
        case kChannelLeft:
          return Channel(0);
        case kChannelRight:
          return Channel(1);
        default:
          return nullptr;
      }

    case 4:  // quad
      switch (channel_type) {
        case kChannelLeft:
          return Channel(0);
        case kChannelRight:
          return Channel(1);
        case kChannelSurroundLeft:
          return Channel(2);
        case kChannelSurroundRight:
          return Channel(3);
        default:
          return nullptr;
      }

    case 5:  // 5.0
      switch (channel_type) {
        case kChannelLeft:
          return Channel(0);
        case kChannelRight:
          return Channel(1);
        case kChannelCenter:
          return Channel(2);
        case kChannelSurroundLeft:
          return Channel(3);
        case kChannelSurroundRight:
          return Channel(4);
        default:
          return nullptr;
      }

    case 6:  // 5.1
      switch (channel_type) {
        case kChannelLeft:
          return Channel(0);
        case kChannelRight:
          return Channel(1);
        case kChannelCenter:
          return Channel(2);
        case kChannelLFE:
          return Channel(3);
        case kChannelSurroundLeft:
          return Channel(4);
        case kChannelSurroundRight:
          return Channel(5);
        default:
          return nullptr;
      }
  }

  NOTREACHED();
}

const AudioChannel* AudioBus::ChannelByType(unsigned type) const {
  return const_cast<AudioBus*>(this)->ChannelByType(type);
}

// Returns true if the channel count and frame-size match.
bool AudioBus::TopologyMatches(const AudioBus& bus) const {
  if (NumberOfChannels() != bus.NumberOfChannels()) {
    return false;  // channel mismatch
  }

  // Make sure source bus has enough frames.
  if (length() > bus.length()) {
    return false;  // frame-size mismatch
  }

  return true;
}

scoped_refptr<AudioBus> AudioBus::CreateBufferFromRange(
    const AudioBus* source_buffer,
    unsigned start_frame,
    unsigned end_frame) {
  uint32_t number_of_source_frames = source_buffer->length();
  unsigned number_of_channels = source_buffer->NumberOfChannels();

  // Sanity checking
  bool is_range_safe =
      start_frame < end_frame && end_frame <= number_of_source_frames;
  DCHECK(is_range_safe);
  if (!is_range_safe) {
    return nullptr;
  }

  uint32_t range_length = end_frame - start_frame;

  scoped_refptr<AudioBus> audio_bus = Create(number_of_channels, range_length);
  audio_bus->SetSampleRate(source_buffer->SampleRate());

  for (unsigned i = 0; i < number_of_channels; ++i) {
    audio_bus->Channel(i)->CopyFromRange(source_buffer->Channel(i), start_frame,
                                         end_frame);
  }

  return audio_bus;
}

float AudioBus::MaxAbsValue() const {
  float max = 0.0f;
  for (unsigned i = 0; i < NumberOfChannels(); ++i) {
    const AudioChannel* channel = Channel(i);
    max = std::max(max, channel->MaxAbsValue());
  }

  return max;
}

void AudioBus::Normalize() {
  float max = MaxAbsValue();
  if (max) {
    Scale(1.0f / max);
  }
}

void AudioBus::Scale(float scale) {
  for (unsigned i = 0; i < NumberOfChannels(); ++i) {
    Channel(i)->Scale(scale);
  }
}

void AudioBus::CopyFrom(const AudioBus& source_bus,
                        ChannelInterpretation channel_interpretation) {
  if (&source_bus == this) {
    return;
  }

  // Copying bus is equivalent to zeroing and then summing.
  Zero();
  SumFrom(source_bus, channel_interpretation);
}

void AudioBus::SumFrom(const AudioBus& source_bus,
                       ChannelInterpretation channel_interpretation) {
  if (&source_bus == this) {
    return;
  }

  unsigned number_of_source_channels = source_bus.NumberOfChannels();
  unsigned number_of_destination_channels = NumberOfChannels();

  // If the channel numbers are equal, perform channels-wise summing.
  if (number_of_source_channels == number_of_destination_channels) {
    for (unsigned i = 0; i < number_of_source_channels; ++i) {
      Channel(i)->SumFrom(source_bus.Channel(i));
    }

    return;
  }

  // Otherwise perform up/down-mix or the discrete transfer based on the
  // number of channels and the channel interpretation.
  switch (channel_interpretation) {
    case kSpeakers:
      if (number_of_source_channels < number_of_destination_channels) {
        SumFromByUpMixing(source_bus);
      } else {
        SumFromByDownMixing(source_bus);
      }
      break;
    case kDiscrete:
      DiscreteSumFrom(source_bus);
      break;
  }
}

void AudioBus::DiscreteSumFrom(const AudioBus& source_bus) {
  unsigned number_of_source_channels = source_bus.NumberOfChannels();
  unsigned number_of_destination_channels = NumberOfChannels();

  if (number_of_destination_channels < number_of_source_channels) {
    // Down-mix by summing channels and dropping the remaining.
    for (unsigned i = 0; i < number_of_destination_channels; ++i) {
      Channel(i)->SumFrom(source_bus.Channel(i));
    }
  } else if (number_of_destination_channels > number_of_source_channels) {
    // Up-mix by summing as many channels as we have.
    for (unsigned i = 0; i < number_of_source_channels; ++i) {
      Channel(i)->SumFrom(source_bus.Channel(i));
    }
  }
}

void AudioBus::SumFromByUpMixing(const AudioBus& source_bus) {
  unsigned number_of_source_channels = source_bus.NumberOfChannels();
  unsigned number_of_destination_channels = NumberOfChannels();

  if ((number_of_source_channels == 1 && number_of_destination_channels == 2) ||
      (number_of_source_channels == 1 && number_of_destination_channels == 4)) {
    // Up-mixing: 1 -> 2, 1 -> 4
    //   output.L = input
    //   output.R = input
    //   output.SL = 0 (in the case of 1 -> 4)
    //   output.SR = 0 (in the case of 1 -> 4)
    const AudioChannel* source_l = source_bus.ChannelByType(kChannelLeft);
    ChannelByType(kChannelLeft)->SumFrom(source_l);
    ChannelByType(kChannelRight)->SumFrom(source_l);
  } else if (number_of_source_channels == 1 &&
             number_of_destination_channels == 6) {
    // Up-mixing: 1 -> 5.1
    //   output.L = 0
    //   output.R = 0
    //   output.C = input (put in center channel)
    //   output.LFE = 0
    //   output.SL = 0
    //   output.SR = 0
    ChannelByType(kChannelCenter)
        ->SumFrom(source_bus.ChannelByType(kChannelLeft));
  } else if ((number_of_source_channels == 2 &&
              number_of_destination_channels == 4) ||
             (number_of_source_channels == 2 &&
              number_of_destination_channels == 6)) {
    // Up-mixing: 2 -> 4, 2 -> 5.1
    //   output.L = input.L
    //   output.R = input.R
    //   output.C = 0 (in the case of 2 -> 5.1)
    //   output.LFE = 0 (in the case of 2 -> 5.1)
    //   output.SL = 0
    //   output.SR = 0
    ChannelByType(kChannelLeft)
        ->SumFrom(source_bus.ChannelByType(kChannelLeft));
    ChannelByType(kChannelRight)
        ->SumFrom(source_bus.ChannelByType(kChannelRight));
  } else if (number_of_source_channels == 4 &&
             number_of_destination_channels == 6) {
    // Up-mixing: 4 -> 5.1
    //   output.L = input.L
    //   output.R = input.R
    //   output.C = 0
    //   output.LFE = 0
    //   output.SL = input.SL
    //   output.SR = input.SR
    ChannelByType(kChannelLeft)
        ->SumFrom(source_bus.ChannelByType(kChannelLeft));
    ChannelByType(kChannelRight)
        ->SumFrom(source_bus.ChannelByType(kChannelRight));
    ChannelByType(kChannelSurroundLeft)
        ->SumFrom(source_bus.ChannelByType(kChannelSurroundLeft));
    ChannelByType(kChannelSurroundRight)
        ->SumFrom(source_bus.ChannelByType(kChannelSurroundRight));
  } else {
    // All other cases, fall back to the discrete sum. This will silence the
    // excessive channels.
    DiscreteSumFrom(source_bus);
  }
}

void AudioBus::SumFromByDownMixing(const AudioBus& source_bus) {
  unsigned number_of_source_channels = source_bus.NumberOfChannels();
  unsigned number_of_destination_channels = NumberOfChannels();

  if (number_of_source_channels == 2 && number_of_destination_channels == 1) {
    // Down-mixing: 2 -> 1
    //   output = 0.5 * (input.L + input.R)
    const float* source_l = source_bus.ChannelByType(kChannelLeft)->Data();
    const float* source_r = source_bus.ChannelByType(kChannelRight)->Data();

    float* destination = ChannelByType(kChannelLeft)->MutableData();
    float scale = 0.5;

    Vsma(source_l, 1, &scale, destination, 1, length());
    Vsma(source_r, 1, &scale, destination, 1, length());
  } else if (number_of_source_channels == 4 &&
             number_of_destination_channels == 1) {
    // Down-mixing: 4 -> 1
    //   output = 0.25 * (input.L + input.R + input.SL + input.SR)
    const float* source_l = source_bus.ChannelByType(kChannelLeft)->Data();
    const float* source_r = source_bus.ChannelByType(kChannelRight)->Data();
    const float* source_sl =
        source_bus.ChannelByType(kChannelSurroundLeft)->Data();
    const float* source_sr =
        source_bus.ChannelByType(kChannelSurroundRight)->Data();

    float* destination = ChannelByType(kChannelLeft)->MutableData();
    float scale = 0.25;

    Vsma(source_l, 1, &scale, destination, 1, length());
    Vsma(source_r, 1, &scale, destination, 1, length());
    Vsma(source_sl, 1, &scale, destination, 1, length());
    Vsma(source_sr, 1, &scale, destination, 1, length());
  } else if (number_of_source_channels == 6 &&
             number_of_destination_channels == 1) {
    // Down-mixing: 5.1 -> 1
    //   output = sqrt(1/2) * (input.L + input.R) + input.C
    //            + 0.5 * (input.SL + input.SR)
    const float* source_l = source_bus.ChannelByType(kChannelLeft)->Data();
    const float* source_r = source_bus.ChannelByType(kChannelRight)->Data();
    const float* source_c = source_bus.ChannelByType(kChannelCenter)->Data();
    const float* source_sl =
        source_bus.ChannelByType(kChannelSurroundLeft)->Data();
    const float* source_sr =
        source_bus.ChannelByType(kChannelSurroundRight)->Data();

    float* destination = ChannelByType(kChannelLeft)->MutableData();
    float scale_sqrt_half = sqrtf(0.5);
    float scale_half = 0.5;

    Vsma(source_l, 1, &scale_sqrt_half, destination, 1, length());
    Vsma(source_r, 1, &scale_sqrt_half, destination, 1, length());
    Vadd(source_c, 1, destination, 1, destination, 1, length());
    Vsma(source_sl, 1, &scale_half, destination, 1, length());
    Vsma(source_sr, 1, &scale_half, destination, 1, length());
  } else if (number_of_source_channels == 4 &&
             number_of_destination_channels == 2) {
    // Down-mixing: 4 -> 2
    //   output.L = 0.5 * (input.L + input.SL)
    //   output.R = 0.5 * (input.R + input.SR)
    const float* source_l = source_bus.ChannelByType(kChannelLeft)->Data();
    const float* source_r = source_bus.ChannelByType(kChannelRight)->Data();
    const float* source_sl =
        source_bus.ChannelByType(kChannelSurroundLeft)->Data();
    const float* source_sr =
        source_bus.ChannelByType(kChannelSurroundRight)->Data();

    float* destination_l = ChannelByType(kChannelLeft)->MutableData();
    float* destination_r = ChannelByType(kChannelRight)->MutableData();
    float scale_half = 0.5;

    Vsma(source_l, 1, &scale_half, destination_l, 1, length());
    Vsma(source_sl, 1, &scale_half, destination_l, 1, length());
    Vsma(source_r, 1, &scale_half, destination_r, 1, length());
    Vsma(source_sr, 1, &scale_half, destination_r, 1, length());
  } else if (number_of_source_channels == 6 &&
             number_of_destination_channels == 2) {
    // Down-mixing: 5.1 -> 2
    //   output.L = input.L + sqrt(1/2) * (input.C + input.SL)
    //   output.R = input.R + sqrt(1/2) * (input.C + input.SR)
    const float* source_l = source_bus.ChannelByType(kChannelLeft)->Data();
    const float* source_r = source_bus.ChannelByType(kChannelRight)->Data();
    const float* source_c = source_bus.ChannelByType(kChannelCenter)->Data();
    const float* source_sl =
        source_bus.ChannelByType(kChannelSurroundLeft)->Data();
    const float* source_sr =
        source_bus.ChannelByType(kChannelSurroundRight)->Data();

    float* destination_l = ChannelByType(kChannelLeft)->MutableData();
    float* destination_r = ChannelByType(kChannelRight)->MutableData();
    float scale_sqrt_half = sqrtf(0.5);

    Vadd(source_l, 1, destination_l, 1, destination_l, 1, length());
    Vsma(source_c, 1, &scale_sqrt_half, destination_l, 1, length());
    Vsma(source_sl, 1, &scale_sqrt_half, destination_l, 1, length());
    Vadd(source_r, 1, destination_r, 1, destination_r, 1, length());
    Vsma(source_c, 1, &scale_sqrt_half, destination_r, 1, length());
    Vsma(source_sr, 1, &scale_sqrt_half, destination_r, 1, length());
  } else if (number_of_source_channels == 6 &&
             number_of_destination_channels == 4) {
    // Down-mixing: 5.1 -> 4
    //   output.L = input.L + sqrt(1/2) * input.C
    //   output.R = input.R + sqrt(1/2) * input.C
    //   output.SL = input.SL
    //   output.SR = input.SR
    const float* source_l = source_bus.ChannelByType(kChannelLeft)->Data();
    const float* source_r = source_bus.ChannelByType(kChannelRight)->Data();
    const float* source_c = source_bus.ChannelByType(kChannelCenter)->Data();

    float* destination_l = ChannelByType(kChannelLeft)->MutableData();
    float* destination_r = ChannelByType(kChannelRight)->MutableData();
    float scale_sqrt_half = sqrtf(0.5);

    Vadd(source_l, 1, destination_l, 1, destination_l, 1, length());
    Vsma(source_c, 1, &scale_sqrt_half, destination_l, 1, length());
    Vadd(source_r, 1, destination_r, 1, destination_r, 1, length());
    Vsma(source_c, 1, &scale_sqrt_half, destination_r, 1, length());
    Channel(2)->SumFrom(source_bus.Channel(4));
    Channel(3)->SumFrom(source_bus.Channel(5));
  } else {
    // All other cases, fall back to the discrete sum. This will perform
    // channel-wise sum until the destination channels run out.
    DiscreteSumFrom(source_bus);
  }
}

void AudioBus::CopyWithGainFrom(const AudioBus& source_bus, float gain) {
  if (!TopologyMatches(source_bus)) {
    NOTREACHED();
  }

  if (source_bus.IsSilent()) {
    Zero();
    return;
  }

  unsigned number_of_channels = NumberOfChannels();
  DCHECK_LE(number_of_channels, kMaxBusChannels);
  if (number_of_channels > kMaxBusChannels) {
    return;
  }

  // If it is copying from the same bus and no need to change gain, just return.
  if (this == &source_bus && gain == 1) {
    return;
  }

  const float* sources[kMaxBusChannels];
  float* destinations[kMaxBusChannels];

  for (unsigned i = 0; i < number_of_channels; ++i) {
    sources[i] = source_bus.Channel(i)->Data();
    destinations[i] = Channel(i)->MutableData();
  }

  unsigned frames_to_process = length();

  // Handle gains of 0 and 1 (exactly) specially.
  if (gain == 1) {
    for (unsigned channel_index = 0; channel_index < number_of_channels;
         ++channel_index) {
      memcpy(destinations[channel_index], sources[channel_index],
             frames_to_process * sizeof(*destinations[channel_index]));
    }
  } else if (gain == 0) {
    for (unsigned channel_index = 0; channel_index < number_of_channels;
         ++channel_index) {
      memset(destinations[channel_index], 0,
             frames_to_process * sizeof(*destinations[channel_index]));
    }
  } else {
    for (unsigned channel_index = 0; channel_index < number_of_channels;
         ++channel_index) {
      vector_math::Vsmul(sources[channel_index], 1, &gain,
                         destinations[channel_index], 1, frames_to_process);
    }
  }
}

void AudioBus::CopyWithSampleAccurateGainValuesFrom(
    const AudioBus& source_bus,
    float* gain_values,
    unsigned number_of_gain_values) {
  // Make sure we're processing from the same type of bus.
  // We *are* able to process from mono -> stereo
  if (source_bus.NumberOfChannels() != 1 && !TopologyMatches(source_bus)) {
    NOTREACHED();
  }

  if (!gain_values || number_of_gain_values > source_bus.length()) {
    NOTREACHED();
  }

  if (source_bus.length() == number_of_gain_values &&
      source_bus.length() == length() && source_bus.IsSilent()) {
    Zero();
    return;
  }

  // We handle both the 1 -> N and N -> N case here.
  const float* source = source_bus.Channel(0)->Data();
  for (unsigned channel_index = 0; channel_index < NumberOfChannels();
       ++channel_index) {
    if (source_bus.NumberOfChannels() == NumberOfChannels()) {
      source = source_bus.Channel(channel_index)->Data();
    }
    float* destination = Channel(channel_index)->MutableData();
    vector_math::Vmul(source, 1, gain_values, 1, destination, 1,
                      number_of_gain_values);
  }
}

scoped_refptr<AudioBus> AudioBus::CreateBySampleRateConverting(
    const AudioBus* source_bus,
    bool mix_to_mono,
    double new_sample_rate) {
  // sourceBus's sample-rate must be known.
  DCHECK(source_bus);
  DCHECK(source_bus->SampleRate());
  if (!source_bus || !source_bus->SampleRate()) {
    return nullptr;
  }

  double source_sample_rate = source_bus->SampleRate();
  double destination_sample_rate = new_sample_rate;
  double sample_rate_ratio = source_sample_rate / destination_sample_rate;
  unsigned number_of_source_channels = source_bus->NumberOfChannels();

  if (number_of_source_channels == 1) {
    mix_to_mono = false;  // already mono
  }

  if (source_sample_rate == destination_sample_rate) {
    // No sample-rate conversion is necessary.
    if (mix_to_mono) {
      return AudioBus::CreateByMixingToMono(source_bus);
    }

    // Return exact copy.
    return AudioBus::CreateBufferFromRange(source_bus, 0, source_bus->length());
  }

  if (source_bus->IsSilent()) {
    scoped_refptr<AudioBus> silent_bus = Create(
        number_of_source_channels, source_bus->length() / sample_rate_ratio);
    silent_bus->SetSampleRate(new_sample_rate);
    return silent_bus;
  }

  // First, mix to mono (if necessary) then sample-rate convert.
  const AudioBus* resampler_source_bus;
  scoped_refptr<AudioBus> mixed_mono_bus;
  if (mix_to_mono) {
    mixed_mono_bus = AudioBus::CreateByMixingToMono(source_bus);
    resampler_source_bus = mixed_mono_bus.get();
  } else {
    // Directly resample without down-mixing.
    resampler_source_bus = source_bus;
  }

  // Calculate destination length based on the sample-rates.
  int source_length = resampler_source_bus->length();
  int destination_length = source_length / sample_rate_ratio;

  // Create destination bus with same number of channels.
  unsigned number_of_destination_channels =
      resampler_source_bus->NumberOfChannels();
  scoped_refptr<AudioBus> destination_bus =
      Create(number_of_destination_channels, destination_length);

  // Sample-rate convert each channel.
  for (unsigned i = 0; i < number_of_destination_channels; ++i) {
    const float* source = resampler_source_bus->Channel(i)->Data();
    float* destination = destination_bus->Channel(i)->MutableData();

    SincResampler resampler(sample_rate_ratio);
    resampler.Process(source, destination, source_length);
  }

  destination_bus->ClearSilentFlag();
  destination_bus->SetSampleRate(new_sample_rate);
  return destination_bus;
}

scoped_refptr<AudioBus> AudioBus::CreateByMixingToMono(
    const AudioBus* source_bus) {
  if (source_bus->IsSilent()) {
    return Create(1, source_bus->length());
  }

  switch (source_bus->NumberOfChannels()) {
    case 1:
      // Simply create an exact copy.
      return AudioBus::CreateBufferFromRange(source_bus, 0,
                                             source_bus->length());
    case 2: {
      unsigned n = source_bus->length();
      scoped_refptr<AudioBus> destination_bus = Create(1, n);

      const float* source_l = source_bus->Channel(0)->Data();
      const float* source_r = source_bus->Channel(1)->Data();
      float* destination = destination_bus->Channel(0)->MutableData();

      // Do the mono mixdown.
      for (unsigned i = 0; i < n; ++i) {
        destination[i] = (source_l[i] + source_r[i]) / 2;
      }

      destination_bus->ClearSilentFlag();
      destination_bus->SetSampleRate(source_bus->SampleRate());
      return destination_bus;
    }
  }

  NOTREACHED();
}

bool AudioBus::IsSilent() const {
  return base::ranges::all_of(channels_, &AudioChannel::IsSilent);
}

void AudioBus::ClearSilentFlag() {
  for (AudioChannel& channel : channels_) {
    channel.ClearSilentFlag();
  }
}

scoped_refptr<AudioBus> DecodeAudioFileData(const char* data, size_t size) {
  WebAudioBus web_audio_bus;
  if (Platform::Current()->DecodeAudioFileData(&web_audio_bus, data, size)) {
    return web_audio_bus.Release();
  }
  return nullptr;
}

scoped_refptr<AudioBus> AudioBus::GetDataResource(int resource_id,
                                                  float sample_rate) {
  const WebData& resource = Platform::Current()->GetDataResource(resource_id);
  if (resource.IsEmpty()) {
    return nullptr;
  }

  // Currently, the only client of this method is caching the result -- so
  // it's reasonable to (potentially) pay a one-time flat access cost.
  // If this becomes problematic, we'll have the refactor DecodeAudioFileData
  // to take WebData and use segmented access.
  SegmentedBuffer::DeprecatedFlatData flat_data(
      resource.operator scoped_refptr<SharedBuffer>().get());
  scoped_refptr<AudioBus> audio_bus =
      DecodeAudioFileData(flat_data.data(), flat_data.size());

  if (!audio_bus.get()) {
    return nullptr;
  }

  // If the bus is already at the requested sample-rate then return as is.
  if (audio_bus->SampleRate() == sample_rate) {
    return audio_bus;
  }

  return AudioBus::CreateBySampleRateConverting(audio_bus.get(), false,
                                                sample_rate);
}

scoped_refptr<AudioBus> AudioBus::CreateBusFromInMemoryAudioFile(
    const void* data,
    size_t data_size,
    bool mix_to_mono,
    float sample_rate) {
  scoped_refptr<AudioBus> audio_bus =
      DecodeAudioFileData(static_cast<const char*>(data), data_size);
  if (!audio_bus.get()) {
    return nullptr;
  }

  // If the bus needs no conversion then return as is.
  if ((!mix_to_mono || audio_bus->NumberOfChannels() == 1) &&
      audio_bus->SampleRate() == sample_rate) {
    return audio_bus;
  }

  return AudioBus::CreateBySampleRateConverting(audio_bus.get(), mix_to_mono,
                                                sample_rate);
}

}  // namespace blink

"""

```