Response:
Let's break down the thought process for analyzing the provided C++ code. The goal is to understand its functionality, its relation to web technologies, and potential usage errors.

**1. Initial Understanding and High-Level Purpose:**

* **File Name and Path:** `blink/renderer/platform/audio/sinc_resampler.cc`. The path immediately tells us this is part of the Blink rendering engine, specifically within the audio processing domain. The "sinc_resampler" part strongly suggests it's related to resampling audio using a sinc function. Resampling means changing the sample rate of audio.

* **Copyright and License:**  The copyright notice indicates it's based on work from Google and Apple, under a BSD-style license. This is standard for Chromium code.

* **Includes:**  Looking at the included headers gives further clues:
    * `"third_party/blink/renderer/platform/audio/sinc_resampler.h"`:  The corresponding header file, likely containing class declarations and interface definitions.
    * `"base/memory/raw_ptr.h"`:  Deals with raw pointers and memory management (though note the comment about unsafe buffers).
    * `"build/build_config.h"`:  Build-related configuration.
    * `"third_party/blink/renderer/platform/audio/audio_bus.h"`:  Represents a multi-channel audio buffer, crucial for audio processing.
    * `"third_party/blink/renderer/platform/wtf/math_extras.h"`:  Likely contains mathematical constants and helper functions.
    * `"third_party/fdlibm/ieee754.h"`:  IEEE 754 floating-point math functions (standard for audio).
    * `<emmintrin.h>`:  SSE intrinsics for x86 SIMD optimizations. This suggests performance is a consideration.

* **Code Structure:** The code defines a `SincResampler` class. This is the core of the functionality.

**2. Deep Dive into Functionality:**

* **Constructor (`SincResampler::SincResampler`):**
    * Takes `scale_factor`, `kernel_size`, and `number_of_kernel_offsets` as arguments. These parameters are fundamental to the resampling process. `scale_factor` indicates the ratio between input and output sample rates. `kernel_size` relates to the length of the sinc filter. `number_of_kernel_offsets` allows for sub-sample precision.
    * Initializes member variables. The `kernel_storage_` suggests pre-calculated filter coefficients.
    * Calls `InitializeKernel()`.

* **`InitializeKernel()`:**
    * Calculates the windowed sinc function for different sub-sample offsets. This is the heart of the sinc resampling algorithm. It uses a Blackman window to reduce artifacts.
    * The comments explain the Blackman window and the `sinc_scale_factor` (cutoff frequency). This shows an understanding of signal processing principles.

* **`ConsumeSource()`:**
    * Takes a raw buffer and the number of frames.
    * Creates an `AudioBus` to wrap the buffer, making it usable with the `AudioSourceProvider` interface.

* **`BufferSourceProvider` (nested class):**
    * A helper class that implements `AudioSourceProvider` for in-memory buffers. This is useful for testing and for simple resampling tasks where the entire audio data is available.
    * The `ProvideInput()` method handles copying data and zero-padding if needed.

* **`Process(const float* source, ...)`:**
    * A convenience overload that takes a raw input buffer and uses `BufferSourceProvider`.
    * Divides the processing into blocks.

* **`Process(AudioSourceProvider* source_provider, ...)`:**
    * The main processing function. It takes an `AudioSourceProvider`, allowing for various sources of audio data.
    * Implements the core resampling algorithm described in the comments. The comments about buffer layout (r0-r5) are crucial for understanding the buffering strategy.
    * The algorithm involves consuming input, applying the sinc filter (convolution), and advancing the virtual source index.
    * **SIMD Optimizations:**  The `#if defined(ARCH_CPU_X86_FAMILY)` block shows the use of SSE intrinsics for performance on x86 architectures. This is a key optimization.
    * **Unrolled Loops:**  The handling of `n == 32` and `n == 64` suggests further scalar optimizations by unrolling loops, which can reduce loop overhead.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **AudioContext and Web Audio API:** The primary connection is through the Web Audio API in JavaScript. The `SincResampler` is a low-level component that enables the browser to handle audio playback and processing at different sample rates.
* **`<audio>` and `<video>` elements:** When these elements play audio, the browser might need to resample the audio to match the output device's sample rate. The `SincResampler` could be used internally for this.
* **`OfflineAudioContext`:** This API allows for rendering audio without playing it back immediately. Resampling is often necessary in this context.
* **No Direct CSS Relationship:**  CSS is for styling and layout, so there's no direct functional relationship.

**4. Logical Reasoning and Examples:**

* **Assumptions:** The core assumption is that the sinc function provides a good approximation of an ideal low-pass filter, which is necessary for preventing aliasing during downsampling and reconstructing the signal during upsampling.

* **Input/Output Examples:**
    * **Input:** Audio buffer at 48kHz, `scale_factor` = 44.1/48 (downsampling).
    * **Output:** Resampled audio buffer at 44.1kHz.

    * **Input:** Audio buffer at 44.1kHz, `scale_factor` = 48/44.1 (upsampling).
    * **Output:** Resampled audio buffer at 48kHz.

    * **Input:**  A single sine wave at 440Hz, 48kHz sample rate.
    * **Output (downsampled to 24kHz):**  A sine wave at 440Hz, but now represented with fewer samples per second.

**5. Common Usage Errors:**

* **Incorrect `scale_factor`:** Providing a `scale_factor` that's zero or negative would be a critical error, leading to division by zero or undefined behavior.
* **Mismatched Sample Rates:**  If the user provides audio data at a sample rate that doesn't align with the expected input rate of the resampler (based on the `scale_factor`), the output will be incorrect. This often happens when users try to process audio from different sources without proper conversion.
* **Insufficient Input Data:**  If the `AudioSourceProvider` doesn't provide enough data to the `Process()` method, the output might be incomplete or contain artifacts. The zero-padding helps mitigate this, but it's still a potential issue.
* **Buffer Overflows (Potential):** Although the code seems to manage buffers carefully, incorrect calculations of buffer sizes or indices could lead to buffer overflows, especially in the SIMD optimized sections if alignment is not handled correctly. The `#pragma allow_unsafe_buffers` suggests this might be a concern in some build configurations.
* **Not Understanding `kernel_size`:**  Using a `kernel_size` that is too small can lead to poor filtering and aliasing. A kernel size that's too large increases computational cost. The user wouldn't directly set this in web APIs, but it's an internal parameter that affects quality.

By following this thought process, combining code inspection with knowledge of audio processing and web technologies, we can arrive at a comprehensive understanding of the `SincResampler`'s function and its role.
这个 `sinc_resampler.cc` 文件是 Chromium Blink 引擎中负责音频重采样的核心组件。它使用 sinc 函数插值来实现高质量的音频采样率转换。

以下是其主要功能和相关说明：

**主要功能:**

1. **音频采样率转换 (Resampling):**  `SincResampler` 的主要目的是将音频数据的采样率从一个频率转换为另一个频率。这在 Web 浏览器中至关重要，因为音频源可能具有不同的采样率，而音频输出设备也有其特定的采样率。为了确保音频能够正确播放，需要在必要时进行重采样。

2. **高质量插值:** 它使用基于 sinc 函数的插值方法。Sinc 函数是一种理想的低通滤波器，可以最大限度地减少重采样过程中引入的失真和混叠（aliasing）。为了实用性，sinc 函数会被窗口化（例如使用 Blackman 窗口）以限制其长度并减少振铃效应。

3. **亚采样精度 (Sub-sample Accuracy):**  通过 `number_of_kernel_offsets_` 参数和预先计算的多个 sinc 滤波器内核，`SincResampler` 实现了亚采样精度的插值。这意味着它可以更精确地计算出目标采样点的值，即使目标采样点不在原始采样点的精确位置上。

4. **分块处理 (Block-based Processing):**  为了高效处理音频数据，`SincResampler` 将输入音频分成固定大小的块 (`block_size_`) 进行处理。这有助于管理内存并优化性能。

5. **缓存管理 (Buffer Management):**  为了实现平滑的重采样，`SincResampler` 使用一个内部缓冲区 (`input_buffer_`) 来存储一部分输入音频数据。这个缓冲区允许算法在需要未来或过去的数据点时能够访问它们，这是 sinc 插值所必需的。

6. **优化的实现:**  代码中包含针对 x86 架构的 SSE 指令优化，可以显著提高重采样性能。  对于其他架构，也可能存在或未来会添加类似的优化（例如 ARM NEON）。

7. **支持不同的音频来源:**  通过 `AudioSourceProvider` 接口，`SincResampler` 可以处理来自不同来源的音频数据，包括内存中的缓冲区和实时音频流。

**与 JavaScript, HTML, CSS 的关系:**

`SincResampler` 位于浏览器引擎的底层，直接与 JavaScript 的 Web Audio API 相关联。

* **JavaScript (Web Audio API):**
    * **`AudioContext`:**  当你在 JavaScript 中使用 `AudioContext` 创建音频节点（如 `OscillatorNode`, `AudioBufferSourceNode`, `MediaElementAudioSourceNode` 等）时，这些节点产生的或读取的音频数据可能具有不同的采样率。
    * **`AudioNode.connect()`:** 当你将一个音频节点的输出连接到另一个输入采样率不同的音频节点时，浏览器可能需要在内部使用 `SincResampler` 来转换采样率，以保证音频数据的兼容性。例如，你可能将一个 48kHz 的音频源连接到一个运行在 44.1kHz 的 `AudioContext` 上，这时就需要进行重采样。
    * **`OfflineAudioContext`:** 在使用 `OfflineAudioContext` 进行音频渲染时，`SincResampler` 也扮演着重要的角色，确保最终渲染的音频具有正确的采样率。
    * **例程:**
      ```javascript
      const audioContext = new AudioContext({ sampleRate: 44100 });
      const oscillator = audioContext.createOscillator();
      // 假设这个音频文件是 48000Hz 采样率
      const audioBufferSource = audioContext.createBufferSource();
      audioBufferSource.buffer = my48kHzaudioBuffer;

      // 连接时可能触发内部的重采样
      oscillator.connect(audioContext.destination);
      audioBufferSource.connect(audioContext.destination);

      oscillator.start();
      audioBufferSource.start();
      ```

* **HTML (`<audio>`, `<video>`):**
    * 当 HTML5 的 `<audio>` 或 `<video>` 元素播放音频时，浏览器可能需要使用 `SincResampler` 将音频文件的采样率转换为音频输出设备的采样率。例如，一个 MP3 文件可能是 44.1kHz，而用户的声卡可能支持 48kHz 或其他采样率。

* **CSS:**  CSS 主要负责样式和布局，与 `SincResampler` 的功能没有直接关系。

**逻辑推理与假设输入输出:**

假设我们有一个 `SincResampler` 实例，其 `scale_factor_` 小于 1 (例如 0.5，表示降采样)，并且 `block_size_` 为 10，`kernel_size_` 为 8。

**假设输入:** 一个包含 20 个浮点数的输入音频缓冲区，代表原始采样率的 20 个样本： `[1.0, 0.8, 0.6, 0.4, 0.2, 0.0, -0.2, -0.4, -0.6, -0.8, -1.0, -0.8, -0.6, -0.4, -0.2, 0.0, 0.2, 0.4, 0.6, 0.8]`

**假设输出:**  由于 `scale_factor_` 是 0.5，输出采样率将是输入采样率的一半。对于每两个输入样本，`SincResampler` 会计算出一个输出样本。考虑到 sinc 插值的特性，输出样本的值将是周围多个输入样本的加权平均。  简化起见，我们假设插值过程是理想的：

第一块处理 (假设 `block_size_` 为 10，并且已经 prime 过 buffer)：

1. `virtual_source_index_` 从 0 开始。
2. 对于第一个输出样本，它会查看输入缓冲区中以索引 0 附近为中心的 `kernel_size_` (8) 个样本，并应用 sinc 函数进行插值。输出一个样本。
3. `virtual_source_index_` 增加 `scale_factor_` (0.5)。
4. 对于第二个输出样本，它会查看输入缓冲区中以索引 0.5 附近为中心的 8 个样本进行插值。输出一个样本。
5. ... 以此类推，直到 `virtual_source_index_` 接近 `block_size_` (10)。

由于是降采样，理想情况下输出的样本数量应该大约是输入样本数量乘以 `scale_factor_`，即 20 * 0.5 = 10 个样本。  实际输出值会受到 sinc 函数的形状和窗口函数的影响。

**注意:**  实际的计算非常复杂，涉及到 sinc 函数的具体实现和窗口函数的应用。这里的例子只是概念性的。

**用户或编程常见的使用错误:**

1. **错误的 `scale_factor`:**
   * **错误:** 提供一个负数或零的 `scale_factor`。
   * **后果:** 可能导致程序崩溃或产生无法预测的输出。
   * **例子:** `SincResampler resampler(-0.5, 32, 10);`

2. **输入音频数据不足:**
   * **错误:** 在处理开始时或过程中，`AudioSourceProvider` 无法提供足够的音频数据。
   * **后果:**  可能导致输出音频出现静音、咔哒声或其他失真。`SincResampler` 内部虽然有零填充机制，但如果数据严重不足，仍然会产生问题。
   * **例子:**  假设一个实时音频流源中断了一段时间，导致 `source_provider_->ProvideInput()` 返回的数据量少于预期。

3. **假设输入和输出缓冲区大小不匹配:**
   * **错误:**  在调用 `Process` 函数时，假设目标缓冲区的大小不足以容纳所有重采样后的数据。
   * **后果:** 可能导致缓冲区溢出，程序崩溃或数据截断。
   * **例子:**  在 JavaScript 中计算输出缓冲区的大小时出现错误，分配的空间小于实际需要。

4. **不正确的内核大小 (`kernel_size`) 和内核偏移数 (`number_of_kernel_offsets`):**
   * **错误:** 使用不合适的 `kernel_size` 或 `number_of_kernel_offsets` 可能导致重采样质量下降。过小的内核可能导致混叠，过大的内核会增加计算成本。偏移数不足会降低亚采样精度。
   * **后果:** 输出音频质量不佳，可能出现失真。
   * **注意:** 这些参数通常由 Blink 引擎内部管理，用户不太可能直接设置错误的值。

5. **与多声道音频的误用 (假设 `SincResampler` 仅处理单声道):**
   * **错误:** 假设 `SincResampler` 被设计为仅处理单声道音频，但尝试用它处理多声道音频时没有正确地为每个声道创建实例或进行处理。
   * **后果:** 可能导致声道数据错乱或丢失。
   * **例子:**  对立体声音频数据调用单声道的 `SincResampler::Process`，没有对左右声道分别处理。

理解这些潜在的错误可以帮助开发者在使用 Web Audio API 或研究 Blink 引擎代码时更好地理解音频重采样的原理和可能出现的问题。

### 提示词
```
这是目录为blink/renderer/platform/audio/sinc_resampler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/audio/sinc_resampler.h"

#include "base/memory/raw_ptr.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/fdlibm/ieee754.h"

#if defined(ARCH_CPU_X86_FAMILY)
#include <emmintrin.h>
#endif

// Input buffer layout, dividing the total buffer into regions (r0 - r5):
//
// |----------------|-----------------------------------------|----------------|
//
//                                     blockSize + kernelSize / 2
//                   <--------------------------------------------------------->
//                                                r0
//
//   kernelSize / 2   kernelSize / 2          kernelSize / 2     kernelSize / 2
// <---------------> <--------------->       <---------------> <--------------->
//         r1                r2                      r3               r4
//
//                                                     blockSize
//                                    <---------------------------------------->
//                                                         r5

// The Algorithm:
//
// 1) Consume input frames into r0 (r1 is zero-initialized).
// 2) Position kernel centered at start of r0 (r2) and generate output frames
//    until kernel is centered at start of r4, or we've finished generating
//    all the output frames.
// 3) Copy r3 to r1 and r4 to r2.
// 4) Consume input frames into r5 (zero-pad if we run out of input).
// 5) Goto (2) until all of input is consumed.
//
// note: we're glossing over how the sub-sample handling works with
// m_virtualSourceIndex, etc.

namespace blink {

SincResampler::SincResampler(double scale_factor,
                             unsigned kernel_size,
                             unsigned number_of_kernel_offsets)
    : scale_factor_(scale_factor),
      kernel_size_(kernel_size),
      number_of_kernel_offsets_(number_of_kernel_offsets),
      kernel_storage_(kernel_size_ * (number_of_kernel_offsets_ + 1)),
      virtual_source_index_(0),
      block_size_(512),
      // See input buffer layout above.
      input_buffer_(block_size_ + kernel_size_),
      source_(nullptr),
      source_frames_available_(0),
      source_provider_(nullptr),
      is_buffer_primed_(false) {
  InitializeKernel();
}

void SincResampler::InitializeKernel() {
  // Blackman window parameters.
  double alpha = 0.16;
  double a0 = 0.5 * (1.0 - alpha);
  double a1 = 0.5;
  double a2 = 0.5 * alpha;

  // sincScaleFactor is basically the normalized cutoff frequency of the
  // low-pass filter.
  double sinc_scale_factor = scale_factor_ > 1.0 ? 1.0 / scale_factor_ : 1.0;

  // The sinc function is an idealized brick-wall filter, but since we're
  // windowing it the transition from pass to stop does not happen right away.
  // So we should adjust the lowpass filter cutoff slightly downward to avoid
  // some aliasing at the very high-end.
  // FIXME: this value is empirical and to be more exact should vary depending
  // on m_kernelSize.
  sinc_scale_factor *= 0.9;

  int n = kernel_size_;
  int half_size = n / 2;

  // Generates a set of windowed sinc() kernels.
  // We generate a range of sub-sample offsets from 0.0 to 1.0.
  for (unsigned offset_index = 0; offset_index <= number_of_kernel_offsets_;
       ++offset_index) {
    double subsample_offset =
        static_cast<double>(offset_index) / number_of_kernel_offsets_;

    for (int i = 0; i < n; ++i) {
      // Compute the sinc() with offset.
      double s =
          sinc_scale_factor * kPiDouble * (i - half_size - subsample_offset);
      double sinc = !s ? 1.0 : fdlibm::sin(s) / s;
      sinc *= sinc_scale_factor;

      // Compute Blackman window, matching the offset of the sinc().
      double x = (i - subsample_offset) / n;
      double window = a0 - a1 * fdlibm::cos(kTwoPiDouble * x) +
                      a2 * fdlibm::cos(kTwoPiDouble * 2.0 * x);

      // Window the sinc() function and store at the correct offset.
      kernel_storage_[i + offset_index * kernel_size_] = sinc * window;
    }
  }
}

void SincResampler::ConsumeSource(float* buffer,
                                  unsigned number_of_source_frames) {
  DCHECK(source_provider_);

  // Wrap the provided buffer by an AudioBus for use by the source provider.
  scoped_refptr<AudioBus> bus =
      AudioBus::Create(1, number_of_source_frames, false);

  // FIXME: Find a way to make the following const-correct:
  bus->SetChannelMemory(0, buffer, number_of_source_frames);

  source_provider_->ProvideInput(
      bus.get(), base::checked_cast<int>(number_of_source_frames));
}

namespace {

// BufferSourceProvider is an AudioSourceProvider wrapping an in-memory buffer.

class BufferSourceProvider final : public AudioSourceProvider {
 public:
  BufferSourceProvider(const float* source, int number_of_source_frames)
      : source_(source), source_frames_available_(number_of_source_frames) {}

  // Consumes samples from the in-memory buffer.
  void ProvideInput(AudioBus* bus, int frames_to_process) override {
    DCHECK(source_);
    DCHECK(bus);
    if (!source_ || !bus) {
      return;
    }

    float* buffer = bus->Channel(0)->MutableData();

    // Clamp to number of frames available and zero-pad.
    int frames_to_copy = std::min(source_frames_available_, frames_to_process);
    memcpy(buffer, source_, sizeof(float) * frames_to_copy);

    // Zero-pad if necessary.
    if (frames_to_copy < frames_to_process) {
      memset(buffer + frames_to_copy, 0,
             sizeof(float) * (frames_to_process - frames_to_copy));
    }

    source_frames_available_ -= frames_to_copy;
    source_ += frames_to_copy;
  }

 private:
  raw_ptr<const float, AllowPtrArithmetic> source_;
  int source_frames_available_;
};

}  // namespace

void SincResampler::Process(const float* source,
                            float* destination,
                            int number_of_source_frames) {
  // Resample an in-memory buffer using an AudioSourceProvider.
  BufferSourceProvider source_provider(source, number_of_source_frames);

  unsigned number_of_destination_frames =
      static_cast<unsigned>(number_of_source_frames / scale_factor_);
  unsigned remaining = number_of_destination_frames;

  while (remaining) {
    unsigned frames_this_time = std::min(remaining, block_size_);
    Process(&source_provider, destination, frames_this_time);

    destination += frames_this_time;
    remaining -= frames_this_time;
  }
}

void SincResampler::Process(AudioSourceProvider* source_provider,
                            float* destination,
                            uint32_t frames_to_process) {
  DCHECK(source_provider);
  DCHECK_GT(block_size_, kernel_size_);
  DCHECK_GE(input_buffer_.size(), block_size_ + kernel_size_);
  DCHECK_EQ(kernel_size_ % 2, 0u);

  source_provider_ = source_provider;

  unsigned number_of_destination_frames = frames_to_process;

  // Setup various region pointers in the buffer (see diagram above).
  float* r0 = input_buffer_.Data() + kernel_size_ / 2;
  float* r1 = input_buffer_.Data();
  float* r2 = r0;
  float* r3 = r0 + block_size_ - kernel_size_ / 2;
  float* r4 = r0 + block_size_;
  float* r5 = r0 + kernel_size_ / 2;

  // Step (1)
  // Prime the input buffer at the start of the input stream.
  if (!is_buffer_primed_) {
    ConsumeSource(r0, block_size_ + kernel_size_ / 2);
    is_buffer_primed_ = true;
  }

  // Step (2)

  while (number_of_destination_frames) {
    while (virtual_source_index_ < block_size_) {
      // m_virtualSourceIndex lies in between two kernel offsets so figure out
      // what they are.
      int source_index_i = static_cast<int>(virtual_source_index_);
      double subsample_remainder = virtual_source_index_ - source_index_i;

      double virtual_offset_index =
          subsample_remainder * number_of_kernel_offsets_;
      int offset_index = static_cast<int>(virtual_offset_index);

      float* k1 = kernel_storage_.Data() + offset_index * kernel_size_;
      float* k2 = k1 + kernel_size_;

      // Initialize input pointer based on quantized m_virtualSourceIndex.
      float* input_p = r1 + source_index_i;

      // We'll compute "convolutions" for the two kernels which straddle
      // m_virtualSourceIndex
      float sum1 = 0;
      float sum2 = 0;

      // Figure out how much to weight each kernel's "convolution".
      double kernel_interpolation_factor = virtual_offset_index - offset_index;

      // Generate a single output sample.
      int n = kernel_size_;

#define CONVOLVE_ONE_SAMPLE() \
  do {                        \
    input = *input_p++;       \
    sum1 += input * *k1;      \
    sum2 += input * *k2;      \
    ++k1;                     \
    ++k2;                     \
  } while (0)

      {
        float input;

#if defined(ARCH_CPU_X86_FAMILY)
        // If the sourceP address is not 16-byte aligned, the first several
        // frames (at most three) should be processed seperately.
        while ((reinterpret_cast<uintptr_t>(input_p) & 0x0F) && n) {
          CONVOLVE_ONE_SAMPLE();
          n--;
        }

        // Now the inputP is aligned and start to apply SSE.
        float* end_p = input_p + n - n % 4;
        __m128 m_input;
        __m128 m_k1;
        __m128 m_k2;
        __m128 mul1;
        __m128 mul2;

        __m128 sums1 = _mm_setzero_ps();
        __m128 sums2 = _mm_setzero_ps();
        bool k1_aligned = !(reinterpret_cast<uintptr_t>(k1) & 0x0F);
        bool k2_aligned = !(reinterpret_cast<uintptr_t>(k2) & 0x0F);

#define LOAD_DATA(l1, l2)           \
  do {                              \
    m_input = _mm_load_ps(input_p); \
    m_k1 = _mm_##l1##_ps(k1);       \
    m_k2 = _mm_##l2##_ps(k2);       \
  } while (0)

#define CONVOLVE_4_SAMPLES()          \
  do {                                \
    mul1 = _mm_mul_ps(m_input, m_k1); \
    mul2 = _mm_mul_ps(m_input, m_k2); \
    sums1 = _mm_add_ps(sums1, mul1);  \
    sums2 = _mm_add_ps(sums2, mul2);  \
    input_p += 4;                     \
    k1 += 4;                          \
    k2 += 4;                          \
  } while (0)

        if (k1_aligned && k2_aligned) {  // both aligned
          while (input_p < end_p) {
            LOAD_DATA(load, load);
            CONVOLVE_4_SAMPLES();
          }
        } else if (!k1_aligned && k2_aligned) {  // only k2 aligned
          while (input_p < end_p) {
            LOAD_DATA(loadu, load);
            CONVOLVE_4_SAMPLES();
          }
        } else if (k1_aligned && !k2_aligned) {  // only k1 aligned
          while (input_p < end_p) {
            LOAD_DATA(load, loadu);
            CONVOLVE_4_SAMPLES();
          }
        } else {  // both non-aligned
          while (input_p < end_p) {
            LOAD_DATA(loadu, loadu);
            CONVOLVE_4_SAMPLES();
          }
        }

        // Summarize the SSE results to sum1 and sum2.
        float* group_sum_p = reinterpret_cast<float*>(&sums1);
        sum1 +=
            group_sum_p[0] + group_sum_p[1] + group_sum_p[2] + group_sum_p[3];
        group_sum_p = reinterpret_cast<float*>(&sums2);
        sum2 +=
            group_sum_p[0] + group_sum_p[1] + group_sum_p[2] + group_sum_p[3];

        n %= 4;
        while (n) {
          CONVOLVE_ONE_SAMPLE();
          n--;
        }
#else
        // FIXME: add ARM NEON optimizations for the following. The scalar
        // code-path can probably also be optimized better.

        // Optimize size 32 and size 64 kernels by unrolling the while loop.
        // A 20 - 30% speed improvement was measured in some cases by using this
        // approach.

        if (n == 32) {
          CONVOLVE_ONE_SAMPLE();  // 1
          CONVOLVE_ONE_SAMPLE();  // 2
          CONVOLVE_ONE_SAMPLE();  // 3
          CONVOLVE_ONE_SAMPLE();  // 4
          CONVOLVE_ONE_SAMPLE();  // 5
          CONVOLVE_ONE_SAMPLE();  // 6
          CONVOLVE_ONE_SAMPLE();  // 7
          CONVOLVE_ONE_SAMPLE();  // 8
          CONVOLVE_ONE_SAMPLE();  // 9
          CONVOLVE_ONE_SAMPLE();  // 10
          CONVOLVE_ONE_SAMPLE();  // 11
          CONVOLVE_ONE_SAMPLE();  // 12
          CONVOLVE_ONE_SAMPLE();  // 13
          CONVOLVE_ONE_SAMPLE();  // 14
          CONVOLVE_ONE_SAMPLE();  // 15
          CONVOLVE_ONE_SAMPLE();  // 16
          CONVOLVE_ONE_SAMPLE();  // 17
          CONVOLVE_ONE_SAMPLE();  // 18
          CONVOLVE_ONE_SAMPLE();  // 19
          CONVOLVE_ONE_SAMPLE();  // 20
          CONVOLVE_ONE_SAMPLE();  // 21
          CONVOLVE_ONE_SAMPLE();  // 22
          CONVOLVE_ONE_SAMPLE();  // 23
          CONVOLVE_ONE_SAMPLE();  // 24
          CONVOLVE_ONE_SAMPLE();  // 25
          CONVOLVE_ONE_SAMPLE();  // 26
          CONVOLVE_ONE_SAMPLE();  // 27
          CONVOLVE_ONE_SAMPLE();  // 28
          CONVOLVE_ONE_SAMPLE();  // 29
          CONVOLVE_ONE_SAMPLE();  // 30
          CONVOLVE_ONE_SAMPLE();  // 31
          CONVOLVE_ONE_SAMPLE();  // 32
        } else if (n == 64) {
          CONVOLVE_ONE_SAMPLE();  // 1
          CONVOLVE_ONE_SAMPLE();  // 2
          CONVOLVE_ONE_SAMPLE();  // 3
          CONVOLVE_ONE_SAMPLE();  // 4
          CONVOLVE_ONE_SAMPLE();  // 5
          CONVOLVE_ONE_SAMPLE();  // 6
          CONVOLVE_ONE_SAMPLE();  // 7
          CONVOLVE_ONE_SAMPLE();  // 8
          CONVOLVE_ONE_SAMPLE();  // 9
          CONVOLVE_ONE_SAMPLE();  // 10
          CONVOLVE_ONE_SAMPLE();  // 11
          CONVOLVE_ONE_SAMPLE();  // 12
          CONVOLVE_ONE_SAMPLE();  // 13
          CONVOLVE_ONE_SAMPLE();  // 14
          CONVOLVE_ONE_SAMPLE();  // 15
          CONVOLVE_ONE_SAMPLE();  // 16
          CONVOLVE_ONE_SAMPLE();  // 17
          CONVOLVE_ONE_SAMPLE();  // 18
          CONVOLVE_ONE_SAMPLE();  // 19
          CONVOLVE_ONE_SAMPLE();  // 20
          CONVOLVE_ONE_SAMPLE();  // 21
          CONVOLVE_ONE_SAMPLE();  // 22
          CONVOLVE_ONE_SAMPLE();  // 23
          CONVOLVE_ONE_SAMPLE();  // 24
          CONVOLVE_ONE_SAMPLE();  // 25
          CONVOLVE_ONE_SAMPLE();  // 26
          CONVOLVE_ONE_SAMPLE();  // 27
          CONVOLVE_ONE_SAMPLE();  // 28
          CONVOLVE_ONE_SAMPLE();  // 29
          CONVOLVE_ONE_SAMPLE();  // 30
          CONVOLVE_ONE_SAMPLE();  // 31
          CONVOLVE_ONE_SAMPLE();  // 32
          CONVOLVE_ONE_SAMPLE();  // 33
          CONVOLVE_ONE_SAMPLE();  // 34
          CONVOLVE_ONE_SAMPLE();  // 35
          CONVOLVE_ONE_SAMPLE();  // 36
          CONVOLVE_ONE_SAMPLE();  // 37
          CONVOLVE_ONE_SAMPLE();  // 38
          CONVOLVE_ONE_SAMPLE();  // 39
          CONVOLVE_ONE_SAMPLE();  // 40
          CONVOLVE_ONE_SAMPLE();  // 41
          CONVOLVE_ONE_SAMPLE();  // 42
          CONVOLVE_ONE_SAMPLE();  // 43
          CONVOLVE_ONE_SAMPLE();  // 44
          CONVOLVE_ONE_SAMPLE();  // 45
          CONVOLVE_ONE_SAMPLE();  // 46
          CONVOLVE_ONE_SAMPLE();  // 47
          CONVOLVE_ONE_SAMPLE();  // 48
          CONVOLVE_ONE_SAMPLE();  // 49
          CONVOLVE_ONE_SAMPLE();  // 50
          CONVOLVE_ONE_SAMPLE();  // 51
          CONVOLVE_ONE_SAMPLE();  // 52
          CONVOLVE_ONE_SAMPLE();  // 53
          CONVOLVE_ONE_SAMPLE();  // 54
          CONVOLVE_ONE_SAMPLE();  // 55
          CONVOLVE_ONE_SAMPLE();  // 56
          CONVOLVE_ONE_SAMPLE();  // 57
          CONVOLVE_ONE_SAMPLE();  // 58
          CONVOLVE_ONE_SAMPLE();  // 59
          CONVOLVE_ONE_SAMPLE();  // 60
          CONVOLVE_ONE_SAMPLE();  // 61
          CONVOLVE_ONE_SAMPLE();  // 62
          CONVOLVE_ONE_SAMPLE();  // 63
          CONVOLVE_ONE_SAMPLE();  // 64
        } else {
          while (n--) {
            // Non-optimized using actual while loop.
            CONVOLVE_ONE_SAMPLE();
          }
        }
#endif
      }
#undef CONVOLVE_ONE_SAMPLE

      // Linearly interpolate the two "convolutions".
      double result = (1.0 - kernel_interpolation_factor) * sum1 +
                      kernel_interpolation_factor * sum2;

      *destination++ = result;

      // Advance the virtual index.
      virtual_source_index_ += scale_factor_;

      --number_of_destination_frames;
      if (!number_of_destination_frames) {
        return;
      }
    }

    // Wrap back around to the start.
    virtual_source_index_ -= block_size_;

    // Step (3) Copy r3 to r1 and r4 to r2.
    // This wraps the last input frames back to the start of the buffer.
    memcpy(r1, r3, sizeof(float) * (kernel_size_ / 2));
    memcpy(r2, r4, sizeof(float) * (kernel_size_ / 2));

    // Step (4)
    // Refresh the buffer with more input.
    ConsumeSource(r5, block_size_);
  }
}

}  // namespace blink
```