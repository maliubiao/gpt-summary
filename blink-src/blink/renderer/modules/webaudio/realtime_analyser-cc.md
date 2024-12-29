Response:
Let's break down the thought process for analyzing the `realtime_analyser.cc` file.

1. **Initial Scan and High-Level Understanding:**

   - The filename `realtime_analyser.cc` and the `webaudio` directory immediately suggest this code is related to real-time audio analysis in a web browser.
   - The copyright notice indicates it's part of the Chromium/Blink project.
   - The included headers (`audio_bus.h`, `audio_utilities.h`, `vector_math.h`, `FFTFrame.h`) hint at core functionalities like audio signal processing, Fast Fourier Transform (FFT), and vector operations.

2. **Identifying Key Classes and Members:**

   - The class `RealtimeAnalyser` is the central focus.
   - Its constructor takes `render_quantum_frames` as an argument, implying it operates on chunks of audio data.
   - Member variables like `input_buffer_`, `down_mix_bus_`, `fft_size_`, `magnitude_buffer_`, `smoothing_time_constant_`, `min_decibels_`, and `max_decibels_` point to its internal state and configuration.
   - The `analysis_frame_` of type `FFTFrame` confirms the use of FFT for analysis.

3. **Analyzing Public Methods (API):**

   - `SetFftSize()`:  Allows changing the FFT window size, a crucial parameter for frequency analysis. The validation logic (power of two, within bounds) is important.
   - `GetFloatFrequencyData()` and `GetByteFrequencyData()`:  These are the main methods for retrieving frequency domain data. The distinction between float and byte output is significant. The `current_time` parameter and the `last_analysis_time_` member suggest optimization to avoid redundant calculations.
   - `GetFloatTimeDomainData()` and `GetByteTimeDomainData()`: These methods provide access to the raw audio waveform data. Again, the float and byte variations exist.
   - `WriteInput()`: This is how audio data is fed into the analyzer. The downmixing aspect is notable.

4. **Analyzing Private/Internal Methods:**

   - `ApplyWindow()`:  Implements a Blackman window function, a standard technique for reducing spectral leakage in FFT.
   - `EnsureFinite()`: A utility function for handling potential NaN or infinite values, indicating robustness considerations.
   - `DoFFTAnalysis()`: This is the core processing method: buffering, windowing, FFT, and magnitude calculation. The smoothing logic (`smoothing_time_constant_`) is present.
   - `ConvertToByteData()` and `ConvertFloatToDb()`: These handle the conversion of magnitude data into the format requested by the JavaScript API (byte or float, potentially in decibels).

5. **Tracing the Data Flow:**

   - Audio data comes in through `WriteInput()`.
   - It's stored in `input_buffer_`.
   - When `Get...Data()` is called and the time has advanced, `DoFFTAnalysis()` is triggered.
   - `DoFFTAnalysis()` extracts a chunk from `input_buffer_`, applies the window function, performs the FFT, calculates magnitudes, and applies smoothing.
   - `ConvertToByteData()` or `ConvertFloatToDb()` then formats the magnitude data for return to JavaScript.

6. **Considering Interactions with JavaScript, HTML, and CSS:**

   - The methods returning `DOMFloat32Array` and `DOMUint8Array` directly link to JavaScript's `Float32Array` and `Uint8Array`, used in the Web Audio API.
   - The properties controlled by JavaScript (like `fftSize`, `smoothingTimeConstant`, `minDecibels`, `maxDecibels`) influence the behavior of this C++ code.
   - While CSS doesn't directly interact with this specific file, the visualization of the audio analysis results (frequency bars, waveforms) in a web page *is* often done using CSS styling applied to HTML elements that are updated based on the data returned by these methods.

7. **Identifying Potential Issues and Debugging Clues:**

   - The checks in `SetFftSize()` highlight common errors: using non-power-of-two sizes or values outside the allowed range.
   - The time-based logic in `Get...Data()` is important for understanding when the analysis is actually performed.
   - The buffer management and modulo arithmetic in `GetTimeDomainData()` can be a source of errors if not handled correctly.

8. **Formulating Examples and Explanations:**

   - Based on the analysis, construct concrete examples of JavaScript code using the `AnalyserNode` (the JavaScript counterpart).
   - Explain how changes in JavaScript properties affect the internal C++ state.
   - Illustrate how user actions in a web page (e.g., playing audio) lead to the execution of this code.

9. **Refinement and Organization:**

   - Structure the analysis into logical sections (functionality, JavaScript interaction, logic, errors, debugging).
   - Use clear and concise language.
   - Provide code snippets where helpful.
   - Ensure the examples are realistic and demonstrate the concepts effectively.

By following these steps, we can systematically dissect the `realtime_analyser.cc` file, understand its purpose, its interactions with the web platform, and potential issues that might arise. The process involves a mix of code reading, domain knowledge (audio processing, web development), and logical deduction.
这个文件 `blink/renderer/modules/webaudio/realtime_analyser.cc` 是 Chromium Blink 引擎中 Web Audio API 的一部分，它实现了 `AnalyserNode` 接口的功能。`AnalyserNode` 允许开发者获取音频数据的实时分析信息，例如频谱数据和波形数据。

**功能列举：**

1. **实时音频数据捕获:**  `RealtimeAnalyser` 对象会捕获连接到它的音频流的实时数据。这通过 `WriteInput` 方法实现，该方法接收来自 `AudioBus` 的音频数据。
2. **频域分析 (FFT):**  它执行快速傅里叶变换 (FFT) 来将时域的音频信号转换为频域表示，从而得到音频的频谱信息。`DoFFTAnalysis` 方法负责执行 FFT。
3. **时域分析:** 它也保留了时域的音频波形数据，可以通过 `GetFloatTimeDomainData` 和 `GetByteTimeDomainData` 方法获取。
4. **频谱数据获取:**  提供方法来获取频谱数据，格式可以是浮点数 (分贝值) 或无符号字节 (`GetFloatFrequencyData`, `GetByteFrequencyData`)。
5. **波形数据获取:** 提供方法来获取时域波形数据，格式可以是浮点数或无符号字节 (`GetFloatTimeDomainData`, `GetByteTimeDomainData`)。
6. **可配置的 FFT 大小:** 允许开发者通过 `fftSize` 属性设置 FFT 的大小，这决定了频谱分析的精度和频率分辨率 (`SetFftSize`)。
7. **平滑处理:**  支持通过 `smoothingTimeConstant` 属性设置频谱数据的平滑程度，以减少频谱的抖动。
8. **分贝范围控制:**  允许通过 `minDecibels` 和 `maxDecibels` 属性设置频谱数据转换为字节时的分贝范围，从而控制频谱图的显示范围。
9. **窗口函数应用:**  在执行 FFT 之前，会对音频数据应用窗口函数（默认为 Blackman 窗口），以减少频谱泄漏。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`RealtimeAnalyser` 是 Web Audio API 的核心组成部分，因此与 JavaScript 紧密相关。开发者主要通过 JavaScript 来创建、配置和使用 `AnalyserNode`。

**JavaScript 交互:**

```javascript
// JavaScript 代码示例
const audioContext = new AudioContext();
const analyser = audioContext.createAnalyser();

// 设置 FFT 大小
analyser.fftSize = 2048;

// 设置平滑时间常数
analyser.smoothingTimeConstant = 0.8;

// 设置分贝范围
analyser.minDecibels = -100;
analyser.maxDecibels = -30;

// 获取频谱数据 (浮点数分贝值)
const frequencyDataFloatArray = new Float32Array(analyser.frequencyBinCount);
analyser.getFloatFrequencyData(frequencyDataFloatArray);

// 获取频谱数据 (字节)
const frequencyDataByteArray = new Uint8Array(analyser.frequencyBinCount);
analyser.getByteFrequencyData(frequencyDataByteArray);

// 获取波形数据 (浮点数)
const timeDomainDataFloatArray = new Float32Array(analyser.fftSize);
analyser.getFloatTimeDomainData(timeDomainDataFloatArray);

// 获取波形数据 (字节)
const timeDomainDataByteArray = new Uint8Array(analyser.fftSize);
analyser.getByteTimeDomainData(timeDomainDataByteArray);

// 将音频源连接到分析器
const source = audioContext.createMediaElementSource(document.getElementById('myAudio'));
source.connect(analyser);
analyser.connect(audioContext.destination); // 如果需要输出音频
```

* **`audioContext.createAnalyser()`:**  JavaScript 通过 `AudioContext` 创建 `AnalyserNode` 的实例，最终会对应到 C++ 的 `RealtimeAnalyser` 对象。
* **`analyser.fftSize = 2048;`:**  JavaScript 设置 `fftSize` 属性会调用 C++ 端的 `SetFftSize` 方法。
* **`analyser.getFloatFrequencyData(frequencyDataFloatArray);`:** JavaScript 调用这些方法会触发 C++ 端相应的 `GetFloatFrequencyData` 等方法，将分析结果填充到传入的 JavaScript 数组中。

**HTML 交互:**

HTML 主要提供音频源。例如，可以使用 `<audio>` 或 `<video>` 元素作为分析器的输入。

```html
<!-- HTML 代码示例 -->
<audio id="myAudio" src="audio.mp3" controls></audio>
```

JavaScript 可以获取这个 HTML 元素，并使用 `audioContext.createMediaElementSource()` 将其音频流连接到 `AnalyserNode`。

**CSS 交互:**

CSS 本身不直接与 `RealtimeAnalyser` 交互，但它通常用于**可视化**从 `AnalyserNode` 获取的音频分析数据。例如，可以使用 CSS 来绘制频谱图或波形图。

**举例说明:**

假设你想在网页上实时显示音频的频谱图：

1. **HTML:**  包含一个 `<canvas>` 元素，用于绘制频谱图。
2. **JavaScript:**
   - 获取 `<audio>` 元素作为音频源。
   - 创建 `AudioContext` 和 `AnalyserNode`。
   - 将音频源连接到分析器。
   - 创建一个循环，定时调用 `analyser.getByteFrequencyData()` 获取频谱数据。
   - 使用 Canvas API 根据获取的频谱数据绘制柱状图或其他形式的频谱可视化。
3. **CSS:**  可以用来样式化 `<canvas>` 元素。

**逻辑推理与假设输入输出：**

**假设输入:**  `RealtimeAnalyser` 接收到一个单声道音频信号，采样率为 44100Hz，帧大小为 128。

**假设配置:**
* `fftSize` 设置为 256。
* `smoothingTimeConstant` 设置为 0.8。

**逻辑推理 (以 `GetByteFrequencyData` 为例):**

1. **数据捕获:**  `WriteInput` 方法会将最近的 256 个音频采样点存储在内部缓冲区 `input_buffer_` 中。
2. **窗口函数:**  `DoFFTAnalysis` 会从 `input_buffer_` 中取出 256 个采样点，并应用 Blackman 窗口函数。
3. **FFT 计算:**  对加窗后的数据执行 FFT，得到 128 个复数频率分量。
4. **幅度计算:**  计算每个频率分量的幅度（模）。
5. **平滑处理:**  使用设定的 `smoothingTimeConstant` 对当前的幅度值和上次的幅度值进行加权平均，得到平滑后的幅度。
6. **分贝转换:**  将线性幅度值转换为分贝值。
7. **字节映射:**  根据 `minDecibels` 和 `maxDecibels` 的设置，将分贝值映射到 0-255 的无符号字节范围。

**假设输出 (近似):**

如果输入是一个 440Hz 的正弦波，那么 `GetByteFrequencyData` 获取到的 `Uint8Array` 大小为 128，其中索引对应于不同的频率。在接近 440Hz 对应的索引位置，字节值会接近 255（如果幅度足够大），而其他索引位置的字节值会比较小，接近 0。平滑处理会使这些值的变化更平滑，不会立即跳变到最大值或最小值。

**用户或编程常见的使用错误：**

1. **未连接音频源:**  创建了 `AnalyserNode` 但没有将其连接到任何音频源（例如 `MediaElementSource`, `OscillatorNode` 等），导致无法获取任何数据。
   ```javascript
   const analyser = audioContext.createAnalyser();
   // 错误：没有连接音频源
   // analyser.getByteFrequencyData(dataArray); // dataArray 将全是 0
   ```
2. **`fftSize` 设置不当:**  `fftSize` 必须是 2 的幂次方，并且在允许的范围内。设置不正确的值会导致 `SetFftSize` 返回 `false`，并且 FFT 分析可能无法进行或产生错误结果。
   ```javascript
   analyser.fftSize = 1000; // 错误：不是 2 的幂次方
   ```
3. **输出数组大小不匹配:**  传递给 `getByteFrequencyData` 或 `getFloatTimeDomainData` 等方法的数组大小与 `frequencyBinCount` 或 `fftSize` 不匹配，会导致数据截断或超出数组边界。
   ```javascript
   const frequencyData = new Uint8Array(10); // 错误：大小应该等于 analyser.frequencyBinCount
   analyser.getByteFrequencyData(frequencyData);
   ```
4. **频繁调用数据获取方法:**  在每个音频处理帧都调用数据获取方法可能会导致性能问题，特别是如果 FFT 大小很大。应该根据实际需要进行采样调用。
5. **误解分贝范围:**  不理解 `minDecibels` 和 `maxDecibels` 的作用，导致频谱图的显示范围不正确。如果 `maxDecibels` 设置得过低，可能会丢失高音量的信息。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户打开一个包含 Web Audio 功能的网页。**
2. **网页的 JavaScript 代码创建了一个 `AudioContext` 对象。**
3. **JavaScript 代码调用 `audioContext.createAnalyser()` 创建了一个 `AnalyserNode` 实例。** 这会在 Blink 渲染进程中创建一个对应的 `RealtimeAnalyser` 对象。
4. **JavaScript 代码可能设置了 `AnalyserNode` 的属性，例如 `fftSize`，`smoothingTimeConstant`，`minDecibels`，`maxDecibels`。**  这些设置会调用 `RealtimeAnalyser` 的相应方法。
5. **JavaScript 代码将一个音频源（例如 `<audio>` 元素或 `OscillatorNode`) 连接到 `AnalyserNode`。**  当音频源产生音频数据时，这些数据会被传递到 `RealtimeAnalyser` 的 `WriteInput` 方法。
6. **JavaScript 代码使用 `requestAnimationFrame` 或 `setInterval` 等机制定期调用 `analyser.getByteFrequencyData()` 或 `analyser.getFloatTimeDomainData()` 等方法。** 这会触发 `RealtimeAnalyser` 内部的 `DoFFTAnalysis`（如果需要获取频谱数据）并从内部缓冲区读取数据。
7. **`GetByteFrequencyData` 等方法会将结果填充到 JavaScript 传递的数组中。**
8. **JavaScript 代码可能会使用 Canvas API 或其他可视化库来渲染获取到的音频分析数据，并在网页上显示频谱图或波形图。**

**调试线索：**

如果在网页上看到的频谱图或波形图不正确，可以按照以下步骤进行调试，并可能最终追踪到 `realtime_analyser.cc` 中的代码：

1. **检查 JavaScript 代码:**  确认 `AnalyserNode` 是否已正确创建和配置，音频源是否已正确连接，数据获取方法是否被正确调用，以及输出数组的大小是否正确。
2. **使用浏览器的开发者工具:**
   - **Console:**  查看是否有 JavaScript 错误或警告。
   - **Sources:**  设置断点在 JavaScript 代码中，查看频谱数据和波形数据的值是否符合预期。
   - **Performance:**  分析性能瓶颈，如果数据获取过于频繁，可能会导致性能问题。
3. **如果怀疑是 Web Audio API 内部的问题:**
   - 可以尝试修改 `fftSize` 等参数，观察频谱图的变化是否符合预期。
   - 如果问题很底层，可能需要深入到 Chromium 的源代码进行调试。这可能涉及到在 `realtime_analyser.cc` 中添加日志输出或设置断点来查看中间计算结果，例如 FFT 的输出、幅度值、分贝值等。

理解用户操作的路径有助于开发者定位问题。例如，如果频谱图显示没有任何数据，那么很可能是音频源没有连接到分析器，或者分析器的配置不正确。如果频谱图看起来噪声很大，可能是平滑参数设置不当，或者 `minDecibels` 和 `maxDecibels` 的范围不合适。通过逐步跟踪数据流和逻辑，可以更有效地诊断和解决问题。

Prompt: 
```
这是目录为blink/renderer/modules/webaudio/realtime_analyser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webaudio/realtime_analyser.h"

#include <limits.h>

#include <algorithm>
#include <bit>
#include <complex>

#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/audio/vector_math.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

namespace {

void ApplyWindow(float* p, size_t n) {
  DCHECK(IsMainThread());

  // Blackman window
  double alpha = 0.16;
  double a0 = 0.5 * (1 - alpha);
  double a1 = 0.5;
  double a2 = 0.5 * alpha;

  for (unsigned i = 0; i < n; ++i) {
    double x = static_cast<double>(i) / static_cast<double>(n);
    double window =
        a0 - a1 * cos(kTwoPiDouble * x) + a2 * cos(kTwoPiDouble * 2.0 * x);
    p[i] *= static_cast<float>(window);
  }
}

// Returns x if x is finite (not NaN or infinite), otherwise returns
// default_value
float EnsureFinite(float x, float default_value) {
  return std::isfinite(x) ? x : default_value;
}

}  // namespace

RealtimeAnalyser::RealtimeAnalyser(unsigned render_quantum_frames)
    : input_buffer_(kInputBufferSize),
      down_mix_bus_(AudioBus::Create(1, render_quantum_frames)),
      fft_size_(kDefaultFFTSize),
      magnitude_buffer_(kDefaultFFTSize / 2),
      smoothing_time_constant_(kDefaultSmoothingTimeConstant),
      min_decibels_(kDefaultMinDecibels),
      max_decibels_(kDefaultMaxDecibels) {
  analysis_frame_ = std::make_unique<FFTFrame>(kDefaultFFTSize);
}

bool RealtimeAnalyser::SetFftSize(uint32_t size) {
  DCHECK(IsMainThread());

  // Only allow powers of two within the allowed range.
  if (size > kMaxFFTSize || size < kMinFFTSize || !std::has_single_bit(size)) {
    return false;
  }

  if (fft_size_ != size) {
    analysis_frame_ = std::make_unique<FFTFrame>(size);
    // m_magnitudeBuffer has size = fftSize / 2 because it contains floats
    // reduced from complex values in m_analysisFrame.
    magnitude_buffer_.Allocate(size / 2);
    fft_size_ = size;
  }

  return true;
}

void RealtimeAnalyser::GetFloatFrequencyData(DOMFloat32Array* destination_array,
                                             double current_time) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  if (current_time <= last_analysis_time_) {
    ConvertFloatToDb(destination_array);
    return;
  }

  // Time has advanced since the last call; update the FFT data.
  last_analysis_time_ = current_time;
  DoFFTAnalysis();

  ConvertFloatToDb(destination_array);
}

void RealtimeAnalyser::GetByteFrequencyData(DOMUint8Array* destination_array,
                                            double current_time) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  if (current_time <= last_analysis_time_) {
    // FIXME: Is it worth caching the data so we don't have to do the conversion
    // every time?  Perhaps not, since we expect many calls in the same
    // rendering quantum.
    ConvertToByteData(destination_array);
    return;
  }

  // Time has advanced since the last call; update the FFT data.
  last_analysis_time_ = current_time;
  DoFFTAnalysis();

  ConvertToByteData(destination_array);
}

void RealtimeAnalyser::GetFloatTimeDomainData(
    DOMFloat32Array* destination_array) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  unsigned fft_size = FftSize();
  size_t len =
      std::min(static_cast<size_t>(fft_size), destination_array->length());
  if (len > 0) {
    DCHECK_EQ(input_buffer_.size(), kInputBufferSize);
    DCHECK_GT(input_buffer_.size(), fft_size);

    float* input_buffer = input_buffer_.Data();
    float* destination = destination_array->Data();

    unsigned write_index = GetWriteIndex();

    for (unsigned i = 0; i < len; ++i) {
      // Buffer access is protected due to modulo operation.
      float value =
          input_buffer[(i + write_index - fft_size + kInputBufferSize) %
                       kInputBufferSize];

      destination[i] = value;
    }
  }
}

void RealtimeAnalyser::GetByteTimeDomainData(DOMUint8Array* destination_array) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  unsigned fft_size = FftSize();
  size_t len =
      std::min(static_cast<size_t>(fft_size), destination_array->length());
  if (len > 0) {
    DCHECK_EQ(input_buffer_.size(), kInputBufferSize);
    DCHECK_GT(input_buffer_.size(), fft_size);

    float* input_buffer = input_buffer_.Data();
    unsigned char* destination = destination_array->Data();

    unsigned write_index = GetWriteIndex();

    for (unsigned i = 0; i < len; ++i) {
      // Buffer access is protected due to modulo operation.
      float value =
          input_buffer[(i + write_index - fft_size + kInputBufferSize) %
                       kInputBufferSize];

      // Scale from nominal -1 -> +1 to unsigned byte.
      double scaled_value = 128 * (value + 1);

      // Clip to valid range.
      destination[i] =
          static_cast<unsigned char>(ClampTo(scaled_value, 0, UCHAR_MAX));
    }
  }
}

void RealtimeAnalyser::WriteInput(AudioBus* bus, uint32_t frames_to_process) {
  DCHECK(bus);
  DCHECK_GT(bus->NumberOfChannels(), 0u);
  DCHECK_GE(bus->Channel(0)->length(), frames_to_process);

  unsigned write_index = GetWriteIndex();
  // FIXME : allow to work with non-FFTSize divisible chunking
  DCHECK_LT(write_index, input_buffer_.size());
  DCHECK_LE(write_index + frames_to_process, input_buffer_.size());

  // Perform real-time analysis
  float* dest = input_buffer_.Data() + write_index;

  // Clear the bus and downmix the input according to the down mixing rules.
  // Then save the result in the m_inputBuffer at the appropriate place.
  down_mix_bus_->Zero();
  down_mix_bus_->SumFrom(*bus);
  memcpy(dest, down_mix_bus_->Channel(0)->Data(),
         frames_to_process * sizeof(*dest));

  write_index += frames_to_process;
  if (write_index >= kInputBufferSize) {
    write_index = 0;
  }
  SetWriteIndex(write_index);
}

void RealtimeAnalyser::DoFFTAnalysis() {
  DCHECK(IsMainThread());

  // Unroll the input buffer into a temporary buffer, where we'll apply an
  // analysis window followed by an FFT.
  uint32_t fft_size = FftSize();

  AudioFloatArray temporary_buffer(fft_size);
  float* input_buffer = input_buffer_.Data();
  float* temp_p = temporary_buffer.Data();

  // Take the previous fftSize values from the input buffer and copy into the
  // temporary buffer.
  unsigned write_index = GetWriteIndex();
  if (write_index < fft_size) {
    memcpy(temp_p, input_buffer + write_index - fft_size + kInputBufferSize,
           sizeof(*temp_p) * (fft_size - write_index));
    memcpy(temp_p + fft_size - write_index, input_buffer,
           sizeof(*temp_p) * write_index);
  } else {
    memcpy(temp_p, input_buffer + write_index - fft_size,
           sizeof(*temp_p) * fft_size);
  }

  // Window the input samples.
  ApplyWindow(temp_p, fft_size);

  // Do the analysis.
  analysis_frame_->DoFFT(temp_p);

  const AudioFloatArray& real = analysis_frame_->RealData();
  AudioFloatArray& imag = analysis_frame_->ImagData();

  // Blow away the packed nyquist component.
  imag[0] = 0;

  // Normalize so than an input sine wave at 0dBfs registers as 0dBfs (undo FFT
  // scaling factor).
  const double magnitude_scale = 1.0 / fft_size;

  // A value of 0 does no averaging with the previous result.  Larger values
  // produce slower, but smoother changes.
  const double k = ClampTo(smoothing_time_constant_, 0.0, 1.0);

  // Convert the analysis data from complex to magnitude and average with the
  // previous result.
  float* destination = MagnitudeBuffer().Data();
  size_t n = MagnitudeBuffer().size();
  DCHECK_GE(real.size(), n);
  const float* real_p_data = real.Data();
  DCHECK_GE(imag.size(), n);
  const float* imag_p_data = imag.Data();
  for (size_t i = 0; i < n; ++i) {
    std::complex<double> c(real_p_data[i], imag_p_data[i]);
    double scalar_magnitude = abs(c) * magnitude_scale;
    destination[i] = EnsureFinite(
        static_cast<float>(k * destination[i] + (1 - k) * scalar_magnitude), 0);
  }
}

void RealtimeAnalyser::ConvertToByteData(DOMUint8Array* destination_array) {
  // Convert from linear magnitude to unsigned-byte decibels.
  size_t source_length = MagnitudeBuffer().size();
  size_t len = std::min(source_length, destination_array->length());
  if (len > 0) {
    const double range_scale_factor = max_decibels_ == min_decibels_
                                          ? 1
                                          : 1 / (max_decibels_ - min_decibels_);
    const double min_decibels = min_decibels_;

    const float* source = MagnitudeBuffer().Data();
    unsigned char* destination = destination_array->Data();

    for (unsigned i = 0; i < len; ++i) {
      float linear_value = source[i];
      double db_mag = audio_utilities::LinearToDecibels(linear_value);

      // The range m_minDecibels to m_maxDecibels will be scaled to byte values
      // from 0 to UCHAR_MAX.
      double scaled_value =
          UCHAR_MAX * (db_mag - min_decibels) * range_scale_factor;

      // Clip to valid range.
      destination[i] =
          static_cast<unsigned char>(ClampTo(scaled_value, 0, UCHAR_MAX));
    }
  }
}

void RealtimeAnalyser::ConvertFloatToDb(DOMFloat32Array* destination_array) {
  // Convert from linear magnitude to floating-point decibels.
  size_t source_length = MagnitudeBuffer().size();
  size_t len = std::min(source_length, destination_array->length());
  if (len > 0) {
    const float* source = MagnitudeBuffer().Data();
    float* destination = destination_array->Data();

    for (unsigned i = 0; i < len; ++i) {
      float linear_value = source[i];
      double db_mag = audio_utilities::LinearToDecibels(linear_value);
      destination[i] = static_cast<float>(db_mag);
    }
  }
}

}  // namespace blink

"""

```