Response:
Let's break down the thought process to analyze the C++ code and fulfill the request.

1. **Understand the Goal:** The request asks for the functionality of the provided C++ code, its relation to web technologies (JavaScript, HTML, CSS), examples of logic, and potential user/programming errors. The core of the file is `dynamics_compressor.cc`, so the focus should be on audio dynamic range compression.

2. **Initial Scan for Key Terms:** I'd first scan the code for obvious keywords related to audio processing, web technologies, and potential issues.

    * **Audio Terms:**  `DynamicsCompressor`, `AudioBus`, `sample_rate`, `channels`, `threshold`, `knee`, `ratio`, `attack`, `release`, `gain`, `decibels`, `linear`, `predelay`. These clearly indicate audio processing.
    * **Web/Blink Terms:** `blink`, `renderer`, `platform`, `JavaScript` (implicitly through the context of Chromium Blink).
    * **Potential Issues:** `DCHECK`, `NOTREACHED`, `EnsureFinite`, comments mentioning "unsafe buffers" and TODOs. These hint at assertions, error handling, and areas needing attention.
    * **Math Terms:** `powf`, `exp`, `sin`, `sqrtf`, `log10`. This confirms mathematical operations central to audio signal manipulation.

3. **Identify the Core Functionality:** The class name `DynamicsCompressor` and the parameter names strongly suggest that this code implements an audio dynamic range compressor. This type of processor reduces the dynamic range of an audio signal, making loud parts quieter and quiet parts louder.

4. **Analyze the `Process` Function (Crucial):** This is the heart of the audio processing. I'd carefully read through the `Process` function step-by-step:

    * **Input/Output:** It takes `source_bus` and `destination_bus` (audio data).
    * **Parameter Retrieval:** It gets compressor parameters like `threshold`, `knee`, `ratio`, `attack`, and `release` times.
    * **Channel Handling:** It handles stereo (2 channels) explicitly. The `NOTREACHED()` suggests other channel counts aren't yet fully supported.
    * **Key Processing Steps:**
        * **Gain Calculation:**  It calculates a `desired_gain` based on the input signal.
        * **Envelope Following:**  It uses attack and release times to smooth the gain changes (`envelope_rate`).
        * **Predelay:** It introduces a delay (`kPreDelay`) in the signal path. This is crucial for look-ahead compression, allowing the compressor to react to transients *before* they arrive.
        * **Shaping Curve:** The `Saturate` function implements the compression curve, with linear, knee, and ratio regions.
        * **Gain Application:** It applies the calculated `total_gain` to the delayed audio signal.
        * **Metering:** It measures the gain reduction for display/feedback.
    * **Loop Structure:** The code processes audio in chunks (`kNumberOfDivisionFrames`).

5. **Connect to Web Technologies:**

    * **Web Audio API:** The presence of `AudioBus`, `sample_rate`, and the concept of audio nodes directly link this code to the Web Audio API in JavaScript. The `DynamicsCompressorNode` in the Web Audio API likely uses this C++ implementation under the hood.
    * **HTML:**  HTML provides the `<audio>` and `<video>` elements where this audio processing can be applied.
    * **CSS:** While CSS doesn't directly control the audio processing logic, it can influence the user interface for controlling these effects (e.g., sliders for threshold, ratio, etc.).

6. **Develop Examples of Logic and Input/Output:**  Focus on the core compression logic.

    * **Threshold:** If the input signal exceeds the threshold, compression starts. Example input: sine wave at -10dB, threshold at -20dB. Output: attenuated sine wave.
    * **Ratio:** The amount of compression applied above the threshold. Example input: sine wave increasing by 10dB above the threshold, ratio 2:1. Output: increase of only 5dB in the output.
    * **Attack/Release:** How quickly the compressor reacts to changes in the signal level. Example input: sudden loud sound (transient). Slow attack: lets some of the transient through. Fast attack: quickly reduces the gain.

7. **Identify Potential Errors:**

    * **User Errors (via Web Audio API):**  Setting invalid parameter values (negative ratio, zero attack/release), connecting nodes in incorrect ways.
    * **Programming Errors (in the C++ code):** The `DCHECK` and `NOTREACHED` statements indicate areas where assumptions are made and errors might occur if those assumptions are violated (e.g., unexpected number of channels). The "unsafe buffers" comment also points to potential memory safety issues. The `EnsureFinite` function suggests dealing with potential NaN or infinite values.

8. **Structure the Response:** Organize the findings logically:

    * Start with a clear summary of the file's purpose.
    * Detail the core functionality.
    * Explain the relationship to web technologies with examples.
    * Provide concrete examples of logic with hypothetical inputs and outputs.
    * Highlight potential user and programming errors.

9. **Refine and Review:**  Read through the generated response to ensure clarity, accuracy, and completeness. Make sure the examples are easy to understand and the explanations are technically correct. For instance, initially, I might have just said "it processes audio," but refining it to "implements an audio dynamic range compressor" is more precise. Similarly, instead of just mentioning Web Audio API, providing the example of `DynamicsCompressorNode` adds more context.
这个C++源代码文件 `dynamics_compressor.cc` 实现了 Chromium Blink 引擎中的一个音频处理模块：**动态压缩器 (Dynamics Compressor)**。

**主要功能:**

1. **动态范围压缩:**  核心功能是减少音频信号的动态范围。这通过降低响亮部分的声音强度，并可能提升安静部分的声音强度来实现，从而使整体音量更加一致。

2. **音频信号处理:** 它接收音频数据作为输入 (`AudioBus* source_bus`)，并对这些数据进行处理，然后将处理后的音频数据输出到另一个 `AudioBus` (`AudioBus* destination_bus`)。

3. **可配置参数:**  它提供了一系列可配置的参数来控制压缩的行为，这些参数通常与硬件或软件压缩器的设置相对应：
    * **Threshold (阈值):**  压缩开始生效的音量水平。当音频信号超过阈值时，压缩器开始降低增益。
    * **Knee (拐点):**  定义了压缩开始生效的平滑程度。一个较小的 knee 值会使压缩更突然地发生，而较大的 knee 值会使压缩逐渐生效。
    * **Ratio (比率):**  决定了当信号超过阈值时，输出信号的增益降低多少。例如，一个 2:1 的比率意味着输入信号每增加 2 分贝，输出信号只增加 1 分贝。
    * **Attack (启动时间):**  压缩器开始降低增益的速度，以秒为单位。
    * **Release (释放时间):**  压缩器停止降低增益并恢复正常增益的速度，以秒为单位。
    * **Reduction (衰减):**  表示当前压缩器正在进行的增益衰减量 (以分贝为单位)，这是一个只读参数，用于监控压缩效果。

4. **预延迟 (Pre-delay):**  实现了一个小的预延迟，允许压缩器在实际的响亮部分到达之前就对其做出反应。这对于处理快速瞬态声音（例如鼓声）非常重要，可以避免“泵浦”效应。

5. **自适应释放时间:**  释放时间不是一个固定值，而是会根据压缩量进行自适应调整，使得在高压缩量下释放更快。

6. **增益补偿 (Makeup Gain):**  虽然代码中没有显式的 "Makeup Gain" 参数，但 `linear_post_gain` 变量承担了一部分增益补偿的功能。在压缩降低音量的同时，可能需要提升整体音量以保持感知上的响度。

7. **声道处理:**  目前的代码主要支持单声道和立体声 (2声道) 处理。对于单声道输入，会复制到左右声道进行处理。

8. **平滑处理:**  在增益变化过程中使用了平滑算法（例如，指数平滑），以避免突然的音量跳变，从而产生更自然的压缩效果。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件是 Chromium 渲染引擎的一部分，它与 Web Audio API 密切相关。Web Audio API 允许 JavaScript 在 Web 浏览器中进行复杂的音频处理。

* **JavaScript:**  Web Audio API 暴露了 `DynamicsCompressorNode` 接口，JavaScript 代码可以使用这个接口来创建和控制动态压缩器。 `blink/renderer/platform/audio/dynamics_compressor.cc` 中的代码就是 `DynamicsCompressorNode` 在底层 C++ 层的实现。

   **JavaScript 示例:**

   ```javascript
   const audioContext = new AudioContext();
   const source = audioContext.createBufferSource();
   const compressor = audioContext.createDynamicsCompressor();

   // 设置压缩器参数
   compressor.threshold.setValueAtTime(-20, audioContext.currentTime);
   compressor.knee.setValueAtTime(6, audioContext.currentTime);
   compressor.ratio.setValueAtTime(4, audioContext.currentTime);
   compressor.attack.setValueAtTime(0.05, audioContext.currentTime);
   compressor.release.setValueAtTime(0.25, audioContext.currentTime);

   // 连接音频节点
   source.connect(compressor);
   compressor.connect(audioContext.destination);

   // 播放音频
   source.start();
   ```

* **HTML:**  HTML 的 `<audio>` 和 `<video>` 元素是音频的来源。Web Audio API 可以从这些元素中获取音频流进行处理，包括应用动态压缩。

   **HTML 示例:**

   ```html
   <audio id="myAudio" src="my_audio.mp3"></audio>
   <script>
       const audio = document.getElementById('myAudio');
       const audioContext = new AudioContext();
       const source = audioContext.createMediaElementSource(audio);
       const compressor = audioContext.createDynamicsCompressor();

       source.connect(compressor);
       compressor.connect(audioContext.destination);
   </script>
   ```

* **CSS:**  CSS 本身不直接参与音频处理逻辑。但是，CSS 可以用于创建控制音频效果的用户界面（例如，滑块来调整压缩器的参数）。JavaScript 可以监听这些 UI 元素的事件，并更新 `DynamicsCompressorNode` 的相应参数。

**逻辑推理和假设输入/输出:**

**假设输入:**  一个单声道正弦波，频率为 440Hz，峰值幅度为 0.8。

**压缩器参数:**
* `threshold`: -12dB (线性值约为 0.25)
* `ratio`: 4:1
* `attack`: 0.01 秒
* `release`: 0.1 秒

**逻辑推理:**

1. **检测超过阈值:** 当正弦波的幅度超过阈值 0.25 时，压缩器开始工作。
2. **增益衰减计算:**  假设当前输入峰值为 0.8 (大约是 0 dB)。超过阈值的部分约为 0dB - (-12dB) = 12dB。由于比率为 4:1，输出增益的增加将减少为 12dB / 4 = 3dB。这意味着输出信号的线性增益将减少。
3. **Attack 阶段:** 压缩器不会立即将增益降低到目标水平，而是根据 `attack` 时间逐渐降低增益。在 0.01 秒内，增益会快速下降。
4. **Release 阶段:** 当正弦波的幅度降回阈值以下时，压缩器会根据 `release` 时间逐渐恢复增益。在 0.1 秒内，增益会平缓上升。

**假设输出:**

* 当输入正弦波幅度超过 0.25 时，输出正弦波的幅度会受到压缩，峰值幅度会降低。降低的幅度取决于超过阈值的程度和比率。
* 在幅度快速变化时（attack 阶段），输出的幅度会快速响应并降低。
* 当幅度下降到阈值以下时（release 阶段），输出的幅度会逐渐恢复到接近原始水平。
* 整体上，输出信号的动态范围会比输入信号更小。

**用户或编程常见的使用错误:**

1. **设置不合理的参数:**
   * **负数的 `ratio`:**  这在物理上没有意义，会导致不可预测的行为。
   * **零或非常小的 `attack` 或 `release` 时间:**  可能导致增益变化过于剧烈，产生失真或不自然的“泵浦”效应。
   * **`threshold` 设置过高或过低:**  如果 `threshold` 设置得太高，压缩器可能永远不会工作。如果设置得太低，可能会导致不必要的持续压缩，使声音听起来“闷”。

   **示例 (JavaScript):**
   ```javascript
   compressor.ratio.setValueAtTime(-2, audioContext.currentTime); // 错误：负数比率
   compressor.attack.setValueAtTime(0, audioContext.currentTime);   // 错误：零启动时间
   ```

2. **误解参数的作用:**  用户可能不理解 `knee` 参数的作用，导致压缩效果不符合预期。例如，希望获得更“硬”的压缩效果却使用了很大的 `knee` 值。

3. **连接音频节点错误:**  如果将压缩器节点连接到音频图中的错误位置，可能导致音频无法处理或产生意外的效果。

   **示例 (JavaScript):**
   ```javascript
   // 错误：直接将 source 连接到 destination，跳过了 compressor
   source.connect(audioContext.destination);
   ```

4. **性能考虑不周:**  过度使用或配置不当的压缩器会消耗大量的计算资源，尤其是在处理多声道或高采样率音频时。用户可能会在性能受限的设备上遇到问题。

5. **没有考虑预延迟的影响:**  虽然预延迟可以改善瞬态处理，但它也会引入延迟。在需要实时交互的应用程序中，过大的预延迟可能会成为问题。

6. **忘记重置或初始化参数:**  在某些情况下，如果重复使用 `DynamicsCompressorNode` 实例而不重置其参数，可能会沿用之前的设置，导致意外的结果。

总之，`dynamics_compressor.cc` 文件实现了 Chromium 中用于音频动态范围压缩的核心功能，并通过 Web Audio API 与 JavaScript、HTML 和 CSS 等 Web 技术相结合，为 Web 应用提供了强大的音频处理能力。理解其功能和参数对于开发者正确使用和调试 Web Audio 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/audio/dynamics_compressor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
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

#include "third_party/blink/renderer/platform/audio/dynamics_compressor.h"

#include <algorithm>
#include <cmath>

#include "base/logging.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/audio/denormal_disabler.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/fdlibm/ieee754.h"

namespace blink {

namespace {

// Metering hits peaks instantly, but releases this fast (in seconds).
constexpr float kMeteringReleaseTimeConstant = 0.325f;

constexpr float kUninitializedValue = -1;

constexpr float kPreDelay = 0.006f;  // seconds

// Release zone values 0 -> 1.
constexpr float kReleaseZone1 = 0.09f;
constexpr float kReleaseZone2 = 0.16f;
constexpr float kReleaseZone3 = 0.42f;
constexpr float kReleaseZone4 = 0.98f;

constexpr float kABase = 0.9999999999999998f * kReleaseZone1 +
                         1.8432219684323923e-16f * kReleaseZone2 -
                         1.9373394351676423e-16f * kReleaseZone3 +
                         8.824516011816245e-18f * kReleaseZone4;
constexpr float kBBase =
    -1.5788320352845888f * kReleaseZone1 + 2.3305837032074286f * kReleaseZone2 -
    0.9141194204840429f * kReleaseZone3 + 0.1623677525612032f * kReleaseZone4;
constexpr float kCBase =
    0.5334142869106424f * kReleaseZone1 - 1.272736789213631f * kReleaseZone2 +
    0.9258856042207512f * kReleaseZone3 - 0.18656310191776226f * kReleaseZone4;
constexpr float kDBase =
    0.08783463138207234f * kReleaseZone1 - 0.1694162967925622f * kReleaseZone2 +
    0.08588057951595272f * kReleaseZone3 - 0.00429891410546283f * kReleaseZone4;
constexpr float kEBase = -0.042416883008123074f * kReleaseZone1 +
                         0.1115693827987602f * kReleaseZone2 -
                         0.09764676325265872f * kReleaseZone3 +
                         0.028494263462021576f * kReleaseZone4;

// Detector release time.
constexpr float kSatReleaseTime = 0.0025f;

// Returns x if x is finite (not NaN or infinite), otherwise returns
// default_value
float EnsureFinite(float x, float default_value) {
  DCHECK(!std::isnan(x));
  DCHECK(!std::isinf(x));
  return std::isfinite(x) ? x : default_value;
}

}  // namespace

DynamicsCompressor::DynamicsCompressor(float sample_rate,
                                       unsigned number_of_channels)
    : number_of_channels_(number_of_channels),
      sample_rate_(sample_rate),
      ratio_(kUninitializedValue),
      slope_(kUninitializedValue),
      linear_threshold_(kUninitializedValue),
      db_threshold_(kUninitializedValue),
      db_knee_(kUninitializedValue),
      knee_threshold_(kUninitializedValue),
      db_knee_threshold_(kUninitializedValue),
      db_yknee_threshold_(kUninitializedValue),
      knee_(kUninitializedValue) {
  SetNumberOfChannels(number_of_channels);
  // Initializes most member variables
  Reset();
  metering_release_k_ =
      static_cast<float>(audio_utilities::DiscreteTimeConstantForSampleRate(
          kMeteringReleaseTimeConstant, sample_rate));
  InitializeParameters();
}

void DynamicsCompressor::Process(const AudioBus* source_bus,
                                 AudioBus* destination_bus,
                                 unsigned frames_to_process) {
  // Though number_of_channels is retrieved from destination_bus, we still name
  // it number_of_channels instead of number_of_destination_channels.  It's
  // because we internally match source_channels's size to destination_bus by
  // channel up/down mix. Thus we need number_of_channels to do the loop work
  // for both source_channels_ and destination_channels_.

  const unsigned number_of_channels = destination_bus->NumberOfChannels();
  const unsigned number_of_source_channels = source_bus->NumberOfChannels();

  DCHECK_EQ(number_of_channels, number_of_channels_);
  DCHECK(number_of_source_channels);

  switch (number_of_channels) {
    case 2:  // stereo
      source_channels_[0] = source_bus->Channel(0)->Data();

      if (number_of_source_channels > 1) {
        source_channels_[1] = source_bus->Channel(1)->Data();
      } else {
        // Simply duplicate mono channel input data to right channel for stereo
        // processing.
        source_channels_[1] = source_channels_[0];
      }

      break;
    default:
      // FIXME : support other number of channels.
      NOTREACHED();
  }

  for (unsigned i = 0; i < number_of_channels; ++i) {
    destination_channels_[i] = destination_bus->Channel(i)->MutableData();
  }

  const float db_threshold = ParameterValue(kParamThreshold);
  const float db_knee = ParameterValue(kParamKnee);
  const float ratio = ParameterValue(kParamRatio);
  const float attack_time = ParameterValue(kParamAttack);
  const float release_time = ParameterValue(kParamRelease);

  // Apply compression to the source signal.
  const float** source_channels = source_channels_.get();
  float** destination_channels = destination_channels_.get();

  DCHECK_EQ(pre_delay_buffers_.size(), number_of_channels);

  const float sample_rate = SampleRate();

  const float k = UpdateStaticCurveParameters(db_threshold, db_knee, ratio);

  // Makeup gain with empirical/perceptual tuning.
  const float linear_post_gain = fdlibm::powf(1 / Saturate(1, k), 0.6f);

  // Attack parameters.
  const float attack_frames = std::max(0.001f, attack_time) * sample_rate;

  // Release parameters.
  const float release_frames = sample_rate * release_time;

  const float sat_release_frames = kSatReleaseTime * sample_rate;

  // Create a smooth function which passes through four points.

  // Polynomial of the form
  // y = a + b*x + c*x^2 + d*x^3 + e*x^4;
  // All of these coefficients were derived for 4th order polynomial curve
  // fitting where the y values match the evenly spaced x values as follows:
  // (y1 : x == 0, y2 : x == 1, y3 : x == 2, y4 : x == 3)
  const float a = release_frames * kABase;
  const float b = release_frames * kBBase;
  const float c = release_frames * kCBase;
  const float d = release_frames * kDBase;
  const float e = release_frames * kEBase;

  // x ranges from 0 -> 3       0    1    2   3
  //                           -15  -10  -5   0db

  // y calculates adaptive release frames depending on the amount of
  // compression.

  SetPreDelayTime(kPreDelay);

  constexpr int kNumberOfDivisionFrames = 32;

  const int number_of_divisions = frames_to_process / kNumberOfDivisionFrames;

  unsigned frame_index = 0;
  for (int i = 0; i < number_of_divisions; ++i) {
    // Calculate desired gain

    detector_average_ = EnsureFinite(detector_average_, 1);

    const float desired_gain = detector_average_;

    // Pre-warp so we get desired_gain after sin() warp below.
    const float scaled_desired_gain =
        fdlibm::asinf(desired_gain) / kPiOverTwoFloat;

    // Deal with envelopes

    // envelope_rate is the rate we slew from current compressor level to the
    // desired level.  The exact rate depends on if we're attacking or
    // releasing and by how much.
    float envelope_rate;

    const bool is_releasing = scaled_desired_gain > compressor_gain_;

    // compression_diff_db is the difference between current compression level
    // and the desired level.
    float db_compression_diff;

    if (scaled_desired_gain == 0) {
      db_compression_diff = is_releasing ? -1 : 1;
    } else {
      db_compression_diff = audio_utilities::LinearToDecibels(
          compressor_gain_ / scaled_desired_gain);
    }

    if (is_releasing) {
      // Release mode - db_compression_diff should be negative dB
      db_max_attack_compression_diff_ = -1;

      db_compression_diff = EnsureFinite(db_compression_diff, -1);

      // Adaptive release - higher compression (lower db_compression_diff)
      // releases faster.

      // Contain within range: -12 -> 0 then scale to go from 0 -> 3
      float x = db_compression_diff;
      x = ClampTo(x, -12.0f, 0.0f);
      x = 0.25f * (x + 12);

      // Compute adaptive release curve using 4th order polynomial.
      // Normal values for the polynomial coefficients would create a
      // monotonically increasing function.
      const float x2 = x * x;
      const float x3 = x2 * x;
      const float x4 = x2 * x2;
      const float calc_release_frames = a + b * x + c * x2 + d * x3 + e * x4;

      constexpr float kDbSpacing = 5;
      const float db_per_frame = kDbSpacing / calc_release_frames;

      envelope_rate = audio_utilities::DecibelsToLinear(db_per_frame);
    } else {
      // Attack mode - db_compression_diff should be positive dB

      db_compression_diff = EnsureFinite(db_compression_diff, 1);

      // As long as we're still in attack mode, use a rate based off
      // the largest db_compression_diff we've encountered so far.
      if (db_max_attack_compression_diff_ == -1 ||
          db_max_attack_compression_diff_ < db_compression_diff) {
        db_max_attack_compression_diff_ = db_compression_diff;
      }

      const float db_eff_atten_diff =
          std::max(0.5f, db_max_attack_compression_diff_);

      const float x = 0.25f / db_eff_atten_diff;
      envelope_rate = 1 - fdlibm::powf(x, 1 / attack_frames);
    }

    // Inner loop - calculate shaped power average - apply compression.
    int pre_delay_read_index = pre_delay_read_index_;
    int pre_delay_write_index = pre_delay_write_index_;
    float detector_average = detector_average_;
    float compressor_gain = compressor_gain_;

    int loop_frames = kNumberOfDivisionFrames;
    while (loop_frames--) {
      float compressor_input = 0;

      // Predelay signal, computing compression amount from un-delayed
      // version.
      for (unsigned j = 0; j < number_of_channels; ++j) {
        float* const delay_buffer = pre_delay_buffers_[j]->Data();
        const float undelayed_source = source_channels[j][frame_index];
        delay_buffer[pre_delay_write_index] = undelayed_source;

        const float abs_undelayed_source =
            undelayed_source > 0 ? undelayed_source : -undelayed_source;
        if (compressor_input < abs_undelayed_source) {
          compressor_input = abs_undelayed_source;
        }
      }

      // Calculate shaped power on undelayed input.

      const float scaled_input = compressor_input;
      const float abs_input = scaled_input > 0 ? scaled_input : -scaled_input;

      // Put through shaping curve.
      // This is linear up to the threshold, then enters a "knee" portion
      // followed by the "ratio" portion.  The transition from the threshold
      // to the knee is smooth (1st derivative matched).  The transition
      // from the knee to the ratio portion is smooth (1st derivative
      // matched).
      const float shaped_input = Saturate(abs_input, k);

      const float attenuation =
          abs_input <= 0.0001f ? 1 : shaped_input / abs_input;

      const float db_attenuation =
          std::max(2.0f, -audio_utilities::LinearToDecibels(attenuation));

      const float db_per_frame = db_attenuation / sat_release_frames;

      const float sat_release_rate =
          audio_utilities::DecibelsToLinear(db_per_frame) - 1;

      const bool is_release = (attenuation > detector_average);
      const float rate = is_release ? sat_release_rate : 1;

      detector_average += (attenuation - detector_average) * rate;
      detector_average = std::min(1.0f, detector_average);

      detector_average = EnsureFinite(detector_average, 1);

      // Exponential approach to desired gain.
      if (envelope_rate < 1) {
        // Attack - reduce gain to desired.
        compressor_gain +=
            (scaled_desired_gain - compressor_gain) * envelope_rate;
      } else {
        // Release - exponentially increase gain to 1.0
        compressor_gain *= envelope_rate;
        compressor_gain = std::min(1.0f, compressor_gain);
      }

      // Warp pre-compression gain to smooth out sharp exponential transition
      // points.
      const float post_warp_compressor_gain = static_cast<float>(
          sin(static_cast<double>(kPiOverTwoFloat * compressor_gain)));

      // Calculate total gain using the linear post-gain.
      const float total_gain = linear_post_gain * post_warp_compressor_gain;

      // Calculate metering.
      const float db_real_gain =
          audio_utilities::LinearToDecibels(post_warp_compressor_gain);
      if (db_real_gain < metering_gain_) {
        metering_gain_ = db_real_gain;
      } else {
        metering_gain_ += (db_real_gain - metering_gain_) * metering_release_k_;
      }

      // Apply final gain.
      for (unsigned j = 0; j < number_of_channels; ++j) {
        const float* const delay_buffer = pre_delay_buffers_[j]->Data();
        destination_channels[j][frame_index] =
            delay_buffer[pre_delay_read_index] * total_gain;
      }

      frame_index++;
      pre_delay_read_index =
          (pre_delay_read_index + 1) & kMaxPreDelayFramesMask;
      pre_delay_write_index =
          (pre_delay_write_index + 1) & kMaxPreDelayFramesMask;
    }

    // Locals back to member variables.
    pre_delay_read_index_ = pre_delay_read_index;
    pre_delay_write_index_ = pre_delay_write_index;
    detector_average_ =
        DenormalDisabler::FlushDenormalFloatToZero(detector_average);
    compressor_gain_ =
        DenormalDisabler::FlushDenormalFloatToZero(compressor_gain);
  }

  // Update the compression amount.
  SetParameterValue(kParamReduction, metering_gain_);
}

void DynamicsCompressor::Reset() {
  detector_average_ = 0;
  compressor_gain_ = 1;
  metering_gain_ = 1;

  // Predelay section.
  for (auto& pre_delay_buffer : pre_delay_buffers_) {
    pre_delay_buffer->Zero();
  }

  pre_delay_read_index_ = 0;
  pre_delay_write_index_ = kDefaultPreDelayFrames;

  db_max_attack_compression_diff_ = -1;  // uninitialized state
}

void DynamicsCompressor::SetNumberOfChannels(unsigned number_of_channels) {
  source_channels_ = std::make_unique<const float*[]>(number_of_channels);
  destination_channels_ = std::make_unique<float*[]>(number_of_channels);

  if (pre_delay_buffers_.size() == number_of_channels) {
    return;
  }

  pre_delay_buffers_.clear();
  for (unsigned i = 0; i < number_of_channels; ++i) {
    pre_delay_buffers_.push_back(
        std::make_unique<AudioFloatArray>(kMaxPreDelayFrames));
  }

  number_of_channels_ = number_of_channels;
}

void DynamicsCompressor::SetParameterValue(unsigned parameter_id, float value) {
  DCHECK_LT(parameter_id, static_cast<unsigned>(kParamLast));
  parameters_[parameter_id] = value;
}

float DynamicsCompressor::ParameterValue(unsigned parameter_id) const {
  DCHECK_LT(parameter_id, static_cast<unsigned>(kParamLast));
  return parameters_[parameter_id];
}

float DynamicsCompressor::SampleRate() const {
  return sample_rate_;
}

float DynamicsCompressor::Nyquist() const {
  return sample_rate_ / 2;
}

double DynamicsCompressor::TailTime() const {
  // The reduction value of the compressor is computed from the gain
  // using an exponential filter with a time constant of
  // |kMeteringReleaseTimeConstant|.  We need to keep he compressor
  // running for some time after the inputs go away so that the
  // reduction value approaches 0.  This is a tradeoff between how
  // long we keep the node alive and how close we approach the final
  // value.  A value of 5 to 10 times the time constant is a
  // reasonable trade-off.
  return 5 * kMeteringReleaseTimeConstant;
}

double DynamicsCompressor::LatencyTime() const {
  return last_pre_delay_frames_ / static_cast<double>(SampleRate());
}

bool DynamicsCompressor::RequiresTailProcessing() const {
  // Always return true even if the tail time and latency might both be zero.
  return true;
}

void DynamicsCompressor::InitializeParameters() {
  // Initializes compressor to default values.
  parameters_[kParamThreshold] = -24;   // dB
  parameters_[kParamKnee] = 30;         // dB
  parameters_[kParamRatio] = 12;        // unit-less
  parameters_[kParamAttack] = 0.003f;   // seconds
  parameters_[kParamRelease] = 0.250f;  // seconds
  parameters_[kParamReduction] = 0;     // dB
}

void DynamicsCompressor::SetPreDelayTime(float pre_delay_time) {
  // Re-configure look-ahead section pre-delay if delay time has changed.
  unsigned pre_delay_frames = pre_delay_time * SampleRate();
  if (pre_delay_frames > kMaxPreDelayFrames - 1) {
    pre_delay_frames = kMaxPreDelayFrames - 1;
  }

  if (last_pre_delay_frames_ != pre_delay_frames) {
    last_pre_delay_frames_ = pre_delay_frames;
    for (auto& pre_delay_buffer : pre_delay_buffers_) {
      pre_delay_buffer->Zero();
    }

    pre_delay_read_index_ = 0;
    pre_delay_write_index_ = pre_delay_frames;
  }
}

// Exponential curve for the knee.
// It is 1st derivative matched at linear_threshold_ and asymptotically
// approaches the value linear_threshold_ + 1 / k.
float DynamicsCompressor::KneeCurve(float x, float k) const {
  // Linear up to threshold.
  if (x < linear_threshold_) {
    return x;
  }

  return linear_threshold_ + (1 - static_cast<float>(exp(static_cast<double>(
                                      -k * (x - linear_threshold_))))) /
                                 k;
}

// Full compression curve with constant ratio after knee.
float DynamicsCompressor::Saturate(float x, float k) const {
  if (x < knee_threshold_) {
    return KneeCurve(x, k);
  }
  // Constant ratio after knee.
  const float db_x = audio_utilities::LinearToDecibels(x);
  const float db_y = db_yknee_threshold_ + slope_ * (db_x - db_knee_threshold_);
  return audio_utilities::DecibelsToLinear(db_y);
}

float DynamicsCompressor::KAtSlope(float desired_slope) const {
  const float db_x = db_threshold_ + db_knee_;
  const float x = audio_utilities::DecibelsToLinear(db_x);
  float x2 = 1;
  float db_x2 = 0;

  if (!(x < linear_threshold_)) {
    x2 = x * 1.001;
    db_x2 = audio_utilities::LinearToDecibels(x2);
  }

  // Approximate k given initial values.
  float min_k = 0.1;
  float max_k = 10000;
  float k = 5;

  float slope = 1;
  for (int i = 0; i < 15; ++i) {
    // A high value for k will more quickly asymptotically approach a slope of
    // 0.

    // Approximate 1st derivative with input and output expressed in dB.
    // This slope is equal to the inverse of the compression "ratio".
    // In other words, a compression ratio of 20 would be a slope of 1/20.
    if (!(x < linear_threshold_)) {
      const float db_y = audio_utilities::LinearToDecibels(KneeCurve(x, k));
      const float db_y2 = audio_utilities::LinearToDecibels(KneeCurve(x2, k));
      slope = (db_y2 - db_y) / (db_x2 - db_x);
    }

    if (slope < desired_slope) {
      // k is too high.
      max_k = k;
    } else {
      // k is too low.
      min_k = k;
    }

    // Re-calculate based on geometric mean.
    k = sqrtf(min_k * max_k);
  }

  return k;
}

float DynamicsCompressor::UpdateStaticCurveParameters(float db_threshold,
                                                      float db_knee,
                                                      float ratio) {
  if (db_threshold != db_threshold_ || db_knee != db_knee_ || ratio != ratio_) {
    // Threshold and knee.
    db_threshold_ = db_threshold;
    linear_threshold_ = audio_utilities::DecibelsToLinear(db_threshold);
    db_knee_ = db_knee;

    // Compute knee parameters.
    ratio_ = ratio;
    slope_ = 1 / ratio_;

    const float k = KAtSlope(1 / ratio_);

    db_knee_threshold_ = db_threshold + db_knee;
    knee_threshold_ = audio_utilities::DecibelsToLinear(db_knee_threshold_);

    db_yknee_threshold_ =
        audio_utilities::LinearToDecibels(KneeCurve(knee_threshold_, k));

    knee_ = k;
  }
  return knee_;
}

}  // namespace blink

"""

```