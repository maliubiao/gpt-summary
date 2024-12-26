Response:
The user wants to understand the functionality of the `hrtf_panner.cc` file in the Chromium Blink engine. I need to explain what this code does, how it relates to web technologies (JavaScript, HTML, CSS), provide logical examples with inputs and outputs, and point out common user/programming errors.

Here's a breakdown of the steps:

1. **Identify the Core Functionality:**  The filename and the code content clearly indicate this file implements a Head-Related Transfer Function (HRTF) based audio spatialization or panning effect.

2. **Explain HRTF Panning:**  Describe the purpose of HRTF in creating a 3D audio experience by simulating how sounds reach our ears from different directions.

3. **Relate to Web Technologies:**
    * **JavaScript:**  Think about how JavaScript Audio APIs (like the Web Audio API's `PannerNode`) would interact with this C++ code. The JavaScript API provides the high-level control, while this C++ code performs the actual audio processing.
    * **HTML:**  Consider how HTML elements (like `<audio>` or `<video>`) might be sources of audio that are processed by this panner.
    * **CSS:**  While CSS doesn't directly interact with audio processing, it might influence the user interface elements that control audio panning. However, the connection is very indirect.

4. **Logical Examples (Input/Output):**
    * **Input:** Think about the inputs to the `Pan` function: azimuth, elevation, an audio input (mono or stereo).
    * **Output:** The output is a stereo audio bus representing the spatialized sound.
    * **Assumptions:**  I need to make reasonable assumptions about the HRTF database and the audio data.

5. **Common Errors:** Consider common mistakes developers might make when using the Web Audio API or when interacting with spatial audio concepts:
    * Incorrectly setting azimuth/elevation values.
    * Misunderstanding mono vs. stereo input.
    * Not handling the asynchronous loading of HRTF data.

6. **Review the Code for Details:**  Look for specific implementation details within the code (like the use of FFTs, delay lines, crossfading) to provide a more accurate and comprehensive explanation.

7. **Structure the Answer:** Organize the information clearly with headings for functionality, web technology relationships, examples, and common errors.
这个文件 `blink/renderer/platform/audio/hrtf_panner.cc` 是 Chromium Blink 渲染引擎中用于实现基于头部相关传输函数 (HRTF) 的音频声像控制（spatialization 或 panning）的功能模块。它允许将单声道或立体声音频源定位在 3D 空间中的特定位置，从而模拟声音从特定方向到达听者的效果。

以下是它的主要功能：

1. **基于 HRTF 的空间音频处理:**  核心功能是使用 HRTF 数据来模拟声音从特定方位角和仰角到达听者的双耳的方式。这通过对输入音频信号应用特定的滤波和延迟来实现，这些滤波和延迟是从 HRTF 数据库中获取的。

2. **加载和管理 HRTF 数据库:**  该模块依赖于 `HRTFDatabaseLoader` 来加载和管理 HRTF 数据。HRTF 数据通常包含在不同方位角和仰角上测量的头部对声音的响应（脉冲响应）。

3. **方位角和仰角控制:**  提供了 `Pan` 和 `PanWithSampleAccurateValues` 方法来根据给定的方位角（azimuth）和仰角（elevation）控制音频源的位置。

4. **单声道和立体声输入处理:**  可以处理单声道和立体声音频输入。对于立体声输入，它分别使用左声道和右声道的 HRTF 进行处理。

5. **平滑过渡 (Crossfading):**  为了避免在音频源位置快速变化时产生明显的咔嗒声或颗粒感，该模块实现了平滑过渡的功能。当方位角或仰角发生变化时，它会在新旧 HRTF 之间进行交叉淡化。

6. **延迟线 (Delay Lines):** 使用延迟线来模拟声音到达左右耳的时间差 (Interaural Time Difference, ITD)，这是 HRTF 空间化中重要的一个方面。

7. **卷积处理 (Convolution):**  使用快速傅里叶变换 (FFT) 进行卷积运算，将输入音频信号与 HRTF 脉冲响应进行卷积，从而模拟 HRTF 的滤波效果。

8. **性能优化:**  代码中考虑了性能，例如使用 FFT 进行高效卷积，并根据采样率调整 FFT 大小。

9. **尾部处理 (Tail Processing) 和延迟 (Latency):**  由于使用了卷积运算，HRTF 处理器会引入一定的延迟和尾部。该模块提供了 `RequiresTailProcessing`、`TailTime` 和 `LatencyTime` 方法来报告这些信息。

**与 JavaScript, HTML, CSS 的关系：**

该 C++ 文件位于 Blink 引擎的底层音频处理部分，它与 JavaScript、HTML 和 CSS 的交互主要通过 Web Audio API 实现。

* **JavaScript (Web Audio API):**
    * **`PannerNode`:** Web Audio API 中的 `PannerNode` 可以使用 HRTF 进行空间化处理。当 `PannerNode` 的 `panningModel` 属性设置为 "HRTF" 时，浏览器底层就会使用 `hrtf_panner.cc` 中的代码来执行实际的音频处理。
    * **控制参数:** JavaScript 代码可以通过 `PannerNode` 的 `positionX`, `positionY`, `positionZ` 属性来设置音频源在 3D 空间中的位置。这些三维坐标会被转换成方位角和仰角，并传递给 `hrtf_panner.cc` 中的 `Pan` 方法。
    * **HRTF 数据库加载:** Web Audio API 允许开发者提供自定义的 HRTF 数据库。`HRTFDatabaseLoader` 负责加载这些数据，而 `hrtf_panner.cc` 使用加载后的数据进行处理。

    **示例：**
    ```javascript
    const audioCtx = new AudioContext();
    const audioElement = document.getElementById('myAudio');
    const source = audioCtx.createMediaElementSource(audioElement);
    const panner = audioCtx.createPanner();

    // 设置 PannerNode 使用 HRTF 模型
    panner.panningModel = 'HRTF';

    // 设置音频源的位置 (假设耳朵位于 (0, 0, 0))
    panner.positionX.setValueAtTime(1, audioCtx.currentTime); // 将音源放在右侧
    panner.positionY.setValueAtTime(0, audioCtx.currentTime);
    panner.positionZ.setValueAtTime(0, audioCtx.currentTime);

    source.connect(panner).connect(audioCtx.destination);
    ```
    在这个例子中，JavaScript 代码创建了一个 `PannerNode` 并将其 `panningModel` 设置为 "HRTF"。当设置 `panner.positionX` 等属性时，浏览器底层的 `hrtf_panner.cc` 代码会被调用来根据 HRTF 数据对音频进行空间化处理，模拟声音从右侧传来的效果。

* **HTML:**
    * **`<audio>` 或 `<video>` 元素:**  HTML 中的 `<audio>` 或 `<video>` 元素可以作为音频源，通过 Web Audio API 的 `createMediaElementSource` 节点连接到 `PannerNode` 进行处理。

    **示例：**
    ```html
    <audio id="myAudio" src="mysound.mp3" controls></audio>
    ```
    JavaScript 代码可以获取这个 `<audio>` 元素，并将其音频输出连接到使用 HRTF 的 `PannerNode`。

* **CSS:**
    * **间接关系:** CSS 本身不直接控制音频处理。但是，可以使用 CSS 来创建用户界面元素（例如滑块或旋钮），用户可以通过这些元素来控制音频源的方位角和仰角。JavaScript 可以监听这些 UI 元素的事件，并更新 `PannerNode` 的位置属性。

**逻辑推理的假设输入与输出：**

**假设输入：**

* **采样率 (sample_rate):** 44100 Hz
* **渲染量帧数 (render_quantum_frames):** 128 帧
* **方位角 (desired_azimuth):** 45 度（表示声音位于听者右前方）
* **仰角 (elevation):** 0 度（表示声音位于水平面上）
* **输入音频总线 (input_bus):** 单声道音频总线，包含一段正弦波信号。
* **HRTF 数据库:**  已加载包含各种方位角和仰角的 HRTF 脉冲响应。

**逻辑推理过程：**

1. **计算目标方位角索引和混合值:** `CalculateDesiredAzimuthIndexAndBlend` 函数会根据输入的方位角 (45 度) 计算出最接近的 HRTF 数据索引，以及一个用于在两个相邻 HRTF 之间进行插值的混合值。
2. **获取 HRTF 核:** `GetKernelsFromAzimuthElevation` 函数会从 HRTF 数据库中检索出与目标方位角和仰角最相关的 HRTF 脉冲响应（或两个，如果需要插值）。
3. **延迟线处理:**  根据 HRTF 数据中的延迟信息，对输入音频信号进行延迟，模拟双耳时间差。
4. **卷积处理:**  将延迟后的输入信号与检索到的 HRTF 脉冲响应进行卷积。这个过程会改变音频信号的频谱特性，模拟声音从特定方向到达耳朵时产生的频率响应变化。
5. **交叉淡化 (如果需要):** 如果方位角或仰角在之前的处理中发生了变化，则会在新旧 HRTF 处理结果之间进行平滑过渡。

**假设输出：**

* **输出音频总线 (output_bus):** 立体声音频总线。
    * **左声道数据:** 包含经过 HRTF 处理的音频信号，模拟声音到达左耳的效果（包括滤波和延迟）。
    * **右声道数据:** 包含经过 HRTF 处理的音频信号，模拟声音到达右耳的效果（滤波和延迟可能与左声道不同）。

**输出结果的特点:**

* 由于方位角为 45 度，右声道的声音可能会比左声道稍早到达，并且频谱特性也会有所不同，从而产生声音来自右前方的感觉。
* 输出信号的频谱特性会根据所使用的 HRTF 数据进行调整，模拟头部和外耳对声音的滤波效应。

**用户或编程常见的使用错误：**

1. **方位角和仰角单位错误:**  `HRTFPanner` 通常期望方位角在 -180 到 +180 度之间，仰角在 -90 到 +90 度之间。传递超出此范围的值可能会导致意外的结果或错误。

    **示例：**  JavaScript 代码中将方位角设置为 360 度。
    ```javascript
    panner.positionX.setValueAtTime(Math.cos(360 * Math.PI / 180), audioCtx.currentTime);
    panner.positionZ.setValueAtTime(Math.sin(360 * Math.PI / 180), audioCtx.currentTime);
    ```
    在这种情况下，`CalculateDesiredAzimuthIndexAndBlend` 函数会将 360 度转换为 0 度，导致声音被错误地定位在正前方。

2. **未正确加载 HRTF 数据库:** 如果 `HRTFDatabaseLoader` 未能成功加载 HRTF 数据，`database` 指针可能为空。在这种情况下，`Pan` 方法会直接将输入复制到输出，而不会进行任何空间化处理。

    **示例：**  HRTF 数据库文件路径错误或文件损坏。开发者没有检查 `database_loader_->Database()` 的返回值是否为空。

3. **假设单声道输入会被复制到双声道输出:** 虽然 `HRTFPanner` 的输出是双声道的，但如果输入是单声道的，开发者可能会错误地认为左右声道会完全相同。实际上，HRTF 处理会为左右声道应用不同的滤波和延迟，即使输入是单声道。

4. **在快速移动的音源上期望平滑的过渡，但过渡时间不足:**  `HRTFPanner` 使用交叉淡化来平滑过渡，但如果音源移动速度非常快，默认的交叉淡化时间可能不足以完全消除咔嗒声或颗粒感。开发者可能需要调整相关的参数（如果允许）或者采取其他平滑策略。

5. **在不支持 HRTF 模式的 `PannerNode` 上设置位置:**  如果 `PannerNode` 的 `panningModel` 没有设置为 "HRTF"，设置 `positionX`, `positionY`, `positionZ` 属性将不会调用 `hrtf_panner.cc` 中的代码。开发者需要确保正确配置 `PannerNode` 以使用 HRTF 模式。

理解 `hrtf_panner.cc` 的功能有助于开发者在使用 Web Audio API 进行 3D 音频处理时，更好地理解底层的实现原理以及可能遇到的问题。

Prompt: 
```
这是目录为blink/renderer/platform/audio/hrtf_panner.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

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

#include "third_party/blink/renderer/platform/audio/hrtf_panner.h"

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/audio/fft_frame.h"
#include "third_party/blink/renderer/platform/audio/hrtf_database.h"
#include "third_party/blink/renderer/platform/audio/hrtf_database_loader.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

namespace {

// The value of 2 milliseconds is larger than the largest delay which exists in
// any HRTFKernel from the default HRTFDatabase (0.0136 seconds).
// We ASSERT the delay values used in process() with this value.
constexpr double kMaxDelayTimeSeconds = 0.002;

constexpr int kUninitializedAzimuth = -1;

// Given an azimuth angle in the range -180 -> +180, returns the corresponding
// azimuth index for the database, and azimuthBlend which is an interpolation
// value from 0 -> 1.
int CalculateDesiredAzimuthIndexAndBlend(double azimuth,
                                         double& azimuth_blend) {
  // Convert the azimuth angle from the range -180 -> +180 into the range 0 ->
  // 360.  The azimuth index may then be calculated from this positive value.
  if (azimuth < 0) {
    azimuth += 360.0;
  }

  const int number_of_azimuths = HRTFDatabase::NumberOfAzimuths();
  const double angle_between_azimuths = 360.0 / number_of_azimuths;

  // Calculate the azimuth index and the blend (0 -> 1) for interpolation.
  const double desired_azimuth_index_float = azimuth / angle_between_azimuths;
  int desired_azimuth_index = static_cast<int>(desired_azimuth_index_float);
  azimuth_blend =
      desired_azimuth_index_float - static_cast<double>(desired_azimuth_index);

  // We don't immediately start using this azimuth index, but instead approach
  // this index from the last index we rendered at.  This minimizes the clicks
  // and graininess for moving sources which occur otherwise.
  desired_azimuth_index =
      ClampTo(desired_azimuth_index, 0, number_of_azimuths - 1);
  return desired_azimuth_index;
}

}  // namespace

HRTFPanner::HRTFPanner(float sample_rate,
                       unsigned render_quantum_frames,
                       HRTFDatabaseLoader* database_loader)
    : database_loader_(database_loader),
      sample_rate_(sample_rate),
      azimuth_index1_(kUninitializedAzimuth),
      azimuth_index2_(kUninitializedAzimuth),
      convolver_l1_(FftSizeForSampleRate(sample_rate)),
      convolver_r1_(FftSizeForSampleRate(sample_rate)),
      convolver_l2_(FftSizeForSampleRate(sample_rate)),
      convolver_r2_(FftSizeForSampleRate(sample_rate)),
      delay_line_l_(kMaxDelayTimeSeconds, sample_rate, render_quantum_frames),
      delay_line_r_(kMaxDelayTimeSeconds, sample_rate, render_quantum_frames),
      temp_l1_(render_quantum_frames),
      temp_r1_(render_quantum_frames),
      temp_l2_(render_quantum_frames),
      temp_r2_(render_quantum_frames),
      render_quantum_frames_(render_quantum_frames) {
  DCHECK(database_loader);
}

HRTFPanner::~HRTFPanner() = default;

unsigned HRTFPanner::FftSizeForSampleRate(float sample_rate) {
  // The HRTF impulse responses (loaded as audio resources) are 512
  // sample-frames @44.1KHz.  Currently, we truncate the impulse responses to
  // half this size, but an FFT-size of twice impulse response size is needed
  // (for convolution).  So for sample rates around 44.1KHz an FFT size of 512
  // is good.  For different sample rates, the truncated response is resampled.
  // The resampled length is used to compute the FFT size by choosing a power
  // of two that is greater than or equal the resampled length. This power of
  // two is doubled to get the actual FFT size.

  DCHECK(audio_utilities::IsValidAudioBufferSampleRate(sample_rate));

  constexpr int truncated_impulse_length = 256;
  const double sample_rate_ratio = sample_rate / 44100;
  const double resampled_length = truncated_impulse_length * sample_rate_ratio;

  // This is the size used for analysis frames in the HRTF kernel.  The
  // convolvers used by the kernel are twice this size.
  unsigned analysis_fft_size = 1u
                               << static_cast<unsigned>(log2(resampled_length));

  // Don't let the analysis size be smaller than the supported size
  analysis_fft_size = std::max(analysis_fft_size, FFTFrame::MinFFTSize());

  const unsigned convolver_fft_size = 2 * analysis_fft_size;

  // Make sure this size of convolver is supported.
  DCHECK_LE(convolver_fft_size, FFTFrame::MaxFFTSize());

  return convolver_fft_size;
}

void HRTFPanner::Reset() {
  convolver_l1_.Reset();
  convolver_r1_.Reset();
  convolver_l2_.Reset();
  convolver_r2_.Reset();
  delay_line_l_.Reset();
  delay_line_r_.Reset();
}

void HRTFPanner::Pan(double desired_azimuth,
                     double elevation,
                     const AudioBus* input_bus,
                     AudioBus* output_bus,
                     uint32_t frames_to_process,
                     AudioBus::ChannelInterpretation channel_interpretation) {
  const unsigned num_input_channels =
      input_bus ? input_bus->NumberOfChannels() : 0;

  DCHECK(input_bus);
  DCHECK_GE(num_input_channels, 1u);
  DCHECK_LE(num_input_channels, 2u);

  DCHECK(output_bus);
  DCHECK_EQ(output_bus->NumberOfChannels(), 2u);
  DCHECK_LE(frames_to_process, output_bus->length());

  const HRTFDatabase* const database = database_loader_->Database();
  if (!database) {
    output_bus->CopyFrom(*input_bus, channel_interpretation);
    return;
  }

  // IRCAM HRTF azimuths values from the loaded database is reversed from the
  // panner's notion of azimuth.
  const double azimuth = -desired_azimuth;

  DCHECK_GE(azimuth, -180.0);
  DCHECK_LE(azimuth, 180.0);

  // Normally, we'll just be dealing with mono sources.
  // If we have a stereo input, implement stereo panning with left source
  // processed by left HRTF, and right source by right HRTF.
  const AudioChannel* input_channel_l =
      input_bus->ChannelByType(AudioBus::kChannelLeft);
  const AudioChannel* input_channel_r =
      num_input_channels > 1 ? input_bus->ChannelByType(AudioBus::kChannelRight)
                             : nullptr;

  // Get source and destination pointers.
  const float* source_l = input_channel_l->Data();
  const float* source_r =
      num_input_channels > 1 ? input_channel_r->Data() : source_l;
  float* destination_l =
      output_bus->ChannelByType(AudioBus::kChannelLeft)->MutableData();
  float* destination_r =
      output_bus->ChannelByType(AudioBus::kChannelRight)->MutableData();

  double azimuth_blend;
  const int desired_azimuth_index =
      CalculateDesiredAzimuthIndexAndBlend(azimuth, azimuth_blend);

  // Initially snap azimuth and elevation values to first values encountered.
  if (azimuth_index1_ == kUninitializedAzimuth) {
    azimuth_index1_ = desired_azimuth_index;
    elevation1_ = elevation;
  }
  if (azimuth_index2_ == kUninitializedAzimuth) {
    azimuth_index2_ = desired_azimuth_index;
    elevation2_ = elevation;
  }

  // Cross-fade / transition over a period of around 45 milliseconds.
  // This is an empirical value tuned to be a reasonable trade-off between
  // smoothness and speed.
  const double fade_frames = SampleRate() <= 48000 ? 2048 : 4096;

  // Check for azimuth and elevation changes, initiating a cross-fade if needed.
  if (!crossfade_x_ && crossfade_selection_ == kCrossfadeSelection1) {
    if (desired_azimuth_index != azimuth_index1_ || elevation != elevation1_) {
      // Cross-fade from 1 -> 2
      crossfade_incr_ = 1 / fade_frames;
      azimuth_index2_ = desired_azimuth_index;
      elevation2_ = elevation;
    }
  }
  if (crossfade_x_ == 1 && crossfade_selection_ == kCrossfadeSelection2) {
    if (desired_azimuth_index != azimuth_index2_ || elevation != elevation2_) {
      // Cross-fade from 2 -> 1
      crossfade_incr_ = -1 / fade_frames;
      azimuth_index1_ = desired_azimuth_index;
      elevation1_ = elevation;
    }
  }

  // This algorithm currently requires that we process in power-of-two size
  // chunks of at least `RenderQuantumFrames()`.
  DCHECK_EQ(1UL << static_cast<int>(log2(frames_to_process)),
            frames_to_process);
  DCHECK_GE(frames_to_process, RenderQuantumFrames());

  const unsigned kFramesPerSegment = RenderQuantumFrames();
  const unsigned number_of_segments = frames_to_process / kFramesPerSegment;

  for (unsigned segment = 0; segment < number_of_segments; ++segment) {
    // Get the HRTFKernels and interpolated delays.
    HRTFKernel* kernel_l1;
    HRTFKernel* kernel_r1;
    HRTFKernel* kernel_l2;
    HRTFKernel* kernel_r2;
    double frame_delay_l1;
    double frame_delay_r1;
    double frame_delay_l2;
    double frame_delay_r2;
    database->GetKernelsFromAzimuthElevation(azimuth_blend, azimuth_index1_,
                                             elevation1_, kernel_l1, kernel_r1,
                                             frame_delay_l1, frame_delay_r1);
    database->GetKernelsFromAzimuthElevation(azimuth_blend, azimuth_index2_,
                                             elevation2_, kernel_l2, kernel_r2,
                                             frame_delay_l2, frame_delay_r2);

    DCHECK(kernel_l1);
    DCHECK(kernel_r1);
    DCHECK(kernel_l2);
    DCHECK(kernel_r2);
    DCHECK_LT(frame_delay_l1 / SampleRate(), kMaxDelayTimeSeconds);
    DCHECK_LT(frame_delay_r1 / SampleRate(), kMaxDelayTimeSeconds);
    DCHECK_LT(frame_delay_l2 / SampleRate(), kMaxDelayTimeSeconds);
    DCHECK_LT(frame_delay_r2 / SampleRate(), kMaxDelayTimeSeconds);

    // Crossfade inter-aural delays based on transitions.
    const double frame_delay_l =
        (1 - crossfade_x_) * frame_delay_l1 + crossfade_x_ * frame_delay_l2;
    const double frame_delay_r =
        (1 - crossfade_x_) * frame_delay_r1 + crossfade_x_ * frame_delay_r2;

    // Calculate the source and destination pointers for the current segment.
    const unsigned offset = segment * kFramesPerSegment;
    const float* segment_source_l = source_l + offset;
    const float* segment_source_r = source_r + offset;
    float* segment_destination_l = destination_l + offset;
    float* segment_destination_r = destination_r + offset;

    // First run through delay lines for inter-aural time difference.
    delay_line_l_.SetDelayFrames(frame_delay_l);
    delay_line_r_.SetDelayFrames(frame_delay_r);
    delay_line_l_.ProcessKRate(segment_source_l, segment_destination_l,
                               kFramesPerSegment);
    delay_line_r_.ProcessKRate(segment_source_r, segment_destination_r,
                               kFramesPerSegment);

    const bool needs_crossfading = crossfade_incr_;

    // Have the convolvers render directly to the final destination if we're not
    // cross-fading.
    float* convolution_destination_l1 =
        needs_crossfading ? temp_l1_.Data() : segment_destination_l;
    float* convolution_destination_r1 =
        needs_crossfading ? temp_r1_.Data() : segment_destination_r;
    float* convolution_destination_l2 =
        needs_crossfading ? temp_l2_.Data() : segment_destination_l;
    float* convolution_destination_r2 =
        needs_crossfading ? temp_r2_.Data() : segment_destination_r;

    // Now do the convolutions.
    // Note that we avoid doing convolutions on both sets of convolvers if we're
    // not currently cross-fading.

    if (crossfade_selection_ == kCrossfadeSelection1 || needs_crossfading) {
      convolver_l1_.Process(kernel_l1->FftFrame(), segment_destination_l,
                            convolution_destination_l1, kFramesPerSegment);
      convolver_r1_.Process(kernel_r1->FftFrame(), segment_destination_r,
                            convolution_destination_r1, kFramesPerSegment);
    }

    if (crossfade_selection_ == kCrossfadeSelection2 || needs_crossfading) {
      convolver_l2_.Process(kernel_l2->FftFrame(), segment_destination_l,
                            convolution_destination_l2, kFramesPerSegment);
      convolver_r2_.Process(kernel_r2->FftFrame(), segment_destination_r,
                            convolution_destination_r2, kFramesPerSegment);
    }

    if (needs_crossfading) {
      // Apply linear cross-fade.
      float x = crossfade_x_;
      const float incr = crossfade_incr_;
      for (unsigned i = 0; i < kFramesPerSegment; ++i) {
        segment_destination_l[i] = (1 - x) * convolution_destination_l1[i] +
                                   x * convolution_destination_l2[i];
        segment_destination_r[i] = (1 - x) * convolution_destination_r1[i] +
                                   x * convolution_destination_r2[i];
        x += incr;
      }
      // Update cross-fade value from local.
      crossfade_x_ = x;

      if (crossfade_incr_ > 0 && fabs(crossfade_x_ - 1) < crossfade_incr_) {
        // We've fully made the crossfade transition from 1 -> 2.
        crossfade_selection_ = kCrossfadeSelection2;
        crossfade_x_ = 1;
        crossfade_incr_ = 0;
      } else if (crossfade_incr_ < 0 && fabs(crossfade_x_) < -crossfade_incr_) {
        // We've fully made the crossfade transition from 2 -> 1.
        crossfade_selection_ = kCrossfadeSelection1;
        crossfade_x_ = 0;
        crossfade_incr_ = 0;
      }
    }
  }
}

void HRTFPanner::PanWithSampleAccurateValues(
    double* desired_azimuth,
    double* elevation,
    const AudioBus* input_bus,
    AudioBus* output_bus,
    uint32_t frames_to_process,
    AudioBus::ChannelInterpretation channel_interpretation) {
  // Sample-accurate (a-rate) HRTF panner is not implemented, just k-rate.  Just
  // grab the current azimuth/elevation and use that.
  //
  // We are assuming that the inherent smoothing in the HRTF processing is good
  // enough, and we don't want to increase the complexity of the HRTF panner by
  // 15-20 times.  (We need to compute one output sample for each possibly
  // different impulse response.  That N^2.  Previously, we used an FFT to do
  // them all at once for a complexity of N/log2(N).  Hence, N/log2(N) times
  // more complex.)
  Pan(desired_azimuth[0], elevation[0], input_bus, output_bus,
      frames_to_process, channel_interpretation);
}

bool HRTFPanner::RequiresTailProcessing() const {
  // Always return true since the tail and latency are never zero.
  return true;
}

double HRTFPanner::TailTime() const {
  // Because HRTFPanner is implemented with a DelayKernel and a FFTConvolver,
  // the tailTime of the HRTFPanner is the sum of the tailTime of the
  // DelayKernel and the tailTime of the FFTConvolver, which is
  // MaxDelayTimeSeconds and fftSize() / 2, respectively.
  return kMaxDelayTimeSeconds +
         (FftSize() / 2) / static_cast<double>(SampleRate());
}

double HRTFPanner::LatencyTime() const {
  // The latency of a FFTConvolver is also fftSize() / 2, and is in addition to
  // its tailTime of the same value.
  return (FftSize() / 2) / static_cast<double>(SampleRate());
}

}  // namespace blink

"""

```