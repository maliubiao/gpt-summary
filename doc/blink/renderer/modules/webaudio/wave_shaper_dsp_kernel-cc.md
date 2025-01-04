Response:
Let's break down the thought process to analyze this C++ code and generate the comprehensive explanation.

**1. Initial Code Examination and Goal Identification:**

* **File Path:**  `blink/renderer/modules/webaudio/wave_shaper_dsp_kernel.cc` immediately tells us this is part of the Web Audio API implementation within the Blink rendering engine (Chromium). Specifically, it's related to the `WaveShaperNode`.
* **Keywords:**  `WaveShaperDSPKernel`, `Process`, `Curve`, `Oversample`, `UpSampler`, `DownSampler`. These words are strong indicators of the code's core function:  manipulating audio signals based on a curve, potentially using oversampling techniques.
* **Copyright Notice:**  Indicates the code's origin (Google/Apple) and licensing (BSD). This is good to note for understanding the context but not crucial for the functional analysis.
* **Includes:**  Headers like `<algorithm>`, `<memory>`, platform-specific audio and math utilities, and threading primitives hint at the types of operations being performed. The architecture-specific includes (`xmmintrin.h`, `arm_neon.h`) point to performance optimizations.

**2. Core Functionality - `Process` and `WaveShaperCurveValues`:**

* **`Process` Function:** This is the entry point for processing audio. The `switch` statement based on `Oversample()` is a key structural element. It directs the audio processing to different functions (`ProcessCurve`, `ProcessCurve2x`, `ProcessCurve4x`). This immediately suggests that the code handles different oversampling rates.
* **`ProcessCurve`:**  This seems to be the fundamental processing logic. It checks for a valid curve and then calls `WaveShaperCurveValues`. If no curve is present, it passes the audio through unchanged. This is important for understanding the "bypass" behavior.
* **`WaveShaperCurveValues`:** This function is where the core waveshaping happens. The comments describe the process of calculating a `virtual_index` based on the input signal, then using this index to look up or interpolate values in the `curve_data`. The use of vector math (`vector_math::Vsadd`, `Vsmul`, etc.) and platform-specific intrinsics (`__m128`, `vld1q_f32`) points to optimized signal processing.

**3. Oversampling Logic:**

* **`kOverSample2x` and `kOverSample4x` Cases:**  These cases in the `Process` function utilize `UpSampler` and `DownSampler` objects. The names are self-explanatory. This confirms that oversampling is implemented to potentially improve the quality of the waveshaping effect.
* **`LazyInitializeOversampling`:**  This function creates the `UpSampler` and `DownSampler` instances only when needed, optimizing resource usage.

**4. Connection to Web Technologies (JavaScript, HTML, CSS):**

* **Web Audio API:**  The directory name and the presence of `WaveShaperProcessor` strongly indicate a connection to the Web Audio API.
* **JavaScript:** The Web Audio API is primarily accessed through JavaScript. The connection is that this C++ code *implements* the functionality exposed by the JavaScript `WaveShaperNode`.
* **HTML:**  While not directly related to this *specific* file, the Web Audio API is used within HTML pages. The user might connect the `WaveShaperNode` to other audio nodes created in JavaScript and playing audio from `<audio>` or `<video>` elements.
* **CSS:** No direct connection to CSS.

**5. Logic Reasoning and Examples:**

* **`WaveShaperCurveValue`:**  The explanation of how the `virtual_index` is calculated and how interpolation is performed lends itself well to input/output examples. Choose a simple curve (e.g., a straight line) and test input values at the boundaries and in the middle.
* **Oversampling:**  Illustrate the flow of data with oversampling – upsampling, processing at the higher rate, and downsampling.

**6. User and Programming Errors:**

* **No Curve:**  Highlight the scenario where the user forgets to set a curve, leading to a pass-through effect.
* **Invalid Curve Data:**  Mention potential issues if the curve data is malformed or empty.
* **Incorrect Oversampling Settings:**  Point out that mismatches or incorrect use of oversampling settings could lead to unexpected results or performance issues.

**7. Debugging Clues:**

* **Stepping Through Code:** Suggest using a debugger to examine the values of variables at different stages.
* **Logging:**  Emphasize the usefulness of logging input and output values at various points in the `Process` function.
* **Oversampling Settings:** Check the oversampling settings to ensure they are as expected.
* **Curve Data Inspection:** Inspect the contents of the wave shaping curve.

**8. Structuring the Explanation:**

* **Categorize:**  Organize the information into logical sections (Functionality, Web Technology Relation, Logic Reasoning, Errors, Debugging).
* **Clarity and Conciseness:** Use clear and straightforward language. Avoid overly technical jargon where possible.
* **Examples:** Provide concrete examples to illustrate concepts.
* **Code Snippets:** Refer to specific parts of the code to support explanations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Might focus too much on the low-level details of the SIMD optimizations. *Correction:*  Realize that the high-level functionality and the connection to the Web Audio API are more important for a general understanding.
* **Overlooking error scenarios:** Initially might not consider all the possible error conditions. *Correction:*  Think about what could go wrong from a user's perspective or due to programming mistakes.
* **Not making the Web API connection explicit enough:**  The connection to JavaScript/HTML might be implicit. *Correction:*  Explicitly state that this C++ code *implements* the functionality of the `WaveShaperNode` in the Web Audio API.
* **Debugging steps too vague:** Initial debugging suggestions might be too generic. *Correction:* Provide more specific debugging steps relevant to the code, such as checking oversampling settings and curve data.
This C++ source code file, `wave_shaper_dsp_kernel.cc`, belonging to the Blink rendering engine (used in Chromium), implements the digital signal processing (DSP) kernel for the **`WaveShaperNode`** in the Web Audio API. Its primary function is to apply a non-linear distortion effect to audio signals based on a defined curve.

Here's a breakdown of its functionalities:

**1. Core Functionality: Applying a Wave Shaping Curve**

* **Distortion Effect:** The core purpose is to introduce harmonic distortion or other non-linear effects to an audio signal. This is achieved by mapping the input audio sample values to output values according to a pre-defined curve.
* **`WaveShaperCurveValue` Function:** This function takes an input audio sample, the wave shaping curve data, and the curve length. It calculates an index into the curve based on the input value and then performs linear interpolation between the two nearest points on the curve to determine the output value.
* **`WaveShaperCurveValues` Function:** This function processes a block of audio samples efficiently. It calculates the interpolated output values for each input sample based on the provided curve data, leveraging vector math optimizations (SIMD instructions like SSE on x86 and NEON on ARM) for performance.
* **`ProcessCurve` Function:** This is the main processing function when no oversampling is used. It retrieves the wave shaping curve from the `WaveShaperProcessor` and applies it to the input audio buffer using `WaveShaperCurveValues`. If no curve is set, it acts as a pass-through (no effect).

**2. Oversampling Support for Improved Quality**

* **Reducing Aliasing:**  Oversampling is a technique used to reduce aliasing artifacts that can occur during non-linear processing. This kernel supports 2x and 4x oversampling.
* **`ProcessCurve2x` and `ProcessCurve4x` Functions:** These functions implement the processing logic when 2x or 4x oversampling is enabled.
    * **Upsampling:** They use `UpSampler` objects to increase the sampling rate of the input audio.
    * **Processing at Higher Rate:** The `ProcessCurve` function is then called to apply the wave shaping at the higher sampling rate.
    * **Downsampling:**  `DownSampler` objects are used to bring the audio signal back down to the original sampling rate.
* **`LazyInitializeOversampling`:** This function initializes the `UpSampler` and `DownSampler` objects only when oversampling is actually needed, optimizing resource usage.

**3. Management and Lifecycle**

* **Constructor (`WaveShaperDSPKernel`):** Initializes the kernel, including allocating memory for internal buffers used in oversampling.
* **`Reset` Function:** Resets the internal state of the upsamplers and downsamplers.
* **`RequiresTailProcessing` Function:** Indicates whether the node requires processing of any remaining samples after the main processing block (relevant for certain DSP operations, though in this case, it always returns `true`).
* **`TailTime` Function:** Returns the duration of the tail processing (currently likely 0 but could be used for future extensions).
* **`LatencyTime` Function:** Calculates and returns the latency introduced by the oversampling process.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This C++ code directly implements the underlying DSP logic for the `WaveShaperNode` in the Web Audio API, which is accessed and manipulated through JavaScript.
    * **Example:** In JavaScript, you might create a `WaveShaperNode`, set its `curve` property (an array representing the wave shaping function), and connect it to other audio nodes. The `Process` function in this C++ file is what gets called behind the scenes when audio flows through this node.

    ```javascript
    const audioContext = new AudioContext();
    const oscillator = audioContext.createOscillator();
    const waveShaper = audioContext.createWaveShaper();

    // Define a simple wave shaping curve (example: hard clipping)
    const curve = new Float32Array([-1, -1, -1, 1, 1, 1]);
    waveShaper.curve = curve;

    oscillator.connect(waveShaper);
    waveShaper.connect(audioContext.destination);
    oscillator.start();
    ```

* **HTML:** The Web Audio API, and thus this code, is used within HTML pages to provide audio processing capabilities. Audio sources could come from `<audio>` or `<video>` elements, or be generated programmatically.
    * **Example:** An HTML page could have a button that, when clicked, starts an oscillator and pipes it through a `WaveShaperNode` to create a distorted sound.

* **CSS:** This specific C++ file has no direct relationship with CSS. CSS is for styling and visual presentation, while this code handles audio signal processing.

**Logic Reasoning and Examples:**

**Assumption:**  Let's assume a simple wave shaping curve: `curve = [-1, 1]`. This is a very small curve for demonstration.

**Scenario 1: Input Sample = 0**

* **`WaveShaperCurveValue` Input:** `input = 0`, `curve_data = [-1, 1]`, `curve_length = 2`
* **Calculation:**
    * `virtual_index = 0.5 * (0 + 1) * (2 - 1) = 0.5`
    * `index1 = floor(0.5) = 0`
    * `index2 = 0 + 1 = 1`
    * `interpolation_factor = 0.5 - 0 = 0.5`
    * `value1 = curve_data[0] = -1`
    * `value2 = curve_data[1] = 1`
    * `output = (1 - 0.5) * -1 + 0.5 * 1 = -0.5 + 0.5 = 0`
* **Output:** 0

**Scenario 2: Input Sample = 1**

* **`WaveShaperCurveValue` Input:** `input = 1`, `curve_data = [-1, 1]`, `curve_length = 2`
* **Calculation:**
    * `virtual_index = 0.5 * (1 + 1) * (2 - 1) = 1`
    * Since `virtual_index >= curve_length - 1`, the output is clamped to the last curve value.
    * `output = curve_data[1] = 1`
* **Output:** 1

**Scenario 3: Input Sample = -0.5**

* **`WaveShaperCurveValue` Input:** `input = -0.5`, `curve_data = [-1, 1]`, `curve_length = 2`
* **Calculation:**
    * `virtual_index = 0.5 * (-0.5 + 1) * (2 - 1) = 0.25`
    * `index1 = floor(0.25) = 0`
    * `index2 = 0 + 1 = 1`
    * `interpolation_factor = 0.25 - 0 = 0.25`
    * `value1 = curve_data[0] = -1`
    * `value2 = curve_data[1] = 1`
    * `output = (1 - 0.25) * -1 + 0.25 * 1 = -0.75 + 0.25 = -0.5`
* **Output:** -0.5

**User or Programming Common Usage Errors:**

1. **Not Setting a Curve:**  If the JavaScript code creates a `WaveShaperNode` but doesn't assign a `curve` to it, the `ProcessCurve` function will detect a null curve and simply pass the audio through without any effect. This might confuse the user if they expect distortion.
    ```javascript
    const waveShaper = audioContext.createWaveShaper();
    // Oops! Forgot to set waveShaper.curve = ...
    ```

2. **Providing an Empty Curve:** Setting an empty array as the curve will also result in the pass-through behavior in `ProcessCurve`.
    ```javascript
    const waveShaper = audioContext.createWaveShaper();
    waveShaper.curve = new Float32Array([]); // Empty curve
    ```

3. **Providing a Curve with Incorrect Data Types:** The `curve` property in JavaScript expects a `Float32Array`. Providing an array of integers or other data types might lead to unexpected behavior or errors.

4. **Using Oversampling Without Understanding its Implications:** Enabling oversampling increases computational cost. If the user's application is performance-sensitive, unnecessarily using high oversampling rates can lead to audio glitches or frame drops.

5. **Creating a Curve that Introduces Unwanted Artifacts:** The shape of the wave shaping curve directly determines the distortion characteristics. A poorly designed curve can lead to harsh or unpleasant sounds.

**User Operation Steps to Reach This Code (Debugging Scenario):**

Let's say a user is experiencing unexpected behavior with a `WaveShaperNode` and wants to debug it. Here's a possible sequence of actions:

1. **User creates an HTML page with JavaScript:** This page uses the Web Audio API to process audio.
2. **User adds a `WaveShaperNode`:** The JavaScript code instantiates a `WaveShaperNode`.
3. **User sets a `curve` for the `WaveShaperNode`:** The user defines a `Float32Array` and assigns it to the `curve` property.
4. **User connects audio nodes:** The `WaveShaperNode` is connected between an audio source (e.g., an oscillator, media element) and the audio destination (speakers).
5. **User plays audio:** The user triggers the audio playback.
6. **User notices unexpected sound:** The audio output from the `WaveShaperNode` doesn't sound as expected (e.g., no distortion, too much distortion, strange artifacts).
7. **User opens browser's developer tools:** Specifically, the "Sources" or "Debugger" tab.
8. **User sets a breakpoint in their JavaScript code:** They might set a breakpoint near where the `curve` is defined or where the `WaveShaperNode` is created and connected.
9. **User refreshes the page and the breakpoint is hit:** They can inspect the value of the `curve` variable to ensure it's what they intended.
10. **If the JavaScript looks correct, the issue might be in the underlying C++ implementation:**  To investigate further, a developer with access to the Chromium source code might:
    * **Search for `wave_shaper_dsp_kernel.cc`:**  They would locate this file in the Blink repository.
    * **Set breakpoints in the C++ code:**  They could add breakpoints in functions like `Process`, `WaveShaperCurveValue`, or `WaveShaperCurveValues`.
    * **Run Chromium in a debug build:** This allows the debugger to step through the C++ code.
    * **Reproduce the audio issue:**  By playing the audio in the debug build, the breakpoints in the C++ code would be hit.
    * **Inspect variables:** The developer could examine the input audio samples, the contents of the `curve_data`, the calculated `virtual_index`, and the interpolated output values to pinpoint where the unexpected behavior originates. For instance, they might find that the `virtual_index` calculation is off, or the interpolation logic has an error, or that the input samples are outside the expected range.
    * **Step through the code:** They can step line by line through the C++ code to understand the flow of execution and the values of variables at each step.

This detailed breakdown provides a comprehensive understanding of the `wave_shaper_dsp_kernel.cc` file's functionality, its connections to web technologies, potential usage errors, and how a developer might arrive at this code during a debugging session.

Prompt: 
```
这是目录为blink/renderer/modules/webaudio/wave_shaper_dsp_kernel.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/modules/webaudio/wave_shaper_dsp_kernel.h"

#include <algorithm>
#include <memory>

#include "build/build_config.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/audio/vector_math.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

#if defined(ARCH_CPU_X86_FAMILY)
#include <xmmintrin.h>
#elif defined(CPU_ARM_NEON)
#include <arm_neon.h>
#endif

namespace blink {

WaveShaperDSPKernel::WaveShaperDSPKernel(WaveShaperProcessor* processor)
    : AudioDSPKernel(processor),
      // 4 times render size to handle 4x oversampling.
      virtual_index_(4 * RenderQuantumFrames()),
      index_(4 * RenderQuantumFrames()),
      v1_(4 * RenderQuantumFrames()),
      v2_(4 * RenderQuantumFrames()),
      f_(4 * RenderQuantumFrames()) {
  if (processor->Oversample() != WaveShaperProcessor::kOverSampleNone) {
    LazyInitializeOversampling();
  }
}

void WaveShaperDSPKernel::LazyInitializeOversampling() {
  if (!temp_buffer_) {
    temp_buffer_ = std::make_unique<AudioFloatArray>(RenderQuantumFrames() * 2);
    temp_buffer2_ =
        std::make_unique<AudioFloatArray>(RenderQuantumFrames() * 4);
    up_sampler_ = std::make_unique<UpSampler>(RenderQuantumFrames());
    down_sampler_ = std::make_unique<DownSampler>(RenderQuantumFrames() * 2);
    up_sampler2_ = std::make_unique<UpSampler>(RenderQuantumFrames() * 2);
    down_sampler2_ = std::make_unique<DownSampler>(RenderQuantumFrames() * 4);
  }
}

void WaveShaperDSPKernel::Process(const float* source,
                                  float* destination,
                                  uint32_t frames_to_process) {
  switch (GetWaveShaperProcessor()->Oversample()) {
    case WaveShaperProcessor::kOverSampleNone:
      ProcessCurve(source, destination, frames_to_process);
      break;
    case WaveShaperProcessor::kOverSample2x:
      ProcessCurve2x(source, destination, frames_to_process);
      break;
    case WaveShaperProcessor::kOverSample4x:
      ProcessCurve4x(source, destination, frames_to_process);
      break;

    default:
      NOTREACHED();
  }
}

double WaveShaperDSPKernel::WaveShaperCurveValue(float input,
                                                 const float* curve_data,
                                                 int curve_length) const {
  // Calculate a virtual index based on input -1 -> +1 with -1 being curve[0],
  // +1 being curve[curveLength - 1], and 0 being at the center of the curve
  // data. Then linearly interpolate between the two points in the curve.
  double virtual_index = 0.5 * (input + 1) * (curve_length - 1);
  double output;
  if (virtual_index < 0) {
    // input < -1, so use curve[0]
    output = curve_data[0];
  } else if (virtual_index >= curve_length - 1) {
    // input >= 1, so use last curve value
    output = curve_data[curve_length - 1];
  } else {
    // The general case where -1 <= input < 1, where 0 <= virtualIndex <
    // curveLength - 1, so interpolate between the nearest samples on the
    // curve.
    unsigned index1 = static_cast<unsigned>(virtual_index);
    unsigned index2 = index1 + 1;
    double interpolation_factor = virtual_index - index1;

    double value1 = curve_data[index1];
    double value2 = curve_data[index2];

    output =
        (1.0 - interpolation_factor) * value1 + interpolation_factor * value2;
  }

  return output;
}

void WaveShaperDSPKernel::WaveShaperCurveValues(float* destination,
                                                const float* source,
                                                uint32_t frames_to_process,
                                                const float* curve_data,
                                                int curve_length) const {
  DCHECK_LE(frames_to_process, virtual_index_.size());
  // Index into the array computed from the source value.
  float* virtual_index = virtual_index_.Data();

  // virtual_index[k] =
  //   ClampTo(0.5 * (source[k] + 1) * (curve_length - 1),
  //           0.0f,
  //           static_cast<float>(curve_length - 1))

  // Add 1 to source puttting  result in virtual_index
  vector_math::Vsadd(source, 1, 1, virtual_index, 1, frames_to_process);

  // Scale virtual_index in place by (curve_lenth -1)/2
  vector_math::Vsmul(virtual_index, 1, 0.5 * (curve_length - 1), virtual_index,
                     1, frames_to_process);

  // Clip virtual_index, in place.
  vector_math::Vclip(virtual_index, 1, 0, curve_length - 1, virtual_index, 1,
                     frames_to_process);

  // index = floor(virtual_index)
  DCHECK_LE(frames_to_process, index_.size());
  float* index = index_.Data();

  // v1 and v2 hold the curve_data corresponding to the closest curve
  // values to the source sample.  To save memory, v1 will use the
  // destination array.
  DCHECK_LE(frames_to_process, v1_.size());
  DCHECK_LE(frames_to_process, v2_.size());
  float* v1 = v1_.Data();
  float* v2 = v2_.Data();

  // Interpolation factor: virtual_index - index.
  DCHECK_LE(frames_to_process, f_.size());
  float* f = f_.Data();

  int max_index = curve_length - 1;
  unsigned k = 0;
#if defined(ARCH_CPU_X86_FAMILY)
  {
    int loop_limit = frames_to_process / 4;

    // one = 1
    __m128i one = _mm_set1_epi32(1);

    // Do 4 eleemnts at a time
    for (int loop = 0; loop < loop_limit; ++loop, k += 4) {
      // v = virtual_index[k]
      __m128 v = _mm_loadu_ps(virtual_index + k);

      // index1 = static_cast<int>(v);
      __m128i index1 = _mm_cvttps_epi32(v);

      // v = static_cast<float>(index1) and save result to index[k:k+3]
      v = _mm_cvtepi32_ps(index1);
      _mm_storeu_ps(&index[k], v);

      // index2 = index2 + 1;
      __m128i index2 = _mm_add_epi32(index1, one);

      // Convert index1/index2 to arrays of 32-bit int values that are our
      // array indices to use to get the curve data.
      int32_t* i1 = reinterpret_cast<int32_t*>(&index1);
      int32_t* i2 = reinterpret_cast<int32_t*>(&index2);

      // Get the curve_data values and save them in v1 and v2,
      // carfully clamping the values.  If the input is NaN, index1
      // could be 0x8000000.
      v1[k] = curve_data[ClampTo(i1[0], 0, max_index)];
      v2[k] = curve_data[ClampTo(i2[0], 0, max_index)];
      v1[k + 1] = curve_data[ClampTo(i1[1], 0, max_index)];
      v2[k + 1] = curve_data[ClampTo(i2[1], 0, max_index)];
      v1[k + 2] = curve_data[ClampTo(i1[2], 0, max_index)];
      v2[k + 2] = curve_data[ClampTo(i2[2], 0, max_index)];
      v1[k + 3] = curve_data[ClampTo(i1[3], 0, max_index)];
      v2[k + 3] = curve_data[ClampTo(i2[3], 0, max_index)];
    }
  }
#elif defined(CPU_ARM_NEON)
  {
    int loop_limit = frames_to_process / 4;

    // Neon constants:
    //   zero = 0
    //   one  = 1
    //   max  = max_index
    int32x4_t zero = vdupq_n_s32(0);
    int32x4_t one = vdupq_n_s32(1);
    int32x4_t max = vdupq_n_s32(max_index);

    for (int loop = 0; loop < loop_limit; ++loop, k += 4) {
      // v = virtual_index
      float32x4_t v = vld1q_f32(virtual_index + k);

      // index1 = static_cast<int32_t>(v), then clamp to a valid index range for
      // curve_data
      int32x4_t index1 = vcvtq_s32_f32(v);
      index1 = vmaxq_s32(vminq_s32(index1, max), zero);

      // v = static_cast<float>(v) and save it away for later use.
      v = vcvtq_f32_s32(index1);
      vst1q_f32(&index[k], v);

      // index2 = index1 + 1, then clamp to a valid range for curve_data.
      int32x4_t index2 = vaddq_s32(index1, one);
      index2 = vmaxq_s32(vminq_s32(index2, max), zero);

      // Save index1/2 so we can get the individual parts.  Aligned to
      // 16 bytes for vst1q instruction.
      int32_t i1[4] __attribute__((aligned(16)));
      int32_t i2[4] __attribute__((aligned(16)));
      vst1q_s32(i1, index1);
      vst1q_s32(i2, index2);

      // Get curve elements corresponding to the indices.
      v1[k] = curve_data[i1[0]];
      v2[k] = curve_data[i2[0]];
      v1[k + 1] = curve_data[i1[1]];
      v2[k + 1] = curve_data[i2[1]];
      v1[k + 2] = curve_data[i1[2]];
      v2[k + 2] = curve_data[i2[2]];
      v1[k + 3] = curve_data[i1[3]];
      v2[k + 3] = curve_data[i2[3]];
    }
  }
#endif

  // Compute values for index1 and load the curve_data corresponding to indices.
  for (; k < frames_to_process; ++k) {
    unsigned index1 =
        ClampTo(static_cast<unsigned>(virtual_index[k]), 0, max_index);
    unsigned index2 = ClampTo(index1 + 1, 0, max_index);
    index[k] = index1;
    v1[k] = curve_data[index1];
    v2[k] = curve_data[index2];
  }

  // f[k] = virtual_index[k] - index[k]
  vector_math::Vsub(virtual_index, 1, index, 1, f, 1, frames_to_process);

  // Do the linear interpolation of the curve data:
  // destination[k] = v1[k] + f[k]*(v2[k] - v1[k])
  //
  // 1. v2[k] = v2[k] - v1[k]
  // 2. v2[k] = f[k]*v2[k] = f[k]*(v2[k] - v1[k])
  // 3. destination[k] = destination[k] + v2[k]
  //                   = v1[k] + f[k]*(v2[k] - v1[k])
  vector_math::Vsub(v2, 1, v1, 1, v2, 1, frames_to_process);
  vector_math::Vmul(f, 1, v2, 1, v2, 1, frames_to_process);
  vector_math::Vadd(v2, 1, v1, 1, destination, 1, frames_to_process);
}

void WaveShaperDSPKernel::ProcessCurve(const float* source,
                                       float* destination,
                                       uint32_t frames_to_process) {
  DCHECK(source);
  DCHECK(destination);
  DCHECK(GetWaveShaperProcessor());

  Vector<float>* curve = GetWaveShaperProcessor()->Curve();
  if (!curve) {
    // Act as "straight wire" pass-through if no curve is set.
    memcpy(destination, source, sizeof(float) * frames_to_process);
    return;
  }

  float* curve_data = curve->data();
  int curve_length = curve->size();

  DCHECK(curve_data);

  if (!curve_data || !curve_length) {
    memcpy(destination, source, sizeof(float) * frames_to_process);
    return;
  }

  // Apply waveshaping curve.
  WaveShaperCurveValues(destination, source, frames_to_process, curve_data,
                        curve_length);
}

void WaveShaperDSPKernel::ProcessCurve2x(const float* source,
                                         float* destination,
                                         uint32_t frames_to_process) {
  DCHECK_EQ(frames_to_process, RenderQuantumFrames());

  float* temp_p = temp_buffer_->Data();

  up_sampler_->Process(source, temp_p, frames_to_process);

  // Process at 2x up-sampled rate.
  ProcessCurve(temp_p, temp_p, frames_to_process * 2);

  down_sampler_->Process(temp_p, destination, frames_to_process * 2);
}

void WaveShaperDSPKernel::ProcessCurve4x(const float* source,
                                         float* destination,
                                         uint32_t frames_to_process) {
  DCHECK_EQ(frames_to_process, RenderQuantumFrames());

  float* temp_p = temp_buffer_->Data();
  float* temp_p2 = temp_buffer2_->Data();

  up_sampler_->Process(source, temp_p, frames_to_process);
  up_sampler2_->Process(temp_p, temp_p2, frames_to_process * 2);

  // Process at 4x up-sampled rate.
  ProcessCurve(temp_p2, temp_p2, frames_to_process * 4);

  down_sampler2_->Process(temp_p2, temp_p, frames_to_process * 4);
  down_sampler_->Process(temp_p, destination, frames_to_process * 2);
}

void WaveShaperDSPKernel::Reset() {
  if (up_sampler_) {
    up_sampler_->Reset();
    down_sampler_->Reset();
    up_sampler2_->Reset();
    down_sampler2_->Reset();
  }
}

bool WaveShaperDSPKernel::RequiresTailProcessing() const {
  // Always return true even if the tail time and latency might both be zero.
  return true;
}

double WaveShaperDSPKernel::TailTime() const {
  return tail_time_;
}

double WaveShaperDSPKernel::LatencyTime() const {
  size_t latency_frames = 0;
  WaveShaperDSPKernel* kernel = const_cast<WaveShaperDSPKernel*>(this);

  switch (kernel->GetWaveShaperProcessor()->Oversample()) {
    case WaveShaperProcessor::kOverSampleNone:
      break;
    case WaveShaperProcessor::kOverSample2x:
      latency_frames += up_sampler_->LatencyFrames();
      latency_frames += down_sampler_->LatencyFrames();
      break;
    case WaveShaperProcessor::kOverSample4x: {
      // Account for first stage upsampling.
      latency_frames += up_sampler_->LatencyFrames();
      latency_frames += down_sampler_->LatencyFrames();

      // Account for second stage upsampling.
      // and divide by 2 to get back down to the regular sample-rate.
      size_t latency_frames2 =
          (up_sampler2_->LatencyFrames() + down_sampler2_->LatencyFrames()) / 2;
      latency_frames += latency_frames2;
      break;
    }
    default:
      NOTREACHED();
  }

  return static_cast<double>(latency_frames) / SampleRate();
}

}  // namespace blink

"""

```