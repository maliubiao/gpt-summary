Response:
Let's break down the thought process to analyze the provided C++ code for the `Biquad` class.

**1. Initial Understanding - The Context:**

* **File Path:** `blink/renderer/platform/audio/biquad.cc`. This immediately tells us it's part of the Chromium Blink rendering engine, specifically related to audio processing within the platform layer. The name "biquad" is a strong indicator that it deals with a specific type of digital filter.
* **Copyright Notice:**  Standard boilerplate, indicating ownership and licensing. Not directly functional but important context.
* **Includes:**  These are crucial for understanding dependencies. We see:
    * `biquad.h`:  The header file for this class (likely defines the public interface).
    * Audio-related headers (`audio_utilities.h`, `denormal_disabler.h`).
    * Math-related headers (`wtf/math_extras.h`, `fdlibm/ieee754.h`, `<cmath>`, `<complex>`).
    * Platform-specific (`build_config.h`, `<Accelerate/Accelerate.h>` for macOS).
    * Standard library (`<stdio.h>`, `<algorithm>`).

**2. Core Functionality Identification - The "What":**

* **Constructor (`Biquad::Biquad`)**:  Sets up internal buffers, allocates memory for filter coefficients, and initializes the filter as a "pass-thru" (no filtering). The `render_quantum_frames` parameter suggests it processes audio in chunks.
* **Destructor (`Biquad::~Biquad`)**:  Standard cleanup (in this case, the default).
* **`Process`**: The main processing function. Takes input and output audio buffers and the number of frames to process. It has two primary paths:
    * **Sample-accurate processing:**  Handles dynamic filter coefficient changes on a per-sample basis.
    * **Block processing:**  Uses fixed filter coefficients for the entire processing block.
* **`ProcessFast` and `ProcessSliceFast` (macOS specific):** Optimized processing using the Accelerate framework for better performance.
* **`Reset`**: Clears the internal filter state (memory).
* **`Set...Params` functions:** A suite of methods (`SetLowpassParams`, `SetHighpassParams`, etc.) that calculate and set the filter coefficients for various filter types (low-pass, high-pass, shelving filters, peaking, all-pass, notch, bandpass). These involve mathematical formulas based on cutoff frequency, resonance/Q, and gain.
* **`SetNormalizedCoefficients`**: A helper function to set the filter coefficients after normalization.
* **`GetFrequencyResponse`**: Calculates the filter's magnitude and phase response at given frequencies. This is important for visualizing and analyzing the filter's behavior.
* **`TailFrame`**:  Estimates how long the filter's impulse response "tails off" below a certain threshold. This is crucial for knowing how much latency or delay is introduced by the filter.
* **Helper Functions:**  `pow10`, `RepeatedRootResponse`, `RootFinder` are internal utility functions used within the `Biquad` implementation.

**3. Relationship to Web Technologies (JavaScript, HTML, CSS) - The "Why":**

* **Web Audio API:** The `Biquad` class is a fundamental building block for the Web Audio API. JavaScript code using the `BiquadFilterNode` in the Web Audio API directly interacts with the underlying C++ `Biquad` implementation.
* **Parameters:**  The `Set...Params` functions directly correspond to the properties you can manipulate on a `BiquadFilterNode` in JavaScript (e.g., `type`, `frequency`, `Q`, `gain`).
* **Frequency Response:** The `GetFrequencyResponse` method maps to the `getFrequencyResponse()` method on a `BiquadFilterNode`, allowing JavaScript to analyze the filter's characteristics.
* **Latency:** The `TailFrame` function is relevant for understanding the inherent latency introduced by digital filters, although this might not be directly exposed as a property in the Web Audio API.

**4. Logic and Assumptions - The "How":**

* **Filter Structure:** The code implements a standard second-order IIR (Infinite Impulse Response) filter structure, evident from the coefficients `b0`, `b1`, `b2`, `a1`, `a2` and the processing equation in `Process`.
* **Normalization:** The `SetNormalizedCoefficients` function normalizes the coefficients by `a0`, which is a standard practice in digital filter design to avoid scaling issues.
* **Sample-accurate vs. Block Processing:**  The code intelligently handles cases where filter parameters change dynamically (sample-accurate) and cases where they remain constant within a processing block.
* **macOS Optimization:** The use of Accelerate framework functions demonstrates platform-specific optimizations for better performance on macOS.
* **Denormal Handling:** The `DenormalDisabler` class is used to prevent performance issues caused by denormal floating-point numbers.

**5. Common Errors - The "Gotchas":**

* **Invalid Parameter Values:**  The code includes clamping for parameters like `cutoff` and `frequency` to prevent nonsensical or unstable filter behavior. A user might accidentally provide values outside the valid range (e.g., negative frequency).
* **Unstable Filters (Q value):** The code mentions that negative `q` can lead to unstable filters. This is a common pitfall in filter design.
* **Performance with Sample-Accurate Automation:** While powerful, sample-accurate automation can be more computationally expensive than block processing. Users might overuse it when not strictly necessary.

**6. Refinement and Iteration (Self-Correction):**

* **Initial thought:** "This file does audio filtering."  **Refinement:** "More specifically, it implements a Biquad (second-order) IIR filter."
* **Initial thought:** "It's used by JavaScript." **Refinement:** "It's the *underlying implementation* for the `BiquadFilterNode` in the Web Audio API."
* **Initially missed:** The significance of the `TailFrame` function for latency calculation. Realized this during deeper analysis of the code.
* **Initially focused heavily on `Process`:** Recognized the importance of the `Set...Params` functions for configuring the filter and how they map to Web Audio API properties.

By following these steps – understanding the context, identifying core functionalities, relating it to web technologies, analyzing the logic, considering potential errors, and refining understanding – we can arrive at a comprehensive and accurate explanation of the code's purpose and relevance.
This C++ source code file, `biquad.cc`, located within the Chromium Blink rendering engine, implements a **Biquad filter**. A Biquad filter is a second-order Infinite Impulse Response (IIR) digital filter.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Digital Audio Filtering:** The primary function is to process digital audio signals by applying various filter effects. It acts as a building block for more complex audio processing.
2. **Second-Order IIR Filter Implementation:** It specifically implements a biquad filter, meaning it uses two poles and two zeros in its transfer function. This structure is versatile and can implement a wide range of filter types.
3. **Filter Coefficient Management:** It stores and manages the five coefficients (b0, b1, b2, a1, a2) that define the characteristics of the biquad filter.
4. **Filter Type Implementations:** It provides methods to set the filter coefficients for various standard filter types:
    * **Lowpass:** Allows frequencies below a cutoff frequency to pass through.
    * **Highpass:** Allows frequencies above a cutoff frequency to pass through.
    * **Low Shelf:** Boosts or attenuates low frequencies.
    * **High Shelf:** Boosts or attenuates high frequencies.
    * **Peaking (Bell):** Boosts or attenuates frequencies around a center frequency.
    * **Allpass:**  Passes all frequencies but modifies the phase response.
    * **Notch:** Attenuates frequencies around a center frequency.
    * **Bandpass:** Allows frequencies within a specific band to pass through.
5. **Audio Processing (`Process` method):** This is the core method that takes an input audio buffer, applies the filter based on the current coefficients, and writes the filtered audio to an output buffer. It handles both sample-accurate coefficient changes (for dynamic effects) and block-based processing.
6. **State Management:** It maintains internal state variables (x1, x2, y1, y2) which represent the previous input and output samples. These are necessary for the IIR filter's feedback mechanism.
7. **Resetting:**  Provides a `Reset()` method to clear the filter's internal state.
8. **Frequency Response Calculation (`GetFrequencyResponse`):**  Calculates the magnitude and phase response of the filter at given frequencies. This is useful for analyzing and visualizing the filter's effect.
9. **Tail Time Calculation (`TailFrame`):**  Estimates the time it takes for the filter's impulse response to decay below a certain threshold. This is important for understanding the filter's latency.
10. **Platform Optimization (macOS):** Includes platform-specific optimizations for macOS using the `Accelerate.framework` for potentially faster processing.
11. **Denormal Handling:** Includes mechanisms to handle denormal floating-point numbers, which can sometimes cause performance issues.

**Relationship to JavaScript, HTML, CSS:**

This `biquad.cc` file is a fundamental part of the implementation behind the **Web Audio API** in web browsers. Here's how it relates to web technologies:

* **JavaScript (Web Audio API):**
    * The `BiquadFilterNode` in the Web Audio API in JavaScript directly uses the functionality provided by this C++ code. When you create a `BiquadFilterNode` in JavaScript and set its properties (like `type`, `frequency`, `Q`, `gain`), you are indirectly calling the corresponding methods in this `Biquad` class.
    * **Example:**
        ```javascript
        const audioCtx = new AudioContext();
        const biquadFilter = audioCtx.createBiquadFilter();
        biquadFilter.type = 'lowpass';
        biquadFilter.frequency.value = 440;
        biquadFilter.Q.value = 1;
        ```
        This JavaScript code will eventually trigger calls to the `SetLowpassParams` method in the `biquad.cc` file with the provided `frequency` and `Q` values.
    * The `getFrequencyResponse()` method of the `BiquadFilterNode` in JavaScript directly corresponds to the `GetFrequencyResponse` method in this C++ file.

* **HTML:**
    * HTML provides the `<audio>` and `<video>` elements which can be sources for the Web Audio API. The `Biquad` filter can be used to process the audio streams from these elements.

* **CSS:**
    * CSS does not directly interact with the `Biquad` filter. However, CSS can indirectly influence audio processing by controlling aspects of the user interface that trigger audio events or parameter changes. For example, a CSS animation might control the gain of a filter.

**Logic and Assumptions with Hypothetical Input/Output:**

Let's consider the `Process` method with a simple example:

**Hypothetical Input:**

* **`source_p`:** A pointer to an array of floating-point audio samples, e.g., `[0.1, 0.2, 0.3, 0.4, 0.5]` (representing 5 audio frames).
* **`dest_p`:** A pointer to an empty array of the same size where the filtered output will be written.
* **`frames_to_process`:** 5.
* **Filter type:**  Assume a lowpass filter is configured with a certain cutoff frequency and resonance.
* **Internal filter state (initially):** `x1_ = 0`, `x2_ = 0`, `y1_ = 0`, `y2_ = 0`.
* **Filter coefficients (after `SetLowpassParams`):** Let's say `b0 = 0.1`, `b1 = 0.2`, `b2 = 0.1`, `a1 = -0.5`, `a2 = 0.2`.

**Logical Reasoning (simplified):**

The `Process` method iterates through each frame. For the first frame (k=0):

1. `x = source_p[0] = 0.1`
2. `y = b0 * x + b1 * x1_ + b2 * x2_ - a1 * y1_ - a2 * y2_`
   `y = 0.1 * 0.1 + 0.2 * 0 + 0.1 * 0 - (-0.5) * 0 - 0.2 * 0 = 0.01`
3. `dest_p[0] = y = 0.01`
4. Update state variables:
   `x2_ = x1_ = 0`
   `x1_ = x = 0.1`
   `y2_ = y1_ = 0`
   `y1_ = y = 0.01`

This process repeats for the remaining frames, using the updated state variables.

**Hypothetical Output:**

The `dest_p` array would contain the filtered audio samples. Due to the lowpass nature of the filter, higher frequencies present in the input would be attenuated. The exact output values depend on the specific filter coefficients. A possible output could be something like: `[0.01, 0.028, 0.054, 0.088, 0.13]` (these are illustrative and not exact calculations).

**User or Programming Common Usage Errors:**

1. **Setting Invalid Parameter Values:**
   * **Example:** Setting a negative cutoff frequency or a negative Q value. The code includes `ClampTo` and `std::max` to mitigate some of these, but providing nonsensical values might still lead to unexpected behavior or even unstable filters.
   * **Consequence:** The filter might not behave as intended, potentially producing no output, distorted output, or even infinitely increasing output (instability).

2. **Not Resetting the Filter When Needed:**
   * **Example:** Applying a filter to a long audio stream and then wanting to process a completely new, unrelated audio segment. If the filter's internal state is not reset, the previous audio will influence the filtering of the new segment.
   * **Consequence:** The beginning of the new audio segment will be affected by the tail of the previous processing.

3. **Incorrectly Interpreting Frequency Response:**
   * **Example:** Misunderstanding the normalized frequency used in `GetFrequencyResponse` (0 to 1, where 1 is the Nyquist frequency).
   * **Consequence:** Incorrect analysis of the filter's behavior.

4. **Performance Issues with Sample-Accurate Automation:**
   * **Example:**  Setting filter parameters to change every single sample using the Web Audio API's automation features when it's not strictly necessary.
   * **Consequence:** Increased CPU usage, potentially leading to audio glitches or dropped frames. The code handles this, but excessive sample-accurate processing can still be a performance bottleneck.

5. **Forgetting to Normalize Coefficients:**
   * Although the code handles normalization internally in `SetNormalizedCoefficients`, if someone were to try to implement a similar filter manually and forget to divide by `a0`, the filter's gain would be incorrect.

6. **Using a Q value of 0 for Peaking/Notch Filters:**
   * The code explicitly handles the case where Q is 0 for peaking/notch filters, setting the gain directly. However, a naive implementation without this check could lead to division by zero errors.

This detailed explanation covers the functionality of the `biquad.cc` file, its connection to web technologies, provides a logical example, and highlights potential usage errors.

Prompt: 
```
这是目录为blink/renderer/platform/audio/biquad.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/audio/biquad.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/audio/denormal_disabler.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/fdlibm/ieee754.h"

#include <stdio.h>
#include <algorithm>
#include <complex>
#if BUILDFLAG(IS_MAC)
#include <Accelerate/Accelerate.h>
#endif

namespace blink {

#if BUILDFLAG(IS_MAC)
const int kBiquadBufferSize = 1024;
#endif

// Compute 10^x = exp(x*log(10))
static double pow10(double x) {
  return fdlibm::expf(x * 2.30258509299404568402);
}

Biquad::Biquad(unsigned render_quantum_frames)
    : has_sample_accurate_values_(false) {
#if BUILDFLAG(IS_MAC)
  // Allocate two samples more for filter history
  input_buffer_.Allocate(kBiquadBufferSize + 2);
  output_buffer_.Allocate(kBiquadBufferSize + 2);
#endif

  // Allocate enough space for the a-rate filter coefficients to handle a
  // rendering quantum of 128 frames.
  b0_.Allocate(render_quantum_frames);
  b1_.Allocate(render_quantum_frames);
  b2_.Allocate(render_quantum_frames);
  a1_.Allocate(render_quantum_frames);
  a2_.Allocate(render_quantum_frames);

  // Initialize as pass-thru (straight-wire, no filter effect)
  SetNormalizedCoefficients(0, 1, 0, 0, 1, 0, 0);

  Reset();  // clear filter memory
}

Biquad::~Biquad() = default;

void Biquad::Process(const float* source_p,
                     float* dest_p,
                     uint32_t frames_to_process) {
  // WARNING: sourceP and destP may be pointing to the same area of memory!
  // Be sure to read from sourceP before writing to destP!
  if (HasSampleAccurateValues()) {
    int n = frames_to_process;

    // Create local copies of member variables
    double x1 = x1_;
    double x2 = x2_;
    double y1 = y1_;
    double y2 = y2_;

    const double* b0 = b0_.Data();
    const double* b1 = b1_.Data();
    const double* b2 = b2_.Data();
    const double* a1 = a1_.Data();
    const double* a2 = a2_.Data();

    for (int k = 0; k < n; ++k) {
      // FIXME: this can be optimized by pipelining the multiply adds...
      float x = *source_p++;
      float y = b0[k] * x + b1[k] * x1 + b2[k] * x2 - a1[k] * y1 - a2[k] * y2;

      *dest_p++ = y;

      // Update state variables
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
    }

    // Local variables back to member. Flush denormals here so we
    // don't slow down the inner loop above.
    x1_ = DenormalDisabler::FlushDenormalFloatToZero(x1);
    x2_ = DenormalDisabler::FlushDenormalFloatToZero(x2);
    y1_ = DenormalDisabler::FlushDenormalFloatToZero(y1);
    y2_ = DenormalDisabler::FlushDenormalFloatToZero(y2);

    // There is an assumption here that once we have sample accurate values we
    // can never go back to not having sample accurate values.  This is
    // currently true in the way AudioParamTimline is implemented: once an
    // event is inserted, sample accurate processing is always enabled.
    //
    // If so, then we never have to update the state variables for the MACOSX
    // path.  The structure of the state variable in these cases aren't well
    // documented so it's not clear how to update them anyway.
  } else {
#if BUILDFLAG(IS_MAC)
    double* input_p = input_buffer_.Data();
    double* output_p = output_buffer_.Data();

    // Set up filter state.  This is needed in case we're switching from
    // filtering with variable coefficients (i.e., with automations) to
    // fixed coefficients (without automations).
    input_p[0] = x2_;
    input_p[1] = x1_;
    output_p[0] = y2_;
    output_p[1] = y1_;

    // Use vecLib if available
    ProcessFast(source_p, dest_p, frames_to_process);

    // Copy the last inputs and outputs to the filter memory variables.
    // This is needed because the next rendering quantum might be an
    // automation which needs the history to continue correctly.  Because
    // sourceP and destP can be the same block of memory, we can't read from
    // sourceP to get the last inputs.  Fortunately, processFast has put the
    // last inputs in input[0] and input[1].
    x1_ = input_p[1];
    x2_ = input_p[0];
    y1_ = dest_p[frames_to_process - 1];
    y2_ = dest_p[frames_to_process - 2];

#else
    int n = frames_to_process;

    // Create local copies of member variables
    double x1 = x1_;
    double x2 = x2_;
    double y1 = y1_;
    double y2 = y2_;

    double b0 = b0_[0];
    double b1 = b1_[0];
    double b2 = b2_[0];
    double a1 = a1_[0];
    double a2 = a2_[0];

    while (n--) {
      // FIXME: this can be optimized by pipelining the multiply adds...
      float x = *source_p++;
      float y = b0 * x + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;

      *dest_p++ = y;

      // Update state variables
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
    }

    // Local variables back to member. Flush denormals here so we
    // don't slow down the inner loop above.
    x1_ = DenormalDisabler::FlushDenormalFloatToZero(x1);
    x2_ = DenormalDisabler::FlushDenormalFloatToZero(x2);
    y1_ = DenormalDisabler::FlushDenormalFloatToZero(y1);
    y2_ = DenormalDisabler::FlushDenormalFloatToZero(y2);
#endif
  }
}

#if BUILDFLAG(IS_MAC)

// Here we have optimized version using Accelerate.framework

void Biquad::ProcessFast(const float* source_p,
                         float* dest_p,
                         uint32_t frames_to_process) {
  double filter_coefficients[5];
  filter_coefficients[0] = b0_[0];
  filter_coefficients[1] = b1_[0];
  filter_coefficients[2] = b2_[0];
  filter_coefficients[3] = a1_[0];
  filter_coefficients[4] = a2_[0];

  double* input_p = input_buffer_.Data();
  double* output_p = output_buffer_.Data();

  double* input2p = input_p + 2;
  double* output2p = output_p + 2;

  // Break up processing into smaller slices (kBiquadBufferSize) if necessary.

  int n = frames_to_process;

  while (n > 0) {
    int frames_this_time = n < kBiquadBufferSize ? n : kBiquadBufferSize;

    // Copy input to input buffer
    for (int i = 0; i < frames_this_time; ++i)
      input2p[i] = *source_p++;

    ProcessSliceFast(input_p, output_p, filter_coefficients, frames_this_time);

    // Copy output buffer to output (converts float -> double).
    for (int i = 0; i < frames_this_time; ++i)
      *dest_p++ = static_cast<float>(output2p[i]);

    n -= frames_this_time;
  }
}

void Biquad::ProcessSliceFast(double* source_p,
                              double* dest_p,
                              double* coefficients_p,
                              uint32_t frames_to_process) {
  // Use double-precision for filter stability
  vDSP_deq22D(source_p, 1, coefficients_p, dest_p, 1, frames_to_process);

  // Save history.  Note that sourceP and destP reference m_inputBuffer and
  // m_outputBuffer respectively.  These buffers are allocated (in the
  // constructor) with space for two extra samples so it's OK to access array
  // values two beyond framesToProcess.
  source_p[0] = source_p[frames_to_process - 2 + 2];
  source_p[1] = source_p[frames_to_process - 1 + 2];
  dest_p[0] = dest_p[frames_to_process - 2 + 2];
  dest_p[1] = dest_p[frames_to_process - 1 + 2];
}

#endif  // BUILDFLAG(IS_MAC)

void Biquad::Reset() {
#if BUILDFLAG(IS_MAC)
  // Two extra samples for filter history
  double* input_p = input_buffer_.Data();
  input_p[0] = 0;
  input_p[1] = 0;

  double* output_p = output_buffer_.Data();
  output_p[0] = 0;
  output_p[1] = 0;

#endif
  x1_ = x2_ = y1_ = y2_ = 0;
}

void Biquad::SetLowpassParams(int index, double cutoff, double resonance) {
  // Limit cutoff to 0 to 1.
  cutoff = ClampTo(cutoff, 0.0, 1.0);

  if (cutoff == 1) {
    // When cutoff is 1, the z-transform is 1.
    SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
  } else if (cutoff > 0) {
    // Compute biquad coefficients for lowpass filter

    resonance = pow10(resonance / 20);

    double theta = kPiDouble * cutoff;
    double alpha = fdlibm::sin(theta) / (2 * resonance);
    double cosw = fdlibm::cos(theta);
    double beta = (1 - cosw) / 2;

    double b0 = beta;
    double b1 = 2 * beta;
    double b2 = beta;

    double a0 = 1 + alpha;
    double a1 = -2 * cosw;
    double a2 = 1 - alpha;

    SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
  } else {
    // When cutoff is zero, nothing gets through the filter, so set
    // coefficients up correctly.
    SetNormalizedCoefficients(index, 0, 0, 0, 1, 0, 0);
  }
}

void Biquad::SetHighpassParams(int index, double cutoff, double resonance) {
  // Limit cutoff to 0 to 1.
  cutoff = ClampTo(cutoff, 0.0, 1.0);

  if (cutoff == 1) {
    // The z-transform is 0.
    SetNormalizedCoefficients(index, 0, 0, 0, 1, 0, 0);
  } else if (cutoff > 0) {
    // Compute biquad coefficients for highpass filter

    resonance = pow10(resonance / 20);
    double theta = kPiDouble * cutoff;
    double alpha = fdlibm::sin(theta) / (2 * resonance);
    double cosw = fdlibm::cos(theta);
    double beta = (1 + cosw) / 2;

    double b0 = beta;
    double b1 = -2 * beta;
    double b2 = beta;

    double a0 = 1 + alpha;
    double a1 = -2 * cosw;
    double a2 = 1 - alpha;

    SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
  } else {
    // When cutoff is zero, we need to be careful because the above
    // gives a quadratic divided by the same quadratic, with poles
    // and zeros on the unit circle in the same place. When cutoff
    // is zero, the z-transform is 1.
    SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
  }
}

void Biquad::SetNormalizedCoefficients(int index,
                                       double b0,
                                       double b1,
                                       double b2,
                                       double a0,
                                       double a1,
                                       double a2) {
  double a0_inverse = 1 / a0;

  b0_[index] = b0 * a0_inverse;
  b1_[index] = b1 * a0_inverse;
  b2_[index] = b2 * a0_inverse;
  a1_[index] = a1 * a0_inverse;
  a2_[index] = a2 * a0_inverse;
}

void Biquad::SetLowShelfParams(int index, double frequency, double db_gain) {
  // Clip frequencies to between 0 and 1, inclusive.
  frequency = ClampTo(frequency, 0.0, 1.0);

  double a = pow10(db_gain / 40);

  if (frequency == 1) {
    // The z-transform is a constant gain.
    SetNormalizedCoefficients(index, a * a, 0, 0, 1, 0, 0);
  } else if (frequency > 0) {
    double w0 = kPiDouble * frequency;
    double s = 1;  // filter slope (1 is max value)
    double alpha = 0.5 * fdlibm::sin(w0) * sqrt((a + 1 / a) * (1 / s - 1) + 2);
    double k = fdlibm::cos(w0);
    double k2 = 2 * sqrt(a) * alpha;
    double a_plus_one = a + 1;
    double a_minus_one = a - 1;

    double b0 = a * (a_plus_one - a_minus_one * k + k2);
    double b1 = 2 * a * (a_minus_one - a_plus_one * k);
    double b2 = a * (a_plus_one - a_minus_one * k - k2);
    double a0 = a_plus_one + a_minus_one * k + k2;
    double a1 = -2 * (a_minus_one + a_plus_one * k);
    double a2 = a_plus_one + a_minus_one * k - k2;

    SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
  } else {
    // When frequency is 0, the z-transform is 1.
    SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
  }
}

void Biquad::SetHighShelfParams(int index, double frequency, double db_gain) {
  // Clip frequencies to between 0 and 1, inclusive.
  frequency = ClampTo(frequency, 0.0, 1.0);

  double a = pow10(db_gain / 40);

  if (frequency == 1) {
    // The z-transform is 1.
    SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
  } else if (frequency > 0) {
    double w0 = kPiDouble * frequency;
    double s = 1;  // filter slope (1 is max value)
    double alpha = 0.5 * fdlibm::sin(w0) * sqrt((a + 1 / a) * (1 / s - 1) + 2);
    double k = fdlibm::cos(w0);
    double k2 = 2 * sqrt(a) * alpha;
    double a_plus_one = a + 1;
    double a_minus_one = a - 1;

    double b0 = a * (a_plus_one + a_minus_one * k + k2);
    double b1 = -2 * a * (a_minus_one + a_plus_one * k);
    double b2 = a * (a_plus_one + a_minus_one * k - k2);
    double a0 = a_plus_one - a_minus_one * k + k2;
    double a1 = 2 * (a_minus_one - a_plus_one * k);
    double a2 = a_plus_one - a_minus_one * k - k2;

    SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
  } else {
    // When frequency = 0, the filter is just a gain, A^2.
    SetNormalizedCoefficients(index, a * a, 0, 0, 1, 0, 0);
  }
}

void Biquad::SetPeakingParams(int index,
                              double frequency,
                              double q,
                              double db_gain) {
  // Clip frequencies to between 0 and 1, inclusive.
  frequency = ClampTo(frequency, 0.0, 1.0);

  // Don't let Q go negative, which causes an unstable filter.
  q = std::max(0.0, q);

  double a = pow10(db_gain / 40);

  if (frequency > 0 && frequency < 1) {
    if (q > 0) {
      double w0 = kPiDouble * frequency;
      double alpha = fdlibm::sin(w0) / (2 * q);
      double k = fdlibm::cos(w0);

      double b0 = 1 + alpha * a;
      double b1 = -2 * k;
      double b2 = 1 - alpha * a;
      double a0 = 1 + alpha / a;
      double a1 = -2 * k;
      double a2 = 1 - alpha / a;

      SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
    } else {
      // When Q = 0, the above formulas have problems. If we look at
      // the z-transform, we can see that the limit as Q->0 is A^2, so
      // set the filter that way.
      SetNormalizedCoefficients(index, a * a, 0, 0, 1, 0, 0);
    }
  } else {
    // When frequency is 0 or 1, the z-transform is 1.
    SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
  }
}

void Biquad::SetAllpassParams(int index, double frequency, double q) {
  // Clip frequencies to between 0 and 1, inclusive.
  frequency = ClampTo(frequency, 0.0, 1.0);

  // Don't let Q go negative, which causes an unstable filter.
  q = std::max(0.0, q);

  if (frequency > 0 && frequency < 1) {
    if (q > 0) {
      double w0 = kPiDouble * frequency;
      double alpha = fdlibm::sin(w0) / (2 * q);
      double k = fdlibm::cos(w0);

      double b0 = 1 - alpha;
      double b1 = -2 * k;
      double b2 = 1 + alpha;
      double a0 = 1 + alpha;
      double a1 = -2 * k;
      double a2 = 1 - alpha;

      SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
    } else {
      // When Q = 0, the above formulas have problems. If we look at
      // the z-transform, we can see that the limit as Q->0 is -1, so
      // set the filter that way.
      SetNormalizedCoefficients(index, -1, 0, 0, 1, 0, 0);
    }
  } else {
    // When frequency is 0 or 1, the z-transform is 1.
    SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
  }
}

void Biquad::SetNotchParams(int index, double frequency, double q) {
  // Clip frequencies to between 0 and 1, inclusive.
  frequency = ClampTo(frequency, 0.0, 1.0);

  // Don't let Q go negative, which causes an unstable filter.
  q = std::max(0.0, q);

  if (frequency > 0 && frequency < 1) {
    if (q > 0) {
      double w0 = kPiDouble * frequency;
      double alpha = fdlibm::sin(w0) / (2 * q);
      double k = fdlibm::cos(w0);

      double b0 = 1;
      double b1 = -2 * k;
      double b2 = 1;
      double a0 = 1 + alpha;
      double a1 = -2 * k;
      double a2 = 1 - alpha;

      SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
    } else {
      // When Q = 0, the above formulas have problems. If we look at
      // the z-transform, we can see that the limit as Q->0 is 0, so
      // set the filter that way.
      SetNormalizedCoefficients(index, 0, 0, 0, 1, 0, 0);
    }
  } else {
    // When frequency is 0 or 1, the z-transform is 1.
    SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
  }
}

void Biquad::SetBandpassParams(int index, double frequency, double q) {
  // No negative frequencies allowed.
  frequency = std::max(0.0, frequency);

  // Don't let Q go negative, which causes an unstable filter.
  q = std::max(0.0, q);

  if (frequency > 0 && frequency < 1) {
    double w0 = kPiDouble * frequency;
    if (q > 0) {
      double alpha = fdlibm::sin(w0) / (2 * q);
      double k = fdlibm::cos(w0);

      double b0 = alpha;
      double b1 = 0;
      double b2 = -alpha;
      double a0 = 1 + alpha;
      double a1 = -2 * k;
      double a2 = 1 - alpha;

      SetNormalizedCoefficients(index, b0, b1, b2, a0, a1, a2);
    } else {
      // When Q = 0, the above formulas have problems. If we look at
      // the z-transform, we can see that the limit as Q->0 is 1, so
      // set the filter that way.
      SetNormalizedCoefficients(index, 1, 0, 0, 1, 0, 0);
    }
  } else {
    // When the cutoff is zero, the z-transform approaches 0, if Q
    // > 0. When both Q and cutoff are zero, the z-transform is
    // pretty much undefined. What should we do in this case?
    // For now, just make the filter 0. When the cutoff is 1, the
    // z-transform also approaches 0.
    SetNormalizedCoefficients(index, 0, 0, 0, 1, 0, 0);
  }
}

void Biquad::GetFrequencyResponse(int n_frequencies,
                                  const float* frequency,
                                  float* mag_response,
                                  float* phase_response) {
  // Evaluate the Z-transform of the filter at given normalized
  // frequency from 0 to 1.  (1 corresponds to the Nyquist
  // frequency.)
  //
  // The z-transform of the filter is
  //
  // H(z) = (b0 + b1*z^(-1) + b2*z^(-2))/(1 + a1*z^(-1) + a2*z^(-2))
  //
  // Evaluate as
  //
  // b0 + (b1 + b2*z1)*z1
  // --------------------
  // 1 + (a1 + a2*z1)*z1
  //
  // with z1 = 1/z and z = exp(j*pi*frequency). Hence z1 = exp(-j*pi*frequency)

  // Make local copies of the coefficients as a micro-optimization.
  double b0 = b0_[0];
  double b1 = b1_[0];
  double b2 = b2_[0];
  double a1 = a1_[0];
  double a2 = a2_[0];

  for (int k = 0; k < n_frequencies; ++k) {
    if (frequency[k] < 0 || frequency[k] > 1) {
      // Out-of-bounds frequencies should return NaN.
      mag_response[k] = std::nanf("");
      phase_response[k] = std::nanf("");
    } else {
      double omega = -kPiDouble * frequency[k];
      std::complex<double> z =
          std::complex<double>(fdlibm::cos(omega), fdlibm::sin(omega));
      std::complex<double> numerator = b0 + (b1 + b2 * z) * z;
      std::complex<double> denominator =
          std::complex<double>(1, 0) + (a1 + a2 * z) * z;
      std::complex<double> response = numerator / denominator;
      mag_response[k] = static_cast<float>(abs(response));
      phase_response[k] =
          static_cast<float>(fdlibm::atan2(imag(response), real(response)));
    }
  }
}

static double RepeatedRootResponse(double n,
                                   double c1,
                                   double c2,
                                   double r,
                                   double log_eps) {
  // The response is h(n) = r^(n-2)*[c1*(n+1)*r^2+c2]. We're looking
  // for n such that |h(n)| = eps.  Equivalently, we want a root
  // of the equation log(|h(n)|) - log(eps) = 0 or
  //
  //   (n-2)*log(r) + log(|c1*(n+1)*r^2+c2|) - log(eps)
  //
  // This helps with finding a nuemrical solution because this
  // approximately linearizes the response for large n.

  return (n - 2) * fdlibm::log(r) +
         fdlibm::log(fabs(c1 * (n + 1) * r * r + c2)) - log_eps;
}

// Regula Falsi root finder, Illinois variant
// (https://en.wikipedia.org/wiki/False_position_method#The_Illinois_algorithm).
//
// This finds a root of the repeated root response where the root is
// assumed to lie between |low| and |high|.  The response is given by
// |c1|, |c2|, and |r| as determined by |RepeatedRootResponse|.
// |log_eps| is the log the the maximum allowed amplitude in the
// response.
static double RootFinder(double low,
                         double high,
                         double log_eps,
                         double c1,
                         double c2,
                         double r) {
  // Desired accuray of the root (in frames).  This doesn't need to be
  // super-accurate, so half frame is good enough, and should be less
  // than 1 because the algorithm may prematurely terminate.
  const double kAccuracyThreshold = 0.5;
  // Max number of iterations to do.  If we haven't converged by now,
  // just return whatever we've found.
  const int kMaxIterations = 10;

  int side = 0;
  double root = 0;
  double f_low = RepeatedRootResponse(low, c1, c2, r, log_eps);
  double f_high = RepeatedRootResponse(high, c1, c2, r, log_eps);

  // The function values must be finite and have opposite signs!
  DCHECK(std::isfinite(f_low));
  DCHECK(std::isfinite(f_high));
  DCHECK_LE(f_low * f_high, 0);

  int iteration;
  for (iteration = 0; iteration < kMaxIterations; ++iteration) {
    root = (f_low * high - f_high * low) / (f_low - f_high);
    if (fabs(high - low) < kAccuracyThreshold * fabs(high + low)) {
      break;
    }
    double fr = RepeatedRootResponse(root, c1, c2, r, log_eps);

    DCHECK(std::isfinite(fr));

    if (fr * f_high > 0) {
      // fr and f_high have same sign.  Copy root to f_high
      high = root;
      f_high = fr;
      side = -1;
    } else if (f_low * fr > 0) {
      // fr and f_low have same sign. Copy root to f_low
      low = root;
      f_low = fr;
      if (side == 1) {
        f_high /= 2;
      }
      side = 1;
    } else {
      // f_low * fr looks like zero, so assume we've converged.
      break;
    }
  }

  // Want to know if the max number of iterations is ever exceeded so
  // we can understand why that happened.
  DCHECK_LT(iteration, kMaxIterations);

  return root;
}

double Biquad::TailFrame(int coef_index, double max_frame) {
  // The Biquad filter is given by
  //
  //   H(z) = (b0 + b1/z + b2/z^2)/(1 + a1/z + a2/z^2).
  //
  // To compute the tail time, compute the impulse response, h(n), of
  // H(z), which we can do analytically.  From this impulse response,
  // find the value n0 where |h(n)| <= eps for n >= n0.
  //
  // Assume first that the two poles of H(z) are not repeated, say r1
  // and r2.  Then, we can compute a partial fraction expansion of
  // H(z):
  //
  //   H(z) = (b0+b1/z+b2/z^2)/[(1-r1/z)*(1-r2/z)]
  //        = b0 + C2/(z-r2) - C1/(z-r1)
  //
  //  where
  //    C2 = (b0*r2^2+b1*r2+b2)/(r2-r1)
  //    C1 = (b0*r1^2+b1*r1+b2)/(r2-r1)
  //
  // Expand H(z) then this in powers of 1/z gives:
  //
  //   H(z) = b0 -(C2/r2+C1/r1) + sum(C2*r2^(i-1)/z^i + C1*r1^(i-1)/z^i)
  //
  // Thus, for n > 1 (we don't care about small n),
  //
  //   h(n) = C2*r2^(n-1) + C1*r1^(n-1)
  //
  // We need to find n0 such that |h(n)| < eps for n > n0.
  //
  // Case 1: r1 and r2 are real and distinct, with |r1|>=|r2|.
  //
  // Then
  //
  //   h(n) = C1*r1^(n-1)*(1 + C2/C1*(r2/r1)^(n-1))
  //
  // so
  //
  //   |h(n)| = |C1|*|r1|^(n-1)*|1+C2/C1*(r2/r1)^(n-1)|
  //          <= |C1|*|r1|^(n-1)*[1 + |C2/C1|*|r2/r1|^(n-1)]
  //          <= |C1|*|r1|^(n-1)*[1 + |C2/C1|]
  //
  // by using the triangle inequality and the fact that |r2|<=|r1|.
  // And we want |h(n)|<=eps which is true if
  //
  //   |C1|*|r1|^(n-1)*[1 + |C2/C1|] <= eps
  //
  // or
  //
  //   n >= 1 + log(eps/C)/log(|r1|)
  //
  // where C = |C1|*[1+|C2/C1|] = |C1| + |C2|.
  //
  // Case 2: r1 and r2 are complex
  //
  // Thne we can write r1=r*exp(i*p) and r2=r*exp(-i*p).  So,
  //
  //   |h(n)| = |C2*r^(n-1)*exp(-i*p*(n-1)) + C1*r^(n-1)*exp(i*p*(n-1))|
  //          = |C1|*r^(n-1)*|1 + C2/C1*exp(-i*p*(n-1))/exp(i*n*(n-1))|
  //          <= |C1|*r^(n-1)*[1 + |C2/C1|]
  //
  // Again, this is easily solved to give
  //
  //   n >= 1 + log(eps/C)/log(r)
  //
  // where C = |C1|*[1+|C2/C1|] = |C1| + |C2|.
  //
  // Case 3: Repeated roots, r1=r2=r.
  //
  // In this case,
  //
  //   H(z) = (b0+b1/z+b2/z^2)/[(1-r/z)^2
  //
  // Expanding this in powers of 1/z gives:
  //
  //   H(z) = C1*sum((i+1)*r^i/z^i) - C2 * sum(r^(i-2)/z^i) + b2/r^2
  //        = b2/r^2 + sum([C1*(i+1)*r^i + C2*r^(i-2)]/z^i)
  // where
  //   C1 = (b0*r^2+b1*r+b2)/r^2
  //   C2 = b1*r+2*b2
  //
  // Thus, the impulse response is
  //
  //   h(n) = C1*(n+1)*r^n + C2*r^(n-2)
  //        = r^(n-2)*[C1*(n+1)*r^2+C2]
  //
  // So
  //
  //   |h(n)| = |r|^(n-2)*|C1*(n+1)*r^2+C2|
  //
  // To find n such that |h(n)| < eps, we need a numerical method in
  // general, so there's no real reason to simplify this or use other
  // approximations.  Just solve |h(n)|=eps directly.
  //
  // Thus, for an set of filter coefficients, we can compute the tail
  // time.
  //

  // If the maximum amplitude of the impulse response is less than
  // this, we assume that we've reached the tail of the response.
  // Currently, this means that the impulse is less than 1 bit of a
  // 16-bit PCM value.
  const double kMaxTailAmplitude = 1 / 32768.0;

  // Find the roots of 1+a1/z+a2/z^2 = 0.  Or equivalently,
  // z^2+a1*z+a2 = 0.  From the quadratic formula the roots are
  // (-a1+/-sqrt(a1^2-4*a2))/2.

  double a1 = a1_[coef_index];
  double a2 = a2_[coef_index];
  double b0 = b0_[coef_index];
  double b1 = b1_[coef_index];
  double b2 = b2_[coef_index];

  double tail_frame = 0;
  double discrim = a1 * a1 - 4 * a2;

  if (discrim > 0) {
    // Compute the real roots so that r1 has the largest magnitude.
    double rplus = (-a1 + sqrt(discrim)) / 2;
    double rminus = (-a1 - sqrt(discrim)) / 2;
    double r1 = fabs(rplus) >= fabs(rminus) ? rplus : rminus;
    // Use the fact that a2 = r1*r2
    double r2 = a2 / r1;

    double c1 = (b0 * r1 * r1 + b1 * r1 + b2) / (r2 - r1);
    double c2 = (b0 * r2 * r2 + b1 * r2 + b2) / (r2 - r1);

    DCHECK(std::isfinite(r1));
    DCHECK(std::isfinite(r2));
    DCHECK(std::isfinite(c1));
    DCHECK(std::isfinite(c2));

    // It's possible for kMaxTailAmplitude to be greater than c1 + c2.
    // This may produce a negative tail frame.  Just clamp the tail
    // frame to 0.
    tail_frame =
        ClampTo(1 + fdlibm::log(kMaxTailAmplitude / (fabs(c1) + fabs(c2))) /
                        fdlibm::log(fabs(r1)),
                0);

    DCHECK(std::isfinite(tail_frame));
  } else if (discrim < 0) {
    // Two complex roots.
    // One root is -a1/2 + i*sqrt(-discrim)/2.
    double x = -a1 / 2;
    double y = sqrt(-discrim) / 2;
    std::complex<double> r1(x, y);
    std::complex<double> r2(x, -y);
    double r = hypot(x, y);

    DCHECK(std::isfinite(r));

    // It's possible for r to be 1. (LPF with Q very large can cause this.)
    if (r == 1) {
      tail_frame = max_frame;
    } else {
      double c1 = abs((b0 * r1 * r1 + b1 * r1 + b2) / (r2 - r1));
      double c2 = abs((b0 * r2 * r2 + b1 * r2 + b2) / (r2 - r1));

      DCHECK(std::isfinite(c1));
      DCHECK(std::isfinite(c2));

      tail_frame =
          1 + fdlibm::log(kMaxTailAmplitude / (c1 + c2)) / fdlibm::log(r);
      if (c1 == 0 && c2 == 0) {
        // If c1 = c2 = 0, then H(z) = b0.  Hence, there's no tail
        // because this is just a wire from input to output.
        tail_frame = 0;
      } else {
        // Otherwise, check that the tail has finite length.  Not
        // strictly necessary, but we want to know if this ever
        // happens.
        DCHECK(std::isfinite(tail_frame));
      }
    }
  } else {
    // Repeated roots.  This should be pretty rare because all the
    // coefficients need to be just the right values to get a
    // discriminant of exactly zero.
    double r = -a1 / 2;

    if (r == 0) {
      // Double pole at 0.  This just delays the signal by 2 frames,
      // so set the tail frame to 2.
      tail_frame = 2;
    } else if (std::abs(r) >= 1) {
      // Double pole at 1 or -1 (or outside the unit circle in general).  In any
      // case, the impulse response grows without bound since the pole is on or
      // outside the unit circle.  Return infinity and let the caller clamp it
      // to something more reasonable.
      tail_frame = std::numeric_limits<double>::infinity();
    } else {
      double c1 = (b0 * r * r + b1 * r + b2) / (r * r);
      double c2 = b1 * r + 2 * b2;

      DCHECK(std::isfinite(c1));
      DCHECK(std::isfinite(c2));

      // It can happen that c1=c2=0.  This basically means that H(z) =
      // constant, which is the limiting case for several of the
      // biquad filters.
      if (c1 == 0 && c2 == 0) {
        tail_frame = 0;
      } else {
        // The function c*(n+1)*r^n is not monotonic, but it's easy to
        // find the max point since the derivative is
        // c*r^n*(1+(n+1)*log(r)).  This has a root at
        // -(1+log(r))/log(r). so we can start our search from that
        // point to max_frames.

        double low = ClampTo(-(1 + fdlibm::log(r)) / fdlibm::log(r), 1.0,
                             static_cast<double>(max_frame - 1));
        double high = max_frame;

        DCHECK(std::isfinite(low));
        DCHECK(std::isfinite(high));

        tail_frame =
            RootFinder(low, high, fdlibm::log(kMaxTailAmplitude), c1, c2, r);
      }
    }
  }

  return tail_frame;
}

}  // namespace blink

"""

```