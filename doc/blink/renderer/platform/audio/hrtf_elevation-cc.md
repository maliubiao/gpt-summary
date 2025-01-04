Response:
Let's break down the thought process for analyzing this C++ source code and fulfilling the request.

1. **Understand the Core Purpose:** The first thing is to read the initial comments and includes to get a high-level understanding. The file name `hrtf_elevation.cc` and the inclusion of files like `hrtf_database.h` and `hrtf_panner.h` strongly suggest this code deals with Head-Related Transfer Functions (HRTFs) and their application in spatial audio, specifically handling elevation. The copyright mentions Google and a historical connection to Apple.

2. **Identify Key Data Structures and Constants:** Scan the file for important data structures (like `HRTFKernelList`) and constants (starting with `k`). These constants often define the parameters of the HRTF data and the processing involved. Notice constants like `kAzimuthSpacing`, `kNumberOfRawAzimuths`, `kInterpolationFactor`, `kNumberOfTotalAzimuths`, `kResponseFrameSize`, and `kElevationIndexTable`. These give clues about how the HRTF data is organized and manipulated.

3. **Analyze Key Functions:** Focus on the main functions and their roles:
    * `CalculateKernelsForAzimuthElevation`: This function seems central to loading and processing HRTF data for a specific azimuth and elevation. The presence of `AudioBus::GetDataResource` and sample rate conversion suggests it handles retrieving the HRTF impulse responses.
    * `CreateForSubject`:  This function likely creates an `HRTFElevation` object for a given listener (subject) and elevation. It iterates through azimuths, calling `CalculateKernelsForAzimuthElevation`, and then performs interpolation.
    * `CreateByInterpolatingSlices`: This suggests the ability to interpolate between different elevations.
    * `GetKernelsFromAzimuth`: This function appears to retrieve the relevant HRTF kernels for a given azimuth, handling interpolation between adjacent azimuths.

4. **Trace the Data Flow:**  Follow how data is loaded and transformed. The `GetConcatenatedImpulseResponsesForSubject` function loads the raw HRTF data. `CalculateKernelsForAzimuthElevation` extracts a specific impulse response. The `HRTFKernel` class likely stores the processed HRTF data (possibly in the frequency domain after an FFT, given the reference to `fft_size`). Interpolation is a key operation happening at both azimuth and elevation levels.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Now, consider how this C++ code in the Blink rendering engine might connect to web technologies. Think about the Web Audio API:
    * **JavaScript:**  The Web Audio API exposes interfaces for spatialization. The C++ code here *implements* the low-level audio processing that the JavaScript API controls. Specifically, the `PannerNode` in the Web Audio API utilizes HRTFs for spatial positioning.
    * **HTML:**  HTML `<audio>` or `<video>` elements provide the media source. The audio from these elements is what gets processed by the Web Audio API and, eventually, this HRTF code.
    * **CSS:**  CSS is less directly related to the *functionality* of audio processing. However, CSS could potentially control visual aspects of a web page that *relate* to the audio experience, like visualizers or interactive elements representing sound sources.

6. **Identify Potential User/Programming Errors:** Think about common mistakes developers or users might make when interacting with spatial audio:
    * **Incorrect Parameter Values:**  Providing invalid azimuth or elevation values to the Web Audio API (which would then be passed down to this C++ code).
    * **Mismatched Data:**  Using HRTF data that doesn't align with the expected format or sample rate.
    * **Performance Issues:**  Using too many spatialized audio sources can be computationally expensive.
    * **Misunderstanding Interpolation:** Incorrectly assuming the interpolation works in a certain way.

7. **Construct Hypothetical Inputs and Outputs:** For functions like `CalculateKernelsForAzimuthElevation`, imagine passing in specific azimuth, elevation, and sample rate values. Think about what the output would be: two `HRTFKernel` objects representing the left and right ear filters.

8. **Structure the Answer:** Organize the findings into logical sections based on the prompt's requirements:
    * Functionality description.
    * Relationship to JavaScript, HTML, and CSS with examples.
    * Logical reasoning with hypothetical inputs and outputs.
    * Common user/programming errors.

9. **Refine and Elaborate:**  Review the generated answer. Ensure the explanations are clear, concise, and technically accurate. Add details where necessary to make the explanation more complete. For example, when discussing interpolation, mention *why* it's done (to create smoother transitions).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This seems like basic audio processing."  **Correction:** Recognize the specific domain of HRTFs and spatial audio, which involves psychoacoustics and specialized filtering.
* **Initial thought:** "CSS has nothing to do with this." **Correction:**  Consider indirect relationships, such as visual elements that enhance the audio experience.
* **During input/output examples:** Initially, might focus only on the immediate inputs and outputs of a single function. **Refinement:** Consider the broader context – how the output of one function becomes the input of another.
* **When explaining errors:** Might initially think only of coding errors. **Refinement:** Include user errors in understanding the concepts or limitations.

By following this systematic approach, combining code analysis with knowledge of web technologies and potential usage scenarios, a comprehensive and accurate answer can be constructed.
好的，让我们来分析一下 `blink/renderer/platform/audio/hrtf_elevation.cc` 这个文件。

**文件功能概述**

`hrtf_elevation.cc` 文件的主要功能是**管理和处理特定仰角（elevation）的头部相关传输函数（HRTF）数据**，用于在 Web Audio API 中实现 3D 空间音频的定位效果。更具体地说，它负责：

1. **加载 HRTF 数据：** 从预先编译的资源文件中加载针对特定“subject”（可以理解为不同人头模型的 HRTF 数据）的 HRTF 脉冲响应。
2. **组织和索引 HRTF 数据：**  将加载的脉冲响应数据按照方位角（azimuth）进行组织，并存储在一个列表中，方便后续根据方位角快速访问。
3. **插值 HRTF 数据：**
   - **方位角插值：**  对相邻方位角的 HRTF 数据进行插值，以生成更精细的方位角之间的 HRTF，从而提供更平滑的声像移动效果。
   - **仰角插值：**  能够在两个不同仰角的 `HRTFElevation` 对象之间进行插值，从而创建出中间仰角的 HRTF 数据。
4. **提供 HRTF 内核：**  为音频处理模块提供特定方位角的左耳和右耳 HRTF 内核（`HRTFKernel`），这些内核实际上是用于卷积音频信号的滤波器。
5. **管理延迟信息：**  存储和提供与 HRTF 内核相关的延迟信息，这些延迟对于模拟声音到达双耳的时间差 (ITD) 至关重要。

**与 JavaScript, HTML, CSS 的关系**

`hrtf_elevation.cc` 文件是 Chromium 渲染引擎 Blink 的一部分，它直接参与 Web Audio API 的实现。

* **JavaScript:**  开发者通过 Web Audio API 的 `PannerNode` 接口来控制音频源在 3D 空间中的位置。`PannerNode` 内部会使用 HRTF 数据来实现声音的方位和仰角定位。`hrtf_elevation.cc` 提供的功能正是 `PannerNode` 实现 HRTF 空间化效果的关键底层支撑。

   **举例说明:**

   ```javascript
   const audioCtx = new AudioContext();
   const oscillator = audioCtx.createOscillator();
   const panner = audioCtx.createPanner();

   // 设置 PannerNode 的定位参数
   panner.setPosition(1, 0, 0); // 设置到右侧
   panner.orientationY.value = 1; // 设置向上方向

   oscillator.connect(panner).connect(audioCtx.destination);
   oscillator.start();
   ```

   当 JavaScript 代码设置 `panner.setPosition()` 时，Blink 引擎内部会根据这个位置信息（包括方位角和仰角），使用 `hrtf_elevation.cc` 中的逻辑来选择合适的 HRTF 内核，并将其应用于音频信号，从而产生空间化的听觉效果。虽然 JavaScript 代码没有直接调用 `hrtf_elevation.cc` 中的函数，但它是通过 Web Audio API 间接使用的。

* **HTML:** HTML 的 `<audio>` 或 `<video>` 元素提供了音频或视频的来源。Web Audio API 可以获取这些元素的音频流，并对其进行处理，包括使用 HRTF 进行空间化。

   **举例说明:**

   ```html
   <audio id="myAudio" src="sound.mp3"></audio>
   <script>
     const audioCtx = new AudioContext();
     const audioElement = document.getElementById('myAudio');
     const source = audioCtx.createMediaElementSource(audioElement);
     const panner = audioCtx.createPanner();

     panner.setPosition(0, 1, 0); // 设置到上方

     source.connect(panner).connect(audioCtx.destination);
     audioElement.play();
   </script>
   ```

   在这个例子中，来自 `sound.mp3` 的音频流被送入 `PannerNode` 进行空间处理，`hrtf_elevation.cc` 的功能确保了声音能够被正确地定位到上方。

* **CSS:** CSS 本身与音频处理没有直接的功能关系。但是，CSS 可以用于创建与音频体验相关的视觉元素，例如显示声源位置的动画、均衡器效果的可视化等。这些视觉元素可以增强用户对空间音频效果的感知，但 CSS 并不直接参与 HRTF 的计算或应用。

**逻辑推理与假设输入输出**

假设我们调用 `HRTFElevation::CalculateKernelsForAzimuthElevation` 函数：

**假设输入:**

* `azimuth`: 30 (度)
* `elevation`: 15 (度)
* `sample_rate`: 48000 (Hz)
* `subject_resource_id`: 一个表示特定人头 HRTF 数据的 ID，例如 1 (假设存在 ID 为 1 的 HRTF 数据)

**逻辑推理:**

1. 函数会首先验证输入的方位角和仰角是否在有效范围内，并是否为 15 度的倍数。
2. 它会调用 `GetConcatenatedImpulseResponsesForSubject(1)` 来获取与 `subject_resource_id` 对应的完整的 HRTF 脉冲响应数据（包含所有方位角和仰角的响应）。
3. 根据输入的 `azimuth` (30 度) 和 `elevation` (15 度)，以及预定义的 `kAzimuthSpacing` 和 `kElevationIndexTable`，计算出在连接的脉冲响应数据中，对应这个特定方位角和仰角的左右耳脉冲响应的起始和结束帧。
4. 使用 `AudioBus::CreateBufferFromRange` 从连接的脉冲响应数据中提取出所需的左右耳脉冲响应。
5. 如果 `sample_rate` 与 HRTF 数据的原始采样率 (`kResponseSampleRate`，默认为 44100 Hz) 不同，则会使用 `AudioBus::CreateBySampleRateConverting` 进行重采样。
6. 根据 `HRTFPanner::FftSizeForSampleRate(sample_rate)` 获取当前采样率下推荐的 FFT 大小。
7. 如果提取出的脉冲响应长度小于 FFT 大小的一半，则会进行零填充。
8. 创建 `HRTFKernel` 对象，将左右耳的脉冲响应数据和 FFT 大小传递给它们。

**假设输出:**

* `kernel_l`: 一个指向 `HRTFKernel` 对象的智能指针，该对象包含了方位角 30 度、仰角 15 度的左耳 HRTF 内核数据（可能是频域表示）。
* `kernel_r`: 一个指向 `HRTFKernel` 对象的智能指针，该对象包含了方位角 30 度、仰角 15 度的右耳 HRTF 内核数据。
* 函数返回 `true`，表示成功计算出内核。

**用户或编程常见的使用错误**

1. **传入无效的方位角或仰角值:**
   - **错误示例:**  JavaScript 代码中设置 `panner.setPosition(1, 1, 0)`，导致内部计算出的仰角值超出 [-45, 90] 的范围。
   - **后果:**  `CalculateKernelsForAzimuthElevation` 函数中的断言 (DCHECK) 会触发，程序可能会崩溃（在开发模式下）。在生产环境中，可能会使用默认值或者导致未定义的行为。

2. **使用未加载或错误的 HRTF 数据资源 ID:**
   - **错误示例:** `HRTFElevation::CreateForSubject` 函数中传入了不存在的 `subject_resource_id`。
   - **后果:** `GetConcatenatedImpulseResponsesForSubject` 函数返回 `nullptr`，导致 `CalculateKernelsForAzimuthElevation` 返回 `false`，最终可能导致空间化效果失效或者程序错误。

3. **假设 HRTF 数据覆盖所有可能的方位角和仰角，而实际并非如此:**
   - **错误示例:**  开发者期望能够精细地控制声源的仰角，但实际加载的 HRTF 数据只包含有限的仰角采样点 (如 -45, 0, 45, 90)。
   - **后果:**  当请求的仰角不在采样点上时，系统会进行插值，但如果采样点过于稀疏，插值结果可能不够准确，导致空间感不佳。

4. **没有考虑到 HRTF 数据的“subject”差异:**
   - **错误示例:**  使用为成人设计的 HRTF 数据来模拟儿童的听觉体验。
   - **后果:**  由于不同人头部的形状和大小差异，HRTF 数据也会有所不同。使用不匹配的 HRTF 数据会导致空间听觉体验不真实。

5. **在多线程环境下不正确地访问共享的 HRTF 数据:**
   - 虽然代码中使用了 `DEFINE_THREAD_SAFE_STATIC_LOCAL` 和 `base::Lock` 来保护 HRTF 数据的加载，但在其他地方如果直接访问这些数据而没有适当的同步机制，可能会导致数据竞争。

总而言之，`hrtf_elevation.cc` 是 Web Audio API 实现 3D 空间音频的关键组成部分，它负责管理和处理 HRTF 数据，并通过插值等技术提供平滑的空间定位效果。开发者在使用 Web Audio API 的 `PannerNode` 时，虽然不会直接操作这个文件，但其功能直接影响了最终的声音空间化效果。理解其内部机制有助于更好地利用 Web Audio API 实现沉浸式的音频体验。

Prompt: 
```
这是目录为blink/renderer/platform/audio/hrtf_elevation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/audio/hrtf_elevation.h"

#include <math.h>
#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/synchronization/lock.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/audio/hrtf_database.h"
#include "third_party/blink/renderer/platform/audio/hrtf_panner.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"

namespace blink {

namespace {
// Spacing, in degrees, between every azimuth loaded from resource.
constexpr unsigned kAzimuthSpacing = 15;

// Number of azimuths loaded from resource.
constexpr unsigned kNumberOfRawAzimuths = 360 / kAzimuthSpacing;

// Interpolates by this factor to get the total number of azimuths from every
// azimuth loaded from resource.
constexpr unsigned kInterpolationFactor = 8;

// Total number of azimuths after interpolation.
constexpr unsigned kNumberOfTotalAzimuths =
    kNumberOfRawAzimuths * kInterpolationFactor;

// Total number of components of an HRTF database.
constexpr size_t kTotalNumberOfResponses = 240;

// Number of frames in an individual impulse response.
constexpr size_t kResponseFrameSize = 256;

// Sample-rate of the spatialization impulse responses as stored in the resource
// file.  The impulse responses may be resampled to a different sample-rate
// (depending on the audio hardware) when they are loaded.
constexpr float kResponseSampleRate = 44100;

// This table maps the index into the elevation table with the corresponding
// angle. See https://bugs.webkit.org/show_bug.cgi?id=98294#c9 for the
// elevation angles and their order in the concatenated response.
constexpr int kElevationIndexTableSize = 10;
constexpr int kElevationIndexTable[kElevationIndexTableSize] = {
    0, 15, 30, 45, 60, 75, 90, 315, 330, 345};

// The range of elevations for the IRCAM impulse responses varies depending on
// azimuth, but the minimum elevation appears to always be -45.
//
// Here's how it goes:
constexpr int kMaxElevations[] = {
    //  Azimuth
    //
    90,  // 0
    45,  // 15
    60,  // 30
    45,  // 45
    75,  // 60
    45,  // 75
    60,  // 90
    45,  // 105
    75,  // 120
    45,  // 135
    60,  // 150
    45,  // 165
    75,  // 180
    45,  // 195
    60,  // 210
    45,  // 225
    75,  // 240
    45,  // 255
    60,  // 270
    45,  // 285
    75,  // 300
    45,  // 315
    60,  // 330
    45   // 345
};

// Lazily load a concatenated HRTF database for given subject and store it in a
// local hash table to ensure quick efficient future retrievals.
scoped_refptr<AudioBus> GetConcatenatedImpulseResponsesForSubject(
    int subject_resource_id) {
  typedef HashMap<int, scoped_refptr<AudioBus>> AudioBusMap;
  DEFINE_THREAD_SAFE_STATIC_LOCAL(AudioBusMap, audio_bus_map, ());
  DEFINE_THREAD_SAFE_STATIC_LOCAL(base::Lock, lock, ());

  base::AutoLock locker(lock);
  scoped_refptr<AudioBus> bus;
  AudioBusMap::iterator iterator = audio_bus_map.find(subject_resource_id);
  if (iterator == audio_bus_map.end()) {
    scoped_refptr<AudioBus> concatenated_impulse_responses(
        AudioBus::GetDataResource(subject_resource_id, kResponseSampleRate));
    DCHECK(concatenated_impulse_responses);

    bus = concatenated_impulse_responses;
    audio_bus_map.Set(subject_resource_id, bus);
  } else {
    bus = iterator->value;
  }

  size_t response_length = bus->length();
  size_t expected_length =
      static_cast<size_t>(kTotalNumberOfResponses * kResponseFrameSize);

  // Check number of channels and length. For now these are fixed and known.
  DCHECK_EQ(response_length, expected_length);
  DCHECK_EQ(bus->NumberOfChannels(), 2u);

  return bus;
}

}  // namespace

bool HRTFElevation::CalculateKernelsForAzimuthElevation(
    int azimuth,
    int elevation,
    float sample_rate,
    int subject_resource_id,
    std::unique_ptr<HRTFKernel>& kernel_l,
    std::unique_ptr<HRTFKernel>& kernel_r) {
  // Valid values for azimuth are 0 -> 345 in 15 degree increments.
  // Valid values for elevation are -45 -> +90 in 15 degree increments.

  DCHECK_GE(azimuth, 0);
  DCHECK_LE(azimuth, 345);
  DCHECK_EQ((azimuth / 15) * 15, azimuth);

  DCHECK_GE(elevation, -45);
  DCHECK_LE(elevation, 90);
  DCHECK_EQ((elevation / 15) * 15, elevation);

  const int positive_elevation = elevation < 0 ? elevation + 360 : elevation;

  scoped_refptr<AudioBus> bus(
      GetConcatenatedImpulseResponsesForSubject(subject_resource_id));

  if (!bus) {
    return false;
  }

  // Just sequentially search the table to find the correct index.
  int elevation_index = -1;

  for (int k = 0; k < kElevationIndexTableSize; ++k) {
    if (kElevationIndexTable[k] == positive_elevation) {
      elevation_index = k;
      break;
    }
  }

  DCHECK_GE(elevation_index, 0);
  DCHECK_LT(elevation_index, kElevationIndexTableSize);

  // The concatenated impulse response is a bus containing all
  // the elevations per azimuth, for all azimuths by increasing
  // order. So for a given azimuth and elevation we need to compute
  // the index of the wanted audio frames in the concatenated table.
  unsigned index =
      ((azimuth / kAzimuthSpacing) * HRTFDatabase::NumberOfRawElevations()) +
      elevation_index;
  DCHECK_LE(index, kTotalNumberOfResponses);

  // Extract the individual impulse response from the concatenated
  // responses and potentially sample-rate convert it to the desired
  // (hardware) sample-rate.
  unsigned start_frame = index * kResponseFrameSize;
  unsigned stop_frame = start_frame + kResponseFrameSize;
  scoped_refptr<AudioBus> pre_sample_rate_converted_response(
      AudioBus::CreateBufferFromRange(bus.get(), start_frame, stop_frame));
  scoped_refptr<AudioBus> response(AudioBus::CreateBySampleRateConverting(
      pre_sample_rate_converted_response.get(), false, sample_rate));

  // Note that depending on the fftSize returned by the panner, we may be
  // truncating the impulse response we just loaded in, or we might zero-pad it.
  const unsigned fft_size = HRTFPanner::FftSizeForSampleRate(sample_rate);

  if (2 * response->length() < fft_size) {
    // Need to resize the response buffer length so that it fis the fft size.
    // Create a new response of the right length and copy over the current
    // response.
    scoped_refptr<AudioBus> padded_response(
        AudioBus::Create(response->NumberOfChannels(), fft_size / 2));
    for (unsigned channel = 0; channel < response->NumberOfChannels();
         ++channel) {
      memcpy(padded_response->Channel(channel)->MutableData(),
             response->Channel(channel)->Data(),
             response->length() * sizeof(float));
    }
    response = padded_response;
  }
  DCHECK_GE(2 * response->length(), fft_size);

  AudioChannel* left_ear_impulse_response =
      response->Channel(AudioBus::kChannelLeft);
  AudioChannel* right_ear_impulse_response =
      response->Channel(AudioBus::kChannelRight);

  kernel_l = std::make_unique<HRTFKernel>(left_ear_impulse_response, fft_size,
                                          sample_rate);
  kernel_r = std::make_unique<HRTFKernel>(right_ear_impulse_response, fft_size,
                                          sample_rate);

  return true;
}

std::unique_ptr<HRTFElevation> HRTFElevation::CreateForSubject(
    int subject_resource_id,
    int elevation,
    float sample_rate) {
  DCHECK_GE(elevation, -45);
  DCHECK_LE(elevation, 90);
  DCHECK_EQ((elevation / 15) * 15, elevation);

  std::unique_ptr<HRTFKernelList> kernel_list_l =
      std::make_unique<HRTFKernelList>(kNumberOfTotalAzimuths);
  std::unique_ptr<HRTFKernelList> kernel_list_r =
      std::make_unique<HRTFKernelList>(kNumberOfTotalAzimuths);

  // Load convolution kernels from HRTF files.
  int interpolated_index = 0;
  for (unsigned raw_index = 0; raw_index < kNumberOfRawAzimuths; ++raw_index) {
    // Don't let elevation exceed maximum for this azimuth.
    const int max_elevation = kMaxElevations[raw_index];
    const int actual_elevation = std::min(elevation, max_elevation);

    const bool success = CalculateKernelsForAzimuthElevation(
        raw_index * kAzimuthSpacing, actual_elevation, sample_rate,
        subject_resource_id, kernel_list_l->at(interpolated_index),
        kernel_list_r->at(interpolated_index));
    if (!success) {
      return nullptr;
    }

    interpolated_index += kInterpolationFactor;
  }

  // Now go back and interpolate intermediate azimuth values.
  for (unsigned i = 0; i < kNumberOfTotalAzimuths; i += kInterpolationFactor) {
    int j = (i + kInterpolationFactor) % kNumberOfTotalAzimuths;

    // Create the interpolated convolution kernels and delays.
    for (unsigned jj = 1; jj < kInterpolationFactor; ++jj) {
      float x =
          static_cast<float>(jj) /
          static_cast<float>(kInterpolationFactor);  // interpolate from 0 -> 1

      (*kernel_list_l)[i + jj] = HRTFKernel::CreateInterpolatedKernel(
          kernel_list_l->at(i).get(), kernel_list_l->at(j).get(), x);
      (*kernel_list_r)[i + jj] = HRTFKernel::CreateInterpolatedKernel(
          kernel_list_r->at(i).get(), kernel_list_r->at(j).get(), x);
    }
  }

  std::unique_ptr<HRTFElevation> hrtf_elevation =
      base::WrapUnique(new HRTFElevation(std::move(kernel_list_l),
                                         std::move(kernel_list_r), elevation));
  return hrtf_elevation;
}

std::unique_ptr<HRTFElevation> HRTFElevation::CreateByInterpolatingSlices(
    HRTFElevation* hrtf_elevation1,
    HRTFElevation* hrtf_elevation2,
    float x) {
  DCHECK(hrtf_elevation1);
  DCHECK(hrtf_elevation2);

  DCHECK_GE(x, 0.0);
  DCHECK_LT(x, 1.0);

  std::unique_ptr<HRTFKernelList> kernel_list_l =
      std::make_unique<HRTFKernelList>(kNumberOfTotalAzimuths);
  std::unique_ptr<HRTFKernelList> kernel_list_r =
      std::make_unique<HRTFKernelList>(kNumberOfTotalAzimuths);

  HRTFKernelList* kernel_list_l1 = hrtf_elevation1->KernelListL();
  HRTFKernelList* kernel_list_r1 = hrtf_elevation1->KernelListR();
  HRTFKernelList* kernel_list_l2 = hrtf_elevation2->KernelListL();
  HRTFKernelList* kernel_list_r2 = hrtf_elevation2->KernelListR();

  // Interpolate kernels of corresponding azimuths of the two elevations.
  for (unsigned i = 0; i < kNumberOfTotalAzimuths; ++i) {
    (*kernel_list_l)[i] = HRTFKernel::CreateInterpolatedKernel(
        kernel_list_l1->at(i).get(), kernel_list_l2->at(i).get(), x);
    (*kernel_list_r)[i] = HRTFKernel::CreateInterpolatedKernel(
        kernel_list_r1->at(i).get(), kernel_list_r2->at(i).get(), x);
  }

  // Interpolate elevation angle.
  const double angle = (1.0 - x) * hrtf_elevation1->elevation_angle_ +
                       x * hrtf_elevation2->elevation_angle_;

  std::unique_ptr<HRTFElevation> hrtf_elevation = base::WrapUnique(
      new HRTFElevation(std::move(kernel_list_l), std::move(kernel_list_r),
                        static_cast<int>(angle)));
  return hrtf_elevation;
}

unsigned HRTFElevation::NumberOfAzimuths() {
  return kNumberOfTotalAzimuths;
}

void HRTFElevation::GetKernelsFromAzimuth(double azimuth_blend,
                                          unsigned azimuth_index,
                                          HRTFKernel*& kernel_l,
                                          HRTFKernel*& kernel_r,
                                          double& frame_delay_l,
                                          double& frame_delay_r) {
  DCHECK_GE(azimuth_blend, 0.0);
  DCHECK_LT(azimuth_blend, 1.0);

  const unsigned num_kernels = kernel_list_l_->size();

  DCHECK_LT(azimuth_index, num_kernels);

  // Return the left and right kernels.
  kernel_l = kernel_list_l_->at(azimuth_index).get();
  kernel_r = kernel_list_r_->at(azimuth_index).get();

  frame_delay_l = kernel_list_l_->at(azimuth_index)->FrameDelay();
  frame_delay_r = kernel_list_r_->at(azimuth_index)->FrameDelay();

  const int azimuth_index2 = (azimuth_index + 1) % num_kernels;
  const double frame_delay2l = kernel_list_l_->at(azimuth_index2)->FrameDelay();
  const double frame_delay2r = kernel_list_r_->at(azimuth_index2)->FrameDelay();

  // Linearly interpolate delays.
  frame_delay_l =
      (1.0 - azimuth_blend) * frame_delay_l + azimuth_blend * frame_delay2l;
  frame_delay_r =
      (1.0 - azimuth_blend) * frame_delay_r + azimuth_blend * frame_delay2r;
}

}  // namespace blink

"""

```