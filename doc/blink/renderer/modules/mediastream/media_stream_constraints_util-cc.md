Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive response.

**1. Understanding the Goal:**

The core request is to understand the functionality of `media_stream_constraints_util.cc` within the Chromium Blink engine, specifically in the context of WebRTC and media stream constraints. Key aspects to address are:

* Functionality of the code.
* Its relationship to JavaScript, HTML, and CSS.
* Logical inferences and example inputs/outputs.
* Common user/programming errors.
* How a user's action leads to this code being executed (debugging perspective).

**2. Initial Code Scan and Identification of Key Components:**

The first step is to skim the code and identify the main building blocks. Keywords like "Constraints," "Settings," "VideoCapture," "AudioCapture," "Scan," "GetConstraintValue," and "Select" immediately stand out. The namespace `blink` and the inclusion of headers like `media_stream_request.h` and `media_stream_constraints_util_sets.h` confirm the area of focus.

* **`VideoCaptureSettings` and `AudioCaptureSettings`:** These classes clearly represent the configuration for video and audio capture. They store parameters like device IDs, resolution, frame rate, buffer size, etc.
* **Template Functions (`ScanConstraintsForExactValue`, `ScanConstraintsForMaxValue`, `ScanConstraintsForMinValue`):** These suggest a pattern for extracting specific constraint values (exact, maximum, minimum) from a `MediaConstraints` object. The use of templates indicates genericity, likely working with different types of constraints (integer, double, boolean).
* **`GetConstraintValueAsBoolean`, `GetConstraintValueAsInteger`, etc.:** These are wrappers around the template functions, providing type-specific interfaces for retrieving constraint values.
* **`SelectVideoTrackAdapterSettings`:** This function seems responsible for choosing optimal video track adapter settings based on constraints and the source format. It involves resolution and frame rate adjustments.
* **`NumericConstraintFitnessDistance` and `StringConstraintFitnessDistance`:** These functions likely play a role in comparing requested constraints with available capabilities, potentially for selecting the best matching device or format.
* **`ComputeCapabilitiesForVideoSource`:** This function calculates the capabilities of a video source based on its supported formats.

**3. Deeper Dive and Functional Analysis:**

Once the key components are identified, the next step is to analyze their specific roles and interactions.

* **Constraint Processing:** The `ScanConstraintsFor...` and `GetConstraintValueAs...` functions are central to how the code interprets user-defined constraints. They traverse the `MediaConstraints` structure (basic and advanced) to find specific values.
* **Settings Object Population:** The `VideoCaptureSettings` and `AudioCaptureSettings` classes act as data containers. The code likely uses the constraint values extracted by the previous step to populate these settings objects.
* **Adapter Selection:** `SelectVideoTrackAdapterSettings` is crucial for adapting the raw video stream to the requested constraints, potentially involving scaling and frame rate adjustment. This is important for performance and resource management.
* **Capability Matching:** The "fitness distance" functions suggest a mechanism for comparing user requirements with the capabilities of available media devices. This is essential for selecting the most appropriate device.
* **Capability Computation:**  `ComputeCapabilitiesForVideoSource` gathers information about a video source's supported formats and other properties, making this information available for constraint matching.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This is where understanding the context of WebRTC becomes vital.

* **JavaScript `getUserMedia()`:** The most direct link is the `getUserMedia()` API. JavaScript code uses this API to request access to media devices, specifying constraints as arguments. The C++ code is responsible for *interpreting* these JavaScript constraints.
* **HTML `<video>` and `<audio>` elements:** While not directly manipulated by this C++ code, these elements are the ultimate destination for the media streams. The constraints influence *which* stream is delivered to these elements.
* **CSS (Indirect):**  CSS styles the video and audio elements, but the constraints managed by this C++ code determine the *content* of those streams. There's an indirect relationship because constraints can affect the resolution and frame rate, which might influence how the video is displayed.

**5. Logical Inference and Examples:**

To solidify understanding, constructing examples is crucial.

* **Assumptions:** Start with basic assumptions about how constraints are structured (e.g., `width: { exact: 640 }`).
* **Input/Output:**  For functions like `ScanConstraintsForExactValue`, define a sample `MediaConstraints` object and the expected extracted value. For `SelectVideoTrackAdapterSettings`, consider different constraint scenarios and how the adapter settings would be adjusted.

**6. Identifying Common Errors:**

Think about common mistakes developers make when working with WebRTC constraints.

* **Typos in constraint names:**  A frequent error.
* **Incompatible constraints:** Requesting impossible combinations (e.g., a very high resolution and very high frame rate simultaneously on a low-end device).
* **Incorrect data types:** Providing a string where a number is expected.
* **Missing or invalid device IDs:**  Specifying a device ID that doesn't exist or is misspelled.

**7. Tracing User Actions (Debugging Perspective):**

This requires imagining the user's flow on a web page.

* **User interaction:** The user clicks a button that triggers a JavaScript function.
* **`getUserMedia()` call:** The JavaScript function calls `navigator.mediaDevices.getUserMedia()` with constraints.
* **Browser processing:** The browser (Chromium in this case) receives the request and needs to resolve the constraints, which involves calling into the Blink rendering engine.
* **Execution of `media_stream_constraints_util.cc`:**  This C++ code is invoked to parse and process the constraints passed from JavaScript.

**8. Structuring the Response:**

Finally, organize the information logically and clearly. Use headings and bullet points to improve readability. Start with a high-level overview of the file's purpose and then delve into specifics. Provide clear examples and explanations.

**Self-Correction/Refinement during the process:**

* **Initially, I might have focused too much on the low-level details of the template functions.**  Realizing that the higher-level functions like `GetConstraintValueAs...` are more important for understanding the overall purpose is key.
* **Connecting to Web technologies might require some back-and-forth.**  Thinking about the lifecycle of a `getUserMedia()` call helps to solidify these connections.
* **Ensuring the examples are concrete and easy to understand is crucial.**  Abstract explanations are less helpful than specific scenarios.

By following this systematic approach, combining code analysis with knowledge of WebRTC and common development practices, a comprehensive and accurate explanation of the code's functionality can be generated.
这个C++源代码文件 `media_stream_constraints_util.cc` 位于 Chromium Blink 引擎中，其主要功能是 **解析、处理和应用媒体流的约束条件（Constraints）**。这些约束条件通常由 JavaScript 代码通过 `getUserMedia()` API 传递给浏览器，用于指定用户希望获得的媒体流的特性，例如视频的分辨率、帧率、音频的采样率等。

以下是该文件的详细功能列表以及与其他 Web 技术的关系：

**主要功能：**

1. **解析约束条件 (`ScanConstraintsFor...` 模板函数)：**
   - 该文件包含多个模板函数（如 `ScanConstraintsForExactValue`, `ScanConstraintsForMaxValue`, `ScanConstraintsForMinValue`），用于遍历和解析 `MediaConstraints` 对象。
   - `MediaConstraints` 对象包含了基本的约束 (`Basic`) 和高级的约束 (`Advanced`)。
   - 这些函数会查找特定的约束属性（由 `picker` 参数指定），并尝试提取出期望的值（精确值、最大值、最小值）。

2. **获取特定类型的约束值 (`GetConstraintValueAs...` 函数)：**
   - 提供了一系列便捷的函数（如 `GetConstraintValueAsBoolean`, `GetConstraintValueAsInteger`, `GetConstraintValueAsDouble`）来获取特定数据类型的约束值。
   - 这些函数内部调用了上述的模板函数，简化了对不同类型约束值的提取。

3. **选择视频轨道适配器设置 (`SelectVideoTrackAdapterSettings`)：**
   - 该函数根据提供的约束条件（包括分辨率、帧率等）和源视频的格式，选择合适的视频轨道适配器设置 (`VideoTrackAdapterSettings`).
   - 这涉及到根据约束调整视频流的分辨率和帧率，以满足用户的需求，同时考虑到性能和资源消耗。

4. **计算数值和字符串约束的匹配度 (`NumericConstraintFitnessDistance`, `StringConstraintFitnessDistance`)：**
   - 这些函数用于衡量实际的媒体设备能力与用户请求的约束之间的差距。
   - 这对于选择最符合用户约束的媒体设备和格式非常重要。

5. **计算视频源的能力 (`ComputeCapabilitiesForVideoSource`)：**
   - 该函数根据视频设备的 ID 和其支持的格式 (`media::VideoCaptureFormats`)，计算出该视频源的能力信息 (`MediaStreamSource::Capabilities`)，例如支持的最大分辨率、帧率等。
   - 这有助于系统判断哪些设备和格式能够满足用户的约束。

6. **定义媒体捕获设置结构体 (`VideoCaptureSettings`, `AudioCaptureSettings`)：**
   - 定义了用于存储视频和音频捕获设置的结构体。
   - 这些结构体包含了设备 ID、捕获参数（如分辨率、帧率）、噪声抑制、音频处理类型等信息。
   - 这些结构体是解析和处理约束后的结果，用于配置实际的媒体捕获过程。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件在 WebRTC 流程中扮演着关键的角色，它直接处理来自 JavaScript 的约束信息。

**与 JavaScript 的关系：**

- **`getUserMedia()` API：** JavaScript 代码通过 `navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 } })`  这样的方式来请求访问用户的摄像头，并指定了视频的约束条件。
- **约束对象传递：**  JavaScript 中定义的约束对象（例如 `{ width: { min: 640 } }`）会被传递到浏览器内核，最终由这个 C++ 文件中的代码进行解析和处理。
- **示例：**
    - **假设 JavaScript 代码为：**
      ```javascript
      navigator.mediaDevices.getUserMedia({
        video: {
          width: { min: 640, ideal: 1280 },
          frameRate: { max: 30 }
        }
      })
      .then(function(stream) { /* 使用 stream */ })
      .catch(function(error) { /* 处理错误 */ });
      ```
    - **`media_stream_constraints_util.cc` 的作用：**  该文件中的代码会解析 `width` 和 `frameRate` 的约束。例如，`ScanConstraintsForMinValue` 模板函数会被用来查找 `width` 的最小值（640），`ScanConstraintsForMaxValue` 模板函数会被用来查找 `frameRate` 的最大值（30）。`SelectVideoTrackAdapterSettings` 函数会根据这些约束以及设备的能力，选择合适的视频捕获参数。

**与 HTML 的关系：**

- **`<video>` 和 `<audio>` 元素：** 虽然这个 C++ 文件本身不直接操作 HTML 元素，但它处理的约束条件直接影响着最终呈现到 HTML `<video>` 或 `<audio>` 元素中的媒体流的特性。例如，如果约束条件指定了特定的分辨率，那么最终的视频流就会以接近该分辨率的形式展示在 `<video>` 元素中。

**与 CSS 的关系：**

- **间接影响：** CSS 用于控制 HTML 元素的外观和布局，包括 `<video>` 和 `<audio>` 元素。虽然这个 C++ 文件不直接与 CSS 交互，但它处理的约束条件可能会影响到需要应用到媒体元素的 CSS 规则。例如，如果视频分辨率很高，可能需要调整包含视频元素的容器的 CSS 样式以适应显示。

**逻辑推理与假设输入/输出：**

**假设输入：** 一个包含视频约束的 `MediaConstraints` 对象，例如：

```
MediaConstraints {
  basic: MediaTrackConstraintSetPlatform {
    width: LongConstraint { ideal: 1920 },
    height: LongConstraint { min: 1080 },
    frameRate: DoubleConstraint { max: 60 }
  },
  advanced: []
}
```

**逻辑推理和输出：**

- **`ScanConstraintsForExactValue(constraints, &MediaTrackConstraintSetPlatform::width, &value)`:**  会尝试查找精确的 `width` 值，如果存在则返回 `true` 并将 `value` 设置为 1920。
- **`ScanConstraintsForMinValue(constraints, &MediaTrackConstraintSetPlatform::height, &value)`:** 会查找 `height` 的最小值，返回 `true` 并将 `value` 设置为 1080。
- **`ScanConstraintsForMaxValue(constraints, &MediaTrackConstraintSetPlatform::frameRate, &value)`:** 会查找 `frameRate` 的最大值，返回 `true` 并将 `value` 设置为 60.0。
- **`SelectVideoTrackAdapterSettings`:** 基于这些解析出的约束，以及实际的摄像头支持的格式，会计算出最佳的视频轨道适配器设置，例如目标分辨率可能会接近 1920x1080，最大帧率不超过 60fps。

**用户或编程常见的使用错误：**

1. **约束名称拼写错误：** 在 JavaScript 中指定约束时，如果属性名称拼写错误（例如 `widht` 而不是 `width`），则这个 C++ 文件中的代码将无法正确解析该约束，导致约束失效或使用默认值。

   **示例：**
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: { widht: 640 } }); // 拼写错误
   ```
   **结果：** 摄像头将以默认的宽度启动，而不是用户期望的 640 像素。

2. **指定了互相冲突的约束：**  例如，同时要求一个非常小的分辨率和一个非常高的帧率，这可能超出设备的物理能力。

   **示例：**
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: { width: { max: 320 }, frameRate: { min: 120 } } });
   ```
   **结果：**  浏览器可能会选择一个尽可能接近这些约束的配置，但很可能无法同时满足两者，最终的帧率可能低于 120fps。

3. **使用了不支持的约束属性：**  WebRTC 标准定义了一些标准的约束属性，如果使用了非标准的或过时的属性，浏览器可能无法识别并忽略这些约束。

4. **类型不匹配的约束值：**  例如，将字符串值赋给一个应该为数字类型的约束。

   **示例：**
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: { frameRate: "high" } }); // frameRate 应该是一个数字
   ```
   **结果：**  该约束将被忽略。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户打开一个网页，该网页包含使用 WebRTC 的 JavaScript 代码。**
2. **JavaScript 代码调用 `navigator.mediaDevices.getUserMedia(constraints)`，并传入一个包含媒体约束的对象。**
3. **浏览器接收到 `getUserMedia` 请求后，会将这些约束信息传递给 Blink 渲染引擎。**
4. **Blink 引擎中的媒体流处理模块会创建 `MediaConstraints` 对象来表示这些约束。**
5. **`media_stream_constraints_util.cc` 文件中的相关函数会被调用，以解析和处理 `MediaConstraints` 对象中的各种约束。**
   - 例如，当需要获取视频轨道的设置时，`SelectVideoTrackAdapterSettings` 函数会被调用。
   - 当需要查找特定的约束值时，`ScanConstraintsFor...` 或 `GetConstraintValueAs...` 函数会被调用。
6. **处理后的约束信息会被用于配置底层的媒体捕获管道，例如选择合适的摄像头、设置捕获分辨率和帧率等。**
7. **最终，用户请求的媒体流（如果成功获取）会返回给 JavaScript 代码。**

**调试线索：**

- **查看浏览器控制台的日志：**  Chromium 通常会在控制台中输出与 `getUserMedia` 相关的错误或警告信息，这可以帮助定位约束问题。
- **使用 `chrome://webrtc-internals/`：**  这个 Chrome 提供的内部页面可以查看详细的 WebRTC 会话信息，包括应用的约束、实际使用的设备能力、协商过程等，有助于分析约束是否生效以及为什么选择了特定的设备或格式。
- **断点调试 C++ 代码：**  对于 Chromium 开发人员或需要深入了解实现细节的情况，可以在 `media_stream_constraints_util.cc` 文件中的关键函数设置断点，例如在 `ScanConstraintsForExactValue` 或 `SelectVideoTrackAdapterSettings` 函数中，来观察约束的解析和处理过程。
- **检查 `MediaConstraints` 对象的内容：**  在 C++ 代码中，可以打印或查看 `MediaConstraints` 对象的内容，确认从 JavaScript 传递过来的约束是否正确。

总而言之，`media_stream_constraints_util.cc` 是 Blink 引擎中处理 WebRTC 媒体约束的核心组件，它连接了 JavaScript 中声明的用户意图和底层媒体设备的实际能力，确保用户能够获得符合其需求的媒体流。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"

#include <algorithm>
#include <limits>
#include <utility>

#include "third_party/blink/public/common/mediastream/media_stream_request.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.h"

namespace blink {

namespace {

template <typename P, typename T>
bool ScanConstraintsForExactValue(const MediaConstraints& constraints,
                                  P picker,
                                  T* value) {
  if (constraints.IsNull())
    return false;

  const auto& the_field = constraints.Basic().*picker;
  if (the_field.HasExact()) {
    *value = the_field.Exact();
    return true;
  }
  for (const auto& advanced_constraint : constraints.Advanced()) {
    const auto& advanced_field = advanced_constraint.*picker;
    if (advanced_field.HasExact()) {
      *value = advanced_field.Exact();
      return true;
    }
  }
  return false;
}

template <typename P, typename T>
bool ScanConstraintsForMaxValue(const MediaConstraints& constraints,
                                P picker,
                                T* value) {
  if (constraints.IsNull())
    return false;
  const auto& the_field = constraints.Basic().*picker;
  if (the_field.HasMax()) {
    *value = the_field.Max();
    return true;
  }
  if (the_field.HasExact()) {
    *value = the_field.Exact();
    return true;
  }
  for (const auto& advanced_constraint : constraints.Advanced()) {
    const auto& advanced_field = advanced_constraint.*picker;
    if (advanced_field.HasMax()) {
      *value = advanced_field.Max();
      return true;
    }
    if (advanced_field.HasExact()) {
      *value = advanced_field.Exact();
      return true;
    }
  }
  return false;
}

template <typename P, typename T>
bool ScanConstraintsForMinValue(const MediaConstraints& constraints,
                                P picker,
                                T* value) {
  if (constraints.IsNull())
    return false;
  const auto& the_field = constraints.Basic().*picker;
  if (the_field.HasMin()) {
    *value = the_field.Min();
    return true;
  }
  if (the_field.HasExact()) {
    *value = the_field.Exact();
    return true;
  }
  for (const auto& advanced_constraint : constraints.Advanced()) {
    const auto& advanced_field = advanced_constraint.*picker;
    if (advanced_field.HasMin()) {
      *value = advanced_field.Min();
      return true;
    }
    if (advanced_field.HasExact()) {
      *value = advanced_field.Exact();
      return true;
    }
  }
  return false;
}

}  // namespace

const double kMinDeviceCaptureFrameRate = std::numeric_limits<double>::min();

VideoCaptureSettings::VideoCaptureSettings() : VideoCaptureSettings("") {}

VideoCaptureSettings::VideoCaptureSettings(const char* failed_constraint_name)
    : failed_constraint_name_(failed_constraint_name) {
  DCHECK(failed_constraint_name_);
}

VideoCaptureSettings::VideoCaptureSettings(
    std::string device_id,
    media::VideoCaptureParams capture_params,
    std::optional<bool> noise_reduction,
    const VideoTrackAdapterSettings& track_adapter_settings,
    std::optional<double> min_frame_rate,
    std::optional<double> max_frame_rate,
    std::optional<ImageCaptureDeviceSettings> image_capture_device_settings)
    : failed_constraint_name_(nullptr),
      device_id_(std::move(device_id)),
      capture_params_(capture_params),
      noise_reduction_(noise_reduction),
      track_adapter_settings_(track_adapter_settings),
      min_frame_rate_(min_frame_rate),
      max_frame_rate_(max_frame_rate),
      image_capture_device_settings_(image_capture_device_settings) {
  DCHECK(!min_frame_rate ||
         *min_frame_rate_ <= capture_params.requested_format.frame_rate);
  DCHECK(!track_adapter_settings.target_size() ||
         track_adapter_settings.target_size()->width() <=
             capture_params.requested_format.frame_size.width());
  DCHECK(!track_adapter_settings_.target_size() ||
         track_adapter_settings_.target_size()->height() <=
             capture_params.requested_format.frame_size.height());
}

VideoCaptureSettings::VideoCaptureSettings(const VideoCaptureSettings& other) =
    default;
VideoCaptureSettings::VideoCaptureSettings(VideoCaptureSettings&& other) =
    default;
VideoCaptureSettings::~VideoCaptureSettings() = default;
VideoCaptureSettings& VideoCaptureSettings::operator=(
    const VideoCaptureSettings& other) = default;
VideoCaptureSettings& VideoCaptureSettings::operator=(
    VideoCaptureSettings&& other) = default;

AudioCaptureSettings::AudioCaptureSettings() : AudioCaptureSettings("") {}

AudioCaptureSettings::AudioCaptureSettings(const char* failed_constraint_name)
    : failed_constraint_name_(failed_constraint_name) {
  DCHECK(failed_constraint_name_);
}

AudioCaptureSettings::AudioCaptureSettings(
    std::string device_id,
    const std::optional<int>& requested_buffer_size,
    bool disable_local_echo,
    bool enable_automatic_output_device_selection,
    ProcessingType processing_type,
    const AudioProcessingProperties& audio_processing_properties,
    int num_channels)
    : failed_constraint_name_(nullptr),
      device_id_(std::move(device_id)),
      requested_buffer_size_(requested_buffer_size),
      disable_local_echo_(disable_local_echo),
      render_to_associated_sink_(enable_automatic_output_device_selection),
      processing_type_(processing_type),
      audio_processing_properties_(audio_processing_properties),
      num_channels_(num_channels) {}

AudioCaptureSettings::AudioCaptureSettings(const AudioCaptureSettings& other) =
    default;
AudioCaptureSettings& AudioCaptureSettings::operator=(
    const AudioCaptureSettings& other) = default;
AudioCaptureSettings::AudioCaptureSettings(AudioCaptureSettings&& other) =
    default;
AudioCaptureSettings& AudioCaptureSettings::operator=(
    AudioCaptureSettings&& other) = default;

bool GetConstraintValueAsBoolean(
    const MediaConstraints& constraints,
    const BooleanConstraint MediaTrackConstraintSetPlatform::*picker,
    bool* value) {
  return ScanConstraintsForExactValue(constraints, picker, value);
}

bool GetConstraintValueAsInteger(
    const MediaConstraints& constraints,
    const LongConstraint MediaTrackConstraintSetPlatform::*picker,
    int* value) {
  return ScanConstraintsForExactValue(constraints, picker, value);
}

bool GetConstraintMinAsInteger(
    const MediaConstraints& constraints,
    const LongConstraint MediaTrackConstraintSetPlatform::*picker,
    int* value) {
  return ScanConstraintsForMinValue(constraints, picker, value);
}

bool GetConstraintMaxAsInteger(
    const MediaConstraints& constraints,
    const LongConstraint MediaTrackConstraintSetPlatform::*picker,
    int* value) {
  return ScanConstraintsForMaxValue(constraints, picker, value);
}

bool GetConstraintValueAsDouble(
    const MediaConstraints& constraints,
    const DoubleConstraint MediaTrackConstraintSetPlatform::*picker,
    double* value) {
  return ScanConstraintsForExactValue(constraints, picker, value);
}

VideoTrackAdapterSettings SelectVideoTrackAdapterSettings(
    const MediaTrackConstraintSetPlatform& basic_constraint_set,
    const media_constraints::ResolutionSet& resolution_set,
    const media_constraints::NumericRangeSet<double>& frame_rate_set,
    const media::VideoCaptureFormat& source_format,
    bool enable_rescale) {
  std::optional<gfx::Size> target_resolution;
  if (enable_rescale) {
    media_constraints::ResolutionSet::Point resolution =
        resolution_set.SelectClosestPointToIdeal(
            basic_constraint_set, source_format.frame_size.height(),
            source_format.frame_size.width());
    int track_target_height = static_cast<int>(std::round(resolution.height()));
    int track_target_width = static_cast<int>(std::round(resolution.width()));
    target_resolution = gfx::Size(track_target_width, track_target_height);
  }
  double track_min_aspect_ratio =
      std::max(resolution_set.min_aspect_ratio(),
               static_cast<double>(resolution_set.min_width()) /
                   static_cast<double>(resolution_set.max_height()));
  double track_max_aspect_ratio =
      std::min(resolution_set.max_aspect_ratio(),
               static_cast<double>(resolution_set.max_width()) /
                   static_cast<double>(resolution_set.min_height()));
  // VideoTrackAdapter uses an unset frame rate to disable frame-rate
  // adjustment.
  std::optional<double> track_max_frame_rate = frame_rate_set.Max();
  if (basic_constraint_set.frame_rate.HasIdeal()) {
    track_max_frame_rate = std::max(basic_constraint_set.frame_rate.Ideal(),
                                    kMinDeviceCaptureFrameRate);
    if (frame_rate_set.Min() && *track_max_frame_rate < *frame_rate_set.Min()) {
      track_max_frame_rate = *frame_rate_set.Min();
    }
    if (frame_rate_set.Max() && *track_max_frame_rate > *frame_rate_set.Max()) {
      track_max_frame_rate = *frame_rate_set.Max();
    }
  }

  return VideoTrackAdapterSettings(target_resolution, track_min_aspect_ratio,
                                   track_max_aspect_ratio,
                                   track_max_frame_rate);
}

double NumericConstraintFitnessDistance(double value1, double value2) {
  if (std::fabs(value1 - value2) <= DoubleConstraint::kConstraintEpsilon)
    return 0.0;

  return std::fabs(value1 - value2) /
         std::max(std::fabs(value1), std::fabs(value2));
}

double StringConstraintFitnessDistance(const WebString& value,
                                       const StringConstraint& constraint) {
  if (!constraint.HasIdeal())
    return 0.0;

  for (auto& ideal_value : constraint.Ideal()) {
    // TODO(crbug.com/787254): Remove the explicit conversion to WebString when
    // this method operates solely over WTF::String.
    if (value == WebString(ideal_value))
      return 0.0;
  }

  return 1.0;
}

MediaStreamSource::Capabilities ComputeCapabilitiesForVideoSource(
    const String& device_id,
    const media::VideoCaptureFormats& formats,
    mojom::blink::FacingMode facing_mode,
    bool is_device_capture,
    const std::optional<std::string>& group_id) {
  MediaStreamSource::Capabilities capabilities;
  capabilities.device_id = std::move(device_id);
  if (is_device_capture) {
    capabilities.facing_mode = ToPlatformFacingMode(facing_mode);
    if (group_id)
      capabilities.group_id = String::FromUTF8(*group_id);
  }
  if (!formats.empty()) {
    int max_width = 1;
    int max_height = 1;
    float min_frame_rate =
        is_device_capture ? kMinDeviceCaptureFrameRate : 0.0f;
    float max_frame_rate = min_frame_rate;
    for (const auto& format : formats) {
      max_width = std::max(max_width, format.frame_size.width());
      max_height = std::max(max_height, format.frame_size.height());
      max_frame_rate = std::max(max_frame_rate, format.frame_rate);
    }
    capabilities.width = {1, static_cast<uint32_t>(max_width)};
    capabilities.height = {1, static_cast<uint32_t>(max_height)};
    capabilities.aspect_ratio = {1.0 / max_height,
                                 static_cast<double>(max_width)};
    capabilities.frame_rate = {min_frame_rate, max_frame_rate};
  }
  return capabilities;
}

}  // namespace blink
```