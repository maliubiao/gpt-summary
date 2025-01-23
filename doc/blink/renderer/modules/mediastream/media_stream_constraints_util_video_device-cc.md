Response:
The user wants to understand the functionality of the given C++ code file `media_stream_constraints_util_video_device.cc`. I need to analyze the code and explain its purpose, especially its relation to web technologies (JavaScript, HTML, CSS). I also need to provide examples of logical reasoning, user errors, and debugging steps. Finally, I need to summarize the functionalities in this first part.

**Plan:**

1. **High-level functionality:** Determine the main goal of this file. It seems to be related to handling video device constraints in the context of `getUserMedia` or similar APIs.
2. **Relationship with web technologies:** Identify how the C++ code interacts with JavaScript, HTML, and CSS. Focus on how constraints defined in JavaScript are processed here.
3. **Logical reasoning:** Pick a function or a block of code and explain its logic with example inputs and outputs.
4. **User/programming errors:** Think about common mistakes developers might make when setting video constraints in JavaScript, and how this code might handle or expose those errors.
5. **Debugging scenario:** Describe the steps a user might take in a web page that would lead to the execution of this code, providing debugging hints.
6. **Summarize the functionality:** Provide a concise overview of the file's purpose based on the analysis of the first part.
这是 blink 渲染引擎中处理视频设备媒体流约束的核心工具文件。它的主要功能是：

**核心功能：根据用户指定的约束条件，从可用的视频设备能力中选择最佳的视频捕获格式和设备设置。**

具体来说，这个文件包含了一些类和函数，用于：

*   **表示和操作约束条件 (Constraints):**  定义了如何处理各种视频约束，例如分辨率（宽度、高度、宽高比）、帧率、facingMode（前置/后置摄像头）等。
*   **表示设备能力 (Capabilities):**  假定存在一个 `VideoInputDeviceCapabilities` (DeviceInfo) 类型（尽管在提供的代码片段中没有完整定义），用于表示视频设备支持的各种格式和设置。
*   **计算匹配度 (Fitness):** 核心在于计算每个可能的视频格式和设备设置与用户指定约束的匹配程度（fitness）。匹配度越低，表示越符合用户的理想设置。
*   **应用约束集 (Apply Constraint Set):**  提供了一种机制来逐步应用不同的约束集，并跟踪哪些格式和设置仍然满足所有约束。
*   **选择最佳设置 (Select Best Settings):**  最终目标是根据计算出的匹配度，选择最符合用户约束的视频格式和设备设置。
*   **处理高级约束 (Advanced Constraints):**  支持处理基本的和高级的约束。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是浏览器内核的一部分，它直接响应 JavaScript 中通过 `getUserMedia()` API 设置的媒体约束。

**举例说明：**

1. **JavaScript (getUserMedia):**  当网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { min: 720 } } })` 时，这些约束（理想宽度 1280，最小高度 720）会被传递到浏览器内核。

2. **C++ 处理:**  `media_stream_constraints_util_video_device.cc` 中的代码会接收到这些约束，并与可用的视频设备能力进行比较。例如，`ResolutionSet::FromConstraintSet(constraint_set)` 可以将 JavaScript 传递的宽度和高度约束转换为 C++ 中用于比较的数据结构。

3. **HTML/CSS (间接关系):**  虽然这个 C++ 文件不直接处理 HTML 或 CSS，但它选择的视频格式和设备设置会影响最终渲染在 HTML `<video>` 元素中的视频流。例如，如果 JavaScript 请求高分辨率，而该文件选择了一个低分辨率格式，那么 `<video>` 元素中显示的视频质量就会受到影响。CSS 可以用来控制 `<video>` 元素的显示尺寸，但这与 C++ 中选择的实际视频流分辨率是不同的。

**逻辑推理举例：**

假设输入：

*   **设备能力 (DeviceInfo):**  支持两种视频格式：
    *   格式 1: 宽度 640, 高度 480, 帧率 30
    *   格式 2: 宽度 1280, 高度 720, 帧率 25
*   **用户约束 (MediaTrackConstraintSetPlatform):**
    *   理想宽度: 1200
    *   最小高度: 600
    *   理想帧率: 30

逻辑推理过程 (简化)：

1. **`CandidateFormat` 创建:** 为每种设备能力创建一个 `CandidateFormat` 对象。
2. **应用约束:**  `TryToApplyConstraintSet` 函数会尝试将用户约束应用到每个 `CandidateFormat`。
    *   格式 1 满足最小高度约束 (480 < 600 不满足)，因此被排除。
    *   格式 2 满足最小高度约束 (720 >= 600)。
3. **计算匹配度 (`Fitness`):** 计算格式 2 的匹配度。
    *   宽度匹配度：`NumericValueFitness(1200, 1280)`  (理想宽度 1200，实际 1280)
    *   高度匹配度：`NumericValueFitness`  (由于只有最小值约束，这里可能为 0)
    *   帧率匹配度：`NumericValueFitness(30, 25)` (理想帧率 30，实际 25)
4. **选择最佳:**  由于只有格式 2 满足约束，它将被选中。

输出：

*   选择格式 2 (宽度 1280, 高度 720, 帧率 25) 作为最佳匹配。

**用户或编程常见的使用错误举例：**

1. **约束冲突:**  用户在 JavaScript 中设置了互相冲突的约束。例如，同时要求 `minWidth: 1920` 和 `maxWidth: 640`。这个 C++ 代码会尝试应用这些约束，但最终可能无法找到任何满足条件的格式。

2. **超出设备能力:** 用户要求的约束超出了设备的实际能力。例如，要求 4K 分辨率，但设备只能支持 1080p。这个代码会尝试匹配，但最终会选择最接近但仍低于用户要求的格式。

3. **拼写错误或使用了不支持的约束属性:**  JavaScript 中约束属性的拼写错误（例如 `widht` 而不是 `width`）或者使用了浏览器不支持的约束属性，会导致这些约束根本无法传递到 C++ 代码中进行处理，或者被忽略。

**用户操作到达这里的步骤 (调试线索)：**

1. **用户打开一个网页:** 用户在 Chrome 浏览器中打开一个使用了 `getUserMedia()` API 获取摄像头视频流的网页。
2. **网页请求摄像头权限:** 网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: ... })`，并请求用户的摄像头权限。
3. **用户同意授权:** 用户在浏览器提示中点击允许，授予网页访问摄像头的权限。
4. **浏览器内核处理请求:** Chrome 浏览器内核接收到 `getUserMedia()` 请求，并开始枚举可用的视频输入设备及其能力。
5. **约束处理:**  `blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.cc` 中的代码被调用，接收 JavaScript 传递的视频约束。
6. **匹配和选择:**  该文件中的函数会根据约束条件和设备能力进行匹配和选择，确定最佳的视频格式和设备设置。
7. **返回结果:**  选择好的视频流信息被返回给 JavaScript，然后网页可以使用这些信息在 `<video>` 元素中显示视频。

**调试线索：**

*   如果在网页上看到的视频分辨率或帧率与预期不符，可以检查 JavaScript 中设置的约束是否正确。
*   可以使用 Chrome 的开发者工具 (特别是 "Media" 面板) 来查看 `getUserMedia()` 的请求和返回的媒体流信息，包括选择的视频格式。
*   如果怀疑是约束处理的问题，可以在 Chrome 源码中设置断点来调试 `media_stream_constraints_util_video_device.cc` 中的代码，查看约束是如何被解析和匹配的。

**归纳一下它的功能 (第 1 部分)：**

这个 C++ 代码文件的主要功能是作为 Chromium Blink 引擎处理视频设备媒体流约束的核心部分。它负责接收来自 JavaScript 的视频约束条件，并根据这些约束，从可用的视频设备能力中选择最佳的视频捕获格式和设备设置。这包括表示和操作约束、表示设备能力、计算匹配度、应用约束集等关键步骤。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

#include "base/containers/contains.h"
#include "base/strings/stringprintf.h"
#include "media/base/limits.h"
#include "media/base/video_types.h"
#include "media/mojo/mojom/display_media_information.mojom-blink.h"
#include "media/webrtc/webrtc_features.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace {

using ResolutionSet = media_constraints::ResolutionSet;
using DoubleRangeSet = media_constraints::NumericRangeSet<double>;
using IntRangeSet = media_constraints::NumericRangeSet<int32_t>;
using BoolSet = media_constraints::DiscreteSet<bool>;
// TODO(crbug.com/704136): Replace VideoInputDeviceCapabilities with Blink
// mojo pointer type once dependent types are migrated to Blink.
using DeviceInfo = VideoInputDeviceCapabilities;
using DistanceVector = WTF::Vector<double>;

// Number of default settings to be used as final tie-breaking criteria for
// settings that are equally good at satisfying constraints:
// device ID, noise reduction, resolution and frame rate.
const int kNumDefaultDistanceEntries = 4;

WebString ToWebString(mojom::blink::FacingMode facing_mode) {
  switch (facing_mode) {
    case mojom::blink::FacingMode::kUser:
      return WebString::FromASCII("user");
    case mojom::blink::FacingMode::kEnvironment:
      return WebString::FromASCII("environment");
    default:
      return WebString();
  }
}

double BoolSetFitness(const BooleanConstraint& constraint, const BoolSet& set) {
  DCHECK(!set.IsEmpty());

  if (!constraint.HasIdeal()) {
    return 0.0;
  }

  bool ideal = constraint.Ideal();
  return set.Contains(ideal) ? 0.0 : 1.0;
}

// Returns the fitness distance between the ideal value of |constraint| and
// |value|. Based on
// https://w3c.github.io/mediacapture-main/#dfn-fitness-distance.
template <typename NumericConstraint>
double NumericValueFitness(const NumericConstraint& constraint,
                           decltype(constraint.Min()) value) {
  return constraint.HasIdeal()
             ? NumericConstraintFitnessDistance(value, constraint.Ideal())
             : 0.0;
}

// Returns the fitness distance between the ideal value of |constraint| and the
// closest value to it in the range [min, max].
// If the ideal value is contained in the range, returns 0.
// If there is no ideal value, returns 0;
// Based on https://w3c.github.io/mediacapture-main/#dfn-fitness-distance.
template <typename NumericConstraint>
double NumericRangeSetFitness(
    const NumericConstraint& constraint,
    const media_constraints::NumericRangeSet<decltype(constraint.Min())>&
        range) {
  DCHECK(!range.IsEmpty());

  if (!constraint.HasIdeal()) {
    return 0.0;
  }

  auto ideal = constraint.Ideal();
  if (range.Max().has_value() && ideal > *range.Max()) {
    return NumericConstraintFitnessDistance(ideal, *range.Max());
  } else if (range.Min().has_value() && ideal < *range.Min()) {
    return NumericConstraintFitnessDistance(ideal, *range.Min());
  }

  return 0.0;  // |range| contains |ideal|
}

// Returns the fitness distance between the ideal value of |constraint| and the
// closest value to it in the range [min, max] if the constraint is supported.
// If the constraint is present but not supported, returns 1.
// If the ideal value is contained in the range, returns 0.
// If there is no ideal value, returns 0;
// Based on https://w3c.github.io/mediacapture-main/#dfn-fitness-distance.
template <typename NumericConstraint>
double NumericRangeSupportFitness(
    const NumericConstraint& constraint,
    const media_constraints::NumericRangeSet<decltype(constraint.Min())>& range,
    bool constraint_present,
    bool constraint_supported) {
  DCHECK(!range.IsEmpty());

  if (constraint_present && !constraint_supported) {
    return 1.0;
  }

  return NumericRangeSetFitness(constraint, range);
}

// Returns a custom distance between |native_value| and the ideal value and
// allowed range for a constrainable property. The ideal value is obtained from
// |constraint| and the allowed range is specified by |min| and |max|.
// The allowed range is not obtained from |constraint| because it might be the
// result of the application of multiple constraint sets.
// The custom distance is computed using the spec-defined fitness distance
// between |native_value| and the value within the range [|min|, |max|] closest
// to the ideal value.
// If there is no ideal value and |native_value| is greater than |max|, the
// distance between |max| and |native_value| is returned.
// The purpose of this function is to be used to break ties among equally good
// candidates by penalizing those whose native settings are further from the
// range and ideal values specified by constraints.
template <typename NumericConstraint>
double NumericRangeNativeFitness(const NumericConstraint& constraint,
                                 decltype(constraint.Min()) min,
                                 decltype(constraint.Min()) max,
                                 decltype(constraint.Min()) native_value) {
  auto reference_value = constraint.HasIdeal()
                             ? std::max(std::min(constraint.Ideal(), max), min)
                             : max;
  return NumericConstraintFitnessDistance(native_value, reference_value);
}

// Returns the fitness distance between the ideal value of |constraint| and
// an optional boolean |value|.
// Based on https://w3c.github.io/mediacapture-main/#dfn-fitness-distance.
double OptionalBoolFitness(const std::optional<bool>& value,
                           const BooleanConstraint& constraint) {
  if (!constraint.HasIdeal()) {
    return 0.0;
  }

  return value && value == constraint.Ideal() ? 0.0 : 1.0;
}

// If |failed_constraint_name| is not null, this function updates it with the
// name of |constraint|.
void UpdateFailedConstraintName(const BaseConstraint& constraint,
                                const char** failed_constraint_name) {
  if (failed_constraint_name) {
    *failed_constraint_name = constraint.GetName();
  }
}

// The CandidateFormat class keeps track of the effect of constraint sets on
// the range of values supported by a video-capture format. For example, suppose
// a device supports a width of 1024. Then, in principle, it can support any
// width below 1024 using cropping and rescaling. Suppose the first advanced
// constraint set requests a maximum width of 640, and the second advanced
// constraint set requests a minimum of 800. Separately, the camera supports
// both advanced sets. However, if the first set is supported, the second set
// can no longer be supported because width can no longer exceed 640. The
// CandidateFormat class keeps track of this.
class CandidateFormat {
 public:
  class ApplyConstraintSetResult {
   public:
    ApplyConstraintSetResult() = default;

   private:
    friend class CandidateFormat;

    DoubleRangeSet constrained_frame_rate_;
    IntRangeSet constrained_width_;
    IntRangeSet constrained_height_;
    DoubleRangeSet constrained_aspect_ratio_;

    BoolSet rescale_intersection_;
    ResolutionSet resolution_intersection_;
  };

  explicit CandidateFormat(const media::VideoCaptureFormat& format)
      : format_(format),
        resolution_set_(1,
                        format.frame_size.height(),
                        1,
                        format.frame_size.width(),
                        0.0,
                        HUGE_VAL) {}

  const media::VideoCaptureFormat& format() const { return format_; }
  const ResolutionSet& resolution_set() const { return resolution_set_; }
  const DoubleRangeSet& constrained_frame_rate() const {
    return constrained_frame_rate_;
  }

  // Convenience accessors for format() fields.
  int NativeHeight() const { return format_.frame_size.height(); }
  int NativeWidth() const { return format_.frame_size.width(); }
  double NativeAspectRatio() const {
    DCHECK(NativeWidth() > 0 || NativeHeight() > 0);
    return static_cast<double>(NativeWidth()) / NativeHeight();
  }
  double NativeFrameRate() const { return format_.frame_rate; }

  // Convenience accessors for accessors for resolution_set() fields. They
  // return the minimum and maximum resolution settings supported by this
  // format, subject to applied constraints.
  int MinHeight() const { return resolution_set_.min_height(); }
  int MaxHeight() const { return resolution_set_.max_height(); }
  int MinWidth() const { return resolution_set_.min_width(); }
  int MaxWidth() const { return resolution_set_.max_width(); }
  double MinAspectRatio() const {
    return std::max(resolution_set_.min_aspect_ratio(),
                    static_cast<double>(MinWidth()) / MaxHeight());
  }
  double MaxAspectRatio() const {
    return std::min(resolution_set_.max_aspect_ratio(),
                    static_cast<double>(MaxWidth()) / MinHeight());
  }

  // Convenience accessors for constrained_frame_rate() fields.
  const std::optional<double>& MinFrameRateConstraint() const {
    return constrained_frame_rate_.Min();
  }
  const std::optional<double>& MaxFrameRateConstraint() const {
    return constrained_frame_rate_.Max();
  }

  // Accessors that return the minimum and maximum frame rates supported by
  // this format, subject to applied constraints.
  double MaxFrameRate() const {
    if (MaxFrameRateConstraint()) {
      return std::min(*MaxFrameRateConstraint(), NativeFrameRate());
    }
    return NativeFrameRate();
  }
  double MinFrameRate() const {
    if (MinFrameRateConstraint()) {
      return std::max(*MinFrameRateConstraint(), kMinDeviceCaptureFrameRate);
    }
    return kMinDeviceCaptureFrameRate;
  }

  // This function tries to apply |constraint_set| and returns the result
  // if successful. If |constraint_set| cannot be satisfied,
  // a nullopt is returned, and the name of one of the constraints that
  // could not be satisfied is returned in |failed_constraint_name| if
  // |failed_constraint_name| is not null.
  std::optional<ApplyConstraintSetResult> TryToApplyConstraintSet(
      const MediaTrackConstraintSetPlatform& constraint_set,
      const char** failed_constraint_name = nullptr) const {
    std::optional<ApplyConstraintSetResult> result(std::in_place);

    result->rescale_intersection_ =
        rescale_set_.Intersection(media_constraints::RescaleSetFromConstraint(
            constraint_set.resize_mode));
    if (result->rescale_intersection_.IsEmpty()) {
      UpdateFailedConstraintName(constraint_set.resize_mode,
                                 failed_constraint_name);
      return std::nullopt;
    }

    result->resolution_intersection_ = resolution_set_.Intersection(
        ResolutionSet::FromConstraintSet(constraint_set));
    if (!result->rescale_intersection_.Contains(true)) {
      // If rescaling is not allowed, only the native resolution is allowed.
      result->resolution_intersection_ =
          result->resolution_intersection_.Intersection(
              ResolutionSet::FromExactResolution(NativeWidth(),
                                                 NativeHeight()));
    }
    if (result->resolution_intersection_.IsWidthEmpty()) {
      UpdateFailedConstraintName(constraint_set.width, failed_constraint_name);
      return std::nullopt;
    }
    if (result->resolution_intersection_.IsHeightEmpty()) {
      UpdateFailedConstraintName(constraint_set.height, failed_constraint_name);
      return std::nullopt;
    }
    if (result->resolution_intersection_.IsAspectRatioEmpty()) {
      UpdateFailedConstraintName(constraint_set.aspect_ratio,
                                 failed_constraint_name);
      return std::nullopt;
    }

    if (!SatisfiesFrameRateConstraint(constraint_set.frame_rate)) {
      UpdateFailedConstraintName(constraint_set.frame_rate,
                                 failed_constraint_name);
      return std::nullopt;
    }

    result->constrained_frame_rate_ = constrained_frame_rate_.Intersection(
        DoubleRangeSet::FromConstraint(constraint_set.frame_rate, 0.0,
                                       media::limits::kMaxFramesPerSecond));
    result->constrained_width_ =
        constrained_width_.Intersection(IntRangeSet::FromConstraint(
            constraint_set.width, 1L, ResolutionSet::kMaxDimension));
    result->constrained_height_ =
        constrained_height_.Intersection(IntRangeSet::FromConstraint(
            constraint_set.height, 1L, ResolutionSet::kMaxDimension));
    result->constrained_aspect_ratio_ =
        constrained_aspect_ratio_.Intersection(DoubleRangeSet::FromConstraint(
            constraint_set.aspect_ratio, 0.0, HUGE_VAL));

    return result;
  }

  void ApplyResult(const ApplyConstraintSetResult& result) {
    constrained_frame_rate_ = result.constrained_frame_rate_;
    constrained_width_ = result.constrained_width_;
    constrained_height_ = result.constrained_height_;
    constrained_aspect_ratio_ = result.constrained_aspect_ratio_;
    resolution_set_ = result.resolution_intersection_;
    rescale_set_ = result.rescale_intersection_;
  }

  // Returns the best fitness distance that can be achieved with this candidate
  // format based on distance from the ideal values in |basic_constraint_set|.
  // The track settings that correspond to this fitness are returned on the
  // |track_settings| output parameter. The fitness function is based on
  // https://w3c.github.io/mediacapture-main/#dfn-fitness-distance.
  double Fitness(const MediaTrackConstraintSetPlatform& basic_constraint_set,
                 VideoTrackAdapterSettings* track_settings) const {
    DCHECK(!rescale_set_.IsEmpty());
    double track_fitness_with_rescale = HUGE_VAL;
    VideoTrackAdapterSettings track_settings_with_rescale;
    if (rescale_set_.Contains(true)) {
      track_settings_with_rescale = SelectVideoTrackAdapterSettings(
          basic_constraint_set, resolution_set(), constrained_frame_rate(),
          format(), true /* enable_rescale */);
      DCHECK(track_settings_with_rescale.target_size().has_value());
      double target_aspect_ratio =
          static_cast<double>(track_settings_with_rescale.target_width()) /
          track_settings_with_rescale.target_height();
      DCHECK(!std::isnan(target_aspect_ratio));
      std::optional<double> best_supported_frame_rate =
          track_settings_with_rescale.max_frame_rate();
      if (!best_supported_frame_rate.has_value() ||
          *best_supported_frame_rate > NativeFrameRate()) {
        best_supported_frame_rate = NativeFrameRate();
      }

      track_fitness_with_rescale =
          NumericValueFitness(basic_constraint_set.aspect_ratio,
                              target_aspect_ratio) +
          NumericValueFitness(basic_constraint_set.height,
                              track_settings_with_rescale.target_height()) +
          NumericValueFitness(basic_constraint_set.width,
                              track_settings_with_rescale.target_width()) +
          NumericValueFitness(basic_constraint_set.frame_rate,
                              *best_supported_frame_rate);
    }

    double track_fitness_without_rescale = HUGE_VAL;
    VideoTrackAdapterSettings track_settings_without_rescale;
    if (rescale_set_.Contains(false)) {
      bool can_use_native_resolution =
          constrained_width_.Contains(NativeWidth()) &&
          constrained_height_.Contains(NativeHeight()) &&
          constrained_aspect_ratio_.Contains(NativeAspectRatio());
      if (can_use_native_resolution) {
        track_settings_without_rescale = SelectVideoTrackAdapterSettings(
            basic_constraint_set, resolution_set(), constrained_frame_rate(),
            format(), false /* enable_rescale */);
        DCHECK(!track_settings_without_rescale.target_size().has_value());
        std::optional<double> best_supported_frame_rate =
            track_settings_without_rescale.max_frame_rate();
        if (!best_supported_frame_rate.has_value() ||
            *best_supported_frame_rate > NativeFrameRate()) {
          best_supported_frame_rate = NativeFrameRate();
        }
        track_fitness_without_rescale =
            NumericValueFitness(basic_constraint_set.aspect_ratio,
                                NativeAspectRatio()) +
            NumericValueFitness(basic_constraint_set.height, NativeHeight()) +
            NumericValueFitness(basic_constraint_set.width, NativeWidth()) +
            NumericValueFitness(basic_constraint_set.frame_rate,
                                *best_supported_frame_rate);
      }
    }

    if (basic_constraint_set.resize_mode.HasIdeal()) {
      if (!base::Contains(basic_constraint_set.resize_mode.Ideal(),
                          WebMediaStreamTrack::kResizeModeNone)) {
        track_fitness_without_rescale += 1.0;
      }
      if (!base::Contains(basic_constraint_set.resize_mode.Ideal(),
                          WebMediaStreamTrack::kResizeModeRescale)) {
        track_fitness_with_rescale += 1.0;
      }
    }

    // If rescaling and not rescaling have the same fitness, prefer not
    // rescaling.
    if (track_fitness_without_rescale <= track_fitness_with_rescale) {
      *track_settings = track_settings_without_rescale;
      return track_fitness_without_rescale;
    }

    *track_settings = track_settings_with_rescale;
    return track_fitness_with_rescale;
  }

  // Returns a custom "native" fitness distance that expresses how close the
  // native settings of this format are to the ideal and allowed ranges for
  // the corresponding width, height and frameRate properties.
  // This distance is intended to be used to break ties among candidates that
  // are equally good according to the standard fitness distance.
  double NativeFitness(
      const MediaTrackConstraintSetPlatform& constraint_set) const {
    return NumericRangeNativeFitness(constraint_set.width, MinWidth(),
                                     MaxWidth(), NativeWidth()) +
           NumericRangeNativeFitness(constraint_set.height, MinHeight(),
                                     MaxHeight(), NativeHeight()) +
           NumericRangeNativeFitness(constraint_set.frame_rate, MinFrameRate(),
                                     MaxFrameRate(), NativeFrameRate());
  }

 private:
  bool SatisfiesFrameRateConstraint(const DoubleConstraint& constraint) const {
    double constraint_min =
        ConstraintHasMin(constraint) ? ConstraintMin(constraint) : -1.0;
    double constraint_max =
        ConstraintHasMax(constraint)
            ? ConstraintMax(constraint)
            : static_cast<double>(media::limits::kMaxFramesPerSecond);
    bool constraint_min_out_of_range =
        ((constraint_min > NativeFrameRate()) ||
         (constraint_min > MaxFrameRateConstraint().value_or(
                               media::limits::kMaxFramesPerSecond) +
                               DoubleConstraint::kConstraintEpsilon));
    bool constraint_max_out_of_range =
        ((constraint_max < kMinDeviceCaptureFrameRate) ||
         (constraint_max < MinFrameRateConstraint().value_or(0.0) -
                               DoubleConstraint::kConstraintEpsilon));
    bool constraint_self_contradicts = constraint_min > constraint_max;

    return !constraint_min_out_of_range && !constraint_max_out_of_range &&
           !constraint_self_contradicts;
  }

  // Native format for this candidate.
  media::VideoCaptureFormat format_;

  // Contains the set of allowed resolutions allowed by |format_| and subject
  // to applied constraints.
  ResolutionSet resolution_set_;

  // Contains the constrained range for the frameRate property, regardless
  // of what the native frame rate is. The intersection of this range and the
  // range [kMinDeviceCaptureFrameRate, NativeframeRate()] is the set of
  // frame rates supported by this candidate.
  DoubleRangeSet constrained_frame_rate_;
  IntRangeSet constrained_width_;
  IntRangeSet constrained_height_;
  DoubleRangeSet constrained_aspect_ratio_;

  // Contains the set of allowed rescale modes subject to applied constraints.
  BoolSet rescale_set_;
};

// Returns true if the facing mode |value| satisfies |constraints|, false
// otherwise.
bool FacingModeSatisfiesConstraint(mojom::blink::FacingMode value,
                                   const StringConstraint& constraint) {
  WebString string_value = ToWebString(value);
  if (string_value.IsNull()) {
    return constraint.Exact().empty();
  }

  return constraint.Matches(string_value);
}

class PTZDeviceState {
 public:
  explicit PTZDeviceState(const MediaTrackConstraintSetPlatform& constraint_set)
      : pan_set_(DoubleRangeSet::FromConstraint(constraint_set.pan)),
        tilt_set_(DoubleRangeSet::FromConstraint(constraint_set.tilt)),
        zoom_set_(DoubleRangeSet::FromConstraint(constraint_set.zoom)) {}

  PTZDeviceState(const DoubleRangeSet& pan_set,
                 const DoubleRangeSet& tilt_set,
                 const DoubleRangeSet& zoom_set)
      : pan_set_(pan_set), tilt_set_(tilt_set), zoom_set_(zoom_set) {}

  PTZDeviceState(const PTZDeviceState& other) = default;
  PTZDeviceState& operator=(const PTZDeviceState& other) = default;

  PTZDeviceState Intersection(
      const MediaTrackConstraintSetPlatform& constraint_set) const {
    DoubleRangeSet pan_intersection = pan_set_.Intersection(
        DoubleRangeSet::FromConstraint(constraint_set.pan));
    DoubleRangeSet tilt_intersection = tilt_set_.Intersection(
        DoubleRangeSet::FromConstraint(constraint_set.tilt));
    DoubleRangeSet zoom_intersection = zoom_set_.Intersection(
        DoubleRangeSet::FromConstraint(constraint_set.zoom));

    return PTZDeviceState(pan_intersection, tilt_intersection,
                          zoom_intersection);
  }

  bool IsEmpty() const {
    return pan_set_.IsEmpty() || tilt_set_.IsEmpty() || zoom_set_.IsEmpty();
  }

  double Fitness(
      const MediaTrackConstraintSetPlatform& basic_set,
      const media::VideoCaptureControlSupport& control_support) const {
    return NumericRangeSupportFitness(basic_set.pan, pan_set_,
                                      basic_set.pan.IsPresent(),
                                      control_support.pan) +
           NumericRangeSupportFitness(basic_set.tilt, tilt_set_,
                                      basic_set.tilt.IsPresent(),
                                      control_support.tilt) +
           NumericRangeSupportFitness(basic_set.zoom, zoom_set_,
                                      basic_set.zoom.IsPresent(),
                                      control_support.zoom);
  }

  const char* FailedConstraintName() const {
    MediaTrackConstraintSetPlatform dummy;
    if (pan_set_.IsEmpty()) {
      return dummy.pan.GetName();
    }
    if (tilt_set_.IsEmpty()) {
      return dummy.tilt.GetName();
    }
    if (zoom_set_.IsEmpty()) {
      return dummy.zoom.GetName();
    }

    // No failed constraint.
    return nullptr;
  }

  std::optional<double> SelectPan(
      const MediaTrackConstraintSetPlatform& basic_set) const {
    return SelectProperty(&PTZDeviceState::pan_set_, basic_set,
                          &MediaTrackConstraintSetPlatform::pan);
  }

  std::optional<double> SelectTilt(
      const MediaTrackConstraintSetPlatform& basic_set) const {
    return SelectProperty(&PTZDeviceState::tilt_set_, basic_set,
                          &MediaTrackConstraintSetPlatform::tilt);
  }

  std::optional<double> SelectZoom(
      const MediaTrackConstraintSetPlatform& basic_set) const {
    return SelectProperty(&PTZDeviceState::zoom_set_, basic_set,
                          &MediaTrackConstraintSetPlatform::zoom);
  }

 private:
  // Select the target value of a property based on the ideal value in
  // |basic_set| as follows:
  // If an ideal value is provided, return the value in the range closest to
  // ideal.
  // If no ideal value is provided:
  // * If minimum is provided, return minimum.
  // * Otherwise, if maximum is provided, return maximum.
  // * Otherwise, return nullopt.
  std::optional<double> SelectProperty(
      DoubleRangeSet PTZDeviceState::*ptz_field,
      const MediaTrackConstraintSetPlatform& basic_set,
      DoubleConstraint MediaTrackConstraintSetPlatform::*basic_set_field)
      const {
    if (!(basic_set.*basic_set_field).HasIdeal()) {
      return (this->*ptz_field).Min().has_value() ? (this->*ptz_field).Min()
                                                  : (this->*ptz_field).Max();
    }

    auto ideal = (basic_set.*basic_set_field).Ideal();
    if ((this->*ptz_field).Min().has_value() &&
        ideal < (this->*ptz_field).Min().value()) {
      return (this->*ptz_field).Min();
    }
    if ((this->*ptz_field).Max().has_value() &&
        ideal > (this->*ptz_field).Max().value()) {
      return (this->*ptz_field).Max();
    }

    return ideal;
  }

  DoubleRangeSet pan_set_;
  DoubleRangeSet tilt_set_;
  DoubleRangeSet zoom_set_;
};

class ImageCaptureDeviceState {
 public:
  class ApplyConstraintSetResult {
   public:
    ApplyConstraintSetResult() = default;

   private:
    friend class ImageCaptureDeviceState;

    std::optional<DoubleRangeSet> exposure_compensation_intersection_;
    std::optional<DoubleRangeSet> exposure_time_intersection_;
    std::optional<DoubleRangeSet> color_temperature_intersection_;
    std::optional<DoubleRangeSet> iso_intersection_;
    std::optional<DoubleRangeSet> brightness_intersection_;
    std::optional<DoubleRangeSet> contrast_intersection_;
    std::optional<DoubleRangeSet> saturation_intersection_;
    std::optional<DoubleRangeSet> sharpness_intersection_;
    std::optional<DoubleRangeSet> focus_distance_intersection_;
    std::optional<BoolSet> torch_intersection_;
    std::optional<BoolSet> background_blur_intersection_;
    std::optional<BoolSet> background_segmentation_mask_intersection_;
    std::optional<BoolSet> eye_gaze_correction_intersection_;
    std::optional<BoolSet> face_framing_intersection_;
  };

  explicit ImageCaptureDeviceState(const DeviceInfo& device) {}

  std::optional<ApplyConstraintSetResult> TryToApplyConstraintSet(
      const MediaTrackConstraintSetPlatform& constraint_set,
      const char** failed_constraint_name = nullptr) const {
    std::optional<ApplyConstraintSetResult> result(std::in_place);

    if (!(TryToApplyConstraint(constraint_set.exposure_compensation,
                               exposure_compensation_set_,
                               result->exposure_compensation_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.exposure_time, exposure_time_set_,
                               result->exposure_time_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.color_temperature,
                               color_temperature_set_,
                               result->color_temperature_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.iso, iso_set_,
                               result->iso_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.brightness, brightness_set_,
                               result->brightness_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.contrast, contrast_set_,
                               result->contrast_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.saturation, saturation_set_,
                               result->saturation_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.sharpness, sharpness_set_,
                               result->sharpness_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(
              constraint_set.focus_distance, focus_distance_set_,
              result->focus_distance_intersection_, failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.torch, torch_set_,
                               result->torch_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(
              constraint_set.background_blur, background_blur_set_,
              result->background_blur_intersection_, failed_constraint_name) &&
          TryToApplyConstraint(
              constraint_set.background_segmentation_mask,
              background_segmentation_mask_set_,
              result->background_segmentation_mask_intersection_,
              failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.eye_gaze_correction,
                               eye_gaze_correction_set_,
                               result->eye_gaze_correction_intersection_,
                               failed_constraint_name) &&
          TryToApplyConstraint(constraint_set.face_framing, face_framing_set_,
                               result->face_framing_intersection_,
                               failed_constraint_name))) {
      result.reset();
    }

    return result;
  }

  void ApplyResult(const ApplyConstraintSetResult& result) {
    if (result.exposure_compensation_intersection_.has_value()) {
      exposure_compensation_set_ = *result.exposure_compensation_intersection_;
    }
    if (result.exposure_time_intersection_.has_value()) {
      exposure_time_set_ = *result.exposure_time_intersection_;
    }
    if (result.color_temperature_intersection_.has_value()) {
      color_temperature_set_ = *result.color_temperature_intersection_;
    }
    if (result.iso_intersection_.has_value()) {
      iso_set_ = *result.iso_intersection_;
    }
    if (result.brightness_intersection_.has_value()) {
      brightness_set_ = *result.brightness_intersection_;
    }
    if (result.contrast_intersection_.has_value()) {
      contrast_set_ = *result.contrast_intersection_;
    }
    if (result.saturation_intersection_.has_value()) {
      saturation_set_ = *result.saturation_intersection_;
    }
    if (result.sharpness_intersection_.has_value()) {
      sharpness_set_ = *result.sharpness_intersection_;
    }
    if (result.focus_distance_intersection_.has_value()) {
      focus_distance_set_ = *result.focus_distance_intersection_;
    }
    if (result.torch_intersection_.has_value()) {
      torch_set_ = *result.torch_intersection_;
    }
    if (result.background_blur_intersection_.has_value()) {
      background_blur_set_ = *result.background_blur_intersection_;
    }
    if (result.background_segmentation_mask_intersection_.has_value()) {
      background_segmentation_mask_set_ =
          *result.background_segmentation_mask_intersection_;
    }
    if (result.eye_gaze_correction_intersection_.has_value()) {
      eye_gaze_correction_set_ = *result.eye_gaze_correction_intersection_;
    }
    if (result.face_framing_intersection_.has_value()) {
      face_framing_set_ = *result.face_framing_intersection_;
    }
  }

  double Fitness(
      const MediaTrackConstraintSetPlatform& basic_constraint_set) const {
    return NumericRangeSetFitness(basic_constraint_set.exposure_compensation,
                                  exposure_compensation_set_) +
           NumericRangeSetFitness(basic_constraint_set.exposure_time,
                                  exposure_time_set_) +
           NumericRangeSetFitness(basic_constraint_set.color_temperature,
                                  color_temperature_set_) +
           NumericRangeSetFitness(basic_constraint_set.iso, iso_set_) +
           NumericRangeSetFitness(basic_constraint_set.brightness,
                                  brightness_set_) +
           NumericRangeSetFitness(basic_constraint_set.contrast,
                                  contrast_set_) +
           NumericRangeSetF
```