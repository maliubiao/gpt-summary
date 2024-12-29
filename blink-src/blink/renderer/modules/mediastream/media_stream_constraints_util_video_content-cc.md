Response:
Let's break down the thought process for analyzing this C++ code snippet and fulfilling the request.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided C++ file (`media_stream_constraints_util_video_content.cc`) within the Chromium Blink engine. We also need to relate it to web technologies (JavaScript, HTML, CSS), consider logical reasoning, identify common errors, and trace user actions.

2. **Initial Code Scan and Identification of Key Areas:**  A quick scan reveals several important aspects:
    * **Header Inclusion:**  Standard headers (`algorithm`, `cmath`, `utility`) and Blink-specific headers related to `mediastream`. This immediately suggests it's part of the WebRTC or media streaming functionality.
    * **Constants:**  Definitions like `kMinScreenCastDimension`, `kMaxScreenCastDimension`, `kDefaultScreenCastWidth`, etc., point to constraints and default values for screen capture.
    * **Namespaces:** The `blink` namespace confirms it's within the Blink rendering engine.
    * **`VideoContentCaptureCandidates` Class:** This class appears central, holding information about potential video capture configurations based on constraints.
    * **Functions with `Select...`:**  Functions like `SelectResolutionPolicyFromCandidates`, `SelectFrameRateFromCandidates`, `SelectVideoCaptureParamsFromCandidates`, etc., strongly suggest this code is responsible for selecting optimal video capture settings based on provided constraints.
    * **`SelectSettingsVideoContentCapture` Function:** This seems like the main entry point for the logic.
    * **`UnsatisfiedConstraintsResult` Function:** This hints at handling cases where user-defined constraints cannot be met.

3. **Deciphering the Core Functionality:** By examining the `VideoContentCaptureCandidates` class and the `Select...` functions, the core functionality becomes clear:
    * **Constraint Parsing:** The code takes `MediaTrackConstraintSetPlatform` objects (which represent user-defined constraints) and parses them into sets of possible values (resolutions, frame rates, etc.).
    * **Intersection Logic:** The `Intersection` method of `VideoContentCaptureCandidates` suggests that the code combines multiple constraint sets to find a common ground. This is a key aspect of how WebRTC constraints work (basic and advanced constraints).
    * **Selection Algorithm:** The `Select...` functions implement logic to choose the "best" video capture parameters from the allowed sets, potentially considering "ideal" values.
    * **Default Values:** Constants like `kDefaultScreenCastWidth` and `kDefaultScreenCastFrameRate` are used when constraints don't fully specify the desired parameters.

4. **Relating to JavaScript, HTML, CSS:** This requires understanding how web developers interact with media streams:
    * **`getUserMedia()` API:** This is the primary entry point in JavaScript for accessing media devices, including screen capture. Constraints are passed to `getUserMedia()`.
    * **Constraints Object:**  The JavaScript constraints object maps directly to the C++ `MediaTrackConstraintSetPlatform`. Examples of width, height, frameRate, deviceId constraints can be readily constructed.
    * **HTML `<video>` Element:** The captured video stream is often displayed in a `<video>` element. CSS might be used to style this element, but the *constraint logic itself* isn't directly influenced by CSS.

5. **Logical Reasoning (Input/Output):**  To illustrate the logic, we need to consider example constraints and how the code would process them:
    * **Simple Case:** A constraint like `{ video: { width: 1280 } }` would lead to the selection of a width close to 1280, respecting the maximum and minimum limits.
    * **Conflicting Constraints:**  Constraints like `{ video: { width: { min: 1920 }, width: { max: 640 } } }` would result in unsatisfied constraints.
    * **"Ideal" vs. "Exact":** Demonstrating how `ideal` and exact constraints are handled by the selection logic is important.

6. **Common User Errors:**  This involves thinking about typical mistakes developers make when using the `getUserMedia()` API:
    * **Incorrect Constraint Syntax:**  Typos in constraint names or incorrect value types.
    * **Conflicting Constraints:**  Setting `min` greater than `max`.
    * **Unrealistic Constraints:** Requesting extremely high resolutions or frame rates that the system cannot provide.
    * **Permissions Issues:** Although not directly related to this code, it's a common source of error when accessing media devices.

7. **Tracing User Actions (Debugging):** This requires simulating the steps a user takes to initiate screen capture and how that leads to this specific code:
    * **User clicks a button.**
    * **JavaScript calls `navigator.mediaDevices.getDisplayMedia()` (for screen capture) or `navigator.mediaDevices.getUserMedia()` with screen capture options.**
    * **The browser processes the constraints.**
    * **Blink (the rendering engine) receives the request and invokes the relevant C++ code, including the file in question.**

8. **Structuring the Answer:**  Finally, the information needs to be organized logically, starting with the high-level functionality and then delving into details, examples, and connections to web technologies. Using headings and bullet points helps improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Might focus too heavily on specific implementation details within the C++ code. **Correction:** Shift focus to the *purpose* and *impact* of the code within the larger context of WebRTC and web development.
* **Realization:** The difference between `getUserMedia` and `getDisplayMedia` is important for the "User Actions" section. **Correction:**  Include both scenarios.
* **Consideration:**  Should I explain the intricacies of `MediaTrackConstraintSetPlatform`? **Decision:**  Keep it high-level, explaining its role as a representation of user constraints. Avoid getting bogged down in the internal structure of this class.
* **Review:** After drafting the answer, review it for clarity, accuracy, and completeness. Ensure that all aspects of the prompt have been addressed.
这个文件 `media_stream_constraints_util_video_content.cc` 是 Chromium Blink 引擎中负责处理视频内容捕获（例如屏幕共享、标签页共享）时，对用户指定的媒体约束进行解析、验证和选择最佳配置的核心组件。它位于 `blink/renderer/modules/mediastream` 目录下，表明它属于 WebRTC 和 MediaStream API 的实现部分。

**主要功能：**

1. **解析和存储视频内容捕获的约束:**
   - 它定义了 `VideoContentCaptureCandidates` 类，用于存储和操作从 JavaScript 传递过来的视频轨道约束（例如 `width`, `height`, `frameRate`, `deviceId` 等）。
   - 它使用 `media_constraints` 命名空间下的工具类（如 `ResolutionSet`, `NumericRangeSet`, `DiscreteSet`）来更方便地表示和操作各种类型的约束值（例如，宽度可以是具体的数值，也可以是一个范围）。

2. **定义屏幕共享的默认和限制值:**
   - 文件中定义了诸如 `kMinScreenCastDimension`, `kMaxScreenCastDimension`, `kDefaultScreenCastWidth`, `kDefaultScreenCastHeight`, `kMaxScreenCastFrameRate` 等常量，这些常量规定了屏幕共享的最小/最大尺寸、默认尺寸和最大帧率。

3. **计算和选择最佳的视频捕获参数:**
   - `SelectSettingsVideoContentCapture` 函数是该文件的核心入口点。它接收用户指定的约束、媒体流类型（例如屏幕共享或标签页共享）以及屏幕的宽高信息。
   - 它通过 `VideoContentCaptureCandidates` 类来表示可能的候选配置，并根据用户约束与系统能力进行交集运算，找出满足所有约束的配置。
   - 它实现了选择分辨率、帧率、设备 ID、降噪选项和缩放模式等参数的逻辑。
   - 例如，`SelectResolutionPolicyFromCandidates` 函数会根据用户指定的分辨率范围来确定是否允许在捕获过程中动态调整分辨率。
   - `SelectVideoCaptureParamsFromCandidates` 函数会根据候选配置和基本约束选择最接近理想值的分辨率和帧率。

4. **处理不满足约束的情况:**
   - `UnsatisfiedConstraintsResult` 函数用于处理当用户指定的约束无法被满足时的情况，并返回相应的错误信息，指示哪个约束无法满足。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接服务于 JavaScript 的 `navigator.mediaDevices.getDisplayMedia()` API 以及 `getUserMedia()` API 在捕获屏幕或标签页时的行为。

**JavaScript:**

```javascript
navigator.mediaDevices.getDisplayMedia({
  video: {
    width: { min: 640, ideal: 1280, max: 1920 },
    height: { min: 480, ideal: 720, max: 1080 },
    frameRate: { ideal: 30, max: 60 }
  },
  audio: false
})
.then(stream => {
  // 使用 stream
})
.catch(error => {
  // 处理错误，例如 ConstraintNotSatisfiedError
});
```

在这个例子中，JavaScript 代码通过 `getDisplayMedia` 请求一个视频流，并指定了 `width`, `height`, 和 `frameRate` 的约束。`media_stream_constraints_util_video_content.cc` 文件的代码会被调用来解析这些约束，并在可用的屏幕捕获能力范围内选择最合适的参数。

**HTML:**

HTML 中通常会使用 `<video>` 元素来显示捕获到的视频流。但是，`media_stream_constraints_util_video_content.cc` 的功能并不直接操作 HTML 元素。它负责在捕获 *之前*  确定视频流的参数。

**CSS:**

CSS 用于样式化网页元素，包括 `<video>` 元素。同样，这个 C++ 文件与 CSS 没有直接的交互。CSS 作用于视频流被捕获并显示 *之后* 的外观。

**逻辑推理（假设输入与输出）：**

**假设输入：**

- `constraints.Basic()`:  `{ width: { min: 1000 }, height: { ideal: 720 } }`
- `stream_type`: `mojom::MediaStreamType::GUM_TAB_VIDEO_CAPTURE` (标签页共享)
- `screen_width`: 1920
- `screen_height`: 1080

**逻辑推理过程：**

1. **创建 `VideoContentCaptureCandidates`:** 基于基本约束创建一个候选对象。
2. **与默认能力交集:**  将用户约束与屏幕共享的默认能力（例如最大尺寸）进行交集。例如，如果用户请求的最小宽度是 1000，且小于 `kMaxScreenCastDimension`，则保留。
3. **处理理想值:** `height` 的 `ideal` 值为 720，代码会尝试选择接近 720 的高度。
4. **选择最佳分辨率:**  在满足最小宽度 1000 的前提下，选择最接近理想高度 720 的分辨率。由于是标签页共享，默认的分辨率策略可能是 `FIXED_RESOLUTION`。
5. **选择其他参数:** 可能会使用默认的帧率，除非用户有明确指定。

**可能的输出 (VideoCaptureSettings):**

- `device_id`:  (可能是空字符串，表示默认设备)
- `capture_params.requested_format.frame_rate`:  `kDefaultScreenCastFrameRate` 或用户指定的其他值
- `capture_params.requested_format.video_size`:  `gfx::Size(1000, 720)` (假设系统能提供此分辨率，且 720 是最接近的可用高度)
- `capture_params.resolution_change_policy`: `media::ResolutionChangePolicy::FIXED_RESOLUTION`
- `noise_reduction`:  (默认值或用户指定的值)
- `track_adapter_settings`: (根据约束和捕获参数生成的适配器设置)

**涉及用户或编程常见的使用错误：**

1. **指定超出范围的约束:**
   - **错误示例（JavaScript）:**
     ```javascript
     navigator.mediaDevices.getDisplayMedia({ video: { width: 10000 } });
     ```
   - **结果:** `media_stream_constraints_util_video_content.cc` 会检测到宽度超出了 `kMaxScreenCastDimension`，导致约束无法满足，并可能抛出 `ConstraintNotSatisfiedError`。

2. **指定冲突的约束:**
   - **错误示例（JavaScript）:**
     ```javascript
     navigator.mediaDevices.getDisplayMedia({ video: { width: { min: 1280, max: 640 } } });
     ```
   - **结果:** `media_stream_constraints_util_video_content.cc` 中的 `Intersection` 操作会发现 `min` 大于 `max`，导致 `resolution_set` 为空，最终 `UnsatisfiedConstraintsResult` 会返回宽度约束不满足的信息。

3. **忘记处理 `ConstraintNotSatisfiedError`:**
   - **错误示例（JavaScript）:** 没有在 `getDisplayMedia` 的 `catch` 块中处理错误。
   - **结果:** 当约束无法满足时，程序可能会崩溃或行为异常，用户体验不佳。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户操作触发 JavaScript 代码:** 用户点击网页上的一个按钮，或执行了某个操作，导致 JavaScript 代码被执行。
2. **JavaScript 调用 `navigator.mediaDevices.getDisplayMedia()` 或 `getUserMedia()`:**  这个调用是请求访问用户的媒体设备（在这里是屏幕或标签页）。
3. **传递约束对象:** 在 `getDisplayMedia()` 或 `getUserMedia()` 的参数中，包含了 `video` 约束对象，描述了用户希望的视频流特性。
4. **浏览器进程处理请求:** 浏览器的主进程接收到这个媒体请求。
5. **Blink 渲染引擎介入:**  对于网页的媒体请求，Blink 渲染引擎负责处理，包括约束的解析和设备的选择。
6. **调用 `SelectSettingsVideoContentCapture`:**  Blink 会调用 `media_stream_constraints_util_video_content.cc` 中的 `SelectSettingsVideoContentCapture` 函数，将 JavaScript 传递的约束、媒体流类型和屏幕信息作为参数传入。
7. **约束解析和参数选择:**  `SelectSettingsVideoContentCapture` 及其调用的其他函数会解析约束，与系统能力进行比较，并选择最佳的视频捕获参数。
8. **返回结果:** 选择好的参数会被传递回浏览器进程，最终用于配置底层的媒体捕获管道。
9. **捕获媒体流:**  根据选择的参数，浏览器开始捕获屏幕或标签页的视频。
10. **媒体流返回给 JavaScript:** 捕获到的媒体流作为 `Promise` 的 resolved 值返回给 JavaScript 代码。

**调试线索：**

- 如果用户报告屏幕共享或标签页共享无法正常工作，或者视频尺寸、帧率不符合预期，可以检查用户在 JavaScript 中设置的约束是否合理。
- 可以通过 Chromium 的内部日志（`chrome://webrtc-internals`）查看媒体协商的详细过程，包括约束信息和最终选择的参数。
- 在 `media_stream_constraints_util_video_content.cc` 中添加日志输出，可以跟踪约束解析和参数选择的流程，帮助定位问题。
- 检查浏览器版本和操作系统，因为不同的环境可能对屏幕共享的能力有不同的限制。

总而言之，`media_stream_constraints_util_video_content.cc` 是 Blink 引擎中处理视频内容捕获约束的关键部分，它连接了 JavaScript API 和底层的媒体捕获实现，确保用户指定的期望能够尽可能地被满足，并处理各种错误情况。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.h"

#include <algorithm>
#include <cmath>
#include <utility>

#include "base/feature_list.h"
#include "media/base/limits.h"
#include "media/base/video_types.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/mediastream/media_stream_controls.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"

namespace blink {

const int kMinScreenCastDimension = 1;
// Use kMaxDimension/2 as maximum to ensure selected resolutions have area less
// than media::limits::kMaxCanvas.
const int kMaxScreenCastDimension = media::limits::kMaxDimension / 2;
static_assert(kMaxScreenCastDimension * kMaxScreenCastDimension <
                  media::limits::kMaxCanvas,
              "Invalid kMaxScreenCastDimension");

const int kDefaultScreenCastWidth = 2880;
const int kDefaultScreenCastHeight = 1800;
static_assert(kDefaultScreenCastWidth <= kMaxScreenCastDimension,
              "Invalid kDefaultScreenCastWidth");
static_assert(kDefaultScreenCastHeight <= kMaxScreenCastDimension,
              "Invalid kDefaultScreenCastHeight");

const double kMaxScreenCastFrameRate = 120.0;
const double kDefaultScreenCastFrameRate =
    MediaStreamVideoSource::kDefaultFrameRate;

namespace {

using ResolutionSet = media_constraints::ResolutionSet;
using Point = ResolutionSet::Point;
using StringSet = media_constraints::DiscreteSet<std::string>;
using BoolSet = media_constraints::DiscreteSet<bool>;
using DoubleRangeSet = media_constraints::NumericRangeSet<double>;

constexpr double kMinScreenCastAspectRatio =
    static_cast<double>(kMinScreenCastDimension) /
    static_cast<double>(kMaxScreenCastDimension);
constexpr double kMaxScreenCastAspectRatio =
    static_cast<double>(kMaxScreenCastDimension) /
    static_cast<double>(kMinScreenCastDimension);

class VideoContentCaptureCandidates {
 public:
  VideoContentCaptureCandidates()
      : has_explicit_max_height_(false), has_explicit_max_width_(false) {}
  explicit VideoContentCaptureCandidates(
      const MediaTrackConstraintSetPlatform& constraint_set)
      : resolution_set_(ResolutionSet::FromConstraintSet(constraint_set)),
        has_explicit_max_height_(ConstraintHasMax(constraint_set.height) &&
                                 ConstraintMax(constraint_set.height) <=
                                     kMaxScreenCastDimension),
        has_explicit_max_width_(ConstraintHasMax(constraint_set.width) &&
                                ConstraintMax(constraint_set.width) <=
                                    kMaxScreenCastDimension),
        frame_rate_set_(
            DoubleRangeSet::FromConstraint(constraint_set.frame_rate,
                                           0.0,
                                           kMaxScreenCastFrameRate)),
        device_id_set_(media_constraints::StringSetFromConstraint(
            constraint_set.device_id)),
        noise_reduction_set_(media_constraints::BoolSetFromConstraint(
            constraint_set.goog_noise_reduction)),
        rescale_set_(media_constraints::RescaleSetFromConstraint(
            constraint_set.resize_mode)) {}

  VideoContentCaptureCandidates(VideoContentCaptureCandidates&& other) =
      default;
  VideoContentCaptureCandidates& operator=(
      VideoContentCaptureCandidates&& other) = default;

  bool IsEmpty() const {
    return resolution_set_.IsEmpty() || frame_rate_set_.IsEmpty() ||
           (frame_rate_set_.Max().has_value() &&
            frame_rate_set_.Max().value() <= 0.0) ||
           device_id_set_.IsEmpty() || noise_reduction_set_.IsEmpty() ||
           rescale_set_.IsEmpty();
  }

  VideoContentCaptureCandidates Intersection(
      const VideoContentCaptureCandidates& other) {
    VideoContentCaptureCandidates intersection;
    intersection.resolution_set_ =
        resolution_set_.Intersection(other.resolution_set_);
    intersection.has_explicit_max_height_ =
        has_explicit_max_height_ || other.has_explicit_max_height_;
    intersection.has_explicit_max_width_ =
        has_explicit_max_width_ || other.has_explicit_max_width_;
    intersection.frame_rate_set_ =
        frame_rate_set_.Intersection(other.frame_rate_set_);
    intersection.device_id_set_ =
        device_id_set_.Intersection(other.device_id_set_);
    intersection.noise_reduction_set_ =
        noise_reduction_set_.Intersection(other.noise_reduction_set_);
    intersection.rescale_set_ = rescale_set_.Intersection(other.rescale_set_);
    return intersection;
  }

  const ResolutionSet& resolution_set() const { return resolution_set_; }
  bool has_explicit_max_height() const { return has_explicit_max_height_; }
  bool has_explicit_max_width() const { return has_explicit_max_width_; }
  const DoubleRangeSet& frame_rate_set() const { return frame_rate_set_; }
  const StringSet& device_id_set() const { return device_id_set_; }
  const BoolSet& noise_reduction_set() const { return noise_reduction_set_; }
  const BoolSet& rescale_set() const { return rescale_set_; }
  void set_resolution_set(const ResolutionSet& set) { resolution_set_ = set; }
  void set_frame_rate_set(const DoubleRangeSet& set) { frame_rate_set_ = set; }

 private:
  ResolutionSet resolution_set_;
  bool has_explicit_max_height_;
  bool has_explicit_max_width_;
  DoubleRangeSet frame_rate_set_;
  StringSet device_id_set_;
  BoolSet noise_reduction_set_;
  BoolSet rescale_set_;
};

ResolutionSet ScreenCastResolutionCapabilities() {
  return ResolutionSet(kMinScreenCastDimension, kMaxScreenCastDimension,
                       kMinScreenCastDimension, kMaxScreenCastDimension,
                       kMinScreenCastAspectRatio, kMaxScreenCastAspectRatio);
}

// This algorithm for selecting policy matches the old non-spec compliant
// algorithm in order to be more compatible with existing applications.
// TODO(guidou): Update this algorithm to properly take into account the minimum
// width and height, and the aspect_ratio constraint once most existing
// applications migrate to the new syntax. See https://crbug.com/701302.
media::ResolutionChangePolicy SelectResolutionPolicyFromCandidates(
    const ResolutionSet& resolution_set,
    media::ResolutionChangePolicy default_policy) {
  if (resolution_set.max_height() < kMaxScreenCastDimension &&
      resolution_set.max_width() < kMaxScreenCastDimension &&
      resolution_set.min_height() > kMinScreenCastDimension &&
      resolution_set.min_width() > kMinScreenCastDimension) {
    if (resolution_set.min_height() == resolution_set.max_height() &&
        resolution_set.min_width() == resolution_set.max_width()) {
      return media::ResolutionChangePolicy::FIXED_RESOLUTION;
    }

    int approx_aspect_ratio_min_resolution =
        100 * resolution_set.min_width() / resolution_set.min_height();
    int approx_aspect_ratio_max_resolution =
        100 * resolution_set.max_width() / resolution_set.max_height();
    if (approx_aspect_ratio_min_resolution ==
        approx_aspect_ratio_max_resolution) {
      return media::ResolutionChangePolicy::FIXED_ASPECT_RATIO;
    }

    return media::ResolutionChangePolicy::ANY_WITHIN_LIMIT;
  }

  return default_policy;
}

int RoundToInt(double d) {
  return static_cast<int>(std::round(d));
}

gfx::Size ToGfxSize(const Point& point) {
  return gfx::Size(RoundToInt(point.width()), RoundToInt(point.height()));
}

double SelectFrameRateFromCandidates(
    const DoubleRangeSet& candidate_set,
    const MediaTrackConstraintSetPlatform& basic_constraint_set,
    double default_frame_rate) {
  double frame_rate = basic_constraint_set.frame_rate.HasIdeal()
                          ? basic_constraint_set.frame_rate.Ideal()
                          : default_frame_rate;
  if (candidate_set.Max() && frame_rate > *candidate_set.Max())
    frame_rate = *candidate_set.Max();
  else if (candidate_set.Min() && frame_rate < *candidate_set.Min())
    frame_rate = *candidate_set.Min();

  return frame_rate;
}

media::VideoCaptureParams SelectVideoCaptureParamsFromCandidates(
    const VideoContentCaptureCandidates& candidates,
    const MediaTrackConstraintSetPlatform& basic_constraint_set,
    int default_height,
    int default_width,
    double default_frame_rate,
    media::ResolutionChangePolicy default_resolution_policy) {
  double requested_frame_rate = SelectFrameRateFromCandidates(
      candidates.frame_rate_set(), basic_constraint_set, default_frame_rate);
  Point requested_resolution =
      candidates.resolution_set().SelectClosestPointToIdeal(
          basic_constraint_set, default_height, default_width);
  media::VideoCaptureParams params;
  // If zero-copy tab capture is enabled, we want the capturer to auto-select
  // the pixel format:
  const media::VideoPixelFormat pixel_format =
      base::FeatureList::IsEnabled(blink::features::kZeroCopyTabCapture)
          ? media::PIXEL_FORMAT_UNKNOWN
          : media::PIXEL_FORMAT_I420;
  params.requested_format = media::VideoCaptureFormat(
      ToGfxSize(requested_resolution), static_cast<float>(requested_frame_rate),
      pixel_format);
  params.resolution_change_policy = SelectResolutionPolicyFromCandidates(
      candidates.resolution_set(), default_resolution_policy);
  // Content capture always uses default power-line frequency.
  DCHECK(params.IsValid());

  return params;
}

std::string SelectDeviceIDFromCandidates(
    const StringSet& candidates,
    const MediaTrackConstraintSetPlatform& basic_constraint_set) {
  DCHECK(!candidates.IsEmpty());
  if (basic_constraint_set.device_id.HasIdeal()) {
    // If there are multiple elements specified by ideal, break ties by choosing
    // the first one that satisfies the constraints.
    for (const auto& ideal_entry : basic_constraint_set.device_id.Ideal()) {
      std::string ideal_value = ideal_entry.Ascii();
      if (candidates.Contains(ideal_value)) {
        return ideal_value;
      }
    }
  }

  // Return the empty string if nothing is specified in the constraints.
  // The empty string is treated as a default device ID by the browser.
  if (candidates.is_universal()) {
    return std::string();
  }

  // If there are multiple elements that satisfy the constraints, break ties by
  // using the element that was specified first.
  return candidates.FirstElement();
}

std::optional<bool> SelectNoiseReductionFromCandidates(
    const BoolSet& candidates,
    const MediaTrackConstraintSetPlatform& basic_constraint_set) {
  DCHECK(!candidates.IsEmpty());
  if (basic_constraint_set.goog_noise_reduction.HasIdeal() &&
      candidates.Contains(basic_constraint_set.goog_noise_reduction.Ideal())) {
    return std::optional<bool>(
        basic_constraint_set.goog_noise_reduction.Ideal());
  }

  if (candidates.is_universal())
    return std::optional<bool>();

  // A non-universal BoolSet can have at most one element.
  return std::optional<bool>(candidates.FirstElement());
}

bool SelectRescaleFromCandidates(
    const BoolSet& candidates,
    const MediaTrackConstraintSetPlatform& basic_constraint_set) {
  DCHECK(!candidates.IsEmpty());
  if (basic_constraint_set.resize_mode.HasIdeal()) {
    for (const auto& ideal_resize_value :
         basic_constraint_set.resize_mode.Ideal()) {
      if (ideal_resize_value == WebMediaStreamTrack::kResizeModeNone &&
          candidates.Contains(false)) {
        return false;
      } else if (ideal_resize_value ==
                     WebMediaStreamTrack::kResizeModeRescale &&
                 candidates.Contains(true)) {
        return true;
      }
    }
  }

  DCHECK(!candidates.HasExplicitElements() ||
         candidates.elements().size() == 1);
  // Rescaling is the default for content capture.
  return candidates.HasExplicitElements() ? candidates.FirstElement() : true;
}

int ClampToValidScreenCastDimension(int value) {
  if (value > kMaxScreenCastDimension)
    return kMaxScreenCastDimension;
  else if (value < kMinScreenCastDimension)
    return kMinScreenCastDimension;
  return value;
}

VideoCaptureSettings SelectResultFromCandidates(
    const VideoContentCaptureCandidates& candidates,
    const MediaTrackConstraintSetPlatform& basic_constraint_set,
    mojom::MediaStreamType stream_type,
    int screen_width,
    int screen_height) {
  std::string device_id = SelectDeviceIDFromCandidates(
      candidates.device_id_set(), basic_constraint_set);
  // If a maximum width or height is explicitly given, use them as default.
  // If only one of them is given, use the default aspect ratio to determine the
  // other default value.
  int default_width = screen_width;
  int default_height = screen_height;
  double default_aspect_ratio =
      static_cast<double>(default_width) / default_height;
  if (candidates.has_explicit_max_height() &&
      candidates.has_explicit_max_width()) {
    default_height = candidates.resolution_set().max_height();
    default_width = candidates.resolution_set().max_width();
  } else if (candidates.has_explicit_max_height()) {
    default_height = candidates.resolution_set().max_height();
    default_width =
        static_cast<int>(std::round(default_height * default_aspect_ratio));
  } else if (candidates.has_explicit_max_width()) {
    default_width = candidates.resolution_set().max_width();
    default_height =
        static_cast<int>(std::round(default_width / default_aspect_ratio));
  }
  // When the given maximum values are large, the computed values using default
  // aspect ratio may fall out of range. Ensure the defaults are in the valid
  // range.
  default_height = ClampToValidScreenCastDimension(default_height);
  default_width = ClampToValidScreenCastDimension(default_width);

  // If a maximum frame rate is explicitly given, use it as default for
  // better compatibility with the old constraints algorithm.
  // TODO(guidou): Use the actual default when applications migrate to the new
  // constraint syntax.  https://crbug.com/710800
  double default_frame_rate =
      candidates.frame_rate_set().Max().value_or(kDefaultScreenCastFrameRate);

  // This default comes from the old algorithm.
  media::ResolutionChangePolicy default_resolution_policy =
      stream_type == mojom::MediaStreamType::GUM_TAB_VIDEO_CAPTURE
          ? media::ResolutionChangePolicy::FIXED_RESOLUTION
          : media::ResolutionChangePolicy::ANY_WITHIN_LIMIT;

  media::VideoCaptureParams capture_params =
      SelectVideoCaptureParamsFromCandidates(
          candidates, basic_constraint_set, default_height, default_width,
          default_frame_rate, default_resolution_policy);

  std::optional<bool> noise_reduction = SelectNoiseReductionFromCandidates(
      candidates.noise_reduction_set(), basic_constraint_set);

  bool enable_rescale = SelectRescaleFromCandidates(candidates.rescale_set(),
                                                    basic_constraint_set);

  auto track_adapter_settings = SelectVideoTrackAdapterSettings(
      basic_constraint_set, candidates.resolution_set(),
      candidates.frame_rate_set(), capture_params.requested_format,
      enable_rescale);

  return VideoCaptureSettings(std::move(device_id), capture_params,
                              noise_reduction, track_adapter_settings,
                              candidates.frame_rate_set().Min(),
                              candidates.frame_rate_set().Max());
}

VideoCaptureSettings UnsatisfiedConstraintsResult(
    const VideoContentCaptureCandidates& candidates,
    const MediaTrackConstraintSetPlatform& constraint_set) {
  DCHECK(candidates.IsEmpty());
  if (candidates.resolution_set().IsHeightEmpty()) {
    return VideoCaptureSettings(constraint_set.height.GetName());
  } else if (candidates.resolution_set().IsWidthEmpty()) {
    return VideoCaptureSettings(constraint_set.width.GetName());
  } else if (candidates.resolution_set().IsAspectRatioEmpty()) {
    return VideoCaptureSettings(constraint_set.aspect_ratio.GetName());
  } else if (candidates.frame_rate_set().IsEmpty() ||
             (candidates.frame_rate_set().Max().has_value() &&
              candidates.frame_rate_set().Max().value() <= 0)) {
    return VideoCaptureSettings(constraint_set.frame_rate.GetName());
  } else if (candidates.noise_reduction_set().IsEmpty()) {
    return VideoCaptureSettings(constraint_set.goog_noise_reduction.GetName());
  } else if (candidates.rescale_set().IsEmpty()) {
    return VideoCaptureSettings(constraint_set.resize_mode.GetName());
  } else {
    DCHECK(candidates.device_id_set().IsEmpty());
    return VideoCaptureSettings(constraint_set.device_id.GetName());
  }
}

}  // namespace

VideoCaptureSettings SelectSettingsVideoContentCapture(
    const MediaConstraints& constraints,
    mojom::MediaStreamType stream_type,
    int screen_width,
    int screen_height) {
  VideoContentCaptureCandidates candidates;
  candidates.set_resolution_set(ScreenCastResolutionCapabilities());

  candidates = candidates.Intersection(
      VideoContentCaptureCandidates(constraints.Basic()));
  if (candidates.IsEmpty())
    return UnsatisfiedConstraintsResult(candidates, constraints.Basic());

  for (const auto& advanced_set : constraints.Advanced()) {
    VideoContentCaptureCandidates advanced_candidates(advanced_set);
    VideoContentCaptureCandidates intersection =
        candidates.Intersection(advanced_candidates);
    if (!intersection.IsEmpty())
      candidates = std::move(intersection);
  }

  DCHECK(!candidates.IsEmpty());
  return SelectResultFromCandidates(candidates, constraints.Basic(),
                                    stream_type, screen_width, screen_height);
}

}  // namespace blink

"""

```