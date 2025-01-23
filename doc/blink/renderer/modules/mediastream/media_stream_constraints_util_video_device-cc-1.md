Response:
The user wants me to analyze the provided C++ code snippet, which is the second part of a file related to video device constraints in the Chromium Blink engine. I need to:

1. **Summarize the functionality of this part.** Building on the first part, this section seems to deal with selecting the best video capture settings based on device capabilities and user constraints.

2. **Identify relationships with JavaScript, HTML, and CSS.**  This involves understanding how the constraints defined in JavaScript (through the WebRTC API) are processed and used to configure the underlying video capture.

3. **Provide examples and explain the connection.** I should illustrate how JavaScript constraints translate into the logic in this C++ code.

4. **Illustrate logical reasoning with input/output examples.**  This will involve showing how specific constraints lead to particular setting selections.

5. **Highlight common user or programming errors.** I need to think about how incorrect or conflicting constraints might lead to issues.

6. **Explain the user journey to this code.**  This involves tracing back from the user's actions in a web page to the execution of this C++ code.

7. **Summarize the overall function of the entire file (both parts).**

**High-level plan:**

*   Focus on the functions `DeviceSatisfiesConstraintSet`, `DeviceFitness`, `CandidateFitness`, `AppendDistancesFromDefault`, and `SelectSettingsVideoDeviceCapture`.
*   Explain how these functions work together to evaluate and select the optimal video capture settings.
*   Connect the concepts of `MediaTrackConstraintSetPlatform` with JavaScript's `MediaTrackConstraints`.
*   Provide concrete examples of how JavaScript constraints (like `facingMode`, `width`, `frameRate`) affect the execution of the C++ code.
*   Think about error scenarios like requesting unsupported features or conflicting constraints.
*   Describe the user's interaction with `getUserMedia()` and how it triggers this code.
```cpp
// Returns true if |constraint_set| can be satisfied by |device|. Otherwise,
// returns false and, if |failed_constraint_name| is not null, updates
// |failed_constraint_name| with the name of a constraint that could not be
// satisfied.
bool DeviceSatisfiesConstraintSet(
    const DeviceInfo& device,
    const MediaTrackConstraintSetPlatform& constraint_set,
    const char** failed_constraint_name = nullptr);

// Returns true if |value| satisfies the given |constraint|, false otherwise.
// If |constraint| is not satisfied and |failed_constraint_name| is not null,
// |failed_constraint_name| is set to |constraints|'s name.
bool OptionalBoolSatisfiesConstraint(
    const std::optional<bool>& value,
    const BooleanConstraint& constraint,
    const char** failed_constraint_name = nullptr);

double DeviceFitness(const DeviceInfo& device,
                     const MediaTrackConstraintSetPlatform& constraint_set);

// Returns the fitness distance between |constraint_set| and |candidate| given
// that the configuration is already constrained by |candidate_format|.
// Based on https://w3c.github.io/mediacapture-main/#dfn-fitness-distance.
// The track settings for |candidate| that correspond to the returned fitness
// are returned in |track_settings|.
double CandidateFitness(
    const DeviceInfo& device,
    const PTZDeviceState& ptz_state,
    const CandidateFormat& candidate_format,
    const ImageCaptureDeviceState& image_capture_device_state,
    const std::optional<bool>& noise_reduction,
    const MediaTrackConstraintSetPlatform& constraint_set,
    VideoTrackAdapterSettings* track_settings);

// This function appends additional entries to |distance_vector| based on
// custom distance metrics between some default settings and the candidate
// represented by |device|, |candidate_format| and |noise_reduction|.
// These entries are to be used as the final tie breaker for candidates that
// are equally good according to the spec and the custom distance functions
// between candidates and constraints.
void AppendDistancesFromDefault(
    const DeviceInfo& device,
    const CandidateFormat& candidate_format,
    const std::optional<bool>& noise_reduction,
    const VideoDeviceCaptureCapabilities& capabilities,
    int default_width,
    int default_height,
    double default_frame_rate,
    DistanceVector* distance_vector);

}  // namespace

VideoInputDeviceCapabilities::VideoInputDeviceCapabilities() = default;

VideoInputDeviceCapabilities::VideoInputDeviceCapabilities(
    String device_id,
    String group_id,
    const media::VideoCaptureControlSupport& control_support,
    Vector<media::VideoCaptureFormat> formats,
    mojom::blink::FacingMode facing_mode)
    : device_id(std::move(device_id)),
      group_id(std::move(group_id)),
      control_support(control_support),
      formats(std::move(formats)),
      facing_mode(facing_mode) {}

VideoInputDeviceCapabilities::VideoInputDeviceCapabilities(
    VideoInputDeviceCapabilities&& other) = default;
VideoInputDeviceCapabilities& VideoInputDeviceCapabilities::operator=(
    VideoInputDeviceCapabilities&& other) = default;

VideoInputDeviceCapabilities::~VideoInputDeviceCapabilities() = default;

MediaStreamTrackPlatform::FacingMode ToPlatformFacingMode(
    mojom::blink::FacingMode video_facing) {
  switch (video_facing) {
    case mojom::blink::FacingMode::kNone:
      return MediaStreamTrackPlatform::FacingMode::kNone;
    case mojom::blink::FacingMode::kUser:
      return MediaStreamTrackPlatform::FacingMode::kUser;
    case mojom::blink::FacingMode::kEnvironment:
      return MediaStreamTrackPlatform::FacingMode::kEnvironment;
    default:
      return MediaStreamTrackPlatform::FacingMode::kNone;
  }
}

VideoDeviceCaptureCapabilities::VideoDeviceCaptureCapabilities() = default;
VideoDeviceCaptureCapabilities::VideoDeviceCaptureCapabilities(
    VideoDeviceCaptureCapabilities&& other) = default;
VideoDeviceCaptureCapabilities::~VideoDeviceCaptureCapabilities() = default;
VideoDeviceCaptureCapabilities& VideoDeviceCaptureCapabilities::operator=(
    VideoDeviceCaptureCapabilities&& other) = default;

VideoCaptureSettings SelectSettingsVideoDeviceCapture(
    const VideoDeviceCaptureCapabilities& capabilities,
    const MediaConstraints& constraints,
    int default_width,
    int default_height,
    double default_frame_rate);

base::expected<Vector<VideoCaptureSettings>, std::string>
SelectEligibleSettingsVideoDeviceCapture(
    const VideoDeviceCaptureCapabilities& capabilities,
    const MediaConstraints& constraints,
    int default_width,
    int default_height,
    double default_frame_rate);

}  // namespace blink
```

### 功能归纳 (第 2 部分)

这部分代码主要负责 **根据用户指定的媒体约束条件，从可用的视频设备及其能力中选择最佳的视频捕获设置**。它实现了以下核心功能：

1. **设备和约束的匹配 (`DeviceSatisfiesConstraintSet`)**: 检查给定的视频设备是否满足基本的媒体约束条件，例如设备 ID、组 ID 和摄像头朝向模式（前置/后置）。
2. **可选布尔约束的匹配 (`OptionalBoolSatisfiesConstraint`)**:  检查一个可选的布尔值（如降噪功能是否启用）是否满足约束条件。
3. **设备适应度评估 (`DeviceFitness`)**:  计算设备与约束条件的匹配程度，主要基于设备 ID、组 ID 和摄像头朝向模式的匹配度。
4. **候选配置适应度评估 (`CandidateFitness`)**:  评估特定候选视频配置（包括设备、格式、图像捕获设置和 PTZ 状态等）与约束条件的匹配程度。这个函数会计算一个“适应度距离”，距离越小表示匹配度越高。
5. **默认设置的距离计算 (`AppendDistancesFromDefault`)**:  对于满足所有约束的候选配置，此函数会计算其与一些默认设置的距离，作为最终打破平局的依据。这些默认设置包括设备在枚举中的顺序、是否启用降噪、分辨率和帧率与默认值的接近程度。
6. **选择最佳捕获设置 (`SelectSettingsVideoDeviceCapture`)**:  这是核心函数，它遍历所有可用的视频设备及其支持的格式，并根据用户提供的媒体约束条件选择最佳的视频捕获设置。它利用前面提到的适应度评估函数来找到最佳匹配。
7. **选择所有符合条件的捕获设置 (`SelectEligibleSettingsVideoDeviceCapture`)**:  此函数返回一个包含所有满足约束条件的 `VideoCaptureSettings` 的向量，而不是只返回最佳的一个。

### 与 JavaScript, HTML, CSS 的关系

这段 C++ 代码是 Chromium 渲染引擎的一部分，它处理由 JavaScript Web API（特别是 `getUserMedia`）发起的媒体请求。

**JavaScript:**

*   **`getUserMedia()` API**:  JavaScript 使用 `navigator.mediaDevices.getUserMedia()` 方法来请求访问用户的摄像头和麦克风。在 `getUserMedia()` 的参数中，开发者可以指定各种约束条件，例如：
    ```javascript
    navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: 'user',
        width: { min: 640, ideal: 1280 },
        frameRate: { ideal: 30 }
      }
    })
    .then(function(stream) { /* 使用 stream */ })
    .catch(function(error) { /* 处理错误 */ });
    ```
*   **`MediaTrackConstraints` 接口**:  `getUserMedia()` 的参数 `video` 就是一个 `MediaTrackConstraints` 对象，它定义了对视频轨道的约束条件。这些约束条件最终会被传递到 Blink 引擎的 C++ 代码中进行处理。

**HTML:**

*   HTML 只是触发 JavaScript 代码的载体。例如，一个按钮的点击事件可能会调用 `getUserMedia()`。

**CSS:**

*   CSS 与此代码没有直接关系。CSS 负责页面的样式，而这段代码处理的是媒体设备的配置和选择。

**举例说明:**

假设 JavaScript 代码请求用户 facing 的摄像头，并且希望分辨率至少为 640 像素宽度：

```javascript
navigator.mediaDevices.getUserMedia({
  video: {
    facingMode: 'user',
    width: { min: 640 }
  }
});
```

1. **JavaScript 调用 `getUserMedia()`**:  浏览器接收到这个请求。
2. **约束传递到 Blink**:  JavaScript 的约束条件被转换为 Blink 引擎可以理解的数据结构，例如 `MediaTrackConstraintSetPlatform`。
3. **`DeviceSatisfiesConstraintSet`**:  C++ 代码中的 `DeviceSatisfiesConstraintSet` 函数会被调用，遍历可用的摄像头设备，检查它们的 `facing_mode` 是否为 'user'。
4. **`CandidateFitness` 和 `SelectSettingsVideoDeviceCapture`**:  `SelectSettingsVideoDeviceCapture` 函数会进一步调用 `CandidateFitness` 来评估每个满足 `facingMode` 的摄像头的不同分辨率，并选择宽度不小于 640 的最佳分辨率。

### 逻辑推理与输入/输出

**假设输入:**

*   **`DeviceInfo` (device1):** `device_id: "cam1"`, `group_id: "groupA"`, `facing_mode: USER_FACING`, `control_support: { pan: true, tilt: false, zoom: true }`, `formats: [...]`
*   **`DeviceInfo` (device2):** `device_id: "cam2"`, `group_id: "groupB"`, `facing_mode: ENVIRONMENT_FACING`, `control_support: { pan: false, tilt: false, zoom: false }`, `formats: [...]`
*   **`MediaTrackConstraintSetPlatform` (constraints):** `device_id: { exact: "cam1" }`, `facing_mode: { ideal: "user" }`, `pan: { mandatory: true }`

**逻辑推理:**

1. **`DeviceSatisfiesConstraintSet(device1, constraints)`**:
    *   `constraint_set.device_id.Matches(WebString(device1.device_id))` 为真 ("cam1" == "cam1")。
    *   `constraint_set.group_id.Matches(WebString(device1.group_id))`  如果 constraints 中没有指定 `group_id` 则为真。
    *   `FacingModeSatisfiesConstraint(device1.facing_mode, constraint_set.facing_mode)` 为真 (USER_FACING 符合 `ideal: "user"`)。
    *   `constraint_set.pan.HasMandatory()` 为真，但 `device1.control_support.pan` 也为真。
    *   **输出: `true`** (假设 `group_id` 约束满足)。

2. **`DeviceSatisfiesConstraintSet(device2, constraints)`**:
    *   `constraint_set.device_id.Matches(WebString(device2.device_id))` 为假 ("cam1" != "cam2")。
    *   **输出: `false`**, 并且如果 `failed_constraint_name` 不为空，则会被设置为 "deviceId"。

3. **`CandidateFitness`**:  这个函数会根据提供的约束和候选配置计算一个数值。例如，如果约束中指定了理想的帧率，并且候选配置的帧率与理想值接近，则适应度距离会更小。

**假设输出 (`SelectSettingsVideoDeviceCapture`):**

假设 `device1` 的某个格式满足其他约束条件，并且具有较高的适应度评分，那么 `SelectSettingsVideoDeviceCapture` 可能会返回一个 `VideoCaptureSettings` 对象，其中包含 `device_id: "cam1"` 和选择的最佳视频格式参数。

### 常见的使用错误

1. **请求不存在的设备 ID (`exact` 约束)**:  如果 JavaScript 代码指定了一个 `deviceId` 的 `exact` 约束，但该 ID 的设备不存在，则 `DeviceSatisfiesConstraintSet` 会返回 `false`，导致请求失败。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: { deviceId: { exact: "nonexistent-device-id" } } });
    ```
    **错误**: 用户可能会看到一个错误提示，表明找不到匹配的设备。

2. **请求设备不支持的 mandatory 功能**:  例如，请求 `pan: { mandatory: true }`，但用户的摄像头不支持平移控制。`DeviceSatisfiesConstraintSet` 会返回 `false`。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: { pan: { mandatory: true } } });
    ```
    **错误**: 请求可能会失败，或者浏览器可能会选择一个不支持该功能的摄像头。

3. **指定冲突的约束**:  例如，同时要求 `facingMode: "user"` 和 `facingMode: "environment"` 的 `exact` 值。这将导致没有设备满足约束。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: { facingMode: { exact: "user" }, facingMode: { exact: "environment" } } });
    ```
    **错误**: 请求会失败，因为没有设备能同时满足这两个互斥的条件.

4. **超出设备能力的约束**:  例如，要求一个非常高的分辨率或帧率，超过了设备所能提供的最大值。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: { width: { min: 4000 } } }); // 假设设备最大宽度小于 4000
    ```
    **错误**: 请求可能失败，或者浏览器会选择设备支持的最大分辨率。

### 用户操作到达此处的步骤 (调试线索)

1. **用户打开一个网页**: 用户在浏览器中打开一个包含使用摄像头的 Web 应用的网页。
2. **JavaScript 代码执行**: 网页加载后，JavaScript 代码开始执行。
3. **调用 `getUserMedia()`**:  JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 方法，并传入包含视频约束的对象。
4. **Blink 引擎接收请求**: 浏览器将 `getUserMedia()` 请求传递给 Blink 渲染引擎。
5. **约束解析**: Blink 引擎解析 JavaScript 传递的约束条件，并将其转换为内部数据结构（例如 `MediaTrackConstraintSetPlatform`）。
6. **设备能力查询**: Blink 引擎查询系统获取可用的视频捕获设备及其能力信息 (`VideoDeviceCaptureCapabilities`)。
7. **`SelectSettingsVideoDeviceCapture` 调用**:  `SelectSettingsVideoDeviceCapture` 函数被调用，开始根据约束条件和设备能力选择最佳的捕获设置。
8. **约束匹配和适应度评估**:  `DeviceSatisfiesConstraintSet` 和 `CandidateFitness` 等函数被调用，用于匹配设备和评估候选配置的适应度。
9. **选择最佳设置**:  根据适应度评估的结果，选择最佳的 `VideoCaptureSettings`。
10. **返回结果**:  选定的设置被用于配置视频捕获，并将媒体流返回给 JavaScript 代码（如果成功）。

### 完整文件功能归纳 (结合第 1 部分)

整个 `media_stream_constraints_util_video_device.cc` 文件的主要功能是 **实现视频媒体流约束的处理和设备选择逻辑**。它负责：

1. **定义用于表示和操作媒体约束条件的数据结构** (第 1 部分)。
2. **将 JavaScript 的 `MediaTrackConstraints` 转换为 Blink 内部表示** (可能在其他相关文件中，但此处使用这些表示)。
3. **查询系统获取可用的视频捕获设备及其能力信息** (通过其他 Chromium 组件)。
4. **根据用户指定的约束条件，过滤和评估可用的视频设备和捕获格式** (第 1 和第 2 部分)。
5. **计算设备和候选配置与约束条件的匹配程度 (适应度)** (第 2 部分)。
6. **选择满足约束条件且适应度最高的视频捕获设置** (第 2 部分)。
7. **返回选定的捕获设置，以便 Blink 引擎可以配置底层的视频捕获管道** (第 2 部分)。

总而言之，这个文件是 Chromium Blink 引擎中处理视频媒体约束的核心部分，它连接了 JavaScript 的媒体请求和底层的操作系统视频设备管理。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
itness(basic_constraint_set.saturation,
                                  saturation_set_) +
           NumericRangeSetFitness(basic_constraint_set.sharpness,
                                  sharpness_set_) +
           NumericRangeSetFitness(basic_constraint_set.focus_distance,
                                  focus_distance_set_) +
           BoolSetFitness(basic_constraint_set.torch, torch_set_) +
           BoolSetFitness(basic_constraint_set.background_blur,
                          background_blur_set_) +
           BoolSetFitness(basic_constraint_set.background_segmentation_mask,
                          background_segmentation_mask_set_) +
           BoolSetFitness(basic_constraint_set.eye_gaze_correction,
                          eye_gaze_correction_set_) +
           BoolSetFitness(basic_constraint_set.face_framing, face_framing_set_);
  }

  std::optional<ImageCaptureDeviceSettings> SelectSettings(
      const MediaTrackConstraintSetPlatform& basic_constraint_set,
      const PTZDeviceState& ptz_state) const {
    std::optional<ImageCaptureDeviceSettings> settings(std::in_place);

    settings->exposure_compensation = SelectSetting(
        basic_constraint_set.exposure_compensation, exposure_compensation_set_);
    settings->exposure_time =
        SelectSetting(basic_constraint_set.exposure_time, exposure_time_set_);
    settings->color_temperature = SelectSetting(
        basic_constraint_set.color_temperature, color_temperature_set_);
    settings->iso = SelectSetting(basic_constraint_set.iso, iso_set_);
    settings->brightness =
        SelectSetting(basic_constraint_set.brightness, brightness_set_);
    settings->contrast =
        SelectSetting(basic_constraint_set.contrast, contrast_set_);
    settings->saturation =
        SelectSetting(basic_constraint_set.saturation, saturation_set_);
    settings->sharpness =
        SelectSetting(basic_constraint_set.sharpness, sharpness_set_);
    settings->focus_distance =
        SelectSetting(basic_constraint_set.focus_distance, focus_distance_set_);

    settings->pan = ptz_state.SelectPan(basic_constraint_set);
    settings->tilt = ptz_state.SelectTilt(basic_constraint_set);
    settings->zoom = ptz_state.SelectZoom(basic_constraint_set);

    settings->torch = SelectSetting(basic_constraint_set.torch, torch_set_);
    settings->background_blur = SelectSetting(
        basic_constraint_set.background_blur, background_blur_set_);
    settings->background_segmentation_mask =
        SelectSetting(basic_constraint_set.background_segmentation_mask,
                      background_segmentation_mask_set_);
    settings->eye_gaze_correction = SelectSetting(
        basic_constraint_set.eye_gaze_correction, eye_gaze_correction_set_);
    settings->face_framing =
        SelectSetting(basic_constraint_set.face_framing, face_framing_set_);

    if (!(settings->exposure_compensation || settings->exposure_time ||
          settings->color_temperature || settings->iso ||
          settings->brightness || settings->contrast || settings->saturation ||
          settings->sharpness || settings->focus_distance || settings->pan ||
          settings->tilt || settings->zoom || settings->torch ||
          settings->background_blur || settings->background_segmentation_mask ||
          settings->eye_gaze_correction || settings->face_framing)) {
      settings.reset();
    }

    return settings;
  }

 private:
  std::optional<bool> SelectSetting(const BooleanConstraint& basic_constraint,
                                    const BoolSet& set) const {
    if (basic_constraint.HasIdeal()) {
      auto ideal = basic_constraint.Ideal();
      if (set.Contains(ideal)) {
        return ideal;
      }
    }
    if (set.is_universal()) {
      return std::nullopt;
    }
    return set.FirstElement();
  }

  std::optional<double> SelectSetting(const DoubleConstraint& basic_constraint,
                                      const DoubleRangeSet& set) const {
    if (basic_constraint.HasIdeal()) {
      auto ideal = basic_constraint.Ideal();
      if (set.Contains(ideal)) {
        return ideal;
      }
      if (set.Min().has_value() && ideal < *set.Min()) {
        return *set.Min();
      }
      if (set.Max().has_value() && ideal > *set.Max()) {
        return *set.Max();
      }
    }
    if (!set.Max().has_value()) {
      return set.Min();  // Returns nullopt if Min() does not have a value.
    }
    if (!set.Min().has_value()) {
      return set.Max();
    }
    return (*set.Min() + *set.Max()) / 2;
  }

  BoolSet SetFromConstraint(const BooleanConstraint& constraint) const {
    return media_constraints::BoolSetFromConstraint(constraint);
  }

  DoubleRangeSet SetFromConstraint(const DoubleConstraint& constraint) const {
    return DoubleRangeSet::FromConstraint(constraint);
  }

  template <typename Constraint, typename Set>
  bool TryToApplyConstraint(
      const Constraint& constraint,
      const Set& current_set,
      std::optional<Set>& intersection,
      const char** failed_constraint_name = nullptr) const {
    if (!constraint.HasMandatory()) {
      return true;
    }
    intersection = current_set.Intersection(SetFromConstraint(constraint));
    if (intersection->IsEmpty()) {
      UpdateFailedConstraintName(constraint, failed_constraint_name);
      return false;
    }
    return true;
  }

  DoubleRangeSet exposure_compensation_set_;
  DoubleRangeSet exposure_time_set_;
  DoubleRangeSet color_temperature_set_;
  DoubleRangeSet iso_set_;
  DoubleRangeSet brightness_set_;
  DoubleRangeSet contrast_set_;
  DoubleRangeSet saturation_set_;
  DoubleRangeSet sharpness_set_;
  DoubleRangeSet focus_distance_set_;
  BoolSet torch_set_;
  BoolSet background_blur_set_;
  BoolSet background_segmentation_mask_set_;
  BoolSet eye_gaze_correction_set_;
  BoolSet face_framing_set_;
};

// Returns true if |constraint_set| can be satisfied by |device|. Otherwise,
// returns false and, if |failed_constraint_name| is not null, updates
// |failed_constraint_name| with the name of a constraint that could not be
// satisfied.
bool DeviceSatisfiesConstraintSet(
    const DeviceInfo& device,
    const MediaTrackConstraintSetPlatform& constraint_set,
    const char** failed_constraint_name = nullptr) {
  if (!constraint_set.device_id.Matches(WebString(device.device_id))) {
    UpdateFailedConstraintName(constraint_set.device_id,
                               failed_constraint_name);
    return false;
  }

  if (!constraint_set.group_id.Matches(WebString(device.group_id))) {
    UpdateFailedConstraintName(constraint_set.group_id, failed_constraint_name);
    return false;
  }

  if (!FacingModeSatisfiesConstraint(device.facing_mode,
                                     constraint_set.facing_mode)) {
    UpdateFailedConstraintName(constraint_set.facing_mode,
                               failed_constraint_name);
    return false;
  }

  if (constraint_set.pan.HasMandatory() && !device.control_support.pan) {
    UpdateFailedConstraintName(constraint_set.pan, failed_constraint_name);
    return false;
  }

  if (constraint_set.tilt.HasMandatory() && !device.control_support.tilt) {
    UpdateFailedConstraintName(constraint_set.tilt, failed_constraint_name);
    return false;
  }

  if (constraint_set.zoom.HasMandatory() && !device.control_support.zoom) {
    UpdateFailedConstraintName(constraint_set.zoom, failed_constraint_name);
    return false;
  }

  return true;
}

// Returns true if |value| satisfies the given |constraint|, false otherwise.
// If |constraint| is not satisfied and |failed_constraint_name| is not null,
// |failed_constraint_name| is set to |constraints|'s name.
bool OptionalBoolSatisfiesConstraint(
    const std::optional<bool>& value,
    const BooleanConstraint& constraint,
    const char** failed_constraint_name = nullptr) {
  if (!constraint.HasExact()) {
    return true;
  }

  if (value && *value == constraint.Exact()) {
    return true;
  }

  UpdateFailedConstraintName(constraint, failed_constraint_name);
  return false;
}

double DeviceFitness(const DeviceInfo& device,
                     const MediaTrackConstraintSetPlatform& constraint_set) {
  return StringConstraintFitnessDistance(WebString(device.device_id),
                                         constraint_set.device_id) +
         StringConstraintFitnessDistance(WebString(device.group_id),
                                         constraint_set.group_id) +
         StringConstraintFitnessDistance(ToWebString(device.facing_mode),
                                         constraint_set.facing_mode);
}

// Returns the fitness distance between |constraint_set| and |candidate| given
// that the configuration is already constrained by |candidate_format|.
// Based on https://w3c.github.io/mediacapture-main/#dfn-fitness-distance.
// The track settings for |candidate| that correspond to the returned fitness
// are returned in |track_settings|.
double CandidateFitness(
    const DeviceInfo& device,
    const PTZDeviceState& ptz_state,
    const CandidateFormat& candidate_format,
    const ImageCaptureDeviceState& image_capture_device_state,
    const std::optional<bool>& noise_reduction,
    const MediaTrackConstraintSetPlatform& constraint_set,
    VideoTrackAdapterSettings* track_settings) {
  return DeviceFitness(device, constraint_set) +
         ptz_state.Fitness(constraint_set, device.control_support) +
         candidate_format.Fitness(constraint_set, track_settings) +
         image_capture_device_state.Fitness(constraint_set) +
         OptionalBoolFitness(noise_reduction,
                             constraint_set.goog_noise_reduction);
}

// This function appends additional entries to |distance_vector| based on
// custom distance metrics between some default settings and the candidate
// represented by |device|, |candidate_format| and |noise_reduction|.
// These entries are to be used as the final tie breaker for candidates that
// are equally good according to the spec and the custom distance functions
// between candidates and constraints.
void AppendDistancesFromDefault(
    const DeviceInfo& device,
    const CandidateFormat& candidate_format,
    const std::optional<bool>& noise_reduction,
    const VideoDeviceCaptureCapabilities& capabilities,
    int default_width,
    int default_height,
    double default_frame_rate,
    DistanceVector* distance_vector) {
  // Favor IDs that appear first in the enumeration.
  for (WTF::wtf_size_t i = 0; i < capabilities.device_capabilities.size();
       ++i) {
    if (device.device_id == capabilities.device_capabilities[i].device_id) {
      distance_vector->push_back(i);
      break;
    }
  }

  // Prefer not having a specific noise-reduction value and let the lower-layer
  // implementation choose a noise-reduction strategy.
  double noise_reduction_distance = noise_reduction ? HUGE_VAL : 0.0;
  distance_vector->push_back(noise_reduction_distance);

  // Prefer a native resolution closest to the default.
  double resolution_distance = ResolutionSet::Point::SquareEuclideanDistance(
      ResolutionSet::Point(candidate_format.NativeHeight(),
                           candidate_format.NativeWidth()),
      ResolutionSet::Point(default_height, default_width));
  distance_vector->push_back(resolution_distance);

  // Prefer a native frame rate close to the default.
  double frame_rate_distance = NumericConstraintFitnessDistance(
      candidate_format.NativeFrameRate(), default_frame_rate);
  distance_vector->push_back(frame_rate_distance);
}

}  // namespace

VideoInputDeviceCapabilities::VideoInputDeviceCapabilities() = default;

VideoInputDeviceCapabilities::VideoInputDeviceCapabilities(
    String device_id,
    String group_id,
    const media::VideoCaptureControlSupport& control_support,
    Vector<media::VideoCaptureFormat> formats,
    mojom::blink::FacingMode facing_mode)
    : device_id(std::move(device_id)),
      group_id(std::move(group_id)),
      control_support(control_support),
      formats(std::move(formats)),
      facing_mode(facing_mode) {}

VideoInputDeviceCapabilities::VideoInputDeviceCapabilities(
    VideoInputDeviceCapabilities&& other) = default;
VideoInputDeviceCapabilities& VideoInputDeviceCapabilities::operator=(
    VideoInputDeviceCapabilities&& other) = default;

VideoInputDeviceCapabilities::~VideoInputDeviceCapabilities() = default;

MediaStreamTrackPlatform::FacingMode ToPlatformFacingMode(
    mojom::blink::FacingMode video_facing) {
  switch (video_facing) {
    case mojom::blink::FacingMode::kNone:
      return MediaStreamTrackPlatform::FacingMode::kNone;
    case mojom::blink::FacingMode::kUser:
      return MediaStreamTrackPlatform::FacingMode::kUser;
    case mojom::blink::FacingMode::kEnvironment:
      return MediaStreamTrackPlatform::FacingMode::kEnvironment;
    default:
      return MediaStreamTrackPlatform::FacingMode::kNone;
  }
}

VideoDeviceCaptureCapabilities::VideoDeviceCaptureCapabilities() = default;
VideoDeviceCaptureCapabilities::VideoDeviceCaptureCapabilities(
    VideoDeviceCaptureCapabilities&& other) = default;
VideoDeviceCaptureCapabilities::~VideoDeviceCaptureCapabilities() = default;
VideoDeviceCaptureCapabilities& VideoDeviceCaptureCapabilities::operator=(
    VideoDeviceCaptureCapabilities&& other) = default;

VideoCaptureSettings SelectSettingsVideoDeviceCapture(
    const VideoDeviceCaptureCapabilities& capabilities,
    const MediaConstraints& constraints,
    int default_width,
    int default_height,
    double default_frame_rate) {
  DCHECK_GT(default_width, 0);
  DCHECK_GT(default_height, 0);
  DCHECK_GE(default_frame_rate, 0.0);
  // This function works only if infinity is defined for the double type.
  static_assert(std::numeric_limits<double>::has_infinity, "Requires infinity");

  // A distance vector contains:
  // a) For each advanced constraint set, a 0/Infinity value indicating if the
  //    candidate satisfies the corresponding constraint set.
  // b) Fitness distance for the candidate based on support for the ideal values
  //    of the basic constraint set.
  // c) A custom distance value based on how far the native format for a
  //    candidate is from the allowed and ideal resolution and frame rate after
  //    applying all constraint sets.
  // d) A custom distance value based on how close the candidate is to default
  //    settings.
  // Parts (a) and (b) are according to spec. Parts (c) and (d) are
  // implementation specific and used to break ties.
  DistanceVector best_distance(constraints.Advanced().size() + 2 +
                               kNumDefaultDistanceEntries);
  std::fill(best_distance.begin(), best_distance.end(), HUGE_VAL);
  VideoCaptureSettings result;
  const char* failed_constraint_name = result.failed_constraint_name();

  for (auto& device : capabilities.device_capabilities) {
    if (!DeviceSatisfiesConstraintSet(device, constraints.Basic(),
                                      &failed_constraint_name)) {
      continue;
    }

    ImageCaptureDeviceState image_capture_device_state(device);
    if (auto image_capture_device_result =
            image_capture_device_state.TryToApplyConstraintSet(
                constraints.Basic(), &failed_constraint_name)) {
      image_capture_device_state.ApplyResult(*image_capture_device_result);
    } else {
      continue;
    }

    PTZDeviceState ptz_device_state(constraints.Basic());
    if (ptz_device_state.IsEmpty()) {
      failed_constraint_name = ptz_device_state.FailedConstraintName();
      continue;
    }

    for (auto& format : device.formats) {
      PTZDeviceState ptz_state_for_format = ptz_device_state;
      CandidateFormat candidate_format(format);
      if (auto candidate_format_result =
              candidate_format.TryToApplyConstraintSet(
                  constraints.Basic(), &failed_constraint_name)) {
        candidate_format.ApplyResult(*candidate_format_result);
      } else {
        continue;
      }

      for (auto& noise_reduction : capabilities.noise_reduction_capabilities) {
        if (!OptionalBoolSatisfiesConstraint(
                noise_reduction, constraints.Basic().goog_noise_reduction,
                &failed_constraint_name)) {
          continue;
        }

        // At this point we have a candidate that satisfies all basic
        // constraints. The candidate consists of |device|, |candidate_format|
        // and |noise_reduction|.
        DistanceVector candidate_distance_vector;

        // First criteria for valid candidates is satisfaction of advanced
        // constraint sets.
        for (const auto& advanced_set : constraints.Advanced()) {
          PTZDeviceState ptz_advanced_state =
              ptz_state_for_format.Intersection(advanced_set);
          bool satisfies_advanced_set = false;

          if (DeviceSatisfiesConstraintSet(device, advanced_set) &&
              !ptz_advanced_state.IsEmpty() &&
              OptionalBoolSatisfiesConstraint(
                  noise_reduction, advanced_set.goog_noise_reduction)) {
            if (auto candidate_format_result =
                    candidate_format.TryToApplyConstraintSet(advanced_set)) {
              if (auto image_capture_device_result =
                      image_capture_device_state.TryToApplyConstraintSet(
                          advanced_set)) {
                satisfies_advanced_set = true;
                candidate_format.ApplyResult(*candidate_format_result);
                image_capture_device_state.ApplyResult(
                    *image_capture_device_result);
                ptz_state_for_format = ptz_advanced_state;
              }
            }
          }

          candidate_distance_vector.push_back(
              satisfies_advanced_set ? 0 : HUGE_VAL);
        }

        VideoTrackAdapterSettings track_settings;
        // Second criterion is fitness distance.
        candidate_distance_vector.push_back(
            CandidateFitness(device, ptz_state_for_format, candidate_format,
                             image_capture_device_state, noise_reduction,
                             constraints.Basic(), &track_settings));

        // Third criterion is native fitness distance.
        candidate_distance_vector.push_back(
            candidate_format.NativeFitness(constraints.Basic()));

        // Final criteria are custom distances to default settings.
        AppendDistancesFromDefault(device, candidate_format, noise_reduction,
                                   capabilities, default_width, default_height,
                                   default_frame_rate,
                                   &candidate_distance_vector);

        DCHECK_EQ(best_distance.size(), candidate_distance_vector.size());
        if (std::lexicographical_compare(candidate_distance_vector.begin(),
                                         candidate_distance_vector.end(),
                                         best_distance.begin(),
                                         best_distance.end())) {
          best_distance = candidate_distance_vector;

          media::VideoCaptureParams capture_params;
          capture_params.requested_format = candidate_format.format();
          result = VideoCaptureSettings(
              device.device_id.Utf8(), capture_params, noise_reduction,
              track_settings, candidate_format.constrained_frame_rate().Min(),
              candidate_format.constrained_frame_rate().Max(),
              image_capture_device_state.SelectSettings(constraints.Basic(),
                                                        ptz_state_for_format));
        }
      }
    }
  }

  if (!result.HasValue()) {
    return VideoCaptureSettings(failed_constraint_name);
  }

  return result;
}

base::expected<Vector<VideoCaptureSettings>, std::string>
SelectEligibleSettingsVideoDeviceCapture(
    const VideoDeviceCaptureCapabilities& capabilities,
    const MediaConstraints& constraints,
    int default_width,
    int default_height,
    double default_frame_rate) {
  Vector<VideoCaptureSettings> settings;
  std::string failed_constraint_name;
  for (const auto& device : capabilities.device_capabilities) {
    VideoDeviceCaptureCapabilities device_capabilities;
    device_capabilities.device_capabilities.emplace_back(
        device.device_id, device.group_id, device.control_support,
        device.formats, device.facing_mode);
    device_capabilities.noise_reduction_capabilities =
        capabilities.noise_reduction_capabilities;
    const auto device_settings = SelectSettingsVideoDeviceCapture(
        device_capabilities, constraints, default_width, default_height,
        default_frame_rate);
    if (device_settings.HasValue()) {
      settings.push_back(device_settings);
    } else {
      failed_constraint_name = device_settings.failed_constraint_name();
    }
  }

  if (settings.empty()) {
    return base::unexpected(failed_constraint_name);
  }
  return settings;
}

}  // namespace blink
```