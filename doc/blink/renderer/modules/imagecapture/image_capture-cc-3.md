Response:
The user wants to understand the functionality of the `image_capture.cc` file in the Chromium Blink engine. I need to analyze the code and provide:

1. A summary of the file's functionalities.
2. Connections to JavaScript, HTML, and CSS, with examples.
3. Illustrative logic using hypothetical inputs and outputs.
4. Common user or programming errors with examples.
5. A step-by-step explanation of how a user's actions might lead to this code being executed (debugging clues).
6. A concise overall summary of the file's purpose as the final part of a four-part explanation.

Based on the code, the file seems to handle capturing images from a video stream, managing device capabilities and settings related to image capture, and dealing with user constraints.
```
这是目录为blink/renderer/modules/imagecapture/image_capture.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

**功能归纳:**

`image_capture.cc` 文件的主要功能是实现 **ImageCapture API** 在 Chromium Blink 渲染引擎中的核心逻辑。 它是 Web 开发者通过 JavaScript 访问设备摄像头进行拍照的核心桥梁。

更具体地说，该文件负责：

1. **管理和查询摄像头能力 (Capabilities):**  
    - 从底层平台获取摄像头支持的各种图像捕获能力，例如支持的白平衡模式、曝光模式、ISO 值范围、缩放范围、是否支持闪光灯等。
    - 将这些底层能力转换为 `MediaTrackCapabilities` 对象，供 JavaScript 查询。

2. **管理和设置图像捕获设置 (Settings):**
    - 维护当前应用的图像捕获设置，例如当前的白平衡模式、曝光补偿、是否开启闪光灯等。
    - 允许 JavaScript 通过 `getPhotoSettings()` 和 `setOptions()` 方法获取和修改这些设置。

3. **应用和检查约束 (Constraints):**
    - 接收来自 JavaScript 的 `MediaTrackConstraints` 对象，这些约束指定了用户期望的图像捕获参数。
    - 检查这些约束是否与摄像头实际支持的能力相符。
    - 如果约束无法满足，会返回 `OverconstrainedError` 错误。

4. **执行拍照操作:**
    - 响应 JavaScript 的 `takePhoto()` 调用，与底层的媒体服务进行交互，触发拍照。
    - 将捕获的图像数据（Blob 对象）返回给 JavaScript。

5. **处理权限:**
    - 管理与摄像头的 Pan, Tilt, Zoom 控制相关的权限。

6. **与 Mojo 通信:**
    - 使用 Mojo 接口与浏览器进程中的媒体服务进行通信，以获取摄像头信息和执行拍照操作。

7. **错误处理:**
    - 处理各种错误情况，例如摄像头未找到、权限被拒绝、设置超出范围等。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript:** 这是该文件交互的主要对象。Web 开发者使用 JavaScript 中的 `ImageCapture` 接口来调用此文件中实现的功能。

    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(stream => {
        const track = stream.getVideoTracks()[0];
        const imageCapture = new ImageCapture(track);

        imageCapture.getPhotoCapabilities()
          .then(capabilities => console.log("摄像头支持的能力:", capabilities));

        imageCapture.takePhoto()
          .then(blob => {
            const imageUrl = URL.createObjectURL(blob);
            const img = document.createElement('img');
            img.src = imageUrl;
            document.body.appendChild(img);
          })
          .catch(error => console.error("拍照失败:", error));
      });
    ```

*   **HTML:**  HTML 用于展示捕获的图像。在上面的 JavaScript 示例中，捕获到的图像 Blob 被转换为 URL 并设置到 `<img>` 元素的 `src` 属性上，从而在页面上显示出来。

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Image Capture Example</title>
    </head>
    <body>
      <script src="script.js"></script>
    </body>
    </html>
    ```

*   **CSS:** CSS 可以用于样式化展示的图像，例如设置大小、边框等。

    ```css
    img {
      width: 300px;
      border: 1px solid black;
    }
    ```

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码尝试设置 ISO 值为 400：

*   **假设输入:**
    ```javascript
    imageCapture.setOptions({ iso: 400 })
      .then(() => console.log("ISO 设置成功"))
      .catch(error => console.error("ISO 设置失败:", error));
    ```
*   **`image_capture.cc` 中的逻辑:**
    1. `SetOptions()` 方法被调用。
    2. `ApplyConstraints` 函数会被调用，检查 `iso` 约束。
    3. `CheckMediaTrackConstraintSet` 函数会被调用，检查 ISO 值 400 是否在摄像头支持的 ISO 范围内 (`effective_capabilities->iso()`).
    4. 如果 400 在支持范围内，Mojo 消息会被发送到媒体服务来设置 ISO 值。
    5. `OnMojoSetPhotoOptions` 会被调用，如果底层设置成功，Promise 会 resolve。
*   **可能的输出:**
    *   **成功:**  控制台输出 "ISO 设置成功"。
    *   **失败 (ISO 不在支持范围内):** 控制台输出类似 "ISO 设置失败: OverconstrainedError: iso" 的错误信息。

**用户或编程常见的使用错误举例:**

1. **尝试设置不支持的属性:** 用户尝试设置摄像头不支持的属性，例如尝试设置一个不支持手动曝光的摄像头的 `exposureMode` 为 `"manual"`。
    *   **错误:**  `OverconstrainedError` 会被抛出。

2. **设置超出范围的值:** 用户尝试设置一个超出摄像头能力范围的值，例如设置 `zoom` 为一个超出最大值的值。
    *   **错误:** `OverconstrainedError` 会被抛出，提示 "zoom setting out of range"。

3. **在 Track 失活后调用 `takePhoto()`:**  如果视频轨道已经停止（例如，用户关闭了摄像头），尝试调用 `takePhoto()` 会导致错误。
    *   **错误:** `DOMException`，错误码 `kInvalidStateError`，消息 "Cannot call methods on a MediaStreamTrack whose readyState is ‘ended’"。 (虽然这里的文件内部会返回 `kInvalidStateTrackError`)

**用户操作到达此处的调试线索:**

1. **用户打开一个网页，该网页请求摄像头权限。**
2. **用户允许了摄像头权限。**
3. **网页的 JavaScript 代码使用 `navigator.mediaDevices.getUserMedia({ video: true })` 获取了视频流。**
4. **JavaScript 代码创建了 `ImageCapture` 对象，并将视频轨道的对象传递给它：`const imageCapture = new ImageCapture(track);`**  ->  这将触发 `ImageCapture` 对象的创建，并可能初始化与底层媒体服务的连接。
5. **用户点击了一个“拍照”按钮，或者网页自动调用了 `imageCapture.takePhoto()`。** -> 这会触发 `ImageCapture::TakePhoto()` 方法，最终导致与 Mojo 服务的交互，并可能涉及到 `GetMojoPhotoState` 和 `OnMojoTakePhoto` 等方法。
6. **用户尝试调整图像设置，例如点击界面上的白平衡模式选项。** ->  这可能触发 JavaScript 调用 `imageCapture.setOptions({ whiteBalanceMode: '...' })`，从而调用 `ImageCapture::SetOptions()` 和相关的约束检查逻辑。

**总结 (作为第 4 部分):**

总而言之，`blink/renderer/modules/imagecapture/image_capture.cc` 文件是 Chromium 浏览器中 ImageCapture API 的核心实现，它充当了 Web 开发者通过 JavaScript 控制摄像头拍照的桥梁。该文件负责管理摄像头的能力和设置，应用用户指定的约束，并执行拍照操作，最终将捕获的图像数据返回给网页。它与 JavaScript 紧密配合，并间接地通过 HTML 和 CSS 将捕获的图像呈现给用户。理解该文件的功能对于调试与摄像头图像捕获相关的问题至关重要。
```
### 提示词
```
这是目录为blink/renderer/modules/imagecapture/image_capture.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
pabilities->setBackgroundSegmentationMask(ApplyValueConstraint(
        &has_setting, &setting,
        effective_capabilities->backgroundSegmentationMask(),
        constraint_set->backgroundSegmentationMask(), constraint_set_type));
    if (has_setting) {
      settings->background_segmentation_mask_state.emplace(setting);
    }
  }
  if (constraint_set->hasEyeGazeCorrection() &&
      effective_capabilities->hasEyeGazeCorrection()) {
    bool has_setting = false;
    bool setting;
    effective_capabilities->setEyeGazeCorrection(ApplyValueConstraint(
        &has_setting, &setting, effective_capabilities->eyeGazeCorrection(),
        constraint_set->eyeGazeCorrection(), constraint_set_type));
    if (has_setting) {
      settings->eye_gaze_correction_mode.emplace(
          ParseEyeGazeCorrection(setting));
    }
  }
  if (constraint_set->hasFaceFraming() &&
      effective_capabilities->hasFaceFraming()) {
    bool has_setting = false;
    bool setting;
    effective_capabilities->setFaceFraming(ApplyValueConstraint(
        &has_setting, &setting, effective_capabilities->faceFraming(),
        constraint_set->faceFraming(), constraint_set_type));
    if (has_setting) {
      settings->has_face_framing_mode = true;
      settings->face_framing_mode = ParseFaceFraming(setting);
    }
  }
}

// TODO(crbug.com/708723): Integrate image capture constraints processing with
// the main implementation and remove this support function.
bool ImageCapture::CheckMediaTrackConstraintSet(
    const MediaTrackCapabilities* effective_capabilities,
    const MediaTrackSettings* effective_settings,
    const MediaTrackConstraintSet* constraint_set,
    MediaTrackConstraintSetType constraint_set_type,
    ScriptPromiseResolverBase* resolver) const {
  if (std::optional<const char*> name =
          GetConstraintWithCapabilityExistenceMismatch(constraint_set,
                                                       constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, name.value(),
                                        "Unsupported constraint");
    return false;
  }

  if (constraint_set->hasWhiteBalanceMode() &&
      effective_capabilities->hasWhiteBalanceMode() &&
      !CheckValueConstraint(effective_capabilities->whiteBalanceMode(),
                            constraint_set->whiteBalanceMode(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "whiteBalanceMode",
                                        "Unsupported whiteBalanceMode.");
    return false;
  }
  if (constraint_set->hasExposureMode() &&
      effective_capabilities->hasExposureMode() &&
      !CheckValueConstraint(effective_capabilities->exposureMode(),
                            constraint_set->exposureMode(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "exposureMode",
                                        "Unsupported exposureMode.");
    return false;
  }
  if (constraint_set->hasFocusMode() &&
      effective_capabilities->hasFocusMode() &&
      !CheckValueConstraint(effective_capabilities->focusMode(),
                            constraint_set->focusMode(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "focusMode",
                                        "Unsupported focusMode.");
    return false;
  }
  if (constraint_set->hasPointsOfInterest() &&
      !CheckValueConstraint(effective_settings->hasPointsOfInterest()
                                ? &effective_settings->pointsOfInterest()
                                : nullptr,
                            constraint_set->pointsOfInterest(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(
        resolver, "pointsOfInterest", "pointsOfInterest setting out of range");
    return false;
  }
  if (constraint_set->hasExposureCompensation() &&
      effective_capabilities->hasExposureCompensation() &&
      !CheckValueConstraint(effective_capabilities->exposureCompensation(),
                            constraint_set->exposureCompensation(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(
        resolver, "exposureCompensation",
        "exposureCompensation setting out of range");
    return false;
  }
  if (constraint_set->hasExposureTime() &&
      effective_capabilities->hasExposureTime() &&
      !CheckValueConstraint(effective_capabilities->exposureTime(),
                            constraint_set->exposureTime(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "exposureTime",
                                        "exposureTime setting out of range");
    return false;
  }
  if (constraint_set->hasColorTemperature() &&
      effective_capabilities->hasColorTemperature() &&
      !CheckValueConstraint(effective_capabilities->colorTemperature(),
                            constraint_set->colorTemperature(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(
        resolver, "colorTemperature", "colorTemperature setting out of range");
    return false;
  }
  if (constraint_set->hasIso() && effective_capabilities->hasIso() &&
      !CheckValueConstraint(effective_capabilities->iso(),
                            constraint_set->iso(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "iso",
                                        "iso setting out of range");
    return false;
  }
  if (constraint_set->hasBrightness() &&
      effective_capabilities->hasBrightness() &&
      !CheckValueConstraint(effective_capabilities->brightness(),
                            constraint_set->brightness(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "brightness",
                                        "brightness setting out of range");
    return false;
  }
  if (constraint_set->hasContrast() && effective_capabilities->hasContrast() &&
      !CheckValueConstraint(effective_capabilities->contrast(),
                            constraint_set->contrast(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "contrast",
                                        "contrast setting out of range");
    return false;
  }
  if (constraint_set->hasSaturation() &&
      effective_capabilities->hasSaturation() &&
      !CheckValueConstraint(effective_capabilities->saturation(),
                            constraint_set->saturation(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "saturation",
                                        "saturation setting out of range");
    return false;
  }
  if (constraint_set->hasSharpness() &&
      effective_capabilities->hasSharpness() &&
      !CheckValueConstraint(effective_capabilities->sharpness(),
                            constraint_set->sharpness(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "sharpness",
                                        "sharpness setting out of range");
    return false;
  }
  if (constraint_set->hasFocusDistance() &&
      effective_capabilities->hasFocusDistance() &&
      !CheckValueConstraint(effective_capabilities->focusDistance(),
                            constraint_set->focusDistance(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "focusDistance",
                                        "focusDistance setting out of range");
    return false;
  }
  if (constraint_set->hasPan() && effective_capabilities->hasPan() &&
      !CheckValueConstraint(effective_capabilities->pan(),
                            constraint_set->pan(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "pan",
                                        "pan setting out of range");
    return false;
  }
  if (constraint_set->hasTilt() && effective_capabilities->hasTilt() &&
      !CheckValueConstraint(effective_capabilities->tilt(),
                            constraint_set->tilt(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "tilt",
                                        "tilt setting out of range");
    return false;
  }
  if (constraint_set->hasZoom() && effective_capabilities->hasZoom() &&
      !CheckValueConstraint(effective_capabilities->zoom(),
                            constraint_set->zoom(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "zoom",
                                        "zoom setting out of range");
    return false;
  }
  if (constraint_set->hasTorch() && effective_capabilities->hasTorch() &&
      effective_capabilities->torch() &&
      !CheckValueConstraint(effective_settings->hasTorch()
                                ? Vector<bool>({effective_settings->torch()})
                                : Vector<bool>({false, true}),
                            constraint_set->torch(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(resolver, "torch",
                                        "torch not supported");
    return false;
  }
  if (constraint_set->hasBackgroundBlur() &&
      effective_capabilities->hasBackgroundBlur() &&
      !CheckValueConstraint(effective_capabilities->backgroundBlur(),
                            constraint_set->backgroundBlur(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(
        resolver, "backgroundBlur",
        "backgroundBlur setting value not supported");
    return false;
  }
  if (constraint_set->hasBackgroundSegmentationMask() &&
      effective_capabilities->hasBackgroundSegmentationMask() &&
      !CheckValueConstraint(
          effective_capabilities->backgroundSegmentationMask(),
          constraint_set->backgroundSegmentationMask(), constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(
        resolver, "backgroundSegmentationMask",
        "backgroundSegmentationMask setting value not supported");
    return false;
  }
  if (constraint_set->hasEyeGazeCorrection() &&
      effective_capabilities->hasEyeGazeCorrection() &&
      !CheckValueConstraint(effective_capabilities->eyeGazeCorrection(),
                            constraint_set->eyeGazeCorrection(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(
        resolver, "eyeGazeCorrection",
        "eyeGazeCorrection setting value not supported");
    return false;
  }
  if (constraint_set->hasFaceFraming() &&
      effective_capabilities->hasFaceFraming() &&
      !CheckValueConstraint(effective_capabilities->faceFraming(),
                            constraint_set->faceFraming(),
                            constraint_set_type)) {
    MaybeRejectWithOverconstrainedError(
        resolver, "faceFraming", "faceFraming setting value not supported");
    return false;
  }

  return true;
}

void ImageCapture::OnPermissionStatusChange(
    mojom::blink::PermissionStatus status) {
  pan_tilt_zoom_permission_ = status;
}

bool ImageCapture::HasPanTiltZoomPermissionGranted() const {
  return pan_tilt_zoom_permission_ == mojom::blink::PermissionStatus::GRANTED;
}

void ImageCapture::GetMojoPhotoState(ScriptPromiseResolverBase* resolver,
                                     PromiseResolverFunction resolver_cb) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::GetMojoPhotoState");
  if (TrackIsInactive(*stream_track_)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, kInvalidStateTrackError));
    return;
  }

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotFoundError, kNoServiceError));
    return;
  }
  service_requests_.insert(resolver);

  service_->GetPhotoState(
      SourceId(),
      WTF::BindOnce(&ImageCapture::OnMojoGetPhotoState, WrapPersistent(this),
                    WrapPersistent(resolver), std::move(resolver_cb),
                    /*trigger_take_photo=*/false));
}

void ImageCapture::OnMojoGetPhotoState(
    ScriptPromiseResolverBase* resolver,
    PromiseResolverFunction resolve_function,
    bool trigger_take_photo,
    media::mojom::blink::PhotoStatePtr photo_state) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::OnMojoGetPhotoState");
  DCHECK(service_requests_.Contains(resolver));

  if (photo_state.is_null()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError, "platform error"));
    service_requests_.erase(resolver);
    return;
  }

  if (TrackIsInactive(*stream_track_)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kOperationError, kInvalidStateTrackError));
    service_requests_.erase(resolver);
    return;
  }

  photo_settings_ = PhotoSettings::Create();
  photo_settings_->setImageHeight(photo_state->height->current);
  photo_settings_->setImageWidth(photo_state->width->current);
  // TODO(mcasas): collect the remaining two entries https://crbug.com/732521.

  photo_capabilities_ = MakeGarbageCollected<PhotoCapabilities>();
  photo_capabilities_->setRedEyeReduction(
      ToString(photo_state->red_eye_reduction));
  if (photo_state->height->min != 0 || photo_state->height->max != 0) {
    photo_capabilities_->setImageHeight(
        ToMediaSettingsRange(*photo_state->height));
  }
  if (photo_state->width->min != 0 || photo_state->width->max != 0) {
    photo_capabilities_->setImageWidth(
        ToMediaSettingsRange(*photo_state->width));
  }

  WTF::Vector<V8FillLightMode> fill_light_mode;
  for (const auto& mode : photo_state->fill_light_mode) {
    fill_light_mode.push_back(ToV8FillLightMode(mode));
  }
  if (!fill_light_mode.empty())
    photo_capabilities_->setFillLightMode(fill_light_mode);

  // Update the local track photo_state cache.
  UpdateMediaTrackSettingsAndCapabilities(base::DoNothing(),
                                          std::move(photo_state));

  if (trigger_take_photo) {
    service_->TakePhoto(
        SourceId(),
        WTF::BindOnce(&ImageCapture::OnMojoTakePhoto, WrapPersistent(this),
                      WrapPersistent(resolver)));
    return;
  }

  std::move(resolve_function).Run(resolver);
  service_requests_.erase(resolver);
}

void ImageCapture::OnMojoSetPhotoOptions(ScriptPromiseResolverBase* resolver,
                                         bool trigger_take_photo,
                                         bool result) {
  DCHECK(service_requests_.Contains(resolver));
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::OnMojoSetPhotoOptions");

  if (!result) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError, "setPhotoOptions failed"));
    service_requests_.erase(resolver);
    return;
  }

  auto resolver_cb =
      WTF::BindOnce(&ImageCapture::ResolveWithNothing, WrapPersistent(this));

  // Retrieve the current device status after setting the options.
  service_->GetPhotoState(
      SourceId(), WTF::BindOnce(&ImageCapture::OnMojoGetPhotoState,
                                WrapPersistent(this), WrapPersistent(resolver),
                                std::move(resolver_cb), trigger_take_photo));
}

void ImageCapture::OnMojoTakePhoto(ScriptPromiseResolverBase* resolver,
                                   media::mojom::blink::BlobPtr blob) {
  DCHECK(service_requests_.Contains(resolver));
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::OnMojoTakePhoto", "blob_size", blob->data.size());

  // TODO(mcasas): Should be using a mojo::StructTraits.
  if (blob->data.empty()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError, "platform error"));
  } else {
    resolver->DowncastTo<Blob>()->Resolve(
        Blob::Create(blob->data, blob->mime_type));
  }
  service_requests_.erase(resolver);
}

void ImageCapture::UpdateMediaTrackSettingsAndCapabilities(
    base::OnceClosure initialized_callback,
    media::mojom::blink::PhotoStatePtr photo_state) {
  if (!photo_state) {
    std::move(initialized_callback).Run();
    return;
  }

  WTF::Vector<WTF::String> supported_white_balance_modes;
  supported_white_balance_modes.ReserveInitialCapacity(
      photo_state->supported_white_balance_modes.size());
  for (const auto& supported_mode : photo_state->supported_white_balance_modes)
    supported_white_balance_modes.push_back(ToString(supported_mode));
  if (!supported_white_balance_modes.empty()) {
    capabilities_->setWhiteBalanceMode(
        std::move(supported_white_balance_modes));
    settings_->setWhiteBalanceMode(
        ToString(photo_state->current_white_balance_mode));
  }

  WTF::Vector<WTF::String> supported_exposure_modes;
  supported_exposure_modes.ReserveInitialCapacity(
      photo_state->supported_exposure_modes.size());
  for (const auto& supported_mode : photo_state->supported_exposure_modes)
    supported_exposure_modes.push_back(ToString(supported_mode));
  if (!supported_exposure_modes.empty()) {
    capabilities_->setExposureMode(std::move(supported_exposure_modes));
    settings_->setExposureMode(ToString(photo_state->current_exposure_mode));
  }

  WTF::Vector<WTF::String> supported_focus_modes;
  supported_focus_modes.ReserveInitialCapacity(
      photo_state->supported_focus_modes.size());
  for (const auto& supported_mode : photo_state->supported_focus_modes)
    supported_focus_modes.push_back(ToString(supported_mode));
  if (!supported_focus_modes.empty()) {
    capabilities_->setFocusMode(std::move(supported_focus_modes));
    settings_->setFocusMode(ToString(photo_state->current_focus_mode));
  }

  HeapVector<Member<Point2D>> current_points_of_interest;
  if (!photo_state->points_of_interest.empty()) {
    for (const auto& point : photo_state->points_of_interest) {
      Point2D* web_point = Point2D::Create();
      web_point->setX(point->x);
      web_point->setY(point->y);
      current_points_of_interest.push_back(web_point);
    }
  }
  settings_->setPointsOfInterest(current_points_of_interest);

  if (photo_state->exposure_compensation->max !=
      photo_state->exposure_compensation->min) {
    capabilities_->setExposureCompensation(
        ToMediaSettingsRange(*photo_state->exposure_compensation));
    settings_->setExposureCompensation(
        photo_state->exposure_compensation->current);
  }
  if (photo_state->exposure_time->max != photo_state->exposure_time->min) {
    capabilities_->setExposureTime(
        ToMediaSettingsRange(*photo_state->exposure_time));
    settings_->setExposureTime(photo_state->exposure_time->current);
  }
  if (photo_state->color_temperature->max !=
      photo_state->color_temperature->min) {
    capabilities_->setColorTemperature(
        ToMediaSettingsRange(*photo_state->color_temperature));
    settings_->setColorTemperature(photo_state->color_temperature->current);
  }
  if (photo_state->iso->max != photo_state->iso->min) {
    capabilities_->setIso(ToMediaSettingsRange(*photo_state->iso));
    settings_->setIso(photo_state->iso->current);
  }

  if (photo_state->brightness->max != photo_state->brightness->min) {
    capabilities_->setBrightness(
        ToMediaSettingsRange(*photo_state->brightness));
    settings_->setBrightness(photo_state->brightness->current);
  }
  if (photo_state->contrast->max != photo_state->contrast->min) {
    capabilities_->setContrast(ToMediaSettingsRange(*photo_state->contrast));
    settings_->setContrast(photo_state->contrast->current);
  }
  if (photo_state->saturation->max != photo_state->saturation->min) {
    capabilities_->setSaturation(
        ToMediaSettingsRange(*photo_state->saturation));
    settings_->setSaturation(photo_state->saturation->current);
  }
  if (photo_state->sharpness->max != photo_state->sharpness->min) {
    capabilities_->setSharpness(ToMediaSettingsRange(*photo_state->sharpness));
    settings_->setSharpness(photo_state->sharpness->current);
  }

  if (photo_state->focus_distance->max != photo_state->focus_distance->min) {
    capabilities_->setFocusDistance(
        ToMediaSettingsRange(*photo_state->focus_distance));
    settings_->setFocusDistance(photo_state->focus_distance->current);
  }

  if (HasPanTiltZoomPermissionGranted()) {
    if (photo_state->pan->max != photo_state->pan->min) {
      capabilities_->setPan(ToMediaSettingsRange(*photo_state->pan));
      settings_->setPan(photo_state->pan->current);
    }
    if (photo_state->tilt->max != photo_state->tilt->min) {
      capabilities_->setTilt(ToMediaSettingsRange(*photo_state->tilt));
      settings_->setTilt(photo_state->tilt->current);
    }
    if (photo_state->zoom->max != photo_state->zoom->min) {
      capabilities_->setZoom(ToMediaSettingsRange(*photo_state->zoom));
      settings_->setZoom(photo_state->zoom->current);
    }
  }

  if (photo_state->supports_torch)
    capabilities_->setTorch(photo_state->supports_torch);
  if (photo_state->supports_torch)
    settings_->setTorch(photo_state->torch);

  if (photo_state->supported_background_blur_modes &&
      !photo_state->supported_background_blur_modes->empty()) {
    Vector<bool> supported_background_blur_modes;
    for (auto mode : *photo_state->supported_background_blur_modes) {
      bool boolean_mode = ToBooleanMode(mode);
      if (!base::Contains(supported_background_blur_modes, boolean_mode)) {
        supported_background_blur_modes.push_back(boolean_mode);
      }
    }
    capabilities_->setBackgroundBlur(
        std::move(supported_background_blur_modes));
    settings_->setBackgroundBlur(
        ToBooleanMode(photo_state->background_blur_mode));
  }

  if (photo_state->supported_background_segmentation_mask_states &&
      !photo_state->supported_background_segmentation_mask_states->empty()) {
    capabilities_->setBackgroundSegmentationMask(
        *photo_state->supported_background_segmentation_mask_states);
    settings_->setBackgroundSegmentationMask(
        photo_state->current_background_segmentation_mask_state);
  }

  if (photo_state->supported_eye_gaze_correction_modes &&
      !photo_state->supported_eye_gaze_correction_modes->empty()) {
    Vector<bool> supported_eye_gaze_correction_modes;
    for (const auto& mode : *photo_state->supported_eye_gaze_correction_modes) {
      bool boolean_mode = ToBooleanMode(mode);
      if (!base::Contains(supported_eye_gaze_correction_modes, boolean_mode)) {
        supported_eye_gaze_correction_modes.push_back(boolean_mode);
      }
    }
    capabilities_->setEyeGazeCorrection(
        std::move(supported_eye_gaze_correction_modes));
    settings_->setEyeGazeCorrection(
        ToBooleanMode(photo_state->current_eye_gaze_correction_mode));
  }

  if (photo_state->supported_face_framing_modes &&
      !photo_state->supported_face_framing_modes->empty()) {
    Vector<bool> supported_face_framing_modes;
    for (auto mode : *photo_state->supported_face_framing_modes) {
      if (mode == MeteringMode::CONTINUOUS ||
          mode == MeteringMode::SINGLE_SHOT) {
        supported_face_framing_modes.push_back(true);
      } else if (mode == MeteringMode::NONE) {
        supported_face_framing_modes.push_back(false);
      }
    }
    if (!supported_face_framing_modes.empty()) {
      capabilities_->setFaceFraming(supported_face_framing_modes);
      settings_->setFaceFraming(photo_state->current_face_framing_mode !=
                                MeteringMode::NONE);
    }
  }

  std::move(initialized_callback).Run();
}

void ImageCapture::OnServiceConnectionError() {
  service_.reset();

  HeapHashSet<Member<ScriptPromiseResolverBase>> resolvers;
  resolvers.swap(service_requests_);
  for (ScriptPromiseResolverBase* resolver : resolvers) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotFoundError, kNoServiceError));
  }
}

void ImageCapture::MaybeRejectWithOverconstrainedError(
    ScriptPromiseResolverBase* resolver,
    const char* constraint,
    const char* message) const {
  if (!resolver) {
    return;
  }
  resolver->Reject(
      MakeGarbageCollected<OverconstrainedError>(constraint, message));
}

void ImageCapture::ResolveWithNothing(ScriptPromiseResolverBase* resolver) {
  DCHECK(resolver);
  resolver->DowncastTo<IDLUndefined>()->Resolve();
}

void ImageCapture::ResolveWithPhotoSettings(
    ScriptPromiseResolverBase* resolver) {
  DCHECK(resolver);
  resolver->DowncastTo<PhotoSettings>()->Resolve(photo_settings_);
}

void ImageCapture::ResolveWithPhotoCapabilities(
    ScriptPromiseResolverBase* resolver) {
  DCHECK(resolver);
  resolver->DowncastTo<PhotoCapabilities>()->Resolve(photo_capabilities_);
}

bool ImageCapture::IsPageVisible() const {
  return DomWindow() && DomWindow()->document()->IsPageVisible();
}

const String& ImageCapture::SourceId() const {
  return stream_track_->Component()->Source()->Id();
}

const std::optional<const char*>
ImageCapture::GetConstraintWithCapabilityExistenceMismatch(
    const MediaTrackConstraintSet* constraint_set,
    MediaTrackConstraintSetType constraint_set_type) const {
  if (constraint_set->hasWhiteBalanceMode() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->whiteBalanceMode(),
          CapabilityExists(capabilities_->hasWhiteBalanceMode()),
          constraint_set_type)) {
    return "whiteBalanceMode";
  }
  if (constraint_set->hasExposureMode() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->exposureMode(),
          CapabilityExists(capabilities_->hasExposureMode()),
          constraint_set_type)) {
    return "exposureMode";
  }
  if (constraint_set->hasFocusMode() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->focusMode(),
          CapabilityExists(capabilities_->hasFocusMode()),
          constraint_set_type)) {
    return "focusMode";
  }
  if (constraint_set->hasExposureCompensation() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->exposureCompensation(),
          CapabilityExists(capabilities_->hasExposureCompensation()),
          constraint_set_type)) {
    return "exposureCompensation";
  }
  if (constraint_set->hasExposureTime() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->exposureTime(),
          CapabilityExists(capabilities_->hasExposureTime()),
          constraint_set_type)) {
    return "exposureTime";
  }
  if (constraint_set->hasColorTemperature() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->colorTemperature(),
          CapabilityExists(capabilities_->hasColorTemperature()),
          constraint_set_type)) {
    return "colorTemperature";
  }
  if (constraint_set->hasIso() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->iso(), CapabilityExists(capabilities_->hasIso()),
          constraint_set_type)) {
    return "iso";
  }
  if (constraint_set->hasBrightness() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->brightness(),
          CapabilityExists(capabilities_->hasBrightness()),
          constraint_set_type)) {
    return "brightness";
  }
  if (constraint_set->hasContrast() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->contrast(),
          CapabilityExists(capabilities_->hasContrast()),
          constraint_set_type)) {
    return "contrast";
  }
  if (constraint_set->hasSaturation() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->saturation(),
          CapabilityExists(capabilities_->hasSaturation()),
          constraint_set_type)) {
    return "saturation";
  }
  if (constraint_set->hasSharpness() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->sharpness(),
          CapabilityExists(capabilities_->hasSharpness()),
          constraint_set_type)) {
    return "sharpness";
  }
  if (constraint_set->hasFocusDistance() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->focusDistance(),
          CapabilityExists(capabilities_->hasFocusDistance()),
          constraint_set_type)) {
    return "focusDistance";
  }
  if (constraint_set->hasPan() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->pan(),
          CapabilityExists(capabilities_->hasPan() &&
                           HasPanTiltZoomPermissionGranted()),
          constraint_set_type)) {
    return "pan";
  }
  if (constraint_set->hasTilt() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->tilt(),
          CapabilityExists(capabilities_->hasTilt() &&
                           HasPanTiltZoomPermissionGranted()),
          constraint_set_type)) {
    return "tilt";
  }
  if (constraint_set->hasZoom() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->zoom(),
          CapabilityExists(capabilities_->hasZoom() &&
                           HasPanTiltZoomPermissionGranted()),
          constraint_set_type)) {
    return "zoom";
  }
  if (constraint_set->hasTorch() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->torch(), CapabilityExists(capabilities_->hasTorch()),
          constraint_set_type)) {
    return "torch";
  }
  if (constraint_set->hasBackgroundBlur() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->backgroundBlur(),
          CapabilityExists(capabilities_->hasBackgroundBlur()),
          constraint_set_type)) {
    return "backgroundBlur";
  }
  if (constraint_set->hasBackgroundSegmentationMask() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->backgroundSegmentationMask(),
          CapabilityExists(capabilities_->hasBackgroundSegmentationMask()),
          constraint_set_type)) {
    return "backgroundSegmentationMask";
  }
  if (constraint_set->hasEyeGazeCorrection() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->eyeGazeCorrection(),
          CapabilityExists(capabilities_->hasEyeGazeCorrection()),
          constraint_set_type)) {
    return "eyeGazeCorrection";
  }
  if (constraint_set->hasFaceFraming() &&
      !CheckIfCapabilityExistenceSatisfiesConstraint(
          constraint_set->faceFraming(),
          CapabilityExists(capabilities_->hasFaceFraming()),
          constraint_set_type)) {
    return "faceFraming";
  }
  return std::nullopt;
}

ImageCapture* ImageCapture::Clone() const {
  ImageCapture* clone = MakeGarbageCollected<ImageCapture>(
      GetExecutionContext(), stream_track_, HasPanTiltZoomPermissionGranted(),
      /*callback=*/base::DoNothing());

  // Copy capabilities.
  CopyCapabilities(capabilities_, clone->capabilities_, CopyPanTiltZoom(true));

  // Copy settings.
  CopySettings(settings_, clone->settings_, CopyPanTiltZoom(true));

  // Copy current constraints.
  if (current_constraints_) {
    clone->current_constraints_ = MediaTrackConstraints::Create();
    CopyConstraints(current_constraints_, clone->current_constraints_);
  }

  return clone;
}

void ImageCapture::Trace(Visitor* visitor) const {
  visitor->Trace(stream_track_);
  visitor->Trace(service_);
  visitor->Trace(permission_service_);
  visitor->Trace(permission_observer_receiver_);
  visitor->Trace(capabilities_);
  visitor->Trace(settings_);
  visitor->Trace(photo_settings_);
  visitor->Trace(current_constraints_);
  visitor->Trace(photo_capabilities_);
  visitor->Trace(service_requests_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink
```