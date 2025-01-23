Response:
The user wants a summary of the provided C++ code for `blink/renderer/modules/imagecapture/image_capture.cc`. This is part 3 of 4.

I need to identify the main functionalities within this code snippet, especially focusing on how it interacts with JavaScript, HTML, and CSS. I should also look for logic, potential errors, and the user flow that might lead to this code being executed.

**Key areas to focus on based on the code:**

*   **`SetPhotoOptions`**: Setting image capture options (height, width, red-eye reduction, fill light).
*   **`grabFrame`**: Capturing a single frame as an `ImageBitmap`.
*   **`UpdateAndCheckMediaTrackSettingsAndCapabilities`**:  Fetching and comparing media track settings and capabilities.
*   **`CheckAndApplyMediaTrackConstraintsToSettings`**: Applying constraints to photo settings.
*   **`GetMediaTrackCapabilities`**: Retrieving the device's image capture capabilities.
*   **`SetMediaTrackConstraints`**: Applying constraints requested by the user.
*   **`SetVideoTrackDeviceSettingsFromTrack`**: Applying initial device settings from the video track.
*   **`GetMediaTrackConstraints` and `ClearMediaTrackConstraints`**:  Managing current constraints.
*   **`GetMediaTrackSettings`**: Retrieving the current settings.
*   **Constraint Application Logic**: The `ApplyMediaTrackConstraintSetToSettings` function and related helpers.

**Relationships with web technologies:**

*   **JavaScript:** The functions are likely called from JavaScript using the `ImageCapture` API.
*   **HTML:** The captured image might be displayed in an `<img>` tag or manipulated using `<canvas>`.
*   **CSS:** CSS might be used to style the display of captured images.

**Logic and potential errors:**

*   Range checks on image height and width.
*   Checks for supported features (e.g., red-eye reduction, fill light).
*   Handling of inactive tracks in `grabFrame`.
*   Constraint application logic and potential `NotSupportedError` or `OverconstrainedError`.

**User actions:**

The user likely interacts with a web page that uses the `ImageCapture` API to:

1. Get access to a media stream (camera).
2. Create an `ImageCapture` object from the video track.
3. Call methods like `getPhotoCapabilities()`, `getPhotoSettings()`, `setOptions()`, `grabFrame()`, or `applyConstraints()`.

**Overall Summary for this part:**

This section of the `ImageCapture` code focuses on the core functionalities of setting photo options, capturing single frames, and managing media track settings and capabilities, including the complex logic of applying user-defined constraints.
这是 `blink/renderer/modules/imagecapture/image_capture.cc` 文件的第三部分代码，主要负责处理图像捕获的配置、帧抓取以及媒体轨道约束和能力的管理。

**功能归纳:**

1. **设置照片选项 (Set Photo Options):**  该部分代码处理通过 JavaScript 的 `ImageCapture.setOptions()` 方法设置照片属性，如 `imageHeight`（图像高度）、`imageWidth`（图像宽度）、`redEyeReduction`（红眼消除）和 `fillLightMode`（补光模式）。它会将这些 JavaScript 的设置转换为内部的 `media::mojom::blink::PhotoSettings` 结构，并进行有效性验证，例如检查高度和宽度是否在设备支持的范围内，以及红眼消除和补光模式是否受支持。如果设置超出范围或不受支持，则会返回一个包含 `NotSupportedError` 的 Promise rejected。

2. **抓取单帧 (Grab Frame):** `grabFrame` 方法实现了从视频轨道抓取当前帧的功能。它首先检查视频轨道是否处于活动状态，如果不是，则会返回一个包含 `InvalidStateError` 的 Promise rejected。如果这是第一次调用 `grabFrame`，它会创建一个 `ImageCaptureFrameGrabber` 对象来实际执行帧抓取。抓取成功后，会将图像数据封装成 `ImageBitmap` 对象并通过 Promise resolve 返回给 JavaScript。如果创建平台资源失败，则会返回包含 `UnknownError` 的 Promise rejected。

3. **更新和检查媒体轨道设置与能力 (Update and Check Media Track Settings and Capabilities):** `UpdateAndCheckMediaTrackSettingsAndCapabilities` 方法用于获取最新的媒体轨道设置和能力信息。它会调用 Mojo 接口 `service_->GetPhotoState` 来获取设备当前的状态。获取状态后，`GotPhotoState` 方法会被调用，它会比较当前和之前的背景虚化和人脸检测设置和能力，如果发现变化，则会执行回调函数，通知这些变化。

4. **检查并应用媒体轨道约束到设置 (Check and Apply Media Track Constraints To Settings):** `CheckAndApplyMediaTrackConstraintsToSettings` 方法是处理通过 `ImageCapture.applyConstraints()` 方法设置的媒体轨道约束的核心逻辑。它会遍历所有约束集，并根据设备的能力和当前状态来检查这些约束是否可以应用。如果页面不可见，则会拒绝与平移、倾斜和缩放相关的约束，抛出 `SecurityError`。该方法还会维护一个“有效能力”的概念，考虑到环境限制和先前的约束。

5. **获取媒体轨道能力 (Get Media Track Capabilities):** `GetMediaTrackCapabilities` 方法用于获取设备支持的媒体轨道能力，例如支持的白平衡模式、曝光模式、焦点模式等等。它会将内部存储的 `capabilities_` 复制到传入的 `MediaTrackCapabilities` 对象中。

6. **设置媒体轨道约束 (Set Media Track Constraints):** `SetMediaTrackConstraints` 方法接收来自 JavaScript 的 `applyConstraints()` 调用，并将约束转换为内部的 `media::mojom::blink::PhotoSettings` 结构。它会调用 `CheckAndApplyMediaTrackConstraintsToSettings` 来验证和应用约束。如果约束成功应用，会将当前约束存储在 `current_constraints_` 中。然后通过 Mojo 接口 `service_->SetPhotoOptions` 将设置发送到设备。

7. **从视频轨道设置设备设置 (Set Video Track Device Settings From Track):** `SetVideoTrackDeviceSettingsFromTrack` 方法用于在初始化时，从 `MediaStreamVideoTrack` 中获取设备的初始设置，并应用到 `ImageCapture`。这包括曝光补偿、曝光时间、色温、ISO、亮度、对比度、饱和度、清晰度、焦距、平移、倾斜、缩放、闪光灯、背景虚化等。

8. **获取和清除媒体轨道约束 (Get and Clear Media Track Constraints):** `GetMediaTrackConstraints` 返回当前生效的媒体轨道约束，`ClearMediaTrackConstraints` 清除这些约束。

9. **获取媒体轨道设置 (Get Media Track Settings):** `GetMediaTrackSettings` 方法用于获取当前生效的媒体轨道设置。

10. **约束的应用逻辑 (Constraint Application Logic):** `ApplyMediaTrackConstraintSetToSettings` 实现了将具体的媒体轨道约束应用到照片设置的逻辑。它会根据约束的类型（值约束、范围约束等）和设备的能力来调整内部的 `PhotoSettings`，并更新“有效能力”。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **JavaScript:**
    *   `ImageCapture.setOptions(photoSettings)`:  例如，JavaScript 代码可以调用 `imageCapture.setOptions({ imageHeight: 720, imageWidth: 1280 })` 来设置捕获图像的分辨率。对应到这段 C++ 代码，会进入 `SetPhotoOptions` 方法，并检查 `photo_settings` 中的 `imageHeight` 和 `imageWidth` 是否在设备支持的范围内。
    *   `ImageCapture.grabFrame()`: JavaScript 调用 `imageCapture.grabFrame()` 会触发 C++ 中的 `grabFrame` 方法，从而捕获当前摄像头画面并返回一个 `Promise<ImageBitmap>`。
    *   `ImageCapture.getPhotoCapabilities()`: 虽然这段代码没有直接展示 `getPhotoCapabilities` 的处理，但 `UpdateAndCheckMediaTrackSettingsAndCapabilities` 和 `GotPhotoState` 方法在内部获取和处理设备能力信息，这些信息最终会通过 JavaScript 的 `getPhotoCapabilities()` 方法暴露出来。
    *   `ImageCapture.applyConstraints(constraints)`: JavaScript 调用 `imageCapture.applyConstraints({ advanced: [ { whiteBalanceMode: 'manual' } ] })` 来请求设置白平衡模式。对应的 C++ 代码会进入 `SetMediaTrackConstraints` 和 `CheckAndApplyMediaTrackConstraintsToSettings`，尝试将白平衡模式设置为手动。

*   **HTML:**
    *   `<video>` 元素通常用于显示摄像头预览，`ImageCapture` 对象就是基于 `MediaStreamTrack` 创建的，而这个 `MediaStreamTrack` 通常来自 `<video>` 元素关联的媒体流。
    *   `<canvas>` 元素可以用于绘制和处理通过 `grabFrame()` 获取的 `ImageBitmap` 对象。例如，可以将 `ImageBitmap` 绘制到 canvas 上，或者进行图像处理。
    *   `<img>` 元素可以用于显示通过 `takePhoto()`（虽然这段代码没有直接展示 `takePhoto`，但其原理与 `grabFrame` 类似）获取的图像数据。

*   **CSS:**
    *   CSS 可以用于控制 `<video>` 元素或显示捕获图像的元素的样式，例如大小、位置、边框等。CSS 本身不直接影响 `ImageCapture` 的功能逻辑。

**逻辑推理、假设输入与输出:**

**假设输入 (针对 `SetPhotoOptions`):**

*   `photo_settings` (来自 JavaScript): `{ imageHeight: 1080, imageWidth: 1920 }`
*   `photo_capabilities_` (设备能力):  `imageHeight: { min: 480, max: 1080 }, imageWidth: { min: 640, max: 1920 }`

**输出:**

*   `settings->has_height = true;`
*   `settings->height = 1080;`
*   `settings->has_width = true;`
*   `settings->width = 1920;`
*   Mojo 调用 `service_->SetPhotoOptions`，将包含这些设置的 `settings` 发送到设备。

**假设输入 (针对 `grabFrame`):**

*   `stream_track_` 处于活动状态。

**输出:**

*   创建一个 `ImageCaptureFrameGrabber` 对象 (如果尚未创建)。
*   调用 `frame_grabber_->GrabFrame`，请求抓取当前帧。
*   Promise 将会在帧抓取成功后 resolve，并返回一个 `ImageBitmap` 对象。

**用户或编程常见的使用错误:**

1. **设置超出设备能力的选项:** 用户尝试通过 `setOptions` 设置 `imageHeight` 为一个大于设备最大支持的值。
    *   **例如:** JavaScript 调用 `imageCapture.setOptions({ imageHeight: 2000 })`，而设备的 `photo_capabilities_.imageHeight().max()` 为 1920。
    *   **结果:** C++ 代码会检测到该设置超出范围，`resolver->Reject` 会被调用，Promise 将会被 rejected，并返回一个 `NotSupportedError` 类型的 `DOMException`，错误消息为 "imageHeight setting out of range"。

2. **在轨道未激活时抓取帧:** 用户在视频轨道已经停止后尝试调用 `grabFrame()`。
    *   **例如:** 用户停止了媒体流，然后调用 `imageCapture.grabFrame()`。
    *   **结果:** `TrackIsInactive(*stream_track_)` 会返回 true，`resolver->Reject` 会被调用，Promise 将会被 rejected，并返回一个 `InvalidStateError` 类型的 `DOMException`，错误消息为 "The track has been stopped"。

3. **错误地使用约束:** 用户设置了互相冲突或设备不支持的约束。
    *   **例如:** 设备只支持 "auto" 和 "single-shot" 的焦点模式，但用户尝试通过 `applyConstraints` 设置为 "continuous"。
    *   **结果:** `CheckAndApplyMediaTrackConstraintsToSettings` 会检测到该约束无法满足，`resolver->Reject` 可能会被调用，Promise 将会被 rejected，并返回一个 `OverconstrainedError` 类型的 `DOMException`。

**用户操作到达此处的步骤 (调试线索):**

1. 用户访问一个使用 WebRTC 或 Media Capture API 的网页。
2. 网页的 JavaScript 代码通过 `navigator.mediaDevices.getUserMedia()` 获取摄像头访问权限，并获得一个 `MediaStream` 对象。
3. 从 `MediaStream` 中获取视频轨 (`MediaStreamTrack`)。
4. 创建一个 `ImageCapture` 对象，并将视频轨传递给它：`const imageCapture = new ImageCapture(videoTrack);`。这会触发 `ImageCapture` 对象的构造函数。
5. 用户与网页交互，例如点击一个按钮来设置照片选项或抓取帧。
6. JavaScript 代码调用 `imageCapture.setOptions(options)`，这会触发 C++ 代码中的 `ImageCapture::SetPhotoOptions` 方法。
7. 或者，JavaScript 代码调用 `imageCapture.grabFrame()`，这会触发 C++ 代码中的 `ImageCapture::grabFrame` 方法。
8. 或者，JavaScript 代码调用 `imageCapture.applyConstraints(constraints)`，这会触发 C++ 代码中的 `ImageCapture::SetMediaTrackConstraints` 方法。

**这是第3部分，共4部分，所以此部分主要关注 `ImageCapture` 对象的核心功能实现，包括设置照片属性、抓取帧以及管理媒体轨道约束和能力。它处理了来自 JavaScript 的请求，并与底层的媒体服务进行交互，以实现图像捕获的功能。**

### 提示词
```
这是目录为blink/renderer/modules/imagecapture/image_capture.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
should be using a mojo::StructTraits instead.
  auto settings = media::mojom::blink::PhotoSettings::New();

  settings->has_height = photo_settings->hasImageHeight();
  if (settings->has_height) {
    const double height = photo_settings->imageHeight();
    if (photo_capabilities_ && photo_capabilities_->hasImageHeight() &&
        (height < photo_capabilities_->imageHeight()->min() ||
         height > photo_capabilities_->imageHeight()->max())) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "imageHeight setting out of range"));
      return promise;
    }
    settings->height = height;
  }
  settings->has_width = photo_settings->hasImageWidth();
  if (settings->has_width) {
    const double width = photo_settings->imageWidth();
    if (photo_capabilities_ && photo_capabilities_->hasImageWidth() &&
        (width < photo_capabilities_->imageWidth()->min() ||
         width > photo_capabilities_->imageWidth()->max())) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "imageWidth setting out of range"));
      return promise;
    }
    settings->width = width;
  }

  settings->has_red_eye_reduction = photo_settings->hasRedEyeReduction();
  if (settings->has_red_eye_reduction) {
    if (photo_capabilities_ && photo_capabilities_->hasRedEyeReduction() &&
        photo_capabilities_->redEyeReduction() !=
            V8RedEyeReduction::Enum::kControllable) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "redEyeReduction is not controllable."));
      return promise;
    }
    settings->red_eye_reduction = photo_settings->redEyeReduction();
  }

  settings->has_fill_light_mode = photo_settings->hasFillLightMode();
  if (settings->has_fill_light_mode) {
    auto fill_light_mode = photo_settings->fillLightMode();
    if (photo_capabilities_ && photo_capabilities_->hasFillLightMode() &&
        photo_capabilities_->fillLightMode().Find(fill_light_mode) ==
            kNotFound) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError, "Unsupported fillLightMode"));
      return promise;
    }
    settings->fill_light_mode = V8EnumToFillLightMode(fill_light_mode.AsEnum());
  }

  service_->SetPhotoOptions(
      SourceId(), std::move(settings),
      WTF::BindOnce(&ImageCapture::OnMojoSetPhotoOptions, WrapPersistent(this),
                    WrapPersistent(resolver), /*trigger_take_photo=*/true));
  return promise;
}

ScriptPromise<ImageBitmap> ImageCapture::grabFrame(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<ImageBitmap>>(script_state);
  auto promise = resolver->Promise();

  if (TrackIsInactive(*stream_track_)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, kInvalidStateTrackError));
    return promise;
  }

  // Create |m_frameGrabber| the first time.
  if (!frame_grabber_) {
    frame_grabber_ = std::make_unique<ImageCaptureFrameGrabber>();
  }

  if (!frame_grabber_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError, "Couldn't create platform resources"));
    return promise;
  }

  auto resolver_callback_adapter =
      std::make_unique<CallbackPromiseAdapter<ImageBitmap, void>>(resolver);
  frame_grabber_->GrabFrame(stream_track_->Component(),
                            std::move(resolver_callback_adapter),
                            ExecutionContext::From(script_state)
                                ->GetTaskRunner(TaskType::kDOMManipulation),
                            grab_frame_timeout_);

  return promise;
}

void ImageCapture::UpdateAndCheckMediaTrackSettingsAndCapabilities(
    base::OnceCallback<void(bool)> callback) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::UpdateAndCheckMediaTrackSettingsAndCapabilities");
  service_->GetPhotoState(
      stream_track_->Component()->Source()->Id(),
      WTF::BindOnce(&ImageCapture::GotPhotoState, WrapPersistent(this),
                    std::move(callback)));
}

void ImageCapture::GotPhotoState(
    base::OnceCallback<void(bool)> callback,
    media::mojom::blink::PhotoStatePtr photo_state) {
  MediaTrackSettings* settings = MediaTrackSettings::Create();
  MediaTrackCapabilities* capabilities = MediaTrackCapabilities::Create();

  // Take a snapshot of local track settings and capabilities.
  CopySettings(settings_, settings, CopyPanTiltZoom(true));
  CopyCapabilities(capabilities_, capabilities, CopyPanTiltZoom(true));

  // Update local track settings and capabilities.
  UpdateMediaTrackSettingsAndCapabilities(base::DoNothing(),
                                          std::move(photo_state));

  // Check whether background blur settings and capabilities have changed.
  if (settings_->hasBackgroundBlur() != settings->hasBackgroundBlur() ||
      (settings_->hasBackgroundBlur() &&
       settings_->backgroundBlur() != settings->backgroundBlur()) ||
      capabilities_->hasBackgroundBlur() != capabilities->hasBackgroundBlur() ||
      (capabilities_->hasBackgroundBlur() &&
       capabilities_->backgroundBlur() != capabilities->backgroundBlur())) {
    std::move(callback).Run(true);
    return;
  }

  // Check whether face framing settings and capabilities have changed.
  if (settings_->hasFaceFraming() != settings->hasFaceFraming() ||
      (settings_->hasFaceFraming() &&
       settings_->faceFraming() != settings->faceFraming()) ||
      capabilities_->hasFaceFraming() != capabilities->hasFaceFraming() ||
      (capabilities_->hasFaceFraming() &&
       capabilities_->faceFraming() != capabilities->faceFraming())) {
    std::move(callback).Run(true);
    return;
  }

  std::move(callback).Run(false);
}

bool ImageCapture::CheckAndApplyMediaTrackConstraintsToSettings(
    media::mojom::blink::PhotoSettings* settings,
    const MediaTrackConstraints* constraints,
    ScriptPromiseResolverBase* resolver) const {
  if (!IsPageVisible()) {
    for (const MediaTrackConstraintSet* constraint_set :
         AllConstraintSets(constraints)) {
      if ((constraint_set->hasPan() &&
           !IsBooleanFalseConstraint(constraint_set->pan())) ||
          (constraint_set->hasTilt() &&
           !IsBooleanFalseConstraint(constraint_set->tilt())) ||
          (constraint_set->hasZoom() &&
           !IsBooleanFalseConstraint(constraint_set->zoom()))) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kSecurityError, "the page is not visible"));
        return false;
      }
    }
  }

  // The "effective capability" C of an object O as the possibly proper subset
  // of the possible values of C (as returned by getCapabilities) taking into
  // consideration environmental limitations and/or restrictions placed by
  // other constraints.
  // https://w3c.github.io/mediacapture-main/#dfn-fitness-distance
  // More definitions
  auto* effective_capabilities = MediaTrackCapabilities::Create();
  CopyCapabilities(capabilities_, effective_capabilities,
                   CopyPanTiltZoom(HasPanTiltZoomPermissionGranted()));

  // There is no capability for `pointsOfInterest` in `MediaTrackCapabilities`
  // to be used as a storage for an effective capability for `pointsOfInterest`.
  // There is a capability for `torch` in `MediaTrackCapabilities` but it is
  // a boolean instead of a sequence of booleans so not suitable to be used as
  // a storage for an effective capability for `torch`.
  // As a substitute, we use `MediaTrackSettings` and its `pointsOfInterest`
  // `torch` fields to convey restrictions placed by previous exact
  // `pointsOfInterest` and `torch` constraints.
  auto* effective_settings = MediaTrackSettings::Create();

  for (const MediaTrackConstraintSet* constraint_set :
       AllConstraintSets(constraints)) {
    const MediaTrackConstraintSetType constraint_set_type =
        GetMediaTrackConstraintSetType(constraint_set, constraints);
    const bool may_reject =
        MayRejectWithOverconstrainedError(constraint_set_type);
    if (CheckMediaTrackConstraintSet(effective_capabilities, effective_settings,
                                     constraint_set, constraint_set_type,
                                     may_reject ? resolver : nullptr)) {
      ApplyMediaTrackConstraintSetToSettings(&*settings, effective_capabilities,
                                             effective_settings, constraint_set,
                                             constraint_set_type);
    } else if (may_reject) {
      return false;
    }
  }

  return true;
}

void ImageCapture::GetMediaTrackCapabilities(
    MediaTrackCapabilities* capabilities) const {
  // Merge any present |capabilities_| members into |capabilities|.
  CopyCapabilities(capabilities_, capabilities,
                   CopyPanTiltZoom(HasPanTiltZoomPermissionGranted()));
}

// TODO(mcasas): make the implementation fully Spec compliant, see the TODOs
// inside the method, https://crbug.com/708723.
void ImageCapture::SetMediaTrackConstraints(
    ScriptPromiseResolverBase* resolver,
    const MediaTrackConstraints* constraints) {
  DCHECK(constraints);

  ExecutionContext* context = GetExecutionContext();
  for (const MediaTrackConstraintSet* constraint_set :
       AllConstraintSets(constraints)) {
    if (constraint_set->hasWhiteBalanceMode()) {
      UseCounter::Count(context, WebFeature::kImageCaptureWhiteBalanceMode);
    }
    if (constraint_set->hasExposureMode()) {
      UseCounter::Count(context, WebFeature::kImageCaptureExposureMode);
    }
    if (constraint_set->hasFocusMode()) {
      UseCounter::Count(context, WebFeature::kImageCaptureFocusMode);
    }
    if (constraint_set->hasPointsOfInterest()) {
      UseCounter::Count(context, WebFeature::kImageCapturePointsOfInterest);
    }
    if (constraint_set->hasExposureCompensation()) {
      UseCounter::Count(context, WebFeature::kImageCaptureExposureCompensation);
    }
    if (constraint_set->hasExposureTime()) {
      UseCounter::Count(context, WebFeature::kImageCaptureExposureTime);
    }
    if (constraint_set->hasColorTemperature()) {
      UseCounter::Count(context, WebFeature::kImageCaptureColorTemperature);
    }
    if (constraint_set->hasIso()) {
      UseCounter::Count(context, WebFeature::kImageCaptureIso);
    }
    if (constraint_set->hasBrightness()) {
      UseCounter::Count(context, WebFeature::kImageCaptureBrightness);
    }
    if (constraint_set->hasContrast()) {
      UseCounter::Count(context, WebFeature::kImageCaptureContrast);
    }
    if (constraint_set->hasSaturation()) {
      UseCounter::Count(context, WebFeature::kImageCaptureSaturation);
    }
    if (constraint_set->hasSharpness()) {
      UseCounter::Count(context, WebFeature::kImageCaptureSharpness);
    }
    if (constraint_set->hasFocusDistance()) {
      UseCounter::Count(context, WebFeature::kImageCaptureFocusDistance);
    }
    if (constraint_set->hasPan()) {
      UseCounter::Count(context, WebFeature::kImageCapturePan);
    }
    if (constraint_set->hasTilt()) {
      UseCounter::Count(context, WebFeature::kImageCaptureTilt);
    }
    if (constraint_set->hasZoom()) {
      UseCounter::Count(context, WebFeature::kImageCaptureZoom);
    }
    if (constraint_set->hasTorch()) {
      UseCounter::Count(context, WebFeature::kImageCaptureTorch);
    }
    if (RuntimeEnabledFeatures::MediaCaptureBackgroundBlurEnabled(context) &&
        constraint_set->hasBackgroundBlur()) {
      UseCounter::Count(context, WebFeature::kImageCaptureBackgroundBlur);
    }
  }

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotFoundError, kNoServiceError));
    return;
  }

  auto settings = media::mojom::blink::PhotoSettings::New();

  if (!CheckAndApplyMediaTrackConstraintsToSettings(&*settings, constraints,
                                                    resolver)) {
    return;
  }

  // TODO(crbug.com/1423282): This is not spec compliant. The current
  // constraints are used by `GetMediaTrackConstraints()` which is used by
  // `MediaStreamTrackImpl::getConstraints()` which should return
  // the constraints that were the argument to the most recent successful
  // invocation of the ApplyConstraints algorithm.
  // https://w3c.github.io/mediacapture-main/#dom-constrainablepattern-getconstraints
  //
  // At this point the ApplyConstraints algorithm is still ongoing and not
  // succeeded yet. Move this to `OnMojoSetPhotoOptions()` or such.
  current_constraints_ = MediaTrackConstraints::Create();
  CopyConstraints(constraints, current_constraints_);

  service_requests_.insert(resolver);

  service_->SetPhotoOptions(
      SourceId(), std::move(settings),
      WTF::BindOnce(&ImageCapture::OnMojoSetPhotoOptions, WrapPersistent(this),
                    WrapPersistent(resolver), /*trigger_take_photo=*/false));
}

void ImageCapture::SetVideoTrackDeviceSettingsFromTrack(
    base::OnceClosure initialized_callback,
    media::mojom::blink::PhotoStatePtr photo_state) {
  UpdateMediaTrackSettingsAndCapabilities(base::DoNothing(),
                                          std::move(photo_state));

  auto* video_track = MediaStreamVideoTrack::From(stream_track_->Component());
  DCHECK(video_track);

  const auto& device_settings = video_track->image_capture_device_settings();

  if (device_settings) {
    ExecutionContext* context = GetExecutionContext();
    if (device_settings->exposure_compensation.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureExposureCompensation);
    }
    if (device_settings->exposure_time.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureExposureTime);
    }
    if (device_settings->color_temperature.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureColorTemperature);
    }
    if (device_settings->iso.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureIso);
    }
    if (device_settings->brightness.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureBrightness);
    }
    if (device_settings->contrast.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureContrast);
    }
    if (device_settings->saturation.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureSaturation);
    }
    if (device_settings->sharpness.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureSharpness);
    }
    if (device_settings->focus_distance.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureFocusDistance);
    }
    if (device_settings->pan.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCapturePan);
    }
    if (device_settings->tilt.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureTilt);
    }
    if (device_settings->zoom.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureZoom);
    }
    if (device_settings->torch.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureTorch);
    }
    if (device_settings->background_blur.has_value()) {
      UseCounter::Count(context, WebFeature::kImageCaptureBackgroundBlur);
    }

    auto settings = media::mojom::blink::PhotoSettings::New();

    if (device_settings->exposure_compensation.has_value() &&
        capabilities_->hasExposureCompensation()) {
      MaybeSetDoubleSetting(*device_settings->exposure_compensation,
                            *capabilities_->exposureCompensation(),
                            settings->has_exposure_compensation,
                            settings->exposure_compensation);
    }
    if (device_settings->exposure_time.has_value() &&
        capabilities_->hasExposureTime()) {
      MaybeSetDoubleSetting(
          *device_settings->exposure_time, *capabilities_->exposureTime(),
          settings->has_exposure_time, settings->exposure_time);
    }
    if (device_settings->color_temperature.has_value() &&
        capabilities_->hasColorTemperature()) {
      MaybeSetDoubleSetting(*device_settings->color_temperature,
                            *capabilities_->colorTemperature(),
                            settings->has_color_temperature,
                            settings->color_temperature);
    }
    if (device_settings->iso.has_value() && capabilities_->hasIso()) {
      MaybeSetDoubleSetting(*device_settings->iso, *capabilities_->iso(),
                            settings->has_iso, settings->iso);
    }
    if (device_settings->brightness.has_value() &&
        capabilities_->hasBrightness()) {
      MaybeSetDoubleSetting(*device_settings->brightness,
                            *capabilities_->brightness(),
                            settings->has_brightness, settings->brightness);
    }
    if (device_settings->contrast.has_value() && capabilities_->hasContrast()) {
      MaybeSetDoubleSetting(*device_settings->contrast,
                            *capabilities_->contrast(), settings->has_contrast,
                            settings->contrast);
    }
    if (device_settings->saturation.has_value() &&
        capabilities_->hasSaturation()) {
      MaybeSetDoubleSetting(*device_settings->saturation,
                            *capabilities_->saturation(),
                            settings->has_saturation, settings->saturation);
    }
    if (device_settings->sharpness.has_value() &&
        capabilities_->hasSharpness()) {
      MaybeSetDoubleSetting(*device_settings->sharpness,
                            *capabilities_->sharpness(),
                            settings->has_sharpness, settings->sharpness);
    }
    if (device_settings->focus_distance.has_value() &&
        capabilities_->hasFocusDistance()) {
      MaybeSetDoubleSetting(
          *device_settings->focus_distance, *capabilities_->focusDistance(),
          settings->has_focus_distance, settings->focus_distance);
    }
    if (HasPanTiltZoomPermissionGranted()) {
      if (device_settings->pan.has_value() && capabilities_->hasPan()) {
        MaybeSetDoubleSetting(*device_settings->pan, *capabilities_->pan(),
                              settings->has_pan, settings->pan);
      }
      if (device_settings->tilt.has_value() && capabilities_->hasTilt()) {
        MaybeSetDoubleSetting(*device_settings->tilt, *capabilities_->tilt(),
                              settings->has_tilt, settings->tilt);
      }
      if (device_settings->zoom.has_value() && capabilities_->hasZoom()) {
        MaybeSetDoubleSetting(*device_settings->zoom, *capabilities_->zoom(),
                              settings->has_zoom, settings->zoom);
      }
    }
    if (device_settings->torch.has_value() && capabilities_->hasTorch()) {
      MaybeSetBoolSetting(
          *device_settings->torch,
          capabilities_->torch() ? Vector<bool>({false, true}) : Vector<bool>(),
          settings->has_torch, settings->torch);
    }
    if (device_settings->background_blur.has_value() &&
        capabilities_->hasBackgroundBlur()) {
      MaybeSetBackgroundBlurSetting(
          *device_settings->background_blur, capabilities_->backgroundBlur(),
          settings->has_background_blur_mode, settings->background_blur_mode);
    }
    if (device_settings->background_segmentation_mask.has_value() &&
        capabilities_->hasBackgroundSegmentationMask()) {
      MaybeSetBoolSetting(*device_settings->background_segmentation_mask,
                          capabilities_->backgroundSegmentationMask(),
                          settings->background_segmentation_mask_state);
    }
    if (device_settings->eye_gaze_correction.has_value() &&
        capabilities_->hasEyeGazeCorrection()) {
      MaybeSetEyeGazeCorrectionSetting(*device_settings->eye_gaze_correction,
                                       capabilities_->eyeGazeCorrection(),
                                       settings->eye_gaze_correction_mode);
    }
    if (device_settings->face_framing.has_value() &&
        capabilities_->hasFaceFraming()) {
      MaybeSetFaceFramingSetting(
          *device_settings->face_framing, capabilities_->faceFraming(),
          settings->has_face_framing_mode, settings->face_framing_mode);
    }

    if (service_.is_bound() &&
        (settings->has_exposure_compensation || settings->has_exposure_time ||
         settings->has_color_temperature || settings->has_iso ||
         settings->has_brightness || settings->has_contrast ||
         settings->has_saturation || settings->has_sharpness ||
         settings->has_focus_distance || settings->has_pan ||
         settings->has_tilt || settings->has_zoom || settings->has_torch ||
         settings->has_background_blur_mode ||
         settings->has_face_framing_mode ||
         settings->eye_gaze_correction_mode.has_value() ||
         settings->background_segmentation_mask_state.has_value())) {
      service_->SetPhotoOptions(
          SourceId(), std::move(settings),
          WTF::BindOnce(&ImageCapture::OnSetVideoTrackDeviceSettingsFromTrack,
                        WrapPersistent(this), std::move(initialized_callback)));
      return;
    }
  }

  std::move(initialized_callback).Run();
}

void ImageCapture::OnSetVideoTrackDeviceSettingsFromTrack(
    base::OnceClosure done_callback,
    bool result) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::OnSetVideoTrackDeviceSettingsFromTrack");
  service_->GetPhotoState(
      SourceId(),
      WTF::BindOnce(&ImageCapture::UpdateMediaTrackSettingsAndCapabilities,
                    WrapPersistent(this), std::move(done_callback)));
}

MediaTrackConstraints* ImageCapture::GetMediaTrackConstraints() const {
  return current_constraints_.Get();
}

void ImageCapture::ClearMediaTrackConstraints() {
  current_constraints_ = nullptr;

  // TODO(mcasas): Clear also any PhotoSettings that the device might have got
  // configured, for that we need to know a "default" state of the device; take
  // a snapshot upon first opening. https://crbug.com/700607.
}

void ImageCapture::GetMediaTrackSettings(MediaTrackSettings* settings) const {
  // Merge any present |settings_| members into |settings|.
  CopySettings(settings_, settings,
               CopyPanTiltZoom(HasPanTiltZoomPermissionGranted()));
}

ImageCapture::ImageCapture(ExecutionContext* context,
                           MediaStreamTrack* track,
                           bool pan_tilt_zoom_allowed,
                           base::OnceClosure initialized_callback,
                           base::TimeDelta grab_frame_timeout)
    : ExecutionContextLifecycleObserver(context),
      stream_track_(track),
      service_(context),
      pan_tilt_zoom_permission_(pan_tilt_zoom_allowed
                                    ? mojom::blink::PermissionStatus::GRANTED
                                    : mojom::blink::PermissionStatus::ASK),
      permission_service_(context),
      permission_observer_receiver_(this, context),
      capabilities_(MediaTrackCapabilities::Create()),
      settings_(MediaTrackSettings::Create()),
      photo_settings_(PhotoSettings::Create()),
      grab_frame_timeout_(grab_frame_timeout) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::CreateImageCapture");
  DCHECK(stream_track_);
  DCHECK(!service_.is_bound());
  DCHECK(!permission_service_.is_bound());

  // This object may be constructed over an ExecutionContext that has already
  // been detached. In this case the ImageCapture service will not be available.
  if (!DomWindow())
    return;

  DomWindow()->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(
          context->GetTaskRunner(TaskType::kDOMManipulation)));

  service_.set_disconnect_handler(WTF::BindOnce(
      &ImageCapture::OnServiceConnectionError, WrapWeakPersistent(this)));

  // Launch a retrieval of the current photo state, which arrive asynchronously
  // to avoid blocking the main UI thread.
  service_->GetPhotoState(
      SourceId(),
      WTF::BindOnce(&ImageCapture::SetVideoTrackDeviceSettingsFromTrack,
                    WrapPersistent(this), std::move(initialized_callback)));

  ConnectToPermissionService(
      context, permission_service_.BindNewPipeAndPassReceiver(
                   context->GetTaskRunner(TaskType::kMiscPlatformAPI)));

  mojo::PendingRemote<mojom::blink::PermissionObserver> observer;
  permission_observer_receiver_.Bind(
      observer.InitWithNewPipeAndPassReceiver(),
      context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  permission_service_->AddPermissionObserver(
      CreateVideoCapturePermissionDescriptor(/*pan_tilt_zoom=*/true),
      pan_tilt_zoom_permission_, std::move(observer));
}

// TODO(crbug.com/708723): Integrate image capture constraints processing with
// the main implementation and remove this support function.
void ImageCapture::ApplyMediaTrackConstraintSetToSettings(
    media::mojom::blink::PhotoSettings* settings,
    MediaTrackCapabilities* effective_capabilities,
    MediaTrackSettings* effective_settings,
    const MediaTrackConstraintSet* constraint_set,
    MediaTrackConstraintSetType constraint_set_type) const {
  // Apply value constraints to photo settings and update effective
  // capabilities.
  //
  // Roughly the SelectSettings algorithm steps 3 and 5.
  // https://www.w3.org/TR/mediacapture-streams/#dfn-selectsettings
  if (constraint_set->hasWhiteBalanceMode() &&
      effective_capabilities->hasWhiteBalanceMode()) {
    effective_capabilities->setWhiteBalanceMode(ApplyValueConstraint(
        &settings->has_white_balance_mode, &settings->white_balance_mode,
        effective_capabilities->whiteBalanceMode(),
        constraint_set->whiteBalanceMode(), constraint_set_type,
        settings_->whiteBalanceMode()));
  }
  if (constraint_set->hasExposureMode() &&
      effective_capabilities->hasExposureMode()) {
    effective_capabilities->setExposureMode(ApplyValueConstraint(
        &settings->has_exposure_mode, &settings->exposure_mode,
        effective_capabilities->exposureMode(), constraint_set->exposureMode(),
        constraint_set_type, settings_->exposureMode()));
  }
  if (constraint_set->hasFocusMode() &&
      effective_capabilities->hasFocusMode()) {
    effective_capabilities->setFocusMode(ApplyValueConstraint(
        &settings->has_focus_mode, &settings->focus_mode,
        effective_capabilities->focusMode(), constraint_set->focusMode(),
        constraint_set_type, settings_->focusMode()));
  }
  if (constraint_set->hasPointsOfInterest()) {
    // There is no |settings->has_points_of_interest|.
    bool has_points_of_interest = !settings->points_of_interest.empty();
    std::optional new_effective_setting = ApplyValueConstraint(
        &has_points_of_interest, &settings->points_of_interest,
        effective_settings->hasPointsOfInterest()
            ? &effective_settings->pointsOfInterest()
            : nullptr,
        constraint_set->pointsOfInterest(), constraint_set_type);
    if (new_effective_setting) {
      effective_settings->setPointsOfInterest(*new_effective_setting);
    }
  }
  if (constraint_set->hasExposureCompensation() &&
      effective_capabilities->hasExposureCompensation()) {
    effective_capabilities->setExposureCompensation(ApplyValueConstraint(
        &settings->has_exposure_compensation, &settings->exposure_compensation,
        effective_capabilities->exposureCompensation(),
        constraint_set->exposureCompensation(), constraint_set_type,
        settings_->exposureCompensation()));
  }
  if (constraint_set->hasExposureTime() &&
      effective_capabilities->hasExposureTime()) {
    effective_capabilities->setExposureTime(ApplyValueConstraint(
        &settings->has_exposure_time, &settings->exposure_time,
        effective_capabilities->exposureTime(), constraint_set->exposureTime(),
        constraint_set_type, settings_->exposureTime()));
  }
  if (constraint_set->hasColorTemperature() &&
      effective_capabilities->hasColorTemperature()) {
    effective_capabilities->setColorTemperature(ApplyValueConstraint(
        &settings->has_color_temperature, &settings->color_temperature,
        effective_capabilities->colorTemperature(),
        constraint_set->colorTemperature(), constraint_set_type,
        settings_->colorTemperature()));
  }
  if (constraint_set->hasIso() && effective_capabilities->hasIso()) {
    effective_capabilities->setIso(ApplyValueConstraint(
        &settings->has_iso, &settings->iso, effective_capabilities->iso(),
        constraint_set->iso(), constraint_set_type, settings_->iso()));
  }
  if (constraint_set->hasBrightness() &&
      effective_capabilities->hasBrightness()) {
    effective_capabilities->setBrightness(ApplyValueConstraint(
        &settings->has_brightness, &settings->brightness,
        effective_capabilities->brightness(), constraint_set->brightness(),
        constraint_set_type, settings_->brightness()));
  }
  if (constraint_set->hasContrast() && effective_capabilities->hasContrast()) {
    effective_capabilities->setContrast(ApplyValueConstraint(
        &settings->has_contrast, &settings->contrast,
        effective_capabilities->contrast(), constraint_set->contrast(),
        constraint_set_type, settings_->contrast()));
  }
  if (constraint_set->hasSaturation() &&
      effective_capabilities->hasSaturation()) {
    effective_capabilities->setSaturation(ApplyValueConstraint(
        &settings->has_saturation, &settings->saturation,
        effective_capabilities->saturation(), constraint_set->saturation(),
        constraint_set_type, settings_->saturation()));
  }
  if (constraint_set->hasSharpness() &&
      effective_capabilities->hasSharpness()) {
    effective_capabilities->setSharpness(ApplyValueConstraint(
        &settings->has_sharpness, &settings->sharpness,
        effective_capabilities->sharpness(), constraint_set->sharpness(),
        constraint_set_type, settings_->sharpness()));
  }
  if (constraint_set->hasFocusDistance() &&
      effective_capabilities->hasFocusDistance()) {
    effective_capabilities->setFocusDistance(ApplyValueConstraint(
        &settings->has_focus_distance, &settings->focus_distance,
        effective_capabilities->focusDistance(),
        constraint_set->focusDistance(), constraint_set_type,
        settings_->focusDistance()));
  }
  if (constraint_set->hasPan() && effective_capabilities->hasPan()) {
    effective_capabilities->setPan(ApplyValueConstraint(
        &settings->has_pan, &settings->pan, effective_capabilities->pan(),
        constraint_set->pan(), constraint_set_type, settings_->pan()));
  }
  if (constraint_set->hasTilt() && effective_capabilities->hasTilt()) {
    effective_capabilities->setTilt(ApplyValueConstraint(
        &settings->has_tilt, &settings->tilt, effective_capabilities->tilt(),
        constraint_set->tilt(), constraint_set_type, settings_->tilt()));
  }
  if (constraint_set->hasZoom() && effective_capabilities->hasZoom()) {
    effective_capabilities->setZoom(ApplyValueConstraint(
        &settings->has_zoom, &settings->zoom, effective_capabilities->zoom(),
        constraint_set->zoom(), constraint_set_type, settings_->zoom()));
  }
  if (constraint_set->hasTorch() && effective_capabilities->hasTorch() &&
      effective_capabilities->torch()) {
    const auto& new_effective_capability =
        ApplyValueConstraint(&settings->has_torch, &settings->torch,
                             effective_settings->hasTorch()
                                 ? Vector<bool>({effective_settings->torch()})
                                 : Vector<bool>({false, true}),
                             constraint_set->torch(), constraint_set_type);
    if (new_effective_capability.size() == 1u) {
      effective_settings->setTorch(new_effective_capability[0]);
    }
  }
  if (constraint_set->hasBackgroundBlur() &&
      effective_capabilities->hasBackgroundBlur()) {
    bool has_setting = false;
    bool setting;
    effective_capabilities->setBackgroundBlur(ApplyValueConstraint(
        &has_setting, &setting, effective_capabilities->backgroundBlur(),
        constraint_set->backgroundBlur(), constraint_set_type));
    if (has_setting) {
      settings->has_background_blur_mode = true;
      settings->background_blur_mode = ParseBackgroundBlur(setting);
    }
  }
  if (constraint_set->hasBackgroundSegmentationMask() &&
      effective_capabilities->hasBackgroundSegmentationMask()) {
    bool has_setting = false;
    bool setting;
    effective_ca
```