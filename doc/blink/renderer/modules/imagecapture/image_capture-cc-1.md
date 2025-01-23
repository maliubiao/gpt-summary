Response:
The user wants a summary of the functionality of the provided C++ code snippet from `image_capture.cc`. This is the second part of a four-part chunk.

Here's a plan:
1. **Identify the core functionalities** within this code snippet. The code primarily deals with constraint checking and application for various media settings related to image capture.
2. **Explain the relationship to web technologies (JavaScript, HTML, CSS)**. ImageCapture is a JavaScript API, so this C++ code is the underlying implementation of that API.
3. **Provide examples of logical reasoning with input and output**. Focus on the constraint checking functions, showcasing how they validate constraints against available capabilities.
4. **Illustrate common user or programming errors**. These often involve providing invalid constraint values or combinations.
5. **Describe how a user might reach this code**. This involves using the ImageCapture API in JavaScript.
6. **Summarize the functionality of this specific part of the code**. Focus on constraint handling.
这是 `blink/renderer/modules/imagecapture/image_capture.cc` 文件的一部分，主要负责**处理和应用图像捕获的各种约束条件 (constraints)**。它实现了 W3C Media Capture and Streams 规范中关于 `ImageCapture` API 的部分功能，特别是关于如何比较和应用用户指定的约束和设备实际能力。

**功能归纳 (针对提供的代码片段):**

1. **约束检查 (Constraint Checking):**
   - 提供了一系列名为 `CheckValueConstraint` 的函数，用于检查用户提供的约束是否与设备的能力兼容。
   - 这些函数针对不同的数据类型和约束类型（例如，精确值、范围、布尔值、字符串等）进行检查。
   - 这些检查会考虑不同类型的约束集 (`MediaTrackConstraintSetType`)，例如 "basic" 或 "advanced"。

2. **约束应用 (Constraint Application):**
   - 提供了一系列名为 `ApplyValueConstraint` 的函数，用于将用户提供的约束应用到设备的实际能力上，从而确定最终的设置值。
   - 这些函数也针对不同的数据类型和约束类型进行处理。
   - 其中包括处理精确约束 (`exact`) 和理想约束 (`ideal`) 的逻辑。

3. **辅助功能:**
   - 提供了一些辅助函数，例如 `ApplyExactValueConstraint` 和 `ApplyIdealValueConstraint`，分别用于应用精确值和理想值约束。
   - 提供了一些 `MaybeSet...Setting` 的函数，用于根据能力值来设置特定的设置项。

**与 JavaScript, HTML, CSS 的关系:**

`ImageCapture` API 是一个 JavaScript API，允许网页从媒体流（通常是摄像头）捕获图像。这段 C++ 代码是浏览器引擎 Blink 对这个 API 的底层实现。

* **JavaScript:**  JavaScript 代码会调用 `ImageCapture` API 的方法，例如 `getPhotoCapabilities()` 和 `takePhoto()`，并在调用时可以传入 `PhotoSettings` 对象来指定各种约束。例如：

   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(stream => {
       const track = stream.getVideoTracks()[0];
       const imageCapture = new ImageCapture(track);

       imageCapture.getPhotoCapabilities()
         .then(capabilities => {
           console.log('Photo Capabilities:', capabilities);
         });

       const photoSettings = {
         imageWidth: { min: 640, ideal: 1280 },
         fillLightMode: 'flash'
       };

       imageCapture.takePhoto(photoSettings)
         .then(blob => {
           // 处理捕获到的图像
         })
         .catch(error => console.error('Error taking photo:', error));
     });
   ```

   在这个例子中，`photoSettings` 对象中 `imageWidth` 和 `fillLightMode` 就代表了用户通过 JavaScript 指定的约束。这段 C++ 代码会接收并处理这些约束。

* **HTML:** HTML 主要用于构建网页结构，包含了调用 JavaScript 代码的 `<script>` 标签。用户操作（例如点击按钮触发拍照）会间接导致 JavaScript 代码执行，进而触发对 `ImageCapture` API 的调用。

* **CSS:** CSS 负责网页的样式，与 `ImageCapture` API 的核心功能没有直接关系。但是，CSS 可以用于控制用户界面元素，这些元素可能触发与图像捕获相关的 JavaScript 代码。

**逻辑推理举例 (假设输入与输出):**

**假设输入:**

* **设备能力 (effective_capability):**  对于 `whiteBalanceMode` 可能支持 `["auto", "manual"]`。
* **用户约束 (constraint):**  `{ exact: "manual" }`。
* **约束类型 (constraint_set_type):** `MediaTrackConstraintSetType::kBasic`。

**`CheckValueConstraint` 函数的逻辑推理:**

1. 函数接收设备能力 `["auto", "manual"]` 和约束 `{ exact: "manual" }`。
2. 识别出约束类型是精确值约束 (`hasExact()` 为真)。
3. 检查用户指定的精确值 `"manual"` 是否包含在设备能力中。
4. 由于 `"manual"` 在 `["auto", "manual"]` 中，函数返回 `true`。

**`ApplyValueConstraint` 函数的逻辑推理:**

1. 函数接收设备能力 `["auto", "manual"]` 和约束 `{ exact: "manual" }`。
2. 识别出是精确值约束。
3. 调用 `ApplyExactValueConstraint`。
4. `ApplyExactValueConstraint` 将设置 `whiteBalanceMode` 为 `"manual"`，并返回新的有效能力 `["manual"]`。

**用户或编程常见的使用错误举例:**

1. **指定了设备不支持的精确约束:**

   ```javascript
   const photoSettings = { whiteBalanceMode: { exact: "sunny" } }; // 假设设备不支持 "sunny"
   ```
   这段 C++ 代码的 `CheckValueConstraint` 函数会检测到 `"sunny"` 不在设备支持的 `whiteBalanceMode` 列表中，从而可能导致 `takePhoto()` 方法失败或返回一个不满足约束的设置。

2. **指定了自相矛盾的范围约束:**

   ```javascript
   const photoSettings = { zoom: { min: 5, max: 2 } };
   ```
   这段 C++ 代码的 `CheckValueConstraint` 函数会检测到 `min` 大于 `max`，从而拒绝这个约束。

**用户操作到达这里的步骤 (调试线索):**

1. **用户打开一个包含使用 `ImageCapture` API 的 JavaScript 代码的网页。**
2. **网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 获取媒体流（摄像头）。**
3. **JavaScript 代码使用媒体流的视频轨道创建一个 `ImageCapture` 对象。**
4. **JavaScript 代码调用 `imageCapture.getPhotoCapabilities()` 或 `imageCapture.takePhoto(photoSettings)`，并传入包含约束的 `PhotoSettings` 对象。**
5. **浏览器引擎 (Blink) 接收到 JavaScript 的调用，并开始执行 `ImageCapture` 类的相应 C++ 方法。**
6. **在 `getPhotoCapabilities()` 的实现中，会获取设备的硬件能力信息，并将其封装成 `PhotoCapabilities` 对象返回给 JavaScript。**
7. **在 `takePhoto(photo_settings)` 的实现中，这段 C++ 代码会被调用来检查和应用 `photo_settings` 中指定的约束，以确定最终的拍照参数。**
8. **如果在约束检查或应用过程中出现问题，可能会抛出异常或返回错误，这可以在浏览器的开发者工具中观察到。**

总而言之，这段代码是 Chromium 浏览器 Blink 引擎中处理 `ImageCapture` API 约束的核心部分，负责验证用户指定的拍照参数是否可行，并根据约束调整设备的设置。

### 提示词
```
这是目录为blink/renderer/modules/imagecapture/image_capture.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
constraint, constraint_set_type)) {
    return true;
  }
  using ContentType = V8UnionConstrainDoubleRangeOrDouble::ContentType;
  switch (constraint->GetContentType()) {
    case ContentType::kDouble:
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        return CheckExactValueConstraint(effective_capability,
                                         constraint->GetAsDouble());
      }
      return true;
    case ContentType::kConstrainDoubleRange: {
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      const auto* dictionary_constraint =
          constraint->GetAsConstrainDoubleRange();
      if (dictionary_constraint->hasExact()) {
        const double exact_constraint = dictionary_constraint->exact();
        if (dictionary_constraint->hasMax() &&
            exact_constraint > dictionary_constraint->max()) {
          return false;  // Reject self-contradiction.
        }
        if (dictionary_constraint->hasMin() &&
            exact_constraint < dictionary_constraint->min()) {
          return false;  // Reject self-contradiction.
        }
        if (!CheckExactValueConstraint(effective_capability,
                                       exact_constraint)) {
          return false;
        }
      }
      if (dictionary_constraint->hasMax()) {
        const double max_constraint = dictionary_constraint->max();
        if (dictionary_constraint->hasMin() &&
            max_constraint < dictionary_constraint->min()) {
          return false;  // Reject self-contradiction.
        }
        if (effective_capability->hasMin() &&
            max_constraint < effective_capability->min()) {
          return false;
        }
      }
      if (dictionary_constraint->hasMin()) {
        const double min_constraint = dictionary_constraint->min();
        if (effective_capability->hasMax() &&
            min_constraint > effective_capability->max()) {
          return false;
        }
      }
      return true;
    }
  }
}

// For `(boolean or ConstrainDouble)` constraints and `MediaSettingsRange`
// effective capabilities such as pan, tilt and zoom.
bool CheckValueConstraint(
    const MediaSettingsRange* effective_capability,
    const V8UnionBooleanOrConstrainDoubleRangeOrDouble* constraint,
    MediaTrackConstraintSetType constraint_set_type) {
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    return true;
  }
  // We classify boolean constraints for double constrainable properties as
  // existence constraints instead of as value constraints.
  DCHECK(!constraint->IsBoolean());
  return CheckValueConstraint(
      effective_capability,
      constraint->GetAsV8UnionConstrainDoubleRangeOrDouble(),
      constraint_set_type);
}

// For `ConstrainBoolean` constraints and `sequence<boolean>` effective
// capabilities such as torch and backgroundBlur.
bool CheckValueConstraint(
    const Vector<bool>& effective_capability,
    const V8UnionBooleanOrConstrainBooleanParameters* constraint,
    MediaTrackConstraintSetType constraint_set_type) {
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    return true;
  }
  using ContentType = V8UnionBooleanOrConstrainBooleanParameters::ContentType;
  switch (constraint->GetContentType()) {
    case ContentType::kBoolean:
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        const bool exact_constraint = constraint->GetAsBoolean();
        return base::Contains(effective_capability, exact_constraint);
      }
      return true;
    case ContentType::kConstrainBooleanParameters: {
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      const auto* dictionary_constraint =
          constraint->GetAsConstrainBooleanParameters();
      if (dictionary_constraint->hasExact()) {
        const bool exact_constraint = dictionary_constraint->exact();
        return base::Contains(effective_capability, exact_constraint);
      }
      return true;
    }
  }
}

// For `ConstrainDOMString` constraints and `sequence<DOMString>` effective
// capabilities such as whiteBalanceMode, exposureMode and focusMode.
bool CheckValueConstraint(
    const Vector<String>& effective_capability,
    const V8UnionConstrainDOMStringParametersOrStringOrStringSequence*
        constraint,
    MediaTrackConstraintSetType constraint_set_type) {
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    return true;
  }
  using ContentType =
      V8UnionConstrainDOMStringParametersOrStringOrStringSequence::ContentType;
  switch (constraint->GetContentType()) {
    case ContentType::kString:
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        return CheckExactValueConstraint(effective_capability,
                                         constraint->GetAsString());
      }
      return true;
    case ContentType::kStringSequence:
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        return CheckExactValueConstraint(effective_capability,
                                         constraint->GetAsStringSequence());
      }
      return true;
    case ContentType::kConstrainDOMStringParameters: {
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      const auto* dictionary_constraint =
          constraint->GetAsConstrainDOMStringParameters();
      if (dictionary_constraint->hasExact()) {
        const auto* exact_constraint = dictionary_constraint->exact();
        switch (exact_constraint->GetContentType()) {
          case V8UnionStringOrStringSequence::ContentType::kString:
            return CheckExactValueConstraint(effective_capability,
                                             exact_constraint->GetAsString());
          case V8UnionStringOrStringSequence::ContentType::kStringSequence:
            return CheckExactValueConstraint(
                effective_capability, exact_constraint->GetAsStringSequence());
        }
      }
      return true;
    }
  }
}

// Apply exact value constraints to photo settings and return new effective
// capabilities.
//
// Roughly the SelectSettings algorithm steps 3 and 5.
// https://www.w3.org/TR/mediacapture-streams/#dfn-selectsettings
//
// TODO(crbug.com/708723): Integrate image capture constraints processing with
// the main implementation and remove these support functions.

// For exact `boolean` constraints and `sequence<boolean>` effective
// capabilities such as torch and backgroundBlur.
Vector<bool> ApplyExactValueConstraint(bool* has_setting_ptr,
                                       bool* setting_ptr,
                                       const Vector<bool>& effective_capability,
                                       bool exact_constraint) {
  // Update the setting.
  *has_setting_ptr = true;
  *setting_ptr = exact_constraint;
  // Update the effective capability.
  return {exact_constraint};
}

// For exact `double` constraints and `MediaSettingsRange` effective
// capabilities such as exposureCompensation, ..., zoom.
MediaSettingsRange* ApplyExactValueConstraint(
    bool* has_setting_ptr,
    double* setting_ptr,
    const MediaSettingsRange* effective_capability,
    double exact_constraint) {
  // Update the setting.
  *has_setting_ptr = true;
  *setting_ptr = exact_constraint;
  // Update the effective capability.
  auto* new_effective_capability = MediaSettingsRange::Create();
  new_effective_capability->setMax(exact_constraint);
  new_effective_capability->setMin(exact_constraint);
  return new_effective_capability;
}

// For exact `DOMString` constraints and `sequence<DOMString>` effective
// capabilities such as whiteBalanceMode, exposureMode and focusMode.
Vector<String> ApplyExactValueConstraint(
    bool* has_setting_ptr,
    MeteringMode* setting_ptr,
    const Vector<String>& effective_capability,
    const String& exact_constraint) {
  // Update the setting.
  *has_setting_ptr = true;
  *setting_ptr = ParseMeteringMode(exact_constraint);
  // Update the effective capability.
  return {exact_constraint};
}

// For exact `sequence<DOMString>` constraints and `sequence<DOMString>`
// effective capabilities such as whiteBalanceMode, exposureMode and focusMode.
Vector<String> ApplyExactValueConstraint(
    bool* has_setting_ptr,
    MeteringMode* setting_ptr,
    const Vector<String>& effective_capability,
    const Vector<String>& exact_constraints) {
  // Update the effective capability.
  Vector<String> new_effective_capability;
  for (const auto& exact_constraint : exact_constraints) {
    if (base::Contains(effective_capability, exact_constraint)) {
      new_effective_capability.push_back(exact_constraint);
    }
  }
  DCHECK(!new_effective_capability.empty());
  // Clamp and update the setting.
  if (!*has_setting_ptr ||
      !base::Contains(exact_constraints,
                      static_cast<const String&>(ToString(*setting_ptr)))) {
    *has_setting_ptr = true;
    *setting_ptr = ParseMeteringMode(new_effective_capability[0]);
  }
  return new_effective_capability;
}

// Apply ideal value constraints to photo settings and return effective
// capabilities intact (ideal constraints have no effect on effective
// capabilities).
//
// Roughly the SelectSettings algorithm step 3.
// https://www.w3.org/TR/mediacapture-streams/#dfn-selectsettings
//
// TODO(crbug.com/708723): Integrate image capture constraints processing with
// the main implementation and remove these support functions.

// For ideal `boolean` constraints and `sequence<boolean>` effective
// capabilities such as torch and backgroundBlur.
Vector<bool> ApplyIdealValueConstraint(bool* has_setting_ptr,
                                       bool* setting_ptr,
                                       const Vector<bool>& effective_capability,
                                       bool ideal_constraint) {
  // Clamp and update the setting.
  *has_setting_ptr = true;
  *setting_ptr = base::Contains(effective_capability, ideal_constraint)
                     ? ideal_constraint
                     : effective_capability[0];
  // Keep the effective capability intact.
  return effective_capability;
}

// For ideal `double` constraints and `MediaSettingsRange` effective
// capabilities such as exposureCompensation, ..., zoom.
MediaSettingsRange* ApplyIdealValueConstraint(
    bool* has_setting_ptr,
    double* setting_ptr,
    MediaSettingsRange* effective_capability,
    std::optional<double> ideal_constraint,
    double current_setting) {
  // Clamp and update the setting.
  *has_setting_ptr = true;
  *setting_ptr =
      std::clamp(ideal_constraint ? *ideal_constraint : current_setting,
                 effective_capability->min(), effective_capability->max());
  // Keep the effective capability intact.
  return effective_capability;
}

// For ideal `DOMString` constraints and `sequence<DOMString>` effective
// capabilities such as whiteBalanceMode, exposureMode and focusMode.
Vector<String> ApplyIdealValueConstraint(
    bool* has_setting_ptr,
    MeteringMode* setting_ptr,
    const Vector<String>& effective_capability,
    const String& ideal_constraint,
    const String& current_setting) {
  // Validate and update the setting.
  *has_setting_ptr = true;
  *setting_ptr = ParseMeteringMode(
      base::Contains(effective_capability, ideal_constraint) ? ideal_constraint
                                                             : current_setting);
  // Keep the effective capability intact.
  return effective_capability;
}

// For ideal `sequence<DOMString>` constraints and `sequence<DOMString>`
// effective capabilities such as whiteBalanceMode, exposureMode and focusMode.
Vector<String> ApplyIdealValueConstraint(
    bool* has_setting_ptr,
    MeteringMode* setting_ptr,
    const Vector<String>& effective_capability,
    const Vector<String>& ideal_constraints,
    const String& current_setting) {
  // Clamp and update the setting.
  if (!*has_setting_ptr ||
      !base::Contains(ideal_constraints,
                      static_cast<const String&>(ToString(*setting_ptr)))) {
    String setting_name = current_setting;
    for (const auto& ideal_constraint : ideal_constraints) {
      if (base::Contains(effective_capability, ideal_constraint)) {
        setting_name = ideal_constraint;
        break;
      }
    }
    *has_setting_ptr = true;
    *setting_ptr = ParseMeteringMode(setting_name);
  }
  // Keep the effective capability intact.
  return effective_capability;
}

// Apply value constraints to photo settings and return new effective
// capabilities.
//
// Roughly the SelectSettings algorithm steps 3 and 5.
// https://www.w3.org/TR/mediacapture-streams/#dfn-selectsettings
//
// TODO(crbug.com/708723): Integrate image capture constraints processing with
// the main implementation and remove these support functions.

// For `ConstrainBoolean` constraints and `sequence<boolean>` effective
// capabilities such as torch and backgroundBlur.
Vector<bool> ApplyValueConstraint(
    bool* has_setting_ptr,
    bool* setting_ptr,
    const Vector<bool>& effective_capability,
    const V8UnionBooleanOrConstrainBooleanParameters* constraint,
    MediaTrackConstraintSetType constraint_set_type) {
  DCHECK(CheckValueConstraint(effective_capability, constraint,
                              constraint_set_type));
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    // Keep the effective capability intact.
    return effective_capability;
  }
  using ContentType = V8UnionBooleanOrConstrainBooleanParameters::ContentType;
  switch (constraint->GetContentType()) {
    case ContentType::kBoolean:
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        return ApplyExactValueConstraint(has_setting_ptr, setting_ptr,
                                         effective_capability,
                                         constraint->GetAsBoolean());
      }
      // We classify ideal bare value constraints as value constraints only in
      // the basic constraint set in which they have an effect on
      // the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      return ApplyIdealValueConstraint(has_setting_ptr, setting_ptr,
                                       effective_capability,
                                       constraint->GetAsBoolean());
    case ContentType::kConstrainBooleanParameters: {
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      const auto* dictionary_constraint =
          constraint->GetAsConstrainBooleanParameters();
      if (dictionary_constraint->hasExact()) {
        return ApplyExactValueConstraint(has_setting_ptr, setting_ptr,
                                         effective_capability,
                                         dictionary_constraint->exact());
      }
      // We classify `ConstrainBooleanParameters` constraints containing only
      // the `ideal` member as value constraints only in the basic constraint
      // set in which they have an effect on the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      return ApplyIdealValueConstraint(has_setting_ptr, setting_ptr,
                                       effective_capability,
                                       dictionary_constraint->ideal());
    }
  }
}

// For `ConstrainDouble` constraints and `MediaSettingsRange` effective
// capabilities such as exposureCompensation, ..., focusDistance.
MediaSettingsRange* ApplyValueConstraint(
    bool* has_setting_ptr,
    double* setting_ptr,
    const MediaSettingsRange* effective_capability,
    const V8UnionConstrainDoubleRangeOrDouble* constraint,
    MediaTrackConstraintSetType constraint_set_type,
    double current_setting) {
  DCHECK(CheckValueConstraint(effective_capability, constraint,
                              constraint_set_type));
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    // Keep the effective capability intact.
    return const_cast<MediaSettingsRange*>(effective_capability);
  }
  using ContentType = V8UnionConstrainDoubleRangeOrDouble::ContentType;
  switch (constraint->GetContentType()) {
    case ContentType::kDouble:
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        return ApplyExactValueConstraint(has_setting_ptr, setting_ptr,
                                         effective_capability,
                                         constraint->GetAsDouble());
      }
      // We classify ideal bare value constraints as value constraints only in
      // the basic constraint set in which they have an effect on
      // the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      return ApplyIdealValueConstraint(
          has_setting_ptr, setting_ptr,
          const_cast<MediaSettingsRange*>(effective_capability),
          constraint->GetAsDouble(), current_setting);
    case ContentType::kConstrainDoubleRange: {
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      const auto* dictionary_constraint =
          constraint->GetAsConstrainDoubleRange();
      if (dictionary_constraint->hasExact()) {
        return ApplyExactValueConstraint(has_setting_ptr, setting_ptr,
                                         effective_capability,
                                         dictionary_constraint->exact());
      }
      // Update the effective capability.
      auto* new_effective_capability = DuplicateRange(effective_capability);
      if (dictionary_constraint->hasMax()) {
        new_effective_capability->setMax(std::min(dictionary_constraint->max(),
                                                  effective_capability->max()));
      }
      if (dictionary_constraint->hasMin()) {
        new_effective_capability->setMin(std::max(dictionary_constraint->min(),
                                                  effective_capability->min()));
      }
      // Ideal constraints have an effect on the SelectSettings algorithm only
      // in the basic constraint set. Always call `ApplyIdealValueConstraint()`
      // so that either the ideal value constraint or the current setting is
      // clamped so that the setting is within the new effective capability.
      DCHECK(
          (dictionary_constraint->hasIdeal() &&
           constraint_set_type == MediaTrackConstraintSetType::kBasic) ||
          (dictionary_constraint->hasMax() || dictionary_constraint->hasMin()));
      return ApplyIdealValueConstraint(
          has_setting_ptr, setting_ptr, new_effective_capability,
          (dictionary_constraint->hasIdeal() &&
           constraint_set_type == MediaTrackConstraintSetType::kBasic)
              ? std::make_optional(dictionary_constraint->ideal())
              : std::nullopt,
          current_setting);
    }
  }
}

// For `(boolean or ConstrainDouble)` constraints and `MediaSettingsRange`
// effective capabilities such as pan, tilt and zoom.
MediaSettingsRange* ApplyValueConstraint(
    bool* has_setting_ptr,
    double* setting_ptr,
    const MediaSettingsRange* effective_capability,
    const V8UnionBooleanOrConstrainDoubleRangeOrDouble* constraint,
    MediaTrackConstraintSetType constraint_set_type,
    double current_setting) {
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    // Keep the effective capability intact.
    return const_cast<MediaSettingsRange*>(effective_capability);
  }
  // We classify boolean constraints for double constrainable properties as
  // existence constraints instead of as value constraints.
  DCHECK(!constraint->IsBoolean());
  return ApplyValueConstraint(
      has_setting_ptr, setting_ptr, effective_capability,
      constraint->GetAsV8UnionConstrainDoubleRangeOrDouble(),
      constraint_set_type, current_setting);
}

// For `ConstrainDOMString` constraints and `sequence<DOMString>` effective
// capabilities such as whiteBalanceMode, exposureMode and focusMode.
Vector<String> ApplyValueConstraint(
    bool* has_setting_ptr,
    MeteringMode* setting_ptr,
    const Vector<String>& effective_capability,
    const V8UnionConstrainDOMStringParametersOrStringOrStringSequence*
        constraint,
    MediaTrackConstraintSetType constraint_set_type,
    const String& current_setting) {
  DCHECK(CheckValueConstraint(effective_capability, constraint,
                              constraint_set_type));
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    // Keep the effective capability intact.
    return effective_capability;
  }
  using ContentType =
      V8UnionConstrainDOMStringParametersOrStringOrStringSequence::ContentType;
  switch (constraint->GetContentType()) {
    case ContentType::kString:
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        return ApplyExactValueConstraint(has_setting_ptr, setting_ptr,
                                         effective_capability,
                                         constraint->GetAsString());
      }
      // We classify ideal bare value constraints as value constraints only in
      // the basic constraint set in which they have an effect on
      // the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      return ApplyIdealValueConstraint(
          has_setting_ptr, setting_ptr, effective_capability,
          constraint->GetAsString(), current_setting);
    case ContentType::kStringSequence:
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        return ApplyExactValueConstraint(has_setting_ptr, setting_ptr,
                                         effective_capability,
                                         constraint->GetAsStringSequence());
      }
      // We classify ideal bare value constraints as value constraints only in
      // the basic constraint set in which they have an effect on
      // the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      return ApplyIdealValueConstraint(
          has_setting_ptr, setting_ptr, effective_capability,
          constraint->GetAsStringSequence(), current_setting);
    case ContentType::kConstrainDOMStringParameters: {
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      const auto* dictionary_constraint =
          constraint->GetAsConstrainDOMStringParameters();
      if (dictionary_constraint->hasExact()) {
        const V8UnionStringOrStringSequence* exact_constraint =
            dictionary_constraint->exact();
        switch (exact_constraint->GetContentType()) {
          case V8UnionStringOrStringSequence::ContentType::kString:
            return ApplyExactValueConstraint(has_setting_ptr, setting_ptr,
                                             effective_capability,
                                             exact_constraint->GetAsString());
          case V8UnionStringOrStringSequence::ContentType::kStringSequence:
            return ApplyExactValueConstraint(
                has_setting_ptr, setting_ptr, effective_capability,
                exact_constraint->GetAsStringSequence());
        }
      }
      // We classify `ConstrainDOMStringParameters` constraints containing only
      // the `ideal` member as value constraints only in the basic constraint
      // set in which they have an effect on the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      const V8UnionStringOrStringSequence* ideal_constraint =
          dictionary_constraint->ideal();
      switch (ideal_constraint->GetContentType()) {
        case V8UnionStringOrStringSequence::ContentType::kString:
          return ApplyIdealValueConstraint(
              has_setting_ptr, setting_ptr, effective_capability,
              ideal_constraint->GetAsString(), current_setting);
        case V8UnionStringOrStringSequence::ContentType::kStringSequence:
          return ApplyIdealValueConstraint(
              has_setting_ptr, setting_ptr, effective_capability,
              ideal_constraint->GetAsStringSequence(), current_setting);
      }
    }
  }
}

// For `ConstrainPoint2D` constraints such as `pointsOfInterest`.
// There is no capability for `pointsOfInterest` in `MediaTrackCapabilities`
// to be used as a storage for an effective capability.
// As a substitute, we use `MediaTrackSettings` and its `pointsOfInterest`
// field to convey restrictions placed by previous exact `pointsOfInterest`
// constraints.
void ApplyValueConstraint(bool* has_setting_ptr,
                          Vector<media::mojom::blink::Point2DPtr>* setting_ptr,
                          const HeapVector<Member<Point2D>>* effective_setting,
                          const HeapVector<Member<Point2D>>& constraint) {
  // Update the setting.
  *has_setting_ptr = true;
  setting_ptr->clear();
  for (const auto& point : constraint) {
    auto mojo_point = media::mojom::blink::Point2D::New();
    mojo_point->x = std::clamp(point->x(), 0.0, 1.0);
    mojo_point->y = std::clamp(point->y(), 0.0, 1.0);
    setting_ptr->push_back(std::move(mojo_point));
  }
}

// For `ConstrainPoint2D` constraints such as `pointsOfInterest`.
// There is no capability for `pointsOfInterest` in `MediaTrackCapabilities`
// to be used as a storage for an effective capability.
// As a substitute, we use `MediaTrackSettings` and its `pointsOfInterest`
// field to convey restrictions placed by previous exact `pointsOfInterest`
// constraints.
std::optional<HeapVector<Member<Point2D>>> ApplyValueConstraint(
    bool* has_setting_ptr,
    Vector<media::mojom::blink::Point2DPtr>* setting_ptr,
    const HeapVector<Member<Point2D>>* effective_setting,
    const V8UnionConstrainPoint2DParametersOrPoint2DSequence* constraint,
    MediaTrackConstraintSetType constraint_set_type) {
  DCHECK(
      CheckValueConstraint(effective_setting, constraint, constraint_set_type));
  if (!IsValueConstraint(constraint, constraint_set_type)) {
    // Keep the effective capability intact.
    return std::nullopt;
  }
  using ContentType =
      V8UnionConstrainPoint2DParametersOrPoint2DSequence::ContentType;
  switch (constraint->GetContentType()) {
    case ContentType::kPoint2DSequence:
      if (IsBareValueToBeTreatedAsExact(constraint_set_type)) {
        ApplyValueConstraint(has_setting_ptr, setting_ptr, effective_setting,
                             constraint->GetAsPoint2DSequence());
        return constraint->GetAsPoint2DSequence();
      }
      // We classify ideal bare value constraints as value constraints only in
      // the basic constraint set in which they have an effect on
      // the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      ApplyValueConstraint(has_setting_ptr, setting_ptr, effective_setting,
                           constraint->GetAsPoint2DSequence());
      return std::nullopt;
    case ContentType::kConstrainPoint2DParameters: {
      DCHECK_NE(constraint_set_type,
                MediaTrackConstraintSetType::kFirstAdvanced);
      const auto* dictionary_constraint =
          constraint->GetAsConstrainPoint2DParameters();
      if (dictionary_constraint->hasExact()) {
        ApplyValueConstraint(has_setting_ptr, setting_ptr, effective_setting,
                             dictionary_constraint->exact());
        return dictionary_constraint->exact();
      }
      // We classify `ConstrainPoint2DParameters` constraints containing only
      // the `ideal` member as value constraints only in the basic constraint
      // set in which they have an effect on the SelectSettings algorithm.
      DCHECK_EQ(constraint_set_type, MediaTrackConstraintSetType::kBasic);
      ApplyValueConstraint(has_setting_ptr, setting_ptr, effective_setting,
                           dictionary_constraint->ideal());
      return std::nullopt;
    }
  }
}

void MaybeSetBackgroundBlurSetting(bool value,
                                   const Vector<bool>& capability,
                                   bool& has_setting,
                                   BackgroundBlurMode& setting) {
  if (!base::Contains(capability, value)) {
    return;
  }

  has_setting = true;
  setting = ParseBackgroundBlur(value);
}

void MaybeSetBoolSetting(bool value,
                         const Vector<bool>& capability,
                         std::optional<bool>& setting) {
  if (!base::Contains(capability, value)) {
    return;
  }

  setting = value;
}

void MaybeSetBoolSetting(bool value,
                         const Vector<bool>& capability,
                         bool& has_setting,
                         bool& setting) {
  if (!base::Contains(capability, value)) {
    return;
  }

  has_setting = true;
  setting = value;
}

void MaybeSetEyeGazeCorrectionSetting(
    bool value,
    const Vector<bool>& capability,
    std::optional<EyeGazeCorrectionMode>& setting) {
  if (!base::Contains(capability, value)) {
    return;
  }

  setting = ParseEyeGazeCorrection(value);
}

void MaybeSetFaceFramingSetting(bool value,
                                const Vector<bool>& capability,
                                bool& has_setting,
                                MeteringMode& setting) {
  if (!base::Contains(capability, value)) {
    return;
  }

  has_setting = true;
  setting = ParseFaceFraming(value);
}

void MaybeSetDoubleSetting(double value,
                           const MediaSettingsRange& capability,
                           bool& has_setting,
                           double& setting) {
  if (!(capability.min() <= value && value <= capability.max())) {
    return;
  }

  has_setting = true;
  setting = value;
}

}  // anonymous namespace

ImageCapture* ImageCapture::Create(ExecutionContext* context,
                                   MediaStreamTrack* track,
                                   ExceptionState& exception_state) {
  if (track->kind() != "video") {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Cannot create an ImageCapturer from a non-video Track.");
    return nullptr;
  }

  // The initial PTZ permission comes from the internal ImageCapture object of
  // the track, if already created.
  bool pan_tilt_zoom_allowed =
      (track->GetImageCapture() &&
       track->GetImageCapture()->HasPanTiltZoomPermissionGranted());

  return MakeGarbageCollected<ImageCapture>(
      context, track, pan_tilt_zoom_allowed, base::DoNothing());
}

ImageCapture::~ImageCapture() {
  // There should be no more outstanding |service_requests_| at this point
  // since each of them holds a persistent handle to this object.
  DCHECK(service_requests_.empty());
}

void ImageCapture::ContextDestroyed() {
  service_requests_.clear();
  frame_grabber_.reset();
}

ScriptPromise<PhotoCapabilities> ImageCapture::getPhotoCapabilities(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PhotoCapabilities>>(
          script_state);
  auto promise = resolver->Promise();
  GetMojoPhotoState(resolver,
                    WTF::BindOnce(&ImageCapture::ResolveWithPhotoCapabilities,
                                  WrapPersistent(this)));
  return promise;
}

ScriptPromise<PhotoSettings> ImageCapture::getPhotoSettings(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PhotoSettings>>(script_state);
  auto promise = resolver->Promise();
  GetMojoPhotoState(resolver,
                    WTF::BindOnce(&ImageCapture::ResolveWithPhotoSettings,
                                  WrapPersistent(this)));
  return promise;
}

ScriptPromise<Blob> ImageCapture::takePhoto(
    ScriptState* script_state,
    const PhotoSettings* photo_settings) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("video_and_image_capture"),
               "ImageCapture::takePhoto");

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Blob>>(script_state);
  auto promise = resolver->Promise();

  if (TrackIsInactive(*stream_track_)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, kInvalidStateTrackError));
    return promise;
  }

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotFoundError, kNoServiceError));
    return promise;
  }
  service_requests_.insert(resolver);

  // TODO(mcasas):
```