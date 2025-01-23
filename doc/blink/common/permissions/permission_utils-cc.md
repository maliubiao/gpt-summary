Response: Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The core request is to understand the functionality of `permission_utils.cc` within the Blink rendering engine and how it relates to web technologies (JavaScript, HTML, CSS) and potential user/developer errors.

2. **Initial Skim and Identify Key Components:** Read through the code, looking for keywords and structures that give clues about its purpose. I see:
    * `#include` statements indicating dependencies (e.g., `permission.mojom.h`, `permissions_policy_feature.mojom.h`). "mojom" often suggests inter-process communication definitions in Chromium.
    * Namespaces: `blink`.
    * Enumerations: `PermissionType`, `PermissionStatus`, `PermissionsPolicyFeature`.
    * Functions: `ToPermissionStatus`, `GetPermissionString`, `PermissionTypeToPermissionsPolicyFeature`, `GetAllPermissionTypes`, `PermissionDescriptorToPermissionType`, `PermissionDescriptorInfoToPermissionType`.
    * `switch` statements, which are crucial for understanding mappings between different representations of permissions.
    * `static const base::NoDestructor`:  Suggests lazily initialized global constants.
    * `NOTREACHED()`: Indicates code that should never be executed, often used for error handling or completeness checks in `switch` statements.

3. **Analyze Individual Functions:** Go through each function and determine its role:

    * **`ToPermissionStatus(const std::string& status)`:** This clearly converts a string representation of a permission status ("granted", "prompt", "denied") to an enum value (`mojom::PermissionStatus`). This strongly suggests interaction with an external system or configuration that uses string representations.

    * **`GetPermissionString(PermissionType permission)`:**  This maps `PermissionType` enum values to human-readable strings (e.g., `PermissionType::GEOLOCATION` to "Geolocation"). This is useful for logging, debugging, or potentially user interfaces.

    * **`PermissionTypeToPermissionsPolicyFeature(PermissionType permission)`:** This is a key function. It links `PermissionType` to `mojom::PermissionsPolicyFeature`. This strongly suggests it's involved in the Permissions Policy mechanism, which controls feature access in web pages through HTTP headers or iframe attributes. The `std::optional` return type indicates that not all permissions have a corresponding Permissions Policy feature.

    * **`GetAllPermissionTypes()`:**  This returns a list of all defined `PermissionType` values. The comment about skipping removed entries is interesting and suggests that the set of permissions has evolved.

    * **`PermissionDescriptorToPermissionType(const PermissionDescriptorPtr& descriptor)` and `PermissionDescriptorInfoToPermissionType(...)`:** These are more complex. They take structured data (`PermissionDescriptorPtr` which likely comes from a JavaScript `navigator.permissions.query()` call or similar) or its individual components and try to map them back to a `PermissionType`. The presence of parameters like `midi_sysex`, `camera_ptz`, `clipboard_will_be_sanitized`, etc., reveals that some permissions have subtypes or additional conditions. The `#if defined(ENABLE_PROTECTED_MEDIA_IDENTIFIER_PERMISSION)` shows a build-time configuration aspect.

4. **Identify Relationships with Web Technologies:**  Connect the C++ code's functionality back to JavaScript, HTML, and CSS:

    * **JavaScript `navigator.permissions.query()`:**  The `PermissionDescriptorPtr` directly corresponds to the structure used when querying permissions in JavaScript. The `PermissionStatus` returned by `ToPermissionStatus` aligns with the states returned by this API.
    * **Permissions Policy (HTML/HTTP Headers):** The `PermissionTypeToPermissionsPolicyFeature` function is the direct link. The `PermissionsPolicyFeature` enum values correspond to the feature names used in the `Permissions-Policy` header or the `allow` attribute of iframes.
    * **User Prompts:** The "prompt" status is directly related to the browser's permission prompt dialogs.
    * **Feature Control:** The various `PermissionType` values correspond to web features like geolocation, camera, microphone, etc., which are accessible through JavaScript APIs.

5. **Consider Logical Reasoning and Examples:** Think about how the code would behave with different inputs:

    * **`ToPermissionStatus`:**  Input "granted" -> Output `mojom::PermissionStatus::GRANTED`. Input "invalid" -> `NOTREACHED()` (or undefined behavior, although the code tries to prevent this).
    * **`GetPermissionString`:** Input `PermissionType::GEOLOCATION` -> Output "Geolocation". Input `PermissionType::NUM` -> `NOTREACHED()`.
    * **`PermissionTypeToPermissionsPolicyFeature`:** Input `PermissionType::GEOLOCATION` -> `mojom::PermissionsPolicyFeature::kGeolocation`. Input `PermissionType::NOTIFICATIONS` -> `std::nullopt`.
    * **`PermissionDescriptorToPermissionType`:** Think about various `PermissionDescriptorPtr` objects created in JavaScript and how they would map. For example, a simple geolocation request vs. a MIDI Sysex request.

6. **Identify Potential User/Developer Errors:** Focus on how developers might misuse the related JavaScript APIs or misunderstand the permission system:

    * **Incorrect String for Status:** Passing an invalid string to a function expecting a permission status.
    * **Assuming All Permissions Have Policy Features:**  Not checking the return value of `PermissionTypeToPermissionsPolicyFeature`.
    * **Misunderstanding Sanitized Clipboard:** Incorrectly assuming all clipboard writes are allowed.
    * **Permissions Policy Mismatches:**  Conflicting settings in the Permissions Policy and the actual permission requests.

7. **Structure the Output:** Organize the information logically, starting with the overall purpose, then detailing the functionality of each part, and finally addressing the connections to web technologies and potential errors. Use clear headings and examples.

8. **Review and Refine:**  Read through the explanation to ensure clarity, accuracy, and completeness. Are there any ambiguities? Could examples be more illustrative?  For instance, initially, I might not have explicitly linked `PermissionDescriptorPtr` to `navigator.permissions.query()`, but realizing their close connection is important. Similarly, emphasizing the role of Permissions Policy in controlling these features is crucial.
这个文件 `blink/common/permissions/permission_utils.cc` 的主要功能是提供**权限相关的实用工具函数**，用于在 Chromium Blink 引擎中处理各种权限请求和状态。它定义了一些枚举类型和函数，用于在不同的权限表示形式之间进行转换，并提供关于权限的信息。

下面详细列举其功能，并解释与 JavaScript、HTML、CSS 的关系，以及逻辑推理和常见错误：

**主要功能:**

1. **权限类型定义和字符串转换:**
   - 定义了 `PermissionType` 枚举，包含了各种浏览器支持的权限类型，例如地理位置、通知、摄像头、麦克风等。
   - 提供了 `GetPermissionString(PermissionType permission)` 函数，将 `PermissionType` 枚举值转换为易于理解的字符串表示（例如，`PermissionType::GEOLOCATION` 转换为 "Geolocation"）。

2. **权限状态转换:**
   - 提供了 `ToPermissionStatus(const std::string& status)` 函数，将字符串形式的权限状态（"granted"、"prompt"、"denied"）转换为 `mojom::PermissionStatus` 枚举值。这用于处理从外部（例如配置文件或命令行参数）读取的权限状态。

3. **权限类型与 Permissions Policy 特性映射:**
   - 提供了 `PermissionTypeToPermissionsPolicyFeature(PermissionType permission)` 函数，将 `PermissionType` 映射到对应的 `mojom::PermissionsPolicyFeature` 枚举值。Permissions Policy 是一种 Web 平台机制，允许网站控制其自身以及其嵌入的 iframe 是否可以使用某些浏览器功能。

4. **获取所有权限类型:**
   - 提供了 `GetAllPermissionTypes()` 函数，返回一个包含所有 `PermissionType` 枚举值的 `std::vector`。

5. **PermissionDescriptor 到 PermissionType 的转换:**
   - 提供了 `PermissionDescriptorToPermissionType(const PermissionDescriptorPtr& descriptor)` 和 `PermissionDescriptorInfoToPermissionType(...)` 函数，用于将 `PermissionDescriptorPtr` (通常来自 JavaScript 的 `navigator.permissions.query()` 方法的参数) 或其组成部分转换为 `PermissionType` 枚举值。 这涉及到根据描述符中的扩展信息（例如 MIDI 的 sysex 属性，摄像头的 pan/tilt/zoom 属性，剪贴板的 sanitized 属性等）来确定具体的权限类型。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - `navigator.permissions.query()` API：JavaScript 代码可以使用 `navigator.permissions.query()` 方法来查询特定权限的状态。该方法的参数是一个 `PermissionDescriptor` 对象，该对象的信息会传递到 Blink 引擎，并可能通过 `PermissionDescriptorToPermissionType` 函数转换为内部的 `PermissionType` 枚举。
    - **举例:** JavaScript 代码 `navigator.permissions.query({ name: 'geolocation' })`  会触发 Blink 内部对地理位置权限的检查，`permission_utils.cc` 中的函数可能被用来解析这个请求。
    - **举例:** JavaScript 代码 `navigator.permissions.query({ name: 'midi', sysex: true })`  请求 MIDI SysEx 权限，`PermissionDescriptorToPermissionType` 会根据 `sysex: true` 将其识别为 `PermissionType::MIDI_SYSEX`。

* **HTML:**
    - **Permissions Policy (通过 HTTP 头部或 `<iframe>` 标签的 `allow` 属性):**  HTML 可以通过 Permissions Policy 来控制权限。`PermissionTypeToPermissionsPolicyFeature` 函数的作用就是将内部的权限类型映射到 Permissions Policy 中使用的 feature name。
    - **举例:**  一个网站的 HTTP 响应头可能包含 `Permissions-Policy: geolocation=self`，这意味着只有该网站自己的源可以使用地理位置 API。`PermissionTypeToPermissionsPolicyFeature(PermissionType::GEOLOCATION)` 会返回 `mojom::PermissionsPolicyFeature::kGeolocation`，这个值对应着 Permissions Policy 中的 "geolocation" feature。
    - **举例:** 一个 `<iframe>` 标签可能有 `allow="camera"` 属性，这允许 iframe 内的页面请求摄像头权限。`PermissionTypeToPermissionsPolicyFeature(PermissionType::VIDEO_CAPTURE)` 会返回 `mojom::PermissionsPolicyFeature::kCamera`。

* **CSS:**
    -  这个文件本身与 CSS 的功能没有直接关系。CSS 主要负责页面的样式和布局，而权限控制是浏览器安全和功能特性的管理。

**逻辑推理与假设输入/输出：**

* **假设输入 (对于 `ToPermissionStatus`):**  字符串 "granted"
* **输出:** `mojom::PermissionStatus::GRANTED`

* **假设输入 (对于 `GetPermissionString`):** `PermissionType::VIDEO_CAPTURE`
* **输出:** 字符串 "VideoCapture"

* **假设输入 (对于 `PermissionTypeToPermissionsPolicyFeature`):** `PermissionType::GEOLOCATION`
* **输出:** `std::optional<mojom::PermissionsPolicyFeature>` 包含 `mojom::PermissionsPolicyFeature::kGeolocation`

* **假设输入 (对于 `PermissionDescriptorToPermissionType`):**  一个表示地理位置权限的 `PermissionDescriptorPtr` 对象。
* **输出:** `std::optional<PermissionType>` 包含 `PermissionType::GEOLOCATION`

* **假设输入 (对于 `PermissionDescriptorToPermissionType`):**  一个表示 MIDI SysEx 权限的 `PermissionDescriptorPtr` 对象 (name 为 "midi", extension 中 sysex 为 true)。
* **输出:** `std::optional<PermissionType>` 包含 `PermissionType::MIDI_SYSEX`

**用户或编程常见的使用错误：**

1. **在 JavaScript 中使用错误的权限名称字符串:**
   - **错误示例:** `navigator.permissions.query({ name: 'location' })`  (正确的名称是 'geolocation')
   - **说明:**  如果 JavaScript 代码中使用的权限名称字符串与 Blink 引擎中定义的 `PermissionName` 不匹配，`PermissionDescriptorToPermissionType` 将无法正确识别权限类型。

2. **假设所有权限都有对应的 Permissions Policy 特性:**
   - **错误示例:**  开发者可能直接假设所有在 `PermissionType` 中定义的权限都有一个对应的 `PermissionsPolicyFeature`，并在代码中直接使用 `PermissionTypeToPermissionsPolicyFeature` 的返回值，而不检查 `std::optional` 是否包含值。
   - **说明:**  并非所有权限都有对应的 Permissions Policy 特性（例如，`PermissionType::NOTIFICATIONS` 目前就没有）。直接使用 `nullopt` 的返回值可能导致程序错误。

3. **混淆 sanitized 和 unsanitized 剪贴板写入权限:**
   - **错误示例:**  开发者可能错误地认为写入任何内容到剪贴板都需要用户手势，而忽略了 sanitized write 权限在有用户手势时可以默认授予。
   - **说明:**  `PermissionDescriptorInfoToPermissionType` 会根据 `clipboard_will_be_sanitized` 和 `clipboard_has_user_gesture` 参数来区分 `CLIPBOARD_SANITIZED_WRITE` 和 `CLIPBOARD_READ_WRITE`。理解这两种类型的区别对于正确请求和处理剪贴板权限至关重要。

4. **在 Permissions Policy 中使用错误的 feature name:**
   - **错误示例:**  在 HTTP 头部设置 `Permissions-Policy: camera-access=self`，但正确的 feature name 是 `camera`。
   - **说明:**  `PermissionTypeToPermissionsPolicyFeature` 的输出必须与 Permissions Policy 标准中定义的 feature name 完全一致，否则浏览器将无法正确解析策略。

5. **不理解某些权限的扩展属性:**
   - **错误示例:**  尝试请求 MIDI 权限，但不理解 `sysex` 属性的重要性。
   - **说明:**  对于某些权限，例如 MIDI 和摄像头，可能需要额外的扩展属性来区分不同的子权限（例如 MIDI SysEx）或功能（例如摄像头的 pan/tilt/zoom）。开发者需要正确设置 `PermissionDescriptor` 中的这些属性。

总而言之，`permission_utils.cc` 是 Blink 引擎中处理权限的核心组成部分，它负责权限类型的定义、状态转换以及与 Web 平台权限机制的集成。理解这个文件的功能对于理解浏览器如何管理和控制各种 Web 功能的访问权限至关重要。

### 提示词
```
这是目录为blink/common/permissions/permission_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/permissions/permission_utils.h"

#include "base/no_destructor.h"
#include "base/notreached.h"
#include "third_party/blink/public/mojom/permissions/permission.mojom.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom.h"

namespace blink {

using mojom::PermissionDescriptorPtr;
using mojom::PermissionName;
using mojom::PermissionStatus;

mojom::PermissionStatus ToPermissionStatus(const std::string& status) {
  if (status == "granted")
    return mojom::PermissionStatus::GRANTED;
  if (status == "prompt")
    return mojom::PermissionStatus::ASK;
  if (status == "denied")
    return mojom::PermissionStatus::DENIED;
  NOTREACHED();
}

std::string GetPermissionString(PermissionType permission) {
  switch (permission) {
    case PermissionType::GEOLOCATION:
      return "Geolocation";
    case PermissionType::NOTIFICATIONS:
      return "Notifications";
    case PermissionType::MIDI_SYSEX:
      return "MidiSysEx";
    case PermissionType::DURABLE_STORAGE:
      return "DurableStorage";
    case PermissionType::PROTECTED_MEDIA_IDENTIFIER:
      return "ProtectedMediaIdentifier";
    case PermissionType::AUDIO_CAPTURE:
      return "AudioCapture";
    case PermissionType::VIDEO_CAPTURE:
      return "VideoCapture";
    case PermissionType::MIDI:
      return "Midi";
    case PermissionType::BACKGROUND_SYNC:
      return "BackgroundSync";
    case PermissionType::SENSORS:
      return "Sensors";
    case PermissionType::CLIPBOARD_READ_WRITE:
      return "ClipboardReadWrite";
    case PermissionType::CLIPBOARD_SANITIZED_WRITE:
      return "ClipboardSanitizedWrite";
    case PermissionType::PAYMENT_HANDLER:
      return "PaymentHandler";
    case PermissionType::BACKGROUND_FETCH:
      return "BackgroundFetch";
    case PermissionType::IDLE_DETECTION:
      return "IdleDetection";
    case PermissionType::PERIODIC_BACKGROUND_SYNC:
      return "PeriodicBackgroundSync";
    case PermissionType::WAKE_LOCK_SCREEN:
      return "WakeLockScreen";
    case PermissionType::WAKE_LOCK_SYSTEM:
      return "WakeLockSystem";
    case PermissionType::NFC:
      return "NFC";
    case PermissionType::VR:
      return "VR";
    case PermissionType::AR:
      return "AR";
    case PermissionType::HAND_TRACKING:
      return "HandTracking";
    case PermissionType::SMART_CARD:
      return "SmartCard";
    case PermissionType::STORAGE_ACCESS_GRANT:
      return "StorageAccess";
    case PermissionType::CAMERA_PAN_TILT_ZOOM:
      return "CameraPanTiltZoom";
    case PermissionType::WINDOW_MANAGEMENT:
      return "WindowPlacement";
    case PermissionType::LOCAL_FONTS:
      return "LocalFonts";
    case PermissionType::DISPLAY_CAPTURE:
      return "DisplayCapture";
    case PermissionType::TOP_LEVEL_STORAGE_ACCESS:
      return "TopLevelStorageAccess";
    case PermissionType::CAPTURED_SURFACE_CONTROL:
      return "CapturedSurfaceControl";
    case PermissionType::WEB_PRINTING:
      return "WebPrinting";
    case PermissionType::SPEAKER_SELECTION:
      return "SpeakerSelection";
    case PermissionType::KEYBOARD_LOCK:
      return "KeyboardLock";
    case PermissionType::POINTER_LOCK:
      return "PointerLock";
    case PermissionType::AUTOMATIC_FULLSCREEN:
      return "AutomaticFullscreen";
    case PermissionType::WEB_APP_INSTALLATION:
      return "WebAppInstallation";
    case PermissionType::NUM:
      NOTREACHED();
  }
  NOTREACHED();
}

std::optional<mojom::PermissionsPolicyFeature>
PermissionTypeToPermissionsPolicyFeature(PermissionType permission) {
  switch (permission) {
    case PermissionType::GEOLOCATION:
      return mojom::PermissionsPolicyFeature::kGeolocation;
    case PermissionType::MIDI_SYSEX:
      return mojom::PermissionsPolicyFeature::kMidiFeature;
    case PermissionType::PROTECTED_MEDIA_IDENTIFIER:
      return mojom::PermissionsPolicyFeature::kEncryptedMedia;
    case PermissionType::AUDIO_CAPTURE:
      return mojom::PermissionsPolicyFeature::kMicrophone;
    case PermissionType::VIDEO_CAPTURE:
      return mojom::PermissionsPolicyFeature::kCamera;
    case PermissionType::MIDI:
      return mojom::PermissionsPolicyFeature::kMidiFeature;
    case PermissionType::CLIPBOARD_READ_WRITE:
      return mojom::PermissionsPolicyFeature::kClipboardRead;
    case PermissionType::CLIPBOARD_SANITIZED_WRITE:
      return mojom::PermissionsPolicyFeature::kClipboardWrite;
    case PermissionType::IDLE_DETECTION:
      return mojom::PermissionsPolicyFeature::kIdleDetection;
    case PermissionType::WAKE_LOCK_SCREEN:
      return mojom::PermissionsPolicyFeature::kScreenWakeLock;
    case PermissionType::HAND_TRACKING:
      return mojom::PermissionsPolicyFeature::kWebXr;
    case PermissionType::VR:
      return mojom::PermissionsPolicyFeature::kWebXr;
    case PermissionType::AR:
      return mojom::PermissionsPolicyFeature::kWebXr;
    case PermissionType::SMART_CARD:
      return mojom::PermissionsPolicyFeature::kSmartCard;
    case PermissionType::WEB_PRINTING:
      return mojom::PermissionsPolicyFeature::kWebPrinting;
    case PermissionType::STORAGE_ACCESS_GRANT:
      return mojom::PermissionsPolicyFeature::kStorageAccessAPI;
    case PermissionType::TOP_LEVEL_STORAGE_ACCESS:
      return mojom::PermissionsPolicyFeature::kStorageAccessAPI;
    case PermissionType::WINDOW_MANAGEMENT:
      return mojom::PermissionsPolicyFeature::kWindowManagement;
    case PermissionType::LOCAL_FONTS:
      return mojom::PermissionsPolicyFeature::kLocalFonts;
    case PermissionType::DISPLAY_CAPTURE:
      return mojom::PermissionsPolicyFeature::kDisplayCapture;
    case PermissionType::CAPTURED_SURFACE_CONTROL:
      return mojom::PermissionsPolicyFeature::kCapturedSurfaceControl;
    case PermissionType::SPEAKER_SELECTION:
      return mojom::PermissionsPolicyFeature::kSpeakerSelection;
    case PermissionType::AUTOMATIC_FULLSCREEN:
      return mojom::PermissionsPolicyFeature::kFullscreen;
    case PermissionType::WEB_APP_INSTALLATION:
      return mojom::PermissionsPolicyFeature::kWebAppInstallation;

    case PermissionType::PERIODIC_BACKGROUND_SYNC:
    case PermissionType::DURABLE_STORAGE:
    case PermissionType::BACKGROUND_SYNC:
    // TODO(crbug.com/1384434): decouple this to separated types of sensor,
    // with a corresponding permission policy.
    case PermissionType::SENSORS:
    case PermissionType::PAYMENT_HANDLER:
    case PermissionType::BACKGROUND_FETCH:
    case PermissionType::WAKE_LOCK_SYSTEM:
    case PermissionType::NFC:
    case PermissionType::CAMERA_PAN_TILT_ZOOM:
    case PermissionType::NOTIFICATIONS:
    case PermissionType::KEYBOARD_LOCK:
    case PermissionType::POINTER_LOCK:
      return std::nullopt;

    case PermissionType::NUM:
      NOTREACHED();
  }
  NOTREACHED();
}

const std::vector<PermissionType>& GetAllPermissionTypes() {
  static const base::NoDestructor<std::vector<PermissionType>>
      kAllPermissionTypes([] {
        const int NUM_TYPES = static_cast<int>(PermissionType::NUM);
        std::vector<PermissionType> all_types;
        // Note: Update this if the set of removed entries changes.
        // This is 6 because it skips 0 as well as the 5 numbers explicitly
        // mentioned below.
        all_types.reserve(NUM_TYPES - 6);
        for (int i = 1; i < NUM_TYPES; ++i) {
          // Skip removed entries.
          if (i == 2 || i == 11 || i == 14 || i == 15 || i == 32)
            continue;
          all_types.push_back(static_cast<PermissionType>(i));
        }
        return all_types;
      }());
  return *kAllPermissionTypes;
}

std::optional<PermissionType> PermissionDescriptorToPermissionType(
    const PermissionDescriptorPtr& descriptor) {
  return PermissionDescriptorInfoToPermissionType(
      descriptor->name,
      descriptor->extension && descriptor->extension->is_midi() &&
          descriptor->extension->get_midi()->sysex,
      descriptor->extension && descriptor->extension->is_camera_device() &&
          descriptor->extension->get_camera_device()->panTiltZoom,
      descriptor->extension && descriptor->extension->is_clipboard() &&
          descriptor->extension->get_clipboard()->will_be_sanitized,
      descriptor->extension && descriptor->extension->is_clipboard() &&
          descriptor->extension->get_clipboard()->has_user_gesture,
      descriptor->extension && descriptor->extension->is_fullscreen() &&
          descriptor->extension->get_fullscreen()->allow_without_user_gesture);
}

std::optional<PermissionType> PermissionDescriptorInfoToPermissionType(
    mojom::PermissionName name,
    bool midi_sysex,
    bool camera_ptz,
    bool clipboard_will_be_sanitized,
    bool clipboard_has_user_gesture,
    bool fullscreen_allow_without_user_gesture) {
  switch (name) {
    case PermissionName::GEOLOCATION:
      return PermissionType::GEOLOCATION;
    case PermissionName::NOTIFICATIONS:
      return PermissionType::NOTIFICATIONS;
    case PermissionName::MIDI: {
      if (midi_sysex) {
        return PermissionType::MIDI_SYSEX;
      }
      return PermissionType::MIDI;
    }
    case PermissionName::PROTECTED_MEDIA_IDENTIFIER:
#if defined(ENABLE_PROTECTED_MEDIA_IDENTIFIER_PERMISSION)
      return PermissionType::PROTECTED_MEDIA_IDENTIFIER;
#else
      NOTIMPLEMENTED();
      return std::nullopt;
#endif  // defined(ENABLE_PROTECTED_MEDIA_IDENTIFIER_PERMISSION)
    case PermissionName::DURABLE_STORAGE:
      return PermissionType::DURABLE_STORAGE;
    case PermissionName::AUDIO_CAPTURE:
      return PermissionType::AUDIO_CAPTURE;
    case PermissionName::VIDEO_CAPTURE:
      if (camera_ptz) {
        return PermissionType::CAMERA_PAN_TILT_ZOOM;
      } else {
        return PermissionType::VIDEO_CAPTURE;
      }
    case PermissionName::BACKGROUND_SYNC:
      return PermissionType::BACKGROUND_SYNC;
    case PermissionName::SENSORS:
      return PermissionType::SENSORS;
    case PermissionName::CLIPBOARD_READ:
      return PermissionType::CLIPBOARD_READ_WRITE;
    case PermissionName::CLIPBOARD_WRITE:
      // If the write is both sanitized (i.e. plain text or known-format
      // images), and a user gesture is present, use CLIPBOARD_SANITIZED_WRITE,
      // which Chrome grants by default.
      if (clipboard_will_be_sanitized && clipboard_has_user_gesture) {
        return PermissionType::CLIPBOARD_SANITIZED_WRITE;
      } else {
        return PermissionType::CLIPBOARD_READ_WRITE;
      }
    case PermissionName::PAYMENT_HANDLER:
      return PermissionType::PAYMENT_HANDLER;
    case PermissionName::BACKGROUND_FETCH:
      return PermissionType::BACKGROUND_FETCH;
    case PermissionName::IDLE_DETECTION:
      return PermissionType::IDLE_DETECTION;
    case PermissionName::PERIODIC_BACKGROUND_SYNC:
      return PermissionType::PERIODIC_BACKGROUND_SYNC;
    case PermissionName::SCREEN_WAKE_LOCK:
      return PermissionType::WAKE_LOCK_SCREEN;
    case PermissionName::SYSTEM_WAKE_LOCK:
      return PermissionType::WAKE_LOCK_SYSTEM;
    case PermissionName::NFC:
      return PermissionType::NFC;
    case PermissionName::STORAGE_ACCESS:
      return PermissionType::STORAGE_ACCESS_GRANT;
    case PermissionName::WINDOW_MANAGEMENT:
      return PermissionType::WINDOW_MANAGEMENT;
    case PermissionName::LOCAL_FONTS:
      return PermissionType::LOCAL_FONTS;
    case PermissionName::DISPLAY_CAPTURE:
      return PermissionType::DISPLAY_CAPTURE;
    case PermissionName::TOP_LEVEL_STORAGE_ACCESS:
      return PermissionType::TOP_LEVEL_STORAGE_ACCESS;
    case PermissionName::CAPTURED_SURFACE_CONTROL:
      return PermissionType::CAPTURED_SURFACE_CONTROL;
    case PermissionName::SPEAKER_SELECTION:
      return PermissionType::SPEAKER_SELECTION;
    case PermissionName::KEYBOARD_LOCK:
      return PermissionType::KEYBOARD_LOCK;
    case PermissionName::POINTER_LOCK:
      return PermissionType::POINTER_LOCK;
    case PermissionName::FULLSCREEN:
      if (fullscreen_allow_without_user_gesture) {
        return PermissionType::AUTOMATIC_FULLSCREEN;
      }
      // There is no PermissionType for fullscreen with user gesture.
      NOTIMPLEMENTED_LOG_ONCE();
      return std::nullopt;
    case PermissionName::WEB_APP_INSTALLATION:
      return PermissionType::WEB_APP_INSTALLATION;
    default:
      NOTREACHED();
  }
}

}  // namespace blink
```