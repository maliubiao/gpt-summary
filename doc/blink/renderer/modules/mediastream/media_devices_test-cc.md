Response:
The user wants a summary of the functionality of the C++ file `media_devices_test.cc` in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name itself, `media_devices_test.cc`, strongly suggests that this file contains tests for the `MediaDevices` API in Blink.

2. **Scan for Key Classes and Functions:** Look for classes and functions being tested. The `#include` directives provide clues. We see:
    * `MediaDevices`
    * `MockMediaDevicesDispatcherHost`
    * Test fixtures (`MediaDevicesTest`)
    * GTest macros (`TEST_F`, `EXPECT_EQ`, etc.)

3. **Analyze Test Cases:**  Go through the `TEST_F` blocks to understand what specific functionalities are being tested. Keywords like "EnumerateDevices", "GetUserMedia", "SetCaptureHandleConfig", and "ObserveDeviceChangeEvent" stand out.

4. **Infer Functionality from Test Cases:** Based on the test names and the code within them, deduce the functionality of the `MediaDevices` API being tested. For example:
    * `EnumerateDevices` tests the ability to retrieve lists of audio and video input/output devices.
    * `GetUserMedia` tests the ability to request access to media devices.
    * `SetCaptureHandleConfig` tests the ability to configure how media streams can be captured by other origins.
    * `ObserveDeviceChangeEvent` tests the mechanism for receiving notifications when media devices are added, removed, or changed.

5. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):** Consider how these C++ tests relate to web development. The `MediaDevices` API is a JavaScript API. The tests simulate interactions that a web page might perform.
    * **JavaScript:** The tests implicitly verify the behavior of the JavaScript `navigator.mediaDevices` API. The test setup uses V8 (the JavaScript engine in Chrome) to interact with the C++ code.
    * **HTML:** The concept of "origins" (tested in `SetCaptureHandleConfig`) is fundamental to web security and how browsers handle resources from different domains.
    * **CSS:** While not directly tested here, the outcome of media stream access can influence how media elements are rendered on a web page.

6. **Look for Logic and Assumptions:**  Examine the `MockMediaDevicesDispatcherHost`. This class simulates the browser's backend for handling media device requests. The specific device configurations and the logic within the mock host are the assumptions under which the tests run. Consider how inputs to the `MediaDevices` API (e.g., constraints in `getUserMedia`) lead to expected outputs (e.g., lists of devices).

7. **Identify Potential User/Programming Errors:**  Think about common mistakes developers might make when using the `MediaDevices` API and see if the tests cover those scenarios. For example, trying to enumerate devices after the connection to the backend is lost.

8. **Trace User Operations (Debugging Clues):**  Consider how a user interacting with a web page might trigger the code being tested. For example:
    * A user clicking a button that calls `navigator.mediaDevices.enumerateDevices()`.
    * A website requesting camera or microphone access using `navigator.mediaDevices.getUserMedia()`.
    * A website using the Capture Handle API to allow cross-origin capture.

9. **Summarize the Functionality (Part 1):** Condense the observations into a concise summary, focusing on the main purpose of the file.

10. **Refine and Structure:** Organize the findings into logical sections (functionality, relationship to web technologies, logic/assumptions, errors, user operations, summary). Use clear and concise language. Provide specific examples where possible.

**(Self-Correction during thought process):**

* Initially, I might focus too much on the low-level details of the C++ code. It's important to remember the higher-level purpose: testing a web API.
*  I should avoid getting bogged down in the specific implementation details of the mock host unless they are crucial for understanding the *tested* functionality.
* It's important to explicitly connect the C++ testing to the corresponding JavaScript APIs and web concepts.
```
这是目录为blink/renderer/modules/mediastream/media_devices_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

这个 C++ 文件 `media_devices_test.cc` 是 Chromium Blink 引擎中用于测试 `MediaDevices` 接口功能的单元测试文件。  它的主要目的是验证 `blink::MediaDevices` 类的各种功能是否按预期工作。

**主要功能:**

1. **测试 `enumerateDevices()` 方法:**
   - 验证是否能够正确枚举可用的音频输入、视频输入和音频输出设备。
   - 验证枚举结果中设备信息的正确性 (deviceId, groupId, label, kind)。
   - 验证在连接错误后调用 `enumerateDevices()` 是否会正确处理。
   - 验证 `enumerateDevices()` 是否能正确返回设备的能力信息 (例如视频输入设备支持的分辨率和帧率，音频输入设备的能力 - 虽然这部分在提供的代码片段中被注释掉了，但测试框架支持)。

2. **测试 `getUserMedia()` 方法:**
   - 验证调用 `getUserMedia()` 方法的基本流程，即使提供的约束条件为空 (会抛出类型错误)。

3. **测试 `addEventListener('devicechange', ...)` 功能:**
   - 验证是否能够正确监听 `devicechange` 事件，并在设备列表发生变化时触发。
   - 验证哪些类型的设备变化会触发 `devicechange` 事件 (例如添加、删除、重命名设备 ID、重命名标签、设备可用性变化)。
   - 验证改变设备的 `facingMode` (摄像头朝向) 是否会触发 `devicechange` 事件。
   - 验证在添加和移除 `devicechange` 事件监听器后，事件触发行为是否符合预期。

4. **测试 `setCaptureHandleConfig()` 方法:**
   - 验证可以设置用于控制跨域捕获媒体流的配置。
   - 验证设置空配置、包含 `exposeOrigin` 标志、包含 `captureHandle` 字符串、以及包含允许的源列表的配置是否生效。
   - 验证在连接错误后调用 `setCaptureHandleConfig()` 是否可以正常调用。

5. **模拟 `MediaDevicesDispatcherHost` 的行为:**
   - 通过 `MockMediaDevicesDispatcherHost` 类模拟浏览器进程中处理媒体设备请求的组件的行为。
   - 可以预设模拟的设备列表和设备能力。
   - 可以模拟设备状态的变化，从而触发 `devicechange` 事件。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 测试文件直接测试的是 Blink 引擎中 `MediaDevices` 接口的实现，而这个接口是 Web API 的一部分，主要通过 JavaScript 暴露给 Web 开发者。

* **JavaScript:**  `navigator.mediaDevices` 对象是 JavaScript 中访问 `MediaDevices` 接口的主要入口。这个测试文件中的测试用例模拟了 JavaScript 代码可能进行的调用，例如：
    ```javascript
    navigator.mediaDevices.enumerateDevices()
      .then(devices => {
        // 处理设备列表
      });

    navigator.mediaDevices.getUserMedia({ video: true, audio: true })
      .then(stream => {
        // 使用媒体流
      });

    navigator.mediaDevices.addEventListener('devicechange', event => {
      // 处理设备变化事件
    });

    navigator.mediaDevices.setCaptureHandleConfig({
      exposeOrigin: true,
      handle: 'my-capture-handle'
    });
    ```

* **HTML:** HTML 元素 (例如 `<video>` 和 `<audio>`) 通常用于呈现通过 `getUserMedia()` 获取的媒体流。虽然这个测试文件本身不涉及 HTML 的解析或渲染，但它测试的功能是使得 JavaScript 能够获取到媒体设备信息和媒体流，这是在 HTML 中使用媒体的基础。

* **CSS:** CSS 可以用于控制 HTML 中媒体元素的样式和布局。同样，这个测试文件不直接测试 CSS，但它测试的核心功能为 JavaScript 操作媒体提供了基础，而 JavaScript 可能会根据媒体设备的状态或媒体流的特性来动态调整 CSS 样式。

**逻辑推理 (假设输入与输出):**

假设输入：

1. **调用 `enumerateDevices()`:**
   - **假设输入:**  在浏览器中，JavaScript 代码调用 `navigator.mediaDevices.enumerateDevices()`。
   - **假设输出:**  C++ 测试代码会验证 `MockMediaDevicesDispatcherHost` 返回的预设设备列表是否与 JavaScript 接收到的设备列表一致。例如，如果 `MockMediaDevicesDispatcherHost` 配置了两个音频输入设备，那么测试会断言 JavaScript 返回的设备列表中确实有两个 `kind` 为 "audioinput" 的设备，并且它们的 `deviceId`, `label`, `groupId` 等属性与预设值一致。

2. **监听 `devicechange` 事件并添加新设备:**
   - **假设输入:** JavaScript 代码添加了 `devicechange` 事件监听器后，`MockMediaDevicesDispatcherHost` 模拟添加了一个新的视频输入设备。
   - **假设输出:** C++ 测试代码会验证 `devicechange` 事件是否被触发，并且事件对象中包含的设备列表更新了，包含了新添加的视频输入设备的信息。

**用户或编程常见的使用错误:**

1. **未处理 `enumerateDevices()` 的 Promise 拒绝:**
   - **错误:** 开发者可能忘记处理 `enumerateDevices()` 返回的 Promise 被拒绝的情况，例如在权限被拒绝或者底层系统出现错误时。
   - **测试覆盖:**  测试用例 `EnumerateDevicesAfterConnectionError` 模拟了底层连接错误，验证了在这种情况下 `enumerateDevices()` 会返回被拒绝的 Promise，这可以提醒开发者需要处理这种情况。

2. **错误地假设 `devicechange` 事件会立即触发:**
   - **错误:** 开发者可能错误地认为只要设备状态发生一点变化，`devicechange` 事件就会立刻触发，而忽略了某些细微的变化可能不会触发事件 (例如，摄像头朝向的改变在某些情况下可能不触发)。
   - **测试覆盖:** 测试用例 `ObserveDeviceChangeEvent` 中明确测试了哪些类型的设备变化会触发 `devicechange` 事件，哪些不会，帮助开发者理解事件的触发条件。

3. **在不安全的上下文中使用 `getUserMedia()` 或 `enumerateDevices()`:**
   - **错误:** 在非 HTTPS 或 localhost 环境下调用这些 API 通常会被浏览器阻止，导致 Promise 拒绝。
   - **虽然这个测试文件没有直接测试安全上下文，但它测试了 API 的基本功能，为上层安全策略的实施提供了基础。**

**用户操作到达这里的调试线索:**

当用户在浏览器中与使用 `MediaDevices` API 的网页进行交互时，可能会触发这里的代码。以下是一些可能的步骤：

1. **用户访问一个需要访问摄像头或麦克风的网站 (例如视频会议应用)。**
2. **网站的 JavaScript 代码调用 `navigator.mediaDevices.enumerateDevices()` 来获取可用的媒体设备列表，以便用户选择。**  如果调试过程中发现 `enumerateDevices()` 返回的设备列表不正确或缺少设备，可以查看这个测试文件中的相关测试用例，例如 `EnumerateDevices`，来理解 Blink 引擎是如何处理设备枚举的。
3. **用户允许网站访问其摄像头或麦克风，导致网站的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()`。** 如果调试过程中发现 `getUserMedia()` 调用失败或返回的媒体流不正确，可以查看这个测试文件中 `GetUserMediaCanBeCalled` (虽然这个测试比较基础) 以及其他更底层的媒体流相关的测试。
4. **用户连接或断开一个 USB 摄像头或麦克风，或者系统中的音频设备状态发生变化，导致浏览器触发 `devicechange` 事件。** 如果调试过程中发现 `devicechange` 事件没有按预期触发或事件携带的信息不正确，可以查看 `ObserveDeviceChangeEvent` 等测试用例，了解 Blink 引擎是如何监听和处理设备变化的。
5. **网站使用 Capture Handle API 来允许其他域捕获其媒体流。**  如果调试中涉及到跨域媒体捕获的问题，可以查看 `SetCaptureHandleConfig` 相关的测试用例，了解 Blink 引擎是如何处理捕获句柄配置的。

**归纳一下它的功能 (第 1 部分):**

这个 `media_devices_test.cc` 文件的主要功能是 **测试 Chromium Blink 引擎中 `MediaDevices` 接口的核心功能**，包括设备枚举 (`enumerateDevices`)、媒体流请求 (`getUserMedia`)、设备变化事件监听 (`devicechange`) 和跨域媒体捕获控制 (`setCaptureHandleConfig`)。 它通过模拟浏览器后端行为和 JavaScript 调用来验证这些功能是否按预期工作，并覆盖了一些常见的错误场景。  它是确保 Web 开发者能够可靠地使用 `navigator.mediaDevices` API 的重要组成部分。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_devices_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/mediastream/media_devices.h"

#include <memory>
#include <utility>

#include "base/test/metrics/histogram_tester.h"
#include "build/build_config.h"
#include "media/base/video_types.h"
#include "media/capture/mojom/video_capture_types.mojom.h"
#include "media/capture/video/video_capture_device_descriptor.h"
#include "media/capture/video_capture_types.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/mediastream/media_devices.h"
#include "third_party/blink/public/mojom/media/capture_handle_config.mojom-blink.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_output_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_capture_handle_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crop_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_double_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_long_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_device_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_device_kind.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_capabilities.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_restriction_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_user_media_stream_constraints.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/mediastream/crop_target.h"
#include "third_party/blink/renderer/modules/mediastream/input_device_info.h"
#include "third_party/blink/renderer/modules/mediastream/media_device_info.h"
#include "third_party/blink/renderer/modules/mediastream/restriction_target.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/geometry/mojom/geometry.mojom.h"

namespace blink {

using ::base::HistogramTester;
using ::blink::mojom::blink::MediaDeviceInfoPtr;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::StrictMock;
using MediaDeviceType = ::blink::mojom::MediaDeviceType;

namespace {

String MaxLengthCaptureHandle() {
  String maxHandle = "0123456789abcdef";  // 16 characters.
  while (maxHandle.length() < 1024) {
    maxHandle = maxHandle + maxHandle;
  }
  CHECK_EQ(maxHandle.length(), 1024u) << "Malformed test.";
  return maxHandle;
}

class MockMediaDevicesDispatcherHost final
    : public mojom::blink::MediaDevicesDispatcherHost {
 public:
  MockMediaDevicesDispatcherHost()
      : enumeration_({
            // clang-format off
            {
              {"fake_audio_input_1", "Fake Audio Input 1", "common_group_1"},
              {"fake_audio_input_2", "Fake Audio Input 2", "common_group_2"},
              {"fake_audio_input_3", "Fake Audio Input 3", "audio_input_group"},
            }, {
              {"fake_video_input_1", "Fake Video Input 1", "common_group_1",
               media::VideoCaptureControlSupport(),
               blink::mojom::FacingMode::kNone,
               media::CameraAvailability::kAvailable},
              {"fake_video_input_2", "Fake Video Input 2", "video_input_group",
               media::VideoCaptureControlSupport(),
               blink::mojom::FacingMode::kUser, std::nullopt},
              {"fake_video_input_3", "Fake Video Input 3", "video_input_group 2",
               media::VideoCaptureControlSupport(),
               blink::mojom::FacingMode::kUser,
               media::CameraAvailability::
                    kUnavailableExclusivelyUsedByOtherApplication},
            },
            {
              {"fake_audio_output_1", "Fake Audio Output 1", "common_group_1"},
              {"fake_audio_putput_2", "Fake Audio Output 2", "common_group_2"},
            }
            // clang-format on
        }) {
    // TODO(crbug.com/935960): add missing mocked capabilities and related
    // tests when media::AudioParameters is visible in this context.

    mojom::blink::VideoInputDeviceCapabilitiesPtr capabilities =
        mojom::blink::VideoInputDeviceCapabilities::New();
    capabilities->device_id = String(enumeration_[1][0].device_id);
    capabilities->group_id = String(enumeration_[1][0].group_id);
    capabilities->facing_mode =
        enumeration_[1][0].video_facing;  // mojom::blink::FacingMode::kNone;
    capabilities->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0, media::VideoPixelFormat::PIXEL_FORMAT_I420));
    capabilities->availability = static_cast<media::mojom::CameraAvailability>(
        *enumeration_[1][0].availability);
    video_input_capabilities_.push_back(std::move(capabilities));

    capabilities = mojom::blink::VideoInputDeviceCapabilities::New();
    capabilities->device_id = String(enumeration_[1][1].device_id);
    capabilities->group_id = String(enumeration_[1][1].group_id);
    capabilities->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0, media::VideoPixelFormat::PIXEL_FORMAT_I420));
    capabilities->facing_mode = enumeration_[1][1].video_facing;
    media::VideoCaptureFormat format;
    video_input_capabilities_.push_back(std::move(capabilities));

    capabilities = mojom::blink::VideoInputDeviceCapabilities::New();
    capabilities->device_id = String(enumeration_[1][2].device_id);
    capabilities->group_id = String(enumeration_[1][2].group_id);
    capabilities->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0, media::VideoPixelFormat::PIXEL_FORMAT_I420));
    capabilities->formats.push_back(
        media::VideoCaptureFormat(gfx::Size(1920, 1080), 60.0,
                                  media::VideoPixelFormat::PIXEL_FORMAT_I420));
    capabilities->facing_mode = enumeration_[1][2].video_facing;
    capabilities->availability = static_cast<media::mojom::CameraAvailability>(
        *enumeration_[1][2].availability);
    video_input_capabilities_.push_back(std::move(capabilities));
  }

  ~MockMediaDevicesDispatcherHost() override {
    EXPECT_FALSE(expected_capture_handle_config_);
  }

  void EnumerateDevices(bool request_audio_input,
                        bool request_video_input,
                        bool request_audio_output,
                        bool request_video_input_capabilities,
                        bool request_audio_input_capabilities,
                        EnumerateDevicesCallback callback) override {
    Vector<Vector<WebMediaDeviceInfo>> enumeration(static_cast<size_t>(
        blink::mojom::blink::MediaDeviceType::kNumMediaDeviceTypes));
    Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>
        video_input_capabilities;
    Vector<mojom::blink::AudioInputDeviceCapabilitiesPtr>
        audio_input_capabilities;
    if (request_audio_input) {
      wtf_size_t index = static_cast<wtf_size_t>(
          blink::mojom::blink::MediaDeviceType::kMediaAudioInput);
      enumeration[index] = enumeration_[index];

      if (request_audio_input_capabilities) {
        for (const auto& c : audio_input_capabilities_) {
          mojom::blink::AudioInputDeviceCapabilitiesPtr capabilities =
              mojom::blink::AudioInputDeviceCapabilities::New();
          *capabilities = *c;
          audio_input_capabilities.push_back(std::move(capabilities));
        }
      }
    }
    if (request_video_input) {
      wtf_size_t index = static_cast<wtf_size_t>(
          blink::mojom::blink::MediaDeviceType::kMediaVideoInput);
      enumeration[index] = enumeration_[index];

      if (request_video_input_capabilities) {
        for (const auto& c : video_input_capabilities_) {
          mojom::blink::VideoInputDeviceCapabilitiesPtr capabilities =
              mojom::blink::VideoInputDeviceCapabilities::New();
          *capabilities = *c;
          video_input_capabilities.push_back(std::move(capabilities));
        }
      }
    }
    if (request_audio_output) {
      wtf_size_t index = static_cast<wtf_size_t>(
          blink::mojom::blink::MediaDeviceType::kMediaAudioOutput);
      enumeration[index] = enumeration_[index];
    }
    std::move(callback).Run(std::move(enumeration),
                            std::move(video_input_capabilities),
                            std::move(audio_input_capabilities));
  }

  void SelectAudioOutput(
      const String& device_id,
      SelectAudioOutputCallback select_audio_output_callback) override {
    mojom::blink::SelectAudioOutputResultPtr result =
        mojom::blink::SelectAudioOutputResult::New();
    if (device_id == "test_device_id") {
      result->status = blink::mojom::AudioOutputStatus::kSuccess;
      result->device_info.device_id = "test_device_id";
      result->device_info.label = "Test Speaker";
      result->device_info.group_id = "test_group_id";
    } else {
      result->status = blink::mojom::AudioOutputStatus::kNoPermission;
    }
    std::move(select_audio_output_callback).Run(std::move(result));
  }

  void GetVideoInputCapabilities(GetVideoInputCapabilitiesCallback) override {
    NOTREACHED();
  }

  void GetAllVideoInputDeviceFormats(
      const String&,
      GetAllVideoInputDeviceFormatsCallback) override {
    NOTREACHED();
  }

  void GetAvailableVideoInputDeviceFormats(
      const String&,
      GetAvailableVideoInputDeviceFormatsCallback) override {
    NOTREACHED();
  }

  void GetAudioInputCapabilities(GetAudioInputCapabilitiesCallback) override {
    NOTREACHED();
  }

  void AddMediaDevicesListener(
      bool subscribe_audio_input,
      bool subscribe_video_input,
      bool subscribe_audio_output,
      mojo::PendingRemote<mojom::blink::MediaDevicesListener> listener)
      override {
    listener_.Bind(std::move(listener));
  }

  void SetCaptureHandleConfig(
      mojom::blink::CaptureHandleConfigPtr config) override {
    CHECK(config);

    auto expected_config = std::move(expected_capture_handle_config_);
    expected_capture_handle_config_ = nullptr;
    CHECK(expected_config);

    // TODO(crbug.com/1208868): Define CaptureHandleConfig traits that compare
    // |permitted_origins| using SecurityOrigin::IsSameOriginWith(), thereby
    // allowing this block to be replaced by a single EXPECT_EQ. (This problem
    // only manifests in Blink.)
    EXPECT_EQ(config->expose_origin, expected_config->expose_origin);
    EXPECT_EQ(config->capture_handle, expected_config->capture_handle);
    EXPECT_EQ(config->all_origins_permitted,
              expected_config->all_origins_permitted);
    CHECK_EQ(config->permitted_origins.size(),
             expected_config->permitted_origins.size());
    for (wtf_size_t i = 0; i < config->permitted_origins.size(); ++i) {
      EXPECT_TRUE(config->permitted_origins[i]->IsSameOriginWith(
          expected_config->permitted_origins[i].get()));
    }
  }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  void CloseFocusWindowOfOpportunity(const String& label) override {}

  void ProduceSubCaptureTargetId(
      SubCaptureTarget::Type type,
      ProduceSubCaptureTargetIdCallback callback) override {
    auto it = next_ids_.find(type);
    if (it == next_ids_.end()) {
      GTEST_FAIL();
    }
    std::vector<String>& queue = it->second;
    CHECK(!queue.empty());
    String next_id = queue.front();
    queue.erase(queue.begin());
    std::move(callback).Run(std::move(next_id));
  }

  void SetNextId(SubCaptureTarget::Type type, String next_id) {
    std::vector<String>& queue = next_ids_[type];
    queue.push_back(std::move(next_id));
  }
#endif

  void ExpectSetCaptureHandleConfig(
      mojom::blink::CaptureHandleConfigPtr config) {
    CHECK(config);
    CHECK(!expected_capture_handle_config_) << "Unfulfilled expectation.";
    expected_capture_handle_config_ = std::move(config);
  }

  mojom::blink::CaptureHandleConfigPtr expected_capture_handle_config() {
    return std::move(expected_capture_handle_config_);
  }

  mojo::PendingRemote<mojom::blink::MediaDevicesDispatcherHost>
  CreatePendingRemoteAndBind() {
    mojo::PendingRemote<mojom::blink::MediaDevicesDispatcherHost> remote;
    receiver_.Bind(remote.InitWithNewPipeAndPassReceiver());
    return remote;
  }

  void CloseBinding() { receiver_.reset(); }

  mojo::Remote<mojom::blink::MediaDevicesListener>& listener() {
    return listener_;
  }

  const Vector<Vector<WebMediaDeviceInfo>>& enumeration() const {
    return enumeration_;
  }

  void NotifyDeviceChanges() {
    listener()->OnDevicesChanged(MediaDeviceType::kMediaAudioInput,
                                 enumeration_[static_cast<wtf_size_t>(
                                     MediaDeviceType::kMediaAudioInput)]);
    listener()->OnDevicesChanged(MediaDeviceType::kMediaVideoInput,
                                 enumeration_[static_cast<wtf_size_t>(
                                     MediaDeviceType::kMediaVideoInput)]);
    listener()->OnDevicesChanged(MediaDeviceType::kMediaAudioOutput,
                                 enumeration_[static_cast<wtf_size_t>(
                                     MediaDeviceType::kMediaAudioOutput)]);
  }

  Vector<WebMediaDeviceInfo>& AudioInputDevices() {
    return enumeration_[static_cast<wtf_size_t>(
        MediaDeviceType::kMediaAudioInput)];
  }
  Vector<WebMediaDeviceInfo>& VideoInputDevices() {
    return enumeration_[static_cast<wtf_size_t>(
        MediaDeviceType::kMediaVideoInput)];
  }
  Vector<WebMediaDeviceInfo>& AudioOutputDevices() {
    return enumeration_[static_cast<wtf_size_t>(
        MediaDeviceType::kMediaAudioOutput)];
  }

  const Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>&
  VideoInputCapabilities() {
    return video_input_capabilities_;
  }

 private:
  mojo::Remote<mojom::blink::MediaDevicesListener> listener_;
  mojo::Receiver<mojom::blink::MediaDevicesDispatcherHost> receiver_{this};
  mojom::blink::CaptureHandleConfigPtr expected_capture_handle_config_;
  std::map<SubCaptureTarget::Type, std::vector<String>> next_ids_;

  Vector<Vector<WebMediaDeviceInfo>> enumeration_{static_cast<size_t>(
      blink::mojom::blink::MediaDeviceType::kNumMediaDeviceTypes)};
  Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>
      video_input_capabilities_;
  Vector<mojom::blink::AudioInputDeviceCapabilitiesPtr>
      audio_input_capabilities_;
};

class MockDeviceChangeEventListener : public NativeEventListener {
 public:
  MOCK_METHOD(void, Invoke, (ExecutionContext*, Event*));
};

V8MediaDeviceKind::Enum ToEnum(MediaDeviceType type) {
  switch (type) {
    case MediaDeviceType::kMediaAudioInput:
      return V8MediaDeviceKind::Enum::kAudioinput;
    case blink::MediaDeviceType::kMediaVideoInput:
      return V8MediaDeviceKind::Enum::kVideoinput;
    case blink::MediaDeviceType::kMediaAudioOutput:
      return V8MediaDeviceKind::Enum::kAudiooutput;
    case blink::MediaDeviceType::kNumMediaDeviceTypes:
      break;
  }
  NOTREACHED();
}

void VerifyFacingMode(const Vector<String>& js_facing_mode,
                      blink::mojom::FacingMode cpp_facing_mode) {
  switch (cpp_facing_mode) {
    case blink::mojom::FacingMode::kNone:
      EXPECT_TRUE(js_facing_mode.empty());
      break;
    case blink::mojom::FacingMode::kUser:
      EXPECT_THAT(js_facing_mode, ElementsAre("user"));
      break;
    case blink::mojom::FacingMode::kEnvironment:
      EXPECT_THAT(js_facing_mode, ElementsAre("environment"));
      break;
    case blink::mojom::FacingMode::kLeft:
      EXPECT_THAT(js_facing_mode, ElementsAre("left"));
      break;
    case blink::mojom::FacingMode::kRight:
      EXPECT_THAT(js_facing_mode, ElementsAre("right"));
      break;
  }
}

void VerifyDeviceInfo(const MediaDeviceInfo* device,
                      const WebMediaDeviceInfo& expected,
                      MediaDeviceType type) {
  EXPECT_EQ(device->deviceId(), String(expected.device_id));
  EXPECT_EQ(device->groupId(), String(expected.group_id));
  EXPECT_EQ(device->label(), String(expected.label));
  EXPECT_EQ(device->kind(), ToEnum(type));
}

void VerifyVideoInputCapabilities(
    const MediaDeviceInfo* device,
    const WebMediaDeviceInfo& expected_device_info,
    const mojom::blink::VideoInputDeviceCapabilitiesPtr&
        expected_capabilities) {
  CHECK_EQ(device->kind(), V8MediaDeviceKind::Enum::kVideoinput);
  const InputDeviceInfo* info = static_cast<const InputDeviceInfo*>(device);
  MediaTrackCapabilities* capabilities = info->getCapabilities();
  EXPECT_EQ(capabilities->hasFacingMode(), expected_device_info.IsAvailable());
  if (capabilities->hasFacingMode()) {
    VerifyFacingMode(capabilities->facingMode(),
                     expected_device_info.video_facing);
  }
  EXPECT_EQ(capabilities->hasDeviceId(), expected_device_info.IsAvailable());
  EXPECT_EQ(capabilities->hasGroupId(), expected_device_info.IsAvailable());
  EXPECT_EQ(capabilities->hasWidth(), expected_device_info.IsAvailable());
  EXPECT_EQ(capabilities->hasHeight(), expected_device_info.IsAvailable());
  EXPECT_EQ(capabilities->hasAspectRatio(), expected_device_info.IsAvailable());
  EXPECT_EQ(capabilities->hasFrameRate(), expected_device_info.IsAvailable());
  if (expected_device_info.IsAvailable()) {
    int max_expected_width = 0;
    int max_expected_height = 0;
    float max_expected_frame_rate = 0.0;
    for (const auto& format : expected_capabilities->formats) {
      max_expected_width =
          std::max(max_expected_width, format.frame_size.width());
      max_expected_height =
          std::max(max_expected_height, format.frame_size.height());
      max_expected_frame_rate =
          std::max(max_expected_frame_rate, format.frame_rate);
    }
    EXPECT_EQ(capabilities->deviceId().Utf8(), expected_device_info.device_id);
    EXPECT_EQ(capabilities->groupId().Utf8(), expected_device_info.group_id);
    EXPECT_EQ(capabilities->width()->min(), 1);
    EXPECT_EQ(capabilities->width()->max(), max_expected_width);
    EXPECT_EQ(capabilities->height()->min(), 1);
    EXPECT_EQ(capabilities->height()->max(), max_expected_height);
    EXPECT_EQ(capabilities->aspectRatio()->min(), 1.0 / max_expected_height);
    EXPECT_EQ(capabilities->aspectRatio()->max(), max_expected_width);
    EXPECT_EQ(capabilities->frameRate()->min(), 1.0);
    EXPECT_EQ(capabilities->frameRate()->max(), max_expected_frame_rate);
  }
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
SubCaptureTarget* ToSubCaptureTarget(const blink::ScriptValue& value) {
  if (CropTarget* crop_target =
          V8CropTarget::ToWrappable(value.GetIsolate(), value.V8Value())) {
    return crop_target;
  }

  if (RestrictionTarget* restriction_target = V8RestrictionTarget::ToWrappable(
          value.GetIsolate(), value.V8Value())) {
    return restriction_target;
  }

  NOTREACHED();
}
#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)

bool ProduceSubCaptureTargetAndGetPromise(V8TestingScope& scope,
                                          SubCaptureTarget::Type type,
                                          MediaDevices* media_devices,
                                          Element* element) {
  switch (type) {
    case SubCaptureTarget::Type::kCropTarget:
      return !media_devices
                  ->ProduceCropTarget(scope.GetScriptState(), element,
                                      scope.GetExceptionState())
                  .IsEmpty();

    case SubCaptureTarget::Type::kRestrictionTarget:
      return !media_devices
                  ->ProduceRestrictionTarget(scope.GetScriptState(), element,
                                             scope.GetExceptionState())
                  .IsEmpty();
  }
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
void ProduceSubCaptureTargetAndGetTester(
    V8TestingScope& scope,
    SubCaptureTarget::Type type,
    MediaDevices* media_devices,
    Element* element,
    std::optional<ScriptPromiseTester>& tester) {
  switch (type) {
    case SubCaptureTarget::Type::kCropTarget:
      tester.emplace(
          scope.GetScriptState(),
          media_devices->ProduceCropTarget(scope.GetScriptState(), element,
                                           scope.GetExceptionState()));
      return;
    case SubCaptureTarget::Type::kRestrictionTarget:
      tester.emplace(
          scope.GetScriptState(),
          media_devices->ProduceRestrictionTarget(
              scope.GetScriptState(), element, scope.GetExceptionState()));
      return;
  }
}
#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)

}  // namespace

class MediaDevicesTest : public PageTestBase {
 public:
  using MediaDeviceInfos = HeapVector<Member<MediaDeviceInfo>>;

  MediaDevicesTest()
      : dispatcher_host_(std::make_unique<MockMediaDevicesDispatcherHost>()),
        device_infos_(MakeGarbageCollected<MediaDeviceInfos>()) {}

  MediaDevices* GetMediaDevices(LocalDOMWindow& window) {
    if (!media_devices_) {
      media_devices_ = MakeGarbageCollected<MediaDevices>(*window.navigator());
      media_devices_->SetDispatcherHostForTesting(
          dispatcher_host_->CreatePendingRemoteAndBind());
    }
    return media_devices_;
  }

  void CloseBinding() { dispatcher_host_->CloseBinding(); }

  void OnListenerConnectionError() { listener_connection_error_ = true; }
  bool listener_connection_error() const { return listener_connection_error_; }

  ScopedTestingPlatformSupport<TestingPlatformSupport>& platform() {
    return platform_;
  }

  MockMediaDevicesDispatcherHost& dispatcher_host() {
    DCHECK(dispatcher_host_);
    return *dispatcher_host_;
  }

  void AddDeviceChangeListener(EventListener* event_listener) {
    GetMediaDevices(*GetDocument().domWindow())
        ->addEventListener(event_type_names::kDevicechange, event_listener);
    platform()->RunUntilIdle();
  }

  void RemoveDeviceChangeListener(EventListener* event_listener) {
    GetMediaDevices(*GetDocument().domWindow())
        ->removeEventListener(event_type_names::kDevicechange, event_listener,
                              /*use_capture=*/false);
    platform()->RunUntilIdle();
  }

  void NotifyDeviceChanges() {
    dispatcher_host().NotifyDeviceChanges();
    platform()->RunUntilIdle();
  }

  void ExpectEnumerateDevicesHistogramReport(
      EnumerateDevicesResult expected_result) {
    histogram_tester_.ExpectTotalCount(
        "Media.MediaDevices.EnumerateDevices.Result", 1);
    histogram_tester_.ExpectUniqueSample(
        "Media.MediaDevices.EnumerateDevices.Result", expected_result, 1);
    histogram_tester_.ExpectTotalCount(
        "Media.MediaDevices.EnumerateDevices.Latency", 1);
  }

 private:
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
  std::unique_ptr<MockMediaDevicesDispatcherHost> dispatcher_host_;
  Persistent<MediaDeviceInfos> device_infos_;
  bool listener_connection_error_ = false;
  Persistent<MediaDevices> media_devices_;
  base::HistogramTester histogram_tester_;
};

TEST_F(MediaDevicesTest, GetUserMediaCanBeCalled) {
  V8TestingScope scope;
  UserMediaStreamConstraints* constraints =
      UserMediaStreamConstraints::Create();
  auto promise = GetMediaDevices(scope.GetWindow())
                     ->getUserMedia(scope.GetScriptState(), constraints,
                                    scope.GetExceptionState());
  // We return the created promise before it was resolved/rejected.
  ASSERT_FALSE(promise.IsEmpty());
  // We expect a type error because the given constraints are empty.
  EXPECT_EQ(scope.GetExceptionState().Code(),
            ToExceptionCode(ESErrorType::kTypeError));
  VLOG(1) << "Exception message is" << scope.GetExceptionState().Message();
}

TEST_F(MediaDevicesTest, EnumerateDevices) {
  V8TestingScope scope;
  auto* media_devices = GetMediaDevices(*GetDocument().domWindow());
  ScriptPromiseTester tester(
      scope.GetScriptState(),
      media_devices->enumerateDevices(scope.GetScriptState(),
                                      scope.GetExceptionState()));
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  auto device_infos = NativeValueTraits<IDLArray<MediaDeviceInfo>>::NativeValue(
      scope.GetIsolate(), tester.Value().V8Value(), scope.GetExceptionState());
  ASSERT_FALSE(scope.GetExceptionState().HadException());

  ExpectEnumerateDevicesHistogramReport(EnumerateDevicesResult::kOk);

  const auto& video_input_capabilities =
      dispatcher_host().VideoInputCapabilities();
  for (wtf_size_t i = 0, result_index = 0, video_input_index = 0;
       i < static_cast<wtf_size_t>(MediaDeviceType::kNumMediaDeviceTypes);
       ++i) {
    for (const auto& expected_device_info :
         dispatcher_host().enumeration()[i]) {
      testing::Message message;
      message << "Verifying result index " << result_index;
      SCOPED_TRACE(message);
      VerifyDeviceInfo(device_infos[result_index], expected_device_info,
                       static_cast<MediaDeviceType>(i));
      if (i == static_cast<wtf_size_t>(MediaDeviceType::kMediaVideoInput)) {
        VerifyVideoInputCapabilities(
            device_infos[result_index], expected_device_info,
            video_input_capabilities[video_input_index]);
        video_input_index++;
      }
      result_index++;
    }
  }
}

TEST_F(MediaDevicesTest, EnumerateDevicesAfterConnectionError) {
  V8TestingScope scope;
  auto* media_devices = GetMediaDevices(*GetDocument().domWindow());

  // Simulate a connection error by closing the binding.
  CloseBinding();
  platform()->RunUntilIdle();

  ScriptPromiseTester tester(
      scope.GetScriptState(),
      media_devices->enumerateDevices(scope.GetScriptState(),
                                      scope.GetExceptionState()));
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  ExpectEnumerateDevicesHistogramReport(
      EnumerateDevicesResult::kErrorMediaDevicesDispatcherHostDisconnected);
}

TEST_F(MediaDevicesTest, SetCaptureHandleConfigAfterConnectionError) {
  V8TestingScope scope;
  auto* media_devices = GetMediaDevices(*GetDocument().domWindow());

  // Simulate a connection error by closing the binding.
  CloseBinding();
  platform()->RunUntilIdle();

  // Note: SetCaptureHandleConfigEmpty proves the following is a valid call.
  CaptureHandleConfig* input_config =
      MakeGarbageCollected<CaptureHandleConfig>();
  media_devices->setCaptureHandleConfig(scope.GetScriptState(), input_config,
                                        scope.GetExceptionState());
  platform()->RunUntilIdle();
}

TEST_F(MediaDevicesTest, ObserveDeviceChangeEvent) {
  if (!RuntimeEnabledFeatures::OnDeviceChangeEnabled()) {
    return;
  }
  EXPECT_FALSE(dispatcher_host().listener());

  // Subscribe to the devicechange event.
  StrictMock<MockDeviceChangeEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockDeviceChangeEventListener>>();
  AddDeviceChangeListener(event_listener);
  EXPECT_TRUE(dispatcher_host().listener());
  dispatcher_host().listener().set_disconnect_handler(WTF::BindOnce(
      &MediaDevicesTest::OnListenerConnectionError, WTF::Unretained(this)));

  // Send a device change notification from the dispatcher host. The event is
  // not fired because devices did not actually change.
  NotifyDeviceChanges();

  // Adding a new device fires the event.
  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().AudioInputDevices().push_back(WebMediaDeviceInfo(
      "new_fake_audio_input_device", "new_fake_label", "new_fake_group"));
  NotifyDeviceChanges();

  // Renaming a device ID fires the event.
  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().VideoInputDevices().begin()->device_id = "new_device_id";
  NotifyDeviceChanges();

  // Renaming a group ID fires the event.
  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().AudioOutputDevices().begin()->group_id = "new_group_id";
  NotifyDeviceChanges();

  // Renaming a label fires the event.
  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().AudioOutputDevices().begin()->label = "new_label";
  NotifyDeviceChanges();

  // Changing availability fires the event.
  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().VideoInputDevices().begin()->availability =
      media::CameraAvailability::kUnavailableExclusivelyUsedByOtherApplication;
  NotifyDeviceChanges();

  // Changing facing mode does not file the event.
  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(0);
  dispatcher_host().VideoInputDevices().begin()->video_facing =
      blink::mojom::FacingMode::kLeft;
  NotifyDeviceChanges();

  // Unsubscribe.
  RemoveDeviceChangeListener(event_listener);
  EXPECT_TRUE(listener_connection_error());

  // Sending a device change notification after unsubscribe does not fire the
  // event.
  dispatcher_host().AudioInputDevices().push_back(WebMediaDeviceInfo(
      "yet_another_input_device", "yet_another_label", "yet_another_group"));
  NotifyDeviceChanges();
}

TEST_F(MediaDevicesTest, RemoveDeviceFiresDeviceChange) {
  if (!RuntimeEnabledFeatures::OnDeviceChangeEnabled()) {
    return;
  }
  StrictMock<MockDeviceChangeEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockDeviceChangeEventListener>>();
  AddDeviceChangeListener(event_listener);

  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().VideoInputDevices().EraseAt(0);
  NotifyDeviceChanges();
}

TEST_F(MediaDevicesTest, RenameDeviceIDFiresDeviceChange) {
  if (!RuntimeEnabledFeatures::OnDeviceChangeEnabled()) {
    return;
  }
  StrictMock<MockDeviceChangeEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockDeviceChangeEventListener>>();
  AddDeviceChangeListener(event_listener);

  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().AudioOutputDevices().begin()->device_id = "new_device_id";
  NotifyDeviceChanges();
}

TEST_F(MediaDevicesTest, RenameLabelFiresDeviceChange) {
  if (!RuntimeEnabledFeatures::OnDeviceChangeEnabled()) {
    return;
  }
  StrictMock<MockDeviceChangeEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockDeviceChangeEventListener>>();
  AddDeviceChangeListener(event_listener);

  EXPECT_CALL(*event_listener, Invoke(_, _));
  dispatcher_host().AudioOutputDevices().begin()->label = "new_label";
  NotifyDeviceChanges();
}

TEST_F(MediaDevicesTest, SetCaptureHandleConfigEmpty) {
  V8TestingScope scope;
  auto* media_devices = GetMediaDevices(*GetDocument().domWindow());

  CaptureHandleConfig* input_config =
      MakeGarbageCollected<CaptureHandleConfig>();

  // Expected output.
  auto expected_config = mojom::blink::CaptureHandleConfig::New();
  expected_config->expose_origin = false;
  expected_config->capture_handle = "";
  expected_config->all_origins_permitted = false;
  expected_config->permitted_origins = {};
  dispatcher_host().ExpectSetCaptureHandleConfig(std::move(expected_config));

  media_devices->setCaptureHandleConfig(scope.GetScriptState(), input_config,
                                        scope.GetExceptionState());

  platform()->RunUntilIdle();

  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

TEST_F(MediaDevicesTest, SetCaptureHandleConfigWithExposeOrigin) {
  V8TestingScope sc
```