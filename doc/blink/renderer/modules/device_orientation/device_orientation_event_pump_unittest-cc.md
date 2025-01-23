Response:
Let's break down the thought process for analyzing the provided C++ unittest file.

1. **Understand the Goal:** The request asks for the functionality of the C++ file `device_orientation_event_pump_unittest.cc`, its relation to web technologies (JavaScript, HTML, CSS), examples of logic with inputs and outputs, common user/programming errors, and debugging steps.

2. **Initial Code Scan:**  The first step is to quickly skim the code, looking for keywords and structural elements that provide clues about its purpose. I see:
    * `#include`:  Indicates dependencies, which can hint at the file's role. `device_orientation_event_pump.h` is a crucial one.
    * `namespace blink`: This tells us the code belongs to the Blink rendering engine.
    * `TEST_F`: This is a GTest macro, clearly marking this as a unit testing file.
    * `MockDeviceOrientationController`: A custom class likely used to simulate the real device orientation controller for testing purposes.
    * `FakeSensorProvider`:  Another mock/fake object, probably simulating the hardware sensor interface.
    * `DeviceOrientationEventPump`: The core class being tested.
    * Tests with names like `SensorIsActive`, `SensorSuspendedDuringInitialization`, etc.: These describe specific scenarios being tested.

3. **Identify Core Functionality (Based on Class Names and Test Names):** The core functionality being tested revolves around `DeviceOrientationEventPump`. The test names suggest it handles:
    * Activating and suspending sensors.
    * Fallback mechanisms when certain sensors are unavailable.
    * Handling missing sensor data.
    * Filtering events based on thresholds.
    * Distinguishing between relative and absolute orientation.

4. **Relate to Web Technologies:**  Device orientation is a web API. This immediately suggests a connection to JavaScript. I need to think about *how* this C++ code relates to the JavaScript API:
    * **JavaScript Events:**  The `DeviceOrientationEvent` in JavaScript is the most obvious connection. This C++ code is likely responsible for *generating* the data that populates these JavaScript events.
    * **HTML Permissions/Features:**  While this specific file doesn't directly touch HTML parsing, the device orientation feature itself is exposed to web pages, requiring permissions and potentially affecting how a page renders. CSS might be influenced by orientation changes (e.g., responsive design).

5. **Detailed Analysis of Test Cases:** Now, examine individual tests to understand the specific logic being tested:

    * **`SensorIsActive`:** Registers the controller, checks if the sensor becomes active, simulates sensor data updates, "fires an event" (simulates the event being triggered), and verifies the data received by the controller. This confirms the basic flow of data when a sensor is available.

    * **`SensorSuspendedDuringInitialization`:**  Tests what happens if the controller is unregistered *during* the sensor initialization process. This checks for proper state management.

    * **`SensorIsActiveWithSensorFallback`:**  Simulates a scenario where the relative orientation sensor isn't available, and the system falls back to the absolute orientation sensor. This tests the fallback logic.

    * **`SomeSensorDataFieldsNotAvailable`:** Checks how the system handles cases where some sensor readings (alpha, beta, gamma) are NaN (Not a Number), indicating unavailability.

    * **`FireAllNullEvent`:** Tests the case where *no* sensor data is available.

    * **`NotFireEventWhenSensorReadingTimeStampIsZero`:** This is important. It implies a mechanism to avoid processing stale or invalid data. A zero timestamp likely indicates an issue with the sensor reading.

    * **`UpdateRespectsOrientationThreshold`:** This highlights a crucial optimization. Small changes in orientation might be ignored to prevent excessive event firing and battery drain.

6. **Logic and Input/Output Examples:** For each test case (or a representative subset), I need to formulate a hypothetical scenario with inputs and expected outputs. The key is to map the C++ test setup to actions a web page might take. For example, in `SensorIsActive`:
    * **Hypothetical Input:** JavaScript calls `window.addEventListener('deviceorientation', ...)` to start listening for events.
    * **Internal Processing:** The C++ code registers with the sensor provider. The fake sensor provides data (alpha=1, beta=2, gamma=3).
    * **Hypothetical Output:** A `DeviceOrientationEvent` is fired in JavaScript with `event.alpha = 1`, `event.beta = 2`, `event.gamma = 3`, and `event.absolute = false`.

7. **Common Errors:** Think about what could go wrong from a developer's perspective when using the Device Orientation API:
    * **Permission Issues:**  Forgetting to request or handle permission denials.
    * **Incorrect Event Listener Setup:**  Typos in the event name, incorrect target for the listener.
    * **Assuming Data Availability:**  Not checking `event.alpha`, `event.beta`, `event.gamma` for `null` or handling `event.absolute` correctly.
    * **Performance Concerns:**  Not being mindful of the frequency of events and potential battery drain.

8. **Debugging Steps:**  Consider how a developer would troubleshoot issues related to device orientation:
    * **Browser Developer Tools:** Inspecting the console for errors, checking event listeners, using the sensor emulation tools.
    * **Testing on Real Devices:**  Emulators may not perfectly replicate real-world sensor behavior.
    * **Logging:** Adding `console.log` statements to track event data.
    * **Simplifying the Code:** Isolating the problematic part of the JavaScript code.

9. **Structure the Answer:** Organize the information logically, using clear headings and bullet points. Start with the core functionality, then move to the relationships with web technologies, examples, errors, and debugging. Use clear and concise language.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, ensure the connection between the C++ test setup and the corresponding JavaScript behavior is clear. Make sure the examples are easy to understand.
好的，让我们详细分析一下 `blink/renderer/modules/device_orientation/device_orientation_event_pump_unittest.cc` 这个文件。

**功能概述**

这个文件是一个 C++ 单元测试文件，用于测试 `DeviceOrientationEventPump` 类的功能。`DeviceOrientationEventPump` 类在 Chromium Blink 渲染引擎中负责从底层传感器获取设备方向数据，并将其转换为可以分发给 JavaScript 的 `DeviceOrientationEvent`。

**核心功能点测试:**

* **传感器激活与数据接收:** 测试当 `DeviceOrientationEventPump` 注册后，是否能正确激活传感器，并在传感器数据更新时接收到数据。
* **传感器挂起与恢复:** 测试在注册和取消注册 `DeviceOrientationEventPump` 时，传感器是否能正确地挂起和恢复。
* **传感器回退机制:**  测试当相对方向传感器不可用时，`DeviceOrientationEventPump` 是否能正确地回退到使用绝对方向传感器。
* **处理部分传感器数据不可用:** 测试当传感器返回部分数据为 `NaN` 时，`DeviceOrientationEventPump` 如何处理，并确保相应的 `canProvideAlpha`、`canProvideBeta`、`canProvideGamma` 标志被正确设置。
* **处理所有传感器数据不可用:** 测试当所有传感器数据都不可用时，`DeviceOrientationEventPump` 如何生成 `DeviceOrientationEvent`。
* **时间戳为零时的处理:** 测试当传感器数据的时间戳为零时，`DeviceOrientationEventPump` 是否会阻止事件的触发，这通常意味着数据无效或陈旧。
* **方向变化的阈值处理:** 测试 `DeviceOrientationEventPump` 是否会尊重预设的方向变化阈值，只有当方向变化超过阈值时才触发新的事件，以避免过于频繁的事件触发。
* **绝对方向事件泵的独立测试:**  文件中还包含了针对绝对方向事件泵的独立测试，验证其在没有相对方向传感器时的行为。

**与 JavaScript, HTML, CSS 的关系**

这个 C++ 文件直接关系到 JavaScript 中 `DeviceOrientationEvent` 的功能。

* **JavaScript:**
    * **事件触发:** `DeviceOrientationEventPump` 的主要职责是处理传感器数据，并最终触发 JavaScript 中的 `deviceorientation` 事件。
    * **事件数据:**  测试用例中验证了 `DeviceOrientationData` 中的 `alpha`、`beta`、`gamma` 以及 `absolute` 属性，这些属性会映射到 JavaScript `DeviceOrientationEvent` 对象的相应属性上。
    * **示例:**  在 JavaScript 中，开发者可以通过监听 `deviceorientation` 事件来获取设备方向信息：
      ```javascript
      window.addEventListener('deviceorientation', function(event) {
        console.log('Alpha:', event.alpha);
        console.log('Beta:', event.beta);
        console.log('Gamma:', event.gamma);
        console.log('Absolute:', event.absolute);
      });
      ```
      `DeviceOrientationEventPump` 的正确工作是保证这段 JavaScript 代码能够接收到准确的设备方向数据。

* **HTML:**
    * **权限请求:**  在 HTML 中，一些新的 API 可能需要用户授权才能访问，例如传感器 API。虽然这个测试文件本身没有直接涉及 HTML，但 `DeviceOrientationEvent` 的使用可能涉及到浏览器对传感器权限的管理。

* **CSS:**
    * **媒体查询:** CSS 可以通过媒体查询（Media Queries）来响应设备方向的变化。例如，可以使用 `@media (orientation: portrait)` 和 `@media (orientation: landscape)` 来应用不同的样式。`DeviceOrientationEventPump` 提供的方向数据是这些媒体查询的基础。
    * **示例:**
      ```css
      @media (orientation: portrait) {
        body {
          background-color: lightblue;
        }
      }

      @media (orientation: landscape) {
        body {
          background-color: lightgreen;
        }
      }
      ```

**逻辑推理：假设输入与输出**

**测试用例：`SensorIsActive`**

* **假设输入:**
    1. JavaScript 代码请求监听 `deviceorientation` 事件。
    2. `DeviceOrientationEventPump` 被注册。
    3. 底层传感器提供相对方向数据：alpha=1, beta=2, gamma=3。
    4. `FireEvent()` 被调用，模拟事件触发。

* **预期输出:**
    1. `controller()->relative_sensor_state()` 为 `State::kActive`。
    2. `controller()->did_change_device_orientation()` 返回 `true`，表示方向数据已更新。
    3. `controller()->data()` 返回的 `DeviceOrientationData` 对象具有以下属性：
        *   `Alpha()` ≈ 1
        *   `CanProvideAlpha()` 为 `true`
        *   `Beta()` ≈ 2
        *   `CanProvideBeta()` 为 `true`
        *   `Gamma()` ≈ 3
        *   `CanProvideGamma()` 为 `true`
        *   `Absolute()` 为 `false`

**测试用例：`SensorIsActiveWithSensorFallback`**

* **假设输入:**
    1. JavaScript 代码请求监听 `deviceorientation` 事件。
    2. 相对方向传感器不可用 (`sensor_provider()->set_relative_orientation_sensor_is_available(false)`)。
    3. `DeviceOrientationEventPump` 被注册。
    4. 底层绝对方向传感器提供数据：alpha=4, beta=5, gamma=6。
    5. `FireEvent()` 被调用。

* **预期输出:**
    1. `controller()->relative_sensor_state()` 为 `State::kNotInitialized`。
    2. `controller()->absolute_sensor_state()` 为 `State::kActive`。
    3. `controller()->did_change_device_orientation()` 返回 `true`。
    4. `controller()->data()` 返回的 `DeviceOrientationData` 对象具有以下属性：
        *   `Alpha()` ≈ 4
        *   `CanProvideAlpha()` 为 `true`
        *   `Beta()` ≈ 5
        *   `CanProvideBeta()` 为 `true`
        *   `Gamma()` ≈ 6
        *   `CanProvideGamma()` 为 `true`
        *   `Absolute()` 为 `true`

**用户或编程常见的使用错误**

1. **未正确监听事件:**  开发者可能拼写错误事件名称 (`'deviceoreintation'` 而不是 `'deviceorientation'`) 或者将事件监听器添加到错误的元素上。
    ```javascript
    // 错误示例
    window.addEventListener('deviceoreintation', function(event) { /* ... */ });

    // 正确示例
    window.addEventListener('deviceorientation', function(event) { /* ... */ });
    ```

2. **假设所有数据都可用:** 开发者可能没有检查 `event.alpha`、`event.beta`、`event.gamma` 是否为 `null`，或者没有考虑到 `event.absolute` 的值。在某些情况下，某些方向数据可能不可用。
    ```javascript
    window.addEventListener('deviceorientation', function(event) {
      // 没有检查数据是否可用
      console.log(event.alpha.toFixed(2)); // 如果 alpha 为 null，会报错
    });

    window.addEventListener('deviceorientation', function(event) {
      // 正确示例：检查数据是否可用
      if (event.alpha !== null) {
        console.log(event.alpha.toFixed(2));
      }
    });
    ```

3. **性能问题：过度处理事件:**  `deviceorientation` 事件可能会非常频繁地触发，开发者如果没有进行适当的节流或防抖处理，可能会导致性能问题和电池消耗。
    ```javascript
    let lastProcessedTime = 0;
    const throttleDelay = 100; // 毫秒

    window.addEventListener('deviceorientation', function(event) {
      const now = Date.now();
      if (now - lastProcessedTime > throttleDelay) {
        // 处理事件
        console.log('Orientation changed');
        lastProcessedTime = now;
      }
    });
    ```

4. **权限问题:** 在某些浏览器或场景下，访问设备方向传感器可能需要用户授权。开发者需要处理权限被拒绝的情况。虽然这个 C++ 文件本身不直接处理权限，但它为上层权限管理提供了基础。

**用户操作如何一步步到达这里，作为调试线索**

1. **用户打开一个网页:** 用户在浏览器中访问一个使用了 Device Orientation API 的网页。
2. **网页请求设备方向数据:**  网页的 JavaScript 代码通过 `window.addEventListener('deviceorientation', ...)` 注册了设备方向事件监听器。
3. **浏览器触发权限请求 (如果需要):**  如果浏览器尚未获得访问传感器的权限，可能会弹出一个权限请求提示框。
4. **浏览器底层获取传感器数据:**  浏览器底层 (C++ 代码) 开始尝试从设备的物理传感器（例如陀螺仪、加速度计）读取数据。
5. **`DeviceOrientationEventPump` 参与数据处理:**
    *   `DeviceOrientationEventPump` (在 `MockDeviceOrientationController::RegisterWithDispatcher()` 中通过 `orientation_pump_->SetController(this);` 注册) 开始监听底层的传感器数据更新。
    *   当传感器数据更新时，`DeviceOrientationEventPump` 会接收到这些原始数据。
    *   `DeviceOrientationEventPump` 会根据当前的状态（例如，是否应该使用绝对方向传感器）处理这些数据。
    *   `FireEvent()` 方法被调用 (在真实场景中，可能由底层传感器驱动或定时器触发)，将处理后的数据封装到 `DeviceOrientationData` 对象中。
    *   `MockDeviceOrientationController::DidUpdateData()` 被调用，通知控制器数据已更新。
6. **触发 JavaScript 事件:**  Blink 渲染引擎最终会创建一个 `DeviceOrientationEvent` 对象，并将 `DeviceOrientationData` 中的数据填充到这个事件对象中。
7. **JavaScript 接收事件:** 网页的 JavaScript 事件监听器接收到 `deviceorientation` 事件，并可以访问 `event.alpha`、`event.beta`、`event.gamma` 等属性。

**调试线索:**

如果开发者在使用 Device Orientation API 时遇到问题，可以按照以下步骤进行调试，其中会涉及到对 `DeviceOrientationEventPump` 行为的理解：

1. **检查 JavaScript 代码:**  确认事件监听器是否正确注册，事件处理函数是否有错误，是否正确处理了可能为 `null` 的数据。
2. **使用浏览器开发者工具:**
    *   **Console:** 查看是否有 JavaScript 错误或警告。
    *   **Sensors 标签 (Chrome DevTools):**  可以使用 Chrome 开发者工具的 "Sensors" 标签来模拟设备方向的变化，观察 JavaScript 事件是否被触发，以及事件数据是否正确。这可以帮助判断问题是否出在 JavaScript 代码本身还是底层的传感器数据获取。
    *   **Event Listeners 标签:** 检查 `window` 对象上是否成功注册了 `deviceorientation` 事件监听器。
3. **检查浏览器权限:** 确认网页是否具有访问设备传感器的权限。
4. **查看浏览器内部日志 (如果可以):**  在 Chromium 开发版本中，可能可以通过特定的标志或内部页面查看更底层的日志信息，这可能包含关于传感器数据获取和 `DeviceOrientationEventPump` 运行状态的信息。
5. **单元测试 (作为开发者):**  `device_orientation_event_pump_unittest.cc` 文件本身就是很好的调试参考。如果怀疑是 Blink 引擎的实现问题，可以参考这些单元测试来理解 `DeviceOrientationEventPump` 的预期行为，甚至可以编写新的单元测试来复现和验证问题。

总而言之，`blink/renderer/modules/device_orientation/device_orientation_event_pump_unittest.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中设备方向功能的正确性，并且直接影响了 web 开发者在 JavaScript 中使用 `DeviceOrientationEvent` 的体验。理解其功能和测试用例可以帮助开发者更好地理解和调试与设备方向相关的 web 应用。

### 提示词
```
这是目录为blink/renderer/modules/device_orientation/device_orientation_event_pump_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/device_orientation/device_orientation_event_pump.h"

#include <string.h>

#include <memory>

#include "base/run_loop.h"
#include "base/test/bind.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/device/public/cpp/test/fake_sensor_and_provider.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/cross_variant_mojo_util.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/platform_event_controller.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_data.h"
#include "third_party/blink/renderer/modules/device_orientation/device_sensor_entry.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace {

constexpr double kEpsilon = 1e-8;

}  // namespace

namespace blink {

using device::FakeSensorProvider;
using device::mojom::SensorType;

using State = DeviceSensorEntry::State;

class MockDeviceOrientationController final
    : public GarbageCollected<MockDeviceOrientationController>,
      public PlatformEventController {
 public:
  explicit MockDeviceOrientationController(
      DeviceOrientationEventPump* orientation_pump,
      LocalDOMWindow& window)
      : PlatformEventController(window),
        did_change_device_orientation_(false),
        orientation_pump_(orientation_pump) {}

  MockDeviceOrientationController(const MockDeviceOrientationController&) =
      delete;
  MockDeviceOrientationController& operator=(
      const MockDeviceOrientationController&) = delete;

  ~MockDeviceOrientationController() override {}

  void Trace(Visitor* visitor) const override {
    PlatformEventController::Trace(visitor);
    visitor->Trace(orientation_pump_);
  }

  void DidUpdateData() override { did_change_device_orientation_ = true; }

  bool did_change_device_orientation() const {
    return did_change_device_orientation_;
  }
  void set_did_change_device_orientation(bool value) {
    did_change_device_orientation_ = value;
  }

  void RegisterWithDispatcher() override {
    orientation_pump_->SetController(this);
  }

  bool HasLastData() override {
    return orientation_pump_->LatestDeviceOrientationData();
  }

  void UnregisterWithDispatcher() override {
    orientation_pump_->RemoveController();
  }

  const DeviceOrientationData* data() {
    return orientation_pump_->LatestDeviceOrientationData();
  }

  DeviceSensorEntry::State relative_sensor_state() {
    return orientation_pump_->GetRelativeSensorStateForTesting();
  }

  DeviceSensorEntry::State absolute_sensor_state() {
    return orientation_pump_->GetAbsoluteSensorStateForTesting();
  }

  DeviceOrientationEventPump* orientation_pump() {
    return orientation_pump_.Get();
  }

 private:
  bool did_change_device_orientation_;
  Member<DeviceOrientationEventPump> orientation_pump_;
};

class DeviceOrientationEventPumpTest : public testing::Test {
 public:
  DeviceOrientationEventPumpTest() = default;

  DeviceOrientationEventPumpTest(const DeviceOrientationEventPumpTest&) =
      delete;
  DeviceOrientationEventPumpTest& operator=(
      const DeviceOrientationEventPumpTest&) = delete;

 protected:
  void SetUp() override {
    page_holder_ = std::make_unique<DummyPageHolder>();

    mojo::PendingRemote<mojom::blink::WebSensorProvider> sensor_provider;
    sensor_provider_.Bind(ToCrossVariantMojoType(
        sensor_provider.InitWithNewPipeAndPassReceiver()));
    auto* orientation_pump = MakeGarbageCollected<DeviceOrientationEventPump>(
        page_holder_->GetFrame(), false /* absolute */);
    orientation_pump->SetSensorProviderForTesting(std::move(sensor_provider));

    controller_ = MakeGarbageCollected<MockDeviceOrientationController>(
        orientation_pump, *page_holder_->GetFrame().DomWindow());

    EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
    EXPECT_EQ(controller()->absolute_sensor_state(), State::kNotInitialized);
    EXPECT_EQ(DeviceOrientationEventPump::PumpState::kStopped,
              controller_->orientation_pump()->GetPumpStateForTesting());
  }

  void FireEvent() { controller_->orientation_pump()->FireEvent(nullptr); }

  MockDeviceOrientationController* controller() { return controller_.Get(); }

  FakeSensorProvider* sensor_provider() { return &sensor_provider_; }

 private:
  test::TaskEnvironment task_environment_;
  Persistent<MockDeviceOrientationController> controller_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  FakeSensorProvider sensor_provider_;
};

TEST_F(DeviceOrientationEventPumpTest, SensorIsActive) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kActive);

  sensor_provider()->UpdateRelativeOrientationSensorData(
      1 /* alpha */, 2 /* beta */, 3 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  // DeviceOrientation Event provides relative orientation data when it is
  // available.
  EXPECT_DOUBLE_EQ(1, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(2, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(3, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_FALSE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest, SensorSuspendedDuringInitialization) {
  controller()->RegisterWithDispatcher();
  EXPECT_EQ(controller()->relative_sensor_state(), State::kInitializing);

  controller()->UnregisterWithDispatcher();
  EXPECT_EQ(controller()->relative_sensor_state(), State::kShouldSuspend);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(controller()->relative_sensor_state(), State::kSuspended);

  controller()->RegisterWithDispatcher();
  EXPECT_EQ(controller()->relative_sensor_state(), State::kActive);

  sensor_provider()->UpdateRelativeOrientationSensorData(
      1 /* alpha */, 2 /* beta */, 3 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  // DeviceOrientation Event provides relative orientation data when it is
  // available.
  EXPECT_DOUBLE_EQ(1, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(2, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(3, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_FALSE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest, SensorIsActiveWithSensorFallback) {
  sensor_provider()->set_relative_orientation_sensor_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */, 5 /* beta */, 6 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  // DeviceOrientation Event provides absolute orientation data when relative
  // orientation data is not available but absolute orientation data is
  // available.
  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(5, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());

  // Since no relative orientation data is available, DeviceOrientationEvent
  // fallback to provide absolute orientation data.
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest, SensorSuspendedDuringFallback) {
  // Make the relative orientation sensor unavailable and the first time it is
  // requested cause Stop() to be called before the error is processed.
  sensor_provider()->set_relative_orientation_sensor_is_available(false);
  sensor_provider()->set_sensor_requested_callback(
      base::BindLambdaForTesting([&](SensorType type) {
        EXPECT_EQ(type, SensorType::RELATIVE_ORIENTATION_EULER_ANGLES);
        controller()->UnregisterWithDispatcher();
        EXPECT_EQ(controller()->relative_sensor_state(), State::kShouldSuspend);
      }));

  controller()->RegisterWithDispatcher();
  EXPECT_EQ(controller()->relative_sensor_state(), State::kInitializing);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */, 5 /* beta */, 6 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  // DeviceOrientation Event provides absolute orientation data when relative
  // orientation data is not available but absolute orientation data is
  // available.
  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(5, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());

  // Since no relative orientation data is available, DeviceOrientationEvent
  // fallback to provide absolute orientation data.
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest, SomeSensorDataFieldsNotAvailable) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kActive);

  sensor_provider()->UpdateRelativeOrientationSensorData(
      NAN /* alpha */, 2 /* beta */, 3 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_FALSE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(2, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(3, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_FALSE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest,
       SomeSensorDataFieldsNotAvailableWithSensorFallback) {
  sensor_provider()->set_relative_orientation_sensor_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */, NAN /* beta */, 6 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  // DeviceOrientation Event provides absolute orientation data when relative
  // orientation data is not available but absolute orientation data is
  // available.
  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_FALSE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  // Since no relative orientation data is available, DeviceOrientationEvent
  // fallback to provide absolute orientation data.
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest, FireAllNullEvent) {
  // No active sensors.
  sensor_provider()->set_relative_orientation_sensor_is_available(false);
  sensor_provider()->set_absolute_orientation_sensor_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kNotInitialized);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_FALSE(received_data->CanProvideAlpha());
  EXPECT_FALSE(received_data->CanProvideBeta());
  EXPECT_FALSE(received_data->CanProvideGamma());
  EXPECT_FALSE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kNotInitialized);
}

TEST_F(DeviceOrientationEventPumpTest,
       NotFireEventWhenSensorReadingTimeStampIsZero) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kActive);

  FireEvent();

  EXPECT_FALSE(controller()->did_change_device_orientation());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest,
       NotFireEventWhenSensorReadingTimeStampIsZeroWithSensorFallback) {
  sensor_provider()->set_relative_orientation_sensor_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  FireEvent();

  EXPECT_FALSE(controller()->did_change_device_orientation());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest, UpdateRespectsOrientationThreshold) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kActive);

  sensor_provider()->UpdateRelativeOrientationSensorData(
      1 /* alpha */, 2 /* beta */, 3 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  // DeviceOrientation Event provides relative orientation data when it is
  // available.
  EXPECT_DOUBLE_EQ(1, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(2, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(3, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_FALSE(received_data->Absolute());

  controller()->set_did_change_device_orientation(false);

  sensor_provider()->UpdateRelativeOrientationSensorData(
      1 + DeviceOrientationEventPump::kOrientationThreshold / 2.0 /* alpha */,
      2 /* beta */, 3 /* gamma */);

  FireEvent();

  received_data = controller()->data();
  EXPECT_FALSE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(1, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(2, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(3, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_FALSE(received_data->Absolute());

  controller()->set_did_change_device_orientation(false);

  sensor_provider()->UpdateRelativeOrientationSensorData(
      1 + DeviceOrientationEventPump::kOrientationThreshold /* alpha */,
      2 /* beta */, 3 /* gamma */);

  FireEvent();

  received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(1 + DeviceOrientationEventPump::kOrientationThreshold,
                   received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(2, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(3, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_FALSE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kSuspended);
}

TEST_F(DeviceOrientationEventPumpTest,
       UpdateRespectsOrientationThresholdWithSensorFallback) {
  sensor_provider()->set_relative_orientation_sensor_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */, 5 /* beta */, 6 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  // DeviceOrientation Event provides absolute orientation data when relative
  // orientation data is not available but absolute orientation data is
  // available.
  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(5, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  // Since no relative orientation data is available, DeviceOrientationEvent
  // fallback to provide absolute orientation data.
  EXPECT_TRUE(received_data->Absolute());

  controller()->set_did_change_device_orientation(false);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */,
      5 + DeviceOrientationEventPump::kOrientationThreshold / 2.0 /* beta */,
      6 /* gamma */);

  FireEvent();

  received_data = controller()->data();
  EXPECT_FALSE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(5, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->set_did_change_device_orientation(false);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */,
      5 + DeviceOrientationEventPump::kOrientationThreshold +
          kEpsilon /* beta */,
      6 /* gamma */);

  FireEvent();

  received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(
      5 + DeviceOrientationEventPump::kOrientationThreshold + kEpsilon,
      received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->relative_sensor_state(), State::kNotInitialized);
  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

class DeviceAbsoluteOrientationEventPumpTest : public testing::Test {
 public:
  DeviceAbsoluteOrientationEventPumpTest() = default;

  DeviceAbsoluteOrientationEventPumpTest(
      const DeviceAbsoluteOrientationEventPumpTest&) = delete;
  DeviceAbsoluteOrientationEventPumpTest& operator=(
      const DeviceAbsoluteOrientationEventPumpTest&) = delete;

 protected:
  void SetUp() override {
    page_holder_ = std::make_unique<DummyPageHolder>();

    mojo::PendingRemote<mojom::blink::WebSensorProvider> sensor_provider;
    sensor_provider_.Bind(ToCrossVariantMojoType(
        sensor_provider.InitWithNewPipeAndPassReceiver()));
    auto* absolute_orientation_pump =
        MakeGarbageCollected<DeviceOrientationEventPump>(
            page_holder_->GetFrame(), true /* absolute */);
    absolute_orientation_pump->SetSensorProviderForTesting(
        std::move(sensor_provider));

    controller_ = MakeGarbageCollected<MockDeviceOrientationController>(
        absolute_orientation_pump, *page_holder_->GetFrame().DomWindow());

    EXPECT_EQ(controller()->absolute_sensor_state(), State::kNotInitialized);
    EXPECT_EQ(DeviceOrientationEventPump::PumpState::kStopped,
              controller_->orientation_pump()->GetPumpStateForTesting());
  }

  void FireEvent() { controller_->orientation_pump()->FireEvent(nullptr); }

  MockDeviceOrientationController* controller() { return controller_.Get(); }

  FakeSensorProvider* sensor_provider() { return &sensor_provider_; }

 private:
  test::TaskEnvironment task_environment_;
  Persistent<MockDeviceOrientationController> controller_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  FakeSensorProvider sensor_provider_;
};

TEST_F(DeviceAbsoluteOrientationEventPumpTest, SensorIsActive) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */, 5 /* beta */, 6 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(5, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

TEST_F(DeviceAbsoluteOrientationEventPumpTest,
       SomeSensorDataFieldsNotAvailable) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */, NAN /* beta */, 6 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_FALSE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

TEST_F(DeviceAbsoluteOrientationEventPumpTest, FireAllNullEvent) {
  // No active sensor.
  sensor_provider()->set_absolute_orientation_sensor_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kNotInitialized);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_FALSE(received_data->CanProvideAlpha());
  EXPECT_FALSE(received_data->CanProvideBeta());
  EXPECT_FALSE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kNotInitialized);
}

TEST_F(DeviceAbsoluteOrientationEventPumpTest,
       NotFireEventWhenSensorReadingTimeStampIsZero) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  FireEvent();

  EXPECT_FALSE(controller()->did_change_device_orientation());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

TEST_F(DeviceAbsoluteOrientationEventPumpTest,
       UpdateRespectsOrientationThreshold) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kActive);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */, 5 /* beta */, 6 /* gamma */);

  FireEvent();

  const DeviceOrientationData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(5, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->set_did_change_device_orientation(false);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */,
      5 + DeviceOrientationEventPump::kOrientationThreshold / 2.0 /* beta */,
      6 /* gamma */);

  FireEvent();

  received_data = controller()->data();
  EXPECT_FALSE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(5, received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->set_did_change_device_orientation(false);

  sensor_provider()->UpdateAbsoluteOrientationSensorData(
      4 /* alpha */,
      5 + DeviceOrientationEventPump::kOrientationThreshold +
          kEpsilon /* beta */,
      6 /* gamma */);

  FireEvent();

  received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_orientation());

  EXPECT_DOUBLE_EQ(4, received_data->Alpha());
  EXPECT_TRUE(received_data->CanProvideAlpha());
  EXPECT_DOUBLE_EQ(
      5 + DeviceOrientationEventPump::kOrientationThreshold + kEpsilon,
      received_data->Beta());
  EXPECT_TRUE(received_data->CanProvideBeta());
  EXPECT_DOUBLE_EQ(6, received_data->Gamma());
  EXPECT_TRUE(received_data->CanProvideGamma());
  EXPECT_TRUE(received_data->Absolute());

  controller()->UnregisterWithDispatcher();

  EXPECT_EQ(controller()->absolute_sensor_state(), State::kSuspended);
}

}  // namespace blink
```