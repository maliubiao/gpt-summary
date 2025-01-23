Response:
Let's break down the thought process to analyze the provided C++ unittest file.

1. **Understand the Goal:** The core objective is to analyze a C++ file (`device_motion_event_pump_unittest.cc`) from the Chromium Blink engine. The request asks for its functionality, relation to web technologies (JavaScript, HTML, CSS), logical reasoning examples, common user errors, and debugging hints.

2. **Initial Scan for Keywords:** Quickly scan the code for relevant terms:
    * `DeviceMotionEventPump`: This is the central class being tested. It likely manages the flow of device motion data.
    * `MockDeviceMotionController`: A test double, used to simulate the interaction of other components with the `DeviceMotionEventPump`.
    * `FakeSensorProvider`: Another test double, simulating the underlying sensor hardware.
    * `Accelerometer`, `Gyroscope`, `LinearAccelerationSensor`: The types of sensor data being handled.
    * `DeviceMotionData`, `DeviceMotionEventAcceleration`, `DeviceMotionEventRotationRate`: Data structures representing the motion event information.
    * `RegisterWithDispatcher`, `UnregisterWithDispatcher`:  Indicates how components subscribe and unsubscribe to motion events.
    * `FireEvent`: Triggers the event processing logic.
    * `testing::Test`, `TEST_F`, `EXPECT_...`:  Keywords from the Google Test framework, confirming this is a unit test file.
    * `JavaScript`, `HTML`, `CSS`:  Keep these in mind to connect the C++ code to the web platform.

3. **Identify Core Functionality (Based on Test Cases):**  Examine the individual test cases (`TEST_F`) to understand what aspects of `DeviceMotionEventPump` are being verified:
    * `AllSensorsAreActive`:  Tests the case where all three sensor types are available and provide data. Checks if the `DeviceMotionData` contains the correct values.
    * `TwoSensorsAreActive`: Checks the scenario where one sensor is unavailable. Verifies that the `DeviceMotionData` reflects the available data and omits the missing sensor's data.
    * `SomeSensorDataFieldsNotAvailable`: Tests the case where some individual data fields within a sensor reading are missing (NaN). Confirms that the `DeviceMotionData` handles these missing values correctly.
    * `FireAllNullEvent`:  Tests the scenario where no sensors are available. Verifies that a "null" or empty `DeviceMotionData` is generated.
    * `NotFireEventWhenSensorReadingTimeStampIsZero`: This is a crucial test. It checks that the pump doesn't fire an event until *all* active sensors have provided a non-zero timestamp. This hints at a synchronization mechanism.
    * `PumpThrottlesEventRate`: Tests that the event pump limits the rate at which events are dispatched. This is important for performance and security (preventing timing attacks).

4. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, consider how the functionality being tested relates to the web platform:
    * **JavaScript:** The core connection is the `devicemotion` event. JavaScript code uses `window.addEventListener('devicemotion', ...)` to receive these events. This C++ code is responsible for *generating* these events.
    * **HTML:** HTML elements don't directly interact with device motion, but the browser's rendering engine (Blink) uses HTML to structure the page where the JavaScript is running. The `LocalDOMWindow` and `LocalFrame` classes in the code point to this connection.
    * **CSS:** CSS doesn't directly relate to device motion data. However, JavaScript code receiving `devicemotion` events can *modify* CSS properties to create interactive effects (e.g., tilting an object on the screen).

5. **Logical Reasoning Examples (Input/Output):** For each test case, think about the "input" (simulated sensor data) and the expected "output" (the content of the `DeviceMotionData`). This is largely covered by analyzing the `EXPECT_EQ` and `EXPECT_TRUE`/`EXPECT_FALSE` assertions in the test cases.

6. **Common User/Programming Errors:** Consider how developers might misuse the `devicemotion` API:
    * **Assuming all sensors are always available:**  The "TwoSensorsAreActive" test highlights this. Developers need to check if the relevant data is present in the event.
    * **Not handling missing data (NaN):**  The "SomeSensorDataFieldsNotAvailable" test shows that individual axes might be unavailable.
    * **Expecting an immediate event:** The "NotFireEventWhenSensorReadingTimeStampIsZero" test reveals that there's a synchronization delay.
    * **Over-processing events:** The "PumpThrottlesEventRate" test is relevant here. Developers don't need to implement their own throttling.

7. **Debugging Hints (User Operations to Code):**  Trace how a user action leads to this C++ code:
    1. User opens a webpage that uses the `devicemotion` API.
    2. The JavaScript code requests access to device motion data (implicitly or explicitly by adding an event listener).
    3. The browser (Chromium) needs to request permission from the user (if not already granted).
    4. The browser's rendering engine (Blink) starts listening to the operating system's sensor APIs.
    5. The operating system provides sensor data to Blink.
    6. The `DeviceMotionEventPump` (this C++ code) receives and processes the raw sensor data.
    7. It packages the data into `DeviceMotionData` objects.
    8. It dispatches `devicemotion` events to the JavaScript code running on the webpage.

8. **Structure the Answer:** Organize the information clearly into the requested categories: Functionality, relationship to web technologies, logical reasoning, user errors, and debugging hints. Use clear and concise language. Provide code snippets from the test file as evidence.

9. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all aspects of the request have been addressed. For instance, explicitly mentioning the role of `FakeSensorProvider` in testing adds clarity.
好的，让我们来分析一下 `blink/renderer/modules/device_orientation/device_motion_event_pump_unittest.cc` 这个文件。

**文件功能：**

这个文件是 Chromium Blink 引擎中 `DeviceMotionEventPump` 类的单元测试文件。`DeviceMotionEventPump` 的主要职责是管理设备运动传感器的信息，并将这些信息转换成 `devicemotion` 事件，然后分发给 web 页面上的 JavaScript。

更具体地说，这个单元测试文件旨在测试以下 `DeviceMotionEventPump` 的功能：

1. **传感器数据的收集和处理:** 测试 `DeviceMotionEventPump` 能否正确地从底层传感器（例如加速计、陀螺仪）获取数据，并将其存储在 `DeviceMotionData` 对象中。
2. **事件的触发和分发:** 测试 `DeviceMotionEventPump` 能否在收到新的传感器数据后，正确地创建并触发 `devicemotion` 事件。
3. **传感器状态的管理:** 测试 `DeviceMotionEventPump` 能否正确地管理各个传感器的激活、暂停和未初始化状态。
4. **数据字段的可用性处理:** 测试当某些传感器数据字段不可用（例如 NaN）时，`DeviceMotionEventPump` 能否正确处理。
5. **事件节流:** 测试 `DeviceMotionEventPump` 是否实现了事件节流机制，防止事件触发频率过高。
6. **在没有可用传感器时的行为:** 测试当没有可用的加速度计或陀螺仪等传感器时，`DeviceMotionEventPump` 的行为。
7. **与 `PlatformEventController` 的集成:** 测试 `DeviceMotionEventPump` 如何与 `PlatformEventController` 协同工作，将事件传递给渲染流程。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件直接关系到 JavaScript 中 `devicemotion` 事件的实现。

* **JavaScript:**
    * **功能关系:**  JavaScript 代码可以使用 `window.addEventListener('devicemotion', function(event) { ... });` 来监听设备运动事件。这个 C++ 文件中的 `DeviceMotionEventPump` 负责收集传感器数据并创建 `devicemotion` 事件对象，最终这些事件会被传递到 JavaScript 中。
    * **举例说明:**
        ```javascript
        window.addEventListener('devicemotion', function(event) {
          const acceleration = event.acceleration;
          const accelerationIncludingGravity = event.accelerationIncludingGravity;
          const rotationRate = event.rotationRate;

          if (acceleration) {
            console.log('加速度 X:', acceleration.x);
            console.log('加速度 Y:', acceleration.y);
            console.log('加速度 Z:', acceleration.z);
          }

          if (accelerationIncludingGravity) {
            console.log('包含重力的加速度 X:', accelerationIncludingGravity.x);
          }

          if (rotationRate) {
            console.log('旋转速率 alpha:', rotationRate.alpha);
          }
        });
        ```
        当上述 JavaScript 代码运行时，`DeviceMotionEventPump` 会根据设备传感器的数据生成 `event` 对象，其中包含了 `acceleration`, `accelerationIncludingGravity`, `rotationRate` 等属性。

* **HTML:**
    * **功能关系:** HTML 提供了页面的结构，JavaScript 代码通常嵌入在 HTML 中或通过 `<script>` 标签引入。当用户访问包含监听 `devicemotion` 事件的 HTML 页面时，`DeviceMotionEventPump` 开始工作。
    * **举例说明:**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>Device Motion Example</title>
        </head>
        <body>
          <p>查看控制台输出设备运动数据。</p>
          <script>
            window.addEventListener('devicemotion', function(event) {
              // ... (上面的 JavaScript 代码)
            });
          </script>
        </body>
        </html>
        ```

* **CSS:**
    * **功能关系:** CSS 本身不直接参与设备运动事件的处理。但是，JavaScript 代码在接收到 `devicemotion` 事件后，可以根据传感器数据动态地修改 CSS 样式，从而实现一些交互效果。
    * **举例说明:**
        ```javascript
        window.addEventListener('devicemotion', function(event) {
          const x = event.accelerationIncludingGravity.x;
          const element = document.getElementById('myElement');
          // 根据 X 轴加速度调整元素的旋转
          element.style.transform = `rotate(${x * 10}deg)`;
        });
        ```
        在这个例子中，JavaScript 代码监听 `devicemotion` 事件，并根据 `accelerationIncludingGravity.x` 的值来旋转 ID 为 `myElement` 的 HTML 元素。

**逻辑推理的假设输入与输出：**

假设输入：

1. **用户在支持设备运动传感器的设备上打开一个网页。**
2. **网页上的 JavaScript 代码添加了 `devicemotion` 事件监听器。**
3. **设备上的加速计传感器报告了新的数据：x=1, y=2, z=3 (包含重力)。**
4. **设备上的线性加速度传感器报告了新的数据：x=0.1, y=0.2, z=0.3 (不包含重力)。**
5. **设备上的陀螺仪传感器报告了新的数据：alpha=0.01 rad, beta=0.02 rad, gamma=0.03 rad。**

逻辑推理和输出：

* **`DeviceMotionEventPump` 接收到这些传感器数据。**
* **`DeviceMotionEventPump` 创建一个 `DeviceMotionData` 对象，包含以下信息：**
    * `accelerationIncludingGravity`: { x: 1, y: 2, z: 3 }
    * `acceleration`: { x: 0.1, y: 0.2, z: 0.3 }
    * `rotationRate`: { alpha: 0.57 (0.01 * 180 / PI), beta: 1.15, gamma: 1.72 } (弧度转换为度)
* **`DeviceMotionEventPump` 创建一个 `devicemotion` 事件对象。**
* **事件对象被分发到网页的 JavaScript 环境。**
* **JavaScript 的事件监听器函数被调用，`event` 对象包含上述的传感器数据。**

**涉及用户或者编程常见的使用错误：**

1. **假设所有传感器都可用:** 开发者可能会直接访问 `event.acceleration` 和 `event.rotationRate`，而没有检查这些属性是否存在。如果设备缺少线性加速度传感器或陀螺仪，这些属性可能为 `null`。
   * **错误示例 (JavaScript):**
     ```javascript
     window.addEventListener('devicemotion', function(event) {
       console.log(event.acceleration.x); // 如果线性加速度传感器不可用，会报错
     });
     ```
   * **正确做法:** 检查属性是否存在。
     ```javascript
     window.addEventListener('devicemotion', function(event) {
       if (event.acceleration) {
         console.log(event.acceleration.x);
       }
     });
     ```

2. **未处理 `null` 值:** 即使传感器存在，某些轴的数据可能不可用，导致属性值为 `null`。
   * **错误示例 (JavaScript):**
     ```javascript
     window.addEventListener('devicemotion', function(event) {
       const x = event.accelerationIncludingGravity.x;
       console.log(x + 10); // 如果 x 为 null，会得到 "null10" 或 NaN
     });
     ```
   * **正确做法:** 检查值是否为 `null`。
     ```javascript
     window.addEventListener('devicemotion', function(event) {
       const x = event.accelerationIncludingGravity.x;
       if (x !== null) {
         console.log(x + 10);
       }
     });
     ```

3. **过度依赖事件触发频率:** 开发者可能会假设 `devicemotion` 事件会以非常高的频率触发，从而用于实现对时间精度要求很高的操作。然而，浏览器通常会对事件进行节流，以避免性能问题和安全风险。

4. **没有处理权限请求:** 在某些浏览器中，访问设备运动传感器可能需要用户授权。开发者需要确保他们的代码能够正确处理权限请求流程。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开网页:** 用户在 Chrome 浏览器中打开一个包含监听 `devicemotion` 事件的网页。
2. **JavaScript 代码执行:** 浏览器加载并执行网页上的 JavaScript 代码，包括 `addEventListener('devicemotion', ...)` 的调用。
3. **Blink 请求传感器访问:** 当 JavaScript 代码尝试注册 `devicemotion` 事件监听器时，Blink 渲染引擎会向底层操作系统或硬件层请求访问设备运动传感器。
4. **操作系统/硬件提供数据:** 设备上的传感器开始采集数据，并通过操作系统或驱动程序将数据传递给 Chrome 浏览器。
5. **`DeviceMotionEventPump` 接收数据:** `DeviceMotionEventPump` 类作为 Blink 引擎的一部分，负责接收来自底层传感器的原始数据。
6. **数据处理和事件创建:** `DeviceMotionEventPump` 将接收到的原始传感器数据进行处理，转换成更有意义的 `DeviceMotionData` 对象，并创建 `devicemotion` 事件对象。
7. **事件分发:** `DeviceMotionEventPump` 将创建的 `devicemotion` 事件分发到相应的 `LocalDOMWindow` 对象。
8. **JavaScript 事件处理函数执行:** 之前注册的 JavaScript `devicemotion` 事件处理函数被调用，接收到包含传感器数据的 `event` 对象。

**调试线索：**

* **检查 JavaScript 代码:** 确认 JavaScript 代码是否正确地添加了 `devicemotion` 事件监听器，并且事件处理函数内部的逻辑是否正确。
* **检查浏览器控制台:** 查看浏览器控制台是否有与设备运动相关的错误或警告信息。
* **检查设备传感器状态:** 确认设备的加速度计和陀螺仪等传感器是否正常工作。在某些设备上，可能需要手动启用这些传感器。
* **使用开发者工具模拟传感器数据:** Chrome 开发者工具提供了一个 "Sensors" 面板，可以用来模拟设备运动数据，方便调试。
* **查看 `chrome://device-log/`:**  这个 Chrome 内部页面可能会提供有关设备传感器状态和数据传输的更底层的日志信息。
* **断点调试 C++ 代码:** 如果需要深入了解 `DeviceMotionEventPump` 的工作原理，可以在 `blink/renderer/modules/device_orientation/device_motion_event_pump.cc` 和 `device_motion_event_pump_unittest.cc` 中设置断点，逐步跟踪代码执行流程。单元测试文件本身就提供了很好的代码示例和测试用例，可以帮助理解代码逻辑。

总而言之，`blink/renderer/modules/device_orientation/device_motion_event_pump_unittest.cc` 是一个非常重要的测试文件，它确保了 Blink 引擎能够正确地处理设备运动传感器数据，并将其可靠地传递给 JavaScript 环境，从而支持各种基于设备运动的 Web 应用。

### 提示词
```
这是目录为blink/renderer/modules/device_orientation/device_motion_event_pump_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/device_orientation/device_motion_event_pump.h"

#include <string.h>

#include <memory>

#include "base/numerics/angle_conversions.h"
#include "base/run_loop.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/device/public/cpp/test/fake_sensor_and_provider.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/cross_variant_mojo_util.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/platform_event_controller.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/modules/device_orientation/device_motion_data.h"
#include "third_party/blink/renderer/modules/device_orientation/device_motion_event_acceleration.h"
#include "third_party/blink/renderer/modules/device_orientation/device_motion_event_rotation_rate.h"
#include "third_party/blink/renderer/modules/device_orientation/device_sensor_entry.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

using device::FakeSensorProvider;

class MockDeviceMotionController final
    : public GarbageCollected<MockDeviceMotionController>,
      public PlatformEventController {
 public:
  explicit MockDeviceMotionController(DeviceMotionEventPump* motion_pump,
                                      LocalDOMWindow& window)
      : PlatformEventController(window),
        did_change_device_motion_(false),
        motion_pump_(motion_pump) {}

  MockDeviceMotionController(const MockDeviceMotionController&) = delete;
  MockDeviceMotionController& operator=(const MockDeviceMotionController&) =
      delete;

  ~MockDeviceMotionController() override {}

  void Trace(Visitor* visitor) const override {
    PlatformEventController::Trace(visitor);
    visitor->Trace(motion_pump_);
  }

  void DidUpdateData() override {
    did_change_device_motion_ = true;
    ++number_of_events_;
  }

  bool did_change_device_motion() const { return did_change_device_motion_; }

  int number_of_events() const { return number_of_events_; }

  void RegisterWithDispatcher() override { motion_pump_->SetController(this); }

  bool HasLastData() override { return motion_pump_->LatestDeviceMotionData(); }

  void UnregisterWithDispatcher() override { motion_pump_->RemoveController(); }

  const DeviceMotionData* data() {
    return motion_pump_->LatestDeviceMotionData();
  }

  DeviceMotionEventPump* motion_pump() { return motion_pump_.Get(); }

 private:
  bool did_change_device_motion_;
  int number_of_events_;
  Member<DeviceMotionEventPump> motion_pump_;
};

class DeviceMotionEventPumpTest : public testing::Test {
 public:
  DeviceMotionEventPumpTest() = default;

  DeviceMotionEventPumpTest(const DeviceMotionEventPumpTest&) = delete;
  DeviceMotionEventPumpTest& operator=(const DeviceMotionEventPumpTest&) =
      delete;

 protected:
  void SetUp() override {
    page_holder_ = std::make_unique<DummyPageHolder>();

    mojo::PendingRemote<device::mojom::SensorProvider> sensor_provider;
    sensor_provider_.Bind(sensor_provider.InitWithNewPipeAndPassReceiver());
    auto* motion_pump =
        MakeGarbageCollected<DeviceMotionEventPump>(page_holder_->GetFrame());
    motion_pump->SetSensorProviderForTesting(
        ToCrossVariantMojoType(std::move(sensor_provider)));

    controller_ = MakeGarbageCollected<MockDeviceMotionController>(
        motion_pump, *page_holder_->GetFrame().DomWindow());

    ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kNotInitialized);
    EXPECT_EQ(DeviceMotionEventPump::PumpState::kStopped,
              controller_->motion_pump()->GetPumpStateForTesting());
  }

  void FireEvent() { controller_->motion_pump()->FireEvent(nullptr); }

  void ExpectAccelerometerStateToBe(
      DeviceSensorEntry::State expected_sensor_state) {
    EXPECT_EQ(expected_sensor_state,
              controller_->motion_pump()->accelerometer_->state());
  }

  void ExpectLinearAccelerationSensorStateToBe(
      DeviceSensorEntry::State expected_sensor_state) {
    EXPECT_EQ(expected_sensor_state,
              controller_->motion_pump()->linear_acceleration_sensor_->state());
  }

  void ExpectGyroscopeStateToBe(
      DeviceSensorEntry::State expected_sensor_state) {
    EXPECT_EQ(expected_sensor_state,
              controller_->motion_pump()->gyroscope_->state());
  }

  void ExpectAllThreeSensorsStateToBe(
      DeviceSensorEntry::State expected_sensor_state) {
    ExpectAccelerometerStateToBe(expected_sensor_state);
    ExpectLinearAccelerationSensorStateToBe(expected_sensor_state);
    ExpectGyroscopeStateToBe(expected_sensor_state);
  }

  MockDeviceMotionController* controller() { return controller_.Get(); }

  FakeSensorProvider* sensor_provider() { return &sensor_provider_; }

 private:
  test::TaskEnvironment task_environment_;
  Persistent<MockDeviceMotionController> controller_;
  std::unique_ptr<DummyPageHolder> page_holder_;

  FakeSensorProvider sensor_provider_;
};

TEST_F(DeviceMotionEventPumpTest, AllSensorsAreActive) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kActive);

  sensor_provider()->UpdateAccelerometerData(1, 2, 3);
  sensor_provider()->UpdateLinearAccelerationSensorData(4, 5, 6);
  sensor_provider()->UpdateGyroscopeData(7, 8, 9);

  FireEvent();

  const DeviceMotionData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_motion());

  EXPECT_TRUE(
      received_data->GetAccelerationIncludingGravity()->HasAccelerationData());
  EXPECT_EQ(1, received_data->GetAccelerationIncludingGravity()->x().value());
  EXPECT_EQ(2, received_data->GetAccelerationIncludingGravity()->y().value());
  EXPECT_EQ(3, received_data->GetAccelerationIncludingGravity()->z().value());

  EXPECT_TRUE(received_data->GetAcceleration()->HasAccelerationData());
  EXPECT_EQ(4, received_data->GetAcceleration()->x().value());
  EXPECT_EQ(5, received_data->GetAcceleration()->y().value());
  EXPECT_EQ(6, received_data->GetAcceleration()->z().value());

  EXPECT_TRUE(received_data->GetRotationRate()->HasRotationData());
  EXPECT_EQ(base::RadToDeg(7.0),
            received_data->GetRotationRate()->alpha().value());
  EXPECT_EQ(base::RadToDeg(8.0),
            received_data->GetRotationRate()->beta().value());
  EXPECT_EQ(base::RadToDeg(9.0),
            received_data->GetRotationRate()->gamma().value());

  controller()->UnregisterWithDispatcher();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kSuspended);
}

TEST_F(DeviceMotionEventPumpTest, TwoSensorsAreActive) {
  sensor_provider()->set_linear_acceleration_sensor_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  ExpectAccelerometerStateToBe(DeviceSensorEntry::State::kActive);
  ExpectLinearAccelerationSensorStateToBe(
      DeviceSensorEntry::State::kNotInitialized);
  ExpectGyroscopeStateToBe(DeviceSensorEntry::State::kActive);

  sensor_provider()->UpdateAccelerometerData(1, 2, 3);
  sensor_provider()->UpdateGyroscopeData(7, 8, 9);

  FireEvent();

  const DeviceMotionData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_motion());

  EXPECT_TRUE(
      received_data->GetAccelerationIncludingGravity()->HasAccelerationData());
  EXPECT_EQ(1, received_data->GetAccelerationIncludingGravity()->x().value());
  EXPECT_EQ(2, received_data->GetAccelerationIncludingGravity()->y().value());
  EXPECT_EQ(3, received_data->GetAccelerationIncludingGravity()->z().value());

  EXPECT_FALSE(received_data->GetAcceleration()->x().has_value());
  EXPECT_FALSE(received_data->GetAcceleration()->y().has_value());
  EXPECT_FALSE(received_data->GetAcceleration()->z().has_value());

  EXPECT_TRUE(received_data->GetRotationRate()->HasRotationData());
  EXPECT_EQ(base::RadToDeg(7.0),
            received_data->GetRotationRate()->alpha().value());
  EXPECT_EQ(base::RadToDeg(8.0),
            received_data->GetRotationRate()->beta().value());
  EXPECT_EQ(base::RadToDeg(9.0),
            received_data->GetRotationRate()->gamma().value());

  controller()->UnregisterWithDispatcher();

  ExpectAccelerometerStateToBe(DeviceSensorEntry::State::kSuspended);
  ExpectLinearAccelerationSensorStateToBe(
      DeviceSensorEntry::State::kNotInitialized);
  ExpectGyroscopeStateToBe(DeviceSensorEntry::State::kSuspended);
}

TEST_F(DeviceMotionEventPumpTest, SomeSensorDataFieldsNotAvailable) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kActive);

  sensor_provider()->UpdateAccelerometerData(NAN, 2, 3);
  sensor_provider()->UpdateLinearAccelerationSensorData(4, NAN, 6);
  sensor_provider()->UpdateGyroscopeData(7, 8, NAN);

  FireEvent();

  const DeviceMotionData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_motion());

  EXPECT_FALSE(
      received_data->GetAccelerationIncludingGravity()->x().has_value());
  EXPECT_EQ(2, received_data->GetAccelerationIncludingGravity()->y().value());
  EXPECT_EQ(3, received_data->GetAccelerationIncludingGravity()->z().value());

  EXPECT_EQ(4, received_data->GetAcceleration()->x().value());
  EXPECT_FALSE(received_data->GetAcceleration()->y().has_value());
  EXPECT_EQ(6, received_data->GetAcceleration()->z().value());

  EXPECT_TRUE(received_data->GetAcceleration()->HasAccelerationData());
  EXPECT_EQ(base::RadToDeg(7.0),
            received_data->GetRotationRate()->alpha().value());
  EXPECT_EQ(base::RadToDeg(8.0),
            received_data->GetRotationRate()->beta().value());
  EXPECT_FALSE(received_data->GetRotationRate()->gamma().has_value());

  controller()->UnregisterWithDispatcher();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kSuspended);
}

TEST_F(DeviceMotionEventPumpTest, FireAllNullEvent) {
  // No active sensors.
  sensor_provider()->set_accelerometer_is_available(false);
  sensor_provider()->set_linear_acceleration_sensor_is_available(false);
  sensor_provider()->set_gyroscope_is_available(false);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kNotInitialized);

  FireEvent();

  const DeviceMotionData* received_data = controller()->data();
  EXPECT_TRUE(controller()->did_change_device_motion());

  EXPECT_FALSE(received_data->GetAcceleration()->HasAccelerationData());

  EXPECT_FALSE(
      received_data->GetAccelerationIncludingGravity()->HasAccelerationData());

  EXPECT_FALSE(received_data->GetRotationRate()->HasRotationData());

  controller()->UnregisterWithDispatcher();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kNotInitialized);
}

TEST_F(DeviceMotionEventPumpTest,
       NotFireEventWhenSensorReadingTimeStampIsZero) {
  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kActive);

  FireEvent();
  EXPECT_FALSE(controller()->did_change_device_motion());

  sensor_provider()->UpdateAccelerometerData(1, 2, 3);
  FireEvent();
  EXPECT_FALSE(controller()->did_change_device_motion());

  sensor_provider()->UpdateLinearAccelerationSensorData(4, 5, 6);
  FireEvent();
  EXPECT_FALSE(controller()->did_change_device_motion());

  sensor_provider()->UpdateGyroscopeData(7, 8, 9);
  FireEvent();
  // Event is fired only after all the available sensors have data.
  EXPECT_TRUE(controller()->did_change_device_motion());

  controller()->UnregisterWithDispatcher();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kSuspended);
}

// Confirm that the frequency of pumping events is not greater than 60Hz.
// A rate above 60Hz would allow for the detection of keystrokes.
// (crbug.com/421691)
TEST_F(DeviceMotionEventPumpTest, PumpThrottlesEventRate) {
  // Confirm that the delay for pumping events is 60 Hz.
  EXPECT_GE(60, base::Time::kMicrosecondsPerSecond /
                    DeviceMotionEventPump::kDefaultPumpDelayMicroseconds);

  controller()->RegisterWithDispatcher();
  base::RunLoop().RunUntilIdle();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kActive);

  sensor_provider()->UpdateAccelerometerData(1, 2, 3);
  sensor_provider()->UpdateLinearAccelerationSensorData(4, 5, 6);
  sensor_provider()->UpdateGyroscopeData(7, 8, 9);

  base::RunLoop loop;
  blink::scheduler::GetSingleThreadTaskRunnerForTesting()->PostDelayedTask(
      FROM_HERE, loop.QuitWhenIdleClosure(), base::Milliseconds(100));
  loop.Run();
  controller()->UnregisterWithDispatcher();

  ExpectAllThreeSensorsStateToBe(DeviceSensorEntry::State::kSuspended);

  // Check that the PlatformEventController does not receive excess
  // events.
  EXPECT_TRUE(controller()->did_change_device_motion());
  EXPECT_GE(6, controller()->number_of_events());
}

}  // namespace blink
```