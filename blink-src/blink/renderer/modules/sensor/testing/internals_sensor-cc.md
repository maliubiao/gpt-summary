Response:
Let's break down the thought process for analyzing this code.

1. **Identify the Core Purpose:** The file name `internals_sensor.cc` and the namespace `blink::sensor::testing` immediately suggest this is about internal testing of sensor functionality within the Blink rendering engine. The `InternalsSensor` class reinforces this.

2. **Look for Key Interactions:**  The `#include` directives are crucial. They reveal dependencies:
    * `mojo/...`: Indicates interaction with the Mojo IPC system, likely for communication between different processes or components.
    * `services/device/...`:  Suggests interaction with the underlying device sensor framework.
    * `third_party/blink/public/mojom/sensor/...`:  More Mojo definitions, specifically related to sensors in Blink's public API.
    * `third_party/blink/public/platform/browser_interface_broker_proxy.h`:  Shows a mechanism to communicate with the browser process.
    * `third_party/blink/renderer/bindings/...`: Implies JavaScript integration, as these headers relate to V8 (the JavaScript engine) and its bindings to Blink's C++ code.
    * `third_party/blink/renderer/core/frame/local_dom_window.h`:  Connects the functionality to the DOM and browser windows.

3. **Analyze the Class Structure:** The `InternalsSensor` class has static methods. This suggests a utility-like role, providing functions that can be called directly without instantiating an object.

4. **Examine Each Method:**  Go through each public static method (`createVirtualSensor`, `updateVirtualSensor`, `removeVirtualSensor`, `getVirtualSensorInformation`) and try to understand its purpose:
    * **`createVirtualSensor`**: Takes a sensor type and options, and creates a *virtual* sensor. The "virtual" aspect is important – it's not a real hardware sensor. The use of `WebSensorProviderAutomation` suggests a way to simulate sensor behavior.
    * **`updateVirtualSensor`**: Takes a sensor type and a reading, and updates the state of the virtual sensor. This confirms the simulation aspect.
    * **`removeVirtualSensor`**:  Destroys a virtual sensor.
    * **`getVirtualSensorInformation`**: Retrieves information about a virtual sensor, such as its sampling frequency.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** The presence of `ScriptPromise`, `ScriptState`, and the conversion functions to Mojo types strongly indicate a JavaScript interface. The "Internals" prefix often denotes features accessible through Chromium's `chrome://inspect/#internals` page or similar developer tools. This suggests a way to *programmatically control* sensor behavior from JavaScript for testing purposes.

6. **Trace Data Flow:** For each method, follow the data flow:
    * JavaScript calls the `InternalsSensor` method.
    * The method converts the JavaScript parameters into Mojo types.
    * It uses `BrowserInterfaceBroker` to get a `WebSensorProviderAutomation` interface.
    * It calls a method on the `WebSensorProviderAutomation` (via Mojo).
    * The Mojo call likely interacts with the actual sensor implementation or a test double.
    * The result is passed back, potentially resolving or rejecting a JavaScript Promise.

7. **Infer Assumptions and Logic:**  The code assumes the existence of a `WebSensorProviderAutomation` service. The conversion functions (`ToMojoSensorType`, `ToMojoSensorMetadata`, `ToMojoRawReading`) encapsulate the logic of translating between JavaScript representations and the underlying system's data formats. The error handling within the promise callbacks is also important logic.

8. **Consider User Errors and Debugging:** Think about how a developer might misuse these internal testing tools. For example, trying to update a sensor that hasn't been created, or providing invalid sensor data. The promise rejection paths handle some of these scenarios. The debugging aspect comes from understanding *how* one would reach this code – likely through JavaScript calls triggered by developer tools or automated tests.

9. **Construct Examples:** Concrete examples make the explanation clearer. Illustrate how JavaScript code could invoke these methods, and what the corresponding effects would be.

10. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation. Ensure the connection to web technologies and the debugging context is clear. For instance, initially, I might have focused too much on the Mojo details. Refining involves emphasizing the JavaScript interaction and the "testing" aspect more strongly.

By following these steps, we can systematically analyze the code and produce a comprehensive explanation of its functionality, its relationship to web technologies, and its role in the broader system.
这个文件 `blink/renderer/modules/sensor/testing/internals_sensor.cc` 是 Chromium Blink 引擎中用于**内部测试**传感器功能的代码。它提供了一组 JavaScript 可以调用的接口，用于模拟和控制虚拟传感器，以便在没有实际硬件传感器的情况下测试基于传感器的 Web API。

**以下是它的主要功能：**

1. **创建虚拟传感器 (createVirtualSensor):**
   - 允许 JavaScript 代码创建一个指定类型的虚拟传感器。
   - 可以设置虚拟传感器的元数据，例如是否连接、最小和最大采样频率。
   - 这使得开发者可以在测试环境中模拟各种传感器的存在和特性。

2. **更新虚拟传感器数据 (updateVirtualSensor):**
   - 允许 JavaScript 代码向已创建的虚拟传感器注入模拟的传感器读数。
   - 可以模拟各种传感器的数据变化，例如加速度计的 X、Y、Z 轴数值，或方向传感器的 Alpha、Beta、Gamma 值。
   - 这对于测试 Web 应用如何响应不同的传感器数据至关重要。

3. **移除虚拟传感器 (removeVirtualSensor):**
   - 允许 JavaScript 代码移除之前创建的虚拟传感器。
   - 用于清理测试环境。

4. **获取虚拟传感器信息 (getVirtualSensorInformation):**
   - 允许 JavaScript 代码获取关于已创建的虚拟传感器的信息，例如请求的采样频率。
   - 这有助于验证虚拟传感器的配置是否正确。

**与 JavaScript, HTML, CSS 的关系：**

这个文件本身是 C++ 代码，属于 Blink 渲染引擎的底层实现。然而，它通过 Chromium 的 "Internals" 功能暴露了一些 JavaScript 接口，使得开发者可以通过 JavaScript 代码来调用这些 C++ 功能。

**举例说明：**

假设我们在一个网页中使用了 `Accelerometer` API 来监听设备的加速度：

```javascript
const accelerometer = new Accelerometer();
accelerometer.start();

accelerometer.onreading = () => {
  console.log(`Acceleration X: ${accelerometer.x}`);
  console.log(`Acceleration Y: ${accelerometer.y}`);
  console.log(`Acceleration Z: ${accelerometer.z}`);
};

accelerometer.onerror = (event) => {
  console.error("Accelerometer failed:", event.error.name);
};
```

为了测试这段代码在各种加速度情况下的行为，我们可以使用 `internals_sensor.cc` 提供的功能。

1. **创建虚拟加速度计：**

   ```javascript
   // 假设可以通过某种内部 JavaScript API 访问到 InternalsSensor 的功能
   internals.sensor.createVirtualSensor('accelerometer', { connected: true });
   ```
   这将创建一个模拟的加速度计。

2. **更新虚拟加速度计的数据：**

   ```javascript
   internals.sensor.updateVirtualSensor('accelerometer', { x: 1, y: 0, z: 0 });
   ```
   这将模拟设备沿 X 轴有一个单位的加速度。此时，网页中的 `accelerometer.onreading` 回调函数会被触发，并且控制台会输出 `Acceleration X: 1`, `Acceleration Y: 0`, `Acceleration Z: 0`。

3. **模拟传感器断开：**

   ```javascript
   internals.sensor.createVirtualSensor('accelerometer', { connected: false });
   ```
   重新创建连接状态为 `false` 的虚拟传感器，可能会触发网页中 `accelerometer.onerror` 的回调，具体行为取决于 `Accelerometer` API 的实现细节。

4. **移除虚拟加速度计：**

   ```javascript
   internals.sensor.removeVirtualSensor('accelerometer');
   ```
   这将移除虚拟加速度计，后续的传感器 API 调用可能会失败。

**注意：**  `internals` 对象通常不是标准 Web API，而是 Chromium 浏览器内部用于测试和调试的接口，可能需要在特定的 Chromium 构建版本或通过特定的标志启用才能使用。

**逻辑推理与假设输入输出：**

**假设输入 (JavaScript 调用):**

```javascript
internals.sensor.createVirtualSensor('gyroscope', { minSamplingFrequency: 10, maxSamplingFrequency: 60 });
```

**逻辑推理：**

- `InternalsSensor::createVirtualSensor` 方法会被调用。
- `ToMojoSensorType` 函数会将字符串 'gyroscope' 转换为 `device::mojom::blink::SensorType::GYROSCOPE`。
- `ToMojoSensorMetadata` 函数会将 JavaScript 对象 `{ minSamplingFrequency: 10, maxSamplingFrequency: 60 }` 转换为 `device::mojom::blink::VirtualSensorMetadataPtr`，其中 `minimum_frequency` 为 10，`maximum_frequency` 为 60。
- 通过 Mojo 接口 `WebSensorProviderAutomation` 向浏览器进程发送创建虚拟陀螺仪的请求，并附带转换后的传感器类型和元数据。
- 如果创建成功，Promise 会 resolve。

**假设输出 (C++ 函数的执行结果):**

- `device::mojom::blink::CreateVirtualSensorResult::kSuccess` (如果成功)
- 浏览器进程中会创建一个模拟的陀螺仪传感器，其属性符合提供的元数据。

**用户或编程常见的使用错误：**

1. **尝试更新未创建的虚拟传感器：**
   - **用户操作：** 直接调用 `internals.sensor.updateVirtualSensor` 而没有先调用 `createVirtualSensor`。
   - **C++ 代码逻辑：** `InternalsSensor::updateVirtualSensor` 中，如果 `UpdateVirtualSensor` 的 Mojo 调用返回 `kSensorTypeNotOverridden`，Promise 会被 reject，JavaScript 代码会收到一个错误，提示 "A virtual sensor with this type has not been created"。

2. **提供无效的传感器读数：**
   - **用户操作：** 调用 `internals.sensor.updateVirtualSensor('accelerometer', { alpha: 10, beta: 20 });`  为加速度计提供了角度值，而不是加速度值。
   - **C++ 代码逻辑：** `ToMojoRawReading` 函数会根据传感器类型检查读数的格式。对于加速度计，它期望 `x`, `y`, `z` 属性。如果缺少或类型不匹配，会返回一个 `base::unexpected`，导致 `updateVirtualSensor` 返回一个 rejected Promise，并抛出一个 `DOMException`。

3. **重复创建相同类型的虚拟传感器：**
   - **用户操作：**  连续调用两次 `internals.sensor.createVirtualSensor('accelerometer', ...)`。
   - **C++ 代码逻辑：** `InternalsSensor::createVirtualSensor` 中，如果 Mojo 调用返回 `kSensorTypeAlreadyOverridden`，Promise 会被 reject，JavaScript 代码会收到一个错误，提示 "This sensor type has already been created"。

**用户操作如何一步步到达这里，作为调试线索：**

1. **开发者想要测试网页中使用的传感器 API，但不想依赖真实的硬件传感器。**
2. **开发者知道 Chromium 提供了内部测试工具。**
3. **开发者可能查阅了 Chromium 的文档或源代码，找到了 `internals.sensor` 相关的 API。**
4. **开发者在 Chromium 浏览器的开发者工具的控制台中，或者在自动化测试脚本中，使用了 `internals.sensor.createVirtualSensor` 来创建一个虚拟传感器。**
5. **为了模拟传感器数据的变化，开发者随后调用了 `internals.sensor.updateVirtualSensor` 并传入模拟的传感器读数。**
6. **如果网页代码对传感器数据的处理有误，或者虚拟传感器的配置不正确，开发者可能会观察到意外的行为或错误。**
7. **为了定位问题，开发者可能会在 JavaScript 代码中设置断点，或者在 Blink 渲染引擎的 C++ 代码中设置断点（如果可以访问 Chromium 的源代码和构建环境）。**
8. **当执行到 `blink/renderer/modules/sensor/testing/internals_sensor.cc` 中的代码时，开发者可以检查虚拟传感器的创建、更新和移除逻辑是否按预期工作，以及 JavaScript 传入的参数是否正确。**
9. **例如，开发者可能会检查 `ToMojoSensorType` 和 `ToMojoSensorMetadata` 的转换结果，或者查看 `WebSensorProviderAutomation` 的 Mojo 调用是否成功。**

总而言之，`internals_sensor.cc` 是一个用于 Blink 内部测试的重要文件，它允许开发者在没有物理传感器的情况下模拟和控制传感器行为，从而更方便地测试基于传感器的 Web 应用。它通过 Chromium 的内部 JavaScript 接口暴露功能，使得开发者可以通过 JavaScript 代码来驱动这些测试。

Prompt: 
```
这是目录为blink/renderer/modules/sensor/testing/internals_sensor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/sensor/testing/internals_sensor.h"

#include <utility>

#include "base/types/expected.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/device/public/cpp/generic_sensor/orientation_util.h"
#include "services/device/public/mojom/sensor.mojom-blink.h"
#include "services/device/public/mojom/sensor_provider.mojom-blink.h"
#include "third_party/blink/public/mojom/sensor/web_sensor_provider_automation.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_create_virtual_sensor_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_virtual_sensor_information.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_virtual_sensor_reading.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_virtual_sensor_type.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

device::mojom::blink::SensorType ToMojoSensorType(
    V8VirtualSensorType::Enum type) {
  switch (type) {
    case V8VirtualSensorType::Enum::kAbsoluteOrientation:
      return device::mojom::blink::SensorType::ABSOLUTE_ORIENTATION_QUATERNION;
    case V8VirtualSensorType::Enum::kAccelerometer:
      return device::mojom::blink::SensorType::ACCELEROMETER;
    case V8VirtualSensorType::Enum::kAmbientLight:
      return device::mojom::blink::SensorType::AMBIENT_LIGHT;
    case V8VirtualSensorType::Enum::kGravity:
      return device::mojom::blink::SensorType::GRAVITY;
    case V8VirtualSensorType::Enum::kGyroscope:
      return device::mojom::blink::SensorType::GYROSCOPE;
    case V8VirtualSensorType::Enum::kLinearAcceleration:
      return device::mojom::blink::SensorType::LINEAR_ACCELERATION;
    case V8VirtualSensorType::Enum::kMagnetometer:
      return device::mojom::blink::SensorType::MAGNETOMETER;
    case V8VirtualSensorType::Enum::kRelativeOrientation:
      return device::mojom::blink::SensorType::RELATIVE_ORIENTATION_QUATERNION;
  }
}

device::mojom::blink::VirtualSensorMetadataPtr ToMojoSensorMetadata(
    CreateVirtualSensorOptions* options) {
  if (!options) {
    return device::mojom::blink::VirtualSensorMetadata::New();
  }

  auto metadata = device::mojom::blink::VirtualSensorMetadata::New();
  metadata->available = options->connected();
  if (options->hasMinSamplingFrequency()) {
    metadata->minimum_frequency = options->minSamplingFrequency().value();
  }
  if (options->hasMaxSamplingFrequency()) {
    metadata->maximum_frequency = options->maxSamplingFrequency().value();
  }
  return metadata;
}

base::expected<device::mojom::blink::SensorReadingRawPtr, String>
ToMojoRawReading(V8VirtualSensorType::Enum type,
                 VirtualSensorReading* reading) {
  if (!reading) {
    return device::mojom::blink::SensorReadingRaw::New();
  }

  // TODO(crbug.com/1492436): with the right Blink Mojo traits, we could use
  // device::SensorReading instead of device::mojom::blink::SensorReadingRaw.
  auto raw_reading = device::mojom::blink::SensorReadingRaw::New();
  raw_reading->timestamp =
      (base::TimeTicks::Now() - base::TimeTicks()).InSecondsF();
  raw_reading->values.Fill(0.0, 4);
  switch (type) {
    case V8VirtualSensorType::Enum::kAbsoluteOrientation:
    case V8VirtualSensorType::Enum::kRelativeOrientation: {
      if (reading->hasAlpha() && reading->hasBeta() && reading->hasGamma()) {
        const double alpha = reading->getAlphaOr(0);
        const double beta = reading->getBetaOr(0);
        const double gamma = reading->getGammaOr(0);
        device::SensorReading quaternion_readings;
        if (!device::ComputeQuaternionFromEulerAngles(alpha, beta, gamma,
                                                      &quaternion_readings)) {
          return base::unexpected("Invalid value for alpha, beta or gamma");
        }
        Vector<double> quaternion{
            quaternion_readings.orientation_quat.x,
            quaternion_readings.orientation_quat.y,
            quaternion_readings.orientation_quat.z,
            quaternion_readings.orientation_quat.w,
        };
        raw_reading->values.swap(quaternion);
      } else {
        return base::unexpected(
            "'alpha'/'beta'/'gamma' expected in the readings");
      }
      break;
    }
    case V8VirtualSensorType::Enum::kAmbientLight:
      if (!reading->hasIlluminance()) {
        return base::unexpected("Invalid illuminance reading format");
      }
      raw_reading->values[0] = reading->getIlluminanceOr(0);
      break;
    case V8VirtualSensorType::Enum::kAccelerometer:
    case V8VirtualSensorType::Enum::kGravity:
    case V8VirtualSensorType::Enum::kGyroscope:
    case V8VirtualSensorType::Enum::kLinearAcceleration:
    case V8VirtualSensorType::Enum::kMagnetometer:
      if (!reading->hasX() || !reading->hasY() || !reading->hasZ()) {
        return base::unexpected("Invalid xyz reading format");
      }
      raw_reading->values[0] = reading->getXOr(0);
      raw_reading->values[1] = reading->getYOr(0);
      raw_reading->values[2] = reading->getZOr(0);
      break;
  }
  return raw_reading;
}

}  // namespace

// static
ScriptPromise<IDLUndefined> InternalsSensor::createVirtualSensor(
    ScriptState* script_state,
    Internals&,
    V8VirtualSensorType type,
    CreateVirtualSensorOptions* options) {
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  CHECK(window);
  mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>
      virtual_sensor_provider;
  window->GetBrowserInterfaceBroker().GetInterface(
      virtual_sensor_provider.BindNewPipeAndPassReceiver());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  auto* raw_virtual_sensor_provider = virtual_sensor_provider.get();
  raw_virtual_sensor_provider->CreateVirtualSensor(
      ToMojoSensorType(type.AsEnum()), ToMojoSensorMetadata(options),
      WTF::BindOnce(
          // While we only really need |resolver|, we also take the
          // mojo::Remote<> so that it remains alive after this function exits.
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>,
             device::mojom::blink::CreateVirtualSensorResult result) {
            switch (result) {
              case device::mojom::blink::CreateVirtualSensorResult::kSuccess:
                resolver->Resolve();
                break;
              case device::mojom::blink::CreateVirtualSensorResult::
                  kSensorTypeAlreadyOverridden:
                resolver->Reject("This sensor type has already been created");
                break;
            }
          },
          WrapPersistent(resolver), std::move(virtual_sensor_provider)));
  return promise;
}

// static
ScriptPromise<IDLUndefined> InternalsSensor::updateVirtualSensor(
    ScriptState* script_state,
    Internals&,
    V8VirtualSensorType type,
    VirtualSensorReading* reading) {
  auto mojo_reading = ToMojoRawReading(type.AsEnum(), reading);
  if (!mojo_reading.has_value()) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state,
        V8ThrowDOMException::CreateOrEmpty(script_state->GetIsolate(),
                                           DOMExceptionCode::kInvalidStateError,
                                           mojo_reading.error()));
  }

  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  CHECK(window);
  mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>
      virtual_sensor_provider;
  window->GetBrowserInterfaceBroker().GetInterface(
      virtual_sensor_provider.BindNewPipeAndPassReceiver());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  auto* raw_virtual_sensor_provider = virtual_sensor_provider.get();
  raw_virtual_sensor_provider->UpdateVirtualSensor(
      ToMojoSensorType(type.AsEnum()), std::move(mojo_reading.value()),
      WTF::BindOnce(
          // While we only really need |resolver|, we also take the
          // mojo::Remote<> so that it remains alive after this function exits.
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>,
             device::mojom::blink::UpdateVirtualSensorResult result) {
            switch (result) {
              case device::mojom::blink::UpdateVirtualSensorResult::kSuccess: {
                resolver->Resolve();
                break;
              }
              case device::mojom::blink::UpdateVirtualSensorResult::
                  kSensorTypeNotOverridden:
                resolver->Reject(
                    "A virtual sensor with this type has not been created");
                break;
            }
          },
          WrapPersistent(resolver), std::move(virtual_sensor_provider)));
  return promise;
}

// static
ScriptPromise<IDLUndefined> InternalsSensor::removeVirtualSensor(
    ScriptState* script_state,
    Internals&,
    V8VirtualSensorType type) {
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  CHECK(window);
  mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>
      virtual_sensor_provider;
  window->GetBrowserInterfaceBroker().GetInterface(
      virtual_sensor_provider.BindNewPipeAndPassReceiver());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  auto* raw_virtual_sensor_provider = virtual_sensor_provider.get();
  raw_virtual_sensor_provider->RemoveVirtualSensor(
      ToMojoSensorType(type.AsEnum()),
      WTF::BindOnce(
          // While we only really need |resolver|, we also take the
          // mojo::Remote<> so that it remains alive after this function exits.
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>) {
            resolver->Resolve();
          },
          WrapPersistent(resolver), std::move(virtual_sensor_provider)));
  return promise;
}

// static
ScriptPromise<VirtualSensorInformation>
InternalsSensor::getVirtualSensorInformation(ScriptState* script_state,
                                             Internals&,
                                             V8VirtualSensorType type) {
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  CHECK(window);
  mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>
      virtual_sensor_provider;
  window->GetBrowserInterfaceBroker().GetInterface(
      virtual_sensor_provider.BindNewPipeAndPassReceiver());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<VirtualSensorInformation>>(
          script_state);
  auto promise = resolver->Promise();
  auto* raw_virtual_sensor_provider = virtual_sensor_provider.get();
  raw_virtual_sensor_provider->GetVirtualSensorInformation(
      ToMojoSensorType(type.AsEnum()),
      WTF::BindOnce(
          // While we only really need |resolver|, we also take the
          // mojo::Remote<> so that it remains alive after this function exits.
          [](ScriptPromiseResolver<VirtualSensorInformation>* resolver,
             mojo::Remote<test::mojom::blink::WebSensorProviderAutomation>,
             device::mojom::blink::GetVirtualSensorInformationResultPtr
                 result) {
            if (result->is_error()) {
              switch (result->get_error()) {
                case device::mojom::blink::GetVirtualSensorInformationError::
                    kSensorTypeNotOverridden:
                  resolver->Reject(
                      "A virtual sensor with this type has not been created");
                  return;
              }
            }
            CHECK(result->is_info());
            auto* sensor_info = VirtualSensorInformation::Create();
            sensor_info->setRequestedSamplingFrequency(
                result->get_info()->sampling_frequency);
            resolver->Resolve(sensor_info);
          },
          WrapPersistent(resolver), std::move(virtual_sensor_provider)));
  return promise;
}

}  // namespace blink

"""

```