Response:
Let's break down the thought process for analyzing the `sensor.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies, examples of usage and errors, and how a user might trigger this code.

2. **Initial Skim for Core Functionality:**  The filename `sensor.cc` and the `#include` directives like `<utility>`,  `services/device/public/mojom/sensor.mojom-blink.h`, and  `third_party/blink/renderer/modules/sensor/sensor.h` immediately suggest this file implements the core logic for accessing device sensors within the Blink rendering engine. The namespace `blink` confirms this context.

3. **Identify the Central Class:** The presence of a class named `Sensor` is a strong indicator of the file's primary purpose. The constructors and methods within this class are likely to define the sensor's behavior.

4. **Analyze Key Methods:** Focus on the public methods of the `Sensor` class:
    * **Constructors (`Sensor::Sensor`)**:  These are crucial for understanding how a `Sensor` object is created and initialized. Note the parameters: `ExecutionContext`, `SensorOptions`, `ExceptionState`, `SensorType`, and PermissionsPolicy. This points to the integration with the web page context, configuration options, error handling, sensor types, and security policies.
    * **`start()` and `stop()`**:  These are fundamental for controlling the sensor's operation. They indicate a state machine within the `Sensor` class.
    * **Getters (`activated()`, `hasReading()`, `timestamp()`)**: These methods provide information about the sensor's current state and data. The `timestamp()` method's logic involving `DOMWindowPerformance` links it to web performance measurements.
    * **Event Handlers (`OnSensorInitialized()`, `OnSensorReadingChanged()`, `OnSensorError()`, `OnAddConfigurationRequestCompleted()`)**: These suggest an asynchronous interaction with the underlying sensor hardware or service. The names clearly indicate their purpose.
    * **`Activate()` and `Deactivate()`**: These internal methods detail the steps involved in starting and stopping the sensor, including interaction with `SensorProviderProxy`.
    * **`HandleError()` and `Notify...()` methods**:  These handle error conditions and dispatch events to JavaScript, establishing the connection to the web page.

5. **Examine Data Members:** Look at the private members of the `Sensor` class:
    * `frequency_`, `type_`, `state_`, `last_reported_timestamp_`, `sensor_proxy_`, `configuration_`, `use_screen_coords_`, and the `pending_*_notification_` members. These provide insight into the sensor's configuration, internal state management, and communication with the sensor service. The `pending_*_notification_` members suggest asynchronous operations and the need for cancellation.

6. **Trace Interactions with Other Classes:** Identify how `Sensor` interacts with other Blink components:
    * **`ExecutionContext`**: Used for security checks, task scheduling, and console logging.
    * **`SensorOptions` and `SpatialSensorOptions`**: Provide configuration parameters.
    * **`SensorProviderProxy`**:  A crucial intermediary for accessing the underlying sensor implementation.
    * **`DOMWindowPerformance`**: Used for converting sensor timestamps to web-compatible timestamps.
    * **`ConsoleMessage`**: Used for reporting information and warnings.
    * **`SensorErrorEvent`**: Represents errors that occur during sensor operation.
    * **`PermissionsPolicyFeature`**:  Used for enforcing security policies.
    * **`mojom::blink::Sensor`**:  Likely an interface definition for the sensor service.

7. **Map Functionality to Web Concepts:** Connect the identified functionality to JavaScript, HTML, and CSS:
    * **JavaScript:**  The `start()`, `stop()`, event listeners (`onreading`, `onactivate`, `onerror`), and the access to sensor data (`timestamp()`, and data available in derived classes not shown here) are the primary JavaScript interfaces.
    * **HTML:**  No direct HTML relationship is apparent in this file, but the sensor API is accessed from JavaScript within the context of a web page. The Permissions Policy, however, *can* be influenced by HTTP headers or meta tags in HTML.
    * **CSS:** No direct CSS relationship is present.

8. **Construct Examples:** Create concrete examples to illustrate the functionality:
    * **JavaScript Interaction:**  Show how to create a sensor, start/stop it, and handle events.
    * **Error Handling:**  Demonstrate scenarios that lead to errors (permissions, invalid frequency).
    * **Permissions Policy:** Explain how the Permissions Policy restricts access.

9. **Consider User Errors:** Think about common mistakes developers might make:
    * Not checking for secure context.
    * Incorrectly handling permissions.
    * Setting invalid frequencies.
    * Not handling errors.
    * Misunderstanding the asynchronous nature of sensor events.

10. **Debug Scenarios:**  Outline how a user's actions can lead to this code being executed, focusing on the steps to trigger sensor access and the potential error paths.

11. **Refine and Organize:** Review the generated information, ensuring clarity, accuracy, and a logical flow. Group related concepts together (e.g., JavaScript interaction, error scenarios). Use clear headings and bullet points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing solely on the `Sensor` class might miss the broader picture. Realization: Need to analyze the `#include` directives and how `Sensor` interacts with other components (like `SensorProviderProxy`).
* **Confusion about timestamps:**  The `timestamp()` method's use of `DOMWindowPerformance` might be initially unclear. Realization: This is necessary to convert device-specific timestamps to web-standard high-resolution timestamps.
* **Overlooking Permissions Policy:** Initially, I might not have emphasized the Permissions Policy enough. Realization: The constructor checks this, and it's a crucial security mechanism. Needs to be included in examples and error scenarios.
* **Simplifying Debugging:**  The initial debugging explanation might be too technical. Realization: Focus on the user's perspective – what actions in the browser lead to sensor access?

By following this iterative process of skimming, analyzing key elements, tracing interactions, connecting to web concepts, and constructing examples, a comprehensive understanding of the `sensor.cc` file can be achieved.这个文件是 Chromium Blink 渲染引擎中 `blink/renderer/modules/sensor/sensor.cc`，它实现了 Web 感应器 API 的基础抽象类 `Sensor`。这个类是所有具体传感器类型（如加速度计、陀螺仪、磁力计等）的基类。

以下是 `sensor.cc` 的主要功能：

**1. 传感器基础抽象:**
    *   定义了所有传感器的通用行为和状态，例如启动、停止、激活、读取数据和处理错误。
    *   管理传感器的状态机 (`SensorState`): `kIdle`, `kActivating`, `kActivated`。
    *   处理传感器的通用配置，例如采样频率。

**2. 与底层传感器服务的交互:**
    *   使用 `SensorProviderProxy` 与设备底层的传感器服务进行通信。
    *   负责请求初始化传感器、添加和移除传感器配置。
    *   处理来自底层传感器服务的事件，例如数据更新和错误。

**3. 事件派发:**
    *   当传感器状态改变或有新的读数时，会派发相应的事件到 JavaScript 层 (`reading`, `activate`, `error`)。

**4. 权限策略 (Permissions Policy) 检查:**
    *   在传感器创建时，会检查是否允许通过 Permissions Policy 访问该传感器功能。

**5. 频率控制:**
    *   允许开发者设置传感器的采样频率，并对设置的频率进行限制，防止过高的频率影响性能。

**6. 时间戳管理:**
    *   管理传感器读数的时间戳，并将其转换为 `DOMHighResTimeStamp`，以便在 JavaScript 中使用。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件是 Blink 渲染引擎的 C++ 代码，直接与 JavaScript API 相关联，但与 HTML 和 CSS 没有直接的语法层面的关系。 它的作用是为 JavaScript 提供底层的功能实现。

*   **JavaScript:**  `Sensor` 类的功能直接对应了 JavaScript 中的 `GenericSensor` 接口以及其派生接口 (例如 `Accelerometer`, `Gyroscope`, `Magnetometer`)。
    *   **举例:**  在 JavaScript 中创建一个 `Accelerometer` 对象的背后，Blink 会创建一个 `Sensor` 类的实例（更具体地说是 `Accelerometer` 的子类实例），并调用其 `start()` 方法。当传感器有新的数据时，`sensor.cc` 中的 `NotifyReading()` 方法会被调用，然后会派发 `reading` 事件，JavaScript 中注册了 `onreading` 事件监听器的代码就会被执行。

    ```javascript
    const accelerometer = new Accelerometer({ frequency: 60 });

    accelerometer.onreading = () => {
      console.log("Acceleration X: " + accelerometer.x);
      console.log("Acceleration Y: " + accelerometer.y);
      console.log("Acceleration Z: " + accelerometer.z);
    };

    accelerometer.onerror = (event) => {
      console.error("Sensor error:", event.error.name, event.error.message);
    };

    accelerometer.start();

    // 稍后停止传感器
    // accelerometer.stop();
    ```

*   **HTML:**  HTML 本身不直接涉及传感器 API 的实现。但是，HTML 中可以通过 `<meta>` 标签设置 Permissions Policy，从而影响到 `sensor.cc` 中的权限检查逻辑。
    *   **举例:**  以下 HTML 代码可能会阻止网页访问某些传感器：
        ```html
        <meta http-equiv="Permissions-Policy" content="accelerometer=()">
        ```
        如果 JavaScript 代码尝试创建并启动 `Accelerometer`，`sensor.cc` 中的 `AreFeaturesEnabled` 函数会检查 Permissions Policy，如果发现 `accelerometer` 被禁用，则会抛出一个安全错误，JavaScript 的 `onerror` 回调会被触发。

*   **CSS:** CSS 与传感器 API 没有直接关系。

**逻辑推理与假设输入输出:**

*   **假设输入:** JavaScript 调用 `accelerometer.start()`，并且 Permissions Policy 允许访问加速度计。
*   **输出:**
    1. `Sensor` 类的状态从 `kIdle` 变为 `kActivating`。
    2. `InitSensorProxyIfNeeded()` 方法被调用，如果 `sensor_proxy_` 为空，则会创建与底层传感器服务的连接。
    3. `RequestAddConfiguration()` 方法被调用，创建一个 `SensorConfiguration` 对象，包含设置的频率。
    4. 通过 `sensor_proxy_` 向底层传感器服务发送添加配置的请求。
    5. 底层传感器服务成功初始化并开始发送数据后，`OnSensorInitialized()` 被调用。
    6. `OnAddConfigurationRequestCompleted(true)` 被调用。
    7. `NotifyActivated()` 被调用，`Sensor` 的状态变为 `kActivated`，并且派发 `activate` 事件。
    8. 当底层传感器有新的读数时，`OnSensorReadingChanged()` 被调用。
    9. 根据设置的频率，决定是否立即或延迟调用 `NotifyReading()`。
    10. `NotifyReading()` 被调用，派发 `reading` 事件，并将最新的传感器数据传递给 JavaScript。

*   **假设输入:** JavaScript 设置了一个超出传感器允许最大频率的值，例如 `new Accelerometer({ frequency: 1000 })`，而设备只支持最大 100Hz。
*   **输出:**
    1. 在 `Sensor` 构造函数中，会检测到频率超出最大值。
    2. `frequency_` 会被设置为允许的最大值 (100Hz)。
    3. 一个 `info` 级别的 console message 会被添加到控制台，提示用户最大允许的频率。

**用户或编程常见的使用错误举例说明:**

1. **在非安全上下文中使用传感器 API:**  Sensor API 通常需要在安全上下文 (HTTPS) 中使用。如果网页通过 HTTP 加载，尝试创建传感器对象可能会失败并抛出安全错误。
    *   **错误示例:**  在 HTTP 网站上的 JavaScript 代码尝试 `new Accelerometer()`。
    *   **`sensor.cc` 中的体现:** 构造函数中的 `DCHECK(execution_context->IsSecureContext());` 会触发断言（在开发版本中），并且会抛出安全错误。

2. **没有处理 `onerror` 事件:**  传感器可能会因为各种原因出错（例如权限被拒绝，传感器硬件故障）。如果没有处理 `onerror` 事件，错误可能不会被开发者注意到。
    *   **错误示例:**  创建并启动传感器，但没有添加 `onerror` 监听器。如果用户拒绝了传感器权限，网页不会有任何提示。
    *   **`sensor.cc` 中的体现:** 当底层传感器服务报告错误时，`OnSensorError()` 方法会被调用，然后会派发 `error` 事件。如果 JavaScript 没有监听这个事件，错误信息就丢失了。

3. **设置过高的采样频率:**  设置过高的采样频率可能会影响设备的性能和电池寿命。
    *   **错误示例:**  `new Accelerometer({ frequency: 1000 })`，超过了设备的实际能力。
    *   **`sensor.cc` 中的体现:**  构造函数中会检查并限制频率，并发出控制台警告。

4. **在 Permissions Policy 被禁止的情况下使用传感器:**  如果网站的 Permissions Policy 禁止使用某个传感器，尝试使用该传感器会失败。
    *   **错误示例:**  网站设置了 `<meta http-equiv="Permissions-Policy" content="accelerometer=()">`，然后 JavaScript 代码尝试 `new Accelerometer().start()`。
    *   **`sensor.cc` 中的体现:** `AreFeaturesEnabled()` 函数会检查 Permissions Policy，如果被禁用，构造函数会抛出安全错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个网页上与某个需要使用加速度计的功能进行交互，例如玩一个需要倾斜手机控制的游戏。以下是用户操作如何逐步触发 `sensor.cc` 中的代码：

1. **用户访问网页:** 用户在浏览器中输入网址或点击链接访问包含使用加速度计功能的网页。
2. **网页加载和 JavaScript 执行:** 浏览器加载 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 请求传感器:**  JavaScript 代码在某个时机（例如，用户点击“开始游戏”按钮）创建一个 `Accelerometer` 对象：
    ```javascript
    const accelerometer = new Accelerometer({ frequency: 60 });
    ```
    这会在 Blink 渲染引擎中创建一个 `Sensor` 类（更具体的是 `Accelerometer` 的子类）的实例，调用 `sensor.cc` 中的构造函数。
4. **权限请求 (如果需要):** 如果这是用户首次访问该网站的传感器功能，浏览器可能会弹出权限请求，询问用户是否允许该网站访问加速度计。
5. **用户授权/拒绝权限:**
    *   **授权:** 用户点击“允许”，浏览器会将授权信息传递给 Blink。`sensor.cc` 中的权限检查会通过。
    *   **拒绝:** 用户点击“拒绝”，`sensor.cc` 中的权限检查会失败，并可能触发 `onerror` 事件。
6. **JavaScript 启动传感器:**  JavaScript 代码调用 `accelerometer.start()` 方法。这会调用 `sensor.cc` 中的 `start()` 方法，并将传感器状态设置为 `kActivating`。
7. **Blink 与底层服务交互:** `sensor.cc` 中的 `Activate()` 方法会被调用，它会请求 `SensorProviderProxy` 连接到设备底层的加速度计服务。
8. **数据更新:** 一旦连接建立，底层传感器开始报告加速度数据。这些数据通过 `SensorProviderProxy` 传递到 `sensor.cc`，触发 `OnSensorReadingChanged()` 方法。
9. **事件派发:** `NotifyReading()` 方法被调用，创建一个 `reading` 事件，并将其派发给 JavaScript。
10. **JavaScript 处理数据:** JavaScript 中注册的 `onreading` 事件监听器被调用，可以获取加速度数据并更新游戏状态。

**作为调试线索:**

当开发者在调试传感器相关问题时，可以利用以下线索：

*   **Console 输出:**  `sensor.cc` 中可能会输出 `console.info` 或 `console.warn` 消息，例如当设置的频率被限制时。
*   **断点调试:** 可以在 `sensor.cc` 中的关键方法（如构造函数、`start()`、`stop()`、事件处理函数）设置断点，查看代码执行流程和变量值。
*   **Tracing/Logging:**  Blink 提供了 tracing 和 logging 机制，可以用来跟踪传感器相关的事件和状态变化。
*   **Permissions API:** 检查浏览器的权限设置，确认网站是否被授予了传感器访问权限。
*   **Permissions Policy:** 检查网页的 Permissions Policy 设置，确认传感器功能是否被允许。
*   **浏览器开发者工具:** 使用浏览器开发者工具的 "Sensors" 标签，可以模拟传感器数据，帮助测试和调试。

理解 `sensor.cc` 的功能和它与 web 技术的联系，对于开发和调试涉及到设备传感器的 Web 应用至关重要。它揭示了 JavaScript API 背后的 Blink 内部实现，以及如何与底层操作系统和硬件进行交互。

Prompt: 
```
这是目录为blink/renderer/modules/sensor/sensor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/sensor/sensor.h"

#include <utility>

#include "base/ranges/algorithm.h"
#include "services/device/public/cpp/generic_sensor/sensor_traits.h"
#include "services/device/public/mojom/sensor.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/modules/sensor/sensor_error_event.h"
#include "third_party/blink/renderer/modules/sensor/sensor_provider_proxy.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/web_test_support.h"

namespace blink {

namespace {
const double kWaitingIntervalThreshold = 0.01;

bool AreFeaturesEnabled(
    ExecutionContext* context,
    const Vector<mojom::blink::PermissionsPolicyFeature>& features) {
  return base::ranges::all_of(
      features, [context](mojom::blink::PermissionsPolicyFeature feature) {
        return context->IsFeatureEnabled(feature,
                                         ReportOptions::kReportOnFailure);
      });
}

}  // namespace

Sensor::Sensor(ExecutionContext* execution_context,
               const SensorOptions* sensor_options,
               ExceptionState& exception_state,
               device::mojom::blink::SensorType type,
               const Vector<mojom::blink::PermissionsPolicyFeature>& features)
    : ActiveScriptWrappable<Sensor>({}),
      ExecutionContextLifecycleObserver(execution_context),
      frequency_(0.0),
      type_(type),
      state_(SensorState::kIdle),
      last_reported_timestamp_(0.0) {
  // [SecureContext] in idl.
  DCHECK(execution_context->IsSecureContext());
  DCHECK(!features.empty());

  if (!AreFeaturesEnabled(execution_context, features)) {
    exception_state.ThrowSecurityError(
        "Access to sensor features is disallowed by permissions policy");
    return;
  }

  // Check the given frequency value.
  if (sensor_options->hasFrequency()) {
    frequency_ = sensor_options->frequency();
    const double max_allowed_frequency =
        device::GetSensorMaxAllowedFrequency(type_);
    if (frequency_ > max_allowed_frequency) {
      frequency_ = max_allowed_frequency;
      String message = String::Format(
          "Maximum allowed frequency value for this sensor type is %.0f Hz.",
          max_allowed_frequency);
      auto* console_message = MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kJavaScript,
          mojom::ConsoleMessageLevel::kInfo, std::move(message));
      execution_context->AddConsoleMessage(console_message);
    }
  }
}

Sensor::Sensor(ExecutionContext* execution_context,
               const SpatialSensorOptions* options,
               ExceptionState& exception_state,
               device::mojom::blink::SensorType sensor_type,
               const Vector<mojom::blink::PermissionsPolicyFeature>& features)
    : Sensor(execution_context,
             static_cast<const SensorOptions*>(options),
             exception_state,
             sensor_type,
             features) {
  use_screen_coords_ = (options->referenceFrame() == "screen");
}

Sensor::~Sensor() = default;

void Sensor::start() {
  if (!GetExecutionContext())
    return;
  if (state_ != SensorState::kIdle)
    return;
  state_ = SensorState::kActivating;
  Activate();
}

void Sensor::stop() {
  if (state_ == SensorState::kIdle)
    return;
  Deactivate();
  state_ = SensorState::kIdle;
}

// Getters
bool Sensor::activated() const {
  return state_ == SensorState::kActivated;
}

bool Sensor::hasReading() const {
  if (!activated())
    return false;
  DCHECK(sensor_proxy_);
  return sensor_proxy_->GetReading().timestamp() != 0.0;
}

std::optional<DOMHighResTimeStamp> Sensor::timestamp(
    ScriptState* script_state) const {
  if (!hasReading()) {
    return std::nullopt;
  }

  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  if (!window) {
    return std::nullopt;
  }

  WindowPerformance* performance = DOMWindowPerformance::performance(*window);
  DCHECK(performance);
  DCHECK(sensor_proxy_);

  return performance->MonotonicTimeToDOMHighResTimeStamp(
      base::TimeTicks() +
      base::Seconds(sensor_proxy_->GetReading().timestamp()));
}

void Sensor::Trace(Visitor* visitor) const {
  visitor->Trace(sensor_proxy_);
  ActiveScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  EventTarget::Trace(visitor);
}

bool Sensor::HasPendingActivity() const {
  if (state_ == SensorState::kIdle)
    return false;
  return GetExecutionContext() && HasEventListeners();
}

auto Sensor::CreateSensorConfig() -> SensorConfigurationPtr {
  auto result = SensorConfiguration::New();

  double default_frequency = sensor_proxy_->GetDefaultFrequency();
  double minimum_frequency = sensor_proxy_->GetFrequencyLimits().first;
  double maximum_frequency = sensor_proxy_->GetFrequencyLimits().second;

  if (frequency_ == 0.0)  // i.e. was never set.
    frequency_ = default_frequency;
  if (frequency_ > maximum_frequency)
    frequency_ = maximum_frequency;
  if (frequency_ < minimum_frequency)
    frequency_ = minimum_frequency;

  result->frequency = frequency_;
  return result;
}

void Sensor::InitSensorProxyIfNeeded() {
  if (sensor_proxy_)
    return;

  LocalDOMWindow* window = To<LocalDOMWindow>(GetExecutionContext());
  auto* provider = SensorProviderProxy::From(window);
  sensor_proxy_ = provider->GetSensorProxy(type_);

  if (!sensor_proxy_) {
    sensor_proxy_ =
        provider->CreateSensorProxy(type_, window->GetFrame()->GetPage());
  }
}

void Sensor::ContextDestroyed() {
  // We do not use IsIdleOrErrored() here because we also want to call
  // Deactivate() if |pending_error_notification_| is active (see
  // https://crbug.com/324301018).
  if (state_ != SensorState::kIdle) {
    Deactivate();
  }

  state_ = SensorState::kIdle;

  if (sensor_proxy_)
    sensor_proxy_->Detach();
}

void Sensor::OnSensorInitialized() {
  if (state_ != SensorState::kActivating)
    return;

  RequestAddConfiguration();
}

void Sensor::OnSensorReadingChanged() {
  if (state_ != SensorState::kActivated)
    return;

  // Return if reading update is already scheduled or the cached
  // reading is up-to-date.
  if (pending_reading_notification_.IsActive())
    return;
  double elapsedTime =
      sensor_proxy_->GetReading().timestamp() - last_reported_timestamp_;
  DCHECK_GT(elapsedTime, 0.0);

  DCHECK_GT(configuration_->frequency, 0.0);
  double waitingTime = 1 / configuration_->frequency - elapsedTime;

  // Negative or zero 'waitingTime' means that polling period has elapsed.
  // We also avoid scheduling if the elapsed time is slightly behind the
  // polling period.
  auto sensor_reading_changed =
      WTF::BindOnce(&Sensor::NotifyReading, WrapWeakPersistent(this));
  if (waitingTime < kWaitingIntervalThreshold) {
    // Invoke JS callbacks in a different callchain to obviate
    // possible modifications of SensorProxy::observers_ container
    // while it is being iterated through.
    pending_reading_notification_ = PostCancellableTask(
        *GetExecutionContext()->GetTaskRunner(TaskType::kSensor), FROM_HERE,
        std::move(sensor_reading_changed));
  } else {
    pending_reading_notification_ = PostDelayedCancellableTask(
        *GetExecutionContext()->GetTaskRunner(TaskType::kSensor), FROM_HERE,
        std::move(sensor_reading_changed), base::Seconds(waitingTime));
  }
}

void Sensor::OnSensorError(DOMExceptionCode code,
                           const String& sanitized_message,
                           const String& unsanitized_message) {
  HandleError(code, sanitized_message, unsanitized_message);
}

void Sensor::OnAddConfigurationRequestCompleted(bool result) {
  if (state_ != SensorState::kActivating)
    return;

  if (!result) {
    HandleError(DOMExceptionCode::kNotReadableError,
                "start() call has failed.");
    return;
  }

  if (!GetExecutionContext())
    return;

  pending_activated_notification_ = PostCancellableTask(
      *GetExecutionContext()->GetTaskRunner(TaskType::kSensor), FROM_HERE,
      WTF::BindOnce(&Sensor::NotifyActivated, WrapWeakPersistent(this)));
}

void Sensor::Activate() {
  DCHECK_EQ(state_, SensorState::kActivating);

  InitSensorProxyIfNeeded();
  DCHECK(sensor_proxy_);

  if (sensor_proxy_->IsInitialized())
    RequestAddConfiguration();
  else
    sensor_proxy_->Initialize();

  sensor_proxy_->AddObserver(this);
}

void Sensor::Deactivate() {
  DCHECK_NE(state_, SensorState::kIdle);
  // state_ is not set to kIdle here as on error it should
  // transition to the kIdle state in the same call chain
  // the error event is dispatched, i.e. inside NotifyError().
  pending_reading_notification_.Cancel();
  pending_activated_notification_.Cancel();
  pending_error_notification_.Cancel();

  if (!sensor_proxy_)
    return;

  if (sensor_proxy_->IsInitialized()) {
    DCHECK(configuration_);
    sensor_proxy_->RemoveConfiguration(configuration_->Clone());
    last_reported_timestamp_ = 0.0;
  }

  sensor_proxy_->RemoveObserver(this);
}

void Sensor::RequestAddConfiguration() {
  if (!configuration_) {
    configuration_ = CreateSensorConfig();
    DCHECK(configuration_);
    DCHECK_GE(configuration_->frequency,
              sensor_proxy_->GetFrequencyLimits().first);
    DCHECK_LE(configuration_->frequency,
              sensor_proxy_->GetFrequencyLimits().second);
  }

  DCHECK(sensor_proxy_);
  sensor_proxy_->AddConfiguration(
      configuration_->Clone(),
      WTF::BindOnce(&Sensor::OnAddConfigurationRequestCompleted,
                    WrapWeakPersistent(this)));
}

void Sensor::HandleError(DOMExceptionCode code,
                         const String& sanitized_message,
                         const String& unsanitized_message) {
  if (!GetExecutionContext()) {
    // Deactivate() is already called from Sensor::ContextDestroyed().
    return;
  }

  if (IsIdleOrErrored())
    return;

  Deactivate();

  auto* error = MakeGarbageCollected<DOMException>(code, sanitized_message,
                                                   unsanitized_message);
  pending_error_notification_ = PostCancellableTask(
      *GetExecutionContext()->GetTaskRunner(TaskType::kSensor), FROM_HERE,
      WTF::BindOnce(&Sensor::NotifyError, WrapWeakPersistent(this),
                    WrapPersistent(error)));
}

void Sensor::NotifyReading() {
  DCHECK_EQ(state_, SensorState::kActivated);
  last_reported_timestamp_ = sensor_proxy_->GetReading().timestamp();
  DispatchEvent(*Event::Create(event_type_names::kReading));
}

void Sensor::NotifyActivated() {
  DCHECK_EQ(state_, SensorState::kActivating);
  state_ = SensorState::kActivated;

  if (hasReading()) {
    // If reading has already arrived, process the reading values (a subclass
    // may do some filtering, for example) and then send an initial "reading"
    // event right away.
    DCHECK(!pending_reading_notification_.IsActive());
    pending_reading_notification_ = PostCancellableTask(
        *GetExecutionContext()->GetTaskRunner(TaskType::kSensor), FROM_HERE,
        WTF::BindOnce(&Sensor::OnSensorReadingChanged,
                      WrapWeakPersistent(this)));
  }

  DispatchEvent(*Event::Create(event_type_names::kActivate));
}

void Sensor::NotifyError(DOMException* error) {
  DCHECK_NE(state_, SensorState::kIdle);
  state_ = SensorState::kIdle;
  DispatchEvent(*SensorErrorEvent::Create(event_type_names::kError, error));
}

bool Sensor::IsIdleOrErrored() const {
  return (state_ == SensorState::kIdle) ||
         pending_error_notification_.IsActive();
}

const device::SensorReading& Sensor::GetReading() const {
  DCHECK(sensor_proxy_);
  return sensor_proxy_->GetReading(use_screen_coords_);
}

}  // namespace blink

"""

```