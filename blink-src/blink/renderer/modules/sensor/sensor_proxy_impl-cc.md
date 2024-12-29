Response:
Let's break down the thought process for analyzing the `sensor_proxy_impl.cc` file.

1. **Understanding the Goal:** The request asks for the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical inference, common errors, and debugging context.

2. **Initial Scan and Keyword Recognition:**  Quickly skim the code for recognizable keywords and patterns:
    * `#include`:  Indicates dependencies on other files (like `SensorProviderProxy.h`, `SensorReadingRemapper.h`, and platform headers). These give clues about the file's role.
    * `class SensorProxyImpl`: The core of the file – a class implementation. This will likely hold the main logic.
    * `SensorType`, `SensorConfigurationPtr`, `SensorReading`, `ReportingMode`: These suggest this class deals with sensor data and configuration.
    * `Initialize`, `AddConfiguration`, `RemoveConfiguration`, `Suspend`, `Resume`: These are methods suggesting lifecycle management and interaction with the sensor.
    * `UpdateSensorReading`, `RaiseError`, `ReportError`: Methods dealing with data processing and error handling.
    * `OnSensorCreated`, `OnPollingTimer`: Callback functions, indicating asynchronous behavior.
    * `JavaScript`, `HTML`, `CSS`: Explicit keywords to keep in mind for relating the code to web technologies.

3. **Deconstructing the Class Structure:**  Focus on the `SensorProxyImpl` class and its members:
    * **Constructor (`SensorProxyImpl`)**: Takes `sensor_type`, `SensorProviderProxy`, and `Page` as arguments. This suggests it's instantiated within a web page context and interacts with a sensor provider.
    * **Destructor (`~SensorProxyImpl`)**:  Likely cleans up resources, though it's empty here.
    * **`Trace`**:  For debugging and memory management.
    * **`Initialize`**:  Sets up the sensor connection. Crucially, it calls `sensor_provider_proxy()->GetSensor()`, revealing a dependency on another component.
    * **Configuration Methods (`AddConfiguration`, `RemoveConfiguration`, `GetDefaultFrequency`, `GetFrequencyLimits`)**:  Manage the sensor's operational parameters. These are directly tied to how a web page might control sensor behavior.
    * **Lifecycle Management (`Suspend`, `Resume`)**:  Control the sensor's active state.
    * **Data Handling (`UpdateSensorReading`, `SensorReadingChanged`)**: Processes sensor data, likely from a shared memory buffer. The `shared_buffer_reader_` is a key component here.
    * **Error Handling (`RaiseError`, `ReportError`, `HandleSensorError`)**: Deals with various error scenarios.
    * **Callback Methods (`OnSensorCreated`, `OnPollingTimer`)**: Respond to asynchronous events. `OnSensorCreated` handles the initial sensor setup, while `OnPollingTimer` is used for continuous data updates.
    * **Helper Methods (`ShouldProcessReadings`, `UpdatePollingStatus`, `RemoveActiveFrequency`, `AddActiveFrequency`)**: Internal logic for managing the sensor's state and polling behavior.

4. **Identifying Functionality:** Based on the class structure and method names, we can infer the main functions:
    * **Initialization:** Establishes a connection to the underlying sensor.
    * **Configuration:** Allows setting the sensor's reporting frequency.
    * **Data Acquisition:** Retrieves sensor readings.
    * **Lifecycle Management:**  Starts, stops, and pauses the sensor.
    * **Error Handling:**  Manages and reports errors related to the sensor.

5. **Relating to Web Technologies:**  This is where we connect the C++ code to the user-facing aspects:
    * **JavaScript:** The primary interface for web developers to access sensor data. The C++ code acts as the "backend" for JavaScript sensor APIs (like `Accelerometer`, `Gyroscope`, etc.). The examples demonstrate how JavaScript code interacts with these APIs, indirectly triggering the C++ logic.
    * **HTML:**  While not directly interacting with this C++ file, HTML provides the structure for web pages where sensor-using JavaScript code resides.
    * **CSS:**  Generally irrelevant to the core functionality of sensor data acquisition.

6. **Logical Inference and Examples:** Think about how the code would behave in specific scenarios:
    * **Assumption:** A JavaScript program requests accelerometer data.
    * **Input:** The request includes a desired reporting frequency.
    * **Output:** The C++ code initializes the sensor, configures the reporting frequency, and starts sending data.
    * **Assumption:** An error occurs (e.g., sensor not available).
    * **Input:** The underlying sensor service reports an error.
    * **Output:** The C++ code propagates the error to the JavaScript layer, potentially triggering an error event.

7. **Common Errors:** Consider how developers might misuse the sensor APIs:
    * **Accessing sensor before it's ready:**  Highlight the asynchronous nature of sensor initialization.
    * **Requesting unsupported frequencies:**  Point out the importance of checking `GetFrequencyLimits`.
    * **Permission issues:** Emphasize the browser's permission model.

8. **Debugging Context:**  Trace the user's actions leading to this code:
    * User opens a web page.
    * JavaScript code on the page requests sensor access.
    * The browser's permission system might prompt the user.
    * If permission is granted, the browser (Blink engine) instantiates `SensorProxyImpl`.
    * JavaScript calls methods on the sensor object, which are forwarded to the C++ implementation.

9. **Review and Refine:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Are the examples clear?  Is the relationship to web technologies well-explained?  Are the common errors relevant?

**Self-Correction Example During the Process:**

* **Initial thought:**  "This file directly handles sensor hardware."
* **Correction:** "No, it's a *proxy*. It interacts with another service (`sensor_provider_proxy()`) which likely handles the lower-level hardware interaction. This file focuses on the Blink/renderer side of things."

By following this structured approach, you can effectively analyze complex source code and extract the key information requested. The key is to combine code reading with an understanding of the surrounding system and how it interacts with web technologies.
好的，让我们来详细分析一下 `blink/renderer/modules/sensor/sensor_proxy_impl.cc` 这个文件。

**功能概要:**

`SensorProxyImpl` 类是 Chromium Blink 渲染引擎中，用于代理访问设备传感器的实现。它的主要功能可以概括为：

1. **连接和管理传感器服务:** 它负责与设备服务（通过 `SensorProviderProxy`）建立连接，请求特定类型的传感器（例如加速度计、陀螺仪）。
2. **传感器生命周期管理:**  控制传感器的启动、停止、暂停和恢复。
3. **配置传感器参数:** 允许设置传感器的采样频率。
4. **接收和处理传感器数据:** 从底层传感器服务接收原始数据，并将其传递给 Blink 渲染引擎的其他部分。
5. **错误处理:** 处理传感器连接失败、权限错误等异常情况。
6. **状态管理:** 维护传感器的当前状态（例如，是否已初始化、是否暂停）。
7. **与 JavaScript API 的桥梁:** 虽然 `SensorProxyImpl` 本身是 C++ 代码，但它是 Web 感应器 API (如 `Accelerometer`, `Gyroscope`) 在 Blink 渲染器中的核心实现部分。JavaScript 调用这些 API 时，最终会调用到 `SensorProxyImpl` 的方法。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    * 当 JavaScript 代码中使用 `new Accelerometer()` 创建一个加速度计传感器对象时，Blink 引擎会创建一个对应的 `SensorProxyImpl` 实例。
    * JavaScript 调用传感器的 `start()` 方法会触发 `SensorProxyImpl::Initialize()` 方法，进而连接到设备传感器服务。
    * JavaScript 设置传感器的 `frequency` 属性会调用 `SensorProxyImpl::AddConfiguration()` 或 `SensorProxyImpl::RemoveConfiguration()` 来调整传感器的采样频率。
    * 当传感器数据更新时，底层服务会将数据发送到 `SensorProxyImpl`，然后 `SensorProxyImpl::SensorReadingChanged()` 方法会被调用，最终通知到 JavaScript 层的事件监听器。
    * **举例:**  以下 JavaScript 代码创建了一个加速度计传感器，并监听了 `reading` 事件：

      ```javascript
      const accelerometer = new Accelerometer({ frequency: 60 }); // 请求 60Hz 的采样率
      accelerometer.addEventListener('reading', () => {
        console.log("Acceleration X:", accelerometer.x);
        console.log("Acceleration Y:", accelerometer.y);
        console.log("Acceleration Z:", accelerometer.z);
      });
      accelerometer.start();
      ```
      在这个例子中，`SensorProxyImpl` 负责与设备加速度计通信，并将获取的加速度数据传递给 JavaScript 的事件处理函数。

* **HTML:**
    * HTML 本身不直接与 `SensorProxyImpl` 交互。但是，HTML 提供了网页结构，其中包含的 JavaScript 代码会使用传感器 API，从而间接地触发 `SensorProxyImpl` 的工作。
    * **举例:** 一个简单的 HTML 文件可能包含一个 `<button>` 元素，当点击该按钮时，会执行 JavaScript 代码来启动加速度计。

      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <title>Accelerometer Example</title>
      </head>
      <body>
        <button id="startButton">启动加速度计</button>
        <script>
          const startButton = document.getElementById('startButton');
          startButton.addEventListener('click', () => {
            const accelerometer = new Accelerometer();
            accelerometer.addEventListener('reading', () => {
              console.log(accelerometer.x, accelerometer.y, accelerometer.z);
            });
            accelerometer.start();
          });
        </script>
      </body>
      </html>
      ```

* **CSS:**
    * CSS 与 `SensorProxyImpl` 没有直接关系。CSS 用于控制网页的样式和布局，而 `SensorProxyImpl` 专注于处理传感器数据。

**逻辑推理与假设输入输出:**

**假设输入:**

1. **JavaScript 代码请求创建一个采样频率为 10Hz 的陀螺仪传感器。**
2. **用户已授予该网页访问陀螺仪传感器的权限。**

**`SensorProxyImpl` 内部处理逻辑推理:**

1. `SensorProxyImpl` 的构造函数被调用，`sensor_type` 设置为陀螺仪类型。
2. `Initialize()` 方法被调用。
3. `sensor_provider_proxy()->GetSensor()` 被调用，向设备服务请求陀螺仪传感器。
4. 设备服务成功创建陀螺仪传感器，并通过 `OnSensorCreated()` 回调返回初始化参数。
5. `AddConfiguration()` 方法被调用，传入包含 10Hz 频率的配置。
6. `sensor_remote_->AddConfiguration()` 将配置发送到设备传感器服务。
7. 设备服务配置陀螺仪以 10Hz 的频率上报数据。
8. 当陀螺仪数据更新时，设备服务会将数据发送到 `SensorProxyImpl`。
9. `SensorProxyImpl::SensorReadingChanged()` 被调用。
10. 如果报告模式是 `ON_CHANGE`，`UpdateSensorReading()` 从共享内存读取最新的传感器数据。
11. 如果报告模式是 `CONTINUOUS`，`OnPollingTimer()` 会定期触发 `UpdateSensorReading()`。
12. 观察者 (通常是 JavaScript 层的传感器对象) 的 `OnSensorReadingChanged()` 方法被调用，将数据传递给 JavaScript。

**假设输出:**

* `SensorProxyImpl` 成功连接到陀螺仪传感器。
* 陀螺仪传感器以约 10Hz 的频率开始向 `SensorProxyImpl` 发送数据。
* JavaScript 代码能够接收到陀螺仪的数据更新事件。

**用户或编程常见的使用错误举例说明:**

1. **在传感器未初始化完成前尝试访问数据:**
   * **错误代码示例 (JavaScript):**
     ```javascript
     const accelerometer = new Accelerometer();
     console.log(accelerometer.x); // 可能在 'reading' 事件触发前访问，此时数据未就绪
     ```
   * **`SensorProxyImpl` 层面:**  `reading_` 成员变量可能还没有被初始化，或者包含旧数据。
   * **调试线索:**  检查 `state_` 的值是否为 `kInitialized`。

2. **请求超出传感器支持的频率范围:**
   * **错误代码示例 (JavaScript):**
     ```javascript
     const accelerometer = new Accelerometer({ frequency: 1000 }); // 假设传感器不支持如此高的频率
     ```
   * **`SensorProxyImpl` 层面:** `AddConfiguration()` 调用可能会失败，或者设备服务会限制到支持的最大频率。
   * **调试线索:**  查看 `GetFrequencyLimits()` 返回的频率范围，以及 `AddConfiguration()` 的回调结果。

3. **没有检查传感器权限:**
   * **错误代码示例 (JavaScript):**
     ```javascript
     const accelerometer = new Accelerometer();
     accelerometer.start(); // 如果用户未授权，可能会抛出错误
     ```
   * **`SensorProxyImpl` 层面:** `OnSensorCreated()` 回调可能会收到 `SensorCreationResult::ERROR_NOT_ALLOWED`，导致 `HandleSensorError()` 被调用。
   * **调试线索:**  查看控制台的错误信息，以及 `ReportError()` 方法的调用。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个网页上使用了需要访问加速度计的功能：

1. **用户打开网页:** 用户在浏览器中输入网址或点击链接打开包含传感器相关 JavaScript 代码的网页。
2. **JavaScript 代码执行:**  当网页加载完成后，浏览器开始执行 JavaScript 代码。
3. **创建传感器对象:** JavaScript 代码中使用 `new Accelerometer()` 创建一个加速度计传感器对象。
    * **Blink 层面:**  这会触发 Blink 引擎创建一个 `Accelerometer` 类的 JavaScript 对象，并关联一个 `SensorProxyImpl` 实例。
4. **请求启动传感器:** JavaScript 代码调用 `accelerometer.start()` 方法。
    * **Blink 层面:**  `Accelerometer` 对象的 `start()` 方法会调用到对应的 `SensorProxyImpl::Initialize()` 方法。
5. **`SensorProxyImpl::Initialize()`:**
    * 检查当前状态，确保没有被初始化过。
    * 调用 `sensor_provider_proxy()->GetSensor()`，向设备服务发起请求，请求创建加速度计传感器。
    * **调试线索:**  可以在 `SensorProviderProxy::GetSensor()` 的实现中设置断点，查看请求是否正确发送。
6. **设备服务处理请求:**  设备服务接收到 Blink 的请求，尝试创建加速度计传感器。这可能涉及访问操作系统或硬件层面的传感器接口。
7. **`SensorProxyImpl::OnSensorCreated()` 回调:**
    * 设备服务创建成功后，会将包含传感器初始化参数的消息发送回 Blink 渲染进程。
    * `SensorProxyImpl::OnSensorCreated()` 方法会被调用，接收这些参数。
    * **调试线索:**  检查 `params` 是否为空，以及 `result` 的值，可以判断传感器创建是否成功。
    * 如果创建成功，会绑定 Mojo 接口 (`sensor_remote_`, `client_receiver_`)，并创建共享内存读取器 (`shared_buffer_reader_`)。
8. **JavaScript 添加事件监听器:**  JavaScript 代码可能会添加 `reading` 事件的监听器。
    * **Blink 层面:**  这会将一个回调函数注册到 `SensorProxyImpl` 的观察者列表中。
9. **传感器数据更新:**
    * 设备加速度计产生新的数据。
    * 设备服务将数据写入共享内存，并通过 Mojo 接口通知 Blink。
    * **`SensorProxyImpl::SensorReadingChanged()` 被调用:**  接收到数据更新的通知。
    * **`UpdateSensorReading()` 被调用:** 从共享内存读取最新的传感器数据。
    * **通知观察者:** 遍历观察者列表，调用每个观察者的 `OnSensorReadingChanged()` 方法。
    * **Blink 层面:**  这会将数据传递给 JavaScript 的 `Accelerometer` 对象，并触发 `reading` 事件。
10. **JavaScript 事件处理:** JavaScript 的 `reading` 事件监听器被触发，可以访问 `accelerometer.x`, `accelerometer.y`, `accelerometer.z` 等属性来获取最新的加速度值。

**调试线索总结:**

* **断点:** 在 `SensorProxyImpl` 的关键方法（如 `Initialize`, `OnSensorCreated`, `SensorReadingChanged`, `AddConfiguration`）设置断点，可以跟踪代码的执行流程。
* **日志:** 使用 `DLOG` 或 `DVLOG` 记录关键变量的值，例如传感器类型、频率、状态、接收到的数据等。
* **Mojo Inspector:**  使用 Chrome 的 `chrome://inspect/#mojo` 工具可以查看 Blink 渲染进程和设备服务之间的 Mojo 消息传递情况，帮助诊断通信问题。
* **权限检查:** 确保用户已授予网页访问传感器的权限。可以在浏览器的设置中查看和修改权限。
* **设备状态:**  确认设备传感器硬件工作正常。

希望以上分析能够帮助你理解 `blink/renderer/modules/sensor/sensor_proxy_impl.cc` 文件的功能和在 Chromium Blink 引擎中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/sensor/sensor_proxy_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/sensor/sensor_proxy_impl.h"

#include "services/device/public/cpp/generic_sensor/sensor_traits.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/modules/sensor/sensor_provider_proxy.h"
#include "third_party/blink/renderer/modules/sensor/sensor_reading_remapper.h"

using device::mojom::blink::SensorCreationResult;

namespace blink {

SensorProxyImpl::SensorProxyImpl(device::mojom::blink::SensorType sensor_type,
                                 SensorProviderProxy* provider,
                                 Page* page)
    : SensorProxy(sensor_type, provider, page),
      sensor_remote_(provider->GetSupplementable()),
      client_receiver_(this, provider->GetSupplementable()),
      task_runner_(
          provider->GetSupplementable()->GetTaskRunner(TaskType::kSensor)),
      polling_timer_(
          provider->GetSupplementable()->GetTaskRunner(TaskType::kSensor),
          this,
          &SensorProxyImpl::OnPollingTimer) {}

SensorProxyImpl::~SensorProxyImpl() {}

void SensorProxyImpl::Trace(Visitor* visitor) const {
  visitor->Trace(sensor_remote_);
  visitor->Trace(client_receiver_);
  visitor->Trace(polling_timer_);
  SensorProxy::Trace(visitor);
}

void SensorProxyImpl::Initialize() {
  if (state_ != kUninitialized)
    return;

  if (!sensor_provider_proxy()) {
    HandleSensorError();
    return;
  }

  state_ = kInitializing;
  sensor_provider_proxy()->GetSensor(
      type_, WTF::BindOnce(&SensorProxyImpl::OnSensorCreated,
                           WrapWeakPersistent(this)));
}

void SensorProxyImpl::AddConfiguration(
    device::mojom::blink::SensorConfigurationPtr configuration,
    base::OnceCallback<void(bool)> callback) {
  DCHECK(IsInitialized());
  AddActiveFrequency(configuration->frequency);
  sensor_remote_->AddConfiguration(std::move(configuration),
                                   std::move(callback));
}

void SensorProxyImpl::RemoveConfiguration(
    device::mojom::blink::SensorConfigurationPtr configuration) {
  DCHECK(IsInitialized());
  RemoveActiveFrequency(configuration->frequency);
  if (sensor_remote_.is_bound())
    sensor_remote_->RemoveConfiguration(std::move(configuration));
}

double SensorProxyImpl::GetDefaultFrequency() const {
  DCHECK(IsInitialized());
  return default_frequency_;
}

std::pair<double, double> SensorProxyImpl::GetFrequencyLimits() const {
  DCHECK(IsInitialized());
  return frequency_limits_;
}

void SensorProxyImpl::Suspend() {
  if (suspended_ || !sensor_remote_.is_bound())
    return;

  sensor_remote_->Suspend();
  suspended_ = true;
  UpdatePollingStatus();
}

void SensorProxyImpl::Resume() {
  if (!suspended_ || !sensor_remote_.is_bound())
    return;

  sensor_remote_->Resume();
  suspended_ = false;
  UpdatePollingStatus();
}

void SensorProxyImpl::UpdateSensorReading() {
  DCHECK(ShouldProcessReadings());
  DCHECK(shared_buffer_reader_);

  // Try to read the latest value from shared memory. Failure should not be
  // fatal because we only retry a finite number of times.
  device::SensorReading reading_data;
  if (!shared_buffer_reader_->GetReading(&reading_data))
    return;

  double latest_timestamp = reading_data.timestamp();
  if (reading_.timestamp() != latest_timestamp &&
      latest_timestamp != 0.0)  // The shared buffer is zeroed when
                                // sensor is stopped, we skip this
                                // reading.
  {
    DCHECK_GT(latest_timestamp, reading_.timestamp())
        << "Timestamps must increase monotonically";
    reading_ = reading_data;
    for (Observer* observer : observers_)
      observer->OnSensorReadingChanged();
  }
}

void SensorProxyImpl::RaiseError() {
  HandleSensorError();
}

void SensorProxyImpl::SensorReadingChanged() {
  DCHECK_EQ(device::mojom::blink::ReportingMode::ON_CHANGE, mode_);
  if (ShouldProcessReadings())
    UpdateSensorReading();
}

void SensorProxyImpl::ReportError(DOMExceptionCode code,
                                  const String& message) {
  state_ = kUninitialized;
  active_frequencies_.clear();
  reading_ = device::SensorReading();
  UpdatePollingStatus();

  sensor_remote_.reset();
  shared_buffer_reader_.reset();
  default_frequency_ = 0.0;
  frequency_limits_ = {0.0, 0.0};
  client_receiver_.reset();

  SensorProxy::ReportError(code, message);
}

void SensorProxyImpl::HandleSensorError(SensorCreationResult error) {
  if (error == SensorCreationResult::ERROR_NOT_ALLOWED) {
    String description = "Permissions to access sensor are not granted";
    ReportError(DOMExceptionCode::kNotAllowedError, std::move(description));
  } else {
    ReportError(DOMExceptionCode::kNotReadableError, kDefaultErrorDescription);
  }
}

void SensorProxyImpl::OnSensorCreated(
    SensorCreationResult result,
    device::mojom::blink::SensorInitParamsPtr params) {
  DCHECK_EQ(kInitializing, state_);
  if (!params) {
    DCHECK_NE(SensorCreationResult::SUCCESS, result);
    HandleSensorError(result);
    return;
  }

  DCHECK_EQ(SensorCreationResult::SUCCESS, result);

  mode_ = params->mode;
  if (!params->default_configuration) {
    HandleSensorError();
    return;
  }

  default_frequency_ = params->default_configuration->frequency;
  DCHECK_GT(default_frequency_, 0.0);

  sensor_remote_.Bind(std::move(params->sensor), task_runner_);
  client_receiver_.Bind(std::move(params->client_receiver), task_runner_);

  shared_buffer_reader_ = device::SensorReadingSharedBufferReader::Create(
      std::move(params->memory), params->buffer_offset);
  if (!shared_buffer_reader_) {
    HandleSensorError();
    return;
  }

  device::SensorReading reading;
  if (!shared_buffer_reader_->GetReading(&reading)) {
    HandleSensorError();
    return;
  }
  reading_ = std::move(reading);

  frequency_limits_.first = params->minimum_frequency;
  frequency_limits_.second = params->maximum_frequency;

  DCHECK_GT(frequency_limits_.first, 0.0);
  DCHECK_GE(frequency_limits_.second, frequency_limits_.first);
  DCHECK_GE(device::GetSensorMaxAllowedFrequency(type_),
            frequency_limits_.second);

  auto error_callback = WTF::BindOnce(
      &SensorProxyImpl::HandleSensorError, WrapWeakPersistent(this),
      SensorCreationResult::ERROR_NOT_AVAILABLE);
  sensor_remote_.set_disconnect_handler(std::move(error_callback));

  state_ = kInitialized;

  UpdateSuspendedStatus();

  for (Observer* observer : observers_)
    observer->OnSensorInitialized();
}

void SensorProxyImpl::OnPollingTimer(TimerBase*) {
  UpdateSensorReading();
}

bool SensorProxyImpl::ShouldProcessReadings() const {
  return IsInitialized() && !suspended_ && !active_frequencies_.empty();
}

void SensorProxyImpl::UpdatePollingStatus() {
  if (mode_ != device::mojom::blink::ReportingMode::CONTINUOUS)
    return;

  if (ShouldProcessReadings()) {
    // TODO(crbug/721297) : We need to find out an algorithm for resulting
    // polling frequency.
    polling_timer_.StartRepeating(base::Seconds(1 / active_frequencies_.back()),
                                  FROM_HERE);
  } else {
    polling_timer_.Stop();
  }
}

void SensorProxyImpl::RemoveActiveFrequency(double frequency) {
  // Can use binary search as active_frequencies_ is sorted.
  Vector<double>::iterator it = std::lower_bound(
      active_frequencies_.begin(), active_frequencies_.end(), frequency);
  if (it == active_frequencies_.end() || *it != frequency) {
    NOTREACHED() << "Attempted to remove active frequency which is not present "
                    "in the list";
  }

  active_frequencies_.erase(it);
  UpdatePollingStatus();

  if (active_frequencies_.empty())
    reading_ = device::SensorReading();
}

void SensorProxyImpl::AddActiveFrequency(double frequency) {
  Vector<double>::iterator it = std::lower_bound(
      active_frequencies_.begin(), active_frequencies_.end(), frequency);
  if (it == active_frequencies_.end()) {
    active_frequencies_.push_back(frequency);
  } else {
    active_frequencies_.insert(
        static_cast<wtf_size_t>(std::distance(active_frequencies_.begin(), it)),
        frequency);
  }
  UpdatePollingStatus();
}

}  // namespace blink

"""

```