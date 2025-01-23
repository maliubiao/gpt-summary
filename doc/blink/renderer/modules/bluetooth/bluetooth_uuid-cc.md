Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `bluetooth_uuid.cc` file, its relation to web technologies (JavaScript, HTML, CSS), potential user/programmer errors, and debugging steps to reach this code.

2. **Initial Code Scan (Keywords and Structure):**  Quickly skim the code looking for familiar keywords and structural elements. I see:
    * `#include`: This tells me it's C++ and includes other files (headers). The included headers like `v8_union_string_unsignedlong.h` and the `blink` namespace strongly suggest this is part of the Chromium browser's Blink rendering engine.
    * `namespace blink`: Confirms it's within the Blink engine.
    * `HashMap`: Indicates the use of hash tables for efficient lookups.
    * `String`, `StringBuilder`: Suggests string manipulation is a core function.
    * `enum class GATTAttribute`: Defines a type for GATT attributes (Service, Characteristic, Descriptor).
    * Static functions like `GetAssignedNumberToServiceNameMap()`, `GetAssignedNumberForCharacteristicNameMap()`, `GetAssignedNumberForDescriptorNameMap()`:  These seem to be providing mappings between names and numerical IDs. The comments above them with URLs to bluetooth.com confirm this is about Bluetooth GATT specifications.
    * Functions like `GetUUIDFromV8Value`, `GetUUIDForGATTAttribute`, `GetBluetoothUUIDFromV8Value`:  These clearly deal with UUIDs (Universally Unique Identifiers) and converting between different representations.
    * Static methods in the `BluetoothUUID` class: `getService`, `getCharacteristic`, `getDescriptor`, `canonicalUUID`. These appear to be the main public interface.
    * `ExceptionState`:  Indicates error handling and the possibility of throwing exceptions.

3. **Core Functionality Identification:** Based on the initial scan, it's clear the primary function of this file is to handle Bluetooth UUIDs within the Blink engine. Specifically:
    * **Mapping:**  It maps human-readable names (like "heart_rate") to their assigned 16-bit UUID numbers.
    * **Conversion:** It converts these 16-bit numbers into canonical 128-bit UUID strings.
    * **Validation:** It validates if an input string is a valid UUID or a recognized name.

4. **Relationship to Web Technologies:**  The inclusion of `v8_union_string_unsignedlong.h` is the key here. V8 is Google's high-performance JavaScript engine. This strongly suggests a connection to the Web Bluetooth API.

    * **JavaScript Interaction:** The `BluetoothUUID.getService()`, `BluetoothUUID.getCharacteristic()`, and `BluetoothUUID.getDescriptor()` methods in C++ likely correspond to static methods accessible in JavaScript through the Web Bluetooth API. When a developer uses these methods in JavaScript, the calls are eventually routed to this C++ code for processing.

    * **HTML/CSS - Indirect Relationship:** The relationship with HTML and CSS is indirect. Web Bluetooth API usage (and thus this code) is triggered by JavaScript code embedded in an HTML page. CSS is unrelated to the core functionality of Bluetooth interaction.

5. **Logic and Examples:** The core logic involves checking the input against different formats (16-bit number, 128-bit UUID string, standard name).

    * **Assumption:** A JavaScript developer uses the Web Bluetooth API.
    * **Input Example:** A JavaScript call like `BluetoothUUID.getService('heart_rate')`.
    * **Output:** The C++ code will look up "heart_rate" in its service map and return the canonical UUID string for the Heart Rate service.
    * **Error Example:** A JavaScript call like `BluetoothUUID.getService('invalid_service_name')`. The C++ code will not find this name and throw a `TypeError`.

6. **User/Programmer Errors:**  Common errors revolve around providing invalid input to the `getService`, `getCharacteristic`, and `getDescriptor` methods:

    * **Incorrect Name:**  Typing the name wrong (e.g., "heat_rate" instead of "heart_rate").
    * **Invalid UUID Format:**  Providing a UUID string with incorrect formatting (e.g., missing hyphens, wrong number of characters).
    * **Incorrect Data Type:** While the function accepts both strings and numbers, providing the wrong *type* might lead to unexpected behavior or errors elsewhere in the system.

7. **Debugging Steps:**  To reach this code during debugging, a developer would typically:

    * **Start with JavaScript:** They would be writing JavaScript code using the Web Bluetooth API.
    * **Encounter an Error:**  They might get an error related to an invalid UUID.
    * **Set Breakpoints:** They would set breakpoints in their JavaScript code around the `BluetoothUUID.getService`, `getCharacteristic`, or `getDescriptor` calls.
    * **Step Through Code:** Using the browser's developer tools, they would step through the JavaScript code.
    * **Potentially "Dive" into Native Code:**  If they have the Chromium source code and debugging symbols, they could potentially step into the native C++ code of the Blink engine, eventually reaching `bluetooth_uuid.cc`. More realistically, they would rely on console logs or error messages to diagnose the issue originating from the native code.

8. **Refine and Organize:**  Finally, organize the information into clear sections as requested by the prompt (functionality, relationship to web technologies, examples, errors, debugging). Ensure the language is clear and concise. Use bullet points and code formatting to improve readability. Emphasize the connection to the Web Bluetooth API as the core link to the web technologies.
好的，让我们来分析一下 `blink/renderer/modules/bluetooth/bluetooth_uuid.cc` 这个文件。

**文件功能:**

这个文件定义了 `blink::BluetoothUUID` 类及其相关的辅助函数，主要负责处理蓝牙 UUID (Universally Unique Identifier) 的表示和转换。其核心功能包括：

1. **UUID 的规范化:**  将短格式的 16 位 UUID 转换为标准的 128 位 UUID 字符串格式。例如，将 `0x1800` 转换为 `"00001800-0000-1000-8000-00805f9b34fb"`。
2. **已分配名称到 UUID 的映射:** 维护了 Bluetooth SIG (Special Interest Group) 定义的 GATT (Generic Attribute Profile) 服务、特征和描述符的名称与其对应的 16 位 UUID 的映射关系。
3. **通过名称获取 UUID:**  提供了静态方法 `getService`、`getCharacteristic` 和 `getDescriptor`，允许通过 GATT 服务的名称（例如 `"heart_rate"`）或特征的名称（例如 `"battery_level"`）来获取其对应的 UUID。
4. **输入校验:** 在通过名称获取 UUID 时，会对输入的字符串进行校验，判断其是否为合法的 UUID、16 位 UUID 的别名（例如 "0x1800"）或者已知的标准名称。如果输入不合法，会抛出 `TypeError` 异常。

**与 JavaScript, HTML, CSS 的关系:**

这个文件是 Chromium Blink 引擎的一部分，负责实现 Web Bluetooth API 的底层逻辑。Web Bluetooth API 允许网页上的 JavaScript 代码与附近的蓝牙设备进行通信。

* **JavaScript:**  这个文件中的 `BluetoothUUID` 类提供的静态方法，直接对应了 Web Bluetooth API 中 `BluetoothUUID` 接口的静态方法。

   **举例说明:**

   ```javascript
   // JavaScript 代码
   navigator.bluetooth.requestDevice({
       filters: [{ services: ['heart_rate'] }]
   })
   .then(device => {
       console.log('设备名称:', device.name);
       return device.gatt.connect();
   })
   .then(server => {
       return server.getPrimaryService('heart_rate'); // 这里用到了服务名称 'heart_rate'
   })
   .then(service => {
       console.log('已连接到心率服务:', service);
       return service.getCharacteristic('heart_rate_measurement'); // 这里用到了特征名称 'heart_rate_measurement'
   })
   .then(characteristic => {
       console.log('已获取心率测量特征:', characteristic);
       // ...
   })
   .catch(error => {
       console.error('发生错误:', error);
   });
   ```

   在上面的 JavaScript 代码中，当调用 `server.getPrimaryService('heart_rate')` 和 `service.getCharacteristic('heart_rate_measurement')` 时，Blink 引擎会调用 `blink::BluetoothUUID::getService` 和 `blink::BluetoothUUID::getCharacteristic` 这两个 C++ 函数。`bluetooth_uuid.cc` 文件会根据传入的字符串（例如 `"heart_rate"`）在内部的映射表中查找对应的 UUID，并返回规范化的 UUID 字符串。

* **HTML:** HTML 文件中通过 `<script>` 标签引入 JavaScript 代码，从而间接地使用了这个 C++ 文件的功能。

* **CSS:** CSS 与这个文件的功能没有直接关系。CSS 负责网页的样式和布局，而这个文件处理的是蓝牙相关的逻辑。

**逻辑推理及假设输入与输出:**

假设 JavaScript 代码调用了 `BluetoothUUID.getService()` 方法：

* **假设输入 1 (已知的服务名称):**  `"heart_rate"`
   * **C++ 代码逻辑:** `GetAssignedNumberToServiceNameMap()` 会被调用，查找 `"heart_rate"` 对应的 16 位 UUID `0x180D`。然后 `canonicalUUID(0x180D)` 被调用，返回规范化的 UUID 字符串 `"0000180d-0000-1000-8000-00805f9b34fb"`。
   * **输出:** `"0000180d-0000-1000-8000-00805f9b34fb"`

* **假设输入 2 (16 位 UUID 别名):** `"0x180F"`
   * **C++ 代码逻辑:** `GetUUIDFromV8Value` 会将 `"0x180F"` 解析为数字 `0x180F`。 `canonicalUUID(0x180F)` 被调用，返回 `"0000180f-0000-1000-8000-00805f9b34fb"`。
   * **输出:** `"0000180f-0000-1000-8000-00805f9b34fb"`

* **假设输入 3 (合法的 128 位 UUID):** `"0000ffe0-0000-1000-8000-00805f9b34fb"`
   * **C++ 代码逻辑:** `WTF::IsValidUUID` 判断输入是合法的 UUID，直接返回输入的字符串。
   * **输出:** `"0000ffe0-0000-1000-8000-00805f9b34fb"`

* **假设输入 4 (无效的服务名称):** `"invalid_service"`
   * **C++ 代码逻辑:** 在 `GetAssignedNumberToServiceNameMap()` 中找不到 `"invalid_service"`，会构建一个包含错误信息的字符串，并通过 `exception_state.ThrowTypeError()` 抛出一个类型错误。
   * **输出:** 抛出一个 `TypeError` 异常，错误信息类似于 "Invalid Service name: 'invalid_service'. It must be a valid UUID alias (e.g. 0x1234), UUID (lowercase hex characters e.g. '00001234-0000-1000-8000-00805f9b34fb'), or recognized standard name from https://www.bluetooth.com/specifications/gatt/services e.g. 'alert_notification'."

**用户或编程常见的使用错误:**

1. **拼写错误或使用了非标准的 UUID 名称:**  用户在 JavaScript 代码中输入了错误的 GATT 服务、特征或描述符名称，例如将 `"heart_rate"` 拼写成 `"heat_rate"`，或者使用了自定义的、未在 Bluetooth SIG 注册的名称。这会导致 `getService`、`getCharacteristic` 或 `getDescriptor` 方法找不到对应的 UUID 并抛出 `TypeError`。

   **举例:**

   ```javascript
   // 错误示例
   navigator.bluetooth.requestDevice({
       filters: [{ services: ['heat_rate'] }] // 拼写错误
   });
   ```

   **错误信息 (假设浏览器未做名称纠正):**  "Invalid Service name: 'heat_rate'..."

2. **使用了错误的 UUID 格式:**  用户直接在 JavaScript 代码中提供了 UUID 字符串，但格式不正确，例如缺少连字符、使用了大写字母等。虽然 `IsValidUUID` 会进行校验，但错误的格式仍然可能导致其他问题。

   **举例:**

   ```javascript
   // 错误示例
   server.getPrimaryService('0000180D00001000800000805F9B34FB'); // 缺少连字符
   ```

   虽然这个例子最终可能也能工作（因为数字形式也会被处理），但在其他场景下，格式错误可能会导致解析失败。

3. **混淆了不同类型的 UUID:**  用户可能错误地将服务 UUID 当作特征 UUID 使用，或者反之。例如，在 `getCharacteristic` 方法中传入了服务名称。

   **举例:**

   ```javascript
   // 错误示例
   service.getCharacteristic('heart_rate'); // 'heart_rate' 是服务名称，应该传入特征名称
   ```

   这将导致 `GetUUIDForGATTAttribute` 函数在查找特征映射表时找不到对应的 UUID。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在网页上操作，尝试连接一个心率监测设备并读取心率数据：

1. **用户点击网页上的 "连接心率设备" 按钮。**
2. **JavaScript 代码被触发，调用 `navigator.bluetooth.requestDevice(...)` 方法，并在 `filters` 中指定了 `services: ['heart_rate']`。**
3. **浏览器显示蓝牙设备选择器，用户选择了一个心率设备。**
4. **JavaScript 代码获取到 `BluetoothDevice` 对象后，调用 `device.gatt.connect()` 尝试连接 GATT 服务器。**
5. **连接成功后，JavaScript 代码调用 `server.getPrimaryService('heart_rate')`。**  <-- **这里会调用 `blink::BluetoothUUID::getService`**
   * Blink 引擎接收到 JavaScript 的调用，参数为字符串 `"heart_rate"`。
   * `blink::BluetoothUUID::getService` 函数被执行，调用 `GetUUIDForGATTAttribute`。
   * `GetUUIDForGATTAttribute` 函数根据 `"heart_rate"` 在服务名称映射表中查找对应的 UUID。
   * 找到对应的 UUID `0x180D`，并将其转换为规范的 UUID 字符串 `"0000180d-0000-1000-8000-00805f9b34fb"`。
   * 该 UUID 字符串被返回给 JavaScript。
6. **JavaScript 代码获取到 `BluetoothService` 对象后，调用 `service.getCharacteristic('heart_rate_measurement')`。**  <-- **这里会调用 `blink::BluetoothUUID::getCharacteristic`**
   * Blink 引擎接收到 JavaScript 的调用，参数为字符串 `"heart_rate_measurement"`。
   * `blink::BluetoothUUID::getCharacteristic` 函数被执行，调用 `GetUUIDForGATTAttribute`。
   * `GetUUIDForGATTAttribute` 函数根据 `"heart_rate_measurement"` 在特征名称映射表中查找对应的 UUID。
   * 找到对应的 UUID `0x2A37`，并将其转换为规范的 UUID 字符串 `"00002a37-0000-1000-8000-00805f9b34fb"`。
   * 该 UUID 字符串被返回给 JavaScript。
7. **JavaScript 代码获取到 `BluetoothCharacteristic` 对象后，可以进行读取心率数据等操作。**

**调试线索:**

* 如果在第 5 步或第 6 步出现错误，例如控制台输出 `TypeError: Invalid Service name: '...'` 或 `TypeError: Invalid Characteristic name: '...'`，则很可能问题出在用户提供的服务或特征名称不正确。
* 可以通过在 JavaScript 代码中添加 `console.log()` 语句来查看传递给 `getPrimaryService` 和 `getCharacteristic` 的参数是否正确。
* 如果怀疑是底层 C++ 代码的问题，可以尝试在 Chromium 源代码中设置断点，例如在 `blink::BluetoothUUID::getService` 或 `GetUUIDForGATTAttribute` 函数入口处，来跟踪代码的执行流程和变量的值。
* 查看浏览器的开发者工具中的 "Network" 或 "Bluetooth" 面板，可能会提供更底层的蓝牙通信信息，帮助定位问题。

希望以上分析能够帮助你理解 `blink/renderer/modules/bluetooth/bluetooth_uuid.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/bluetooth/bluetooth_uuid.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/bluetooth/bluetooth_uuid.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_unsignedlong.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"

namespace blink {

namespace {

typedef WTF::HashMap<String, unsigned> NameToAssignedNumberMap;

enum class GATTAttribute { kService, kCharacteristic, kDescriptor };

NameToAssignedNumberMap* GetAssignedNumberToServiceNameMap() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      NameToAssignedNumberMap, services_map,
      ({
          // https://www.bluetooth.com/specifications/gatt/services
          {"generic_access", 0x1800},
          {"generic_attribute", 0x1801},
          {"immediate_alert", 0x1802},
          {"link_loss", 0x1803},
          {"tx_power", 0x1804},
          {"current_time", 0x1805},
          {"reference_time_update", 0x1806},
          {"next_dst_change", 0x1807},
          {"glucose", 0x1808},
          {"health_thermometer", 0x1809},
          {"device_information", 0x180A},
          {"heart_rate", 0x180D},
          {"phone_alert_status", 0x180E},
          {"battery_service", 0x180F},
          {"blood_pressure", 0x1810},
          {"alert_notification", 0x1811},
          {"human_interface_device", 0x1812},
          {"scan_parameters", 0x1813},
          {"running_speed_and_cadence", 0x1814},
          {"automation_io", 0x1815},
          {"cycling_speed_and_cadence", 0x1816},
          {"cycling_power", 0x1818},
          {"location_and_navigation", 0x1819},
          {"environmental_sensing", 0x181A},
          {"body_composition", 0x181B},
          {"user_data", 0x181C},
          {"weight_scale", 0x181D},
          {"bond_management", 0x181E},
          {"continuous_glucose_monitoring", 0x181F},
          {"internet_protocol_support", 0x1820},
          {"indoor_positioning", 0x1821},
          {"pulse_oximeter", 0x1822},
          {"http_proxy", 0x1823},
          {"transport_discovery", 0x1824},
          {"object_transfer", 0x1825},
          {"fitness_machine", 0x1826},
          {"mesh_provisioning", 0x1827},
          {"mesh_proxy", 0x1828},
          {"reconnection_configuration", 0x1829},
      }));

  return &services_map;
}

NameToAssignedNumberMap* GetAssignedNumberForCharacteristicNameMap() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      NameToAssignedNumberMap, characteristics_map,
      ({
          // https://www.bluetooth.com/specifications/gatt/characteristics
          {"gap.device_name", 0x2A00},
          {"gap.appearance", 0x2A01},
          {"gap.peripheral_privacy_flag", 0x2A02},
          {"gap.reconnection_address", 0x2A03},
          {"gap.peripheral_preferred_connection_parameters", 0x2A04},
          {"gatt.service_changed", 0x2A05},
          {"alert_level", 0x2A06},
          {"tx_power_level", 0x2A07},
          {"date_time", 0x2A08},
          {"day_of_week", 0x2A09},
          {"day_date_time", 0x2A0A},
          {"exact_time_100", 0x2A0B},
          {"exact_time_256", 0x2A0C},
          {"dst_offset", 0x2A0D},
          {"time_zone", 0x2A0E},
          {"local_time_information", 0x2A0F},
          {"secondary_time_zone", 0x2A10},
          {"time_with_dst", 0x2A11},
          {"time_accuracy", 0x2A12},
          {"time_source", 0x2A13},
          {"reference_time_information", 0x2A14},
          {"time_broadcast", 0x2A15},
          {"time_update_control_point", 0x2A16},
          {"time_update_state", 0x2A17},
          {"glucose_measurement", 0x2A18},
          {"battery_level", 0x2A19},
          {"battery_power_state", 0x2A1A},
          {"battery_level_state", 0x2A1B},
          {"temperature_measurement", 0x2A1C},
          {"temperature_type", 0x2A1D},
          {"intermediate_temperature", 0x2A1E},
          {"temperature_celsius", 0x2A1F},
          {"temperature_fahrenheit", 0x2A20},
          {"measurement_interval", 0x2A21},
          {"boot_keyboard_input_report", 0x2A22},
          {"system_id", 0x2A23},
          {"model_number_string", 0x2A24},
          {"serial_number_string", 0x2A25},
          {"firmware_revision_string", 0x2A26},
          {"hardware_revision_string", 0x2A27},
          {"software_revision_string", 0x2A28},
          {"manufacturer_name_string", 0x2A29},
          {"ieee_11073-20601_regulatory_certification_data_list", 0x2A2A},
          {"current_time", 0x2A2B},
          {"magnetic_declination", 0x2A2C},
          {"position_2d", 0x2A2F},
          {"position_3d", 0x2A30},
          {"scan_refresh", 0x2A31},
          {"boot_keyboard_output_report", 0x2A32},
          {"boot_mouse_input_report", 0x2A33},
          {"glucose_measurement_context", 0x2A34},
          {"blood_pressure_measurement", 0x2A35},
          {"intermediate_cuff_pressure", 0x2A36},
          {"heart_rate_measurement", 0x2A37},
          {"body_sensor_location", 0x2A38},
          {"heart_rate_control_point", 0x2A39},
          {"removable", 0x2A3A},
          {"service_required", 0x2A3B},
          {"scientific_temperature_celsius", 0x2A3C},
          {"string", 0x2A3D},
          {"network_availability", 0x2A3E},
          {"alert_status", 0x2A3F},
          {"ringer_control_point", 0x2A40},
          {"ringer_setting", 0x2A41},
          {"alert_category_id_bit_mask", 0x2A42},
          {"alert_category_id", 0x2A43},
          {"alert_notification_control_point", 0x2A44},
          {"unread_alert_status", 0x2A45},
          {"new_alert", 0x2A46},
          {"supported_new_alert_category", 0x2A47},
          {"supported_unread_alert_category", 0x2A48},
          {"blood_pressure_feature", 0x2A49},
          {"hid_information", 0x2A4A},
          {"report_map", 0x2A4B},
          {"hid_control_point", 0x2A4C},
          {"report", 0x2A4D},
          {"protocol_mode", 0x2A4E},
          {"scan_interval_window", 0x2A4F},
          {"pnp_id", 0x2A50},
          {"glucose_feature", 0x2A51},
          {"record_access_control_point", 0x2A52},
          {"rsc_measurement", 0x2A53},
          {"rsc_feature", 0x2A54},
          {"sc_control_point", 0x2A55},
          {"digital", 0x2A56},
          {"digital_output", 0x2A57},
          {"analog", 0x2A58},
          {"analog_output", 0x2A59},
          {"aggregate", 0x2A5A},
          {"csc_measurement", 0x2A5B},
          {"csc_feature", 0x2A5C},
          {"sensor_location", 0x2A5D},
          {"plx_spot_check_measurement", 0x2A5E},
          {"plx_continuous_measurement", 0x2A5F},
          {"plx_features", 0x2A60},
          {"pulse_oximetry_control_point", 0x2A62},
          {"cycling_power_measurement", 0x2A63},
          {"cycling_power_vector", 0x2A64},
          {"cycling_power_feature", 0x2A65},
          {"cycling_power_control_point", 0x2A66},
          {"location_and_speed", 0x2A67},
          {"navigation", 0x2A68},
          {"position_quality", 0x2A69},
          {"ln_feature", 0x2A6A},
          {"ln_control_point", 0x2A6B},
          {"elevation", 0x2A6C},
          {"pressure", 0x2A6D},
          {"temperature", 0x2A6E},
          {"humidity", 0x2A6F},
          {"true_wind_speed", 0x2A70},
          {"true_wind_direction", 0x2A71},
          {"apparent_wind_speed", 0x2A72},
          {"apparent_wind_direction", 0x2A73},
          {"gust_factor", 0x2A74},
          {"pollen_concentration", 0x2A75},
          {"uv_index", 0x2A76},
          {"irradiance", 0x2A77},
          {"rainfall", 0x2A78},
          {"wind_chill", 0x2A79},
          {"heat_index", 0x2A7A},
          {"dew_point", 0x2A7B},
          {"descriptor_value_changed", 0x2A7D},
          {"aerobic_heart_rate_lower_limit", 0x2A7E},
          {"aerobic_threshold", 0x2A7F},
          {"age", 0x2A80},
          {"anaerobic_heart_rate_lower_limit", 0x2A81},
          {"anaerobic_heart_rate_upper_limit", 0x2A82},
          {"anaerobic_threshold", 0x2A83},
          {"aerobic_heart_rate_upper_limit", 0x2A84},
          {"date_of_birth", 0x2A85},
          {"date_of_threshold_assessment", 0x2A86},
          {"email_address", 0x2A87},
          {"fat_burn_heart_rate_lower_limit", 0x2A88},
          {"fat_burn_heart_rate_upper_limit", 0x2A89},
          {"first_name", 0x2A8A},
          {"five_zone_heart_rate_limits", 0x2A8B},
          {"gender", 0x2A8C},
          {"heart_rate_max", 0x2A8D},
          {"height", 0x2A8E},
          {"hip_circumference", 0x2A8F},
          {"last_name", 0x2A90},
          {"maximum_recommended_heart_rate", 0x2A91},
          {"resting_heart_rate", 0x2A92},
          {"sport_type_for_aerobic_and_anaerobic_thresholds", 0x2A93},
          {"three_zone_heart_rate_limits", 0x2A94},
          {"two_zone_heart_rate_limit", 0x2A95},
          {"vo2_max", 0x2A96},
          {"waist_circumference", 0x2A97},
          {"weight", 0x2A98},
          {"database_change_increment", 0x2A99},
          {"user_index", 0x2A9A},
          {"body_composition_feature", 0x2A9B},
          {"body_composition_measurement", 0x2A9C},
          {"weight_measurement", 0x2A9D},
          {"weight_scale_feature", 0x2A9E},
          {"user_control_point", 0x2A9F},
          {"magnetic_flux_density_2D", 0x2AA0},
          {"magnetic_flux_density_3D", 0x2AA1},
          {"language", 0x2AA2},
          {"barometric_pressure_trend", 0x2AA3},
          {"bond_management_control_point", 0x2AA4},
          {"bond_management_feature", 0x2AA5},
          {"gap.central_address_resolution_support", 0x2AA6},
          {"cgm_measurement", 0x2AA7},
          {"cgm_feature", 0x2AA8},
          {"cgm_status", 0x2AA9},
          {"cgm_session_start_time", 0x2AAA},
          {"cgm_session_run_time", 0x2AAB},
          {"cgm_specific_ops_control_point", 0x2AAC},
          {"indoor_positioning_configuration", 0x2AAD},
          {"latitude", 0x2AAE},
          {"longitude", 0x2AAF},
          {"local_north_coordinate", 0x2AB0},
          {"local_east_coordinate.xml", 0x2AB1},
          {"floor_number", 0x2AB2},
          {"altitude", 0x2AB3},
          {"uncertainty", 0x2AB4},
          {"location_name", 0x2AB5},
          {"uri", 0x2AB6},
          {"http_headers", 0x2AB7},
          {"http_status_code", 0x2AB8},
          {"http_entity_body", 0x2AB9},
          {"http_control_point", 0x2ABA},
          {"https_security", 0x2ABB},
          {"tds_control_point", 0x2ABC},
          {"ots_feature", 0x2ABD},
          {"object_name", 0x2ABE},
          {"object_type", 0x2ABF},
          {"object_size", 0x2AC0},
          {"object_first_created", 0x2AC1},
          {"object_last_modified", 0x2AC2},
          {"object_id", 0x2AC3},
          {"object_properties", 0x2AC4},
          {"object_action_control_point", 0x2AC5},
          {"object_list_control_point", 0x2AC6},
          {"object_list_filter", 0x2AC7},
          {"object_changed", 0x2AC8},
          {"resolvable_private_address_only", 0x2AC9},
          {"fitness_machine_feature", 0x2ACC},
          {"treadmill_data", 0x2ACD},
          {"cross_trainer_data", 0x2ACE},
          {"step_climber_data", 0x2ACF},
          {"stair_climber_data", 0x2AD0},
          {"rower_data", 0x2AD1},
          {"indoor_bike_data", 0x2AD2},
          {"training_status", 0x2AD3},
          {"supported_speed_range", 0x2AD4},
          {"supported_inclination_range", 0x2AD5},
          {"supported_resistance_level_range", 0x2AD6},
          {"supported_heart_rate_range", 0x2AD7},
          {"supported_power_range", 0x2AD8},
          {"fitness_machine_control_point", 0x2AD9},
          {"fitness_machine_status", 0x2ADA},
          {"date_utc", 0x2AED},
      }));

  return &characteristics_map;
}

NameToAssignedNumberMap* GetAssignedNumberForDescriptorNameMap() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      NameToAssignedNumberMap, descriptors_map,
      ({
          // https://www.bluetooth.com/specifications/gatt/descriptors
          {"gatt.characteristic_extended_properties", 0x2900},
          {"gatt.characteristic_user_description", 0x2901},
          {"gatt.client_characteristic_configuration", 0x2902},
          {"gatt.server_characteristic_configuration", 0x2903},
          {"gatt.characteristic_presentation_format", 0x2904},
          {"gatt.characteristic_aggregate_format", 0x2905},
          {"valid_range", 0x2906},
          {"external_report_reference", 0x2907},
          {"report_reference", 0x2908},
          {"number_of_digitals", 0x2909},
          {"value_trigger_setting", 0x290A},
          {"es_configuration", 0x290B},
          {"es_measurement", 0x290C},
          {"es_trigger_setting", 0x290D},
          {"time_trigger_setting", 0x290E},
      }));

  return &descriptors_map;
}

String GetUUIDFromV8Value(const V8UnionStringOrUnsignedLong* value) {
  // unsigned long values interpret as 16-bit UUID values as per
  // https://btprodspecificationrefs.blob.core.windows.net/assigned-values/16-bit%20UUID%20Numbers%20Document.pdf.
  if (value->IsUnsignedLong()) {
    return blink::BluetoothUUID::canonicalUUID(value->GetAsUnsignedLong());
  }

  return value->GetAsString();
}

String GetUUIDForGATTAttribute(GATTAttribute attribute,
                               const V8UnionStringOrUnsignedLong* name,
                               ExceptionState& exception_state) {
  DCHECK(name);
  // Implementation of BluetoothUUID.getService, BluetoothUUID.getCharacteristic
  // and BluetoothUUID.getDescriptor algorithms:
  // https://webbluetoothcg.github.io/web-bluetooth/#dom-bluetoothuuid-getservice
  // https://webbluetoothcg.github.io/web-bluetooth/#dom-bluetoothuuid-getcharacteristic
  // https://webbluetoothcg.github.io/web-bluetooth/#dom-bluetoothuuid-getdescriptor

  const String name_str = GetUUIDFromV8Value(name);
  if (WTF::IsValidUUID(name_str))
    return name_str;

  // If name is in the corresponding attribute map return
  // BluetoothUUID.canonicalUUID(alias).
  NameToAssignedNumberMap* map = nullptr;
  const char* attribute_type = nullptr;
  switch (attribute) {
    case GATTAttribute::kService:
      map = GetAssignedNumberToServiceNameMap();
      attribute_type = "Service";
      break;
    case GATTAttribute::kCharacteristic:
      map = GetAssignedNumberForCharacteristicNameMap();
      attribute_type = "Characteristic";
      break;
    case GATTAttribute::kDescriptor:
      map = GetAssignedNumberForDescriptorNameMap();
      attribute_type = "Descriptor";
      break;
  }

  if (map->Contains(name_str))
    return BluetoothUUID::canonicalUUID(map->at(name_str));

  StringBuilder error_message;
  error_message.Append("Invalid ");
  error_message.Append(attribute_type);
  error_message.Append(" name: '");
  error_message.Append(name_str);
  error_message.Append(
      "'. It must be a valid UUID alias (e.g. 0x1234), "
      "UUID (lowercase hex characters e.g. "
      "'00001234-0000-1000-8000-00805f9b34fb'), "
      "or recognized standard name from ");
  switch (attribute) {
    case GATTAttribute::kService:
      error_message.Append(
          "https://www.bluetooth.com/specifications/gatt/services"
          " e.g. 'alert_notification'.");
      break;
    case GATTAttribute::kCharacteristic:
      error_message.Append(
          "https://www.bluetooth.com/specifications/gatt/characteristics"
          " e.g. 'aerobic_heart_rate_lower_limit'.");
      break;
    case GATTAttribute::kDescriptor:
      error_message.Append(
          "https://www.bluetooth.com/specifications/gatt/descriptors"
          " e.g. 'gatt.characteristic_presentation_format'.");
      break;
  }
  // Otherwise, throw a TypeError.
  exception_state.ThrowTypeError(error_message.ToString());
  return String();
}

}  // namespace

String GetBluetoothUUIDFromV8Value(const V8UnionStringOrUnsignedLong* value) {
  const String value_str = GetUUIDFromV8Value(value);
  return WTF::IsValidUUID(value_str) ? value_str : "";
}

// static
String BluetoothUUID::getService(const V8BluetoothServiceUUID* name,
                                 ExceptionState& exception_state) {
  return GetUUIDForGATTAttribute(GATTAttribute::kService, name,
                                 exception_state);
}

// static
String BluetoothUUID::getCharacteristic(
    const V8BluetoothCharacteristicUUID* name,
    ExceptionState& exception_state) {
  return GetUUIDForGATTAttribute(GATTAttribute::kCharacteristic, name,
                                 exception_state);
}

// static
String BluetoothUUID::getDescriptor(const V8BluetoothDescriptorUUID* name,
                                    ExceptionState& exception_state) {
  return GetUUIDForGATTAttribute(GATTAttribute::kDescriptor, name,
                                 exception_state);
}

// static
String BluetoothUUID::canonicalUUID(unsigned alias) {
  return String::Format("%08x-0000-1000-8000-00805f9b34fb", alias);
}

}  // namespace blink
```