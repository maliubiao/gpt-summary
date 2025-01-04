Response:
Let's break down the thought process for analyzing this C++ file and generating the detailed response.

**1. Initial Understanding of the File's Purpose:**

The filename `navigator_managed_data.cc` and the namespace `blink::modules::managed_device` immediately suggest this code is related to providing managed device information within the Blink rendering engine. The "navigator" part hints at its integration with the JavaScript `navigator` object.

**2. Core Functionality Identification - Reading the Code Top-Down:**

* **Includes:**  The included headers give clues:
    * `navigator_managed_data.h`:  The corresponding header file, likely defining the class interface.
    * `browser_interface_broker_proxy.h`:  Indicates interaction with the browser process, suggesting data retrieval from outside the rendering process.
    * `script_promise_resolver.h`:  Confirms asynchronous operations and interaction with JavaScript Promises.
    * `dom_exception.h`:  Shows error handling.
    * `event.h`, `execution_context.h`, `local_dom_window.h`, `navigator.h`, `console_message.h`, `event_target_modules.h`: These connect the functionality to the DOM, JavaScript execution, and event handling within the browser.

* **Constants:**  The `kNotHighTrustedAppExceptionMessage`, `kServiceConnectionExceptionMessage`, and `kManagedConfigNotSupported` constants point to specific error conditions and constraints. The "managed apps" wording is key.

* **`NavigatorManagedData::managed(Navigator& navigator)`:** This static function is a classic "supplement" pattern in Blink. It ensures there's a single `NavigatorManagedData` instance associated with a `Navigator` object. This is a crucial entry point.

* **Constructor:**  The constructor initializes members like `device_api_service_`, `managed_configuration_service_`, and `configuration_observer_`. These strongly suggest interaction with platform services for device information and configuration.

* **`GetService()` and `GetManagedConfigurationService()`:**  These methods are responsible for obtaining interfaces to browser-side services using `BrowserInterfaceBroker`. The disconnect handlers are also important for handling service errors.

* **Public Methods (starting with `getManagedConfiguration`, `getDirectoryId`, etc.):** These are the main entry points callable from JavaScript. They all follow a similar pattern:
    1. Create a `ScriptPromiseResolver`.
    2. Store the resolver in `pending_promises_`.
    3. Obtain the relevant service interface.
    4. Call the service method asynchronously, providing a callback.
    5. Return the Promise.

* **Callback Methods (`OnConfigurationReceived`, `OnAttributeReceived`):**  These handle the results from the asynchronous service calls, resolving or rejecting the Promises.

* **Event Handling (`AddedEventListener`, `RemovedEventListener`, `OnConfigurationChanged`):**  This shows support for the `managedconfigurationchange` event, indicating that web pages can react to changes in managed configuration.

* **Platform-Specific Logic (`#if BUILDFLAG(IS_ANDROID)`):** The code explicitly handles Android differently, indicating that managed configuration might not be supported or implemented in the same way on that platform.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The presence of Promises, event handling (`managedconfigurationchange`), and the `Navigator` object strongly indicate a JavaScript API. The function names (`getManagedConfiguration`, `getDirectoryId`, etc.) suggest properties that would be accessible via `navigator.managed`.

* **JavaScript:**  The most direct connection. The methods become available as properties/functions on `navigator.managed`.

* **HTML:**  HTML itself doesn't directly interact with this API. The API is exposed to JavaScript running within an HTML page.

* **CSS:** CSS has no direct relationship with this API.

**4. Logical Reasoning and Examples:**

By examining the method signatures and the error messages, logical deductions can be made:

* **Input to `getManagedConfiguration`:** An array of strings (keys).
* **Output of `getManagedConfiguration`:** A Promise resolving to an object where keys are the requested keys and values are the corresponding configuration values (as strings).
* **Input to `getDirectoryId`, etc.:**  No input parameters.
* **Output of `getDirectoryId`, etc.:**  A Promise resolving to a string or null.

**5. User and Programming Errors:**

The error messages (`kNotHighTrustedAppExceptionMessage`, `kServiceConnectionExceptionMessage`, `kManagedConfigNotSupported`) provide clues about common errors. The fact that it's for "managed apps" is crucial.

**6. Debugging Clues and User Operations:**

To reach this code, a web page would need to:

1. Be running within a "managed" environment (e.g., a managed Chrome browser on a corporate device).
2. Access the `navigator.managed` property (which this code provides).
3. Call one of the methods like `navigator.managed.getManagedConfiguration(['key1', 'key2'])`.
4. Potentially register an event listener for `managedconfigurationchange`.

**7. Structuring the Response:**

The information is then organized into logical sections: functionality, relationship to web technologies, examples, errors, and debugging steps. The use of code blocks and bullet points enhances readability. Emphasis is placed on connecting the C++ implementation to the JavaScript API it exposes.

This systematic approach, starting with understanding the overall purpose and then diving into the details of the code, combined with knowledge of web technologies and common programming patterns, allows for a comprehensive analysis of the provided source code.
这个文件 `navigator_managed_data.cc` 是 Chromium Blink 引擎的一部分，它为 JavaScript 提供了访问**受管理设备数据**的能力。 简单来说，它允许在受管理的设备上运行的 Web 应用获取一些关于设备及其配置的信息。

以下是该文件的主要功能：

**1. 提供 JavaScript API：**

*   它实现了 `NavigatorManagedData` 类，该类作为 `Navigator` 接口的扩展 (Supplement)。这意味着通过 `window.navigator.managed` (在 JavaScript 中)，Web 应用可以访问该类提供的方法。
*   它提供了以下 JavaScript 方法（对应 C++ 中的方法）：
    *   `getManagedConfiguration(keys)`: 获取指定键的受管理配置数据。返回一个 Promise，resolve 的结果是一个包含键值对的对象。
    *   `getDirectoryId()`: 获取设备的目录 ID。返回一个 Promise，resolve 的结果是一个字符串或 null。
    *   `getHostname()`: 获取设备的主机名。返回一个 Promise，resolve 的结果是一个字符串或 null。
    *   `getSerialNumber()`: 获取设备的序列号。返回一个 Promise，resolve 的结果是一个字符串或 null。
    *   `getAnnotatedAssetId()`: 获取设备带注释的资产 ID。返回一个 Promise，resolve 的结果是一个字符串或 null。
    *   `getAnnotatedLocation()`: 获取设备带注释的位置信息。返回一个 Promise，resolve 的结果是一个字符串或 null。

**2. 与浏览器进程通信：**

*   它使用 `BrowserInterfaceBroker` 与浏览器进程（Browser Process）中的 `DeviceAPIService` 和 `ManagedConfigurationService` 进行通信。
*   `DeviceAPIService` 负责提供设备的各种属性，如目录 ID、主机名、序列号等。
*   `ManagedConfigurationService` 负责提供设备上配置的受管理数据。

**3. 异步操作和 Promises：**

*   所有提供给 JavaScript 的方法都返回 `Promise` 对象，因为获取设备信息或配置数据通常是异步操作。
*   它使用 `ScriptPromiseResolver` 来管理 Promise 的 resolve 和 reject。

**4. 事件处理：**

*   它支持 `managedconfigurationchange` 事件。当受管理配置发生更改时，会触发此事件。
*   它使用 `ConfigurationObserver` 来监听配置更改。

**5. 平台特定处理：**

*   在 Android 平台上，受管理配置 API 可能不受支持，代码中对此进行了处理，并在控制台中输出警告信息。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件主要与 **JavaScript** 功能相关。它扩展了 JavaScript 的 `Navigator` 对象，使得 Web 开发者可以使用 JavaScript 代码来访问受管理设备的信息。

*   **JavaScript 举例:**

    ```javascript
    // 获取所有受管理配置
    navigator.managed.getManagedConfiguration([]).then(config => {
      console.log('Managed Configuration:', config);
      // config 的结构可能类似于: { "key1": "value1", "key2": 123 }
    }).catch(error => {
      console.error('Failed to get managed configuration:', error);
    });

    // 获取特定键的受管理配置
    navigator.managed.getManagedConfiguration(['theme']).then(config => {
      console.log('Theme:', config.theme);
    });

    // 获取设备目录 ID
    navigator.managed.getDirectoryId().then(directoryId => {
      console.log('Directory ID:', directoryId);
    });

    // 监听受管理配置更改事件
    navigator.managed.addEventListener('managedconfigurationchange', () => {
      console.log('Managed configuration has changed!');
      // 重新获取配置或执行相应的操作
    });
    ```

*   **HTML 和 CSS 关系：**

    HTML 和 CSS 本身不直接与 `navigator_managed_data.cc` 提供的功能交互。但是，通过 JavaScript 获取到的受管理设备数据可以用来动态地改变 HTML 结构或 CSS 样式，从而实现与设备管理策略相关的用户界面定制。

    *   **举例:** 假设受管理配置中包含一个名为 "theme" 的键，其值为 "dark" 或 "light"。JavaScript 代码可以根据这个值来动态切换页面的 CSS 样式表：

        ```javascript
        navigator.managed.getManagedConfiguration(['theme']).then(config => {
          if (config && config.theme === 'dark') {
            document.body.classList.add('dark-theme');
          } else {
            document.body.classList.remove('dark-theme');
          }
        });
        ```

        ```css
        /* 默认主题样式 */
        body {
          background-color: white;
          color: black;
        }

        /* 深色主题样式 */
        body.dark-theme {
          background-color: black;
          color: white;
        }
        ```

**逻辑推理的假设输入与输出：**

**假设输入 (JavaScript 调用):**

*   `navigator.managed.getManagedConfiguration(['app_lock_enabled', 'allowed_urls'])`

**假设输出 (Promise resolve 的结果):**

*   如果设备是受管理的，且配置中存在这两个键，输出可能如下：
    ```json
    {
      "app_lock_enabled": "true",
      "allowed_urls": "https://example.com,https://another.com"
    }
    ```
*   如果设备不是受管理的，Promise 会被 reject，并抛出 `DOMException`，错误消息为 "Managed configuration is empty. This API is available only for managed apps."
*   如果与浏览器进程的连接出现问题，Promise 会被 reject，并抛出 `DOMException`，错误消息为 "Service connection error. This API is available only for managed apps."
*   如果在 Android 平台上调用 `getManagedConfiguration`，Promise 会被 reject，并抛出 `DOMException`，错误消息为 "Managed Configuration API is not supported on this platform."

**用户或编程常见的使用错误及举例说明：**

1. **在非受管理设备上使用 API：**
    *   **错误:**  在未注册到企业管理系统的设备上调用 `navigator.managed.getManagedConfiguration()` 等方法。
    *   **现象:**  Promise 会被 reject，并抛出错误，指示该 API 仅适用于受管理的应用。
    *   **避免:**  在调用这些 API 之前，可以尝试检查 `navigator.managed` 对象是否存在，但这并不能完全保证设备是受管理的。更可靠的方式是捕获 Promise 的 rejection 并处理错误。

2. **请求不存在的配置键：**
    *   **错误:**  调用 `navigator.managed.getManagedConfiguration(['non_existent_key'])` 请求一个在受管理配置中不存在的键。
    *   **现象:**  Promise 会成功 resolve，但是返回的配置对象中不会包含该键。
    *   **避免:**  开发者需要了解受管理配置中可用的键。

3. **在 Android 平台上使用 `getManagedConfiguration`：**
    *   **错误:**  在 Android 设备上调用 `navigator.managed.getManagedConfiguration()`。
    *   **现象:**  Promise 会被 reject，并抛出错误，指示该 API 在此平台上不受支持。
    *   **避免:**  在 Android 平台上使用此 API 之前，需要进行平台检查。

4. **忘记处理 Promise 的 rejection：**
    *   **错误:**  调用 `navigator.managed.getManagedConfiguration()` 但没有 `.catch()` 处理 Promise 可能被 reject 的情况。
    *   **现象:**  如果 API 调用失败（例如，设备未受管理），可能会导致未捕获的错误。
    *   **避免:**  始终为返回 Promise 的方法添加 `.then()` 和 `.catch()` 来处理成功和失败的情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户使用的是一个受管理的设备。** 这意味着设备可能由企业或组织管理，并安装了相应的管理策略。
2. **用户打开了一个网页应用。** 这个网页应用可能由管理员部署，或者用户访问了一个需要访问受管理设备信息的网页。
3. **网页应用的 JavaScript 代码尝试访问 `window.navigator.managed` 对象。**
4. **网页应用调用了 `navigator.managed` 对象上的方法，例如 `getManagedConfiguration()`。**
5. **Blink 引擎的 JavaScript 绑定代码会将这个 JavaScript 调用路由到 `NavigatorManagedData` 类的相应方法 (`GetManagedConfiguration`)。**
6. **`GetManagedConfiguration` 方法会创建一个 `ScriptPromiseResolver`，并异步地通过 `ManagedConfigurationService` 向浏览器进程请求受管理配置数据。**
7. **浏览器进程处理请求，并返回配置数据或错误信息。**
8. **`NavigatorManagedData::OnConfigurationReceived` 方法接收到来自浏览器进程的结果，并根据结果 resolve 或 reject 之前创建的 Promise。**
9. **JavaScript 代码中的 `.then()` 或 `.catch()` 回调函数会被执行，处理返回的数据或错误。**

**调试线索：**

*   **检查 `navigator.managed` 对象是否存在。** 如果不存在，说明当前上下文可能不支持此 API，或者代码运行在非受管理设备上。
*   **查看控制台错误信息。** 如果 Promise 被 reject，控制台会显示相应的错误消息，这有助于诊断问题（例如，设备未受管理，服务连接错误，平台不支持）。
*   **使用 Chrome 的开发者工具进行断点调试。** 可以在 `NavigatorManagedData` 类的方法中设置断点，例如 `GetManagedConfiguration`，`OnConfigurationReceived` 等，来跟踪代码执行流程，查看变量的值，以及确认是否成功与浏览器进程通信。
*   **检查浏览器进程的日志。**  如果怀疑是与浏览器进程通信的问题，可以查看浏览器进程的日志，看是否有相关的错误或警告信息。
*   **确认设备是否真的处于受管理状态。** 可以通过操作系统的设置或设备管理工具来确认设备是否已注册到管理系统。

总而言之，`navigator_managed_data.cc` 是 Blink 引擎中一个关键的组件，它桥接了 Web 应用和底层的设备管理功能，使得受管理的 Web 应用能够安全地访问设备特定的信息和配置。

Prompt: 
```
这是目录为blink/renderer/modules/managed_device/navigator_managed_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/managed_device/navigator_managed_data.h"

#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"

namespace blink {

namespace {

const char kNotHighTrustedAppExceptionMessage[] =
    "Managed configuration is empty. This API is available only for "
    "managed apps.";
const char kServiceConnectionExceptionMessage[] =
    "Service connection error. This API is available only for managed apps.";

#if BUILDFLAG(IS_ANDROID)
const char kManagedConfigNotSupported[] =
    "Managed Configuration API is not supported on this platform.";
#endif  // BUILDFLAG(IS_ANDROID)

}  // namespace

const char NavigatorManagedData::kSupplementName[] = "NavigatorManagedData";

NavigatorManagedData* NavigatorManagedData::managed(Navigator& navigator) {
  if (!navigator.DomWindow())
    return nullptr;

  NavigatorManagedData* device_service =
      Supplement<Navigator>::From<NavigatorManagedData>(navigator);
  if (!device_service) {
    device_service = MakeGarbageCollected<NavigatorManagedData>(navigator);
    ProvideTo(navigator, device_service);
  }
  return device_service;
}

NavigatorManagedData::NavigatorManagedData(Navigator& navigator)
    : ActiveScriptWrappable<NavigatorManagedData>({}),
      Supplement<Navigator>(navigator),
      device_api_service_(navigator.DomWindow()),
      managed_configuration_service_(navigator.DomWindow()),
      configuration_observer_(this, navigator.DomWindow()) {}

const AtomicString& NavigatorManagedData::InterfaceName() const {
  return event_target_names::kNavigatorManagedData;
}

ExecutionContext* NavigatorManagedData::GetExecutionContext() const {
  return GetSupplementable()->DomWindow();
}

bool NavigatorManagedData::HasPendingActivity() const {
  // Prevents garbage collecting of this object when not hold by another
  // object but still has listeners registered.
  return !pending_promises_.empty() || HasEventListeners();
}

void NavigatorManagedData::Trace(Visitor* visitor) const {
  EventTarget::Trace(visitor);
  ActiveScriptWrappable::Trace(visitor);
  Supplement<Navigator>::Trace(visitor);

  visitor->Trace(device_api_service_);
  visitor->Trace(managed_configuration_service_);
  visitor->Trace(pending_promises_);
  visitor->Trace(configuration_observer_);
}

mojom::blink::DeviceAPIService* NavigatorManagedData::GetService() {
  if (!device_api_service_.is_bound()) {
    GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
        device_api_service_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI)));
    // The access status of Device API can change dynamically. Hence, we have to
    // properly handle cases when we are losing this access.
    device_api_service_.set_disconnect_handler(
        WTF::BindOnce(&NavigatorManagedData::OnServiceConnectionError,
                      WrapWeakPersistent(this)));
  }

  return device_api_service_.get();
}

#if !BUILDFLAG(IS_ANDROID)
mojom::blink::ManagedConfigurationService*
NavigatorManagedData::GetManagedConfigurationService() {
  if (!managed_configuration_service_.is_bound()) {
    GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
        managed_configuration_service_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI)));
    // The access status of Device API can change dynamically. Hence, we have to
    // properly handle cases when we are losing this access.
    managed_configuration_service_.set_disconnect_handler(
        WTF::BindOnce(&NavigatorManagedData::OnServiceConnectionError,
                      WrapWeakPersistent(this)));
  }

  return managed_configuration_service_.get();
}
#endif  // !BUILDFLAG(IS_ANDROID)

void NavigatorManagedData::OnServiceConnectionError() {
  device_api_service_.reset();

  // We should reset managed configuration service only it actually got
  // disconnected.
  if (managed_configuration_service_.is_bound() &&
      !managed_configuration_service_.is_connected()) {
    managed_configuration_service_.reset();
  }

  // Resolve all pending promises with a failure.
  for (ScriptPromiseResolverBase* resolver : pending_promises_) {
    resolver->Reject(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kNotAllowedError,
                                           kServiceConnectionExceptionMessage));
  }
}

ScriptPromise<IDLRecord<IDLString, IDLAny>>
NavigatorManagedData::getManagedConfiguration(ScriptState* script_state,
                                              Vector<String> keys) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLRecord<IDLString, IDLAny>>>(
          script_state);
  pending_promises_.insert(resolver);

  auto promise = resolver->Promise();
  if (!GetExecutionContext()) {
    return promise;
  }
#if !BUILDFLAG(IS_ANDROID)
  GetManagedConfigurationService()->GetManagedConfiguration(
      keys, WTF::BindOnce(&NavigatorManagedData::OnConfigurationReceived,
                          WrapWeakPersistent(this), WrapPersistent(resolver)));
#else
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, kManagedConfigNotSupported));
#endif  // !BUILDFLAG(IS_ANDROID)

  return promise;
}

ScriptPromise<IDLNullable<IDLString>> NavigatorManagedData::getDirectoryId(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<IDLString>>>(
          script_state);
  pending_promises_.insert(resolver);

  auto promise = resolver->Promise();
  if (!GetExecutionContext()) {
    return promise;
  }
  GetService()->GetDirectoryId(WTF::BindOnce(
      &NavigatorManagedData::OnAttributeReceived, WrapWeakPersistent(this),
      WrapPersistent(script_state), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLNullable<IDLString>> NavigatorManagedData::getHostname(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<IDLString>>>(
          script_state);
  pending_promises_.insert(resolver);

  auto promise = resolver->Promise();
  if (!GetExecutionContext()) {
    return promise;
  }
  GetService()->GetHostname(WTF::BindOnce(
      &NavigatorManagedData::OnAttributeReceived, WrapWeakPersistent(this),
      WrapPersistent(script_state), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLNullable<IDLString>> NavigatorManagedData::getSerialNumber(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<IDLString>>>(
          script_state);
  pending_promises_.insert(resolver);

  auto promise = resolver->Promise();
  if (!GetExecutionContext()) {
    return promise;
  }
  GetService()->GetSerialNumber(WTF::BindOnce(
      &NavigatorManagedData::OnAttributeReceived, WrapWeakPersistent(this),
      WrapPersistent(script_state), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLNullable<IDLString>> NavigatorManagedData::getAnnotatedAssetId(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<IDLString>>>(
          script_state);
  pending_promises_.insert(resolver);

  auto promise = resolver->Promise();
  if (!GetExecutionContext()) {
    return promise;
  }
  GetService()->GetAnnotatedAssetId(WTF::BindOnce(
      &NavigatorManagedData::OnAttributeReceived, WrapWeakPersistent(this),
      WrapPersistent(script_state), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLNullable<IDLString>>
NavigatorManagedData::getAnnotatedLocation(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLNullable<IDLString>>>(
          script_state);
  pending_promises_.insert(resolver);

  auto promise = resolver->Promise();
  if (!GetExecutionContext()) {
    return promise;
  }
  GetService()->GetAnnotatedLocation(WTF::BindOnce(
      &NavigatorManagedData::OnAttributeReceived, WrapWeakPersistent(this),
      WrapPersistent(script_state), WrapPersistent(resolver)));
  return promise;
}

void NavigatorManagedData::OnConfigurationReceived(
    ScriptPromiseResolver<IDLRecord<IDLString, IDLAny>>* resolver,
    const std::optional<HashMap<String, String>>& configurations) {
  pending_promises_.erase(resolver);

  ScriptState* script_state = resolver->GetScriptState();
  ScriptState::Scope scope(script_state);

  if (!configurations.has_value()) {
    resolver->Reject(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kNotAllowedError,
                                           kNotHighTrustedAppExceptionMessage));
    return;
  }

  HeapVector<std::pair<String, ScriptValue>> result;
  for (const auto& config_pair : *configurations) {
    v8::Local<v8::Value> v8_object =
        FromJSONString(script_state, config_pair.value);
    if (!v8_object.IsEmpty()) {
      result.emplace_back(config_pair.key,
                          ScriptValue(script_state->GetIsolate(), v8_object));
    }
  }
  resolver->Resolve(result);
}

void NavigatorManagedData::OnAttributeReceived(
    ScriptState* script_state,
    ScriptPromiseResolver<IDLNullable<IDLString>>* resolver,
    mojom::blink::DeviceAttributeResultPtr result) {
  pending_promises_.erase(resolver);

  if (result->is_error_message()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError, result->get_error_message()));
  } else {
    resolver->Resolve(result->get_attribute());
  }
}

void NavigatorManagedData::OnConfigurationChanged() {
  DispatchEvent(*Event::Create(event_type_names::kManagedconfigurationchange));
}

void NavigatorManagedData::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  if (!GetExecutionContext()) {
    return;
  }

  EventTarget::AddedEventListener(event_type, registered_listener);
#if !BUILDFLAG(IS_ANDROID)
  if (event_type == event_type_names::kManagedconfigurationchange) {
    if (!configuration_observer_.is_bound()) {
      GetManagedConfigurationService()->SubscribeToManagedConfiguration(
          configuration_observer_.BindNewPipeAndPassRemote(
              GetExecutionContext()->GetTaskRunner(
                  TaskType::kMiscPlatformAPI)));
    }
  }
#else
  GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kOther,
      mojom::blink::ConsoleMessageLevel::kWarning, kManagedConfigNotSupported));
#endif  // !BUILDFLAG(IS_ANDROID)
}

void NavigatorManagedData::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  EventTarget::RemovedEventListener(event_type, registered_listener);
  if (!HasEventListeners())
    StopObserving();
}

void NavigatorManagedData::StopObserving() {
  if (!configuration_observer_.is_bound())
    return;
  configuration_observer_.reset();
}

}  // namespace blink

"""

```