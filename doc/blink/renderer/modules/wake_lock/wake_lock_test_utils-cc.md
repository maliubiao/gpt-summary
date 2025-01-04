Response:
Let's break down the thought process to analyze the provided C++ code.

**1. Understanding the Core Task:**

The initial prompt asks for the functionality of `wake_lock_test_utils.cc` within the Chromium Blink engine. The key is to recognize the "test_utils" part, indicating this file provides utilities specifically for *testing* Wake Lock functionality.

**2. Identifying Key Components and Their Roles:**

* **Headers:**  The `#include` directives are a good starting point. They reveal dependencies on base libraries (like `base/run_loop.h`), Mojo bindings (`mojo/public/cpp/bindings/`), Blink core classes (`third_party/blink/renderer/core/...`), and the specific Wake Lock module (`third_party/blink/renderer/modules/wake_lock/...`). This suggests the file interacts with the Wake Lock API at a lower level.
* **Namespaces:**  The `namespace blink` is obvious. The anonymous namespace `namespace { ... }` suggests helper functions that are only used within this file.
* **Classes:** The prominent classes are `MockWakeLock`, `MockWakeLockService`, `MockPermissionService`, and `WakeLockTestingContext`. The "Mock" prefix strongly indicates these are for testing purposes, simulating real implementations.
* **Helper Functions:** Functions like `RunWithStack`, `ClosureOnResolve`, `ClosureOnReject`, and `ToBlinkWakeLockType` are present. Their names hint at their specific uses.

**3. Analyzing Individual Components (Iterative Process):**

* **`RunWithStack`:**  This simply runs a `base::RunLoop`. This immediately suggests asynchronous operations and waiting for events.
* **`ClosureOnResolve`/`ClosureOnReject`:**  These classes inherit from `ThenCallable`. This is a strong indicator they're involved in handling promises, specifically success and failure callbacks. The `base::OnceClosure` member further confirms this asynchronous, one-time execution behavior.
* **`ToBlinkWakeLockType`:** This function clearly translates between different `WakeLockType` enums, likely from a Mojo interface to an internal Blink representation.
* **`MockWakeLock`:**
    * `Bind`:  Connects the mock to a Mojo receiver.
    * `Unbind`: Disconnects the mock.
    * `WaitForRequest`/`WaitForCancelation`: These are *critical*. They involve a `base::RunLoop` and callbacks. This confirms the utility's role in controlling the timing and flow of Wake Lock requests and releases during tests. The "WaitFor" naming is a clear indication of synchronization for testing.
    * `RequestWakeLock`/`CancelWakeLock`: These simulate the actions of acquiring and releasing a wake lock.
    * Other methods (`AddClient`, `ChangeType`, `HasWakeLockForTests`): These are likely implementations of the `device::mojom::blink::WakeLock` interface, but the mock implementation doesn't have any complex logic.
* **`MockWakeLockService`:**
    * `BindRequest`:  Handles binding of the Wake Lock Service interface.
    * `get_wake_lock`:  Provides access to the internal `MockWakeLock` instances.
    * `GetWakeLock`:  Simulates the Wake Lock Service receiving a request, creating and binding a `MockWakeLock`.
* **`MockPermissionService`:**
    * `BindRequest`:  Handles binding of the Permission Service interface.
    * `SetPermissionResponse`:  Allows setting predefined permission results for tests. This is essential for testing different permission scenarios.
    * `WaitForPermissionRequest`: Similar to `MockWakeLock`, this allows tests to synchronize with permission requests.
    * `HasPermission`/`RequestPermission`: Simulate the permission checking and requesting logic, using the pre-set responses.
    * Other methods: Placeholder or simplified implementations of the Permission Service interface.
* **`WakeLockTestingContext`:** This class acts as a central fixture for setting up the testing environment.
    * Constructor:  It uses `SetBinderForTesting` to replace the real Wake Lock and Permission services with the mock implementations. This is a standard testing technique for isolating components.
    * Destructor: Cleans up the mock bindings.
    * `DomWindow`/`Frame`/`GetScriptState`: Provides access to the relevant Blink environment for tests.
    * `GetPermissionService`: Returns the mock permission service.
    * `WaitForPromiseFulfillment`/`WaitForPromiseRejection`:  Key functions for dealing with asynchronous JavaScript Promises in the testing context. They use `base::RunLoop` and the `ClosureOnResolve`/`ClosureOnReject` helpers. The note about microtasks is important.
* **`ScriptPromiseUtils`:**  Static utility functions for inspecting the state and results of JavaScript Promises.

**4. Connecting to JavaScript/HTML/CSS:**

The key connection point is the `WakeLockTestingContext`. It allows tests to simulate how JavaScript code interacts with the Wake Lock API.

* **JavaScript `navigator.wakeLock.request()`:** The mock services and the `WaitForRequest`/`WaitForCancelation` methods allow tests to verify that when JavaScript calls `navigator.wakeLock.request()`, the corresponding Mojo calls are made and the mock Wake Lock is activated.
* **JavaScript Promise resolution/rejection:** The `WaitForPromiseFulfillment`/`WaitForPromiseRejection` methods are crucial for testing the asynchronous nature of the Wake Lock API and how JavaScript handles successful and failed requests.
* **Permissions:** The `MockPermissionService` allows testing scenarios where permission for wake locks is granted or denied, simulating the browser's permission prompt behavior.

**5. Identifying User/Programming Errors and Debugging:**

The examples provided in the analysis are derived directly from the understanding of the mock objects' roles. For instance, forgetting to call `WaitForRequest` would lead to tests not waiting for the simulated wake lock acquisition. The debugging section connects user actions in the browser to the underlying C++ code flow.

**6. Refining and Structuring the Answer:**

Finally, the information is organized into clear sections like "Functionality," "Relationship with JS/HTML/CSS," "Logical Reasoning," "Common Errors," and "Debugging."  This structure makes the explanation more understandable and accessible. The use of bullet points, code snippets, and clear explanations enhances readability.

By following these steps – understanding the purpose, identifying key components, analyzing their behavior, connecting to the higher-level concepts, and structuring the information effectively – it's possible to arrive at a comprehensive analysis of the given C++ code.
好的，我们来详细分析一下 `blink/renderer/modules/wake_lock/wake_lock_test_utils.cc` 文件的功能。

**文件功能总览**

`wake_lock_test_utils.cc` 文件在 Chromium Blink 渲染引擎中，主要提供了一系列用于测试 Wake Lock API 功能的辅助工具类和函数。由于 Wake Lock API 涉及到与操作系统底层的交互（例如防止屏幕休眠），直接进行单元测试比较困难，因此需要模拟相关的服务和行为。

该文件主要包含以下几个核心组件：

1. **`MockWakeLock` 类:**  模拟 `device::mojom::blink::WakeLock` Mojo 接口。这个类允许测试代码控制 wake lock 的获取和释放，以及等待这些事件发生。
2. **`MockWakeLockService` 类:** 模拟 `mojom::blink::WakeLockService` Mojo 接口。这个类负责接收来自渲染进程的 wake lock 请求，并创建和管理 `MockWakeLock` 实例。
3. **`MockPermissionService` 类:** 模拟 `mojom::blink::PermissionService` Mojo 接口。Wake Lock API 的使用需要权限，这个类允许测试代码设置权限请求的模拟结果（允许或拒绝）。
4. **`WakeLockTestingContext` 类:**  提供一个测试上下文环境，用于设置 mock 服务并与 Blink 的其他组件进行交互，例如 DOM Window 和 ScriptState。
5. **辅助函数:**  例如 `RunWithStack` 用于运行消息循环，`ClosureOnResolve` 和 `ClosureOnReject` 用于处理 Promise 的成功和失败回调，以及类型转换函数。
6. **`ScriptPromiseUtils` 命名空间:** 提供用于检查 JavaScript Promise 状态和结果的静态工具函数。

**与 JavaScript, HTML, CSS 的关系**

该文件提供的工具类主要是为了测试 JavaScript 中 Wake Lock API 的功能。Wake Lock API 允许网页通过 JavaScript 代码请求阻止设备进入屏幕休眠或系统休眠状态。

**举例说明：**

假设有以下 JavaScript 代码：

```javascript
async function requestWakeLock() {
  try {
    const wakeLock = await navigator.wakeLock.request('screen');
    console.log('Wake lock acquired!');

    wakeLock.addEventListener('release', () => {
      console.log('Wake lock was released.');
    });

    // ... 保持 wake lock 激活一段时间 ...

    await wakeLock.release();
  } catch (err) {
    console.error(`Failed to acquire wake lock: ${err.name}, ${err.message}`);
  }
}

requestWakeLock();
```

在这个场景下，`wake_lock_test_utils.cc` 中的 mock 类可以用来测试以下方面：

* **权限请求:** 当 JavaScript 调用 `navigator.wakeLock.request('screen')` 时，`MockPermissionService` 可以模拟权限是否被授予。例如，可以设置 `MockPermissionService` 返回 `GRANTED` 或 `DENIED`，然后测试 JavaScript 代码中 `try...catch` 块的不同行为。
* **Wake Lock 获取:** `MockWakeLockService` 可以捕获到 `navigator.wakeLock.request()` 触发的 Mojo 调用，并创建一个 `MockWakeLock` 实例。`MockWakeLock` 可以模拟 wake lock 的成功获取。
* **Wake Lock 释放:**  当 JavaScript 调用 `wakeLock.release()` 时，`MockWakeLock` 可以模拟 wake lock 的释放，并且测试代码可以验证 'release' 事件是否被触发。
* **Promise 的状态:** `ScriptPromiseUtils` 可以用来检查 `navigator.wakeLock.request()` 返回的 Promise 在不同测试场景下的状态（例如，pending, fulfilled, rejected）。

**逻辑推理（假设输入与输出）**

假设测试代码执行以下操作：

**假设输入:**

1. 测试代码创建 `WakeLockTestingContext` 实例。
2. 测试代码在 `MockPermissionService` 中设置屏幕唤醒锁权限状态为 `GRANTED`。
3. 测试代码执行 JavaScript 代码 `navigator.wakeLock.request('screen')`。

**逻辑推理过程:**

1. `WakeLockTestingContext` 的创建会将真实的 Wake Lock 和 Permission 服务替换为 mock 实现。
2. 当 JavaScript 调用 `navigator.wakeLock.request('screen')` 时，Blink 引擎会向 `mojom::blink::PermissionService` 发起权限请求。
3. 由于使用了 `MockPermissionService`，并且之前设置了权限为 `GRANTED`，mock 服务会返回成功状态。
4. 接着，Blink 引擎会向 `mojom::blink::WakeLockService` 发起获取 wake lock 的请求。
5. `MockWakeLockService` 会接收到请求，并创建一个 `MockWakeLock` 实例。
6. `MockWakeLock` 的 `RequestWakeLock()` 方法会被调用（在 mock 实现中，这通常只是设置一个内部状态）。
7. JavaScript 中的 Promise 会被 resolve，并返回一个 `WakeLockSentinel` 对象。

**可能的输出 (测试断言):**

* 可以断言 `MockPermissionService` 的 `RequestPermission` 方法被调用，并且收到的权限类型是屏幕唤醒锁。
* 可以断言 `MockWakeLockService` 的 `GetWakeLock` 方法被调用。
* 可以断言 `MockWakeLock` 的 `RequestWakeLock` 方法被调用。
* 可以断言 JavaScript 中 `navigator.wakeLock.request('screen')` 返回的 Promise 状态为 `fulfilled`。

**用户或编程常见的使用错误**

使用 Wake Lock API 时，常见的错误以及如何通过测试工具进行验证：

1. **忘记处理权限被拒绝的情况:** 用户可能在浏览器设置中禁用了 Wake Lock 权限。测试代码可以通过 `MockPermissionService` 设置权限为 `DENIED`，然后验证 JavaScript 代码是否正确处理了 Promise 的 rejection。
   * **例子:**  测试代码设置 `permission_service_.SetPermissionResponse(V8WakeLockType::Enum::kScreen, mojom::blink::PermissionStatus::DENIED);`，然后执行请求 wake lock 的 JavaScript，并断言 Promise 被 reject，并且 `catch` 块中的代码被执行。

2. **过早地释放 Wake Lock:**  开发者可能在需要保持唤醒状态时意外地释放了 wake lock。测试代码可以通过在 mock wake lock 被请求后立即调用其 `CancelWakeLock()` 方法来模拟这种情况，并验证 JavaScript 中 'release' 事件是否被触发。
   * **例子:** 在测试中，获取 mock 的 `MockWakeLock` 实例，并在预期的时间点后断言其 `is_acquired_` 状态为 `false`。

3. **在不合适的上下文中请求 Wake Lock:**  例如，在没有用户手势的情况下请求某些类型的 wake lock 可能会失败。测试代码可以模拟不同的用户手势状态，并验证 wake lock 请求是否成功或失败。

**用户操作如何一步步到达这里 (作为调试线索)**

当用户在一个网页上与 Wake Lock API 进行交互时，其操作会触发一系列事件，最终可能会涉及到 `wake_lock_test_utils.cc` 中模拟的服务：

1. **用户访问包含 Wake Lock API 调用的网页。**
2. **JavaScript 代码执行 `navigator.wakeLock.request(type)`。**
3. **浏览器首先检查是否已经有相同类型的 wake lock 激活。**
4. **如果没有，浏览器会检查 Wake Lock 权限状态。**
   * 这会涉及到调用实现了 `mojom::blink::PermissionService` 接口的服务（在测试中是 `MockPermissionService`）。
5. **如果权限被授予，浏览器会向实现了 `mojom::blink::WakeLockService` 接口的服务发起请求。**
   * 在测试环境中，这会调用 `MockWakeLockService` 的 `GetWakeLock` 方法。
6. **`MockWakeLockService` 会创建一个 `MockWakeLock` 实例并绑定 Mojo 接收器。**
7. **`MockWakeLock` 模拟底层系统的 wake lock 获取操作。**
8. **JavaScript 中的 Promise 会根据操作结果 resolve 或 reject。**
9. **如果用户离开页面或脚本调用 `wakeLock.release()`，则会触发 wake lock 的释放流程。**
   * 这会调用 `MockWakeLock` 的 `CancelWakeLock` 方法。

**调试线索:**

* **断点:** 在 `wake_lock_test_utils.cc` 的 `MockWakeLock::RequestWakeLock()`, `MockWakeLock::CancelWakeLock()`, `MockWakeLockService::GetWakeLock()`, `MockPermissionService::RequestPermission()` 等方法中设置断点，可以观察测试过程中这些方法是否被调用，以及调用时的参数。
* **日志:** 在 mock 类的关键方法中添加日志输出，记录 wake lock 的状态变化和权限请求的结果。
* **测试输出:**  仔细分析测试框架提供的输出信息，例如断言失败时的信息，可以帮助定位问题。
* **Mojo Inspector:** 使用 Chromium 的 Mojo Inspector 工具可以查看 Mojo 接口之间的消息传递，有助于理解 Wake Lock API 请求的整个流程。

总而言之，`wake_lock_test_utils.cc` 文件是 Blink 引擎中用于 Wake Lock API 功能测试的关键组成部分，它通过模拟底层服务和行为，使得开发者能够有效地测试 JavaScript 中 Wake Lock API 的各种场景，包括权限处理、wake lock 的获取和释放，以及错误处理等。

Prompt: 
```
这是目录为blink/renderer/modules/wake_lock/wake_lock_test_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/wake_lock/wake_lock_test_utils.h"

#include <tuple>
#include <utility>

#include "base/check.h"
#include "base/notreached.h"
#include "base/run_loop.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_wake_lock_sentinel.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/wake_lock/wake_lock_sentinel.h"
#include "third_party/blink/renderer/modules/wake_lock/wake_lock_type.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/heap_test_utilities.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

using mojom::blink::PermissionDescriptorPtr;

namespace {

void RunWithStack(base::RunLoop* run_loop) {
  run_loop->Run();
}

// Helper classes for WaitForPromise{Fulfillment,Rejection}(). Provides a
// function that invokes |callback| when a ScriptPromise is resolved/rejected.
class ClosureOnResolve final
    : public ThenCallable<WakeLockSentinel, ClosureOnResolve> {
 public:
  explicit ClosureOnResolve(base::OnceClosure callback)
      : callback_(std::move(callback)) {}

  void React(ScriptState*, WakeLockSentinel*) {
    CHECK(callback_);
    std::move(callback_).Run();
  }

 private:
  base::OnceClosure callback_;
};

class ClosureOnReject final : public ThenCallable<IDLAny, ClosureOnReject> {
 public:
  explicit ClosureOnReject(base::OnceClosure callback)
      : callback_(std::move(callback)) {}

  void React(ScriptState*, ScriptValue) {
    CHECK(callback_);
    std::move(callback_).Run();
  }

 private:
  base::OnceClosure callback_;
};

V8WakeLockType::Enum ToBlinkWakeLockType(
    device::mojom::blink::WakeLockType type) {
  switch (type) {
    case device::mojom::blink::WakeLockType::kPreventDisplaySleep:
    case device::mojom::blink::WakeLockType::kPreventDisplaySleepAllowDimming:
      return V8WakeLockType::Enum::kScreen;
    case device::mojom::blink::WakeLockType::kPreventAppSuspension:
      return V8WakeLockType::Enum::kSystem;
  }
}

}  // namespace

// MockWakeLock

MockWakeLock::MockWakeLock() = default;
MockWakeLock::~MockWakeLock() = default;

void MockWakeLock::Bind(
    mojo::PendingReceiver<device::mojom::blink::WakeLock> receiver) {
  DCHECK(!receiver_.is_bound());
  receiver_.Bind(std::move(receiver));
  receiver_.set_disconnect_handler(
      WTF::BindOnce(&MockWakeLock::OnConnectionError, WTF::Unretained(this)));
}

void MockWakeLock::Unbind() {
  OnConnectionError();
}

void MockWakeLock::WaitForRequest() {
  DCHECK(!request_wake_lock_callback_);
  base::RunLoop run_loop;
  request_wake_lock_callback_ = run_loop.QuitClosure();
  RunWithStack(&run_loop);
}

void MockWakeLock::WaitForCancelation() {
  DCHECK(!cancel_wake_lock_callback_);
  if (!receiver_.is_bound()) {
    // If OnConnectionError() has been called, bail out early to avoid waiting
    // forever.
    DCHECK(!is_acquired_);
    return;
  }
  base::RunLoop run_loop;
  cancel_wake_lock_callback_ = run_loop.QuitClosure();
  RunWithStack(&run_loop);
}

void MockWakeLock::OnConnectionError() {
  receiver_.reset();
  CancelWakeLock();
}

void MockWakeLock::RequestWakeLock() {
  is_acquired_ = true;
  if (request_wake_lock_callback_)
    std::move(request_wake_lock_callback_).Run();
}

void MockWakeLock::CancelWakeLock() {
  is_acquired_ = false;
  if (cancel_wake_lock_callback_)
    std::move(cancel_wake_lock_callback_).Run();
}

void MockWakeLock::AddClient(
    mojo::PendingReceiver<device::mojom::blink::WakeLock>) {}
void MockWakeLock::ChangeType(device::mojom::blink::WakeLockType,
                              ChangeTypeCallback) {}
void MockWakeLock::HasWakeLockForTests(HasWakeLockForTestsCallback) {}

// MockWakeLockService

MockWakeLockService::MockWakeLockService() = default;
MockWakeLockService::~MockWakeLockService() = default;

void MockWakeLockService::BindRequest(mojo::ScopedMessagePipeHandle handle) {
  receivers_.Add(this, mojo::PendingReceiver<mojom::blink::WakeLockService>(
                           std::move(handle)));
}

MockWakeLock& MockWakeLockService::get_wake_lock(V8WakeLockType::Enum type) {
  size_t pos = static_cast<size_t>(type);
  return mock_wake_lock_[pos];
}

void MockWakeLockService::GetWakeLock(
    device::mojom::blink::WakeLockType type,
    device::mojom::blink::WakeLockReason reason,
    const String& description,
    mojo::PendingReceiver<device::mojom::blink::WakeLock> receiver) {
  size_t pos = static_cast<size_t>(ToBlinkWakeLockType(type));
  mock_wake_lock_[pos].Bind(std::move(receiver));
}

// MockPermissionService

MockPermissionService::MockPermissionService() = default;
MockPermissionService::~MockPermissionService() = default;

void MockPermissionService::BindRequest(mojo::ScopedMessagePipeHandle handle) {
  DCHECK(!receiver_.is_bound());
  receiver_.Bind(mojo::PendingReceiver<mojom::blink::PermissionService>(
      std::move(handle)));
  receiver_.set_disconnect_handler(WTF::BindOnce(
      &MockPermissionService::OnConnectionError, WTF::Unretained(this)));
}

void MockPermissionService::SetPermissionResponse(
    V8WakeLockType::Enum type,
    mojom::blink::PermissionStatus status) {
  DCHECK(status == mojom::blink::PermissionStatus::GRANTED ||
         status == mojom::blink::PermissionStatus::DENIED);
  permission_responses_[static_cast<size_t>(type)] = status;
}

void MockPermissionService::OnConnectionError() {
  std::ignore = receiver_.Unbind();
}

bool MockPermissionService::GetWakeLockTypeFromDescriptor(
    const PermissionDescriptorPtr& descriptor,
    V8WakeLockType::Enum* output) {
  if (descriptor->name == mojom::blink::PermissionName::SCREEN_WAKE_LOCK) {
    *output = V8WakeLockType::Enum::kScreen;
    return true;
  }
  if (descriptor->name == mojom::blink::PermissionName::SYSTEM_WAKE_LOCK) {
    *output = V8WakeLockType::Enum::kSystem;
    return true;
  }
  return false;
}

void MockPermissionService::WaitForPermissionRequest(
    V8WakeLockType::Enum type) {
  size_t pos = static_cast<size_t>(type);
  DCHECK(!request_permission_callbacks_[pos]);
  base::RunLoop run_loop;
  request_permission_callbacks_[pos] = run_loop.QuitClosure();
  RunWithStack(&run_loop);
}

void MockPermissionService::HasPermission(PermissionDescriptorPtr permission,
                                          HasPermissionCallback callback) {
  V8WakeLockType::Enum type;
  if (!GetWakeLockTypeFromDescriptor(permission, &type)) {
    std::move(callback).Run(mojom::blink::PermissionStatus::DENIED);
    return;
  }
  size_t pos = static_cast<size_t>(type);
  DCHECK(permission_responses_[pos].has_value());
  std::move(callback).Run(permission_responses_[pos].value_or(
      mojom::blink::PermissionStatus::DENIED));
}

void MockPermissionService::RegisterPageEmbeddedPermissionControl(
    Vector<mojom::blink::PermissionDescriptorPtr> permissions,
    mojo::PendingRemote<mojom::blink::EmbeddedPermissionControlClient> client) {
}

void MockPermissionService::RequestPageEmbeddedPermission(
    mojom::blink::EmbeddedPermissionRequestDescriptorPtr permissions,
    RequestPageEmbeddedPermissionCallback) {
  NOTREACHED();
}

void MockPermissionService::RequestPermission(
    PermissionDescriptorPtr permission,
    bool user_gesture,
    RequestPermissionCallback callback) {
  V8WakeLockType::Enum type;
  if (!GetWakeLockTypeFromDescriptor(permission, &type)) {
    std::move(callback).Run(mojom::blink::PermissionStatus::DENIED);
    return;
  }

  size_t pos = static_cast<size_t>(type);
  DCHECK(permission_responses_[pos].has_value());
  if (request_permission_callbacks_[pos])
    std::move(request_permission_callbacks_[pos]).Run();
  std::move(callback).Run(permission_responses_[pos].value_or(
      mojom::blink::PermissionStatus::DENIED));
}

void MockPermissionService::RequestPermissions(
    Vector<PermissionDescriptorPtr> permissions,
    bool user_gesture,
    mojom::blink::PermissionService::RequestPermissionsCallback) {
  NOTREACHED();
}

void MockPermissionService::RevokePermission(PermissionDescriptorPtr permission,
                                             RevokePermissionCallback) {
  NOTREACHED();
}

void MockPermissionService::AddPermissionObserver(
    PermissionDescriptorPtr permission,
    mojom::blink::PermissionStatus last_known_status,
    mojo::PendingRemote<mojom::blink::PermissionObserver>) {
  NOTREACHED();
}

void MockPermissionService::AddPageEmbeddedPermissionObserver(
    PermissionDescriptorPtr permission,
    mojom::blink::PermissionStatus last_known_status,
    mojo::PendingRemote<mojom::blink::PermissionObserver>) {
  NOTREACHED();
}

void MockPermissionService::NotifyEventListener(
    PermissionDescriptorPtr permission,
    const String& event_type,
    bool is_added) {
  NOTREACHED();
}
// WakeLockTestingContext

WakeLockTestingContext::WakeLockTestingContext(
    MockWakeLockService* mock_wake_lock_service) {
  DomWindow()->GetBrowserInterfaceBroker().SetBinderForTesting(
      mojom::blink::WakeLockService::Name_,
      WTF::BindRepeating(&MockWakeLockService::BindRequest,
                         WTF::Unretained(mock_wake_lock_service)));
  DomWindow()->GetBrowserInterfaceBroker().SetBinderForTesting(
      mojom::blink::PermissionService::Name_,
      WTF::BindRepeating(&MockPermissionService::BindRequest,
                         WTF::Unretained(&permission_service_)));
}

WakeLockTestingContext::~WakeLockTestingContext() {
  // Remove the testing binder to avoid crashes between tests caused by
  // our mocks rebinding an already-bound Binding.
  // See https://crbug.com/1010116 for more information.
  DomWindow()->GetBrowserInterfaceBroker().SetBinderForTesting(
      mojom::blink::WakeLockService::Name_, {});
  DomWindow()->GetBrowserInterfaceBroker().SetBinderForTesting(
      mojom::blink::PermissionService::Name_, {});
}

LocalDOMWindow* WakeLockTestingContext::DomWindow() {
  return Frame()->DomWindow();
}

LocalFrame* WakeLockTestingContext::Frame() {
  return &testing_scope_.GetFrame();
}

ScriptState* WakeLockTestingContext::GetScriptState() {
  return testing_scope_.GetScriptState();
}

MockPermissionService& WakeLockTestingContext::GetPermissionService() {
  return permission_service_;
}

void WakeLockTestingContext::WaitForPromiseFulfillment(
    ScriptPromise<WakeLockSentinel> promise) {
  base::RunLoop run_loop;
  promise.Then(GetScriptState(),
               MakeGarbageCollected<ClosureOnResolve>(run_loop.QuitClosure()));
  // Execute pending microtasks, otherwise it can take a few seconds for the
  // promise to resolve.
  GetScriptState()->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
      GetScriptState()->GetIsolate());
  RunWithStack(&run_loop);
}

// Synchronously waits for |promise| to be rejected.
void WakeLockTestingContext::WaitForPromiseRejection(
    ScriptPromise<WakeLockSentinel> promise) {
  base::RunLoop run_loop;
  promise.Catch(GetScriptState(),
                MakeGarbageCollected<ClosureOnReject>(run_loop.QuitClosure()));
  // Execute pending microtasks, otherwise it can take a few seconds for the
  // promise to resolve.
  GetScriptState()->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
      GetScriptState()->GetIsolate());
  RunWithStack(&run_loop);
}

// ScriptPromiseUtils

// static
v8::Promise::PromiseState ScriptPromiseUtils::GetPromiseState(
    const ScriptPromise<WakeLockSentinel>& promise) {
  return promise.V8Promise()->State();
}

// static
DOMException* ScriptPromiseUtils::GetPromiseResolutionAsDOMException(
    v8::Isolate* isolate,
    const ScriptPromise<WakeLockSentinel>& promise) {
  return V8DOMException::ToWrappable(isolate, promise.V8Promise()->Result());
}

// static
WakeLockSentinel* ScriptPromiseUtils::GetPromiseResolutionAsWakeLockSentinel(
    v8::Isolate* isolate,
    const ScriptPromise<WakeLockSentinel>& promise) {
  return V8WakeLockSentinel::ToWrappable(isolate,
                                         promise.V8Promise()->Result());
}

}  // namespace blink

"""

```