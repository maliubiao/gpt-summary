Response:
Let's break down the thought process for analyzing the provided `pressure_observer.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies, logical reasoning with examples, common usage errors, and debugging context.

2. **Initial Skim and Keyword Identification:**  Read through the code, looking for key terms and structures. Words like `PressureObserver`, `observe`, `unobserve`, `disconnect`, `callback`, `Promise`, `PressureRecord`, `PressureSource`, `PressureState`, `PermissionsPolicy`, `sampleInterval`, `takeRecords` immediately stand out. The inclusion of `#include` directives tells us about dependencies.

3. **Identify Core Functionality (Top-Down):**

   * **Observation:** The name `PressureObserver` strongly suggests its primary function is to observe changes in system pressure. The `observe` method confirms this. It takes a `PressureSource` (like CPU) and `PressureObserverOptions`. It returns a `ScriptPromise`, indicating asynchronous behavior.

   * **Data Reporting:** The `OnUpdate` method is called when pressure changes are detected. It creates `PressureRecord` objects. The `ReportToCallback` method then delivers these records to a JavaScript callback function.

   * **Lifecycle Management:**  The `unobserve` and `disconnect` methods provide ways to stop observing and release resources.

   * **Error Handling:**  The code checks for things like detached execution contexts and Permissions Policy. The `OnBindingFailed` and `OnConnectionError` methods suggest handling failures in acquiring pressure data.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**

   * **JavaScript:**  The file heavily interacts with JavaScript. The `observe` method is likely called from JavaScript. The `V8PressureUpdateCallback` is a C++ representation of a JavaScript function. The `ScriptPromise` is directly tied to JavaScript Promises. The `takeRecords` method provides a way for JavaScript to retrieve collected data. *Example:*  A JavaScript snippet calling `navigator.computePressure.observe('cpu', { sampleInterval: 1000 }, (records) => { ... })` would directly interact with the functionality in this file.

   * **HTML:**  The Permissions Policy check is relevant to HTML. The `<meta>` tag or HTTP headers can control the `compute-pressure` feature. *Example:*  If an HTML page has `<meta http-equiv="Permissions-Policy" content="compute-pressure=()">`, the `IsFeatureEnabled` check would fail.

   * **CSS:** The connection to CSS is less direct, but potentially through the impact of system pressure on rendering performance. While this file doesn't *directly* manipulate CSS, the data it collects could *indirectly* influence CSS-related decisions (though this is speculative for this particular file).

5. **Analyze Logical Reasoning and Provide Examples:**

   * **Rate Limiting/Obfuscation:** The `PassesRateTest` and `PassesRateObfuscation` methods are clear examples of logical checks. They implement specific rules (e.g., a minimum interval between reports, and a more complex rate limiting mechanism for obfuscation). *Example:* Assume `sampleInterval` is 100ms. If `OnUpdate` is called twice within 50ms, the second call will be ignored due to `PassesRateTest` returning `false`.

   * **Data Change Detection:** The `HasChangeInData` method prevents reporting the same pressure state repeatedly. *Example:* If the CPU pressure remains "nominal," subsequent `OnUpdate` calls with the same state will be ignored.

   * **Promise Management:** The `pending_resolvers_` structure and the `ResolvePendingResolvers` and `RejectPendingResolvers` methods demonstrate how the asynchronous `observe` operation is managed using Promises.

6. **Identify Potential User/Programming Errors:**

   * **Permissions Policy:**  A common error is trying to use the API when it's blocked by Permissions Policy.
   * **Detached Context:**  Calling `observe` after the document is unloaded will fail.
   * **Incorrect `sampleInterval`:** Setting a very low `sampleInterval` might lead to rate limiting and missed updates.
   * **Calling `unobserve`/`disconnect` prematurely:** This can lead to unexpected behavior and loss of data.

7. **Trace User Operations (Debugging Context):**

   * Start with a user interaction in the browser (e.g., opening a website).
   * Identify the JavaScript code that calls the Compute Pressure API (e.g., `navigator.computePressure.observe(...)`).
   * This call will go through the Blink bindings and eventually reach the C++ `PressureObserver::observe` method.
   * System pressure changes trigger the underlying platform's pressure monitoring mechanism, which in turn calls `PressureObserver::OnUpdate`.
   * The callback function provided in the JavaScript will eventually be invoked by `PressureObserver::ReportToCallback`.

8. **Review and Refine:**  Go back through the analysis, ensuring clarity, accuracy, and completeness. Check for any missed details or areas where the explanation could be improved. For instance, clarify the purpose of the rate obfuscation mechanism.

This systematic approach helps in dissecting the code, understanding its role, and providing a comprehensive answer to the request. It combines code analysis with knowledge of web platform concepts and debugging principles.
好的，让我们详细分析一下 `blink/renderer/modules/compute_pressure/pressure_observer.cc` 这个文件。

**文件功能概述**

`pressure_observer.cc` 文件实现了 Chromium Blink 引擎中用于监测设备计算压力（Compute Pressure）的 `PressureObserver` 接口。这个接口允许网页通过 JavaScript 代码注册监听器，以便在设备 CPU 或其他系统资源压力发生变化时收到通知。

**核心功能点：**

1. **创建和管理观察者 (Observers):**
   - `PressureObserver::Create`:  静态方法，用于创建一个 `PressureObserver` 实例。
   - 维护一个 JavaScript 回调函数 (`observer_callback_`)，当压力更新时会调用这个回调函数。
   - 与 `PressureObserverManager` 协同工作，后者负责管理全局的压力数据源和观察者。

2. **启动压力监测 (`observe` 方法):**
   - 接收 JavaScript 传递的参数：
     - `source`:  要观察的压力源，目前只支持 `cpu`。
     - `options`:  包含 `sampleInterval` 属性，指定报告压力变化的最小时间间隔（毫秒）。
   - 进行权限检查：
     - 检查当前执行上下文是否被 Permissions Policy 允许使用 "compute pressure" 功能。如果被阻止，会抛出 `NotAllowedError` 异常。
     - 检查执行上下文是否已销毁。
   - 创建一个 Promise，当压力源绑定成功后会 resolve 这个 Promise。
   - 将当前的 `PressureObserver` 添加到 `PressureObserverManager` 中，开始监听指定压力源的变化。

3. **停止压力监测 (`unobserve` 和 `disconnect` 方法):**
   - `unobserve(V8PressureSource source)`:  停止观察指定的压力源。
     - 从 `PressureObserverManager` 中移除观察者。
     - 清理与该压力源相关的缓存数据和待处理的回调任务。
     - reject 与该压力源相关的 pending 的 Promise。
   - `disconnect()`: 停止观察所有压力源。
     - 从 `PressureObserverManager` 中移除所有观察。
     - 清理所有压力源相关的缓存数据和待处理的回调任务。
     - reject 所有 pending 的 Promise。

4. **接收和处理压力更新 (`OnUpdate` 方法):**
   - 当 `PressureObserverManager` 检测到压力源状态变化时，会调用此方法。
   - 进行速率测试 (`PassesRateTest`): 检查自上次报告以来是否超过了 `sampleInterval`。
   - 检查数据是否发生变化 (`HasChangeInData`): 避免报告相同的压力状态。
   - 创建 `PressureRecord` 对象，包含压力源、状态和时间戳。
   - **速率混淆缓解 (Rate Obfuscation Mitigation):**  如果启用了 `kComputePressureRateObfuscationMitigation` 特性：
     -  实现了一种机制，当压力变化过于频繁时，会延迟报告，以避免泄露过于精确的压力信息。
     -  使用 `change_rate_monitor_` 跟踪变化频率。
     -  如果短时间内变化过于频繁，会将新的 `PressureRecord` 暂存，并延迟一段时间后报告。
   - 将 `PressureRecord` 添加到内部队列 (`records_`)。
   - 如果当前没有待处理的回调任务，则启动一个任务 (`ReportToCallback`)，将队列中的压力记录报告给 JavaScript 回调函数。

5. **报告压力变化给 JavaScript (`ReportToCallback` 方法):**
   - 获取内部队列中的所有 `PressureRecord`。
   - 调用 JavaScript 回调函数 (`observer_callback_->InvokeAndReportException`)，将 `PressureRecord` 数组作为参数传递给回调函数。

6. **手动获取压力记录 (`takeRecords` 方法):**
   - 允许 JavaScript 代码主动获取当前已收集但尚未报告的压力记录。
   - 清空内部的 `records_` 队列。

7. **处理绑定状态 (`OnBindingSucceeded`, `OnBindingFailed`, `OnConnectionError`):**
   - 与底层的压力源绑定过程相关。
   - `OnBindingSucceeded`:  当成功绑定到压力源时调用，resolve 相关的 Promise。
   - `OnBindingFailed`:  当绑定失败时调用，reject 相关的 Promise。
   - `OnConnectionError`: 当与压力源的连接出现错误时调用，reject 所有 pending 的 Promise。

**与 JavaScript, HTML, CSS 的关系**

这个文件是 Blink 渲染引擎的一部分，负责实现 Web API 的底层逻辑，直接与 JavaScript 交互。

* **JavaScript:**
    - `PressureObserver` 类是在 JavaScript 中通过 `navigator.computePressure.observe()` 方法创建和使用的。
    - `observe` 方法的参数（`source`, `options`）由 JavaScript 提供。
    - 当压力变化时，`ReportToCallback` 方法最终会调用 JavaScript 中提供的回调函数，将压力数据传递给 JavaScript。
    - `takeRecords()` 方法可以直接在 JavaScript 中调用，获取压力记录。
    - JavaScript 的 Promise 用于处理 `observe` 方法的异步操作。

    **举例:**

    ```javascript
    const observer = new PressureObserver((records) => {
      console.log("压力更新:", records);
      records.forEach(record => {
        console.log(`  源: ${record.source}, 状态: ${record.state}, 时间: ${record.time}`);
      });
    });

    observer.observe('cpu', { sampleInterval: 1000 })
      .then(() => console.log("开始观察 CPU 压力"))
      .catch((error) => console.error("观察失败:", error));

    // 一段时间后停止观察
    // observer.unobserve('cpu');
    // 或者完全断开连接
    // observer.disconnect();

    // 手动获取记录
    // const currentRecords = observer.takeRecords();
    // console.log("手动获取的记录:", currentRecords);
    ```

* **HTML:**
    - HTML 中的 `<meta>` 标签可以通过 Permissions Policy 控制 "compute pressure" 功能是否可用。

    **举例:**

    ```html
    <!-- 允许当前域使用 compute-pressure 特性 -->
    <meta http-equiv="Permissions-Policy" content="compute-pressure=(self)">

    <!-- 阻止 compute-pressure 特性 -->
    <meta http-equiv="Permissions-Policy" content="compute-pressure=()">
    ```

* **CSS:**
    - 该文件与 CSS 的关系较为间接。收集到的压力数据可能会被用于浏览器内部优化渲染性能，例如，在高压力下可能会降低渲染优先级或执行一些节流操作。但是，开发者无法直接通过 CSS 来访问或控制 `PressureObserver` 的功能。

**逻辑推理与假设输入输出**

假设 JavaScript 代码执行以下操作：

```javascript
const observer = new PressureObserver((records) => {
  console.log("压力更新:", records.map(r => r.state));
});
observer.observe('cpu', { sampleInterval: 500 });
```

**假设输入:**

1. 用户在支持 Compute Pressure API 的浏览器中打开了网页。
2. JavaScript 代码创建了一个 `PressureObserver` 实例，并设置了 `sampleInterval` 为 500 毫秒。
3. 在一段时间内，CPU 压力状态发生了以下变化（假设的时间戳）：
   - t=0ms: "nominal"
   - t=100ms: "fair"
   - t=400ms: "serious"
   - t=600ms: "nominal"
   - t=1150ms: "fair"

**逻辑推理与输出:**

- 首次调用 `observe` 会成功，Promise 会 resolve。
- **t=0ms:** CPU 压力变为 "nominal"。由于是第一次更新，且满足了初始条件，会创建一个 `PressureRecord`，并放入队列。
- **t=100ms:** CPU 压力变为 "fair"。距离上次报告只有 100ms，小于 `sampleInterval` (500ms)，`PassesRateTest` 返回 false，此次更新会被忽略。
- **t=400ms:** CPU 压力变为 "serious"。距离上次报告 400ms，仍小于 `sampleInterval`，此次更新会被忽略。
- **t=500ms 附近:**  由于队列中有待报告的记录，且距离上次报告超过了 500ms，`ReportToCallback` 任务会被执行，JavaScript 回调函数会被调用，输出：`压力更新: ["nominal"]`。同时，`last_record_map_` 会更新为 "serious"。
- **t=600ms:** CPU 压力变为 "nominal"。距离上次*报告*（不是上次压力变化）大约 100ms，小于 `sampleInterval`，此次更新被忽略。
- **t=1100ms 附近:** 距离上次报告超过 500ms，`ReportToCallback` 任务执行，输出：`压力更新: ["serious"]`。
- **t=1150ms:** CPU 压力变为 "fair"。距离上次报告大约 50ms，小于 `sampleInterval`，被忽略。
- **t=1600ms 附近:** 距离上次报告超过 500ms，`ReportToCallback` 任务执行，输出：`压力更新: ["fair"]`。

**涉及用户或编程常见的使用错误**

1. **Permissions Policy 阻止:** 用户尝试在没有权限的上下文中调用 `navigator.computePressure.observe()`，会导致 `NotAllowedError` 异常。
   ```javascript
   try {
     const observer = new PressureObserver(() => {});
     observer.observe('cpu', { sampleInterval: 1000 });
   } catch (error) {
     console.error("观察压力失败:", error); // 可能输出 NotAllowedError
   }
   ```

2. **错误的 `sampleInterval` 设置:**  设置过小的 `sampleInterval` 可能会导致频繁的回调，影响性能。设置过大的 `sampleInterval` 会导致压力变化报告不及时。

3. **在文档卸载后调用 `observe`:**  如果在一个即将卸载的文档中调用 `observe`，`ExecutionContext` 可能已被销毁，导致 `NotSupportedError` 异常。

4. **忘记处理 Promise 的 rejection:** `observe` 方法返回一个 Promise，如果没有处理 rejection，当 Permissions Policy 阻止或发生其他错误时，可能会出现未捕获的 Promise 错误。

5. **混淆 `unobserve` 和 `disconnect`:**
   - `unobserve` 只停止观察特定的压力源。
   - `disconnect` 停止观察所有压力源。
   错误地使用会导致意外的行为。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户打开一个网页:** 用户在浏览器中输入网址或点击链接，加载包含 Compute Pressure API 使用的网页。
2. **JavaScript 代码执行:** 网页加载完成后，嵌入的 JavaScript 代码开始执行。
3. **调用 `navigator.computePressure.observe()`:** JavaScript 代码调用 `navigator.computePressure.observe('cpu', options, callback)` 方法。
4. **Blink 绑定层:** 这个调用会通过 Blink 的 JavaScript 绑定层，将请求传递到 C++ 代码。
5. **`PressureObserver::observe()` 被调用:** 在 `pressure_observer.cc` 文件中，`PressureObserver::observe()` 方法被调用，处理 JavaScript 传递的参数，进行权限检查，并创建 Promise。
6. **`PressureObserverManager` 交互:** `PressureObserver` 实例会被添加到 `PressureObserverManager` 中，后者负责订阅底层的系统压力数据源。
7. **系统压力变化通知:** 当操作系统或浏览器底层检测到 CPU 压力变化时，`PressureObserverManager` 会收到通知。
8. **`PressureObserver::OnUpdate()` 被调用:** `PressureObserverManager` 会调用已注册的 `PressureObserver` 实例的 `OnUpdate()` 方法，传递压力状态和时间戳。
9. **速率测试和数据检查:** `OnUpdate()` 方法会进行速率测试和数据变化检查。
10. **创建 `PressureRecord` 并加入队列:** 如果通过检查，会创建一个 `PressureRecord` 对象并添加到内部队列 `records_`。
11. **`ReportToCallback()` 任务调度:** 如果需要报告，会调度一个任务来执行 `ReportToCallback()`。
12. **JavaScript 回调执行:** `ReportToCallback()` 方法最终会调用 JavaScript 中提供的回调函数，将 `PressureRecord` 数据传递回去。

**调试线索:**

- **断点:** 在 `PressureObserver::observe()`, `PressureObserver::OnUpdate()`, `PressureObserver::ReportToCallback()` 等关键方法设置断点，可以跟踪代码的执行流程。
- **日志输出:** 在这些方法中添加日志输出，可以查看参数值和执行状态。
- **Permissions Policy 检查:** 检查浏览器的开发者工具中的 "Security" 标签，查看 "Permissions Policy" 是否阻止了 "compute-pressure" 特性。
- **`sampleInterval` 的影响:**  调整 `sampleInterval` 的值，观察回调函数的触发频率。
- **检查 `PressureObserverManager`:**  虽然这个文件没有包含 `PressureObserverManager` 的实现，但理解其作用可以帮助理解整个流程。
- **浏览器内部机制:**  了解浏览器如何获取系统压力信息（可能涉及到操作系统 API 调用）也有助于深入理解。

希望以上详细的分析能够帮助你理解 `pressure_observer.cc` 文件的功能和它在 Chromium Blink 引擎中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/compute_pressure/pressure_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/compute_pressure/pressure_observer.h"

#include "base/ranges/algorithm.h"
#include "base/task/sequenced_task_runner.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_pressure_observer_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_pressure_record.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_pressure_source.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/modules/compute_pressure/pressure_observer_manager.h"
#include "third_party/blink/renderer/modules/compute_pressure/pressure_record.h"
#include "third_party/blink/renderer/modules/compute_pressure/pressure_source_index.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

constexpr char kFeaturePolicyBlocked[] =
    "Access to the feature \"compute pressure\" is disallowed by permissions "
    "policy.";

}  // namespace

PressureObserver::PressureObserver(V8PressureUpdateCallback* observer_callback)
    : observer_callback_(observer_callback) {}

PressureObserver::~PressureObserver() = default;

// static
PressureObserver* PressureObserver::Create(V8PressureUpdateCallback* callback) {
  return MakeGarbageCollected<PressureObserver>(callback);
}

// static
Vector<V8PressureSource> PressureObserver::knownSources() {
  return Vector<V8PressureSource>(
      {V8PressureSource(V8PressureSource::Enum::kCpu)});
}

ScriptPromise<IDLUndefined> PressureObserver::observe(
    ScriptState* script_state,
    V8PressureSource source,
    PressureObserverOptions* options,
    ExceptionState& exception_state) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  if (execution_context->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Execution context is detached.");
    return EmptyPromise();
  }

  // Checks whether the document is allowed by Permissions Policy to call
  // Compute Pressure API.
  if (!execution_context->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kComputePressure,
          ReportOptions::kReportOnFailure)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                      kFeaturePolicyBlocked);
    return EmptyPromise();
  }

  sample_interval_ = options->sampleInterval();
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  pending_resolvers_[ToSourceIndex(source.AsEnum())].insert(resolver);

  if (!manager_) {
    manager_ = PressureObserverManager::From(execution_context);
  }
  manager_->AddObserver(source.AsEnum(), this);

  return resolver->Promise();
}

void PressureObserver::unobserve(V8PressureSource source) {
  // Wrong order of calls.
  if (!manager_) {
    return;
  }
  const auto source_index = ToSourceIndex(source.AsEnum());
  // https://w3c.github.io/compute-pressure/#the-unobserve-method
  manager_->RemoveObserver(source.AsEnum(), this);
  last_record_map_[source_index].Clear();
  after_penalty_records_[source_index].Clear();
  pending_delayed_report_to_callback_[source_index].Cancel();
  // Reject all pending promises for `source`.
  RejectPendingResolvers(source.AsEnum(), DOMExceptionCode::kAbortError,
                         "Called unobserve method.");
  records_.erase(base::ranges::remove_if(records_,
                                         [source](const auto& record) {
                                           return record->source() == source;
                                         }),
                 records_.end());
}

void PressureObserver::disconnect() {
  // Wrong order of calls.
  if (!manager_) {
    return;
  }
  // https://w3c.github.io/compute-pressure/#the-disconnect-method
  manager_->RemoveObserverFromAllSources(this);
  for (auto& last_record : last_record_map_) {
    last_record.Clear();
  }
  for (auto& after_penalty_record : after_penalty_records_) {
    after_penalty_record.Clear();
  }

  for (auto& pending_callback : pending_delayed_report_to_callback_) {
    pending_callback.Cancel();
  }

  // Reject all pending promises.
  for (const auto& source : knownSources()) {
    RejectPendingResolvers(source.AsEnum(), DOMExceptionCode::kAbortError,
                           "Called disconnect method.");
  }
  records_.clear();
}

void PressureObserver::Trace(blink::Visitor* visitor) const {
  visitor->Trace(manager_);
  visitor->Trace(observer_callback_);
  for (const auto& after_penalty_record : after_penalty_records_) {
    visitor->Trace(after_penalty_record);
  }
  for (const auto& last_record : last_record_map_) {
    visitor->Trace(last_record);
  }
  for (const auto& pending_resolver_set : pending_resolvers_) {
    visitor->Trace(pending_resolver_set);
  }
  visitor->Trace(records_);
  ScriptWrappable::Trace(visitor);
}

void PressureObserver::OnUpdate(ExecutionContext* execution_context,
                                V8PressureSource::Enum source,
                                V8PressureState::Enum state,
                                DOMHighResTimeStamp timestamp) {
  if (!PassesRateTest(source, timestamp)) {
    return;
  }

  if (!HasChangeInData(source, state)) {
    return;
  }

  auto* record = MakeGarbageCollected<PressureRecord>(source, state, timestamp);

  if (base::FeatureList::IsEnabled(
          features::kComputePressureRateObfuscationMitigation)) {
    const auto source_index = ToSourceIndex(source);
    // Steps 4.5.1 and 4.5.2
    // https://w3c.github.io/compute-pressure/#dfn-data-delivery
    if (pending_delayed_report_to_callback_[source_index].IsActive()) {
      after_penalty_records_[source_index] = record;
      return;
    }

    change_rate_monitor_.ResetIfNeeded();
    change_rate_monitor_.IncreaseChangeCount(source);

    if (!PassesRateObfuscation(source)) {
      // Steps 4.6.1 and 4.6.2
      // https://w3c.github.io/compute-pressure/#dfn-data-delivery
      after_penalty_records_[source_index] = record;
      pending_delayed_report_to_callback_[source_index] =
          PostDelayedCancellableTask(
              *execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI),
              FROM_HERE,
              WTF::BindOnce(&PressureObserver::QueueAfterPenaltyRecord,
                            WrapWeakPersistent(this),
                            WrapWeakPersistent(execution_context), source),
              change_rate_monitor_.penalty_duration());
      change_rate_monitor_.ResetChangeCount(source);
      return;
    }
  }

  QueuePressureRecord(execution_context, source, record);
}

// Steps 4.6.3.1.1-3 of
// https://w3c.github.io/compute-pressure/#dfn-data-delivery
void PressureObserver::QueueAfterPenaltyRecord(
    ExecutionContext* execution_context,
    V8PressureSource::Enum source) {
  const auto source_index = ToSourceIndex(source);
  CHECK(after_penalty_records_[source_index]);
  auto& record = after_penalty_records_[source_index];
  QueuePressureRecord(execution_context, source, record);
}

// https://w3c.github.io/compute-pressure/#queue-a-pressurerecord
void PressureObserver::QueuePressureRecord(ExecutionContext* execution_context,
                                           V8PressureSource::Enum source,
                                           PressureRecord* record) {
  // This should happen infrequently since `records_` is supposed
  // to be emptied at every callback invoking or takeRecords().
  if (records_.size() >= kMaxQueuedRecords)
    records_.erase(records_.begin());

  records_.push_back(record);
  CHECK_LE(records_.size(), kMaxQueuedRecords);

  last_record_map_[ToSourceIndex(source)] = record;
  if (pending_report_to_callback_.IsActive())
    return;

  pending_report_to_callback_ = PostCancellableTask(
      *execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI), FROM_HERE,
      WTF::BindOnce(&PressureObserver::ReportToCallback,
                    WrapWeakPersistent(this),
                    WrapWeakPersistent(execution_context)));
}

void PressureObserver::OnBindingSucceeded(V8PressureSource::Enum source) {
  ResolvePendingResolvers(source);
}

void PressureObserver::OnBindingFailed(V8PressureSource::Enum source,
                                       DOMExceptionCode exception_code) {
  RejectPendingResolvers(source, exception_code,
                         "Not available on this platform.");
}

void PressureObserver::OnConnectionError() {
  for (const auto& source : knownSources()) {
    RejectPendingResolvers(source.AsEnum(),
                           DOMExceptionCode::kNotSupportedError,
                           "Connection error.");
  }
}

void PressureObserver::ReportToCallback(ExecutionContext* execution_context) {
  CHECK(observer_callback_);
  if (!execution_context || execution_context->IsContextDestroyed()) {
    return;
  }

  // Cleared by takeRecords, for example.
  if (records_.empty()) {
    return;
  }

  HeapVector<Member<PressureRecord>, kMaxQueuedRecords> records;
  records_.swap(records);
  observer_callback_->InvokeAndReportException(this, records, this);
}

HeapVector<Member<PressureRecord>> PressureObserver::takeRecords() {
  // This method clears records_.
  HeapVector<Member<PressureRecord>, kMaxQueuedRecords> records;
  records.swap(records_);
  return records;
}

// https://w3c.github.io/compute-pressure/#dfn-passes-rate-test
bool PressureObserver::PassesRateTest(
    V8PressureSource::Enum source,
    const DOMHighResTimeStamp& timestamp) const {
  const auto& last_record = last_record_map_[ToSourceIndex(source)];

  if (!last_record)
    return true;

  const double time_delta_milliseconds = timestamp - last_record->time();
  return time_delta_milliseconds >= static_cast<double>(sample_interval_);
}

// https://w3c.github.io/compute-pressure/#dfn-has-change-in-data
bool PressureObserver::HasChangeInData(V8PressureSource::Enum source,
                                       V8PressureState::Enum state) const {
  const auto& last_record = last_record_map_[ToSourceIndex(source)];

  if (!last_record)
    return true;

  return last_record->state() != state;
}

// This function only checks the status of the rate obfuscation test.
// Incrementing of change count should happen before this call as described in
// https://w3c.github.io/compute-pressure/#dfn-passes-rate-obfuscation-test
bool PressureObserver::PassesRateObfuscation(
    V8PressureSource::Enum source) const {
  return !change_rate_monitor_.ChangeCountExceedsLimit(source);
}

void PressureObserver::ResolvePendingResolvers(V8PressureSource::Enum source) {
  const auto source_index = ToSourceIndex(source);
  for (const auto& resolver : pending_resolvers_[source_index]) {
    resolver->Resolve();
  }
  pending_resolvers_[source_index].clear();
}

void PressureObserver::RejectPendingResolvers(V8PressureSource::Enum source,
                                              DOMExceptionCode exception_code,
                                              const String& message) {
  const auto source_index = ToSourceIndex(source);
  for (const auto& resolver : pending_resolvers_[source_index]) {
    resolver->RejectWithDOMException(exception_code, message);
  }
  pending_resolvers_[source_index].clear();
}

}  // namespace blink

"""

```