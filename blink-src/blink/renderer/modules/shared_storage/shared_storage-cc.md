Response:
My thinking process to analyze the code and answer the prompt goes like this:

1. **Understand the Goal:** The prompt asks for a functional summary of `shared_storage.cc`, focusing on its relationship with web technologies, logical reasoning, potential errors, debugging, and a final summarized functionality.

2. **High-Level Overview:** I first scan the `#include` directives and the namespace declaration (`namespace blink`). This immediately tells me the file is part of the Chromium Blink rendering engine, specifically within the `shared_storage` module. The included headers point to interactions with Mojo, V8 (JavaScript), and other Blink components. This suggests it deals with a web storage mechanism accessible via JavaScript.

3. **Identify Key Classes and Functions:** I look for the main class defined in the file, which is `SharedStorage`. Then I examine its public methods: `set`, `append`, `Delete`, `clear`, `get`, `length`, `remainingBudget`, `keys`, `values`, `entries`, `run`. These are the primary interactions developers will have with this functionality through JavaScript. The presence of `Worklet` related methods hints at asynchronous execution capabilities.

4. **Analyze Each Function (Initial Pass):** I go through each public method and try to understand its basic purpose from the name and the arguments.

    * `set`, `append`, `Delete`, `clear`: These clearly modify the shared storage.
    * `get`: This retrieves data from the storage.
    * `length`:  Returns the number of entries.
    * `remainingBudget`:  Indicates a resource limit.
    * `keys`, `values`, `entries`:  Provide iterators for accessing the stored data.
    * `run`:  Seems to execute some kind of operation within a worklet.

5. **Look for Relationships with Web Technologies:**  I specifically search for mentions of JavaScript, HTML, and CSS.

    * **JavaScript:** The presence of `ScriptState`, `ScriptPromise`, `V8ThrowDOMException`, and the method signatures accepting `String` arguments strongly indicate interaction with JavaScript. The file implements the API exposed to JavaScript.
    * **HTML:**  The code checks for `ExecutionContext` being a `Window` or `SharedStorageWorkletGlobalScope`. This links it to the context within which JavaScript executes in a browser, which is tied to HTML documents. The `CanGetOutsideWorklet` function and the fenced frames feature are direct links to HTML and its rendering concepts.
    * **CSS:** I don't see any direct interaction with CSS in this particular file. While shared storage might indirectly influence what JavaScript does which *could* affect CSS (e.g., by determining which elements to display or what data to fetch), this file itself doesn't seem to handle CSS directly.

6. **Identify Logical Reasoning and Assumptions:** I look for conditional statements and how data flows.

    * **Permissions:**  The `CheckSharedStoragePermissionsPolicy` function is a key logical step. It assumes a permissions mechanism exists to control access.
    * **Input Validation:** The checks for `IsValidSharedStorageKeyStringLength` and `IsValidSharedStorageValueStringLength` show input validation. The assumption is that there are limits to the size of keys and values.
    * **Error Handling:** The use of `ScriptPromiseResolver` and `V8ThrowDOMException` indicates how errors are handled and propagated back to JavaScript.
    * **Asynchronous Operations:** The use of `WTF::BindOnce` and callbacks suggests asynchronous operations, likely involving communication with other browser processes via Mojo.
    * **Worklets:** The code manages interactions with `SharedStorageWorklet`, indicating a separate execution environment.

7. **Consider User/Programming Errors:** Based on the code, I think about common mistakes:

    * **Invalid Key/Value Lengths:** Users might try to store keys or values that are too long.
    * **Incorrect Context:** Calling methods like `get` from the wrong context (e.g., outside a fenced frame when required).
    * **Permissions Issues:**  The feature might be disabled, or the site might not have the necessary permissions.
    * **Opaque Origins:** Attempting to use shared storage in contexts with opaque origins is disallowed.

8. **Trace User Operations and Debugging:** I try to envision how a user action leads to this code:

    * A website's JavaScript uses the `sharedStorage` API (e.g., `navigator.sharedStorage.set('myKey', 'myValue')`).
    * This JavaScript call goes through the V8 bindings and eventually calls the C++ methods in this file.
    * The C++ code interacts with browser services (via Mojo) to perform the underlying storage operations.

9. **Summarize Functionality (Initial Draft):** Based on the above, I draft a summary focusing on the main purpose: providing a web API for storing and retrieving key-value data, with worklet support and permission controls.

10. **Refine and Organize:** I review my notes and the code comments to structure the answer logically. I group related functionalities together (e.g., the setter methods, the getter methods, the iterator methods). I make sure to address all parts of the prompt (JavaScript/HTML/CSS relation, logical reasoning, errors, debugging).

11. **Review and Add Examples:** I review the answer for clarity and accuracy. I add specific examples to illustrate the interaction with JavaScript and the potential errors. I ensure the assumptions and input/output of the logical reasoning are clear.

By following these steps, I can systematically analyze the code and provide a comprehensive answer to the prompt. The iterative process of analyzing, summarizing, and refining is key to capturing the nuances of the code's functionality.
好的，这是对提供的 Chromium Blink 引擎源代码文件 `blink/renderer/modules/shared_storage/shared_storage.cc` 第一部分的功能归纳：

**功能归纳:**

这个 C++ 代码文件 `shared_storage.cc` 实现了 Blink 渲染引擎中 **Shared Storage API** 的核心功能。Shared Storage API 允许网站存储跨站点上下文的数据，同时限制数据泄露，主要用于隐私保护的用例，例如衡量广告覆盖率、A/B 测试等。

**主要功能点包括:**

1. **JavaScript API 的实现:**  该文件实现了 `SharedStorage` 这个 JavaScript 接口，该接口在 JavaScript 中通过 `navigator.sharedStorage` 访问。它定义了以下 JavaScript 方法的底层逻辑：
    * **数据写入/修改:** `set()`, `append()`, `delete()`, `clear()`：用于设置、追加、删除和清空共享存储中的数据。
    * **数据读取:** `get()`：用于从共享存储中读取特定键的值。
    * **元数据访问:** `length()`: 获取共享存储中条目的数量。 `remainingBudget()`: 获取剩余的预算（可能与私有聚合相关）。
    * **迭代器:** `keys()`, `values()`, `entries()`:  提供异步迭代器来遍历共享存储中的键、值或键值对。
    * **Worklet 执行:** `run()`: 允许在 Shared Storage Worklet 中执行代码，进行更复杂的逻辑操作。

2. **与浏览器进程的通信:**  该文件使用 **Mojo** 与浏览器进程中的 `SharedStorageDocumentService` 和 `SharedStorageWorkletServiceClient` 组件进行通信。这意味着渲染进程中的 JavaScript 调用最终会通过 Mojo 传递到浏览器进程进行实际的存储操作和权限检查。

3. **权限控制:** 代码中包含对共享存储权限策略的检查 (`CheckSharedStoragePermissionsPolicy`)，确保只有在允许的情况下才能进行操作。

4. **错误处理:**  使用了 `ScriptPromiseResolver` 来处理异步操作的结果，并将错误信息以 `DOMException` 的形式返回给 JavaScript。

5. **性能监控:**  通过 `base::UmaHistogramMediumTimes` 等函数记录各种操作的耗时，用于性能分析和监控。

6. **Fenced Frames 支持:** 代码中包含对 Fenced Frames 的特殊处理，特别是 `get()` 方法，限制了在非 Fenced Frames 上下文中的使用，并进行了额外的权限检查。

7. **Worklet 支持:**  该文件涉及 Shared Storage Worklet 的创建和交互，允许在独立的上下文中执行与共享存储相关的逻辑。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  `SharedStorage` 类直接对应 JavaScript 中的 `navigator.sharedStorage` 对象。例如，在 JavaScript 中调用 `navigator.sharedStorage.set('myKey', 'myValue')`，最终会触发 `shared_storage.cc` 中的 `SharedStorage::set()` 方法。

* **HTML:**  Shared Storage API 是通过 JavaScript 在 HTML 页面中使用的。用户可以通过 HTML 中嵌入的 `<script>` 标签内的 JavaScript 代码来访问和操作共享存储。例如：
  ```html
  <!DOCTYPE html>
  <html>
  <head>
    <title>Shared Storage Example</title>
  </head>
  <body>
    <script>
      navigator.sharedStorage.set('user_preference', 'dark_mode');
    </script>
  </body>
  </html>
  ```

* **CSS:**  Shared Storage API 本身不直接操作 CSS。但是，存储在 Shared Storage 中的数据可以通过 JavaScript 读取，并用来动态修改页面的 CSS 样式。例如：
  ```javascript
  navigator.sharedStorage.get('user_preference').then(preference => {
    if (preference === 'dark_mode') {
      document.body.classList.add('dark-theme'); // JavaScript 修改 CSS 类
    }
  });
  ```

**逻辑推理的假设输入与输出 (以 `set()` 方法为例):**

**假设输入:**

* **JavaScript 调用:** `navigator.sharedStorage.set('item_id', '12345')`
* **`SharedStorage::set()` 的参数:**
    * `script_state`: 当前脚本的执行状态。
    * `key`: "item_id"
    * `value`: "12345"
    * `options`:  一个 `SharedStorageSetMethodOptions` 对象，假设为空或包含默认值。
    * `exception_state`: 用于报告异常的状态对象。

**逻辑推理:**

1. 检查浏览上下文是否有效。
2. 检查安全源是否为 opaque（不透明）。
3. 检查共享存储的权限策略是否允许该操作。
4. 验证 `key` 和 `value` 的长度是否符合限制。
5. 创建一个 Mojo 方法调用，指示浏览器进程执行 set 操作。
6. 设置一个回调函数 `OnSharedStorageUpdateFinished` 来处理浏览器进程的响应。

**假设输出 (成功情况):**

* 浏览器进程成功存储数据。
* `OnSharedStorageUpdateFinished` 被调用，`error_message` 为空。
* 记录操作耗时的性能指标。
* `ScriptPromiseResolver` 解析 Promise，JavaScript 中 `set()` 方法返回的 Promise 会 resolve。

**假设输出 (失败情况 - 例如权限被拒绝):**

* 浏览器进程拒绝存储操作。
* `OnSharedStorageUpdateFinished` 被调用，`error_message` 包含拒绝原因。
* `ScriptPromiseResolver` 拒绝 Promise，JavaScript 中 `set()` 方法返回的 Promise 会 reject，并抛出一个 `DOMException`。

**用户或编程常见的使用错误举例:**

1. **Key 或 Value 长度超出限制:**
   ```javascript
   // 假设最大 Key 长度为 128
   navigator.sharedStorage.set('a'.repeat(200), 'some_value'); // 可能会导致 DataError
   ```
   **错误说明:**  `network::IsValidSharedStorageKeyStringLength` 或 `network::IsValidSharedStorageValueStringLength` 会检测到长度超限，导致 Promise 被 reject 并抛出 `DOMException`。

2. **在不允许的上下文中使用 `get()` (非 Fenced Frame):**
   ```javascript
   // 在普通的页面中尝试调用 get
   navigator.sharedStorage.get('some_key'); // 可能会导致 OperationError
   ```
   **错误说明:** `CanGetOutsideWorklet(script_state)` 会返回 `false`，导致 Promise 被 reject 并抛出 `DOMException`，提示只能在 Fenced Frame 中调用。

3. **权限策略阻止操作:**  如果站点的 Permissions Policy 设置不允许使用 Shared Storage，或者某些特定的操作（如读取），则尝试调用相关方法会导致 Promise 被 reject。

**用户操作如何一步步到达这里 (调试线索 - 以 `set()` 为例):**

1. **用户访问网页:** 用户通过浏览器访问一个使用了 Shared Storage API 的网页。
2. **JavaScript 执行:** 网页中的 JavaScript 代码被执行。
3. **调用 `navigator.sharedStorage.set()`:** JavaScript 代码调用了 `navigator.sharedStorage.set('someKey', 'someValue')`。
4. **V8 绑定:** V8 引擎捕获到这个 JavaScript 调用，并将其路由到对应的 Blink C++ 代码。
5. **`SharedStorage::set()` 被调用:**  `blink/renderer/modules/shared_storage/shared_storage.cc` 文件中的 `SharedStorage::set()` 方法被调用。
6. **权限检查和参数验证:**  `set()` 方法内部会进行一系列检查，例如权限策略和参数长度。
7. **Mojo 调用:**  如果检查通过，`set()` 方法会创建一个 Mojo 消息，发送给浏览器进程的 `SharedStorageDocumentService`。
8. **浏览器进程处理:** 浏览器进程接收到 Mojo 消息，执行实际的存储操作。
9. **Mojo 回复:** 浏览器进程将操作结果通过 Mojo 发送回渲染进程。
10. **`OnSharedStorageUpdateFinished` 被调用:**  渲染进程接收到 Mojo 回复，并调用之前绑定的回调函数 `OnSharedStorageUpdateFinished`。
11. **Promise 状态更新:** `OnSharedStorageUpdateFinished` 根据结果 resolve 或 reject JavaScript 的 Promise。

**总结 - 第 1 部分的功能:**

总而言之，`blink/renderer/modules/shared_storage/shared_storage.cc` 的第一部分主要负责实现 **Shared Storage API 的 JavaScript 接口**，处理来自 JavaScript 的调用，进行 **初步的权限检查和参数验证**，并通过 **Mojo 与浏览器进程通信**，将存储操作请求转发到浏览器进程进行实际处理。它还包含了 **性能监控和错误处理** 的逻辑，并初步支持了 **Fenced Frames 的特殊用例**。这部分代码是连接 JavaScript API 和底层浏览器存储机制的关键桥梁。

Prompt: 
```
这是目录为blink/renderer/modules/shared_storage/shared_storage.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/shared_storage/shared_storage.h"

#include <memory>
#include <tuple>
#include <utility>

#include "base/check.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "base/time/time.h"
#include "services/network/public/cpp/shared_storage_utils.h"
#include "services/network/public/mojom/shared_storage.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/shared_storage/shared_storage_utils.h"
#include "third_party/blink/public/mojom/shared_storage/shared_storage.mojom-blink.h"
#include "third_party/blink/public/mojom/shared_storage/shared_storage_worklet_service.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_worklet_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shared_storage_private_aggregation_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shared_storage_run_operation_method_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shared_storage_set_method_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shared_storage_url_with_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shared_storage_worklet_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_window_supplement.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet_global_scope.h"
#include "third_party/blink/renderer/modules/shared_storage/util.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

enum class GlobalScope {
  kWindow,
  kSharedStorageWorklet,
};

enum class SharedStorageSetterMethod {
  kSet = 0,
  kAppend = 1,
  kDelete = 2,
  kClear = 3,
};

void LogTimingHistogramForSetterMethod(SharedStorageSetterMethod method,
                                       GlobalScope global_scope,
                                       base::TimeTicks start_time) {
  base::TimeDelta elapsed_time = base::TimeTicks::Now() - start_time;

  std::string histogram_prefix = (global_scope == GlobalScope::kWindow)
                                     ? "Storage.SharedStorage.Document."
                                     : "Storage.SharedStorage.Worklet.";

  switch (method) {
    case SharedStorageSetterMethod::kSet:
      base::UmaHistogramMediumTimes(
          base::StrCat({histogram_prefix, "Timing.Set"}), elapsed_time);
      break;
    case SharedStorageSetterMethod::kAppend:
      base::UmaHistogramMediumTimes(
          base::StrCat({histogram_prefix, "Timing.Append"}), elapsed_time);
      break;
    case SharedStorageSetterMethod::kDelete:
      base::UmaHistogramMediumTimes(
          base::StrCat({histogram_prefix, "Timing.Delete"}), elapsed_time);
      break;
    case SharedStorageSetterMethod::kClear:
      base::UmaHistogramMediumTimes(
          base::StrCat({histogram_prefix, "Timing.Clear"}), elapsed_time);
      break;
    default:
      NOTREACHED();
  }
}

void OnSharedStorageUpdateFinished(ScriptPromiseResolver<IDLAny>* resolver,
                                   SharedStorage* shared_storage,
                                   SharedStorageSetterMethod method,
                                   GlobalScope global_scope,
                                   base::TimeTicks start_time,
                                   const String& error_message) {
  DCHECK(resolver);
  ScriptState* script_state = resolver->GetScriptState();

  if (!error_message.empty()) {
    if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                      script_state)) {
      ScriptState::Scope scope(script_state);
      resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kOperationError,
          error_message));
    }
    return;
  }

  LogTimingHistogramForSetterMethod(method, global_scope, start_time);
  resolver->Resolve();
}

mojom::blink::SharedStorageDocumentService* GetSharedStorageDocumentService(
    ExecutionContext* execution_context) {
  CHECK(execution_context->IsWindow());
  return SharedStorageWindowSupplement::From(
             To<LocalDOMWindow>(*execution_context))
      ->GetSharedStorageDocumentService();
}

mojom::blink::SharedStorageWorkletServiceClient*
GetSharedStorageWorkletServiceClient(ExecutionContext* execution_context) {
  CHECK(execution_context->IsSharedStorageWorkletGlobalScope());
  return To<SharedStorageWorkletGlobalScope>(execution_context)
      ->GetSharedStorageWorkletServiceClient();
}

bool CanGetOutsideWorklet(ScriptState* script_state) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow());

  LocalFrame* frame = To<LocalDOMWindow>(execution_context)->GetFrame();
  DCHECK(frame);

  if (!blink::features::IsFencedFramesEnabled()) {
    return false;
  }

  // Calling get() is only allowed in fenced frame trees where network access
  // has been restricted. We can't check the network access part in the
  // renderer, so we'll defer to the browser for that.
  return frame->IsInFencedFrameTree();
}

SharedStorageDataOrigin EnumToDataOrigin(
    V8SharedStorageDataOrigin::Enum data_origin_value) {
  switch (data_origin_value) {
    case V8SharedStorageDataOrigin::Enum::kContextOrigin:
      return SharedStorageDataOrigin::kContextOrigin;
    case V8SharedStorageDataOrigin::Enum::kScriptOrigin:
      return SharedStorageDataOrigin::kScriptOrigin;
  }
  NOTREACHED();
}

}  // namespace

class SharedStorage::IterationSource final
    : public PairAsyncIterable<SharedStorage>::IterationSource,
      public mojom::blink::SharedStorageEntriesListener {
 public:
  IterationSource(ScriptState* script_state,
                  ExecutionContext* execution_context,
                  Kind kind,
                  mojom::blink::SharedStorageWorkletServiceClient* client)
      : PairAsyncIterable<SharedStorage>::IterationSource(script_state, kind),
        receiver_(this, execution_context) {
    if (GetKind() == Kind::kKey) {
      client->SharedStorageKeys(receiver_.BindNewPipeAndPassRemote(
          execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI)));
    } else {
      client->SharedStorageEntries(receiver_.BindNewPipeAndPassRemote(
          execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI)));
    }

    base::UmaHistogramExactLinear(
        "Storage.SharedStorage.AsyncIterator.IteratedEntriesBenchmarks", 0,
        101);
  }

  void DidReadEntries(
      bool success,
      const String& error_message,
      Vector<mojom::blink::SharedStorageKeyAndOrValuePtr> entries,
      bool has_more_entries,
      int total_queued_to_send) override {
    CHECK(is_waiting_for_more_entries_);
    CHECK(error_message_.IsNull());
    CHECK(!(success && entries.empty() && has_more_entries));

    if (!success) {
      if (error_message.IsNull()) {
        error_message_ = g_empty_string;
      } else {
        error_message_ = error_message;
      }
    }

    for (auto& entry : entries) {
      shared_storage_entry_queue_.push_back(std::move(entry));
    }
    is_waiting_for_more_entries_ = has_more_entries;

    // Benchmark
    if (!total_entries_queued_) {
      total_entries_queued_ = total_queued_to_send;
      base::UmaHistogramCounts10000(
          "Storage.SharedStorage.AsyncIterator.EntriesQueuedCount",
          total_entries_queued_);
    }
    base::CheckedNumeric<int> count = entries_received_;
    count += entries.size();
    entries_received_ = count.ValueOrDie();
    while (next_benchmark_for_receipt_ <= 100 &&
           MeetsBenchmark(entries_received_, next_benchmark_for_receipt_)) {
      base::UmaHistogramExactLinear(
          "Storage.SharedStorage.AsyncIterator.ReceivedEntriesBenchmarks",
          next_benchmark_for_receipt_, 101);
      next_benchmark_for_receipt_ += kBenchmarkStep;
    }

    ScriptState::Scope script_state_scope(GetScriptState());
    TryResolvePromise();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(receiver_);
    PairAsyncIterable<SharedStorage>::IterationSource::Trace(visitor);
  }

 protected:
  void GetNextIterationResult() override {
    DCHECK(!next_start_time_);
    next_start_time_ = base::TimeTicks::Now();

    TryResolvePromise();
  }

 private:
  void TryResolvePromise() {
    if (!HasPendingPromise()) {
      return;
    }

    if (!shared_storage_entry_queue_.empty()) {
      mojom::blink::SharedStorageKeyAndOrValuePtr entry =
          shared_storage_entry_queue_.TakeFirst();
      TakePendingPromiseResolver()->Resolve(
          MakeIterationResult(entry->key, entry->value));
      LogElapsedTime();

      base::CheckedNumeric<int> count = entries_iterated_;
      entries_iterated_ = (++count).ValueOrDie();

      while (next_benchmark_for_iteration_ <= 100 &&
             MeetsBenchmark(entries_iterated_, next_benchmark_for_iteration_)) {
        base::UmaHistogramExactLinear(
            "Storage.SharedStorage.AsyncIterator.IteratedEntriesBenchmarks",
            next_benchmark_for_iteration_, 101);
        next_benchmark_for_iteration_ += kBenchmarkStep;
      }

      return;
    }

    if (!error_message_.IsNull()) {
      TakePendingPromiseResolver()->Reject(V8ThrowDOMException::CreateOrEmpty(
          GetScriptState()->GetIsolate(), DOMExceptionCode::kOperationError,
          error_message_));
      // We only record timing histograms when there is no error. Discard the
      // start time for this call.
      DCHECK(next_start_time_);
      next_start_time_.reset();
      return;
    }

    if (!is_waiting_for_more_entries_) {
      TakePendingPromiseResolver()->Resolve(MakeEndOfIteration());
      LogElapsedTime();
      return;
    }
  }

  bool MeetsBenchmark(int value, int benchmark) {
    CHECK_GE(benchmark, 0);
    CHECK_LE(benchmark, 100);
    CHECK_EQ(benchmark % kBenchmarkStep, 0);
    CHECK_GE(total_entries_queued_, 0);

    if (benchmark == 0 || (total_entries_queued_ == 0 && value == 0)) {
      return true;
    }

    CHECK_GT(total_entries_queued_, 0);
    return (100 * value) / total_entries_queued_ >= benchmark;
  }

  void LogElapsedTime() {
    CHECK(next_start_time_);
    base::TimeDelta elapsed_time = base::TimeTicks::Now() - *next_start_time_;
    next_start_time_.reset();
    switch (GetKind()) {
      case Kind::kKey:
        base::UmaHistogramMediumTimes(
            "Storage.SharedStorage.Worklet.Timing.Keys.Next", elapsed_time);
        break;
      case Kind::kValue:
        base::UmaHistogramMediumTimes(
            "Storage.SharedStorage.Worklet.Timing.Values.Next", elapsed_time);
        break;
      case Kind::kKeyValue:
        base::UmaHistogramMediumTimes(
            "Storage.SharedStorage.Worklet.Timing.Entries.Next", elapsed_time);
        break;
    }
  }

  HeapMojoReceiver<mojom::blink::SharedStorageEntriesListener, IterationSource>
      receiver_;
  // Queue of the successful results.
  Deque<mojom::blink::SharedStorageKeyAndOrValuePtr>
      shared_storage_entry_queue_;
  String error_message_;  // Non-null string means error.
  bool is_waiting_for_more_entries_ = true;

  // Benchmark
  //
  // The total number of entries that the database has queued to send via this
  // iterator.
  int total_entries_queued_ = 0;
  // The number of entries that the iterator has received from the database so
  // far.
  int entries_received_ = 0;
  // The number of entries that the iterator has iterated through.
  int entries_iterated_ = 0;
  // The lowest benchmark for received entries that is currently unmet and so
  // has not been logged.
  int next_benchmark_for_receipt_ = 0;
  // The lowest benchmark for iterated entries that is currently unmet and so
  // has not been logged.
  int next_benchmark_for_iteration_ = kBenchmarkStep;
  // The step size of received / iterated entries.
  static constexpr int kBenchmarkStep = 10;
  // Start time of each call to GetTheNextIterationResult. Used to record a
  // timing histogram.
  std::optional<base::TimeTicks> next_start_time_;
};

SharedStorage::SharedStorage() = default;
SharedStorage::~SharedStorage() = default;

void SharedStorage::Trace(Visitor* visitor) const {
  visitor->Trace(shared_storage_worklet_);
  ScriptWrappable::Trace(visitor);
}

ScriptPromise<IDLAny> SharedStorage::set(ScriptState* script_state,
                                         const String& key,
                                         const String& value,
                                         ExceptionState& exception_state) {
  return set(script_state, key, value, SharedStorageSetMethodOptions::Create(),
             exception_state);
}

ScriptPromise<IDLAny> SharedStorage::set(
    ScriptState* script_state,
    const String& key,
    const String& value,
    const SharedStorageSetMethodOptions* options,
    ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow() ||
        execution_context->IsSharedStorageWorkletGlobalScope());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state))
    return EmptyPromise();

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (execution_context->IsWindow() &&
      execution_context->GetSecurityOrigin()->IsOpaque()) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        kOpaqueContextOriginCheckErrorMessage));
    return promise;
  }

  if (!CheckSharedStoragePermissionsPolicy(*script_state, *execution_context,
                                           *resolver)) {
    return promise;
  }

  if (!network::IsValidSharedStorageKeyStringLength(key.length())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Length of the \"key\" parameter is not valid."));
    return promise;
  }

  if (!network::IsValidSharedStorageValueStringLength(value.length())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Length of the \"value\" parameter is not valid."));
    return promise;
  }

  bool ignore_if_present =
      options->hasIgnoreIfPresent() && options->ignoreIfPresent();

  auto method =
      network::mojom::blink::SharedStorageModifierMethod::NewSetMethod(
          network::mojom::blink::SharedStorageSetMethod::New(
              key, value, ignore_if_present));

  if (execution_context->IsWindow()) {
    GetSharedStorageDocumentService(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kSet, GlobalScope::kWindow,
                          start_time));
  } else {
    GetSharedStorageWorkletServiceClient(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kSet,
                          GlobalScope::kSharedStorageWorklet, start_time));
  }

  return promise;
}

ScriptPromise<IDLAny> SharedStorage::append(ScriptState* script_state,
                                            const String& key,
                                            const String& value,
                                            ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow() ||
        execution_context->IsSharedStorageWorkletGlobalScope());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state))
    return EmptyPromise();

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (execution_context->IsWindow() &&
      execution_context->GetSecurityOrigin()->IsOpaque()) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        kOpaqueContextOriginCheckErrorMessage));
    return promise;
  }

  if (!CheckSharedStoragePermissionsPolicy(*script_state, *execution_context,
                                           *resolver)) {
    return promise;
  }

  if (!network::IsValidSharedStorageKeyStringLength(key.length())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Length of the \"key\" parameter is not valid."));
    return promise;
  }

  if (!network::IsValidSharedStorageValueStringLength(value.length())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Length of the \"value\" parameter is not valid."));
    return promise;
  }

  auto method =
      network::mojom::blink::SharedStorageModifierMethod::NewAppendMethod(
          network::mojom::blink::SharedStorageAppendMethod::New(key, value));

  if (execution_context->IsWindow()) {
    GetSharedStorageDocumentService(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kAppend,
                          GlobalScope::kWindow, start_time));
  } else {
    GetSharedStorageWorkletServiceClient(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kAppend,
                          GlobalScope::kSharedStorageWorklet, start_time));
  }

  return promise;
}

ScriptPromise<IDLAny> SharedStorage::Delete(ScriptState* script_state,
                                            const String& key,
                                            ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow() ||
        execution_context->IsSharedStorageWorkletGlobalScope());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state))
    return EmptyPromise();

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (execution_context->IsWindow() &&
      execution_context->GetSecurityOrigin()->IsOpaque()) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        kOpaqueContextOriginCheckErrorMessage));
    return promise;
  }

  if (!CheckSharedStoragePermissionsPolicy(*script_state, *execution_context,
                                           *resolver)) {
    return promise;
  }

  if (!network::IsValidSharedStorageKeyStringLength(key.length())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Length of the \"key\" parameter is not valid."));
    return promise;
  }

  auto method =
      network::mojom::blink::SharedStorageModifierMethod::NewDeleteMethod(
          network::mojom::blink::SharedStorageDeleteMethod::New(key));

  if (execution_context->IsWindow()) {
    GetSharedStorageDocumentService(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kDelete,
                          GlobalScope::kWindow, start_time));
  } else {
    GetSharedStorageWorkletServiceClient(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kDelete,
                          GlobalScope::kSharedStorageWorklet, start_time));
  }

  return promise;
}

ScriptPromise<IDLAny> SharedStorage::clear(ScriptState* script_state,
                                           ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow() ||
        execution_context->IsSharedStorageWorkletGlobalScope());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state))
    return EmptyPromise();

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (execution_context->IsWindow() &&
      execution_context->GetSecurityOrigin()->IsOpaque()) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        kOpaqueContextOriginCheckErrorMessage));
    return promise;
  }

  if (!CheckSharedStoragePermissionsPolicy(*script_state, *execution_context,
                                           *resolver)) {
    return promise;
  }

  auto method =
      network::mojom::blink::SharedStorageModifierMethod::NewClearMethod(
          network::mojom::blink::SharedStorageClearMethod::New());

  if (execution_context->IsWindow()) {
    GetSharedStorageDocumentService(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kClear,
                          GlobalScope::kWindow, start_time));
  } else {
    GetSharedStorageWorkletServiceClient(execution_context)
        ->SharedStorageUpdate(
            std::move(method),
            WTF::BindOnce(&OnSharedStorageUpdateFinished,
                          WrapPersistent(resolver), WrapPersistent(this),
                          SharedStorageSetterMethod::kClear,
                          GlobalScope::kSharedStorageWorklet, start_time));
  }

  return promise;
}

ScriptPromise<IDLString> SharedStorage::get(ScriptState* script_state,
                                            const String& key,
                                            ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow() ||
        execution_context->IsSharedStorageWorkletGlobalScope());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state)) {
    return EmptyPromise();
  }

  ScriptPromiseResolver<IDLString>* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (execution_context->IsWindow()) {
    if (execution_context->GetSecurityOrigin()->IsOpaque()) {
      resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
          kOpaqueContextOriginCheckErrorMessage));
      return promise;
    }

    if (!CanGetOutsideWorklet(script_state)) {
      resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kOperationError,
          "Cannot call get() outside of a fenced frame."));
      return promise;
    }

    if (!base::FeatureList::IsEnabled(
            blink::features::kFencedFramesLocalUnpartitionedDataAccess)) {
      resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kOperationError,
          "Cannot call get() in a fenced frame with feature "
          "FencedFramesLocalUnpartitionedDataAccess disabled."));
      return promise;
    }

    if (!execution_context->IsFeatureEnabled(
        mojom::blink::PermissionsPolicyFeature::
            kFencedUnpartitionedStorageRead)) {
      resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kOperationError,
          "Cannot call get() in a fenced frame without the "
          "fenced-unpartitioned-storage-read Permissions Policy feature "
          "enabled."));
      return promise;
    }
  }

  CHECK(CheckSharedStoragePermissionsPolicy(*script_state, *execution_context,
                                            *resolver));

  if (!network::IsValidSharedStorageKeyStringLength(key.length())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Length of the \"key\" parameter is not valid."));
    return promise;
  }

  std::string histogram_name = execution_context->IsWindow()
                                   ? "Storage.SharedStorage.Document.Timing.Get"
                                   : "Storage.SharedStorage.Worklet.Timing.Get";
  auto callback = WTF::BindOnce(
      [](ScriptPromiseResolver<IDLString>* resolver,
         SharedStorage* shared_storage, base::TimeTicks start_time,
         const std::string& histogram_name,
         mojom::blink::SharedStorageGetStatus status,
         const String& error_message, const String& value) {
        DCHECK(resolver);
        ScriptState* script_state = resolver->GetScriptState();

        if (status == mojom::blink::SharedStorageGetStatus::kError) {
          if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                            script_state)) {
            ScriptState::Scope scope(script_state);
            resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                script_state->GetIsolate(), DOMExceptionCode::kOperationError,
                error_message));
          }
          return;
        }

        base::UmaHistogramMediumTimes(histogram_name,
                                      base::TimeTicks::Now() - start_time);

        if (status == mojom::blink::SharedStorageGetStatus::kSuccess) {
          resolver->Resolve(value);
          return;
        }

        CHECK_EQ(status, mojom::blink::SharedStorageGetStatus::kNotFound);
        resolver->Resolve();
      },
      WrapPersistent(resolver), WrapPersistent(this), start_time,
      histogram_name);

  if (execution_context->IsWindow()) {
    GetSharedStorageDocumentService(execution_context)
        ->SharedStorageGet(key, std::move(callback));
  } else {
    GetSharedStorageWorkletServiceClient(execution_context)
        ->SharedStorageGet(key, std::move(callback));
  }

  return promise;
}

ScriptPromise<IDLUnsignedLong> SharedStorage::length(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsSharedStorageWorkletGlobalScope());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUnsignedLong>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  CHECK(CheckSharedStoragePermissionsPolicy(*script_state, *execution_context,
                                            *resolver));

  GetSharedStorageWorkletServiceClient(execution_context)
      ->SharedStorageLength(WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUnsignedLong>* resolver,
             SharedStorage* shared_storage, base::TimeTicks start_time,
             bool success, const String& error_message, uint32_t length) {
            DCHECK(resolver);
            ScriptState* script_state = resolver->GetScriptState();

            if (!success) {
              if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                                script_state)) {
                ScriptState::Scope scope(script_state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    script_state->GetIsolate(),
                    DOMExceptionCode::kOperationError, error_message));
              }
              return;
            }

            base::UmaHistogramMediumTimes(
                "Storage.SharedStorage.Worklet.Timing.Length",
                base::TimeTicks::Now() - start_time);

            resolver->Resolve(length);
          },
          WrapPersistent(resolver), WrapPersistent(this), start_time));

  return promise;
}

ScriptPromise<IDLDouble> SharedStorage::remainingBudget(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsSharedStorageWorkletGlobalScope());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLDouble>>(
      script_state, exception_state.GetContext());
  ScriptPromise<IDLDouble> promise = resolver->Promise();

  CHECK(CheckSharedStoragePermissionsPolicy(*script_state, *execution_context,
                                            *resolver));

  GetSharedStorageWorkletServiceClient(execution_context)
      ->SharedStorageRemainingBudget(WTF::BindOnce(
          [](ScriptPromiseResolver<IDLDouble>* resolver,
             SharedStorage* shared_storage, base::TimeTicks start_time,
             bool success, const String& error_message, double bits) {
            DCHECK(resolver);
            ScriptState* script_state = resolver->GetScriptState();

            if (!success) {
              if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                                script_state)) {
                ScriptState::Scope scope(script_state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    script_state->GetIsolate(),
                    DOMExceptionCode::kOperationError, error_message));
    
"""


```