Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. The code is a unit test file for the Shared Storage Worklet feature in the Chromium Blink engine.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The file name `shared_storage_worklet_unittest.cc` immediately suggests its purpose: to test the functionality of the Shared Storage Worklet. Unit tests verify individual components in isolation.

2. **Scan for key classes and namespaces:**  The `blink` namespace and classes like `SharedStorageWorkletTest`, `TestClient`, `MockMojomPrivateAggregationHost`, and `MockMojomCoceCacheHost` are crucial. These hint at the different aspects being tested.

3. **Analyze the test fixtures:** The `SharedStorageWorkletTest` class is the main test fixture. Its member functions like `AddModule`, `SelectURL`, and `Run` represent the core operations that a Shared Storage Worklet can perform.

4. **Examine helper classes:**
    * `TestClient`:  This class mocks the client-side interaction with the worklet, allowing tests to simulate how the browser interacts with the worklet. The methods like `SharedStorageUpdate`, `SharedStorageGet`, `DidAddMessageToConsole`, and `RecordUseCounters` indicate the types of interactions being tested.
    * `TestWorkletDevToolsHost`: This suggests testing the integration with developer tools.
    * `MockMojomPrivateAggregationHost`: This points to testing the Private Aggregation API integration within the worklet.
    * `MockMojomCoceCacheHost`:  This suggests tests related to code caching for worklets.

5. **Look at included headers:** The included headers reveal dependencies and functionalities:
    * `<memory>`, `<string>`, `<vector>`: Basic C++ data structures.
    * `"base/*"`:  Chromium base library utilities.
    * `"gin/*"`:  Integration with V8 JavaScript engine.
    * `"mojo/*"`:  Inter-process communication.
    * `"services/network/*"`: Network-related functionality, especially `shared_storage.mojom.h`.
    * `"third_party/blink/public/mojom/*"`:  Blink's Mojo interfaces, including those for Shared Storage, Aggregation Service, Blobs, Interest Groups, Code Cache, Private Aggregation, and Workers.
    * `"third_party/blink/renderer/*"`:  Blink's rendering engine code, specifically modules related to Shared Storage and workers.

6. **Infer functionality from test method names (even though not fully included):**  The provided code shows the setup and helper functions of the test suite. Even without the actual `TEST_F` definitions, the existence of `AddModule`, `SelectURL`, and `Run` functions strongly implies that the tests cover adding modules to the worklet and running operations within it.

7. **Consider potential interactions with web technologies:** The presence of "javascript," "html," and "css" in the prompt requires linking the C++ code to these technologies. Shared Storage Worklets execute JavaScript code. While they don't directly manipulate HTML or CSS, their results (like selecting a URL) could indirectly influence how a website behaves or renders.

8. **Think about user errors and debugging:**  Since it's a test file, it likely simulates scenarios that could lead to errors. The tests would check for correct error reporting and handling. Understanding the flow of user actions leading to the worklet execution is relevant for debugging.

9. **Structure the summary:** Organize the findings into logical categories: Core Functionality, Relationship with Web Technologies, Logic and Data Flow (even if hypothetical), Common Errors, and Debugging Clues.

10. **Refine and expand:** Flesh out each section with specific examples and details based on the code analysis. For instance, when mentioning JavaScript, connect it to the `AddModule` functionality and the execution of scripts within the worklet. For debugging, discuss how user actions trigger Shared Storage operations.

By following this systematic approach, we can generate a comprehensive summary of the functionality of the given C++ unit test file.
这是 `blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc` 文件的第一部分，它主要的功能是**为 Blink 引擎中的 Shared Storage Worklet 功能编写单元测试**。

更具体地说，这部分代码定义了用于测试 Shared Storage Worklet 的基础架构和辅助类，以便能够模拟和验证 worklet 的各种行为。

以下是根据提供的代码片段归纳的功能点：

**1. 测试基础架构搭建:**

* **包含了必要的头文件:**  引入了各种 Chromium 和 Blink 相关的头文件，用于处理内存管理、字符串操作、函数回调、并发、测试框架 (gtest, gmock)、Mojo 绑定、网络请求、以及 Blink 引擎特定的模块（如 Shared Storage、Private Aggregation、Code Cache 等）。
* **定义了命名空间和常量:** 使用了 `blink` 命名空间，并定义了像 `kModuleScriptSource` 这样的常量，用于测试中模拟模块脚本的来源。
* **定义了各种结果结构体:**  定义了 `VoidOperationResult`, `AddModuleResult`, `RunResult`, `SelectURLResult`, `GetResult`, `LengthResult`, `RemainingBudgetResult` 等结构体，用于统一表示异步操作的结果，包括成功状态、错误消息和可能的返回值。
* **定义了辅助函数:** 提供了 `CreateBatchResult` 函数，用于方便地创建 `SharedStorageKeyAndOrValuePtr` 向量，这在测试批量操作时非常有用。

**2. 模拟 Worklet 的宿主环境:**

* **定义了 `TestWorkletDevToolsHost` 类:**  这是一个用于模拟 Worklet 的开发者工具宿主的类。它可以用来测试 Worklet 是否正确地通知开发者工具准备好进行检查。
* **定义了 `TestClient` 类:**  这是关键的模拟客户端类，用于模拟浏览器或渲染器与 Shared Storage Worklet 之间的交互。它实现了 `blink::mojom::SharedStorageWorkletServiceClient` 接口，可以：
    * 捕获 worklet 发起的 `SharedStorageUpdate` (修改共享存储) 请求。
    * 捕获 worklet 发起的 `SharedStorageGet` (读取共享存储) 请求。
    * 捕获 worklet 发起的 `SharedStorageKeys` 和 `SharedStorageEntries` (枚举共享存储键或键值对) 请求。
    * 捕获 worklet 发起的 `SharedStorageLength` (获取共享存储大小) 请求。
    * 捕获 worklet 发起的 `SharedStorageRemainingBudget` (获取剩余预算) 请求。
    * 捕获 worklet 发起的 `GetInterestGroups` (获取兴趣组) 请求。
    * 捕获 worklet 输出的控制台日志消息 (`DidAddMessageToConsole`).
    * 捕获 worklet 使用的 Web 功能 (`RecordUseCounters`).
    * 允许测试设置这些操作的模拟返回值。
* **定义了 `MockMojomPrivateAggregationHost` 类:**  这是一个用于模拟 Private Aggregation Host 的 Mock 类，用于测试 Worklet 与 Private Aggregation API 的集成。
* **定义了 `MockMojomCoceCacheHost` 类:**  这是一个用于模拟 Code Cache Host 的 Mock 类，用于测试 Worklet 的代码缓存机制。

**3. 定义了测试 Fixture `SharedStorageWorkletTest`:**

* **继承自 `PageTestBase`:**  表明这是一个基于 Blink 渲染引擎的集成测试。
* **提供了 `AddModule` 方法:**  用于测试向 Worklet 添加模块脚本的功能。它可以模拟脚本下载成功或失败的情况。
* **提供了 `SelectURL` 方法:**  用于测试 Worklet 的 URL 选择操作。
* **提供了 `Run` 方法:**  用于测试 Worklet 的通用操作执行。
* **提供了 `MaybeInitPAOperationDetails` 方法:**  用于辅助创建包含 Private Aggregation 操作细节的 Mojo 结构体。
* **提供了 `CreateSerializedUndefined` 和 `CreateSerializedDict` 方法:** 用于创建序列化的 JavaScript 值，以便在 Worklet 中传递数据。
* **包含了 Scoped Feature List:**  使用 `ScopedSharedStorageAPIM125ForTest`, `ScopedInterestGroupsInSharedStorageWorkletForTest`, `ScopedSharedStorageWebLocksForTest` 来控制特定功能是否启用，以便针对不同的功能组合进行测试。
* **持有了指向 `SharedStorageWorkletService` 的 `mojo::Remote`:** 这是与实际 Worklet 服务通信的接口。
* **持有了指向 `SharedStorageWorkletMessagingProxy` 的 `Persistent` 指针:**  这代表了 Worklet 的消息代理。
* **持有了测试辅助类的实例:**  `test_client_`, `test_worklet_devtools_host_`, `mock_private_aggregation_host_`, `mock_code_cache_host_`。
* **提供了 `InitializeWorkletServiceOnce` 方法:**  用于初始化 Worklet 服务及其相关的 Mock 对象。

**与 JavaScript, HTML, CSS 的关系 (基于推断，因为只提供了部分代码):**

* **JavaScript:**  Worklet 的核心是执行 JavaScript 代码。`AddModule` 方法就是用于加载和执行 JavaScript 模块的。测试会验证 JavaScript 代码的执行结果，例如是否正确地调用了共享存储相关的 API。例如，在测试中，你可以编写 JavaScript 代码，使用 `sharedStorage.set('key', 'value')`，然后通过 `TestClient` 检查是否收到了相应的 `SharedStorageUpdate` 请求。
* **HTML:** 虽然这个测试文件本身不直接涉及 HTML，但 Shared Storage Worklet 是由 HTML 页面中的 JavaScript 代码创建和控制的。用户通过与 HTML 页面交互，例如点击按钮，可能会触发 JavaScript 代码来启动 Worklet 操作。
* **CSS:**  CSS 与 Shared Storage Worklet 的关系较为间接。Worklet 的执行结果可能会影响页面的状态或行为，间接地影响 CSS 的应用或计算结果。例如，Worklet 可以根据共享存储中的数据选择一个 URL，然后 JavaScript 可以根据这个 URL 加载不同的 CSS 文件。

**逻辑推理的假设输入与输出 (基于已有的方法名):**

* **假设输入 (AddModule):**
    * `script_content`:  一个包含 JavaScript 代码的字符串，例如 `"sharedStorage.set('myKey', 'myValue');"`
    * `mime_type`:  指定脚本的 MIME 类型，例如 `"application/javascript"`
* **预期输出 (AddModuleResult):**
    * `success`:  如果脚本成功加载和编译，则为 `true`，否则为 `false`。
    * `error_message`: 如果加载或编译失败，则包含错误消息。

* **假设输入 (Run):**
    * `name`:  Worklet 中注册的操作名称，例如 `"myOperation"`.
    * `serialized_data`:  传递给 Worklet 操作的序列化数据。
* **预期输出 (RunResult):**
    * `success`:  如果 Worklet 操作成功执行，则为 `true`，否则为 `false`。
    * `error_message`: 如果执行失败，则包含错误消息。

* **假设输入 (SelectURL):**
    * `name`: Worklet 中注册的 URL 选择操作名称。
    * `urls`:  一个包含多个 URL 的向量。
    * `serialized_data`: 传递给 Worklet 操作的序列化数据。
* **预期输出 (SelectURLResult):**
    * `success`: 如果操作成功，则为 `true`。
    * `error_message`: 如果操作失败，则包含错误消息。
    * `index`:  Worklet 选择的 URL 在 `urls` 向量中的索引。

**用户或编程常见的使用错误 (基于推断):**

* **JavaScript 语法错误:** 在 `AddModule` 中提供的 `script_content` 包含 JavaScript 语法错误，例如 `AddModule("let a")`。这将导致 `AddModuleResult.success` 为 `false`，并且 `error_message` 中包含语法错误的详细信息。
* **尝试在 `addModule` 期间访问 `sharedStorage` 或 `navigator`:**  根据后续的测试代码，尝试在 `addModule` 回调中访问 `sharedStorage` 或 `navigator` 对象是禁止的，这可能会导致错误。
* **Worklet 操作名称拼写错误:** 在 `Run` 或 `SelectURL` 中使用的 `name` 参数与 Worklet 中注册的操作名称不匹配，导致操作无法找到并执行。
* **传递给 Worklet 的数据格式不正确:** `serialized_data` 的格式与 Worklet 期望的格式不一致，导致 Worklet 执行失败。
* **超过共享存储的配额:** Worklet 尝试写入超过配额的数据到共享存储。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户访问一个网页:** 用户在浏览器中打开一个包含 Shared Storage 功能的网页。
2. **网页 JavaScript 调用 Shared Storage API:** 网页上的 JavaScript 代码调用了 Shared Storage 相关的 API，例如 `navigator.sharedStorage.run('myOperation', data)` 或 `navigator.sharedStorage.selectURL('myURLSelection', urls, data)`.
3. **浏览器触发 Worklet 执行:**  浏览器接收到这些 API 调用后，会创建或复用一个 Shared Storage Worklet 实例，并将操作分发给它。
4. **Worklet 加载和执行模块:** 如果 Worklet 还没有加载过模块，或者需要加载新的模块，浏览器会根据配置加载指定的 JavaScript 模块（这就是 `AddModule` 测试所模拟的）。
5. **Worklet 执行指定的操作:** Worklet 内部的 JavaScript 代码会执行 `run` 或 `selectURL` 等操作中定义的回调函数。
6. **Worklet 与浏览器交互:** 在执行过程中，Worklet 可能会调用 `sharedStorage.set()`, `sharedStorage.get()`, `interestGroups()` 等 API 与浏览器进行交互。这些交互对应着 `TestClient` 中捕获的各种请求。
7. **测试捕获交互并验证结果:**  在单元测试中，`TestClient` 会捕获这些交互，允许测试代码验证 Worklet 是否按照预期的方式与浏览器进行通信，并且操作的结果是否正确。

这个测试文件的目的是确保当用户通过网页上的 JavaScript 代码触发 Shared Storage Worklet 的各种操作时，Blink 引擎中的相关逻辑能够正确执行。通过模拟各种场景和错误情况，开发者可以确保 Shared Storage Worklet 的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/barrier_closure.h"
#include "base/check_op.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_future.h"
#include "gin/array_buffer.h"
#include "gin/dictionary.h"
#include "gin/public/isolate_holder.h"
#include "mojo/public/cpp/bindings/associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "services/network/public/mojom/shared_storage.mojom.h"
#include "services/network/test/test_url_loader_factory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/numeric/int128.h"
#include "third_party/blink/public/common/messaging/cloneable_message_mojom_traits.h"
#include "third_party/blink/public/common/shared_storage/shared_storage_utils.h"
#include "third_party/blink/public/mojom/aggregation_service/aggregatable_report.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/blob.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/blob.mojom.h"
#include "third_party/blink/public/mojom/interest_group/interest_group_types.mojom.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/mojom/private_aggregation/private_aggregation_host.mojom-blink.h"
#include "third_party/blink/public/mojom/shared_storage/shared_storage_worklet_service.mojom.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/mojom/worker/worklet_global_scope_creation_params.mojom-blink.h"
#include "third_party/blink/public/platform/cross_variant_mojo_util.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/messaging/blink_cloneable_message_mojom_traits.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/workers/worker_thread_test_helper.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet_messaging_proxy.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "v8/include/v8-isolate.h"

namespace blink {

namespace {

constexpr char kModuleScriptSource[] = "https://foo.com/module_script.js";
constexpr char kMaxChar16StringLengthPlusOneLiteral[] = "2621441";
constexpr base::Time kScriptResponseTime =
    base::Time::FromDeltaSinceWindowsEpoch(base::Days(100));

struct VoidOperationResult {
  bool success = true;
  std::string error_message;
};

using AddModuleResult = VoidOperationResult;
using RunResult = VoidOperationResult;

struct SelectURLResult {
  bool success = true;
  std::string error_message;
  uint32_t index = 0;
};

struct GetResult {
  blink::mojom::SharedStorageGetStatus status =
      blink::mojom::SharedStorageGetStatus::kSuccess;
  std::string error_message;
  std::u16string value;
};

struct LengthResult {
  bool success = true;
  std::string error_message;
  uint32_t length = 0;
};

struct RemainingBudgetResult {
  bool success = true;
  std::string error_message;
  double bits = 0;
};

std::vector<blink::mojom::SharedStorageKeyAndOrValuePtr> CreateBatchResult(
    std::vector<std::pair<std::u16string, std::u16string>> input) {
  std::vector<blink::mojom::SharedStorageKeyAndOrValuePtr> result;
  for (const auto& p : input) {
    blink::mojom::SharedStorageKeyAndOrValuePtr e =
        blink::mojom::SharedStorageKeyAndOrValue::New(p.first, p.second);
    result.push_back(std::move(e));
  }
  return result;
}

class TestWorkletDevToolsHost : public mojom::blink::WorkletDevToolsHost {
 public:
  explicit TestWorkletDevToolsHost(
      mojo::PendingReceiver<mojom::blink::WorkletDevToolsHost> receiver)
      : receiver_(this, std::move(receiver)) {}

  void OnReadyForInspection(
      mojo::PendingRemote<mojom::blink::DevToolsAgent> agent,
      mojo::PendingReceiver<mojom::blink::DevToolsAgentHost> agent_host)
      override {
    EXPECT_FALSE(ready_for_inspection_);
    ready_for_inspection_ = true;
  }

  void FlushForTesting() { receiver_.FlushForTesting(); }

  bool ready_for_inspection() const { return ready_for_inspection_; }

 private:
  bool ready_for_inspection_ = false;

  mojo::Receiver<mojom::blink::WorkletDevToolsHost> receiver_{this};
};

class TestClient : public blink::mojom::SharedStorageWorkletServiceClient {
 public:
  explicit TestClient(mojo::PendingAssociatedReceiver<
                      blink::mojom::SharedStorageWorkletServiceClient> receiver)
      : receiver_(this, std::move(receiver)) {}

  void SharedStorageUpdate(
      network::mojom::SharedStorageModifierMethodPtr method,
      SharedStorageUpdateCallback callback) override {
    observed_update_params_.push_back(std::move(method));

    std::move(callback).Run(update_result_error_message_);
  }

  void SharedStorageGet(const std::u16string& key,
                        SharedStorageGetCallback callback) override {
    observed_get_params_.push_back(key);
    std::move(callback).Run(get_result_.status, get_result_.error_message,
                            get_result_.value);
  }

  void SharedStorageKeys(
      mojo::PendingRemote<blink::mojom::SharedStorageEntriesListener>
          pending_listener) override {
    pending_keys_listeners_.push_back(std::move(pending_listener));
  }

  void SharedStorageEntries(
      mojo::PendingRemote<blink::mojom::SharedStorageEntriesListener>
          pending_listener) override {
    pending_entries_listeners_.push_back(std::move(pending_listener));
  }

  void SharedStorageLength(SharedStorageLengthCallback callback) override {
    observed_length_count_++;
    std::move(callback).Run(length_result_.success,
                            length_result_.error_message,
                            length_result_.length);
  }

  void SharedStorageRemainingBudget(
      SharedStorageRemainingBudgetCallback callback) override {
    observed_remaining_budget_count_++;
    std::move(callback).Run(remaining_budget_result_.success,
                            remaining_budget_result_.error_message,
                            remaining_budget_result_.bits);
  }

  void GetInterestGroups(GetInterestGroupsCallback callback) override {
    observed_get_interest_groups_count_++;
    std::move(callback).Run(std::move(interest_groups_result_));
  }

  void DidAddMessageToConsole(blink::mojom::ConsoleMessageLevel level,
                              const std::string& message) override {
    observed_console_log_messages_.push_back(message);
  }

  void RecordUseCounters(
      const std::vector<mojom::WebFeature>& features) override {
    base::ranges::for_each(features, [&](mojom::WebFeature feature) {
      observed_use_counters_.push_back(feature);
    });
  }

  mojo::Remote<blink::mojom::SharedStorageEntriesListener>
  TakeKeysListenerAtFront() {
    CHECK(!pending_keys_listeners_.empty());

    auto pending_listener = std::move(pending_keys_listeners_.front());
    pending_keys_listeners_.pop_front();

    return mojo::Remote<blink::mojom::SharedStorageEntriesListener>(
        std::move(pending_listener));
  }

  mojo::Remote<blink::mojom::SharedStorageEntriesListener>
  TakeEntriesListenerAtFront() {
    CHECK(!pending_entries_listeners_.empty());

    auto pending_listener = std::move(pending_entries_listeners_.front());
    pending_entries_listeners_.pop_front();

    return mojo::Remote<blink::mojom::SharedStorageEntriesListener>(
        std::move(pending_listener));
  }

  std::deque<mojo::PendingRemote<blink::mojom::SharedStorageEntriesListener>>
      pending_keys_listeners_;

  std::deque<mojo::PendingRemote<blink::mojom::SharedStorageEntriesListener>>
      pending_entries_listeners_;

  std::vector<network::mojom::SharedStorageModifierMethodPtr>
      observed_update_params_;
  std::vector<std::u16string> observed_get_params_;
  size_t observed_length_count_ = 0;
  size_t observed_remaining_budget_count_ = 0;
  size_t observed_get_interest_groups_count_ = 0;
  std::vector<std::string> observed_console_log_messages_;
  std::vector<mojom::WebFeature> observed_use_counters_;

  // Default results to be returned for corresponding operations. They can be
  // overridden.
  std::string update_result_error_message_;
  GetResult get_result_;
  LengthResult length_result_;
  RemainingBudgetResult remaining_budget_result_;
  mojom::GetInterestGroupsResultPtr interest_groups_result_;

 private:
  mojo::AssociatedReceiver<blink::mojom::SharedStorageWorkletServiceClient>
      receiver_{this};
};

class MockMojomPrivateAggregationHost
    : public blink::mojom::blink::PrivateAggregationHost {
 public:
  MockMojomPrivateAggregationHost() = default;

  void FlushForTesting() { receiver_set_.FlushForTesting(); }

  mojo::ReceiverSet<blink::mojom::blink::PrivateAggregationHost>&
  receiver_set() {
    return receiver_set_;
  }

  // blink::mojom::blink::PrivateAggregationHost:
  MOCK_METHOD(
      void,
      ContributeToHistogram,
      (Vector<blink::mojom::blink::AggregatableReportHistogramContributionPtr>),
      (override));
  MOCK_METHOD(void,
              EnableDebugMode,
              (blink::mojom::blink::DebugKeyPtr),
              (override));

 private:
  mojo::ReceiverSet<blink::mojom::blink::PrivateAggregationHost> receiver_set_;
};

class MockMojomCoceCacheHost : public blink::mojom::blink::CodeCacheHost {
 public:
  MockMojomCoceCacheHost() = default;

  void FlushForTesting() { receiver_set_.FlushForTesting(); }

  mojo::ReceiverSet<blink::mojom::blink::CodeCacheHost>& receiver_set() {
    return receiver_set_;
  }

  // blink::mojom::blink::CoceCacheHost:
  void DidGenerateCacheableMetadata(mojom::CodeCacheType cache_type,
                                    const KURL& url,
                                    base::Time expected_response_time,
                                    mojo_base::BigBuffer data) override {
    did_generate_cacheable_metadata_count_++;

    // Store the time and data. This mirrors the real-world behavior.
    response_time_ = expected_response_time;
    data_ = std::move(data);
  }

  void FetchCachedCode(mojom::CodeCacheType cache_type,
                       const KURL& url,
                       FetchCachedCodeCallback callback) override {
    fetch_cached_code_count_++;
    std::move(callback).Run(response_time_, data_.Clone());
  }

  void ClearCodeCacheEntry(mojom::CodeCacheType cache_type,
                           const KURL& url) override {
    clear_code_cache_entry_count_++;
  }

  void DidGenerateCacheableMetadataInCacheStorage(
      const KURL& url,
      base::Time expected_response_time,
      mojo_base::BigBuffer data,
      const String& cache_storage_cache_name) override {
    NOTREACHED();
  }

  void OverrideFetchCachedCodeResult(base::Time response_time,
                                     mojo_base::BigBuffer data) {
    response_time_ = response_time;
    data_ = std::move(data);
  }

  size_t did_generate_cacheable_metadata_count() const {
    return did_generate_cacheable_metadata_count_;
  }

  size_t fetch_cached_code_count() const { return fetch_cached_code_count_; }

  size_t clear_code_cache_entry_count() const {
    return clear_code_cache_entry_count_;
  }

 private:
  base::Time response_time_;
  mojo_base::BigBuffer data_;

  size_t did_generate_cacheable_metadata_count_ = 0;
  size_t fetch_cached_code_count_ = 0;
  size_t clear_code_cache_entry_count_ = 0;

  mojo::ReceiverSet<blink::mojom::blink::CodeCacheHost> receiver_set_;
};

std::unique_ptr<GlobalScopeCreationParams> MakeTestGlobalScopeCreationParams() {
  return std::make_unique<GlobalScopeCreationParams>(
      KURL("https://foo.com"),
      /*script_type=*/mojom::blink::ScriptType::kModule, "SharedStorageWorklet",
      /*user_agent=*/String(),
      /*ua_metadata=*/std::optional<UserAgentMetadata>(),
      /*web_worker_fetch_context=*/nullptr,
      /*outside_content_security_policies=*/
      Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
      /*response_content_security_policies=*/
      Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
      /*referrer_policy=*/network::mojom::ReferrerPolicy::kDefault,
      /*starter_origin=*/nullptr,
      /*starter_secure_context=*/false,
      /*starter_https_state=*/HttpsState::kNone,
      /*worker_clients=*/nullptr,
      /*content_settings_client=*/nullptr,
      /*inherited_trial_features=*/nullptr,
      /*parent_devtools_token=*/base::UnguessableToken::Create(),
      /*worker_settings=*/nullptr,
      /*v8_cache_options=*/mojom::blink::V8CacheOptions::kDefault,
      /*module_responses_map=*/nullptr);
}

}  // namespace

class SharedStorageWorkletTest : public PageTestBase {
 public:
  SharedStorageWorkletTest() {
    mock_code_cache_host_ = std::make_unique<MockMojomCoceCacheHost>();
  }

  void TearDown() override {
    // Shut down the worklet gracefully. Otherwise, there could the a data race
    // on accessing the base::FeatureList: the worklet thread may access the
    // feature during SharedStorageWorkletGlobalScope::FinishOperation() or
    // SharedStorageWorkletGlobalScope::NotifyContextDestroyed(), which can
    // occur after the (maybe implicit) ScopedFeatureList is destroyed in the
    // main thread.
    shared_storage_worklet_service_.reset();
    EXPECT_TRUE(worklet_terminated_future_.Wait());

    PageTestBase::TearDown();
  }

  AddModuleResult AddModule(const std::string& script_content,
                            std::string mime_type = "application/javascript") {
    InitializeWorkletServiceOnce();

    mojo::Remote<network::mojom::URLLoaderFactory> factory;

    network::TestURLLoaderFactory proxied_url_loader_factory;

    auto head = network::mojom::URLResponseHead::New();
    head->mime_type = mime_type;
    head->charset = "us-ascii";
    head->response_time = kScriptResponseTime;

    proxied_url_loader_factory.AddResponse(
        GURL(kModuleScriptSource), std::move(head),
        /*content=*/script_content, network::URLLoaderCompletionStatus());

    proxied_url_loader_factory.Clone(factory.BindNewPipeAndPassReceiver());

    base::test::TestFuture<bool, const std::string&> future;
    shared_storage_worklet_service_->AddModule(
        factory.Unbind(), GURL(kModuleScriptSource), future.GetCallback());

    return {future.Get<0>(), future.Get<1>()};
  }

  SelectURLResult SelectURL(const std::string& name,
                            const std::vector<GURL>& urls,
                            blink::CloneableMessage serialized_data) {
    InitializeWorkletServiceOnce();

    base::test::TestFuture<bool, const std::string&, uint32_t> future;
    shared_storage_worklet_service_->RunURLSelectionOperation(
        name, urls, std::move(serialized_data), MaybeInitPAOperationDetails(),
        future.GetCallback());

    return {future.Get<0>(), future.Get<1>(), future.Get<2>()};
  }

  RunResult Run(const std::string& name,
                blink::CloneableMessage serialized_data,
                int filtering_id_max_bytes = 1) {
    InitializeWorkletServiceOnce();

    base::test::TestFuture<bool, const std::string&> future;
    shared_storage_worklet_service_->RunOperation(
        name, std::move(serialized_data),
        MaybeInitPAOperationDetails(filtering_id_max_bytes),
        future.GetCallback());

    return {future.Get<0>(), future.Get<1>()};
  }

  // CrossVariantMojoRemote<mojom::blink::PrivateAggregationHostInterfaceBase>
  mojom::PrivateAggregationOperationDetailsPtr MaybeInitPAOperationDetails(
      int filtering_id_max_bytes =
          kPrivateAggregationApiDefaultFilteringIdMaxBytes) {
    CHECK_EQ(ShouldDefinePrivateAggregationInSharedStorage(),
             !!mock_private_aggregation_host_);

    if (!ShouldDefinePrivateAggregationInSharedStorage()) {
      return nullptr;
    }

    mojo::PendingRemote<mojom::blink::PrivateAggregationHost>
        pending_pa_host_remote;
    mojo::PendingReceiver<mojom::blink::PrivateAggregationHost>
        pending_pa_host_receiver =
            pending_pa_host_remote.InitWithNewPipeAndPassReceiver();

    mock_private_aggregation_host_->receiver_set().Add(
        mock_private_aggregation_host_.get(),
        std::move(pending_pa_host_receiver));

    return mojom::PrivateAggregationOperationDetails::New(
        CrossVariantMojoRemote<
            mojom::blink::PrivateAggregationHostInterfaceBase>(
            std::move(pending_pa_host_remote)),
        filtering_id_max_bytes);
  }

  CloneableMessage CreateSerializedUndefined() {
    return CreateSerializedDictOrUndefined(nullptr);
  }

  CloneableMessage CreateSerializedDict(
      const std::map<std::string, std::string>& dict) {
    return CreateSerializedDictOrUndefined(&dict);
  }

 protected:
  ScopedSharedStorageAPIM125ForTest shared_storage_m125_runtime_enabled_feature{
      /*enabled=*/true};

  ScopedInterestGroupsInSharedStorageWorkletForTest
      interest_groups_in_shared_storage_worklet_runtime_enabled_feature{
          /*enabled=*/true};

  ScopedSharedStorageWebLocksForTest
      shared_storage_web_locks_runtime_enabled_feature{/*enabled=*/true};

  mojo::Remote<mojom::SharedStorageWorkletService>
      shared_storage_worklet_service_;

  Persistent<SharedStorageWorkletMessagingProxy> messaging_proxy_;

  std::optional<std::u16string> embedder_context_;

  blink::mojom::SharedStorageWorkletPermissionsPolicyStatePtr
      permissions_policy_state_ =
          blink::mojom::SharedStorageWorkletPermissionsPolicyState::New(
              /*private_aggregation_allowed=*/true,
              /*join_ad_interest_group_allowed=*/true,
              /*run_ad_auction_allowed=*/true);

  base::test::TestFuture<void> worklet_terminated_future_;

  std::unique_ptr<TestClient> test_client_;
  std::unique_ptr<TestWorkletDevToolsHost> test_worklet_devtools_host_;
  std::unique_ptr<MockMojomPrivateAggregationHost>
      mock_private_aggregation_host_;
  std::unique_ptr<MockMojomCoceCacheHost> mock_code_cache_host_;

  base::HistogramTester histogram_tester_;

  bool worklet_service_initialized_ = false;

 private:
  CloneableMessage CreateSerializedDictOrUndefined(
      const std::map<std::string, std::string>* dict) {
    ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());
    ScriptState::Scope scope(script_state);
    v8::MicrotasksScope microtasksScope(script_state->GetContext(),
                                        v8::MicrotasksScope::kRunMicrotasks);

    v8::Isolate* isolate = script_state->GetIsolate();

    scoped_refptr<SerializedScriptValue> serialized_value;
    if (dict) {
      v8::Local<v8::Object> v8_value = v8::Object::New(isolate);
      gin::Dictionary gin_dict(isolate, v8_value);
      for (auto const& [key, val] : *dict) {
        gin_dict.Set<std::string>(key, val);
      }

      serialized_value = SerializedScriptValue::SerializeAndSwallowExceptions(
          isolate, v8_value);
    } else {
      serialized_value = SerializedScriptValue::UndefinedValue();
    }

    BlinkCloneableMessage original;
    original.message = std::move(serialized_value);
    original.sender_agent_cluster_id = base::UnguessableToken::Create();

    mojo::Message message =
        mojom::CloneableMessage::SerializeAsMessage(&original);
    mojo::ScopedMessageHandle handle = message.TakeMojoMessage();
    message = mojo::Message::CreateFromMessageHandle(&handle);
    DCHECK(!message.IsNull());

    CloneableMessage converted;
    mojom::CloneableMessage::DeserializeFromMessage(std::move(message),
                                                    &converted);
    return converted;
  }

  void InitializeWorkletServiceOnce() {
    if (worklet_service_initialized_) {
      return;
    }

    mojo::PendingReceiver<mojom::SharedStorageWorkletService> receiver =
        shared_storage_worklet_service_.BindNewPipeAndPassReceiver();

    mojo::PendingRemote<mojom::blink::WorkletDevToolsHost>
        pending_devtools_host_remote;
    mojo::PendingReceiver<mojom::blink::WorkletDevToolsHost>
        pending_devtools_host_receiver =
            pending_devtools_host_remote.InitWithNewPipeAndPassReceiver();
    test_worklet_devtools_host_ = std::make_unique<TestWorkletDevToolsHost>(
        std::move(pending_devtools_host_receiver));

    mojo::PendingRemote<mojom::blink::CodeCacheHost>
        pending_code_cache_host_remote;
    mojo::PendingReceiver<mojom::blink::CodeCacheHost>
        pending_code_cache_host_receiver =
            pending_code_cache_host_remote.InitWithNewPipeAndPassReceiver();

    mock_code_cache_host_->receiver_set().Add(
        mock_code_cache_host_.get(),
        std::move(pending_code_cache_host_receiver));

    messaging_proxy_ = MakeGarbageCollected<SharedStorageWorkletMessagingProxy>(
        base::SingleThreadTaskRunner::GetCurrentDefault(),
        CrossVariantMojoReceiver<
            mojom::blink::SharedStorageWorkletServiceInterfaceBase>(
            std::move(receiver)),
        mojom::blink::WorkletGlobalScopeCreationParams::New(
            KURL(kModuleScriptSource),
            /*starter_origin=*/
            SecurityOrigin::Create(KURL(kModuleScriptSource)),
            Vector<blink::mojom::OriginTrialFeature>(),
            /*devtools_worker_token=*/base::UnguessableToken(),
            std::move(pending_devtools_host_remote),
            std::move(pending_code_cache_host_remote),
            mojo::PendingRemote<mojom::blink::BrowserInterfaceBroker>(),
            /*wait_for_debugger=*/false),
        worklet_terminated_future_.GetCallback());

    mojo::PendingAssociatedRemote<mojom::SharedStorageWorkletServiceClient>
        pending_shared_storage_service_client_remote;
    mojo::PendingAssociatedReceiver<mojom::SharedStorageWorkletServiceClient>
        pending_shared_storage_service_client_receiver =
            pending_shared_storage_service_client_remote
                .InitWithNewEndpointAndPassReceiver();

    test_client_ = std::make_unique<TestClient>(
        std::move(pending_shared_storage_service_client_receiver));

    if (ShouldDefinePrivateAggregationInSharedStorage()) {
      mock_private_aggregation_host_ =
          std::make_unique<MockMojomPrivateAggregationHost>();
    }

    shared_storage_worklet_service_->Initialize(
        std::move(pending_shared_storage_service_client_remote),
        permissions_policy_state_->Clone(), embedder_context_);

    worklet_service_initialized_ = true;
  }
};

TEST_F(SharedStorageWorkletTest, AddModule_EmptyScriptSuccess) {
  AddModuleResult result = AddModule(/*script_content=*/"");
  EXPECT_TRUE(result.success);
  EXPECT_TRUE(result.error_message.empty());
}

TEST_F(SharedStorageWorkletTest, AddModule_SimpleScriptSuccess) {
  AddModuleResult result = AddModule(/*script_content=*/"let a = 1;");
  EXPECT_TRUE(result.success);
  EXPECT_TRUE(result.error_message.empty());

  test_worklet_devtools_host_->FlushForTesting();
  EXPECT_TRUE(test_worklet_devtools_host_->ready_for_inspection());
}

TEST_F(SharedStorageWorkletTest, AddModule_SimpleScriptError) {
  AddModuleResult result = AddModule(/*script_content=*/"a;");
  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("ReferenceError: a is not defined"));

  test_worklet_devtools_host_->FlushForTesting();
  EXPECT_TRUE(test_worklet_devtools_host_->ready_for_inspection());
}

TEST_F(SharedStorageWorkletTest, AddModule_ScriptDownloadError) {
  AddModuleResult result = AddModule(/*script_content=*/"",
                                     /*mime_type=*/"unsupported_mime_type");
  EXPECT_FALSE(result.success);
  EXPECT_EQ(result.error_message,
            "Rejecting load of https://foo.com/module_script.js due to "
            "unexpected MIME type.");
}

TEST_F(SharedStorageWorkletTest,
       CodeCache_NoClearDueToEmptyCache_NoGenerateData) {
  // Configure to return empty data, with matched response time.
  mock_code_cache_host_->OverrideFetchCachedCodeResult(
      /*response_time=*/kScriptResponseTime,
      /*data=*/{});

  AddModule(/*script_content=*/"");

  mock_code_cache_host_->FlushForTesting();

  EXPECT_EQ(mock_code_cache_host_->fetch_cached_code_count(), 1u);

  // No invalidation was triggered, as `FetchCachedCode()` responded with empty
  // data.
  EXPECT_EQ(mock_code_cache_host_->clear_code_cache_entry_count(), 0u);

  // No code cache was generated, as the script size is too small.
  EXPECT_EQ(mock_code_cache_host_->did_generate_cacheable_metadata_count(), 0u);
}

TEST_F(SharedStorageWorkletTest,
       CodeCache_DidClearDueToUnmatchedTime_NoGenerateData) {
  // Configure to return non-empty data, with unmatched response time.
  mock_code_cache_host_->OverrideFetchCachedCodeResult(
      /*response_time=*/kScriptResponseTime - base::Days(1),
      /*data=*/{std::vector<uint8_t>(1)});

  AddModule(/*script_content=*/"");
  mock_code_cache_host_->FlushForTesting();

  EXPECT_EQ(mock_code_cache_host_->fetch_cached_code_count(), 1u);

  // Cache was cleared, as the response time did not match the time from the
  // script loading.
  EXPECT_EQ(mock_code_cache_host_->clear_code_cache_entry_count(), 1u);

  // No code cache was generated, as the script size is too small.
  EXPECT_EQ(mock_code_cache_host_->did_generate_cacheable_metadata_count(), 0u);
}

TEST_F(SharedStorageWorkletTest,
       CodeCache_NoClearDueToMatchedTime_NoGenerateData) {
  // Configure to return non-empty data, with matched response time.
  mock_code_cache_host_->OverrideFetchCachedCodeResult(
      /*response_time=*/kScriptResponseTime,
      /*data=*/{std::vector<uint8_t>(1)});

  AddModule(/*script_content=*/"");
  mock_code_cache_host_->FlushForTesting();

  EXPECT_EQ(mock_code_cache_host_->fetch_cached_code_count(), 1u);

  // No invalidation was triggered, as `FetchCachedCode()` responded with some
  // data with a matched response time.
  EXPECT_EQ(mock_code_cache_host_->clear_code_cache_entry_count(), 0u);

  // No code cache was generated, as the script size is too small.
  EXPECT_EQ(mock_code_cache_host_->did_generate_cacheable_metadata_count(), 0u);
}

TEST_F(SharedStorageWorkletTest, CodeCache_DidGenerateData) {
  // Code cache will be generated when the code length is at least 1024 bytes.
  std::string large_script;
  while (large_script.size() < 1024) {
    large_script += "a=1;";
  }

  AddModule(large_script);
  mock_code_cache_host_->FlushForTesting();

  EXPECT_EQ(mock_code_cache_host_->fetch_cached_code_count(), 1u);

  // No invalidation was triggered, as `FetchCachedCode()` responded with empty
  // data.
  EXPECT_EQ(mock_code_cache_host_->clear_code_cache_entry_count(), 0u);

  // Code cache was generated.
  EXPECT_EQ(mock_code_cache_host_->did_generate_cacheable_metadata_count(), 1u);
}

TEST_F(SharedStorageWorkletTest, CodeCache_AddModuleTwice) {
  // Code cache will be generated when the code length is at least 1024 bytes.
  std::string large_script;
  while (large_script.size() < 1024) {
    large_script += "a=1;";
  }

  AddModule(large_script);
  AddModule(large_script);
  mock_code_cache_host_->FlushForTesting();

  EXPECT_EQ(mock_code_cache_host_->fetch_cached_code_count(), 2u);

  // No invalidation was triggered. The second code cache fetch returns a
  // response time from the first result, which matches the response time from
  // the second script loading.
  EXPECT_EQ(mock_code_cache_host_->clear_code_cache_entry_count(), 0u);

  // The second script loading also triggered the code cache generation. This
  // implies that the code cache was still not used. This is expected, as we
  // won't store the cached code entirely for first seen URLs.
  EXPECT_EQ(mock_code_cache_host_->did_generate_cacheable_metadata_count(), 2u);
}

TEST_F(SharedStorageWorkletTest, CodeCache_AddModuleThreeTimes) {
  // Code cache will be generated when the code length is at least 1024 bytes.
  std::string large_script;
  while (large_script.size() < 1024) {
    large_script += "a=1;";
  }

  AddModule(large_script);
  AddModule(large_script);
  AddModule(large_script);
  mock_code_cache_host_->FlushForTesting();

  EXPECT_EQ(mock_code_cache_host_->fetch_cached_code_count(), 3u);

  // No invalidation was triggered. The second and third code cache fetch
  // returns a response time from the first result, which matches the response
  // time from the second and third script loading.
  EXPECT_EQ(mock_code_cache_host_->clear_code_cache_entry_count(), 0u);

  // The third script loading did not trigger the code cache generation. This
  // implies that the cached code was used for the third script loading.
  EXPECT_EQ(mock_code_cache_host_->did_generate_cacheable_metadata_count(), 2u);
}

TEST_F(SharedStorageWorkletTest, WorkletTerminationDueToDisconnect) {
  AddModuleResult result = AddModule(/*script_content=*/"");

  // Trigger the disconnect handler.
  shared_storage_worklet_service_.reset();

  // Callback called means the worklet has terminated successfully.
  EXPECT_TRUE(worklet_terminated_future_.Wait());
}

TEST_F(SharedStorageWorkletTest, ConsoleLog_DuringAddModule) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
    console.log(123, "abc");
  )");

  EXPECT_TRUE(result.success);
  EXPECT_TRUE(result.error_message.empty());

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "123 abc");
}

TEST_F(SharedStorageWorkletTest,
       GlobalScopeObjectsAndFunctions_DuringAddModule) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
    var expectedObjects = [
      "console",
      "crypto"
    ];

    var expectedFunctions = [
      "SharedStorageWorkletNavigator",
      "LockManager",
      "Lock",
      "SharedStorage",
      "Crypto",
      "CryptoKey",
      "SubtleCrypto",
      "TextEncoder",
      "TextDecoder",
      "register",
      "console.log",
      "interestGroups"
    ];

    var expectedUndefinedVariables = [];

    for (let expectedObject of expectedObjects) {
      if (eval("typeof " + expectedObject) !== "object") {
        throw Error(expectedObject + " is not object type.")
      }
    }

    for (let expectedFunction of expectedFunctions) {
      if (eval("typeof " + expectedFunction) !== "function") {
        throw Error(expectedFunction + " is not function type.")
      }
    }

    for (let expectedUndefined of expectedUndefinedVariables) {
      if (eval("typeof " + expectedUndefined) !== "undefined") {
        throw Error(expectedUndefined + " is not undefined.")
      }
    }

    // Verify that trying to access `sharedStorage` would throw a custom error.
    try {
      sharedStorage;
    } catch (e) {
      console.log("Expected error:", e.message);
    }

    // Verify that trying to access `navigator` would throw a custom error.
    try {
      navigator;
    } catch (e) {
      console.log("Expected error:", e.message);
    }

    // Verify that `interestGroups()` would reject with a custom error.
    interestGroups().then(groups => {
      console.log("Unexpected groups: ", groups);
    }).catch(e => {
      console.log("Expected async error:", e.message);
    });
  )");

  EXPECT_TRUE(add_module_result.success);
  EXPECT_EQ(add_module_result.error_message, "");

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 3u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0],
            "Expected error: Failed to read the 'sharedStorage' property from "
            "'SharedStorageWorkletGlobalScope': sharedStorage cannot be "
            "accessed during addModule().");
  EXPECT_EQ(test_client_->observed_console_log_messages_[1],
            "Expected error: Failed to read the 'navigator' property from "
            "'SharedStorageWorkletGlobalScope': navigator cannot be accessed "
            "during addMod
"""


```