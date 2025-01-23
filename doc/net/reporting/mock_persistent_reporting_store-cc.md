Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The request asks for the functionality of `mock_persistent_reporting_store.cc`, its relationship to JavaScript (if any), logical input/output examples, common user errors, and debugging steps to reach this code.

2. **Identify the Core Class:** The central element is the `MockPersistentReportingStore` class. The name itself is a huge clue: "Mock" suggests this isn't a real persistent store but rather a simulated one, likely for testing purposes. "Persistent Reporting Store" tells us it deals with storing information related to reporting (likely network error reporting).

3. **Analyze the Public Interface (`.h` - though not provided, deduce from `.cc`):**  Examine the public methods of `MockPersistentReportingStore`. These are the actions that can be performed on this mock store:
    * `LoadReportingClients()`:  This is clearly for retrieving stored reporting data. The `ReportingClientsLoadedCallback` suggests it's asynchronous.
    * `AddReportingEndpoint()`, `AddReportingEndpointGroup()`:  These are for storing new reporting entities.
    * `UpdateReportingEndpointGroupAccessTime()`, `UpdateReportingEndpointDetails()`, `UpdateReportingEndpointGroupDetails()`: These are for modifying existing stored data.
    * `DeleteReportingEndpoint()`, `DeleteReportingEndpointGroup()`:  These are for removing stored data.
    * `Flush()`: This likely simulates the process of writing changes to the "persistent" store (though in this mock, it's just in-memory).
    * `SetPrestoredClients()`: This allows for pre-populating the mock store for testing.
    * `FinishLoading()`:  Likely called after `LoadReportingClients()` to simulate the completion of the loading process.
    * `VerifyCommands()`, `CountCommands()`, `ClearCommands()`, `GetAllCommands()`: These methods strongly suggest the mock store is tracking the operations performed on it, again, for testing.

4. **Analyze the `Command` Inner Class:**  The `Command` class is used to record the operations being performed. Each `Command` instance represents a single action (add, delete, update, load, flush). This reinforces the idea that the mock store is tracking the history of operations. The overloaded constructors clarify which data is relevant for each command type. The `operator==` and `operator<<` are essential for comparing and debugging the commands.

5. **Infer Functionality:** Based on the methods and the `Command` class, we can infer the primary function: **Simulate a persistent store for network reporting data, primarily for testing the parts of the Chromium network stack that interact with this storage.** It doesn't actually persist data to disk or a database.

6. **JavaScript Relationship:** Consider where network reporting might interact with JavaScript. JavaScript in web pages can trigger network requests that might lead to errors. The Reporting API is a W3C standard that allows websites to define where browser-generated reports (like CSP violations, network errors) should be sent. Therefore, *if* the Chromium network stack is using this persistent store to manage reporting endpoints configured by JavaScript through the Reporting API, there's a connection.

7. **Logical Input/Output:** Choose a few key methods and illustrate how they work in the mock:
    * `LoadReportingClients()`: The input is a callback. The output depends on `SetPrestoredClients()` and `FinishLoading()`.
    * `AddReportingEndpoint()`: Input is an `ReportingEndpoint`. The output is the command being stored.
    * `Flush()`: No direct input (besides prior commands). The output is the counters being updated.

8. **Common User/Programming Errors:** Think about how someone might misuse this *mock* object in a testing scenario:
    * Not calling `FinishLoading()` after `LoadReportingClients()`.
    * Incorrectly asserting the order or type of commands in tests.
    * Expecting actual persistence.

9. **Debugging Steps:**  How would a developer end up looking at this code?
    * Suspecting issues with network reporting persistence.
    * Following the call stack when a reporting-related function is executed.
    * Specifically looking for the *mock* implementation during testing.

10. **Structure the Answer:** Organize the findings into the requested categories: Functionality, JavaScript Relationship, Input/Output, User Errors, and Debugging Steps. Use clear and concise language. Provide specific examples.

11. **Refine and Review:** Read through the answer. Are there any ambiguities?  Are the explanations clear? Is the reasoning sound?  For example, initially, I might just say "it stores reporting data," but clarifying that it's a *mock* and thus *simulates* storage is crucial. Also, explicitly mentioning the `Command` class and its role is important for understanding how the mock works.

By following these steps, you can systematically analyze the code and generate a comprehensive and accurate answer to the prompt. The key is to break down the problem into smaller, manageable parts and leverage the information present in the code itself (like class names and method signatures).
这个文件 `net/reporting/mock_persistent_reporting_store.cc` 实现了 `MockPersistentReportingStore` 类，这是一个**用于测试目的的模拟的持久化报告存储**。它不进行真实的磁盘 I/O 操作，而是将所有操作记录在内存中，方便测试网络栈中与持久化报告存储交互的组件。

以下是它的主要功能：

**1. 模拟持久化报告存储操作:**

* **加载报告客户端信息 (`LoadReportingClients`)**: 模拟从持久化存储中加载报告端点和端点组信息的过程。
* **添加报告端点 (`AddReportingEndpoint`)**: 模拟向持久化存储中添加新的报告端点。
* **添加报告端点组 (`AddReportingEndpointGroup`)**: 模拟向持久化存储中添加新的报告端点组。
* **更新报告端点组访问时间 (`UpdateReportingEndpointGroupAccessTime`)**: 模拟更新报告端点组的最后访问时间。
* **更新报告端点详情 (`UpdateReportingEndpointDetails`)**: 模拟更新现有报告端点的详细信息。
* **更新报告端点组详情 (`UpdateReportingEndpointGroupDetails`)**: 模拟更新现有报告端点组的详细信息。
* **删除报告端点 (`DeleteReportingEndpoint`)**: 模拟从持久化存储中删除报告端点。
* **删除报告端点组 (`DeleteReportingEndpointGroup`)**: 模拟从持久化存储中删除报告端点组。
* **刷新 (`Flush`)**: 模拟将内存中的更改刷新到持久化存储的过程。

**2. 记录执行的命令:**

* 使用一个 `std::vector<Command> command_list_` 成员变量来记录所有对 `MockPersistentReportingStore` 执行的操作。
* `Command` 是一个内部类，用于封装执行的操作类型以及相关的参数（例如，要添加/删除的端点或组的信息）。
* 这使得测试代码可以验证是否执行了预期的存储操作以及操作的顺序和参数。

**3. 提供预设数据能力:**

* `SetPrestoredClients` 方法允许在测试开始前预先设置存储中的报告端点和端点组，以便模拟特定的初始状态。

**4. 完成加载模拟:**

* `FinishLoading` 方法用于模拟加载过程的完成，并根据提供的布尔值指示加载是否成功，然后调用加载时提供的回调函数，并将预设或空的数据传递给回调。

**与 JavaScript 的关系 (可能存在但此处代码不直接涉及):**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它模拟的持久化报告存储可能会被网络栈中处理来自 JavaScript 的 Reporting API 请求的组件使用。

**举例说明:**

假设一个网页使用 JavaScript 的 Reporting API 配置了一个报告端点，当浏览器检测到违反安全策略 (CSP) 的情况时，会生成一个报告并尝试发送到配置的端点。

1. **JavaScript 配置报告端点:**  网页中的 JavaScript 代码调用 `navigator.sendBeacon` 或 `fetch` 向服务器发送请求，该请求包含 Reporting API 的配置信息，例如报告的 `url` 和 `group`。
2. **浏览器处理配置:** Chromium 的网络栈接收到这个配置信息，并需要将其持久化。实际生产环境中，会使用真实的持久化存储。在测试环境中，可能会使用 `MockPersistentReportingStore`。
3. **调用 `MockPersistentReportingStore`:** 网络栈中负责处理 Reporting API 配置的 C++ 代码会调用 `MockPersistentReportingStore::AddReportingEndpoint` 或 `MockPersistentReportingStore::AddReportingEndpointGroup` 来模拟存储这个配置。

**假设输入与输出 (针对 `Command` 类和部分方法):**

**假设输入 (针对 `Command` 构造函数):**

* **类型: `Command::Type::ADD_REPORTING_ENDPOINT`，`ReportingEndpoint` 对象 `endpoint`**:
   ```cpp
   ReportingEndpoint endpoint;
   endpoint.group_key.origin = url::Origin::Create(GURL("https://example.com"));
   endpoint.group_key.group_name = "csp-violations";
   endpoint.info.url = GURL("https://report-collector.example.com/report");
   MockPersistentReportingStore::Command cmd(MockPersistentReportingStore::Command::Type::ADD_REPORTING_ENDPOINT, endpoint);
   ```

**输出 (针对 `Command` 的 `operator<<`):**

```
ADD_REPORTING_ENDPOINT(NAK=NetworkAnonymizationKey(), origin=https://example.com, group=csp-violations, endpoint=https://report-collector.example.com/report)
```

**假设输入 (针对 `AddReportingEndpoint` 方法):**

```cpp
ReportingEndpoint endpoint;
endpoint.group_key.origin = url::Origin::Create(GURL("https://test.example"));
endpoint.group_key.group_name = "network-errors";
endpoint.info.url = GURL("https://report.test.example/submit");
mock_store.AddReportingEndpoint(endpoint);
```

**输出 (影响 `command_list_`):**

`command_list_` 中会添加一个 `Command` 对象，其类型为 `ADD_REPORTING_ENDPOINT`，并且包含 `endpoint` 的信息。

**涉及用户或编程常见的使用错误 (在使用 `MockPersistentReportingStore` 进行测试时):**

1. **忘记调用 `FinishLoading`:**  如果在测试中调用了 `LoadReportingClients`，但忘记调用 `FinishLoading` 来模拟加载完成，则与加载完成相关的回调不会被执行，可能导致测试卡住或行为不符合预期。

   ```cpp
   // 错误示例
   MockPersistentReportingStore mock_store;
   bool load_completed = false;
   mock_store.LoadReportingClients(
       base::BindOnce([](std::vector<ReportingEndpoint> endpoints,
                         std::vector<CachedReportingEndpointGroup> groups) {
         // 这里的代码永远不会被执行
       }));
   // ... 缺少 mock_store.FinishLoading(true);
   ```

2. **对命令列表的错误断言:**  测试代码可能会错误地断言 `command_list_` 中的命令顺序或参数。例如，预期先添加端点 A 再添加端点 B，但实际的执行顺序可能相反。

   ```cpp
   // 错误示例
   MockPersistentReportingStore mock_store;
   // ... 执行添加端点 A 和端点 B 的操作 ...
   MockPersistentReportingStore::CommandList expected_commands;
   // 假设期望先添加端点 B 再添加端点 A
   // ... 构造 expected_commands ...
   EXPECT_TRUE(mock_store.VerifyCommands(expected_commands)); // 这可能失败
   ```

3. **在未加载完成前调用修改方法:**  虽然 `MockPersistentReportingStore` 会检查 `load_started_` 标志，但如果测试逻辑没有正确模拟加载过程，可能会在 `LoadReportingClients` 回调之前调用 `AddReportingEndpoint` 等修改方法，导致 `DCHECK` 失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者正在调试一个关于浏览器如何处理 Reporting API 配置的问题，例如，用户在一个网页上设置了一个报告端点，但浏览器似乎没有正确地保存或加载这个配置。

1. **用户访问包含 Reporting API 配置的网页:** 用户在浏览器中打开一个网页，该网页的 JavaScript 代码使用了 Reporting API 来设置报告端点。
2. **浏览器接收并处理配置:**  Chromium 的网络栈接收到来自网页的配置信息。
3. **调用持久化存储接口:**  网络栈中负责持久化报告端点信息的组件会调用一个 `PersistentReportingStore` 接口的方法（例如 `AddReportingEndpoint`）。
4. **在测试环境中命中 `MockPersistentReportingStore`:** 如果当前运行的是一个测试环境，并且配置使用了 `MockPersistentReportingStore` 作为 `PersistentReportingStore` 的实现，那么对持久化存储接口的调用最终会路由到 `MockPersistentReportingStore` 的相应方法（例如 `AddReportingEndpoint`）。
5. **查看 `command_list_`:** 开发者可以通过查看 `MockPersistentReportingStore` 实例的 `command_list_` 成员变量，来验证是否接收到了预期的存储操作以及操作的参数是否正确。
6. **单步调试 `MockPersistentReportingStore` 的代码:**  开发者可以使用调试器，设置断点在 `MockPersistentReportingStore` 的方法中，例如 `AddReportingEndpoint`，来观察代码的执行流程，查看接收到的参数值，以及 `command_list_` 的变化。
7. **验证 `FinishLoading` 的调用:** 如果问题涉及到加载已保存的报告端点，开发者可以检查 `LoadReportingClients` 方法是否被调用，以及 `FinishLoading` 方法是否在合适的时机被调用，并传递了正确的数据。

通过以上步骤，开发者可以利用 `MockPersistentReportingStore` 提供的功能，在测试环境中模拟和验证报告存储相关的逻辑，从而定位和解决问题。这个文件本身是测试基础设施的一部分，通常不会在生产环境的用户操作中直接被访问到，而是作为测试和调试的辅助工具。

### 提示词
```
这是目录为net/reporting/mock_persistent_reporting_store.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/mock_persistent_reporting_store.h"

#include <algorithm>
#include <memory>

namespace net {

MockPersistentReportingStore::Command::Command(
    Type type,
    ReportingClientsLoadedCallback loaded_callback)
    : type(type), loaded_callback(std::move(loaded_callback)) {
  DCHECK(type == Type::LOAD_REPORTING_CLIENTS);
}

MockPersistentReportingStore::Command::Command(
    Type type,
    const ReportingEndpoint& endpoint)
    : Command(type, endpoint.group_key, endpoint.info.url) {}

MockPersistentReportingStore::Command::Command(
    Type type,
    const ReportingEndpointGroupKey& group_key,
    const GURL& endpoint_url)
    : type(type), group_key(group_key), url(endpoint_url) {
  DCHECK(type == Type::ADD_REPORTING_ENDPOINT ||
         type == Type::UPDATE_REPORTING_ENDPOINT_DETAILS ||
         type == Type::DELETE_REPORTING_ENDPOINT);
}

MockPersistentReportingStore::Command::Command(
    Type type,
    const CachedReportingEndpointGroup& group)
    : Command(type, group.group_key) {}

MockPersistentReportingStore::Command::Command(
    Type type,
    const ReportingEndpointGroupKey& group_key)
    : type(type), group_key(group_key) {
  DCHECK(type == Type::ADD_REPORTING_ENDPOINT_GROUP ||
         type == Type::UPDATE_REPORTING_ENDPOINT_GROUP_DETAILS ||
         type == Type::UPDATE_REPORTING_ENDPOINT_GROUP_ACCESS_TIME ||
         type == Type::DELETE_REPORTING_ENDPOINT_GROUP);
}

MockPersistentReportingStore::Command::Command(Type type) : type(type) {
  DCHECK(type == Type::FLUSH || type == Type::LOAD_REPORTING_CLIENTS);
}

MockPersistentReportingStore::Command::Command(const Command& other)
    : type(other.type), group_key(other.group_key), url(other.url) {}

MockPersistentReportingStore::Command::Command(Command&& other) = default;

MockPersistentReportingStore::Command::~Command() = default;

bool operator==(const MockPersistentReportingStore::Command& lhs,
                const MockPersistentReportingStore::Command& rhs) {
  if (lhs.type != rhs.type)
    return false;
  bool equal = true;
  switch (lhs.type) {
    // For load and flush, just check the type.
    case MockPersistentReportingStore::Command::Type::LOAD_REPORTING_CLIENTS:
    case MockPersistentReportingStore::Command::Type::FLUSH:
      return true;
    // For endpoint operations, check the url and group key.
    case MockPersistentReportingStore::Command::Type::ADD_REPORTING_ENDPOINT:
    case MockPersistentReportingStore::Command::Type::
        UPDATE_REPORTING_ENDPOINT_DETAILS:
    case MockPersistentReportingStore::Command::Type::DELETE_REPORTING_ENDPOINT:
      equal &= (lhs.url == rhs.url);
      [[fallthrough]];
    // For endpoint group operations, check the group key only.
    case MockPersistentReportingStore::Command::Type::
        ADD_REPORTING_ENDPOINT_GROUP:
    case MockPersistentReportingStore::Command::Type::
        UPDATE_REPORTING_ENDPOINT_GROUP_ACCESS_TIME:
    case MockPersistentReportingStore::Command::Type::
        UPDATE_REPORTING_ENDPOINT_GROUP_DETAILS:
    case MockPersistentReportingStore::Command::Type::
        DELETE_REPORTING_ENDPOINT_GROUP:
      equal &= (lhs.group_key == rhs.group_key);
  }
  return equal;
}

bool operator!=(const MockPersistentReportingStore::Command& lhs,
                const MockPersistentReportingStore::Command& rhs) {
  return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& out,
                         const MockPersistentReportingStore::Command& cmd) {
  switch (cmd.type) {
    case MockPersistentReportingStore::Command::Type::LOAD_REPORTING_CLIENTS:
      return out << "LOAD_REPORTING_CLIENTS()";
    case MockPersistentReportingStore::Command::Type::FLUSH:
      return out << "FLUSH()";
    case MockPersistentReportingStore::Command::Type::ADD_REPORTING_ENDPOINT:
      return out << "ADD_REPORTING_ENDPOINT("
                 << "NAK="
                 << cmd.group_key.network_anonymization_key.ToDebugString()
                 << ", "
                 << "origin=" << cmd.group_key.origin.value() << ", "
                 << "group=" << cmd.group_key.group_name << ", "
                 << "endpoint=" << cmd.url << ")";
    case MockPersistentReportingStore::Command::Type::
        UPDATE_REPORTING_ENDPOINT_DETAILS:
      return out << "UPDATE_REPORTING_ENDPOINT_DETAILS("
                 << "NAK="
                 << cmd.group_key.network_anonymization_key.ToDebugString()
                 << ", "
                 << "origin=" << cmd.group_key.origin.value() << ", "
                 << "group=" << cmd.group_key.group_name << ", "
                 << "endpoint=" << cmd.url << ")";
    case MockPersistentReportingStore::Command::Type::DELETE_REPORTING_ENDPOINT:
      return out << "DELETE_REPORTING_ENDPOINT("
                 << "NAK="
                 << cmd.group_key.network_anonymization_key.ToDebugString()
                 << ", "
                 << "origin=" << cmd.group_key.origin.value() << ", "
                 << "group=" << cmd.group_key.group_name << ", "
                 << "endpoint=" << cmd.url << ")";
    case MockPersistentReportingStore::Command::Type::
        ADD_REPORTING_ENDPOINT_GROUP:
      return out << "ADD_REPORTING_ENDPOINT_GROUP("
                 << "NAK="
                 << cmd.group_key.network_anonymization_key.ToDebugString()
                 << ", "
                 << "origin=" << cmd.group_key.origin.value() << ", "
                 << "group=" << cmd.group_key.group_name << ")";
    case MockPersistentReportingStore::Command::Type::
        UPDATE_REPORTING_ENDPOINT_GROUP_ACCESS_TIME:
      return out << "UPDATE_REPORTING_ENDPOINT_GROUP_ACCESS_TIME("
                 << "NAK="
                 << cmd.group_key.network_anonymization_key.ToDebugString()
                 << ", "
                 << "origin=" << cmd.group_key.origin.value() << ", "
                 << "group=" << cmd.group_key.group_name << ")";
    case MockPersistentReportingStore::Command::Type::
        UPDATE_REPORTING_ENDPOINT_GROUP_DETAILS:
      return out << "UPDATE_REPORTING_ENDPOINT_GROUP_DETAILS("
                 << "NAK="
                 << cmd.group_key.network_anonymization_key.ToDebugString()
                 << ", "
                 << "origin=" << cmd.group_key.origin.value() << ", "
                 << "group=" << cmd.group_key.group_name << ")";
    case MockPersistentReportingStore::Command::Type::
        DELETE_REPORTING_ENDPOINT_GROUP:
      return out << "DELETE_REPORTING_ENDPOINT_GROUP("
                 << "NAK="
                 << cmd.group_key.network_anonymization_key.ToDebugString()
                 << ", "
                 << "origin=" << cmd.group_key.origin.value() << ", "
                 << "group=" << cmd.group_key.group_name << ")";
  }
}

MockPersistentReportingStore::MockPersistentReportingStore() = default;
MockPersistentReportingStore::~MockPersistentReportingStore() = default;

void MockPersistentReportingStore::LoadReportingClients(
    ReportingClientsLoadedCallback loaded_callback) {
  DCHECK(!load_started_);
  command_list_.emplace_back(Command::Type::LOAD_REPORTING_CLIENTS,
                             std::move(loaded_callback));
  load_started_ = true;
}

void MockPersistentReportingStore::AddReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  DCHECK(load_started_);
  command_list_.emplace_back(Command::Type::ADD_REPORTING_ENDPOINT, endpoint);
  ++queued_endpoint_count_delta_;
}

void MockPersistentReportingStore::AddReportingEndpointGroup(
    const CachedReportingEndpointGroup& group) {
  DCHECK(load_started_);
  command_list_.emplace_back(Command::Type::ADD_REPORTING_ENDPOINT_GROUP,
                             group);
  ++queued_endpoint_group_count_delta_;
}

void MockPersistentReportingStore::UpdateReportingEndpointGroupAccessTime(
    const CachedReportingEndpointGroup& group) {
  DCHECK(load_started_);
  command_list_.emplace_back(
      Command::Type::UPDATE_REPORTING_ENDPOINT_GROUP_ACCESS_TIME, group);
}

void MockPersistentReportingStore::UpdateReportingEndpointDetails(
    const ReportingEndpoint& endpoint) {
  DCHECK(load_started_);
  command_list_.emplace_back(Command::Type::UPDATE_REPORTING_ENDPOINT_DETAILS,
                             endpoint);
}

void MockPersistentReportingStore::UpdateReportingEndpointGroupDetails(
    const CachedReportingEndpointGroup& group) {
  DCHECK(load_started_);
  command_list_.emplace_back(
      Command::Type::UPDATE_REPORTING_ENDPOINT_GROUP_DETAILS, group);
}

void MockPersistentReportingStore::DeleteReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  DCHECK(load_started_);
  command_list_.emplace_back(Command::Type::DELETE_REPORTING_ENDPOINT,
                             endpoint);
  --queued_endpoint_count_delta_;
}

void MockPersistentReportingStore::DeleteReportingEndpointGroup(
    const CachedReportingEndpointGroup& group) {
  DCHECK(load_started_);
  command_list_.emplace_back(Command::Type::DELETE_REPORTING_ENDPOINT_GROUP,
                             group);
  --queued_endpoint_group_count_delta_;
}

void MockPersistentReportingStore::Flush() {
  // Can be called before |load_started_| is true, if the ReportingCache is
  // destroyed before getting a chance to load.
  command_list_.emplace_back(Command::Type::FLUSH);
  endpoint_count_ += queued_endpoint_count_delta_;
  queued_endpoint_count_delta_ = 0;
  endpoint_group_count_ += queued_endpoint_group_count_delta_;
  queued_endpoint_group_count_delta_ = 0;
}

void MockPersistentReportingStore::SetPrestoredClients(
    std::vector<ReportingEndpoint> endpoints,
    std::vector<CachedReportingEndpointGroup> groups) {
  DCHECK(!load_started_);
  DCHECK_EQ(0, endpoint_count_);
  DCHECK_EQ(0, endpoint_group_count_);
  endpoint_count_ += endpoints.size();
  prestored_endpoints_.swap(endpoints);
  endpoint_group_count_ += groups.size();
  prestored_endpoint_groups_.swap(groups);
}

void MockPersistentReportingStore::FinishLoading(bool load_success) {
  DCHECK(load_started_);
  for (size_t i = 0; i < command_list_.size(); ++i) {
    Command& command = command_list_[i];
    if (command.type == Command::Type::LOAD_REPORTING_CLIENTS) {
      // If load has been initiated, it should be the first operation.
      DCHECK_EQ(0u, i);
      DCHECK(!command.loaded_callback.is_null());
      if (load_success) {
        std::move(command.loaded_callback)
            .Run(std::move(prestored_endpoints_),
                 std::move(prestored_endpoint_groups_));
      } else {
        std::move(command.loaded_callback)
            .Run(std::vector<ReportingEndpoint>(),
                 std::vector<CachedReportingEndpointGroup>());
      }
    }
    if (i > 0) {
      // Load should not have been called twice.
      DCHECK(command.type != Command::Type::LOAD_REPORTING_CLIENTS);
    }
  }
}

bool MockPersistentReportingStore::VerifyCommands(
    const CommandList& expected_commands) const {
  return command_list_ == expected_commands;
}

int MockPersistentReportingStore::CountCommands(Command::Type t) {
  int c = 0;
  for (const auto& cmd : command_list_) {
    if (cmd.type == t)
      ++c;
  }
  return c;
}

void MockPersistentReportingStore::ClearCommands() {
  command_list_.clear();
}

MockPersistentReportingStore::CommandList
MockPersistentReportingStore::GetAllCommands() const {
  return command_list_;
}

}  // namespace net
```