Response:
The user wants to understand the functionality of the `sqlite_persistent_reporting_and_nel_store.cc` file in Chromium's network stack. I need to go through the code and identify its main purposes, how it interacts with JavaScript (if it does), analyze its logic with hypothetical inputs and outputs, discuss potential user or programming errors, explain how a user's actions might lead to this code being executed, and finally, summarize its core functionality based on this first part of the file.

**Functionality Breakdown:**

1. **Data Persistence:** The core function is to persist Network Error Logging (NEL) policies and Reporting API data (endpoints and endpoint groups) using SQLite.
2. **Data Structures:**  It defines data structures (`NelPolicyInfo`, `ReportingEndpointInfo`, `ReportingEndpointGroupInfo`) to represent the data stored in the SQLite database.
3. **Database Schema:** It defines the SQLite schema for the tables that store this data. The schema has evolved (version 1 to version 2), and the code includes migration logic.
4. **CRUD Operations:** It provides methods for adding, updating, deleting, and loading NEL policies and Reporting API data.
5. **Asynchronous Operations:** It uses background tasks for database operations to avoid blocking the main thread.
6. **Batching and Coalescing:** It implements a mechanism to batch database operations for efficiency and potentially coalesce similar operations to reduce redundant writes.
7. **Network Anonymization Key (NAK):** It handles the persistence of Network Anonymization Keys associated with the stored data. It includes logic to handle cases where NAKs are enabled or disabled.

**Relationship with JavaScript:**

JavaScript code running in a web page can trigger actions that lead to this code being executed. For example, a website can set NEL policies or Reporting endpoints using HTTP headers. The browser needs to store these settings persistently, and this is where this code comes into play.

**Hypothetical Input and Output:**

Imagine JavaScript on `example.com` triggers a request that includes a `NEL` header. This header contains a new NEL policy. The input to this code would be the parsed NEL policy data. The output would be the successful insertion of this data into the SQLite database.

**User/Programming Errors:**

A common programming error might be incorrectly formatting the data being passed to the store, leading to database insertion failures. A user-related issue might be clearing browser data, which would lead to the deletion of the persisted NEL policies and Reporting data.

**User Operation to Reach This Code:**

A user visits a website that sends HTTP headers instructing the browser to store NEL policies or Reporting endpoints.

**Summary of Part 1:**

This first part of the file sets up the foundation for the persistent storage of NEL policies and Reporting API data using SQLite. It defines the basic data structures, the database schema, and the mechanisms for interacting with the database in an asynchronous and efficient manner, taking into account the Network Anonymization Key.
根据提供的代码，`net/extras/sqlite/sqlite_persistent_reporting_and_nel_store.cc` 文件的主要功能是：

1. **持久化存储 NEL (Network Error Logging) 策略:** 该文件负责将从服务器接收到的 NEL 策略存储到 SQLite 数据库中。这包括策略的来源 (origin)、过期时间、采样率、是否包含子域名等信息。
2. **持久化存储 Reporting API 的端点 (Endpoints) 和端点组 (Endpoint Groups):**  该文件也负责将 Reporting API 相关的配置信息存储到 SQLite 数据库中。这包括报告接收端点的 URL、优先级、权重，以及端点组的名称、过期时间、是否包含子域名等信息。
3. **数据库管理:** 该文件管理 SQLite 数据库的创建、迁移和升级。它定义了数据库的 schema (表结构)，并提供了从旧版本数据库迁移到新版本的逻辑。
4. **异步数据库操作:** 为了避免阻塞主线程，所有的数据库操作（读取、写入、更新、删除）都是在后台线程中异步执行的。
5. **批量处理数据库操作:**  为了提高效率，该文件会批量处理数据库的写入操作。它维护了一个待处理操作的队列，并在达到一定数量或超时后一次性提交到数据库。
6. **处理 NetworkAnonymizationKey:**  该文件考虑了 NetworkAnonymizationKey (网络匿名化密钥)，用于在支持网络分区的环境中存储和检索数据。它将 NetworkAnonymizationKey 转换为字符串进行存储，并在加载时将其恢复。
7. **指标收集:** 代码中使用了宏 `UMA_HISTOGRAM_COUNTS` 来记录加载的 NEL 策略和 Reporting 客户端的数量，用于性能和使用情况的分析。

**与 JavaScript 功能的关系:**

该文件本身不包含 JavaScript 代码，但它存储的数据直接影响浏览器如何处理网络错误和报告。JavaScript 可以通过浏览器提供的 API (例如，通过设置 HTTP 头部 `NEL` 和 `Report-To`) 间接地影响这里存储的数据。

**举例说明:**

当一个网站 (例如 `https://example.com`) 返回一个包含 `NEL` 头部的响应时，浏览器会解析这个头部并提取 NEL 策略。这些策略会通过 `NetworkErrorLoggingService` 传递到 `SQLitePersistentReportingAndNelStore::Backend::AddNelPolicy` 方法，最终持久化到 SQLite 数据库中。

**假设输入与输出:**

**假设输入 (AddNelPolicy):**

```c++
NetworkErrorLoggingService::NelPolicy policy;
policy.key.origin = url::Origin::Create(GURL("https://example.com"));
policy.key.network_anonymization_key = NetworkAnonymizationKey(); // 假设为空
policy.received_ip_address = net::IPAddress(192, 168, 1, 1);
policy.report_to = "default";
policy.expires = base::Time::Now() + base::Days(7);
policy.success_fraction = 0.1;
policy.failure_fraction = 0.9;
policy.include_subdomains = true;
policy.last_used = base::Time::Now();
```

**预期输出:**

在 SQLite 数据库的 `nel_policies` 表中，会新增一条记录，其对应的字段值与输入 `policy` 对象中的数据一致。例如，`origin_scheme` 为 "https"，`origin_host` 为 "example.com"，`group_name` 为 "default"，`expires_us_since_epoch` 为 `policy.expires` 转换为微秒后的时间戳，等等。

**涉及用户或者编程常见的使用错误:**

1. **数据格式错误:** 编程人员在设置 NEL 策略或 Reporting 端点信息时，如果提供的参数格式不正确（例如，URL 格式错误），可能会导致数据无法正确存储或加载。
2. **权限问题:** 如果 SQLite 数据库文件所在的目录没有写入权限，则无法持久化数据，会导致功能异常。
3. **数据库损坏:**  在极少数情况下，SQLite 数据库文件可能损坏，导致数据丢失或程序崩溃。
4. **并发访问冲突 (虽然代码中使用了锁):**  如果多个进程或线程同时尝试访问和修改数据库，可能会导致数据不一致或死锁。尽管代码中使用了 `base::Lock` 来保护并发访问，但在复杂的场景下仍然需要谨慎处理。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问网站:** 用户在浏览器中输入网址 `https://example.com` 并访问。
2. **服务器响应包含 NEL/Report-To 头部:** `example.com` 的服务器返回的 HTTP 响应头中包含了 `NEL` 或 `Report-To` 头部，指示浏览器应该缓存 NEL 策略或 Reporting 端点。
3. **浏览器解析头部:** Chromium 的网络栈接收到响应后，会解析这些头部信息。
4. **NEL/Reporting 服务处理:**  `NetworkErrorLoggingService` 或 `ReportingService` 会接收解析后的策略或端点信息。
5. **调用持久化存储:** 这些服务会调用 `SQLitePersistentReportingAndNelStore` 的相应方法 (例如 `AddNelPolicy`, `AddReportingEndpoint`) 来将数据存储到数据库中。
6. **后台数据库操作:** `SQLitePersistentReportingAndNelStore::Backend` 会将这些操作添加到队列中，并在后台线程中执行 SQL 语句写入数据库。

在调试过程中，如果怀疑 NEL 策略或 Reporting 端点没有正确存储，可以：

*   检查网站响应头是否包含了预期的 `NEL` 或 `Report-To` 头部。
*   查看 Chromium 的网络日志 (`chrome://net-export/`)，确认是否接收到这些头部信息。
*   断点调试 `SQLitePersistentReportingAndNelStore::Backend` 的相关方法，查看传入的参数是否正确。
*   如果可以访问到用户的本地文件系统，可以检查 SQLite 数据库文件是否存在，以及其内容是否符合预期（需要使用 SQLite 数据库查看工具）。

**归纳一下它的功能 (第 1 部分):**

这部分代码定义了一个用于持久化存储 NEL 策略和 Reporting API 配置信息的组件。它使用 SQLite 数据库作为存储介质，提供了异步的增删改查操作，并考虑了 NetworkAnonymizationKey 的处理。核心是 `SQLitePersistentReportingAndNelStore::Backend` 类，它负责数据库的管理和操作。代码也定义了数据库的 schema 和迁移逻辑，并使用了批量处理来优化数据库写入性能。

Prompt: 
```
这是目录为net/extras/sqlite/sqlite_persistent_reporting_and_nel_store.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/extras/sqlite/sqlite_persistent_reporting_and_nel_store.h"

#include <list>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/json/json_reader.h"
#include "base/json/json_string_value_serializer.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/thread_annotations.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/extras/sqlite/sqlite_persistent_store_backend_base.h"
#include "net/reporting/reporting_endpoint.h"
#include "net/reporting/reporting_target_type.h"
#include "sql/database.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "sql/transaction.h"
#include "url/origin.h"

namespace net {

namespace {
// Version 1 - 2019/03 - crrev.com/c/1504493, crrev.com/c/1560456
//
// Version 1 adds tables for NEL policies, Reporting endpoints, and Reporting
// endpoint groups.
//
// Version 2 - 2020/10 - https://crrev.com/c/2485253
//
// Version 2 adds NetworkAnonymizationKey fields to all entries. When migrating,
// existing entries get an empty NetworkAnonymizationKey value.
const int kCurrentVersionNumber = 2;
const int kCompatibleVersionNumber = 2;

// Histogram names
const char kNumberOfLoadedNelPoliciesHistogramName[] =
    "ReportingAndNEL.NumberOfLoadedNELPolicies";
const char kNumberOfLoadedNelPolicies2HistogramName[] =
    "ReportingAndNEL.NumberOfLoadedNELPolicies2";
const char kNumberOfLoadedReportingEndpoints2HistogramName[] =
    "ReportingAndNEL.NumberOfLoadedReportingEndpoints2";
const char kNumberOfLoadedReportingEndpointGroups2HistogramName[] =
    "ReportingAndNEL.NumberOfLoadedReportingEndpointGroups2";
}  // namespace

base::TaskPriority GetReportingAndNelStoreBackgroundSequencePriority() {
  return base::TaskPriority::USER_BLOCKING;
}

// Converts a NetworkAnonymizationKey to a string for serializing to disk.
// Returns false on failure, which happens for transient keys that should not be
// serialized to disk.
[[nodiscard]] bool NetworkAnonymizationKeyToString(
    const NetworkAnonymizationKey& network_anonymization_key,
    std::string* out_string) {
  base::Value value;
  if (!network_anonymization_key.ToValue(&value))
    return false;
  return JSONStringValueSerializer(out_string).Serialize(value);
}

// Attempts to convert a string returned by NetworkAnonymizationKeyToString() to
// a NetworkAnonymizationKey. Returns false on failure.
[[nodiscard]] bool NetworkAnonymizationKeyFromString(
    const std::string& string,
    NetworkAnonymizationKey* out_network_anonymization_key) {
  std::optional<base::Value> value = base::JSONReader::Read(string);
  if (!value)
    return false;

  if (!NetworkAnonymizationKey::FromValue(*value,
                                          out_network_anonymization_key))
    return false;

  // If network state partitionining is disabled, but the
  // NetworkAnonymizationKeys is non-empty, ignore the entry. The entry will
  // still be in the on-disk database, in case NAKs are re-enabled, it just
  // won't be loaded into memory. The entry could still be loaded with an empty
  // NetworkAnonymizationKey, but that would require logic to resolve conflicts.
  if (!out_network_anonymization_key->IsEmpty() &&
      !NetworkAnonymizationKey::IsPartitioningEnabled()) {
    *out_network_anonymization_key = NetworkAnonymizationKey();
    return false;
  }

  return true;
}

class SQLitePersistentReportingAndNelStore::Backend
    : public SQLitePersistentStoreBackendBase {
 public:
  Backend(
      const base::FilePath& path,
      const scoped_refptr<base::SequencedTaskRunner>& client_task_runner,
      const scoped_refptr<base::SequencedTaskRunner>& background_task_runner)
      : SQLitePersistentStoreBackendBase(
            path,
            /* histogram_tag = */ "ReportingAndNEL",
            kCurrentVersionNumber,
            kCompatibleVersionNumber,
            background_task_runner,
            client_task_runner,
            /*enable_exclusive_access=*/false) {}

  Backend(const Backend&) = delete;
  Backend& operator=(const Backend&) = delete;

  void LoadNelPolicies(NelPoliciesLoadedCallback loaded_callback);
  void AddNelPolicy(const NetworkErrorLoggingService::NelPolicy& policy);
  void UpdateNelPolicyAccessTime(
      const NetworkErrorLoggingService::NelPolicy& policy);
  void DeleteNelPolicy(const NetworkErrorLoggingService::NelPolicy& policy);

  void LoadReportingClients(ReportingClientsLoadedCallback loaded_callback);
  void AddReportingEndpoint(const ReportingEndpoint& endpoint);
  void AddReportingEndpointGroup(const CachedReportingEndpointGroup& group);
  void UpdateReportingEndpointGroupAccessTime(
      const CachedReportingEndpointGroup& group);
  void UpdateReportingEndpointDetails(const ReportingEndpoint& endpoint);
  void UpdateReportingEndpointGroupDetails(
      const CachedReportingEndpointGroup& group);
  void DeleteReportingEndpoint(const ReportingEndpoint& endpoint);
  void DeleteReportingEndpointGroup(const CachedReportingEndpointGroup& group);

  // Gets the number of queued operations.
  size_t GetQueueLengthForTesting() const;

 private:
  ~Backend() override {
    DCHECK(nel_policy_pending_ops_.empty());
    DCHECK(reporting_endpoint_pending_ops_.empty());
    DCHECK(reporting_endpoint_group_pending_ops_.empty());
    DCHECK_EQ(0u, num_pending_);
  }

  // Represents a mutating operation to the database, specified by a type (add,
  // update access time, update data, or delete) and data representing the entry
  // in the database to be added/updated/deleted.
  template <typename DataType>
  class PendingOperation;

  // Types of PendingOperation. Here to avoid templatizing the enum.
  enum class PendingOperationType {
    ADD,
    UPDATE_ACCESS_TIME,
    UPDATE_DETAILS,
    DELETE
  };

  // List of pending operations for a particular entry in the database.
  template <typename DataType>
  using PendingOperationsVector =
      std::vector<std::unique_ptr<PendingOperation<DataType>>>;

  // A copy of the information relevant to a NEL policy.
  struct NelPolicyInfo;
  // A copy of the information relevant to a Reporting endpoint.
  struct ReportingEndpointInfo;
  // A copy of the information relevant to a Reporting endpoint group.
  struct ReportingEndpointGroupInfo;
  // TODO(chlily): add ReportingReportInfo.

  // Uniquely identifies an endpoint in the store.
  using ReportingEndpointKey = std::pair<ReportingEndpointGroupKey, GURL>;

  // Map of pending operations for each entry in the database.
  // Key types are: - url::Origin for NEL policies,
  //                - ReportingEndpointKey for Reporting endpoints,
  //                - ReportingEndpointGroupKey for Reporting endpoint groups
  //                  (defined in //net/reporting/reporting_endpoint.h).
  template <typename KeyType, typename DataType>
  using QueueType = std::map<KeyType, PendingOperationsVector<DataType>>;

  // SQLitePersistentStoreBackendBase implementation
  bool CreateDatabaseSchema() override;
  std::optional<int> DoMigrateDatabaseSchema() override;
  void DoCommit() override;

  // Commit a pending operation pertaining to a NEL policy.
  // Returns true on success.
  bool CommitNelPolicyOperation(PendingOperation<NelPolicyInfo>* op);
  // Commit a pending operation pertaining to a Reporting endpoint.
  // Returns true on success.
  bool CommitReportingEndpointOperation(
      PendingOperation<ReportingEndpointInfo>* op);
  // Commit a pending operation pertaining to a Reporting endpoint group.
  // Returns true on success.
  bool CommitReportingEndpointGroupOperation(
      PendingOperation<ReportingEndpointGroupInfo>* op);

  // Add a pending operation to the appropriate queue.
  template <typename KeyType, typename DataType>
  void BatchOperation(KeyType key,
                      std::unique_ptr<PendingOperation<DataType>> po,
                      QueueType<KeyType, DataType>* queue);

  // If there are existing pending operations for a given key, potentially
  // remove some of the existing operations before adding |new_op|.
  // In particular, if |new_op| is a deletion, then all the previous pending
  // operations are made irrelevant and can be deleted. If |new_op| is an
  // update-access-time, and the last operation in |ops_for_key| is also an
  // update-access-time, then it can be discarded because |new_op| is about to
  // overwrite the access time with a new value anyway. Similarly for
  // update-details.
  template <typename DataType>
  void MaybeCoalesceOperations(PendingOperationsVector<DataType>* ops_for_key,
                               PendingOperation<DataType>* new_op)
      EXCLUSIVE_LOCKS_REQUIRED(lock_);

  // After adding a pending operation to one of the pending operations queues,
  // this method posts a task to commit all pending operations if we reached the
  // batch size, or starts a timer to commit after a time interval if we just
  // started a new batch. |num_pending| is the total number of pending
  // operations after the one we just added.
  void OnOperationBatched(size_t num_pending);

  // Loads NEL policies into a vector in the background, then posts a
  // task to the client task runner to call |loaded_callback| with the loaded
  // NEL policies.
  void LoadNelPoliciesAndNotifyInBackground(
      NelPoliciesLoadedCallback loaded_callback);

  // Calls |loaded_callback| with the loaded NEL policies (which may be empty if
  // loading was unsuccessful). If loading was successful, also report metrics.
  void CompleteLoadNelPoliciesAndNotifyInForeground(
      NelPoliciesLoadedCallback loaded_callback,
      std::vector<NetworkErrorLoggingService::NelPolicy> loaded_policies,
      bool load_success);

  // Loads Reporting endpoints and endpoint groups into two vectors in the
  // background, then posts a task to the client task runner to call
  // |loaded_callback| with the loaded endpoints and endpoint groups.
  void LoadReportingClientsAndNotifyInBackground(
      ReportingClientsLoadedCallback loaded_callback);

  // Calls |loaded_callback| with the loaded endpoints and endpoint groups
  // (which may be empty if loading was unsuccessful). If loading was
  // successful, also report metrics.
  void CompleteLoadReportingClientsAndNotifyInForeground(
      ReportingClientsLoadedCallback loaded_callback,
      std::vector<ReportingEndpoint> loaded_endpoints,
      std::vector<CachedReportingEndpointGroup> loaded_endpoint_groups,
      bool load_success);

  void RecordNumberOfLoadedNelPolicies(size_t count);
  void RecordNumberOfLoadedReportingEndpoints(size_t count);
  void RecordNumberOfLoadedReportingEndpointGroups(size_t count);

  // Total number of pending operations (may not match the sum of the number of
  // elements in the pending operations queues, due to operation coalescing).
  size_t num_pending_ GUARDED_BY(lock_) = 0;

  // Queue of pending operations pertaining to NEL policies, keyed on origin.
  QueueType<NetworkErrorLoggingService::NelPolicyKey, NelPolicyInfo>
      nel_policy_pending_ops_ GUARDED_BY(lock_);
  // Queue of pending operations pertaining to Reporting endpoints, keyed on
  // origin, group name, and url.
  QueueType<ReportingEndpointKey, ReportingEndpointInfo>
      reporting_endpoint_pending_ops_ GUARDED_BY(lock_);
  // Queue of pending operations pertaining to Reporting endpoint groups, keyed
  // on origin and group name.
  QueueType<ReportingEndpointGroupKey, ReportingEndpointGroupInfo>
      reporting_endpoint_group_pending_ops_ GUARDED_BY(lock_);

  // TODO(chlily): add reporting_report_pending_ops_ for Reporting reports.

  // Protects |num_pending_|, and all the pending operations queues.
  mutable base::Lock lock_;
};

namespace {

bool CreateV2NelPoliciesSchema(sql::Database* db) {
  DCHECK(!db->DoesTableExist("nel_policies"));

  const char stmt[] =
      "CREATE TABLE nel_policies ("
      "  nik TEXT NOT NULL,"
      "  origin_scheme TEXT NOT NULL,"
      "  origin_host TEXT NOT NULL,"
      "  origin_port INTEGER NOT NULL,"
      "  received_ip_address TEXT NOT NULL,"
      "  group_name TEXT NOT NULL,"
      "  expires_us_since_epoch INTEGER NOT NULL,"
      "  success_fraction REAL NOT NULL,"
      "  failure_fraction REAL NOT NULL,"
      "  is_include_subdomains INTEGER NOT NULL,"
      "  last_access_us_since_epoch INTEGER NOT NULL,"
      // Each (origin, nik) specifies at most one NEL policy.
      "  UNIQUE (origin_scheme, origin_host, origin_port, nik)"
      ")";

  return db->Execute(stmt);
}

bool CreateV2ReportingEndpointsSchema(sql::Database* db) {
  DCHECK(!db->DoesTableExist("reporting_endpoints"));

  const char stmt[] =
      "CREATE TABLE reporting_endpoints ("
      "  nik TEXT NOT NULL,"
      "  origin_scheme TEXT NOT NULL,"
      "  origin_host TEXT NOT NULL,"
      "  origin_port INTEGER NOT NULL,"
      "  group_name TEXT NOT NULL,"
      "  url TEXT NOT NULL,"
      "  priority INTEGER NOT NULL,"
      "  weight INTEGER NOT NULL,"
      // Each (origin, group, url, nik) tuple specifies at most one endpoint.
      "  UNIQUE (origin_scheme, origin_host, origin_port, group_name, url, nik)"
      ")";

  return db->Execute(stmt);
}

bool CreateV2ReportingEndpointGroupsSchema(sql::Database* db) {
  DCHECK(!db->DoesTableExist("reporting_endpoint_groups"));

  const char stmt[] =
      "CREATE TABLE reporting_endpoint_groups ("
      "  nik TEXT NOT NULL,"
      "  origin_scheme TEXT NOT NULL,"
      "  origin_host TEXT NOT NULL,"
      "  origin_port INTEGER NOT NULL,"
      "  group_name TEXT NOT NULL,"
      "  is_include_subdomains INTEGER NOT NULL,"
      "  expires_us_since_epoch INTEGER NOT NULL,"
      "  last_access_us_since_epoch INTEGER NOT NULL,"
      // Each (origin, group, nik) tuple specifies at most one endpoint group.
      "  UNIQUE (origin_scheme, origin_host, origin_port, group_name, nik)"
      ")";

  return db->Execute(stmt);
}

}  // namespace

template <typename DataType>
class SQLitePersistentReportingAndNelStore::Backend::PendingOperation {
 public:
  PendingOperation(PendingOperationType type, DataType data)
      : type_(type), data_(std::move(data)) {}

  PendingOperationType type() const { return type_; }
  const DataType& data() const { return data_; }

 private:
  const PendingOperationType type_;
  const DataType data_;
};

// Makes a copy of the relevant information about a NelPolicy, stored in a
// form suitable for adding to the database.
// TODO(chlily): Add NIK.
struct SQLitePersistentReportingAndNelStore::Backend::NelPolicyInfo {
  // This should only be invoked through CreatePendingOperation().
  NelPolicyInfo(const NetworkErrorLoggingService::NelPolicy& nel_policy,
                std::string network_anonymization_key_string)
      : network_anonymization_key_string(
            std::move(network_anonymization_key_string)),
        origin_scheme(nel_policy.key.origin.scheme()),
        origin_host(nel_policy.key.origin.host()),
        origin_port(nel_policy.key.origin.port()),
        received_ip_address(nel_policy.received_ip_address.ToString()),
        report_to(nel_policy.report_to),
        expires_us_since_epoch(
            nel_policy.expires.ToDeltaSinceWindowsEpoch().InMicroseconds()),
        success_fraction(nel_policy.success_fraction),
        failure_fraction(nel_policy.failure_fraction),
        is_include_subdomains(nel_policy.include_subdomains),
        last_access_us_since_epoch(
            nel_policy.last_used.ToDeltaSinceWindowsEpoch().InMicroseconds()) {}

  // Creates the specified operation for the given policy. Returns nullptr for
  // endpoints with transient NetworkAnonymizationKeys.
  static std::unique_ptr<PendingOperation<NelPolicyInfo>>
  CreatePendingOperation(
      PendingOperationType type,
      const NetworkErrorLoggingService::NelPolicy& nel_policy) {
    std::string network_anonymization_key_string;
    if (!NetworkAnonymizationKeyToString(
            nel_policy.key.network_anonymization_key,
            &network_anonymization_key_string)) {
      return nullptr;
    }

    return std::make_unique<PendingOperation<NelPolicyInfo>>(
        type,
        NelPolicyInfo(nel_policy, std::move(network_anonymization_key_string)));
  }

  // NetworkAnonymizationKey associated with the request that received the
  // policy, converted to a string via NetworkAnonymizationKeyToString().
  std::string network_anonymization_key_string;

  // Origin the policy was received from.
  std::string origin_scheme;
  std::string origin_host;
  int origin_port = 0;

  // IP address of the server that the policy was received from.
  std::string received_ip_address;
  // The Reporting group which the policy specifies.
  std::string report_to;
  // When the policy expires, in microseconds since the Windows epoch.
  int64_t expires_us_since_epoch = 0;
  // Sampling fractions.
  double success_fraction = 0.0;
  double failure_fraction = 1.0;
  // Whether the policy applies to subdomains of the origin.
  bool is_include_subdomains = false;
  // Last time the policy was updated or used, in microseconds since the
  // Windows epoch.
  int64_t last_access_us_since_epoch = 0;
};

// Makes a copy of the relevant information about a ReportingEndpoint, stored in
// a form suitable for adding to the database.
struct SQLitePersistentReportingAndNelStore::Backend::ReportingEndpointInfo {
  // This should only be invoked through CreatePendingOperation().
  ReportingEndpointInfo(const ReportingEndpoint& endpoint,
                        std::string network_anonymization_key_string)
      : network_anonymization_key_string(
            std::move(network_anonymization_key_string)),
        group_name(endpoint.group_key.group_name),
        url(endpoint.info.url.spec()),
        priority(endpoint.info.priority),
        weight(endpoint.info.weight) {
    // The group key should have an origin.
    DCHECK(endpoint.group_key.origin.has_value());
    origin_scheme = endpoint.group_key.origin.value().scheme();
    origin_host = endpoint.group_key.origin.value().host();
    origin_port = endpoint.group_key.origin.value().port();
  }

  // Creates the specified operation for the given endpoint. Returns nullptr for
  // endpoints with transient NetworkAnonymizationKeys.
  static std::unique_ptr<PendingOperation<ReportingEndpointInfo>>
  CreatePendingOperation(PendingOperationType type,
                         const ReportingEndpoint& endpoint) {
    std::string network_anonymization_key_string;
    if (!NetworkAnonymizationKeyToString(
            endpoint.group_key.network_anonymization_key,
            &network_anonymization_key_string)) {
      return nullptr;
    }

    return std::make_unique<PendingOperation<ReportingEndpointInfo>>(
        type, ReportingEndpointInfo(
                  endpoint, std::move(network_anonymization_key_string)));
  }

  // NetworkAnonymizationKey associated with the endpoint, converted to a string
  // via NetworkAnonymizationKeyString().
  std::string network_anonymization_key_string;

  // Origin the endpoint was received from.
  std::string origin_scheme;
  std::string origin_host;
  int origin_port = 0;

  // Name of the group the endpoint belongs to.
  std::string group_name;
  // URL of the endpoint.
  std::string url;
  // Priority of the endpoint.
  int priority = ReportingEndpoint::EndpointInfo::kDefaultPriority;
  // Weight of the endpoint.
  int weight = ReportingEndpoint::EndpointInfo::kDefaultWeight;
};

struct SQLitePersistentReportingAndNelStore::Backend::
    ReportingEndpointGroupInfo {
  ReportingEndpointGroupInfo(const CachedReportingEndpointGroup& group,
                             std::string network_anonymization_key_string)
      : network_anonymization_key_string(
            std::move(network_anonymization_key_string)),
        group_name(group.group_key.group_name),
        is_include_subdomains(group.include_subdomains ==
                              OriginSubdomains::INCLUDE),
        expires_us_since_epoch(
            group.expires.ToDeltaSinceWindowsEpoch().InMicroseconds()),
        last_access_us_since_epoch(
            group.last_used.ToDeltaSinceWindowsEpoch().InMicroseconds()) {
    // The group key should have an origin.
    DCHECK(group.group_key.origin.has_value());
    origin_scheme = group.group_key.origin.value().scheme();
    origin_host = group.group_key.origin.value().host();
    origin_port = group.group_key.origin.value().port();
  }

  // Creates the specified operation for the given endpoint reporting group.
  // Returns nullptr for groups with transient NetworkAnonymizationKeys.
  static std::unique_ptr<PendingOperation<ReportingEndpointGroupInfo>>
  CreatePendingOperation(PendingOperationType type,
                         const CachedReportingEndpointGroup& group) {
    std::string network_anonymization_key_string;
    if (!NetworkAnonymizationKeyToString(
            group.group_key.network_anonymization_key,
            &network_anonymization_key_string)) {
      return nullptr;
    }

    return std::make_unique<PendingOperation<ReportingEndpointGroupInfo>>(
        type, ReportingEndpointGroupInfo(
                  group, std::move(network_anonymization_key_string)));
  }

  // NetworkAnonymizationKey associated with the endpoint group, converted to a
  // string via NetworkAnonymizationKeyToString().
  std::string network_anonymization_key_string;

  // Origin the endpoint group was received from.
  std::string origin_scheme;
  std::string origin_host;
  int origin_port = 0;

  // Name of the group.
  std::string group_name;
  // Whether the group applies to subdomains of the origin.
  bool is_include_subdomains = false;
  // When the group expires, in microseconds since the Windows epoch.
  int64_t expires_us_since_epoch = 0;
  // Last time the group was updated or used, in microseconds since the Windows
  // epoch.
  int64_t last_access_us_since_epoch = 0;
};

void SQLitePersistentReportingAndNelStore::Backend::LoadNelPolicies(
    NelPoliciesLoadedCallback loaded_callback) {
  PostBackgroundTask(
      FROM_HERE, base::BindOnce(&Backend::LoadNelPoliciesAndNotifyInBackground,
                                this, std::move(loaded_callback)));
}

void SQLitePersistentReportingAndNelStore::Backend::AddNelPolicy(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  auto po =
      NelPolicyInfo::CreatePendingOperation(PendingOperationType::ADD, policy);
  if (!po)
    return;
  BatchOperation(policy.key, std::move(po), &nel_policy_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::UpdateNelPolicyAccessTime(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  auto po = NelPolicyInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_ACCESS_TIME, policy);
  if (!po)
    return;
  BatchOperation(policy.key, std::move(po), &nel_policy_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::DeleteNelPolicy(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  auto po = NelPolicyInfo::CreatePendingOperation(PendingOperationType::DELETE,
                                                  policy);
  if (!po)
    return;
  BatchOperation(policy.key, std::move(po), &nel_policy_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::LoadReportingClients(
    ReportingClientsLoadedCallback loaded_callback) {
  PostBackgroundTask(
      FROM_HERE,
      base::BindOnce(&Backend::LoadReportingClientsAndNotifyInBackground, this,
                     std::move(loaded_callback)));
}

void SQLitePersistentReportingAndNelStore::Backend::AddReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  auto po = ReportingEndpointInfo::CreatePendingOperation(
      PendingOperationType::ADD, endpoint);
  if (!po)
    return;
  ReportingEndpointKey key = std::pair(endpoint.group_key, endpoint.info.url);
  BatchOperation(std::move(key), std::move(po),
                 &reporting_endpoint_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::AddReportingEndpointGroup(
    const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::ADD, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    UpdateReportingEndpointGroupAccessTime(
        const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_ACCESS_TIME, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    UpdateReportingEndpointDetails(const ReportingEndpoint& endpoint) {
  auto po = ReportingEndpointInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_DETAILS, endpoint);
  if (!po)
    return;
  ReportingEndpointKey key = std::pair(endpoint.group_key, endpoint.info.url);
  BatchOperation(std::move(key), std::move(po),
                 &reporting_endpoint_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    UpdateReportingEndpointGroupDetails(
        const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_DETAILS, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::DeleteReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  auto po = ReportingEndpointInfo::CreatePendingOperation(
      PendingOperationType::DELETE, endpoint);
  if (!po)
    return;
  ReportingEndpointKey key = std::pair(endpoint.group_key, endpoint.info.url);
  BatchOperation(std::move(key), std::move(po),
                 &reporting_endpoint_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    DeleteReportingEndpointGroup(const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::DELETE, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

size_t SQLitePersistentReportingAndNelStore::Backend::GetQueueLengthForTesting()
    const {
  size_t count = 0;
  {
    base::AutoLock locked(lock_);
    for (auto& key_and_pending_ops : nel_policy_pending_ops_) {
      count += key_and_pending_ops.second.size();
    }
    for (auto& key_and_pending_ops : reporting_endpoint_pending_ops_) {
      count += key_and_pending_ops.second.size();
    }
    for (auto& key_and_pending_ops : reporting_endpoint_group_pending_ops_) {
      count += key_and_pending_ops.second.size();
    }
  }
  return count;
}

bool SQLitePersistentReportingAndNelStore::Backend::CreateDatabaseSchema() {
  if (!db()->DoesTableExist("nel_policies") &&
      !CreateV2NelPoliciesSchema(db())) {
    return false;
  }

  if (!db()->DoesTableExist("reporting_endpoints") &&
      !CreateV2ReportingEndpointsSchema(db())) {
    return false;
  }

  if (!db()->DoesTableExist("reporting_endpoint_groups") &&
      !CreateV2ReportingEndpointGroupsSchema(db())) {
    return false;
  }

  // TODO(chlily): Initialize tables for Reporting reports.

  return true;
}

std::optional<int>
SQLitePersistentReportingAndNelStore::Backend::DoMigrateDatabaseSchema() {
  int cur_version = meta_table()->GetVersionNumber();

  // Migrate from version 1 to version 2.
  //
  // For migration purposes, the NetworkAnonymizationKey field of the stored
  // policies will be populated with an empty list, which corresponds to an
  // empty NAK. This matches the behavior when NAKs are disabled. This will
  // result in effectively clearing all policies once NAKs are enabled, at
  // which point the the migration code should just be switched to deleting
  // the old tables instead.
  if (cur_version == 1) {
    sql::Transaction transaction(db());
    if (!transaction.Begin())
      return std::nullopt;

    // Migrate NEL policies table.
    if (!db()->Execute("DROP TABLE IF EXISTS nel_policies_old; "
                       "ALTER TABLE nel_policies RENAME TO nel_policies_old")) {
      return std::nullopt;
    }
    if (!CreateV2NelPoliciesSchema(db()))
      return std::nullopt;
    // clang-format off
    // The "report_to" field is renamed to "group_name" for consistency with
    // the other tables.
    const char nel_policies_migrate_stmt[] =
      "INSERT INTO nel_policies (nik, origin_scheme, origin_host, "
      "  origin_port, group_name, received_ip_address, expires_us_since_epoch, "
      "  success_fraction, failure_fraction, is_include_subdomains, "
      "  last_access_us_since_epoch) "
      "SELECT '[]', origin_scheme, origin_host, origin_port, "
      "  report_to, received_ip_address, expires_us_since_epoch, "
      "  success_fraction, failure_fraction, is_include_subdomains, "
      "  last_access_us_since_epoch "
      "FROM nel_policies_old" ;
    // clang-format on
    if (!db()->Execute(nel_policies_migrate_stmt)) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP TABLE nel_policies_old"))
      return std::nullopt;

    // Migrate Reporting endpoints table.
    if (!db()->Execute("DROP TABLE IF EXISTS reporting_endpoints_old; "
                       "ALTER TABLE reporting_endpoints RENAME TO "
                       "reporting_endpoints_old")) {
      return std::nullopt;
    }
    if (!CreateV2ReportingEndpointsSchema(db()))
      return std::nullopt;
    // clang-format off
    const char reporting_endpoints_migrate_stmt[] =
      "INSERT INTO reporting_endpoints (nik,  origin_scheme, origin_host, "
      "  origin_port, group_name, url, priority, weight) "
      "SELECT '[]', origin_scheme, origin_host, origin_port, group_name, "
      "  url, priority, weight "
      "FROM reporting_endpoints_old" ;
    // clang-format on
    if (!db()->Execute(reporting_endpoints_migrate_stmt)) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP TABLE reporting_endpoints_old"))
      return std::nullopt;

    // Migrate Reporting endpoint groups table.
    if (!db()->Execute("DROP TABLE IF EXISTS reporting_endpoint_groups_old; "
                       "ALTER TABLE reporting_endpoint_groups RENAME TO "
                       "reporting_endpoint_groups_old")) {
      return std::nullopt;
    }
    if (!CreateV2ReportingEndpointGroupsSchema(db()))
      return std::nullopt;
    // clang-format off
    const char reporting_endpoint_groups_migrate_stmt[] =
      "INSERT INTO reporting_endpoint_groups (nik,  origin_scheme, "
      "  origin_host, origin_port, group_name, is_include_subdomains, "
      "  expires_us_since_epoch, last_access_us_since_epoch) "
      "SELECT '[]', origin_scheme, origin_host, origin_port, "
      "  group_name, is_include_subdomains, expires_us_since_epoch, "
      "  last_access_us_since_epoch "
      "FROM reporting_endpoint_groups_old" ;
    // clang-format on
    if (!db()->Execute(reporting_endpoint_groups_migrate_stmt)) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP TABLE reporting_endpoint_groups_old"))
      return std::nullopt;

    ++cur_version;
    if (!meta_table()->SetVersionNumber(cur_version) ||
        !meta_table()->SetCompatibleVersionNumber(
            std::min(cur_version, kCompatibleVersionNumber)) ||
        !transaction.Commit()) {
      return std::nullopt;
    }
  }

  // Future database upgrade statements go here.

  return std::make_optional(cur_version);
}

void SQLitePersistentReportingAndNelStore::Backend::DoCommit() {
  QueueType<NetworkErrorLoggingService::NelPolicyKey, NelPolicyInfo>
      nel_policy_ops;
  QueueType<ReportingEndpointKey, ReportingEndpointInfo> reporting_endpoint_ops;
  QueueType<ReportingEndpointGroupKey, ReportingEndpointGroupInfo>
      reporting_endpoint_group_ops;
  size_t op_count = 0;
  {
    base::AutoLock locked(lock_);
    nel_policy_pending_ops_.swap(nel_policy_ops);
    reporting_endpoint_pending_ops_.swap(reporting_endpoint_ops);
    reporting_endpoint_group_pending_ops_.swap(reporting_endpoint_group_ops);
    // TODO(chlily): swap out pending operations queue for Re
"""


```