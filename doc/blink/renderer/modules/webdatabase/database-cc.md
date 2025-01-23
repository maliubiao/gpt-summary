Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/modules/webdatabase/database.cc`. The summary should cover:

1. **Core Functions:** What does this code do?
2. **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS? Provide examples if applicable.
3. **Logical Inference:** If any logical deductions are made within the code, provide input and output examples.
4. **Common User Errors:**  What mistakes do users or programmers typically make when interacting with this functionality?
5. **User Journey:** How does a user action lead to this code being executed (debugging clues)?
6. **Overall Function (Part 1):**  A concise summary of the code's purpose.

Let's break down the code to address these points:

*   **Includes:** The included headers reveal dependencies on threading, platform services, core Blink concepts (execution context, frames), and other webdatabase-related modules.
*   **DatabaseVersionCache:** This class manages a cache of database versions, keyed by origin and name. This suggests that the code is concerned with tracking and potentially caching database state.
*   **Helper Functions:** `FormatErrorMessage`, `RetrieveTextResultFromDatabase`, `SetTextValueInDatabase` indicate interactions with an underlying database (likely SQLite).
*   **Database Class:** This is the central class. Key members and methods:
    *   `OpenAndVerifyVersion`, `PerformOpenAndVerify`:  Opening and verifying the database, including version checks and creating the info table if necessary.
    *   `Close`, `CloseDatabase`: Closing the database connection.
    *   `RunTransaction`, `ScheduleTransaction`: Managing transactions, including queuing and scheduling them on a separate thread.
    *   `version`, `GetVersionFromDatabase`, `SetVersionInDatabase`: Accessing and modifying the database version.
    *   `changeVersion`, `transaction`, `readTransaction`: Public methods to initiate database transactions from JavaScript.
    *   `DatabaseAuthorizer`:  A component to control database access permissions.
*   **Database Tracking:** The comments about `DatabaseTracker` highlight the role of this component in keeping track of open databases.
*   **Threading:** The code extensively uses threading primitives (e.g., `base::WaitableEvent`, `base::Lock`, scheduling tasks on a separate thread) indicating that database operations are handled asynchronously.

**Now, let's construct the summary based on these observations.**
这是 `blink/renderer/modules/webdatabase/database.cc` 文件的第一部分，主要负责 `blink::Database` 类的实现。这个类是 Web SQL Database API 的核心，代表一个打开的数据库连接，并处理与该数据库相关的操作。以下是其主要功能的归纳：

**核心功能：**

1. **数据库生命周期管理:**
    *   **打开数据库 (`OpenAndVerifyVersion`, `PerformOpenAndVerify`):**  负责打开底层的 SQLite 数据库文件，并验证或设置数据库的版本信息。这包括创建必要的元数据表（`__WebKitDatabaseInfoTable__`）以及处理新数据库的创建。
    *   **关闭数据库 (`Close`, `CloseDatabase`):**  安全地关闭数据库连接，释放资源。这涉及到清理未完成的事务。
2. **事务管理:**
    *   **启动事务 (`RunTransaction`):**  接收来自 JavaScript 的事务请求，将其封装成 `SQLTransactionBackend` 对象并加入到事务队列中。
    *   **调度事务 (`ScheduleTransaction`, `ScheduleTransactionStep`):**  负责将队列中的事务调度到数据库线程上执行。
    *   **跟踪事务状态 (`InProgressTransactionCompleted`):**  在事务完成后更新状态。
3. **版本管理:**
    *   **获取和设置版本 (`version`, `GetVersionFromDatabase`, `SetVersionInDatabase`):**  从数据库的元数据表中读取和更新数据库的版本号。使用了缓存 (`DatabaseVersionCache`) 来提高性能，尤其是在多进程浏览器中。
    *   **版本校验:** 在打开数据库时，会校验期望的版本号与数据库中已有的版本号是否一致。
    *   **`changeVersion` 方法:**  允许通过 JavaScript 修改数据库的版本号，并执行一个包含版本变更的事务。
4. **权限控制 (`DatabaseAuthorizer`):**
    *   使用 `DatabaseAuthorizer` 类来控制对数据库的访问权限，例如限制某些 SQL 操作。
5. **错误处理:**
    *   提供格式化错误消息的辅助函数 (`FormatErrorMessage`).
    *   向 `WebDatabaseHost` 报告 SQLite 错误。
    *   将错误消息记录到控制台。
6. **与 `DatabaseTracker` 交互:**
    *   注册已打开的数据库，以便 `DatabaseTracker` 可以跟踪和管理所有打开的数据库，用于中断或删除操作。
7. **线程管理:**
    *   利用单独的数据库线程来执行数据库操作，避免阻塞主线程。
    *   使用任务队列和事件机制在不同线程之间进行通信和同步。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**  `blink::Database` 类是 Web SQL Database API 的底层实现，JavaScript 通过 `openDatabase()` 函数获取 `Database` 对象的实例，并调用其 `transaction()`, `readTransaction()`, `changeVersion()` 等方法来执行 SQL 语句。例如：

    ```javascript
    // JavaScript 示例
    var db = openDatabase('mydb', '1.0', 'My Database', 2 * 1024 * 1024);

    db.transaction(function (tx) {
      tx.executeSql('CREATE TABLE IF NOT EXISTS LOGS (id unique, log)');
      tx.executeSql('INSERT INTO LOGS (id, log) VALUES (1, "Foo")');
    });

    db.changeVersion('', '2.0', function(tx) {
      tx.executeSql('ALTER TABLE LOGS ADD COLUMN timestamp REAL');
    }, function(error) {
      console.error('Error changing version: ' + error.message);
    }, function() {
      console.log('Version changed successfully!');
    });
    ```
    在这个例子中，JavaScript 调用了 `openDatabase` 来请求打开一个数据库，然后使用 `transaction` 和 `changeVersion` 方法，这些方法在 Blink 引擎中最终会调用到 `blink::Database` 类的相应方法，例如 `RunTransaction`。

*   **HTML:**  HTML 本身不直接与 `blink::Database` 交互。Web SQL Database API 是通过 JavaScript 访问的。HTML 页面中嵌入的 JavaScript 代码可以利用这个 API 来进行客户端数据存储。

*   **CSS:** CSS 与 `blink::Database` 没有直接关系。CSS 负责页面的样式和布局，而 `blink::Database` 负责客户端的数据存储。

**逻辑推理示例：**

*   **假设输入:** JavaScript 调用 `openDatabase('mydb', '1.0', ..., ...)`，数据库文件不存在。
*   **逻辑推理:** `PerformOpenAndVerify` 方法会被调用，检测到数据库文件不存在，会创建新的数据库文件，并创建 `__WebKitDatabaseInfoTable__` 表，并将版本设置为 '1.0'。
*   **输出:** 数据库文件创建成功，`blink::Database` 对象被创建并关联到该文件，其内部状态 `new_` 被设置为 `true`。

*   **假设输入:** JavaScript 调用 `openDatabase('mydb', '2.0', ..., ...)`，数据库已存在，版本为 '1.0'。
*   **逻辑推理:** `PerformOpenAndVerify` 方法会被调用，读取到数据库的当前版本为 '1.0'，与期望的版本 '2.0' 不匹配。
*   **输出:** 数据库打开失败，并生成一个错误消息，指示版本不匹配。

**用户或编程常见的使用错误：**

*   **忘记处理错误回调:**  开发者在调用 `transaction` 或 `changeVersion` 时，可能没有提供或正确处理错误回调函数 (`error_callback`)。这会导致在数据库操作失败时，用户或开发者无法得知具体原因。
    ```javascript
    // 错误示例：缺少错误回调
    db.transaction(function (tx) {
      tx.executeSql('INSERT INTO non_existent_table (col) VALUES ("value")');
    });
    ```
*   **在回调函数中假设同步执行:**  Web SQL Database 的操作是异步的。开发者可能会错误地假设在 `transaction` 或 `executeSql` 调用后，数据库操作立即完成。
*   **版本号管理混乱:** 在使用 `changeVersion` 时，如果开发者对版本号的更新逻辑没有清晰的规划，可能会导致版本号混乱，难以追踪数据库的变更历史。
*   **未正确关闭数据库:** 虽然浏览器会自动管理数据库的关闭，但在某些特殊情况下，例如程序错误导致 `Database` 对象无法正常释放，可能会导致资源泄漏。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户访问包含 Web SQL Database 操作的网页:** 用户在浏览器中打开一个包含使用 Web SQL Database API 的 JavaScript 代码的 HTML 页面。
2. **JavaScript 调用 `openDatabase()`:** 网页中的 JavaScript 代码调用 `openDatabase()` 函数请求打开或创建一个数据库。
3. **Blink 引擎处理 `openDatabase()`:** 浏览器接收到 `openDatabase()` 的调用，Blink 引擎开始处理这个请求。
4. **创建 `DatabaseContext` (如果需要):**  Blink 引擎可能会首先创建或获取一个与当前上下文相关的 `DatabaseContext` 对象，用于管理数据库操作。
5. **调用 `DatabaseServer` 创建 `Database` 对象:** `DatabaseContext` 或相关的组件会请求 `DatabaseServer` 创建一个 `blink::Database` 对象来表示要打开的数据库。
6. **执行 `OpenAndVerifyVersion`:**  `blink::Database` 对象的 `OpenAndVerifyVersion` 方法被调用，该方法会将实际的打开操作调度到数据库线程。
7. **数据库线程执行 `PerformOpenAndVerify`:** 在数据库线程上，`PerformOpenAndVerify` 方法会被执行，进行实际的数据库文件打开、版本校验等操作。
8. **后续事务操作:** 如果 JavaScript 代码调用了 `transaction` 或 `changeVersion`，这些调用会最终触发 `blink::Database` 的 `RunTransaction` 方法，并将事务调度到数据库线程执行。

**总结 (第 1 部分功能):**

`blink/renderer/modules/webdatabase/database.cc` 的第一部分主要定义并实现了 `blink::Database` 类，它是 Web SQL Database API 的核心，负责处理数据库的打开、关闭、版本管理、事务调度以及基本的权限控制。它充当了 JavaScript 与底层 SQLite 数据库之间的桥梁，确保数据库操作在独立的线程上执行，并提供了一系列方法来管理数据库的生命周期和状态。

### 提示词
```
这是目录为blink/renderer/modules/webdatabase/database.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/webdatabase/database.h"

#include <memory>
#include <utility>

#include "base/synchronization/waitable_event.h"
#include "base/thread_annotations.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/webdatabase/change_version_data.h"
#include "third_party/blink/renderer/modules/webdatabase/change_version_wrapper.h"
#include "third_party/blink/renderer/modules/webdatabase/database_authorizer.h"
#include "third_party/blink/renderer/modules/webdatabase/database_context.h"
#include "third_party/blink/renderer/modules/webdatabase/database_task.h"
#include "third_party/blink/renderer/modules/webdatabase/database_thread.h"
#include "third_party/blink/renderer/modules/webdatabase/database_tracker.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_error.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_transaction_backend.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_transaction_client.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_transaction_coordinator.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sqlite_statement.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sqlite_transaction.h"
#include "third_party/blink/renderer/modules/webdatabase/storage_log.h"
#include "third_party/blink/renderer/modules/webdatabase/web_database_host.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

// Registering "opened" databases with the DatabaseTracker
// =======================================================
// The DatabaseTracker maintains a list of databases that have been
// "opened" so that the client can call interrupt or delete on every database
// associated with a DatabaseContext.
//
// We will only call DatabaseTracker::addOpenDatabase() to add the database
// to the tracker as opened when we've succeeded in opening the database,
// and will set m_opened to true. Similarly, we only call
// DatabaseTracker::removeOpenDatabase() to remove the database from the
// tracker when we set m_opened to false in closeDatabase(). This sets up
// a simple symmetry between open and close operations, and a direct
// correlation to adding and removing databases from the tracker's list,
// thus ensuring that we have a correct list for the interrupt and
// delete operations to work on.
//
// The only databases instances not tracked by the tracker's open database
// list are the ones that have not been added yet, or the ones that we
// attempted an open on but failed to. Such instances only exist in the
// DatabaseServer's factory methods for creating database backends.
//
// The factory methods will either call openAndVerifyVersion() or
// performOpenAndVerify(). These methods will add the newly instantiated
// database backend if they succeed in opening the requested database.
// In the case of failure to open the database, the factory methods will
// simply discard the newly instantiated database backend when they return.
// The ref counting mechanims will automatically destruct the un-added
// (and un-returned) databases instances.

namespace blink {

namespace {

// Stores a cached version of each database, keyed by a unique integer obtained
// by providing an origin-name pair.
class DatabaseVersionCache {
  USING_FAST_MALLOC(DatabaseVersionCache);

 public:
  base::Lock& GetLock() const LOCK_RETURNED(lock_) { return lock_; }

  // Registers a globally-unique integer using the string key (reusing it if it
  // already exists), and returns the integer. Currently, these IDs live for the
  // lifetime of the process.
  DatabaseGuid RegisterOriginAndName(const String& origin, const String& name)
      EXCLUSIVE_LOCKS_REQUIRED(lock_) {
    lock_.AssertAcquired();
    String string_id = origin + "/" + name;

    DatabaseGuid guid;
    auto origin_name_to_guid_it = origin_name_to_guid_.find(string_id);
    if (origin_name_to_guid_it == origin_name_to_guid_.end()) {
      guid = next_guid_++;
      origin_name_to_guid_.Set(string_id, guid);
    } else {
      guid = origin_name_to_guid_it->value;
      DCHECK(guid);
    }

    count_.insert(guid);
    return guid;
  }

  // Releases one use of this identifier (corresponding to a call to
  // RegisterOriginAndName). If all uses are released, the cached version will
  // be erased from memory.
  void ReleaseGuid(DatabaseGuid guid) EXCLUSIVE_LOCKS_REQUIRED(lock_) {
    lock_.AssertAcquired();
    DCHECK(count_.Contains(guid));
    if (count_.erase(guid))
      guid_to_version_.erase(guid);
  }

  // The null string is returned only if the cached version has not been set.
  String GetVersion(DatabaseGuid guid) const EXCLUSIVE_LOCKS_REQUIRED(lock_) {
    lock_.AssertAcquired();

    String version;
    auto guid_to_version_it = guid_to_version_.find(guid);
    if (guid_to_version_it != guid_to_version_.end()) {
      version = guid_to_version_it->value;
      DCHECK(version);
    }
    return version;
  }

  // Updates the cached version of a database.
  // The null string is treated as the empty string.
  void SetVersion(DatabaseGuid guid, const String& new_version)
      EXCLUSIVE_LOCKS_REQUIRED(lock_) {
    lock_.AssertAcquired();
    guid_to_version_.Set(guid,
                         new_version.IsNull() ? g_empty_string : new_version);
  }

 private:
  mutable base::Lock lock_;
  HashMap<String, DatabaseGuid> origin_name_to_guid_ GUARDED_BY(lock_);
  HashCountedSet<DatabaseGuid> count_ GUARDED_BY(lock_);
  HashMap<DatabaseGuid, String> guid_to_version_ GUARDED_BY(lock_);
  DatabaseGuid next_guid_ GUARDED_BY(lock_) = 1;
};

DatabaseVersionCache& GetDatabaseVersionCache() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(DatabaseVersionCache, cache, ());
  return cache;
}

}  // namespace

static const char kVersionKey[] = "WebKitDatabaseVersionKey";
static const char kInfoTableName[] = "__WebKitDatabaseInfoTable__";

static String FormatErrorMessage(const char* message,
                                 int sqlite_error_code,
                                 const char* sqlite_error_message) {
  return String::Format("%s (%d %s)", message, sqlite_error_code,
                        sqlite_error_message);
}

static bool RetrieveTextResultFromDatabase(SQLiteDatabase& db,
                                           const String& query,
                                           String& result_string) {
  SQLiteStatement statement(db, query);
  int result = statement.Prepare();

  if (result != kSQLResultOk) {
    DLOG(ERROR) << "Error (" << result
                << ") preparing statement to read text result from database ("
                << query << ")";
    return false;
  }

  result = statement.Step();
  if (result == kSQLResultRow) {
    result_string = statement.GetColumnText(0);
    return true;
  }
  if (result == kSQLResultDone) {
    result_string = String();
    return true;
  }

  DLOG(ERROR) << "Error (" << result << ") reading text result from database ("
              << query << ")";
  return false;
}

static bool SetTextValueInDatabase(SQLiteDatabase& db,
                                   const String& query,
                                   const String& value) {
  SQLiteStatement statement(db, query);
  int result = statement.Prepare();

  if (result != kSQLResultOk) {
    DLOG(ERROR) << "Failed to prepare statement to set value in database ("
                << query << ")";
    return false;
  }

  statement.BindText(1, value);

  result = statement.Step();
  if (result != kSQLResultDone) {
    DLOG(ERROR) << "Failed to step statement to set value in database ("
                << query << ")";
    return false;
  }

  return true;
}

Database::Database(DatabaseContext* database_context,
                   const String& name,
                   const String& expected_version,
                   const String& display_name)
    : database_context_(database_context),
      name_(name),
      expected_version_(expected_version),
      display_name_(display_name),
      guid_(0),
      opened_(false),
      new_(false),
      database_authorizer_(kInfoTableName),
      transaction_in_progress_(false),
      is_transaction_queue_enabled_(true),
      did_try_to_count_transaction_(false),
      feature_handle_for_scheduler_(
          database_context->GetExecutionContext()
              ->GetScheduler()
              ->RegisterFeature(
                  SchedulingPolicy::Feature::kWebDatabase,
                  {SchedulingPolicy::DisableBackForwardCache()})) {
  DCHECK(IsMainThread());
  context_thread_security_origin_ =
      database_context_->GetSecurityOrigin()->IsolatedCopy();

  if (name_.IsNull())
    name_ = "";

  {
    auto& cache = GetDatabaseVersionCache();
    base::AutoLock locker(cache.GetLock());
    guid_ = cache.RegisterOriginAndName(GetSecurityOrigin()->ToString(), name);
  }

  filename_ = DatabaseTracker::Tracker().FullPathForDatabase(
      GetSecurityOrigin(), name_, /*create_if_does_not_exist=*/true);

  database_thread_security_origin_ =
      context_thread_security_origin_->IsolatedCopy();
  DCHECK(database_context_->GetDatabaseThread());
  DCHECK(database_context_->IsContextThread());
  database_task_runner_ =
      GetExecutionContext()->GetTaskRunner(TaskType::kDatabaseAccess);
}

Database::~Database() {
  // SQLite is "multi-thread safe", but each database handle can only be used
  // on a single thread at a time.
  //
  // For Database, we open the SQLite database on the DatabaseThread, and
  // hence we should also close it on that same thread. This means that the
  // SQLite database need to be closed by another mechanism (see
  // DatabaseContext::stopDatabases()). By the time we get here, the SQLite
  // database should have already been closed.

  DCHECK(!Opened());
}

void Database::Trace(Visitor* visitor) const {
  visitor->Trace(database_context_);
  ScriptWrappable::Trace(visitor);
}

bool Database::OpenAndVerifyVersion(bool set_version_in_new_database,
                                    DatabaseError& error,
                                    String& error_message,
                                    V8DatabaseCallback* creation_callback) {
  base::WaitableEvent event;
  if (!GetDatabaseContext()->DatabaseThreadAvailable())
    return false;

  DatabaseTracker::Tracker().PrepareToOpenDatabase(this);
  bool success = false;
  auto task = std::make_unique<DatabaseOpenTask>(
      this, set_version_in_new_database, &event, error, error_message, success);
  GetDatabaseContext()->GetDatabaseThread()->ScheduleTask(std::move(task));
  event.Wait();
  if (creation_callback) {
    if (success && IsNew()) {
      STORAGE_DVLOG(1)
          << "Scheduling DatabaseCreationCallbackTask for database " << this;
      auto async_task_context = std::make_unique<probe::AsyncTaskContext>();
      async_task_context->Schedule(GetExecutionContext(), "openDatabase");
      GetExecutionContext()
          ->GetTaskRunner(TaskType::kDatabaseAccess)
          ->PostTask(FROM_HERE, WTF::BindOnce(&Database::RunCreationCallback,
                                              WrapPersistent(this),
                                              WrapPersistent(creation_callback),
                                              std::move(async_task_context)));
    }
  }

  return success;
}

void Database::RunCreationCallback(
    V8DatabaseCallback* creation_callback,
    std::unique_ptr<probe::AsyncTaskContext> async_task_context) {
  probe::AsyncTask async_task(GetExecutionContext(), async_task_context.get());
  creation_callback->InvokeAndReportException(nullptr, this);
}

void Database::Close() {
  DCHECK(GetDatabaseContext()->GetDatabaseThread());
  DCHECK(GetDatabaseContext()->GetDatabaseThread()->IsDatabaseThread());

  {
    base::AutoLock locker(transaction_in_progress_lock_);

    // Clean up transactions that have not been scheduled yet:
    // Transaction phase 1 cleanup. See comment on "What happens if a
    // transaction is interrupted?" at the top of SQLTransactionBackend.cpp.
    SQLTransactionBackend* transaction = nullptr;
    while (!transaction_queue_.empty()) {
      transaction = transaction_queue_.TakeFirst();
      transaction->NotifyDatabaseThreadIsShuttingDown();
    }

    is_transaction_queue_enabled_ = false;
    transaction_in_progress_ = false;
  }

  CloseDatabase();
  GetDatabaseContext()->GetDatabaseThread()->RecordDatabaseClosed(this);
}

SQLTransactionBackend* Database::RunTransaction(SQLTransaction* transaction,
                                                bool read_only,
                                                const ChangeVersionData* data) {
  base::AutoLock locker(transaction_in_progress_lock_);
  if (!is_transaction_queue_enabled_)
    return nullptr;

  SQLTransactionWrapper* wrapper = nullptr;
  if (data) {
    wrapper = MakeGarbageCollected<ChangeVersionWrapper>(data->OldVersion(),
                                                         data->NewVersion());
  }

  auto* transaction_backend = MakeGarbageCollected<SQLTransactionBackend>(
      this, transaction, wrapper, read_only);
  transaction_queue_.push_back(transaction_backend);
  if (!transaction_in_progress_)
    ScheduleTransaction();

  return transaction_backend;
}

void Database::InProgressTransactionCompleted() {
  base::AutoLock locker(transaction_in_progress_lock_);
  transaction_in_progress_ = false;
  ScheduleTransaction();
}

void Database::ScheduleTransaction() {
  SQLTransactionBackend* transaction = nullptr;

  if (is_transaction_queue_enabled_ && !transaction_queue_.empty())
    transaction = transaction_queue_.TakeFirst();

  if (transaction && GetDatabaseContext()->DatabaseThreadAvailable()) {
    auto task = std::make_unique<DatabaseTransactionTask>(transaction);
    STORAGE_DVLOG(1) << "Scheduling DatabaseTransactionTask " << task.get()
                     << " for transaction " << task->Transaction();
    transaction_in_progress_ = true;
    GetDatabaseContext()->GetDatabaseThread()->ScheduleTask(std::move(task));
  } else {
    transaction_in_progress_ = false;
  }
}

void Database::ScheduleTransactionStep(SQLTransactionBackend* transaction) {
  if (!GetDatabaseContext()->DatabaseThreadAvailable())
    return;

  auto task = std::make_unique<DatabaseTransactionTask>(transaction);
  STORAGE_DVLOG(1) << "Scheduling DatabaseTransactionTask " << task.get()
                   << " for the transaction step";
  GetDatabaseContext()->GetDatabaseThread()->ScheduleTask(std::move(task));
}

SQLTransactionClient* Database::TransactionClient() const {
  return GetDatabaseContext()->GetDatabaseThread()->TransactionClient();
}

SQLTransactionCoordinator* Database::TransactionCoordinator() const {
  return GetDatabaseContext()->GetDatabaseThread()->TransactionCoordinator();
}

// static
const char* Database::DatabaseInfoTableName() {
  return kInfoTableName;
}

void Database::CloseDatabase() {
  if (!opened_.load(std::memory_order_relaxed))
    return;

  opened_.store(false, std::memory_order_release);
  sqlite_database_.Close();
  // See comment at the top this file regarding calling removeOpenDatabase().
  DatabaseTracker::Tracker().RemoveOpenDatabase(this);
  {
    auto& cache = GetDatabaseVersionCache();
    base::AutoLock locker(cache.GetLock());
    cache.ReleaseGuid(guid_);
  }
}

String Database::version() const {
  // Note: In multi-process browsers the cached value may be accurate, but we
  // cannot read the actual version from the database without potentially
  // inducing a deadlock.
  // FIXME: Add an async version getter to the DatabaseAPI.
  return GetCachedVersion();
}

class DoneCreatingDatabaseOnExitCaller {
  STACK_ALLOCATED();

 public:
  DoneCreatingDatabaseOnExitCaller(Database* database)
      : database_(database), open_succeeded_(false) {}
  ~DoneCreatingDatabaseOnExitCaller() {
    if (!open_succeeded_)
      DatabaseTracker::Tracker().FailedToOpenDatabase(database_);
  }

  void SetOpenSucceeded() { open_succeeded_ = true; }

 private:
  CrossThreadPersistent<Database> database_;
  bool open_succeeded_;
};

bool Database::PerformOpenAndVerify(bool should_set_version_in_new_database,
                                    DatabaseError& error,
                                    String& error_message) {
  DoneCreatingDatabaseOnExitCaller on_exit_caller(this);
  DCHECK(error_message.empty());
  DCHECK_EQ(error,
            DatabaseError::kNone);  // Better not have any errors already.
  // Presumed failure. We'll clear it if we succeed below.
  error = DatabaseError::kInvalidDatabaseState;

  const int kMaxSqliteBusyWaitTime = 30000;

  if (!sqlite_database_.Open(filename_)) {
    ReportSqliteError(sqlite_database_.LastError());
    error_message = FormatErrorMessage("unable to open database",
                                       sqlite_database_.LastError(),
                                       sqlite_database_.LastErrorMsg());
    return false;
  }
  if (!sqlite_database_.TurnOnIncrementalAutoVacuum())
    DLOG(ERROR) << "Unable to turn on incremental auto-vacuum ("
                << sqlite_database_.LastError() << " "
                << sqlite_database_.LastErrorMsg() << ")";

  sqlite_database_.SetBusyTimeout(kMaxSqliteBusyWaitTime);

  String current_version;
  {
    auto& cache = GetDatabaseVersionCache();
    base::AutoLock locker(cache.GetLock());

    current_version = cache.GetVersion(guid_);
    if (!current_version.IsNull()) {
      STORAGE_DVLOG(1) << "Current cached version for guid " << guid_ << " is "
                       << current_version;

      // Note: In multi-process browsers the cached value may be
      // inaccurate, but we cannot read the actual version from the
      // database without potentially inducing a form of deadlock, a
      // busytimeout error when trying to access the database. So we'll
      // use the cached value if we're unable to read the value from the
      // database file without waiting.
      // FIXME: Add an async openDatabase method to the DatabaseAPI.
      const int kNoSqliteBusyWaitTime = 0;
      sqlite_database_.SetBusyTimeout(kNoSqliteBusyWaitTime);
      String version_from_database;
      if (GetVersionFromDatabase(version_from_database, false)) {
        current_version = version_from_database;
        cache.SetVersion(guid_, current_version);
      }
      sqlite_database_.SetBusyTimeout(kMaxSqliteBusyWaitTime);
    } else {
      STORAGE_DVLOG(1) << "No cached version for guid " << guid_;

      SQLiteTransaction transaction(sqlite_database_);
      transaction.begin();
      if (!transaction.InProgress()) {
        ReportSqliteError(sqlite_database_.LastError());
        error_message = FormatErrorMessage(
            "unable to open database, failed to start transaction",
            sqlite_database_.LastError(), sqlite_database_.LastErrorMsg());
        sqlite_database_.Close();
        return false;
      }

      String table_name(kInfoTableName);
      if (!sqlite_database_.TableExists(table_name)) {
        new_ = true;

        if (!sqlite_database_.ExecuteCommand(
                "CREATE TABLE " + table_name +
                " (key TEXT NOT NULL ON CONFLICT FAIL UNIQUE ON CONFLICT "
                "REPLACE,value TEXT NOT NULL ON CONFLICT FAIL);")) {
          ReportSqliteError(sqlite_database_.LastError());
          error_message = FormatErrorMessage(
              "unable to open database, failed to create 'info' table",
              sqlite_database_.LastError(), sqlite_database_.LastErrorMsg());
          transaction.Rollback();
          sqlite_database_.Close();
          return false;
        }
      } else if (!GetVersionFromDatabase(current_version, false)) {
        ReportSqliteError(sqlite_database_.LastError());
        error_message = FormatErrorMessage(
            "unable to open database, failed to read current version",
            sqlite_database_.LastError(), sqlite_database_.LastErrorMsg());
        transaction.Rollback();
        sqlite_database_.Close();
        return false;
      }

      if (current_version.length()) {
        STORAGE_DVLOG(1) << "Retrieved current version " << current_version
                         << " from database " << DatabaseDebugName();
      } else if (!new_ || should_set_version_in_new_database) {
        STORAGE_DVLOG(1) << "Setting version " << expected_version_
                         << " in database " << DatabaseDebugName()
                         << " that was just created";
        if (!SetVersionInDatabase(expected_version_, false)) {
          ReportSqliteError(sqlite_database_.LastError());
          error_message = FormatErrorMessage(
              "unable to open database, failed to write current version",
              sqlite_database_.LastError(), sqlite_database_.LastErrorMsg());
          transaction.Rollback();
          sqlite_database_.Close();
          return false;
        }
        current_version = expected_version_;
      }
      cache.SetVersion(guid_, current_version);
      transaction.Commit();
    }
  }

  if (current_version.IsNull()) {
    STORAGE_DVLOG(1) << "Database " << DatabaseDebugName()
                     << " does not have its version set";
    current_version = "";
  }

  // If the expected version isn't the empty string, ensure that the current
  // database version we have matches that version. Otherwise, set an
  // exception.
  // If the expected version is the empty string, then we always return with
  // whatever version of the database we have.
  if ((!new_ || should_set_version_in_new_database) &&
      expected_version_.length() && expected_version_ != current_version) {
    error_message =
        "unable to open database, version mismatch, '" + expected_version_ +
        "' does not match the currentVersion of '" + current_version + "'";
    sqlite_database_.Close();
    return false;
  }

  sqlite_database_.SetAuthorizer(&database_authorizer_);

  // See comment at the top this file regarding calling addOpenDatabase().
  DatabaseTracker::Tracker().AddOpenDatabase(this);
  opened_.store(true, std::memory_order_release);

  // Declare success:
  error = DatabaseError::kNone;  // Clear the presumed error from above.
  on_exit_caller.SetOpenSucceeded();

  if (new_ && !should_set_version_in_new_database) {
    // The caller provided a creationCallback which will set the expected
    // version.
    expected_version_ = "";
  }

  if (GetDatabaseContext()->GetDatabaseThread())
    GetDatabaseContext()->GetDatabaseThread()->RecordDatabaseOpen(this);
  return true;
}

String Database::StringIdentifier() const {
  return name_;
}

String Database::DisplayName() const {
  return display_name_;
}

String Database::FileName() const {
  return filename_;
}

bool Database::GetVersionFromDatabase(String& version,
                                      bool should_cache_version) {
  String query(String("SELECT value FROM ") + kInfoTableName +
               " WHERE key = '" + kVersionKey + "';");

  database_authorizer_.Disable();

  bool result =
      RetrieveTextResultFromDatabase(sqlite_database_, query, version);
  if (result) {
    if (should_cache_version)
      SetCachedVersion(version);
  } else {
    DLOG(ERROR) << "Failed to retrieve version from database "
                << DatabaseDebugName();
  }

  database_authorizer_.Enable();

  return result;
}

bool Database::SetVersionInDatabase(const String& version,
                                    bool should_cache_version) {
  // The INSERT will replace an existing entry for the database with the new
  // version number, due to the UNIQUE ON CONFLICT REPLACE clause in the
  // CREATE statement (see Database::performOpenAndVerify()).
  String query(String("INSERT INTO ") + kInfoTableName +
               " (key, value) VALUES ('" + kVersionKey + "', ?);");

  database_authorizer_.Disable();

  bool result = SetTextValueInDatabase(sqlite_database_, query, version);
  if (result) {
    if (should_cache_version)
      SetCachedVersion(version);
  } else {
    DLOG(ERROR) << "Failed to set version " << version << " in database ("
                << query << ")";
  }

  database_authorizer_.Enable();

  return result;
}

void Database::SetExpectedVersion(const String& version) {
  expected_version_ = version;
}

String Database::GetCachedVersion() const {
  auto& cache = GetDatabaseVersionCache();
  base::AutoLock locker(cache.GetLock());
  return cache.GetVersion(guid_);
}

void Database::SetCachedVersion(const String& actual_version) {
  auto& cache = GetDatabaseVersionCache();
  base::AutoLock locker(cache.GetLock());
  cache.SetVersion(guid_, actual_version);
}

bool Database::GetActualVersionForTransaction(String& actual_version) {
  DCHECK(sqlite_database_.TransactionInProgress());
  // Note: In multi-process browsers the cached value may be inaccurate. So we
  // retrieve the value from the database and update the cached value here.
  return GetVersionFromDatabase(actual_version, true);
}

void Database::DisableAuthorizer() {
  database_authorizer_.Disable();
}

void Database::EnableAuthorizer() {
  database_authorizer_.Enable();
}

void Database::SetAuthorizerPermissions(int permissions) {
  database_authorizer_.SetPermissions(permissions);
}

bool Database::LastActionChangedDatabase() {
  return database_authorizer_.LastActionChangedDatabase();
}

bool Database::LastActionWasInsert() {
  return database_authorizer_.LastActionWasInsert();
}

void Database::ResetDeletes() {
  database_authorizer_.ResetDeletes();
}

bool Database::HadDeletes() {
  return database_authorizer_.HadDeletes();
}

void Database::ResetAuthorizer() {
  database_authorizer_.Reset();
}

uint64_t Database::MaximumSize() const {
  return DatabaseTracker::Tracker().GetMaxSizeForDatabase(this);
}

void Database::IncrementalVacuumIfNeeded() {
  int64_t free_space_size = sqlite_database_.FreeSpaceSize();
  int64_t total_size = sqlite_database_.TotalSize();
  if (total_size <= 10 * free_space_size) {
    int result = sqlite_database_.RunIncrementalVacuumCommand();
    if (result != kSQLResultOk) {
      ReportSqliteError(result);
      LogErrorMessage(FormatErrorMessage("error vacuuming database", result,
                                         sqlite_database_.LastErrorMsg()));
    }
  }
}

void Database::ReportSqliteError(int sqlite_error_code) {
  WebDatabaseHost::GetInstance().ReportSqliteError(
      *GetSecurityOrigin(), StringIdentifier(), sqlite_error_code);
}

void Database::LogErrorMessage(const String& message) {
  GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kStorage, mojom::ConsoleMessageLevel::kError,
      message));
}

ExecutionContext* Database::GetExecutionContext() const {
  return GetDatabaseContext()->GetExecutionContext();
}

void Database::CloseImmediately() {
  DCHECK(GetExecutionContext()->IsContextThread());
  if (GetDatabaseContext()->DatabaseThreadAvailable() && Opened()) {
    LogErrorMessage("forcibly closing database");
    GetDatabaseContext()->GetDatabaseThread()->ScheduleTask(
        std::make_unique<DatabaseCloseTask>(this, nullptr));
  }
}

void Database::changeVersion(const String& old_version,
                             const String& new_version,
                             V8SQLTransactionCallback* callback,
                             V8SQLTransactionErrorCallback* error_callback,
                             V8VoidCallback* success_callback) {
  ChangeVersionData data(old_version, new_version);
  RunTransaction(SQLTransaction::OnProcessV8Impl::Create(callback),
                 SQLTransaction::OnErrorV8Impl::Create(error_callback),
                 SQLTransaction::OnSuccessV8Impl::Create(success_callback),
                 false, &data);
}

void Database::transaction(V8SQLTransactionCallback* callback,
                           V8SQLTransactionErrorCallback* error_callback,
                           V8VoidCallback* success_callback) {
  RunTransaction(SQLTransaction::OnProcessV8Impl::Create(callback),
                 SQLTransaction::OnErrorV8Impl::Create(error_callback),
                 SQLTransaction::OnSuccessV8Impl::Create(success_callback),
                 false);
}

void Database::readTransaction(V8SQLTransactionCallback* callback,
                               V8SQLTransactionErrorCallback* error_callback,
                               V8VoidCallback* success_callback) {
  RunTransaction(SQLTransaction::OnProcessV8Impl::Create(callback),
                 SQLTransaction::OnErrorV8Impl::Create(error_callback),
                 SQLTransaction::OnSuccessV8Impl::Create(success_callback),
                 true);
}

void Database::PerformTransaction(
    SQLTransaction::OnProcessCallback* callback,
    SQLTransaction::OnErrorCallback* error_callback,
    SQLTransaction::OnSuccessCallback* success_callback) {
  RunTransaction(callback, error_callback, success_callback, false);
}

static void CallTransactionErrorCallback(
    SQLTransaction::OnErrorCallback* callback,
    std::unique_ptr<SQLErrorData> error_data) {
  callback->OnError(MakeGarbageCollected<SQLError>(*error_data));
}

void Database::RunTransaction(
    SQLTransaction::OnProcessCallback* callback,
    SQLTransaction::OnErrorCallback* error_callback,
    SQLTransaction::OnSuccessCallback* success_callback,
    bool read_only,
    const ChangeVersionData* change_version_data) {
  if (!GetExecutionContext())
    return;

  DCHECK(GetExecutionContext()->IsContextThread());

  if (!did_try_to_count_transaction_) {
    GetExecutionContext()->CountUse(WebFeature::kReadOrWriteWebDatabase);
    did_try_to_count_transaction_ = true;
  }

// FIXME: Rather than passing errorCallback to SQLTransaction and then
// sometimes firing it ourselves, this code should probably be pushed down
// into Database so that we only create the SQLTransaction if we're
// actually going to run it.
#if DCHECK_IS_ON()
  SQLTransaction::OnErrorCallback* original_error_callback = error_callback;
#endif
  SQLTransaction* transaction = SQLTransaction::Create(
      this, callback, success_callback, error_callback, read_only);
  SQLTransactionBackend* transaction_backend =
      RunTransaction(transaction, read_only, change_version_data);
  if (!transaction_backend) {
    SQLTransaction::OnErrorCallback* transaction_error_callback =
        transaction->ReleaseErrorCallback();
#if DCHECK_IS_ON()
    DCHECK_EQ(transaction_error_callback, original_error_callback);
#endif
    if (transaction_error_callback) {
      auto error = std::make_unique<SQLErrorData>(SQLError::kUnknownErr,
                                                  "database has been closed");
      GetDatab
```