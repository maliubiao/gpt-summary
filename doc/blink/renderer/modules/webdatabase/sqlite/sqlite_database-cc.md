Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

1. **Understand the Core Request:** The user wants to understand the functionality of `sqlite_database.cc` within the Chromium Blink engine, specifically its relationship to web technologies (JavaScript, HTML, CSS), how it works internally, potential errors, and how users might trigger this code.

2. **Initial Scan for Key Information:** Read through the code, paying attention to:
    * **Includes:** These reveal dependencies and give hints about the purpose (e.g., `sql/sandboxed_vfs.h`, `webdatabase/database_authorizer.h`).
    * **Class Name:** `SQLiteDatabase` strongly suggests database interaction.
    * **Member Variables:**  Variables like `db_`, `open_error_`, `page_size_`, and `authorizer_` indicate the class manages a SQLite database connection, tracks errors, and handles authorization.
    * **Public Methods:**  Methods like `Open`, `Close`, `ExecuteCommand`, `SetMaximumSize`, `TableExists`, `RunVacuumCommand`, and `SetAuthorizer` are the primary ways to interact with this class.
    * **Private/Internal Methods:**  Methods like `OpenDatabase`, `EnableAuthorizer`, and `AuthorizerFunction` show internal workings.
    * **Constants and Namespaces:** `kSqliteVfsName`, `blink`, and the various `SQLITE_...` constants are relevant.

3. **Identify Core Functionality:** Based on the above, the primary function is to provide an interface to a SQLite database within the Blink rendering engine. This involves:
    * Opening and closing database connections.
    * Executing SQL commands.
    * Managing database size and vacuuming.
    * Handling authorization/permissions.
    * Tracking errors.

4. **Analyze Relationships with Web Technologies:**  Consider how this code connects to the user's experience:
    * **JavaScript:** The key connection is the Web SQL Database API, which allows JavaScript code to interact with a local database. This file is a crucial part of *implementing* that API. Think about how JavaScript calls to open a database, execute queries, etc., eventually translate to calls within this C++ code.
    * **HTML:**  HTML doesn't directly interact with this code. However, the *result* of database operations (triggered by JavaScript) can dynamically update the HTML content displayed on the page.
    * **CSS:** CSS is for styling and layout and has no direct functional relationship with the database operations in this file.

5. **Infer Logical Reasoning and Examples:** Look at specific methods and try to understand their logic. Create simple scenarios to illustrate how they work:
    * **`Open`:**  Input: filename. Output: success/failure.
    * **`ExecuteCommand`:** Input: SQL string. Output: success/failure.
    * **`TableExists`:** Input: table name. Output: true/false.
    * **`SetMaximumSize`:** Input: size in bytes. Output: success (implicitly).
    * **`SetAuthorizer`:** Input: `DatabaseAuthorizer` object. Output: authorization enabled.

6. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using the Web SQL Database API or how the browser might handle unexpected situations:
    * Incorrect SQL syntax.
    * Trying to access a closed database.
    * Exceeding the database size limit.
    * Violating authorization rules.

7. **Trace User Actions to the Code:** Consider how a user's actions in a web browser can lead to this code being executed:
    * A website uses JavaScript to open a database.
    * The website executes SQL queries using JavaScript.
    * The browser needs to manage the database size or perform maintenance tasks.

8. **Organize and Structure the Answer:**  Group the information logically, using headings and bullet points for clarity. Address each part of the user's request: functionality, relationships, logical reasoning, errors, and debugging clues.

9. **Refine and Elaborate:** Review the answer for clarity and completeness. Add details and explanations where needed. For example, explain the purpose of the `SandboxedVfs`, the authorizer, and the different `PRAGMA` commands. Ensure the examples are easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file directly handles parsing SQL. **Correction:**  The `SQLiteStatement` class (included) likely handles the parsing and execution details; this class manages the database *connection*.
* **Initial thought:**  The connection to HTML might be more direct. **Correction:**  The connection is indirect through JavaScript. JavaScript interacts with the database, and then JavaScript updates the DOM (which affects HTML).
* **Realization:** The code uses `DLOG(ERROR)` extensively. This suggests error handling and logging are important functionalities. Emphasize this.
* **Considering the `AuthorizerFunction`:** Realize that this is a security mechanism, preventing unauthorized database operations. Explain its significance.

By following these steps, and continually refining the understanding of the code, a comprehensive and accurate answer can be constructed. The key is to start with a broad understanding and then delve into the specific details while keeping the user's perspective and questions in mind.
好的，让我们来详细分析一下 `blink/renderer/modules/webdatabase/sqlite/sqlite_database.cc` 这个文件。

**文件功能概览:**

`sqlite_database.cc` 文件是 Chromium Blink 引擎中 WebDatabase 功能的核心组成部分，它封装了对 SQLite 数据库的底层操作。其主要功能可以概括为：

1. **数据库连接管理:**
   - 负责打开和关闭 SQLite 数据库连接。
   - 使用沙箱化的虚拟文件系统 (`SandboxedVfs`) 来增强安全性，防止恶意代码直接访问文件系统。
   - 管理数据库连接的生命周期。

2. **SQL 执行:**
   - 提供执行 SQL 命令的接口 (`ExecuteCommand`)。
   - 内部使用 `SQLiteStatement` 类来准备和执行 SQL 语句。

3. **数据库配置:**
   - 设置数据库的各种配置选项，例如：
     - `locking_mode`: 设置数据库的锁定模式。
     - `temp_store`: 设置临时表的存储位置（内存或磁盘）。
     - `foreign_keys`: 控制是否启用外键约束（WebDatabase 不支持外键）。
     - `max_page_count`: 设置数据库的最大大小。
     - `page_size`: 获取数据库的页大小。
     - `auto_vacuum`: 控制数据库的自动清理模式。

4. **数据库信息查询:**
   - 提供查询数据库信息的接口，例如：
     - `TableExists`: 检查表是否存在。
     - `FreeSpaceSize`: 获取数据库的可用空间大小。
     - `TotalSize`: 获取数据库的总大小。
     - `LastInsertRowID`: 获取最后插入行的 ID。
     - `LastChanges`: 获取自上次调用以来的更改次数。

5. **数据库维护:**
   - 提供执行数据库维护操作的接口，例如：
     - `RunVacuumCommand`: 执行数据库清理操作。
     - `RunIncrementalVacuumCommand`: 执行增量数据库清理操作。

6. **权限控制 (Authorizer):**
   - 提供设置和管理数据库授权者的机制 (`SetAuthorizer`)。
   - 使用 `DatabaseAuthorizer` 类来控制哪些 SQL 操作是被允许的。这对于 WebDatabase 的安全至关重要，因为它允许网页运行 SQL 代码。

7. **错误处理:**
   - 跟踪数据库操作的错误状态 (`LastError`, `LastErrorMsg`)。

**与 JavaScript, HTML, CSS 的关系及举例:**

`sqlite_database.cc` 文件本身是用 C++ 编写的，并不直接涉及 JavaScript, HTML 或 CSS 代码。然而，它是 Web SQL Database API 的底层实现，因此与 JavaScript 有着密切的联系。

**JavaScript:**

- **用户操作:** 当网页中的 JavaScript 代码调用 Web SQL Database API (例如 `openDatabase`, `transaction`, `executeSql` 等) 时，这些调用最终会触发 `sqlite_database.cc` 中的相应功能。
- **举例说明:**
  ```javascript
  // JavaScript 代码
  const db = openDatabase('mydb', '1.0', 'My Database', 2 * 1024 * 1024);

  db.transaction(function (tx) {
    tx.executeSql('CREATE TABLE IF NOT EXISTS mytable (id INTEGER PRIMARY KEY, name TEXT)');
    tx.executeSql('INSERT INTO mytable (name) VALUES (?)', ['Example Data']);
    tx.executeSql('SELECT * FROM mytable', [], function (tx, results) {
      // 处理查询结果
      for (let i = 0; i < results.rows.length; i++) {
        console.log(results.rows.item(i).name);
      }
    });
  });
  ```
  在这个例子中：
    - `openDatabase('mydb', ...)` 会间接地调用 `SQLiteDatabase::Open` 来打开或创建名为 `mydb` 的数据库。
    - `tx.executeSql('CREATE TABLE ...')` 和 `tx.executeSql('INSERT INTO ...')` 会调用 `SQLiteDatabase::ExecuteCommand` 来执行相应的 SQL 命令。
    - `tx.executeSql('SELECT * FROM ...')` 也会调用 `ExecuteCommand`，并且结果会通过某种机制返回给 JavaScript 的回调函数。

**HTML:**

- **用户操作:** HTML 定义了网页的结构，其中包含可能触发 JavaScript 代码的交互元素（例如按钮）。用户与这些元素交互，可能导致 JavaScript 调用 Web SQL Database API。
- **举例说明:** 一个按钮的 `onclick` 事件可能触发一个 JavaScript 函数，该函数会从数据库中读取数据并更新页面上的内容。

**CSS:**

- **关系:** CSS 负责网页的样式，与 `sqlite_database.cc` 的功能没有直接的逻辑关系。CSS 可以用于美化由从数据库检索到的数据动态生成的内容，但数据库操作本身并不依赖于 CSS。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **用户 JavaScript 调用:** `db.transaction(tx => tx.executeSql('SELECT COUNT(*) FROM users'));`
2. **`SQLiteDatabase` 对象 `db_` 指向一个已打开的 SQLite 数据库连接。**

**执行流程与输出:**

1. **`ExecuteCommand` 调用:**  `SQLiteDatabase::ExecuteCommand` 方法被调用，传入 SQL 语句 `"SELECT COUNT(*) FROM users"`。
2. **`SQLiteStatement` 创建与准备:** 在 `ExecuteCommand` 内部，会创建一个 `SQLiteStatement` 对象，并将 SQL 语句传递给它。`SQLiteStatement::Prepare()` 会调用底层的 SQLite API (`sqlite3_prepare_v2`) 来编译 SQL 语句。
3. **语句执行:** `SQLiteStatement::Step()` 被调用，执行编译后的 SQL 语句。
4. **结果处理:**
   - 如果表 `users` 存在且查询成功，`Step()` 会返回 `SQLITE_ROW`。
   - `SQLiteStatement::GetColumnInt(0)` 会被调用来获取第一列（即 `COUNT(*)` 的结果）的整数值。
   - 这个整数值会被传递回 JavaScript 的回调函数中。
5. **假设输出:** 如果 `users` 表中有 10 条记录，那么 JavaScript 回调函数会接收到 `10` 这个数字。

**用户或编程常见的使用错误:**

1. **尝试在数据库未打开时执行 SQL 命令:**
   - **错误示例:** 在调用 `openDatabase` 之前或在 `openDatabase` 失败后，尝试执行 `executeSql`。
   - **后果:** 可能导致程序崩溃或抛出异常。`SQLiteDatabase` 中的检查 (`if (!db_)`) 可以帮助预防这种情况，并返回错误信息。
   - **调试线索:** 检查 `LastError()` 和 `LastErrorMsg()` 的返回值，它们会指示数据库未打开。

2. **SQL 语法错误:**
   - **错误示例:** `tx.executeSql('SELECt * FROM users WHERE age = "abc"');` (类型不匹配，age 是数字)。
   - **后果:** SQLite 会返回错误码，`ExecuteCommand` 或 `SQLiteStatement::Step()` 会返回表示错误的值。
   - **调试线索:** `LastError()` 会返回 SQLite 错误码（例如 `SQLITE_ERROR`），`LastErrorMsg()` 会提供更详细的错误信息，例如 "SQL logic error near \"abc\": syntax error"。

3. **违反数据库约束 (例如唯一性约束):**
   - **错误示例:** 尝试插入一个已经存在的唯一键值。
   - **后果:** SQLite 会返回 `SQLITE_CONSTRAINT` 错误码。
   - **调试线索:** `LastError()` 会返回 `SQLITE_CONSTRAINT`，`LastErrorMsg()` 会包含关于约束冲突的信息。

4. **超出数据库大小限制:**
   - **错误示例:** 持续向数据库插入数据，直到达到预设的最大大小。
   - **后果:** SQLite 会返回 `SQLITE_FULL` 错误码。
   - **调试线索:** `LastError()` 会返回 `SQLITE_FULL`。

5. **权限不足 (如果设置了 Authorizer):**
   - **错误示例:** 尝试执行被 `DatabaseAuthorizer` 拒绝的 SQL 操作（例如尝试删除受保护的表）。
   - **后果:** `AuthorizerFunction` 会返回 `kSQLAuthDeny`，`ExecuteCommand` 会返回失败。
   - **调试线索:** `LastError()` 可能会返回一个通用的错误码，但可以通过查看 `DatabaseAuthorizer` 的实现来了解具体的权限控制逻辑。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **网页的 JavaScript 代码被执行。**
3. **JavaScript 代码调用了 Web SQL Database API，例如 `openDatabase()`。**
   - 这会触发 Blink 引擎中的 WebDatabase 相关代码，最终可能调用 `SQLiteDatabase::Open()`。
4. **如果 JavaScript 代码执行 `transaction()` 或 `executeSql()`。**
   - Blink 引擎会将 SQL 语句传递给 `SQLiteDatabase::ExecuteCommand()`。
5. **在 `ExecuteCommand()` 内部：**
   - 创建 `SQLiteStatement` 对象。
   - 调用底层的 SQLite API (`sqlite3_prepare_v2`, `sqlite3_bind_...`, `sqlite3_step`, `sqlite3_column_...`, `sqlite3_finalize`).
6. **如果操作涉及到数据库配置（例如设置大小）。**
   - JavaScript 代码可能间接地触发对 `SQLiteDatabase::SetMaximumSize()` 等方法的调用.
7. **如果发生了错误。**
   - SQLite 会返回错误码，这些错误码会被封装在 `SQLiteDatabase` 对象中，可以通过 `LastError()` 和 `LastErrorMsg()` 获取。

**调试线索:**

- **浏览器开发者工具 (Console):**  查看 JavaScript 代码执行时的错误信息，特别是与数据库操作相关的错误。
- **Chromium 的 `net-internals` 工具:** 可以查看网络请求和一些内部事件，虽然对于本地数据库操作的帮助有限。
- **Blink 渲染引擎的日志:** 如果编译了调试版本的 Chromium，可以查看 Blink 引擎的详细日志输出，其中可能包含关于数据库操作的信息（例如 `DLOG` 宏输出的内容）。
- **断点调试:** 在 Blink 引擎的源代码中设置断点，可以逐步跟踪 JavaScript 调用如何到达 `sqlite_database.cc` 中的代码，并查看变量的值。
- **检查 `LastError()` 和 `LastErrorMsg()` 的返回值:**  这是诊断数据库操作问题的关键。
- **查看 `DatabaseAuthorizer` 的实现:** 如果怀疑是权限问题，需要检查 `DatabaseAuthorizer` 的具体授权逻辑。

总而言之，`sqlite_database.cc` 是 Blink 引擎中 WebDatabase 功能的核心 C++ 代码，负责与底层的 SQLite 数据库进行交互，处理 SQL 执行、数据库配置、维护和权限控制。理解这个文件的功能对于理解 Web SQL Database API 的实现至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/webdatabase/sqlite/sqlite_database.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2007 Justin Haygood (jhaygood@reaktix.com)
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/webdatabase/sqlite/sqlite_database.h"

#include "base/notreached.h"
#include "sql/sandboxed_vfs.h"
#include "third_party/blink/renderer/modules/webdatabase/database_authorizer.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sandboxed_vfs_delegate.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sql_log.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sqlite_statement.h"
#include "third_party/sqlite/sqlite3.h"

namespace blink {

namespace {

constexpr char kSqliteVfsName[] = "renderer_sandboxed_vfs";

std::tuple<int, sqlite3*> OpenDatabase(const String& filename) {
  sql::SandboxedVfs::Register(kSqliteVfsName,
                              std::make_unique<SandboxedVfsDelegate>(),
                              /*make_default=*/false);

  sqlite3* connection;
  constexpr int open_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                             SQLITE_OPEN_EXRESCODE | SQLITE_OPEN_PRIVATECACHE;
  int status = sqlite3_open_v2(filename.Utf8().c_str(), &connection, open_flags,
                               kSqliteVfsName);
  if (status != SQLITE_OK) {
    // SQLite creates a connection handle in most cases where open fails.
    if (connection) {
      sqlite3_close(connection);
      connection = nullptr;
    }
  }
  return {status, connection};
}

}  // namespace

const int kSQLResultDone = SQLITE_DONE;
const int kSQLResultOk = SQLITE_OK;
const int kSQLResultRow = SQLITE_ROW;
const int kSQLResultFull = SQLITE_FULL;
const int kSQLResultInterrupt = SQLITE_INTERRUPT;
const int kSQLResultConstraint = SQLITE_CONSTRAINT;

static const char kNotOpenErrorMessage[] = "database is not open";

SQLiteDatabase::SQLiteDatabase() : open_error_(SQLITE_ERROR) {}

SQLiteDatabase::~SQLiteDatabase() {
  Close();
}

bool SQLiteDatabase::Open(const String& filename) {
  Close();

  // TODO(pwnall): This doesn't have to be synchronous. WebSQL's open sequence
  //               is asynchronous, so we could open all the needed files (DB,
  //               journal, etc.) asynchronously, and store them in a hash table
  //               that would be used here.
  std::tie(open_error_, db_) = OpenDatabase(filename);
  if (open_error_ != SQLITE_OK) {
    DCHECK_EQ(db_, nullptr);

    open_error_message_ =
        db_ ? sqlite3_errmsg(db_) : "sqlite_open returned null";
    DLOG(ERROR) << "SQLite database failed to load from " << filename
                << "\nCause - " << open_error_message_;
    return false;
  }

  if (!db_) {
    open_error_message_ = "sqlite_open returned null";
    return false;
  }

  // Defensive mode is a layer of defense in depth for applications that must
  // run SQL queries from an untrusted source, such as WebDatabase. Refuse to
  // proceed if this layer cannot be enabled.
  open_error_ =
      sqlite3_db_config(db_.get(), SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
  if (open_error_ != SQLITE_OK) {
    open_error_message_ = sqlite3_errmsg(db_);
    DLOG(ERROR) << "SQLite database error when enabling defensive mode - "
                << open_error_message_.data();
    sqlite3_close(db_);
    db_ = nullptr;
    return false;
  }

  opening_thread_ = CurrentThread();

  if (!SQLiteStatement(*this, "PRAGMA locking_mode = NORMAL;").ExecuteCommand())
    DLOG(ERROR) << "SQLite database could not set locking_mode to normal";

  if (!SQLiteStatement(*this, "PRAGMA temp_store = MEMORY;").ExecuteCommand())
    DLOG(ERROR) << "SQLite database could not set temp_store to memory";

  // Foreign keys are not supported by WebDatabase.  Make sure foreign key
  // support is consistent if SQLite has SQLITE_DEFAULT_FOREIGN_KEYS.
  if (!SQLiteStatement(*this, "PRAGMA foreign_keys = OFF;").ExecuteCommand())
    DLOG(ERROR) << "SQLite database could not turn off foreign_keys";

  return true;
}

void SQLiteDatabase::Close() {
  if (db_) {
    // FIXME: This is being called on the main thread during JS GC.
    // <rdar://problem/5739818>
    // DCHECK_EQ(currentThread(), m_openingThread);
    sqlite3* db = db_;
    {
      base::AutoLock locker(database_closing_mutex_);
      db_ = nullptr;
    }
    sqlite3_close(db);
  }

  opening_thread_ = 0;
  open_error_ = SQLITE_ERROR;
  open_error_message_ = std::string();
}

void SQLiteDatabase::SetMaximumSize(int64_t size) {
  if (size < 0)
    size = 0;

  int current_page_size = PageSize();

  DCHECK(current_page_size || !db_);
  int64_t new_max_page_count = current_page_size ? size / current_page_size : 0;

  base::AutoLock locker(authorizer_lock_);
  EnableAuthorizer(false);

  SQLiteStatement statement(
      *this, "PRAGMA max_page_count = " + String::Number(new_max_page_count));
  statement.Prepare();
  if (statement.Step() != kSQLResultRow)
    DLOG(ERROR) << "Failed to set maximum size of database to " << size
                << " bytes";

  EnableAuthorizer(true);
}

int SQLiteDatabase::PageSize() {
  // Since the page size of a database is locked in at creation and therefore
  // cannot be dynamic, we can cache the value for future use.
  if (page_size_ == -1) {
    base::AutoLock locker(authorizer_lock_);
    EnableAuthorizer(false);

    SQLiteStatement statement(*this, "PRAGMA page_size");
    page_size_ = statement.GetColumnInt(0);

    EnableAuthorizer(true);
  }

  return page_size_;
}

int64_t SQLiteDatabase::FreeSpaceSize() {
  int64_t freelist_count = 0;

  {
    base::AutoLock locker(authorizer_lock_);
    EnableAuthorizer(false);
    // Note: freelist_count was added in SQLite 3.4.1.
    SQLiteStatement statement(*this, "PRAGMA freelist_count");
    freelist_count = statement.GetColumnInt64(0);
    EnableAuthorizer(true);
  }

  return freelist_count * PageSize();
}

int64_t SQLiteDatabase::TotalSize() {
  int64_t page_count = 0;

  {
    base::AutoLock locker(authorizer_lock_);
    EnableAuthorizer(false);
    SQLiteStatement statement(*this, "PRAGMA page_count");
    page_count = statement.GetColumnInt64(0);
    EnableAuthorizer(true);
  }

  return page_count * PageSize();
}

void SQLiteDatabase::SetBusyTimeout(int ms) {
  if (db_)
    sqlite3_busy_timeout(db_, ms);
  else
    SQL_DVLOG(1) << "BusyTimeout set on non-open database";
}

bool SQLiteDatabase::ExecuteCommand(const String& sql) {
  return SQLiteStatement(*this, sql).ExecuteCommand();
}

bool SQLiteDatabase::TableExists(const String& tablename) {
  if (!db_)
    return false;

  String statement =
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '" +
      tablename + "';";

  SQLiteStatement sql(*this, statement);
  sql.Prepare();
  return sql.Step() == SQLITE_ROW;
}

int SQLiteDatabase::RunVacuumCommand() {
  if (!ExecuteCommand("VACUUM;"))
    SQL_DVLOG(1) << "Unable to vacuum database -" << LastErrorMsg();
  return LastError();
}

int SQLiteDatabase::RunIncrementalVacuumCommand() {
  base::AutoLock locker(authorizer_lock_);
  EnableAuthorizer(false);

  if (!ExecuteCommand("PRAGMA incremental_vacuum"))
    SQL_DVLOG(1) << "Unable to run incremental vacuum - " << LastErrorMsg();

  EnableAuthorizer(true);
  return LastError();
}

int64_t SQLiteDatabase::LastInsertRowID() {
  if (!db_)
    return 0;
  return sqlite3_last_insert_rowid(db_);
}

void SQLiteDatabase::UpdateLastChangesCount() {
  if (!db_)
    return;

  last_changes_count_ = sqlite3_total_changes64(db_);
}

int64_t SQLiteDatabase::LastChanges() {
  if (!db_)
    return 0;

  return sqlite3_total_changes64(db_) - last_changes_count_;
}

int SQLiteDatabase::LastError() {
  return db_ ? sqlite3_extended_errcode(db_) : open_error_;
}

const char* SQLiteDatabase::LastErrorMsg() {
  if (db_)
    return sqlite3_errmsg(db_);
  return open_error_message_.empty() ? kNotOpenErrorMessage
                                     : open_error_message_.c_str();
}

int SQLiteDatabase::AuthorizerFunction(void* user_data,
                                       int action_code,
                                       const char* parameter1,
                                       const char* parameter2,
                                       const char* /*databaseName*/,
                                       const char* /*trigger_or_view*/) {
  DatabaseAuthorizer* auth = static_cast<DatabaseAuthorizer*>(user_data);
  DCHECK(auth);

  switch (action_code) {
    case SQLITE_CREATE_INDEX:
      return auth->CreateIndex(parameter1, parameter2);
    case SQLITE_CREATE_TABLE:
      return auth->CreateTable(parameter1);
    case SQLITE_CREATE_TEMP_INDEX:
      return auth->CreateTempIndex(parameter1, parameter2);
    case SQLITE_CREATE_TEMP_TABLE:
      return auth->CreateTempTable(parameter1);
    case SQLITE_CREATE_TEMP_TRIGGER:
      return auth->CreateTempTrigger(parameter1, parameter2);
    case SQLITE_CREATE_TEMP_VIEW:
      return auth->CreateTempView(parameter1);
    case SQLITE_CREATE_TRIGGER:
      return auth->CreateTrigger(parameter1, parameter2);
    case SQLITE_CREATE_VIEW:
      return auth->CreateView(parameter1);
    case SQLITE_DELETE:
      return auth->AllowDelete(parameter1);
    case SQLITE_DROP_INDEX:
      return auth->DropIndex(parameter1, parameter2);
    case SQLITE_DROP_TABLE:
      return auth->DropTable(parameter1);
    case SQLITE_DROP_TEMP_INDEX:
      return auth->DropTempIndex(parameter1, parameter2);
    case SQLITE_DROP_TEMP_TABLE:
      return auth->DropTempTable(parameter1);
    case SQLITE_DROP_TEMP_TRIGGER:
      return auth->DropTempTrigger(parameter1, parameter2);
    case SQLITE_DROP_TEMP_VIEW:
      return auth->DropTempView(parameter1);
    case SQLITE_DROP_TRIGGER:
      return auth->DropTrigger(parameter1, parameter2);
    case SQLITE_DROP_VIEW:
      return auth->DropView(parameter1);
    case SQLITE_INSERT:
      return auth->AllowInsert(parameter1);
    case SQLITE_PRAGMA:
      return auth->AllowPragma(parameter1, parameter2);
    case SQLITE_READ:
      return auth->AllowRead(parameter1, parameter2);
    case SQLITE_SELECT:
      return auth->AllowSelect();
    case SQLITE_TRANSACTION:
      return auth->AllowTransaction();
    case SQLITE_UPDATE:
      return auth->AllowUpdate(parameter1, parameter2);
    case SQLITE_ATTACH:
      return kSQLAuthDeny;
    case SQLITE_DETACH:
      return kSQLAuthDeny;
    case SQLITE_ALTER_TABLE:
      return auth->AllowAlterTable(parameter1, parameter2);
    case SQLITE_REINDEX:
      return auth->AllowReindex(parameter1);
    case SQLITE_ANALYZE:
      return auth->AllowAnalyze(parameter1);
    case SQLITE_CREATE_VTABLE:
      return auth->CreateVTable(parameter1, parameter2);
    case SQLITE_DROP_VTABLE:
      return auth->DropVTable(parameter1, parameter2);
    case SQLITE_FUNCTION:
      return auth->AllowFunction(parameter2);
    case SQLITE_SAVEPOINT:
      return kSQLAuthDeny;
    case SQLITE_RECURSIVE:
      return kSQLAuthDeny;
  }
  NOTREACHED();
}

void SQLiteDatabase::SetAuthorizer(DatabaseAuthorizer* authorizer) {
  if (!db_) {
    NOTREACHED() << "Attempt to set an authorizer on a non-open SQL database";
  }

  base::AutoLock locker(authorizer_lock_);

  authorizer_ = authorizer;

  EnableAuthorizer(true);
}

void SQLiteDatabase::EnableAuthorizer(bool enable) {
  if (authorizer_ && enable) {
    sqlite3_set_authorizer(db_, &SQLiteDatabase::AuthorizerFunction,
                           authorizer_);
  } else {
    sqlite3_set_authorizer(db_, nullptr, nullptr);
  }
}

bool SQLiteDatabase::IsAutoCommitOn() const {
  return sqlite3_get_autocommit(db_);
}

bool SQLiteDatabase::TurnOnIncrementalAutoVacuum() {
  SQLiteStatement statement(*this, "PRAGMA auto_vacuum");
  int auto_vacuum_mode = statement.GetColumnInt(0);
  int error = LastError();

  // Finalize statement to not block potential VACUUM.
  statement.Finalize();

  // Check if we got an error while trying to get the value of the auto_vacuum
  // flag.  If we got a SQLITE_BUSY error, then there's probably another
  // transaction in progress on this database. In this case, keep the current
  // value of the auto_vacuum flag and try to set it to INCREMENTAL the next
  // time we open this database. If the error is not SQLITE_BUSY, then we
  // probably ran into a more serious problem and should return false (to log an
  // error message).
  if (error != SQLITE_ROW)
    return false;

  switch (auto_vacuum_mode) {
    case kAutoVacuumIncremental:
      return true;
    case kAutoVacuumFull:
      return ExecuteCommand("PRAGMA auto_vacuum = 2");
    case kAutoVacuumNone:
    default:
      if (!ExecuteCommand("PRAGMA auto_vacuum = 2"))
        return false;
      RunVacuumCommand();
      error = LastError();
      return (error == SQLITE_OK);
  }
}

}  // namespace blink

"""

```