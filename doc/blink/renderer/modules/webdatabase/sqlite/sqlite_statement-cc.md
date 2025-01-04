Response:
Let's break down the thought process to analyze the `sqlite_statement.cc` file and address the prompt's requirements.

**1. Understanding the Core Purpose:**

The filename itself, `sqlite_statement.cc`, immediately suggests this file deals with the concept of "statements" in the context of SQLite. Reading the initial comments reinforces this: it's about interacting with SQLite queries. The inclusion of `<sqlite3.h>` confirms this.

**2. Identifying Key Classes and Methods:**

The core class is `SQLiteStatement`. The methods within this class (like `Prepare`, `Step`, `Finalize`, `BindText`, `GetColumnValue`, etc.) reveal the lifecycle and operations involved in executing an SQLite statement. These are the building blocks of interacting with the database.

**3. Functionality Breakdown (Based on Method Names and Code):**

* **Initialization and Destruction:** `SQLiteStatement` constructor takes the database and SQL query. The destructor calls `Finalize`, suggesting resource management.
* **Preparation:** `Prepare()` uses `sqlite3_prepare_v3` to compile the SQL query. Error handling is present.
* **Execution:** `Step()` executes the prepared statement one step at a time, retrieving a row of results.
* **Finalization:** `Finalize()` releases resources associated with the prepared statement using `sqlite3_finalize`.
* **Binding Parameters:**  Methods like `BindText`, `BindDouble`, `BindNull`, and `BindValue` are for safely inserting data into the query before execution, preventing SQL injection.
* **Retrieving Results:** Methods like `ColumnCount`, `GetColumnName`, `GetColumnValue`, `GetColumnText`, `GetColumnInt`, and `GetColumnInt64` are responsible for fetching data from the result set after a successful `Step()`.
* **Error Handling:**  The `restrictError` function and checks after SQLite API calls indicate a focus on robust error handling. The `SQL_DVLOG` calls suggest logging for debugging.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The key is understanding *where* this code fits within the browser architecture. The `blink/renderer/modules/webdatabase` path gives a strong hint: this is part of the *client-side* database functionality accessible to web pages.

* **JavaScript:** The most direct connection is through the JavaScript Web SQL API (though deprecated, understanding its past helps). JavaScript code uses methods like `database.transaction()` and `transaction.executeSql()` to interact with the database. The `SQLiteStatement` class is the underlying mechanism for executing those SQL queries. *Example:*  A JavaScript `executeSql` call with a `SELECT` statement would eventually lead to the creation of an `SQLiteStatement`, preparation, stepping through rows, and retrieving data to be returned to the JavaScript callback.
* **HTML:**  HTML doesn't directly interact with `SQLiteStatement`. However, user actions in HTML (e.g., clicking a button that triggers a JavaScript function) can initiate database operations that eventually involve this code.
* **CSS:** CSS has no direct interaction with the database layer.

**5. Logical Reasoning and Examples:**

* **Preparation and Execution Flow:**  A prepared statement can be executed multiple times with different bound parameters. *Hypothetical Input:*  `SELECT * FROM users WHERE id = ?`. `BindText(1, '123')` followed by `Step()` would retrieve the row for user ID 123. Subsequent calls to `BindText(1, '456')` and `Step()` would retrieve data for user ID 456 without re-preparing the query.
* **Data Type Handling:**  The `BindValue` and `GetColumnValue` methods demonstrate how different SQL data types (TEXT, REAL, NULL) are handled and converted to Blink's internal representations.

**6. Common User/Programming Errors:**

Focus on the interaction points between the JavaScript API and the native code.

* **Incorrect SQL Syntax:**  The `Prepare()` method would fail, and the JavaScript callback would receive an error.
* **Incorrect Number of Bind Parameters:** The `Bind...` methods would likely trigger an error if the number of bound parameters doesn't match the placeholders in the SQL.
* **Data Type Mismatch:**  Trying to bind a string to an integer column could lead to errors or unexpected behavior.
* **Forgetting to Bind Parameters:** Executing a prepared statement with placeholders without binding values will result in errors.

**7. Debugging Scenario:**

Think about how a developer might end up examining this code.

* **User Action:**  A user interacts with a web page that uses client-side storage. For example, they might submit a form that saves data to a local database.
* **JavaScript Execution:**  The JavaScript code calls `executeSql()` to perform the database operation (e.g., `INSERT` or `UPDATE`).
* **Error Occurs:**  Something goes wrong – perhaps the database file is corrupt, the query is invalid, or there's an issue with data binding.
* **Debugging Tools:** The developer uses the browser's developer tools (like the "Sources" tab or a specialized SQLite debugging tool) to step through the JavaScript code. They might notice an error in the database operation.
* **Deeper Investigation:** To understand the root cause, the developer might need to examine the Blink source code, particularly the `sqlite_statement.cc` file, to see how the SQL query is being prepared and executed, and how errors are handled. The `SQL_DVLOG` messages would be particularly helpful here.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this file directly handles the database file operations.
* **Correction:**  Reviewing the imports and methods suggests it's more focused on the *statement execution* aspect, with `SQLiteDatabase` likely handling the file operations.
* **Initial thought:**  The connection to web technologies might be vague.
* **Refinement:**  Focus on the flow of data and control from JavaScript `executeSql` calls down to the native SQLite API interactions within this file.

By following these steps, systematically dissecting the code and connecting it to the broader context of web technologies, we can arrive at a comprehensive and accurate analysis of the `sqlite_statement.cc` file.
好的，让我们来详细分析一下 `blink/renderer/modules/webdatabase/sqlite/sqlite_statement.cc` 这个 Chromium Blink 引擎源代码文件的功能。

**文件功能概述:**

`sqlite_statement.cc` 文件定义了 `SQLiteStatement` 类，这个类是 Blink 中用于执行 SQLite 数据库语句的核心组件。它封装了与 SQLite C API 交互的细节，并提供了更高级别的接口供 Blink 的 WebDatabase 模块使用。

主要功能包括：

1. **SQL 语句准备 (Preparation):**  负责将 SQL 字符串编译成 SQLite 可以执行的预处理语句（prepared statement）。这通过调用 SQLite 的 `sqlite3_prepare_v3` 函数实现。预处理可以提高性能，特别是对于重复执行的语句。
2. **参数绑定 (Binding):**  允许将外部数据（例如 JavaScript 传递的参数）安全地绑定到预处理语句中的占位符。这通过 `BindText`、`BindDouble`、`BindNull` 等方法实现，使用 SQLite 的 `sqlite3_bind_*` 系列函数。参数绑定是防止 SQL 注入攻击的关键措施。
3. **语句执行 (Stepping):** 执行已准备好的 SQL 语句。对于 `SELECT` 语句，每次执行 `Step()` 会返回结果集中的下一行。对于 `INSERT`、`UPDATE`、`DELETE` 等语句，`Step()` 会执行操作。这通过调用 SQLite 的 `sqlite3_step` 函数实现。
4. **结果获取 (Column Access):**  在执行 `SELECT` 语句后，提供方法来获取结果集中每一列的数据。包括 `GetColumnName` (获取列名)、`GetColumnValue` (获取列的通用值)、`GetColumnText` (获取列的文本值)、`GetColumnInt` (获取列的整数值) 等。这些方法使用 SQLite 的 `sqlite3_column_*` 系列函数。
5. **语句终结 (Finalization):**  释放与已准备语句相关的资源。这通过调用 SQLite 的 `sqlite3_finalize` 函数实现，确保资源不会泄漏。
6. **错误处理:**  封装了 SQLite 的错误代码，并提供 `restrictError` 函数来过滤和限制返回的错误代码，使其与特定 SQLite 版本（3.7.6.3）保持一致。
7. **日志记录:**  使用 `SQL_DVLOG` 宏进行 SQL 操作的调试日志记录。

**与 JavaScript, HTML, CSS 的关系：**

`sqlite_statement.cc` 文件位于 WebDatabase 模块中，该模块提供了在浏览器端存储结构化数据的能力，并通过 JavaScript 的 Web SQL Database API 暴露给网页开发者（虽然 Web SQL Database 已经被废弃，但了解其工作原理有助于理解）。

* **JavaScript:**
    * **直接关系:** JavaScript 代码使用 `openDatabase` 函数创建数据库，并使用 `transaction` 和 `executeSql` 方法执行 SQL 查询。`executeSql` 内部最终会创建并使用 `SQLiteStatement` 对象来执行 SQL 语句。
    * **举例说明:**
        ```javascript
        const db = openDatabase('mydb', '1.0', 'My Database', 2 * 1024 * 1024);
        db.transaction(function (tx) {
          tx.executeSql('SELECT name, age FROM users WHERE city = ?', ['London'], function (tx, results) {
            // 处理查询结果
            for (let i = 0; i < results.rows.length; i++) {
              const row = results.rows.item(i);
              console.log(row.name, row.age);
            }
          }, function(tx, error) {
            console.error('查询失败:', error.message);
          });
        });
        ```
        在这个例子中，`tx.executeSql` 接收的 SQL 字符串和参数 `['London']` 会被传递到 Blink 的 WebDatabase 模块。`SQLiteStatement` 类会被用来准备 `SELECT` 语句，并将 `'London'` 绑定到 `?` 占位符。执行后，通过 `GetColumnName` 和 `GetColumnValue` 等方法获取 `name` 和 `age` 列的值，并将结果返回给 JavaScript 的回调函数。

* **HTML:**
    * **间接关系:** HTML 负责网页的结构和内容，它本身不直接与 `SQLiteStatement` 交互。但是，用户在 HTML 页面上的操作（如点击按钮、提交表单）可能会触发 JavaScript 代码，而这些 JavaScript 代码可能会调用 Web SQL Database API 来执行数据库操作，从而间接地使用到 `SQLiteStatement`。
    * **举例说明:** 一个 HTML 按钮的 `onclick` 事件可能触发一个 JavaScript 函数，该函数会向本地数据库插入新的用户数据。

* **CSS:**
    * **无直接关系:** CSS 负责网页的样式，与数据库操作没有直接关联。

**逻辑推理与示例：**

假设有以下 SQL 查询：

```sql
SELECT name, email FROM customers WHERE order_count > ? AND last_login < ?
```

1. **假设输入（在 JavaScript 中调用 `executeSql`）：**
   ```javascript
   tx.executeSql('SELECT name, email FROM customers WHERE order_count > ? AND last_login < ?', [5, '2023-01-01']);
   ```

2. **`SQLiteStatement::Prepare()` 的过程:**
   * 输入 SQL 字符串: `"SELECT name, email FROM customers WHERE order_count > ? AND last_login < ?"`
   * 调用 `sqlite3_prepare_v3` 将 SQL 字符串编译成预处理语句。
   * **假设输出:**  如果编译成功，`statement_` 成员变量将指向一个有效的 `sqlite3_stmt` 对象。如果编译失败，`Prepare()` 返回非 `SQLITE_OK` 的错误码。

3. **`SQLiteStatement::BindText()` 和 `SQLiteStatement::BindDouble()` 的过程:**
   * `BindDouble(1, 5)` 将整数 `5` 绑定到第一个 `?` 占位符（`order_count`）。
   * `BindText(2, '2023-01-01')` 将字符串 `'2023-01-01'` 绑定到第二个 `?` 占位符（`last_login`）。
   * **假设输出:** 如果绑定成功，返回 `SQLITE_OK`。

4. **`SQLiteStatement::Step()` 的过程:**
   * 执行预处理语句。
   * **假设输出:**
     * 如果有匹配的行，`Step()` 返回 `SQLITE_ROW`。
     * 如果没有更多行，`Step()` 返回 `SQLITE_DONE`。
     * 如果发生错误，`Step()` 返回相应的 SQLite 错误码。

5. **`SQLiteStatement::GetColumnText()` 的过程（假设 `Step()` 返回 `SQLITE_ROW`）：**
   * `GetColumnText(0)` 获取第一列（`name`）的文本值。
   * `GetColumnText(1)` 获取第二列（`email`）的文本值。
   * **假设输入:** 数据库中存在满足条件的客户，例如：`{ name: 'Alice', email: 'alice@example.com' }`
   * **假设输出:**
     * `GetColumnText(0)` 返回 `"Alice"`。
     * `GetColumnText(1)` 返回 `"alice@example.com"`。

**用户或编程常见的使用错误：**

1. **SQL 语法错误:**  用户在 JavaScript 中提供的 SQL 字符串包含语法错误，导致 `Prepare()` 失败。
   * **举例:** `tx.executeSql('SELECt name FROM users');` (拼写错误 `SELECt`)
   * **后果:** `Prepare()` 返回错误码，JavaScript 的错误回调函数被调用。

2. **绑定参数类型不匹配:**  绑定的数据类型与数据库表定义的列类型不匹配。
   * **举例:**  如果 `order_count` 列是整数类型，但用户尝试绑定一个字符串：`tx.executeSql('...', ['not_a_number', ...])`
   * **后果:**  SQLite 可能会尝试进行类型转换，但如果转换失败，可能会导致错误或意外结果。

3. **绑定参数数量不匹配:**  SQL 语句中的占位符数量与提供的参数数量不一致。
   * **举例:** `tx.executeSql('SELECT * FROM products WHERE id = ? AND category = ?', [1]);` (缺少一个参数)
   * **后果:** `Bind...` 方法可能会报错，或者执行时发生错误。

4. **忘记绑定参数:**  SQL 语句中有占位符，但没有提供相应的参数进行绑定。
   * **举例:** `tx.executeSql('INSERT INTO logs (message) VALUES (?)');` (没有提供要插入的消息)
   * **后果:**  执行语句时会出错。

5. **在 `Finalize()` 之后尝试操作语句:**  一旦语句被终结，就不能再对其进行绑定、执行或获取结果。
   * **举例:** 调用 `ExecuteCommand()` 后，再次调用 `Step()` 或 `GetColumnText()`。
   * **后果:**  可能会导致程序崩溃或未定义行为。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在一个在线购物网站上尝试查看他们的订单历史。

1. **用户操作:** 用户点击了页面上的 "我的订单" 按钮。
2. **前端 JavaScript 代码执行:**  按钮的点击事件触发了一个 JavaScript 函数。
3. **JavaScript 调用 Web SQL Database API:**  该 JavaScript 函数可能使用 `openDatabase` 获取数据库连接，并使用 `transaction` 和 `executeSql` 执行一个 SQL 查询来获取用户的订单信息。例如：
   ```javascript
   db.transaction(function (tx) {
     tx.executeSql('SELECT order_id, order_date, total FROM orders WHERE user_id = ?', [currentUserId], function (tx, results) {
       // 在页面上显示订单信息
     }, function(tx, error) {
       console.error('获取订单历史失败:', error.message);
     });
   });
   ```
4. **Blink WebDatabase 模块处理 `executeSql`:**  Blink 接收到 `executeSql` 的调用，并创建 `SQLiteStatement` 对象，传入 SQL 字符串和数据库连接。
5. **`SQLiteStatement::Prepare()` 被调用:**  SQL 字符串被编译成预处理语句。
6. **`SQLiteStatement::BindText()` 或 `BindDouble()` 被调用:** `currentUserId` 的值被绑定到 SQL 查询的 `?` 占位符。
7. **`SQLiteStatement::Step()` 被调用:**  执行查询，从数据库中获取匹配的订单记录。
8. **`SQLiteStatement::GetColumn...()` 系列方法被调用:**  从结果集中提取 `order_id`, `order_date`, `total` 等列的值。
9. **结果返回给 JavaScript:**  获取到的订单信息被传递回 JavaScript 的成功回调函数。
10. **JavaScript 更新页面:**  JavaScript 代码将订单信息动态地添加到 HTML 页面上显示给用户。

**作为调试线索，如果开发者需要调试与此文件相关的问题，可能会采取以下步骤：**

* **设置断点:**  在 `SQLiteStatement` 的关键方法（如 `Prepare`, `Step`, `BindText`, `GetColumnValue`）中设置断点，以便观察 SQL 语句的准备、参数绑定、执行过程以及结果的获取。
* **查看日志:**  检查控制台或 Blink 的内部日志 (`SQL_DVLOG`)，查看是否有 SQL 相关的错误信息或调试输出。
* **检查 SQL 语句和参数:**  确认 JavaScript 中传递给 `executeSql` 的 SQL 语句是否正确，参数类型和数量是否匹配。
* **使用 SQLite 调试工具:**  有时，可以使用独立的 SQLite 客户端工具连接到 Blink 使用的数据库文件，直接执行 SQL 查询，以排除是数据库本身的问题。
* **分析错误码:**  如果发生错误，仔细分析 `restrictError` 返回的错误码，查阅 SQLite 的文档，了解错误的具体含义。

希望以上详细的解释能够帮助你理解 `blink/renderer/modules/webdatabase/sqlite/sqlite_statement.cc` 文件的功能以及它在 Chromium Blink 引擎中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/webdatabase/sqlite/sqlite_statement.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/modules/webdatabase/sqlite/sqlite_statement.h"

#include <memory>

#include "base/notreached.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sql_log.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sql_value.h"
#include "third_party/sqlite/sqlite3.h"

// SQLite 3.6.16 makes sqlite3_prepare_v2 automatically retry preparing the
// statement once if the database scheme has changed. We rely on this behavior.
#if SQLITE_VERSION_NUMBER < 3006016
#error SQLite version 3.6.16 or newer is required
#endif

namespace {

// Only return error codes consistent with 3.7.6.3.
int restrictError(int error) {
  switch (error) {
    case SQLITE_IOERR_READ:
    case SQLITE_IOERR_SHORT_READ:
    case SQLITE_IOERR_WRITE:
    case SQLITE_IOERR_FSYNC:
    case SQLITE_IOERR_DIR_FSYNC:
    case SQLITE_IOERR_TRUNCATE:
    case SQLITE_IOERR_FSTAT:
    case SQLITE_IOERR_UNLOCK:
    case SQLITE_IOERR_RDLOCK:
    case SQLITE_IOERR_DELETE:
    case SQLITE_IOERR_BLOCKED:
    case SQLITE_IOERR_NOMEM:
    case SQLITE_IOERR_ACCESS:
    case SQLITE_IOERR_CHECKRESERVEDLOCK:
    case SQLITE_IOERR_LOCK:
    case SQLITE_IOERR_CLOSE:
    case SQLITE_IOERR_DIR_CLOSE:
    case SQLITE_IOERR_SHMOPEN:
    case SQLITE_IOERR_SHMSIZE:
    case SQLITE_IOERR_SHMLOCK:
    case SQLITE_LOCKED_SHAREDCACHE:
    case SQLITE_BUSY_RECOVERY:
    case SQLITE_CANTOPEN_NOTEMPDIR:
      return error;
    default:
      return (error & 0xff);
  }
}

scoped_refptr<StringImpl> ColumnText16ToStringImpl(sqlite3_stmt* statement,
                                                   int col) {
  const UChar* text16 =
      static_cast<const UChar*>(sqlite3_column_text16(statement, col));
  const size_t text16_byte_length =
      base::checked_cast<size_t>(sqlite3_column_bytes16(statement, col));
  // SAFETY: sqlite3_column_bytes16() returns at least the number of bytes that
  // sqlite3_column_text16() points to.
  return StringImpl::Create8BitIfPossible(
      UNSAFE_BUFFERS({text16, text16_byte_length / sizeof(UChar)}));
}

}  // namespace

namespace blink {

SQLiteStatement::SQLiteStatement(SQLiteDatabase& db, const String& sql)
    : database_(db), query_(sql), statement_(nullptr) {}

SQLiteStatement::~SQLiteStatement() {
  Finalize();
}

int SQLiteStatement::Prepare() {
#if DCHECK_IS_ON()
  DCHECK(!is_prepared_);
#endif

  std::string query = query_.StripWhiteSpace().Utf8();

  // Need to pass non-stack |const char*| and |sqlite3_stmt*| to avoid race
  // with Oilpan stack scanning.
  std::unique_ptr<const char*> tail = std::make_unique<const char*>();
  std::unique_ptr<sqlite3_stmt*> statement = std::make_unique<sqlite3_stmt*>();
  *tail = nullptr;
  *statement = nullptr;
  int error;
  {
    SQL_DVLOG(1) << "SQL - prepare - " << query;

    // Pass the length of the string including the null character to
    // sqlite3_prepare_v3(); this lets SQLite avoid an extra string copy.
    wtf_size_t length_including_null_character =
        static_cast<wtf_size_t>(query.length()) + 1;

    error = sqlite3_prepare_v3(database_->Sqlite3Handle(), query.c_str(),
                               length_including_null_character,
                               /* prepFlags= */ 0, statement.get(), tail.get());
  }
  statement_ = *statement;

  if (error != SQLITE_OK) {
    SQL_DVLOG(1) << "sqlite3_prepare_v3 failed (" << error << ")\n"
                 << query << "\n"
                 << sqlite3_errmsg(database_->Sqlite3Handle());
  } else if (*tail && **tail) {
    error = SQLITE_ERROR;
  }

#if DCHECK_IS_ON()
  is_prepared_ = error == SQLITE_OK;
#endif
  return restrictError(error);
}

int SQLiteStatement::Step() {
  if (!statement_)
    return SQLITE_OK;

  // The database needs to update its last changes count before each statement
  // in order to compute properly the lastChanges() return value.
  database_->UpdateLastChangesCount();

  SQL_DVLOG(1) << "SQL - step - " << query_;
  int error = sqlite3_step(statement_);
  if (error != SQLITE_DONE && error != SQLITE_ROW) {
    SQL_DVLOG(1) << "sqlite3_step failed (" << error << " )\nQuery - " << query_
                 << "\nError - " << sqlite3_errmsg(database_->Sqlite3Handle());
  }

  return restrictError(error);
}

int SQLiteStatement::Finalize() {
#if DCHECK_IS_ON()
  is_prepared_ = false;
#endif
  if (!statement_)
    return SQLITE_OK;
  SQL_DVLOG(1) << "SQL - finalize - " << query_;
  int result = sqlite3_finalize(statement_);
  statement_ = nullptr;
  return restrictError(result);
}

bool SQLiteStatement::ExecuteCommand() {
  if (!statement_ && Prepare() != SQLITE_OK)
    return false;
#if DCHECK_IS_ON()
  DCHECK(is_prepared_);
#endif
  if (Step() != SQLITE_DONE) {
    Finalize();
    return false;
  }
  Finalize();
  return true;
}

int SQLiteStatement::BindText(int index, const String& text) {
#if DCHECK_IS_ON()
  DCHECK(is_prepared_);
#endif
  DCHECK_GT(index, 0);
  DCHECK_LE(static_cast<unsigned>(index), BindParameterCount());

  String text16(text);
  text16.Ensure16Bit();
  return restrictError(
      sqlite3_bind_text16(statement_, index, text16.Characters16(),
                          sizeof(UChar) * text16.length(), SQLITE_TRANSIENT));
}

int SQLiteStatement::BindDouble(int index, double number) {
#if DCHECK_IS_ON()
  DCHECK(is_prepared_);
#endif
  DCHECK_GT(index, 0);
  DCHECK_LE(static_cast<unsigned>(index), BindParameterCount());

  return restrictError(sqlite3_bind_double(statement_, index, number));
}

int SQLiteStatement::BindNull(int index) {
#if DCHECK_IS_ON()
  DCHECK(is_prepared_);
#endif
  DCHECK_GT(index, 0);
  DCHECK_LE(static_cast<unsigned>(index), BindParameterCount());

  return restrictError(sqlite3_bind_null(statement_, index));
}

int SQLiteStatement::BindValue(int index, const SQLValue& value) {
  switch (value.GetType()) {
    case SQLValue::kStringValue:
      return BindText(index, value.GetString());
    case SQLValue::kNumberValue:
      return BindDouble(index, value.Number());
    case SQLValue::kNullValue:
      return BindNull(index);
  }

  NOTREACHED();
}

unsigned SQLiteStatement::BindParameterCount() const {
#if DCHECK_IS_ON()
  DCHECK(is_prepared_);
#endif
  if (!statement_)
    return 0;
  return sqlite3_bind_parameter_count(statement_);
}

int SQLiteStatement::ColumnCount() {
#if DCHECK_IS_ON()
  DCHECK(is_prepared_);
#endif
  if (!statement_)
    return 0;
  return sqlite3_data_count(statement_);
}

String SQLiteStatement::GetColumnName(int col) {
  DCHECK_GE(col, 0);
  if (!statement_)
    if (PrepareAndStep() != SQLITE_ROW)
      return String();
  if (ColumnCount() <= col)
    return String();
  return String(
      reinterpret_cast<const UChar*>(sqlite3_column_name16(statement_, col)));
}

SQLValue SQLiteStatement::GetColumnValue(int col) {
  DCHECK_GE(col, 0);
  if (!statement_)
    if (PrepareAndStep() != SQLITE_ROW)
      return SQLValue();
  if (ColumnCount() <= col)
    return SQLValue();

  // SQLite is typed per value. optional column types are
  // "(mostly) ignored"
  switch (sqlite3_column_type(statement_, col)) {
    case SQLITE_INTEGER:  // SQLValue and JS don't represent integers, so use
                          // FLOAT -case
    case SQLITE_FLOAT:
      return SQLValue(sqlite3_column_double(statement_, col));
    case SQLITE_BLOB:  // SQLValue and JS don't represent blobs, so use TEXT
                       // -case
    case SQLITE_TEXT:
      return SQLValue(ColumnText16ToStringImpl(statement_, col));
    case SQLITE_NULL:
      return SQLValue();
  }
  NOTREACHED();
}

String SQLiteStatement::GetColumnText(int col) {
  DCHECK_GE(col, 0);
  if (!statement_)
    if (PrepareAndStep() != SQLITE_ROW)
      return String();
  if (ColumnCount() <= col)
    return String();
  return ColumnText16ToStringImpl(statement_, col);
}

int SQLiteStatement::GetColumnInt(int col) {
  DCHECK_GE(col, 0);
  if (!statement_)
    if (PrepareAndStep() != SQLITE_ROW)
      return 0;
  if (ColumnCount() <= col)
    return 0;
  return sqlite3_column_int(statement_, col);
}

int64_t SQLiteStatement::GetColumnInt64(int col) {
  DCHECK_GE(col, 0);
  if (!statement_)
    if (PrepareAndStep() != SQLITE_ROW)
      return 0;
  if (ColumnCount() <= col)
    return 0;
  return sqlite3_column_int64(statement_, col);
}

}  // namespace blink

"""

```