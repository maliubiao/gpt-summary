Response:
Let's break down the thought process for analyzing the `DatabaseAuthorizer.cc` file.

**1. Initial Understanding - What is the Goal?**

The file name `database_authorizer.cc` immediately suggests a component responsible for controlling access and permissions related to a database. The copyright notice confirms it's part of the Blink rendering engine, specifically within the `webdatabase` module. This points to the Web SQL Database API (now deprecated but still present in older Chromium versions).

**2. Core Functionality - Authorization Logic**

The class `DatabaseAuthorizer` is the central piece. The constructor takes a `database_info_table_name`, hinting at a specific table used for internal tracking. The `Reset()` method suggests the state can be reset. The presence of `security_enabled_` and `permissions_` variables strongly indicates its core function is to enforce security policies.

**3. Analyzing Individual Methods - Action-Based Permissions**

The bulk of the class consists of methods like `CreateTable`, `DropTable`, `AllowInsert`, `AllowUpdate`, etc. These directly correspond to SQL operations. The pattern is clear: each method checks if the operation is allowed based on the current security state and potentially the table name.

**4. Key Security Concepts:**

* **Read/Write Restrictions:** The `AllowWrite()` method and the checks in other methods (e.g., `!AllowWrite() ? kSQLAuthDeny : ...`) highlight the ability to enforce read-only access.
* **Table Name Restrictions:**  `DenyBasedOnTableName()` specifically blocks access to certain internal tables (like `sqlite_master` and the `database_info_table_name_`). This is a common security measure to prevent accidental or malicious modification of database metadata.
* **Function Whitelisting:**  `AllowedFunctions()` and `AllowFunction()` implement a whitelist of allowed SQLite functions. This limits the potential attack surface by preventing the execution of arbitrary or potentially dangerous functions.
* **Transactions:** `AllowTransaction()` hints at controlling the use of transactions, possibly to enforce atomicity or isolation.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The key here is understanding *how* this code gets called. The Web SQL Database API is exposed to JavaScript. JavaScript code interacts with the database via methods like `openDatabase()`, `transaction()`, and `executeSql()`. The `DatabaseAuthorizer` acts as a gatekeeper, intercepting and validating the SQL commands sent from JavaScript.

* **Example:** A JavaScript `executeSql()` call attempting to create a table named "users" would eventually trigger the `CreateTable("users")` method in this C++ code.

**6. Logical Reasoning and Examples:**

The methods often return `kSQLAuthDeny` or `kSQLAuthAllow`. This is a clear input/output relationship. We can then construct scenarios:

* **Input (JavaScript):** `db.transaction(function(tx) { tx.executeSql('CREATE TABLE sensitive_data (...)'); });`
* **Processing (C++):** The `CreateTable("sensitive_data")` method is called. If `security_enabled_` is true and "sensitive_data" is a restricted name, the method returns `kSQLAuthDeny`.
* **Output (Back to JavaScript):** The `executeSql()` call would fail with an error indicating insufficient permissions.

**7. User/Programming Errors:**

The file itself doesn't *directly* cause user errors. Instead, it *prevents* certain actions that could lead to errors or security vulnerabilities. However, we can infer potential developer errors:

* **Trying to access restricted tables:** A developer might unknowingly try to query or modify internal SQLite tables.
* **Using non-whitelisted functions:** A developer might use an advanced SQLite function not included in the `AllowedFunctions()` list.

**8. Debugging Clues - Tracing User Actions:**

To reach this code, a user *must* be interacting with a web page that uses the Web SQL Database API. The steps would be:

1. **User visits a webpage:** The webpage contains JavaScript code.
2. **JavaScript opens a database:** `openDatabase()` is called.
3. **JavaScript executes SQL:** `transaction()` and `executeSql()` are used to send SQL queries.
4. **Blink processes the SQL:**  The `DatabaseAuthorizer` methods are invoked during the processing of the SQL query to check permissions *before* the query is executed by the underlying SQLite engine.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  Focus solely on individual method behavior.
* **Correction:** Realize the importance of the overall context – the Web SQL Database API and its interaction with JavaScript.
* **Initial thought:**  Assume all restrictions are about table names.
* **Correction:** Identify the function whitelisting mechanism as another crucial security aspect.
* **Initial thought:**  Treat the C++ code in isolation.
* **Correction:** Understand that this code is part of a larger system and interacts with other Blink components and the SQLite library.

By following these steps, combining code analysis with an understanding of the surrounding technologies, we can arrive at a comprehensive explanation of the `DatabaseAuthorizer.cc` file's functionality.
这个文件是 Chromium Blink 引擎中 `webdatabase` 模块下的 `database_authorizer.cc` 文件。它的主要功能是**对 Web SQL Database 的操作进行权限控制和安全检查**。简单来说，它决定了哪些 SQL 操作是被允许的，哪些是被禁止的。

以下是它的详细功能分解：

**1. 权限控制 (Authorization):**

* **核心职责:**  `DatabaseAuthorizer` 类实现了对数据库操作的授权逻辑。当 Web 页面通过 JavaScript 执行 SQL 语句时，这个类的实例会被调用，以确定该操作是否被允许。
* **基于操作类型的授权:** 它针对不同的 SQL 操作（例如 `CREATE TABLE`, `DROP TABLE`, `INSERT`, `UPDATE`, `DELETE` 等）提供不同的授权方法（例如 `CreateTable`, `DropTable`, `AllowInsert`, `AllowUpdate`, `AllowDelete`）。
* **基于表名的授权:**  `DenyBasedOnTableName` 函数允许基于表名来拒绝或允许操作。这通常用于保护内部系统表，例如 `sqlite_master` 或用于存储数据库元数据的表。
* **基于函数名的授权:** `AllowFunction` 函数维护一个允许使用的 SQLite 函数列表（白名单）。如果 SQL 语句中使用了不在列表中的函数，则会被拒绝。
* **读写权限控制:** `AllowWrite` 函数检查当前是否允许写入操作，这可能受到安全设置或浏览模式（例如隐私模式）的影响。
* **事务控制:** `AllowTransaction` 函数控制是否允许开启事务。
* **临时对象控制:** 针对临时表、临时索引和临时触发器的创建和删除有专门的授权方法。

**2. 安全检查:**

* **防止修改内部表:** 阻止用户直接修改 `sqlite_master` 等 SQLite 内部表，以维护数据库的完整性。
* **限制可执行的函数:**  通过 `AllowedFunctions` 限制用户可以调用的 SQLite 函数，防止执行潜在的恶意或危险函数。
* **根据安全策略进行限制:**  `security_enabled_` 标志控制是否启用安全检查。`permissions_` 变量可以设置更细粒度的权限控制，例如只读模式。
* **记录数据库修改操作:**  `last_action_changed_database_` 标志用于跟踪是否有修改数据库结构的操作发生。
* **记录删除操作:** `had_deletes_` 标志用于跟踪是否有删除数据的操作发生。

**与 JavaScript, HTML, CSS 的关系：**

`DatabaseAuthorizer` 直接与 JavaScript 的 Web SQL Database API 相关联。

* **JavaScript:** 当 JavaScript 代码使用 Web SQL Database API（例如 `openDatabase`, `transaction`, `executeSql`）执行 SQL 语句时，Blink 引擎会调用 `DatabaseAuthorizer` 来验证这些操作。
    * **示例:**  JavaScript 代码 `db.transaction(function(tx) { tx.executeSql('CREATE TABLE users (id INTEGER)'); });` 会触发 `DatabaseAuthorizer::CreateTable("users")` 方法。如果授权器不允许创建表，`executeSql` 将会失败并抛出一个错误，这个错误会被 JavaScript 捕获。
    * **示例:**  JavaScript 代码 `db.transaction(function(tx) { tx.executeSql('SELECT hex(password) FROM users'); });` 会触发 `DatabaseAuthorizer::AllowFunction("hex")` 方法。如果 `hex` 函数不在 `AllowedFunctions()` 列表中，授权器会拒绝该操作。
* **HTML:** HTML 文件通过 `<script>` 标签引入 JavaScript 代码，这些 JavaScript 代码可能包含操作 Web SQL Database 的逻辑。因此，`DatabaseAuthorizer` 的权限控制间接地影响了 HTML 中嵌入的 JavaScript 行为。
* **CSS:** CSS 本身与数据库操作没有直接关系，但如果 JavaScript 代码根据数据库中的数据动态修改 CSS 样式，那么 `DatabaseAuthorizer` 对数据库操作的限制可能会间接影响页面的最终呈现。

**逻辑推理和假设输入输出：**

假设 `security_enabled_` 为 `true`，并且 `permissions_` 为默认值 (`kReadWriteMask`)。

* **假设输入:** JavaScript 执行 SQL 语句 `CREATE TABLE sensitive_data (col1 TEXT);`
* **处理过程:** `DatabaseAuthorizer::CreateTable("sensitive_data")` 被调用。如果 `DenyBasedOnTableName("sensitive_data")` 返回 `kSQLAuthDeny`（例如，如果配置禁止创建名为 "sensitive_data" 的表），则该操作被拒绝。
* **预期输出:**  `CreateTable` 方法返回 `kSQLAuthDeny`，导致 SQLite 执行失败，JavaScript 中的 `executeSql` 回调函数会收到一个错误。

* **假设输入:** JavaScript 执行 SQL 语句 `SELECT abs(-5) FROM my_table;`
* **处理过程:** `DatabaseAuthorizer::AllowFunction("abs")` 被调用。由于 `abs` 函数在 `AllowedFunctions()` 列表中，该方法返回 `kSQLAuthAllow`。
* **预期输出:** `AllowFunction` 方法返回 `kSQLAuthAllow`，SQLite 执行该查询。

* **假设输入:** JavaScript 执行 SQL 语句 `SELECT my_custom_function(data) FROM my_table;`  (假设 `my_custom_function` 不是内置的 SQLite 函数，也没有被添加到 `AllowedFunctions()` 列表中)
* **处理过程:** `DatabaseAuthorizer::AllowFunction("my_custom_function")` 被调用。由于 `my_custom_function` 不在 `AllowedFunctions()` 列表中，该方法返回 `kSQLAuthDeny`。
* **预期输出:** `AllowFunction` 方法返回 `kSQLAuthDeny`，导致 SQLite 执行失败。

**用户或编程常见的使用错误：**

* **尝试操作受保护的表:**  开发者可能尝试创建、删除或修改名为 `sqlite_master` 或 `__WebKitDatabaseInfoTable__`（默认的 `database_info_table_name_`）的表，这些操作通常会被 `DenyBasedOnTableName` 阻止。
    * **错误示例 (JavaScript):** `db.transaction(function(tx) { tx.executeSql('DROP TABLE sqlite_master;'); });`  这将导致一个权限错误。
* **使用未授权的 SQLite 函数:** 开发者可能在 SQL 语句中使用了不在 `AllowedFunctions()` 列表中的函数。
    * **错误示例 (JavaScript):** `db.transaction(function(tx) { tx.executeSql('SELECT load_extension(\'my_extension.so\');'); });`  `load_extension` 函数默认不在允许列表中，因此会被阻止。
* **在只读模式下尝试写入操作:**  如果浏览器的安全设置或用户的操作导致数据库处于只读模式，开发者尝试执行 `INSERT`, `UPDATE`, `DELETE`, `CREATE TABLE` 等操作将会失败。
    * **错误场景:** 用户在隐身模式下访问一个使用 Web SQL Database 的网站，并且该网站尝试写入数据。`AllowWrite()` 会返回 `false`，阻止写入操作。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户访问包含 Web SQL Database 使用的网页:** 用户在浏览器中输入网址或点击链接，访问一个使用了 Web SQL Database API 的网页。
2. **网页 JavaScript 代码执行数据库操作:** 网页加载后，其中的 JavaScript 代码调用 `openDatabase()` 打开或创建数据库。
3. **JavaScript 代码发起事务和执行 SQL 语句:** JavaScript 代码使用 `db.transaction()` 创建事务，并在事务中使用 `tx.executeSql()` 执行 SQL 语句。
4. **Blink 引擎接收 SQL 语句:** 当 `executeSql()` 被调用时，Blink 引擎的 Web SQL Database 实现会接收到要执行的 SQL 语句。
5. **创建 DatabaseAuthorizer 实例 (如果需要):** 在处理数据库操作之前，可能会创建 `DatabaseAuthorizer` 类的实例。
6. **调用相应的授权方法:**  根据 SQL 语句的类型，会调用 `DatabaseAuthorizer` 实例的相应方法，例如 `CreateTable`, `AllowInsert`, `AllowUpdate` 等。
7. **执行安全检查和权限判断:**  这些授权方法会根据当前的安全性设置、表名、函数名等进行检查，判断操作是否允许。
8. **返回授权结果:** 授权方法返回 `kSQLAuthAllow` 或 `kSQLAuthDeny`。
9. **SQLite 执行或拒绝执行:** 如果返回 `kSQLAuthAllow`，Blink 引擎会将 SQL 语句传递给底层的 SQLite 数据库引擎执行。如果返回 `kSQLAuthDeny`，执行会被阻止，并会向 JavaScript 返回一个错误。
10. **JavaScript 处理错误 (如果发生):** JavaScript 代码中的 `executeSql` 的错误回调函数会被调用，开发者可以在这里处理数据库操作失败的情况。

**调试线索示例:**

如果你在调试 Web SQL Database 相关的错误，并怀疑权限问题，可以关注以下几点：

* **检查 JavaScript 代码中执行的 SQL 语句:**  确认 SQL 语句是否尝试操作受保护的表或使用了未授权的函数。
* **查看浏览器的控制台错误信息:**  通常，当 Web SQL Database 操作被阻止时，控制台会显示相关的错误信息，例如 "SQLITE_ERROR: access denied"。
* **检查浏览器的安全设置和模式:**  确认浏览器是否处于隐私模式或有其他安全设置可能限制数据库的写入操作。
* **在 Blink 源码中设置断点:** 如果需要深入分析，可以在 `database_authorizer.cc` 文件中的相关授权方法上设置断点，例如 `CreateTable`, `DenyBasedOnTableName`, `AllowFunction` 等，以查看在执行特定 SQL 语句时是如何进行授权判断的。

总而言之，`blink/renderer/modules/webdatabase/database_authorizer.cc` 文件是 Web SQL Database 安全性的关键组成部分，它通过对数据库操作进行细致的权限控制，保护用户数据和浏览器的安全。

### 提示词
```
这是目录为blink/renderer/modules/webdatabase/database_authorizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2007 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/webdatabase/database_authorizer.h"

#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/case_folding_hash.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

DatabaseAuthorizer::DatabaseAuthorizer(const String& database_info_table_name)
    : security_enabled_(false),
      database_info_table_name_(database_info_table_name) {
  DCHECK(IsMainThread());

  Reset();
}

DatabaseAuthorizer::~DatabaseAuthorizer() = default;

void DatabaseAuthorizer::Reset() {
  last_action_was_insert_ = false;
  last_action_changed_database_ = false;
  permissions_ = kReadWriteMask;
}

void DatabaseAuthorizer::ResetDeletes() {
  had_deletes_ = false;
}

namespace {
using FunctionNameList = HashSet<String, CaseFoldingHashTraits<String>>;

const FunctionNameList& AllowedFunctions() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      FunctionNameList, list,
      ({
          // SQLite functions used to help implement some operations
          // ALTER TABLE helpers
          "sqlite_rename_column",
          "sqlite_rename_table",
          "sqlite_rename_test",
          "sqlite_rename_quotefix",
          // GLOB helpers
          "glob",
          // SQLite core functions
          "abs",
          "changes",
          "coalesce",
          "glob",
          "ifnull",
          "hex",
          "last_insert_rowid",
          "length",
          "like",
          "lower",
          "ltrim",
          "max",
          "min",
          "nullif",
          "quote",
          "replace",
          "round",
          "rtrim",
          "soundex",
          "sqlite_source_id",
          "sqlite_version",
          "substr",
          "total_changes",
          "trim",
          "typeof",
          "upper",
          "zeroblob",
          // SQLite date and time functions
          "date",
          "time",
          "datetime",
          "julianday",
          "strftime",
          // SQLite aggregate functions
          // max() and min() are already in the list
          "avg",
          "count",
          "group_concat",
          "sum",
          "total",
          // SQLite FTS functions
          "match",
          "snippet",
          "offsets",
          "optimize",
          // SQLite ICU functions
          // like(), lower() and upper() are already in the list
          "regexp",
          // Used internally by ALTER TABLE ADD COLUMN.
          "printf",
      }));
  return list;
}
}

int DatabaseAuthorizer::CreateTable(const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  last_action_changed_database_ = true;
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::CreateTempTable(const String& table_name) {
  // SQLITE_CREATE_TEMP_TABLE results in a UPDATE operation, which is not
  // allowed in read-only transactions or private browsing, so we might as
  // well disallow SQLITE_CREATE_TEMP_TABLE in these cases
  if (!AllowWrite())
    return kSQLAuthDeny;

  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::DropTable(const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::DropTempTable(const String& table_name) {
  // SQLITE_DROP_TEMP_TABLE results in a DELETE operation, which is not
  // allowed in read-only transactions or private browsing, so we might as
  // well disallow SQLITE_DROP_TEMP_TABLE in these cases
  if (!AllowWrite())
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::AllowAlterTable(const String&,
                                        const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  last_action_changed_database_ = true;
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::CreateIndex(const String&, const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  last_action_changed_database_ = true;
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::CreateTempIndex(const String&,
                                        const String& table_name) {
  // SQLITE_CREATE_TEMP_INDEX should result in a UPDATE or INSERT operation,
  // which is not allowed in read-only transactions or private browsing,
  // so we might as well disallow SQLITE_CREATE_TEMP_INDEX in these cases
  if (!AllowWrite())
    return kSQLAuthDeny;

  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::DropIndex(const String&, const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::DropTempIndex(const String&, const String& table_name) {
  // SQLITE_DROP_TEMP_INDEX should result in a DELETE operation, which is
  // not allowed in read-only transactions or private browsing, so we might
  // as well disallow SQLITE_DROP_TEMP_INDEX in these cases
  if (!AllowWrite())
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::CreateTrigger(const String&, const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  last_action_changed_database_ = true;
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::CreateTempTrigger(const String&,
                                          const String& table_name) {
  // SQLITE_CREATE_TEMP_TRIGGER results in a INSERT operation, which is not
  // allowed in read-only transactions or private browsing, so we might as
  // well disallow SQLITE_CREATE_TEMP_TRIGGER in these cases
  if (!AllowWrite())
    return kSQLAuthDeny;

  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::DropTrigger(const String&, const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::DropTempTrigger(const String&,
                                        const String& table_name) {
  // SQLITE_DROP_TEMP_TRIGGER results in a DELETE operation, which is not
  // allowed in read-only transactions or private browsing, so we might as
  // well disallow SQLITE_DROP_TEMP_TRIGGER in these cases
  if (!AllowWrite())
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::CreateView(const String&) {
  return (!AllowWrite() ? kSQLAuthDeny : kSQLAuthAllow);
}

int DatabaseAuthorizer::CreateTempView(const String&) {
  // SQLITE_CREATE_TEMP_VIEW results in a UPDATE operation, which is not
  // allowed in read-only transactions or private browsing, so we might as
  // well disallow SQLITE_CREATE_TEMP_VIEW in these cases
  return (!AllowWrite() ? kSQLAuthDeny : kSQLAuthAllow);
}

int DatabaseAuthorizer::DropView(const String&) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  had_deletes_ = true;
  return kSQLAuthAllow;
}

int DatabaseAuthorizer::DropTempView(const String&) {
  // SQLITE_DROP_TEMP_VIEW results in a DELETE operation, which is not
  // allowed in read-only transactions or private browsing, so we might as
  // well disallow SQLITE_DROP_TEMP_VIEW in these cases
  if (!AllowWrite())
    return kSQLAuthDeny;

  had_deletes_ = true;
  return kSQLAuthAllow;
}

int DatabaseAuthorizer::CreateVTable(const String& table_name,
                                     const String& module_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  // Allow only the FTS3 extension
  if (!EqualIgnoringASCIICase(module_name, "fts3"))
    return kSQLAuthDeny;

  last_action_changed_database_ = true;
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::DropVTable(const String& table_name,
                                   const String& module_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  // Allow only the FTS3 extension
  if (!DeprecatedEqualIgnoringCase(module_name, "fts3"))
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::AllowDelete(const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  return UpdateDeletesBasedOnTableName(table_name);
}

int DatabaseAuthorizer::AllowInsert(const String& table_name) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  last_action_changed_database_ = true;
  last_action_was_insert_ = true;
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::AllowUpdate(const String& table_name, const String&) {
  if (!AllowWrite())
    return kSQLAuthDeny;

  last_action_changed_database_ = true;
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::AllowTransaction() {
  return security_enabled_ ? kSQLAuthDeny : kSQLAuthAllow;
}

int DatabaseAuthorizer::AllowRead(const String& table_name, const String&) {
  if (permissions_ & kNoAccessMask && security_enabled_)
    return kSQLAuthDeny;

  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::AllowReindex(const String&) {
  return (!AllowWrite() ? kSQLAuthDeny : kSQLAuthAllow);
}

int DatabaseAuthorizer::AllowAnalyze(const String& table_name) {
  return DenyBasedOnTableName(table_name);
}

int DatabaseAuthorizer::AllowPragma(const String&, const String&) {
  return security_enabled_ ? kSQLAuthDeny : kSQLAuthAllow;
}

int DatabaseAuthorizer::AllowFunction(const String& function_name) {
  if (security_enabled_ && !AllowedFunctions().Contains(function_name))
    return kSQLAuthDeny;

  return kSQLAuthAllow;
}

void DatabaseAuthorizer::Disable() {
  security_enabled_ = false;
}

void DatabaseAuthorizer::Enable() {
  security_enabled_ = true;
}

bool DatabaseAuthorizer::AllowWrite() {
  return !(security_enabled_ &&
           (permissions_ & kReadOnlyMask || permissions_ & kNoAccessMask));
}

void DatabaseAuthorizer::SetPermissions(int permissions) {
  permissions_ = permissions;
}

int DatabaseAuthorizer::DenyBasedOnTableName(const String& table_name) const {
  if (!security_enabled_)
    return kSQLAuthAllow;

  // Sadly, normal creates and drops end up affecting sqlite_master in an
  // authorizer callback, so it will be tough to enforce all of the following
  // policies:
  // if (EqualIgnoringASCIICase(table_name, "sqlite_master") ||
  //     EqualIgnoringASCIICase(table_name, "sqlite_temp_master") ||
  //     EqualIgnoringASCIICase(table_name, "sqlite_sequence") ||
  //     EqualIgnoringASCIICase(table_name, database_info_table_name_))
  //   return SQLAuthDeny;

  if (EqualIgnoringASCIICase(table_name, database_info_table_name_))
    return kSQLAuthDeny;

  return kSQLAuthAllow;
}

int DatabaseAuthorizer::UpdateDeletesBasedOnTableName(
    const String& table_name) {
  int allow = DenyBasedOnTableName(table_name);
  if (allow)
    had_deletes_ = true;
  return allow;
}

}  // namespace blink
```