Response:
My thinking process to analyze the `gumquickdatabase.c` code and answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the code, its relevance to reverse engineering, its connection to low-level concepts, any logical inferences, potential user errors, and how a user might reach this code.

2. **Initial Scan for Keywords and Structure:** I first scan the code for obvious keywords and structures. I see `#include`, `typedef`, `struct`, `enum`, function declarations with `GUMJS_DECLARE_FUNCTION`, `static`, and function definitions with `GUMJS_DEFINE_FUNCTION`. This tells me it's C code defining data structures and functions. The `GUMJS_` prefixes suggest a connection to the Frida/Gum environment. The presence of `sqlite3*` and related functions immediately flags database interaction as a core function.

3. **Identify Core Functionality (High-Level):** Based on the initial scan, the most prominent functionality is interacting with SQLite databases. The code defines functions to open, close, execute SQL, prepare statements, bind parameters, step through results, and dump database contents. The `GUM_STORAGE_FILESYSTEM` and `GUM_STORAGE_MEMORY` enums indicate the ability to work with on-disk and in-memory databases.

4. **Map Functions to Actions:** I go through the `GUMJS_DEFINE_FUNCTION` definitions and their corresponding `GUMJS_DECLARE_FUNCTION` declarations to understand the available operations. I create a mental (or actual) list:
    * `gumjs_database_open`: Opens a database from a file.
    * `gumjs_database_open_inline`: Opens a database from in-memory data.
    * `gumjs_database_close`: Closes a database.
    * `gumjs_database_exec`: Executes raw SQL.
    * `gumjs_database_prepare`: Prepares a parameterized SQL statement.
    * `gumjs_database_dump`:  Retrieves the database content.
    * `gumjs_statement_bind_*`: Binds values to prepared statement parameters.
    * `gumjs_statement_step`: Executes a prepared statement and fetches a row.
    * `gumjs_statement_reset`: Resets a prepared statement.

5. **Analyze Reverse Engineering Relevance:**  I consider how these database operations can be used in reverse engineering. The ability to open and query databases within a running process is crucial for:
    * **Inspecting application data:** Many applications store data in SQLite databases. Frida can be used to examine this data in real-time.
    * **Modifying application behavior:** By modifying database entries, one could potentially alter the application's logic or state.
    * **Understanding data structures:** Examining the database schema and data can reveal internal data structures and relationships.

6. **Connect to Low-Level Concepts:**  I look for code elements related to operating systems and low-level programming:
    * **`sqlite3_*` functions:** These are part of the SQLite library, which is a fundamental database engine often used on various platforms, including Linux and Android.
    * **File system interaction:** `sqlite3_open_v2` with file paths indicates interaction with the file system.
    * **Memory management:**  `g_malloc`, `g_free`, `g_slice_new`, `g_slice_free` are GLib functions for memory management, common in Linux development. The `gum_memory_vfs_*` functions indicate a custom in-memory file system abstraction.
    * **Virtual File System (VFS):** The code explicitly registers and unregisters a memory VFS (`gum_memory_vfs_new`, `sqlite3_vfs_register`). This is a Linux kernel concept that allows abstracting file system operations. This is particularly relevant for in-memory databases.
    * **Data types:**  `guint`, `gchar*`, `gint`, `gdouble`, `gpointer`, `gsize`, `GBytes` are GLib/GObject data types, common in Linux and cross-platform development.

7. **Identify Logical Inferences and Potential Inputs/Outputs:** I think about the control flow and data transformations:
    * **Opening a database:** Input: file path (string), flags (integer). Output: A `GumDatabase` object (or an error if opening fails).
    * **Executing SQL:** Input: `GumDatabase` object, SQL query (string). Output:  Success (undefined) or an error.
    * **Preparing a statement:** Input: `GumDatabase` object, SQL query with placeholders (string). Output: A `SqliteStatement` object (or an error).
    * **Binding parameters:** Input: `SqliteStatement` object, parameter index (integer), value (integer, float, text, blob, or null). Output: Success (undefined) or an error.
    * **Stepping a statement:** Input: `SqliteStatement` object. Output: A row of data (as a JavaScript array) or `null` if no more rows, or an error.

8. **Consider User Errors:** I think about common mistakes a programmer using this API might make:
    * **Incorrect file path:** Providing a non-existent or inaccessible file path for `open`.
    * **Invalid SQL syntax:**  Providing malformed SQL to `exec` or `prepare`.
    * **Incorrect number or type of parameters:**  Mismatched parameter binding in prepared statements.
    * **Operating on a closed database:** Calling methods on a database object after it has been closed.
    * **Forgetting to finalize statements:** Not calling `reset` or letting the statement object be garbage collected, potentially leading to resource leaks.

9. **Trace User Actions (Debugging Scenario):** I consider how a user would interact with Frida to reach this code:
    1. **Write a Frida script:** The user would write a JavaScript script using the Frida API.
    2. **Access the `SqliteDatabase` class:** The script would access the `SqliteDatabase` class, likely available under a module (e.g., `Database`).
    3. **Call `SqliteDatabase._open()` or `SqliteDatabase.openInline()`:** The user would call these static methods to open a database.
    4. **Call methods on the database object:** The user would then call methods like `exec`, `prepare`, or `dump` on the returned `SqliteDatabase` object.
    5. **Call methods on statement objects:** If using prepared statements, they would call `bindInteger`, `bindText`, `step`, etc., on the returned `SqliteStatement` objects.
    6. **Encounter an error:** If something goes wrong (e.g., invalid SQL), the JavaScript exception might originate from the C code in `gumquickdatabase.c`, as it handles the SQLite error codes and throws exceptions.
    7. **Debugging:** The user might use Frida's logging or debugging features to trace the execution and see where the error originates, leading them to this C code.

10. **Structure the Answer:**  Finally, I organize my findings into the requested categories, providing clear explanations and examples for each point. I use the insights gained from the previous steps to generate the detailed answers.
这个文件 `gumquickdatabase.c` 是 Frida 工具中用于提供 JavaScript 绑定，以便在目标进程中操作 SQLite 数据库的功能模块。它的核心作用是将底层的 SQLite 库功能暴露给 JavaScript 环境，使得用户可以使用 JavaScript 代码来与目标进程中的数据库进行交互。

下面详细列举一下它的功能，并根据你的要求进行说明：

**功能列举：**

1. **打开数据库:**
   - `gumjs_database_open`:  允许 JavaScript 代码打开目标进程文件系统中的 SQLite 数据库文件。
   - `gumjs_database_open_inline`: 允许 JavaScript 代码打开一个内存中的 SQLite 数据库，其内容可以由 JavaScript 提供（通常是 base64 编码的）。

2. **关闭数据库:**
   - `gumjs_database_close`: 允许 JavaScript 代码关闭已打开的数据库连接。

3. **执行 SQL 语句:**
   - `gumjs_database_exec`: 允许 JavaScript 代码执行任意 SQL 语句，例如 `CREATE TABLE`, `INSERT`, `UPDATE`, `DELETE` 等，但不返回结果。

4. **准备 SQL 语句:**
   - `gumjs_database_prepare`: 允许 JavaScript 代码预编译一个带有占位符的 SQL 语句，以便后续绑定参数并执行。这有助于提高效率和防止 SQL 注入。

5. **转储数据库内容:**
   - `gumjs_database_dump`: 允许 JavaScript 代码获取整个数据库文件的内容（对于文件系统数据库）或者内存数据库的快照，以字符串形式返回。

6. **操作预编译语句:**
   - `gumjs_statement_bind_integer`, `gumjs_statement_bind_float`, `gumjs_statement_bind_text`, `gumjs_statement_bind_blob`, `gumjs_statement_bind_null`:  允许 JavaScript 代码为预编译的 SQL 语句绑定参数，支持整数、浮点数、文本、二进制数据（blob）和 NULL 值。
   - `gumjs_statement_step`: 允许 JavaScript 代码执行预编译的 SQL 查询语句，并逐行获取结果。
   - `gumjs_statement_reset`: 允许 JavaScript 代码重置预编译的 SQL 语句，以便可以重新绑定参数并执行。

**与逆向方法的关系及举例说明：**

Frida 本身就是一个动态 instrumentation 工具，常用于逆向工程。`gumquickdatabase.c` 提供的功能直接服务于逆向分析，因为它允许逆向工程师在运行时检查和操作目标应用程序的数据库。

* **举例说明：** 假设一个 Android 应用将其用户登录信息存储在 SQLite 数据库中。逆向工程师可以使用 Frida 脚本，通过 `gumjs_database_open` 打开该数据库，然后使用 `gumjs_database_exec` 执行 `SELECT username, password FROM users` 这样的 SQL 语句，从而在运行时获取用户的用户名和密码。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制底层:**
    - **`sqlite3*` 指针:**  代码中大量使用了 `sqlite3*` 和 `sqlite3_stmt*` 这样的指针，它们是 SQLite 库中表示数据库连接和预编译语句的底层数据结构。Frida 通过调用 SQLite 的 C API 来实现数据库操作。
    - **内存管理:** 代码中使用了 `g_slice_new`, `g_free`, `g_strdup` 等 GLib 库的内存管理函数，这在底层的 C 开发中很常见。
    - **数据类型转换:**  在绑定参数和解析结果时，需要在 JavaScript 的数据类型和 SQLite 的数据类型之间进行转换（例如，JavaScript 的 Number 对应 SQLite 的 INTEGER 或 REAL，JavaScript 的 String 对应 SQLite 的 TEXT）。

* **Linux:**
    - **文件系统路径:** `gumjs_database_open` 接受文件系统路径作为参数，这是 Linux 和 Android 中访问文件的基本方式。
    - **虚拟文件系统 (VFS):** 代码中使用了 `gum_memory_vfs_new` 和 `sqlite3_vfs_register`，这涉及到 SQLite 的 VFS 机制。VFS 允许 SQLite 使用不同的底层存储机制，例如，`gum_memory_vfs` 实现了内存中的文件系统，使得可以操作不实际存在于磁盘上的数据库。

* **Android 内核及框架:**
    - **目标进程上下文:** Frida 运行在目标进程的上下文中，因此它可以访问目标进程打开的数据库文件。在 Android 中，应用程序的私有数据通常存储在 `/data/data/<package_name>/databases/` 目录下。
    - **Hooking 和 Instrumentation:** 虽然这个文件本身不是 Frida 的 hook 代码，但它是 Frida 功能的一部分。Frida 通过在目标进程中注入代码来实现 hook 和 instrumentation，从而使得 JavaScript 代码可以调用 `gumjs_database_open` 等函数来访问目标进程的资源。

**逻辑推理及假设输入与输出：**

* **假设输入：**
    - JavaScript 代码调用 `SqliteDatabase._open("/data/data/com.example.app/databases/mydb.db", 0)`。
    - 目标进程存在该路径的数据库文件，并且有读取权限。
* **逻辑推理：**
    - `gumjs_database_open` 函数会被调用。
    - 它会调用底层的 `sqlite3_open_v2` 函数尝试打开该文件。
* **输出：**
    - **成功：** 如果数据库成功打开，`gumjs_database_open` 将返回一个新的 `SqliteDatabase` 对象的 JavaScript 包装器。
    - **失败：** 如果打开失败（例如，文件不存在或权限不足），`sqlite3_open_v2` 会返回错误代码，`gumjs_database_open` 会抛出一个包含 SQLite 错误信息的 JavaScript 异常。

* **假设输入：**
    - 已打开一个数据库对象 `db`。
    - JavaScript 代码调用 `db.prepare("SELECT name FROM users WHERE id = ?")`。
* **逻辑推理：**
    - `gumjs_database_prepare` 函数会被调用。
    - 它会调用底层的 `sqlite3_prepare_v2` 函数预编译 SQL 语句。
* **输出：**
    - **成功：** 如果 SQL 语句语法正确，`gumjs_database_prepare` 将返回一个新的 `SqliteStatement` 对象的 JavaScript 包装器。
    - **失败：** 如果 SQL 语句语法错误，`sqlite3_prepare_v2` 会返回错误代码，`gumjs_database_prepare` 会抛出一个包含 SQLite 错误信息的 JavaScript 异常。

**涉及用户或编程常见的使用错误及举例说明：**

1. **忘记关闭数据库连接:** 用户在完成数据库操作后，如果没有调用 `database.close()`，可能会导致资源泄漏，尤其是在长时间运行的 Frida 脚本中。

   ```javascript
   // 错误示例
   const db = SqliteDatabase._open("/path/to/db.db", 0);
   // ... 进行数据库操作 ...
   // 忘记调用 db.close();
   ```

2. **SQL 注入风险:** 虽然预编译语句可以防止 SQL 注入，但如果用户直接使用 `database.exec()` 并拼接用户输入到 SQL 语句中，仍然存在 SQL 注入的风险。

   ```javascript
   // 错误示例 (存在 SQL 注入风险)
   const tableName = "users"; // 假设这是用户可控的输入
   db.exec(`SELECT * FROM ${tableName}`);
   ```

3. **参数绑定错误:** 在使用预编译语句时，如果绑定的参数类型或数量与 SQL 语句中的占位符不匹配，会导致错误。

   ```javascript
   // 错误示例
   const stmt = db.prepare("SELECT name FROM users WHERE id = ? AND email = ?");
   stmt.bindInteger(1, 123); // 只绑定了一个参数
   stmt.step(); // 这将导致错误
   ```

4. **操作已关闭的数据库或语句:** 用户尝试在数据库或语句对象被关闭后继续操作，会导致错误。

   ```javascript
   const db = SqliteDatabase._open("/path/to/db.db", 0);
   db.close();
   db.exec("SELECT ..."); // 错误：数据库已关闭

   const stmt = db.prepare("SELECT ...");
   stmt.finalize(); // 假设存在 finalize 方法，实际是语句对象被垃圾回收
   stmt.step(); // 错误：语句已无效
   ```

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本，该脚本的目标是与目标进程的 SQLite 数据库进行交互。

2. **获取 `SqliteDatabase` 类:**  在 JavaScript 脚本中，用户会通过 Frida 提供的 API 获取到 `SqliteDatabase` 类。这通常是通过访问 Frida 的模块命名空间来实现的，例如 `Database` 模块导出了 `SqliteDatabase` 类。

   ```javascript
   // 假设 Database 模块导出了 SqliteDatabase
   const SqliteDatabase = Database.SqliteDatabase;
   ```

3. **打开数据库:** 用户会调用 `SqliteDatabase._open()` 或 `SqliteDatabase.openInline()` 来打开目标进程的数据库。这会触发 `gumjs_database_open` 或 `gumjs_database_open_inline` 函数的执行。

   ```javascript
   const db = SqliteDatabase._open("/data/data/com.example.app/databases/mydb.db", 0);
   ```

4. **执行 SQL 操作:**  用户可能会调用 `db.exec()`, `db.prepare()` 等方法来执行 SQL 操作。如果调用了 `db.prepare()`, 还会涉及到创建 `SqliteStatement` 对象，并调用其 `bind...()` 和 `step()` 方法。

   ```javascript
   db.exec("INSERT INTO ...");
   const stmt = db.prepare("SELECT ...");
   stmt.bindInteger(1, 1);
   const row = stmt.step();
   ```

5. **遇到错误或需要深入了解:** 如果在执行脚本过程中遇到与数据库相关的错误，或者用户需要深入了解 Frida 是如何与数据库交互的，他们可能会查看 Frida 的源代码，包括 `gumquickdatabase.c` 这个文件。

6. **调试线索:**
   - **异常堆栈:** 当 JavaScript 代码调用数据库操作时发生错误，Frida 会抛出 JavaScript 异常，其堆栈信息可能会指向 `gumquickdatabase.c` 中的某个函数。
   - **Frida 日志:**  Frida 内部可能会有日志输出，指示数据库操作的执行情况。
   - **源码审查:** 为了理解特定数据库操作的实现细节（例如，`openInline` 是如何处理内存数据库的），用户可能会直接查看 `gumquickdatabase.c` 的源代码。
   - **动态调试:** 更高级的用户可能会使用 GDB 等调试器attach到 Frida server 进程，并在 `gumquickdatabase.c` 中的函数设置断点，以跟踪代码执行流程，查看变量的值，从而进行更深入的调试。

总而言之，`gumquickdatabase.c` 是 Frida 提供数据库操作功能的关键组成部分，它通过 C 代码桥接了 JavaScript 环境和底层的 SQLite 库，使得逆向工程师可以使用 JavaScript 灵活地与目标进程的数据库进行交互。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickdatabase.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2020-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickdatabase.h"

#include "gumquickinterceptor.h"
#include "gumquickmacros.h"

typedef struct _GumDatabase GumDatabase;
typedef guint GumStorage;

struct _GumDatabase
{
  sqlite3 * handle;
  gchar * path;
  GumStorage storage;
  GumQuickDatabase * parent;
};

enum _GumStorage
{
  GUM_STORAGE_FILESYSTEM,
  GUM_STORAGE_MEMORY
};

GUMJS_DECLARE_FUNCTION (gumjs_database_open)
GUMJS_DECLARE_FUNCTION (gumjs_database_open_inline)

static gboolean gum_database_get_unchecked (JSContext * ctx, JSValueConst val,
    GumQuickCore * core, GumDatabase ** database);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_database_construct)
GUMJS_DECLARE_FINALIZER (gumjs_database_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_database_close)
GUMJS_DECLARE_FUNCTION (gumjs_database_exec)
GUMJS_DECLARE_FUNCTION (gumjs_database_prepare)
GUMJS_DECLARE_FUNCTION (gumjs_database_dump)

static JSValue gum_database_new (JSContext * ctx, sqlite3 * handle,
    const gchar * path, GumStorage storage, GumQuickDatabase * parent);
static void gum_database_free (GumDatabase * self);
static void gum_database_close (GumDatabase * self);

GUMJS_DECLARE_FINALIZER (gumjs_statement_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_integer)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_float)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_text)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_blob)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_null)
GUMJS_DECLARE_FUNCTION (gumjs_statement_step)
GUMJS_DECLARE_FUNCTION (gumjs_statement_reset)

static JSValue gum_statement_new (JSContext * ctx, sqlite3_stmt * handle,
    GumQuickDatabase * parent);

static JSValue gum_parse_row (JSContext * ctx, sqlite3_stmt * statement);
static JSValue gum_parse_column (JSContext * ctx, sqlite3_stmt * statement,
    guint index);

static const JSClassDef gumjs_database_def =
{
  .class_name = "SqliteDatabase",
  .finalizer = gumjs_database_finalize,
};

static const JSCFunctionListEntry gumjs_database_module_entries[] =
{
  JS_CFUNC_DEF ("_open", 0, gumjs_database_open),
  JS_CFUNC_DEF ("openInline", 0, gumjs_database_open_inline),
};

static const JSCFunctionListEntry gumjs_database_entries[] =
{
  JS_CFUNC_DEF ("close", 0, gumjs_database_close),
  JS_CFUNC_DEF ("exec", 0, gumjs_database_exec),
  JS_CFUNC_DEF ("prepare", 0, gumjs_database_prepare),
  JS_CFUNC_DEF ("dump", 0, gumjs_database_dump),
};

static const JSClassDef gumjs_statement_def =
{
  .class_name = "SqliteStatement",
  .finalizer = gumjs_statement_finalize,
};

static const JSCFunctionListEntry gumjs_statement_entries[] =
{
  JS_CFUNC_DEF ("bindInteger", 0, gumjs_statement_bind_integer),
  JS_CFUNC_DEF ("bindFloat", 0, gumjs_statement_bind_float),
  JS_CFUNC_DEF ("bindText", 0, gumjs_statement_bind_text),
  JS_CFUNC_DEF ("bindBlob", 0, gumjs_statement_bind_blob),
  JS_CFUNC_DEF ("bindNull", 0, gumjs_statement_bind_null),
  JS_CFUNC_DEF ("step", 0, gumjs_statement_step),
  JS_CFUNC_DEF ("reset", 0, gumjs_statement_reset),
};

void
_gum_quick_database_init (GumQuickDatabase * self,
                          JSValue ns,
                          GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "database", self);

  _gum_quick_create_class (ctx, &gumjs_database_def, core,
      &self->database_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_database_construct,
      gumjs_database_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_database_module_entries,
      G_N_ELEMENTS (gumjs_database_module_entries));
  JS_SetPropertyFunctionList (ctx, proto, gumjs_database_entries,
      G_N_ELEMENTS (gumjs_database_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_database_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_statement_def, core,
      &self->statement_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_statement_entries,
      G_N_ELEMENTS (gumjs_statement_entries));

  self->memory_vfs = gum_memory_vfs_new ();
  sqlite3_vfs_register (&self->memory_vfs->vfs, FALSE);
}

void
_gum_quick_database_dispose (GumQuickDatabase * self)
{
}

void
_gum_quick_database_finalize (GumQuickDatabase * self)
{
  sqlite3_vfs_unregister (&self->memory_vfs->vfs);
  gum_memory_vfs_free (self->memory_vfs);
}

static GumQuickDatabase *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "database");
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open)
{
  GumQuickDatabase * self;
  const gchar * path;
  gint flags;
  sqlite3 * handle;
  gint status;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "si", &path, &flags))
    return JS_EXCEPTION;

  handle = NULL;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_open_v2 (path, &handle, flags, NULL);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    goto invalid_database;

  return gum_database_new (ctx, handle, path, GUM_STORAGE_FILESYSTEM, self);

invalid_database:
  {
    GUMJS_INTERCEPTOR_IGNORE ();

    sqlite3_close_v2 (handle);

    GUMJS_INTERCEPTOR_UNIGNORE ();

    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open_inline)
{
  GumQuickDatabase * self;
  const gchar * encoded_contents;
  gpointer contents;
  gsize size;
  gboolean valid;
  const gchar * path;
  sqlite3 * handle;
  gint status;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "s", &encoded_contents))
    return JS_EXCEPTION;

  valid =
      gum_memory_vfs_contents_from_string (encoded_contents, &contents, &size);
  if (!valid)
    goto invalid_data;

  path = gum_memory_vfs_add_file (self->memory_vfs, contents, size);

  handle = NULL;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_open_v2 (path, &handle, SQLITE_OPEN_READWRITE,
      self->memory_vfs->name);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    goto invalid_database;

  return gum_database_new (ctx, handle, path, GUM_STORAGE_MEMORY, self);

invalid_data:
  {
    return _gum_quick_throw_literal (ctx, "invalid data");
  }
invalid_database:
  {
    GUMJS_INTERCEPTOR_IGNORE ();

    sqlite3_close_v2 (handle);

    GUMJS_INTERCEPTOR_UNIGNORE ();

    gum_memory_vfs_remove_file (self->memory_vfs, path);

    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));
  }
}

static gboolean
gum_database_get (JSContext * ctx,
                  JSValueConst val,
                  GumQuickCore * core,
                  GumDatabase ** database)
{
  GumDatabase * db;

  if (!gum_database_get_unchecked (ctx, val, core, &db))
    return FALSE;

  if (db->handle == NULL)
  {
    _gum_quick_throw_literal (ctx, "database is closed");
    return FALSE;
  }

  *database = db;
  return TRUE;
}

static gboolean
gum_database_get_unchecked (JSContext * ctx,
                            JSValueConst val,
                            GumQuickCore * core,
                            GumDatabase ** database)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->database_class, core,
      (gpointer *) database);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_database_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FINALIZER (gumjs_database_finalize)
{
  GumDatabase * db;

  db = JS_GetOpaque (val, gumjs_get_parent_module (core)->database_class);
  if (db == NULL)
    return;

  GUMJS_INTERCEPTOR_IGNORE ();

  gum_database_free (db);

  GUMJS_INTERCEPTOR_UNIGNORE ();
}

GUMJS_DEFINE_FUNCTION (gumjs_database_close)
{
  GumDatabase * self;

  if (!gum_database_get_unchecked (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  gum_database_close (self);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_database_exec)
{
  GumDatabase * self;
  const gchar * sql;
  gchar * error_message;
  gint status;

  if (!gum_database_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "s", &sql))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_exec (self->handle, sql, NULL, NULL, &error_message);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    goto error;

  return JS_UNDEFINED;

error:
  {
    _gum_quick_throw_literal (ctx, error_message);

    GUMJS_INTERCEPTOR_IGNORE ();

    sqlite3_free (error_message);

    GUMJS_INTERCEPTOR_UNIGNORE ();

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_prepare)
{
  GumDatabase * self;
  const gchar * sql;
  sqlite3_stmt * statement;
  gint status;

  if (!gum_database_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "s", &sql))
    return JS_EXCEPTION;

  statement = NULL;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_prepare_v2 (self->handle, sql, -1, &statement, NULL);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (statement == NULL)
    goto invalid_sql;

  return gum_statement_new (ctx, statement, gumjs_get_parent_module (core));

invalid_sql:
  {
    if (status == SQLITE_OK)
      _gum_quick_throw_literal (ctx, "invalid statement");
    else
      _gum_quick_throw_literal (ctx, sqlite3_errstr (status));
    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_dump)
{
  JSValue result;
  GumDatabase * self;
  gpointer data, malloc_data;
  gsize size;
  GError * error;
  gchar * data_str;

  if (!gum_database_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (self->storage == GUM_STORAGE_MEMORY)
  {
    gum_memory_vfs_get_file_contents (self->parent->memory_vfs, self->path,
        &data, &size);

    malloc_data = NULL;
  }
  else
  {
    error = NULL;
    if (!g_file_get_contents (self->path, (gchar **) &data, &size, &error))
      return _gum_quick_throw_error (ctx, &error);

    malloc_data = data;
  }

  data_str = gum_memory_vfs_contents_to_string (data, size);

  result = JS_NewString (ctx, data_str);

  g_free (data_str);
  g_free (malloc_data);

  return result;
}

static JSValue
gum_database_new (JSContext * ctx,
                  sqlite3 * handle,
                  const gchar * path,
                  GumStorage storage,
                  GumQuickDatabase * parent)
{
  JSValue wrapper;
  GumDatabase * db;

  wrapper = JS_NewObjectClass (ctx, parent->database_class);

  db = g_slice_new (GumDatabase);
  db->handle = handle;
  db->path = g_strdup (path);
  db->storage = storage;
  db->parent = parent;

  JS_SetOpaque (wrapper, db);

  return wrapper;
}

static void
gum_database_free (GumDatabase * self)
{
  gum_database_close (self);

  g_free (self->path);

  g_slice_free (GumDatabase, self);
}

static void
gum_database_close (GumDatabase * self)
{
  if (self->handle == NULL)
    return;

  sqlite3_close_v2 (self->handle);
  self->handle = NULL;

  if (self->storage == GUM_STORAGE_MEMORY)
    gum_memory_vfs_remove_file (self->parent->memory_vfs, self->path);
}

static gboolean
gum_statement_get (JSContext * ctx,
                   JSValueConst val,
                   GumQuickCore * core,
                   sqlite3_stmt ** statement)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->statement_class, core,
      (gpointer *) statement);
}

GUMJS_DEFINE_FINALIZER (gumjs_statement_finalize)
{
  sqlite3_stmt * s;

  s = JS_GetOpaque (val, gumjs_get_parent_module (core)->statement_class);
  if (s == NULL)
    return;

  GUMJS_INTERCEPTOR_IGNORE ();

  sqlite3_finalize (s);

  GUMJS_INTERCEPTOR_UNIGNORE ();
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_integer)
{
  sqlite3_stmt * self;
  gint index, value, status;

  if (!gum_statement_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "ii", &index, &value))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_bind_int64 (self, index, value);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_float)
{
  sqlite3_stmt * self;
  gint index;
  gdouble value;
  gint status;

  if (!gum_statement_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "in", &index, &value))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_bind_double (self, index, value);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_text)
{
  sqlite3_stmt * self;
  gint index;
  const gchar * value;
  gint status;

  if (!gum_statement_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "is", &index, &value))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_bind_text (self, index, value, -1, SQLITE_TRANSIENT);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_blob)
{
  sqlite3_stmt * self;
  gint index;
  GBytes * bytes;
  gpointer data;
  gsize size;
  gint status;

  if (!gum_statement_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "iB~", &index, &bytes))
    return JS_EXCEPTION;

  data = g_bytes_unref_to_data (_gum_quick_args_steal_bytes (args, bytes),
      &size);

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_bind_blob64 (self, index, data, size, g_free);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_null)
{
  sqlite3_stmt * self;
  gint index, status;

  if (!gum_statement_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "i", &index))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_bind_null (self, index);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_step)
{
  sqlite3_stmt * self;
  gint status;

  if (!gum_statement_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_step (self);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  switch (status)
  {
    case SQLITE_ROW:
      return gum_parse_row (ctx, self);
    case SQLITE_DONE:
      return JS_NULL;
    default:
      return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_reset)
{
  sqlite3_stmt * self;
  gint status;

  if (!gum_statement_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  status = sqlite3_reset (self);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (status != SQLITE_OK)
    return _gum_quick_throw_literal (ctx, sqlite3_errstr (status));

  return JS_UNDEFINED;
}

static JSValue
gum_statement_new (JSContext * ctx,
                   sqlite3_stmt * handle,
                   GumQuickDatabase * parent)
{
  JSValue wrapper = JS_NewObjectClass (ctx, parent->statement_class);

  JS_SetOpaque (wrapper, handle);

  return wrapper;
}

static JSValue
gum_parse_row (JSContext * ctx,
               sqlite3_stmt * statement)
{
  JSValue row;
  gint num_columns, i;

  row = JS_NewArray (ctx);

  num_columns = sqlite3_column_count (statement);

  for (i = 0; i != num_columns; i++)
  {
    JS_DefinePropertyValueUint32 (ctx, row, i,
        gum_parse_column (ctx, statement, i),
        JS_PROP_C_W_E);
  }

  return row;
}

static JSValue
gum_parse_column (JSContext * ctx,
                  sqlite3_stmt * statement,
                  guint index)
{
  switch (sqlite3_column_type (statement, index))
  {
    case SQLITE_INTEGER:
      return JS_NewInt64 (ctx, sqlite3_column_int64 (statement, index));
    case SQLITE_FLOAT:
      return JS_NewFloat64 (ctx, sqlite3_column_double (statement, index));
    case SQLITE_TEXT:
      return JS_NewString (ctx,
          (const char *) sqlite3_column_text (statement, index));
    case SQLITE_BLOB:
      return JS_NewArrayBufferCopy (ctx, sqlite3_column_blob (statement, index),
          sqlite3_column_bytes (statement, index));
    case SQLITE_NULL:
      return JS_NULL;
    default:
      g_assert_not_reached ();
  }
}
```