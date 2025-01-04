Response:
Let's break down the thought process for analyzing this C++ code for Frida.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the `gumv8database.cpp` file within the Frida framework, relating it to reverse engineering, low-level concepts, potential user errors, and how a user might reach this code.

**2. Initial Scan and Keyword Recognition:**

The first step is a quick scan for recognizable keywords and patterns. Keywords like `sqlite3`, `database`, `statement`, `bind`, `step`, `exec`, `open`, `close`, `v8`, `Gum`, and `GUMJS_DEFINE_FUNCTION` immediately jump out. These provide a high-level overview: this file deals with integrating SQLite database functionality into the Frida environment using the V8 JavaScript engine.

**3. Deconstructing the Code by Sections:**

The code is structured logically. I'd analyze it section by section:

* **Includes and Defines:** These tell us about dependencies (`gumv8macros.h`, `gumv8scope.h`) and set a module name (`Database`).

* **Struct Definitions (`GumDatabase`, `GumStatement`):** These define the internal representation of database and statement objects within the C++ code. Crucially, they hold pointers to the actual SQLite handles (`sqlite3 *`, `sqlite3_stmt *`) and the V8 wrapper objects. This highlights the bridge between C++ and JavaScript.

* **Function Declarations (`GUMJS_DECLARE_FUNCTION`):** These declare the functions that will be exposed to JavaScript. The naming convention (`gumjs_database_*`, `gumjs_statement_*`) is a strong indicator of their purpose.

* **Static Helper Functions (`gum_database_new`, `gum_database_free`, etc.):** These are internal C++ functions used to manage the lifecycle and operations of the database and statement objects. The `_on_weak_notify` functions are a hint about garbage collection and resource management in V8.

* **Function Tables (`gumjs_database_module_functions`, `gumjs_database_functions`, `gumjs_statement_functions`):**  These explicitly map the C++ functions to the JavaScript names they will be accessible by (e.g., `gumjs_database_open` becomes `_open` in JavaScript).

* **Initialization, Realization, Disposal, and Finalization (`_gum_v8_database_init`, `_gum_v8_database_realize`, etc.):** These are standard patterns for managing the lifecycle of a module or component. The `memory_vfs` part is interesting, suggesting in-memory database capabilities.

* **`GUMJS_DEFINE_FUNCTION` Blocks:**  These are the implementations of the JavaScript-exposed functions. This is where the core logic resides. I would analyze each function individually, focusing on:
    * **Input Arguments:** What data does the function expect from JavaScript?
    * **Core Logic:** What SQLite API calls are being made?
    * **Error Handling:** How are errors from SQLite handled and propagated back to JavaScript?
    * **Return Values:** What data is returned to JavaScript?

* **Static Helper Implementations:** Analyzing the implementations of the internal C++ functions to understand how the `GumDatabase` and `GumStatement` structs are managed. The weak callbacks are important for memory management.

* **`gum_parse_row` and `gum_parse_column`:** These functions are responsible for converting data retrieved from SQLite into JavaScript-compatible data types.

**3. Relating to the Prompts:**

As I analyzed the code, I'd actively think about how it relates to the specific questions in the prompt:

* **Functionality:**  This becomes clear as I analyze the `GUMJS_DEFINE_FUNCTION` blocks.

* **Reverse Engineering:**  Think about how Frida is used in reverse engineering. The ability to interact with databases inside a target process is a powerful tool for analyzing application behavior, data storage, and potentially hidden functionalities.

* **Binary/Low-Level:**  The interaction with SQLite's C API, memory management (especially the virtual file system), and the integration with the V8 engine all touch on lower-level concepts.

* **Linux/Android Kernel/Framework:** While the core logic is about SQLite, the context of Frida running on Linux/Android and interacting with application processes brings in those elements. The virtual file system is a good example of an abstraction that might be relevant in constrained environments.

* **Logic and Assumptions:**  For each function, consider the expected inputs and outputs. For example, `gumjs_database_open` expects a file path and flags and returns a database object. What happens if the path is invalid? What if the flags are incorrect?

* **User Errors:**  Think about common mistakes a user might make when interacting with these functions from JavaScript. Incorrect argument types, trying to operate on a closed database/statement, and SQL syntax errors are prime candidates.

* **User Path:**  Trace back how a user would use the Frida API to reach these C++ functions. They would likely use the `Database` object in their JavaScript code and call methods like `open`, `exec`, `prepare`, etc.

**4. Structuring the Answer:**

Finally, I would organize the findings into a clear and structured answer, addressing each point in the prompt with specific examples from the code. I'd use headings and bullet points to improve readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just about SQLite."
* **Correction:** "While SQLite is central, the V8 integration and the `Gum` framework are equally important. I need to explain *how* Frida makes SQLite accessible from JavaScript."

* **Initial thought:** "Just list the functions."
* **Correction:** "I need to explain the *purpose* of each function and how they relate to database operations."

* **Initial thought:** "Focus only on the happy path."
* **Correction:** "I must consider error handling and potential user mistakes, as that's a key aspect of robust software."

By following this systematic approach, combining code analysis with an understanding of the prompt's requirements, I can generate a comprehensive and informative answer.
This C++ file, `gumv8database.cpp`, is a part of the Frida dynamic instrumentation toolkit. Its primary function is to provide a way for Frida scripts (written in JavaScript and executed within the target process's V8 engine) to interact with SQLite databases.

Here's a breakdown of its functionalities:

**Core Functionality: Bridging JavaScript and SQLite**

The file essentially acts as a bridge between the JavaScript environment provided by Frida's GumJS and the native SQLite library. It allows Frida users to:

1. **Open SQLite Databases:**
   - `gumjs_database_open`: Opens an existing SQLite database file on the file system.
   - `gumjs_database_open_inline`:  Opens an in-memory SQLite database from a base64 encoded string representation of the database file. This is useful for embedding databases or working with them without relying on the file system.

2. **Close SQLite Databases:**
   - `gumjs_database_close`: Closes an open SQLite database connection, releasing resources.

3. **Execute SQL Statements Directly:**
   - `gumjs_database_exec`: Executes a non-query SQL statement (like `CREATE TABLE`, `INSERT`, `UPDATE`, `DELETE`) directly.

4. **Prepare SQL Statements for Execution:**
   - `gumjs_database_prepare`: Prepares an SQL statement for later execution. This is crucial for parameterized queries and efficient execution of the same query multiple times. It returns a `SqliteStatement` object.

5. **Dump Database Contents:**
   - `gumjs_database_dump`: Reads the entire content of the SQLite database file (or in-memory representation) and returns it as a string.

6. **Work with Prepared Statements:**
   - **Binding Parameters:** The following functions allow binding values to parameters in a prepared statement:
     - `gumjs_statement_bind_integer`: Binds an integer value.
     - `gumjs_statement_bind_float`: Binds a floating-point value.
     - `gumjs_statement_bind_text`: Binds a text (string) value.
     - `gumjs_statement_bind_blob`: Binds binary data (blob).
     - `gumjs_statement_bind_null`: Binds a NULL value.
   - **Executing Statements:**
     - `gumjs_statement_step`: Executes a prepared statement and retrieves the next row of results (if any).
   - **Resetting Statements:**
     - `gumjs_statement_reset`: Resets a prepared statement, allowing it to be executed again with potentially different parameters.

**Relationship with Reverse Engineering:**

This file is highly relevant to reverse engineering as it provides a powerful mechanism to interact with application-local databases. Here are some examples:

* **Analyzing Data Storage:** Reverse engineers can use these functions to inspect how an application stores its data. They can open the application's database and query tables to understand data structures, relationships, and sensitive information.
    * **Example:** An Android application might store user credentials or configuration settings in an SQLite database. A Frida script could use `Database.open()` to connect to this database and then use `db.exec("SELECT username, password FROM users")` to retrieve the stored credentials.

* **Modifying Application Behavior:** By interacting with the database, reverse engineers can potentially modify application behavior. For example, they could change configuration values, bypass authentication checks, or manipulate game states.
    * **Example:** In a game, high scores might be stored in a database. A Frida script could use `db.exec("UPDATE highscores SET score = 99999 WHERE player = 'current_user'")` to cheat and set a high score.

* **Intercepting Database Interactions:** While this specific file doesn't directly provide interception capabilities, the ability to access and manipulate the database enables more advanced reverse engineering techniques. For example, one could hook database access functions and log the queries being executed by the application to understand its internal logic.

**Involvement of Binary, Linux/Android Kernel & Framework Knowledge:**

* **Binary Level:** The code interacts directly with the SQLite C library (`sqlite3.h`), which is a compiled binary. It manages pointers to `sqlite3` database handles and `sqlite3_stmt` statement handles. The binding of different data types (integer, float, text, blob) involves understanding how these data types are represented at the binary level and how to pass them correctly to the SQLite API.
* **Linux/Android:**
    * **File System Access:** `gumjs_database_open` directly interacts with the underlying file system to open database files. This relies on operating system APIs.
    * **In-Memory Databases:** The `gumjs_database_open_inline` function uses a custom in-memory virtual file system (`gum_memory_vfs`). This demonstrates an understanding of how to abstract file system operations, which can be relevant in environments like Android where direct file system access might be restricted or where self-contained execution is desired.
    * **Memory Management:** The code uses `g_slice_new` and `g_slice_free` (from GLib) for memory allocation and deallocation, which are common in Linux/Android development. It also carefully manages the lifetime of SQLite handles to avoid memory leaks.
    * **V8 Integration:** The entire file is built on top of the V8 JavaScript engine, which is used extensively in environments like Chrome and Node.js, and also forms the basis of Frida's scripting environment. Understanding how to bridge native C++ code with V8's object model is crucial here.

**Logical Reasoning and Assumptions (Hypothetical Examples):**

Let's consider the `gumjs_statement_step` function:

* **Hypothetical Input:** A `SqliteStatement` object representing a prepared statement for `SELECT name, age FROM users WHERE city = ?`. The user has previously bound the string "London" to the parameter.
* **Assumption:** The database contains a table named `users` with columns `name`, `age`, and `city`.
* **Possible Outputs:**
    * **Success (SQLITE_ROW):** If there are rows in the `users` table where the `city` is "London", the function will return a JavaScript array containing the `name` and `age` for the first matching row. Subsequent calls to `step` would return further rows until no more matches are found.
    * **No More Rows (SQLITE_DONE):** If there are no more matching rows, the function will return `null`.
    * **Error (Other SQLITE_* codes):** If there's an error during execution (e.g., database is closed, statement is invalid), the function will throw a JavaScript exception containing the SQLite error message.

**Common User/Programming Errors:**

* **Incorrect Argument Types:** Passing the wrong type of argument to the binding functions (e.g., passing a string to `bindInteger`). Frida's argument parsing (`_gum_v8_args_parse`) helps catch some of these errors.
    * **Example:** `statement.bindInteger("1", 123);`  The first argument should be the parameter index (an integer), not a string.
* **Binding to Non-Existent Parameters:** Trying to bind a value to an index that doesn't correspond to a parameter in the prepared statement.
    * **Example:** If the SQL is `SELECT * FROM users WHERE id = ?`, and the user calls `statement.bindInteger(2, 5);`, this will likely cause an error because there's only one parameter (at index 1).
* **Operating on Closed Databases or Statements:** Trying to execute a statement or perform operations on a database that has already been closed.
    * **Example:**
    ```javascript
    var db = Database.open('/path/to/mydb.db');
    db.close();
    db.exec("SELECT * FROM users"); // Error: database is closed
    ```
* **SQL Syntax Errors:** Providing invalid SQL to `prepare` or `exec`. The SQLite error message will be propagated to the JavaScript side.
    * **Example:** `db.exec("SELEKT * FROM users");` (misspelled `SELECT`).
* **Resource Leaks (Less Common due to RAII):** While the C++ code tries to manage resources correctly using RAII principles (like the `Global` smart pointers and weak callbacks), improper usage in the JavaScript layer (e.g., not closing databases when finished) could potentially lead to resource leaks in the target process over time.

**User Operation Flow as a Debugging Clue:**

If you are debugging an issue related to database interaction in a Frida script, understanding the typical user flow can help pinpoint the problem:

1. **Opening the Database:** The user will first call either `Database.open()` or `Database.openInline()`. Errors here might indicate issues with file paths, permissions, or the integrity of the inline database data.
2. **Preparing Statements (Optional but Recommended):** For complex queries or repeated execution, users will call `db.prepare()`. Errors at this stage point to SQL syntax problems.
3. **Binding Parameters (If Using Prepared Statements):** Users will call `statement.bindInteger()`, `statement.bindText()`, etc. Errors here suggest issues with argument types or parameter indices.
4. **Executing Statements:** Users will call `statement.step()` for queries or `db.exec()` for non-query statements. Errors here can be due to runtime issues with the data or database state.
5. **Processing Results (For Queries):** After calling `step()`, the returned value (an array or `null`) needs to be handled correctly.
6. **Closing Resources:** Finally, users should call `db.close()` and potentially finalize statements if they are no longer needed.

By tracing the user's JavaScript code and understanding the corresponding C++ functions being called in `gumv8database.cpp`, you can effectively debug issues related to database interactions within a Frida environment. Looking at the arguments passed to these functions and the SQLite error messages returned can provide valuable clues.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8database.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2017-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8database.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#define GUMJS_MODULE_NAME Database

using namespace v8;

struct GumDatabase
{
  Global<Object> * wrapper;
  sqlite3 * handle;
  gchar * path;
  gboolean is_virtual;
  GumV8Database * module;
};

struct GumStatement
{
  Global<Object> * wrapper;
  sqlite3_stmt * handle;
  GumV8Database * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_database_open)
GUMJS_DECLARE_FUNCTION (gumjs_database_open_inline)

GUMJS_DECLARE_FUNCTION (gumjs_database_close)
GUMJS_DECLARE_FUNCTION (gumjs_database_exec)
GUMJS_DECLARE_FUNCTION (gumjs_database_prepare)
GUMJS_DECLARE_FUNCTION (gumjs_database_dump)

static Local<Object> gum_database_new (sqlite3 * handle, const gchar * path,
    gboolean is_virtual, GumV8Database * module);
static void gum_database_free (GumDatabase * self);
static void gum_database_close (GumDatabase * self);
static gboolean gum_database_check_open (GumDatabase * self, Isolate * isolate);
static void gum_database_on_weak_notify (
    const WeakCallbackInfo<GumDatabase> & info);

GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_integer)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_float)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_text)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_blob)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_null)
GUMJS_DECLARE_FUNCTION (gumjs_statement_step)
GUMJS_DECLARE_FUNCTION (gumjs_statement_reset)

static Local<Object> gum_statement_new (sqlite3_stmt * handle,
    GumV8Database * module);
static void gum_statement_free (GumStatement * self);
static void gum_statement_on_weak_notify (
    const WeakCallbackInfo<GumStatement> & info);

static Local<Array> gum_parse_row (Isolate * isolate, sqlite3_stmt * statement);
static Local<Value> gum_parse_column (Isolate * isolate,
    sqlite3_stmt * statement, guint index);

static const GumV8Function gumjs_database_module_functions[] =
{
  { "_open", gumjs_database_open },
  { "openInline", gumjs_database_open_inline },

  { NULL, NULL }
};

static const GumV8Function gumjs_database_functions[] =
{
  { "close", gumjs_database_close },
  { "exec", gumjs_database_exec },
  { "prepare", gumjs_database_prepare },
  { "dump", gumjs_database_dump },

  { NULL, NULL }
};

static const GumV8Function gumjs_statement_functions[] =
{
  { "bindInteger", gumjs_statement_bind_integer },
  { "bindFloat", gumjs_statement_bind_float },
  { "bindText", gumjs_statement_bind_text },
  { "bindBlob", gumjs_statement_bind_blob },
  { "bindNull", gumjs_statement_bind_null },
  { "step", gumjs_statement_step },
  { "reset", gumjs_statement_reset },

  { NULL, NULL }
};

void
_gum_v8_database_init (GumV8Database * self,
                       GumV8Core * core,
                       Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto database = _gum_v8_create_class ("SqliteDatabase", nullptr, scope,
      module, isolate);
  _gum_v8_class_add_static (database, gumjs_database_module_functions, module,
      isolate);
  _gum_v8_class_add (database, gumjs_database_functions, module, isolate);
  self->database = new Global<FunctionTemplate> (isolate, database);

  auto statement = _gum_v8_create_class ("SqliteStatement", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (statement, gumjs_statement_functions, module, isolate);
  self->statement = new Global<FunctionTemplate> (isolate, statement);

  self->memory_vfs = gum_memory_vfs_new ();
  sqlite3_vfs_register (&self->memory_vfs->vfs, FALSE);
}

void
_gum_v8_database_realize (GumV8Database * self)
{
  self->databases = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_database_free);
  self->statements = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_statement_free);
}

void
_gum_v8_database_dispose (GumV8Database * self)
{
  g_hash_table_unref (self->statements);
  self->statements = NULL;

  g_hash_table_unref (self->databases);
  self->databases = NULL;

  delete self->statement;
  self->statement = nullptr;

  delete self->database;
  self->database = nullptr;
}

void
_gum_v8_database_finalize (GumV8Database * self)
{
  sqlite3_vfs_unregister (&self->memory_vfs->vfs);
  gum_memory_vfs_free (self->memory_vfs);
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open)
{
  gchar * path;
  gint flags;
  sqlite3 * handle;
  gint status;
  Local<Object> object;

  if (!_gum_v8_args_parse (args, "si", &path, &flags))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  handle = NULL;
  status = sqlite3_open_v2 (path, &handle, flags, NULL);
  if (status != SQLITE_OK)
    goto invalid_database;

  object = gum_database_new (handle, path, FALSE, module);

  info.GetReturnValue ().Set (object);

  g_free (path);

  return;

invalid_database:
  {
    sqlite3_close_v2 (handle);
    g_free (path);
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
    return;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open_inline)
{
  gchar * encoded_contents;
  gpointer contents;
  gsize size;
  gboolean valid;
  const gchar * path;
  sqlite3 * handle;
  gint status;
  Local<Object> object;

  if (!_gum_v8_args_parse (args, "s", &encoded_contents))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  valid =
      gum_memory_vfs_contents_from_string (encoded_contents, &contents, &size);
  g_free (encoded_contents);
  if (!valid)
    goto invalid_data;

  path = gum_memory_vfs_add_file (module->memory_vfs, contents, size);

  handle = NULL;
  status = sqlite3_open_v2 (path, &handle, SQLITE_OPEN_READWRITE,
      module->memory_vfs->name);
  if (status != SQLITE_OK)
    goto invalid_database;

  object = gum_database_new (handle, path, TRUE, module);

  info.GetReturnValue ().Set (object);

  return;

invalid_data:
  {
    _gum_v8_throw (isolate, "invalid data");
    return;
  }
invalid_database:
  {
    sqlite3_close_v2 (handle);
    gum_memory_vfs_remove_file (module->memory_vfs, path);
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
    return;
  }
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_database_close, GumDatabase)
{
  gum_database_close (self);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_database_exec, GumDatabase)
{
  gchar * sql, * error_message;
  gint status;

  if (!gum_database_check_open (self, isolate))
    return;

  if (!_gum_v8_args_parse (args, "s", &sql))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  status = sqlite3_exec (self->handle, sql, NULL, NULL, &error_message);
  g_free (sql);
  if (status != SQLITE_OK)
    goto error;

  return;

error:
  {
    _gum_v8_throw (isolate, "%s", error_message);
    sqlite3_free (error_message);
    return;
  }
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_database_prepare, GumDatabase)
{
  gchar * sql;
  sqlite3_stmt * statement;
  gint status;
  Local<Object> object;

  if (!gum_database_check_open (self, isolate))
    return;

  if (!_gum_v8_args_parse (args, "s", &sql))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  statement = NULL;
  status = sqlite3_prepare_v2 (self->handle, sql, -1, &statement, NULL);
  g_free (sql);
  if (statement == NULL)
    goto invalid_sql;

  object = gum_statement_new (statement, module);

  info.GetReturnValue ().Set (object);

  return;

invalid_sql:
  {
    if (status == SQLITE_OK)
      _gum_v8_throw (isolate, "invalid statement");
    else
      _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
    return;
  }
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_database_dump, GumDatabase)
{
  gpointer data, malloc_data;
  gsize size;
  GError * error;
  gchar * data_str;

  if (!gum_database_check_open (self, isolate))
    return;

  if (self->is_virtual)
  {
    gboolean found;

    found = gum_memory_vfs_get_file_contents (module->memory_vfs, self->path,
        &data, &size);
    g_assert (found);

    malloc_data = NULL;
  }
  else
  {
    error = NULL;
    g_file_get_contents (self->path, (gchar **) &data, &size, &error);
    if (_gum_v8_maybe_throw (isolate, &error))
      return;

    malloc_data = data;
  }

  data_str = gum_memory_vfs_contents_to_string (data, size);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, data_str));

  g_free (data_str);
  g_free (malloc_data);
}

static Local<Object>
gum_database_new (sqlite3 * handle,
                  const gchar * path,
                  gboolean is_virtual,
                  GumV8Database * module)
{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto constructor = Local<FunctionTemplate>::New (isolate,
      *module->database);
  auto object = constructor->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();

  auto database = g_slice_new (GumDatabase);
  database->wrapper = new Global<Object> (isolate, object);
  database->wrapper->SetWeak (database, gum_database_on_weak_notify,
      WeakCallbackType::kParameter);
  database->handle = handle;
  database->path = g_strdup (path);
  database->is_virtual = is_virtual;
  database->module = module;

  object->SetAlignedPointerInInternalField (0, database);

  g_hash_table_add (module->databases, database);

  return object;
}

static void
gum_database_free (GumDatabase * self)
{
  gum_database_close (self);

  delete self->wrapper;

  g_slice_free (GumDatabase, self);
}

static void
gum_database_close (GumDatabase * self)
{
  if (self->handle == NULL)
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  sqlite3_close_v2 (self->handle);
  self->handle = NULL;

  if (self->is_virtual)
    gum_memory_vfs_remove_file (self->module->memory_vfs, self->path);

  g_free (self->path);
  self->path = NULL;
}

static gboolean
gum_database_check_open (GumDatabase * self,
                         Isolate * isolate)
{
  if (self->handle == NULL)
  {
    _gum_v8_throw (isolate, "database is closed");
    return FALSE;
  }

  return TRUE;
}

static void
gum_database_on_weak_notify (const WeakCallbackInfo<GumDatabase> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->databases, self);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_statement_bind_integer, GumStatement)
{
  gint index, value;
  if (!_gum_v8_args_parse (args, "ii", &index, &value))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto status = sqlite3_bind_int64 (self->handle, index, value);
  if (status != SQLITE_OK)
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_statement_bind_float, GumStatement)
{
  gint index;
  gdouble value;
  if (!_gum_v8_args_parse (args, "in", &index, &value))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto status = sqlite3_bind_double (self->handle, index, value);
  if (status != SQLITE_OK)
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_statement_bind_text, GumStatement)
{
  gint index;
  gchar * value;
  if (!_gum_v8_args_parse (args, "is", &index, &value))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto status = sqlite3_bind_text (self->handle, index, value, -1, g_free);
  if (status != SQLITE_OK)
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_statement_bind_blob, GumStatement)
{
  gint index;
  GBytes * bytes;
  if (!_gum_v8_args_parse (args, "iB~", &index, &bytes))
    return;

  gsize size;
  auto data = g_bytes_unref_to_data (bytes, &size);

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto status = sqlite3_bind_blob64 (self->handle, index, data, size, g_free);
  if (status != SQLITE_OK)
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_statement_bind_null, GumStatement)
{
  gint index;
  if (!_gum_v8_args_parse (args, "i", &index))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto status = sqlite3_bind_null (self->handle, index);
  if (status != SQLITE_OK)
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_statement_step, GumStatement)
{
  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto status = sqlite3_step (self->handle);
  switch (status)
  {
    case SQLITE_ROW:
      info.GetReturnValue ().Set (gum_parse_row (isolate, self->handle));
      break;
    case SQLITE_DONE:
      info.GetReturnValue ().SetNull ();
      break;
    default:
      _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
      break;
  }
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_statement_reset, GumStatement)
{
  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto status = sqlite3_reset (self->handle);
  if (status != SQLITE_OK)
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
}

static Local<Object>
gum_statement_new (sqlite3_stmt * handle,
                   GumV8Database * module)
{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto constructor = Local<FunctionTemplate>::New (isolate,
      *module->statement);
  auto object = constructor->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();

  auto statement = g_slice_new (GumStatement);
  statement->wrapper = new Global<Object> (isolate, object);
  statement->wrapper->SetWeak (statement, gum_statement_on_weak_notify,
      WeakCallbackType::kParameter);
  statement->handle = handle;
  statement->module = module;

  object->SetAlignedPointerInInternalField (0, statement);

  g_hash_table_add (module->statements, statement);

  return object;
}

static void
gum_statement_free (GumStatement * self)
{
  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  delete self->wrapper;

  sqlite3_finalize (self->handle);

  g_slice_free (GumStatement, self);
}

static void
gum_statement_on_weak_notify (const WeakCallbackInfo<GumStatement> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->statements, self);
}

static Local<Array>
gum_parse_row (Isolate * isolate,
               sqlite3_stmt * statement)
{
  auto context = isolate->GetCurrentContext ();

  auto num_columns = sqlite3_column_count (statement);
  auto row = Array::New (isolate, num_columns);

  for (gint index = 0; index != num_columns; index++)
  {
    auto column = gum_parse_column (isolate, statement, index);
    row->Set (context, index, column).Check ();
  }

  return row;
}

static Local<Value>
gum_parse_column (Isolate * isolate,
                  sqlite3_stmt * statement,
                  guint index)
{
  switch (sqlite3_column_type (statement, index))
  {
    case SQLITE_INTEGER:
      return Number::New (isolate, sqlite3_column_int64 (statement, index));
    case SQLITE_FLOAT:
      return Number::New (isolate, sqlite3_column_int64 (statement, index));
    case SQLITE_TEXT:
      return String::NewFromUtf8 (isolate,
          (const char *) sqlite3_column_text (statement, index),
          NewStringType::kNormal).ToLocalChecked ();
    case SQLITE_BLOB:
    {
      auto size = sqlite3_column_bytes (statement, index);
      auto data = g_memdup2 (sqlite3_column_blob (statement, index), size);
      return _gum_v8_array_buffer_new_take (isolate, data, size);
    }
    case SQLITE_NULL:
      return Null (isolate);
    default:
      g_assert_not_reached ();
  }

  return Local<Value> ();
}

"""

```