Response:
Let's break down the thought process for analyzing the `IDBDatabase.cc` file and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of this specific Chromium Blink engine file (`blink/renderer/modules/indexeddb/idb_database.cc`). This involves identifying its primary responsibilities, how it interacts with other components (especially JavaScript, HTML, CSS), potential user errors, and how a user's actions might lead to this code being executed.

**2. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code for keywords and patterns that provide clues about its purpose. Key terms jump out:

* `IDBDatabase`: This is the central entity the file deals with. It strongly suggests this file implements the core logic for an IndexedDB database object within the Blink rendering engine.
* `IndexedDB`:  The directory path itself (`modules/indexeddb`) confirms the file's role in the IndexedDB API.
* `mojom::blink::IDBDatabase`:  The presence of `mojom` indicates this file interacts with the Chromium IPC system. `mojom` files define interfaces for communication between processes.
* `createObjectStore`, `deleteObjectStore`, `transaction`, `close`: These are direct mappings to the JavaScript IndexedDB API methods.
* `versionchange`, `close` (events): These are important events in the IndexedDB lifecycle.
* `IDBTransaction`, `IDBObjectStore`, `IDBIndex`, `IDBCursor`: These are related IndexedDB API objects, suggesting this class manages or interacts with them.
* Error messages (constants like `kIndexDeletedErrorMessage`): These point to specific error conditions the code handles.
* `ExecutionContext`: This signifies the file's integration within the browser's execution environment.
* `ScriptState`:  Indicates interaction with JavaScript.
* `EventTarget`:  Highlights the file's ability to dispatch and handle events.

**3. Identifying Core Functionality:**

Based on the initial scan, we can deduce the core responsibilities of `IDBDatabase`:

* **Lifecycle Management:** Creating, opening, closing, and handling version changes of IndexedDB databases.
* **Transaction Management:** Creating and managing transactions on the database.
* **Object Store Management:** Creating, deleting, and renaming object stores.
* **Index Management:**  Creating, deleting, and renaming indexes (though the implementation details might be in other related files like `IDBObjectStore.cc` or separate index files).
* **Data Access Operations:** Providing an interface for getting, getting all, counting, deleting, and clearing data.
* **Communication with the Backend:**  Using `mojom` interfaces to communicate with the browser's backend process responsible for the actual storage and persistence of the data.
* **Event Handling:** Dispatching `versionchange` and `close` events.
* **Error Handling:** Managing and reporting errors.

**4. Mapping to JavaScript, HTML, and CSS:**

The connection to JavaScript is very direct. The methods in this C++ file are implementations of the JavaScript `IDBDatabase` API. The analysis needs to provide concrete examples:

* **JavaScript API Methods:**  Show how JavaScript code using `indexedDB.open()`, `db.createObjectStore()`, `db.transaction()`, etc., directly triggers the C++ methods in this file.
* **Events:** Explain how the `versionchange` and `close` events in JavaScript are dispatched by this C++ code.

The relationship with HTML and CSS is less direct but still important:

* **HTML:**  Explain that the JavaScript code interacting with IndexedDB is typically embedded within `<script>` tags in an HTML document.
* **CSS:** Note that while CSS doesn't directly interact with IndexedDB, the application's styling and visual presentation might depend on data fetched from IndexedDB.

**5. Logical Reasoning (Hypothetical Input/Output):**

This involves considering what happens when specific JavaScript actions are taken. Examples:

* **`createObjectStore("myStore")`:**  The input is the string "myStore". The output is the creation of an `IDBObjectStore` object in the C++ layer and the sending of a message to the backend to create the store.
* **`transaction(["myStore"], "readwrite").objectStore("myStore").add({ key: "value" })`:** This complex sequence triggers the creation of an `IDBTransaction` in C++, then an `IDBObjectStore`, and eventually a message to the backend to perform the "add" operation.

**6. Common User/Programming Errors:**

Based on the error messages and the functionality, identify common mistakes:

* **Incorrect transaction mode:** Trying to modify data in a `readonly` transaction.
* **Object store or index already exists:**  Trying to create an object store or index with a name that's already in use.
* **Transaction not active:** Trying to perform operations after a transaction has completed or aborted.
* **Database closed:**  Trying to interact with a database after it has been closed.
* **Version change errors:** Issues during database upgrades (e.g., not closing connections promptly in `versionchange` handlers).

**7. User Operation and Debugging Clues:**

Trace a user's actions that lead to this code being executed. This helps understand the context and how to debug issues:

* **Opening a website:**  The initial interaction with IndexedDB often starts when a website loads and its JavaScript code attempts to open or interact with a database.
* **Inspecting IndexedDB in DevTools:** Developers might be using the browser's developer tools to inspect the state of IndexedDB, which can trigger backend interactions and potentially surface issues handled by this code.
* **Error messages in the console:**  Errors reported by this C++ code will often appear in the browser's JavaScript console, providing clues for debugging.

**8. Structuring the Response:**

Organize the information logically into sections:

* **Functionality Summary:** A high-level overview of what the file does.
* **Relationship to JavaScript/HTML/CSS:** Clear explanations and examples.
* **Logical Reasoning:**  Illustrative input/output scenarios.
* **Common Errors:** Practical examples of mistakes.
* **User Operations and Debugging:** How users interact with this code and how to troubleshoot.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing too much on the specific code details might miss the broader context. Shift focus to the *purpose* of the code and its interactions with other parts of the system.
* **Realization:** The `mojom` interfaces are crucial. Emphasize the communication with the backend process.
* **Refinement:** Ensure the examples for JavaScript interaction are clear and directly relate to the C++ methods. Avoid vague statements.
* **Consideration:**  Think about the audience. The explanation should be understandable to someone familiar with web development concepts, even if they don't have deep knowledge of Chromium's internals.

By following these steps, iterating, and refining the analysis, we can generate a comprehensive and accurate understanding of the `IDBDatabase.cc` file's role and functionality.
好的，我们来分析一下 `blink/renderer/modules/indexeddb/idb_database.cc` 这个文件。

**文件功能概述**

`IDBDatabase.cc` 文件实现了 Chromium Blink 引擎中 `IDBDatabase` 接口的核心逻辑。`IDBDatabase` 接口代表一个 IndexedDB 数据库的连接。这个文件主要负责：

1. **数据库生命周期管理:**  处理数据库的打开、关闭。
2. **事务管理:**  创建、跟踪和管理数据库上的事务 (`IDBTransaction`)。
3. **对象存储管理:** 提供创建、删除对象存储 (`IDBObjectStore`) 的功能。
4. **版本控制:** 处理数据库的版本变更，触发 `versionchange` 事件。
5. **与 JavaScript 的桥梁:** 接收来自 JavaScript 的调用，并将其转换为底层的 IndexedDB 操作。
6. **与后端 IndexedDB 服务的通信:**  通过 Mojo 接口与浏览器进程中负责实际数据存储的 IndexedDB 服务进行通信。
7. **错误处理:**  处理各种 IndexedDB 操作中可能出现的错误。
8. **事件派发:**  负责派发 `versionchange` 和 `close` 等事件到 JavaScript。

**与 JavaScript, HTML, CSS 的关系**

`IDBDatabase.cc` 是 IndexedDB API 在 Blink 渲染引擎中的实现核心部分，因此与 JavaScript 的关系最为密切。

**JavaScript 交互举例：**

* **打开数据库:** 当 JavaScript 代码调用 `indexedDB.open('mydatabase', 2)` 时，会触发 Blink 引擎中相应的逻辑，最终会创建或获取一个 `IDBDatabase` 的实例，这个实例的实现就在 `IDBDatabase.cc` 中。

   ```javascript
   const request = indexedDB.open('mydatabase', 2);

   request.onsuccess = function(event) {
     const db = event.target.result; // `db` 就是一个 IDBDatabase 对象
     console.log("Database opened successfully");
   };
   ```

* **创建对象存储:** JavaScript 调用 `db.createObjectStore('myStore', { keyPath: 'id', autoIncrement: true })` 会调用 `IDBDatabase::createObjectStore` 方法。

   ```javascript
   request.onupgradeneeded = function(event) {
     const db = event.target.result;
     const store = db.createObjectStore('myStore', { keyPath: 'id', autoIncrement: true });
   };
   ```
   * **假设输入:** JavaScript 调用 `db.createObjectStore("users", { keyPath: "email" })`
   * **逻辑推理:** `IDBDatabase::createObjectStore` 方法会被调用，参数 `name` 为 "users"，`key_path` 为 "email"，`auto_increment` 为 false (默认)。该方法会检查版本变更事务是否正在进行，名称是否已存在，然后通过 Mojo 接口向后端发送创建对象存储的请求，并在内部维护对象存储的元数据。
   * **输出:** 如果一切顺利，数据库的元数据会更新，并且在 JavaScript 中可以通过事务访问新创建的对象存储。

* **启动事务:** JavaScript 调用 `db.transaction(['myStore'], 'readwrite')` 会调用 `IDBDatabase::transaction` 方法。

   ```javascript
   const transaction = db.transaction(['myStore'], 'readwrite');
   const store = transaction.objectStore('myStore');
   store.add({ id: 1, name: 'Alice' });
   ```
   * **假设输入:** JavaScript 调用 `db.transaction(["products"], "readonly")`
   * **逻辑推理:** `IDBDatabase::transaction` 方法会被调用，参数 `store_names` 包含 "products"，`mode` 为只读。该方法会检查数据库是否已关闭，版本变更事务是否正在进行，然后通过 Mojo 接口向后端请求创建一个只读事务，并在内部创建并返回一个 `IDBTransaction` 对象。
   * **输出:**  如果 "products" 对象存储存在，JavaScript 代码可以通过返回的 `IDBTransaction` 对象访问并读取 "products" 对象存储的数据。

* **关闭数据库:** JavaScript 调用 `db.close()` 会调用 `IDBDatabase::close` 方法。

   ```javascript
   db.close();
   ```

* **版本变更事件:** 当尝试打开一个更高版本的数据库时，`onupgradeneeded` 事件会触发，这与 `IDBDatabase::VersionChange` 方法的调用有关。

   ```javascript
   const request = indexedDB.open('mydatabase', 3);
   request.onupgradeneeded = function(event) {
     // ... 执行数据库升级操作
   };
   ```

**与 HTML 和 CSS 的关系：**

HTML 和 CSS 本身不直接与 `IDBDatabase.cc` 交互。但是，嵌入在 HTML 中的 `<script>` 标签内的 JavaScript 代码会使用 IndexedDB API，从而间接地触发 `IDBDatabase.cc` 中的逻辑。例如，一个网页的 JavaScript 代码可以使用 IndexedDB 来存储用户的离线数据或应用状态。

**用户或编程常见的使用错误及示例**

1. **在只读事务中尝试修改数据:**

   ```javascript
   const tx = db.transaction(['myStore'], 'readonly');
   const store = tx.objectStore('myStore');
   store.add({ id: 1, name: 'Bob' }); // 错误！
   ```
   * **假设输入:**  上述 JavaScript 代码在一个已经成功打开的数据库上执行。
   * **逻辑推理:** `store.add()` 操作会尝试修改数据，但由于事务是只读的，后端会拒绝此操作。
   * **输出:**  `IDBDatabase.cc` 中的相关逻辑会捕捉到这个错误，并通过 Mojo 接口将错误信息返回给渲染进程，最终导致 JavaScript 中事务的 `onerror` 事件被触发，并可能抛出一个 `DOMException`。错误消息可能包含 "The transaction is read-only." (对应 `kTransactionReadOnlyErrorMessage`)。

2. **尝试创建已存在的对象存储:**

   ```javascript
   request.onupgradeneeded = function(event) {
     const db = event.target.result;
     db.createObjectStore('myStore', { keyPath: 'id' });
     db.createObjectStore('myStore', { keyPath: 'email' }); // 错误！
   };
   ```
   * **假设输入:** 上述 JavaScript 代码在一个 `onupgradeneeded` 事件处理函数中执行。
   * **逻辑推理:** 第二次调用 `createObjectStore` 时，会检查到名为 "myStore" 的对象存储已经存在。
   * **输出:** `IDBDatabase::createObjectStore` 方法会抛出一个 `DOMException`，错误代码为 `kConstraintError`，错误消息为 "An object store with the specified name already exists." (对应 `kObjectStoreNameTakenErrorMessage`)。

3. **在 `versionchange` 事件外尝试修改数据库结构:**

   ```javascript
   const tx = db.transaction(['myStore'], 'readwrite');
   tx.oncomplete = function() {
     db.createObjectStore('anotherStore', { keyPath: 'id' }); // 错误！
   };
   ```
   * **假设输入:**  上述 JavaScript 代码在一个已经成功打开的数据库上执行。
   * **逻辑推理:** 数据库结构的修改（如创建或删除对象存储）只能在 `versionchange` 事务中进行。
   * **输出:**  `IDBDatabase::createObjectStore` 方法会检查当前是否在版本变更事务中，如果不是，则会抛出一个 `DOMException`，错误代码为 `kInvalidStateError`，错误消息为 "The database is not running a version change transaction." (对应 `kNotVersionChangeTransactionErrorMessage`)。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户访问一个网页:** 用户在浏览器地址栏输入网址或点击链接，访问一个包含使用 IndexedDB 的 JavaScript 代码的网页。
2. **JavaScript 代码执行:**  浏览器加载并解析 HTML，执行嵌入的 JavaScript 代码。
3. **`indexedDB.open()` 调用:** JavaScript 代码调用 `indexedDB.open()` 尝试打开或创建数据库。
4. **Blink 引擎处理:**  Blink 引擎接收到 `open` 请求，创建或获取 `IDBDatabase` 的实例 (由 `IDBDatabase.cc` 实现)。
5. **`onupgradeneeded` 事件 (如果需要):** 如果数据库版本需要升级，会触发 `onupgradeneeded` 事件，此时 JavaScript 代码可以调用 `db.createObjectStore()` 或 `db.deleteObjectStore()`，这些调用会进入 `IDBDatabase.cc` 的相应方法。
6. **`db.transaction()` 调用:**  JavaScript 代码调用 `db.transaction()` 启动一个事务。
7. **事务操作:** 在事务中，JavaScript 代码可以对对象存储进行增删改查操作，这些操作会通过 `IDBDatabase.cc` 中实现的接口与后端的 IndexedDB 服务通信。
8. **错误发生:**  如果在 JavaScript 代码中使用了错误的 API 调用方式（如上述示例），或者后端在处理请求时遇到问题，`IDBDatabase.cc` 中的代码会负责捕获并处理这些错误，并将错误信息传递回 JavaScript。

**调试线索:**

* **浏览器开发者工具 (DevTools):**  可以使用浏览器的开发者工具的 "Application" 或 "存储" 面板来查看 IndexedDB 的内容，以及在 "Console" 面板查看 JavaScript 的错误信息。
* **断点调试:**  可以在 `IDBDatabase.cc` 中设置断点，例如在 `createObjectStore`、`transaction` 等方法入口，来跟踪 JavaScript 的调用是如何进入到 Blink 引擎的，以及变量的值和执行流程。
* **日志输出:**  可以在 `IDBDatabase.cc` 中添加日志输出（例如使用 `DLOG` 或 `TRACE_EVENT`），以便在调试版本中查看 IndexedDB 操作的详细过程。
* **Mojo 接口分析:**  如果涉及到与后端服务的通信问题，可以分析通过 Mojo 接口传递的消息，查看请求和响应的内容。

总而言之，`IDBDatabase.cc` 是 Blink 引擎中实现 IndexedDB 数据库连接的核心组件，它负责处理 JavaScript 的请求，管理数据库的生命周期和事务，并与后端的存储服务进行通信。理解这个文件的功能对于理解 IndexedDB 在 Chromium 中的实现至关重要。

### 提示词
```
这是目录为blink/renderer/modules/indexeddb/idb_database.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/modules/indexeddb/idb_database.h"

#include <limits>
#include <memory>
#include <optional>
#include <utility>

#include "base/atomic_sequence_num.h"
#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/public/mojom/indexeddb/indexeddb.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_stringsequence.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/modules/indexed_db_names.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_any.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_event_dispatcher.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_index.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_path.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_range.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_version_change_event.h"
#include "third_party/blink/renderer/modules/indexeddb/indexed_db_blink_mojom_traits.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

const char IDBDatabase::kIndexDeletedErrorMessage[] =
    "The index or its object store has been deleted.";
const char IDBDatabase::kIndexNameTakenErrorMessage[] =
    "An index with the specified name already exists.";
const char IDBDatabase::kIsKeyCursorErrorMessage[] =
    "The cursor is a key cursor.";
const char IDBDatabase::kNoKeyOrKeyRangeErrorMessage[] =
    "No key or key range specified.";
const char IDBDatabase::kNoSuchIndexErrorMessage[] =
    "The specified index was not found.";
const char IDBDatabase::kNoSuchObjectStoreErrorMessage[] =
    "The specified object store was not found.";
const char IDBDatabase::kNoValueErrorMessage[] =
    "The cursor is being iterated or has iterated past its end.";
const char IDBDatabase::kNotValidKeyErrorMessage[] =
    "The parameter is not a valid key.";
const char IDBDatabase::kNotVersionChangeTransactionErrorMessage[] =
    "The database is not running a version change transaction.";
const char IDBDatabase::kObjectStoreDeletedErrorMessage[] =
    "The object store has been deleted.";
const char IDBDatabase::kObjectStoreNameTakenErrorMessage[] =
    "An object store with the specified name already exists.";
const char IDBDatabase::kRequestNotFinishedErrorMessage[] =
    "The request has not finished.";
const char IDBDatabase::kSourceDeletedErrorMessage[] =
    "The cursor's source or effective object store has been deleted.";
const char IDBDatabase::kTransactionInactiveErrorMessage[] =
    "The transaction is not active.";
const char IDBDatabase::kTransactionFinishedErrorMessage[] =
    "The transaction has finished.";
const char IDBDatabase::kTransactionReadOnlyErrorMessage[] =
    "The transaction is read-only.";
const char IDBDatabase::kDatabaseClosedErrorMessage[] =
    "The database connection is closed.";

IDBDatabase::IDBDatabase(
    ExecutionContext* context,
    mojo::PendingAssociatedReceiver<mojom::blink::IDBDatabaseCallbacks>
        callbacks_receiver,
    mojo::PendingRemote<mojom::blink::ObservedFeature> connection_lifetime,
    mojo::PendingAssociatedRemote<mojom::blink::IDBDatabase> pending_database,
    int connection_priority)
    : ActiveScriptWrappable<IDBDatabase>({}),
      ExecutionContextLifecycleStateObserver(context),
      database_remote_(context),
      connection_lifetime_(std::move(connection_lifetime)),
      scheduling_priority_(connection_priority),
      callbacks_receiver_(this, context) {
  database_remote_.Bind(std::move(pending_database),
                        context->GetTaskRunner(TaskType::kDatabaseAccess));
  callbacks_receiver_.Bind(std::move(callbacks_receiver),
                           context->GetTaskRunner(TaskType::kDatabaseAccess));

  // Invokes the callback immediately.
  scheduler_observer_ = context->GetScheduler()->AddLifecycleObserver(
      FrameOrWorkerScheduler::ObserverType::kWorkerScheduler,
      WTF::BindRepeating(&IDBDatabase::OnSchedulerLifecycleStateChanged,
                         WrapWeakPersistent(this)));

  UpdateStateIfNeeded();
}

void IDBDatabase::Trace(Visitor* visitor) const {
  visitor->Trace(database_remote_);
  visitor->Trace(version_change_transaction_);
  visitor->Trace(transactions_);
  visitor->Trace(callbacks_receiver_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

int64_t IDBDatabase::NextTransactionId() {
  // Starts at 1, unlike AtomicSequenceNumber.
  // Only keep a 32-bit counter to allow ports to use the other 32
  // bits of the id.
  static base::AtomicSequenceNumber current_transaction_id;
  return current_transaction_id.GetNext() + 1;
}

void IDBDatabase::SetMetadata(const IDBDatabaseMetadata& metadata) {
  metadata_ = metadata;
}

void IDBDatabase::SetDatabaseMetadata(const IDBDatabaseMetadata& metadata) {
  metadata_.CopyFrom(metadata);
}

void IDBDatabase::TransactionCreated(IDBTransaction* transaction) {
  DCHECK(transaction);
  DCHECK(!transactions_.Contains(transaction->Id()));
  transactions_.insert(transaction->Id(), transaction);

  if (transaction->IsVersionChange()) {
    DCHECK(!version_change_transaction_);
    version_change_transaction_ = transaction;
  }
}

void IDBDatabase::TransactionWillFinish(const IDBTransaction* transaction) {
  if (version_change_transaction_ && transaction->IsVersionChange()) {
    DCHECK_EQ(version_change_transaction_, transaction);
    version_change_transaction_ = nullptr;
  }
}

void IDBDatabase::TransactionFinished(const IDBTransaction* transaction) {
  DCHECK(transaction);
  DCHECK(transactions_.Contains(transaction->Id()));
  DCHECK_EQ(transactions_.at(transaction->Id()), transaction);
  transactions_.erase(transaction->Id());

  TransactionWillFinish(transaction);

  if (close_pending_ && transactions_.empty()) {
    CloseConnection();
  }
}

void IDBDatabase::ForcedClose() {
  for (const auto& it : transactions_) {
    it.value->StartAborting(nullptr);
  }
  this->close();
  DispatchEvent(*Event::Create(event_type_names::kClose));
}

void IDBDatabase::VersionChange(int64_t old_version, int64_t new_version) {
  TRACE_EVENT0("IndexedDB", "IDBDatabase::onVersionChange");
  if (!GetExecutionContext()) {
    return;
  }

  if (close_pending_) {
    // If we're pending, that means there's a busy transaction. We won't
    // fire 'versionchange' but since we're not closing immediately the
    // back-end should still send out 'blocked'.
    VersionChangeIgnored();
    return;
  }

  std::optional<uint64_t> new_version_nullable;
  if (new_version != IDBDatabaseMetadata::kNoVersion) {
    new_version_nullable = new_version;
  }
  DispatchEvent(*MakeGarbageCollected<IDBVersionChangeEvent>(
      event_type_names::kVersionchange, old_version, new_version_nullable));
}

void IDBDatabase::Abort(int64_t transaction_id,
                        mojom::blink::IDBException code,
                        const WTF::String& message) {
  DCHECK(transactions_.Contains(transaction_id));
  transactions_.at(transaction_id)
      ->OnAbort(MakeGarbageCollected<DOMException>(
          static_cast<DOMExceptionCode>(code), message));
}

void IDBDatabase::Complete(int64_t transaction_id) {
  DCHECK(transactions_.Contains(transaction_id));
  transactions_.at(transaction_id)->OnComplete();
}

DOMStringList* IDBDatabase::objectStoreNames() const {
  auto* object_store_names = MakeGarbageCollected<DOMStringList>();
  for (const auto& it : metadata_.object_stores) {
    object_store_names->Append(it.value->name);
  }
  object_store_names->Sort();
  return object_store_names;
}

IDBObjectStore* IDBDatabase::createObjectStore(
    const String& name,
    const IDBKeyPath& key_path,
    bool auto_increment,
    ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBDatabase::createObjectStore");

  if (!version_change_transaction_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kNotVersionChangeTransactionErrorMessage);
    return nullptr;
  }
  if (!version_change_transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        version_change_transaction_->InactiveErrorMessage());
    return nullptr;
  }

  if (!key_path.IsNull() && !key_path.IsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The keyPath option is not a valid key path.");
    return nullptr;
  }

  if (ContainsObjectStore(name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kConstraintError,
        IDBDatabase::kObjectStoreNameTakenErrorMessage);
    return nullptr;
  }

  if (auto_increment && ((key_path.GetType() == mojom::IDBKeyPathType::String &&
                          key_path.GetString().empty()) ||
                         key_path.GetType() == mojom::IDBKeyPathType::Array)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The autoIncrement option was set but the "
        "keyPath option was empty or an array.");
    return nullptr;
  }

  if (!database_remote_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  int64_t object_store_id = metadata_.max_object_store_id + 1;
  DCHECK_NE(object_store_id, IDBObjectStoreMetadata::kInvalidId);
  version_change_transaction_->CreateObjectStore(object_store_id, name,
                                                 key_path, auto_increment);

  scoped_refptr<IDBObjectStoreMetadata> store_metadata = base::AdoptRef(
      new IDBObjectStoreMetadata(name, object_store_id, key_path,
                                 auto_increment, IDBDatabase::kMinimumIndexId));
  auto* object_store = MakeGarbageCollected<IDBObjectStore>(
      store_metadata, version_change_transaction_.Get());
  version_change_transaction_->ObjectStoreCreated(name, object_store);
  metadata_.object_stores.Set(object_store_id, std::move(store_metadata));
  ++metadata_.max_object_store_id;

  return object_store;
}

IDBTransaction* IDBDatabase::transaction(
    ScriptState* script_state,
    const V8UnionStringOrStringSequence* store_names,
    const V8IDBTransactionMode& v8_mode,
    const IDBTransactionOptions* options,
    ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBDatabase::transaction");

  HashSet<String> scope;
  DCHECK(store_names);
  switch (store_names->GetContentType()) {
    case V8UnionStringOrStringSequence::ContentType::kString:
      scope.insert(store_names->GetAsString());
      break;
    case V8UnionStringOrStringSequence::ContentType::kStringSequence:
      for (const String& name : store_names->GetAsStringSequence()) {
        scope.insert(name);
      }
      break;
  }

  if (version_change_transaction_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "A version change transaction is running.");
    return nullptr;
  }

  if (close_pending_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The database connection is closing.");
    return nullptr;
  }

  if (!database_remote_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  if (scope.empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The storeNames parameter was empty.");
    return nullptr;
  }

  Vector<int64_t> object_store_ids;
  for (const String& name : scope) {
    int64_t object_store_id = FindObjectStoreId(name);
    if (object_store_id == IDBObjectStoreMetadata::kInvalidId) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotFoundError,
          "One of the specified object stores was not found.");
      return nullptr;
    }
    object_store_ids.push_back(object_store_id);
  }

  mojom::blink::IDBTransactionMode mode =
      IDBTransaction::EnumToMode(v8_mode.AsEnum());
  if (mode != mojom::blink::IDBTransactionMode::ReadOnly &&
      mode != mojom::blink::IDBTransactionMode::ReadWrite) {
    exception_state.ThrowTypeError(
        "The mode provided ('" + v8_mode.AsString() +
        "') is not one of 'readonly' or 'readwrite'.");
    return nullptr;
  }

  mojom::blink::IDBTransactionDurability durability =
      mojom::blink::IDBTransactionDurability::Default;
  DCHECK(options);
  if (options->durability() == indexed_db_names::kRelaxed) {
    durability = mojom::blink::IDBTransactionDurability::Relaxed;
  } else if (options->durability() == indexed_db_names::kStrict) {
    durability = mojom::blink::IDBTransactionDurability::Strict;
  }

  // TODO(cmp): Delete |transaction_id| once all users are removed.
  int64_t transaction_id = NextTransactionId();
  auto* execution_context = ExecutionContext::From(script_state);
  IDBTransaction::TransactionMojoRemote transaction_remote(execution_context);
  mojo::PendingAssociatedReceiver<mojom::blink::IDBTransaction> receiver =
      transaction_remote.BindNewEndpointAndPassReceiver(
          execution_context->GetTaskRunner(TaskType::kDatabaseAccess));
  CreateTransaction(std::move(receiver), transaction_id, object_store_ids, mode,
                    durability);

  return IDBTransaction::CreateNonVersionChange(
      script_state, std::move(transaction_remote), transaction_id, scope, mode,
      durability, this);
}

void IDBDatabase::deleteObjectStore(const String& name,
                                    ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBDatabase::deleteObjectStore");
  if (!version_change_transaction_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kNotVersionChangeTransactionErrorMessage);
    return;
  }
  if (!version_change_transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        version_change_transaction_->InactiveErrorMessage());
    return;
  }

  int64_t object_store_id = FindObjectStoreId(name);
  if (object_store_id == IDBObjectStoreMetadata::kInvalidId) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The specified object store was not found.");
    return;
  }

  if (!database_remote_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return;
  }

  version_change_transaction_->DeleteObjectStore(object_store_id);
  version_change_transaction_->ObjectStoreDeleted(object_store_id, name);
  metadata_.object_stores.erase(object_store_id);
}

void IDBDatabase::close() {
  TRACE_EVENT0("IndexedDB", "IDBDatabase::close");
  if (close_pending_) {
    return;
  }

  connection_lifetime_.reset();
  close_pending_ = true;

  if (transactions_.empty()) {
    CloseConnection();
  }
}

void IDBDatabase::CloseConnection() {
  DCHECK(close_pending_);
  DCHECK(transactions_.empty());

  if (database_remote_.is_bound()) {
    database_remote_.reset();
  }

  if (callbacks_receiver_.is_bound()) {
    callbacks_receiver_.reset();
  }
}

DispatchEventResult IDBDatabase::DispatchEventInternal(Event& event) {
  TRACE_EVENT0("IndexedDB", "IDBDatabase::dispatchEvent");

  event.SetTarget(this);

  // If this event originated from script, it should have no side effects.
  if (!event.isTrusted()) {
    return EventTarget::DispatchEventInternal(event);
  }
  DCHECK(event.type() == event_type_names::kVersionchange ||
         event.type() == event_type_names::kClose);

  if (!GetExecutionContext()) {
    return DispatchEventResult::kCanceledBeforeDispatch;
  }

  DispatchEventResult dispatch_result =
      EventTarget::DispatchEventInternal(event);

  if (event.type() == event_type_names::kVersionchange && !close_pending_ &&
      database_remote_.is_bound()) {
    VersionChangeIgnored();
  }
  return dispatch_result;
}

int64_t IDBDatabase::FindObjectStoreId(const String& name) const {
  for (const auto& it : metadata_.object_stores) {
    if (it.value->name == name) {
      DCHECK_NE(it.key, IDBObjectStoreMetadata::kInvalidId);
      return it.key;
    }
  }
  return IDBObjectStoreMetadata::kInvalidId;
}

void IDBDatabase::RenameObjectStore(int64_t object_store_id,
                                    const String& new_name) {
  DCHECK(version_change_transaction_)
      << "Object store renamed on database without a versionchange "
         "transaction";
  DCHECK(version_change_transaction_->IsActive())
      << "Object store renamed when versionchange transaction is not active";
  DCHECK(metadata_.object_stores.Contains(object_store_id));

  RenameObjectStore(version_change_transaction_->Id(), object_store_id,
                    new_name);

  IDBObjectStoreMetadata* object_store_metadata =
      metadata_.object_stores.at(object_store_id);
  version_change_transaction_->ObjectStoreRenamed(object_store_metadata->name,
                                                  new_name);
  object_store_metadata->name = new_name;
}

void IDBDatabase::RevertObjectStoreCreation(int64_t object_store_id) {
  DCHECK(version_change_transaction_) << "Object store metadata reverted on "
                                         "database without a versionchange "
                                         "transaction";
  DCHECK(!version_change_transaction_->IsActive())
      << "Object store metadata reverted when versionchange transaction is "
         "still active";
  DCHECK(metadata_.object_stores.Contains(object_store_id));
  metadata_.object_stores.erase(object_store_id);
}

void IDBDatabase::RevertObjectStoreMetadata(
    scoped_refptr<IDBObjectStoreMetadata> old_metadata) {
  DCHECK(version_change_transaction_) << "Object store metadata reverted on "
                                         "database without a versionchange "
                                         "transaction";
  DCHECK(!version_change_transaction_->IsActive())
      << "Object store metadata reverted when versionchange transaction is "
         "still active";
  DCHECK(old_metadata.get());
  metadata_.object_stores.Set(old_metadata->id, std::move(old_metadata));
}

bool IDBDatabase::HasPendingActivity() const {
  // The script wrapper must not be collected before the object is closed or
  // we can't fire a "versionchange" event to let script manually close the
  // connection.
  return !close_pending_ && GetExecutionContext() && HasEventListeners();
}

void IDBDatabase::ContextDestroyed() {
  // Immediately close the connection to the back end. Don't attempt a
  // normal close() since that may wait on transactions which require a
  // round trip to the back-end to abort.
  if (database_remote_.is_bound()) {
    database_remote_.reset();
  }
  connection_lifetime_.reset();
}

void IDBDatabase::ContextEnteredBackForwardCache() {
  if (!database_remote_.is_bound()) {
    return;
  }

  DidBecomeInactive();
}

void IDBDatabase::ContextLifecycleStateChanged(
    mojom::blink::FrameLifecycleState state) {
  if (!database_remote_.is_bound()) {
    return;
  }

  if (state == mojom::blink::FrameLifecycleState::kFrozen ||
      state == mojom::blink::FrameLifecycleState::kFrozenAutoResumeMedia) {
    DidBecomeInactive();
  }
}

bool IDBDatabase::IsConnectionOpen() const {
  return database_remote_.is_bound();
}

const AtomicString& IDBDatabase::InterfaceName() const {
  return event_target_names::kIDBDatabase;
}

ExecutionContext* IDBDatabase::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

STATIC_ASSERT_ENUM(mojom::blink::IDBException::kNoError,
                   DOMExceptionCode::kNoError);
STATIC_ASSERT_ENUM(mojom::blink::IDBException::kUnknownError,
                   DOMExceptionCode::kUnknownError);
STATIC_ASSERT_ENUM(mojom::blink::IDBException::kConstraintError,
                   DOMExceptionCode::kConstraintError);
STATIC_ASSERT_ENUM(mojom::blink::IDBException::kDataError,
                   DOMExceptionCode::kDataError);
STATIC_ASSERT_ENUM(mojom::blink::IDBException::kVersionError,
                   DOMExceptionCode::kVersionError);
STATIC_ASSERT_ENUM(mojom::blink::IDBException::kAbortError,
                   DOMExceptionCode::kAbortError);
STATIC_ASSERT_ENUM(mojom::blink::IDBException::kQuotaError,
                   DOMExceptionCode::kQuotaExceededError);
STATIC_ASSERT_ENUM(mojom::blink::IDBException::kTimeoutError,
                   DOMExceptionCode::kTimeoutError);

void IDBDatabase::Get(
    int64_t transaction_id,
    int64_t object_store_id,
    int64_t index_id,
    const IDBKeyRange* key_range,
    bool key_only,
    base::OnceCallback<void(mojom::blink::IDBDatabaseGetResultPtr)>
        result_callback) {
  IDBCursor::ResetCursorPrefetchCaches(transaction_id, nullptr);

  mojom::blink::IDBKeyRangePtr key_range_ptr =
      mojom::blink::IDBKeyRange::From(key_range);
  database_remote_->Get(transaction_id, object_store_id, index_id,
                        std::move(key_range_ptr), key_only,
                        std::move(result_callback));
}

void IDBDatabase::GetAll(int64_t transaction_id,
                         int64_t object_store_id,
                         int64_t index_id,
                         const IDBKeyRange* key_range,
                         mojom::blink::IDBGetAllResultType result_type,
                         int64_t max_count,
                         mojom::blink::IDBCursorDirection direction,
                         IDBRequest* request) {
  IDBCursor::ResetCursorPrefetchCaches(transaction_id, nullptr);

  mojom::blink::IDBKeyRangePtr key_range_ptr =
      mojom::blink::IDBKeyRange::From(key_range);
  database_remote_->GetAll(
      transaction_id, object_store_id, index_id, std::move(key_range_ptr),
      result_type, max_count, direction,
      WTF::BindOnce(&IDBRequest::OnGetAll, WrapWeakPersistent(request),
                    result_type));
}

void IDBDatabase::SetIndexKeys(int64_t transaction_id,
                               int64_t object_store_id,
                               std::unique_ptr<IDBKey> primary_key,
                               Vector<IDBIndexKeys> index_keys) {
  database_remote_->SetIndexKeys(transaction_id, object_store_id,
                                 std::move(primary_key), std::move(index_keys));
}

void IDBDatabase::SetIndexesReady(int64_t transaction_id,
                                  int64_t object_store_id,
                                  const Vector<int64_t>& index_ids) {
  database_remote_->SetIndexesReady(transaction_id, object_store_id,
                                    std::move(index_ids));
}

void IDBDatabase::OpenCursor(int64_t object_store_id,
                             int64_t index_id,
                             const IDBKeyRange* key_range,
                             mojom::blink::IDBCursorDirection direction,
                             bool key_only,
                             mojom::blink::IDBTaskType task_type,
                             IDBRequest* request) {
  IDBCursor::ResetCursorPrefetchCaches(request->transaction()->Id(), nullptr);

  mojom::blink::IDBKeyRangePtr key_range_ptr =
      mojom::blink::IDBKeyRange::From(key_range);
  database_remote_->OpenCursor(
      request->transaction()->Id(), object_store_id, index_id,
      std::move(key_range_ptr), direction, key_only, task_type,
      WTF::BindOnce(&IDBRequest::OnOpenCursor, WrapWeakPersistent(request)));
}

void IDBDatabase::Count(int64_t transaction_id,
                        int64_t object_store_id,
                        int64_t index_id,
                        const IDBKeyRange* key_range,
                        mojom::blink::IDBDatabase::CountCallback callback) {
  IDBCursor::ResetCursorPrefetchCaches(transaction_id, nullptr);

  database_remote_->Count(transaction_id, object_store_id, index_id,
                          mojom::blink::IDBKeyRange::From(key_range),
                          std::move(callback));
}

void IDBDatabase::Delete(int64_t transaction_id,
                         int64_t object_store_id,
                         const IDBKey* primary_key,
                         base::OnceCallback<void(bool)> success_callback) {
  IDBCursor::ResetCursorPrefetchCaches(transaction_id, nullptr);

  mojom::blink::IDBKeyRangePtr key_range_ptr =
      mojom::blink::IDBKeyRange::From(IDBKeyRange::Create(primary_key));
  database_remote_->DeleteRange(transaction_id, object_store_id,
                                std::move(key_range_ptr),
                                std::move(success_callback));
}

void IDBDatabase::DeleteRange(int64_t transaction_id,
                              int64_t object_store_id,
                              const IDBKeyRange* key_range,
                              base::OnceCallback<void(bool)> success_callback) {
  IDBCursor::ResetCursorPrefetchCaches(transaction_id, nullptr);

  mojom::blink::IDBKeyRangePtr key_range_ptr =
      mojom::blink::IDBKeyRange::From(key_range);
  database_remote_->DeleteRange(transaction_id, object_store_id,
                                std::move(key_range_ptr),
                                std::move(success_callback));
}

void IDBDatabase::GetKeyGeneratorCurrentNumber(
    int64_t transaction_id,
    int64_t object_store_id,
    mojom::blink::IDBDatabase::GetKeyGeneratorCurrentNumberCallback callback) {
  database_remote_->GetKeyGeneratorCurrentNumber(
      transaction_id, object_store_id, std::move(callback));
}

void IDBDatabase::Clear(
    int64_t transaction_id,
    int64_t object_store_id,
    mojom::blink::IDBDatabase::ClearCallback success_callback) {
  IDBCursor::ResetCursorPrefetchCaches(transaction_id, nullptr);
  database_remote_->Clear(transaction_id, object_store_id,
                          std::move(success_callback));
}

void IDBDatabase::CreateIndex(int64_t transaction_id,
                              int64_t object_store_id,
                              int64_t index_id,
                              const String& name,
                              const IDBKeyPath& key_path,
                              bool unique,
                              bool multi_entry) {
  database_remote_->CreateIndex(transaction_id, object_store_id, index_id, name,
                                key_path, unique, multi_entry);
}

void IDBDatabase::DeleteIndex(int64_t transaction_id,
                              int64_t object_store_id,
                              int64_t index_id) {
  database_remote_->DeleteIndex(transaction_id, object_store_id, index_id);
}

void IDBDatabase::RenameIndex(int64_t transaction_id,
                              int64_t object_store_id,
                              int64_t index_id,
                              const String& new_name) {
  DCHECK(!new_name.IsNull());
  database_remote_->RenameIndex(transaction_id, object_store_id, index_id,
                                new_name);
}

void IDBDatabase::Abort(int64_t transaction_id) {
  if (database_remote_.is_bound()) {
    database_remote_->Abort(transaction_id);
  }
}

void IDBDatabase::OnSchedulerLifecycleStateChanged(
    scheduler::SchedulingLifecycleState lifecycle_state) {
  int new_priority = GetSchedulingPriority(lifecycle_state);
  if (new_priority == scheduling_priority_) {
    return;
  }
  scheduling_priority_ = new_priority;
  if (database_remote_) {
    database_remote_->UpdatePriority(scheduling_priority_);
  }
}

// static
int IDBDatabase::GetSchedulingPriority(
    scheduler::SchedulingLifecycleState lifecycle_state) {
  switch (lifecycle_state) {
    case scheduler::SchedulingLifecycleState::kNotThrottled:
      return 0;
    case scheduler::SchedulingLifecycleState::kHidden:
      return 1;
    case scheduler::SchedulingLifecycleState::kThrottled:
      return 2;
    case scheduler::SchedulingLifecycleState::kStopped:
      return 3;
  }

  return 0;
}

}  // namespace blink
```