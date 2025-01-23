Response:
Let's break down the thought process for analyzing the provided C++ code snippet for `IDBCursor.cc`.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `IDBCursor` class within the Chromium Blink engine (specifically its IndexedDB module). The prompt also requests relating this functionality to web technologies (JavaScript, HTML, CSS), identifying logical inferences, pinpointing potential user errors, and tracing user actions leading to this code.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for keywords and patterns that give clues about its purpose. I'd look for:

* **Class Name:** `IDBCursor` - immediately tells me this is related to cursors in IndexedDB.
* **Includes:** Headers like `idb_cursor.h`, `idb_request.h`, `idb_transaction.h`, `v8_idb_request.h` indicate dependencies and interactions with other IndexedDB components and the V8 JavaScript engine. `mojom::blink::IDBCursor` points to the Mojo interface definition.
* **Methods:**  `advance`, `continue`, `continuePrimaryKey`, `update`, `delete`, `key`, `primaryKey`, `value`, `Close`. These are clearly the core operations a cursor performs.
* **Member Variables:** `remote_`, `request_`, `direction_`, `source_`, `transaction_`, `key_`, `primary_key_unless_injected_`, `value_`,  `prefetch_keys_`, etc. These represent the state of the cursor.
* **Namespaces:** `blink`, suggesting it's part of the Blink rendering engine.
* **Copyright:**  Indicates ownership and licensing.
* **Comments:**  Provide hints about specific functionalities.
* **`TRACE_EVENT0`:** Indicates performance instrumentation.
* **Error Handling:**  `ExceptionState` is used for reporting errors to JavaScript.
* **Prefetching Logic:**  Variables like `prefetch_keys_`, `prefetch_amount_`, `CachedAdvance`, `CachedContinue` are strong indicators of prefetching optimizations.

**3. Deconstructing Functionality by Method:**

Once the key elements are identified, I'd analyze each significant method in detail, considering its arguments, logic, and how it interacts with other parts of the system.

* **Constructor (`IDBCursor::IDBCursor`):**  Establishes the basic relationships: links the cursor to a Mojo remote, a request, a source (object store or index), and a transaction.
* **Destructor (`IDBCursor::~IDBCursor`):** Cleans up resources.
* **`advance`:** Moves the cursor forward a specified number of records. Handles potential errors (zero count).
* **`Continue` (overloads):** Moves the cursor to a specific key or key/primary key combination. Includes error handling for invalid keys and directions.
* **`update`:** Modifies the current record. Restricted in read-only transactions.
* **`Delete`:** Removes the current record. Restricted in read-only transactions.
* **`key`, `primaryKey`, `value`:**  Return the current record's key, primary key, and value, respectively. Notice the `dirty_` flags, suggesting lazy evaluation or caching.
* **`Close`:** Invalidates the cursor.
* **Prefetching Methods (`AdvanceImpl`, `CursorContinue`, `PrefetchCallback`, `CachedAdvance`, `CachedContinue`, `ResetPrefetchCache`):** This section is crucial. It implements a prefetching mechanism to improve performance by fetching multiple records in advance. This involves managing cached keys, primary keys, and values.

**4. Connecting to Web Technologies:**

Now, the goal is to link the C++ code to its manifestations in web technologies:

* **JavaScript:**  The most direct connection. The methods in `IDBCursor.cc` directly implement the functionality exposed by the `IDBCursor` interface in JavaScript. Examples of JavaScript usage are essential.
* **HTML:**  HTML provides the structure for web pages. IndexedDB is often used to store data related to web applications built with HTML.
* **CSS:**  Less direct, but CSS is used for styling web pages. IndexedDB might store data that influences how a page is styled dynamically.

**5. Logical Inferences and Assumptions:**

This involves reasoning about the code's behavior based on its structure:

* **Prefetching Optimization:**  The presence of prefetching logic implies that iterating through cursors can be a performance bottleneck, and this optimization aims to mitigate that.
* **Transaction Boundaries:**  Operations like `update` and `delete` are tied to the transaction's mode (read-only or read-write).
* **Error Handling:** The use of `ExceptionState` suggests how errors in IndexedDB operations are communicated back to the JavaScript layer as exceptions.

**6. Identifying Potential User Errors:**

Think about common mistakes developers might make when using IndexedDB cursors:

* Calling `continue` or `advance` with invalid arguments.
* Performing write operations in read-only transactions.
* Using a cursor after the transaction has completed or the source has been deleted.

**7. Tracing User Actions:**

This involves outlining the steps a user might take in a web application that would eventually lead to the execution of the code in `IDBCursor.cc`. This often involves a series of asynchronous operations.

**8. Structuring the Answer:**

Finally, organize the gathered information into a coherent and readable answer, addressing each point of the prompt:

* **Functionality:** Summarize the main responsibilities of the `IDBCursor` class.
* **Relationship to Web Technologies:** Provide concrete JavaScript examples and explain how HTML and CSS might indirectly relate.
* **Logical Inferences:** Present the deductions made about the code's behavior.
* **User Errors:** Give practical examples of common mistakes.
* **User Action Trace:** Detail the sequence of user interactions and API calls.

**Self-Correction/Refinement:**

During the process, I'd review my findings and refine my understanding:

* **Are the JavaScript examples accurate and illustrative?**
* **Have I correctly identified the core functionalities?**
* **Is the explanation of prefetching clear and concise?**
* **Are the user error examples realistic?**
* **Is the user action trace logical and complete?**

By following this structured approach, combining code analysis with knowledge of web technologies and common programming patterns, I can effectively analyze and explain the functionality of a complex piece of code like `IDBCursor.cc`.
好的，让我们详细分析一下 `blink/renderer/modules/indexeddb/idb_cursor.cc` 这个文件。

**文件功能概述:**

`IDBCursor.cc` 文件定义了 Chromium Blink 引擎中 `IDBCursor` 类的实现。`IDBCursor` 代表了 IndexedDB API 中的游标对象，它允许开发者迭代访问数据库中对象存储或索引中的记录。

**核心功能点:**

1. **游标的创建和管理:**
   - `IDBCursor` 类负责创建游标对象，并维护游标的状态，例如当前位置、方向等。
   - 它关联到一个 `IDBRequest` 对象，用于异步操作完成时的通知。
   - 它关联到一个 `Source` 对象，指明游标遍历的是哪个对象存储或索引。
   - 它关联到一个 `IDBTransaction` 对象，确保操作在事务的上下文中进行。

2. **游标的移动:**
   - **`advance(unsigned count, ExceptionState& exception_state)`:**  将游标向前移动指定的 `count` 条记录。
   - **`Continue(ScriptState* script_state, const ScriptValue& key_value, ExceptionState& exception_state)`:** 将游标移动到指定的 `key_value` 处或之后的位置。
   - **`continuePrimaryKey(ScriptState* script_state, const ScriptValue& key_value, const ScriptValue& primary_key_value, ExceptionState& exception_state)`:** 对于使用复合键的索引，将游标移动到指定的 `key_value` 和 `primary_key_value` 处或之后的位置。

3. **访问游标指向的数据:**
   - **`key(ScriptState* script_state)`:** 返回当前游标指向记录的键。
   - **`primaryKey(ScriptState* script_state)`:** 返回当前游标指向记录的主键。
   - **`value(ScriptState* script_state)`:** 返回当前游标指向记录的值（仅对值游标有效，例如通过 `openCursor()` 创建的游标）。

4. **通过游标进行操作:**
   - **`update(ScriptState* script_state, const ScriptValue& value, ExceptionState& exception_state)`:**  更新当前游标指向的记录。只能在读写事务中执行。
   - **`Delete(ScriptState* script_state, ExceptionState& exception_state)`:** 删除当前游标指向的记录。只能在读写事务中执行。

5. **游标的关闭:**
   - **`Close()`:**  释放游标占用的资源。

6. **预取优化:**
   - 代码中实现了预取（prefetch）机制，通过 `Prefetch`、`PrefetchCallback`、`CachedAdvance`、`CachedContinue` 等方法，在用户请求下一条或多条记录之前，提前加载一批数据，以提高性能。

**与 JavaScript, HTML, CSS 的关系:**

`IDBCursor.cc` 的功能直接暴露给 JavaScript 中的 `IDBCursor` 接口。开发者通过 JavaScript 代码使用 IndexedDB API 来操作数据库，其中就包括使用游标进行数据遍历和操作。

**举例说明:**

**JavaScript 代码:**

```javascript
const request = indexedDB.open('myDatabase', 1);

request.onsuccess = function(event) {
  const db = event.target.result;
  const transaction = db.transaction('myObjectStore', 'readwrite');
  const objectStore = transaction.objectStore('myObjectStore');
  const cursorRequest = objectStore.openCursor(); // 打开一个值游标

  cursorRequest.onsuccess = function(event) {
    const cursor = event.target.result;
    if (cursor) {
      console.log('Key:', cursor.key);
      console.log('PrimaryKey:', cursor.primaryKey);
      console.log('Value:', cursor.value);

      // 更新当前记录
      const updateRequest = cursor.update({ name: 'Updated Name' });
      updateRequest.onsuccess = function() {
        console.log('Record updated successfully');
      };

      // 继续到下一条记录
      cursor.continue();
    } else {
      console.log('No more records.');
    }
  };

  cursorRequest.onerror = function(event) {
    console.error('Error opening cursor:', event.target.error);
  };
};
```

**关系说明:**

- JavaScript 代码中的 `indexedDB.open()`, `transaction()`, `objectStore()`, `openCursor()` 等方法最终会调用 Blink 引擎中相应的 C++ 代码。
- `objectStore.openCursor()` 会创建一个 `IDBCursor` 对象（或其子类 `IDBCursorWithValue`），其实现就在 `IDBCursor.cc` 中。
- JavaScript 中 `cursor.key`, `cursor.primaryKey`, `cursor.value`, `cursor.continue()`, `cursor.update()` 等方法的调用，会映射到 `IDBCursor.cc` 中对应的 `key()`, `primaryKey()`, `value()`, `Continue()`, `update()` 等方法。

**HTML 和 CSS 的关系:**

HTML 和 CSS 本身不直接与 `IDBCursor.cc` 有交互。然而，前端开发者通常会使用 JavaScript 和 IndexedDB 来存储和管理 Web 应用的数据，这些数据最终可能用于动态生成 HTML 结构或改变 CSS 样式。

**例如:**

一个在线任务管理应用可以使用 IndexedDB 存储任务列表。当用户打开应用时，JavaScript 代码会使用游标遍历 IndexedDB 中的任务数据，然后动态生成包含任务信息的 HTML 列表，并根据任务的状态应用不同的 CSS 样式（例如，已完成的任务可能显示为灰色）。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 用户在 JavaScript 中调用 `cursor.continue('apple')`。
2. 当前游标指向的记录的键是 'banana'。
3. 游标的方向是 `next`。

**逻辑推理:**

- `IDBCursor::Continue()` 方法会被调用，传入键值 'apple'。
- 代码会比较传入的键 'apple' 和当前游标的键 'banana'。
- 由于游标方向是 `next`，并且 'apple' 小于 'banana'，`Continue()` 方法会抛出一个 `DOMException`，指示提供的参数小于当前游标的位置。

**输出 (抛出异常):**

JavaScript 代码中 `cursorRequest.onsuccess` 不会被触发，而是会触发 `cursorRequest.onerror`，错误信息可能是 "The parameter is less than or equal to this cursor's position."

**常见的使用错误:**

1. **在只读事务中尝试更新或删除记录:**

   ```javascript
   const transaction = db.transaction('myObjectStore', 'readonly');
   const cursorRequest = objectStore.openCursor();
   cursorRequest.onsuccess = function(event) {
     const cursor = event.target.result;
     if (cursor) {
       cursor.update({ name: 'New Name' }); // 错误：只读事务
     }
   };
   ```
   **结果:** 会抛出 `ReadOnlyError` 异常。

2. **在游标没有指向有效记录时尝试操作:**

   ```javascript
   const transaction = db.transaction('myObjectStore', 'readwrite');
   const cursorRequest = objectStore.openCursor();
   cursorRequest.onsuccess = function(event) {
     const cursor = event.target.result;
     if (cursor) {
       cursor.continue(); // 移动到最后
     } else {
       cursor.update({ name: 'Error' }); // 错误：游标已结束
     }
   };
   ```
   **结果:**  当 `cursor` 为 `null` 时尝试调用 `update()` 会抛出 `InvalidStateError` 异常，因为游标不再指向任何有效的记录。

3. **在事务不活跃时操作游标:**

   ```javascript
   const transaction = db.transaction('myObjectStore', 'readwrite');
   const objectStore = transaction.objectStore('myObjectStore');
   const cursorRequest = objectStore.openCursor();

   transaction.oncomplete = function() {
     // 事务已完成
     cursorRequest.onsuccess = function(event) {
       const cursor = event.target.result;
       if (cursor) {
         cursor.continue(); // 错误：事务已完成
       }
     };
   };
   ```
   **结果:** 在事务 `oncomplete` 之后尝试操作游标会抛出 `TransactionInactiveError` 异常。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个使用了 IndexedDB 的网页。**
2. **网页中的 JavaScript 代码尝试打开一个 IndexedDB 数据库或对象存储。**
3. **JavaScript 代码调用 `objectStore.openCursor()` 或 `index.openCursor()` 方法，创建一个游标请求。** 这会在 Blink 引擎中创建对应的 `IDBRequest` 对象。
4. **Blink 引擎处理 `openCursor()` 请求，创建 `IDBCursor` 或 `IDBCursorWithValue` 对象。** 相关的代码逻辑会在 `blink/renderer/modules/indexeddb/idb_object_store.cc` 或 `blink/renderer/modules/indexeddb/idb_index.cc` 中。
5. **当游标请求成功时，JavaScript 的 `cursorRequest.onsuccess` 回调函数被调用，并接收到 `IDBCursor` 对象。**
6. **用户在 JavaScript 中调用 `cursor.continue()`, `cursor.advance()`, `cursor.update()`, `cursor.delete()` 等方法。**
7. **这些 JavaScript 方法的调用会被 Blink 的绑定机制拦截，并映射到 `IDBCursor.cc` 文件中对应的 C++ 方法。** 例如，调用 `cursor.continue()` 会执行 `IDBCursor::Continue()` 方法。
8. **在 `IDBCursor.cc` 的方法中，会进行各种检查，例如事务状态、游标状态等，并与底层的 IndexedDB 实现进行交互。**
9. **如果需要与浏览器进程进行通信 (例如，获取下一批数据)，会使用 Mojo 接口 (`remote_`) 发送消息。**
10. **如果在 C++ 代码中发生错误，会通过 `ExceptionState` 对象将错误信息传递回 JavaScript 层，触发 `cursorRequest.onerror` 回调。**

**调试线索:**

- **断点:** 在 `IDBCursor.cc` 中设置断点，例如在 `Continue()`, `advance()`, `update()` 等方法入口，可以跟踪 JavaScript 调用如何进入 C++ 代码，并查看游标的状态。
- **日志:** 使用 `TRACE_EVENT0` 或自定义的日志输出，可以记录 `IDBCursor` 方法的调用顺序和参数，帮助理解执行流程。
- **Mojo 调试:** 如果涉及到与浏览器进程的通信，可以使用 Mojo 的调试工具来查看发送和接收的消息，了解数据是如何在进程之间传递的。
- **IndexedDB 内部日志:** Chromium 提供了 IndexedDB 的内部日志记录功能，可以提供更底层的操作信息。

希望以上详细的分析能够帮助你理解 `blink/renderer/modules/indexeddb/idb_cursor.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/indexeddb/idb_cursor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/indexeddb/idb_cursor.h"

#include <limits>
#include <memory>
#include <utility>

#include "base/check.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_idb_request.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_idbcursor_idbindex_idbobjectstore.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_idbindex_idbobjectstore.h"
#include "third_party/blink/renderer/modules/indexed_db_names.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_any.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor_with_value.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_database.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_object_store.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_request.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_transaction.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_value.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"

namespace blink {

namespace {

using CursorSet = HeapHashSet<WeakMember<IDBCursor>>;

CursorSet& GetGlobalCursorSet() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ThreadSpecific<Persistent<CursorSet>>,
                                  thread_specific_instance, ());
  if (!*thread_specific_instance) {
    *thread_specific_instance = MakeGarbageCollected<CursorSet>();
  }
  return **thread_specific_instance;
}

void RegisterCursor(IDBCursor* cursor) {
  CursorSet& cursor_set = GetGlobalCursorSet();
  CHECK(!cursor_set.Contains(cursor));
  cursor_set.insert(cursor);
}

}  // namespace

IDBCursor::IDBCursor(
    mojo::PendingAssociatedRemote<mojom::blink::IDBCursor> pending_cursor,
    mojom::IDBCursorDirection direction,
    IDBRequest* request,
    const Source* source,
    IDBTransaction* transaction)
    : remote_(request->GetExecutionContext()),
      request_(request),
      direction_(direction),
      source_(source),
      transaction_(transaction) {
  DCHECK(request_);
  DCHECK(source_);
  DCHECK(transaction_);
  remote_.Bind(std::move(pending_cursor),
               request_->GetExecutionContext()->GetTaskRunner(
                   TaskType::kDatabaseAccess));
  RegisterCursor(this);
}

IDBCursor::~IDBCursor() = default;

void IDBCursor::Trace(Visitor* visitor) const {
  visitor->Trace(remote_);
  visitor->Trace(request_);
  visitor->Trace(source_);
  visitor->Trace(transaction_);
  visitor->Trace(value_);
  ScriptWrappable::Trace(visitor);
}

void IDBCursor::ContextWillBeDestroyed() {
  ResetPrefetchCache();
}

// Keep the request's wrapper alive as long as the cursor's wrapper is alive,
// so that the same script object is seen each time the cursor is used.
v8::Local<v8::Object> IDBCursor::AssociateWithWrapper(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type,
    v8::Local<v8::Object> wrapper) {
  wrapper =
      ScriptWrappable::AssociateWithWrapper(isolate, wrapper_type, wrapper);
  if (!wrapper.IsEmpty()) {
    static const V8PrivateProperty::SymbolKey kPrivatePropertyRequest;
    V8PrivateProperty::GetSymbol(isolate, kPrivatePropertyRequest)
        .Set(wrapper, request_->ToV8(isolate, wrapper));
  }
  return wrapper;
}

IDBRequest* IDBCursor::update(ScriptState* script_state,
                              const ScriptValue& value,
                              ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBCursor::updateRequestSetup");
  static const char kReadOnlyUpdateErrorMessage[] =
      "The record may not be updated inside a read-only transaction.";
  if (!CheckForCommonExceptions(exception_state, kReadOnlyUpdateErrorMessage)) {
    return nullptr;
  }

  IDBObjectStore* object_store = EffectiveObjectStore();
  return object_store->DoPut(script_state, mojom::IDBPutMode::CursorUpdate,
                             MakeGarbageCollected<IDBRequest::Source>(this),
                             value, IdbPrimaryKey(), exception_state);
}

void IDBCursor::advance(unsigned count, ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBCursor::advanceRequestSetup");
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kCursorAdvance);
  if (!count) {
    exception_state.ThrowTypeError(
        "A count argument with value 0 (zero) was supplied, must be greater "
        "than 0.");
    return;
  }
  if (!CheckForCommonExceptions(exception_state, nullptr)) {
    return;
  }

  request_->SetPendingCursor(this);
  request_->AssignNewMetrics(std::move(metrics));
  got_value_ = false;

  CHECK(remote_.is_bound());
  AdvanceImpl(count, request_);
}

void IDBCursor::Continue(ScriptState* script_state,
                         const ScriptValue& key_value,
                         ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBCursor::continueRequestSetup");
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kCursorContinue);

  if (!CheckForCommonExceptions(exception_state, nullptr)) {
    return;
  }

  std::unique_ptr<IDBKey> key =
      key_value.IsUndefined() || key_value.IsNull()
          ? nullptr
          : CreateIDBKeyFromValue(script_state->GetIsolate(),
                                  key_value.V8Value(), exception_state);
  if (exception_state.HadException())
    return;
  if (key && !key->IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      IDBDatabase::kNotValidKeyErrorMessage);
    return;
  }
  Continue(std::move(key), nullptr, std::move(metrics), exception_state);
}

void IDBCursor::continuePrimaryKey(ScriptState* script_state,
                                   const ScriptValue& key_value,
                                   const ScriptValue& primary_key_value,
                                   ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBCursor::continuePrimaryKeyRequestSetup");
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kCursorContinuePrimaryKey);

  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return;
  }

  if (IsDeleted()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kSourceDeletedErrorMessage);
    return;
  }

  if (!source_->IsIDBIndex()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The cursor's source is not an index.");
    return;
  }

  if (direction_ != mojom::IDBCursorDirection::Next &&
      direction_ != mojom::IDBCursorDirection::Prev) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The cursor's direction is not 'next' or 'prev'.");
    return;
  }

  // Some of the checks in this helper will be redundant with those above, but
  // this is necessary to retain a specific ordering (see WPT
  // idbcursor-continuePrimaryKey-exception-order.html).
  if (!CheckForCommonExceptions(exception_state, nullptr)) {
    return;
  }

  std::unique_ptr<IDBKey> key = CreateIDBKeyFromValue(
      script_state->GetIsolate(), key_value.V8Value(), exception_state);
  if (exception_state.HadException()) {
    return;
  }
  if (!key->IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      IDBDatabase::kNotValidKeyErrorMessage);
    return;
  }

  std::unique_ptr<IDBKey> primary_key = CreateIDBKeyFromValue(
      script_state->GetIsolate(), primary_key_value.V8Value(), exception_state);
  if (exception_state.HadException())
    return;
  if (!primary_key->IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      IDBDatabase::kNotValidKeyErrorMessage);
    return;
  }

  Continue(std::move(key), std::move(primary_key), std::move(metrics),
           exception_state);
}

void IDBCursor::Continue(std::unique_ptr<IDBKey> key,
                         std::unique_ptr<IDBKey> primary_key,
                         IDBRequest::AsyncTraceState metrics,
                         ExceptionState& exception_state) {
  DCHECK(transaction_->IsActive());
  DCHECK(got_value_);
  DCHECK(!IsDeleted());
  DCHECK(!primary_key || (key && primary_key));

  const IDBKey* current_primary_key = IdbPrimaryKey();

  if (!key)
    key = IDBKey::CreateNone();

  if (key->GetType() != mojom::IDBKeyType::None) {
    DCHECK(key_);
    if (direction_ == mojom::IDBCursorDirection::Next ||
        direction_ == mojom::IDBCursorDirection::NextNoDuplicate) {
      const bool ok = key_->IsLessThan(key.get()) ||
                      (primary_key && key_->IsEqual(key.get()) &&
                       current_primary_key->IsLessThan(primary_key.get()));
      if (!ok) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataError,
            "The parameter is less than or equal to this cursor's position.");
        return;
      }

    } else {
      const bool ok = key->IsLessThan(key_.get()) ||
                      (primary_key && key->IsEqual(key_.get()) &&
                       primary_key->IsLessThan(current_primary_key));
      if (!ok) {
        exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                          "The parameter is greater than or "
                                          "equal to this cursor's position.");
        return;
      }
    }
  }

  if (!primary_key)
    primary_key = IDBKey::CreateNone();

  // FIXME: We're not using the context from when continue was called, which
  // means the callback will be on the original context openCursor was called
  // on. Is this right?
  request_->SetPendingCursor(this);
  request_->AssignNewMetrics(std::move(metrics));
  got_value_ = false;
  CHECK(remote_.is_bound());
  CursorContinue(key.get(), primary_key.get(), request_);
}

IDBRequest* IDBCursor::Delete(ScriptState* script_state,
                              ExceptionState& exception_state) {
  TRACE_EVENT0("IndexedDB", "IDBCursor::deleteRequestSetup");
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kCursorDelete);
  static const char kReadOnlyDeleteErrorMessage[] =
      "The record may not be deleted inside a read-only transaction.";
  if (!CheckForCommonExceptions(exception_state, kReadOnlyDeleteErrorMessage)) {
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  transaction_->db().Delete(
      transaction_->Id(), EffectiveObjectStore()->Id(), IdbPrimaryKey(),
      WTF::BindOnce(&IDBRequest::OnDelete, WrapPersistent(request)));
  return request;
}

void IDBCursor::Close() {
  value_ = nullptr;
  request_.Clear();
  remote_.reset();
  ResetPrefetchCache();
  GetGlobalCursorSet().erase(this);
}

ScriptValue IDBCursor::key(ScriptState* script_state) {
  key_dirty_ = false;
  return ScriptValue(script_state->GetIsolate(), key_->ToV8(script_state));
}

ScriptValue IDBCursor::primaryKey(ScriptState* script_state) {
  primary_key_dirty_ = false;
  const IDBKey* primary_key = primary_key_unless_injected_.get();
  if (!primary_key) {
#if DCHECK_IS_ON()
    DCHECK(value_has_injected_primary_key_);

    IDBObjectStore* object_store = EffectiveObjectStore();
    DCHECK(object_store->autoIncrement() &&
           !object_store->IdbKeyPath().IsNull());
#endif  // DCHECK_IS_ON()

    primary_key = value_->Value()->PrimaryKey();
  }
  return ScriptValue(script_state->GetIsolate(),
                     primary_key->ToV8(script_state));
}

ScriptValue IDBCursor::value(ScriptState* script_state) {
  DCHECK(IsA<IDBCursorWithValue>(this));

  IDBAny* value;
  if (value_) {
    value = value_;
#if DCHECK_IS_ON()
    if (value_has_injected_primary_key_) {
      IDBObjectStore* object_store = EffectiveObjectStore();
      DCHECK(object_store->autoIncrement() &&
             !object_store->IdbKeyPath().IsNull());
      AssertPrimaryKeyValidOrInjectable(script_state, value_->Value());
    }
#endif  // DCHECK_IS_ON()

  } else {
    value = MakeGarbageCollected<IDBAny>(IDBAny::kUndefinedType);
  }

  value_dirty_ = false;
  return ScriptValue(script_state->GetIsolate(), value->ToV8(script_state));
}

const IDBCursor::Source* IDBCursor::source() const {
  return source_.Get();
}

void IDBCursor::SetValueReady(std::unique_ptr<IDBKey> key,
                              std::unique_ptr<IDBKey> primary_key,
                              std::unique_ptr<IDBValue> value) {
  key_ = std::move(key);
  key_dirty_ = true;

  primary_key_unless_injected_ = std::move(primary_key);
  primary_key_dirty_ = true;

  got_value_ = true;

  if (!IsA<IDBCursorWithValue>(this))
    return;

  value_dirty_ = true;
#if DCHECK_IS_ON()
  value_has_injected_primary_key_ = false;
#endif  // DCHECK_IS_ON()

  if (!value) {
    value_ = nullptr;
    return;
  }

  IDBObjectStore* object_store = EffectiveObjectStore();
  if (object_store->autoIncrement() && !object_store->IdbKeyPath().IsNull()) {
    value->SetInjectedPrimaryKey(std::move(primary_key_unless_injected_),
                                 object_store->IdbKeyPath());
#if DCHECK_IS_ON()
    value_has_injected_primary_key_ = true;
#endif  // DCHECK_IS_ON()
  }

  value_ = MakeGarbageCollected<IDBAny>(std::move(value));
}

const IDBKey* IDBCursor::IdbPrimaryKey() const {
  if (primary_key_unless_injected_ || !value_)
    return primary_key_unless_injected_.get();

#if DCHECK_IS_ON()
  DCHECK(value_has_injected_primary_key_);
#endif  // DCHECK_IS_ON()
  return value_->Value()->PrimaryKey();
}

IDBObjectStore* IDBCursor::EffectiveObjectStore() const {
  switch (source_->GetContentType()) {
    case Source::ContentType::kIDBIndex:
      return source_->GetAsIDBIndex()->objectStore();
    case Source::ContentType::kIDBObjectStore:
      return source_->GetAsIDBObjectStore();
  }
  NOTREACHED();
}

bool IDBCursor::IsDeleted() const {
  switch (source_->GetContentType()) {
    case Source::ContentType::kIDBIndex:
      return source_->GetAsIDBIndex()->IsDeleted();
    case Source::ContentType::kIDBObjectStore:
      return source_->GetAsIDBObjectStore()->IsDeleted();
  }
  NOTREACHED();
}

// static
mojom::blink::IDBCursorDirection IDBCursor::V8EnumToDirection(
    V8IDBCursorDirection::Enum mode) {
  switch (mode) {
    case V8IDBCursorDirection::Enum::kNext:
      return mojom::blink::IDBCursorDirection::Next;
    case V8IDBCursorDirection::Enum::kNextunique:
      return mojom::blink::IDBCursorDirection::NextNoDuplicate;
    case V8IDBCursorDirection::Enum::kPrev:
      return mojom::blink::IDBCursorDirection::Prev;
    case V8IDBCursorDirection::Enum::kPrevunique:
      return mojom::blink::IDBCursorDirection::PrevNoDuplicate;
  }
}

// static
void IDBCursor::ResetCursorPrefetchCaches(int64_t transaction_id,
                                          IDBCursor* except_cursor) {
  CursorSet& cursor_set = GetGlobalCursorSet();

  for (IDBCursor* cursor : cursor_set) {
    if (cursor != except_cursor &&
        cursor->GetTransactionId() == transaction_id) {
      cursor->ResetPrefetchCache();
    }
  }
}

V8IDBCursorDirection IDBCursor::direction() const {
  switch (direction_) {
    case mojom::IDBCursorDirection::Next:
      return V8IDBCursorDirection(V8IDBCursorDirection::Enum::kNext);

    case mojom::IDBCursorDirection::NextNoDuplicate:
      return V8IDBCursorDirection(V8IDBCursorDirection::Enum::kNextunique);

    case mojom::IDBCursorDirection::Prev:
      return V8IDBCursorDirection(V8IDBCursorDirection::Enum::kPrev);

    case mojom::IDBCursorDirection::PrevNoDuplicate:
      return V8IDBCursorDirection(V8IDBCursorDirection::Enum::kPrevunique);
  }
  NOTREACHED();
}

void IDBCursor::AdvanceImpl(uint32_t count, IDBRequest* request) {
  if (count <= prefetch_keys_.size()) {
    CachedAdvance(count, request);
    return;
  }
  ResetPrefetchCache();

  // Reset all cursor prefetch caches except for this cursor.
  ResetCursorPrefetchCaches(transaction_->Id(), this);

  remote_->Advance(
      count, WTF::BindOnce(&IDBCursor::AdvanceCallback, WrapPersistent(this),
                           WrapWeakPersistent(request)));
}

void IDBCursor::AdvanceCallback(IDBRequest* request,
                                mojom::blink::IDBCursorResultPtr result) {
  // May be null in tests.
  if (request) {
    request->OnAdvanceCursor(std::move(result));
  }
}

void IDBCursor::CursorContinue(const IDBKey* key,
                               const IDBKey* primary_key,
                               IDBRequest* request) {
  DCHECK(key && primary_key);

  if (key->GetType() == mojom::blink::IDBKeyType::None &&
      primary_key->GetType() == mojom::blink::IDBKeyType::None) {
    // No key(s), so this would qualify for a prefetch.
    ++continue_count_;

    if (!prefetch_keys_.empty()) {
      // We have a prefetch cache, so serve the result from that.
      CachedContinue(request);
      return;
    }

    if (continue_count_ > kPrefetchContinueThreshold) {
      // Request pre-fetch.
      ++pending_onsuccess_callbacks_;

      remote_->Prefetch(
          prefetch_amount_,
          WTF::BindOnce(&IDBCursor::PrefetchCallback, WrapPersistent(this),
                        WrapWeakPersistent(request)));

      // Increase prefetch_amount_ exponentially.
      prefetch_amount_ *= 2;
      if (prefetch_amount_ > kMaxPrefetchAmount) {
        prefetch_amount_ = kMaxPrefetchAmount;
      }

      return;
    }
  } else {
    // Key argument supplied. We couldn't prefetch this.
    ResetPrefetchCache();
  }

  // Reset all cursor prefetch caches except for this cursor.
  ResetCursorPrefetchCaches(transaction_->Id(), this);
  remote_->Continue(
      IDBKey::Clone(key), IDBKey::Clone(primary_key),
      WTF::BindOnce(&IDBCursor::AdvanceCallback, WrapPersistent(this),
                    WrapWeakPersistent(request)));
}

void IDBCursor::PrefetchCallback(IDBRequest* request,
                                 mojom::blink::IDBCursorResultPtr result) {
  if (!result->is_error_result() && !result->is_empty() &&
      result->get_values()->keys.size() ==
          result->get_values()->primary_keys.size() &&
      result->get_values()->keys.size() ==
          result->get_values()->values.size()) {
    SetPrefetchData(std::move(result->get_values()->keys),
                    std::move(result->get_values()->primary_keys),
                    std::move(result->get_values()->values));
    CachedContinue(request);
  } else if (request) {
    // This is the error case. We want error handling to match the AdvanceCursor
    // case.
    request->OnAdvanceCursor(std::move(result));
  }
}

void IDBCursor::PostSuccessHandlerCallback() {
  pending_onsuccess_callbacks_--;

  // If the onsuccess callback called continue()/advance() on the cursor
  // again, and that request was served by the prefetch cache, then
  // pending_onsuccess_callbacks_ would be incremented. If not, it means the
  // callback did something else, or nothing at all, in which case we need to
  // reset the cache.

  if (pending_onsuccess_callbacks_ == 0) {
    ResetPrefetchCache();
  }
}

void IDBCursor::SetPrefetchData(Vector<std::unique_ptr<IDBKey>> keys,
                                Vector<std::unique_ptr<IDBKey>> primary_keys,
                                Vector<std::unique_ptr<IDBValue>> values) {
  // Keys and values are stored in reverse order so that a cache'd continue can
  // pop a value off of the back and prevent new memory allocations.
  prefetch_keys_.AppendRange(std::make_move_iterator(keys.rbegin()),
                             std::make_move_iterator(keys.rend()));
  prefetch_primary_keys_.AppendRange(
      std::make_move_iterator(primary_keys.rbegin()),
      std::make_move_iterator(primary_keys.rend()));
  prefetch_values_.AppendRange(std::make_move_iterator(values.rbegin()),
                               std::make_move_iterator(values.rend()));

  used_prefetches_ = 0;
  pending_onsuccess_callbacks_ = 0;
}

void IDBCursor::CachedAdvance(uint32_t count, IDBRequest* request) {
  DCHECK_GE(prefetch_keys_.size(), count);
  DCHECK_EQ(prefetch_primary_keys_.size(), prefetch_keys_.size());
  DCHECK_EQ(prefetch_values_.size(), prefetch_keys_.size());

  while (count > 1) {
    prefetch_keys_.pop_back();
    prefetch_primary_keys_.pop_back();
    prefetch_values_.pop_back();
    ++used_prefetches_;
    --count;
  }

  CachedContinue(request);
}

void IDBCursor::CachedContinue(IDBRequest* request) {
  DCHECK_GT(prefetch_keys_.size(), 0ul);
  DCHECK_EQ(prefetch_primary_keys_.size(), prefetch_keys_.size());
  DCHECK_EQ(prefetch_values_.size(), prefetch_keys_.size());

  // Keys and values are stored in reverse order so that a cache'd continue can
  // pop a value off of the back and prevent new memory allocations.
  std::unique_ptr<IDBKey> key = std::move(prefetch_keys_.back());
  std::unique_ptr<IDBKey> primary_key =
      std::move(prefetch_primary_keys_.back());
  std::unique_ptr<IDBValue> value = std::move(prefetch_values_.back());

  prefetch_keys_.pop_back();
  prefetch_primary_keys_.pop_back();
  prefetch_values_.pop_back();
  ++used_prefetches_;

  ++pending_onsuccess_callbacks_;

  if (!continue_count_) {
    // The cache was invalidated by a call to ResetPrefetchCache()
    // after the RequestIDBCursorPrefetch() was made. Now that the
    // initiating continue() call has been satisfied, discard
    // the rest of the cache.
    ResetPrefetchCache();
  }

  // May be null in tests.
  if (request) {
    // Since the cached request is not round tripping through the browser
    // process, the request has to be explicitly queued. See step 11 of
    // https://www.w3.org/TR/IndexedDB/#dom-idbcursor-continue
    // This is prevented from becoming out-of-order with other requests that
    // do travel through the browser process by the fact that any previous
    // request currently making its way through the browser would have already
    // cleared this cache via `ResetCursorPrefetchCaches()`.
    request->GetExecutionContext()
        ->GetTaskRunner(TaskType::kDatabaseAccess)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&IDBRequest::HandleResponseAdvanceCursor,
                                 WrapWeakPersistent(request), std::move(key),
                                 std::move(primary_key), std::move(value)));
  }
}

void IDBCursor::ResetPrefetchCache() {
  continue_count_ = 0;
  prefetch_amount_ = kMinPrefetchAmount;

  if (prefetch_keys_.empty()) {
    // No prefetch cache, so no need to reset the cursor in the back-end.
    return;
  }

  // Reset the back-end cursor.
  if (remote_.is_bound()) {
    remote_->PrefetchReset(used_prefetches_);
  }

  // Reset the prefetch cache.
  prefetch_keys_.clear();
  prefetch_primary_keys_.clear();
  prefetch_values_.clear();

  pending_onsuccess_callbacks_ = 0;
}

int64_t IDBCursor::GetTransactionId() const {
  return transaction_->Id();
}

bool IDBCursor::CheckForCommonExceptions(ExceptionState& exception_state,
                                         const char* read_only_error_message) {
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return false;
  }
  if (read_only_error_message && transaction_->IsReadOnly()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kReadOnlyError,
                                      read_only_error_message);
    return false;
  }
  if (IsDeleted()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kSourceDeletedErrorMessage);
    return false;
  }
  if (!got_value_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kNoValueErrorMessage);
    return false;
  }
  if (read_only_error_message && IsKeyCursor()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kIsKeyCursorErrorMessage);
    return false;
  }
  ExecutionContext* context =
      request_ ? request_->GetExecutionContext() : nullptr;
  if (!context || context->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return false;
  }

  return true;
}

}  // namespace blink
```