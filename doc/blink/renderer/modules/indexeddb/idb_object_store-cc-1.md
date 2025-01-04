Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink engine and deals with IndexedDB object stores.

Here's a breakdown of the thinking process to arrive at the summary:

1. **Identify the core class:** The code is within `IDBObjectStore`. This is the central entity to focus on.

2. **Understand the context:** The code interacts with IndexedDB, JavaScript, HTML, and potentially CSS (indirectly through web page interactions). The "Part 2" indication suggests this is a continuation of related functionality.

3. **Analyze the methods:**  Go through each method and understand its purpose. Key methods and their functionalities include:
    * `createIndex`: Creating a new index on the object store.
    * `index`: Retrieving an existing index by name.
    * `deleteIndex`: Deleting an index.
    * `openCursor`: Creating a cursor to iterate over the object store's data.
    * `openKeyCursor`: Creating a cursor to iterate over the object store's keys.
    * `count`:  Getting the number of records in the object store.
    * `MarkDeleted`: Marking the object store as deleted (typically during schema changes).
    * `ClearIndexCache`: Clearing the cache of `IDBIndex` objects.
    * `RevertMetadata`:  Reverting metadata changes during a transaction rollback.
    * `RevertDeletedIndexMetadata`: Reverting metadata for a deleted index.
    * `RenameIndex`: Renaming an existing index.
    * `FindIndexId`:  Finding the internal ID of an index by its name.
    * `CreateGetAllRequest`:  Fetching multiple records from the object store.
    * `db`:  Accessing the parent `IDBDatabase`.

4. **Identify relationships with web technologies:**
    * **JavaScript:**  These methods are called from JavaScript code that uses the IndexedDB API. Examples: `objectStore.createIndex()`, `objectStore.index()`, etc.
    * **HTML:**  HTML provides the structure of web pages where JavaScript code interacting with IndexedDB is executed.
    * **CSS:**  While not directly involved in the core logic, CSS styles the user interface elements that might trigger actions leading to IndexedDB operations.

5. **Recognize logic and error handling:**  Notice the checks for valid states, transaction status, and error conditions that lead to throwing DOM exceptions.

6. **Infer user actions and debugging:** Consider how a user's interaction with a web page might trigger these methods and how developers would use this code for debugging.

7. **Address "Part 2" and summarize:**  Combine the understanding of the methods to provide a concise summary of the object store's capabilities. Since it's "Part 2," focus on the aspects *not* covered in the likely "Part 1" (which would probably include methods for adding, getting, and deleting data directly in the object store).

8. **Structure the output:** Organize the information logically with clear headings and examples.

**(Self-Correction during the process):**

* **Initial thought:**  Focus heavily on the low-level implementation details.
* **Correction:**  Shift focus to the high-level functionalities and how they relate to web development concepts. The user is likely interested in *what* the code does, not just *how* it's implemented.
* **Initial thought:**  Treat each method in isolation.
* **Correction:**  Group related methods together (e.g., index creation, retrieval, deletion) to provide a more cohesive understanding.
* **Initial thought:**  Overlook the "Part 2" aspect.
* **Correction:**  Emphasize that this section deals primarily with index management and related operations, suggesting that other core object store functions might be in "Part 1."

By following these steps, the detailed and informative summary provided earlier can be generated.
这是 `blink/renderer/modules/indexeddb/idb_object_store.cc` 文件的第二部分，主要延续了第一部分的功能，集中在 **管理 IndexedDB 对象存储的索引** 以及与游标相关的操作。

以下是这部分代码的功能归纳：

**核心功能：索引管理**

* **创建索引 (`createIndex`)**:
    * 允许在对象存储上创建新的索引。
    * 接收索引名称 (`name`)、索引的键路径 (`keyPath`) 和可选的配置项 (`options`)（例如 `unique` 和 `multiEntry`）。
    * **与 JavaScript 关系**:  对应 JavaScript 中 `IDBObjectStore.createIndex()` 方法的底层实现。
        * **举例**: JavaScript 代码 `objectStore.createIndex("email", "email", { unique: true });` 会调用此 C++ 方法。
    * **逻辑推理**:
        * **假设输入**:  尝试在一个名为 "users" 的对象存储上创建一个名为 "ageIdx"，键路径为 "age" 的索引。
        * **输出**: 如果一切顺利，将在该对象存储的元数据中添加新的索引信息，并可能创建一个后台任务来填充索引。
    * **常见错误**:
        * 尝试创建已存在的索引。
        * 使用无效的键路径。
        * 在键路径为数组的情况下设置 `multiEntry` 为 `true`。
        * 在事务未激活或数据库已关闭的情况下尝试创建索引。
    * **用户操作到达此处**: 用户通过 JavaScript 调用 `objectStore.createIndex()`。

* **获取索引 (`index`)**:
    * 根据索引名称 (`name`) 获取对象存储上的索引对象。
    * **与 JavaScript 关系**: 对应 JavaScript 中 `IDBObjectStore.index()` 方法的底层实现。
        * **举例**: JavaScript 代码 `const index = objectStore.index("email");` 会调用此 C++ 方法。
    * **逻辑推理**:
        * **假设输入**:  尝试获取名为 "cityIdx" 的索引。
        * **输出**: 如果索引存在，返回对应的 `IDBIndex` 对象；否则抛出异常。
    * **常见错误**:
        * 尝试获取不存在的索引。
        * 在对象存储已删除或事务已完成的情况下尝试获取索引。
    * **用户操作到达此处**: 用户通过 JavaScript 调用 `objectStore.index()`。

* **删除索引 (`deleteIndex`)**:
    * 从对象存储中删除指定的索引。
    * **重要**: 只能在版本变更事务中进行。
    * **与 JavaScript 关系**: 对应 JavaScript 中 `IDBObjectStore.deleteIndex()` 方法的底层实现。
        * **举例**: JavaScript 代码 `objectStore.deleteIndex("email");` 会调用此 C++ 方法。
    * **逻辑推理**:
        * **假设输入**:  尝试删除名为 "zipCodeIdx" 的索引。
        * **输出**: 如果索引存在且在版本变更事务中，该索引将被删除，相关的元数据会被更新。
    * **常见错误**:
        * 在非版本变更事务中尝试删除索引。
        * 尝试删除不存在的索引。
        * 在对象存储已删除或事务未激活的情况下尝试删除索引。
    * **用户操作到达此处**: 用户通过 JavaScript 调用 `objectStore.deleteIndex()`。

* **重命名索引 (`RenameIndex`)**:
    * 在版本变更事务中重命名索引。
    * **逻辑推理**:
        * **假设输入**: 将 ID 为 5 的索引重命名为 "newIndexName"。
        * **输出**: 数据库中该索引的名称会被更新，内部的 `index_map_` 也会相应更新。

**核心功能：游标操作**

* **打开游标 (`openCursor`)**:
    * 创建一个用于遍历对象存储中数据的游标。
    * 可以指定遍历的范围 (`range`) 和方向 (`direction`)。
    * **与 JavaScript 关系**: 对应 JavaScript 中 `IDBObjectStore.openCursor()` 方法的底层实现。
        * **举例**: JavaScript 代码 `objectStore.openCursor().onsuccess = function(event) { ... };` 会调用此 C++ 方法。
    * **逻辑推理**:
        * **假设输入**:  打开一个从头到尾遍历所有记录的游标。
        * **输出**: 返回一个 `IDBRequest` 对象，当请求成功时，会返回一个 `IDBCursor` 对象，允许逐个访问对象存储中的记录。
    * **常见错误**:
        * 在对象存储已删除或事务未激活的情况下尝试打开游标。
    * **用户操作到达此处**: 用户通过 JavaScript 调用 `objectStore.openCursor()`。

* **打开键游标 (`openKeyCursor`)**:
    * 创建一个用于遍历对象存储中键的游标，只返回键，不返回完整的值。
    * **与 JavaScript 关系**: 对应 JavaScript 中 `IDBObjectStore.openKeyCursor()` 方法的底层实现。
        * **举例**: JavaScript 代码 `objectStore.openKeyCursor().onsuccess = function(event) { ... };` 会调用此 C++ 方法。
    * **用户操作到达此处**: 用户通过 JavaScript 调用 `objectStore.openKeyCursor()`。

**其他功能**

* **计数 (`count`)**:
    * 返回对象存储中符合指定范围的记录数量。
    * **与 JavaScript 关系**: 对应 JavaScript 中 `IDBObjectStore.count()` 方法的底层实现。
        * **举例**: JavaScript 代码 `objectStore.count().onsuccess = function(event) { ... };` 会调用此 C++ 方法。
    * **用户操作到达此处**: 用户通过 JavaScript 调用 `objectStore.count()`。

* **标记删除 (`MarkDeleted`)**:
    * 标记对象存储为已删除状态。通常在版本变更事务中发生。

* **清除索引缓存 (`ClearIndexCache`)**:
    * 清理缓存的 `IDBIndex` 对象。

* **回滚元数据 (`RevertMetadata`, `RevertDeletedIndexMetadata`)**:
    * 在事务回滚时，将对象存储或索引的元数据恢复到之前的状态。

* **查找索引 ID (`FindIndexId`)**:
    * 根据索引名称查找其内部 ID。

* **创建 GetAll 请求 (`CreateGetAllRequest`)**:
    * 创建一个请求来获取对象存储中指定范围内的所有数据或键。
    * **与 JavaScript 关系**: 对应 JavaScript 中 `IDBObjectStore.getAll()` 和 `IDBObjectStore.getAllKeys()` 方法的底层实现。
    * **用户操作到达此处**: 用户通过 JavaScript 调用 `objectStore.getAll()` 或 `objectStore.getAllKeys()`。

* **获取数据库对象 (`db`)**:
    * 提供访问所属 `IDBDatabase` 对象的接口。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户与网页交互**: 用户在网页上执行某些操作，例如点击按钮、提交表单等。
2. **JavaScript 代码执行**: 网页上的 JavaScript 代码响应用户操作，并调用 IndexedDB API。
3. **打开或使用数据库**:  JavaScript 代码可能首先打开一个 IndexedDB 数据库连接 (`indexedDB.open(...)`)。
4. **开始事务**:  为了操作对象存储，需要开始一个事务 (`db.transaction(...)`)。
5. **获取对象存储**:  通过事务获取需要操作的对象存储 (`transaction.objectStore(...)`)。
6. **调用对象存储的方法**: 用户尝试创建、获取、删除索引，或者打开游标、计数、获取所有数据等，例如：
    * `objectStore.createIndex("name", "name");`  -> 调用 `IDBObjectStore::createIndex`
    * `objectStore.index("email");` -> 调用 `IDBObjectStore::index`
    * `objectStore.openCursor();` -> 调用 `IDBObjectStore::openCursor`
    * `objectStore.count();` -> 调用 `IDBObjectStore::count`
7. **C++ 代码执行**:  Blink 引擎将 JavaScript 的 API 调用映射到相应的 C++ 方法，例如这里的 `IDBObjectStore` 中的方法。

**总结来说，这部分 `IDBObjectStore.cc` 代码主要负责实现 IndexedDB 对象存储的索引管理功能（创建、获取、删除、重命名）以及提供用于遍历数据的游标操作，并通过这些功能与 JavaScript 的 IndexedDB API 交互，最终服务于网页上使用 IndexedDB 的用户操作。**

Prompt: 
```
这是目录为blink/renderer/modules/indexeddb/idb_object_store.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
 IDBDatabase::kIndexNameTakenErrorMessage);
    return nullptr;
  }
  if (!key_path.IsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The keyPath argument contains an invalid key path.");
    return nullptr;
  }
  if (key_path.GetType() == mojom::IDBKeyPathType::Array &&
      options->multiEntry()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The keyPath argument was an array and the multiEntry option is true.");
    return nullptr;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  int64_t index_id = metadata_->max_index_id + 1;
  DCHECK_NE(index_id, IDBIndexMetadata::kInvalidId);
  db().CreateIndex(transaction_->Id(), Id(), index_id, name, key_path,
                   options->unique(), options->multiEntry());

  ++metadata_->max_index_id;

  scoped_refptr<IDBIndexMetadata> index_metadata =
      base::AdoptRef(new IDBIndexMetadata(
          name, index_id, key_path, options->unique(), options->multiEntry()));
  auto* index =
      MakeGarbageCollected<IDBIndex>(index_metadata, this, transaction_.Get());
  index_map_.Set(name, index);
  metadata_->indexes.Set(index_id, index_metadata);

  DCHECK(!exception_state.HadException());
  if (exception_state.HadException())
    return nullptr;

  IDBRequest* index_request =
      openCursor(script_state, nullptr, mojom::IDBCursorDirection::Next,
                 mojom::IDBTaskType::Preemptive, std::move(metrics));
  index_request->PreventPropagation();

  // This is kept alive by being the success handler of the request, which is in
  // turn kept alive by the owning transaction.
  auto* index_populator = MakeGarbageCollected<IndexPopulator>(
      script_state, &transaction()->db(), transaction_->Id(), Id(), metadata_,
      std::move(index_metadata));
  index_request->setOnsuccess(index_populator);
  return index;
}

IDBIndex* IDBObjectStore::index(const String& name,
                                ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::index", "store_name",
               metadata_->name.Utf8());
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (transaction_->IsFinished() || transaction_->IsFinishing()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kTransactionFinishedErrorMessage);
    return nullptr;
  }

  IDBIndexMap::iterator it = index_map_.find(name);
  if (it != index_map_.end())
    return it->value.Get();

  int64_t index_id = FindIndexId(name);
  if (index_id == IDBIndexMetadata::kInvalidId) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      IDBDatabase::kNoSuchIndexErrorMessage);
    return nullptr;
  }

  DCHECK(Metadata().indexes.Contains(index_id));
  scoped_refptr<IDBIndexMetadata> index_metadata =
      Metadata().indexes.at(index_id);
  DCHECK(index_metadata.get());
  auto* index = MakeGarbageCollected<IDBIndex>(std::move(index_metadata), this,
                                               transaction_.Get());
  index_map_.Set(name, index);
  return index;
}

void IDBObjectStore::deleteIndex(const String& name,
                                 ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::deleteIndex", "store_name",
               metadata_->name.Utf8());
  if (!transaction_->IsVersionChange()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kNotVersionChangeTransactionErrorMessage);
    return;
  }
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return;
  }
  int64_t index_id = FindIndexId(name);
  if (index_id == IDBIndexMetadata::kInvalidId) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      IDBDatabase::kNoSuchIndexErrorMessage);
    return;
  }
  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return;
  }

  db().DeleteIndex(transaction_->Id(), Id(), index_id);

  metadata_->indexes.erase(index_id);
  IDBIndexMap::iterator it = index_map_.find(name);
  if (it != index_map_.end()) {
    transaction_->IndexDeleted(it->value);
    it->value->MarkDeleted();
    index_map_.erase(name);
  }
}

IDBRequest* IDBObjectStore::openCursor(ScriptState* script_state,
                                       const ScriptValue& range,
                                       const V8IDBCursorDirection& v8_direction,
                                       ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::openCursorRequestSetup",
               "store_name", metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreOpenCursor);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }

  mojom::IDBCursorDirection direction =
      IDBCursor::V8EnumToDirection(v8_direction.AsEnum());
  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), range, exception_state);
  if (exception_state.HadException())
    return nullptr;

  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  return openCursor(script_state, key_range, direction,
                    mojom::IDBTaskType::Normal, std::move(metrics));
}

IDBRequest* IDBObjectStore::openCursor(ScriptState* script_state,
                                       IDBKeyRange* range,
                                       mojom::IDBCursorDirection direction,
                                       mojom::IDBTaskType task_type,
                                       IDBRequest::AsyncTraceState metrics) {
  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  request->SetCursorDetails(indexed_db::kCursorKeyAndValue, direction);

  db().OpenCursor(Id(), IDBIndexMetadata::kInvalidId, range, direction, false,
                  task_type, request);
  return request;
}

IDBRequest* IDBObjectStore::openKeyCursor(
    ScriptState* script_state,
    const ScriptValue& range,
    const V8IDBCursorDirection& v8_direction,
    ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::openKeyCursorRequestSetup",
               "store_name", metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreOpenKeyCursor);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }

  mojom::IDBCursorDirection direction =
      IDBCursor::V8EnumToDirection(v8_direction.AsEnum());
  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), range, exception_state);
  if (exception_state.HadException())
    return nullptr;

  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  request->SetCursorDetails(indexed_db::kCursorKeyOnly, direction);

  db().OpenCursor(Id(), IDBIndexMetadata::kInvalidId, key_range, direction,
                  true, mojom::blink::IDBTaskType::Normal, request);
  return request;
}

IDBRequest* IDBObjectStore::count(ScriptState* script_state,
                                  const ScriptValue& range,
                                  ExceptionState& exception_state) {
  TRACE_EVENT1("IndexedDB", "IDBObjectStore::countRequestSetup", "store_name",
               metadata_->name.Utf8());
  IDBRequest::AsyncTraceState metrics(
      IDBRequest::TypeForMetrics::kObjectStoreCount);
  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }
  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }

  IDBKeyRange* key_range = IDBKeyRange::FromScriptValue(
      ExecutionContext::From(script_state), range, exception_state);
  if (exception_state.HadException())
    return nullptr;

  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().Count(transaction_->Id(), Id(), IDBIndexMetadata::kInvalidId, key_range,
             WTF::BindOnce(&IDBRequest::OnCount, WrapWeakPersistent(request)));
  return request;
}

void IDBObjectStore::MarkDeleted() {
  DCHECK(transaction_->IsVersionChange())
      << "An object store got deleted outside a versionchange transaction.";

  deleted_ = true;
  metadata_->indexes.clear();

  for (auto& it : index_map_) {
    IDBIndex* index = it.value;
    index->MarkDeleted();
  }
}

void IDBObjectStore::ClearIndexCache() {
  DCHECK(!transaction_->IsActive() || (IsDeleted() && IsNewlyCreated()));

#if DCHECK_IS_ON()
  // There is no harm in having ClearIndexCache() happen multiple times for
  // the same object. We assert that it is called once to uncover potential
  // object store accounting bugs.
  DCHECK(!clear_index_cache_called_);
  clear_index_cache_called_ = true;
#endif  // DCHECK_IS_ON()

  index_map_.clear();
}

void IDBObjectStore::RevertMetadata(
    scoped_refptr<IDBObjectStoreMetadata> old_metadata) {
  DCHECK(transaction_->IsVersionChange());
  DCHECK(!transaction_->IsActive());
  DCHECK(old_metadata.get());
  DCHECK(Id() == old_metadata->id);

  for (auto& index : index_map_.Values()) {
    const int64_t index_id = index->Id();

    if (index->IsNewlyCreated(*old_metadata)) {
      // The index was created by this transaction. According to the spec,
      // its metadata will remain as-is.
      DCHECK(!old_metadata->indexes.Contains(index_id));
      index->MarkDeleted();
      continue;
    }

    // The index was created in a previous transaction. We need to revert
    // its metadata. The index might have been deleted, so we
    // unconditionally reset the deletion marker.
    DCHECK(old_metadata->indexes.Contains(index_id));
    scoped_refptr<IDBIndexMetadata> old_index_metadata =
        old_metadata->indexes.at(index_id);
    index->RevertMetadata(std::move(old_index_metadata));
  }
  metadata_ = std::move(old_metadata);

  // An object store's metadata will only get reverted if the index was in the
  // database when the versionchange transaction started.
  deleted_ = false;
}

void IDBObjectStore::RevertDeletedIndexMetadata(IDBIndex& deleted_index) {
  DCHECK(transaction_->IsVersionChange());
  DCHECK(!transaction_->IsActive());
  DCHECK(deleted_index.objectStore() == this);
  DCHECK(deleted_index.IsDeleted());

  const int64_t index_id = deleted_index.Id();
  DCHECK(metadata_->indexes.Contains(index_id))
      << "The object store's metadata was not correctly reverted";
  scoped_refptr<IDBIndexMetadata> old_index_metadata =
      metadata_->indexes.at(index_id);
  deleted_index.RevertMetadata(std::move(old_index_metadata));
}

void IDBObjectStore::RenameIndex(int64_t index_id, const String& new_name) {
  DCHECK(transaction_->IsVersionChange());
  DCHECK(transaction_->IsActive());

  db().RenameIndex(transaction_->Id(), Id(), index_id, new_name);

  auto metadata_iterator = metadata_->indexes.find(index_id);
  CHECK_NE(metadata_iterator, metadata_->indexes.end(),
           base::NotFatalUntil::M130)
      << "Invalid index_id";
  const String& old_name = metadata_iterator->value->name;

  DCHECK(index_map_.Contains(old_name))
      << "The index had to be accessed in order to be renamed.";
  DCHECK(!index_map_.Contains(new_name));
  index_map_.Set(new_name, index_map_.Take(old_name));

  metadata_iterator->value->name = new_name;
}

int64_t IDBObjectStore::FindIndexId(const String& name) const {
  for (const auto& it : Metadata().indexes) {
    if (it.value->name == name) {
      DCHECK_NE(it.key, IDBIndexMetadata::kInvalidId);
      return it.key;
    }
  }
  return IDBIndexMetadata::kInvalidId;
}

IDBRequest* IDBObjectStore::CreateGetAllRequest(
    IDBRequest::TypeForMetrics type_for_metrics,
    ScriptState* script_state,
    const ScriptValue& key_range_script_value,
    mojom::blink::IDBGetAllResultType result_type,
    uint32_t max_count,
    mojom::blink::IDBCursorDirection direction,
    ExceptionState& exception_state) {
  IDBRequest::AsyncTraceState metrics(type_for_metrics);

  if (!max_count) {
    max_count = std::numeric_limits<uint32_t>::max();
  }

  if (IsDeleted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        IDBDatabase::kObjectStoreDeletedErrorMessage);
    return nullptr;
  }

  if (!transaction_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTransactionInactiveError,
        transaction_->InactiveErrorMessage());
    return nullptr;
  }

  IDBKeyRange* key_range =
      IDBKeyRange::FromScriptValue(ExecutionContext::From(script_state),
                                   key_range_script_value, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  if (!db().IsConnectionOpen()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      IDBDatabase::kDatabaseClosedErrorMessage);
    return nullptr;
  }

  IDBRequest* request = IDBRequest::Create(
      script_state, this, transaction_.Get(), std::move(metrics));
  db().GetAll(transaction_->Id(), Id(), IDBIndexMetadata::kInvalidId, key_range,
              result_type, max_count, direction, request);
  return request;
}

IDBDatabase& IDBObjectStore::db() const {
  return transaction_->db();
}

}  // namespace blink

"""


```