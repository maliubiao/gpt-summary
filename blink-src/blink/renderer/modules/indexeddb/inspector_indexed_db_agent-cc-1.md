Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink engine and specifically relates to the IndexedDB inspector agent.

I need to:
1. **Identify the main purpose of the code:** It seems to handle requests from the DevTools to inspect and manipulate IndexedDB data.
2. **List the core functionalities:**  Based on the function names, these include requesting database names, requesting a specific database, requesting data from an object store, getting metadata of an object store, deleting entries from an object store, clearing an object store, and deleting a database.
3. **Analyze the interactions with web technologies (JavaScript, HTML, CSS):**  IndexedDB is a JavaScript API. This C++ code acts as a bridge between the DevTools and the underlying IndexedDB implementation in the browser. The user interacts with IndexedDB via JavaScript in a webpage (HTML context), and the DevTools (likely accessed through a browser UI rendered with HTML/CSS) uses this agent to inspect it.
4. **Identify potential logic and data flow:** The code uses callbacks and asynchronous operations. It resolves frames based on security origin and interacts with the IDBFactory and IDBDatabase interfaces.
5. **Point out potential user or programming errors:** Incorrect key ranges, database names, or object store names could lead to errors.
6. **Describe the user steps to reach this code:**  The user would interact with a webpage that uses IndexedDB and then open the browser's DevTools, navigating to the "Application" or "Storage" tab and selecting "IndexedDB".
7. **Focus on summarizing the functionality for the second part of the request.**
这是 `blink/renderer/modules/indexeddb/inspector_indexed_db_agent.cc` 文件的第二部分，延续了第一部分的功能，主要负责处理来自 Chrome 开发者工具（DevTools）关于 IndexedDB 的各种操作请求。

**功能归纳：**

这部分代码的核心功能是**响应和处理来自开发者工具的关于 IndexedDB 的各种操作请求**。 它提供了一系列方法，允许开发者通过 DevTools 界面与浏览器中的 IndexedDB 数据库进行交互，包括：

* **`getMetadata`**: 获取指定数据库中指定对象存储的元数据，例如条目数量和键生成器的当前值。
* **`deleteObjectStoreEntries`**:  删除指定数据库的指定对象存储中符合特定键值范围的条目。
* **`clearObjectStore`**: 清空指定数据库的指定对象存储中的所有条目。
* **`deleteDatabase`**: 删除指定名称的 IndexedDB 数据库。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript**:  这些功能直接响应开发者在 DevTools 中对 IndexedDB 进行的操作。例如，当开发者在 DevTools 的 "Application" -> "IndexedDB" 面板中点击 "Clear object store" 按钮时，就会触发 `clearObjectStore` 方法。  用户在网页中编写的 JavaScript 代码使用 IndexedDB API 来创建和操作数据库，而这里的 C++ 代码则允许开发者 *观察* 和 *管理* 这些数据库。
* **HTML**:  用户通常通过浏览器访问包含 JavaScript 代码的 HTML 页面，这些 JavaScript 代码可能会使用 IndexedDB 来存储数据。开发者打开 DevTools 来检查和操作这些数据，DevTools 自身的界面也是用 HTML/CSS 构建的。
* **CSS**: CSS 主要用于 DevTools 界面的样式渲染，与这部分 IndexedDB 功能的直接逻辑关系较弱，但它确保了开发者工具用户界面的可读性和易用性，从而方便开发者进行 IndexedDB 的管理和调试。

**逻辑推理的假设输入与输出：**

以 `getMetadata` 函数为例：

* **假设输入：**
    * `security_origin`:  例如 `"https://example.com"`，指定数据库的安全来源。
    * `database_name`: 例如 `"mydatabase"`，指定要查询的数据库名称。
    * `object_store_name`: 例如 `"customers"`，指定要查询元数据的对象存储名称。
* **逻辑处理：**
    1. `ResolveFrame` 确认安全来源对应的 LocalFrame 是否存在。
    2. 创建 `GetMetadata` 对象，传入对象存储名称和回调函数。
    3. `GetMetadata::Start` 获取数据库连接，开启只读事务。
    4. 执行两个子任务：
        * 使用 `IDBObjectStore::count` 获取对象存储中的条目数量。
        * 使用 `IDBObjectStore::getKeyGeneratorCurrentNumber` 获取键生成器的当前值。
    5. 两个子任务完成后，通过回调函数将结果返回。
* **假设输出（成功情况）：**
    * DevTools 收到一个包含 `entries_count`（例如 `100`）和 `key_generator_current_number`（例如 `5`）的成功响应。

以 `deleteObjectStoreEntries` 函数为例：

* **假设输入：**
    * `security_origin`: 例如 `"https://example.com"`
    * `database_name`: 例如 `"orders"`
    * `object_store_name`: 例如 `"pending_orders"`
    * `key_range`: 例如 `{ lower: 10, upper: 20, lowerOpen: false, upperOpen: true }`，表示删除键值在 10 (包含) 到 20 (不包含) 之间的条目。
* **逻辑处理：**
    1. `ResolveFrame` 确认安全来源。
    2. 将 DevTools 传递的 `KeyRange` 转换为 Blink 内部的 `IDBKeyRange`。
    3. 创建 `DeleteObjectStoreEntries` 对象，传入对象存储名称和键值范围。
    4. `DeleteObjectStoreEntries::Start` 获取数据库连接，开启读写事务。
    5. 调用 `IDBObjectStore::deleteFunction` 删除指定范围的条目。
    6. 操作成功后，通过回调函数发送成功响应。
* **假设输出（成功情况）：**
    * DevTools 收到一个表示删除操作成功的响应。

**涉及用户或者编程常见的使用错误举例说明：**

* **错误的数据库或对象存储名称：** 用户在 DevTools 中输入了不存在的数据库或对象存储名称，会导致 `ObjectStoreForTransaction` 返回空指针，从而触发错误回调，例如 "Could not get object store"。
* **无效的键值范围：** 用户提供的键值范围无法被解析成有效的 `IDBKeyRange`，例如类型错误或逻辑错误，`IdbKeyRangeFromKeyRange` 会返回空指针，导致 `request_callback->sendFailure(protocol::Response::ServerError("Can not parse key range"));`。
* **在只读模式下尝试修改数据：**  `deleteObjectStoreEntries` 和 `clearObjectStore` 需要读写事务。如果在某些情况下（尽管 DevTools 通常会确保这一点），尝试在只读事务中执行这些操作，会导致错误。
* **并发修改冲突：** 虽然这里没有直接展示，但如果网页的 JavaScript 代码同时在修改 IndexedDB 数据，而开发者又通过 DevTools 进行操作，可能会出现并发修改冲突的情况，虽然 IndexedDB 有一定的事务机制来处理，但在某些极端情况下可能会导致意外结果。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个包含使用 IndexedDB 的功能的网页。** 网页上的 JavaScript 代码可能创建、读取、更新或删除 IndexedDB 中的数据。
2. **用户打开 Chrome 浏览器的开发者工具 (DevTools)。**  通常通过右键点击页面并选择 "检查" 或使用快捷键 F12 / Ctrl+Shift+I。
3. **用户导航到 "Application" (或 "存储") 标签页。**  不同的 Chrome 版本可能标签名称略有不同。
4. **用户在左侧导航栏中选择 "IndexedDB"。** 这将展开显示当前页面可访问的 IndexedDB 数据库列表。
5. **用户选择一个特定的数据库。** 这会显示该数据库中的对象存储列表。
6. **用户选择一个特定的对象存储。** 这会显示该对象存储中的数据（如果请求数据）。
7. **用户可能执行以下操作，从而触发这里代码中的相应函数：**
    * **查看数据库信息：**  DevTools 会调用 `requestDatabaseNames` 和 `requestDatabase` 来获取数据库和对象存储的结构信息。
    * **查看对象存储数据：** DevTools 会调用 `requestData` 来分页获取对象存储中的数据。
    * **查看对象存储元数据：**  当用户需要查看对象存储的条目数量或键生成器信息时，DevTools 会调用 `getMetadata`。
    * **删除对象存储条目：**  用户在 DevTools 中选择部分或全部条目并点击删除按钮，会触发 `deleteObjectStoreEntries`。
    * **清空对象存储：** 用户点击 "Clear object store" 按钮，会触发 `clearObjectStore`。
    * **删除数据库：** 用户点击数据库旁边的删除按钮，会触发 `deleteDatabase`。

这些用户操作在 DevTools 的前端界面触发相应的事件，DevTools 前端会通过 Chrome 的 DevTools 协议 (CDP) 发送指令给浏览器内核的相应模块，最终路由到 `InspectorIndexedDBAgent` 中的对应方法进行处理。  调试时，可以通过在这些 C++ 方法中设置断点，或者查看 DevTools 的 Network 面板中与 "Inspector.IndexedDB" 相关的请求和响应，来追踪问题的发生。

Prompt: 
```
这是目录为blink/renderer/modules/indexeddb/inspector_indexed_db_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
   [](std::unique_ptr<RequestDatabaseNamesCallback> request_callback,
             LocalFrame* frame, protocol::Response response,
             IDBFactory* idb_factory) {
            if (!response.IsSuccess()) {
              request_callback->sendFailure(response);
              return;
            }
            ScriptState* script_state = ToScriptStateForMainWorld(frame);
            if (!script_state) {
              request_callback->sendFailure(
                  protocol::Response::InternalError());
              return;
            }
            idb_factory->GetDatabaseInfoForDevTools(WTF::BindOnce(
                &OnGotDatabaseNames, std::move(request_callback)));
          },
          std::move(request_callback), WrapPersistent(frame)));
}

void InspectorIndexedDBAgent::requestDatabase(
    protocol::Maybe<String> security_origin,
    protocol::Maybe<String> storage_key,
    protocol::Maybe<protocol::Storage::StorageBucket> storage_bucket,
    const String& database_name,
    std::unique_ptr<RequestDatabaseCallback> request_callback) {
  base::expected<LocalFrame*, protocol::Response> frame_or_response =
      ResolveFrame(inspected_frames_.Get(), security_origin, storage_key,
                   storage_bucket);
  if (!frame_or_response.has_value()) {
    request_callback->sendFailure(frame_or_response.error());
    return;
  }
  scoped_refptr<DatabaseLoader> database_loader =
      DatabaseLoader::Create(std::move(request_callback));
  database_loader->Start(frame_or_response.value(), std::move(storage_bucket),
                         database_name);
}

void InspectorIndexedDBAgent::requestData(
    protocol::Maybe<String> security_origin,
    protocol::Maybe<String> storage_key,
    protocol::Maybe<protocol::Storage::StorageBucket> storage_bucket,
    const String& database_name,
    const String& object_store_name,
    const String& index_name,
    int skip_count,
    int page_size,
    Maybe<protocol::IndexedDB::KeyRange> key_range,
    std::unique_ptr<RequestDataCallback> request_callback) {
  IDBKeyRange* idb_key_range =
      key_range ? IdbKeyRangeFromKeyRange(&*key_range) : nullptr;
  if (key_range && !idb_key_range) {
    request_callback->sendFailure(
        protocol::Response::ServerError("Can not parse key range."));
    return;
  }
  base::expected<LocalFrame*, protocol::Response> frame_or_response =
      ResolveFrame(inspected_frames_.Get(), security_origin, storage_key,
                   storage_bucket);
  if (!frame_or_response.has_value()) {
    request_callback->sendFailure(frame_or_response.error());
    return;
  }
  scoped_refptr<DataLoader> data_loader = DataLoader::Create(
      v8_session_, std::move(request_callback), object_store_name, index_name,
      idb_key_range, skip_count, page_size);

  data_loader->Start(frame_or_response.value(), std::move(storage_bucket),
                     database_name);
}

class GetMetadata;

class GetMetadataListener final : public NativeEventListener {
 public:
  GetMetadataListener(scoped_refptr<GetMetadata> owner, int64_t* result)
      : owner_(owner), result_(result) {}
  ~GetMetadataListener() override = default;

  void Invoke(ExecutionContext*, Event* event) override {
    if (event->type() != event_type_names::kSuccess) {
      NotifySubtaskDone(owner_, "Failed to get meta data of object store.");
      return;
    }

    IDBRequest* idb_request = static_cast<IDBRequest*>(event->target());
    IDBAny* request_result = idb_request->ResultAsAny();
    if (request_result->GetType() != IDBAny::kIntegerType) {
      NotifySubtaskDone(owner_, "Unexpected result type.");
      return;
    }
    *result_ = request_result->Integer();
    NotifySubtaskDone(owner_, String());
  }

 private:
  void NotifySubtaskDone(scoped_refptr<GetMetadata> owner,
                         const String& error) const;
  scoped_refptr<GetMetadata> owner_;
  raw_ptr<int64_t> result_;
};

class GetMetadata final : public ExecutableWithDatabase<GetMetadataCallback> {
 public:
  static scoped_refptr<GetMetadata> Create(
      const String& object_store_name,
      std::unique_ptr<GetMetadataCallback> request_callback) {
    return AdoptRef(
        new GetMetadata(object_store_name, std::move(request_callback)));
  }

  void NotifySubtaskDone(const String& error) {
    if (!error.IsNull()) {
      request_callback_->sendFailure(
          protocol::Response::ServerError(error.Utf8()));
      return;
    }
    if (--subtask_pending_ == 0) {
      request_callback_->sendSuccess(entries_count_,
                                     key_generator_current_number_);
    }
  }

 private:
  GetMetadata(const String& object_store_name,
              std::unique_ptr<GetMetadataCallback> request_callback)
      : object_store_name_(object_store_name),
        request_callback_(std::move(request_callback)),
        subtask_pending_(2),
        entries_count_(-1),
        key_generator_current_number_(-1) {}

  void Execute(IDBDatabase* idb_database, ScriptState* script_state) override {
    IDBTransaction* idb_transaction =
        TransactionForDatabase(script_state, idb_database, object_store_name_,
                               indexed_db_names::kReadonly);
    if (!idb_transaction) {
      request_callback_->sendFailure(
          protocol::Response::ServerError("Could not get transaction"));
      return;
    }
    IDBObjectStore* idb_object_store =
        ObjectStoreForTransaction(idb_transaction, object_store_name_);
    if (!idb_object_store) {
      request_callback_->sendFailure(
          protocol::Response::ServerError("Could not get object store"));
      return;
    }

    // subtask 1. get entries count
    ScriptState::Scope scope(script_state);
    DummyExceptionStateForTesting exception_state;
    IDBRequest* idb_request_get_entries_count = idb_object_store->count(
        script_state, ScriptValue::CreateNull(script_state->GetIsolate()),
        exception_state);
    DCHECK(!exception_state.HadException());
    if (exception_state.HadException()) {
      ExceptionCode ec = exception_state.Code();
      request_callback_->sendFailure(protocol::Response::ServerError(
          String::Format("Could not count entries in object store '%s': %d",
                         object_store_name_.Latin1().c_str(), ec)
              .Utf8()));
      return;
    }
    GetMetadataListener* listener_get_entries_count =
        MakeGarbageCollected<GetMetadataListener>(this, &entries_count_);
    idb_request_get_entries_count->addEventListener(
        event_type_names::kSuccess, listener_get_entries_count, false);
    idb_request_get_entries_count->addEventListener(
        event_type_names::kError, listener_get_entries_count, false);

    // subtask 2. get key generator current number
    IDBRequest* idb_request_get_key_generator =
        idb_object_store->getKeyGeneratorCurrentNumber(script_state);
    GetMetadataListener* listener_get_key_generator =
        MakeGarbageCollected<GetMetadataListener>(
            this, &key_generator_current_number_);
    idb_request_get_key_generator->addEventListener(
        event_type_names::kSuccess, listener_get_key_generator, false);
    idb_request_get_key_generator->addEventListener(
        event_type_names::kError, listener_get_key_generator, false);
  }

  GetMetadataCallback* GetRequestCallback() override {
    return request_callback_.get();
  }

 private:
  const String object_store_name_;
  std::unique_ptr<GetMetadataCallback> request_callback_;
  uint8_t subtask_pending_;
  int64_t entries_count_;
  int64_t key_generator_current_number_;
};

void GetMetadataListener::NotifySubtaskDone(scoped_refptr<GetMetadata> owner,
                                            const String& error) const {
  owner->NotifySubtaskDone(error);
}

void InspectorIndexedDBAgent::getMetadata(
    protocol::Maybe<String> security_origin,
    protocol::Maybe<String> storage_key,
    protocol::Maybe<protocol::Storage::StorageBucket> storage_bucket,
    const String& database_name,
    const String& object_store_name,
    std::unique_ptr<GetMetadataCallback> request_callback) {
  base::expected<LocalFrame*, protocol::Response> frame_or_response =
      ResolveFrame(inspected_frames_.Get(), security_origin, storage_key,
                   storage_bucket);
  if (!frame_or_response.has_value()) {
    request_callback->sendFailure(frame_or_response.error());
    return;
  }
  scoped_refptr<GetMetadata> get_metadata =
      GetMetadata::Create(object_store_name, std::move(request_callback));
  get_metadata->Start(frame_or_response.value(), std::move(storage_bucket),
                      database_name);
}

class DeleteObjectStoreEntriesListener final : public NativeEventListener {
 public:
  explicit DeleteObjectStoreEntriesListener(
      std::unique_ptr<DeleteObjectStoreEntriesCallback> request_callback)
      : request_callback_(std::move(request_callback)) {}
  ~DeleteObjectStoreEntriesListener() override = default;

  void Invoke(ExecutionContext*, Event* event) override {
    if (event->type() != event_type_names::kSuccess) {
      request_callback_->sendFailure(protocol::Response::ServerError(
          "Failed to delete specified entries"));
      return;
    }

    request_callback_->sendSuccess();
  }

 private:
  std::unique_ptr<DeleteObjectStoreEntriesCallback> request_callback_;
};

class DeleteObjectStoreEntries final
    : public ExecutableWithDatabase<DeleteObjectStoreEntriesCallback> {
 public:
  static scoped_refptr<DeleteObjectStoreEntries> Create(
      const String& object_store_name,
      IDBKeyRange* idb_key_range,
      std::unique_ptr<DeleteObjectStoreEntriesCallback> request_callback) {
    return AdoptRef(new DeleteObjectStoreEntries(
        object_store_name, idb_key_range, std::move(request_callback)));
  }

  DeleteObjectStoreEntries(
      const String& object_store_name,
      IDBKeyRange* idb_key_range,
      std::unique_ptr<DeleteObjectStoreEntriesCallback> request_callback)
      : object_store_name_(object_store_name),
        idb_key_range_(idb_key_range),
        request_callback_(std::move(request_callback)) {}

  void Execute(IDBDatabase* idb_database, ScriptState* script_state) override {
    IDBTransaction* idb_transaction =
        TransactionForDatabase(script_state, idb_database, object_store_name_,
                               indexed_db_names::kReadwrite);
    if (!idb_transaction) {
      request_callback_->sendFailure(
          protocol::Response::ServerError("Could not get transaction"));
      return;
    }
    IDBObjectStore* idb_object_store =
        ObjectStoreForTransaction(idb_transaction, object_store_name_);
    if (!idb_object_store) {
      request_callback_->sendFailure(
          protocol::Response::ServerError("Could not get object store"));
      return;
    }

    IDBRequest* idb_request =
        idb_object_store->deleteFunction(script_state, idb_key_range_.Get());
    idb_request->addEventListener(
        event_type_names::kSuccess,
        MakeGarbageCollected<DeleteObjectStoreEntriesListener>(
            std::move(request_callback_)),
        false);
  }

  DeleteObjectStoreEntriesCallback* GetRequestCallback() override {
    return request_callback_.get();
  }

 private:
  const String object_store_name_;
  Persistent<IDBKeyRange> idb_key_range_;
  std::unique_ptr<DeleteObjectStoreEntriesCallback> request_callback_;
};

void InspectorIndexedDBAgent::deleteObjectStoreEntries(
    protocol::Maybe<String> security_origin,
    protocol::Maybe<String> storage_key,
    protocol::Maybe<protocol::Storage::StorageBucket> storage_bucket,
    const String& database_name,
    const String& object_store_name,
    std::unique_ptr<protocol::IndexedDB::KeyRange> key_range,
    std::unique_ptr<DeleteObjectStoreEntriesCallback> request_callback) {
  IDBKeyRange* idb_key_range = IdbKeyRangeFromKeyRange(key_range.get());
  if (!idb_key_range) {
    request_callback->sendFailure(
        protocol::Response::ServerError("Can not parse key range"));
    return;
  }
  base::expected<LocalFrame*, protocol::Response> frame_or_response =
      ResolveFrame(inspected_frames_.Get(), security_origin, storage_key,
                   storage_bucket);
  if (!frame_or_response.has_value()) {
    request_callback->sendFailure(frame_or_response.error());
    return;
  }
  scoped_refptr<DeleteObjectStoreEntries> delete_object_store_entries =
      DeleteObjectStoreEntries::Create(object_store_name, idb_key_range,
                                       std::move(request_callback));
  delete_object_store_entries->Start(frame_or_response.value(),
                                     std::move(storage_bucket), database_name);
}

class ClearObjectStoreListener final : public NativeEventListener {
 public:
  explicit ClearObjectStoreListener(
      std::unique_ptr<ClearObjectStoreCallback> request_callback)
      : request_callback_(std::move(request_callback)) {}
  ~ClearObjectStoreListener() override = default;

  void Invoke(ExecutionContext*, Event* event) override {
    if (event->type() != event_type_names::kComplete) {
      request_callback_->sendFailure(
          protocol::Response::ServerError("Unexpected event type."));
      return;
    }

    request_callback_->sendSuccess();
  }

 private:
  std::unique_ptr<ClearObjectStoreCallback> request_callback_;
};

class ClearObjectStore final
    : public ExecutableWithDatabase<ClearObjectStoreCallback> {
 public:
  static scoped_refptr<ClearObjectStore> Create(
      const String& object_store_name,
      std::unique_ptr<ClearObjectStoreCallback> request_callback) {
    return base::AdoptRef(
        new ClearObjectStore(object_store_name, std::move(request_callback)));
  }

  ClearObjectStore(const String& object_store_name,
                   std::unique_ptr<ClearObjectStoreCallback> request_callback)
      : object_store_name_(object_store_name),
        request_callback_(std::move(request_callback)) {}

  void Execute(IDBDatabase* idb_database, ScriptState* script_state) override {
    IDBTransaction* idb_transaction =
        TransactionForDatabase(script_state, idb_database, object_store_name_,
                               indexed_db_names::kReadwrite);
    if (!idb_transaction) {
      request_callback_->sendFailure(
          protocol::Response::ServerError("Could not get transaction"));
      return;
    }
    IDBObjectStore* idb_object_store =
        ObjectStoreForTransaction(idb_transaction, object_store_name_);
    if (!idb_object_store) {
      request_callback_->sendFailure(
          protocol::Response::ServerError("Could not get object store"));
      return;
    }

    DummyExceptionStateForTesting exception_state;
    idb_object_store->clear(script_state, exception_state);
    DCHECK(!exception_state.HadException());
    if (exception_state.HadException()) {
      ExceptionCode ec = exception_state.Code();
      request_callback_->sendFailure(protocol::Response::ServerError(
          String::Format("Could not clear object store '%s': %d",
                         object_store_name_.Latin1().c_str(), ec)
              .Utf8()));
      return;
    }
    idb_transaction->addEventListener(
        event_type_names::kComplete,
        MakeGarbageCollected<ClearObjectStoreListener>(
            std::move(request_callback_)),
        false);
  }

  ClearObjectStoreCallback* GetRequestCallback() override {
    return request_callback_.get();
  }

 private:
  const String object_store_name_;
  std::unique_ptr<ClearObjectStoreCallback> request_callback_;
};

void InspectorIndexedDBAgent::clearObjectStore(
    protocol::Maybe<String> security_origin,
    protocol::Maybe<String> storage_key,
    protocol::Maybe<protocol::Storage::StorageBucket> storage_bucket,
    const String& database_name,
    const String& object_store_name,
    std::unique_ptr<ClearObjectStoreCallback> request_callback) {
  base::expected<LocalFrame*, protocol::Response> frame_or_response =
      ResolveFrame(inspected_frames_.Get(), security_origin, storage_key,
                   storage_bucket);
  if (!frame_or_response.has_value()) {
    request_callback->sendFailure(frame_or_response.error());
    return;
  }
  scoped_refptr<ClearObjectStore> clear_object_store =
      ClearObjectStore::Create(object_store_name, std::move(request_callback));
  clear_object_store->Start(frame_or_response.value(),
                            std::move(storage_bucket), database_name);
}

void InspectorIndexedDBAgent::deleteDatabase(
    protocol::Maybe<String> security_origin,
    protocol::Maybe<String> storage_key,
    protocol::Maybe<protocol::Storage::StorageBucket> storage_bucket,
    const String& database_name,
    std::unique_ptr<DeleteDatabaseCallback> request_callback) {
  base::expected<LocalFrame*, protocol::Response> frame_or_response =
      ResolveFrame(inspected_frames_.Get(), security_origin, storage_key,
                   storage_bucket);
  if (!frame_or_response.has_value()) {
    request_callback->sendFailure(frame_or_response.error());
    return;
  }
  LocalFrame* frame = frame_or_response.value();
  ExecutableWithIdbFactory::Start(
      frame, std::move(storage_bucket),
      WTF::BindOnce(
          [](std::unique_ptr<DeleteDatabaseCallback> request_callback,
             LocalFrame* frame, String database_name,
             protocol::Response response, IDBFactory* idb_factory) {
            if (!response.IsSuccess()) {
              request_callback->sendFailure(response);
              return;
            }

            ScriptState* script_state = ToScriptStateForMainWorld(frame);
            if (!script_state) {
              request_callback->sendFailure(
                  protocol::Response::InternalError());
              return;
            }
            ScriptState::Scope scope(script_state);
            DummyExceptionStateForTesting exception_state;
            IDBRequest* idb_request =
                idb_factory->CloseConnectionsAndDeleteDatabase(
                    script_state, database_name, exception_state);
            if (exception_state.HadException()) {
              request_callback->sendFailure(protocol::Response::ServerError(
                  "Could not delete database."));
              return;
            }
            idb_request->addEventListener(
                event_type_names::kSuccess,
                MakeGarbageCollected<DeleteCallback>(
                    std::move(request_callback),
                    frame->DomWindow()->GetSecurityOrigin()->ToRawString()),
                false);
          },
          std::move(request_callback), WrapPersistent(frame), database_name));
}

void InspectorIndexedDBAgent::Trace(Visitor* visitor) const {
  visitor->Trace(inspected_frames_);
  InspectorBaseAgent::Trace(visitor);
}

}  // namespace blink

"""


```