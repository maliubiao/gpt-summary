Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. This is the second part of the file. I need to summarize the functionality demonstrated in this specific part of the code.

The code primarily contains unit tests for the `IDBRequest` class, specifically focusing on the `getAll` functionality in IndexedDB. These tests verify different scenarios of retrieving data using `getAll`, including:

- Retrieving only values.
- Retrieving values when a blob is involved.
- Retrieving values with an injected key.
- Retrieving entire records (key-value pairs).
- Retrieving records when no index keys are present.
- Retrieving records when a blob is involved.
- Retrieving records with an injected key.
- Testing the abortion of a `getAll` request in various stages (before receiving values, while receiving values, and while loading blob values).
- Testing the `AsyncTraceState` functionality of `IDBRequest`.

I will now summarize these points clearly and concisely.
```c++
TEST_F(IDBRequestTest, GetAllValuesWithoutKeys) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/10, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false));
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/9, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false));

  V8TestingScope scope;
  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Values,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllValuesWithBlob) {
  V8TestingScope scope;

  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/5, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false));

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  // Append a blob value to the results.
  const uint8_t array_buffer_bytes[] = {1, 2, 3, 4, 5, 6, 7, 8};
  v8::Local<v8::ArrayBuffer> array_buffer =
      CreateArrayBuffer(scope.GetIsolate(), array_buffer_bytes);

  mojom::blink::IDBReturnValuePtr blob_return_value =
      CreateIDBReturnValuePtrWithBlob(scope.GetIsolate(), array_buffer);

  get_all_results.back().emplace_back(mojom::blink::IDBRecord::New(
      /*primary_key=*/std::nullopt, std::move(blob_return_value),
      /*index_key=*/std::nullopt));

  // Append the unwrapped blob value to the expected results.
  std::unique_ptr<IDBValue> blob_expected_value =
      CreateIDBValueWithV8Value(scope.GetIsolate(), array_buffer);

  expected_results.values.emplace_back(std::move(blob_expected_value));

  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Values,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllValuesWithInjectedKey) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/6, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false));

  std::unique_ptr<IDBKey> injected_primary_key =
      IDBKey::CreateString(u"injected_primary_key");
  IDBKeyPath injected_key_path("injected_key_path");

  // Add an injected key to the last result.
  mojom::blink::IDBReturnValuePtr& last_value =
      get_all_results.back().back()->return_value;
  last_value->primary_key = IDBKey::Clone(injected_primary_key);
  last_value->key_path = injected_key_path;

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  V8TestingScope scope;
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Values,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecords) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/10, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/9, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));

  V8TestingScope scope;
  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecordsWithoutIndexKeys) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/10, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/false));
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/9, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/false));

  V8TestingScope scope;
  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecordsWithBlob) {
  V8TestingScope scope;

  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/5, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  // Append a blob value to the results.
  const uint8_t array_buffer_bytes[] = {100, 101, 102, 103, 104, 105,
                                        106, 107, 108, 109, 110, 111,
                                        112, 113, 114, 115, 116};
  v8::Local<v8::ArrayBuffer> array_buffer =
      CreateArrayBuffer(scope.GetIsolate(), array_buffer_bytes);

  mojom::blink::IDBReturnValuePtr blob_return_value =
      CreateIDBReturnValuePtrWithBlob(scope.GetIsolate(), array_buffer);

  std::unique_ptr<IDBKey> blob_primary_key =
      IDBKey::CreateString(u"blob_primary_key");
  std::unique_ptr<IDBKey> blob_index_key =
      IDBKey::CreateString(u"blob_index_key");

  get_all_results.back().emplace_back(mojom::blink::IDBRecord::New(
      IDBKey::Clone(blob_primary_key), std::move(blob_return_value),
      IDBKey::Clone(blob_index_key)));

  // Append the unwrapped blob value to the expected results.
  std::unique_ptr<IDBValue> blob_expected_value =
      CreateIDBValueWithV8Value(scope.GetIsolate(), array_buffer);

  expected_results.primary_keys.emplace_back(std::move(blob_primary_key));
  expected_results.values.emplace_back(std::move(blob_expected_value));
  expected_results.index_keys.emplace_back(std::move(blob_index_key));

  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecordsWithInjectedKey) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/6, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));

  std::unique_ptr<IDBKey> injected_primary_key =
      IDBKey::CreateString(u"injected_primary_key");
  IDBKeyPath injected_key_path("injected_key_path");

  // Add an injected key to the last result.
  mojom::blink::IDBReturnValuePtr& last_value =
      get_all_results.back().back()->return_value;
  last_value->primary_key = IDBKey::Clone(injected_primary_key);
  last_value->key_path = injected_key_path;

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  V8TestingScope scope;
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, AbortGetAll) {
  V8TestingScope scope;

  // Set up the transaction.
  MockIDBDatabase database_backend;
  MockIDBTransaction transaction_backend;
  BuildTransaction(scope, database_backend, transaction_backend);
  ASSERT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(transaction_);

  // Create the get all request.
  IDBRequest* request =
      IDBRequest::Create(scope.GetScriptState(), store_.Get(),
                         transaction_.Get(), IDBRequest::AsyncTraceState());
  mojo::AssociatedRemote<mojom::blink::IDBDatabaseGetAllResultSink>
      get_all_sink_remote;
  request->OnGetAll(
      mojom::blink::IDBGetAllResultType::Values,
      get_all_sink_remote.BindNewEndpointAndPassDedicatedReceiver());

  // Abort the request and verify the results.
  request->Abort(/*queue_dispatch=*/true);
  scope.PerformMicrotaskCheckpoint();
  platform_->RunUntilIdle();

  EXPECT_EQ(request->readyState(), V8IDBRequestReadyState::Enum::kDone);

  IDBAny* actual_result = request->ResultAsAny();
  ASSERT_NE(actual_result, nullptr);
  EXPECT_EQ(actual_result->GetType(), IDBAny::Type::kUndefinedType);

  NonThrowableExceptionState exception_state;
  DOMException* error = request->error(exception_state);
  ASSERT_NE(error, nullptr);
  EXPECT_EQ(error->name(), "AbortError");
}

TEST_F(IDBRequestTest, AbortGetAllWhileReceivingValues) {
  V8TestingScope scope;

  // Set up the transaction.
  MockIDBDatabase database_backend;
  MockIDBTransaction transaction_backend;
  BuildTransaction(scope, database_backend, transaction_backend);
  ASSERT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(transaction_);

  // Create the get all request.
  IDBRequest* request =
      IDBRequest::Create(scope.GetScriptState(), store_.Get(),
                         transaction_.Get(), IDBRequest::AsyncTraceState());
  mojo::AssociatedRemote<mojom::blink::IDBDatabaseGetAllResultSink>
      get_all_sink_remote;
  request->OnGetAll(
      mojom::blink::IDBGetAllResultType::Values,
      get_all_sink_remote.BindNewEndpointAndPassDedicatedReceiver());

  // Stream a batch of results to the request.
  Vector<mojom::blink::IDBRecordPtr> records = GenerateGetAllResults(
      /*result_count=*/3, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false);
  get_all_sink_remote->ReceiveResults(std::move(records),
                                      /*done=*/false);

  // Wait for the request to process the result records before aborting.
  platform_->RunUntilIdle();

  // Abort the request and verify the results.
  request->Abort(/*queue_dispatch=*/true);
  scope.PerformMicrotaskCheckpoint();
  platform_->RunUntilIdle();

  EXPECT_EQ(request->readyState(), V8IDBRequestReadyState::Enum::kDone);

  IDBAny* actual_result = request->ResultAsAny();
  ASSERT_NE(actual_result, nullptr);
  EXPECT_EQ(actual_result->GetType(), IDBAny::Type::kUndefinedType);

  NonThrowableExceptionState exception_state;
  DOMException* error = request->error(exception_state);
  ASSERT_NE(error, nullptr);
  EXPECT_EQ(error->name(), "AbortError");
}

TEST_F(IDBRequestTest, AbortGetAllWhileLoadingValues) {
  V8TestingScope scope;

  // Remove the blob registry to force timeouts when loading blob values. This
  // gives the test a chance to abort the request while waiting for the blob to
  // load.
  BlobDataHandle::SetBlobRegistryForTesting(nullptr);

  // Set up the transaction.
  MockIDBDatabase database_backend;
  MockIDBTransaction transaction_backend;
  BuildTransaction(scope, database_backend, transaction_backend);
  ASSERT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(transaction_);

  // Create the get all request.
  IDBRequest* request =
      IDBRequest::Create(scope.GetScriptState(), store_.Get(),
                         transaction_.Get(), IDBRequest::AsyncTraceState());
  mojo::AssociatedRemote<mojom::blink::IDBDatabaseGetAllResultSink>
      get_all_sink_remote;
  request->OnGetAll(
      mojom::blink::IDBGetAllResultType::Values,
      get_all_sink_remote.BindNewEndpointAndPassDedicatedReceiver());

  // Stream a batch of results to the request. Include a blob value that
  // requires loading.
  const uint8_t array_buffer_bytes[] = {200, 201};
  v8::Local<v8::ArrayBuffer> array_buffer =
      CreateArrayBuffer(scope.GetIsolate(), array_buffer_bytes);

  mojom::blink::IDBReturnValuePtr blob_return_value =
      CreateIDBReturnValuePtrWithBlob(scope.GetIsolate(), array_buffer);

  Vector<mojom::blink::IDBRecordPtr> records = GenerateGetAllResults(
      /*result_count=*/3, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false);
  records.emplace_back(mojom::blink::IDBRecord::New(
      /*primary_key=*/std::nullopt, std::move(blob_return_value),
      /*index_key=*/std::nullopt));

  get_all_sink_remote->ReceiveResults(std::move(records),
                                      /*done=*/true);

  // Wait for the request to load the result values before aborting.
  platform_->RunUntilIdle();

  // Abort the request and verify the results.
  request->Abort(/*queue_dispatch=*/true);
  scope.PerformMicrotaskCheckpoint();
  platform_->RunUntilIdle();

  EXPECT_EQ(request->readyState(), V8IDBRequestReadyState::Enum::kDone);

  IDBAny* actual_result = request->ResultAsAny();
  ASSERT_NE(actual_result, nullptr);
  EXPECT_EQ(actual_result->GetType(), IDBAny::Type::kUndefinedType);

  NonThrowableExceptionState exception_state;
  DOMException* error = request->error(exception_state);
  ASSERT_NE(error, nullptr);
  EXPECT_EQ(error->name(), "AbortError");
}

// Expose private state for testing.
class AsyncTraceStateForTesting : public IDBRequest::AsyncTraceState {
 public:
  explicit AsyncTraceStateForTesting(IDBRequest::TypeForMetrics type)
      : IDBRequest::AsyncTraceState(type) {}
  AsyncTraceStateForTesting() = default;
  AsyncTraceStateForTesting(AsyncTraceStateForTesting&& other)
      : IDBRequest::AsyncTraceState(std::move(other)) {}
  AsyncTraceStateForTesting& operator=(AsyncTraceStateForTesting&& rhs) {
    AsyncTraceState::operator=(std::move(rhs));
    return *this;
  }

  std::optional<IDBRequest::TypeForMetrics> type() const {
    return IDBRequest::AsyncTraceState::type();
  }
  const base::TimeTicks& start_time() const {
    return IDBRequest::AsyncTraceState::start_time();
  }
  size_t id() const { return IDBRequest::AsyncTraceState::id(); }
};

TEST(IDBRequestAsyncTraceStateTest, EmptyConstructor) {
  AsyncTraceStateForTesting state;

  EXPECT_FALSE(state.type());
  EXPECT_TRUE(state.IsEmpty());
}

TEST(IDBRequestAsyncTraceStateTest, MoveConstructor) {
  IDBRequest::TypeForMetrics type =
      IDBRequest::TypeForMetrics::kObjectStoreGetAllKeys;
  AsyncTraceStateForTesting source_state(type);
  size_t id = source_state.id();
  base::TimeTicks start_time = source_state.start_time();

  AsyncTraceStateForTesting state(std::move(source_state));
  EXPECT_EQ(type, *state.type());
  EXPECT_EQ(id, state.id());
  EXPECT_EQ(start_time, state.start_time());
  EXPECT_TRUE(source_state.IsEmpty());
}

TEST(IDBRequestAsyncTraceStateTest, MoveAssignment) {
  IDBRequest::TypeForMetrics type =
      IDBRequest::TypeForMetrics::kObjectStoreGetAllKeys;
  AsyncTraceStateForTesting source_state(type);
  size_t id = source_state.id();
  base::TimeTicks start_time = source_state.start_time();

  AsyncTraceStateForTesting state;
  EXPECT_TRUE(state.IsEmpty());

  state = std::move(source_state);
  EXPECT_EQ(type, *state.type());
  EXPECT_EQ(id, state.id());
  EXPECT_EQ(start_time, state.start_time());
  EXPECT_TRUE(source_state.IsEmpty());
}

}  // namespace blink
```

This second part of the `blink/renderer/modules/indexeddb/idb_request_test.cc` file primarily focuses on **testing the `getAll` functionality of `IDBRequest`**.

Here's a breakdown of the tested scenarios:

*   **`GetAllValuesWithoutKeys`**: Tests retrieving only the values from the object store when no keys are associated with the records.
*   **`GetAllValuesWithBlob`**: Tests retrieving values when some of the values are Blobs. This involves creating `ArrayBuffer` in JavaScript and converting it to a Blob.
*   **`GetAllValuesWithInjectedKey`**: Tests retrieving values where the backend injects a primary key and key path into the result.
*   **`GetAllRecords`**: Tests retrieving the complete records (primary key, value, and index key) from the object store.
*   **`GetAllRecordsWithoutIndexKeys`**: Tests retrieving records when the object store doesn't have index keys defined.
*   **`GetAllRecordsWithBlob`**: Tests retrieving complete records when some of the values are Blobs.
*   **`GetAllRecordsWithInjectedKey`**: Tests retrieving records where the backend injects a primary key and key path into the result.
*   **`AbortGetAll`**: Tests the scenario where a `getAll` request is aborted before any results are received.
*   **`AbortGetAllWhileReceivingValues`**: Tests aborting a `getAll` request while results are being streamed from the backend.
*   **`AbortGetAllWhileLoadingValues`**: Tests aborting a `getAll` request while the system is waiting for Blob data to load. This test specifically simulates a scenario where Blob loading might be delayed.
*   **`IDBRequestAsyncTraceStateTest`**: This section tests the `AsyncTraceState` helper class within `IDBRequest`. This likely deals with tracking the lifecycle and performance of asynchronous IndexedDB operations for debugging and metrics.

**Relationship to JavaScript, HTML, CSS:**

These tests are directly related to the JavaScript IndexedDB API. The `getAll` method is a core part of this API.

*   **JavaScript:**  A JavaScript application would use methods like `objectStore.getAll()` to trigger the underlying C++ code being tested here.
    ```javascript
    const request = db.transaction('myStore', 'readonly')
      .objectStore('myStore')
      .getAll();

    request.onsuccess = function(event) {
      console.log('Retrieved values:', event.target.result);
    };

    request.onerror = function(event) {
      console.error('Error retrieving values:', event.target.error);
    };
    ```
*   **HTML:** HTML provides the structure for the web page where the JavaScript code interacting with IndexedDB would reside. There's no direct functional relationship between this C++ code and HTML elements in terms of rendering or layout.
*   **CSS:** CSS is for styling the web page. It has no functional interaction with the IndexedDB API or this C++ code.

**Logic Inference (Hypothetical Input and Output):**

Let's take the `GetAllValuesWithBlob` test as an example:

*   **Hypothetical Input (from the backend):**  The IndexedDB backend provides a result set. One of the records has a `mojom::blink::IDBReturnValuePtr` that signifies a Blob. This `IDBReturnValuePtr` would contain metadata about the Blob (e.g., its size and identifier).
*   **Processing:** The `IDBRequest` object in C++ receives this result. For the Blob value, it needs to fetch the actual Blob data.
*   **Hypothetical Output (to JavaScript):** The `request.onsuccess` handler in JavaScript would receive an array of values. The Blob value would be represented as a JavaScript `Blob` object.

**User/Programming Errors:**

*   **Incorrectly handling `getAll` results:** A common programming error is not properly handling the asynchronous nature of `getAll`. Developers might try to access the results before the `onsuccess` event fires.
*   **Not checking for errors:** Forgetting to implement the `onerror` handler can lead to unhandled exceptions and make debugging difficult.
*   **Aborting transactions prematurely:**  While the tests cover deliberate aborts, a user might inadvertently abort a transaction containing a `getAll` request, leading to an `AbortError`.

**User Operations as Debugging Clues:**

To reach the `getAll` functionality and potentially trigger the code being tested:

1. **User interacts with a web page:** A user might perform an action (e.g., clicking a button, submitting a form) on a web page that triggers JavaScript code.
2. **JavaScript interacts with IndexedDB:** The JavaScript code might then open an IndexedDB database, start a transaction, and call `objectStore.getAll()` on an object store.
3. **Browser processes the request:** The browser's IndexedDB implementation (which involves this C++ code) receives the `getAll` request.
4. **Backend fetches data:** The request is passed to the underlying storage engine to retrieve the requested data.
5. **Results are returned:** The results are packaged and sent back to the renderer process.
6. **`IDBRequest` handles the results:** The `IDBRequest` object (the focus of these tests) receives the results and processes them, potentially including handling Blobs, injected keys, etc.
7. **JavaScript `onsuccess` is triggered:** Finally, the JavaScript `onsuccess` handler receives the results.

If a user reports an issue related to retrieving data from IndexedDB, and the error manifests as an incorrect result set or an `AbortError`, debugging might involve examining the network requests to the IndexedDB backend, stepping through the JavaScript code, and potentially using internal browser debugging tools to trace the execution within the Blink engine, including the `IDBRequest` class.

**Summary of Functionality (Part 2):**

This part of the `idb_request_test.cc` file comprehensively tests the **`getAll` functionality of the `IDBRequest` class** in the Chromium Blink engine's IndexedDB implementation. It covers various scenarios of retrieving data, including handling Blobs, injected keys, and testing the behavior when a `getAll` request is aborted at different stages. It also includes tests for the `AsyncTraceState` class, which is used for tracking asynchronous operations.

Prompt: 
```
这是目录为blink/renderer/modules/indexeddb/idb_request_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
te_index_key=*/false));

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  // Append a blob value to the results.
  const uint8_t array_buffer_bytes[] = {1, 2, 3, 4, 5, 6, 7, 8};
  v8::Local<v8::ArrayBuffer> array_buffer =
      CreateArrayBuffer(scope.GetIsolate(), array_buffer_bytes);

  mojom::blink::IDBReturnValuePtr blob_return_value =
      CreateIDBReturnValuePtrWithBlob(scope.GetIsolate(), array_buffer);

  get_all_results.back().emplace_back(mojom::blink::IDBRecord::New(
      /*primary_key=*/std::nullopt, std::move(blob_return_value),
      /*index_key=*/std::nullopt));

  // Append the unwrapped blob value to the expected results.
  std::unique_ptr<IDBValue> blob_expected_value =
      CreateIDBValueWithV8Value(scope.GetIsolate(), array_buffer);

  expected_results.values.emplace_back(std::move(blob_expected_value));

  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Values,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllValuesWithInjectedKey) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/6, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false));

  std::unique_ptr<IDBKey> injected_primary_key =
      IDBKey::CreateString(u"injected_primary_key");
  IDBKeyPath injected_key_path("injected_key_path");

  // Add an injected key to the last result.
  mojom::blink::IDBReturnValuePtr& last_value =
      get_all_results.back().back()->return_value;
  last_value->primary_key = IDBKey::Clone(injected_primary_key);
  last_value->key_path = injected_key_path;

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  V8TestingScope scope;
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Values,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecords) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/10, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/9, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));

  V8TestingScope scope;
  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecordsWithoutIndexKeys) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/10, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/false));
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/9, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/false));

  V8TestingScope scope;
  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecordsWithBlob) {
  V8TestingScope scope;

  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/5, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  // Append a blob value to the results.
  const uint8_t array_buffer_bytes[] = {100, 101, 102, 103, 104, 105,
                                        106, 107, 108, 109, 110, 111,
                                        112, 113, 114, 115, 116};
  v8::Local<v8::ArrayBuffer> array_buffer =
      CreateArrayBuffer(scope.GetIsolate(), array_buffer_bytes);

  mojom::blink::IDBReturnValuePtr blob_return_value =
      CreateIDBReturnValuePtrWithBlob(scope.GetIsolate(), array_buffer);

  std::unique_ptr<IDBKey> blob_primary_key =
      IDBKey::CreateString(u"blob_primary_key");
  std::unique_ptr<IDBKey> blob_index_key =
      IDBKey::CreateString(u"blob_index_key");

  get_all_results.back().emplace_back(mojom::blink::IDBRecord::New(
      IDBKey::Clone(blob_primary_key), std::move(blob_return_value),
      IDBKey::Clone(blob_index_key)));

  // Append the unwrapped blob value to the expected results.
  std::unique_ptr<IDBValue> blob_expected_value =
      CreateIDBValueWithV8Value(scope.GetIsolate(), array_buffer);

  expected_results.primary_keys.emplace_back(std::move(blob_primary_key));
  expected_results.values.emplace_back(std::move(blob_expected_value));
  expected_results.index_keys.emplace_back(std::move(blob_index_key));

  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, GetAllRecordsWithInjectedKey) {
  Vector<Vector<mojom::blink::IDBRecordPtr>> get_all_results;
  get_all_results.push_back(GenerateGetAllResults(
      /*result_count=*/6, /*generate_primary_key=*/true,
      /*generate_value=*/true, /*generate_index_key=*/true));

  std::unique_ptr<IDBKey> injected_primary_key =
      IDBKey::CreateString(u"injected_primary_key");
  IDBKeyPath injected_key_path("injected_key_path");

  // Add an injected key to the last result.
  mojom::blink::IDBReturnValuePtr& last_value =
      get_all_results.back().back()->return_value;
  last_value->primary_key = IDBKey::Clone(injected_primary_key);
  last_value->key_path = injected_key_path;

  IDBRecordArray expected_results = ToIDBRecordArray(get_all_results);

  V8TestingScope scope;
  ASSERT_NO_FATAL_FAILURE(
      TestGetAll(scope, mojom::blink::IDBGetAllResultType::Records,
                 std::move(get_all_results), std::move(expected_results)));
}

TEST_F(IDBRequestTest, AbortGetAll) {
  V8TestingScope scope;

  // Set up the transaction.
  MockIDBDatabase database_backend;
  MockIDBTransaction transaction_backend;
  BuildTransaction(scope, database_backend, transaction_backend);
  ASSERT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(transaction_);

  // Create the get all request.
  IDBRequest* request =
      IDBRequest::Create(scope.GetScriptState(), store_.Get(),
                         transaction_.Get(), IDBRequest::AsyncTraceState());
  mojo::AssociatedRemote<mojom::blink::IDBDatabaseGetAllResultSink>
      get_all_sink_remote;
  request->OnGetAll(
      mojom::blink::IDBGetAllResultType::Values,
      get_all_sink_remote.BindNewEndpointAndPassDedicatedReceiver());

  // Abort the request and verify the results.
  request->Abort(/*queue_dispatch=*/true);
  scope.PerformMicrotaskCheckpoint();
  platform_->RunUntilIdle();

  EXPECT_EQ(request->readyState(), V8IDBRequestReadyState::Enum::kDone);

  IDBAny* actual_result = request->ResultAsAny();
  ASSERT_NE(actual_result, nullptr);
  EXPECT_EQ(actual_result->GetType(), IDBAny::Type::kUndefinedType);

  NonThrowableExceptionState exception_state;
  DOMException* error = request->error(exception_state);
  ASSERT_NE(error, nullptr);
  EXPECT_EQ(error->name(), "AbortError");
}

TEST_F(IDBRequestTest, AbortGetAllWhileReceivingValues) {
  V8TestingScope scope;

  // Set up the transaction.
  MockIDBDatabase database_backend;
  MockIDBTransaction transaction_backend;
  BuildTransaction(scope, database_backend, transaction_backend);
  ASSERT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(transaction_);

  // Create the get all request.
  IDBRequest* request =
      IDBRequest::Create(scope.GetScriptState(), store_.Get(),
                         transaction_.Get(), IDBRequest::AsyncTraceState());
  mojo::AssociatedRemote<mojom::blink::IDBDatabaseGetAllResultSink>
      get_all_sink_remote;
  request->OnGetAll(
      mojom::blink::IDBGetAllResultType::Values,
      get_all_sink_remote.BindNewEndpointAndPassDedicatedReceiver());

  // Stream a batch of results to the request.
  Vector<mojom::blink::IDBRecordPtr> records = GenerateGetAllResults(
      /*result_count=*/3, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false);
  get_all_sink_remote->ReceiveResults(std::move(records),
                                      /*done=*/false);

  // Wait for the request to process the result records before aborting.
  platform_->RunUntilIdle();

  // Abort the request and verify the results.
  request->Abort(/*queue_dispatch=*/true);
  scope.PerformMicrotaskCheckpoint();
  platform_->RunUntilIdle();

  EXPECT_EQ(request->readyState(), V8IDBRequestReadyState::Enum::kDone);

  IDBAny* actual_result = request->ResultAsAny();
  ASSERT_NE(actual_result, nullptr);
  EXPECT_EQ(actual_result->GetType(), IDBAny::Type::kUndefinedType);

  NonThrowableExceptionState exception_state;
  DOMException* error = request->error(exception_state);
  ASSERT_NE(error, nullptr);
  EXPECT_EQ(error->name(), "AbortError");
}

TEST_F(IDBRequestTest, AbortGetAllWhileLoadingValues) {
  V8TestingScope scope;

  // Remove the blob registry to force timeouts when loading blob values. This
  // gives the test a chance to abort the request while waiting for the blob to
  // load.
  BlobDataHandle::SetBlobRegistryForTesting(nullptr);

  // Set up the transaction.
  MockIDBDatabase database_backend;
  MockIDBTransaction transaction_backend;
  BuildTransaction(scope, database_backend, transaction_backend);
  ASSERT_TRUE(!scope.GetExceptionState().HadException());
  ASSERT_TRUE(transaction_);

  // Create the get all request.
  IDBRequest* request =
      IDBRequest::Create(scope.GetScriptState(), store_.Get(),
                         transaction_.Get(), IDBRequest::AsyncTraceState());
  mojo::AssociatedRemote<mojom::blink::IDBDatabaseGetAllResultSink>
      get_all_sink_remote;
  request->OnGetAll(
      mojom::blink::IDBGetAllResultType::Values,
      get_all_sink_remote.BindNewEndpointAndPassDedicatedReceiver());

  // Stream a batch of results to the request.  Include a blob value that
  // requires loading.
  const uint8_t array_buffer_bytes[] = {200, 201};
  v8::Local<v8::ArrayBuffer> array_buffer =
      CreateArrayBuffer(scope.GetIsolate(), array_buffer_bytes);

  mojom::blink::IDBReturnValuePtr blob_return_value =
      CreateIDBReturnValuePtrWithBlob(scope.GetIsolate(), array_buffer);

  Vector<mojom::blink::IDBRecordPtr> records = GenerateGetAllResults(
      /*result_count=*/3, /*generate_primary_key=*/false,
      /*generate_value=*/true, /*generate_index_key=*/false);
  records.emplace_back(mojom::blink::IDBRecord::New(
      /*primary_key=*/std::nullopt, std::move(blob_return_value),
      /*index_key=*/std::nullopt));

  get_all_sink_remote->ReceiveResults(std::move(records),
                                      /*done=*/true);

  // Wait for the request to load the result values before aborting.
  platform_->RunUntilIdle();

  // Abort the request and verify the results.
  request->Abort(/*queue_dispatch=*/true);
  scope.PerformMicrotaskCheckpoint();
  platform_->RunUntilIdle();

  EXPECT_EQ(request->readyState(), V8IDBRequestReadyState::Enum::kDone);

  IDBAny* actual_result = request->ResultAsAny();
  ASSERT_NE(actual_result, nullptr);
  EXPECT_EQ(actual_result->GetType(), IDBAny::Type::kUndefinedType);

  NonThrowableExceptionState exception_state;
  DOMException* error = request->error(exception_state);
  ASSERT_NE(error, nullptr);
  EXPECT_EQ(error->name(), "AbortError");
}

// Expose private state for testing.
class AsyncTraceStateForTesting : public IDBRequest::AsyncTraceState {
 public:
  explicit AsyncTraceStateForTesting(IDBRequest::TypeForMetrics type)
      : IDBRequest::AsyncTraceState(type) {}
  AsyncTraceStateForTesting() = default;
  AsyncTraceStateForTesting(AsyncTraceStateForTesting&& other)
      : IDBRequest::AsyncTraceState(std::move(other)) {}
  AsyncTraceStateForTesting& operator=(AsyncTraceStateForTesting&& rhs) {
    AsyncTraceState::operator=(std::move(rhs));
    return *this;
  }

  std::optional<IDBRequest::TypeForMetrics> type() const {
    return IDBRequest::AsyncTraceState::type();
  }
  const base::TimeTicks& start_time() const {
    return IDBRequest::AsyncTraceState::start_time();
  }
  size_t id() const { return IDBRequest::AsyncTraceState::id(); }
};

TEST(IDBRequestAsyncTraceStateTest, EmptyConstructor) {
  AsyncTraceStateForTesting state;

  EXPECT_FALSE(state.type());
  EXPECT_TRUE(state.IsEmpty());
}

TEST(IDBRequestAsyncTraceStateTest, MoveConstructor) {
  IDBRequest::TypeForMetrics type =
      IDBRequest::TypeForMetrics::kObjectStoreGetAllKeys;
  AsyncTraceStateForTesting source_state(type);
  size_t id = source_state.id();
  base::TimeTicks start_time = source_state.start_time();

  AsyncTraceStateForTesting state(std::move(source_state));
  EXPECT_EQ(type, *state.type());
  EXPECT_EQ(id, state.id());
  EXPECT_EQ(start_time, state.start_time());
  EXPECT_TRUE(source_state.IsEmpty());
}

TEST(IDBRequestAsyncTraceStateTest, MoveAssignment) {
  IDBRequest::TypeForMetrics type =
      IDBRequest::TypeForMetrics::kObjectStoreGetAllKeys;
  AsyncTraceStateForTesting source_state(type);
  size_t id = source_state.id();
  base::TimeTicks start_time = source_state.start_time();

  AsyncTraceStateForTesting state;
  EXPECT_TRUE(state.IsEmpty());

  state = std::move(source_state);
  EXPECT_EQ(type, *state.type());
  EXPECT_EQ(id, state.id());
  EXPECT_EQ(start_time, state.start_time());
  EXPECT_TRUE(source_state.IsEmpty());
}

}  // namespace blink

"""


```