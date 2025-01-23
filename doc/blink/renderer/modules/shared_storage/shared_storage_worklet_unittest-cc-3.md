Response:
The user wants a summary of the functionality of the provided C++ code. This is part 4 of 5, so the summary should focus on the tests within this specific chunk.

The code defines several test cases within the `SharedStorageWorkletTest` fixture. These tests verify the behavior of the Shared Storage API when accessed from within a worklet.

Looking at the test names and the code within each test, it seems like this part specifically focuses on testing:

- **`sharedStorage.entries()`**:  Iterating through key-value pairs in Shared Storage. This includes tests for successful iteration, handling errors during iteration, and the interaction with the `SharedStorageEntriesListener`.
- **`sharedStorage.keys()`**: Iterating through the keys in Shared Storage. There's a test for basic successful iteration and another that explores manual control over the asynchronous iterator using `next()`.
- **`sharedStorage.values()`**: Iterating through the values in Shared Storage, similar to the `keys()` test with manual iterator control.
- **`sharedStorage.remainingBudget()`**: Fetching the remaining budget for the Shared Storage API. Tests cover both success and failure scenarios.
- **`sharedStorage.context`**: Accessing the embedder-provided context. Tests check for both defined and undefined contexts.
- **Error handling**: Ensuring that asynchronous failures within the worklet don't prevent the overall `run()` operation from succeeding.
- **`crypto.getRandomValues()` and `crypto.randomUUID()`**: Testing the availability and basic functionality of these cryptographic functions within the worklet environment.
- **`TextEncoder`, `TextDecoder`, and `crypto.subtle.encrypt/decrypt`**:  Verifying the presence and basic usage of these APIs for text encoding/decoding and cryptographic operations.
- **Feature flags**: Tests that ensure certain APIs are not available when their corresponding feature flags are disabled (e.g., Web Locks, Interest Groups, Private Aggregation).
- **Private Aggregation API**: Tests specifically for the Private Aggregation API when enabled, including successful contributions and error scenarios.
Based on the provided code snippet, this part of `shared_storage_worklet_unittest.cc` primarily focuses on testing the functionality of the `sharedStorage` API and related JavaScript built-ins within the context of a Shared Storage Worklet. It specifically tests the following aspects:

**Functionality Tested:**

1. **Iterating through Shared Storage entries (`sharedStorage.entries()`):**
    *   **Successful iteration:** Verifies that the worklet can successfully iterate through key-value pairs in shared storage and log them to the console. It tests scenarios with single and multiple batches of entries.
    *   **Error handling during iteration:** Checks that errors reported by the underlying storage mechanism are correctly propagated to the worklet and result in an `OperationError`.

2. **Iterating through Shared Storage keys (`sharedStorage.keys()`):**
    *   **Successful iteration:** Confirms the worklet can iterate through the keys in shared storage and log them.
    *   **Manual iteration control:** Tests the ability to manually control the asynchronous iterator for keys using `next()`, allowing skipping of results and handling the `done` state.

3. **Iterating through Shared Storage values (`sharedStorage.values()`):**
    *   **Manual iteration control:** Similar to the `keys()` test, it verifies the manual control of the asynchronous iterator for values.

4. **Retrieving remaining budget (`sharedStorage.remainingBudget()`):**
    *   **Success and failure:** Checks both successful retrieval of the remaining budget and handling of errors reported by the client.

5. **Accessing the context attribute (`sharedStorage.context`):**
    *   **Presence and value:** Tests that the `context` attribute is accessible and reflects the embedder-provided context (or is `undefined` if no context is provided).

6. **Asynchronous failures during operations:**
    *   Ensures that failures occurring within individual `sharedStorage` operations (like `set`, `append`, `delete`, `get`) do not cause the overall `run()` operation in the worklet to fail.

7. **Cryptographic functions (`crypto.getRandomValues()`, `crypto.randomUUID()`):**
    *   **Availability and basic functionality:** Verifies that these standard web crypto APIs are available within the worklet and produce seemingly random outputs.

8. **Text encoding/decoding and subtle crypto (`TextEncoder`, `TextDecoder`, `crypto.subtle.encrypt/decrypt`):**
    *   **Availability and basic functionality:** Tests the presence and basic usage of these APIs for common text and cryptographic operations within the worklet.

9. **Feature flag based API availability:**
    *   **Web Locks:** Tests that APIs related to Web Locks (`SharedStorageWorkletNavigator`, `LockManager`, `Lock`, `navigator`) are not exposed when the corresponding feature flag is disabled.
    *   **Interest Groups:** Verifies that the `interestGroups()` function is not available when its feature flag is disabled.
    *   **Private Aggregation (disabled):** Checks that the `privateAggregation` API is not available (or throws specific errors during `addModule`) when the feature flag is disabled, and that only the expected global objects and functions are present. It also tests scenarios where `addModule` fails.
    *   **Private Aggregation (enabled):**  Tests the successful contribution to histograms using the `privateAggregation` API when the feature is enabled. It includes validating the bucket and value of the contribution, as well as the use counters. It also covers scenarios with debug mode and filtering IDs.

**Relationships with JavaScript, HTML, CSS:**

*   **JavaScript:** This entire test suite is focused on the interaction between the C++ Blink engine and JavaScript code running within a Shared Storage Worklet. The tests define JavaScript classes and functions that utilize the `sharedStorage` API and other JavaScript built-ins.
    *   **Example:** The code `for await (const [key, value] of sharedStorage.entries()) { console.log(key + ';' + value); }` directly demonstrates JavaScript's asynchronous iteration capabilities interacting with the `sharedStorage` API.
*   **HTML:** While this specific code doesn't directly interact with HTML, the Shared Storage API itself is a web platform feature accessible from JavaScript running within HTML pages. The worklet is loaded and executed in the context of a browsing context initiated by an HTML page.
*   **CSS:** CSS is not directly involved in the functionality being tested here.

**Logic Inference (Hypothetical Input & Output):**

*   **Assumption:** The underlying shared storage contains the following key-value pairs: `{"key0": "value0", "key1": "value1", "key2": "value2", "key3": "value3"}`

*   **Test:** `Entries_TwoBatches_Success`

    *   **Input:**  The JavaScript code iterates through `sharedStorage.entries()`. The test simulates the underlying storage returning the entries in two batches.
    *   **Simulated Output (from `DidReadEntries`):**
        *   Batch 1: `success=true`, `entries=[{"key0", "value0"}]`, `has_more_entries=true`
        *   Batch 2: `success=true`, `entries=[{"key1", "value1"}, {"key2", "value2"}]`, `has_more_entries=false`
    *   **Expected Output (from `console.log`):**
        ```
        key0;value0
        key1;value1
        key2;value2
        ```
    *   **Expected Test Outcome:** `run_result.success` is `true`.

*   **Test:** `Keys_ManuallyCallNext`

    *   **Input:** The JavaScript code manually calls `next()` on the asynchronous iterator for `sharedStorage.keys()`, skipping the first two results. The underlying storage returns keys in batches.
    *   **Simulated Output (from `DidReadEntries`):**
        *   Batch 1: `success=true`, `keys=["key0"]`, `has_more_entries=true`
        *   Batch 2: `success=true`, `keys=["key1", "key2"]`, `has_more_entries=true`
        *   Batch 3: `success=true`, `keys=["key3"]`, `has_more_entries=false`
    *   **Expected Output (from `console.log(JSON.stringify(result))`):**
        ```json
        {"done":false,"value":"key2"}
        {"done":false,"value":"key3"}
        {"done":true}
        {"done":true}
        ```
    *   **Expected Test Outcome:** `run_result.success` is `true`.

**User/Programming Errors:**

*   **Incorrect usage of asynchronous iterators:**  A common error would be to not use `await` when calling `keys_iterator.next()`, which would lead to incorrect handling of the asynchronous results. The tests like `Keys_ManuallyCallNext` demonstrate the correct way to use these iterators.
*   **Assuming synchronous behavior:** Developers might mistakenly assume that operations like `sharedStorage.entries()` return all data immediately, while they are actually asynchronous and may involve multiple batches. The tests with multiple `DidReadEntries` calls highlight this.
*   **Not handling errors:**  A developer might not check for errors during iteration or budget retrieval. The tests with `/*success=*/false` in `DidReadEntries` demonstrate how errors should be handled.
*   **Accessing `sharedStorage` during `addModule()`:** The tests for Private Aggregation specifically point out that `sharedStorage` cannot be accessed during the `addModule()` phase and will result in an error.

**User Operation Steps and Debugging Clues:**

To reach this code during debugging, a typical scenario would involve:

1. **User interacts with a website:** The user visits a website that utilizes the Shared Storage API.
2. **Website initiates a Shared Storage operation:** The website's JavaScript code calls a method on the `sharedStorage` object (e.g., `sharedStorage.set()`, `sharedStorage.run()`).
3. **Worklet execution:** If the operation involves a worklet (using `sharedStorage.run()`), the browser loads and executes the specified worklet script.
4. **Worklet interacts with Shared Storage:** The worklet's JavaScript code accesses the `sharedStorage` API (e.g., using `sharedStorage.entries()`, `sharedStorage.get()`).
5. **Blink engine handles the request:** The Blink rendering engine processes the worklet's request to interact with shared storage. This involves the C++ code in `blink/renderer/modules/shared_storage/`.
6. **Debugging:** A developer debugging this process might set breakpoints in the C++ code (like `shared_storage_worklet_unittest.cc`) to understand how the worklet's JavaScript interacts with the underlying storage and how errors are handled. They might inspect the values of variables like `pending_entries_listeners_`, the contents of `observed_console_log_messages_`, and the results of `run_future`.

**Summary of Functionality (Part 4):**

This section of the test suite comprehensively verifies the core functionalities of the `sharedStorage` API within a Shared Storage Worklet, focusing on asynchronous operations like iterating through entries, keys, and values, retrieving the remaining budget, and accessing the context. It also tests the availability and basic functionality of standard JavaScript APIs like `crypto` and text encoding/decoding within the worklet environment. Furthermore, it ensures proper handling of errors and the conditional availability of features based on their respective feature flags, particularly focusing on the Private Aggregation API.

### 提示词
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
esult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          for await (const [key, value] of sharedStorage.entries()) {
            console.log(key + ';' + value);
          }
        }
      }

      register("test-operation", TestClass);
  )");

  base::test::TestFuture<bool, const std::string&> run_future;
  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), run_future.GetCallback());
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->pending_entries_listeners_.size(), 1u);

  mojo::Remote<blink::mojom::SharedStorageEntriesListener> listener =
      test_client_->TakeEntriesListenerAtFront();
  listener->DidReadEntries(
      /*success=*/false, /*error_message=*/"Internal error 12345",
      CreateBatchResult({}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/0);

  RunResult run_result{run_future.Get<0>(), run_future.Get<1>()};
  EXPECT_FALSE(run_result.success);
  EXPECT_EQ(run_result.error_message, "OperationError: Internal error 12345");

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Entries_TwoBatches_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          for await (const [key, value] of sharedStorage.entries()) {
            console.log(key + ';' + value);
          }
        }
      }

      register("test-operation", TestClass);
  )");

  base::test::TestFuture<bool, const std::string&> run_future;
  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), run_future.GetCallback());
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->pending_entries_listeners_.size(), 1u);

  mojo::Remote<blink::mojom::SharedStorageEntriesListener> listener =
      test_client_->TakeEntriesListenerAtFront();
  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key0", u"value0"}}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/3);
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "key0;value0");

  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key1", u"value1"}, {u"key2", u"value2"}}),
      /*has_more_entries=*/false, /*total_queued_to_send=*/3);

  RunResult run_result{run_future.Get<0>(), run_future.Get<1>()};
  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 3u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[1], "key1;value1");
  EXPECT_EQ(test_client_->observed_console_log_messages_[2], "key2;value2");
}

TEST_F(SharedStorageWorkletTest, Entries_SecondBatchError_Failure) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          for await (const [key, value] of sharedStorage.entries()) {
            console.log(key + ';' + value);
          }
        }
      }

      register("test-operation", TestClass);
  )");

  base::test::TestFuture<bool, const std::string&> run_future;
  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), run_future.GetCallback());
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->pending_entries_listeners_.size(), 1u);

  mojo::Remote<blink::mojom::SharedStorageEntriesListener> listener =
      test_client_->TakeEntriesListenerAtFront();
  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key0", u"value0"}}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/3);
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "key0;value0");

  listener->DidReadEntries(
      /*success=*/false, /*error_message=*/"Internal error 12345",
      CreateBatchResult({}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/3);

  RunResult run_result{run_future.Get<0>(), run_future.Get<1>()};
  EXPECT_FALSE(run_result.success);
  EXPECT_EQ(run_result.error_message, "OperationError: Internal error 12345");

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
}

TEST_F(SharedStorageWorkletTest, Keys_OneBatch_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          for await (const key of sharedStorage.keys()) {
            console.log(key);
          }
        }
      }

      register("test-operation", TestClass);
  )");

  base::test::TestFuture<bool, const std::string&> run_future;
  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), run_future.GetCallback());
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->pending_keys_listeners_.size(), 1u);

  mojo::Remote<blink::mojom::SharedStorageEntriesListener> listener =
      test_client_->TakeKeysListenerAtFront();
  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key0", u"value0"}, {u"key1", u"value1"}}),
      /*has_more_entries=*/false, /*total_queued_to_send=*/2);

  RunResult run_result{run_future.Get<0>(), run_future.Get<1>()};
  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 2u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "key0");
  EXPECT_EQ(test_client_->observed_console_log_messages_[1], "key1");
}

TEST_F(SharedStorageWorkletTest, Keys_ManuallyCallNext) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          const keys_iterator = sharedStorage.keys()[Symbol.asyncIterator]();

          keys_iterator.next(); // result0 skipped
          keys_iterator.next(); // result1 skipped

          const result2 = await keys_iterator.next();
          console.log(JSON.stringify(result2));

          const result3 = await keys_iterator.next();
          console.log(JSON.stringify(result3));

          const result4 = await keys_iterator.next();
          console.log(JSON.stringify(result4));

          const result5 = await keys_iterator.next();
          console.log(JSON.stringify(result5));
        }
      }

      register("test-operation", TestClass);
  )");

  base::test::TestFuture<bool, const std::string&> run_future;
  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), run_future.GetCallback());
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->pending_keys_listeners_.size(), 1u);

  mojo::Remote<blink::mojom::SharedStorageEntriesListener> listener =
      test_client_->TakeKeysListenerAtFront();
  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key0", /*value=*/{}}}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/4);
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 0u);

  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key1", /*value=*/{}}, {u"key2", /*value=*/{}}}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/4);
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0],
            "{\"done\":false,\"value\":\"key2\"}");

  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key3", /*value=*/{}}}),
      /*has_more_entries=*/false, /*total_queued_to_send=*/4);

  RunResult run_result{run_future.Get<0>(), run_future.Get<1>()};
  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 4u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[1],
            "{\"done\":false,\"value\":\"key3\"}");
  EXPECT_EQ(test_client_->observed_console_log_messages_[2], "{\"done\":true}");
  EXPECT_EQ(test_client_->observed_console_log_messages_[3], "{\"done\":true}");
}

TEST_F(SharedStorageWorkletTest, Values_ManuallyCallNext) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          const values_iterator = (
            sharedStorage.values()[Symbol.asyncIterator]());

          values_iterator.next(); // result0 skipped
          values_iterator.next(); // result1 skipped

          const result2 = await values_iterator.next();
          console.log(JSON.stringify(result2));

          const result3 = await values_iterator.next();
          console.log(JSON.stringify(result3));

          const result4 = await values_iterator.next();
          console.log(JSON.stringify(result4));

          const result5 = await values_iterator.next();
          console.log(JSON.stringify(result5));
        }
      }

      register("test-operation", TestClass);
  )");

  base::test::TestFuture<bool, const std::string&> run_future;
  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), run_future.GetCallback());
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->pending_entries_listeners_.size(), 1u);

  mojo::Remote<blink::mojom::SharedStorageEntriesListener> listener =
      test_client_->TakeEntriesListenerAtFront();
  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key0", u"value0"}}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/4);
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 0u);

  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key1", u"value1"}, {u"key2", u"value2"}}),
      /*has_more_entries=*/true, /*total_queued_to_send=*/4);
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0],
            "{\"done\":false,\"value\":\"value2\"}");

  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{},
      CreateBatchResult({{u"key3", u"value3"}}),
      /*has_more_entries=*/false, /*total_queued_to_send=*/4);

  RunResult run_result{run_future.Get<0>(), run_future.Get<1>()};
  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 4u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[1],
            "{\"done\":false,\"value\":\"value3\"}");
  EXPECT_EQ(test_client_->observed_console_log_messages_[2], "{\"done\":true}");
  EXPECT_EQ(test_client_->observed_console_log_messages_[3], "{\"done\":true}");
}

TEST_F(SharedStorageWorkletTest, RemainingBudget_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let a = await sharedStorage.remainingBudget();
          console.log(a);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->remaining_budget_result_ = RemainingBudgetResult{
      .success = false, .error_message = "error 123", .bits = 0};

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_remaining_budget_count_, 1u);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, RemainingBudget_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let a = await sharedStorage.remainingBudget();
          console.log(a);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->remaining_budget_result_ = RemainingBudgetResult{
      .success = true, .error_message = std::string(), .bits = 2.0};

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_remaining_budget_count_, 1u);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "2");
}

TEST_F(SharedStorageWorkletTest, ContextAttribute_Undefined) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          console.log(sharedStorage.context);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "undefined");

  histogram_tester_.ExpectUniqueSample(
      "Storage.SharedStorage.Worklet.Context.IsDefined", /*sample=*/false,
      /*expected_bucket_count=*/1);
}

TEST_F(SharedStorageWorkletTest, ContextAttribute_String) {
  embedder_context_ = u"some embedder context";

  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          console.log(sharedStorage.context);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0],
            "some embedder context");

  histogram_tester_.ExpectUniqueSample(
      "Storage.SharedStorage.Worklet.Context.IsDefined", /*sample=*/true,
      /*expected_bucket_count=*/1);
}

// Test that methods on sharedStorage are resolved asynchronously, e.g. param
// validation failures won't affect the result of run().
TEST_F(SharedStorageWorkletTest,
       AsyncFailuresDuringOperation_OperationSucceed) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          sharedStorage.set();
          sharedStorage.append();
          sharedStorage.delete();
          sharedStorage.get();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());
}

TEST_F(SharedStorageWorkletTest, Crypto_GetRandomValues) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          const myArray = new BigUint64Array(2);
          crypto.getRandomValues(myArray);
          console.log(myArray[0]);
          console.log(myArray[1]);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 2u);
  // Naive test for randomness: the two numbers are different.
  EXPECT_NE(test_client_->observed_console_log_messages_[0],
            test_client_->observed_console_log_messages_[1]);
}

TEST_F(SharedStorageWorkletTest, Crypto_RandomUUID) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          console.log(crypto.randomUUID());
          console.log(crypto.randomUUID());
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 2u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0].size(), 36u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[1].size(), 36u);
  // Naive test for randomness: the two numbers are different.
  EXPECT_NE(test_client_->observed_console_log_messages_[0],
            test_client_->observed_console_log_messages_[1]);
}

TEST_F(SharedStorageWorkletTest,
       TextEncoderDecoderAndSubtleCryptoEncryptDecrypt) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let iv = crypto.getRandomValues(new Uint8Array(12));

          let key = await crypto.subtle.generateKey(
            {
              name: "AES-GCM",
              length: 256,
            },
            true,
            ["encrypt", "decrypt"]
          );

          let text = "123abc";
          let encodedText = new TextEncoder().encode(text);

          let ciphertext = await crypto.subtle.encrypt(
            {name:"AES-GCM", iv:iv}, key, encodedText);

          let decipheredText = await crypto.subtle.decrypt(
            {name:"AES-GCM", iv}, key, ciphertext);

          let decodedText = new TextDecoder().decode(decipheredText)

          console.log(decodedText);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "123abc");
}

class SharedStorageWebLocksDisabledTest : public SharedStorageWorkletTest {
 private:
  ScopedSharedStorageWebLocksForTest
      shared_storage_web_locks_runtime_enabled_feature{/*enabled=*/false};
};

TEST_F(SharedStorageWebLocksDisabledTest,
       InterfaceAndObjectExposure_DuringAddModule) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
    var expectedUndefinedVariables = [
      "SharedStorageWorkletNavigator",
      "LockManager",
      "Lock",
      "navigator",
    ];

    for (let expectedUndefined of expectedUndefinedVariables) {
      if (eval("typeof " + expectedUndefined) !== "undefined") {
        throw Error(expectedUndefined + " is not undefined.")
      }
    }
  )");

  EXPECT_TRUE(add_module_result.success);
}

class SharedStorageInterestGroupsDisabledTest
    : public SharedStorageWorkletTest {
 private:
  ScopedInterestGroupsInSharedStorageWorkletForTest
      interest_groups_in_shared_storage_worklet_runtime_enabled_feature{
          /*enabled=*/false};
};

TEST_F(SharedStorageInterestGroupsDisabledTest, InterestGroups) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
    interestGroups();
  )");

  EXPECT_FALSE(add_module_result.success);
  EXPECT_THAT(
      add_module_result.error_message,
      testing::HasSubstr("ReferenceError: interestGroups is not defined"));
}

// TODO(crbug.com/1316659): When the Private Aggregation feature is removed
// (after being default enabled for a few milestones), removes these tests and
// integrate the feature-enabled tests into the broader tests.
class SharedStoragePrivateAggregationDisabledTest
    : public SharedStorageWorkletTest {
 public:
  SharedStoragePrivateAggregationDisabledTest() {
    private_aggregation_feature_.InitAndDisableFeature(
        blink::features::kPrivateAggregationApi);
  }

 private:
  base::test::ScopedFeatureList private_aggregation_feature_;
};

TEST_F(SharedStoragePrivateAggregationDisabledTest,
       GlobalScopeObjectsAndFunctions_DuringAddModule) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
    var expectedObjects = [
      "console",
      "crypto"
    ];

    var expectedFunctions = [
      "SharedStorage",
      "Crypto",
      "CryptoKey",
      "SubtleCrypto",
      "TextEncoder",
      "TextDecoder",
      "register",
      "console.log"
    ];

    var expectedUndefinedVariables = [
      // PrivateAggregation related variables are undefined because the
      // corresponding base::Feature(s) are not enabled.
      "privateAggregation",
      "PrivateAggregation"
    ];

    for (let expectedObject of expectedObjects) {
      if (eval("typeof " + expectedObject) !== "object") {
        throw Error(expectedObject + " is not object type.")
      }
    }

    for (let expectedFunction of expectedFunctions) {
      if (eval("typeof " + expectedFunction) !== "function") {
        throw Error(expectedFunction + " is not function type.")
      }
    }

    for (let expectedUndefined of expectedUndefinedVariables) {
      if (eval("typeof " + expectedUndefined) !== "undefined") {
        throw Error(expectedUndefined + " is not undefined.")
      }
    }

    // Verify that trying to access `sharedStorage` would throw a custom error.
    try {
      sharedStorage;
    } catch (e) {
      console.log("Expected error:", e.message);
    }
  )");

  EXPECT_TRUE(add_module_result.success);
  EXPECT_EQ(add_module_result.error_message, "");

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0],
            "Expected error: Failed to read the 'sharedStorage' property from "
            "'SharedStorageWorkletGlobalScope': sharedStorage cannot be "
            "accessed during addModule().");
}

TEST_F(SharedStoragePrivateAggregationDisabledTest,
       GlobalScopeObjectsAndFunctions_AfterAddModuleSuccess) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          var expectedObjects = [
            "console",
            "sharedStorage",
            "crypto"
          ];

          var expectedFunctions = [
            "SharedStorage",
            "Crypto",
            "CryptoKey",
            "SubtleCrypto",
            "TextEncoder",
            "TextDecoder",
            "register",
            "sharedStorage.set",
            "sharedStorage.append",
            "sharedStorage.delete",
            "sharedStorage.clear",
            "sharedStorage.get",
            "sharedStorage.length",
            "sharedStorage.keys",
            "sharedStorage.entries",
            "sharedStorage.remainingBudget"
          ];

          // Those are either not implemented yet, or should stay undefined.
          var expectedUndefinedVariables = [
            "sharedStorage.selectURL",
            "sharedStorage.run",
            "sharedStorage.worklet",
            "sharedStorage.context",

            // PrivateAggregation related variables are undefined because the
            // corresponding base::Feature(s) are not enabled.
            "privateAggregation",
            "PrivateAggregation"
          ];

          for (let expectedObject of expectedObjects) {
            if (eval("typeof " + expectedObject) !== "object") {
              throw Error(expectedObject + " is not object type.")
            }
          }

          for (let expectedFunction of expectedFunctions) {
            if (eval("typeof " + expectedFunction) !== "function") {
              throw Error(expectedFunction + " is not function type.")
            }
          }

          for (let expectedUndefined of expectedUndefinedVariables) {
            if (eval("typeof " + expectedUndefined) !== "undefined") {
              throw Error(expectedUndefined + " is not undefined.")
            }
          }
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_EQ(run_result.error_message, "");
}

TEST_F(SharedStoragePrivateAggregationDisabledTest,
       GlobalScopeObjectsAndFunctions_AfterAddModuleFailure) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          var expectedObjects = [
            "console",
            "sharedStorage",
            "crypto"
          ];

          var expectedFunctions = [
            "SharedStorage",
            "Crypto",
            "CryptoKey",
            "SubtleCrypto",
            "TextEncoder",
            "TextDecoder",
            "register",
            "sharedStorage.set",
            "sharedStorage.append",
            "sharedStorage.delete",
            "sharedStorage.clear",
            "sharedStorage.get",
            "sharedStorage.length",
            "sharedStorage.keys",
            "sharedStorage.entries",
            "sharedStorage.remainingBudget"
          ];

          // Those are either not implemented yet, or should stay undefined.
          var expectedUndefinedVariables = [
            "sharedStorage.selectURL",
            "sharedStorage.run",
            "sharedStorage.worklet",
            "sharedStorage.context",

            // PrivateAggregation related variables are undefined because the
            // corresponding base::Feature(s) are not enabled.
            "privateAggregation",
            "PrivateAggregation"
          ];

          for (let expectedObject of expectedObjects) {
            if (eval("typeof " + expectedObject) !== "object") {
              throw Error(expectedObject + " is not object type.")
            }
          }

          for (let expectedFunction of expectedFunctions) {
            if (eval("typeof " + expectedFunction) !== "function") {
              throw Error(expectedFunction + " is not function type.")
            }
          }

          for (let expectedUndefined of expectedUndefinedVariables) {
            if (eval("typeof " + expectedUndefined) !== "undefined") {
              throw Error(expectedUndefined + " is not undefined.")
            }
          }
        }
      }

      register("test-operation", TestClass);

      // This should fail the addModule()
      a;
  )");

  EXPECT_FALSE(add_module_result.success);
  EXPECT_THAT(add_module_result.error_message,
              testing::HasSubstr("ReferenceError: a is not defined"));

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_EQ(run_result.error_message, "");
}

class SharedStoragePrivateAggregationTest : public SharedStorageWorkletTest {
 public:
  SharedStoragePrivateAggregationTest() {
    private_aggregation_feature_.InitWithFeaturesAndParameters(
        /*enabled_features=*/
        {{blink::features::kPrivateAggregationApi,
          {{"enabled_in_shared_storage", "true"}}}},
        /*disabled_features=*/{});
  }

  // `error_message` being `nullptr` indicates no error is expected.
  void ExecuteScriptAndValidateContribution(
      const std::string& script_body,
      absl::uint128 expected_bucket,
      int expected_value,
      mojom::blink::DebugModeDetailsPtr expected_debug_mode_details =
          mojom::blink::DebugModeDetails::New(),
      std::optional<uint64_t> filtering_id = std::nullopt,
      int filtering_id_max_bytes = 1,
      std::string* error_message = nullptr) {
    AddModuleResult add_module_result =
        AddModule(/*script_content=*/base::StrCat(
            {"class TestClass { async run() {", script_body,
             "}}; register(\"test-operation\", TestClass);"}));

    EXPECT_CALL(*mock_private_aggregation_host_, ContributeToHistogram)
        .WillOnce(testing::Invoke(
            [&](Vector<
                blink::mojom::blink::AggregatableReportHistogramContributionPtr>
                    contributions) {
              ASSERT_EQ(contributions.size(), 1u);
              EXPECT_EQ(contributions[0]->bucket, expected_bucket);
              EXPECT_EQ(contributions[0]->value, expected_value);
            }));
    if (expected_debug_mode_details->is_enabled) {
      EXPECT_CALL(*mock_private_aggregation_host_, EnableDebugMode)
          .WillOnce(testing::Invoke([&](mojom::blink::DebugKeyPtr debug_key) {
            EXPECT_TRUE(debug_key == expected_debug_mode_details->debug_key);
          }));
    }

    RunResult run_result = Run("test-operation", CreateSerializedUndefined(),
                               filtering_id_max_bytes);

    EXPECT_EQ(run_result.success, (error_message == nullptr));

    if (error_message != nullptr) {
      *error_message = run_result.error_message;
    }

    std::vector<mojom::WebFeature> expected_use_counters = {
        mojom::WebFeature::kPrivateAggregationApiAll,
        mojom::WebFeature::kPrivateAggregationApiSharedStorage};
    if (expected_debug_mode_details->is_enabled) {
      expected_use_counters.push_back(
          mojom::WebFeature::kPrivateAggregationApiEnableDebugMode);
    }
    if (filtering_id.has_value()) {
      expected_use_counters.push_back(
          mojom::WebFeature::kPrivateAggregationApiFilteringIds);
    }

    EXPECT_THAT(test_client_->observed_use_counters_,
                testing::UnorderedElementsAreArray(expected_use_counters));

    mock_private_aggregation_host_->FlushForTesting();
  }

  std::string ExecuteScriptReturningError(
      const std::string& script_body,
      std::vector<mojom::WebFeature> expect_use_counters = {},
      int filtering_id_max_bytes = 1) {
    AddModuleResult add_module_result =
        AddModule(/*script_content=*/base::StrCat(
            {"class TestClass { async run() {", script_body,
             "}}; register(\"test-operation\", TestClass);"}));

    CHECK_EQ(ShouldDefinePrivateAggregationInSharedStorage(),
             !!mock_private_aggregation_host_);

    if (mock_private_aggregation_host_) {
      EXPECT_CALL(*mock_private_aggregation_host_, ContributeToHistogram)
          .Times(0);
      EXPECT_CALL(*mock_private_aggregation_host_, EnableDebugMode).Times(0);
    }

    RunResult run_result = Run("test-operation", CreateSerializedUndefined(),
                               filtering_id_max_bytes);
    EXPECT_FALSE(run_result.success);

    EXPECT_THAT(test_client_->observed_use_counters_,
                testing::UnorderedElementsAreArray(expect_use_counters));

    if (mock_private_aggregation_host_) {
      mock_private_aggregation_host_->FlushForTesting();
    }

    return run_result.error_message;
  }

 private:
  base::test::ScopedFeatureList private_aggregation_feature_;
};

TEST_F(SharedStoragePrivateAggregationTest,
       InterfaceAndObjectExposure_DuringAddModule) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
    // This will succeed.
    PrivateAggregation;

    // This will fail.
    privateAggregation;
  )");

  EXPECT_FALSE(add_module_result.success);
  EXPECT_THAT(add_module_result.error_message,
              testing::HasSubstr(
                  "privateAggregation cannot be accessed during addModule()"));
}

TEST_F(SharedStoragePrivateAggregationTest,
       InterfaceAndObjectExposure_AfterAddModuleSuccess) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          PrivateAggregation;
          privateAggregation;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXP
```