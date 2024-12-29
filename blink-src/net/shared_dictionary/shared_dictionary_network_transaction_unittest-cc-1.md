Response:
The user wants a summary of the functionality of the provided C++ code, which is part 2 of a larger file. I need to analyze the provided test cases to understand the capabilities of the `SharedDictionaryNetworkTransaction` class.

Here's a breakdown of the tests and their implications:

* **`MultipleContentEncodingWithSbr`:** Checks how the transaction handles multiple `content-encoding` headers when one of them is `dcb`. It verifies that if other encodings are present, the shared dictionary decoding is skipped, and the raw (likely Brotli) data is returned.
* **`AsyncDictionarySuccessBeforeStartReading`:** Tests the case where an asynchronous dictionary load completes successfully *before* the network transaction starts reading data.
* **`AsyncDictionarySuccessAfterStartReading`:** Tests the case where an asynchronous dictionary load completes successfully *after* the network transaction has begun reading data.
* **`AsyncDictionarySuccessAfterTransactionDestroy`:**  Examines how the transaction handles an asynchronous dictionary load when the transaction is destroyed before the dictionary is fully loaded. It verifies that the pending dictionary callback doesn't cause issues after the transaction's demise.
* **`AsyncDictionaryFailureBeforeStartReading`:** Tests the scenario where an asynchronous dictionary load fails before the transaction starts reading. It expects an `ERR_DICTIONARY_LOAD_FAILED` error.
* **`AsyncDictionaryFailureAfterStartReading`:**  Tests the scenario where an asynchronous dictionary load fails after the transaction has already started reading. It also expects an `ERR_DICTIONARY_LOAD_FAILED` error.
* **`Restart`:** Checks the behavior of restart methods (`RestartIgnoringLastError`, `RestartWithCertificate`, `RestartWithAuth`) when the underlying network transaction fails to start. It verifies that these restart attempts also fail.
* **`StopCaching`:** Verifies that calling `StopCaching` on the `SharedDictionaryNetworkTransaction` propagates the call to the underlying network transaction.
* **`DoneReading`:** Verifies that calling `DoneReading` on the `SharedDictionaryNetworkTransaction` propagates the call to the underlying network transaction.
* **`GetLoadState`:**  Checks the `GetLoadState` method at different points in the transaction lifecycle, specifically after starting and during reading.
* **`SharedZstd`:** Tests the functionality when the `content-encoding` is `dcz` (indicating shared Zstandard dictionary compression) and the feature is enabled. It verifies successful decompression.
* **`NoZstdDContentEncoding`:** Tests the case where shared Zstandard is enabled, but the `content-encoding` header is missing or doesn't include `dcz`. It ensures that no decompression is attempted.
* **`SharedDictionaryNetworkTransactionProtocolCheckTest` (Parameterized Tests):** These tests cover scenarios involving different HTTP protocols (HTTP/1.1, HTTP/2, HTTP/3) and feature flags for enabling shared dictionary transport over those protocols. The tests verify if the dictionary is used based on the protocol, feature flags, and whether the request is to `localhost`.

Based on these test cases, the primary function of `SharedDictionaryNetworkTransaction` revolves around handling network requests that might use shared dictionaries for compression. It needs to manage both synchronous and asynchronous dictionary loading, handle failures gracefully, and interact correctly with the underlying network transaction. The protocol-specific tests highlight the conditions under which shared dictionary compression is considered for different HTTP versions.
这是 `net/shared_dictionary/shared_dictionary_network_transaction_unittest.cc` 文件的第二部分，延续了第一部分的功能测试，专注于 `SharedDictionaryNetworkTransaction` 类的更具体和复杂的场景。

**归纳一下它的功能:**

这部分的主要功能是测试 `SharedDictionaryNetworkTransaction` 类在以下场景中的行为：

1. **处理多种内容编码：** 验证当响应头包含多个 `content-encoding` 时，只有当其中一个是 `dcb` (Shared Brotli Dictionary) 或 `dcz` (Shared Zstandard Dictionary) 时，才会尝试使用共享字典进行解码。如果存在其他编码，则不进行共享字典解码。
2. **异步字典加载的成功与失败：**  测试了异步加载共享字典的不同时机（在开始读取前、开始读取后）成功和失败的情况，以及事务在字典加载完成前被销毁的情况。
3. **事务重启：** 验证当底层的网络事务启动失败时，重启相关的操作也会失败。
4. **控制缓存行为：**  测试了 `StopCaching` 和 `DoneReading` 方法是否正确地传递到底层的网络事务。
5. **获取加载状态：**  验证了在事务的不同阶段调用 `GetLoadState` 方法能够返回正确的加载状态。
6. **支持共享 Zstandard 字典：** 测试了当启用共享 Zstandard 字典功能时，`SharedDictionaryNetworkTransaction` 是否能够正确处理 `content-encoding: dcz` 的响应，并进行解压。同时测试了当缺少 `dcz` 时，不会尝试进行 Zstandard 解压。
7. **基于协议的共享字典支持：** 通过参数化测试，详细验证了在不同的 HTTP 协议 (HTTP/1.1, HTTP/2, HTTP/3) 下，以及在不同的 Feature Flag 配置下，是否会尝试使用共享字典。这包括对 `localhost` 的特殊处理。

**与 Javascript 的功能关系：**

`SharedDictionaryNetworkTransaction` 的核心功能是在网络层处理压缩，对 Javascript 的影响是透明的。当 Javascript 发起网络请求，并接收到使用共享字典压缩的内容时，`SharedDictionaryNetworkTransaction` 会在底层完成解压，Javascript 代码接收到的已经是解压后的数据，无需关心压缩细节。

**举例说明：**

假设一个网站使用 Shared Brotli Dictionary 技术压缩资源。

* **用户在浏览器中访问该网站，Javascript 发起了一个请求。**
* **服务器返回的响应头包含 `content-encoding: dcb` 和 `available-dictionary: <dictionary-url>`。**
* **`SharedDictionaryNetworkTransaction` 会根据 `available-dictionary` 的 URL 获取共享字典。**
* **`SharedDictionaryNetworkTransaction` 使用获取到的字典解压响应体。**
* **Javascript 代码接收到的是解压后的内容，例如 HTML、CSS 或 Javascript 文件，就像没有使用压缩一样。**

**逻辑推理，假设输入与输出：**

**场景 1：`MultipleContentEncodingWithSbr`**

* **假设输入 (HTTP 响应头):** `content-encoding: dcb, deflate`，响应体是使用 Shared Brotli Dictionary 和 Deflate 压缩的数据。
* **预期输出：** 由于存在 `deflate`，`SharedDictionaryNetworkTransaction` 不会尝试使用共享字典解压，而是返回 Deflate 压缩后的数据 (对应测试用例中的 `kBrotliEncodedDataString`)。

**场景 2：`AsyncDictionarySuccessBeforeStartReading`**

* **假设输入：** 请求需要使用共享字典，且字典的异步加载在开始读取响应体之前成功完成。
* **预期输出：** `transaction.Read` 方法会返回解压后的数据 (对应测试用例中的 `kTestData`)。

**涉及用户或编程常见的使用错误：**

* **服务器配置错误：**  如果服务器配置了错误的 `content-encoding` 或 `available-dictionary` 头，或者提供的字典文件损坏，`SharedDictionaryNetworkTransaction` 可能会加载失败，导致 `ERR_DICTIONARY_LOAD_FAILED` 错误。这对于用户来说通常是不可见的，会表现为资源加载失败。
* **Feature Flag 配置错误：** 开发者或测试人员可能会错误地配置 Feature Flags，例如禁用了共享字典功能，导致即使服务器支持，浏览器也不会尝试使用。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 或点击链接。**
2. **浏览器解析 URL，并构建网络请求。**
3. **如果请求的资源可能使用共享字典，网络栈会尝试查找适用的共享字典。** 这可能涉及到检查缓存或发送额外的请求获取字典元数据。
4. **底层的网络事务 (例如 `HttpStream`) 被创建并开始与服务器建立连接。**
5. **服务器返回响应头，其中可能包含 `content-encoding: dcb` 或 `dcz` 以及 `available-dictionary`。**
6. **如果启用了共享字典功能，并且响应头指示使用了共享字典，`SharedDictionaryNetworkTransaction` 会被创建，并包装底层的网络事务。**
7. **如果需要异步加载字典，会发起字典加载操作。**
8. **用户代码 (例如 Javascript) 调用 `fetch` 或 `XMLHttpRequest` 的 `response.body.getReader().read()` 方法尝试读取响应体。**
9. **`SharedDictionaryNetworkTransaction` 的 `Read` 方法被调用。**
10. **如果字典加载成功，并且内容编码是 `dcb` 或 `dcz`，`SharedDictionaryNetworkTransaction` 会使用字典解压数据，并将解压后的数据返回给调用者。**
11. **如果在这个过程中发生错误（例如字典加载失败），`SharedDictionaryNetworkTransaction` 会返回相应的错误码。**

**作为调试线索：** 如果开发者遇到与共享字典相关的问题，例如资源加载失败或解压错误，可以检查以下几点：

* **Network 面板：** 查看请求的响应头，确认是否包含 `content-encoding: dcb` 或 `dcz` 和 `available-dictionary` 头。
* **`net-internals` (chrome://net-internals/#events):**  过滤与共享字典相关的事件，查看字典加载是否成功，以及解压过程是否有错误。
* **Feature Flags (chrome://flags):** 检查与共享字典相关的 Feature Flags 是否已正确启用。
* **服务器配置：**  确认服务器是否正确配置了共享字典相关的头信息，并且字典文件可访问且有效。

Prompt: 
```
这是目录为net/shared_dictionary/shared_dictionary_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
f.get(), buf->size(), read_callback.callback())),
              test::IsError(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER));
}
TEST_F(SharedDictionaryNetworkTransactionTest, MultipleContentEncodingWithSbr) {
  // Change MockTransaction to set `content-encoding: dcb, deflate`.
  scoped_mock_transaction_->response_headers =
      "content-encoding: dcb, deflate\n";

  MockHttpRequest request(*scoped_mock_transaction_);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(kTestDictionaryData);
      });
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  int read_result = read_callback.WaitForResult();

  // When there is Content-Encoding header which value is other than "dcb",
  // SharedDictionaryNetworkTransaction must not decode the body.
  EXPECT_THAT(read_result, kBrotliEncodedDataString.size());
  EXPECT_EQ(kBrotliEncodedDataString, std::string(buf->data(), read_result));
}

TEST_F(SharedDictionaryNetworkTransactionTest,
       AsyncDictionarySuccessBeforeStartReading) {
  scoped_refptr<DummyAsyncDictionary> dictionary =
      base::MakeRefCounted<DummyAsyncDictionary>(kTestDictionaryData);
  DummyAsyncDictionary* dictionary_ptr = dictionary.get();

  MockHttpRequest request(kBrotliDictionaryTestTransaction);
  request.dictionary_getter = base::BindRepeating(
      [](scoped_refptr<DummyAsyncDictionary>* dictionary,
         const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        CHECK(*dictionary);
        return std::move(*dictionary);
      },
      base::Unretained(&dictionary));
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  base::OnceCallback<void(int)> dictionary_read_all_callback =
      dictionary_ptr->TakeReadAllCallback();
  ASSERT_TRUE(dictionary_read_all_callback);
  std::move(dictionary_read_all_callback).Run(OK);

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  int read_result = read_callback.WaitForResult();
  EXPECT_THAT(read_result, kTestData.size());
  EXPECT_EQ(kTestData, std::string(buf->data(), read_result));
}

TEST_F(SharedDictionaryNetworkTransactionTest,
       AsyncDictionarySuccessAfterStartReading) {
  scoped_refptr<DummyAsyncDictionary> dictionary =
      base::MakeRefCounted<DummyAsyncDictionary>(kTestDictionaryData);
  DummyAsyncDictionary* dictionary_ptr = dictionary.get();

  MockHttpRequest request(kBrotliDictionaryTestTransaction);
  request.dictionary_getter = base::BindRepeating(
      [](scoped_refptr<DummyAsyncDictionary>* dictionary,
         const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        CHECK(*dictionary);
        return std::move(*dictionary);
      },
      base::Unretained(&dictionary));
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  base::OnceCallback<void(int)> dictionary_read_all_callback =
      dictionary_ptr->TakeReadAllCallback();
  ASSERT_TRUE(dictionary_read_all_callback);

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  RunUntilIdle();
  EXPECT_FALSE(read_callback.have_result());

  std::move(dictionary_read_all_callback).Run(OK);

  int read_result = read_callback.WaitForResult();
  EXPECT_THAT(read_result, kTestData.size());
  EXPECT_EQ(kTestData, std::string(buf->data(), read_result));
}

TEST_F(SharedDictionaryNetworkTransactionTest,
       AsyncDictionarySuccessAfterTransactionDestroy) {
  scoped_refptr<DummyAsyncDictionary> dictionary =
      base::MakeRefCounted<DummyAsyncDictionary>(kTestDictionaryData);
  DummyAsyncDictionary* dictionary_ptr = dictionary.get();

  MockHttpRequest request(kBrotliDictionaryTestTransaction);
  request.dictionary_getter = base::BindRepeating(
      [](scoped_refptr<DummyAsyncDictionary>* dictionary,
         const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        CHECK(*dictionary);
        return std::move(*dictionary);
      },
      base::Unretained(&dictionary));
  std::unique_ptr<SharedDictionaryNetworkTransaction> transaction =
      std::make_unique<SharedDictionaryNetworkTransaction>(
          CreateNetworkTransaction(), /*enable_shared_zstd=*/false);
  transaction->SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction->Start(&request, start_callback.callback(),
                                 NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  base::OnceCallback<void(int)> dictionary_read_all_callback =
      dictionary_ptr->TakeReadAllCallback();
  ASSERT_TRUE(dictionary_read_all_callback);

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction->Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  RunUntilIdle();
  EXPECT_FALSE(read_callback.have_result());

  transaction.reset();

  std::move(dictionary_read_all_callback).Run(OK);

  EXPECT_FALSE(read_callback.have_result());
}

TEST_F(SharedDictionaryNetworkTransactionTest,
       AsyncDictionaryFailureBeforeStartReading) {
  scoped_refptr<DummyAsyncDictionary> dictionary =
      base::MakeRefCounted<DummyAsyncDictionary>(kTestDictionaryData);
  DummyAsyncDictionary* dictionary_ptr = dictionary.get();

  MockHttpRequest request(kBrotliDictionaryTestTransaction);
  request.dictionary_getter = base::BindRepeating(
      [](scoped_refptr<DummyAsyncDictionary>* dictionary,
         const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        CHECK(*dictionary);
        return std::move(*dictionary);
      },
      base::Unretained(&dictionary));
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  base::OnceCallback<void(int)> dictionary_read_all_callback =
      dictionary_ptr->TakeReadAllCallback();
  ASSERT_TRUE(dictionary_read_all_callback);
  std::move(dictionary_read_all_callback).Run(ERR_FAILED);

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_DICTIONARY_LOAD_FAILED));
}

TEST_F(SharedDictionaryNetworkTransactionTest,
       AsyncDictionaryFailureAfterStartReading) {
  scoped_refptr<DummyAsyncDictionary> dictionary =
      base::MakeRefCounted<DummyAsyncDictionary>(kTestDictionaryData);
  DummyAsyncDictionary* dictionary_ptr = dictionary.get();

  MockHttpRequest request(kBrotliDictionaryTestTransaction);
  request.dictionary_getter = base::BindRepeating(
      [](scoped_refptr<DummyAsyncDictionary>* dictionary,
         const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        CHECK(*dictionary);
        return std::move(*dictionary);
      },
      base::Unretained(&dictionary));
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  base::OnceCallback<void(int)> dictionary_read_all_callback =
      dictionary_ptr->TakeReadAllCallback();
  ASSERT_TRUE(dictionary_read_all_callback);

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  RunUntilIdle();
  EXPECT_FALSE(read_callback.have_result());

  std::move(dictionary_read_all_callback).Run(ERR_FAILED);

  EXPECT_EQ(ERR_DICTIONARY_LOAD_FAILED, read_callback.WaitForResult());
}

TEST_F(SharedDictionaryNetworkTransactionTest, Restart) {
  ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.start_return_code = ERR_FAILED;
  MockHttpRequest request(mock_transaction);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return nullptr;
      });
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(ERR_FAILED));

  {
    TestCompletionCallback restart_callback;
    ASSERT_THAT(
        transaction.RestartIgnoringLastError(restart_callback.callback()),
        test::IsError(ERR_FAILED));
  }
  {
    TestCompletionCallback restart_callback;
    ASSERT_THAT(
        transaction.RestartWithCertificate(
            /*client_cert=*/nullptr,
            /*client_private_key=*/nullptr, restart_callback.callback()),
        test::IsError(ERR_FAILED));
  }
  {
    TestCompletionCallback restart_callback;
    ASSERT_THAT(transaction.RestartWithAuth(AuthCredentials(),
                                            restart_callback.callback()),
                test::IsError(ERR_FAILED));
  }
  ASSERT_FALSE(transaction.IsReadyToRestartForAuth());
}

TEST_F(SharedDictionaryNetworkTransactionTest, StopCaching) {
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  EXPECT_FALSE(network_layer().stop_caching_called());
  transaction.StopCaching();
  EXPECT_TRUE(network_layer().stop_caching_called());
}

TEST_F(SharedDictionaryNetworkTransactionTest, DoneReading) {
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  EXPECT_FALSE(network_layer().done_reading_called());
  transaction.DoneReading();
  EXPECT_TRUE(network_layer().done_reading_called());
}

TEST_F(SharedDictionaryNetworkTransactionTest, GetLoadState) {
  ScopedMockTransaction scoped_mock_transaction(kSimpleGET_Transaction);
  MockHttpRequest request(scoped_mock_transaction);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return nullptr;
      });
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  EXPECT_EQ(LOAD_STATE_IDLE, transaction.GetLoadState());

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(1);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  int read_result = read_callback.WaitForResult();
  EXPECT_THAT(read_result, 1);

  EXPECT_EQ(LOAD_STATE_READING_RESPONSE, transaction.GetLoadState());
}

TEST_F(SharedDictionaryNetworkTransactionTest, SharedZstd) {
  // Override MockTransaction to use `content-encoding: dcz`.
  scoped_mock_transaction_.reset();
  ScopedMockTransaction new_mock_transaction(kZstdDictionaryTestTransaction);

  MockHttpRequest request(new_mock_transaction);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(kTestDictionaryData);
      });
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/true);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
#if defined(NET_DISABLE_ZSTD)
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_CONTENT_DECODING_FAILED));
#else   // defined(NET_DISABLE_ZSTD)
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  int read_result = read_callback.WaitForResult();
  EXPECT_THAT(read_result, kTestData.size());
  EXPECT_EQ(kTestData, std::string(buf->data(), read_result));
#endif  // defined(NET_DISABLE_ZSTD)
}

TEST_F(SharedDictionaryNetworkTransactionTest, NoZstdDContentEncoding) {
  // Change MockTransaction to remove `content-encoding: dcz`.
  scoped_mock_transaction_.reset();
  ScopedMockTransaction scoped_mock_transaction(kZstdDictionaryTestTransaction);
  scoped_mock_transaction.response_headers = "";

  MockHttpRequest request(scoped_mock_transaction);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(kTestDictionaryData);
      });
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/true);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  int read_result = read_callback.WaitForResult();

  // When there is no "content-encoding: dcz" header,
  // SharedDictionaryNetworkTransaction must not decode the body.
  EXPECT_THAT(read_result, kZstdEncodedDataString.size());
  EXPECT_EQ(kZstdEncodedDataString, std::string(buf->data(), read_result));
}

enum class ProtocolCheckProtocolTestCase {
  kHttp1,
  kHttp2,
  kHttp3,
};
std::string ToString(ProtocolCheckProtocolTestCase protocol) {
  switch (protocol) {
    case ProtocolCheckProtocolTestCase::kHttp1:
      return "Http1";
    case ProtocolCheckProtocolTestCase::kHttp2:
      return "Http2";
    case ProtocolCheckProtocolTestCase::kHttp3:
      return "Http3";
  }
}

enum class ProtocolCheckHttp1TestCase {
  kAllowHttp1,
  kDoNotAllowHttp1,
};
std::string ToString(ProtocolCheckHttp1TestCase feature) {
  switch (feature) {
    case ProtocolCheckHttp1TestCase::kAllowHttp1:
      return "AllowHttp1";
    case ProtocolCheckHttp1TestCase::kDoNotAllowHttp1:
      return "DoNotAllowHttp1";
  }
}

enum class ProtocolCheckHttp2TestCase {
  kAllowHttp2,
  kDoNotAllowHttp2,
};
std::string ToString(ProtocolCheckHttp2TestCase feature) {
  switch (feature) {
    case ProtocolCheckHttp2TestCase::kAllowHttp2:
      return "AllowHttp2";
    case ProtocolCheckHttp2TestCase::kDoNotAllowHttp2:
      return "DoNotAllowHttp2";
  }
}

enum class ProtocolCheckHostTestCase {
  kLocalHost,
  kNonLocalhost,
};
std::string ToString(ProtocolCheckHostTestCase host_type) {
  switch (host_type) {
    case ProtocolCheckHostTestCase::kLocalHost:
      return "LocalHost";
    case ProtocolCheckHostTestCase::kNonLocalhost:
      return "NonLocalhost";
  }
}

class SharedDictionaryNetworkTransactionProtocolCheckTest
    : public SharedDictionaryNetworkTransactionTest,
      public testing::WithParamInterface<
          std::tuple<ProtocolCheckHttp1TestCase,
                     ProtocolCheckHttp2TestCase,
                     ProtocolCheckProtocolTestCase,
                     ProtocolCheckHostTestCase>> {
 public:
  SharedDictionaryNetworkTransactionProtocolCheckTest() {
    std::vector<base::test::FeatureRef> enabled_features;
    std::vector<base::test::FeatureRef> disabled_features;
    if (AllowHttp1()) {
      enabled_features.push_back(
          features::kCompressionDictionaryTransportOverHttp1);
    } else {
      disabled_features.push_back(
          features::kCompressionDictionaryTransportOverHttp1);
    }
    if (AllowHttp2()) {
      enabled_features.push_back(
          features::kCompressionDictionaryTransportOverHttp2);
    } else {
      disabled_features.push_back(
          features::kCompressionDictionaryTransportOverHttp2);
    }
    scoped_feature_list_.InitWithFeatures(enabled_features, disabled_features);
  }
  SharedDictionaryNetworkTransactionProtocolCheckTest(
      const SharedDictionaryNetworkTransactionProtocolCheckTest&) = delete;
  SharedDictionaryNetworkTransactionProtocolCheckTest& operator=(
      const SharedDictionaryNetworkTransactionProtocolCheckTest&) = delete;
  ~SharedDictionaryNetworkTransactionProtocolCheckTest() override = default;

 protected:
  MockTransaction CreateMockTransaction() {
    MockTransaction mock_transaction = kBrotliDictionaryTestTransaction;
    if (IsLocalHost()) {
      mock_transaction.url = "http://localhost/test";
    }
    if (!ShuoldUseDictionary()) {
      // Change MockTransaction to check that there is no available-dictionary
      // header.
      mock_transaction.handler =
          kTestTransactionHandlerWithoutAvailableDictionary;
    }
    if (IsHttp2()) {
      mock_transaction.transport_info.negotiated_protocol = kProtoHTTP2;
    } else if (IsHttp3()) {
      mock_transaction.transport_info.negotiated_protocol = kProtoQUIC;
    } else {
      mock_transaction.transport_info.negotiated_protocol = kProtoHTTP11;
    }
    return mock_transaction;
  }

 private:
  bool AllowHttp1() const {
    return std::get<0>(GetParam()) == ProtocolCheckHttp1TestCase::kAllowHttp1;
  }
  bool AllowHttp2() const {
    return std::get<1>(GetParam()) == ProtocolCheckHttp2TestCase::kAllowHttp2;
  }
  bool IsHttp1() const {
    return std::get<2>(GetParam()) == ProtocolCheckProtocolTestCase::kHttp1;
  }
  bool IsHttp2() const {
    return std::get<2>(GetParam()) == ProtocolCheckProtocolTestCase::kHttp2;
  }
  bool IsHttp3() const {
    return std::get<2>(GetParam()) == ProtocolCheckProtocolTestCase::kHttp3;
  }
  bool IsLocalHost() const {
    return std::get<3>(GetParam()) == ProtocolCheckHostTestCase::kLocalHost;
  }
  bool ShuoldUseDictionary() const {
    if (AllowHttp1()) {
      if (AllowHttp2()) {
        return true;
      } else {
        return IsLocalHost() || IsHttp1() || IsHttp3();
      }
    } else {
      if (AllowHttp2()) {
        return IsLocalHost() || IsHttp2() || IsHttp3();
      } else {
        return IsLocalHost() || IsHttp3();
      }
    }
  }

  base::test::ScopedFeatureList scoped_feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    All,
    SharedDictionaryNetworkTransactionProtocolCheckTest,
    ::testing::Combine(
        ::testing::Values(ProtocolCheckHttp1TestCase::kAllowHttp1,
                          ProtocolCheckHttp1TestCase::kDoNotAllowHttp1),
        ::testing::Values(ProtocolCheckHttp2TestCase::kAllowHttp2,
                          ProtocolCheckHttp2TestCase::kDoNotAllowHttp2),
        ::testing::Values(ProtocolCheckProtocolTestCase::kHttp1,
                          ProtocolCheckProtocolTestCase::kHttp2,
                          ProtocolCheckProtocolTestCase::kHttp3),
        ::testing::Values(ProtocolCheckHostTestCase::kLocalHost,
                          ProtocolCheckHostTestCase::kNonLocalhost)),
    [](const testing::TestParamInfo<std::tuple<ProtocolCheckHttp1TestCase,
                                               ProtocolCheckHttp2TestCase,
                                               ProtocolCheckProtocolTestCase,
                                               ProtocolCheckHostTestCase>>&
           info) {
      return ToString(std::get<0>(info.param)) + "_" +
             ToString(std::get<1>(info.param)) + "_" +
             ToString(std::get<2>(info.param)) + "_" +
             ToString(std::get<3>(info.param));
    });

TEST_P(SharedDictionaryNetworkTransactionProtocolCheckTest, Basic) {
  // Reset `scoped_mock_transaction_` to use the custom ScopedMockTransaction.
  scoped_mock_transaction_.reset();
  ScopedMockTransaction new_mock_transaction(CreateMockTransaction());

  MockHttpRequest request(new_mock_transaction);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(kTestDictionaryData);
      });
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return true; }));

  TestCompletionCallback start_callback;
  ASSERT_THAT(transaction.Start(&request, start_callback.callback(),
                                NetLogWithSource()),
              test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(start_callback.WaitForResult(), test::IsError(OK));

  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(
      transaction.Read(buf.get(), buf->size(), read_callback.callback()),
      test::IsError(ERR_IO_PENDING));
  int read_result = read_callback.WaitForResult();
  EXPECT_THAT(read_result, kTestData.size());
  EXPECT_EQ(kTestData, std::string(buf->data(), read_result));
}

}  // namespace

}  // namespace net

"""


```