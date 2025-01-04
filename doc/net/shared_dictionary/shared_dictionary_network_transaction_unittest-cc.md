Response:
The user wants a summary of the provided C++ code file, focusing on its functionality within the Chromium networking stack. I need to identify the main purpose of this unit test file and relate it to shared dictionaries.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the file's purpose:** The filename `shared_dictionary_network_transaction_unittest.cc` immediately suggests that this file contains unit tests for the `SharedDictionaryNetworkTransaction` class. The `unittest.cc` suffix is a strong indicator.

2. **Analyze the includes:** The included headers provide clues about the functionalities being tested. Key headers include:
    * `net/shared_dictionary/shared_dictionary_network_transaction.h`:  Confirms that the file tests this specific class.
    * `net/shared_dictionary/*`: Indicates the tests are related to shared dictionaries.
    * `net/http/*`: Suggests interaction with HTTP transactions.
    * `net/test/*`, `testing/gtest/*`:  Confirms this is a unit test file using the Google Test framework.

3. **Examine the test structure:** The code defines a test fixture `SharedDictionaryNetworkTransactionTest` which inherits from `::testing::Test`. This is standard practice in gtest. The `TEST_F` macros define individual test cases.

4. **Understand the test scenarios:**  Reading through the individual `TEST_F` functions reveals the specific aspects of `SharedDictionaryNetworkTransaction` being tested. Common themes emerge:
    * **Dictionary Usage:** Tests where a dictionary is provided and the expected behavior (request headers, response decoding) is verified.
    * **Dictionary Absence:** Tests where no dictionary is provided or allowed.
    * **Feature Flags:** Tests for behavior when specific feature flags related to shared dictionaries are enabled or disabled.
    * **Error Handling:** Tests that simulate error conditions or incorrect configurations.
    * **Request Headers:** Verification of specific headers (e.g., `available-dictionary`, `dictionary-id`).
    * **Content Encoding:** Tests involving `dcb` (brotli with dictionary) and `dcz` (zstd with dictionary) content encodings.

5. **Identify key components:**  The code uses `MockNetworkLayer` and `MockTransaction` to simulate network interactions. `DummySyncDictionary` and `DummyAsyncDictionary` are used as test implementations of the `SharedDictionary` interface. `TestCompletionCallback` is used for asynchronous testing.

6. **Synthesize the functionality:** Based on the observations above, the core functionality of the test file can be summarized as:  testing the `SharedDictionaryNetworkTransaction` class, which handles network requests when shared dictionaries are involved. This includes ensuring the class correctly interacts with dictionaries, sets appropriate request headers, and handles responses encoded using dictionaries.

7. **Address the specific questions in the prompt:**
    * **Functionality:**  Summarize the core purpose as described above.
    * **JavaScript Relation:**  Acknowledge that while the C++ code doesn't directly interact with JavaScript, the shared dictionary mechanism can improve web page loading, which is relevant to JavaScript performance.
    * **Logic Inference (Part 1):** Focus on the successful dictionary usage scenario as a basic example. Provide the input (dictionary, encoded data) and the expected output (decoded data).
    * **User/Programming Errors:**  Highlight cases where the dictionary is not provided, the feature is disabled, or the content encoding is incorrect.
    * **User Operation and Debugging:** Explain how a user action (requesting a resource) can trigger this code and how the tests can help debug issues related to shared dictionary usage.

8. **Formulate the summary:**  Combine the identified functionalities and answers to the specific questions into a concise summary, keeping in mind that this is "Part 1" of the explanation. Focus on the core functionalities and defer more detailed aspects to the subsequent parts.
这是文件 `net/shared_dictionary/shared_dictionary_network_transaction_unittest.cc` 的第一部分，它是一个 Chromium 网络栈的单元测试文件。这个文件的主要功能是**测试 `SharedDictionaryNetworkTransaction` 类的行为**。`SharedDictionaryNetworkTransaction` 是 Chromium 中处理网络请求时，如果涉及到共享字典压缩（Shared Brotli/Zstandard Dictionary Compression）的关键类。

以下是更详细的功能归纳：

1. **测试 `SharedDictionaryNetworkTransaction` 的基本功能:**  验证在启用共享字典功能时，`SharedDictionaryNetworkTransaction` 如何处理网络请求。这包括：
    *  **请求头的设置:** 验证是否正确地添加了 `available-dictionary` 和 `dictionary-id` 请求头，以告知服务器客户端可用的共享字典。
    *  **响应体的解码:** 测试当服务器返回使用共享字典压缩的内容时，`SharedDictionaryNetworkTransaction` 是否能够正确地使用本地字典进行解压缩。

2. **模拟不同的网络场景:**  通过使用 `MockNetworkLayer` 和 `MockTransaction`，该文件可以模拟各种不同的网络请求和响应场景，以便全面测试 `SharedDictionaryNetworkTransaction` 的行为，例如：
    *  服务器支持共享字典压缩并返回压缩后的内容。
    *  服务器不支持共享字典压缩。
    *  客户端没有可用的匹配字典。
    *  使用了错误的字典或压缩格式。

3. **测试与共享字典的交互:**  该文件创建了 `DummySyncDictionary` 和 `DummyAsyncDictionary` 两种简单的 `SharedDictionary` 实现，用于模拟同步和异步加载字典的情况，并测试 `SharedDictionaryNetworkTransaction` 与这些字典的交互。

4. **测试各种配置和条件:** 该文件还测试了在不同配置和条件下 `SharedDictionaryNetworkTransaction` 的行为，例如：
    *  是否允许使用共享字典 (`SetIsSharedDictionaryReadAllowedCallback`)。
    *  是否需要已知的根证书 (`features::kCompressionDictionaryTransportRequireKnownRootCert`)。
    *  不同的请求来源 (`frame_origin`)。
    *  不同的加载标志 (`load_flags`)。

5. **确保在不满足条件时不启用共享字典:**  测试在缺少必要的加载标志或响应头时，`SharedDictionaryNetworkTransaction` 是否会回退到正常的网络请求处理流程。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但共享字典功能最终会影响到 JavaScript 代码的执行效率。

* **提升页面加载速度:**  当浏览器请求资源时，如果服务器指示可以使用共享字典，并且浏览器本地有相应的字典，浏览器可以使用该字典解压缩服务器返回的压缩内容。这可以显著减少需要下载的数据量，从而加快页面加载速度，最终提升 JavaScript 代码的加载和执行速度。

**逻辑推理示例：**

**假设输入：**

* **客户端：**
    *  有一个内容为 "HelloHallo你好こんにちは" 的共享字典，其 SHA256 哈希值为 `c19728aed36503cfc81a0f5359e6f472e121f77bf20a2faac7994191293c0623`。
    *  发送一个带有 `LOAD_CAN_USE_SHARED_DICTIONARY` 标志的 GET 请求到 `https://test.example/test`。
* **服务器：**
    *  接收到请求后，检查请求头中的 `available-dictionary`，发现客户端拥有正确的字典。
    *  使用该字典对内容 "HelloこんにちはHallo你好HelloこんにちはHallo你好" 进行 Brotli 压缩，并设置 `content-encoding: dcb` 响应头。
    *  返回压缩后的数据。

**预期输出：**

*  `SharedDictionaryNetworkTransaction` 会成功识别出响应使用了共享字典压缩。
*  它会使用本地的共享字典对响应体进行解压缩。
*  最终读取到的数据是原始的未压缩内容 "HelloこんにちはHallo你好HelloこんにちはHallo你好"。

**用户或编程常见的使用错误示例：**

1. **用户禁用共享字典功能：** 用户可能在浏览器的设置中禁用了共享字典功能，导致即使服务器支持，浏览器也不会尝试使用共享字典，从而可能下载更多数据。

2. **编程错误 - 未设置正确的加载标志：**  开发者在发起网络请求时，可能忘记设置 `LOAD_CAN_USE_SHARED_DICTIONARY` 标志。这将导致 `SharedDictionaryNetworkTransaction` 不会尝试使用共享字典，即使本地有可用的字典。例如：

   ```c++
   // 错误示例：缺少 LOAD_CAN_USE_SHARED_DICTIONARY
   URLFetcher::ResourceRequest request(GURL("https://test.example/test"),
                                       net::URLFetcher::GET);
   // ... 发起请求 ...
   ```

3. **编程错误 - 服务器配置错误：** 服务器可能配置了错误的 `content-encoding` 头，或者发送了与 `available-dictionary` 头不匹配的压缩数据，导致客户端解压缩失败。例如，服务器声称使用了 `dcb` 但实际上没有使用共享字典进行 Brotli 压缩。

**用户操作如何到达这里作为调试线索：**

1. **用户在浏览器中访问一个网页 (例如 `https://test.example/test`)。**
2. **浏览器解析网页内容，发现需要加载一些资源（例如图片、脚本、样式表）。**
3. **对于这些资源请求，网络栈会根据请求的属性（例如 `sec-fetch-dest`）和浏览器配置，决定是否可以使用共享字典。**
4. **如果可以使用共享字典（`LOAD_CAN_USE_SHARED_DICTIONARY` 被设置），并且本地存在一些可用的共享字典，`SharedDictionaryNetworkTransaction` 就会被创建来处理这个请求。**
5. **`SharedDictionaryNetworkTransaction` 会检查本地是否有与服务器可能使用的字典匹配的字典。**
6. **如果找到匹配的字典，它会在请求头中添加 `available-dictionary` 或 `dictionary-id` 信息。**
7. **服务器返回响应后，`SharedDictionaryNetworkTransaction` 会检查 `content-encoding` 头。**
8. **如果 `content-encoding` 是 `dcb` 或 `dcz`，则会尝试使用本地字典进行解压缩。**

**调试线索：**

*  如果在网络请求的请求头中看到了 `available-dictionary` 或 `dictionary-id`，则说明共享字典功能被触发。
*  如果在响应头中看到了 `content-encoding: dcb` 或 `content-encoding: dcz`，则说明服务器尝试使用了共享字典压缩。
*  可以使用 Chrome 的开发者工具 (Network 面板) 查看请求头和响应头，以及资源是否使用了共享字典压缩。
*  如果解压缩失败，可能会在 `net-internals` (chrome://net-internals/#events) 中看到相关的错误信息。

**功能归纳 (针对第 1 部分):**

总的来说，该文件的主要功能是**为 `SharedDictionaryNetworkTransaction` 类提供全面的单元测试**，以确保其在各种场景下能够正确地处理涉及共享字典压缩的网络请求，包括请求头的设置、响应体的解码以及与本地共享字典的交互。它通过模拟不同的网络场景和配置，验证了该类的核心逻辑和边界情况。

Prompt: 
```
这是目录为net/shared_dictionary/shared_dictionary_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/shared_dictionary/shared_dictionary_network_transaction.h"

#include <memory>
#include <optional>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/test/scoped_feature_list.h"
#include "crypto/secure_hash.h"
#include "net/base/features.h"
#include "net/base/hash_value.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/x509_certificate.h"
#include "net/http/http_transaction.h"
#include "net/http/http_transaction_test_util.h"
#include "net/log/net_log_with_source.h"
#include "net/shared_dictionary/shared_dictionary.h"
#include "net/shared_dictionary/shared_dictionary_constants.h"
#include "net/ssl/ssl_private_key.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

const std::string kTestDictionaryData = "HelloHallo你好こんにちは";
// The hex of sha256 of `kTestDictionaryData`.
const std::string kTestDictionarySha256 =
    "c19728aed36503cfc81a0f5359e6f472e121f77bf20a2faac7994191293c0623";
// The Structured Field sf-binary hash of sha256 of `kTestDictionaryData`.
const std::string kTestDictionarySha256Base64 =
    ":wZcortNlA8/IGg9TWeb0cuEh93vyCi+qx5lBkSk8BiM=:";
const std::string kTestData =
    "HelloこんにちはHallo你好HelloこんにちはHallo你好";
// The brotli encoded data of `kTestData` using `kTestDictionaryData` as a
// dictionary.
// kBrotliEncodedData is generated using the following commands:
// $ echo -n "HelloHallo你好こんにちは" > /tmp/dict
// $ echo -n "HelloこんにちはHallo你好HelloこんにちはHallo你好" > /tmp/data
// $ echo -en '\xffDCB' > /tmp/out.dcb
// $ openssl dgst -sha256 -binary /tmp/dict >> /tmp/out.dcb
// $ brotli --stdout -D /tmp/dict /tmp/data >> /tmp/out.dcb
// $ xxd -i /tmp/out.dcb
const uint8_t kBrotliEncodedData[] = {
    0xff, 0x44, 0x43, 0x42, 0xc1, 0x97, 0x28, 0xae, 0xd3, 0x65, 0x03, 0xcf,
    0xc8, 0x1a, 0x0f, 0x53, 0x59, 0xe6, 0xf4, 0x72, 0xe1, 0x21, 0xf7, 0x7b,
    0xf2, 0x0a, 0x2f, 0xaa, 0xc7, 0x99, 0x41, 0x91, 0x29, 0x3c, 0x06, 0x23,
    0xa1, 0xe8, 0x01, 0x00, 0x22, 0x8d, 0x54, 0xc6, 0xf6, 0x26, 0x81, 0x69,
    0x46, 0x9d, 0xb2, 0x60, 0x0e, 0x6b, 0xf5, 0x07, 0x02};
const std::string kBrotliEncodedDataString =
    std::string(reinterpret_cast<const char*>(kBrotliEncodedData),
                sizeof(kBrotliEncodedData));

// The zstd encoded data of `kTestData` using `kTestDictionaryData` as a
// dictionary.
// kZstdEncodedData is generated using the following commands:
// $ echo -n "HelloHallo你好こんにちは" > /tmp/dict
// $ echo -n "HelloこんにちはHallo你好HelloこんにちはHallo你好" > /tmp/data
// $ echo -en '\x5e\x2a\x4d\x18\x20\x00\x00\x00' > /tmp/out.dcz
// $ openssl dgst -sha256 -binary /tmp/dict >> /tmp/out.dcz
// $ zstd -D /tmp/dict -f -o /tmp/tmp.zstd /tmp/data
// $ cat /tmp/tmp.zstd >> /tmp/out.dcz
// $ xxd -i /tmp/out.dcz
const uint8_t kZstdEncodedData[] = {
    0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00, 0xc1, 0x97, 0x28, 0xae,
    0xd3, 0x65, 0x03, 0xcf, 0xc8, 0x1a, 0x0f, 0x53, 0x59, 0xe6, 0xf4, 0x72,
    0xe1, 0x21, 0xf7, 0x7b, 0xf2, 0x0a, 0x2f, 0xaa, 0xc7, 0x99, 0x41, 0x91,
    0x29, 0x3c, 0x06, 0x23, 0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x3e, 0x85, 0x00,
    0x00, 0x28, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x03, 0x00, 0x42, 0x35, 0x88,
    0x6a, 0x03, 0x87, 0x4c, 0x2d, 0xcd, 0x1e, 0xde, 0x25};
const std::string kZstdEncodedDataString =
    std::string(reinterpret_cast<const char*>(kZstdEncodedData),
                sizeof(kZstdEncodedData));

const size_t kDefaultBufferSize = 1023;

class DummySyncDictionary : public SharedDictionary {
 public:
  explicit DummySyncDictionary(const std::string& data_string,
                               const std::string& id = "")
      : data_(base::MakeRefCounted<StringIOBuffer>(data_string)),
        size_(data_string.size()),
        id_(id) {
    std::unique_ptr<crypto::SecureHash> secure_hash =
        crypto::SecureHash::Create(crypto::SecureHash::SHA256);
    secure_hash->Update(data_->data(), size_);
    secure_hash->Finish(hash_.data, sizeof(hash_.data));
  }

  // SharedDictionary
  int ReadAll(base::OnceCallback<void(int)> callback) override { return OK; }
  scoped_refptr<IOBuffer> data() const override { return data_; }
  size_t size() const override { return size_; }
  const SHA256HashValue& hash() const override { return hash_; }
  const std::string& id() const override { return id_; }

 protected:
  ~DummySyncDictionary() override = default;

 private:
  const scoped_refptr<IOBuffer> data_;
  const size_t size_;
  const std::string id_;
  SHA256HashValue hash_;
};

class DummyAsyncDictionary : public DummySyncDictionary {
 public:
  explicit DummyAsyncDictionary(const std::string& data_string)
      : DummySyncDictionary(data_string) {}

  // SharedDictionary
  int ReadAll(base::OnceCallback<void(int)> callback) override {
    read_all_callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }
  base::OnceCallback<void(int)> TakeReadAllCallback() {
    return std::move(read_all_callback_);
  }

 private:
  ~DummyAsyncDictionary() override = default;

  base::OnceCallback<void(int)> read_all_callback_;
};

TransportInfo TestSpdyTransportInfo() {
  return TransportInfo(TransportType::kDirect,
                       IPEndPoint(IPAddress::IPv4Localhost(), 80),
                       /*accept_ch_frame_arg=*/"",
                       /*cert_is_issued_by_known_root=*/false, kProtoHTTP2);
}

static void BrotliTestTransactionHandler(const HttpRequestInfo* request,
                                         std::string* response_status,
                                         std::string* response_headers,
                                         std::string* response_data) {
  EXPECT_THAT(request->extra_headers.GetHeader(
                  shared_dictionary::kAvailableDictionaryHeaderName),
              testing::Optional(kTestDictionarySha256Base64));
  *response_data = kBrotliEncodedDataString;
}

static void ZstdTestTransactionHandler(const HttpRequestInfo* request,
                                       std::string* response_status,
                                       std::string* response_headers,
                                       std::string* response_data) {
  EXPECT_THAT(request->extra_headers.GetHeader(
                  shared_dictionary::kAvailableDictionaryHeaderName),
              testing::Optional(kTestDictionarySha256Base64));
  *response_data = kZstdEncodedDataString;
}

static const auto kTestTransactionHandlerWithoutAvailableDictionary =
    base::BindRepeating([](const HttpRequestInfo* request,
                           std::string* response_status,
                           std::string* response_headers,
                           std::string* response_data) {
      EXPECT_FALSE(request->extra_headers.HasHeader(
          shared_dictionary::kAvailableDictionaryHeaderName));
      *response_data = kTestData;
    });

constexpr char kTestUrl[] = "https://test.example/test";

const MockTransaction kBrotliDictionaryTestTransaction = {
    .url = kTestUrl,
    .method = "GET",
    .request_time = base::Time(),
    .request_headers = "sec-fetch-dest: document\r\n",
    .load_flags = LOAD_CAN_USE_SHARED_DICTIONARY,
    .transport_info = TestSpdyTransportInfo(),
    .status = "HTTP/1.1 200 OK",
    .response_headers = "content-encoding: dcb\n",
    .response_time = base::Time(),
    .data = "",  // We set the body in the `handler` function.
    .dns_aliases = {},
    .fps_cache_filter = std::nullopt,
    .browser_run_id = std::nullopt,
    .test_mode = TEST_MODE_NORMAL,
    .handler = base::BindRepeating(&BrotliTestTransactionHandler),
    .read_handler = MockTransactionReadHandler(),
    .cert = nullptr,
    .cert_status = 0,
    .ssl_connection_status = 0,
    .start_return_code = OK,
    .read_return_code = OK,
};

const MockTransaction kZstdDictionaryTestTransaction = {
    .url = kTestUrl,
    .method = "GET",
    .request_time = base::Time(),
    .request_headers = "sec-fetch-dest: document\r\n",
    .load_flags = LOAD_CAN_USE_SHARED_DICTIONARY,
    .transport_info = TestSpdyTransportInfo(),
    .status = "HTTP/1.1 200 OK",
    .response_headers = "content-encoding: dcz\n",
    .response_time = base::Time(),
    .data = "",  // We set the body in the `handler` function.
    .dns_aliases = {},
    .fps_cache_filter = std::nullopt,
    .browser_run_id = std::nullopt,
    .test_mode = TEST_MODE_NORMAL,
    .handler = base::BindRepeating(&ZstdTestTransactionHandler),
    .read_handler = MockTransactionReadHandler(),
    .cert = nullptr,
    .cert_status = 0,
    .ssl_connection_status = 0,
    .start_return_code = OK,
    .read_return_code = OK,
};

class SharedDictionaryNetworkTransactionTest : public ::testing::Test {
 public:
  SharedDictionaryNetworkTransactionTest()
      : scoped_mock_transaction_(kBrotliDictionaryTestTransaction),
        network_layer_(std::make_unique<MockNetworkLayer>()) {
    scoped_feature_list_.InitWithFeatures(
        /*enabled_features=*/{},
        /*disabled_features=*/{
            features::kCompressionDictionaryTransportRequireKnownRootCert});
  }
  ~SharedDictionaryNetworkTransactionTest() override = default;

  SharedDictionaryNetworkTransactionTest(
      const SharedDictionaryNetworkTransactionTest&) = delete;
  SharedDictionaryNetworkTransactionTest& operator=(
      const SharedDictionaryNetworkTransactionTest&) = delete;

 protected:
  std::unique_ptr<HttpTransaction> CreateNetworkTransaction() {
    std::unique_ptr<HttpTransaction> network_transaction;
    network_layer_->CreateTransaction(DEFAULT_PRIORITY, &network_transaction);
    return network_transaction;
  }

  void RunUntilIdle() { task_environment_.RunUntilIdle(); }

  MockNetworkLayer& network_layer() { return *network_layer_.get(); }

  std::optional<ScopedMockTransaction> scoped_mock_transaction_;

 private:
  std::unique_ptr<MockNetworkLayer> network_layer_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(SharedDictionaryNetworkTransactionTest, SyncDictionary) {
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
  EXPECT_THAT(read_result, kTestData.size());
  EXPECT_EQ(kTestData, std::string(buf->data(), read_result));
}

TEST_F(SharedDictionaryNetworkTransactionTest, NotAllowedToUseDictionary) {
  // Change MockTransaction to check that there is no available-dictionary
  // header.
  scoped_mock_transaction_->handler =
      kTestTransactionHandlerWithoutAvailableDictionary;

  MockHttpRequest request(*scoped_mock_transaction_);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(kTestDictionaryData);
      });

  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);
  transaction.SetIsSharedDictionaryReadAllowedCallback(
      base::BindRepeating([]() { return false; }));

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

TEST_F(SharedDictionaryNetworkTransactionTest, DictionaryId) {
  // Change MockTransaction to check the dictionary-id header
  scoped_mock_transaction_->handler = base::BindRepeating(
      [](const HttpRequestInfo* request, std::string* response_status,
         std::string* response_headers, std::string* response_data) {
        EXPECT_THAT(request->extra_headers.GetHeader("dictionary-id"),
                    testing::Optional(std::string("\"test-id\"")));
        *response_data = kBrotliEncodedDataString;
      });

  MockHttpRequest request(*scoped_mock_transaction_);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(kTestDictionaryData,
                                                         "test-id");
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

TEST_F(SharedDictionaryNetworkTransactionTest,
       DictionaryIdWithBackSlashAndDquote) {
  // Change MockTransaction to check the dictionary-id header
  scoped_mock_transaction_->handler = base::BindRepeating(
      [](const HttpRequestInfo* request, std::string* response_status,
         std::string* response_headers, std::string* response_data) {
        EXPECT_THAT(
            request->extra_headers.GetHeader("dictionary-id"),
            testing::Optional(std::string("\"test\\\\dictionary\\\"id\"")));
        *response_data = kBrotliEncodedDataString;
      });

  MockHttpRequest request(*scoped_mock_transaction_);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(
            kTestDictionaryData, "test\\dictionary\"id");
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

TEST_F(SharedDictionaryNetworkTransactionTest, EmptyDictionaryId) {
  // Change MockTransaction to check the dictionary-id header
  scoped_mock_transaction_->handler = base::BindRepeating(
      [](const HttpRequestInfo* request, std::string* response_status,
         std::string* response_headers, std::string* response_data) {
        EXPECT_FALSE(request->extra_headers.HasHeader("dictionary-id"));
        *response_data = kBrotliEncodedDataString;
      });

  MockHttpRequest request(*scoped_mock_transaction_);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return base::MakeRefCounted<DummySyncDictionary>(kTestDictionaryData,
                                                         "");
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

TEST_F(SharedDictionaryNetworkTransactionTest,
       RequireKnownRootCertCheckFailure) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kCompressionDictionaryTransportRequireKnownRootCert);
  // Change MockTransaction to check that there is no available-dictionary
  // header.
  scoped_mock_transaction_->handler =
      kTestTransactionHandlerWithoutAvailableDictionary;
  scoped_mock_transaction_->transport_info.cert_is_issued_by_known_root = false;

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
  EXPECT_THAT(read_result, kTestData.size());
  EXPECT_EQ(kTestData, std::string(buf->data(), read_result));
}

TEST_F(SharedDictionaryNetworkTransactionTest,
       RequireKnownRootCertCheckSuccess) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kCompressionDictionaryTransportRequireKnownRootCert);
  // The BrotliTestTransactionHandler `scoped_mock_transaction_->handler` will
  // check that the there is a correct available-dictionary request header.
  scoped_mock_transaction_->transport_info.cert_is_issued_by_known_root = true;

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
  EXPECT_THAT(read_result, kTestData.size());
  EXPECT_EQ(kTestData, std::string(buf->data(), read_result));
}

TEST_F(SharedDictionaryNetworkTransactionTest,
       RequireKnownRootCertCheckSuccessForLocalhost) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kCompressionDictionaryTransportRequireKnownRootCert);
  // The BrotliTestTransactionHandler `new_mock_transaction.handler` will check
  // that the there is a correct available-dictionary request header.
  ScopedMockTransaction scoped_mock_transaction(
      kBrotliDictionaryTestTransaction, "http:///localhost:1234/test");
  scoped_mock_transaction.transport_info.cert_is_issued_by_known_root = false;

  MockHttpRequest request(scoped_mock_transaction);
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

TEST_F(SharedDictionaryNetworkTransactionTest, NoMatchingDictionary) {
  // Change MockTransaction to check that there is no available-dictionary
  // header.
  scoped_mock_transaction_->handler =
      kTestTransactionHandlerWithoutAvailableDictionary;

  MockHttpRequest request(*scoped_mock_transaction_);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        return nullptr;
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

TEST_F(SharedDictionaryNetworkTransactionTest, OpaqueFrameOrigin) {
  // Change MockTransaction to check that there is no available-dictionary
  // header.
  scoped_mock_transaction_->handler =
      kTestTransactionHandlerWithoutAvailableDictionary;

  MockHttpRequest request(*scoped_mock_transaction_);
  request.dictionary_getter = base::BindRepeating(
      [](const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        // dictionary_getter must be called with a nullopt isolation_key.
        CHECK(!isolation_key);
        return nullptr;
      });
  request.frame_origin = url::Origin();
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

TEST_F(SharedDictionaryNetworkTransactionTest, WithoutValidLoadFlag) {
  // Change MockTransaction to check that there is no available-dictionary
  // header.
  scoped_mock_transaction_->handler =
      kTestTransactionHandlerWithoutAvailableDictionary;

  MockHttpRequest request(*scoped_mock_transaction_);
  bool getter_called = false;
  request.dictionary_getter = base::BindRepeating(
      [](bool* getter_called,
         const std::optional<SharedDictionaryIsolationKey>& isolation_key,
         const GURL& request_url) -> scoped_refptr<SharedDictionary> {
        *getter_called = true;
        return nullptr;
      },
      base::Unretained(&getter_called));
  SharedDictionaryNetworkTransaction transaction(CreateNetworkTransaction(),
                                                 /*enable_shared_zstd=*/false);

  CHECK_EQ(LOAD_CAN_USE_SHARED_DICTIONARY, request.load_flags);
  // Change load_flags not to trigger the shared dictionary logic.
  request.load_flags = LOAD_NORMAL;

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

  // SharedDictionaryGetter must not be called when
  // LOAD_CAN_USE_SHARED_DICTIONARY is not set.
  EXPECT_FALSE(getter_called);
}

TEST_F(SharedDictionaryNetworkTransactionTest, NoSbrContentEncoding) {
  // Change MockTransaction to remove `content-encoding: dcb`.
  scoped_mock_transaction_->response_headers = "";

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

  // When there is no "content-encoding: dcb" header,
  // SharedDictionaryNetworkTransaction must not decode the body.
  EXPECT_THAT(read_result, kBrotliEncodedDataString.size());
  EXPECT_EQ(kBrotliEncodedDataString, std::string(buf->data(), read_result));
}

TEST_F(SharedDictionaryNetworkTransactionTest, WrongContentDictionaryHeader) {
  scoped_mock_transaction_->handler = base::BindRepeating(
      [](const HttpRequestInfo* request, std::string* response_status,
         std::string* response_headers, std::string* response_data) {
        std::string data = kBrotliEncodedDataString;
        // Change the first byte of the compressed data to trigger
        // UNEXPECTED_CONTENT_DICTIONARY_HEADER error.
        ++data[0];
        *response_data = data;
      });

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
  ASSERT_THAT(start_callback.GetResult(transaction.Start(
                  &request, start_callback.callback(), NetLogWithSource())),
              test::IsError(OK));
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback read_callback;
  ASSERT_THAT(read_callback.GetResult(transaction.Read(
                  bu
"""


```