Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The primary goal is to understand the purpose of the `SharedDictionaryHeaderCheckerSourceStreamTest` class and its associated tests. This involves figuring out what `SharedDictionaryHeaderCheckerSourceStream` itself does.

2. **Identify Key Components:** Scan the code for important classes, methods, constants, and data structures. In this case, the obvious starting points are:
    * `SharedDictionaryHeaderCheckerSourceStream` (the class under test)
    * `MockSourceStream` (a testing utility)
    * `IOBufferWithSize` (a buffer used for reading data)
    * `SHA256HashValue` (used for hash comparison)
    * `kBrotliSignature`, `kZstdSignature` (compression format identifiers)
    * `Read` method (the primary method being tested)
    * The various `TEST_P` macros (indicating parameterized tests)

3. **Infer Functionality from Class Name and Context:** The name "SharedDictionaryHeaderCheckerSourceStream" strongly suggests its purpose: to check the header of a shared dictionary. The "SourceStream" part implies it's part of a data streaming pipeline. The context of "net" further suggests it's related to network operations.

4. **Analyze the Test Structure:**  Notice the `TEST_P` macro. This tells us the tests are parameterized, meaning they run with different inputs. The `INSTANTIATE_TEST_SUITE_P` line clarifies that the parameter is the `Type` enum, specifically `kDictionaryCompressedBrotli` and `kDictionaryCompressedZstd`. This immediately reveals that the header checker handles two compression formats.

5. **Examine Individual Tests:**  Go through each `TEST_P` function and understand its purpose:
    * **`Description` and `MayHaveMoreBytes`:** These are basic tests for informational methods of the stream.
    * **`SyncReadError` and `AsyncReadError`:** Test how the header checker handles errors from the underlying stream.
    * **`EmptyStream...` tests:** Focus on scenarios where the underlying stream provides no data or completes immediately. These check for proper error handling of incomplete headers.
    * **`TooSmallHeader...` tests:** Verify how the checker behaves when the received header is too short to contain the signature and hash.
    * **`HeaderSync` and `HeaderAsync`:**  Test successful header verification and subsequent data reading in synchronous and asynchronous scenarios, respectively. These are the core positive test cases.
    * **`HeaderSplittedSync` and `HeaderSplittedAsync`:** Check if the header checker correctly handles situations where the signature and hash arrive in separate read calls.
    * **`WrongSinatureSync`, `WrongSinatureAsync`, `WrongHashSync`, `WrongHashAsync`:** These are negative tests confirming that the checker detects incorrect signatures and hashes.

6. **Trace Data Flow:**  Observe how the tests are set up. `MockSourceStream` is used to simulate the underlying data source. `AddReadResult` is crucial; it defines the sequence of data (or errors) the mock stream will return. The `Read` method of the `SharedDictionaryHeaderCheckerSourceStream` is called, and the results are compared to expected values using `EXPECT_EQ`.

7. **Look for Assumptions and Logic:** The tests implicitly assume that the header structure is: `[Signature][Hash]`. The lengths of the signatures are defined implicitly within the test setup. The hash is a fixed size (32 bytes for SHA256). The logic is straightforward: read enough data to get the signature and hash, compare them to the expected values, and then pass through the remaining data.

8. **Consider JavaScript Relevance:**  Think about where shared dictionaries and compressed content might interact with JavaScript. The most likely scenario is fetching resources. Browsers might use shared dictionaries to optimize resource loading. JavaScript's `fetch` API could be involved. The `Content-Encoding` header is a key link.

9. **Identify Potential User/Programming Errors:** Consider how developers might misuse this functionality. A common mistake would be providing the wrong hash or configuring the shared dictionary incorrectly on the server side.

10. **Deduce Debugging Steps:**  Imagine a scenario where something goes wrong. The tests provide clues:  Check the server's `Content-Encoding` header, verify the dictionary's hash, and inspect the raw bytes being transferred.

11. **Structure the Explanation:** Organize the findings logically. Start with the main function, then delve into the details of JavaScript interaction, assumptions, errors, and debugging. Use examples to illustrate the concepts.

**(Self-Correction during the process):** Initially, I might have focused too much on the individual test cases without understanding the broader purpose. Realizing the significance of the `Type` parameter and the different compression formats helped to get a clearer picture. Also, connecting the C++ code to the high-level browser functionality (resource fetching, `Content-Encoding`) is important to explain the relevance to JavaScript developers.
这个文件是 Chromium 网络栈中的一个单元测试文件，名为 `shared_dictionary_header_checker_source_stream_unittest.cc`。它的主要功能是**测试 `SharedDictionaryHeaderCheckerSourceStream` 类的各种行为和功能。**

`SharedDictionaryHeaderCheckerSourceStream` 的作用是**验证从底层数据流（Source Stream）读取到的共享字典的头部信息是否正确。** 它会检查字典的签名（magic number）和哈希值，以确保接收到的字典是期望的，并且没有被篡改。

**具体来说，这个测试文件会测试以下方面：**

1. **正确的头部识别：** 验证 `SharedDictionaryHeaderCheckerSourceStream` 能否正确识别 Brotli 和 Zstd 压缩格式的字典头部，包括签名和哈希值。
2. **错误的头部识别：** 验证当字典头部信息错误时，例如签名不匹配或哈希值不一致时，`SharedDictionaryHeaderCheckerSourceStream` 是否会返回相应的错误。
3. **头部读取过程中的各种情况：** 测试在读取字典头部时，数据是同步到达还是异步到达，以及头部信息是否分多次读取。
4. **空数据流的处理：** 验证当底层数据流为空时，`SharedDictionaryHeaderCheckerSourceStream` 的行为。
5. **数据读取的透明性：** 验证在成功验证头部后，`SharedDictionaryHeaderCheckerSourceStream` 能否将后续的数据透明地传递给上层。
6. **错误处理：** 测试当底层数据流发生错误时，`SharedDictionaryHeaderCheckerSourceStream` 如何处理并向上层报告错误。

**它与 JavaScript 的功能有关系，因为共享字典机制是 Web 性能优化的一种手段，可以被浏览器用来加速资源加载。**

**举例说明：**

假设一个网站使用了共享字典来压缩一些通用的 JavaScript 库。

1. **服务器端：** 服务器在发送资源（例如一个 JavaScript 文件）时，可能会使用 `Content-Encoding: br; content-dictionary=sha-256=:...:` 这样的 HTTP 头部来指示资源使用了 Brotli 压缩，并且使用了指定的共享字典。
2. **浏览器端：** 浏览器接收到这个响应后，会解析 `content-dictionary` 头部，获取共享字典的哈希值。
3. **`SharedDictionaryHeaderCheckerSourceStream` 的作用：** 当浏览器需要使用这个共享字典来解压资源时，它会创建一个 `SharedDictionaryHeaderCheckerSourceStream` 实例，并将提供字典数据的底层数据流传递给它。`SharedDictionaryHeaderCheckerSourceStream` 会读取数据流的开头，提取 Brotli 的签名和字典的哈希值，并与期望的哈希值（从 `content-dictionary` 头部获取）进行比较。
4. **JavaScript 的关联：** 如果头部校验成功，浏览器就可以安全地使用这个共享字典来解压服务器发送的压缩 JavaScript 文件。这意味着 JavaScript 代码能够被正确加载和执行。如果头部校验失败，浏览器会认为字典不可信或已被篡改，可能会拒绝使用该字典，导致资源加载失败或者需要使用其他方式加载（例如重新下载未压缩的版本）。

**逻辑推理 (假设输入与输出):**

**假设输入:** 底层数据流提供了一个 Brotli 压缩的共享字典，其内容如下（简化表示）：

* **前 4 个字节 (签名):** `0xff 0x44 0x43 0x42` (Brotli 签名)
* **后 32 个字节 (哈希值):** `0x01 0x02 ... 0x20` (与 `kTestHash` 相同)
* **后续数据:** 字典的实际内容

**假设 `SharedDictionaryHeaderCheckerSourceStream` 被创建时，期望的哈希值设置为 `kTestHash`。**

**输出:**

* **`Read` 操作的返回值:**  当读取到足够的数据进行头部校验后，`Read` 操作会返回读取到的字节数（例如，如果一次读取操作读取了签名和哈希值，则返回 36）。之后读取字典的实际内容时，会返回读取到的实际内容字节数。
* **内部状态:** `SharedDictionaryHeaderCheckerSourceStream` 的内部状态会标记头部校验已通过。

**假设输入 (错误情况):** 底层数据流提供的字典的哈希值与期望的 `kTestHash` 不同。

**输出:**

* **`Read` 操作的返回值:** `ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER`，表示字典头部校验失败。

**涉及用户或编程常见的使用错误 (举例说明):**

1. **服务器配置错误：**  服务器在 `content-dictionary` 头部中指定了错误的共享字典哈希值。这会导致浏览器在尝试使用字典时，`SharedDictionaryHeaderCheckerSourceStream` 校验失败。
    * **用户操作:** 用户访问配置错误的网站。
    * **调试线索:** 浏览器开发者工具的网络面板会显示资源加载失败，并且可能包含与共享字典相关的错误信息。
2. **共享字典文件损坏或被篡改：**  服务器存储的共享字典文件本身被损坏或者被恶意修改，导致其哈希值与预期不符。
    * **用户操作:** 用户访问依赖于损坏或被篡改共享字典的网站。
    * **调试线索:** 类似于服务器配置错误，浏览器可能会报告资源加载失败和共享字典校验错误。
3. **中间代理或 CDN 的问题：**  在客户端和服务器之间，有中间代理或 CDN 缓存了旧的或错误的共享字典版本，导致客户端接收到的字典与服务器期望的不一致。
    * **用户操作:** 用户访问使用了中间代理或 CDN 的网站。
    * **调试线索:**  检查浏览器缓存，尝试清除缓存并重新加载。查看网络请求头和响应头，确认是否使用了缓存的资源。
4. **浏览器 bug 或实现问题：**  虽然不太常见，但浏览器自身在实现共享字典功能时可能存在 bug，导致头部校验逻辑错误。
    * **用户操作:**  用户访问使用了共享字典的网站。
    * **调试线索:**  这种情况下，可能需要在不同浏览器版本或环境下进行测试，以确定是否是浏览器特定的问题。提交 bug 报告给浏览器开发团队。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入网址或点击链接，发起对网站的访问。**
2. **浏览器向服务器发送 HTTP 请求。**
3. **服务器处理请求，并返回包含使用了共享字典压缩资源的 HTTP 响应。** 响应头中可能包含 `Content-Encoding` 和 `content-dictionary` 头部。
4. **浏览器解析响应头，发现资源使用了共享字典。**
5. **浏览器尝试获取共享字典。** 这可能涉及到从本地缓存加载，或者发起对字典资源的单独请求。
6. **一旦共享字典的数据流可用，浏览器会创建 `SharedDictionaryHeaderCheckerSourceStream` 实例。**
7. **`SharedDictionaryHeaderCheckerSourceStream` 开始从底层数据流读取数据，进行头部校验。**
8. **如果在校验过程中发生错误（例如，哈希值不匹配），`SharedDictionaryHeaderCheckerSourceStream` 会返回错误。**
9. **浏览器根据错误信息采取相应的措施，例如放弃使用共享字典，或者报告资源加载失败。**
10. **作为调试线索，开发者可以使用浏览器开发者工具的网络面板查看请求和响应头，特别是 `Content-Encoding` 和 `content-dictionary` 头部。** 检查共享字典资源的加载情况以及可能的错误信息。还可以通过 Chrome 的 `net-internals` 工具（在地址栏输入 `chrome://net-internals/#events`）查看更底层的网络事件，包括共享字典相关的事件。

总而言之，`shared_dictionary_header_checker_source_stream_unittest.cc` 这个文件是用来确保 Chromium 网络栈中负责校验共享字典头部的组件能够正确可靠地工作，这对于保证 Web 性能优化机制的安全性和有效性至关重要。

Prompt: 
```
这是目录为net/shared_dictionary/shared_dictionary_header_checker_source_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/shared_dictionary/shared_dictionary_header_checker_source_stream.h"

#include <memory>

#include "base/containers/span.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/strings/cstring_view.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/mock_source_stream.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

using Type = SharedDictionaryHeaderCheckerSourceStream::Type;

static constexpr SHA256HashValue kTestHash = {
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
     0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
     0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}};

static constexpr unsigned char kBrotliSignature[] = {0xff, 0x44, 0x43, 0x42};

// The first byte is different from the correct signature.
static constexpr unsigned char kWrongBrotliSignature[] = {0xf0, 0x44, 0x43,
                                                          0x42};
static constexpr unsigned char kBrotliSignatureAndHash[] = {
    // kBrotliSignature
    0xff, 0x44, 0x43, 0x42,
    // kTestHash
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static constexpr base::span<const unsigned char> kTooSmallBrotliHeader =
    base::make_span(kBrotliSignatureAndHash)
        .subspan(sizeof(kBrotliSignatureAndHash) / 2);

static constexpr unsigned char kZstdSignature[] = {0x5e, 0x2a, 0x4d, 0x18,
                                                   0x20, 0x00, 0x00, 0x00};
// The first byte is different from the correct signature.
static constexpr unsigned char kWrongZstdSignature[] = {0x50, 0x2a, 0x4d, 0x18,
                                                        0x20, 0x00, 0x00, 0x00};
static constexpr unsigned char kZstdSignatureAndHash[] = {
    // kZstdSignature
    0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00,
    // kTestHash
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static constexpr base::span<const unsigned char> kTooSmallZstdHeader =
    base::span(kZstdSignatureAndHash)
        .subspan(sizeof(kZstdSignatureAndHash) / 2u);
constexpr size_t kOutputBufferSize = 1024;

constexpr base::cstring_view kTestBodyData = "test body data";

}  // namespace

class SharedDictionaryHeaderCheckerSourceStreamTest
    : public ::testing::TestWithParam<Type> {
 public:
  SharedDictionaryHeaderCheckerSourceStreamTest()
      : mock_stream_(std::make_unique<MockSourceStream>()),
        mock_stream_ptr_(mock_stream_.get()),
        buffer_(base::MakeRefCounted<IOBufferWithSize>(kOutputBufferSize)) {}
  ~SharedDictionaryHeaderCheckerSourceStreamTest() override = default;
  SharedDictionaryHeaderCheckerSourceStreamTest(
      const SharedDictionaryHeaderCheckerSourceStreamTest&) = delete;
  SharedDictionaryHeaderCheckerSourceStreamTest& operator=(
      const SharedDictionaryHeaderCheckerSourceStreamTest&) = delete;

 protected:
  using Mode = MockSourceStream::Mode;
  Type GetType() const { return GetParam(); }
  base::span<const unsigned char> GetSignature() const {
    switch (GetType()) {
      case Type::kDictionaryCompressedBrotli:
        return kBrotliSignature;
      case Type::kDictionaryCompressedZstd:
        return kZstdSignature;
    }
  }
  base::span<const unsigned char> GetSignatureAndHash() const {
    switch (GetType()) {
      case Type::kDictionaryCompressedBrotli:
        return kBrotliSignatureAndHash;
      case Type::kDictionaryCompressedZstd:
        return kZstdSignatureAndHash;
    }
  }
  base::span<const unsigned char> GetTooSmallHeader() const {
    switch (GetType()) {
      case Type::kDictionaryCompressedBrotli:
        return kTooSmallBrotliHeader;
      case Type::kDictionaryCompressedZstd:
        return kTooSmallZstdHeader;
    }
  }
  base::span<const unsigned char> GetWrongSignature() const {
    switch (GetType()) {
      case Type::kDictionaryCompressedBrotli:
        return kWrongBrotliSignature;
      case Type::kDictionaryCompressedZstd:
        return kWrongZstdSignature;
    }
  }
  void CreateHeaderCheckerSourceStream() {
    stream_ = std::make_unique<SharedDictionaryHeaderCheckerSourceStream>(
        std::move(mock_stream_), GetType(), kTestHash);
  }
  SharedDictionaryHeaderCheckerSourceStream* stream() { return stream_.get(); }
  IOBufferWithSize* buffer() { return buffer_.get(); }

  void AddReadResult(base::span<const char> span, Mode mode) {
    mock_stream_ptr_->AddReadResult(span.data(), span.size(), OK, mode);
  }
  void AddReadResult(base::span<const unsigned char> span, Mode mode) {
    AddReadResult(base::as_chars(span), mode);
  }
  void AddReadResult(Error error, Mode mode) {
    mock_stream_ptr_->AddReadResult(nullptr, 0, error, mode);
  }
  void CompleteNextRead() { mock_stream_ptr_->CompleteNextRead(); }

  void CheckSyncRead(int expected_result) {
    TestCompletionCallback callback;
    EXPECT_EQ(Read(callback.callback()), expected_result);
    EXPECT_FALSE(callback.have_result());
  }
  void CheckAsyncRead(int expected_result, size_t mock_stream_read_count) {
    TestCompletionCallback callback;
    EXPECT_EQ(Read(callback.callback()), ERR_IO_PENDING);
    EXPECT_FALSE(callback.have_result());
    for (size_t i = 0; i < mock_stream_read_count - 1; ++i) {
      CompleteNextRead();
      EXPECT_FALSE(callback.have_result());
    }
    CompleteNextRead();
    EXPECT_TRUE(callback.have_result());
    EXPECT_EQ(callback.WaitForResult(), expected_result);
  }
  int Read(CompletionOnceCallback callback) {
    return stream()->Read(buffer(), buffer()->size(), std::move(callback));
  }

 private:
  std::unique_ptr<MockSourceStream> mock_stream_;
  std::unique_ptr<SharedDictionaryHeaderCheckerSourceStream> stream_;
  raw_ptr<MockSourceStream> mock_stream_ptr_;
  scoped_refptr<IOBufferWithSize> buffer_;
};

std::string ToString(Type type) {
  switch (type) {
    case Type::kDictionaryCompressedBrotli:
      return "Brotli";
    case Type::kDictionaryCompressedZstd:
      return "Zstd";
  }
}

INSTANTIATE_TEST_SUITE_P(All,
                         SharedDictionaryHeaderCheckerSourceStreamTest,
                         testing::ValuesIn({Type::kDictionaryCompressedBrotli,
                                            Type::kDictionaryCompressedZstd}),
                         [](const testing::TestParamInfo<Type>& info) {
                           return ToString(info.param);
                         });

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, Description) {
  AddReadResult(OK, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  EXPECT_EQ(stream()->Description(),
            "SharedDictionaryHeaderCheckerSourceStream");
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, MayHaveMoreBytes) {
  AddReadResult(OK, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  EXPECT_TRUE(stream()->MayHaveMoreBytes());
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, SyncReadError) {
  AddReadResult(ERR_FAILED, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  CheckSyncRead(ERR_FAILED);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, AsyncReadError) {
  AddReadResult(ERR_FAILED, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CheckAsyncRead(ERR_FAILED, 1);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, EmptyStreamSyncComplete) {
  AddReadResult(OK, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  CheckSyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest,
       EmptyStreamAsyncCompleteBeforeRead) {
  AddReadResult(OK, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CheckAsyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER, 1);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest,
       EmptyStreamAsyncCompleteAfterRead) {
  AddReadResult(OK, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CompleteNextRead();
  CheckSyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest,
       TooSmallHeaderSyncDataSyncComplete) {
  AddReadResult(GetTooSmallHeader(), Mode::SYNC);
  AddReadResult(OK, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  CheckSyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest,
       TooSmallHeaderSyncDataAsyncCompleteBeforeRead) {
  AddReadResult(GetTooSmallHeader(), Mode::SYNC);
  AddReadResult(OK, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CompleteNextRead();
  CheckSyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest,
       TooSmallHeaderSyncDataAsyncCompleteAfterRead) {
  AddReadResult(GetTooSmallHeader(), Mode::SYNC);
  AddReadResult(OK, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CheckAsyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER, 1);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, HeaderSync) {
  AddReadResult(GetSignatureAndHash(), Mode::SYNC);
  AddReadResult(kTestBodyData, Mode::SYNC);
  AddReadResult(OK, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  CheckSyncRead(kTestBodyData.size());
  EXPECT_EQ(base::as_chars(buffer()->span()).first(kTestBodyData.size()),
            kTestBodyData);
  CheckSyncRead(OK);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, HeaderSplittedSync) {
  AddReadResult(GetSignature(), Mode::SYNC);
  AddReadResult(kTestHash.data, Mode::SYNC);
  AddReadResult(kTestBodyData, Mode::SYNC);
  AddReadResult(OK, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  CheckSyncRead(kTestBodyData.size());
  EXPECT_EQ(base::as_chars(buffer()->span()).first(kTestBodyData.size()),
            kTestBodyData);
  CheckSyncRead(OK);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, HeaderAsync) {
  AddReadResult(GetSignatureAndHash(), Mode::ASYNC);
  AddReadResult(kTestBodyData, Mode::ASYNC);
  AddReadResult(OK, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CheckAsyncRead(kTestBodyData.size(), 2);
  EXPECT_EQ(base::as_chars(buffer()->span()).first(kTestBodyData.size()),
            kTestBodyData);
  CheckAsyncRead(OK, 1);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, HeaderSplittedAsync) {
  AddReadResult(GetSignature(), Mode::ASYNC);
  AddReadResult(kTestHash.data, Mode::ASYNC);
  AddReadResult(kTestBodyData, Mode::ASYNC);
  AddReadResult(OK, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CheckAsyncRead(kTestBodyData.size(), 3);
  EXPECT_EQ(base::as_chars(buffer()->span()).first(kTestBodyData.size()),
            kTestBodyData);
  CheckAsyncRead(OK, 1);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, WrongSinatureSync) {
  AddReadResult(GetWrongSignature(), Mode::SYNC);
  AddReadResult(kTestHash.data, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  CheckSyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, WrongSinatureAsync) {
  AddReadResult(GetWrongSignature(), Mode::ASYNC);
  AddReadResult(kTestHash.data, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CheckAsyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER, 2);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, WrongHashSync) {
  const SHA256HashValue kWrongHash = {{0x01}};
  AddReadResult(GetSignature(), Mode::SYNC);
  AddReadResult(kWrongHash.data, Mode::SYNC);
  CreateHeaderCheckerSourceStream();
  CheckSyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER);
}

TEST_P(SharedDictionaryHeaderCheckerSourceStreamTest, WrongHashAsync) {
  const SHA256HashValue kWrongHash = {{0x01}};
  AddReadResult(GetSignature(), Mode::ASYNC);
  AddReadResult(kWrongHash.data, Mode::ASYNC);
  CreateHeaderCheckerSourceStream();
  CheckAsyncRead(ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER, 2);
}

}  // namespace net

"""

```