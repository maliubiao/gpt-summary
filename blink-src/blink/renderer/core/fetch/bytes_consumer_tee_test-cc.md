Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request is to analyze `bytes_consumer_tee_test.cc`. This implies understanding its purpose, how it works, its relationship to other parts of the system (if any), and potential usage scenarios, including errors.

2. **Identify the Core Component:** The filename `bytes_consumer_tee_test.cc` immediately points to the `BytesConsumerTee` class as the central subject. The `_test.cc` suffix confirms it's a unit test file.

3. **Examine Includes:** The `#include` directives provide valuable clues about the context and dependencies:
    * `bytes_consumer_tee.h`: This is the header file for the class being tested, confirming the focus.
    * `testing/gtest/include/gtest/gtest.h`: Indicates this file uses Google Test for unit testing.
    * `bytes_consumer_test_util.h`: Suggests there are utility functions or classes specifically for testing `BytesConsumer` related components.
    * `local_dom_window.h`, `local_frame.h`, `page_test_base.h`:  These link the testing to the Blink rendering engine's DOM and frame structure. This strongly suggests the `BytesConsumerTee` is used within the rendering process.
    * `blob_data.h`, `encoded_form_data.h`: These suggest potential data types that the `BytesConsumerTee` might handle.
    * `bytes_consumer_test_reader.h`, `replaying_bytes_consumer.h`: These are test-specific classes for simulating or interacting with `BytesConsumer` instances.
    * `task_environment.h`, `unit_test_helpers.h`: General testing utilities.

4. **Analyze the Test Structure:** The file defines a test fixture `BytesConsumerTeeTest` inheriting from `PageTestBase`. This confirms that the tests run within a simulated page environment. Each `TEST_F` macro defines an individual test case.

5. **Deconstruct Individual Tests:** Go through each `TEST_F` and understand what it's testing:
    * **`CreateDone`:** Tests the scenario where the source `BytesConsumer` is already finished. It verifies that both output consumers also become finished.
    * **`TwoPhaseRead`, `TwoPhaseReadWithDataAndDone`:** Test scenarios involving asynchronous data arrival (`kWait`, `kData`, `kDataAndDone`). They check if the data is correctlytee'd to both output consumers.
    * **`Error`:** Tests how the tee behaves when the source consumer encounters an error.
    * **`Cancel`:** Tests the cancellation behavior of the tee and its impact on the source and destination consumers.
    * **`CancelShouldNotAffectTheOtherDestination`, `CancelShouldNotAffectTheOtherDestination2`:** Crucial tests verifying that cancelling one output consumer doesn't inadvertently affect the other.
    * **`BlobHandle`, `BlobHandleWithInvalidSize`:** Test the `DrainAsBlobDataHandle` functionality, demonstrating how the tee handles `BlobDataHandle` objects. The "invalid size" test checks a specific edge case.
    * **`FormData`:** Tests the `DrainAsFormData` functionality, showing how the tee handles `EncodedFormData`.
    * **`ConsumerCanBeErroredInTwoPhaseRead`:** Tests a scenario where one of the tee'd consumers encounters an error during an asynchronous read.
    * **`AsyncNotificationShouldBeDispatchedWhenAllDataIsConsumed`, `AsyncCloseNotificationShouldBeCancelledBySubsequentReadCall`:** These tests focus on the asynchronous notification mechanisms and how subsequent reads interact with them.
    * **`ClosedBytesConsumer`, `ErroredBytesConsumer`:**  These test the behavior of pre-closed and pre-errored `BytesConsumer` instances, potentially used as source consumers for the tee.

6. **Identify Key Concepts and Relationships:**
    * **`BytesConsumer`:** The fundamental interface for consuming byte streams.
    * **`BytesConsumerTee`:** The class under test, responsible for splitting a single `BytesConsumer` into two.
    * **Source and Destination Consumers:** The tee takes a source and creates two destination consumers.
    * **States:** `kReadableOrWaiting`, `kClosed`, `kErrored` are key states of a `BytesConsumer`.
    * **Asynchronous Operations:** The use of `kWait` and the asynchronous notification tests highlight the importance of asynchronous behavior.
    * **Blob and FormData Handling:** The specific tests for these types indicate they are important use cases for the `BytesConsumerTee`.

7. **Infer Functionality and Relevance:** Based on the tests, deduce the core functionality of `BytesConsumerTee`:
    * It allows consuming a byte stream in two independent ways.
    * It correctly handles various states of the source consumer (done, error).
    * Cancelling one output doesn't affect the other.
    * It supports specific data types like Blobs and Form Data.
    * It manages asynchronous notifications.

8. **Connect to Web Technologies (if applicable):**  Based on the included headers and the concepts, make connections to web technologies:
    * **JavaScript `tee()` method on `ReadableStream`:** This is the most direct analogy. The `BytesConsumerTee` likely implements similar functionality at the C++ level.
    * **Fetching Resources:** The `fetch` namespace and the handling of blobs and form data strongly suggest this is related to network requests and response processing.
    * **HTML Forms:** `EncodedFormData` directly relates to how HTML form submissions are handled.
    * **Blobs:** These are used for representing raw data in the browser, often for file uploads or downloads.

9. **Consider Error Scenarios and Debugging:**
    * **User Errors:**  Think about how developers might misuse the JavaScript `tee()` API, which would relate to the underlying C++ implementation.
    * **Debugging:** Explain how the test setup (simulated environment, controlled input via `ReplayingBytesConsumer`) can help debug issues related to byte stream processing.

10. **Structure the Explanation:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the functionality of `BytesConsumerTee`.
    * Explain the relationship to web technologies with examples.
    * Provide logical reasoning with hypothetical input/output.
    * Discuss potential user errors.
    * Explain the debugging context.

11. **Refine and Elaborate:** Review the explanation for clarity, completeness, and accuracy. Add details and examples where necessary. For instance, elaborating on the asynchronous nature of the operations is important.

By following these steps, one can systematically analyze the C++ test file and generate a comprehensive explanation like the example provided in the initial prompt. The key is to combine code inspection with an understanding of the broader context of the Blink rendering engine and web technologies.
这个文件 `blink/renderer/core/fetch/bytes_consumer_tee_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件。它的主要功能是 **测试 `BytesConsumerTee` 类的行为**。`BytesConsumerTee` 的作用是将一个 `BytesConsumer`（字节流消费者）分叉成两个独立的 `BytesConsumer`，使得两个不同的消费者可以同时读取相同的字节流。

下面对文件内容进行详细分析，并解释其与 JavaScript, HTML, CSS 的关系，以及可能的逻辑推理、用户错误和调试线索。

**1. 文件功能：测试 `BytesConsumerTee` 类**

* **核心功能：** `BytesConsumerTee` 允许将一个输入的字节流（由一个 `BytesConsumer` 提供）复制到两个独立的输出字节流（由两个新的 `BytesConsumer` 提供）。这在需要同时对同一份数据进行多种处理时非常有用。
* **测试用例覆盖：**  测试文件包含了多种场景来验证 `BytesConsumerTee` 的正确性，包括：
    * 当源 `BytesConsumer` 已经完成时的行为。
    * 分阶段读取数据时的行为（模拟网络请求的 chunked 传输）。
    * 源 `BytesConsumer` 发生错误时的行为。
    * 取消其中一个 tee 产生的 `BytesConsumer` 时的行为。
    * 如何处理 `BlobDataHandle` 和 `EncodedFormData` 等特定数据类型。
    * 异步通知机制的正确性。

**2. 与 JavaScript, HTML, CSS 的关系**

`BytesConsumerTee` 本身是一个底层的 C++ 类，直接与 JavaScript, HTML, CSS 没有直接的语法关系。但是，它在 Blink 引擎中扮演着重要的角色，支持着这些上层技术的功能。

* **JavaScript `ReadableStream.tee()` 方法：**  `BytesConsumerTee` 的功能与 JavaScript 的 `ReadableStream` 接口提供的 `tee()` 方法非常相似。`ReadableStream.tee()` 允许将一个可读流分叉成两个独立的流，这两个流可以被独立地读取。`BytesConsumerTee` 很可能就是 `ReadableStream.tee()` 方法在 Blink 内部的 C++ 实现基础。

   **举例说明：** 在 JavaScript 中，你可以使用 `fetch` API 获取一个网络资源，并使用 `response.body.tee()` 将响应体（`ReadableStream`）分叉：

   ```javascript
   fetch('https://example.com/data')
     .then(response => {
       const [stream1, stream2] = response.body.tee();

       // stream1 用于处理数据的显示
       const reader1 = stream1.getReader();
       reader1.read().then(function processData({ done, value }) {
         if (done) {
           console.log("Stream 1 finished");
           return;
         }
         console.log("Stream 1 data:", value);
         // ... 处理 value ...
         return reader1.read().then(processData);
       });

       // stream2 用于将数据缓存到本地
       const reader2 = stream2.getReader();
       reader2.read().then(function cacheData({ done, value }) {
         if (done) {
           console.log("Stream 2 finished");
           return;
         }
         // ... 将 value 缓存到本地 ...
         return reader2.read().then(cacheData);
       });
     });
   ```

   在这个例子中，`response.body.tee()` 底层就可能使用了 `BytesConsumerTee` 来创建两个独立的字节流消费者，分别用于数据处理和缓存。

* **Fetch API 和网络请求：** 当浏览器发起网络请求时，响应的数据会以字节流的形式接收。`BytesConsumer` 及其相关的类（包括 `BytesConsumerTee`）负责处理这些字节流。例如，一个响应体可能需要同时被用于渲染页面（HTML/CSS/JavaScript 资源）和下载到本地（文件下载）。`BytesConsumerTee` 可以确保这两者都能独立地消费响应体的数据。

* **Blob 和 FormData 处理：** 文件中测试了 `BytesConsumerTee` 如何处理 `BlobDataHandle` 和 `EncodedFormData`。这表明 `BytesConsumerTee` 在处理文件上传（FormData）和二进制数据（Blob）等场景中也有应用。

**3. 逻辑推理和假设输入/输出**

假设我们有一个 `ReplayingBytesConsumer`，它可以模拟一个网络请求的响应体，并包含以下数据和状态变化：

**假设输入：**

```
Source BytesConsumer:
  - Command::kData, "chunk1"
  - Command::kWait
  - Command::kData, "chunk2"
  - Command::kDone
```

我们使用 `BytesConsumerTee` 将其分叉成 `dest1` 和 `dest2`。

**逻辑推理：**

1. 当源 `BytesConsumer` 发出 "chunk1" 数据时，`dest1` 和 `dest2` 都可以读取到 "chunk1"。
2. 当源 `BytesConsumer` 进入等待状态 (`kWait`) 时，`dest1` 和 `dest2` 也都处于等待状态，直到源消费者有新的数据或状态变化。
3. 当源 `BytesConsumer` 发出 "chunk2" 数据时，`dest1` 和 `dest2` 都可以读取到 "chunk2"。
4. 当源 `BytesConsumer` 完成 (`kDone`) 时，`dest1` 和 `dest2` 也都会完成。

**假设输出（使用 `BytesConsumerTestReader` 读取 `dest1` 和 `dest2`）：**

```
Result for dest1:
  - Result::kOk, "chunk1"
  - Result::kOk, "chunk2"
  - Result::kDone, ""

Result for dest2:
  - Result::kOk, "chunk1"
  - Result::kOk, "chunk2"
  - Result::kDone, ""
```

**4. 用户或编程常见的使用错误**

虽然用户通常不会直接操作 `BytesConsumerTee`，但在使用 JavaScript 的 `ReadableStream.tee()` 方法时，可能会遇到一些与底层 `BytesConsumerTee` 相关的错误：

* **过早地关闭或取消其中一个 tee 产生的流：**  如果开发者过早地关闭或取消了其中一个由 `tee()` 产生的流，可能会影响到另一个流的读取，尤其是在底层实现中资源管理不当的情况下。`BytesConsumerTee` 的测试用例 `CancelShouldNotAffectTheOtherDestination` 和 `CancelShouldNotAffectTheOtherDestination2` 就是为了验证这种情况。
* **假设两个 tee 产生的流是完全独立的，没有共享状态：** 虽然 `BytesConsumerTee` 的目标是创建两个独立的消费者，但在某些边缘情况下，底层的实现细节可能会导致它们之间存在某种关联。例如，如果源 `BytesConsumer` 发生错误，两个 tee 产生的消费者都会进入错误状态。
* **不正确地处理异步读取：**  `BytesConsumer` 的读取是异步的。开发者在使用 `ReadableStream` 时需要正确地处理 `read()` 方法返回的 Promise，以避免数据丢失或程序hang住。

**5. 用户操作如何一步步到达这里，作为调试线索**

当开发者在使用浏览器时遇到与网络请求、文件下载、或者涉及流式数据处理相关的问题时，可能会触发 Blink 引擎中与 `BytesConsumerTee` 相关的代码。以下是一些可能的场景：

1. **使用 Fetch API 下载大文件：** 当用户通过 JavaScript 使用 `fetch` API 下载一个大型文件，并且代码中使用了 `response.body.tee()` 来同时进行下载和进度显示等操作时，如果出现下载中断或数据不一致的问题，开发者可能会需要深入到 Blink 引擎的网络层进行调试，从而接触到 `BytesConsumerTee` 相关的代码。

2. **网页中使用了 Service Worker 进行资源缓存：** Service Worker 可以拦截网络请求并缓存响应。如果 Service Worker 中使用了 `response.body.tee()` 来同时缓存响应和将响应传递给浏览器，那么在缓存或响应处理出现问题时，也可能涉及到 `BytesConsumerTee` 的调试。

3. **处理 `Blob` 或 `FormData` 对象：** 当网页需要上传大型文件（通过 `FormData`）或处理来自用户的文件输入（生成 `Blob`）时，Blink 引擎会使用 `BytesConsumer` 来读取这些数据。如果在这些过程中出现错误，例如上传失败或数据损坏，开发者可能会需要查看 `BytesConsumerTee` 是否正确地处理了数据的分发。

**调试线索：**

* **崩溃堆栈：** 如果程序崩溃，崩溃堆栈信息可能会指向 `bytes_consumer_tee.cc` 或相关的 `BytesConsumer` 类。
* **网络请求日志：** 检查浏览器的网络请求日志，查看请求的状态、响应头和响应体，可以帮助判断是否是网络层的问题导致了 `BytesConsumerTee` 的异常行为。
* **Blink 内部日志：** Blink 引擎有自己的日志系统。在调试构建中，可以启用更详细的日志输出，查看 `BytesConsumer` 和 `BytesConsumerTee` 的状态变化。
* **断点调试：** 如果开发者有 Blink 引擎的源码，可以使用调试器（如 gdb 或 lldb）在 `bytes_consumer_tee.cc` 中设置断点，逐步跟踪代码的执行流程，查看变量的值和状态变化。

总而言之，`bytes_consumer_tee_test.cc` 这个文件是 Blink 引擎中一个重要的测试文件，它确保了 `BytesConsumerTee` 类的正确性，而 `BytesConsumerTee` 作为底层基础设施，支撑着诸如 JavaScript 的 `ReadableStream.tee()`、Fetch API 和文件处理等重要的 Web 平台功能。理解这个文件的功能有助于理解 Blink 引擎如何处理字节流数据，并在遇到相关问题时提供调试思路。

Prompt: 
```
这是目录为blink/renderer/core/fetch/bytes_consumer_tee_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/bytes_consumer_tee.h"

#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/fetch/bytes_consumer_test_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/loader/testing/replaying_bytes_consumer.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

using Result = BytesConsumer::Result;

class BytesConsumerTestClient final
    : public GarbageCollected<BytesConsumerTestClient>,
      public BytesConsumer::Client {
 public:
  void OnStateChange() override { ++num_on_state_change_called_; }
  String DebugName() const override { return "BytesConsumerTestClient"; }
  int NumOnStateChangeCalled() const { return num_on_state_change_called_; }

 private:
  int num_on_state_change_called_ = 0;
};

class BytesConsumerTeeTest : public PageTestBase {
 public:
  using Command = ReplayingBytesConsumer::Command;
  void SetUp() override { PageTestBase::SetUp(gfx::Size()); }
};

class FakeBlobBytesConsumer : public BytesConsumer {
 public:
  explicit FakeBlobBytesConsumer(scoped_refptr<BlobDataHandle> handle)
      : blob_handle_(std::move(handle)) {}
  ~FakeBlobBytesConsumer() override {}

  Result BeginRead(base::span<const char>& buffer) override {
    if (state_ == PublicState::kClosed)
      return Result::kDone;
    blob_handle_ = nullptr;
    state_ = PublicState::kErrored;
    return Result::kError;
  }
  Result EndRead(size_t read_size) override {
    if (state_ == PublicState::kClosed)
      return Result::kError;
    blob_handle_ = nullptr;
    state_ = PublicState::kErrored;
    return Result::kError;
  }
  scoped_refptr<BlobDataHandle> DrainAsBlobDataHandle(
      BlobSizePolicy policy) override {
    if (state_ != PublicState::kReadableOrWaiting)
      return nullptr;
    DCHECK(blob_handle_);
    if (policy == BlobSizePolicy::kDisallowBlobWithInvalidSize &&
        blob_handle_->size() == UINT64_MAX)
      return nullptr;
    state_ = PublicState::kClosed;
    return std::move(blob_handle_);
  }

  void SetClient(Client*) override {}
  void ClearClient() override {}
  void Cancel() override {}
  PublicState GetPublicState() const override { return state_; }
  Error GetError() const override { return Error(); }
  String DebugName() const override { return "FakeBlobBytesConsumer"; }

 private:
  PublicState state_ = PublicState::kReadableOrWaiting;
  scoped_refptr<BlobDataHandle> blob_handle_;
};

class FakeFormDataBytesConsumer : public BytesConsumer {
 public:
  explicit FakeFormDataBytesConsumer(scoped_refptr<EncodedFormData> form_data)
      : form_data_(std::move(form_data)) {}
  ~FakeFormDataBytesConsumer() override {}

  Result BeginRead(base::span<const char>& buffer) override {
    if (state_ == PublicState::kClosed)
      return Result::kDone;
    form_data_ = nullptr;
    state_ = PublicState::kErrored;
    return Result::kError;
  }
  Result EndRead(size_t read_size) override {
    if (state_ == PublicState::kClosed)
      return Result::kError;
    form_data_ = nullptr;
    state_ = PublicState::kErrored;
    return Result::kError;
  }
  scoped_refptr<EncodedFormData> DrainAsFormData() override {
    if (state_ != PublicState::kReadableOrWaiting)
      return nullptr;
    DCHECK(form_data_);
    return std::move(form_data_);
  }

  void SetClient(Client*) override {}
  void ClearClient() override {}
  void Cancel() override {}
  PublicState GetPublicState() const override { return state_; }
  Error GetError() const override { return Error(); }
  String DebugName() const override { return "FakeFormDataBytesConsumer"; }

 private:
  PublicState state_ = PublicState::kReadableOrWaiting;
  scoped_refptr<EncodedFormData> form_data_;
};

TEST_F(BytesConsumerTeeTest, CreateDone) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kDone));
  EXPECT_FALSE(src->IsCancelled());

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  auto result1 = (MakeGarbageCollected<BytesConsumerTestReader>(dest1))->Run();
  auto result2 = (MakeGarbageCollected<BytesConsumerTestReader>(dest2))->Run();

  EXPECT_EQ(Result::kDone, result1.first);
  EXPECT_TRUE(result1.second.empty());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(Result::kDone, result2.first);
  EXPECT_TRUE(result2.second.empty());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());

  // Cancelling does nothing when closed.
  dest1->Cancel();
  dest2->Cancel();
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());
}

TEST_F(BytesConsumerTeeTest, TwoPhaseRead) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));

  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "hello, "));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "world"));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kDone));

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());

  auto result1 = (MakeGarbageCollected<BytesConsumerTestReader>(dest1))->Run();
  auto result2 = (MakeGarbageCollected<BytesConsumerTestReader>(dest2))->Run();

  EXPECT_EQ(Result::kDone, result1.first);
  EXPECT_EQ("hello, world", String(result1.second));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(Result::kDone, result2.first);
  EXPECT_EQ("hello, world", String(result2.second));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());
}

TEST_F(BytesConsumerTeeTest, TwoPhaseReadWithDataAndDone) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));

  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "hello, "));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kDataAndDone, "world"));

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());

  auto result1 = (MakeGarbageCollected<BytesConsumerTestReader>(dest1))->Run();
  auto result2 = (MakeGarbageCollected<BytesConsumerTestReader>(dest2))->Run();

  EXPECT_EQ(Result::kDone, result1.first);
  EXPECT_EQ("hello, world", String(result1.second));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(Result::kDone, result2.first);
  EXPECT_EQ("hello, world", String(result2.second));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());
}

TEST_F(BytesConsumerTeeTest, Error) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));

  src->Add(Command(Command::kData, "hello, "));
  src->Add(Command(Command::kData, "world"));
  src->Add(Command(Command::kError));

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest2->GetPublicState());

  auto result1 = (MakeGarbageCollected<BytesConsumerTestReader>(dest1))->Run();
  auto result2 = (MakeGarbageCollected<BytesConsumerTestReader>(dest2))->Run();

  EXPECT_EQ(Result::kError, result1.first);
  EXPECT_TRUE(result1.second.empty());
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest1->GetPublicState());
  EXPECT_EQ(Result::kError, result2.first);
  EXPECT_TRUE(result2.second.empty());
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());

  // Cancelling does nothing when errored.
  dest1->Cancel();
  dest2->Cancel();
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());
}

TEST_F(BytesConsumerTeeTest, Cancel) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));

  src->Add(Command(Command::kData, "hello, "));
  src->Add(Command(Command::kWait));

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());

  EXPECT_FALSE(src->IsCancelled());
  dest1->Cancel();
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());
  dest2->Cancel();
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest2->GetPublicState());
  EXPECT_TRUE(src->IsCancelled());
}

TEST_F(BytesConsumerTeeTest, CancelShouldNotAffectTheOtherDestination) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));

  src->Add(Command(Command::kData, "hello, "));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "world"));
  src->Add(Command(Command::kDone));

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());

  EXPECT_FALSE(src->IsCancelled());
  dest1->Cancel();
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());

  auto result2 = (MakeGarbageCollected<BytesConsumerTestReader>(dest2))->Run();

  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest2->GetPublicState());
  EXPECT_EQ(Result::kDone, result2.first);
  EXPECT_EQ("hello, world", String(result2.second));
  EXPECT_FALSE(src->IsCancelled());
}

TEST_F(BytesConsumerTeeTest, CancelShouldNotAffectTheOtherDestination2) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));

  src->Add(Command(Command::kData, "hello, "));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "world"));
  src->Add(Command(Command::kError));

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());

  EXPECT_FALSE(src->IsCancelled());
  dest1->Cancel();
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest2->GetPublicState());
  EXPECT_FALSE(src->IsCancelled());

  auto result2 = (MakeGarbageCollected<BytesConsumerTestReader>(dest2))->Run();

  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest2->GetPublicState());
  EXPECT_EQ(Result::kError, result2.first);
  EXPECT_FALSE(src->IsCancelled());
}

TEST_F(BytesConsumerTeeTest, BlobHandle) {
  scoped_refptr<BlobDataHandle> blob_data_handle =
      BlobDataHandle::Create(std::make_unique<BlobData>(), 12345);
  BytesConsumer* src =
      MakeGarbageCollected<FakeBlobBytesConsumer>(blob_data_handle);

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  scoped_refptr<BlobDataHandle> dest_blob_data_handle1 =
      dest1->DrainAsBlobDataHandle(
          BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize);
  scoped_refptr<BlobDataHandle> dest_blob_data_handle2 =
      dest2->DrainAsBlobDataHandle(
          BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize);
  ASSERT_TRUE(dest_blob_data_handle1);
  ASSERT_TRUE(dest_blob_data_handle2);
  EXPECT_EQ(12345u, dest_blob_data_handle1->size());
  EXPECT_EQ(12345u, dest_blob_data_handle2->size());
}

TEST_F(BytesConsumerTeeTest, BlobHandleWithInvalidSize) {
  scoped_refptr<BlobDataHandle> blob_data_handle = BlobDataHandle::Create(
      std::make_unique<BlobData>(), std::numeric_limits<uint64_t>::max());
  BytesConsumer* src =
      MakeGarbageCollected<FakeBlobBytesConsumer>(blob_data_handle);

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  scoped_refptr<BlobDataHandle> dest_blob_data_handle1 =
      dest1->DrainAsBlobDataHandle(
          BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize);
  scoped_refptr<BlobDataHandle> dest_blob_data_handle2 =
      dest2->DrainAsBlobDataHandle(
          BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize);
  ASSERT_TRUE(dest_blob_data_handle1);
  ASSERT_FALSE(dest_blob_data_handle2);
  EXPECT_EQ(UINT64_MAX, dest_blob_data_handle1->size());
}

TEST_F(BytesConsumerTeeTest, FormData) {
  auto form_data = EncodedFormData::Create();

  auto* src = MakeGarbageCollected<FakeFormDataBytesConsumer>(form_data);

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  scoped_refptr<EncodedFormData> dest_form_data1 = dest1->DrainAsFormData();
  scoped_refptr<EncodedFormData> dest_form_data2 = dest2->DrainAsFormData();
  EXPECT_EQ(form_data, dest_form_data1);
  EXPECT_EQ(form_data, dest_form_data2);
}

TEST_F(BytesConsumerTeeTest, ConsumerCanBeErroredInTwoPhaseRead) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kData, "a"));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kError));

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);
  BytesConsumerTestClient* client =
      MakeGarbageCollected<BytesConsumerTestClient>();
  dest1->SetClient(client);

  base::span<const char> buffer;
  ASSERT_EQ(Result::kOk, dest1->BeginRead(buffer));
  ASSERT_EQ(1u, buffer.size());

  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());
  int num_on_state_change_called = client->NumOnStateChangeCalled();
  EXPECT_EQ(
      Result::kError,
      (MakeGarbageCollected<BytesConsumerTestReader>(dest2))->Run().first);
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, dest1->GetPublicState());
  EXPECT_EQ(num_on_state_change_called + 1, client->NumOnStateChangeCalled());
  EXPECT_EQ('a', buffer[0]);
  EXPECT_EQ(Result::kOk, dest1->EndRead(buffer.size()));
}

TEST_F(BytesConsumerTeeTest,
       AsyncNotificationShouldBeDispatchedWhenAllDataIsConsumed) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kData, "a"));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kDone));
  BytesConsumerTestClient* client =
      MakeGarbageCollected<BytesConsumerTestClient>();

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  dest1->SetClient(client);

  base::span<const char> buffer;
  ASSERT_EQ(Result::kOk, dest1->BeginRead(buffer));
  ASSERT_EQ(1u, buffer.size());
  EXPECT_EQ('a', buffer[0]);

  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            src->GetPublicState());
  test::RunPendingTasks();
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, src->GetPublicState());
  // Just for checking UAF.
  EXPECT_EQ('a', buffer[0]);
  ASSERT_EQ(Result::kOk, dest1->EndRead(1));

  EXPECT_EQ(0, client->NumOnStateChangeCalled());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());
  test::RunPendingTasks();
  EXPECT_EQ(1, client->NumOnStateChangeCalled());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
}

TEST_F(BytesConsumerTeeTest,
       AsyncCloseNotificationShouldBeCancelledBySubsequentReadCall) {
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kData, "a"));
  src->Add(Command(Command::kDone));
  BytesConsumerTestClient* client =
      MakeGarbageCollected<BytesConsumerTestClient>();

  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  BytesConsumerTee(GetFrame().DomWindow(), src, &dest1, &dest2);

  dest1->SetClient(client);

  base::span<const char> buffer;
  ASSERT_EQ(Result::kOk, dest1->BeginRead(buffer));
  ASSERT_EQ(1u, buffer.size());
  EXPECT_EQ('a', buffer[0]);

  test::RunPendingTasks();
  // Just for checking UAF.
  EXPECT_EQ('a', buffer[0]);
  ASSERT_EQ(Result::kOk, dest1->EndRead(1));
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            dest1->GetPublicState());

  EXPECT_EQ(Result::kDone, dest1->BeginRead(buffer));
  EXPECT_EQ(0, client->NumOnStateChangeCalled());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
  test::RunPendingTasks();
  EXPECT_EQ(0, client->NumOnStateChangeCalled());
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, dest1->GetPublicState());
}

TEST(BytesConusmerTest, ClosedBytesConsumer) {
  test::TaskEnvironment task_environment;
  BytesConsumer* consumer = BytesConsumer::CreateClosed();

  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST(BytesConusmerTest, ErroredBytesConsumer) {
  test::TaskEnvironment task_environment;
  BytesConsumer::Error error("hello");
  BytesConsumer* consumer = BytesConsumer::CreateErrored(error);

  base::span<const char> buffer;
  EXPECT_EQ(Result::kError, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, consumer->GetPublicState());
  EXPECT_EQ(error.Message(), consumer->GetError().Message());

  consumer->Cancel();
  EXPECT_EQ(BytesConsumer::PublicState::kErrored, consumer->GetPublicState());
}

}  // namespace

}  // namespace blink

"""

```