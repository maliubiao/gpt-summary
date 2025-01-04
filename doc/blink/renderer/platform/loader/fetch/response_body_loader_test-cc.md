Response:
My thought process to answer the request about `response_body_loader_test.cc` goes like this:

1. **Understand the Core Purpose:** The file name itself, `response_body_loader_test.cc`, strongly suggests it's a test file for a component called `ResponseBodyLoader`. The `.cc` extension means it's C++ code. The `test` suffix clearly indicates its role.

2. **Identify Key Classes and Concepts:**  I scan the `#include` directives and the code itself for prominent class names and related concepts. Immediately, `ResponseBodyLoader`, `BytesConsumer`, and `TestClient` stand out. I also notice mentions of `BackForwardCacheLoaderHelper`, `DataPipeBytesConsumer`, and `ReplayingBytesConsumer`. The presence of `testing/gtest/include/gtest/gtest.h` confirms it's using the Google Test framework.

3. **Analyze the Test Structure:** I observe the `TEST_F` macros. Each one represents an individual test case. I look at the names of these tests (e.g., `Load`, `LoadFailure`, `Abort`, `Suspend`, `DrainAsDataPipe`). These names give me a high-level overview of what aspects of `ResponseBodyLoader` are being tested.

4. **Decipher Test Logic (General Pattern):**  I examine the structure within a typical test case. I see a pattern:
    * **Setup:** Create a `FakeTaskRunner` for controlling asynchronous operations. Instantiate a `ReplayingBytesConsumer` (or a `DataPipeBytesConsumer` in some cases) to simulate the source of data. Create a `TestClient` to act as the receiver of data. Instantiate the `ResponseBodyLoader` being tested, passing in the consumer and client.
    * **Action:**  Call the method being tested on the `ResponseBodyLoader` (e.g., `Start()`, `Abort()`, `Suspend()`, `DrainAsDataPipe()`).
    * **Assertion:** Use `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_EQ` to verify the state of the `TestClient` (whether loading finished, failed, data received) and the `ResponseBodyLoader` itself (e.g., `IsAborted()`, `IsSuspended()`, `IsDrained()`). The `FakeTaskRunner->RunUntilIdle()` is crucial for advancing asynchronous operations.

5. **Relate to Web Concepts (JavaScript, HTML, CSS):**  I think about how the `ResponseBodyLoader` might interact with front-end technologies. It's responsible for fetching and processing the *content* of web resources. This content could be:
    * **HTML:** The main structure of a webpage. The loader brings in the HTML that the browser parses to build the DOM.
    * **CSS:** Stylesheets. The loader fetches CSS files so the browser can apply styling to the HTML.
    * **JavaScript:** Scripts. The loader retrieves JavaScript files that the browser's JavaScript engine executes.
    * **Other resources:** Images, fonts, etc., although the examples in *this specific test file* seem more focused on text-based content.

6. **Identify Logical Inferences and Assumptions:** I consider the implicit logic within the tests. For instance, the tests involving `Suspend` and `Resume` make assumptions about the order of data processing and the impact of suspension on buffering. The tests with `ReplayingBytesConsumer` make assumptions about how this mock consumer behaves.

7. **Recognize Potential Usage Errors:**  I look for test cases that explore error scenarios or unusual usage patterns. The `Abort` test demonstrates how cancelling the load might work. The `DrainAsDataPipe` and `DrainAsBytesConsumer` tests showcase alternative ways to consume the response body, and improper usage (like trying to drain multiple times or draining after starting) could be an error.

8. **Address the "Part 1" Constraint:**  Since it's the first part, I focus on summarizing the *core functionalities* demonstrated in this section of the code. I avoid speculating too much on what might be in the *next* part.

9. **Structure the Answer:** I organize my findings into the requested categories: functionality, relationship to web technologies, logical inferences, common errors, and a summary. I use clear and concise language, providing examples where appropriate. I emphasize that this is a *test* file, so its purpose is to *verify* the behavior of the `ResponseBodyLoader`.

By following this thought process, I can systematically analyze the C++ test code and extract the relevant information to answer the user's question effectively. The key is to understand the testing methodology, the roles of the involved classes, and how these components fit into the broader context of a web browser engine.
这是 `blink/renderer/platform/loader/fetch/response_body_loader_test.cc` 文件的第一部分，它的主要功能是 **测试 `ResponseBodyLoader` 类的各种功能和行为**。

`ResponseBodyLoader` 负责从网络或其他来源加载响应体 (response body) 的数据流。这个测试文件通过模拟不同的数据接收场景和用户操作，来验证 `ResponseBodyLoader` 是否按照预期工作，包括成功加载、加载失败、取消加载、暂停和恢复加载等等。

**以下是根据代码内容进行的更详细的功能列举和说明：**

**1. 核心功能：测试 `ResponseBodyLoader` 的数据加载流程**

* **成功加载 (Load):** 测试正常接收数据并成功完成加载的情况。
    * **假设输入:** `ReplayingBytesConsumer` 模拟接收 "he", 等待, "llo", 完成信号。
    * **预期输出:** `TestClient` 接收到 "hello"，`LoadingIsFinished()` 返回 true。
* **加载失败 (LoadFailure):** 测试接收数据过程中遇到错误的情况。
    * **假设输入:** `ReplayingBytesConsumer` 模拟接收 "he", 等待, "llo", 错误信号。
    * **预期输出:** `TestClient` 接收到 "hello"，`LoadingIsFailed()` 返回 true。
* **带有数据和完成信号的加载 (LoadWithDataAndDone):** 测试一次性接收到数据和完成信号的情况。
    * **假设输入:** `ReplayingBytesConsumer` 模拟接收 "he", 等待, "llo" 和完成信号。
    * **预期输出:** `TestClient` 接收到 "hello"，`LoadingIsFinished()` 返回 true。

**2. 测试 `ResponseBodyLoader` 的控制方法**

* **中止加载 (Abort):** 测试在接收数据过程中主动中止加载的情况。
    * **假设输入:** `ReplayingBytesConsumer` 模拟接收数据，`TestClient` 在接收到数据后调用 `loader_->Abort()`。
    * **预期输出:** `body_loader->IsAborted()` 返回 true，加载没有完成也没有失败，已接收的数据保持不变。
* **暂停和恢复加载 (Suspend/Resume):** 测试暂停加载和恢复加载的功能，并区分了针对 BackForwardCache 的暂停和普通暂停。
    * **假设输入:** `ReplayingBytesConsumer` 模拟接收数据，`TestClient` 在接收到数据后调用 `loader_->Suspend()`，然后调用 `loader_->Resume()`。
    * **预期输出:**  验证在暂停期间数据是否被缓冲，恢复后是否继续加载并最终完成。
* **读取过大的缓冲区 (ReadTooBigBuffer):** 测试处理超过预定义大小的数据块的能力。
    * **假设输入:** `ReplayingBytesConsumer` 模拟发送不同大小的数据块，包括大于 `network::features::kMaxNumConsumedBytesInTask` 的数据。
    * **预期输出:** `TestClient` 能正确接收所有数据并最终完成加载。

**3. 测试 `ResponseBodyLoader` 的数据导出功能**

* **无法导出为 DataPipe (NotDrainable):** 测试在未开始加载时尝试导出为 DataPipe 的情况。
    * **假设输入:** 在调用 `body_loader->Start()` 之前调用 `DrainAsDataPipe()`。
    * **预期输出:** `DrainAsDataPipe()` 返回空，`IsDrained()` 返回 false。
* **导出为 DataPipe (DrainAsDataPipe):** 测试将已加载或正在加载的数据导出到 Mojo DataPipe 的功能。
    * **假设输入:** 调用 `DrainAsDataPipe()` 获取 `data_pipe` 和 `client_for_draining`，然后通过 `client_for_draining` 模拟接收数据并发送完成信号。
    * **预期输出:**  `data_pipe` 不为空，`IsDrained()` 返回 true，原始的 `TestClient` 接收到通过 DataPipe 传递的数据，并且加载状态正确。
* **导出为 BytesConsumer (DrainAsBytesConsumer):** 测试将 `ResponseBodyLoader` 的数据流导出为一个新的 `BytesConsumer`。
    * **假设输入:** 调用 `DrainAsBytesConsumer()` 获取 `consumer`，然后使用 `BytesConsumerTestReader` 从导出的 `consumer` 中读取数据。
    * **预期输出:** `IsDrained()` 返回 true，导出的 `consumer` 能提供和原始加载器相同的数据，并且加载状态正确。
* **取消导出的 BytesConsumer (CancelDrainedBytesConsumer):** 测试取消导出的 `BytesConsumer` 的情况。
    * **假设输入:** 调用 `DrainAsBytesConsumer()` 后调用 `consumer.Cancel()`。
    * **预期输出:** 原始的 `TestClient` 的加载会被取消。
* **在加载时中止导出的 BytesConsumer (AbortDrainAsBytesConsumerWhileLoading):** 测试在加载进行中导出 `BytesConsumer` 后中止加载的情况。
    * **假设输入:** 在 `ResponseBodyLoader` 加载过程中调用 `DrainAsBytesConsumer()` 并立即调用 `Abort()`。
    * **预期输出:** 导出的 `BytesConsumer` 的状态变为错误。
* **导出带有错误的 BytesConsumer (DrainAsBytesConsumerWithError):** 测试在加载过程中发生错误并导出 `BytesConsumer` 的情况。
    * **假设输入:** `ResponseBodyLoader` 加载过程中遇到错误，然后调用 `DrainAsBytesConsumer()`。
    * **预期输出:** 导出的 `BytesConsumer` 的状态为错误，并且可以读取到错误发生前的数据。
* **在 BytesConsumer 导出后中止 (AbortAfterBytesConsumerIsDrained/AbortAfterBytesConsumerIsDrainedIsNotified):** 测试在导出 `BytesConsumer` 后再中止原始加载器的情况。
    * **假设输入:** 调用 `DrainAsBytesConsumer()` 导出后，调用 `body_loader->Abort()`。
    * **预期输出:** 导出的 `BytesConsumer` 的状态变为错误，其客户端会收到状态改变的通知。

**4. 涉及 BackForwardCache 的测试**

* **针对 BackForwardCache 的暂停和恢复 (ResponseBodyLoaderLoadingTasksUnfreezableTest):**  这部分测试特别关注 `ResponseBodyLoader` 在进入和退出浏览器的 BackForwardCache 时的行为，包括暂停、缓冲数据和恢复加载的机制。这些测试用例使用了参数化测试 (`testing::WithParamInterface`) 来覆盖启用和禁用 `features::kLoadingTasksUnfreezable` 特性的情况。

**与 Javascript, HTML, CSS 的关系：**

`ResponseBodyLoader` 是浏览器引擎底层网络加载机制的一部分，直接负责获取网页资源的内容。它与 Javascript, HTML, CSS 的关系体现在：

* **HTML:** 当浏览器请求一个 HTML 页面时，`ResponseBodyLoader` 负责下载 HTML 的内容。`TestClient::DidReceiveData` 模拟接收到的 HTML 数据，最终这些数据会被传递给 HTML 解析器来构建 DOM 树。
    * **举例:** 假设 `ReplayingBytesConsumer` 发送的是 `<html><head><title>Test Page</title></head><body>Hello</body></html>`，那么 `TestClient::GetData()` 最终会包含这段 HTML 字符串。
* **CSS:**  当 HTML 解析器遇到 `<link rel="stylesheet" href="style.css">` 这样的标签时，浏览器会发起对 `style.css` 的请求。`ResponseBodyLoader` 负责下载 CSS 文件的内容。
    * **举例:** 假设 `ReplayingBytesConsumer` 发送的是 `body { background-color: red; }`，那么对于加载 `style.css` 的 `ResponseBodyLoader`，`TestClient::GetData()` 会包含这段 CSS 字符串。
* **Javascript:** 类似于 CSS，当 HTML 解析器遇到 `<script src="script.js"></script>` 时，`ResponseBodyLoader` 负责下载 Javascript 文件的内容。
    * **举例:** 假设 `ReplayingBytesConsumer` 发送的是 `console.log("Hello from script.js");`，那么对于加载 `script.js` 的 `ResponseBodyLoader`，`TestClient::GetData()` 会包含这段 Javascript 代码。

**逻辑推理的假设输入与输出：**

在上面的功能列举中，已经包含了大部分的假设输入和预期输出。 核心思想是模拟不同的网络响应数据流和用户操作，然后验证 `ResponseBodyLoader` 的状态和行为是否符合预期。

**涉及用户或编程常见的使用错误：**

虽然这个文件是测试代码，但它反映了一些用户或编程中可能出现的与资源加载相关的问题：

* **网络请求失败:**  `LoadFailure` 测试模拟了这种情况，编程时需要处理网络请求失败的情况。
* **请求被取消:** `Abort` 测试模拟了用户取消页面加载或程序主动取消请求的情况，需要清理相关资源。
* **处理大量数据:** `ReadTooBigBuffer` 测试提醒开发者需要考虑处理大型响应体的情况，避免内存溢出或其他性能问题。
* **在不正确的时机操作加载器:** 例如在加载开始前就尝试导出数据流 (`NotDrainable`)，这反映了 API 使用的顺序性。
* **重复使用已导出的数据流:** 虽然测试中没有直接体现，但一旦数据流被 `DrainAsDataPipe` 或 `DrainAsBytesConsumer` 导出，原始的 `ResponseBodyLoader` 就不再负责管理这部分数据了，如果继续使用可能会导致逻辑错误。

**本部分功能归纳：**

这部分 `response_body_loader_test.cc` 文件的主要功能是 **全面测试 `ResponseBodyLoader` 类的核心加载流程、控制方法（中止、暂停、恢复）以及数据导出功能（导出为 DataPipe 和 BytesConsumer）**。  此外，它还涵盖了与浏览器 BackForwardCache 交互的特定场景。通过这些测试用例，可以确保 `ResponseBodyLoader` 能够可靠地处理各种网络响应和用户操作，为浏览器正确加载网页资源提供保障。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/response_body_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"

#include <memory>
#include <string>
#include <utility>
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "services/network/public/cpp/features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/loader/fetch/back_forward_cache_loader_helper.h"
#include "third_party/blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/loader/testing/replaying_bytes_consumer.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

class TestBackForwardCacheLoaderHelper : public BackForwardCacheLoaderHelper {
 public:
  TestBackForwardCacheLoaderHelper() = default;

  void EvictFromBackForwardCache(
      mojom::blink::RendererEvictionReason reason) override {}

  void DidBufferLoadWhileInBackForwardCache(bool update_process_wide_count,
                                            size_t num_bytes) override {}

  void Detach() override {}
};

class ResponseBodyLoaderTest : public testing::Test {
 protected:
  using Command = ReplayingBytesConsumer::Command;
  using PublicState = BytesConsumer::PublicState;
  using Result = BytesConsumer::Result;

  class TestClient final : public GarbageCollected<TestClient>,
                           public ResponseBodyLoaderClient {
   public:
    enum class Option {
      kNone,
      kAbortOnDidReceiveData,
      kSuspendOnDidReceiveData,
    };

    TestClient() : TestClient(Option::kNone) {}
    TestClient(Option option) : option_(option) {}
    ~TestClient() override {}

    String GetData() { return data_.ToString(); }
    bool LoadingIsFinished() const { return finished_; }
    bool LoadingIsFailed() const { return failed_; }
    bool LoadingIsCancelled() const { return cancelled_; }

    void DidReceiveData(base::span<const char> data) override {
      DCHECK(!finished_);
      DCHECK(!failed_);
      data_.Append(base::as_bytes(data));
      switch (option_) {
        case Option::kNone:
          break;
        case Option::kAbortOnDidReceiveData:
          loader_->Abort();
          break;
        case Option::kSuspendOnDidReceiveData:
          loader_->Suspend(LoaderFreezeMode::kStrict);
          break;
      }
    }
    void DidReceiveDecodedData(
        const String& data,
        std::unique_ptr<ParkableStringImpl::SecureDigest> digest) override {}
    void DidFinishLoadingBody() override {
      DCHECK(!finished_);
      DCHECK(!failed_);
      finished_ = true;
    }
    void DidFailLoadingBody() override {
      DCHECK(!finished_);
      DCHECK(!failed_);
      failed_ = true;
    }
    void DidCancelLoadingBody() override {
      DCHECK(!finished_);
      DCHECK(!failed_);
      cancelled_ = true;
    }

    void SetLoader(ResponseBodyLoader& loader) { loader_ = loader; }
    void Trace(Visitor* visitor) const override { visitor->Trace(loader_); }

   private:
    const Option option_;
    Member<ResponseBodyLoader> loader_;
    StringBuilder data_;
    bool finished_ = false;
    bool failed_ = false;
    bool cancelled_ = false;
  };

  class ReadingClient final : public GarbageCollected<ReadingClient>,
                              public BytesConsumer::Client {
   public:
    ReadingClient(BytesConsumer& bytes_consumer,
                  TestClient& test_response_body_loader_client)
        : bytes_consumer_(bytes_consumer),
          test_response_body_loader_client_(test_response_body_loader_client) {}

    void OnStateChangeInternal() {
      while (true) {
        base::span<const char> buffer;
        Result result = bytes_consumer_->BeginRead(buffer);
        if (result == Result::kShouldWait)
          return;
        if (result == Result::kOk) {
          result = bytes_consumer_->EndRead(buffer.size());
        }
        if (result != Result::kOk)
          return;
      }
    }

    // BytesConsumer::Client implementation
    void OnStateChange() override {
      on_state_change_called_ = true;
      OnStateChangeInternal();
      // Notification is done asynchronously.
      EXPECT_FALSE(test_response_body_loader_client_->LoadingIsCancelled());
      EXPECT_FALSE(test_response_body_loader_client_->LoadingIsFinished());
      EXPECT_FALSE(test_response_body_loader_client_->LoadingIsFailed());
    }
    String DebugName() const override { return "ReadingClient"; }
    void Trace(Visitor* visitor) const override {
      visitor->Trace(bytes_consumer_);
      visitor->Trace(test_response_body_loader_client_);
      BytesConsumer::Client::Trace(visitor);
    }

    bool IsOnStateChangeCalled() const { return on_state_change_called_; }

   private:
    bool on_state_change_called_ = false;
    const Member<BytesConsumer> bytes_consumer_;
    const Member<TestClient> test_response_body_loader_client_;
  };

  ResponseBodyLoader* MakeResponseBodyLoader(
      BytesConsumer& bytes_consumer,
      ResponseBodyLoaderClient& client,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    return MakeGarbageCollected<ResponseBodyLoader>(
        bytes_consumer, client, task_runner,
        MakeGarbageCollected<TestBackForwardCacheLoaderHelper>());
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

class ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest
    : public ResponseBodyLoaderTest {};

class ResponseBodyLoaderDrainedBytesConsumerNotificationInOnStateChangeTest
    : public ResponseBodyLoaderTest {};

TEST_F(ResponseBodyLoaderTest, Load) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  consumer->Add(Command(Command::kData, "he"));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kData, "llo"));
  consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_TRUE(client->GetData().empty());

  body_loader->Start();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("he", client->GetData());

  task_runner->RunUntilIdle();

  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
}

TEST_F(ResponseBodyLoaderTest, LoadFailure) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  consumer->Add(Command(Command::kData, "he"));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kData, "llo"));
  consumer->Add(Command(Command::kError));

  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_TRUE(client->GetData().empty());

  body_loader->Start();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("he", client->GetData());

  task_runner->RunUntilIdle();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_TRUE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
}

TEST_F(ResponseBodyLoaderTest, LoadWithDataAndDone) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  consumer->Add(Command(Command::kData, "he"));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kDataAndDone, "llo"));

  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_TRUE(client->GetData().empty());

  body_loader->Start();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("he", client->GetData());

  task_runner->RunUntilIdle();

  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
}

TEST_F(ResponseBodyLoaderTest, Abort) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  consumer->Add(Command(Command::kData, "he"));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kData, "llo"));
  consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>(
      TestClient::Option::kAbortOnDidReceiveData);
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);
  client->SetLoader(*body_loader);

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_TRUE(client->GetData().empty());
  EXPECT_FALSE(body_loader->IsAborted());

  body_loader->Start();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("he", client->GetData());
  EXPECT_TRUE(body_loader->IsAborted());

  task_runner->RunUntilIdle();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("he", client->GetData());
  EXPECT_TRUE(body_loader->IsAborted());
}

TEST_F(ResponseBodyLoaderTest, Suspend) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  consumer->Add(Command(Command::kData, "h"));
  consumer->Add(Command(Command::kDataAndDone, "ello"));

  auto* client = MakeGarbageCollected<TestClient>(
      TestClient::Option::kSuspendOnDidReceiveData);
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);
  client->SetLoader(*body_loader);

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_TRUE(client->GetData().empty());
  EXPECT_FALSE(body_loader->IsSuspended());

  body_loader->Start();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("h", client->GetData());
  EXPECT_TRUE(body_loader->IsSuspended());

  task_runner->RunUntilIdle();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("h", client->GetData());
  EXPECT_TRUE(body_loader->IsSuspended());

  body_loader->Resume();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("h", client->GetData());
  EXPECT_FALSE(body_loader->IsSuspended());

  task_runner->RunUntilIdle();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
  EXPECT_TRUE(body_loader->IsSuspended());

  body_loader->Resume();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
  EXPECT_FALSE(body_loader->IsSuspended());

  task_runner->RunUntilIdle();

  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
  EXPECT_FALSE(body_loader->IsSuspended());
}

TEST_F(ResponseBodyLoaderTest, ReadTooBigBuffer) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  const size_t kMax = network::features::kMaxNumConsumedBytesInTask;

  consumer->Add(Command(Command::kData, std::string(kMax - 1, 'a').data()));
  consumer->Add(Command(Command::kData, std::string(2, 'b').data()));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kData, std::string(kMax, 'c').data()));
  consumer->Add(Command(Command::kData, std::string(kMax + 3, 'd').data()));
  consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_TRUE(client->GetData().empty());

  body_loader->Start();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ((std::string(kMax - 1, 'a') + 'b').data(), client->GetData());

  task_runner->RunUntilIdle();

  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ((std::string(kMax - 1, 'a') + "bb" + std::string(kMax, 'c') +
             std::string(kMax + 3, 'd'))
                .data(),
            client->GetData());
}

TEST_F(ResponseBodyLoaderTest, NotDrainable) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  consumer->Add(Command(Command::kData, "he"));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kData, "llo"));
  consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);

  ResponseBodyLoaderClient* intermediate_client = nullptr;
  auto data_pipe = body_loader->DrainAsDataPipe(&intermediate_client);

  ASSERT_FALSE(data_pipe);
  EXPECT_FALSE(intermediate_client);
  EXPECT_FALSE(body_loader->IsDrained());

  // We can start loading.

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_TRUE(client->GetData().empty());

  body_loader->Start();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("he", client->GetData());

  task_runner->RunUntilIdle();

  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
}

TEST_F(ResponseBodyLoaderTest, DrainAsDataPipe) {
  mojo::ScopedDataPipeConsumerHandle consumer_end;
  mojo::ScopedDataPipeProducerHandle producer_end;
  auto result = mojo::CreateDataPipe(nullptr, producer_end, consumer_end);

  ASSERT_EQ(result, MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* completion_notifier = nullptr;

  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner, std::move(consumer_end), &completion_notifier);
  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);

  ResponseBodyLoaderClient* client_for_draining = nullptr;
  auto data_pipe = body_loader->DrainAsDataPipe(&client_for_draining);

  ASSERT_TRUE(data_pipe);
  ASSERT_TRUE(client);
  EXPECT_TRUE(body_loader->IsDrained());

  client_for_draining->DidReceiveData(base::span_from_cstring("xyz"));
  client_for_draining->DidReceiveData(base::span_from_cstring("abc"));

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("xyzabc", client->GetData());

  client_for_draining->DidFinishLoadingBody();

  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("xyzabc", client->GetData());
}

class ResponseBodyLoaderLoadingTasksUnfreezableTest
    : public ResponseBodyLoaderTest,
      public ::testing::WithParamInterface<bool> {
 protected:
  ResponseBodyLoaderLoadingTasksUnfreezableTest() {
    if (DeferWithBackForwardCacheEnabled()) {
      scoped_feature_list_.InitAndEnableFeature(
          features::kLoadingTasksUnfreezable);
    }
    WebRuntimeFeatures::EnableBackForwardCache(
        DeferWithBackForwardCacheEnabled());
  }

  bool DeferWithBackForwardCacheEnabled() { return GetParam(); }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_P(ResponseBodyLoaderLoadingTasksUnfreezableTest,
       SuspendedThenSuspendedForBackForwardCacheThenResume) {
  if (!DeferWithBackForwardCacheEnabled())
    return;
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);
  consumer->Add(Command(Command::kData, "he"));
  body_loader->Start();
  task_runner->RunUntilIdle();
  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // Suspend (not for back-forward cache), then add some data to |consumer|.
  body_loader->Suspend(LoaderFreezeMode::kStrict);
  consumer->Add(Command(Command::kData, "llo"));
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  // Simulate the "readable again" signal.
  consumer->TriggerOnStateChange();
  task_runner->RunUntilIdle();

  // When suspended not for back-forward cache, ResponseBodyLoader won't consume
  // the data.
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // Suspend for back-forward cache, then add some more data to |consumer|.
  body_loader->Suspend(LoaderFreezeMode::kBufferIncoming);
  consumer->Add(Command(Command::kData, "w"));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kData, "o"));

  // ResponseBodyLoader will buffer data when deferred for back-forward cache,
  // but won't notify the client until it's resumed.
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  task_runner->RunUntilIdle();
  EXPECT_TRUE(consumer->IsCommandsEmpty());

  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // The data received while suspended will be processed after resuming, before
  // processing newer data.
  body_loader->Resume();
  consumer->Add(Command(Command::kData, "rld"));
  consumer->Add(Command(Command::kDone));

  task_runner->RunUntilIdle();
  EXPECT_EQ("helloworld", client->GetData());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_P(ResponseBodyLoaderLoadingTasksUnfreezableTest,
       FinishedWhileSuspendedThenSuspendedForBackForwardCacheThenResume) {
  if (!DeferWithBackForwardCacheEnabled())
    return;
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);
  consumer->Add(Command(Command::kData, "he"));
  body_loader->Start();
  task_runner->RunUntilIdle();
  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // Suspend (not for back-forward cache), then add some data to |consumer| with
  // the finish signal at the end.
  body_loader->Suspend(LoaderFreezeMode::kStrict);
  consumer->Add(Command(Command::kData, "llo"));
  consumer->Add(Command(Command::kDone));
  // Simulate the "readable again" signal.
  consumer->TriggerOnStateChange();
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  task_runner->RunUntilIdle();

  // When suspended not for back-forward cache, ResponseBodyLoader won't consume
  // the data, including the finish signal.
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // Suspend for back-forward cache.
  body_loader->Suspend(LoaderFreezeMode::kBufferIncoming);
  // ResponseBodyLoader will buffer data when deferred for back-forward cache,
  // but won't notify the client until it's resumed.
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  task_runner->RunUntilIdle();
  EXPECT_TRUE(consumer->IsCommandsEmpty());

  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // The data received while suspended will be processed after resuming,
  // including the finish signal.
  body_loader->Resume();
  task_runner->RunUntilIdle();
  EXPECT_EQ("hello", client->GetData());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_P(ResponseBodyLoaderLoadingTasksUnfreezableTest,
       SuspendedForBackForwardCacheThenSuspendedThenResume) {
  if (!DeferWithBackForwardCacheEnabled())
    return;
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);
  consumer->Add(Command(Command::kData, "he"));
  body_loader->Start();
  task_runner->RunUntilIdle();

  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // Suspend for back-forward cache, then add some more data to |consumer|.
  body_loader->Suspend(LoaderFreezeMode::kBufferIncoming);
  consumer->Add(Command(Command::kData, "llo"));
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  // Simulate the "readable again" signal.
  consumer->TriggerOnStateChange();

  // ResponseBodyLoader will buffer data  when deferred for back-forward cache,
  // but won't notify the client until it's resumed.
  while (!consumer->IsCommandsEmpty()) {
    task_runner->RunUntilIdle();
  }

  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // Suspend (not for back-forward cache), then add some data to |consumer|.
  body_loader->Suspend(LoaderFreezeMode::kStrict);
  consumer->Add(Command(Command::kData, "w"));
  consumer->Add(Command(Command::kWait));
  consumer->Add(Command(Command::kData, "o"));

  // When suspended not for back-forward cache, ResponseBodyLoader won't consume
  // the data, even with OnStateChange triggered.
  for (int i = 0; i < 3; ++i) {
    consumer->TriggerOnStateChange();
    task_runner->RunUntilIdle();
  }
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  EXPECT_EQ("he", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // The data received while suspended will be processed after resuming, before
  // processing newer data.
  body_loader->Resume();
  consumer->Add(Command(Command::kData, "rld"));
  consumer->Add(Command(Command::kDone));

  task_runner->RunUntilIdle();
  EXPECT_EQ("helloworld", client->GetData());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_P(ResponseBodyLoaderLoadingTasksUnfreezableTest,
       ReadDataFromConsumerWhileSuspendedForBackForwardCacheLong) {
  if (!DeferWithBackForwardCacheEnabled())
    return;
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);
  body_loader->Start();
  task_runner->RunUntilIdle();
  EXPECT_EQ("", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // Suspend, then add a long response body to |consumer|.
  body_loader->Suspend(LoaderFreezeMode::kBufferIncoming);
  std::string body(70000, '*');
  consumer->Add(Command(Command::kDataAndDone, body.c_str()));

  // ResponseBodyLoader will buffer data when deferred, and won't notify the
  // client until it's resumed.
  EXPECT_FALSE(consumer->IsCommandsEmpty());
  // Simulate the "readable" signal.
  consumer->TriggerOnStateChange();
  while (!consumer->IsCommandsEmpty()) {
    task_runner->RunUntilIdle();
  }

  EXPECT_EQ("", client->GetData());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  // The data received while suspended will be processed after resuming.
  body_loader->Resume();
  task_runner->RunUntilIdle();
  EXPECT_EQ(AtomicString(body.c_str()), client->GetData());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

INSTANTIATE_TEST_SUITE_P(All,
                         ResponseBodyLoaderLoadingTasksUnfreezableTest,
                         ::testing::Bool());

TEST_F(ResponseBodyLoaderTest, DrainAsDataPipeAndReportError) {
  mojo::ScopedDataPipeConsumerHandle consumer_end;
  mojo::ScopedDataPipeProducerHandle producer_end;
  auto result = mojo::CreateDataPipe(nullptr, producer_end, consumer_end);

  ASSERT_EQ(result, MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* completion_notifier = nullptr;

  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner, std::move(consumer_end), &completion_notifier);
  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader = MakeResponseBodyLoader(*consumer, *client, task_runner);

  ResponseBodyLoaderClient* client_for_draining = nullptr;
  auto data_pipe = body_loader->DrainAsDataPipe(&client_for_draining);

  ASSERT_TRUE(data_pipe);
  ASSERT_TRUE(client);
  EXPECT_TRUE(body_loader->IsDrained());

  client_for_draining->DidReceiveData(base::span_from_cstring("xyz"));
  client_for_draining->DidReceiveData(base::span_from_cstring("abc"));

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("xyzabc", client->GetData());

  client_for_draining->DidFailLoadingBody();

  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_TRUE(client->LoadingIsFailed());
  EXPECT_EQ("xyzabc", client->GetData());
}

TEST_F(ResponseBodyLoaderTest, DrainAsBytesConsumer) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kData, "he"));
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kData, "l"));
  original_consumer->Add(Command(Command::kData, "lo"));
  original_consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  EXPECT_TRUE(body_loader->IsDrained());
  EXPECT_NE(&consumer, original_consumer);

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(&consumer);

  auto result = reader->Run(task_runner.get());
  EXPECT_EQ(result.first, BytesConsumer::Result::kDone);
  EXPECT_EQ(String(result.second), "hello");
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("hello", client->GetData());
}

TEST_F(ResponseBodyLoaderTest, CancelDrainedBytesConsumer) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kData, "he"));
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kData, "llo"));
  original_consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  EXPECT_TRUE(body_loader->IsDrained());
  EXPECT_NE(&consumer, original_consumer);
  consumer.Cancel();

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(&consumer);

  auto result = reader->Run(task_runner.get());
  EXPECT_EQ(result.first, BytesConsumer::Result::kDone);
  EXPECT_EQ(String(result.second), String());

  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();

  EXPECT_TRUE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderTest, AbortDrainAsBytesConsumerWhileLoading) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kData, "hello"));
  original_consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();
  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);
  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer.GetPublicState());

  body_loader->Abort();
  EXPECT_EQ(PublicState::kErrored, consumer.GetPublicState());
  EXPECT_EQ("Response body loading was aborted", consumer.GetError().Message());
}

TEST_F(ResponseBodyLoaderTest, DrainAsBytesConsumerWithError) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kData, "he"));
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kData, "llo"));
  original_consumer->Add(Command(Command::kError));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  EXPECT_TRUE(body_loader->IsDrained());
  EXPECT_NE(&consumer, original_consumer);

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(&consumer);

  auto result = reader->Run(task_runner.get());
  EXPECT_EQ(result.first, BytesConsumer::Result::kError);
  EXPECT_EQ(String(result.second), "hello");
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_TRUE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderTest, AbortAfterBytesConsumerIsDrained) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kData, "he"));
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kData, "llo"));
  original_consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();
  auto* bytes_consumer_client =
      MakeGarbageCollected<ReadingClient>(consumer, *client);
  consumer.SetClient(bytes_consumer_client);

  EXPECT_TRUE(body_loader->IsDrained());
  EXPECT_NE(&consumer, original_consumer);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer.GetPublicState());
  EXPECT_FALSE(bytes_consumer_client->IsOnStateChangeCalled());
  body_loader->Abort();
  EXPECT_EQ(PublicState::kErrored, consumer.GetPublicState());
  EXPECT_TRUE(bytes_consumer_client->IsOnStateChangeCalled());

  task_runner->RunUntilIdle();

  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderTest, AbortAfterBytesConsumerIsDrainedIsNotified) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_load
"""


```