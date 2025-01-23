Response: Let's break down the thought process for analyzing this C++ unit test file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `mime_sniffing_throttle_unittest.cc`. This involves identifying the code being tested (the "system under test" or SUT) and what aspects of its behavior are being verified.

**2. Identifying the System Under Test (SUT):**

The `#include` directives at the beginning of the file are crucial. The line `#include "third_party/blink/public/common/loader/mime_sniffing_throttle.h"` immediately tells us that the core component being tested is the `MimeSniffingThrottle` class.

**3. Analyzing the Test Structure:**

Unit test files typically follow a pattern:

* **Setup:** Creating necessary objects and configuring their initial state.
* **Action:**  Calling the methods of the SUT that are being tested.
* **Assertion:** Verifying that the SUT behaved as expected.

The `MimeSniffingThrottleTest` class, inheriting from `testing::Test`, sets up the basic testing environment. Each `TEST_F` function represents an individual test case.

**4. Examining Individual Test Cases (Key Insight Generation):**

Now, we go through each `TEST_F` function and ask:

* **What scenario is being tested?**  Look at the test function name and the setup within the test. For example, `NoMimeTypeWithSniffableScheme` suggests a scenario where the response lacks a MIME type and the URL scheme allows sniffing.
* **What inputs are being provided to the SUT?** Pay attention to how the `MimeSniffingThrottle`'s methods are called (specifically `WillProcessResponse`) and what data is passed in (like the `GURL` and `URLResponseHead`).
* **What is the expected behavior?**  Look at the `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_EQ` assertions. These directly state the expected outcome. For instance, `EXPECT_TRUE(defer)` in `NoMimeTypeWithSniffableScheme` means the throttle is expected to defer processing.
* **How does the `MockDelegate` interact?** The `MockDelegate` plays a crucial role in simulating the environment the `MimeSniffingThrottle` operates in. Its methods (`is_intercepted`, `is_resumed`, `destination_loader_client()->response_head()->mime_type`) are used to verify the throttle's effects.

**5. Connecting to Web Concepts (JavaScript, HTML, CSS):**

Once we understand the core functionality of the throttle (deciding whether to sniff and potentially modifying the MIME type), we can connect this to how web browsers handle resources:

* **MIME Type Importance:** Recall that the MIME type informs the browser how to interpret a resource (e.g., execute as JavaScript, render as HTML, apply as CSS).
* **Mime Sniffing:** Remember that browsers sometimes try to *guess* the MIME type if it's missing or incorrect. This can be necessary for compatibility but also introduces security risks.
* **JavaScript Execution:** If a resource is mistakenly identified as JavaScript, the browser will try to execute it, potentially leading to errors or security vulnerabilities.
* **HTML Rendering:**  Incorrect MIME types can prevent HTML from being rendered correctly.
* **CSS Styling:** Similarly, incorrect MIME types for CSS files will prevent styling from being applied.

**6. Identifying Logical Inferences and Assumptions:**

The tests implicitly make assumptions:

* **Sniffable Schemes:** The tests assume that "https://" is a sniffable scheme and "wss://" is not.
* **Sniffable MIME Types:** The tests implicitly know which MIME types are considered "sniffable" (like `text/plain`) and which are not (like `text/javascript`).
* **Default MIME Type:** The test `EmptyBody` demonstrates the assumption that the default MIME type when sniffing fails or the body is empty is "text/plain".

**7. Recognizing Common Usage Errors (From the Tests):**

The tests also highlight potential problems:

* **Missing MIME Type:** The `NoMimeTypeWithSniffableScheme` test shows the throttle's behavior when the server doesn't provide a MIME type.
* **Incorrect MIME Type:** While not explicitly tested, the *purpose* of mime sniffing implies that the server might send an incorrect MIME type, which the throttle aims to correct.
* **Empty or Incomplete Responses:** The `NoBody` and `EmptyBody` tests address how the throttle handles cases where the response body is missing or empty.

**8. Structuring the Output:**

Finally, organize the findings into the requested categories: functionality, relation to web technologies, logical inferences, and common usage errors. Provide concrete examples to illustrate each point, drawing directly from the test code and web development knowledge. Use clear and concise language.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This file just tests mime sniffing."
* **Refinement:** "It tests the `MimeSniffingThrottle` class specifically. It doesn't perform the actual sniffing, but rather decides *whether* to sniff and how to handle the results."
* **Further refinement:** "The `MockDelegate` is crucial. It simulates the interaction with the network layer and the client receiving the response. The tests focus on the throttle's decisions (deferring, intercepting) and how it updates the response."

By following these steps and iteratively refining our understanding, we arrive at a comprehensive explanation of the unit test file's purpose and implications.
这个文件 `mime_sniffing_throttle_unittest.cc` 是 Chromium Blink 引擎中 `MimeSniffingThrottle` 类的单元测试文件。单元测试的目的是验证代码的特定部分（这里是 `MimeSniffingThrottle` 类）是否按照预期工作。

以下是该文件的功能分解：

**1. 测试 `MimeSniffingThrottle` 的基本行为:**

   - **根据 URL 协议头（scheme）和响应头信息判断是否需要进行 MIME 类型嗅探:**
     -  `MimeSniffingThrottle` 的主要功能是决定是否需要对下载的资源内容进行 MIME 类型嗅探。
     -  测试用例覆盖了各种情况：
         -   **可嗅探的协议头 (e.g., `https://`)：**
             -   `NoMimeTypeWithSniffableScheme`:  如果响应头没有 MIME 类型，应该触发嗅探。
             -   `SniffableMimeTypeWithSniffableScheme`:  如果响应头有可能是需要嗅探的 MIME 类型 (e.g., `text/plain`)，应该触发嗅探。
             -   `NotSniffableMimeTypeWithSniffableScheme`: 如果响应头已经明确指定了不需要嗅探的 MIME 类型 (e.g., `text/javascript`)，则不应该触发嗅探。
         -   **不可嗅探的协议头 (e.g., `wss://`)：**
             -   `NoMimeTypeWithNotSniffableScheme`, `SniffableMimeTypeWithNotSniffableScheme`, `NotSniffableMimeTypeWithNotSniffableScheme`:  对于这些情况，即使 MIME 类型可能需要嗅探，也不应该触发嗅探，因为协议本身不建议或不允许嗅探。
         -   **已经嗅探过的情况:**
             -   `SniffableButAlreadySniffed`: 如果响应头已经标记为 `did_mime_sniff = true`，则不应该再次触发嗅探。

   - **在需要嗅探时，拦截响应并准备进行嗅探:**
     -  当 `MimeSniffingThrottle` 判断需要嗅探时，它会通知其委托对象 (`MockDelegate`) 进行拦截。
     -  `MockDelegate` 模拟了网络加载器的行为，用于测试 `MimeSniffingThrottle` 与网络加载流程的交互。
     -  拦截涉及到创建一个新的 `URLLoader` 和 `URLLoaderClient` 用于嗅探，并将原始的加载器和客户端连接到新的加载器。

**2. 测试 `MimeSniffingThrottle` 如何处理响应体:**

   - **接收响应体数据并进行 MIME 类型判断:**
     -  测试用例模拟了接收不同内容的响应体，并验证 `MimeSniffingThrottle` 是否能正确识别 MIME 类型。
     -  `Body_PlainText`: 测试识别纯文本。
     -  `Body_Docx`: 测试识别 Microsoft Word 文档 (通过文件头魔数)。
     -  `Body_PNG`: 测试识别 PNG 图片 (通过文件头魔数)。
     -  `Body_LongPlainText`: 测试处理较长的响应体，确保数据管道的正确处理。

   - **更新响应头中的 MIME 类型:**
     -  如果嗅探成功，`MimeSniffingThrottle` 会更新 `URLResponseHead` 中的 `mime_type` 字段。
     -  `MockDelegate` 会在 `Resume()` 方法中模拟更新响应头并继续请求处理。

   - **处理没有响应体或空响应体的情况:**
     -  `NoBody`: 测试当没有响应体时，MIME 类型是否会设置为默认值 (`text/plain`)。
     -  `EmptyBody`: 测试当响应体为空时，MIME 类型是否会设置为默认值 (`text/plain`)。

**3. 测试 `MimeSniffingThrottle` 的边缘情况和错误处理:**

   - **中断加载:**
     -  `Abort_NoBodyPipe`: 测试当响应体的数据管道在接收端被关闭时，`MimeSniffingThrottle` 的行为，确保不会崩溃。

**与 JavaScript, HTML, CSS 的关系:**

`MimeSniffingThrottle` 的功能直接关系到浏览器如何处理 JavaScript, HTML, 和 CSS 等 Web 资源。

* **JavaScript:**
    - **例子：** 假设服务器错误地将一个 JavaScript 文件标记为 `text/plain`。`MimeSniffingThrottle` 会嗅探文件内容，识别出它是 JavaScript，并将 MIME 类型更新为 `application/javascript`（或类似的 JavaScript MIME 类型）。这确保了浏览器会将该文件作为脚本执行，而不是显示为纯文本。
    - **假设输入与输出：**
        - **假设输入：**  `URLResponseHead` 的 `mime_type` 为 "text/plain"，响应体内容以 `// JavaScript code` 开头。
        - **预期输出：** `MimeSniffingThrottle` 拦截响应，读取响应体，识别出是 JavaScript，并通过 `MockDelegate` 更新 `URLResponseHead` 的 `mime_type` 为 "application/javascript"。

* **HTML:**
    - **例子：** 假设服务器没有设置 HTML 文件的 MIME 类型。`MimeSniffingThrottle` 会嗅探文件内容，识别出它是 HTML（通常通过 `<!DOCTYPE html>` 声明），并将 MIME 类型设置为 `text/html`。这确保了浏览器会将该文件渲染为网页。
    - **假设输入与输出：**
        - **假设输入：** `URLResponseHead` 的 `mime_type` 为空，响应体内容以 `<!DOCTYPE html>` 开头。
        - **预期输出：** `MimeSniffingThrottle` 拦截响应，读取响应体，识别出是 HTML，并通过 `MockDelegate` 更新 `URLResponseHead` 的 `mime_type` 为 "text/html"。

* **CSS:**
    - **例子：** 假设服务器错误地将一个 CSS 文件标记为 `text/plain`。`MimeSniffingThrottle` 会嗅探文件内容，识别出它是 CSS（通常通过 `@charset` 声明或 CSS 语法），并将 MIME 类型更新为 `text/css`. 这确保了浏览器会将该文件作为样式表应用到页面上。
    - **假设输入与输出：**
        - **假设输入：** `URLResponseHead` 的 `mime_type` 为 "text/plain"，响应体内容以 `body { ... }` 开头。
        - **预期输出：** `MimeSniffingThrottle` 拦截响应，读取响应体，识别出是 CSS，并通过 `MockDelegate` 更新 `URLResponseHead` 的 `mime_type` 为 "text/css"。

**用户或编程常见的使用错误举例:**

* **服务器配置错误导致 MIME 类型不正确:** 这是 `MimeSniffingThrottle` 要解决的主要问题。开发者可能会错误地配置 Web 服务器，导致发送的资源的 MIME 类型不正确。例如，将所有的静态文件都设置为 `text/plain`。`MimeSniffingThrottle` 可以纠正这些错误，提升用户体验。

* **缺少 MIME 类型:**  服务器可能没有为某些资源设置 MIME 类型。对于可嗅探的协议，`MimeSniffingThrottle` 会尝试通过内容来猜测其类型。

* **使用不允许嗅探的协议加载需要嗅探的内容:**  例如，通过 `file://` 协议加载本地 HTML 文件，可能不会触发嗅探（取决于具体的浏览器实现）。如果开发者依赖嗅探来处理这种情况，可能会遇到问题。

* **混淆文件扩展名和实际内容:**  开发者可能会错误地认为文件扩展名决定了 MIME 类型。例如，一个扩展名为 `.txt` 的文件可能包含 HTML 内容。`MimeSniffingThrottle` 会根据实际内容进行判断，而不是仅仅依赖文件扩展名。

总而言之，`mime_sniffing_throttle_unittest.cc` 通过各种测试用例，确保 `MimeSniffingThrottle` 能够正确地判断是否需要进行 MIME 类型嗅探，并在需要时拦截响应并根据内容更新 MIME 类型，从而保证浏览器能够正确地处理各种 Web 资源，包括 JavaScript, HTML 和 CSS。它也测试了在各种边界情况下的健壮性。

### 提示词
```
这是目录为blink/common/loader/mime_sniffing_throttle_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/loader/mime_sniffing_throttle.h"

#include <memory>
#include <string_view>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/test/task_environment.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "services/network/test/test_url_loader_client.h"
#include "services/network/test/test_url_loader_factory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/loader/mime_sniffing_url_loader.h"
#include "third_party/blink/public/common/loader/url_loader_throttle.h"
#include "url/gurl.h"

namespace blink {

namespace {

class MojoDataPipeSender {
 public:
  MojoDataPipeSender(mojo::ScopedDataPipeProducerHandle handle)
      : handle_(std::move(handle)),
        watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::AUTOMATIC) {}

  void Start(std::string data, base::OnceClosure done_callback) {
    data_ = std::move(data);
    done_callback_ = std::move(done_callback);
    watcher_.Watch(handle_.get(),
                   MOJO_HANDLE_SIGNAL_WRITABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
                   base::BindRepeating(&MojoDataPipeSender::OnWritable,
                                       base::Unretained(this)));
  }

  void OnWritable(MojoResult) {
    base::span<const uint8_t> bytes = base::as_byte_span(data_);
    bytes = bytes.subspan(sent_bytes_);
    size_t actually_written_bytes = 0;
    MojoResult result = handle_->WriteData(bytes, MOJO_WRITE_DATA_FLAG_NONE,
                                           actually_written_bytes);
    switch (result) {
      case MOJO_RESULT_OK:
        break;
      case MOJO_RESULT_FAILED_PRECONDITION:
        // Finished unexpectedly.
        std::move(done_callback_).Run();
        return;
      case MOJO_RESULT_SHOULD_WAIT:
        // Just wait until OnWritable() is called by the watcher.
        return;
      default:
        NOTREACHED();
    }
    sent_bytes_ += actually_written_bytes;
    if (data_.size() == sent_bytes_)
      std::move(done_callback_).Run();
  }

  mojo::ScopedDataPipeProducerHandle ReleaseHandle() {
    return std::move(handle_);
  }

  bool has_succeeded() const { return data_.size() == sent_bytes_; }

 private:
  mojo::ScopedDataPipeProducerHandle handle_;
  mojo::SimpleWatcher watcher_;
  base::OnceClosure done_callback_;
  std::string data_;
  size_t sent_bytes_ = 0;
};

class MockDelegate : public blink::URLLoaderThrottle::Delegate {
 public:
  // Implements blink::URLLoaderThrottle::Delegate.
  void CancelWithError(int error_code,
                       std::string_view custom_reason) override {
    NOTIMPLEMENTED();
  }
  void Resume() override {
    is_resumed_ = true;
    // Resume from OnReceiveResponse() with a customized response header.
    destination_loader_client()->OnReceiveResponse(
        std::move(updated_response_head_), std::move(body_), std::nullopt);
  }

  void UpdateDeferredResponseHead(
      network::mojom::URLResponseHeadPtr new_response_head,
      mojo::ScopedDataPipeConsumerHandle body) override {
    updated_response_head_ = std::move(new_response_head);
    body_ = std::move(body);
  }
  void InterceptResponse(
      mojo::PendingRemote<network::mojom::URLLoader> new_loader,
      mojo::PendingReceiver<network::mojom::URLLoaderClient>
          new_client_receiver,
      mojo::PendingRemote<network::mojom::URLLoader>* original_loader,
      mojo::PendingReceiver<network::mojom::URLLoaderClient>*
          original_client_receiver,
      mojo::ScopedDataPipeConsumerHandle* body) override {
    is_intercepted_ = true;

    destination_loader_remote_.Bind(std::move(new_loader));
    ASSERT_TRUE(
        mojo::FusePipes(std::move(new_client_receiver),
                        mojo::PendingRemote<network::mojom::URLLoaderClient>(
                            destination_loader_client_.CreateRemote())));
    pending_receiver_ = original_loader->InitWithNewPipeAndPassReceiver();

    *original_client_receiver =
        source_loader_client_remote_.BindNewPipeAndPassReceiver();

    if (no_body_)
      return;

    DCHECK(!source_body_handle_);
    mojo::ScopedDataPipeConsumerHandle consumer;
    EXPECT_EQ(MOJO_RESULT_OK,
              mojo::CreateDataPipe(nullptr, source_body_handle_, consumer));
    *body = std::move(consumer);
  }

  void LoadResponseBody(const std::string& body) {
    MojoDataPipeSender sender(std::move(source_body_handle_));
    base::RunLoop loop;
    sender.Start(body, loop.QuitClosure());
    loop.Run();

    EXPECT_TRUE(sender.has_succeeded());
    source_body_handle_ = sender.ReleaseHandle();
  }

  void CompleteResponse() {
    source_loader_client_remote()->OnComplete(
        network::URLLoaderCompletionStatus());
    source_body_handle_.reset();
  }

  uint32_t ReadResponseBody(size_t size) {
    std::vector<uint8_t> buffer(size);
    MojoResult result = destination_loader_client_.response_body().ReadData(
        MOJO_READ_DATA_FLAG_NONE, buffer, size);
    switch (result) {
      case MOJO_RESULT_OK:
        return size;
      case MOJO_RESULT_FAILED_PRECONDITION:
        return 0;
      case MOJO_RESULT_SHOULD_WAIT:
        return 0;
      default:
        NOTREACHED();
    }
  }

  void ResetProducer() { source_body_handle_.reset(); }

  bool is_intercepted() const { return is_intercepted_; }
  bool is_resumed() const { return is_resumed_; }
  void set_no_body() { no_body_ = true; }

  network::TestURLLoaderClient* destination_loader_client() {
    return &destination_loader_client_;
  }

  mojo::Remote<network::mojom::URLLoaderClient>& source_loader_client_remote() {
    return source_loader_client_remote_;
  }

 private:
  bool is_intercepted_ = false;
  bool is_resumed_ = false;
  bool no_body_ = false;
  network::mojom::URLResponseHeadPtr updated_response_head_;
  mojo::ScopedDataPipeConsumerHandle body_;

  // A pair of a loader and a loader client for destination of the response.
  mojo::Remote<network::mojom::URLLoader> destination_loader_remote_;
  network::TestURLLoaderClient destination_loader_client_;

  // A pair of a receiver and a remote for source of the response.
  mojo::PendingReceiver<network::mojom::URLLoader> pending_receiver_;
  mojo::Remote<network::mojom::URLLoaderClient> source_loader_client_remote_;

  mojo::ScopedDataPipeProducerHandle source_body_handle_;
};

}  // namespace

class MimeSniffingThrottleTest : public testing::Test {
 protected:
  // Be the first member so it is destroyed last.
  base::test::TaskEnvironment task_environment_;
};

TEST_F(MimeSniffingThrottleTest, NoMimeTypeWithSniffableScheme) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(GURL("https://example.com"),
                                response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());
}

TEST_F(MimeSniffingThrottleTest, SniffableMimeTypeWithSniffableScheme) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  auto response_head = network::mojom::URLResponseHead::New();
  response_head->mime_type = "text/plain";
  bool defer = false;
  throttle->WillProcessResponse(GURL("https://example.com"),
                                response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());
}

TEST_F(MimeSniffingThrottleTest, NotSniffableMimeTypeWithSniffableScheme) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  auto response_head = network::mojom::URLResponseHead::New();
  response_head->mime_type = "text/javascript";
  bool defer = false;
  throttle->WillProcessResponse(GURL("https://example.com"),
                                response_head.get(), &defer);
  EXPECT_FALSE(defer);
  EXPECT_FALSE(delegate->is_intercepted());
}

TEST_F(MimeSniffingThrottleTest, NoMimeTypeWithNotSniffableScheme) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(GURL("wss://example.com"), response_head.get(),
                                &defer);
  EXPECT_FALSE(defer);
  EXPECT_FALSE(delegate->is_intercepted());
}

TEST_F(MimeSniffingThrottleTest, SniffableMimeTypeWithNotSniffableScheme) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  auto response_head = network::mojom::URLResponseHead::New();
  response_head->mime_type = "text/plain";
  bool defer = false;
  throttle->WillProcessResponse(GURL("wss://example.com"), response_head.get(),
                                &defer);
  EXPECT_FALSE(defer);
  EXPECT_FALSE(delegate->is_intercepted());
}

TEST_F(MimeSniffingThrottleTest, NotSniffableMimeTypeWithNotSniffableScheme) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  auto response_head = network::mojom::URLResponseHead::New();
  response_head->mime_type = "text/javascript";
  bool defer = false;
  throttle->WillProcessResponse(GURL("wss://example.com"), response_head.get(),
                                &defer);
  EXPECT_FALSE(defer);
  EXPECT_FALSE(delegate->is_intercepted());
}

TEST_F(MimeSniffingThrottleTest, SniffableButAlreadySniffed) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  auto response_head = network::mojom::URLResponseHead::New();
  response_head->mime_type = "text/plain";
  response_head->did_mime_sniff = true;
  bool defer = false;
  throttle->WillProcessResponse(GURL("https://example.com"),
                                response_head.get(), &defer);
  EXPECT_FALSE(defer);
  EXPECT_FALSE(delegate->is_intercepted());
}

TEST_F(MimeSniffingThrottleTest, NoBody) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  GURL response_url("https://example.com");
  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  delegate->set_no_body();
  throttle->WillProcessResponse(response_url, response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());

  // Call OnComplete() without sending body.
  delegate->source_loader_client_remote()->OnComplete(
      network::URLLoaderCompletionStatus(net::ERR_FAILED));
  delegate->destination_loader_client()->RunUntilComplete();

  // The mime type should be updated to the default mime type ("text/plain").
  EXPECT_TRUE(delegate->destination_loader_client()->has_received_response());
  EXPECT_EQ("text/plain",
            delegate->destination_loader_client()->response_head()->mime_type);
}

TEST_F(MimeSniffingThrottleTest, EmptyBody) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  GURL response_url("https://example.com");
  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(response_url, response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());

  delegate->ResetProducer();

  delegate->source_loader_client_remote()->OnComplete(
      network::URLLoaderCompletionStatus());
  delegate->destination_loader_client()->RunUntilComplete();

  // The mime type should be updated to the default mime type ("text/plain").
  EXPECT_TRUE(delegate->destination_loader_client()->has_received_response());
  EXPECT_EQ("text/plain",
            delegate->destination_loader_client()->response_head()->mime_type);
}

TEST_F(MimeSniffingThrottleTest, Body_PlainText) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  GURL response_url("https://example.com");
  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(response_url, response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());

  // Send the body and complete the response.
  delegate->LoadResponseBody("This is a text.");
  delegate->CompleteResponse();
  delegate->destination_loader_client()->RunUntilComplete();

  // The mime type should be updated.
  EXPECT_TRUE(delegate->is_resumed());
  EXPECT_EQ("text/plain",
            delegate->destination_loader_client()->response_head()->mime_type);
}

TEST_F(MimeSniffingThrottleTest, Body_Docx) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  GURL response_url("https://example.com/hogehoge.docx");
  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(response_url, response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());

  // Send the body and complete the response.
  delegate->LoadResponseBody("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
  delegate->CompleteResponse();
  delegate->destination_loader_client()->RunUntilComplete();

  // The mime type should be updated.
  EXPECT_TRUE(delegate->is_resumed());
  EXPECT_EQ("application/msword",
            delegate->destination_loader_client()->response_head()->mime_type);
}

TEST_F(MimeSniffingThrottleTest, Body_PNG) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  GURL response_url("https://example.com/hogehoge.docx");
  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(response_url, response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());

  // Send the body and complete the response.
  delegate->LoadResponseBody("\x89PNG\x0D\x0A\x1A\x0A");
  delegate->CompleteResponse();
  delegate->destination_loader_client()->RunUntilComplete();

  // The mime type should be updated.
  EXPECT_TRUE(delegate->is_resumed());
  EXPECT_EQ("image/png",
            delegate->destination_loader_client()->response_head()->mime_type);
}

TEST_F(MimeSniffingThrottleTest, Body_LongPlainText) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  GURL response_url("https://example.com");
  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(response_url, response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());

  // 64KiB is coming from the default value used in
  // mojo::core::Core::CreateDataPipe().
  const uint32_t kDefaultDataPipeBufferSize = 64 * 1024;
  std::string long_body(kDefaultDataPipeBufferSize * 2, 'x');

  // Send the data to the MimeSniffingURLLoader.
  // |delegate|'s MojoDataPipeSender sends the first
  // |kDefaultDataPipeBufferSize| bytes to MimeSniffingURLLoader and
  // MimeSniffingURLLoader will read the first |kDefaultDataPipeBufferSize|
  // bytes of the body, so the MojoDataPipeSender can push the rest of
  // |kDefaultDataPipeBufferSize| of the body soon and finishes sending the
  // body. After this, MimeSniffingURLLoader is waiting to push the body to the
  // destination data pipe since the pipe should be full until it's read.
  delegate->LoadResponseBody(long_body);
  task_environment_.RunUntilIdle();

  // Send OnComplete() to the MimeSniffingURLLoader.
  delegate->CompleteResponse();
  task_environment_.RunUntilIdle();
  // MimeSniffingURLLoader should not send OnComplete() to the destination
  // client until it finished writing all the data.
  EXPECT_FALSE(
      delegate->destination_loader_client()->has_received_completion());

  // Read the half of the body. This unblocks MimeSniffingURLLoader to push the
  // rest of the body to the data pipe.
  uint32_t read_bytes = delegate->ReadResponseBody(long_body.size() / 2);
  task_environment_.RunUntilIdle();

  // Read the rest of the body.
  read_bytes += delegate->ReadResponseBody(long_body.size() / 2);
  task_environment_.RunUntilIdle();
  delegate->destination_loader_client()->RunUntilComplete();

  // Check if all data has been read.
  EXPECT_EQ(long_body.size(), read_bytes);

  // The mime type should be updated.
  EXPECT_TRUE(delegate->is_resumed());
  EXPECT_EQ("text/plain",
            delegate->destination_loader_client()->response_head()->mime_type);
}

TEST_F(MimeSniffingThrottleTest, Abort_NoBodyPipe) {
  auto throttle = std::make_unique<MimeSniffingThrottle>(
      task_environment_.GetMainThreadTaskRunner());
  auto delegate = std::make_unique<MockDelegate>();
  throttle->set_delegate(delegate.get());

  GURL response_url("https://example.com");
  auto response_head = network::mojom::URLResponseHead::New();
  bool defer = false;
  throttle->WillProcessResponse(response_url, response_head.get(), &defer);
  EXPECT_TRUE(defer);
  EXPECT_TRUE(delegate->is_intercepted());

  // Send the body
  std::string body = "This should be long enough to complete sniffing.";
  body.resize(1024, 'a');
  delegate->LoadResponseBody(body);
  task_environment_.RunUntilIdle();

  // Release a pipe for the body on the receiver side.
  delegate->destination_loader_client()->response_body_release();
  task_environment_.RunUntilIdle();

  // Calling OnComplete should not crash.
  delegate->CompleteResponse();
  task_environment_.RunUntilIdle();
}

}  // namespace blink
```