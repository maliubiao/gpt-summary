Response: Let's break down the thought process for analyzing this C++ code.

1. **Understand the Purpose:** The filename `mime_sniffing_url_loader.cc` immediately suggests this component is involved in determining the MIME type of a resource being loaded over the network. The "URL Loader" part indicates it's within the network loading pipeline. The "blink" namespace confirms it's part of the rendering engine of Chromium.

2. **Identify Key Components:**  Scan the code for important classes, methods, and data members.

    * **Class `MimeSniffingURLLoader`:** This is the central actor. It implements the `network::mojom::URLLoader` interface, which means it participates in the standard network request/response flow.
    * **`MimeSniffingThrottle`:**  The code interacts with a `MimeSniffingThrottle`. This suggests a higher-level component controls *when* and *why* MIME sniffing occurs. The `WillProcessResponse` method mentioned in comments reinforces this.
    * **`network::mojom::URLLoader`, `network::mojom::URLLoaderClient`:** These are Mojo interfaces for the network loading process. The `MimeSniffingURLLoader` acts as an intermediary between a source loader and a destination client.
    * **`mojo::ScopedDataPipeConsumerHandle`, `mojo::ScopedDataPipeProducerHandle`:**  These are used for transferring the response body efficiently using Mojo data pipes.
    * **`net::MimeSniffer`:**  This is the core logic for actually sniffing the content.
    * **`base::WeakPtr`:**  Used for the `throttle_`, indicating the `MimeSniffingURLLoader` doesn't own the `MimeSniffingThrottle` and needs to handle potential invalidation.
    * **State Machine (`enum class State`):**  The code uses a state machine to manage the different stages of the sniffing process.
    * **Callbacks (`base::BindRepeating`):** Callbacks are used for asynchronous operations related to data pipe readability/writability.

3. **Trace the Data Flow:** How does the data move through this component?

    * A source `URLLoader` provides the response body as a `mojo::ScopedDataPipeConsumerHandle`.
    * `MimeSniffingURLLoader` reads chunks of data from this consumer handle into `buffered_body_`.
    * `net::SniffMimeType` is called on the buffered data to determine the MIME type.
    * Once sniffing is complete, a new data pipe is created.
    * The buffered data is written to the producer end of the new pipe.
    * Subsequent data from the original consumer is forwarded to the new producer.
    * The destination `URLLoaderClient` receives the potentially modified response head and the new data pipe.

4. **Analyze Key Methods:** Understand the purpose of the important methods.

    * **`CreateLoader`:**  Static factory method to create and connect the loader.
    * **Constructor:** Initializes the loader with necessary dependencies.
    * **`Start`:**  Starts the sniffing process by binding to the source loader and setting up the data pipe watcher.
    * **`OnBodyReadable`:**  Reads data from the source data pipe and performs MIME sniffing.
    * **`CompleteSniffing`:**  Called when enough data is sniffed to make a decision (or the body ends). Creates the new data pipe and resumes the loading process with the potentially updated MIME type.
    * **`OnBodyWritable`:** Handles writing data to the destination data pipe.
    * **`SendReceivedBodyToClient`:** Writes the buffered data to the destination.
    * **`ForwardBodyToClient`:**  Forwards data directly from the source consumer to the destination producer.
    * **`OnComplete`:** Handles the completion of the loading process.
    * **The other `On...` methods (e.g., `OnReceiveRedirect`, `OnReceiveResponse`):**  The comments clearly indicate these should not be called directly on this loader, reinforcing its role as an intermediary.

5. **Identify Interactions with Web Technologies:**  How does this relate to JavaScript, HTML, and CSS?

    * **MIME Type Importance:** The core function is determining the correct MIME type. This is critical for browsers to interpret resources correctly.
    * **HTML:** Incorrectly sniffing HTML could lead to security issues (e.g., a malicious file being treated as HTML).
    * **JavaScript:**  Incorrectly sniffing JavaScript could prevent scripts from executing or cause errors.
    * **CSS:** Incorrectly sniffing CSS could lead to styling issues or prevent stylesheets from being applied.

6. **Consider Edge Cases and Error Handling:**

    * **Incomplete Body:** The code handles cases where the body ends before enough data is sniffed.
    * **Mojo Pipe Errors:** The code checks the results of Mojo pipe operations and handles errors (e.g., pipe closed unexpectedly).
    * **Aborting:**  The `Abort` method provides a way to stop the process.

7. **Formulate the Explanation:**  Organize the findings into a clear and concise explanation, covering:

    * Core functionality
    * Relationship to web technologies (with examples)
    * Logic and assumptions (input/output scenarios)
    * Potential user/programming errors

8. **Review and Refine:**  Check for accuracy, clarity, and completeness. Ensure the examples are relevant and easy to understand. Make sure the assumptions and potential errors are well-explained. For example, initially, I might have just said "handles errors," but refining it means specifying *what kind* of errors (Mojo pipe errors).

This systematic approach helps to dissect the code, understand its purpose within the larger system, and identify its interactions with other components and web technologies. The focus on data flow, key methods, and error handling is crucial for a comprehensive analysis.
`blink/common/loader/mime_sniffing_url_loader.cc` 文件是 Chromium Blink 引擎中的一个源代码文件，其主要功能是 **在网络加载过程中对资源的 MIME 类型进行嗅探 (sniffing)**。 它作为一个中间层 URLLoader，拦截原始的响应，读取一部分响应体数据，并使用这些数据来更准确地判断资源的 MIME 类型，尤其是在服务器返回的 `Content-Type` 头部不正确或缺失的情况下。

以下是该文件功能的详细说明，并结合与 JavaScript, HTML, CSS 的关系进行举例：

**主要功能:**

1. **MIME 类型嗅探:**
   - 该类实现了 `network::mojom::URLLoader` 接口，用于处理网络请求的响应。
   - 它接收上游 URLLoader 提供的响应头和响应体数据流。
   - 它会读取响应体的前一部分数据（最多 `net::kMaxBytesToSniff` 字节）。
   - 它使用 `net::SniffMimeType` 函数，根据读取到的数据以及服务器返回的 MIME 类型进行判断，得出更准确的 MIME 类型。
   - 更新后的 MIME 类型会保存在 `response_head_` 中。

2. **作为中间层代理:**
   - `MimeSniffingURLLoader` 位于原始 URLLoader 和最终的 URLLoaderClient 之间。
   - 它接收来自原始 URLLoader 的数据，进行 MIME 嗅探，然后将修改后的响应头和响应体数据转发给下游的 `destination_url_loader_client_`。

3. **处理数据管道 (DataPipe):**
   - 它使用 Mojo 的 `DataPipe` 机制来高效地处理响应体数据流。
   - 它从上游的 `body_consumer_handle_` 读取数据，并将数据写入到下游的 `body_producer_handle_`。

4. **状态管理:**
   - 它使用一个状态机 (`enum class State`) 来管理 MIME 嗅探过程的不同阶段，例如 `kSniffing` (嗅探中), `kSending` (发送数据), `kCompleted` (完成)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

MIME 类型对于浏览器如何处理资源至关重要。`MimeSniffingURLLoader` 的功能直接影响到 JavaScript, HTML, CSS 资源的加载和解析：

* **HTML:**
    - **场景:** 假设服务器错误地将一个 HTML 文件标记为 `text/plain`。
    - **`MimeSniffingURLLoader` 的作用:**  它会读取文件的前几个字节，识别出 HTML 的标签 (`<!DOCTYPE html>`, `<html>` 等)，并将其 MIME 类型修正为 `text/html`。
    - **影响:** 如果没有 MIME 嗅探，浏览器可能会将该文件当作纯文本显示，导致网页结构无法解析，JavaScript 和 CSS 也无法执行和应用。

* **JavaScript:**
    - **场景:** 假设服务器返回的 JavaScript 文件的 `Content-Type` 头部缺失。
    - **`MimeSniffingURLLoader` 的作用:** 它会检查文件内容，如果发现类似 `function() { ... }` 或者 `var x = ...` 的 JavaScript 代码结构，则会推断出 MIME 类型为 `text/javascript` 或 `application/javascript`。
    - **影响:** 如果 MIME 类型未正确识别，浏览器可能不会将其作为 JavaScript 执行，导致网页功能失效。

* **CSS:**
    - **场景:** 假设服务器将一个 CSS 文件错误地标记为 `application/octet-stream`。
    - **`MimeSniffingURLLoader` 的作用:** 它会读取文件内容，如果发现 CSS 语法，例如选择器 (`body { ... }`, `.class { ... }`) 和属性，则会将其 MIME 类型修正为 `text/css`。
    - **影响:** 如果 MIME 类型错误，浏览器可能不会将该文件作为样式表处理，导致网页样式丢失。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **服务器响应头:**
   ```
   HTTP/1.1 200 OK
   Content-Type: application/octet-stream
   ```
2. **响应体数据 (前 20 个字节):**
   ```
   <!DOCTYPE html>
   <html>
   <head>
   ```
3. **`response_url_`:** `https://example.com/page.dat`

**逻辑推理过程:**

1. `MimeSniffingURLLoader` 的 `Start` 方法被调用，开始读取响应体数据。
2. `OnBodyReadable` 方法被调用，读取最多 `net::kMaxBytesToSniff` 字节的数据到 `buffered_body_`。
3. `net::SniffMimeType` 函数被调用，传入 `buffered_body_` 的内容、`response_url_` 和原始的 MIME 类型 `application/octet-stream`。
4. `net::SniffMimeType` 函数分析数据，识别出 `<!DOCTYPE html>` 标签，判断这是一个 HTML 文件。
5. `response_head_->mime_type` 被更新为 `text/html`。
6. `CompleteSniffing` 方法被调用，准备向下游发送数据。
7. 一个新的 `DataPipe` 被创建，原始的响应体数据（包括已读取的部分和后续的数据）被转发到下游。

**预期输出:**

1. 下游 `URLLoaderClient` 收到的 `response_head` 中的 `mime_type` 为 `text/html`。
2. 响应体的完整数据流被传递到下游。

**用户或编程常见的使用错误 (尽管这个类不是直接由用户使用的):**

由于 `MimeSniffingURLLoader` 是 Blink 内部的组件，用户和开发者通常不会直接与其交互。但了解其机制可以帮助理解一些与资源加载相关的问题：

1. **服务器配置错误:** 最常见的问题是服务器配置不正确，返回错误的 `Content-Type` 头部。`MimeSniffingURLLoader` 可以在一定程度上缓解这个问题，但过度依赖客户端嗅探是不好的实践。**解决方法:** 确保服务器正确配置 `Content-Type` 头部。

2. **期望禁用嗅探:**  在某些特殊情况下，开发者可能希望禁用 MIME 嗅探。虽然 `MimeSniffingURLLoader` 本身没有提供直接禁用嗅探的接口，但浏览器可能会提供全局或请求级别的配置来控制嗅探行为。**错误:** 假设开发者希望强制将所有 `.dat` 文件当作纯文本处理，但由于嗅探，HTML 文件会被错误地解析。

3. **安全隐患:** 虽然 MIME 嗅探可以提高兼容性，但也可能带来安全风险。例如，某些浏览器的 MIME 嗅探机制存在漏洞，可能导致恶意文件被当作可执行脚本执行。 Chromium 的 `MimeSniffingURLLoader` 采用了相对安全的嗅探策略，但开发者仍然需要意识到这种潜在的风险。

**总结:**

`blink/common/loader/mime_sniffing_url_loader.cc` 文件中的 `MimeSniffingURLLoader` 类在 Chromium Blink 引擎中扮演着重要的角色，它通过读取部分响应体数据来修正或确定资源的 MIME 类型。这对于正确加载和解析 JavaScript, HTML, CSS 等 Web 资源至关重要，直接影响着网页的呈现和功能。虽然开发者通常不会直接使用这个类，但理解其功能有助于诊断和解决与资源加载相关的问题。

Prompt: 
```
这是目录为blink/common/loader/mime_sniffing_url_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/loader/mime_sniffing_url_loader.h"

#include <string_view>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/task/sequenced_task_runner.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "net/base/mime_sniffer.h"
#include "services/network/public/cpp/record_ontransfersizeupdate_utils.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/loader/mime_sniffing_throttle.h"

namespace blink {

// static
const char MimeSniffingURLLoader::kDefaultMimeType[] = "text/plain";

// static
std::tuple<mojo::PendingRemote<network::mojom::URLLoader>,
           mojo::PendingReceiver<network::mojom::URLLoaderClient>,
           MimeSniffingURLLoader*>
MimeSniffingURLLoader::CreateLoader(
    base::WeakPtr<MimeSniffingThrottle> throttle,
    const GURL& response_url,
    network::mojom::URLResponseHeadPtr response_head,
    scoped_refptr<base::SequencedTaskRunner> task_runner) {
  mojo::PendingRemote<network::mojom::URLLoader> url_loader;
  mojo::PendingRemote<network::mojom::URLLoaderClient> url_loader_client;
  mojo::PendingReceiver<network::mojom::URLLoaderClient>
      url_loader_client_receiver =
          url_loader_client.InitWithNewPipeAndPassReceiver();

  auto loader = base::WrapUnique(new MimeSniffingURLLoader(
      std::move(throttle), response_url, std::move(response_head),
      std::move(url_loader_client), std::move(task_runner)));
  MimeSniffingURLLoader* loader_rawptr = loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(loader),
                              url_loader.InitWithNewPipeAndPassReceiver());
  return std::make_tuple(std::move(url_loader),
                         std::move(url_loader_client_receiver), loader_rawptr);
}

MimeSniffingURLLoader::MimeSniffingURLLoader(
    base::WeakPtr<MimeSniffingThrottle> throttle,
    const GURL& response_url,
    network::mojom::URLResponseHeadPtr response_head,
    mojo::PendingRemote<network::mojom::URLLoaderClient>
        destination_url_loader_client,
    scoped_refptr<base::SequencedTaskRunner> task_runner)
    : throttle_(throttle),
      destination_url_loader_client_(std::move(destination_url_loader_client)),
      response_url_(response_url),
      response_head_(std::move(response_head)),
      task_runner_(task_runner),
      body_consumer_watcher_(FROM_HERE,
                             mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                             task_runner),
      body_producer_watcher_(FROM_HERE,
                             mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                             std::move(task_runner)) {}

MimeSniffingURLLoader::~MimeSniffingURLLoader() = default;

void MimeSniffingURLLoader::Start(
    mojo::PendingRemote<network::mojom::URLLoader> source_url_loader_remote,
    mojo::PendingReceiver<network::mojom::URLLoaderClient>
        source_url_client_receiver,
    mojo::ScopedDataPipeConsumerHandle body) {
  source_url_loader_.Bind(std::move(source_url_loader_remote));
  source_url_client_receiver_.Bind(std::move(source_url_client_receiver),
                                   task_runner_);
  if (!body)
    return;

  state_ = State::kSniffing;
  body_consumer_handle_ = std::move(body);
  body_consumer_watcher_.Watch(
      body_consumer_handle_.get(),
      MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      base::BindRepeating(&MimeSniffingURLLoader::OnBodyReadable,
                          base::Unretained(this)));
  body_consumer_watcher_.ArmOrNotify();
}

void MimeSniffingURLLoader::OnReceiveEarlyHints(
    network::mojom::EarlyHintsPtr early_hints) {
  // OnReceiveEarlyHints() shouldn't be called. See the comment in
  // OnReceiveResponse().
  NOTREACHED();
}

void MimeSniffingURLLoader::OnReceiveResponse(
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle body,
    std::optional<mojo_base::BigBuffer> cached_metadata) {
  // OnReceiveResponse() shouldn't be called because MimeSniffingURLLoader is
  // created by MimeSniffingThrottle::WillProcessResponse(), which is equivalent
  // to OnReceiveResponse().
  NOTREACHED();
}

void MimeSniffingURLLoader::OnReceiveRedirect(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr response_head) {
  // OnReceiveRedirect() shouldn't be called because MimeSniffingURLLoader is
  // created by MimeSniffingThrottle::WillProcessResponse(), which is equivalent
  // to OnReceiveResponse().
  NOTREACHED();
}

void MimeSniffingURLLoader::OnUploadProgress(
    int64_t current_position,
    int64_t total_size,
    OnUploadProgressCallback ack_callback) {
  destination_url_loader_client_->OnUploadProgress(current_position, total_size,
                                                   std::move(ack_callback));
}

void MimeSniffingURLLoader::OnTransferSizeUpdated(int32_t transfer_size_diff) {
  network::RecordOnTransferSizeUpdatedUMA(
      network::OnTransferSizeUpdatedFrom::kMimeSniffingURLLoader);
  destination_url_loader_client_->OnTransferSizeUpdated(transfer_size_diff);
}

void MimeSniffingURLLoader::OnComplete(
    const network::URLLoaderCompletionStatus& status) {
  DCHECK(!complete_status_.has_value());
  switch (state_) {
    case State::kWaitForBody:
      // An error occured before receiving any data.
      DCHECK_NE(net::OK, status.error_code);
      state_ = State::kCompleted;
      response_head_->mime_type = kDefaultMimeType;
      if (!throttle_) {
        Abort();
        return;
      }
      throttle_->ResumeWithNewResponseHead(
          std::move(response_head_), mojo::ScopedDataPipeConsumerHandle());
      destination_url_loader_client_->OnComplete(status);
      return;
    case State::kSniffing:
    case State::kSending:
      // Defer calling OnComplete() until mime sniffing has finished and all
      // data is sent.
      complete_status_ = status;
      return;
    case State::kCompleted:
      destination_url_loader_client_->OnComplete(status);
      return;
    case State::kAborted:
      NOTREACHED();
  }
  NOTREACHED();
}

void MimeSniffingURLLoader::FollowRedirect(
    const std::vector<std::string>& removed_headers,
    const net::HttpRequestHeaders& modified_headers,
    const net::HttpRequestHeaders& modified_cors_exempt_headers,
    const std::optional<GURL>& new_url) {
  // MimeSniffingURLLoader starts handling the request after
  // OnReceivedResponse(). A redirect response is not expected.
  NOTREACHED();
}

void MimeSniffingURLLoader::SetPriority(net::RequestPriority priority,
                                        int32_t intra_priority_value) {
  if (state_ == State::kAborted)
    return;
  source_url_loader_->SetPriority(priority, intra_priority_value);
}

void MimeSniffingURLLoader::PauseReadingBodyFromNet() {
  if (state_ == State::kAborted)
    return;
  source_url_loader_->PauseReadingBodyFromNet();
}

void MimeSniffingURLLoader::ResumeReadingBodyFromNet() {
  if (state_ == State::kAborted)
    return;
  source_url_loader_->ResumeReadingBodyFromNet();
}

void MimeSniffingURLLoader::OnBodyReadable(MojoResult) {
  if (state_ == State::kSending) {
    // The pipe becoming readable when kSending means all buffered body has
    // already been sent.
    ForwardBodyToClient();
    return;
  }
  DCHECK_EQ(State::kSniffing, state_);

  size_t start_size = buffered_body_.size();
  size_t read_bytes = net::kMaxBytesToSniff;
  buffered_body_.resize(start_size + read_bytes);
  MojoResult result = body_consumer_handle_->ReadData(
      MOJO_READ_DATA_FLAG_NONE,
      base::as_writable_byte_span(buffered_body_)
          .subspan(start_size, read_bytes),
      read_bytes);
  switch (result) {
    case MOJO_RESULT_OK:
      break;
    case MOJO_RESULT_FAILED_PRECONDITION:
      // Finished the body before mime type is completely decided.
      buffered_body_.resize(start_size);
      CompleteSniffing();
      return;
    case MOJO_RESULT_SHOULD_WAIT:
      buffered_body_.resize(start_size);
      body_consumer_watcher_.ArmOrNotify();
      return;
    default:
      NOTREACHED();
  }

  DCHECK_EQ(MOJO_RESULT_OK, result);
  buffered_body_.resize(start_size + read_bytes);
  std::string new_type;
  bool made_final_decision = net::SniffMimeType(
      std::string_view(buffered_body_.data(), buffered_body_.size()),
      response_url_, response_head_->mime_type,
      net::ForceSniffFileUrlsForHtml::kDisabled, &new_type);
  response_head_->mime_type = new_type;
  response_head_->did_mime_sniff = true;
  if (made_final_decision) {
    CompleteSniffing();
    return;
  }
  body_consumer_watcher_.ArmOrNotify();
}

void MimeSniffingURLLoader::OnBodyWritable(MojoResult) {
  DCHECK_EQ(State::kSending, state_);
  if (bytes_remaining_in_buffer_ > 0) {
    SendReceivedBodyToClient();
  } else {
    ForwardBodyToClient();
  }
}

void MimeSniffingURLLoader::CompleteSniffing() {
  DCHECK_EQ(State::kSniffing, state_);
  if (buffered_body_.empty()) {
    // The URLLoader ended before sending any data. There is not enough
    // information to determine the MIME type.
    response_head_->mime_type = kDefaultMimeType;
  }

  state_ = State::kSending;
  bytes_remaining_in_buffer_ = buffered_body_.size();
  if (!throttle_) {
    Abort();
    return;
  }
  mojo::ScopedDataPipeConsumerHandle body_to_send;
  MojoResult result =
      mojo::CreateDataPipe(nullptr, body_producer_handle_, body_to_send);
  if (result != MOJO_RESULT_OK) {
    Abort();
    return;
  }
  throttle_->ResumeWithNewResponseHead(std::move(response_head_),
                                       std::move(body_to_send));
  // Set up the watcher for the producer handle.
  body_producer_watcher_.Watch(
      body_producer_handle_.get(),
      MOJO_HANDLE_SIGNAL_WRITABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      base::BindRepeating(&MimeSniffingURLLoader::OnBodyWritable,
                          base::Unretained(this)));

  if (bytes_remaining_in_buffer_) {
    SendReceivedBodyToClient();
    return;
  }

  CompleteSending();
}

void MimeSniffingURLLoader::CompleteSending() {
  DCHECK_EQ(State::kSending, state_);
  state_ = State::kCompleted;
  // Call client's OnComplete() if |this|'s OnComplete() has already been
  // called.
  if (complete_status_.has_value())
    destination_url_loader_client_->OnComplete(complete_status_.value());

  body_consumer_watcher_.Cancel();
  body_producer_watcher_.Cancel();
  body_consumer_handle_.reset();
  body_producer_handle_.reset();
}

void MimeSniffingURLLoader::SendReceivedBodyToClient() {
  DCHECK_EQ(State::kSending, state_);
  // Send the buffered data first.
  DCHECK_GT(bytes_remaining_in_buffer_, 0u);
  base::span<const uint8_t> bytes =
      base::as_byte_span(buffered_body_).last(bytes_remaining_in_buffer_);
  size_t actually_sent_bytes = 0;
  MojoResult result = body_producer_handle_->WriteData(
      bytes, MOJO_WRITE_DATA_FLAG_NONE, actually_sent_bytes);
  switch (result) {
    case MOJO_RESULT_OK:
      break;
    case MOJO_RESULT_FAILED_PRECONDITION:
      // The pipe is closed unexpectedly. |this| should be deleted once
      // URLLoader on the destination is released.
      Abort();
      return;
    case MOJO_RESULT_SHOULD_WAIT:
      body_producer_watcher_.ArmOrNotify();
      return;
    default:
      NOTREACHED();
  }
  bytes_remaining_in_buffer_ -= actually_sent_bytes;
  body_producer_watcher_.ArmOrNotify();
}

void MimeSniffingURLLoader::ForwardBodyToClient() {
  DCHECK_EQ(0u, bytes_remaining_in_buffer_);
  // Send the body from the consumer to the producer.
  base::span<const uint8_t> buffer;
  MojoResult result = body_consumer_handle_->BeginReadData(
      MOJO_BEGIN_READ_DATA_FLAG_NONE, buffer);
  switch (result) {
    case MOJO_RESULT_OK:
      break;
    case MOJO_RESULT_SHOULD_WAIT:
      body_consumer_watcher_.ArmOrNotify();
      return;
    case MOJO_RESULT_FAILED_PRECONDITION:
      // All data has been sent.
      CompleteSending();
      return;
    default:
      NOTREACHED();
  }

  size_t actually_written_bytes = 0;
  result = body_producer_handle_->WriteData(buffer, MOJO_WRITE_DATA_FLAG_NONE,
                                            actually_written_bytes);
  switch (result) {
    case MOJO_RESULT_OK:
      break;
    case MOJO_RESULT_FAILED_PRECONDITION:
      // The pipe is closed unexpectedly. |this| should be deleted once
      // URLLoader on the destination is released.
      Abort();
      return;
    case MOJO_RESULT_SHOULD_WAIT:
      body_consumer_handle_->EndReadData(0);
      body_producer_watcher_.ArmOrNotify();
      return;
    default:
      NOTREACHED();
  }

  body_consumer_handle_->EndReadData(actually_written_bytes);
  body_consumer_watcher_.ArmOrNotify();
}

void MimeSniffingURLLoader::Abort() {
  state_ = State::kAborted;
  body_consumer_watcher_.Cancel();
  body_producer_watcher_.Cancel();
  source_url_loader_.reset();
  source_url_client_receiver_.reset();
  destination_url_loader_client_.reset();
  // |this| should be removed since the owner will destroy |this| or the owner
  // has already been destroyed by some reason.
}

}  // namespace blink

"""

```