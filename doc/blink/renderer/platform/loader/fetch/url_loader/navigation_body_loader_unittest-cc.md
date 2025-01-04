Response:
My thinking process to answer the request about `navigation_body_loader_unittest.cc` goes like this:

1. **Understand the Goal:** The request asks for the functionalities of the given C++ unit test file, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning examples, and common usage errors.

2. **Identify the Core Class Under Test:** The filename `navigation_body_loader_unittest.cc` immediately points to the class being tested: `NavigationBodyLoader`. The `#include` directive confirms this.

3. **Analyze Test Structure:** I scan the test file for the `TEST_F` macros. Each `TEST_F` defines a specific test case. I read the name of each test case to get a high-level understanding of what aspects of `NavigationBodyLoader` are being tested. Keywords like "SetDefers," "DecodedData," "ProcessBackgroundData," "DataReceived," "StartDeferred," "OnComplete," "Close," and "FillResponse" give clues.

4. **Categorize Functionalities:** Based on the test case names and the actions within them (like `Write`, `Complete`, `StartLoading`, `SetDefersLoading`), I start categorizing the tested functionalities of `NavigationBodyLoader`:
    * **Basic Data Handling:** Receiving and processing data chunks (`DataReceived`, `DecodedDataReceived`).
    * **Lifecycle Management:** Starting and finishing the loading process, handling completion with errors (`StartLoading`, `BodyLoadingFinished`, `OnComplete`, `Close`).
    * **Deferred Loading:**  Managing the pausing and resuming of data processing (`SetDefersLoading`, `StartDeferred`).
    * **Background Processing:**  Handling data on a separate thread (`StartLoadingInBackground`, `ProcessBackgroundData`).
    * **Integration with Navigation:** How the loader fits into the broader navigation process, specifically how it interacts with `NavigationParams` and response headers (`FillResponseWithSecurityDetails`, `FillResponseReferrerRedirects`).
    * **Resource Limits/Chunking:**  Testing how the loader handles data in chunks, potentially related to performance or memory management (`MaxDataSize1`, `MaxDataSize2`, `MaxDataSizeAll`).

5. **Relate to Web Technologies:** I think about how `NavigationBodyLoader` interacts with the rendering engine and the data it loads. Since it's involved in fetching content for navigation, it's directly related to:
    * **HTML:** The primary content being loaded.
    * **CSS:** While not directly processed by this loader, CSS is often part of the HTML content being fetched.
    * **JavaScript:**  Similar to CSS, JavaScript is often part of the HTML and its loading can be influenced by the navigation process. The `BodyTextDecoder` (like `UppercaseDecoder`) hints at text processing, which is relevant to all three technologies.

6. **Construct Examples (JavaScript, HTML, CSS):**  For each technology, I come up with simple, illustrative examples:
    * **HTML:** A basic HTML structure to represent what the loader might be fetching.
    * **JavaScript:** A simple script that might be included in the HTML.
    * **CSS:**  A basic CSS rule that might style the HTML. The connection here is indirect—the loader fetches the HTML, which *contains* or *links to* CSS.

7. **Identify Logical Reasoning Scenarios:** I look for tests that involve specific sequences of actions and expected outcomes. The "deferred loading" tests (`StartDeferred`, `StartDeferredWithBackForwardCache`) are good examples. I formulate a scenario with clear inputs (setting deferral, writing data) and expected outputs (data not received until deferral is lifted). I also look for tests involving callbacks and asynchronous behavior (`ProcessBackgroundData`).

8. **Pinpoint Common Usage Errors:**  I consider the types of issues a developer integrating with or using a component like `NavigationBodyLoader` might encounter. These often relate to:
    * **Order of Operations:**  Calling methods in the wrong sequence (e.g., starting loading before setting up necessary parameters). The `SetDefersBeforeStart` test hints at this.
    * **Resource Management:** Forgetting to handle completion or errors.
    * **Assumptions about Asynchronous Behavior:**  Not understanding how data is delivered through callbacks.
    * **Incorrectly Handling Deferred Loading:**  Not properly resuming a deferred load.

9. **Structure the Output:** I organize the information into the requested categories: Functionalities, Relationship to Web Technologies, Logical Reasoning, and Common Usage Errors. I use clear and concise language, providing examples where requested.

10. **Review and Refine:** I reread my answer to ensure it's accurate, comprehensive, and easy to understand. I check that the examples are relevant and the logical reasoning scenarios are clear. I make sure I've addressed all parts of the original request. For instance, I initially might have focused too much on the technical details of the C++ code and needed to consciously bring in the web technology connections.
这个文件 `navigation_body_loader_unittest.cc` 是 Chromium Blink 引擎中用于测试 `NavigationBodyLoader` 类的单元测试文件。`NavigationBodyLoader` 的主要职责是在页面导航期间加载响应主体内容。

以下是该文件的功能列表：

**核心功能测试:**

1. **主体数据接收 (Body Data Received):** 测试 `NavigationBodyLoader` 能否正确接收并传递原始的、未经解码的响应主体数据。
    * **例如 `DataReceived` 测试:**  模拟服务器发送 "hello"，验证 `NavigationBodyLoader` 能否通过 `BodyDataReceived` 回调将 "hello" 传递给客户端。
    * **例如 `DataReceivedFromDataReceived` 测试:**  在接收到第一部分数据后，客户端在回调中执行某些操作（例如准备写入更多数据），验证 `NavigationBodyLoader` 能否正确处理这种情况。

2. **解码后的主体数据接收 (Decoded Body Data Received):** 测试 `NavigationBodyLoader` 在使用解码器的情况下，能否正确接收并传递解码后的响应主体数据。
    * **例如 `DecodedDataReceived` 测试:** 使用一个简单的 `UppercaseDecoder`，模拟接收到 "hello"，验证 `NavigationBodyLoader` 能否通过 `DecodedBodyDataReceived` 回调将解码后的 "HELLO" 传递给客户端。

3. **后台数据处理 (Process Background Data):** 测试 `NavigationBodyLoader` 能否在后台线程处理数据，并通过回调将部分或全部数据传递给客户端。
    * **例如 `ProcessBackgroundData` 测试:**  首先将一部分数据发送到后台读取器，此时未设置后台数据回调。然后设置回调并发送更多数据，验证回调是否按预期被调用并接收到数据。

4. **加载完成通知 (Body Loading Finished):** 测试 `NavigationBodyLoader` 能否在加载完成后正确通知客户端，包括成功完成和发生错误的情况。
    * **例如 `OnCompleteThenClose` 测试:**  模拟加载完成并发生网络错误，验证 `NavigationBodyLoader` 能否通过 `BodyLoadingFinished` 回调通知客户端，并包含错误信息。
    * **例如 `CloseThenOnComplete` 测试:**  模拟在接收到所有数据之前关闭连接，验证 `NavigationBodyLoader` 能否正确处理并通知客户端。

5. **延迟加载 (Deferred Loading):** 测试 `NavigationBodyLoader` 的延迟加载功能，允许在特定时机暂停和恢复数据接收。
    * **例如 `SetDefersBeforeStart` 测试:**  在开始加载前设置延迟状态，验证是否不会崩溃。
    * **例如 `StartDeferred` 测试:**  先设置延迟加载，然后开始加载并发送数据，最后取消延迟，验证之前发送的数据是否会被接收。
    * **例如 `StartDeferredWithBackForwardCache` 测试:**  测试在启用 BackForwardCache 的情况下延迟加载的行为。

6. **导航参数填充 (Navigation Parameters Filling):** 测试 `FillNavigationParamsResponseAndBodyLoader` 函数，该函数用于将响应头信息和主体加载器关联到导航参数中。
    * **例如 `FillResponseWithSecurityDetails` 测试:**  验证当响应头包含安全信息（例如 SSL 证书）时，这些信息能否正确填充到 `NavigationParams` 中。
    * **例如 `FillResponseReferrerRedirects` 测试:** 验证在重定向过程中，Referrer 信息能否正确填充到 `NavigationParams` 中。

7. **最大数据大小限制 (Max Data Size):**  测试在启用 `kThreadedBodyLoader` 特性并设置最大数据处理量时，`NavigationBodyLoader` 如何分块传递解码后的数据。
    * **例如 `MaxDataSize1`, `MaxDataSize2`, `MaxDataSizeAll` 测试:**  通过设置不同的 `max-data-to-process` 参数，验证解码后的数据是否按照指定的块大小传递给客户端。

**与 Javascript, HTML, CSS 的关系:**

`NavigationBodyLoader` 的核心功能是加载网页内容，这与 Javascript, HTML, CSS 有着直接的关系：

* **HTML:** `NavigationBodyLoader` 负责下载 HTML 文档的原始字节流。下载完成后，这些字节流会被解码并传递给 HTML 解析器，最终构建 DOM 树。
    * **举例:** 当用户在浏览器中输入网址并按下回车键时，Blink 引擎会创建一个 `NavigationBodyLoader` 来获取服务器返回的 HTML 内容。
    * **假设输入:** 服务器返回的 HTML 响应体是 `<html><body>Hello, world!</body></html>`。
    * **预期输出:** `NavigationBodyLoader` 将接收到这段字节流，并可能通过 `BodyDataReceived` 或 `DecodedBodyDataReceived` 回调将内容传递给后续的 HTML 处理模块。

* **Javascript:** HTML 文档中可能包含 `<script>` 标签引入的 Javascript 代码，或者内联的 Javascript 代码。`NavigationBodyLoader` 负责下载包含这些 Javascript 代码的 HTML 文档。
    * **举例:**  如果 HTML 中包含 `<script src="script.js"></script>`，当浏览器加载这个 HTML 时，可能会有另一个资源加载器（而不是 `NavigationBodyLoader` 直接负责）来加载 `script.js`，但 `NavigationBodyLoader` 负责加载包含这个 `<script>` 标签的 HTML。
    * **假设输入:** HTML 响应体包含 `<script>console.log("Hello from JS");</script>`。
    * **预期输出:** `NavigationBodyLoader` 会接收到包含这段 Javascript 代码的 HTML 内容。

* **CSS:** 类似于 Javascript，HTML 文档会通过 `<link>` 标签引入外部 CSS 文件，或者包含 `<style>` 标签定义的内联 CSS 样式。`NavigationBodyLoader` 负责下载包含这些 CSS 引用或定义的 HTML 文档。单独的 CSS 文件通常由其他资源加载器负责下载。
    * **举例:** 如果 HTML 中包含 `<link rel="stylesheet" href="style.css">`，`NavigationBodyLoader` 负责加载包含这个 `<link>` 标签的 HTML。
    * **假设输入:** HTML 响应体包含 `<style>body { background-color: red; }</style>`。
    * **预期输出:** `NavigationBodyLoader` 会接收到包含这段 CSS 代码的 HTML 内容。

**逻辑推理的假设输入与输出:**

考虑 `StartDeferred` 测试用例：

* **假设输入:**
    1. 调用 `CreateBodyLoader()` 创建 `NavigationBodyLoader` 实例。
    2. 调用 `loader_->SetDefersLoading(WebLoaderFreezeMode::kStrict)` 设置延迟加载模式。
    3. 调用 `StartLoading()` 开始加载。
    4. 调用 `Write("hello")` 模拟接收到 "hello" 数据。
    5. 调用 `loader_->SetDefersLoading(WebLoaderFreezeMode::kNone)` 取消延迟加载。

* **预期输出:**
    1. 在调用 `SetDefersLoading(WebLoaderFreezeMode::kStrict)` 之后，即使调用了 `Write("hello")`，`BodyDataReceived` 回调也不会立即被调用。
    2. 直到调用 `SetDefersLoading(WebLoaderFreezeMode::kNone)` 取消延迟加载后，`BodyDataReceived` 回调才会被触发，并且接收到的数据是 "hello"。`TakeDataReceived()` 将返回 "hello"。

**用户或编程常见的使用错误举例:**

1. **过早调用需要已加载数据的操作:** 用户可能会在 `BodyLoadingFinished` 回调之前尝试访问或处理响应主体数据，导致数据尚未完全接收或处理完成。
    * **举例:**  假设一个 Javascript 脚本尝试在 `DOMContentLoaded` 事件触发之前就访问某个 HTML 元素，而该元素的数据可能还在通过 `NavigationBodyLoader` 加载中。

2. **没有正确处理加载错误:** 开发者可能没有实现 `BodyLoadingFinished` 回调来处理加载失败的情况（例如网络错误），导致程序在加载失败时行为异常。
    * **举例:** 用户在网络不稳定的情况下访问网页，`NavigationBodyLoader` 可能因为网络错误而加载失败，如果开发者没有处理这种情况，网页可能显示空白或停留在加载状态。

3. **在不恰当的时机设置或取消延迟加载:**  错误地使用 `SetDefersLoading` 可能会导致数据接收被意外暂停或提前恢复，影响页面的加载和渲染。
    * **举例:**  开发者可能在接收到部分数据后错误地设置了延迟加载，导致后续数据无法及时到达，页面加载出现卡顿。

4. **对解码的假设不正确:** 如果使用了自定义的解码器，开发者需要确保解码逻辑的正确性。假设解码器出现错误，`DecodedBodyDataReceived` 回调传递的数据可能不是预期的。
    * **举例:**  如果使用了错误的字符编码解码器，原本是 UTF-8 的内容可能被按照 ISO-8859-1 解码，导致乱码。

5. **在回调函数中执行耗时操作:**  如果在 `BodyDataReceived` 或 `DecodedBodyDataReceived` 等回调函数中执行了大量的同步计算或阻塞操作，可能会阻塞渲染主线程，导致页面无响应。应该尽量将耗时操作放到后台线程执行。

这些测试用例覆盖了 `NavigationBodyLoader` 的关键功能和边界情况，帮助确保这个类在页面导航过程中能够正确、高效地加载和处理响应主体内容。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/navigation_body_loader_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/navigation_body_loader.h"

#include <string_view>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "net/cert/x509_util.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/cert_test_util.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/fetch_api.mojom.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/navigation/navigation_params.h"
#include "third_party/blink/public/mojom/navigation/navigation_params.mojom.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_navigation_body_loader.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/renderer/platform/loader/fetch/body_text_decoder.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

namespace {

using ::testing::ElementsAre;

class UppercaseDecoder : public BodyTextDecoder {
  String Decode(base::span<const char> data) override {
    return String(data).UpperASCII();
  }

  String Flush() override { return String(); }

  WebEncodingData GetEncodingData() const override { return WebEncodingData(); }
};

class NavigationBodyLoaderTest : public ::testing::Test,
                                 public WebNavigationBodyLoader::Client {
 protected:
  NavigationBodyLoaderTest() {}

  ~NavigationBodyLoaderTest() override { base::RunLoop().RunUntilIdle(); }

  MojoCreateDataPipeOptions CreateDataPipeOptions() {
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(MojoCreateDataPipeOptions);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = 1024;
    return options;
  }

  void CreateBodyLoader() {
    mojo::ScopedDataPipeProducerHandle producer_handle;
    mojo::ScopedDataPipeConsumerHandle consumer_handle;
    MojoCreateDataPipeOptions options = CreateDataPipeOptions();
    ASSERT_EQ(mojo::CreateDataPipe(&options, producer_handle, consumer_handle),
              MOJO_RESULT_OK);

    writer_ = std::move(producer_handle);
    auto endpoints = network::mojom::URLLoaderClientEndpoints::New();
    endpoints->url_loader_client = client_remote_.BindNewPipeAndPassReceiver();
    WebNavigationParams navigation_params;
    auto common_params = CreateCommonNavigationParams();
    common_params->request_destination =
        network::mojom::RequestDestination::kDocument;
    auto commit_params = CreateCommitNavigationParams();
    WebNavigationBodyLoader::FillNavigationParamsResponseAndBodyLoader(
        std::move(common_params), std::move(commit_params), /*request_id=*/1,
        network::mojom::URLResponseHead::New(), std::move(consumer_handle),
        std::move(endpoints), scheduler::GetSingleThreadTaskRunnerForTesting(),
        std::make_unique<ResourceLoadInfoNotifierWrapper>(
            /*resource_load_info_notifier=*/nullptr),
        /*is_main_frame=*/true, &navigation_params, /*is_ad_frame=*/false);
    loader_ = std::move(navigation_params.body_loader);
  }

  void StartLoading() {
    loader_->StartLoadingBody(this);
    base::RunLoop().RunUntilIdle();
  }

  void StartLoadingInBackground() {
    To<NavigationBodyLoader>(loader_.get())
        ->StartLoadingBodyInBackground(std::make_unique<UppercaseDecoder>(),
                                       false);
    base::RunLoop().RunUntilIdle();
  }

  void Write(const std::string& buffer) {
    size_t actually_written_bytes = 0;
    MojoResult result = writer_->WriteData(base::as_byte_span(buffer), kNone,
                                           actually_written_bytes);
    ASSERT_EQ(MOJO_RESULT_OK, result);
    ASSERT_EQ(buffer.size(), actually_written_bytes);
  }

  void WriteAndFlush(const std::string& buffer) {
    Write(buffer);
    To<NavigationBodyLoader>(loader_.get())
        ->FlushOffThreadBodyReaderForTesting();
  }

  void Complete(int net_error) {
    client_remote_->OnComplete(network::URLLoaderCompletionStatus(net_error));
    base::RunLoop().RunUntilIdle();
  }

  void BodyDataReceived(base::span<const char> data) override {
    ASSERT_FALSE(did_receive_decoded_data_);
    ASSERT_TRUE(expecting_data_received_);
    did_receive_data_ = true;
    data_received_ += std::string(data.data(), data.size());
    TakeActions();
    if (run_loop_)
      run_loop_->Quit();
  }

  void DecodedBodyDataReceived(
      const WebString& data,
      const WebEncodingData& encoding_data,
      base::SpanOrSize<const char> encoded_data) override {
    ASSERT_FALSE(did_receive_data_);
    ASSERT_TRUE(expecting_decoded_data_received_);
    did_receive_decoded_data_ = true;
    data_received_ += data.Ascii();
    TakeActions();
    if (run_loop_)
      run_loop_->Quit();
  }

  void BodyLoadingFinished(base::TimeTicks completion_time,
                           int64_t total_encoded_data_length,
                           int64_t total_encoded_body_length,
                           int64_t total_decoded_body_length,
                           const std::optional<WebURLError>& error) override {
    ASSERT_TRUE(expecting_finished_);
    did_finish_ = true;
    error_ = error;
    TakeActions();
    if (run_loop_)
      run_loop_->Quit();
  }

  ProcessBackgroundDataCallback TakeProcessBackgroundDataCallback() override {
    return std::move(process_background_data_callback_);
  }

  void TakeActions() {
    if (!buffer_to_write_.empty()) {
      std::string buffer = buffer_to_write_;
      buffer_to_write_ = std::string();
      ExpectDataReceived();
      Write(buffer);
    }
    if (toggle_defers_loading_) {
      toggle_defers_loading_ = false;
      loader_->SetDefersLoading(WebLoaderFreezeMode::kNone);
      loader_->SetDefersLoading(WebLoaderFreezeMode::kStrict);
    }
    if (destroy_loader_) {
      destroy_loader_ = false;
      loader_.reset();
    }
  }

  void ExpectDataReceived() {
    expecting_data_received_ = true;
    did_receive_data_ = false;
  }

  void ExpectDecodedDataReceived() {
    expecting_decoded_data_received_ = true;
    did_receive_decoded_data_ = false;
  }

  void ExpectFinished() {
    expecting_finished_ = true;
    did_finish_ = false;
  }

  std::string TakeDataReceived() {
    std::string data = data_received_;
    data_received_ = std::string();
    return data;
  }

  void Wait() {
    if (expecting_data_received_) {
      if (!did_receive_data_)
        WaitForRunLoop();
      ASSERT_TRUE(did_receive_data_);
      expecting_data_received_ = false;
    }
    if (expecting_decoded_data_received_) {
      if (!did_receive_decoded_data_)
        WaitForRunLoop();
      ASSERT_TRUE(did_receive_decoded_data_);
      expecting_decoded_data_received_ = false;
    }
    if (expecting_finished_) {
      if (!did_finish_)
        WaitForRunLoop();
      ASSERT_TRUE(did_finish_);
      expecting_finished_ = false;
    }
  }

  void WaitForRunLoop() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
    run_loop_.reset();
  }

  base::test::TaskEnvironment task_environment_;
  static const MojoWriteDataFlags kNone = MOJO_WRITE_DATA_FLAG_NONE;
  mojo::Remote<network::mojom::URLLoaderClient> client_remote_;
  std::unique_ptr<WebNavigationBodyLoader> loader_;
  mojo::ScopedDataPipeProducerHandle writer_;

  std::unique_ptr<base::RunLoop> run_loop_;
  bool expecting_data_received_ = false;
  bool did_receive_data_ = false;
  bool expecting_decoded_data_received_ = false;
  bool did_receive_decoded_data_ = false;
  bool expecting_finished_ = false;
  bool did_finish_ = false;
  std::string buffer_to_write_;
  bool toggle_defers_loading_ = false;
  bool destroy_loader_ = false;
  std::string data_received_;
  std::optional<WebURLError> error_;
  ProcessBackgroundDataCallback process_background_data_callback_;
};

TEST_F(NavigationBodyLoaderTest, SetDefersBeforeStart) {
  CreateBodyLoader();
  loader_->SetDefersLoading(WebLoaderFreezeMode::kStrict);
  loader_->SetDefersLoading(WebLoaderFreezeMode::kNone);
  // Should not crash.
}

TEST_F(NavigationBodyLoaderTest, DecodedDataReceived) {
  CreateBodyLoader();
  StartLoadingInBackground();
  StartLoading();
  ExpectDecodedDataReceived();
  Write("hello");
  Wait();
  EXPECT_EQ("HELLO", TakeDataReceived());
}

TEST_F(NavigationBodyLoaderTest, ProcessBackgroundData) {
  CreateBodyLoader();
  StartLoadingInBackground();
  // First flush data to the off thread reader. The background data callback
  // should not see this since it is not set yet.
  WriteAndFlush("hello");

  String background_data = "";
  process_background_data_callback_ = CrossThreadBindRepeating(
      [](String* background_data, const WebString& data) {
        *background_data = *background_data + String(data);
      },
      CrossThreadUnretained(&background_data));

  ExpectDecodedDataReceived();
  StartLoading();
  Wait();
  EXPECT_EQ("HELLO", TakeDataReceived());
  EXPECT_EQ("", background_data);

  // Now write more data with the background data callback set.
  ExpectDecodedDataReceived();
  Write("hello2");
  Wait();
  EXPECT_EQ("HELLO2", TakeDataReceived());
  EXPECT_EQ("HELLO2", background_data);

  ExpectDecodedDataReceived();
  Write("hello3");
  Wait();
  EXPECT_EQ("HELLO3", TakeDataReceived());
  EXPECT_EQ("HELLO2HELLO3", background_data);
}

TEST_F(NavigationBodyLoaderTest, DataReceived) {
  CreateBodyLoader();
  StartLoading();
  ExpectDataReceived();
  Write("hello");
  Wait();
  EXPECT_EQ("hello", TakeDataReceived());
}

TEST_F(NavigationBodyLoaderTest, DataReceivedFromDataReceived) {
  CreateBodyLoader();
  StartLoading();
  ExpectDataReceived();
  buffer_to_write_ = "world";
  Write("hello");
  Wait();
  EXPECT_EQ("helloworld", TakeDataReceived());
}

TEST_F(NavigationBodyLoaderTest, DestroyFromDataReceived) {
  CreateBodyLoader();
  StartLoading();
  ExpectDataReceived();
  destroy_loader_ = false;
  Write("hello");
  Wait();
  EXPECT_EQ("hello", TakeDataReceived());
}

TEST_F(NavigationBodyLoaderTest, SetDefersLoadingFromDataReceived) {
  CreateBodyLoader();
  StartLoading();
  ExpectDataReceived();
  toggle_defers_loading_ = true;
  Write("hello");
  Wait();
  EXPECT_EQ("hello", TakeDataReceived());
}

TEST_F(NavigationBodyLoaderTest, StartDeferred) {
  CreateBodyLoader();
  loader_->SetDefersLoading(WebLoaderFreezeMode::kStrict);
  StartLoading();
  Write("hello");
  ExpectDataReceived();
  loader_->SetDefersLoading(WebLoaderFreezeMode::kNone);
  Wait();
  EXPECT_EQ("hello", TakeDataReceived());
}

TEST_F(NavigationBodyLoaderTest, StartDeferredWithBackForwardCache) {
  CreateBodyLoader();
  loader_->SetDefersLoading(WebLoaderFreezeMode::kBufferIncoming);
  StartLoading();
  Write("hello");
  ExpectDataReceived();
  loader_->SetDefersLoading(WebLoaderFreezeMode::kNone);
  Wait();
  EXPECT_EQ("hello", TakeDataReceived());
}

TEST_F(NavigationBodyLoaderTest, OnCompleteThenClose) {
  CreateBodyLoader();
  StartLoading();
  Complete(net::ERR_FAILED);
  ExpectFinished();
  writer_.reset();
  Wait();
  EXPECT_TRUE(error_.has_value());
}

TEST_F(NavigationBodyLoaderTest, DestroyFromOnCompleteThenClose) {
  CreateBodyLoader();
  StartLoading();
  Complete(net::ERR_FAILED);
  ExpectFinished();
  destroy_loader_ = true;
  writer_.reset();
  Wait();
  EXPECT_TRUE(error_.has_value());
}

TEST_F(NavigationBodyLoaderTest, SetDefersLoadingFromOnCompleteThenClose) {
  CreateBodyLoader();
  StartLoading();
  Complete(net::ERR_FAILED);
  ExpectFinished();
  toggle_defers_loading_ = true;
  writer_.reset();
  Wait();
  EXPECT_TRUE(error_.has_value());
}

TEST_F(NavigationBodyLoaderTest, CloseThenOnComplete) {
  CreateBodyLoader();
  StartLoading();
  writer_.reset();
  ExpectFinished();
  Complete(net::ERR_FAILED);
  Wait();
  EXPECT_TRUE(error_.has_value());
}

TEST_F(NavigationBodyLoaderTest, DestroyFromCloseThenOnComplete) {
  CreateBodyLoader();
  StartLoading();
  writer_.reset();
  ExpectFinished();
  destroy_loader_ = true;
  Complete(net::ERR_FAILED);
  Wait();
  EXPECT_TRUE(error_.has_value());
}

TEST_F(NavigationBodyLoaderTest, SetDefersLoadingFromCloseThenOnComplete) {
  CreateBodyLoader();
  StartLoading();
  writer_.reset();
  ExpectFinished();
  toggle_defers_loading_ = true;
  Complete(net::ERR_FAILED);
  Wait();
  EXPECT_TRUE(error_.has_value());
}

// Tests that FillNavigationParamsResponseAndBodyLoader populates security
// details on the response when they are present.
TEST_F(NavigationBodyLoaderTest, FillResponseWithSecurityDetails) {
  auto response = network::mojom::URLResponseHead::New();
  response->ssl_info = net::SSLInfo();
  net::CertificateList certs;
  ASSERT_TRUE(net::LoadCertificateFiles(
      {"subjectAltName_sanity_check.pem", "root_ca_cert.pem"}, &certs));
  ASSERT_EQ(2U, certs.size());

  std::string_view cert0_der =
      net::x509_util::CryptoBufferAsStringPiece(certs[0]->cert_buffer());
  std::string_view cert1_der =
      net::x509_util::CryptoBufferAsStringPiece(certs[1]->cert_buffer());

  response->ssl_info->cert =
      net::X509Certificate::CreateFromDERCertChain({cert0_der, cert1_der});
  net::SSLConnectionStatusSetVersion(net::SSL_CONNECTION_VERSION_TLS1_2,
                                     &response->ssl_info->connection_status);

  auto common_params = CreateCommonNavigationParams();
  common_params->url = GURL("https://example.test");
  common_params->request_destination =
      network::mojom::RequestDestination::kDocument;
  auto commit_params = CreateCommitNavigationParams();

  WebNavigationParams navigation_params;
  auto endpoints = network::mojom::URLLoaderClientEndpoints::New();
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  MojoResult rv =
      mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle);
  ASSERT_EQ(MOJO_RESULT_OK, rv);
  WebNavigationBodyLoader::FillNavigationParamsResponseAndBodyLoader(
      std::move(common_params), std::move(commit_params), /*request_id=*/1,
      std::move(response), std::move(consumer_handle), std::move(endpoints),
      scheduler::GetSingleThreadTaskRunnerForTesting(),
      std::make_unique<ResourceLoadInfoNotifierWrapper>(
          /*resource_load_info_notifier=*/nullptr),
      /*is_main_frame=*/true, &navigation_params, /*is_ad_frame=*/false);
  EXPECT_TRUE(
      navigation_params.response.ToResourceResponse().GetSSLInfo().has_value());
}

// Tests that FillNavigationParamsResponseAndBodyLoader populates referrer
// on redirects correctly.
TEST_F(NavigationBodyLoaderTest, FillResponseReferrerRedirects) {
  auto response = network::mojom::URLResponseHead::New();
  auto common_params = CreateCommonNavigationParams();
  common_params->url = GURL("https://example.test");
  common_params->request_destination =
      network::mojom::RequestDestination::kDocument;
  auto commit_params = CreateCommitNavigationParams();
  // The first redirect will have an empty referrer, which should result in an
  // output of the default WebString. The second has an actual referrer, which
  // should be populated verbatim.
  net::RedirectInfo first_redirect_info;
  net::RedirectInfo second_redirect_info;
  GURL first_redirect_url = GURL("");
  GURL second_redirect_url = GURL("https://www.google.com");
  second_redirect_info.new_referrer = second_redirect_url.spec();

  network::mojom::URLResponseHeadPtr first_redirect_response =
      network::mojom::URLResponseHead::New();
  network::mojom::URLResponseHeadPtr second_redirect_response =
      network::mojom::URLResponseHead::New();
  commit_params->redirect_infos.push_back(first_redirect_info);
  commit_params->redirect_infos.push_back(second_redirect_info);
  commit_params->redirect_response.push_back(
      std::move(first_redirect_response));
  commit_params->redirect_response.push_back(
      std::move(second_redirect_response));
  commit_params->redirects.push_back(first_redirect_url);
  commit_params->redirects.push_back(second_redirect_url);

  WebNavigationParams navigation_params;
  auto endpoints = network::mojom::URLLoaderClientEndpoints::New();
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  MojoResult rv =
      mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle);
  ASSERT_EQ(MOJO_RESULT_OK, rv);
  WebNavigationBodyLoader::FillNavigationParamsResponseAndBodyLoader(
      std::move(common_params), std::move(commit_params), /*request_id=*/1,
      std::move(response), std::move(consumer_handle), std::move(endpoints),
      scheduler::GetSingleThreadTaskRunnerForTesting(),
      std::make_unique<ResourceLoadInfoNotifierWrapper>(
          /*resource_load_info_notifier=*/nullptr),
      /*is_main_frame=*/true, &navigation_params, /*is_ad_frame=*/false);
  ASSERT_EQ(navigation_params.redirects.size(), 2u);
  ASSERT_EQ(navigation_params.redirects[0].new_referrer,
            WebString(Referrer::NoReferrer()));
  ASSERT_EQ(navigation_params.redirects[1].new_referrer,
            WebString::FromUTF8(second_redirect_url.spec()));
}

// A loader client which keeps track of chunks of data that are received in a
// single PostTask.
class ChunkingLoaderClient : public WebNavigationBodyLoader::Client {
 public:
  void BodyDataReceived(base::span<const char> data) override { NOTREACHED(); }
  void DecodedBodyDataReceived(
      const WebString& data,
      const WebEncodingData& encoding_data,
      base::SpanOrSize<const char> encoded_data) override {
    scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
        FROM_HERE, base::BindOnce(&ChunkingLoaderClient::CreateNewChunk,
                                  base::Unretained(this)));
    chunks_.back() += data.Ascii();
  }
  void BodyLoadingFinished(base::TimeTicks completion_time,
                           int64_t total_encoded_data_length,
                           int64_t total_encoded_body_length,
                           int64_t total_decoded_body_length,
                           const std::optional<WebURLError>& error) override {
    scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
        FROM_HERE, run_loop_.QuitClosure());
  }

  void CreateNewChunk() {
    if (!chunks_.back().empty())
      chunks_.push_back("");
  }

  std::vector<std::string> TakeChunks() {
    run_loop_.Run();
    return std::move(chunks_);
  }

 private:
  base::RunLoop run_loop_;
  std::vector<std::string> chunks_{""};
};

TEST_F(NavigationBodyLoaderTest, MaxDataSize1) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeatureWithParameters(
      features::kThreadedBodyLoader, {{"max-data-to-process", "1"}});
  CreateBodyLoader();
  StartLoadingInBackground();
  for (const char* s : {"a", "b", "c", "d", "e", "f", "g", "h"})
    WriteAndFlush(std::string(s));

  ChunkingLoaderClient client;
  loader_->StartLoadingBody(&client);
  Complete(net::OK);
  writer_.reset();
  // First chunk is doubled since we can't catch the first PostTask.
  EXPECT_THAT(client.TakeChunks(),
              ElementsAre("AB", "C", "D", "E", "F", "G", "H", ""));
}

TEST_F(NavigationBodyLoaderTest, MaxDataSize2) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeatureWithParameters(
      features::kThreadedBodyLoader, {{"max-data-to-process", "2"}});
  CreateBodyLoader();
  StartLoadingInBackground();
  for (const char* s : {"a", "b", "c", "d", "e", "f", "g", "h"})
    WriteAndFlush(std::string(s));

  ChunkingLoaderClient client;
  loader_->StartLoadingBody(&client);
  Complete(net::OK);
  writer_.reset();
  // First chunk is doubled since we can't catch the first PostTask.
  EXPECT_THAT(client.TakeChunks(), ElementsAre("ABCD", "EF", "GH", ""));
}

TEST_F(NavigationBodyLoaderTest, MaxDataSizeAll) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeatureWithParameters(
      features::kThreadedBodyLoader, {{"max-data-to-process", "0"}});
  CreateBodyLoader();
  StartLoadingInBackground();
  for (const char* s : {"a", "b", "c", "d", "e", "f", "g", "h"})
    WriteAndFlush(std::string(s));

  ChunkingLoaderClient client;
  loader_->StartLoadingBody(&client);
  Complete(net::OK);
  writer_.reset();
  EXPECT_THAT(client.TakeChunks(), ElementsAre("ABCDEFGH", ""));
}

}  // namespace

}  // namespace blink

"""

```