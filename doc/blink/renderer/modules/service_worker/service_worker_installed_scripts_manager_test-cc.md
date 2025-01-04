Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the test file, its relationship to web technologies, logical reasoning with input/output, common errors, and how to reach this code during debugging.

2. **Identify the Core Class Under Test:** The filename `service_worker_installed_scripts_manager_test.cc` immediately points to the class being tested: `ServiceWorkerInstalledScriptsManager`. The `#include` statement confirms this.

3. **Analyze the Test Fixture:**  The `ServiceWorkerInstalledScriptsManagerTest` class is the test fixture. It sets up the environment for testing. Key observations:
    * It creates two threads: `io_thread_` and `worker_thread_`. This suggests asynchronous behavior and the involvement of different threads in the actual `ServiceWorkerInstalledScriptsManager`.
    * It has a `worker_waiter_`, indicating synchronization between threads, likely for waiting for results on the worker thread.
    * The `CreateInstalledScriptsManager` method is crucial. It takes a `mojom::blink::ServiceWorkerInstalledScriptsInfoPtr` and instantiates the class under test. This hints at the interaction with Mojo for inter-process communication (IPC).

4. **Analyze the Helper Class `BrowserSideSender`:** This class simulates the browser process side of the communication. Key observations:
    * It implements the `mojom::blink::ServiceWorkerInstalledScriptsManagerHost` interface. This confirms the Mojo interaction.
    * `CreateAndBind` sets up the Mojo pipes and creates the `ServiceWorkerInstalledScriptsInfo`.
    * `TransferInstalledScript`, `PushBody`, `PushMetaData`, `FinishTransferBody`, `FinishTransferMetaData`  clearly simulate sending script content and metadata.
    * `WaitForRequestInstalledScript` suggests a mechanism where the renderer can request the script again if it's not already present.

5. **Analyze the Individual Test Cases:**  Each `TEST_F` represents a specific test scenario. Break them down:
    * **`GetRawScriptData`:** This is the core functionality test. It checks:
        * Initial `IsScriptInstalled` state.
        * Retrieval of script body and metadata.
        * Handling of subsequent requests for the same script (triggering `RequestInstalledScript`).
    * **`EarlyDisconnectionBody`:** Tests the scenario where the data pipe for the script body is closed prematurely. It checks that `GetRawScriptData` returns null.
    * **`EarlyDisconnectionMetaData`:** Similar to the above, but for the metadata pipe.
    * **`EarlyDisconnectionManager`:** Tests what happens when the entire Mojo connection is broken.

6. **Identify the Core Functionality:** Based on the test cases and the class under test, the core functionality is:
    * Managing a collection of installed scripts.
    * Providing access to the raw script content and metadata.
    * Handling asynchronous loading of scripts, potentially involving communication with the browser process.
    * Dealing with potential disconnections during the transfer.

7. **Relate to Web Technologies:**
    * **JavaScript:** Service Workers are used to intercept and handle network requests for a web application. The scripts managed here *are* JavaScript code. The test verifies the correct retrieval of this JavaScript.
    * **HTML:** Service Workers are registered for a specific scope within a web application defined in the HTML. While this test doesn't directly involve HTML parsing, the *concept* of a Service Worker and its registration is tied to HTML.
    * **CSS:** While less direct, Service Workers can potentially intercept requests for CSS files. This test focuses on JavaScript, but the underlying mechanism could apply to other resource types.

8. **Logical Reasoning (Input/Output):**  For `GetRawScriptData`, the input is a script URL. The output is either the raw script data (body, metadata, encoding, headers) or `nullptr` if the script isn't installed or if there's an error during transfer. The "BrowserSideSender" acts as a simulated browser, providing the script content.

9. **Common Usage Errors:** The "EarlyDisconnection" tests highlight potential errors:
    * **Browser process crashes:**  Simulated by `ResetManager()`.
    * **Network issues/transfer interruptions:** Simulated by closing the data pipes early.
    * **Incorrect size information:** The tests deliberately provide incorrect size information to simulate mismatches.

10. **Debugging Steps:**  Think about how a developer might end up looking at this test file:
    * **Investigating Service Worker loading issues:** If a Service Worker script fails to load or behaves unexpectedly, a developer might look at the code responsible for fetching and managing these scripts.
    * **Debugging crashes related to Mojo communication:** If there are crashes involving the `ServiceWorkerInstalledScriptsManager`, developers would examine the IPC mechanisms.
    * **Writing new tests for Service Worker features:**  Developers creating new Service Worker functionality might look at existing tests for guidance.

11. **Refine and Structure:** Organize the findings logically into the requested categories: Functionality, Relationship to web tech, Logical Reasoning, Common Errors, and Debugging. Use clear and concise language. Provide specific examples where necessary. For logical reasoning, explicitly state the "if...then..." relationships. For common errors, explain the *cause* of the error.

By following these steps, one can systematically analyze the C++ test file and provide a comprehensive answer to the request. The key is to understand the purpose of testing, identify the key components involved, and connect the code to the broader context of web technologies and potential problems.
这个 C++ 代码文件 `service_worker_installed_scripts_manager_test.cc` 是 Chromium Blink 引擎中用于测试 `ServiceWorkerInstalledScriptsManager` 类的单元测试。  `ServiceWorkerInstalledScriptsManager` 的主要职责是管理已安装的 Service Worker 的脚本，并提供访问这些脚本内容的能力。

**功能列表:**

1. **测试 `GetRawScriptData` 方法:** 测试从 `ServiceWorkerInstalledScriptsManager` 获取已安装 Service Worker 脚本的原始数据（脚本内容和元数据）的功能。涵盖了以下场景：
    * 首次获取已安装的脚本。
    * 再次获取相同的已安装脚本（会触发向浏览器进程的请求）。
    * 脚本内容和元数据的正确传输和解析。
    * 在脚本传输完成之前，`GetRawScriptData` 会被阻塞。
    * `IsScriptInstalled` 方法在脚本传输开始前就能正确判断脚本是否已安装。

2. **测试提前断开连接的情况:** 模拟在脚本传输过程中，浏览器进程（宿主）提前断开与渲染器进程的连接，测试 `ServiceWorkerInstalledScriptsManager` 的处理情况：
    * **提前断开 Body 数据管道:**  测试当脚本主体内容的数据管道提前关闭时，`GetRawScriptData` 是否返回空。
    * **提前断开 MetaData 数据管道:** 测试当脚本元数据的数据管道提前关闭时，`GetRawScriptData` 是否返回空。
    * **提前断开 Manager 连接:** 测试当整个 `ServiceWorkerInstalledScriptsManager` 的 Mojo 连接断开时，`GetRawScriptData` 是否返回空，并且后续的调用不会被阻塞。

**与 JavaScript, HTML, CSS 的关系:**

虽然此代码是 C++，但它直接关系到 Service Worker 的功能，而 Service Worker 是一个与 JavaScript 密切相关的 Web API。

* **JavaScript:**  `ServiceWorkerInstalledScriptsManager` 管理的脚本正是 Service Worker 的 JavaScript 代码。 这些脚本包含了 Service Worker 的逻辑，例如处理网络请求、缓存资源等。 测试中获取的 "This is a script body." 和 "This is another script body."  模拟的就是 JavaScript 代码的内容。
* **HTML:**  Service Worker 的注册和作用域是在 HTML 中通过 JavaScript 代码进行的。当浏览器加载包含 Service Worker 注册代码的 HTML 页面时，就会触发 Service Worker 的安装。 `ServiceWorkerInstalledScriptsManager` 负责管理这些已安装的 Service Worker 的脚本。
* **CSS:**  虽然此测试主要关注 JavaScript 脚本，但 Service Worker 同样可以拦截和处理 CSS 资源的请求。因此，`ServiceWorkerInstalledScriptsManager` 的管理范围也可能包括未来支持的 CSS Service Worker 脚本或其他类型的脚本。

**举例说明:**

假设一个 Service Worker 的 JavaScript 文件 `sw.js` 内容如下：

```javascript
// sw.js
self.addEventListener('fetch', event => {
  console.log('Fetching:', event.request.url);
  event.respondWith(fetch(event.request));
});
```

当浏览器安装了这个 Service Worker 后，`ServiceWorkerInstalledScriptsManager` 就负责存储和管理 `sw.js` 的内容。  测试用例 `GetRawScriptData` 中模拟的 "This is a script body."  就可能对应着 `sw.js` 的内容。

**逻辑推理 (假设输入与输出):**

**测试用例: `GetRawScriptData` (首次获取)**

* **假设输入:**
    * `kScriptUrl` = "https://example.com/installed1.js"
    * 浏览器进程发送脚本内容 "This is a script body." 和元数据 "This is a meta data."
* **预期输出:**
    * `IsScriptInstalled(kScriptUrl)` 在传输开始前返回 `true`。
    * `GetRawScriptData(kScriptUrl)` 返回一个包含以下数据的 `RawScriptData` 对象：
        * 脚本内容: "This is a script body."
        * 元数据: "This is a meta data."
        * 编码: "utf8"
        * Headers: {"Cache-Control": "no-cache", "User-Agent": "Chrome"}

**测试用例: `EarlyDisconnectionBody`**

* **假设输入:**
    * 浏览器进程声明脚本 body 大小为 100 字节，但实际只发送了 "This is a script body." (不足 100 字节)。
* **预期输出:**
    * `GetRawScriptData(kScriptUrl)` 返回 `nullptr`，因为 body 数据管道提前断开，导致数据不完整。

**涉及用户或编程常见的使用错误:**

这些测试主要关注框架内部的错误处理，但可以间接反映出一些用户或编程的常见错误：

* **Service Worker 脚本下载失败或不完整:**  `EarlyDisconnectionBody` 和 `EarlyDisconnectionMetaData` 测试模拟了这种情况。如果由于网络问题或其他原因，Service Worker 脚本的下载不完整，那么 `ServiceWorkerInstalledScriptsManager` 会检测到并返回错误，防止后续使用不完整的脚本。
* **浏览器进程崩溃:** `EarlyDisconnectionManager` 测试模拟了这种情况。如果浏览器进程意外崩溃，导致 Mojo 连接断开，渲染器进程应该能正确处理，避免程序崩溃或死锁。
* **错误的脚本大小声明:**  `EarlyDisconnectionBody` 和 `EarlyDisconnectionMetaData` 通过声明错误的大小来模拟浏览器进程传输数据时可能出现的错误。 这有助于确保渲染器进程能够验证数据的完整性。

**用户操作如何一步步的到达这里 (调试线索):**

一个开发者在调试 Service Worker 相关问题时，可能按照以下步骤到达这个测试文件：

1. **用户反馈 Service Worker 功能异常:**  例如，网页离线后无法正常工作，或者推送通知没有收到等。
2. **开发者开始调查 Service Worker 的生命周期和脚本加载:**  开发者可能会检查浏览器的开发者工具中的 "Application" -> "Service Workers" 面板，查看 Service Worker 的状态、注册信息以及是否有错误。
3. **如果发现脚本加载或更新有问题，开发者可能会查看 Blink 渲染引擎中负责处理 Service Worker 脚本加载和管理的模块:**  这就会涉及到 `blink/renderer/modules/service_worker` 目录。
4. **开发者可能会怀疑 `ServiceWorkerInstalledScriptsManager` 存在问题:**  因为它负责管理已安装的脚本。为了验证想法或理解其工作原理，开发者会查看 `service_worker_installed_scripts_manager.cc` 的实现代码。
5. **为了更深入地理解其功能和边界情况，开发者会查看对应的测试文件 `service_worker_installed_scripts_manager_test.cc`:**  通过阅读测试用例，开发者可以了解该类如何处理各种正常和异常情况，例如脚本的获取、连接断开等。
6. **如果开发者需要修改或修复 `ServiceWorkerInstalledScriptsManager` 的代码，他们会通过运行这些测试用例来验证修改的正确性，并确保没有引入新的 bug。**

总而言之，`service_worker_installed_scripts_manager_test.cc` 是一个至关重要的测试文件，它确保了 `ServiceWorkerInstalledScriptsManager` 类的正确性和健壮性，从而保证了 Service Worker 功能的稳定运行。开发者可以通过阅读和运行这些测试用例来理解和调试 Service Worker 相关的代码。

Prompt: 
```
这是目录为blink/renderer/modules/service_worker/service_worker_installed_scripts_manager_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/service_worker/service_worker_installed_scripts_manager.h"

#include <utility>

#include "base/containers/span.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_installed_scripts_manager.mojom-blink.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/web/web_embedded_worker.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

class BrowserSideSender
    : mojom::blink::ServiceWorkerInstalledScriptsManagerHost {
 public:
  BrowserSideSender() = default;

  BrowserSideSender(const BrowserSideSender&) = delete;
  BrowserSideSender& operator=(const BrowserSideSender&) = delete;

  ~BrowserSideSender() override = default;

  mojom::blink::ServiceWorkerInstalledScriptsInfoPtr CreateAndBind(
      const Vector<KURL>& installed_urls) {
    EXPECT_FALSE(manager_.is_bound());
    EXPECT_FALSE(body_handle_.is_valid());
    EXPECT_FALSE(meta_data_handle_.is_valid());
    auto scripts_info = mojom::blink::ServiceWorkerInstalledScriptsInfo::New();
    scripts_info->installed_urls = installed_urls;
    scripts_info->manager_receiver = manager_.BindNewPipeAndPassReceiver();
    receiver_.Bind(
        scripts_info->manager_host_remote.InitWithNewPipeAndPassReceiver());
    return scripts_info;
  }

  void TransferInstalledScript(const KURL& script_url,
                               const String& encoding,
                               const HashMap<String, String>& headers,
                               int64_t body_size,
                               int64_t meta_data_size) {
    EXPECT_FALSE(body_handle_.is_valid());
    EXPECT_FALSE(meta_data_handle_.is_valid());
    auto script_info = mojom::blink::ServiceWorkerScriptInfo::New();
    script_info->script_url = script_url;
    script_info->encoding = encoding;
    script_info->headers = headers;
    EXPECT_EQ(MOJO_RESULT_OK,
              mojo::CreateDataPipe(nullptr, body_handle_, script_info->body));
    EXPECT_EQ(MOJO_RESULT_OK, mojo::CreateDataPipe(nullptr, meta_data_handle_,
                                                   script_info->meta_data));
    script_info->body_size = body_size;
    script_info->meta_data_size = meta_data_size;
    manager_->TransferInstalledScript(std::move(script_info));
  }

  void PushBody(const String& data) {
    PushDataPipe(data.Utf8(), body_handle_.get());
  }

  void PushMetaData(const String& data) {
    PushDataPipe(data.Utf8(), meta_data_handle_.get());
  }

  void FinishTransferBody() { body_handle_.reset(); }

  void FinishTransferMetaData() { meta_data_handle_.reset(); }

  void ResetManager() { manager_.reset(); }

  void WaitForRequestInstalledScript(const KURL& script_url) {
    waiting_requested_url_ = script_url;
    base::RunLoop loop;
    requested_script_closure_ = loop.QuitClosure();
    loop.Run();
  }

 private:
  void RequestInstalledScript(const KURL& script_url) override {
    EXPECT_EQ(waiting_requested_url_, script_url);
    ASSERT_TRUE(requested_script_closure_);
    std::move(requested_script_closure_).Run();
  }

  // Send |data| with null terminator.
  void PushDataPipe(const std::string& data,
                    const mojo::DataPipeProducerHandle& handle) {
    ASSERT_TRUE(handle.is_valid());

    size_t actually_written_bytes = 0;
    MojoResult rv =
        handle.WriteData(base::as_byte_span(data), MOJO_WRITE_DATA_FLAG_NONE,
                         actually_written_bytes);
    ASSERT_EQ(MOJO_RESULT_OK, rv);
    ASSERT_EQ(data.size(), actually_written_bytes);

    char nul_char = '\0';
    rv = handle.WriteData(base::byte_span_from_ref(nul_char),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes);
    ASSERT_EQ(MOJO_RESULT_OK, rv);
    ASSERT_EQ(1u, actually_written_bytes);
  }

  base::OnceClosure requested_script_closure_;
  KURL waiting_requested_url_;

  mojo::Remote<mojom::blink::ServiceWorkerInstalledScriptsManager> manager_;
  mojo::Receiver<mojom::blink::ServiceWorkerInstalledScriptsManagerHost>
      receiver_{this};

  mojo::ScopedDataPipeProducerHandle body_handle_;
  mojo::ScopedDataPipeProducerHandle meta_data_handle_;
};

CrossThreadHTTPHeaderMapData ToCrossThreadHTTPHeaderMapData(
    const HashMap<String, String>& headers) {
  CrossThreadHTTPHeaderMapData data;
  for (const auto& entry : headers)
    data.emplace_back(entry.key, entry.value);
  return data;
}

}  // namespace

class ServiceWorkerInstalledScriptsManagerTest : public testing::Test {
 public:
  ServiceWorkerInstalledScriptsManagerTest()
      : io_thread_(NonMainThread::CreateThread(
            ThreadCreationParams(ThreadType::kTestThread)
                .SetThreadNameForTest("io thread"))),
        worker_thread_(NonMainThread::CreateThread(
            ThreadCreationParams(ThreadType::kTestThread)
                .SetThreadNameForTest("worker thread"))),
        worker_waiter_(std::make_unique<base::WaitableEvent>(
            base::WaitableEvent::ResetPolicy::AUTOMATIC,
            base::WaitableEvent::InitialState::NOT_SIGNALED)) {}

  ServiceWorkerInstalledScriptsManagerTest(
      const ServiceWorkerInstalledScriptsManagerTest&) = delete;
  ServiceWorkerInstalledScriptsManagerTest& operator=(
      const ServiceWorkerInstalledScriptsManagerTest&) = delete;

 protected:
  using RawScriptData = ThreadSafeScriptContainer::RawScriptData;

  void CreateInstalledScriptsManager(
      mojom::blink::ServiceWorkerInstalledScriptsInfoPtr
          installed_scripts_info) {
    auto installed_scripts_manager_params =
        std::make_unique<WebServiceWorkerInstalledScriptsManagerParams>(
            std::move(installed_scripts_info->installed_urls),
            std::move(installed_scripts_info->manager_receiver),
            std::move(installed_scripts_info->manager_host_remote));
    installed_scripts_manager_ =
        std::make_unique<ServiceWorkerInstalledScriptsManager>(
            std::move(installed_scripts_manager_params),
            io_thread_->GetTaskRunner());
  }

  base::WaitableEvent* IsScriptInstalledOnWorkerThread(const String& script_url,
                                                       bool* out_installed) {
    PostCrossThreadTask(
        *worker_thread_->GetTaskRunner(), FROM_HERE,
        CrossThreadBindOnce(
            [](ServiceWorkerInstalledScriptsManager* installed_scripts_manager,
               const String& script_url, bool* out_installed,
               base::WaitableEvent* waiter) {
              *out_installed = installed_scripts_manager->IsScriptInstalled(
                  KURL(script_url));
              waiter->Signal();
            },
            CrossThreadUnretained(installed_scripts_manager_.get()), script_url,
            CrossThreadUnretained(out_installed),
            CrossThreadUnretained(worker_waiter_.get())));
    return worker_waiter_.get();
  }

  base::WaitableEvent* GetRawScriptDataOnWorkerThread(
      const String& script_url,
      std::unique_ptr<RawScriptData>* out_data) {
    PostCrossThreadTask(
        *worker_thread_->GetTaskRunner(), FROM_HERE,
        CrossThreadBindOnce(
            &ServiceWorkerInstalledScriptsManagerTest::CallGetRawScriptData,
            CrossThreadUnretained(this), script_url,
            CrossThreadUnretained(out_data),
            CrossThreadUnretained(worker_waiter_.get())));
    return worker_waiter_.get();
  }

 private:
  void CallGetRawScriptData(const String& script_url,
                            std::unique_ptr<RawScriptData>* out_data,
                            base::WaitableEvent* waiter) {
    *out_data = installed_scripts_manager_->GetRawScriptData(KURL(script_url));
    waiter->Signal();
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<NonMainThread> io_thread_;
  std::unique_ptr<NonMainThread> worker_thread_;

  std::unique_ptr<base::WaitableEvent> worker_waiter_;

  std::unique_ptr<ServiceWorkerInstalledScriptsManager>
      installed_scripts_manager_;
};

TEST_F(ServiceWorkerInstalledScriptsManagerTest, GetRawScriptData) {
  const KURL kScriptUrl("https://example.com/installed1.js");
  const KURL kUnknownScriptUrl("https://example.com/not_installed.js");

  BrowserSideSender sender;
  CreateInstalledScriptsManager(sender.CreateAndBind({kScriptUrl}));

  {
    bool result = false;
    IsScriptInstalledOnWorkerThread(kScriptUrl, &result)->Wait();
    // IsScriptInstalled returns correct answer even before script transfer
    // hasn't been started yet.
    EXPECT_TRUE(result);
  }

  {
    bool result = true;
    IsScriptInstalledOnWorkerThread(kUnknownScriptUrl, &result)->Wait();
    // IsScriptInstalled returns correct answer even before script transfer
    // hasn't been started yet.
    EXPECT_FALSE(result);
  }

  {
    std::unique_ptr<RawScriptData> script_data;
    const String kExpectedBody = "This is a script body.";
    const String kExpectedMetaData = "This is a meta data.";
    const String kScriptInfoEncoding("utf8");
    const HashMap<String, String> kScriptInfoHeaders(
        {{"Cache-Control", "no-cache"}, {"User-Agent", "Chrome"}});

    base::WaitableEvent* get_raw_script_data_waiter =
        GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data);

    // Start transferring the script. +1 for null terminator.
    sender.TransferInstalledScript(
        kScriptUrl, kScriptInfoEncoding, kScriptInfoHeaders,
        kExpectedBody.length() + 1, kExpectedMetaData.length() + 1);
    sender.PushBody(kExpectedBody);
    sender.PushMetaData(kExpectedMetaData);
    // GetRawScriptData should be blocked until body and meta data transfer are
    // finished.
    EXPECT_FALSE(get_raw_script_data_waiter->IsSignaled());
    sender.FinishTransferBody();
    sender.FinishTransferMetaData();

    // Wait for the script's arrival.
    get_raw_script_data_waiter->Wait();
    EXPECT_TRUE(script_data);
    Vector<uint8_t> script_text = script_data->TakeScriptText();
    Vector<uint8_t> meta_data = script_data->TakeMetaData();
    ASSERT_EQ(kExpectedBody.length() + 1, script_text.size());
    EXPECT_EQ(kExpectedBody,
              String(reinterpret_cast<const char*>(script_text.data())));
    ASSERT_EQ(kExpectedMetaData.length() + 1, meta_data.size());
    EXPECT_EQ(kExpectedMetaData,
              String(reinterpret_cast<const char*>(meta_data.data())));
    EXPECT_EQ(kScriptInfoEncoding, script_data->Encoding());
    EXPECT_EQ(ToCrossThreadHTTPHeaderMapData(kScriptInfoHeaders),
              *(script_data->TakeHeaders()));
  }

  {
    std::unique_ptr<RawScriptData> script_data;
    const String kExpectedBody = "This is another script body.";
    const String kExpectedMetaData = "This is another meta data.";
    const String kScriptInfoEncoding("ASCII");
    const HashMap<String, String> kScriptInfoHeaders(
        {{"Connection", "keep-alive"}, {"Content-Length", "512"}});

    // Request the same script again.
    base::WaitableEvent* get_raw_script_data_waiter =
        GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data);

    // It should call a Mojo IPC "RequestInstalledScript()" to the browser.
    sender.WaitForRequestInstalledScript(kScriptUrl);

    // Start transferring the script. +1 for null terminator.
    sender.TransferInstalledScript(
        kScriptUrl, kScriptInfoEncoding, kScriptInfoHeaders,
        kExpectedBody.length() + 1, kExpectedMetaData.length() + 1);
    sender.PushBody(kExpectedBody);
    sender.PushMetaData(kExpectedMetaData);
    // GetRawScriptData should be blocked until body and meta data transfer are
    // finished.
    EXPECT_FALSE(get_raw_script_data_waiter->IsSignaled());
    sender.FinishTransferBody();
    sender.FinishTransferMetaData();

    // Wait for the script's arrival.
    get_raw_script_data_waiter->Wait();
    EXPECT_TRUE(script_data);
    Vector<uint8_t> script_text = script_data->TakeScriptText();
    Vector<uint8_t> meta_data = script_data->TakeMetaData();
    ASSERT_EQ(kExpectedBody.length() + 1, script_text.size());
    EXPECT_EQ(kExpectedBody,
              String(reinterpret_cast<const char*>(script_text.data())));
    ASSERT_EQ(kExpectedMetaData.length() + 1, meta_data.size());
    EXPECT_EQ(kExpectedMetaData,
              String(reinterpret_cast<const char*>(meta_data.data())));
    EXPECT_EQ(kScriptInfoEncoding, script_data->Encoding());
    EXPECT_EQ(ToCrossThreadHTTPHeaderMapData(kScriptInfoHeaders),
              *(script_data->TakeHeaders()));
  }
}

TEST_F(ServiceWorkerInstalledScriptsManagerTest, EarlyDisconnectionBody) {
  const KURL kScriptUrl("https://example.com/installed1.js");
  const KURL kUnknownScriptUrl("https://example.com/not_installed.js");

  BrowserSideSender sender;
  CreateInstalledScriptsManager(sender.CreateAndBind({kScriptUrl}));

  {
    std::unique_ptr<RawScriptData> script_data;
    const String kExpectedBody = "This is a script body.";
    const String kExpectedMetaData = "This is a meta data.";
    base::WaitableEvent* get_raw_script_data_waiter =
        GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data);

    // Start transferring the script.
    // Body is expected to be 100 bytes larger than kExpectedBody, but sender
    // only sends kExpectedBody and a null byte (kExpectedBody.length() + 1
    // bytes in total).
    sender.TransferInstalledScript(
        kScriptUrl, String::FromUTF8("utf8"), HashMap<String, String>(),
        kExpectedBody.length() + 100, kExpectedMetaData.length() + 1);
    sender.PushBody(kExpectedBody);
    sender.PushMetaData(kExpectedMetaData);
    // GetRawScriptData should be blocked until body and meta data transfer are
    // finished.
    EXPECT_FALSE(get_raw_script_data_waiter->IsSignaled());
    sender.FinishTransferBody();
    sender.FinishTransferMetaData();

    // Wait for the script's arrival.
    get_raw_script_data_waiter->Wait();
    // |script_data| should be null since the data pipe for body
    // gets disconnected during sending.
    EXPECT_FALSE(script_data);
  }

  {
    std::unique_ptr<RawScriptData> script_data;
    GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data)->Wait();
    // |script_data| should be null since the data wasn't received on the
    // renderer process.
    EXPECT_FALSE(script_data);
  }
}

TEST_F(ServiceWorkerInstalledScriptsManagerTest, EarlyDisconnectionMetaData) {
  const KURL kScriptUrl("https://example.com/installed1.js");
  const KURL kUnknownScriptUrl("https://example.com/not_installed.js");

  BrowserSideSender sender;
  CreateInstalledScriptsManager(sender.CreateAndBind({kScriptUrl}));

  {
    std::unique_ptr<RawScriptData> script_data;
    const String kExpectedBody = "This is a script body.";
    const String kExpectedMetaData = "This is a meta data.";
    base::WaitableEvent* get_raw_script_data_waiter =
        GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data);

    // Start transferring the script.
    // Meta data is expected to be 100 bytes larger than kExpectedMetaData, but
    // sender only sends kExpectedMetaData and a null byte
    // (kExpectedMetaData.length() + 1 bytes in total).
    sender.TransferInstalledScript(
        kScriptUrl, String::FromUTF8("utf8"), HashMap<String, String>(),
        kExpectedBody.length() + 1, kExpectedMetaData.length() + 100);
    sender.PushBody(kExpectedBody);
    sender.PushMetaData(kExpectedMetaData);
    // GetRawScriptData should be blocked until body and meta data transfer are
    // finished.
    EXPECT_FALSE(get_raw_script_data_waiter->IsSignaled());
    sender.FinishTransferBody();
    sender.FinishTransferMetaData();

    // Wait for the script's arrival.
    get_raw_script_data_waiter->Wait();
    // |script_data| should be null since the data pipe for meta data gets
    // disconnected during sending.
    EXPECT_FALSE(script_data);
  }

  {
    std::unique_ptr<RawScriptData> script_data;
    GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data)->Wait();
    // |script_data| should be null since the data wasn't received on the
    // renderer process.
    EXPECT_FALSE(script_data);
  }
}

TEST_F(ServiceWorkerInstalledScriptsManagerTest, EarlyDisconnectionManager) {
  const KURL kScriptUrl("https://example.com/installed1.js");
  const KURL kUnknownScriptUrl("https://example.com/not_installed.js");

  BrowserSideSender sender;
  CreateInstalledScriptsManager(sender.CreateAndBind({kScriptUrl}));

  {
    std::unique_ptr<RawScriptData> script_data;
    base::WaitableEvent* get_raw_script_data_waiter =
        GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data);

    // Reset the Mojo connection before sending the script.
    EXPECT_FALSE(get_raw_script_data_waiter->IsSignaled());
    sender.ResetManager();

    // Wait for the script's arrival.
    get_raw_script_data_waiter->Wait();
    // |script_data| should be nullptr since no data will arrive.
    EXPECT_FALSE(script_data);
  }

  {
    std::unique_ptr<RawScriptData> script_data;
    // This should not be blocked because data will not arrive anymore.
    GetRawScriptDataOnWorkerThread(kScriptUrl, &script_data)->Wait();
    // |script_data| should be null since the data wasn't received on the
    // renderer process.
    EXPECT_FALSE(script_data);
  }
}

}  // namespace blink

"""

```