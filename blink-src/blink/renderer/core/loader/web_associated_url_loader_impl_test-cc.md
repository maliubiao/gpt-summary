Response:
The user wants to understand the functionality of the `web_associated_url_loader_impl_test.cc` file in the Chromium Blink engine.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the Core Purpose:** The file name ends with `_test.cc`. This strongly suggests it's a unit test file. Unit tests are designed to verify the correct behavior of specific components or functionalities. The name `WebAssociatedURLLoaderImplTest` further indicates it tests the implementation of `WebAssociatedURLLoader`.

2. **Examine the Includes:** The included headers provide clues about the functionalities being tested. Key includes are:
    * `testing/gtest/include/gtest/gtest.h`:  Indicates the use of the Google Test framework for testing.
    * `third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h`:  Points to the testing of how associated URL loaders interact with fetch requests.
    * `third_party/blink/public/platform/web_url.h`, `web_url_request.h`, `web_url_response.h`: Shows that the tests involve making URL requests and handling responses.
    * `third_party/blink/public/web/web_associated_url_loader.h`, `web_associated_url_loader_client.h`, `web_associated_url_loader_options.h`:  These are the primary interfaces being tested.
    * `third_party/blink/public/web/web_frame.h`, `web_view.h`: Suggests the tests are performed within the context of a web frame and view.
    * `third_party/blink/renderer/core/frame/frame_test_helpers.h`, `web_local_frame_impl.h`:  Indicates the use of test helpers for setting up frame environments.
    * `third_party/blink/renderer/platform/testing/url_loader_mock_factory.h`, `url_test_helpers.h`: Implies that network requests are being mocked for controlled testing.

3. **Analyze the Test Class:** The `WebAssociatedURLLoaderTest` class inherits from `testing::Test` and `WebAssociatedURLLoaderClient`. This means it's a test fixture and it implements the client interface to receive callbacks from the `WebAssociatedURLLoader`.

4. **Identify Key Test Methods:**  The `TEST_F` macros define individual test cases. Skimming through the test names provides insights into the tested scenarios:
    * `SameOriginSuccess`, `SameOriginRestriction`: Testing same-origin policy.
    * `CrossOriginSuccess`: Testing cross-origin requests.
    * `RedirectSuccess`, `RedirectCrossOriginFailure`, `RedirectCrossOriginWithAccessControlSuccess`: Testing HTTP redirects and CORS interactions with redirects.
    * `UntrustedCheckMethods`, `UntrustedCheckHeaders`: Testing restrictions on HTTP methods and headers for "untrusted" loads.
    * `CrossOriginHeaderSafelisting`, `CrossOriginHeaderAllowResponseHeaders`: Testing CORS header filtering and allowing non-safelisted headers.
    * `AccessCheckForLocalURL`, `BypassAccessCheckForLocalURL`: Testing access restrictions for local file URLs and how to bypass them.

5. **Connect to Web Concepts:** Based on the test names and included headers, establish connections to web technologies:
    * **JavaScript:** While not directly manipulating JavaScript code, the tests simulate scenarios triggered by JavaScript's `fetch` API or `XMLHttpRequest`, which rely on the underlying network stack. The tests verify the browser's security and request handling logic that JavaScript interacts with.
    * **HTML:** The tests often involve loading HTML files (`iframes_test.html`) and testing behaviors related to frames and resource loading initiated by HTML.
    * **CSS:**  While not explicitly tested, CSS loading relies on the same underlying network mechanisms. The principles of same-origin policy and CORS apply to CSS requests as well.

6. **Construct Example Scenarios:** For each relevant web technology, devise concrete examples to illustrate the connection. For instance, for JavaScript, show a `fetch` call that would trigger the tested code.

7. **Explain Logic and Assumptions:** For tests involving conditional behavior (like CORS), describe the assumptions and expected outcomes. For example, explain why a cross-origin redirect fails by default and succeeds with correct CORS headers.

8. **Identify Potential User Errors:** Think about common mistakes developers make related to cross-origin requests, forbidden headers, or local file access. Connect these errors to the tested scenarios.

9. **Trace User Actions:**  Consider how a user's action in a web browser (e.g., clicking a link, submitting a form, a JavaScript making a request) might lead to the execution of the code being tested. This involves understanding the browser's request lifecycle.

10. **Outline Debugging Steps:** Describe how a developer could use breakpoints or logging in the `WebAssociatedURLLoaderImpl` code (the counterpart to the test file) to investigate issues related to the tested scenarios.

11. **Structure the Answer:** Organize the information logically with clear headings and examples. Start with a high-level overview of the file's purpose, then delve into specifics, connecting the tests to web technologies, user errors, and debugging.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the C++ implementation details. The user's request asks for connections to web technologies, so I need to shift the focus towards the *behavior* being tested and how it relates to JavaScript, HTML, and CSS.
*  I need to be careful not to overstate the direct involvement of JavaScript/HTML/CSS *within* the test file itself. The test file *simulates* requests that these technologies might initiate.
* I should ensure the examples are clear and concise, illustrating the specific point being made.
* I need to explicitly state the assumptions in the logical reasoning, especially for CORS-related tests.
* The debugging section should be practical and relevant to someone working with the Chromium codebase.
这个文件 `blink/renderer/core/loader/web_associated_url_loader_impl_test.cc` 是 Chromium Blink 渲染引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `WebAssociatedURLLoaderImpl` 类的行为**。`WebAssociatedURLLoaderImpl` 负责在渲染进程中加载与当前文档关联的资源，例如通过脚本发起的网络请求 (如 `fetch` API 调用) 或者一些内部资源加载。

更具体地说，这个测试文件会模拟各种场景，验证 `WebAssociatedURLLoaderImpl` 在不同条件下的行为是否符合预期，包括：

**核心功能测试:**

* **成功加载资源 (Same-Origin 和 Cross-Origin):** 测试在同源和跨域情况下，成功加载资源的能力。
* **处理 HTTP 重定向:** 测试能否正确处理同源和跨域的 HTTP 重定向。
* **CORS (跨域资源共享) 机制:** 重点测试与 CORS 相关的行为，例如：
    * 同源策略的默认限制。
    * 跨域请求的成功加载（需要服务器返回正确的 CORS 头部）。
    * 跨域重定向的限制和成功情况（需要服务器返回正确的 CORS 头部）。
    * 响应头部的过滤（根据 CORS 规范，一些头部默认不暴露给脚本）。
    * 允许暴露非安全列表的响应头。
* **安全性检查:**
    * **禁止使用某些 HTTP 方法 (Untrusted Check Methods):** 测试是否阻止使用不安全的 HTTP 方法，例如 `CONNECT`, `TRACE`。
    * **禁止设置某些 HTTP 请求头部 (Untrusted Check Headers):** 测试是否阻止设置敏感的 HTTP 请求头部，例如 `Cookie`, `Origin`, `Referer` 等。
    * **本地 URL 的访问控制 (AccessCheckForLocalURL):** 测试默认情况下是否禁止访问本地文件 URL。
    * **绕过本地 URL 的访问控制 (BypassAccessCheckForLocalURL):** 测试在特定配置下是否可以绕过本地文件访问限制。

**与 JavaScript, HTML, CSS 的关系举例:**

`WebAssociatedURLLoaderImpl` 直接参与处理由 JavaScript 发起的网络请求，也影响着 HTML 和 CSS 资源的加载。

**1. JavaScript (fetch API):**

* **假设输入:** 一个网页中的 JavaScript 代码使用 `fetch` API 发起一个跨域请求：
  ```javascript
  fetch('http://www.other.com/data.json')
    .then(response => response.json())
    .then(data => console.log(data));
  ```
* **测试场景 (对应测试文件中的 `CrossOriginSuccess`):** `WebAssociatedURLLoaderImpl` 会处理这个 `fetch` 请求。如果服务器 `http://www.other.com/data.json` 返回了正确的 CORS 头部 (`Access-Control-Allow-Origin: *` 或包含当前域名)，`WebAssociatedURLLoaderImpl` 会允许加载，并最终将数据传递给 JavaScript。
* **测试场景 (对应测试文件中的 `SameOriginRestriction`):** 如果服务器没有返回 CORS 头部，且请求是跨域的，`WebAssociatedURLLoaderImpl` 会阻止加载，导致 `fetch` API 抛出网络错误。

**2. HTML (<img> 标签的跨域图片加载):**

* **假设输入:** 一个 HTML 页面包含一个 `<img>` 标签，指向一个跨域的图片资源：
  ```html
  <img src="http://www.other.com/image.png">
  ```
* **测试场景 (虽然测试文件没有直接测试 `<img>`，但原理相同):** 当浏览器解析到这个 `<img>` 标签时，会触发一个资源加载请求，这个请求也可能由 `WebAssociatedURLLoaderImpl` 处理。如果 `http://www.other.com/image.png` 服务器返回了允许跨域访问的 CORS 头部，图片就能正常显示。否则，浏览器可能会阻止图片的加载（取决于具体的 CORS 配置）。

**3. CSS (@font-face 规则加载跨域字体):**

* **假设输入:** 一个 CSS 文件包含 `@font-face` 规则，尝试加载一个跨域字体：
  ```css
  @font-face {
    font-family: 'MyFont';
    src: url('http://www.other.com/font.woff2');
  }
  ```
* **测试场景 (虽然测试文件没有直接测试字体加载，但原理相同):**  浏览器在渲染页面时，会尝试加载这个跨域字体。`WebAssociatedURLLoaderImpl` 会参与处理这个请求。服务器需要返回适当的 CORS 头部 (`Access-Control-Allow-Origin` 和 `Access-Control-Allow-Headers`，可能包含 `Origin`) 才能让字体加载成功。

**逻辑推理的假设输入与输出:**

**示例 1: 测试禁止设置 `Cookie` 请求头 (对应 `UntrustedCheckHeaders`):**

* **假设输入:** JavaScript 代码尝试使用 `fetch` API 并手动设置 `Cookie` 请求头：
  ```javascript
  fetch('http://www.test.com/api', {
    headers: {
      'Cookie': 'my_session_id=12345'
    }
  });
  ```
* **`WebAssociatedURLLoaderImpl` 的处理:**  `UntrustedCheckHeaders` 测试会模拟这个场景。`WebAssociatedURLLoaderImpl` 会检查请求头，发现 `Cookie` 是被禁止的头部。
* **输出:**  `WebAssociatedURLLoaderImpl` 会阻止这个请求的发送，并可能触发一个错误回调。测试代码会断言 `did_fail_` 标志被设置为 `true`。

**示例 2: 测试跨域重定向失败 (对应 `RedirectCrossOriginFailure`):**

* **假设输入:**  一个网页请求 `http://www.test.com/page1`，服务器 `page1` 返回一个 HTTP 重定向到 `http://www.other.com/page2`。
* **`WebAssociatedURLLoaderImpl` 的处理:** `RedirectCrossOriginFailure` 测试会模拟这个场景。由于默认情况下不允许跨域重定向，`WebAssociatedURLLoaderImpl` 会阻止这次重定向。
* **输出:** 测试代码会断言 `will_follow_redirect_` 标志为 `false`，表明没有跟随重定向，并且后续的响应接收标志 (`did_receive_response_`, `did_receive_data_`, `did_finish_loading_`) 也为 `false`。

**用户或编程常见的使用错误举例:**

1. **忘记设置 CORS 头部:**  开发者在搭建 API 服务器时，经常忘记为跨域请求设置正确的 CORS 头部，导致前端 JavaScript 代码无法访问 API 资源。`WebAssociatedURLLoaderImpl` 会阻止这些请求，这是符合浏览器安全策略的。

   ```
   // 服务器端 (例如 Node.js + Express): 错误的 CORS 配置
   app.get('/api/data', (req, res) => {
     // 缺少 Access-Control-Allow-Origin 头部
     res.json({ message: 'Hello' });
   });

   // 前端 JavaScript: 跨域请求会失败
   fetch('http://api.example.com/api/data') // 假设当前页面在另一个域名
     .then(response => response.json()) // 会进入错误处理
     .catch(error => console.error("CORS error:", error));
   ```

2. **尝试手动设置被禁止的请求头:** 开发者可能会尝试使用 `fetch` 或 `XMLHttpRequest` 手动设置一些被浏览器禁止的请求头，例如 `Cookie` 或 `Origin`。`WebAssociatedURLLoaderImpl` 会阻止这些操作，以防止潜在的安全问题。

   ```javascript
   fetch('http://www.example.com', {
     headers: {
       'Cookie': 'some_value' // 浏览器会忽略或阻止设置
     }
   });
   ```

3. **不理解跨域重定向的限制:**  开发者可能会假设跨域重定向会自动跟随，但浏览器出于安全考虑，默认会阻止跨域重定向。需要服务器返回包含 CORS 信息的重定向响应才能允许。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页。**
2. **网页中的 JavaScript 代码执行，发起一个网络请求 (例如使用 `fetch` API)。**
3. **浏览器接收到 JavaScript 的请求指令。**
4. **浏览器内部会创建一个 `WebAssociatedURLLoaderImpl` 实例来处理这个请求。**
5. **`WebAssociatedURLLoaderImpl` 根据请求的 URL、方法、头部等信息，以及当前的浏览器安全策略 (例如同源策略、CORS)，执行相应的加载逻辑。**
6. **如果请求是跨域的，`WebAssociatedURLLoaderImpl` 会检查服务器返回的 CORS 头部。**
7. **如果一切正常，资源会被加载，并通过回调通知 JavaScript 代码。**
8. **如果出现错误 (例如 CORS 错误，网络错误)，`WebAssociatedURLLoaderImpl` 会触发相应的错误处理流程。**

**调试线索:**

当遇到与资源加载相关的问题时，可以考虑以下调试步骤，可能会涉及到 `WebAssociatedURLLoaderImpl` 的代码：

1. **浏览器开发者工具的网络面板:** 查看网络请求的状态、请求头、响应头，以及任何 CORS 相关的错误信息。
2. **在 Chromium 源代码中设置断点:** 如果怀疑 `WebAssociatedURLLoaderImpl` 的行为有问题，可以在以下关键位置设置断点进行调试：
   * `WebAssociatedURLLoaderImpl::LoadAsynchronously`: 请求加载的入口点。
   * 与 CORS 相关的检查逻辑，例如检查 `Access-Control-Allow-Origin` 头部的地方。
   * 处理重定向的逻辑。
   * 检查禁止的 HTTP 方法和头部的逻辑。
3. **查看 Chromium 的网络日志:** Chromium 有详细的网络日志，可以提供更底层的网络请求信息。
4. **使用 `//net/` 组件的调试工具:** Chromium 的网络层 (`//net/`) 提供了更底层的网络调试工具，可以帮助分析网络请求的细节。

总而言之，`blink/renderer/core/loader/web_associated_url_loader_impl_test.cc` 是一个至关重要的测试文件，它确保了 `WebAssociatedURLLoaderImpl` 这个核心组件能够正确、安全地处理各种资源加载场景，特别是与 Web 安全模型 (如同源策略和 CORS) 相关的场景，这直接影响着 JavaScript、HTML 和 CSS 资源的加载和网页的正常运行。

Prompt: 
```
这是目录为blink/renderer/core/loader/web_associated_url_loader_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <memory>

#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/web_associated_url_loader.h"
#include "third_party/blink/public/web/web_associated_url_loader_client.h"
#include "third_party/blink/public/web/web_associated_url_loader_options.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

using blink::test::RunPendingTasks;
using blink::url_test_helpers::ToKURL;

namespace blink {

class WebAssociatedURLLoaderTest : public testing::Test,
                                   public WebAssociatedURLLoaderClient {
 public:
  WebAssociatedURLLoaderTest()
      : will_follow_redirect_(false),
        did_send_data_(false),
        did_receive_response_(false),
        did_receive_data_(false),
        did_finish_loading_(false),
        did_fail_(false) {
    // Reuse one of the test files from WebFrameTest.
    frame_file_path_ = test::CoreTestDataPath("iframes_test.html");
  }

  void RegisterMockedURLLoadWithCustomResponse(const WebURL& full_url,
                                               WebURLResponse response,
                                               const WebString& file_path) {
    url_test_helpers::RegisterMockedURLLoadWithCustomResponse(
        full_url, file_path, response);
  }

  KURL RegisterMockedUrl(const std::string& url_root,
                         const WTF::String& filename) {
    WebURLResponse response;
    response.SetMimeType("text/html");
    KURL url = ToKURL(url_root + filename.Utf8());
    RegisterMockedURLLoadWithCustomResponse(
        url, response, test::CoreTestDataPath(filename.Utf8().c_str()));
    return url;
  }

  void SetUp() override {
    helper_.Initialize();

    std::string url_root = "http://www.test.com/";
    KURL url = RegisterMockedUrl(url_root, "iframes_test.html");
    const char* iframe_support_files[] = {
        "invisible_iframe.html",
        "visible_iframe.html",
        "zero_sized_iframe.html",
    };
    for (size_t i = 0; i < std::size(iframe_support_files); ++i) {
      RegisterMockedUrl(url_root, iframe_support_files[i]);
    }

    frame_test_helpers::LoadFrame(MainFrame(), url.GetString().Utf8().c_str());

    url_test_helpers::RegisterMockedURLUnregister(url);
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void ServeRequests() { url_test_helpers::ServeAsynchronousRequests(); }

  std::unique_ptr<WebAssociatedURLLoader> CreateAssociatedURLLoader(
      const WebAssociatedURLLoaderOptions options =
          WebAssociatedURLLoaderOptions()) {
    return MainFrame()->CreateAssociatedURLLoader(options);
  }

  // WebAssociatedURLLoaderClient implementation.
  bool WillFollowRedirect(const WebURL& new_url,
                          const WebURLResponse& redirect_response) override {
    will_follow_redirect_ = true;
    EXPECT_EQ(expected_new_url_, new_url);
    EXPECT_EQ(expected_redirect_response_.CurrentRequestUrl(),
              redirect_response.CurrentRequestUrl());
    EXPECT_EQ(expected_redirect_response_.HttpStatusCode(),
              redirect_response.HttpStatusCode());
    EXPECT_EQ(expected_redirect_response_.MimeType(),
              redirect_response.MimeType());
    return true;
  }

  void DidSendData(uint64_t bytes_sent,
                   uint64_t total_bytes_to_be_sent) override {
    did_send_data_ = true;
  }

  void DidReceiveResponse(const WebURLResponse& response) override {
    did_receive_response_ = true;
    actual_response_ = WebURLResponse(response);
    EXPECT_EQ(expected_response_.CurrentRequestUrl(),
              response.CurrentRequestUrl());
    EXPECT_EQ(expected_response_.HttpStatusCode(), response.HttpStatusCode());
  }

  void DidDownloadData(uint64_t data_length) override {
    did_download_data_ = true;
  }

  void DidReceiveData(base::span<const char> data) override {
    did_receive_data_ = true;
    EXPECT_TRUE(data.data());
    EXPECT_GT(data.size(), 0u);
  }

  void DidFinishLoading() override { did_finish_loading_ = true; }

  void DidFail(const WebURLError& error) override { did_fail_ = true; }

  void CheckMethodFails(const char* unsafe_method) {
    WebURLRequest request(ToKURL("http://www.test.com/success.html"));
    request.SetMode(network::mojom::RequestMode::kSameOrigin);
    request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
    request.SetHttpMethod(WebString::FromUTF8(unsafe_method));
    WebAssociatedURLLoaderOptions options;
    options.untrusted_http = true;
    CheckFails(request, options);
  }

  void CheckHeaderFails(const char* header_field) {
    CheckHeaderFails(header_field, "foo");
  }

  void CheckHeaderFails(const char* header_field, const char* header_value) {
    WebURLRequest request(ToKURL("http://www.test.com/success.html"));
    request.SetMode(network::mojom::RequestMode::kSameOrigin);
    request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
    if (EqualIgnoringASCIICase(WebString::FromUTF8(header_field), "referer")) {
      request.SetReferrerString(WebString::FromUTF8(header_value));
      request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kDefault);
    } else {
      request.SetHttpHeaderField(WebString::FromUTF8(header_field),
                                 WebString::FromUTF8(header_value));
    }

    WebAssociatedURLLoaderOptions options;
    options.untrusted_http = true;
    CheckFails(request, options);
  }

  void CheckFails(
      const WebURLRequest& request,
      WebAssociatedURLLoaderOptions options = WebAssociatedURLLoaderOptions()) {
    expected_loader_ = CreateAssociatedURLLoader(options);
    EXPECT_TRUE(expected_loader_);
    did_fail_ = false;
    expected_loader_->LoadAsynchronously(request, this);
    // Failure should not be reported synchronously.
    EXPECT_FALSE(did_fail_);
    // Allow the loader to return the error.
    RunPendingTasks();
    EXPECT_TRUE(did_fail_);
    EXPECT_FALSE(did_receive_response_);
  }

  bool CheckAccessControlHeaders(const char* header_name, bool exposed) {
    std::string id("http://www.other.com/CheckAccessControlExposeHeaders_");
    id.append(header_name);
    if (exposed)
      id.append("-Exposed");
    id.append(".html");

    KURL url = ToKURL(id);
    WebURLRequest request(url);
    request.SetMode(network::mojom::RequestMode::kCors);
    request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

    WebString header_name_string(WebString::FromUTF8(header_name));
    expected_response_ = WebURLResponse();
    expected_response_.SetMimeType("text/html");
    expected_response_.SetHttpStatusCode(200);
    expected_response_.AddHttpHeaderField("Access-Control-Allow-Origin", "*");
    if (exposed) {
      expected_response_.AddHttpHeaderField("access-control-expose-headers",
                                            header_name_string);
    }
    expected_response_.AddHttpHeaderField(header_name_string, "foo");
    RegisterMockedURLLoadWithCustomResponse(url, expected_response_,
                                            frame_file_path_);

    WebAssociatedURLLoaderOptions options;
    expected_loader_ = CreateAssociatedURLLoader(options);
    EXPECT_TRUE(expected_loader_);
    expected_loader_->LoadAsynchronously(request, this);
    ServeRequests();
    EXPECT_TRUE(did_receive_response_);
    EXPECT_TRUE(did_receive_data_);
    EXPECT_TRUE(did_finish_loading_);

    return !actual_response_.HttpHeaderField(header_name_string).IsEmpty();
  }

  WebLocalFrameImpl* MainFrame() const {
    return helper_.GetWebView()->MainFrameImpl();
  }

 protected:
  test::TaskEnvironment task_environment_;
  String frame_file_path_;
  frame_test_helpers::WebViewHelper helper_;

  std::unique_ptr<WebAssociatedURLLoader> expected_loader_;
  WebURLResponse actual_response_;
  WebURLResponse expected_response_;
  WebURL expected_new_url_;
  WebURLResponse expected_redirect_response_;
  bool will_follow_redirect_;
  bool did_send_data_;
  bool did_receive_response_;
  bool did_download_data_;
  bool did_receive_data_;
  bool did_finish_loading_;
  bool did_fail_;
};

// Test a successful same-origin URL load.
TEST_F(WebAssociatedURLLoaderTest, SameOriginSuccess) {
  KURL url = ToKURL("http://www.test.com/SameOriginSuccess.html");
  WebURLRequest request(url);
  request.SetMode(network::mojom::RequestMode::kSameOrigin);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/html");
  expected_response_.SetHttpStatusCode(200);
  RegisterMockedURLLoadWithCustomResponse(url, expected_response_,
                                          frame_file_path_);

  expected_loader_ = CreateAssociatedURLLoader();
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);
  ServeRequests();
  EXPECT_TRUE(did_receive_response_);
  EXPECT_TRUE(did_receive_data_);
  EXPECT_TRUE(did_finish_loading_);
}

// Test that the same-origin restriction is the default.
TEST_F(WebAssociatedURLLoaderTest, SameOriginRestriction) {
  // This is cross-origin since the frame was loaded from www.test.com.
  KURL url = ToKURL("http://www.other.com/SameOriginRestriction.html");
  WebURLRequest request(url);
  request.SetMode(network::mojom::RequestMode::kSameOrigin);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
  CheckFails(request);
}

// Test a successful cross-origin load.
TEST_F(WebAssociatedURLLoaderTest, CrossOriginSuccess) {
  // This is cross-origin since the frame was loaded from www.test.com.
  KURL url = ToKURL("http://www.other.com/CrossOriginSuccess");
  WebURLRequest request(url);
  // No-CORS requests (CrossOriginRequestPolicyAllow) aren't allowed for the
  // default context. So we set the context as Script here.
  request.SetRequestContext(mojom::blink::RequestContextType::SCRIPT);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/html");
  expected_response_.SetHttpStatusCode(200);
  RegisterMockedURLLoadWithCustomResponse(url, expected_response_,
                                          frame_file_path_);

  WebAssociatedURLLoaderOptions options;
  expected_loader_ = CreateAssociatedURLLoader(options);
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);
  ServeRequests();
  EXPECT_TRUE(did_receive_response_);
  EXPECT_TRUE(did_receive_data_);
  EXPECT_TRUE(did_finish_loading_);
}

// Test a same-origin URL redirect and load.
TEST_F(WebAssociatedURLLoaderTest, RedirectSuccess) {
  KURL url = ToKURL("http://www.test.com/RedirectSuccess.html");
  char redirect[] = "http://www.test.com/RedirectSuccess2.html";  // Same-origin
  KURL redirect_url = ToKURL(redirect);

  WebURLRequest request(url);
  request.SetMode(network::mojom::RequestMode::kSameOrigin);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

  expected_redirect_response_ = WebURLResponse();
  expected_redirect_response_.SetMimeType("text/html");
  expected_redirect_response_.SetHttpStatusCode(301);
  expected_redirect_response_.SetHttpHeaderField("Location", redirect);
  RegisterMockedURLLoadWithCustomResponse(url, expected_redirect_response_,
                                          frame_file_path_);

  expected_new_url_ = WebURL(redirect_url);

  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/html");
  expected_response_.SetHttpStatusCode(200);
  RegisterMockedURLLoadWithCustomResponse(redirect_url, expected_response_,
                                          frame_file_path_);

  expected_loader_ = CreateAssociatedURLLoader();
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);
  ServeRequests();
  EXPECT_TRUE(will_follow_redirect_);
  EXPECT_TRUE(did_receive_response_);
  EXPECT_TRUE(did_receive_data_);
  EXPECT_TRUE(did_finish_loading_);
}

// Test a cross-origin URL redirect without Access Control set.
TEST_F(WebAssociatedURLLoaderTest, RedirectCrossOriginFailure) {
  KURL url = ToKURL("http://www.test.com/RedirectCrossOriginFailure.html");
  char redirect[] =
      "http://www.other.com/RedirectCrossOriginFailure.html";  // Cross-origin
  KURL redirect_url = ToKURL(redirect);

  WebURLRequest request(url);
  request.SetMode(network::mojom::RequestMode::kSameOrigin);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

  expected_redirect_response_ = WebURLResponse();
  expected_redirect_response_.SetMimeType("text/html");
  expected_redirect_response_.SetHttpStatusCode(301);
  expected_redirect_response_.SetHttpHeaderField("Location", redirect);
  RegisterMockedURLLoadWithCustomResponse(url, expected_redirect_response_,
                                          frame_file_path_);

  expected_new_url_ = WebURL(redirect_url);

  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/html");
  expected_response_.SetHttpStatusCode(200);
  RegisterMockedURLLoadWithCustomResponse(redirect_url, expected_response_,
                                          frame_file_path_);

  expected_loader_ = CreateAssociatedURLLoader();
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);

  ServeRequests();
  EXPECT_FALSE(will_follow_redirect_);
  EXPECT_FALSE(did_receive_response_);
  EXPECT_FALSE(did_receive_data_);
  EXPECT_FALSE(did_finish_loading_);
}

// Test that a cross origin redirect response with CORS headers that allow the
// requesting origin succeeds.
TEST_F(WebAssociatedURLLoaderTest,
       RedirectCrossOriginWithAccessControlSuccess) {
  KURL url = ToKURL(
      "http://www.test.com/RedirectCrossOriginWithAccessControlSuccess.html");
  char redirect[] =
      "http://www.other.com/"
      "RedirectCrossOriginWithAccessControlSuccess.html";  // Cross-origin
  KURL redirect_url = ToKURL(redirect);

  WebURLRequest request(url);
  request.SetMode(network::mojom::RequestMode::kCors);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
  // Add a CORS simple header.
  request.SetHttpHeaderField("accept", "application/json");

  // Create a redirect response that allows the redirect to pass the access
  // control checks.
  expected_redirect_response_ = WebURLResponse();
  expected_redirect_response_.SetMimeType("text/html");
  expected_redirect_response_.SetHttpStatusCode(301);
  expected_redirect_response_.SetHttpHeaderField("Location", redirect);
  expected_redirect_response_.AddHttpHeaderField("access-control-allow-origin",
                                                 "*");
  RegisterMockedURLLoadWithCustomResponse(url, expected_redirect_response_,
                                          frame_file_path_);

  expected_new_url_ = WebURL(redirect_url);

  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/html");
  expected_response_.SetHttpStatusCode(200);
  expected_response_.AddHttpHeaderField("access-control-allow-origin", "*");
  RegisterMockedURLLoadWithCustomResponse(redirect_url, expected_response_,
                                          frame_file_path_);

  WebAssociatedURLLoaderOptions options;
  expected_loader_ = CreateAssociatedURLLoader(options);
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);
  ServeRequests();
  EXPECT_TRUE(will_follow_redirect_);
  EXPECT_TRUE(did_receive_response_);
  EXPECT_TRUE(did_receive_data_);
  EXPECT_TRUE(did_finish_loading_);
}

// Test that untrusted loads can't use a forbidden method.
TEST_F(WebAssociatedURLLoaderTest, UntrustedCheckMethods) {
  // Check non-token method fails.
  CheckMethodFails("GET()");
  CheckMethodFails("POST\x0d\x0ax-csrf-token:\x20test1234");

  // Forbidden methods should fail regardless of casing.
  CheckMethodFails("CoNneCt");
  CheckMethodFails("TrAcK");
  CheckMethodFails("TrAcE");
}

// This test is flaky on Windows and Android. See <http://crbug.com/471645>.
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_ANDROID)
#define MAYBE_UntrustedCheckHeaders DISABLED_UntrustedCheckHeaders
#else
#define MAYBE_UntrustedCheckHeaders UntrustedCheckHeaders
#endif

// Test that untrusted loads can't use a forbidden header field.
TEST_F(WebAssociatedURLLoaderTest, MAYBE_UntrustedCheckHeaders) {
  // Check non-token header fails.
  CheckHeaderFails("foo()");

  // Check forbidden headers fail.
  CheckHeaderFails("accept-charset");
  CheckHeaderFails("accept-encoding");
  CheckHeaderFails("connection");
  CheckHeaderFails("content-length");
  CheckHeaderFails("cookie");
  CheckHeaderFails("cookie2");
  CheckHeaderFails("date");
  CheckHeaderFails("dnt");
  CheckHeaderFails("expect");
  CheckHeaderFails("host");
  CheckHeaderFails("keep-alive");
  CheckHeaderFails("origin");
  CheckHeaderFails("referer", "http://example.com/");
  CheckHeaderFails("referer", "");  // no-referrer.
  CheckHeaderFails("te");
  CheckHeaderFails("trailer");
  CheckHeaderFails("transfer-encoding");
  CheckHeaderFails("upgrade");
  CheckHeaderFails("user-agent");
  CheckHeaderFails("via");

  CheckHeaderFails("proxy-");
  CheckHeaderFails("proxy-foo");
  CheckHeaderFails("sec-");
  CheckHeaderFails("sec-foo");

  // Check that validation is case-insensitive.
  CheckHeaderFails("AcCePt-ChArSeT");
  CheckHeaderFails("ProXy-FoO");
}

// Test that the loader filters response headers according to the CORS standard.
TEST_F(WebAssociatedURLLoaderTest, CrossOriginHeaderSafelisting) {
  // Test that safelisted headers are returned without exposing them.
  EXPECT_TRUE(CheckAccessControlHeaders("cache-control", false));
  EXPECT_TRUE(CheckAccessControlHeaders("content-language", false));
  EXPECT_TRUE(CheckAccessControlHeaders("content-type", false));
  EXPECT_TRUE(CheckAccessControlHeaders("expires", false));
  EXPECT_TRUE(CheckAccessControlHeaders("last-modified", false));
  EXPECT_TRUE(CheckAccessControlHeaders("pragma", false));

  // Test that non-safelisted headers aren't returned.
  EXPECT_FALSE(CheckAccessControlHeaders("non-safelisted", false));

  // Test that Set-Cookie headers aren't returned.
  EXPECT_FALSE(CheckAccessControlHeaders("Set-Cookie", false));
  EXPECT_FALSE(CheckAccessControlHeaders("Set-Cookie2", false));

  // Test that exposed headers that aren't safelisted are returned.
  EXPECT_TRUE(CheckAccessControlHeaders("non-safelisted", true));

  // Test that Set-Cookie headers aren't returned, even if exposed.
  EXPECT_FALSE(CheckAccessControlHeaders("Set-Cookie", true));
}

// Test that the loader can allow non-safelisted response headers for trusted
// CORS loads.
TEST_F(WebAssociatedURLLoaderTest, CrossOriginHeaderAllowResponseHeaders) {
  KURL url =
      ToKURL("http://www.other.com/CrossOriginHeaderAllowResponseHeaders.html");
  WebURLRequest request(url);
  request.SetMode(network::mojom::RequestMode::kCors);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

  WebString header_name_string(WebString::FromUTF8("non-safelisted"));
  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/html");
  expected_response_.SetHttpStatusCode(200);
  expected_response_.AddHttpHeaderField("Access-Control-Allow-Origin", "*");
  expected_response_.AddHttpHeaderField(header_name_string, "foo");
  RegisterMockedURLLoadWithCustomResponse(url, expected_response_,
                                          frame_file_path_);

  WebAssociatedURLLoaderOptions options;
  // This turns off response safelisting.
  options.expose_all_response_headers = true;
  expected_loader_ = CreateAssociatedURLLoader(options);
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);
  ServeRequests();
  EXPECT_TRUE(did_receive_response_);
  EXPECT_TRUE(did_receive_data_);
  EXPECT_TRUE(did_finish_loading_);

  EXPECT_FALSE(actual_response_.HttpHeaderField(header_name_string).IsEmpty());
}

TEST_F(WebAssociatedURLLoaderTest, AccessCheckForLocalURL) {
  KURL url = ToKURL("file://test.pdf");

  WebURLRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::PLUGIN);
  request.SetMode(network::mojom::RequestMode::kNoCors);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/plain");
  expected_response_.SetHttpStatusCode(200);
  RegisterMockedURLLoadWithCustomResponse(url, expected_response_,
                                          frame_file_path_);

  WebAssociatedURLLoaderOptions options;
  expected_loader_ = CreateAssociatedURLLoader(options);
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);
  ServeRequests();

  // The request failes due to a security check.
  EXPECT_FALSE(did_receive_response_);
  EXPECT_FALSE(did_receive_data_);
  EXPECT_FALSE(did_finish_loading_);
  EXPECT_TRUE(did_fail_);
}

TEST_F(WebAssociatedURLLoaderTest, BypassAccessCheckForLocalURL) {
  KURL url = ToKURL("file://test.pdf");

  WebURLRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::PLUGIN);
  request.SetMode(network::mojom::RequestMode::kNoCors);
  request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);

  expected_response_ = WebURLResponse();
  expected_response_.SetMimeType("text/plain");
  expected_response_.SetHttpStatusCode(200);
  RegisterMockedURLLoadWithCustomResponse(url, expected_response_,
                                          frame_file_path_);

  WebAssociatedURLLoaderOptions options;
  options.grant_universal_access = true;
  expected_loader_ = CreateAssociatedURLLoader(options);
  EXPECT_TRUE(expected_loader_);
  expected_loader_->LoadAsynchronously(request, this);
  ServeRequests();

  // The security check is bypassed due to |grant_universal_access|.
  EXPECT_TRUE(did_receive_response_);
  EXPECT_TRUE(did_receive_data_);
  EXPECT_TRUE(did_finish_loading_);
  EXPECT_FALSE(did_fail_);
}

#undef MAYBE_UntrustedCheckHeaders
}  // namespace blink

"""

```