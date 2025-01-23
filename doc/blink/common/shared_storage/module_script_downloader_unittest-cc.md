Response: Let's break down the thought process for analyzing the provided C++ unittest file.

**1. Initial Understanding - Context is Key:**

The first step is to recognize the context. The file path `blink/common/shared_storage/module_script_downloader_unittest.cc` immediately tells us several things:

* **`blink`:** This is part of the Chromium Blink rendering engine. It deals with web page rendering and related functionality.
* **`common`:** This suggests the code is not specific to a particular process (like the browser or renderer) but is shared across them.
* **`shared_storage`:** This points to a feature related to persistent storage accessible by multiple origins (with restrictions).
* **`module_script_downloader`:** This clearly indicates the component being tested is responsible for downloading module scripts.
* **`unittest.cc`:**  This suffix definitively identifies the file as a unit test.

**2. Deconstructing the Code - Functionality:**

Now, let's go through the code section by section, focusing on what it *does*.

* **Includes:** The included headers provide valuable clues.
    * `<optional>`, `<string>`, `<utility>`, `<vector>`: Standard C++ utilities.
    * `"base/functional/bind.h"`:  Used for creating callbacks.
    * `"base/run_loop.h"`:  Essential for asynchronous testing, allowing the test to wait for operations to complete.
    * `"base/strings/stringprintf.h"`: For formatted string creation.
    * `"base/test/task_environment.h"`: Sets up the necessary environment for asynchronous tasks.
    * `"net/http/http_response_headers.h"`, `"net/http/http_util.h"`: Deal with HTTP headers and status codes.
    * `"services/network/public/cpp/url_loader_completion_status.h"`: Represents the status of a URL loading request.
    * `"services/network/public/mojom/url_response_head.mojom.h"`: Defines the structure for HTTP response headers (using Mojo IPC).
    * `"services/network/test/test_url_loader_factory.h"`:  A crucial testing component that allows simulating network responses without making actual network requests.
    * `"testing/gtest/include/gtest/gtest.h"`: The Google Test framework.
    * `"url/gurl.h"`: Represents URLs.
    * `"third_party/blink/public/common/shared_storage/module_script_downloader.h"`:  The header for the class being tested.

* **Constants:** The `kAsciiResponseBody`, `kUtf8ResponseBody`, `kNonUtf8ResponseBody`, `kAsciiCharset`, `kUtf8Charset`, `kJavascriptMimeType`, `kJsonMimeType` constants define the various test scenarios for response bodies, character sets, and MIME types.

* **`AddResponse` Function:** This is a helper function to easily configure the `TestURLLoaderFactory` to return specific responses for given URLs. It simulates different HTTP status codes, MIME types, character sets, and even redirects.

* **`ModuleScriptDownloaderTest` Class:** This is the main test fixture.
    * **Constructor/Destructor:** Basic setup and teardown.
    * **`RunRequest()`:** This is the core of each test case. It creates a `ModuleScriptDownloader` instance, initiates the download, and uses a `base::RunLoop` to wait for the asynchronous download to complete.
    * **`DownloadCompleteCallback()`:** This is the callback function that the `ModuleScriptDownloader` invokes when the download finishes (successfully or with an error). It stores the result (body, error, response head).
    * **Member Variables:**  These hold the test environment, the target URL, the state of the asynchronous operation (run loop, body, error, response head), and the mock URL loader factory.

* **Test Cases (`TEST_F`)**: Each `TEST_F` function tests a specific scenario:
    * `NetworkError`: Simulates a network failure.
    * `HttpError`: Tests handling of HTTP error status codes (like 404).
    * `Redirect`: Checks how redirects are handled (should be treated as errors).
    * `Success`: Tests a successful download.
    * `UnexpectedMimeType`: Verifies that only JavaScript MIME types are accepted.
    * `JavscriptMimeTypeVariants`:  Ensures all valid JavaScript MIME types are correctly handled.
    * `Charset`:  Tests the validation of character sets (ASCII and UTF-8).

**3. Identifying Relationships with Web Technologies:**

Now, connect the dots between the C++ code and web technologies.

* **JavaScript:** The core functionality is downloading scripts (`module_script_downloader`). The tests specifically check for JavaScript MIME types and proper handling of JavaScript content.
* **HTML:** While not directly tested, the *purpose* of downloading scripts is to execute them within an HTML page. The downloaded scripts can manipulate the DOM (HTML structure) and CSS.
* **CSS:**  Downloaded JavaScript can dynamically modify CSS styles.
* **HTTP:** The tests heavily rely on HTTP concepts: status codes (200, 404), MIME types, character sets, and redirects. The `TestURLLoaderFactory` simulates HTTP responses.
* **URLs:** The tests use `GURL` to represent the URL of the script being downloaded.

**4. Logical Reasoning - Assumptions and Outputs:**

For each test case, deduce the expected input and output:

* **Input:** The configuration of the `TestURLLoaderFactory` (what response it will return for the given URL).
* **Output:** The value of `body_` (the downloaded content) and `error_` (the error message) after `RunRequest()` completes.

*Example (for `NetworkError`):*
    * **Assumption:** The `TestURLLoaderFactory` is configured to return a network error (`net::ERR_FAILED`).
    * **Input:**  The `url_` ("https://url.test/script.js").
    * **Expected Output:** `body_` will be null (or an empty optional), and `error_` will contain the specific network error message.

*Example (for `Success`):*
    * **Assumption:** The `TestURLLoaderFactory` is configured to return a successful HTTP response (200 OK) with a JavaScript MIME type and some content.
    * **Input:** The `url_`, the specified JavaScript MIME type, and the `kAsciiResponseBody`.
    * **Expected Output:** `body_` will contain `kAsciiResponseBody`, and `error_` will be empty.

**5. Common Usage Errors:**

Think about how developers might misuse the `ModuleScriptDownloader` or related concepts.

* **Incorrect MIME Type on the Server:**  A server might incorrectly serve a JavaScript file with a `text/plain` MIME type. The test cases for `UnexpectedMimeType` directly address this.
* **Incorrect Character Encoding:** A server might declare a charset but serve the content in a different encoding, leading to parsing errors. The `Charset` test case specifically tests this scenario.
* **Network Connectivity Issues:** While the unit test simulates this, in a real application, network errors are common. The `NetworkError` test demonstrates how the downloader handles these.
* **Unexpected Redirects:**  If a script's URL unexpectedly redirects to a different resource or a non-script resource, it could break the application. The `Redirect` test covers this.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  "This just downloads scripts."  **Refinement:**  "It downloads *module* scripts, which likely implies specific handling for ES modules." (Although the tests don't explicitly test module-specific syntax in this file, the naming hints at it).
* **Initial thought:** "The tests only check for success/failure." **Refinement:** "The tests also check the *reasons* for failure (network error, HTTP error, MIME type mismatch, charset mismatch), which is important for robust error handling."
* **Realizing the Role of `TestURLLoaderFactory`:** Initially, I might not fully grasp how the network requests are being simulated. Understanding that `TestURLLoaderFactory` is the key to this is crucial.

By following these steps, you can effectively analyze a C++ unit test file, understand its purpose, and relate it to broader web development concepts. The key is to combine code-level analysis with an understanding of the surrounding technology and potential error scenarios.
这个文件 `module_script_downloader_unittest.cc` 是 Chromium Blink 引擎中 `blink/common/shared_storage` 目录下，专门用于测试 `ModuleScriptDownloader` 类的单元测试文件。 `ModuleScriptDownloader` 的主要功能是**下载模块脚本**。

以下是这个文件的详细功能拆解，以及与 JavaScript、HTML、CSS 的关系，逻辑推理和常见错误示例：

**文件功能:**

1. **测试 `ModuleScriptDownloader` 的网络请求功能:**
   - 它模拟各种网络场景，例如成功的 HTTP 响应、网络错误、HTTP 错误（如 404）、重定向等。
   - 它使用 `network::TestURLLoaderFactory` 来模拟网络请求和响应，避免了实际的网络调用，使得测试更加快速和可控。

2. **测试 `ModuleScriptDownloader` 对不同 HTTP 响应的处理:**
   - **成功响应:** 测试当服务器返回 HTTP 200 OK 并且包含脚本内容时，`ModuleScriptDownloader` 是否能够成功下载脚本内容。
   - **网络错误:** 测试当网络请求失败时（例如 `net::ERR_FAILED`），`ModuleScriptDownloader` 是否能够正确处理并返回错误信息。
   - **HTTP 错误:** 测试当服务器返回 HTTP 错误状态码（例如 404 Not Found）时，`ModuleScriptDownloader` 是否能够正确识别并返回错误信息。
   - **重定向:** 测试当服务器返回重定向响应时，`ModuleScriptDownloader` 是否能够正确处理（通常会将其视为错误）。

3. **测试 `ModuleScriptDownloader` 对响应头信息的处理:**
   - **MIME 类型检查:** 测试 `ModuleScriptDownloader` 是否会根据响应头中的 `Content-Type` 字段来判断下载的内容是否是 JavaScript 模块。它会测试各种 JavaScript 相关的 MIME 类型。
   - **字符集检查:** 测试 `ModuleScriptDownloader` 是否会根据响应头中的 `charset` 字段来判断响应体的字符编码，并拒绝不符合预期的字符集。

**与 JavaScript, HTML, CSS 的关系:**

这个单元测试直接关系到 **JavaScript** 的功能，因为 `ModuleScriptDownloader` 的目标是下载 JavaScript 模块脚本。

* **JavaScript:**
    -  `ModuleScriptDownloader` 负责获取用于 `<script type="module">` 或动态 `import()` 语句加载的 JavaScript 代码。
    -  测试用例中使用了 `kJavascriptMimeType` 和其他 JavaScript 相关的 MIME 类型，模拟服务器返回 JavaScript 内容的情况。
    -  测试用例验证了下载的脚本内容是否与预期一致。

* **HTML:**
    -  在 HTML 中，`<script type="module">` 标签用于声明一个模块脚本。浏览器会使用类似 `ModuleScriptDownloader` 的机制来下载这些模块脚本。
    -  `ModuleScriptDownloader` 的正确性直接影响到网页能否正确加载和执行模块化的 JavaScript 代码。

* **CSS:**
    -  虽然 `ModuleScriptDownloader` 本身不直接下载 CSS 文件，但下载的 JavaScript 模块脚本可能会动态地加载或操作 CSS 样式。
    -  如果 `ModuleScriptDownloader` 下载模块脚本失败，那么依赖这些脚本来控制 CSS 的功能也会受到影响。

**举例说明:**

**假设输入与输出 (逻辑推理):**

**场景 1: 成功的 JavaScript 模块下载**

* **假设输入:**
    * `url_` 为 "https://example.com/my-module.js"
    * `TestURLLoaderFactory` 配置为：当请求 "https://example.com/my-module.js" 时，返回 HTTP 200 OK，响应头 `Content-Type: application/javascript; charset=utf-8`，响应体内容为 `console.log("Hello from module!");`
* **预期输出:**
    * `body_` 成员变量将包含字符串 `"console.log("Hello from module!");"`
    * `error_` 成员变量将为空字符串。

**场景 2: 下载时遇到 404 错误**

* **假设输入:**
    * `url_` 为 "https://example.com/non-existent-module.js"
    * `TestURLLoaderFactory` 配置为：当请求 "https://example.com/non-existent-module.js" 时，返回 HTTP 404 Not Found，响应头 `Content-Type: application/javascript; charset=utf-8`（即使是错误，也可能包含这些头信息）。
* **预期输出:**
    * `body_` 成员变量将为 null 或者表示下载失败的状态。
    * `error_` 成员变量将包含类似 `"Failed to load https://example.com/non-existent-module.js HTTP status = 404 Not Found."` 的错误信息。

**场景 3:  服务器返回错误的 MIME 类型**

* **假设输入:**
    * `url_` 为 "https://example.com/data.json" (虽然URL看起来像JSON)
    * `TestURLLoaderFactory` 配置为：当请求 "https://example.com/data.json" 时，返回 HTTP 200 OK，响应头 `Content-Type: application/json; charset=utf-8`，响应体内容为 `{"key": "value"}`。
* **预期输出:**
    * `body_` 成员变量将为 null 或者表示下载失败的状态。
    * `error_` 成员变量将包含类似 `"Rejecting load of https://example.com/data.json due to unexpected MIME type."` 的错误信息。

**用户或编程常见的使用错误:**

1. **服务器配置错误，返回了错误的 MIME 类型:**
   - **错误示例:** Web 服务器将 JavaScript 文件配置为 `text/plain` MIME 类型。
   - **后果:** 浏览器会拒绝执行该脚本，因为它的 MIME 类型不被认为是 JavaScript。`ModuleScriptDownloaderTest` 中的 `UnexpectedMimeType` 测试用例就模拟了这种情况。

2. **服务器返回了不支持的字符集:**
   - **错误示例:** 服务器声明字符集为 `ISO-8859-1`，但实际内容是 UTF-8 编码的，或者包含了 UTF-8 中无效的字节序列。
   - **后果:** 浏览器在解析脚本时可能会出现乱码或者解析错误。`ModuleScriptDownloaderTest` 中的 `Charset` 测试用例测试了对字符集的验证。

3. **网络请求失败但未正确处理错误:**
   - **错误示例:** 在开发过程中，忘记处理 `ModuleScriptDownloader` 返回的错误，导致当网络出现问题时，网页出现不可预测的行为。
   - **后果:** 用户可能会看到空白页面或者 JavaScript 错误。`ModuleScriptDownloaderTest` 中的 `NetworkError` 和 `HttpError` 测试用例确保了下载器能够返回错误信息，方便上层进行处理。

4. **假设所有 URL 都是有效的，没有进行 URL 格式校验:**
   - **错误示例:**  传递给 `ModuleScriptDownloader` 的 URL 是一个无效的 URL 字符串。
   - **后果:**  网络请求可能会失败，或者程序可能会崩溃。虽然这个单元测试没有直接测试 URL 的有效性，但在实际使用中需要注意。

**总结:**

`module_script_downloader_unittest.cc` 文件通过模拟各种场景，全面地测试了 `ModuleScriptDownloader` 类的核心功能，确保其能够正确地下载 JavaScript 模块脚本，并能够妥善处理各种网络和服务器响应情况，这对于保证基于模块化 JavaScript 的 Web 应用的稳定性和可靠性至关重要。

### 提示词
```
这是目录为blink/common/shared_storage/module_script_downloader_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/shared_storage/module_script_downloader.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/test/task_environment.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "services/network/test/test_url_loader_factory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace blink {

namespace {

const char kAsciiResponseBody[] = "ASCII response body.";
const char kUtf8ResponseBody[] = "\xc3\x9f\xc3\x9e";
const char kNonUtf8ResponseBody[] = "\xc3";

const char kAsciiCharset[] = "us-ascii";
const char kUtf8Charset[] = "utf-8";

const char kJavascriptMimeType[] = "application/javascript";
const char kJsonMimeType[] = "application/json";

void AddResponse(network::TestURLLoaderFactory* url_loader_factory,
                 const GURL& url,
                 std::optional<std::string> mime_type,
                 std::optional<std::string> charset,
                 const std::string content,
                 net::HttpStatusCode http_status = net::HTTP_OK,
                 network::TestURLLoaderFactory::Redirects redirects =
                     network::TestURLLoaderFactory::Redirects()) {
  auto head = network::mojom::URLResponseHead::New();
  // Don't bother adding these as headers, since the script grabs headers from
  // URLResponseHead fields instead of the corresponding
  // net::HttpResponseHeaders fields.
  if (mime_type) {
    head->mime_type = *mime_type;
  }
  if (charset) {
    head->charset = *charset;
  }
  if (http_status != net::HTTP_OK) {
    std::string full_headers = base::StringPrintf(
        "HTTP/1.1 %d %s\r\n\r\n", static_cast<int>(http_status),
        net::GetHttpReasonPhrase(http_status));
    head->headers = net::HttpResponseHeaders::TryToCreate(full_headers);
    CHECK(head->headers);
  }
  url_loader_factory->AddResponse(url, std::move(head), content,
                                  network::URLLoaderCompletionStatus(),
                                  std::move(redirects));
}

}  // namespace

class ModuleScriptDownloaderTest : public testing::Test {
 public:
  ModuleScriptDownloaderTest() = default;
  ~ModuleScriptDownloaderTest() override = default;

  std::unique_ptr<std::string> RunRequest() {
    DCHECK(!run_loop_);

    ModuleScriptDownloader downloader(
        &url_loader_factory_, url_,
        base::BindOnce(&ModuleScriptDownloaderTest::DownloadCompleteCallback,
                       base::Unretained(this)));

    // Populate `run_loop_` after starting the download, since API guarantees
    // callback will not be invoked synchronously.
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
    run_loop_.reset();
    return std::move(body_);
  }

 protected:
  void DownloadCompleteCallback(
      std::unique_ptr<std::string> body,
      std::string error,
      network::mojom::URLResponseHeadPtr response_head) {
    DCHECK(!body_);
    DCHECK(run_loop_);
    body_ = std::move(body);
    error_ = std::move(error);
    response_head_ = std::move(response_head);
    EXPECT_EQ(error_.empty(), !!body_);
    run_loop_->Quit();
  }

  base::test::TaskEnvironment task_environment_;

  const GURL url_ = GURL("https://url.test/script.js");

  std::unique_ptr<base::RunLoop> run_loop_;
  std::unique_ptr<std::string> body_;
  std::string error_;
  network::mojom::URLResponseHeadPtr response_head_;

  network::TestURLLoaderFactory url_loader_factory_;
};

TEST_F(ModuleScriptDownloaderTest, NetworkError) {
  network::URLLoaderCompletionStatus status;
  status.error_code = net::ERR_FAILED;
  url_loader_factory_.AddResponse(url_, /*head=*/nullptr, kAsciiResponseBody,
                                  status);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Failed to load https://url.test/script.js error = net::ERR_FAILED.",
      error_);
  EXPECT_FALSE(response_head_);
}

// HTTP 404 responses are treated as failures.
TEST_F(ModuleScriptDownloaderTest, HttpError) {
  // This is an unlikely response for an error case, but should fail if it ever
  // happens.
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kUtf8Charset,
              kAsciiResponseBody, net::HTTP_NOT_FOUND);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Failed to load https://url.test/script.js HTTP status = 404 Not Found.",
      error_);
  EXPECT_TRUE(response_head_);
  EXPECT_EQ(response_head_->mime_type, kJavascriptMimeType);
}

// Redirect responses are treated as failures.
TEST_F(ModuleScriptDownloaderTest, Redirect) {
  // None of these fields actually matter for this test, but a bit strange for
  // them not to be populated.
  net::RedirectInfo redirect_info;
  redirect_info.status_code = net::HTTP_MOVED_PERMANENTLY;
  redirect_info.new_url = url_;
  redirect_info.new_method = "GET";
  network::TestURLLoaderFactory::Redirects redirects;
  redirects.push_back(
      std::make_pair(redirect_info, network::mojom::URLResponseHead::New()));

  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kUtf8Charset,
              kAsciiResponseBody, net::HTTP_OK, std::move(redirects));
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ("Unexpected redirect on https://url.test/script.js.", error_);
  EXPECT_FALSE(response_head_);
}

TEST_F(ModuleScriptDownloaderTest, Success) {
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kUtf8Charset,
              kAsciiResponseBody);
  std::unique_ptr<std::string> body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kAsciiResponseBody, *body);
}

// Test unexpected response mime type.
TEST_F(ModuleScriptDownloaderTest, UnexpectedMimeType) {
  // Javascript request, JSON response type.
  AddResponse(&url_loader_factory_, url_, kJsonMimeType, kUtf8Charset,
              kAsciiResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected MIME "
      "type.",
      error_);

  // Javascript request, no response type.
  AddResponse(&url_loader_factory_, url_, std::nullopt, kUtf8Charset,
              kAsciiResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected MIME "
      "type.",
      error_);

  // Javascript request, empty response type.
  AddResponse(&url_loader_factory_, url_, "", kUtf8Charset, kAsciiResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected MIME "
      "type.",
      error_);

  // Javascript request, unknown response type.
  AddResponse(&url_loader_factory_, url_, "blobfish", kUtf8Charset,
              kAsciiResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected MIME "
      "type.",
      error_);
}

// Test all Javscript type strings.
TEST_F(ModuleScriptDownloaderTest, JavscriptMimeTypeVariants) {
  // All supported Javscript MIME types, copied from blink's mime_util.cc.
  // TODO(yaoxia): find a way to keep the list in sync with the original list.

  const char* kJavascriptMimeTypes[] = {
      "application/ecmascript",
      "application/javascript",
      "application/x-ecmascript",
      "application/x-javascript",
      "text/ecmascript",
      "text/javascript",
      "text/javascript1.0",
      "text/javascript1.1",
      "text/javascript1.2",
      "text/javascript1.3",
      "text/javascript1.4",
      "text/javascript1.5",
      "text/jscript",
      "text/livescript",
      "text/x-ecmascript",
      "text/x-javascript",
  };

  for (const char* javascript_type : kJavascriptMimeTypes) {
    AddResponse(&url_loader_factory_, url_, javascript_type, kUtf8Charset,
                kAsciiResponseBody);
    std::unique_ptr<std::string> body = RunRequest();
    ASSERT_TRUE(body);
    EXPECT_EQ(kAsciiResponseBody, *body);
  }
}

TEST_F(ModuleScriptDownloaderTest, Charset) {
  // ASCII charset should restrict response bodies to ASCII characters.
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kAsciiCharset,
              kAsciiResponseBody);
  std::unique_ptr<std::string> body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kAsciiResponseBody, *body);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kAsciiCharset,
              kUtf8ResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected charset.",
      error_);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kAsciiCharset,
              kNonUtf8ResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected charset.",
      error_);

  // UTF-8 charset should restrict response bodies to valid UTF-8 characters.
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kUtf8Charset,
              kAsciiResponseBody);
  body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kAsciiResponseBody, *body);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kUtf8Charset,
              kUtf8ResponseBody);
  body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kUtf8ResponseBody, *body);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, kUtf8Charset,
              kNonUtf8ResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected charset.",
      error_);

  // Null charset should act like UTF-8.
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, std::nullopt,
              kAsciiResponseBody);
  body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kAsciiResponseBody, *body);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, std::nullopt,
              kUtf8ResponseBody);
  body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kUtf8ResponseBody, *body);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, std::nullopt,
              kNonUtf8ResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected charset.",
      error_);

  // Empty charset should act like UTF-8.
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, "",
              kAsciiResponseBody);
  body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kAsciiResponseBody, *body);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, "",
              kUtf8ResponseBody);
  body = RunRequest();
  ASSERT_TRUE(body);
  EXPECT_EQ(kUtf8ResponseBody, *body);
  AddResponse(&url_loader_factory_, url_, kJavascriptMimeType, "",
              kNonUtf8ResponseBody);
  EXPECT_FALSE(RunRequest());
  EXPECT_EQ(
      "Rejecting load of https://url.test/script.js due to unexpected charset.",
      error_);
}

}  // namespace blink
```