Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `default_handlers.cc` file in Chromium's network stack. We need to identify what each function does and, if possible, relate it to web concepts, especially JavaScript. The prompt also specifically asks for examples, user errors, and debugging tips.

**2. Initial Scan and Identification of Key Components:**

The first step is to quickly scan the code, looking for patterns and recognizable elements. Here's what stands out:

* **Includes:**  Lots of Chromium/base/net headers (files, strings, URLs, tasks, time, etc.). This tells us it's core Chromium infrastructure.
* **Namespace:** `net::test_server`. This indicates it's part of the testing framework, specifically for an embedded test server.
* **Anonymous Namespace:** The initial part of the file is within an unnamed namespace, suggesting these are internal helpers.
* **Function Definitions:**  Many functions that take an `HttpRequest` and return a `std::unique_ptr<HttpResponse>`. This is the core pattern. These functions are *handlers* for specific URLs.
* **URL-like Strings:**  Strings like `/cachetime`, `/echoheader`, `/auth-basic`, etc. These strongly suggest URL path matching.
* **HTTP Concepts:**  References to HTTP methods (GET, POST, CONNECT), status codes (200, 404, 401), headers (Cache-Control, Set-Cookie, Authorization), and concepts like authentication (Basic, Digest), redirects, and cookies.

**3. Deeper Dive into Individual Handlers:**

The next step is to go through each handler function individually and understand its specific purpose. For each handler, ask:

* **What URL path does it handle?** (Often evident from the function name or a `ShouldHandle` call).
* **What HTTP method(s) does it typically handle?** (Often implicit or explicitly checked).
* **What does it do with the `HttpRequest`?** (Examine request headers, query parameters, body).
* **What `HttpResponse` does it construct?** (Status code, headers, body content).

**4. Identifying Connections to JavaScript:**

After understanding the core functionality, consider how these handlers might interact with JavaScript running in a browser:

* **Fetching Resources:** Handlers that serve HTML, CSS, JavaScript files, images, or other assets are directly relevant.
* **Making API Calls (XHR/Fetch):** Handlers that process POST/PUT requests or return specific data formats (like JSON – though not explicitly in this snippet) are important for AJAX interactions.
* **Authentication:** Handlers like `HandleAuthBasic` and `HandleAuthDigest` are crucial for scenarios where JavaScript needs to authenticate with the server.
* **Cookies:** Handlers that set or expect cookies (`HandleSetCookie`, `HandleExpectAndSetCookie`) are directly relevant to JavaScript's cookie API.
* **Redirects:** Handlers that perform server-side or client-side redirects affect how JavaScript navigates or fetches resources.
* **CORS (Cross-Origin Resource Sharing):** Handlers that set `Access-Control-Allow-Origin` headers are essential for cross-origin requests initiated by JavaScript.

**5. Crafting Examples, Assumptions, and Error Scenarios:**

For each handler with a JavaScript connection, think about:

* **Simple JavaScript code:**  How would you use `fetch` or `XMLHttpRequest` to interact with this handler?
* **Assumptions:** What query parameters or request headers are expected? What is the expected response?
* **User/Programming Errors:** What could go wrong from a developer's perspective when using this handler (e.g., incorrect URL, missing headers, unexpected response)?

**6. Tracing User Actions (Debugging Perspective):**

Imagine a user interacting with a web page. How might their actions lead to a request hitting one of these handlers?  Think about common web development patterns:

* **Typing a URL in the address bar:** Leads to a GET request for the main page (handled by something like `HandleFileRequest` – not in this snippet but implied).
* **Clicking a link:** Another GET request.
* **Submitting a form:** Could be GET or POST.
* **JavaScript making a fetch request:**  Any HTTP method.
* **Image loading:** GET request for an image.
* **Redirects:** One request leads to another.
* **Authentication prompts:**  Occur after an unauthorized response from an authentication handler.

**7. Structuring the Output:**

Organize the information logically. Group handlers by their general function (e.g., caching, echoing, authentication, redirects). For each handler, address the specific points requested in the prompt (functionality, JavaScript relevance, examples, errors, debugging).

**Self-Correction/Refinement During the Process:**

* **Initial Oversimplification:**  Realize that some handlers are more complex than they initially appear. For example, authentication handlers involve multiple steps and different HTTP status codes.
* **Focusing too narrowly on JavaScript:** Remember that the embedded test server is also used for testing the browser's core networking stack, so some handlers might be for internal testing purposes.
* **Missing subtleties:**  Pay attention to details like the `Vary` header in `HandleEchoHeader` or the different redirect types.
* **Clarifying assumptions:** Explicitly state any assumptions made when creating examples.

By following this iterative process of scanning, detailed analysis, connection to web concepts, and example generation, we can arrive at a comprehensive understanding of the `default_handlers.cc` file.
这是 Chromium 网络栈中 `net/test/embedded_test_server/default_handlers.cc` 文件的第一部分，它定义了一系列用于 `EmbeddedTestServer` 的默认请求处理器。这些处理器模拟了各种 HTTP 行为，主要用于网络功能的测试。

**功能归纳 (针对第一部分):**

该文件的主要功能是提供一组预定义的 HTTP 请求处理器，用于模拟各种常见的服务端行为，方便进行网络相关的单元测试和集成测试。这些处理器可以处理不同的 URL 路径和 HTTP 方法，并返回具有特定状态码、头部信息和内容的 HTTP 响应。

**具体功能列表 (基于提供的代码片段):**

* **处理 CONNECT 请求:**  `HandleDefaultConnect` 函数，对所有 `CONNECT` 请求返回 `HTTP_BAD_REQUEST` 错误。
* **返回可缓存的响应:** `HandleCacheTime` 函数，返回一个设置了 `Cache-Control: max-age=60` 头部的 HTML 页面。
* **回显请求头部:** `HandleEchoHeader` 函数，将请求头部的指定字段回显在响应体中，可以选择是否缓存结果。
* **回显带有状态码的 Cookie:** `HandleEchoCookieWithStatus` 函数，使用指定的 HTTP 状态码响应，并将请求中携带的 Cookie 回显在响应体中。
* **回显关键头部 (Critical-CH):** `HandleEchoCriticalHeader` 函数，回显 `Sec-CH-UA-Mobile` 和 `Sec-CH-UA-Platform` 这两个客户端提示头部的值。
* **回显请求体:** `HandleEcho` 函数，将请求体作为响应体返回，并可以根据请求参数设置响应状态码。
* **回显请求体作为标题:** `HandleEchoTitle` 函数，将请求体的内容作为 HTML 页面的 `<title>` 标签内容返回。
* **回显所有信息:** `HandleEchoAll` 函数，返回一个包含请求体、所有请求头部以及一个随机 nonce 的 HTML 页面，可以选择禁止缓存。
* **返回原始查询字符串:** `HandleEchoRaw` 函数，直接将 URL 的查询字符串作为响应体返回，不包含 HTTP 头部。
* **设置响应 Cookie:** `HandleSetCookie` 函数，根据 URL 的查询参数设置 `Set-Cookie` 头部。
* **设置无效 Cookie:** `HandleSetInvalidCookie` 函数，设置一个无效的 Cookie 头部。
* **验证并设置 Cookie:** `HandleExpectAndSetCookie` 函数，验证请求中是否包含期望的 Cookie，然后根据 URL 参数设置新的 Cookie 并返回指定内容。
* **设置响应头部:** `HandleSetHeader` 函数，根据 URL 的查询参数设置响应头部，并将这些头部信息也作为响应内容返回。
* **设置带文件内容的响应头部:** `HandleSetHeaderWithFile` 函数，读取指定文件内容作为响应体，并根据 URL 查询参数设置响应头部。
* **返回 iframe 页面:** `HandleIframe` 函数，返回一个包含指定 URL 的 `<iframe>` 的 HTML 页面。
* **返回无内容响应:** `HandleNoContent` 函数，返回 `HTTP_NO_CONTENT` 状态码的响应。
* **关闭 Socket 连接:** `HandleCloseSocket` 函数，立即关闭连接。
* **执行 Basic 认证:** `HandleAuthBasic` 函数，模拟 Basic HTTP 认证过程。
* **执行 Digest 认证:** `HandleAuthDigest` 函数，模拟 Digest HTTP 认证过程。
* **服务端重定向:** `HandleServerRedirect` 函数，返回一个服务端重定向到指定 URL 的响应，可以选择是否允许 CORS。
* **服务端重定向并设置 Cookie:** `HandleServerRedirectWithCookie` 函数，返回服务端重定向响应并设置一个 Cookie。
* **服务端重定向并设置 Secure Cookie:** `HandleServerRedirectWithSecureCookie` 函数，返回服务端重定向响应并设置一个 Secure Cookie。
* **跨站重定向:** `HandleCrossSiteRedirect` 函数，返回一个重定向到不同域名的响应，可以选择是否设置 Cookie。
* **客户端重定向:** `HandleClientRedirect` 函数，返回一个使用 `<meta http-equiv="refresh">` 进行客户端重定向的 HTML 页面。
* **返回默认响应:** `HandleDefaultResponse` 函数，返回一个默认的 HTTP 200 响应。
* **延迟响应:** `HandleSlowServer` 函数，延迟指定秒数后返回响应。
* **挂起响应 (不返回):** `HandleHungResponse` 函数，永远不返回响应。
* **挂起头部后的响应:** `HandleHungAfterHeadersResponse` 函数，发送完头部后永远不返回响应体。
* **返回超大响应 (Exabyte):** `HandleExabyteResponse` 函数，返回一个声称内容长度为 Exabyte 的响应，实际会持续发送数据。
* **返回 Gzip 压缩的响应体:** `HandleGzipBody` 函数，将指定的请求参数作为内容进行 Gzip 压缩后返回。
* **返回自引用 PAC 文件:** `HandleSelfPac` 函数，返回一个 PAC 脚本，指示浏览器使用测试服务器自身作为代理。

**与 JavaScript 功能的关系及举例说明:**

这些处理器与 JavaScript 功能有密切关系，因为它们模拟了浏览器通过 JavaScript 发起网络请求时可能遇到的各种服务端行为。以下是一些例子：

* **`HandleCacheTime` 和缓存:** JavaScript 通过 `fetch` 或 `XMLHttpRequest` 请求 `/cachetime` 时，浏览器会根据响应头部的 `Cache-Control` 进行缓存。后续对该资源的请求可能会直接从缓存中获取，而不会再次发送到服务器。
  ```javascript
  fetch('/cachetime')
    .then(response => response.text())
    .then(data => console.log(data));

  // 短时间内再次请求，浏览器可能直接从缓存读取
  fetch('/cachetime')
    .then(response => response.text())
    .then(data => console.log("From cache?", data));
  ```

* **`HandleEchoHeader` 和 CORS:** JavaScript 可以通过 `fetch` 发送带有自定义头部的跨域请求到 `/echoheadercache?X-Custom-Header`。服务器会通过 `Access-Control-Allow-Origin: *` 允许跨域，并将 `X-Custom-Header` 的值回显在响应体中。
  ```javascript
  fetch('http://your_test_server/echoheadercache?X-Custom-Header', {
    headers: {
      'X-Custom-Header': 'my-custom-value'
    }
  })
  .then(response => response.text())
  .then(data => console.log(data)); // 输出 "my-custom-value"
  ```

* **`HandleSetCookie` 和 Cookie 操作:** JavaScript 可以通过 `fetch` 请求 `/set-cookie?mycookie=test`，服务器会设置 `mycookie=test` 的 Cookie。后续 JavaScript 可以通过 `document.cookie` 读取到这个 Cookie。
  ```javascript
  fetch('/set-cookie?mycookie=test')
    .then(() => {
      console.log(document.cookie); // 可能输出包含 "mycookie=test" 的字符串
    });
  ```

* **`HandleAuthBasic` 和身份验证:** JavaScript 发起请求到需要 Basic 认证的 `/auth-basic` 路径时，如果未提供认证信息，服务器会返回 401 状态码和 `WWW-Authenticate` 头部。浏览器通常会弹出认证对话框，或者 JavaScript 可以手动设置 `Authorization` 头部。
  ```javascript
  fetch('/auth-basic', {
    headers: {
      'Authorization': 'Basic ' + btoa('user:secret') // 假设用户名是 user，密码是 secret
    }
  })
  .then(response => response.text())
  .then(data => console.log(data));
  ```

* **`HandleServerRedirect` 和重定向:** JavaScript 发起请求到 `/server-redirect?/target`，服务器会返回 302 重定向到 `/target`。浏览器会自动 follow 这个重定向。
  ```javascript
  fetch('/server-redirect?/target')
    .then(response => {
      console.log("Redirected to:", response.url); // 输出重定向后的 URL
      return response.text();
    })
    .then(data => console.log(data));
  ```

**逻辑推理、假设输入与输出:**

以 `HandleEchoHeader` 为例：

**假设输入:**

* **请求方法:** GET
* **请求 URL:** `/echoheader?User-Agent&Accept-Language`
* **请求头部:**
  ```
  User-Agent: Mozilla/5.0 ...
  Accept-Language: en-US,en;q=0.9
  Connection: keep-alive
  ```

**逻辑推理:**

1. `ShouldHandle` 函数会检查请求 URL 是否以 `/echoheader` 开头，结果为真。
2. 从请求 URL 中解析出需要回显的头部字段：`User-Agent` 和 `Accept-Language`。
3. 遍历这些字段，从请求头部中查找对应的值。
4. 构建响应体，包含找到的头部值，用换行符分隔。
5. 设置 `Vary` 头部为 `User-Agent,Accept-Language`，告知浏览器响应内容可能因这些头部的值而异。

**预期输出:**

* **响应状态码:** 200 OK
* **响应头部:**
  ```
  Content-Type: text/plain
  Vary: User-Agent,Accept-Language
  Access-Control-Allow-Origin: *
  Cache-Control: 
  ```
* **响应体:**
  ```
  Mozilla/5.0 ...
  en-US,en;q=0.9
  ```

**用户或编程常见的使用错误及举例说明:**

* **CORS 问题:** JavaScript 发起跨域请求时，如果服务端没有设置正确的 CORS 头部（例如 `Access-Control-Allow-Origin`），浏览器会阻止请求，导致 JavaScript 代码报错。例如，尝试从 `http://example.com` 的页面请求 `http://your_test_server/echoheader`，如果 `HandleEchoHeader` 没有设置 `Access-Control-Allow-Origin: *`，就会出现 CORS 错误。

* **Cookie 设置错误:** 在 JavaScript 中使用 `document.cookie` 设置 Cookie 时，如果没有设置正确的 `path` 或 `domain` 属性，可能会导致 Cookie 不生效或作用域错误。例如，服务端通过 `HandleSetCookie` 设置了 Cookie 但 `path` 属性不正确，导致 JavaScript 在其他路径下无法读取该 Cookie。

* **认证信息错误:** 当请求需要认证的资源（例如 `/auth-basic`）时，如果 JavaScript 提供的认证信息（`Authorization` 头部）不正确，服务端会返回 401 状态码，JavaScript 需要处理这种情况。

* **重定向循环:** 如果服务端配置了错误的重定向逻辑（例如 `/server-redirect?loop` 又重定向到自身），JavaScript 发起的请求可能会陷入无限重定向循环，导致浏览器性能下降甚至崩溃。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问了一个网页 `http://example.com/index.html`，该网页包含以下 JavaScript 代码：

```javascript
fetch('/echoheader?X-Requested-With')
  .then(response => response.text())
  .then(data => console.log(data));
```

1. **用户在浏览器地址栏输入 `http://example.com/index.html` 并按下回车。**
2. **浏览器向 `http://example.com` 发起请求，获取 `index.html` 文件。** (这部分不涉及 `default_handlers.cc`，假设 `example.com` 部署了相应的服务)
3. **浏览器解析 `index.html`，执行其中的 JavaScript 代码。**
4. **JavaScript 代码调用 `fetch('/echoheader?X-Requested-With')`。**
5. **浏览器根据相对路径 `/echoheader?X-Requested-With`，向当前域名的服务器（假设就是运行 `EmbeddedTestServer` 的服务器）发起一个 GET 请求。**
6. **`EmbeddedTestServer` 接收到请求。**
7. **服务器根据请求的路径 `/echoheader`，匹配到 `HandleEchoHeader` 函数。**
8. **`HandleEchoHeader` 函数被调用，处理该请求。**
9. **函数解析请求 URL，提取出需要回显的头部 `X-Requested-With`。**
10. **函数查找请求头部中 `X-Requested-With` 的值（如果没有则为 "None"）。**
11. **函数构建包含该值的响应体，并设置相应的头部信息。**
12. **服务器将响应发送回浏览器。**
13. **浏览器接收到响应，JavaScript 的 `fetch` Promise resolve，调用 `.then` 方法。**
14. **`console.log(data)` 将响应体的内容打印到浏览器的控制台。**

**调试线索:**

* **网络面板:** 浏览器的开发者工具中的 "Network" 面板可以查看该请求的详细信息，包括请求 URL、头部、状态码、响应内容等，可以确认请求是否发送到 `/echoheader`，以及服务器返回的响应内容。
* **服务器日志:** `EmbeddedTestServer` 通常会输出请求和响应的日志，可以查看服务器是否接收到该请求，以及 `HandleEchoHeader` 函数的处理结果。
* **断点调试:** 如果需要深入了解 `HandleEchoHeader` 的执行过程，可以在该函数的代码中设置断点，使用调试器进行单步调试。

希望以上分析能够帮助你理解 `net/test/embedded_test_server/default_handlers.cc` 文件的功能。请提供第二部分的内容，以便进行更全面的分析。

Prompt: 
```
这是目录为net/test/embedded_test_server/default_handlers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/default_handlers.h"

#include <ctime>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/functional/callback_helpers.h"
#include "base/hash/md5.h"
#include "base/logging.h"
#include "base/memory/weak_ptr.h"
#include "base/path_service.h"
#include "base/strings/escape.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "net/base/host_port_pair.h"
#include "net/base/url_util.h"
#include "net/filter/filter_source_stream_test_util.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/embedded_test_server/request_handler_util.h"

namespace net::test_server {
namespace {

const char kDefaultRealm[] = "testrealm";
const char kDefaultPassword[] = "secret";
const char kEtag[] = "abc";
const char kLogoPath[] = "chrome/test/data/google/logo.gif";

// method: CONNECT
// Responses with a BAD_REQUEST to any CONNECT requests.
std::unique_ptr<HttpResponse> HandleDefaultConnect(const HttpRequest& request) {
  if (request.method != METHOD_CONNECT)
    return nullptr;

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(HTTP_BAD_REQUEST);
  http_response->set_content(
      "Your client has issued a malformed or illegal request.");
  http_response->set_content_type("text/html");
  return http_response;
}

// /cachetime
// Returns a cacheable response.
std::unique_ptr<HttpResponse> HandleCacheTime(const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content("<!doctype html><title>Cache: max-age=60</title>");
  http_response->set_content_type("text/html");
  http_response->AddCustomHeader("Cache-Control", "max-age=60");
  return http_response;
}

// /echoheader?HEADERS | /echoheadercache?HEADERS
// Responds with the headers echoed in the message body.
// echoheader does not cache the results, while echoheadercache does.
std::unique_ptr<HttpResponse> HandleEchoHeader(const std::string& url,
                                               const std::string& cache_control,
                                               const HttpRequest& request) {
  if (!ShouldHandle(request, url))
    return nullptr;

  auto http_response = std::make_unique<BasicHttpResponse>();

  GURL request_url = request.GetURL();
  std::string vary;
  std::string content;
  RequestQuery headers = ParseQuery(request_url);
  for (const auto& header : headers) {
    std::string header_name = header.first;
    std::string header_value = "None";
    if (request.headers.find(header_name) != request.headers.end())
      header_value = request.headers.at(header_name);
    if (!vary.empty())
      vary += ",";
    vary += header_name;
    if (!content.empty())
      content += "\n";
    content += header_value;
  }

  http_response->AddCustomHeader("Vary", vary);
  http_response->set_content(content);
  http_response->set_content_type("text/plain");
  http_response->AddCustomHeader("Access-Control-Allow-Origin", "*");
  http_response->AddCustomHeader("Cache-Control", cache_control);
  return http_response;
}

// /echo-cookie-with-status?status=###
// Responds with the given status code and echos the cookies sent in the request
std::unique_ptr<HttpResponse> HandleEchoCookieWithStatus(
    const std::string& url,
    const HttpRequest& request) {
  if (!ShouldHandle(request, url))
    return nullptr;

  auto http_response = std::make_unique<BasicHttpResponse>();

  GURL request_url = request.GetURL();
  RequestQuery query = ParseQuery(request_url);

  int status_code = 400;
  const auto given_status = query.find("status");

  if (given_status != query.end() && !given_status->second.empty() &&
      !base::StringToInt(given_status->second.front(), &status_code)) {
    status_code = 400;
  }

  http_response->set_code(static_cast<HttpStatusCode>(status_code));

  const auto given_cookie = request.headers.find("Cookie");
  std::string content =
      (given_cookie == request.headers.end()) ? "None" : given_cookie->second;
  http_response->set_content(content);
  http_response->set_content_type("text/plain");
  return http_response;
}

// TODO(crbug.com/40153192): Remove when request handlers are
// implementable in Android's embedded test server implementation
std::unique_ptr<HttpResponse> HandleEchoCriticalHeader(
    const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();

  http_response->set_content_type("text/plain");
  http_response->AddCustomHeader("Access-Control-Allow-Origin", "*");

  http_response->AddCustomHeader("Accept-CH", "Sec-CH-UA-Platform");
  http_response->AddCustomHeader("Critical-CH", "Sec-CH-UA-Platform");

  http_response->set_content(
      request.headers.find("Sec-CH-UA-Mobile")->second +
      request.headers.find("Sec-CH-UA-Platform")->second);

  return http_response;
}

// /echo?status=STATUS
// Responds with the request body as the response body and
// a status code of STATUS.
std::unique_ptr<HttpResponse> HandleEcho(const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();

  GURL request_url = request.GetURL();
  if (request_url.has_query()) {
    RequestQuery query = ParseQuery(request_url);
    if (query.find("status") != query.end())
      http_response->set_code(static_cast<HttpStatusCode>(
          std::atoi(query["status"].front().c_str())));
  }

  http_response->set_content_type("text/html");
  if (request.method != METHOD_POST && request.method != METHOD_PUT)
    http_response->set_content("Echo");
  else
    http_response->set_content(request.content);
  return http_response;
}

// /echotitle
// Responds with the request body as the title.
std::unique_ptr<HttpResponse> HandleEchoTitle(const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");
  http_response->set_content("<!doctype html><title>" + request.content +
                             "</title>");
  return http_response;
}

// /echoall?QUERY
// Responds with the list of QUERY and the request headers.
//
// Alternative form:
// /echoall/nocache?QUERY prevents caching of the response.
std::unique_ptr<HttpResponse> HandleEchoAll(const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();

  std::string body =
      "<!doctype html><title>EmbeddedTestServer - EchoAll</title><style>"
      "pre { border: 1px solid black; margin: 5px; padding: 5px }"
      "</style>"
      "<div style=\"float: right\">"
      "<a href=\"/echo\">back to referring page</a></div>"
      "<h1>Request Body:</h1><pre>";

  if (request.has_content) {
    std::vector<std::string> query_list = base::SplitString(
        request.content, "&", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    for (const auto& query : query_list)
      body += query + "\n";
  }

  body +=
      "</pre>"
      "<h1>Request Headers:</h1><pre id='request-headers'>" +
      request.all_headers + "</pre>" +
      "<h1>Response nonce:</h1><pre id='response-nonce'>" +
      base::UnguessableToken::Create().ToString() + "</pre>";

  http_response->set_content_type("text/html");
  http_response->set_content(body);

  if (request.GetURL().path_piece().ends_with("/nocache")) {
    http_response->AddCustomHeader("Cache-Control",
                                   "no-cache, no-store, must-revalidate");
  }

  return http_response;
}

// /echo-raw
// Returns the query string as the raw response (no HTTP headers).
std::unique_ptr<HttpResponse> HandleEchoRaw(const HttpRequest& request) {
  return std::make_unique<RawHttpResponse>("", request.GetURL().query());
}

// /set-cookie?COOKIES
// Sets response cookies to be COOKIES.
std::unique_ptr<HttpResponse> HandleSetCookie(const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");
  std::string content;
  GURL request_url = request.GetURL();
  if (request_url.has_query()) {
    std::vector<std::string> cookies = base::SplitString(
        request_url.query(), "&", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    for (const auto& cookie : cookies) {
      http_response->AddCustomHeader("Set-Cookie", cookie);
      content += cookie;
    }
  }

  http_response->set_content(content);
  return http_response;
}

// /set-invalid-cookie
// Sets invalid response cookies "\x01" (chosen via fuzzer to not be a parsable
// cookie).
std::unique_ptr<HttpResponse> HandleSetInvalidCookie(
    const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");
  std::string content;
  GURL request_url = request.GetURL();

  http_response->AddCustomHeader("Set-Cookie", "\x01");

  http_response->set_content("TEST");
  return http_response;
}

// /expect-and-set-cookie?expect=EXPECTED&set=SET&data=DATA
// Verifies that the request cookies match EXPECTED and then returns cookies
// that match SET and a content that matches DATA.
std::unique_ptr<HttpResponse> HandleExpectAndSetCookie(
    const HttpRequest& request) {
  std::vector<std::string> received_cookies;
  if (request.headers.find("Cookie") != request.headers.end()) {
    received_cookies =
        base::SplitString(request.headers.at("Cookie"), ";",
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  }

  bool got_all_expected = true;
  GURL request_url = request.GetURL();
  RequestQuery query_list = ParseQuery(request_url);
  if (query_list.find("expect") != query_list.end()) {
    for (const auto& expected_cookie : query_list.at("expect")) {
      bool found = false;
      for (const auto& received_cookie : received_cookies) {
        if (expected_cookie == received_cookie)
          found = true;
      }
      got_all_expected &= found;
    }
  }

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");
  if (got_all_expected) {
    for (const auto& cookie : query_list.at("set")) {
      http_response->AddCustomHeader(
          "Set-Cookie",
          base::UnescapeBinaryURLComponent(
              cookie, base::UnescapeRule::REPLACE_PLUS_WITH_SPACE));
    }
  }

  std::string content;
  if (query_list.find("data") != query_list.end()) {
    for (const auto& item : query_list.at("data"))
      content += item;
  }

  http_response->set_content(content);
  return http_response;
}

// An internal utility to extract HTTP Headers from a URL in the format of
// "/url&KEY1: VALUE&KEY2: VALUE2". Returns a header key to header value map.
std::multimap<std::string, std::string> ExtractHeadersFromQuery(
    const GURL& url) {
  std::multimap<std::string, std::string> key_to_value;
  if (url.has_query()) {
    RequestQuery headers = ParseQuery(url);
    for (const auto& header : headers) {
      size_t delimiter = header.first.find(": ");
      if (delimiter == std::string::npos) {
        continue;
      }
      std::string key = header.first.substr(0, delimiter);
      std::string value = header.first.substr(delimiter + 2);
      key_to_value.emplace(key, value);
    }
  }
  return key_to_value;
}

// /set-header?HEADERS
// Returns a response with HEADERS set as the response headers, and also set as
// the response content.
//
// Example:
//    /set-header?Content-Security-Policy: sandbox&Referer-Policy: origin
std::unique_ptr<HttpResponse> HandleSetHeader(const HttpRequest& request) {
  std::string content;

  GURL request_url = request.GetURL();

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");
  auto headers = ExtractHeadersFromQuery(request_url);
  for (const auto& [key, value] : headers) {
    http_response->AddCustomHeader(key, value);
    content += key + ": " + value;
  }

  http_response->set_content(content);
  return http_response;
}

// /set-header-with-file/FILE_PATH?HEADERS
// Returns a response with context read from FILE_PATH as the response content,
// and HEADERS as the response header. Unlike /set-header?HEADERS, which only
// serves a response with HEADERS as response header and also HEADERS as its
// content.
//
// FILE_PATH points to the static test file. For example, a query like
// /set-header-with-file/content/test/data/title1.html will returns the content
// of the file at content/test/data/title1.html.
// HEADERS is composed of a list of "key: value" pairs. Note that unlike how a
// file is normally served by `HandleFileRequest()`, its static mock headers
// from the other file FILE_PATH.mock-http-headers will NOT be used here.
//
// Example:
//    /set-header-with-file/content/test/data/title1.html?Referer-Policy: origin
std::unique_ptr<HttpResponse> HandleSetHeaderWithFile(
    const std::string& prefix,
    const HttpRequest& request) {
  if (!ShouldHandle(request, prefix)) {
    return nullptr;
  }

  GURL request_url = request.GetURL();
  auto http_response = std::make_unique<BasicHttpResponse>();

  base::FilePath server_root;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &server_root);
  base::FilePath file_path =
      server_root.AppendASCII(request_url.path().substr(prefix.size() + 1));
  std::string file_content;
  CHECK(base::ReadFileToString(file_path, &file_content));
  http_response->set_content(file_content);
  http_response->set_content_type(GetContentType(file_path));

  auto headers = ExtractHeadersFromQuery(request_url);
  for (const auto& [key, value] : headers) {
    http_response->AddCustomHeader(key, value);
  }

  http_response->set_code(HTTP_OK);
  return http_response;
}

// /iframe?URL
// Returns a page that iframes the specified URL.
std::unique_ptr<HttpResponse> HandleIframe(const HttpRequest& request) {
  GURL request_url = request.GetURL();

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");

  GURL iframe_url("about:blank");
  if (request_url.has_query()) {
    iframe_url = GURL(base::UnescapeBinaryURLComponent(request_url.query()));
  }

  http_response->set_content(base::StringPrintf(
      "<!doctype html><iframe src=\"%s\">", iframe_url.spec().c_str()));
  return http_response;
}

// /nocontent
// Returns a NO_CONTENT response.
std::unique_ptr<HttpResponse> HandleNoContent(const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(HTTP_NO_CONTENT);
  return http_response;
}

// /close-socket
// Immediately closes the connection.
std::unique_ptr<HttpResponse> HandleCloseSocket(const HttpRequest& request) {
  return std::make_unique<RawHttpResponse>("", "");
}

// /auth-basic?password=PASS&realm=REALM
// Performs "Basic" HTTP authentication using expected password PASS and
// realm REALM.
std::unique_ptr<HttpResponse> HandleAuthBasic(const HttpRequest& request) {
  GURL request_url = request.GetURL();
  RequestQuery query = ParseQuery(request_url);

  std::string expected_password = kDefaultPassword;
  if (query.find("password") != query.end())
    expected_password = query.at("password").front();
  std::string realm = kDefaultRealm;
  if (query.find("realm") != query.end())
    realm = query.at("realm").front();

  bool authed = false;
  std::string error;
  std::string auth;
  std::string username;
  std::string userpass;
  std::string password;
  std::string b64str;
  if (request.headers.find("Authorization") == request.headers.end()) {
    error = "Missing Authorization Header";
  } else {
    auth = request.headers.at("Authorization");
    if (auth.find("Basic ") == std::string::npos) {
      error = "Invalid Authorization Header";
    } else {
      b64str = auth.substr(std::string("Basic ").size());
      base::Base64Decode(b64str, &userpass);
      size_t delimiter = userpass.find(":");
      if (delimiter != std::string::npos) {
        username = userpass.substr(0, delimiter);
        password = userpass.substr(delimiter + 1);
        if (password == expected_password)
          authed = true;
        else
          error = "Invalid Credentials";
      } else {
        error = "Invalid Credentials";
      }
    }
  }

  auto http_response = std::make_unique<BasicHttpResponse>();
  if (!authed) {
    http_response->set_code(HTTP_UNAUTHORIZED);
    http_response->set_content_type("text/html");
    http_response->AddCustomHeader("WWW-Authenticate",
                                   "Basic realm=\"" + realm + "\"");
    if (query.find("set-cookie-if-challenged") != query.end())
      http_response->AddCustomHeader("Set-Cookie", "got_challenged=true");
    if (query.find("set-secure-cookie-if-challenged") != query.end())
      http_response->AddCustomHeader("Set-Cookie",
                                     "got_challenged=true;Secure");
    http_response->set_content(base::StringPrintf(
        "<!doctype html><title>Denied: %s</title>"
        "<p>auth=%s<p>b64str=%s<p>username: %s<p>userpass: %s"
        "<p>password: %s<p>You sent:<br>%s",
        error.c_str(), auth.c_str(), b64str.c_str(), username.c_str(),
        userpass.c_str(), password.c_str(), request.all_headers.c_str()));
    return http_response;
  }

  if (query.find("set-cookie-if-not-challenged") != query.end())
    http_response->AddCustomHeader("Set-Cookie", "got_challenged=true");

  if (request.headers.find("If-None-Match") != request.headers.end() &&
      request.headers.at("If-None-Match") == kEtag) {
    http_response->set_code(HTTP_NOT_MODIFIED);
    return http_response;
  }

  base::FilePath file_path =
      base::FilePath().AppendASCII(request.relative_url.substr(1));
  if (file_path.FinalExtension() == FILE_PATH_LITERAL("gif")) {
    base::FilePath server_root;
    base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &server_root);
    base::FilePath gif_path = server_root.AppendASCII(kLogoPath);
    std::string gif_data;
    base::ReadFileToString(gif_path, &gif_data);
    http_response->set_content_type("image/gif");
    http_response->set_content(gif_data);
  } else {
    http_response->set_content_type("text/html");
    http_response->set_content(
        base::StringPrintf("<!doctype html><title>%s/%s</title>"
                           "<p>auth=%s<p>You sent:<br>%s",
                           username.c_str(), password.c_str(), auth.c_str(),
                           request.all_headers.c_str()));
  }

  http_response->AddCustomHeader("Cache-Control", "max-age=60000");
  http_response->AddCustomHeader("Etag", kEtag);
  return http_response;
}

// /auth-digest
// Performs "Digest" HTTP authentication.
std::unique_ptr<HttpResponse> HandleAuthDigest(const HttpRequest& request) {
  std::string nonce = base::MD5String(
      base::StringPrintf("privatekey%s", request.relative_url.c_str()));
  std::string opaque = base::MD5String("opaque");
  std::string password = kDefaultPassword;
  std::string realm = kDefaultRealm;

  bool authed = false;
  std::string error;
  std::string auth;
  std::string digest_str = "Digest";
  std::string username;
  if (request.headers.find("Authorization") == request.headers.end()) {
    error = "no auth";
  } else if (request.headers.at("Authorization").substr(0, digest_str.size()) !=
             digest_str) {
    error = "not digest";
  } else {
    auth = request.headers.at("Authorization").substr(digest_str.size() + 1);

    std::map<std::string, std::string> auth_pairs;
    base::StringPairs auth_vector;
    base::SplitStringIntoKeyValuePairs(auth, '=', ',', &auth_vector);
    for (const auto& auth_pair : auth_vector) {
      std::string key;
      std::string value;
      base::TrimWhitespaceASCII(auth_pair.first, base::TRIM_ALL, &key);
      base::TrimWhitespaceASCII(auth_pair.second, base::TRIM_ALL, &value);
      if (value.size() > 2 && value.at(0) == '"' &&
          value.at(value.size() - 1) == '"') {
        value = value.substr(1, value.size() - 2);
      }
      auth_pairs[key] = value;
    }

    if (auth_pairs["nonce"] != nonce) {
      error = "wrong nonce";
    } else if (auth_pairs["opaque"] != opaque) {
      error = "wrong opaque";
    } else {
      username = auth_pairs["username"];

      std::string hash1 = base::MD5String(
          base::StringPrintf("%s:%s:%s", auth_pairs["username"].c_str(),
                             realm.c_str(), password.c_str()));
      std::string hash2 = base::MD5String(base::StringPrintf(
          "%s:%s", request.method_string.c_str(), auth_pairs["uri"].c_str()));

      std::string response;
      if (auth_pairs.find("qop") != auth_pairs.end() &&
          auth_pairs.find("nc") != auth_pairs.end() &&
          auth_pairs.find("cnonce") != auth_pairs.end()) {
        response = base::MD5String(base::StringPrintf(
            "%s:%s:%s:%s:%s:%s", hash1.c_str(), nonce.c_str(),
            auth_pairs["nc"].c_str(), auth_pairs["cnonce"].c_str(),
            auth_pairs["qop"].c_str(), hash2.c_str()));
      } else {
        response = base::MD5String(base::StringPrintf(
            "%s:%s:%s", hash1.c_str(), nonce.c_str(), hash2.c_str()));
      }

      if (auth_pairs["response"] == response)
        authed = true;
      else
        error = "wrong password";
    }
  }

  auto http_response = std::make_unique<BasicHttpResponse>();
  if (!authed) {
    http_response->set_code(HTTP_UNAUTHORIZED);
    http_response->set_content_type("text/html");
    std::string auth_header = base::StringPrintf(
        "Digest realm=\"%s\", "
        "domain=\"/\", qop=\"auth\", algorithm=MD5, nonce=\"%s\", "
        "opaque=\"%s\"",
        realm.c_str(), nonce.c_str(), opaque.c_str());
    http_response->AddCustomHeader("WWW-Authenticate", auth_header);
    http_response->set_content(
        base::StringPrintf("<!doctype html><title>Denied: %s</title>"
                           "<p>auth=%s"
                           "You sent:<br>%s<p>We are replying:<br>%s",
                           error.c_str(), auth.c_str(),
                           request.all_headers.c_str(), auth_header.c_str()));
    return http_response;
  }

  http_response->set_content_type("text/html");
  http_response->set_content(
      base::StringPrintf("<!doctype html><title>%s/%s</title>"
                         "<p>auth=%s",
                         username.c_str(), password.c_str(), auth.c_str()));

  return http_response;
}

// 1. /server-redirect?URL or /server-redirect-xxx?URL
//    Returns a server redirect to URL.
// 2. /no-cors-server-redirect?URL or /no-cors-server-redirect-xxx?URL
//    Returns a server redirect to URL which does not allow CORS.
std::unique_ptr<HttpResponse> HandleServerRedirect(HttpStatusCode redirect_code,
                                                   bool allow_cors,
                                                   const HttpRequest& request) {
  GURL request_url = request.GetURL();
  std::string dest =
      base::UnescapeBinaryURLComponent(request_url.query_piece());
  RequestQuery query = ParseQuery(request_url);

  if (request.method == METHOD_OPTIONS) {
    auto http_response = std::make_unique<BasicHttpResponse>();
    http_response->set_code(HTTP_OK);
    if (allow_cors) {
      http_response->AddCustomHeader("Access-Control-Allow-Origin", "*");
      http_response->AddCustomHeader("Access-Control-Allow-Methods", "*");
      http_response->AddCustomHeader("Access-Control-Allow-Headers", "*");
    }
    return http_response;
  }

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(redirect_code);
  http_response->AddCustomHeader("Location", dest);
  if (allow_cors) {
    http_response->AddCustomHeader("Access-Control-Allow-Origin", "*");
  }
  http_response->set_content_type("text/html");
  http_response->set_content(
      base::StringPrintf("<!doctype html><p>Redirecting to %s", dest.c_str()));
  return http_response;
}
// /server-redirect-with-cookie?URL
// Returns a server redirect to URL, and sets the cookie server-redirect=true.
std::unique_ptr<HttpResponse> HandleServerRedirectWithCookie(
    HttpStatusCode redirect_code,
    const HttpRequest& request) {
  GURL request_url = request.GetURL();
  std::string dest =
      base::UnescapeBinaryURLComponent(request_url.query_piece());
  RequestQuery query = ParseQuery(request_url);

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(redirect_code);
  http_response->AddCustomHeader("Location", dest);
  http_response->AddCustomHeader("Set-Cookie", "server-redirect=true");
  http_response->set_content_type("text/html");
  http_response->set_content(
      base::StringPrintf("<!doctype html><p>Redirecting to %s", dest.c_str()));
  return http_response;
}

// /server-redirect-with-secure-cookie?URL
// Returns a server redirect to URL, and sets the cookie
// server-redirect=true;Secure.
std::unique_ptr<HttpResponse> HandleServerRedirectWithSecureCookie(
    HttpStatusCode redirect_code,
    const HttpRequest& request) {
  GURL request_url = request.GetURL();
  std::string dest =
      base::UnescapeBinaryURLComponent(request_url.query_piece());
  RequestQuery query = ParseQuery(request_url);

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(redirect_code);
  http_response->AddCustomHeader("Location", dest);
  http_response->AddCustomHeader("Set-Cookie", "server-redirect=true;Secure");
  http_response->set_content_type("text/html");
  http_response->set_content(
      base::StringPrintf("<!doctype html><p>Redirecting to %s", dest.c_str()));
  return http_response;
}

// /cross-site?URL (also /cross-site-with-cookie?URL)
// Returns a cross-site redirect to URL.
std::unique_ptr<HttpResponse> HandleCrossSiteRedirect(
    EmbeddedTestServer* server,
    const std::string& prefix,
    bool set_cookie,
    const HttpRequest& request) {
  if (!ShouldHandle(request, prefix))
    return nullptr;

  std::string dest_all = base::UnescapeBinaryURLComponent(
      request.relative_url.substr(prefix.size() + 1));

  std::string dest;
  size_t delimiter = dest_all.find("/");
  if (delimiter != std::string::npos) {
    dest = base::StringPrintf(
        "//%s:%hu/%s", dest_all.substr(0, delimiter).c_str(), server->port(),
        dest_all.substr(delimiter + 1).c_str());
  }

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(HTTP_MOVED_PERMANENTLY);
  http_response->AddCustomHeader("Location", dest);
  if (set_cookie) {
    http_response->AddCustomHeader("Set-Cookie", "server-redirect=true");
  }
  http_response->set_content_type("text/html");
  http_response->set_content(
      base::StringPrintf("<!doctype html><p>Redirecting to %s", dest.c_str()));
  return http_response;
}

// /client-redirect?URL
// Returns a meta redirect to URL.
std::unique_ptr<HttpResponse> HandleClientRedirect(const HttpRequest& request) {
  GURL request_url = request.GetURL();
  std::string dest =
      base::UnescapeBinaryURLComponent(request_url.query_piece());

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");
  http_response->set_content(base::StringPrintf(
      "<!doctype html><meta http-equiv=\"refresh\" content=\"0;url=%s\">"
      "<p>Redirecting to %s",
      dest.c_str(), dest.c_str()));
  return http_response;
}

// /defaultresponse
// Returns a valid 200 response.
std::unique_ptr<HttpResponse> HandleDefaultResponse(
    const HttpRequest& request) {
  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content_type("text/html");
  http_response->set_content("Default response given for path: " +
                             request.relative_url);
  return http_response;
}

// /slow?N
// Returns a response to the server delayed by N seconds.
std::unique_ptr<HttpResponse> HandleSlowServer(const HttpRequest& request) {
  double delay = 1.0f;

  GURL request_url = request.GetURL();
  if (request_url.has_query())
    delay = std::atof(request_url.query().c_str());

  auto http_response =
      std::make_unique<DelayedHttpResponse>(base::Seconds(delay));
  http_response->set_content_type("text/plain");
  http_response->set_content(base::StringPrintf("waited %.1f seconds", delay));
  return http_response;
}

// /hung
// Never returns a response.
std::unique_ptr<HttpResponse> HandleHungResponse(const HttpRequest& request) {
  return std::make_unique<HungResponse>();
}

// /hung-after-headers
// Never returns a response.
std::unique_ptr<HttpResponse> HandleHungAfterHeadersResponse(
    const HttpRequest& request) {
  return std::make_unique<HungAfterHeadersHttpResponse>();
}

// /exabyte_response
// A HttpResponse that is almost never ending (with an Exabyte content-length).
class ExabyteResponse : public BasicHttpResponse {
 public:
  ExabyteResponse() = default;

  ExabyteResponse(const ExabyteResponse&) = delete;
  ExabyteResponse& operator=(const ExabyteResponse&) = delete;

  void SendResponse(base::WeakPtr<HttpResponseDelegate> delegate) override {
    // Use 10^18 bytes (exabyte) as the content length so that the client will
    // be expecting data.
    delegate->SendResponseHeaders(HTTP_OK, "OK",
                                  {{"Content-Length", "1000000000000000000"}});
    SendExabyte(delegate);
  }

 private:
  // Keeps sending the word "echo" over and over again. It can go further to
  // limit the response to exactly an exabyte, but it shouldn't be necessary
  // for the purpose of testing.
  void SendExabyte(base::WeakPtr<HttpResponseDelegate> delegate) {
    delegate->SendContents(
        "echo", base::BindOnce(&ExabyteResponse::PostSendExabyteTask,
                               weak_factory_.GetWeakPtr(), delegate));
  }

  void PostSendExabyteTask(base::WeakPtr<HttpResponseDelegate> delegate) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&ExabyteResponse::SendExabyte,
                                  weak_factory_.GetWeakPtr(), delegate));
  }

  base::WeakPtrFactory<ExabyteResponse> weak_factory_{this};
};

// /exabyte_response
// Almost never ending response.
std::unique_ptr<HttpResponse> HandleExabyteResponse(
    const HttpRequest& request) {
  return std::make_unique<ExabyteResponse>();
}

// /gzip-body?<body>
// Returns a response with a gzipped body of "<body>". Attempts to allocate
// enough memory to contain the body, but DCHECKs if that fails.
std::unique_ptr<HttpResponse> HandleGzipBody(const HttpRequest& request) {
  std::string uncompressed_body = request.GetURL().query();
  // Attempt to pick size that's large enough even in the worst case (deflate
  // block headers should be shorter than 512 bytes, and deflating should never
  // double size of data, modulo headers).
  // TODO(mmenke): This is rather awkward. Worth improving CompressGzip?
  std::vector<char> compressed_body(uncompressed_body.size() * 2 + 512);
  size_t compressed_size = compressed_body.size();
  CompressGzip(uncompressed_body.c_str(), uncompressed_body.size(),
               compressed_body.data(), &compressed_size,
               true /* gzip_framing */);
  // CompressGzip should DCHECK itself if this fails, anyways.
  DCHECK_GE(compressed_body.size(), compressed_size);

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_content(
      std::string(compressed_body.data(), compressed_size));
  http_response->AddCustomHeader("Content-Encoding", "gzip");
  http_response->AddCustomHeader("Cache-Control", "max-age=60");
  return http_response;
}

// /self.pac
// Returns a response that is a PAC script making requests use the
// EmbeddedTestServer itself as a proxy.
std::unique_ptr<HttpResponse> HandleSelfPac(const HttpRequest& request) {
  std::unique_ptr<BasicHttpResponse> http_response =
      std::make_unique<BasicHttpResponse>();
  http_response->set_content(base::StringPrintf(
      "function FindProxyForURL(url, host) {\n"
      "return 'PROXY %s';\n"
      "}",
      net::HostPortPair::FromURL(request.base_url).ToString().c_str()));
  return http_response;
}

// A chunked HTTP response, with optional delays between chunks. See
// HandleChun
"""


```