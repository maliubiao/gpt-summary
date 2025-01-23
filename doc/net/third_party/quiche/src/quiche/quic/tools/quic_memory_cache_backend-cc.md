Response:
Let's break down the thought process for analyzing the `quic_memory_cache_backend.cc` file.

1. **Understand the Core Purpose:** The name "QuicMemoryCacheBackend" strongly suggests this component acts as an in-memory cache for HTTP responses within a QUIC server. The `.cc` extension indicates C++ source code, likely part of the Chromium network stack's QUIC implementation.

2. **Identify Key Data Structures:** Scan the class definition and member variables. The presence of `responses_` (a map), `default_response_`, and `generate_bytes_response_` are strong indicators of the caching mechanism. The `ResourceFile` inner class hints at how cached data might be loaded from files.

3. **Analyze Core Methods:**  Focus on the public methods. Methods like `GetResponse`, `AddResponse`, `AddSimpleResponse`, `InitializeBackend`, and `FetchResponseFromBackend` are crucial for understanding the backend's functionality.

4. **Trace Data Flow:**  Consider how data enters and leaves the cache.
    * **Loading:** `InitializeBackend` reads files from a directory and populates the `responses_` map.
    * **Adding:** `AddResponse` (and its variations) programmatically inserts responses.
    * **Retrieving:** `GetResponse` looks up responses based on host and path.
    * **Serving:** `FetchResponseFromBackend` uses `GetResponse` to serve responses to incoming requests.

5. **Examine Specific Functionalities:**
    * **File Loading:**  The `ResourceFile` class and its `Read()` method are responsible for parsing cached responses from files. Note the handling of headers and body separation.
    * **Key Generation:** The `GetKey()` method defines how cache entries are indexed.
    * **Special Responses:** The `AddSpecialResponse()` method allows for non-standard responses (like error codes).
    * **Dynamic Responses:** The `GenerateDynamicResponses()` method shows how to create responses programmatically (in this case, a byte generation response).
    * **WebTransport Support:** The `EnableWebTransport()` and `ProcessWebTransportRequest()` methods indicate integration with the WebTransport protocol.

6. **Look for JavaScript Relevance:**  Consider how a memory cache backend might interact with a JavaScript environment in a browser. While the C++ code doesn't *directly* interact with JavaScript, it provides the underlying mechanism for serving web resources. The key connection is through the browser's network stack:
    * JavaScript makes a network request (e.g., using `fetch`).
    * The browser's QUIC implementation uses this backend to check if a cached response exists.
    * If cached, the response is served without hitting the network.
    * This improves page load times and reduces bandwidth usage, which is directly observable in the JavaScript environment.

7. **Consider Logic and Assumptions:** Analyze the decision-making within the code. For example, how does `GetResponse` handle cache misses? How does `InitializeBackend` process filenames?

8. **Identify Potential Errors:** Think about common mistakes users or programmers might make. Providing an empty cache directory, duplicate cache entries, or incorrectly formatted cache files are all potential issues.

9. **Trace User Interaction:**  Imagine the steps a user takes that would lead to this code being executed. Typing a URL, clicking a link, or a JavaScript application making an API call can all trigger network requests that might be served by this cache.

10. **Structure the Explanation:** Organize the findings into logical sections: Functionality, JavaScript relevance, Logic/Assumptions, Common Errors, and Debugging. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just a simple key-value store for HTTP responses."  **Correction:** It's more than that. It handles loading from files, has special response types, and integrates with WebTransport.
* **Initial thought:** "JavaScript directly calls this C++ code." **Correction:**  JavaScript interacts with the *browser's* network APIs, which in turn use this C++ backend. The connection is indirect.
* **Realization:** The `ResourceFile` class is crucial for understanding how the cache is populated from disk. Need to explain its role in detail.
* **Consideration:** The `GetKey` function normalizes hostnames by removing the port. This is an important detail to include.
* **Emphasis:** The performance implications for JavaScript (faster loading) are a key point to highlight.

By following these steps and iterating through the code, a comprehensive understanding of the `quic_memory_cache_backend.cc` file can be developed, leading to a detailed and accurate explanation.
这个文件是 Chromium 网络栈中 QUIC 协议实现的一部分，它实现了一个**内存缓存后端**，用于模拟服务器的行为，主要用于测试和本地开发环境。

以下是它的主要功能：

**1. 模拟 HTTP/3 服务器行为:**
    *  它能够存储和检索预定义的 HTTP 响应，包括状态码、头部和 body。
    *  它可以根据请求的 host 和 path (URL 的一部分) 返回对应的缓存响应。

**2. 从文件系统加载缓存:**
    *  它能够从指定的目录中读取文件，并将文件内容解析为 HTTP 响应存储在内存中。
    *  文件名被解析成 host 和 path 信息，用于后续的请求匹配。
    *  文件内容需要符合特定的格式：HTTP 头部以行为单位，以空行分隔头部和 body。

**3. 支持动态生成响应:**
    *  它可以配置生成特定类型的动态响应，例如生成指定大小的字节流，用于测试下载等场景。

**4. 支持设置响应延迟:**
    *  可以为特定的请求设置响应延迟，用于模拟网络延迟。

**5. 支持 Early Hints:**
    *  能够为响应添加 Early Hints 头部，用于优化页面加载性能。

**6. 支持特殊类型的响应:**
    *  可以添加预定义的特殊类型响应，例如用于模拟错误状态或重定向。

**7. 支持 WebTransport:**
    *  可以处理 WebTransport 请求，并提供简单的 "echo" 功能作为示例。

**与 JavaScript 功能的关系和举例说明:**

尽管这个 C++ 文件本身不包含 JavaScript 代码，但它提供的缓存功能直接影响到 JavaScript 在浏览器中的行为。

**举例说明:**

假设一个网站的静态资源 (例如图片、CSS 文件、JavaScript 文件) 被存储在这个内存缓存后端中。

1. **JavaScript 发起请求:**  浏览器中的 JavaScript 代码通过 `fetch()` API 或 `XMLHttpRequest` 发起对某个静态资源的请求，例如 `https://example.com/image.png`。

2. **QUIC 连接处理:**  Chromium 的网络栈使用 QUIC 协议与服务器建立连接 (如果是 HTTPS)。

3. **内存缓存查找:**  `QuicMemoryCacheBackend` 会接收到请求的 host (`example.com`) 和 path (`/image.png`)。

4. **返回缓存响应:** 如果在内存缓存中找到了匹配的响应，`QuicMemoryCacheBackend` 会将缓存的 HTTP 响应 (包括头部和图片数据) 返回给 QUIC 连接处理模块。

5. **浏览器接收数据:**  浏览器接收到响应数据。

6. **JavaScript 处理数据:**  JavaScript 代码可以访问 `fetch()` API 返回的 Response 对象，获取图片的 URL、HTTP 头部和图片数据，并进行后续处理 (例如显示图片)。

**在这个过程中，`QuicMemoryCacheBackend` 的作用是加速资源加载，避免真实的网络请求。这对于本地开发和测试环境非常有用，可以快速模拟各种服务器响应。**

**逻辑推理、假设输入与输出:**

**假设输入:**

* **缓存目录:**  一个包含以下文件的目录：
    * `example.com/index.html`: 内容为 "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h1>Hello World</h1>"
    * `example.com/style.css`: 内容为 "HTTP/1.1 200 OK\nContent-Type: text/css\n\nbody { color: blue; }"

* **请求:** 一个 QUIC 连接请求 `https://example.com/index.html`。

**逻辑推理:**

1. `InitializeBackend` 函数会被调用，并指定缓存目录。
2. `InitializeBackend` 会读取 `example.com/index.html` 和 `example.com/style.css` 两个文件。
3. 对于 `index.html`，`SetHostPathFromBase` 会解析出 host 为 `example.com`，path 为 `/index.html`。
4. `Read` 函数会解析文件内容，提取出 HTTP 头部和 body。
5. 一个包含 `index.html` 响应的 `QuicBackendResponse` 对象会被添加到 `responses_` map 中，key 为 `example.com/index.html`。
6. 当收到对 `https://example.com/index.html` 的请求时，`FetchResponseFromBackend` 函数会被调用。
7. `GetResponse` 函数会查找 `responses_` map，找到 key 为 `example.com/index.html` 的响应。

**预期输出:**

* `GetResponse` 函数返回一个指向包含 "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h1>Hello World</h1>" 响应的 `QuicBackendResponse` 对象的指针。
* 浏览器会收到包含 "Hello World" 的 HTML 页面。

**用户或编程常见的使用错误:**

1. **缓存文件格式错误:**
    * **错误:**  缓存文件缺少空行分隔头部和 body，或者 HTTP 头部格式不正确 (例如缺少冒号)。
    * **结果:**  `Read()` 函数中的 `QUIC_LOG(DFATAL)` 会被触发，表示无法解析文件，该文件会被忽略。
    * **用户操作:** 用户手动创建或修改缓存文件时，可能会不小心破坏文件格式。

2. **缓存目录不存在或不可读:**
    * **错误:**  传递给 `InitializeBackend` 的缓存目录路径不存在或者程序没有读取该目录的权限。
    * **结果:** `EnumerateDirectoryRecursively` 函数会返回 `false`，导致 `InitializeBackend` 返回 `false`，缓存无法加载。
    * **用户操作:**  在命令行启动程序时，可能错误地指定了缓存目录路径，或者文件系统权限设置不正确。

3. **重复添加相同 host 和 path 的响应:**
    * **错误:**  多次调用 `AddResponse` 或 `AddSimpleResponse` 添加相同的 host 和 path 的响应。
    * **结果:**  `AddResponseImpl` 函数中的 `QUIC_BUG` 会被触发，提示已存在相同的响应。
    * **编程错误:**  在配置缓存时，逻辑错误导致重复添加相同的资源。

4. **期望缓存生效但未正确配置:**
    * **错误:**  用户期望某个请求使用缓存响应，但该请求的 host 或 path 与缓存中的不匹配。
    * **结果:**  `GetResponse` 函数返回 `nullptr`，表示缓存未命中，可能会导致实际的网络请求。
    * **用户操作/编程错误:**  缓存配置不完整或者请求的 URL 与缓存配置不一致。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问一个使用了 QUIC 协议的网站，并且该网站的资源被配置为使用 `QuicMemoryCacheBackend` 进行缓存。以下是可能的操作步骤：

1. **启动 Chromium 浏览器并开启 QUIC 支持。**  (某些版本的 Chromium 可能默认开启 QUIC)

2. **在命令行启动一个使用 `QuicMemoryCacheBackend` 的 QUIC 服务器。**  这通常是开发者在本地搭建测试环境时进行的操作。启动命令可能包含指定缓存目录的参数。

3. **在浏览器地址栏输入要访问的 URL，例如 `https://example.com/index.html`，然后回车。**

4. **浏览器解析 URL，并尝试与服务器建立 QUIC 连接。**

5. **Chromium 的网络栈在处理该请求时，会调用到 `QuicMemoryCacheBackend` 的相关方法。**

6. **`FetchResponseFromBackend` 函数会被调用，传入请求的头部信息。**

7. **`GetResponse` 函数会根据请求的 `:authority` (host) 和 `:path` 在内存缓存中查找匹配的响应。**

8. **如果找到了匹配的响应，缓存的 HTTP 响应会被返回给浏览器。** 浏览器会渲染页面。

9. **如果在调试过程中发现页面加载不正确，或者期望的缓存没有生效，开发者可以检查以下内容作为调试线索：**

    * **确认 QUIC 连接是否建立成功。**  可以使用 Chrome 的 `chrome://net-internals/#quic` 页面查看 QUIC 连接信息。
    * **检查服务器端的 `QuicMemoryCacheBackend` 的日志输出。**  查看是否成功加载了缓存文件，以及请求是否命中了缓存。
    * **检查缓存目录中的文件内容和格式是否正确。**
    * **确认请求的 URL (host 和 path) 与缓存中配置的响应是否一致。**
    * **如果设置了响应延迟，确认是否符合预期。**

通过以上分析，可以定位问题是出在缓存配置错误、文件格式问题，还是其他网络层的问题。  `QuicMemoryCacheBackend` 的代码提供了查看缓存加载和匹配逻辑的关键入口。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/quic_memory_cache_backend.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_memory_cache_backend.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/spdy_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/tools/web_transport_test_visitors.h"
#include "quiche/common/platform/api/quiche_file_utils.h"
#include "quiche/common/quiche_text_utils.h"

using quiche::HttpHeaderBlock;
using spdy::kV3LowestPriority;

namespace quic {

QuicMemoryCacheBackend::ResourceFile::ResourceFile(const std::string& file_name)
    : file_name_(file_name) {}

QuicMemoryCacheBackend::ResourceFile::~ResourceFile() = default;

void QuicMemoryCacheBackend::ResourceFile::Read() {
  std::optional<std::string> maybe_file_contents =
      quiche::ReadFileContents(file_name_);
  if (!maybe_file_contents) {
    QUIC_LOG(DFATAL) << "Failed to read file for the memory cache backend: "
                     << file_name_;
    return;
  }
  file_contents_ = *maybe_file_contents;

  // First read the headers.
  for (size_t start = 0; start < file_contents_.length();) {
    size_t pos = file_contents_.find('\n', start);
    if (pos == std::string::npos) {
      QUIC_LOG(DFATAL) << "Headers invalid or empty, ignoring: " << file_name_;
      return;
    }
    size_t len = pos - start;
    // Support both dos and unix line endings for convenience.
    if (file_contents_[pos - 1] == '\r') {
      len -= 1;
    }
    absl::string_view line(file_contents_.data() + start, len);
    start = pos + 1;
    // Headers end with an empty line.
    if (line.empty()) {
      body_ = absl::string_view(file_contents_.data() + start,
                                file_contents_.size() - start);
      break;
    }
    // Extract the status from the HTTP first line.
    if (line.substr(0, 4) == "HTTP") {
      pos = line.find(' ');
      if (pos == std::string::npos) {
        QUIC_LOG(DFATAL) << "Headers invalid or empty, ignoring: "
                         << file_name_;
        return;
      }
      spdy_headers_[":status"] = line.substr(pos + 1, 3);
      continue;
    }
    // Headers are "key: value".
    pos = line.find(": ");
    if (pos == std::string::npos) {
      QUIC_LOG(DFATAL) << "Headers invalid or empty, ignoring: " << file_name_;
      return;
    }
    spdy_headers_.AppendValueOrAddHeader(
        quiche::QuicheTextUtils::ToLower(line.substr(0, pos)),
        line.substr(pos + 2));
  }

  // The connection header is prohibited in HTTP/2.
  spdy_headers_.erase("connection");

  // Override the URL with the X-Original-Url header, if present.
  if (auto it = spdy_headers_.find("x-original-url");
      it != spdy_headers_.end()) {
    x_original_url_ = it->second;
    HandleXOriginalUrl();
  }
}

void QuicMemoryCacheBackend::ResourceFile::SetHostPathFromBase(
    absl::string_view base) {
  QUICHE_DCHECK(base[0] != '/') << base;
  size_t path_start = base.find_first_of('/');
  if (path_start == absl::string_view::npos) {
    host_ = std::string(base);
    path_ = "";
    return;
  }

  host_ = std::string(base.substr(0, path_start));
  size_t query_start = base.find_first_of(',');
  if (query_start > 0) {
    path_ = std::string(base.substr(path_start, query_start - 1));
  } else {
    path_ = std::string(base.substr(path_start));
  }
}

absl::string_view QuicMemoryCacheBackend::ResourceFile::RemoveScheme(
    absl::string_view url) {
  if (absl::StartsWith(url, "https://")) {
    url.remove_prefix(8);
  } else if (absl::StartsWith(url, "http://")) {
    url.remove_prefix(7);
  }
  return url;
}

void QuicMemoryCacheBackend::ResourceFile::HandleXOriginalUrl() {
  absl::string_view url(x_original_url_);
  SetHostPathFromBase(RemoveScheme(url));
}

const QuicBackendResponse* QuicMemoryCacheBackend::GetResponse(
    absl::string_view host, absl::string_view path) const {
  quiche::QuicheWriterMutexLock lock(&response_mutex_);

  auto it = responses_.find(GetKey(host, path));
  if (it == responses_.end()) {
    uint64_t ignored = 0;
    if (generate_bytes_response_) {
      if (absl::SimpleAtoi(absl::string_view(path.data() + 1, path.size() - 1),
                           &ignored)) {
        // The actual parsed length is ignored here and will be recomputed
        // by the caller.
        return generate_bytes_response_.get();
      }
    }
    QUIC_DVLOG(1) << "Get response for resource failed: host " << host
                  << " path " << path;
    if (default_response_) {
      return default_response_.get();
    }
    return nullptr;
  }
  return it->second.get();
}

using SpecialResponseType = QuicBackendResponse::SpecialResponseType;

void QuicMemoryCacheBackend::AddSimpleResponse(absl::string_view host,
                                               absl::string_view path,
                                               int response_code,
                                               absl::string_view body) {
  HttpHeaderBlock response_headers;
  response_headers[":status"] = absl::StrCat(response_code);
  response_headers["content-length"] = absl::StrCat(body.length());
  AddResponse(host, path, std::move(response_headers), body);
}

void QuicMemoryCacheBackend::AddDefaultResponse(QuicBackendResponse* response) {
  quiche::QuicheWriterMutexLock lock(&response_mutex_);
  default_response_.reset(response);
}

void QuicMemoryCacheBackend::AddResponse(absl::string_view host,
                                         absl::string_view path,
                                         HttpHeaderBlock response_headers,
                                         absl::string_view response_body) {
  AddResponseImpl(host, path, QuicBackendResponse::REGULAR_RESPONSE,
                  std::move(response_headers), response_body, HttpHeaderBlock(),
                  std::vector<quiche::HttpHeaderBlock>());
}

void QuicMemoryCacheBackend::AddResponse(absl::string_view host,
                                         absl::string_view path,
                                         HttpHeaderBlock response_headers,
                                         absl::string_view response_body,
                                         HttpHeaderBlock response_trailers) {
  AddResponseImpl(host, path, QuicBackendResponse::REGULAR_RESPONSE,
                  std::move(response_headers), response_body,
                  std::move(response_trailers),
                  std::vector<quiche::HttpHeaderBlock>());
}

bool QuicMemoryCacheBackend::SetResponseDelay(absl::string_view host,
                                              absl::string_view path,
                                              QuicTime::Delta delay) {
  quiche::QuicheWriterMutexLock lock(&response_mutex_);
  auto it = responses_.find(GetKey(host, path));
  if (it == responses_.end()) return false;

  it->second->set_delay(delay);
  return true;
}

void QuicMemoryCacheBackend::AddResponseWithEarlyHints(
    absl::string_view host, absl::string_view path,
    quiche::HttpHeaderBlock response_headers, absl::string_view response_body,
    const std::vector<quiche::HttpHeaderBlock>& early_hints) {
  AddResponseImpl(host, path, QuicBackendResponse::REGULAR_RESPONSE,
                  std::move(response_headers), response_body, HttpHeaderBlock(),
                  early_hints);
}

void QuicMemoryCacheBackend::AddSpecialResponse(
    absl::string_view host, absl::string_view path,
    SpecialResponseType response_type) {
  AddResponseImpl(host, path, response_type, HttpHeaderBlock(), "",
                  HttpHeaderBlock(), std::vector<quiche::HttpHeaderBlock>());
}

void QuicMemoryCacheBackend::AddSpecialResponse(
    absl::string_view host, absl::string_view path,
    quiche::HttpHeaderBlock response_headers, absl::string_view response_body,
    SpecialResponseType response_type) {
  AddResponseImpl(host, path, response_type, std::move(response_headers),
                  response_body, HttpHeaderBlock(),
                  std::vector<quiche::HttpHeaderBlock>());
}

QuicMemoryCacheBackend::QuicMemoryCacheBackend() : cache_initialized_(false) {}

bool QuicMemoryCacheBackend::InitializeBackend(
    const std::string& cache_directory) {
  if (cache_directory.empty()) {
    QUIC_BUG(quic_bug_10932_1) << "cache_directory must not be empty.";
    return false;
  }
  QUIC_LOG(INFO)
      << "Attempting to initialize QuicMemoryCacheBackend from directory: "
      << cache_directory;
  std::vector<std::string> files;
  if (!quiche::EnumerateDirectoryRecursively(cache_directory, files)) {
    QUIC_BUG(QuicMemoryCacheBackend unreadable directory)
        << "Can't read QuicMemoryCacheBackend directory: " << cache_directory;
    return false;
  }
  for (const auto& filename : files) {
    std::unique_ptr<ResourceFile> resource_file(new ResourceFile(filename));

    // Tease apart filename into host and path.
    std::string base(resource_file->file_name());
    // Transform windows path separators to URL path separators.
    for (size_t i = 0; i < base.length(); ++i) {
      if (base[i] == '\\') {
        base[i] = '/';
      }
    }
    base.erase(0, cache_directory.length());
    if (base[0] == '/') {
      base.erase(0, 1);
    }

    resource_file->SetHostPathFromBase(base);
    resource_file->Read();

    AddResponse(resource_file->host(), resource_file->path(),
                resource_file->spdy_headers().Clone(), resource_file->body());
  }

  cache_initialized_ = true;
  return true;
}

void QuicMemoryCacheBackend::GenerateDynamicResponses() {
  quiche::QuicheWriterMutexLock lock(&response_mutex_);
  // Add a generate bytes response.
  quiche::HttpHeaderBlock response_headers;
  response_headers[":status"] = "200";
  generate_bytes_response_ = std::make_unique<QuicBackendResponse>();
  generate_bytes_response_->set_headers(std::move(response_headers));
  generate_bytes_response_->set_response_type(
      QuicBackendResponse::GENERATE_BYTES);
}

void QuicMemoryCacheBackend::EnableWebTransport() {
  enable_webtransport_ = true;
}

bool QuicMemoryCacheBackend::IsBackendInitialized() const {
  return cache_initialized_;
}

void QuicMemoryCacheBackend::FetchResponseFromBackend(
    const HttpHeaderBlock& request_headers, const std::string& request_body,
    QuicSimpleServerBackend::RequestHandler* quic_stream) {
  const QuicBackendResponse* quic_response = nullptr;
  // Find response in cache. If not found, send error response.
  auto authority = request_headers.find(":authority");
  auto path_it = request_headers.find(":path");
  const absl::string_view* path = nullptr;
  if (path_it != request_headers.end()) {
    path = &path_it->second;
  }
  auto method = request_headers.find(":method");
  std::unique_ptr<QuicBackendResponse> echo_response;
  if (path && *path == "/echo" && method != request_headers.end() &&
      method->second == "POST") {
    echo_response = std::make_unique<QuicBackendResponse>();
    quiche::HttpHeaderBlock response_headers;
    response_headers[":status"] = "200";
    echo_response->set_headers(std::move(response_headers));
    echo_response->set_body(request_body);
    quic_response = echo_response.get();
  } else if (authority != request_headers.end() && path) {
    quic_response = GetResponse(authority->second, *path);
  }

  std::string request_url;
  if (authority != request_headers.end()) {
    request_url = std::string(authority->second);
  }
  if (path) {
    request_url += std::string(*path);
  }
  QUIC_DVLOG(1)
      << "Fetching QUIC response from backend in-memory cache for url "
      << request_url;
  quic_stream->OnResponseBackendComplete(quic_response);
}

// The memory cache does not have a per-stream handler
void QuicMemoryCacheBackend::CloseBackendResponseStream(
    QuicSimpleServerBackend::RequestHandler* /*quic_stream*/) {}

QuicMemoryCacheBackend::WebTransportResponse
QuicMemoryCacheBackend::ProcessWebTransportRequest(
    const quiche::HttpHeaderBlock& request_headers,
    WebTransportSession* session) {
  if (!SupportsWebTransport()) {
    return QuicSimpleServerBackend::ProcessWebTransportRequest(request_headers,
                                                               session);
  }

  auto path_it = request_headers.find(":path");
  if (path_it == request_headers.end()) {
    WebTransportResponse response;
    response.response_headers[":status"] = "400";
    return response;
  }
  absl::string_view path = path_it->second;
  if (path == "/echo") {
    WebTransportResponse response;
    response.response_headers[":status"] = "200";
    response.visitor =
        std::make_unique<EchoWebTransportSessionVisitor>(session);
    return response;
  }

  WebTransportResponse response;
  response.response_headers[":status"] = "404";
  return response;
}

QuicMemoryCacheBackend::~QuicMemoryCacheBackend() {
  {
    quiche::QuicheWriterMutexLock lock(&response_mutex_);
    responses_.clear();
  }
}

void QuicMemoryCacheBackend::AddResponseImpl(
    absl::string_view host, absl::string_view path,
    SpecialResponseType response_type, HttpHeaderBlock response_headers,
    absl::string_view response_body, HttpHeaderBlock response_trailers,
    const std::vector<quiche::HttpHeaderBlock>& early_hints) {
  quiche::QuicheWriterMutexLock lock(&response_mutex_);

  QUICHE_DCHECK(!host.empty())
      << "Host must be populated, e.g. \"www.google.com\"";
  std::string key = GetKey(host, path);
  if (responses_.contains(key)) {
    QUIC_BUG(quic_bug_10932_3)
        << "Response for '" << key << "' already exists!";
    return;
  }
  auto new_response = std::make_unique<QuicBackendResponse>();
  new_response->set_response_type(response_type);
  new_response->set_headers(std::move(response_headers));
  new_response->set_body(response_body);
  new_response->set_trailers(std::move(response_trailers));
  for (auto& headers : early_hints) {
    new_response->AddEarlyHints(headers);
  }
  QUIC_DVLOG(1) << "Add response with key " << key;
  responses_[key] = std::move(new_response);
}

std::string QuicMemoryCacheBackend::GetKey(absl::string_view host,
                                           absl::string_view path) const {
  std::string host_string = std::string(host);
  size_t port = host_string.find(':');
  if (port != std::string::npos)
    host_string = std::string(host_string.c_str(), port);
  return host_string + std::string(path);
}

}  // namespace quic
```