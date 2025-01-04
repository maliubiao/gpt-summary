Response:
Let's break down the thought process for analyzing this code and answering the user's request.

**1. Understanding the Core Functionality:**

The first step is to read the code and identify its primary purpose. Keywords and class names are helpful here: `PacFileFetcherImpl`. The name suggests it fetches PAC files. The methods like `Fetch`, `Cancel`, and the callbacks like `OnResponseStarted`, `OnReadCompleted` reinforce this. The comments also directly state this purpose. Therefore, the core function is fetching PAC (Proxy Auto-Config) files.

**2. Identifying Key Responsibilities:**

Once the core function is clear, consider the key responsibilities of the class:

* **Initiating Network Requests:**  It creates and manages `URLRequest` objects.
* **Handling Responses:** It processes the downloaded data, including headers and body.
* **Error Handling:** It deals with network errors, timeouts, and invalid responses.
* **Data Conversion:** It converts the downloaded data to UTF-16.
* **Managing Constraints:**  It enforces size and timeout limits.
* **Callback Mechanism:** It uses a callback to notify the caller of completion.

**3. Connecting to JavaScript:**

The mention of "PAC" immediately brings JavaScript to mind. PAC files are essentially JavaScript code. Therefore, the connection is direct: this code *fetches* the JavaScript code that defines how proxy settings should be determined.

* **Example:** A simple example would be retrieving a PAC file that contains a `FindProxyForURL` function.

**4. Logical Reasoning (Input/Output):**

Think about the `Fetch` method. What does it need, and what does it produce?

* **Input:** A URL of the PAC file and a callback function.
* **Output:** The content of the PAC file (as a UTF-16 string) and a result code indicating success or failure.

Consider different scenarios:

* **Successful Fetch:** Input: Valid URL. Output: PAC script content, `OK`.
* **File Not Found (404):** Input: URL to a non-existent file. Output: Empty string, `ERR_HTTP_RESPONSE_CODE_FAILURE`.
* **Timeout:** Input: URL to a slow server. Output: Empty string, `ERR_TIMED_OUT`.
* **File Too Big:** Input: URL to a very large PAC file. Output: Empty string, `ERR_FILE_TOO_BIG`.

**5. Common User/Programming Errors:**

Think about how someone might misuse this class or encounter common issues.

* **Incorrect URL:**  Typos or pointing to non-PAC files.
* **Network Issues:** The device not being connected to the internet.
* **Server Issues:** The server hosting the PAC file being down or responding with errors.
* **Firewall Blocking:** A firewall preventing access to the PAC file.
* **Conflicting Proxy Settings:** Existing proxy configurations interfering.

**6. Tracing User Actions (Debugging Clues):**

Consider how a user's actions might lead to this code being executed. This involves thinking about where PAC files are configured.

* **Manual Proxy Configuration:**  Users manually entering a PAC file URL in their operating system or browser settings.
* **WPAD (Web Proxy Auto-Discovery):** The system automatically discovering the PAC file location via DHCP or DNS.

The steps involve the user initiating a network request that triggers proxy resolution. The proxy resolution mechanism then needs to fetch the PAC file.

**7. Structuring the Answer:**

Organize the information logically based on the user's questions. Use headings and bullet points for clarity. Provide code snippets or examples where appropriate.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the class *executes* the JavaScript. **Correction:** The code focuses on *fetching* the file. Another part of the Chromium stack is responsible for running the PAC script.
* **Considering edge cases:** What happens with redirects?  The code handles this. What about different character encodings? The code addresses BOMs and charset conversion. This makes the answer more comprehensive.
* **Adding detail:**  Instead of just saying "handles errors," specify some common error codes (`ERR_FILE_TOO_BIG`, `ERR_TIMED_OUT`, etc.).
* **Focusing on the user's perspective:** Explain how user actions trigger this code, providing helpful debugging information.

By following these steps, combining code analysis with domain knowledge (networking, proxying, JavaScript), and thinking from the user's and developer's perspective, a detailed and accurate answer can be constructed.
这个文件 `net/proxy_resolution/pac_file_fetcher_impl.cc` 是 Chromium 网络栈中负责**获取 PAC (Proxy Auto-Config) 文件**的实现。PAC 文件是一个包含 JavaScript 代码的文件，用于决定特定 URL 请求应该使用哪个代理服务器。

**功能列举:**

1. **下载 PAC 文件:**  它通过 URL 发起网络请求，下载 PAC 文件的内容。支持 `http://`, `https://`, 和 `data:` 协议的 URL。
2. **处理下载结果:**  它处理网络请求的各种结果，包括成功、失败、重定向、认证请求、SSL 证书错误等。
3. **超时控制:**  可以设置下载 PAC 文件的最大时长，超过时间会取消请求并返回超时错误。
4. **大小限制:**  可以设置下载 PAC 文件的最大大小，超过大小会取消请求并返回文件过大错误。
5. **字符编码转换:**  它会尝试检测和转换下载的 PAC 文件内容到 UTF-16 编码，这是 Chromium 内部 PAC 脚本引擎使用的编码格式。它会检查 BOM (Byte Order Mark) 并支持指定的字符集。如果未指定字符集，则会猜测或默认使用 ISO-8859-1。
6. **防止循环依赖:**  在下载 PAC 文件时，会强制使用直连，避免因为 PAC 文件的内容指示需要通过代理才能访问自身而导致的循环依赖。
7. **禁用缓存:**  下载 PAC 文件时会禁用缓存，确保获取的是最新的 PAC 文件。
8. **处理 `data:` URL:**  可以直接处理包含 base64 编码 PAC 脚本的 `data:` URL。
9. **错误处理和回调:**  当 PAC 文件下载完成（成功或失败）后，会通过回调函数通知调用者结果和下载的文本内容。

**与 JavaScript 的关系及举例说明:**

PAC 文件本身就是一个包含 JavaScript 代码的文件。`PacFileFetcherImpl` 的主要职责就是获取这个 JavaScript 代码。

**举例说明:**

假设 PAC 文件的 URL 是 `http://example.com/proxy.pac`，其内容如下：

```javascript
function FindProxyForURL(url, host) {
  if (host == "www.google.com") {
    return "PROXY proxy1.example.com:8080";
  } else {
    return "DIRECT";
  }
}
```

当 Chromium 需要决定访问 `www.google.com` 或 `www.example.net` 时使用哪个代理时，会调用 `PacFileFetcherImpl` 去下载 `http://example.com/proxy.pac`。  `PacFileFetcherImpl` 会将上述 JavaScript 代码下载下来，并传递给 PAC 脚本解释器去执行。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

* URL: `http://localhost/my_proxy.pac`
* PAC 文件内容 (UTF-8 编码):
  ```javascript
  function FindProxyForURL(url, host) {
    return "PROXY myproxy:3128";
  }
  ```

**输出 1:**

* 下载成功
* 输出的 UTF-16 字符串:  JavaScript 代码的 UTF-16 编码形式。

**假设输入 2:**

* URL: `http://doesnotexist/proxy.pac`

**输出 2:**

* 下载失败
* 错误码: `ERR_NAME_NOT_RESOLVED` 或其他网络错误码。
* 输出的 UTF-16 字符串: 空字符串。

**假设输入 3:**

* URL: `data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5Rm9yVVJMKHVybCwgaG9zdCkgewogIHJldHVybiAiRElSRUNUIjsKfQo=`
* (base64 解码后是简单的 `function FindProxyForURL(url, host) { return "DIRECT"; }`)

**输出 3:**

* 下载成功 (通过 `data:` URL 直接获取)
* 输出的 UTF-16 字符串:  `function FindProxyForURL(url, host) { return "DIRECT"; }` 的 UTF-16 编码形式。

**用户或编程常见的使用错误及举例说明:**

1. **错误的 PAC 文件 URL:** 用户在系统或浏览器设置中配置了错误的 PAC 文件 URL，导致无法下载。
   * **例子:** 用户输入 `htpp://example.com/proxy.pac` (拼写错误) 而不是 `http://example.com/proxy.pac`。这将导致 `PacFileFetcherImpl` 尝试连接到一个不存在的地址，最终返回网络错误。

2. **PAC 文件服务器不可用:** PAC 文件所在的服务器宕机或网络连接失败，导致无法下载。
   * **例子:**  用户配置的 PAC 文件 URL 指向一个临时的测试服务器，该服务器在用户尝试连接时已经关闭。`PacFileFetcherImpl` 会返回 `ERR_CONNECTION_REFUSED` 或 `ERR_ADDRESS_UNREACHABLE` 等错误。

3. **PAC 文件内容过大:** PAC 文件超过了 `PacFileFetcherImpl` 设置的最大大小限制。
   * **例子:**  攻击者可能会在 PAC 文件中注入大量无意义的字符，使得文件大小超过 `kDefaultMaxResponseBytes` (1MB)。`PacFileFetcherImpl` 会检测到文件过大并返回 `ERR_FILE_TOO_BIG` 错误。

4. **PAC 文件服务器返回非 200 状态码:** PAC 文件服务器返回的 HTTP 状态码不是 200 (OK)。
   * **例子:**  服务器配置错误，当请求 PAC 文件时返回 404 (Not Found) 或 500 (Internal Server Error)。`PacFileFetcherImpl` 会检查响应状态码，如果不是 200，则会返回 `ERR_HTTP_RESPONSE_CODE_FAILURE` 错误。

5. **PAC 文件使用了不允许的重定向:** PAC 文件服务器重定向到一个不允许的协议或文件 URL。
   * **例子:** PAC 文件服务器将请求重定向到 `file:///path/to/local/proxy.pac`。`PacFileFetcherImpl` 会阻止这种重定向并返回 `ERR_UNSAFE_REDIRECT`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户配置代理设置:** 用户在操作系统或浏览器的设置中配置了使用自动代理配置 (PAC)。
   * **Windows:**  "Internet 选项" -> "连接" -> "局域网设置" -> 勾选 "使用自动配置脚本"，并填写 PAC 文件 URL。
   * **macOS:** "系统设置" -> "网络" -> 选择网络接口 -> "高级..." -> "代理" -> 选择 "自动代理配置"，并填写 PAC 文件 URL。
   * **Chrome 浏览器:** 通常会使用操作系统的代理设置。

2. **浏览器发起网络请求:** 用户在浏览器中输入一个 URL 并尝试访问，例如 `www.example.com`。

3. **代理解析启动:**  Chromium 的网络栈需要确定是否需要使用代理以及使用哪个代理。对于配置了 PAC 的情况，会启动 PAC 脚本的解析流程。

4. **PAC 文件获取:**  `PacFileFetcherImpl` 被调用，根据用户配置的 PAC 文件 URL 发起网络请求，下载 PAC 文件的内容。

5. **处理下载结果:**  `PacFileFetcherImpl` 会根据下载结果调用相应的回调函数。
   * **成功:**  PAC 文件内容被成功下载并转换为 UTF-16 格式，然后传递给 PAC 脚本解释器。
   * **失败:**  如果下载失败 (例如网络错误、文件不存在等)，会记录错误信息，并可能导致网络请求失败或使用直连 (取决于 PAC 脚本的逻辑或默认配置)。

**调试线索:**

* **网络错误:** 如果用户无法访问任何网站，并且配置了 PAC，首先需要检查 PAC 文件 URL 是否正确，PAC 文件服务器是否可达。可以使用 `ping` 或 `traceroute` 命令来测试网络连通性。
* **特定网站无法访问:** 如果只有特定网站无法访问，而其他网站可以，可能是 PAC 脚本的逻辑问题。可以检查 PAC 脚本的 `FindProxyForURL` 函数，看是否对该网站配置了错误的代理或阻止了访问。
* **下载错误:**  如果 `PacFileFetcherImpl` 返回错误 (例如 `ERR_FILE_TOO_BIG` 或 `ERR_HTTP_RESPONSE_CODE_FAILURE`)，需要检查 PAC 文件的大小和服务器的配置。
* **性能问题:** 如果访问网站速度很慢，可能是 PAC 文件下载很慢或者 PAC 脚本执行很慢。可以检查 PAC 文件的大小和复杂程度。

通过查看 Chromium 的网络日志 (可以使用 `--log-net-log` 启动 Chromium 并分析生成的日志文件)，可以详细了解 `PacFileFetcherImpl` 的运行情况，包括请求的 URL、返回的状态码、下载耗时等，从而帮助定位问题。

Prompt: 
```
这是目录为net/proxy_resolution/pac_file_fetcher_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy_resolution/pac_file_fetcher_impl.h"

#include <string_view>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/data_url.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/net_string_util.h"
#include "net/base/request_priority.h"
#include "net/cert/cert_status_flags.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request_context.h"

// TODO(eroman):
//   - Support auth-prompts (http://crbug.com/77366)

namespace net {

namespace {

// The maximum size (in bytes) allowed for a PAC script. Responses exceeding
// this will fail with ERR_FILE_TOO_BIG.
const int kDefaultMaxResponseBytes = 1048576;  // 1 megabyte

// The maximum duration (in milliseconds) allowed for fetching the PAC script.
// Responses exceeding this will fail with ERR_TIMED_OUT.
//
// This timeout applies to both scripts fetched in the course of WPAD, as well
// as explicitly configured ones.
//
// If the default timeout is too high, auto-detect can stall for a long time,
// and if it is too low then slow loading scripts may be skipped.
//
// 30 seconds is a compromise between those competing goals. This value also
// appears to match Microsoft Edge (based on testing).
constexpr base::TimeDelta kDefaultMaxDuration = base::Seconds(30);

// Returns true if |mime_type| is one of the known PAC mime type.
constexpr bool IsPacMimeType(std::string_view mime_type) {
  constexpr std::string_view kSupportedPacMimeTypes[] = {
      "application/x-ns-proxy-autoconfig",
      "application/x-javascript-config",
  };
  return base::ranges::any_of(kSupportedPacMimeTypes, [&](auto pac_mime_type) {
    return base::EqualsCaseInsensitiveASCII(pac_mime_type, mime_type);
  });
}

struct BomMapping {
  std::string_view prefix;
  const char* charset;
};

const BomMapping kBomMappings[] = {
    {"\xFE\xFF", "utf-16be"},
    {"\xFF\xFE", "utf-16le"},
    {"\xEF\xBB\xBF", "utf-8"},
};

// Converts |bytes| (which is encoded by |charset|) to UTF16, saving the resul
// to |*utf16|.
// If |charset| is empty, then we don't know what it was and guess.
void ConvertResponseToUTF16(const std::string& charset,
                            const std::string& bytes,
                            std::u16string* utf16) {
  if (charset.empty()) {
    // Guess the charset by looking at the BOM.
    std::string_view bytes_str(bytes);
    for (const auto& bom : kBomMappings) {
      if (bytes_str.starts_with(bom.prefix)) {
        return ConvertResponseToUTF16(
            bom.charset,
            // Strip the BOM in the converted response.
            bytes.substr(bom.prefix.size()), utf16);
      }
    }

    // Otherwise assume ISO-8859-1 if no charset was specified.
    return ConvertResponseToUTF16(kCharsetLatin1, bytes, utf16);
  }

  DCHECK(!charset.empty());

  // Be generous in the conversion -- if any characters lie outside of |charset|
  // (i.e. invalid), then substitute them with U+FFFD rather than failing.
  ConvertToUTF16WithSubstitutions(bytes, charset.c_str(), utf16);
}

}  // namespace

std::unique_ptr<PacFileFetcherImpl> PacFileFetcherImpl::Create(
    URLRequestContext* url_request_context) {
  return base::WrapUnique(new PacFileFetcherImpl(url_request_context));
}

PacFileFetcherImpl::~PacFileFetcherImpl() {
  // The URLRequest's destructor will cancel the outstanding request, and
  // ensure that the delegate (this) is not called again.
}

base::TimeDelta PacFileFetcherImpl::SetTimeoutConstraint(
    base::TimeDelta timeout) {
  base::TimeDelta prev = max_duration_;
  max_duration_ = timeout;
  return prev;
}

size_t PacFileFetcherImpl::SetSizeConstraint(size_t size_bytes) {
  size_t prev = max_response_bytes_;
  max_response_bytes_ = size_bytes;
  return prev;
}

void PacFileFetcherImpl::OnResponseCompleted(URLRequest* request,
                                             int net_error) {
  DCHECK_EQ(request, cur_request_.get());

  // Use |result_code_| as the request's error if we have already set it to
  // something specific.
  if (result_code_ == OK && net_error != OK)
    result_code_ = net_error;

  FetchCompleted();
}

int PacFileFetcherImpl::Fetch(
    const GURL& url,
    std::u16string* text,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag traffic_annotation) {
  // It is invalid to call Fetch() while a request is already in progress.
  DCHECK(!cur_request_.get());
  DCHECK(!callback.is_null());
  DCHECK(text);

  if (!url_request_context_)
    return ERR_CONTEXT_SHUT_DOWN;

  if (!IsUrlSchemeAllowed(url))
    return ERR_DISALLOWED_URL_SCHEME;

  // Handle base-64 encoded data-urls that contain custom PAC scripts.
  if (url.SchemeIs("data")) {
    std::string mime_type;
    std::string charset;
    std::string data;
    if (!DataURL::Parse(url, &mime_type, &charset, &data))
      return ERR_FAILED;

    ConvertResponseToUTF16(charset, data, text);
    return OK;
  }

  DCHECK(fetch_start_time_.is_null());
  fetch_start_time_ = base::TimeTicks::Now();

  // Use highest priority, so if socket pools are being used for other types of
  // requests, PAC requests are aren't blocked on them.
  cur_request_ = url_request_context_->CreateRequest(url, MAXIMUM_PRIORITY,
                                                     this, traffic_annotation);

  cur_request_->set_isolation_info(isolation_info());

  // Make sure that the PAC script is downloaded using a direct connection,
  // to avoid circular dependencies (fetching is a part of proxy resolution).
  // Also disable the use of the disk cache. The cache is disabled so that if
  // the user switches networks we don't potentially use the cached response
  // from old network when we should in fact be re-fetching on the new network.
  // If the PAC script is hosted on an HTTPS server we bypass revocation
  // checking in order to avoid a circular dependency when attempting to fetch
  // the OCSP response or CRL. We could make the revocation check go direct but
  // the proxy might be the only way to the outside world.  IGNORE_LIMITS is
  // used to avoid blocking proxy resolution on other network requests.
  cur_request_->SetLoadFlags(LOAD_BYPASS_PROXY | LOAD_DISABLE_CACHE |
                             LOAD_DISABLE_CERT_NETWORK_FETCHES |
                             LOAD_IGNORE_LIMITS);

  // Save the caller's info for notification on completion.
  callback_ = std::move(callback);
  result_text_ = text;

  bytes_read_so_far_.clear();

  // Post a task to timeout this request if it takes too long.
  cur_request_id_ = ++next_id_;

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&PacFileFetcherImpl::OnTimeout, weak_factory_.GetWeakPtr(),
                     cur_request_id_),
      max_duration_);

  // Start the request.
  cur_request_->Start();
  return ERR_IO_PENDING;
}

void PacFileFetcherImpl::Cancel() {
  // ResetCurRequestState will free the URLRequest, which will cause
  // cancellation.
  ResetCurRequestState();
}

URLRequestContext* PacFileFetcherImpl::GetRequestContext() const {
  return url_request_context_;
}

void PacFileFetcherImpl::OnShutdown() {
  url_request_context_ = nullptr;

  if (cur_request_) {
    result_code_ = ERR_CONTEXT_SHUT_DOWN;
    FetchCompleted();
  }
}

void PacFileFetcherImpl::OnReceivedRedirect(URLRequest* request,
                                            const RedirectInfo& redirect_info,
                                            bool* defer_redirect) {
  int error = OK;

  // Redirection to file:// is never OK. Ordinarily this is handled lower in the
  // stack (|FileProtocolHandler::IsSafeRedirectTarget|), but this is reachable
  // when built without file:// suppport. Return the same error for consistency.
  if (redirect_info.new_url.SchemeIsFile()) {
    error = ERR_UNSAFE_REDIRECT;
  } else if (!IsUrlSchemeAllowed(redirect_info.new_url)) {
    error = ERR_DISALLOWED_URL_SCHEME;
  }

  if (error != OK) {
    // Fail the redirect.
    request->CancelWithError(error);
    OnResponseCompleted(request, error);
  }
}

void PacFileFetcherImpl::OnAuthRequired(URLRequest* request,
                                        const AuthChallengeInfo& auth_info) {
  DCHECK_EQ(request, cur_request_.get());
  // TODO(eroman): http://crbug.com/77366
  LOG(WARNING) << "Auth required to fetch PAC script, aborting.";
  result_code_ = ERR_NOT_IMPLEMENTED;
  request->CancelAuth();
}

void PacFileFetcherImpl::OnSSLCertificateError(URLRequest* request,
                                               int net_error,
                                               const SSLInfo& ssl_info,
                                               bool fatal) {
  DCHECK_EQ(request, cur_request_.get());
  LOG(WARNING) << "SSL certificate error when fetching PAC script, aborting.";
  // Certificate errors are in same space as net errors.
  result_code_ = net_error;
  request->Cancel();
}

void PacFileFetcherImpl::OnResponseStarted(URLRequest* request, int net_error) {
  DCHECK_EQ(request, cur_request_.get());
  DCHECK_NE(ERR_IO_PENDING, net_error);

  if (net_error != OK) {
    OnResponseCompleted(request, net_error);
    return;
  }

  // Require HTTP responses to have a success status code.
  if (request->url().SchemeIsHTTPOrHTTPS()) {
    // NOTE about status codes: We are like Firefox 3 in this respect.
    // {IE 7, Safari 3, Opera 9.5} do not care about the status code.
    if (request->GetResponseCode() != 200) {
      VLOG(1) << "Fetched PAC script had (bad) status line: "
              << request->response_headers()->GetStatusLine();
      result_code_ = ERR_HTTP_RESPONSE_CODE_FAILURE;
      request->Cancel();
      return;
    }

    // NOTE about mime types: We do not enforce mime types on PAC files.
    // This is for compatibility with {IE 7, Firefox 3, Opera 9.5}. We will
    // however log mismatches to help with debugging.
    std::string mime_type;
    cur_request_->GetMimeType(&mime_type);
    if (!IsPacMimeType(mime_type)) {
      VLOG(1) << "Fetched PAC script does not have a proper mime type: "
              << mime_type;
    }
  }

  ReadBody(request);
}

void PacFileFetcherImpl::OnReadCompleted(URLRequest* request, int num_bytes) {
  DCHECK_NE(ERR_IO_PENDING, num_bytes);

  DCHECK_EQ(request, cur_request_.get());
  if (ConsumeBytesRead(request, num_bytes)) {
    // Keep reading.
    ReadBody(request);
  }
}

PacFileFetcherImpl::PacFileFetcherImpl(URLRequestContext* url_request_context)
    : url_request_context_(url_request_context),
      buf_(base::MakeRefCounted<IOBufferWithSize>(kBufSize)),
      max_response_bytes_(kDefaultMaxResponseBytes),
      max_duration_(kDefaultMaxDuration) {
  DCHECK(url_request_context);
}

bool PacFileFetcherImpl::IsUrlSchemeAllowed(const GURL& url) const {
  // Always allow http://, https://, and data:.
  if (url.SchemeIsHTTPOrHTTPS() || url.SchemeIs("data"))
    return true;

  // Disallow any other URL scheme.
  return false;
}

void PacFileFetcherImpl::ReadBody(URLRequest* request) {
  // Read as many bytes as are available synchronously.
  while (true) {
    int num_bytes = request->Read(buf_.get(), kBufSize);
    if (num_bytes == ERR_IO_PENDING)
      return;

    if (num_bytes < 0) {
      OnResponseCompleted(request, num_bytes);
      return;
    }

    if (!ConsumeBytesRead(request, num_bytes))
      return;
  }
}

bool PacFileFetcherImpl::ConsumeBytesRead(URLRequest* request, int num_bytes) {
  if (fetch_time_to_first_byte_.is_null())
    fetch_time_to_first_byte_ = base::TimeTicks::Now();

  if (num_bytes <= 0) {
    // Error while reading, or EOF.
    OnResponseCompleted(request, num_bytes);
    return false;
  }

  // Enforce maximum size bound.
  if (num_bytes + bytes_read_so_far_.size() >
      static_cast<size_t>(max_response_bytes_)) {
    result_code_ = ERR_FILE_TOO_BIG;
    request->Cancel();
    return false;
  }

  bytes_read_so_far_.append(buf_->data(), num_bytes);
  return true;
}

void PacFileFetcherImpl::FetchCompleted() {
  if (result_code_ == OK) {
    // Calculate duration of time for PAC file fetch to complete.
    DCHECK(!fetch_start_time_.is_null());
    DCHECK(!fetch_time_to_first_byte_.is_null());
    DEPRECATED_UMA_HISTOGRAM_MEDIUM_TIMES(
        "Net.ProxyScriptFetcher.FirstByteDuration",
        fetch_time_to_first_byte_ - fetch_start_time_);

    // The caller expects the response to be encoded as UTF16.
    std::string charset;
    cur_request_->GetCharset(&charset);
    ConvertResponseToUTF16(charset, bytes_read_so_far_, result_text_);
  } else {
    // On error, the caller expects empty string for bytes.
    result_text_->clear();
  }

  int result_code = result_code_;
  CompletionOnceCallback callback = std::move(callback_);

  ResetCurRequestState();

  std::move(callback).Run(result_code);
}

void PacFileFetcherImpl::ResetCurRequestState() {
  cur_request_.reset();
  cur_request_id_ = 0;
  callback_.Reset();
  result_code_ = OK;
  result_text_ = nullptr;
  fetch_start_time_ = base::TimeTicks();
  fetch_time_to_first_byte_ = base::TimeTicks();
}

void PacFileFetcherImpl::OnTimeout(int id) {
  // Timeout tasks may outlive the URLRequest they reference. Make sure it
  // is still applicable.
  if (cur_request_id_ != id)
    return;

  DCHECK(cur_request_.get());
  result_code_ = ERR_TIMED_OUT;
  FetchCompleted();
}

}  // namespace net

"""

```