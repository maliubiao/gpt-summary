Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of Chromium's network stack, specifically the `dns_transaction.cc` file.

I need to:

1. **Identify the core purpose of the code:** Based on the class names and included headers, it seems to be responsible for handling DNS queries and responses, potentially using both UDP and HTTPS (DoH).
2. **List the main functionalities:** Break down the code into logical blocks and describe what each part does. This includes handling individual DNS attempts, managing UDP and TCP connections for DNS, and handling DoH requests.
3. **Check for JavaScript interaction:** Determine if this low-level network code directly interacts with JavaScript. Likely not directly, but I need to consider how the results of these DNS operations are used by higher-level components that *do* interact with JS.
4. **Analyze logic and provide examples:** If there are specific decision points or data transformations, I should provide hypothetical input and output.
5. **Identify potential user errors:** Think about common mistakes users or developers could make that might lead to this code being executed.
6. **Describe user flow:** Explain how a user action in the browser can trigger the execution of this code.
7. **Summarize the overall function:** Provide a concise summary of the file's purpose.
这是`net/dns/dns_transaction.cc`文件的第一部分，主要负责实现**DNS事务**的核心功能。它处理发起DNS查询，并通过不同的协议（UDP、TCP、HTTPS）与DNS服务器进行通信，接收并解析响应。

**主要功能归纳:**

1. **定义了 DNS 尝试 (DnsAttempt) 的抽象基类:**  `DnsAttempt` 是一个虚基类，定义了一个 DNS 查询尝试的基本接口，包括启动尝试、获取查询和响应、获取原始响应数据等。

2. **实现了基于 UDP 的 DNS 尝试 (DnsUDPAttempt):**  `DnsUDPAttempt` 类继承自 `DnsAttempt`，负责通过 UDP 协议发送 DNS 查询并接收响应。它管理 UDP socket 的连接、发送查询、接收数据，并解析响应。

3. **实现了基于 HTTP (DoH) 的 DNS 尝试 (DnsHTTPAttempt):** `DnsHTTPAttempt` 类继承自 `DnsAttempt` 和 `URLRequest::Delegate`，负责通过 HTTPS 协议发送 DNS 查询并接收响应。它使用 `URLRequest` 发起 HTTPS 请求，处理响应头和数据，并解析 DNS 响应。

4. **实现了基于 TCP 的 DNS 尝试 (DnsTCPAttempt):** `DnsTCPAttempt` 类继承自 `DnsAttempt`，负责通过 TCP 协议发送 DNS 查询并接收响应。它管理 TCP socket 的连接、发送包含长度前缀的查询、接收包含长度前缀的响应，并解析响应。

5. **定义了 DoH 探测运行器 (DnsOverHttpsProbeRunner):**  `DnsOverHttpsProbeRunner` 负责定期向 DoH 服务器发送测试查询，以检测服务器的可用性。它使用了退避策略 (backoff policy) 来控制探测的频率。

**与 JavaScript 功能的关系：**

此代码是 Chromium 网络栈的底层实现，与 JavaScript 的功能没有直接的同步调用关系。但是，它的功能是浏览器进行网络请求的基础，最终会影响到 JavaScript 代码的执行。

**举例说明:**

当 JavaScript 代码尝试访问一个域名（例如 `www.example.com`）时，浏览器需要将这个域名解析成 IP 地址。这个解析过程会触发网络栈中的 DNS 解析流程，最终可能会调用到 `dns_transaction.cc` 中的代码。

1. **JavaScript 发起请求:**  JavaScript 代码通过 `fetch()` API 或者 `XMLHttpRequest` 对象发起对 `www.example.com` 的请求。
2. **URL 解析:**  浏览器解析 URL，提取出域名 `www.example.com`。
3. **DNS 查询:**  浏览器发现需要解析该域名，就会创建一个 DNS 查询。
4. **DnsTransaction 工作:**  `DnsTransaction` 相关代码（包括本文件）会被调用，根据配置选择合适的协议（UDP、TCP 或 HTTPS）和 DNS 服务器。
5. **IP 地址返回:**  `DnsTransaction` 与 DNS 服务器通信，获取 `www.example.com` 的 IP 地址。
6. **连接建立:**  浏览器使用解析得到的 IP 地址建立与服务器的连接。
7. **JavaScript 获得响应:**  服务器响应后，JavaScript 代码才能接收到数据。

**逻辑推理与假设输入输出 (以 `DnsUDPAttempt` 为例):**

**假设输入:**

* `server_index`: 0 (假设使用配置中的第一个 DNS 服务器)
* `socket`: 一个已创建但未连接的 `DatagramClientSocket` 对象
* `server`:  IPEndPoint{8.8.8.8, 53} (Google 的公共 DNS 服务器)
* `query`: 一个包含对 `www.example.com` 进行 A 记录查询的 `DnsQuery` 对象。

**输出 (成功情况):**

* `Start()` 函数返回 `ERR_IO_PENDING` (异步操作)。
* 当收到 DNS 服务器的响应后，`callback` 被调用，传入 `OK`。
* `GetResponse()` 返回一个 `DnsResponse` 对象，其中包含 `www.example.com` 的 IP 地址。

**输出 (失败情况，例如 DNS 服务器无响应):**

* `Start()` 函数返回 `ERR_IO_PENDING`。
* 超时后，`callback` 被调用，传入相应的错误码，例如 `ERR_NAME_NOT_RESOLVED`。

**用户或编程常见的使用错误 (可能间接影响到此代码的执行):**

1. **网络配置错误:** 用户的网络配置中 DNS 服务器设置错误或者无法访问，会导致 DNS 解析失败，最终影响到此代码执行的结果。例如，用户手动设置了一个不存在或者无法访问的 DNS 服务器地址。
2. **防火墙阻止:** 防火墙阻止了浏览器与 DNS 服务器之间的 UDP 或 TCP 连接，导致 DNS 查询无法发送或接收。
3. **DoH 配置错误:** 用户配置了错误的 DoH 服务器地址或者模板，导致 DoH 请求失败。
4. **代理配置错误:** 如果用户使用了代理服务器，但代理服务器没有正确配置 DNS 解析，也会导致问题。

**用户操作是如何一步步到达这里，作为调试线索 (以访问一个网页为例):**

1. **用户在地址栏输入网址并回车:** 例如，输入 `www.example.com`。
2. **浏览器解析 URL:** 浏览器识别出需要解析主机名 `www.example.com`。
3. **HostResolver 调用:** 浏览器的 HostResolver 组件开始进行 DNS 解析。
4. **DnsSession 创建:** `DnsSession` 对象被创建或重用，管理 DNS 解析的上下文。
5. **DnsTransaction 创建:**  `DnsTransaction` 对象被创建，负责执行实际的 DNS 查询。
6. **选择尝试类型:**  `DnsTransaction` 根据配置（例如是否启用 DoH）和当前网络状态，决定尝试使用 UDP、TCP 或 HTTPS 进行查询。
7. **创建 DnsAttempt 对象:**  根据选择的协议，创建相应的 `DnsUDPAttempt`、`DnsTCPAttempt` 或 `DnsHTTPAttempt` 对象。
8. **Socket 操作:**  `DnsAttempt` 对象创建相应的 socket (UDP 或 TCP) 或 `URLRequest` 对象，并与 DNS 服务器进行通信。
9. **接收和解析响应:**  接收到 DNS 服务器的响应后，由 `DnsResponse` 对象进行解析。
10. **结果返回:**  解析后的 IP 地址被返回给 HostResolver。
11. **建立连接:**  浏览器使用解析得到的 IP 地址建立与服务器的连接。

**总结：**

`net/dns/dns_transaction.cc` 文件的第一部分定义了 Chromium 网络栈中处理 DNS 查询的核心组件，包括不同协议的 DNS 尝试实现和 DoH 探测功能。它负责与 DNS 服务器通信，获取域名对应的 IP 地址，是浏览器进行网络请求的关键步骤。虽然不直接与 JavaScript 交互，但其功能直接影响到 JavaScript 发起的网络请求能否成功完成。

### 提示词
```
这是目录为net/dns/dns_transaction.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_transaction.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/base64url.h"
#include "base/containers/circular_deque.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/safe_ref.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/byte_conversions.h"
#include "base/rand_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "base/timer/elapsed_timer.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/backoff_entry.h"
#include "net/base/completion_once_callback.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/idempotency.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_names_util.h"
#include "net/dns/dns_query.h"
#include "net/dns/dns_response.h"
#include "net/dns/dns_response_result_extractor.h"
#include "net/dns/dns_server_iterator.h"
#include "net/dns/dns_session.h"
#include "net/dns/dns_udp_tracker.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/public/dns_over_https_config.h"
#include "net/dns/public/dns_over_https_server_config.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/dns/resolve_context.h"
#include "net/http/http_request_headers.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/datagram_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/third_party/uri_template/uri_template.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "url/url_constants.h"

namespace net {

namespace {

constexpr net::NetworkTrafficAnnotationTag kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("dns_transaction", R"(
        semantics {
          sender: "DNS Transaction"
          description:
            "DNS Transaction implements a stub DNS resolver as defined in RFC "
            "1034."
          trigger:
            "Any network request that may require DNS resolution, including "
            "navigations, connecting to a proxy server, detecting proxy "
            "settings, getting proxy config, certificate checking, and more."
          data:
            "Domain name that needs resolution."
          destination: OTHER
          destination_other:
            "The connection is made to a DNS server based on user's network "
            "settings."
        }
        policy {
          cookies_allowed: NO
          setting:
            "This feature cannot be disabled. Without DNS Transactions Chrome "
            "cannot resolve host names."
          policy_exception_justification:
            "Essential for Chrome's navigation."
        })");

const char kDnsOverHttpResponseContentType[] = "application/dns-message";

// The maximum size of the DNS message for DoH, per
// https://datatracker.ietf.org/doc/html/rfc8484#section-6
const int64_t kDnsOverHttpResponseMaximumSize = 65535;

// Count labels in the fully-qualified name in DNS format.
int CountLabels(base::span<const uint8_t> name) {
  size_t count = 0;
  for (size_t i = 0; i < name.size() && name[i]; i += name[i] + 1)
    ++count;
  return count;
}

bool IsIPLiteral(const std::string& hostname) {
  IPAddress ip;
  return ip.AssignFromIPLiteral(hostname);
}

base::Value::Dict NetLogStartParams(const std::string& hostname,
                                    uint16_t qtype) {
  base::Value::Dict dict;
  dict.Set("hostname", hostname);
  dict.Set("query_type", qtype);
  return dict;
}

// ----------------------------------------------------------------------------

// A single asynchronous DNS exchange, which consists of sending out a
// DNS query, waiting for a response, and returning the response that it
// matches. Logging is done in the socket and in the outer DnsTransaction.
class DnsAttempt {
 public:
  explicit DnsAttempt(size_t server_index) : server_index_(server_index) {}

  DnsAttempt(const DnsAttempt&) = delete;
  DnsAttempt& operator=(const DnsAttempt&) = delete;

  virtual ~DnsAttempt() = default;
  // Starts the attempt. Returns ERR_IO_PENDING if cannot complete synchronously
  // and calls |callback| upon completion.
  virtual int Start(CompletionOnceCallback callback) = 0;

  // Returns the query of this attempt.
  virtual const DnsQuery* GetQuery() const = 0;

  // Returns the response or NULL if has not received a matching response from
  // the server.
  virtual const DnsResponse* GetResponse() const = 0;

  virtual base::Value GetRawResponseBufferForLog() const = 0;

  // Returns the net log bound to the source of the socket.
  virtual const NetLogWithSource& GetSocketNetLog() const = 0;

  // Returns the index of the destination server within DnsConfig::nameservers
  // (or DnsConfig::dns_over_https_servers for secure transactions).
  size_t server_index() const { return server_index_; }

  // Returns a Value representing the received response, along with a reference
  // to the NetLog source source of the UDP socket used.  The request must have
  // completed before this is called.
  base::Value::Dict NetLogResponseParams(NetLogCaptureMode capture_mode) const {
    base::Value::Dict dict;

    if (GetResponse()) {
      DCHECK(GetResponse()->IsValid());
      dict.Set("rcode", GetResponse()->rcode());
      dict.Set("answer_count", static_cast<int>(GetResponse()->answer_count()));
      dict.Set("additional_answer_count",
               static_cast<int>(GetResponse()->additional_answer_count()));
    }

    GetSocketNetLog().source().AddToEventParameters(dict);

    if (capture_mode == NetLogCaptureMode::kEverything) {
      dict.Set("response_buffer", GetRawResponseBufferForLog());
    }

    return dict;
  }

  // True if current attempt is pending (waiting for server response).
  virtual bool IsPending() const = 0;

 private:
  const size_t server_index_;
};

class DnsUDPAttempt : public DnsAttempt {
 public:
  DnsUDPAttempt(size_t server_index,
                std::unique_ptr<DatagramClientSocket> socket,
                const IPEndPoint& server,
                std::unique_ptr<DnsQuery> query,
                DnsUdpTracker* udp_tracker)
      : DnsAttempt(server_index),
        socket_(std::move(socket)),
        server_(server),
        query_(std::move(query)),
        udp_tracker_(udp_tracker) {}

  DnsUDPAttempt(const DnsUDPAttempt&) = delete;
  DnsUDPAttempt& operator=(const DnsUDPAttempt&) = delete;

  // DnsAttempt methods.

  int Start(CompletionOnceCallback callback) override {
    DCHECK_EQ(STATE_NONE, next_state_);
    callback_ = std::move(callback);
    start_time_ = base::TimeTicks::Now();
    next_state_ = STATE_CONNECT_COMPLETE;

    int rv = socket_->ConnectAsync(
        server_,
        base::BindOnce(&DnsUDPAttempt::OnIOComplete, base::Unretained(this)));
    if (rv == ERR_IO_PENDING) {
      return rv;
    }
    return DoLoop(rv);
  }

  const DnsQuery* GetQuery() const override { return query_.get(); }

  const DnsResponse* GetResponse() const override {
    const DnsResponse* resp = response_.get();
    return (resp != nullptr && resp->IsValid()) ? resp : nullptr;
  }

  base::Value GetRawResponseBufferForLog() const override {
    if (!response_)
      return base::Value();
    return NetLogBinaryValue(response_->io_buffer()->data(), read_size_);
  }

  const NetLogWithSource& GetSocketNetLog() const override {
    return socket_->NetLog();
  }

  bool IsPending() const override { return next_state_ != STATE_NONE; }

 private:
  enum State {
    STATE_CONNECT_COMPLETE,
    STATE_SEND_QUERY,
    STATE_SEND_QUERY_COMPLETE,
    STATE_READ_RESPONSE,
    STATE_READ_RESPONSE_COMPLETE,
    STATE_NONE,
  };

  int DoLoop(int result) {
    CHECK_NE(STATE_NONE, next_state_);
    int rv = result;
    do {
      State state = next_state_;
      next_state_ = STATE_NONE;
      switch (state) {
        case STATE_CONNECT_COMPLETE:
          rv = DoConnectComplete(rv);
          break;
        case STATE_SEND_QUERY:
          rv = DoSendQuery(rv);
          break;
        case STATE_SEND_QUERY_COMPLETE:
          rv = DoSendQueryComplete(rv);
          break;
        case STATE_READ_RESPONSE:
          rv = DoReadResponse();
          break;
        case STATE_READ_RESPONSE_COMPLETE:
          rv = DoReadResponseComplete(rv);
          break;
        default:
          NOTREACHED();
      }
    } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

    if (rv != ERR_IO_PENDING)
      DCHECK_EQ(STATE_NONE, next_state_);

    return rv;
  }

  int DoConnectComplete(int rv) {
    if (rv != OK) {
      DVLOG(1) << "Failed to connect socket: " << rv;
      udp_tracker_->RecordConnectionError(rv);
      return ERR_CONNECTION_REFUSED;
    }
    next_state_ = STATE_SEND_QUERY;
    IPEndPoint local_address;
    if (socket_->GetLocalAddress(&local_address) == OK)
      udp_tracker_->RecordQuery(local_address.port(), query_->id());
    return OK;
  }

  int DoSendQuery(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;
    next_state_ = STATE_SEND_QUERY_COMPLETE;
    return socket_->Write(
        query_->io_buffer(), query_->io_buffer()->size(),
        base::BindOnce(&DnsUDPAttempt::OnIOComplete, base::Unretained(this)),
        kTrafficAnnotation);
  }

  int DoSendQueryComplete(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;

    // Writing to UDP should not result in a partial datagram.
    if (rv != query_->io_buffer()->size())
      return ERR_MSG_TOO_BIG;

    next_state_ = STATE_READ_RESPONSE;
    return OK;
  }

  int DoReadResponse() {
    next_state_ = STATE_READ_RESPONSE_COMPLETE;
    response_ = std::make_unique<DnsResponse>();
    return socket_->Read(
        response_->io_buffer(), response_->io_buffer_size(),
        base::BindOnce(&DnsUDPAttempt::OnIOComplete, base::Unretained(this)));
  }

  int DoReadResponseComplete(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;
    read_size_ = rv;

    bool parse_result = response_->InitParse(rv, *query_);
    if (response_->id())
      udp_tracker_->RecordResponseId(query_->id(), response_->id().value());

    if (!parse_result)
      return ERR_DNS_MALFORMED_RESPONSE;
    if (response_->flags() & dns_protocol::kFlagTC)
      return ERR_DNS_SERVER_REQUIRES_TCP;
    if (response_->rcode() == dns_protocol::kRcodeNXDOMAIN)
      return ERR_NAME_NOT_RESOLVED;
    if (response_->rcode() != dns_protocol::kRcodeNOERROR)
      return ERR_DNS_SERVER_FAILED;

    return OK;
  }

  void OnIOComplete(int rv) {
    rv = DoLoop(rv);
    if (rv != ERR_IO_PENDING)
      std::move(callback_).Run(rv);
  }

  State next_state_ = STATE_NONE;
  base::TimeTicks start_time_;

  std::unique_ptr<DatagramClientSocket> socket_;
  IPEndPoint server_;
  std::unique_ptr<DnsQuery> query_;

  // Should be owned by the DnsSession, to which the transaction should own a
  // reference.
  const raw_ptr<DnsUdpTracker> udp_tracker_;

  std::unique_ptr<DnsResponse> response_;
  int read_size_ = 0;

  CompletionOnceCallback callback_;
};

class DnsHTTPAttempt : public DnsAttempt, public URLRequest::Delegate {
 public:
  DnsHTTPAttempt(size_t doh_server_index,
                 std::unique_ptr<DnsQuery> query,
                 const string& server_template,
                 const GURL& gurl_without_parameters,
                 bool use_post,
                 URLRequestContext* url_request_context,
                 const IsolationInfo& isolation_info,
                 RequestPriority request_priority_,
                 bool is_probe)
      : DnsAttempt(doh_server_index),
        query_(std::move(query)),
        net_log_(NetLogWithSource::Make(NetLog::Get(),
                                        NetLogSourceType::DNS_OVER_HTTPS)) {
    GURL url;
    if (use_post) {
      // Set url for a POST request
      url = gurl_without_parameters;
    } else {
      // Set url for a GET request
      std::string url_string;
      std::unordered_map<string, string> parameters;
      std::string encoded_query;
      base::Base64UrlEncode(std::string_view(query_->io_buffer()->data(),
                                             query_->io_buffer()->size()),
                            base::Base64UrlEncodePolicy::OMIT_PADDING,
                            &encoded_query);
      parameters.emplace("dns", encoded_query);
      uri_template::Expand(server_template, parameters, &url_string);
      url = GURL(url_string);
    }

    net_log_.BeginEvent(NetLogEventType::DOH_URL_REQUEST, [&] {
      if (is_probe) {
        return NetLogStartParams("(probe)", query_->qtype());
      }
      std::optional<std::string> hostname =
          dns_names_util::NetworkToDottedName(query_->qname());
      DCHECK(hostname.has_value());
      return NetLogStartParams(*hostname, query_->qtype());
    });

    HttpRequestHeaders extra_request_headers;
    extra_request_headers.SetHeader(HttpRequestHeaders::kAccept,
                                    kDnsOverHttpResponseContentType);
    // Send minimal request headers where possible.
    extra_request_headers.SetHeader(HttpRequestHeaders::kAcceptLanguage, "*");
    extra_request_headers.SetHeader(HttpRequestHeaders::kUserAgent, "Chrome");
    extra_request_headers.SetHeader(HttpRequestHeaders::kAcceptEncoding,
                                    "identity");

    DCHECK(url_request_context);
    request_ = url_request_context->CreateRequest(
        url, request_priority_, this,
        net::DefineNetworkTrafficAnnotation("dns_over_https", R"(
        semantics {
          sender: "DNS over HTTPS"
          description: "Domain name resolution over HTTPS"
          trigger: "User enters a navigates to a domain or Chrome otherwise "
                   "makes a connection to a domain whose IP address isn't cached"
          data: "The domain name that is being requested"
          destination: OTHER
          destination_other: "The user configured DNS over HTTPS server, which"
                             "may be dns.google.com"
        }
        policy {
          cookies_allowed: NO
          setting:
            "You can configure this feature via that 'dns_over_https_servers' and"
            "'dns_over_https.method' prefs. Empty lists imply this feature is"
            "disabled"
          policy_exception_justification: "Experimental feature that"
                                          "is disabled by default"
        }
      )"),
        /*is_for_websockets=*/false, net_log_.source());

    if (use_post) {
      request_->set_method("POST");
      request_->SetIdempotency(IDEMPOTENT);
      std::unique_ptr<UploadElementReader> reader =
          std::make_unique<UploadBytesElementReader>(
              query_->io_buffer()->span());
      request_->set_upload(
          ElementsUploadDataStream::CreateWithReader(std::move(reader)));
      extra_request_headers.SetHeader(HttpRequestHeaders::kContentType,
                                      kDnsOverHttpResponseContentType);
    }

    request_->SetExtraRequestHeaders(extra_request_headers);
    // Apply special policy to DNS lookups for for a DoH server hostname to
    // avoid deadlock and enable the use of preconfigured IP addresses.
    request_->SetSecureDnsPolicy(SecureDnsPolicy::kBootstrap);
    request_->SetLoadFlags(request_->load_flags() | LOAD_DISABLE_CACHE |
                           LOAD_BYPASS_PROXY);
    request_->set_allow_credentials(false);
    request_->set_isolation_info(isolation_info);
  }

  DnsHTTPAttempt(const DnsHTTPAttempt&) = delete;
  DnsHTTPAttempt& operator=(const DnsHTTPAttempt&) = delete;

  // DnsAttempt overrides.

  int Start(CompletionOnceCallback callback) override {
    callback_ = std::move(callback);
    // Start the request asynchronously to avoid reentrancy in
    // the network stack.
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&DnsHTTPAttempt::StartAsync,
                                  weak_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  }

  const DnsQuery* GetQuery() const override { return query_.get(); }
  const DnsResponse* GetResponse() const override {
    const DnsResponse* resp = response_.get();
    return (resp != nullptr && resp->IsValid()) ? resp : nullptr;
  }
  base::Value GetRawResponseBufferForLog() const override {
    if (!response_)
      return base::Value();

    return NetLogBinaryValue(response_->io_buffer()->data(),
                             response_->io_buffer_size());
  }
  const NetLogWithSource& GetSocketNetLog() const override { return net_log_; }

  // URLRequest::Delegate overrides

  void OnResponseStarted(net::URLRequest* request, int net_error) override {
    DCHECK_NE(net::ERR_IO_PENDING, net_error);
    std::string content_type;
    if (net_error != OK) {
      // Update the error code if there was an issue resolving the secure
      // server hostname.
      if (IsHostnameResolutionError(net_error))
        net_error = ERR_DNS_SECURE_RESOLVER_HOSTNAME_RESOLUTION_FAILED;
      ResponseCompleted(net_error);
      return;
    }

    if (request_->GetResponseCode() != 200 ||
        !request->response_headers()->GetMimeType(&content_type) ||
        0 != content_type.compare(kDnsOverHttpResponseContentType)) {
      ResponseCompleted(ERR_DNS_MALFORMED_RESPONSE);
      return;
    }

    buffer_ = base::MakeRefCounted<GrowableIOBuffer>();

    if (request->response_headers()->HasHeader(
            HttpRequestHeaders::kContentLength)) {
      if (request_->response_headers()->GetContentLength() >
          kDnsOverHttpResponseMaximumSize) {
        ResponseCompleted(ERR_DNS_MALFORMED_RESPONSE);
        return;
      }

      buffer_->SetCapacity(request_->response_headers()->GetContentLength() +
                           1);
    } else {
      buffer_->SetCapacity(kDnsOverHttpResponseMaximumSize + 1);
    }

    DCHECK(buffer_->data());
    DCHECK_GT(buffer_->capacity(), 0);

    int bytes_read =
        request_->Read(buffer_.get(), buffer_->RemainingCapacity());

    // If IO is pending, wait for the URLRequest to call OnReadCompleted.
    if (bytes_read == net::ERR_IO_PENDING)
      return;

    OnReadCompleted(request_.get(), bytes_read);
  }

  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override {
    // Section 5 of RFC 8484 states that scheme must be https.
    if (!redirect_info.new_url.SchemeIs(url::kHttpsScheme)) {
      request->Cancel();
    }
  }

  void OnReadCompleted(net::URLRequest* request, int bytes_read) override {
    // bytes_read can be an error.
    if (bytes_read < 0) {
      ResponseCompleted(bytes_read);
      return;
    }

    DCHECK_GE(bytes_read, 0);

    if (bytes_read > 0) {
      if (buffer_->offset() + bytes_read > kDnsOverHttpResponseMaximumSize) {
        ResponseCompleted(ERR_DNS_MALFORMED_RESPONSE);
        return;
      }

      buffer_->set_offset(buffer_->offset() + bytes_read);

      if (buffer_->RemainingCapacity() == 0) {
        buffer_->SetCapacity(buffer_->capacity() + 16384);  // Grow by 16kb.
      }

      DCHECK(buffer_->data());
      DCHECK_GT(buffer_->capacity(), 0);

      int read_result =
          request_->Read(buffer_.get(), buffer_->RemainingCapacity());

      // If IO is pending, wait for the URLRequest to call OnReadCompleted.
      if (read_result == net::ERR_IO_PENDING)
        return;

      if (read_result <= 0) {
        OnReadCompleted(request_.get(), read_result);
      } else {
        // Else, trigger OnReadCompleted asynchronously to avoid starving the IO
        // thread in case the URLRequest can provide data synchronously.
        base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
            FROM_HERE, base::BindOnce(&DnsHTTPAttempt::OnReadCompleted,
                                      weak_factory_.GetWeakPtr(),
                                      request_.get(), read_result));
      }
    } else {
      // URLRequest reported an EOF. Call ResponseCompleted.
      DCHECK_EQ(0, bytes_read);
      ResponseCompleted(net::OK);
    }
  }

  bool IsPending() const override { return !callback_.is_null(); }

 private:
  void StartAsync() {
    DCHECK(request_);
    request_->Start();
  }

  void ResponseCompleted(int net_error) {
    request_.reset();
    std::move(callback_).Run(CompleteResponse(net_error));
  }

  int CompleteResponse(int net_error) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::DOH_URL_REQUEST,
                                      net_error);
    DCHECK_NE(net::ERR_IO_PENDING, net_error);
    if (net_error != OK) {
      return net_error;
    }
    if (!buffer_.get() || 0 == buffer_->capacity())
      return ERR_DNS_MALFORMED_RESPONSE;

    size_t size = buffer_->offset();
    buffer_->set_offset(0);
    if (size == 0u)
      return ERR_DNS_MALFORMED_RESPONSE;
    response_ = std::make_unique<DnsResponse>(buffer_, size);
    if (!response_->InitParse(size, *query_))
      return ERR_DNS_MALFORMED_RESPONSE;
    if (response_->rcode() == dns_protocol::kRcodeNXDOMAIN)
      return ERR_NAME_NOT_RESOLVED;
    if (response_->rcode() != dns_protocol::kRcodeNOERROR)
      return ERR_DNS_SERVER_FAILED;
    return OK;
  }

  scoped_refptr<GrowableIOBuffer> buffer_;
  std::unique_ptr<DnsQuery> query_;
  CompletionOnceCallback callback_;
  std::unique_ptr<DnsResponse> response_;
  std::unique_ptr<URLRequest> request_;
  NetLogWithSource net_log_;

  base::WeakPtrFactory<DnsHTTPAttempt> weak_factory_{this};
};

void ConstructDnsHTTPAttempt(DnsSession* session,
                             size_t doh_server_index,
                             base::span<const uint8_t> qname,
                             uint16_t qtype,
                             const OptRecordRdata* opt_rdata,
                             std::vector<std::unique_ptr<DnsAttempt>>* attempts,
                             URLRequestContext* url_request_context,
                             const IsolationInfo& isolation_info,
                             RequestPriority request_priority,
                             bool is_probe) {
  DCHECK(url_request_context);

  std::unique_ptr<DnsQuery> query;
  if (attempts->empty()) {
    query =
        std::make_unique<DnsQuery>(/*id=*/0, qname, qtype, opt_rdata,
                                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  } else {
    query = std::make_unique<DnsQuery>(*attempts->at(0)->GetQuery());
  }

  DCHECK_LT(doh_server_index, session->config().doh_config.servers().size());
  const DnsOverHttpsServerConfig& doh_server =
      session->config().doh_config.servers()[doh_server_index];
  GURL gurl_without_parameters(
      GetURLFromTemplateWithoutParameters(doh_server.server_template()));
  attempts->push_back(std::make_unique<DnsHTTPAttempt>(
      doh_server_index, std::move(query), doh_server.server_template(),
      gurl_without_parameters, doh_server.use_post(), url_request_context,
      isolation_info, request_priority, is_probe));
}

class DnsTCPAttempt : public DnsAttempt {
 public:
  DnsTCPAttempt(size_t server_index,
                std::unique_ptr<StreamSocket> socket,
                std::unique_ptr<DnsQuery> query)
      : DnsAttempt(server_index),
        socket_(std::move(socket)),
        query_(std::move(query)),
        length_buffer_(
            base::MakeRefCounted<IOBufferWithSize>(sizeof(uint16_t))) {}

  DnsTCPAttempt(const DnsTCPAttempt&) = delete;
  DnsTCPAttempt& operator=(const DnsTCPAttempt&) = delete;

  // DnsAttempt:
  int Start(CompletionOnceCallback callback) override {
    DCHECK_EQ(STATE_NONE, next_state_);
    callback_ = std::move(callback);
    start_time_ = base::TimeTicks::Now();
    next_state_ = STATE_CONNECT_COMPLETE;
    int rv = socket_->Connect(
        base::BindOnce(&DnsTCPAttempt::OnIOComplete, base::Unretained(this)));
    if (rv == ERR_IO_PENDING) {
      return rv;
    }
    return DoLoop(rv);
  }

  const DnsQuery* GetQuery() const override { return query_.get(); }

  const DnsResponse* GetResponse() const override {
    const DnsResponse* resp = response_.get();
    return (resp != nullptr && resp->IsValid()) ? resp : nullptr;
  }

  base::Value GetRawResponseBufferForLog() const override {
    if (!response_)
      return base::Value();

    return NetLogBinaryValue(response_->io_buffer()->data(),
                             response_->io_buffer_size());
  }

  const NetLogWithSource& GetSocketNetLog() const override {
    return socket_->NetLog();
  }

  bool IsPending() const override { return next_state_ != STATE_NONE; }

 private:
  enum State {
    STATE_CONNECT_COMPLETE,
    STATE_SEND_LENGTH,
    STATE_SEND_QUERY,
    STATE_READ_LENGTH,
    STATE_READ_LENGTH_COMPLETE,
    STATE_READ_RESPONSE,
    STATE_READ_RESPONSE_COMPLETE,
    STATE_NONE,
  };

  int DoLoop(int result) {
    CHECK_NE(STATE_NONE, next_state_);
    int rv = result;
    do {
      State state = next_state_;
      next_state_ = STATE_NONE;
      switch (state) {
        case STATE_CONNECT_COMPLETE:
          rv = DoConnectComplete(rv);
          break;
        case STATE_SEND_LENGTH:
          rv = DoSendLength(rv);
          break;
        case STATE_SEND_QUERY:
          rv = DoSendQuery(rv);
          break;
        case STATE_READ_LENGTH:
          rv = DoReadLength(rv);
          break;
        case STATE_READ_LENGTH_COMPLETE:
          rv = DoReadLengthComplete(rv);
          break;
        case STATE_READ_RESPONSE:
          rv = DoReadResponse(rv);
          break;
        case STATE_READ_RESPONSE_COMPLETE:
          rv = DoReadResponseComplete(rv);
          break;
        default:
          NOTREACHED();
      }
    } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

    if (rv != ERR_IO_PENDING)
      DCHECK_EQ(STATE_NONE, next_state_);

    return rv;
  }

  int DoConnectComplete(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;

    uint16_t query_size = static_cast<uint16_t>(query_->io_buffer()->size());
    if (static_cast<int>(query_size) != query_->io_buffer()->size())
      return ERR_FAILED;
    length_buffer_->span().copy_from(base::U16ToBigEndian(query_size));
    buffer_ = base::MakeRefCounted<DrainableIOBuffer>(length_buffer_,
                                                      length_buffer_->size());
    next_state_ = STATE_SEND_LENGTH;
    return OK;
  }

  int DoSendLength(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;

    buffer_->DidConsume(rv);
    if (buffer_->BytesRemaining() > 0) {
      next_state_ = STATE_SEND_LENGTH;
      return socket_->Write(
          buffer_.get(), buffer_->BytesRemaining(),
          base::BindOnce(&DnsTCPAttempt::OnIOComplete, base::Unretained(this)),
          kTrafficAnnotation);
    }
    buffer_ = base::MakeRefCounted<DrainableIOBuffer>(
        query_->io_buffer(), query_->io_buffer()->size());
    next_state_ = STATE_SEND_QUERY;
    return OK;
  }

  int DoSendQuery(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;

    buffer_->DidConsume(rv);
    if (buffer_->BytesRemaining() > 0) {
      next_state_ = STATE_SEND_QUERY;
      return socket_->Write(
          buffer_.get(), buffer_->BytesRemaining(),
          base::BindOnce(&DnsTCPAttempt::OnIOComplete, base::Unretained(this)),
          kTrafficAnnotation);
    }
    buffer_ = base::MakeRefCounted<DrainableIOBuffer>(length_buffer_,
                                                      length_buffer_->size());
    next_state_ = STATE_READ_LENGTH;
    return OK;
  }

  int DoReadLength(int rv) {
    DCHECK_EQ(OK, rv);

    next_state_ = STATE_READ_LENGTH_COMPLETE;
    return ReadIntoBuffer();
  }

  int DoReadLengthComplete(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;
    if (rv == 0)
      return ERR_CONNECTION_CLOSED;

    buffer_->DidConsume(rv);
    if (buffer_->BytesRemaining() > 0) {
      next_state_ = STATE_READ_LENGTH;
      return OK;
    }

    response_length_ =
        base::U16FromBigEndian(length_buffer_->span().first<2u>());
    // Check if advertised response is too short. (Optimization only.)
    if (response_length_ < query_->io_buffer()->size())
      return ERR_DNS_MALFORMED_RESPONSE;
    response_ = std::make_unique<DnsResponse>(response_length_);
    buffer_ = base::MakeRefCounted<DrainableIOBuffer>(response_->io_buffer(),
                                                      response_length_);
    next_state_ = STATE_READ_RESPONSE;
    return OK;
  }

  int DoReadResponse(int rv) {
    DCHECK_EQ(OK, rv);

    next_state_ = STATE_READ_RESPONSE_COMPLETE;
    return ReadIntoBuffer();
  }

  int DoReadResponseComplete(int rv) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;
    if (rv == 0)
      return ERR_CONNECTION_CLOSED;

    buffer_->DidConsume(rv);
    if (buffer_->BytesRemaining() > 0) {
      next_state_ = STATE_READ_RESPONSE;
      return OK;
    }
    DCHECK_GT(buffer_->BytesConsumed(), 0);
    if (!response_->InitParse(buffer_->BytesConsumed(), *query_))
      return ERR_DNS_MALFORMED_RESPONSE;
    if (response_->flags() & dns_protocol::kFlagTC)
      return ERR_UNEXPECTED;
    // TODO(szym): Frankly, none of these are expected.
    if (response_->rcode() == dns_protocol::kRcodeNXDOMAIN)
      return ERR_NAME_NOT_RESOLVED;
    if (response_->rcode() != dns_protocol::kRcodeNOERROR)
      return ERR_DNS_SERVER_FAILED;

    return OK;
  }

  void OnIOComplete(int rv) {
    rv = DoLoop(rv);
    if (rv != ERR_IO_PENDING)
      std::move(callback_).Run(rv);
  }

  int ReadIntoBuffer() {
    return socket_->Read(
        buffer_.get(), buffer_->BytesRemaining(),
        base::BindOnce(&DnsTCPAttempt::OnIOComplete, base::Unretained(this)));
  }

  State next_state_ = STATE_NONE;
  base::TimeTicks start_time_;

  std::unique_ptr<StreamSocket> socket_;
  std::unique_ptr<DnsQuery> query_;
  scoped_refptr<IOBufferWithSize> length_buffer_;
  scoped_refptr<DrainableIOBuffer> buffer_;

  uint16_t response_length_ = 0;
  std::unique_ptr<DnsResponse> response_;

  CompletionOnceCallback callback_;
};

// ----------------------------------------------------------------------------

const net::BackoffEntry::Policy kProbeBackoffPolicy = {
    // Apply exponential backoff rules after the first error.
    0,
    // Begin with a 1s delay between probes.
    1000,
    // Increase the delay between consecutive probes by a factor of 1.5.
    1.5,
    // Fuzz the delay between consecutive probes between 80%-100% of the
    // calculated time.
    0.2,
    // Cap the maximum delay between consecutive probes at 1 hour.
    1000 * 60 * 60,
    // Never expire entries.
    -1,
    // Do not apply an initial delay.
    false,
};

// Probe runner that continually sends test queries (with backoff) to DoH
// servers to determine availability.
//
// Expected to be contained in request classes owned externally to HostResolver,
// so no assumptions are made regarding cancellation compared to the DnsSession
// or ResolveContext. Instead, uses WeakPtrs to gracefully clean itself up and
// stop probing after session or context destruction.
class DnsOverHttpsProbeRunner : public DnsProbeRunner {
 public:
  DnsOverHttpsProbeRunner(base::WeakPtr<DnsSession> session,
                          base::WeakPtr<R
```