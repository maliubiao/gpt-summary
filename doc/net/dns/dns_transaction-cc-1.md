Response:
The user wants to understand the functionality of the provided C++ code snippet, which is the second part of a file named `dns_transaction.cc` within the Chromium network stack. I need to analyze the code, explain its purpose, and address the specific points raised by the user: relationship with JavaScript, logical inference with input/output, common user/programming errors, and how user actions lead to this code.

**Plan:**

1. **Analyze `DnsOverHttpsProbeRunner`:**
    *   Understand its role in probing DoH servers.
    *   Identify key methods like `Start`, `ContinueProbe`, and `ProbeComplete`.
    *   Explain the backoff mechanism.
    *   Check for any direct interaction with JavaScript (unlikely).
    *   Consider how network changes or configuration updates trigger it.

2. **Analyze `DnsTransactionImpl`:**
    *   Understand its role in performing DNS lookups.
    *   Identify the core workflow: `Start`, `PrepareSearch`, `MakeAttempt`, `OnAttemptComplete`, `ProcessAttemptResult`, and `DoCallback`.
    *   Explain the handling of UDP and TCP attempts, including retries and fallbacks.
    *   Explain the integration with `ResolveContext` and `DnsSession`.
    *   Check for any direct interaction with JavaScript (unlikely, but the results will eventually be used in the browser).
    *   Think about potential user errors that might lead to specific outcomes in this code.

3. **Analyze `DnsTransactionFactoryImpl`:**
    *   Understand its role in creating instances of `DnsTransaction`.
    *   Note the creation of `DnsOverHttpsProbeRunner` here as well.
    *   Explain the handling of EDNS options.

4. **Address Specific User Questions:**
    *   **JavaScript Relation:** Explain that while this C++ code doesn't directly interact with JavaScript, its results (DNS resolutions) are crucial for network requests initiated by JavaScript. Provide an example.
    *   **Logical Inference:**  Provide a simplified scenario with assumptions about DNS configuration and server availability, illustrating the flow through `DnsTransactionImpl`.
    *   **User/Programming Errors:**  Give examples of common mistakes and how they might manifest in the context of DNS resolution (e.g., incorrect DNS settings).
    *   **User Operation to Reach Here:** Describe the steps a user takes that eventually trigger DNS lookups and involve this code.
    *   **Summarize Functionality:** Provide a concise summary of the file's purpose.
好的，这是 `net/dns/dns_transaction.cc` 文件的第二部分代码，主要包含了以下两个核心功能：

**1. `DnsOverHttpsProbeRunner` 类：负责探测 DNS-over-HTTPS (DoH) 服务器的可用性。**

*   **功能概述:**
    *   该类用于在后台主动探测配置的 DoH 服务器是否可用。
    *   它会定期向 DoH 服务器发送一个简单的 DNS 查询（查询 `kDohProbeHostname` 的 A 记录），以判断服务器是否响应正常。
    *   它使用了退避算法 (`BackoffEntry`) 来控制探测的频率，避免过于频繁的探测给服务器带来负担。
    *   探测结果会更新到 `ResolveContext` 中，用于后续 DNS 查询时选择可用的 DoH 服务器。
    *   探测可以在网络状态变化或配置变化时启动。

*   **与 JavaScript 的关系:**
    *   `DnsOverHttpsProbeRunner` 本身不直接与 JavaScript 代码交互。
    *   但是，它的探测结果会影响浏览器通过 DoH 进行 DNS 解析的行为。当 JavaScript 发起需要进行 DNS 查询的网络请求时，浏览器会根据 `ResolveContext` 中 DoH 服务器的可用性信息来决定是否使用 DoH 进行解析。
    *   **举例说明:** 假设一个网页的 JavaScript 代码尝试加载一个图片资源 `<img>`。浏览器会首先需要解析图片域名对应的 IP 地址。如果 DoH 可用，浏览器可能会选择通过 DoH 服务器进行解析，而 `DnsOverHttpsProbeRunner` 的探测结果就决定了哪些 DoH 服务器被认为是可用的。

*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**
        *   Chromium 启动，并且配置了多个 DoH 服务器。
        *   网络连接正常。
    *   **输出:**
        *   `DnsOverHttpsProbeRunner` 会为每个配置的 DoH 服务器启动一个探测序列。
        *   如果 DoH 服务器响应探测请求，`ResolveContext` 会记录该服务器为可用。
        *   如果 DoH 服务器没有响应或响应错误，`ResolveContext` 会记录该服务器为不可用，并根据退避策略延迟下一次探测。

*   **用户或编程常见的使用错误:**
    *   **用户错误:**  用户可能会错误地配置了不可用的 DoH 服务器地址。这会导致 `DnsOverHttpsProbeRunner` 持续探测失败，但不会影响浏览器的基本功能，因为浏览器通常会回退到传统的 DNS 解析。
    *   **编程错误:** 在 Chromium 内部开发中，如果错误地修改了 DoH 探测相关的配置或逻辑，可能会导致探测功能异常，例如探测过于频繁或无法正确判断服务器可用性。

*   **用户操作如何一步步到达这里 (调试线索):**
    1. **用户在浏览器设置中启用了 "使用安全 DNS" (通常是 DoH)。**
    2. **用户在安全 DNS 设置中选择了 "自定义"，并添加了一个或多个 DoH 服务器的模板或提供商。**
    3. **浏览器启动或网络状态发生变化（例如，从 Wi-Fi 切换到移动数据）。**
    4. 在 `DnsSession` 初始化时，会创建 `DnsOverHttpsProbeRunner` 实例。
    5. `DnsOverHttpsProbeRunner::Start()` 方法会被调用，开始探测配置的 DoH 服务器。
    6. `ContinueProbe()` 方法会被定期调用，向 DoH 服务器发送探测请求。
    7. `ProbeComplete()` 方法处理探测结果，并更新 `ResolveContext` 中服务器的可用性状态。

**2. `DnsTransactionImpl` 类：实现了 `DnsTransaction` 接口，负责执行 DNS 查询。**

*   **功能概述:**
    *   该类负责发起和管理一个完整的 DNS 查询过程。
    *   它会根据 `DnsSession` 提供的配置（例如，DNS 服务器地址、搜索后缀）和要查询的主机名和类型，构建 DNS 查询报文。
    *   它可以选择使用 UDP 或 TCP 协议进行查询，也可以使用 DoH 进行安全查询。
    *   它支持搜索后缀扩展、TCP 重试、超时重试等机制，以提高 DNS 解析的成功率。
    *   查询结果（包括成功或失败）会通过回调函数返回。

*   **与 JavaScript 的关系:**
    *   `DnsTransactionImpl` 是浏览器网络栈中执行 DNS 查询的关键组件，而 DNS 查询是加载网页资源的基础。
    *   当 JavaScript 代码发起网络请求（例如，通过 `fetch()` 或 `XMLHttpRequest`）时，如果需要解析域名，浏览器内部会创建 `DnsTransactionImpl` 实例来执行 DNS 查询。
    *   **举例说明:** 当 JavaScript 代码执行 `fetch('https://www.example.com/data.json')` 时，浏览器需要先解析 `www.example.com` 的 IP 地址。这个解析过程会涉及到创建 `DnsTransactionImpl` 实例，根据配置选择合适的 DNS 服务器和协议进行查询，最终将解析结果传递给网络请求模块，以便建立连接并获取数据。

*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**
        *   `hostname_`: "www.google.com"
        *   `qtype_`: `dns_protocol::kTypeA` (查询 IPv4 地址)
        *   DNS 配置包含多个传统 DNS 服务器和一个可用的 DoH 服务器。
        *   `secure_dns_mode_`: `SECURE_DNS_MODE_AUTOMATIC` (自动模式，优先尝试 DoH)
    *   **输出:**
        *   如果 DoH 服务器响应快速且成功解析了域名，`ProcessAttemptResult` 会返回 `OK`，并将解析结果通过 `DoCallback` 传递给回调函数。
        *   如果 DoH 查询失败或超时，且传统 DNS 服务器配置可用，`DnsTransactionImpl` 可能会回退到使用传统 DNS 服务器进行查询。
        *   如果所有查询尝试都失败，`ProcessAttemptResult` 会返回相应的错误码（例如，`ERR_NAME_NOT_RESOLVED` 或 `ERR_DNS_TIMED_OUT`）。

*   **用户或编程常见的使用错误:**
    *   **用户错误:**  用户的网络配置可能存在问题，例如 DNS 服务器地址错误或网络连接不稳定，导致 DNS 查询失败。
    *   **编程错误:**  在 Chromium 内部开发中，如果错误地配置了 DNS 参数、处理了查询结果或实现了重试逻辑，可能会导致 DNS 解析异常，例如解析速度慢、解析错误或死循环。

*   **用户操作如何一步步到达这里 (调试线索):**
    1. **用户在浏览器地址栏中输入一个网址 (例如，"www.example.com") 并按下回车键。**
    2. **用户点击了网页上的一个链接。**
    3. **网页上的 JavaScript 代码发起了一个网络请求 (例如，加载图片、CSS 文件或 API 数据)。**
    4. 浏览器网络栈需要解析目标域名。
    5. `DnsSession::CreateTransaction()` 方法会被调用，根据配置创建 `DnsTransactionImpl` 实例。
    6. `DnsTransactionImpl::Start()` 方法被调用，开始 DNS 查询过程。
    7. 根据配置和网络状况，可能会尝试 UDP、TCP 或 DoH 查询，并可能进行重试和回退。
    8. `OnAttemptComplete()` 方法处理每次 DNS 查询尝试的结果。
    9. `ProcessAttemptResult()` 方法根据查询结果决定下一步操作，例如继续尝试其他服务器或返回最终结果。
    10. `DoCallback()` 方法将最终的查询结果传递给上层模块。

**3. `DnsTransactionFactoryImpl` 类：实现了 `DnsTransactionFactory` 接口，负责创建 `DnsTransaction` 实例和 `DnsProbeRunner` 实例。**

*   **功能概述:**
    *   这是一个工厂类，用于创建 `DnsTransactionImpl` 和 `DnsOverHttpsProbeRunner` 的对象。
    *   它持有 `DnsSession` 的引用，并将 `DnsSession` 的配置信息传递给创建的 `DnsTransactionImpl` 对象。
    *   它还负责管理 EDNS 选项。

*   **与 JavaScript 的关系:**
    *   `DnsTransactionFactoryImpl` 本身不直接与 JavaScript 交互。
    *   但是，当浏览器需要进行 DNS 查询或启动 DoH 探测时，会使用 `DnsTransactionFactoryImpl` 来创建相应的对象。

*   **功能归纳:**

总而言之，`net/dns/dns_transaction.cc` 文件的第二部分主要负责 **执行 DNS 查询和探测 DoH 服务器的可用性**。`DnsTransactionImpl` 负责具体的 DNS 查询逻辑，包括选择协议、处理重试和回退；`DnsOverHttpsProbeRunner` 负责在后台探测 DoH 服务器的健康状态；而 `DnsTransactionFactoryImpl` 则负责创建这些类的实例。 这些功能对于浏览器加载网页和进行网络通信至关重要，尽管它们本身是用 C++ 实现的，但它们的操作是由用户的浏览行为和网页上的 JavaScript 代码间接触发的。

Prompt: 
```
这是目录为net/dns/dns_transaction.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
esolveContext> context)
      : session_(session), context_(context) {
    DCHECK(session_);
    DCHECK(!session_->config().doh_config.servers().empty());
    DCHECK(context_);

    std::optional<std::vector<uint8_t>> qname =
        dns_names_util::DottedNameToNetwork(kDohProbeHostname);
    DCHECK(qname.has_value());
    formatted_probe_qname_ = std::move(qname).value();

    for (size_t i = 0; i < session_->config().doh_config.servers().size();
         i++) {
      probe_stats_list_.push_back(nullptr);
    }
  }

  ~DnsOverHttpsProbeRunner() override = default;

  void Start(bool network_change) override {
    DCHECK(session_);
    DCHECK(context_);

    const auto& config = session_->config().doh_config;
    // Start probe sequences for any servers where it is not currently running.
    for (size_t i = 0; i < config.servers().size(); i++) {
      if (!probe_stats_list_[i]) {
        probe_stats_list_[i] = std::make_unique<ProbeStats>();
        ContinueProbe(i, probe_stats_list_[i]->weak_factory.GetWeakPtr(),
                      network_change,
                      base::TimeTicks::Now() /* sequence_start_time */);
      }
    }
  }

  base::TimeDelta GetDelayUntilNextProbeForTest(
      size_t doh_server_index) const override {
    if (doh_server_index >= probe_stats_list_.size() ||
        !probe_stats_list_[doh_server_index])
      return base::TimeDelta();

    return probe_stats_list_[doh_server_index]
        ->backoff_entry->GetTimeUntilRelease();
  }

 private:
  struct ProbeStats {
    ProbeStats()
        : backoff_entry(
              std::make_unique<net::BackoffEntry>(&kProbeBackoffPolicy)) {}

    std::unique_ptr<net::BackoffEntry> backoff_entry;
    std::vector<std::unique_ptr<DnsAttempt>> probe_attempts;
    base::WeakPtrFactory<ProbeStats> weak_factory{this};
  };

  void ContinueProbe(size_t doh_server_index,
                     base::WeakPtr<ProbeStats> probe_stats,
                     bool network_change,
                     base::TimeTicks sequence_start_time) {
    // If the DnsSession or ResolveContext has been destroyed, no reason to
    // continue probing.
    if (!session_ || !context_) {
      probe_stats_list_.clear();
      return;
    }

    // If the ProbeStats for which this probe was scheduled has been deleted,
    // don't continue to send probes.
    if (!probe_stats)
      return;

    // Cancel the probe sequence for this server if the server is already
    // available.
    if (context_->GetDohServerAvailability(doh_server_index, session_.get())) {
      probe_stats_list_[doh_server_index] = nullptr;
      return;
    }

    // Schedule a new probe assuming this one will fail. The newly scheduled
    // probe will not run if an earlier probe has already succeeded. Probes may
    // take awhile to fail, which is why we schedule the next one here rather
    // than on probe completion.
    DCHECK(probe_stats);
    DCHECK(probe_stats->backoff_entry);
    probe_stats->backoff_entry->InformOfRequest(false /* success */);
    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&DnsOverHttpsProbeRunner::ContinueProbe,
                       weak_ptr_factory_.GetWeakPtr(), doh_server_index,
                       probe_stats, network_change, sequence_start_time),
        probe_stats->backoff_entry->GetTimeUntilRelease());

    unsigned attempt_number = probe_stats->probe_attempts.size();
    ConstructDnsHTTPAttempt(
        session_.get(), doh_server_index, formatted_probe_qname_,
        dns_protocol::kTypeA, /*opt_rdata=*/nullptr,
        &probe_stats->probe_attempts, context_->url_request_context(),
        context_->isolation_info(), RequestPriority::DEFAULT_PRIORITY,
        /*is_probe=*/true);

    DnsAttempt* probe_attempt = probe_stats->probe_attempts.back().get();
    probe_attempt->Start(base::BindOnce(
        &DnsOverHttpsProbeRunner::ProbeComplete, weak_ptr_factory_.GetWeakPtr(),
        attempt_number, doh_server_index, std::move(probe_stats),
        network_change, sequence_start_time,
        base::TimeTicks::Now() /* query_start_time */));
  }

  void ProbeComplete(unsigned attempt_number,
                     size_t doh_server_index,
                     base::WeakPtr<ProbeStats> probe_stats,
                     bool network_change,
                     base::TimeTicks sequence_start_time,
                     base::TimeTicks query_start_time,
                     int rv) {
    bool success = false;
    while (probe_stats && session_ && context_) {
      if (rv != OK) {
        // The DoH probe queries don't go through the standard DnsAttempt path,
        // so the ServerStats have not been updated yet.
        context_->RecordServerFailure(doh_server_index, /*is_doh_server=*/true,
                                      rv, session_.get());
        break;
      }
      // Check that the response parses properly before considering it a
      // success.
      DCHECK_LT(attempt_number, probe_stats->probe_attempts.size());
      const DnsAttempt* attempt =
          probe_stats->probe_attempts[attempt_number].get();
      const DnsResponse* response = attempt->GetResponse();
      if (response) {
        DnsResponseResultExtractor extractor(*response);
        DnsResponseResultExtractor::ResultsOrError results =
            extractor.ExtractDnsResults(
                DnsQueryType::A,
                /*original_domain_name=*/kDohProbeHostname,
                /*request_port=*/0);

        if (results.has_value()) {
          for (const auto& result : results.value()) {
            if (result->type() == HostResolverInternalResult::Type::kData &&
                !result->AsData().endpoints().empty()) {
              context_->RecordServerSuccess(
                  doh_server_index, /*is_doh_server=*/true, session_.get());
              context_->RecordRtt(doh_server_index, /*is_doh_server=*/true,
                                  base::TimeTicks::Now() - query_start_time, rv,
                                  session_.get());
              success = true;

              // Do not delete the ProbeStats and cancel the probe sequence. It
              // will cancel itself on the next scheduled ContinueProbe() call
              // if the server is still available. This way, the backoff
              // schedule will be maintained if a server quickly becomes
              // unavailable again before that scheduled call.
              break;
            }
          }
        }
      }
      if (!success) {
        context_->RecordServerFailure(
            doh_server_index, /*is_doh_server=*/true,
            /*rv=*/ERR_DNS_SECURE_PROBE_RECORD_INVALID, session_.get());
      }
      break;
    }

    base::UmaHistogramLongTimes(
        base::JoinString({"Net.DNS.ProbeSequence",
                          network_change ? "NetworkChange" : "ConfigChange",
                          success ? "Success" : "Failure", "AttemptTime"},
                         "."),
        base::TimeTicks::Now() - sequence_start_time);
  }

  base::WeakPtr<DnsSession> session_;
  base::WeakPtr<ResolveContext> context_;
  std::vector<uint8_t> formatted_probe_qname_;

  // List of ProbeStats, one for each DoH server, indexed by the DoH server
  // config index.
  std::vector<std::unique_ptr<ProbeStats>> probe_stats_list_;

  base::WeakPtrFactory<DnsOverHttpsProbeRunner> weak_ptr_factory_{this};
};

// ----------------------------------------------------------------------------

// Implements DnsTransaction. Configuration is supplied by DnsSession.
// The suffix list is built according to the DnsConfig from the session.
// The fallback period for each DnsUDPAttempt is given by
// ResolveContext::NextClassicFallbackPeriod(). The first server to attempt on
// each query is given by ResolveContext::NextFirstServerIndex, and the order is
// round-robin afterwards. Each server is attempted DnsConfig::attempts times.
class DnsTransactionImpl final : public DnsTransaction {
 public:
  DnsTransactionImpl(DnsSession* session,
                     std::string hostname,
                     uint16_t qtype,
                     const NetLogWithSource& parent_net_log,
                     const OptRecordRdata* opt_rdata,
                     bool secure,
                     SecureDnsMode secure_dns_mode,
                     ResolveContext* resolve_context,
                     bool fast_timeout)
      : session_(session),
        hostname_(std::move(hostname)),
        qtype_(qtype),
        opt_rdata_(opt_rdata),
        secure_(secure),
        secure_dns_mode_(secure_dns_mode),
        fast_timeout_(fast_timeout),
        net_log_(NetLogWithSource::Make(NetLog::Get(),
                                        NetLogSourceType::DNS_TRANSACTION)),
        resolve_context_(resolve_context->AsSafeRef()) {
    DCHECK(session_.get());
    DCHECK(!hostname_.empty());
    DCHECK(!IsIPLiteral(hostname_));
    parent_net_log.AddEventReferencingSource(NetLogEventType::DNS_TRANSACTION,
                                             net_log_.source());
  }

  DnsTransactionImpl(const DnsTransactionImpl&) = delete;
  DnsTransactionImpl& operator=(const DnsTransactionImpl&) = delete;

  ~DnsTransactionImpl() override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    if (!callback_.is_null()) {
      net_log_.EndEventWithNetErrorCode(NetLogEventType::DNS_TRANSACTION,
                                        ERR_ABORTED);
    }  // otherwise logged in DoCallback or Start
  }

  const std::string& GetHostname() const override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    return hostname_;
  }

  uint16_t GetType() const override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    return qtype_;
  }

  void Start(ResponseCallback callback) override {
    DCHECK(!callback.is_null());
    DCHECK(callback_.is_null());
    DCHECK(attempts_.empty());

    callback_ = std::move(callback);

    net_log_.BeginEvent(NetLogEventType::DNS_TRANSACTION,
                        [&] { return NetLogStartParams(hostname_, qtype_); });
    time_from_start_ = std::make_unique<base::ElapsedTimer>();
    AttemptResult result(PrepareSearch(), nullptr);
    if (result.rv == OK) {
      qnames_initial_size_ = qnames_.size();
      result = ProcessAttemptResult(StartQuery());
    }

    // Must always return result asynchronously, to avoid reentrancy.
    if (result.rv != ERR_IO_PENDING) {
      // Clear all other non-completed attempts. They are no longer needed and
      // they may interfere with this posted result.
      ClearAttempts(result.attempt);
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&DnsTransactionImpl::DoCallback,
                                    weak_ptr_factory_.GetWeakPtr(), result));
    }
  }

  void SetRequestPriority(RequestPriority priority) override {
    request_priority_ = priority;
  }

 private:
  // Wrapper for the result of a DnsUDPAttempt.
  struct AttemptResult {
    AttemptResult() = default;
    AttemptResult(int rv, const DnsAttempt* attempt)
        : rv(rv), attempt(attempt) {}

    int rv;
    raw_ptr<const DnsAttempt, AcrossTasksDanglingUntriaged> attempt;
  };

  // Used in UMA (DNS.AttemptType). Do not renumber or remove values.
  enum class DnsAttemptType {
    kUdp = 0,
    kTcpLowEntropy = 1,
    kTcpTruncationRetry = 2,
    kHttp = 3,
    kMaxValue = kHttp,
  };

  // Prepares |qnames_| according to the DnsConfig.
  int PrepareSearch() {
    const DnsConfig& config = session_->config();

    std::optional<std::vector<uint8_t>> labeled_qname =
        dns_names_util::DottedNameToNetwork(
            hostname_,
            /*require_valid_internet_hostname=*/true);
    if (!labeled_qname.has_value())
      return ERR_INVALID_ARGUMENT;

    if (hostname_.back() == '.') {
      // It's a fully-qualified name, no suffix search.
      qnames_.push_back(std::move(labeled_qname).value());
      return OK;
    }

    int ndots = CountLabels(labeled_qname.value()) - 1;

    if (ndots > 0 && !config.append_to_multi_label_name) {
      qnames_.push_back(std::move(labeled_qname).value());
      return OK;
    }

    // Set true when `labeled_qname` is put on the list.
    bool had_qname = false;

    if (ndots >= config.ndots) {
      qnames_.push_back(labeled_qname.value());
      had_qname = true;
    }

    for (const auto& suffix : config.search) {
      std::optional<std::vector<uint8_t>> qname =
          dns_names_util::DottedNameToNetwork(
              hostname_ + "." + suffix,
              /*require_valid_internet_hostname=*/true);
      // Ignore invalid (too long) combinations.
      if (!qname.has_value())
        continue;
      if (qname.value().size() == labeled_qname.value().size()) {
        if (had_qname)
          continue;
        had_qname = true;
      }
      qnames_.push_back(std::move(qname).value());
    }

    if (ndots > 0 && !had_qname)
      qnames_.push_back(std::move(labeled_qname).value());

    return qnames_.empty() ? ERR_DNS_SEARCH_EMPTY : OK;
  }

  void DoCallback(AttemptResult result) {
    DCHECK_NE(ERR_IO_PENDING, result.rv);

    // TODO(mgersh): consider changing back to a DCHECK once
    // https://crbug.com/779589 is fixed.
    if (callback_.is_null())
      return;

    const DnsResponse* response =
        result.attempt ? result.attempt->GetResponse() : nullptr;
    CHECK(result.rv != OK || response != nullptr);

    timer_.Stop();

    net_log_.EndEventWithNetErrorCode(NetLogEventType::DNS_TRANSACTION,
                                      result.rv);

    std::move(callback_).Run(result.rv, response);
  }

  void RecordAttemptUma(DnsAttemptType attempt_type) {
    UMA_HISTOGRAM_ENUMERATION("Net.DNS.DnsTransaction.AttemptType",
                              attempt_type);
  }

  AttemptResult MakeAttempt() {
    DCHECK(MoreAttemptsAllowed());

    DnsConfig config = session_->config();
    if (secure_) {
      DCHECK(!config.doh_config.servers().empty());
      RecordAttemptUma(DnsAttemptType::kHttp);
      return MakeHTTPAttempt();
    }

    DCHECK_GT(config.nameservers.size(), 0u);
    return MakeClassicDnsAttempt();
  }

  AttemptResult MakeClassicDnsAttempt() {
    uint16_t id = session_->NextQueryId();
    std::unique_ptr<DnsQuery> query;
    if (attempts_.empty()) {
      query =
          std::make_unique<DnsQuery>(id, qnames_.front(), qtype_, opt_rdata_);
    } else {
      query = attempts_[0]->GetQuery()->CloneWithNewId(id);
    }
    DCHECK(dns_server_iterator_->AttemptAvailable());
    size_t server_index = dns_server_iterator_->GetNextAttemptIndex();

    size_t attempt_number = attempts_.size();
    AttemptResult result;
    if (session_->udp_tracker()->low_entropy()) {
      result = MakeTcpAttempt(server_index, std::move(query));
      RecordAttemptUma(DnsAttemptType::kTcpLowEntropy);
    } else {
      result = MakeUdpAttempt(server_index, std::move(query));
      RecordAttemptUma(DnsAttemptType::kUdp);
    }

    if (result.rv == ERR_IO_PENDING) {
      base::TimeDelta fallback_period =
          resolve_context_->NextClassicFallbackPeriod(
              server_index, attempt_number, session_.get());
      timer_.Start(FROM_HERE, fallback_period, this,
                   &DnsTransactionImpl::OnFallbackPeriodExpired);
    }

    return result;
  }

  // Makes another attempt at the current name, |qnames_.front()|, using the
  // next nameserver.
  AttemptResult MakeUdpAttempt(size_t server_index,
                               std::unique_ptr<DnsQuery> query) {
    DCHECK(!secure_);
    DCHECK(!session_->udp_tracker()->low_entropy());

    const DnsConfig& config = session_->config();
    DCHECK_LT(server_index, config.nameservers.size());
    size_t attempt_number = attempts_.size();

    std::unique_ptr<DatagramClientSocket> socket =
        resolve_context_->url_request_context()
            ->GetNetworkSessionContext()
            ->client_socket_factory->CreateDatagramClientSocket(
                DatagramSocket::RANDOM_BIND, net_log_.net_log(),
                net_log_.source());

    attempts_.push_back(std::make_unique<DnsUDPAttempt>(
        server_index, std::move(socket), config.nameservers[server_index],
        std::move(query), session_->udp_tracker()));
    ++attempts_count_;

    DnsAttempt* attempt = attempts_.back().get();
    net_log_.AddEventReferencingSource(NetLogEventType::DNS_TRANSACTION_ATTEMPT,
                                       attempt->GetSocketNetLog().source());

    int rv = attempt->Start(base::BindOnce(
        &DnsTransactionImpl::OnAttemptComplete, base::Unretained(this),
        attempt_number, true /* record_rtt */, base::TimeTicks::Now()));
    return AttemptResult(rv, attempt);
  }

  AttemptResult MakeHTTPAttempt() {
    DCHECK(secure_);

    size_t doh_server_index = dns_server_iterator_->GetNextAttemptIndex();

    unsigned attempt_number = attempts_.size();
    ConstructDnsHTTPAttempt(session_.get(), doh_server_index, qnames_.front(),
                            qtype_, opt_rdata_, &attempts_,
                            resolve_context_->url_request_context(),
                            resolve_context_->isolation_info(),
                            request_priority_, /*is_probe=*/false);
    ++attempts_count_;
    DnsAttempt* attempt = attempts_.back().get();
    // Associate this attempt with the DoH request in NetLog.
    net_log_.AddEventReferencingSource(
        NetLogEventType::DNS_TRANSACTION_HTTPS_ATTEMPT,
        attempt->GetSocketNetLog().source());
    attempt->GetSocketNetLog().AddEventReferencingSource(
        NetLogEventType::DNS_TRANSACTION_HTTPS_ATTEMPT, net_log_.source());
    int rv = attempt->Start(base::BindOnce(
        &DnsTransactionImpl::OnAttemptComplete, base::Unretained(this),
        attempt_number, true /* record_rtt */, base::TimeTicks::Now()));
    if (rv == ERR_IO_PENDING) {
      base::TimeDelta fallback_period = resolve_context_->NextDohFallbackPeriod(
          doh_server_index, session_.get());
      timer_.Start(FROM_HERE, fallback_period, this,
                   &DnsTransactionImpl::OnFallbackPeriodExpired);
    }
    return AttemptResult(rv, attempts_.back().get());
  }

  AttemptResult RetryUdpAttemptAsTcp(const DnsAttempt* previous_attempt) {
    DCHECK(previous_attempt);
    DCHECK(!had_tcp_retry_);

    // Only allow a single TCP retry per query.
    had_tcp_retry_ = true;

    size_t server_index = previous_attempt->server_index();
    // Use a new query ID instead of reusing the same one from the UDP attempt.
    // RFC5452, section 9.2 requires an unpredictable ID for all outgoing
    // queries, with no distinction made between queries made via TCP or UDP.
    std::unique_ptr<DnsQuery> query =
        previous_attempt->GetQuery()->CloneWithNewId(session_->NextQueryId());

    // Cancel all attempts that have not received a response, as they will
    // likely similarly require TCP retry.
    ClearAttempts(nullptr);

    AttemptResult result = MakeTcpAttempt(server_index, std::move(query));
    RecordAttemptUma(DnsAttemptType::kTcpTruncationRetry);

    if (result.rv == ERR_IO_PENDING) {
      // On TCP upgrade, use 2x the upgraded fallback period.
      base::TimeDelta fallback_period = timer_.GetCurrentDelay() * 2;
      timer_.Start(FROM_HERE, fallback_period, this,
                   &DnsTransactionImpl::OnFallbackPeriodExpired);
    }

    return result;
  }

  AttemptResult MakeTcpAttempt(size_t server_index,
                               std::unique_ptr<DnsQuery> query) {
    DCHECK(!secure_);
    const DnsConfig& config = session_->config();
    DCHECK_LT(server_index, config.nameservers.size());

    // TODO(crbug.com/40146880): Pass a non-null NetworkQualityEstimator.
    NetworkQualityEstimator* network_quality_estimator = nullptr;

    std::unique_ptr<StreamSocket> socket =
        resolve_context_->url_request_context()
            ->GetNetworkSessionContext()
            ->client_socket_factory->CreateTransportClientSocket(
                AddressList(config.nameservers[server_index]), nullptr,
                network_quality_estimator, net_log_.net_log(),
                net_log_.source());

    unsigned attempt_number = attempts_.size();

    attempts_.push_back(std::make_unique<DnsTCPAttempt>(
        server_index, std::move(socket), std::move(query)));
    ++attempts_count_;

    DnsAttempt* attempt = attempts_.back().get();
    net_log_.AddEventReferencingSource(
        NetLogEventType::DNS_TRANSACTION_TCP_ATTEMPT,
        attempt->GetSocketNetLog().source());

    int rv = attempt->Start(base::BindOnce(
        &DnsTransactionImpl::OnAttemptComplete, base::Unretained(this),
        attempt_number, false /* record_rtt */, base::TimeTicks::Now()));
    return AttemptResult(rv, attempt);
  }

  // Begins query for the current name. Makes the first attempt.
  AttemptResult StartQuery() {
    std::optional<std::string> dotted_qname =
        dns_names_util::NetworkToDottedName(qnames_.front());
    net_log_.BeginEventWithStringParams(
        NetLogEventType::DNS_TRANSACTION_QUERY, "qname",
        dotted_qname.value_or("???MALFORMED_NAME???"));

    attempts_.clear();
    had_tcp_retry_ = false;
    if (secure_) {
      dns_server_iterator_ = resolve_context_->GetDohIterator(
          session_->config(), secure_dns_mode_, session_.get());
    } else {
      dns_server_iterator_ = resolve_context_->GetClassicDnsIterator(
          session_->config(), session_.get());
    }
    DCHECK(dns_server_iterator_);
    // Check for available server before starting as DoH servers might be
    // unavailable.
    if (!dns_server_iterator_->AttemptAvailable())
      return AttemptResult(ERR_BLOCKED_BY_CLIENT, nullptr);

    return MakeAttempt();
  }

  void OnAttemptComplete(unsigned attempt_number,
                         bool record_rtt,
                         base::TimeTicks start,
                         int rv) {
    DCHECK_LT(attempt_number, attempts_.size());
    const DnsAttempt* attempt = attempts_[attempt_number].get();
    if (record_rtt && attempt->GetResponse()) {
      resolve_context_->RecordRtt(
          attempt->server_index(), secure_ /* is_doh_server */,
          base::TimeTicks::Now() - start, rv, session_.get());
    }
    if (callback_.is_null())
      return;
    AttemptResult result = ProcessAttemptResult(AttemptResult(rv, attempt));
    if (result.rv != ERR_IO_PENDING)
      DoCallback(result);
  }

  void LogResponse(const DnsAttempt* attempt) {
    if (attempt) {
      net_log_.AddEvent(NetLogEventType::DNS_TRANSACTION_RESPONSE,
                        [&](NetLogCaptureMode capture_mode) {
                          return attempt->NetLogResponseParams(capture_mode);
                        });
    }
  }

  bool MoreAttemptsAllowed() const {
    if (had_tcp_retry_)
      return false;

    return dns_server_iterator_->AttemptAvailable();
  }

  // Resolves the result of a DnsAttempt until a terminal result is reached
  // or it will complete asynchronously (ERR_IO_PENDING).
  AttemptResult ProcessAttemptResult(AttemptResult result) {
    while (result.rv != ERR_IO_PENDING) {
      LogResponse(result.attempt);

      switch (result.rv) {
        case OK:
          resolve_context_->RecordServerSuccess(result.attempt->server_index(),
                                                secure_ /* is_doh_server */,
                                                session_.get());
          net_log_.EndEventWithNetErrorCode(
              NetLogEventType::DNS_TRANSACTION_QUERY, result.rv);
          DCHECK(result.attempt);
          DCHECK(result.attempt->GetResponse());
          return result;
        case ERR_NAME_NOT_RESOLVED:
          resolve_context_->RecordServerSuccess(result.attempt->server_index(),
                                                secure_ /* is_doh_server */,
                                                session_.get());
          net_log_.EndEventWithNetErrorCode(
              NetLogEventType::DNS_TRANSACTION_QUERY, result.rv);
          // Try next suffix. Check that qnames_ isn't already empty first,
          // which can happen when there are two attempts running at once.
          // TODO(mgersh): remove this workaround for https://crbug.com/774846
          // when https://crbug.com/779589 is fixed.
          if (!qnames_.empty())
            qnames_.pop_front();
          if (qnames_.empty()) {
            return result;
          } else {
            result = StartQuery();
          }
          break;
        case ERR_DNS_TIMED_OUT:
          timer_.Stop();

          if (result.attempt) {
            DCHECK(result.attempt == attempts_.back().get());
            resolve_context_->RecordServerFailure(
                result.attempt->server_index(), secure_ /* is_doh_server */,
                result.rv, session_.get());
          }
          if (MoreAttemptsAllowed()) {
            result = MakeAttempt();
            break;
          }

          if (!fast_timeout_ && AnyAttemptPending()) {
            StartTimeoutTimer();
            return AttemptResult(ERR_IO_PENDING, nullptr);
          }

          return result;
        case ERR_DNS_SERVER_REQUIRES_TCP:
          result = RetryUdpAttemptAsTcp(result.attempt);
          break;
        case ERR_BLOCKED_BY_CLIENT:
          net_log_.EndEventWithNetErrorCode(
              NetLogEventType::DNS_TRANSACTION_QUERY, result.rv);
          return result;
        default:
          // Server failure.
          DCHECK(result.attempt);

          // If attempt is not the most recent attempt, means this error is for
          // a previous attempt that already passed its fallback period and
          // continued attempting in parallel with new attempts (see the
          // ERR_DNS_TIMED_OUT case above). As the failure was already recorded
          // at fallback time and is no longer being waited on, ignore this
          // failure.
          if (result.attempt == attempts_.back().get()) {
            timer_.Stop();
            resolve_context_->RecordServerFailure(
                result.attempt->server_index(), secure_ /* is_doh_server */,
                result.rv, session_.get());

            if (MoreAttemptsAllowed()) {
              result = MakeAttempt();
              break;
            }

            if (fast_timeout_) {
              return result;
            }

            // No more attempts can be made, but there may be other attempts
            // still pending, so start the timeout timer.
            StartTimeoutTimer();
          }

          // If any attempts are still pending, continue to wait for them.
          if (AnyAttemptPending()) {
            DCHECK(timer_.IsRunning());
            return AttemptResult(ERR_IO_PENDING, nullptr);
          }

          return result;
      }
    }
    return result;
  }

  // Clears and cancels all pending attempts. If |leave_attempt| is not
  // null, that attempt is not cleared even if pending.
  void ClearAttempts(const DnsAttempt* leave_attempt) {
    for (auto it = attempts_.begin(); it != attempts_.end();) {
      if ((*it)->IsPending() && it->get() != leave_attempt) {
        it = attempts_.erase(it);
      } else {
        ++it;
      }
    }
  }

  bool AnyAttemptPending() {
    return base::ranges::any_of(attempts_,
                                [](std::unique_ptr<DnsAttempt>& attempt) {
                                  return attempt->IsPending();
                                });
  }

  void OnFallbackPeriodExpired() {
    if (callback_.is_null())
      return;
    DCHECK(!attempts_.empty());
    AttemptResult result = ProcessAttemptResult(
        AttemptResult(ERR_DNS_TIMED_OUT, attempts_.back().get()));
    if (result.rv != ERR_IO_PENDING)
      DoCallback(result);
  }

  void StartTimeoutTimer() {
    DCHECK(!fast_timeout_);
    DCHECK(!timer_.IsRunning());
    DCHECK(!callback_.is_null());

    base::TimeDelta timeout;
    if (secure_) {
      timeout = resolve_context_->SecureTransactionTimeout(secure_dns_mode_,
                                                           session_.get());
    } else {
      timeout = resolve_context_->ClassicTransactionTimeout(session_.get());
    }
    timeout -= time_from_start_->Elapsed();

    timer_.Start(FROM_HERE, timeout, this, &DnsTransactionImpl::OnTimeout);
  }

  void OnTimeout() {
    if (callback_.is_null())
      return;
    DoCallback(AttemptResult(ERR_DNS_TIMED_OUT, nullptr));
  }

  scoped_refptr<DnsSession> session_;
  std::string hostname_;
  uint16_t qtype_;
  raw_ptr<const OptRecordRdata, DanglingUntriaged> opt_rdata_;
  const bool secure_;
  const SecureDnsMode secure_dns_mode_;
  // Cleared in DoCallback.
  ResponseCallback callback_;

  // When true, transaction should time out immediately on expiration of the
  // last attempt fallback period rather than waiting the overall transaction
  // timeout period.
  const bool fast_timeout_;

  NetLogWithSource net_log_;

  // Search list of fully-qualified DNS names to query next (in DNS format).
  base::circular_deque<std::vector<uint8_t>> qnames_;
  size_t qnames_initial_size_ = 0;

  // List of attempts for the current name.
  std::vector<std::unique_ptr<DnsAttempt>> attempts_;
  // Count of attempts, not reset when |attempts_| vector is cleared.
  int attempts_count_ = 0;

  // Records when an attempt was retried via TCP due to a truncation error.
  bool had_tcp_retry_ = false;

  // Iterator to get the index of the DNS server for each search query.
  std::unique_ptr<DnsServerIterator> dns_server_iterator_;

  base::OneShotTimer timer_;
  std::unique_ptr<base::ElapsedTimer> time_from_start_;

  base::SafeRef<ResolveContext> resolve_context_;
  RequestPriority request_priority_ = DEFAULT_PRIORITY;

  THREAD_CHECKER(thread_checker_);

  base::WeakPtrFactory<DnsTransactionImpl> weak_ptr_factory_{this};
};

// ----------------------------------------------------------------------------

// Implementation of DnsTransactionFactory that returns instances of
// DnsTransactionImpl.
class DnsTransactionFactoryImpl : public DnsTransactionFactory {
 public:
  explicit DnsTransactionFactoryImpl(DnsSession* session) {
    session_ = session;
  }

  std::unique_ptr<DnsTransaction> CreateTransaction(
      std::string hostname,
      uint16_t qtype,
      const NetLogWithSource& net_log,
      bool secure,
      SecureDnsMode secure_dns_mode,
      ResolveContext* resolve_context,
      bool fast_timeout) override {
    return std::make_unique<DnsTransactionImpl>(
        session_.get(), std::move(hostname), qtype, net_log, opt_rdata_.get(),
        secure, secure_dns_mode, resolve_context, fast_timeout);
  }

  std::unique_ptr<DnsProbeRunner> CreateDohProbeRunner(
      ResolveContext* resolve_context) override {
    // Start a timer that will emit metrics after a timeout to indicate whether
    // DoH auto-upgrade was successful for this session.
    resolve_context->StartDohAutoupgradeSuccessTimer(session_.get());

    return std::make_unique<DnsOverHttpsProbeRunner>(
        session_->GetWeakPtr(), resolve_context->GetWeakPtr());
  }

  void AddEDNSOption(std::unique_ptr<OptRecordRdata::Opt> opt) override {
    DCHECK(opt);
    if (opt_rdata_ == nullptr)
      opt_rdata_ = std::make_unique<OptRecordRdata>();

    opt_rdata_->AddOpt(std::move(opt));
  }

  SecureDnsMode GetSecureDnsModeForTest() override {
    return session_->config().secure_dns_mode;
  }

 private:
  scoped_refptr<DnsSession> session_;
  std::unique_ptr<OptRecordRdata> opt_rdata_;
};

}  // namespace

DnsTransactionFactory::DnsTransactionFactory() = default;
DnsTransactionFactory::~DnsTransactionFactory() = default;

// static
std::unique_ptr<DnsTransactionFactory> DnsTransactionFactory::CreateFactory(
    DnsSession* session) {
  return std::make_unique<DnsTransactionFactoryImpl>(session);
}

}  // namespace net

"""


```