Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of the `configured_proxy_resolution_service.cc` file in Chromium's network stack.

Here's a breakdown of the code's responsibilities:

1. **Handling Proxy Resolution Requests:** The core function is `ResolveProxy`, which takes a URL and attempts to determine the appropriate proxy to use (or direct connection).
2. **Managing Proxy Configuration:** It interacts with `ProxyConfigService` to get the current proxy settings (manual, auto-detect, PAC script).
3. **PAC Script Handling:**  It deals with downloading and interpreting PAC (Proxy Auto-Config) scripts, using `ProxyResolver` and `PacFileFetcher`.
4. **Error Handling and Fallback:**  It manages errors during proxy resolution and can fall back to direct connections or manual proxy settings if necessary.
5. **Retrying Failed Proxies:** It keeps track of bad proxies to avoid using them again for a certain period.
6. **Synchronization and State Management:** It uses states to manage the asynchronous process of fetching and applying proxy configurations.
7. **Network Change Notifications:** It responds to network changes (IP address, DNS) and can trigger re-evaluation of proxy settings.
8. **Testing Helpers:** It includes several `CreateFixedForTest` methods to set up specific proxy configurations for testing.

Now, I need to organize these functionalities into a concise summary, addressing the specific points raised in the prompt: Javascript interaction, logical reasoning with input/output examples, common user/programming errors, and user actions leading to this code.
这是 `net/proxy_resolution/configured_proxy_resolution_service.cc` 文件的第二部分，延续了第一部分的功能，主要负责以下方面的功能：

**核心功能归纳：**

1. **处理代理解析请求 (ResolveProxy):**
   - 接收需要解析代理的 URL、请求方法等信息。
   - 协调配置服务、PAC 解析器等组件来确定最终使用的代理服务器。
   - 维护一个挂起的请求队列 `pending_requests_`，处理异步的代理解析过程。
   - 提供同步尝试完成的优化路径 `TryToCompleteSynchronously`，对于简单情况（例如直连）可以立即返回结果。

2. **管理代理配置的生命周期:**
   - 监听来自 `ProxyConfigService` 的代理配置更新通知 (`OnProxyConfigChanged`)。
   - 根据获取到的配置（手动、自动检测、PAC 脚本）初始化代理解析器。
   - 维护当前生效的代理配置 `config_` 和最近获取的配置 `fetched_config_`。
   - 实现了代理配置的重置 (`ResetProxyConfig`) 和强制重新加载 (`ForceReloadProxyConfig`)。

3. **PAC 脚本的处理和管理:**
   - 如果配置包含 PAC 脚本，则负责下载 (`PacFileFetcher`) 和解析 PAC 脚本 (`ProxyResolver`)。
   - 使用 `PacFileDeciderPoller` 定期检查 PAC 脚本是否更新，并根据结果重新初始化代理配置。
   - 提供了处理 PAC 脚本执行错误和回退机制的功能。

4. **错误处理和回退机制:**
   - 当 PAC 脚本执行出错时，可以回退到直连模式 (前提是配置允许，且非强制 PAC)。
   - 记录永久性错误 `permanent_error_`，并在后续请求中返回。

5. **维护坏的代理列表 (Bad Proxies):**
   - 记录连接失败的代理服务器，并在一段时间内避免再次使用 (`proxy_retry_info_`)。
   - 允许 `ProxyDelegate` 干预代理选择，例如在失败后进行回退。

6. **处理网络状态变化:**
   - 监听网络 IP 地址变化 (`OnIPAddressChanged`) 和 DNS 变化 (`OnDNSChanged`)。
   - 当 IP 地址变化时，可能会延迟代理自动配置的执行，并重新加载代理配置。
   - 当 DNS 变化时，会通知 `PacFileDeciderPoller` 进行检查。

7. **提供测试辅助方法:**
   - 提供了 `CreateFixedForTest` 等静态方法，用于在测试中创建具有特定固定代理配置的 `ConfiguredProxyResolutionService` 实例。

**与 JavaScript 的关系及举例说明:**

`ConfiguredProxyResolutionService` 的核心功能是处理代理设置，而这些设置很多时候是由 JavaScript 代码控制的，尤其是在浏览器环境中。

* **PAC 脚本 (Proxy Auto-Config):**  PAC 脚本本身就是 JavaScript 代码。浏览器（或其他网络客户端）会下载并执行 PAC 脚本，以确定特定 URL 请求应该使用哪个代理服务器（或直连）。`ConfiguredProxyResolutionService` 负责下载、缓存和执行这些 PAC 脚本。
    * **举例:** 一个 PAC 脚本可能会根据请求的域名来返回不同的代理服务器：
      ```javascript
      function FindProxyForURL(url, host) {
        if (shExpMatch(host, "*.example.com")) {
          return "PROXY proxy1.example.com:8080";
        } else if (shExpMatch(host, "*.internal.net")) {
          return "DIRECT";
        } else {
          return "PROXY proxy2.example.com:8080";
        }
      }
      ```
      当浏览器请求 `www.example.com` 时，`ConfiguredProxyResolutionService` 执行这个 PAC 脚本，得到 `PROXY proxy1.example.com:8080`，然后指示网络栈使用该代理。

* **浏览器设置页面:** 用户在浏览器设置页面配置的代理设置（例如手动配置代理、自动检测代理或使用 PAC URL）最终会影响 `ConfiguredProxyResolutionService` 的行为。浏览器设置页面通常使用 JavaScript 来实现用户交互和数据处理。

**逻辑推理 (假设输入与输出):**

假设输入一个需要解析代理的 URL 和当前的代理配置：

**场景 1:  手动配置代理**

* **假设输入:**
    * `raw_url`: `http://www.example.com`
    * 当前生效的代理配置 (`config_`): 手动配置了代理服务器 `proxy.mycompany.com:80`。
* **逻辑推理:** `TryToCompleteSynchronously` 会检测到是非自动配置，直接应用手动配置的代理规则。
* **假设输出:** `result` 会被设置为使用代理 `proxy.mycompany.com:80`。

**场景 2: 使用 PAC 脚本，但脚本尚未初始化完成**

* **假设输入:**
    * `raw_url`: `http://www.example.com`
    * 当前生效的代理配置 (`config_`):  配置了 PAC URL `http://my.pac.url/proxy.pac`，但 PAC 脚本正在下载或解析中 (`current_state_` 不是 `STATE_READY`)。
* **逻辑推理:** `TryToCompleteSynchronously` 检测到 `current_state_` 不是 `STATE_READY`，返回 `ERR_IO_PENDING`。该请求会被加入 `pending_requests_` 队列，等待 PAC 脚本初始化完成后再处理。
* **假设输出:**  `ResolveProxy` 返回 `ERR_IO_PENDING`，并通过 `out_request` 提供一个可以取消的请求对象。

**场景 3: 使用 PAC 脚本，且脚本指示直连**

* **假设输入:**
    * `raw_url`: `http://internal.mycompany.com`
    * 当前生效的代理配置 (`config_`): 配置了 PAC URL，且 PAC 脚本执行后对该 URL 返回 "DIRECT"。
* **逻辑推理:**  `ResolveProxy` 会调用代理解析器（执行 PAC 脚本），解析器返回直连。
* **假设输出:** `result` 会被设置为使用直连。

**用户或编程常见的使用错误及举例说明:**

1. **PAC 脚本错误:**  如果 PAC 脚本包含语法错误或运行时错误，`ConfiguredProxyResolutionService` 会检测到并可能回退到直连或报告错误。
    * **用户现象:**  用户在配置了错误的 PAC URL 后，可能无法访问某些网站，或者所有连接都变成了直连。
    * **调试线索:**  NetLog 中会记录 PAC 脚本下载和执行的日志，包括错误信息。

2. **强制 PAC 配置错误:** 如果配置了强制 PAC，但 PAC 脚本下载或执行失败，所有网络请求将被阻止。
    * **用户现象:**  用户无法访问任何网站。
    * **编程错误:**  管理员错误地配置了强制 PAC，但提供的 PAC URL 不可用或脚本有错误。

3. **不正确的代理服务器配置:** 手动配置了无法访问的代理服务器。
    * **用户现象:**  访问网站时出现连接超时或无法连接到代理服务器的错误。
    * **调试线索:** NetLog 中会记录尝试连接代理服务器的失败信息。

4. **网络环境变化后代理配置未及时更新:** 在网络环境发生变化（例如连接了新的 Wi-Fi）后，旧的代理配置可能不再适用。
    * **用户现象:**  部分网站可以访问，部分网站无法访问。
    * **调试线索:** `ConfiguredProxyResolutionService` 会监听网络变化，并尝试重新加载代理配置。NetLog 中会记录网络变化和代理配置更新的事件。

**用户操作如何一步步地到达这里 (作为调试线索):**

1. **用户打开浏览器，尝试访问一个网页 (例如 `http://www.example.com`)。**
2. **浏览器网络栈接收到这个请求。**
3. **网络栈需要知道应该使用哪个代理服务器来发送这个请求。**
4. **网络栈会调用 `ConfiguredProxyResolutionService::ResolveProxy` 方法。**
5. **`ResolveProxy` 方法首先检查当前的代理配置状态 (`current_state_`)。**
6. **如果代理配置尚未加载，`ApplyProxyConfigIfAvailable` 会被调用，尝试从 `ProxyConfigService` 获取最新的代理配置。**
7. **`ProxyConfigService` 可能会从操作系统设置、策略或其他来源读取代理配置。**
8. **如果配置指示使用 PAC 脚本，则会下载并解析 PAC 脚本。**
9. **最终，`ResolveProxy` 会根据代理配置和 PAC 脚本的执行结果，返回应该使用的代理服务器信息。**
10. **网络栈使用返回的代理信息（或直连）来发送网页请求。**

**总结第二部分的功能:**

第二部分主要负责 **请求代理解析** 的核心逻辑，包括处理异步请求、管理 PAC 脚本的生命周期、处理错误和回退、维护坏的代理列表以及响应网络状态变化。它与第一部分共同完成了代理配置的获取、解析和应用，为 Chromium 的网络请求提供了关键的代理决策能力。

### 提示词
```
这是目录为net/proxy_resolution/configured_proxy_resolution_service.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
proxy,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString(proxy);
  ProxyConfigWithAnnotation annotated_config(proxy_config, traffic_annotation);
  return ConfiguredProxyResolutionService::CreateFixedForTest(annotated_config);
}

// static
std::unique_ptr<ConfiguredProxyResolutionService>
ConfiguredProxyResolutionService::CreateDirect() {
  // Use direct connections.
  return std::make_unique<ConfiguredProxyResolutionService>(
      std::make_unique<ProxyConfigServiceDirect>(),
      std::make_unique<ProxyResolverFactoryForNullResolver>(), nullptr,
      /*quick_check_enabled=*/true);
}

// static
std::unique_ptr<ConfiguredProxyResolutionService>
ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
    const std::string& pac_string,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  // We need the settings to contain an "automatic" setting, otherwise the
  // ProxyResolver dependency we give it will never be used.
  auto proxy_config_service = std::make_unique<ProxyConfigServiceFixed>(
      ProxyConfigWithAnnotation(ProxyConfig::CreateFromCustomPacURL(GURL(
                                    "https://my-pac-script.invalid/wpad.dat")),
                                traffic_annotation));

  return std::make_unique<ConfiguredProxyResolutionService>(
      std::move(proxy_config_service),
      std::make_unique<ProxyResolverFactoryForPacResult>(pac_string), nullptr,
      /*quick_check_enabled=*/true);
}

// static
std::unique_ptr<ConfiguredProxyResolutionService>
ConfiguredProxyResolutionService::CreateFixedFromAutoDetectedPacResultForTest(
    const std::string& pac_string,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  auto proxy_config_service =
      std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
          ProxyConfig::CreateAutoDetect(), traffic_annotation));

  return std::make_unique<ConfiguredProxyResolutionService>(
      std::move(proxy_config_service),
      std::make_unique<ProxyResolverFactoryForPacResult>(pac_string), nullptr,
      /*quick_check_enabled=*/true);
}

// static
std::unique_ptr<ConfiguredProxyResolutionService>
ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
    const std::vector<ProxyChain>& proxy_chains,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  // We need the settings to contain an "automatic" setting, otherwise the
  // ProxyResolver dependency we give it will never be used.
  auto proxy_config_service = std::make_unique<ProxyConfigServiceFixed>(
      ProxyConfigWithAnnotation(ProxyConfig::CreateFromCustomPacURL(GURL(
                                    "https://my-pac-script.invalid/wpad.dat")),
                                traffic_annotation));

  return std::make_unique<ConfiguredProxyResolutionService>(
      std::move(proxy_config_service),
      std::make_unique<ProxyResolverFactoryForProxyChains>(proxy_chains),
      nullptr,
      /*quick_check_enabled=*/true);
}

int ConfiguredProxyResolutionService::ResolveProxy(
    const GURL& raw_url,
    const std::string& method,
    const NetworkAnonymizationKey& network_anonymization_key,
    ProxyInfo* result,
    CompletionOnceCallback callback,
    std::unique_ptr<ProxyResolutionRequest>* out_request,
    const NetLogWithSource& net_log) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!callback.is_null());
  DCHECK(out_request);

  net_log.BeginEvent(NetLogEventType::PROXY_RESOLUTION_SERVICE);

  // Notify our polling-based dependencies that a resolve is taking place.
  // This way they can schedule their polls in response to network activity.
  config_service_->OnLazyPoll();
  if (script_poller_.get())
    script_poller_->OnLazyPoll();

  if (current_state_ == STATE_NONE)
    ApplyProxyConfigIfAvailable();

  // Sanitize the URL before passing it on to the proxy resolver (i.e. PAC
  // script). The goal is to remove sensitive data (like embedded user names
  // and password), and local data (i.e. reference fragment) which does not need
  // to be disclosed to the resolver.
  GURL url = SanitizeUrl(raw_url);

  // Check if the request can be completed right away. (This is the case when
  // using a direct connection for example).
  int rv = TryToCompleteSynchronously(url, result);
  if (rv != ERR_IO_PENDING) {
    rv = DidFinishResolvingProxy(url, network_anonymization_key, method, result,
                                 rv, net_log);
    return rv;
  }

  auto req = std::make_unique<ConfiguredProxyResolutionRequest>(
      this, url, method, network_anonymization_key, result, std::move(callback),
      net_log);

  if (current_state_ == STATE_READY) {
    // Start the resolve request.
    rv = req->Start();
    if (rv != ERR_IO_PENDING)
      return req->QueryDidCompleteSynchronously(rv);
  } else {
    req->net_log()->BeginEvent(
        NetLogEventType::PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC);
  }

  DCHECK_EQ(ERR_IO_PENDING, rv);
  DCHECK(!ContainsPendingRequest(req.get()));
  pending_requests_.insert(req.get());

  // Completion will be notified through |callback|, unless the caller cancels
  // the request using |out_request|.
  *out_request = std::move(req);
  return rv;  // ERR_IO_PENDING
}

int ConfiguredProxyResolutionService::TryToCompleteSynchronously(
    const GURL& url,
    ProxyInfo* result) {
  DCHECK_NE(STATE_NONE, current_state_);

  if (current_state_ != STATE_READY)
    return ERR_IO_PENDING;  // Still initializing.

  DCHECK(config_);
  // If it was impossible to fetch or parse the PAC script, we cannot complete
  // the request here and bail out.
  if (permanent_error_ != OK) {
    // Before returning the permanent error check if the URL would have been
    // implicitly bypassed.
    if (ApplyPacBypassRules(url, result))
      return OK;
    return permanent_error_;
  }

  if (config_->value().HasAutomaticSettings())
    return ERR_IO_PENDING;  // Must submit the request to the proxy resolver.

  // Use the manual proxy settings.
  config_->value().proxy_rules().Apply(url, result);
  result->set_traffic_annotation(
      MutableNetworkTrafficAnnotationTag(config_->traffic_annotation()));

  return OK;
}

ConfiguredProxyResolutionService::~ConfiguredProxyResolutionService() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  NetworkChangeNotifier::RemoveIPAddressObserver(this);
  NetworkChangeNotifier::RemoveDNSObserver(this);
  config_service_->RemoveObserver(this);

  // Cancel any inprogress requests.
  // This cancels the internal requests, but leaves the responsibility of
  // canceling the high-level Request (by deleting it) to the client.
  // Since |pending_requests_| might be modified in one of the requests'
  // callbacks (if it deletes another request), iterating through the set in a
  // for-loop will not work.
  while (!pending_requests_.empty()) {
    ConfiguredProxyResolutionRequest* req = *pending_requests_.begin();
    req->QueryComplete(ERR_ABORTED);
  }
}

void ConfiguredProxyResolutionService::SuspendAllPendingRequests() {
  for (ConfiguredProxyResolutionRequest* req : pending_requests_) {
    if (req->is_started()) {
      req->CancelResolveJob();

      req->net_log()->BeginEvent(
          NetLogEventType::PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC);
    }
  }
}

void ConfiguredProxyResolutionService::SetReady() {
  DCHECK(!init_proxy_resolver_.get());
  current_state_ = STATE_READY;

  // TODO(lilyhoughton): This is necessary because a callback invoked by
  // |StartAndCompleteCheckingForSynchronous()| might delete |this|.  A better
  // solution would be to disallow synchronous callbacks altogether.
  base::WeakPtr<ConfiguredProxyResolutionService> weak_this =
      weak_ptr_factory_.GetWeakPtr();

  auto pending_requests_copy = pending_requests_;
  for (ConfiguredProxyResolutionRequest* req : pending_requests_copy) {
    if (!ContainsPendingRequest(req))
      continue;

    if (!req->is_started()) {
      req->net_log()->EndEvent(
          NetLogEventType::PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC);

      // Note that we re-check for synchronous completion, in case we are
      // no longer using a ProxyResolver (can happen if we fell-back to manual.)
      req->StartAndCompleteCheckingForSynchronous();
      if (!weak_this)
        return;  // Synchronous callback deleted |this|
    }
  }
}

void ConfiguredProxyResolutionService::ApplyProxyConfigIfAvailable() {
  DCHECK_EQ(STATE_NONE, current_state_);

  config_service_->OnLazyPoll();

  // If we have already fetched the configuration, start applying it.
  if (fetched_config_) {
    InitializeUsingLastFetchedConfig();
    return;
  }

  // Otherwise we need to first fetch the configuration.
  current_state_ = STATE_WAITING_FOR_PROXY_CONFIG;

  // Retrieve the current proxy configuration from the ProxyConfigService.
  // If a configuration is not available yet, we will get called back later
  // by our ProxyConfigService::Observer once it changes.
  ProxyConfigWithAnnotation config;
  ProxyConfigService::ConfigAvailability availability =
      config_service_->GetLatestProxyConfig(&config);
  if (availability != ProxyConfigService::CONFIG_PENDING)
    OnProxyConfigChanged(config, availability);
}

void ConfiguredProxyResolutionService::OnInitProxyResolverComplete(int result) {
  DCHECK_EQ(STATE_WAITING_FOR_INIT_PROXY_RESOLVER, current_state_);
  DCHECK(init_proxy_resolver_.get());
  DCHECK(fetched_config_);
  DCHECK(fetched_config_->value().HasAutomaticSettings());
  config_ = init_proxy_resolver_->effective_config();

  // At this point we have decided which proxy settings to use (i.e. which PAC
  // script if any). We start up a background poller to periodically revisit
  // this decision. If the contents of the PAC script change, or if the
  // result of proxy auto-discovery changes, this poller will notice it and
  // will trigger a re-initialization using the newly discovered PAC.
  script_poller_ = std::make_unique<PacFileDeciderPoller>(
      base::BindRepeating(
          &ConfiguredProxyResolutionService::InitializeUsingDecidedConfig,
          base::Unretained(this)),
      fetched_config_.value(), resolver_factory_->expects_pac_bytes(),
      pac_file_fetcher_.get(), dhcp_pac_file_fetcher_.get(), result,
      init_proxy_resolver_->script_data(), net_log_);
  script_poller_->set_quick_check_enabled(quick_check_enabled_);

  init_proxy_resolver_.reset();

  if (result != OK) {
    if (fetched_config_->value().pac_mandatory()) {
      VLOG(1) << "Failed configuring with mandatory PAC script, blocking all "
                 "traffic.";
      config_ = fetched_config_;
      result = ERR_MANDATORY_PROXY_CONFIGURATION_FAILED;
    } else {
      VLOG(1) << "Failed configuring with PAC script, falling-back to manual "
                 "proxy servers.";
      ProxyConfig proxy_config = fetched_config_->value();
      proxy_config.ClearAutomaticSettings();
      config_ = ProxyConfigWithAnnotation(
          proxy_config, fetched_config_->traffic_annotation());
      result = OK;
    }
  }
  permanent_error_ = result;

  // Resume any requests which we had to defer until the PAC script was
  // downloaded.
  SetReady();
}

void ConfiguredProxyResolutionService::ReportSuccess(const ProxyInfo& result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  const ProxyRetryInfoMap& new_retry_info = result.proxy_retry_info();
  if (new_retry_info.empty())
    return;

  if (proxy_delegate_) {
    proxy_delegate_->OnSuccessfulRequestAfterFailures(new_retry_info);
  }

  for (const auto& iter : new_retry_info) {
    auto existing = proxy_retry_info_.find(iter.first);
    if (existing == proxy_retry_info_.end()) {
      proxy_retry_info_[iter.first] = iter.second;
      if (proxy_delegate_) {
        const ProxyChain& bad_proxy = iter.first;
        DCHECK(!bad_proxy.is_direct());
        const ProxyRetryInfo& proxy_retry_info = iter.second;
        proxy_delegate_->OnFallback(bad_proxy, proxy_retry_info.net_error);
      }
    } else if (existing->second.bad_until < iter.second.bad_until) {
      existing->second.bad_until = iter.second.bad_until;
    }
  }
  if (net_log_) {
    net_log_->AddGlobalEntry(NetLogEventType::BAD_PROXY_LIST_REPORTED, [&] {
      return NetLogBadProxyListParams(&new_retry_info);
    });
  }
}

bool ConfiguredProxyResolutionService::ContainsPendingRequest(
    ConfiguredProxyResolutionRequest* req) {
  return pending_requests_.count(req) == 1;
}

void ConfiguredProxyResolutionService::RemovePendingRequest(
    ConfiguredProxyResolutionRequest* req) {
  DCHECK(ContainsPendingRequest(req));
  pending_requests_.erase(req);
}

int ConfiguredProxyResolutionService::DidFinishResolvingProxy(
    const GURL& url,
    const NetworkAnonymizationKey& network_anonymization_key,
    const std::string& method,
    ProxyInfo* result,
    int result_code,
    const NetLogWithSource& net_log) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Log the result of the proxy resolution.
  if (result_code == OK) {
    // Allow the proxy delegate to interpose on the resolution decision,
    // possibly modifying the ProxyInfo.
    if (proxy_delegate_)
      proxy_delegate_->OnResolveProxy(url, network_anonymization_key, method,
                                      proxy_retry_info_, result);

    net_log.AddEvent(
        NetLogEventType::PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST,
        [&] { return NetLogFinishedResolvingProxyParams(result); });

    // This check is done to only log the NetLog event when necessary, it's
    // not a performance optimization.
    if (!proxy_retry_info_.empty()) {
      result->DeprioritizeBadProxyChains(proxy_retry_info_);
      net_log.AddEvent(
          NetLogEventType::PROXY_RESOLUTION_SERVICE_DEPRIORITIZED_BAD_PROXIES,
          [&] { return NetLogFinishedResolvingProxyParams(result); });
    }
  } else {
    net_log.AddEventWithNetErrorCode(
        NetLogEventType::PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST,
        result_code);

    bool reset_config = result_code == ERR_PAC_SCRIPT_TERMINATED;
    if (config_ && !config_->value().pac_mandatory()) {
      // Fall-back to direct when the proxy resolver fails. This corresponds
      // with a javascript runtime error in the PAC script.
      //
      // This implicit fall-back to direct matches Firefox 3.5 and
      // Internet Explorer 8. For more information, see:
      //
      // http://www.chromium.org/developers/design-documents/proxy-settings-fallback
      result->UseDirect();
      result_code = OK;

      // Allow the proxy delegate to interpose on the resolution decision,
      // possibly modifying the ProxyInfo.
      if (proxy_delegate_)
        proxy_delegate_->OnResolveProxy(url, network_anonymization_key, method,
                                        proxy_retry_info_, result);
    } else {
      result_code = ERR_MANDATORY_PROXY_CONFIGURATION_FAILED;
    }
    if (reset_config) {
      ResetProxyConfig(false);
      // If the ProxyResolver crashed, force it to be re-initialized for the
      // next request by resetting the proxy config. If there are other pending
      // requests, trigger the recreation immediately so those requests retry.
      if (pending_requests_.size() > 1)
        ApplyProxyConfigIfAvailable();
    }
  }

  net_log.EndEvent(NetLogEventType::PROXY_RESOLUTION_SERVICE);
  return result_code;
}

void ConfiguredProxyResolutionService::SetPacFileFetchers(
    std::unique_ptr<PacFileFetcher> pac_file_fetcher,
    std::unique_ptr<DhcpPacFileFetcher> dhcp_pac_file_fetcher) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  State previous_state = ResetProxyConfig(false);
  pac_file_fetcher_ = std::move(pac_file_fetcher);
  dhcp_pac_file_fetcher_ = std::move(dhcp_pac_file_fetcher);
  if (previous_state != STATE_NONE)
    ApplyProxyConfigIfAvailable();
}

void ConfiguredProxyResolutionService::SetProxyDelegate(
    ProxyDelegate* delegate) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!proxy_delegate_ || !delegate);
  proxy_delegate_ = delegate;
}

void ConfiguredProxyResolutionService::OnShutdown() {
  // Order here does not matter for correctness. |init_proxy_resolver_| is first
  // because shutting it down also cancels its requests using the fetcher.
  if (init_proxy_resolver_)
    init_proxy_resolver_->OnShutdown();
  if (pac_file_fetcher_)
    pac_file_fetcher_->OnShutdown();
  if (dhcp_pac_file_fetcher_)
    dhcp_pac_file_fetcher_->OnShutdown();
}

const ProxyRetryInfoMap& ConfiguredProxyResolutionService::proxy_retry_info()
    const {
  return proxy_retry_info_;
}

void ConfiguredProxyResolutionService::ClearBadProxiesCache() {
  proxy_retry_info_.clear();
}

PacFileFetcher* ConfiguredProxyResolutionService::GetPacFileFetcher() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return pac_file_fetcher_.get();
}

bool ConfiguredProxyResolutionService::GetLoadStateIfAvailable(
    LoadState* load_state) const {
  if (current_state_ == STATE_WAITING_FOR_INIT_PROXY_RESOLVER) {
    *load_state = init_proxy_resolver_->GetLoadState();
    return true;
  }

  return false;
}

ProxyResolver* ConfiguredProxyResolutionService::GetProxyResolver() const {
  return resolver_.get();
}

ConfiguredProxyResolutionService::State
ConfiguredProxyResolutionService::ResetProxyConfig(bool reset_fetched_config) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  State previous_state = current_state_;

  permanent_error_ = OK;
  proxy_retry_info_.clear();
  script_poller_.reset();
  init_proxy_resolver_.reset();
  SuspendAllPendingRequests();
  resolver_.reset();
  config_ = std::nullopt;
  if (reset_fetched_config)
    fetched_config_ = std::nullopt;
  current_state_ = STATE_NONE;

  return previous_state;
}

void ConfiguredProxyResolutionService::ForceReloadProxyConfig() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  ResetProxyConfig(false);
  ApplyProxyConfigIfAvailable();
}

base::Value::Dict ConfiguredProxyResolutionService::GetProxyNetLogValues() {
  base::Value::Dict net_info_dict;

  // Log Proxy Settings.
  {
    base::Value::Dict dict;
    if (fetched_config_)
      dict.Set("original", fetched_config_->value().ToValue());
    if (config_)
      dict.Set("effective", config_->value().ToValue());

    net_info_dict.Set(kNetInfoProxySettings, std::move(dict));
  }

  // Log Bad Proxies.
  {
    base::Value::List list;

    for (const auto& it : proxy_retry_info_) {
      const std::string& proxy_chain_uri = it.first.ToDebugString();
      const ProxyRetryInfo& retry_info = it.second;

      base::Value::Dict dict;
      dict.Set("proxy_chain_uri", proxy_chain_uri);
      dict.Set("bad_until", NetLog::TickCountToString(retry_info.bad_until));

      list.Append(base::Value(std::move(dict)));
    }

    net_info_dict.Set(kNetInfoBadProxies, std::move(list));
  }

  return net_info_dict;
}

bool ConfiguredProxyResolutionService::CastToConfiguredProxyResolutionService(
    ConfiguredProxyResolutionService** configured_proxy_resolution_service) {
  *configured_proxy_resolution_service = this;
  return true;
}

// static
const ConfiguredProxyResolutionService::PacPollPolicy*
ConfiguredProxyResolutionService::set_pac_script_poll_policy(
    const PacPollPolicy* policy) {
  return PacFileDeciderPoller::set_policy(policy);
}

// static
std::unique_ptr<ConfiguredProxyResolutionService::PacPollPolicy>
ConfiguredProxyResolutionService::CreateDefaultPacPollPolicy() {
  return std::make_unique<DefaultPollPolicy>();
}

void ConfiguredProxyResolutionService::OnProxyConfigChanged(
    const ProxyConfigWithAnnotation& config,
    ProxyConfigService::ConfigAvailability availability) {
  // Retrieve the current proxy configuration from the ProxyConfigService.
  // If a configuration is not available yet, we will get called back later
  // by our ProxyConfigService::Observer once it changes.
  ProxyConfigWithAnnotation effective_config;
  switch (availability) {
    case ProxyConfigService::CONFIG_PENDING:
      // ProxyConfigService implementors should never pass CONFIG_PENDING.
      NOTREACHED() << "Proxy config change with CONFIG_PENDING availability!";
    case ProxyConfigService::CONFIG_VALID:
      effective_config = config;
      break;
    case ProxyConfigService::CONFIG_UNSET:
      effective_config = ProxyConfigWithAnnotation::CreateDirect();
      break;
  }

  // Emit the proxy settings change to the NetLog stream.
  if (net_log_) {
    net_log_->AddGlobalEntry(NetLogEventType::PROXY_CONFIG_CHANGED, [&] {
      return NetLogProxyConfigChangedParams(&fetched_config_,
                                            &effective_config);
    });
  }

  // Set the new configuration as the most recently fetched one.
  fetched_config_ = effective_config;

  InitializeUsingLastFetchedConfig();
}

bool ConfiguredProxyResolutionService::ApplyPacBypassRules(const GURL& url,
                                                           ProxyInfo* results) {
  DCHECK(config_);

  if (ProxyBypassRules::MatchesImplicitRules(url)) {
    results->UseDirectWithBypassedProxy();
    return true;
  }

  return false;
}

void ConfiguredProxyResolutionService::InitializeUsingLastFetchedConfig() {
  ResetProxyConfig(false);

  DCHECK(fetched_config_);
  if (!fetched_config_->value().HasAutomaticSettings()) {
    config_ = fetched_config_;
    SetReady();
    return;
  }

  // Start downloading + testing the PAC scripts for this new configuration.
  current_state_ = STATE_WAITING_FOR_INIT_PROXY_RESOLVER;

  // If we changed networks recently, we should delay running proxy auto-config.
  base::TimeDelta wait_delay = stall_proxy_autoconfig_until_ - TimeTicks::Now();

  init_proxy_resolver_ = std::make_unique<InitProxyResolver>();
  init_proxy_resolver_->set_quick_check_enabled(quick_check_enabled_);
  int rv = init_proxy_resolver_->Start(
      &resolver_, resolver_factory_.get(), pac_file_fetcher_.get(),
      dhcp_pac_file_fetcher_.get(), net_log_, fetched_config_.value(),
      wait_delay,
      base::BindOnce(
          &ConfiguredProxyResolutionService::OnInitProxyResolverComplete,
          base::Unretained(this)));

  if (rv != ERR_IO_PENDING)
    OnInitProxyResolverComplete(rv);
}

void ConfiguredProxyResolutionService::InitializeUsingDecidedConfig(
    int decider_result,
    const PacFileDataWithSource& script_data,
    const ProxyConfigWithAnnotation& effective_config) {
  DCHECK(fetched_config_);
  DCHECK(fetched_config_->value().HasAutomaticSettings());

  ResetProxyConfig(false);

  current_state_ = STATE_WAITING_FOR_INIT_PROXY_RESOLVER;

  init_proxy_resolver_ = std::make_unique<InitProxyResolver>();
  int rv = init_proxy_resolver_->StartSkipDecider(
      &resolver_, resolver_factory_.get(), effective_config, decider_result,
      script_data,
      base::BindOnce(
          &ConfiguredProxyResolutionService::OnInitProxyResolverComplete,
          base::Unretained(this)));

  if (rv != ERR_IO_PENDING)
    OnInitProxyResolverComplete(rv);
}

void ConfiguredProxyResolutionService::OnIPAddressChanged() {
  // See the comment block by |kDelayAfterNetworkChangesMs| for info.
  stall_proxy_autoconfig_until_ =
      TimeTicks::Now() + stall_proxy_auto_config_delay_;

  // With a new network connection, using the proper proxy configuration for the
  // new connection may be essential for URL requests to work properly. Reset
  // the config to ensure new URL requests are blocked until the potential new
  // proxy configuration is loaded.
  State previous_state = ResetProxyConfig(false);
  if (previous_state != STATE_NONE)
    ApplyProxyConfigIfAvailable();
}

void ConfiguredProxyResolutionService::OnDNSChanged() {
  // Do not fully reset proxy config on DNS change notifications. Instead,
  // inform the poller that it would be a good time to check for changes.
  //
  // While a change to DNS servers in use could lead to different WPAD results,
  // and thus a different proxy configuration, it is extremely unlikely to ever
  // be essential for that changed proxy configuration to be picked up
  // immediately. Either URL requests on the connection are generally working
  // fine without the proxy, or requests are already broken, leaving little harm
  // in letting a couple more requests fail until Chrome picks up the new proxy.
  if (script_poller_.get())
    script_poller_->OnLazyPoll();
}

}  // namespace net
```