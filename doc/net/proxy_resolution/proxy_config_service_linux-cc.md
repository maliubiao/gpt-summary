Response:
The user wants me to analyze the provided C++ code snippet from Chromium's network stack, specifically the `proxy_config_service_linux.cc` file.

Here's a breakdown of the tasks:

1. **Functionality Listing:** I need to identify and list the primary functions of this code.
2. **JavaScript Relation:** Determine if and how this C++ code interacts with JavaScript. Provide examples if there's a connection.
3. **Logical Inference with Examples:** If the code involves logical reasoning, I need to create hypothetical inputs and their corresponding outputs.
4. **Common Usage Errors:** Identify potential mistakes users or programmers might make when interacting with or extending this code, and illustrate them with examples.
5. **User Path to Code:** Describe the steps a user might take in a browser that eventually leads to the execution of this code, serving as debugging clues.
6. **Functionality Summary:**  Provide a concise summary of the code's purpose based on the provided first part of the file.

**Mental Sandbox:**

* **Functionality Identification:**  The code deals with retrieving proxy configurations on Linux. Keywords like "ProxyConfigServiceLinux", "Delegate", "gsettings", "kioslaverc", "environment variables" suggest it reads proxy settings from various Linux-specific sources. It also seems to handle notifications for changes in these settings.
* **JavaScript Interaction:**  Direct interaction with JavaScript is unlikely in this low-level networking code. It's more about the browser's internal workings. However, the *effects* of this code are definitely visible to JavaScript. For example, if this code determines that a proxy is needed, network requests initiated by JavaScript will be routed through that proxy.
* **Logical Inference:** The code parses configuration files and environment variables. I can create examples of environment variables or configuration file entries and show how the code would interpret them.
* **Usage Errors:**  Common errors might involve incorrect syntax in configuration files or misunderstanding how environment variables are prioritized.
* **User Path:**  A user changing proxy settings in the browser's settings UI, or a system administrator setting environment variables, could trigger this code.
* **Functionality Summary (Part 1):** This part of the code seems to focus on the infrastructure for retrieving proxy configurations, including delegates for different setting retrieval methods (environment variables, gsettings, KDE config).

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes.
2. JavaScript relation and examples: Yes (indirect relationship).
3. Logical inference with examples: Yes.
4. Common usage errors with examples: Yes.
5. User path to code: Yes.
6. Summarize functionality (Part 1): Yes.

Confidence Score: 5/5

**Strategizing complete. I will now proceed with generating the response.**

这是 `net/proxy_resolution/proxy_config_service_linux.cc` 文件（第一部分）的主要功能归纳：

**主要功能：**

1. **代理配置服务基础架构:**  定义了 `ProxyConfigServiceLinux` 类及其委托 (`Delegate`) 接口，为从不同的 Linux 系统配置源获取代理设置提供了一个抽象层。
2. **从环境变量获取代理配置:** `Delegate` 类提供了从环境变量（如 `http_proxy`, `https_proxy`, `no_proxy` 等）中读取代理配置的功能。它可以解析这些环境变量，提取代理服务器地址、端口和绕过规则，并将其转换为 Chromium 网络栈可以理解的 `ProxyConfig` 对象。
3. **支持不同的配置源:**  代码中为不同的 Linux 配置源定义了不同的 `SettingGetter` 实现：
    * **`SettingGetterImplGSettings`:** 使用 `gsettings` (GNOME 桌面环境的配置系统) 获取代理配置。
    * **`SettingGetterImplKDE`:**  通过解析 KDE 的配置文件 (`kioslaverc`) 来获取代理配置，并模拟 `gsettings` 的行为。
4. **配置变化的通知机制:**  `SettingGetter` 的实现（`SettingGetterImplGSettings` 和 `SettingGetterImplKDE`）都实现了监听配置变化的功能（通过 `g_signal_connect` 和 `inotify`）。当检测到配置变化时，它们会通知 `Delegate`，进而触发代理配置的更新。
5. **代理绕过规则处理:**  代码包含了处理代理绕过规则的逻辑，包括从环境变量 (`no_proxy`) 和配置文件中读取规则，并将其转换为 `ProxyBypassRules` 对象。它还包含 `RewriteRulesForSuffixMatching` 函数，用于将基于主机名的规则转换为后缀匹配规则。
6. **代理地址的格式化和校验:**  `FixupProxyHostScheme` 函数用于修正代理服务器地址的格式，例如添加协议前缀（`http://`, `socks5://` 等）。
7. **线程管理:**  代码使用了 `base::SingleThreadTaskRunner` 和 `base::ThreadPool::CreateSequencedTaskRunner` 来在不同的线程上执行任务，例如在 UI 线程上监听 `gsettings` 的变化，在文件线程上监听 `inotify` 的事件。

**与 Javascript 的关系：**

这个 C++ 文件本身不包含任何 JavaScript 代码，也不直接执行 JavaScript。但是，它的功能直接影响到通过 Chromium 内嵌的 JavaScript 引擎（V8）执行的 JavaScript 代码的网络请求行为。

**举例说明：**

假设一个网页的 JavaScript 代码尝试发起一个 HTTP 请求：

```javascript
fetch('https://www.example.com');
```

1. **用户操作:** 用户可能在 Linux 系统中设置了 `http_proxy` 环境变量，例如：
   ```bash
   export http_proxy="http://proxy.mycompany.com:8080"
   ```
2. **Chromium 启动:** 当 Chromium 启动时，`ProxyConfigServiceLinux` 会被创建并负责获取系统的代理配置。
3. **读取环境变量:** `Delegate::GetConfigFromEnv()` 函数会读取到 `http_proxy` 环境变量的值。
4. **解析配置:**  `FixupProxyHostScheme` 和相关的解析逻辑会将 `http://proxy.mycompany.com:8080` 解析为代理服务器地址。
5. **配置生效:**  解析后的代理配置会被应用到 Chromium 的网络栈中。
6. **JavaScript 发起请求:** 当 JavaScript 代码执行 `fetch('https://www.example.com')` 时，Chromium 的网络栈会根据当前的代理配置，将该请求路由到 `proxy.mycompany.com:8080`。

**逻辑推理示例：**

**假设输入 (环境变量):**

* `http_proxy="http://web-proxy:3128"`
* `no_proxy="localhost,*.internal.net"`

**输出 (推断的 `ProxyConfig`):**

* `proxy_rules().type = ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME`
* `proxy_rules().proxies_for_http.SetSingleProxyChain(ProxyChain::FromSchemeHostPort("http", "web-proxy", 3128))`
* `proxy_rules().bypass_rules` 将包含两条规则，用于绕过 `localhost` 和所有以 `.internal.net` 结尾的主机。

**用户或编程常见的使用错误：**

1. **环境变量设置错误:** 用户可能错误地设置了环境变量的值，例如忘记指定端口号：
   ```bash
   export http_proxy="http://proxy.mycompany.com"  # 缺少端口
   ```
   这将导致 `ProxyUriToProxyChain` 解析失败，Chromium 可能会忽略这个代理设置或者报错。
2. **`no_proxy` 语法错误:** 用户可能在 `no_proxy` 环境变量中使用了错误的语法，例如使用了通配符在中间：
   ```bash
   export no_proxy="localhost,192.*.168.0/24" # 星号只能在开头
   ```
   这可能导致绕过规则无法正确解析，导致不应该走代理的请求走了代理，或者应该走代理的请求被绕过。
3. **程序未正确处理配置源优先级:**  如果程序员在扩展这个代码时，没有正确处理不同配置源的优先级（例如，环境变量通常会覆盖配置文件），可能会导致配置读取错误。

**用户操作到达此处的调试线索：**

1. **用户报告网络连接问题:** 用户可能报告无法访问某些网站，或者访问速度异常缓慢，这可能与代理配置有关。
2. **开发者工具检查:** 开发者可能会在 Chromium 的开发者工具中查看网络请求，发现请求被路由到了错误的代理服务器，或者本不该使用代理的请求使用了代理。
3. **检查系统代理设置:**  开发者可能会首先检查操作系统的代理设置（例如，GNOME 的网络设置，KDE 的系统设置）。
4. **检查环境变量:** 开发者会检查相关的环境变量是否被设置，以及其值是否正确。
5. **查看 Chromium 日志:**  通过启动带有特定命令行标志的 Chromium，可以查看详细的网络日志，包括代理配置的读取和应用过程。相关的日志信息可能会出现在 `net::ProxyConfigServiceLinux` 或 `net::ProxyResolutionService` 相关的日志中。
6. **断点调试:** 开发者可以在 `ProxyConfigServiceLinux::Delegate::GetConfigFromEnv()` 或 `SettingGetter` 的实现中设置断点，逐步跟踪代码的执行，查看代理配置是如何被读取和解析的。

总结来说，`net/proxy_resolution/proxy_config_service_linux.cc` (第一部分) 负责构建 Linux 系统上获取和管理代理配置的基础框架，并实现了从环境变量中读取代理配置的功能。它为后续从其他配置源（如 gsettings 和 KDE 配置文件）获取配置奠定了基础。 虽然它本身不涉及 JavaScript，但它的功能直接影响着 JavaScript 发起的网络请求的行为。

### 提示词
```
这是目录为net/proxy_resolution/proxy_config_service_linux.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/proxy_resolution/proxy_config_service_linux.h"

#include <errno.h>
#include <limits.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <utility>

#include "base/files/file_descriptor_watcher_posix.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/nix/xdg_util.h"
#include "base/observer_list.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/threading/thread_restrictions.h"
#include "base/timer/timer.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"

#if defined(USE_GIO)
#include <gio/gio.h>
#endif  // defined(USE_GIO)

namespace net {

class ScopedAllowBlockingForSettingGetter : public base::ScopedAllowBlocking {};

namespace {

// This turns all rules with a hostname into wildcard matches, which will
// match not just the indicated hostname but also any hostname that ends with
// it.
void RewriteRulesForSuffixMatching(ProxyBypassRules* out) {
  // Prepend a wildcard (*) to any hostname based rules, provided it isn't an IP
  // address.
  for (size_t i = 0; i < out->rules().size(); ++i) {
    if (!out->rules()[i]->IsHostnamePatternRule())
      continue;

    const SchemeHostPortMatcherHostnamePatternRule* prev_rule =
        static_cast<const SchemeHostPortMatcherHostnamePatternRule*>(
            out->rules()[i].get());
    out->ReplaceRule(i, prev_rule->GenerateSuffixMatchingRule());
  }
}

// Given a proxy hostname from a setting, returns that hostname with
// an appropriate proxy server scheme prefix.
// scheme indicates the desired proxy scheme: usually http, with
// socks 4 or 5 as special cases.
// TODO(arindam): Remove URI string manipulation by using MapUrlSchemeToProxy.
std::string FixupProxyHostScheme(ProxyServer::Scheme scheme,
                                 std::string host) {
  if (scheme == ProxyServer::SCHEME_SOCKS5 &&
      base::StartsWith(host, "socks4://",
                       base::CompareCase::INSENSITIVE_ASCII)) {
    // We default to socks 5, but if the user specifically set it to
    // socks4://, then use that.
    scheme = ProxyServer::SCHEME_SOCKS4;
  }
  // Strip the scheme if any.
  std::string::size_type colon = host.find("://");
  if (colon != std::string::npos)
    host = host.substr(colon + 3);
  // If a username and perhaps password are specified, give a warning.
  std::string::size_type at_sign = host.find("@");
  // Should this be supported?
  if (at_sign != std::string::npos) {
    // ProxyConfig does not support authentication parameters, but Chrome
    // will prompt for the password later. Disregard the
    // authentication parameters and continue with this hostname.
    LOG(WARNING) << "Proxy authentication parameters ignored, see bug 16709";
    host = host.substr(at_sign + 1);
  }
  // If this is a socks proxy, prepend a scheme so as to tell
  // ProxyServer. This also allows ProxyServer to choose the right
  // default port.
  if (scheme == ProxyServer::SCHEME_SOCKS4)
    host = "socks4://" + host;
  else if (scheme == ProxyServer::SCHEME_SOCKS5)
    host = "socks5://" + host;
  // If there is a trailing slash, remove it so |host| will parse correctly
  // even if it includes a port number (since the slash is not numeric).
  if (!host.empty() && host.back() == '/')
    host.resize(host.length() - 1);
  return host;
}

ProxyConfigWithAnnotation GetConfigOrDirect(
    const std::optional<ProxyConfigWithAnnotation>& optional_config) {
  if (optional_config)
    return optional_config.value();

  ProxyConfigWithAnnotation config = ProxyConfigWithAnnotation::CreateDirect();
  return config;
}

}  // namespace

ProxyConfigServiceLinux::Delegate::~Delegate() = default;

bool ProxyConfigServiceLinux::Delegate::GetProxyFromEnvVarForScheme(
    std::string_view variable,
    ProxyServer::Scheme scheme,
    ProxyChain* result_chain) {
  std::string env_value;
  if (!env_var_getter_->GetVar(variable, &env_value))
    return false;

  if (env_value.empty())
    return false;

  env_value = FixupProxyHostScheme(scheme, std::move(env_value));
  ProxyChain proxy_chain =
      ProxyUriToProxyChain(env_value, ProxyServer::SCHEME_HTTP);
  if (proxy_chain.IsValid() &&
      (proxy_chain.is_direct() || proxy_chain.is_single_proxy())) {
    *result_chain = proxy_chain;
    return true;
  }
  LOG(ERROR) << "Failed to parse environment variable " << variable;
  return false;
}

bool ProxyConfigServiceLinux::Delegate::GetProxyFromEnvVar(
    std::string_view variable,
    ProxyChain* result_chain) {
  return GetProxyFromEnvVarForScheme(variable, ProxyServer::SCHEME_HTTP,
                                     result_chain);
}

std::optional<ProxyConfigWithAnnotation>
ProxyConfigServiceLinux::Delegate::GetConfigFromEnv() {
  ProxyConfig config;

  // Check for automatic configuration first, in
  // "auto_proxy". Possibly only the "environment_proxy" firefox
  // extension has ever used this, but it still sounds like a good
  // idea.
  std::string auto_proxy;
  if (env_var_getter_->GetVar("auto_proxy", &auto_proxy)) {
    if (auto_proxy.empty()) {
      // Defined and empty => autodetect
      config.set_auto_detect(true);
    } else {
      // specified autoconfig URL
      config.set_pac_url(GURL(auto_proxy));
    }
    return ProxyConfigWithAnnotation(
        config, NetworkTrafficAnnotationTag(traffic_annotation_));
  }
  // "all_proxy" is a shortcut to avoid defining {http,https,ftp}_proxy.
  ProxyChain proxy_chain;
  if (GetProxyFromEnvVar("all_proxy", &proxy_chain)) {
    config.proxy_rules().type = ProxyConfig::ProxyRules::Type::PROXY_LIST;
    config.proxy_rules().single_proxies.SetSingleProxyChain(proxy_chain);
  } else {
    bool have_http = GetProxyFromEnvVar("http_proxy", &proxy_chain);
    if (have_http)
      config.proxy_rules().proxies_for_http.SetSingleProxyChain(proxy_chain);
    // It would be tempting to let http_proxy apply for all protocols
    // if https_proxy and ftp_proxy are not defined. Googling turns up
    // several documents that mention only http_proxy. But then the
    // user really might not want to proxy https. And it doesn't seem
    // like other apps do this. So we will refrain.
    bool have_https = GetProxyFromEnvVar("https_proxy", &proxy_chain);
    if (have_https)
      config.proxy_rules().proxies_for_https.SetSingleProxyChain(proxy_chain);
    bool have_ftp = GetProxyFromEnvVar("ftp_proxy", &proxy_chain);
    if (have_ftp)
      config.proxy_rules().proxies_for_ftp.SetSingleProxyChain(proxy_chain);
    if (have_http || have_https || have_ftp) {
      // mustn't change type unless some rules are actually set.
      config.proxy_rules().type =
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME;
    }
  }
  if (config.proxy_rules().empty()) {
    // If the above were not defined, try for socks.
    // For environment variables, we default to version 5, per the gnome
    // documentation: http://library.gnome.org/devel/gnet/stable/gnet-socks.html
    ProxyServer::Scheme scheme = ProxyServer::SCHEME_SOCKS5;
    std::string env_version;
    if (env_var_getter_->GetVar("SOCKS_VERSION", &env_version)
        && env_version == "4")
      scheme = ProxyServer::SCHEME_SOCKS4;
    if (GetProxyFromEnvVarForScheme("SOCKS_SERVER", scheme, &proxy_chain)) {
      config.proxy_rules().type = ProxyConfig::ProxyRules::Type::PROXY_LIST;
      config.proxy_rules().single_proxies.SetSingleProxyChain(proxy_chain);
    }
  }
  // Look for the proxy bypass list.
  std::string no_proxy;
  env_var_getter_->GetVar("no_proxy", &no_proxy);
  if (config.proxy_rules().empty()) {
    // Having only "no_proxy" set, presumably to "*", makes it
    // explicit that env vars do specify a configuration: having no
    // rules specified only means the user explicitly asks for direct
    // connections.
    return !no_proxy.empty()
               ? ProxyConfigWithAnnotation(
                     config, NetworkTrafficAnnotationTag(traffic_annotation_))
               : std::optional<ProxyConfigWithAnnotation>();
  }
  // Note that this uses "suffix" matching. So a bypass of "google.com"
  // is understood to mean a bypass of "*google.com".
  config.proxy_rules().bypass_rules.ParseFromString(no_proxy);
  RewriteRulesForSuffixMatching(&config.proxy_rules().bypass_rules);

  return ProxyConfigWithAnnotation(
      config, NetworkTrafficAnnotationTag(traffic_annotation_));
}

namespace {

const int kDebounceTimeoutMilliseconds = 250;

#if defined(USE_GIO)
const char kProxyGSettingsSchema[] = "org.gnome.system.proxy";

// This setting getter uses gsettings, as used in most GNOME 3 desktops.
class SettingGetterImplGSettings
    : public ProxyConfigServiceLinux::SettingGetter {
 public:
  SettingGetterImplGSettings()
      : debounce_timer_(std::make_unique<base::OneShotTimer>()) {}

  SettingGetterImplGSettings(const SettingGetterImplGSettings&) = delete;
  SettingGetterImplGSettings& operator=(const SettingGetterImplGSettings&) =
      delete;

  ~SettingGetterImplGSettings() override {
    // client_ should have been released before now, from
    // Delegate::OnDestroy(), while running on the UI thread. However
    // on exiting the process, it may happen that
    // Delegate::OnDestroy() task is left pending on the glib loop
    // after the loop was quit, and pending tasks may then be deleted
    // without being run.
    if (client_) {
      // gsettings client was not cleaned up.
      if (task_runner_->RunsTasksInCurrentSequence()) {
        // We are on the UI thread so we can clean it safely.
        VLOG(1) << "~SettingGetterImplGSettings: releasing gsettings client";
        ShutDown();
      } else {
        LOG(WARNING) << "~SettingGetterImplGSettings: leaking gsettings client";
        client_.ExtractAsDangling();
      }
    }
    DCHECK(!client_);
  }

  // CheckVersion() must be called *before* Init()!
  bool CheckVersion(base::Environment* env);

  bool Init(const scoped_refptr<base::SingleThreadTaskRunner>& glib_task_runner)
      override {
    DCHECK(glib_task_runner->RunsTasksInCurrentSequence());
    DCHECK(!client_);
    DCHECK(!task_runner_.get());

    if (!g_settings_schema_source_lookup(g_settings_schema_source_get_default(),
                                         kProxyGSettingsSchema, TRUE) ||
        !(client_ = g_settings_new(kProxyGSettingsSchema))) {
      // It's not clear whether/when this can return NULL.
      LOG(ERROR) << "Unable to create a gsettings client";
      return false;
    }
    task_runner_ = glib_task_runner;
    // We assume these all work if the above call worked.
    http_client_ = g_settings_get_child(client_, "http");
    https_client_ = g_settings_get_child(client_, "https");
    ftp_client_ = g_settings_get_child(client_, "ftp");
    socks_client_ = g_settings_get_child(client_, "socks");
    DCHECK(http_client_ && https_client_ && ftp_client_ && socks_client_);
    return true;
  }

  void ShutDown() override {
    if (client_) {
      DCHECK(task_runner_->RunsTasksInCurrentSequence());
      // This also disables gsettings notifications.
      g_object_unref(socks_client_.ExtractAsDangling());
      g_object_unref(ftp_client_.ExtractAsDangling());
      g_object_unref(https_client_.ExtractAsDangling());
      g_object_unref(http_client_.ExtractAsDangling());
      g_object_unref(client_.ExtractAsDangling());
      // We only need to null client_ because it's the only one that we check.
      client_ = nullptr;
      task_runner_ = nullptr;
    }
    debounce_timer_.reset();
  }

  bool SetUpNotifications(
      ProxyConfigServiceLinux::Delegate* delegate) override {
    DCHECK(client_);
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    notify_delegate_ = delegate;
    // We could watch for the change-event signal instead of changed, but
    // since we have to watch more than one object, we'd still have to
    // debounce change notifications. This is conceptually simpler.
    g_signal_connect(G_OBJECT(client_.get()), "changed",
                     G_CALLBACK(OnGSettingsChangeNotification), this);
    g_signal_connect(G_OBJECT(http_client_.get()), "changed",
                     G_CALLBACK(OnGSettingsChangeNotification), this);
    g_signal_connect(G_OBJECT(https_client_.get()), "changed",
                     G_CALLBACK(OnGSettingsChangeNotification), this);
    g_signal_connect(G_OBJECT(ftp_client_.get()), "changed",
                     G_CALLBACK(OnGSettingsChangeNotification), this);
    g_signal_connect(G_OBJECT(socks_client_.get()), "changed",
                     G_CALLBACK(OnGSettingsChangeNotification), this);
    // Simulate a change to avoid possibly losing updates before this point.
    OnChangeNotification();
    return true;
  }

  const scoped_refptr<base::SequencedTaskRunner>& GetNotificationTaskRunner()
      override {
    return task_runner_;
  }

  bool GetString(StringSetting key, std::string* result) override {
    DCHECK(client_);
    switch (key) {
      case PROXY_MODE:
        return GetStringByPath(client_, "mode", result);
      case PROXY_AUTOCONF_URL:
        return GetStringByPath(client_, "autoconfig-url", result);
      case PROXY_HTTP_HOST:
        return GetStringByPath(http_client_, "host", result);
      case PROXY_HTTPS_HOST:
        return GetStringByPath(https_client_, "host", result);
      case PROXY_FTP_HOST:
        return GetStringByPath(ftp_client_, "host", result);
      case PROXY_SOCKS_HOST:
        return GetStringByPath(socks_client_, "host", result);
    }
    return false;  // Placate compiler.
  }
  bool GetBool(BoolSetting key, bool* result) override {
    DCHECK(client_);
    switch (key) {
      case PROXY_USE_HTTP_PROXY:
        // Although there is an "enabled" boolean in http_client_, it is not set
        // to true by the proxy config utility. We ignore it and return false.
        return false;
      case PROXY_USE_SAME_PROXY:
        // Similarly, although there is a "use-same-proxy" boolean in client_,
        // it is never set to false by the proxy config utility. We ignore it.
        return false;
      case PROXY_USE_AUTHENTICATION:
        // There is also no way to set this in the proxy config utility, but it
        // doesn't hurt us to get the actual setting (unlike the two above).
        return GetBoolByPath(http_client_, "use-authentication", result);
    }
    return false;  // Placate compiler.
  }
  bool GetInt(IntSetting key, int* result) override {
    DCHECK(client_);
    switch (key) {
      case PROXY_HTTP_PORT:
        return GetIntByPath(http_client_, "port", result);
      case PROXY_HTTPS_PORT:
        return GetIntByPath(https_client_, "port", result);
      case PROXY_FTP_PORT:
        return GetIntByPath(ftp_client_, "port", result);
      case PROXY_SOCKS_PORT:
        return GetIntByPath(socks_client_, "port", result);
    }
    return false;  // Placate compiler.
  }
  bool GetStringList(StringListSetting key,
                     std::vector<std::string>* result) override {
    DCHECK(client_);
    switch (key) {
      case PROXY_IGNORE_HOSTS:
        return GetStringListByPath(client_, "ignore-hosts", result);
    }
    return false;  // Placate compiler.
  }

  bool BypassListIsReversed() override {
    // This is a KDE-specific setting.
    return false;
  }

  bool UseSuffixMatching() override { return false; }

 private:
  bool GetStringByPath(GSettings* client,
                       std::string_view key,
                       std::string* result) {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    gchar* value = g_settings_get_string(client, key.data());
    if (!value)
      return false;
    *result = value;
    g_free(value);
    return true;
  }
  bool GetBoolByPath(GSettings* client, std::string_view key, bool* result) {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    *result = static_cast<bool>(g_settings_get_boolean(client, key.data()));
    return true;
  }
  bool GetIntByPath(GSettings* client, std::string_view key, int* result) {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    *result = g_settings_get_int(client, key.data());
    return true;
  }
  bool GetStringListByPath(GSettings* client,
                           std::string_view key,
                           std::vector<std::string>* result) {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    gchar** list = g_settings_get_strv(client, key.data());
    if (!list)
      return false;
    for (size_t i = 0; list[i]; ++i) {
      result->push_back(static_cast<char*>(list[i]));
      g_free(list[i]);
    }
    g_free(list);
    return true;
  }

  // This is the callback from the debounce timer.
  void OnDebouncedNotification() {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    CHECK(notify_delegate_);
    // Forward to a method on the proxy config service delegate object.
    notify_delegate_->OnCheckProxyConfigSettings();
  }

  void OnChangeNotification() {
    // We don't use Reset() because the timer may not yet be running.
    // (In that case Stop() is a no-op.)
    debounce_timer_->Stop();
    debounce_timer_->Start(
        FROM_HERE, base::Milliseconds(kDebounceTimeoutMilliseconds), this,
        &SettingGetterImplGSettings::OnDebouncedNotification);
  }

  // gsettings notification callback, dispatched on the default glib main loop.
  static void OnGSettingsChangeNotification(GSettings* client, gchar* key,
                                            gpointer user_data) {
    VLOG(1) << "gsettings change notification for key " << key;
    // We don't track which key has changed, just that something did change.
    SettingGetterImplGSettings* setting_getter =
        reinterpret_cast<SettingGetterImplGSettings*>(user_data);
    setting_getter->OnChangeNotification();
  }

  raw_ptr<GSettings> client_ = nullptr;
  raw_ptr<GSettings> http_client_ = nullptr;
  raw_ptr<GSettings> https_client_ = nullptr;
  raw_ptr<GSettings> ftp_client_ = nullptr;
  raw_ptr<GSettings> socks_client_ = nullptr;
  raw_ptr<ProxyConfigServiceLinux::Delegate> notify_delegate_ = nullptr;
  std::unique_ptr<base::OneShotTimer> debounce_timer_;

  // Task runner for the thread that we make gsettings calls on. It should
  // be the UI thread and all our methods should be called on this
  // thread. Only for assertions.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

bool SettingGetterImplGSettings::CheckVersion(
    base::Environment* env) {
  // CheckVersion() must be called *before* Init()!
  DCHECK(!client_);

  GSettings* client = nullptr;
  if (g_settings_schema_source_lookup(g_settings_schema_source_get_default(),
                                      kProxyGSettingsSchema, TRUE)) {
    client = g_settings_new(kProxyGSettingsSchema);
  }
  if (!client) {
    VLOG(1) << "Cannot create gsettings client.";
    return false;
  }
  g_object_unref(client);

  VLOG(1) << "All gsettings tests OK. Will get proxy config from gsettings.";
  return true;
}
#endif  // defined(USE_GIO)

// Converts |value| from a decimal string to an int. If there was a failure
// parsing, returns |default_value|.
int StringToIntOrDefault(std::string_view value, int default_value) {
  int result;
  if (base::StringToInt(value, &result))
    return result;
  return default_value;
}

// This is the KDE version that reads kioslaverc and simulates gsettings.
// Doing this allows the main Delegate code, as well as the unit tests
// for it, to stay the same - and the settings map fairly well besides.
class SettingGetterImplKDE : public ProxyConfigServiceLinux::SettingGetter {
 public:
  explicit SettingGetterImplKDE(base::Environment* env_var_getter)
      : debounce_timer_(std::make_unique<base::OneShotTimer>()),
        env_var_getter_(env_var_getter) {
    // This has to be called on the UI thread (http://crbug.com/69057).
    ScopedAllowBlockingForSettingGetter allow_blocking;

    // Derive the location(s) of the kde config dir from the environment.
    std::string home;
    if (env_var_getter->GetVar("KDEHOME", &home) && !home.empty()) {
      // $KDEHOME is set. Use it unconditionally.
      kde_config_dirs_.emplace_back(KDEHomeToConfigPath(base::FilePath(home)));
    } else {
      // $KDEHOME is unset. Try to figure out what to use. This seems to be
      // the common case on most distributions.
      if (!env_var_getter->GetVar(base::env_vars::kHome, &home))
        // User has no $HOME? Give up. Later we'll report the failure.
        return;
      auto desktop = base::nix::GetDesktopEnvironment(env_var_getter);
      if (desktop == base::nix::DESKTOP_ENVIRONMENT_KDE3) {
        // KDE3 always uses .kde for its configuration.
        base::FilePath kde_path = base::FilePath(home).Append(".kde");
        kde_config_dirs_.emplace_back(KDEHomeToConfigPath(kde_path));
      } else if (desktop == base::nix::DESKTOP_ENVIRONMENT_KDE4) {
        // Some distributions patch KDE4 to use .kde4 instead of .kde, so that
        // both can be installed side-by-side. Sadly they don't all do this, and
        // they don't always do this: some distributions have started switching
        // back as well. So if there is a .kde4 directory, check the timestamps
        // of the config directories within and use the newest one.
        // Note that we should currently be running in the UI thread, because in
        // the gsettings version, that is the only thread that can access the
        // proxy settings (a gsettings restriction). As noted below, the initial
        // read of the proxy settings will be done in this thread anyway, so we
        // check for .kde4 here in this thread as well.
        base::FilePath kde3_path = base::FilePath(home).Append(".kde");
        base::FilePath kde3_config = KDEHomeToConfigPath(kde3_path);
        base::FilePath kde4_path = base::FilePath(home).Append(".kde4");
        base::FilePath kde4_config = KDEHomeToConfigPath(kde4_path);
        bool use_kde4 = false;
        if (base::DirectoryExists(kde4_path)) {
          base::File::Info kde3_info;
          base::File::Info kde4_info;
          if (base::GetFileInfo(kde4_config, &kde4_info)) {
            if (base::GetFileInfo(kde3_config, &kde3_info)) {
              use_kde4 = kde4_info.last_modified >= kde3_info.last_modified;
            } else {
              use_kde4 = true;
            }
          }
        }
        if (use_kde4) {
          kde_config_dirs_.emplace_back(KDEHomeToConfigPath(kde4_path));
        } else {
          kde_config_dirs_.emplace_back(KDEHomeToConfigPath(kde3_path));
        }
      } else if (desktop == base::nix::DESKTOP_ENVIRONMENT_KDE5 ||
                 desktop == base::nix::DESKTOP_ENVIRONMENT_KDE6) {
        // KDE 5 migrated to ~/.config for storing kioslaverc.
        kde_config_dirs_.emplace_back(base::FilePath(home).Append(".config"));

        // kioslaverc also can be stored in any of XDG_CONFIG_DIRS
        std::string config_dirs;
        if (env_var_getter_->GetVar("XDG_CONFIG_DIRS", &config_dirs)) {
          auto dirs = base::SplitString(config_dirs, ":", base::KEEP_WHITESPACE,
                                        base::SPLIT_WANT_NONEMPTY);
          for (const auto& dir : dirs) {
            kde_config_dirs_.emplace_back(dir);
          }
        }

        // Reverses the order of paths to store them in ascending order of
        // priority
        std::reverse(kde_config_dirs_.begin(), kde_config_dirs_.end());
      }
    }
  }

  SettingGetterImplKDE(const SettingGetterImplKDE&) = delete;
  SettingGetterImplKDE& operator=(const SettingGetterImplKDE&) = delete;

  ~SettingGetterImplKDE() override {
    // inotify_fd_ should have been closed before now, from
    // Delegate::OnDestroy(), while running on the file thread. However
    // on exiting the process, it may happen that Delegate::OnDestroy()
    // task is left pending on the file loop after the loop was quit,
    // and pending tasks may then be deleted without being run.
    // Here in the KDE version, we can safely close the file descriptor
    // anyway. (Not that it really matters; the process is exiting.)
    if (inotify_fd_ >= 0)
      ShutDown();
    DCHECK_LT(inotify_fd_, 0);
  }

  bool Init(const scoped_refptr<base::SingleThreadTaskRunner>& glib_task_runner)
      override {
    // This has to be called on the UI thread (http://crbug.com/69057).
    ScopedAllowBlockingForSettingGetter allow_blocking;
    DCHECK_LT(inotify_fd_, 0);
    inotify_fd_ = inotify_init();
    if (inotify_fd_ < 0) {
      PLOG(ERROR) << "inotify_init failed";
      return false;
    }
    if (!base::SetNonBlocking(inotify_fd_)) {
      PLOG(ERROR) << "base::SetNonBlocking failed";
      close(inotify_fd_);
      inotify_fd_ = -1;
      return false;
    }

    constexpr base::TaskTraits kTraits = {base::TaskPriority::USER_VISIBLE,
                                          base::MayBlock()};
    file_task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(kTraits);

    // The initial read is done on the current thread, not
    // |file_task_runner_|, since we will need to have it for
    // SetUpAndFetchInitialConfig().
    UpdateCachedSettings();
    return true;
  }

  void ShutDown() override {
    if (inotify_fd_ >= 0) {
      ResetCachedSettings();
      inotify_watcher_.reset();
      close(inotify_fd_);
      inotify_fd_ = -1;
    }
    debounce_timer_.reset();
  }

  bool SetUpNotifications(
      ProxyConfigServiceLinux::Delegate* delegate) override {
    DCHECK_GE(inotify_fd_, 0);
    DCHECK(file_task_runner_->RunsTasksInCurrentSequence());
    // We can't just watch the kioslaverc file directly, since KDE will write
    // a new copy of it and then rename it whenever settings are changed and
    // inotify watches inodes (so we'll be watching the old deleted file after
    // the first change, and it will never change again). So, we watch the
    // directory instead. We then act only on changes to the kioslaverc entry.
    // TODO(eroman): What if the file is deleted? (handle with IN_DELETE).
    size_t failed_dirs = 0;
    for (const auto& kde_config_dir : kde_config_dirs_) {
      if (inotify_add_watch(inotify_fd_, kde_config_dir.value().c_str(),
                            IN_MODIFY | IN_MOVED_TO) < 0) {
        ++failed_dirs;
      }
    }
    // Fail if inotify_add_watch failed with every directory
    if (failed_dirs == kde_config_dirs_.size()) {
      return false;
    }
    notify_delegate_ = delegate;
    inotify_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        inotify_fd_,
        base::BindRepeating(&SettingGetterImplKDE::OnChangeNotification,
                            base::Unretained(this)));
    // Simulate a change to avoid possibly losing updates before this point.
    OnChangeNotification();
    return true;
  }

  const scoped_refptr<base::SequencedTaskRunner>& GetNotificationTaskRunner()
      override {
    return file_task_runner_;
  }

  bool GetString(StringSetting key, std::string* result) override {
    auto it = string_table_.find(key);
    if (it == string_table_.end())
      return false;
    *result = it->second;
    return true;
  }
  bool GetBool(BoolSetting key, bool* result) override {
    // We don't ever have any booleans.
    return false;
  }
  bool GetInt(IntSetting key, int* result) override {
    // We don't ever have any integers. (See AddProxy() below about ports.)
    return false;
  }
  bool GetStringList(StringListSetting key,
                     std::vector<std::string>* result) override {
    auto it = strings_table_.find(key);
    if (it == strings_table_.end())
      return false;
    *result = it->second;
    return true;
  }

  bool BypassListIsReversed() override { return reversed_bypass_list_; }

  bool UseSuffixMatching() override { return true; }

 private:
  void ResetCachedSettings() {
    string_table_.clear();
    strings_table_.clear();
    indirect_manual_ = false;
    auto_no_pac_ = false;
    reversed_bypass_list_ = false;
  }

  base::FilePath KDEHomeToConfigPath(const base::FilePath& kde_home) {
    return kde_home.Append("share").Append("config");
  }

  void AddProxy(StringSetting host_key, const std::string& value) {
    if (value.empty() || value.substr(0, 3) == "//:")
      // No proxy.
      return;
    size_t space = value.find(' ');
    if (space != std::string::npos) {
      // Newer versions of KDE use a space rather than a colon to separate the
      // port number from the hostname. If we find this, we need to convert it.
      std::string fixed = value;
      fixed[space] = ':';
      string_table_[host_key] = std::move(fixed);
    } else {
      // We don't need to parse the port number out; GetProxyFromSettings()
      // would only append it right back again. So we just leave the port
      // number right in the host string.
      string_table_[host_key] = value;
    }
  }

  void AddHostList(StringListSetting key, const std::string& value) {
    std::vector<std::string> tokens;
    base::StringTokenizer tk(value, ", ");
    while (tk.GetNext()) {
      std::string token = tk.token();
      if (!token.empty())
        tokens.push_back(token);
    }
    strings_table_[key] = tokens;
  }

  void AddKDESetting(const std::string& key, const std::string& value) {
    if (key == "ProxyType") {
      const char* mode = "none";
      indirect_manual_ = false;
      auto_no_pac_ = false;
      int int_value = StringToIntOrDefault(value, 0);
      switch (int_value) {
        case 1:  // Manual configuration.
          mode = "manual";
          break;
        case 2:  // PAC URL.
          mode = "auto";
          break;
        case 3:  // WPAD.
          mode = "auto";
          auto_no_pac_ = true;
          break;
        case 4:  // Indirect manual via environment variables.
          mode = "manual";
          indirect_manual_ = true;
          break;
        default:  // No proxy, or maybe kioslaverc syntax error.
          break;
      }
      string_table_[PROXY_MODE] = mode;
    } else if (key == "Proxy Config Script") {
      string_table_[PROXY_AUTOCONF_URL] = value;
    } else if (key == "httpProxy") {
      AddProxy(PROXY_HTTP_HOST, value);
    } else if (key == "httpsProxy") {
      AddProxy(PROXY_HTTPS_HOST, value);
    } else if (key == "ftpProxy") {
      AddProxy(PROXY_FTP_HOST, value);
    } else if (key == "socksProxy") {
      // Older versions of KDE configure SOCKS in a weird way involving
      // LD_PRELOAD and a library that intercepts network calls to SOCKSify
      // them. We don't support it. KDE 4.8 added a proper SOCKS setting.
      AddProxy(PROXY_SOCKS_HOST, value);
    } else if (key == "ReversedException") {
      // We count "true" or any nonzero number as true, otherwise false.
      // A failure parsing the integer will also mean false.
      reversed_bypass_list_ =
          (value == "true" || StringToIntOrDefault(value, 0) != 0);
    } else if (key == "NoProxyFor") {
      AddHostList(PROXY_IGNORE_HOSTS, value);
    } else if (key == "AuthMode") {
      // Check for authentication, just so we can warn.
      int mode = StringToIntOrDefault(value, 0);
      if (mode) {
        // ProxyConfig does not support authentication parameters, but
        // Chrome will prompt for the password later. So we ignore this.
        LOG(WARNING) <<
            "Proxy authentication parameters ignored, see bug 16709";
      }
    }
  }

  void ResolveIndirect(StringSetting key) {
    auto it = string_table_.find(key);
    if (it != string_table_.end()) {
      std::string value;
      if (env_var_getter_->GetVar(it->second.c_str(), &value))
        it->second = value;
      else
        string_table_.erase(it);
    }
  }

  void ResolveIndirectList(StringListSetting key) {
    auto it = strings_table_.find(key);
    if (it != strings_table_.end()) {
      std::string value;
      if (!it->second.empty() &&
          env_var_getter_->GetVar(it->second[0].c_str(), &value))
        AddHostList(key, value);
      else
        strings_table_.erase(it);
    }
  }

  // The settings in
```