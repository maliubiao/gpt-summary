Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Core Purpose:**

The filename `net/proxy_resolution/proxy_config_service_android.cc` immediately gives a strong hint: it's about managing proxy configurations on Android. The `#include` directives confirm this, bringing in Android-specific JNI (Java Native Interface) headers and general networking components. The core function will likely be reading proxy settings from the Android system and making them available to Chromium's network stack.

**2. Initial Code Scan - Identifying Key Components:**

A quick skim reveals several important elements:

* **JNI Interactions:** The heavy use of `base::android::*` and the inclusion of `net/net_jni_headers/ProxyChangeListener_jni.h` signal that this code bridges between C++ and Java. It interacts with Android's Java-based proxy settings.
* **`ProxyConfigServiceAndroid` Class:** This is the main class, responsible for providing proxy configuration.
* **`Delegate` Class:**  This seems like an internal implementation detail, likely handling the asynchronous nature of interacting with the Android system and managing observers.
* **`GetPropertyCallback`:** This type alias suggests a way to retrieve system properties, which is how Android typically stores proxy settings.
* **`ProxyConfig`, `ProxyServer`, `ProxyBypassRules`:** These are standard networking classes within Chromium, representing the actual proxy configuration.
* **Static Helper Functions:**  Functions like `ConstructProxyServer`, `LookupProxy`, `AddBypassRules`, `GetProxyRules`, and `GetLatestProxyConfigInternal` are responsible for the logic of interpreting Android's property settings.
* **Override Functionality:**  Functions like `CreateStaticProxyConfig`, `ParseOverrideRules`, and `CreateOverrideProxyConfig` indicate that there's a mechanism to temporarily override the system proxy settings.

**3. Deeper Dive into Key Functions:**

Now, it's time to analyze the most important functions in detail:

* **`GetJavaProperty`:** This is the entry point for retrieving Android system properties. It clearly uses JNI to call a Java method.
* **`GetLatestProxyConfigInternal` and `GetProxyRules`:** These functions are the heart of reading the system proxy settings. They parse the `http.proxyHost`, `http.proxyPort`, `https.proxyHost`, etc., properties. The logic mirrors the Java implementation in Android, as noted in the comments.
* **`ConstructProxyServer` and `ConvertStringToPort`:** These are utility functions to convert the host and port strings into the `ProxyServer` object. Error handling (checking for invalid ports) is present.
* **Override Functions:**  Understanding how `SetProxyOverride` and `ClearProxyOverride` work is crucial. They introduce a temporary state that deviates from the system settings.
* **`Delegate` Class:**  Realizing that this class manages the asynchronous interactions and observer notifications is key to understanding the architecture. The JNI calls trigger events in the `Delegate`, which then updates the main thread.

**4. Identifying Relationships and Data Flow:**

Connecting the pieces:

1. Android's system settings are stored as properties.
2. The `ProxyChangeListener` Java class (bridged via JNI) notifies the C++ code when these settings change.
3. `GetJavaProperty` fetches these properties.
4. `GetLatestProxyConfigInternal` and related functions parse these properties into a `ProxyConfig`.
5. The `Delegate` manages this process and notifies observers (other parts of Chromium's network stack) when the configuration changes.
6. Override functions allow temporarily setting a different proxy configuration.

**5. Answering the Specific Questions:**

Now, with a good understanding of the code, answering the prompt's questions becomes straightforward:

* **Functionality:** Summarize the core purpose, focusing on reading and providing Android proxy settings, and the override mechanism.
* **JavaScript Relationship:** Recognize that this C++ code *indirectly* affects JavaScript by configuring how network requests are made by the browser. Think about `XMLHttpRequest` and `fetch` and how they are routed through proxies. Provide a simple example.
* **Logical Reasoning (Hypothetical Input/Output):** Choose a scenario, like setting specific proxy settings in Android, and trace how the code would process those settings. Show the input (Android properties) and the resulting output (`ProxyConfig`).
* **User/Programming Errors:** Think about common mistakes: incorrect proxy settings, typos in bypass rules, not handling the override mechanism correctly.
* **User Operation to Reach Here (Debugging Clues):** Describe the user actions that would trigger this code, starting from the user changing proxy settings in Android's system settings and following the chain of events to this C++ code.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Might initially focus too much on the low-level JNI details.
* **Correction:** Realize the importance of understanding the overall flow and the role of the `Delegate`. Shift focus to the higher-level logic.
* **Initial thought:** Might overlook the override functionality.
* **Correction:**  Pay close attention to functions like `SetProxyOverride` and `ClearProxyOverride` and their impact on the normal proxy configuration process.
* **Initial thought:**  Might not clearly articulate the JavaScript connection.
* **Correction:**  Explicitly connect the C++ proxy configuration to how JavaScript makes network requests.

By following this structured thought process, including identifying key components, diving into crucial functions, understanding the data flow, and then addressing the specific questions, a comprehensive and accurate analysis of the code can be achieved.
好的，让我们来分析一下 `net/proxy_resolution/proxy_config_service_android.cc` 这个文件。

**文件功能概述:**

`ProxyConfigServiceAndroid` 类的主要功能是为 Chromium 的网络栈提供来自 Android 系统级别的代理配置信息。它会监听 Android 系统代理设置的更改，并将这些更改转化为 Chromium 可以理解的 `ProxyConfig` 对象。

更具体地说，它的功能包括：

1. **读取 Android 系统代理设置:**  通过 JNI (Java Native Interface) 调用 Android Java 层的 `ProxyChangeListener` 类来获取代理设置信息。这些信息通常以系统属性的形式存在，例如 `http.proxyHost`, `http.proxyPort`, `https.proxyHost` 等。
2. **监听代理设置变化:**  `ProxyConfigServiceAndroid` 会注册一个监听器，当 Android 系统的代理设置发生变化时，会收到通知。
3. **解析代理配置:** 将从 Android 系统获取的字符串形式的代理信息解析成 Chromium 内部使用的 `ProxyConfig` 对象，包括代理服务器地址、端口、协议类型以及绕过规则等。
4. **提供代理配置信息:**  实现 `ProxyConfigService` 接口，允许 Chromium 的其他网络组件查询当前的代理配置。
5. **支持代理覆盖 (Override):**  允许在某些情况下临时覆盖 Android 系统的代理设置，例如通过应用特定的配置。
6. **处理 PAC (Proxy Auto-Config) 文件:**  虽然代码主要关注静态代理配置，但它也包含了处理 PAC 文件 URL 的逻辑。

**与 JavaScript 的关系:**

`ProxyConfigServiceAndroid` 本身不包含直接的 JavaScript 代码。然而，它提供的代理配置信息会直接影响到在 Chromium 中运行的 JavaScript 代码的网络行为。

**举例说明:**

假设一个网页上的 JavaScript 代码尝试发起一个 `XMLHttpRequest` 或 `fetch` 请求。 Chromium 的网络栈会使用 `ProxyConfigServiceAndroid` 提供的代理配置来决定如何发送这个请求：

* **没有代理:** 如果 `ProxyConfigServiceAndroid` 指示没有设置代理，JavaScript 发起的请求会直接发送到目标服务器。
* **HTTP 代理:** 如果配置了 HTTP 代理，JavaScript 发起的 HTTP 请求会被发送到配置的代理服务器，由代理服务器转发。
* **HTTPS 代理:**  与 HTTP 类似，但用于 HTTPS 请求。
* **SOCKS 代理:** 如果配置了 SOCKS 代理，JavaScript 发起的请求会通过 SOCKS 代理进行连接。
* **代理绕过规则:**  如果 JavaScript 请求的目标地址匹配配置的绕过规则（例如 `*.example.com`），则请求会直接发送，不经过代理。
* **PAC 文件:** 如果配置了 PAC 文件 URL， Chromium 会下载并执行 PAC 文件中的 JavaScript 代码，根据 PAC 文件返回的规则来决定是否使用代理以及使用哪个代理。

**逻辑推理 (假设输入与输出):**

**假设输入 (Android 系统属性):**

```
http.proxyHost=proxy.example.com
http.proxyPort=8080
https.proxyHost=secure-proxy.example.com
https.proxyPort=8443
http.nonProxyHosts=localhost|127.0.0.1|*.internal.net
```

**逻辑推理过程:**

1. `ProxyConfigServiceAndroid` 通过 JNI 调用 `ProxyChangeListener` 获取到这些系统属性。
2. `GetJavaProperty` 函数会被用来读取这些属性值。
3. `LookupProxy` 函数会根据前缀 (例如 "http", "https") 和属性名 (例如 "proxyHost", "proxyPort") 来构建 `ProxyServer` 对象。
4. `AddBypassRules` 函数会解析 `http.nonProxyHosts` 属性，并将其添加到 `ProxyBypassRules` 中。

**预期输出 (部分 `ProxyConfig` 内容):**

```
proxy_rules: {
  type: PROXY_LIST_PER_SCHEME
  proxies_for_http: "PROXY proxy.example.com:8080"
  proxies_for_https: "PROXY secure-proxy.example.com:8443"
  bypass_rules: {
    rules: [
      "http://localhost",
      "http://127.0.0.1",
      "http://*.internal.net"
    ]
  }
}
```

**用户或编程常见的使用错误:**

1. **错误的代理服务器地址或端口:** 用户可能在 Android 系统设置中输入了错误的代理服务器主机名或端口号，导致网络请求失败。例如，将 `http.proxyPort` 设置为非数字的值。
2. **错误的绕过规则:** 用户可能配置了不正确的绕过规则，导致某些应该使用代理的请求被直接发送，或者反之。例如，拼写错误，或者使用了错误的通配符。
3. **PAC 文件错误:** 如果配置了 PAC 文件，PAC 文件中的 JavaScript 代码可能存在错误，导致返回错误的代理配置，或者执行失败。
4. **JNI 调用问题 (开发者):**  在开发 Chromium 时，如果与 `ProxyChangeListener` 的 JNI 交互出现问题，例如方法签名错误，可能会导致无法正确获取 Android 系统代理设置。
5. **权限问题 (开发者/用户):**  某些情况下，获取系统属性可能需要特定的权限。如果 Chromium 没有必要的权限，可能无法读取代理设置。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 Android 设备的设置中修改了 Wi-Fi 或移动网络的代理设置。**  这会触发 Android 系统的代理设置更改。
2. **Android 系统会发出一个广播或调用相关的系统服务通知代理设置已更改。**
3. **`ProxyChangeListener` (Java 代码) 会接收到这个通知。**
4. **`ProxyChangeListener` (Java 代码) 会调用其 native 方法，即 `ProxyConfigServiceAndroid::JNIDelegate::ProxySettingsChangedTo` 或 `ProxyConfigServiceAndroid::JNIDelegate::ProxySettingsChanged`。**  这会通过 JNI 调用到 C++ 代码。
5. **在 C++ 代码中，`ProxyConfigServiceAndroid` 的 `Delegate::ProxySettingsChangedTo` 或 `Delegate::ProxySettingsChanged` 方法会被调用。**
6. **这些方法会请求最新的代理配置信息，通常是通过调用 `GetLatestProxyConfigInternal`，它会读取 Android 系统属性。**
7. **新的代理配置会被存储起来，并通知所有观察者（例如，网络栈的其他部分）。**

**调试线索:**

* **检查 Android 系统的代理设置:** 确认用户是否真的修改了代理设置，以及设置是否正确。
* **查看 logcat 日志:** 查找与 `ProxyChangeListener` 和 `ProxyConfigServiceAndroid` 相关的日志信息，看是否有错误或异常。
* **断点调试 C++ 代码:** 在 `ProxyConfigServiceAndroid::JNIDelegate::ProxySettingsChangedTo` 和 `Delegate::ProxySettingsChangedTo` 等关键位置设置断点，查看代码执行流程和变量值。
* **检查 JNI 调用:** 确认 JNI 调用是否成功，参数是否正确传递。
* **查看 Chromium 的网络事件日志:**  在 `chrome://net-internals/#events` 中查看网络事件，可以了解代理配置的加载和应用情况。
* **使用 `adb shell` 查看系统属性:** 可以使用 `adb shell getprop` 命令来直接查看 Android 系统的代理相关属性，验证 C++ 代码读取到的值是否正确。

希望这些信息能够帮助你理解 `net/proxy_resolution/proxy_config_service_android.cc` 文件的功能以及它在 Chromium 网络栈中的作用。

Prompt: 
```
这是目录为net/proxy_resolution/proxy_config_service_android.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy_resolution/proxy_config_service_android.h"

#include <sys/system_properties.h>

#include "base/android/jni_array.h"
#include "base/android/jni_string.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/observer_list.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "net/base/host_port_pair.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"
#include "url/third_party/mozilla/url_parse.h"

// Must come after all headers that specialize FromJniType() / ToJniType().
#include "net/net_jni_headers/ProxyChangeListener_jni.h"

using base::android::AttachCurrentThread;
using base::android::ConvertUTF8ToJavaString;
using base::android::ConvertJavaStringToUTF8;
using base::android::CheckException;
using base::android::ClearException;
using base::android::JavaParamRef;
using base::android::ScopedJavaGlobalRef;
using base::android::ScopedJavaLocalRef;

namespace net {

namespace {

typedef ProxyConfigServiceAndroid::GetPropertyCallback GetPropertyCallback;

// Returns whether the provided string was successfully converted to a port.
bool ConvertStringToPort(const std::string& port, int* output) {
  url::Component component(0, port.size());
  int result = url::ParsePort(port.c_str(), component);
  if (result == url::PORT_INVALID || result == url::PORT_UNSPECIFIED)
    return false;
  *output = result;
  return true;
}

ProxyServer ConstructProxyServer(ProxyServer::Scheme scheme,
                                 const std::string& proxy_host,
                                 const std::string& proxy_port) {
  DCHECK(!proxy_host.empty());
  int port_as_int = 0;
  if (proxy_port.empty())
    port_as_int = ProxyServer::GetDefaultPortForScheme(scheme);
  else if (!ConvertStringToPort(proxy_port, &port_as_int))
    return ProxyServer();
  DCHECK(port_as_int > 0);
  return ProxyServer(
      scheme, HostPortPair(proxy_host, static_cast<uint16_t>(port_as_int)));
}

ProxyServer LookupProxy(const std::string& prefix,
                        const GetPropertyCallback& get_property,
                        ProxyServer::Scheme scheme) {
  DCHECK(!prefix.empty());
  std::string proxy_host = get_property.Run(prefix + ".proxyHost");
  if (!proxy_host.empty()) {
    std::string proxy_port = get_property.Run(prefix + ".proxyPort");
    return ConstructProxyServer(scheme, proxy_host, proxy_port);
  }
  // Fall back to default proxy, if any.
  proxy_host = get_property.Run("proxyHost");
  if (!proxy_host.empty()) {
    std::string proxy_port = get_property.Run("proxyPort");
    return ConstructProxyServer(scheme, proxy_host, proxy_port);
  }
  return ProxyServer();
}

ProxyServer LookupSocksProxy(const GetPropertyCallback& get_property) {
  std::string proxy_host = get_property.Run("socksProxyHost");
  if (!proxy_host.empty()) {
    std::string proxy_port = get_property.Run("socksProxyPort");
    return ConstructProxyServer(ProxyServer::SCHEME_SOCKS5, proxy_host,
                                proxy_port);
  }
  return ProxyServer();
}

void AddBypassRules(const std::string& scheme,
                    const GetPropertyCallback& get_property,
                    ProxyBypassRules* bypass_rules) {
  // The format of a hostname pattern is a list of hostnames that are separated
  // by | and that use * as a wildcard. For example, setting the
  // http.nonProxyHosts property to *.android.com|*.kernel.org will cause
  // requests to http://developer.android.com to be made without a proxy.

  std::string non_proxy_hosts =
      get_property.Run(scheme + ".nonProxyHosts");
  if (non_proxy_hosts.empty())
    return;
  base::StringTokenizer tokenizer(non_proxy_hosts, "|");
  while (tokenizer.GetNext()) {
    std::string token = tokenizer.token();
    std::string pattern;
    base::TrimWhitespaceASCII(token, base::TRIM_ALL, &pattern);
    if (pattern.empty())
      continue;
    // '?' is not one of the specified pattern characters above.
    DCHECK_EQ(std::string::npos, pattern.find('?'));
    bypass_rules->AddRuleFromString(scheme + "://" + pattern);
  }
}

// Returns true if a valid proxy was found.
bool GetProxyRules(const GetPropertyCallback& get_property,
                   ProxyConfig::ProxyRules* rules) {
  // See libcore/luni/src/main/java/java/net/ProxySelectorImpl.java for the
  // mostly equivalent Android implementation.  There is one intentional
  // difference: by default Chromium uses the HTTP port (80) for HTTPS
  // connections via proxy.  This default is identical on other platforms.
  // On the opposite, Java spec suggests to use HTTPS port (443) by default (the
  // default value of https.proxyPort).
  rules->type = ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME;
  rules->proxies_for_http.SetSingleProxyServer(
      LookupProxy("http", get_property, ProxyServer::SCHEME_HTTP));
  rules->proxies_for_https.SetSingleProxyServer(
      LookupProxy("https", get_property, ProxyServer::SCHEME_HTTP));
  rules->proxies_for_ftp.SetSingleProxyServer(
      LookupProxy("ftp", get_property, ProxyServer::SCHEME_HTTP));
  rules->fallback_proxies.SetSingleProxyServer(LookupSocksProxy(get_property));
  rules->bypass_rules.Clear();
  AddBypassRules("ftp", get_property, &rules->bypass_rules);
  AddBypassRules("http", get_property, &rules->bypass_rules);
  AddBypassRules("https", get_property, &rules->bypass_rules);
  // We know a proxy was found if not all of the proxy lists are empty.
  return !(rules->proxies_for_http.IsEmpty() &&
      rules->proxies_for_https.IsEmpty() &&
      rules->proxies_for_ftp.IsEmpty() &&
      rules->fallback_proxies.IsEmpty());
}

void GetLatestProxyConfigInternal(const GetPropertyCallback& get_property,
                                  ProxyConfigWithAnnotation* config) {
  ProxyConfig proxy_config;
  proxy_config.set_from_system(true);
  if (GetProxyRules(get_property, &proxy_config.proxy_rules())) {
    *config =
        ProxyConfigWithAnnotation(proxy_config, MISSING_TRAFFIC_ANNOTATION);
  } else {
    *config = ProxyConfigWithAnnotation::CreateDirect();
  }
}

std::string GetJavaProperty(const std::string& property) {
  // Use Java System.getProperty to get configuration information.
  // TODO(pliard): Conversion to/from UTF8 ok here?
  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jstring> str = ConvertUTF8ToJavaString(env, property);
  ScopedJavaLocalRef<jstring> result =
      Java_ProxyChangeListener_getProperty(env, str);
  return result.is_null() ?
      std::string() : ConvertJavaStringToUTF8(env, result.obj());
}

void CreateStaticProxyConfig(const std::string& host,
                             int port,
                             const std::string& pac_url,
                             const std::vector<std::string>& exclusion_list,
                             ProxyConfigWithAnnotation* config) {
  ProxyConfig proxy_config;
  if (!pac_url.empty()) {
    proxy_config.set_pac_url(GURL(pac_url));
    proxy_config.set_pac_mandatory(false);
    *config =
        ProxyConfigWithAnnotation(proxy_config, MISSING_TRAFFIC_ANNOTATION);
  } else if (port != 0) {
    std::string rules = base::StringPrintf("%s:%d", host.c_str(), port);
    proxy_config.proxy_rules().ParseFromString(rules);
    proxy_config.proxy_rules().bypass_rules.Clear();

    std::vector<std::string>::const_iterator it;
    for (it = exclusion_list.begin(); it != exclusion_list.end(); ++it) {
      std::string pattern;
      base::TrimWhitespaceASCII(*it, base::TRIM_ALL, &pattern);
      if (pattern.empty())
          continue;
      proxy_config.proxy_rules().bypass_rules.AddRuleFromString(pattern);
    }
    *config =
        ProxyConfigWithAnnotation(proxy_config, MISSING_TRAFFIC_ANNOTATION);
  } else {
    *config = ProxyConfigWithAnnotation::CreateDirect();
  }
}

std::string ParseOverrideRules(
    const std::vector<ProxyConfigServiceAndroid::ProxyOverrideRule>&
        override_rules,
    ProxyConfig::ProxyRules* proxy_rules) {
  // If no rules were specified, use DIRECT for everything.
  if (override_rules.empty()) {
    DCHECK(proxy_rules->empty());
    return "";
  }

  // Otherwise use a proxy list per URL scheme.
  proxy_rules->type = ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME;

  for (const auto& rule : override_rules) {
    // Parse the proxy URL.
    ProxyChain proxy_chain =
        ProxyUriToProxyChain(rule.proxy_url, ProxyServer::Scheme::SCHEME_HTTP);
    if (!proxy_chain.IsValid()) {
      return "Invalid Proxy URL: " + rule.proxy_url;
    } else if (proxy_chain.is_multi_proxy()) {
      return "Unsupported multi proxy chain: " + rule.proxy_url;
    } else if (proxy_chain.is_single_proxy() && proxy_chain.First().is_quic()) {
      return "Unsupported proxy scheme: " + rule.proxy_url;
    }

    // Parse the URL scheme.
    if (base::EqualsCaseInsensitiveASCII(rule.url_scheme, "http")) {
      proxy_rules->proxies_for_http.AddProxyChain(proxy_chain);
    } else if (base::EqualsCaseInsensitiveASCII(rule.url_scheme, "https")) {
      proxy_rules->proxies_for_https.AddProxyChain(proxy_chain);
    } else if (rule.url_scheme == "*") {
      proxy_rules->fallback_proxies.AddProxyChain(proxy_chain);
    } else {
      return "Unsupported URL scheme: " + rule.url_scheme;
    }
  }

  // If there is no per-URL scheme distinction simplify the ProxyRules.
  if (proxy_rules->proxies_for_http.IsEmpty() &&
      proxy_rules->proxies_for_https.IsEmpty() &&
      !proxy_rules->fallback_proxies.IsEmpty()) {
    proxy_rules->type = ProxyConfig::ProxyRules::Type::PROXY_LIST;
    std::swap(proxy_rules->single_proxies, proxy_rules->fallback_proxies);
  }

  return "";
}

std::string CreateOverrideProxyConfig(
    const std::vector<ProxyConfigServiceAndroid::ProxyOverrideRule>&
        proxy_rules,
    const std::vector<std::string>& bypass_rules,
    const bool reverse_bypass,
    ProxyConfigWithAnnotation* config) {
  ProxyConfig proxy_config;
  auto result = ParseOverrideRules(proxy_rules, &proxy_config.proxy_rules());
  if (!result.empty()) {
    return result;
  }

  proxy_config.proxy_rules().reverse_bypass = reverse_bypass;

  for (const auto& bypass_rule : bypass_rules) {
    if (!proxy_config.proxy_rules().bypass_rules.AddRuleFromString(
            bypass_rule)) {
      return "Invalid bypass rule " + bypass_rule;
    }
  }
  *config = ProxyConfigWithAnnotation(proxy_config, MISSING_TRAFFIC_ANNOTATION);
  return "";
}

}  // namespace

class ProxyConfigServiceAndroid::Delegate
    : public base::RefCountedThreadSafe<Delegate> {
 public:
  Delegate(const scoped_refptr<base::SequencedTaskRunner>& main_task_runner,
           const scoped_refptr<base::SequencedTaskRunner>& jni_task_runner,
           const GetPropertyCallback& get_property_callback)
      : jni_delegate_(this),
        main_task_runner_(main_task_runner),
        jni_task_runner_(jni_task_runner),
        get_property_callback_(get_property_callback) {}

  Delegate(const Delegate&) = delete;
  Delegate& operator=(const Delegate&) = delete;

  void SetupJNI() {
    DCHECK(InJNISequence());
    JNIEnv* env = AttachCurrentThread();
    if (java_proxy_change_listener_.is_null()) {
      java_proxy_change_listener_.Reset(Java_ProxyChangeListener_create(env));
      CHECK(!java_proxy_change_listener_.is_null());
    }
    Java_ProxyChangeListener_start(env, java_proxy_change_listener_,
                                   reinterpret_cast<intptr_t>(&jni_delegate_));
  }

  void FetchInitialConfig() {
    DCHECK(InJNISequence());
    ProxyConfigWithAnnotation proxy_config;
    GetLatestProxyConfigInternal(get_property_callback_, &proxy_config);
    main_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&Delegate::SetNewConfigInMainSequence, this,
                                  proxy_config));
  }

  void Shutdown() {
    if (InJNISequence()) {
      ShutdownInJNISequence();
    } else {
      jni_task_runner_->PostTask(
          FROM_HERE, base::BindOnce(&Delegate::ShutdownInJNISequence, this));
    }
  }

  // Called only in the network sequence.
  void AddObserver(Observer* observer) {
    DCHECK(InMainSequence());
    observers_.AddObserver(observer);
  }

  void RemoveObserver(Observer* observer) {
    DCHECK(InMainSequence());
    observers_.RemoveObserver(observer);
  }

  ConfigAvailability GetLatestProxyConfig(ProxyConfigWithAnnotation* config) {
    DCHECK(InMainSequence());
    if (!config)
      return ProxyConfigService::CONFIG_UNSET;
    *config = proxy_config_;
    return ProxyConfigService::CONFIG_VALID;
  }

  // Called in the JNI sequence.
  void ProxySettingsChanged() {
    DCHECK(InJNISequence());
    if (has_proxy_override_)
      return;

    ProxyConfigWithAnnotation proxy_config;
    GetLatestProxyConfigInternal(get_property_callback_, &proxy_config);
    main_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&Delegate::SetNewConfigInMainSequence, this,
                                  proxy_config));
  }

  // Called in the JNI sequence.
  void ProxySettingsChangedTo(const std::string& host,
                              int port,
                              const std::string& pac_url,
                              const std::vector<std::string>& exclusion_list) {
    DCHECK(InJNISequence());
    if (has_proxy_override_)
      return;

    ProxyConfigWithAnnotation proxy_config;
    if (exclude_pac_url_) {
      CreateStaticProxyConfig(host, port, "", exclusion_list, &proxy_config);
    } else {
      CreateStaticProxyConfig(host, port, pac_url, exclusion_list,
          &proxy_config);
    }
    main_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&Delegate::SetNewConfigInMainSequence, this,
                                  proxy_config));
  }

  void set_exclude_pac_url(bool enabled) {
    exclude_pac_url_ = enabled;
  }

  // Called in the JNI sequence.
  std::string SetProxyOverride(
      const std::vector<ProxyOverrideRule>& proxy_rules,
      const std::vector<std::string>& bypass_rules,
      const bool reverse_bypass,
      base::OnceClosure callback) {
    DCHECK(InJNISequence());
    has_proxy_override_ = true;

    // Creates a new proxy config
    ProxyConfigWithAnnotation proxy_config;
    std::string result = CreateOverrideProxyConfig(
        proxy_rules, bypass_rules, reverse_bypass, &proxy_config);
    if (!result.empty()) {
      return result;
    }

    main_task_runner_->PostTaskAndReply(
        FROM_HERE,
        base::BindOnce(&Delegate::SetNewConfigInMainSequence, this,
                       proxy_config),
        std::move(callback));

    return "";
  }

  // Called in the JNI sequence.
  void ClearProxyOverride(base::OnceClosure callback) {
    DCHECK(InJNISequence());
    if (!has_proxy_override_) {
      std::move(callback).Run();
      return;
    }

    ProxyConfigWithAnnotation proxy_config;
    GetLatestProxyConfigInternal(get_property_callback_, &proxy_config);
    main_task_runner_->PostTaskAndReply(
        FROM_HERE,
        base::BindOnce(&Delegate::SetNewConfigInMainSequence, this,
                       proxy_config),
        std::move(callback));
    has_proxy_override_ = false;
  }

 private:
  friend class base::RefCountedThreadSafe<Delegate>;

  class JNIDelegateImpl : public ProxyConfigServiceAndroid::JNIDelegate {
   public:
    explicit JNIDelegateImpl(Delegate* delegate) : delegate_(delegate) {}

    // ProxyConfigServiceAndroid::JNIDelegate overrides.
    void ProxySettingsChangedTo(
        JNIEnv* env,
        const JavaParamRef<jobject>& jself,
        const JavaParamRef<jstring>& jhost,
        jint jport,
        const JavaParamRef<jstring>& jpac_url,
        const JavaParamRef<jobjectArray>& jexclusion_list) override {
      std::string host = ConvertJavaStringToUTF8(env, jhost);
      std::string pac_url;
      if (jpac_url)
        ConvertJavaStringToUTF8(env, jpac_url, &pac_url);
      std::vector<std::string> exclusion_list;
      base::android::AppendJavaStringArrayToStringVector(
          env, jexclusion_list, &exclusion_list);
      delegate_->ProxySettingsChangedTo(host, jport, pac_url, exclusion_list);
    }

    void ProxySettingsChanged(JNIEnv* env,
                              const JavaParamRef<jobject>& self) override {
      delegate_->ProxySettingsChanged();
    }

   private:
    const raw_ptr<Delegate> delegate_;
  };

  virtual ~Delegate() = default;

  void ShutdownInJNISequence() {
    if (java_proxy_change_listener_.is_null())
      return;
    JNIEnv* env = AttachCurrentThread();
    Java_ProxyChangeListener_stop(env, java_proxy_change_listener_);
  }

  // Called on the network sequence.
  void SetNewConfigInMainSequence(
      const ProxyConfigWithAnnotation& proxy_config) {
    DCHECK(InMainSequence());
    proxy_config_ = proxy_config;
    for (auto& observer : observers_) {
      observer.OnProxyConfigChanged(proxy_config,
                                    ProxyConfigService::CONFIG_VALID);
    }
  }

  bool InJNISequence() const {
    return jni_task_runner_->RunsTasksInCurrentSequence();
  }

  bool InMainSequence() const {
    return main_task_runner_->RunsTasksInCurrentSequence();
  }

  ScopedJavaGlobalRef<jobject> java_proxy_change_listener_;

  JNIDelegateImpl jni_delegate_;
  base::ObserverList<Observer>::Unchecked observers_;
  scoped_refptr<base::SequencedTaskRunner> main_task_runner_;
  scoped_refptr<base::SequencedTaskRunner> jni_task_runner_;
  GetPropertyCallback get_property_callback_;
  ProxyConfigWithAnnotation proxy_config_;
  bool exclude_pac_url_ = false;
  // This may only be accessed or modified on the JNI thread
  bool has_proxy_override_ = false;
};

ProxyConfigServiceAndroid::ProxyConfigServiceAndroid(
    const scoped_refptr<base::SequencedTaskRunner>& main_task_runner,
    const scoped_refptr<base::SequencedTaskRunner>& jni_task_runner)
    : delegate_(base::MakeRefCounted<Delegate>(
          main_task_runner,
          jni_task_runner,
          base::BindRepeating(&GetJavaProperty))) {
  delegate_->SetupJNI();
  delegate_->FetchInitialConfig();
}

ProxyConfigServiceAndroid::~ProxyConfigServiceAndroid() {
  delegate_->Shutdown();
}

void ProxyConfigServiceAndroid::set_exclude_pac_url(bool enabled) {
  delegate_->set_exclude_pac_url(enabled);
}

void ProxyConfigServiceAndroid::AddObserver(Observer* observer) {
  delegate_->AddObserver(observer);
}

void ProxyConfigServiceAndroid::RemoveObserver(Observer* observer) {
  delegate_->RemoveObserver(observer);
}

ProxyConfigService::ConfigAvailability
ProxyConfigServiceAndroid::GetLatestProxyConfig(
    ProxyConfigWithAnnotation* config) {
  return delegate_->GetLatestProxyConfig(config);
}

ProxyConfigServiceAndroid::ProxyConfigServiceAndroid(
    const scoped_refptr<base::SequencedTaskRunner>& main_task_runner,
    const scoped_refptr<base::SequencedTaskRunner>& jni_task_runner,
    GetPropertyCallback get_property_callback)
    : delegate_(base::MakeRefCounted<Delegate>(main_task_runner,
                                               jni_task_runner,
                                               get_property_callback)) {
  delegate_->SetupJNI();
  delegate_->FetchInitialConfig();
}

void ProxyConfigServiceAndroid::ProxySettingsChangedTo(
    const std::string& host,
    int port,
    const std::string& pac_url,
    const std::vector<std::string>& exclusion_list) {
  delegate_->ProxySettingsChangedTo(host, port, pac_url, exclusion_list);
}

void ProxyConfigServiceAndroid::ProxySettingsChanged() {
  delegate_->ProxySettingsChanged();
}

std::string ProxyConfigServiceAndroid::SetProxyOverride(
    const std::vector<ProxyOverrideRule>& proxy_rules,
    const std::vector<std::string>& bypass_rules,
    const bool reverse_bypass,
    base::OnceClosure callback) {
  return delegate_->SetProxyOverride(proxy_rules, bypass_rules, reverse_bypass,
                                     std::move(callback));
}

void ProxyConfigServiceAndroid::ClearProxyOverride(base::OnceClosure callback) {
  delegate_->ClearProxyOverride(std::move(callback));
}

} // namespace net

"""

```