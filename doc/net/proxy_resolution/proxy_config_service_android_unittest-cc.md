Response:
The user wants to understand the functionality of the C++ file `proxy_config_service_android_unittest.cc` in Chromium's networking stack.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename ends with `_unittest.cc`, which strongly indicates this file contains unit tests. The presence of `#include "testing/gtest/include/gtest/gtest.h"` confirms this. The file tests `net/proxy_resolution/proxy_config_service_android.h`.

2. **Understand the class under test:** The file includes `proxy_config_service_android.h`. The test classes like `ProxyConfigServiceAndroidTest` and `ProxyConfigServiceAndroidWithInitialConfigTest` instantiate `ProxyConfigServiceAndroid`. Therefore, the primary goal of the tests is to verify the behavior of `ProxyConfigServiceAndroid`.

3. **Analyze the test setup:**  The base class `ProxyConfigServiceAndroidTestBase` provides common setup:
    * It initializes a `ProxyConfigServiceAndroid` instance.
    * It uses a `TestObserver` to monitor proxy configuration changes.
    * It provides methods to manipulate the proxy configuration via a `configuration_` map.
    * It includes a `JavaLooperPreparer` to set up the Android Looper, likely because `ProxyConfigServiceAndroid` interacts with Android Java code.

4. **Categorize the test cases:**  Scanning the test functions reveals different aspects of `ProxyConfigServiceAndroid` being tested:
    * **Basic Configuration Changes:** `TestChangePropertiesNotification`, `TestInitialConfig`.
    * **Clearing Proxy Settings:** `TestClearProxy`.
    * **Proxy Overrides:**  A significant portion of the tests (`TestProxyOverrideCallback`, `TestProxyOverrideSchemes`, `TestProxyOverridePorts`, etc.) focuses on the `SetProxyOverride` and `ClearProxyOverride` methods. These tests verify how the service handles explicitly defined proxy rules that can override the system-level proxy settings.
    * **Interaction of Overrides and System Settings:** Tests like `TestOverrideAndProxy`, `TestProxyAndOverride` check how overrides interact with the regular proxy settings.
    * **Bypass Rules:**  Tests involving `TestOverrideBypassRules` and `TestReverseBypass` examine how the service handles specifying hosts or patterns that should *not* use the proxy.
    * **Direct Connection Overrides:**  `TestOverrideToDirect` verifies overriding to explicitly use no proxy.
    * **System Property Mapping:** The tests with names like `NoProxy`, `HttpProxyHostAndPort`, `HttpNonProxyHosts1`, etc., directly test how Android system properties (like `http.proxyHost`, `http.nonProxyHosts`) are translated into proxy configurations. These are crucial for how Android's proxy settings are applied within Chromium.

5. **Identify potential relationships with JavaScript:** The file name contains "android," and proxy settings are often relevant in web contexts. While this specific C++ code doesn't *directly* execute JavaScript, it's responsible for configuring how network requests are made. JavaScript code running in a web page within the Chromium browser will be affected by these proxy settings. Examples include how `fetch()` or `XMLHttpRequest` will route requests.

6. **Consider logical reasoning and input/output:** Many tests demonstrate clear input/output relationships. For example, setting specific properties and then calling `TestMapping` to check the resulting proxy configuration for a given URL.

7. **Think about user/programming errors:**  The tests implicitly highlight potential errors:
    * **Incorrect Property Names:**  Typos in property names like `http.proxyHost` would lead to the proxy not being applied.
    * **Invalid Port Numbers:** The `HttpProxyHostAndInvalidPort` test explicitly checks this.
    * **Conflicting Configurations:** While not explicitly tested for conflicts *within* the Android settings in this file, the override tests demonstrate how explicit rules can take precedence. A user might be confused by conflicting system settings and overrides.

8. **Trace user operations to this code:** To reach this code, a user would typically configure proxy settings on their Android device. This triggers Android system services that eventually propagate these settings to Chromium via JNI (Java Native Interface), which is hinted at by the inclusion of the JNI header.

9. **Structure the response:** Organize the findings into the requested categories: functionality, relationship with JavaScript, logical reasoning (input/output), user/programming errors, and user path. Use clear and concise language.
这个文件 `net/proxy_resolution/proxy_config_service_android_unittest.cc` 是 Chromium 网络栈中 `ProxyConfigServiceAndroid` 类的单元测试文件。它的主要功能是测试 `ProxyConfigServiceAndroid` 类的各种行为和功能是否符合预期。

以下是该文件的详细功能列表：

**核心功能：测试 `ProxyConfigServiceAndroid` 类**

* **初始化和配置加载:**
    * 测试从 Android 系统属性中加载初始代理配置，例如 `http.proxyHost` 和 `http.proxyPort`。 (`TestInitialConfig`)
    * 测试当 Android 系统属性发生变化时，`ProxyConfigServiceAndroid` 能否正确接收并更新代理配置。 (`TestChangePropertiesNotification`)
* **直接连接配置:**
    * 测试在没有配置代理的情况下，连接是否为直接连接。 (`NoProxy`)
    * 测试通过特定方法 (`ProxySettingsChangedTo("", 0, "", {})`) 清除代理设置，使其变为直接连接。 (`TestClearProxy`)
* **HTTP 代理配置:**
    * 测试 `http.proxyHost` 和 `http.proxyPort` 属性的解析和应用。 (`HttpProxyHostAndPort`, `HttpProxyHostOnly`, `HttpProxyPortOnly`)
    * 测试 `http.nonProxyHosts` 属性的解析和应用，以指定不使用代理的主机。 (`HttpNonProxyHosts1`, `HttpNonProxyHosts2`, `HttpNonProxyHosts3`)
* **FTP 代理配置:**
    * 测试 `ftp.proxyHost` 和 `ftp.proxyPort` 属性的解析和应用。 (`FtpProxyHostAndPort`, `FtpProxyHostOnly`)
    * 测试 `ftp.nonProxyHosts` 属性的解析和应用。 (`FtpNonProxyHosts`)
* **HTTPS 代理配置:**
    * 测试 `https.proxyHost` 和 `https.proxyPort` 属性的解析和应用。 (`HttpsProxyHostAndPort`, `HttpsProxyHostOnly`)
* **SOCKS 代理配置:**
    * 测试 `socksProxyHost` 和 `socksProxyPort` 属性的解析和应用。 (`FallbackToSocks`, `SocksExplicitPort`)
    * 测试当同时存在 HTTP 代理和 SOCKS 代理配置时，HTTP 代理优先。 (`HttpProxySupercedesSocks`)
* **默认代理配置:**
    * 测试 `proxyHost` 和 `proxyPort` 属性作为默认代理的解析和应用。 (`DefaultProxyExplictPort`, `DefaultProxyDefaultPort`)
* **代理覆盖 (Overrides):**
    * 测试通过 `SetProxyOverride` 方法设置临时的、优先级更高的代理规则。
    * 测试可以根据 scheme (http, https, ftp, *) 和主机/端口来设置覆盖规则。 (`TestProxyOverrideSchemes`, `TestProxyOverridePorts`)
    * 测试可以设置多个覆盖规则，并按照顺序应用。 (`TestProxyOverrideMultipleRules`, `TestProxyOverrideListOfRules`)
    * 测试代理覆盖规则与 Android 系统属性配置的交互，例如覆盖会覆盖系统属性的设置。 (`TestOverrideAndProxy`, `TestProxyAndOverride`, `TestOverrideThenProxy`)
    * 测试清除代理覆盖规则的功能。 (`TestClearOverride`, `TestProxyAndClearOverride`)
    * 测试代理覆盖规则中的 bypass 规则，以指定某些主机不使用覆盖的代理。 (`TestOverrideBypassRules`)
    * 测试将覆盖规则设置为直接连接。 (`TestOverrideToDirect`)
    * 测试反向 bypass 规则，即只对 bypass 列表中的 URL 应用代理覆盖规则。 (`TestReverseBypass`)
    * 测试 `SetProxyOverride` 和 `ClearProxyOverride` 的回调函数是否正常工作。 (`TestProxyOverrideCallback`)
* **IPv6 地址支持:**
    * 测试代理服务器地址支持 IPv6 格式。 (`HttpProxyHostIPv6`, `HttpProxyHostAndPortIPv6`)
* **错误处理:**
    * 测试当 `http.proxyPort` 属性设置为无效端口时，程序不会崩溃。 (`HttpProxyHostAndInvalidPort`)

**与 JavaScript 的关系：**

`ProxyConfigServiceAndroid` 本身是用 C++ 实现的，并不直接运行 JavaScript 代码。但是，它负责管理浏览器的代理设置。当在 Chromium 内核中运行的 JavaScript 代码发起网络请求时（例如通过 `fetch()` 或 `XMLHttpRequest`），网络栈会使用 `ProxyConfigServiceAndroid` 提供的代理配置来决定如何路由这些请求。

**举例说明：**

假设在 Android 设备的系统设置中配置了 HTTP 代理 `proxy.example.com:8080`。当运行在 Chromium 中的 JavaScript 代码执行以下操作时：

```javascript
fetch('http://www.example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. `ProxyConfigServiceAndroid` 会从 Android 系统属性中读取到 `http.proxyHost = proxy.example.com` 和 `http.proxyPort = 8080`。
2. 当 JavaScript 发起 `fetch` 请求时，网络栈会查询 `ProxyConfigServiceAndroid` 获取代理配置。
3. `ProxyConfigServiceAndroid` 返回配置信息，指示对于 `http://www.example.com/data.json` 这个 URL，应该使用代理 `proxy.example.com:8080`。
4. 网络栈会将请求发送到 `proxy.example.com:8080` 代理服务器，而不是直接连接 `www.example.com`。

**逻辑推理、假设输入与输出：**

以下举例说明一个测试用例的逻辑推理：

**测试用例:** `TEST_F(ProxyConfigServiceAndroidTest, HttpProxyHostAndPort)`

**假设输入:**

*   Android 系统属性中设置了 `http.proxyHost = httpproxy.com`
*   Android 系统属性中设置了 `http.proxyPort = 8080`

**执行步骤:**

1. 调用 `AddProperty("http.proxyHost", "httpproxy.com");` 设置模拟的系统属性。
2. 调用 `AddProperty("http.proxyPort", "8080");` 设置模拟的系统属性。
3. 调用 `ProxySettingsChanged();` 模拟系统代理设置发生变化。
4. 调用 `TestMapping("ftp://example.com/", "DIRECT");` 检查访问 FTP 站点是否为直接连接。
5. 调用 `TestMapping("http://example.com/", "PROXY httpproxy.com:8080");` 检查访问 HTTP 站点是否使用了配置的代理。
6. 调用 `TestMapping("https://example.com/", "DIRECT");` 检查访问 HTTPS 站点是否为直接连接（默认 HTTP 代理不适用于 HTTPS）。

**预期输出:**

*   访问 `ftp://example.com/` 时，代理配置应为 `DIRECT`。
*   访问 `http://example.com/` 时，代理配置应为 `PROXY httpproxy.com:8080`。
*   访问 `https://example.com/` 时，代理配置应为 `DIRECT`。

**涉及用户或编程常见的使用错误：**

*   **错误的属性名称:** 用户或开发者可能会错误地使用代理相关的系统属性名称，例如将 `http.proxyHost` 拼写为 `http.proxyhost`，导致代理设置不生效。
*   **无效的端口号:**  配置代理时，可能会输入无效的端口号（超出 0-65535 的范围），如测试用例 `HttpProxyHostAndInvalidPort` 所示。
*   **代理服务器地址错误:**  代理服务器的域名或 IP 地址可能输入错误，导致连接失败。
*   **Bypass 规则配置错误:**  配置 `http.nonProxyHosts` 时，使用了错误的语法或模式，导致某些主机本应走代理却走了直连，或者反之。
*   **覆盖规则冲突:**  在使用 `SetProxyOverride` 设置覆盖规则时，可能会设置相互冲突的规则，导致行为不符合预期。
*   **忘记清除覆盖规则:**  在某些场景下设置了临时的覆盖规则后，如果忘记清除，可能会影响后续的网络请求。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在 Android 设备上配置代理设置：** 用户通过设备的设置界面，例如 "WLAN" -> 长按已连接的 Wi-Fi -> "修改网络" -> "高级选项" -> "代理"，手动配置 HTTP、HTTPS 或 SOCKS 代理服务器的地址和端口，或者配置 PAC 文件的 URL。
2. **Android 系统服务接收代理配置：** Android 系统会将用户配置的代理信息保存在系统设置中。相关的系统服务（例如 ConnectivityService）会监听这些设置的变更。
3. **Chromium 初始化时读取代理配置：** 当 Chromium 浏览器启动或网络状态发生变化时，`ProxyConfigServiceAndroid` 会通过 JNI 调用 Android 平台的 API (例如 `android.net.Proxy`) 来获取当前的系统代理配置。
4. **系统属性传递给 `ProxyConfigServiceAndroid`：**  Android 系统通常会将代理配置信息以系统属性的形式暴露出来，例如 `http.proxyHost`, `http.proxyPort`, `http.nonProxyHosts` 等。`ProxyConfigServiceAndroid` 会读取这些属性。
5. **`ProxyConfigServiceAndroid` 解析并应用配置：** `ProxyConfigServiceAndroid` 会解析这些系统属性，构建内部的代理配置对象，并将其应用到网络栈中，影响后续的网络请求路由。
6. **JavaScript 发起网络请求：** 当网页中的 JavaScript 代码发起网络请求时，网络栈会查询 `ProxyConfigServiceAndroid` 获取当前的代理配置。
7. **调试线索：** 如果用户发现网页无法访问或使用了错误的代理，开发者或调试人员可以检查以下内容：
    *   **Android 设备的代理设置是否正确。**
    *   **Chromium 是否成功读取了 Android 的代理配置。** 可以通过 chrome://net-internals/#proxy 查看 Chromium 当前使用的代理设置。
    *   **是否存在通过 `SetProxyOverride` 设置的覆盖规则，影响了当前的请求。**
    *   **`ProxyConfigServiceAndroid` 的单元测试可以帮助开发者验证其代理配置解析和应用逻辑的正确性。** 通过运行这些单元测试，可以排查 `ProxyConfigServiceAndroid` 本身是否存在 bug。

总而言之，`net/proxy_resolution/proxy_config_service_android_unittest.cc` 文件通过一系列单元测试，确保 `ProxyConfigServiceAndroid` 能够正确地从 Android 系统中读取和应用代理配置，以及处理临时的代理覆盖规则，保证了 Chromium 在 Android 平台上的网络请求能够按照用户或应用的配置进行路由。

### 提示词
```
这是目录为net/proxy_resolution/proxy_config_service_android_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy_resolution/proxy_config_service_android.h"

#include <map>
#include <memory>
#include <string>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gtest/include/gtest/gtest.h"

// Must come after all headers that specialize FromJniType() / ToJniType().
#include "net/android/net_tests_jni/AndroidProxyConfigServiceTestUtil_jni.h"

namespace net {

namespace {

class TestObserver : public ProxyConfigService::Observer {
 public:
  TestObserver() : availability_(ProxyConfigService::CONFIG_UNSET) {}

  // ProxyConfigService::Observer:
  void OnProxyConfigChanged(
      const ProxyConfigWithAnnotation& config,
      ProxyConfigService::ConfigAvailability availability) override {
    config_ = config;
    availability_ = availability;
  }

  ProxyConfigService::ConfigAvailability availability() const {
    return availability_;
  }

  const ProxyConfigWithAnnotation& config() const { return config_; }

 private:
  ProxyConfigWithAnnotation config_;
  ProxyConfigService::ConfigAvailability availability_;
};

// Helper class that simply prepares Java's Looper on construction.
class JavaLooperPreparer {
 public:
  JavaLooperPreparer() {
    Java_AndroidProxyConfigServiceTestUtil_prepareLooper(
        base::android::AttachCurrentThread());
  }
};

}  // namespace

typedef std::map<std::string, std::string> StringMap;

class ProxyConfigServiceAndroidTestBase : public TestWithTaskEnvironment {
 protected:
  // Note that the current thread's message loop is initialized by the test
  // suite (see net/test/net_test_suite.cc).
  explicit ProxyConfigServiceAndroidTestBase(
      const StringMap& initial_configuration)
      : configuration_(initial_configuration),
        service_(
            base::SingleThreadTaskRunner::GetCurrentDefault(),
            base::SingleThreadTaskRunner::GetCurrentDefault(),
            base::BindRepeating(&ProxyConfigServiceAndroidTestBase::GetProperty,
                                base::Unretained(this))) {}

  ~ProxyConfigServiceAndroidTestBase() override = default;

  // testing::Test:
  void SetUp() override {
    base::RunLoop().RunUntilIdle();
    service_.AddObserver(&observer_);
  }

  void TearDown() override { service_.RemoveObserver(&observer_); }

  void ClearConfiguration() {
    configuration_.clear();
  }

  void AddProperty(const std::string& key, const std::string& value) {
    configuration_[key] = value;
  }

  std::string GetProperty(const std::string& key) {
    StringMap::const_iterator it = configuration_.find(key);
    if (it == configuration_.end())
      return std::string();
    return it->second;
  }

  void ProxySettingsChangedTo(const std::string& host,
                              int port,
                              const std::string& pac_url,
                              const std::vector<std::string>& exclusion_list) {
    service_.ProxySettingsChangedTo(host, port, pac_url, exclusion_list);
    base::RunLoop().RunUntilIdle();
  }

  void ProxySettingsChanged() {
    service_.ProxySettingsChanged();
    base::RunLoop().RunUntilIdle();
  }

  void TestMapping(const std::string& url, const std::string& expected) {
    ProxyConfigService::ConfigAvailability availability;
    ProxyConfigWithAnnotation proxy_config;
    availability = service_.GetLatestProxyConfig(&proxy_config);
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID, availability);
    ProxyInfo proxy_info;
    proxy_config.value().proxy_rules().Apply(GURL(url), &proxy_info);
    EXPECT_EQ(expected, proxy_info.ToDebugString());
  }

  void SetProxyOverride(
      const ProxyConfigServiceAndroid::ProxyOverrideRule& rule,
      const std::vector<std::string>& bypass_rules,
      const bool reverse_bypass,
      base::OnceClosure callback) {
    std::vector<ProxyConfigServiceAndroid::ProxyOverrideRule> rules;
    rules.push_back(rule);
    SetProxyOverride(rules, bypass_rules, reverse_bypass, std::move(callback));
  }

  void SetProxyOverride(
      const std::vector<ProxyConfigServiceAndroid::ProxyOverrideRule>& rules,
      const std::vector<std::string>& bypass_rules,
      const bool reverse_bypass,
      base::OnceClosure callback) {
    service_.SetProxyOverride(rules, bypass_rules, reverse_bypass,
                              std::move(callback));
    base::RunLoop().RunUntilIdle();
  }

  void ClearProxyOverride(base::OnceClosure callback) {
    service_.ClearProxyOverride(std::move(callback));
    base::RunLoop().RunUntilIdle();
  }

  StringMap configuration_;
  TestObserver observer_;
  // |java_looper_preparer_| appears before |service_| so that Java's Looper is
  // prepared before constructing |service_| as it creates a ProxyChangeListener
  // which requires a Looper.
  JavaLooperPreparer java_looper_preparer_;
  ProxyConfigServiceAndroid service_;
};

class ProxyConfigServiceAndroidTest : public ProxyConfigServiceAndroidTestBase {
 public:
  ProxyConfigServiceAndroidTest()
      : ProxyConfigServiceAndroidTestBase(StringMap()) {}
};

class ProxyConfigServiceAndroidWithInitialConfigTest
    : public ProxyConfigServiceAndroidTestBase {
 public:
  ProxyConfigServiceAndroidWithInitialConfigTest()
      : ProxyConfigServiceAndroidTestBase(MakeInitialConfiguration()) {}

 private:
  StringMap MakeInitialConfiguration() {
    StringMap initial_configuration;
    initial_configuration["http.proxyHost"] = "httpproxy.com";
    initial_configuration["http.proxyPort"] = "8080";
    return initial_configuration;
  }
};

TEST_F(ProxyConfigServiceAndroidTest, TestChangePropertiesNotification) {
  // Set up a non-empty configuration
  AddProperty("http.proxyHost", "localhost");
  ProxySettingsChanged();
  EXPECT_EQ(ProxyConfigService::CONFIG_VALID, observer_.availability());
  EXPECT_FALSE(observer_.config().value().proxy_rules().empty());

  // Set up an empty configuration
  ClearConfiguration();
  ProxySettingsChanged();
  EXPECT_EQ(ProxyConfigService::CONFIG_VALID, observer_.availability());
  EXPECT_TRUE(observer_.config().value().proxy_rules().empty());
}

TEST_F(ProxyConfigServiceAndroidWithInitialConfigTest, TestInitialConfig) {
  // Make sure that the initial config is set.
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "PROXY httpproxy.com:8080");

  // Override the initial configuration.
  ClearConfiguration();
  AddProperty("http.proxyHost", "httpproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpproxy.com:80");
}

TEST_F(ProxyConfigServiceAndroidTest, TestClearProxy) {
  AddProperty("http.proxyHost", "httpproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpproxy.com:80");

  // These values are used in ProxyChangeListener.java to indicate a direct
  // proxy connection.
  ProxySettingsChangedTo("", 0, "", {});
  TestMapping("http://example.com/", "DIRECT");
}

struct ProxyCallback {
  ProxyCallback()
      : callback(base::BindOnce(&ProxyCallback::Call, base::Unretained(this))) {
  }

  void Call() { called = true; }

  bool called = false;
  base::OnceClosure callback;
};

TEST_F(ProxyConfigServiceAndroidTest, TestProxyOverrideCallback) {
  ProxyCallback proxyCallback;
  ASSERT_FALSE(proxyCallback.called);
  ClearProxyOverride(std::move(proxyCallback.callback));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(proxyCallback.called);
}

TEST_F(ProxyConfigServiceAndroidTest, TestProxyOverrideSchemes) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the default proxy
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "DIRECT");
  TestMapping("ftp://example.com/", "DIRECT");

  SetProxyOverride({"*", "httpoverrideproxy.com:200"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:200");
  TestMapping("https://example.com/", "PROXY httpoverrideproxy.com:200");
  TestMapping("ftp://example.com/", "PROXY httpoverrideproxy.com:200");

  // Check that webview uses the custom proxy only for https
  SetProxyOverride({"https", "httpoverrideproxy.com:200"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "PROXY httpoverrideproxy.com:200");
  TestMapping("ftp://example.com/", "DIRECT");

  // Check that webview uses the default proxy
  ClearProxyOverride(base::DoNothing());
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "DIRECT");
  TestMapping("ftp://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, TestProxyOverridePorts) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the default proxy
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "DIRECT");
  TestMapping("ftp://example.com/", "DIRECT");

  // Check that webview uses port 80 for http proxies
  SetProxyOverride({"*", "httpoverrideproxy.com"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://example.com:444", "PROXY httpoverrideproxy.com:80");
  TestMapping("https://example.com:2222", "PROXY httpoverrideproxy.com:80");
  TestMapping("ftp://example.com:15", "PROXY httpoverrideproxy.com:80");

  // Check that webview uses port 443 for https proxies
  SetProxyOverride({"*", "https://httpoverrideproxy.com"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://example.com:8080", "HTTPS httpoverrideproxy.com:443");
  TestMapping("https://example.com:1111", "HTTPS httpoverrideproxy.com:443");
  TestMapping("ftp://example.com:752", "HTTPS httpoverrideproxy.com:443");

  // Check that webview uses custom port
  SetProxyOverride({"*", "https://httpoverrideproxy.com:777"}, bypass_rules,
                   false, base::DoNothing());
  TestMapping("http://example.com:8080", "HTTPS httpoverrideproxy.com:777");
  TestMapping("https://example.com:1111", "HTTPS httpoverrideproxy.com:777");
  TestMapping("ftp://example.com:752", "HTTPS httpoverrideproxy.com:777");

  ClearProxyOverride(base::DoNothing());
}

TEST_F(ProxyConfigServiceAndroidTest, TestProxyOverrideMultipleRules) {
  std::vector<std::string> bypass_rules;

  // Multiple rules with schemes are valid
  std::vector<ProxyConfigServiceAndroid::ProxyOverrideRule> rules;
  rules.emplace_back("http", "httpoverrideproxy.com");
  rules.emplace_back("https", "https://httpoverrideproxy.com");
  SetProxyOverride(rules, bypass_rules, false, base::DoNothing());
  TestMapping("https://example.com/", "HTTPS httpoverrideproxy.com:443");
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:80");

  // Rules with and without scheme can be combined
  rules.clear();
  rules.emplace_back("http", "overrideproxy1.com");
  rules.emplace_back("*", "overrideproxy2.com");
  SetProxyOverride(rules, bypass_rules, false, base::DoNothing());
  TestMapping("https://example.com/", "PROXY overrideproxy2.com:80");
  TestMapping("http://example.com/", "PROXY overrideproxy1.com:80");

  ClearProxyOverride(base::DoNothing());
}

TEST_F(ProxyConfigServiceAndroidTest, TestProxyOverrideListOfRules) {
  std::vector<std::string> bypass_rules;

  std::vector<ProxyConfigServiceAndroid::ProxyOverrideRule> rules;
  rules.emplace_back("http", "httpproxy1");
  rules.emplace_back("*", "socks5://fallback1");
  rules.emplace_back("http", "httpproxy2");
  rules.emplace_back("*", "fallback2");
  rules.emplace_back("*", "direct://");
  SetProxyOverride(rules, bypass_rules, false, base::DoNothing());

  TestMapping("http://example.com", "PROXY httpproxy1:80;PROXY httpproxy2:80");
  TestMapping("https://example.com",
              "SOCKS5 fallback1:1080;PROXY fallback2:80;DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, TestOverrideAndProxy) {
  std::vector<std::string> bypass_rules;
  bypass_rules.push_back("www.excluded.com");

  // Check that webview uses the default proxy
  TestMapping("http://example.com/", "DIRECT");

  // Check that webview uses the custom proxy
  SetProxyOverride({"*", "httpoverrideproxy.com:200"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:200");

  // Check that webview continues to use the custom proxy
  AddProperty("http.proxyHost", "httpsomeproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:200");
  TestMapping("http://www.excluded.com/", "DIRECT");

  // Check that webview uses the non default proxy
  ClearProxyOverride(base::DoNothing());
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");
}

TEST_F(ProxyConfigServiceAndroidTest, TestProxyAndOverride) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the default proxy
  TestMapping("http://example.com/", "DIRECT");

  // Check that webview uses the non default proxy
  AddProperty("http.proxyHost", "httpsomeproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");

  // Check that webview uses the custom proxy
  SetProxyOverride({"*", "httpoverrideproxy.com:200"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:200");

  // Check that webview uses the non default proxy
  ClearProxyOverride(base::DoNothing());
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");
}

TEST_F(ProxyConfigServiceAndroidTest, TestOverrideThenProxy) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the default proxy
  TestMapping("http://example.com/", "DIRECT");

  // Check that webview uses the custom proxy
  SetProxyOverride({"*", "httpoverrideproxy.com:200"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:200");

  // Check that webview uses the default proxy
  ClearProxyOverride(base::DoNothing());
  TestMapping("http://example.com/", "DIRECT");

  // Check that webview uses the non default proxy
  AddProperty("http.proxyHost", "httpsomeproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");
}

TEST_F(ProxyConfigServiceAndroidTest, TestClearOverride) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the default proxy
  TestMapping("http://example.com/", "DIRECT");

  // Check that webview uses the default proxy
  ClearProxyOverride(base::DoNothing());
  TestMapping("http://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, TestProxyAndClearOverride) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the non default proxy
  AddProperty("http.proxyHost", "httpsomeproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");

  // Check that webview uses the non default proxy
  ClearProxyOverride(base::DoNothing());
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");
}

TEST_F(ProxyConfigServiceAndroidTest, TestOverrideBypassRules) {
  std::vector<std::string> bypass_rules;
  bypass_rules.push_back("excluded.com");

  // Check that webview uses the default proxy
  TestMapping("http://excluded.com/", "DIRECT");
  TestMapping("http://example.com/", "DIRECT");

  // Check that webview handles the bypass rules correctly
  SetProxyOverride({"*", "httpoverrideproxy.com:200"}, bypass_rules, false,
                   base::DoNothing());
  TestMapping("http://excluded.com/", "DIRECT");
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:200");

  // Check that webview uses the default proxy
  ClearProxyOverride(base::DoNothing());
  TestMapping("http://excluded.com/", "DIRECT");
  TestMapping("http://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, TestOverrideToDirect) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the non default proxy
  AddProperty("http.proxyHost", "httpsomeproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");

  // Check that webview uses no proxy
  TestMapping("http://example.com/", "PROXY httpsomeproxy.com:80");
  SetProxyOverride({"*", "direct://"}, bypass_rules, false, base::DoNothing());
  TestMapping("http://example.com/", "DIRECT");

  ClearProxyOverride(base::DoNothing());
}

TEST_F(ProxyConfigServiceAndroidTest, TestReverseBypass) {
  std::vector<std::string> bypass_rules;

  // Check that webview uses the default proxy
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("http://other.com/", "DIRECT");

  // Use a reverse bypass list, that is, WebView will only apply the proxy
  // settings to URLs in the bypass list
  bypass_rules.push_back("http://example.com");
  SetProxyOverride({"*", "httpoverrideproxy.com:200"}, bypass_rules, true,
                   base::DoNothing());

  // Check that URLs in the bypass list use the proxy
  TestMapping("http://example.com/", "PROXY httpoverrideproxy.com:200");
  TestMapping("http://other.com/", "DIRECT");
}

// !! The following test cases are automatically generated from
// !! net/android/tools/proxy_test_cases.py.
// !! Please edit that file instead of editing the test cases below and
// !! update also the corresponding Java unit tests in
// !! AndroidProxySelectorTest.java

TEST_F(ProxyConfigServiceAndroidTest, NoProxy) {
  // Test direct mapping when no proxy defined.
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpProxyHostAndPort) {
  // Test http.proxyHost and http.proxyPort works.
  AddProperty("http.proxyHost", "httpproxy.com");
  AddProperty("http.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "PROXY httpproxy.com:8080");
  TestMapping("https://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpProxyHostOnly) {
  // We should get the default port (80) for proxied hosts.
  AddProperty("http.proxyHost", "httpproxy.com");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "PROXY httpproxy.com:80");
  TestMapping("https://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpProxyPortOnly) {
  // http.proxyPort only should not result in any hosts being proxied.
  AddProperty("http.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpNonProxyHosts1) {
  // Test that HTTP non proxy hosts are mapped correctly
  AddProperty("http.nonProxyHosts", "slashdot.org");
  AddProperty("http.proxyHost", "httpproxy.com");
  AddProperty("http.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpproxy.com:8080");
  TestMapping("http://slashdot.org/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpNonProxyHosts2) {
  // Test that | pattern works.
  AddProperty("http.nonProxyHosts", "slashdot.org|freecode.net");
  AddProperty("http.proxyHost", "httpproxy.com");
  AddProperty("http.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY httpproxy.com:8080");
  TestMapping("http://freecode.net/", "DIRECT");
  TestMapping("http://slashdot.org/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpNonProxyHosts3) {
  // Test that * pattern works.
  AddProperty("http.nonProxyHosts", "*example.com");
  AddProperty("http.proxyHost", "httpproxy.com");
  AddProperty("http.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("http://slashdot.org/", "PROXY httpproxy.com:8080");
  TestMapping("http://www.example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, FtpNonProxyHosts) {
  // Test that FTP non proxy hosts are mapped correctly
  AddProperty("ftp.nonProxyHosts", "slashdot.org");
  AddProperty("ftp.proxyHost", "httpproxy.com");
  AddProperty("ftp.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "PROXY httpproxy.com:8080");
  TestMapping("http://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, FtpProxyHostAndPort) {
  // Test ftp.proxyHost and ftp.proxyPort works.
  AddProperty("ftp.proxyHost", "httpproxy.com");
  AddProperty("ftp.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "PROXY httpproxy.com:8080");
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, FtpProxyHostOnly) {
  // Test ftp.proxyHost and default port.
  AddProperty("ftp.proxyHost", "httpproxy.com");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "PROXY httpproxy.com:80");
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpsProxyHostAndPort) {
  // Test https.proxyHost and https.proxyPort works.
  AddProperty("https.proxyHost", "httpproxy.com");
  AddProperty("https.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "PROXY httpproxy.com:8080");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpsProxyHostOnly) {
  // Test https.proxyHost and default port.
  AddProperty("https.proxyHost", "httpproxy.com");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "DIRECT");
  TestMapping("https://example.com/", "PROXY httpproxy.com:80");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpProxyHostIPv6) {
  // Test IPv6 https.proxyHost and default port.
  AddProperty("http.proxyHost", "a:b:c::d:1");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "PROXY [a:b:c::d:1]:80");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpProxyHostAndPortIPv6) {
  // Test IPv6 http.proxyHost and http.proxyPort works.
  AddProperty("http.proxyHost", "a:b:c::d:1");
  AddProperty("http.proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "PROXY [a:b:c::d:1]:8080");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpProxyHostAndInvalidPort) {
  // Test invalid http.proxyPort does not crash.
  AddProperty("http.proxyHost", "a:b:c::d:1");
  AddProperty("http.proxyPort", "65536");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "DIRECT");
  TestMapping("http://example.com/", "DIRECT");
}

TEST_F(ProxyConfigServiceAndroidTest, DefaultProxyExplictPort) {
  // Default http proxy is used if a scheme-specific one is not found.
  AddProperty("ftp.proxyHost", "httpproxy.com");
  AddProperty("ftp.proxyPort", "8080");
  AddProperty("proxyHost", "defaultproxy.com");
  AddProperty("proxyPort", "8080");
  ProxySettingsChanged();
  TestMapping("ftp://example.com/", "PROXY httpproxy.com:8080");
  TestMapping("http://example.com/", "PROXY defaultproxy.com:8080");
  TestMapping("https://example.com/", "PROXY defaultproxy.com:8080");
}

TEST_F(ProxyConfigServiceAndroidTest, DefaultProxyDefaultPort) {
  // Check that the default proxy port is as expected.
  AddProperty("proxyHost", "defaultproxy.com");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY defaultproxy.com:80");
  TestMapping("https://example.com/", "PROXY defaultproxy.com:80");
}

TEST_F(ProxyConfigServiceAndroidTest, FallbackToSocks) {
  // SOCKS proxy is used if scheme-specific one is not found.
  AddProperty("http.proxyHost", "defaultproxy.com");
  AddProperty("socksProxyHost", "socksproxy.com");
  ProxySettingsChanged();
  TestMapping("ftp://example.com", "SOCKS5 socksproxy.com:1080");
  TestMapping("http://example.com/", "PROXY defaultproxy.com:80");
  TestMapping("https://example.com/", "SOCKS5 socksproxy.com:1080");
}

TEST_F(ProxyConfigServiceAndroidTest, SocksExplicitPort) {
  // SOCKS proxy port is used if specified
  AddProperty("socksProxyHost", "socksproxy.com");
  AddProperty("socksProxyPort", "9000");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "SOCKS5 socksproxy.com:9000");
}

TEST_F(ProxyConfigServiceAndroidTest, HttpProxySupercedesSocks) {
  // SOCKS proxy is ignored if default HTTP proxy defined.
  AddProperty("proxyHost", "defaultproxy.com");
  AddProperty("socksProxyHost", "socksproxy.com");
  AddProperty("socksProxyPort", "9000");
  ProxySettingsChanged();
  TestMapping("http://example.com/", "PROXY defaultproxy.com:80");
}

}  // namespace net
```