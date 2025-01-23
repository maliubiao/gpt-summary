Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Functionality:** The file name `proxy_config_unittest.cc` immediately suggests that it's testing the `ProxyConfig` class. The `#include "net/proxy_resolution/proxy_config.h"` confirms this. Unit tests generally verify the behavior of a specific unit of code (in this case, the `ProxyConfig` class).

2. **Examine Included Headers:**  The included headers provide clues about what aspects of `ProxyConfig` are being tested:
    * `base/json/json_writer.h`:  Indicates testing the serialization/deserialization of `ProxyConfig` to JSON.
    * `base/test/gtest_util.h`, `testing/gtest/include/gtest/gtest.h`:  Confirms this is a unit test using the Google Test framework.
    * `base/values.h`:  Suggests `ProxyConfig` might interact with `base::Value`, a generic data structure in Chromium.
    * `build/buildflag.h`, `net/net_buildflags.h`: Implies conditional compilation and testing of features based on build flags (like `ENABLE_BRACKETED_PROXY_URIS` and `ENABLE_QUIC_PROXY_SUPPORT`).
    * `net/base/proxy_string_util.h`: Hints at parsing and manipulation of proxy strings.
    * `net/proxy_resolution/proxy_config_service_common_unittest.h`:  This might contain common test utilities or fixtures related to proxy configuration.
    * `net/proxy_resolution/proxy_info.h`:  Shows `ProxyConfig`'s interaction with `ProxyInfo`, a class likely holding the resolved proxy information.

3. **Analyze the Test Structure:** Look for `TEST()` and `TEST_F()` macros. These define individual test cases. `TEST_F()` indicates the use of a test fixture (`ProxyConfigWebSocketTest`).

4. **Categorize the Test Cases:** Group the tests by the feature they are testing. Initial scan reveals tests for:
    * Equality (`Equals`)
    * Serialization to JSON (`ToValueJSON`)
    * Parsing proxy rules from strings (`ParseProxyRules`)
    * Handling of QUIC proxies (conditional on build flags)
    * Handling of multi-proxy chains (conditional on build flags)
    * Setting the "bypass proxy" flag
    * WebSocket proxy selection (using the `ProxyConfigWebSocketTest` fixture)

5. **Examine Individual Test Cases:** For each test case, understand its purpose:
    * **`Equals`**: Tests the `Equals()` method for different configurations of `ProxyConfig` (auto-detect, PAC URL, proxy rules, bypass rules, reverse bypass).
    * **`ToValueJSON`**:  Verifies that different `ProxyConfig` objects can be correctly serialized to JSON strings. This involves setting up various `ProxyConfig` states and comparing the output with expected JSON.
    * **`ParseProxyRules`**:  Focuses on testing the `ParseFromString()` method of `ProxyConfig::ProxyRules`. It checks how different proxy rule strings are parsed into the internal representation. It covers single proxies, proxy-per-scheme, direct connections, and the interaction of scheme-specific and general proxies.
    * **Conditional Tests (QUIC, Multi-Proxy):** These test features that are enabled or disabled based on compile-time flags. They are crucial for verifying that the code behaves correctly in different build configurations.
    * **`ProxyRulesSetBypassFlag`**:  Specifically checks if the `did_bypass_proxy()` flag in `ProxyInfo` is correctly set when bypass rules are applied.
    * **`ProxyConfigWebSocketTest`**:  Dedicated to testing how `ProxyConfig` interacts with WebSocket URLs (ws:// and wss://). It covers preference for SOCKS proxies, HTTPS proxies over HTTP, fallback proxies, and the application of bypass rules.

6. **Look for Potential JavaScript Relevance:**  Consider how proxy settings are often configured in web browsers. JavaScript is a common language for web UI and browser extensions. The `ToValueJSON` tests immediately suggest a connection:  JSON is a standard data format for communication between JavaScript and backend systems. Proxy settings configured in a browser (potentially by JavaScript) might be serialized into a JSON format similar to what these tests are verifying.

7. **Identify Logic and Assumptions:**  For tests like `Equals` and `ParseProxyRules`, note the underlying assumptions and logic:
    * `Equals`:  The tests systematically check equality based on individual members of the `ProxyConfig` class.
    * `ParseProxyRules`:  The tests rely on a defined syntax for proxy rule strings. The code needs to correctly interpret this syntax to populate the `ProxyConfig::ProxyRules` structure.

8. **Consider User Errors and Debugging:** Think about common mistakes users or programmers might make when dealing with proxy configurations:
    * Incorrect proxy syntax in strings.
    * Misunderstanding the precedence of different proxy rules.
    * Issues with bypass rules (e.g., not matching the intended URLs).
    * Forgetting to handle WebSocket-specific proxy requirements.
    * Not accounting for build flag dependencies.

9. **Trace User Actions (Debugging):**  Imagine how a user might arrive at a point where these configurations are relevant:
    * Manually configuring proxy settings in the browser's settings UI.
    * Using a PAC script.
    * A browser extension setting proxy configurations.
    * Command-line flags passed to the browser.
    * Group policies or system-wide proxy settings.

10. **Synthesize the Information:**  Organize the findings into the requested categories: functionality, JavaScript relation, logic/assumptions, user errors, and debugging clues. Use clear and concise language. Provide specific examples from the code.

By following these steps, you can systematically analyze the provided C++ unittest file and extract the necessary information to answer the prompt effectively. The key is to understand the purpose of each test case and how it relates to the overall functionality of the `ProxyConfig` class.
This C++ source code file, `proxy_config_unittest.cc`, is part of the Chromium network stack and focuses on **unit testing the `ProxyConfig` class**. The primary goal of these tests is to ensure that the `ProxyConfig` class behaves correctly under various conditions and configurations.

Here's a breakdown of its functionalities:

**1. Testing `ProxyConfig::Equals()`:**
   - This set of tests verifies that the `Equals()` method of the `ProxyConfig` class correctly determines if two `ProxyConfig` objects are equivalent.
   - It covers various attributes of `ProxyConfig`, including:
     - `auto_detect`: Whether to automatically detect proxy settings.
     - `pac_url`: The URL of a Proxy Auto-Configuration (PAC) file.
     - `proxy_rules`:  A complex structure defining proxy servers for different protocols and bypass rules. This includes testing equality of:
       - `type`: Whether it's a single proxy list or proxy-per-scheme.
       - `single_proxies`: A list of proxies to use for all traffic.
       - `bypass_rules`:  Rules specifying which hosts or IP ranges to bypass the proxy for.
       - `reverse_bypass`:  Whether the bypass rules are inverted (only use the proxy for matching rules).
       - Multi-proxy chains (when `ENABLE_BRACKETED_PROXY_URIS` is enabled).

**2. Testing `ProxyConfig::ToValue()` and JSON Serialization:**
   - This part tests the ability of `ProxyConfig` objects to be converted into a `base::Value` object, which can then be serialized into a JSON string.
   - It covers different `ProxyConfig` configurations and compares the generated JSON with expected outputs. This is crucial for scenarios where proxy configurations need to be stored or transmitted in a structured format.

**3. Testing `ProxyConfig::ProxyRules::ParseFromString()`:**
   - These tests focus on the `ParseFromString()` method of the nested `ProxyConfig::ProxyRules` class. This method is responsible for parsing a string representation of proxy rules into the internal structure.
   - It tests various proxy rule string formats, including:
     - Single proxy servers (with and without port numbers).
     - Proxy servers for specific protocols (e.g., `http=`, `https=`, `ftp=`, `socks=`).
     - Multiple proxy servers for a single protocol.
     - The `direct://` directive to indicate a direct connection.
     - Handling of unsupported schemes (they should be ignored).
     - Multi-proxy chains (when `ENABLE_BRACKETED_PROXY_URIS` is enabled).
     - QUIC proxy support (when `ENABLE_QUIC_PROXY_SUPPORT` is enabled).

**4. Testing `ProxyConfig::ProxyRules::Apply()` and Bypass Rules:**
   - This test verifies that the `Apply()` method of `ProxyConfig::ProxyRules` correctly determines whether a proxy should be used for a given URL, considering the defined bypass rules and the `reverse_bypass` flag.
   - It specifically checks if the `did_bypass_proxy()` flag in the `ProxyInfo` object is set correctly.

**5. Testing WebSocket Proxy Selection:**
   - The `ProxyConfigWebSocketTest` fixture is dedicated to testing how `ProxyConfig` handles proxy selection for WebSocket (ws:// and wss://) URLs.
   - It verifies:
     - The preference for SOCKS proxies over HTTP/HTTPS proxies for WebSockets.
     - The preference for HTTPS proxies over HTTP proxies for secure WebSockets (wss://).
     - The use of fallback proxies (specified with `socks=`) if no protocol-specific proxy is defined.
     - The correct application of bypass rules to WebSocket URLs.

**Relationship with JavaScript:**

While this is a C++ file, it has a strong indirect relationship with JavaScript. Here's how:

* **Browser Configuration:**  Web browsers often allow users or administrators to configure proxy settings. These settings might be entered through a browser's UI (which is often implemented using JavaScript or a similar web technology) or set via system-level configurations. The C++ network stack then reads and interprets these configurations using classes like `ProxyConfig`.
* **PAC Scripts:**  PAC (Proxy Auto-Configuration) scripts are written in JavaScript. When a `ProxyConfig` object has a `pac_url` set, the Chromium network stack will fetch and execute this JavaScript code to dynamically determine the appropriate proxy for a given request. The results of this JavaScript execution are then used to populate `ProxyInfo`.
* **Browser Extensions:** Browser extensions written in JavaScript can interact with the browser's proxy settings API. These extensions can modify or set proxy configurations, which are ultimately handled by the C++ network stack.
* **Debugging:** When debugging proxy-related issues in a web application, understanding how the browser's proxy configuration (managed by C++ code tested here) interacts with JavaScript running in the browser is crucial. For example, if a web request is unexpectedly failing to use a proxy, it might be due to a misconfiguration handled by `ProxyConfig` or an error in a PAC script.

**Example of JavaScript Interaction:**

Imagine a user opens their browser settings and manually enters the following proxy configuration:

* **HTTP Proxy:** `myproxy.example.com:8080`
* **Bypass List:** `*.internal.net, localhost`

The browser's UI (likely using JavaScript) would collect this information and store it in a way that the underlying C++ code can access. When the C++ network stack processes this configuration, it would create a `ProxyConfig` object where:

* `config.proxy_rules().type` would be `ProxyConfig::ProxyRules::Type::PROXY_LIST`.
* `config.proxy_rules().single_proxies.ToDebugString()` would be `"PROXY myproxy.example.com:8080"`.
* `config.proxy_rules().bypass_rules` would contain rules for `*.internal.net` and `localhost`.

When a JavaScript application running in the browser makes a request to `http://intranet.internal.net/`, the C++ network stack (using the tested `ProxyConfig` logic) would recognize that this URL matches a bypass rule and make a direct connection instead of going through the proxy.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

Let's take the `TEST(ProxyConfigTest, ParseProxyRules)` as an example:

**Assumption:** The `ParseFromString()` method correctly interprets the defined syntax for proxy rule strings.

**Hypothetical Input:**  The proxy rules string is `"http=webproxy:3128; https=sslproxy"`.

**Expected Output:**
* `config.proxy_rules().type` will be `ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME`.
* `config.proxy_rules().proxies_for_http.ToDebugString()` will be `"PROXY webproxy:3128"`.
* `config.proxy_rules().proxies_for_https.ToDebugString()` will be `"PROXY sslproxy:80"` (assuming default port 80 for HTTP).
* Other proxy-specific attributes (`proxy_for_ftp`, `fallback_proxy`) will be empty.

**User or Programming Common Usage Errors:**

1. **Incorrect Proxy Syntax:** Users or developers might enter incorrect proxy server addresses or port numbers. For example, typing `myproxy:abc` instead of `myproxy:80`. The `ParseFromString()` tests help ensure that the parsing logic is robust against such errors (though the tests mainly focus on correct syntax). The actual error handling might happen in layers above `ProxyConfig`.
   ```c++
   // Example of incorrect user input leading to parsing issues
   ProxyConfig config;
   config.proxy_rules().ParseFromString("http=badproxy:invalidport");
   // The parsing might fail or produce an unexpected ProxyServer object.
   ```

2. **Misunderstanding Bypass Rules:** Users might create bypass rules that are too broad or too specific, not achieving the intended effect.
   ```c++
   // User intends to bypass all internal traffic but makes a mistake.
   ProxyConfig config;
   config.proxy_rules().ParseFromString("http=myproxy");
   config.proxy_rules().bypass_rules.AddRuleFromString(".com"); // Too broad, will bypass many external sites.
   ```

3. **Forgetting WebSocket Specifics:** Developers might assume that standard HTTP/HTTPS proxies will automatically work for WebSockets, which isn't always the case. The `ProxyConfigWebSocketTest` highlights the nuances of WebSocket proxy selection.
   ```c++
   // Developer sets an HTTP proxy but doesn't realize WebSockets might prefer SOCKS.
   ProxyConfig config;
   config.proxy_rules().ParseFromString("http=httpproxy");
   // A WebSocket connection might not use this proxy if a SOCKS proxy is available elsewhere.
   ```

**User Operation Steps to Reach Here (Debugging Clues):**

Imagine a user is experiencing issues connecting to a website through a proxy. Here's how their actions might lead to the execution of code tested in `proxy_config_unittest.cc`:

1. **Manual Proxy Configuration:**
   - The user opens their browser's settings.
   - They navigate to the proxy settings section.
   - They choose "Manual proxy configuration".
   - They enter the HTTP proxy address, HTTPS proxy address, and a list of domains to bypass.
   - When the browser attempts to load a webpage, the C++ network stack will read these settings and create a `ProxyConfig` object. The `ParseFromString()` logic will be used to interpret the entered proxy addresses. The bypass rules will be stored in the `bypass_rules` attribute. If the user mistypes a proxy address, the parsing logic (tested here) will determine how that error is handled.

2. **Using a PAC Script:**
   - The user opens their browser's settings.
   - They navigate to the proxy settings section.
   - They choose "Automatic proxy configuration URL".
   - They enter the URL of a PAC file.
   - When the browser needs to determine the proxy for a request, it will fetch and execute the JavaScript code in the PAC file. The results of this script execution will ultimately be translated into a `ProxyConfig` object. While this file doesn't directly test PAC script execution, it tests the structure (`ProxyConfig`) that holds the results of that execution.

3. **Browser Extension Setting Proxy:**
   - The user installs a browser extension that manages proxy settings.
   - The extension uses the browser's proxy API (often JavaScript-based) to set the proxy configuration.
   - Internally, the browser translates these API calls into modifications of the `ProxyConfig` object in the C++ network stack. The tests here ensure the integrity and correct behavior of that `ProxyConfig` object regardless of how it's populated.

4. **System-Level Proxy Settings:**
   - The user's operating system has proxy settings configured (e.g., via group policy on Windows).
   - When the browser starts, it reads these system-level settings and creates a `ProxyConfig` object accordingly. The parsing and interpretation of these settings are implicitly tested by the unit tests in this file.

By understanding the functionality tested in `proxy_config_unittest.cc`, developers can pinpoint potential areas of failure when debugging proxy-related issues. For instance, if a user reports that their bypass rules aren't working as expected, the `ProxyRulesSetBypassFlag` test provides insights into how the bypass logic should behave. Similarly, issues with WebSocket proxying can be investigated by examining the behavior tested in `ProxyConfigWebSocketTest`.

### 提示词
```
这是目录为net/proxy_resolution/proxy_config_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/proxy_resolution/proxy_config.h"

#include "base/json/json_writer.h"
#include "base/test/gtest_util.h"
#include "base/values.h"
#include "build/buildflag.h"
#include "net/base/proxy_string_util.h"
#include "net/net_buildflags.h"
#include "net/proxy_resolution/proxy_config_service_common_unittest.h"
#include "net/proxy_resolution/proxy_info.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

void ExpectProxyServerEquals(const char* expectation,
                             const ProxyList& proxy_list) {
  if (expectation == nullptr) {
    EXPECT_TRUE(proxy_list.IsEmpty());
  } else {
    EXPECT_EQ(expectation, proxy_list.ToDebugString());
  }
}

TEST(ProxyConfigTest, Equals) {
  // Test |ProxyConfig::auto_detect|.

  ProxyConfig config1;
  config1.set_auto_detect(true);

  ProxyConfig config2;
  config2.set_auto_detect(false);

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config2.set_auto_detect(true);

  EXPECT_TRUE(config1.Equals(config2));
  EXPECT_TRUE(config2.Equals(config1));

  // Test |ProxyConfig::pac_url|.

  config2.set_pac_url(GURL("http://wpad/wpad.dat"));

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config1.set_pac_url(GURL("http://wpad/wpad.dat"));

  EXPECT_TRUE(config1.Equals(config2));
  EXPECT_TRUE(config2.Equals(config1));

  // Test |ProxyConfig::proxy_rules|.

  config2.proxy_rules().type = ProxyConfig::ProxyRules::Type::PROXY_LIST;
  config2.proxy_rules().single_proxies.SetSingleProxyServer(
      ProxyUriToProxyServer("myproxy:80", ProxyServer::SCHEME_HTTP));

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config1.proxy_rules().type = ProxyConfig::ProxyRules::Type::PROXY_LIST;
  config1.proxy_rules().single_proxies.SetSingleProxyServer(
      ProxyUriToProxyServer("myproxy:100", ProxyServer::SCHEME_HTTP));

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config1.proxy_rules().single_proxies.SetSingleProxyServer(
      ProxyUriToProxyServer("myproxy", ProxyServer::SCHEME_HTTP));

  EXPECT_TRUE(config1.Equals(config2));
  EXPECT_TRUE(config2.Equals(config1));

  // Test |ProxyConfig::bypass_rules|.

  config2.proxy_rules().bypass_rules.AddRuleFromString("*.google.com");

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config1.proxy_rules().bypass_rules.AddRuleFromString("*.google.com");

  EXPECT_TRUE(config1.Equals(config2));
  EXPECT_TRUE(config2.Equals(config1));

  // Test |ProxyConfig::proxy_rules.reverse_bypass|.

  config2.proxy_rules().reverse_bypass = true;

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config1.proxy_rules().reverse_bypass = true;

  EXPECT_TRUE(config1.Equals(config2));
  EXPECT_TRUE(config2.Equals(config1));
}

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
TEST(ProxyConfigTest, EqualsMultiProxyChains) {
  ProxyConfig config1;
  ProxyConfig config2;

  config2.proxy_rules().type =
      ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME;
  config2.proxy_rules().proxies_for_https.SetSingleProxyChain(
      MultiProxyUrisToProxyChain("[https://foopy:443 https://hoopy:443]",
                                 ProxyServer::SCHEME_HTTPS));

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config1.proxy_rules().type =
      ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME;
  config1.proxy_rules().proxies_for_https.SetSingleProxyChain(
      MultiProxyUrisToProxyChain("[https://foopy:80 https://hoopy:80]",
                                 ProxyServer::SCHEME_HTTPS));

  EXPECT_FALSE(config1.Equals(config2));
  EXPECT_FALSE(config2.Equals(config1));

  config1.proxy_rules().proxies_for_https.SetSingleProxyChain(
      MultiProxyUrisToProxyChain("[https://foopy https://hoopy]",
                                 ProxyServer::SCHEME_HTTPS));

  EXPECT_TRUE(config1.Equals(config2));
  EXPECT_TRUE(config2.Equals(config1));
}
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)

struct ProxyConfigToValueTestCase {
  ProxyConfig config;
  const char* expected_value_json;
};

class ProxyConfigToValueTest
    : public ::testing::TestWithParam<ProxyConfigToValueTestCase> {};

TEST_P(ProxyConfigToValueTest, ToValueJSON) {
  const ProxyConfigToValueTestCase& test_case = GetParam();

  base::Value value = test_case.config.ToValue();

  std::string json_string;
  ASSERT_TRUE(base::JSONWriter::Write(value, &json_string));

  EXPECT_EQ(std::string(test_case.expected_value_json), json_string);
}

ProxyConfigToValueTestCase GetTestCaseDirect() {
  return {ProxyConfig::CreateDirect(), "{}"};
}

ProxyConfigToValueTestCase GetTestCaseAutoDetect() {
  return {ProxyConfig::CreateAutoDetect(), "{\"auto_detect\":true}"};
}

ProxyConfigToValueTestCase GetTestCasePacUrl() {
  ProxyConfig config;
  config.set_pac_url(GURL("http://www.example.com/test.pac"));

  return {std::move(config),
          "{\"pac_url\":\"http://www.example.com/test.pac\"}"};
}

ProxyConfigToValueTestCase GetTestCasePacUrlMandatory() {
  ProxyConfig config;
  config.set_pac_url(GURL("http://www.example.com/test.pac"));
  config.set_pac_mandatory(true);

  return {std::move(config),
          "{\"pac_mandatory\":true,\"pac_url\":\"http://www.example.com/"
          "test.pac\"}"};
}

ProxyConfigToValueTestCase GetTestCasePacUrlAndAutoDetect() {
  ProxyConfig config = ProxyConfig::CreateAutoDetect();
  config.set_pac_url(GURL("http://www.example.com/test.pac"));

  return {
      std::move(config),
      "{\"auto_detect\":true,\"pac_url\":\"http://www.example.com/test.pac\"}"};
}

ProxyConfigToValueTestCase GetTestCaseSingleProxy() {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("https://proxy1:8080");

  return {std::move(config), "{\"single_proxy\":[\"[https://proxy1:8080]\"]}"};
}

ProxyConfigToValueTestCase GetTestCaseSingleProxyWithBypass() {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("https://proxy1:8080");
  config.proxy_rules().bypass_rules.AddRuleFromString("*.google.com");
  config.proxy_rules().bypass_rules.AddRuleFromString("192.168.0.1/16");

  return {std::move(config),
          "{\"bypass_list\":[\"*.google.com\",\"192.168.0.1/"
          "16\"],\"single_proxy\":[\"[https://proxy1:8080]\"]}"};
}

ProxyConfigToValueTestCase GetTestCaseSingleProxyWithReversedBypass() {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("https://proxy1:8080");
  config.proxy_rules().bypass_rules.AddRuleFromString("*.google.com");
  config.proxy_rules().reverse_bypass = true;

  return {std::move(config),
          "{\"bypass_list\":[\"*.google.com\"],\"reverse_bypass\":true,"
          "\"single_proxy\":[\"[https://proxy1:8080]\"]}"};
}

ProxyConfigToValueTestCase GetTestCaseProxyPerScheme() {
  ProxyConfig config;
  config.proxy_rules().ParseFromString(
      "http=https://proxy1:8080;https=socks5://proxy2");
  config.proxy_rules().bypass_rules.AddRuleFromString("*.google.com");
  config.set_pac_url(GURL("http://wpad/wpad.dat"));
  config.set_auto_detect(true);

  return {
      std::move(config),
      "{\"auto_detect\":true,\"bypass_list\":[\"*.google.com\"],\"pac_url\":"
      "\"http://wpad/wpad.dat\",\"proxy_per_scheme\":{\"http\":[\"[https://"
      "proxy1:8080]\"],\"https\":[\"[socks5://proxy2:1080]\"]}}"};
}

ProxyConfigToValueTestCase GetTestCaseSingleProxyList() {
  ProxyConfig config;
  config.proxy_rules().ParseFromString(
      "https://proxy1:8080,http://proxy2,direct://");

  return {
      std::move(config),
      "{\"single_proxy\":[\"[https://proxy1:8080]\",\"[proxy2:80]\",\"direct://"
      "\"]}"};
}

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
// Multi-proxy chains present
ProxyConfigToValueTestCase GetTestCaseMultiProxyChainProxyPerScheme() {
  ProxyConfig config;
  config.proxy_rules().ParseFromString(
      "http=[https://proxy1:8080 https://proxy2:8080];https=socks5://proxy2",
      /*allow_bracketed_proxy_chains=*/true);
  config.proxy_rules().bypass_rules.AddRuleFromString("*.google.com");
  config.set_pac_url(GURL("http://wpad/wpad.dat"));
  config.set_auto_detect(true);

  return {std::move(config),
          "{\"auto_detect\":true,\"bypass_list\":[\"*.google.com\"],\"pac_"
          "url\":\"http://wpad/"
          "wpad.dat\",\"proxy_per_scheme\":{\"http\":[\"[https://proxy1:8080, "
          "https://proxy2:8080]\"],\"https\":[\"[socks5://proxy2:1080]\"]}}"};
}
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)

INSTANTIATE_TEST_SUITE_P(
    All,
    ProxyConfigToValueTest,
    testing::Values(GetTestCaseDirect(),
                    GetTestCaseAutoDetect(),
                    GetTestCasePacUrl(),
                    GetTestCasePacUrlMandatory(),
                    GetTestCasePacUrlAndAutoDetect(),
                    GetTestCaseSingleProxy(),
                    GetTestCaseSingleProxyWithBypass(),
                    GetTestCaseSingleProxyWithReversedBypass(),
                    GetTestCaseProxyPerScheme(),
#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
                    GetTestCaseMultiProxyChainProxyPerScheme(),
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
                    GetTestCaseSingleProxyList()));

TEST(ProxyConfigTest, ParseProxyRules) {
  const struct {
    const char* proxy_rules;

    ProxyConfig::ProxyRules::Type type;
    // These will be PAC-stle strings, eg 'PROXY foo.com'
    const char* single_proxy;
    const char* proxy_for_http;
    const char* proxy_for_https;
    const char* proxy_for_ftp;
    const char* fallback_proxy;
  } tests[] = {
      // One HTTP proxy for all schemes.
      {
          "myproxy:80",

          ProxyConfig::ProxyRules::Type::PROXY_LIST,
          "PROXY myproxy:80",
          nullptr,
          nullptr,
          nullptr,
          nullptr,
      },

      // Multiple HTTP proxies for all schemes.
      {
          "myproxy:80,https://myotherproxy",

          ProxyConfig::ProxyRules::Type::PROXY_LIST,
          "PROXY myproxy:80;HTTPS myotherproxy:443",
          nullptr,
          nullptr,
          nullptr,
          nullptr,
      },

      // Only specify a proxy server for "http://" urls.
      {
          "http=myproxy:80",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "PROXY myproxy:80",
          nullptr,
          nullptr,
          nullptr,
      },

      // Specify an HTTP proxy for "ftp://" and a SOCKS proxy for "https://"
      // urls.
      {
          "ftp=ftp-proxy ; https=socks4://foopy",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          "SOCKS foopy:1080",
          "PROXY ftp-proxy:80",
          nullptr,
      },

      // Give a scheme-specific proxy as well as a non-scheme specific.
      // The first entry "foopy" takes precedence marking this list as
      // Type::PROXY_LIST.
      {
          "foopy ; ftp=ftp-proxy",

          ProxyConfig::ProxyRules::Type::PROXY_LIST,
          "PROXY foopy:80",
          nullptr,
          nullptr,
          nullptr,
          nullptr,
      },

      // Give a scheme-specific proxy as well as a non-scheme specific.
      // The first entry "ftp=ftp-proxy" takes precedence marking this list as
      // Type::PROXY_LIST_PER_SCHEME.
      {
          "ftp=ftp-proxy ; foopy",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          nullptr,
          "PROXY ftp-proxy:80",
          nullptr,
      },

      // Include a list of entries for a single scheme.
      {
          "ftp=ftp1,ftp2,ftp3",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          nullptr,
          "PROXY ftp1:80;PROXY ftp2:80;PROXY ftp3:80",
          nullptr,
      },

      // Include multiple entries for the same scheme -- they accumulate.
      {
          "http=http1,http2; http=http3",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "PROXY http1:80;PROXY http2:80;PROXY http3:80",
          nullptr,
          nullptr,
          nullptr,
      },

      // Include lists of entries for multiple schemes.
      {
          "ftp=ftp1,ftp2,ftp3 ; http=http1,http2; ",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "PROXY http1:80;PROXY http2:80",
          nullptr,
          "PROXY ftp1:80;PROXY ftp2:80;PROXY ftp3:80",
          nullptr,
      },

      // Include non-default proxy schemes.
      {
          "http=https://secure_proxy; ftp=socks4://socks_proxy; "
          "https=socks://foo",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "HTTPS secure_proxy:443",
          "SOCKS5 foo:1080",
          "SOCKS socks_proxy:1080",
          nullptr,
      },

      // Only SOCKS proxy present, others being blank.
      {
          "socks=foopy",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          "SOCKS foopy:1080",
      },

      // SOCKS proxy present along with other proxies too
      {
          "http=httpproxy ; https=httpsproxy ; ftp=ftpproxy ; socks=foopy ",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "PROXY httpproxy:80",
          "PROXY httpsproxy:80",
          "PROXY ftpproxy:80",
          "SOCKS foopy:1080",
      },

      // SOCKS proxy (with modifier) present along with some proxies
      // (FTP being blank)
      {
          "http=httpproxy ; https=httpsproxy ; socks=socks5://foopy ",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "PROXY httpproxy:80",
          "PROXY httpsproxy:80",
          nullptr,
          "SOCKS5 foopy:1080",
      },

      // Include unsupported schemes -- they are discarded.
      {
          "crazy=foopy ; foo=bar ; https=myhttpsproxy",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          "PROXY myhttpsproxy:80",
          nullptr,
          nullptr,
      },

      // direct:// as first option for a scheme.
      {
          "http=direct://,myhttpproxy; https=direct://",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "DIRECT;PROXY myhttpproxy:80",
          "DIRECT",
          nullptr,
          nullptr,
      },

      // direct:// as a second option for a scheme.
      {
          "http=myhttpproxy,direct://",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "PROXY myhttpproxy:80;DIRECT",
          nullptr,
          nullptr,
          nullptr,
      },

      // Multi-proxy bracketed URIs will result in no proxy being set
      {
          "http=[https://proxy1:8080 https://proxy2:8080]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
      }

  };

  ProxyConfig config;

  for (const auto& test : tests) {
    config.proxy_rules().ParseFromString(test.proxy_rules);
    EXPECT_EQ(test.type, config.proxy_rules().type);
    ExpectProxyServerEquals(test.single_proxy,
                            config.proxy_rules().single_proxies);
    ExpectProxyServerEquals(test.proxy_for_http,
                            config.proxy_rules().proxies_for_http);
    ExpectProxyServerEquals(test.proxy_for_https,
                            config.proxy_rules().proxies_for_https);
    ExpectProxyServerEquals(test.proxy_for_ftp,
                            config.proxy_rules().proxies_for_ftp);
    ExpectProxyServerEquals(test.fallback_proxy,
                            config.proxy_rules().fallback_proxies);
  }
}

#if BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
// When the bool to allow quic proxy support is false, there should be no valid
// proxies in the config.
TEST(ProxyConfigTest, ParseProxyRulesQuicIsNotAllowed) {
  ProxyConfig config;

  config.proxy_rules().ParseFromString("quic://foopy:443",
                                       /*allow_bracketed_proxy_chains=*/false,
                                       /*is_quic_allowed=*/false);

  EXPECT_EQ(ProxyConfig::ProxyRules::Type::PROXY_LIST,
            config.proxy_rules().type);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().single_proxies);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().proxies_for_http);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().proxies_for_https);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().proxies_for_ftp);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().fallback_proxies);
}

// When the bool to allow quic proxy support is true, a valid quic proxy should
// be found in the config.
TEST(ProxyConfigTest, ParseProxyRulesQuicIsAllowed) {
  ProxyConfig config;

  config.proxy_rules().ParseFromString("quic://foopy:443",
                                       /*allow_bracketed_proxy_chains=*/false,
                                       /*is_quic_allowed=*/true);

  EXPECT_EQ(ProxyConfig::ProxyRules::Type::PROXY_LIST,
            config.proxy_rules().type);
  ExpectProxyServerEquals("QUIC foopy:443",
                          config.proxy_rules().single_proxies);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().proxies_for_http);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().proxies_for_https);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().proxies_for_ftp);
  ExpectProxyServerEquals(nullptr, config.proxy_rules().fallback_proxies);
}
#endif  // BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)

#if !BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
// When the build flag is disabled for QUIC support, `ParseFromString` should
// not allow QUIC proxy support by setting bool to true. A true value should
// crash.
TEST(ProxyConfigTest,
     ParseProxyRulesDisallowQuicProxySupportIfBuildFlagDisabled) {
  ProxyConfig config;

  EXPECT_CHECK_DEATH(config.proxy_rules().ParseFromString(
      "quic://foopy:443",
      /*allow_bracketed_proxy_chains=*/false, /*is_quic_allowed=*/true));
}
#endif  // !BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)

#if !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
// In release builds, `ParseFromString` should not allow parsing of multi-proxy
// chains by setting bool to true. A true value should crash.
TEST(ProxyConfigTest, ParseProxyRulesDisallowMultiProxyChainsInReleaseBuilds) {
  ProxyConfig config;

  EXPECT_CHECK_DEATH(config.proxy_rules().ParseFromString(
      "http=[https://proxy1:8080 https://proxy2:8080]", true));
}
#endif  // !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
// Tests for multi-proxy chains which are currently only allowed in debug mode.
TEST(ProxyConfigTest, MultiProxyChainsParseProxyRules) {
  const struct {
    const char* proxy_rules;

    ProxyConfig::ProxyRules::Type type;
    // For multi-proxy chains, proxies within a single chain will be formatted
    // within a bracket separated by a space and comma.
    const char* single_proxy;
    const char* proxy_for_http;
    const char* proxy_for_https;
    const char* proxy_for_ftp;
    const char* fallback_proxy;
  } tests[] = {

      // One HTTP proxy for all schemes.
      {
          "[https://proxy1:8080]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST,
          "HTTPS proxy1:8080",
          nullptr,
          nullptr,
          nullptr,
          nullptr,
      },

      // Multiple proxies for all schemes.
      {
          "[https://proxy1:8080 https://proxy2:8080],[https://proxy3:8080]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST,
          "[https://proxy1:8080, https://proxy2:8080];HTTPS proxy3:8080",
          nullptr,
          nullptr,
          nullptr,
          nullptr,
      },

      // Only specify a proxy chain for "http://" urls.
      {
          "http=[https://proxy1:8080 https://proxy2:8080]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "[https://proxy1:8080, https://proxy2:8080]",
          nullptr,
          nullptr,
          nullptr,
      },

      // Specify different multi-proxy chains for different schemes.
      {
          "http=[https://proxy1:8080 https://proxy2:8080] ; "
          "https=[https://proxy3:8080 https://proxy4:8080]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "[https://proxy1:8080, https://proxy2:8080]",
          "[https://proxy3:8080, https://proxy4:8080]",
          nullptr,
          nullptr,
      },

      // Give a scheme-specific proxy as well as a non-scheme specific.
      // The first entry takes precedence marking this list as Type::PROXY_LIST.
      {
          "[https://proxy1:8080 https://proxy2:8080] ; "
          "http=[https://proxy3:8080 https://proxy4:8080]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST,
          "[https://proxy1:8080, https://proxy2:8080]",
          nullptr,
          nullptr,
          nullptr,
          nullptr,
      },

      // Give a scheme-specific proxy as well as a non-scheme specific.
      // The first entry takes precedence marking this list as
      // Type::PROXY_LIST_PER_SCHEME.
      {
          "http=[https://proxy3:8080 https://proxy4:8080] ; "
          "[https://proxy1:8080 https://proxy2:8080]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "[https://proxy3:8080, https://proxy4:8080]",
          nullptr,
          nullptr,
          nullptr,
      },

      // Include a list of entries for a single scheme.
      {
          "ftp=[https://proxy1:80 https://proxy2:80],[https://proxy3:80 "
          "https://proxy4:80],[https://proxy5:80 https://proxy6:80]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          nullptr,
          "[https://proxy1:80, https://proxy2:80];[https://proxy3:80, "
          "https://proxy4:80];[https://proxy5:80, https://proxy6:80]",
          nullptr,
      },

      // Include multiple entries for the same scheme -- they accumulate.
      {
          "http=[https://proxy1:80 https://proxy2:80]; http=[https://proxy3:80 "
          "https://proxy4:80],[https://proxy5:80 https://proxy6:80]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "[https://proxy1:80, https://proxy2:80];[https://proxy3:80, "
          "https://proxy4:80];[https://proxy5:80, https://proxy6:80]",
          nullptr,
          nullptr,
          nullptr,
      },

      // Include lists of entries for multiple schemes.
      {
          "http=[https://proxy1:80 https://proxy2:80]; ftp=[https://proxy3:80 "
          "https://proxy4:80],[https://proxy5:80 https://proxy6:80]",
          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          "[https://proxy1:80, https://proxy2:80]",
          nullptr,
          "[https://proxy3:80, https://proxy4:80];[https://proxy5:80, "
          "https://proxy6:80]",
          nullptr,
      },

      // Include unsupported schemes -- they are discarded.
      {
          "crazy=[https://proxy1:80 https://proxy2:80] ; foo=bar ; "
          "https=[https://proxy3:80 https://proxy4:80]",

          ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
          nullptr,
          nullptr,
          "[https://proxy3:80, https://proxy4:80]",
          nullptr,
          nullptr,
      },
  };

  ProxyConfig config;

  for (const auto& test : tests) {
    config.proxy_rules().ParseFromString(test.proxy_rules, true);
    EXPECT_EQ(test.type, config.proxy_rules().type);
    ExpectProxyServerEquals(test.single_proxy,
                            config.proxy_rules().single_proxies);
    ExpectProxyServerEquals(test.proxy_for_http,
                            config.proxy_rules().proxies_for_http);
    ExpectProxyServerEquals(test.proxy_for_https,
                            config.proxy_rules().proxies_for_https);
    ExpectProxyServerEquals(test.proxy_for_ftp,
                            config.proxy_rules().proxies_for_ftp);
    ExpectProxyServerEquals(test.fallback_proxy,
                            config.proxy_rules().fallback_proxies);
  }
}
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)

TEST(ProxyConfigTest, ProxyRulesSetBypassFlag) {
  // Test whether the did_bypass_proxy() flag is set in proxy info correctly.
  ProxyConfig::ProxyRules rules;
  ProxyInfo result;

  rules.ParseFromString("http=httpproxy:80");
  rules.bypass_rules.AddRuleFromString(".com");

  rules.Apply(GURL("http://example.com"), &result);
  EXPECT_TRUE(result.is_direct_only());
  EXPECT_TRUE(result.did_bypass_proxy());

  rules.Apply(GURL("http://example.org"), &result);
  EXPECT_FALSE(result.is_direct());
  EXPECT_FALSE(result.did_bypass_proxy());

  // Try with reversed bypass rules.
  rules.reverse_bypass = true;

  rules.Apply(GURL("http://example.org"), &result);
  EXPECT_TRUE(result.is_direct_only());
  EXPECT_TRUE(result.did_bypass_proxy());

  rules.Apply(GURL("http://example.com"), &result);
  EXPECT_FALSE(result.is_direct());
  EXPECT_FALSE(result.did_bypass_proxy());
}

static const char kWsUrl[] = "ws://example.com/echo";
static const char kWssUrl[] = "wss://example.com/echo";

class ProxyConfigWebSocketTest : public ::testing::Test {
 protected:
  void ParseFromString(const std::string& rules) {
    rules_.ParseFromString(rules);
  }
  void Apply(const GURL& gurl) { rules_.Apply(gurl, &info_); }
  std::string ToDebugString() const { return info_.ToDebugString(); }

  static GURL WsUrl() { return GURL(kWsUrl); }
  static GURL WssUrl() { return GURL(kWssUrl); }

  ProxyConfig::ProxyRules rules_;
  ProxyInfo info_;
};

// If a single proxy is set for all protocols, WebSocket uses it.
TEST_F(ProxyConfigWebSocketTest, UsesProxy) {
  ParseFromString("proxy:3128");
  Apply(WsUrl());
  EXPECT_EQ("PROXY proxy:3128", ToDebugString());
}

// See RFC6455 Section 4.1. item 3, "_Proxy Usage_". Note that this favors a
// SOCKSv4 proxy (although technically the spec only notes SOCKSv5).
TEST_F(ProxyConfigWebSocketTest, PrefersSocksV4) {
  ParseFromString(
      "http=proxy:3128 ; https=sslproxy:3128 ; socks=socksproxy:1080");
  Apply(WsUrl());
  EXPECT_EQ("SOCKS socksproxy:1080", ToDebugString());
}

// See RFC6455 Section 4.1. item 3, "_Proxy Usage_".
TEST_F(ProxyConfigWebSocketTest, PrefersSocksV5) {
  ParseFromString(
      "http=proxy:3128 ; https=sslproxy:3128 ; socks=socks5://socksproxy:1080");
  Apply(WsUrl());
  EXPECT_EQ("SOCKS5 socksproxy:1080", ToDebugString());
}

TEST_F(ProxyConfigWebSocketTest, PrefersHttpsToHttp) {
  ParseFromString("http=proxy:3128 ; https=sslproxy:3128");
  Apply(WssUrl());
  EXPECT_EQ("PROXY sslproxy:3128", ToDebugString());
}

// Tests when a proxy-per-url-scheme configuration was used, and proxies are
// specified for http://, https://, and a fallback proxy (non-SOCKS).
// Even though the fallback proxy is not SOCKS, it is still favored over the
// proxy for http://* and https://*.
TEST_F(ProxyConfigWebSocketTest, PrefersNonSocksFallbackOverHttps) {
  // The notation for "socks=" is abused to set the "fallback proxy".
  ParseFromString(
      "http=proxy:3128 ; https=sslproxy:3128; socks=https://httpsproxy");
  EXPECT_EQ("HTTPS httpsproxy:443", rules_.fallback_proxies.ToDebugString());
  Apply(WssUrl());
  EXPECT_EQ("HTTPS httpsproxy:443", ToDebugString());
}

// Tests when a proxy-per-url-scheme configuration was used, and the fallback
// proxy is a non-SOCKS proxy, and no proxy was given for https://* or
// http://*. The fallback proxy is used.
TEST_F(ProxyConfigWebSocketTest, UsesNonSocksFallbackProxy) {
  // The notation for "socks=" is abused to set the "fallback proxy".
  ParseFromString("ftp=ftpproxy:3128; socks=https://httpsproxy");
  EXPECT_EQ("HTTPS httpsproxy:443", rules_.fallback_proxies.ToDebugString());
  Apply(WssUrl());
  EXPECT_EQ("HTTPS httpsproxy:443", ToDebugString());
}

TEST_F(ProxyConfigWebSocketTest, PrefersHttpsEvenForWs) {
  ParseFromString("http=proxy:3128 ; https=sslproxy:3128");
  Apply(WsUrl());
  EXPECT_EQ("PROXY sslproxy:3128", ToDebugString());
}

TEST_F(ProxyConfigWebSocketTest, PrefersHttpToDirect) {
  ParseFromString("http=proxy:3128");
  Apply(WssUrl());
  EXPECT_EQ("PROXY proxy:3128", ToDebugString());
}

TEST_F(ProxyConfigWebSocketTest, IgnoresFtpProxy) {
  ParseFromString("ftp=ftpproxy:3128");
  Apply(WssUrl());
  EXPECT_EQ("DIRECT", ToDebugString());
}

TEST_F(ProxyConfigWebSocketTest, ObeysBypassRules) {
  ParseFromString("http=proxy:3128 ; https=sslproxy:3128");
  rules_.bypass_rules.AddRuleFromString(".chromium.org");
  Apply(GURL("wss://codereview.chromium.org/feed"));
  EXPECT_EQ("DIRECT", ToDebugString());
}

TEST_F(ProxyConfigWebSocketTest, ObeysLocalBypass) {
  ParseFromString("http=proxy:3128 ; https=sslproxy:3128");
  rules_.bypass_rules.AddRuleFromString("<local>");
  Apply(GURL("ws://localhost/feed"));
  EXPECT_EQ("DIRECT", ToDebugString());
}

}  // namespace
}  // namespace net
```