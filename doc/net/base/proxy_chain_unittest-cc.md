Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Understanding the Goal:**

The request asks for the *functionality* of `proxy_chain_unittest.cc`, its relation to JavaScript (if any), logical reasoning examples (input/output), common user errors, and how a user might reach this code (debugging perspective).

**2. Initial Skim and Keyword Spotting:**

I'd start by quickly skimming the code, looking for key terms and patterns:

* **`TEST(...)`**:  Immediately signals that this is a unit test file using Google Test.
* **`ProxyChain`**:  The core class being tested. This tells me the tests are about creating, manipulating, and comparing `ProxyChain` objects.
* **`ProxyServer`**:  A component of `ProxyChain`, indicating that a proxy chain is composed of individual proxy servers.
* **`ProxyUriToProxyServer`**:  A utility function for creating `ProxyServer` objects from URIs.
* **`Direct()`**:  A static method likely representing a direct connection (no proxy).
* **`ForIpProtection()`**:  A method suggesting special handling for IP protection scenarios.
* **`IsValid()`**:  A crucial method for verifying the validity of a `ProxyChain`.
* **`is_direct()`, `is_single_proxy()`, `is_multi_proxy()`**: Methods for checking the type of proxy chain.
* **`length()`**:  Returns the number of proxy servers in the chain.
* **`proxy_servers()`**: Returns the underlying vector of `ProxyServer` objects.
* **`ToDebugString()`**:  A method for generating a human-readable string representation, useful for debugging.
* **`FromSchemeHostAndPort()`**:  A method for constructing a `ProxyChain` from individual components.
* **`SplitLast()`, `Prefix()`, `First()`, `Last()`**: Methods for manipulating the chain (splitting, getting prefixes, first/last elements).
* **`is_for_ip_protection()`**:  Checks if the chain is for IP protection.
* **`is_get_to_proxy_allowed()`**:  Checks if a "GET to proxy" request is allowed with this chain.
* **`Persist()`, `InitFromPickle()`**: Methods related to serialization (saving and loading).
* **`EXPECT_*`, `ASSERT_*`**: Google Test macros for making assertions in tests.
* **`BUILDFLAG(...)`**:  Conditional compilation based on build flags. This is important for understanding why certain tests might be enabled or disabled.

**3. Analyzing Test Cases (Grouping by Functionality):**

I'd then go through the individual test cases and group them by the aspect of `ProxyChain` they are testing:

* **Construction/Assignment:** `DefaultConstructor`, `ConstructorsAndAssignmentOperators`
* **Direct Proxy:** `DirectProxy`
* **String Representation:** `Ostream`, `ToDebugString`
* **Creation from Components:** `FromSchemeHostAndPort`
* **Invalid Input Handling:** `InvalidHostname`, `InvalidPort`
* **Single Proxy Chains:** `SingleProxyChain`
* **Chain Manipulation:** `SplitLast`, `Prefix`, `First`, `Last`
* **IP Protection:** `IsForIpProtection`, `ForIpProtection`
* **Proxy Type Checking:** `IsGetToProxyAllowed`
* **Validity Checks:** `IsValid`
* **Comparison:** `Unequal`, `Equal`
* **Serialization:** `PickleDirect`, `PickleOneProxy`, `UnpickleInvalidProxy`, `PickleTwoProxies` (and `MultiProxyChain` related tests)
* **Multi-Proxy Support (conditional):** Tests related to `ENABLE_BRACKETED_PROXY_URIS`.
* **QUIC Proxy Support (conditional):** Tests related to `ENABLE_QUIC_PROXY_SUPPORT`.

**4. Identifying JavaScript Relevance:**

With an understanding of the tested functionalities, I'd consider how these relate to JavaScript. The key connection is the *web browser's networking stack*. JavaScript running in a browser often interacts with proxy settings. I'd think about:

* **`navigator.proxy` API (hypothetical):**  While a direct API like this might not exist exactly as named, JavaScript can influence proxy settings indirectly.
* **`fetch()` API and proxy settings:**  How might a `fetch()` request be affected by the proxy chain configuration?
* **WebSockets and proxies:**  Do proxies play a role in WebSocket connections?
* **PAC (Proxy Auto-Configuration) scripts:**  JavaScript is used in PAC scripts to determine which proxy to use.

**5. Developing Logical Reasoning Examples:**

For each test case (or group of related tests), I'd think about a simplified input and the expected output, focusing on the logic being tested. For example, with `FromSchemeHostAndPort`,  I'd consider different schemes, host formats, and ports and predict the resulting `ProxyServer` properties.

**6. Identifying Common User Errors:**

This requires thinking about how developers or users might interact with proxy settings or make mistakes:

* **Incorrect proxy URI format:**  Typos, missing parts, wrong schemes.
* **Using unsupported proxy schemes.**
* **Misconfiguring PAC scripts.**
* **Assuming a proxy will work without proper authentication.**

**7. Tracing User Actions to the Code:**

This involves imagining the steps a user takes that would lead to this network stack code being executed:

* **Setting proxy settings in the browser's settings.**
* **Using a PAC script.**
* **Enterprise policies forcing proxy usage.**
* **Extensions that manage proxy settings.**
* **Command-line flags when launching Chrome.**

**8. Considering Conditional Compilation (`BUILDFLAG`):**

It's crucial to note how build flags affect the validity of multi-proxy chains and QUIC proxy support. This explains why some tests are conditional and highlights potential differences between debug and release builds.

**9. Structuring the Output:**

Finally, I'd organize the information clearly, addressing each part of the request: functionality, JavaScript relevance, logical reasoning, user errors, and debugging hints. Using bullet points, code examples (even hypothetical JavaScript ones), and clear explanations helps in presenting the information effectively.
This C++ source file, `proxy_chain_unittest.cc`, contains unit tests for the `ProxyChain` class within Chromium's networking stack. The primary function of this file is to ensure the `ProxyChain` class behaves as expected under various conditions.

Here's a breakdown of its functionalities:

**1. Testing Basic `ProxyChain` Operations:**

* **Construction and Assignment:** Tests different ways to construct `ProxyChain` objects (default, copy, move, from a list of `ProxyServer`s) and verifies assignment operators work correctly.
* **Direct Proxy Representation:** Tests the creation and properties of a "direct" proxy chain (no proxy).
* **String Conversion:** Tests converting `ProxyChain` objects to human-readable strings for debugging and logging (`ToDebugString`, `operator<<`).
* **Creation from Scheme, Host, and Port:**  Tests the `FromSchemeHostAndPort` method, which is crucial for parsing proxy server information from strings. It covers various cases, including different schemes (HTTP, HTTPS, SOCKS), host formats (hostname, IPv4, IPv6), and port specifications.
* **Handling Invalid Input:** Tests how the `ProxyChain` class handles invalid hostname and port inputs when using `FromSchemeHostAndPort`.

**2. Testing Properties of Proxy Chains:**

* **Single Proxy Chains:** Verifies the properties of a `ProxyChain` containing a single proxy server.
* **Multi-Proxy Chains:** Tests the creation and properties of `ProxyChain`s with multiple proxy servers (note: this functionality might be conditional based on build flags).
* **IP Protection Proxy Chains:** Tests the creation and properties of `ProxyChain`s specifically intended for IP protection mechanisms.
* **Checking Proxy Chain Type:** Tests methods like `is_direct()`, `is_single_proxy()`, and `is_multi_proxy()` to determine the type of the chain.
* **Getting Proxy Servers:** Tests methods like `length()` and `GetProxyServer()` to access the individual `ProxyServer` objects within the chain.

**3. Testing Chain Manipulation:**

* **Splitting the Last Proxy:** Tests the `SplitLast()` method, which divides a chain into the prefix and the last proxy server.
* **Getting a Prefix of the Chain:** Tests the `Prefix()` method, which returns a new `ProxyChain` containing a prefix of the original chain.
* **Accessing First and Last Proxy:** Tests the `First()` and `Last()` methods to retrieve the first and last `ProxyServer` in the chain.

**4. Testing Validity and Compatibility:**

* **Checking Validity (`IsValid()`):** Tests various scenarios to ensure `IsValid()` correctly identifies valid and invalid `ProxyChain` configurations, considering factors like the sequence of proxy schemes (e.g., QUIC after HTTPS is usually invalid without IP protection). Build flags like `ENABLE_BRACKETED_PROXY_URIS` and `ENABLE_QUIC_PROXY_SUPPORT` influence the validity of multi-proxy chains and QUIC proxies.
* **Checking if GET to Proxy is Allowed (`is_get_to_proxy_allowed()`):** Tests if the proxy chain configuration allows for "GET to proxy" requests (often disallowed with SOCKS proxies).
* **Checking if it's for IP Protection (`is_for_ip_protection()`):** Tests the method that identifies if a `ProxyChain` is specifically created for IP protection.

**5. Testing Equality and Comparison:**

* **Equality Operators (`==`):** Tests if two `ProxyChain` objects are considered equal based on their content.
* **Inequality and Ordering (`<`):** Tests the less-than operator, which is used for ordering `ProxyChain` objects in collections like `std::set`.

**6. Testing Serialization (Pickling):**

* **Persisting and Restoring (`Persist()`, `InitFromPickle()`):** Tests the ability to serialize and deserialize `ProxyChain` objects using Chromium's `base::Pickle` mechanism. This is important for storing and retrieving proxy chain configurations.
* **Handling Invalid Pickled Data:** Tests how the `ProxyChain` class handles attempts to unpickle data representing an invalid proxy chain.

**Relationship with JavaScript:**

While this C++ code doesn't directly contain JavaScript, it plays a crucial role in how Chromium handles network requests initiated by JavaScript code running in a web page or extension.

Here's how they are related:

* **`navigator.proxy` API (conceptual):**  Although JavaScript doesn't have a direct `navigator.proxy` API to manipulate proxy chains in detail, the proxy settings configured in the browser (either manually by the user, through enterprise policies, or via extensions) ultimately translate into `ProxyChain` objects within the browser's network stack. When JavaScript makes a network request (e.g., using `fetch` or `XMLHttpRequest`), the browser's networking code uses the active `ProxyChain` to route the request.
* **PAC (Proxy Auto-Configuration) Scripts:**  JavaScript is used within PAC scripts to determine the appropriate proxy server(s) for a given URL. The execution of these PAC scripts within the browser's network stack eventually results in the creation of a `ProxyChain` object that reflects the chosen proxy configuration.
* **WebSockets and Proxies:** When JavaScript establishes a WebSocket connection, the browser's network stack (which uses `ProxyChain`) handles the initial handshake and connection setup, potentially through a proxy server.
* **Service Workers:** Service workers, written in JavaScript, can intercept network requests and modify them, including potentially influencing proxy usage (though they don't directly manipulate `ProxyChain` objects).

**Example of JavaScript interaction (conceptual):**

Imagine a user has configured a proxy server "proxy.example.com:8080" in their browser settings. When a JavaScript code executes:

```javascript
fetch('https://www.example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

The browser's networking stack will:

1. **Retrieve the active `ProxyChain`:** This `ProxyChain` would likely contain a single `ProxyServer` object representing "proxy.example.com:8080".
2. **Use the `ProxyChain` to route the request:** The browser will establish a connection to "proxy.example.com:8080" and send a request to fetch "https://www.example.com/data.json" through the proxy.

**Logical Reasoning Examples (Hypothetical Input and Output):**

* **Input:** `ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_HTTPS, "secure.proxy", 443)`
   * **Output:** A `ProxyChain` object containing a single `ProxyServer` with scheme `SCHEME_HTTPS`, host "secure.proxy", and port 443. `IsValid()` would likely return `true`.

* **Input:** A `ProxyChain` created with two `ProxyServer` objects: one with `SCHEME_HTTP` and another with `SCHEME_SOCKS5`.
   * **Output:**  Depending on the build flags, `IsValid()` might return `false` (as SOCKS5 is often not allowed in multi-proxy chains without IP protection).

* **Input:** `proxy_chain.SplitLast()` on a `ProxyChain` containing proxies A, B, and C.
   * **Output:** A pair:
      * The first element is a `ProxyChain` containing proxies A and B.
      * The second element is the `ProxyServer` object representing proxy C.

**Common User or Programming Errors and Examples:**

* **Incorrect Proxy URI Format:**
    * **User Error:**  Typing "htttp://proxy:80" instead of "http://proxy:80" in browser settings. This would likely lead to the `ProxyChain::FromSchemeHostAndPort` failing to parse the URI correctly, resulting in an invalid proxy configuration.
    * **Programming Error:** In code that programmatically sets proxy settings, constructing an invalid URI string.

* **Using Unsupported Proxy Schemes:**
    * **User Error:** Trying to configure a proxy with a scheme not supported by the browser.
    * **Programming Error:**  Attempting to create a `ProxyServer` or `ProxyChain` with an invalid or unsupported `ProxyServer::Scheme`. The `IsValid()` method would likely catch this.

* **Misunderstanding Multi-Proxy Chain Restrictions:**
    * **Programming Error:**  Creating a multi-proxy chain with an invalid sequence of schemes (e.g., QUIC after HTTPS without IP protection enabled) if the build flags don't allow it. The `IsValid()` method would flag this as invalid.

* **Not Handling Proxy Authentication:**
    * **User Experience:**  Configuring a proxy that requires authentication but not providing credentials. The browser will likely prompt for credentials, and network requests will fail until they are provided. While `ProxyChain` itself doesn't directly handle authentication, it represents the proxy that requires it.

**User Operations Leading to This Code (Debugging Clues):**

1. **User Manually Configures Proxy Settings:**
   * The user opens their browser's settings (e.g., Chrome Settings -> Advanced -> System -> Open your computer's proxy settings).
   * They enter the address and port of a proxy server.
   * This input is parsed and used to create a `ProxyChain` object within the browser's network stack. Debugging would involve inspecting how the input is processed and how the `ProxyChain` is constructed.

2. **User Uses a PAC (Proxy Auto-Configuration) Script:**
   * The user configures their browser to use a PAC script URL.
   * When the browser needs to make a network request, it fetches and executes the PAC script (which is JavaScript).
   * The PAC script's logic determines the proxy server(s) to use for the target URL.
   * This information is then used to create a `ProxyChain` object. Debugging would involve stepping through the PAC script execution and examining the resulting `ProxyChain`.

3. **Enterprise Policies Force Proxy Usage:**
   * An organization's administrator sets group policies that mandate the use of specific proxy servers.
   * When the browser starts, it reads these policies and configures the proxy settings accordingly, leading to the creation of `ProxyChain` objects.

4. **Browser Extensions Manage Proxy Settings:**
   * A user installs a browser extension that helps manage or switch between proxy configurations.
   * The extension interacts with the browser's proxy settings APIs, which internally involve creating and managing `ProxyChain` objects.

5. **Command-Line Flags:**
   * When launching Chromium, command-line flags like `--proxy-server` can be used to specify proxy settings. These flags are processed and used to initialize the `ProxyChain`.

**As a debugging line:** If a network request is failing due to proxy issues, a developer might:

* **Inspect the active `ProxyChain` object:**  Using internal Chromium debugging tools or logging, they could examine the properties of the `ProxyChain` being used for the failing request. This would show the configured proxy servers, their schemes, and whether the chain is considered valid.
* **Trace the creation of the `ProxyChain`:**  They might try to trace back how the current `ProxyChain` was created, whether it was from manual settings, a PAC script, or a policy.
* **Test `IsValid()` at different stages:**  They could check the validity of the `ProxyChain` object at various points in the request processing to see if it becomes invalid at some stage.
* **Examine the output of `ToDebugString()`:** This provides a human-readable representation of the `ProxyChain`, which can be helpful for quickly understanding its configuration.

In summary, `proxy_chain_unittest.cc` is a critical part of ensuring the robustness and correctness of Chromium's proxy handling, which directly impacts how web requests from JavaScript and other parts of the browser are routed through proxy servers.

Prompt: 
```
这是目录为net/base/proxy_chain_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/proxy_chain.h"

#include <optional>
#include <sstream>

#include "base/pickle.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/gtest_util.h"
#include "build/buildflag.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/net_buildflags.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(ProxyChainTest, DefaultConstructor) {
  ProxyChain proxy_chain;
  EXPECT_FALSE(proxy_chain.IsValid());
}

TEST(ProxyChainTest, ConstructorsAndAssignmentOperators) {
  std::vector proxy_servers = {
      ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS),
      ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_HTTPS)};

  ProxyChain proxy_chain = ProxyChain(proxy_servers);

  ProxyChain copy_constructed(proxy_chain);
  EXPECT_EQ(proxy_chain, copy_constructed);

  ProxyChain copy_assigned = proxy_chain;
  EXPECT_EQ(proxy_chain, copy_assigned);

  ProxyChain move_constructed{std::move(copy_constructed)};
  EXPECT_EQ(proxy_chain, move_constructed);

  ProxyChain move_assigned = std::move(copy_assigned);
  EXPECT_EQ(proxy_chain, move_assigned);
}

TEST(ProxyChainTest, DirectProxy) {
  ProxyChain proxy_chain1 = ProxyChain::Direct();
  ProxyChain proxy_chain2 = ProxyChain(std::vector<ProxyServer>());
  std::vector<ProxyServer> proxy_servers = {};

  // Equal and valid proxy chains.
  ASSERT_EQ(proxy_chain1, proxy_chain2);
  EXPECT_TRUE(proxy_chain1.IsValid());
  EXPECT_TRUE(proxy_chain2.IsValid());

  EXPECT_TRUE(proxy_chain1.is_direct());
  EXPECT_FALSE(proxy_chain1.is_single_proxy());
  EXPECT_FALSE(proxy_chain1.is_multi_proxy());
  ASSERT_EQ(proxy_chain1.length(), 0u);
  ASSERT_EQ(proxy_chain1.proxy_servers(), proxy_servers);
}

TEST(ProxyChainTest, Ostream) {
  ProxyChain proxy_chain =
      ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_HTTP, "foo", 80);
  std::ostringstream out;
  out << proxy_chain;
  EXPECT_EQ(out.str(), "[foo:80]");
}

TEST(ProxyChainTest, ToDebugString) {
  ProxyChain proxy_chain1 =
      ProxyChain(ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_SOCKS5));
  EXPECT_EQ(proxy_chain1.ToDebugString(), "[socks5://foo:333]");

  ProxyChain direct_proxy_chain = ProxyChain::Direct();
  EXPECT_EQ(direct_proxy_chain.ToDebugString(), "[direct://]");

  ProxyChain ip_protection_proxy_chain = ProxyChain::ForIpProtection(
      {ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS),
       ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS)});
  EXPECT_EQ(ip_protection_proxy_chain.ToDebugString(),
            "[https://foo:444, https://foo:555] (IP Protection)");

  ProxyChain invalid_proxy_chain = ProxyChain();
  EXPECT_EQ(invalid_proxy_chain.ToDebugString(), "INVALID PROXY CHAIN");

// Multi-proxy chains can only be created outside of Ip Protection in debug
// builds.
#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  ProxyChain proxy_chain2 =
      ProxyChain({ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS),
                  ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS)});
  EXPECT_EQ(proxy_chain2.ToDebugString(), "[https://foo:444, https://foo:555]");
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
}

TEST(ProxyChainTest, FromSchemeHostAndPort) {
  const struct {
    const ProxyServer::Scheme input_scheme;
    const char* const input_host;
    const std::optional<uint16_t> input_port;
    const char* const input_port_str;
    const char* const expected_host;
    const uint16_t expected_port;
  } tests[] = {
      {ProxyServer::SCHEME_HTTP, "foopy", 80, "80", "foopy", 80},

      // Non-standard port
      {ProxyServer::SCHEME_HTTP, "foopy", 10, "10", "foopy", 10},
      {ProxyServer::SCHEME_HTTP, "foopy", 0, "0", "foopy", 0},

      // Hostname canonicalization
      {ProxyServer::SCHEME_HTTP, "FoOpY", 80, "80", "foopy", 80},
      {ProxyServer::SCHEME_HTTP, "f\u00fcpy", 80, "80", "xn--fpy-hoa", 80},

      // IPv4 literal
      {ProxyServer::SCHEME_HTTP, "1.2.3.4", 80, "80", "1.2.3.4", 80},

      // IPv4 literal canonicalization
      {ProxyServer::SCHEME_HTTP, "127.1", 80, "80", "127.0.0.1", 80},
      {ProxyServer::SCHEME_HTTP, "0x7F.0x1", 80, "80", "127.0.0.1", 80},
      {ProxyServer::SCHEME_HTTP, "0177.01", 80, "80", "127.0.0.1", 80},

      // IPv6 literal
      {ProxyServer::SCHEME_HTTP, "[3ffe:2a00:100:7031::1]", 80, "80",
       "[3ffe:2a00:100:7031::1]", 80},
      {ProxyServer::SCHEME_HTTP, "3ffe:2a00:100:7031::1", 80, "80",
       "[3ffe:2a00:100:7031::1]", 80},

      // IPv6 literal canonicalization
      {ProxyServer::SCHEME_HTTP, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", 80,
       "80", "[fedc:ba98:7654:3210:fedc:ba98:7654:3210]", 80},
      {ProxyServer::SCHEME_HTTP, "::192.9.5.5", 80, "80", "[::c009:505]", 80},

      // Other schemes
      {ProxyServer::SCHEME_HTTPS, "foopy", 111, "111", "foopy", 111},
      {ProxyServer::SCHEME_SOCKS4, "foopy", 111, "111", "foopy", 111},
      {ProxyServer::SCHEME_SOCKS5, "foopy", 111, "111", "foopy", 111},

      // Default ports
      {ProxyServer::SCHEME_HTTP, "foopy", std::nullopt, "", "foopy", 80},
      {ProxyServer::SCHEME_HTTPS, "foopy", std::nullopt, "", "foopy", 443},
      {ProxyServer::SCHEME_SOCKS4, "foopy", std::nullopt, "", "foopy", 1080},
      {ProxyServer::SCHEME_SOCKS5, "foopy", std::nullopt, "", "foopy", 1080},
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(base::NumberToString(i) + ": " + tests[i].input_host + ":" +
                 base::NumberToString(tests[i].input_port.value_or(-1)));
    auto chain = ProxyChain::FromSchemeHostAndPort(
        tests[i].input_scheme, tests[i].input_host, tests[i].input_port);
    auto proxy = chain.First();

    ASSERT_TRUE(proxy.is_valid());
    EXPECT_EQ(proxy.scheme(), tests[i].input_scheme);
    EXPECT_EQ(proxy.GetHost(), tests[i].expected_host);
    EXPECT_EQ(proxy.GetPort(), tests[i].expected_port);

    auto chain_from_string_port = ProxyChain::FromSchemeHostAndPort(
        tests[i].input_scheme, tests[i].input_host, tests[i].input_port_str);
    auto proxy_from_string_port = chain_from_string_port.First();
    EXPECT_TRUE(proxy_from_string_port.is_valid());
    EXPECT_EQ(proxy, proxy_from_string_port);
  }
}

TEST(ProxyChainTest, InvalidHostname) {
  const char* const tests[]{
      "",
      "[]",
      "[foo]",
      "foo:",
      "foo:80",
      ":",
      "http://foo",
      "3ffe:2a00:100:7031::1]",
      "[3ffe:2a00:100:7031::1",
      "foo.80",
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(base::NumberToString(i) + ": " + tests[i]);
    auto proxy = ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_HTTP,
                                                   tests[i], 80);
    EXPECT_FALSE(proxy.IsValid());
  }
}

TEST(ProxyChainTest, InvalidPort) {
  const char* const tests[]{
      "-1",
      "65536",
      "foo",
      "0x35",
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(base::NumberToString(i) + ": " + tests[i]);
    auto proxy = ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_HTTP,
                                                   "foopy", tests[i]);
    EXPECT_FALSE(proxy.IsValid());
  }
}

TEST(ProxyChainTest, SingleProxyChain) {
  auto proxy_server =
      ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_HTTPS);

  std::vector<ProxyServer> proxy_servers = {proxy_server};
  auto proxy = ProxyChain(proxy_servers);

  EXPECT_FALSE(proxy.is_direct());
  EXPECT_TRUE(proxy.is_single_proxy());
  EXPECT_FALSE(proxy.is_multi_proxy());
  ASSERT_EQ(proxy.proxy_servers(), proxy_servers);
  ASSERT_EQ(proxy.length(), 1u);
  ASSERT_EQ(proxy.GetProxyServer(0), proxy_server);
}

TEST(ProxyChainTest, SplitLast) {
  auto proxy_server1 =
      ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_HTTPS);
  auto proxy_server2 =
      ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS);
  auto proxy_server3 =
      ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS);

  auto chain3 = ProxyChain::ForIpProtection(
      {proxy_server1, proxy_server2, proxy_server3});
  EXPECT_EQ(chain3.SplitLast(),
            std::make_pair(
                ProxyChain::ForIpProtection({proxy_server1, proxy_server2}),
                proxy_server3));

  auto chain1 = ProxyChain({proxy_server1});
  EXPECT_EQ(chain1.SplitLast(),
            std::make_pair(ProxyChain::Direct(), proxy_server1));

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  // Multi-proxy chains (not for Ip Protection) are only valid in debug builds.
  auto chain2 = ProxyChain({proxy_server1, proxy_server2});
  EXPECT_EQ(chain2.SplitLast(),
            std::make_pair(ProxyChain({proxy_server1}), proxy_server2));
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
}

TEST(ProxyChainTest, Prefix) {
  auto proxy_server1 =
      ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_HTTPS);
  auto proxy_server2 =
      ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS);
  auto proxy_server3 =
      ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS);
  auto chain = ProxyChain::ForIpProtection(
      {proxy_server1, proxy_server2, proxy_server3}, /*chain_id=*/2);
  EXPECT_EQ(chain.Prefix(0), ProxyChain::ForIpProtection({}, /*chain_id=*/2));
  EXPECT_EQ(chain.Prefix(1),
            ProxyChain::ForIpProtection({proxy_server1}, /*chain_id=*/2));
  EXPECT_EQ(chain.Prefix(2),
            ProxyChain::ForIpProtection({proxy_server1, proxy_server2},
                                        /*chain_id=*/2));
  EXPECT_EQ(chain.Prefix(3),
            ProxyChain::ForIpProtection(
                {proxy_server1, proxy_server2, proxy_server3}, /*chain_id=*/2));
}

TEST(ProxyChainTest, First) {
  auto proxy_server1 =
      ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_HTTPS);

  auto chain = ProxyChain({proxy_server1});
  EXPECT_EQ(chain.First(), proxy_server1);

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  // Multi-proxy chains (not for Ip Protection) are only valid in debug builds.
  auto proxy_server2 =
      ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS);

  chain = ProxyChain({proxy_server1, proxy_server2});
  EXPECT_EQ(chain.First(), proxy_server1);
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
}

TEST(ProxyChainTest, Last) {
  auto proxy_server1 =
      ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_HTTPS);

  auto chain = ProxyChain({proxy_server1});
  EXPECT_EQ(chain.Last(), proxy_server1);

#if BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  // Multi-proxy chains (not for Ip Protection) are only valid in debug builds.
  auto proxy_server2 =
      ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS);

  chain = ProxyChain({proxy_server1, proxy_server2});
  EXPECT_EQ(chain.Last(), proxy_server2);
#endif  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
}

TEST(ProxyChainTest, IsForIpProtection) {
  auto regular_proxy_chain1 = ProxyChain::Direct();
  EXPECT_FALSE(regular_proxy_chain1.is_for_ip_protection());

  auto ip_protection_proxy_chain1 =
      ProxyChain::ForIpProtection(std::vector<ProxyServer>());
  EXPECT_TRUE(ip_protection_proxy_chain1.is_for_ip_protection());

  auto regular_proxy_chain2 =
      ProxyChain({ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS),
                  ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_HTTPS)});
  EXPECT_FALSE(regular_proxy_chain2.is_for_ip_protection());

  auto ip_protection_proxy_chain2 = ProxyChain::ForIpProtection(
      {ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS),
       ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_HTTPS)});
  EXPECT_TRUE(ip_protection_proxy_chain2.is_for_ip_protection());
}

TEST(ProxyChainTest, ForIpProtection) {
  auto ip_protection_proxy_chain1 =
      ProxyChain::ForIpProtection(std::vector<ProxyServer>());
  EXPECT_TRUE(ip_protection_proxy_chain1.is_direct());
  EXPECT_TRUE(ip_protection_proxy_chain1.is_for_ip_protection());
  EXPECT_EQ(ip_protection_proxy_chain1.ip_protection_chain_id(),
            ProxyChain::kDefaultIpProtectionChainId);

  // Ensure that ProxyChain can be reassigned a new value created using its own
  // `proxy_severs()`.
  auto proxy_chain =
      ProxyChain({ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS)});
  auto copied_proxy_chain = proxy_chain;

  // Assert that the newly created `ProxyChain` is not for IP protection.
  EXPECT_FALSE(proxy_chain.is_for_ip_protection());
  EXPECT_EQ(proxy_chain.ip_protection_chain_id(),
            ProxyChain::kNotIpProtectionChainId);

  // Re-assign new value to `proxy_chain` by using its own proxy servers to
  // create a proxy chain for IP protection.
  proxy_chain =
      ProxyChain::ForIpProtection(std::move(proxy_chain.proxy_servers()));

  // Assert re-assigned proxy chain is now for IP protection and contains the
  // same servers from the original copy.
  EXPECT_TRUE(proxy_chain.is_for_ip_protection());
  EXPECT_EQ(proxy_chain.ip_protection_chain_id(),
            ProxyChain::kDefaultIpProtectionChainId);
  EXPECT_FALSE(copied_proxy_chain.is_for_ip_protection());
  EXPECT_EQ(proxy_chain.proxy_servers(), copied_proxy_chain.proxy_servers());

  auto chain_with_id = ProxyChain::ForIpProtection(
      {ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS),
       ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_HTTPS)},
      /*chain_id=*/3);
  EXPECT_FALSE(chain_with_id.is_direct());
  EXPECT_TRUE(chain_with_id.is_for_ip_protection());
  EXPECT_EQ(chain_with_id.ip_protection_chain_id(), 3);
}

TEST(ProxyChainTest, IsGetToProxyAllowed) {
  auto https_server1 =
      ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_HTTPS);
  auto https_server2 =
      ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS);
  auto http_server = ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTP);
  auto socks_server =
      ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_SOCKS4);

  EXPECT_FALSE(ProxyChain::Direct().is_get_to_proxy_allowed());
  EXPECT_TRUE(ProxyChain({https_server1}).is_get_to_proxy_allowed());
  EXPECT_TRUE(ProxyChain({http_server}).is_get_to_proxy_allowed());
  EXPECT_FALSE(ProxyChain({socks_server}).is_get_to_proxy_allowed());
  EXPECT_FALSE(
      ProxyChain({https_server1, https_server2}).is_get_to_proxy_allowed());
}

TEST(ProxyChainTest, IsValid) {
  // Single hop proxy of type Direct is valid.
  EXPECT_TRUE(ProxyChain::Direct().IsValid());

  auto https1 = ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS);
  auto https2 = ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS);
  auto quic1 = ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_QUIC);
  auto quic2 = ProxyUriToProxyServer("foo:777", ProxyServer::SCHEME_QUIC);
  auto socks = ProxyUriToProxyServer("foo:777", ProxyServer::SCHEME_SOCKS5);

  // Single proxy chain is valid.
  EXPECT_TRUE(ProxyChain({https1}).IsValid());

  // Invalid Chains.
  //
  // If multi-proxy chain support is disabled, any chain greater
  // than length 1 is considered invalid. If multi-proxy support is enabled AND
  // QUIC proxy support is enabled, these chains remain invalid due to the
  // sequence of schemes.
  EXPECT_FALSE(ProxyChain({https1, quic2}).IsValid());
  EXPECT_FALSE(ProxyChain({https1, https2, quic1, quic2}).IsValid());
  // ProxyChain cannot contains socks server. Only QUIC and HTTPS.
  EXPECT_FALSE(ProxyChain({socks, https1}).IsValid());
  EXPECT_FALSE(ProxyChain({socks, https1, https2}).IsValid());
  EXPECT_FALSE(ProxyChain({https1, socks}).IsValid());
  EXPECT_FALSE(ProxyChain({https1, https2, socks}).IsValid());

  // IP protection accepts chains with SCHEME_QUIC and/or multi-proxy chains
  EXPECT_TRUE(ProxyChain::ForIpProtection({https1}).IsValid());
  EXPECT_TRUE(ProxyChain::ForIpProtection({quic1}).IsValid());
  EXPECT_TRUE(ProxyChain::ForIpProtection({https1, https2}).IsValid());
  EXPECT_TRUE(ProxyChain::ForIpProtection({quic1, https1}).IsValid());
  EXPECT_TRUE(
      ProxyChain::ForIpProtection({quic1, quic2, https1, https2}).IsValid());

  // IP protection CHECKs on failure instead of just creating an invalid chain.
  // QUIC cannot follow HTTPS proxy server.
  EXPECT_CHECK_DEATH(ProxyChain::ForIpProtection({https1, quic2}).IsValid());
  EXPECT_CHECK_DEATH(
      ProxyChain::ForIpProtection({https1, https2, quic1, quic2}).IsValid());
  // Socks proxy server is not valid for multi-proxy chain.
  EXPECT_CHECK_DEATH(ProxyChain::ForIpProtection({socks, https1}).IsValid());
  EXPECT_CHECK_DEATH(
      ProxyChain::ForIpProtection({socks, https1, https2}).IsValid());
  EXPECT_CHECK_DEATH(ProxyChain::ForIpProtection({https1, socks}).IsValid());
  EXPECT_CHECK_DEATH(
      ProxyChain::ForIpProtection({https1, https2, socks}).IsValid());

#if !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  bool multi_proxy_chain_supported = false;
#else  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
  bool multi_proxy_chain_supported = true;
#endif
  // Multi-proxy chains are only supported in debug mode.
  EXPECT_EQ(ProxyChain({https1, https2}).IsValid(),
            multi_proxy_chain_supported);

#if !BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
  bool is_quic_supported = false;
#else  // BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
  bool is_quic_supported = true;
#endif
  // Multi-proxy chains are only supported in debug mode.
  EXPECT_EQ(ProxyChain({quic1}).IsValid(), is_quic_supported);

// If quic proxy support is enabled AND multi-proxy chain support is
// enabled, the following chains are valid. Otherwise, they are invalid.
#if !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS) || \
    !BUILDFLAG(ENABLE_QUIC_PROXY_SUPPORT)
  bool is_multi_proxy_quic_supported = false;
#else
  bool is_multi_proxy_quic_supported = true;
#endif
  EXPECT_EQ(ProxyChain({quic1, https1}).IsValid(),
            is_multi_proxy_quic_supported);
  EXPECT_EQ(ProxyChain({quic1, quic2, https1, https2}).IsValid(),
            is_multi_proxy_quic_supported);
}

TEST(ProxyChainTest, Unequal) {
  // Ordered proxy chains.
  std::vector<ProxyChain> proxy_chain_list = {
      ProxyChain::Direct(),
      ProxyUriToProxyChain("foo:333", ProxyServer::SCHEME_HTTP),
      ProxyUriToProxyChain("foo:444", ProxyServer::SCHEME_HTTP),
      ProxyChain({ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS),
                  ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_HTTPS)}),
      ProxyUriToProxyChain("socks4://foo:33", ProxyServer::SCHEME_SOCKS4),
      ProxyUriToProxyChain("http://foo:33", ProxyServer::SCHEME_HTTP),
      ProxyChain({ProxyUriToProxyChain("bar:33", ProxyServer::SCHEME_HTTP)}),
      ProxyChain::ForIpProtection(
          {ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS),
           ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_HTTPS)})};

  // Unordered proxy chains.
  std::set<ProxyChain> proxy_chain_set(proxy_chain_list.begin(),
                                       proxy_chain_list.end());

  // Initial proxy chain list and set are equal.
  ASSERT_EQ(proxy_chain_list.size(), proxy_chain_set.size());

  for (const ProxyChain& proxy_chain1 : proxy_chain_list) {
    auto proxy_chain2 = proxy_chain_set.begin();
    // Chain set entries less than `proxy_chain1`.
    while (*proxy_chain2 < proxy_chain1) {
      EXPECT_TRUE(*proxy_chain2 < proxy_chain1);
      EXPECT_FALSE(proxy_chain1 < *proxy_chain2);
      EXPECT_FALSE(*proxy_chain2 == proxy_chain1);
      EXPECT_FALSE(proxy_chain1 == *proxy_chain2);
      ++proxy_chain2;
    }

    // Chain set entry for `proxy_chain1`.
    EXPECT_FALSE(*proxy_chain2 < proxy_chain1);
    EXPECT_FALSE(proxy_chain1 < *proxy_chain2);
    EXPECT_TRUE(*proxy_chain2 == proxy_chain1);
    EXPECT_TRUE(proxy_chain1 == *proxy_chain2);
    ++proxy_chain2;

    // Chain set entries greater than `proxy_chain1`.
    while (proxy_chain2 != proxy_chain_set.end() &&
           proxy_chain1 < *proxy_chain2) {
      EXPECT_FALSE(*proxy_chain2 < proxy_chain1);
      EXPECT_TRUE(proxy_chain1 < *proxy_chain2);
      EXPECT_FALSE(*proxy_chain2 == proxy_chain1);
      EXPECT_FALSE(proxy_chain1 == *proxy_chain2);
      ++proxy_chain2;
    }
    ASSERT_EQ(proxy_chain2, proxy_chain_set.end());
  }
}

TEST(ProxyChainTest, Equal) {
  ProxyServer proxy_server =
      ProxyUriToProxyServer("foo:11", ProxyServer::SCHEME_HTTP);

  ProxyChain proxy_chain1 = ProxyChain(proxy_server);
  ProxyChain proxy_chain2 = ProxyChain(std::vector<ProxyServer>{proxy_server});
  ProxyChain proxy_chain3 =
      ProxyChain(ProxyServer::SCHEME_HTTP, HostPortPair("foo", 11));

  EXPECT_FALSE(proxy_chain1 < proxy_chain2);
  EXPECT_FALSE(proxy_chain2 < proxy_chain1);
  EXPECT_TRUE(proxy_chain2 == proxy_chain1);
  EXPECT_TRUE(proxy_chain2 == proxy_chain1);

  EXPECT_FALSE(proxy_chain2 < proxy_chain3);
  EXPECT_FALSE(proxy_chain3 < proxy_chain2);
  EXPECT_TRUE(proxy_chain3 == proxy_chain2);
  EXPECT_TRUE(proxy_chain3 == proxy_chain2);
}

TEST(ProxyChainTest, PickleDirect) {
  ProxyChain proxy_chain = ProxyChain::Direct();
  base::Pickle pickle;
  proxy_chain.Persist(&pickle);
  base::PickleIterator iter(pickle);
  ProxyChain proxy_chain_from_pickle;
  EXPECT_TRUE(proxy_chain_from_pickle.InitFromPickle(&iter));
  EXPECT_EQ(proxy_chain, proxy_chain_from_pickle);
}

TEST(ProxyChainTest, PickleOneProxy) {
  ProxyChain proxy_chain =
      ProxyChain(ProxyUriToProxyServer("foo:11", ProxyServer::SCHEME_HTTPS));
  base::Pickle pickle;
  proxy_chain.Persist(&pickle);
  base::PickleIterator iter(pickle);
  ProxyChain proxy_chain_from_pickle;
  EXPECT_TRUE(proxy_chain_from_pickle.InitFromPickle(&iter));
  EXPECT_EQ(proxy_chain, proxy_chain_from_pickle);
}

TEST(ProxyChainTest, UnpickleInvalidProxy) {
  ProxyServer invalid_proxy_server;
  // Manually pickle a proxcy chain with an invalid proxy server.
  base::Pickle pickle;
  pickle.WriteInt(ProxyChain::kNotIpProtectionChainId);
  pickle.WriteInt(1);  // Length of the chain
  invalid_proxy_server.Persist(&pickle);

  base::PickleIterator iter(pickle);
  ProxyChain invalid_proxy_chain_from_pickle;
  // Unpickling should fail and leave us with an invalid proxy chain.
  EXPECT_FALSE(invalid_proxy_chain_from_pickle.InitFromPickle(&iter));
  // Make sure that we unpickled the invalid proxy server.
  EXPECT_TRUE(iter.ReachedEnd());
  EXPECT_FALSE(invalid_proxy_chain_from_pickle.IsValid());
}

#if !BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
// Multi-proxy chains that are not for Ip Protection are not allowed in release
// builds. If created, it should be considered invalid.
TEST(ProxyChainTest, MultiProxyChainNotForIpProtectionInvalidProxyChain) {
  ProxyChain invalid_chain =
      ProxyChain({ProxyUriToProxyServer("foo:11", ProxyServer::SCHEME_HTTPS),
                  ProxyUriToProxyServer("hoo:11", ProxyServer::SCHEME_HTTPS)});

  EXPECT_FALSE(invalid_chain.IsValid());
}
#else  // BUILDFLAG(ENABLE_BRACKETED_PROXY_URIS)
TEST(ProxyChainTest, MultiProxyChain) {
  auto proxy_server1 =
      ProxyUriToProxyServer("foo:333", ProxyServer::SCHEME_HTTPS);
  auto proxy_server2 =
      ProxyUriToProxyServer("foo:444", ProxyServer::SCHEME_HTTPS);
  auto proxy_server3 =
      ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS);

  std::vector<ProxyServer> proxy_servers = {proxy_server1, proxy_server2,
                                            proxy_server3};
  auto proxy = ProxyChain(proxy_servers);

  EXPECT_FALSE(proxy.is_direct());
  EXPECT_FALSE(proxy.is_single_proxy());
  EXPECT_TRUE(proxy.is_multi_proxy());
  ASSERT_EQ(proxy.proxy_servers(), proxy_servers);
  ASSERT_EQ(proxy.length(), 3u);
  ASSERT_EQ(proxy.GetProxyServer(0), proxy_server1);
  ASSERT_EQ(proxy.GetProxyServer(1), proxy_server2);
  ASSERT_EQ(proxy.GetProxyServer(2), proxy_server3);

  // Ensure that proxy chains are equal even if one is for IP Protection.
  auto regular_proxy_chain = ProxyChain({proxy_server1, proxy_server2});
  auto ip_protection_proxy_chain =
      ProxyChain::ForIpProtection({proxy_server1, proxy_server2});
  EXPECT_TRUE(ip_protection_proxy_chain.is_for_ip_protection());
  EXPECT_EQ(regular_proxy_chain.proxy_servers(),
            ip_protection_proxy_chain.proxy_servers());
}

TEST(ProxyChainTest, MultiProxyChainsCanBeConvertedToForIpProtection) {
  ProxyChain proxy_chain =
      ProxyChain({ProxyUriToProxyServer("foo:555", ProxyServer::SCHEME_HTTPS),
                  ProxyUriToProxyServer("foo:666", ProxyServer::SCHEME_HTTPS)});
  ProxyChain copied_proxy_chain = proxy_chain;

  // Assert the proxy chain is currently not for ip protection.
  EXPECT_FALSE(proxy_chain.is_for_ip_protection());
  EXPECT_EQ(proxy_chain.ip_protection_chain_id(),
            ProxyChain::kNotIpProtectionChainId);

  // Convert proxy_chain to be for IP protection.
  proxy_chain =
      ProxyChain::ForIpProtection(std::move(proxy_chain.proxy_servers()));

  // Assert proxy_chain now shows it is for IP protection while copied proxy
  // chain still isn't.
  EXPECT_TRUE(proxy_chain.is_for_ip_protection());
  EXPECT_EQ(proxy_chain.ip_protection_chain_id(),
            ProxyChain::kDefaultIpProtectionChainId);
  EXPECT_FALSE(copied_proxy_chain.is_for_ip_protection());
  EXPECT_EQ(copied_proxy_chain.ip_protection_chain_id(),
            ProxyChain::kNotIpProtectionChainId);

  // Ensure servers contained are still equal.
  EXPECT_EQ(proxy_chain.proxy_servers(), copied_proxy_chain.proxy_servers());
}

TEST(ProxyChainTest, PickleTwoProxies) {
  ProxyChain proxy_chain =
      ProxyChain({ProxyUriToProxyServer("foo:11", ProxyServer::SCHEME_HTTPS),
                  ProxyUriToProxyServer("foo:22", ProxyServer::SCHEME_HTTPS)});
  base::Pickle pickle;
  proxy_chain.Persist(&pickle);
  base::PickleIterator iter(pickle);
  ProxyChain proxy_chain_from_pickle;
  EXPECT_TRUE(proxy_chain_from_pickle.InitFromPickle(&iter));
  EXPECT_EQ(proxy_chain, proxy_chain_from_pickle);
}
#endif

}  // namespace

}  // namespace net

"""

```