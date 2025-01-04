Response:
Let's break down the thought process for analyzing this C++ test file for Chromium's network stack.

**1. Initial Understanding of the File's Purpose:**

The file name `host_resolver_manager_unittest.cc` immediately suggests this is a unit test file for the `HostResolverManager` component. The `.cc` extension confirms it's C++ code. Unit tests are designed to verify the functionality of individual units (classes, functions) of code in isolation.

**2. Identifying Key Components and Concepts:**

Scanning through the code, several important elements emerge:

* **`HostResolverManager`:** This is the core component being tested. It's responsible for resolving hostnames to IP addresses.
* **`HostResolver`:**  An interface or class that interacts with the `HostResolverManager`. The tests create requests using `resolver_->CreateRequest(...)`.
* **`HostCache`:**  A cache for storing previously resolved hostnames and their IP addresses to improve performance. The tests directly interact with the cache (`resolve_context_->host_cache()`).
* **`DnsClient` (mocked):**  The code interacts with a mock DNS client (`mock_dns_client_`). This indicates that the tests are not directly hitting a real DNS server but using a controlled environment. This is crucial for unit testing to ensure predictability.
* **`MockDnsClientRule`:**  Used to configure the behavior of the mock DNS client, allowing tests to simulate different DNS responses (success, failure, specific IP addresses).
* **`SecureDnsPolicy`:**  Specifically the `kBootstrap` policy, which indicates a particular mode of DNS resolution involving fetching secure DNS server addresses.
* **`NetworkAnonymizationKey`:**  Likely related to privacy features, used as a key in DNS lookups and caching.
* **`DnsQueryType`:**  Specifies the type of DNS query (e.g., A for IPv4, AAAA for IPv6, HTTPS for SVCB records).
* **`HostResolverSource`:**  Indicates the source of the resolution (e.g., DNS, cache).
* **`IPEndPoint` and `IPAddress`:** Represent network endpoints (IP address and port).
* **`AddressList`:** A collection of `IPEndPoint` objects.
* **Matchers (e.g., `ElementsAre`, `Pointee`, `AddressesMatch`):**  Used with Google Test (`EXPECT_THAT`) to make assertions about the state of objects and data structures.

**3. Analyzing Test Cases:**

The code consists of multiple test cases, each focusing on a specific aspect of the `HostResolverManager`'s behavior. Key observations about the tests:

* **Caching:** Several tests (`HTTPSRRStoredInCacheTest`, `InsecureCacheEntry`, `SecureCacheEntry`) explicitly test the interaction with the `HostCache`.
* **DNS Query Types:** Tests use different `DnsQueryType` values to verify handling of different record types.
* **Secure DNS Bootstrap:**  The `HostResolverManagerBootstrapTest` suite is dedicated to testing the bootstrap mechanism for secure DNS. These tests involve simulating different scenarios with the mock DNS client and cache.
* **IPv6-Only Networks:**  The `IPv4AddressLiteralInIPv6OnlyNetworkTest` family of tests checks how IPv4 address literals are handled in IPv6-only network environments, including DNS64 scenarios.
* **Error Handling:**  Tests like `BlankSlateFailure` and `BootstrapFollowupFailure` verify the manager's behavior when DNS resolution fails.

**4. Identifying Potential Relationships with JavaScript:**

The connection to JavaScript isn't immediately obvious within the *code* of this unit test file. However, considering the context of Chromium's network stack:

* **Web Browser Functionality:** The `HostResolverManager` is fundamental to a web browser. When JavaScript code in a web page tries to access a resource (e.g., an image, an API endpoint), the browser needs to resolve the hostname to an IP address. This resolution is handled by components like the `HostResolverManager`.
* **`fetch()` API:**  The `fetch()` API in JavaScript is a common way to make network requests. Behind the scenes, when `fetch("https://example.com")` is called, the browser's network stack, including the `HostResolverManager`, will be involved in resolving `example.com`.
* **`XMLHttpRequest`:** The older `XMLHttpRequest` API also relies on the same underlying network stack.
* **Service Workers:** Service workers can intercept network requests made by JavaScript and thus interact indirectly with the DNS resolution process.

**5. Constructing Examples and Scenarios:**

Based on the identified concepts and test cases, I can now construct concrete examples:

* **Caching:**  If a JavaScript application makes multiple requests to the same domain, the `HostResolverManager`'s caching mechanism (tested in the C++ code) ensures that the DNS lookup isn't repeated for every request, improving performance.
* **Secure DNS Bootstrap:** When a user enables "Secure DNS" in their browser settings, and JavaScript makes a request to an HTTPS site, the `HostResolverManager` (specifically the bootstrap logic being tested) will try to find the IP addresses of secure DNS servers to use for future lookups.
* **IPv6-Only Networks:**  If a user is on an IPv6-only network, and JavaScript tries to connect to an IPv4 address, the `HostResolverManager` (as tested by the `IPv4AddressLiteralInIPv6OnlyNetworkTest` cases) will handle the translation or connection appropriately.

**6. Addressing User and Programming Errors:**

Thinking about how developers and users might encounter issues related to DNS resolution:

* **Typing Errors in URLs:**  Users might mistype a website address in the browser's address bar. This would lead to a DNS lookup failure, which the `HostResolverManager` handles (and the tests likely cover various failure scenarios).
* **Network Connectivity Issues:**  If a user's internet connection is down or if their DNS server is unreachable, DNS resolution will fail.
* **Incorrect DNS Configuration:**  A user might have misconfigured their DNS settings (e.g., using an invalid DNS server).
* **Programming Errors (JavaScript):** While less directly related to *this specific C++ code*, incorrect use of APIs like `fetch()` or `XMLHttpRequest` (e.g., providing an invalid URL) could trigger DNS resolution errors handled by the `HostResolverManager`.

**7. Tracing User Actions to the Code:**

This involves thinking about the flow of actions when a user interacts with a web browser:

1. **User Types URL:** The user enters a URL in the address bar or clicks a link.
2. **Browser Parses URL:** The browser extracts the hostname from the URL.
3. **DNS Resolution Initiation:** The browser's networking component (which includes the `HostResolverManager`) initiates a DNS lookup for the hostname.
4. **`HostResolverManager` Interaction:** The `HostResolverManager` checks its cache. If the hostname isn't cached or the entry is expired, it interacts with the DNS client (or a mock DNS client in tests).
5. **DNS Query:** A DNS query is sent to a DNS server (or simulated by the mock).
6. **DNS Response:** The DNS server (or mock) sends back IP addresses.
7. **Caching (if successful):** The `HostResolverManager` caches the results.
8. **Connection Establishment:** The browser uses the resolved IP address to establish a connection to the server.

**8. Summarizing the File's Function (as the 21st of 21 parts):**

Since this is the final part, the summary should encompass all the functionalities tested across the entire suite of `host_resolver_manager_unittest.cc` files. It's about bringing together all the tested aspects of the `HostResolverManager`.

By following this structured approach, I can systematically analyze the C++ test file, understand its purpose, identify key concepts, relate it to higher-level functionality (like JavaScript interactions), and provide relevant examples and debugging information.
This C++ source code file, `host_resolver_manager_unittest.cc`, is part of the Chromium network stack and specifically focuses on **unit testing the `HostResolverManager` class**.

Here's a breakdown of its functions:

**Core Functionality: Testing the `HostResolverManager`**

The primary goal of this file is to rigorously test the behavior of the `HostResolverManager`. This involves:

* **Resolving Hostnames:** Verifying that the `HostResolverManager` correctly resolves hostnames to IP addresses. This includes testing different scenarios like successful resolutions, failures, and handling of different IP address families (IPv4, IPv6).
* **Caching:** Testing the `HostResolverManager`'s caching mechanism (`HostCache`). This includes verifying that results are cached correctly, that cache lookups work, and that stale entries are handled appropriately.
* **Secure DNS (DNS-over-HTTPS/TLS):**  Specifically, this section tests the "bootstrap" mechanism for Secure DNS. This involves the `HostResolverManager` querying for the IP addresses of secure DNS servers.
* **Handling Different DNS Query Types:** Testing how the manager handles different DNS record types like A (IPv4), AAAA (IPv6), and HTTPS (SVCB records).
* **Network Conditions:** Simulating different network conditions, such as IPv6-only networks, and ensuring the `HostResolverManager` behaves correctly.
* **Error Handling:** Testing how the `HostResolverManager` handles various DNS resolution errors.
* **Concurrency and Asynchronous Operations:** The tests likely cover asynchronous resolution scenarios to ensure the manager handles concurrent requests correctly.
* **Network Anonymization:** The tests use `NetworkAnonymizationKey`, indicating testing around privacy features and how DNS resolution interacts with them.

**Relationship with JavaScript Functionality:**

While this is a C++ file, the `HostResolverManager` is a crucial component that directly impacts how JavaScript in a web browser makes network requests. Here's how they are related:

* **`fetch()` API and `XMLHttpRequest`:** When JavaScript code in a web page uses `fetch()` or `XMLHttpRequest` to make a network request (e.g., `fetch("https://www.example.com")`), the browser's network stack, including the `HostResolverManager`, is responsible for resolving the hostname (`www.example.com`) to an IP address.
* **Secure Contexts (HTTPS):** The tests involving `DnsQueryType::HTTPS` and the Secure DNS bootstrap are directly relevant to how JavaScript in a secure context (HTTPS) benefits from secure DNS resolutions, enhancing privacy and security.
* **Service Workers:** Service workers, which are written in JavaScript, can intercept network requests. When a service worker makes or modifies a request, the underlying DNS resolution is still handled by the `HostResolverManager`.

**Example:**

Imagine a JavaScript application running in a browser.

```javascript
fetch("https://api.example.com/data")
  .then(response => response.json())
  .then(data => console.log(data));
```

When this code executes:

1. The browser's networking code will take the hostname `api.example.com`.
2. The `HostResolverManager` will be invoked to find the IP address of `api.example.com`.
3. If the IP address is in the cache (tested in this file), it will be retrieved quickly.
4. If not, a DNS query will be made (potentially a secure DNS query, as tested in the bootstrap sections).
5. Once the IP address is obtained, a connection to `api.example.com` can be established.

**Logical Inference with Assumptions and Outputs:**

Let's take the `HTTPSRRStoredInCacheTest` as an example:

**Assumption Input:**

1. A DNS query for `kHost` (let's say "example.com") with type HTTPS is made.
2. The DNS server responds with an error indicating HTTPS is the only allowed type (`ERR_DNS_NAME_HTTPS_ONLY`).
3. Subsequently, queries for A and AAAA records for the same host are made and return successful results (IPv4 and IPv6 addresses).

**Logical Inference:**

The test infers that even though the HTTPS query failed, the successful A and AAAA results should be cached. Furthermore, the *metadata* of the failed HTTPS query (the fact it's HTTPS-only) should also be cached.

**Expected Output:**

1. After the initial queries, looking up A and AAAA for `example.com` should return the cached IP addresses.
2. Looking up HTTPS for `example.com` should return the cached metadata indicating the `ERR_DNS_NAME_HTTPS_ONLY` error. This allows the browser to avoid unnecessary queries for HTTPS in the future.

**User or Programming Common Usage Errors:**

* **User Typing Errors:** A user might type `htps://www.example.com` (missing an 't'). The `HostResolverManager` would attempt to resolve `htps://www.example.com`, which is likely an invalid hostname, leading to a DNS resolution error.
* **Incorrect DNS Configuration:** If a user has manually configured their DNS servers with incorrect or non-functional addresses, the `HostResolverManager` will fail to resolve hostnames.
* **Website Configuration Errors (HTTPS-only):** As demonstrated in the `HTTPSRRStoredInCacheTest`, if a website is configured to only accept HTTPS connections and a browser tries to connect via HTTP first, the `HostResolverManager` (and the browser) will learn this and potentially avoid future HTTP attempts.
* **JavaScript Errors (Incorrect URLs):** If a JavaScript developer uses an incorrect or misspelled URL in a `fetch()` call, it will lead to DNS resolution failures handled by the `HostResolverManager`.

**User Operations Leading to This Code (Debugging Clues):**

1. **User types a URL in the address bar and presses Enter.** This is the most common scenario. The browser needs to resolve the hostname.
2. **User clicks a link.** Similar to typing a URL, the browser needs to resolve the hostname in the link.
3. **JavaScript code on a web page makes a network request (using `fetch()` or `XMLHttpRequest`).** This triggers the DNS resolution process.
4. **The browser is configured to use Secure DNS.** This would engage the Secure DNS bootstrap logic tested in the `HostResolverManagerBootstrapTest` section.
5. **The user is on a network with specific characteristics (e.g., IPv6-only).** This would exercise the code paths tested in the `IPv4AddressLiteralInIPv6OnlyNetworkTest` family of tests.

As a debugger, if you're investigating a network issue in Chromium, you might look at the logs and see calls to the `HostResolverManager`. You might step through this C++ code to understand how a particular hostname resolution is being handled, whether it's hitting the cache, performing a DNS query, or encountering an error.

**归纳一下它的功能 (Summary of its Functionality):**

This specific section (part 21 of 21) of `host_resolver_manager_unittest.cc` focuses on testing the following aspects of the `HostResolverManager`:

* **Caching of HTTPS-only DNS responses:**  Verifying that when a DNS query for HTTPS returns an error indicating the domain is HTTPS-only, this information is cached.
* **Secure DNS Bootstrap:** Thoroughly testing the logic for bootstrapping secure DNS, including scenarios with and without cached bootstrap server addresses, and handling both successful and failed bootstrap attempts.
* **Handling IPv4 address literals in IPv6-only networks:** Testing how the `HostResolverManager` handles resolving IPv4 addresses when the network only supports IPv6, including scenarios with DNS64 and potential issues with bad DNS responses.

In the context of the entire `host_resolver_manager_unittest.cc` file, this section contributes to the comprehensive testing of the `HostResolverManager`'s core functionalities, its interaction with the DNS cache, its handling of secure DNS, and its adaptability to different network environments. By having thorough unit tests like these, the Chromium team ensures the reliability and correctness of a critical component of the browser's network stack.

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第21部分，共21部分，请归纳一下它的功能

"""
e_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::A,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::A,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv4Localhost(), 0)))));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 0)))));
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey, DnsQueryType::HTTPS,
      HostResolverSource::DNS, /*secure=*/false));

  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));

  // All responses cached, including the full metadata result because it is
  // still a usable result when requested for https://.
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::A,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::A,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv4Localhost(), 0)))));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 0)))));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::HTTPS,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalMetadataResult(
                  std::string(kHost), DnsQueryType::HTTPS,
                  HostResolverInternalResult::Source::kDns,
                  Optional(base::TimeTicks::Now() + base::Days(20)),
                  Optional(base::Time::Now() + base::Days(20)))));
}

class HostResolverManagerBootstrapTest : public HostResolverManagerDnsTest {
 protected:
  using MockResult = MockDnsClientRule::ResultType;

  void SetUp() override {
    // The request host scheme and port are only preserved if the SVCB feature
    // is enabled.
    features.InitAndEnableFeatureWithParameters(
        features::kUseDnsHttpsSvcb,
        {// Disable timeouts.
         {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
         {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
         {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
         {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
         {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
         {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

    HostResolverManagerDnsTest::SetUp();

    // MockHostResolverProc only returns failure if there is at least one
    // non-matching rule.
    proc_->AddRuleForAllFamilies("other_name", {});
    proc_->SignalMultiple(1u);  // Allow up to one proc query.
  }

  const NetworkAnonymizationKey kAnonymizationKey;
  const url::SchemeHostPort kEndpoint =
      url::SchemeHostPort(url::kHttpsScheme, "bootstrap", 443);
  const std::vector<IPEndPoint> kCacheAddrs = {
      {{0x20, 0x01, 0x0d, 0xb1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 0},
      {{192, 0, 2, 1}, 0}};
  const std::vector<IPEndPoint> kBootstrapAddrs = {
      {{0x20, 0x01, 0x0d, 0xb1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, 0},
      {{192, 0, 2, 2}, 0}};
  // The mock DNS client always returns localhost.
  const std::vector<IPEndPoint> kRemoteAddrs = {
      {IPAddress::IPv6Localhost(), 0},
      {IPAddress::IPv4Localhost(), 0}};

  static HostResolver::ResolveHostParameters bootstrap_params() {
    HostResolver::ResolveHostParameters params;
    params.secure_dns_policy = SecureDnsPolicy::kBootstrap;
    return params;
  }

  void ConfigureMockDns(MockResult insecure_result, MockResult secure_result) {
    MockDnsClientRuleList rules;
    AddDnsRule(&rules, kEndpoint.host(), dns_protocol::kTypeA, insecure_result,
               /*delay=*/false);
    AddDnsRule(&rules, kEndpoint.host(), dns_protocol::kTypeAAAA,
               insecure_result, /*delay=*/false);
    AddSecureDnsRule(&rules, kEndpoint.host(), dns_protocol::kTypeA,
                     secure_result, /*delay=*/false);
    AddSecureDnsRule(&rules, kEndpoint.host(), dns_protocol::kTypeAAAA,
                     secure_result, /*delay=*/false);
    UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
    mock_dns_client_->set_preset_endpoint(kEndpoint);
  }

  HostCache::Key MakeCacheKey(bool secure) {
    HostCache::Key cache_key(kEndpoint, DnsQueryType::UNSPECIFIED, 0,
                             HostResolverSource::ANY, kAnonymizationKey);
    cache_key.secure = secure;
    return cache_key;
  }

  void PopulateCache(bool secure) {
    constexpr base::TimeDelta kTtl = base::Seconds(3600);
    HostCache::Entry entry(OK, kCacheAddrs, /*aliases=*/{},
                           HostCache::Entry::SOURCE_DNS, kTtl);
    resolve_context_->host_cache()->Set(MakeCacheKey(secure), std::move(entry),
                                        GetMockTickClock()->NowTicks(), kTtl);
  }

  base::test::ScopedFeatureList features;
};

std::vector<IPAddress> IPAddresses(const std::vector<IPEndPoint>& endpoints) {
  return base::ToVector(endpoints, &IPEndPoint::address);
}

std::vector<IPAddress> IPAddresses(const AddressList& addresses) {
  return IPAddresses(addresses.endpoints());
}

MATCHER_P(AddressesMatch, expected, "Matches addresses between AddressLists") {
  return testing::Matches(testing::UnorderedElementsAreArray(
      IPAddresses(expected)))(IPAddresses(arg));
}

TEST_F(HostResolverManagerBootstrapTest, BlankSlate) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kOk,
                   /*secure_result=*/MockResult::kUnexpected);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_FALSE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kRemoteAddrs)));
  EXPECT_THAT(bootstrap_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kRemoteAddrs)))));
}

TEST_F(HostResolverManagerBootstrapTest, InsecureCacheEntry) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kUnexpected);
  PopulateCache(/*secure=*/false);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kCacheAddrs)));
  EXPECT_THAT(bootstrap_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kCacheAddrs)))));
}

TEST_F(HostResolverManagerBootstrapTest, SecureCacheEntry) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kUnexpected);
  PopulateCache(/*secure=*/true);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kCacheAddrs)));
  EXPECT_THAT(bootstrap_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kCacheAddrs)))));
}

TEST_F(HostResolverManagerBootstrapTest, OnlyBootstrap) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kOk);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kBootstrapAddrs)));
  EXPECT_THAT(bootstrap_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kBootstrapAddrs)))));

  // Run the followup query.
  RunUntilIdle();

  // Confirm that the remote addresses are now in the secure cache.
  const auto* secure_result = resolve_context_->host_cache()->Lookup(
      MakeCacheKey(/*secure=*/true), GetMockTickClock()->NowTicks());
  ASSERT_THAT(secure_result, testing::NotNull());
  EXPECT_THAT(
      secure_result->second.GetEndpoints(),
      testing::ElementsAre(ExpectEndpointResult(AddressesMatch(kRemoteAddrs))));
}

// The insecure cache is ignored, so the results are identical to
// OnlyBootstrap.
TEST_F(HostResolverManagerBootstrapTest, BootstrapAndInsecureCache) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kOk);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);
  PopulateCache(/*secure=*/false);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kBootstrapAddrs)));
  EXPECT_THAT(bootstrap_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kBootstrapAddrs)))));

  // Run the followup query.
  RunUntilIdle();

  // Confirm that the remote addresses are now in the secure cache.
  const auto* secure_result = resolve_context_->host_cache()->Lookup(
      MakeCacheKey(/*secure=*/true), GetMockTickClock()->NowTicks());
  ASSERT_THAT(secure_result, testing::NotNull());
  EXPECT_THAT(
      secure_result->second.GetEndpoints(),
      testing::ElementsAre(ExpectEndpointResult(AddressesMatch(kRemoteAddrs))));
}

// The bootstrap addrs are ignored, so the results are identical to
// SecureCacheEntry.
TEST_F(HostResolverManagerBootstrapTest, BootstrapAndSecureCacheEntry) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kUnexpected);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);
  PopulateCache(/*secure=*/true);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kCacheAddrs)));
  EXPECT_THAT(bootstrap_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kCacheAddrs)))));
}

TEST_F(HostResolverManagerBootstrapTest, BlankSlateFailure) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kFail,
                   /*secure_result=*/MockResult::kUnexpected);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_FALSE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_FALSE(bootstrap_response.request()
                   ->GetResolveErrorInfo()
                   .is_secure_network_error);
}

TEST_F(HostResolverManagerBootstrapTest, BootstrapFollowupFailure) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kFail);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);

  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response.complete());
  EXPECT_THAT(bootstrap_response.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kBootstrapAddrs)));
  EXPECT_THAT(bootstrap_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kBootstrapAddrs)))));

  // Run the followup query.
  RunUntilIdle();

  // Confirm that the secure cache remains empty.
  const auto* secure_result = resolve_context_->host_cache()->Lookup(
      MakeCacheKey(/*secure=*/true), GetMockTickClock()->NowTicks());
  EXPECT_THAT(secure_result, testing::IsNull());
}

TEST_F(HostResolverManagerBootstrapTest, ContextClose) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kOk);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);

  // Trigger a followup request.
  ResolveHostResponseHelper bootstrap_response(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  // Deregistering the resolve context should clean up the pending followup job.
  EXPECT_EQ(1u, resolver_->num_jobs_for_testing());
  resolver_->DeregisterResolveContext(resolve_context_.get());
  EXPECT_EQ(0u, resolver_->num_jobs_for_testing());

  mock_dns_client_ = nullptr;
  resolver_ = nullptr;  // Avoid duplicate Deregister in TearDown.
}

// Equivalent to OnlyBootstrap + BootstrapAndSecureCacheEntry
TEST_F(HostResolverManagerBootstrapTest, BootstrapAfterFollowup) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kOk);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);

  // Run bootstrap and its followup query.
  ResolveHostResponseHelper bootstrap_response1(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));
  RunUntilIdle();

  // The remote addresses are now in the secure cache.
  // Rerun bootstrap, which reads the secure cache results.
  ResolveHostResponseHelper bootstrap_response2(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response2.complete());
  EXPECT_THAT(bootstrap_response2.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response2.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kRemoteAddrs)));
  EXPECT_THAT(bootstrap_response2.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kRemoteAddrs)))));
}

TEST_F(HostResolverManagerBootstrapTest, BootstrapFollowupFailureTwice) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kFail);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);

  // Run the bootstrap query and the followup, which will fail.
  ResolveHostResponseHelper bootstrap_response1(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));
  RunUntilIdle();

  // Reissue the bootstrap query.
  ResolveHostResponseHelper bootstrap_response2(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response2.complete());
  EXPECT_THAT(bootstrap_response2.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response2.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kBootstrapAddrs)));
  EXPECT_THAT(bootstrap_response2.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kBootstrapAddrs)))));

  // Run the followup query again.
  RunUntilIdle();

  // Confirm that the secure cache remains empty.
  const auto* secure_result = resolve_context_->host_cache()->Lookup(
      MakeCacheKey(/*secure=*/true), GetMockTickClock()->NowTicks());
  EXPECT_THAT(secure_result, testing::IsNull());
}

TEST_F(HostResolverManagerBootstrapTest, OnlyBootstrapTwice) {
  ConfigureMockDns(/*insecure_result=*/MockResult::kUnexpected,
                   /*secure_result=*/MockResult::kOk);
  mock_dns_client_->set_preset_addrs(kBootstrapAddrs);

  ResolveHostResponseHelper bootstrap_response1(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response1.complete());
  EXPECT_THAT(bootstrap_response1.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response1.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kBootstrapAddrs)));
  EXPECT_THAT(bootstrap_response1.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kBootstrapAddrs)))));

  ResolveHostResponseHelper bootstrap_response2(
      resolver_->CreateRequest(kEndpoint, kAnonymizationKey, NetLogWithSource(),
                               bootstrap_params(), resolve_context_.get()));

  EXPECT_TRUE(bootstrap_response2.complete());
  EXPECT_THAT(bootstrap_response2.result_error(), IsOk());
  EXPECT_THAT(bootstrap_response2.request()->GetAddressResults(),
              testing::Pointee(AddressesMatch(kBootstrapAddrs)));
  EXPECT_THAT(bootstrap_response2.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(AddressesMatch(kBootstrapAddrs)))));

  // Run the followup query.
  RunUntilIdle();

  // Confirm that the remote addresses are now in the secure cache.
  const auto* secure_result = resolve_context_->host_cache()->Lookup(
      MakeCacheKey(/*secure=*/true), GetMockTickClock()->NowTicks());
  ASSERT_THAT(secure_result, testing::NotNull());
  EXPECT_THAT(
      secure_result->second.GetEndpoints(),
      testing::ElementsAre(ExpectEndpointResult(AddressesMatch(kRemoteAddrs))));
}

void HostResolverManagerTest::IPv4AddressLiteralInIPv6OnlyNetworkTest(
    bool is_async) {
  HostResolver::ManagerOptions options = DefaultOptions();
  CreateResolverWithOptionsAndParams(std::move(options), DefaultParams(proc_),
                                     true /* ipv6_reachable */, is_async,
                                     false /* ipv4_reachable */);
  proc_->AddRule("ipv4only.arpa", ADDRESS_FAMILY_IPV6,
                 "64:ff9b::c000:aa,64:ff9b::c000:ab,2001:db8:43::c000:aa,"
                 "2001:db8:43::c000:ab");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("192.168.1.42", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.top_level_result_error(), IsOk());
  EXPECT_THAT(
      response.request()->GetAddressResults()->endpoints(),
      testing::ElementsAre(CreateExpected("64:ff9b::c0a8:12a", 80),
                           CreateExpected("2001:db8:43::c0a8:12a", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("64:ff9b::c0a8:12a", 80),
                               CreateExpected("2001:db8:43::c0a8:12a", 80))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());

  ASSERT_TRUE(!proc_->GetCaptureList().empty());
  EXPECT_EQ("ipv4only.arpa", proc_->GetCaptureList()[0].hostname);

  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(HostCache::Key(
          "ipv4only.arpa", DnsQueryType::AAAA, 0 /* host_resolver_flags */,
          HostResolverSource::ANY, NetworkAnonymizationKey()));
  EXPECT_TRUE(cache_result);
}

TEST_F(HostResolverManagerTest, IPv4AddressLiteralInIPv6OnlyNetworkAsync) {
  IPv4AddressLiteralInIPv6OnlyNetworkTest(true);
}

TEST_F(HostResolverManagerTest, IPv4AddressLiteralInIPv6OnlyNetworkSync) {
  IPv4AddressLiteralInIPv6OnlyNetworkTest(false);
}

void HostResolverManagerTest::IPv4AddressLiteralInIPv6OnlyNetworkPort443Test(
    bool is_async) {
  HostResolver::ManagerOptions options = DefaultOptions();
  CreateResolverWithOptionsAndParams(std::move(options), DefaultParams(proc_),
                                     true /* ipv6_reachable */, is_async,
                                     false /* ipv4_reachable */);
  proc_->AddRule("ipv4only.arpa", ADDRESS_FAMILY_IPV6,
                 "64:ff9b::c000:aa,64:ff9b::c000:ab,2001:db8:43::c000:aa,"
                 "2001:db8:43::c000:ab");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("192.168.1.42", 443), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.top_level_result_error(), IsOk());
  EXPECT_THAT(
      response.request()->GetAddressResults()->endpoints(),
      testing::ElementsAre(CreateExpected("64:ff9b::c0a8:12a", 443),
                           CreateExpected("2001:db8:43::c0a8:12a", 443)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::ElementsAre(
                      CreateExpected("64:ff9b::c0a8:12a", 443),
                      CreateExpected("2001:db8:43::c0a8:12a", 443))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());

  ASSERT_TRUE(!proc_->GetCaptureList().empty());
  EXPECT_EQ("ipv4only.arpa", proc_->GetCaptureList()[0].hostname);

  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(HostCache::Key(
          "ipv4only.arpa", DnsQueryType::AAAA, 0 /* host_resolver_flags */,
          HostResolverSource::ANY, NetworkAnonymizationKey()));
  EXPECT_TRUE(cache_result);
}

TEST_F(HostResolverManagerTest,
       IPv4AddressLiteralInIPv6OnlyNetworkPort443Async) {
  IPv4AddressLiteralInIPv6OnlyNetworkPort443Test(true);
}

TEST_F(HostResolverManagerTest,
       IPv4AddressLiteralInIPv6OnlyNetworkPort443Sync) {
  IPv4AddressLiteralInIPv6OnlyNetworkPort443Test(false);
}

void HostResolverManagerTest::IPv4AddressLiteralInIPv6OnlyNetworkNoDns64Test(
    bool is_async) {
  HostResolver::ManagerOptions options = DefaultOptions();
  CreateResolverWithOptionsAndParams(std::move(options), DefaultParams(proc_),
                                     true /* ipv6_reachable */, is_async,
                                     false /* ipv4_reachable */);
  proc_->AddRule("ipv4only.arpa", ADDRESS_FAMILY_IPV6, std::string());
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("192.168.1.42", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.top_level_result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());
}

TEST_F(HostResolverManagerTest,
       IPv4AddressLiteralInIPv6OnlyNetworkNoDns64Async) {
  IPv4AddressLiteralInIPv6OnlyNetworkNoDns64Test(true);
}

TEST_F(HostResolverManagerTest,
       IPv4AddressLiteralInIPv6OnlyNetworkNoDns64Sync) {
  IPv4AddressLiteralInIPv6OnlyNetworkNoDns64Test(false);
}

void HostResolverManagerTest::IPv4AddressLiteralInIPv6OnlyNetworkBadAddressTest(
    bool is_async) {
  HostResolver::ManagerOptions options = DefaultOptions();
  CreateResolverWithOptionsAndParams(std::move(options), DefaultParams(proc_),
                                     true /* ipv6_reachable */, is_async,
                                     false /* ipv4_reachable */);
  proc_->AddRule("ipv4only.arpa", ADDRESS_FAMILY_IPV6, "2001:db8::1");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("192.168.1.42", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.top_level_result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());
}
// Test when DNS returns bad IPv6 address of ipv4only.arpa., and the
// IPv4 address of ipv4only.arpa is not contained in the IPv6 address.
TEST_F(HostResolverManagerTest,
       IPv4AddressLiteralInIPv6OnlyNetworkBadAddressAsync) {
  IPv4AddressLiteralInIPv6OnlyNetworkBadAddressTest(true);
}

TEST_F(HostResolverManagerTest,
       IPv4AddressLiteralInIPv6OnlyNetworkBadAddressSync) {
  IPv4AddressLiteralInIPv6OnlyNetworkBadAddressTest(false);
}

}  // namespace net

"""


```