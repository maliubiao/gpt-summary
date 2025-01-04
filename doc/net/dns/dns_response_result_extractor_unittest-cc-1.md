Response:
The user wants to understand the functionality of the provided C++ code snippet from `dns_response_result_extractor_unittest.cc`. This is the second part of a four-part series, so the focus should be on summarizing the functionality demonstrated within this specific snippet.

The code consists of several test cases (`TEST_F`) within a Google Test framework. Each test case focuses on a specific scenario related to extracting information from DNS responses, particularly for `SRV` and `HTTPS` record types.

Here's a breakdown of the functionalities demonstrated in this part:

1. **SRV Record Handling:**
    - Tests the scenario where an `SRV` response has no TTL (Time-to-Live), resulting in empty extracted results as it's not cacheable.

2. **Basic HTTPS Record Extraction:**
    - Verifies the extraction of basic `HTTPS` record information, including priority, ALPN (Application-Layer Protocol Negotiation), and the setting of expiration times based on the record's TTL.

3. **Comprehensive HTTPS Record Extraction:**
    - Demonstrates the extraction of more complex `HTTPS` record details, including multiple ALPN values and ECH (Encrypted Client Hello) configuration. It also shows how multiple `HTTPS` records with different priorities are handled and ordered.

4. **Ignoring HTTPS Records with Aliases:**
    - Tests scenarios where `HTTPS` responses contain `ALIAS` records (like `CNAME`). It confirms that these aliases are noted, but if there's no directly usable `HTTPS` data, an empty metadata result is returned, but the expiration time from the alias is still respected for caching purposes.

5. **Handling `no-default-alpn` Parameter:**
    - Shows that if all `HTTPS` records in a response have the `no-default-alpn` parameter set, the entire response is effectively ignored, leading to an empty metadata result.

6. **Ignoring Unsupported HTTPS Parameters:**
    - Confirms that unknown or unsupported parameters in an `HTTPS` record are ignored if they are not marked as mandatory.

7. **Ignoring HTTPS Records with Mandatory Unsupported Parameters:**
    - Demonstrates that if an unsupported parameter in an `HTTPS` record is marked as mandatory, that specific record is ignored, but other valid records in the response are still processed.

8. **Service Name Matching in HTTPS Records:**
    - Tests the extraction of `HTTPS` records where the `service_name` parameter matches the queried domain name or is the default (".") or matches in aliasing scenarios.

9. **Ignoring HTTPS Records with Non-Matching Service Names:**
    - Shows that `HTTPS` records with `service_name` values that don't match the queried domain are ignored.

10. **HTTPS Record Extraction with Ports:**
    - Verifies that the extractor can handle `HTTPS` records with explicit port numbers and only extracts the record if the requested port matches.

11. **Handling HTTPS Records with No ALPN and `no-default-alpn`:**
    - Tests that `HTTPS` records with the `no-default-alpn` parameter set but without an `alpn` parameter are considered inconsistent and are ignored.

12. **Handling NXDOMAIN and NODATA Responses for HTTPS:**
    - Checks how the extractor processes `NXDOMAIN` (non-existent domain) and `NODATA` (no records of the requested type) responses for `HTTPS` queries, resulting in error results with appropriate expiration times.

13. **Handling NODATA Responses without TTL:**
    - Shows that `NODATA` responses for `HTTPS` without a TTL are not cached, resulting in an empty result.

14. **Rejecting Malformed HTTPS Records:**
    - Tests the scenario where an `HTTPS` record has malformed RDATA (resource data), and confirms that the extractor handles this gracefully.

Based on these observations, the core functionality of this part of the code is to rigorously test the `DnsResponseResultExtractor` class's ability to correctly parse and extract relevant information from various forms of DNS responses, specifically focusing on `SRV` and `HTTPS` records, while also handling edge cases like missing TTLs, unsupported parameters, and error responses.
这是`net/dns/dns_response_result_extractor_unittest.cc` 文件的一部分， 主要的功能是**测试 `DnsResponseResultExtractor` 类在处理不同类型的 DNS 响应时，能否正确地提取出需要的信息，特别是针对 `SRV` 和 `HTTPS` 记录**。

以下是对这段代码功能的归纳：

**主要功能归纳：**

* **测试 `SRV` 记录的提取：**  测试了当 `SRV` 记录没有 TTL (Time To Live) 时，提取器是否会返回空结果。这是因为没有 TTL 的记录通常不应该被缓存。
* **测试基本的 `HTTPS` 记录提取：**  验证了提取器能够从 `HTTPS` 记录中提取出优先级、ALPN (Application-Layer Protocol Negotiation) 等基本信息，并正确设置缓存过期时间。
* **测试全面的 `HTTPS` 记录提取：**  测试了提取器处理包含多个 ALPN 值和 ECH (Encrypted Client Hello) 配置的复杂 `HTTPS` 记录的能力。
* **测试忽略包含别名 (ALIAS) 的 `HTTPS` 记录：**  验证了当 `HTTPS` 响应中包含别名记录（例如 `CNAME`）时，提取器会忽略 `HTTPS` 记录本身的数据，但仍会考虑别名的 TTL 来设置缓存过期时间。
* **测试忽略包含 `no-default-alpn` 参数的 `HTTPS` 记录：**  如果 `HTTPS` 记录中包含 `no-default-alpn` 参数，指示不支持默认的 ALPN 协议，提取器会忽略这些记录。
* **测试忽略 `HTTPS` 记录中不支持的参数：**  验证了提取器会忽略 `HTTPS` 记录中不认识的或不支持的参数（如果这些参数不是强制性的）。
* **测试忽略包含强制性不支持参数的 `HTTPS` 记录：** 如果 `HTTPS` 记录中包含一个被标记为强制性的不支持的参数，则整个记录会被忽略。
* **测试提取 `service_name` 匹配的 `HTTPS` 记录：** 验证了提取器能够正确提取 `service_name` 与查询域名匹配的 `HTTPS` 记录。这包括完全匹配、使用默认的 "." 以及在存在别名的情况下匹配。
* **测试忽略 `service_name` 不匹配的 `HTTPS` 记录：**  验证了当 `HTTPS` 记录中的 `service_name` 与查询域名不匹配时，提取器会忽略这些记录。
* **测试带端口匹配的 `HTTPS` 记录提取：** 验证了提取器能够处理带有端口信息的 `HTTPS` 记录，并且只有当请求的端口与记录中的端口匹配时才会提取。
* **测试忽略端口不匹配的 `HTTPS` 记录：**  验证了当 `HTTPS` 记录中的端口与请求的端口不匹配时，提取器会忽略这些记录。
* **测试忽略缺少 `alpn` 的 `no-default-alpn` `HTTPS` 记录：**  如果 `HTTPS` 记录设置了 `no-default-alpn` 但没有提供任何 `alpn` 值，提取器会认为记录不一致并忽略它。
* **测试忽略所有兼容默认 ALPN 的 `HTTPS` 响应：** 测试了在多种情况下（例如不支持的参数、端口不匹配、服务名不匹配）导致 `HTTPS` 记录不兼容默认 ALPN 时，提取器会忽略这些记录。
* **测试 `NXDOMAIN` 和 `NODATA` `HTTPS` 响应的提取：**  验证了提取器能够正确处理 `NXDOMAIN` (域名不存在) 和 `NODATA` (存在域名但没有请求的记录类型) 的 `HTTPS` 响应，并生成相应的错误结果。
* **测试没有 TTL 的 `NODATA` `HTTPS` 响应：** 验证了当 `NODATA` 响应中没有 TTL 信息时，提取器不会缓存结果。
* **测试拒绝解析格式错误的 `HTTPS` 记录：**  验证了当遇到格式错误的 `HTTPS` 记录时，提取器能够正确地处理。

**与 JavaScript 的关系：**

这段 C++ 代码主要处理网络栈底层的 DNS 解析逻辑，直接与 JavaScript 没有直接关系。但是，当 JavaScript 代码（例如在 Chrome 浏览器中运行的网页）需要访问一个使用 HTTPS 的域名时，底层的网络栈会执行 DNS 查询。`DnsResponseResultExtractor` 的功能就是在这个过程中，解析 DNS 服务器返回的 `HTTPS` 记录，从而告诉浏览器该如何建立安全的 HTTPS 连接。

例如，如果一个网站配置了 `HTTPS` 记录，指定了支持的 ALPN 协议（例如 "h2" 代表 HTTP/2），那么 `DnsResponseResultExtractor` 会提取这些信息，然后 Chrome 浏览器就可以在与服务器建立连接时，优先选择这些协议。

**假设输入与输出 (针对 `ExtractsBasicHttpsResponses` 测试用例):**

**假设输入:**

一个 DNS 响应 ( `DnsResponse` 对象) 包含以下信息：

* 查询的域名: "https.test"
* 记录类型: `HTTPS`
* 回答部分包含一个 `HTTPS` 记录，内容如下：
    * 优先级: 4
    * 服务名: "." (表示与查询域名相同)
    * 参数: 空
    * TTL: 12 小时

**预期输出:**

一个包含 `HostResolverInternalResult` 的 `ResultsOrError` 对象，其中：

* 类型为 `HostResolverInternalMetadataResult`
* 对应的域名为 "https.test"
* 查询类型为 `HTTPS`
* 来源为 `kDnsSource`
* 过期时间为当前时间加上 12 小时
* 元数据部分包含一个条目，优先级为 4，包含 `ConnectionEndpointMetadata`，其中：
    * ALPN 列表包含 `dns_protocol::kHttpsServiceDefaultAlpn` (通常是 "h3" 或 "h2")
    * ECH 配置列表为空
    * 服务名为 "https.test"

**用户或编程常见使用错误：**

虽然这段代码是测试代码，但它反映了在 DNS 配置中可能出现的问题：

* **忘记设置 TTL：**  如果 DNS 管理员配置 `SRV` 或 `HTTPS` 记录时忘记设置 TTL，可能会导致客户端不会缓存这些记录，从而增加 DNS 查询的次数。测试用例 `ExtractsSrvResponsesWithoutTtl` 就体现了这一点。
* **配置了不兼容的 `HTTPS` 记录：**  例如，错误地配置了 mandatory 但浏览器不支持的参数，或者配置了端口与实际服务不符的 `HTTPS` 记录。测试用例 `IgnoresHttpsRecordWithUnsupportedMandatoryParam` 和 `IgnoresHttpsRecordWithMismatchingPort` 就覆盖了这些场景。
* **`service_name` 配置错误：**  在 `HTTPS` 记录中，`service_name` 应该与实际提供服务的域名匹配。如果配置错误，浏览器可能无法正确使用这些记录。测试用例 `IgnoreHttpsRecordWithNonMatchingServiceName` 演示了这种情况。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个以 `https://` 开头的网址，例如 `https://https.test`。**
2. **浏览器需要解析 `https.test` 的 IP 地址。**
3. **浏览器发起一个 DNS 查询请求，请求 `https.test` 的 A 或 AAAA 记录，以及 `_https.https.test` 的 `HTTPS` 记录。**
4. **操作系统或配置的 DNS 服务器收到请求，并向权威 DNS 服务器查询。**
5. **权威 DNS 服务器返回包含 `HTTPS` 记录的 DNS 响应。**
6. **Chrome 浏览器的网络栈接收到 DNS 响应。**
7. **`DnsResponseResultExtractor` 类被用来解析这个 DNS 响应。**  相关代码就在这个文件中进行单元测试，确保解析器能够正确处理各种可能的 `HTTPS` 记录配置。

这段代码的功能是确保 Chrome 浏览器能够正确理解和利用 DNS 中 `SRV` 和 `HTTPS` 记录的信息，从而优化网络连接，特别是 HTTPS 连接的建立。通过大量的单元测试，可以保证在各种复杂的 DNS 响应场景下，提取器都能正常工作。

Prompt: 
```
这是目录为net/dns/dns_response_result_extractor_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
gTypeSrvResponses) {
  constexpr char kName[] = "name.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeSRV,
      {BuildTestAddressRecord(kName, IPAddress(1, 2, 3, 4))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::SRV,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty results because NODATA is not cacheable (due to no TTL).
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(), IsEmpty());
}

TEST_F(DnsResponseResultExtractorTest, ExtractsBasicHttpsResponses) {
  constexpr char kName[] = "https.test";
  constexpr auto kTtl = base::Hours(12);

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeHttps,
                           {BuildTestHttpsServiceRecord(kName,
                                                        /*priority=*/4,
                                                        /*service_name=*/".",
                                                        /*params=*/{}, kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          Eq(tick_clock_.NowTicks() + kTtl), Eq(clock_.Now() + kTtl),
          ElementsAre(
              Pair(4, ExpectConnectionEndpointMetadata(
                          ElementsAre(dns_protocol::kHttpsServiceDefaultAlpn),
                          /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsComprehensiveHttpsResponses) {
  constexpr char kName[] = "https.test";
  constexpr char kAlpn[] = "foo";
  constexpr uint8_t kEchConfig[] = "EEEEEEEEECH!";
  constexpr auto kTtl = base::Hours(12);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(
           kName, /*priority=*/4,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({kAlpn}),
            BuildTestHttpsServiceEchConfigParam(kEchConfig)},
           kTtl),
       BuildTestHttpsServiceRecord(
           kName, /*priority=*/3,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({kAlpn}),
            {dns_protocol::kHttpsServiceParamKeyNoDefaultAlpn, ""}},
           /*ttl=*/base::Days(3))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          Eq(tick_clock_.NowTicks() + kTtl), Eq(clock_.Now() + kTtl),
          ElementsAre(
              Pair(3, ExpectConnectionEndpointMetadata(
                          ElementsAre(kAlpn),
                          /*ech_config_list_matcher=*/IsEmpty(), kName)),
              Pair(4, ExpectConnectionEndpointMetadata(
                          ElementsAre(kAlpn,
                                      dns_protocol::kHttpsServiceDefaultAlpn),
                          ElementsAreArray(kEchConfig), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest, IgnoresHttpsResponseWithJustAlias) {
  constexpr char kName[] = "https.test";
  constexpr base::TimeDelta kTtl = base::Days(5);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsAliasRecord(kName, "alias.test", kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty metadata result to signify compatible HTTPS records with no
  // data of use to Chrome. Still expect expiration from record, so the empty
  // response can be cached.
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kTtl),
          /*metadatas_matcher=*/IsEmpty()))));
}

TEST_F(DnsResponseResultExtractorTest, IgnoresHttpsResponseWithAlias) {
  constexpr char kName[] = "https.test";
  constexpr base::TimeDelta kLowestTtl = base::Minutes(32);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kName,
                                   /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/{}, base::Days(1)),
       BuildTestHttpsAliasRecord(kName, "alias.test", kLowestTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty metadata result to signify compatible HTTPS records with no
  // data of use to Chrome. Expiration should match lowest TTL from all
  // compatible records.
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kLowestTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kLowestTtl),
          /*metadatas_matcher=*/IsEmpty()))));
}

// Expect the entire response to be ignored if all HTTPS records have the
// "no-default-alpn" param.
TEST_F(DnsResponseResultExtractorTest, IgnoresHttpsResponseWithNoDefaultAlpn) {
  constexpr char kName[] = "https.test";
  constexpr base::TimeDelta kLowestTtl = base::Hours(3);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(
           kName, /*priority=*/4,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({"foo1"}),
            {dns_protocol::kHttpsServiceParamKeyNoDefaultAlpn, ""}},
           kLowestTtl),
       BuildTestHttpsServiceRecord(
           kName, /*priority=*/5,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({"foo2"}),
            {dns_protocol::kHttpsServiceParamKeyNoDefaultAlpn, ""}},
           base::Days(3))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty metadata result to signify compatible HTTPS records with no
  // data of use to Chrome.
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kLowestTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kLowestTtl),
          /*metadatas_matcher=*/IsEmpty()))));
}

// Unsupported/unknown HTTPS params are simply ignored if not marked mandatory.
TEST_F(DnsResponseResultExtractorTest, IgnoresUnsupportedParamsInHttpsRecord) {
  constexpr char kName[] = "https.test";
  constexpr uint16_t kMadeUpParamKey = 65500;  // From the private-use block.

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kName, /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {{kMadeUpParamKey, "foo"}})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Ne(std::nullopt),
          /*timed_expiration_matcher=*/Ne(std::nullopt),
          ElementsAre(
              Pair(4, ExpectConnectionEndpointMetadata(
                          ElementsAre(dns_protocol::kHttpsServiceDefaultAlpn),
                          /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

// Entire record is dropped if an unsupported/unknown HTTPS param is marked
// mandatory.
TEST_F(DnsResponseResultExtractorTest,
       IgnoresHttpsRecordWithUnsupportedMandatoryParam) {
  constexpr char kName[] = "https.test";
  constexpr uint16_t kMadeUpParamKey = 65500;  // From the private-use block.
  constexpr base::TimeDelta kTtl = base::Days(5);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(
           kName, /*priority=*/4,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({"ignored_alpn"}),
            BuildTestHttpsServiceMandatoryParam({kMadeUpParamKey}),
            {kMadeUpParamKey, "foo"}},
           base::Hours(2)),
       BuildTestHttpsServiceRecord(
           kName, /*priority=*/5,
           /*service_name=*/".",
           /*params=*/{BuildTestHttpsServiceAlpnParam({"foo"})}, kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());

  // Expect expiration to be derived only from non-ignored records.
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kTtl),
          ElementsAre(Pair(
              5, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest,
       ExtractsHttpsRecordWithMatchingServiceName) {
  constexpr char kName[] = "https.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kName, /*priority=*/4,
                                   /*service_name=*/kName,
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Ne(std::nullopt),
          /*timed_expiration_matcher=*/Ne(std::nullopt),
          ElementsAre(Pair(
              4, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest,
       ExtractsHttpsRecordWithMatchingDefaultServiceName) {
  constexpr char kName[] = "https.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kName, /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Ne(std::nullopt),
          /*timed_expiration_matcher=*/Ne(std::nullopt),
          ElementsAre(Pair(
              4, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest,
       ExtractsHttpsRecordWithPrefixedNameAndMatchingServiceName) {
  constexpr char kName[] = "https.test";
  constexpr char kPrefixedName[] = "_444._https.https.test";

  DnsResponse response = BuildTestDnsResponse(
      kPrefixedName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kPrefixedName, /*priority=*/4,
                                   /*service_name=*/kName,
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kPrefixedName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Ne(std::nullopt),
          /*timed_expiration_matcher=*/Ne(std::nullopt),
          ElementsAre(Pair(
              4, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest,
       ExtractsHttpsRecordWithAliasingAndMatchingServiceName) {
  constexpr char kName[] = "https.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestCnameRecord(kName, "alias.test"),
       BuildTestHttpsServiceRecord("alias.test", /*priority=*/4,
                                   /*service_name=*/kName,
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::HTTPS, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "alias.test")),
          Pointee(ExpectHostResolverInternalMetadataResult(
              "alias.test", DnsQueryType::HTTPS, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              ElementsAre(Pair(
                  4, ExpectConnectionEndpointMetadata(
                         ElementsAre("foo",
                                     dns_protocol::kHttpsServiceDefaultAlpn),
                         /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest,
       IgnoreHttpsRecordWithNonMatchingServiceName) {
  constexpr char kName[] = "https.test";
  constexpr base::TimeDelta kTtl = base::Hours(14);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(
           kName, /*priority=*/4,
           /*service_name=*/"other.service.test",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({"ignored"})}, base::Hours(3)),
       BuildTestHttpsServiceRecord("https.test", /*priority=*/5,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})},
                                   kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());

  // Expect expiration to be derived only from non-ignored records.
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kTtl),
          ElementsAre(Pair(
              5, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest,
       ExtractsHttpsRecordWithPrefixedNameAndDefaultServiceName) {
  constexpr char kPrefixedName[] = "_445._https.https.test";

  DnsResponse response = BuildTestDnsResponse(
      kPrefixedName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kPrefixedName, /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/"https.test",
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kPrefixedName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Ne(std::nullopt),
          /*timed_expiration_matcher=*/Ne(std::nullopt),
          ElementsAre(Pair(
              4,
              ExpectConnectionEndpointMetadata(
                  ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                  /*ech_config_list_matcher=*/IsEmpty(), kPrefixedName)))))));
}

TEST_F(DnsResponseResultExtractorTest,
       ExtractsHttpsRecordWithAliasingAndDefaultServiceName) {
  constexpr char kName[] = "https.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestCnameRecord(kName, "alias.test"),
       BuildTestHttpsServiceRecord("alias.test", /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::HTTPS, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "alias.test")),
          Pointee(ExpectHostResolverInternalMetadataResult(
              "alias.test", DnsQueryType::HTTPS, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              ElementsAre(Pair(
                  4, ExpectConnectionEndpointMetadata(
                         ElementsAre("foo",
                                     dns_protocol::kHttpsServiceDefaultAlpn),
                         /*ech_config_list_matcher=*/IsEmpty(),
                         "alias.test")))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsHttpsRecordWithMatchingPort) {
  constexpr char kName[] = "https.test";
  constexpr uint16_t kPort = 4567;

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kName, /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"}),
                                    BuildTestHttpsServicePortParam(kPort)})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/kPort);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Ne(std::nullopt),
          /*timed_expiration_matcher=*/Ne(std::nullopt),
          ElementsAre(Pair(
              4, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest, IgnoresHttpsRecordWithMismatchingPort) {
  constexpr char kName[] = "https.test";
  constexpr base::TimeDelta kTtl = base::Days(14);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(kName, /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"ignored"}),
                                    BuildTestHttpsServicePortParam(1003)},
                                   base::Hours(12)),
       BuildTestHttpsServiceRecord(kName, /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})},
                                   kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/55);

  ASSERT_TRUE(results.has_value());

  // Expect expiration to be derived only from non-ignored records.
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kTtl),
          ElementsAre(Pair(
              4, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

// HTTPS records with "no-default-alpn" but also no "alpn" are not
// "self-consistent" and should be ignored.
TEST_F(DnsResponseResultExtractorTest, IgnoresHttpsRecordWithNoAlpn) {
  constexpr char kName[] = "https.test";
  constexpr base::TimeDelta kTtl = base::Minutes(150);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(
           kName, /*priority=*/4,
           /*service_name=*/".",
           /*params=*/
           {{dns_protocol::kHttpsServiceParamKeyNoDefaultAlpn, ""}},
           base::Minutes(10)),
       BuildTestHttpsServiceRecord(kName, /*priority=*/4,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo"})},
                                   kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/55);

  ASSERT_TRUE(results.has_value());

  // Expect expiration to be derived only from non-ignored records.
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kTtl),
          ElementsAre(Pair(
              4, ExpectConnectionEndpointMetadata(
                     ElementsAre("foo", dns_protocol::kHttpsServiceDefaultAlpn),
                     /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

// Expect the entire response to be ignored if all HTTPS records have the
// "no-default-alpn" param.
TEST_F(DnsResponseResultExtractorTest,
       IgnoresHttpsResponseWithNoCompatibleDefaultAlpn) {
  constexpr char kName[] = "https.test";
  constexpr uint16_t kMadeUpParamKey = 65500;  // From the private-use block.
  constexpr base::TimeDelta kLowestTtl = base::Days(2);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsServiceRecord(
           kName, /*priority=*/4,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({"foo1"}),
            {dns_protocol::kHttpsServiceParamKeyNoDefaultAlpn, ""}},
           base::Days(3)),
       BuildTestHttpsServiceRecord(
           kName, /*priority=*/5,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({"foo2"}),
            {dns_protocol::kHttpsServiceParamKeyNoDefaultAlpn, ""}},
           base::Days(4)),
       // Allows default ALPN, but ignored due to non-matching service name.
       BuildTestHttpsServiceRecord(kName, /*priority=*/3,
                                   /*service_name=*/"other.test",
                                   /*params=*/{}, kLowestTtl),
       // Allows default ALPN, but ignored due to incompatible param.
       BuildTestHttpsServiceRecord(
           kName, /*priority=*/6,
           /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceMandatoryParam({kMadeUpParamKey}),
            {kMadeUpParamKey, "foo"}},
           base::Hours(1)),
       // Allows default ALPN, but ignored due to mismatching port.
       BuildTestHttpsServiceRecord(
           kName, /*priority=*/10,
           /*service_name=*/".",
           /*params=*/{BuildTestHttpsServicePortParam(1005)}, base::Days(5))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());

  // Expect expiration to be from the lowest TTL from the "compatible" records
  // that don't have incompatible params.
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          /*expiration_matcher=*/Optional(tick_clock_.NowTicks() + kLowestTtl),
          /*timed_expiration_matcher=*/Optional(clock_.Now() + kLowestTtl),
          /*metadatas_matcher=*/IsEmpty()))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNxdomainHttpsResponses) {
  constexpr char kName[] = "https.test";
  constexpr auto kTtl = base::Minutes(45);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)},
      /*additional=*/{}, dns_protocol::kRcodeNXDOMAIN);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::HTTPS, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNodataHttpsResponses) {
  constexpr char kName[] = "https.test";
  constexpr auto kTtl = base::Hours(36);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::HTTPS, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNodataHttpsResponsesWithoutTtl) {
  constexpr char kName[] = "https.test";

  // Response without a TTL-containing SOA record.
  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeHttps, /*answers=*/{});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty result because not cacheable.
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(), IsEmpty());
}

TEST_F(DnsResponseResultExtractorTest, RejectsMalformedHttpsRecord) {
  constexpr char kName[] = "https.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestDnsRecord(kName, dns_protocol::kTypeHttps,
                          "malformed rdata")} /* answers */);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::HTTPS,
                                   /*original_domain_name=*/kName,
             
"""


```