Response:
The user wants to understand the functionality of the C++ code file `net/dns/dns_response_result_extractor_unittest.cc`.

The file is a unit test file for a class named `DnsResponseResultExtractor`.

I need to analyze the provided test cases to understand the functionality of the `DnsResponseResultExtractor`.

The test cases cover scenarios like:
- Extracting results for different DNS query types (A, TXT, HTTPS).
- Handling CNAME chains (in order, reverse order, arbitrary order).
- Handling errors like malformed records, name mismatch, CNAME loops, etc.
- Ignoring irrelevant records in the DNS response.
- Extracting TTL values.

Regarding the connection to JavaScript, DNS resolution is a fundamental part of web browsing. JavaScript running in a browser relies on the underlying network stack to resolve domain names. While this C++ code doesn't directly interact with JavaScript, it's part of the mechanism that allows JavaScript to load resources from the internet.

For user/programming errors, the test cases demonstrate scenarios that would lead to errors or incorrect results, such as malformed DNS responses or inconsistent data.

To understand how a user reaches this code, I need to consider the path of a DNS query within Chrome's network stack.

Finally, I need to summarize the functionality of the code based on the analyzed test cases.
这是文件 `net/dns/dns_response_result_extractor_unittest.cc` 的第三部分，它延续了对 `DnsResponseResultExtractor` 类的单元测试。从这部分的代码来看，其主要功能集中在测试 `DnsResponseResultExtractor` 如何处理 CNAME 链以及如何正确提取或拒绝包含 CNAME 记录的 DNS 响应结果。

**归纳一下这部分的功能：**

这部分测试主要关注 `DnsResponseResultExtractor` 如何正确解析和处理包含 CNAME (Canonical Name) 记录的 DNS 响应。它测试了以下关键方面：

1. **正确处理各种顺序的 CNAME 链：**  测试用例验证了 `DnsResponseResultExtractor` 能够正确解析按照正序、倒序以及任意顺序排列的 CNAME 记录链，并最终找到最终的资源记录（例如 A 记录或 TXT 记录）。

2. **忽略与 CNAME 链无关的记录：** 测试用例验证了当 DNS 响应中包含与当前 CNAME 链无关的其他类型的记录时，`DnsResponseResultExtractor` 会忽略这些记录，只关注与当前查询类型和 CNAME 链相关的记录。

3. **处理没有最终结果的 CNAME 链：** 测试用例覆盖了 CNAME 链存在但没有找到最终的 A 或 TXT 记录的情况，验证了 `DnsResponseResultExtractor` 能够正确提取 CNAME 别名信息。

4. **拒绝不合法的 CNAME 链：**  测试用例重点验证了 `DnsResponseResultExtractor` 能够识别并拒绝各种不合法的 CNAME 链，包括：
    - **循环引用 (Loop)：** CNAME 记录指向链中之前的域名。
    - **指向起始域名的循环：** CNAME 链最终指向最初查询的域名。
    - **起始域名错误：** 响应中的 CNAME 链没有从最初查询的域名开始。
    - **结果记录名称不匹配：** 最终的 A 或 TXT 记录的域名与 CNAME 链指向的域名不一致。
    - **CNAME 记录与结果记录共享域名：**  CNAME 记录和最终的 A 或 TXT 记录指向同一个域名。
    - **不连续的 CNAME 链：** 响应中存在多条不相关的 CNAME 链。
    - **重复的 CNAME 记录：** 同一个域名存在多条 CNAME 记录。

5. **忽略非结果记录的 TTL：** 测试用例验证了当响应中存在多种类型的记录时，`DnsResponseResultExtractor` 会根据最终结果记录的 TTL 来确定缓存时间，而忽略非结果类型记录的 TTL。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它所实现的功能对于在浏览器中运行的 JavaScript 代码至关重要。

例如，当 JavaScript 代码尝试访问一个域名（比如 `www.example.com`）时，浏览器需要先将其解析为 IP 地址。如果 `www.example.com` 有一个 CNAME 记录指向 `webserver.example.net`，而 `webserver.example.net` 又有一个 CNAME 指向 `cdn.provider.com`，最终 `cdn.provider.com` 指向一个 IP 地址，那么 `DnsResponseResultExtractor` 的工作就是正确地追踪这个 CNAME 链，直到找到最终的 IP 地址。

**举例说明：**

假设 JavaScript 代码尝试加载 `https://first.test/image.png`。

1. **假设输入 DNS 响应 (对应 `TEST_F(DnsResponseResultExtractorTest, HandlesArbitraryOrderCnameChainTypeA)`):**
   - `first.test` 的 CNAME 记录指向 `qsecond.test`
   - `qsecond.test` 的 CNAME 记录指向 `athird.test`
   - `athird.test` 的 CNAME 记录指向 `zfourth.test`
   - `zfourth.test` 的 A 记录是 `192.168.0.1`

2. **逻辑推理：** `DnsResponseResultExtractor` 会按照 CNAME 链进行解析：
   - 查找 `first.test` 的 CNAME 记录，找到 `qsecond.test`。
   - 查找 `qsecond.test` 的 CNAME 记录，找到 `athird.test`。
   - 查找 `athird.test` 的 CNAME 记录，找到 `zfourth.test`。
   - 查找 `zfourth.test` 的 A 记录，找到 `192.168.0.1`。

3. **假设输出：** `DnsResponseResultExtractor` 会提取出以下信息：
   - `first.test` 是 `qsecond.test` 的别名。
   - `qsecond.test` 是 `athird.test` 的别名。
   - `athird.test` 是 `zfourth.test` 的别名。
   - `zfourth.test` 的 IP 地址是 `192.168.0.1`。

**用户或编程常见的使用错误：**

1. **DNS 配置错误导致 CNAME 循环：**  管理员错误地配置 DNS 记录，使得一个域名通过 CNAME 链最终指向自身，例如 `a.com` CNAME 到 `b.com`，`b.com` CNAME 到 `a.com`。`DnsResponseResultExtractor` 会检测到 `ExtractionError::kBadAliasChain` 错误。

2. **DNS 响应数据损坏或格式错误：** 如果 DNS 服务器返回的响应数据不符合规范，例如缺少必要的字段或格式错误，`DnsResponseResultExtractor` 可能会返回 `ExtractionError::kMalformedRecord` 错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问 `https://first.test/index.html`，而 `first.test` 的 DNS 解析涉及到 CNAME 链。

1. **用户在地址栏输入 `https://first.test/index.html` 并回车。**
2. **Chrome 浏览器的网络栈开始进行域名解析。**
3. **网络栈向配置的 DNS 服务器发送查询 `first.test` 的 A 记录的请求。**
4. **DNS 服务器返回包含 CNAME 记录的响应。** 例如：
   ```
   first.test. IN CNAME second.test.
   second.test. IN CNAME third.test.
   third.test. IN A 192.168.1.100
   ```
5. **`DnsResponseResultExtractor` 类被用来解析这个 DNS 响应。** 它会：
   - 提取 `first.test` 的 CNAME 指向 `second.test`。
   - 提取 `second.test` 的 CNAME 指向 `third.test`。
   - 提取 `third.test` 的 A 记录指向 `192.168.1.100`。
6. **如果在这个解析过程中出现任何错误，例如 CNAME 循环，那么 `DnsResponseResultExtractor` 会返回相应的错误码。** 开发者在调试网络连接问题时，可以通过查看 Chrome 的网络日志 (chrome://net-export/) 或者使用 Wireshark 等工具抓包来查看 DNS 响应的内容，并分析 `DnsResponseResultExtractor` 的行为，从而定位 DNS 配置问题。

总而言之，这部分测试深入验证了 `DnsResponseResultExtractor` 在处理复杂 CNAME 链场景下的正确性和健壮性，确保了 Chrome 浏览器能够准确地解析域名，即使域名配置了多层 CNAME 别名。

### 提示词
```
这是目录为net/dns/dns_response_result_extractor_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kMalformedRecord);
}

TEST_F(DnsResponseResultExtractorTest, RejectsWrongNameHttpsRecord) {
  constexpr char kName[] = "https.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestHttpsAliasRecord("different.test", "alias.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::HTTPS,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kNameMismatch);
}

TEST_F(DnsResponseResultExtractorTest, IgnoresWrongTypeHttpsResponses) {
  constexpr char kName[] = "https.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      {BuildTestAddressRecord(kName, IPAddress(1, 2, 3, 4))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(), IsEmpty());
}

TEST_F(DnsResponseResultExtractorTest, IgnoresAdditionalHttpsRecords) {
  constexpr char kName[] = "https.test";
  constexpr auto kTtl = base::Days(5);

  // Give all records an "alpn" value to help validate that only the correct
  // record is used.
  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeHttps,
      /*answers=*/
      {BuildTestHttpsServiceRecord(kName, /*priority=*/5u,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo1"})},
                                   kTtl)},
      /*authority=*/{},
      /*additional=*/
      {BuildTestHttpsServiceRecord(kName, /*priority=*/3u,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo2"})},
                                   base::Minutes(44)),
       BuildTestHttpsServiceRecord(kName, /*priority=*/2u,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo3"})},
                                   base::Minutes(30))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::HTTPS,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(Pointee(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, kDnsSource,
          Eq(tick_clock_.NowTicks() + kTtl), Eq(clock_.Now() + kTtl),
          ElementsAre(Pair(
              5,
              ExpectConnectionEndpointMetadata(
                  ElementsAre("foo1", dns_protocol::kHttpsServiceDefaultAlpn),
                  /*ech_config_list_matcher=*/IsEmpty(), kName)))))));
}

TEST_F(DnsResponseResultExtractorTest, IgnoresUnsolicitedHttpsRecords) {
  constexpr char kName[] = "name.test";
  constexpr auto kTtl = base::Minutes(45);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      /*answers=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeTXT, "\003foo", kTtl)},
      /*authority=*/{},
      /*additional=*/
      {BuildTestHttpsServiceRecord(
           "https.test", /*priority=*/3u, /*service_name=*/".",
           /*params=*/
           {BuildTestHttpsServiceAlpnParam({"foo2"})}, base::Minutes(44)),
       BuildTestHttpsServiceRecord("https.test", /*priority=*/2u,
                                   /*service_name=*/".",
                                   /*params=*/
                                   {BuildTestHttpsServiceAlpnParam({"foo3"})},
                                   base::Minutes(30))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());

  // Expect expiration to be derived only from the non-ignored answer record.
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::TXT, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  /*endpoints_matcher=*/IsEmpty(), ElementsAre("foo")))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesInOrderCnameChain) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord(kName, "second.test"),
                            BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestTextRecord("fourth.test", {"foo"}),
                            BuildTestTextRecord("fourth.test", {"bar"})});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "fourth.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              /*endpoints_matcher=*/IsEmpty(),
              UnorderedElementsAre("foo", "bar")))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesInOrderCnameChainTypeA) {
  constexpr char kName[] = "first.test";

  const IPAddress kExpected(192, 168, 0, 1);
  IPEndPoint expected_endpoint(kExpected, 0 /* port */);

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeA,
                           {BuildTestCnameRecord(kName, "second.test"),
                            BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestAddressRecord("fourth.test", kExpected)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "fourth.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              ElementsAre(expected_endpoint)))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesReverseOrderCnameChain) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestTextRecord("fourth.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "fourth.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              /*endpoints_matcher=*/IsEmpty(), ElementsAre("foo")))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesReverseOrderCnameChainTypeA) {
  constexpr char kName[] = "first.test";

  const IPAddress kExpected(192, 168, 0, 1);
  IPEndPoint expected_endpoint(kExpected, 0 /* port */);

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeA,
                           {BuildTestAddressRecord("fourth.test", kExpected),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "fourth.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              ElementsAre(expected_endpoint)))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesArbitraryOrderCnameChain) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord("fourth.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "fourth.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              /*endpoints_matcher=*/IsEmpty(), ElementsAre("foo")))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesArbitraryOrderCnameChainTypeA) {
  constexpr char kName[] = "first.test";

  const IPAddress kExpected(192, 168, 0, 1);
  IPEndPoint expected_endpoint(kExpected, 0 /* port */);

  // Alias names are chosen so that the chain order is not in alphabetical
  // order.
  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeA,
                           {BuildTestCnameRecord("qsecond.test", "athird.test"),
                            BuildTestAddressRecord("zfourth.test", kExpected),
                            BuildTestCnameRecord("athird.test", "zfourth.test"),
                            BuildTestCnameRecord(kName, "qsecond.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "qsecond.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "qsecond.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "athird.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "athird.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "zfourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "zfourth.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              ElementsAre(expected_endpoint)))));
}

TEST_F(DnsResponseResultExtractorTest,
       IgnoresNonResultTypesMixedWithCnameChain) {
  constexpr char kName[] = "first.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      {BuildTestCnameRecord("second.test", "third.test"),
       BuildTestTextRecord("fourth.test", {"foo"}),
       BuildTestCnameRecord("third.test", "fourth.test"),
       BuildTestAddressRecord("third.test", IPAddress(1, 2, 3, 4)),
       BuildTestCnameRecord(kName, "second.test"),
       BuildTestAddressRecord("fourth.test", IPAddress(2, 3, 4, 5))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "fourth.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              /*endpoints_matcher=*/IsEmpty(), ElementsAre("foo")))));
}

TEST_F(DnsResponseResultExtractorTest,
       IgnoresNonResultTypesMixedWithCnameChainTypeA) {
  constexpr char kName[] = "first.test";

  const IPAddress kExpected(192, 168, 0, 1);
  IPEndPoint expected_endpoint(kExpected, 0 /* port */);

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeA,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord("fourth.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord(kName, "second.test"),
                            BuildTestAddressRecord("fourth.test", kExpected)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test")),
          Pointee(ExpectHostResolverInternalDataResult(
              "fourth.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              ElementsAre(expected_endpoint)))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesCnameChainWithoutResult) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::TXT, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test"))));
}

TEST_F(DnsResponseResultExtractorTest, HandlesCnameChainWithoutResultTypeA) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeA,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "second.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "second.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "third.test")),
          Pointee(ExpectHostResolverInternalAliasResult(
              "third.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "fourth.test"))));
}

TEST_F(DnsResponseResultExtractorTest, RejectsCnameChainWithLoop) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord("third.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "second.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kBadAliasChain);
}

TEST_F(DnsResponseResultExtractorTest, RejectsCnameChainWithLoopToBeginning) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord("third.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "first.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kBadAliasChain);
}

TEST_F(DnsResponseResultExtractorTest,
       RejectsCnameChainWithLoopToBeginningWithoutResult) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestCnameRecord("third.test", "first.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kBadAliasChain);
}

TEST_F(DnsResponseResultExtractorTest, RejectsCnameChainWithWrongStart) {
  constexpr char kName[] = "test.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord("fourth.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord("first.test", "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kBadAliasChain);
}

TEST_F(DnsResponseResultExtractorTest, RejectsCnameChainWithWrongResultName) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord("third.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kNameMismatch);
}

TEST_F(DnsResponseResultExtractorTest, RejectsCnameSharedWithResult) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord(kName, {"foo"}),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kNameMismatch);
}

TEST_F(DnsResponseResultExtractorTest, RejectsDisjointCnameChain) {
  constexpr char kName[] = "first.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      {BuildTestCnameRecord("second.test", "third.test"),
       BuildTestTextRecord("fourth.test", {"foo"}),
       BuildTestCnameRecord("third.test", "fourth.test"),
       BuildTestCnameRecord("other1.test", "other2.test"),
       BuildTestCnameRecord(kName, "second.test"),
       BuildTestCnameRecord("other2.test", "other3.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kBadAliasChain);
}

TEST_F(DnsResponseResultExtractorTest, RejectsDoubledCnames) {
  constexpr char kName[] = "first.test";

  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeTXT,
                           {BuildTestCnameRecord("second.test", "third.test"),
                            BuildTestTextRecord("fourth.test", {"foo"}),
                            BuildTestCnameRecord("third.test", "fourth.test"),
                            BuildTestCnameRecord("third.test", "fifth.test"),
                            BuildTestCnameRecord(kName, "second.test")});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kMultipleCnames);
}

TEST_F(DnsResponseResultExtractorTest, IgnoresTtlFromNonResultType) {
  constexpr char kName[] = "name.test";
  constexpr base::TimeDelta kMinTtl = base::Minutes(4);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      {BuildTestTextRecord(kName, {"foo"}, base::Hours(3)),
       BuildTestTextRecord(kName, {"bar"}, kMinTtl),
       BuildTestAddressRecord(kName, IPAddress(1, 2, 3, 4), base::Seconds(2)),
       BuildTestTextRecord(kName, {"baz"}, base::Minutes(15))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::TXT, kDnsSource,
          Eq(tick_clock_.NowTicks() + kMinTtl), Eq(clock_.Now() + kMinTtl),
          /*endpoints_matcher=*/IsEmpty(),
          UnorderedElementsAre("foo", "bar", "baz")))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsTtlFromCname) {
  constexpr char kName[] = "name.test";
  constexpr char kAlias[] = "alias.test";
  constexpr base::TimeDelta kTtl = base::Minutes(4);

  DnsResponse response =
      BuildTestDnsResponse("name.test", dns_protocol::kTypeTXT,
```