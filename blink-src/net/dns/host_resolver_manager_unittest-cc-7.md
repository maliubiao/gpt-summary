Response:
My thinking process to analyze the given C++ code and fulfill the user's request goes like this:

1. **Understand the Core Task:** The user wants to understand the functionality of the `host_resolver_manager_unittest.cc` file within the Chromium networking stack. The requests are specific: list functionalities, identify JavaScript relationships, provide logic examples with inputs and outputs, detail common user/programming errors, and explain how a user might reach this code (debugging context). Finally, summarize the functionality of this specific part (part 8 of 21).

2. **Initial Code Scan (Keywords and Patterns):** I quickly scan the code looking for keywords and patterns that indicate functionality. Things like `TEST_F`, `EXPECT_THAT`, `ChangeDnsConfig`, `ResolveHostResponseHelper`, `CreateRequest`, `IsError`, `IsOk`, `IsEmpty`, specific error codes (like `ERR_NAME_NOT_RESOLVED`, `ERR_ICANN_NAME_COLLISION`), IP addresses, hostnames, and comments give strong clues.

3. **Categorize Test Cases:** I notice the code is structured as a series of test cases using the Google Test framework (`TEST_F`). Each `TEST_F` block focuses on a specific aspect of the `HostResolverManager`'s DNS resolution capabilities. I start grouping these tests by the functionality they seem to be verifying:

    * **Basic Resolution:**  `NameCollisionIcann`, `ServeFromHosts` (these test basic success/failure scenarios and interactions with the HOSTS file).
    * **Bypassing DNS:** `SkipHostsWithUpcomingHostResolverSystemTask`, `BypassDnsTask`, `BypassDnsToMdnsWithNonAddress` (these check how certain hostnames or configurations might bypass the standard DNS resolution process).
    * **Forcing DNS or System Resolution:** `DnsNotBypassedWhenDnsSource`, `SystemOnlyBypassesDnsTask` (tests explicit source specification).
    * **Error Handling and Fallback:** `DisableInsecureDnsClientOnPersistentFailure`, `SecureDnsWorksAfterInsecureFailure`, `DontDisableDnsClientOnSporadicFailure` (focuses on how the resolver handles DNS failures and secure DNS).
    * **IPv6 Reachability:**  A significant block of tests dealing with IPv6 (`Ipv6Unreachable...`) – this indicates testing for scenarios where IPv6 might not be available or preferred.
    * **Secure DNS Modes:** `SeparateJobsBySecureDnsMode` (specifically tests interactions with different Secure DNS configurations).
    * **Request Cancellation:** `CancelWithOneTransactionActive`, `CancelWithOneTransactionActiveOnePending`, `CancelWithTwoTransactionsActive` (verifies how requests are cancelled).
    * **Object Deletion:** `DeleteWithActiveTransactions` (tests resource management when the resolver is destroyed).

4. **Detail Functionality (Based on Test Categories):**  For each category, I formulate a concise description of the functionality being tested. For example, for "Basic Resolution," I note the tests verify DNS resolution success and failure, especially around ICANN name collisions and the use of the HOSTS file.

5. **JavaScript Relationship Analysis:**  I consider how DNS resolution relates to JavaScript in a browser. The most direct link is when JavaScript code uses APIs like `fetch()` or `XMLHttpRequest` to make network requests. The browser's network stack, which includes the `HostResolverManager`, is responsible for resolving the domain names in these requests. I provide a simple `fetch()` example to illustrate this.

6. **Logic Examples (Input/Output):** For a few representative test cases, I create hypothetical input (e.g., a specific hostname and DNS configuration) and the expected output (the resolved IP address or an error). This makes the code's behavior more concrete. I choose examples that illustrate different functionalities, like HOSTS file lookup and ICANN collision handling.

7. **Common User/Programming Errors:** I think about common mistakes developers or users might make that would involve DNS resolution. Incorrect hostnames in URLs, misconfigured DNS settings, and problems with local HOSTS files are good examples.

8. **Debugging Scenario (User Steps):**  I trace back how a user action in a browser could lead to the execution of this code. A user typing a URL, clicking a link, or a web page making an API call are all valid starting points. I explain the flow from user action to the network stack and the role of the `HostResolverManager`.

9. **Summarize Current Section (Part 8 of 21):**  Given that the prompt mentions this is part 8, I look at the types of tests included in *this specific snippet*. It heavily features tests related to DNS resolution with a focus on:
    * Handling ICANN name collisions.
    * Using the HOSTS file for local overrides.
    * Bypassing the standard DNS resolver for specific cases (like `.local` domains).
    * Explicitly requesting DNS or system resolution.
    * Managing DNS client failures and secure DNS.
    * Initial IPv6 reachability considerations.

10. **Refine and Organize:** I organize my findings into the requested sections, ensuring clarity and conciseness. I use bullet points and clear headings to improve readability. I review my explanations to ensure they are accurate and address all parts of the user's request.

This iterative process of scanning, categorizing, analyzing, and synthesizing information allows me to break down the complex C++ code and provide a comprehensive explanation tailored to the user's needs. The focus is on extracting the *what* and *why* of the code, rather than just describing the *how*.
这个文件 `net/dns/host_resolver_manager_unittest.cc` 是 Chromium 网络栈中 `HostResolverManager` 组件的单元测试文件。它的主要功能是**测试 `HostResolverManager` 的各种 DNS 解析行为和管理功能**。

以下是根据提供的代码片段列举的功能，并结合你的要求进行说明：

**主要功能点:**

1. **ICANN 名称冲突处理 (`NameCollisionIcann`)**:
   - 测试当 DNS 解析返回特定的保留 IP 地址 (127.0.53.53) 时，`HostResolverManager` 能正确识别并返回 `ERR_ICANN_NAME_COLLISION` 错误。
   - 它还测试了 IPv6 版本的类似地址 (::127.0.53.53) 不会被视为特殊地址，而是像普通 IP 地址一样处理。
   - **逻辑推理：**
     - **假设输入：** 请求解析主机名 "4collision" 或 "6collision"。DNS 服务器返回 A 记录为 127.0.53.53 或 AAAA 记录为 ::127.0.53.53。
     - **预期输出：** 对于 "4collision"，`result_error()` 返回 `ERR_ICANN_NAME_COLLISION`，地址和端点结果为空。对于 "6collision"，`result_error()` 返回 `IsOk()`，地址和端点结果包含 ::127.0.53.53。

2. **从本地 HOSTS 文件解析 (`ServeFromHosts`)**:
   - 测试 `HostResolverManager` 能否正确读取和使用本地操作系统的 HOSTS 文件进行主机名解析。
   - 包括添加和更新 HOSTS 文件后，解析 IPv4、IPv6 以及同时配置了 IPv4 和 IPv6 的主机名。
   - 还测试了指定 DNS 查询类型 (A 或 AAAA) 时，HOSTS 文件的解析行为。
   - **逻辑推理：**
     - **假设输入：**
       - 初始状态：HOSTS 文件为空。解析 "nx_ipv4"，DNS 服务器返回解析失败。
       - 更新状态：HOSTS 文件中添加 "nx_ipv4" 对应 127.0.0.1，"nx_ipv6" 对应 ::1，"nx_both" 同时对应两者。
       - 再次解析 "nx_ipv4"、"nx_ipv6" 和 "nx_both"。
     - **预期输出：**
       - 初始解析返回 `ERR_NAME_NOT_RESOLVED`。
       - 更新后，"nx_ipv4" 解析到 127.0.0.1，"nx_ipv6" 解析到 ::1，"nx_both" 同时解析到两者。

3. **跳过即将使用系统解析器的 HOSTS 条目 (`SkipHostsWithUpcomingHostResolverSystemTask`)**:
   - 测试当 `HostResolverManager` 预期使用系统解析器时（例如，因为启用了某些特性），是否会跳过 HOSTS 文件中的对应条目。

4. **绕过 DNS 任务 (`BypassDnsTask`)**:
   - 测试对于以 ".local" 或 ".local." 结尾的主机名，`HostResolverManager` 能否正确地绕过标准的 DNS 查询任务，通常会交给系统解析器处理。
   - **与 JavaScript 的关系：** 当 JavaScript 代码尝试访问本地网络中的设备，并且这些设备使用了 `.local` 域名 (通常用于 Bonjour/mDNS)，这个测试确保了 Chromium 能正确处理这种情况，而不会尝试使用标准的 DNS 服务器解析。
     - **举例：**  如果一个智能家居设备在本地网络中的地址是 `mydevice.local`，JavaScript 代码使用 `fetch('http://mydevice.local/')` 访问它时，`HostResolverManager` 会尝试使用系统解析器（通常是 mDNS），而不是发送 DNS 查询到外部 DNS 服务器。

5. **绕过 DNS 并使用 mDNS 进行非地址查询 (`BypassDnsToMdnsWithNonAddress`)**:
   - 测试对于以 ".local" 结尾的主机名，当进行非地址查询 (例如 TXT 记录) 时，`HostResolverManager` 能否正确地将请求发送到 mDNS 解析器。
   - **与 JavaScript 的关系：** 一些 Web API 或库可能需要查询 TXT 记录来发现服务或配置信息。如果这些服务使用了 mDNS 和 `.local` 域名，这个测试确保了 Chromium 能正确处理这些查询。

6. **当指定 DNS 源时不绕过 DNS 任务 (`DnsNotBypassedWhenDnsSource`)**:
   - 测试当明确指定使用 DNS 作为解析源 (`HostResolverSource::DNS`) 时，即使主机名符合绕过 DNS 任务的条件（例如以 ".local" 结尾），`HostResolverManager` 仍然会使用 DNS 进行解析。

7. **仅系统解析器绕过 DNS 任务 (`SystemOnlyBypassesDnsTask`)**:
   - 测试当明确指定使用系统解析器 (`HostResolverSource::SYSTEM`) 时，`HostResolverManager` 会绕过其自身的 DNS 查询任务。

8. **在持久性失败时禁用不安全的 DNS 客户端 (`DisableInsecureDnsClientOnPersistentFailure`)**:
   - 测试当不安全的 DNS 客户端持续失败时，`HostResolverManager` 能否自动禁用它，并在 DNS 配置更改后重新启用。
   - **用户或编程常见的使用错误：** 如果用户的网络环境存在不稳定的 DNS 服务器，导致解析经常失败，Chromium 可能会暂时禁用其不安全的 DNS 查询，转而依赖其他解析方式。这可以避免因频繁失败的 DNS 查询而导致的性能问题。

9. **在不安全失败后安全 DNS 仍然工作 (`SecureDnsWorksAfterInsecureFailure`)**:
   - 测试即使不安全的 DNS 客户端失败，配置为安全 DNS (例如 DNS-over-HTTPS) 的解析仍然能正常工作。

10. **不要在零星失败时禁用 DNS 客户端 (`DontDisableDnsClientOnSporadicFailure`)**:
    - 测试只有当不安全的 DNS 客户端出现持续性失败时才会被禁用，偶尔的失败不会导致禁用。

11. **IPv6 不可达测试 (`Ipv6UnreachableTest`, `Ipv6UnreachableInvalidConfigTest`, `Ipv6Unreachable_UseLocalIpv6`, `Ipv6Unreachable_Localhost`)**:
    - 测试在 IPv6 网络不可达的情况下，`HostResolverManager` 的行为，例如只返回 IPv4 地址，或者在某些情况下仍然解析 IPv6 地址（例如 localhost）。
    - **用户或编程常见的使用错误：**
        - 用户的网络环境不支持 IPv6，但应用程序尝试连接到仅有 IPv6 地址的主机。`HostResolverManager` 的这些测试确保在这种情况下能够优雅地处理，可能返回错误或者回退到 IPv4。
        - 开发者在开发环境中没有正确配置 IPv6 支持，导致测试失败。
    - **假设输入与输出：**
        - **假设输入 (IPv6UnreachableTest)：** 网络被模拟为 IPv6 不可达。请求解析一个同时有 IPv4 和 IPv6 地址的主机 "ok"。
        - **预期输出：** 只返回 IPv4 地址。
        - **假设输入 (Ipv6Unreachable_Localhost)：** 网络被模拟为 IPv6 不可达。请求解析 "localhost"。
        - **预期输出：** 同时返回 IPv4 (127.0.0.1) 和 IPv6 (::1) 地址，因为 localhost 被特殊处理。

12. **IPv6 不可达仅禁用 AAAA 查询 (`Ipv6UnreachableOnlyDisablesAAAAQuery`)**:
    - 测试当 IPv6 不可达时，只会禁用 AAAA 查询（IPv6 地址查询），而不会阻止其他类型的 DNS 查询（例如 HTTPS 记录）。

13. **按安全 DNS 模式分离任务 (`SeparateJobsBySecureDnsMode`)**:
    - 测试 `HostResolverManager` 能否根据安全 DNS 模式（例如，自动模式）为不同的解析请求创建独立的 DNS 查询任务，以确保安全和不安全的查询不会互相干扰。

14. **取消请求 (`CancelWithOneTransactionActive`, `CancelWithOneTransactionActiveOnePending`, `CancelWithTwoTransactionsActive`)**:
    - 测试在不同 DNS 查询事务活跃状态下取消主机名解析请求的行为，确保资源得到正确释放。

15. **删除具有活动事务的解析器 (`DeleteWithActiveTransactions`)**:
    - 测试当 `HostResolverManager` 对象被销毁时，能够正确处理仍在进行中的 DNS 查询事务。

**与 JavaScript 的关系：**

`HostResolverManager` 是 Chromium 网络栈的核心组件，负责将域名解析为 IP 地址。当 JavaScript 代码在网页中发起网络请求时（例如使用 `fetch()`、`XMLHttpRequest` 或加载图片、CSS 等资源），浏览器会使用 `HostResolverManager` 来查找服务器的 IP 地址。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入一个网址或点击一个链接。**
2. **浏览器需要解析该网址中的域名以获取服务器的 IP 地址。**
3. **浏览器进程的网络服务会调用 `HostResolverManager` 的接口来发起 DNS 解析请求。**
4. **`HostResolverManager` 根据当前的网络配置、缓存状态、安全 DNS 设置等，决定如何进行 DNS 解析。** 这可能包括：
   - 检查本地缓存。
   - 查询本地 HOSTS 文件。
   - 使用操作系统提供的 DNS 解析器。
   - 使用 Chromium 内置的 DNS 客户端（可能支持 DNS-over-HTTPS 或 DNS-over-TLS）。
   - 如果涉及到 `.local` 域名，可能会尝试 mDNS 解析。
5. **在开发或调试 Chromium 时，如果怀疑 DNS 解析有问题，开发者可能会运行 `host_resolver_manager_unittest` 来验证 `HostResolverManager` 的行为是否符合预期。** 这通常在 Chromium 的代码仓库中进行，涉及到编译和运行单元测试。

**第 8 部分功能归纳：**

从提供的代码片段来看，第 8 部分的测试主要关注 `HostResolverManager` 在以下方面的功能：

- **对特定 DNS 响应（例如 ICANN 保留地址）的错误处理。**
- **正确使用本地 HOSTS 文件进行主机名解析。**
- **针对特定域名后缀（`.local`）绕过标准 DNS 查询，并可能使用 mDNS。**
- **根据用户或系统的配置，强制使用 DNS 或系统解析器。**
- **在 DNS 客户端出现故障时的弹性处理机制。**
- **初步测试 IPv6 网络不可达情况下的解析行为。**

总而言之，这个测试文件非常重要，因为它验证了 `HostResolverManager` 这一关键网络组件在各种场景下的正确性和健壮性，确保浏览器能够可靠地将域名解析为 IP 地址，从而实现正常的网络访问。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共21部分，请归纳一下它的功能

"""
     testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.101", 80))))));
}

TEST_F(HostResolverManagerDnsTest, NameCollisionIcann) {
  ChangeDnsConfig(CreateValidDnsConfig());

  // When the resolver returns an A record with 127.0.53.53 it should be
  // mapped to a special error.
  ResolveHostResponseHelper response_ipv4(resolver_->CreateRequest(
      HostPortPair("4collision", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_ipv4.result_error(), IsError(ERR_ICANN_NAME_COLLISION));
  EXPECT_THAT(response_ipv4.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response_ipv4.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // When the resolver returns an AAAA record with ::127.0.53.53 it should
  // work just like any other IP. (Despite having the same suffix, it is not
  // considered special)
  ResolveHostResponseHelper response_ipv6(resolver_->CreateRequest(
      HostPortPair("6collision", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_ipv6.result_error(), IsOk());
  EXPECT_THAT(response_ipv6.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::127.0.53.53", 80)));
  EXPECT_THAT(response_ipv6.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::127.0.53.53", 80))))));
}

TEST_F(HostResolverManagerDnsTest, ServeFromHosts) {
  // Initially, use empty HOSTS file.
  DnsConfig config = CreateValidDnsConfig();
  ChangeDnsConfig(config);

  proc_->AddRuleForAllFamilies(std::string(),
                               std::string());  // Default to failures.
  proc_->SignalMultiple(1u);  // For the first request which misses.

  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("nx_ipv4", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(initial_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  IPAddress local_ipv4 = IPAddress::IPv4Localhost();
  IPAddress local_ipv6 = IPAddress::IPv6Localhost();

  DnsHosts hosts;
  hosts[DnsHostsKey("nx_ipv4", ADDRESS_FAMILY_IPV4)] = local_ipv4;
  hosts[DnsHostsKey("nx_ipv6", ADDRESS_FAMILY_IPV6)] = local_ipv6;
  hosts[DnsHostsKey("nx_both", ADDRESS_FAMILY_IPV4)] = local_ipv4;
  hosts[DnsHostsKey("nx_both", ADDRESS_FAMILY_IPV6)] = local_ipv6;

  // Update HOSTS file.
  config.hosts = hosts;
  ChangeDnsConfig(config);

  ResolveHostResponseHelper response_ipv4(resolver_->CreateRequest(
      HostPortPair("nx_ipv4", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_ipv4.result_error(), IsOk());
  EXPECT_THAT(response_ipv4.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(response_ipv4.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));
  EXPECT_THAT(response_ipv4.request()->GetDnsAliasResults(),
              testing::Pointee(testing::IsEmpty()));

  ResolveHostResponseHelper response_ipv6(resolver_->CreateRequest(
      HostPortPair("nx_ipv6", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_ipv6.result_error(), IsOk());
  EXPECT_THAT(response_ipv6.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::1", 80)));
  EXPECT_THAT(response_ipv6.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::1", 80))))));
  EXPECT_THAT(response_ipv6.request()->GetDnsAliasResults(),
              testing::Pointee(testing::IsEmpty()));

  ResolveHostResponseHelper response_both(resolver_->CreateRequest(
      HostPortPair("nx_both", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_both.result_error(), IsOk());
  EXPECT_THAT(response_both.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response_both.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  EXPECT_THAT(response_both.request()->GetDnsAliasResults(),
              testing::Pointee(testing::IsEmpty()));

  // Requests with specified DNS query type.
  HostResolver::ResolveHostParameters parameters;

  parameters.dns_query_type = DnsQueryType::A;
  ResolveHostResponseHelper response_specified_ipv4(resolver_->CreateRequest(
      HostPortPair("nx_ipv4", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(response_specified_ipv4.result_error(), IsOk());
  EXPECT_THAT(
      response_specified_ipv4.request()->GetAddressResults()->endpoints(),
      testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(response_specified_ipv4.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));
  EXPECT_THAT(response_specified_ipv4.request()->GetDnsAliasResults(),
              testing::Pointee(testing::IsEmpty()));

  parameters.dns_query_type = DnsQueryType::AAAA;
  ResolveHostResponseHelper response_specified_ipv6(resolver_->CreateRequest(
      HostPortPair("nx_ipv6", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(response_specified_ipv6.result_error(), IsOk());
  EXPECT_THAT(
      response_specified_ipv6.request()->GetAddressResults()->endpoints(),
      testing::ElementsAre(CreateExpected("::1", 80)));
  EXPECT_THAT(response_specified_ipv6.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::1", 80))))));
  EXPECT_THAT(response_specified_ipv6.request()->GetDnsAliasResults(),
              testing::Pointee(testing::IsEmpty()));
}

TEST_F(HostResolverManagerDnsTest,
       SkipHostsWithUpcomingHostResolverSystemTask) {
  // Disable the DnsClient.
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled=*/false);

  proc_->AddRuleForAllFamilies(std::string(),
                               std::string());  // Default to failures.
  proc_->SignalMultiple(1u);  // For the first request which misses.

  DnsConfig config = CreateValidDnsConfig();
  DnsHosts hosts;
  hosts[DnsHostsKey("hosts", ADDRESS_FAMILY_IPV4)] = IPAddress::IPv4Localhost();

  // Update HOSTS file.
  config.hosts = hosts;
  ChangeDnsConfig(config);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("hosts", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

// Test that hosts ending in ".local" or ".local." are resolved using the system
// resolver.
TEST_F(HostResolverManagerDnsTest, BypassDnsTask) {
  ChangeDnsConfig(CreateValidDnsConfig());

  proc_->AddRuleForAllFamilies(std::string(),
                               std::string());  // Default to failures.

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;

  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("ok.local", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("ok.local.", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("oklocal", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("oklocal.", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));

  proc_->SignalMultiple(5u);

  for (size_t i = 0; i < 2; ++i)
    EXPECT_THAT(responses[i]->result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  for (size_t i = 2; i < responses.size(); ++i)
    EXPECT_THAT(responses[i]->result_error(), IsOk());
}

#if BUILDFLAG(ENABLE_MDNS)
// Test that non-address queries for hosts ending in ".local" are resolved using
// the MDNS resolver.
TEST_F(HostResolverManagerDnsTest, BypassDnsToMdnsWithNonAddress) {
  // Ensure DNS task and system requests will fail.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      "myhello.local", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      false /* delay */);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  proc_->AddRuleForAllFamilies(std::string(), std::string());

  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(2);

  HostResolver::ResolveHostParameters dns_parameters;
  dns_parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), dns_parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponseTxt,
                                      sizeof(kMdnsResponseTxt));
  proc_->SignalMultiple(1u);

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetTextResults(),
              testing::Pointee(testing::ElementsAre("foo", "bar")));
}
#endif  // BUILDFLAG(ENABLE_MDNS)

// Test that DNS task is always used when explicitly requested as the source,
// even with a case that would normally bypass it eg hosts ending in ".local".
TEST_F(HostResolverManagerDnsTest, DnsNotBypassedWhenDnsSource) {
  // Ensure DNS task requests will succeed and system requests will fail.
  ChangeDnsConfig(CreateValidDnsConfig());
  proc_->AddRuleForAllFamilies(std::string(), std::string());

  HostResolver::ResolveHostParameters dns_parameters;
  dns_parameters.source = HostResolverSource::DNS;

  ResolveHostResponseHelper dns_response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      dns_parameters, resolve_context_.get()));
  ResolveHostResponseHelper dns_local_response(resolver_->CreateRequest(
      HostPortPair("ok.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), dns_parameters, resolve_context_.get()));
  ResolveHostResponseHelper normal_local_response(resolver_->CreateRequest(
      HostPortPair("ok.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  proc_->SignalMultiple(3u);

  EXPECT_THAT(dns_response.result_error(), IsOk());
  EXPECT_THAT(dns_local_response.result_error(), IsOk());
  EXPECT_THAT(normal_local_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverManagerDnsTest, SystemOnlyBypassesDnsTask) {
  // Ensure DNS task requests will succeed and system requests will fail.
  ChangeDnsConfig(CreateValidDnsConfig());
  proc_->AddRuleForAllFamilies(std::string(), std::string());

  ResolveHostResponseHelper dns_response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::SYSTEM;
  ResolveHostResponseHelper system_response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));

  proc_->SignalMultiple(2u);

  EXPECT_THAT(dns_response.result_error(), IsOk());
  EXPECT_THAT(system_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverManagerDnsTest,
       DisableInsecureDnsClientOnPersistentFailure) {
  ChangeDnsConfig(CreateValidDnsConfig());

  // Check that DnsTask works.
  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("ok_1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(initial_response.result_error(), IsOk());

  TriggerInsecureFailureCondition();

  // Insecure DnsTasks should be disabled by now unless explicitly requested via
  // |source|.
  ResolveHostResponseHelper fail_response(resolver_->CreateRequest(
      HostPortPair("ok_2", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::DNS;
  ResolveHostResponseHelper dns_response(resolver_->CreateRequest(
      HostPortPair("ok_2", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  proc_->SignalMultiple(2u);
  EXPECT_THAT(fail_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(dns_response.result_error(), IsOk());

  // Check that it is re-enabled after DNS change.
  ChangeDnsConfig(CreateValidDnsConfig());
  ResolveHostResponseHelper reenabled_response(resolver_->CreateRequest(
      HostPortPair("ok_3", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(reenabled_response.result_error(), IsOk());
}

TEST_F(HostResolverManagerDnsTest, SecureDnsWorksAfterInsecureFailure) {
  DnsConfig config = CreateValidDnsConfig();
  config.secure_dns_mode = SecureDnsMode::kSecure;
  ChangeDnsConfig(config);

  TriggerInsecureFailureCondition();

  // Secure DnsTasks should not be affected.
  ResolveHostResponseHelper secure_response(resolver_->CreateRequest(
      HostPortPair("secure", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      /* optional_parameters=*/std::nullopt, resolve_context_.get()));
  EXPECT_THAT(secure_response.result_error(), IsOk());
}

TEST_F(HostResolverManagerDnsTest, DontDisableDnsClientOnSporadicFailure) {
  ChangeDnsConfig(CreateValidDnsConfig());

  // |proc_| defaults to successes.

  // 20 failures interleaved with 20 successes.
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  for (unsigned i = 0; i < 40; ++i) {
    // Use custom names to require separate Jobs.
    std::string hostname = (i % 2) == 0 ? base::StringPrintf("nx_%u", i)
                                        : base::StringPrintf("ok_%u", i);
    responses.emplace_back(
        std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
            HostPortPair(hostname, 80), NetworkAnonymizationKey(),
            NetLogWithSource(), std::nullopt, resolve_context_.get())));
  }

  proc_->SignalMultiple(40u);

  for (const auto& response : responses)
    EXPECT_THAT(response->result_error(), IsOk());

  // Make |proc_| default to failures.
  proc_->AddRuleForAllFamilies(std::string(), std::string());

  // DnsTask should still be enabled.
  ResolveHostResponseHelper final_response(resolver_->CreateRequest(
      HostPortPair("ok_last", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(final_response.result_error(), IsOk());
}

void HostResolverManagerDnsTest::Ipv6UnreachableTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    false /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("ok", 500), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());

  // Only expect IPv4 results.
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 500)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 500))))));
}

TEST_F(HostResolverManagerDnsTest, Ipv6UnreachableAsync) {
  Ipv6UnreachableTest(true);
}

TEST_F(HostResolverManagerDnsTest, Ipv6UnreachableSync) {
  Ipv6UnreachableTest(false);
}

void HostResolverManagerDnsTest::Ipv6UnreachableInvalidConfigTest(
    bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    false /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);

  proc_->AddRule("example.com", ADDRESS_FAMILY_UNSPECIFIED, "1.2.3.4,::5");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("example.com", 500), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("1.2.3.4", 500),
                                            CreateExpected("::5", 500)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::5", 500), CreateExpected("1.2.3.4", 500))))));
}
// Without a valid DnsConfig, assume IPv6 is needed and ignore prober.
TEST_F(HostResolverManagerDnsTest, Ipv6Unreachable_InvalidConfigAsync) {
  Ipv6UnreachableInvalidConfigTest(true);
}

TEST_F(HostResolverManagerDnsTest, Ipv6Unreachable_InvalidConfigSync) {
  Ipv6UnreachableInvalidConfigTest(false);
}

TEST_F(HostResolverManagerDnsTest, Ipv6Unreachable_UseLocalIpv6) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    false /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */);

  DnsConfig config = CreateValidDnsConfig();
  config.use_local_ipv6 = true;
  ChangeDnsConfig(config);

  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("ok", 500), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 500),
                                            CreateExpected("::1", 500)));
  EXPECT_THAT(
      response1.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 500), CreateExpected("127.0.0.1", 500))))));

  // Set |use_local_ipv6| to false. Expect only IPv4 results.
  config.use_local_ipv6 = false;
  ChangeDnsConfig(config);

  ResolveHostResponseHelper response2(resolver_->CreateRequest(
      HostPortPair("ok", 500), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 500)));
  EXPECT_THAT(response2.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 500))))));
}

// Confirm that resolving "localhost" is unrestricted even if there are no
// global IPv6 address. See SystemHostResolverCall for rationale.
// Test both the DnsClient and system host resolver paths.
TEST_F(HostResolverManagerDnsTest, Ipv6Unreachable_Localhost) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    false /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */);

  // Make request fail if we actually get to the system resolver.
  proc_->AddRuleForAllFamilies(std::string(), std::string());

  // Try without DnsClient.
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled=*/false);
  ResolveHostResponseHelper system_response(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(system_response.result_error(), IsOk());
  EXPECT_THAT(system_response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      system_response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  // With DnsClient
  UseMockDnsClient(CreateValidDnsConfig(), CreateDefaultDnsRules());
  ResolveHostResponseHelper builtin_response(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(builtin_response.result_error(), IsOk());
  EXPECT_THAT(builtin_response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      builtin_response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  // DnsClient configured without ipv6 (but ipv6 should still work for
  // localhost).
  DnsConfig config = CreateValidDnsConfig();
  config.use_local_ipv6 = false;
  ChangeDnsConfig(config);
  ResolveHostResponseHelper ipv6_disabled_response(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(ipv6_disabled_response.result_error(), IsOk());
  EXPECT_THAT(
      ipv6_disabled_response.request()->GetAddressResults()->endpoints(),
      testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                    CreateExpected("::1", 80)));
  EXPECT_THAT(
      ipv6_disabled_response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

// Test that IPv6 being unreachable only causes the AAAA query to be disabled,
// rather than querying only for A. See https://crbug.com/1272055.
TEST_F(HostResolverManagerDnsTest, Ipv6UnreachableOnlyDisablesAAAAQuery) {
  const std::string kName = "https.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsAliasRecord(kName, "alias.test")};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kUnexpected),
      /*delay=*/false);

  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    /*ipv6_reachable=*/false,
                                    /*check_ipv6_on_wifi=*/true);
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(),
      /*optional_parameters=*/std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 443)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
          testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 443))))));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, SeparateJobsBySecureDnsMode) {
  MockDnsClientRuleList rules;
  rules.emplace_back(
      "a", dns_protocol::kTypeA, true /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      false /* delay */);
  rules.emplace_back(
      "a", dns_protocol::kTypeAAAA, true /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      false /* delay */);
  rules.emplace_back(
      "a", dns_protocol::kTypeA, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      true /* delay */);
  rules.emplace_back(
      "a", dns_protocol::kTypeAAAA, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      true /* delay */);
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  // Create three requests. One with a DISABLE policy parameter, one with no
  // resolution parameters at all, and one with an ALLOW policy parameter
  // (which is a no-op).
  HostResolver::ResolveHostParameters parameters_disable_secure;
  parameters_disable_secure.secure_dns_policy = SecureDnsPolicy::kDisable;
  ResolveHostResponseHelper insecure_response(resolver_->CreateRequest(
      HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters_disable_secure, resolve_context_.get()));
  EXPECT_EQ(1u, resolver_->num_jobs_for_testing());

  ResolveHostResponseHelper automatic_response0(resolver_->CreateRequest(
      HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_EQ(2u, resolver_->num_jobs_for_testing());

  HostResolver::ResolveHostParameters parameters_allow_secure;
  parameters_allow_secure.secure_dns_policy = SecureDnsPolicy::kAllow;
  ResolveHostResponseHelper automatic_response1(resolver_->CreateRequest(
      HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters_allow_secure, resolve_context_.get()));
  // The AUTOMATIC mode requests should be joined into the same job.
  EXPECT_EQ(2u, resolver_->num_jobs_for_testing());

  // Automatic mode requests have completed.  Insecure request is still blocked.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(insecure_response.complete());
  EXPECT_TRUE(automatic_response0.complete());
  EXPECT_TRUE(automatic_response1.complete());
  EXPECT_THAT(automatic_response0.result_error(), IsOk());
  EXPECT_THAT(automatic_response1.result_error(), IsOk());

  // Complete insecure transaction.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_TRUE(insecure_response.complete());
  EXPECT_THAT(insecure_response.result_error(), IsOk());
}

// Cancel a request with a single DNS transaction active.
TEST_F(HostResolverManagerDnsTest, CancelWithOneTransactionActive) {
  // Disable ipv6 to ensure we'll only try a single transaction for the host.
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    false /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */);
  DnsConfig config = CreateValidDnsConfig();
  config.use_local_ipv6 = false;
  ChangeDnsConfig(config);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response.complete());
  ASSERT_EQ(1u, num_running_dispatcher_jobs());

  response.CancelRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Dispatcher state checked in TearDown.
}

// Cancel a request with a single DNS transaction active and another pending.
TEST_F(HostResolverManagerDnsTest, CancelWithOneTransactionActiveOnePending) {
  CreateSerialResolver();
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_EQ(1u, num_running_dispatcher_jobs());

  response.CancelRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Dispatcher state checked in TearDown.
}

// Cancel a request with two DNS transactions active.
TEST_F(HostResolverManagerDnsTest, CancelWithTwoTransactionsActive) {
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_EQ(2u, num_running_dispatcher_jobs());

  response.CancelRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Dispatcher state checked in TearDown.
}

// Delete a resolver with some active requests and some queued requests.
TEST_F(HostResolverManagerDnsTest, DeleteWithActiveTransactions) {
  // At most 10 Jobs active at once.
  CreateResolverWithLimitsAndParams(10u, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */);

  ChangeDnsConfig(CreateValidDnsConfig());

  // Add 12 DNS lookups (creating well more than 10 transaction).
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  for (int i = 0; i < 12; ++i) {
    std::string hostname = base::StringPrintf("ok%i", i);
    responses.emplace_back(
        std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
            HostPortPair(hostname, 80), NetworkAnonymizationKey(),
            NetLogWith
"""


```