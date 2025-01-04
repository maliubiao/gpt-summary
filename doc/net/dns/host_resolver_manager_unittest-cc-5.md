Response:
The user wants to understand the functionality of the provided C++ code snippet from `host_resolver_manager_unittest.cc`. I need to analyze the code and:

1. **Summarize its functionality:** What is the code testing?
2. **Check for JavaScript relevance:** Does this code interact with or test features related to JavaScript?
3. **Analyze logical inference:** Are there test cases with clear input and output scenarios?
4. **Identify common usage errors:** Does the code highlight potential mistakes users or programmers could make?
5. **Explain user operation leading here:** How does a user action trigger this code (as a debugging aid)?
6. **Provide a concise summary:**  Given this is part 6 of 21, what is the specific aspect of the `HostResolverManager` being tested here?

Based on the code, it seems to be testing the `MdnsListener` functionality of the `HostResolverManager`. Specifically, it checks:

- Receiving and processing mDNS responses (A, TXT, PTR, SRV records).
- Handling goodbye messages and record removals.
- Handling start listening failures.
- Handling record expiration.
- Ignoring responses for non-subscribed query types.
- Handling root domain PTR records.

There doesn't seem to be any direct interaction with JavaScript in this specific snippet. The tests focus on the internal C++ implementation of mDNS resolution.

I can create hypothetical input and output scenarios based on the test cases.

I need to think about common errors related to mDNS listener setup and usage.

For the user operation, I'll focus on how a browser might initiate mDNS requests, such as for devices on a local network.

Finally, I'll summarize the core functionality of this part of the tests.
```cpp
SimulateReceive(kMdnsResponseA2, sizeof(kMdnsResponseA2));
  socket_factory->SimulateReceive(kMdnsResponseA2Goodbye,
                                  sizeof(kMdnsResponseA2Goodbye));

  // Per RFC6762 section 10.1, removals take effect 1 second after receiving the
  // goodbye message.
  clock.Advance(base::Seconds(1));
  cache_cleanup_timer_ptr->Fire();

  // Expect 1 record adding "1.2.3.4", another changing to "5.6.7.8", and a
  // final removing "5.6.7.8".
  EXPECT_THAT(delegate.address_results(),
              testing::ElementsAre(
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kAdded, DnsQueryType::A,
                      CreateExpected("1.2.3.4", 80)),
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kChanged, DnsQueryType::A,
                      CreateExpected("5.6.7.8", 80)),
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kRemoved, DnsQueryType::A,
                      CreateExpected("5.6.7.8", 80))));

  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_StartListenFailure) {
  // Inject an MdnsClient mock that will always fail to start listening.
  auto client = std::make_unique<MockMDnsClient>();
  EXPECT_CALL(*client, StartListening(_)).WillOnce(Return(ERR_TIMED_OUT));
  EXPECT_CALL(*client, IsListening()).WillRepeatedly(Return(false));
  resolver_->SetMdnsClientForTesting(std::move(client));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 80),
                                    DnsQueryType::A);

  EXPECT_THAT(listener->Start(&delegate), IsError(ERR_TIMED_OUT));
  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
}

// Test that removal notifications are sent on natural expiration of MDNS
// records.
TEST_F(HostResolverManagerTest, MdnsListener_Expiration) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  base::SimpleTestClock clock;
  clock.SetNow(base::Time::Now());
  auto cache_cleanup_timer = std::make_unique<base::MockOneShotTimer>();
  auto* cache_cleanup_timer_ptr = cache_cleanup_timer.get();
  auto mdns_client =
      std::make_unique<MDnsClientImpl>(&clock, std::move(cache_cleanup_timer));
  ASSERT_THAT(mdns_client->StartListening(socket_factory.get()), IsOk());
  resolver_->SetMdnsClientForTesting(std::move(mdns_client));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 100),
                                    DnsQueryType::A);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.address_results(), testing::IsEmpty());

  socket_factory->SimulateReceive(kMdnsResponseA, sizeof(kMdnsResponseA));

  EXPECT_THAT(
      delegate.address_results(),
      testing::ElementsAre(TestMdnsListenerDelegate::CreateExpectedResult(
          MdnsListenerUpdateType::kAdded, DnsQueryType::A,
          CreateExpected("1.2.3.4", 100))));

  clock.Advance(base::Seconds(16));
  cache_cleanup_timer_ptr->Fire();

  EXPECT_THAT(delegate.address_results(),
              testing::ElementsAre(
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kAdded, DnsQueryType::A,
                      CreateExpected("1.2.3.4", 100)),
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kRemoved, DnsQueryType::A,
                      CreateExpected("1.2.3.4", 100))));

  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_Txt) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 12),
                                    DnsQueryType::TXT);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.text_results(), testing::IsEmpty());

  socket_factory_ptr->SimulateReceive(kMdnsResponseTxt,
                                      sizeof(kMdnsResponseTxt));

  EXPECT_THAT(
      delegate.text_results(),
      testing::ElementsAre(
          TestMdnsListenerDelegate::CreateExpectedResult(
              MdnsListenerUpdateType::kAdded, DnsQueryType::TXT, "foo"),
          TestMdnsListenerDelegate::CreateExpectedResult(
              MdnsListenerUpdateType::kAdded, DnsQueryType::TXT, "bar")));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_Ptr) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 13),
                                    DnsQueryType::PTR);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.text_results(), testing::IsEmpty());

  socket_factory_ptr->SimulateReceive(kMdnsResponsePtr,
                                      sizeof(kMdnsResponsePtr));

  EXPECT_THAT(
      delegate.hostname_results(),
      testing::ElementsAre(TestMdnsListenerDelegate::CreateExpectedResult(
          MdnsListenerUpdateType::kAdded, DnsQueryType::PTR,
          HostPortPair("foo.com", 13))));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_Srv) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 14),
                                    DnsQueryType::SRV);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.text_results(), testing::IsEmpty());

  socket_factory_ptr->SimulateReceive(kMdnsResponseSrv,
                                      sizeof(kMdnsResponseSrv));

  EXPECT_THAT(
      delegate.hostname_results(),
      testing::ElementsAre(TestMdnsListenerDelegate::CreateExpectedResult(
          MdnsListenerUpdateType::kAdded, DnsQueryType::SRV,
          HostPortPair("foo.com", 8265))));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

// Ensure query types we are not listening for do not affect MdnsListener.
TEST_F(HostResolverManagerTest, MdnsListener_NonListeningTypes) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 41),
                                    DnsQueryType::A);

  ASSERT_THAT(listener->Start(&delegate), IsOk());

  socket_factory_ptr->SimulateReceive(kMdnsResponseAAAA,
                                      sizeof(kMdnsResponseAAAA));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_RootDomain) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 5),
                                    DnsQueryType::PTR);

  ASSERT_THAT(listener->Start(&delegate), IsOk());

  socket_factory_ptr->SimulateReceive(kMdnsResponsePtrRoot,
                                      sizeof(kMdnsResponsePtrRoot));

  EXPECT_THAT(delegate.unhandled_results(),
              testing::ElementsAre(std::pair(MdnsListenerUpdateType::kAdded,
                                             DnsQueryType::PTR)));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
}
#endif  // BUILDFLAG(ENABLE_MDNS)

DnsConfig CreateUpgradableDnsConfig() {
  DnsConfig config;
  config.secure_dns_mode = SecureDnsMode::kAutomatic;
  config.allow_dns_over_https_upgrade = true;

  auto ProviderHasAddr = [](std::string_view provider, const IPAddress& addr) {
    return base::Contains(GetDohProviderEntryForTesting(provider).ip_addresses,
                          addr);
  };

  // Cloudflare upgradeable IPs
  IPAddress dns_ip0(1, 0, 0, 1);
  IPAddress dns_ip1;
  EXPECT_TRUE(dns_ip1.AssignFromIPLiteral("2606:4700:4700::1111"));
  EXPECT_TRUE(ProviderHasAddr("Cloudflare", dns_ip0));
  EXPECT_TRUE(ProviderHasAddr("Cloudflare", dns_ip1));
  // CleanBrowsingFamily upgradeable IP
  IPAddress dns_ip2;
  EXPECT_TRUE(dns_ip2.AssignFromIPLiteral("2a0d:2a00:2::"));
  EXPECT_TRUE(ProviderHasAddr("CleanBrowsingFamily", dns_ip2));
  // CleanBrowsingSecure upgradeable IP
  IPAddress dns_ip3(185, 228, 169, 9);
  EXPECT_TRUE(ProviderHasAddr("CleanBrowsingSecure", dns_ip3));
  // Non-upgradeable IP
  IPAddress dns_ip4(1, 2, 3, 4);

  config.nameservers = {
      IPEndPoint(dns_ip0, dns_protocol::kDefaultPort),
      IPEndPoint(dns_ip1, dns_protocol::kDefaultPort),
      IPEndPoint(dns_ip2, 54),
      IPEndPoint(dns_ip3, dns_protocol::kDefaultPort),
      IPEndPoint(dns_ip4, dns_protocol::kDefaultPort),
  };
  EXPECT_TRUE(config.IsValid());
  return config;
}

// Check that entries are written to the cache with the right NAK.
TEST_F(HostResolverManagerTest, NetworkAnonymizationKeyWriteToHostCache) {
  const SchemefulSite kSite1(GURL("https://origin1.test/"));
  const SchemefulSite kSite2(GURL("https://origin2.test/"));
  auto kNetworkAnonymizationKey1 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite1);
  auto kNetworkAnonymizationKey2 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite2);

  const char kFirstDnsResult[] = "192.168.1.42";
  const char kSecondDnsResult[] = "192.168.1.43";

  for (bool split_cache_by_network_anonymization_key : {false, true}) {
    base::test::ScopedFeatureList feature_list;
    if (split_cache_by_network_anonymization_key) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    } else {
      feature_list.InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }
    proc_->AddRuleForAllFamilies("just.testing", kFirstDnsResult);
    proc_->SignalMultiple(1u);

    // Resolve a host using kNetworkAnonymizationKey1.
    ResolveHostResponseHelper response1(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey1,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response1.result_error(), IsOk());
    EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected(kFirstDnsResult, 80)));
    EXPECT_THAT(
        response1.request()->GetEndpointResults(),
        testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
            testing::ElementsAre(CreateExpected(kFirstDnsResult, 80))))));
    EXPECT_FALSE(response1.request()->GetStaleInfo());
    EXPECT_EQ(1u, proc_->GetCaptureList().size());

    // If the host cache is being split by NetworkAnonymizationKeys, there
    // should be an entry in the HostCache with kNetworkAnonymizationKey1.
    // Otherwise, there should be an entry with the empty NAK.
    if (split_cache_by_network_anonymization_key) {
      EXPECT_TRUE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey1)));

      EXPECT_FALSE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         NetworkAnonymizationKey())));
    } else {
      EXPECT_FALSE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey1)));

      EXPECT_TRUE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         NetworkAnonymizationKey())));
    }

    // There should be no entry using kNetworkAnonymizationKey2 in either case.
    EXPECT_FALSE(GetCacheHit(HostCache::Key(
        "just.testing", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
        HostResolverSource::ANY, kNetworkAnonymizationKey2)));

    // A request using kNetworkAnonymizationKey2 should only be served out of
    // the cache of the cache if |split_cache_by_network_anonymization_key| is
    // false. If it's not served over the network, it is provided a different
    // result.
    if (split_cache_by_network_anonymization_key) {
      proc_->AddRuleForAllFamilies("just.testing", kSecondDnsResult);
      proc_->SignalMultiple(1u);
    }
    ResolveHostResponseHelper response2(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey2,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response2.result_error(), IsOk());
    if (split_cache_by_network_anonymization_key) {
      EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                  testing::ElementsAre(CreateExpected(kSecondDnsResult, 80)));
      EXPECT_THAT(
          response2.request()->GetEndpointResults(),
          testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
              testing::ElementsAre(CreateExpected(kSecondDnsResult, 80))))));
      EXPECT_FALSE(response2.request()->GetStaleInfo());
      EXPECT_EQ(2u, proc_->GetCaptureList().size());
      EXPECT_TRUE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey2)));
    } else {
      EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                  testing::ElementsAre(CreateExpected(kFirstDnsResult, 80)));
      EXPECT_THAT(
          response2.request()->GetEndpointResults(),
          testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
              testing::ElementsAre(CreateExpected(kFirstDnsResult, 80))))));
      EXPECT_TRUE(response2.request()->GetStaleInfo());
      EXPECT_EQ(1u, proc_->GetCaptureList().size());
      EXPECT_FALSE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey2)));
    }

    resolve_context_->host_cache()->clear();
    proc_->ClearCaptureList();
  }
}

// Check that entries are read to the cache with the right NAK.
TEST_F(HostResolverManagerTest, NetworkAnonymizationKeyReadFromHostCache) {
  const SchemefulSite kSite1(GURL("https://origin1.test/"));
  const SchemefulSite kSite2(GURL("https://origin2.test/"));
  auto kNetworkAnonymizationKey1 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite1);
  auto kNetworkAnonymizationKey2 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite2);

  struct CacheEntry {
    NetworkAnonymizationKey network_anonymization_key;
    const char* cached_ip_address;
  };

  const CacheEntry kCacheEntries[] = {
      {NetworkAnonymizationKey(), "192.168.1.42"},
      {kNetworkAnonymizationKey1, "192.168.1.43"},
      {kNetworkAnonymizationKey2, "192.168.1.44"},
  };

  // Add entries to cache for the empty NAK, NAK1, and NAK2. Only the
  // HostResolverManager obeys network state partitioning, so this is fine to do
  // regardless of the feature value.
  for (const auto& cache_entry : kCacheEntries) {
    HostCache::Key key("just.testing", DnsQueryType::UNSPECIFIED, 0,
                       HostResolverSource::ANY,
                       cache_entry.network_anonymization_key);
    IPAddress address;
    ASSERT_TRUE(address.AssignFromIPLiteral(cache_entry.cached_ip_address));
    HostCache::Entry entry = HostCache::Entry(
        OK, {{address, 80}}, /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);
    resolve_context_->host_cache()->Set(key, entry, base::TimeTicks::Now(),
                                        base::Days(1));
  }

  for (bool split_cache_by_network_anonymization_key : {false, true}) {
    base::test::ScopedFeatureList feature_list;
    if (split_cache_by_network_anonymization_key) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    } else {
      feature_list.InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }

    // A request that uses kNetworkAnonymizationKey1 will return cache entry 1
    // if the NetworkAnonymizationKeys are being used, and cache entry 0
    // otherwise.
    ResolveHostResponseHelper response1(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey1,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response1.result_error(), IsOk());
    EXPECT_THAT(
        response1.request()->GetAddressResults()->endpoints(),
        testing::ElementsAre(CreateExpected(
            kCacheEntries[split_cache_by_network_anonymization_key ? 1 : 0]
                .cached_ip_address,
            80)));
    EXPECT_THAT(
        response1.request()->GetEndpointResults(),
        testing::Pointee(testing::ElementsAre(
            ExpectEndpointResult(testing::ElementsAre(CreateExpected(
                kCacheEntries[split_cache_by_network_anonymization_key ? 1 : 0]
                    .cached_ip_address,
                80))))));
    EXPECT_TRUE(response1.request()->GetStaleInfo());

    // A request that uses kNetworkAnonymizationKey2 will return cache entry 2
    // if the NetworkAnonymizationKeys are being used, and cache entry 0
    // otherwise.
    ResolveHostResponseHelper response2(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey2,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response2.result_error(), IsOk());
    EXPECT_THAT(
        response2.request()->GetAddressResults()->endpoints(),
        testing::ElementsAre(CreateExpected(
            kCacheEntries[split_cache_by_network_anonymization_key ? 2 : 0]
                .cached_ip_address,
            80)));
    EXPECT_THAT(
        response2.request()->GetEndpointResults(),
        testing::Pointee(testing::ElementsAre(
            ExpectEndpointResult(testing::ElementsAre(CreateExpected(
                kCacheEntries[split_cache_by_network_anonymization_key ? 2 : 0]
                    .cached_ip_address,
                80))))));
    EXPECT_TRUE(response2.request()->GetStaleInfo());
  }
}

// Test that two requests made with different NetworkAnonymizationKeys are not
// merged if network state partitioning is enabled.
TEST_F(HostResolverManagerTest, NetworkAnonymizationKeyTwoRequestsAtOnce) {
  const SchemefulSite kSite1(GURL("https://origin1.test/"));
  const SchemefulSite kSite2(GURL("https://origin2.test/"));
  auto kNetworkAnonymizationKey1 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite1);
  auto kNetworkAnonymizationKey2 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite2);

  const char kDnsResult[] = "192.168.1.42";

  for (bool split_cache_by_network_anonymization_key : {false, true}) {
    base::test::ScopedFeatureList feature_list;
    if (split_cache_by_network_anonymization_key) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    } else {
      feature_list.InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }
    proc_->AddRuleForAllFamilies("just.testing", kDnsResult);

    // Start resolving a host using kNetworkAnonymizationKey1.
    ResolveHostResponseHelper response1(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey1,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_FALSE(response1.complete());

    // Start resolving the same host using kNetworkAnonymizationKey2.
    ResolveHostResponseHelper response2(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey2,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_FALSE(response2.complete());

    // Wait for and complete the expected number of over-the-wire DNS
    // resolutions.
    if (split_cache_by_network_anonymization_key) {
      proc_->WaitFor(2);
      EXPECT_EQ(2u, proc_->GetCaptureList().size());
      proc_->SignalMultiple(2u);
    } else {
      proc_->WaitFor(1);
      EXPECT_EQ(1u, proc_->GetCaptureList().size());
      proc_->SignalMultiple(1u);
    }

    // Both requests should have completed successfully, with neither served out
    // of the cache.

    EXPECT_THAT(response1.result_error(), IsOk());
    EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected(kDnsResult, 80)));
    EXPECT_THAT(response1.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
    EXPECT_FALSE(response1.request()->GetStaleInfo());

    EXPECT_THAT(response2.result_error(), IsOk());
    EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected(kDnsResult, 80)));
    EXPECT_THAT(response2.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
    EXPECT_FALSE(response2.request()->GetStaleInfo());

    resolve_context_->host_cache()->clear();
    proc_->ClearCaptureList();
  }
}

// Test that two otherwise-identical requests with different ResolveContexts are
// not merged.
TEST_F(HostResolverManagerTest, ContextsNotMerged) {
  const char kDnsResult[] = "192.168.1.42";

  proc_->AddRuleForAllFamilies("just.testing", kDnsResult);

  // Start resolving a host using |resolve_context_|.
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_FALSE(response1.complete());

  // Start resolving the same host using another ResolveContext and cache.
  ResolveContext resolve_context2(resolve_context_->url_request_context(),
                                  true /* enable_caching */);
  resolver_->RegisterResolveContext(&resolve_context2);
  ResolveHostResponseHelper response2(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, &resolve_context2));
  EXPECT_FALSE(response2.complete());
  EXPECT_EQ(2u, resolver_->num_jobs_for_testing());

  // Wait for and complete the 2 over-the-wire DNS resolutions.
  proc_->WaitFor(2);
  EXPECT_EQ(2u, proc_->GetCaptureList().size());
  proc_->SignalMultiple(2u);

  // Both requests should have completed successfully, with neither served out
  // of the cache.

  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected(kDnsResult, 80)));
  EXPECT_THAT(response1.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
  EXPECT_FALSE(response1.request()->GetStaleInfo());

  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected(kDnsResult, 80)));
  EXPECT_THAT(response2.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
  EXPECT_FALSE(response2.request()->GetStaleInfo());

  EXPECT_EQ(1u, resolve_context_->host_cache()->size());
  EXPECT_EQ(1u, resolve_context2.host_cache()->size());

  resolver_->DeregisterResolveContext(&resolve_context2);
}

// HostResolverManagerDnsTest ==================================================

HostResolverManagerDnsTest::HostResolverManagerDnsTest(
    base::test::TaskEnvironment::TimeSource time_source)
    : HostResolverManagerTest(time_source),
      notifier_task_runner_(
          base::MakeRefCounted<base::TestMockTimeTaskRunner>()) {
  auto config_service = std::make_unique<TestDnsConfigService>();
  config_service_ = config_service.get();
  notifier_ = std::make_unique<SystemDnsConfigChangeNotifier>(
      notifier_task_runner_, std::move(config_service));
}

HostResolverManagerDnsTest::~HostResolverManagerDnsTest() = default;

void HostResolverManagerDnsTest::DestroyResolver() {
  mock_dns_client_ = nullptr;
  HostResolverManagerTest::DestroyResolver();
}

void HostResolverManagerDnsTest::SetDnsClient(
    std::unique_ptr<DnsClient> dns_client) {
  mock_dns_client_ = nullptr;
  resolver_->SetDnsClientForTesting(std::move(dns_client));
}

void HostResolverManagerDnsTest::TearDown() {
  HostResolverManagerTest::TearDown();
  InvalidateDnsConfig();

  // Ensure |notifier_| is fully cleaned up before test shutdown.
  notifier_.reset();
  notifier_task_runner_->RunUntilIdle();
}

HostResolver::ManagerOptions HostResolverManagerDnsTest::DefaultOptions() {
  HostResolver::ManagerOptions options =
      HostResolverManagerTest::DefaultOptions();
  options.insecure_dns_client_enabled = true;
  options.additional_types_via_insecure_dns_enabled = true;
  return options;
}

void HostResolverManagerDnsTest::CreateResolverWithOptionsAndParams(
    HostResolver::ManagerOptions options,
    const HostResolverSystemTask::Params& params,
    bool ipv6_reachable,
    bool is_async,
    bool ipv4_reachable) {
  DestroyResolver();
Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共21部分，请归纳一下它的功能

"""
SimulateReceive(kMdnsResponseA2, sizeof(kMdnsResponseA2));
  socket_factory->SimulateReceive(kMdnsResponseA2Goodbye,
                                  sizeof(kMdnsResponseA2Goodbye));

  // Per RFC6762 section 10.1, removals take effect 1 second after receiving the
  // goodbye message.
  clock.Advance(base::Seconds(1));
  cache_cleanup_timer_ptr->Fire();

  // Expect 1 record adding "1.2.3.4", another changing to "5.6.7.8", and a
  // final removing "5.6.7.8".
  EXPECT_THAT(delegate.address_results(),
              testing::ElementsAre(
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kAdded, DnsQueryType::A,
                      CreateExpected("1.2.3.4", 80)),
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kChanged, DnsQueryType::A,
                      CreateExpected("5.6.7.8", 80)),
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kRemoved, DnsQueryType::A,
                      CreateExpected("5.6.7.8", 80))));

  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_StartListenFailure) {
  // Inject an MdnsClient mock that will always fail to start listening.
  auto client = std::make_unique<MockMDnsClient>();
  EXPECT_CALL(*client, StartListening(_)).WillOnce(Return(ERR_TIMED_OUT));
  EXPECT_CALL(*client, IsListening()).WillRepeatedly(Return(false));
  resolver_->SetMdnsClientForTesting(std::move(client));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 80),
                                    DnsQueryType::A);

  EXPECT_THAT(listener->Start(&delegate), IsError(ERR_TIMED_OUT));
  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
}

// Test that removal notifications are sent on natural expiration of MDNS
// records.
TEST_F(HostResolverManagerTest, MdnsListener_Expiration) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  base::SimpleTestClock clock;
  clock.SetNow(base::Time::Now());
  auto cache_cleanup_timer = std::make_unique<base::MockOneShotTimer>();
  auto* cache_cleanup_timer_ptr = cache_cleanup_timer.get();
  auto mdns_client =
      std::make_unique<MDnsClientImpl>(&clock, std::move(cache_cleanup_timer));
  ASSERT_THAT(mdns_client->StartListening(socket_factory.get()), IsOk());
  resolver_->SetMdnsClientForTesting(std::move(mdns_client));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 100),
                                    DnsQueryType::A);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.address_results(), testing::IsEmpty());

  socket_factory->SimulateReceive(kMdnsResponseA, sizeof(kMdnsResponseA));

  EXPECT_THAT(
      delegate.address_results(),
      testing::ElementsAre(TestMdnsListenerDelegate::CreateExpectedResult(
          MdnsListenerUpdateType::kAdded, DnsQueryType::A,
          CreateExpected("1.2.3.4", 100))));

  clock.Advance(base::Seconds(16));
  cache_cleanup_timer_ptr->Fire();

  EXPECT_THAT(delegate.address_results(),
              testing::ElementsAre(
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kAdded, DnsQueryType::A,
                      CreateExpected("1.2.3.4", 100)),
                  TestMdnsListenerDelegate::CreateExpectedResult(
                      MdnsListenerUpdateType::kRemoved, DnsQueryType::A,
                      CreateExpected("1.2.3.4", 100))));

  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_Txt) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 12),
                                    DnsQueryType::TXT);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.text_results(), testing::IsEmpty());

  socket_factory_ptr->SimulateReceive(kMdnsResponseTxt,
                                      sizeof(kMdnsResponseTxt));

  EXPECT_THAT(
      delegate.text_results(),
      testing::ElementsAre(
          TestMdnsListenerDelegate::CreateExpectedResult(
              MdnsListenerUpdateType::kAdded, DnsQueryType::TXT, "foo"),
          TestMdnsListenerDelegate::CreateExpectedResult(
              MdnsListenerUpdateType::kAdded, DnsQueryType::TXT, "bar")));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_Ptr) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 13),
                                    DnsQueryType::PTR);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.text_results(), testing::IsEmpty());

  socket_factory_ptr->SimulateReceive(kMdnsResponsePtr,
                                      sizeof(kMdnsResponsePtr));

  EXPECT_THAT(
      delegate.hostname_results(),
      testing::ElementsAre(TestMdnsListenerDelegate::CreateExpectedResult(
          MdnsListenerUpdateType::kAdded, DnsQueryType::PTR,
          HostPortPair("foo.com", 13))));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_Srv) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 14),
                                    DnsQueryType::SRV);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.text_results(), testing::IsEmpty());

  socket_factory_ptr->SimulateReceive(kMdnsResponseSrv,
                                      sizeof(kMdnsResponseSrv));

  EXPECT_THAT(
      delegate.hostname_results(),
      testing::ElementsAre(TestMdnsListenerDelegate::CreateExpectedResult(
          MdnsListenerUpdateType::kAdded, DnsQueryType::SRV,
          HostPortPair("foo.com", 8265))));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

// Ensure query types we are not listening for do not affect MdnsListener.
TEST_F(HostResolverManagerTest, MdnsListener_NonListeningTypes) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 41),
                                    DnsQueryType::A);

  ASSERT_THAT(listener->Start(&delegate), IsOk());

  socket_factory_ptr->SimulateReceive(kMdnsResponseAAAA,
                                      sizeof(kMdnsResponseAAAA));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.unhandled_results(), testing::IsEmpty());
}

TEST_F(HostResolverManagerTest, MdnsListener_RootDomain) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 5),
                                    DnsQueryType::PTR);

  ASSERT_THAT(listener->Start(&delegate), IsOk());

  socket_factory_ptr->SimulateReceive(kMdnsResponsePtrRoot,
                                      sizeof(kMdnsResponsePtrRoot));

  EXPECT_THAT(delegate.unhandled_results(),
              testing::ElementsAre(std::pair(MdnsListenerUpdateType::kAdded,
                                             DnsQueryType::PTR)));

  EXPECT_THAT(delegate.address_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.text_results(), testing::IsEmpty());
  EXPECT_THAT(delegate.hostname_results(), testing::IsEmpty());
}
#endif  // BUILDFLAG(ENABLE_MDNS)

DnsConfig CreateUpgradableDnsConfig() {
  DnsConfig config;
  config.secure_dns_mode = SecureDnsMode::kAutomatic;
  config.allow_dns_over_https_upgrade = true;

  auto ProviderHasAddr = [](std::string_view provider, const IPAddress& addr) {
    return base::Contains(GetDohProviderEntryForTesting(provider).ip_addresses,
                          addr);
  };

  // Cloudflare upgradeable IPs
  IPAddress dns_ip0(1, 0, 0, 1);
  IPAddress dns_ip1;
  EXPECT_TRUE(dns_ip1.AssignFromIPLiteral("2606:4700:4700::1111"));
  EXPECT_TRUE(ProviderHasAddr("Cloudflare", dns_ip0));
  EXPECT_TRUE(ProviderHasAddr("Cloudflare", dns_ip1));
  // CleanBrowsingFamily upgradeable IP
  IPAddress dns_ip2;
  EXPECT_TRUE(dns_ip2.AssignFromIPLiteral("2a0d:2a00:2::"));
  EXPECT_TRUE(ProviderHasAddr("CleanBrowsingFamily", dns_ip2));
  // CleanBrowsingSecure upgradeable IP
  IPAddress dns_ip3(185, 228, 169, 9);
  EXPECT_TRUE(ProviderHasAddr("CleanBrowsingSecure", dns_ip3));
  // Non-upgradeable IP
  IPAddress dns_ip4(1, 2, 3, 4);

  config.nameservers = {
      IPEndPoint(dns_ip0, dns_protocol::kDefaultPort),
      IPEndPoint(dns_ip1, dns_protocol::kDefaultPort),
      IPEndPoint(dns_ip2, 54),
      IPEndPoint(dns_ip3, dns_protocol::kDefaultPort),
      IPEndPoint(dns_ip4, dns_protocol::kDefaultPort),
  };
  EXPECT_TRUE(config.IsValid());
  return config;
}

// Check that entries are written to the cache with the right NAK.
TEST_F(HostResolverManagerTest, NetworkAnonymizationKeyWriteToHostCache) {
  const SchemefulSite kSite1(GURL("https://origin1.test/"));
  const SchemefulSite kSite2(GURL("https://origin2.test/"));
  auto kNetworkAnonymizationKey1 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite1);
  auto kNetworkAnonymizationKey2 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite2);

  const char kFirstDnsResult[] = "192.168.1.42";
  const char kSecondDnsResult[] = "192.168.1.43";

  for (bool split_cache_by_network_anonymization_key : {false, true}) {
    base::test::ScopedFeatureList feature_list;
    if (split_cache_by_network_anonymization_key) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    } else {
      feature_list.InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }
    proc_->AddRuleForAllFamilies("just.testing", kFirstDnsResult);
    proc_->SignalMultiple(1u);

    // Resolve a host using kNetworkAnonymizationKey1.
    ResolveHostResponseHelper response1(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey1,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response1.result_error(), IsOk());
    EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected(kFirstDnsResult, 80)));
    EXPECT_THAT(
        response1.request()->GetEndpointResults(),
        testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
            testing::ElementsAre(CreateExpected(kFirstDnsResult, 80))))));
    EXPECT_FALSE(response1.request()->GetStaleInfo());
    EXPECT_EQ(1u, proc_->GetCaptureList().size());

    // If the host cache is being split by NetworkAnonymizationKeys, there
    // should be an entry in the HostCache with kNetworkAnonymizationKey1.
    // Otherwise, there should be an entry with the empty NAK.
    if (split_cache_by_network_anonymization_key) {
      EXPECT_TRUE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey1)));

      EXPECT_FALSE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         NetworkAnonymizationKey())));
    } else {
      EXPECT_FALSE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey1)));

      EXPECT_TRUE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         NetworkAnonymizationKey())));
    }

    // There should be no entry using kNetworkAnonymizationKey2 in either case.
    EXPECT_FALSE(GetCacheHit(HostCache::Key(
        "just.testing", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
        HostResolverSource::ANY, kNetworkAnonymizationKey2)));

    // A request using kNetworkAnonymizationKey2 should only be served out of
    // the cache of the cache if |split_cache_by_network_anonymization_key| is
    // false. If it's not served over the network, it is provided a different
    // result.
    if (split_cache_by_network_anonymization_key) {
      proc_->AddRuleForAllFamilies("just.testing", kSecondDnsResult);
      proc_->SignalMultiple(1u);
    }
    ResolveHostResponseHelper response2(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey2,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response2.result_error(), IsOk());
    if (split_cache_by_network_anonymization_key) {
      EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                  testing::ElementsAre(CreateExpected(kSecondDnsResult, 80)));
      EXPECT_THAT(
          response2.request()->GetEndpointResults(),
          testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
              testing::ElementsAre(CreateExpected(kSecondDnsResult, 80))))));
      EXPECT_FALSE(response2.request()->GetStaleInfo());
      EXPECT_EQ(2u, proc_->GetCaptureList().size());
      EXPECT_TRUE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey2)));
    } else {
      EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                  testing::ElementsAre(CreateExpected(kFirstDnsResult, 80)));
      EXPECT_THAT(
          response2.request()->GetEndpointResults(),
          testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
              testing::ElementsAre(CreateExpected(kFirstDnsResult, 80))))));
      EXPECT_TRUE(response2.request()->GetStaleInfo());
      EXPECT_EQ(1u, proc_->GetCaptureList().size());
      EXPECT_FALSE(GetCacheHit(
          HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                         0 /* host_resolver_flags */, HostResolverSource::ANY,
                         kNetworkAnonymizationKey2)));
    }

    resolve_context_->host_cache()->clear();
    proc_->ClearCaptureList();
  }
}

// Check that entries are read to the cache with the right NAK.
TEST_F(HostResolverManagerTest, NetworkAnonymizationKeyReadFromHostCache) {
  const SchemefulSite kSite1(GURL("https://origin1.test/"));
  const SchemefulSite kSite2(GURL("https://origin2.test/"));
  auto kNetworkAnonymizationKey1 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite1);
  auto kNetworkAnonymizationKey2 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite2);

  struct CacheEntry {
    NetworkAnonymizationKey network_anonymization_key;
    const char* cached_ip_address;
  };

  const CacheEntry kCacheEntries[] = {
      {NetworkAnonymizationKey(), "192.168.1.42"},
      {kNetworkAnonymizationKey1, "192.168.1.43"},
      {kNetworkAnonymizationKey2, "192.168.1.44"},
  };

  // Add entries to cache for the empty NAK, NAK1, and NAK2. Only the
  // HostResolverManager obeys network state partitioning, so this is fine to do
  // regardless of the feature value.
  for (const auto& cache_entry : kCacheEntries) {
    HostCache::Key key("just.testing", DnsQueryType::UNSPECIFIED, 0,
                       HostResolverSource::ANY,
                       cache_entry.network_anonymization_key);
    IPAddress address;
    ASSERT_TRUE(address.AssignFromIPLiteral(cache_entry.cached_ip_address));
    HostCache::Entry entry = HostCache::Entry(
        OK, {{address, 80}}, /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);
    resolve_context_->host_cache()->Set(key, entry, base::TimeTicks::Now(),
                                        base::Days(1));
  }

  for (bool split_cache_by_network_anonymization_key : {false, true}) {
    base::test::ScopedFeatureList feature_list;
    if (split_cache_by_network_anonymization_key) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    } else {
      feature_list.InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }

    // A request that uses kNetworkAnonymizationKey1 will return cache entry 1
    // if the NetworkAnonymizationKeys are being used, and cache entry 0
    // otherwise.
    ResolveHostResponseHelper response1(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey1,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response1.result_error(), IsOk());
    EXPECT_THAT(
        response1.request()->GetAddressResults()->endpoints(),
        testing::ElementsAre(CreateExpected(
            kCacheEntries[split_cache_by_network_anonymization_key ? 1 : 0]
                .cached_ip_address,
            80)));
    EXPECT_THAT(
        response1.request()->GetEndpointResults(),
        testing::Pointee(testing::ElementsAre(
            ExpectEndpointResult(testing::ElementsAre(CreateExpected(
                kCacheEntries[split_cache_by_network_anonymization_key ? 1 : 0]
                    .cached_ip_address,
                80))))));
    EXPECT_TRUE(response1.request()->GetStaleInfo());

    // A request that uses kNetworkAnonymizationKey2 will return cache entry 2
    // if the NetworkAnonymizationKeys are being used, and cache entry 0
    // otherwise.
    ResolveHostResponseHelper response2(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey2,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_THAT(response2.result_error(), IsOk());
    EXPECT_THAT(
        response2.request()->GetAddressResults()->endpoints(),
        testing::ElementsAre(CreateExpected(
            kCacheEntries[split_cache_by_network_anonymization_key ? 2 : 0]
                .cached_ip_address,
            80)));
    EXPECT_THAT(
        response2.request()->GetEndpointResults(),
        testing::Pointee(testing::ElementsAre(
            ExpectEndpointResult(testing::ElementsAre(CreateExpected(
                kCacheEntries[split_cache_by_network_anonymization_key ? 2 : 0]
                    .cached_ip_address,
                80))))));
    EXPECT_TRUE(response2.request()->GetStaleInfo());
  }
}

// Test that two requests made with different NetworkAnonymizationKeys are not
// merged if network state partitioning is enabled.
TEST_F(HostResolverManagerTest, NetworkAnonymizationKeyTwoRequestsAtOnce) {
  const SchemefulSite kSite1(GURL("https://origin1.test/"));
  const SchemefulSite kSite2(GURL("https://origin2.test/"));
  auto kNetworkAnonymizationKey1 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite1);
  auto kNetworkAnonymizationKey2 =
      net::NetworkAnonymizationKey::CreateSameSite(kSite2);

  const char kDnsResult[] = "192.168.1.42";

  for (bool split_cache_by_network_anonymization_key : {false, true}) {
    base::test::ScopedFeatureList feature_list;
    if (split_cache_by_network_anonymization_key) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    } else {
      feature_list.InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }
    proc_->AddRuleForAllFamilies("just.testing", kDnsResult);

    // Start resolving a host using kNetworkAnonymizationKey1.
    ResolveHostResponseHelper response1(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey1,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_FALSE(response1.complete());

    // Start resolving the same host using kNetworkAnonymizationKey2.
    ResolveHostResponseHelper response2(resolver_->CreateRequest(
        HostPortPair("just.testing", 80), kNetworkAnonymizationKey2,
        NetLogWithSource(), std::nullopt, resolve_context_.get()));
    EXPECT_FALSE(response2.complete());

    // Wait for and complete the expected number of over-the-wire DNS
    // resolutions.
    if (split_cache_by_network_anonymization_key) {
      proc_->WaitFor(2);
      EXPECT_EQ(2u, proc_->GetCaptureList().size());
      proc_->SignalMultiple(2u);
    } else {
      proc_->WaitFor(1);
      EXPECT_EQ(1u, proc_->GetCaptureList().size());
      proc_->SignalMultiple(1u);
    }

    // Both requests should have completed successfully, with neither served out
    // of the cache.

    EXPECT_THAT(response1.result_error(), IsOk());
    EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected(kDnsResult, 80)));
    EXPECT_THAT(response1.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
    EXPECT_FALSE(response1.request()->GetStaleInfo());

    EXPECT_THAT(response2.result_error(), IsOk());
    EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected(kDnsResult, 80)));
    EXPECT_THAT(response2.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
    EXPECT_FALSE(response2.request()->GetStaleInfo());

    resolve_context_->host_cache()->clear();
    proc_->ClearCaptureList();
  }
}

// Test that two otherwise-identical requests with different ResolveContexts are
// not merged.
TEST_F(HostResolverManagerTest, ContextsNotMerged) {
  const char kDnsResult[] = "192.168.1.42";

  proc_->AddRuleForAllFamilies("just.testing", kDnsResult);

  // Start resolving a host using |resolve_context_|.
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_FALSE(response1.complete());

  // Start resolving the same host using another ResolveContext and cache.
  ResolveContext resolve_context2(resolve_context_->url_request_context(),
                                  true /* enable_caching */);
  resolver_->RegisterResolveContext(&resolve_context2);
  ResolveHostResponseHelper response2(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, &resolve_context2));
  EXPECT_FALSE(response2.complete());
  EXPECT_EQ(2u, resolver_->num_jobs_for_testing());

  // Wait for and complete the 2 over-the-wire DNS resolutions.
  proc_->WaitFor(2);
  EXPECT_EQ(2u, proc_->GetCaptureList().size());
  proc_->SignalMultiple(2u);

  // Both requests should have completed successfully, with neither served out
  // of the cache.

  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected(kDnsResult, 80)));
  EXPECT_THAT(response1.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
  EXPECT_FALSE(response1.request()->GetStaleInfo());

  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected(kDnsResult, 80)));
  EXPECT_THAT(response2.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected(kDnsResult, 80))))));
  EXPECT_FALSE(response2.request()->GetStaleInfo());

  EXPECT_EQ(1u, resolve_context_->host_cache()->size());
  EXPECT_EQ(1u, resolve_context2.host_cache()->size());

  resolver_->DeregisterResolveContext(&resolve_context2);
}

// HostResolverManagerDnsTest ==================================================

HostResolverManagerDnsTest::HostResolverManagerDnsTest(
    base::test::TaskEnvironment::TimeSource time_source)
    : HostResolverManagerTest(time_source),
      notifier_task_runner_(
          base::MakeRefCounted<base::TestMockTimeTaskRunner>()) {
  auto config_service = std::make_unique<TestDnsConfigService>();
  config_service_ = config_service.get();
  notifier_ = std::make_unique<SystemDnsConfigChangeNotifier>(
      notifier_task_runner_, std::move(config_service));
}

HostResolverManagerDnsTest::~HostResolverManagerDnsTest() = default;

void HostResolverManagerDnsTest::DestroyResolver() {
  mock_dns_client_ = nullptr;
  HostResolverManagerTest::DestroyResolver();
}

void HostResolverManagerDnsTest::SetDnsClient(
    std::unique_ptr<DnsClient> dns_client) {
  mock_dns_client_ = nullptr;
  resolver_->SetDnsClientForTesting(std::move(dns_client));
}

void HostResolverManagerDnsTest::TearDown() {
  HostResolverManagerTest::TearDown();
  InvalidateDnsConfig();

  // Ensure |notifier_| is fully cleaned up before test shutdown.
  notifier_.reset();
  notifier_task_runner_->RunUntilIdle();
}

HostResolver::ManagerOptions HostResolverManagerDnsTest::DefaultOptions() {
  HostResolver::ManagerOptions options =
      HostResolverManagerTest::DefaultOptions();
  options.insecure_dns_client_enabled = true;
  options.additional_types_via_insecure_dns_enabled = true;
  return options;
}

void HostResolverManagerDnsTest::CreateResolverWithOptionsAndParams(
    HostResolver::ManagerOptions options,
    const HostResolverSystemTask::Params& params,
    bool ipv6_reachable,
    bool is_async,
    bool ipv4_reachable) {
  DestroyResolver();

  resolver_ = std::make_unique<TestHostResolverManager>(
      options, notifier_.get(), nullptr /* net_log */, ipv6_reachable,
      ipv4_reachable, is_async);
  auto dns_client =
      std::make_unique<MockDnsClient>(DnsConfig(), CreateDefaultDnsRules());
  mock_dns_client_ = dns_client.get();
  resolver_->SetDnsClientForTesting(std::move(dns_client));
  resolver_->SetInsecureDnsClientEnabled(
      options.insecure_dns_client_enabled,
      options.additional_types_via_insecure_dns_enabled);
  resolver_->set_host_resolver_system_params_for_test(params);
  resolver_->RegisterResolveContext(resolve_context_.get());
}

void HostResolverManagerDnsTest::UseMockDnsClient(const DnsConfig& config,
                                                  MockDnsClientRuleList rules) {
  // HostResolver expects DnsConfig to get set after setting DnsClient, so
  // create first with an empty config and then update the config.
  auto dns_client =
      std::make_unique<MockDnsClient>(DnsConfig(), std::move(rules));
  mock_dns_client_ = dns_client.get();
  resolver_->SetDnsClientForTesting(std::move(dns_client));
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/true,
      /*additional_dns_types_enabled=*/true);
  if (!config.Equals(DnsConfig())) {
    ChangeDnsConfig(config);
  }
}

// static
MockDnsClientRuleList HostResolverManagerDnsTest::CreateDefaultDnsRules() {
  MockDnsClientRuleList rules;

  AddDnsRule(&rules, "nodomain", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kNoDomain, false /* delay */);
  AddDnsRule(&rules, "nodomain", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kNoDomain, false /* delay */);
  AddDnsRule(&rules, "nx", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kFail, false /* delay */);
  AddDnsRule(&rules, "nx", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kFail, false /* delay */);
  AddDnsRule(&rules, "ok", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "ok", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "4ok", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "4ok", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, false /* delay */);
  AddDnsRule(&rules, "6ok", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kEmpty, false /* delay */);
  AddDnsRule(&rules, "6ok", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "4nx", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "4nx", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kFail, false /* delay */);
  AddDnsRule(&rules, "empty", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kEmpty, false /* delay */);
  AddDnsRule(&rules, "empty", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, false /* delay */);

  AddDnsRule(&rules, "slow_nx", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kFail, true /* delay */);
  AddDnsRule(&rules, "slow_nx", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kFail, true /* delay */);

  AddDnsRule(&rules, "4slow_ok", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, true /* delay */);
  AddDnsRule(&rules, "4slow_ok", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "6slow_ok", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "6slow_ok", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kOk, true /* delay */);
  AddDnsRule(&rules, "4slow_4ok", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, true /* delay */);
  AddDnsRule(&rules, "4slow_4ok", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, false /* delay */);
  AddDnsRule(&rules, "4slow_4timeout", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kTimeout, true /* delay */);
  AddDnsRule(&rules, "4slow_4timeout", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "4slow_6timeout", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, true /* delay */);
  AddDnsRule(&rules, "4slow_6timeout", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kTimeout, false /* delay */);

  AddDnsRule(&rules, "4collision", dns_protocol::kTypeA,
    
"""


```