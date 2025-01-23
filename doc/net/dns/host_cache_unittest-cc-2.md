Response:
The user wants a summary of the functionality of the `host_cache_unittest.cc` file in the Chromium network stack, focusing on its relation to JavaScript, logical inferences with hypothetical inputs/outputs, common user/programming errors, debugging steps, and a general conclusion.

**Plan:**

1. **High-Level Functionality:** Identify the main purpose of the unit test file. It tests the `HostCache` class.
2. **Specific Test Cases:** Analyze the individual test functions to understand the specific features and scenarios being tested. These include setting, looking up, serializing, deserializing, merging cache entries, and interacting with a persistence delegate.
3. **JavaScript Relationship:** Determine if any test cases directly relate to how JavaScript interacts with the host cache. Likely no direct connection, but consider indirect relationships like browser API usage.
4. **Logical Inferences:** For test cases involving data manipulation (like merging), create hypothetical inputs and predict the outputs based on the code.
5. **User/Programming Errors:** Identify test cases that prevent common errors or handle invalid input, and explain the potential mistake.
6. **Debugging Steps:** Consider how the tests relate to real-world debugging. How would a developer use these tests to pinpoint issues?
7. **Part 3 Summary:** Combine the findings into a concise summary of the file's functionality based on the provided code snippet.
```
这是目录为net/dns/host_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
v4_alias};
  entry.set_canonical_names(canonical_names);

  EXPECT_THAT(entry.GetEndpoints(), Not(IsEmpty()));

  ConnectionEndpointMetadata metadata1;
  metadata1.supported_protocol_alpns = {"h3", "h2"};
  metadata1.ech_config_list = {'f', 'o', 'o'};
  metadata1.target_name = ipv6_alias;
  ConnectionEndpointMetadata metadata2;
  metadata2.supported_protocol_alpns = {"h2", "h4"};
  metadata2.target_name = ipv4_alias;
  HostCache::Entry metadata_entry(
      OK,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {1u, metadata1}, {2u, metadata2}},
      HostCache::Entry::SOURCE_DNS);

  auto merged_entry = HostCache::Entry::MergeEntries(entry, metadata_entry);

  EXPECT_THAT(merged_entry.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ip_endpoints)));
  EXPECT_THAT(
      merged_entry.GetMetadatas(),
      testing::ElementsAre(
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h3", "h2"),
                                           testing::ElementsAre('f', 'o', 'o'),
                                           ipv6_alias),
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h2", "h4"),
                                           IsEmpty(), ipv4_alias)));
  EXPECT_THAT(merged_entry.canonical_names(),
              UnorderedElementsAre(ipv4_alias, ipv6_alias));

  HostCache cache(kMaxCacheEntries);
  cache.Set(key, merged_entry, now, ttl);
  EXPECT_EQ(1u, cache.size());

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);
  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));

  // Check `serialized_cache` can be encoded as JSON. This ensures it has no
  // binary values.
  std::string json;
  EXPECT_TRUE(base::JSONWriter::Write(serialized_cache, &json));

  ASSERT_EQ(1u, restored_cache.size());
  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, now, &stale);

  ASSERT_TRUE(result);
  EXPECT_THAT(result, Pointee(Pair(key, EntryContentsEqual(merged_entry))));
  EXPECT_THAT(result->second.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ip_endpoints)));
  EXPECT_THAT(
      result->second.GetMetadatas(),
      testing::ElementsAre(
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h3", "h2"),
                                           testing::ElementsAre('f', 'o', 'o'),
                                           ipv6_alias),
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h2", "h4"),
                                           IsEmpty(), ipv4_alias)));
  EXPECT_THAT(result->second.canonical_names(),
              UnorderedElementsAre(ipv4_alias, ipv6_alias));

  EXPECT_EQ(result->second.aliases(), aliases);
}

TEST(HostCacheTest, DeserializeNoEndpointNoAliase) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "dns_query_type": 1,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_TRUE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(1u, restored_cache.size());

  HostCache::Key key(url::SchemeHostPort(url::kHttpsScheme, "example.com", 443),
                     DnsQueryType::A, 0, HostResolverSource::DNS,
                     NetworkAnonymizationKey());

  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, base::TimeTicks::Now(), &stale);

  ASSERT_TRUE(result);
  EXPECT_THAT(result->second.aliases(), ElementsAre());
  EXPECT_THAT(result->second.ip_endpoints(), ElementsAre());
}

TEST(HostCacheTest, DeserializeLegacyAddresses) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "addresses": [ "2000::", "1.2.3.4" ],
   "dns_query_type": 1,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_TRUE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(1u, restored_cache.size());

  HostCache::Key key(url::SchemeHostPort(url::kHttpsScheme, "example.com", 443),
                     DnsQueryType::A, 0, HostResolverSource::DNS,
                     NetworkAnonymizationKey());

  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, base::TimeTicks::Now(), &stale);

  ASSERT_TRUE(result);
  EXPECT_THAT(result->second.ip_endpoints(),
              ElementsAreArray(MakeEndpoints({"2000::", "1.2.3.4"})));
  EXPECT_THAT(result->second.aliases(), ElementsAre());
}

TEST(HostCacheTest, DeserializeInvalidQueryTypeIntegrity) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  // RestoreFromListValue doesn't support dns_query_type=6 (INTEGRITY).
  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "addresses": [ "2000::", "1.2.3.4" ],
   "dns_query_type": 6,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_FALSE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(0u, restored_cache.size());
}

TEST(HostCacheTest, DeserializeInvalidQueryTypeHttpsExperimental) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  // RestoreFromListValue doesn't support dns_query_type=8 (HTTPS_EXPERIMENTAL).
  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "addresses": [ "2000::", "1.2.3.4" ],
   "dns_query_type": 8,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_FALSE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(0u, restored_cache.size());
}

TEST(HostCacheTest, PersistenceDelegate) {
  const base::TimeDelta kTTL = base::Seconds(10);
  HostCache cache(kMaxCacheEntries);
  MockPersistenceDelegate delegate;
  cache.set_persistence_delegate(&delegate);

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");

  HostCache::Entry ok_entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);
  std::vector<IPEndPoint> other_endpoints = {
      IPEndPoint(IPAddress(1, 1, 1, 1), 300)};
  HostCache::Entry other_entry(OK, std::move(other_endpoints), /*aliases=*/{},
                               HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry error_entry =
      HostCache::Entry(ERR_NAME_NOT_RESOLVED, /*ip_endpoints=*/{},
                       /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);

  // Start at t=0.
  base::TimeTicks now;
  EXPECT_EQ(0u, cache.size());

  // Add two entries at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, ok_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(1u, cache.size());
  EXPECT_EQ(1, delegate.num_changes());

  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, error_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(2, delegate.num_changes());

  // Advance to t=5.
  now += base::Seconds(5);

  // Changes that shouldn't trigger a write:
  // Add an entry for "foobar.com" with different expiration time.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key1, ok_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(2, delegate.num_changes());

  // Add an entry for "foobar.com" with different TTL.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key1, ok_entry, now, kTTL - base::Seconds(5));
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(2, delegate.num_changes());

  // Changes that should trigger a write:
  // Add an entry for "foobar.com" with different address list.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key1, other_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(3, delegate.num_changes());

  // Add an entry for "foobar2.com" with different error.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key2, ok_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(4, delegate.num_changes());
}

TEST(HostCacheTest, MergeEndpointsWithAliases) {
  const IPAddress kAddressFront(1, 2, 3, 4);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, {"alias1", "alias2", "alias3"},
                         HostCache::Entry::SOURCE_DNS);
  front.set_text_records(std::vector<std::string>{"text1"});
  const HostPortPair kHostnameFront("host", 1);
  front.set_hostnames(std::vector<HostPortPair>{kHostnameFront});

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, {"alias2", "alias4", "alias5"},
                        HostCache::Entry::SOURCE_DNS);
  back.set_text_records(std::vector<std::string>{"text2"});
  const HostPortPair kHostnameBack("host", 2);
  back.set_hostnames(std::vector<HostPortPair>{kHostnameBack});

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(),
              ElementsAre(kEndpointFront, kEndpointBack));
  EXPECT_THAT(result.text_records(), ElementsAre("text1", "text2"));

  EXPECT_THAT(result.hostnames(), ElementsAre(kHostnameFront, kHostnameBack));

  EXPECT_THAT(
      result.aliases(),
      UnorderedElementsAre("alias1", "alias2", "alias3", "alias4", "alias5"));
}

TEST(HostCacheTest, MergeEndpointsKeepEndpointsOrder) {
  std::vector<IPEndPoint> front_addresses =
      MakeEndpoints({"::1", "0.0.0.2", "0.0.0.4"});
  std::vector<IPEndPoint> back_addresses =
      MakeEndpoints({"0.0.0.2", "0.0.0.2", "::3", "::3", "0.0.0.4"});

  HostCache::Entry front(OK, front_addresses, /*aliases=*/{"front"},
                         HostCache::Entry::SOURCE_DNS);
  HostCache::Entry back(OK, back_addresses, /*aliases=*/{"back"},
                        HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_THAT(
      result.ip_endpoints(),
      ElementsAreArray(MakeEndpoints({"::1", "0.0.0.2", "0.0.0.4", "0.0.0.2",
                                      "0.0.0.2", "::3", "::3", "0.0.0.4"})));
  EXPECT_THAT(result.aliases(), UnorderedElementsAre("front", "back"));
}

TEST(HostCacheTest, MergeMetadatas) {
  ConnectionEndpointMetadata front_metadata;
  front_metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  front_metadata.ech_config_list = {'h', 'i'};
  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      front_metadata_map{{4u, front_metadata}};
  HostCache::Entry front(OK, front_metadata_map, HostCache::Entry::SOURCE_DNS);

  ConnectionEndpointMetadata back_metadata;
  back_metadata.supported_protocol_alpns = {"h5"};
  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      back_metadata_map{{2u, back_metadata}};
  HostCache::Entry back(OK, back_metadata_map, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result = HostCache::Entry::MergeEntries(front, back);

  // Expect `GetEndpoints()` to ignore metadatas if no `IPEndPoint`s.
  EXPECT_THAT(result.GetEndpoints(), IsEmpty());

  // Expect order irrelevant for endpoint metadata merging.
  result = HostCache::Entry::MergeEntries(back, front);
  EXPECT_THAT(result.GetEndpoints(), IsEmpty());
}

TEST(HostCacheTest, MergeMetadatasWithIpEndpointsDifferentCanonicalName) {
  std::string target_name = "example.com";
  std::string other_target_name = "other.example.com";
  ConnectionEndpointMetadata metadata;
  metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  metadata.ech_config_list = {'h', 'i'};
  metadata.target_name = target_name;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadata_map{
      {4u, metadata}};
  HostCache::Entry metadata_entry(OK, metadata_map,
                                  HostCache::Entry::SOURCE_DNS);

  // Expect `GetEndpoints()` to always ignore metadatas with no `IPEndPoint`s.
  EXPECT_THAT(metadata_entry.GetEndpoints(), IsEmpty());

  // Merge in an `IPEndPoint` with different canonical name.
  IPEndPoint ip_endpoint(IPAddress(1, 1, 1, 1), 0);
  HostCache::Entry with_ip_endpoint(OK, {ip_endpoint}, /*aliases=*/{},
                                    HostCache::Entry::SOURCE_DNS);
  with_ip_endpoint.set_canonical_names(
      std::set<std::string>{other_target_name});
  HostCache::Entry result =
      HostCache::Entry::MergeEntries(metadata_entry, with_ip_endpoint);

  // Expect `GetEndpoints()` not to return the metadata.
  EXPECT_THAT(
      result.GetEndpoints(),
      ElementsAre(ExpectEndpointResult(std::vector<IPEndPoint>{ip_endpoint})));

  // Expect merge order irrelevant.
  EXPECT_EQ(result,
            HostCache::Entry::MergeEntries(with_ip_endpoint, metadata_entry));
}

TEST(HostCacheTest, MergeMetadatasWithIpEndpointsMatchingCanonicalName) {
  std::string target_name = "example.com";
  ConnectionEndpointMetadata metadata;
  metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  metadata.ech_config_list = {'h', 'i'};
  metadata.target_name = target_name;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadata_map{
      {4u, metadata}};
  HostCache::Entry metadata_entry(OK, metadata_map,
                                  HostCache::Entry::SOURCE_DNS);

  // Expect `GetEndpoints()` to always ignore metadatas with no `IPEndPoint`s.
  EXPECT_THAT(metadata_entry.GetEndpoints(), IsEmpty());

  // Merge in an `IPEndPoint` with different canonical name.
  IPEndPoint ip_endpoint(IPAddress(1, 1, 1, 1), 0);
  HostCache::Entry with_ip_endpoint(OK, {ip_endpoint}, /*aliases=*/{},
                                    HostCache::Entry::SOURCE_DNS);
  with_ip_endpoint.set_canonical_names(std::set<std::string>{target_name});
  HostCache::Entry result =
      HostCache::Entry::MergeEntries(metadata_entry, with_ip_endpoint);

  // Expect `GetEndpoints()` to return the metadata.
  EXPECT_THAT(
      result.GetEndpoints(),
      ElementsAre(ExpectEndpointResult(ElementsAre(ip_endpoint), metadata),
                  ExpectEndpointResult(ElementsAre(ip_endpoint))));

  // Expect merge order irrelevant.
  EXPECT_EQ(result,
            HostCache::Entry::MergeEntries(with_ip_endpoint, metadata_entry));
}

TEST(HostCacheTest, MergeMultipleMetadatasWithIpEndpoints) {
  std::string target_name = "example.com";
  ConnectionEndpointMetadata front_metadata;
  front_metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  front_metadata.ech_config_list = {'h', 'i'};
  front_metadata.target_name = target_name;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      front_metadata_map{{4u, front_metadata}};
  HostCache::Entry front(OK, front_metadata_map, HostCache::Entry::SOURCE_DNS);

  ConnectionEndpointMetadata back_metadata;
  back_metadata.supported_protocol_alpns = {"h5"};
  back_metadata.target_name = target_name;
  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      back_metadata_map{{2u, back_metadata}};
  HostCache::Entry back(OK, back_metadata_map, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry merged_metadatas =
      HostCache::Entry::MergeEntries(front, back);
  HostCache::Entry reversed_merged_metadatas =
      HostCache::Entry::MergeEntries(back, front);

  // Expect `GetEndpoints()` to always ignore metadatas with no `IPEndPoint`s.
  EXPECT_THAT(merged_metadatas.GetEndpoints(), IsEmpty());
  EXPECT_THAT(reversed_merged_metadatas.GetEndpoints(), IsEmpty());

  // Merge in an `IPEndPoint`.
  IPEndPoint ip_endpoint(IPAddress(1, 1, 1, 1), 0);
  HostCache::Entry with_ip_endpoint(OK, {ip_endpoint}, /*aliases=*/{},
                                    HostCache::Entry::SOURCE_DNS);
  with_ip_endpoint.set_canonical_names(std::set<std::string>{target_name});

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(merged_metadatas, with_ip_endpoint);

  // Expect `back_metadata` before `front_metadata` because it has lower
  // priority number.
  EXPECT_THAT(
      result.GetEndpoints(),
      ElementsAre(
          ExpectEndpointResult(ElementsAre(ip_endpoint), back_metadata),
          ExpectEndpointResult(ElementsAre(ip_endpoint), front_metadata),
          ExpectEndpointResult(ElementsAre(ip_endpoint))));

  // Expect merge order irrelevant.
  EXPECT_EQ(result, HostCache::Entry::MergeEntries(reversed_merged_metadatas,
                                                   with_ip_endpoint));
  EXPECT_EQ(result,
            HostCache::Entry::MergeEntries(with_ip_endpoint, merged_metadatas));
  EXPECT_EQ(result, HostCache::Entry::MergeEntries(with_ip_endpoint,
                                                   reversed_merged_metadatas));
}

TEST(HostCacheTest, MergeAliases) {
  HostCache::Entry front(OK, /*ip_endpoints=*/{},
                         /*aliases=*/{"foo1.test", "foo2.test", "foo3.test"},
                         HostCache::Entry::SOURCE_DNS);

  HostCache::Entry back(OK, /*ip_endpoints=*/{},
                        /*aliases=*/{"foo2.test", "foo4.test"},
                        HostCache::Entry::SOURCE_DNS);

  HostCache::Entry expected(
      OK, /*ip_endpoints=*/{},
      /*aliases=*/{"foo1.test", "foo2.test", "foo3.test", "foo4.test"},
      HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result = HostCache::Entry::MergeEntries(front, back);
  EXPECT_EQ(result, expected);

  // Expect order irrelevant for alias merging.
  result = HostCache::Entry::MergeEntries(back, front);
  EXPECT_EQ(result, expected);
}

TEST(HostCacheTest, MergeEntries_frontEmpty) {
  HostCache::Entry front(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, {"alias1", "alias2", "alias3"},
                        HostCache::Entry::SOURCE_DNS, base::Hours(4));
  back.set_text_records(std::vector<std::string>{"text2"});
  const HostPortPair kHostnameBack("host", 2);
  back.set_hostnames(std::vector<HostPortPair>{kHostnameBack});

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointBack));
  EXPECT_THAT(result.text_records(), ElementsAre("text2"));
  EXPECT_THAT(result.hostnames(), ElementsAre(kHostnameBack));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_backEmpty) {
  const IPAddress kAddressFront(1, 2, 3, 4);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, {"alias1", "alias2", "alias3"},
                         HostCache::Entry::SOURCE_DNS, base::Minutes(5));
  front.set_text_records(std::vector<std::string>{"text1"});
  const HostPortPair kHostnameFront("host", 1);
  front.set_hostnames(std::vector<HostPortPair>{kHostnameFront});

  HostCache::Entry back(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointFront));
  EXPECT_THAT(result.text_records(), ElementsAre("text1"));
  EXPECT_THAT(result.hostnames(), ElementsAre(kHostnameFront));

  EXPECT_EQ(base::Minutes(5), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_bothEmpty) {
  HostCache::Entry front(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);
  HostCache::Entry back(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), IsEmpty());
  EXPECT_THAT(result.text_records(), IsEmpty());
  EXPECT_THAT(result.hostnames(), IsEmpty());
  EXPECT_FALSE(result.has_ttl());
}

TEST(HostCacheTest, MergeEntries_frontWithAliasesNoAddressesBackWithBoth) {
  HostCache::Entry front(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);
  std::set<std::string> aliases_front({"alias0", "alias1", "alias2"});
  front.set_aliases(aliases_front);

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, {"alias1", "alias2", "alias3"},
                        HostCache::Entry::SOURCE_DNS, base::Hours(4));

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointBack));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias0", "alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_backWithAliasesNoAddressesFrontWithBoth) {
  HostCache::Entry back(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);
  std::set<std::string> aliases_back({"alias1", "alias2", "alias3"});
  back.set_aliases(aliases_back);

  const IPAddress kAddressFront(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, {"alias0", "alias1", "alias2"},
                         HostCache::Entry::SOURCE_DNS, base::Hours(4));

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointFront));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias0", "alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_frontWithAddressesNoAliasesBackWithBoth) {
  const IPAddress kAddressFront(1, 2, 3, 4);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, /*aliases=*/{},
                         HostCache::Entry::SOURCE_DNS, base::Hours(4));

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  Host
### 提示词
```
这是目录为net/dns/host_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
v4_alias};
  entry.set_canonical_names(canonical_names);

  EXPECT_THAT(entry.GetEndpoints(), Not(IsEmpty()));

  ConnectionEndpointMetadata metadata1;
  metadata1.supported_protocol_alpns = {"h3", "h2"};
  metadata1.ech_config_list = {'f', 'o', 'o'};
  metadata1.target_name = ipv6_alias;
  ConnectionEndpointMetadata metadata2;
  metadata2.supported_protocol_alpns = {"h2", "h4"};
  metadata2.target_name = ipv4_alias;
  HostCache::Entry metadata_entry(
      OK,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {1u, metadata1}, {2u, metadata2}},
      HostCache::Entry::SOURCE_DNS);

  auto merged_entry = HostCache::Entry::MergeEntries(entry, metadata_entry);

  EXPECT_THAT(merged_entry.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ip_endpoints)));
  EXPECT_THAT(
      merged_entry.GetMetadatas(),
      testing::ElementsAre(
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h3", "h2"),
                                           testing::ElementsAre('f', 'o', 'o'),
                                           ipv6_alias),
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h2", "h4"),
                                           IsEmpty(), ipv4_alias)));
  EXPECT_THAT(merged_entry.canonical_names(),
              UnorderedElementsAre(ipv4_alias, ipv6_alias));

  HostCache cache(kMaxCacheEntries);
  cache.Set(key, merged_entry, now, ttl);
  EXPECT_EQ(1u, cache.size());

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);
  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));

  // Check `serialized_cache` can be encoded as JSON. This ensures it has no
  // binary values.
  std::string json;
  EXPECT_TRUE(base::JSONWriter::Write(serialized_cache, &json));

  ASSERT_EQ(1u, restored_cache.size());
  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, now, &stale);

  ASSERT_TRUE(result);
  EXPECT_THAT(result, Pointee(Pair(key, EntryContentsEqual(merged_entry))));
  EXPECT_THAT(result->second.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ip_endpoints)));
  EXPECT_THAT(
      result->second.GetMetadatas(),
      testing::ElementsAre(
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h3", "h2"),
                                           testing::ElementsAre('f', 'o', 'o'),
                                           ipv6_alias),
          ExpectConnectionEndpointMetadata(testing::ElementsAre("h2", "h4"),
                                           IsEmpty(), ipv4_alias)));
  EXPECT_THAT(result->second.canonical_names(),
              UnorderedElementsAre(ipv4_alias, ipv6_alias));

  EXPECT_EQ(result->second.aliases(), aliases);
}

TEST(HostCacheTest, DeserializeNoEndpointNoAliase) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "dns_query_type": 1,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_TRUE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(1u, restored_cache.size());

  HostCache::Key key(url::SchemeHostPort(url::kHttpsScheme, "example.com", 443),
                     DnsQueryType::A, 0, HostResolverSource::DNS,
                     NetworkAnonymizationKey());

  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, base::TimeTicks::Now(), &stale);

  ASSERT_TRUE(result);
  EXPECT_THAT(result->second.aliases(), ElementsAre());
  EXPECT_THAT(result->second.ip_endpoints(), ElementsAre());
}

TEST(HostCacheTest, DeserializeLegacyAddresses) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "addresses": [ "2000::", "1.2.3.4" ],
   "dns_query_type": 1,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_TRUE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(1u, restored_cache.size());

  HostCache::Key key(url::SchemeHostPort(url::kHttpsScheme, "example.com", 443),
                     DnsQueryType::A, 0, HostResolverSource::DNS,
                     NetworkAnonymizationKey());

  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, base::TimeTicks::Now(), &stale);

  ASSERT_TRUE(result);
  EXPECT_THAT(result->second.ip_endpoints(),
              ElementsAreArray(MakeEndpoints({"2000::", "1.2.3.4"})));
  EXPECT_THAT(result->second.aliases(), ElementsAre());
}

TEST(HostCacheTest, DeserializeInvalidQueryTypeIntegrity) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  // RestoreFromListValue doesn't support dns_query_type=6 (INTEGRITY).
  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "addresses": [ "2000::", "1.2.3.4" ],
   "dns_query_type": 6,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_FALSE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(0u, restored_cache.size());
}

TEST(HostCacheTest, DeserializeInvalidQueryTypeHttpsExperimental) {
  base::TimeDelta ttl = base::Seconds(99);
  std::string expiration_time_str = base::NumberToString(
      (base::Time::Now() + ttl).since_origin().InMicroseconds());

  // RestoreFromListValue doesn't support dns_query_type=8 (HTTPS_EXPERIMENTAL).
  auto dict = base::JSONReader::Read(base::StringPrintf(
      R"(
 [ {
   "addresses": [ "2000::", "1.2.3.4" ],
   "dns_query_type": 8,
   "expiration": "%s",
   "flags": 0,
   "host_resolver_source": 2,
   "hostname": "example.com",
   "network_anonymization_key": [  ],
   "port": 443,
   "scheme": "https",
   "secure": false
} ]
)",
      expiration_time_str.c_str()));
  ASSERT_TRUE(dict);

  HostCache restored_cache(kMaxCacheEntries);
  ASSERT_TRUE(dict->is_list());
  EXPECT_FALSE(restored_cache.RestoreFromListValue(dict->GetList()));

  ASSERT_EQ(0u, restored_cache.size());
}

TEST(HostCacheTest, PersistenceDelegate) {
  const base::TimeDelta kTTL = base::Seconds(10);
  HostCache cache(kMaxCacheEntries);
  MockPersistenceDelegate delegate;
  cache.set_persistence_delegate(&delegate);

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");

  HostCache::Entry ok_entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);
  std::vector<IPEndPoint> other_endpoints = {
      IPEndPoint(IPAddress(1, 1, 1, 1), 300)};
  HostCache::Entry other_entry(OK, std::move(other_endpoints), /*aliases=*/{},
                               HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry error_entry =
      HostCache::Entry(ERR_NAME_NOT_RESOLVED, /*ip_endpoints=*/{},
                       /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);

  // Start at t=0.
  base::TimeTicks now;
  EXPECT_EQ(0u, cache.size());

  // Add two entries at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, ok_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(1u, cache.size());
  EXPECT_EQ(1, delegate.num_changes());

  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, error_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(2, delegate.num_changes());

  // Advance to t=5.
  now += base::Seconds(5);

  // Changes that shouldn't trigger a write:
  // Add an entry for "foobar.com" with different expiration time.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key1, ok_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(2, delegate.num_changes());

  // Add an entry for "foobar.com" with different TTL.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key1, ok_entry, now, kTTL - base::Seconds(5));
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(2, delegate.num_changes());

  // Changes that should trigger a write:
  // Add an entry for "foobar.com" with different address list.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key1, other_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(3, delegate.num_changes());

  // Add an entry for "foobar2.com" with different error.
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key2, ok_entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2u, cache.size());
  EXPECT_EQ(4, delegate.num_changes());
}

TEST(HostCacheTest, MergeEndpointsWithAliases) {
  const IPAddress kAddressFront(1, 2, 3, 4);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, {"alias1", "alias2", "alias3"},
                         HostCache::Entry::SOURCE_DNS);
  front.set_text_records(std::vector<std::string>{"text1"});
  const HostPortPair kHostnameFront("host", 1);
  front.set_hostnames(std::vector<HostPortPair>{kHostnameFront});

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, {"alias2", "alias4", "alias5"},
                        HostCache::Entry::SOURCE_DNS);
  back.set_text_records(std::vector<std::string>{"text2"});
  const HostPortPair kHostnameBack("host", 2);
  back.set_hostnames(std::vector<HostPortPair>{kHostnameBack});

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(),
              ElementsAre(kEndpointFront, kEndpointBack));
  EXPECT_THAT(result.text_records(), ElementsAre("text1", "text2"));

  EXPECT_THAT(result.hostnames(), ElementsAre(kHostnameFront, kHostnameBack));

  EXPECT_THAT(
      result.aliases(),
      UnorderedElementsAre("alias1", "alias2", "alias3", "alias4", "alias5"));
}

TEST(HostCacheTest, MergeEndpointsKeepEndpointsOrder) {
  std::vector<IPEndPoint> front_addresses =
      MakeEndpoints({"::1", "0.0.0.2", "0.0.0.4"});
  std::vector<IPEndPoint> back_addresses =
      MakeEndpoints({"0.0.0.2", "0.0.0.2", "::3", "::3", "0.0.0.4"});

  HostCache::Entry front(OK, front_addresses, /*aliases=*/{"front"},
                         HostCache::Entry::SOURCE_DNS);
  HostCache::Entry back(OK, back_addresses, /*aliases=*/{"back"},
                        HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_THAT(
      result.ip_endpoints(),
      ElementsAreArray(MakeEndpoints({"::1", "0.0.0.2", "0.0.0.4", "0.0.0.2",
                                      "0.0.0.2", "::3", "::3", "0.0.0.4"})));
  EXPECT_THAT(result.aliases(), UnorderedElementsAre("front", "back"));
}

TEST(HostCacheTest, MergeMetadatas) {
  ConnectionEndpointMetadata front_metadata;
  front_metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  front_metadata.ech_config_list = {'h', 'i'};
  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      front_metadata_map{{4u, front_metadata}};
  HostCache::Entry front(OK, front_metadata_map, HostCache::Entry::SOURCE_DNS);

  ConnectionEndpointMetadata back_metadata;
  back_metadata.supported_protocol_alpns = {"h5"};
  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      back_metadata_map{{2u, back_metadata}};
  HostCache::Entry back(OK, back_metadata_map, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result = HostCache::Entry::MergeEntries(front, back);

  // Expect `GetEndpoints()` to ignore metadatas if no `IPEndPoint`s.
  EXPECT_THAT(result.GetEndpoints(), IsEmpty());

  // Expect order irrelevant for endpoint metadata merging.
  result = HostCache::Entry::MergeEntries(back, front);
  EXPECT_THAT(result.GetEndpoints(), IsEmpty());
}

TEST(HostCacheTest, MergeMetadatasWithIpEndpointsDifferentCanonicalName) {
  std::string target_name = "example.com";
  std::string other_target_name = "other.example.com";
  ConnectionEndpointMetadata metadata;
  metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  metadata.ech_config_list = {'h', 'i'};
  metadata.target_name = target_name;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadata_map{
      {4u, metadata}};
  HostCache::Entry metadata_entry(OK, metadata_map,
                                  HostCache::Entry::SOURCE_DNS);

  // Expect `GetEndpoints()` to always ignore metadatas with no `IPEndPoint`s.
  EXPECT_THAT(metadata_entry.GetEndpoints(), IsEmpty());

  // Merge in an `IPEndPoint` with different canonical name.
  IPEndPoint ip_endpoint(IPAddress(1, 1, 1, 1), 0);
  HostCache::Entry with_ip_endpoint(OK, {ip_endpoint}, /*aliases=*/{},
                                    HostCache::Entry::SOURCE_DNS);
  with_ip_endpoint.set_canonical_names(
      std::set<std::string>{other_target_name});
  HostCache::Entry result =
      HostCache::Entry::MergeEntries(metadata_entry, with_ip_endpoint);

  // Expect `GetEndpoints()` not to return the metadata.
  EXPECT_THAT(
      result.GetEndpoints(),
      ElementsAre(ExpectEndpointResult(std::vector<IPEndPoint>{ip_endpoint})));

  // Expect merge order irrelevant.
  EXPECT_EQ(result,
            HostCache::Entry::MergeEntries(with_ip_endpoint, metadata_entry));
}

TEST(HostCacheTest, MergeMetadatasWithIpEndpointsMatchingCanonicalName) {
  std::string target_name = "example.com";
  ConnectionEndpointMetadata metadata;
  metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  metadata.ech_config_list = {'h', 'i'};
  metadata.target_name = target_name;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadata_map{
      {4u, metadata}};
  HostCache::Entry metadata_entry(OK, metadata_map,
                                  HostCache::Entry::SOURCE_DNS);

  // Expect `GetEndpoints()` to always ignore metadatas with no `IPEndPoint`s.
  EXPECT_THAT(metadata_entry.GetEndpoints(), IsEmpty());

  // Merge in an `IPEndPoint` with different canonical name.
  IPEndPoint ip_endpoint(IPAddress(1, 1, 1, 1), 0);
  HostCache::Entry with_ip_endpoint(OK, {ip_endpoint}, /*aliases=*/{},
                                    HostCache::Entry::SOURCE_DNS);
  with_ip_endpoint.set_canonical_names(std::set<std::string>{target_name});
  HostCache::Entry result =
      HostCache::Entry::MergeEntries(metadata_entry, with_ip_endpoint);

  // Expect `GetEndpoints()` to return the metadata.
  EXPECT_THAT(
      result.GetEndpoints(),
      ElementsAre(ExpectEndpointResult(ElementsAre(ip_endpoint), metadata),
                  ExpectEndpointResult(ElementsAre(ip_endpoint))));

  // Expect merge order irrelevant.
  EXPECT_EQ(result,
            HostCache::Entry::MergeEntries(with_ip_endpoint, metadata_entry));
}

TEST(HostCacheTest, MergeMultipleMetadatasWithIpEndpoints) {
  std::string target_name = "example.com";
  ConnectionEndpointMetadata front_metadata;
  front_metadata.supported_protocol_alpns = {"h5", "h6", "monster truck rally"};
  front_metadata.ech_config_list = {'h', 'i'};
  front_metadata.target_name = target_name;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      front_metadata_map{{4u, front_metadata}};
  HostCache::Entry front(OK, front_metadata_map, HostCache::Entry::SOURCE_DNS);

  ConnectionEndpointMetadata back_metadata;
  back_metadata.supported_protocol_alpns = {"h5"};
  back_metadata.target_name = target_name;
  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      back_metadata_map{{2u, back_metadata}};
  HostCache::Entry back(OK, back_metadata_map, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry merged_metadatas =
      HostCache::Entry::MergeEntries(front, back);
  HostCache::Entry reversed_merged_metadatas =
      HostCache::Entry::MergeEntries(back, front);

  // Expect `GetEndpoints()` to always ignore metadatas with no `IPEndPoint`s.
  EXPECT_THAT(merged_metadatas.GetEndpoints(), IsEmpty());
  EXPECT_THAT(reversed_merged_metadatas.GetEndpoints(), IsEmpty());

  // Merge in an `IPEndPoint`.
  IPEndPoint ip_endpoint(IPAddress(1, 1, 1, 1), 0);
  HostCache::Entry with_ip_endpoint(OK, {ip_endpoint}, /*aliases=*/{},
                                    HostCache::Entry::SOURCE_DNS);
  with_ip_endpoint.set_canonical_names(std::set<std::string>{target_name});

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(merged_metadatas, with_ip_endpoint);

  // Expect `back_metadata` before `front_metadata` because it has lower
  // priority number.
  EXPECT_THAT(
      result.GetEndpoints(),
      ElementsAre(
          ExpectEndpointResult(ElementsAre(ip_endpoint), back_metadata),
          ExpectEndpointResult(ElementsAre(ip_endpoint), front_metadata),
          ExpectEndpointResult(ElementsAre(ip_endpoint))));

  // Expect merge order irrelevant.
  EXPECT_EQ(result, HostCache::Entry::MergeEntries(reversed_merged_metadatas,
                                                   with_ip_endpoint));
  EXPECT_EQ(result,
            HostCache::Entry::MergeEntries(with_ip_endpoint, merged_metadatas));
  EXPECT_EQ(result, HostCache::Entry::MergeEntries(with_ip_endpoint,
                                                   reversed_merged_metadatas));
}

TEST(HostCacheTest, MergeAliases) {
  HostCache::Entry front(OK, /*ip_endpoints=*/{},
                         /*aliases=*/{"foo1.test", "foo2.test", "foo3.test"},
                         HostCache::Entry::SOURCE_DNS);

  HostCache::Entry back(OK, /*ip_endpoints=*/{},
                        /*aliases=*/{"foo2.test", "foo4.test"},
                        HostCache::Entry::SOURCE_DNS);

  HostCache::Entry expected(
      OK, /*ip_endpoints=*/{},
      /*aliases=*/{"foo1.test", "foo2.test", "foo3.test", "foo4.test"},
      HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result = HostCache::Entry::MergeEntries(front, back);
  EXPECT_EQ(result, expected);

  // Expect order irrelevant for alias merging.
  result = HostCache::Entry::MergeEntries(back, front);
  EXPECT_EQ(result, expected);
}

TEST(HostCacheTest, MergeEntries_frontEmpty) {
  HostCache::Entry front(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, {"alias1", "alias2", "alias3"},
                        HostCache::Entry::SOURCE_DNS, base::Hours(4));
  back.set_text_records(std::vector<std::string>{"text2"});
  const HostPortPair kHostnameBack("host", 2);
  back.set_hostnames(std::vector<HostPortPair>{kHostnameBack});

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointBack));
  EXPECT_THAT(result.text_records(), ElementsAre("text2"));
  EXPECT_THAT(result.hostnames(), ElementsAre(kHostnameBack));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_backEmpty) {
  const IPAddress kAddressFront(1, 2, 3, 4);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, {"alias1", "alias2", "alias3"},
                         HostCache::Entry::SOURCE_DNS, base::Minutes(5));
  front.set_text_records(std::vector<std::string>{"text1"});
  const HostPortPair kHostnameFront("host", 1);
  front.set_hostnames(std::vector<HostPortPair>{kHostnameFront});

  HostCache::Entry back(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointFront));
  EXPECT_THAT(result.text_records(), ElementsAre("text1"));
  EXPECT_THAT(result.hostnames(), ElementsAre(kHostnameFront));

  EXPECT_EQ(base::Minutes(5), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_bothEmpty) {
  HostCache::Entry front(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);
  HostCache::Entry back(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), IsEmpty());
  EXPECT_THAT(result.text_records(), IsEmpty());
  EXPECT_THAT(result.hostnames(), IsEmpty());
  EXPECT_FALSE(result.has_ttl());
}

TEST(HostCacheTest, MergeEntries_frontWithAliasesNoAddressesBackWithBoth) {
  HostCache::Entry front(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);
  std::set<std::string> aliases_front({"alias0", "alias1", "alias2"});
  front.set_aliases(aliases_front);

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, {"alias1", "alias2", "alias3"},
                        HostCache::Entry::SOURCE_DNS, base::Hours(4));

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointBack));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias0", "alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_backWithAliasesNoAddressesFrontWithBoth) {
  HostCache::Entry back(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);
  std::set<std::string> aliases_back({"alias1", "alias2", "alias3"});
  back.set_aliases(aliases_back);

  const IPAddress kAddressFront(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, {"alias0", "alias1", "alias2"},
                         HostCache::Entry::SOURCE_DNS, base::Hours(4));

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(), ElementsAre(kEndpointFront));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias0", "alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_frontWithAddressesNoAliasesBackWithBoth) {
  const IPAddress kAddressFront(1, 2, 3, 4);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, /*aliases=*/{},
                         HostCache::Entry::SOURCE_DNS, base::Hours(4));

  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, {"alias1", "alias2", "alias3"},
                        HostCache::Entry::SOURCE_DNS, base::Hours(4));
  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(),
              ElementsAre(kEndpointFront, kEndpointBack));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_backWithAddressesNoAliasesFrontWithBoth) {
  const IPAddress kAddressFront(1, 2, 3, 4);
  const IPEndPoint kEndpointFront(kAddressFront, 0);
  HostCache::Entry front(OK, {kEndpointFront}, {"alias1", "alias2", "alias3"},
                         HostCache::Entry::SOURCE_DNS, base::Hours(4));
  const IPAddress kAddressBack(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0);
  const IPEndPoint kEndpointBack(kAddressBack, 0);
  HostCache::Entry back(OK, {kEndpointBack}, /*aliases=*/{},
                        HostCache::Entry::SOURCE_DNS, base::Hours(4));

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(OK, result.error());
  EXPECT_EQ(HostCache::Entry::SOURCE_DNS, result.source());

  EXPECT_THAT(result.ip_endpoints(),
              ElementsAre(kEndpointFront, kEndpointBack));

  EXPECT_EQ(base::Hours(4), result.ttl());

  EXPECT_THAT(result.aliases(),
              UnorderedElementsAre("alias1", "alias2", "alias3"));
}

TEST(HostCacheTest, MergeEntries_differentTtl) {
  HostCache::Entry front(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS,
                         base::Days(12));
  HostCache::Entry back(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS,
                        base::Seconds(42));

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_EQ(base::Seconds(42), result.ttl());
}

TEST(HostCacheTest, MergeEntries_FrontCannonnamePreserved) {
  HostCache::Entry front(OK, /*ip_endpoints=*/{}, /*aliases=*/{"name1"},
                         HostCache::Entry::SOURCE_DNS);

  HostCache::Entry back(OK, /*ip_endpoints=*/{}, /*aliases=*/{"name2"},
                        HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_THAT(result.aliases(), UnorderedElementsAre("name1", "name2"));
}

// Test that the back canonname can be used if there is no front cannonname.
TEST(HostCacheTest, MergeEntries_BackCannonnameUsable) {
  HostCache::Entry front(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                         HostCache::Entry::SOURCE_DNS);

  HostCache::Entry back(OK, /*ip_endpoints=*/{}, /*aliases=*/{"name2"},
                        HostCache::Entry::SOURCE_DNS);

  HostCache::Entry result =
      HostCache::Entry::MergeEntries(std::move(front), std::move(back));

  EXPECT_THAT(result.aliases(), UnorderedElementsAre("name2"));
}

TEST(HostCacheTest, ConvertFromInternalAddressResult) {
  const std::vector<IPEndPoint> kEndpoints{
      IPEndPoint(IPAddress(2, 2, 2, 2), 46)};
  constexpr base::TimeDelta kTtl1 = base::Minutes(45);
  constexpr base::TimeDelta kTtl2 = base::Minutes(40);
  constexpr base::TimeDelta kTtl3 = base::Minutes(55);

  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  results.insert(std::make_unique<HostResolverInternalDataResult>(
      "endpoint.test", DnsQueryType::AAAA, base::TimeTicks() + kTtl1,
      base::Time() + kTtl1, HostResolverInternalResult::Source::kDns,
      kEndpoints, std::vector<std::string>{}, std::vector<HostPortPair>{}));
  results.insert(std::make_unique<HostResolverInternalAliasResult>(
      "domain1.test", DnsQueryType::AAAA, base::TimeTicks() + kTtl2,
      base::Time() + kTtl2, HostResolverInternalResult::Source::kDns,
      "domain2.test"));
  results.insert(std::make_unique<HostResolverInternalAliasResult>(
      "domain2.test", DnsQueryType::AAAA, base::TimeTicks() + kTtl3,
      base::Time() + kTtl3, HostResolverInternalResult::Source::kDns,
      "endpoint.test"));

  HostCache::Entry converted(std::move(results), base::Time(),
                             base::TimeTicks());

  // Expect kTtl2 because it is the min TTL.
  HostCache::Entry expected(
      OK, kEndpoints,
      /*aliases=*/{"domain1.test", "domain2.test", "endpoint.test"},
      HostCache::Entry::SOURCE_DNS, kTtl2);
  expected.set_canonical_names(std::set<std::string>{"endpoint.test"});

  // Entries converted from HostResolverInternalDataResults do not differentiate
  // between empty and no-data for the various data types, so need to set empty
  // strings and hostname entries into `expected`.
  expected.set_text_records(std::vector<std::string>());
  expected.set_hostnames(std::vector<HostPortPair>());

  EXPECT_EQ(converted, expected);
}

TEST(HostCacheTest, ConvertFromInternalMetadataResult) {
  const std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      kMetadatas{{1, ConnectionEndpointMetadata({"h2", "h3"},
                                                /*ech_config_list=*/{},
                                                "target.test")}};
  constexpr base::TimeDelta kTtl1 = base::Minutes(45);
  constexpr base::TimeDelta kTtl2 = base::Minutes(40);
  constexpr base::TimeDelta kTtl3 = base::Minutes(55);

  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  results.insert(std::make_unique<HostResolverInternalMetadataResult>(
      "endpoint.test", DnsQueryType::HTTPS, base::TimeTicks() + kTtl1,
      base::Time() + kTtl1, HostResolverInternalResult::Source::kDns,
      kMetadatas));
  results.insert(std::make_unique<HostResolverInternalAliasResult>(
      "domain1.test", DnsQueryType::HTTPS, base::TimeTicks() + kTtl2,
      base::Time() + kTtl2, HostResolverInternalResult::Source::kDns,
      "domain2.test"));
  results.insert(std::make_unique<HostResolverInternalAliasResult>(
      "domain2.test", DnsQueryType::HTTPS, base::TimeTicks() + kTtl3,
      base::Time() + kTtl3, HostResolverInternalResult::Source::kDns,
      "endpoint.test"));

  HostCache::Entry converted(std::move(results), base::Time(),
                             base::TimeTicks());

  // Expect kTtl2 because it is the min TTL.
  HostCache::Entry expected(OK, kMetadatas, HostCache::Entry::SOURCE_DNS,
                            kTtl2);
  expected.set_https_record_compatibility(std::vector<bool>{true});

  EXPECT_EQ(converted, expected);
}

// Test the case of compatible HTTPS records but no metadata of use to Chrome.
// Represented in internal result type as an empty metadata result. Represented
// in HostCache::Entry as empty metadata with at least one true in
// `https_record_compatibility_`.
TEST(HostCacheTest, ConvertFromCompatibleOnlyInternalMetadataResult) {
  const std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      kMetadatas;
  constexpr base::TimeDelta kTtl1 = base::Minutes(45);
  constexpr base::TimeDelta kTtl2 = base::Minutes(40);
  constexpr base::TimeDelta kTtl3 = base::Minutes(55);

  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  results.insert(std::make_unique<HostResolverInternalMetadataResult>(
      "endpoint.test", DnsQueryType::HTTPS, base::TimeTicks() + kTtl1,
      base::Time() + kTtl1, HostResolverInternalResult::Source::kDns,
      kMetadatas));
  results.insert(std::make_unique<HostResolverInternalAliasResult>(
      "domain1.test", DnsQueryType::HTTPS, base::TimeTicks() + kTtl2,
      base::Time() + kTtl2, HostResolverInternalResult::Source::kDns,
      "domain2.test"));
  results.insert(std::make_unique<HostResolverInternalAliasResult>(
      "domain2.test", DnsQueryType::HTTPS, base::TimeTicks() + kTtl3,
      base
```