Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of Chromium's network stack. The file is `http_server_properties_unittest.cc`. Given the filename and the context, it's highly likely this file contains unit tests for the `HttpServerProperties` class.

Here's a breakdown of the thought process to address each part of the request:

1. **Functionality of the code:**
   - The file name `http_server_properties_unittest.cc` immediately suggests unit tests.
   - The code consists of `TEST_F` macros, which are standard Google Test constructs for defining test cases within a test fixture (`HttpServerPropertiesTest`).
   - The tests manipulate and verify the state of an `HttpServerProperties` object (`impl_` in most tests, `properties` in some).
   - The test names (`Clear`, `ClearServerNetworkStats`, `OnQuicServerInfoMapLoaded`, `SetQuicServerInfo`, `QuicServerInfoCanonicalSuffixMatch`, etc.) clearly indicate the specific functionalities being tested.
   - The tests involve setting, getting, and clearing various properties related to HTTP servers, particularly concerning QUIC connections and network statistics.
   - Therefore, the primary function is to **test the functionality of the `HttpServerProperties` class**, ensuring it behaves as expected when managing server-specific data.

2. **Relationship with JavaScript:**
   - `HttpServerProperties` manages network-level configurations and data. JavaScript running in a browser interacts with these settings indirectly through browser APIs.
   - The most direct connection is related to **QUIC and network performance**. JavaScript can initiate network requests, and the underlying network stack (managed partly by `HttpServerProperties`) will determine if a QUIC connection can be established and use the stored server information.
   - **Example:** When a JavaScript application makes an HTTPS request to a server, `HttpServerProperties` might have stored QUIC connection information for that server (from previous visits). This information allows the browser to potentially establish a faster QUIC connection instead of a traditional TCP connection. This is transparent to the JavaScript code, but it benefits from the functionality being tested.
   - **Other potential indirect connections:**  HTTP caching (though not directly showcased in this snippet), HSTS (HTTP Strict Transport Security) – while not explicitly tested here, `HttpServerProperties` often manages related information. JavaScript might trigger actions that rely on these stored properties.

3. **Logical Reasoning (Input/Output):**
   - **`Clear` test:**
     - *Input:*  Set some server network stats for HTTP and HTTPS servers.
     - *Action:* Call `impl_.Clear()`.
     - *Output:*  Getting the server network stats for both servers should return `nullptr`.
   - **`ClearServerNetworkStats` test:**
     - *Input:* Set server network stats for an HTTPS server.
     - *Action:* Call `impl_.ClearServerNetworkStats()` for that server.
     - *Output:* Getting the server network stats for that server should return `nullptr`.
   - **`OnQuicServerInfoMapLoaded` test:**
     - *Input:*  Load an empty or populated `QuicServerInfoMap`.
     - *Action:* Call `impl_.OnQuicServerInfoMapLoadedForTesting()`.
     - *Output:* The `impl_.quic_server_info_map()` should reflect the loaded data, respecting the maximum size and MRU order.
   - **`SetQuicServerInfo` test:**
     - *Input:* Set QUIC server info for different servers with and without network isolation keys enabled.
     - *Action:* Call `impl_.SetQuicServerInfo()` and `properties.SetQuicServerInfo()`.
     - *Output:* Getting the QUIC server info should return the set values, respecting privacy mode and network isolation keys.
   - **`QuicServerInfoCanonicalSuffixMatch` test:**
     - *Input:* Set QUIC server info for `foo.googlevideo.com`.
     - *Action:* Get QUIC server info for `bar.googlevideo.com`.
     - *Output:* The info for `foo.googlevideo.com` should be returned because they share a canonical suffix.
   - **`QuicServerInfoCanonicalSuffixMatchWithNetworkIsolationKey` test:**
     - *Input:* Set QUIC server info for `foo.googlevideo.com` and `bar.googlevideo.com` with different network isolation keys.
     - *Action:* Get QUIC server info for both with different and matching keys.
     - *Output:*  The correct server info should be retrieved based on the matching network isolation key.
   - **`QuicServerInfoCanonicalSuffixMatchReturnsMruEntry` test:**
     - *Input:* Set QUIC server info for `h1.googlevideo.com` and `h2.googlevideo.com`.
     - *Action:* Get info for `foo.googlevideo.com`.
     - *Output:* The info for the most recently used canonical match should be returned.
   - **`QuicServerInfoCanonicalSuffixMatchDoesntChangeOrder` test:**
     - *Input:* Set QUIC server info.
     - *Action:* Get info using a canonical match.
     - *Output:* The MRU order should not change if accessed through canonical matching.
   - **`QuicServerInfoCanonicalSuffixMatchSetInfoMap` test:**
     - *Input:* Set QUIC server info using both `SetQuicServerInfo` and `OnQuicServerInfoMapLoadedForTesting`.
     - *Action:* Get info using canonical matching.
     - *Output:* The most recently used entry (either from memory or loaded map) should be returned.

4. **User/Programming Errors:**
   - **Incorrect key usage:**  Trying to retrieve server properties using an incorrect `NetworkAnonymizationKey` or `PrivacyMode`. The tests demonstrate how these keys affect the retrieval of information.
   - **Forgetting to clear:**  Not calling `Clear()` or specific clear methods when it's necessary, leading to stale or incorrect data being used. The tests verify that clearing works correctly.
   - **Incorrectly assuming canonical suffix matching always works:**  While convenient, it's important to understand when it applies and that the MRU entry is returned. A developer might assume a specific entry is returned based on suffix matching but get a different one due to recency.
   - **Exceeding maximum stored entries:**  Setting more server configurations than the maximum allowed. The tests using `SetMaxServerConfigsStoredInProperties` illustrate how the system handles this.

5. **User Operations Leading to This Code (Debugging):**
   - A user browses the internet, visiting various websites.
   - The browser attempts to establish connections to these websites, potentially using QUIC.
   - The `HttpServerProperties` class stores information about these servers, such as QUIC connection parameters and network statistics.
   - **Scenario leading to `SetQuicServerInfo`:** The browser successfully establishes a QUIC connection with a server. The parameters of this connection (e.g., supported QUIC versions, server configurations) are stored using `SetQuicServerInfo`.
   - **Scenario leading to `GetQuicServerInfo` (canonical suffix match):** The user navigates to a subdomain of a site for which QUIC info is already stored (e.g., navigating to `bar.googlevideo.com` after visiting `foo.googlevideo.com`). The browser might check `HttpServerProperties` for QUIC info for the canonical domain (`googlevideo.com`).
   - **Scenario leading to `Clear`:** The user clears their browsing data (history, cookies, cached data). This action might trigger a call to `Clear()` on `HttpServerProperties` to remove stored server information.
   - **Debugging Steps:** If a user reports issues with slow connections or QUIC not being used as expected, a developer might investigate the state of `HttpServerProperties`. They might:
     - Set breakpoints in the `SetQuicServerInfo` or `GetQuicServerInfo` methods.
     - Check the contents of the `quic_server_info_map_`.
     - Verify if the expected server information is present and being retrieved correctly, considering privacy mode and network isolation keys.
     - Examine the MRU order of the entries in the map.

6. **Summary of Functionality (Part 5):**
   - This specific part of the code continues to test the `HttpServerProperties` class, focusing on how it manages and retrieves QUIC server information. It specifically tests:
     - **Canonical suffix matching for QUIC server info:**  Ensuring that if there's no exact match for a host, the stored information for a host with the same canonical suffix is retrieved.
     - **Interaction of canonical suffix matching with Network Isolation Keys:** Verifying that when network isolation is enabled, canonical suffix matching respects the isolation boundaries.
     - **MRU (Most Recently Used) behavior:**  Confirming that when multiple entries match a canonical suffix, the most recently used entry is returned.
     - **Persistence of MRU order:** Ensuring that accessing server info via canonical suffix matching doesn't inadvertently change the MRU order unless the specific matched entry is directly accessed.
     - **Interaction between in-memory cache and loaded data:** Testing that canonical suffix matching works correctly regardless of whether the server info was added in memory or loaded from persistent storage, and that the MRU order is maintained across both sources.

Essentially, this section delves deeper into the nuanced behavior of how `HttpServerProperties` efficiently stores and retrieves QUIC-related server data, considering canonical domain names, privacy, and network isolation.
This is the **fifth and final part** of the `net/http/http_server_properties_unittest.cc` file in the Chromium network stack. Building upon the previous parts, this section primarily focuses on testing the functionality related to **storing and retrieving QUIC server information**, especially considering **canonical suffixes** and the interaction with **Network Isolation Keys**.

Here's a breakdown of the functionalities tested in this section:

**Core Functionality:**

* **Canonical Suffix Matching for QUIC Server Info:**
    * **Purpose:**  If there's no exact match for a QUIC server ID in the stored properties, the code checks if there's information available for a server with the same canonical suffix (e.g., `foo.googlevideo.com` and `bar.googlevideo.com` share the `googlevideo.com` suffix).
    * **Testing:** The tests `QuicServerInfoCanonicalSuffixMatch`, `QuicServerInfoCanonicalSuffixMatchWithNetworkIsolationKey`, `QuicServerInfoCanonicalSuffixMatchReturnsMruEntry`, `QuicServerInfoCanonicalSuffixMatchDoesntChangeOrder`, and `QuicServerInfoCanonicalSuffixMatchSetInfoMap` all focus on verifying this behavior under different conditions.

* **Interaction with Network Isolation Keys for Canonical Suffix Matching:**
    * **Purpose:** When Network Isolation Keys are enabled (for privacy and security), the canonical suffix matching should respect these keys. Information stored for one Network Isolation Key should not be accessible when querying with a different key, even if the canonical suffix matches.
    * **Testing:** The `QuicServerInfoCanonicalSuffixMatchWithNetworkIsolationKey` test specifically validates this interaction.

* **Most Recently Used (MRU) Behavior with Canonical Suffix Matching:**
    * **Purpose:** When multiple servers with the same canonical suffix have stored QUIC information, the most recently accessed entry should be returned when querying using a server ID with that suffix.
    * **Testing:** The `QuicServerInfoCanonicalSuffixMatchReturnsMruEntry` test confirms this MRU behavior.

* **Maintaining MRU Order During Canonical Suffix Lookups:**
    * **Purpose:** Querying for QUIC information using a canonical suffix match should not change the MRU order of the underlying storage unless the specific matched entry is directly accessed afterwards.
    * **Testing:** The `QuicServerInfoCanonicalSuffixMatchDoesntChangeOrder` test ensures this.

* **Interaction between In-Memory Cache and Loaded Data:**
    * **Purpose:** The canonical suffix matching should work correctly whether the QUIC server information is already in the in-memory cache or loaded from persistent storage (simulated by `OnQuicServerInfoMapLoadedForTesting`).
    * **Testing:** The `QuicServerInfoCanonicalSuffixMatchSetInfoMap` test covers this scenario.

**Relationship with JavaScript:**

While this C++ code doesn't directly execute JavaScript, it profoundly impacts the network behavior experienced by JavaScript running in a web browser.

* **QUIC Connection Optimization:** JavaScript initiating network requests (e.g., via `fetch` or `XMLHttpRequest`) can benefit from the QUIC information stored and retrieved by this code. If QUIC information is available for a server (either an exact match or via canonical suffix matching), the browser can attempt to establish a faster QUIC connection. This is transparent to the JavaScript code itself but improves performance.
    * **Example:** A JavaScript application hosted on `app.example.com` makes a request to `cdn.example.com` for static assets. If QUIC information is stored for `example.com`, the browser might use that information to establish a QUIC connection to `cdn.example.com`, even if it hasn't directly connected to `cdn.example.com` before.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `QuicServerInfoCanonicalSuffixMatch` test:

* **Hypothetical Input:**
    * `impl_` has stored QUIC server info for `foo.googlevideo.com:443` with data "foo_server_info".
    * `impl_` has stored QUIC server info for `baz.video.com:443` with data "baz_server_info".
* **Action:** `impl_.GetQuicServerInfo(quic::QuicServerId("bar.googlevideo.com", 443), PRIVACY_MODE_DISABLED, NetworkAnonymizationKey())` is called.
* **Output:** The test expects the function to return a pointer to a string containing "foo_server_info" because `bar.googlevideo.com` shares the canonical suffix `googlevideo.com` with `foo.googlevideo.com`, and there's no exact match for `bar.googlevideo.com`.

**User or Programming Common Usage Errors:**

* **Assuming exact host matches are always required:** Developers might incorrectly assume that QUIC information is only used for exact hostname matches. Understanding canonical suffix matching is important for predicting network behavior.
* **Not considering Network Isolation Keys:** If Network Isolation Keys are enabled, a developer might be surprised that QUIC information isn't being used for a subdomain if it was stored under a different Network Isolation Key.
* **Incorrectly predicting MRU behavior:**  If relying on canonical suffix matching, developers need to be aware that the *most recently used* entry for that suffix will be returned, which might not be the entry they initially expect.

**User Operations Leading to This Code (Debugging Scenario):**

Imagine a user reports that a particular website's videos load quickly, but videos from a subdomain of that website load slower. Here's how the code in this unit test relates to debugging this:

1. **User Browsing:** The user first visits `foo.googlevideo.com`, and the browser successfully establishes a QUIC connection. The `HttpServerProperties` class (specifically the code tested by `SetQuicServerInfo`) stores QUIC connection parameters for this host.
2. **User Navigates to Subdomain:** The user then navigates to `bar.googlevideo.com`.
3. **Potential QUIC Optimization:** The browser checks `HttpServerProperties` for QUIC information for `bar.googlevideo.com`. If no exact match is found, the code tested by `QuicServerInfoCanonicalSuffixMatch` kicks in. It searches for QUIC information associated with the canonical suffix `googlevideo.com`.
4. **Debugging Insight:** If the tests in this file pass, it confirms that the *logic* for canonical suffix matching is working correctly. If the videos on the subdomain are still slow, the issue might lie elsewhere:
    * **No QUIC info for the canonical suffix:** Perhaps the initial visit to `foo.googlevideo.com` didn't result in storing QUIC info for some reason.
    * **Network Isolation Key mismatch:** If the user is in a context where Network Isolation Keys are used, and the QUIC info was stored under a different key. The tests for `QuicServerInfoCanonicalSuffixMatchWithNetworkIsolationKey` would be relevant here.
    * **Server-side issues:** The subdomain server might not support QUIC or have other performance issues.

**Summary of Functionality (Part 5):**

In essence, this final part of the `http_server_properties_unittest.cc` file ensures the correct and efficient management of QUIC server information within Chromium's network stack. It specifically validates the logic for:

* **Leveraging QUIC information based on canonical domain suffixes when exact matches are not found.**
* **Maintaining privacy and security by respecting Network Isolation Keys during canonical suffix matching.**
* **Prioritizing the most recently used QUIC information when multiple entries exist for the same canonical suffix.**
* **Ensuring consistent behavior regardless of whether the information is in memory or loaded from storage.**

These tests are crucial for guaranteeing that Chromium can effectively utilize QUIC for a wider range of websites and subdomains, improving overall browsing performance.

Prompt: 
```
这是目录为net/http/http_server_properties_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
/ Https server should have nothing set for server network stats.
  EXPECT_EQ(nullptr, impl_.GetServerNetworkStats(foo_https_server,
                                                 NetworkAnonymizationKey()));

  impl_.Clear(base::OnceClosure());
  EXPECT_EQ(nullptr, impl_.GetServerNetworkStats(foo_http_server,
                                                 NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, impl_.GetServerNetworkStats(foo_https_server,
                                                 NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, ClearServerNetworkStats) {
  ServerNetworkStats stats;
  stats.srtt = base::Microseconds(10);
  stats.bandwidth_estimate = quic::QuicBandwidth::FromBitsPerSecond(100);
  url::SchemeHostPort foo_https_server("https", "foo", 443);
  impl_.SetServerNetworkStats(foo_https_server, NetworkAnonymizationKey(),
                              stats);

  impl_.ClearServerNetworkStats(foo_https_server, NetworkAnonymizationKey());
  EXPECT_EQ(nullptr, impl_.GetServerNetworkStats(foo_https_server,
                                                 NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, OnQuicServerInfoMapLoaded) {
  quic::QuicServerId google_quic_server_id("www.google.com", 443);
  HttpServerProperties::QuicServerInfoMapKey google_key(
      google_quic_server_id, PRIVACY_MODE_ENABLED, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);

  const int kMaxQuicServerEntries = 10;
  impl_.SetMaxServerConfigsStoredInProperties(kMaxQuicServerEntries);
  EXPECT_EQ(10u, impl_.quic_server_info_map().max_size());

  // Check empty map.
  std::unique_ptr<HttpServerProperties::QuicServerInfoMap>
      init_quic_server_info_map =
          std::make_unique<HttpServerProperties::QuicServerInfoMap>(
              kMaxQuicServerEntries);
  impl_.OnQuicServerInfoMapLoadedForTesting(
      std::move(init_quic_server_info_map));
  EXPECT_EQ(0u, impl_.quic_server_info_map().size());

  // Check by initializing with www.google.com:443.
  std::string google_server_info("google_quic_server_info");
  init_quic_server_info_map =
      std::make_unique<HttpServerProperties::QuicServerInfoMap>(
          kMaxQuicServerEntries);
  init_quic_server_info_map->Put(google_key, google_server_info);
  impl_.OnQuicServerInfoMapLoadedForTesting(
      std::move(init_quic_server_info_map));

  // Verify data for www.google.com:443.
  EXPECT_EQ(1u, impl_.quic_server_info_map().size());
  EXPECT_EQ(google_server_info, *impl_.GetQuicServerInfo(
                                    google_quic_server_id, PRIVACY_MODE_ENABLED,
                                    NetworkAnonymizationKey()));

  // Test recency order and overwriting of data.
  //
  // |docs_server| has a QuicServerInfo, which will be overwritten by
  // SetQuicServerInfoMap(), because |quic_server_info_map| has an
  // entry for |docs_server|.
  quic::QuicServerId docs_quic_server_id("docs.google.com", 443);
  HttpServerProperties::QuicServerInfoMapKey docs_key(
      docs_quic_server_id, PRIVACY_MODE_ENABLED, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);
  std::string docs_server_info("docs_quic_server_info");
  impl_.SetQuicServerInfo(docs_quic_server_id, PRIVACY_MODE_ENABLED,
                          NetworkAnonymizationKey(), docs_server_info);

  // Recency order will be |docs_server| and |google_server|.
  const HttpServerProperties::QuicServerInfoMap& map =
      impl_.quic_server_info_map();
  ASSERT_EQ(2u, map.size());
  auto map_it = map.begin();
  EXPECT_EQ(map_it->first, docs_key);
  EXPECT_EQ(docs_server_info, map_it->second);
  ++map_it;
  EXPECT_EQ(map_it->first, google_key);
  EXPECT_EQ(google_server_info, map_it->second);

  // Prepare |quic_server_info_map| to be loaded by
  // SetQuicServerInfoMap().
  std::unique_ptr<HttpServerProperties::QuicServerInfoMap>
      quic_server_info_map =
          std::make_unique<HttpServerProperties::QuicServerInfoMap>(
              kMaxQuicServerEntries);
  // Change the values for |docs_server|.
  std::string new_docs_server_info("new_docs_quic_server_info");
  quic_server_info_map->Put(docs_key, new_docs_server_info);
  // Add data for mail.google.com:443.
  quic::QuicServerId mail_quic_server_id("mail.google.com", 443);
  HttpServerProperties::QuicServerInfoMapKey mail_key(
      mail_quic_server_id, PRIVACY_MODE_ENABLED, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);
  std::string mail_server_info("mail_quic_server_info");
  quic_server_info_map->Put(mail_key, mail_server_info);
  impl_.OnQuicServerInfoMapLoadedForTesting(std::move(quic_server_info_map));

  // Recency order will be |docs_server|, |google_server| and |mail_server|.
  const HttpServerProperties::QuicServerInfoMap& memory_map =
      impl_.quic_server_info_map();
  ASSERT_EQ(3u, memory_map.size());
  auto memory_map_it = memory_map.begin();
  EXPECT_EQ(memory_map_it->first, docs_key);
  EXPECT_EQ(new_docs_server_info, memory_map_it->second);
  ++memory_map_it;
  EXPECT_EQ(memory_map_it->first, google_key);
  EXPECT_EQ(google_server_info, memory_map_it->second);
  ++memory_map_it;
  EXPECT_EQ(memory_map_it->first, mail_key);
  EXPECT_EQ(mail_server_info, memory_map_it->second);

  // Shrink the size of |quic_server_info_map| and verify the MRU order is
  // maintained.
  impl_.SetMaxServerConfigsStoredInProperties(2);
  EXPECT_EQ(2u, impl_.quic_server_info_map().max_size());

  const HttpServerProperties::QuicServerInfoMap& memory_map1 =
      impl_.quic_server_info_map();
  ASSERT_EQ(2u, memory_map1.size());
  auto memory_map1_it = memory_map1.begin();
  EXPECT_EQ(memory_map1_it->first, docs_key);
  EXPECT_EQ(new_docs_server_info, memory_map1_it->second);
  ++memory_map1_it;
  EXPECT_EQ(memory_map1_it->first, google_key);
  EXPECT_EQ(google_server_info, memory_map1_it->second);
  // |QuicServerInfo| for |mail_quic_server_id| shouldn't be there.
  EXPECT_EQ(nullptr,
            impl_.GetQuicServerInfo(mail_quic_server_id, PRIVACY_MODE_ENABLED,
                                    NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, SetQuicServerInfo) {
  quic::QuicServerId server1("foo", 80);
  quic::QuicServerId server2("foo", 80);

  std::string quic_server_info1("quic_server_info1");
  std::string quic_server_info2("quic_server_info2");
  std::string quic_server_info3("quic_server_info3");

  // Without network isolation keys enabled for HttpServerProperties, passing in
  // a NetworkAnonymizationKey should have no effect on behavior.
  impl_.SetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), quic_server_info1);
  EXPECT_EQ(quic_server_info1,
            *(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                      NetworkAnonymizationKey())));
  EXPECT_FALSE(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                       NetworkAnonymizationKey()));
  EXPECT_EQ(quic_server_info1,
            *(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                      network_anonymization_key1_)));
  EXPECT_FALSE(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                       network_anonymization_key1_));

  impl_.SetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                          network_anonymization_key1_, quic_server_info2);
  EXPECT_EQ(quic_server_info1,
            *(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                      NetworkAnonymizationKey())));
  EXPECT_EQ(quic_server_info2,
            *(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                      NetworkAnonymizationKey())));
  EXPECT_EQ(quic_server_info1,
            *(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                      network_anonymization_key1_)));
  EXPECT_EQ(quic_server_info2,
            *(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                      network_anonymization_key1_)));

  impl_.SetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                          network_anonymization_key1_, quic_server_info3);
  EXPECT_EQ(quic_server_info3,
            *(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                      NetworkAnonymizationKey())));
  EXPECT_EQ(quic_server_info2,
            *(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                      NetworkAnonymizationKey())));
  EXPECT_EQ(quic_server_info3,
            *(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                      network_anonymization_key1_)));
  EXPECT_EQ(quic_server_info2,
            *(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                      network_anonymization_key1_)));

  impl_.Clear(base::OnceClosure());
  EXPECT_FALSE(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                       NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                       NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                       network_anonymization_key1_));
  EXPECT_FALSE(impl_.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                       network_anonymization_key1_));

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  properties.SetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), quic_server_info1);
  EXPECT_EQ(quic_server_info1,
            *(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                           NetworkAnonymizationKey())));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key1_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                            network_anonymization_key1_));

  properties.SetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                               network_anonymization_key1_, quic_server_info2);
  EXPECT_EQ(quic_server_info1,
            *(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                           NetworkAnonymizationKey())));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_EQ(quic_server_info2,
            *(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                           network_anonymization_key1_)));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                            network_anonymization_key1_));

  properties.SetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                               network_anonymization_key1_, quic_server_info3);
  EXPECT_EQ(quic_server_info1,
            *(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                           NetworkAnonymizationKey())));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_EQ(quic_server_info2,
            *(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                           network_anonymization_key1_)));
  EXPECT_EQ(quic_server_info3,
            *(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                           network_anonymization_key1_)));

  properties.Clear(base::OnceClosure());
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key1_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_ENABLED,
                                            network_anonymization_key1_));
}

// Tests that GetQuicServerInfo() returns server info of a host
// with the same canonical suffix when there is no exact host match.
TEST_F(HttpServerPropertiesTest, QuicServerInfoCanonicalSuffixMatch) {
  // Set up HttpServerProperties.
  // Add a host with a canonical suffix.
  quic::QuicServerId foo_server_id("foo.googlevideo.com", 443);
  std::string foo_server_info("foo_server_info");
  impl_.SetQuicServerInfo(foo_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), foo_server_info);

  // Add a host that has a different canonical suffix.
  quic::QuicServerId baz_server_id("baz.video.com", 443);
  std::string baz_server_info("baz_server_info");
  impl_.SetQuicServerInfo(baz_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), baz_server_info);

  // Create SchemeHostPort with a host that has the initial canonical suffix.
  quic::QuicServerId bar_server_id("bar.googlevideo.com", 443);

  // Check the the server info associated with "foo" is returned for "bar".
  const std::string* bar_server_info = impl_.GetQuicServerInfo(
      bar_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey());
  ASSERT_TRUE(bar_server_info != nullptr);
  EXPECT_EQ(foo_server_info, *bar_server_info);
}

// Make sure that canonical suffices respect NetworkIsolationKeys when using
// QuicServerInfo methods.
TEST_F(HttpServerPropertiesTest,
       QuicServerInfoCanonicalSuffixMatchWithNetworkIsolationKey) {
  // Two servers with same canonical suffix.
  quic::QuicServerId server1("foo.googlevideo.com", 80);
  quic::QuicServerId server2("bar.googlevideo.com", 80);

  std::string server_info1("server_info1");
  std::string server_info2("server_info2");

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  // Set QuicServerInfo for one canononical suffix and
  // |network_anonymization_key1_|. It should be accessible via another
  // SchemeHostPort, but only when the NetworkIsolationKeys match.
  properties.SetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                               network_anonymization_key1_, server_info1);
  const std::string* fetched_server_info = properties.GetQuicServerInfo(
      server1, PRIVACY_MODE_DISABLED, network_anonymization_key1_);
  ASSERT_TRUE(fetched_server_info);
  EXPECT_EQ(server_info1, *fetched_server_info);
  fetched_server_info = properties.GetQuicServerInfo(
      server2, PRIVACY_MODE_DISABLED, network_anonymization_key1_);
  ASSERT_TRUE(fetched_server_info);
  EXPECT_EQ(server_info1, *fetched_server_info);
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key2_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key2_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_DISABLED,
                                            NetworkAnonymizationKey()));

  // Set different QuicServerInfo for the same canononical suffix and
  // |network_anonymization_key2_|. Both infos should be retriveable by using
  // the different NetworkIsolationKeys.
  properties.SetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                               network_anonymization_key2_, server_info2);
  fetched_server_info = properties.GetQuicServerInfo(
      server1, PRIVACY_MODE_DISABLED, network_anonymization_key1_);
  ASSERT_TRUE(fetched_server_info);
  EXPECT_EQ(server_info1, *fetched_server_info);
  fetched_server_info = properties.GetQuicServerInfo(
      server2, PRIVACY_MODE_DISABLED, network_anonymization_key1_);
  ASSERT_TRUE(fetched_server_info);
  EXPECT_EQ(server_info1, *fetched_server_info);
  fetched_server_info = properties.GetQuicServerInfo(
      server1, PRIVACY_MODE_DISABLED, network_anonymization_key2_);
  ASSERT_TRUE(fetched_server_info);
  EXPECT_EQ(server_info2, *fetched_server_info);
  fetched_server_info = properties.GetQuicServerInfo(
      server2, PRIVACY_MODE_DISABLED, network_anonymization_key2_);
  ASSERT_TRUE(fetched_server_info);
  EXPECT_EQ(server_info2, *fetched_server_info);
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_DISABLED,
                                            NetworkAnonymizationKey()));

  // Clearing should destroy all information.
  properties.Clear(base::OnceClosure());
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key1_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key1_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key2_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_DISABLED,
                                            network_anonymization_key2_));
  EXPECT_FALSE(properties.GetQuicServerInfo(server1, PRIVACY_MODE_DISABLED,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(properties.GetQuicServerInfo(server2, PRIVACY_MODE_DISABLED,
                                            NetworkAnonymizationKey()));
}

// Verifies that GetQuicServerInfo() returns the MRU entry if multiple records
// match a given canonical host.
TEST_F(HttpServerPropertiesTest,
       QuicServerInfoCanonicalSuffixMatchReturnsMruEntry) {
  // Set up HttpServerProperties by adding two hosts with the same canonical
  // suffixes.
  quic::QuicServerId h1_server_id("h1.googlevideo.com", 443);
  std::string h1_server_info("h1_server_info");
  impl_.SetQuicServerInfo(h1_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), h1_server_info);

  quic::QuicServerId h2_server_id("h2.googlevideo.com", 443);
  std::string h2_server_info("h2_server_info");
  impl_.SetQuicServerInfo(h2_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), h2_server_info);

  // Create quic::QuicServerId to use for the search.
  quic::QuicServerId foo_server_id("foo.googlevideo.com", 443);

  // Check that 'h2' info is returned since it is MRU.
  const std::string* server_info = impl_.GetQuicServerInfo(
      foo_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey());
  ASSERT_TRUE(server_info != nullptr);
  EXPECT_EQ(h2_server_info, *server_info);

  // Access 'h1' info, so it becomes MRU.
  impl_.GetQuicServerInfo(h1_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey());

  // Check that 'h1' info is returned since it is MRU now.
  server_info = impl_.GetQuicServerInfo(foo_server_id, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey());
  ASSERT_TRUE(server_info != nullptr);
  EXPECT_EQ(h1_server_info, *server_info);
}

// Verifies that |GetQuicServerInfo| doesn't change the MRU order of the server
// info map when a record is matched based on a canonical name.
TEST_F(HttpServerPropertiesTest,
       QuicServerInfoCanonicalSuffixMatchDoesntChangeOrder) {
  // Add a host with a matching canonical name.
  quic::QuicServerId h1_server_id("h1.googlevideo.com", 443);
  HttpServerProperties::QuicServerInfoMapKey h1_key(
      h1_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);
  std::string h1_server_info("h1_server_info");
  impl_.SetQuicServerInfo(h1_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), h1_server_info);

  // Add a host hosts with a non-matching canonical name.
  quic::QuicServerId h2_server_id("h2.video.com", 443);
  HttpServerProperties::QuicServerInfoMapKey h2_key(
      h2_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);
  std::string h2_server_info("h2_server_info");
  impl_.SetQuicServerInfo(h2_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), h2_server_info);

  // Check that "h2.video.com" is the MRU entry in the map.
  EXPECT_EQ(h2_key, impl_.quic_server_info_map().begin()->first);

  // Search for the entry that matches the canonical name
  // ("h1.googlevideo.com").
  quic::QuicServerId foo_server_id("foo.googlevideo.com", 443);
  const std::string* server_info = impl_.GetQuicServerInfo(
      foo_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey());
  ASSERT_TRUE(server_info != nullptr);

  // Check that the search (although successful) hasn't changed the MRU order of
  // the map.
  EXPECT_EQ(h2_key, impl_.quic_server_info_map().begin()->first);

  // Search for "h1.googlevideo.com" directly, so it becomes MRU
  impl_.GetQuicServerInfo(h1_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey());

  // Check that "h1.googlevideo.com" is the MRU entry now.
  EXPECT_EQ(h1_key, impl_.quic_server_info_map().begin()->first);
}

// Tests that the canonical host matching works for hosts stored in memory cache
// and the ones loaded from persistent storage, i.e. server info added
// using SetQuicServerInfo() and SetQuicServerInfoMap() is taken into
// cosideration when searching for server info for a host with the same
// canonical suffix.
TEST_F(HttpServerPropertiesTest, QuicServerInfoCanonicalSuffixMatchSetInfoMap) {
  // Add a host info using SetQuicServerInfo(). That will simulate an info
  // entry stored in memory cache.
  quic::QuicServerId h1_server_id("h1.googlevideo.com", 443);
  std::string h1_server_info("h1_server_info_memory_cache");
  impl_.SetQuicServerInfo(h1_server_id, PRIVACY_MODE_DISABLED,
                          NetworkAnonymizationKey(), h1_server_info);

  // Prepare a map with host info and add it using SetQuicServerInfoMap(). That
  // will simulate info records read from the persistence storage.
  quic::QuicServerId h2_server_id("h2.googlevideo.com", 443);
  HttpServerProperties::QuicServerInfoMapKey h2_key(
      h2_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);
  std::string h2_server_info("h2_server_info_from_disk");

  quic::QuicServerId h3_server_id("h3.ggpht.com", 443);
  HttpServerProperties::QuicServerInfoMapKey h3_key(
      h3_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);
  std::string h3_server_info("h3_server_info_from_disk");

  const int kMaxQuicServerEntries = 10;
  impl_.SetMaxServerConfigsStoredInProperties(kMaxQuicServerEntries);

  std::unique_ptr<HttpServerProperties::QuicServerInfoMap>
      quic_server_info_map =
          std::make_unique<HttpServerProperties::QuicServerInfoMap>(
              kMaxQuicServerEntries);
  quic_server_info_map->Put(h2_key, h2_server_info);
  quic_server_info_map->Put(h3_key, h3_server_info);
  impl_.OnQuicServerInfoMapLoadedForTesting(std::move(quic_server_info_map));

  // Check that the server info from the memory cache is returned since unique
  // entries from the memory cache are added after entries from the
  // persistence storage and, therefore, are most recently used.
  quic::QuicServerId foo_server_id("foo.googlevideo.com", 443);
  const std::string* server_info = impl_.GetQuicServerInfo(
      foo_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey());
  ASSERT_TRUE(server_info != nullptr);
  EXPECT_EQ(h1_server_info, *server_info);

  // Check that server info that was added using SetQuicServerInfoMap() can be
  // found.
  foo_server_id = quic::QuicServerId("foo.ggpht.com", 443);
  server_info = impl_.GetQuicServerInfo(foo_server_id, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey());
  ASSERT_TRUE(server_info != nullptr);
  EXPECT_EQ(h3_server_info, *server_info);
}

}  // namespace

}  // namespace net

"""


```