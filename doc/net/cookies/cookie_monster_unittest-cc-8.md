Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `cookie_monster_unittest.cc` file.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file name `cookie_monster_unittest.cc` immediately suggests this is a unit test file for the `CookieMonster` class. Unit tests verify the behavior of individual units of code.

2. **Analyze the code structure:** The code is organized into `TEST_F` blocks within a `CookieMonsterTest` and `FirstPartySetEnabledCookieMonsterTest` fixture. This confirms it's a set of tests.

3. **Examine individual test cases:**  Each `TEST_F` focuses on a specific aspect of `CookieMonster`'s functionality. Keywords like "Histogram," "Port," "Domain," "FirstPartySet," "Partition," and "Scheme" in the test names provide clues about the tested features.

4. **Relate tests to functionalities:**  Group the test cases based on the functionalities they are testing:
    * **Histogram recording:** Tests with "Histogram" in their name are clearly about verifying the correct emission of metrics.
    * **Cookie Attributes (Domain, Port):** Tests like `CookieDomainSetHistogram`, `CookiePortReadHistogram`, etc., focus on how `CookieMonster` handles specific cookie attributes.
    * **First-Party Sets:**  The `FirstPartySetEnabledCookieMonsterTest` suite specifically tests features related to First-Party Sets.
    * **Partitioned Cookies:** Tests involving "Partition" in the name deal with the functionality of partitioned cookies.
    * **Scheme Binding:** The `FilterCookiesWithOptionsExcludeShadowingDomains` test focuses on the behavior when scheme binding is enabled.

5. **Look for JavaScript interaction:**  The `CookieMonster` is a core component of how the browser manages cookies, which are heavily used by JavaScript. While this specific test file doesn't directly *execute* JavaScript, it tests functionalities that directly impact how JavaScript can set and access cookies. Think about the browser's cookie API (`document.cookie`).

6. **Identify logical reasoning and assumptions:** Some tests involve setting specific cookie configurations and then asserting the state (e.g., histogram counts, retrieved cookies). These tests rely on assumptions about how `CookieMonster` should behave given those inputs.

7. **Consider potential user/programming errors:**  Tests that set invalid cookies or trigger error conditions hint at potential pitfalls for developers using the cookie API. Think about common mistakes like incorrect domain attributes.

8. **Infer user actions leading to the code:** Since this is a unit test, the "user" action is more abstract. It's about a developer writing code that interacts with the network stack and relies on cookies. Consider scenarios like a web page setting a cookie, and how that translates into internal `CookieMonster` operations.

9. **Address the "part 9 of 10" instruction:**  Since this is the penultimate part, focus on summarizing the *overall* functionality covered by this specific set of tests. It's not about the entire `CookieMonster` class, but the aspects covered in this file.

10. **Structure the response:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the specific functionalities tested, providing examples from the code.
    * Explain the relationship to JavaScript.
    * Give examples of logical reasoning with input/output.
    * Highlight potential user errors.
    * Explain how a user might reach this code (from a debugging perspective).
    * Conclude with a summary of the functionalities covered in this part.

**(Self-Correction during the process):**  Initially, I might have focused too much on the technical details of each test case. However, the request emphasizes *functionality* and its relationship to users and JavaScript. Therefore, I need to abstract away some of the low-level test implementation and focus on the higher-level purpose and impact of the tested features. Also,  it's important to distinguish between what this *specific file* tests and the complete functionality of `CookieMonster`.
```cpp
rams;
  const char kHistogramName[] = "Cookie.DomainSet";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  // Set a host only cookie (non-Domain).
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName, false, 1);

  // Set a domain cookie.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(),
                        "A=B; Domain=" + https_www_foo_.host()));
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName, true, 1);

  // Invalid cookies don't count toward the histogram.
  EXPECT_FALSE(
      SetCookie(cm.get(), https_www_foo_.url(), "A=B; Domain=other.com"));
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName, false, 1);
}

TEST_F(CookieMonsterTest, CookiePortReadHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.Port.Read.RemoteHost";
  const char kHistogramNameLocal[] = "Cookie.Port.Read.Localhost";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com"), "A=B"));

  // May as well check that it didn't change the histogram...
  histograms.ExpectTotalCount(kHistogramName, 0);

  // Now read it from some different ports. This requires some knowledge of how
  // `ReducePortRangeForCookieHistogram` maps ports, but that's probably fine.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com")), "A=B");
  // https default is 443, so check that.
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(443), 1);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:82")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(82), 1);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:8080")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 3);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(8080), 1);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:1234")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 4);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(1234), 1);

  // Histogram should not increment if nothing is read.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.other.com")), "");
  histograms.ExpectTotalCount(kHistogramName, 4);

  // Make sure the correct histogram is chosen for localhost.
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://localhost"), "local=host"));

  histograms.ExpectTotalCount(kHistogramNameLocal, 0);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://localhost:82")), "local=host");
  histograms.ExpectTotalCount(kHistogramNameLocal, 1);
  histograms.ExpectBucketCount(kHistogramNameLocal,
                               ReducePortRangeForCookieHistogram(82), 1);
}

TEST_F(CookieMonsterTest, CookiePortSetHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.Port.Set.RemoteHost";
  const char kHistogramNameLocal[] = "Cookie.Port.Set.Localhost";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  // Set some cookies. This requires some knowledge of how
  // ReducePortRangeForCookieHistogram maps ports, but that's probably fine.

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(443), 1);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com:80"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(80), 1);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com:9000"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 3);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(9000), 1);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com:1234"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 4);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(1234), 1);

  // Histogram should not increment for invalid cookie.
  EXPECT_FALSE(SetCookie(cm.get(), GURL("https://www.foo.com"),
                         "A=B; Domain=malformedcookie.com"));
  histograms.ExpectTotalCount(kHistogramName, 4);

  // Nor should it increment for a read operation
  EXPECT_NE(GetCookies(cm.get(), GURL("https://www.foo.com")), "");
  histograms.ExpectTotalCount(kHistogramName, 4);

  // Make sure the correct histogram is chosen for localhost.
  histograms.ExpectTotalCount(kHistogramNameLocal, 0);

  EXPECT_TRUE(
      SetCookie(cm.get(), GURL("https://localhost:1234"), "local=host"));
  histograms.ExpectTotalCount(kHistogramNameLocal, 1);
  histograms.ExpectBucketCount(kHistogramNameLocal,
                               ReducePortRangeForCookieHistogram(1234), 1);
}

TEST_F(CookieMonsterTest, CookiePortReadDiffersFromSetHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.Port.ReadDiffersFromSet.RemoteHost";
  const char kHistogramNameLocal[] = "Cookie.Port.ReadDiffersFromSet.Localhost";
  const char kHistogramNameDomainSet[] =
      "Cookie.Port.ReadDiffersFromSet.DomainSet";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  // Set some cookies. One with a port, one without, and one with an invalid
  // port.
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com/withport"),
                        "A=B; Path=/withport"));  // Port 443

  auto unspecified_cookie = CanonicalCookie::CreateForTesting(
      GURL("https://www.foo.com/withoutport"), "C=D; Path=/withoutport",
      base::Time::Now());
  // Force to be unspecified.
  unspecified_cookie->SetSourcePort(url::PORT_UNSPECIFIED);
  EXPECT_TRUE(SetCanonicalCookieReturnAccessResult(
                  cm.get(), std::move(unspecified_cookie),
                  GURL("https://www.foo.com/withoutport"),
                  false /*can_modify_httponly*/)
                  .status.IsInclude());

  auto invalid_cookie = CanonicalCookie::CreateForTesting(
      GURL("https://www.foo.com/invalidport"), "E=F; Path=/invalidport",
      base::Time::Now());
  // Force to be invalid.
  invalid_cookie->SetSourcePort(99999);
  EXPECT_TRUE(SetCanonicalCookieReturnAccessResult(
                  cm.get(), std::move(invalid_cookie),
                  GURL("https://www.foo.com/invalidport"),
                  false /*can_modify_httponly*/)
                  .status.IsInclude());

  // Try same port.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com/withport")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName,
                               CookieMonster::CookieSentToSamePort::kYes, 1);

  // Try different port.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:8080/withport")),
            "A=B");
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName,
                               CookieMonster::CookieSentToSamePort::kNo, 1);

  // Try different port, but it's the default for a different scheme.
  EXPECT_EQ(GetCookies(cm.get(), GURL("http://www.foo.com/withport")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 3);
  histograms.ExpectBucketCount(
      kHistogramName, CookieMonster::CookieSentToSamePort::kNoButDefault, 1);

  // Now try it with an unspecified port cookie.
  EXPECT_EQ(GetCookies(cm.get(), GURL("http://www.foo.com/withoutport")),
            "C=D");
  histograms.ExpectTotalCount(kHistogramName, 4);
  histograms.ExpectBucketCount(
      kHistogramName,
      CookieMonster::CookieSentToSamePort::kSourcePortUnspecified, 1);

  // Finally try it with an invalid port cookie.
  EXPECT_EQ(GetCookies(cm.get(), GURL("http://www.foo.com/invalidport")),
            "E=F");
  histograms.ExpectTotalCount(kHistogramName, 5);
  histograms.ExpectBucketCount(
      kHistogramName, CookieMonster::CookieSentToSamePort::kInvalid, 1);

  // Make sure the correct histogram is chosen for localhost.
  histograms.ExpectTotalCount(kHistogramNameLocal, 0);
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://localhost"), "local=host"));

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://localhost")), "local=host");
  histograms.ExpectTotalCount(kHistogramNameLocal, 1);
  histograms.ExpectBucketCount(kHistogramNameLocal,
                               CookieMonster::CookieSentToSamePort::kYes, 1);

  // Make sure the Domain set version works.
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com/withDomain"),
                        "W=D; Domain=foo.com; Path=/withDomain"));

  histograms.ExpectTotalCount(kHistogramNameDomainSet, 0);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com/withDomain")),
            "W=D");
  histograms.ExpectTotalCount(kHistogramNameDomainSet, 1);
  histograms.ExpectBucketCount(kHistogramNameDomainSet,
                               CookieMonster::CookieSentToSamePort::kYes, 1);
  // The RemoteHost histogram should also increase with this cookie. Domain
  // cookies aren't special insofar as this metric is concerned.
  histograms.ExpectTotalCount(kHistogramName, 6);
  histograms.ExpectBucketCount(kHistogramName,
                               CookieMonster::CookieSentToSamePort::kYes, 2);
}

TEST_F(CookieMonsterTest, CookieSourceSchemeNameHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.CookieSourceSchemeName";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  struct TestCase {
    CookieSourceSchemeName enum_value;
    std::string scheme;
  };

  // Test the usual and a smattering of some other types including a kOther.
  // It doesn't matter if we add this to the scheme registry or not because we
  // don't actually need the whole url to parse, we just need GURL to pick up on
  // the scheme correctly (which it does). What the rest of the cookie code does
  // with the oddly formed GURL is out of scope of this test (i.e. we don't
  // care).
  const TestCase kTestCases[] = {
      {CookieSourceSchemeName::kHttpsScheme, url::kHttpsScheme},
      {CookieSourceSchemeName::kHttpScheme, url::kHttpScheme},
      {CookieSourceSchemeName::kWssScheme, url::kWssScheme},
      {CookieSourceSchemeName::kWsScheme, url::kWsScheme},
      {CookieSourceSchemeName::kChromeExtensionScheme, "chrome-extension"},
      {CookieSourceSchemeName::kFileScheme, url::kFileScheme},
      {CookieSourceSchemeName::kOther, "abcd1234"}};

  // Make sure all the schemes are considered cookieable.
  std::vector<std::string> schemes;
  for (auto test_case : kTestCases) {
    schemes.push_back(test_case.scheme);
  }
  ResultSavingCookieCallback<bool> cookie_scheme_callback;
  cm->SetCookieableSchemes(schemes, cookie_scheme_callback.MakeCallback());
  cookie_scheme_callback.WaitUntilDone();
  ASSERT_TRUE(cookie_scheme_callback.result());

  const char kUrl[] = "://www.foo.com";
  int count = 0;

  // Test all the cases.
  for (auto test_case : kTestCases) {
    histograms.ExpectBucketCount(kHistogramName, test_case.enum_value, 0);

    EXPECT_TRUE(SetCookie(cm.get(), GURL(test_case.scheme + kUrl), "A=B"));

    histograms.ExpectBucketCount(kHistogramName, test_case.enum_value, 1);
    histograms.ExpectTotalCount(kHistogramName, ++count);
  }

  // This metric is only for cookies that are actually set. Make sure the
  // histogram doesn't increment for cookies that fail to set.

  // Try to set an invalid cookie, for instance: a non-cookieable scheme will be
  // rejected.
  EXPECT_FALSE(SetCookie(cm.get(), GURL("invalidscheme://foo.com"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, count);
}

class FirstPartySetEnabledCookieMonsterTest : public CookieMonsterTest {
 public:
  FirstPartySetEnabledCookieMonsterTest()
      : cm_(nullptr /* store */, nullptr /* netlog */
        ) {
    std::unique_ptr<TestCookieAccessDelegate> access_delegate =
        std::make_unique<TestCookieAccessDelegate>();
    access_delegate_ = access_delegate.get();
    cm_.SetCookieAccessDelegate(std::move(access_delegate));
  }

  ~FirstPartySetEnabledCookieMonsterTest() override = default;

  CookieMonster* cm() { return &cm_; }

 protected:
  CookieMonster cm_;
  raw_ptr<TestCookieAccessDelegate> access_delegate_;
};

TEST_F(FirstPartySetEnabledCookieMonsterTest, RecordsPeriodicFPSSizes) {
  net::SchemefulSite owner1(GURL("https://owner1.test"));
  net::SchemefulSite owner2(GURL("https://owner2.test"));
  net::SchemefulSite member1(GURL("https://member1.test"));
  net::SchemefulSite member2(GURL("https://member2.test"));
  net::SchemefulSite member3(GURL("https://member3.test"));
  net::SchemefulSite member4(GURL("https://member4.test"));

  access_delegate_->SetFirstPartySets({
      {owner1,
       net::FirstPartySetEntry(owner1, net::SiteType::kPrimary, std::nullopt)},
      {member1, net::FirstPartySetEntry(owner1, net::SiteType::kAssociated, 0)},
      {member2, net::FirstPartySetEntry(owner1, net::SiteType::kAssociated, 1)},
      {owner2,
       net::FirstPartySetEntry(owner2, net::SiteType::kPrimary, std::nullopt)},
      {member3, net::FirstPartySetEntry(owner2, net::SiteType::kAssociated, 0)},
      {member4, net::FirstPartySetEntry(owner2, net::SiteType::kAssociated, 1)},
  });

  ASSERT_TRUE(SetCookie(cm(), GURL("https://owner1.test"), kValidCookieLine));
  ASSERT_TRUE(SetCookie(cm(), GURL("https://subdomain.member1.test"),
                        kValidCookieLine));
  ASSERT_TRUE(SetCookie(cm(), GURL("https://member2.test"), kValidCookieLine));
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://subdomain.owner2.test"), kValidCookieLine));
  ASSERT_TRUE(SetCookie(cm(), GURL("https://member3.test"), kValidCookieLine));
  // No cookie set for member4.test.
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://unrelated1.test"), kValidCookieLine));
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://unrelated2.test"), kValidCookieLine));
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://unrelated3.test"), kValidCookieLine));

  base::HistogramTester histogram_tester;
  EXPECT_TRUE(cm()->DoRecordPeriodicStatsForTesting());
  EXPECT_THAT(histogram_tester.GetAllSamples("Cookie.PerFirstPartySetCount"),
              testing::ElementsAre(  //
                                     // owner2.test & member3.test
                  base::Bucket(2 /* min */, 1 /* samples */),
                  // owner1.test, member1.test, & member2.test
                  base::Bucket(3 /* min */, 1 /* samples */)));
}

TEST_F(CookieMonsterTest, GetAllCookiesForURLNonce) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  CookieOptions options = CookieOptions::MakeAllInclusive();

  auto anonymous_iframe_key = CookiePartitionKey::FromURLForTesting(
      GURL("https://anonymous-iframe.test"),
      CookiePartitionKey::AncestorChainBit::kCrossSite,
      base::UnguessableToken::Create());

  // Define cookies from outside an anonymous iframe:
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), https_www_foo_.url(),
                                 "A=0; Secure; HttpOnly; Path=/;", options));
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), https_www_foo_.url(),
                                 "__Host-B=0; Secure; HttpOnly; Path=/;",
                                 options));

  // Define cookies from inside an anonymous iframe:
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_foo_.url(),
      "__Host-B=1; Secure; HttpOnly; Path=/; Partitioned", options,
      std::nullopt, std::nullopt, anonymous_iframe_key));
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_foo_.url(),
      "__Host-C=0; Secure; HttpOnly; Path=/; Partitioned", options,
      std::nullopt, std::nullopt, anonymous_iframe_key));

  // Check cookies from outside the anonymous iframe:
  EXPECT_THAT(GetAllCookiesForURL(cm.get(), https_www_foo_.url()),
              ElementsAre(MatchesCookieNameValue("A", "0"),
                          MatchesCookieNameValue("__Host-B", "0")));

  // Check cookies from inside the anonymous iframe:
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_foo_.url(),
                          CookiePartitionKeyCollection(anonymous_iframe_key)),
      ElementsAre(MatchesCookieNameValue("__Host-B", "1"),
                  MatchesCookieNameValue("__Host-C", "0")));
}

TEST_F(CookieMonsterTest, SiteHasCookieInOtherPartition) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  CookieOptions options = CookieOptions::MakeAllInclusive();

  GURL url("https://subdomain.example.com/");
  net::SchemefulSite site(url);
  auto partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  // At first it should return nullopt...
  EXPECT_FALSE(cm->SiteHasCookieInOtherPartition(site, partition_key));

  // ...until we load cookies for that domain.
  GetAllCookiesForURL(cm.get(), url,
                      CookiePartitionKeyCollection::ContainsAll());
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  // Set partitioned cookie.
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), url, "foo=bar; Secure; SameSite=None; Partitioned", options,
      std::nullopt, std::nullopt, partition_key));

  // Should return false with that cookie's partition key.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  auto other_partition_key = CookiePartitionKey::FromURLForTesting(
      GURL("https://nottoplevelsite.com"));

  // Should return true with another partition key.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, other_partition_key),
              testing::Optional(true));

  // Set a nonced partitioned cookie with a different partition key.
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), url, "foo=bar; Secure; SameSite=None; Partitioned", options,
      std::nullopt, std::nullopt,
      CookiePartitionKey::FromURLForTesting(
          GURL("https://nottoplevelsite.com"),
          CookiePartitionKey::AncestorChainBit::kCrossSite,
          base::UnguessableToken::Create())));

  // Should still return false with the original partition key.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  // Set unpartitioned cookie.
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), url,
                                 "bar=baz; Secure; SameSite=None;", options,
                                 std::nullopt, std::nullopt));

  // Should still return false with the original cookie's partition key. This
  // method only considers partitioned cookies.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  // Should return nullopt when the partition key is nullopt.
  EXPECT_FALSE(
      cm->SiteHasCookieInOtherPartition(site, /*partition_key=*/std::nullopt));
}

// Test that domain cookies which shadow origin cookies are excluded when scheme
// binding is enabled.
TEST_F(CookieMonsterTest, FilterCookiesWithOptionsExcludeShadowingDomains) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options = CookieOptions::MakeAllInclusive();
  options.set_return_excluded_cookies();

  auto CookieListsMatch = [](const CookieAccessResultList& actual,
                             const CookieList& expected) {
    if (actual.size() != expected.size()) {
      return false;
    }

    for (size_t i = 0; i < actual.size(); i++) {
      if (!actual[i].cookie.IsEquivalent(expected[i])) {
        return false;
      }
    }

    return true;
  };

  // We only exclude shadowing domain cookies when scheme binding is enabled.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      {net::features::kEnableSchemeBoundCookies},
      {net::features::kEnablePortBoundCookies});

  std::vector<CanonicalCookie*> cookie_ptrs;
  CookieAccessResultList included;
  CookieAccessResultList excluded;

  auto reset = [&cookie_ptrs, &included, &excluded]() {
    cookie_ptrs.clear();
    included.clear();
    excluded.clear();
  };

  auto origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=origin", creation_time, server_time);
  auto origin_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo2=origin", creation_time, server_time);

  auto domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Shadowing domain cookie after the origin cookie.
  cookie_ptrs = {origin_cookie1.get(), origin_cookie2.get(),
                 domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie1, *origin_cookie2}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1}));
  reset();

  // Shadowing domain cookie before the origin cookie.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie2, *origin_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1}));
  reset();

  auto domain_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo2=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Multiple different shadowing domain cookies.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), domain_cookie2.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie2, *origin_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1, *domain_cookie2}));
  reset();

  auto domain_cookie3 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo3=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Non-shadowing domain cookie should be included.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), domain_cookie2.get(),
                 domain_cookie3.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(
      included, {*origin_cookie2, *origin_cookie1, *domain_cookie3}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1, *domain_cookie2}));
  reset();

  auto sub_domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=subdomain; Domain=" + https_www_foo_.host(),
      creation_time, server_time);

  // If there are multiple domain cookies that shadow the same cookie, they
  // should all be excluded.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), sub_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie2, *origin_cookie1}));
  EXPECT_TRUE(
      CookieListsMatch(excluded, {*domain_cookie1, *sub_domain_cookie1}));
  reset();

  // Domain cookies may shadow each other.
  cookie_ptrs = {domain_cookie1.get(), sub_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(
### 提示词
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
rams;
  const char kHistogramName[] = "Cookie.DomainSet";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  // Set a host only cookie (non-Domain).
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName, false, 1);

  // Set a domain cookie.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(),
                        "A=B; Domain=" + https_www_foo_.host()));
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName, true, 1);

  // Invalid cookies don't count toward the histogram.
  EXPECT_FALSE(
      SetCookie(cm.get(), https_www_foo_.url(), "A=B; Domain=other.com"));
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName, false, 1);
}

TEST_F(CookieMonsterTest, CookiePortReadHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.Port.Read.RemoteHost";
  const char kHistogramNameLocal[] = "Cookie.Port.Read.Localhost";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com"), "A=B"));

  // May as well check that it didn't change the histogram...
  histograms.ExpectTotalCount(kHistogramName, 0);

  // Now read it from some different ports. This requires some knowledge of how
  // `ReducePortRangeForCookieHistogram` maps ports, but that's probably fine.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com")), "A=B");
  // https default is 443, so check that.
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(443), 1);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:82")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(82), 1);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:8080")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 3);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(8080), 1);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:1234")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 4);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(1234), 1);

  // Histogram should not increment if nothing is read.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.other.com")), "");
  histograms.ExpectTotalCount(kHistogramName, 4);

  // Make sure the correct histogram is chosen for localhost.
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://localhost"), "local=host"));

  histograms.ExpectTotalCount(kHistogramNameLocal, 0);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://localhost:82")), "local=host");
  histograms.ExpectTotalCount(kHistogramNameLocal, 1);
  histograms.ExpectBucketCount(kHistogramNameLocal,
                               ReducePortRangeForCookieHistogram(82), 1);
}

TEST_F(CookieMonsterTest, CookiePortSetHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.Port.Set.RemoteHost";
  const char kHistogramNameLocal[] = "Cookie.Port.Set.Localhost";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  // Set some cookies. This requires some knowledge of how
  // ReducePortRangeForCookieHistogram maps ports, but that's probably fine.

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(443), 1);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com:80"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(80), 1);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com:9000"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 3);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(9000), 1);

  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com:1234"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, 4);
  histograms.ExpectBucketCount(kHistogramName,
                               ReducePortRangeForCookieHistogram(1234), 1);

  // Histogram should not increment for invalid cookie.
  EXPECT_FALSE(SetCookie(cm.get(), GURL("https://www.foo.com"),
                         "A=B; Domain=malformedcookie.com"));
  histograms.ExpectTotalCount(kHistogramName, 4);

  // Nor should it increment for a read operation
  EXPECT_NE(GetCookies(cm.get(), GURL("https://www.foo.com")), "");
  histograms.ExpectTotalCount(kHistogramName, 4);

  // Make sure the correct histogram is chosen for localhost.
  histograms.ExpectTotalCount(kHistogramNameLocal, 0);

  EXPECT_TRUE(
      SetCookie(cm.get(), GURL("https://localhost:1234"), "local=host"));
  histograms.ExpectTotalCount(kHistogramNameLocal, 1);
  histograms.ExpectBucketCount(kHistogramNameLocal,
                               ReducePortRangeForCookieHistogram(1234), 1);
}

TEST_F(CookieMonsterTest, CookiePortReadDiffersFromSetHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.Port.ReadDiffersFromSet.RemoteHost";
  const char kHistogramNameLocal[] = "Cookie.Port.ReadDiffersFromSet.Localhost";
  const char kHistogramNameDomainSet[] =
      "Cookie.Port.ReadDiffersFromSet.DomainSet";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  // Set some cookies. One with a port, one without, and one with an invalid
  // port.
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com/withport"),
                        "A=B; Path=/withport"));  // Port 443

  auto unspecified_cookie = CanonicalCookie::CreateForTesting(
      GURL("https://www.foo.com/withoutport"), "C=D; Path=/withoutport",
      base::Time::Now());
  // Force to be unspecified.
  unspecified_cookie->SetSourcePort(url::PORT_UNSPECIFIED);
  EXPECT_TRUE(SetCanonicalCookieReturnAccessResult(
                  cm.get(), std::move(unspecified_cookie),
                  GURL("https://www.foo.com/withoutport"),
                  false /*can_modify_httponly*/)
                  .status.IsInclude());

  auto invalid_cookie = CanonicalCookie::CreateForTesting(
      GURL("https://www.foo.com/invalidport"), "E=F; Path=/invalidport",
      base::Time::Now());
  // Force to be invalid.
  invalid_cookie->SetSourcePort(99999);
  EXPECT_TRUE(SetCanonicalCookieReturnAccessResult(
                  cm.get(), std::move(invalid_cookie),
                  GURL("https://www.foo.com/invalidport"),
                  false /*can_modify_httponly*/)
                  .status.IsInclude());

  // Try same port.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com/withport")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 1);
  histograms.ExpectBucketCount(kHistogramName,
                               CookieMonster::CookieSentToSamePort::kYes, 1);

  // Try different port.
  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com:8080/withport")),
            "A=B");
  histograms.ExpectTotalCount(kHistogramName, 2);
  histograms.ExpectBucketCount(kHistogramName,
                               CookieMonster::CookieSentToSamePort::kNo, 1);

  // Try different port, but it's the default for a different scheme.
  EXPECT_EQ(GetCookies(cm.get(), GURL("http://www.foo.com/withport")), "A=B");
  histograms.ExpectTotalCount(kHistogramName, 3);
  histograms.ExpectBucketCount(
      kHistogramName, CookieMonster::CookieSentToSamePort::kNoButDefault, 1);

  // Now try it with an unspecified port cookie.
  EXPECT_EQ(GetCookies(cm.get(), GURL("http://www.foo.com/withoutport")),
            "C=D");
  histograms.ExpectTotalCount(kHistogramName, 4);
  histograms.ExpectBucketCount(
      kHistogramName,
      CookieMonster::CookieSentToSamePort::kSourcePortUnspecified, 1);

  // Finally try it with an invalid port cookie.
  EXPECT_EQ(GetCookies(cm.get(), GURL("http://www.foo.com/invalidport")),
            "E=F");
  histograms.ExpectTotalCount(kHistogramName, 5);
  histograms.ExpectBucketCount(
      kHistogramName, CookieMonster::CookieSentToSamePort::kInvalid, 1);

  // Make sure the correct histogram is chosen for localhost.
  histograms.ExpectTotalCount(kHistogramNameLocal, 0);
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://localhost"), "local=host"));

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://localhost")), "local=host");
  histograms.ExpectTotalCount(kHistogramNameLocal, 1);
  histograms.ExpectBucketCount(kHistogramNameLocal,
                               CookieMonster::CookieSentToSamePort::kYes, 1);

  // Make sure the Domain set version works.
  EXPECT_TRUE(SetCookie(cm.get(), GURL("https://www.foo.com/withDomain"),
                        "W=D; Domain=foo.com; Path=/withDomain"));

  histograms.ExpectTotalCount(kHistogramNameDomainSet, 0);

  EXPECT_EQ(GetCookies(cm.get(), GURL("https://www.foo.com/withDomain")),
            "W=D");
  histograms.ExpectTotalCount(kHistogramNameDomainSet, 1);
  histograms.ExpectBucketCount(kHistogramNameDomainSet,
                               CookieMonster::CookieSentToSamePort::kYes, 1);
  // The RemoteHost histogram should also increase with this cookie. Domain
  // cookies aren't special insofar as this metric is concerned.
  histograms.ExpectTotalCount(kHistogramName, 6);
  histograms.ExpectBucketCount(kHistogramName,
                               CookieMonster::CookieSentToSamePort::kYes, 2);
}

TEST_F(CookieMonsterTest, CookieSourceSchemeNameHistogram) {
  base::HistogramTester histograms;
  const char kHistogramName[] = "Cookie.CookieSourceSchemeName";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  histograms.ExpectTotalCount(kHistogramName, 0);

  struct TestCase {
    CookieSourceSchemeName enum_value;
    std::string scheme;
  };

  // Test the usual and a smattering of some other types including a kOther.
  // It doesn't matter if we add this to the scheme registry or not because we
  // don't actually need the whole url to parse, we just need GURL to pick up on
  // the scheme correctly (which it does). What the rest of the cookie code does
  // with the oddly formed GURL is out of scope of this test (i.e. we don't
  // care).
  const TestCase kTestCases[] = {
      {CookieSourceSchemeName::kHttpsScheme, url::kHttpsScheme},
      {CookieSourceSchemeName::kHttpScheme, url::kHttpScheme},
      {CookieSourceSchemeName::kWssScheme, url::kWssScheme},
      {CookieSourceSchemeName::kWsScheme, url::kWsScheme},
      {CookieSourceSchemeName::kChromeExtensionScheme, "chrome-extension"},
      {CookieSourceSchemeName::kFileScheme, url::kFileScheme},
      {CookieSourceSchemeName::kOther, "abcd1234"}};

  // Make sure all the schemes are considered cookieable.
  std::vector<std::string> schemes;
  for (auto test_case : kTestCases) {
    schemes.push_back(test_case.scheme);
  }
  ResultSavingCookieCallback<bool> cookie_scheme_callback;
  cm->SetCookieableSchemes(schemes, cookie_scheme_callback.MakeCallback());
  cookie_scheme_callback.WaitUntilDone();
  ASSERT_TRUE(cookie_scheme_callback.result());

  const char kUrl[] = "://www.foo.com";
  int count = 0;

  // Test all the cases.
  for (auto test_case : kTestCases) {
    histograms.ExpectBucketCount(kHistogramName, test_case.enum_value, 0);

    EXPECT_TRUE(SetCookie(cm.get(), GURL(test_case.scheme + kUrl), "A=B"));

    histograms.ExpectBucketCount(kHistogramName, test_case.enum_value, 1);
    histograms.ExpectTotalCount(kHistogramName, ++count);
  }

  // This metric is only for cookies that are actually set. Make sure the
  // histogram doesn't increment for cookies that fail to set.

  // Try to set an invalid cookie, for instance: a non-cookieable scheme will be
  // rejected.
  EXPECT_FALSE(SetCookie(cm.get(), GURL("invalidscheme://foo.com"), "A=B"));
  histograms.ExpectTotalCount(kHistogramName, count);
}

class FirstPartySetEnabledCookieMonsterTest : public CookieMonsterTest {
 public:
  FirstPartySetEnabledCookieMonsterTest()
      : cm_(nullptr /* store */, nullptr /* netlog */
        ) {
    std::unique_ptr<TestCookieAccessDelegate> access_delegate =
        std::make_unique<TestCookieAccessDelegate>();
    access_delegate_ = access_delegate.get();
    cm_.SetCookieAccessDelegate(std::move(access_delegate));
  }

  ~FirstPartySetEnabledCookieMonsterTest() override = default;

  CookieMonster* cm() { return &cm_; }

 protected:
  CookieMonster cm_;
  raw_ptr<TestCookieAccessDelegate> access_delegate_;
};

TEST_F(FirstPartySetEnabledCookieMonsterTest, RecordsPeriodicFPSSizes) {
  net::SchemefulSite owner1(GURL("https://owner1.test"));
  net::SchemefulSite owner2(GURL("https://owner2.test"));
  net::SchemefulSite member1(GURL("https://member1.test"));
  net::SchemefulSite member2(GURL("https://member2.test"));
  net::SchemefulSite member3(GURL("https://member3.test"));
  net::SchemefulSite member4(GURL("https://member4.test"));

  access_delegate_->SetFirstPartySets({
      {owner1,
       net::FirstPartySetEntry(owner1, net::SiteType::kPrimary, std::nullopt)},
      {member1, net::FirstPartySetEntry(owner1, net::SiteType::kAssociated, 0)},
      {member2, net::FirstPartySetEntry(owner1, net::SiteType::kAssociated, 1)},
      {owner2,
       net::FirstPartySetEntry(owner2, net::SiteType::kPrimary, std::nullopt)},
      {member3, net::FirstPartySetEntry(owner2, net::SiteType::kAssociated, 0)},
      {member4, net::FirstPartySetEntry(owner2, net::SiteType::kAssociated, 1)},
  });

  ASSERT_TRUE(SetCookie(cm(), GURL("https://owner1.test"), kValidCookieLine));
  ASSERT_TRUE(SetCookie(cm(), GURL("https://subdomain.member1.test"),
                        kValidCookieLine));
  ASSERT_TRUE(SetCookie(cm(), GURL("https://member2.test"), kValidCookieLine));
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://subdomain.owner2.test"), kValidCookieLine));
  ASSERT_TRUE(SetCookie(cm(), GURL("https://member3.test"), kValidCookieLine));
  // No cookie set for member4.test.
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://unrelated1.test"), kValidCookieLine));
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://unrelated2.test"), kValidCookieLine));
  ASSERT_TRUE(
      SetCookie(cm(), GURL("https://unrelated3.test"), kValidCookieLine));

  base::HistogramTester histogram_tester;
  EXPECT_TRUE(cm()->DoRecordPeriodicStatsForTesting());
  EXPECT_THAT(histogram_tester.GetAllSamples("Cookie.PerFirstPartySetCount"),
              testing::ElementsAre(  //
                                     // owner2.test & member3.test
                  base::Bucket(2 /* min */, 1 /* samples */),
                  // owner1.test, member1.test, & member2.test
                  base::Bucket(3 /* min */, 1 /* samples */)));
}

TEST_F(CookieMonsterTest, GetAllCookiesForURLNonce) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  CookieOptions options = CookieOptions::MakeAllInclusive();

  auto anonymous_iframe_key = CookiePartitionKey::FromURLForTesting(
      GURL("https://anonymous-iframe.test"),
      CookiePartitionKey::AncestorChainBit::kCrossSite,
      base::UnguessableToken::Create());

  // Define cookies from outside an anonymous iframe:
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), https_www_foo_.url(),
                                 "A=0; Secure; HttpOnly; Path=/;", options));
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), https_www_foo_.url(),
                                 "__Host-B=0; Secure; HttpOnly; Path=/;",
                                 options));

  // Define cookies from inside an anonymous iframe:
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_foo_.url(),
      "__Host-B=1; Secure; HttpOnly; Path=/; Partitioned", options,
      std::nullopt, std::nullopt, anonymous_iframe_key));
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_foo_.url(),
      "__Host-C=0; Secure; HttpOnly; Path=/; Partitioned", options,
      std::nullopt, std::nullopt, anonymous_iframe_key));

  // Check cookies from outside the anonymous iframe:
  EXPECT_THAT(GetAllCookiesForURL(cm.get(), https_www_foo_.url()),
              ElementsAre(MatchesCookieNameValue("A", "0"),
                          MatchesCookieNameValue("__Host-B", "0")));

  // Check cookies from inside the anonymous iframe:
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_foo_.url(),
                          CookiePartitionKeyCollection(anonymous_iframe_key)),
      ElementsAre(MatchesCookieNameValue("__Host-B", "1"),
                  MatchesCookieNameValue("__Host-C", "0")));
}

TEST_F(CookieMonsterTest, SiteHasCookieInOtherPartition) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  CookieOptions options = CookieOptions::MakeAllInclusive();

  GURL url("https://subdomain.example.com/");
  net::SchemefulSite site(url);
  auto partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  // At first it should return nullopt...
  EXPECT_FALSE(cm->SiteHasCookieInOtherPartition(site, partition_key));

  // ...until we load cookies for that domain.
  GetAllCookiesForURL(cm.get(), url,
                      CookiePartitionKeyCollection::ContainsAll());
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  // Set partitioned cookie.
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), url, "foo=bar; Secure; SameSite=None; Partitioned", options,
      std::nullopt, std::nullopt, partition_key));

  // Should return false with that cookie's partition key.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  auto other_partition_key = CookiePartitionKey::FromURLForTesting(
      GURL("https://nottoplevelsite.com"));

  // Should return true with another partition key.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, other_partition_key),
              testing::Optional(true));

  // Set a nonced partitioned cookie with a different partition key.
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), url, "foo=bar; Secure; SameSite=None; Partitioned", options,
      std::nullopt, std::nullopt,
      CookiePartitionKey::FromURLForTesting(
          GURL("https://nottoplevelsite.com"),
          CookiePartitionKey::AncestorChainBit::kCrossSite,
          base::UnguessableToken::Create())));

  // Should still return false with the original partition key.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  // Set unpartitioned cookie.
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), url,
                                 "bar=baz; Secure; SameSite=None;", options,
                                 std::nullopt, std::nullopt));

  // Should still return false with the original cookie's partition key. This
  // method only considers partitioned cookies.
  EXPECT_THAT(cm->SiteHasCookieInOtherPartition(site, partition_key),
              testing::Optional(false));

  // Should return nullopt when the partition key is nullopt.
  EXPECT_FALSE(
      cm->SiteHasCookieInOtherPartition(site, /*partition_key=*/std::nullopt));
}

// Test that domain cookies which shadow origin cookies are excluded when scheme
// binding is enabled.
TEST_F(CookieMonsterTest, FilterCookiesWithOptionsExcludeShadowingDomains) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options = CookieOptions::MakeAllInclusive();
  options.set_return_excluded_cookies();

  auto CookieListsMatch = [](const CookieAccessResultList& actual,
                             const CookieList& expected) {
    if (actual.size() != expected.size()) {
      return false;
    }

    for (size_t i = 0; i < actual.size(); i++) {
      if (!actual[i].cookie.IsEquivalent(expected[i])) {
        return false;
      }
    }

    return true;
  };

  // We only exclude shadowing domain cookies when scheme binding is enabled.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      {net::features::kEnableSchemeBoundCookies},
      {net::features::kEnablePortBoundCookies});

  std::vector<CanonicalCookie*> cookie_ptrs;
  CookieAccessResultList included;
  CookieAccessResultList excluded;

  auto reset = [&cookie_ptrs, &included, &excluded]() {
    cookie_ptrs.clear();
    included.clear();
    excluded.clear();
  };

  auto origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=origin", creation_time, server_time);
  auto origin_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo2=origin", creation_time, server_time);

  auto domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Shadowing domain cookie after the origin cookie.
  cookie_ptrs = {origin_cookie1.get(), origin_cookie2.get(),
                 domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie1, *origin_cookie2}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1}));
  reset();

  // Shadowing domain cookie before the origin cookie.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie2, *origin_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1}));
  reset();

  auto domain_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo2=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Multiple different shadowing domain cookies.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), domain_cookie2.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie2, *origin_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1, *domain_cookie2}));
  reset();

  auto domain_cookie3 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo3=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Non-shadowing domain cookie should be included.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), domain_cookie2.get(),
                 domain_cookie3.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(
      included, {*origin_cookie2, *origin_cookie1, *domain_cookie3}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*domain_cookie1, *domain_cookie2}));
  reset();

  auto sub_domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=subdomain; Domain=" + https_www_foo_.host(),
      creation_time, server_time);

  // If there are multiple domain cookies that shadow the same cookie, they
  // should all be excluded.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), sub_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie2, *origin_cookie1}));
  EXPECT_TRUE(
      CookieListsMatch(excluded, {*domain_cookie1, *sub_domain_cookie1}));
  reset();

  // Domain cookies may shadow each other.
  cookie_ptrs = {domain_cookie1.get(), sub_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(
      CookieListsMatch(included, {*domain_cookie1, *sub_domain_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {}));
  reset();

  auto path_origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=pathorigin; Path=/bar", creation_time,
      server_time);

  // Origin cookies on different paths may not be shadowed, even if the
  // origin cookie wouldn't be included on this request.
  cookie_ptrs = {path_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {}));
  EXPECT_TRUE(
      CookieListsMatch(excluded, {*path_origin_cookie1, *domain_cookie1}));
  reset();

  auto insecure_origin_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), "foo1=insecureorigin", creation_time, server_time);
  EXPECT_EQ(insecure_origin_cookie1->SourceScheme(),
            CookieSourceScheme::kNonSecure);

  // Origin cookies that are excluded due to scheme binding don't affect domain
  // cookies.
  cookie_ptrs = {insecure_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*domain_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*insecure_origin_cookie1}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH}));
  reset();

  auto insecure_domain_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(),
      "foo1=insecuredomain; Domain=" + http_www_foo_.domain(), creation_time,
      server_time);

  // Domain cookies that are excluded due to scheme binding shouldn't also be
  // exclude because of shadowing.
  cookie_ptrs = {origin_cookie1.get(), insecure_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*origin_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*insecure_domain_cookie1}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH}));
  reset();

  // If both domain and origin cookie are excluded due to scheme binding then
  // domain cookie shouldn't get shadowing exclusion.
  cookie_ptrs = {insecure_origin_cookie1.get(), insecure_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {}));
  EXPECT_TRUE(CookieListsMatch(
      excluded, {*insecure_origin_cookie1, *insecure_domain_cookie1}));
  EXPECT_TRUE(
      excluded[1].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH}));
  reset();

  cm->SetCookieAccessDelegate(std::make_unique<TestCookieAccessDelegate>());

  CookieURLHelper http_www_trustworthy =
      CookieURLHelper("http://www.trustworthysitefortestdelegate.example");
  CookieURLHelper https_www_trustworthy =
      CookieURLHelper("https://www.trustworthysitefortestdelegate.example");

  auto trust_origin_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_trustworthy.url(), "foo1=trustorigin", creation_time,
      server_time);

  auto secure_trust_domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_trustworthy.url(),
      "foo1=securetrustdomain; Domain=" + https_www_trustworthy.domain(),
      creation_time, server_time);
  auto secure_trust_domain_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_trustworthy.url(),
      "foo2=securetrustdomain; Domain=" + https_www_trustworthy.domain(),
      creation_time, server_time);

  // Securely set domain cookies are excluded when shadowing trustworthy-ly set
  // origin cookies.
  cookie_ptrs = {trust_origin_cookie1.get(), secure_trust_domain_cookie1.get(),
                 secure_trust_domain_cookie2.get()};
  cm->FilterCookiesWithOptions(http_www_trustworthy.url(), options,
                               &cookie_ptrs, &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(
      included, {*trust_origin_cookie1, *secure_trust_domain_cookie2}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*secure_trust_domain_cookie1}));
  reset();

  auto trust_domain_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_trustworthy.url(),
      "foo1=trustdomain; Domain=" + http_www_trustworthy.domain(),
      creation_time, server_time);
  auto trust_domain_cookie2 = CanonicalCookie::CreateForTesting(
      http_www_trustworthy.url(),
      "foo2=trustdomain; Domain=" + http_www_trustworthy.domain(),
      creation_time, server_time);
  auto secure_trust_origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_trustworthy.url(), "foo1=securetrustorigin", creation_time,
      server_time);

  // Trustworthy-ly set domain cookies are excluded when shadowing securely set
  // origin cookies.
  cookie_ptrs = {secure_trust_origin_cookie1.get(), trust_domain_cookie1.get(),
                 trust_domain_cookie2.get()};
  cm->FilterCookiesWithOptions(http_www_trustworthy.url(), options,
                               &cookie_ptrs, &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(
      included, {*secure_trust_origin_cookie1, *trust_domain_cookie2}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*trust_domain_cookie1}));
  reset();

  auto port_origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=differentportorigin", creation_time,
      server_time);
  port_origin_cookie1->SetSourcePort(123);

  // Origin cookies that have warnings due to port binding don't affect domain
  // cookies.
  cookie_ptrs = {port_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(
      CookieListsMatch(included, {*port_origin_cookie1, *domain_cookie1}));
  EXPECT_TRUE(included[0].access_result.status.HasWarningReason(
      CookieInclusionStatus::WARN_PORT_MISMATCH));
  reset();

  auto port_insecure_origin_cookie1 =
      std::make_unique<CanonicalCookie>(*insecure_origin_cookie1);
  port_insecure_origin_cookie1->SetSourcePort(123);

  // Origin cookies that have excluded due to scheme binding and have a port
  // binding warning don't affect domain cookies.
  cookie_ptrs = {port_insecure_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*domain_cookie1}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyWarningReasonsForTesting(
          {CookieInclusionStatus::WARN_PORT_MISMATCH}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH}));
  reset();

  // Enable port binding to test with port exclusions.
  scoped_feature_list.Reset();
  scoped_feature_list.InitWithFeatures(
      {net::features::kEnableSchemeBoundCookies,
       net::features::kEnablePortBoundCookies},
      {});

  //
```