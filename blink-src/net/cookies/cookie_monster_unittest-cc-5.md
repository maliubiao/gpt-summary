Response:
My thinking process to answer the request about the `cookie_monster_unittest.cc` file goes like this:

1. **Understand the Core Request:** The user wants to know the *functionality* of this specific Chromium test file. They also ask about its relationship to JavaScript, want examples of logical reasoning (input/output), common usage errors, debugging tips, and a summary of the provided code snippet (part 6 of 10).

2. **Initial Assessment of the File Name:** The name `cookie_monster_unittest.cc` immediately suggests this file contains *unit tests* for a component named `CookieMonster`. This is a strong starting point. Unit tests verify the individual components of a larger system.

3. **Analyze the Code Snippet (Part 6):**  I'll read through the provided code, paying close attention to:
    * **Test Fixtures (`TEST_F`)**:  These indicate individual test cases within the `CookieMonsterTest` class.
    * **Assertions (`ASSERT_TRUE`, `EXPECT_...`)**: These are the core of the tests, checking if certain conditions are met.
    * **Histogram Testers (`base::HistogramTester`)**: This suggests the tests are verifying that the `CookieMonster` is recording the correct data for performance monitoring and analysis (histograms).
    * **Cookie Creation and Setting**: The code uses functions like `CanonicalCookie::CreateUnsafeCookieForTesting` and `SetCanonicalCookie`. This confirms the tests are about cookie management.
    * **Cookie Properties**: The tests manipulate properties like `SameSite`, `Secure`, `HttpOnly`, and `Partitioned`.
    * **Cookie Partition Keys**:  The code explicitly tests partitioned cookies, indicating a focus on the Partitioned Cookies proposal.
    * **Cookie Size**: The tests use `std::string(cookie_value_size_kb * 1024, '0')` to create cookies of specific sizes, suggesting the tests are verifying size-related metrics.
    * **Histograms Names**:  Names like "Cookie.CookieJarSize", "Cookie.AvgCookieJarSizePerKey2", "Cookie.PartitionedCookieCount", etc., clearly indicate what metrics are being tested.

4. **Identify Key Functionality Based on Code Analysis:**  From the code, I can identify these main functionalities being tested:
    * **Cookie Jar Size Tracking:**  Verifying histograms related to the total size of the cookie jar and the size per domain/key.
    * **Partitioned Cookie Metrics:** Testing histograms for the count and size of partitioned cookies.
    * **SameSite=None Cookie Tracking:** Checking histograms specifically for `SameSite=None` cookies.
    * **Secure Cookie Handling on Localhost:**  Testing the specific behavior of secure cookies on localhost domains.
    * **Cookie Overwriting Logic:**  Verifying how the `CookieMonster` handles attempts to overwrite existing cookies, considering `Secure` and `HttpOnly` attributes, especially in the context of partitioned cookies.
    * **Origin-Bound Cookie Logic (Implicit):** The `CookieMonsterTest_MaybeDeleteEquivalentCookieAndUpdateStatus` fixture and the tests within it point towards testing the behavior of cookies when considering the scheme and port of the origin (this becomes clearer by analyzing the test names and the setup within that fixture).

5. **Address Specific Questions:**

    * **Relationship to JavaScript:**  While the C++ code itself doesn't *directly* interact with JavaScript, the *functionality it tests* is critical for how websites (and therefore JavaScript running on those websites) can set and access cookies. I can give examples of JavaScript `document.cookie` usage and how the tested logic in `CookieMonster` would affect it.

    * **Logical Reasoning (Input/Output):** I can take a specific test case, like the `CookieJarSizeHistograms` test, and describe the sequence of setting cookies and how the histogram values are expected to change. This demonstrates the cause-and-effect being tested.

    * **User/Programming Errors:**  I can think of common mistakes developers might make when setting cookies, such as forgetting the `Secure` attribute for `SameSite=None`, trying to overwrite secure cookies from insecure origins, or not understanding the implications of partitioned cookies. These can be linked to the test cases.

    * **User Operation to Reach Here (Debugging):** I'll outline the steps a user might take that would lead to the browser's cookie handling logic being invoked, which the unit tests are designed to verify. This could involve visiting websites, interacting with web forms, etc.

    * **Summary of Part 6:** I'll specifically focus on summarizing the tests within the provided code snippet, highlighting the main areas of functionality it covers.

6. **Structure the Answer:** I'll organize the information logically, using headings and bullet points to make it easy to read and understand. I'll address each part of the user's request explicitly.

7. **Refine and Elaborate:**  I'll review my answer to ensure accuracy, clarity, and completeness. I'll add details and explanations where necessary to make the concepts more accessible. For example, when discussing partitioned cookies, I'll briefly explain what they are and why they are important.

By following this structured process, I can effectively analyze the code and provide a comprehensive and helpful answer to the user's request. The key is to break down the problem, understand the purpose of the code, and then connect it back to the user's specific questions.
Based on the provided code snippet from `net/cookies/cookie_monster_unittest.cc`, here's a breakdown of its functionality, focusing on the tests included in this section:

**Core Functionality Being Tested:**

This part of the `CookieMonsterTest` suite primarily focuses on testing the **correctness of histogram recording** related to cookie storage and characteristics within the `CookieMonster`. It verifies that the `CookieMonster` accurately tracks and reports metrics about:

* **Total Cookie Jar Size:**  Measures the total size of all cookies stored, specifically for non-partitioned cookies.
* **Average Cookie Jar Size Per Key:** Calculates the average size of cookies associated with a specific domain (key), again for non-partitioned cookies.
* **Maximum Cookie Jar Size Per Key:** Tracks the largest size of cookies associated with a single domain.
* **Partitioned Cookie Counts:**  Counts the number of partitioned cookies, further broken down into nonced and unnonced partitioned cookies.
* **Partitioned Cookie Jar Size:** Measures the total storage size of partitioned cookies, also categorized by nonced and unnonced status.
* **Partitioned Cookie Size Per Partition:** Tracks the size of cookies within individual partitions.
* **Maximum Number of SameSite=None Cookies Per Key:**  Records the maximum number of cookies with the `SameSite=None` attribute stored for a single domain.
* **Secure Cookie Handling on Localhost:** Tests the specific behavior of setting and retrieving secure cookies on localhost domains (both HTTP and HTTPS).
* **Cookie Overwriting Logic (Including Secure and HttpOnly Attributes):**  Verifies that the `CookieMonster` correctly handles attempts to overwrite existing cookies, paying attention to the `Secure` and `HttpOnly` attributes. This includes scenarios where a non-secure cookie tries to overwrite a secure one.
* **Cookie Overwriting Logic with Partitioned Cookies:** Similar to the above, but specifically tests overwriting scenarios involving partitioned cookies.
* **Origin-Bound Cookie Logic (Scheme and Port Binding):** Tests how cookies are treated as equivalent based on the origin's scheme (HTTP/HTTPS) and port, depending on feature flags.

**Relationship to JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it tests the underlying mechanism that JavaScript uses to interact with cookies. Here's how it relates:

* **`document.cookie` API:** JavaScript running in a web page uses the `document.cookie` API to read, set, and modify cookies. The `CookieMonster` is the Chromium component responsible for managing these cookies behind the scenes. The tests here ensure that when JavaScript sets a cookie with specific attributes (like `Secure`, `HttpOnly`, `SameSite`, or `Partitioned`), the `CookieMonster` stores and handles it correctly.
* **Example:**
    * **JavaScript setting a cookie:** `document.cookie = "myCookie=value; Secure; SameSite=None";`
    * **How the test relates:** The `MaxSameSiteNoneCookiesPerKey` test directly verifies that when such a cookie is set (simulated in the C++ test), the `CookieMonster` correctly increments the counter for `SameSite=None` cookies.
    * **JavaScript reading a cookie:**  JavaScript accessing `document.cookie` will rely on the `CookieMonster` to provide the correct set of cookies based on the current page's URL and the cookie attributes. The secure cookie handling tests on localhost ensure that the `CookieMonster` provides the cookie even when accessed from an insecure localhost context, albeit with a warning.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take the `CookieJarSizeHistograms` test case as an example:

* **Hypothetical Input:**
    1. Initially, the `CookieMonster` is empty.
    2. A cookie named "a" with a value size of 2KB is set for the domain "a.url" (non-partitioned).
    3. A partitioned cookie named "b" with a value size of 3KB is set for the same domain.
    4. A non-partitioned cookie named "c" with a value size of 4KB is set for the domain "c.url".

* **Logical Output (as verified by the assertions):**
    * **After setting cookie "a":**
        * `Cookie.CookieJarSize` histogram will have a sample of 2 (representing 2KB).
        * `Cookie.AvgCookieJarSizePerKey2` will have a sample of 2049 (representing 2 * 1024 + 1 for overhead).
        * `Cookie.MaxCookieJarSizePerKey` will have a sample of 2.
    * **After setting partitioned cookie "b":**
        * The non-partitioned histograms (`Cookie.CookieJarSize`, `Cookie.AvgCookieJarSizePerKey2`, `Cookie.MaxCookieJarSizePerKey`) **will not change** because partitioned cookies are tracked separately.
    * **After setting cookie "c":**
        * `Cookie.CookieJarSize` will have a sample of 6 (2KB from "a" + 4KB from "c").
        * `Cookie.AvgCookieJarSizePerKey2` will have a sample of 3073 (approximately (2049 + (4 * 1024 + 1))/2 ).
        * `Cookie.MaxCookieJarSizePerKey` will have a sample of 4 (from cookie "c").

**User or Programming Common Usage Errors (and how the tests relate):**

* **Forgetting the `Secure` attribute for `SameSite=None` cookies:**  Browsers will often reject `SameSite=None` cookies set on insecure origins (HTTP) if the `Secure` attribute is missing. The `MaxSameSiteNoneCookiesPerKey` test implicitly checks the behavior around `SameSite=None` cookies and their impact on metrics.
* **Trying to set a non-secure cookie to overwrite a secure cookie:** The `MaybeDeleteEquivalentCookieAndUpdateStatus` tests specifically verify that attempting to set a non-secure cookie from an insecure origin when a secure cookie with the same name exists will be blocked. This prevents accidental downgrading of security.
* **Misunderstanding cookie partitioning:** Developers might not realize that partitioned cookies are isolated to a specific top-level site and won't be accessible in other contexts. The `PartitionedCookieHistograms` test ensures that the counting and sizing of these isolated cookies are tracked correctly.
* **Incorrectly assuming localhost behaves exactly like a regular domain:** The `SecureCookieLocalhost` test highlights the special handling of secure cookies on localhost, allowing them even over HTTP for development convenience. Developers might make incorrect assumptions about secure cookie behavior based on non-localhost environments.
* **Not understanding HttpOnly cookies:**  Trying to overwrite an `HttpOnly` cookie from client-side JavaScript or a non-HTTP context will fail. The `MaybeDeleteEquivalentCookieAndUpdateStatus` tests check this behavior.

**User Operation to Reach This Code (Debugging Clues):**

As a developer debugging cookie-related issues, you might reach this test file when:

1. **Investigating bug reports related to cookie storage limits or unexpected cookie behavior.**  If users report that cookies are being dropped or not behaving as expected, you might look at the core cookie management logic and its unit tests.
2. **Developing new features related to cookie handling:**  When adding new functionalities like cookie partitioning or enhanced security measures, developers write unit tests like these to ensure the new code works correctly and doesn't introduce regressions.
3. **Performance analysis of cookie operations:** The histogram tests indicate an interest in tracking the performance and resource usage of the cookie system. If performance issues related to cookies are suspected, these metrics and the tests around them become relevant.
4. **Reviewing code changes related to cookie storage:** When code in `CookieMonster` or related components is modified, these tests are run to verify that the changes haven't broken existing functionality.
5. **Understanding the interaction between JavaScript and native cookie handling:**  If you're working on features that bridge the gap between the JavaScript `document.cookie` API and the underlying C++ implementation, you might consult these tests to understand the expected behavior.

**Summary of Part 6's Functionality:**

This specific section of `cookie_monster_unittest.cc` primarily focuses on **verifying the accuracy of internal accounting and metric reporting within the `CookieMonster`**. It uses histogram testers to assert that various cookie characteristics (size, partitioning, `SameSite` attribute) are correctly tracked and recorded. Additionally, it tests specific security-related aspects like the handling of secure cookies on localhost and the prevention of insecure overwrites of secure cookies, including scenarios with partitioned cookies and considerations for origin binding (scheme and port).

Prompt: 
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共10部分，请归纳一下它的功能

"""
terTest, CookieJarSizeHistograms) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  {
    base::HistogramTester histogram_tester;
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample("Cookie.CookieJarSize",
                                        /*sample=*/0,
                                        /*expected_bucket_count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.AvgCookieJarSizePerKey2",
                                        /*sample=*/0,
                                        /*expected_bucket_count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.MaxCookieJarSizePerKey",
                                        /*sample=*/0,
                                        /*expected_bucket_count=*/1);
  }

  auto set_cookie =
      [&](const std::string& name, int cookie_value_size_kb,
          const std::string& domain, CookieSameSite same_site,
          const std::optional<CookiePartitionKey>& partition_key) {
        auto cc = CanonicalCookie::CreateUnsafeCookieForTesting(
            name, std::string(cookie_value_size_kb * 1024, '0'), domain, "/",
            base::Time(), base::Time::Now() + base::Minutes(59), base::Time(),
            base::Time(),
            /*secure=*/true,
            /*httponly=*/false, same_site, COOKIE_PRIORITY_DEFAULT,
            partition_key);
        GURL source_url = cookie_util::SimulatedCookieSource(*cc, "https");
        ASSERT_TRUE(SetCanonicalCookie(cm.get(), std::move(cc), source_url,
                                       /*can_modify_httponly=*/true));
      };

  {  // Add unpartitioned cookie.
    base::HistogramTester histogram_tester;
    set_cookie("a", 2, "a.url", CookieSameSite::NO_RESTRICTION, std::nullopt);
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    histogram_tester.ExpectUniqueSample("Cookie.CookieJarSize",
                                        /*sample=*/2,
                                        /*expected_bucket_count=*/1);
    // Recorded in bytes.
    histogram_tester.ExpectUniqueSample("Cookie.AvgCookieJarSizePerKey2",
                                        /*sample=*/2049,
                                        /*expected_bucket_count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.MaxCookieJarSizePerKey",
                                        /*sample=*/2,
                                        /*expected_bucket_count=*/1);
  }

  {  // Add partitioned cookie, should not impact the counter.
    base::HistogramTester histogram_tester;
    set_cookie("b", 3, "a.url", CookieSameSite::NO_RESTRICTION,
               CookiePartitionKey::FromURLForTesting(
                   GURL("https://toplevelsite.com")));
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    histogram_tester.ExpectUniqueSample("Cookie.CookieJarSize",
                                        /*sample=*/2,
                                        /*expected_bucket_count=*/1);
    // Recorded in bytes.
    histogram_tester.ExpectUniqueSample("Cookie.AvgCookieJarSizePerKey2",
                                        /*sample=*/2049,
                                        /*expected_bucket_count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.MaxCookieJarSizePerKey",
                                        /*sample=*/2,
                                        /*expected_bucket_count=*/1);
  }

  {  // Add unpartitioned cookie from another domain. Is also SameSite=Lax to
     // ensure the counter includes SameSite cookies.
    base::HistogramTester histogram_tester;
    set_cookie("c", 4, "c.url", CookieSameSite::LAX_MODE, std::nullopt);
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    histogram_tester.ExpectUniqueSample("Cookie.CookieJarSize",
                                        /*sample=*/6,
                                        /*expected_bucket_count=*/1);
    // Recorded in bytes.
    histogram_tester.ExpectUniqueSample("Cookie.AvgCookieJarSizePerKey2",
                                        /*sample=*/3073,
                                        /*expected_bucket_count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.MaxCookieJarSizePerKey",
                                        /*sample=*/4,
                                        /*expected_bucket_count=*/1);
  }
}

TEST_F(CookieMonsterTest, PartitionedCookieHistograms) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  {
    base::HistogramTester histogram_tester;
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    // Cookie counters.
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount",
                                        /*sample=*/0,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount.Nonced",
                                        /*sample=*/0,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieCount.Unnonced", /*sample=*/0,
        /*count=*/1);

    // Partitioned cookie jar size.
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes",
        /*sample=*/0,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Nonced", /*sample=*/0,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Unnonced", /*sample=*/0,
        /*count=*/1);

    // Partitioned cookie jar size per partition.
    histogram_tester.ExpectUniqueSample("Cookie.CookiePartitionSizeKibibytes",
                                        /*sample=*/0,
                                        /*count=*/0);
  }

  {  // Add unpartitioned cookie.
    base::HistogramTester histogram_tester;
    auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
        "a", "b", "a.url", "/", base::Time(),
        base::Time::Now() + base::Minutes(59), base::Time(), base::Time(),
        /*secure=*/true,
        /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT);
    GURL source_url = cookie_util::SimulatedCookieSource(*cookie, "https");
    ASSERT_TRUE(SetCanonicalCookie(cm.get(), std::move(cookie), source_url,
                                   /*modify_httponly=*/true));
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    // Cookie counters.
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount",
                                        /*sample=*/0,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount.Nonced",
                                        /*sample=*/0,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieCount.Unnonced", /*sample=*/0,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.Count2", /*sample=*/1,
                                        /*count=*/1);

    // Partitioned cookie jar size.
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes",
        /*sample=*/0,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Nonced", /*sample=*/0,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Unnonced", /*sample=*/0,
        /*count=*/1);

    // Partitioned cookie jar size per partition.
    histogram_tester.ExpectUniqueSample("Cookie.CookiePartitionSizeKibibytes",
                                        /*sample=*/0,
                                        /*count=*/0);
  }

  {  // Add unnonced partitioned cookie.
    base::HistogramTester histogram_tester;
    auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
        "a", std::string(2 * 1024, '0'), "a.url", "/", base::Time(),
        base::Time::Now() + base::Minutes(59), base::Time(), base::Time(),
        /*secure=*/true,
        /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT,
        CookiePartitionKey::FromURLForTesting(GURL("https://example.com")));
    GURL source_url = cookie_util::SimulatedCookieSource(*cookie, "https");
    ASSERT_TRUE(SetCanonicalCookie(cm.get(), std::move(cookie), source_url,
                                   /*modify_httponly=*/true));
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    // Cookie counters.
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount",
                                        /*sample=*/1,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount.Nonced",
                                        /*sample=*/0,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieCount.Unnonced", /*sample=*/1,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.Count2", /*sample=*/1,
                                        /*count=*/1);

    // Partitioned cookie jar size.
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes",
        /*sample=*/2,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Nonced", /*sample=*/0,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Unnonced", /*sample=*/2,
        /*count=*/1);

    // Partitioned cookie jar size per partition.
    histogram_tester.ExpectUniqueSample("Cookie.CookiePartitionSizeKibibytes",
                                        /*sample=*/2,
                                        /*count=*/1);
  }

  {  // Add nonced partitioned cookie.
    base::HistogramTester histogram_tester;
    auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
        "a", std::string(3 * 1024, '0'), "a.url", "/", base::Time(),
        base::Time::Now() + base::Minutes(59), base::Time(), base::Time(),
        /*secure=*/true,
        /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT,
        CookiePartitionKey::FromURLForTesting(
            GURL("https://example.com"),
            CookiePartitionKey::AncestorChainBit::kCrossSite,
            base::UnguessableToken::Create()));
    GURL source_url = cookie_util::SimulatedCookieSource(*cookie, "https");
    ASSERT_TRUE(SetCanonicalCookie(cm.get(), std::move(cookie), source_url,
                                   /*modify_httponly=*/true));
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    // Cookie counts.
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount",
                                        /*sample=*/2,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.PartitionedCookieCount.Nonced",
                                        /*sample=*/1,
                                        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieCount.Unnonced", /*sample=*/1,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample("Cookie.Count2", /*sample=*/1,
                                        /*count=*/1);

    // Partitioned cookie jar size.
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes",
        /*sample=*/5,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Nonced", /*sample=*/3,
        /*count=*/1);
    histogram_tester.ExpectUniqueSample(
        "Cookie.PartitionedCookieJarSizeKibibytes.Unnonced", /*sample=*/2,
        /*count=*/1);

    // Partitioned cookie jar size per partition.
    histogram_tester.ExpectBucketCount("Cookie.CookiePartitionSizeKibibytes",
                                       /*sample=*/2,
                                       /*count=*/1);
    histogram_tester.ExpectBucketCount("Cookie.CookiePartitionSizeKibibytes",
                                       /*sample=*/3,
                                       /*count=*/1);
  }
}

TEST_F(CookieMonsterTest, MaxSameSiteNoneCookiesPerKey) {
  const char kHistogramName[] = "Cookie.MaxSameSiteNoneCookiesPerKey";

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  ASSERT_EQ(0u, GetAllCookies(cm.get()).size());

  {  // Only SameSite cookies should not log a sample.
    base::HistogramTester histogram_tester;

    ASSERT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain1.test"),
                                   "A=1;SameSite=Lax",
                                   CookieOptions::MakeAllInclusive()));
    ASSERT_EQ(1u, GetAllCookies(cm.get()).size());
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 0 /* sample */,
                                        1 /* count */);
  }

  {  // SameSite=None cookie should log a sample.
    base::HistogramTester histogram_tester;

    ASSERT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain1.test"),
                                   "B=2;SameSite=None;Secure",
                                   CookieOptions::MakeAllInclusive()));
    ASSERT_EQ(2u, GetAllCookies(cm.get()).size());
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 1 /* sample */,
                                        1 /* count */);
  }

  {  // Should log the maximum number of SameSite=None cookies.
    base::HistogramTester histogram_tester;

    ASSERT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain2.test"),
                                   "A=1;SameSite=None;Secure",
                                   CookieOptions::MakeAllInclusive()));
    ASSERT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain2.test"),
                                   "B=2;SameSite=None;Secure",
                                   CookieOptions::MakeAllInclusive()));
    ASSERT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain3.test"),
                                   "A=1;SameSite=None;Secure",
                                   CookieOptions::MakeAllInclusive()));
    ASSERT_EQ(5u, GetAllCookies(cm.get()).size());
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 2 /* sample */,
                                        1 /* count */);
  }
}

// Test that localhost URLs can set and get secure cookies, even if
// non-cryptographic.
TEST_F(CookieMonsterTest, SecureCookieLocalhost) {
  auto cm = std::make_unique<CookieMonster>(nullptr, nullptr);

  GURL insecure_localhost("http://localhost");
  GURL secure_localhost("https://localhost");

  // Insecure localhost can set secure cookie, and warning is attached to
  // status.
  {
    auto cookie = CanonicalCookie::CreateForTesting(
        insecure_localhost, "from_insecure_localhost=1; Secure",
        base::Time::Now());
    ASSERT_TRUE(cookie);
    CookieInclusionStatus status =
        SetCanonicalCookieReturnAccessResult(cm.get(), std::move(cookie),
                                             insecure_localhost,
                                             true /* can_modify_httponly */)
            .status;
    EXPECT_TRUE(status.IsInclude());
    EXPECT_TRUE(status.HasExactlyWarningReasonsForTesting(
        {CookieInclusionStatus::WARN_SECURE_ACCESS_GRANTED_NON_CRYPTOGRAPHIC}));
  }
  // Secure localhost can set secure cookie, and warning is not attached to
  // status.
  {
    auto cookie = CanonicalCookie::CreateForTesting(
        secure_localhost, "from_secure_localhost=1; Secure", base::Time::Now());
    ASSERT_TRUE(cookie);
    CookieInclusionStatus status =
        SetCanonicalCookieReturnAccessResult(cm.get(), std::move(cookie),
                                             secure_localhost,
                                             true /* can_modify_httponly */)
            .status;
    EXPECT_EQ(CookieInclusionStatus(), status);
  }

  // Insecure localhost can get secure cookies, and warning is attached to
  // status.
  {
    GetCookieListCallback callback;
    cm->GetCookieListWithOptionsAsync(
        insecure_localhost, CookieOptions::MakeAllInclusive(),
        CookiePartitionKeyCollection(), callback.MakeCallback());
    callback.WaitUntilDone();
    EXPECT_EQ(2u, callback.cookies_with_access_results().size());
    for (const auto& cookie_item : callback.cookies_with_access_results()) {
      EXPECT_TRUE(cookie_item.cookie.SecureAttribute());
      EXPECT_TRUE(cookie_item.access_result.status.IsInclude());
      EXPECT_TRUE(
          cookie_item.access_result.status.HasExactlyWarningReasonsForTesting(
              {CookieInclusionStatus::
                   WARN_SECURE_ACCESS_GRANTED_NON_CRYPTOGRAPHIC}));
    }
  }
  // Secure localhost can get secure cookies, and warning is not attached to
  // status.
  {
    GetCookieListCallback callback;
    cm->GetCookieListWithOptionsAsync(
        secure_localhost, CookieOptions::MakeAllInclusive(),
        CookiePartitionKeyCollection(), callback.MakeCallback());
    callback.WaitUntilDone();
    EXPECT_EQ(2u, callback.cookies_with_access_results().size());
    for (const auto& cookie_item : callback.cookies_with_access_results()) {
      EXPECT_TRUE(cookie_item.cookie.SecureAttribute());
      EXPECT_EQ(CookieInclusionStatus(), cookie_item.access_result.status);
    }
  }
}

TEST_F(CookieMonsterTest, MaybeDeleteEquivalentCookieAndUpdateStatus) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  // Set a secure, httponly cookie from a secure origin
  auto preexisting_cookie = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "A=B;Secure;HttpOnly", base::Time::Now());
  CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(preexisting_cookie), https_www_foo_.url(),
      true /* can_modify_httponly */);
  ASSERT_TRUE(access_result.status.IsInclude());

  // Set a new cookie with a different name. Should work because cookies with
  // different names are not considered equivalent nor "equivalent for secure
  // cookie matching".
  // Same origin:
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "B=A;"));
  // Different scheme, same domain:
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "C=A;"));

  // Set a non-Secure cookie from an insecure origin that is
  // equivalent to the pre-existing Secure cookie.
  auto bad_cookie = CanonicalCookie::CreateForTesting(http_www_foo_.url(),
                                                      "A=D", base::Time::Now());
  // Allow modifying HttpOnly, so that we don't skip preexisting cookies for
  // being HttpOnly.
  access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(bad_cookie), http_www_foo_.url(),
      true /* can_modify_httponly */);
  EXPECT_TRUE(access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  // The preexisting cookie should still be there.
  EXPECT_THAT(GetCookiesWithOptions(cm.get(), https_www_foo_.url(),
                                    CookieOptions::MakeAllInclusive()),
              ::testing::HasSubstr("A=B"));

  auto entries = net_log_.GetEntries();
  size_t skipped_secure_netlog_index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_SECURE,
      NetLogEventPhase::NONE);
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_HTTPONLY));
  ExpectLogContainsSomewhereAfter(
      entries, skipped_secure_netlog_index,
      NetLogEventType::COOKIE_STORE_COOKIE_PRESERVED_SKIPPED_SECURE,
      NetLogEventPhase::NONE);

  net_log_.Clear();

  // Set a non-secure cookie from an insecure origin that matches the name of an
  // already existing cookie but is not equivalent. This should fail since it's
  // trying to shadow a secure cookie.
  bad_cookie = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), "A=E; path=/some/path", base::Time::Now());
  // Allow modifying HttpOnly, so that we don't skip preexisting cookies for
  // being HttpOnly.
  access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(bad_cookie), http_www_foo_.url(),
      true /* can_modify_httponly */);
  EXPECT_TRUE(access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  // The preexisting cookie should still be there.
  EXPECT_THAT(GetCookiesWithOptions(cm.get(), https_www_foo_.url(),
                                    CookieOptions::MakeAllInclusive()),
              ::testing::HasSubstr("A=B"));

  entries = net_log_.GetEntries();
  skipped_secure_netlog_index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_SECURE,
      NetLogEventPhase::NONE);
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_HTTPONLY));
  // There wasn't actually a strictly equivalent cookie that we would have
  // deleted.
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, skipped_secure_netlog_index,
      NetLogEventType::COOKIE_STORE_COOKIE_PRESERVED_SKIPPED_SECURE));

  net_log_.Clear();

  // Test skipping equivalent cookie for HttpOnly only.
  bad_cookie = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "A=E; Secure", base::Time::Now());
  access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(bad_cookie), https_www_foo_.url(),
      false /* can_modify_httponly */);
  EXPECT_TRUE(access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY}));

  entries = net_log_.GetEntries();
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_HTTPONLY,
      NetLogEventPhase::NONE);
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_SECURE));
}

TEST_F(CookieMonsterTest,
       MaybeDeleteEquivalentCookieAndUpdateStatus_PartitionedCookies) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  // Test adding two cookies with the same name, domain, and path but different
  // partition keys.
  auto cookie_partition_key1 =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite1.com"));

  auto preexisting_cookie = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "__Host-A=B; Secure; Path=/; Partitioned; HttpOnly",
      base::Time::Now(), std::nullopt /* server_time */,
      cookie_partition_key1 /* cookie_partition_key */);
  CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(preexisting_cookie), https_www_foo_.url(),
      true /* can_modify_httponly */);
  ASSERT_TRUE(access_result.status.IsInclude());

  // Should be able to set a cookie with a different partition key.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(),
                        "__Host-A=C; Secure; Path=/; Partitioned",
                        CookiePartitionKey::FromURLForTesting(
                            GURL("https://toplevelsite2.com"))));

  // Should not overwrite HttpOnly cookie.
  auto bad_cookie = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "__Host-A=D; Secure; Path=/; Partitioned",
      base::Time::Now(), std::nullopt /* server_time */, cookie_partition_key1);
  access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(bad_cookie), https_www_foo_.url(),
      false /* can_modify_httponly */);
  EXPECT_TRUE(access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY}));
  EXPECT_THAT(
      GetCookiesWithOptions(
          cm.get(), https_www_foo_.url(), CookieOptions::MakeAllInclusive(),
          CookiePartitionKeyCollection(cookie_partition_key1)),
      ::testing::HasSubstr("A=B"));
}

// Tests whether cookies that vary based on their source scheme/port are
// overwritten correctly depending on the state of the origin-bound feature
// flags.
class CookieMonsterTest_MaybeDeleteEquivalentCookieAndUpdateStatus
    : public CookieMonsterTest {
 public:
  // Creates a store, CookieMonster, and inserts a single cookie, created on an
  // https/443 origin.
  void InitializeTest() {
    store_ = base::MakeRefCounted<MockPersistentCookieStore>();
    cm_ = std::make_unique<CookieMonster>(store_.get(), net::NetLog::Get());

    auto preexisting_cookie_https = CanonicalCookie::CreateForTesting(
        https_www_foo_.url(), "A=PreexistingHttps443", base::Time::Now());

    CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
        cm_.get(), std::move(preexisting_cookie_https), https_www_foo_.url(),
        /*can_modify_httponly=*/true);
    ASSERT_TRUE(access_result.status.IsInclude());

    auto preexisting_domain_cookie_https = CanonicalCookie::CreateForTesting(
        https_www_foo_.url(),
        "A=PreexistingDomainHttps443; Domain=" + https_www_foo_.domain(),
        base::Time::Now());

    access_result = SetCanonicalCookieReturnAccessResult(
        cm_.get(), std::move(preexisting_domain_cookie_https),
        https_www_foo_.url(),
        /*can_modify_httponly=*/true);
    ASSERT_TRUE(access_result.status.IsInclude());

    ASSERT_EQ(GetAllCookies(cm_.get()).size(), 2UL);
  }

  // Inserts a single cookie that differs from "PreexistingHttps443" by scheme
  // only.
  void AddHttpPort443Cookie() {
    GURL::Replacements replace_scheme;
    replace_scheme.SetSchemeStr("http");
    // We need to explicitly set the existing port, otherwise GURL will
    // implicitly take the port of the new scheme. I.e.: We'll inadvertently
    // change the port to 80.
    replace_scheme.SetPortStr("443");
    GURL foo_made_http = https_www_foo_.url().ReplaceComponents(replace_scheme);

    auto differ_by_scheme_only = CanonicalCookie::CreateForTesting(
        foo_made_http, "A=InsertedHttp443", base::Time::Now());

    CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
        cm_.get(), std::move(differ_by_scheme_only), foo_made_http,
        /*can_modify_httponly=*/true);
    ASSERT_TRUE(access_result.status.IsInclude());
  }

  // Inserts a single cookie that differs from "PreexistingHttps443" by port
  // only.
  void AddHttpsPort80Cookie() {
    GURL::Replacements replace_port;
    replace_port.SetPortStr("80");
    GURL foo_made_80 = https_www_foo_.url().ReplaceComponents(replace_port);

    auto differ_by_port_only = CanonicalCookie::CreateForTesting(
        foo_made_80, "A=InsertedHttps80", base::Time::Now());

    CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
        cm_.get(), std::move(differ_by_port_only), foo_made_80,
        /*can_modify_httponly=*/true);
    ASSERT_TRUE(access_result.status.IsInclude());
  }

  // Inserts a single Domain cookie that differs from
  // "PreexistingDomainHttps443" by port only.
  void AddDomainHttpsPort80Cookie() {
    GURL::Replacements replace_port;
    replace_port.SetPortStr("80");
    GURL foo_made_80 = https_www_foo_.url().ReplaceComponents(replace_port);

    auto differ_by_port_only = CanonicalCookie::CreateForTesting(
        foo_made_80,
        "A=InsertedDomainHttps80; Domain=" + https_www_foo_.domain(),
        base::Time::Now());

    CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
        cm_.get(), std::move(differ_by_port_only), foo_made_80,
        /*can_modify_httponly=*/true);
    ASSERT_TRUE(access_result.status.IsInclude());
  }

  scoped_refptr<net::MockPersistentCookieStore> store_;
  std::unique_ptr<CookieMonster> cm_;
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Scheme binding disabled.
// Port binding disabled.
// Cookies that differ only in their scheme and/or port should overwrite the
// preexisting cookies.
TEST_F(CookieMonsterTest_MaybeDeleteEquivalentCookieAndUpdateStatus,
       NoSchemeNoPort) {
  scoped_feature_list_.InitWithFeatures(
      {}, {net::features::kEnableSchemeBoundCookies,
           net::features::kEnablePortBoundCookies});

  InitializeTest();

  AddHttpPort443Cookie();

  auto cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddDomainHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "InsertedDomainHttps80")));
}

// Scheme binding enabled.
// Port binding disabled.
// Cookies that differ in scheme are separate, cookies that differ only by
// port should be overwritten.
TEST_F(CookieMonsterTest_MaybeDeleteEquivalentCookieAndUpdateStatus,
       YesSchemeNoPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnableSchemeBoundCookies},
      {net::features::kEnablePortBoundCookies});

  InitializeTest();

  AddHttpPort443Cookie();

  auto cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddDomainHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "InsertedDomainHttps80")));
}

// Scheme binding disabled.
// Port binding enabled.
// Cookies that differ only by scheme and Domain cookies that differ only by
// port should be overwritten. Host cookies that differ only by port are
// separate.
TEST_F(CookieMonsterTest_MaybeDeleteEquivalentCookieAndUpdateStatus,
       NoSchemeYesPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnablePortBoundCookies},
      {net::features::kEnableSchemeBoundCookies});

  InitializeTest();

  AddHttpPort443Cookie();

  auto cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddDomainHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "InsertedDomainHttps80")));
}

// Scheme binding enabled.
// Port binding enabled.
// Cookies that differ by port or scheme are separate. Except for Domain cookies
// which will be overwritten if they differ only by port.
TEST_F(CookieMonsterTest_MaybeDeleteEquivalentCookieAndUpdateStatus,
       YesSchemeYesPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnableSchemeBoun
"""


```