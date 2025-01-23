Response:
The user wants me to analyze a C++ unit test file for Chromium's network stack, specifically `transport_security_state_unittest.cc`. This is part 2 of 3. I need to summarize the functionalities covered in this specific chunk of code.

Here's a breakdown of the key areas within the provided code:

1. **Testing Static Preloaded HSTS/PKP Entries:**  Several tests (`TransportSecurityStateTest`, `TransportSecurityStateStaticTest`) focus on verifying the behavior of preloaded HSTS (HTTP Strict Transport Security) and PKP (Public Key Pinning) entries. These tests check if specific domains are correctly configured to force HTTPS and/or have public key pins.
2. **HSTS Host Bypass List:** The `HstsHostBypassList` test checks if adding a domain to the bypass list correctly prevents HSTS enforcement for that domain while still respecting preloaded entries for subdomains.
3. **Certificate Transparency (CT) Delegate:** The `RequireCTConsultsDelegate` test verifies that the `TransportSecurityState` correctly consults the provided `RequireCTDelegate` to determine if Certificate Transparency is required for a given host.
4. **Emergency CT Disable:** The `CTEmergencyDisableTest` checks that the emergency disable flag for Certificate Transparency correctly overrides any host-specific or delegate-based CT requirements.
5. **Static Key Pinning Enforcement (Feature Flag):** Tests under `TransportSecurityStateStaticTest` use a feature flag (`kStaticKeyPinningEnforcement`) to simulate enabling/disabling static key pinning and verify the corresponding behavior.
6. **Huffman Trie Size Encoding/Decoding:**  The `WriteSizeDecodeSize` and `DecodeSizeFour` tests are related to a Huffman trie implementation, likely used for efficient storage or transmission of preloaded data. These tests specifically check the encoding and decoding of size values.
7. **Updating Key Pins List:** The `UpdateKeyPinsListValidPin` test verifies that the `UpdatePinList` function can successfully add new valid pins for a host, overriding the default behavior.

Now, I need to summarize these functionalities concisely.
这是文件 `net/http/transport_security_state_unittest.cc` 的第二部分，主要功能是测试 Chromium 网络栈中 `TransportSecurityState` 组件关于预加载的 HSTS (HTTP Strict Transport Security) 和 PKP (Public Key Pinning) 策略，以及动态更新和紧急禁用等功能。

**功能归纳:**

1. **测试静态预加载的 HSTS 和 PKP 状态:**  这部分代码着重测试了预加载到浏览器中的 HSTS 和 PKP 策略是否按预期工作。它会检查特定域名是否被正确地标记为强制使用 HTTPS，是否包含了子域名，以及是否设置了正确的公钥指纹 (SPKI hashes)。

2. **测试 HSTS 主机绕过列表:**  测试了将某个域名添加到 HSTS 绕过列表后，是否能够阻止对该域名的 HTTPS 强制升级，同时验证了预加载的 HSTS 规则是否仍然适用于其子域名。

3. **测试 Certificate Transparency (CT) 委托:**  验证了 `TransportSecurityState` 组件在检查 CT 要求时，是否正确地咨询了提供的 `RequireCTDelegate` 委托对象。这允许外部逻辑来决定是否需要对特定主机执行 CT 检查。

4. **测试紧急禁用 CT 功能:**  验证了当设置了紧急禁用 CT 的标志时，无论主机或委托如何配置，CT 检查都会被跳过。

5. **测试静态密钥锁定 (Pinning) 功能的启用和禁用:**  通过 Feature Flag (`kStaticKeyPinningEnforcement`) 模拟启用和禁用静态密钥锁定功能，并测试相应的行为，例如是否能够获取到预加载的公钥指纹。

6. **测试 Huffman Trie 的大小编码和解码:**  包含了一些关于 Huffman Trie 的测试，这很可能用于高效地存储或传输预加载的 HSTS/PKP 数据。这些测试验证了对大小进行编码和解码的正确性。

7. **测试动态更新密钥锁定列表:**  验证了可以通过 `UpdatePinList` 函数动态地添加新的有效的公钥指纹到信任列表中，并覆盖之前的行为。

**与 JavaScript 的关系举例说明:**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但 `TransportSecurityState` 的功能会影响浏览器中 JavaScript 代码的行为。例如：

* **假设输入:** 用户在浏览器的地址栏中输入 `http://paypal.com`。
* **逻辑推理:** 由于 `paypal.com` 在预加载列表中配置了 HSTS，`TransportSecurityState` 会拦截这次 HTTP 请求。
* **输出:** 浏览器会自动将请求升级到 `https://paypal.com`，而这个过程对于 JavaScript 来说是透明的，JavaScript 看到的已经是 HTTPS 连接。

**逻辑推理的假设输入与输出:**

**假设输入 1:**

* 域名: `mix.badssl.com`
* `TransportSecurityState` 实例 `state` 已加载预加载数据。

**输出 1:**

* `GetStaticDomainState(&state, "mix.badssl.com", &sts_state, &pkp_state)` 返回 `true`。
* `sts_state.include_subdomains` 为 `false`。
* `sts_state.upgrade_mode` 为 `TransportSecurityState::STSState::MODE_FORCE_HTTPS`。
* `pkp_state.include_subdomains` 为 `true`。
* `pkp_state.spki_hashes` 包含一个特定的公钥指纹。
* `pkp_state.bad_spki_hashes` 包含一个特定的错误的公钥指纹。

**假设输入 2:**

* 域名: `"simple-entry.example.com"`
* `TransportSecurityState` 实例 `state` 已加载预加载数据。

**输出 2:**

* `GetStaticDomainState(&state, "simple-entry.example.com", &sts_state, &pkp_state)` 返回 `true`。
* `sts_state.include_subdomains` 为 `true`。
* `sts_state.upgrade_mode` 为 `TransportSecurityState::STSState::MODE_FORCE_HTTPS`。
* `pkp_state` 是一个默认的 `TransportSecurityState::PKPState()` 对象 (没有设置公钥指纹)。

**涉及用户或编程常见的使用错误举例说明:**

* **用户错误:**  用户可能会尝试访问一个配置了 HSTS 的网站的 HTTP 版本。浏览器会根据 `TransportSecurityState` 的信息自动升级到 HTTPS，如果 HTTPS 连接失败（例如证书问题），用户可能会看到一个错误页面，而不太清楚是因为 HSTS 的原因。
* **编程错误:**  开发者可能会错误地配置预加载列表中的域名或策略，例如将 `include_subdomains` 设置为 `true` 但实际上某些子域名不支持 HTTPS，这会导致用户访问这些子域名时出现问题。
* **编程错误 (测试代码):**  在测试 `UpdateKeyPinsListValidPin` 时，如果提供的新的公钥指纹格式不正确，`hash.FromString(kBadPath[i])` 可能会返回 `false`，导致测试失败。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在地址栏中输入域名:** 用户在浏览器的地址栏中输入一个域名，例如 `http://www.paypal.com`。
2. **浏览器查询 `TransportSecurityState`:**  浏览器在发起请求前，会查询 `TransportSecurityState` 组件，检查该域名是否配置了 HSTS 或 PKP。
3. **匹配预加载列表或动态数据:** `TransportSecurityState` 会查找预加载的 HSTS/PKP 策略，或者用户之前访问该网站时动态存储的策略。
4. **执行 HSTS 升级或 PKP 检查:** 如果找到了 HSTS 策略，浏览器会将 HTTP 请求升级到 HTTPS。如果找到了 PKP 策略，浏览器会检查服务器返回的证书链是否与配置的公钥指纹匹配。
5. **单元测试模拟上述过程:**  这些单元测试通过直接调用 `TransportSecurityState` 的方法，并设置不同的输入（例如域名、证书指纹），来验证其在各种场景下的行为是否符合预期。调试时，可以通过断点或日志输出，查看 `TransportSecurityState` 在处理特定域名时的内部状态和决策过程。

总而言之，这部分代码主要负责测试 `TransportSecurityState` 组件中关于静态预加载 HSTS/PKP 策略的核心功能，以及相关的动态更新和紧急禁用机制，确保 Chromium 能够正确地执行这些安全策略。

### 提示词
```
这是目录为net/http/transport_security_state_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
e));
  EXPECT_TRUE(sts_state == TransportSecurityState::STSState());
  EXPECT_TRUE(pkp_state.include_subdomains);
  EXPECT_EQ(1U, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], GetSampleSPKIHash(0x1));
  EXPECT_EQ(0U, pkp_state.bad_spki_hashes.size());

  sts_state = TransportSecurityState::STSState();
  pkp_state = TransportSecurityState::PKPState();
  EXPECT_TRUE(
      GetStaticDomainState(&state, "mix.badssl.com", &sts_state, &pkp_state));
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(pkp_state.include_subdomains);
  EXPECT_EQ(1U, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], GetSampleSPKIHash(0x2));
  EXPECT_EQ(1U, pkp_state.bad_spki_hashes.size());
  EXPECT_EQ(pkp_state.bad_spki_hashes[0], GetSampleSPKIHash(0x1));

  sts_state = TransportSecurityState::STSState();
  pkp_state = TransportSecurityState::PKPState();

  // This should be a simple entry in the context of
  // TrieWriter::IsSimpleEntry().
  EXPECT_TRUE(GetStaticDomainState(&state, "simple-entry.example.com",
                                   &sts_state, &pkp_state));
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(pkp_state == TransportSecurityState::PKPState());
}

TEST_F(TransportSecurityStateTest, HstsHostBypassList) {
  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;

  std::string preloaded_tld = "example";
  std::string subdomain = "sub.example";

  {
    TransportSecurityState state;
    // Check that "example" is preloaded with subdomains.
    EXPECT_TRUE(state.ShouldUpgradeToSSL(preloaded_tld));
    EXPECT_TRUE(state.ShouldUpgradeToSSL(subdomain));
  }

  {
    // Add "example" to the bypass list.
    TransportSecurityState state({preloaded_tld});
    EXPECT_FALSE(state.ShouldUpgradeToSSL(preloaded_tld));
    // The preloaded entry should still apply to the subdomain.
    EXPECT_TRUE(state.ShouldUpgradeToSSL(subdomain));
  }
}

// Tests that TransportSecurityState always consults the RequireCTDelegate,
// if supplied.
TEST_F(TransportSecurityStateTest, RequireCTConsultsDelegate) {
  using ::testing::_;
  using ::testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  // Dummy cert to use as the validation chain. The contents do not matter.
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "expired_cert.pem");
  ASSERT_TRUE(cert);

  HashValueVector hashes;
  hashes.push_back(
      HashValue(X509Certificate::CalculateFingerprint256(cert->cert_buffer())));

  // If CT is required, then the requirements are not met if the CT policy
  // wasn't met, but are met if the policy was met or the build was out of
  // date.
  {
    TransportSecurityState state;
    const TransportSecurityState::CTRequirementsStatus original_status =
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS);

    MockRequireCTDelegate always_require_delegate;
    EXPECT_CALL(always_require_delegate, IsCTRequiredForHost(_, _, _))
        .WillRepeatedly(Return(CTRequirementLevel::REQUIRED));
    state.SetRequireCTDelegate(&always_require_delegate);
    EXPECT_EQ(
        TransportSecurityState::CT_REQUIREMENTS_NOT_MET,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS));
    EXPECT_EQ(
        TransportSecurityState::CT_REQUIREMENTS_NOT_MET,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_DIVERSE_SCTS));
    EXPECT_EQ(
        TransportSecurityState::CT_REQUIREMENTS_MET,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));
    EXPECT_EQ(
        TransportSecurityState::CT_REQUIREMENTS_MET,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_BUILD_NOT_TIMELY));

    state.SetRequireCTDelegate(nullptr);
    EXPECT_EQ(
        original_status,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS));
  }

  // If CT is not required, then regardless of the CT state for the host,
  // it should indicate CT is not required.
  {
    TransportSecurityState state;
    const TransportSecurityState::CTRequirementsStatus original_status =
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS);

    MockRequireCTDelegate never_require_delegate;
    EXPECT_CALL(never_require_delegate, IsCTRequiredForHost(_, _, _))
        .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));
    state.SetRequireCTDelegate(&never_require_delegate);
    EXPECT_EQ(
        TransportSecurityState::CT_NOT_REQUIRED,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS));
    EXPECT_EQ(
        TransportSecurityState::CT_NOT_REQUIRED,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_DIVERSE_SCTS));

    state.SetRequireCTDelegate(nullptr);
    EXPECT_EQ(
        original_status,
        state.CheckCTRequirements(
            HostPortPair("www.example.com", 443), true, hashes, cert.get(),
            ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS));
  }
}

// Tests that the emergency disable flags cause CT to stop being required
// regardless of host or delegate status.
TEST(CTEmergencyDisableTest, CTEmergencyDisable) {
  using ::testing::_;
  using ::testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  // Dummy cert to use as the validation chain. The contents do not matter.
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "expired_cert.pem");
  ASSERT_TRUE(cert);

  HashValueVector hashes;
  hashes.push_back(
      HashValue(X509Certificate::CalculateFingerprint256(cert->cert_buffer())));

  TransportSecurityState state;
  state.SetCTEmergencyDisabled(true);

  MockRequireCTDelegate always_require_delegate;
  EXPECT_CALL(always_require_delegate, IsCTRequiredForHost(_, _, _))
      .WillRepeatedly(Return(CTRequirementLevel::REQUIRED));
  state.SetRequireCTDelegate(&always_require_delegate);
  EXPECT_EQ(TransportSecurityState::CT_NOT_REQUIRED,
            state.CheckCTRequirements(
                HostPortPair("www.example.com", 443), true, hashes, cert.get(),
                ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS));
  EXPECT_EQ(TransportSecurityState::CT_NOT_REQUIRED,
            state.CheckCTRequirements(
                HostPortPair("www.example.com", 443), true, hashes, cert.get(),
                ct::CTPolicyCompliance::CT_POLICY_NOT_DIVERSE_SCTS));
  EXPECT_EQ(TransportSecurityState::CT_NOT_REQUIRED,
            state.CheckCTRequirements(
                HostPortPair("www.example.com", 443), true, hashes, cert.get(),
                ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));
  EXPECT_EQ(TransportSecurityState::CT_NOT_REQUIRED,
            state.CheckCTRequirements(
                HostPortPair("www.example.com", 443), true, hashes, cert.get(),
                ct::CTPolicyCompliance::CT_POLICY_BUILD_NOT_TIMELY));

  state.SetRequireCTDelegate(nullptr);
  EXPECT_EQ(TransportSecurityState::CT_NOT_REQUIRED,
            state.CheckCTRequirements(
                HostPortPair("www.example.com", 443), true, hashes, cert.get(),
                ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS));
}

#if BUILDFLAG(INCLUDE_TRANSPORT_SECURITY_STATE_PRELOAD_LIST)

class TransportSecurityStateStaticTest : public TransportSecurityStateTest {
 public:
  TransportSecurityStateStaticTest() {
    SetTransportSecurityStateSourceForTesting(nullptr);
  }
};

static bool StaticShouldRedirect(const char* hostname) {
  TransportSecurityState state;
  TransportSecurityState::STSState sts_state;
  return state.GetStaticSTSState(hostname, &sts_state) &&
         sts_state.ShouldUpgradeToSSL();
}

static bool HasStaticState(const char* hostname) {
  TransportSecurityState state;
  state.SetPinningListAlwaysTimelyForTesting(true);
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;
  return state.GetStaticSTSState(hostname, &sts_state) ||
         state.GetStaticPKPState(hostname, &pkp_state);
}

static bool HasStaticPublicKeyPins(const char* hostname) {
  TransportSecurityState state;
  state.SetPinningListAlwaysTimelyForTesting(true);
  TransportSecurityStateTest::EnableStaticPins(&state);
  TransportSecurityState::PKPState pkp_state;
  if (!state.GetStaticPKPState(hostname, &pkp_state))
    return false;

  return pkp_state.HasPublicKeyPins();
}

static bool OnlyPinningInStaticState(const char* hostname) {
  TransportSecurityState state;
  TransportSecurityStateTest::EnableStaticPins(&state);
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;
  return HasStaticPublicKeyPins(hostname) && !StaticShouldRedirect(hostname);
}

TEST_F(TransportSecurityStateStaticTest, EnableStaticPins) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  TransportSecurityState state;
  state.SetPinningListAlwaysTimelyForTesting(true);
  TransportSecurityState::PKPState pkp_state;

  EnableStaticPins(&state);

  EXPECT_TRUE(state.GetStaticPKPState("chrome.google.com", &pkp_state));
  EXPECT_FALSE(pkp_state.spki_hashes.empty());
}

TEST_F(TransportSecurityStateStaticTest, DisableStaticPins) {
  TransportSecurityState state;
  state.SetPinningListAlwaysTimelyForTesting(true);
  TransportSecurityState::PKPState pkp_state;

  DisableStaticPins(&state);
  EXPECT_FALSE(state.GetStaticPKPState("chrome.google.com", &pkp_state));
  EXPECT_TRUE(pkp_state.spki_hashes.empty());
}

TEST_F(TransportSecurityStateStaticTest, IsPreloaded) {
  const std::string paypal = "paypal.com";
  const std::string www_paypal = "www.paypal.com";
  const std::string foo_paypal = "foo.paypal.com";
  const std::string a_www_paypal = "a.www.paypal.com";
  const std::string abc_paypal = "a.b.c.paypal.com";
  const std::string example = "example.com";
  const std::string aypal = "aypal.com";
  const std::string google = "google";
  const std::string www_google = "www.google";
  const std::string foo = "foo";
  const std::string bank = "example.bank";
  const std::string insurance = "sub.example.insurance";

  TransportSecurityState state;
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;

  EXPECT_TRUE(GetStaticDomainState(&state, paypal, &sts_state, &pkp_state));
  EXPECT_TRUE(GetStaticDomainState(&state, www_paypal, &sts_state, &pkp_state));
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_TRUE(GetStaticDomainState(&state, google, &sts_state, &pkp_state));
  EXPECT_TRUE(GetStaticDomainState(&state, www_google, &sts_state, &pkp_state));
  EXPECT_TRUE(GetStaticDomainState(&state, foo, &sts_state, &pkp_state));
  EXPECT_TRUE(GetStaticDomainState(&state, bank, &sts_state, &pkp_state));
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_TRUE(GetStaticDomainState(&state, insurance, &sts_state, &pkp_state));
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_FALSE(
      GetStaticDomainState(&state, a_www_paypal, &sts_state, &pkp_state));
  EXPECT_FALSE(
      GetStaticDomainState(&state, abc_paypal, &sts_state, &pkp_state));
  EXPECT_FALSE(GetStaticDomainState(&state, example, &sts_state, &pkp_state));
  EXPECT_FALSE(GetStaticDomainState(&state, aypal, &sts_state, &pkp_state));
}

TEST_F(TransportSecurityStateStaticTest, PreloadedDomainSet) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  TransportSecurityState state;
  EnableStaticPins(&state);
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;

  // The domain wasn't being set, leading to a blank string in the
  // chrome://net-internals/#hsts UI. So test that.
  EXPECT_TRUE(state.GetStaticPKPState("market.android.com", &pkp_state));
  EXPECT_TRUE(state.GetStaticSTSState("market.android.com", &sts_state));
  EXPECT_EQ(sts_state.domain, "market.android.com");
  EXPECT_EQ(pkp_state.domain, "market.android.com");
  EXPECT_TRUE(state.GetStaticPKPState("sub.market.android.com", &pkp_state));
  EXPECT_TRUE(state.GetStaticSTSState("sub.market.android.com", &sts_state));
  EXPECT_EQ(sts_state.domain, "market.android.com");
  EXPECT_EQ(pkp_state.domain, "market.android.com");
}

TEST_F(TransportSecurityStateStaticTest, Preloaded) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  TransportSecurityState state;
  EnableStaticPins(&state);
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;

  // We do more extensive checks for the first domain.
  EXPECT_TRUE(state.GetStaticSTSState("www.paypal.com", &sts_state));
  EXPECT_FALSE(state.GetStaticPKPState("www.paypal.com", &pkp_state));
  EXPECT_EQ(sts_state.upgrade_mode,
            TransportSecurityState::STSState::MODE_FORCE_HTTPS);
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_FALSE(pkp_state.include_subdomains);

  EXPECT_TRUE(HasStaticState("paypal.com"));
  EXPECT_FALSE(HasStaticState("www2.paypal.com"));

  // Google hosts:

  EXPECT_TRUE(StaticShouldRedirect("chrome.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("checkout.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("wallet.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("docs.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("sites.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("drive.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("spreadsheets.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("appengine.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("market.android.com"));
  EXPECT_TRUE(StaticShouldRedirect("encrypted.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("accounts.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("profiles.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("mail.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("chatenabled.mail.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("talkgadget.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("hostedtalkgadget.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("talk.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("plus.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("groups.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("apis.google.com"));
  EXPECT_TRUE(StaticShouldRedirect("oauthaccountmanager.googleapis.com"));
  EXPECT_TRUE(StaticShouldRedirect("passwordsleakcheck-pa.googleapis.com"));
  EXPECT_TRUE(StaticShouldRedirect("ssl.google-analytics.com"));
  EXPECT_TRUE(StaticShouldRedirect("google"));
  EXPECT_TRUE(StaticShouldRedirect("foo.google"));
  EXPECT_TRUE(StaticShouldRedirect("foo"));
  EXPECT_TRUE(StaticShouldRedirect("domaintest.foo"));
  EXPECT_TRUE(StaticShouldRedirect("gmail.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.gmail.com"));
  EXPECT_TRUE(StaticShouldRedirect("googlemail.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.googlemail.com"));
  EXPECT_TRUE(StaticShouldRedirect("googleplex.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.googleplex.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.google-analytics.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.youtube.com"));
  EXPECT_TRUE(StaticShouldRedirect("youtube.com"));

  // These domains used to be only HSTS when SNI was available.
  EXPECT_TRUE(state.GetStaticSTSState("gmail.com", &sts_state));
  EXPECT_TRUE(state.GetStaticPKPState("gmail.com", &pkp_state));
  EXPECT_TRUE(state.GetStaticSTSState("www.gmail.com", &sts_state));
  EXPECT_TRUE(state.GetStaticPKPState("www.gmail.com", &pkp_state));
  EXPECT_TRUE(state.GetStaticSTSState("googlemail.com", &sts_state));
  EXPECT_TRUE(state.GetStaticPKPState("googlemail.com", &pkp_state));
  EXPECT_TRUE(state.GetStaticSTSState("www.googlemail.com", &sts_state));
  EXPECT_TRUE(state.GetStaticPKPState("www.googlemail.com", &pkp_state));

  // fi.g.co should not force HTTPS because there are still HTTP-only services
  // on it.
  EXPECT_FALSE(StaticShouldRedirect("fi.g.co"));

  // Other hosts:

  EXPECT_TRUE(StaticShouldRedirect("aladdinschools.appspot.com"));

  EXPECT_TRUE(StaticShouldRedirect("ottospora.nl"));
  EXPECT_TRUE(StaticShouldRedirect("www.ottospora.nl"));

  EXPECT_TRUE(StaticShouldRedirect("www.paycheckrecords.com"));

  EXPECT_TRUE(StaticShouldRedirect("lastpass.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.lastpass.com"));
  EXPECT_FALSE(HasStaticState("blog.lastpass.com"));

  EXPECT_TRUE(StaticShouldRedirect("keyerror.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.keyerror.com"));

  EXPECT_TRUE(StaticShouldRedirect("entropia.de"));
  EXPECT_TRUE(StaticShouldRedirect("www.entropia.de"));
  EXPECT_FALSE(HasStaticState("foo.entropia.de"));

  EXPECT_TRUE(StaticShouldRedirect("www.elanex.biz"));
  EXPECT_FALSE(HasStaticState("elanex.biz"));
  EXPECT_FALSE(HasStaticState("foo.elanex.biz"));

  EXPECT_TRUE(StaticShouldRedirect("sunshinepress.org"));
  EXPECT_TRUE(StaticShouldRedirect("www.sunshinepress.org"));
  EXPECT_TRUE(StaticShouldRedirect("a.b.sunshinepress.org"));

  EXPECT_TRUE(StaticShouldRedirect("www.noisebridge.net"));
  EXPECT_FALSE(HasStaticState("noisebridge.net"));
  EXPECT_FALSE(HasStaticState("foo.noisebridge.net"));

  EXPECT_TRUE(StaticShouldRedirect("neg9.org"));
  EXPECT_FALSE(HasStaticState("www.neg9.org"));

  EXPECT_TRUE(StaticShouldRedirect("riseup.net"));
  EXPECT_TRUE(StaticShouldRedirect("foo.riseup.net"));

  EXPECT_TRUE(StaticShouldRedirect("factor.cc"));
  EXPECT_FALSE(HasStaticState("www.factor.cc"));

  EXPECT_TRUE(StaticShouldRedirect("members.mayfirst.org"));
  EXPECT_TRUE(StaticShouldRedirect("support.mayfirst.org"));
  EXPECT_TRUE(StaticShouldRedirect("id.mayfirst.org"));
  EXPECT_TRUE(StaticShouldRedirect("lists.mayfirst.org"));
  EXPECT_FALSE(HasStaticState("www.mayfirst.org"));

  EXPECT_TRUE(StaticShouldRedirect("romab.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.romab.com"));
  EXPECT_TRUE(StaticShouldRedirect("foo.romab.com"));

  EXPECT_TRUE(StaticShouldRedirect("logentries.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.logentries.com"));
  EXPECT_FALSE(HasStaticState("foo.logentries.com"));

  EXPECT_TRUE(StaticShouldRedirect("stripe.com"));
  EXPECT_TRUE(StaticShouldRedirect("foo.stripe.com"));

  EXPECT_TRUE(StaticShouldRedirect("cloudsecurityalliance.org"));
  EXPECT_TRUE(StaticShouldRedirect("foo.cloudsecurityalliance.org"));

  EXPECT_TRUE(StaticShouldRedirect("login.sapo.pt"));
  EXPECT_TRUE(StaticShouldRedirect("foo.login.sapo.pt"));

  EXPECT_TRUE(StaticShouldRedirect("mattmccutchen.net"));
  EXPECT_TRUE(StaticShouldRedirect("foo.mattmccutchen.net"));

  EXPECT_TRUE(StaticShouldRedirect("betnet.fr"));
  EXPECT_TRUE(StaticShouldRedirect("foo.betnet.fr"));

  EXPECT_TRUE(StaticShouldRedirect("uprotect.it"));
  EXPECT_TRUE(StaticShouldRedirect("foo.uprotect.it"));

  EXPECT_TRUE(StaticShouldRedirect("cert.se"));
  EXPECT_TRUE(StaticShouldRedirect("foo.cert.se"));

  EXPECT_TRUE(StaticShouldRedirect("crypto.is"));
  EXPECT_TRUE(StaticShouldRedirect("foo.crypto.is"));

  EXPECT_TRUE(StaticShouldRedirect("simon.butcher.name"));
  EXPECT_TRUE(StaticShouldRedirect("foo.simon.butcher.name"));

  EXPECT_TRUE(StaticShouldRedirect("linx.net"));
  EXPECT_TRUE(StaticShouldRedirect("foo.linx.net"));

  EXPECT_TRUE(StaticShouldRedirect("dropcam.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.dropcam.com"));
  EXPECT_FALSE(HasStaticState("foo.dropcam.com"));

  EXPECT_TRUE(StaticShouldRedirect("ebanking.indovinabank.com.vn"));
  EXPECT_TRUE(StaticShouldRedirect("foo.ebanking.indovinabank.com.vn"));

  EXPECT_TRUE(StaticShouldRedirect("epoxate.com"));
  EXPECT_FALSE(HasStaticState("foo.epoxate.com"));

  EXPECT_TRUE(StaticShouldRedirect("www.moneybookers.com"));
  EXPECT_FALSE(HasStaticState("moneybookers.com"));

  EXPECT_TRUE(StaticShouldRedirect("ledgerscope.net"));
  EXPECT_TRUE(StaticShouldRedirect("www.ledgerscope.net"));
  EXPECT_FALSE(HasStaticState("status.ledgerscope.net"));

  EXPECT_TRUE(StaticShouldRedirect("foo.app.recurly.com"));
  EXPECT_TRUE(StaticShouldRedirect("foo.api.recurly.com"));

  EXPECT_TRUE(StaticShouldRedirect("greplin.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.greplin.com"));
  EXPECT_FALSE(HasStaticState("foo.greplin.com"));

  EXPECT_TRUE(StaticShouldRedirect("luneta.nearbuysystems.com"));
  EXPECT_TRUE(StaticShouldRedirect("foo.luneta.nearbuysystems.com"));

  EXPECT_TRUE(StaticShouldRedirect("ubertt.org"));
  EXPECT_TRUE(StaticShouldRedirect("foo.ubertt.org"));

  EXPECT_TRUE(StaticShouldRedirect("pixi.me"));
  EXPECT_TRUE(StaticShouldRedirect("www.pixi.me"));

  EXPECT_TRUE(StaticShouldRedirect("grepular.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.grepular.com"));

  EXPECT_TRUE(StaticShouldRedirect("mydigipass.com"));
  EXPECT_FALSE(StaticShouldRedirect("foo.mydigipass.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.mydigipass.com"));
  EXPECT_FALSE(StaticShouldRedirect("foo.www.mydigipass.com"));
  EXPECT_TRUE(StaticShouldRedirect("developer.mydigipass.com"));
  EXPECT_FALSE(StaticShouldRedirect("foo.developer.mydigipass.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.developer.mydigipass.com"));
  EXPECT_FALSE(StaticShouldRedirect("foo.www.developer.mydigipass.com"));
  EXPECT_TRUE(StaticShouldRedirect("sandbox.mydigipass.com"));
  EXPECT_FALSE(StaticShouldRedirect("foo.sandbox.mydigipass.com"));
  EXPECT_TRUE(StaticShouldRedirect("www.sandbox.mydigipass.com"));
  EXPECT_FALSE(StaticShouldRedirect("foo.www.sandbox.mydigipass.com"));

  EXPECT_TRUE(StaticShouldRedirect("bigshinylock.minazo.net"));
  EXPECT_TRUE(StaticShouldRedirect("foo.bigshinylock.minazo.net"));

  EXPECT_TRUE(StaticShouldRedirect("crate.io"));
  EXPECT_TRUE(StaticShouldRedirect("foo.crate.io"));

  EXPECT_TRUE(StaticShouldRedirect("sub.bank"));
  EXPECT_TRUE(StaticShouldRedirect("sub.insurance"));
}

TEST_F(TransportSecurityStateStaticTest, PreloadedPins) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  TransportSecurityState state;
  EnableStaticPins(&state);
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;

  // We do more extensive checks for the first domain.
  EXPECT_TRUE(state.GetStaticSTSState("www.paypal.com", &sts_state));
  EXPECT_FALSE(state.GetStaticPKPState("www.paypal.com", &pkp_state));
  EXPECT_EQ(sts_state.upgrade_mode,
            TransportSecurityState::STSState::MODE_FORCE_HTTPS);
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_FALSE(pkp_state.include_subdomains);

  EXPECT_TRUE(OnlyPinningInStaticState("www.google.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("foo.google.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("google.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("i.ytimg.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("ytimg.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("googleusercontent.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("www.googleusercontent.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("googleapis.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("googleadservices.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("googlecode.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("appspot.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("googlesyndication.com"));
  EXPECT_TRUE(OnlyPinningInStaticState("doubleclick.net"));
  EXPECT_TRUE(OnlyPinningInStaticState("googlegroups.com"));

  // Facebook has pinning and hsts on facebook.com, but only pinning on
  // subdomains.
  EXPECT_TRUE(state.GetStaticPKPState("facebook.com", &pkp_state));
  EXPECT_FALSE(pkp_state.spki_hashes.empty());
  EXPECT_TRUE(StaticShouldRedirect("facebook.com"));

  EXPECT_TRUE(state.GetStaticPKPState("foo.facebook.com", &pkp_state));
  EXPECT_FALSE(pkp_state.spki_hashes.empty());
  EXPECT_FALSE(StaticShouldRedirect("foo.facebook.com"));

  // www.facebook.com and subdomains have both pinning and hsts.
  EXPECT_TRUE(state.GetStaticPKPState("www.facebook.com", &pkp_state));
  EXPECT_FALSE(pkp_state.spki_hashes.empty());
  EXPECT_TRUE(StaticShouldRedirect("www.facebook.com"));

  EXPECT_TRUE(state.GetStaticPKPState("foo.www.facebook.com", &pkp_state));
  EXPECT_FALSE(pkp_state.spki_hashes.empty());
  EXPECT_TRUE(StaticShouldRedirect("foo.www.facebook.com"));
}

TEST_F(TransportSecurityStateStaticTest, BuiltinCertPins) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  TransportSecurityState state;
  EnableStaticPins(&state);
  TransportSecurityState::PKPState pkp_state;

  EXPECT_TRUE(state.GetStaticPKPState("chrome.google.com", &pkp_state));
  EXPECT_TRUE(HasStaticPublicKeyPins("chrome.google.com"));

  HashValueVector hashes;
  // Checks that a built-in list does exist.
  EXPECT_FALSE(pkp_state.CheckPublicKeyPins(hashes));
  EXPECT_FALSE(HasStaticPublicKeyPins("www.paypal.com"));

  EXPECT_TRUE(HasStaticPublicKeyPins("docs.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("1.docs.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("sites.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("drive.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("spreadsheets.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("wallet.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("checkout.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("appengine.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("market.android.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("encrypted.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("accounts.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("profiles.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("mail.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("chatenabled.mail.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("talkgadget.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("hostedtalkgadget.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("talk.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("plus.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("groups.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("apis.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("www.google-analytics.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("www.youtube.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("youtube.com"));

  EXPECT_TRUE(HasStaticPublicKeyPins("ssl.gstatic.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("gstatic.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("www.gstatic.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("ssl.google-analytics.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("www.googleplex.com"));
}

TEST_F(TransportSecurityStateStaticTest, OptionalHSTSCertPins) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  TransportSecurityState state;
  EnableStaticPins(&state);

  EXPECT_TRUE(HasStaticPublicKeyPins("google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("www.google.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("mail-attachment.googleusercontent.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("www.youtube.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("i.ytimg.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("googleapis.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("ajax.googleapis.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("googleadservices.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("pagead2.googleadservices.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("googlecode.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("kibbles.googlecode.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("appspot.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("googlesyndication.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("doubleclick.net"));
  EXPECT_TRUE(HasStaticPublicKeyPins("ad.doubleclick.net"));
  EXPECT_TRUE(HasStaticPublicKeyPins("redirector.gvt1.com"));
  EXPECT_TRUE(HasStaticPublicKeyPins("a.googlegroups.com"));
}

TEST_F(TransportSecurityStateStaticTest, OverrideBuiltins) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  EXPECT_TRUE(HasStaticPublicKeyPins("google.com"));
  EXPECT_FALSE(StaticShouldRedirect("google.com"));
  EXPECT_FALSE(StaticShouldRedirect("www.google.com"));

  TransportSecurityState state;
  state.SetPinningListAlwaysTimelyForTesting(true);

  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  state.AddHSTS("www.google.com", expiry, true);

  EXPECT_TRUE(state.ShouldUpgradeToSSL("www.google.com"));
}

TEST_F(TransportSecurityStateTest, WriteSizeDecodeSize) {
  for (size_t i = 0; i < 300; ++i) {
    SCOPED_TRACE(i);
    huffman_trie::TrieBitBuffer buffer;
    buffer.WriteSize(i);
    huffman_trie::BitWriter writer;
    buffer.WriteToBitWriter(&writer);
    size_t position = writer.position();
    writer.Flush();
    ASSERT_NE(writer.bytes().data(), nullptr);
    extras::PreloadDecoder::BitReader reader(writer.bytes().data(), position);
    size_t decoded_size;
    EXPECT_TRUE(reader.DecodeSize(&decoded_size));
    EXPECT_EQ(i, decoded_size);
  }
}

TEST_F(TransportSecurityStateTest, DecodeSizeFour) {
  // Test that BitReader::DecodeSize properly handles the number 4, including
  // not over-reading input bytes. BitReader::Next only fails if there's not
  // another byte to read from; if it reads past the number of bits in the
  // buffer but is still in the last byte it will still succeed. For this
  // reason, this test puts the encoding of 4 at the end of the byte to check
  // that DecodeSize doesn't over-read.
  //
  // 4 is encoded as 0b010. Shifted right to fill one byte, it is 0x02, with 5
  // bits of padding.
  uint8_t encoded = 0x02;
  extras::PreloadDecoder::BitReader reader(&encoded, 8);
  for (size_t i = 0; i < 5; ++i) {
    bool unused;
    ASSERT_TRUE(reader.Next(&unused));
  }
  size_t decoded_size;
  EXPECT_TRUE(reader.DecodeSize(&decoded_size));
  EXPECT_EQ(4u, decoded_size);
}

#endif  // BUILDFLAG(INCLUDE_TRANSPORT_SECURITY_STATE_PRELOAD_LIST)

TEST_F(TransportSecurityStateTest, UpdateKeyPinsListValidPin) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  HostPortPair host_port_pair(kHost, kPort);

  HashValueVector bad_hashes;
  for (size_t i = 0; kBadPath[i]; i++)
    EXPECT_TRUE(AddHash(kBadPath[i], &bad_hashes));

  TransportSecurityState state;
  EnableStaticPins(&state);

  // Prior to updating the list, bad_hashes should be rejected.
  EXPECT_EQ(TransportSecurityState::PKPStatus::VIOLATED,
            state.CheckPublicKeyPins(host_port_pair, true, bad_hashes));

  // Update the pins list, adding bad_hashes to the accepted hashes for this
  // host.
  std::vector<std::vector<uint8_t>> accepted_hashes;
  for (size_t i = 0; kBadPath[i]; i++) {
    HashValue hash;
    ASSERT_TRUE(hash.FromString(kBadPath[i]));
    accepted_hashes.emplace_back(hash.data(), hash.data() + hash.size());
  }
  TransportSecurityState::PinSet test_pinset(
      /*name=*/"test",
      /*static_spki_hashes=*/accepted_hashes,
      /*bad_static_spki_hashes=*/{});
  TransportSecurityState::PinSetInfo test_pinsetinfo(
      /*hostname=*/kHost, /*pinset_name=*/"test",
      /*include_subdomains=*/false);
  state.UpdatePinList({test_pinset}, {test_pinsetinfo}, base::Time::Now());

  // Hashes should now be accepted.
  EXPECT_EQ(TransportSecurityState::PKPStatus::OK,
```