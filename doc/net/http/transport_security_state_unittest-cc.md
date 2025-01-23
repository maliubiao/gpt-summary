Response:
The user wants to understand the functionality of the `transport_security_state_unittest.cc` file in Chromium's networking stack. I need to analyze the provided code snippet and identify its purpose.

Based on the file name and the included headers, this file is a unit test for the `TransportSecurityState` class. This class manages the HSTS (HTTP Strict Transport Security) and HPKP (HTTP Public Key Pinning) state for different domains.

Here's a breakdown of the functionality I can infer from the code:

1. **Testing HSTS Functionality:** The tests cover adding, retrieving, and expiring HSTS entries. This includes testing for domain matching (including subdomains and case-insensitivity), and checking if a host should be upgraded to HTTPS.
2. **Testing HPKP Functionality:** Similar to HSTS, the tests cover adding, retrieving, and expiring HPKP entries. The tests also check for matching public key pins.
3. **Testing Interaction between HSTS and HPKP:** The tests verify that HSTS and HPKP states are managed independently and don't interfere with each other.
4. **Testing Preloaded HSTS/HPKP Lists:**  The code includes test data from static files (`transport_security_state_static_unittest_default.h`, etc.) and tests how the `TransportSecurityState` class loads and uses these preloaded entries.
5. **Testing Dynamic vs. Static Entries:** The tests distinguish between dynamically added HSTS/HPKP entries and those loaded from the preloaded list.
6. **Testing Data Deletion:** The tests cover deleting dynamic HSTS/HPKP data based on time ranges and specific hostnames.
7. **Error Handling (Implicit):** Although not explicitly stated as "error handling," the tests implicitly check for correct behavior in various scenarios, including invalid input or unexpected states.
8. **Concurrency (Likely not directly tested here):** While the provided snippet doesn't show explicit concurrency tests, the actual `TransportSecurityState` class might have its own internal synchronization mechanisms, which might be tested elsewhere.

Now, let's address the specific points in the user's request:

*   **Functionality Listing:** I will list the identified functionalities.
*   **Relationship with JavaScript:**  I need to determine if any of the tested functionalities have a direct impact on JavaScript behavior in a browser. HSTS and HPKP are security mechanisms enforced by the browser, which can affect how JavaScript code interacts with the network.
*   **Logical Reasoning (Hypothetical Input/Output):** I will provide examples of how the tests might work, including hypothetical inputs and expected outputs.
*   **Common Usage Errors:** I will think about typical mistakes a developer or user might make that would interact with this functionality.
*   **User Operations as Debugging Clues:** I will outline the user actions that might lead to the execution of this code during debugging.
*   **Summary of Functionality (for Part 1):** I will summarize the main functions of the code in the provided snippet.
这是 `net/http/transport_security_state_unittest.cc` 文件的第一部分，主要功能是**对 `TransportSecurityState` 类的核心功能进行单元测试**。`TransportSecurityState` 类负责管理 HTTP 严格传输安全 (HSTS) 和公钥固定 (HPKP) 策略。

**具体功能归纳如下：**

1. **HSTS (HTTP Strict Transport Security) 测试:**
    *   **添加 HSTS 策略:** 测试向 `TransportSecurityState` 对象添加 HSTS 策略，包括是否包含子域名。
    *   **查询 HSTS 策略:** 测试查询特定域名是否应该升级到 HTTPS (`ShouldUpgradeToSSL`) 以及 SSL 错误是否应被视为致命错误 (`ShouldSSLErrorsBeFatal`)。
    *   **域名匹配测试:** 测试 HSTS 策略在不同域名格式下的匹配情况，包括大小写不敏感、是否包含末尾的 `.` 以及子域名匹配。
    *   **HSTS 策略过期:** 测试已过期的 HSTS 策略是否会被正确处理和移除。
    *   **获取动态 HSTS 状态:** 测试 `GetDynamicSTSState` 方法能否正确获取动态添加的 HSTS 策略信息。
    *   **获取 SSL 升级决策:** 测试 `GetSSLUpgradeDecision` 方法能否正确判断是否应该升级到 SSL，并识别决策的来源（静态预加载或动态添加）。

2. **HPKP (HTTP Public Key Pinning) 测试:**
    *   **添加 HPKP 策略:** 测试向 `TransportSecurityState` 对象添加 HPKP 策略，包括是否包含子域名和公钥哈希值。
    *   **查询 HPKP 策略:** 测试查询特定域名是否设置了公钥固定 (`HasPublicKeyPins`)。
    *   **HPKP 策略过期:** 测试已过期的 HPKP 策略是否会被正确处理和移除。
    *   **获取动态 HPKP 状态:** 测试 `GetDynamicPKPState` 方法能否正确获取动态添加的 HPKP 策略信息。
    *   **公钥 Pin 验证:** 测试 `CheckPublicKeyPins` 方法能否正确验证证书链的公钥哈希值是否与预设的 Pin 匹配。

3. **HSTS 和 HPKP 的相互作用测试:**
    *   **独立性:** 测试 HSTS 和 HPKP 策略的添加、查询和过期是相互独立的。
    *   **优先级:** 测试更具体的 HPKP 策略会覆盖更宽泛的策略，即使后者包含了子域名（与 HSTS 不同）。

4. **预加载 HSTS/HPKP 列表测试:**
    *   **加载静态数据:** 测试从静态文件（如 `transport_security_state_static_unittest_default.h` 等）加载预加载的 HSTS 和 HPKP 策略。
    *   **查询静态策略:** 测试 `GetStaticSTSState` 和 `GetStaticPKPState` 方法能否正确获取预加载的策略信息。
    *   **解码测试:** 测试预加载数据的解码过程，包括不同类型的策略和包含子域名的情况。

5. **数据删除测试:**
    *   **删除指定时间范围内的动态数据:** 测试 `DeleteAllDynamicDataBetween` 方法能否正确删除指定时间范围内的动态 HSTS 和 HPKP 策略。
    *   **删除特定主机的动态数据:** 测试 `DeleteDynamicDataForHost` 方法能否正确删除特定主机的动态 HSTS 和 HPKP 策略。

6. **其他测试:**
    *   **长域名测试:** 测试处理非常长的域名时是否会发生错误。
    *   **Pin 验证（无拒绝证书）:** 测试在没有明确拒绝的证书哈希的情况下，Pin 验证是否正常工作。

**与 JavaScript 的功能关系：**

`TransportSecurityState` 的功能直接影响着浏览器中 JavaScript 代码的网络行为。

*   **HTTPS 升级：** 当 JavaScript 代码尝试通过 HTTP 加载资源时，如果目标域名存在 HSTS 策略，浏览器会强制将其升级到 HTTPS。这对于 `fetch` API、`XMLHttpRequest`、`<img>` 标签的 `src` 属性等都有影响。
    *   **举例：** 如果 `example.com` 设置了 HSTS，以下 JavaScript 代码在执行时，浏览器会尝试加载 `https://example.com/resource.js`，即使代码中指定的是 `http://example.com/resource.js`。

    ```javascript
    fetch('http://example.com/resource.js')
      .then(response => response.text())
      .then(data => console.log(data));
    ```

*   **SSL 错误处理：** 如果一个域名设置了 HSTS 或 HPKP，并且在建立 HTTPS 连接时发生了 SSL 证书错误（例如证书过期、自签名等），浏览器会阻止连接，并可能阻止 JavaScript 代码加载资源或完成请求。`
### 提示词
```
这是目录为net/http/transport_security_state_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/transport_security_state.h"

#include <stdint.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "base/base64.h"
#include "base/files/file_path.h"
#include "base/functional/callback_helpers.h"
#include "base/json/json_reader.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/rand_util.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/mock_entropy_provider.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"
#include "crypto/sha2.h"
#include "net/base/features.h"
#include "net/base/hash_value.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/base/schemeful_site.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/extras/preload_data/decoder.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state_source.h"
#include "net/net_buildflags.h"
#include "net/ssl/ssl_info.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/tools/huffman_trie/bit_writer.h"
#include "net/tools/huffman_trie/trie/trie_bit_buffer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/origin.h"

namespace net {

namespace {

namespace test_default {
#include "net/http/transport_security_state_static_unittest_default.h"
}
namespace test1 {
#include "net/http/transport_security_state_static_unittest1.h"
}
namespace test2 {
#include "net/http/transport_security_state_static_unittest2.h"
}
namespace test3 {
#include "net/http/transport_security_state_static_unittest3.h"
}

const char kHost[] = "example.test";
const uint16_t kPort = 443;

const char* const kGoodPath[] = {
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "sha256/fzP+pVAbH0hRoUphJKenIP8+2tD/d2QH9J+kQNieM6Q=",
    "sha256/9vRUVdjloCa4wXUKfDWotV5eUXYD7vu0v0z9SRzQdzg=",
    "sha256/Nn8jk5By4Vkq6BeOVZ7R7AC6XUUBZsWmUbJR1f1Y5FY=",
    nullptr,
};

const char* const kBadPath[] = {
    "sha256/1111111111111111111111111111111111111111111=",
    "sha256/2222222222222222222222222222222222222222222=",
    "sha256/3333333333333333333333333333333333333333333=",
    nullptr,
};

class MockRequireCTDelegate : public TransportSecurityState::RequireCTDelegate {
 public:
  MOCK_METHOD3(IsCTRequiredForHost,
               CTRequirementLevel(std::string_view hostname,
                                  const X509Certificate* chain,
                                  const HashValueVector& hashes));
};

bool operator==(const TransportSecurityState::STSState& lhs,
                const TransportSecurityState::STSState& rhs) {
  return lhs.last_observed == rhs.last_observed && lhs.expiry == rhs.expiry &&
         lhs.upgrade_mode == rhs.upgrade_mode &&
         lhs.include_subdomains == rhs.include_subdomains &&
         lhs.domain == rhs.domain;
}

bool operator==(const TransportSecurityState::PKPState& lhs,
                const TransportSecurityState::PKPState& rhs) {
  return lhs.last_observed == rhs.last_observed && lhs.expiry == rhs.expiry &&
         lhs.spki_hashes == rhs.spki_hashes &&
         lhs.bad_spki_hashes == rhs.bad_spki_hashes &&
         lhs.include_subdomains == rhs.include_subdomains &&
         lhs.domain == rhs.domain;
}

}  // namespace

class TransportSecurityStateTest : public ::testing::Test,
                                   public WithTaskEnvironment {
 public:
  TransportSecurityStateTest()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);
    // Need mocked out time for pruning tests. Don't start with a
    // time of 0, as code doesn't generally expect it.
    FastForwardBy(base::Days(1));
  }

  ~TransportSecurityStateTest() override {
    SetTransportSecurityStateSourceForTesting(nullptr);
  }

  static void DisableStaticPins(TransportSecurityState* state) {
    state->enable_static_pins_ = false;
  }

  static void EnableStaticPins(TransportSecurityState* state) {
    state->enable_static_pins_ = true;
    state->SetPinningListAlwaysTimelyForTesting(true);
  }

  static HashValueVector GetSampleSPKIHashes() {
    HashValueVector spki_hashes;
    HashValue hash(HASH_VALUE_SHA256);
    memset(hash.data(), 0, hash.size());
    spki_hashes.push_back(hash);
    return spki_hashes;
  }

  static HashValue GetSampleSPKIHash(uint8_t value) {
    HashValue hash(HASH_VALUE_SHA256);
    memset(hash.data(), value, hash.size());
    return hash;
  }

 protected:
  bool GetStaticDomainState(TransportSecurityState* state,
                            const std::string& host,
                            TransportSecurityState::STSState* sts_result,
                            TransportSecurityState::PKPState* pkp_result) {
    bool ret = state->GetStaticSTSState(host, sts_result);
    if (state->GetStaticPKPState(host, pkp_result))
      ret = true;
    return ret;
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(TransportSecurityStateTest, DomainNameOddities) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  // DNS suffix search tests. Some DNS resolvers allow a terminal "." to
  // indicate not perform DNS suffix searching. Ensure that regardless
  // of how this is treated at the resolver layer, or at the URL/origin
  // layer (that is, whether they are treated as equivalent or distinct),
  // ensure that for policy matching, something lacking a terminal "."
  // is equivalent to something with a terminal "."
  EXPECT_FALSE(state.ShouldUpgradeToSSL("example.com"));

  state.AddHSTS("example.com", expiry, true /* include_subdomains */);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.com"));
  // Trailing '.' should be equivalent; it's just a resolver hint
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.com."));
  // Leading '.' should be invalid
  EXPECT_FALSE(state.ShouldUpgradeToSSL(".example.com"));
  // Subdomains should work regardless
  EXPECT_TRUE(state.ShouldUpgradeToSSL("sub.example.com"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("sub.example.com."));
  // But invalid subdomains should be rejected
  EXPECT_FALSE(state.ShouldUpgradeToSSL("sub..example.com"));
  EXPECT_FALSE(state.ShouldUpgradeToSSL("sub..example.com."));

  // Now try the inverse form
  TransportSecurityState state2;
  state2.AddHSTS("example.net.", expiry, true /* include_subdomains */);
  EXPECT_TRUE(state2.ShouldUpgradeToSSL("example.net."));
  EXPECT_TRUE(state2.ShouldUpgradeToSSL("example.net"));
  EXPECT_TRUE(state2.ShouldUpgradeToSSL("sub.example.net."));
  EXPECT_TRUE(state2.ShouldUpgradeToSSL("sub.example.net"));

  // Finally, test weird things
  TransportSecurityState state3;
  state3.AddHSTS("", expiry, true /* include_subdomains */);
  EXPECT_FALSE(state3.ShouldUpgradeToSSL(""));
  EXPECT_FALSE(state3.ShouldUpgradeToSSL("."));
  EXPECT_FALSE(state3.ShouldUpgradeToSSL("..."));
  // Make sure it didn't somehow apply HSTS to the world
  EXPECT_FALSE(state3.ShouldUpgradeToSSL("example.org"));

  TransportSecurityState state4;
  state4.AddHSTS(".", expiry, true /* include_subdomains */);
  EXPECT_FALSE(state4.ShouldUpgradeToSSL(""));
  EXPECT_FALSE(state4.ShouldUpgradeToSSL("."));
  EXPECT_FALSE(state4.ShouldUpgradeToSSL("..."));
  EXPECT_FALSE(state4.ShouldUpgradeToSSL("example.org"));

  // Now do the same for preloaded entries
  TransportSecurityState state5;
  EXPECT_TRUE(state5.ShouldUpgradeToSSL("hsts-preloaded.test"));
  EXPECT_TRUE(state5.ShouldUpgradeToSSL("hsts-preloaded.test."));
  EXPECT_FALSE(state5.ShouldUpgradeToSSL("hsts-preloaded..test"));
  EXPECT_FALSE(state5.ShouldUpgradeToSSL("hsts-preloaded..test."));
}

TEST_F(TransportSecurityStateTest, SimpleMatches) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  EXPECT_FALSE(state.ShouldUpgradeToSSL("example.com"));
  bool include_subdomains = false;
  state.AddHSTS("example.com", expiry, include_subdomains);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.com"));
  EXPECT_TRUE(state.ShouldSSLErrorsBeFatal("example.com"));
  EXPECT_FALSE(state.ShouldUpgradeToSSL("foo.example.com"));
  EXPECT_FALSE(state.ShouldSSLErrorsBeFatal("foo.example.com"));
}

TEST_F(TransportSecurityStateTest, MatchesCase1) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  EXPECT_FALSE(state.ShouldUpgradeToSSL("example.com"));
  bool include_subdomains = false;
  state.AddHSTS("EXample.coM", expiry, include_subdomains);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.com"));
}

TEST_F(TransportSecurityStateTest, MatchesCase2) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  // Check dynamic entries
  EXPECT_FALSE(state.ShouldUpgradeToSSL("EXample.coM"));
  bool include_subdomains = false;
  state.AddHSTS("example.com", expiry, include_subdomains);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("EXample.coM"));

  // Check static entries
  EXPECT_TRUE(state.ShouldUpgradeToSSL("hStS-prelOAded.tEsT"));
  EXPECT_TRUE(
      state.ShouldUpgradeToSSL("inClude-subDOmaIns-hsts-prEloaDed.TesT"));
}

TEST_F(TransportSecurityStateTest, SubdomainMatches) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  EXPECT_FALSE(state.ShouldUpgradeToSSL("example.test"));
  bool include_subdomains = true;
  state.AddHSTS("example.test", expiry, include_subdomains);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.example.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.bar.example.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.bar.baz.example.test"));
  EXPECT_FALSE(state.ShouldUpgradeToSSL("test"));
  EXPECT_FALSE(state.ShouldUpgradeToSSL("notexample.test"));
}

// Tests that a more-specific HSTS rule without the includeSubDomains bit does
// not override a less-specific rule with includeSubDomains. Applicability is
// checked before specificity. See https://crbug.com/821811.
TEST_F(TransportSecurityStateTest, STSSubdomainNoOverride) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  const base::Time older = current_time - base::Seconds(1000);

  state.AddHSTS("example.test", expiry, true);
  state.AddHSTS("foo.example.test", expiry, false);

  // The example.test rule applies to the entire domain, including subdomains of
  // foo.example.test.
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.example.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("bar.foo.example.test"));
  EXPECT_TRUE(state.ShouldSSLErrorsBeFatal("bar.foo.example.test"));

  // Expire the foo.example.test rule.
  state.AddHSTS("foo.example.test", older, false);

  // The example.test rule still applies.
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.example.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("bar.foo.example.test"));
  EXPECT_TRUE(state.ShouldSSLErrorsBeFatal("bar.foo.example.test"));
}

// Tests that a more-specific HPKP rule overrides a less-specific rule
// with it, regardless of the includeSubDomains bit. Note this behavior does not
// match HSTS. See https://crbug.com/821811.
TEST_F(TransportSecurityStateTest, PKPSubdomainCarveout) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  const base::Time older = current_time - base::Seconds(1000);

  state.AddHPKP("example.test", expiry, true, GetSampleSPKIHashes());
  state.AddHPKP("foo.example.test", expiry, false, GetSampleSPKIHashes());
  EXPECT_TRUE(state.HasPublicKeyPins("example.test"));
  EXPECT_TRUE(state.HasPublicKeyPins("foo.example.test"));

  // The foo.example.test rule overrides the example1.test rule, so
  // bar.foo.example.test has no HPKP state.
  EXPECT_FALSE(state.HasPublicKeyPins("bar.foo.example.test"));
  EXPECT_FALSE(state.ShouldSSLErrorsBeFatal("bar.foo.example.test"));

  // Expire the foo.example.test rule.
  state.AddHPKP("foo.example.test", older, false, GetSampleSPKIHashes());

  // Now the base example.test rule applies to bar.foo.example.test.
  EXPECT_TRUE(state.HasPublicKeyPins("bar.foo.example.test"));
  EXPECT_TRUE(state.ShouldSSLErrorsBeFatal("bar.foo.example.test"));
}

TEST_F(TransportSecurityStateTest, FatalSSLErrors) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  state.AddHSTS("example1.test", expiry, false);
  state.AddHPKP("example2.test", expiry, false, GetSampleSPKIHashes());

  // The presense of either HSTS or HPKP is enough to make SSL errors fatal.
  EXPECT_TRUE(state.ShouldSSLErrorsBeFatal("example1.test"));
  EXPECT_TRUE(state.ShouldSSLErrorsBeFatal("example2.test"));
}

// Tests that HPKP and HSTS state both expire. Also tests that expired entries
// are pruned.
TEST_F(TransportSecurityStateTest, Expiration) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  const base::Time older = current_time - base::Seconds(1000);

  // Note: this test assumes that inserting an entry with an expiration time in
  // the past works and is pruned on query.
  state.AddHSTS("example1.test", older, false);
  EXPECT_TRUE(TransportSecurityState::STSStateIterator(state).HasNext());
  EXPECT_FALSE(state.ShouldUpgradeToSSL("example1.test"));
  // Querying |state| for a domain should flush out expired entries.
  EXPECT_FALSE(TransportSecurityState::STSStateIterator(state).HasNext());

  state.AddHPKP("example1.test", older, false, GetSampleSPKIHashes());
  EXPECT_TRUE(state.has_dynamic_pkp_state());
  EXPECT_FALSE(state.HasPublicKeyPins("example1.test"));
  // Querying |state| for a domain should flush out expired entries.
  EXPECT_FALSE(state.has_dynamic_pkp_state());

  state.AddHSTS("example1.test", older, false);
  state.AddHPKP("example1.test", older, false, GetSampleSPKIHashes());
  EXPECT_TRUE(TransportSecurityState::STSStateIterator(state).HasNext());
  EXPECT_TRUE(state.has_dynamic_pkp_state());
  EXPECT_FALSE(state.ShouldSSLErrorsBeFatal("example1.test"));
  // Querying |state| for a domain should flush out expired entries.
  EXPECT_FALSE(TransportSecurityState::STSStateIterator(state).HasNext());
  EXPECT_FALSE(state.has_dynamic_pkp_state());

  // Test that HSTS can outlive HPKP.
  state.AddHSTS("example1.test", expiry, false);
  state.AddHPKP("example1.test", older, false, GetSampleSPKIHashes());
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example1.test"));
  EXPECT_FALSE(state.HasPublicKeyPins("example1.test"));

  // Test that HPKP can outlive HSTS.
  state.AddHSTS("example2.test", older, false);
  state.AddHPKP("example2.test", expiry, false, GetSampleSPKIHashes());
  EXPECT_FALSE(state.ShouldUpgradeToSSL("example2.test"));
  EXPECT_TRUE(state.HasPublicKeyPins("example2.test"));
}

// Tests that HPKP and HSTS state are queried independently for subdomain
// matches.
TEST_F(TransportSecurityStateTest, IndependentSubdomain) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  state.AddHSTS("example1.test", expiry, true);
  state.AddHPKP("example1.test", expiry, false, GetSampleSPKIHashes());

  state.AddHSTS("example2.test", expiry, false);
  state.AddHPKP("example2.test", expiry, true, GetSampleSPKIHashes());

  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.example1.test"));
  EXPECT_FALSE(state.HasPublicKeyPins("foo.example1.test"));
  EXPECT_FALSE(state.ShouldUpgradeToSSL("foo.example2.test"));
  EXPECT_TRUE(state.HasPublicKeyPins("foo.example2.test"));
}

// Tests that HPKP and HSTS state are inserted and overridden independently.
TEST_F(TransportSecurityStateTest, IndependentInsertion) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  // Place an includeSubdomains HSTS entry below a normal HPKP entry.
  state.AddHSTS("example1.test", expiry, true);
  state.AddHPKP("foo.example1.test", expiry, false, GetSampleSPKIHashes());

  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.example1.test"));
  EXPECT_TRUE(state.HasPublicKeyPins("foo.example1.test"));
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example1.test"));
  EXPECT_FALSE(state.HasPublicKeyPins("example1.test"));

  // Drop the includeSubdomains from the HSTS entry.
  state.AddHSTS("example1.test", expiry, false);

  EXPECT_FALSE(state.ShouldUpgradeToSSL("foo.example1.test"));
  EXPECT_TRUE(state.HasPublicKeyPins("foo.example1.test"));

  // Place an includeSubdomains HPKP entry below a normal HSTS entry.
  state.AddHSTS("foo.example2.test", expiry, false);
  state.AddHPKP("example2.test", expiry, true, GetSampleSPKIHashes());

  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.example2.test"));
  EXPECT_TRUE(state.HasPublicKeyPins("foo.example2.test"));

  // Drop the includeSubdomains from the HSTS entry.
  state.AddHPKP("example2.test", expiry, false, GetSampleSPKIHashes());

  EXPECT_TRUE(state.ShouldUpgradeToSSL("foo.example2.test"));
  EXPECT_FALSE(state.HasPublicKeyPins("foo.example2.test"));
}

// Tests that GetDynamic[PKP|STS]State returns the correct data and that the
// states are not mixed together.
TEST_F(TransportSecurityStateTest, DynamicDomainState) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry1 = current_time + base::Seconds(1000);
  const base::Time expiry2 = current_time + base::Seconds(2000);

  state.AddHSTS("example.com", expiry1, true);
  state.AddHPKP("foo.example.com", expiry2, false, GetSampleSPKIHashes());

  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;
  ASSERT_TRUE(state.GetDynamicSTSState("foo.example.com", &sts_state));
  ASSERT_TRUE(state.GetDynamicPKPState("foo.example.com", &pkp_state));
  EXPECT_TRUE(sts_state.ShouldUpgradeToSSL());
  EXPECT_TRUE(pkp_state.HasPublicKeyPins());
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_FALSE(pkp_state.include_subdomains);
  EXPECT_EQ(expiry1, sts_state.expiry);
  EXPECT_EQ(expiry2, pkp_state.expiry);
  EXPECT_EQ("example.com", sts_state.domain);
  EXPECT_EQ("foo.example.com", pkp_state.domain);
}

// Tests that GetSSLUpgradeDecision() matches the result of ShouldUpgradeToSSL()
// and correctly identifies the source of the decision.
TEST_F(TransportSecurityStateTest, StaticOrDynamicSource) {
  TransportSecurityState state;
  SetTransportSecurityStateSourceForTesting(&test1::kHSTSSource);

  // Check preconditions of preloaded states.
  TransportSecurityState::STSState sts_state;
  ASSERT_TRUE(state.GetStaticSTSState("hsts.example.com", &sts_state));
  ASSERT_EQ(sts_state.upgrade_mode,
            TransportSecurityState::STSState::MODE_FORCE_HTTPS);
  ASSERT_TRUE(sts_state.include_subdomains);
  ASSERT_FALSE(state.GetStaticSTSState("dynamic.example.com", &sts_state));

  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);

  EXPECT_EQ(state.GetSSLUpgradeDecision("dynamic.example.com"),
            SSLUpgradeDecision::kNoUpgrade);
  EXPECT_FALSE(state.ShouldUpgradeToSSL("dynamic.example.com"));

  EXPECT_EQ(state.GetSSLUpgradeDecision("hsts.example.com"),
            SSLUpgradeDecision::kStaticUpgrade);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("hsts.example.com"));

  state.AddHSTS("dynamic.example.com", expiry, false);
  EXPECT_EQ(state.GetSSLUpgradeDecision("dynamic.example.com"),
            SSLUpgradeDecision::kDynamicUpgrade);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("dynamic.example.com"));

  // Dynamic state for a host that already has static state doesn't change the
  // decision.
  state.AddHSTS("subdomain.hsts.example.com", expiry, false);
  EXPECT_EQ(state.GetSSLUpgradeDecision("subdomain.hsts.example.com"),
            SSLUpgradeDecision::kStaticUpgrade);
  EXPECT_TRUE(state.ShouldUpgradeToSSL("subdomain.hsts.example.com"));
}

// Tests that new pins always override previous pins. This should be true for
// both pins at the same domain or includeSubdomains pins at a parent domain.
TEST_F(TransportSecurityStateTest, NewPinsOverride) {
  TransportSecurityState state;
  TransportSecurityState::PKPState pkp_state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  HashValue hash1(HASH_VALUE_SHA256);
  memset(hash1.data(), 0x01, hash1.size());
  HashValue hash2(HASH_VALUE_SHA256);
  memset(hash2.data(), 0x02, hash1.size());
  HashValue hash3(HASH_VALUE_SHA256);
  memset(hash3.data(), 0x03, hash1.size());

  state.AddHPKP("example.com", expiry, true, HashValueVector(1, hash1));

  ASSERT_TRUE(state.GetDynamicPKPState("foo.example.com", &pkp_state));
  ASSERT_EQ(1u, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], hash1);

  state.AddHPKP("foo.example.com", expiry, false, HashValueVector(1, hash2));

  ASSERT_TRUE(state.GetDynamicPKPState("foo.example.com", &pkp_state));
  ASSERT_EQ(1u, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], hash2);

  state.AddHPKP("foo.example.com", expiry, false, HashValueVector(1, hash3));

  ASSERT_TRUE(state.GetDynamicPKPState("foo.example.com", &pkp_state));
  ASSERT_EQ(1u, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], hash3);
}

TEST_F(TransportSecurityStateTest, DeleteAllDynamicDataBetween) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  const base::Time older = current_time - base::Seconds(1000);

  EXPECT_FALSE(state.ShouldUpgradeToSSL("example.com"));
  EXPECT_FALSE(state.HasPublicKeyPins("example.com"));
  bool include_subdomains = false;
  state.AddHSTS("example.com", expiry, include_subdomains);
  state.AddHPKP("example.com", expiry, include_subdomains,
                GetSampleSPKIHashes());

  state.DeleteAllDynamicDataBetween(expiry, base::Time::Max(),
                                    base::DoNothing());
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.com"));
  EXPECT_TRUE(state.HasPublicKeyPins("example.com"));

  state.DeleteAllDynamicDataBetween(older, current_time, base::DoNothing());
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.com"));
  EXPECT_TRUE(state.HasPublicKeyPins("example.com"));

  state.DeleteAllDynamicDataBetween(base::Time(), current_time,
                                    base::DoNothing());
  EXPECT_TRUE(state.ShouldUpgradeToSSL("example.com"));
  EXPECT_TRUE(state.HasPublicKeyPins("example.com"));

  state.DeleteAllDynamicDataBetween(older, base::Time::Max(),
                                    base::DoNothing());
  EXPECT_FALSE(state.ShouldUpgradeToSSL("example.com"));
  EXPECT_FALSE(state.HasPublicKeyPins("example.com"));

  // Dynamic data in |state| should be empty now.
  EXPECT_FALSE(TransportSecurityState::STSStateIterator(state).HasNext());
  EXPECT_FALSE(state.has_dynamic_pkp_state());
}

TEST_F(TransportSecurityStateTest, DeleteDynamicDataForHost) {
  TransportSecurityState state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  bool include_subdomains = false;

  state.AddHSTS("example1.test", expiry, include_subdomains);
  state.AddHPKP("example1.test", expiry, include_subdomains,
                GetSampleSPKIHashes());

  EXPECT_TRUE(state.ShouldUpgradeToSSL("example1.test"));
  EXPECT_FALSE(state.ShouldUpgradeToSSL("example2.test"));
  EXPECT_TRUE(state.HasPublicKeyPins("example1.test"));
  EXPECT_FALSE(state.HasPublicKeyPins("example2.test"));

  EXPECT_TRUE(state.DeleteDynamicDataForHost("example1.test"));
  EXPECT_FALSE(state.ShouldUpgradeToSSL("example1.test"));
  EXPECT_FALSE(state.HasPublicKeyPins("example1.test"));
}

TEST_F(TransportSecurityStateTest, LongNames) {
  TransportSecurityState state;
  state.SetPinningListAlwaysTimelyForTesting(true);
  const char kLongName[] =
      "lookupByWaveIdHashAndWaveIdIdAndWaveIdDomainAndWaveletIdIdAnd"
      "WaveletIdDomainAndBlipBlipid";
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;
  // Just checks that we don't hit a NOTREACHED
  EXPECT_FALSE(state.GetStaticSTSState(kLongName, &sts_state));
  EXPECT_FALSE(state.GetStaticPKPState(kLongName, &pkp_state));
  EXPECT_FALSE(state.GetDynamicSTSState(kLongName, &sts_state));
  EXPECT_FALSE(state.GetDynamicPKPState(kLongName, &pkp_state));
}

static bool AddHash(const std::string& type_and_base64, HashValueVector* out) {
  HashValue hash;
  if (!hash.FromString(type_and_base64))
    return false;

  out->push_back(hash);
  return true;
}

TEST_F(TransportSecurityStateTest, PinValidationWithoutRejectedCerts) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  HashValueVector good_hashes, bad_hashes;

  for (size_t i = 0; kGoodPath[i]; i++) {
    EXPECT_TRUE(AddHash(kGoodPath[i], &good_hashes));
  }
  for (size_t i = 0; kBadPath[i]; i++) {
    EXPECT_TRUE(AddHash(kBadPath[i], &bad_hashes));
  }

  TransportSecurityState state;
  state.SetPinningListAlwaysTimelyForTesting(true);
  EnableStaticPins(&state);

  TransportSecurityState::PKPState pkp_state;
  EXPECT_TRUE(state.GetStaticPKPState("no-rejected-pins-pkp.preloaded.test",
                                      &pkp_state));
  EXPECT_TRUE(pkp_state.HasPublicKeyPins());

  EXPECT_TRUE(pkp_state.CheckPublicKeyPins(good_hashes));
  EXPECT_FALSE(pkp_state.CheckPublicKeyPins(bad_hashes));
}

// Simple test for the HSTS preload process. The trie (generated from
// transport_security_state_static_unittest1.json) contains 1 entry. Test that
// the lookup methods can find the entry and correctly decode the different
// preloaded states (HSTS and HPKP).
TEST_F(TransportSecurityStateTest, DecodePreloadedSingle) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  SetTransportSecurityStateSourceForTesting(&test1::kHSTSSource);

  TransportSecurityState state;
  TransportSecurityStateTest::EnableStaticPins(&state);

  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;
  EXPECT_TRUE(
      GetStaticDomainState(&state, "hsts.example.com", &sts_state, &pkp_state));
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(pkp_state.include_subdomains);
  ASSERT_EQ(1u, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], GetSampleSPKIHash(0x1));
  ASSERT_EQ(1u, pkp_state.bad_spki_hashes.size());
  EXPECT_EQ(pkp_state.bad_spki_hashes[0], GetSampleSPKIHash(0x2));
}

// More advanced test for the HSTS preload process where the trie (generated
// from transport_security_state_static_unittest2.json) contains multiple
// entries with a common prefix. Test that the lookup methods can find all
// entries and correctly decode the different preloaded states (HSTS and HPKP)
// for each entry.
TEST_F(TransportSecurityStateTest, DecodePreloadedMultiplePrefix) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  SetTransportSecurityStateSourceForTesting(&test2::kHSTSSource);

  TransportSecurityState state;
  TransportSecurityStateTest::EnableStaticPins(&state);

  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;

  EXPECT_TRUE(
      GetStaticDomainState(&state, "hsts.example.com", &sts_state, &pkp_state));
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(pkp_state == TransportSecurityState::PKPState());

  sts_state = TransportSecurityState::STSState();
  pkp_state = TransportSecurityState::PKPState();
  EXPECT_TRUE(
      GetStaticDomainState(&state, "hpkp.example.com", &sts_state, &pkp_state));
  EXPECT_TRUE(sts_state == TransportSecurityState::STSState());
  EXPECT_TRUE(pkp_state.include_subdomains);
  EXPECT_EQ(1U, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], GetSampleSPKIHash(0x1));
  EXPECT_EQ(0U, pkp_state.bad_spki_hashes.size());

  sts_state = TransportSecurityState::STSState();
  pkp_state = TransportSecurityState::PKPState();
  EXPECT_TRUE(
      GetStaticDomainState(&state, "mix.example.com", &sts_state, &pkp_state));
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(pkp_state.include_subdomains);
  EXPECT_EQ(1U, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], GetSampleSPKIHash(0x2));
  EXPECT_EQ(1U, pkp_state.bad_spki_hashes.size());
  EXPECT_EQ(pkp_state.bad_spki_hashes[0], GetSampleSPKIHash(0x1));
}

// More advanced test for the HSTS preload process where the trie (generated
// from transport_security_state_static_unittest3.json) contains a mix of
// entries. Some entries share a prefix with the prefix also having its own
// preloaded state while others share no prefix. This results in a trie with
// several different internal structures. Test that the lookup methods can find
// all entries and correctly decode the different preloaded states (HSTS and
// HPKP) for each entry.
TEST_F(TransportSecurityStateTest, DecodePreloadedMultipleMix) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      features::kStaticKeyPinningEnforcement);
  SetTransportSecurityStateSourceForTesting(&test3::kHSTSSource);

  TransportSecurityState state;
  TransportSecurityStateTest::EnableStaticPins(&state);

  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;

  EXPECT_TRUE(
      GetStaticDomainState(&state, "example.com", &sts_state, &pkp_state));
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(pkp_state == TransportSecurityState::PKPState());

  sts_state = TransportSecurityState::STSState();
  pkp_state = TransportSecurityState::PKPState();
  EXPECT_TRUE(
      GetStaticDomainState(&state, "hpkp.example.com", &sts_state, &pkp_state));
  EXPECT_TRUE(sts_state == TransportSecurityState::STSState());
  EXPECT_TRUE(pkp_state.include_subdomains);
  EXPECT_EQ(1U, pkp_state.spki_hashes.size());
  EXPECT_EQ(pkp_state.spki_hashes[0], GetSampleSPKIHash(0x1));
  EXPECT_EQ(0U, pkp_state.bad_spki_hashes.size());

  sts_state = TransportSecurityState::STSState();
  pkp_state = TransportSecurityState::PKPState();
  EXPECT_TRUE(
      GetStaticDomainState(&state, "example.org", &sts_state, &pkp_state));
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(pkp_state == TransportSecurityState::PKPState());

  sts_state = TransportSecurityState::STSState();
  pkp_state = TransportSecurityState::PKPState();
  EXPECT_TRUE(
      GetStaticDomainState(&state, "badssl.com", &sts_state, &pkp_stat
```