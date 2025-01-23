Response:
My thinking process to analyze the C++ code and answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of `mapped_host_resolver_unittest.cc`, its relation to JavaScript, logical reasoning examples, common user errors, and debugging steps.

2. **High-Level Overview:** I first scanned the `#include` directives. Keywords like `gtest`, `MockHostResolver`, `AddressList`, `HostPortPair`, `NetworkAnonymizationKey`, and `MappedHostResolver` immediately suggest this is a unit test file for a component related to DNS resolution and host mapping within the Chromium networking stack. The filename itself is a strong indicator.

3. **Identify Key Classes and Functionality:** I focused on the core class being tested: `MappedHostResolver`. The tests use `MockHostResolver` to simulate different DNS resolution scenarios. The key functionality being tested revolves around adding and applying rules for mapping hostnames to other hostnames, IP addresses, or errors.

4. **Analyze Individual Test Cases:** I went through each `TEST_F` block (although they are just `TEST` in this file, indicating no shared fixture). For each test:
    * I identified the core scenario being tested (e.g., basic inclusion/mapping, mapping with schemes, exclusion rules, error mapping).
    * I looked for the `AddRuleFromString` calls, as these define the mapping rules.
    * I noted the expected outcome of the `resolver->CreateRequest` calls after the rules are applied. The `EXPECT_THAT` assertions are crucial here.
    * I paid attention to the `HostPortPair` and `url::SchemeHostPort` usage, indicating how hostnames and ports are handled.

5. **Relate to JavaScript (if applicable):**  I considered how DNS resolution and host mapping might manifest in a web browser's interaction with JavaScript. Key areas are:
    * **Fetching resources:**  `fetch()`, `XMLHttpRequest`, `<img>` tags, `<script>` tags all trigger network requests that rely on DNS.
    * **URL manipulation:**  JavaScript can construct URLs, and the browser's underlying network stack (where `MappedHostResolver` lives) handles the resolution.
    * **Service Workers:** These can intercept network requests and potentially be affected by host mapping.

6. **Construct Logical Reasoning Examples:** For the `Inclusion` test as a base, I created examples of input (the mapping rule and the hostname being resolved) and output (the resolved IP address and port). This demonstrates the core mapping logic.

7. **Identify Potential User/Programming Errors:** I thought about common mistakes users or developers might make when dealing with host mapping:
    * **Incorrect rule syntax:** Misspelling keywords, incorrect delimiters, etc.
    * **Overlapping rules:** Defining conflicting mapping rules.
    * **Case sensitivity:**  While the code canonicalizes hostnames, it's a potential point of confusion.
    * **Forgetting to set up the underlying resolver:** `MappedHostResolver` relies on another resolver.

8. **Trace User Operations to Reach the Code:** I considered the steps a user might take that would eventually involve the DNS resolution process:
    * Typing a URL in the address bar.
    * Clicking a link.
    * A website making requests for resources (images, scripts, etc.).
    * A browser extension interacting with the network.

9. **Structure the Answer:** I organized my findings into the categories requested: functionality, relation to JavaScript, logical reasoning, user errors, and debugging steps. I used clear and concise language.

10. **Refine and Review:** I reread my answer to ensure accuracy, completeness, and clarity. I double-checked the code snippets and made sure the examples were relevant. I made sure to connect the C++ code's actions to the user's experience.

Essentially, I approached this like reverse engineering the purpose of the code by examining its tests and then extrapolating how that functionality fits into the broader context of a web browser and its interaction with web content. The test cases were the primary source of truth about what the `MappedHostResolver` is designed to do.
这个文件 `net/dns/mapped_host_resolver_unittest.cc` 是 Chromium 网络栈中 `MappedHostResolver` 类的单元测试文件。它的主要功能是：

**1. 测试 MappedHostResolver 的核心功能：**

   - **主机名映射 (Mapping):** 验证 `MappedHostResolver` 能否根据预定义的规则将一个主机名映射到另一个主机名、IP 地址或 IP 地址和端口的组合。
   - **排除规则 (Exclusion):** 测试 `MappedHostResolver` 是否能正确地排除特定的主机名，即使它们符合映射规则。
   - **错误映射 (Mapping to Error):**  验证 `MappedHostResolver` 是否可以将某些主机名映射到一个特定的 DNS 解析错误，例如 `ERR_NAME_NOT_RESOLVED`。
   - **处理带有 scheme 的主机名:** 测试当提供带有 scheme (例如 "http://", "https://") 的主机名时，映射规则是否仍然生效。
   - **设置规则:** 验证通过字符串设置映射规则的功能 (`SetRulesFromString`, `AddRuleFromString`)。
   - **处理无效规则:** 测试当提供无效的映射规则时，`MappedHostResolver` 是否能够正确处理而不会崩溃。

**2. 验证 MappedHostResolver 与底层 HostResolver 的交互:**

   - 通过使用 `MockHostResolver` 模拟底层的 DNS 解析器，测试 `MappedHostResolver` 如何在其基础上进行映射和排除操作。

**与 JavaScript 功能的关系 (以及举例说明):**

`MappedHostResolver` 位于浏览器网络栈的底层，它影响着浏览器如何解析域名。当 JavaScript 代码发起网络请求时（例如使用 `fetch()` API、`XMLHttpRequest` 对象、或者加载图片/脚本等资源时），浏览器会使用底层的 DNS 解析器来获取目标服务器的 IP 地址。`MappedHostResolver` 的作用就是在这一步介入，根据预设的规则修改或替换原本的域名解析结果。

**举例说明:**

假设你在 Chrome 浏览器中启用了某些网络调试功能或者使用了特定的代理扩展，这些功能可能会使用 `MappedHostResolver` 来修改域名解析的行为。

- **场景 1：本地开发环境映射**

  你正在本地开发一个网站，域名是 `local.dev`。你可能希望将所有对 `local.dev` 的请求都指向本地的服务器 `127.0.0.1:8080`。可以通过某种配置（例如 Chrome 的 DevTools 中的 Network overrides，或者某些代理工具）设置一个映射规则，使得浏览器在解析 `local.dev` 时，实际使用的是 `127.0.0.1`。

  **JavaScript 代码:**
  ```javascript
  fetch('http://local.dev/api/data')
    .then(response => response.json())
    .then(data => console.log(data));
  ```

  **MappedHostResolver 的作用:** 当浏览器尝试解析 `local.dev` 时，`MappedHostResolver` 会将它映射到 `127.0.0.1:8080`，从而让 `fetch()` 请求发送到你的本地服务器。

- **场景 2：阻止特定域名的请求**

  某些浏览器扩展可能会使用域名映射来阻止广告或追踪器。例如，可以设置一个映射规则，将已知的广告域名映射到一个无法解析的地址或错误，从而阻止浏览器加载这些域名的资源。

  **JavaScript 代码 (例如页面尝试加载广告):**
  ```html
  <img src="https://ad.example.com/banner.png">
  ```

  **MappedHostResolver 的作用:**  如果设置了将 `ad.example.com` 映射到错误 (例如 `^NOTFOUND`) 的规则，浏览器在解析 `ad.example.com` 时会得到一个解析失败的错误，从而阻止图片的加载。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

- **映射规则:** `map *.example.com test.local`
- **解析请求:** `www.example.com:80`

**输出 1:**

- 实际解析的主机名将变为 `test.local:80`。
- 底层的 `MockHostResolver` 会解析 `test.local` 并返回其对应的 IP 地址。

**假设输入 2:**

- **映射规则:** `map api.staging.com 192.168.1.100:3000`
- **解析请求:** `api.staging.com:443`

**输出 2:**

- 实际解析的主机名和端口将变为 `192.168.1.100:3000`。
- 如果 `192.168.1.100` 是一个有效的 IP 地址，解析将成功。

**假设输入 3:**

- **映射规则:** `exclude tracker.analytics.net`
- **解析请求:** `tracker.analytics.net`

**输出 3:**

- 即使有其他通配符的映射规则可能匹配 `tracker.analytics.net`，由于排除了该域名，浏览器会直接使用底层的 `MockHostResolver` 来解析 `tracker.analytics.net`。

**涉及用户或编程常见的使用错误 (举例说明):**

1. **错误的规则语法:**

   - **错误示例:** `mispell map example.com target.com` (关键字 "map" 拼写错误)
   - **后果:** `MappedHostResolver` 无法解析该规则，该规则将被忽略，预期的映射不会发生。

2. **规则冲突:**

   - **错误示例:**
     ```
     map *.example.com test1.local
     map www.example.com test2.local
     ```
   - **后果:**  `MappedHostResolver` 通常会按照规则添加的顺序处理，后添加的规则可能会覆盖之前的规则。用户可能期望 `www.example.com` 被映射到 `test2.local`，但如果通配符规则先被匹配，则可能被映射到 `test1.local`。

3. **忘记考虑端口:**

   - **错误示例:**  `map api.example.com 192.168.1.100` (没有指定端口)
   - **后果:**  如果请求的端口不是默认的 80 或 443，映射可能不会按预期工作，或者需要依赖底层解析器对该 IP 地址的默认端口处理。

4. **大小写敏感性混淆:**

   - **说明:** 虽然域名本身通常是不区分大小写的，但映射规则的定义和匹配可能存在大小写敏感性问题，具体取决于 `MappedHostResolver` 的实现细节。用户可能会错误地认为 `MAP example.com ...` 和 `map EXAMPLE.COM ...` 是等价的。

**用户操作是如何一步步的到达这里 (作为调试线索):**

作为一个开发者，要调试涉及到 `MappedHostResolver` 的问题，可能需要以下步骤：

1. **配置映射规则:** 用户（通常是开发者或使用了特定工具的用户）会通过某种方式配置 `MappedHostResolver` 的规则。这可能发生在：
   - **Chrome DevTools 的 Network overrides 功能:**  用户在 DevTools 中设置了本地替换规则，将某些在线资源映射到本地文件或不同的域名。
   - **使用带有 host mapping 功能的代理工具:** 例如 Fiddler、Charles 等，这些工具允许用户修改 DNS 解析结果。
   - **通过 Chrome 扩展程序:** 某些扩展程序可能会使用 Chrome 提供的 API 来修改网络请求的行为，包括 DNS 解析。
   - **在测试环境或自动化测试中:**  开发者可能会在集成测试或端到端测试中配置 `MappedHostResolver` 以模拟特定的网络环境。

2. **发起网络请求:** 用户或应用程序会发起一个网络请求，例如：
   - **在浏览器地址栏中输入 URL 并访问。**
   - **网页上的 JavaScript 代码发起 `fetch()` 或 `XMLHttpRequest` 请求。**
   - **加载网页上的图片、脚本、CSS 等资源。**

3. **MappedHostResolver 介入:** 当浏览器需要解析请求中的域名时，`MappedHostResolver` 会检查是否有匹配的映射规则。

4. **规则匹配和修改:** 如果找到了匹配的规则，`MappedHostResolver` 会修改原始的域名解析请求，将其替换为映射的目标主机名、IP 地址或错误。

5. **底层 HostResolver 处理:** 修改后的请求会被传递给底层的 `HostResolver` (在测试中是 `MockHostResolver`) 进行实际的 DNS 解析。

6. **返回结果:**  `HostResolver` 返回解析结果 (IP 地址或错误)，浏览器使用这个结果来建立网络连接。

**调试线索:**

- **检查 Chrome DevTools 的 Network 面板:** 查看请求的详细信息，特别是 "Initiator" (发起者) 和 "Timing" (时间线) 标签，可能会显示请求是否被重定向或因为 DNS 解析失败而延迟。
- **使用 `chrome://net-internals/#dns`:**  查看 Chrome 的内部 DNS 缓存和解析日志，可以帮助理解域名解析的过程和结果。
- **检查代理设置和扩展程序:** 确认是否有活动的代理或扩展程序正在修改 DNS 解析行为。
- **查看测试代码和配置:** 如果是在开发或测试环境中，检查相关的测试代码和配置文件，确认是否设置了预期的映射规则。
- **使用网络抓包工具 (如 Wireshark):**  捕获网络请求，查看实际发送的 DNS 查询和响应，以及建立的 TCP 连接的目标 IP 地址。

总之，`mapped_host_resolver_unittest.cc` 是理解 `MappedHostResolver` 工作原理的关键，它通过各种测试用例展示了该类如何处理不同的映射和排除规则，以及如何与底层的 DNS 解析器协同工作。 理解这些测试用例对于调试与域名映射相关的问题至关重要。

### 提示词
```
这是目录为net/dns/mapped_host_resolver_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/mapped_host_resolver.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/test/task_environment.h"
#include "net/base/address_list.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_isolation_key.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/net_log_with_source.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

std::string FirstAddress(const AddressList& address_list) {
  if (address_list.empty())
    return std::string();
  return address_list.front().ToString();
}

TEST(MappedHostResolverTest, Inclusion) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddSimulatedFailure("*google.com");
  resolver_impl->rules()->AddRule("baz.com", "192.168.1.5");
  resolver_impl->rules()->AddRule("foo.com", "192.168.1.8");
  resolver_impl->rules()->AddRule("proxy", "192.168.1.11");

  // Create a remapped resolver that uses |resolver_impl|.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));

  // Try resolving "www.google.com:80". There are no mappings yet, so this
  // hits |resolver_impl| and fails.
  TestCompletionCallback callback;
  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(HostPortPair("www.google.com", 80),
                              NetworkAnonymizationKey(), NetLogWithSource(),
                              std::nullopt);
  int rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_FALSE(request->GetAddressResults());

  // Remap *.google.com to baz.com.
  EXPECT_TRUE(resolver->AddRuleFromString("map *.google.com baz.com"));
  request.reset();

  // Try resolving "www.google.com:80". Should be remapped to "baz.com:80".
  request = resolver->CreateRequest(HostPortPair("www.google.com", 80),
                                    NetworkAnonymizationKey(),
                                    NetLogWithSource(), std::nullopt);
  rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.5:80", FirstAddress(*request->GetAddressResults()));
  request.reset();

  // Try resolving "foo.com:77". This will NOT be remapped, so result
  // is "foo.com:77".
  request = resolver->CreateRequest(HostPortPair("foo.com", 77),
                                    NetworkAnonymizationKey(),
                                    NetLogWithSource(), std::nullopt);
  rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.8:77", FirstAddress(*request->GetAddressResults()));
  request.reset();

  // Remap "*.org" to "proxy:99".
  EXPECT_TRUE(resolver->AddRuleFromString("Map *.org proxy:99"));

  // Try resolving "chromium.org:61". Should be remapped to "proxy:99".
  request = resolver->CreateRequest(HostPortPair("chromium.org", 61),
                                    NetworkAnonymizationKey(),
                                    NetLogWithSource(), std::nullopt);
  rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.11:99", FirstAddress(*request->GetAddressResults()));
}

TEST(MappedHostResolverTest, MapsHostWithScheme) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("remapped.test", "192.168.1.22");

  // Create a remapped resolver that uses `resolver_impl`.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));
  ASSERT_TRUE(resolver->AddRuleFromString("MAP to.map.test remapped.test"));

  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(
          url::SchemeHostPort(url::kHttpScheme, "to.map.test", 155),
          NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt);

  TestCompletionCallback callback;
  int rv = request->Start(callback.callback());

  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_THAT(
      request->GetAddressResults()->endpoints(),
      testing::ElementsAre(IPEndPoint(IPAddress(192, 168, 1, 22), 155)));
}

TEST(MappedHostResolverTest, MapsHostWithSchemeToIpLiteral) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("host.test", "192.168.1.22");

  // Create a remapped resolver that uses `resolver_impl`.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));
  ASSERT_TRUE(resolver->AddRuleFromString("MAP host.test [1234:5678::000A]"));

  IPAddress expected_address;
  ASSERT_TRUE(expected_address.AssignFromIPLiteral("1234:5678::000A"));

  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(
          url::SchemeHostPort(url::kHttpScheme, "host.test", 156),
          NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt);

  TestCompletionCallback callback;
  int rv = request->Start(callback.callback());

  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_THAT(request->GetAddressResults()->endpoints(),
              testing::ElementsAre(IPEndPoint(expected_address, 156)));
}

// Tests that remapped URL gets canonicalized when passing scheme.
TEST(MappedHostResolverTest, MapsHostWithSchemeToNonCanon) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("remapped.test", "192.168.1.23");

  // Create a remapped resolver that uses `resolver_impl`.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));
  ASSERT_TRUE(resolver->AddRuleFromString("MAP host.test reMapped.TEST"));

  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(
          url::SchemeHostPort(url::kHttpScheme, "host.test", 157),
          NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt);

  TestCompletionCallback callback;
  int rv = request->Start(callback.callback());

  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_THAT(
      request->GetAddressResults()->endpoints(),
      testing::ElementsAre(IPEndPoint(IPAddress(192, 168, 1, 23), 157)));
}

TEST(MappedHostResolverTest, MapsHostWithSchemeToNameWithPort) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("remapped.test", "192.168.1.24");

  // Create a remapped resolver that uses `resolver_impl`.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));
  ASSERT_TRUE(resolver->AddRuleFromString("MAP host.test remapped.test:258"));

  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(
          url::SchemeHostPort(url::kHttpScheme, "host.test", 158),
          NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt);

  TestCompletionCallback callback;
  int rv = request->Start(callback.callback());

  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_THAT(
      request->GetAddressResults()->endpoints(),
      testing::ElementsAre(IPEndPoint(IPAddress(192, 168, 1, 24), 258)));
}

TEST(MappedHostResolverTest, HandlesUnmappedHostWithScheme) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("unmapped.test", "192.168.1.23");

  // Create a remapped resolver that uses `resolver_impl`.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));

  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(
          url::SchemeHostPort(url::kHttpsScheme, "unmapped.test", 155),
          NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt);

  TestCompletionCallback callback;
  int rv = request->Start(callback.callback());

  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_THAT(
      request->GetAddressResults()->endpoints(),
      testing::ElementsAre(IPEndPoint(IPAddress(192, 168, 1, 23), 155)));
}

// Tests that exclusions are respected.
TEST(MappedHostResolverTest, Exclusion) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("baz", "192.168.1.5");
  resolver_impl->rules()->AddRule("www.google.com", "192.168.1.3");

  // Create a remapped resolver that uses |resolver_impl|.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));

  TestCompletionCallback callback;

  // Remap "*.com" to "baz".
  EXPECT_TRUE(resolver->AddRuleFromString("map *.com baz"));

  // Add an exclusion for "*.google.com".
  EXPECT_TRUE(resolver->AddRuleFromString("EXCLUDE *.google.com"));

  // Try resolving "www.google.com". Should not be remapped due to exclusion).
  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(HostPortPair("www.google.com", 80),
                              NetworkAnonymizationKey(), NetLogWithSource(),
                              std::nullopt);
  int rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.3:80", FirstAddress(*request->GetAddressResults()));
  request.reset();

  // Try resolving "chrome.com:80". Should be remapped to "baz:80".
  request = resolver->CreateRequest(HostPortPair("chrome.com", 80),
                                    NetworkAnonymizationKey(),
                                    NetLogWithSource(), std::nullopt);
  rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.5:80", FirstAddress(*request->GetAddressResults()));
}

TEST(MappedHostResolverTest, SetRulesFromString) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("baz", "192.168.1.7");
  resolver_impl->rules()->AddRule("bar", "192.168.1.9");

  // Create a remapped resolver that uses |resolver_impl|.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));

  TestCompletionCallback callback;

  // Remap "*.com" to "baz", and *.net to "bar:60".
  resolver->SetRulesFromString("map *.com baz , map *.net bar:60");

  // Try resolving "www.google.com". Should be remapped to "baz".
  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(HostPortPair("www.google.com", 80),
                              NetworkAnonymizationKey(), NetLogWithSource(),
                              std::nullopt);
  int rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.7:80", FirstAddress(*request->GetAddressResults()));
  request.reset();

  // Try resolving "chrome.net:80". Should be remapped to "bar:60".
  request = resolver->CreateRequest(HostPortPair("chrome.net", 80),
                                    NetworkAnonymizationKey(),
                                    NetLogWithSource(), std::nullopt);
  rv = request->Start(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.9:60", FirstAddress(*request->GetAddressResults()));
}

// Parsing bad rules should silently discard the rule (and never crash).
TEST(MappedHostResolverTest, ParseInvalidRules) {
  base::test::TaskEnvironment task_environment;

  auto resolver =
      std::make_unique<MappedHostResolver>(std::unique_ptr<HostResolver>());

  EXPECT_FALSE(resolver->AddRuleFromString("xyz"));
  EXPECT_FALSE(resolver->AddRuleFromString(std::string()));
  EXPECT_FALSE(resolver->AddRuleFromString(" "));
  EXPECT_FALSE(resolver->AddRuleFromString("EXCLUDE"));
  EXPECT_FALSE(resolver->AddRuleFromString("EXCLUDE foo bar"));
  EXPECT_FALSE(resolver->AddRuleFromString("INCLUDE"));
  EXPECT_FALSE(resolver->AddRuleFromString("INCLUDE x"));
  EXPECT_FALSE(resolver->AddRuleFromString("INCLUDE x :10"));
}

// Test mapping hostnames to resolving failures.
TEST(MappedHostResolverTest, MapToError) {
  base::test::TaskEnvironment task_environment;

  // Outstanding request.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("*", "192.168.1.5");

  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));

  // Remap *.google.com to resolving failures.
  EXPECT_TRUE(resolver->AddRuleFromString("MAP *.google.com ^NOTFOUND"));

  // Try resolving www.google.com --> Should give an error.
  TestCompletionCallback callback1;
  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(HostPortPair("www.google.com", 80),
                              NetworkAnonymizationKey(), NetLogWithSource(),
                              std::nullopt);
  int rv = request->Start(callback1.callback());
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));
  request.reset();

  // Try resolving www.foo.com --> Should succeed.
  TestCompletionCallback callback2;
  request = resolver->CreateRequest(HostPortPair("www.foo.com", 80),
                                    NetworkAnonymizationKey(),
                                    NetLogWithSource(), std::nullopt);
  rv = request->Start(callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("192.168.1.5:80", FirstAddress(*request->GetAddressResults()));
}

TEST(MappedHostResolverTest, MapHostWithSchemeToError) {
  base::test::TaskEnvironment task_environment;

  // Create a mock host resolver, with specific hostname to IP mappings.
  auto resolver_impl = std::make_unique<MockHostResolver>();
  resolver_impl->rules()->AddRule("host.test", "192.168.1.25");

  // Create a remapped resolver that uses `resolver_impl`.
  auto resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver_impl));
  ASSERT_TRUE(resolver->AddRuleFromString("MAP host.test ^NOTFOUND"));

  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      resolver->CreateRequest(
          url::SchemeHostPort(url::kWssScheme, "host.test", 155),
          NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt);

  TestCompletionCallback callback;
  int rv = request->Start(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_NAME_NOT_RESOLVED));
}

}  // namespace

}  // namespace net
```