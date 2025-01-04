Response:
The user wants a summary of the provided C++ code, specifically the `net/dns/dns_config_service_linux_unittest.cc` file from the Chromium project.

Here's a breakdown of the request and how to address it:

1. **List the functionalities:** This requires analyzing the code and identifying the main purpose of the tests. Key elements to look for are the classes being tested (`DnsConfigServiceLinux`), the types of tests being performed (unit tests), and the aspects of the class being verified (reading DNS configurations, handling different `resolv.conf` and `nsswitch.conf` scenarios).

2. **Relationship with JavaScript:**  Consider how DNS configuration affects web browsing. JavaScript running in a browser needs to resolve domain names, which relies on the underlying OS DNS settings. The tests indirectly relate to this by ensuring the code that reads and interprets these settings is correct.

3. **Logical inference (input/output):** Some tests simulate specific input conditions (e.g., a `resolv.conf` with specific nameservers) and verify the output (`DnsConfig` object). Identify such cases and provide examples.

4. **Common user/programming errors:**  Think about what could go wrong when dealing with DNS configuration. Incorrectly formatted configuration files, missing entries, or unexpected values are potential errors.

5. **User operations leading to this code:**  Consider the user's journey when their browser interacts with DNS settings. This involves the browser starting up, potentially reading local DNS configurations, and then using these settings to resolve hostnames for web requests.

6. **Debugging clues:**  If something goes wrong with DNS resolution in the browser, understanding how the browser reads and interprets the configuration is essential for debugging. This code provides insights into that process.

7. **Overall summary:** Condense the above points into a concise summary of the file's purpose.

**Mental Sandbox:**

* **Focus on the `TEST_F` macros:**  These define individual test cases. Each test focuses on a specific aspect of the `DnsConfigServiceLinux` class.
* **Look for helper functions:** Functions like `InitializeResState` and `InitializeExpectedConfig` set up test conditions and expected outcomes.
* **Identify the tested scenarios:**  The tests cover various valid and invalid configurations of `resolv.conf` and `nsswitch.conf`.
* **Relate to browser functionality:**  Remember that this code is part of the network stack, which is crucial for the browser's ability to access websites.

**High-level plan:**

1. Identify the main purpose: unit testing `DnsConfigServiceLinux`.
2. List specific test scenarios: reading valid configurations, handling empty nameservers, various `nsswitch.conf` configurations.
3. Connect to JavaScript: DNS resolution is essential for web browsing.
4. Provide input/output examples based on test cases.
5. List common errors related to DNS configuration.
6. Describe the user path leading to DNS configuration usage.
7. Summarize the file's role in verifying DNS configuration reading.
这是对 Chromium 网络栈中 `net/dns/dns_config_service_linux_unittest.cc` 文件的功能进行分析。

**功能归纳 (第 1 部分):**

该文件包含了 `DnsConfigServiceLinux` 类的单元测试。`DnsConfigServiceLinux` 负责在 Linux 平台上读取和解析系统的 DNS 配置信息，例如 nameservers、search domains 等。

**具体功能列表:**

1. **测试 `DnsConfigServiceLinux` 实例的创建和销毁:** 验证在不调用 `WatchConfig()` 的情况下，实例的正常销毁，防止内存泄漏或崩溃。
2. **测试将 `res_state` 结构体转换为 `DnsConfig` 对象:**  `res_state` 是 Linux 系统中用于表示 DNS 配置的结构体。该测试验证了 `DnsConfigServiceLinux` 能正确地将系统 `res_state` 结构体中的信息提取并转换为 Chromium 内部使用的 `DnsConfig` 对象。
3. **测试处理无效的 nameserver 地址:** 验证当 `resolv.conf` 中存在空的或无效的 nameserver 地址时，`DnsConfigServiceLinux` 的处理逻辑。
4. **测试处理有效的 nameserver 地址:** 验证当 `resolv.conf` 中存在有效的 nameserver 地址时，`DnsConfigServiceLinux` 能正确解析。
5. **测试在后台任务仍在执行时销毁 `DnsConfigServiceLinux` 实例:** 验证在后台线程池中存在未完成的任务时，实例的正常销毁，防止崩溃。
6. **测试在不同线程销毁 `DnsConfigServiceLinux` 实例:** 验证在创建实例的线程之外的线程销毁实例时的安全性。
7. **测试接受基本的 `nsswitch.conf` 配置:** 验证当 `nsswitch.conf` 文件配置为使用 "files" 和 "dns" 服务进行主机名解析时，`DnsConfigServiceLinux` 能正确处理。
8. **测试当 `resolv.conf` 中存在未处理的选项时忽略基本的 `nsswitch.conf` 配置:**  验证当 `resolv.conf` 中包含 `DnsConfigServiceLinux` 无法处理的选项时，`nsswitch.conf` 的基本配置会被忽略。
9. **测试拒绝不包含 "files" 服务的 `nsswitch.conf` 配置:**  验证 `nsswitch.conf` 必须包含 "files" 服务才能被接受。
10. **测试拒绝包含额外 "files" 服务的 `nsswitch.conf` 配置:** 验证 `nsswitch.conf` 中只能有一个 "files" 服务。
11. **测试忽略 `nsswitch.conf` 中冗余的 action 配置:** 验证当 `nsswitch.conf` 中存在重复的 action 设置时，`DnsConfigServiceLinux` 能正确处理。
12. **测试拒绝 `nsswitch.conf` 中不一致的 action 配置:** 验证当 `nsswitch.conf` 中 action 设置相互冲突时，`DnsConfigServiceLinux` 能正确识别并拒绝。
13. **测试拒绝 "files" 服务中包含错误的 success action 的 `nsswitch.conf` 配置:** 验证 "files" 服务的 success action 必须是默认的 continue 行为。
14. **测试拒绝 "files" 服务中包含错误的 notfound action 的 `nsswitch.conf` 配置:** 验证 "files" 服务的 notfound action 必须是默认的 continue 行为。
15. **测试拒绝不包含 "dns" 服务的 `nsswitch.conf` 配置:** 验证 `nsswitch.conf` 必须包含 "dns" 服务才能被接受。
16. **测试拒绝 "dns" 服务中包含错误的 success action 的 `nsswitch.conf` 配置:** 验证 "dns" 服务的 success action 必须是默认的 return 行为。
17. **测试拒绝服务顺序错误的 `nsswitch.conf` 配置:** 验证 "files" 服务必须在 "dns" 服务之前。
18. **测试接受 "dns" 服务之后存在不兼容的 `nsswitch.conf` 服务:** 验证在 "dns" 服务之后出现例如 "mdns" 等服务时，`DnsConfigServiceLinux` 的处理。
19. **测试拒绝包含 "mdns" 服务的 `nsswitch.conf` 配置:**  验证默认情况下不接受 "mdns" 服务。
20. **测试拒绝包含 "mdns4" 服务的 `nsswitch.conf` 配置。**
21. **测试拒绝包含 "mdns6" 服务的 `nsswitch.conf` 配置。**
22. **测试接受包含 "mdns_minimal", "mdns4_minimal", "mdns6_minimal" 服务的 `nsswitch.conf` 配置:**  验证可以接受用于最小化多播 DNS 查询的服务。
23. **测试接受包含 "mdns_minimal" 等服务以及常见 action 配置的 `nsswitch.conf`:** 验证可以接受例如 `[!UNAVAIL=RETURN]` 或 `[NOTFOUND=RETURN]` 这样的 action 配置。
24. **测试拒绝 "mdns_minimal" 服务中包含错误的 unavailable action 的 `nsswitch.conf` 配置。**
25. **测试接受包含 "myhostname" 服务的 `nsswitch.conf` 配置:** 验证可以接受 "myhostname" 服务。
26. **测试拒绝 "myhostname" 服务中包含错误的 notfound action 的 `nsswitch.conf` 配置。**
27. **测试拒绝包含 "resolve" 服务的 `nsswitch.conf` 配置。**
28. **测试拒绝包含 "nis" 服务的 `nsswitch.conf` 配置。**
29. **测试拒绝 "nis" 服务中包含错误的 notfound action 的 `nsswitch.conf` 配置。**
30. **测试拒绝包含未知服务的 `nsswitch.conf` 配置。**

**与 Javascript 的关系:**

虽然这段 C++ 代码本身不是 Javascript，但它负责读取操作系统底层的 DNS 配置。这些配置直接影响到浏览器中 Javascript 代码的网络请求行为。

**举例说明:**

假设一个网页的 Javascript 代码需要访问 `example.com`。

1. **用户操作:** 用户在浏览器地址栏输入 `example.com` 并回车。
2. **浏览器行为:** 浏览器会尝试解析 `example.com` 的 IP 地址。
3. **底层调用:** 浏览器网络栈会调用 `DnsConfigServiceLinux` 来获取系统 DNS 配置，例如 nameservers。
4. **`DnsConfigServiceLinux` 的工作:**  `DnsConfigServiceLinux` 读取 `/etc/resolv.conf` 和 `/etc/nsswitch.conf` 等文件，解析出 nameserver 地址。
5. **DNS 查询:** 浏览器使用解析出的 nameserver 地址向 DNS 服务器发送查询请求，获取 `example.com` 的 IP 地址。
6. **Javascript 的作用:** 一旦浏览器获取到 `example.com` 的 IP 地址，Javascript 代码才能向该 IP 地址发起 HTTP 请求，获取网页内容。

**逻辑推理 (假设输入与输出):**

**假设输入 (模拟 `resolv.conf` 内容):**

```
nameserver 8.8.8.8
nameserver 192.168.1.1
search example.com chromium.org
options ndots:2
```

**预期输出 (部分 `DnsConfig` 内容):**

```
config->nameservers = [IPAddress("8.8.8.8"), IPAddress("192.168.1.1")]
config->search = ["example.com", "chromium.org"]
config->ndots = 2
```

**用户或编程常见的使用错误:**

1. **错误的 `resolv.conf` 格式:** 用户手动编辑 `/etc/resolv.conf` 时可能输入错误的语法，例如拼写错误的关键字 (如 `nameserverr`) 或无效的 IP 地址。这会导致 `DnsConfigServiceLinux` 解析失败。
   * **例子:**  将 `nameserver 8.8.8.8` 错误地写成 `namesrver 8.8.8.8`。
2. **缺少必要的 `nsswitch.conf` 配置:** 如果 `/etc/nsswitch.conf` 文件中缺少 `hosts: files dns` 的配置，或者配置顺序错误，`DnsConfigServiceLinux` 可能无法正确判断如何进行主机名解析。
   * **例子:** `/etc/nsswitch.conf` 中只包含 `hosts: files`，缺少 `dns`。
3. **权限问题:**  运行 Chromium 的用户可能没有读取 `/etc/resolv.conf` 或 `/etc/nsswitch.conf` 的权限，导致 `DnsConfigServiceLinux` 无法获取配置信息。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户启动 Chromium 浏览器:**  在浏览器启动过程中，网络栈会被初始化。
2. **网络栈初始化:** `DnsConfigServiceLinux` 作为 DNS 配置服务的一部分被创建。
3. **首次 DNS 查询或配置监听:**  当浏览器需要解析域名 (例如用户访问一个新网站) 或者某些功能需要监听 DNS 配置变化时，会触发 `DnsConfigServiceLinux::ReadConfig` 或 `DnsConfigServiceLinux::WatchConfig` 方法。
4. **读取配置文件:** `DnsConfigServiceLinux` 内部会调用 `ResolvReader` 和 `NsswitchReader` 来读取 `/etc/resolv.conf` 和 `/etc/nsswitch.conf` 的内容。
5. **解析配置:**  读取到的内容会被解析并转换为 `DnsConfig` 对象。
6. **应用于网络请求:** 解析后的 `DnsConfig` 对象会被用于后续的网络请求，例如确定使用哪些 DNS 服务器进行域名解析。

如果在调试过程中发现 DNS 解析出现问题，例如浏览器无法访问某些网站，那么可以考虑以下调试线索，并可能涉及到 `DnsConfigServiceLinux` 的代码：

* **检查 `/etc/resolv.conf` 和 `/etc/nsswitch.conf` 的内容和格式是否正确。**
* **确认运行 Chromium 的用户是否有权限读取这些配置文件。**
* **使用 Chromium 提供的内部网络工具 (例如 `net-internals`) 查看 DNS 查询过程和配置信息。**
* **如果怀疑是 `DnsConfigServiceLinux` 的解析逻辑问题，可以查看相关的单元测试 (即当前文件) 来了解其处理各种配置的预期行为。**

总而言之， `net/dns/dns_config_service_linux_unittest.cc` 文件通过大量的单元测试，确保 `DnsConfigServiceLinux` 类能够正确可靠地读取和解析 Linux 系统上的 DNS 配置信息，这是 Chromium 浏览器正常进行网络通信的基础。

Prompt: 
```
这是目录为net/dns/dns_config_service_linux_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/dns/dns_config_service_linux.h"

#include <arpa/inet.h>
#include <resolv.h>

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "base/cancelable_callback.h"
#include "base/check.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/sys_byteorder.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/task_environment.h"
#include "base/test/test_waitable_event.h"
#include "net/base/ip_address.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_config_service.h"
#include "net/dns/nsswitch_reader.h"
#include "net/dns/public/dns_protocol.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// MAXNS is normally 3, but let's test 4 if possible.
const char* const kNameserversIPv4[] = {
    "8.8.8.8",
    "192.168.1.1",
    "63.1.2.4",
    "1.0.0.1",
};

const char* const kNameserversIPv6[] = {
    nullptr,
    "2001:db8::42",
    nullptr,
    "::FFFF:129.144.52.38",
};

const std::vector<NsswitchReader::ServiceSpecification> kBasicNsswitchConfig = {
    NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
    NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)};

void DummyConfigCallback(const DnsConfig& config) {
  // Do nothing
}

// Fills in |res| with sane configuration.
void InitializeResState(res_state res) {
  memset(res, 0, sizeof(*res));
  res->options =
      RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH | RES_ROTATE;
  res->ndots = 2;
  res->retrans = 4;
  res->retry = 7;

  const char kDnsrch[] =
      "chromium.org"
      "\0"
      "example.com";
  memcpy(res->defdname, kDnsrch, sizeof(kDnsrch));
  res->dnsrch[0] = res->defdname;
  res->dnsrch[1] = res->defdname + sizeof("chromium.org");

  for (unsigned i = 0; i < std::size(kNameserversIPv4) && i < MAXNS; ++i) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = base::HostToNet16(NS_DEFAULTPORT + i);
    inet_pton(AF_INET, kNameserversIPv4[i], &sa.sin_addr);
    res->nsaddr_list[i] = sa;
    ++res->nscount;
  }

  // Install IPv6 addresses, replacing the corresponding IPv4 addresses.
  unsigned nscount6 = 0;
  for (unsigned i = 0; i < std::size(kNameserversIPv6) && i < MAXNS; ++i) {
    if (!kNameserversIPv6[i])
      continue;
    // Must use malloc to mimic res_ninit. Expect to be freed in
    // `TestResolvReader::CloseResState()`.
    struct sockaddr_in6* sa6;
    sa6 = static_cast<sockaddr_in6*>(malloc(sizeof(*sa6)));
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = base::HostToNet16(NS_DEFAULTPORT - i);
    inet_pton(AF_INET6, kNameserversIPv6[i], &sa6->sin6_addr);
    res->_u._ext.nsaddrs[i] = sa6;
    memset(&res->nsaddr_list[i], 0, sizeof res->nsaddr_list[i]);
    ++nscount6;
  }
  res->_u._ext.nscount6 = nscount6;
}

void InitializeExpectedConfig(DnsConfig* config) {
  config->ndots = 2;
  config->fallback_period = kDnsDefaultFallbackPeriod;
  config->attempts = 7;
  config->rotate = true;
  config->append_to_multi_label_name = true;
  config->search.clear();
  config->search.push_back("chromium.org");
  config->search.push_back("example.com");

  config->nameservers.clear();
  for (unsigned i = 0; i < std::size(kNameserversIPv4) && i < MAXNS; ++i) {
    IPAddress ip;
    EXPECT_TRUE(ip.AssignFromIPLiteral(kNameserversIPv4[i]));
    config->nameservers.emplace_back(ip, NS_DEFAULTPORT + i);
  }

  for (unsigned i = 0; i < std::size(kNameserversIPv6) && i < MAXNS; ++i) {
    if (!kNameserversIPv6[i])
      continue;
    IPAddress ip;
    EXPECT_TRUE(ip.AssignFromIPLiteral(kNameserversIPv6[i]));
    config->nameservers[i] = IPEndPoint(ip, NS_DEFAULTPORT - i);
  }
}

class CallbackHelper {
 public:
  std::optional<DnsConfig> WaitForResult() {
    run_loop_.Run();
    return GetResult();
  }

  std::optional<DnsConfig> GetResult() {
    std::optional<DnsConfig> result = std::move(config_);
    return result;
  }

  DnsConfigService::CallbackType GetCallback() {
    return base::BindRepeating(&CallbackHelper::OnComplete,
                               base::Unretained(this));
  }

 private:
  void OnComplete(const DnsConfig& config) {
    config_ = config;
    run_loop_.Quit();
  }

  std::optional<DnsConfig> config_;
  base::RunLoop run_loop_;
};

// Helper to allow blocking on some point in the ThreadPool.
class BlockingHelper {
 public:
  ~BlockingHelper() { EXPECT_EQ(state_, State::kUnblocked); }

  // Called by the test code to wait for the block point to be reached.
  void WaitUntilBlocked() {
    CHECK_EQ(state_, State::kUnblocked);
    state_ = State::kRunningUntilBlock;

    CHECK(!run_loop_ || !run_loop_->running());
    run_loop_.emplace();
    run_loop_->Run();

    CHECK_EQ(state_, State::kBlocked);
  }

  // Called by the ThreadPool code on reaching the block point.
  void WaitUntilUnblocked() {
    block_event_.Reset();
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(&BlockingHelper::OnBlockedCallback,
                                          base::Unretained(this)));
    block_event_.Wait();
    blocker_event_.Signal();
  }

  // Called by the test code to unblock the ThreadPool code.
  void Unblock() {
    CHECK_EQ(state_, State::kBlocked);
    CHECK(!block_event_.IsSignaled());

    state_ = State::kUnblocked;

    blocker_event_.Reset();
    block_event_.Signal();
    blocker_event_.Wait();
  }

 private:
  enum class State {
    kRunningUntilBlock,
    kBlocked,
    kUnblocked,
  };

  void OnBlockedCallback() {
    CHECK_EQ(state_, State::kRunningUntilBlock);
    CHECK(run_loop_.has_value());
    CHECK(run_loop_->running());

    state_ = State::kBlocked;
    run_loop_->Quit();
  }

  State state_ = State::kUnblocked;
  std::optional<base::RunLoop> run_loop_;
  base::TestWaitableEvent block_event_;
  base::TestWaitableEvent blocker_event_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_ =
      base::SingleThreadTaskRunner::GetCurrentDefault();
};

class TestScopedResState : public ScopedResState {
 public:
  explicit TestScopedResState(std::unique_ptr<struct __res_state> res)
      : res_(std::move(res)) {}

  ~TestScopedResState() override {
    if (res_) {
      // Assume `res->_u._ext.nsaddrs` memory allocated via malloc, e.g. by
      // `InitializeResState()`.
      for (int i = 0; i < res_->nscount; ++i) {
        if (res_->_u._ext.nsaddrs[i] != nullptr)
          free(res_->_u._ext.nsaddrs[i]);
      }
    }
  }

  const struct __res_state& state() const override {
    EXPECT_TRUE(res_);
    return *res_;
  }

 private:
  std::unique_ptr<struct __res_state> res_;
};

class TestResolvReader : public ResolvReader {
 public:
  ~TestResolvReader() override = default;

  void set_value(std::unique_ptr<struct __res_state> value) {
    CHECK(!value_);
    value_ = std::make_unique<TestScopedResState>(std::move(value));
  }

  bool closed() { return !value_; }

  // ResolvReader:
  std::unique_ptr<ScopedResState> GetResState() override {
    if (blocking_helper_)
      blocking_helper_->WaitUntilUnblocked();

    CHECK(value_);
    return std::move(value_);
  }

  void set_blocking_helper(BlockingHelper* blocking_helper) {
    blocking_helper_ = blocking_helper;
  }

 private:
  std::unique_ptr<TestScopedResState> value_;
  raw_ptr<BlockingHelper> blocking_helper_ = nullptr;
};

class TestNsswitchReader : public NsswitchReader {
 public:
  void set_value(std::vector<ServiceSpecification> value) {
    value_ = std::move(value);
  }

  // NsswitchReader:
  std::vector<ServiceSpecification> ReadAndParseHosts() override {
    return value_;
  }

 private:
  std::vector<ServiceSpecification> value_;
};

class DnsConfigServiceLinuxTest : public ::testing::Test,
                                  public WithTaskEnvironment {
 public:
  DnsConfigServiceLinuxTest()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    auto resolv_reader = std::make_unique<TestResolvReader>();
    resolv_reader_ = resolv_reader.get();
    service_.set_resolv_reader_for_testing(std::move(resolv_reader));

    auto nsswitch_reader = std::make_unique<TestNsswitchReader>();
    nsswitch_reader_ = nsswitch_reader.get();
    service_.set_nsswitch_reader_for_testing(std::move(nsswitch_reader));
  }

 protected:
  internal::DnsConfigServiceLinux service_;
  raw_ptr<TestResolvReader> resolv_reader_;
  raw_ptr<TestNsswitchReader> nsswitch_reader_;
};

// Regression test to verify crash does not occur if DnsConfigServiceLinux
// instance is destroyed without calling WatchConfig()
TEST_F(DnsConfigServiceLinuxTest, CreateAndDestroy) {
  auto service = std::make_unique<internal::DnsConfigServiceLinux>();
  service.reset();
  RunUntilIdle();
}

TEST_F(DnsConfigServiceLinuxTest, ConvertResStateToDnsConfig) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));
  nsswitch_reader_->set_value(kBasicNsswitchConfig);

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());

  DnsConfig expected_config;
  EXPECT_FALSE(expected_config.EqualsIgnoreHosts(config.value()));
  InitializeExpectedConfig(&expected_config);
  EXPECT_TRUE(expected_config.EqualsIgnoreHosts(config.value()));

  EXPECT_TRUE(resolv_reader_->closed());
}

TEST_F(DnsConfigServiceLinuxTest, RejectEmptyNameserver) {
  auto res = std::make_unique<struct __res_state>();
  res->options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
  const char kDnsrch[] = "chromium.org";
  memcpy(res->defdname, kDnsrch, sizeof(kDnsrch));
  res->dnsrch[0] = res->defdname;

  struct sockaddr_in sa = {};
  sa.sin_family = AF_INET;
  sa.sin_port = base::HostToNet16(NS_DEFAULTPORT);
  sa.sin_addr.s_addr = INADDR_ANY;
  res->nsaddr_list[0] = sa;
  sa.sin_addr.s_addr = 0xCAFE1337;
  res->nsaddr_list[1] = sa;
  res->nscount = 2;

  resolv_reader_->set_value(std::move(res));
  nsswitch_reader_->set_value(kBasicNsswitchConfig);

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  RunUntilIdle();
  std::optional<DnsConfig> config = callback_helper.GetResult();

  EXPECT_FALSE(config.has_value());
  EXPECT_TRUE(resolv_reader_->closed());
}

TEST_F(DnsConfigServiceLinuxTest, AcceptNonEmptyNameserver) {
  auto res = std::make_unique<struct __res_state>();
  res->options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
  const char kDnsrch[] = "chromium.org";
  memcpy(res->defdname, kDnsrch, sizeof(kDnsrch));
  res->dnsrch[0] = res->defdname;

  struct sockaddr_in sa = {};
  sa.sin_family = AF_INET;
  sa.sin_port = base::HostToNet16(NS_DEFAULTPORT);
  sa.sin_addr.s_addr = 0xDEADBEEF;
  res->nsaddr_list[0] = sa;
  sa.sin_addr.s_addr = 0xCAFE1337;
  res->nsaddr_list[1] = sa;
  res->nscount = 2;

  resolv_reader_->set_value(std::move(res));
  nsswitch_reader_->set_value(kBasicNsswitchConfig);

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();

  EXPECT_TRUE(config.has_value());
  EXPECT_TRUE(resolv_reader_->closed());
}

// Regression test to verify crash does not occur if DnsConfigServiceLinux
// instance is destroyed while SerialWorker jobs have posted to worker pool.
TEST_F(DnsConfigServiceLinuxTest, DestroyWhileJobsWorking) {
  auto service = std::make_unique<internal::DnsConfigServiceLinux>();
  // Call WatchConfig() which also tests ReadConfig().
  service->WatchConfig(base::BindRepeating(&DummyConfigCallback));
  service.reset();
  FastForwardUntilNoTasksRemain();
}

// Regression test to verify crash does not occur if DnsConfigServiceLinux
// instance is destroyed on another thread.
TEST_F(DnsConfigServiceLinuxTest, DestroyOnDifferentThread) {
  scoped_refptr<base::SequencedTaskRunner> runner =
      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
  std::unique_ptr<internal::DnsConfigServiceLinux, base::OnTaskRunnerDeleter>
      service(new internal::DnsConfigServiceLinux(),
              base::OnTaskRunnerDeleter(runner));

  runner->PostTask(FROM_HERE,
                   base::BindOnce(&internal::DnsConfigServiceLinux::WatchConfig,
                                  base::Unretained(service.get()),
                                  base::BindRepeating(&DummyConfigCallback)));
  service.reset();
  RunUntilIdle();
}

TEST_F(DnsConfigServiceLinuxTest, AcceptsBasicNsswitchConfig) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));
  nsswitch_reader_->set_value(kBasicNsswitchConfig);

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_FALSE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest,
       IgnoresBasicNsswitchConfigIfResolvConfigUnhandled) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  res->options |= RES_USE_DNSSEC;  // Expect unhandled.
  resolv_reader_->set_value(std::move(res));
  nsswitch_reader_->set_value(kBasicNsswitchConfig);

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchWithoutFiles) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsWithExtraFiles) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, IgnoresRedundantActions) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kFiles,
           {{/*negated=*/false, NsswitchReader::Status::kSuccess,
             NsswitchReader::Action::kReturn},
            {/*negated=*/true, NsswitchReader::Status::kSuccess,
             NsswitchReader::Action::kContinue}}),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kDns,
           {{/*negated=*/false, NsswitchReader::Status::kSuccess,
             NsswitchReader::Action::kReturn},
            {/*negated=*/true, NsswitchReader::Status::kSuccess,
             NsswitchReader::Action::kContinue}})});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_FALSE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsInconsistentActions) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kDns,
           {{/*negated=*/false, NsswitchReader::Status::kUnavailable,
             NsswitchReader::Action::kReturn},
            {/*negated=*/true, NsswitchReader::Status::kSuccess,
             NsswitchReader::Action::kContinue}})});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsWithBadFilesSuccessAction) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kFiles,
           {{/*negated=*/false, NsswitchReader::Status::kSuccess,
             NsswitchReader::Action::kContinue}}),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsWithBadFilesNotFoundAction) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kFiles,
           {{/*negated=*/false, NsswitchReader::Status::kNotFound,
             NsswitchReader::Action::kReturn}}),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchWithoutDns) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsWithBadDnsSuccessAction) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kDns,
           {{/*negated=*/false, NsswitchReader::Status::kSuccess,
             NsswitchReader::Action::kContinue}})});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchWithMisorderedServices) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, AcceptsIncompatibleNsswitchServicesAfterDns) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_FALSE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchMdns) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchMdns4) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns4),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchMdns6) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns6),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, AcceptsNsswitchMdnsMinimal) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMdnsMinimal),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMdns4Minimal),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMdns6Minimal),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_FALSE(config->unhandled_options);
}

// mdns*_minimal is often paired with [!UNAVAIL=RETURN] or [NOTFOUND=RETURN]
// actions. Ensure that is accepted.
TEST_F(DnsConfigServiceLinuxTest, AcceptsNsswitchMdnsMinimalWithCommonActions) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMdnsMinimal,
           {{/*negated=*/true, NsswitchReader::Status::kUnavailable,
             NsswitchReader::Action::kReturn}}),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMdns4Minimal,
           {{/*negated=*/false, NsswitchReader::Status::kNotFound,
             NsswitchReader::Action::kReturn}}),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMdns6Minimal,
           {{/*negated=*/true, NsswitchReader::Status::kUnavailable,
             NsswitchReader::Action::kReturn}}),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_FALSE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsWithBadMdnsMinimalUnavailableAction) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMdnsMinimal,
           {{/*negated=*/false, NsswitchReader::Status::kUnavailable,
             NsswitchReader::Action::kReturn}}),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, AcceptsNsswitchMyHostname) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMyHostname),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_FALSE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsWithBadMyHostnameNotFoundAction) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kMyHostname,
           {{/*negated=*/false, NsswitchReader::Status::kNotFound,
             NsswitchReader::Action::kReturn}}),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchResolve) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kResolve),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchNis) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kNis),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsWithBadNisNotFoundAction) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(
           NsswitchReader::Service::kNis,
           {{/*negated=*/false, NsswitchReader::Status::kNotFound,
             NsswitchReader::Action::kReturn}}),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)});

  CallbackHelper callback_helper;
  service_.ReadConfig(callback_helper.GetCallback());
  std::optional<DnsConfig> config = callback_helper.WaitForResult();
  EXPECT_TRUE(resolv_reader_->closed());

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsValid());
  EXPECT_TRUE(config->unhandled_options);
}

TEST_F(DnsConfigServiceLinuxTest, RejectsNsswitchUnknown) {
  auto res = std::make_unique<struct __res_state>();
  InitializeResState(res.get());
  resolv_reader_->set_value(std::move(res));

  nsswitch_reader_->set_value(
      {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
       NsswitchReader::ServiceSpecification(NsswitchReader::Service::kUnknown),
       Ns
"""


```