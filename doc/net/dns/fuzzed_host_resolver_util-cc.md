Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understanding the Goal:** The core request is to understand the functionality of `fuzzed_host_resolver_util.cc` and how it interacts with the broader system, particularly regarding potential Javascript connections and common usage errors. The request specifically mentions debugging and how a user might reach this code.

2. **Initial Skim and Keyword Identification:**  I quickly scanned the code, looking for prominent keywords and patterns. Things that immediately jumped out:
    * `#include <fuzzer/FuzzedDataProvider.h>`:  This is a huge clue. It immediately signals that this code is related to *fuzzing*.
    * `Fuzz...`:  Many functions start with "Fuzz", like `FuzzPort`, `FuzzIPv4Address`, `GetFuzzedDnsConfig`. This reinforces the fuzzing purpose.
    * `HostResolverProc`, `DnsConfig`, `MDnsSocketFactory`, `HostResolverManager`:  These indicate that the code deals with DNS resolution and related networking components.
    * `ERR_...`:  Error codes suggest the code handles potential failures in DNS resolution.
    * `net::`: The namespace confirms this is part of Chromium's network stack.

3. **Deconstructing the Functionality - Piece by Piece:** I then went through the code section by section, focusing on what each part does:

    * **Helper Functions (FuzzPort, FuzzIPAddress, GetFuzzedDnsConfig):**  It's clear these functions generate *randomized* data for different aspects of DNS configuration (ports, IP addresses, DNS server lists, search domains, hosts file entries, etc.). The `FuzzedDataProvider` is the source of this randomness.

    * **`FuzzedHostResolverProc`:** This class *implements* the `HostResolverProc` interface. The key takeaway is that its `Resolve` method *doesn't* perform real DNS lookups. Instead, it *simulates* resolution by returning randomized IP addresses (or failure) based on the `FuzzedDataProvider`. This is crucial for fuzzing. The comment about thread safety is also noted.

    * **`FuzzedMdnsSocket` and `FuzzedMdnsSocketFactory`:** Similar to the `FuzzedHostResolverProc`, these classes *simulate* MDNS (multicast DNS) socket behavior. They randomly decide whether to send/receive data, what data to send/receive, and whether to return errors. This is another component being fuzzed.

    * **`FuzzedHostResolverManager`:** This is the core orchestrator. It *manages* the host resolution process, but in this *fuzzed* version, it uses the fuzzed `HostResolverProc` and `MDnsSocketFactory`. It also fakes the "globally reachable" check and loopback probe. The setup in the constructor involving `set_host_resolver_system_params_for_test` is a strong indicator of testing/fuzzing.

    * **`CreateFuzzedContextHostResolver`:** This is the entry point. It creates a `ContextHostResolver` using the fuzzed components. The `enable_caching` parameter is also noted.

4. **Identifying the Core Purpose:**  The repeated use of "Fuzz" and the interaction with `FuzzedDataProvider` made it obvious: This file is designed for *fuzz testing* the DNS resolution logic in Chromium. The goal is to provide unpredictable inputs to uncover potential bugs or crashes.

5. **Addressing the Javascript Connection:**  This required thinking about how DNS resolution happens in a browser context. Javascript doesn't directly interact with this C++ code. Instead, Javascript uses browser APIs (like `fetch` or `XMLHttpRequest`) that *internally* trigger the browser's network stack, which *eventually* might involve the DNS resolver. Therefore, while *indirect*, there's a connection. I focused on scenarios where Javascript triggers network requests.

6. **Generating Examples (Logical Inference):** For the `FuzzedHostResolverProc`,  I considered a simple case: providing a hostname and seeing how the fuzzer *might* respond with different IP addresses or errors. This illustrates the non-deterministic nature of the fuzzer.

7. **Identifying User/Programming Errors:**  I thought about common mistakes related to DNS and how this fuzzer might expose them. Incorrectly assuming DNS always works, hardcoding IP addresses, and not handling resolution failures are common issues that fuzzing could highlight.

8. **Tracing User Actions (Debugging Clues):**  This required thinking about the user's journey and how a network request initiated by the user (e.g., typing a URL) gets processed by the browser and eventually reaches the DNS resolver. The steps involved in a typical browser network request are key here.

9. **Structuring the Explanation:** Finally, I organized the information into logical sections as requested: functionality, Javascript relation, logical inference, user errors, and debugging clues. I used clear headings and bullet points for readability. I also made sure to highlight the *fuzzing* aspect throughout the explanation.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this code has something to do with custom DNS configurations.
* **Correction:** The `FuzzedDataProvider` is a much stronger signal for fuzzing. Custom configurations are handled differently.
* **Initial thought:** Focus heavily on the technical details of each class.
* **Refinement:**  Balance the technical details with the *purpose* of the code (fuzzing) and its implications for users and developers. Emphasize the *randomness* and *simulation* aspects.
* **Initial thought:** Directly link Javascript code to this C++ file.
* **Refinement:** Clarify the *indirect* relationship via browser APIs and the network stack.

By following these steps, combining code analysis with domain knowledge of networking and browser architecture, and refining the explanation along the way, I arrived at the comprehensive answer provided.
这个文件 `net/dns/fuzzed_host_resolver_util.cc` 的主要功能是为 Chromium 的网络栈提供一个 **用于模糊测试（fuzz testing）Host Resolver（主机名解析器）的工具集**。它不是一个实际用于生产环境的主机名解析器，而是为了在各种随机的、甚至是错误的情况下测试 Host Resolver 的健壮性和错误处理能力而设计的。

以下是其功能的详细列表：

**核心功能：提供用于模糊测试的主机名解析器实现**

* **随机 DNS 配置生成 (`GetFuzzedDnsConfig`)**:  能够生成各种各样的、可能无效或不常见的 DNS 配置，包括：
    * 随机数量和 IP 地址的 DNS 服务器。
    * 随机的搜索域名后缀列表。
    * 随机的 hosts 文件条目。
    * 随机设置 DNS 配置的其他选项（如 `unhandled_options`, `append_to_multi_label_name`, `ndots`, `attempts`, `rotate`, `use_local_ipv6` 等）。
* **模拟 Host Resolver Proc (`FuzzedHostResolverProc`)**:  实现了 `HostResolverProc` 接口，但其 `Resolve` 方法 **不进行真实的 DNS 查询**。相反，它使用 `FuzzedDataProvider` 来生成随机的解析结果，包括：
    * 随机数量的 IPv4 和 IPv6 地址。
    * 可以返回成功 (OK) 或失败 (ERR_NAME_NOT_RESOLVED)。
    * 可以设置别名 (虽然目前是硬编码的)。
* **模拟 MDNS 客户端 (`FuzzedMdnsSocket`, `FuzzedMdnsSocketFactory`)**: 模拟了 MDNS (Multicast DNS) 客户端的行为，用于测试 MDNS 相关的解析逻辑。它可以：
    * 模拟接收和发送 MDNS 数据包。
    * 随机返回成功或各种网络错误。
    * 模拟不接收任何响应的情况。
* **模拟 Host Resolver 管理器 (`FuzzedHostResolverManager`)**:  实现了 `HostResolverManager` 接口，但使用了上面提到的模糊测试组件。它可以：
    * 使用 `FuzzedHostResolverProc` 作为系统 DNS 解析器。
    * 使用 `FuzzedMdnsSocketFactory` 创建 MDNS 套接字。
    * 随机决定全局可达性检查的结果 (`StartGloballyReachableCheck`)。
    * 随机决定是否只存在环回地址 (`RunLoopbackProbeJob`)。
    * 使用随机的 DNS 配置。
* **创建模糊测试上下文 Host Resolver (`CreateFuzzedContextHostResolver`)**:  提供一个方便的函数，用于创建使用上述模糊测试组件的 `ContextHostResolver` 实例。

**与 Javascript 功能的关系**

此文件中的代码 **不直接与 Javascript 代码交互**。然而，它影响着浏览器中由 Javascript 发起的网络请求的行为。当 Javascript 代码（例如通过 `fetch` 或 `XMLHttpRequest`）尝试连接到某个主机名时，浏览器会使用其内部的 Host Resolver 来将主机名解析为 IP 地址。

使用 `FuzzedHostResolverUtil` 创建的 Host Resolver 会以随机的方式响应这些解析请求。例如：

* **假设输入 (Javascript):**  Javascript 代码尝试使用 `fetch('http://example.com')` 发起一个网络请求。
* **模糊测试的影响:**  `FuzzedHostResolverProc` 可能会随机返回 `example.com` 的以下解析结果：
    * 一组随机的 IPv4 和 IPv6 地址。
    * 解析失败 (`ERR_NAME_NOT_RESOLVED`)。
    * 即使本地 hosts 文件或 DNS 服务器配置了特定的 IP，也可能返回不同的随机 IP。

这种随机性可以帮助发现网络栈中对于意外或错误 DNS 解析结果的处理缺陷。例如，如果 Javascript 代码没有正确处理 DNS 解析失败的情况，模糊测试可能会触发错误或崩溃。

**逻辑推理的假设输入与输出**

**场景：测试 DNS 搜索后缀列表的影响**

* **假设输入 (FuzzedDataProvider):**
    * DNS 配置中的搜索后缀列表为 `["foo.com", "bar"]`。
    * 尝试解析的主机名为 `"test"`。
    * `FuzzedHostResolverProc` 被配置为模拟解析成功。
* **逻辑推理:**
    * 模糊测试框架可能会模拟 Host Resolver 尝试解析以下主机名：
        1. `test`
        2. `test.foo.com`
        3. `test.bar`
    * `FuzzedHostResolverProc` 会为其中一个或多个尝试返回随机的 IP 地址。
* **假设输出 (AddressList):**
    * 可能会返回 `test.foo.com` 解析到的一个随机 IPv4 地址 (例如 `192.168.1.1`).
    * 或者可能会返回 `test.bar` 解析到的一个随机 IPv6 地址 (例如 `2001:db8::1`).
    * 或者如果所有解析都“成功”，可能会返回多个 IP 地址的列表。

**涉及用户或编程常见的使用错误**

* **用户错误：假设 DNS 解析总是成功。**
    * **示例:** 用户在 Javascript 代码中直接使用 `fetch('http://some-nonexistent-domain.xyz')`，但没有添加错误处理逻辑来处理网络请求失败的情况。
    * **模糊测试的作用:**  `FuzzedHostResolverProc` 可能会模拟 DNS 解析失败，从而暴露 Javascript 代码中缺少错误处理的缺陷。
* **编程错误：硬编码 IP 地址而不是使用主机名。**
    * **示例:** 开发者在代码中直接使用 `connect('192.168.1.100')`，而不是使用主机名。
    * **模糊测试的作用:**  虽然模糊测试主要针对主机名解析，但它可能间接地暴露这种做法的局限性。例如，如果被硬编码的 IP 地址的主机发生了变化，代码将无法工作。
* **编程错误：错误地假设本地 hosts 文件的影响。**
    * **示例:** 开发者依赖于本地 hosts 文件中的条目进行测试，但没有考虑到在其他环境下或被模糊测试时，hosts 文件可能没有相应的条目。
    * **模糊测试的作用:**  `GetFuzzedDnsConfig` 可以生成包含随机 hosts 文件条目的配置，这可能会导致与开发者预期不同的解析结果，从而暴露对特定 hosts 文件配置的依赖。

**用户操作是如何一步步的到达这里，作为调试线索**

作为一个开发人员或测试人员，用户不会直接 "到达" `fuzzed_host_resolver_util.cc` 这个文件。这个文件是在 Chromium 的开发和测试过程中使用的。以下是一些可能导致相关代码被执行的场景：

1. **运行 Chromium 的网络栈模糊测试:**  Chromium 的开发者会定期运行各种模糊测试，以确保代码的健壮性。当运行与 Host Resolver 相关的模糊测试时，`CreateFuzzedContextHostResolver` 函数会被调用，从而创建使用 `FuzzedHostResolverProc` 和其他模糊测试组件的 Host Resolver。

2. **调试网络请求失败:**
   * 用户在浏览器中访问一个网页，但加载失败。
   * 开发人员可能会使用 Chromium 的网络调试工具 (chrome://net-internals/#dns) 来查看 DNS 解析过程。
   * 如果当时启用了某种形式的 Host Resolver 替换或调试配置，可能会间接地观察到与模糊测试相关的行为（尽管这种情况不太常见，因为模糊测试通常在自动化环境中运行）。

3. **开发或测试涉及自定义 Host Resolver 的功能:**  如果 Chromium 的某个功能正在开发或测试中，并且需要自定义 Host Resolver 的行为，开发者可能会使用或参考 `fuzzed_host_resolver_util.cc` 中的代码作为灵感或调试辅助。

**调试线索:**

* **查看网络日志 (chrome://net-internals/#events):**  网络日志可能会显示 DNS 解析的详细信息。如果看到解析结果是随机的、不符合预期的 IP 地址，或者频繁出现解析失败的情况，并且确定没有人为的网络问题，那么可能与正在进行的模糊测试或某种调试配置有关。
* **检查 chrome://flags 中的实验性功能:**  某些实验性功能可能会影响 Host Resolver 的行为。检查是否启用了与 DNS 或网络相关的实验性功能。
* **检查命令行参数:**  在运行 Chromium 时，可能会使用一些命令行参数来修改网络栈的行为。检查是否使用了影响 Host Resolver 的参数。
* **检查代码变更历史:**  如果怀疑某个代码变更引入了与 Host Resolver 相关的问题，可以查看 `net/dns/` 目录下最近的提交记录。

总而言之，`fuzzed_host_resolver_util.cc` 是 Chromium 网络栈中一个重要的测试工具，它通过模拟各种随机和错误的情况来帮助发现潜在的 bug 和安全漏洞，确保浏览器在面对不稳定的网络环境时依然能够稳定可靠地运行。用户通常不会直接与这个文件交互，但它的存在和运行对最终用户的浏览体验至关重要。

### 提示词
```
这是目录为net/dns/fuzzed_host_resolver_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/fuzzed_host_resolver_util.h"

#include <stdint.h>

#include <fuzzer/FuzzedDataProvider.h>

#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/address_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/dns/context_host_resolver.h"
#include "net/dns/dns_client.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_hosts.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/host_resolver_proc.h"
#include "net/dns/host_resolver_system_task.h"
#include "net/dns/mdns_client.h"
#include "net/dns/public/util.h"
#include "net/dns/resolve_context.h"
#include "net/log/net_log.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/datagram_server_socket.h"
#include "net/socket/fuzzed_socket_factory.h"

namespace net {

namespace {

// Returns a fuzzed non-zero port number.
uint16_t FuzzPort(FuzzedDataProvider* data_provider) {
  return data_provider->ConsumeIntegral<uint16_t>();
}

// Returns a fuzzed IPv4 address.  Can return invalid / reserved addresses.
IPAddress FuzzIPv4Address(FuzzedDataProvider* data_provider) {
  return IPAddress(data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>());
}

// Returns a fuzzed IPv6 address.  Can return invalid / reserved addresses.
IPAddress FuzzIPv6Address(FuzzedDataProvider* data_provider) {
  return IPAddress(data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>(),
                   data_provider->ConsumeIntegral<uint8_t>());
}

// Returns a fuzzed address, which can be either IPv4 or IPv6.  Can return
// invalid / reserved addresses.
IPAddress FuzzIPAddress(FuzzedDataProvider* data_provider) {
  if (data_provider->ConsumeBool())
    return FuzzIPv4Address(data_provider);
  return FuzzIPv6Address(data_provider);
}

DnsConfig GetFuzzedDnsConfig(FuzzedDataProvider* data_provider) {
  // Fuzz DNS configuration.
  DnsConfig config;

  // Fuzz name servers.
  uint32_t num_nameservers = data_provider->ConsumeIntegralInRange(0, 4);
  for (uint32_t i = 0; i < num_nameservers; ++i) {
    config.nameservers.push_back(
        IPEndPoint(FuzzIPAddress(data_provider), FuzzPort(data_provider)));
  }

  // Fuzz suffix search list.
  switch (data_provider->ConsumeIntegralInRange(0, 3)) {
    case 3:
      config.search.push_back("foo.com");
      [[fallthrough]];
    case 2:
      config.search.push_back("bar");
      [[fallthrough]];
    case 1:
      config.search.push_back("com");
      [[fallthrough]];
    default:
      break;
  }

  net::DnsHosts hosts;
  // Fuzz hosts file.
  uint8_t num_hosts_entries = data_provider->ConsumeIntegral<uint8_t>();
  for (uint8_t i = 0; i < num_hosts_entries; ++i) {
    const char* kHostnames[] = {"foo", "foo.com",   "a.foo.com",
                                "bar", "localhost", "localhost6"};
    const char* hostname = data_provider->PickValueInArray(kHostnames);
    net::IPAddress address = FuzzIPAddress(data_provider);
    config.hosts[net::DnsHostsKey(hostname, net::GetAddressFamily(address))] =
        address;
  }

  config.unhandled_options = data_provider->ConsumeBool();
  config.append_to_multi_label_name = data_provider->ConsumeBool();
  config.ndots = data_provider->ConsumeIntegralInRange(0, 3);
  config.attempts = data_provider->ConsumeIntegralInRange(1, 3);

  // Fallback periods don't really work for fuzzing. Even a period of 0
  // milliseconds will be increased after the first expiration, resulting in
  // inconsistent behavior.
  config.fallback_period = base::Days(10);

  config.rotate = data_provider->ConsumeBool();

  config.use_local_ipv6 = data_provider->ConsumeBool();

  return config;
}

// HostResolverProc that returns a random set of results, and can succeed or
// fail. Must only be run on the thread it's created on.
class FuzzedHostResolverProc : public HostResolverProc {
 public:
  // Can safely be used after the destruction of |data_provider|. This can
  // happen if a request is issued but the code never waits for the result
  // before the test ends.
  explicit FuzzedHostResolverProc(
      base::WeakPtr<FuzzedDataProvider> data_provider)
      : HostResolverProc(nullptr),
        data_provider_(data_provider),
        network_task_runner_(
            base::SingleThreadTaskRunner::GetCurrentDefault()) {}

  FuzzedHostResolverProc(const FuzzedHostResolverProc&) = delete;
  FuzzedHostResolverProc& operator=(const FuzzedHostResolverProc&) = delete;

  int Resolve(const std::string& host,
              AddressFamily address_family,
              HostResolverFlags host_resolver_flags,
              AddressList* addrlist,
              int* os_error) override {
    DCHECK(network_task_runner_->BelongsToCurrentThread());

    if (os_error)
      *os_error = 0;

    // If the data provider is no longer avaiable, just fail. The HostResolver
    // has already been deleted by this point, anyways.
    if (!data_provider_)
      return ERR_FAILED;

    AddressList result;

    // Put IPv6 addresses before IPv4 ones. This code doesn't sort addresses
    // correctly, but when sorted according to spec, IPv6 addresses are
    // generally before IPv4 ones.
    if (address_family == ADDRESS_FAMILY_UNSPECIFIED ||
        address_family == ADDRESS_FAMILY_IPV6) {
      uint8_t num_ipv6_addresses = data_provider_->ConsumeIntegral<uint8_t>();
      for (uint8_t i = 0; i < num_ipv6_addresses; ++i) {
        result.push_back(
            net::IPEndPoint(FuzzIPv6Address(data_provider_.get()), 0));
      }
    }

    if (address_family == ADDRESS_FAMILY_UNSPECIFIED ||
        address_family == ADDRESS_FAMILY_IPV4) {
      uint8_t num_ipv4_addresses = data_provider_->ConsumeIntegral<uint8_t>();
      for (uint8_t i = 0; i < num_ipv4_addresses; ++i) {
        result.push_back(
            net::IPEndPoint(FuzzIPv4Address(data_provider_.get()), 0));
      }
    }

    if (result.empty())
      return ERR_NAME_NOT_RESOLVED;

    if (host_resolver_flags & HOST_RESOLVER_CANONNAME) {
      // Don't bother to fuzz this - almost nothing cares.
      std::vector<std::string> aliases({"foo.com"});
      result.SetDnsAliases(std::move(aliases));
    }

    *addrlist = result;
    return OK;
  }

 private:
  ~FuzzedHostResolverProc() override = default;

  base::WeakPtr<FuzzedDataProvider> data_provider_;

  // Just used for thread-safety checks.
  scoped_refptr<base::SingleThreadTaskRunner> network_task_runner_;
};

const Error kMdnsErrors[] = {ERR_FAILED,
                             ERR_ACCESS_DENIED,
                             ERR_INTERNET_DISCONNECTED,
                             ERR_TIMED_OUT,
                             ERR_CONNECTION_RESET,
                             ERR_CONNECTION_ABORTED,
                             ERR_CONNECTION_REFUSED,
                             ERR_ADDRESS_UNREACHABLE};
// Fuzzed socket implementation to handle the limited functionality used by
// MDnsClientImpl. Uses a FuzzedDataProvider to generate errors or responses for
// RecvFrom calls.
class FuzzedMdnsSocket : public DatagramServerSocket {
 public:
  explicit FuzzedMdnsSocket(FuzzedDataProvider* data_provider)
      : data_provider_(data_provider),
        local_address_(FuzzIPAddress(data_provider_), 5353) {}

  int Listen(const IPEndPoint& address) override { return OK; }

  int RecvFrom(IOBuffer* buffer,
               int buffer_length,
               IPEndPoint* out_address,
               CompletionOnceCallback callback) override {
    if (data_provider_->ConsumeBool())
      return GenerateResponse(buffer, buffer_length, out_address);

    // Maybe never receive any responses.
    if (data_provider_->ConsumeBool()) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&FuzzedMdnsSocket::CompleteRecv,
                         weak_factory_.GetWeakPtr(), std::move(callback),
                         base::RetainedRef(buffer), buffer_length,
                         out_address));
    }

    return ERR_IO_PENDING;
  }

  int SendTo(IOBuffer* buf,
             int buf_len,
             const IPEndPoint& address,
             CompletionOnceCallback callback) override {
    if (data_provider_->ConsumeBool()) {
      return data_provider_->ConsumeBool()
                 ? OK
                 : data_provider_->PickValueInArray(kMdnsErrors);
    }

    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&FuzzedMdnsSocket::CompleteSend,
                       weak_factory_.GetWeakPtr(), std::move(callback)));
    return ERR_IO_PENDING;
  }

  int SetReceiveBufferSize(int32_t size) override { return OK; }
  int SetSendBufferSize(int32_t size) override { return OK; }

  void AllowAddressReuse() override {}
  void AllowBroadcast() override {}
  void AllowAddressSharingForMulticast() override {}

  int JoinGroup(const IPAddress& group_address) const override { return OK; }
  int LeaveGroup(const IPAddress& group_address) const override { return OK; }
  int SetMulticastInterface(uint32_t interface_index) override { return OK; }
  int SetMulticastTimeToLive(int time_to_live) override { return OK; }
  int SetMulticastLoopbackMode(bool loopback) override { return OK; }

  int SetDiffServCodePoint(DiffServCodePoint dscp) override { return OK; }

  void DetachFromThread() override {}

  void Close() override {}
  int GetPeerAddress(IPEndPoint* address) const override {
    return ERR_SOCKET_NOT_CONNECTED;
  }
  int GetLocalAddress(IPEndPoint* address) const override {
    *address = local_address_;
    return OK;
  }
  void UseNonBlockingIO() override {}
  int SetDoNotFragment() override { return OK; }
  int SetRecvTos() override { return OK; }
  int SetTos(DiffServCodePoint dscp, EcnCodePoint ecn) override { return OK; }
  void SetMsgConfirm(bool confirm) override {}
  const NetLogWithSource& NetLog() const override { return net_log_; }
  DscpAndEcn GetLastTos() const override { return {DSCP_DEFAULT, ECN_DEFAULT}; }

 private:
  void CompleteRecv(CompletionOnceCallback callback,
                    IOBuffer* buffer,
                    int buffer_length,
                    IPEndPoint* out_address) {
    int rv = GenerateResponse(buffer, buffer_length, out_address);
    std::move(callback).Run(rv);
  }

  int GenerateResponse(IOBuffer* buffer,
                       int buffer_length,
                       IPEndPoint* out_address) {
    if (data_provider_->ConsumeBool()) {
      std::string data =
          data_provider_->ConsumeRandomLengthString(buffer_length);
      base::ranges::copy(data, buffer->data());
      *out_address =
          IPEndPoint(FuzzIPAddress(data_provider_), FuzzPort(data_provider_));
      return data.size();
    }

    return data_provider_->PickValueInArray(kMdnsErrors);
  }

  void CompleteSend(CompletionOnceCallback callback) {
    if (data_provider_->ConsumeBool())
      std::move(callback).Run(OK);
    else
      std::move(callback).Run(data_provider_->PickValueInArray(kMdnsErrors));
  }

  const raw_ptr<FuzzedDataProvider> data_provider_;
  const IPEndPoint local_address_;
  const NetLogWithSource net_log_;

  base::WeakPtrFactory<FuzzedMdnsSocket> weak_factory_{this};
};

class FuzzedMdnsSocketFactory : public MDnsSocketFactory {
 public:
  explicit FuzzedMdnsSocketFactory(FuzzedDataProvider* data_provider)
      : data_provider_(data_provider) {}

  void CreateSockets(
      std::vector<std::unique_ptr<DatagramServerSocket>>* sockets) override {
    int num_sockets = data_provider_->ConsumeIntegralInRange(1, 4);
    for (int i = 0; i < num_sockets; ++i)
      sockets->push_back(std::make_unique<FuzzedMdnsSocket>(data_provider_));
  }

 private:
  const raw_ptr<FuzzedDataProvider> data_provider_;
};

class FuzzedHostResolverManager : public HostResolverManager {
 public:
  // |data_provider| and |net_log| must outlive the FuzzedHostResolver.
  // TODO(crbug.com/40630884): Fuzz system DNS config changes through a non-null
  // SystemDnsConfigChangeNotifier.
  FuzzedHostResolverManager(const HostResolver::ManagerOptions& options,
                            NetLog* net_log,
                            FuzzedDataProvider* data_provider)
      : HostResolverManager(options,
                            nullptr /* system_dns_config_notifier */,
                            net_log),
        data_provider_(data_provider),
        is_globally_reachable_(data_provider->ConsumeBool()),
        start_globally_reachable_async_(data_provider->ConsumeBool()),
        socket_factory_(data_provider_),
        net_log_(net_log),
        data_provider_weak_factory_(data_provider) {
    HostResolverSystemTask::Params system_task_params(
        base::MakeRefCounted<FuzzedHostResolverProc>(
            data_provider_weak_factory_.GetWeakPtr()),
        // Retries are only used when the original request hangs, which this
        // class currently can't simulate.
        0 /* max_retry_attempts */);
    set_host_resolver_system_params_for_test(system_task_params);  // IN-TEST
    SetMdnsSocketFactoryForTesting(
        std::make_unique<FuzzedMdnsSocketFactory>(data_provider_));
    std::unique_ptr<DnsClient> dns_client = DnsClient::CreateClientForTesting(
        net_log_, base::BindRepeating(
                      &FuzzedDataProvider::ConsumeIntegralInRange<int32_t>,
                      base::Unretained(data_provider_)));
    dns_client->SetSystemConfig(GetFuzzedDnsConfig(data_provider_));
    HostResolverManager::SetDnsClientForTesting(std::move(dns_client));
  }

  FuzzedHostResolverManager(const FuzzedHostResolverManager&) = delete;
  FuzzedHostResolverManager& operator=(const FuzzedHostResolverManager&) =
      delete;

  ~FuzzedHostResolverManager() override = default;

  void SetDnsClientForTesting(std::unique_ptr<DnsClient> dns_client) {
    // The only DnsClient that is supported is the one created by the
    // FuzzedHostResolverManager since that DnsClient contains the necessary
    // fuzzing logic.
    NOTREACHED();
  }

 private:
  // HostResolverManager implementation:
  int StartGloballyReachableCheck(const IPAddress& dest,
                                  const NetLogWithSource& net_log,
                                  ClientSocketFactory* client_socket_factory,
                                  CompletionOnceCallback callback) override {
    int reachable_rv = is_globally_reachable_ ? OK : ERR_FAILED;
    if (start_globally_reachable_async_) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback), reachable_rv));
      return ERR_IO_PENDING;
    }
    return reachable_rv;
  }

  void RunLoopbackProbeJob() override {
    SetHaveOnlyLoopbackAddresses(data_provider_->ConsumeBool());
  }

  const raw_ptr<FuzzedDataProvider> data_provider_;

  // Fixed value to be returned by StartGloballyReachableCheck.
  const bool is_globally_reachable_;
  // Determines if StartGloballyReachableCheck returns sync or async.
  const bool start_globally_reachable_async_;

  // Used for UDP and TCP sockets if the async resolver is enabled.
  FuzzedSocketFactory socket_factory_;

  const raw_ptr<NetLog> net_log_;

  base::WeakPtrFactory<FuzzedDataProvider> data_provider_weak_factory_;
};

}  // namespace

std::unique_ptr<ContextHostResolver> CreateFuzzedContextHostResolver(
    const HostResolver::ManagerOptions& options,
    NetLog* net_log,
    FuzzedDataProvider* data_provider,
    bool enable_caching) {
  auto manager = std::make_unique<FuzzedHostResolverManager>(options, net_log,
                                                             data_provider);
  auto resolve_context = std::make_unique<ResolveContext>(
      nullptr /* url_request_context */, enable_caching);
  return std::make_unique<ContextHostResolver>(std::move(manager),
                                               std::move(resolve_context));
}

}  // namespace net
```