Response:
Let's break down the thought process to analyze the given C++ code and generate the desired output.

**1. Understanding the Core Task:**

The primary goal is to understand the functionality of the `dns_response_result_extractor.cc` file in Chromium's network stack. This involves identifying its purpose, key data structures, and how it processes DNS responses. The prompt also specifically asks about its relationship to JavaScript, logical reasoning with inputs and outputs, common user errors, and debugging steps.

**2. Initial Code Scan and Keyword Spotting:**

I'd start by quickly scanning the code for keywords and patterns:

* **`net/dns/`**:  This immediately tells me the file is part of the DNS resolution subsystem.
* **`DnsResponse`**: This is a core class likely representing a parsed DNS response packet.
* **`RecordParsed`**:  Indicates the code is dealing with individual DNS records within a response.
* **`HostResolverInternalResult`**: This suggests the output of this code is used by the host resolution process. It seems to be an internal representation of DNS results.
* **`Extract...Results` functions**: These are strong indicators of the file's core functionality – extracting different types of DNS records.
* **`DnsQueryType`**:  This enumeration defines the different types of DNS queries (A, AAAA, TXT, etc.) that the extractor handles.
* **`AliasMap`**:  Points to the handling of CNAME records (aliases).
* **`ValidateNamesAndAliases`**:  Confirms the logic for ensuring the correctness of alias chains.
* **`SortServiceTargets`**:  Specifically for SRV records, indicating special processing.
* **`HttpsRecordRdata`**:  Highlights specific handling for HTTPS records (SVCB/HTTPS RR).
* **`UMA_HISTOGRAM_ENUMERATION`**:  Shows metrics collection, likely for debugging and performance analysis.
* **`base::Time`, `base::TimeTicks`**:  Indicates the importance of timestamps and TTLs (Time To Live) for caching.
* **Error handling (`ExtractionError`)**:  Shows the code deals with malformed or invalid DNS responses.

**3. Dissecting Key Functions:**

I'd then focus on the major functions:

* **`ExtractResponseRecords`**: This seems to be a central function. It parses the DNS response, identifies CNAME records (aliases), and separates data records. It also handles error conditions like multiple CNAMEs and name mismatches. The logic for caching negative responses (NXDOMAIN, NODATA) is also present here.
* **`ValidateNamesAndAliases`**: Crucial for understanding how CNAME chains are validated for loops and consistency.
* **`ExtractAddressResults` (A/AAAA):**  Simple extraction of IP addresses and associated TTLs.
* **`ExtractTxtResults`**:  Extracts TXT record data.
* **`ExtractPointerResults` (PTR):** Extracts PTR records for reverse DNS lookups.
* **`ExtractServiceResults` (SRV):**  More complex logic involving sorting targets based on priority and weight.
* **`ExtractHttpsResults` (HTTPS):** The most involved, dealing with SVCB/HTTPS RRs, handling priorities, ALPNs, ECH, and the concept of "compatible" records. The exclusion logic based on aliases and `no-default-alpn` is important.

**4. Identifying Functionality and Relationships:**

Based on the dissected functions, I can now summarize the file's functionality. The core purpose is to take a parsed `DnsResponse` and extract meaningful results in a structured format (`HostResolverInternalResult`) that the Chromium network stack can use. It handles various DNS record types and performs validation and error checking.

**5. Relating to JavaScript (or Lack Thereof):**

The key here is to recognize that this is low-level network code. It's part of the *browser's* internal workings, not the web page's scripting environment. Therefore, the direct connection to JavaScript is minimal. However, the *results* of this code are what enable JavaScript code running in a web page to successfully connect to servers. The examples provided illustrate this indirect relationship.

**6. Logical Reasoning, Assumptions, and Outputs:**

For each `Extract...Results` function, I can create simple examples:

* **A/AAAA:**  Basic IP address lookup.
* **TXT:** Retrieving arbitrary text data.
* **PTR:**  Reverse IP lookup.
* **SRV:** Finding service locations.
* **HTTPS:**  Demonstrating the more complex logic with priorities, ALPNs, and handling of incompatible records.

The important part here is to choose simple but illustrative examples that highlight the function's main purpose.

**7. User and Programming Errors:**

This section requires thinking about how things could go wrong from both a user's and a programmer's perspective:

* **User Errors:** Primarily focus on DNS configuration issues that would lead to malformed responses.
* **Programming Errors:** Focus on how *developers within the Chromium project* might misuse the extractor or the classes it interacts with.

**8. Debugging Steps:**

Think about the typical flow of a DNS request in a browser. How does a user's action (typing in a URL) lead to this code being executed?  This helps establish the debugging path. Key steps involve:

* URL input and navigation.
* Host resolution initiation.
* DNS query construction and sending.
* DNS response processing (where this code fits in).

**9. Structuring the Output:**

Finally, organize the findings into the requested sections. Use clear and concise language. Provide code snippets (from the original code) where necessary to support the explanations. The goal is to be informative and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe there's a direct JavaScript API that calls this code.
* **Correction:**  Realized this is more likely an internal C++ component. JavaScript interacts with network requests at a higher level. The connection is indirect.

* **Initial thought:** Focus only on successful cases for logical reasoning.
* **Refinement:** Include examples of error conditions (like malformed responses or incompatible HTTPS records) to demonstrate the error handling capabilities.

* **Initial thought:** List every possible user error related to networking.
* **Refinement:** Focus on errors more directly related to DNS and how they might manifest in the context of this code.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate answer to the prompt.
这个文件 `net/dns/dns_response_result_extractor.cc` 的主要功能是从 DNS 响应 (`DnsResponse`) 中提取出各种类型的 DNS 查询结果，并将其转换为 Chromium 网络栈内部使用的 `HostResolverInternalResult` 对象。 这些结果将用于填充 DNS 缓存 (`HostCache`)，并最终用于建立网络连接。

以下是其主要功能的详细列表：

**核心功能：从 DNS 响应中提取各种类型的 DNS 记录并生成 `HostResolverInternalResult`：**

* **地址记录 (A 和 AAAA):** 提取 IPv4 和 IPv6 地址，并创建 `HostResolverInternalDataResult` 对象。
* **文本记录 (TXT):** 提取文本数据，并创建 `HostResolverInternalDataResult` 对象。
* **指针记录 (PTR):** 提取 PTR 记录指向的主机名，并创建 `HostResolverInternalDataResult` 对象。
* **服务记录 (SRV):** 提取 SRV 记录，根据优先级和权重排序目标主机，并创建 `HostResolverInternalDataResult` 对象。
* **HTTPS 记录:** 提取 HTTPS 记录 (SVCB 或 HTTPS RR)，解析其参数 (优先级、ALPN、ECH 配置等)，并创建 `HostResolverInternalMetadataResult` 对象。 这个过程比较复杂，涉及到兼容性检查和对不同参数的处理。
* **别名记录 (CNAME):**  处理 CNAME 记录，构建别名链，并创建 `HostResolverInternalAliasResult` 对象。
* **错误处理:**  对于 NXDOMAIN (域名不存在) 和 NODATA (存在域名但请求的记录类型不存在) 的响应，如果权威部分包含 SOA 记录，则提取其 TTL 并创建一个 `HostResolverInternalErrorResult` 对象用于缓存 negative responses。

**辅助功能：**

* **验证 DNS 响应的完整性和一致性:** 例如，验证 CNAME 链是否形成闭环，以及数据记录是否与最终的规范名称匹配。
* **管理 TTL (Time To Live):**  计算结果的有效期，基于 DNS 记录的 TTL 值。
* **指标收集:**  使用 UMA (User Metrics Analysis) 记录有关 HTTPS 记录的统计信息，例如是否是 unsolicited 的记录。
* **处理 unsolicited 的额外 HTTPS 记录:** 当请求 A 或 AAAA 记录时，如果响应的附加部分包含 HTTPS 记录，也会进行解析和记录。
* **排序 SRV 记录:**  根据 RFC2782 的规定，按照优先级和权重对 SRV 记录进行排序。

**与 JavaScript 功能的关系：**

`dns_response_result_extractor.cc` 本身是用 C++ 编写的，与 JavaScript 没有直接的代码层面的交互。然而，它的功能对于支持 JavaScript 发起的网络请求至关重要。

当 JavaScript 代码 (例如在网页中) 尝试访问一个域名时，Chromium 浏览器会执行以下步骤：

1. **JavaScript 发起请求:**  例如，使用 `fetch()` API 或 `XMLHttpRequest`。
2. **浏览器解析 URL:**  提取出域名。
3. **主机名解析:** 浏览器会查找该域名对应的 IP 地址。 这通常会涉及到 DNS 查询。
4. **`dns_response_result_extractor.cc` 的作用:** 当 DNS 服务器返回响应时，`dns_response_result_extractor.cc` 会被调用来解析这个响应，提取出 IP 地址 (对于 A/AAAA 查询)、HTTPS 配置信息 (对于 HTTPS 查询) 等。
5. **将结果传递给网络栈:**  提取出的结果会被存储在 DNS 缓存中，并用于建立与服务器的连接。
6. **连接建立:**  浏览器使用解析出的 IP 地址和协议信息 (例如 HTTPS 的 ALPN) 建立 TCP 或 QUIC 连接。
7. **数据传输:**  JavaScript 代码最终可以通过建立的连接与服务器进行数据交互。

**举例说明:**

假设网页中的 JavaScript 代码尝试访问 `https://example.com`:

1. **JavaScript:** `fetch('https://example.com')`
2. **浏览器:**  发起对 `example.com` 的 DNS 查询 (可能首先查询 AAAA 记录，然后查询 A 记录，如果需要可能还会查询 HTTPS 记录)。
3. **DNS 响应:** DNS 服务器返回 `example.com` 的 A 记录 (假设是 `93.184.216.34`) 和 HTTPS 记录。
4. **`dns_response_result_extractor.cc`:**  这个文件会解析 DNS 响应，提取出 IP 地址 `93.184.216.34` 和 HTTPS 记录中的 ALPN 值 (例如 `h3`, `h2`)。
5. **网络栈:**  浏览器使用 IP 地址 `93.184.216.34` 和 ALPN 值来建立与 `example.com` 服务器的 HTTPS 连接。
6. **JavaScript:**  `fetch()` API 成功建立连接并可以获取 `example.com` 的内容。

**逻辑推理，假设输入与输出：**

**假设输入:**

* **查询类型:** `DnsQueryType::A`
* **DNS 响应内容 (简化):**
  ```
  ;; ANSWER SECTION:
  example.com.      3600    IN      A       93.184.216.34
  ```
* **当前时间:** 某个特定的 `base::Time` 和 `base::TimeTicks`。

**假设输出:**

一个包含一个 `HostResolverInternalDataResult` 对象的集合，该对象包含以下信息：

* **主机名:** `example.com`
* **查询类型:** `DnsQueryType::A`
* **到期时间 (TimeTicks):**  当前时间 + 3600 秒
* **到期时间 (Time):** 当前时间 + 3600 秒
* **来源:** `Source::kDns`
* **IP 端点:** `[93.184.216.34]:0`
* **其他字段 (例如别名、SRV 目标列表):** 空

**假设输入 (HTTPS 查询):**

* **查询类型:** `DnsQueryType::HTTPS`
* **原始域名:** `example.com`
* **请求端口:** 443
* **DNS 响应内容 (简化):**
  ```
  ;; ANSWER SECTION:
  example.com.      3600    IN      HTTPS     1 . alpn="h3,h2"
  ```
* **当前时间:** 某个特定的 `base::Time` 和 `base::TimeTicks`。

**假设输出:**

一个包含一个 `HostResolverInternalMetadataResult` 对象的集合，该对象包含以下信息：

* **主机名:** `example.com`
* **查询类型:** `DnsQueryType::HTTPS`
* **到期时间 (TimeTicks):** 当前时间 + 3600 秒
* **到期时间 (Time):** 当前时间 + 3600 秒
* **来源:** `Source::kDns`
* **元数据:** 一个包含优先级为 1，ALPN 列表为 `["h3", "h2"]` 的 `ConnectionEndpointMetadata` 对象。

**用户或编程常见的使用错误：**

* **用户错误:**
    * **错误的 DNS 服务器配置:** 用户配置了错误的 DNS 服务器地址，导致无法解析域名或收到错误的 DNS 响应，`dns_response_result_extractor.cc` 会尝试解析这些错误的响应，可能会产生 `ExtractionError`。
    * **本地 DNS 缓存污染:**  本地 DNS 缓存中存在过期的或错误的记录，导致浏览器使用旧的结果，尽管 `dns_response_result_extractor.cc` 本身没有错误，但用户体验会受到影响。
* **编程错误 (通常是 Chromium 开发者):**
    * **未处理新的 DNS 记录类型:**  如果引入了新的 DNS 记录类型，而 `dns_response_result_extractor.cc` 没有相应的解析逻辑，会导致无法正确提取信息。
    * **解析逻辑错误:**  在解析特定类型的 DNS 记录时出现逻辑错误，导致提取出错误的信息。例如，在处理 SRV 记录排序或 HTTPS 记录参数时出现错误。
    * **假设 DNS 响应总是有效的:**  没有充分处理 malformed 的 DNS 响应，可能导致程序崩溃或出现未定义的行为。 例如，`ValidateNamesAndAliases` 函数会检测一些不一致性，但可能存在其他未考虑到的情况。
    * **不正确的 TTL 处理:**  错误地计算或使用 TTL 值可能导致缓存过期时间不正确。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏中输入 URL 或点击链接:** 例如 `https://www.example.com`。
2. **浏览器解析 URL:**  提取出主机名 `www.example.com`。
3. **主机名解析启动:** 浏览器开始解析主机名。这通常会先检查本地缓存 (`HostCache`)。
4. **如果缓存未命中或过期:** 浏览器会发起 DNS 查询。具体的查询类型取决于多种因素，例如是否启用了 HTTPS-RR 等。 通常会先尝试 AAAA 记录，然后是 A 记录。如果访问的是 HTTPS 站点，可能会查询 HTTPS 记录。
5. **DNS 查询发送:**  浏览器将 DNS 查询发送到配置的 DNS 服务器。
6. **DNS 服务器响应:** DNS 服务器返回一个 DNS 响应。
7. **`DnsTransaction` 处理响应:** Chromium 的 `DnsTransaction` 类负责接收 DNS 响应。
8. **`DnsResponseResultExtractor` 被调用:**  `DnsTransaction` 会创建一个 `DnsResponseResultExtractor` 对象，并将接收到的 `DnsResponse` 传递给它。
9. **提取结果:** `DnsResponseResultExtractor` 根据查询类型调用相应的 `Extract...Results` 函数，例如 `ExtractAddressResults` 或 `ExtractHttpsResults`。
10. **创建 `HostResolverInternalResult`:**  提取出的信息被封装成 `HostResolverInternalResult` 对象。
11. **更新 `HostCache`:**  创建的 `HostResolverInternalResult` 对象会被用于更新 DNS 缓存 (`HostCache`)。
12. **建立连接:**  解析出的 IP 地址和协议信息被用于建立与服务器的连接。
13. **数据传输:**  浏览器开始与服务器进行数据传输。

**调试线索:**

* **在 DNS 解析相关的代码中设置断点:**  可以在 `DnsTransaction::ProcessResponse()` 或 `DnsResponseResultExtractor::ExtractDnsResults()` 等关键函数中设置断点，查看 DNS 响应的内容和提取过程。
* **使用 `net-internals` 工具:** Chrome 的 `chrome://net-internals/#dns` 页面可以查看 DNS 查询的详细信息，包括发送的查询、接收到的响应以及缓存的状态。
* **抓包分析:** 使用 Wireshark 等工具抓取网络包，可以查看实际的 DNS 查询和响应内容，验证浏览器发送和接收的数据是否符合预期。
* **查看日志:** Chromium 的网络栈会输出大量的日志信息，可以启用相关的日志选项来查看 DNS 解析过程的详细信息。
* **检查 `HostCache` 的状态:**  可以使用 `chrome://net-internals/#sockets` 或相关的调试工具查看 `HostCache` 的内容，确认 DNS 结果是否被正确缓存。

总而言之，`net/dns/dns_response_result_extractor.cc` 是 Chromium 网络栈中一个至关重要的组件，它负责将底层的 DNS 响应数据转换为上层可以理解和使用的结果，为浏览器建立网络连接奠定了基础。

### 提示词
```
这是目录为net/dns/dns_response_result_extractor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_response_result_extractor.h"

#include <limits.h>
#include <stdint.h>

#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "base/check.h"
#include "base/containers/contains.h"
#include "base/dcheck_is_on.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/ostream_operators.h"
#include "base/rand_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "base/time/clock.h"
#include "base/time/time.h"
#include "net/base/address_list.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/dns/dns_alias_utility.h"
#include "net/dns/dns_names_util.h"
#include "net/dns/dns_response.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/record_parsed.h"
#include "net/dns/record_rdata.h"

namespace net {

namespace {

using AliasMap = std::map<std::string,
                          std::unique_ptr<const RecordParsed>,
                          dns_names_util::DomainNameComparator>;
using ExtractionError = DnsResponseResultExtractor::ExtractionError;
using RecordsOrError =
    base::expected<std::vector<std::unique_ptr<const RecordParsed>>,
                   ExtractionError>;
using ResultsOrError = DnsResponseResultExtractor::ResultsOrError;
using Source = HostResolverInternalResult::Source;

void SaveMetricsForAdditionalHttpsRecord(const RecordParsed& record,
                                         bool is_unsolicited) {
  const HttpsRecordRdata* rdata = record.rdata<HttpsRecordRdata>();
  DCHECK(rdata);

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class UnsolicitedHttpsRecordStatus {
    kMalformed = 0,  // No longer recorded.
    kAlias = 1,
    kService = 2,
    kMaxValue = kService
  } status;

  if (rdata->IsAlias()) {
    status = UnsolicitedHttpsRecordStatus::kAlias;
  } else {
    status = UnsolicitedHttpsRecordStatus::kService;
  }

  if (is_unsolicited) {
    UMA_HISTOGRAM_ENUMERATION("Net.DNS.DnsTask.AdditionalHttps.Unsolicited",
                              status);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Net.DNS.DnsTask.AdditionalHttps.Requested",
                              status);
  }
}

// Sort service targets per RFC2782.  In summary, sort first by `priority`,
// lowest first.  For targets with the same priority, secondary sort randomly
// using `weight` with higher weighted objects more likely to go first.
std::vector<HostPortPair> SortServiceTargets(
    const std::vector<const SrvRecordRdata*>& rdatas) {
  std::map<uint16_t, std::unordered_set<const SrvRecordRdata*>>
      ordered_by_priority;
  for (const SrvRecordRdata* rdata : rdatas) {
    ordered_by_priority[rdata->priority()].insert(rdata);
  }

  std::vector<HostPortPair> sorted_targets;
  for (auto& priority : ordered_by_priority) {
    // With (num results) <= UINT16_MAX (and in practice, much less) and
    // (weight per result) <= UINT16_MAX, then it should be the case that
    // (total weight) <= UINT32_MAX, but use CheckedNumeric for extra safety.
    auto total_weight = base::MakeCheckedNum<uint32_t>(0);
    for (const SrvRecordRdata* rdata : priority.second) {
      total_weight += rdata->weight();
    }

    // Add 1 to total weight because, to deal with 0-weight targets, we want
    // our random selection to be inclusive [0, total].
    total_weight++;

    // Order by weighted random. Make such random selections, removing from
    // |priority.second| until |priority.second| only contains 1 rdata.
    while (priority.second.size() >= 2) {
      uint32_t random_selection =
          base::RandGenerator(total_weight.ValueOrDie());
      const SrvRecordRdata* selected_rdata = nullptr;
      for (const SrvRecordRdata* rdata : priority.second) {
        // >= to always select the first target on |random_selection| == 0,
        // even if its weight is 0.
        if (rdata->weight() >= random_selection) {
          selected_rdata = rdata;
          break;
        }
        random_selection -= rdata->weight();
      }

      DCHECK(selected_rdata);
      sorted_targets.emplace_back(selected_rdata->target(),
                                  selected_rdata->port());
      total_weight -= selected_rdata->weight();
      size_t removed = priority.second.erase(selected_rdata);
      DCHECK_EQ(1u, removed);
    }

    DCHECK_EQ(1u, priority.second.size());
    DCHECK_EQ((total_weight - 1).ValueOrDie(),
              (*priority.second.begin())->weight());
    const SrvRecordRdata* rdata = *priority.second.begin();
    sorted_targets.emplace_back(rdata->target(), rdata->port());
  }

  return sorted_targets;
}

// Validates that all `aliases` form a single non-looping chain, starting from
// `query_name` and that all alias records are valid. Also validates that all
// `data_records` are at the final name at the end of the alias chain.
// TODO(crbug.com/40245250): Consider altering chain TTLs so that each TTL is
// less than or equal to all previous links in the chain.
ExtractionError ValidateNamesAndAliases(
    std::string_view query_name,
    const AliasMap& aliases,
    const std::vector<std::unique_ptr<const RecordParsed>>& data_records,
    std::string& out_final_chain_name) {
  // Validate that all aliases form a single non-looping chain, starting from
  // `query_name`.
  size_t aliases_in_chain = 0;
  std::string target_name =
      dns_names_util::UrlCanonicalizeNameIfAble(query_name);
  for (auto alias = aliases.find(target_name);
       alias != aliases.end() && aliases_in_chain <= aliases.size();
       alias = aliases.find(target_name)) {
    aliases_in_chain++;

    const CnameRecordRdata* cname_data =
        alias->second->rdata<CnameRecordRdata>();
    if (!cname_data) {
      return ExtractionError::kMalformedCname;
    }

    target_name =
        dns_names_util::UrlCanonicalizeNameIfAble(cname_data->cname());
    if (!dns_names_util::IsValidDnsRecordName(target_name)) {
      return ExtractionError::kMalformedCname;
    }
  }

  if (aliases_in_chain != aliases.size()) {
    return ExtractionError::kBadAliasChain;
  }

  // All records must match final alias name.
  for (const auto& record : data_records) {
    DCHECK_NE(record->type(), dns_protocol::kTypeCNAME);
    if (!base::EqualsCaseInsensitiveASCII(
            target_name,
            dns_names_util::UrlCanonicalizeNameIfAble(record->name()))) {
      return ExtractionError::kNameMismatch;
    }
  }

  out_final_chain_name = std::move(target_name);
  return ExtractionError::kOk;
}

// Common results (aliases and errors) are extracted into
// `out_non_data_results`.
RecordsOrError ExtractResponseRecords(
    const DnsResponse& response,
    DnsQueryType query_type,
    base::Time now,
    base::TimeTicks now_ticks,
    std::set<std::unique_ptr<HostResolverInternalResult>>&
        out_non_data_results) {
  DCHECK_EQ(response.question_count(), 1u);

  std::vector<std::unique_ptr<const RecordParsed>> data_records;
  std::optional<base::TimeDelta> response_ttl;

  DnsRecordParser parser = response.Parser();

  // Expected to be validated by DnsTransaction.
  DCHECK_EQ(DnsQueryTypeToQtype(query_type), response.GetSingleQType());

  AliasMap aliases;
  for (unsigned i = 0; i < response.answer_count(); ++i) {
    std::unique_ptr<const RecordParsed> record =
        RecordParsed::CreateFrom(&parser, now);

    if (!record || !dns_names_util::IsValidDnsRecordName(record->name())) {
      return base::unexpected(ExtractionError::kMalformedRecord);
    }

    if (record->klass() == dns_protocol::kClassIN &&
        record->type() == dns_protocol::kTypeCNAME) {
      std::string canonicalized_name =
          dns_names_util::UrlCanonicalizeNameIfAble(record->name());
      DCHECK(dns_names_util::IsValidDnsRecordName(canonicalized_name));

      bool added =
          aliases.emplace(canonicalized_name, std::move(record)).second;
      // Per RFC2181, multiple CNAME records are not allowed for the same name.
      if (!added) {
        return base::unexpected(ExtractionError::kMultipleCnames);
      }
    } else if (record->klass() == dns_protocol::kClassIN &&
               record->type() == DnsQueryTypeToQtype(query_type)) {
      base::TimeDelta ttl = base::Seconds(record->ttl());
      response_ttl =
          std::min(response_ttl.value_or(base::TimeDelta::Max()), ttl);

      data_records.push_back(std::move(record));
    }
  }

  std::string final_chain_name;
  ExtractionError name_and_alias_validation_error = ValidateNamesAndAliases(
      response.GetSingleDottedName(), aliases, data_records, final_chain_name);
  if (name_and_alias_validation_error != ExtractionError::kOk) {
    return base::unexpected(name_and_alias_validation_error);
  }

  std::set<std::unique_ptr<HostResolverInternalResult>> non_data_results;
  for (const auto& alias : aliases) {
    DCHECK(alias.second->rdata<CnameRecordRdata>());
    non_data_results.insert(std::make_unique<HostResolverInternalAliasResult>(
        alias.first, query_type, now_ticks + base::Seconds(alias.second->ttl()),
        now + base::Seconds(alias.second->ttl()), Source::kDns,
        alias.second->rdata<CnameRecordRdata>()->cname()));
  }

  std::optional<base::TimeDelta> error_ttl;
  for (unsigned i = 0; i < response.authority_count(); ++i) {
    DnsResourceRecord record;
    if (!parser.ReadRecord(&record)) {
      // Stop trying to process records if things get malformed in the authority
      // section.
      break;
    }

    if (record.type == dns_protocol::kTypeSOA) {
      base::TimeDelta ttl = base::Seconds(record.ttl);
      error_ttl = std::min(error_ttl.value_or(base::TimeDelta::Max()), ttl);
    }
  }

  // For NXDOMAIN or NODATA (NOERROR with 0 answers matching the qtype), cache
  // an error if an error TTL was found from SOA records. Also, ignore the error
  // if we somehow have result records (most likely if the server incorrectly
  // sends NXDOMAIN with results). Note that, per the weird QNAME definition in
  // RFC2308, section 1, as well as the clarifications in RFC6604, section 3,
  // and in RFC8020, section 2, the cached error is specific to the final chain
  // name, not the query name.
  //
  // TODO(ericorth@chromium.org): Differentiate nxdomain errors by making it
  // cacheable across any query type (per RFC2308, Section 5).
  bool is_cachable_error = data_records.empty() &&
                           (response.rcode() == dns_protocol::kRcodeNXDOMAIN ||
                            response.rcode() == dns_protocol::kRcodeNOERROR);
  if (is_cachable_error && error_ttl.has_value()) {
    non_data_results.insert(std::make_unique<HostResolverInternalErrorResult>(
        final_chain_name, query_type, now_ticks + error_ttl.value(),
        now + error_ttl.value(), Source::kDns, ERR_NAME_NOT_RESOLVED));
  }

  for (unsigned i = 0; i < response.additional_answer_count(); ++i) {
    std::unique_ptr<const RecordParsed> record =
        RecordParsed::CreateFrom(&parser, base::Time::Now());
    if (record && record->klass() == dns_protocol::kClassIN &&
        record->type() == dns_protocol::kTypeHttps) {
      bool is_unsolicited = query_type != DnsQueryType::HTTPS;
      SaveMetricsForAdditionalHttpsRecord(*record, is_unsolicited);
    }
  }

  out_non_data_results = std::move(non_data_results);
  return data_records;
}

ResultsOrError ExtractAddressResults(const DnsResponse& response,
                                     DnsQueryType query_type,
                                     base::Time now,
                                     base::TimeTicks now_ticks) {
  DCHECK_EQ(response.question_count(), 1u);
  DCHECK(query_type == DnsQueryType::A || query_type == DnsQueryType::AAAA);

  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  RecordsOrError records =
      ExtractResponseRecords(response, query_type, now, now_ticks, results);
  if (!records.has_value()) {
    return base::unexpected(records.error());
  }

  std::vector<IPEndPoint> ip_endpoints;
  auto min_ttl = base::TimeDelta::Max();
  for (const auto& record : records.value()) {
    IPAddress address;
    if (query_type == DnsQueryType::A) {
      const ARecordRdata* rdata = record->rdata<ARecordRdata>();
      DCHECK(rdata);
      address = rdata->address();
      DCHECK(address.IsIPv4());
    } else {
      DCHECK_EQ(query_type, DnsQueryType::AAAA);
      const AAAARecordRdata* rdata = record->rdata<AAAARecordRdata>();
      DCHECK(rdata);
      address = rdata->address();
      DCHECK(address.IsIPv6());
    }
    ip_endpoints.emplace_back(address, /*port=*/0);

    base::TimeDelta ttl = base::Seconds(record->ttl());
    min_ttl = std::min(ttl, min_ttl);
  }

  if (!ip_endpoints.empty()) {
    results.insert(std::make_unique<HostResolverInternalDataResult>(
        records->front()->name(), query_type, now_ticks + min_ttl,
        now + min_ttl, Source::kDns, std::move(ip_endpoints),
        std::vector<std::string>{}, std::vector<HostPortPair>{}));
  }

  return results;
}

ResultsOrError ExtractTxtResults(const DnsResponse& response,
                                 base::Time now,
                                 base::TimeTicks now_ticks) {
  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  RecordsOrError txt_records = ExtractResponseRecords(
      response, DnsQueryType::TXT, now, now_ticks, results);
  if (!txt_records.has_value()) {
    return base::unexpected(txt_records.error());
  }

  std::vector<std::string> strings;
  base::TimeDelta min_ttl = base::TimeDelta::Max();
  for (const auto& record : txt_records.value()) {
    const TxtRecordRdata* rdata = record->rdata<net::TxtRecordRdata>();
    DCHECK(rdata);
    strings.insert(strings.end(), rdata->texts().begin(), rdata->texts().end());

    base::TimeDelta ttl = base::Seconds(record->ttl());
    min_ttl = std::min(ttl, min_ttl);
  }

  if (!strings.empty()) {
    results.insert(std::make_unique<HostResolverInternalDataResult>(
        txt_records->front()->name(), DnsQueryType::TXT, now_ticks + min_ttl,
        now + min_ttl, Source::kDns, std::vector<IPEndPoint>{},
        std::move(strings), std::vector<HostPortPair>{}));
  }

  return results;
}

ResultsOrError ExtractPointerResults(const DnsResponse& response,
                                     base::Time now,
                                     base::TimeTicks now_ticks) {
  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  RecordsOrError ptr_records = ExtractResponseRecords(
      response, DnsQueryType::PTR, now, now_ticks, results);
  if (!ptr_records.has_value()) {
    return base::unexpected(ptr_records.error());
  }

  std::vector<HostPortPair> pointers;
  auto min_ttl = base::TimeDelta::Max();
  for (const auto& record : ptr_records.value()) {
    const PtrRecordRdata* rdata = record->rdata<net::PtrRecordRdata>();
    DCHECK(rdata);
    std::string pointer = rdata->ptrdomain();

    // Skip pointers to the root domain.
    if (!pointer.empty()) {
      pointers.emplace_back(std::move(pointer), 0);

      base::TimeDelta ttl = base::Seconds(record->ttl());
      min_ttl = std::min(ttl, min_ttl);
    }
  }

  if (!pointers.empty()) {
    results.insert(std::make_unique<HostResolverInternalDataResult>(
        ptr_records->front()->name(), DnsQueryType::PTR, now_ticks + min_ttl,
        now + min_ttl, Source::kDns, std::vector<IPEndPoint>{},
        std::vector<std::string>{}, std::move(pointers)));
  }

  return results;
}

ResultsOrError ExtractServiceResults(const DnsResponse& response,
                                     base::Time now,
                                     base::TimeTicks now_ticks) {
  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  RecordsOrError srv_records = ExtractResponseRecords(
      response, DnsQueryType::SRV, now, now_ticks, results);
  if (!srv_records.has_value()) {
    return base::unexpected(srv_records.error());
  }

  std::vector<const SrvRecordRdata*> fitered_rdatas;
  auto min_ttl = base::TimeDelta::Max();
  for (const auto& record : srv_records.value()) {
    const SrvRecordRdata* rdata = record->rdata<net::SrvRecordRdata>();
    DCHECK(rdata);

    // Skip pointers to the root domain.
    if (!rdata->target().empty()) {
      fitered_rdatas.push_back(rdata);

      base::TimeDelta ttl = base::Seconds(record->ttl());
      min_ttl = std::min(ttl, min_ttl);
    }
  }

  std::vector<HostPortPair> ordered_service_targets =
      SortServiceTargets(fitered_rdatas);

  if (!ordered_service_targets.empty()) {
    results.insert(std::make_unique<HostResolverInternalDataResult>(
        srv_records->front()->name(), DnsQueryType::SRV, now_ticks + min_ttl,
        now + min_ttl, Source::kDns, std::vector<IPEndPoint>{},
        std::vector<std::string>{}, std::move(ordered_service_targets)));
  }

  return results;
}

const RecordParsed* UnwrapRecordPtr(
    const std::unique_ptr<const RecordParsed>& ptr) {
  return ptr.get();
}

bool RecordIsAlias(const RecordParsed* record) {
  DCHECK(record->rdata<HttpsRecordRdata>());
  return record->rdata<HttpsRecordRdata>()->IsAlias();
}

ResultsOrError ExtractHttpsResults(const DnsResponse& response,
                                   std::string_view original_domain_name,
                                   uint16_t request_port,
                                   base::Time now,
                                   base::TimeTicks now_ticks) {
  DCHECK(!original_domain_name.empty());

  std::set<std::unique_ptr<HostResolverInternalResult>> results;
  RecordsOrError https_records = ExtractResponseRecords(
      response, DnsQueryType::HTTPS, now, now_ticks, results);
  if (!https_records.has_value()) {
    return base::unexpected(https_records.error());
  }

  // Min TTL among records of full use to Chrome.
  std::optional<base::TimeDelta> min_ttl;

  // Min TTL among all records considered compatible with Chrome, per
  // RFC9460#section-8.
  std::optional<base::TimeDelta> min_compatible_ttl;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadatas;
  bool compatible_record_found = false;
  bool default_alpn_found = false;
  for (const auto& record : https_records.value()) {
    const HttpsRecordRdata* rdata = record->rdata<HttpsRecordRdata>();
    DCHECK(rdata);

    base::TimeDelta ttl = base::Seconds(record->ttl());

    // Chrome does not yet support alias records.
    if (rdata->IsAlias()) {
      // Alias records are always considered compatible because they do not
      // support "mandatory" params.
      compatible_record_found = true;
      min_compatible_ttl =
          std::min(ttl, min_compatible_ttl.value_or(base::TimeDelta::Max()));

      continue;
    }

    const ServiceFormHttpsRecordRdata* service = rdata->AsServiceForm();
    if (service->IsCompatible()) {
      compatible_record_found = true;
      min_compatible_ttl =
          std::min(ttl, min_compatible_ttl.value_or(base::TimeDelta::Max()));
    } else {
      // Ignore services incompatible with Chrome's HTTPS record parser.
      // draft-ietf-dnsop-svcb-https-12#section-8
      continue;
    }

    std::string target_name = dns_names_util::UrlCanonicalizeNameIfAble(
        service->service_name().empty() ? record->name()
                                        : service->service_name());

    // Chrome does not yet support followup queries. So only support services at
    // the original domain name or the canonical name (the record name).
    // Note: HostCache::Entry::GetEndpoints() will not return metadatas which
    // target name is different from the canonical name of A/AAAA query results.
    if (!base::EqualsCaseInsensitiveASCII(
            target_name,
            dns_names_util::UrlCanonicalizeNameIfAble(original_domain_name)) &&
        !base::EqualsCaseInsensitiveASCII(
            target_name,
            dns_names_util::UrlCanonicalizeNameIfAble(record->name()))) {
      continue;
    }

    // Ignore services at a different port from the request port. Chrome does
    // not yet support endpoints diverging by port.  Note that before supporting
    // port redirects, Chrome must ensure redirects to the "bad port list" are
    // disallowed. Unclear if such logic would belong here or in socket
    // connection logic.
    if (service->port().has_value() &&
        service->port().value() != request_port) {
      continue;
    }

    ConnectionEndpointMetadata metadata;

    metadata.supported_protocol_alpns = service->alpn_ids();
    if (service->default_alpn() &&
        !base::Contains(metadata.supported_protocol_alpns,
                        dns_protocol::kHttpsServiceDefaultAlpn)) {
      metadata.supported_protocol_alpns.push_back(
          dns_protocol::kHttpsServiceDefaultAlpn);
    }

    // Services with no supported ALPNs (those with "no-default-alpn" and no or
    // empty "alpn") are not self-consistent and are rejected.
    // draft-ietf-dnsop-svcb-https-12#section-7.1.1 and
    // draft-ietf-dnsop-svcb-https-12#section-2.4.3.
    if (metadata.supported_protocol_alpns.empty()) {
      continue;
    }

    metadata.ech_config_list = ConnectionEndpointMetadata::EchConfigList(
        service->ech_config().cbegin(), service->ech_config().cend());

    metadata.target_name = std::move(target_name);

    metadatas.emplace(service->priority(), std::move(metadata));

    min_ttl = std::min(ttl, min_ttl.value_or(base::TimeDelta::Max()));

    if (service->default_alpn()) {
      default_alpn_found = true;
    }
  }

  // Ignore all records if any are an alias record. Chrome does not yet support
  // alias records, but aliases take precedence over any other records.
  if (base::ranges::any_of(https_records.value(), &RecordIsAlias,
                           &UnwrapRecordPtr)) {
    metadatas.clear();
  }

  // Ignore all records if they all mark "no-default-alpn". Domains should
  // always provide at least one endpoint allowing default ALPN to ensure a
  // reasonable expectation of connection success.
  // draft-ietf-dnsop-svcb-https-12#section-7.1.2
  if (!default_alpn_found) {
    metadatas.clear();
  }

  if (metadatas.empty() && compatible_record_found) {
    // Empty metadata result signifies that compatible HTTPS records were
    // received but with no contained metadata of use to Chrome. Use the min TTL
    // of all compatible records.
    CHECK(min_compatible_ttl.has_value());
    results.insert(std::make_unique<HostResolverInternalMetadataResult>(
        https_records->front()->name(), DnsQueryType::HTTPS,
        now_ticks + min_compatible_ttl.value(),
        now + min_compatible_ttl.value(), Source::kDns,
        /*metadatas=*/
        std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{}));
  } else if (!metadatas.empty()) {
    // Use min TTL only of those records contributing useful metadata.
    CHECK(min_ttl.has_value());
    results.insert(std::make_unique<HostResolverInternalMetadataResult>(
        https_records->front()->name(), DnsQueryType::HTTPS,
        now_ticks + min_ttl.value(), now + min_ttl.value(), Source::kDns,
        std::move(metadatas)));
  }

  return results;
}

}  // namespace

DnsResponseResultExtractor::DnsResponseResultExtractor(
    const DnsResponse& response,
    const base::Clock& clock,
    const base::TickClock& tick_clock)
    : response_(response), clock_(clock), tick_clock_(tick_clock) {}

DnsResponseResultExtractor::~DnsResponseResultExtractor() = default;

ResultsOrError DnsResponseResultExtractor::ExtractDnsResults(
    DnsQueryType query_type,
    std::string_view original_domain_name,
    uint16_t request_port) const {
  DCHECK(!original_domain_name.empty());

  switch (query_type) {
    case DnsQueryType::UNSPECIFIED:
      // Should create multiple transactions with specified types.
      NOTREACHED();
    case DnsQueryType::A:
    case DnsQueryType::AAAA:
      return ExtractAddressResults(*response_, query_type, clock_->Now(),
                                   tick_clock_->NowTicks());
    case DnsQueryType::TXT:
      return ExtractTxtResults(*response_, clock_->Now(),
                               tick_clock_->NowTicks());
    case DnsQueryType::PTR:
      return ExtractPointerResults(*response_, clock_->Now(),
                                   tick_clock_->NowTicks());
    case DnsQueryType::SRV:
      return ExtractServiceResults(*response_, clock_->Now(),
                                   tick_clock_->NowTicks());
    case DnsQueryType::HTTPS:
      return ExtractHttpsResults(*response_, original_domain_name, request_port,
                                 clock_->Now(), tick_clock_->NowTicks());
  }
}

}  // namespace net
```