Response:
The user wants a summary of the provided C++ code file `net/dns/host_resolver_manager_unittest.cc` from the Chromium project. The request specifies several aspects to cover in the summary:

1. **Functionality:** What does the code do?
2. **Relationship to JavaScript:**  Does the code interact with JavaScript in any way?
3. **Logical Inference:** Provide examples of inputs and outputs if logical deductions are made.
4. **Common Usage Errors:**  Illustrate potential mistakes users or programmers could make.
5. **User Interaction (Debugging Clue):** Describe how a user's actions could lead to this code being executed.
6. **Overall Function:**  A concise summary of the file's purpose.
7. **Part Number:** Acknowledge that this is part 5 of 21.

**Mental Model:**

The code appears to be a unit test file for the `HostResolverManager` component in Chromium's network stack. It focuses specifically on testing the Multicast DNS (mDNS) functionality. The presence of `kMdnsResponse*` constants strongly suggests this.

**Plan:**

1. **Identify Core Functionality:** The primary purpose is to test how `HostResolverManager` handles mDNS responses for various record types (A, AAAA, TXT, PTR, SRV, NSEC) and scenarios (successful resolution, timeouts, cancellations, errors).
2. **JavaScript Relationship:**  Consider how mDNS resolution might be triggered in a browser context. While this C++ code doesn't directly execute JavaScript, the results of mDNS resolution *are* used by the browser, potentially in network requests initiated by JavaScript.
3. **Logical Inference:** The test functions clearly demonstrate input (simulated mDNS responses) and expected output (the resolved addresses, text records, etc.).
4. **Common Usage Errors:** Think about common pitfalls in network configuration or application logic that could lead to mDNS resolution issues.
5. **User Interaction:**  Trace the steps a user might take that would involve mDNS, such as accessing a `.local` domain.
6. **Overall Function:**  Summarize the file as a unit test suite for the mDNS capabilities of the `HostResolverManager`.
7. **Part Number:** State that this is part 5/21.

**Detailed Breakdown and Pre-computation:**

* **mDNS Response Constants:**  Analyze the structure of the `kMdnsResponse*` constants. They represent encoded DNS response packets.
* **Test Functions:** Each `TEST_F` function sets up a test scenario, often involving mocking the mDNS socket factory to simulate receiving specific responses. The `EXPECT_THAT` macros assert the expected outcomes.
* **`HostResolver::ResolveHostParameters`:**  Note how different parameters are set to test various mDNS scenarios (e.g., `source = HostResolverSource::MULTICAST_DNS`, `dns_query_type`).
* **`MockMDnsSocketFactory`:** This mock object is crucial for controlling the simulated network interactions.
* **JavaScript Connection:**  Consider the scenario where a web page on a local network uses JavaScript to fetch resources from a `.local` domain. The browser would use its network stack, including the `HostResolverManager`, to resolve the hostname via mDNS.
* **User Errors:** Incorrect local network configuration, firewalls blocking mDNS traffic, or the target device not properly implementing mDNS are potential user errors.

**Self-Correction/Refinement:**

Initially, I might focus too narrowly on the C++ code itself. It's important to connect it to the broader browser context and how it relates to user actions and JavaScript. The request specifically asks for this connection. The mocking framework is central to understanding how these tests function.

Strategizing complete. I will now proceed with generating the response based on this plan.
这是目录为 `net/dns/host_resolver_manager_unittest.cc` 的 Chromium 网络栈的源代码文件，它专门用于测试 `HostResolverManager` 组件的 mDNS（Multicast DNS）功能。以下是它的功能归纳：

**功能列举:**

1. **测试 mDNS 地址解析 (A 和 AAAA 记录):** 验证 `HostResolverManager` 能否正确解析 mDNS 响应中的 IPv4 (A 记录) 和 IPv6 (AAAA 记录) 地址。它模拟接收 mDNS 响应，并断言解析出的 IP 地址是否与预期一致。
2. **测试指定类型的 mDNS 查询:**  测试可以发起针对特定 DNS 记录类型的 mDNS 查询，例如只查询 AAAA 记录或 TXT 记录。
3. **测试 mDNS 文本记录 (TXT 记录) 解析:**  验证 `HostResolverManager` 能否正确解析 mDNS 响应中的文本记录。
4. **测试 mDNS 指针记录 (PTR 记录) 解析:** 验证 `HostResolverManager` 能否正确解析 mDNS 响应中的 PTR 记录，用于反向 DNS 查找，并将解析结果转换为 `HostPortPair`。
5. **测试 mDNS 服务记录 (SRV 记录) 解析:** 验证 `HostResolverManager` 能否正确解析 mDNS 响应中的 SRV 记录，提取目标主机和端口信息。
6. **测试包含特殊字符的主机名解析:** 验证 `HostResolverManager` 是否能够处理包含空格和括号等非标准 DNS 字符的主机名。
7. **测试 mDNS 否定响应 (NSEC 记录):** 验证 `HostResolverManager` 如何处理表示记录不存在的 NSEC 记录，并返回 `ERR_NAME_NOT_RESOLVED` 错误。
8. **测试 mDNS 超时处理:** 模拟在指定时间内没有收到 mDNS 响应的情况，验证 `HostResolverManager` 是否会超时并返回 `ERR_NAME_NOT_RESOLVED` 错误。
9. **测试接收到错误类型的 mDNS 响应:** 验证 `HostResolverManager` 是否会忽略与当前查询类型不匹配的 mDNS 响应。
10. **测试接收到部分 mDNS 响应:** 验证在请求 A 和 AAAA 记录时，如果只收到其中一种类型的响应，`HostResolverManager` 是否会处理已收到的部分结果并在超时后返回。
11. **测试 mDNS 请求的取消:** 验证可以取消正在进行的 mDNS 解析请求。
12. **测试 mDNS 事务启动失败:** 模拟 mDNS 事务启动失败的情况，验证 `HostResolverManager` 能否正确处理并返回错误。
13. **测试 mDNS 监听失败:** 模拟 mDNS 监听器启动失败的情况，验证 `HostResolverManager` 能否正确处理并返回错误。
14. **测试 mDNS 监听器功能:** 验证 `HostResolverManager` 的 mDNS 监听器功能，可以接收和处理实时的 mDNS 广播消息，并将其传递给委托对象。这包括处理地址 (A/AAAA)、文本 (TXT) 和主机名 (PTR/SRV) 记录的更新（添加和移除）。

**与 JavaScript 的关系举例:**

虽然这个 C++ 代码文件本身不包含 JavaScript 代码，但它测试的网络功能直接影响到 JavaScript 在浏览器中的网络请求行为。

**举例说明:**

假设一个局域网内的设备，其主机名为 `myhello.local`，并通过 mDNS 广播其 IP 地址。在网页的 JavaScript 代码中，尝试访问该设备：

```javascript
fetch('http://myhello.local:80/');
```

1. **用户操作:** 用户在浏览器的地址栏输入或点击一个链接指向 `http://myhello.local:80/` 的网页。
2. **浏览器行为:** 浏览器需要解析 `myhello.local` 这个主机名。
3. **到达 `HostResolverManager`:**  浏览器会调用网络栈中的 `HostResolverManager` 来解析主机名。
4. **mDNS 查询:** 如果配置允许，并且主机名看起来像本地主机 (例如以 `.local` 结尾)，`HostResolverManager` 可能会发起一个 mDNS 查询。
5. **`host_resolver_manager_unittest.cc` 的作用:**  这个测试文件中的测试用例模拟了接收到 `kMdnsResponseA` 或 `kMdnsResponseAAAA` 这样的 mDNS 响应，验证 `HostResolverManager` 能否从中正确提取 `1.2.3.4` 或 `000a:0000:0000:0000:0001:0002:0003:0004` 这样的 IP 地址。
6. **JavaScript 的结果:**  一旦 `HostResolverManager` 解析出 IP 地址，浏览器就可以向该 IP 地址的 80 端口发起 HTTP 请求，JavaScript 的 `fetch` 操作才能成功完成。

**逻辑推理的假设输入与输出:**

**假设输入:**  模拟接收到以下 mDNS 响应 (与 `kMdnsResponseTxt` 相同):

```
const uint8_t kMdnsResponseTxtExample[] = {
    // Header ... (省略)
    // "myhello.local." ... (省略)
    0x00, 0x10,              // TYPE is TXT.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x11,  // TTL is 17 (seconds)
    0x00, 0x08,              // RDLENGTH is 8 bytes.
    0x03, 0x66, 0x6f, 0x6f,  // "foo"
    0x03, 0x62, 0x61, 0x72   // "bar"
};
```

**假设输出:**  当 `HostResolverManager` 处理这个响应时，对于一个请求 `myhello.local` 的 TXT 记录的解析请求，预期会得到一个包含字符串 "foo" 和 "bar" 的文本记录列表。在测试代码中，这会被断言：

```c++
EXPECT_THAT(response.request()->GetTextResults(),
            testing::Pointee(testing::ElementsAre("foo", "bar")));
```

**用户或编程常见的使用错误举例:**

1. **网络配置错误:** 用户的本地网络没有正确配置 mDNS 服务，导致无法接收到 mDNS 响应。这会导致 `HostResolverManager` 超时，最终 JavaScript 的 `fetch` 请求失败。
2. **防火墙阻止 mDNS 流量:** 用户的防火墙设置阻止了 mDNS 使用的 UDP 端口 (通常是 5353) 的流量，导致无法进行 mDNS 解析。
3. **主机名拼写错误:**  JavaScript 代码中使用了错误的 `.local` 主机名，导致 `HostResolverManager` 无法找到对应的 mDNS 记录。
4. **目标设备未启用 mDNS:**  局域网内的目标设备没有启用或正确配置 mDNS 服务，因此不会广播其信息，导致解析失败。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 `http://mydevice.local/` 并按下回车。**
2. **浏览器识别出 `.local` 域名，可能触发 mDNS 解析。**
3. **浏览器网络栈中的 `HostResolverManager` 组件被调用。**
4. **`HostResolverManager` 创建一个 mDNS 查询请求。**
5. **底层的 mDNS 实现 (可能涉及 `MDnsClientImpl`) 发送 mDNS 查询报文到本地网络。**
6. **如果网络中存在名为 `mydevice.local` 的设备，它会发送一个 mDNS 响应。**
7. **操作系统接收到 mDNS 响应，并将其传递给浏览器进程。**
8. **`HostResolverManager` 接收并解析 mDNS 响应，例如 `kMdnsResponseA`，从中提取 IP 地址。**
9. **`host_resolver_manager_unittest.cc` 中的测试用例模拟了步骤 6, 7, 8，验证 `HostResolverManager` 的解析逻辑是否正确。**
10. **如果测试失败，开发者可以通过调试 `HostResolverManager` 的代码，查看在接收到特定的 mDNS 响应后，解析逻辑哪里出现了问题。**

**归纳一下它的功能 (作为第 5 部分，共 21 部分):**

这个文件 (`host_resolver_manager_unittest.cc`) 的这部分主要专注于 **测试 `HostResolverManager` 组件处理 Multicast DNS (mDNS) 协议的能力**。它通过模拟发送和接收 mDNS 消息，验证了 `HostResolverManager` 对于不同类型的 DNS 记录 (A, AAAA, TXT, PTR, SRV, NSEC) 的解析、超时处理、错误处理以及监听功能是否正确。  作为单元测试的一部分，它的目的是确保网络栈的 mDNS 功能能够可靠地工作，为浏览器中依赖 mDNS 的功能提供基础保障。

### 提示词
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共21部分，请归纳一下它的功能
```

### 源代码
```cpp
0x00, 0x00, 0x00, 0x10,  // TTL is 16 (seconds)
    0x00, 0x04,              // RDLENGTH is 4 bytes.
    0x01, 0x02, 0x03, 0x04,  // 1.2.3.4
};

const uint8_t kMdnsResponseA2[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x01,              // TYPE is A.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x10,  // TTL is 16 (seconds)
    0x00, 0x04,              // RDLENGTH is 4 bytes.
    0x05, 0x06, 0x07, 0x08,  // 5.6.7.8
};

const uint8_t kMdnsResponseA2Goodbye[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x01,              // TYPE is A.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x00,  // TTL is 0 (signaling "goodbye" removal of result)
    0x00, 0x04,              // RDLENGTH is 4 bytes.
    0x05, 0x06, 0x07, 0x08,  // 5.6.7.8
};

const uint8_t kMdnsResponseAAAA[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x1C,              // TYPE is AAAA.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x10,  // TTL is 16 (seconds)
    0x00, 0x10,              // RDLENGTH is 16 bytes.

    // 000a:0000:0000:0000:0001:0002:0003:0004
    0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
    0x00, 0x03, 0x00, 0x04};

// An MDNS response indicating that the responder owns the hostname, but the
// specific requested type (AAAA) does not exist because the responder only has
// A addresses.
const uint8_t kMdnsResponseNsec[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x2f,              // TYPE is NSEC.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x10,  // TTL is 16 (seconds)
    0x00, 0x06,              // RDLENGTH is 6 bytes.
    0xc0, 0x0c,  // Next Domain Name (always pointer back to name in MDNS)
    0x00,        // Bitmap block number (always 0 in MDNS)
    0x02,        // Bitmap length is 2
    0x00, 0x08   // A type only
};

const uint8_t kMdnsResponseTxt[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x10,              // TYPE is TXT.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x11,  // TTL is 17 (seconds)
    0x00, 0x08,              // RDLENGTH is 8 bytes.

    // "foo"
    0x03, 0x66, 0x6f, 0x6f,
    // "bar"
    0x03, 0x62, 0x61, 0x72};

const uint8_t kMdnsResponsePtr[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x0c,              // TYPE is PTR.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x12,  // TTL is 18 (seconds)
    0x00, 0x09,              // RDLENGTH is 9 bytes.

    // "foo.com."
    0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00};

const uint8_t kMdnsResponsePtrRoot[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x0c,              // TYPE is PTR.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x13,  // TTL is 19 (seconds)
    0x00, 0x01,              // RDLENGTH is 1 byte.

    // "." (the root domain)
    0x00};

const uint8_t kMdnsResponseSrv[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x21,              // TYPE is SRV.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x13,  // TTL is 19 (seconds)
    0x00, 0x0f,              // RDLENGTH is 15 bytes.

    0x00, 0x05,  // Priority 5
    0x00, 0x01,  // Weight 1
    0x20, 0x49,  // Port 8265

    // "foo.com."
    0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00};

const uint8_t kMdnsResponseSrvUnrestricted[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "foo bar(A1B2)._ipps._tcp.local"
    0x0d, 'f', 'o', 'o', ' ', 'b', 'a', 'r', '(', 'A', '1', 'B', '2', ')', 0x05,
    '_', 'i', 'p', 'p', 's', 0x04, '_', 't', 'c', 'p', 0x05, 'l', 'o', 'c', 'a',
    'l', 0x00,

    0x00, 0x21,              // TYPE is SRV.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x13,  // TTL is 19 (seconds)
    0x00, 0x0f,              // RDLENGTH is 15 bytes.

    0x00, 0x05,  // Priority 5
    0x00, 0x01,  // Weight 1
    0x20, 0x49,  // Port 8265

    // "foo.com."
    0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00};

const uint8_t kMdnsResponseSrvUnrestrictedResult[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x21,              // TYPE is SRV.
    0x00, 0x01,              // CLASS is IN.
    0x00, 0x00, 0x00, 0x13,  // TTL is 19 (seconds)
    0x00, 0x15,              // RDLENGTH is 21 bytes.

    0x00, 0x05,  // Priority 5
    0x00, 0x01,  // Weight 1
    0x20, 0x49,  // Port 8265

    // "foo bar.local"
    0x07, 'f', 'o', 'o', ' ', 'b', 'a', 'r', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00};

TEST_F(HostResolverManagerTest, Mdns) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(4);

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponseA, sizeof(kMdnsResponseA));
  socket_factory_ptr->SimulateReceive(kMdnsResponseAAAA,
                                      sizeof(kMdnsResponseAAAA));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(
      response.request()->GetAddressResults()->endpoints(),
      testing::UnorderedElementsAre(
          CreateExpected("1.2.3.4", 80),
          CreateExpected("000a:0000:0000:0000:0001:0002:0003:0004", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("000a:0000:0000:0000:0001:0002:0003:0004", 80),
              CreateExpected("1.2.3.4", 80))))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerTest, Mdns_AaaaOnly) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(2);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::AAAA;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponseAAAA,
                                      sizeof(kMdnsResponseAAAA));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected(
                  "000a:0000:0000:0000:0001:0002:0003:0004", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  ExpectEndpointResult(testing::ElementsAre(CreateExpected(
                      "000a:0000:0000:0000:0001:0002:0003:0004", 80))))));
}

TEST_F(HostResolverManagerTest, Mdns_Txt) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(2);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponseTxt,
                                      sizeof(kMdnsResponseTxt));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              testing::Pointee(testing::ElementsAre("foo", "bar")));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerTest, Mdns_Ptr) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(2);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 83), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponsePtr,
                                      sizeof(kMdnsResponsePtr));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(
      response.request()->GetHostnameResults(),
      testing::Pointee(testing::ElementsAre(HostPortPair("foo.com", 83))));
}

TEST_F(HostResolverManagerTest, Mdns_Srv) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(2);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 83), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponseSrv,
                                      sizeof(kMdnsResponseSrv));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(
      response.request()->GetHostnameResults(),
      testing::Pointee(testing::ElementsAre(HostPortPair("foo.com", 8265))));
}

// Test that we are able to create multicast DNS requests that contain
// characters not permitted in the DNS spec such as spaces and parenthesis.
TEST_F(HostResolverManagerTest, Mdns_Srv_Unrestricted) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("foo bar(A1B2)._ipps._tcp.local", 83),
      NetworkAnonymizationKey(), NetLogWithSource(), parameters,
      resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponseSrvUnrestricted,
                                      sizeof(kMdnsResponseSrvUnrestricted));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(
      response.request()->GetHostnameResults(),
      testing::Pointee(testing::ElementsAre(HostPortPair("foo.com", 8265))));
}

// Test that we are able to create multicast DNS requests that contain
// characters not permitted in the DNS spec such as spaces and parenthesis.
TEST_F(HostResolverManagerTest, Mdns_Srv_Result_Unrestricted) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 83), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(
      kMdnsResponseSrvUnrestrictedResult,
      sizeof(kMdnsResponseSrvUnrestrictedResult));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              testing::Pointee(
                  testing::ElementsAre(HostPortPair("foo bar.local", 8265))));
}

// Test multicast DNS handling of NSEC responses (used for explicit negative
// response).
TEST_F(HostResolverManagerTest, Mdns_Nsec) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(2);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::AAAA;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  socket_factory_ptr->SimulateReceive(kMdnsResponseNsec,
                                      sizeof(kMdnsResponseNsec));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerTest, Mdns_NoResponse) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(4);

  // Add a little bit of extra fudge to the delay to allow reasonable
  // flexibility for time > vs >= etc.  We don't need to fail the test if we
  // timeout at t=6001 instead of t=6000.
  base::TimeDelta kSleepFudgeFactor = base::Milliseconds(1);

  // Override the current thread task runner, so we can simulate the passage of
  // time to trigger the timeout.
  auto test_task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  base::SingleThreadTaskRunner::CurrentHandleOverrideForTesting
      task_runner_current_default_handle_override(test_task_runner);

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  ASSERT_TRUE(test_task_runner->HasPendingTask());
  test_task_runner->FastForwardBy(MDnsTransaction::kTransactionTimeout +
                                  kSleepFudgeFactor);

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  test_task_runner->FastForwardUntilNoTasksRemain();
}

TEST_F(HostResolverManagerTest, Mdns_WrongType) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(2);

  // Add a little bit of extra fudge to the delay to allow reasonable
  // flexibility for time > vs >= etc.  We don't need to fail the test if we
  // timeout at t=6001 instead of t=6000.
  base::TimeDelta kSleepFudgeFactor = base::Milliseconds(1);

  // Override the current thread task runner, so we can simulate the passage of
  // time to trigger the timeout.
  auto test_task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  base::SingleThreadTaskRunner::CurrentHandleOverrideForTesting
      task_runner_current_default_handle_override(test_task_runner);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::A;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  // Not the requested type. Should be ignored.
  socket_factory_ptr->SimulateReceive(kMdnsResponseTxt,
                                      sizeof(kMdnsResponseTxt));

  ASSERT_TRUE(test_task_runner->HasPendingTask());
  test_task_runner->FastForwardBy(MDnsTransaction::kTransactionTimeout +
                                  kSleepFudgeFactor);

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  test_task_runner->FastForwardUntilNoTasksRemain();
}

// Test for a request for both A and AAAA results where results only exist for
// one type.
TEST_F(HostResolverManagerTest, Mdns_PartialResults) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(4);

  // Add a little bit of extra fudge to the delay to allow reasonable
  // flexibility for time > vs >= etc.  We don't need to fail the test if we
  // timeout at t=6001 instead of t=6000.
  base::TimeDelta kSleepFudgeFactor = base::Milliseconds(1);

  // Override the current thread task runner, so we can simulate the passage of
  // time to trigger the timeout.
  auto test_task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  base::SingleThreadTaskRunner::CurrentHandleOverrideForTesting
      task_runner_current_default_handle_override(test_task_runner);

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  ASSERT_TRUE(test_task_runner->HasPendingTask());

  socket_factory_ptr->SimulateReceive(kMdnsResponseA, sizeof(kMdnsResponseA));
  test_task_runner->FastForwardBy(MDnsTransaction::kTransactionTimeout +
                                  kSleepFudgeFactor);

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("1.2.3.4", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("1.2.3.4", 80))))));

  test_task_runner->FastForwardUntilNoTasksRemain();
}

TEST_F(HostResolverManagerTest, Mdns_Cancel) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  MockMDnsSocketFactory* socket_factory_ptr = socket_factory.get();
  resolver_->SetMdnsSocketFactoryForTesting(std::move(socket_factory));
  // 2 socket creations for every transaction.
  EXPECT_CALL(*socket_factory_ptr, OnSendTo(_)).Times(4);

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  response.CancelRequest();

  socket_factory_ptr->SimulateReceive(kMdnsResponseA, sizeof(kMdnsResponseA));
  socket_factory_ptr->SimulateReceive(kMdnsResponseAAAA,
                                      sizeof(kMdnsResponseAAAA));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
}

// Test for a two-transaction query where the first fails to start. The second
// should be cancelled.
TEST_F(HostResolverManagerTest, Mdns_PartialFailure) {
  // Setup a mock MDnsClient where the first transaction will always return
  // |false| immediately on Start(). Second transaction may or may not be
  // created, but if it is, Start() not expected to be called because the
  // overall request should immediately fail.
  auto transaction1 = std::make_unique<MockMDnsTransaction>();
  EXPECT_CALL(*transaction1, Start()).WillOnce(Return(false));
  auto transaction2 = std::make_unique<MockMDnsTransaction>();
  EXPECT_CALL(*transaction2, Start()).Times(0);

  auto client = std::make_unique<MockMDnsClient>();
  EXPECT_CALL(*client, CreateTransaction(_, _, _, _))
      .Times(Between(1, 2))  // Second transaction optionally created.
      .WillOnce(Return(ByMove(std::move(transaction1))))
      .WillOnce(Return(ByMove(std::move(transaction2))));
  EXPECT_CALL(*client, IsListening()).WillRepeatedly(Return(true));
  resolver_->SetMdnsClientForTesting(std::move(client));

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_FAILED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerTest, Mdns_ListenFailure) {
  // Inject an MdnsClient mock that will always fail to start listening.
  auto client = std::make_unique<MockMDnsClient>();
  EXPECT_CALL(*client, StartListening(_)).WillOnce(Return(ERR_FAILED));
  EXPECT_CALL(*client, IsListening()).WillRepeatedly(Return(false));
  resolver_->SetMdnsClientForTesting(std::move(client));

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::MULTICAST_DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("myhello.local", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_FAILED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

// Implementation of HostResolver::MdnsListenerDelegate that records all
// received results in maps.
class TestMdnsListenerDelegate : public HostResolver::MdnsListener::Delegate {
 public:
  using UpdateKey = std::pair<MdnsListenerUpdateType, DnsQueryType>;

  void OnAddressResult(MdnsListenerUpdateType update_type,
                       DnsQueryType result_type,
                       IPEndPoint address) override {
    address_results_.insert({{update_type, result_type}, address});
  }

  void OnTextResult(MdnsListenerUpdateType update_type,
                    DnsQueryType result_type,
                    std::vector<std::string> text_records) override {
    for (auto& text_record : text_records) {
      text_results_.insert(
          {{update_type, result_type}, std::move(text_record)});
    }
  }

  void OnHostnameResult(MdnsListenerUpdateType update_type,
                        DnsQueryType result_type,
                        HostPortPair host) override {
    hostname_results_.insert({{update_type, result_type}, std::move(host)});
  }

  void OnUnhandledResult(MdnsListenerUpdateType update_type,
                         DnsQueryType result_type) override {
    unhandled_results_.insert({update_type, result_type});
  }

  const std::multimap<UpdateKey, IPEndPoint>& address_results() {
    return address_results_;
  }

  const std::multimap<UpdateKey, std::string>& text_results() {
    return text_results_;
  }

  const std::multimap<UpdateKey, HostPortPair>& hostname_results() {
    return hostname_results_;
  }

  const std::multiset<UpdateKey>& unhandled_results() {
    return unhandled_results_;
  }

  template <typename T>
  static std::pair<UpdateKey, T> CreateExpectedResult(
      MdnsListenerUpdateType update_type,
      DnsQueryType query_type,
      T result) {
    return std::pair(std::pair(update_type, query_type), result);
  }

 private:
  std::multimap<UpdateKey, IPEndPoint> address_results_;
  std::multimap<UpdateKey, std::string> text_results_;
  std::multimap<UpdateKey, HostPortPair> hostname_results_;
  std::multiset<UpdateKey> unhandled_results_;
};

TEST_F(HostResolverManagerTest, MdnsListener) {
  auto socket_factory = std::make_unique<MockMDnsSocketFactory>();
  base::SimpleTestClock clock;
  clock.SetNow(base::Time::Now());
  auto cache_cleanup_timer = std::make_unique<base::MockOneShotTimer>();
  auto* cache_cleanup_timer_ptr = cache_cleanup_timer.get();
  auto mdns_client =
      std::make_unique<MDnsClientImpl>(&clock, std::move(cache_cleanup_timer));
  ASSERT_THAT(mdns_client->StartListening(socket_factory.get()), IsOk());
  resolver_->SetMdnsClientForTesting(std::move(mdns_client));

  TestMdnsListenerDelegate delegate;
  std::unique_ptr<HostResolver::MdnsListener> listener =
      resolver_->CreateMdnsListener(HostPortPair("myhello.local", 80),
                                    DnsQueryType::A);

  ASSERT_THAT(listener->Start(&delegate), IsOk());
  ASSERT_THAT(delegate.address_results(), testing::IsEmpty());

  socket_factory->SimulateReceive(kMdnsResponseA, sizeof(kMdnsResponseA));
  socket_factory->
```