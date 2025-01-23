Response:
The user wants me to analyze the provided C++ code snippet from `net/dns/dns_response_unittest.cc`. This file seems to contain unit tests for the `DnsResponse` class in Chromium's network stack.

Here's a breakdown of the thought process to address the user's request:

1. **Understand the Core Functionality:** The file name and the test names (`DnsResponseTest`, `DnsResponseWriteTest`) clearly indicate that this code is testing the functionality of the `DnsResponse` class. This likely involves:
    * **Parsing DNS responses:**  Testing how `DnsResponse` handles incoming DNS data.
    * **Writing/constructing DNS responses:** Testing how `DnsResponse` can be used to create DNS response messages.
    * **Validation:** Ensuring that `DnsResponse` correctly handles valid and invalid DNS data.

2. **Identify Key Test Scenarios:**  By examining the individual test names and the code within them, I can identify specific functionalities being tested. For example:
    * `InitParseWithoutQuery` and `InitParse`: These likely test different ways to initialize a `DnsResponse` object from raw data.
    * Tests with "TooLongName", "NonendedName", "MissingQuestions": These are explicitly testing error handling and validation of DNS response structure.
    * Tests with "ParserLimitedToNumClaimedRecords" and "ParserLimitedToBufferSize": These focus on the behavior of the `DnsRecordParser` and its interaction with the `DnsResponse` header.
    * `SingleARecordAnswer`, `SingleQuadARecordAnswer`, etc.: These test the construction of various DNS response types.
    * Tests involving "Question": These verify the handling of the question section in a DNS response.
    * `WrittenResponseCanBeParsed`: This confirms the round-trip process of creating and then parsing a DNS response.

3. **Relate to JavaScript (if applicable):**  DNS is a fundamental part of the internet, and web browsers (which use Chromium's network stack) rely on it. JavaScript in a browser interacts with DNS indirectly through network requests. When a JavaScript application tries to access a website, the browser's underlying network stack handles the DNS resolution. So, while JavaScript doesn't directly manipulate `DnsResponse` objects, the correct functioning of this C++ code is crucial for JavaScript's ability to interact with web resources.

4. **Infer Logical Reasoning (Input/Output):** For many tests, especially the error handling ones, I can infer the intended behavior:
    * **Input:** A crafted DNS response with a specific error (e.g., too long name).
    * **Expected Output:** The `InitParse` function should return `false`, indicating an error.

5. **Identify Potential User/Programming Errors:** The tests themselves often highlight potential errors:
    * Incorrectly formatting DNS names (too long, not null-terminated).
    * Mismatched record counts in the header vs. actual data.
    * Providing incomplete DNS data.

6. **Trace User Operations (Debugging Clues):** To understand how a user's action might lead to this code being executed, I need to think about the steps involved in a network request:
    1. User enters a URL or clicks a link.
    2. The browser needs to find the IP address of the domain.
    3. A DNS query is initiated.
    4. A DNS server responds with a DNS response.
    5. The browser's network stack (including the code being tested) parses this response. Errors in the DNS response or the parsing logic can lead to issues.

7. **Synthesize a Summary:** Based on the above analysis, I need to create a concise summary of the file's purpose. This will involve combining the core functionality and the types of tests performed.

**Self-Correction/Refinement:**

* **Initial thought:** Focus heavily on the low-level byte manipulation.
* **Correction:** While important, the higher-level goal is to understand the *purpose* of the tests. Focus on the functionalities being validated.
* **Initial thought:** Directly link specific JavaScript APIs to this C++ code.
* **Correction:** The link is more indirect. JavaScript initiates network requests, which trigger the DNS resolution process handled by this C++ code. Avoid overstating the direct connection.
* **Initial thought:**  For input/output, try to provide exact byte sequences.
* **Correction:**  For many error cases, a general description of the malformed input is sufficient and clearer. The code already provides the specific byte sequences.

By following this thought process, I can systematically analyze the code snippet and generate a comprehensive and accurate answer to the user's request.
这是文件 `net/dns/dns_response_unittest.cc` 的第二部分，延续了第一部分的内容，继续对 `DnsResponse` 类进行单元测试。

**功能归纳:**

这部分代码主要集中在以下几个方面对 `DnsResponse` 类进行测试：

1. **DNS 响应的构造和写入 (DnsResponseWriteTest):**
   - 测试了如何使用 `DnsResponse` 类来构建各种类型的 DNS 响应，包括：
     - 包含单个 A 记录的响应。
     - 包含尾部带点的域名（FQDN）的响应。
     - 包含问题 (question) 部分的响应。
     - 从一个内部缓冲区被放大的 `DnsQuery` 对象构造包含问题的响应。
     - 包含 AAAA 记录的响应。
     - 包含 A 记录和 NSEC 附加记录的响应。
     - 包含多个不同类型（A 和 AAAA）答案的响应。
     - 包含权威记录 (authority record) 的响应。
     - 包含 RCODE (响应代码) 的响应（例如 NXDOMAIN）。
     - 针对 AAAA 查询返回 CNAME 答案的情况 (CNAME 答案对于任何查询类型都是允许的)。
   - 验证了写入的 DNS 响应是否可以被成功解析。

**与 JavaScript 的关系:**

JavaScript 代码本身并不会直接操作 `DnsResponse` 对象。 然而，当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）时，浏览器底层会进行 DNS 解析来获取目标服务器的 IP 地址。

1. **间接影响:**  `DnsResponse` 类的正确性直接影响到浏览器能否正确解析 DNS 服务器返回的响应。如果 `DnsResponse` 解析错误，JavaScript 发起的网络请求可能无法成功建立连接，或者获取到错误的 IP 地址。

**举例说明:**

假设一个 JavaScript 应用尝试访问 `www.example.com`：

```javascript
fetch('https://www.example.com');
```

在这个过程中，浏览器会向 DNS 服务器发送一个查询 `www.example.com` 的 IP 地址的请求。 DNS 服务器返回一个 DNS 响应，这个响应的数据会被 Chromium 网络栈中的 `DnsResponse` 类解析。 如果 `DnsResponse` 的解析逻辑有误（比如像这部分测试中模拟的各种错误情况），可能会导致以下问题：

* **解析包含过长域名的响应失败:** 如果 DNS 服务器返回的响应中，`www.example.com` 这个域名被错误地编码成超过 RFC 规定的最大长度，`DnsResponse` 的相关测试（如 `InitParseRejectsQuestionWithTooLongName`) 确保了这种情况会被正确识别和拒绝，防止程序崩溃或错误处理。
* **解析记录数量不匹配的响应失败:** 如果 DNS 服务器声称返回了 3 个答案，但实际响应中只有 2 个，`DnsResponse` 的相关测试（如 `InitParseRejectsResponseWithMissingQuestions`) 保证了这种不一致性会被检测出来。

**逻辑推理 (假设输入与输出):**

以 `TEST(DnsResponseTest, InitParseRejectsQuestionWithTooLongName)` 为例：

* **假设输入:**  一个精心构造的 DNS 响应数据，其问题部分包含一个长度超过 RFC 规定的最大长度的域名。
* **预期输出:** `resp.InitParseWithoutQuery(response_data.size())` 和 `resp.InitParse(response_data.size(), query)` 均返回 `false`，表明解析失败，因为域名过长。

以 `TEST(DnsResponseWriteTest, SingleARecordAnswer)` 为例：

* **假设输入:**  创建一个 `DnsResponse` 对象，包含一个针对 `www.example.com` 的 A 记录 (IP 地址为 192.168.0.1)。
* **预期输出:**  `response.io_buffer()->data()` 返回的字节流与预期的 DNS 响应数据的二进制表示完全一致（`response_data` 数组的内容）。

**用户或编程常见的使用错误 (举例说明):**

1. **构造 DNS 响应时，记录的数量与实际提供的记录不符:**  开发者可能在构造 `DnsResponse` 时，错误地设置了 answer count, authority count 或 additional count，导致实际提供的记录数量与头部声明的不一致。  `TEST(DnsResponseTest, ParserLimitedToNumClaimedRecords)` 和 `TEST(DnsResponseTest, ParserLimitedToBufferSize)`  这类测试就是为了防止这种错误，即使响应数据中包含额外的记录，解析器也会按照头部声明的数量进行解析，避免读取超出预期的数据。

2. **在 JavaScript 中处理 DNS 解析结果时，假设结果总是有效的:**  即使 `DnsResponse` 在 C++ 层做了很多校验，开发者在 JavaScript 中使用 DNS 解析结果时，也应该考虑到 DNS 解析可能失败的情况，并进行相应的错误处理，而不是盲目地使用解析到的 IP 地址。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个网址，例如 `www.example.com`，或点击一个链接。**
2. **浏览器首先需要解析这个域名，获取其对应的 IP 地址。**  浏览器会检查本地缓存，如果找不到，则会发起 DNS 查询。
3. **操作系统或浏览器会向配置的 DNS 服务器发送 DNS 查询请求。**
4. **DNS 服务器返回一个 DNS 响应。**
5. **Chromium 的网络栈接收到这个 DNS 响应数据。**
6. **`net/dns/dns_response.cc` 中的 `DnsResponse` 类会被用来解析这个响应数据。**  `InitParse` 或 `InitParseWithoutQuery` 等方法会被调用。
7. **在单元测试环境下，开发者会模拟各种 DNS 响应数据（包括错误的情况），调用 `DnsResponse` 的方法进行测试。**  如果解析过程中出现错误，相关的 `EXPECT_FALSE` 断言会失败，提示开发者 `DnsResponse` 的实现存在问题。

**总结 (这部分的功能):**

这部分 `net/dns/dns_response_unittest.cc` 的代码主要负责测试 `DnsResponse` 类的 **构造和写入 DNS 响应** 的功能。 它涵盖了创建各种类型的 DNS 响应，包括包含不同类型的记录、问题部分以及错误响应代码的情况。 此外，它还测试了写入的 DNS 响应是否可以被正确地解析，确保了 `DnsResponse` 类在构建 DNS 消息方面的正确性。 这些测试对于确保 Chromium 网络栈能够正确地生成和发送 DNS 响应至关重要，这间接地影响了基于浏览器的 JavaScript 应用的网络通信能力。

### 提示词
```
这是目录为net/dns/dns_response_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ongName) {
  const char kResponseHeader[] =
      "\x02\x45"   // ID=581
      "\x81\x80"   // Standard query response, RA, no error
      "\x00\x01"   // 1 question
      "\x00\x00"   // 0 answers
      "\x00\x00"   // 0 authority records
      "\x00\x00";  // 0 additional records

  std::string dotted_name;
  const std::vector<uint8_t> dns_name =
      BuildRfc1034Name(dns_protocol::kMaxNameLength, &dotted_name);

  std::string response_data(kResponseHeader, sizeof(kResponseHeader) - 1);
  response_data.append(reinterpret_cast<const char*>(dns_name.data()),
                       dns_name.size());
  response_data.append(
      "\x00\x01"   // TYPE=A
      "\x00\x01",  // CLASS=IN)
      4);

  DnsResponse resp1;
  memcpy(resp1.io_buffer()->data(), response_data.data(), response_data.size());

  EXPECT_TRUE(resp1.InitParseWithoutQuery(response_data.size()));

  DnsQuery query(581, dns_name, dns_protocol::kTypeA);

  DnsResponse resp2(resp1.io_buffer(), response_data.size());
  EXPECT_TRUE(resp2.InitParse(response_data.size(), query));
}

// Tests against incorrect name length validation, which is anti-pattern #3 from
// the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsResponseTest, InitParseRejectsQuestionWithTooLongName) {
  const char kResponseHeader[] =
      "\x02\x45"   // ID=581
      "\x81\x80"   // Standard query response, RA, no error
      "\x00\x01"   // 1 question
      "\x00\x00"   // 0 answers
      "\x00\x00"   // 0 authority records
      "\x00\x00";  // 0 additional records

  std::string dotted_name;
  const std::vector<uint8_t> dns_name =
      BuildRfc1034Name(dns_protocol::kMaxNameLength + 1, &dotted_name);

  std::string response_data(kResponseHeader, sizeof(kResponseHeader) - 1);
  response_data.append(reinterpret_cast<const char*>(dns_name.data()),
                       dns_name.size());
  response_data.append(
      "\x00\x01"   // TYPE=A
      "\x00\x01",  // CLASS=IN)
      4);

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), response_data.data(), response_data.size());

  EXPECT_FALSE(resp.InitParseWithoutQuery(response_data.size()));

  // Note that `DnsQuery` disallows construction without a valid name, so
  // `InitParse()` can never be tested with a `query` that matches against a
  // too-long name in the response. Test with an arbitrary valid query name to
  // ensure no issues if this code is exercised after receiving a response with
  // a too-long name.
  const char kQueryName[] = "\005query\004test";
  DnsQuery query(
      /*id=*/581, base::as_byte_span(kQueryName), dns_protocol::kTypeA);
  EXPECT_FALSE(resp.InitParse(response_data.size(), query));
}

// Test that `InitParse[...]()` rejects a response with a question name
// extending past the end of the response.
// Tests against incorrect name length validation, which is anti-pattern #3 from
// the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsResponseTest, InitParseRejectsQuestionWithNonendedName) {
  const char kResponse[] =
      "\x02\x45"                    // ID
      "\x81\x80"                    // Standard query response, RA, no error
      "\x00\x01"                    // 1 question
      "\x00\x00"                    // 0 answers
      "\x00\x00"                    // 0 authority records
      "\x00\x00"                    // 0 additional records
      "\003www\006google\006test";  // Name extending past the end.

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  EXPECT_FALSE(resp.InitParseWithoutQuery(sizeof(kResponse) - 1));

  const char kQueryName[] = "\003www\006google\006testtt";
  DnsQuery query(
      /*id=*/581, base::as_byte_span(kQueryName), dns_protocol::kTypeA);
  EXPECT_FALSE(resp.InitParse(sizeof(kResponse) - 1, query));
}

// Test that `InitParse[...]()` rejects responses that do not contain at least
// the claimed number of questions.
// Tests against incorrect record count field validation, which is anti-pattern
// #5 from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsResponseTest, InitParseRejectsResponseWithMissingQuestions) {
  const char kResponse[] =
      "\x02\x45"                       // ID
      "\x81\x80"                       // Standard query response, RA, no error
      "\x00\x03"                       // 3 questions
      "\x00\x00"                       // 0 answers
      "\x00\x00"                       // 0 authority records
      "\x00\x00"                       // 0 additional records
      "\003www\006google\004test\000"  // www.google.test
      "\x00\x01"                       // TYPE=A
      "\x00\x01"                       // CLASS=IN
      "\003www\010chromium\004test\000"  // www.chromium.test
      "\x00\x01"                         // TYPE=A
      "\x00\x01";                        // CLASS=IN
  // Missing third question.

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  EXPECT_FALSE(resp.InitParseWithoutQuery(sizeof(kResponse) - 1));

  const char kQueryName[] = "\003www\006google\004test";
  DnsQuery query(
      /*id=*/581, base::as_byte_span(kQueryName), dns_protocol::kTypeA);
  EXPECT_FALSE(resp.InitParse(sizeof(kResponse) - 1, query));
}

// Test that a parsed DnsResponse only allows parsing the number of records
// claimed in the response header.
// Tests against incorrect record count field validation, which is anti-pattern
// #5 from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsResponseTest, ParserLimitedToNumClaimedRecords) {
  const char kResponse[] =
      "\x02\x45"  // ID
      "\x81\x80"  // Standard query response, RA, no error
      "\x00\x01"  // 1 question
      "\x00\x01"  // 1 answers
      "\x00\x02"  // 2 authority records
      "\x00\x01"  // 1 additional records
      "\003www\006google\004test\000"
      "\x00\x01"  // TYPE=A
      "\x00\x01"  // CLASS=IN
      // 6 total records.
      "\003www\006google\004test\000"
      "\x00\x01"          // TYPE=A
      "\x00\x01"          // CLASS=IN
      "\x00\x01\x51\x80"  // TTL=1 day
      "\x00\x04"          // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x01"  // 192.168.0.1
      "\003www\010chromium\004test\000"
      "\x00\x01"          // TYPE=A
      "\x00\x01"          // CLASS=IN
      "\x00\x01\x51\x80"  // TTL=1 day
      "\x00\x04"          // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x02"  // 192.168.0.2
      "\003www\007google1\004test\000"
      "\x00\x01"          // TYPE=A
      "\x00\x01"          // CLASS=IN
      "\x00\x01\x51\x80"  // TTL=1 day
      "\x00\x04"          // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x03"  // 192.168.0.3
      "\003www\011chromium1\004test\000"
      "\x00\x01"          // TYPE=A
      "\x00\x01"          // CLASS=IN
      "\x00\x01\x51\x80"  // TTL=1 day
      "\x00\x04"          // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x04"  // 192.168.0.4
      "\003www\007google2\004test\000"
      "\x00\x01"          // TYPE=A
      "\x00\x01"          // CLASS=IN
      "\x00\x01\x51\x80"  // TTL=1 day
      "\x00\x04"          // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x05"  // 192.168.0.5
      "\003www\011chromium2\004test\000"
      "\x00\x01"           // TYPE=A
      "\x00\x01"           // CLASS=IN
      "\x00\x01\x51\x80"   // TTL=1 day
      "\x00\x04"           // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x06";  // 192.168.0.6

  DnsResponse resp1;
  memcpy(resp1.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  ASSERT_TRUE(resp1.InitParseWithoutQuery(sizeof(kResponse) - 1));
  DnsRecordParser parser1 = resp1.Parser();
  ASSERT_TRUE(parser1.IsValid());

  // Response header only claims 4 records, so expect parser to only allow
  // parsing that many, ignoring extra records in the data.
  DnsResourceRecord record;
  EXPECT_TRUE(parser1.ReadRecord(&record));
  EXPECT_TRUE(parser1.ReadRecord(&record));
  EXPECT_TRUE(parser1.ReadRecord(&record));
  EXPECT_TRUE(parser1.ReadRecord(&record));
  EXPECT_FALSE(parser1.ReadRecord(&record));
  EXPECT_FALSE(parser1.ReadRecord(&record));

  // Repeat using InitParse()
  DnsResponse resp2;
  memcpy(resp2.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  const char kQueryName[] = "\003www\006google\004test";
  DnsQuery query(
      /*id=*/581, base::as_byte_span(kQueryName), dns_protocol::kTypeA);

  ASSERT_TRUE(resp2.InitParse(sizeof(kResponse) - 1, query));
  DnsRecordParser parser2 = resp2.Parser();
  ASSERT_TRUE(parser2.IsValid());

  // Response header only claims 4 records, so expect parser to only allow
  // parsing that many, ignoring extra records in the data.
  EXPECT_TRUE(parser2.ReadRecord(&record));
  EXPECT_TRUE(parser2.ReadRecord(&record));
  EXPECT_TRUE(parser2.ReadRecord(&record));
  EXPECT_TRUE(parser2.ReadRecord(&record));
  EXPECT_FALSE(parser2.ReadRecord(&record));
  EXPECT_FALSE(parser2.ReadRecord(&record));
}

// Test that a parsed DnsResponse does not allow parsing past the end of the
// input, even if more records are claimed in the response header.
// Tests against incorrect record count field validation, which is anti-pattern
// #5 from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsResponseTest, ParserLimitedToBufferSize) {
  const char kResponse[] =
      "\x02\x45"  // ID
      "\x81\x80"  // Standard query response, RA, no error
      "\x00\x01"  // 1 question
      "\x00\x01"  // 1 answers
      "\x00\x02"  // 2 authority records
      "\x00\x01"  // 1 additional records
      "\003www\006google\004test\000"
      "\x00\x01"  // TYPE=A
      "\x00\x01"  // CLASS=IN
      // 2 total records.
      "\003www\006google\004test\000"
      "\x00\x01"          // TYPE=A
      "\x00\x01"          // CLASS=IN
      "\x00\x01\x51\x80"  // TTL=1 day
      "\x00\x04"          // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x01"  // 192.168.0.1
      "\003www\010chromium\004test\000"
      "\x00\x01"           // TYPE=A
      "\x00\x01"           // CLASS=IN
      "\x00\x01\x51\x80"   // TTL=1 day
      "\x00\x04"           // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x02";  // 192.168.0.2

  DnsResponse resp1;
  memcpy(resp1.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  ASSERT_TRUE(resp1.InitParseWithoutQuery(sizeof(kResponse) - 1));
  DnsRecordParser parser1 = resp1.Parser();
  ASSERT_TRUE(parser1.IsValid());

  // Response header claims 4 records, but only 2 present in input.
  DnsResourceRecord record;
  EXPECT_TRUE(parser1.ReadRecord(&record));
  EXPECT_TRUE(parser1.ReadRecord(&record));
  EXPECT_FALSE(parser1.ReadRecord(&record));
  EXPECT_FALSE(parser1.ReadRecord(&record));

  // Repeat using InitParse()
  DnsResponse resp2;
  memcpy(resp2.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  ASSERT_TRUE(resp2.InitParseWithoutQuery(sizeof(kResponse) - 1));
  DnsRecordParser parser2 = resp2.Parser();
  ASSERT_TRUE(parser2.IsValid());

  // Response header claims 4 records, but only 2 present in input.
  EXPECT_TRUE(parser2.ReadRecord(&record));
  EXPECT_TRUE(parser2.ReadRecord(&record));
  EXPECT_FALSE(parser2.ReadRecord(&record));
  EXPECT_FALSE(parser2.ReadRecord(&record));
}

TEST(DnsResponseWriteTest, SingleARecordAnswer) {
  const uint8_t response_data[] = {
      0x12, 0x34,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x00,  // number of questions
      0x00, 0x01,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,                    // null label
      0x00, 0x01,              // type A Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x04,              // rdlength, 32 bits
      0xc0, 0xa8, 0x00, 0x01,  // 192.168.0.1
  };
  net::DnsResourceRecord answer;
  answer.name = "www.example.com";
  answer.type = dns_protocol::kTypeA;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  std::vector<DnsResourceRecord> answers(1, answer);
  DnsResponse response(0x1234 /* response_id */, true /* is_authoritative*/,
                       answers, {} /* authority_records */,
                       {} /* additional records */, std::nullopt);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest, SingleARecordAnswerWithFinalDotInName) {
  const uint8_t response_data[] = {
      0x12, 0x34,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x00,  // number of questions
      0x00, 0x01,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,                    // null label
      0x00, 0x01,              // type A Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x04,              // rdlength, 32 bits
      0xc0, 0xa8, 0x00, 0x01,  // 192.168.0.1
  };
  net::DnsResourceRecord answer;
  answer.name = "www.example.com.";  // FQDN with the final dot.
  answer.type = dns_protocol::kTypeA;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  std::vector<DnsResourceRecord> answers(1, answer);
  DnsResponse response(0x1234 /* response_id */, true /* is_authoritative*/,
                       answers, {} /* authority_records */,
                       {} /* additional records */, std::nullopt);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest, SingleARecordAnswerWithQuestion) {
  const uint8_t response_data[] = {
      0x12, 0x34,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x01,  // number of questions
      0x00, 0x01,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,        // null label
      0x00, 0x01,  // type A Record
      0x00, 0x01,  // class IN
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,                    // null label
      0x00, 0x01,              // type A Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x04,              // rdlength, 32 bits
      0xc0, 0xa8, 0x00, 0x01,  // 192.168.0.1
  };
  std::string dotted_name("www.example.com");
  std::optional<std::vector<uint8_t>> dns_name =
      dns_names_util::DottedNameToNetwork(dotted_name);
  ASSERT_TRUE(dns_name.has_value());

  OptRecordRdata opt_rdata;
  opt_rdata.AddOpt(
      OptRecordRdata::UnknownOpt::CreateForTesting(255, "\xde\xad\xbe\xef"));

  std::optional<DnsQuery> query;
  query.emplace(0x1234 /* id */, dns_name.value(), dns_protocol::kTypeA,
                &opt_rdata);
  net::DnsResourceRecord answer;
  answer.name = dotted_name;
  answer.type = dns_protocol::kTypeA;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  std::vector<DnsResourceRecord> answers(1, answer);
  DnsResponse response(0x1234 /* id */, true /* is_authoritative*/, answers,
                       {} /* authority_records */, {} /* additional records */,
                       query);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest,
     SingleAnswerWithQuestionConstructedFromSizeInflatedQuery) {
  const uint8_t response_data[] = {
      0x12, 0x34,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x01,  // number of questions
      0x00, 0x01,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,        // null label
      0x00, 0x01,  // type A Record
      0x00, 0x01,  // class IN
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,                    // null label
      0x00, 0x01,              // type A Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x04,              // rdlength, 32 bits
      0xc0, 0xa8, 0x00, 0x01,  // 192.168.0.1
  };
  std::string dotted_name("www.example.com");
  std::optional<std::vector<uint8_t>> dns_name =
      dns_names_util::DottedNameToNetwork(dotted_name);
  ASSERT_TRUE(dns_name.has_value());
  size_t buf_size =
      sizeof(dns_protocol::Header) + dns_name.value().size() + 2 /* qtype */ +
      2 /* qclass */ +
      10 /* extra bytes that inflate the internal buffer of a query */;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(buf_size);
  std::ranges::fill(buf->span(), 0);
  auto writer = base::SpanWriter(buf->span());
  writer.WriteU16BigEndian(0x1234);                  // id
  writer.WriteU16BigEndian(0);                       // flags, is query
  writer.WriteU16BigEndian(1);                       // qdcount
  writer.WriteU16BigEndian(0);                       // ancount
  writer.WriteU16BigEndian(0);                       // nscount
  writer.WriteU16BigEndian(0);                       // arcount
  writer.Write(dns_name.value());                    // qname
  writer.WriteU16BigEndian(dns_protocol::kTypeA);    // qtype
  writer.WriteU16BigEndian(dns_protocol::kClassIN);  // qclass
  // buf contains 10 extra zero bytes.
  std::optional<DnsQuery> query;
  query.emplace(buf);
  query->Parse(buf_size);
  net::DnsResourceRecord answer;
  answer.name = dotted_name;
  answer.type = dns_protocol::kTypeA;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  std::vector<DnsResourceRecord> answers(1, answer);
  DnsResponse response(0x1234 /* id */, true /* is_authoritative*/, answers,
                       {} /* authority_records */, {} /* additional records */,
                       query);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest, SingleQuadARecordAnswer) {
  const uint8_t response_data[] = {
      0x12, 0x34,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x00,  // number of questions
      0x00, 0x01,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',
      'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
      0x00,                                            // null label
      0x00, 0x1c,                                      // type AAAA Record
      0x00, 0x01,                                      // class IN
      0x00, 0x00, 0x00, 0x78,                          // TTL, 120 seconds
      0x00, 0x10,                                      // rdlength, 128 bits
      0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0x00, 0x01,  // fd12:3456:789a:1::1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  };
  net::DnsResourceRecord answer;
  answer.name = "www.example.com";
  answer.type = dns_protocol::kTypeAAAA;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(std::string(
      "\xfd\x12\x34\x56\x78\x9a\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01", 16));
  std::vector<DnsResourceRecord> answers(1, answer);
  DnsResponse response(0x1234 /* id */, true /* is_authoritative*/, answers,
                       {} /* authority_records */, {} /* additional records */,
                       std::nullopt);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest,
     SingleARecordAnswerWithQuestionAndNsecAdditionalRecord) {
  const uint8_t response_data[] = {
      0x12, 0x34,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x01,  // number of questions
      0x00, 0x01,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x01,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,        // null label
      0x00, 0x01,  // type A Record
      0x00, 0x01,  // class IN
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,                    // null label
      0x00, 0x01,              // type A Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x04,              // rdlength, 32 bits
      0xc0, 0xa8, 0x00, 0x01,  // 192.168.0.1
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,                    // null label
      0x00, 0x2f,              // type NSEC Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x05,              // rdlength, 5 bytes
      0xc0, 0x0c,              // pointer to the previous "www.example.com"
      0x00, 0x01, 0x40,        // type bit map of type A: window block 0, bitmap
                               // length 1, bitmap with bit 1 set
  };
  std::string dotted_name("www.example.com");
  std::optional<std::vector<uint8_t>> dns_name =
      dns_names_util::DottedNameToNetwork(dotted_name);
  ASSERT_TRUE(dns_name.has_value());
  std::optional<DnsQuery> query;
  query.emplace(0x1234 /* id */, dns_name.value(), dns_protocol::kTypeA);
  net::DnsResourceRecord answer;
  answer.name = dotted_name;
  answer.type = dns_protocol::kTypeA;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  std::vector<DnsResourceRecord> answers(1, answer);
  net::DnsResourceRecord additional_record;
  additional_record.name = dotted_name;
  additional_record.type = dns_protocol::kTypeNSEC;
  additional_record.klass = dns_protocol::kClassIN;
  additional_record.ttl = 120;  // 120 seconds.
  // Bitmap for "www.example.com" with type A set.
  additional_record.SetOwnedRdata(std::string("\xc0\x0c\x00\x01\x40", 5));
  std::vector<DnsResourceRecord> additional_records(1, additional_record);
  DnsResponse response(0x1234 /* id */, true /* is_authoritative*/, answers,
                       {} /* authority_records */, additional_records, query);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest, TwoAnswersWithAAndQuadARecords) {
  const uint8_t response_data[] = {
      0x12, 0x34,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x00,  // number of questions
      0x00, 0x02,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p', 'l', 'e',
      0x03, 'c',  'o',  'm',
      0x00,                    // null label
      0x00, 0x01,              // type A Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x04,              // rdlength, 32 bits
      0xc0, 0xa8, 0x00, 0x01,  // 192.168.0.1
      0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'o', 'r', 'g',
      0x00,                                            // null label
      0x00, 0x1c,                                      // type AAAA Record
      0x00, 0x01,                                      // class IN
      0x00, 0x00, 0x00, 0x3c,                          // TTL, 60 seconds
      0x00, 0x10,                                      // rdlength, 128 bits
      0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0x00, 0x01,  // fd12:3456:789a:1::1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  };
  net::DnsResourceRecord answer1;
  answer1.name = "www.example.com";
  answer1.type = dns_protocol::kTypeA;
  answer1.klass = dns_protocol::kClassIN;
  answer1.ttl = 120;  // 120 seconds.
  answer1.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  net::DnsResourceRecord answer2;
  answer2.name = "example.org";
  answer2.type = dns_protocol::kTypeAAAA;
  answer2.klass = dns_protocol::kClassIN;
  answer2.ttl = 60;
  answer2.SetOwnedRdata(std::string(
      "\xfd\x12\x34\x56\x78\x9a\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01", 16));
  std::vector<DnsResourceRecord> answers(2);
  answers[0] = answer1;
  answers[1] = answer2;
  DnsResponse response(0x1234 /* id */, true /* is_authoritative*/, answers,
                       {} /* authority_records */, {} /* additional records */,
                       std::nullopt);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest, AnswerWithAuthorityRecord) {
  const uint8_t response_data[] = {
      0x12, 0x35,  // ID
      0x84, 0x00,  // flags, response with authoritative answer
      0x00, 0x00,  // number of questions
      0x00, 0x00,  // number of answer rr
      0x00, 0x01,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w',  'w',  0x07, 'e', 'x', 'a',
      'm',  'p',  'l',  'e',  0x03, 'c', 'o', 'm',
      0x00,                    // null label
      0x00, 0x01,              // type A Record
      0x00, 0x01,              // class IN
      0x00, 0x00, 0x00, 0x78,  // TTL, 120 seconds
      0x00, 0x04,              // rdlength, 32 bits
      0xc0, 0xa8, 0x00, 0x01,  // 192.168.0.1
  };
  DnsResourceRecord record;
  record.name = "www.example.com";
  record.type = dns_protocol::kTypeA;
  record.klass = dns_protocol::kClassIN;
  record.ttl = 120;  // 120 seconds.
  record.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  std::vector<DnsResourceRecord> authority_records(1, record);
  DnsResponse response(0x1235 /* response_id */, true /* is_authoritative*/,
                       {} /* answers */, authority_records,
                       {} /* additional records */, std::nullopt);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
}

TEST(DnsResponseWriteTest, AnswerWithRcode) {
  const uint8_t response_data[] = {
      0x12, 0x12,  // ID
      0x80, 0x03,  // flags (response with non-existent domain)
      0x00, 0x00,  // number of questions
      0x00, 0x00,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
  };
  DnsResponse response(0x1212 /* response_id */, false /* is_authoritative*/,
                       {} /* answers */, {} /* authority_records */,
                       {} /* additional records */, std::nullopt,
                       dns_protocol::kRcodeNXDOMAIN);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  std::string expected_response(reinterpret_cast<const char*>(response_data),
                                sizeof(response_data));
  std::string actual_response(response.io_buffer()->data(),
                              response.io_buffer_size());
  EXPECT_EQ(expected_response, actual_response);
  EXPECT_EQ(dns_protocol::kRcodeNXDOMAIN, response.rcode());
}

// CNAME answers are always allowed for any question.
TEST(DnsResponseWriteTest, AAAAQuestionAndCnameAnswer) {
  const std::string kName = "www.example.com";
  std::optional<std::vector<uint8_t>> dns_name =
      dns_names_util::DottedNameToNetwork(kName);
  ASSERT_TRUE(dns_name.has_value());

  DnsResourceRecord answer;
  answer.name = kName;
  answer.type = dns_protocol::kTypeCNAME;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(
      std::string(reinterpret_cast<char*>(dns_name.value().data()),
                  dns_name.value().size()));
  std::vector<DnsResourceRecord> answers(1, answer);

  std::optional<DnsQuery> query(std::in_place, 114 /* id */, dns_name.value(),
                                dns_protocol::kTypeAAAA);

  DnsResponse response(114 /* response_id */, true /* is_authoritative*/,
                       answers, {} /* authority_records */,
                       {} /* additional records */, query);

  EXPECT_TRUE(response.IsValid());
}

TEST(DnsResponseWriteTest, WrittenResponseCanBeParsed) {
  std::string dotted_name("www.example.com");
  net::DnsResourceRecord answer;
  answer.name = dotted_name;
  answer.type = dns_protocol::kTypeA;
  answer.klass = dns_protocol::kClassIN;
  answer.ttl = 120;  // 120 seconds.
  answer.SetOwnedRdata(std::string("\xc0\xa8\x00\x01", 4));
  std::vector<DnsResourceRecord> answers(1, answer);
  net::DnsResourceRecord additional_record;
  additional_record.name = dotted_name;
  additional_record.type = dns_protocol::kTypeNSEC;
  additional_record.klass = dns_protocol::kClassIN;
  additional_record.ttl = 120;  // 120 seconds.
  additional_record.SetOwnedRdata(std::string("\xc0\x0c\x00\x01\x04", 5));
  std::vector<DnsResourceRecord> additional_records(1, additional_record);
  DnsResponse response(0x1234 /* response_id */, true /* is_authoritative*/,
                       answers, {} /* authority_records */, additional_records,
                       std::nullopt);
  ASSERT_NE(nullptr, response.io_buffer());
  EXPECT_TRUE(response.IsValid());
  EXPECT_THAT(response.id(), testing::Optional(0x1234));
  EXPECT_EQ(1u, response.answer_count());
  EXPECT_EQ(1u, response.additional_answer_count());
  auto parser = response.Parser();
  net::DnsResourceRecord parsed_record;
  EXPECT_TRUE(parser.ReadRecord(&parsed_record));
  // Answer with an A record.
  EXPECT_EQ(answer.name, parsed_record.name);
  EXPECT_EQ(a
```