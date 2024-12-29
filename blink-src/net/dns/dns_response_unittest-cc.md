Response:
The user wants a summary of the functionality of the C++ source code file `net/dns/dns_response_unittest.cc`. They are also interested in any relationship to JavaScript, logical inference with example inputs and outputs, common user errors, and how a user's actions might lead to this code being executed (debugging context).

**Plan:**

1. **Overall Function:** Identify the primary purpose of the file. It's clearly a unit test file for `net/dns/dns_response.h`.
2. **Key Test Areas:**  Go through the `TEST` macros and categorize the functionality being tested. This will involve:
    * Parsing DNS records (names, types, data).
    * Handling various DNS name formats and compression.
    * Validating DNS response structures (headers, questions, answers).
    * Testing error conditions and boundary cases.
3. **JavaScript Relationship:** Analyze if any tests directly relate to how JavaScript interacts with DNS (unlikely at this low level). Mention the browser's DNS resolution process and where JavaScript fits.
4. **Logical Inference:**  For a few representative tests, outline the assumed input data and the expected outcome.
5. **Common Errors:** Identify potential mistakes users (mostly developers in this case) could make when working with DNS data that these tests aim to catch.
6. **User Journey:** Describe a high-level scenario where a user action in a browser triggers DNS resolution, eventually leading to the execution of related code.
7. **Summarize:** Concisely summarize the file's purpose.
这是文件 `net/dns/dns_response_unittest.cc` 的第 1 部分，它主要的功能是**对 `net/dns/dns_response.h` 中定义的 `DnsResponse` 和 `DnsRecordParser` 类进行单元测试**。

具体来说，这一部分代码主要测试了以下功能：

**1. DnsRecordParser 的功能：**

* **构造函数：** 测试 `DnsRecordParser` 的不同构造方式以及初始状态的 `IsValid()` 和 `AtEnd()` 方法。
* **读取域名 (`ReadName`)：**
    * 测试了从 DNS 数据包中读取不同格式的域名，包括完整 label 和使用指针压缩的域名。
    * 测试了读取域名时是否能正确处理偏移量。
    * 测试了 `ReadName` 在不存储结果情况下的行为。
    * 重点测试了各种解析失败的情况，例如：
        * Label 长度超出数据包边界。
        * 指针偏移超出数据包边界。
        * 指针循环。
        * 不正确的 label 类型 (既不是长度 label 也不是指针 label)。
        * 域名被截断（缺少根 label）。
        * 域名长度超过限制（针对 "NAME:WRECK" 报告中的反模式 #3）。
        * 指针指向数据包外部（针对 "NAME:WRECK" 报告中的反模式 #6）。
        * 指针指向自身形成环路（针对 "NAME:WRECK" 报告中的反模式 #6）。
        * label 类型位为保留值（01 或 10）（针对 "NAME:WRECK" 报告中的反模式 #6）。
* **读取记录 (`ReadRecord`)：**
    * 测试了从 DNS 数据包中读取完整的资源记录，包括记录名、类型、类、TTL 和 RDATA。
    * 测试了读取到的记录各个字段是否正确。
    * 测试了当记录名过长时的处理。
    * 测试了记录名没有以 null 结尾的情况（针对 "NAME:WRECK" 报告中的反模式 #4）。
    * 测试了读取记录时数据被截断的情况。
    * 测试了当声明的记录数量超过实际数量或数据包结尾时的处理。

**2. DnsResponse 的部分功能（`InitParse` 相关）：**

* **`InitParse` 方法：**
    * 测试了 `InitParse` 方法用于解析 DNS 响应数据包头和基本信息的功能。
    * 测试了 `InitParse` 如何验证响应 ID 是否与查询 ID 匹配。
    * 测试了 `InitParse` 如何验证响应的问题部分是否与查询匹配。
    * 测试了成功解析响应的情况，并检查了头部信息（ID、flags、rcode、answer_count、additional_answer_count）和问题部分是否正确解析。
    * 测试了访问解析后的问题部分信息，如域名和类型。
    * 测试了 `InitParse` 如何处理标志位 (`flags`) 不正确的情况（缺少 QR 位）。
    * 测试了 `InitParse` 如何拒绝没有问题的响应。
    * 测试了 `InitParse` 如何拒绝问题数量超过一个的响应。
* **`InitParseWithoutQuery` 方法：**
    * 测试了 `InitParseWithoutQuery` 方法在没有对应查询的情况下解析 DNS 响应数据包头和基本信息的功能。
    * 测试了成功解析的情况，并检查了头部信息和问题部分是否正确解析。
    * 测试了 `InitParseWithoutQuery` 如何处理标志位不正确的情况。
    * 测试了 `InitParseWithoutQuery` 解析包含多个问题的响应的情况。
    * 测试了 `InitParseWithoutQuery` 在数据包过短时的处理。

**与 Javascript 的关系：**

这段 C++ 代码位于 Chromium 的网络栈中，负责处理底层的 DNS 响应解析。 **JavaScript 代码本身并不直接操作这段代码。** 然而，当用户在浏览器中访问一个网页时，浏览器会进行 DNS 查询以获取服务器的 IP 地址。

**举例说明：**

1. **用户在浏览器地址栏输入 `www.example.com` 并按下回车。**
2. **浏览器会发起一个 DNS 查询请求，请求 `www.example.com` 的 IP 地址。**
3. **操作系统的 DNS 解析器或者浏览器自身的 DNS 解析器会将请求发送到 DNS 服务器。**
4. **DNS 服务器返回一个包含 `www.example.com` IP 地址的 DNS 响应。**
5. **Chromium 的网络栈会接收到这个 DNS 响应数据包。**
6. **`DnsResponse` 类（在 `net/dns/dns_response.h` 中定义）会用于封装这个响应数据，而 `DnsRecordParser` 类（在这个测试文件中测试）则负责解析响应数据包中的资源记录（例如 A 记录，包含 IP 地址）。**
7. **解析出的 IP 地址会被浏览器用于建立与 `www.example.com` 服务器的连接。**

**逻辑推理（假设输入与输出）：**

**假设输入：** 一个包含以下 A 记录的 DNS 响应数据包：

```
\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\xa8\x01\x01
```

**解释：**

* `\x03www\x07example\x03com\x00`: 域名 "www.example.com"
* `\x00\x01`: 类型 A (IPv4 地址)
* `\x00\x01`: 类 IN (Internet)
* `\x00\x00\x00\x3c`: TTL 60 秒
* `\x00\x04`: RDATA 长度 4 字节
* `\xc0\xa8\x01\x01`: IPv4 地址 192.168.1.1

**预期输出 (通过 `DnsRecordParser` 解析)：**

* `record.name`: "www.example.com"
* `record.type`: `dns_protocol::kTypeA` (等于 1)
* `record.klass`: `dns_protocol::kClassIN` (等于 1)
* `record.ttl`: 60
* `record.rdata`: 包含字节 `\xc0\xa8\x01\x01` 的 `base::span`

**用户或编程常见的使用错误：**

* **假设 DNS 响应数据总是有效的：** 开发者可能会假设接收到的 DNS 响应数据总是符合规范的，而没有进行充分的错误处理，例如数据包截断、格式错误等。这段测试代码就覆盖了很多解析错误的场景。
* **不正确地处理域名压缩：** DNS 协议允许使用指针压缩来缩短域名长度。开发者可能未能正确实现域名解压缩的逻辑，导致解析错误。`DnsRecordParserTest.ReadName` 中有很多关于域名压缩的测试用例。
* **缓冲区溢出：** 在手动解析 DNS 数据包时，如果开发者没有进行边界检查，可能会发生缓冲区溢出。`DnsRecordParser` 的设计考虑了安全性，避免了这些问题。
* **没有验证响应 ID 和问题：**  在处理 DNS 响应时，需要验证响应的 ID 和问题部分是否与发送的查询匹配，以防止 DNS 欺骗。`DnsResponseTest.InitParse` 中的相关测试就覆盖了这些验证逻辑。

**用户操作如何一步步到达这里（调试线索）：**

假设用户在使用 Chrome 浏览器访问 `https://www.example.com` 时遇到 DNS 解析问题：

1. **用户在 Chrome 浏览器的地址栏输入 `www.example.com` 并按下回车。**
2. **Chrome 浏览器开始进行 DNS 解析。**
3. **浏览器的网络服务（Network Service）进程会创建一个 DNS 查询请求。**
4. **根据操作系统的配置，DNS 查询可能会发送到本地 DNS 缓存、操作系统级别的 DNS 解析器或者直接发送到配置的 DNS 服务器。**
5. **如果 DNS 服务器返回了一个响应，Chrome 的网络服务进程会接收到这个响应数据。**
6. **在 `net/dns` 目录下，`DnsResponse::InitParse` 或 `DnsResponse::InitParseWithoutQuery` 方法会被调用，尝试解析接收到的 DNS 响应数据。**
7. **在解析过程中，会使用 `DnsRecordParser` 来解析响应中的资源记录。**
8. **如果在解析过程中发生错误（例如，数据包格式错误），`DnsRecordParser` 的相关方法会返回错误状态，导致 DNS 解析失败。**
9. **在调试 DNS 解析问题时，开发者可能会查看 `net/dns/dns_response.cc` 和 `net/dns/dns_response_unittest.cc` 这样的代码，以了解 DNS 响应的解析流程和可能出现的错误情况。** 通过运行 `net/dns/dns_response_unittest.cc` 中的单元测试，可以验证 DNS 响应解析逻辑的正确性。

**总结一下 `net/dns/dns_response_unittest.cc` 第 1 部分的功能：**

该文件通过一系列单元测试，全面地验证了 `net/dns/dns_response.h` 中 `DnsResponse` 和 `DnsRecordParser` 类的核心功能，特别是对 DNS 记录的解析和各种错误处理情况进行了细致的测试，确保了 Chromium 网络栈在处理 DNS 响应时的健壮性和安全性。

Prompt: 
```
这是目录为net/dns/dns_response_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/dns/dns_response.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/containers/span_writer.h"
#include "base/time/time.h"
#include "net/base/io_buffer.h"
#include "net/dns/dns_names_util.h"
#include "net/dns/dns_query.h"
#include "net/dns/dns_test_util.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/record_rdata.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(DnsRecordParserTest, Constructor) {
  const uint8_t data[] = {0};

  EXPECT_FALSE(DnsRecordParser().IsValid());
  EXPECT_TRUE(DnsRecordParser(data, 0, 0).IsValid());
  EXPECT_TRUE(DnsRecordParser(data, 1, 0).IsValid());

  EXPECT_FALSE(DnsRecordParser(data, 0, 0).AtEnd());
  EXPECT_TRUE(DnsRecordParser(data, 1, 0).AtEnd());
}

TEST(DnsRecordParserTest, ReadName) {
  const uint8_t data[] = {
      // all labels "foo.example.com"
      0x03, 'f', 'o', 'o', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c',
      'o', 'm',
      // byte 0x10
      0x00,
      // byte 0x11
      // part label, part pointer, "bar.example.com"
      0x03, 'b', 'a', 'r', 0xc0, 0x04,
      // byte 0x17
      // all pointer to "bar.example.com", 2 jumps
      0xc0, 0x11,
      // byte 0x1a
  };

  std::string out;
  DnsRecordParser parser(data, 0, /*num_records=*/0);
  ASSERT_TRUE(parser.IsValid());

  EXPECT_EQ(0x11u, parser.ReadName(data + 0x00, &out));
  EXPECT_EQ("foo.example.com", out);
  // Check that the last "." is never stored.
  out.clear();
  EXPECT_EQ(0x1u, parser.ReadName(data + 0x10, &out));
  EXPECT_EQ("", out);
  out.clear();
  EXPECT_EQ(0x6u, parser.ReadName(data + 0x11, &out));
  EXPECT_EQ("bar.example.com", out);
  out.clear();
  EXPECT_EQ(0x2u, parser.ReadName(data + 0x17, &out));
  EXPECT_EQ("bar.example.com", out);

  // Parse name without storing it.
  EXPECT_EQ(0x11u, parser.ReadName(data + 0x00, nullptr));
  EXPECT_EQ(0x1u, parser.ReadName(data + 0x10, nullptr));
  EXPECT_EQ(0x6u, parser.ReadName(data + 0x11, nullptr));
  EXPECT_EQ(0x2u, parser.ReadName(data + 0x17, nullptr));

  // Check that it works even if initial position is different.
  parser = DnsRecordParser(data, 0x12, /*num_records=*/0);
  EXPECT_EQ(0x6u, parser.ReadName(data + 0x11, nullptr));
}

TEST(DnsRecordParserTest, ReadNameFail) {
  const uint8_t data[] = {
      // label length beyond packet
      0x30, 'x', 'x', 0x00,
      // pointer offset beyond packet
      0xc0, 0x20,
      // pointer loop
      0xc0, 0x08, 0xc0, 0x06,
      // incorrect label type (currently supports only direct and pointer)
      0x80, 0x00,
      // truncated name (missing root label)
      0x02, 'x', 'x',
  };

  DnsRecordParser parser(data, 0, /*num_records=*/0);
  ASSERT_TRUE(parser.IsValid());

  std::string out;
  EXPECT_EQ(0u, parser.ReadName(data + 0x00, &out));
  EXPECT_EQ(0u, parser.ReadName(data + 0x04, &out));
  EXPECT_EQ(0u, parser.ReadName(data + 0x08, &out));
  EXPECT_EQ(0u, parser.ReadName(data + 0x0a, &out));
  EXPECT_EQ(0u, parser.ReadName(data + 0x0c, &out));
  EXPECT_EQ(0u, parser.ReadName(data + 0x0e, &out));
}

// Returns an RFC 1034 style domain name with a length of |name_len|.
// Also writes the expected dotted string representation into |dotted_str|,
// which must be non-null.
std::vector<uint8_t> BuildRfc1034Name(const size_t name_len,
                                      std::string* dotted_str) {
  // Impossible length. If length not zero, need at least 2 to allow label
  // length and label contents.
  CHECK_NE(name_len, 1u);

  CHECK(dotted_str != nullptr);
  auto ChoosePrintableCharLambda = [](uint8_t n) { return n % 26 + 'A'; };
  const size_t max_label_len = 63;
  std::vector<uint8_t> data;

  dotted_str->clear();
  while (data.size() < name_len) {
    // Compute the size of the next label.
    //
    // No need to account for next label length because the final zero length is
    // not considered included in overall length.
    size_t label_len = std::min(name_len - data.size() - 1, max_label_len);
    // Need to ensure the remainder is not 1 because that would leave room for a
    // label length but not a label.
    if (name_len - data.size() - label_len - 1 == 1) {
      CHECK_GT(label_len, 1u);
      label_len -= 1;
    }

    // Write the length octet
    data.push_back(label_len);

    // Write |label_len| bytes of label data
    const size_t size_with_label = data.size() + label_len;
    while (data.size() < size_with_label) {
      const uint8_t chr = ChoosePrintableCharLambda(data.size());
      data.push_back(chr);
      dotted_str->push_back(chr);

      CHECK(data.size() <= name_len);
    }

    // Write a trailing dot after every label
    dotted_str->push_back('.');
  }

  // Omit the final dot
  if (!dotted_str->empty())
    dotted_str->pop_back();

  CHECK(data.size() == name_len);

  // Final zero-length label (not considered included in overall length).
  data.push_back(0);

  return data;
}

TEST(DnsRecordParserTest, ReadNameGoodLength) {
  const size_t name_len_cases[] = {2, 10, 40, 250, 254, 255};

  for (auto name_len : name_len_cases) {
    std::string expected_name;
    const std::vector<uint8_t> data_vector =
        BuildRfc1034Name(name_len, &expected_name);
    ASSERT_EQ(data_vector.size(), name_len + 1);
    const uint8_t* data = data_vector.data();

    DnsRecordParser parser(data_vector, 0, /*num_records=*/0);
    ASSERT_TRUE(parser.IsValid());

    std::string out;
    EXPECT_EQ(data_vector.size(), parser.ReadName(data, &out));
    EXPECT_EQ(expected_name, out);
  }
}

// Tests against incorrect name length validation, which is anti-pattern #3 from
// the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, ReadNameTooLongFail) {
  const size_t name_len_cases[] = {256, 257, 258, 300, 10000};

  for (auto name_len : name_len_cases) {
    std::string expected_name;
    const std::vector<uint8_t> data_vector =
        BuildRfc1034Name(name_len, &expected_name);
    ASSERT_EQ(data_vector.size(), name_len + 1);
    const uint8_t* data = data_vector.data();

    DnsRecordParser parser(data_vector, 0, /*num_records=*/0);
    ASSERT_TRUE(parser.IsValid());

    std::string out;
    EXPECT_EQ(0u, parser.ReadName(data, &out));
  }
}

// Tests against incorrect name compression pointer validation, which is anti-
// pattern #6 from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, RejectsNamesWithLoops) {
  const char kData[] =
      "\003www\007example\300\031"  // www.example with pointer to byte 25
      "aaaaaaaaaaa"                 // Garbage data to spread things out.
      "\003foo\300\004";            // foo with pointer to byte 4.

  DnsRecordParser parser(base::byte_span_from_cstring(kData), /*offset=*/0,
                         /*num_records=*/0);
  ASSERT_TRUE(parser.IsValid());

  std::string out;
  EXPECT_EQ(0u, parser.ReadName(kData, &out));
}

// Tests against incorrect name compression pointer validation, which is anti-
// pattern #6 from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, RejectsNamesPointingOutsideData) {
  const char kData[] =
      "\003www\007example\300\031";  // www.example with pointer to byte 25

  DnsRecordParser parser(base::byte_span_from_cstring(kData), /*offset=*/0,
                         /*num_records=*/0);
  ASSERT_TRUE(parser.IsValid());

  std::string out;
  EXPECT_EQ(0u, parser.ReadName(kData, &out));
}

TEST(DnsRecordParserTest, ParsesValidPointer) {
  const char kData[] =
      "\003www\007example\300\022"  // www.example with pointer to byte 25.
      "aaaa"                        // Garbage data to spread things out.
      "\004test\000";               // .test

  DnsRecordParser parser(base::byte_span_from_cstring(kData), /*offset=*/0,
                         /*num_records=*/0);
  ASSERT_TRUE(parser.IsValid());

  std::string out;
  EXPECT_EQ(14u, parser.ReadName(kData, &out));
  EXPECT_EQ(out, "www.example.test");
}

// Per RFC 1035, section 4.1.4, the first 2 bits of a DNS name label determine
// if it is a length label (if the bytes are 00) or a pointer label (if the
// bytes are 11). It is a common DNS parsing bug to treat 01 or 10 as pointer
// labels, but these are reserved and invalid. Such labels should always result
// in DnsRecordParser rejecting the name.
//
// Tests against incorrect name compression pointer validation, which is anti-
// pattern #6 from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, RejectsNamesWithInvalidLabelTypeAsPointer) {
  const char kData[] =
      "\003www\007example\200\022"  // www.example with invalid label as pointer
      "aaaa"                        // Garbage data to spread things out.
      "\004test\000";               // .test

  DnsRecordParser parser(base::byte_span_from_cstring(kData), /*offset=*/0,
                         /*num_records=*/0);
  ASSERT_TRUE(parser.IsValid());

  std::string out;
  EXPECT_EQ(0u, parser.ReadName(kData, &out));
}

// Per RFC 1035, section 4.1.4, the first 2 bits of a DNS name label determine
// if it is a length label (if the bytes are 00) or a pointer label (if the
// bytes are 11). Such labels should always result in DnsRecordParser rejecting
// the name.
//
// Tests against incorrect name compression pointer validation, which is anti-
// pattern #6 from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, RejectsNamesWithInvalidLabelTypeAsLength) {
  const char kData[] =
      "\003www\007example\104"  // www.example with invalid label as length
      "test\000";  // test. (in case \104 is interpreted as length=4)

  // Append a bunch of zeroes to the buffer in case \104 is interpreted as a
  // long length.
  std::string data(kData, sizeof(kData) - 1);
  data.append(256, '\000');

  DnsRecordParser parser(base::as_byte_span(data), /*offset=*/0,
                         /*num_records=*/0);
  ASSERT_TRUE(parser.IsValid());

  std::string out;
  EXPECT_EQ(0u, parser.ReadName(data.data(), &out));
}

TEST(DnsRecordParserTest, ReadRecord) {
  const uint8_t data[] = {
      // Type CNAME record.
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00,
      0x05,                    // TYPE is CNAME.
      0x00, 0x01,              // CLASS is IN.
      0x00, 0x01, 0x24, 0x74,  // TTL is 0x00012474.
      0x00, 0x06,              // RDLENGTH is 6 bytes.
      0x03, 'f', 'o', 'o',     // compressed name in record
      0xc0, 0x00,
      // Type A record.
      0x03, 'b', 'a', 'r',     // compressed owner name
      0xc0, 0x00, 0x00, 0x01,  // TYPE is A.
      0x00, 0x01,              // CLASS is IN.
      0x00, 0x20, 0x13, 0x55,  // TTL is 0x00201355.
      0x00, 0x04,              // RDLENGTH is 4 bytes.
      0x7f, 0x02, 0x04, 0x01,  // IP is 127.2.4.1
  };

  std::string out;
  DnsRecordParser parser(data, 0, /*num_records=*/2);

  DnsResourceRecord record;
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_EQ("example.com", record.name);
  EXPECT_EQ(dns_protocol::kTypeCNAME, record.type);
  EXPECT_EQ(dns_protocol::kClassIN, record.klass);
  EXPECT_EQ(0x00012474u, record.ttl);
  EXPECT_EQ(6u, record.rdata.length());
  EXPECT_EQ(6u, parser.ReadName(record.rdata.data(), &out));
  EXPECT_EQ("foo.example.com", out);
  EXPECT_FALSE(parser.AtEnd());

  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_EQ("bar.example.com", record.name);
  EXPECT_EQ(dns_protocol::kTypeA, record.type);
  EXPECT_EQ(dns_protocol::kClassIN, record.klass);
  EXPECT_EQ(0x00201355u, record.ttl);
  EXPECT_EQ(4u, record.rdata.length());
  EXPECT_EQ(std::string_view("\x7f\x02\x04\x01"), record.rdata);
  EXPECT_TRUE(parser.AtEnd());

  // Test truncated record.
  auto span = base::span(data);
  parser = DnsRecordParser(span.first(span.size() - 2), 0, /*num_records=*/2);
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_FALSE(parser.AtEnd());
  EXPECT_FALSE(parser.ReadRecord(&record));
}

TEST(DnsRecordParserTest, ReadsRecordWithLongName) {
  std::string dotted_name;
  const std::vector<uint8_t> dns_name =
      BuildRfc1034Name(dns_protocol::kMaxNameLength, &dotted_name);

  std::string data(reinterpret_cast<const char*>(dns_name.data()),
                   dns_name.size());
  data.append(
      "\x00\x01"           // TYPE=A
      "\x00\x01"           // CLASS=IN
      "\x00\x01\x51\x80"   // TTL=1 day
      "\x00\x04"           // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x01",  // 192.168.0.1
      14);

  DnsRecordParser parser(base::as_byte_span(data), 0, /*num_records=*/1);

  DnsResourceRecord record;
  EXPECT_TRUE(parser.ReadRecord(&record));
}

// Tests against incorrect name length validation, which is anti-pattern #3 from
// the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, RejectRecordWithTooLongName) {
  std::string dotted_name;
  const std::vector<uint8_t> dns_name =
      BuildRfc1034Name(dns_protocol::kMaxNameLength + 1, &dotted_name);

  std::string data(reinterpret_cast<const char*>(dns_name.data()),
                   dns_name.size());
  data.append(
      "\x00\x01"           // TYPE=A
      "\x00\x01"           // CLASS=IN
      "\x00\x01\x51\x80"   // TTL=1 day
      "\x00\x04"           // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x01",  // 192.168.0.1
      14);

  DnsRecordParser parser(base::as_byte_span(data), 0, /*num_records=*/1);

  DnsResourceRecord record;
  EXPECT_FALSE(parser.ReadRecord(&record));
}

// Test that a record cannot be parsed with a name extending past the end of the
// data.
// Tests against incorrect name length validation, which is anti-pattern #3 from
// the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, RejectRecordWithNonendedName) {
  const char kNonendedName[] = "\003www\006google\006www";

  DnsRecordParser parser(base::byte_span_from_cstring(kNonendedName), 0,
                         /*num_records=*/1);

  DnsResourceRecord record;
  EXPECT_FALSE(parser.ReadRecord(&record));
}

// Test that a record cannot be parsed with a name without final null
// termination. Parsing should assume the name has not ended and find the first
// byte of the TYPE field instead, making the remainder of the record
// unparsable.
// Tests against incorrect name null termination, which is anti-pattern #4 from
// the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST(DnsRecordParserTest, RejectRecordNameMissingNullTermination) {
  const char kData[] =
      "\003www\006google\004test"  // Name without termination.
      "\x00\x01"                   // TYPE=A
      "\x00\x01"                   // CLASS=IN
      "\x00\x01\x51\x80"           // TTL=1 day
      "\x00\x04"                   // RDLENGTH=4 bytes
      "\xc0\xa8\x00\x01";          // 192.168.0.1

  DnsRecordParser parser(base::byte_span_from_cstring(kData), 0,
                         /*num_records=*/1);

  DnsResourceRecord record;
  EXPECT_FALSE(parser.ReadRecord(&record));
}

// Test that no more records can be parsed once the claimed number of records
// have been parsed.
TEST(DnsRecordParserTest, RejectReadingTooManyRecords) {
  const char kData[] =
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

  DnsRecordParser parser(
      base::byte_span_from_cstring(kData), /*offset=*/0,
      /*num_records=*/1);  // Claim 1 record despite there being 2 in `kData`.

  DnsResourceRecord record1;
  EXPECT_TRUE(parser.ReadRecord(&record1));

  // Expect second record cannot be parsed because only 1 was expected.
  DnsResourceRecord record2;
  EXPECT_FALSE(parser.ReadRecord(&record2));
}

// Test that no more records can be parsed once the end of the buffer is
// reached, even if more records are claimed.
TEST(DnsRecordParserTest, RejectReadingPastEnd) {
  const char kData[] =
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

  DnsRecordParser parser(
      base::byte_span_from_cstring(kData), /*offset=*/0,
      /*num_records=*/3);  // Claim 3 record despite there being 2 in `kData`.

  DnsResourceRecord record;
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_FALSE(parser.ReadRecord(&record));
}

TEST(DnsResponseTest, InitParse) {
  // This includes \0 at the end.
  const char qname[] =
      "\x0A"
      "codereview"
      "\x08"
      "chromium"
      "\x03"
      "org";
  // Compilers want to copy when binding temporary to const &, so must use heap.
  auto query = std::make_unique<DnsQuery>(0xcafe, base::as_byte_span(qname),
                                          dns_protocol::kTypeA);

  const uint8_t response_data[] = {
      // Header
      0xca, 0xfe,  // ID
      0x81, 0x80,  // Standard query response, RA, no error
      0x00, 0x01,  // 1 question
      0x00, 0x02,  // 2 RRs (answers)
      0x00, 0x00,  // 0 authority RRs
      0x00, 0x01,  // 1 additional RRs

      // Question
      // This part is echoed back from the respective query.
      0x0a, 'c', 'o', 'd', 'e', 'r', 'e', 'v', 'i', 'e', 'w', 0x08, 'c', 'h',
      'r', 'o', 'm', 'i', 'u', 'm', 0x03, 'o', 'r', 'g', 0x00, 0x00,
      0x01,        // TYPE is A.
      0x00, 0x01,  // CLASS is IN.

      // Answer 1
      0xc0, 0x0c,  // NAME is a pointer to name in Question section.
      0x00, 0x05,  // TYPE is CNAME.
      0x00, 0x01,  // CLASS is IN.
      0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
      0x24, 0x74, 0x00, 0x12,  // RDLENGTH is 18 bytes.
      // ghs.l.google.com in DNS format.
      0x03, 'g', 'h', 's', 0x01, 'l', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03,
      'c', 'o', 'm', 0x00,

      // Answer 2
      0xc0, 0x35,              // NAME is a pointer to name in Answer 1.
      0x00, 0x01,              // TYPE is A.
      0x00, 0x01,              // CLASS is IN.
      0x00, 0x00,              // TTL (4 bytes) is 53 seconds.
      0x00, 0x35, 0x00, 0x04,  // RDLENGTH is 4 bytes.
      0x4a, 0x7d,              // RDATA is the IP: 74.125.95.121
      0x5f, 0x79,

      // Additional 1
      0x00,                    // NAME is empty (root domain).
      0x00, 0x29,              // TYPE is OPT.
      0x10, 0x00,              // CLASS is max UDP payload size (4096).
      0x00, 0x00, 0x00, 0x00,  // TTL (4 bytes) is rcode, version and flags.
      0x00, 0x08,              // RDLENGTH
      0x00, 0xFF,              // OPT code
      0x00, 0x04,              // OPT data size
      0xDE, 0xAD, 0xBE, 0xEF   // OPT data
  };

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), response_data, sizeof(response_data));

  EXPECT_FALSE(resp.id());

  // Reject too short.
  EXPECT_FALSE(resp.InitParse(query->io_buffer()->size() - 1, *query));
  EXPECT_FALSE(resp.IsValid());
  EXPECT_FALSE(resp.id());

  // Reject wrong id.
  std::unique_ptr<DnsQuery> other_query = query->CloneWithNewId(0xbeef);
  EXPECT_FALSE(resp.InitParse(sizeof(response_data), *other_query));
  EXPECT_FALSE(resp.IsValid());
  EXPECT_THAT(resp.id(), testing::Optional(0xcafe));

  // Reject wrong question.
  auto wrong_query = std::make_unique<DnsQuery>(
      0xcafe, base::as_byte_span(qname), dns_protocol::kTypeCNAME);
  EXPECT_FALSE(resp.InitParse(sizeof(response_data), *wrong_query));
  EXPECT_FALSE(resp.IsValid());
  EXPECT_THAT(resp.id(), testing::Optional(0xcafe));

  // Accept matching question.
  EXPECT_TRUE(resp.InitParse(sizeof(response_data), *query));
  EXPECT_TRUE(resp.IsValid());

  // Check header access.
  EXPECT_THAT(resp.id(), testing::Optional(0xcafe));
  EXPECT_EQ(0x8180, resp.flags());
  EXPECT_EQ(0x0, resp.rcode());
  EXPECT_EQ(2u, resp.answer_count());
  EXPECT_EQ(1u, resp.additional_answer_count());

  // Check question access.
  std::optional<std::vector<uint8_t>> response_qname =
      dns_names_util::DottedNameToNetwork(resp.GetSingleDottedName());
  ASSERT_TRUE(response_qname.has_value());
  EXPECT_THAT(query->qname(),
              testing::ElementsAreArray(response_qname.value()));
  EXPECT_EQ(query->qtype(), resp.GetSingleQType());
  EXPECT_EQ("codereview.chromium.org", resp.GetSingleDottedName());

  DnsResourceRecord record;
  DnsRecordParser parser = resp.Parser();
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_FALSE(parser.AtEnd());
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_FALSE(parser.AtEnd());
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_TRUE(parser.AtEnd());
  EXPECT_FALSE(parser.ReadRecord(&record));
}

TEST(DnsResponseTest, InitParseInvalidFlags) {
  // This includes \0 at the end.
  const char qname[] =
      "\x0A"
      "codereview"
      "\x08"
      "chromium"
      "\x03"
      "org";
  // Compilers want to copy when binding temporary to const &, so must use heap.
  auto query = std::make_unique<DnsQuery>(0xcafe, base::as_byte_span(qname),
                                          dns_protocol::kTypeA);

  const uint8_t response_data[] = {
      // Header
      0xca, 0xfe,  // ID
      0x01, 0x80,  // RA, no error. Note the absence of the required QR bit.
      0x00, 0x01,  // 1 question
      0x00, 0x01,  // 1 RRs (answers)
      0x00, 0x00,  // 0 authority RRs
      0x00, 0x00,  // 0 additional RRs

      // Question
      // This part is echoed back from the respective query.
      0x0a, 'c', 'o', 'd', 'e', 'r', 'e', 'v', 'i', 'e', 'w', 0x08, 'c', 'h',
      'r', 'o', 'm', 'i', 'u', 'm', 0x03, 'o', 'r', 'g', 0x00, 0x00,
      0x01,        // TYPE is A.
      0x00, 0x01,  // CLASS is IN.

      // Answer 1
      0xc0, 0x0c,  // NAME is a pointer to name in Question section.
      0x00, 0x05,  // TYPE is CNAME.
      0x00, 0x01,  // CLASS is IN.
      0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
      0x24, 0x74, 0x00, 0x12,  // RDLENGTH is 18 bytes.
      // ghs.l.google.com in DNS format.
      0x03, 'g', 'h', 's', 0x01, 'l', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03,
      'c', 'o', 'm', 0x00,
  };

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), response_data, sizeof(response_data));

  EXPECT_FALSE(resp.InitParse(sizeof(response_data), *query));
  EXPECT_FALSE(resp.IsValid());
  EXPECT_THAT(resp.id(), testing::Optional(0xcafe));
}

TEST(DnsResponseTest, InitParseRejectsResponseWithoutQuestions) {
  const char kResponse[] =
      "\x02\x45"                       // ID=581
      "\x81\x80"                       // Standard query response, RA, no error
      "\x00\x00"                       // 0 questions
      "\x00\x01"                       // 1 answers
      "\x00\x00"                       // 0 authority records
      "\x00\x00"                       // 0 additional records
      "\003www\006google\004test\000"  // www.google.test
      "\x00\x01"                       // TYPE=A
      "\x00\x01"                       // CLASS=IN
      "\x00\x00\x2a\x30"               // TTL=3 hours
      "\x00\x04"                       // RDLENGTH=4 bytes
      "\xa0\xa0\xa0\xa0";              // 10.10.10.10

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  // Validate that the response is fine if not matching against a query.
  ASSERT_TRUE(resp.InitParseWithoutQuery(sizeof(kResponse) - 1));

  const char kQueryName[] = "\003www\006google\004test";
  DnsQuery query(
      /*id=*/581, base::as_byte_span(kQueryName), dns_protocol::kTypeA);
  EXPECT_FALSE(resp.InitParse(sizeof(kResponse) - 1, query));
}

TEST(DnsResponseTest, InitParseRejectsResponseWithTooManyQuestions) {
  const char kResponse[] =
      "\x02\x46"                       // ID=582
      "\x81\x80"                       // Standard query response, RA, no error
      "\x00\x02"                       // 2 questions
      "\x00\x00"                       // 0 answers
      "\x00\x00"                       // 0 authority records
      "\x00\x00"                       // 0 additional records
      "\003www\006google\004test\000"  // www.google.test
      "\x00\x01"                       // TYPE=A
      "\x00\x01"                       // CLASS=IN
      "\003www\010chromium\004test\000"  // www.chromium.test
      "\x00\x01"                         // TYPE=A
      "\x00\x01";                        // CLASS=IN

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), kResponse, sizeof(kResponse) - 1);

  // Validate that the response is fine if not matching against a query.
  ASSERT_TRUE(resp.InitParseWithoutQuery(sizeof(kResponse) - 1));

  const char kQueryName[] = "\003www\006google\004test";
  DnsQuery query(
      /*id=*/582, base::as_byte_span(kQueryName), dns_protocol::kTypeA);
  EXPECT_FALSE(resp.InitParse(sizeof(kResponse) - 1, query));
}

TEST(DnsResponseTest, InitParseWithoutQuery) {
  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), kT0ResponseDatagram,
         sizeof(kT0ResponseDatagram));

  // Accept matching question.
  EXPECT_TRUE(resp.InitParseWithoutQuery(sizeof(kT0ResponseDatagram)));
  EXPECT_TRUE(resp.IsValid());

  // Check header access.
  EXPECT_EQ(0x8180, resp.flags());
  EXPECT_EQ(0x0, resp.rcode());
  EXPECT_EQ(kT0RecordCount, resp.answer_count());

  // Check question access.
  EXPECT_EQ(kT0Qtype, resp.GetSingleQType());
  EXPECT_EQ(kT0HostName, resp.GetSingleDottedName());

  DnsResourceRecord record;
  DnsRecordParser parser = resp.Parser();
  for (unsigned i = 0; i < kT0RecordCount; i ++) {
    EXPECT_FALSE(parser.AtEnd());
    EXPECT_TRUE(parser.ReadRecord(&record));
  }
  EXPECT_TRUE(parser.AtEnd());
  EXPECT_FALSE(parser.ReadRecord(&record));
}

TEST(DnsResponseTest, InitParseWithoutQueryNoQuestions) {
  const uint8_t response_data[] = {
      // Header
      0xca, 0xfe,  // ID
      0x81, 0x80,  // Standard query response, RA, no error
      0x00, 0x00,  // No question
      0x00, 0x01,  // 2 RRs (answers)
      0x00, 0x00,  // 0 authority RRs
      0x00, 0x00,  // 0 additional RRs

      // Answer 1
      0x0a, 'c', 'o', 'd', 'e', 'r', 'e', 'v', 'i', 'e', 'w', 0x08, 'c', 'h',
      'r', 'o', 'm', 'i', 'u', 'm', 0x03, 'o', 'r', 'g', 0x00, 0x00,
      0x01,                    // TYPE is A.
      0x00, 0x01,              // CLASS is IN.
      0x00, 0x00,              // TTL (4 bytes) is 53 seconds.
      0x00, 0x35, 0x00, 0x04,  // RDLENGTH is 4 bytes.
      0x4a, 0x7d,              // RDATA is the IP: 74.125.95.121
      0x5f, 0x79,
  };

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), response_data, sizeof(response_data));

  EXPECT_TRUE(resp.InitParseWithoutQuery(sizeof(response_data)));

  // Check header access.
  EXPECT_THAT(resp.id(), testing::Optional(0xcafe));
  EXPECT_EQ(0x8180, resp.flags());
  EXPECT_EQ(0x0, resp.rcode());
  EXPECT_EQ(0u, resp.question_count());
  EXPECT_EQ(0x1u, resp.answer_count());

  EXPECT_THAT(resp.dotted_qnames(), testing::IsEmpty());
  EXPECT_THAT(resp.qtypes(), testing::IsEmpty());

  DnsResourceRecord record;
  DnsRecordParser parser = resp.Parser();

  EXPECT_FALSE(parser.AtEnd());
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_EQ("codereview.chromium.org", record.name);
  EXPECT_EQ(0x00000035u, record.ttl);
  EXPECT_EQ(dns_protocol::kTypeA, record.type);

  EXPECT_TRUE(parser.AtEnd());
  EXPECT_FALSE(parser.ReadRecord(&record));
}

TEST(DnsResponseTest, InitParseWithoutQueryInvalidFlags) {
  const uint8_t response_data[] = {
      // Header
      0xca, 0xfe,  // ID
      0x01, 0x80,  // RA, no error. Note the absence of the required QR bit.
      0x00, 0x00,  // No question
      0x00, 0x01,  // 2 RRs (answers)
      0x00, 0x00,  // 0 authority RRs
      0x00, 0x00,  // 0 additional RRs

      // Answer 1
      0x0a, 'c', 'o', 'd', 'e', 'r', 'e', 'v', 'i', 'e', 'w', 0x08, 'c', 'h',
      'r', 'o', 'm', 'i', 'u', 'm', 0x03, 'o', 'r', 'g', 0x00, 0x00,
      0x01,                    // TYPE is A.
      0x00, 0x01,              // CLASS is IN.
      0x00, 0x00,              // TTL (4 bytes) is 53 seconds.
      0x00, 0x35, 0x00, 0x04,  // RDLENGTH is 4 bytes.
      0x4a, 0x7d,              // RDATA is the IP: 74.125.95.121
      0x5f, 0x79,
  };

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), response_data, sizeof(response_data));

  EXPECT_FALSE(resp.InitParseWithoutQuery(sizeof(response_data)));
  EXPECT_THAT(resp.id(), testing::Optional(0xcafe));
}

TEST(DnsResponseTest, InitParseWithoutQueryTwoQuestions) {
  const uint8_t response_data[] = {
      // Header
      0xca,
      0xfe,  // ID
      0x81,
      0x80,  // Standard query response, RA, no error
      0x00,
      0x02,  // 2 questions
      0x00,
      0x01,  // 2 RRs (answers)
      0x00,
      0x00,  // 0 authority RRs
      0x00,
      0x00,  // 0 additional RRs

      // Question 1
      0x0a,
      'c',
      'o',
      'd',
      'e',
      'r',
      'e',
      'v',
      'i',
      'e',
      'w',
      0x08,
      'c',
      'h',
      'r',
      'o',
      'm',
      'i',
      'u',
      'm',
      0x03,
      'o',
      'r',
      'g',
      0x00,
      0x00,
      0x01,  // TYPE is A.
      0x00,
      0x01,  // CLASS is IN.

      // Question 2
      0x0b,
      'c',
      'o',
      'd',
      'e',
      'r',
      'e',
      'v',
      'i',
      'e',
      'w',
      '2',
      0xc0,
      0x17,  // pointer to "chromium.org"
      0x00,
      0x01,  // TYPE is A.
      0x00,
      0x01,  // CLASS is IN.

      // Answer 1
      0xc0,
      0x0c,  // NAME is a pointer to name in Question section.
      0x00,
      0x01,  // TYPE is A.
      0x00,
      0x01,  // CLASS is IN.
      0x00,
      0x00,  // TTL (4 bytes) is 53 seconds.
      0x00,
      0x35,
      0x00,
      0x04,  // RDLENGTH is 4 bytes.
      0x4a,
      0x7d,  // RDATA is the IP: 74.125.95.121
      0x5f,
      0x79,
  };

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), response_data, sizeof(response_data));

  EXPECT_TRUE(resp.InitParseWithoutQuery(sizeof(response_data)));

  // Check header access.
  EXPECT_EQ(0x8180, resp.flags());
  EXPECT_EQ(0x0, resp.rcode());
  EXPECT_EQ(2u, resp.question_count());
  EXPECT_EQ(0x01u, resp.answer_count());

  EXPECT_THAT(resp.dotted_qnames(),
              testing::ElementsAre("codereview.chromium.org",
                                   "codereview2.chromium.org"));
  EXPECT_THAT(resp.qtypes(),
              testing::ElementsAre(dns_protocol::kTypeA, dns_protocol::kTypeA));

  DnsResourceRecord record;
  DnsRecordParser parser = resp.Parser();

  EXPECT_FALSE(parser.AtEnd());
  EXPECT_TRUE(parser.ReadRecord(&record));
  EXPECT_EQ("codereview.chromium.org", record.name);
  EXPECT_EQ(0x35u, record.ttl);
  EXPECT_EQ(dns_protocol::kTypeA, record.type);

  EXPECT_TRUE(parser.AtEnd());
  EXPECT_FALSE(parser.ReadRecord(&record));
}

TEST(DnsResponseTest, InitParseWithoutQueryPacketTooShort) {
  const uint8_t response_data[] = {
      // Header
      0xca, 0xfe,  // ID
      0x81, 0x80,  // Standard query response, RA, no error
      0x00, 0x00,  // No question
  };

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), response_data, sizeof(response_data));

  EXPECT_FALSE(resp.InitParseWithoutQuery(sizeof(response_data)));
}

TEST(DnsResponseTest, InitParseAllowsQuestionWithL
"""


```