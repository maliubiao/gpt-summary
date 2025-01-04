Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The request asks for the functionality of the `opt_record_rdata_unittest.cc` file within the Chromium networking stack. It also asks for connections to JavaScript, logical reasoning examples, common user errors, and debugging tips.

2. **Identify the Core Subject:** The filename and the `#include "net/dns/opt_record_rdata.h"` clearly indicate that this file tests the `OptRecordRdata` class. This class is part of the DNS (Domain Name System) implementation in Chromium.

3. **Examine the Includes:**  The included headers provide valuable context:
    * `net/dns/opt_record_rdata.h`:  This is the header file for the class being tested, defining its interface.
    * `<algorithm>`, `<memory>`, `<optional>`, `<string_view>`, `<utility>`: Standard C++ library headers, suggesting memory management, optional values, and string manipulation are involved.
    * `base/big_endian.h`: Indicates handling of byte order, common in network protocols.
    * `net/dns/dns_response.h`, `net/dns/dns_test_util.h`:  Confirms this is related to DNS and uses test utilities specific to the DNS components.
    * `net/test/gtest_util.h`, `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  These are the Google Test and Google Mock frameworks, confirming this file is a unit test.

4. **Analyze the Test Structure:**  The file uses Google Test's `TEST` macro. Each `TEST` function focuses on a specific aspect of `OptRecordRdata` functionality. This is a standard practice in unit testing.

5. **Deconstruct Individual Tests:**  Go through each `TEST` function and determine its purpose:
    * `ParseOptRecord`: Tests parsing a basic OPT record with unknown options.
    * `ParseOptRecordWithShorterSizeThanData`, `ParseOptRecordWithLongerSizeThanData`: Test error handling for incorrectly sized OPT data.
    * `CreateEdeOpt`: Tests the creation of EDE (Extended DNS Error) options.
    * `TestEdeInfoCode`: Tests the mapping of EDE info codes to enums.
    * `ParseEdeOptRecords`: Tests parsing an OPT record containing both unknown and EDE options.
    * `OptEquality`: Tests the equality operator for `OptRecordRdata` and its nested `Opt` classes.
    * `EdeRecordTooSmall`, `EdeRecordNoExtraText`, `EdeRecordExtraTextNonUTF8`, `EdeRecordUnknownInfoCode`: Test various scenarios and edge cases related to parsing EDE options.
    * `CreatePaddingOpt`, `ParsePaddingOpt`: Test creating and parsing Padding options.
    * `AddOptToOptRecord`: Tests adding options to an `OptRecordRdata` object.
    * `EqualityIsOptOrderSensitive`:  Crucially tests that the equality comparison respects the order of options.
    * `TestGetOptsOrder`: Tests that retrieving options maintains the insertion order for options with the same code.

6. **Synthesize the Functionality:** Based on the individual tests, summarize the overall functionality of `OptRecordRdata`:
    * Parsing the RDATA portion of a DNS OPT record.
    * Handling different types of OPT options (unknown, EDE, Padding).
    * Managing and accessing the collection of OPT options.
    * Implementing equality comparisons, considering option order.
    * Error handling during parsing (e.g., incorrect data sizes, invalid UTF-8).

7. **Address Specific Questions:** Now tackle the specific points raised in the request:

    * **Relationship to JavaScript:** Think about where DNS interacts with the browser. JavaScript in web pages can trigger DNS lookups (indirectly through fetching resources). Explain that while this C++ code doesn't directly *execute* JavaScript, it's part of the browser's infrastructure that supports network requests initiated by JavaScript. Give an example of a JavaScript `fetch()` call causing a DNS lookup.

    * **Logical Reasoning (Input/Output):** Choose a relevant test case (e.g., `ParseOptRecord`). Describe the input (the byte array) and the expected output (the `OptRecordRdata` object with parsed `UnknownOpt` objects).

    * **Common User/Programming Errors:** Consider mistakes developers might make when dealing with DNS or this specific class. Examples include providing malformed DNS data, assuming specific option order when it's not guaranteed by the standard, or misinterpreting the meaning of different OPT options.

    * **User Operations and Debugging:**  Trace how a user action (like visiting a website) leads to DNS resolution. Then, explain how this unit test might be used during development to verify the correctness of the `OptRecordRdata` parsing logic. Emphasize how failures in these tests would guide developers to investigate specific parsing issues.

8. **Refine and Organize:** Structure the answer clearly with headings for each part of the request. Use code examples from the test file to illustrate the explanations. Ensure the language is precise and avoids jargon where possible, while still being technically accurate.

9. **Review and Iterate:** Read through the answer to ensure it's comprehensive, accurate, and addresses all aspects of the original request. For instance, initially, I might have missed the significance of the option order in the equality tests, so a review would catch that.

This systematic approach helps to dissect the code, understand its purpose, and connect it to the broader context of web browsing and development. It also makes it easier to address the specific constraints and questions in the request.
这个文件 `net/dns/opt_record_rdata_unittest.cc` 是 Chromium 网络栈中关于 DNS (Domain Name System) 功能的一部分，专门用于测试 `net/dns/opt_record_rdata.h` 中定义的 `OptRecordRdata` 类的功能。`OptRecordRdata` 类用于解析和操作 DNS OPT (Options) 记录中的 RDATA (Resource Data) 部分。

以下是该文件的主要功能：

**1. 解析 OPT 记录的 RDATA:**

*   该文件包含了多个测试用例，用于验证 `OptRecordRdata::Create()` 方法能否正确地将字节流解析成 `OptRecordRdata` 对象。
*   测试用例涵盖了不同格式的 OPT RDATA，包括包含多个 OPT 选项的情况。
*   它测试了当 OPT 选项的数据长度与声明长度不一致时的解析行为（预期会解析失败）。

**2. 处理不同类型的 OPT 选项:**

*   **未知 OPT 选项 (`UnknownOpt`):** 测试了对未知 OPT 选项的解析，包括 OPT 代码和 OPT 数据的提取。
*   **EDE OPT 选项 (`EdeOpt`):**  EDE (Extended DNS Errors) 选项用于提供更详细的 DNS 错误信息。文件测试了 EDE 选项的创建、解析，以及对 EDE Info Code 的解析和枚举转换。它还测试了 EDE 选项中附加文本的 UTF-8 编码校验。
*   **Padding OPT 选项 (`PaddingOpt`):**  Padding 选项用于填充 OPT 记录，该文件测试了 Padding 选项的创建和解析。

**3. 操作 OPT 记录:**

*   **添加 OPT 选项 (`AddOpt`):** 测试了向 `OptRecordRdata` 对象中添加 OPT 选项的功能。
*   **获取 OPT 选项 (`GetOpts`, `GetEdeOpts`, `GetPaddingOpts`):** 测试了从 `OptRecordRdata` 对象中获取不同类型 OPT 选项列表的功能。
*   **检查是否包含特定 OPT 代码 (`ContainsOptCode`):** 测试了检查 `OptRecordRdata` 对象是否包含具有特定代码的 OPT 选项的功能。

**4. 比较 OPT 记录:**

*   **相等性比较 (`operator==`, `IsEqual`):** 测试了 `OptRecordRdata` 对象及其包含的 OPT 选项的相等性比较，并且**强调了 OPT 选项的顺序在比较中的重要性**。

**与 JavaScript 的关系:**

该 C++ 代码直接位于 Chromium 的网络栈底层，负责 DNS 协议的解析和处理。JavaScript 代码本身不能直接操作这些底层的网络协议细节。但是，JavaScript 发起的网络请求（例如使用 `fetch` 或 `XMLHttpRequest`）会触发浏览器的 DNS 查询过程，而这个 C++ 代码就参与了这个过程。

**举例说明:**

假设 JavaScript 代码发起了一个对 `example.com` 的请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这段 JavaScript 代码执行时，浏览器需要知道 `example.com` 的 IP 地址。这个过程会触发 DNS 查询。

*   浏览器会构建一个 DNS 查询报文。
*   如果 DNS 服务器的响应中包含 OPT 记录，`OptRecordRdata` 类负责解析这个 OPT 记录的 RDATA 部分，提取其中的 OPT 选项。
*   例如，如果 DNS 服务器返回的 OPT 记录中包含 EDE 选项，`OptRecordRdata` 能够解析出错误的具体类型（如 `kNxDomain`，域名不存在）以及服务器提供的额外信息。
*   尽管 JavaScript 代码无法直接访问这些 OPT 记录的细节，但这些信息可能影响浏览器后续的网络行为，例如在开发者工具中显示更详细的 DNS 错误信息。

**逻辑推理、假设输入与输出:**

**假设输入:** 一个包含两个 OPT 选项的 OPT RDATA 字节流：

```
const uint8_t rdata[] = {
    // First OPT (Unknown)
    0x00, 0x01,  // OPT code: 1
    0x00, 0x02,  // OPT data size: 2
    0xDE, 0xAD,  // OPT data: 0xDEAD

    // Second OPT (EDE)
    0x00, 0x0F,  // OPT code: 15 (EDE)
    0x00, 0x04,  // OPT data size: 4
    0x00, 0x03,  // EDE info code: 3
    0x41, 0x42  // EDE extra text: "AB"
};
```

**预期输出:**

*   `OptRecordRdata::Create(rdata_strpiece)` 应该返回一个非空的 `OptRecordRdata` 对象。
*   `rdata_obj->OptCount()` 应该返回 `2u`。
*   `rdata_obj->ContainsOptCode(1)` 应该返回 `true`。
*   `rdata_obj->ContainsOptCode(15)` 应该返回 `true`。
*   `rdata_obj->GetOpts()` 应该包含两个 `OptRecordRdata::Opt` 对象，第一个是 `UnknownOpt`，第二个是 `EdeOpt`。
*   第一个 `OptRecordRdata::UnknownOpt` 的代码应该为 `1`，数据应该为 `"\xDE\xAD"`。
*   第二个 `OptRecordRdata::EdeOpt` 的 info code 应该为 `3`，extra text 应该为 `"AB"`。

**用户或编程常见的使用错误:**

1. **手动构建 DNS 报文时字节序错误:** 用户或程序员在手动构建 DNS 报文时，可能会错误地使用本地字节序而不是网络字节序（大端序），导致 `OptRecordRdata::Create()` 解析失败。

    **举例:** OPT 代码和数据长度都是 16 位整数。如果错误地将小端序的数据放入报文，例如将 OPT 代码 `1` (0x0001) 编码为 `0x0100`，`OptRecordRdata` 将无法正确解析。

2. **假设 OPT 选项的顺序:** 尽管 `OptRecordRdata` 的相等性比较考虑了顺序，但在实际的 DNS 服务器实现中，OPT 选项的返回顺序可能是不确定的。依赖于特定 OPT 选项的顺序可能导致问题。

3. **错误地解释 EDE Info Code:**  用户或程序员可能会错误地理解或使用 EDE Info Code 的含义，导致对 DNS 错误的误判。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址，例如 `https://example.com`，或者点击网页上的链接。**
2. **浏览器首先需要解析域名 `example.com` 对应的 IP 地址。**
3. **浏览器会向本地 DNS 解析器（通常由操作系统提供）发起 DNS 查询。**
4. **本地 DNS 解析器可能会在其缓存中查找，如果未找到，则会递归地向根域名服务器、顶级域名服务器等发起查询。**
5. **最终，负责 `example.com` 域名的权威 DNS 服务器会返回 DNS 响应报文。**
6. **这个 DNS 响应报文可能包含一个 OPT 记录，用于传递额外的信息，例如支持的 DNSSEC 算法、客户端子网信息（EDNS Client Subnet）或者扩展错误信息（EDE）。**
7. **Chromium 的网络栈接收到这个 DNS 响应报文后，如果检测到 OPT 记录，就会创建 `OptRecordRdata` 对象来解析其 RDATA 部分。**
8. **`net/dns/opt_record_rdata_unittest.cc` 中定义的测试用例就是为了验证 `OptRecordRdata` 类在这个解析过程中是否正确地工作。**

**调试线索:**

*   如果在浏览器访问特定网站时遇到 DNS 相关的问题（例如无法解析域名，或者出现与 DNSSEC 相关的错误），开发人员可能会怀疑是 DNS 解析过程中 OPT 记录处理出现了问题。
*   可以使用网络抓包工具（如 Wireshark）捕获 DNS 查询和响应报文，查看返回的 OPT 记录的具体内容。
*   通过查看抓包数据，可以将实际收到的 OPT RDATA 字节流与 `net/dns/opt_record_rdata_unittest.cc` 中的测试用例进行对比，判断 `OptRecordRdata` 的解析逻辑是否符合预期。
*   如果测试用例失败，则表明 `OptRecordRdata` 的实现存在 bug，需要修复。例如，某个特定的 EDE Info Code 没有被正确解析，或者处理包含特定 OPT 选项的报文时崩溃。
*   开发人员还可以编写新的测试用例，模拟导致问题的 DNS 响应报文，以便更好地定位和修复 bug。

Prompt: 
```
这是目录为net/dns/opt_record_rdata_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/opt_record_rdata.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "base/big_endian.h"
#include "net/dns/dns_response.h"
#include "net/dns/dns_test_util.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

using ::testing::ElementsAreArray;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::SizeIs;

std::string_view MakeStringPiece(const uint8_t* data, unsigned size) {
  const char* data_cc = reinterpret_cast<const char*>(data);
  return std::string_view(data_cc, size);
}

TEST(OptRecordRdataTest, ParseOptRecord) {
  // This is just the rdata portion of an OPT record, rather than a complete
  // record.
  const uint8_t rdata[] = {
      // First OPT
      0x00, 0x01,  // OPT code
      0x00, 0x02,  // OPT data size
      0xDE, 0xAD,  // OPT data
      // Second OPT
      0x00, 0xFF,             // OPT code
      0x00, 0x04,             // OPT data size
      0xDE, 0xAD, 0xBE, 0xEF  // OPT data
  };

  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));
  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);

  ASSERT_THAT(rdata_obj, NotNull());
  ASSERT_EQ(rdata_obj->OptCount(), 2u);

  // Check contains
  ASSERT_TRUE(rdata_obj->ContainsOptCode(1));
  ASSERT_FALSE(rdata_obj->ContainsOptCode(30));

  // Check elements

  // Note: When passing string or std::string_view as argument, make sure to
  // construct arguments with length. Otherwise, strings containing a '\0'
  // character will be truncated.
  // https://crbug.com/1348679

  std::unique_ptr<OptRecordRdata::UnknownOpt> opt0 =
      OptRecordRdata::UnknownOpt::CreateForTesting(1,
                                                   std::string("\xde\xad", 2));
  std::unique_ptr<OptRecordRdata::UnknownOpt> opt1 =
      OptRecordRdata::UnknownOpt::CreateForTesting(
          255, std::string("\xde\xad\xbe\xef", 4));

  ASSERT_EQ(*(rdata_obj->GetOpts()[0]), *(opt0.get()));
  ASSERT_EQ(*(rdata_obj->GetOpts()[1]), *(opt1.get()));
}

TEST(OptRecordRdataTest, ParseOptRecordWithShorterSizeThanData) {
  // This is just the rdata portion of an OPT record, rather than a complete
  // record.
  const uint8_t rdata[] = {
      0x00, 0xFF,             // OPT code
      0x00, 0x02,             // OPT data size (incorrect, should be 4)
      0xDE, 0xAD, 0xBE, 0xEF  // OPT data
  };

  DnsRecordParser parser(rdata, 0, /*num_records=*/0);
  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));

  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);
  ASSERT_THAT(rdata_obj, IsNull());
}

TEST(OptRecordRdataTest, ParseOptRecordWithLongerSizeThanData) {
  // This is just the rdata portion of an OPT record, rather than a complete
  // record.
  const uint8_t rdata[] = {
      0x00, 0xFF,  // OPT code
      0x00, 0x04,  // OPT data size (incorrect, should be 4)
      0xDE, 0xAD   // OPT data
  };

  DnsRecordParser parser(rdata, 0, /*num_records=*/0);
  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));

  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);
  ASSERT_THAT(rdata_obj, IsNull());
}

TEST(OptRecordRdataTest, CreateEdeOpt) {
  OptRecordRdata::EdeOpt opt0(22, std::string("Don Quixote"));

  ASSERT_EQ(opt0.data(), std::string("\x00\x16"
                                     "Don Quixote",
                                     13));
  ASSERT_EQ(opt0.info_code(), 22u);
  ASSERT_EQ(opt0.extra_text(), std::string("Don Quixote"));

  std::unique_ptr<OptRecordRdata::EdeOpt> opt1 =
      OptRecordRdata::EdeOpt::Create(std::string("\x00\x08"
                                                 "Manhattan",
                                                 11));

  ASSERT_EQ(opt1->data(), std::string("\x00\x08"
                                      "Manhattan",
                                      11));
  ASSERT_EQ(opt1->info_code(), 8u);
  ASSERT_EQ(opt1->extra_text(), std::string("Manhattan"));
}

TEST(OptRecordRdataTest, TestEdeInfoCode) {
  std::unique_ptr<OptRecordRdata::EdeOpt> edeOpt0 =
      std::make_unique<OptRecordRdata::EdeOpt>(0, "bullettrain");
  std::unique_ptr<OptRecordRdata::EdeOpt> edeOpt1 =
      std::make_unique<OptRecordRdata::EdeOpt>(27, "ferrari");
  std::unique_ptr<OptRecordRdata::EdeOpt> edeOpt2 =
      std::make_unique<OptRecordRdata::EdeOpt>(28, "sukrit ganesh");
  ASSERT_EQ(edeOpt0->GetEnumFromInfoCode(),
            OptRecordRdata::EdeOpt::EdeInfoCode::kOtherError);
  ASSERT_EQ(
      edeOpt1->GetEnumFromInfoCode(),
      OptRecordRdata::EdeOpt::EdeInfoCode::kUnsupportedNsec3IterationsValue);
  ASSERT_EQ(edeOpt2->GetEnumFromInfoCode(),
            OptRecordRdata::EdeOpt::EdeInfoCode::kUnrecognizedErrorCode);
  ASSERT_EQ(OptRecordRdata::EdeOpt::GetEnumFromInfoCode(15),
            OptRecordRdata::EdeOpt::kBlocked);
}

// Test that an Opt EDE record is parsed correctly
TEST(OptRecordRdataTest, ParseEdeOptRecords) {
  const uint8_t rdata[] = {
      // First OPT (non-EDE record)
      0x00, 0x06,              // OPT code (6)
      0x00, 0x04,              // OPT data size (4)
      0xB0, 0xBA, 0xFE, 0x77,  // OPT data (Boba Fett)

      // Second OPT (EDE record)
      0x00, 0x0F,     // OPT code (15 for EDE)
      0x00, 0x05,     // OPT data size (info code + extra text)
      0x00, 0x0D,     // EDE info code (13 for Cached Error)
      'M', 'T', 'A',  // UTF-8 EDE extra text ("MTA")

      // Third OPT (EDE record)
      0x00, 0x0F,         // OPT code (15 for EDE)
      0x00, 0x06,         // OPT data size (info code + extra text)
      0x00, 0x10,         // EDE info code (16 for Censored)
      'M', 'B', 'T', 'A'  // UTF-8 EDE extra text ("MBTA")
  };

  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));
  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);

  // Test Size of Query
  ASSERT_THAT(rdata_obj, NotNull());
  ASSERT_EQ(rdata_obj->OptCount(), 3u);

  // Test Unknown Opt
  std::unique_ptr<OptRecordRdata::UnknownOpt> opt0 =
      OptRecordRdata::UnknownOpt::CreateForTesting(
          6, std::string("\xb0\xba\xfe\x77", 4));

  ASSERT_THAT(rdata_obj->GetOpts(), SizeIs(3));
  ASSERT_EQ(*rdata_obj->GetOpts()[0], *opt0.get());

  // Test EDE
  OptRecordRdata::EdeOpt edeOpt0(13, std::string("MTA", 3));
  OptRecordRdata::EdeOpt edeOpt1(16, std::string("MBTA", 4));

  ASSERT_THAT(rdata_obj->GetEdeOpts(), SizeIs(2));
  ASSERT_EQ(*rdata_obj->GetEdeOpts()[0], edeOpt0);
  ASSERT_EQ(*rdata_obj->GetEdeOpts()[1], edeOpt1);

  // Check that member variables are alright
  ASSERT_EQ(rdata_obj->GetEdeOpts()[0]->data(), edeOpt0.data());
  ASSERT_EQ(rdata_obj->GetEdeOpts()[1]->data(), edeOpt1.data());

  ASSERT_EQ(rdata_obj->GetEdeOpts()[0]->extra_text(), std::string("MTA", 3));
  ASSERT_EQ(rdata_obj->GetEdeOpts()[1]->extra_text(), std::string("MBTA", 4));

  ASSERT_EQ(rdata_obj->GetEdeOpts()[0]->info_code(), edeOpt0.info_code());
  ASSERT_EQ(rdata_obj->GetEdeOpts()[1]->info_code(), edeOpt1.info_code());
}

// Test the Opt equality operator (and its subclasses as well)
TEST(OptRecordRdataTest, OptEquality) {
  // `rdata_obj0` second opt has extra text "BIOS"
  // `rdata_obj1` second opt has extra text "BIOO"
  // Note: rdata_obj0 and rdata_obj1 have 2 common Opts and 1 different one.
  OptRecordRdata rdata_obj0;
  rdata_obj0.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      6, std::string("\xb0\xba\xfe\x77", 4)));
  rdata_obj0.AddOpt(
      std::make_unique<OptRecordRdata::EdeOpt>(13, std::string("USA", 3)));
  rdata_obj0.AddOpt(
      std::make_unique<OptRecordRdata::EdeOpt>(16, std::string("BIOS", 4)));
  ASSERT_EQ(rdata_obj0.OptCount(), 3u);

  OptRecordRdata rdata_obj1;
  rdata_obj1.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      6, std::string("\xb0\xba\xfe\x77", 4)));
  rdata_obj1.AddOpt(
      std::make_unique<OptRecordRdata::EdeOpt>(13, std::string("USA", 3)));
  rdata_obj1.AddOpt(
      std::make_unique<OptRecordRdata::EdeOpt>(16, std::string("BIOO", 4)));
  ASSERT_EQ(rdata_obj1.OptCount(), 3u);

  auto opts0 = rdata_obj0.GetOpts();
  auto opts1 = rdata_obj1.GetOpts();
  auto edeOpts0 = rdata_obj0.GetEdeOpts();
  auto edeOpts1 = rdata_obj1.GetEdeOpts();
  ASSERT_THAT(opts0, SizeIs(3));
  ASSERT_THAT(opts1, SizeIs(3));
  ASSERT_THAT(edeOpts0, SizeIs(2));
  ASSERT_THAT(edeOpts1, SizeIs(2));

  // Opt equality
  ASSERT_EQ(*opts0[0], *opts1[0]);
  ASSERT_EQ(*opts0[1], *opts1[1]);
  ASSERT_NE(*opts0[0], *opts1[1]);

  // EdeOpt equality
  ASSERT_EQ(*edeOpts0[0], *edeOpts1[0]);
  ASSERT_NE(*edeOpts0[1], *edeOpts1[1]);

  // EdeOpt equality with Opt
  ASSERT_EQ(*edeOpts0[0], *opts1[1]);
  ASSERT_NE(*edeOpts0[1], *opts1[2]);

  // Opt equality with EdeOpt
  // Should work if raw data matches
  ASSERT_EQ(*opts1[1], *edeOpts0[0]);
  ASSERT_NE(*opts1[2], *edeOpts0[1]);
}

// Check that rdata is null if the data section of an EDE record is too small
// (<2 bytes)
TEST(OptRecordRdataTest, EdeRecordTooSmall) {
  const uint8_t rdata[] = {
      0x00, 0x0F,  // OPT code (15 for EDE)
      0x00, 0x01,  // OPT data size (info code + extra text)
      0x00         // Fragment of Info Code
  };

  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));
  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);
  ASSERT_THAT(rdata_obj, IsNull());
}

// Check that an EDE record with no extra text is parsed correctly.
TEST(OptRecordRdataTest, EdeRecordNoExtraText) {
  const uint8_t rdata[] = {
      0x00, 0x0F,  // OPT code (15 for EDE)
      0x00, 0x02,  // OPT data size (info code + extra text)
      0x00, 0x05   // Info Code
  };

  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));
  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);
  ASSERT_THAT(rdata_obj, NotNull());
  ASSERT_THAT(rdata_obj->GetEdeOpts(), SizeIs(1));
  ASSERT_EQ(rdata_obj->GetEdeOpts()[0]->data(), std::string("\x00\x05", 2));
  ASSERT_EQ(rdata_obj->GetEdeOpts()[0]->info_code(), 5u);
  ASSERT_EQ(rdata_obj->GetEdeOpts()[0]->extra_text(), "");
}

// Check that an EDE record with non-UTF-8 fails to parse.
TEST(OptRecordRdataTest, EdeRecordExtraTextNonUTF8) {
  const uint8_t rdata[] = {
      0x00, 0x0F,             // OPT code (15 for EDE)
      0x00, 0x06,             // OPT data size (info code + extra text)
      0x00, 0x05,             // Info Code
      0xB1, 0x05, 0xF0, 0x0D  // Extra Text (non-UTF-8)
  };

  ASSERT_FALSE(base::IsStringUTF8(std::string("\xb1\x05\xf0\x0d", 4)));

  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));
  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);
  ASSERT_THAT(rdata_obj, IsNull());
}

// Check that an EDE record with an unknown info code is parsed correctly.
TEST(OptRecordRdataTest, EdeRecordUnknownInfoCode) {
  const uint8_t rdata[] = {
      0x00, 0x0F,                     // OPT code (15 for EDE)
      0x00, 0x08,                     // OPT data size (info code + extra text)
      0x00, 0x44,                     // Info Code (68 doesn't exist)
      'B',  'O',  'S', 'T', 'O', 'N'  // Extra Text ("BOSTON")
  };

  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));
  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);
  ASSERT_THAT(rdata_obj, NotNull());
  ASSERT_THAT(rdata_obj->GetEdeOpts(), SizeIs(1));
  auto* opt = rdata_obj->GetEdeOpts()[0];
  ASSERT_EQ(opt->data(), std::string("\x00\x44"
                                     "BOSTON",
                                     8));
  ASSERT_EQ(opt->info_code(), 68u);
  ASSERT_EQ(opt->extra_text(), std::string("BOSTON", 6));
  ASSERT_EQ(opt->GetEnumFromInfoCode(),
            OptRecordRdata::EdeOpt::EdeInfoCode::kUnrecognizedErrorCode);
}

TEST(OptRecordRdataTest, CreatePaddingOpt) {
  std::unique_ptr<OptRecordRdata::PaddingOpt> opt0 =
      std::make_unique<OptRecordRdata::PaddingOpt>(12);

  ASSERT_EQ(opt0->data(), std::string(12, '\0'));
  ASSERT_THAT(opt0->data(), SizeIs(12u));

  std::unique_ptr<OptRecordRdata::PaddingOpt> opt1 =
      std::make_unique<OptRecordRdata::PaddingOpt>("MASSACHUSETTS");

  ASSERT_EQ(opt1->data(), std::string("MASSACHUSETTS"));
  ASSERT_THAT(opt1->data(), SizeIs(13u));
}

TEST(OptRecordRdataTest, ParsePaddingOpt) {
  const uint8_t rdata[] = {
      // First OPT
      0x00, 0x0C,  // OPT code
      0x00, 0x07,  // OPT data size
      0xB0, 0x03,  // OPT data padding (Book of Boba Fett)
      0x0F, 0xB0, 0xBA, 0xFE, 0x77,
  };

  std::string_view rdata_strpiece = MakeStringPiece(rdata, sizeof(rdata));
  std::unique_ptr<OptRecordRdata> rdata_obj =
      OptRecordRdata::Create(rdata_strpiece);

  ASSERT_THAT(rdata_obj, NotNull());
  ASSERT_EQ(rdata_obj->OptCount(), 1u);
  ASSERT_THAT(rdata_obj->GetOpts(), SizeIs(1));
  ASSERT_THAT(rdata_obj->GetPaddingOpts(), SizeIs(1));

  // Check elements
  OptRecordRdata::PaddingOpt opt0(
      std::string("\xb0\x03\x0f\xb0\xba\xfe\x77", 7));

  ASSERT_EQ(*(rdata_obj->GetOpts()[0]), opt0);
  ASSERT_EQ(*(rdata_obj->GetPaddingOpts()[0]), opt0);
  ASSERT_THAT(opt0.data(), SizeIs(7u));
}

TEST(OptRecordRdataTest, AddOptToOptRecord) {
  // This is just the rdata portion of an OPT record, rather than a complete
  // record.
  const uint8_t expected_rdata[] = {
      0x00, 0xFF,             // OPT code
      0x00, 0x04,             // OPT data size
      0xDE, 0xAD, 0xBE, 0xEF  // OPT data
  };

  OptRecordRdata rdata;
  rdata.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      255, std::string("\xde\xad\xbe\xef", 4)));
  EXPECT_THAT(rdata.buf(), ElementsAreArray(expected_rdata));
}

// Test the OptRecordRdata equality operator.
// Equality must be order sensitive. If Opts are same but inserted in different
// order, test will fail epically.
TEST(OptRecordRdataTest, EqualityIsOptOrderSensitive) {
  // Control rdata
  OptRecordRdata rdata_obj0;
  rdata_obj0.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      1, std::string("\xb0\xba\xfe\x77", 4)));
  rdata_obj0.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      2, std::string("\xb1\x05\xf0\x0d", 4)));
  ASSERT_EQ(rdata_obj0.OptCount(), 2u);

  // Same as `rdata_obj0`
  OptRecordRdata rdata_obj1;
  rdata_obj1.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      1, std::string("\xb0\xba\xfe\x77", 4)));
  rdata_obj1.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      2, std::string("\xb1\x05\xf0\x0d", 4)));
  ASSERT_EQ(rdata_obj1.OptCount(), 2u);

  ASSERT_EQ(rdata_obj0, rdata_obj1);

  // Same contents as `rdata_obj0` & `rdata_obj1`, but different order
  OptRecordRdata rdata_obj2;
  rdata_obj2.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      2, std::string("\xb1\x05\xf0\x0d", 4)));
  rdata_obj2.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      1, std::string("\xb0\xba\xfe\x77", 4)));
  ASSERT_EQ(rdata_obj2.OptCount(), 2u);

  // Order matters! obj0 and obj2 contain same Opts but in different order.
  ASSERT_FALSE(rdata_obj0.IsEqual(&rdata_obj2));

  // Contains only `rdata_obj0` first opt
  // 2nd opt is added later
  OptRecordRdata rdata_obj3;
  rdata_obj3.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      1, std::string("\xb0\xba\xfe\x77", 4)));
  ASSERT_EQ(rdata_obj3.OptCount(), 1u);

  ASSERT_FALSE(rdata_obj0.IsEqual(&rdata_obj3));

  rdata_obj3.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      2, std::string("\xb1\x05\xf0\x0d", 4)));

  ASSERT_TRUE(rdata_obj0.IsEqual(&rdata_obj3));

  // Test == operator
  ASSERT_TRUE(rdata_obj0 == rdata_obj1);
  ASSERT_EQ(rdata_obj0, rdata_obj1);
  ASSERT_NE(rdata_obj0, rdata_obj2);
}

// Test that GetOpts() follows specified order.
// Sort by key, then by insertion order.
TEST(OptRecordRdataTest, TestGetOptsOrder) {
  OptRecordRdata rdata_obj0;
  rdata_obj0.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      10, std::string("\x33\x33", 2)));
  rdata_obj0.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      5, std::string("\x11\x11", 2)));
  rdata_obj0.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
      5, std::string("\x22\x22", 2)));
  ASSERT_EQ(rdata_obj0.OptCount(), 3u);

  auto opts = rdata_obj0.GetOpts();
  ASSERT_EQ(opts[0]->data(),
            std::string("\x11\x11", 2));  // opt code 5 (inserted first)
  ASSERT_EQ(opts[1]->data(),
            std::string("\x22\x22", 2));  // opt code 5 (inserted second)
  ASSERT_EQ(opts[2]->data(), std::string("\x33\x33", 2));  // opt code 10
}

}  // namespace
}  // namespace net

"""

```