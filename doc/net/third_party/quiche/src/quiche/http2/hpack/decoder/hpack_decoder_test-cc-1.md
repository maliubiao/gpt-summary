Response:
The user wants me to analyze a C++ test file for the Chromium network stack related to HTTP/2 HPACK decoding. I need to:

1. **Summarize the functionality** of the test file.
2. **Identify connections to JavaScript functionality** and provide examples.
3. **Illustrate logical reasoning** with hypothetical inputs and outputs.
4. **Point out common user/programming errors** with examples.
5. **Describe user steps to reach this code** as debugging hints.
6. **Provide a comprehensive summary** of the file's function as this is the second part of the analysis.

Based on the code snippets, the file `hpack_decoder_test.cc` seems to focus on testing the correct decoding of HPACK encoded header blocks. It covers various scenarios like decoding literal headers (with and without indexing), indexed headers, dynamic table updates (both optional and required), error handling for invalid inputs, and handling of truncated blocks or oversized strings.

**JavaScript Connection:** While the core logic is in C++, HPACK decoding is crucial for HTTP/2, which is used in web browsers. JavaScript code interacting with network requests and responses relies on the correct handling of HTTP/2 headers. For instance, if a JavaScript application fetches a resource, the browser's network stack uses the HPACK decoder to interpret the response headers.

**Logical Reasoning:** The tests demonstrate specific HPACK encoding patterns and the expected decoded header lists and dynamic table states.

**User/Programming Errors:**  Common errors could involve incorrect HPACK encoding on the server-side or misconfiguration of table size limits.

**User Steps:** A user triggering an HTTP/2 request in a browser would lead to this code being executed.

Since this is the second part, I should summarize the overall functionality based on both parts.
好的，这是Chromium网络栈中`net/third_party/quiche/src/quiche/http2/hpack/decoder/hpack_decoder_test.cc`文件的第二部分。结合第一部分的分析，我们可以归纳一下这个测试文件的功能：

**整体功能归纳：**

这个`hpack_decoder_test.cc` 文件是一个单元测试文件，专门用于测试 HTTP/2 HPACK 解码器 (`HpackDecoder`) 的功能。它通过模拟各种 HPACK 编码的头部块，并断言解码后的结果是否与预期一致，来验证解码器的正确性和健壮性。

具体而言，这个测试文件涵盖了以下几个方面的功能：

1. **基本的头部解码：** 测试解码各种类型的头部字段，包括静态索引、动态索引、以及字面值表示的头部字段。
2. **动态表操作：** 测试解码器如何处理动态表的更新，包括添加新的头部字段，以及在空间不足时驱逐旧的头部字段。测试了可选的和必需的动态表大小更新。
3. **错误处理：** 测试解码器在遇到各种错误情况时的行为，例如：
    * 无效的索引值。
    * 格式错误的变长整数 (varint)。
    * 截断的 HPACK 块。
    * 过长的字符串值。
    * 不允许的动态表大小更新。
    * 缺少必需的动态表大小更新。
    * 初始动态表大小更新超过低水位线。
4. **分片解码：** 虽然这段代码没有直接展示分片解码，但整体测试框架支持通过 `DecodeBuffer` 来模拟分片输入。
5. **最大字符串长度限制：** 测试解码器如何处理超过预设最大长度的头部字段值。

**与 JavaScript 功能的关系：**

虽然这段代码是用 C++ 编写的，但它直接关系到浏览器中 JavaScript 代码发起的网络请求和接收的响应的处理。当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTP/2 请求时，服务器返回的 HTTP 头部信息会被编码成 HPACK 格式。浏览器底层的网络栈（也就是 Chromium 的网络栈）会使用 `HpackDecoder` 来解码这些头部信息，然后这些解码后的头部信息才能被 JavaScript 代码访问。

**举例说明：**

假设一个 JavaScript 应用发起一个请求，服务器返回的响应头信息包含以下内容，并使用 HPACK 进行了编码：

```
:status: 200
content-type: application/json
x-custom-header: some-value
```

`hpack_decoder_test.cc` 中的测试用例就是为了验证 `HpackDecoder` 能否正确地将这段 HPACK 编码的数据解码成上述的键值对形式，从而让浏览器能够将 `response.status` 设置为 `200`，`response.headers.get('content-type')` 返回 `application/json`，以及 `response.headers.get('x-custom-header')` 返回 `some-value`。

**逻辑推理的假设输入与输出：**

**假设输入 (C.5.3 Third Response 的 HPACK 块):**

```
88                                      | == Indexed - Add ==
                                              |   idx = 8
                                              | -> :status: 200
c1                                      | == Indexed - Add ==
                                              |   idx = 65
                                              | -> cache-control: private
61                                      | == Literal indexed ==
                                              |   Indexed name (idx = 33)
                                              |     date
1d                                      |   Literal value (len = 29)
4d6f 6e2c 2032 3120 4f63 7420 3230 3133 | Mon, 21 Oct 2013
2032 303a 3133 3a32 3220 474d 54        |  20:13:22 GMT
                                              | - evict: cache-control:
                                              |   private
                                              | -> date: Mon, 21 Oct 2013
                                              |   20:13:22 GMT
c0                                      | == Indexed - Add ==
                                              |   idx = 64
                                              | -> location:
                                              |   https://www.example.com
5a                                      | == Literal indexed ==
                                              |   Indexed name (idx = 26)
                                              |     content-encoding
104                                      |   Literal value (len = 4)
677a 6970                               | gzip
                                              | - evict: date: Mon, 21 Oct
                                              |    2013 20:13:21 GMT
                                              | -> content-encoding: gzip
77                                      | == Literal indexed ==
                                              |   Indexed name (idx = 55)
                                              |     set-cookie
38                                      |   Literal value (len = 56)
666f 6f3d 4153 444a 4b48 514b 425a 584f | foo=ASDJKHQKBZXO
5157 454f 5049 5541 5851 5745 4f49 553b | QWEOPIUAXQWEOIU;
206d 6178 2d61 6765 3d33 3630 303b 2076 |  max-age=3600; v
6572 7369 6f6e 3d31                     | ersion=1
                                              | - evict: location:
                                              |   https://www.example.com
                                              | - evict: :status: 307
                                              | -> set-cookie: foo=ASDJKHQ
                                              |   KBZXOQWEOPIUAXQWEOIU; ma
                                              |   x-age=3600; version=1
```

**预期输出 (解码后的头部列表):**

```
{":status", "200"},
{"cache-control", "private"},
{"date", "Mon, 21 Oct 2013 20:13:22 GMT"},
{"location", "https://www.example.com"},
{"content-encoding", "gzip"},
{"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"}
```

**涉及用户或者编程常见的使用错误：**

1. **服务器端 HPACK 编码错误：** 如果服务器在编码 HTTP 头部信息时使用了不符合 HPACK 规范的编码方式，例如使用了无效的索引值或者错误的字面值表示，那么客户端的 `HpackDecoder` 将会解码失败，导致网络请求出错。例如，如果服务器发送了 `\x80` 作为索引头部字段，由于 `0` 不是有效的索引，解码器会报错。
2. **客户端配置的动态表大小不一致：** HTTP/2 允许客户端和服务器协商动态表的最大大小。如果客户端配置的初始动态表大小过小，而服务器尝试添加大量的头部字段到动态表中，可能会导致客户端解码错误或者频繁的动态表更新操作，影响性能。例如，如果客户端设置了非常小的动态表大小，而服务器发送了一个包含大量新的头部字段的响应，客户端可能会因为无法将所有头部字段添加到动态表中而报错，或者需要多次更新动态表大小。
3. **处理分片数据不完整：** 如果 `HpackDecoder` 接收到的 HPACK 数据块是不完整的（例如，在头部字段的中间被截断），解码器会报错。例如，如果一个表示头部字段长度的字节指示长度为 10，但实际只接收到了 5 个字节的头部字段值，解码器会检测到截断错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入一个网址 (例如：https://www.example.com)。**
2. **浏览器解析网址，发现需要建立 HTTPS 连接。**
3. **浏览器与服务器进行 TLS 握手，协商使用 HTTP/2 协议。**
4. **浏览器向服务器发送 HTTP/2 请求，可能包含使用 HPACK 编码的请求头。**
5. **服务器处理请求，并返回 HTTP/2 响应，响应头信息使用 HPACK 进行编码。**
6. **浏览器接收到服务器返回的 HPACK 编码的响应头数据。**
7. **Chromium 网络栈中的 `HpackDecoder` 类被调用，开始解码接收到的 HPACK 数据。**
8. **`hpack_decoder_test.cc` 中测试的各种解码逻辑和错误处理机制会在这一步被实际执行。** 例如，如果服务器返回的 `:status` 字段被编码为 `48 03 33 30 32`，`HpackDecoder` 会将其解码为 `":status", "302"`。如果编码有误，比如索引值超出范围，解码器会检测到错误并记录。
9. **解码后的头部信息被传递给浏览器的其他组件，例如网络请求的处理模块或者 JavaScript 引擎。**

在调试网络问题时，如果发现 HTTP 头部信息解析错误，就可以考虑检查 `HpackDecoder` 的行为，并参考 `hpack_decoder_test.cc` 中的测试用例来理解解码器的预期行为和可能的错误原因。

希望这个更全面的归纳能够帮助你理解 `hpack_decoder_test.cc` 的功能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/decoder/hpack_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
.1 First Response
  //
  // Header list to encode:
  //
  //   :status: 302
  //   cache-control: private
  //   date: Mon, 21 Oct 2013 20:13:21 GMT
  //   location: https://www.example.com
  std::string hpack_block = HpackExampleToStringOrDie(R"(
      48                                      | == Literal indexed ==
                                              |   Indexed name (idx = 8)
                                              |     :status
      03                                      |   Literal value (len = 3)
      3330 32                                 | 302
                                              | -> :status: 302
      58                                      | == Literal indexed ==
                                              |   Indexed name (idx = 24)
                                              |     cache-control
      07                                      |   Literal value (len = 7)
      7072 6976 6174 65                       | private
                                              | -> cache-control: private
      61                                      | == Literal indexed ==
                                              |   Indexed name (idx = 33)
                                              |     date
      1d                                      |   Literal value (len = 29)
      4d6f 6e2c 2032 3120 4f63 7420 3230 3133 | Mon, 21 Oct 2013
      2032 303a 3133 3a32 3120 474d 54        |  20:13:21 GMT
                                              | -> date: Mon, 21 Oct 2013
                                              |   20:13:21 GMT
      6e                                      | == Literal indexed ==
                                              |   Indexed name (idx = 46)
                                              |     location
      17                                      |   Literal value (len = 23)
      6874 7470 733a 2f2f 7777 772e 6578 616d | https://www.exam
      706c 652e 636f 6d                       | ple.com
                                              | -> location:
                                              |   https://www.example.com
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":status", "302"},
                  HpackHeaderEntry{"cache-control", "private"},
                  HpackHeaderEntry{"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                  HpackHeaderEntry{"location", "https://www.example.com"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  63) location: https://www.example.com
  //   [  2] (s =  65) date: Mon, 21 Oct 2013 20:13:21 GMT
  //   [  3] (s =  52) cache-control: private
  //   [  4] (s =  42) :status: 302
  //         Table size: 222
  ASSERT_TRUE(
      VerifyDynamicTableContents({{"location", "https://www.example.com"},
                                  {"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                                  {"cache-control", "private"},
                                  {":status", "302"}}));
  ASSERT_EQ(222u, current_header_table_size());

  // C.5.2 Second Response
  //
  // The (":status", "302") header field is evicted from the dynamic table to
  // free space to allow adding the (":status", "307") header field.
  //
  // Header list to encode:
  //
  //   :status: 307
  //   cache-control: private
  //   date: Mon, 21 Oct 2013 20:13:21 GMT
  //   location: https://www.example.com
  hpack_block = HpackExampleToStringOrDie(R"(
      48                                      | == Literal indexed ==
                                              |   Indexed name (idx = 8)
                                              |     :status
      03                                      |   Literal value (len = 3)
      3330 37                                 | 307
                                              | - evict: :status: 302
                                              | -> :status: 307
      c1                                      | == Indexed - Add ==
                                              |   idx = 65
                                              | -> cache-control: private
      c0                                      | == Indexed - Add ==
                                              |   idx = 64
                                              | -> date: Mon, 21 Oct 2013
                                              |   20:13:21 GMT
      bf                                      | == Indexed - Add ==
                                              |   idx = 63
                                              | -> location:
                                              |   https://www.example.com
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":status", "307"},
                  HpackHeaderEntry{"cache-control", "private"},
                  HpackHeaderEntry{"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                  HpackHeaderEntry{"location", "https://www.example.com"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  42) :status: 307
  //   [  2] (s =  63) location: https://www.example.com
  //   [  3] (s =  65) date: Mon, 21 Oct 2013 20:13:21 GMT
  //   [  4] (s =  52) cache-control: private
  //         Table size: 222
  ASSERT_TRUE(
      VerifyDynamicTableContents({{":status", "307"},
                                  {"location", "https://www.example.com"},
                                  {"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                                  {"cache-control", "private"}}));
  ASSERT_EQ(222u, current_header_table_size());

  // C.5.3 Third Response
  //
  // Several header fields are evicted from the dynamic table during the
  // processing of this header list.
  //
  // Header list to encode:
  //
  //   :status: 200
  //   cache-control: private
  //   date: Mon, 21 Oct 2013 20:13:22 GMT
  //   location: https://www.example.com
  //   content-encoding: gzip
  //   set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1
  hpack_block = HpackExampleToStringOrDie(R"(
      88                                      | == Indexed - Add ==
                                              |   idx = 8
                                              | -> :status: 200
      c1                                      | == Indexed - Add ==
                                              |   idx = 65
                                              | -> cache-control: private
      61                                      | == Literal indexed ==
                                              |   Indexed name (idx = 33)
                                              |     date
      1d                                      |   Literal value (len = 29)
      4d6f 6e2c 2032 3120 4f63 7420 3230 3133 | Mon, 21 Oct 2013
      2032 303a 3133 3a32 3220 474d 54        |  20:13:22 GMT
                                              | - evict: cache-control:
                                              |   private
                                              | -> date: Mon, 21 Oct 2013
                                              |   20:13:22 GMT
      c0                                      | == Indexed - Add ==
                                              |   idx = 64
                                              | -> location:
                                              |   https://www.example.com
      5a                                      | == Literal indexed ==
                                              |   Indexed name (idx = 26)
                                              |     content-encoding
      04                                      |   Literal value (len = 4)
      677a 6970                               | gzip
                                              | - evict: date: Mon, 21 Oct
                                              |    2013 20:13:21 GMT
                                              | -> content-encoding: gzip
      77                                      | == Literal indexed ==
                                              |   Indexed name (idx = 55)
                                              |     set-cookie
      38                                      |   Literal value (len = 56)
      666f 6f3d 4153 444a 4b48 514b 425a 584f | foo=ASDJKHQKBZXO
      5157 454f 5049 5541 5851 5745 4f49 553b | QWEOPIUAXQWEOIU;
      206d 6178 2d61 6765 3d33 3630 303b 2076 |  max-age=3600; v
      6572 7369 6f6e 3d31                     | ersion=1
                                              | - evict: location:
                                              |   https://www.example.com
                                              | - evict: :status: 307
                                              | -> set-cookie: foo=ASDJKHQ
                                              |   KBZXOQWEOPIUAXQWEOIU; ma
                                              |   x-age=3600; version=1
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(
      header_entries_,
      ElementsAreArray({
          HpackHeaderEntry{":status", "200"},
          HpackHeaderEntry{"cache-control", "private"},
          HpackHeaderEntry{"date", "Mon, 21 Oct 2013 20:13:22 GMT"},
          HpackHeaderEntry{"location", "https://www.example.com"},
          HpackHeaderEntry{"content-encoding", "gzip"},
          HpackHeaderEntry{
              "set-cookie",
              "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
      }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  98) set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU;
  //                    max-age=3600; version=1
  //   [  2] (s =  52) content-encoding: gzip
  //   [  3] (s =  65) date: Mon, 21 Oct 2013 20:13:22 GMT
  //         Table size: 215
  ASSERT_TRUE(VerifyDynamicTableContents(
      {{"set-cookie",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
       {"content-encoding", "gzip"},
       {"date", "Mon, 21 Oct 2013 20:13:22 GMT"}}));
  ASSERT_EQ(215u, current_header_table_size());
}

// Confirm that the table size can be changed, but at most twice.
TEST_P(HpackDecoderTest, ProcessesOptionalTableSizeUpdates) {
  EXPECT_EQ(Http2SettingsInfo::DefaultHeaderTableSize(),
            header_table_size_limit());
  // One update allowed.
  {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(3000);
    EXPECT_TRUE(DecodeBlock(hbb.buffer()));
    EXPECT_EQ(3000u, header_table_size_limit());
    EXPECT_EQ(0u, current_header_table_size());
    EXPECT_TRUE(header_entries_.empty());
  }
  // Two updates allowed.
  {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(2000);
    hbb.AppendDynamicTableSizeUpdate(2500);
    EXPECT_TRUE(DecodeBlock(hbb.buffer()));
    EXPECT_EQ(2500u, header_table_size_limit());
    EXPECT_EQ(0u, current_header_table_size());
    EXPECT_TRUE(header_entries_.empty());
  }
  // A third update in the same HPACK block is rejected, so the final
  // size is 1000, not 500.
  {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(1500);
    hbb.AppendDynamicTableSizeUpdate(1000);
    hbb.AppendDynamicTableSizeUpdate(500);
    EXPECT_FALSE(DecodeBlock(hbb.buffer()));
    EXPECT_EQ(HpackDecodingError::kDynamicTableSizeUpdateNotAllowed,
              decoder_.error());
    EXPECT_EQ(1u, error_messages_.size());
    EXPECT_THAT(error_messages_[0],
                Eq("Dynamic table size update not allowed"));
    EXPECT_EQ(1000u, header_table_size_limit());
    EXPECT_EQ(0u, current_header_table_size());
    EXPECT_TRUE(header_entries_.empty());
  }
  // An error has been detected, so calls to HpackDecoder::DecodeFragment
  // should return immediately.
  DecodeBuffer db("\x80");
  EXPECT_FALSE(decoder_.DecodeFragment(&db));
  EXPECT_EQ(0u, db.Offset());
  EXPECT_EQ(1u, error_messages_.size());
}

// Confirm that the table size can be changed when required, but at most twice.
TEST_P(HpackDecoderTest, ProcessesRequiredTableSizeUpdate) {
  EXPECT_EQ(4096u, decoder_.GetCurrentHeaderTableSizeSetting());
  // One update required, two allowed, one provided, followed by a header.
  decoder_.ApplyHeaderTableSizeSetting(1024);
  decoder_.ApplyHeaderTableSizeSetting(2048);
  EXPECT_EQ(Http2SettingsInfo::DefaultHeaderTableSize(),
            header_table_size_limit());
  EXPECT_EQ(2048u, decoder_.GetCurrentHeaderTableSizeSetting());
  {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(1024);
    hbb.AppendIndexedHeader(4);  // :path: /
    EXPECT_TRUE(DecodeBlock(hbb.buffer()));
    EXPECT_THAT(header_entries_,
                ElementsAreArray({HpackHeaderEntry{":path", "/"}}));
    EXPECT_EQ(1024u, header_table_size_limit());
    EXPECT_EQ(0u, current_header_table_size());
  }
  // One update required, two allowed, two provided, followed by a header.
  decoder_.ApplyHeaderTableSizeSetting(1000);
  decoder_.ApplyHeaderTableSizeSetting(1500);
  EXPECT_EQ(1500u, decoder_.GetCurrentHeaderTableSizeSetting());
  {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(500);
    hbb.AppendDynamicTableSizeUpdate(1250);
    hbb.AppendIndexedHeader(5);  // :path: /index.html
    EXPECT_TRUE(DecodeBlock(hbb.buffer()));
    EXPECT_THAT(header_entries_,
                ElementsAreArray({HpackHeaderEntry{":path", "/index.html"}}));
    EXPECT_EQ(1250u, header_table_size_limit());
    EXPECT_EQ(0u, current_header_table_size());
  }
  // One update required, two allowed, three provided, followed by a header.
  // The third update is rejected, so the final size is 1000, not 500.
  decoder_.ApplyHeaderTableSizeSetting(500);
  decoder_.ApplyHeaderTableSizeSetting(1000);
  EXPECT_EQ(1000u, decoder_.GetCurrentHeaderTableSizeSetting());
  {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(200);
    hbb.AppendDynamicTableSizeUpdate(700);
    hbb.AppendDynamicTableSizeUpdate(900);
    hbb.AppendIndexedHeader(5);  // Not decoded.
    EXPECT_FALSE(DecodeBlock(hbb.buffer()));
    EXPECT_FALSE(saw_end_);
    EXPECT_EQ(HpackDecodingError::kDynamicTableSizeUpdateNotAllowed,
              decoder_.error());
    EXPECT_EQ(1u, error_messages_.size());
    EXPECT_THAT(error_messages_[0],
                Eq("Dynamic table size update not allowed"));
    EXPECT_EQ(700u, header_table_size_limit());
    EXPECT_EQ(0u, current_header_table_size());
    EXPECT_TRUE(header_entries_.empty());
  }
  EXPECT_EQ(1000u, decoder_.GetCurrentHeaderTableSizeSetting());
  // Now that an error has been detected, StartDecodingBlock should return
  // false.
  EXPECT_FALSE(decoder_.StartDecodingBlock());
}

// Confirm that required size updates are validated.
TEST_P(HpackDecoderTest, InvalidRequiredSizeUpdate) {
  // Require a size update, but provide one that isn't small enough (must be
  // zero or one, in this case).
  decoder_.ApplyHeaderTableSizeSetting(1);
  decoder_.ApplyHeaderTableSizeSetting(1024);
  HpackBlockBuilder hbb;
  hbb.AppendDynamicTableSizeUpdate(2);
  EXPECT_TRUE(decoder_.StartDecodingBlock());
  DecodeBuffer db(hbb.buffer());
  EXPECT_FALSE(decoder_.DecodeFragment(&db));
  EXPECT_FALSE(saw_end_);
  EXPECT_EQ(
      HpackDecodingError::kInitialDynamicTableSizeUpdateIsAboveLowWaterMark,
      decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0],
              Eq("Initial dynamic table size update is above low water mark"));
  EXPECT_EQ(Http2SettingsInfo::DefaultHeaderTableSize(),
            header_table_size_limit());
}

// Confirm that required size updates are indeed required before the end.
TEST_P(HpackDecoderTest, RequiredTableSizeChangeBeforeEnd) {
  decoder_.ApplyHeaderTableSizeSetting(1024);
  EXPECT_FALSE(DecodeBlock(""));
  EXPECT_EQ(HpackDecodingError::kMissingDynamicTableSizeUpdate,
            decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0], Eq("Missing dynamic table size update"));
  EXPECT_FALSE(saw_end_);
}

// Confirm that required size updates are indeed required before an
// indexed header.
TEST_P(HpackDecoderTest, RequiredTableSizeChangeBeforeIndexedHeader) {
  decoder_.ApplyHeaderTableSizeSetting(1024);
  HpackBlockBuilder hbb;
  hbb.AppendIndexedHeader(1);
  EXPECT_FALSE(DecodeBlock(hbb.buffer()));
  EXPECT_EQ(HpackDecodingError::kMissingDynamicTableSizeUpdate,
            decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0], Eq("Missing dynamic table size update"));
  EXPECT_FALSE(saw_end_);
  EXPECT_TRUE(header_entries_.empty());
}

// Confirm that required size updates are indeed required before an indexed
// header name.
// TODO(jamessynge): Move some of these to hpack_decoder_state_test.cc.
TEST_P(HpackDecoderTest, RequiredTableSizeChangeBeforeIndexedHeaderName) {
  decoder_.ApplyHeaderTableSizeSetting(1024);
  HpackBlockBuilder hbb;
  hbb.AppendNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader, 2,
                                     false, "PUT");
  EXPECT_FALSE(DecodeBlock(hbb.buffer()));
  EXPECT_EQ(HpackDecodingError::kMissingDynamicTableSizeUpdate,
            decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0], Eq("Missing dynamic table size update"));
  EXPECT_FALSE(saw_end_);
  EXPECT_TRUE(header_entries_.empty());
}

// Confirm that required size updates are indeed required before a literal
// header name.
TEST_P(HpackDecoderTest, RequiredTableSizeChangeBeforeLiteralName) {
  decoder_.ApplyHeaderTableSizeSetting(1024);
  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, "name", false, "some data.");
  EXPECT_FALSE(DecodeBlock(hbb.buffer()));
  EXPECT_EQ(HpackDecodingError::kMissingDynamicTableSizeUpdate,
            decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0], Eq("Missing dynamic table size update"));
  EXPECT_FALSE(saw_end_);
  EXPECT_TRUE(header_entries_.empty());
}

// Confirm that an excessively long varint is detected, in this case an
// index of 127, but with lots of additional high-order 0 bits provided,
// too many to be allowed.
TEST_P(HpackDecoderTest, InvalidIndexedHeaderVarint) {
  EXPECT_TRUE(decoder_.StartDecodingBlock());
  DecodeBuffer db("\xff\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00");
  EXPECT_FALSE(decoder_.DecodeFragment(&db));
  EXPECT_TRUE(decoder_.DetectError());
  EXPECT_FALSE(saw_end_);
  EXPECT_EQ(HpackDecodingError::kIndexVarintError, decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0],
              Eq("Index varint beyond implementation limit"));
  EXPECT_TRUE(header_entries_.empty());
  // Now that an error has been detected, EndDecodingBlock should not succeed.
  EXPECT_FALSE(decoder_.EndDecodingBlock());
}

// Confirm that an invalid index into the tables is detected, in this case an
// index of 0.
TEST_P(HpackDecoderTest, InvalidIndex) {
  EXPECT_TRUE(decoder_.StartDecodingBlock());
  DecodeBuffer db("\x80");
  EXPECT_FALSE(decoder_.DecodeFragment(&db));
  EXPECT_TRUE(decoder_.DetectError());
  EXPECT_FALSE(saw_end_);
  EXPECT_EQ(HpackDecodingError::kInvalidIndex, decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0],
              Eq("Invalid index in indexed header field representation"));
  EXPECT_TRUE(header_entries_.empty());
  // Now that an error has been detected, EndDecodingBlock should not succeed.
  EXPECT_FALSE(decoder_.EndDecodingBlock());
}

// Confirm that EndDecodingBlock detects a truncated HPACK block.
TEST_P(HpackDecoderTest, TruncatedBlock) {
  HpackBlockBuilder hbb;
  hbb.AppendDynamicTableSizeUpdate(3000);
  EXPECT_EQ(3u, hbb.size());
  hbb.AppendDynamicTableSizeUpdate(4000);
  EXPECT_EQ(6u, hbb.size());
  // Decodes this block if the whole thing is provided.
  EXPECT_TRUE(DecodeBlock(hbb.buffer()));
  EXPECT_EQ(4000u, header_table_size_limit());
  // Multiple times even.
  EXPECT_TRUE(DecodeBlock(hbb.buffer()));
  EXPECT_EQ(4000u, header_table_size_limit());
  // But not if the block is truncated.
  EXPECT_FALSE(DecodeBlock(hbb.buffer().substr(0, hbb.size() - 1)));
  EXPECT_FALSE(saw_end_);
  EXPECT_EQ(HpackDecodingError::kTruncatedBlock, decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0],
              Eq("Block ends in the middle of an instruction"));
  // The first update was decoded.
  EXPECT_EQ(3000u, header_table_size_limit());
  EXPECT_EQ(0u, current_header_table_size());
  EXPECT_TRUE(header_entries_.empty());
}

// Confirm that an oversized string is detected, ending decoding.
TEST_P(HpackDecoderTest, OversizeStringDetected) {
  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, "name", false, "some data.");
  hbb.AppendLiteralNameAndValue(HpackEntryType::kUnindexedLiteralHeader, false,
                                "name2", false, "longer data");

  // Normally able to decode this block.
  EXPECT_TRUE(DecodeBlock(hbb.buffer()));
  EXPECT_THAT(header_entries_,
              ElementsAreArray({HpackHeaderEntry{"name", "some data."},
                                HpackHeaderEntry{"name2", "longer data"}}));

  // But not if the maximum size of strings is less than the longest string.
  decoder_.set_max_string_size_bytes(10);
  EXPECT_FALSE(DecodeBlock(hbb.buffer()));
  EXPECT_THAT(header_entries_,
              ElementsAreArray({HpackHeaderEntry{"name", "some data."}}));
  EXPECT_FALSE(saw_end_);
  EXPECT_EQ(HpackDecodingError::kValueTooLong, decoder_.error());
  EXPECT_EQ(1u, error_messages_.size());
  EXPECT_THAT(error_messages_[0], Eq("Value length exceeds buffer limit"));
}

}  // namespace
}  // namespace test
}  // namespace http2

"""


```