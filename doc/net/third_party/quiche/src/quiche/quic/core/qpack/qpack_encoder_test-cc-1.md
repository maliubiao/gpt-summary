Response:
The user wants to understand the functionality of the provided C++ code snippet from `qpack_encoder_test.cc`. Specifically, they're interested in:

1. **Overall Functionality:** What does this code do?
2. **JavaScript Relation:** Does it have any connection to JavaScript?
3. **Logic and I/O:** Can we infer input and output based on the code?
4. **Common Errors:** What mistakes could a user or programmer make when interacting with this code or related concepts?
5. **User Path:** How does a user's action eventually lead to this code being executed (debugging context)?
6. **Summary:** A concise summary of the code's purpose.

Let's break down the code snippet and address each point:

**Code Analysis:**

The code consists of several test cases within a `QpackEncoderTest` class. Each test focuses on a specific aspect of the QPACK encoder's behavior. Key elements observed are:

* **`QpackEncoder`:** This is the core class being tested. It's responsible for encoding HTTP headers using the QPACK compression scheme.
* **`encoder_stream_sender_delegate_`:** This mock object simulates sending data on the QPACK encoder stream. It's used to verify that the encoder is generating the correct instructions.
* **`decoder_stream_error_delegate_`:** This mock object likely handles errors encountered on the decoder stream (though it's not directly interacted with in this snippet).
* **`HttpHeaderBlock`:** This represents a collection of HTTP headers (name-value pairs).
* **`Encode()` or `encoder_.EncodeHeaderList()`:** These methods perform the actual header encoding.
* **`SetMaximumDynamicTableCapacity()`, `SetDynamicTableCapacity()`:** These methods control the size of the dynamic table used for QPACK compression.
* **`OnStreamCancellation()`:** This method simulates a stream being cancelled, which impacts the dynamic table.
* **Huffman Encoding:** The tests consider whether Huffman encoding is enabled, impacting the encoded representation of literals.
* **Dynamic Table:** The tests explore how the dynamic table (a cache of recently used headers) is used and managed.
* **Static Table:** The tests also refer to the static table (a predefined set of common headers).
* **Cookie Crumbling:** Some tests specifically address how the encoder handles "Cookie" headers.
* **Assertions (`ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_CALL`):** These are used for verifying the correctness of the encoder's behavior.
* **Hexadecimal String Conversions (`absl::HexStringToBytes`):**  This indicates that the tests are comparing the output against expected byte sequences.

**Addressing the User's Questions:**

1. **Functionality:** This code tests the functionality of the `QpackEncoder`. It verifies that the encoder correctly encodes HTTP headers under various conditions, including:
    * Inserting new entries into the dynamic table.
    * Referencing existing entries in the dynamic and static tables.
    * Handling stream cancellations and their impact on the dynamic table.
    * Managing the dynamic table capacity.
    * Encoding with and without Huffman compression.
    * Handling "Cookie" headers with different "cookie crumbling" settings.
    * Preventing the use of unacknowledged dynamic table entries.
    * Falling back to static table or literal encoding when dynamic table entries cannot be used.

2. **JavaScript Relation:**  While this C++ code is part of the Chromium network stack, which is used by the Chrome browser (which executes JavaScript), there's **no direct interaction or dependency on JavaScript within this specific code snippet**. QPACK is a transport-level compression mechanism, and its encoding logic is handled in C++. JavaScript would interact with HTTP headers at a higher level (e.g., setting or reading headers), but it wouldn't be directly involved in the QPACK encoding process.

3. **Logic and I/O:**

   * **Hypothetical Input:**  `HttpHeaderBlock header_list; header_list["foo"] = "bar"; header_list["bar"] = "baz";`
   * **Hypothetical Output (based on the first test case):**  The expected output would be a sequence of bytes representing the QPACK-encoded headers. This involves:
      * Potential "Set Dynamic Table Capacity" instruction.
      * "Insert" instructions to add "foo: bar" and "bar: baz" to the dynamic table.
      * An encoded representation of the header list referencing the newly added dynamic table entries. The exact byte sequence depends on Huffman encoding being enabled or disabled. The provided test case gives examples of these byte sequences as hexadecimal strings.

4. **Common Errors:**

   * **Incorrectly managing dynamic table capacity:** A programmer might set the maximum dynamic table capacity too low, leading to frequent evictions and less efficient compression. This could manifest as performance issues.
   * **Assuming dynamic table entries are always available:**  A programmer might write code that relies on a header being present in the dynamic table without checking if it's actually there (it could have been evicted). This could lead to unexpected fallback to literal encoding.
   * **Misunderstanding the impact of stream cancellation:**  Failing to account for how stream cancellations affect the availability of dynamic table entries could lead to incorrect assumptions about encoding efficiency.
   * **Incorrectly implementing the encoder/decoder:** A common error in implementing QPACK encoders/decoders is incorrectly handling the various encoding formats (literal, indexed, with/without name reference) or the variable-length integer encoding.

5. **User Path (Debugging Context):**

   A user action that could lead to this code being executed involves browsing the web:

   1. **User types a URL or clicks a link.**
   2. **The browser initiates an HTTP/3 connection** (as QPACK is used with HTTP/3).
   3. **The browser needs to send HTTP headers** for the request.
   4. **The `QpackEncoder` class is instantiated and used** to compress these headers before sending them over the network.
   5. **During development or debugging, a developer might run these unit tests** (like the ones in `qpack_encoder_test.cc`) to ensure the `QpackEncoder` is working correctly. If a bug is suspected in header compression, these tests can help isolate the issue.

6. **Summary of Functionality:** This code snippet contains unit tests for the `QpackEncoder` class in Chromium's network stack. These tests verify the encoder's ability to correctly compress HTTP headers using the QPACK protocol, focusing on dynamic table management, static table referencing, Huffman encoding, handling of "Cookie" headers, and the impact of stream cancellations.

**归纳一下它的功能 (Summary of Functionality - Part 2):**

This second part of the code continues to test various aspects of the `QpackEncoder`. It specifically focuses on scenarios where:

* **An unacknowledged dynamic table entry cannot be evicted:** This verifies the correct implementation of a key QPACK requirement related to ensuring reliable decoding.
* **Only the static table name matches:**  This tests the fallback behavior when a dynamic entry isn't usable, but a static entry with the same name exists.
* **Only the dynamic table name matches:** This tests the preference for using a usable dynamic table entry over creating a new one or using a literal.
* **Cookie crumbling is enabled/disabled:**  This verifies how the encoder handles "Cookie" headers, either splitting them into multiple name-value pairs or encoding them as a single entry. This is a specific optimization for "Cookie" headers.

In essence, this part of the tests delves deeper into specific edge cases and optimization strategies employed by the QPACK encoder to achieve efficient header compression. It ensures that the encoder behaves correctly in situations where simple dynamic table lookups aren't possible or where specific optimizations (like cookie crumbling) are applied.

这是文件 `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder_test.cc` 的第二部分，延续了对 Chromium 网络栈中 QPACK 编码器的功能测试。

**归纳一下它的功能:**

这部分代码主要测试了 `QpackEncoder` 在更复杂场景下的行为，特别是关注以下几个方面：

1. **未确认的动态表条目不能被移除 (UnackedEntryCannotBeEvicted):**
   - 验证了当一个动态表条目被添加到表中并被一个流引用，但该流随后被取消时，即使该条目没有其他引用，它也不能被立即移除，直到该条目被接收端确认。这是为了保证编码器和解码器状态的一致性。
   - **功能:** 确保了 QPACK 协议中关于未确认条目保留的规则得到正确执行。

2. **只匹配静态表名称的情况 (UseStaticTableNameOnlyMatch):**
   - 测试了当要编码的头部字段的值与动态表中的条目不匹配，但名称与静态表中的条目匹配时，编码器会使用静态表中的名称引用，并将值作为字面量进行编码。
   - **功能:** 验证了在无法完全匹配动态表条目时，利用静态表进行部分匹配的能力，以减少编码大小。

3. **只匹配动态表名称的情况 (UseDynamicTableNameOnlyMatch):**
   - 测试了当要编码的头部字段的值与动态表中的某个条目不匹配，但名称与动态表中的另一个条目匹配时，编码器会插入一个新的动态表条目，并使用已存在的动态表名称引用。
   - **功能:** 验证了在可以重用动态表名称时，通过插入新条目来优化编码的能力。

4. **Cookie 拆分功能开启和关闭的情况 (CookieCrumblingEnabledNoDynamicTable, CookieCrumblingEnabledDynamicTable, CookieCrumblingDisabledNoDynamicTable, CookieCrumblingDisabledDynamicTable):**
   - 测试了 QPACK 编码器对于 "cookie" 头部字段的特殊处理，即 "cookie crumbling" 功能。
   - **Cookie Crumbling 开启时:**  会将一个包含多个 `key=value` 对的 `cookie` 头部拆分成多个独立的头部字段进行编码，每个字段对应一个 `key=value` 对。这可以提高压缩效率，因为每个独立的 `key=value` 对更有可能被单独引用。
   - **Cookie Crumbling 关闭时:**  会将整个 `cookie` 头部作为一个整体进行编码。
   - 这些测试用例覆盖了在动态表可用和不可用时，Cookie Crumbling 功能开启和关闭的各种组合情况。
   - **功能:** 验证了 QPACK 编码器针对 "cookie" 头部字段的优化策略是否正确实现。

**与 JavaScript 功能的关系 (延续上一部分):**

与上一部分类似，这部分代码也主要关注底层的 QPACK 编码逻辑，与 JavaScript **没有直接的交互**。JavaScript 在浏览器中处理 HTTP 头部时，会使用由 C++ 实现的 QPACK 编码器进行头部压缩，但 JavaScript 代码本身并不直接参与 QPACK 的编码过程。

**逻辑推理、假设输入与输出 (延续上一部分):**

这部分代码的逻辑推理仍然是通过单元测试来验证的。每个测试用例都设置了特定的编码器状态、输入头部列表，并断言了预期的输出编码结果和发送到编码器流的数据。

**假设输入与输出示例 (基于 "未确认的动态表条目不能被移除" 测试):**

* **假设输入:**
    * 编码器动态表容量设置为 40 字节。
    * 第一个头部列表 `header_list1` 包含 `{"foo", "bar"}`。
    * 第二个头部列表 `header_list2` 包含 `{"bar", "baz"}`。
    * 流 ID 为 1 的流在编码完 `header_list1` 后被取消。
* **预期输出:**
    * 编码 `header_list1` 时，会将 "foo: bar" 插入动态表，并输出对该动态表条目的引用。
    * 流 1 取消后，动态表中的 "foo: bar" 条目因为未被确认，所以不会被立即移除。
    * 编码 `header_list2` 时，由于动态表空间有限，无法插入新的 "bar: baz"，因此 "bar: baz" 会被编码为字面量。

**用户或编程常见的使用错误 (延续上一部分):**

* **错误地假设动态表条目总是存在:** 开发者可能会认为之前编码过的头部会一直存在于动态表中，但由于动态表容量限制或条目被移除，这种假设可能不成立。这会导致编码效率下降。
* **不理解流取消的影响:**  未能理解流取消后动态表条目的状态变化，可能会导致对编码结果的误判。

**用户操作如何一步步的到达这里，作为调试线索 (延续上一部分):**

用户浏览网页，发起 HTTP/3 请求，浏览器需要对 HTTP 头部进行 QPACK 编码。如果开发者怀疑 QPACK 编码器存在问题，可能会运行这些单元测试来定位 bug。例如，如果开发者观察到某些头部没有被动态表压缩，他们可能会检查相关的测试用例，比如 "只匹配静态表名称的情况" 或 "只匹配动态表名称的情况"，来理解编码器的行为是否符合预期。

**总结这部分的功能:**

这部分 `qpack_encoder_test.cc` 文件通过一系列细致的单元测试，深入验证了 `QpackEncoder` 在更复杂和特定的场景下的行为，包括对未确认动态表条目的处理、在部分匹配情况下对静态表和动态表的使用策略，以及 "cookie crumbling" 功能的正确性。 这些测试确保了 QPACK 编码器在各种情况下都能高效且正确地压缩 HTTP 头部。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ble.
  std::string insert_entries_hex;
  if (HuffmanEnabled()) {
    insert_entries_hex =
        "62"     // insert without name reference
        "94e7";  // Huffman-encoded literal name "foo"
  } else {
    insert_entries_hex =
        "43"       // insert without name reference
        "666f6f";  // literal name "foo"
  }
  insert_entries_hex +=
      "03626172"   // value "bar"
      "80"         // insert with name reference, dynamic index 0
      "0362617a"   // value "baz"
      "c5"         // insert with name reference, static index 5
      "0362617a";  // value "baz"
  std::string insert_entries;
  ASSERT_TRUE(absl::HexStringToBytes(insert_entries_hex, &insert_entries));
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entries))));

  std::string expected_output;
  ASSERT_TRUE(absl::HexStringToBytes(
      "0400"     // prefix
      "828180",  // dynamic entries with relative index 0, 1, and 2
      &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list1));

  EXPECT_EQ(insert_entries.size(), encoder_stream_sent_byte_count_);

  // If number of bytes buffered by encoder stream goes over the threshold,
  // then QpackEncoder will stop emitting encoder stream instructions.
  ::testing::Mock::VerifyAndClearExpectations(&encoder_stream_sender_delegate_);
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(kTooManyBytesBuffered));

  quiche::HttpHeaderBlock header_list2;
  header_list2["foo"] = "bar";  // matches previously inserted dynamic entry
  header_list2["bar"] = "baz";
  header_list2["cookie"] = "baz";  // name matches static entry

  // Encoder is not allowed to write on the encoder stream.
  // No Set Dynamic Table Capacity or Insert instructions are sent.
  // Headers are encoded as string literals.
  ASSERT_TRUE(
      absl::HexStringToBytes("0400"      // prefix
                             "82"        // dynamic entry with relative index 0
                             "23626172"  // literal name "bar"
                             "0362617a"  // with literal value "baz"
                             "80",       // dynamic entry with relative index 2
                             &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list2));

  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);
}

// Regression test for https://crbug.com/1441880.
TEST_P(QpackEncoderTest, UnackedEntryCannotBeEvicted) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder_.SetMaximumBlockedStreams(2);
  // With 32 byte overhead per entry, only one entry fits in the dynamic table.
  encoder_.SetMaximumDynamicTableCapacity(40);
  encoder_.SetDynamicTableCapacity(40);

  QpackEncoderHeaderTable* header_table =
      QpackEncoderPeer::header_table(&encoder_);
  EXPECT_EQ(0u, header_table->inserted_entry_count());
  EXPECT_EQ(0u, header_table->dropped_entry_count());

  quiche::HttpHeaderBlock header_list1;
  header_list1["foo"] = "bar";

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3f09", &set_dyanamic_table_capacity));
  // Insert one entry into the dynamic table.
  std::string insert_entries1;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("62"    // insert without name reference
                               "94e7"  // Huffman-encoded literal name "foo"
                               "03626172",  // value "bar"
                               &insert_entries1));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("43"         // insert without name reference
                               "666f6f"     // literal name "foo"
                               "03626172",  // value "bar"
                               &insert_entries1));
  }
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entries1))));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0200"  // prefix
                             "80",   // dynamic entry with relative index 0
                             &expected_output));
  EXPECT_EQ(expected_output,
            encoder_.EncodeHeaderList(/* stream_id = */ 1, header_list1,
                                      &encoder_stream_sent_byte_count_));

  EXPECT_EQ(1u, header_table->inserted_entry_count());
  EXPECT_EQ(0u, header_table->dropped_entry_count());

  encoder_.OnStreamCancellation(/* stream_id = */ 1);

  // At this point, entry 0 has no references to it, because stream 1 is
  // cancelled.  However, this entry is unacknowledged, therefore it must not be
  // evicted according to RFC 9204 Section 2.1.1.

  quiche::HttpHeaderBlock header_list2;
  header_list2["bar"] = "baz";

  ASSERT_TRUE(
      absl::HexStringToBytes("0000"       // prefix
                             "23626172"   // literal name "bar"
                             "0362617a",  // literal value "baz"
                             &expected_output));
  EXPECT_EQ(expected_output,
            encoder_.EncodeHeaderList(/* stream_id = */ 2, header_list2,
                                      &encoder_stream_sent_byte_count_));

  EXPECT_EQ(1u, header_table->inserted_entry_count());
  EXPECT_EQ(0u, header_table->dropped_entry_count());
}

// Header name and value match an entry in the dynamic table, but that entry
// cannot be used. If there is an entry with matching name in the static table,
// use that.
TEST_P(QpackEncoderTest, UseStaticTableNameOnlyMatch) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder_.SetMaximumBlockedStreams(2);
  encoder_.SetMaximumDynamicTableCapacity(4096);
  encoder_.SetDynamicTableCapacity(4096);

  quiche::HttpHeaderBlock header_list;
  header_list[":method"] = "bar";

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3fe11f", &set_dyanamic_table_capacity));

  // Insert one entry into the dynamic table.
  std::string insert_entry1;
  ASSERT_TRUE(
      absl::HexStringToBytes("cf"  // insert with name of static table entry 15
                             "03626172",  // literal value "bar"
                             &insert_entry1));
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entry1))));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0200"  // prefix
                             "80",   // dynamic entry 0
                             &expected_output));
  EXPECT_EQ(expected_output,
            encoder_.EncodeHeaderList(/* stream_id = */ 1, header_list,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(insert_entry1.size(), encoder_stream_sent_byte_count_);

  // Stream 2 uses the same dynamic entry.
  EXPECT_EQ(expected_output,
            encoder_.EncodeHeaderList(/* stream_id = */ 2, header_list,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);

  // Streams 1 and 2 are blocked, therefore stream 3 is not allowed to refer to
  // the existing dynamic table entry, nor to add a new entry to the dynamic
  // table.
  ASSERT_TRUE(
      absl::HexStringToBytes("0000"  // prefix
                             "5f00"  // name reference to static table entry 15
                             "03626172",  // literal value "bar"
                             &expected_output));
  EXPECT_EQ(expected_output,
            encoder_.EncodeHeaderList(/* stream_id = */ 3, header_list,
                                      &encoder_stream_sent_byte_count_));
}

// Header name and value match an entry in the dynamic table, but that entry
// cannot be used. If there is an entry with matching name in the dynamic table
// that can be used, do so.
TEST_P(QpackEncoderTest, UseDynamicTableNameOnlyMatch) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list1;
  header_list1["one"] = "foo";
  header_list1["two"] = "foo";
  header_list1["three"] = "foo";
  header_list1["four"] = "foo";
  header_list1["five"] = "foo";
  header_list1["six"] = "foo";
  header_list1["seven"] = "foo";
  header_list1["eight"] = "foo";
  header_list1["nine"] = "foo";
  header_list1["ten"] = "foo";

  // Make just enough room in the dynamic table for the header list,
  // plus another entry using the name of the first one,
  // This will ensure that the oldest entries are draining.
  uint64_t maximum_dynamic_table_capacity = 0;
  for (const auto& header_field : header_list1) {
    maximum_dynamic_table_capacity +=
        QpackEntry::Size(header_field.first, header_field.second);
  }
  maximum_dynamic_table_capacity += QpackEntry::Size("one", "bar");
  encoder_.SetMaximumDynamicTableCapacity(maximum_dynamic_table_capacity);
  encoder_.SetDynamicTableCapacity(maximum_dynamic_table_capacity);

  // Set Dynamic Table Capacity instruction and insert ten entries into the
  // dynamic table.
  EXPECT_CALL(encoder_stream_sender_delegate_, WriteStreamData(_));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0b00"                   // prefix
                             "89888786858483828180",  // dynamic entries
                             &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list1));

  // Entry has the same name as the first one.
  quiche::HttpHeaderBlock header_list2;
  header_list2["one"] = "bar";

  ASSERT_TRUE(absl::HexStringToBytes(
      "89"         // insert entry with same name as dynamic table entry 9
      "03626172",  // and literal value "bar"
      &expected_output));
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(expected_output)));

  ASSERT_TRUE(
      absl::HexStringToBytes("0c00"  // prefix
                             "80",   // most recent dynamic table entry
                             &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list2));

  // Entry is identical to the first one, which is draining, and has the same
  // name but different value as the last one, which is not draining.
  quiche::HttpHeaderBlock header_list3;
  header_list3["one"] = "foo";

  // Entry matches name and value of oldest dynamic table entry, which cannot be
  // used. Use the name of the most recent dynamic table entry instead, and
  // encode value as string literal.
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("0c00"     // prefix
                               "40"       // name as dynamic table entry 0
                               "8294e7",  // Huffman-encoded literal value "foo"
                               &expected_output));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("0c00"       // prefix
                               "40"         // name as dynamic table entry 0
                               "03666f6f",  // literal value "foo"
                               &expected_output));
  }
  EXPECT_EQ(expected_output, Encode(header_list3));
}

TEST_P(QpackEncoderTest, CookieCrumblingEnabledNoDynamicTable) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));

  quiche::HttpHeaderBlock header_list;
  header_list["cookie"] = "foo; bar";

  std::string expected_output;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"       // prefix
                               "55"         // name of static entry 5
                               "8294e7"     // with literal value "bar"
                               "55"         // name of static entry 5
                               "03626172",  // with literal value "bar"
                               &expected_output));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"       // prefix
                               "55"         // name of static entry 5
                               "03666f6f"   // with literal value "foo"
                               "55"         // name of static entry 5
                               "03626172",  // with literal value "bar"
                               &expected_output));
  }
  EXPECT_EQ(expected_output, Encode(header_list));

  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);
}

TEST_P(QpackEncoderTest, CookieCrumblingEnabledDynamicTable) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder_.SetMaximumBlockedStreams(1);
  encoder_.SetMaximumDynamicTableCapacity(4096);
  encoder_.SetDynamicTableCapacity(4096);

  quiche::HttpHeaderBlock header_list;
  header_list["cookie"] = "foo; bar";

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3fe11f", &set_dyanamic_table_capacity));

  // Insert entries into the dynamic table.
  std::string insert_entries;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(absl::HexStringToBytes(
        "c5"         // insert with name reference, static index 5
        "8294e7"     // with literal value "foo"
        "c5"         // insert with name reference, static index 5
        "03626172",  // with literal value "bar"
        &insert_entries));
  } else {
    ASSERT_TRUE(absl::HexStringToBytes(
        "c5"         // insert with name reference, static index 5
        "03666f6f"   // with literal value "foo"
        "c5"         // insert with name reference, static index 5
        "03626172",  // with literal value "bar"
        &insert_entries));
  }
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entries))));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0300"  // prefix
                             "81"    // dynamic entry with relative index 0
                             "80",   // dynamic entry with relative index 1
                             &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list));

  EXPECT_EQ(insert_entries.size(), encoder_stream_sent_byte_count_);
}

TEST_P(QpackEncoderTest, CookieCrumblingDisabledNoDynamicTable) {
  QpackEncoder encoder(&decoder_stream_error_delegate_, huffman_encoding_,
                       CookieCrumbling::kDisabled);

  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));

  quiche::HttpHeaderBlock header_list;
  header_list["cookie"] = "foo; bar";

  std::string expected_output;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(absl::HexStringToBytes(
        "0000"             // prefix
        "55"               // name of static entry 5
        "8694e7fb5231d9",  // with literal value "foo; bar"
        &expected_output));
  } else {
    ASSERT_TRUE(absl::HexStringToBytes(
        "0000"                 // prefix
        "55"                   // name of static entry 5
        "08666f6f3b20626172",  // with literal value "foo; bar"
        &expected_output));
  }
  EXPECT_EQ(expected_output,
            encoder.EncodeHeaderList(/* stream_id = */ 1, header_list,
                                     &encoder_stream_sent_byte_count_));

  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);
}

TEST_P(QpackEncoderTest, CookieCrumblingDisabledDynamicTable) {
  QpackEncoder encoder(&decoder_stream_error_delegate_, huffman_encoding_,
                       CookieCrumbling::kDisabled);
  encoder.SetMaximumBlockedStreams(1);
  encoder.set_qpack_stream_sender_delegate(&encoder_stream_sender_delegate_);

  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder.SetMaximumBlockedStreams(1);
  encoder.SetMaximumDynamicTableCapacity(4096);
  encoder.SetDynamicTableCapacity(4096);

  quiche::HttpHeaderBlock header_list;
  header_list["cookie"] = "foo; bar";

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3fe11f", &set_dyanamic_table_capacity));

  // Insert entries into the dynamic table.
  std::string insert_entries;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(absl::HexStringToBytes(
        "c5"               // insert with name reference, static index 5
        "8694e7fb5231d9",  // with literal value "foo; bar"
        &insert_entries));
  } else {
    ASSERT_TRUE(absl::HexStringToBytes(
        "c5"                   // insert with name reference, static index 5
        "08666f6f3b20626172",  // with literal value "foo; bar"
        &insert_entries));
  }
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entries))));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0200"  // prefix
                             "80",   // dynamic entry with relative index 0
                             &expected_output));
  EXPECT_EQ(expected_output,
            encoder.EncodeHeaderList(/* stream_id = */ 1, header_list,
                                     &encoder_stream_sent_byte_count_));

  EXPECT_EQ(insert_entries.size(), encoder_stream_sent_byte_count_);
}

}  // namespace
}  // namespace test
}  // namespace quic
```