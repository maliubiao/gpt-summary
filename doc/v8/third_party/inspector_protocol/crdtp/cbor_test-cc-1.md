Response:
Let's break down the thought process to analyze the provided C++ code snippet.

1. **Understand the Goal:** The request asks for a functional description of the `cbor_test.cc` file within the V8 project. It also includes specific checks for file extensions, JavaScript relevance, logic analysis, common errors, and finally, a summarization for part 2.

2. **Initial Scan and Keyword Spotting:** Quickly read through the code, looking for recognizable keywords and patterns. The presence of `TEST`, `EXPECT_THAT`, `EXPECT_EQ`, `Status`, `ParseCBOR`, `NewCBOREncoder`, `NewJSONEncoder`, `HandleString8`, `HandleBinary`, etc., strongly suggests this is a unit test file. The names of the test functions (e.g., `JSONToCBOREncoderTest`, `ParseCBORTest`, `EnvelopeHeaderTest`, `AppendString8EntryToMapTest`) give hints about the functionalities being tested. The frequent use of "CBOR" and "JSON" points towards data serialization and deserialization.

3. **Identify Core Functionality:** Based on the test names and the used functions, the core functionality seems to revolve around:
    * **CBOR Encoding:** Converting data (potentially from JSON) into CBOR format.
    * **CBOR Decoding:** Converting CBOR data back into JSON.
    * **Envelope Handling:**  Dealing with a specific "envelope" structure used to wrap CBOR messages (indicated by the `0xd8, 0x5a` magic numbers).
    * **Error Handling:** Testing various error conditions during CBOR parsing.
    * **In-place Modification:**  Appending data to existing CBOR maps.

4. **Address Specific Instructions:**

    * **File Extension:** The code is C++, not Torque, so this part is straightforward.

    * **JavaScript Relevance:** The code deals with converting between JSON and CBOR. JSON is fundamental to JavaScript. This connection needs to be explained. The encoder/decoder facilitates communication where one end might expect CBOR and the other JSON. Provide a simple JavaScript example showing JSON usage.

    * **Logic Analysis (Input/Output):** Focus on representative tests. The `JSONToCBOREncoderTest.HelloWorld` and `ParseCBORTest.ParseCBORHelloWorld` are good examples. Choose one, describe the input JSON/CBOR, the encoding/decoding process, and the expected output.

    * **Common Programming Errors:**  The test file itself provides examples of what can go wrong during CBOR parsing (e.g., `UnexpectedEofError`, `InvalidMapKeyError`, `StackLimitExceededError`). Explain one or two of these errors in a general programming context, not just specific to this CBOR implementation. For instance, forgetting to close a data structure or providing incorrect input types are common mistakes.

5. **Structure the Explanation:** Organize the information logically. Start with the overall purpose, then delve into specific functionalities, address the individual instructions, and finally, provide the summary. Use clear headings and formatting to improve readability.

6. **Refine and Elaborate:**  Review the generated explanation for clarity and completeness.

    * **Elaborate on the Envelope Concept:** Explain why this envelope structure might be used (e.g., for metadata, versioning).
    * **Explain the Role of `ParserHandler`:** Clarify that it's an interface for handling parsing events.
    * **Clarify `Status`:** Mention that it's used for error reporting.
    * **Improve the JavaScript Example:** Make it more concrete and directly relevant to the JSON/CBOR conversion concept.
    * **Strengthen the Error Examples:** Make the connection to common programming mistakes more explicit.

7. **Self-Correction/Review:**  Imagine you are someone unfamiliar with CBOR or V8. Would the explanation make sense? Are there any ambiguities?  For instance, initially, I might have just said "encodes to CBOR," but specifying "from JSON" is important based on the code. Similarly, explaining the purpose of the `SCOPED_TRACE` in the code helps with understanding the test structure. Ensure that the summary accurately reflects all the described functionalities.

By following these steps, we can arrive at a comprehensive and accurate analysis of the provided C++ code snippet, addressing all aspects of the request. The key is to understand the code's purpose, relate it to the broader context (V8, data serialization), and clearly explain its functionality with relevant examples and error scenarios.
Based on the provided C++ code snippet, here's a breakdown of its functionality:

**Core Functionality of `v8/third_party/inspector_protocol/crdtp/cbor_test.cc`:**

This file contains unit tests for CBOR (Concise Binary Object Representation) encoding and decoding functionality within the V8 JavaScript engine's Chrome DevTools Protocol (CRDP) implementation. Specifically, it tests the conversion between JSON and CBOR formats.

**Key Functionalities Being Tested:**

1. **JSON to CBOR Encoding:**
   - Tests the `NewCBOREncoder` which takes JSON input and produces CBOR output.
   - Verifies that nested JSON objects and arrays are correctly encoded into CBOR.
   - Tests the handling of binary data within this encoding process (although direct JSON parsing doesn't support binary, the encoder can handle it when invoked directly).

2. **CBOR to JSON Decoding:**
   - Tests the `ParseCBOR` function, which takes CBOR input and converts it back to JSON using `NewJSONEncoder`.
   - Covers various CBOR data types and structures, including maps (objects), arrays, strings (including UTF-8), and binary data.
   - Tests the handling of CBOR "envelopes" - a specific structure used to wrap CBOR messages (starting with `0xd8, 0x5a`).

3. **CBOR Envelope Handling:**
   - Tests the parsing of CBOR envelope headers using `EnvelopeHeader::Parse`.
   - Verifies the correct extraction of header size, content size, and total size from the envelope.
   - Checks for errors related to invalid or malformed envelopes (e.g., incorrect length indicators, missing start/stop bytes).
   - Validates that only maps and arrays are supported within the CBOR envelopes.

4. **Error Handling during CBOR Parsing:**
   - The tests extensively cover different error scenarios that can occur during CBOR parsing, such as:
     - Unexpected end of file (EOF).
     - Expected value missing.
     - Errors within arrays and maps.
     - Invalid map keys.
     - Stack limit exceeded (for deeply nested structures).
     - Unsupported CBOR value types (like tags).
     - Invalid string encodings (UTF-8 and UTF-16).
     - Invalid binary data.
     - Invalid floating-point numbers (doubles).
     - Invalid signed integers (out of supported range).
     - Trailing garbage data after a valid CBOR message.
     - Mismatched lengths in CBOR envelopes.

5. **In-place Modification of CBOR Maps:**
   - Tests the `AppendString8EntryToCBORMap` function, which allows adding new key-value pairs (string keys and string values) to an existing CBOR map *without* fully re-encoding the message. This is likely for optimization purposes.
   - Verifies that the function correctly appends entries and handles errors like missing map start/stop bytes or invalid envelope structures.

**Relationship to JavaScript (and assuming it was .tq):**

While this specific file is C++, if a file with similar functionality ended in `.tq`, it would be a V8 Torque source file. Torque is a domain-specific language used within V8 for implementing highly performance-critical parts of the JavaScript engine.

If this were a Torque file related to JavaScript, it would likely be involved in:

- **Serialization/Deserialization within the V8 engine:**  Torque code could be responsible for efficiently converting JavaScript objects and values to and from CBOR format when interacting with external systems or the DevTools.
- **Implementing specific DevTools protocol commands:**  Parts of the DevTools protocol might require data to be encoded in CBOR, and Torque code could handle the low-level encoding/decoding.

**JavaScript Example (Illustrating the concept of JSON to CBOR and back):**

Although this C++ code tests the underlying implementation, the concept is about representing data in a more compact binary format (CBOR) compared to the text-based JSON. Imagine sending data from a JavaScript application to a server that prefers CBOR, or receiving CBOR data from the server.

```javascript
// Example using a hypothetical JavaScript CBOR library (not standard browser API)
const myObject = {
  name: "Example",
  value: 123,
  nested: {
    items: [1, 2, 3]
  }
};

// Hypothetical function to encode to CBOR
const cborData = CBOR.encode(myObject);

console.log("CBOR Encoded Data:", cborData); // This would be a Uint8Array

// Hypothetical function to decode from CBOR
const decodedObject = CBOR.decode(cborData);

console.log("Decoded Object:", decodedObject); // Should be the same as myObject
```

**Code Logic Inference with Assumptions:**

Let's take the `JSONToCBOREncoderTest.HelloWorldBinary_WithTripToJson` test as an example:

**Assumed Input (Conceptual JSON that's manually built using the encoder):**

We are manually constructing a CBOR message that *would* represent the following JSON:

```json
{
  "foo": "SGVsbG8sIHdvcmxkLg=="
}
```

Where `"SGVsbG8sIHdvcmxkLg=="` is the base64 encoding of "Hello, world.".

**Steps in the Test:**

1. **Encoding to CBOR:**
   - `NewCBOREncoder` is created.
   - `HandleMapBegin()` starts a CBOR map.
   - `HandleString16(SpanFrom(key))` encodes the key "foo".
   - `HandleBinary(SpanFrom(...))` encodes the byte array representing "Hello, world." as a binary value.
   - `HandleMapEnd()` ends the CBOR map.

2. **Decoding CBOR to JSON:**
   - `ParseCBOR` is called with the encoded CBOR data.
   - `NewJSONEncoder` is used to convert the CBOR back to JSON.

**Expected Output (JSON after decoding):**

```json
{"foo":"SGVsbG8sIHdvcmxkLg=="}
```

**Common Programming Errors Illustrated by the Tests:**

The tests themselves highlight many common errors when dealing with binary formats and structured data:

- **Forgetting to close structures:**  The `ParseCBORTest.UnexpectedEofInMapError` and `ParseCBORTest.UnexpectedEofInArrayError` tests show what happens if a map or array is started but not properly terminated. This is analogous to forgetting closing braces `{}` or brackets `[]` in JSON or other structured formats.
- **Incorrect length indicators:**  The tests around envelope handling (`ParseCBORTest.EnvelopeContentsLengthMismatch`) demonstrate the importance of accurately specifying the size of data structures in binary formats. A mismatch can lead to parsing errors.
- **Providing invalid data types:** The `ParseCBORTest.InvalidMapKeyError` shows that certain data types (like `null`) are not valid as map keys in CBOR (similar to JSON where keys must be strings).
- **Exceeding limits:** The `ParseCBORTest.StackLimitExceededError` illustrates the potential for stack overflows when dealing with deeply nested data structures if not handled carefully by the parser.
- **Assuming correct input format:**  Many error tests (like `ParseCBORTest.NoInputError`, `ParseCBORTest.TrailingJunk`) highlight the need to validate input data and handle cases where the input doesn't conform to the expected format.

**Summary of Functionality (Part 2):**

This code file (`v8/third_party/inspector_protocol/crdtp/cbor_test.cc`) thoroughly tests the CBOR encoding and decoding functionality used within V8's DevTools protocol. It verifies the correct conversion between JSON and CBOR, robustly handles various CBOR data types and structures, and meticulously checks for a wide range of potential error conditions during the parsing process. Furthermore, it tests a mechanism for efficiently appending data to existing CBOR maps. The tests ensure the reliability and correctness of the CBOR implementation within the V8 engine, which is crucial for efficient communication and data representation in the DevTools.

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/cbor_test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/cbor_test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
xamples = {
      // Tests that after closing a nested objects, additional key/value pairs
      // are considered.
      "{\"foo\":{\"bar\":1},\"baz\":2}", "{\"foo\":[1,2,3],\"baz\":2}"};
  for (const std::string& json : examples) {
    SCOPED_TRACE(std::string("example: ") + json);
    std::vector<uint8_t> encoded;
    Status status;
    std::unique_ptr<ParserHandler> encoder = NewCBOREncoder(&encoded, &status);
    span<uint8_t> ascii_in = SpanFrom(json);
    json::ParseJSON(ascii_in, encoder.get());
    std::string decoded;
    std::unique_ptr<ParserHandler> json_writer =
        json::NewJSONEncoder(&decoded, &status);
    ParseCBOR(span<uint8_t>(encoded.data(), encoded.size()), json_writer.get());
    EXPECT_THAT(status, StatusIsOk());
    EXPECT_EQ(json, decoded);
  }
}

TEST(JSONToCBOREncoderTest, HelloWorldBinary_WithTripToJson) {
  // The ParserHandler::HandleBinary is a special case: The JSON parser
  // will never call this method, because JSON does not natively support the
  // binary type. So, we can't fully roundtrip. However, the other direction
  // works: binary will be rendered in JSON, as a base64 string. So, we make
  // calls to the encoder directly here, to construct a message, and one of
  // these calls is ::HandleBinary, to which we pass a "binary" string
  // containing "Hello, world.".
  std::vector<uint8_t> encoded;
  Status status;
  std::unique_ptr<ParserHandler> encoder = NewCBOREncoder(&encoded, &status);
  encoder->HandleMapBegin();
  // Emit a key.
  std::vector<uint16_t> key = {'f', 'o', 'o'};
  encoder->HandleString16(SpanFrom(key));
  // Emit the binary payload, an arbitrary array of bytes that happens to
  // be the ascii message "Hello, world.".
  encoder->HandleBinary(SpanFrom(std::vector<uint8_t>{
      'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '.'}));
  encoder->HandleMapEnd();
  EXPECT_THAT(status, StatusIsOk());

  // Now drive the json writer via the CBOR decoder.
  std::string decoded;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&decoded, &status);
  ParseCBOR(SpanFrom(encoded), json_writer.get());
  EXPECT_THAT(status, StatusIsOk());
  // "Hello, world." in base64 is "SGVsbG8sIHdvcmxkLg==".
  EXPECT_EQ("{\"foo\":\"SGVsbG8sIHdvcmxkLg==\"}", decoded);
}

// =============================================================================
// cbor::ParseCBOR - for receiving streaming parser events for CBOR messages
// =============================================================================

TEST(ParseCBORTest, ParseEmptyCBORMessage) {
  // An envelope starting with 0xd8, 0x5a, with the byte length
  // of 2, containing a map that's empty (0xbf for map
  // start, and 0xff for map end).
  std::vector<uint8_t> in = {0xd8, 0x5a, 0, 0, 0, 2, 0xbf, 0xff};
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(in.data(), in.size()), json_writer.get());
  EXPECT_THAT(status, StatusIsOk());
  EXPECT_EQ("{}", out);
}

TEST(ParseCBORTest, ParseCBORHelloWorld) {
  const uint8_t kPayloadLen = 27;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen};
  bytes.push_back(0xbf);                   // start indef length map.
  EncodeString8(SpanFrom("msg"), &bytes);  // key: msg
  // Now write the value, the familiar "Hello, 🌎." where the globe is expressed
  // as two utf16 chars.
  bytes.push_back(/*major type=*/2 << 5 | /*additional info=*/20);
  for (uint8_t ch : std::array<uint8_t, 20>{
           {'H', 0, 'e', 0, 'l',  0,    'l',  0,    'o', 0,
            ',', 0, ' ', 0, 0x3c, 0xd8, 0x0e, 0xdf, '.', 0}})
    bytes.push_back(ch);
  bytes.push_back(0xff);  // stop byte
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);

  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIsOk());
  EXPECT_EQ("{\"msg\":\"Hello, \\ud83c\\udf0e.\"}", out);
}

TEST(ParseCBORTest, UTF8IsSupportedInKeys) {
  const uint8_t kPayloadLen = 11;
  std::vector<uint8_t> bytes = {0xd8, 0x5a,  // envelope
                                0,    0,    0, kPayloadLen};
  bytes.push_back(cbor::EncodeIndefiniteLengthMapStart());
  // Two UTF16 chars.
  EncodeString8(SpanFrom("🌎"), &bytes);
  // Can be encoded as a single UTF16 char.
  EncodeString8(SpanFrom("☾"), &bytes);
  bytes.push_back(cbor::EncodeStop());
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);

  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIsOk());
  EXPECT_EQ("{\"\\ud83c\\udf0e\":\"\\u263e\"}", out);
}

TEST(ParseCBORTest, NoInputError) {
  std::vector<uint8_t> in = {};
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(in.data(), in.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, 0u));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, UnexpectedEofExpectedValueError) {
  constexpr uint8_t kPayloadLen = 5;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  // A key; so value would be next.
  EncodeString8(SpanFrom("key"), &bytes);
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_UNEXPECTED_EOF_EXPECTED_VALUE,
                               bytes.size()));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, UnexpectedEofInArrayError) {
  constexpr uint8_t kPayloadLen = 8;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};  // The byte for starting a map.
  // A key; so value would be next.
  EncodeString8(SpanFrom("array"), &bytes);
  bytes.push_back(0x9f);  // byte for indefinite length array start.
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status,
              StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_ARRAY, bytes.size()));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, UnexpectedEofInMapError) {
  constexpr uint8_t kPayloadLen = 1;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};  // The byte for starting a map.
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_MAP, 7u));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, EnvelopeEncodingLegacy) {
  constexpr uint8_t kPayloadLen = 8;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen};  // envelope
  bytes.push_back(cbor::EncodeIndefiniteLengthMapStart());
  EncodeString8(SpanFrom("foo"), &bytes);
  EncodeInt32(42, &bytes);
  bytes.emplace_back(EncodeStop());
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIsOk());
  EXPECT_EQ(out, "{\"foo\":42}");
}

TEST(ParseCBORTest, EnvelopeEncodingBySpec) {
  constexpr uint8_t kPayloadLen = 8;
  std::vector<uint8_t> bytes = {0xd8, 0x18, 0x5a,       0,
                                0,    0,    kPayloadLen};  // envelope
  bytes.push_back(cbor::EncodeIndefiniteLengthMapStart());
  EncodeString8(SpanFrom("foo"), &bytes);
  EncodeInt32(42, &bytes);
  bytes.emplace_back(EncodeStop());
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIsOk());
  EXPECT_EQ(out, "{\"foo\":42}");
}

TEST(ParseCBORTest, NoEmptyEnvelopesAllowed) {
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, 0};  // envelope
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_MAP_OR_ARRAY_EXPECTED_IN_ENVELOPE,
                               bytes.size()));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, OnlyMapsAndArraysSupportedInsideEnvelopes) {
  // The top level is a map with key "foo", and the value
  // is an envelope that contains just a number (1). We don't
  // allow numbers to be contained in an envelope though, only
  // maps and arrays.
  constexpr uint8_t kPayloadLen = 8;
  std::vector<uint8_t> bytes = {0xd8,
                                0x5a,
                                0,
                                0,
                                0,
                                kPayloadLen,  // envelope
                                EncodeIndefiniteLengthMapStart()};
  EncodeString8(SpanFrom("foo"), &bytes);
  for (uint8_t byte : {0xd8, 0x5a, 0, 0, 0, /*payload_len*/ 1})
    bytes.emplace_back(byte);
  size_t error_pos = bytes.size();
  bytes.push_back(1);  // Envelope contents / payload = number 1.
  bytes.emplace_back(EncodeStop());

  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_MAP_OR_ARRAY_EXPECTED_IN_ENVELOPE,
                               error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, InvalidMapKeyError) {
  constexpr uint8_t kPayloadLen = 2;
  std::vector<uint8_t> bytes = {0xd8,       0x5a, 0,
                                0,          0,    kPayloadLen,  // envelope
                                0xbf,                           // map start
                                7 << 5 | 22};  // null (not a valid map key)
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_MAP_KEY, 7u));
  EXPECT_EQ("", out);
}

std::vector<uint8_t> MakeNestedCBOR(int depth) {
  std::vector<uint8_t> bytes;
  std::vector<EnvelopeEncoder> envelopes;
  for (int ii = 0; ii < depth; ++ii) {
    envelopes.emplace_back();
    envelopes.back().EncodeStart(&bytes);
    bytes.push_back(0xbf);  // indef length map start
    EncodeString8(SpanFrom("key"), &bytes);
  }
  EncodeString8(SpanFrom("innermost_value"), &bytes);
  for (int ii = 0; ii < depth; ++ii) {
    bytes.push_back(0xff);  // stop byte, finishes map.
    envelopes.back().EncodeStop(&bytes);
    envelopes.pop_back();
  }
  return bytes;
}

TEST(ParseCBORTest, StackLimitExceededError) {
  {  // Depth 3: no stack limit exceeded error and is easy to inspect.
    std::vector<uint8_t> bytes = MakeNestedCBOR(3);
    std::string out;
    Status status;
    std::unique_ptr<ParserHandler> json_writer =
        json::NewJSONEncoder(&out, &status);
    ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
    EXPECT_THAT(status, StatusIsOk());
    EXPECT_EQ("{\"key\":{\"key\":{\"key\":\"innermost_value\"}}}", out);
  }
  {  // Depth 300: no stack limit exceeded.
    std::vector<uint8_t> bytes = MakeNestedCBOR(300);
    std::string out;
    Status status;
    std::unique_ptr<ParserHandler> json_writer =
        json::NewJSONEncoder(&out, &status);
    ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
    EXPECT_THAT(status, StatusIsOk());
  }

  // We just want to know the length of one opening map so we can compute
  // where the error is encountered. So we look at a small example and find
  // the second envelope start.
  std::vector<uint8_t> small_example = MakeNestedCBOR(3);
  size_t opening_segment_size = 1;  // Start after the first envelope start.
  while (opening_segment_size < small_example.size() &&
         small_example[opening_segment_size] != 0xd8)
    opening_segment_size++;

  {  // Depth 301: limit exceeded.
    std::vector<uint8_t> bytes = MakeNestedCBOR(301);
    std::string out;
    Status status;
    std::unique_ptr<ParserHandler> json_writer =
        json::NewJSONEncoder(&out, &status);
    ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
    EXPECT_THAT(status, StatusIs(Error::CBOR_STACK_LIMIT_EXCEEDED,
                                 opening_segment_size * 301));
  }
  {  // Depth 320: still limit exceeded, and at the same pos as for 1001
    std::vector<uint8_t> bytes = MakeNestedCBOR(320);
    std::string out;
    Status status;
    std::unique_ptr<ParserHandler> json_writer =
        json::NewJSONEncoder(&out, &status);
    ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
    EXPECT_THAT(status, StatusIs(Error::CBOR_STACK_LIMIT_EXCEEDED,
                                 opening_segment_size * 301));
  }
}

TEST(ParseCBORTest, UnsupportedValueError) {
  constexpr uint8_t kPayloadLen = 6;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  EncodeString8(SpanFrom("key"), &bytes);
  size_t error_pos = bytes.size();
  bytes.push_back(6 << 5 | 5);  // tags aren't supported yet.
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);

  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_UNSUPPORTED_VALUE, error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, InvalidString16Error) {
  constexpr uint8_t kPayloadLen = 11;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  EncodeString8(SpanFrom("key"), &bytes);
  size_t error_pos = bytes.size();
  // a BYTE_STRING of length 5 as value; since we interpret these as string16,
  // it's going to be invalid as each character would need two bytes, but
  // 5 isn't divisible by 2.
  bytes.push_back(2 << 5 | 5);
  for (int ii = 0; ii < 5; ++ii)
    bytes.push_back(' ');
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_STRING16, error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, InvalidString8Error) {
  constexpr uint8_t kPayloadLen = 6;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  EncodeString8(SpanFrom("key"), &bytes);
  size_t error_pos = bytes.size();
  // a STRING of length 5 as value, but we're at the end of the bytes array
  // so it can't be decoded successfully.
  bytes.push_back(3 << 5 | 5);
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_STRING8, error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, InvalidBinaryError) {
  constexpr uint8_t kPayloadLen = 9;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  EncodeString8(SpanFrom("key"), &bytes);
  size_t error_pos = bytes.size();
  bytes.push_back(6 << 5 | 22);  // base64 hint for JSON; indicates binary
  bytes.push_back(2 << 5 | 10);  // BYTE_STRING (major type 2) of length 10
  // Just two garbage bytes, not enough for the binary.
  bytes.push_back(0x31);
  bytes.push_back(0x23);
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_BINARY, error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, InvalidDoubleError) {
  constexpr uint8_t kPayloadLen = 8;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  EncodeString8(SpanFrom("key"), &bytes);
  size_t error_pos = bytes.size();
  bytes.push_back(7 << 5 | 27);  // initial byte for double
  // Just two garbage bytes, not enough to represent an actual double.
  bytes.push_back(0x31);
  bytes.push_back(0x23);
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_DOUBLE, error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, InvalidSignedError) {
  constexpr uint8_t kPayloadLen = 14;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  EncodeString8(SpanFrom("key"), &bytes);
  size_t error_pos = bytes.size();
  // uint64_t max is a perfectly fine value to encode as CBOR unsigned,
  // but we don't support this since we only cover the int32_t range.
  internals::WriteTokenStart(MajorType::UNSIGNED,
                             std::numeric_limits<uint64_t>::max(), &bytes);
  EXPECT_EQ(kPayloadLen, bytes.size() - 6);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_INT32, error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, TrailingJunk) {
  constexpr uint8_t kPayloadLen = 12;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  EncodeString8(SpanFrom("key"), &bytes);
  EncodeString8(SpanFrom("value"), &bytes);
  bytes.push_back(0xff);  // Up to here, it's a perfectly fine msg.
  ASSERT_EQ(kPayloadLen, bytes.size() - 6);
  size_t error_pos = bytes.size();
  // Now write some trailing junk after the message.
  EncodeString8(SpanFrom("trailing junk"), &bytes);
  internals::WriteTokenStart(MajorType::UNSIGNED,
                             std::numeric_limits<uint64_t>::max(), &bytes);
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_TRAILING_JUNK, error_pos));
  EXPECT_EQ("", out);
}

TEST(ParseCBORTest, EnvelopeContentsLengthMismatch) {
  constexpr uint8_t kPartialPayloadLen = 5;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0,
                                0,    0,    kPartialPayloadLen,  // envelope
                                0xbf};                           // map start
  EncodeString8(SpanFrom("key"), &bytes);
  // kPartialPayloadLen would need to indicate the length of the entire map,
  // all the way past the 0xff map stop character. Instead, it only covers
  // a portion of the map.
  EXPECT_EQ(bytes.size() - 6, kPartialPayloadLen);
  EncodeString8(SpanFrom("value"), &bytes);
  bytes.push_back(0xff);  // map stop

  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(span<uint8_t>(bytes.data(), bytes.size()), json_writer.get());
  EXPECT_THAT(status, StatusIs(Error::CBOR_ENVELOPE_CONTENTS_LENGTH_MISMATCH,
                               bytes.size()));
  EXPECT_EQ("", out);
}

// =============================================================================
// cbor::EnvelopeHeader - for parsing envelope headers
// =============================================================================
// Note most of converage for this is historically on a higher level of
// ParseCBOR(). This provides just a few essnetial scenarios for now.

template <typename T>
class EnvelopeHeaderTest : public ::testing::Test {};

TEST(EnvelopeHeaderTest, EnvelopeStartLegacy) {
  std::vector<uint8_t> bytes = {0xd8,             // Tag start
                                0x5a,             // Byte string, 4 bytes length
                                0,    0,   0, 2,  // Length
                                0xbf, 0xff};      // map start / map end
  auto result = EnvelopeHeader::Parse(SpanFrom(bytes));
  ASSERT_THAT(result.status(), StatusIsOk());
  EXPECT_THAT((*result).header_size(), Eq(6u));
  EXPECT_THAT((*result).content_size(), Eq(2u));
  EXPECT_THAT((*result).outer_size(), Eq(8u));
}

TEST(EnvelopeHeaderTest, EnvelopeStartSpecCompliant) {
  std::vector<uint8_t> bytes = {0xd8,             // Tag start
                                0x18,             // Tag type (CBOR)
                                0x5a,             // Byte string, 4 bytes length
                                0,    0,   0, 2,  // Length
                                0xbf, 0xff};      // map start / map end
  auto result = EnvelopeHeader::Parse(SpanFrom(bytes));
  ASSERT_THAT(result.status(), StatusIsOk());
  EXPECT_THAT((*result).header_size(), Eq(7u));
  EXPECT_THAT((*result).content_size(), Eq(2u));
  EXPECT_THAT((*result).outer_size(), Eq(9u));
}

TEST(EnvelopeHeaderTest, EnvelopeStartShortLen) {
  std::vector<uint8_t> bytes = {0xd8,         // Tag start
                                0x18,         // Tag type (CBOR)
                                0x58,         // Byte string, 1 byte length
                                2,            // Length
                                0xbf, 0xff};  // map start / map end
  auto result = EnvelopeHeader::Parse(SpanFrom(bytes));
  ASSERT_THAT(result.status(), StatusIsOk());
  EXPECT_THAT((*result).header_size(), Eq(4u));
  EXPECT_THAT((*result).content_size(), Eq(2u));
  EXPECT_THAT((*result).outer_size(), Eq(6u));
}

TEST(EnvelopeHeaderTest, ParseFragment) {
  std::vector<uint8_t> bytes = {0xd8,  // Tag start
                                0x18,  // Tag type (CBOR)
                                0x5a,  // Byte string, 4 bytes length
                                0,    0, 0, 20, 0xbf};  // map start
  auto result = EnvelopeHeader::ParseFromFragment(SpanFrom(bytes));
  ASSERT_THAT(result.status(), StatusIsOk());
  EXPECT_THAT((*result).header_size(), Eq(7u));
  EXPECT_THAT((*result).content_size(), Eq(20u));
  EXPECT_THAT((*result).outer_size(), Eq(27u));

  result = EnvelopeHeader::Parse(SpanFrom(bytes));
  ASSERT_THAT(result.status(),
              StatusIs(Error::CBOR_ENVELOPE_CONTENTS_LENGTH_MISMATCH, 8));
}

// =============================================================================
// cbor::AppendString8EntryToMap - for limited in-place editing of messages
// =============================================================================

template <typename T>
class AppendString8EntryToMapTest : public ::testing::Test {};

using ContainerTestTypes = ::testing::Types<std::vector<uint8_t>, std::string>;
TYPED_TEST_SUITE(AppendString8EntryToMapTest, ContainerTestTypes);

TEST(AppendString8EntryToMapTest, AppendsEntrySuccessfully) {
  constexpr uint8_t kPayloadLen = 12;
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, kPayloadLen,  // envelope
                                0xbf};                             // map start
  size_t pos_before_payload = bytes.size() - 1;
  EncodeString8(SpanFrom("key"), &bytes);
  EncodeString8(SpanFrom("value"), &bytes);
  bytes.push_back(0xff);  // A perfectly fine cbor message.
  EXPECT_EQ(kPayloadLen, bytes.size() - pos_before_payload);

  std::vector<uint8_t> msg(bytes.begin(), bytes.end());

  Status status =
      AppendString8EntryToCBORMap(SpanFrom("foo"), SpanFrom("bar"), &msg);
  EXPECT_THAT(status, StatusIsOk());
  std::string out;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(SpanFrom(msg), json_writer.get());
  EXPECT_EQ("{\"key\":\"value\",\"foo\":\"bar\"}", out);
  EXPECT_THAT(status, StatusIsOk());
}

TYPED_TEST(AppendString8EntryToMapTest, AppendThreeEntries) {
  std::vector<uint8_t> encoded = {
      0xd8, 0x5a, 0, 0, 0, 2, EncodeIndefiniteLengthMapStart(), EncodeStop()};
  EXPECT_THAT(
      AppendString8EntryToCBORMap(SpanFrom("key"), SpanFrom("value"), &encoded),
      StatusIsOk());
  EXPECT_THAT(AppendString8EntryToCBORMap(SpanFrom("key1"), SpanFrom("value1"),
                                          &encoded),
              StatusIsOk());
  EXPECT_THAT(AppendString8EntryToCBORMap(SpanFrom("key2"), SpanFrom("value2"),
                                          &encoded),
              StatusIsOk());
  TypeParam msg(encoded.begin(), encoded.end());
  std::string out;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&out, &status);
  ParseCBOR(SpanFrom(msg), json_writer.get());
  EXPECT_EQ("{\"key\":\"value\",\"key1\":\"value1\",\"key2\":\"value2\"}", out);
  EXPECT_THAT(status, StatusIsOk());
}

TEST(AppendString8EntryToMapTest, MapStartExpected_Error) {
  std::vector<uint8_t> msg = {
      0xd8, 0x5a, 0, 0, 0, 1, EncodeIndefiniteLengthArrayStart()};
  Status status =
      AppendString8EntryToCBORMap(SpanFrom("key"), SpanFrom("value"), &msg);
  EXPECT_THAT(status, StatusIs(Error::CBOR_MAP_START_EXPECTED, 6u));
}

TEST(AppendString8EntryToMapTest, MapStopExpected_Error) {
  std::vector<uint8_t> msg = {
      0xd8, 0x5a, 0, 0, 0, 2, EncodeIndefiniteLengthMapStart(), 42};
  Status status =
      AppendString8EntryToCBORMap(SpanFrom("key"), SpanFrom("value"), &msg);
  EXPECT_THAT(status, StatusIs(Error::CBOR_MAP_STOP_EXPECTED, 7u));
}

TEST(AppendString8EntryToMapTest, InvalidEnvelope_Error) {
  {  // Second byte is wrong.
    std::vector<uint8_t> msg = {
        0x5a, 0, 0, 0, 2, EncodeIndefiniteLengthMapStart(), EncodeStop(), 0};
    Status status =
        AppendString8EntryToCBORMap(SpanFrom("key"), SpanFrom("value"), &msg);
    EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_ENVELOPE, 0u));
  }
  {  // Second byte is wrong.
    std::vector<uint8_t> msg = {
        0xd8, 0x7a, 0, 0, 0, 2, EncodeIndefiniteLengthMapStart(), EncodeStop()};
    Status status =
        AppendString8EntryToCBORMap(SpanFrom("key"), SpanFrom("value"), &msg);
    EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_ENVELOPE, 1u));
  }
  {  // Invalid envelope size example.
    std::vector<uint8_t> msg = {
        0xd8, 0x5a, 0, 0, 0, 3, EncodeIndefiniteLengthMapStart(), EncodeStop(),
    };
    Status status =
        AppendString8EntryToCBORMap(SpanFrom("key"), SpanFrom("value"), &msg);
    EXPECT_THAT(status,
                StatusIs(Error::CBOR_ENVELOPE_CONTENTS_LENGTH_MISMATCH, 8u));
  }
  {  // Invalid envelope size example.
    std::vector<uint8_t> msg = {
        0xd8, 0x5a, 0, 0, 0, 1, EncodeIndefiniteLengthMapStart(), EncodeStop(),
    };
    Status status =
        AppendString8EntryToCBORMap(SpanFrom("key"), SpanFrom("value"), &msg);
    EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_ENVELOPE, 0));
  }
}
}  // namespace cbor
}  // namespace v8_crdtp
```