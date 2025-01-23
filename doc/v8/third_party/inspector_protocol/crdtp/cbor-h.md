Response:
My thinking process to analyze the `cbor.h` file went through these stages:

1. **Initial Scan for Core Purpose:** I immediately recognized "CBOR" in the filename and comments, and the mention of RFC 7049. This instantly told me the primary function is handling Concise Binary Object Representation (CBOR) encoding and decoding. The comment about the inspector protocol further narrowed down its use case within V8.

2. **Identify Key Components and Groupings:** I started to visually group related sections. The `Detecting CBOR content`, `Encoding individual CBOR items`, `cbor::EnvelopeEncoder`, `cbor::NewCBOREncoder`, `cbor::CBORTokenizer`, and `cbor::ParseCBOR` sections clearly represented different functionalities. I also noted the helper functions like `AppendString8EntryToCBORMap`.

3. **Analyze Each Section's Functionality:**  I went through each section, reading the comments and looking at the function signatures:

    * **Detecting CBOR content:**  `IsCBORMessage` and `CheckCBORMessage` are self-explanatory – they verify if a byte span is a valid CBOR message, with the latter doing a lightweight check.

    * **Encoding individual CBOR items:**  This section contains functions for encoding basic CBOR types: booleans, null, integers, UTF-8 and UTF-16 strings, binary data, and doubles. The specifics about UTF-8/UTF-16 handling and the binary data prefix caught my attention.

    * **`EnvelopeEncoder` and `EnvelopeHeader`:** The comments clearly explain the envelope concept (a tag and length prefix for maps and arrays). I understood `EnvelopeEncoder` is for creating these envelopes during encoding, and `EnvelopeHeader` is for parsing them.

    * **`NewCBOREncoder`:**  The comment about a "streaming parser" hinted at an event-driven encoding approach. It suggests this function sets up a handler that can receive parser events and generate CBOR.

    * **`CBORTokenizer`:** This looked like the core of the parsing logic. The `CBORTokenTag` enum defined the different CBOR element types the tokenizer could identify. The methods (`TokenTag`, `Next`, `EnterEnvelope`, `GetInt32`, `GetString8`, etc.) clearly indicated its role in breaking down a CBOR message into tokens. The `EnterEnvelope` method is important for handling nested structures.

    * **`ParseCBOR`:** This function seemed to be a higher-level parsing function that takes CBOR bytes and a `ParserHandler` (presumably an interface for handling parsing events). This aligns with the streaming nature implied by `NewCBOREncoder`.

    * **`AppendString8EntryToCBORMap`:** This function provides a specific utility for modifying existing CBOR maps, which is interesting and potentially error-prone.

    * **`internals`:**  I recognized this as a namespace for implementation details, likely used in testing.

4. **Identify Relationships and Data Flow:** I started to connect the different components. The encoder (`NewCBOREncoder`, individual `Encode...` functions, `EnvelopeEncoder`) takes data and produces CBOR byte sequences. The tokenizer (`CBORTokenizer`) takes CBOR bytes and breaks them down into logical units. `ParseCBOR` acts as a bridge between the raw bytes and a higher-level `ParserHandler`. Envelopes seemed crucial for handling structured data.

5. **Consider JavaScript Relevance (as requested):**  I knew that V8 is the JavaScript engine, and the inspector protocol is used by developer tools. This made the connection to JavaScript clear. The CBOR format is used to serialize data exchanged between the browser's JavaScript environment and the DevTools frontend. I then thought about how this would manifest in JavaScript:  fetching data from the DevTools, sending data to the DevTools, and how this data might be structured (objects, arrays, strings, numbers). This led to the JavaScript examples.

6. **Think About Potential Errors:** Based on my understanding of encoding/decoding and binary formats, I considered common issues: incorrect data types, malformed CBOR, unexpected message structures, and the limitations imposed by the specification (e.g., integer range, string encodings). This led to the "Common Programming Errors" section.

7. **Construct Hypothetical Input/Output (as requested):** I chose a simple example of encoding an object with a string and a number to demonstrate the encoding process and how the envelope wraps the map. For decoding, I showed the reverse process with the tokenizer.

8. **Refine and Organize:** I structured my findings logically, starting with the overall purpose and then diving into the details of each section. I used clear headings and bullet points to improve readability. I ensured I addressed all the specific questions in the prompt (functionality, Torque, JavaScript relevance, input/output, common errors).

Essentially, my process involved understanding the core problem the code solves (CBOR handling), breaking down the code into functional units, analyzing each unit's purpose, identifying the relationships between units, connecting it to the broader context of V8 and JavaScript, anticipating potential problems, and finally, structuring the information in a clear and comprehensive way.
This header file, `v8/third_party/inspector_protocol/crdtp/cbor.h`, defines functionalities for encoding and decoding data using the Concise Binary Object Representation (CBOR) format within the V8 JavaScript engine's Chrome DevTools Protocol (CRDP) implementation.

Here's a breakdown of its functionalities:

**Core Functionality: CBOR Encoding and Decoding for CRDP**

The primary purpose of this file is to provide tools for serializing and deserializing data exchanged between the V8 engine and the Chrome DevTools frontend. CBOR is used as a binary encoding format for efficiency.

**Key Features and Sections:**

* **CBOR Specification Adherence with Constraints:**
    * It explicitly mentions adherence to the CBOR specification (RFC 7049).
    * It outlines specific constraints for the inspector protocol's use of CBOR, such as:
        * Only indefinite length maps and arrays are supported.
        * Maps and arrays are wrapped in an envelope containing their byte length.
        * Top-level messages must be enveloped indefinite-length maps.
        * Maximum message size is 4GB.
        * Scalar values are limited to the `int32_t` range.
        * UTF-16 strings are encoded as byte strings with even byte length.
        * UTF-8 strings are supported.
        * 7-bit US-ASCII strings are always encoded as UTF-8.
        * Binary data is encoded as byte strings with a base64 indicator for JSON rendering.

* **Detecting CBOR Content:**
    * `IsCBORMessage(span<uint8_t> msg)`: Checks if a given byte span `msg` is a valid CBOR message according to the defined constraints.
    * `CheckCBORMessage(span<uint8_t> msg)`: Performs a lightweight check for common structural properties of a DevTools CBOR message (non-empty, starts with the envelope tag, etc.).

* **Encoding Individual CBOR Items:**
    * Functions to encode basic CBOR types:
        * `EncodeTrue()`, `EncodeFalse()`, `EncodeNull()`: Encode boolean and null values.
        * `EncodeIndefiniteLengthArrayStart()`, `EncodeIndefiniteLengthMapStart()`, `EncodeStop()`: Encode the start and end markers for indefinite-length arrays and maps.
        * `EncodeInt32(int32_t value, std::vector<uint8_t>* out)`: Encodes a 32-bit integer.
        * `EncodeString16(span<uint16_t> in, std::vector<uint8_t>* out)`: Encodes a UTF-16 string.
        * `EncodeString8(span<uint8_t> in, std::vector<uint8_t>* out)`: Encodes a UTF-8 string.
        * `EncodeFromLatin1(span<uint8_t> latin1, std::vector<uint8_t>* out)`: Encodes a Latin-1 string as UTF-8.
        * `EncodeFromUTF16(span<uint16_t> utf16, std::vector<uint8_t>* out)`: Encodes a UTF-16 string as UTF-8 if it's US-ASCII, otherwise as UTF-16.
        * `EncodeBinary(span<uint8_t> in, std::vector<uint8_t>* out)`: Encodes arbitrary binary data.
        * `EncodeDouble(double value, std::vector<uint8_t>* out)`: Encodes a double-precision floating-point number.

* **`EnvelopeEncoder` and `EnvelopeHeader`:**
    * `EnvelopeEncoder`: A class for wrapping maps and arrays with an envelope that includes their byte length. This allows decoders to efficiently skip over nested structures.
        * `EncodeStart()`: Emits the envelope start bytes.
        * `EncodeStop()`: Records the size of the enclosed content.
    * `EnvelopeHeader`: A class for parsing and representing the envelope header.
        * `Parse()`: Parses the envelope header from a byte span.
        * `ParseFromFragment()`: Parses the envelope header from a partial byte span.
        * Provides methods to access the header size, content size, and total outer size.

* **`NewCBOREncoder`:**
    * `NewCBOREncoder(std::vector<uint8_t>* out, Status* status)`: Creates a `ParserHandler` that can be used to convert streaming parser events into CBOR encoding. This suggests an event-driven approach to encoding.

* **`CBORTokenizer`:**
    * A class for parsing individual CBOR items from a byte stream. It's not a full CBOR parser but provides a way to tokenize a CBOR message.
    * `CBORTokenTag`: An enumeration defining the types of CBOR tokens the tokenizer can identify (e.g., `INT32`, `STRING8`, `MAP_START`, `ENVELOPE`).
    * `MajorType`: An enumeration representing the major types defined in the CBOR specification.
    * Methods:
        * `TokenTag()`: Returns the type of the current token.
        * `Next()`: Advances to the next token.
        * `EnterEnvelope()`: Moves the cursor inside an envelope to explore its contents.
        * `Status()`: Returns the current parsing status (including errors).
        * `GetInt32()`, `GetDouble()`, `GetString8()`, `GetString16WireRep()`, `GetBinary()`, `GetEnvelope()`, `GetEnvelopeContents()`, `GetEnvelopeHeader()`: Methods to retrieve the value of the current token based on its type.

* **`ParseCBOR`:**
    * `ParseCBOR(span<uint8_t> bytes, ParserHandler* out)`: Parses a CBOR-encoded message and sends events to a `ParserHandler`. This is a higher-level function for parsing complete CBOR messages.

* **`AppendString8EntryToCBORMap`:**
    * `AppendString8EntryToCBORMap(span<uint8_t> string8_key, span<uint8_t> string8_value, std::vector<uint8_t>* cbor)`: Provides a utility to append a new key-value pair (both as UTF-8 strings) to an existing CBOR map.

* **`internals` Namespace:**
    * Contains internal functions for reading and writing CBOR token starts, likely used for testing or low-level manipulation.

**Is `v8/third_party/inspector_protocol/crdtp/cbor.h` a Torque Source File?**

No, based on the file extension `.h`, it's a standard C++ header file. Torque source files in V8 typically have the extension `.tq`. The comment block also indicates standard C++ copyright and license.

**Relationship with JavaScript Functionality:**

This code is directly related to JavaScript functionality, specifically in the context of the Chrome DevTools. When the DevTools communicates with the V8 engine (e.g., to get the current state of JavaScript execution, set breakpoints, evaluate expressions), the data exchanged is often serialized using CBOR.

**JavaScript Example:**

Imagine the DevTools wants to get the value of a variable named `myVariable` in the JavaScript context.

1. **DevTools Frontend (JavaScript):** The DevTools UI sends a request to the V8 engine. This request is likely structured as a JSON object which is then converted into a CBOR message using the functionalities defined in this header.

   ```javascript
   // (Conceptual - actual DevTools protocol interaction is more complex)
   const request = {
     method: "Runtime.evaluate",
     params: {
       expression: "myVariable"
     }
   };

   // Assume a function to encode this to CBOR using the C++ logic
   const cborEncodedRequest = encodeToCBOR(request);

   // Send cborEncodedRequest to the V8 engine
   ```

2. **V8 Engine (C++):** The V8 engine receives the CBOR-encoded request. The code defined in `cbor.h` is used to decode this message.

   ```c++
   // Inside the V8 engine, handling the DevTools request:
   std::vector<uint8_t> received_cbor_data = /* ... received CBOR bytes ... */;
   v8_crdtp::cbor::CBORTokenizer tokenizer(received_cbor_data);

   // ... use the tokenizer to parse the request and extract the method and parameters ...
   ```

3. **V8 Engine (C++):** The V8 engine executes the request (evaluates `myVariable`). The result (e.g., the value of `myVariable`) is then encoded back into a CBOR message using the functions in `cbor.h`.

   ```c++
   // ... after evaluating myVariable, let's say its value is a string "hello" ...
   std::vector<uint8_t> cbor_response;
   v8_crdtp::cbor::EncodeIndefiniteLengthMapStart(); // Start an indefinite length map
   // ... encode key for the result property ...
   v8_crdtp::cbor::EncodeString8(v8::StringView("result").as_string_view(), &cbor_response);
   v8_crdtp::cbor::EncodeString8(v8::StringView("hello").as_string_view(), &cbor_response);
   v8_crdtp::cbor::EncodeStop(); // End the map

   // Wrap the map in an envelope
   v8_crdtp::cbor::EnvelopeEncoder envelope_encoder;
   envelope_encoder.EncodeStart(&cbor_response);
   // ... (encode the map content) ...
   envelope_encoder.EncodeStop(&cbor_response);

   // Send cbor_response back to the DevTools
   ```

4. **DevTools Frontend (JavaScript):** The DevTools receives the CBOR-encoded response and decodes it back into a JavaScript object.

   ```javascript
   // Receive the cborEncodedResponse from the V8 engine
   const cborEncodedResponse = /* ... received CBOR bytes ... */;

   // Assume a function to decode this from CBOR using corresponding JavaScript logic
   const response = decodeFromCBOR(cborEncodedResponse);

   console.log(response.result); // Output: "hello"
   ```

**Code Logic Inference (Hypothetical Input and Output):**

**Encoding Example:**

**Input (Conceptual C++ data):**  Representing a simple object `{ "id": 123, "name": "example" }`

```c++
std::vector<uint8_t> cbor_data;
v8_crdtp::cbor::EnvelopeEncoder envelope_encoder;
envelope_encoder.EncodeStart(&cbor_data); // Start the envelope

v8_crdtp::cbor::EncodeIndefiniteLengthMapStart(); // Start an indefinite length map

// Encode "id": 123
v8_crdtp::cbor::EncodeString8(v8::StringView("id").as_string_view(), &cbor_data);
v8_crdtp::cbor::EncodeInt32(123, &cbor_data);

// Encode "name": "example"
v8_crdtp::cbor::EncodeString8(v8::StringView("name").as_string_view(), &cbor_data);
v8_crdtp::cbor::EncodeString8(v8::StringView("example").as_string_view(), &cbor_data);

v8_crdtp::cbor::EncodeStop(); // End the map

envelope_encoder.EncodeStop(&cbor_data); // End the envelope
```

**Output (Hypothetical CBOR byte sequence):** The exact byte sequence depends on the CBOR encoding rules, but it would start with the envelope tag and length, followed by the map start, key-value pairs encoded according to their types, and the map stop and envelope stop markers. It would look something like: `D8 5A 00 00 00 13 BF 62 69 64 7B 64 6E 61 6D 65 67 65 78 61 6D 70 6C 65 FF` (this is a simplified representation, the actual byte sequence would be based on CBOR's variable-length integer encoding).

**Decoding Example:**

**Input (Hypothetical CBOR byte sequence):** Let's take the output from the encoding example.

**Output (Conceptual C++ interpretation using `CBORTokenizer`):**

```c++
std::vector<uint8_t> cbor_bytes = /* ... the hypothetical CBOR byte sequence ... */;
v8_crdtp::cbor::CBORTokenizer tokenizer(cbor_bytes);

if (tokenizer.TokenTag() == v8_crdtp::cbor::CBORTokenTag::ENVELOPE) {
  tokenizer.EnterEnvelope(); // Enter the envelope
  if (tokenizer.TokenTag() == v8_crdtp::cbor::CBORTokenTag::MAP_START) {
    tokenizer.Next(); // Move past MAP_START
    while (tokenizer.TokenTag() != v8_crdtp::cbor::CBORTokenTag::STOP) {
      if (tokenizer.TokenTag() == v8_crdtp::cbor::CBORTokenTag::STRING8) {
        v8::StringView key(reinterpret_cast<const char*>(tokenizer.GetString8().data()), tokenizer.GetString8().size());
        tokenizer.Next();
        if (key == "id" && tokenizer.TokenTag() == v8_crdtp::cbor::CBORTokenTag::INT32) {
          int32_t id = tokenizer.GetInt32();
          // ... process id ...
        } else if (key == "name" && tokenizer.TokenTag() == v8_crdtp::cbor::CBORTokenTag::STRING8) {
          v8::StringView name(reinterpret_cast<const char*>(tokenizer.GetString8().data()), tokenizer.GetString8().size());
          // ... process name ...
        }
      }
      tokenizer.Next();
    }
  }
}
```

**Common Programming Errors:**

1. **Incorrectly Handling Envelopes:** Forgetting to wrap maps and arrays in envelopes or not correctly calculating the length can lead to decoding errors.

   ```c++
   // Error: Forgetting the envelope
   std::vector<uint8_t> cbor_data;
   v8_crdtp::cbor::EncodeIndefiniteLengthMapStart(&cbor_data);
   // ... encode map content ...
   v8_crdtp::cbor::EncodeStop(&cbor_data);

   // Decoding this without expecting an envelope will fail.
   ```

2. **Mismatching Data Types During Encoding/Decoding:** Encoding a value as an integer and trying to decode it as a string will result in errors.

   ```c++
   // Encoding an integer
   std::vector<uint8_t> cbor_data;
   v8_crdtp::cbor::EncodeInt32(123, &cbor_data);

   // Attempting to decode as a string
   v8_crdtp::cbor::CBORTokenizer tokenizer(cbor_data);
   if (tokenizer.TokenTag() == v8_crdtp::cbor::CBORTokenTag::STRING8) { // This condition will be false
       // ...
   }
   ```

3. **Encoding Strings with Incorrect Encoding:** Encoding non-ASCII characters as if they were simple ASCII or using the wrong UTF encoding can lead to garbled text.

   ```c++
   // Error: Treating a UTF-8 string with non-ASCII as Latin-1
   std::string utf8_string = "你好"; // Contains non-ASCII characters
   std::vector<uint8_t> cbor_data;
   v8_crdtp::cbor::EncodeFromLatin1(
       v8::as_bytes(v8::StringView(utf8_string.data(), utf8_string.size())),
       &cbor_data); // This will likely encode incorrectly
   ```

4. **Exceeding the `int32_t` Range for Scalars:**  Trying to encode integer values outside the -2<sup>31</sup> to 2<sup>31</sup> - 1 range will violate the specified constraints.

   ```c++
   // Error: Encoding a value outside the int32_t range
   std::vector<uint8_t> cbor_data;
   v8_crdtp::cbor::EncodeInt32(3000000000LL, &cbor_data); // Likely to cause issues
   ```

5. **Modifying CBOR without Updating Envelope Sizes:** When using functions like `AppendString8EntryToCBORMap`, failing to ensure the envelope size is correctly updated can lead to invalid CBOR messages.

These examples illustrate how the functionalities in `cbor.h` are used and some common pitfalls developers might encounter when working with CBOR encoding and decoding in the context of V8's DevTools protocol.

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/cbor.h的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/cbor.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CRDTP_CBOR_H_
#define V8_CRDTP_CBOR_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "export.h"
#include "parser_handler.h"
#include "span.h"

namespace v8_crdtp {
namespace cbor {
// The binary encoding for the inspector protocol follows the CBOR specification
// (RFC 7049). Additional constraints:
// - Only indefinite length maps and arrays are supported.
// - Maps and arrays are wrapped with an envelope, that is, a
//   CBOR tag with value 24 followed by a byte string specifying
//   the byte length of the enclosed map / array. The byte string
//   must use a 32 bit wide length.
// - At the top level, a message must be an indefinite length map
//   wrapped by an envelope.
// - Maximal size for messages is 2^32 (4 GB).
// - For scalars, we support only the int32_t range, encoded as
//   UNSIGNED/NEGATIVE (major types 0 / 1).
// - UTF16 strings, including with unbalanced surrogate pairs, are encoded
//   as CBOR BYTE_STRING (major type 2). For such strings, the number of
//   bytes encoded must be even.
// - UTF8 strings (major type 3) are supported.
// - 7 bit US-ASCII strings must always be encoded as UTF8 strings, never
//   as UTF16 strings.
// - Arbitrary byte arrays, in the inspector protocol called 'binary',
//   are encoded as BYTE_STRING (major type 2), prefixed with a byte
//   indicating base64 when rendered as JSON.

// =============================================================================
// Detecting CBOR content
// =============================================================================

// Checks whether |msg| is a cbor message.
bool IsCBORMessage(span<uint8_t> msg);

// Performs a leightweight check of |msg|.
// Disallows:
// - Empty message
// - Not starting with the two bytes 0xd8, 0x5a
// - Empty envelope (all length bytes are 0)
// - Not starting with a map after the envelope stanza
// DevTools messages should pass this check.
Status CheckCBORMessage(span<uint8_t> msg);

// =============================================================================
// Encoding individual CBOR items
// =============================================================================

// Some constants for CBOR tokens that only take a single byte on the wire.
uint8_t EncodeTrue();
uint8_t EncodeFalse();
uint8_t EncodeNull();
uint8_t EncodeIndefiniteLengthArrayStart();
uint8_t EncodeIndefiniteLengthMapStart();
uint8_t EncodeStop();

// Encodes |value| as |UNSIGNED| (major type 0) iff >= 0, or |NEGATIVE|
// (major type 1) iff < 0.
void EncodeInt32(int32_t value, std::vector<uint8_t>* out);

// Encodes a UTF16 string as a BYTE_STRING (major type 2). Each utf16
// character in |in| is emitted with most significant byte first,
// appending to |out|.
void EncodeString16(span<uint16_t> in, std::vector<uint8_t>* out);

// Encodes a UTF8 string |in| as STRING (major type 3).
void EncodeString8(span<uint8_t> in, std::vector<uint8_t>* out);

// Encodes the given |latin1| string as STRING8.
// If any non-ASCII character is present, it will be represented
// as a 2 byte UTF8 sequence.
void EncodeFromLatin1(span<uint8_t> latin1, std::vector<uint8_t>* out);

// Encodes the given |utf16| string as STRING8 if it's entirely US-ASCII.
// Otherwise, encodes as STRING16.
void EncodeFromUTF16(span<uint16_t> utf16, std::vector<uint8_t>* out);

// Encodes arbitrary binary data in |in| as a BYTE_STRING (major type 2) with
// definitive length, prefixed with tag 22 indicating expected conversion to
// base64 (see RFC 7049, Table 3 and Section 2.4.4.2).
void EncodeBinary(span<uint8_t> in, std::vector<uint8_t>* out);

// Encodes / decodes a double as Major type 7 (SIMPLE_VALUE),
// with additional info = 27, followed by 8 bytes in big endian.
void EncodeDouble(double value, std::vector<uint8_t>* out);

// =============================================================================
// cbor::EnvelopeEncoder - for wrapping submessages
// =============================================================================

// An envelope indicates the byte length of a wrapped item.
// We use this for maps and array, which allows the decoder
// to skip such (nested) values whole sale.
// It's implemented as a CBOR tag (major type 6) with additional
// info = 24, followed by a byte string with a 32 bit length value;
// so the maximal structure that we can wrap is 2^32 bits long.
// See also: https://tools.ietf.org/html/rfc7049#section-2.4.4.1
class EnvelopeEncoder {
 public:
  // Emits the envelope start bytes and records the position for the
  // byte size in |byte_size_pos_|. Also emits empty bytes for the
  // byte sisze so that encoding can continue.
  void EncodeStart(std::vector<uint8_t>* out);
  // This records the current size in |out| at position byte_size_pos_.
  // Returns true iff successful.
  bool EncodeStop(std::vector<uint8_t>* out);

 private:
  size_t byte_size_pos_ = 0;
};

class EnvelopeHeader {
 public:
  EnvelopeHeader() = default;
  ~EnvelopeHeader() = default;

  // Parse envelope. Implies that `in` accomodates the entire size of envelope.
  static StatusOr<EnvelopeHeader> Parse(span<uint8_t> in);
  // Parse envelope, but allow `in` to only include the beginning of the
  // envelope.
  static StatusOr<EnvelopeHeader> ParseFromFragment(span<uint8_t> in);

  size_t header_size() const { return header_size_; }
  size_t content_size() const { return content_size_; }
  size_t outer_size() const { return header_size_ + content_size_; }

 private:
  EnvelopeHeader(size_t header_size, size_t content_size)
      : header_size_(header_size), content_size_(content_size) {}

  size_t header_size_ = 0;
  size_t content_size_ = 0;
};

// =============================================================================
// cbor::NewCBOREncoder - for encoding from a streaming parser
// =============================================================================

// This can be used to convert to CBOR, by passing the return value to a parser
// that drives it. The handler will encode into |out|, and iff an error occurs
// it will set |status| to an error and clear |out|. Otherwise, |status.ok()|
// will be |true|.
std::unique_ptr<ParserHandler> NewCBOREncoder(std::vector<uint8_t>* out,
                                              Status* status);

// =============================================================================
// cbor::CBORTokenizer - for parsing individual CBOR items
// =============================================================================

// Tags for the tokens within a CBOR message that CBORTokenizer understands.
// Note that this is not the same terminology as the CBOR spec (RFC 7049),
// but rather, our adaptation. For instance, we lump unsigned and signed
// major type into INT32 here (and disallow values outside the int32_t range).
enum class CBORTokenTag {
  // Encountered an error in the structure of the message. Consult
  // status() for details.
  ERROR_VALUE,
  // Booleans and NULL.
  TRUE_VALUE,
  FALSE_VALUE,
  NULL_VALUE,
  // An int32_t (signed 32 bit integer).
  INT32,
  // A double (64 bit floating point).
  DOUBLE,
  // A UTF8 string.
  STRING8,
  // A UTF16 string.
  STRING16,
  // A binary string.
  BINARY,
  // Starts an indefinite length map; after the map start we expect
  // alternating keys and values, followed by STOP.
  MAP_START,
  // Starts an indefinite length array; after the array start we
  // expect values, followed by STOP.
  ARRAY_START,
  // Ends a map or an array.
  STOP,
  // An envelope indicator, wrapping a map or array.
  // Internally this carries the byte length of the wrapped
  // map or array. While CBORTokenizer::Next() will read / skip the entire
  // envelope, CBORTokenizer::EnterEnvelope() reads the tokens
  // inside of it.
  ENVELOPE,
  // We've reached the end there is nothing else to read.
  DONE,
};

// The major types from RFC 7049 Section 2.1.
enum class MajorType {
  UNSIGNED = 0,
  NEGATIVE = 1,
  BYTE_STRING = 2,
  STRING = 3,
  ARRAY = 4,
  MAP = 5,
  TAG = 6,
  SIMPLE_VALUE = 7
};

// CBORTokenizer segments a CBOR message, presenting the tokens therein as
// numbers, strings, etc. This is not a complete CBOR parser, but makes it much
// easier to implement one (e.g. ParseCBOR, above). It can also be used to parse
// messages partially.
class CBORTokenizer {
 public:
  explicit CBORTokenizer(span<uint8_t> bytes);
  ~CBORTokenizer();

  // Identifies the current token that we're looking at,
  // or ERROR_VALUE (in which ase ::Status() has details)
  // or DONE (if we're past the last token).
  CBORTokenTag TokenTag() const;

  // Advances to the next token.
  void Next();
  // Can only be called if TokenTag() == CBORTokenTag::ENVELOPE.
  // While Next() would skip past the entire envelope / what it's
  // wrapping, EnterEnvelope positions the cursor inside of the envelope,
  // letting the client explore the nested structure.
  void EnterEnvelope();

  // If TokenTag() is CBORTokenTag::ERROR_VALUE, then Status().error describes
  // the error more precisely; otherwise it'll be set to Error::OK.
  // In either case, Status().pos is the current position.
  struct Status Status() const;

  // The following methods retrieve the token values. They can only
  // be called if TokenTag() matches.

  // To be called only if ::TokenTag() == CBORTokenTag::INT32.
  int32_t GetInt32() const;

  // To be called only if ::TokenTag() == CBORTokenTag::DOUBLE.
  double GetDouble() const;

  // To be called only if ::TokenTag() == CBORTokenTag::STRING8.
  span<uint8_t> GetString8() const;

  // Wire representation for STRING16 is low byte first (little endian).
  // To be called only if ::TokenTag() == CBORTokenTag::STRING16. The result is
  // guaranteed to have even length.
  span<uint8_t> GetString16WireRep() const;

  // To be called only if ::TokenTag() == CBORTokenTag::BINARY.
  span<uint8_t> GetBinary() const;

  // To be called only if ::TokenTag() == CBORTokenTag::ENVELOPE.
  // Returns the envelope including its payload; message which
  // can be passed to the CBORTokenizer constructor, which will
  // then see the envelope token first (looking at it a second time,
  // basically).
  span<uint8_t> GetEnvelope() const;

  // To be called only if ::TokenTag() == CBORTokenTag::ENVELOPE.
  // Returns only the payload inside the envelope, e.g., a map
  // or an array. This is not a complete message by our
  // IsCBORMessage definition, since it doesn't include the
  // enclosing envelope (the header, basically).
  span<uint8_t> GetEnvelopeContents() const;

  // To be called only if ::TokenTag() == CBORTokenTag::ENVELOPE.
  // Returns the envelope header.
  const EnvelopeHeader& GetEnvelopeHeader() const;

 private:
  void ReadNextToken();
  void SetToken(CBORTokenTag token, size_t token_byte_length);
  void SetError(Error error);

  const span<uint8_t> bytes_;
  CBORTokenTag token_tag_;
  struct Status status_;
  size_t token_byte_length_ = 0;
  MajorType token_start_type_;
  uint64_t token_start_internal_value_;
  EnvelopeHeader envelope_header_;
};

// =============================================================================
// cbor::ParseCBOR - for receiving streaming parser events for CBOR messages
// =============================================================================

// Parses a CBOR encoded message from |bytes|, sending events to
// |out|. If an error occurs, sends |out->HandleError|, and parsing stops.
// The client is responsible for discarding the already received information in
// that case.
void ParseCBOR(span<uint8_t> bytes, ParserHandler* out);

// =============================================================================
// cbor::AppendString8EntryToMap - for limited in-place editing of messages
// =============================================================================

// Modifies the |cbor| message by appending a new key/value entry at the end
// of the map. Patches up the envelope size; Status.ok() iff successful.
// If not successful, |cbor| may be corrupted after this call.
Status AppendString8EntryToCBORMap(span<uint8_t> string8_key,
                                   span<uint8_t> string8_value,
                                   std::vector<uint8_t>* cbor);

namespace internals {  // Exposed only for writing tests.
size_t ReadTokenStart(span<uint8_t> bytes,
                      cbor::MajorType* type,
                      uint64_t* value);

void WriteTokenStart(cbor::MajorType type,
                     uint64_t value,
                     std::vector<uint8_t>* encoded);
}  // namespace internals
}  // namespace cbor
}  // namespace v8_crdtp

#endif  // V8_CRDTP_CBOR_H_
```