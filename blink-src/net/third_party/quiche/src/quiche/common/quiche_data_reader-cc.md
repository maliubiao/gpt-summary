Response:
Let's break down the request and the provided code to construct the answer.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of `quiche_data_reader.cc`. The key points are:

* **Functionality:** What does this code *do*?
* **Relationship to JavaScript:**  Is there any connection? If so, how?
* **Logical Reasoning (with examples):** Illustrate the behavior with input and output.
* **Common Usage Errors (with examples):**  Point out mistakes developers might make.
* **Debugging Context:** How does a user arrive at this code during debugging?

**2. Initial Code Scan and Keyword Identification:**

Quickly looking through the code reveals core functionalities:

* **Reading data:** `ReadUInt8`, `ReadUInt16`, `ReadUInt24`, `ReadUInt32`, `ReadUInt64`, `ReadBytes`, `ReadStringPiece`, `ReadVarInt62`.
* **Tracking position:** `pos_`, `AdvancePos`, `Seek`.
* **Checking boundaries:** `CanRead`, `BytesRemaining`, `IsDoneReading`.
* **Endianness handling:**  `endianness_`, `quiche::NETWORK_BYTE_ORDER`, `quiche::HOST_BYTE_ORDER`, `quiche::QuicheEndian::NetToHost*`.
* **String/view manipulation:** `absl::string_view`.
* **Error handling:** `OnFailure`.

These keywords provide a strong starting point for describing the functionality.

**3. Functionality Breakdown (Iterative Process):**

I will go through each function and describe its purpose:

* **Constructors:** Initialize the reader with data and endianness.
* **`ReadUInt*`:**  Read integer types of various sizes, handling endianness conversion for network byte order. Crucially, the UInt24 case highlights a potential future feature.
* **`ReadBytesToUInt64`:**  Read a specific number of bytes and convert them to a 64-bit integer, considering endianness.
* **`ReadStringPiece*`:** Read strings with length prefixes (8-bit and 16-bit) and without.
* **`ReadAtMost`:** Read up to a certain number of bytes.
* **`ReadTag`:** Reads a 32-bit value (likely for tagging purposes, though not explicitly defined in the code).
* **`ReadDecimal64`:** Reads a string of decimal digits and converts it to a `uint64_t`.
* **`PeekVarInt62Length`:** Determines the length of a variable-length integer *without* consuming the bytes.
* **`ReadVarInt62`:**  Reads a variable-length integer according to RFC 9000. The detailed comments about performance are important.
* **`ReadStringPieceVarInt62` and `ReadStringVarInt62`:** Read strings prefixed by a variable-length integer indicating the length.
* **`ReadRemainingPayload`, `PeekRemainingPayload`, `FullPayload`, `PreviouslyReadPayload`:**  Methods to access different parts of the data.
* **`ReadBytes`:** Reads a specified number of raw bytes.
* **`Seek`:** Advances the reading position.
* **`IsDoneReading`:** Checks if the entire data has been read.
* **`BytesRemaining`:** Returns the number of unread bytes.
* **`TruncateRemaining`:**  Reduces the amount of data that can be read from the current position.
* **`CanRead`:** Checks if enough data is available for a read operation.
* **`OnFailure`:** Marks the reader as failed, preventing further reads.
* **`PeekByte`:** Looks at the next byte without advancing the position.
* **`DebugString`:**  Provides a string representation of the reader's state.

**4. JavaScript Relationship:**

The key here is to understand where this C++ code might interact with JavaScript in a browser context. The most likely scenario is through the network stack and data received over the network.

* **Network Data Parsing:** JavaScript making network requests will receive data in a byte stream. This C++ code is designed to parse that byte stream.
* **QUIC Protocol:** The file path `net/third_party/quiche/src/quiche/common/` strongly suggests involvement with the QUIC protocol, a modern transport protocol used by Chromium.
* **Example:** Imagine JavaScript fetches data using `fetch()`. The browser's network stack (which includes this C++ code) handles the underlying QUIC communication, parsing the incoming data.

**5. Logical Reasoning (Input/Output Examples):**

For each significant function, I need to craft simple examples demonstrating its behavior. Focus on different data types and edge cases.

* **Integers:** Show how different `ReadUInt` functions handle byte order.
* **Strings:** Illustrate `ReadStringPiece` with length prefixes.
* **VarInt:** Demonstrate the variable-length encoding.
* **Failure Cases:** Show scenarios where reads fail (e.g., not enough data).

**6. Common Usage Errors:**

Think about the common pitfalls when working with data readers:

* **Reading beyond the end:** This is a classic buffer overflow scenario.
* **Incorrect length assumptions:**  Assuming a fixed length when a variable length is expected.
* **Endianness mistakes:** Not accounting for network byte order.
* **Forgetting to check return values:** Not verifying if a read operation was successful.

**7. Debugging Context:**

How does a developer end up looking at this code?  Consider the workflow of debugging network issues:

* **Network Inspector:** Observing network requests and responses.
* **Error Messages:** Seeing errors related to data parsing or protocol violations.
* **Source Code Stepping:** Using a debugger to trace the execution flow of the network stack.

**8. Structuring the Answer:**

Organize the information logically:

* **Introduction:** Briefly state the file's purpose.
* **Functionality (Detailed):**  Go through each function with explanations.
* **JavaScript Relationship:** Explain the connection with examples.
* **Logical Reasoning (with examples):** Present clear input/output scenarios.
* **Common Usage Errors (with examples):** Highlight potential mistakes.
* **Debugging Context:** Describe how a user might encounter this code.

**9. Refinement and Review:**

After drafting the answer, review it for clarity, accuracy, and completeness. Ensure the examples are easy to understand and the explanations are concise. Double-check the code snippets and explanations for any errors. For instance, initially I might forget to mention the `QUICHE_BUG` macro, which is important for understanding error handling. Or I might not explicitly connect the `ReadTag` function to potential protocol elements. Reviewing helps catch these omissions.
This C++ source file, `quiche_data_reader.cc`, defines the `QuicheDataReader` class within the Chromium network stack's QUIC implementation (specifically the "quiche" library, a fork of Google's QUIC implementation). Its primary function is to provide a convenient and safe way to read data from a byte array (represented by `absl::string_view` or a raw `char*` and length). It handles endianness and provides methods for reading various data types.

Here's a breakdown of its functionalities:

**Core Functionality: Reading Data from a Buffer**

The `QuicheDataReader` class acts as a stateful reader for a given data buffer. It maintains an internal position (`pos_`) indicating the current read offset. It provides methods to read different data types from the buffer, advancing the internal position accordingly.

* **Constructors:**  Initializes the reader with the data buffer and optionally the endianness (defaulting to network byte order).
* **`ReadUInt8`, `ReadUInt16`, `ReadUInt32`, `ReadUInt64`:** Reads unsigned integers of specific sizes (8, 16, 32, and 64 bits). It handles network byte order to host byte order conversion if necessary.
* **`ReadUInt24`:** Specifically reads a 24-bit unsigned integer (common in some network protocols). Currently, it only supports network byte order.
* **`ReadBytesToUInt64`:** Reads a specified number of bytes (up to 8) and interprets them as an unsigned 64-bit integer, respecting endianness.
* **`ReadStringPiece8`, `ReadStringPiece16`:** Reads a length-prefixed string. The length is read as either an 8-bit or 16-bit unsigned integer, followed by reading that many bytes as a `absl::string_view`.
* **`ReadStringPiece`:** Reads a string of a specified length as a `absl::string_view`.
* **`ReadAtMost`:** Reads up to a specified number of bytes, returning the actual number of bytes read if less are available.
* **`ReadTag`:** Reads a 4-byte value, typically used for identifying data structures or fields in a protocol.
* **`ReadDecimal64`:** Reads a string of decimal digits of a specified length and converts it to a `uint64_t`.
* **`PeekVarInt62Length`:**  Inspects the next byte(s) to determine the length of a variable-length integer (as defined in RFC 9000) without actually reading the integer.
* **`ReadVarInt62`:** Reads a variable-length integer (up to 62 bits) as defined in RFC 9000. This is a common encoding for efficiency in network protocols.
* **`ReadStringPieceVarInt62`:** Reads a length-prefixed string where the length is encoded as a variable-length integer.
* **`ReadStringVarInt62`:** Similar to `ReadStringPieceVarInt62`, but reads the string into a `std::string` object.
* **`ReadRemainingPayload`, `PeekRemainingPayload`:** Returns the unread portion of the buffer as a `absl::string_view`. `ReadRemainingPayload` advances the read position to the end.
* **`FullPayload`, `PreviouslyReadPayload`:** Returns the entire buffer or the portion that has already been read, respectively, as `absl::string_view`.
* **`ReadBytes`:** Reads a specified number of raw bytes into a provided memory location.
* **`Seek`:** Advances the internal read position by a specified number of bytes.
* **`IsDoneReading`:** Returns `true` if the entire buffer has been read.
* **`BytesRemaining`:** Returns the number of bytes remaining to be read.
* **`TruncateRemaining`:**  Reduces the effective length of the buffer from the current position.
* **`CanRead`:** Checks if there are enough bytes remaining to read a specified number of bytes.
* **`OnFailure`:**  Marks the reader as failed and sets the read position to the end of the buffer, ensuring subsequent read attempts fail.
* **`PeekByte`:** Returns the next byte without advancing the read position.
* **`DebugString`:**  Provides a string representation of the reader's internal state (length and current position).

**Relationship to JavaScript Functionality**

`QuicheDataReader` is a C++ class and directly doesn't interact with JavaScript code at the JavaScript language level. However, it plays a crucial role in processing data received by the browser's network stack, which can be triggered by JavaScript.

Here's how it relates:

1. **Network Data Parsing:** When JavaScript makes network requests (e.g., using `fetch` or `XMLHttpRequest`), the browser receives data as a stream of bytes. This C++ code is used within the Chromium network stack to parse and interpret this raw byte stream.

2. **QUIC Protocol:**  The file path `net/third_party/quiche/src/quiche/common/` strongly suggests this code is part of the QUIC protocol implementation. QUIC is a transport layer network protocol used by Chromium for faster and more reliable connections. When a JavaScript application communicates over QUIC, `QuicheDataReader` would be used to read the incoming QUIC packets.

**Example:**

Imagine a JavaScript application fetches a resource from a server using the QUIC protocol.

* **JavaScript Action:**
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => response.json())
     .then(data => console.log(data));
   ```

* **Under the Hood (C++):**
    1. The browser's network stack establishes a QUIC connection with `example.com`.
    2. The server sends data back in QUIC packets.
    3. The Chromium QUIC implementation, which includes `QuicheDataReader`, receives these packets as byte arrays.
    4. `QuicheDataReader` is used to parse the structure of the QUIC packets, extracting headers, payload data, etc. For instance, it might use `ReadVarInt62` to read packet numbers or frame lengths.
    5. Eventually, the actual JSON data in the response body is also read using `QuicheDataReader`. The server might have encoded the JSON data itself in a specific binary format (though typically it's sent as UTF-8 text). If it were a binary format, `QuicheDataReader` would be essential for deserializing it.
    6. The parsed data is then passed up the layers of the network stack until it reaches the JavaScript engine, where the `response.json()` method parses the JSON.

**Logical Reasoning: Assumptions, Inputs, and Outputs**

Let's take the `ReadUInt16` function as an example:

**Function:** `bool QuicheDataReader::ReadUInt16(uint16_t* result)`

**Assumptions:**

* The reader's internal position (`pos_`) is within the bounds of the data buffer.
* There are at least 2 bytes remaining in the buffer starting from `pos_`.
* `result` is a valid pointer to a `uint16_t` variable.

**Hypothetical Input:**

Let's say the `QuicheDataReader` is initialized with the following byte array (in hexadecimal): `0x01 0x02 0x03 0x04` and `pos_` is currently `0`. The `endianness_` is set to `quiche::NETWORK_BYTE_ORDER`.

**Steps:**

1. `ReadBytes` is called internally to read 2 bytes from the buffer into the memory location pointed to by `result`. So, the memory pointed to by `result` now contains `0x01 0x02`.
2. The code checks if `endianness_` is `quiche::NETWORK_BYTE_ORDER`. In this case, it is.
3. `quiche::QuicheEndian::NetToHost16(*result)` is called. This function takes the 16-bit value in network byte order (big-endian: `0x0102`) and converts it to host byte order.
4. Assuming the host system is little-endian, `0x0102` (big-endian) becomes `0x0201` (little-endian).
5. The converted value `0x0201` is assigned back to `*result`.
6. The internal position `pos_` is advanced by 2.

**Output:**

* The function returns `true` (assuming enough bytes were available).
* The variable pointed to by `result` now holds the value `0x0201` (or the decimal equivalent, 513).
* The reader's internal position `pos_` is now `2`.

**User or Programming Common Usage Errors**

1. **Reading Beyond Buffer Boundaries:**
   ```c++
   const char data[] = {0x01, 0x02};
   QuicheDataReader reader(data, sizeof(data));
   uint32_t value;
   if (!reader.ReadUInt32(&value)) {
     // Error: Attempted to read 4 bytes when only 2 were available.
     // OnFailure() will be called, and the reader is now at the end.
   }
   ```

2. **Incorrect Length Assumptions with String Pieces:**
   ```c++
   const char data[] = {0x03, 'a', 'b'}; // Length prefix is 3, but only 2 bytes follow
   QuicheDataReader reader(data, sizeof(data));
   absl::string_view str;
   if (!reader.ReadStringPiece8(&str)) {
     // Error: Tried to read 3 bytes for the string, but only 2 are left.
   }
   ```

3. **Ignoring Return Values:**
   ```c++
   const char data[] = {0x01};
   QuicheDataReader reader(data, sizeof(data));
   uint16_t value;
   reader.ReadUInt16(&value); // Incorrect: Doesn't check the return value
   // value might contain uninitialized or garbage data because ReadUInt16 failed.
   ```

4. **Assuming Host Byte Order when Network Byte Order is Expected:**
   While the class handles this internally, if you were manually parsing data without this class, forgetting about network byte order is a common mistake. This class mitigates this risk by explicitly handling it.

**User Operations Leading to This Code (Debugging Clues)**

As a developer debugging network issues in Chromium, you might end up examining this code in these scenarios:

1. **Debugging QUIC Connection Issues:** If there are problems establishing or maintaining a QUIC connection, you might step through the QUIC implementation code, including `QuicheDataReader`, to see how incoming packets are being parsed.

2. **Analyzing Network Packet Structure:**  When investigating issues related to the format or interpretation of data exchanged over the network (especially with QUIC), you might need to understand how the raw bytes are being read and interpreted. Setting breakpoints within `QuicheDataReader` functions like `ReadVarInt62` or `ReadStringPieceVarInt62` can help.

3. **Investigating Data Corruption or Parsing Errors:** If data received from the network is being misinterpreted or appears corrupted, the issue might lie in how it's being read. You might trace the execution to see if the correct number of bytes are being read and if endianness is handled properly.

4. **Examining Crash Dumps:** If Chromium crashes within the QUIC stack, the stack trace might lead you to functions in `QuicheDataReader`, indicating a potential problem with reading or accessing the data buffer. The `QUICHE_BUG` macro usage in the code is also a clue for unexpected states.

**Steps to Reach this Code During Debugging:**

1. **Identify a Network Issue:** A user reports a website not loading correctly, or there are errors in network communication within the browser.
2. **Open Chromium's Internal Tools (e.g., `net-internals`):**  Inspect network logs and events, looking for errors related to QUIC connections.
3. **Enable QUIC Debug Logging:**  Configure Chromium with specific flags to enable detailed logging of QUIC events.
4. **Attach a Debugger to Chromium:** If the issue is complex, a developer might attach a debugger (like gdb or lldb) to the Chromium process.
5. **Set Breakpoints:** Based on the network logs or the nature of the issue, set breakpoints in relevant QUIC code, potentially including files within the `net/third_party/quiche/src/quiche/common/` directory, such as `quiche_data_reader.cc`.
6. **Reproduce the Issue:**  Perform the user action that triggers the network problem.
7. **Step Through the Code:** When the debugger hits a breakpoint in `QuicheDataReader`, the developer can examine the contents of the data buffer, the current read position (`pos_`), and the values being read. This helps understand how the data is being processed at a low level.
8. **Analyze Call Stack:** The call stack will show the sequence of function calls that led to the execution of `QuicheDataReader` methods, providing context about which part of the network stack is using it.

By understanding the functionality of `QuicheDataReader` and how it's used within the Chromium network stack, developers can effectively debug network-related issues and ensure the correct processing of data received over the network.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/common/quiche_data_reader.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/quiche_data_reader.h"

#include <algorithm>
#include <cstring>
#include <string>

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_endian.h"

namespace quiche {

QuicheDataReader::QuicheDataReader(absl::string_view data)
    : QuicheDataReader(data.data(), data.length(), quiche::NETWORK_BYTE_ORDER) {
}

QuicheDataReader::QuicheDataReader(const char* data, const size_t len)
    : QuicheDataReader(data, len, quiche::NETWORK_BYTE_ORDER) {}

QuicheDataReader::QuicheDataReader(const char* data, const size_t len,
                                   quiche::Endianness endianness)
    : data_(data), len_(len), pos_(0), endianness_(endianness) {}

bool QuicheDataReader::ReadUInt8(uint8_t* result) {
  return ReadBytes(result, sizeof(*result));
}

bool QuicheDataReader::ReadUInt16(uint16_t* result) {
  if (!ReadBytes(result, sizeof(*result))) {
    return false;
  }
  if (endianness_ == quiche::NETWORK_BYTE_ORDER) {
    *result = quiche::QuicheEndian::NetToHost16(*result);
  }
  return true;
}

bool QuicheDataReader::ReadUInt24(uint32_t* result) {
  if (endianness_ != quiche::NETWORK_BYTE_ORDER) {
    // TODO(b/214573190): Implement and test HOST_BYTE_ORDER case.
    QUICHE_BUG(QuicheDataReader_ReadUInt24_NotImplemented);
    return false;
  }

  *result = 0;
  if (!ReadBytes(reinterpret_cast<char*>(result) + 1, 3u)) {
    return false;
  }
  *result = quiche::QuicheEndian::NetToHost32(*result);
  return true;
}

bool QuicheDataReader::ReadUInt32(uint32_t* result) {
  if (!ReadBytes(result, sizeof(*result))) {
    return false;
  }
  if (endianness_ == quiche::NETWORK_BYTE_ORDER) {
    *result = quiche::QuicheEndian::NetToHost32(*result);
  }
  return true;
}

bool QuicheDataReader::ReadUInt64(uint64_t* result) {
  if (!ReadBytes(result, sizeof(*result))) {
    return false;
  }
  if (endianness_ == quiche::NETWORK_BYTE_ORDER) {
    *result = quiche::QuicheEndian::NetToHost64(*result);
  }
  return true;
}

bool QuicheDataReader::ReadBytesToUInt64(size_t num_bytes, uint64_t* result) {
  *result = 0u;
  if (num_bytes > sizeof(*result)) {
    return false;
  }
  if (endianness_ == quiche::HOST_BYTE_ORDER) {
    return ReadBytes(result, num_bytes);
  }

  if (!ReadBytes(reinterpret_cast<char*>(result) + sizeof(*result) - num_bytes,
                 num_bytes)) {
    return false;
  }
  *result = quiche::QuicheEndian::NetToHost64(*result);
  return true;
}

bool QuicheDataReader::ReadStringPiece16(absl::string_view* result) {
  // Read resultant length.
  uint16_t result_len;
  if (!ReadUInt16(&result_len)) {
    // OnFailure() already called.
    return false;
  }

  return ReadStringPiece(result, result_len);
}

bool QuicheDataReader::ReadStringPiece8(absl::string_view* result) {
  // Read resultant length.
  uint8_t result_len;
  if (!ReadUInt8(&result_len)) {
    // OnFailure() already called.
    return false;
  }

  return ReadStringPiece(result, result_len);
}

bool QuicheDataReader::ReadStringPiece(absl::string_view* result, size_t size) {
  // Make sure that we have enough data to read.
  if (!CanRead(size)) {
    OnFailure();
    return false;
  }

  // Set result.
  *result = absl::string_view(data_ + pos_, size);

  // Iterate.
  pos_ += size;

  return true;
}

absl::string_view QuicheDataReader::ReadAtMost(size_t size) {
  size_t actual_size = std::min(size, BytesRemaining());
  absl::string_view result = absl::string_view(data_ + pos_, actual_size);
  AdvancePos(actual_size);
  return result;
}

bool QuicheDataReader::ReadTag(uint32_t* tag) {
  return ReadBytes(tag, sizeof(*tag));
}

bool QuicheDataReader::ReadDecimal64(size_t num_digits, uint64_t* result) {
  absl::string_view digits;
  if (!ReadStringPiece(&digits, num_digits)) {
    return false;
  }

  return absl::SimpleAtoi(digits, result);
}

QuicheVariableLengthIntegerLength QuicheDataReader::PeekVarInt62Length() {
  QUICHE_DCHECK_EQ(endianness(), NETWORK_BYTE_ORDER);
  const unsigned char* next =
      reinterpret_cast<const unsigned char*>(data() + pos());
  if (BytesRemaining() == 0) {
    return VARIABLE_LENGTH_INTEGER_LENGTH_0;
  }
  return static_cast<QuicheVariableLengthIntegerLength>(
      1 << ((*next & 0b11000000) >> 6));
}

// Read an RFC 9000 62-bit Variable Length Integer.
//
// Performance notes
//
// Measurements and experiments showed that unrolling the four cases
// like this and dereferencing next_ as we do (*(next_+n) --- and then
// doing a single pos_+=x at the end) gains about 10% over making a
// loop and dereferencing next_ such as *(next_++)
//
// Using a register for pos_ was not helpful.
//
// Branches are ordered to increase the likelihood of the first being
// taken.
//
// Low-level optimization is useful here because this function will be
// called frequently, leading to outsize benefits.
bool QuicheDataReader::ReadVarInt62(uint64_t* result) {
  QUICHE_DCHECK_EQ(endianness(), quiche::NETWORK_BYTE_ORDER);

  size_t remaining = BytesRemaining();
  const unsigned char* next =
      reinterpret_cast<const unsigned char*>(data() + pos());
  if (remaining != 0) {
    switch (*next & 0xc0) {
      case 0xc0:
        // Leading 0b11...... is 8 byte encoding
        if (remaining >= 8) {
          *result = (static_cast<uint64_t>((*(next)) & 0x3f) << 56) +
                    (static_cast<uint64_t>(*(next + 1)) << 48) +
                    (static_cast<uint64_t>(*(next + 2)) << 40) +
                    (static_cast<uint64_t>(*(next + 3)) << 32) +
                    (static_cast<uint64_t>(*(next + 4)) << 24) +
                    (static_cast<uint64_t>(*(next + 5)) << 16) +
                    (static_cast<uint64_t>(*(next + 6)) << 8) +
                    (static_cast<uint64_t>(*(next + 7)) << 0);
          AdvancePos(8);
          return true;
        }
        return false;

      case 0x80:
        // Leading 0b10...... is 4 byte encoding
        if (remaining >= 4) {
          *result = (((*(next)) & 0x3f) << 24) + (((*(next + 1)) << 16)) +
                    (((*(next + 2)) << 8)) + (((*(next + 3)) << 0));
          AdvancePos(4);
          return true;
        }
        return false;

      case 0x40:
        // Leading 0b01...... is 2 byte encoding
        if (remaining >= 2) {
          *result = (((*(next)) & 0x3f) << 8) + (*(next + 1));
          AdvancePos(2);
          return true;
        }
        return false;

      case 0x00:
        // Leading 0b00...... is 1 byte encoding
        *result = (*next) & 0x3f;
        AdvancePos(1);
        return true;
    }
  }
  return false;
}

bool QuicheDataReader::ReadStringPieceVarInt62(absl::string_view* result) {
  uint64_t result_length;
  if (!ReadVarInt62(&result_length)) {
    return false;
  }
  return ReadStringPiece(result, result_length);
}

bool QuicheDataReader::ReadStringVarInt62(std::string& result) {
  absl::string_view result_view;
  bool success = ReadStringPieceVarInt62(&result_view);
  result = std::string(result_view);
  return success;
}

absl::string_view QuicheDataReader::ReadRemainingPayload() {
  absl::string_view payload = PeekRemainingPayload();
  pos_ = len_;
  return payload;
}

absl::string_view QuicheDataReader::PeekRemainingPayload() const {
  return absl::string_view(data_ + pos_, len_ - pos_);
}

absl::string_view QuicheDataReader::FullPayload() const {
  return absl::string_view(data_, len_);
}

absl::string_view QuicheDataReader::PreviouslyReadPayload() const {
  return absl::string_view(data_, pos_);
}

bool QuicheDataReader::ReadBytes(void* result, size_t size) {
  // Make sure that we have enough data to read.
  if (!CanRead(size)) {
    OnFailure();
    return false;
  }

  // Read into result.
  memcpy(result, data_ + pos_, size);

  // Iterate.
  pos_ += size;

  return true;
}

bool QuicheDataReader::Seek(size_t size) {
  if (!CanRead(size)) {
    OnFailure();
    return false;
  }
  pos_ += size;
  return true;
}

bool QuicheDataReader::IsDoneReading() const { return len_ == pos_; }

size_t QuicheDataReader::BytesRemaining() const {
  if (pos_ > len_) {
    QUICHE_BUG(quiche_reader_pos_out_of_bound)
        << "QUIC reader pos out of bound: " << pos_ << ", len: " << len_;
    return 0;
  }
  return len_ - pos_;
}

bool QuicheDataReader::TruncateRemaining(size_t truncation_length) {
  if (truncation_length > BytesRemaining()) {
    return false;
  }
  len_ = pos_ + truncation_length;
  return true;
}

bool QuicheDataReader::CanRead(size_t bytes) const {
  return bytes <= (len_ - pos_);
}

void QuicheDataReader::OnFailure() {
  // Set our iterator to the end of the buffer so that further reads fail
  // immediately.
  pos_ = len_;
}

uint8_t QuicheDataReader::PeekByte() const {
  if (pos_ >= len_) {
    QUICHE_LOG(FATAL)
        << "Reading is done, cannot peek next byte. Tried to read pos = "
        << pos_ << " buffer length = " << len_;
    return 0;
  }
  return data_[pos_];
}

std::string QuicheDataReader::DebugString() const {
  return absl::StrCat(" { length: ", len_, ", position: ", pos_, " }");
}

#undef ENDPOINT  // undef for jumbo builds
}  // namespace quiche

"""

```