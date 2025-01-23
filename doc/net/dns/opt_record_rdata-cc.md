Response:
Let's break down the thought process for analyzing this C++ code and fulfilling the request.

1. **Understand the Core Task:** The request asks for an analysis of the `net/dns/opt_record_rdata.cc` file. The key is to understand its purpose, its relationship (if any) to JavaScript, and common usage errors, along with debugging hints.

2. **Initial Code Scan and Keyword Spotting:**  Quickly read through the code, looking for important keywords and patterns. Things that stand out:
    * `#include`:  Indicates dependencies and the general area of functionality (networking, DNS).
    * `namespace net`: Confirms it's part of the Chromium networking stack.
    * `OptRecordRdata`, `Opt`, `EdeOpt`, `PaddingOpt`, `UnknownOpt`: These are clearly the main classes being defined, suggesting this file deals with parsing and representing DNS OPT records.
    * `kOptCode`, `kEdnsPadding`, `kEdnsExtendedDnsError`:  These are constants likely related to specific OPT record types.
    * `SerializeEdeOpt`, `Create`, `AddOpt`: These are methods indicating actions performed on these OPT records.
    * `base::SpanReader`, `base::SpanWriter`, `base::as_byte_span`, `base::WriteU16BigEndian`: These suggest the code is involved in reading and writing binary data in a specific format (big-endian).
    * The numerous `EdeInfoCode` enum members clearly relate to Extended DNS Errors.

3. **Identify the Primary Functionality:** Based on the keywords and class names, it becomes clear that `opt_record_rdata.cc` is responsible for:
    * **Parsing DNS OPT records:** The `Create` method and the internal parsing logic within it are the core of this. It takes raw byte data and turns it into structured `Opt` objects.
    * **Representing different OPT record types:** The subclasses `EdeOpt`, `PaddingOpt`, and `UnknownOpt` handle specific OPT codes, while the base `Opt` class provides a common interface.
    * **Serializing OPT records:** The `AddOpt` method and `SerializeEdeOpt` function suggest the ability to construct or modify OPT records and convert them back into byte sequences.
    * **Handling Extended DNS Errors (EDE):** The `EdeOpt` class specifically deals with parsing and representing EDE options within OPT records.
    * **Handling Padding Options:** The `PaddingOpt` class handles padding.
    * **Handling Unknown Options:** The `UnknownOpt` class provides a way to represent OPT records with codes that are not specifically handled.

4. **Analyze the Relationship with JavaScript:**  Consider how DNS and networking interact with JavaScript in a browser. JavaScript directly doesn't parse raw DNS packets. However:
    * **Indirect Relationship:** JavaScript uses browser APIs (like `fetch`, `XMLHttpRequest`, `navigator.connection`) that rely on the underlying network stack, including DNS resolution.
    * **No Direct API Mapping:** There's no direct JavaScript API that exposes the internal structure of OPT records. JavaScript deals with higher-level concepts like network requests and responses.
    * **Example:**  If a DNS query with an EDE OPT record is received, the information in `EdeOpt` might indirectly influence how the browser handles the response (e.g., error messages, retries). The *effect* of this processing might be observable in JavaScript (e.g., a fetch failing with a specific error code), but the parsing within `opt_record_rdata.cc` is hidden.

5. **Develop Hypothetical Input/Output Scenarios:** Create simple examples to illustrate the parsing logic:
    * **Padding OPT:** A sequence of bytes representing a Padding OPT record. The output would be a `PaddingOpt` object containing the padding data.
    * **EDE OPT:** Bytes representing an EDE OPT record with a specific info code and extra text. The output would be an `EdeOpt` object with the extracted info code and text.
    * **Unknown OPT:** Bytes for an OPT record with an unrecognized code. The output would be an `UnknownOpt` object storing the code and data.
    * **Invalid Input:**  Malformed byte sequences to demonstrate error handling (returning `nullptr`).

6. **Identify Potential User/Programming Errors:** Think about how developers might interact with or misuse DNS configurations:
    * **Incorrect OPT Record Formatting:**  Manually constructing DNS packets with malformed OPT records. The code would likely fail to parse these.
    * **Unexpected OPT Codes:**  Encountering OPT codes that the browser doesn't fully understand. The `UnknownOpt` class is designed to handle this gracefully, but developers might need to be aware that not all OPT records are interpreted.
    * **Server-Side Configuration Errors:** Incorrectly configured DNS servers might send unexpected OPT records, leading to parsing errors or unexpected behavior.

7. **Trace User Actions to Reach the Code:** Consider the steps a user takes that might lead to this code being executed:
    * **Basic Web Browsing:**  Every time a user visits a website, DNS resolution occurs, potentially involving OPT records.
    * **Specific DNS-Related Features:**  Features like DNS over HTTPS (DoH) or DNS over TLS (DoT) might involve more complex DNS interactions, increasing the likelihood of encountering different OPT records.
    * **Troubleshooting Network Issues:**  If a user experiences DNS resolution problems, developers might use network analysis tools (like Wireshark) that capture DNS traffic, revealing the OPT records being exchanged. This then might lead a developer to examine the browser's DNS handling code.

8. **Structure the Output:** Organize the analysis into clear sections, addressing each part of the request: functionality, JavaScript relationship, input/output examples, common errors, and debugging. Use clear and concise language.

9. **Refine and Review:**  Read through the analysis to ensure accuracy, completeness, and clarity. Double-check the code snippets and examples. Ensure the explanation of the JavaScript relationship is nuanced and avoids overstating direct interaction.

This systematic approach, combining code analysis, domain knowledge (DNS and networking), and logical reasoning, helps in generating a comprehensive and accurate response to the request.
The file `net/dns/opt_record_rdata.cc` in the Chromium network stack is responsible for **parsing, representing, and manipulating the RDATA (Resource Data) of OPT (OPTional) DNS records**.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Parsing OPT Record RDATA:**
   - The primary function is to take a raw byte sequence representing the RDATA of an OPT record and parse it into a structured object (`OptRecordRdata`).
   - It iterates through the byte sequence, identifying individual options based on their code and length.
   - It uses `base::SpanReader` to efficiently read data from the byte span.

2. **Representing OPT Record Options:**
   - It defines a base class `OptRecordRdata::Opt` to represent individual options within the OPT record.
   - It provides specialized subclasses for known OPT codes:
     - `OptRecordRdata::PaddingOpt`: Represents the Padding option (EDNS padding).
     - `OptRecordRdata::EdeOpt`: Represents the Extended DNS Error (EDE) option.
     - `OptRecordRdata::UnknownOpt`: Represents options with unknown or unhandled codes.
   - Each subclass stores the data associated with the specific option type.

3. **Serializing OPT Record RDATA:**
   - The `AddOpt` method allows adding new options to an existing `OptRecordRdata` object.
   - It serializes the added option into the internal buffer (`buf_`).
   - It uses `base::SpanWriter` to efficiently write data to the byte span.

4. **Accessing and Querying Options:**
   - Provides methods to retrieve the parsed options:
     - `GetOpts()`: Returns a vector of all parsed options.
     - `GetPaddingOpts()`: Returns a vector of all Padding options.
     - `GetEdeOpts()`: Returns a vector of all EDE options.
     - `ContainsOptCode()`: Checks if a specific option code is present.

5. **Handling Extended DNS Errors (EDE):**
   - The `EdeOpt` class specifically handles the parsing and representation of EDE options.
   - It extracts the "Info Code" and "Extra Text" from the EDE option data.
   - It provides an enum `EdeOpt::EdeInfoCode` to represent the standardized EDE error codes, making it easier to work with these errors programmatically.

**Relationship with JavaScript:**

This C++ code has an **indirect** relationship with JavaScript functionality in a web browser. JavaScript running in a web page doesn't directly interact with this specific C++ code. However, the functionality provided by this code is crucial for the browser's network stack and how it handles DNS resolution, which in turn affects JavaScript's ability to load resources and communicate with servers.

Here's how they are related:

- **DNS Resolution:** When a JavaScript application (e.g., using `fetch()` or `XMLHttpRequest`) tries to access a resource on a domain name, the browser needs to perform DNS resolution to find the IP address of the server.
- **EDNS and OPT Records:** The browser often sends DNS queries with EDNS (Extension mechanisms for DNS) enabled. OPT records are used within EDNS to convey additional information or request specific features from the DNS server.
- **Extended DNS Errors (EDE):** If a DNS server encounters an error while processing a query, it can include an EDE option in the response's OPT record. This provides more detailed information about the error than standard DNS response codes.
- **Browser's Network Stack:** The C++ code in `opt_record_rdata.cc` is part of the browser's network stack. It's responsible for parsing the OPT records in DNS responses, including EDE options.
- **Impact on JavaScript:** While JavaScript doesn't directly see the parsed OPT record data, the *outcome* of the DNS resolution process, including any errors signaled by EDE, can affect how the browser handles the network request initiated by the JavaScript code. For instance, if an EDE indicates a DNSSEC validation failure, the browser might refuse to connect, and the `fetch()` call in JavaScript would likely reject with an error.

**Example:**

Imagine a scenario where a website uses DNSSEC, and a misconfigured DNS server returns an EDE with the `kDnssecBogus` (DNSSEC Bogus) error code.

1. **JavaScript `fetch()`:** Your JavaScript code executes `fetch('https://example.com')`.
2. **DNS Query with EDNS:** The browser sends a DNS query for `example.com` with an OPT record indicating it supports EDNS.
3. **DNS Response with EDE:** The misconfigured DNS server responds with an OPT record containing an `EdeOpt` with `info_code_` set to the value corresponding to `kDnssecBogus`.
4. **`opt_record_rdata.cc` Parsing:** The code in `opt_record_rdata.cc` parses this OPT record and creates an `EdeOpt` object.
5. **Network Stack Processing:** The browser's network stack uses this information to determine that the DNSSEC validation failed.
6. **`fetch()` Rejection:** The `fetch()` promise in your JavaScript code will be rejected, possibly with a network error indicating a DNS issue. The specific error message might not directly expose the EDE details, but the underlying reason for the failure is due to the information parsed by this C++ code.

**Hypothetical Input and Output:**

**Scenario 1: Parsing a Padding Option**

* **Input (raw bytes):** `00 0c 00 04 aa bb cc dd` (Option Code: 12 (Padding), Length: 4, Padding Data: aa bb cc dd)
* **Processing:** The `Create` method will parse this. It will identify the option code as `dns_protocol::kEdnsPadding`.
* **Output:** An `OptRecordRdata` object containing a single `PaddingOpt` object. The `PaddingOpt` object's `data()` would be the string `"\xaa\xbb\xcc\xdd"`.

**Scenario 2: Parsing an EDE Option**

* **Input (raw bytes):** `00 12 00 07 00 0a 55 54 46 2d 38` (Option Code: 18 (Extended DNS Error), Length: 7, Info Code: 10, Extra Text: UTF-8)
* **Processing:** The `Create` method will parse this. It will identify the option code as `dns_protocol::kEdnsExtendedDnsError`. The `EdeOpt::Create` method will be called.
* **Output:** An `OptRecordRdata` object containing a single `EdeOpt` object. The `EdeOpt` object would have:
    - `info_code_`: 10 (corresponding to `EdeInfoCode::kRrsigsMissing`)
    - `extra_text_`: "UTF-8"

**Scenario 3: Parsing an Unknown Option**

* **Input (raw bytes):** `12 34 00 02 01 02` (Option Code: 0x1234 (Unknown), Length: 2, Data: 01 02)
* **Processing:** The `Create` method will parse this. It won't find a specific handler for option code `0x1234`.
* **Output:** An `OptRecordRdata` object containing a single `UnknownOpt` object. The `UnknownOpt` object would have:
    - `code_`: 0x1234
    - The base `Opt`'s `data()` would be `"\x01\x02"`.

**User or Programming Common Usage Errors:**

1. **Incorrectly Formatting OPT Record Data:** If you are manually constructing DNS packets (e.g., for testing or specialized network tools), you might incorrectly format the OPT record RDATA. This could lead to parsing failures in the browser's network stack, although users typically don't construct raw DNS packets directly.
   - **Example:** Providing an incorrect length for an option, or not adhering to the specific format of an EDE option. The `Create` method might return `nullptr` in such cases.

2. **Assuming Specific OPT Codes are Always Present:** Developers working on network-related features within Chromium might make assumptions about the presence or absence of specific OPT codes in DNS responses. However, DNS servers can implement different sets of EDNS options.
   - **Example:** Code that directly tries to access an `EdeOpt` without first checking if an EDE option exists using `ContainsOptCode(dns_protocol::kEdnsExtendedDnsError)`.

3. **Misinterpreting EDE Info Codes:**  While the `EdeOpt::EdeInfoCode` enum provides a standardized set of error codes, it's important to correctly interpret their meaning in the context of DNS resolution and potential security implications.

**User Operation Steps to Reach Here (Debugging Clues):**

As an end-user, you wouldn't directly interact with this C++ code. However, as a developer debugging network issues, you might encounter this code in the following scenarios:

1. **Investigating DNS Resolution Failures:**
   - A user reports a website is not loading.
   - As a developer, you use network debugging tools (like Chrome DevTools' Network tab or Wireshark) to inspect the DNS queries and responses.
   - You notice a DNS response with an OPT record containing an EDE option indicating an error (e.g., DNSSEC validation failed).
   - To understand how the browser is interpreting this error, you might examine the code in `opt_record_rdata.cc` to see how the EDE option is parsed and what error codes are recognized.

2. **Debugging DNS over HTTPS (DoH) or DNS over TLS (DoT) Implementations:**
   - If you're working on the browser's implementation of secure DNS protocols, you'll be dealing with DNS messages that often include OPT records.
   - You might step through the code in `opt_record_rdata.cc` to ensure that OPT records are being parsed correctly in the context of DoH/DoT.

3. **Analyzing Network Security Issues:**
   - If you're investigating potential DNS-related security vulnerabilities or attacks, you might need to understand how the browser handles different types of OPT records, including those that might be used maliciously.

**Debugging Steps:**

1. **Set Breakpoints:** If you have the Chromium source code and are debugging the browser, you can set breakpoints in `opt_record_rdata.cc`, particularly in the `Create` method or the constructors of the `Opt` subclasses.
2. **Inspect DNS Traffic:** Use network sniffing tools like Wireshark to capture the raw DNS packets being exchanged. This allows you to see the exact byte sequence of the OPT record RDATA.
3. **Examine Logging:** Look for relevant logging output from the Chromium network stack related to DNS resolution and EDNS. There might be logs indicating the parsing of OPT records and any encountered errors.
4. **Test with Different DNS Servers:** If you suspect issues with specific OPT records, try using different DNS servers (e.g., Google Public DNS, Cloudflare DNS) to see if the behavior changes. This can help isolate whether the problem is with the browser's parsing or the DNS server's responses.

In summary, `net/dns/opt_record_rdata.cc` is a crucial component for handling the extensible nature of the DNS protocol, particularly the EDNS mechanism. It plays a vital role in ensuring the browser can correctly interpret and react to various extensions and error conditions signaled through OPT records, ultimately impacting the reliability and security of web browsing.

### 提示词
```
这是目录为net/dns/opt_record_rdata.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/opt_record_rdata.h"

#include <algorithm>
#include <memory>
#include <numeric>
#include <string_view>
#include <utility>

#include "base/big_endian.h"
#include "base/check_is_test.h"
#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/containers/span_reader.h"
#include "base/containers/span_writer.h"
#include "base/memory/ptr_util.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_util.h"
#include "base/types/optional_util.h"
#include "net/dns/public/dns_protocol.h"

namespace net {

namespace {
std::string SerializeEdeOpt(uint16_t info_code, std::string_view extra_text) {
  std::string buf(2 + extra_text.size(), '\0');

  auto writer = base::SpanWriter(base::as_writable_byte_span(buf));
  CHECK(writer.WriteU16BigEndian(info_code));
  CHECK(writer.Write(base::as_byte_span(extra_text)));
  CHECK_EQ(writer.remaining(), 0u);
  return buf;
}
}  // namespace

OptRecordRdata::Opt::Opt(std::string data) : data_(std::move(data)) {}

bool OptRecordRdata::Opt::operator==(const OptRecordRdata::Opt& other) const {
  return IsEqual(other);
}

bool OptRecordRdata::Opt::operator!=(const OptRecordRdata::Opt& other) const {
  return !IsEqual(other);
}

bool OptRecordRdata::Opt::IsEqual(const OptRecordRdata::Opt& other) const {
  return GetCode() == other.GetCode() && data() == other.data();
}

OptRecordRdata::EdeOpt::EdeOpt(uint16_t info_code, std::string extra_text)
    : Opt(SerializeEdeOpt(info_code, extra_text)),
      info_code_(info_code),
      extra_text_(std::move(extra_text)) {
  CHECK(base::IsStringUTF8(extra_text_));
}

OptRecordRdata::EdeOpt::~EdeOpt() = default;

std::unique_ptr<OptRecordRdata::EdeOpt> OptRecordRdata::EdeOpt::Create(
    std::string data) {
  uint16_t info_code;
  auto edeReader = base::SpanReader(base::as_byte_span(data));

  // size must be at least 2: info_code + optional extra_text
  base::span<const uint8_t> extra_text;
  if (!edeReader.ReadU16BigEndian(info_code) ||
      !base::OptionalUnwrapTo(edeReader.Read(edeReader.remaining()),
                              extra_text)) {
    return nullptr;
  }

  if (!base::IsStringUTF8(base::as_string_view(extra_text))) {
    return nullptr;
  }

  return std::make_unique<EdeOpt>(
      info_code, std::string(base::as_string_view(extra_text)));
}

uint16_t OptRecordRdata::EdeOpt::GetCode() const {
  return EdeOpt::kOptCode;
}

OptRecordRdata::EdeOpt::EdeInfoCode
OptRecordRdata::EdeOpt::GetEnumFromInfoCode() const {
  return GetEnumFromInfoCode(info_code_);
}

OptRecordRdata::EdeOpt::EdeInfoCode OptRecordRdata::EdeOpt::GetEnumFromInfoCode(
    uint16_t info_code) {
  switch (info_code) {
    case 0:
      return EdeInfoCode::kOtherError;
    case 1:
      return EdeInfoCode::kUnsupportedDnskeyAlgorithm;
    case 2:
      return EdeInfoCode::kUnsupportedDsDigestType;
    case 3:
      return EdeInfoCode::kStaleAnswer;
    case 4:
      return EdeInfoCode::kForgedAnswer;
    case 5:
      return EdeInfoCode::kDnssecIndeterminate;
    case 6:
      return EdeInfoCode::kDnssecBogus;
    case 7:
      return EdeInfoCode::kSignatureExpired;
    case 8:
      return EdeInfoCode::kSignatureNotYetValid;
    case 9:
      return EdeInfoCode::kDnskeyMissing;
    case 10:
      return EdeInfoCode::kRrsigsMissing;
    case 11:
      return EdeInfoCode::kNoZoneKeyBitSet;
    case 12:
      return EdeInfoCode::kNsecMissing;
    case 13:
      return EdeInfoCode::kCachedError;
    case 14:
      return EdeInfoCode::kNotReady;
    case 15:
      return EdeInfoCode::kBlocked;
    case 16:
      return EdeInfoCode::kCensored;
    case 17:
      return EdeInfoCode::kFiltered;
    case 18:
      return EdeInfoCode::kProhibited;
    case 19:
      return EdeInfoCode::kStaleNxdomainAnswer;
    case 20:
      return EdeInfoCode::kNotAuthoritative;
    case 21:
      return EdeInfoCode::kNotSupported;
    case 22:
      return EdeInfoCode::kNoReachableAuthority;
    case 23:
      return EdeInfoCode::kNetworkError;
    case 24:
      return EdeInfoCode::kInvalidData;
    case 25:
      return EdeInfoCode::kSignatureExpiredBeforeValid;
    case 26:
      return EdeInfoCode::kTooEarly;
    case 27:
      return EdeInfoCode::kUnsupportedNsec3IterationsValue;
    default:
      return EdeInfoCode::kUnrecognizedErrorCode;
  }
}

OptRecordRdata::PaddingOpt::PaddingOpt(std::string padding)
    : Opt(std::move(padding)) {}

OptRecordRdata::PaddingOpt::PaddingOpt(uint16_t padding_len)
    : Opt(std::string(base::checked_cast<size_t>(padding_len), '\0')) {}

OptRecordRdata::PaddingOpt::~PaddingOpt() = default;

uint16_t OptRecordRdata::PaddingOpt::GetCode() const {
  return PaddingOpt::kOptCode;
}

OptRecordRdata::UnknownOpt::~UnknownOpt() = default;

std::unique_ptr<OptRecordRdata::UnknownOpt>
OptRecordRdata::UnknownOpt::CreateForTesting(uint16_t code, std::string data) {
  CHECK_IS_TEST();
  return base::WrapUnique(
      new OptRecordRdata::UnknownOpt(code, std::move(data)));
}

OptRecordRdata::UnknownOpt::UnknownOpt(uint16_t code, std::string data)
    : Opt(std::move(data)), code_(code) {
  CHECK(!base::Contains(kOptsWithDedicatedClasses, code));
}

uint16_t OptRecordRdata::UnknownOpt::GetCode() const {
  return code_;
}

OptRecordRdata::OptRecordRdata() = default;

OptRecordRdata::~OptRecordRdata() = default;

bool OptRecordRdata::operator==(const OptRecordRdata& other) const {
  return IsEqual(&other);
}

bool OptRecordRdata::operator!=(const OptRecordRdata& other) const {
  return !IsEqual(&other);
}

// static
std::unique_ptr<OptRecordRdata> OptRecordRdata::Create(std::string_view data) {
  auto rdata = std::make_unique<OptRecordRdata>();
  rdata->buf_.assign(data.begin(), data.end());

  auto reader = base::SpanReader(base::as_byte_span(data));
  while (reader.remaining() > 0u) {
    uint16_t opt_code, opt_data_size;
    base::span<const uint8_t> opt_data;

    if (!reader.ReadU16BigEndian(opt_code) ||
        !reader.ReadU16BigEndian(opt_data_size) ||
        !base::OptionalUnwrapTo(reader.Read(opt_data_size), opt_data)) {
      return nullptr;
    }

    // After the Opt object has been parsed, parse the contents (the data)
    // depending on the opt_code. The specific Opt subclasses all inherit from
    // Opt. If an opt code does not have a matching Opt subclass, a simple Opt
    // object will be created, and data won't be parsed.

    std::unique_ptr<Opt> opt;

    switch (opt_code) {
      case dns_protocol::kEdnsPadding:
        opt = std::make_unique<OptRecordRdata::PaddingOpt>(
            std::string(base::as_string_view(opt_data)));
        break;
      case dns_protocol::kEdnsExtendedDnsError:
        opt = OptRecordRdata::EdeOpt::Create(
            std::string(base::as_string_view(opt_data)));
        break;
      default:
        opt = base::WrapUnique(new OptRecordRdata::UnknownOpt(
            opt_code, std::string(base::as_string_view(opt_data))));
        break;
    }

    // Confirm that opt is not null, which would be the result of a failed
    // parse.
    if (!opt) {
      return nullptr;
    }

    rdata->opts_.emplace(opt_code, std::move(opt));
  }

  return rdata;
}

uint16_t OptRecordRdata::Type() const {
  return OptRecordRdata::kType;
}

bool OptRecordRdata::IsEqual(const RecordRdata* other) const {
  if (other->Type() != Type()) {
    return false;
  }
  const OptRecordRdata* opt_other = static_cast<const OptRecordRdata*>(other);
  return opt_other->buf_ == buf_;
}

void OptRecordRdata::AddOpt(std::unique_ptr<Opt> opt) {
  std::string_view opt_data = opt->data();

  // Resize buffer to accommodate new OPT.
  const size_t orig_rdata_size = buf_.size();
  buf_.resize(orig_rdata_size + Opt::kHeaderSize + opt_data.size());

  // Start writing from the end of the existing rdata.
  auto writer = base::SpanWriter(base::as_writable_byte_span(buf_));
  CHECK(writer.Skip(orig_rdata_size));
  bool success = writer.WriteU16BigEndian(opt->GetCode()) &&
                 writer.WriteU16BigEndian(opt_data.size()) &&
                 writer.Write(base::as_byte_span(opt_data));
  DCHECK(success);

  opts_.emplace(opt->GetCode(), std::move(opt));
}

bool OptRecordRdata::ContainsOptCode(uint16_t opt_code) const {
  return base::Contains(opts_, opt_code);
}

std::vector<const OptRecordRdata::Opt*> OptRecordRdata::GetOpts() const {
  std::vector<const OptRecordRdata::Opt*> opts;
  opts.reserve(OptCount());
  for (const auto& elem : opts_) {
    opts.push_back(elem.second.get());
  }
  return opts;
}

std::vector<const OptRecordRdata::PaddingOpt*> OptRecordRdata::GetPaddingOpts()
    const {
  std::vector<const OptRecordRdata::PaddingOpt*> opts;
  auto range = opts_.equal_range(dns_protocol::kEdnsPadding);
  for (auto it = range.first; it != range.second; ++it) {
    opts.push_back(static_cast<const PaddingOpt*>(it->second.get()));
  }
  return opts;
}

std::vector<const OptRecordRdata::EdeOpt*> OptRecordRdata::GetEdeOpts() const {
  std::vector<const OptRecordRdata::EdeOpt*> opts;
  auto range = opts_.equal_range(dns_protocol::kEdnsExtendedDnsError);
  for (auto it = range.first; it != range.second; ++it) {
    opts.push_back(static_cast<const EdeOpt*>(it->second.get()));
  }
  return opts;
}

}  // namespace net
```