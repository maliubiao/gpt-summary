Response:
Let's break down the thought process for analyzing the `spdy_utils.cc` file.

**1. Understanding the Goal:**

The core request is to analyze a Chromium networking stack source file (`spdy_utils.cc`) and describe its functionality, its relationship to JavaScript (if any), any logic involved (including examples), common usage errors, and how a user's actions might lead to this code being executed (debugging).

**2. Initial Code Scan and Identification of Key Functions:**

The first step is to quickly read through the code and identify the main functions and their purposes. Looking at the function names and their parameters gives a good overview.

* `ExtractContentLengthFromHeaders`:  Seems to be about getting the `content-length` from HTTP headers.
* `CopyAndValidateHeaders`: Likely responsible for copying headers and validating their format.
* `CopyAndValidateTrailers`: Similar to the above, but for HTTP trailers (data sent after the main body).
* `PopulateHeaderBlockFromUrl`:  Generating a header block from a URL string.
* `ExtractQuicVersionFromAltSvcEntry`:  Dealing with extracting the QUIC protocol version from an Alt-Svc entry.

**3. Function-by-Function Analysis:**

Now, delve into each function in more detail:

* **`ExtractContentLengthFromHeaders`:**
    * **Purpose:** Extract the `content-length` from a `HttpHeaderBlock`. It also handles the case of multiple `content-length` headers, ensuring they are consistent.
    * **Logic:**  Iterates through the `content-length` header values, parsing them and checking for consistency.
    * **Error Handling:** Checks for invalid (non-numeric or negative) and inconsistent `content-length` values.
    * **JavaScript Relevance (Initial thought):**  While not directly called by JavaScript, JavaScript's `fetch` API or similar network requests might *result* in these headers being parsed on the server-side or within the browser's networking stack.

* **`CopyAndValidateHeaders`:**
    * **Purpose:** Copies headers from a `QuicHeaderList` (likely a list of key-value pairs) to a `HttpHeaderBlock`, performing validation checks.
    * **Validation:** Checks for empty header names and uppercase characters in header names.
    * **Interaction with `ExtractContentLengthFromHeaders`:** Calls it to specifically handle the `content-length` header.
    * **JavaScript Relevance:** Again, JavaScript network requests generate headers that this function could process.

* **`CopyAndValidateTrailers`:**
    * **Purpose:** Similar to `CopyAndValidateHeaders`, but for HTTP trailers. It also handles the special `kFinalOffsetHeaderKey`.
    * **Specific Logic:**  Looks for the `kFinalOffsetHeaderKey` (used in some QUIC scenarios to indicate the total body size).
    * **Validation:** Checks for empty names, pseudo-headers (starting with `:`) and uppercase characters.
    * **JavaScript Relevance:** Less common, but some advanced JavaScript APIs or server-sent events might involve trailers.

* **`PopulateHeaderBlockFromUrl`:**
    * **Purpose:** Takes a URL string and generates a basic HTTP header block (including `:method`, `:scheme`, `:authority`, `:path`).
    * **Logic:**  Parses the URL to extract the different components.
    * **JavaScript Relevance:** Direct connection. JavaScript's `fetch` or `XMLHttpRequest` often take URLs as input, and the browser's networking stack would need to generate the initial HTTP headers based on that URL.

* **`ExtractQuicVersionFromAltSvcEntry`:**
    * **Purpose:** Extracts a supported QUIC version from an Alt-Svc (Alternative Service) entry. This helps clients discover that a server supports QUIC.
    * **Logic:**  Compares the protocol ID in the Alt-Svc entry with the ALPN strings for the supported QUIC versions.
    * **JavaScript Relevance:** Indirect. When a website advertises QUIC support via Alt-Svc, the browser (including its JavaScript engine) can potentially upgrade the connection to QUIC.

**4. Identifying JavaScript Relationships and Examples:**

Focus on where JavaScript directly interacts or triggers the execution of this C++ code:

* **`PopulateHeaderBlockFromUrl` is the most direct link.**  A `fetch()` call with a URL will likely lead to this function (or something similar in the browser's networking stack) being executed.

* For the header and trailer processing functions, the connection is more about the *result* of JavaScript network operations. JavaScript initiates the request, but the C++ code handles the lower-level parsing and validation of the received headers/trailers.

**5. Logic and Examples (Hypothetical Inputs/Outputs):**

For each function with significant logic, create simple input and output examples to illustrate how it works:

* **`ExtractContentLengthFromHeaders`:** Show cases with a single valid length, multiple consistent lengths, and inconsistent lengths.
* **`PopulateHeaderBlockFromUrl`:** Demonstrate how different URLs are parsed into header fields.
* **`CopyAndValidateTrailers`:** Illustrate the handling of `kFinalOffsetHeaderKey`.

**6. Common Usage Errors:**

Think about how a *programmer* using the underlying networking APIs (which JavaScript indirectly uses) might make mistakes:

* Incorrect header casing.
* Providing invalid characters in header values.
* Mismatched content lengths.
* Missing required trailers (like `final-offset`).

**7. Debugging Scenario (User Actions):**

Trace a user action (e.g., clicking a link) that would lead to the execution of this code:

* User clicks a link.
* Browser initiates a network request.
* Browser's networking stack needs to generate headers (using something like `PopulateHeaderBlockFromUrl`).
* Server responds with headers and possibly trailers.
* Browser's networking stack parses and validates these (using functions like `CopyAndValidateHeaders` and `CopyAndValidateTrailers`).

**8. Refinement and Organization:**

Finally, organize the information clearly, using headings and bullet points for readability. Ensure that each part of the prompt is addressed. Refine the language to be precise and avoid jargon where possible. Review for clarity and accuracy. For instance, initially, I might just say "JavaScript makes network requests," but then refine it to mention specific APIs like `fetch` and `XMLHttpRequest`.

This detailed process of analyzing each function, thinking about its purpose, its relationship to the broader context (including JavaScript), and providing concrete examples is key to generating a comprehensive and informative answer.
This C++ source file, `spdy_utils.cc`, located within the Chromium networking stack, provides utility functions for working with the **SPDY** and **HTTP/2** protocols within the context of the **QUIC** transport protocol. While SPDY is largely superseded by HTTP/2, many concepts and underlying structures are shared, and QUIC implementations often build upon these foundations. The functions in this file primarily focus on **handling HTTP headers and trailers** in a QUIC environment.

Here's a breakdown of its functions:

**1. `ExtractContentLengthFromHeaders(int64_t* content_length, HttpHeaderBlock* headers)`:**

* **Functionality:** This function extracts the `content-length` from a given `HttpHeaderBlock`. It handles cases where the `content-length` header might appear multiple times (separated by null characters, which is valid in HTTP/2 and sometimes seen in SPDY). It also performs validation to ensure that multiple `content-length` values are consistent and that the value is a valid, non-negative integer.
* **Logic/Reasoning:**
    * **Input:** A pointer to an `int64_t` to store the extracted content length and a pointer to the `HttpHeaderBlock` containing the headers.
    * **Process:**
        1. It searches for the "content-length" header in the `headers`.
        2. If found, it splits the header value by null characters.
        3. For each part, it attempts to parse it as an unsigned 64-bit integer.
        4. It checks if the parsed value is a valid positive number.
        5. If a `content_length` has already been extracted, it compares the new value with the existing one to ensure consistency.
    * **Output:** Returns `true` if the `content-length` is successfully extracted and valid, `false` otherwise.
    * **Hypothetical Input/Output:**
        * **Input:** `content_length` points to -1, `headers` contains `{"content-length": "1024"}`. **Output:** `true`, `content_length` becomes 1024.
        * **Input:** `content_length` points to -1, `headers` contains `{"content-length": "abc"}`. **Output:** `false`.
        * **Input:** `content_length` points to 1024, `headers` contains `{"content-length": "1024\01024"}`. **Output:** `true`.
        * **Input:** `content_length` points to 1024, `headers` contains `{"content-length": "2048"}`. **Output:** `false`.

**2. `CopyAndValidateHeaders(const QuicHeaderList& header_list, int64_t* content_length, HttpHeaderBlock* headers)`:**

* **Functionality:** This function copies headers from a `QuicHeaderList` (a list of key-value pairs used in QUIC) to an `HttpHeaderBlock`. During the copy, it performs validation checks: header names must not be empty and must not contain uppercase characters (as per HTTP/2 and SPDY conventions for lowercase header names). It also calls `ExtractContentLengthFromHeaders` to handle the `content-length` header specifically.
* **Logic/Reasoning:**
    * **Input:** A constant reference to a `QuicHeaderList`, a pointer to an `int64_t` for content length, and a pointer to the `HttpHeaderBlock` to populate.
    * **Process:**
        1. It iterates through each key-value pair in the `header_list`.
        2. It checks if the header name is empty.
        3. It checks if the header name contains uppercase characters.
        4. It appends the header to the `headers` block.
        5. If the header name is "content-length", it calls `ExtractContentLengthFromHeaders`.
    * **Output:** Returns `true` if all headers are valid and copied, `false` otherwise.
    * **Hypothetical Input/Output:**
        * **Input:** `header_list` is `{{":method", "GET"}, {"host", "example.com"}}`, `content_length` points to -1, `headers` is empty. **Output:** `true`, `headers` becomes `{{":method", "GET"}, {"host", "example.com"}}`.
        * **Input:** `header_list` is `{{":method", "GET"}, {"Host", "example.com"}}`, `content_length` points to -1, `headers` is empty. **Output:** `false`.
        * **Input:** `header_list` is `{{":method", "GET"}, {"", "value"}}`, `content_length` points to -1, `headers` is empty. **Output:** `false`.

**3. `CopyAndValidateTrailers(const QuicHeaderList& header_list, bool expect_final_byte_offset, size_t* final_byte_offset, HttpHeaderBlock* trailers)`:**

* **Functionality:**  Similar to `CopyAndValidateHeaders`, but this function processes **trailers**, which are headers sent after the main body of a response. It validates that trailer names are not empty and do not start with a colon (`:`), as pseudo-headers are not allowed in trailers. It also handles a specific pseudo-header `kFinalOffsetHeaderKey` (likely `final-offset`), which might be present in QUIC to indicate the total number of bytes in the response body.
* **Logic/Reasoning:**
    * **Input:** A constant reference to a `QuicHeaderList` (trailers), a boolean indicating whether a final byte offset is expected, a pointer to a `size_t` to store the final byte offset, and a pointer to the `HttpHeaderBlock` for trailers.
    * **Process:**
        1. It iterates through each key-value pair in the `header_list`.
        2. If `expect_final_byte_offset` is true and the current header is `kFinalOffsetHeaderKey`, it attempts to parse its value as a `size_t`.
        3. It checks if the trailer name is empty or starts with `:`.
        4. It checks if the trailer name contains uppercase characters.
        5. It appends the trailer to the `trailers` block.
        6. If `expect_final_byte_offset` is true and the `kFinalOffsetHeaderKey` was not found, it returns `false`.
    * **Output:** Returns `true` if all trailers are valid, `false` otherwise.
    * **Hypothetical Input/Output:**
        * **Input:** `header_list` is `{"trailer-name", "trailer-value"}`, `expect_final_byte_offset` is `false`, `trailers` is empty. **Output:** `true`, `trailers` becomes `{"trailer-name", "trailer-value"}`.
        * **Input:** `header_list` is `{":pseudo-trailer", "value"}`, `expect_final_byte_offset` is `false`, `trailers` is empty. **Output:** `false`.
        * **Input:** `header_list` is `{"final-offset", "1000"}`, `expect_final_byte_offset` is `true`, `final_byte_offset` points to 0, `trailers` is empty. **Output:** `true`, `final_byte_offset` becomes 1000.
        * **Input:** `header_list` is `{"trailer-name", "value"}`, `expect_final_byte_offset` is `true`, `final_byte_offset` points to 0, `trailers` is empty. **Output:** `false`.

**4. `PopulateHeaderBlockFromUrl(const std::string url, HttpHeaderBlock* headers)`:**

* **Functionality:** This function takes a URL string and populates a basic `HttpHeaderBlock` with the necessary pseudo-headers for an HTTP request. It sets the `:method` to "GET", parses the URL to extract the scheme, authority (host), and path.
* **Logic/Reasoning:**
    * **Input:** A URL string and a pointer to an `HttpHeaderBlock`.
    * **Process:**
        1. Sets the `:method` header to "GET".
        2. Finds the position of "://".
        3. Extracts the scheme (e.g., "http", "https").
        4. Finds the position of the first "/" after the authority.
        5. Extracts the authority (hostname and port).
        6. Extracts the path.
    * **Output:** Returns `true` if the URL is parsed successfully, `false` otherwise.
    * **Hypothetical Input/Output:**
        * **Input:** `url` is "https://www.example.com/path", `headers` is empty. **Output:** `true`, `headers` becomes `{{":method", "GET"}, {":scheme", "https"}, {":authority", "www.example.com"}, {":path", "/path"}}`.
        * **Input:** `url` is "http://example.com", `headers` is empty. **Output:** `true`, `headers` becomes `{{":method", "GET"}, {":scheme", "http"}, {":authority", "example.com"}, {":path", "/"}}`.
        * **Input:** `url` is "invalid-url", `headers` is empty. **Output:** `false`.

**5. `ExtractQuicVersionFromAltSvcEntry(const spdy::SpdyAltSvcWireFormat::AlternativeService& alternative_service_entry, const ParsedQuicVersionVector& supported_versions)`:**

* **Functionality:** This function extracts a supported QUIC version from an Alt-Svc (Alternative Service) entry. Alt-Svc is a mechanism for servers to advertise support for alternative protocols like QUIC. The function compares the advertised protocol ID with the ALPN (Application-Layer Protocol Negotiation) strings for the supported QUIC versions.
* **Logic/Reasoning:**
    * **Input:** An `AlternativeService` entry from an Alt-Svc header and a vector of supported QUIC versions.
    * **Process:**
        1. Iterates through the `supported_versions`.
        2. Skips versions that defer to RFC v1 ALPN (as they might not be advertised directly).
        3. Compares the `protocol_id` from the Alt-Svc entry with the ALPN string for the current version.
    * **Output:** Returns the `ParsedQuicVersion` if a match is found, otherwise returns `ParsedQuicVersion::Unsupported()`.
    * **Hypothetical Input/Output:**
        * **Input:** `alternative_service_entry` has `protocol_id` "h3-29", `supported_versions` contains a version with ALPN "h3-29". **Output:** The corresponding `ParsedQuicVersion`.
        * **Input:** `alternative_service_entry` has `protocol_id` "h3-29", `supported_versions` does not contain a version with ALPN "h3-29". **Output:** `ParsedQuicVersion::Unsupported()`.

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it plays a crucial role in the underlying network communication that JavaScript relies on. Here's how they relate:

* **`PopulateHeaderBlockFromUrl`:** When JavaScript uses APIs like `fetch()` to make a network request, the browser's networking stack (which includes this C++ code) needs to construct the initial HTTP headers. `PopulateHeaderBlockFromUrl` is a function that could be involved in generating these headers based on the URL provided in the `fetch()` call.
    * **Example:**  A JavaScript `fetch("https://example.com/data")` call would eventually lead to the browser's network code parsing this URL. `PopulateHeaderBlockFromUrl` (or a similar function) would generate headers like `":method": "GET"`, `":scheme": "https"`, `":authority": "example.com"`, and `":path": "/data"`.
* **`CopyAndValidateHeaders` and `CopyAndValidateTrailers`:** When the browser receives an HTTP response (or trailers) after a JavaScript `fetch()` request, this C++ code is involved in parsing and validating the headers and trailers before they are made available to the JavaScript code through the `Response` object. The `content-length` extracted here is used to track the download progress and determine if the entire response has been received.
    * **Example:** A JavaScript `fetch()` call to an API might return JSON data with a `content-length` header. The browser's C++ networking code would use `CopyAndValidateHeaders` and `ExtractContentLengthFromHeaders` to parse this header and ensure its validity. The JavaScript code would then access the response body.
* **`ExtractQuicVersionFromAltSvcEntry`:** When a website advertises QUIC support using the `Alt-Svc` header, the browser's networking stack uses this function to identify which supported QUIC versions the server is offering. This allows the browser to potentially upgrade the connection to QUIC for subsequent requests, potentially improving performance. This happens transparently to the JavaScript code, but it benefits from the improved transport.

**User or Programming Common Usage Errors (related to these functions):**

* **Incorrect Header Casing:**  If a programmer using the underlying C++ networking APIs incorrectly sets header names with uppercase letters (e.g., "Host" instead of "host"), `CopyAndValidateHeaders` will detect this as an error.
    * **Example:**  A low-level networking library might allow direct manipulation of headers. If a developer writes code that sets a header as `headers->AppendValueOrAddHeader("Content-Length", "100");` (uppercase 'L'), the validation in `CopyAndValidateHeaders` would flag this.
* **Providing Invalid Characters in Header Values:**  While not directly checked by these functions, other parts of the networking stack might reject header values containing invalid characters. However, if multiple `content-length` headers with non-numeric values are present, `ExtractContentLengthFromHeaders` will catch this.
    * **Example:** Setting `headers->AppendValueOrAddHeader("content-length", "abc");` would be caught by `ExtractContentLengthFromHeaders`.
* **Mismatched `content-length` Values:**  If multiple `content-length` headers are sent with different numeric values, `ExtractContentLengthFromHeaders` will detect the inconsistency and return an error. This can happen due to server-side errors or malicious behavior.
* **Missing or Invalid `final-offset` Trailer:** If a QUIC connection expects a `final-offset` trailer (as indicated by the `expect_final_byte_offset` parameter in `CopyAndValidateTrailers`), and it's missing or not a valid number, the function will return an error. This is a specific requirement of some QUIC stream types.
* **Constructing Invalid URLs:** If a programmer attempts to use `PopulateHeaderBlockFromUrl` with an improperly formatted URL (e.g., missing the "://" separator), the function will return `false`, indicating an error in the URL construction.

**User Operations and Debugging:**

Here's how a user's actions might lead to this code being executed, serving as debugging线索:

1. **User types a URL in the address bar or clicks a link:**
   - The browser needs to initiate a network request for the given URL.
   - The browser's networking stack uses a function similar to `PopulateHeaderBlockFromUrl` to construct the initial HTTP headers for the request.

2. **User interacts with a website that uses JavaScript to fetch data:**
   - JavaScript code on the webpage calls the `fetch()` API (or `XMLHttpRequest`).
   - The browser's networking stack intercepts this request.
   - Again, a function like `PopulateHeaderBlockFromUrl` might be used to construct the request headers based on the URL provided to `fetch()`.

3. **The server sends an HTTP response:**
   - The browser receives the response headers.
   - The networking stack uses `CopyAndValidateHeaders` to parse and validate these headers, including extracting the `content-length`.

4. **The server sends trailers after the response body (in HTTP/2 or QUIC):**
   - The browser receives the trailers.
   - The networking stack uses `CopyAndValidateTrailers` to parse and validate the trailer headers, potentially including the `final-offset`.

5. **The website advertises QUIC support via the `Alt-Svc` header:**
   - The browser receives the `Alt-Svc` header.
   - The networking stack uses `ExtractQuicVersionFromAltSvcEntry` to determine the supported QUIC versions offered by the server.

**Debugging Scenario:**

Let's say a user is experiencing an issue where a webpage is not loading correctly, and the browser's developer tools show errors related to network requests. A developer investigating this might:

1. **Examine the Network tab in the developer tools:** They might see the request headers and response headers.
2. **Look for inconsistencies in `content-length`:** If multiple `content-length` headers are present with different values, this could point to a server-side error that `ExtractContentLengthFromHeaders` would have detected.
3. **Check for invalid header names:** If a custom header has an uppercase letter, the developer might suspect a problem related to header validation, potentially involving `CopyAndValidateHeaders`.
4. **Investigate trailer issues (if applicable):** If the request involves trailers, the developer might check if the `final-offset` is present and correct, or if any trailer names are invalid (starting with `:` or containing uppercase letters), which would be flagged by `CopyAndValidateTrailers`.
5. **Look for issues with QUIC connection establishment:** If the connection is supposed to be using QUIC, but it's falling back to TCP, the developer might investigate the `Alt-Svc` header and how the browser is parsing it, potentially leading them to examine the logic in `ExtractQuicVersionFromAltSvcEntry`.

By understanding the role of these utility functions in parsing and validating HTTP headers and trailers within the QUIC context, developers can better diagnose network-related issues in Chromium-based browsers.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/spdy_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/spdy_utils.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/quiche_text_utils.h"

using quiche::HttpHeaderBlock;

namespace quic {

// static
bool SpdyUtils::ExtractContentLengthFromHeaders(int64_t* content_length,
                                                HttpHeaderBlock* headers) {
  auto it = headers->find("content-length");
  if (it == headers->end()) {
    return false;
  } else {
    // Check whether multiple values are consistent.
    absl::string_view content_length_header = it->second;
    std::vector<absl::string_view> values =
        absl::StrSplit(content_length_header, '\0');
    for (const absl::string_view& value : values) {
      uint64_t new_value;
      if (!absl::SimpleAtoi(value, &new_value) ||
          !quiche::QuicheTextUtils::IsAllDigits(value)) {
        QUIC_DLOG(ERROR)
            << "Content length was either unparseable or negative.";
        return false;
      }
      if (*content_length < 0) {
        *content_length = new_value;
        continue;
      }
      if (new_value != static_cast<uint64_t>(*content_length)) {
        QUIC_DLOG(ERROR)
            << "Parsed content length " << new_value << " is "
            << "inconsistent with previously detected content length "
            << *content_length;
        return false;
      }
    }
    return true;
  }
}

bool SpdyUtils::CopyAndValidateHeaders(const QuicHeaderList& header_list,
                                       int64_t* content_length,
                                       HttpHeaderBlock* headers) {
  for (const auto& p : header_list) {
    const std::string& name = p.first;
    if (name.empty()) {
      QUIC_DLOG(ERROR) << "Header name must not be empty.";
      return false;
    }

    if (quiche::QuicheTextUtils::ContainsUpperCase(name)) {
      QUIC_DLOG(ERROR) << "Malformed header: Header name " << name
                       << " contains upper-case characters.";
      return false;
    }

    headers->AppendValueOrAddHeader(name, p.second);
  }

  if (headers->contains("content-length") &&
      !ExtractContentLengthFromHeaders(content_length, headers)) {
    return false;
  }

  QUIC_DVLOG(1) << "Successfully parsed headers: " << headers->DebugString();
  return true;
}

bool SpdyUtils::CopyAndValidateTrailers(const QuicHeaderList& header_list,
                                        bool expect_final_byte_offset,
                                        size_t* final_byte_offset,
                                        HttpHeaderBlock* trailers) {
  bool found_final_byte_offset = false;
  for (const auto& p : header_list) {
    const std::string& name = p.first;

    // Pull out the final offset pseudo header which indicates the number of
    // response body bytes expected.
    if (expect_final_byte_offset && !found_final_byte_offset &&
        name == kFinalOffsetHeaderKey &&
        absl::SimpleAtoi(p.second, final_byte_offset)) {
      found_final_byte_offset = true;
      continue;
    }

    if (name.empty() || name[0] == ':') {
      QUIC_DLOG(ERROR)
          << "Trailers must not be empty, and must not contain pseudo-"
          << "headers. Found: '" << name << "'";
      return false;
    }

    if (quiche::QuicheTextUtils::ContainsUpperCase(name)) {
      QUIC_DLOG(ERROR) << "Malformed header: Header name " << name
                       << " contains upper-case characters.";
      return false;
    }

    trailers->AppendValueOrAddHeader(name, p.second);
  }

  if (expect_final_byte_offset && !found_final_byte_offset) {
    QUIC_DLOG(ERROR) << "Required key '" << kFinalOffsetHeaderKey
                     << "' not present";
    return false;
  }

  // TODO(rjshade): Check for other forbidden keys, following the HTTP/2 spec.

  QUIC_DVLOG(1) << "Successfully parsed Trailers: " << trailers->DebugString();
  return true;
}

// static
// TODO(danzh): Move it to quic/tools/ and switch to use GURL.
bool SpdyUtils::PopulateHeaderBlockFromUrl(const std::string url,
                                           HttpHeaderBlock* headers) {
  (*headers)[":method"] = "GET";
  size_t pos = url.find("://");
  if (pos == std::string::npos) {
    return false;
  }
  (*headers)[":scheme"] = url.substr(0, pos);
  size_t start = pos + 3;
  pos = url.find('/', start);
  if (pos == std::string::npos) {
    (*headers)[":authority"] = url.substr(start);
    (*headers)[":path"] = "/";
    return true;
  }
  (*headers)[":authority"] = url.substr(start, pos - start);
  (*headers)[":path"] = url.substr(pos);
  return true;
}

// static
ParsedQuicVersion SpdyUtils::ExtractQuicVersionFromAltSvcEntry(
    const spdy::SpdyAltSvcWireFormat::AlternativeService&
        alternative_service_entry,
    const ParsedQuicVersionVector& supported_versions) {
  for (const ParsedQuicVersion& version : supported_versions) {
    if (version.AlpnDeferToRFCv1()) {
      // Versions with share an ALPN with v1 are currently unable to be
      // advertised with Alt-Svc.
      continue;
    }
    if (AlpnForVersion(version) == alternative_service_entry.protocol_id) {
      return version;
    }
  }

  return ParsedQuicVersion::Unsupported();
}

}  // namespace quic
```