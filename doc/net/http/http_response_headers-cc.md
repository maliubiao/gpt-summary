Response:
My thinking process to analyze the provided C++ code snippet for `net/http/http_response_headers.cc` went something like this:

1. **Understand the Core Purpose:** The file name `http_response_headers.cc` immediately suggests this code is responsible for handling HTTP response headers within the Chromium networking stack. My initial goal is to understand *how* it handles them.

2. **Scan for Key Data Structures and Classes:**  I quickly look for prominent data structures and classes. The `HttpResponseHeaders` class itself is the central focus. I also notice the `Builder` nested class, hinting at a construction pattern. The `ParsedHeader` struct is important for understanding how the headers are internally represented.

3. **Identify Core Functionality by Examining Methods:**  I start reading through the public methods of `HttpResponseHeaders`. This is crucial for understanding the *actions* the class performs. I see methods like:
    * `Parse()`:  Likely for taking a raw header string and interpreting it.
    * `Persist()`: Suggests serialization or saving of headers.
    * `Update()`:  Modifying headers, potentially based on new responses (like 304 Not Modified).
    * `MergeWithHeaders()`: Combining header sets.
    * `RemoveHeader()`, `RemoveHeaders()`, `RemoveHeaderLine()`:  Manipulation of existing headers.
    * `AddHeader()`, `SetHeader()`:  Adding or modifying single headers.
    * `AddCookie()`: Specialized header addition.
    * `ReplaceStatusLine()`: Modifying the HTTP status line.
    * `UpdateWithNewRange()`:  Specific logic for handling range requests.
    * `GetNormalizedHeader()`:  Retrieving header values, potentially combining multiple instances of the same header.
    * `GetStatusLine()`, `GetStatusText()`: Accessing parts of the status line.
    * `EnumerateHeaderLines()`, `EnumerateHeader()`:  Iterating through headers.
    * `HasHeaderValue()`, `HasHeader()`:  Checking for the presence of headers and their values.
    * `ParseVersion()`, `ParseStatusLine()`:  Lower-level parsing functions.
    * `FindHeader()`:  Internal helper for locating headers.
    * `GetCacheControlDirective()`:  Specific parsing for cache-control directives.

4. **Look for Connections to External Libraries/Concepts:** I observe `#include` directives and the `using namespace net;` statement. This tells me the code interacts with other parts of the Chromium networking stack. I see includes for:
    * `base/`:  Fundamental Chromium base library (strings, logging, metrics, time, etc.).
    * `net/base/`: Core networking concepts (features, number parsing, tracing).
    * `net/http/`: Other HTTP-related components (byte ranges, log utilities, status codes, utilities, structured headers).
    * `net/log/`: Network logging.

5. **Analyze Static Data and Constants:**  The constants like `kHopByHopResponseHeaders`, `kChallengeResponseHeaders`, `kCookieResponseHeaders`, etc., provide important context. They define categories of headers that are treated specially (e.g., not cached).

6. **Identify Key Algorithms and Logic:** I pay attention to the parsing logic within `Parse()` and the manipulation logic in methods like `Update()` and `MergeWithHeaders()`. The use of iterators to traverse the raw header string and the `parsed_` vector is a key detail. The `ShouldUpdateHeader()` function reveals rules about which headers are copied during updates.

7. **Consider JavaScript Interaction (based on prompt):** I know that HTTP headers directly influence how web browsers (and therefore JavaScript) behave. I think about:
    * **Caching:** Headers like `Cache-Control`, `Expires`, `ETag`, `Last-Modified` are crucial for browser caching, which JavaScript can indirectly influence (e.g., through fetch API cache modes).
    * **Cookies:** `Set-Cookie` headers control cookie setting, directly accessible and modifiable by JavaScript.
    * **Security:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, etc., affect browser security policies, influencing what JavaScript can do.
    * **Content Type:** The `Content-Type` header determines how the browser interprets the response body, directly impacting how JavaScript can process the data.
    * **Redirection:** `Location` headers for redirects are followed by the browser, affecting the page JavaScript runs on.

8. **Think about Error Scenarios and User Mistakes:** Based on the code and HTTP standards, I consider potential errors:
    * **Invalid Header Syntax:** The parsing logic needs to handle malformed headers gracefully.
    * **Incorrect Cache Control Directives:** Users might misunderstand how caching works.
    * **Security Header Misconfiguration:**  Incorrectly set security headers can introduce vulnerabilities.
    * **Cookie Issues:**  Problems with cookie format or expiration can lead to authentication issues.

9. **Trace User Actions (based on prompt):** I imagine a typical web browsing scenario and how it leads to this code:
    * User enters a URL or clicks a link.
    * The browser's network stack initiates an HTTP request.
    * The server responds with HTTP headers.
    * This `HttpResponseHeaders` class is used to parse and manage those received headers.
    * The parsed header information is then used by other parts of the browser (cache, rendering engine, JavaScript).

10. **Structure the Explanation:** Finally, I organize my findings into the requested categories: functionality, JavaScript relation, logical inference, user errors, debugging clues, and summarization. I try to provide concrete examples where possible.
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The rules for header parsing were borrowed from Firefox:
// http://lxr.mozilla.org/seamonkey/source/netwerk/protocol/http/src/nsHttpResponseHead.cpp
// The rules for parsing content-types were also borrowed from Firefox:
// http://lxr.mozilla.org/mozilla/source/netwerk/base/src/nsURLHelper.cpp#834

#include "net/http/http_response_headers.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "base/format_macros.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/pickle.h"
#include "base/ranges/algorithm.h"
#include "base/strings/escape.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/parse_number.h"
#include "net/base/tracing.h"
#include "net/http/http_byte_range.h"
#include "net/http/http_log_util.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"
#include "net/http/structured_headers.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_values.h"

using base::Time;

namespace net {

//-----------------------------------------------------------------------------

namespace {

// These headers are RFC 2616 hop-by-hop headers;
// not to be stored by caches.
const char* const kHopByHopResponseHeaders[] = {
  "connection",
  "proxy-connection",
  "keep-alive",
  "trailer",
  "transfer-encoding",
  "upgrade"
};

// These headers are challenge response headers;
// not to be stored by caches.
const char* const kChallengeResponseHeaders[] = {
  "www-authenticate",
  "proxy-authenticate"
};

// These headers are cookie setting headers;
// not to be stored by caches or disclosed otherwise.
const char* const kCookieResponseHeaders[] = {
  "set-cookie",
  "set-cookie2",
  "clear-site-data",
};

// By default, do not cache Strict-Transport-Security.
// This avoids erroneously re-processing it on page loads from cache ---
// it is defined to be valid only on live and error-free HTTPS connections.
const char* const kSecurityStateHeaders[] = {
  "strict-transport-security",
};

// These response headers are not copied from a 304/206 response to the cached
// response headers. This list is based on Mozilla's nsHttpResponseHead.cpp.
const char* const kNonUpdatedHeaders[] = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "www-authenticate",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-location",
    "content-md5",
    "etag",
    "content-encoding",
    "content-range",
    "content-type",
    "content-length",
    "x-frame-options",
    "x-xss-protection",
};

// Some header prefixes mean "Don't copy this header from a 304 response.".
// Rather than listing all the relevant headers, we can consolidate them into
// this list:
const char* const kNonUpdatedHeaderPrefixes[] = {
  "x-content-",
  "x-webkit-"
};

constexpr char kActivateStorageAccessHeader[] = "activate-storage-access";

bool ShouldUpdateHeader(std::string_view name) {
  for (const auto* header : kNonUpdatedHeaders) {
    if (base::EqualsCaseInsensitiveASCII(name, header))
      return false;
  }
  for (const auto* prefix : kNonUpdatedHeaderPrefixes) {
    if (base::StartsWith(name, prefix, base::CompareCase::INSENSITIVE_ASCII))
      return false;
  }
  return true;
}

bool HasEmbeddedNulls(std::string_view str) {
  return str.find('\0') != std::string::npos;
}

void CheckDoesNotHaveEmbeddedNulls(std::string_view str) {
  // Care needs to be taken when adding values to the raw headers string to
  // make sure it does not contain embeded NULLs. Any embeded '\0' may be
  // understood as line terminators and change how header lines get tokenized.
  CHECK(!HasEmbeddedNulls(str));
}

void RemoveLeadingSpaces(std::string_view* s) {
  s->remove_prefix(std::min(s->find_first_not_of(' '), s->size()));
}

// Parses `status` for response code and status text. Returns the response code,
// and appends the response code and trimmed status text preceded by a space to
// `append_to`. For example, given the input " 404 Not found " would return 404
// and append " 404 Not found" to `append_to`. The odd calling convention is
// necessary to avoid extra copies in the implementation of
// HttpResponseHeaders::ParseStatusLine().
int ParseStatus(std::string_view status, std::string& append_to) {
  // Skip whitespace. Tabs are not skipped, for backwards compatibility.
  RemoveLeadingSpaces(&status);

  auto first_non_digit = std::ranges::find_if(
      status, [](char c) { return !base::IsAsciiDigit(c); });

  if (first_non_digit == status.begin()) {
    DVLOG(1) << "missing response status number; assuming 200";
    append_to.append(" 200");
    return HTTP_OK;
  }

  append_to.push_back(' ');
  append_to.append(status.begin(), first_non_digit);
  int response_code = -1;
  // For backwards compatibility, overlarge response codes are permitted.
  // base::StringToInt will clamp the value to INT_MAX.
  base::StringToInt(base::MakeStringPiece(status.begin(), first_non_digit),
                    &response_code);
  CHECK_GE(response_code, 0);

  status.remove_prefix(first_non_digit - status.begin());

  // Skip whitespace. Tabs are not skipped, as before.
  RemoveLeadingSpaces(&status);

  // Trim trailing whitespace. Tabs are not trimmed.
  const size_t last_non_space_pos = status.find_last_not_of(' ');
  if (last_non_space_pos != std::string_view::npos) {
    status.remove_suffix(status.size() - last_non_space_pos - 1);
  }

  if (status.empty()) {
    return response_code;
  }

  CheckDoesNotHaveEmbeddedNulls(status);

  append_to.push_back(' ');
  append_to.append(status);
  return response_code;
}

}  // namespace

const char HttpResponseHeaders::kContentRange[] = "Content-Range";
const char HttpResponseHeaders::kLastModified[] = "Last-Modified";
const char HttpResponseHeaders::kVary[] = "Vary";

struct HttpResponseHeaders::ParsedHeader {
  // A header "continuation" contains only a subsequent value for the
  // preceding header. (Header values are comma separated.)
  bool is_continuation() const { return name_begin == name_end; }

  std::string::const_iterator name_begin;
  std::string::const_iterator name_end;
  std::string::const_iterator value_begin;
  std::string::const_iterator value_end;

  // Write a representation of this object into a tracing proto.
  void WriteIntoTrace(perfetto::TracedValue context) const {
    auto dict = std::move(context).WriteDictionary();
    dict.Add("name", base::MakeStringPiece(name_begin, name_end));
    dict.Add("value", base::MakeStringPiece(value_begin, value_end));
  }
};

//-----------------------------------------------------------------------------

HttpResponseHeaders::Builder::Builder(HttpVersion version,
                                      std::string_view status)
    : version_(version), status_(status) {
  DCHECK(version == HttpVersion(1, 0) || version == HttpVersion(1, 1) ||
         version == HttpVersion(2, 0));
}

HttpResponseHeaders::Builder::~Builder() = default;

scoped_refptr<HttpResponseHeaders> HttpResponseHeaders::Builder::Build() {
  return base::MakeRefCounted<HttpResponseHeaders>(BuilderPassKey(), version_,
                                                   status_, headers_);
}

HttpResponseHeaders::HttpResponseHeaders(const std::string& raw_input)
    : response_code_(-1) {
  Parse(raw_input);

  // As it happens right now, there aren't double-constructions of response
  // headers using this constructor, so our counts should also be accurate,
  // without instantiating the histogram in two places. It is also
  // important that this histogram not collect data in the other
  // constructor, which rebuilds an histogram from a pickle, since
  // that would actually create a double call between the original
  // HttpResponseHeader that was serialized, and initialization of the
  // new object from that pickle.
  if (base::FeatureList::IsEnabled(features::kOptimizeParsingDataUrls)) {
    std::optional<HttpStatusCode> status_code =
        TryToGetHttpStatusCode(response_code_);
    if (status_code.has_value()) {
      UMA_HISTOGRAM_ENUMERATION("Net.HttpResponseCode2", status_code.value(),
                                net::HttpStatusCode::HTTP_STATUS_CODE_MAX);
    }
  } else {
    UMA_HISTOGRAM_CUSTOM_ENUMERATION(
        "Net.HttpResponseCode",
        HttpUtil::MapStatusCodeForHistogram(response_code_),
        // Note the third argument is only
        // evaluated once, see macro
        // definition for details.
        HttpUtil::GetStatusCodesForHistogram());
  }
}

HttpResponseHeaders::HttpResponseHeaders(base::PickleIterator* iter)
    : response_code_(-1) {
  std::string raw_input;
  if (iter->ReadString(&raw_input))
    Parse(raw_input);
}

HttpResponseHeaders::HttpResponseHeaders(
    BuilderPassKey,
    HttpVersion version,
    std::string_view status,
    base::span<const std::pair<std::string_view, std::string_view>> headers)
    : http_version_(version) {
  // This must match the behaviour of Parse(). We don't use Parse() because
  // avoiding the overhead of parsing is the point of this constructor.

  std::string formatted_status;
  formatted_status.reserve(status.size() + 1);  // ParseStatus() may add a space
  response_code_ = ParseStatus(status, formatted_status);

  // First calculate how big the output will be so that we can allocate the
  // right amount of memory.
  size_t expected_size = 8;  // "HTTP/x.x"
  expected_size += formatted_status.size();
  expected_size += 1;  // "\0"
  size_t expected_parsed_size = 0;

  // Track which headers (by index) have a comma in the value. Since bools are
  // only 1 byte, we can afford to put 100 of them on the stack and avoid
  // allocating more memory 99.9% of the time.
  absl::InlinedVector<bool, 100> header_contains_comma;
  for (const auto& [key, value] : headers) {
    expected_size += key.size();
    expected_size += 1;  // ":"
    expected_size += value.size();
    expected_size += 1;  // "\0"
    // It's okay if we over-estimate the size of `parsed_`, so treat all ','
    // characters as if they might split the value to avoid parsing the value
    // carefully here.
    const size_t comma_count = base::ranges::count(value, ',') + 1;
    expected_parsed_size += comma_count;
    header_contains_comma.push_back(comma_count);
  }
  expected_size += 1;  // "\0"
  raw_headers_.reserve(expected_size);
  parsed_.reserve(expected_parsed_size);

  // Now fill in the output.
  const uint16_t major = version.major_value();
  const uint16_t minor = version.minor_value();
  CHECK_LE(major, 9);
  CHECK_LE(minor, 9);
  raw_headers_.append("HTTP/");
  raw_headers_.push_back('0' + major);
  raw_headers_.push_back('.');
  raw_headers_.push_back('0' + minor);
  raw_headers_.append(formatted_status);
  raw_headers_.push_back('\0');
  // It is vital that `raw_headers_` iterators are not invalidated after this
  // point.
  const char* const data_at_start = raw_headers_.data();
  size_t index = 0;
  for (const auto& [key, value] : headers) {
    CheckDoesNotHaveEmbeddedNulls(key);
    CheckDoesNotHaveEmbeddedNulls(value);
    // Because std::string iterators are random-access, end() has to point to
    // the position where the next character will be appended.
    const auto name_begin = raw_headers_.cend();
    raw_headers_.append(key);
    const auto name_end = raw_headers_.cend();
    raw_headers_.push_back(':');
    auto values_begin = raw_headers_.cend();
    raw_headers_.append(value);
    auto values_end = raw_headers_.cend();
    raw_headers_.push_back('\0');
    // The HTTP/2 standard disallows header values starting or ending with
    // whitespace (RFC 9113 8.2.1). Hopefully the same is also true of HTTP/3.
    // TODO(crbug.com/40282642): Validate that our implementations
    // actually enforce this constraint and change this TrimLWS() to a DCHECK.
    HttpUtil::TrimLWS(&values_begin, &values_end);
    AddHeader(name_begin, name_end, values_begin, values_end,
              header_contains_comma[index] ? ContainsCommas::kYes
                                           : ContainsCommas::kNo);
    ++index;
  }
  raw_headers_.push_back('\0');
  CHECK_EQ(expected_size, raw_headers_.size());
  CHECK_EQ(data_at_start, raw_headers_.data());
  DCHECK_LE(parsed_.size(), expected_parsed_size);

  DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 2]);
  DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 1]);
}

scoped_refptr<HttpResponseHeaders> HttpResponseHeaders::TryToCreate(
    std::string_view headers) {
  // Reject strings with nulls.
  if (HasEmbeddedNulls(headers) ||
      headers.size() > std::numeric_limits<int>::max()) {
    return nullptr;
  }

  return base::MakeRefCounted<HttpResponseHeaders>(
      HttpUtil::AssembleRawHeaders(headers));
}

scoped_refptr<HttpResponseHeaders> HttpResponseHeaders::TryToCreateForDataURL(
    std::string_view content_type) {
  // Reject strings with nulls.
  if (HasEmbeddedNulls(content_type) ||
      content_type.size() > std::numeric_limits<int>::max()) {
    return nullptr;
  }

  constexpr char kStatusLineAndHeaderName[] = "HTTP/1.1 200 OK\0Content-Type:";
  std::string raw_headers =
      base::StrCat({std::string_view(kStatusLineAndHeaderName,
                                     sizeof(kStatusLineAndHeaderName) - 1),
                    content_type, std::string_view("\0\0", 2)});

  return base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
}

void HttpResponseHeaders::Persist(base::Pickle* pickle,
                                  PersistOptions options) {
  if (options == PERSIST_RAW) {
    pickle->WriteString(raw_headers_);
    return;  // Done.
  }

  HeaderSet filter_headers;

  // Construct set of headers to filter out based on options.
  if ((options & PERSIST_SANS_NON_CACHEABLE) == PERSIST_SANS_NON_CACHEABLE)
    AddNonCacheableHeaders(&filter_headers);

  if ((options & PERSIST_SANS_COOKIES) == PERSIST_SANS_COOKIES)
    AddCookieHeaders(&filter_headers);

  if ((options & PERSIST_SANS_CHALLENGES) == PERSIST_SANS_CHALLENGES)
    AddChallengeHeaders(&filter_headers);

  if ((options & PERSIST_SANS_HOP_BY_HOP) == PERSIST_SANS_HOP_BY_HOP)
    AddHopByHopHeaders(&filter_headers);

  if ((options & PERSIST_SANS_RANGES) == PERSIST_SANS_RANGES)
    AddHopContentRangeHeaders(&filter_headers);

  if ((options & PERSIST_SANS_SECURITY_STATE) == PERSIST_SANS_SECURITY_STATE)
    AddSecurityStateHeaders(&filter_headers);

  std::string blob;
  blob.reserve(raw_headers_.size());

  // This copies the status line w/ terminator null.
  // Note raw_headers_ has embedded nulls instead of \n,
  // so this just copies the first header line.
  blob.assign(raw_headers_.c_str(), strlen(raw_headers_.c_str()) + 1);

  for (size_t i = 0; i < parsed_.size(); ++i) {
    DCHECK(!parsed_[i].is_continuation());

    // Locate the start of the next header.
    size_t k = i;
    while (++k < parsed_.size() && parsed_[k].is_continuation()) {}
    --k;

    std::string header_name = base::ToLowerASCII(
        base::MakeStringPiece(parsed_[i].name_begin, parsed_[i].name_end));
    if (filter_headers.find(header_name) == filter_headers.end()) {
      // Make sure there is a null after the value.
      blob.append(parsed_[i].name_begin, parsed_[k].value_end);
      blob.push_back('\0');
    }

    i = k;
  }
  blob.push_back('\0');

  pickle->WriteString(blob);
}

void HttpResponseHeaders::Update(const HttpResponseHeaders& new_headers) {
  DCHECK(new_headers.response_code() == HTTP_NOT_MODIFIED ||
         new_headers.response_code() == HTTP_PARTIAL_CONTENT);

  // Copy up to the null byte. This just copies the status line.
  std::string new_raw_headers(raw_headers_.c_str());
  new_raw_headers.push_back('\0');

  HeaderSet updated_headers;

  // NOTE: we write the new headers then the old headers for convenience. The
  // order should not matter.

  // Figure out which headers we want to take from new_headers:
  for (size_t i = 0; i < new_headers.parsed_.size(); ++i) {
    const HeaderList& new_parsed = new_headers.parsed_;

    DCHECK(!new_parsed[i].is_continuation());

    // Locate the start of the next header.
    size_t k = i;
    while (++k < new_parsed.size() && new_parsed[k].is_continuation()) {}
    --k;

    auto name =
        base::MakeStringPiece(new_parsed[i].name_begin, new_parsed[i].name_end);
    if (ShouldUpdateHeader(name)) {
      std::string name_lower = base::ToLowerASCII(name);
      updated_headers.insert(name_lower);

      // Preserve this header line in the merged result, making sure there is
      // a null after the value.
      new_raw_headers.append(new_parsed[i].name_begin, new_parsed[k].value_end);
      new_raw_headers.push_back('\0');
    }

    i = k;
  }

  // Now, build the new raw headers.
  MergeWithHeaders(std::move(new_raw_headers), updated_headers);
}

void HttpResponseHeaders::MergeWithHeaders(std::string raw_headers,
                                           const HeaderSet& headers_to_remove) {
  for (size_t i = 0; i < parsed_.size(); ++i) {
    DCHECK(!parsed_[i].is_continuation());

    // Locate the start of the next header.
    size_t k = i;
    while (++k < parsed_.size() && parsed_[k].is_continuation()) {}
    --k;

    std::string name = base::ToLowerASCII(
        base::MakeStringPiece(parsed_[i].name_begin, parsed_[i].name_end));
    if (headers_to_remove.find(name) == headers_to_remove.end()) {
      // It's ok to preserve this header in the final result.
      raw_headers.append(parsed_[i].name_begin, parsed_[k].value_end);
      raw_headers.push_back('\0');
    }

    i = k;
  }
  raw_headers.push_back('\0');

  // Make this object hold the new data.
  raw_headers_.clear();
  parsed_.clear();
  Parse(raw_headers);
}

void HttpResponseHeaders::RemoveHeader(std::string_view name) {
  // Copy up to the null byte. This just copies the status line.
  std::string new_raw_headers(raw_headers_.c_str());
  new_raw_headers.push_back('\0');

  HeaderSet to_remove;
  to_remove.insert(base::ToLowerASCII(name));
  MergeWithHeaders(std::move(new_raw_headers), to_remove);
}

void HttpResponseHeaders::RemoveHeaders(
    const std::unordered_set<std::string>& header_names) {
  // Copy up to the null byte. This just copies the status line.
  std::string new_raw_headers(raw_headers_.c_str());
  new_raw_headers.push_back('\0');

  HeaderSet to_remove;
  for (const auto& header_name : header_names) {
    to_remove.insert(base::ToLowerASCII(header_name));
  }
  MergeWithHeaders(std::move(new_raw_headers), to_remove);
}

void HttpResponseHeaders::RemoveHeaderLine(const std::string& name,
                                           const std::string& value) {
  std::string name_lowercase = base::ToLowerASCII(name);

  std::string new_raw_headers(GetStatusLine());
  new_raw_headers.push_back('\0');

  new_raw_headers.reserve(raw_headers_.size());

  size_t iter = 0;
  std::string old_header_name;
  std::string old_header_value;
  while (EnumerateHeaderLines(&iter, &old_header_name, &old_header_value)) {
    std::string old_header_name_lowercase = base::ToLowerASCII(old_header_name);
    if (name_lowercase == old_header_name_lowercase &&
        value == old_header_value)
      continue;

    new_raw_headers.append(old_header_name);
    new_raw_headers.push_back(':');
    new_raw_headers.push_back(' ');
    new_raw_headers.append(old_header_value);
    new_raw_headers.push_back('\0');
  }
  new_raw_headers.push_back('\0');

  // Make this object hold the new data.
  raw_headers_.clear();
  parsed_.clear();
  Parse(new_raw_headers);
}

void HttpResponseHeaders::AddHeader(std::string_view name,
                                    std::string_view value) {
  DCHECK(HttpUtil::IsValidHeaderName(name));
  DCHECK(HttpUtil::IsValidHeaderValue(value));

  // Don't copy the last null.
  std::string new_raw_headers(raw_headers_, 0, raw_headers_.size() - 1);
  new_raw_headers.append(name.begin(), name.end());
  new_raw_headers.append(": ");
  new_raw_headers.append(value.begin(), value.end());
  new_raw_headers.push_back('\0');
  new_raw_headers.push_back('\0');

  // Make this object hold the new data.
  raw_headers_.clear();
  parsed_.clear();
  Parse(new_raw_headers);
}

void HttpResponseHeaders::SetHeader(std::string_view name,
                                    std::string_view value) {
  RemoveHeader(name);
  AddHeader(name, value);
}

void HttpResponseHeaders::AddCookie(const std::string& cookie_string) {
  AddHeader("Set-Cookie", cookie_string);
}

void HttpResponseHeaders::ReplaceStatusLine(const std::string& new_status) {
  CheckDoesNotHaveEmbeddedNulls(new_status);
  // Copy up to the null byte. This just copies the status line.
  std::string new_raw_headers(new_status);
  new_raw_headers.push_back('\0');

  HeaderSet empty_to_remove;
  MergeWithHeaders(std::move(new_raw_headers), empty_to_remove);
}

void HttpResponseHeaders::UpdateWithNewRange(const HttpByteRange& byte_range,
                                             int64_t resource_size,
                                             bool replace_status_line) {
  DCHECK(byte_range.IsValid());
  DCHECK(byte_range.HasFirstBytePosition());
  DCHECK(byte_range.HasLastBytePosition());

  const char kLengthHeader[] = "Content-Length";
  const char kRangeHeader[] = "Content-Range";

  RemoveHeader(kLengthHeader);
  RemoveHeader(kRangeHeader);

  int64_t start = byte_range.first_byte_position();
  int64_t end = byte_range.last_byte_position();
  int64_t range_len = end - start + 1;

  if (replace_status_line)
    ReplaceStatusLine("HTTP/1.1 206 Partial Content");

  AddHeader(kRangeHeader,
            base::StringPrintf("bytes %" PRId64 "-%" PRId64 "/%" PRId64, start,
                               end, resource_size));
  AddHeader(kLengthHeader, base::StringPrintf("%" PRId64, range_len));
}

void HttpResponseHeaders::Parse(const std::string& raw_input) {
  raw_headers_.reserve(raw_input.size());
  // TODO(crbug.com/40277776): Call reserve() on `parsed_` with an
  // appropriate value.

  // ParseStatusLine adds a normalized status line to raw_headers_
  std::string::const_iterator line_begin = raw_input.begin();
  std::string::const_iterator line_end = base::ranges::find(raw_input, '\0');
  // has_headers = true, if there is any data following the status line.
  // Used by ParseStatusLine() to decide if a HTTP/0.9 is really a HTTP/1.0.
  bool has_headers =
      (line_end != raw_input.end() && (line_end + 1) != raw_input.end() &&
       *(line_end + 1) != '\0');
  ParseStatusLine(line_begin, line_end, has_headers);
  raw_headers_.push_back('\0');  // Terminate
Prompt: 
```
这是目录为net/http/http_response_headers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The rules for header parsing were borrowed from Firefox:
// http://lxr.mozilla.org/seamonkey/source/netwerk/protocol/http/src/nsHttpResponseHead.cpp
// The rules for parsing content-types were also borrowed from Firefox:
// http://lxr.mozilla.org/mozilla/source/netwerk/base/src/nsURLHelper.cpp#834

#include "net/http/http_response_headers.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "base/format_macros.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/pickle.h"
#include "base/ranges/algorithm.h"
#include "base/strings/escape.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/parse_number.h"
#include "net/base/tracing.h"
#include "net/http/http_byte_range.h"
#include "net/http/http_log_util.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"
#include "net/http/structured_headers.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_values.h"

using base::Time;

namespace net {

//-----------------------------------------------------------------------------

namespace {

// These headers are RFC 2616 hop-by-hop headers;
// not to be stored by caches.
const char* const kHopByHopResponseHeaders[] = {
  "connection",
  "proxy-connection",
  "keep-alive",
  "trailer",
  "transfer-encoding",
  "upgrade"
};

// These headers are challenge response headers;
// not to be stored by caches.
const char* const kChallengeResponseHeaders[] = {
  "www-authenticate",
  "proxy-authenticate"
};

// These headers are cookie setting headers;
// not to be stored by caches or disclosed otherwise.
const char* const kCookieResponseHeaders[] = {
  "set-cookie",
  "set-cookie2",
  "clear-site-data",
};

// By default, do not cache Strict-Transport-Security.
// This avoids erroneously re-processing it on page loads from cache ---
// it is defined to be valid only on live and error-free HTTPS connections.
const char* const kSecurityStateHeaders[] = {
  "strict-transport-security",
};

// These response headers are not copied from a 304/206 response to the cached
// response headers.  This list is based on Mozilla's nsHttpResponseHead.cpp.
const char* const kNonUpdatedHeaders[] = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "www-authenticate",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-location",
    "content-md5",
    "etag",
    "content-encoding",
    "content-range",
    "content-type",
    "content-length",
    "x-frame-options",
    "x-xss-protection",
};

// Some header prefixes mean "Don't copy this header from a 304 response.".
// Rather than listing all the relevant headers, we can consolidate them into
// this list:
const char* const kNonUpdatedHeaderPrefixes[] = {
  "x-content-",
  "x-webkit-"
};

constexpr char kActivateStorageAccessHeader[] = "activate-storage-access";

bool ShouldUpdateHeader(std::string_view name) {
  for (const auto* header : kNonUpdatedHeaders) {
    if (base::EqualsCaseInsensitiveASCII(name, header))
      return false;
  }
  for (const auto* prefix : kNonUpdatedHeaderPrefixes) {
    if (base::StartsWith(name, prefix, base::CompareCase::INSENSITIVE_ASCII))
      return false;
  }
  return true;
}

bool HasEmbeddedNulls(std::string_view str) {
  return str.find('\0') != std::string::npos;
}

void CheckDoesNotHaveEmbeddedNulls(std::string_view str) {
  // Care needs to be taken when adding values to the raw headers string to
  // make sure it does not contain embeded NULLs. Any embeded '\0' may be
  // understood as line terminators and change how header lines get tokenized.
  CHECK(!HasEmbeddedNulls(str));
}

void RemoveLeadingSpaces(std::string_view* s) {
  s->remove_prefix(std::min(s->find_first_not_of(' '), s->size()));
}

// Parses `status` for response code and status text. Returns the response code,
// and appends the response code and trimmed status text preceded by a space to
// `append_to`. For example, given the input " 404 Not found " would return 404
// and append " 404 Not found" to `append_to`. The odd calling convention is
// necessary to avoid extra copies in the implementation of
// HttpResponseHeaders::ParseStatusLine().
int ParseStatus(std::string_view status, std::string& append_to) {
  // Skip whitespace. Tabs are not skipped, for backwards compatibility.
  RemoveLeadingSpaces(&status);

  auto first_non_digit = std::ranges::find_if(
      status, [](char c) { return !base::IsAsciiDigit(c); });

  if (first_non_digit == status.begin()) {
    DVLOG(1) << "missing response status number; assuming 200";
    append_to.append(" 200");
    return HTTP_OK;
  }

  append_to.push_back(' ');
  append_to.append(status.begin(), first_non_digit);
  int response_code = -1;
  // For backwards compatibility, overlarge response codes are permitted.
  // base::StringToInt will clamp the value to INT_MAX.
  base::StringToInt(base::MakeStringPiece(status.begin(), first_non_digit),
                    &response_code);
  CHECK_GE(response_code, 0);

  status.remove_prefix(first_non_digit - status.begin());

  // Skip whitespace. Tabs are not skipped, as before.
  RemoveLeadingSpaces(&status);

  // Trim trailing whitespace. Tabs are not trimmed.
  const size_t last_non_space_pos = status.find_last_not_of(' ');
  if (last_non_space_pos != std::string_view::npos) {
    status.remove_suffix(status.size() - last_non_space_pos - 1);
  }

  if (status.empty()) {
    return response_code;
  }

  CheckDoesNotHaveEmbeddedNulls(status);

  append_to.push_back(' ');
  append_to.append(status);
  return response_code;
}

}  // namespace

const char HttpResponseHeaders::kContentRange[] = "Content-Range";
const char HttpResponseHeaders::kLastModified[] = "Last-Modified";
const char HttpResponseHeaders::kVary[] = "Vary";

struct HttpResponseHeaders::ParsedHeader {
  // A header "continuation" contains only a subsequent value for the
  // preceding header.  (Header values are comma separated.)
  bool is_continuation() const { return name_begin == name_end; }

  std::string::const_iterator name_begin;
  std::string::const_iterator name_end;
  std::string::const_iterator value_begin;
  std::string::const_iterator value_end;

  // Write a representation of this object into a tracing proto.
  void WriteIntoTrace(perfetto::TracedValue context) const {
    auto dict = std::move(context).WriteDictionary();
    dict.Add("name", base::MakeStringPiece(name_begin, name_end));
    dict.Add("value", base::MakeStringPiece(value_begin, value_end));
  }
};

//-----------------------------------------------------------------------------

HttpResponseHeaders::Builder::Builder(HttpVersion version,
                                      std::string_view status)
    : version_(version), status_(status) {
  DCHECK(version == HttpVersion(1, 0) || version == HttpVersion(1, 1) ||
         version == HttpVersion(2, 0));
}

HttpResponseHeaders::Builder::~Builder() = default;

scoped_refptr<HttpResponseHeaders> HttpResponseHeaders::Builder::Build() {
  return base::MakeRefCounted<HttpResponseHeaders>(BuilderPassKey(), version_,
                                                   status_, headers_);
}

HttpResponseHeaders::HttpResponseHeaders(const std::string& raw_input)
    : response_code_(-1) {
  Parse(raw_input);

  // As it happens right now, there aren't double-constructions of response
  // headers using this constructor, so our counts should also be accurate,
  // without instantiating the histogram in two places.  It is also
  // important that this histogram not collect data in the other
  // constructor, which rebuilds an histogram from a pickle, since
  // that would actually create a double call between the original
  // HttpResponseHeader that was serialized, and initialization of the
  // new object from that pickle.
  if (base::FeatureList::IsEnabled(features::kOptimizeParsingDataUrls)) {
    std::optional<HttpStatusCode> status_code =
        TryToGetHttpStatusCode(response_code_);
    if (status_code.has_value()) {
      UMA_HISTOGRAM_ENUMERATION("Net.HttpResponseCode2", status_code.value(),
                                net::HttpStatusCode::HTTP_STATUS_CODE_MAX);
    }
  } else {
    UMA_HISTOGRAM_CUSTOM_ENUMERATION(
        "Net.HttpResponseCode",
        HttpUtil::MapStatusCodeForHistogram(response_code_),
        // Note the third argument is only
        // evaluated once, see macro
        // definition for details.
        HttpUtil::GetStatusCodesForHistogram());
  }
}

HttpResponseHeaders::HttpResponseHeaders(base::PickleIterator* iter)
    : response_code_(-1) {
  std::string raw_input;
  if (iter->ReadString(&raw_input))
    Parse(raw_input);
}

HttpResponseHeaders::HttpResponseHeaders(
    BuilderPassKey,
    HttpVersion version,
    std::string_view status,
    base::span<const std::pair<std::string_view, std::string_view>> headers)
    : http_version_(version) {
  // This must match the behaviour of Parse(). We don't use Parse() because
  // avoiding the overhead of parsing is the point of this constructor.

  std::string formatted_status;
  formatted_status.reserve(status.size() + 1);  // ParseStatus() may add a space
  response_code_ = ParseStatus(status, formatted_status);

  // First calculate how big the output will be so that we can allocate the
  // right amount of memory.
  size_t expected_size = 8;  // "HTTP/x.x"
  expected_size += formatted_status.size();
  expected_size += 1;  // "\0"
  size_t expected_parsed_size = 0;

  // Track which headers (by index) have a comma in the value. Since bools are
  // only 1 byte, we can afford to put 100 of them on the stack and avoid
  // allocating more memory 99.9% of the time.
  absl::InlinedVector<bool, 100> header_contains_comma;
  for (const auto& [key, value] : headers) {
    expected_size += key.size();
    expected_size += 1;  // ":"
    expected_size += value.size();
    expected_size += 1;  // "\0"
    // It's okay if we over-estimate the size of `parsed_`, so treat all ','
    // characters as if they might split the value to avoid parsing the value
    // carefully here.
    const size_t comma_count = base::ranges::count(value, ',') + 1;
    expected_parsed_size += comma_count;
    header_contains_comma.push_back(comma_count);
  }
  expected_size += 1;  // "\0"
  raw_headers_.reserve(expected_size);
  parsed_.reserve(expected_parsed_size);

  // Now fill in the output.
  const uint16_t major = version.major_value();
  const uint16_t minor = version.minor_value();
  CHECK_LE(major, 9);
  CHECK_LE(minor, 9);
  raw_headers_.append("HTTP/");
  raw_headers_.push_back('0' + major);
  raw_headers_.push_back('.');
  raw_headers_.push_back('0' + minor);
  raw_headers_.append(formatted_status);
  raw_headers_.push_back('\0');
  // It is vital that `raw_headers_` iterators are not invalidated after this
  // point.
  const char* const data_at_start = raw_headers_.data();
  size_t index = 0;
  for (const auto& [key, value] : headers) {
    CheckDoesNotHaveEmbeddedNulls(key);
    CheckDoesNotHaveEmbeddedNulls(value);
    // Because std::string iterators are random-access, end() has to point to
    // the position where the next character will be appended.
    const auto name_begin = raw_headers_.cend();
    raw_headers_.append(key);
    const auto name_end = raw_headers_.cend();
    raw_headers_.push_back(':');
    auto values_begin = raw_headers_.cend();
    raw_headers_.append(value);
    auto values_end = raw_headers_.cend();
    raw_headers_.push_back('\0');
    // The HTTP/2 standard disallows header values starting or ending with
    // whitespace (RFC 9113 8.2.1). Hopefully the same is also true of HTTP/3.
    // TODO(crbug.com/40282642): Validate that our implementations
    // actually enforce this constraint and change this TrimLWS() to a DCHECK.
    HttpUtil::TrimLWS(&values_begin, &values_end);
    AddHeader(name_begin, name_end, values_begin, values_end,
              header_contains_comma[index] ? ContainsCommas::kYes
                                           : ContainsCommas::kNo);
    ++index;
  }
  raw_headers_.push_back('\0');
  CHECK_EQ(expected_size, raw_headers_.size());
  CHECK_EQ(data_at_start, raw_headers_.data());
  DCHECK_LE(parsed_.size(), expected_parsed_size);

  DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 2]);
  DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 1]);
}

scoped_refptr<HttpResponseHeaders> HttpResponseHeaders::TryToCreate(
    std::string_view headers) {
  // Reject strings with nulls.
  if (HasEmbeddedNulls(headers) ||
      headers.size() > std::numeric_limits<int>::max()) {
    return nullptr;
  }

  return base::MakeRefCounted<HttpResponseHeaders>(
      HttpUtil::AssembleRawHeaders(headers));
}

scoped_refptr<HttpResponseHeaders> HttpResponseHeaders::TryToCreateForDataURL(
    std::string_view content_type) {
  // Reject strings with nulls.
  if (HasEmbeddedNulls(content_type) ||
      content_type.size() > std::numeric_limits<int>::max()) {
    return nullptr;
  }

  constexpr char kStatusLineAndHeaderName[] = "HTTP/1.1 200 OK\0Content-Type:";
  std::string raw_headers =
      base::StrCat({std::string_view(kStatusLineAndHeaderName,
                                     sizeof(kStatusLineAndHeaderName) - 1),
                    content_type, std::string_view("\0\0", 2)});

  return base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
}

void HttpResponseHeaders::Persist(base::Pickle* pickle,
                                  PersistOptions options) {
  if (options == PERSIST_RAW) {
    pickle->WriteString(raw_headers_);
    return;  // Done.
  }

  HeaderSet filter_headers;

  // Construct set of headers to filter out based on options.
  if ((options & PERSIST_SANS_NON_CACHEABLE) == PERSIST_SANS_NON_CACHEABLE)
    AddNonCacheableHeaders(&filter_headers);

  if ((options & PERSIST_SANS_COOKIES) == PERSIST_SANS_COOKIES)
    AddCookieHeaders(&filter_headers);

  if ((options & PERSIST_SANS_CHALLENGES) == PERSIST_SANS_CHALLENGES)
    AddChallengeHeaders(&filter_headers);

  if ((options & PERSIST_SANS_HOP_BY_HOP) == PERSIST_SANS_HOP_BY_HOP)
    AddHopByHopHeaders(&filter_headers);

  if ((options & PERSIST_SANS_RANGES) == PERSIST_SANS_RANGES)
    AddHopContentRangeHeaders(&filter_headers);

  if ((options & PERSIST_SANS_SECURITY_STATE) == PERSIST_SANS_SECURITY_STATE)
    AddSecurityStateHeaders(&filter_headers);

  std::string blob;
  blob.reserve(raw_headers_.size());

  // This copies the status line w/ terminator null.
  // Note raw_headers_ has embedded nulls instead of \n,
  // so this just copies the first header line.
  blob.assign(raw_headers_.c_str(), strlen(raw_headers_.c_str()) + 1);

  for (size_t i = 0; i < parsed_.size(); ++i) {
    DCHECK(!parsed_[i].is_continuation());

    // Locate the start of the next header.
    size_t k = i;
    while (++k < parsed_.size() && parsed_[k].is_continuation()) {}
    --k;

    std::string header_name = base::ToLowerASCII(
        base::MakeStringPiece(parsed_[i].name_begin, parsed_[i].name_end));
    if (filter_headers.find(header_name) == filter_headers.end()) {
      // Make sure there is a null after the value.
      blob.append(parsed_[i].name_begin, parsed_[k].value_end);
      blob.push_back('\0');
    }

    i = k;
  }
  blob.push_back('\0');

  pickle->WriteString(blob);
}

void HttpResponseHeaders::Update(const HttpResponseHeaders& new_headers) {
  DCHECK(new_headers.response_code() == HTTP_NOT_MODIFIED ||
         new_headers.response_code() == HTTP_PARTIAL_CONTENT);

  // Copy up to the null byte.  This just copies the status line.
  std::string new_raw_headers(raw_headers_.c_str());
  new_raw_headers.push_back('\0');

  HeaderSet updated_headers;

  // NOTE: we write the new headers then the old headers for convenience.  The
  // order should not matter.

  // Figure out which headers we want to take from new_headers:
  for (size_t i = 0; i < new_headers.parsed_.size(); ++i) {
    const HeaderList& new_parsed = new_headers.parsed_;

    DCHECK(!new_parsed[i].is_continuation());

    // Locate the start of the next header.
    size_t k = i;
    while (++k < new_parsed.size() && new_parsed[k].is_continuation()) {}
    --k;

    auto name =
        base::MakeStringPiece(new_parsed[i].name_begin, new_parsed[i].name_end);
    if (ShouldUpdateHeader(name)) {
      std::string name_lower = base::ToLowerASCII(name);
      updated_headers.insert(name_lower);

      // Preserve this header line in the merged result, making sure there is
      // a null after the value.
      new_raw_headers.append(new_parsed[i].name_begin, new_parsed[k].value_end);
      new_raw_headers.push_back('\0');
    }

    i = k;
  }

  // Now, build the new raw headers.
  MergeWithHeaders(std::move(new_raw_headers), updated_headers);
}

void HttpResponseHeaders::MergeWithHeaders(std::string raw_headers,
                                           const HeaderSet& headers_to_remove) {
  for (size_t i = 0; i < parsed_.size(); ++i) {
    DCHECK(!parsed_[i].is_continuation());

    // Locate the start of the next header.
    size_t k = i;
    while (++k < parsed_.size() && parsed_[k].is_continuation()) {}
    --k;

    std::string name = base::ToLowerASCII(
        base::MakeStringPiece(parsed_[i].name_begin, parsed_[i].name_end));
    if (headers_to_remove.find(name) == headers_to_remove.end()) {
      // It's ok to preserve this header in the final result.
      raw_headers.append(parsed_[i].name_begin, parsed_[k].value_end);
      raw_headers.push_back('\0');
    }

    i = k;
  }
  raw_headers.push_back('\0');

  // Make this object hold the new data.
  raw_headers_.clear();
  parsed_.clear();
  Parse(raw_headers);
}

void HttpResponseHeaders::RemoveHeader(std::string_view name) {
  // Copy up to the null byte.  This just copies the status line.
  std::string new_raw_headers(raw_headers_.c_str());
  new_raw_headers.push_back('\0');

  HeaderSet to_remove;
  to_remove.insert(base::ToLowerASCII(name));
  MergeWithHeaders(std::move(new_raw_headers), to_remove);
}

void HttpResponseHeaders::RemoveHeaders(
    const std::unordered_set<std::string>& header_names) {
  // Copy up to the null byte.  This just copies the status line.
  std::string new_raw_headers(raw_headers_.c_str());
  new_raw_headers.push_back('\0');

  HeaderSet to_remove;
  for (const auto& header_name : header_names) {
    to_remove.insert(base::ToLowerASCII(header_name));
  }
  MergeWithHeaders(std::move(new_raw_headers), to_remove);
}

void HttpResponseHeaders::RemoveHeaderLine(const std::string& name,
                                           const std::string& value) {
  std::string name_lowercase = base::ToLowerASCII(name);

  std::string new_raw_headers(GetStatusLine());
  new_raw_headers.push_back('\0');

  new_raw_headers.reserve(raw_headers_.size());

  size_t iter = 0;
  std::string old_header_name;
  std::string old_header_value;
  while (EnumerateHeaderLines(&iter, &old_header_name, &old_header_value)) {
    std::string old_header_name_lowercase = base::ToLowerASCII(old_header_name);
    if (name_lowercase == old_header_name_lowercase &&
        value == old_header_value)
      continue;

    new_raw_headers.append(old_header_name);
    new_raw_headers.push_back(':');
    new_raw_headers.push_back(' ');
    new_raw_headers.append(old_header_value);
    new_raw_headers.push_back('\0');
  }
  new_raw_headers.push_back('\0');

  // Make this object hold the new data.
  raw_headers_.clear();
  parsed_.clear();
  Parse(new_raw_headers);
}

void HttpResponseHeaders::AddHeader(std::string_view name,
                                    std::string_view value) {
  DCHECK(HttpUtil::IsValidHeaderName(name));
  DCHECK(HttpUtil::IsValidHeaderValue(value));

  // Don't copy the last null.
  std::string new_raw_headers(raw_headers_, 0, raw_headers_.size() - 1);
  new_raw_headers.append(name.begin(), name.end());
  new_raw_headers.append(": ");
  new_raw_headers.append(value.begin(), value.end());
  new_raw_headers.push_back('\0');
  new_raw_headers.push_back('\0');

  // Make this object hold the new data.
  raw_headers_.clear();
  parsed_.clear();
  Parse(new_raw_headers);
}

void HttpResponseHeaders::SetHeader(std::string_view name,
                                    std::string_view value) {
  RemoveHeader(name);
  AddHeader(name, value);
}

void HttpResponseHeaders::AddCookie(const std::string& cookie_string) {
  AddHeader("Set-Cookie", cookie_string);
}

void HttpResponseHeaders::ReplaceStatusLine(const std::string& new_status) {
  CheckDoesNotHaveEmbeddedNulls(new_status);
  // Copy up to the null byte.  This just copies the status line.
  std::string new_raw_headers(new_status);
  new_raw_headers.push_back('\0');

  HeaderSet empty_to_remove;
  MergeWithHeaders(std::move(new_raw_headers), empty_to_remove);
}

void HttpResponseHeaders::UpdateWithNewRange(const HttpByteRange& byte_range,
                                             int64_t resource_size,
                                             bool replace_status_line) {
  DCHECK(byte_range.IsValid());
  DCHECK(byte_range.HasFirstBytePosition());
  DCHECK(byte_range.HasLastBytePosition());

  const char kLengthHeader[] = "Content-Length";
  const char kRangeHeader[] = "Content-Range";

  RemoveHeader(kLengthHeader);
  RemoveHeader(kRangeHeader);

  int64_t start = byte_range.first_byte_position();
  int64_t end = byte_range.last_byte_position();
  int64_t range_len = end - start + 1;

  if (replace_status_line)
    ReplaceStatusLine("HTTP/1.1 206 Partial Content");

  AddHeader(kRangeHeader,
            base::StringPrintf("bytes %" PRId64 "-%" PRId64 "/%" PRId64, start,
                               end, resource_size));
  AddHeader(kLengthHeader, base::StringPrintf("%" PRId64, range_len));
}

void HttpResponseHeaders::Parse(const std::string& raw_input) {
  raw_headers_.reserve(raw_input.size());
  // TODO(crbug.com/40277776): Call reserve() on `parsed_` with an
  // appropriate value.

  // ParseStatusLine adds a normalized status line to raw_headers_
  std::string::const_iterator line_begin = raw_input.begin();
  std::string::const_iterator line_end = base::ranges::find(raw_input, '\0');
  // has_headers = true, if there is any data following the status line.
  // Used by ParseStatusLine() to decide if a HTTP/0.9 is really a HTTP/1.0.
  bool has_headers =
      (line_end != raw_input.end() && (line_end + 1) != raw_input.end() &&
       *(line_end + 1) != '\0');
  ParseStatusLine(line_begin, line_end, has_headers);
  raw_headers_.push_back('\0');  // Terminate status line with a null.

  if (line_end == raw_input.end()) {
    raw_headers_.push_back('\0');  // Ensure the headers end with a double null.

    DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 2]);
    DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 1]);
    return;
  }

  // Including a terminating null byte.
  size_t status_line_len = raw_headers_.size();

  // Now, we add the rest of the raw headers to raw_headers_, and begin parsing
  // it (to populate our parsed_ vector).
  raw_headers_.append(line_end + 1, raw_input.end());

  // Ensure the headers end with a double null.
  while (raw_headers_.size() < 2 ||
         raw_headers_[raw_headers_.size() - 2] != '\0' ||
         raw_headers_[raw_headers_.size() - 1] != '\0') {
    raw_headers_.push_back('\0');
  }

  // Adjust to point at the null byte following the status line
  line_end = raw_headers_.begin() + status_line_len - 1;

  HttpUtil::HeadersIterator headers(line_end + 1, raw_headers_.end(),
                                    std::string(1, '\0'));
  while (headers.GetNext()) {
    AddHeader(headers.name_begin(), headers.name_end(), headers.values_begin(),
              headers.values_end(), ContainsCommas::kMaybe);
  }

  DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 2]);
  DCHECK_EQ('\0', raw_headers_[raw_headers_.size() - 1]);
}

std::optional<std::string> HttpResponseHeaders::GetNormalizedHeader(
    std::string_view name) const {
  // If you hit this assertion, please use EnumerateHeader instead!
  DCHECK(!HttpUtil::IsNonCoalescingHeader(name));

  std::optional<std::string> value;
  for (size_t i = 0; i < parsed_.size();) {
    i = FindHeader(i, name);
    if (i == std::string::npos)
      break;

    if (value) {
      value->append(", ");
    } else {
      value.emplace();
    }

    std::string::const_iterator value_begin = parsed_[i].value_begin;
    std::string::const_iterator value_end = parsed_[i].value_end;
    while (++i < parsed_.size() && parsed_[i].is_continuation())
      value_end = parsed_[i].value_end;
    value->append(value_begin, value_end);
  }

  return value;
}

std::string HttpResponseHeaders::GetStatusLine() const {
  // copy up to the null byte.
  return std::string(raw_headers_.c_str());
}

std::string HttpResponseHeaders::GetStatusText() const {
  // GetStatusLine() is already normalized, so it has the format:
  // '<http_version> SP <response_code>' or
  // '<http_version> SP <response_code> SP <status_text>'.
  std::string status_text = GetStatusLine();
  // Seek to beginning of <response_code>.
  std::string::const_iterator begin = base::ranges::find(status_text, ' ');
  std::string::const_iterator end = status_text.end();
  CHECK(begin != end);
  ++begin;
  CHECK(begin != end);
  // See if there is another space.
  begin = std::find(begin, end, ' ');
  if (begin == end)
    return std::string();
  ++begin;
  CHECK(begin != end);
  return std::string(begin, end);
}

bool HttpResponseHeaders::EnumerateHeaderLines(size_t* iter,
                                               std::string* name,
                                               std::string* value) const {
  size_t i = *iter;
  if (i == parsed_.size())
    return false;

  DCHECK(!parsed_[i].is_continuation());

  name->assign(parsed_[i].name_begin, parsed_[i].name_end);

  std::string::const_iterator value_begin = parsed_[i].value_begin;
  std::string::const_iterator value_end = parsed_[i].value_end;
  while (++i < parsed_.size() && parsed_[i].is_continuation())
    value_end = parsed_[i].value_end;

  value->assign(value_begin, value_end);

  *iter = i;
  return true;
}

std::optional<std::string_view> HttpResponseHeaders::EnumerateHeader(
    size_t* iter,
    std::string_view name) const {
  size_t i;
  if (!iter || !*iter) {
    i = FindHeader(0, name);
  } else {
    i = *iter;
    if (i >= parsed_.size()) {
      i = std::string::npos;
    } else if (!parsed_[i].is_continuation()) {
      i = FindHeader(i, name);
    }
  }

  if (i == std::string::npos) {
    return std::nullopt;
  }

  if (iter)
    *iter = i + 1;
  return std::string_view(parsed_[i].value_begin, parsed_[i].value_end);
}

bool HttpResponseHeaders::EnumerateHeader(size_t* iter,
                                          std::string_view name,
                                          std::string* value) const {
  std::optional<std::string_view> result = EnumerateHeader(iter, name);
  if (!result) {
    value->clear();
    return false;
  }
  value->assign(*result);
  return true;
}

bool HttpResponseHeaders::HasHeaderValue(std::string_view name,
                                         std::string_view value) const {
  // The value has to be an exact match.  This is important since
  // 'cache-control: no-cache' != 'cache-control: no-cache="foo"'
  size_t iter = 0;
  std::optional<std::string_view> temp;
  while ((temp = EnumerateHeader(&iter, name))) {
    if (base::EqualsCaseInsensitiveASCII(value, *temp)) {
      return true;
    }
  }
  return false;
}

bool HttpResponseHeaders::HasHeader(std::string_view name) const {
  return FindHeader(0, name) != std::string::npos;
}

HttpResponseHeaders::~HttpResponseHeaders() = default;

// Note: this implementation implicitly assumes that line_end points at a valid
// sentinel character (such as '\0').
// static
HttpVersion HttpResponseHeaders::ParseVersion(
    std::string::const_iterator line_begin,
    std::string::const_iterator line_end) {
  std::string::const_iterator p = line_begin;

  // RFC9112 Section 2.3:
  // HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
  // HTTP-name     = %s"HTTP"

  if (!base::StartsWith(base::MakeStringPiece(line_begin, line_end), "http",
                        base::CompareCase::INSENSITIVE_ASCII)) {
    DVLOG(1) << "missing status line";
    return HttpVersion();
  }

  p += 4;

  if (p >= line_end || *p != '/') {
    DVLOG(1) << "missing version";
    return HttpVersion();
  }

  std::string::const_iterator dot = std::find(p, line_end, '.');
  if (dot == line_end) {
    DVLOG(1) << "malformed version";
    return HttpVersion();
  }

  ++p;  // from / to first digit.
  ++dot;  // from . to second digit.

  if (!(base::IsAsciiDigit(*p) && base::IsAsciiDigit(*dot))) {
    DVLOG(1) << "malformed version number";
    return HttpVersion();
  }

  uint16_t major = *p - '0';
  uint16_t minor = *dot - '0';

  return HttpVersion(major, minor);
}

// Note: this implementation implicitly assumes that line_end points at a valid
// sentinel character (such as '\0').
void HttpResponseHeaders::ParseStatusLine(
    std::string::const_iterator line_begin,
    std::string::const_iterator line_end,
    bool has_headers) {
  // Extract the version number
  HttpVersion parsed_http_version = ParseVersion(line_begin, line_end);

  // Clamp the version number to one of: {0.9, 1.0, 1.1, 2.0}
  if (parsed_http_version == HttpVersion(0, 9) && !has_headers) {
    http_version_ = HttpVersion(0, 9);
    raw_headers_ = "HTTP/0.9";
  } else if (parsed_http_version == HttpVersion(2, 0)) {
    http_version_ = HttpVersion(2, 0);
    raw_headers_ = "HTTP/2.0";
  } else if (parsed_http_version >= HttpVersion(1, 1)) {
    http_version_ = HttpVersion(1, 1);
    raw_headers_ = "HTTP/1.1";
  } else {
    // Treat everything else like HTTP 1.0
    http_version_ = HttpVersion(1, 0);
    raw_headers_ = "HTTP/1.0";
  }
  if (parsed_http_version != http_version_) {
    DVLOG(1) << "assuming HTTP/" << http_version_.major_value() << "."
             << http_version_.minor_value();
  }

  // TODO(eroman): this doesn't make sense if ParseVersion failed.
  std::string::const_iterator p = std::find(line_begin, line_end, ' ');

  if (p == line_end) {
    DVLOG(1) << "missing response status; assuming 200 OK";
    raw_headers_.append(" 200 OK");
    response_code_ = HTTP_OK;
    return;
  }

  response_code_ =
      ParseStatus(base::MakeStringPiece(p + 1, line_end), raw_headers_);
}

size_t HttpResponseHeaders::FindHeader(size_t from,
                                       std::string_view search) const {
  for (size_t i = from; i < parsed_.size(); ++i) {
    if (parsed_[i].is_continuation())
      continue;
    auto name =
        base::MakeStringPiece(parsed_[i].name_begin, parsed_[i].name_end);
    if (base::EqualsCaseInsensitiveASCII(search, name))
      return i;
  }

  return std::string::npos;
}

std::optional<base::TimeDelta> HttpResponseHeaders::GetCacheControlDirective(
    std::string_view directive) const {
  static constexpr std::string_view name("cache-control");
  std::optional<std::string_view> value;

  size_t directive_size = directive.size();

  size_t iter = 0;
  while ((value = EnumerateHeader(&iter, name))) {
    if (!base::StartsWith(*value, directive,
                          base::CompareCase::INSENSITIVE_ASCII)) {
      continue;
    }
    if (value->size() == directive_size || (*value)[directive_size] != '=') {
      continue;
    }
    // 1*DIGIT with leading and trailing spaces, as described at
    // https://datatracker.ietf.org/doc/html/rfc7234#section-1.2.1.
    auto start = value->cbegin() + directive_size + 1;
    auto end = value->cend();
    while (start < end && *start == ' ') {
      // leading spaces
      ++start;
    }
    while (start < end - 1 && *(end - 1) == ' ') {
      // trailing spaces
      --end;
    }
    if (start == end ||
        !std::all_of(start, end, [](char c) { return '0' <= c && c <= '9'; })) {
      continue;
    }
    int64_t seconds = 0;
    base::StringToInt64(base::MakeStringPiece(start, end), &seconds);
    // We ignore the return value because we've already checked the input
    // string. For the overflow case we use
    // base::TimeDelta::FiniteMax().InSeconds().
    seconds = std::min(seconds, base::TimeDelta::FiniteMax()
"""


```