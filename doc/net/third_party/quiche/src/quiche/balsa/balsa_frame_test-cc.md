Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc`. The request has several specific constraints:

1. **List the functionalities:** I need to identify the key purposes and actions of the code.
2. **Relate to JavaScript (if applicable):** I should check if any of the functionalities have counterparts or are relevant in a JavaScript context, providing examples if they do.
3. **Provide logic inference with input/output:**  If the code performs logical operations, I need to demonstrate this with hypothetical inputs and their corresponding outputs.
4. **Illustrate common user/programming errors:** I should identify potential pitfalls or mistakes users or programmers could make when interacting with or using this code, with examples.
5. **Explain user actions leading to the code:**  I need to describe the steps a user might take that would eventually involve this code in the Chromium networking stack.
6. **This is part 1 of 6:**  I should focus on the content within this specific snippet and avoid drawing conclusions about the entire file based on just this part.
7. **Summarize the functionality:** I need to provide a concise overview of the purpose of this code segment.

**My Analysis of the Code Snippet:**

This file appears to be a unit test suite for the `BalsaFrame` class in the Quiche library. Key observations:

* **Includes:** It includes headers for `BalsaFrame`, standard C++ libraries, and several Quiche-specific headers related to HTTP parsing (`BalsaHeaders`, `BalsaVisitorInterface`).
* **Test Fixture:** It defines a test fixture `HTTPBalsaFrameTest` which sets up a `BalsaFrame` and a mock visitor.
* **Helper Functions:**  It contains numerous helper functions like `CreateFirstLine`, `CreateMessage`, `VerifyRequestFirstLine`, `VerifyResponseFirstLine`, `VerifyHeaderLines`, `FirstLineParsedCorrectlyHelper`. These functions are designed to construct and verify HTTP messages for testing purposes.
* **Test Cases:**  It includes several `TEST_F` macros that represent individual test cases for different aspects of `BalsaFrame`'s functionality, such as parsing first lines, handling trailers, and verifying error conditions.
* **Randomness:** It uses a random number generator, potentially for generating varied test inputs.
* **Mocking:** It utilizes Google Mock (`NiceMock`) to create mock implementations of the `BalsaVisitorInterface`, allowing for verification of interactions.
* **Focus on HTTP Framing:** The tests seem to focus heavily on the process of taking raw byte streams and parsing them into HTTP message components like headers, body, and trailers.

**Plan for Generating the Response:**

1. **Summarize overall functionality:** Start by stating that this is a unit test file for `BalsaFrame`, responsible for testing HTTP framing.
2. **List key functionalities:**  Enumerate the core testing aspects covered by this part of the file, such as parsing first lines, handling trailers, checking error conditions, and using helper functions for test setup.
3. **Address JavaScript relevance:** Explain that while directly written in C++, the underlying concepts of HTTP parsing are universal and relevant to JavaScript's handling of network requests and responses. Provide examples like `fetch` API and Node.js HTTP modules.
4. **Illustrate logic inference:** Focus on the `VerifyRequestFirstLine` and `VerifyResponseFirstLine` functions. Provide example inputs (the `tokens` array) and how they are expected to map to the `BalsaHeaders` object.
5. **Identify common errors:** Highlight scenarios like malformed HTTP messages (missing whitespace, incorrect line endings, missing colons in headers/trailers) as common errors that the tests are designed to catch.
6. **Explain user actions:** Describe a typical user scenario, like a web browser making an HTTP request, and how the Chromium networking stack, including `BalsaFrame`, would be involved in parsing the server's response.
7. **Reiterate this is part 1:** Emphasize that the summary is based only on this initial section.
```cpp
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/balsa/balsa_frame.h"

#include <stdlib.h>

#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "quiche/balsa/balsa_enums.h"
#include "quiche/balsa/balsa_headers.h"
#include "quiche/balsa/balsa_visitor_interface.h"
#include "quiche/balsa/http_validation_policy.h"
#include "quiche/balsa/noop_balsa_visitor.h"
#include "quiche/balsa/simple_buffer.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::InSequence;
using ::testing::IsEmpty;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Property;
using ::testing::Range;
using ::testing::StrEq;
using ::testing::StrictMock;

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, randseed, "",
    "This is the seed for Pseudo-random number"
    " generator used when generating random messages for unittests");

namespace quiche::test {

// This random engine from the standard library supports initialization with a
// seed, which is helpful for reproducing any unit test failures that are due to
// random sequence variation.
using RandomEngine = std::mt19937;

class BalsaFrameTestPeer {
 public:
  static int32_t HeaderFramingFound(BalsaFrame* balsa_frame, char c) {
    return balsa_frame->HeaderFramingFound(c);
  }

  static void FindColonsAndParseIntoKeyValue(BalsaFrame* balsa_frame,
                                             const BalsaFrame::Lines& lines,
                                             bool is_trailer,
                                             BalsaHeaders* headers) {
    balsa_frame->FindColonsAndParseIntoKeyValue(lines, is_trailer, headers);
  }
};

class BalsaHeadersTestPeer {
 public:
  static void WriteFromFramer(BalsaHeaders* headers, const char* ptr,
                              size_t size) {
    headers->WriteFromFramer(ptr, size);
  }
};

namespace {

// This class encapsulates the policy of seed selection. If user supplies a
// valid use via the --randseed flag, GetSeed will only return the user
// supplied seed value. This is useful in reproducing bugs reported by the
// test. If an invalid seed value is supplied (likely due to bad numeric
// format), the test will abort (since this mode tend to be used for debugging,
// it is better to die early so the user knows a bad value is supplied). If no
// seed is supplied, the value supplied by ACMRandom::HostnamePidTimeSeed() is
// used. This class is supposed to be a singleton, but there is no ill-effect if
// multiple instances are created (although that tends not to be what the user
// wants).
class TestSeed {
 public:
  TestSeed() : test_seed_(0), user_supplied_seed_(false) {}

  void Initialize(const std::string& seed_flag) {
    if (!seed_flag.empty()) {
      ASSERT_TRUE(absl::SimpleAtoi(seed_flag, &test_seed_));
      user_supplied_seed_ = true;
    }
  }

  int GetSeed() const {
    int seed =
        (user_supplied_seed_ ? test_seed_
                             : testing::UnitTest::GetInstance()->random_seed());
    QUICHE_LOG(INFO) << "**** The current seed is " << seed << " ****";
    return seed;
  }

 private:
  int test_seed_;
  bool user_supplied_seed_;
};

static bool RandomBool(RandomEngine& rng) { return rng() % 2 != 0; }

std::string EscapeString(absl::string_view message) {
  return absl::StrReplaceAll(
      message, {{"\n", "\\\\n\n"}, {"\\r", "\\\\r"}, {"\\t", "\\\\t"}});
}

char random_lws(RandomEngine& rng) {
  if (RandomBool(rng)) {
    return '\t';
  }
  return ' ';
}

const char* random_line_term(RandomEngine& rng) {
  if (RandomBool(rng)) {
    return "\r\n";
  }
  return "\n";
}

void AppendRandomWhitespace(RandomEngine& rng, std::stringstream* s) {
  // Appending a random amount of whitespace to the unparsed value. There is a
  // max of 1000 pieces of whitespace that will be attached, however, it is
  // extremely unlikely (1 in 2^1000) that we'll hit this limit, as we have a
  // 50% probability of exiting the loop at any point in time.
  for (int i = 0; i < 1000 && RandomBool(rng); ++i) {
    *s << random_lws(rng);
  }
}

// Creates an HTTP message firstline from the given inputs.
//
// tokens - The list of nonwhitespace tokens (which should later be parsed out
//          from the firstline).
// whitespace - the whitespace that occurs before, between, and
//              after the tokens. Note that the last whitespace
//              character should -not- include any '\n'.
// line_ending - one of "\n" or "\r\n"
//
// whitespace[0] occurs before the first token.
// whitespace[1] occurs between the first and second token
// whitespace[2] occurs between the second and third token
// whitespace[3] occurs between the third token and the line_ending.
//
// This code:
//   const char tokens[3] = {"GET", "/", "HTTP/1.0"};
//   const char whitespace[4] = { "\n\n", " ", "\t", "\t"};
//   const char line_ending = "\r\n";
//   CreateFirstLine(tokens, whitespace, line_ending) ->
// Would yield the following string:
//   string(
//     "\n"
//     "\n"
//     "GET /\tHTTP/1.0\t\r\n"
//   );
//
std::string CreateFirstLine(const char* tokens[3], const char* whitespace[4],
                            const char* line_ending) {
  QUICHE_CHECK(tokens != nullptr);
  QUICHE_CHECK(whitespace != nullptr);
  QUICHE_CHECK(line_ending != nullptr);
  QUICHE_CHECK(std::string(line_ending) == "\n" ||
               std::string(line_ending) == "\r\n")
      << "line_ending: " << EscapeString(line_ending);
  SimpleBuffer firstline_buffer;
  firstline_buffer.WriteString(whitespace[0]);
  for (int i = 0; i < 3; ++i) {
    firstline_buffer.WriteString(tokens[i]);
    firstline_buffer.WriteString(whitespace[i + 1]);
  }
  firstline_buffer.WriteString(line_ending);
  return std::string(firstline_buffer.GetReadableRegion());
}

// Creates a string (ostensibly an entire HTTP message) from the given input
// arguments.
//
// firstline - the first line of the request or response.
//     The firstline should already have a line-ending on it. If you use the
//     CreateFirstLine function, you'll get a valid firstline string for this
//     function. This may include 'extraneous' whitespace before the first
//     nonwhitespace character, including '\n's
// headers - a list of the -interpreted- key, value pairs.
//     In other words, the value should be what you expect to get out of the
//     headers after framing has occurred (and should include no whitespace
//     before or after the first and list nonwhitespace characters,
//     respectively). While this function will succeed if you don't follow
//     these guidelines, the VerifyHeaderLines function will likely not agree
//     with that input.
// headers_len - the number of key value pairs
// colon - the string that exists between the key and value pairs.
//     It MUST include EXACTLY one colon, and may include any amount of either
//     ' ' or '\t'. Note that for certain key strings, this value will be
//     modified to exclude any leading whitespace. See the body of the function
//     for more details.
// line_ending - one of "\r\n", or "\n\n"
// body - the appropriate body.
//     The CreateMessage function does not do any checking that the headers
//     agree with the present of any body, so the input must be correct given
//     the set of headers.
std::string CreateMessage(const char* firstline,
                          const std::pair<std::string, std::string>* headers,
                          size_t headers_len, const char* colon,
                          const char* line_ending, const char* body) {
  SimpleBuffer request_buffer;
  request_buffer.WriteString(firstline);
  if (headers_len > 0) {
    QUICHE_CHECK(headers != nullptr);
    QUICHE_CHECK(colon != nullptr);
  }
  QUICHE_CHECK(line_ending != nullptr);
  QUICHE_CHECK(std::string(line_ending) == "\n" ||
               std::string(line_ending) == "\r\n")
      << "line_ending: " << EscapeString(line_ending);
  QUICHE_CHECK(body != nullptr);
  for (size_t i = 0; i < headers_len; ++i) {
    bool only_whitespace_in_key = true;
    {
      // If the 'key' part includes no non-whitespace characters, then we need
      // to be sure that the 'colon' part includes no whitespace before the
      // ':'. If it did, then the line would be (correctly!) interpreted as a
      // continuation, and the test would not work properly.
      const char* tmp_key = headers[i].first.c_str();
      while (*tmp_key != '\0') {
        if (*tmp_key > ' ') {
          only_whitespace_in_key = false;
          break;
        }
        ++tmp_key;
      }
    }
    const char* tmp_colon = colon;
    if (only_whitespace_in_key) {
      while (*tmp_colon != ':') {
        ++tmp_colon;
      }
    }
    request_buffer.WriteString(headers[i].first);
    request_buffer.WriteString(tmp_colon);
    request_buffer.WriteString(headers[i].second);
    request_buffer.WriteString(line_ending);
  }
  request_buffer.WriteString(line_ending);
  request_buffer.WriteString(body);
  return std::string(request_buffer.GetReadableRegion());
}

void VerifyRequestFirstLine(const char* tokens[3],
                            const BalsaHeaders& headers) {
  EXPECT_EQ(tokens[0], headers.request_method());
  EXPECT_EQ(tokens[1], headers.request_uri());
  EXPECT_EQ(0u, headers.parsed_response_code());
  EXPECT_EQ(tokens[2], headers.request_version());
}

void VerifyResponseFirstLine(const char* tokens[3],
                             size_t expected_response_code,
                             const BalsaHeaders& headers) {
  EXPECT_EQ(tokens[0], headers.response_version());
  EXPECT_EQ(tokens[1], headers.response_code());
  EXPECT_EQ(expected_response_code, headers.parsed_response_code());
  EXPECT_EQ(tokens[2], headers.response_reason_phrase());
}

// This function verifies that the expected_headers key and values
// are exactly equal to that returned by an iterator to a BalsaHeader
// object.
//
// expected_headers - key, value pairs, in the order in which they're
//                    expected to be returned from the iterator.
// headers_len - as expected, the number of expected key-value pairs.
// headers - the BalsaHeaders from which we'll examine the actual
//           headers.
void VerifyHeaderLines(
    const std::pair<std::string, std::string>* expected_headers,
    size_t headers_len, const BalsaHeaders& headers) {
  BalsaHeaders::const_header_lines_iterator it = headers.lines().begin();
  for (size_t i = 0; it != headers.lines().end(); ++it, ++i) {
    ASSERT_GT(headers_len, i);
    std::string actual_key;
    std::string actual_value;
    if (!it->first.empty()) {
      actual_key = std::string(it->first);
    }
    if (!it->second.empty()) {
      actual_value = std::string(it->second);
    }
    EXPECT_THAT(actual_key, StrEq(expected_headers[i].first));
    EXPECT_THAT(actual_value, StrEq(expected_headers[i].second));
  }
  EXPECT_TRUE(headers.lines().end() == it);
}

void FirstLineParsedCorrectlyHelper(const char* tokens[3],
                                    size_t expected_response_code,
                                    bool is_request, const char* whitespace) {
  BalsaHeaders headers;
  BalsaFrame framer;
  framer.set_is_request(is_request);
  framer.set_balsa_headers(&headers);
  const char* tmp_tokens[3] = {tokens[0], tokens[1], tokens[2]};
  const char* tmp_whitespace[4] = {"", whitespace, whitespace, ""};
  for (int j = 2; j >= 0; --j) {
    framer.Reset();
    std::string firstline = CreateFirstLine(tmp_tokens, tmp_whitespace, "\n");
    std::string message =
        CreateMessage(firstline.c_str(), nullptr, 0, nullptr, "\n", "");
    SCOPED_TRACE(absl::StrFormat("input: \n%s", EscapeString(message)));
    EXPECT_GE(message.size(),
              framer.ProcessInput(message.data(), message.size()));
    // If this is a request then we don't expect a framer error (as we'll be
    // getting back warnings that fields are missing). If, however, this is
    // a response, and it is missing anything other than the reason phrase,
    // the framer will signal an error instead.
    if (is_request || j >= 1) {
      EXPECT_FALSE(framer.Error());
      if (is_request) {
        EXPECT_TRUE(framer.MessageFullyRead());
      }
      if (j == 0) {
        expected_response_code = 0;
      }
      if (is_request) {
        VerifyRequestFirstLine(tmp_tokens, *framer.headers());
      } else {
        VerifyResponseFirstLine(tmp_tokens, expected_response_code,
                                *framer.headers());
      }
    } else {
      EXPECT_TRUE(framer.Error());
    }
    tmp_tokens[j] = "";
    tmp_whitespace[j] = "";
  }
}

TEST(HTTPBalsaFrame, ParseStateToString) {
  EXPECT_STREQ("ERROR",
               BalsaFrameEnums::ParseStateToString(BalsaFrameEnums::ERROR));
  EXPECT_STREQ("READING_HEADER_AND_FIRSTLINE",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE));
  EXPECT_STREQ("READING_CHUNK_LENGTH",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_CHUNK_LENGTH));
  EXPECT_STREQ("READING_CHUNK_EXTENSION",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_CHUNK_EXTENSION));
  EXPECT_STREQ("READING_CHUNK_DATA", BalsaFrameEnums::ParseStateToString(
                                         BalsaFrameEnums::READING_CHUNK_DATA));
  EXPECT_STREQ("READING_CHUNK_TERM", BalsaFrameEnums::ParseStateToString(
                                         BalsaFrameEnums::READING_CHUNK_TERM));
  EXPECT_STREQ("READING_LAST_CHUNK_TERM",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_LAST_CHUNK_TERM));
  EXPECT_STREQ("READING_TRAILER", BalsaFrameEnums::ParseStateToString(
                                      BalsaFrameEnums::READING_TRAILER));
  EXPECT_STREQ("READING_UNTIL_CLOSE",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_UNTIL_CLOSE));
  EXPECT_STREQ("READING_CONTENT", BalsaFrameEnums::ParseStateToString(
                                      BalsaFrameEnums::READING_CONTENT));
  EXPECT_STREQ("MESSAGE_FULLY_READ", BalsaFrameEnums::ParseStateToString(
                                         BalsaFrameEnums::MESSAGE_FULLY_READ));

  EXPECT_STREQ("UNKNOWN_STATE", BalsaFrameEnums::ParseStateToString(
                                    BalsaFrameEnums::NUM_STATES));
  EXPECT_STREQ("UNKNOWN_STATE",
               BalsaFrameEnums::ParseStateToString(
                   static_cast<BalsaFrameEnums::ParseState>(-1)));

  for (int i = 0; i < BalsaFrameEnums::NUM_STATES; ++i) {
    EXPECT_STRNE("UNKNOWN_STATE",
                 BalsaFrameEnums::ParseStateToString(
                     static_cast<BalsaFrameEnums::ParseState>(i)));
  }
}

TEST(HTTPBalsaFrame, ErrorCodeToString) {
  EXPECT_STREQ("NO_STATUS_LINE_IN_RESPONSE",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::NO_STATUS_LINE_IN_RESPONSE));
  EXPECT_STREQ("NO_REQUEST_LINE_IN_REQUEST",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::NO_REQUEST_LINE_IN_REQUEST));
  EXPECT_STREQ("FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION));
  EXPECT_STREQ("FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD));
  EXPECT_STREQ(
      "FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE));
  EXPECT_STREQ(
      "FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI));
  EXPECT_STREQ(
      "FAILED_TO_FIND_NL_AFTER_RESPONSE_REASON_PHRASE",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_NL_AFTER_RESPONSE_REASON_PHRASE));
  EXPECT_STREQ(
      "FAILED_TO_FIND_NL_AFTER_REQUEST_HTTP_VERSION",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_NL_AFTER_REQUEST_HTTP_VERSION));
  EXPECT_STREQ("FAILED_CONVERTING_STATUS_CODE_TO_INT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT));
  EXPECT_STREQ("HEADERS_TOO_LONG", BalsaFrameEnums::ErrorCodeToString(
                                       BalsaFrameEnums::HEADERS_TOO_LONG));
  EXPECT_STREQ("UNPARSABLE_CONTENT_LENGTH",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH));
  EXPECT_STREQ("MAYBE_BODY_BUT_NO_CONTENT_LENGTH",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::MAYBE_BODY_BUT_NO_CONTENT_LENGTH));
  EXPECT_STREQ("HEADER_MISSING_COLON",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::HEADER_MISSING_COLON));
  EXPECT_STREQ("INVALID_CHUNK_LENGTH",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_CHUNK_LENGTH));
  EXPECT_STREQ("CHUNK_LENGTH_OVERFLOW",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW));
  EXPECT_STREQ("CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO));
  EXPECT_STREQ("CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::
                       CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT));
  EXPECT_STREQ("MULTIPLE_CONTENT_LENGTH_KEYS",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::MULTIPLE_CONTENT_LENGTH_KEYS));
  EXPECT_STREQ("MULTIPLE_TRANSFER_ENCODING_KEYS",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::MULTIPLE_TRANSFER_ENCODING_KEYS));
  EXPECT_STREQ("INVALID_HEADER_FORMAT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_HEADER_FORMAT));
  EXPECT_STREQ("INVALID_TRAILER_FORMAT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_TRAILER_FORMAT));
  EXPECT_STREQ("TRAILER_TOO_LONG", BalsaFrameEnums::ErrorCodeToString(
                                       BalsaFrameEnums::TRAILER_TOO_LONG));
  EXPECT_STREQ("TRAILER_MISSING_COLON",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::TRAILER_MISSING_COLON));
  EXPECT_STREQ("INTERNAL_LOGIC_ERROR",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INTERNAL_LOGIC_ERROR));
  EXPECT_STREQ("INVALID_HEADER_CHARACTER",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_HEADER_CHARACTER));

  EXPECT_STREQ("UNKNOWN_ERROR", BalsaFrameEnums::ErrorCodeToString(
                                    BalsaFrameEnums::NUM_ERROR_CODES));
  EXPECT_STREQ("UNKNOWN_ERROR",
               BalsaFrameEnums::ErrorCodeToString(
                   static_cast<BalsaFrameEnums::ErrorCode>(-1)));

  for (int i = 0; i < BalsaFrameEnums::NUM_ERROR_CODES; ++i) {
    EXPECT_STRNE("UNKNOWN_ERROR",
                 BalsaFrameEnums::ErrorCodeToString(
                     static_cast<BalsaFrameEnums::ErrorCode>(i)));
  }
}

class FakeHeaders {
 public:
  struct KeyValuePair {
    KeyValuePair(const std::string& key, const std::string& value)
        : key(key), value(value) {}
    KeyValuePair() {}

    std::string key;
    std::string value;
  };
  typedef std::vector<KeyValuePair> KeyValuePairs;
  KeyValuePairs key_value_pairs_;

  bool operator==(const FakeHeaders& other) const {
    if (key_value_pairs_.size() != other.key_value_pairs_.size()) {
      return false;
    }
    for (KeyValuePairs::size_type i = 0; i < key_value_pairs_.size(); ++i) {
      if (key_value_pairs_[i].key != other.key_value_pairs_[i].key) {
        return false;
      }
      if (key_value_pairs_[i].value != other.key_value_pairs_[i].value) {
        return false;
      }
    }
    return true;
  }

  void AddKeyValue(const std::string& key, const std::string& value) {
    key_value_pairs_.push_back(KeyValuePair(key, value));
  }
};

class BalsaVisitorMock : public BalsaVisitorInterface {
 public:
  ~BalsaVisitorMock() override = default;

  void ProcessHeaders(const BalsaHeaders& headers) override {
    FakeHeaders fake_headers;
    GenerateFakeHeaders(headers, &fake_headers);
    ProcessHeaders(fake_headers);
  }
  void OnTrailers(std::unique_ptr<BalsaHeaders> trailers) override {
    FakeHeaders fake_trailers;
    GenerateFakeHeaders(*trailers, &fake_trailers);
    OnTrailers(fake_trailers);
  }

  MOCK_METHOD(void, OnRawBodyInput, (absl::string_view input), (override));
  MOCK_METHOD(void, OnBodyChunkInput, (absl::string_view input), (override));
  MOCK_METHOD(void, OnHeaderInput, (absl::string_view input), (override));
  MOCK_METHOD(void, OnTrailerInput, (absl::string_view input), (override));
  MOCK_METHOD(void, ProcessHeaders, (const FakeHeaders& headers));
  MOCK_METHOD(void, OnTrailers, (const FakeHeaders& trailers));
  MOCK_METHOD(void, OnRequestFirstLineInput,
              (absl::string_view line_input, absl::string_view method_input,
               absl::string_view request_uri, absl::string_view version_input),
              (override));
  MOCK_METHOD(void, OnResponseFirstLineInput,
              (absl::string_view line_input, absl::string_view version_input,
               absl::string_view status_input, absl::string_view reason_input),
              (override));
  MOCK_METHOD(void, OnChunkLength, (size_t length), (override));
  MOCK_METHOD(void, OnChunkExtensionInput, (absl::string_view input),
              (override));
  MOCK_METHOD(void, OnInterimHeaders, (std::unique_ptr<BalsaHeaders> headers),
              (override));
  MOCK_METHOD(void, ContinueHeaderDone, (), (override));
  MOCK_METHOD(void, HeaderDone, (), (override));
  MOCK_METHOD(void, MessageDone, (), (override));
  MOCK_METHOD(void, HandleError, (BalsaFrameEnums::ErrorCode error_code),
              (override));
  MOCK_METHOD(void, HandleWarning, (BalsaFrameEnums::ErrorCode error_code),
              (override));

 private:
  static void GenerateFakeHeaders(const BalsaHeaders& headers,
                                  FakeHeaders* fake_headers) {
    for (const auto& line : headers.lines()) {
      fake_headers->AddKeyValue(std::string(line.first),
                                std::string(line.second));
    }
  }
};

class HTTPBalsaFrameTest : public QuicheTest {
 protected:
  void SetUp() override {
    balsa_frame_.set_balsa_headers(&headers_);
    balsa_frame_.set_balsa_visitor(&visitor_mock_);
    balsa_frame_.set_is_request(true);
    balsa_frame_.EnableTrailers();
  }

  void VerifyFirstLineParsing(const std::string& firstline,
                              BalsaFrameEnums::ErrorCode error_code) {
    balsa_frame_.ProcessInput(firstline.data(), firstline.size());
    EXPECT_EQ(error_code, balsa_frame_.ErrorCode());
  }

  BalsaHeaders headers_;
  BalsaFrame balsa_frame_;
  NiceMock<BalsaVisitorMock> visitor_mock_;
};

// Test correct return value for HeaderFramingFound.
TEST_F(HTTPBalsaFrameTest, TestHeaderFramingFound) {
  // Pattern \r\n\r\n should match kValidTerm1.
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, ' '));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(BalsaFrame::kValidTerm1,
            BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));

  // Pattern \n\r\n should match kValidTerm1.
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\t'));
  EXPECT_EQ(0, BalsaFrame
### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/balsa/balsa_frame.h"

#include <stdlib.h>

#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "quiche/balsa/balsa_enums.h"
#include "quiche/balsa/balsa_headers.h"
#include "quiche/balsa/balsa_visitor_interface.h"
#include "quiche/balsa/http_validation_policy.h"
#include "quiche/balsa/noop_balsa_visitor.h"
#include "quiche/balsa/simple_buffer.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::InSequence;
using ::testing::IsEmpty;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Property;
using ::testing::Range;
using ::testing::StrEq;
using ::testing::StrictMock;

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, randseed, "",
    "This is the seed for Pseudo-random number"
    " generator used when generating random messages for unittests");

namespace quiche::test {

// This random engine from the standard library supports initialization with a
// seed, which is helpful for reproducing any unit test failures that are due to
// random sequence variation.
using RandomEngine = std::mt19937;

class BalsaFrameTestPeer {
 public:
  static int32_t HeaderFramingFound(BalsaFrame* balsa_frame, char c) {
    return balsa_frame->HeaderFramingFound(c);
  }

  static void FindColonsAndParseIntoKeyValue(BalsaFrame* balsa_frame,
                                             const BalsaFrame::Lines& lines,
                                             bool is_trailer,
                                             BalsaHeaders* headers) {
    balsa_frame->FindColonsAndParseIntoKeyValue(lines, is_trailer, headers);
  }
};

class BalsaHeadersTestPeer {
 public:
  static void WriteFromFramer(BalsaHeaders* headers, const char* ptr,
                              size_t size) {
    headers->WriteFromFramer(ptr, size);
  }
};

namespace {

// This class encapsulates the policy of seed selection. If user supplies a
// valid use via the --randseed flag, GetSeed will only return the user
// supplied seed value. This is useful in reproducing bugs reported by the
// test. If an invalid seed value is supplied (likely due to bad numeric
// format), the test will abort (since this mode tend to be used for debugging,
// it is better to die early so the user knows a bad value is supplied). If no
// seed is supplied, the value supplied by ACMRandom::HostnamePidTimeSeed() is
// used. This class is supposed to be a singleton, but there is no ill-effect if
// multiple instances are created (although that tends not to be what the user
// wants).
class TestSeed {
 public:
  TestSeed() : test_seed_(0), user_supplied_seed_(false) {}

  void Initialize(const std::string& seed_flag) {
    if (!seed_flag.empty()) {
      ASSERT_TRUE(absl::SimpleAtoi(seed_flag, &test_seed_));
      user_supplied_seed_ = true;
    }
  }

  int GetSeed() const {
    int seed =
        (user_supplied_seed_ ? test_seed_
                             : testing::UnitTest::GetInstance()->random_seed());
    QUICHE_LOG(INFO) << "**** The current seed is " << seed << " ****";
    return seed;
  }

 private:
  int test_seed_;
  bool user_supplied_seed_;
};

static bool RandomBool(RandomEngine& rng) { return rng() % 2 != 0; }

std::string EscapeString(absl::string_view message) {
  return absl::StrReplaceAll(
      message, {{"\n", "\\\\n\n"}, {"\\r", "\\\\r"}, {"\\t", "\\\\t"}});
}

char random_lws(RandomEngine& rng) {
  if (RandomBool(rng)) {
    return '\t';
  }
  return ' ';
}

const char* random_line_term(RandomEngine& rng) {
  if (RandomBool(rng)) {
    return "\r\n";
  }
  return "\n";
}

void AppendRandomWhitespace(RandomEngine& rng, std::stringstream* s) {
  // Appending a random amount of whitespace to the unparsed value. There is a
  // max of 1000 pieces of whitespace that will be attached, however, it is
  // extremely unlikely (1 in 2^1000) that we'll hit this limit, as we have a
  // 50% probability of exiting the loop at any point in time.
  for (int i = 0; i < 1000 && RandomBool(rng); ++i) {
    *s << random_lws(rng);
  }
}

// Creates an HTTP message firstline from the given inputs.
//
// tokens - The list of nonwhitespace tokens (which should later be parsed out
//          from the firstline).
// whitespace - the whitespace that occurs before, between, and
//              after the tokens. Note that the last whitespace
//              character should -not- include any '\n'.
// line_ending - one of "\n" or "\r\n"
//
// whitespace[0] occurs before the first token.
// whitespace[1] occurs between the first and second token
// whitespace[2] occurs between the second and third token
// whitespace[3] occurs between the third token and the line_ending.
//
// This code:
//   const char tokens[3] = {"GET", "/", "HTTP/1.0"};
//   const char whitespace[4] = { "\n\n", " ", "\t", "\t"};
//   const char line_ending = "\r\n";
//   CreateFirstLine(tokens, whitespace, line_ending) ->
// Would yield the following string:
//   string(
//     "\n"
//     "\n"
//     "GET /\tHTTP/1.0\t\r\n"
//   );
//
std::string CreateFirstLine(const char* tokens[3], const char* whitespace[4],
                            const char* line_ending) {
  QUICHE_CHECK(tokens != nullptr);
  QUICHE_CHECK(whitespace != nullptr);
  QUICHE_CHECK(line_ending != nullptr);
  QUICHE_CHECK(std::string(line_ending) == "\n" ||
               std::string(line_ending) == "\r\n")
      << "line_ending: " << EscapeString(line_ending);
  SimpleBuffer firstline_buffer;
  firstline_buffer.WriteString(whitespace[0]);
  for (int i = 0; i < 3; ++i) {
    firstline_buffer.WriteString(tokens[i]);
    firstline_buffer.WriteString(whitespace[i + 1]);
  }
  firstline_buffer.WriteString(line_ending);
  return std::string(firstline_buffer.GetReadableRegion());
}

// Creates a string (ostensibly an entire HTTP message) from the given input
// arguments.
//
// firstline - the first line of the request or response.
//     The firstline should already have a line-ending on it.  If you use the
//     CreateFirstLine function, you'll get a valid firstline string for this
//     function.  This may include 'extraneous' whitespace before the first
//     nonwhitespace character, including '\n's
// headers - a list of the -interpreted- key, value pairs.
//     In other words, the value should be what you expect to get out of the
//     headers after framing has occurred (and should include no whitespace
//     before or after the first and list nonwhitespace characters,
//     respectively).  While this function will succeed if you don't follow
//     these guidelines, the VerifyHeaderLines function will likely not agree
//     with that input.
// headers_len - the number of key value pairs
// colon - the string that exists between the key and value pairs.
//     It MUST include EXACTLY one colon, and may include any amount of either
//     ' ' or '\t'. Note that for certain key strings, this value will be
//     modified to exclude any leading whitespace. See the body of the function
//     for more details.
// line_ending - one of "\r\n", or "\n\n"
// body - the appropriate body.
//     The CreateMessage function does not do any checking that the headers
//     agree with the present of any body, so the input must be correct given
//     the set of headers.
std::string CreateMessage(const char* firstline,
                          const std::pair<std::string, std::string>* headers,
                          size_t headers_len, const char* colon,
                          const char* line_ending, const char* body) {
  SimpleBuffer request_buffer;
  request_buffer.WriteString(firstline);
  if (headers_len > 0) {
    QUICHE_CHECK(headers != nullptr);
    QUICHE_CHECK(colon != nullptr);
  }
  QUICHE_CHECK(line_ending != nullptr);
  QUICHE_CHECK(std::string(line_ending) == "\n" ||
               std::string(line_ending) == "\r\n")
      << "line_ending: " << EscapeString(line_ending);
  QUICHE_CHECK(body != nullptr);
  for (size_t i = 0; i < headers_len; ++i) {
    bool only_whitespace_in_key = true;
    {
      // If the 'key' part includes no non-whitespace characters, then we need
      // to be sure that the 'colon' part includes no whitespace before the
      // ':'. If it did, then the line would be (correctly!) interpreted as a
      // continuation, and the test would not work properly.
      const char* tmp_key = headers[i].first.c_str();
      while (*tmp_key != '\0') {
        if (*tmp_key > ' ') {
          only_whitespace_in_key = false;
          break;
        }
        ++tmp_key;
      }
    }
    const char* tmp_colon = colon;
    if (only_whitespace_in_key) {
      while (*tmp_colon != ':') {
        ++tmp_colon;
      }
    }
    request_buffer.WriteString(headers[i].first);
    request_buffer.WriteString(tmp_colon);
    request_buffer.WriteString(headers[i].second);
    request_buffer.WriteString(line_ending);
  }
  request_buffer.WriteString(line_ending);
  request_buffer.WriteString(body);
  return std::string(request_buffer.GetReadableRegion());
}

void VerifyRequestFirstLine(const char* tokens[3],
                            const BalsaHeaders& headers) {
  EXPECT_EQ(tokens[0], headers.request_method());
  EXPECT_EQ(tokens[1], headers.request_uri());
  EXPECT_EQ(0u, headers.parsed_response_code());
  EXPECT_EQ(tokens[2], headers.request_version());
}

void VerifyResponseFirstLine(const char* tokens[3],
                             size_t expected_response_code,
                             const BalsaHeaders& headers) {
  EXPECT_EQ(tokens[0], headers.response_version());
  EXPECT_EQ(tokens[1], headers.response_code());
  EXPECT_EQ(expected_response_code, headers.parsed_response_code());
  EXPECT_EQ(tokens[2], headers.response_reason_phrase());
}

// This function verifies that the expected_headers key and values
// are exactly equal to that returned by an iterator to a BalsaHeader
// object.
//
// expected_headers - key, value pairs, in the order in which they're
//                    expected to be returned from the iterator.
// headers_len - as expected, the number of expected key-value pairs.
// headers - the BalsaHeaders from which we'll examine the actual
//           headers.
void VerifyHeaderLines(
    const std::pair<std::string, std::string>* expected_headers,
    size_t headers_len, const BalsaHeaders& headers) {
  BalsaHeaders::const_header_lines_iterator it = headers.lines().begin();
  for (size_t i = 0; it != headers.lines().end(); ++it, ++i) {
    ASSERT_GT(headers_len, i);
    std::string actual_key;
    std::string actual_value;
    if (!it->first.empty()) {
      actual_key = std::string(it->first);
    }
    if (!it->second.empty()) {
      actual_value = std::string(it->second);
    }
    EXPECT_THAT(actual_key, StrEq(expected_headers[i].first));
    EXPECT_THAT(actual_value, StrEq(expected_headers[i].second));
  }
  EXPECT_TRUE(headers.lines().end() == it);
}

void FirstLineParsedCorrectlyHelper(const char* tokens[3],
                                    size_t expected_response_code,
                                    bool is_request, const char* whitespace) {
  BalsaHeaders headers;
  BalsaFrame framer;
  framer.set_is_request(is_request);
  framer.set_balsa_headers(&headers);
  const char* tmp_tokens[3] = {tokens[0], tokens[1], tokens[2]};
  const char* tmp_whitespace[4] = {"", whitespace, whitespace, ""};
  for (int j = 2; j >= 0; --j) {
    framer.Reset();
    std::string firstline = CreateFirstLine(tmp_tokens, tmp_whitespace, "\n");
    std::string message =
        CreateMessage(firstline.c_str(), nullptr, 0, nullptr, "\n", "");
    SCOPED_TRACE(absl::StrFormat("input: \n%s", EscapeString(message)));
    EXPECT_GE(message.size(),
              framer.ProcessInput(message.data(), message.size()));
    // If this is a request then we don't expect a framer error (as we'll be
    // getting back warnings that fields are missing). If, however, this is
    // a response, and it is missing anything other than the reason phrase,
    // the framer will signal an error instead.
    if (is_request || j >= 1) {
      EXPECT_FALSE(framer.Error());
      if (is_request) {
        EXPECT_TRUE(framer.MessageFullyRead());
      }
      if (j == 0) {
        expected_response_code = 0;
      }
      if (is_request) {
        VerifyRequestFirstLine(tmp_tokens, *framer.headers());
      } else {
        VerifyResponseFirstLine(tmp_tokens, expected_response_code,
                                *framer.headers());
      }
    } else {
      EXPECT_TRUE(framer.Error());
    }
    tmp_tokens[j] = "";
    tmp_whitespace[j] = "";
  }
}

TEST(HTTPBalsaFrame, ParseStateToString) {
  EXPECT_STREQ("ERROR",
               BalsaFrameEnums::ParseStateToString(BalsaFrameEnums::ERROR));
  EXPECT_STREQ("READING_HEADER_AND_FIRSTLINE",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE));
  EXPECT_STREQ("READING_CHUNK_LENGTH",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_CHUNK_LENGTH));
  EXPECT_STREQ("READING_CHUNK_EXTENSION",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_CHUNK_EXTENSION));
  EXPECT_STREQ("READING_CHUNK_DATA", BalsaFrameEnums::ParseStateToString(
                                         BalsaFrameEnums::READING_CHUNK_DATA));
  EXPECT_STREQ("READING_CHUNK_TERM", BalsaFrameEnums::ParseStateToString(
                                         BalsaFrameEnums::READING_CHUNK_TERM));
  EXPECT_STREQ("READING_LAST_CHUNK_TERM",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_LAST_CHUNK_TERM));
  EXPECT_STREQ("READING_TRAILER", BalsaFrameEnums::ParseStateToString(
                                      BalsaFrameEnums::READING_TRAILER));
  EXPECT_STREQ("READING_UNTIL_CLOSE",
               BalsaFrameEnums::ParseStateToString(
                   BalsaFrameEnums::READING_UNTIL_CLOSE));
  EXPECT_STREQ("READING_CONTENT", BalsaFrameEnums::ParseStateToString(
                                      BalsaFrameEnums::READING_CONTENT));
  EXPECT_STREQ("MESSAGE_FULLY_READ", BalsaFrameEnums::ParseStateToString(
                                         BalsaFrameEnums::MESSAGE_FULLY_READ));

  EXPECT_STREQ("UNKNOWN_STATE", BalsaFrameEnums::ParseStateToString(
                                    BalsaFrameEnums::NUM_STATES));
  EXPECT_STREQ("UNKNOWN_STATE",
               BalsaFrameEnums::ParseStateToString(
                   static_cast<BalsaFrameEnums::ParseState>(-1)));

  for (int i = 0; i < BalsaFrameEnums::NUM_STATES; ++i) {
    EXPECT_STRNE("UNKNOWN_STATE",
                 BalsaFrameEnums::ParseStateToString(
                     static_cast<BalsaFrameEnums::ParseState>(i)));
  }
}

TEST(HTTPBalsaFrame, ErrorCodeToString) {
  EXPECT_STREQ("NO_STATUS_LINE_IN_RESPONSE",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::NO_STATUS_LINE_IN_RESPONSE));
  EXPECT_STREQ("NO_REQUEST_LINE_IN_REQUEST",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::NO_REQUEST_LINE_IN_REQUEST));
  EXPECT_STREQ("FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION));
  EXPECT_STREQ("FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD));
  EXPECT_STREQ(
      "FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE));
  EXPECT_STREQ(
      "FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI));
  EXPECT_STREQ(
      "FAILED_TO_FIND_NL_AFTER_RESPONSE_REASON_PHRASE",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_NL_AFTER_RESPONSE_REASON_PHRASE));
  EXPECT_STREQ(
      "FAILED_TO_FIND_NL_AFTER_REQUEST_HTTP_VERSION",
      BalsaFrameEnums::ErrorCodeToString(
          BalsaFrameEnums::FAILED_TO_FIND_NL_AFTER_REQUEST_HTTP_VERSION));
  EXPECT_STREQ("FAILED_CONVERTING_STATUS_CODE_TO_INT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT));
  EXPECT_STREQ("HEADERS_TOO_LONG", BalsaFrameEnums::ErrorCodeToString(
                                       BalsaFrameEnums::HEADERS_TOO_LONG));
  EXPECT_STREQ("UNPARSABLE_CONTENT_LENGTH",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH));
  EXPECT_STREQ("MAYBE_BODY_BUT_NO_CONTENT_LENGTH",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::MAYBE_BODY_BUT_NO_CONTENT_LENGTH));
  EXPECT_STREQ("HEADER_MISSING_COLON",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::HEADER_MISSING_COLON));
  EXPECT_STREQ("INVALID_CHUNK_LENGTH",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_CHUNK_LENGTH));
  EXPECT_STREQ("CHUNK_LENGTH_OVERFLOW",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW));
  EXPECT_STREQ("CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO));
  EXPECT_STREQ("CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::
                       CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT));
  EXPECT_STREQ("MULTIPLE_CONTENT_LENGTH_KEYS",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::MULTIPLE_CONTENT_LENGTH_KEYS));
  EXPECT_STREQ("MULTIPLE_TRANSFER_ENCODING_KEYS",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::MULTIPLE_TRANSFER_ENCODING_KEYS));
  EXPECT_STREQ("INVALID_HEADER_FORMAT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_HEADER_FORMAT));
  EXPECT_STREQ("INVALID_TRAILER_FORMAT",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_TRAILER_FORMAT));
  EXPECT_STREQ("TRAILER_TOO_LONG", BalsaFrameEnums::ErrorCodeToString(
                                       BalsaFrameEnums::TRAILER_TOO_LONG));
  EXPECT_STREQ("TRAILER_MISSING_COLON",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::TRAILER_MISSING_COLON));
  EXPECT_STREQ("INTERNAL_LOGIC_ERROR",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INTERNAL_LOGIC_ERROR));
  EXPECT_STREQ("INVALID_HEADER_CHARACTER",
               BalsaFrameEnums::ErrorCodeToString(
                   BalsaFrameEnums::INVALID_HEADER_CHARACTER));

  EXPECT_STREQ("UNKNOWN_ERROR", BalsaFrameEnums::ErrorCodeToString(
                                    BalsaFrameEnums::NUM_ERROR_CODES));
  EXPECT_STREQ("UNKNOWN_ERROR",
               BalsaFrameEnums::ErrorCodeToString(
                   static_cast<BalsaFrameEnums::ErrorCode>(-1)));

  for (int i = 0; i < BalsaFrameEnums::NUM_ERROR_CODES; ++i) {
    EXPECT_STRNE("UNKNOWN_ERROR",
                 BalsaFrameEnums::ErrorCodeToString(
                     static_cast<BalsaFrameEnums::ErrorCode>(i)));
  }
}

class FakeHeaders {
 public:
  struct KeyValuePair {
    KeyValuePair(const std::string& key, const std::string& value)
        : key(key), value(value) {}
    KeyValuePair() {}

    std::string key;
    std::string value;
  };
  typedef std::vector<KeyValuePair> KeyValuePairs;
  KeyValuePairs key_value_pairs_;

  bool operator==(const FakeHeaders& other) const {
    if (key_value_pairs_.size() != other.key_value_pairs_.size()) {
      return false;
    }
    for (KeyValuePairs::size_type i = 0; i < key_value_pairs_.size(); ++i) {
      if (key_value_pairs_[i].key != other.key_value_pairs_[i].key) {
        return false;
      }
      if (key_value_pairs_[i].value != other.key_value_pairs_[i].value) {
        return false;
      }
    }
    return true;
  }

  void AddKeyValue(const std::string& key, const std::string& value) {
    key_value_pairs_.push_back(KeyValuePair(key, value));
  }
};

class BalsaVisitorMock : public BalsaVisitorInterface {
 public:
  ~BalsaVisitorMock() override = default;

  void ProcessHeaders(const BalsaHeaders& headers) override {
    FakeHeaders fake_headers;
    GenerateFakeHeaders(headers, &fake_headers);
    ProcessHeaders(fake_headers);
  }
  void OnTrailers(std::unique_ptr<BalsaHeaders> trailers) override {
    FakeHeaders fake_trailers;
    GenerateFakeHeaders(*trailers, &fake_trailers);
    OnTrailers(fake_trailers);
  }

  MOCK_METHOD(void, OnRawBodyInput, (absl::string_view input), (override));
  MOCK_METHOD(void, OnBodyChunkInput, (absl::string_view input), (override));
  MOCK_METHOD(void, OnHeaderInput, (absl::string_view input), (override));
  MOCK_METHOD(void, OnTrailerInput, (absl::string_view input), (override));
  MOCK_METHOD(void, ProcessHeaders, (const FakeHeaders& headers));
  MOCK_METHOD(void, OnTrailers, (const FakeHeaders& trailers));
  MOCK_METHOD(void, OnRequestFirstLineInput,
              (absl::string_view line_input, absl::string_view method_input,
               absl::string_view request_uri, absl::string_view version_input),
              (override));
  MOCK_METHOD(void, OnResponseFirstLineInput,
              (absl::string_view line_input, absl::string_view version_input,
               absl::string_view status_input, absl::string_view reason_input),
              (override));
  MOCK_METHOD(void, OnChunkLength, (size_t length), (override));
  MOCK_METHOD(void, OnChunkExtensionInput, (absl::string_view input),
              (override));
  MOCK_METHOD(void, OnInterimHeaders, (std::unique_ptr<BalsaHeaders> headers),
              (override));
  MOCK_METHOD(void, ContinueHeaderDone, (), (override));
  MOCK_METHOD(void, HeaderDone, (), (override));
  MOCK_METHOD(void, MessageDone, (), (override));
  MOCK_METHOD(void, HandleError, (BalsaFrameEnums::ErrorCode error_code),
              (override));
  MOCK_METHOD(void, HandleWarning, (BalsaFrameEnums::ErrorCode error_code),
              (override));

 private:
  static void GenerateFakeHeaders(const BalsaHeaders& headers,
                                  FakeHeaders* fake_headers) {
    for (const auto& line : headers.lines()) {
      fake_headers->AddKeyValue(std::string(line.first),
                                std::string(line.second));
    }
  }
};

class HTTPBalsaFrameTest : public QuicheTest {
 protected:
  void SetUp() override {
    balsa_frame_.set_balsa_headers(&headers_);
    balsa_frame_.set_balsa_visitor(&visitor_mock_);
    balsa_frame_.set_is_request(true);
    balsa_frame_.EnableTrailers();
  }

  void VerifyFirstLineParsing(const std::string& firstline,
                              BalsaFrameEnums::ErrorCode error_code) {
    balsa_frame_.ProcessInput(firstline.data(), firstline.size());
    EXPECT_EQ(error_code, balsa_frame_.ErrorCode());
  }

  BalsaHeaders headers_;
  BalsaFrame balsa_frame_;
  NiceMock<BalsaVisitorMock> visitor_mock_;
};

// Test correct return value for HeaderFramingFound.
TEST_F(HTTPBalsaFrameTest, TestHeaderFramingFound) {
  // Pattern \r\n\r\n should match kValidTerm1.
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, ' '));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(BalsaFrame::kValidTerm1,
            BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));

  // Pattern \n\r\n should match kValidTerm1.
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\t'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(BalsaFrame::kValidTerm1,
            BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));

  // Pattern \r\n\n should match kValidTerm2.
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, 'a'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));
  EXPECT_EQ(BalsaFrame::kValidTerm2,
            BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));

  // Pattern \n\n should match kValidTerm2.
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '1'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));
  EXPECT_EQ(BalsaFrame::kValidTerm2,
            BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));

  // Other patterns should not match.
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, ':'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\r'));
  EXPECT_EQ(0, BalsaFrameTestPeer::HeaderFramingFound(&balsa_frame_, '\n'));
}

TEST_F(HTTPBalsaFrameTest, MissingColonInTrailer) {
  const absl::string_view trailer = "kv\r\n\r\n";

  BalsaFrame::Lines lines;
  lines.push_back({0, 4});
  lines.push_back({4, trailer.length()});
  BalsaHeaders trailers;
  BalsaHeadersTestPeer::WriteFromFramer(&trailers, trailer.data(),
                                        trailer.length());
  BalsaFrameTestPeer::FindColonsAndParseIntoKeyValue(
      &balsa_frame_, lines, true /*is_trailer*/, &trailers);
  // Note missing colon is not an error, just a warning.
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::TRAILER_MISSING_COLON, balsa_frame_.ErrorCode());
}

// Correctness of FindColonsAndParseIntoKeyValue is already verified for
// headers, so trailer related test is light.
TEST_F(HTTPBalsaFrameTest, FindColonsAndParseIntoKeyValueInTrailer) {
  const absl::string_view trailer_line1 = "Fraction: 0.23\r\n";
  const absl::string_view trailer_line2 = "Some:junk \r\n";
  const absl::string_view trailer_line3 = "\r\n";
  const std::string trailer =
      absl::StrCat(trailer_line1, trailer_line2, trailer_line3);

  BalsaFrame::Lines lines;
  lines.push_back({0, trailer_line1.length()});
  lines.push_back({trailer_line1.length(),
                   trailer_line1.length() + trailer_line2.length()});
  lines.push_back(
      {trailer_line1.length() + trailer_line2.length(), trailer.length()});
  BalsaHeaders trailers;
  BalsaHeadersTestPeer::WriteFromFramer(&trailers, trailer.data(),
                                        trailer.length());
  BalsaFrameTestPeer::FindColonsAndParseIntoKeyValue(
      &balsa_frame_, lines, true /*is_trailer*/, &trailers);
  EXPECT_FALSE(balsa_frame_.Error());
  absl::string_view fraction = trailers.GetHeader("Fraction");
  EXPECT_EQ("0.23", fraction);
  absl::string_view some = trailers.GetHeader("Some");
  EXPECT_EQ("junk", some);
}

TEST_F(HTTPBalsaFrameTest, InvalidTrailer) {
  const absl::string_view trailer_line1 = "Fraction : 0.23\r\n";
  const absl::string_view trailer_line2 = "Some\t  :junk \r\n";
  const absl::string_view trailer_line3 = "\r\n";
  const std::string trailer =
      absl::StrCat(trailer_line1, trailer_line2, trailer_line3);

  BalsaFrame::Lines lines;
  lines.push_back({0, trailer_line1.length()});
  lines.push_back({trailer_line1.length(),
                   trailer_line1.length() + trailer_line2.length()});
  lines.push_back(
      {trailer_line1.length() + trailer_line2.length(), trailer.length()});
  BalsaHeaders trailers;
  BalsaHeadersTestPeer::WriteFromFramer(&trailers, trailer.data(),
                                        trailer.length());
  BalsaFrameTestPeer::FindColonsAndParseIntoKeyValue(
      &balsa_frame_, lines, true /*is_trailer*/, &trailers);
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TRAILER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, OneCharacterFirstLineParsedAsExpected) {
  VerifyFirstLineParsing(
      "a\r\n\r\n", BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD);
}

TEST_F(HTTPBalsaFrameTest,
       OneCharacterFirstLineWithWhitespaceParsedAsExpected) {
  VerifyFirstLineParsing(
      "a   \r\n\r\n", BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD);
}

TEST_F(HTTPBalsaFrameTest, WhitespaceOnlyFirstLineIsNotACompleteHeader) {
  VerifyFirstLineParsing(" \n\n", BalsaFrameEnums::NO_REQUEST_LINE_IN_REQUEST);
}

TEST(HTTPBalsaFrame, RequestFirstLineParsedCorrectly) {
  const char* request_tokens[3] = {"GET", "/jjsdjrqk", "HTTP/1.0"};
  FirstLineParsedCorrectlyHelper(request_tokens, 0, true, " ");
  FirstLineParsedCorrectlyHelper(request_tokens, 0, true, "\t");
  FirstLineParsedCorrectlyHelper(request_tokens, 0, true, "\t    ");
  FirstLineParsedCorrectlyHelper(request_tokens, 0, true, "   \t");
  FirstLineParsedCorrectlyHelper(request_tokens, 0, true, "   \t \t  ");
}

TEST(HTTPBalsaFrame, RequestLineSanitizedProperly) {
  SCOPED_TRACE("Testing that the request line is properly sanitized.");
  using enum HttpValidationPolicy::FirstLineValidationOption;
  using FirstLineValidationOption =
      HttpValidationPolicy::FirstLineValidationOption;

  struct TestCase {
    const absl::string_view input;     // Input to the parser.
    const absl::string_view parsed;    // Expected output.
    FirstLineValidationOption option;  // Whether to sanitize/reject.
    BalsaFrameEnums::ErrorCode expected_error;
  };
  const std::vector<TestCase> cases = {
      // No invalid whitespace.
      {"GET / HTTP/1.1\r\n", "GET / HTTP/1.1", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET / HTTP/1.1\r\n", "GET / HTTP/1.1", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET / HTTP/1.1\r\n", "GET / HTTP/1.1", REJECT,
       BalsaFrameEnums::BALSA_NO_ERROR},

      // Illegal CR in the request-line.
      {"GET /\rHTTP/1.1\r\n", "GET /\rHTTP/1.1", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET /\rHTTP/1.1\r\n", "GET / HTTP/1.1", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET /\rHTTP/1.1\r\n", "", REJECT,
       BalsaFrameEnums::INVALID_WS_IN_REQUEST_LINE},

      // Invalid tab in the request-line.
      {"GET \t/ HTTP/1.1\r\n", "GET \t/ HTTP/1.1", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET \t/ HTTP/1.1\r\n", "GET  / HTTP/1.1", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET \t/ HTTP/1.1\r\n", "", REJECT,
       BalsaFrameEnums::INVALID_WS_IN_REQUEST_LINE},

      // Both CR and tab in the request-line.
      {"GET \t/\rHTTP/1.1 \r\n", "GET \t/\rHTTP/1.1", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET \t/\rHTTP/1.1 \r\n", "GET  / HTTP/1.1", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"GET \t/\rHTTP/1.1 \r\n", "", REJECT,
       BalsaFrameEnums::INVALID_WS_IN_REQUEST_LINE},
  };
  const absl::string_view kHeaderLineAndEnding = "Foo: bar\r\n\r\n";
  for (auto& [firstline, parsed, ws_option, expected_error] : cases) {
    SCOPED_TRACE(
        absl::StrCat("Input: ", absl::CEscape(firstline),
                     " Expected output: ", absl::CEscape(parsed),
                     " whitespace option: ", static_cast<int>(ws_option)));
    const std::string input = absl::StrCat(firstline, kHeaderLineAndEnding);

    BalsaHeaders headers;
    BalsaFrame framer;
    HttpValidationPolicy policy;
    policy.sanitize_cr_tab_in_first_line = ws_option;
    framer.set_http_validation_policy(policy);
    framer.set_is_request(true);
    framer.set_balsa_headers(&headers);
    framer.ProcessInput(input.data(), input.size());
    EXPECT_EQ(headers.first_line(),
```