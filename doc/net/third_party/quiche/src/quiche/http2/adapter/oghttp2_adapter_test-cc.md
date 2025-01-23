Response:
My thinking process for summarizing the provided C++ test file went through these stages:

1. **Identify the Core Purpose:** The file name `oghttp2_adapter_test.cc` immediately suggests this is a test file. The `_test.cc` suffix is a common convention for C++ unit tests. The "oghttp2_adapter" part indicates it's testing a component related to HTTP/2 ("http2") and potentially a specific implementation or adaptation layer ("adapter", "og" likely standing for something specific, possibly "original" or a project name).

2. **Scan for Key Classes and Functions:**  I looked for the main class being tested. The inclusion of `"quiche/http2/adapter/oghttp2_adapter.h"` and the numerous instantiations of `OgHttp2Adapter` confirmed this. I also noted the frequent use of `TestVisitor`, a mock object used for verifying interactions.

3. **Recognize the Test Framework:** The presence of `TEST(OgHttp2AdapterTest, ...)` clearly indicates the use of a C++ testing framework (likely Google Test, given the Chromium context and `quiche_test.h`). This tells me the file contains individual test cases.

4. **Categorize Test Functionality by Test Case Name:** I then started going through each `TEST(...)` block and tried to understand the specific functionality being tested based on the test case name. I grouped related tests together. For example, tests like `IsServerSession`, `ProcessBytes`, and the various `HeaderValues...` tests all deal with basic adapter functionality and frame processing. The `InitialSettings...` tests focus on how initial HTTP/2 settings are handled. Tests involving "Invalid..." in their names likely cover error handling. Tests with "Automatic..." probably check for default behaviors.

5. **Infer Functionality from Assertions and Expectations:** The core of understanding each test lies in the `EXPECT_CALL` and `EXPECT_EQ` (and similar) statements. `EXPECT_CALL` on the `visitor` object reveals what actions the `OgHttp2Adapter` is expected to take. `EXPECT_EQ` verifies return values and state changes. I paid attention to the sequence of expected calls established by `testing::InSequence`.

6. **Identify Key HTTP/2 Concepts:**  I recognized terms like "ClientPreface," "SETTINGS," "PING," "HEADERS," "GOAWAY," "WINDOW_UPDATE," and HTTP status codes (like "100" and "200"). This confirms the tests are indeed exercising HTTP/2 protocol handling.

7. **Look for Variations and Edge Cases:** I noted tests that explicitly tested different configurations (e.g., `allow_obs_text`, `validate_path`, `allow_extended_connect`). Tests with "Invalid..." clearly target error conditions and boundary cases.

8. **Infer User/Developer Interactions (Hypothesize):**  Even though it's a test file, the tests simulate interactions with the `OgHttp2Adapter`. I reasoned about how a user or developer would *use* this adapter. They would create an instance, provide input (bytes), and expect certain callbacks or behaviors. This helped me formulate the "User/Developer Errors" section.

9. **Trace the "Path to This Code" (Debugging):** I considered the context of network stacks and HTTP/2. A developer debugging network issues might step through code that parses incoming HTTP/2 frames. This led to the explanation of how a user action in a browser could eventually lead to this code being executed.

10. **Focus on the "Part 1" Request:**  Finally, I concentrated on summarizing the functionality covered by the provided snippet (the first 12 parts). I made sure the summary accurately reflected the types of tests present in this specific section.

11. **Iterative Refinement:** I reread my summary and compared it against the code to ensure accuracy and completeness. I refined the language to be clear and concise. For instance, instead of just saying "it tests settings," I elaborated on *what* aspects of settings are being tested (initial settings, invalid settings, etc.).

By following these steps, I could effectively analyze the C++ test file and generate a comprehensive summary of its functionalities, including connections to JavaScript, logical reasoning with examples, common errors, debugging context, and a concise overview of the provided part.
```cpp
#include "quiche/http2/adapter/oghttp2_adapter.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_join.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/oghttp2_util.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using ConnectionError = Http2VisitorInterface::ConnectionError;

using spdy::SpdyFrameType;
using testing::_;

enum FrameType {
  DATA,
  HEADERS,
  PRIORITY,
  RST_STREAM,
  SETTINGS,
  PUSH_PROMISE,
  PING,
  GOAWAY,
  WINDOW_UPDATE,
  CONTINUATION,
};

TEST(OgHttp2AdapterTest, IsServerSession) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_TRUE(adapter->IsServerSession());
}

TEST(OgHttp2AdapterTest, ProcessBytes) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence seq;
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, 4, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 8, 6, 0));
  EXPECT_CALL(visitor, OnPing(17, false));
  adapter->ProcessBytes(
      TestFrameSequence().ClientPreface().Ping(17).Serialize());
}

TEST(OgHttp2AdapterTest, HeaderValuesWithObsTextAllowedByDefault) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  ASSERT_TRUE(options.allow_obs_text);
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"name", "val\xa1ue"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "name", "val\xa1ue"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, HeaderValuesWithObsTextDisallowed) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.allow_obs_text = false;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"name", "val\xa1ue"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, RequestPathWithSpaceOrTab) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.allow_obs_text = false;
  options.perspective = Perspective::kServer;
  ASSERT_EQ(false, options.validate_path);
  options.validate_path = true;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/ fragment"}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/\tfragment2"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  // Stream 3
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, RequestPathWithSpaceOrTabNoPathValidation) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.allow_obs_text = false;
  options.perspective = Perspective::kServer;
  ASSERT_EQ(false, options.validate_path);
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/ fragment"}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/\tfragment2"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/ fragment"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  // Stream 3
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/\tfragment2"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, InitialSettingsNoExtendedConnect) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options client_options;
  client_options.perspective = Perspective::kClient;
  client_options.max_header_list_bytes = 42;
  client_options.allow_extended_connect = false;
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);

  TestVisitor server_visitor;
  OgHttp2Adapter::Options server_options;
  server_options.perspective = Perspective::kServer;
  server_options.allow_extended_connect = false;
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  testing::InSequence s;

  // Client sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, 12, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, 12, 0x0, 0));
  {
    int result = client_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = client_visitor.data();
    EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
    data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Server sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(server_visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(server_visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  {
    int result = server_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = server_visitor.data();
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Client processes the server's initial bytes, including initial SETTINGS.
  EXPECT_CALL(client_visitor, OnFrameHeader(0, 0, SETTINGS, 0x0));
  EXPECT_CALL(client_visitor, OnSettingsStart());
  EXPECT_CALL(client_visitor, OnSettingsEnd());
  {
    const int64_t result = client_adapter->ProcessBytes(server_visitor.data());
    EXPECT_EQ(server_visitor.data().size(), static_cast<size_t>(result));
  }

  // Server processes the client's initial bytes, including initial SETTINGS.
  EXPECT_CALL(server_visitor, OnFrameHeader(0, 12, SETTINGS, 0x0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor,
              OnSetting(Http2Setting{Http2KnownSettingsId::ENABLE_PUSH, 0u}));
  EXPECT_CALL(
      server_visitor,
      OnSetting(Http2Setting{Http2KnownSettingsId::MAX_HEADER_LIST_SIZE, 42u}));
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  {
    const int64_t result = server_adapter->ProcessBytes(client_visitor.data());
    EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
  }
}

TEST(OgHttp2AdapterTest, InitialSettings) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options client_options;
  client_options.perspective = Perspective::kClient;
  client_options.max_header_list_bytes = 42;
  ASSERT_TRUE(client_options.allow_extended_connect);
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);

  TestVisitor server_visitor;
  OgHttp2Adapter::Options server_options;
  server_options.perspective = Perspective::kServer;
  ASSERT_TRUE(server_options.allow_extended_connect);
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  testing::InSequence s;

  // Client sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, 12, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, 12, 0x0, 0));
  {
    int result = client_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = client_visitor.data();
    EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
    data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Server sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(server_visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(server_visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  {
    int result = server_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = server_visitor.data();
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Client processes the server's initial bytes, including initial SETTINGS.
  EXPECT_CALL(client_visitor, OnFrameHeader(0, 6, SETTINGS, 0x0));
  EXPECT_CALL(client_visitor, OnSettingsStart());
  EXPECT_CALL(client_visitor,
              OnSetting(Http2Setting{
                  Http2KnownSettingsId::ENABLE_CONNECT_PROTOCOL, 1u}));
  EXPECT_CALL(client_visitor, OnSettingsEnd());
  {
    const int64_t result = client_adapter->ProcessBytes(server_visitor.data());
    EXPECT_EQ(server_visitor.data().size(), static_cast<size_t>(result));
  }

  // Server processes the client's initial bytes, including initial SETTINGS.
  EXPECT_CALL(server_visitor, OnFrameHeader(0, 12, SETTINGS, 0x0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor,
              OnSetting(Http2Setting{Http2KnownSettingsId::ENABLE_PUSH, 0u}));
  EXPECT_CALL(
      server_visitor,
      OnSetting(Http2Setting{Http2KnownSettingsId::MAX_HEADER_LIST_SIZE, 42u}));
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  {
    const int64_t result = server_adapter->ProcessBytes(client_visitor.data());
    EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
  }
}

TEST(OgHttp2AdapterTest, AutomaticSettingsAndPingAcks) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface().Ping(42).Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // PING
  EXPECT_CALL(visitor, OnFrameHeader(0, _, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // PING ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::PING}));
}

TEST(OgHttp2AdapterTest, AutomaticPingAcksDisabled) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.auto_ping_ack = false;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface().Ping(42).Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // PING
  EXPECT_CALL(visitor, OnFrameHeader(0, _, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // No PING ack expected because automatic PING acks are disabled.

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, InvalidMaxFrameSizeSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface({{MAX_FRAME_SIZE, 3u}}).Serialize();
  testing::InSequence s;

  // Client preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, InvalidPushSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface({{ENABLE_PUSH, 3u}}).Serialize();
  testing::InSequence s;

  // Client preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, InvalidConnectProtocolSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface({{ENABLE_CONNECT_PROTOCOL, 3u}})
                                 .Serialize();
  testing::InSequence s;

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));

  auto adapter2 = OgHttp2Adapter::Create(visitor, options);
  const std::string frames2 = TestFrameSequence()
                                  .ClientPreface({{ENABLE_CONNECT_PROTOCOL, 1}})
                                  .Settings({{ENABLE_CONNECT_PROTOCOL, 0}})
                                  .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{ENABLE_CONNECT_PROTOCOL, 1u}));
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  read_result = adapter2->ProcessBytes(frames2);
  EXPECT_EQ(static_cast<size_t>(read_result), frames2.size());

  EXPECT_TRUE(adapter2->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  adapter2->Send();
}

TEST(OgHttp2AdapterTest, ClientSetsRemoteMaxStreamOption) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  // Set a lower-than-default initial remote max_concurrent_streams.
  options.remote_max_concurrent_streams = 3;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers = ToHeaders({{":method", "GET"},
                                                 {":scheme", "http"},
                                                 {":authority", "example.com"},
                                                 {":path", "/"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  const int32_t stream_id2 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  const int32_t stream_id3 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  const int32_t stream_id4 =
      
### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
#include "quiche/http2/adapter/oghttp2_adapter.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_join.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/oghttp2_util.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using ConnectionError = Http2VisitorInterface::ConnectionError;

using spdy::SpdyFrameType;
using testing::_;

enum FrameType {
  DATA,
  HEADERS,
  PRIORITY,
  RST_STREAM,
  SETTINGS,
  PUSH_PROMISE,
  PING,
  GOAWAY,
  WINDOW_UPDATE,
  CONTINUATION,
};

TEST(OgHttp2AdapterTest, IsServerSession) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_TRUE(adapter->IsServerSession());
}

TEST(OgHttp2AdapterTest, ProcessBytes) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence seq;
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, 4, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 8, 6, 0));
  EXPECT_CALL(visitor, OnPing(17, false));
  adapter->ProcessBytes(
      TestFrameSequence().ClientPreface().Ping(17).Serialize());
}

TEST(OgHttp2AdapterTest, HeaderValuesWithObsTextAllowedByDefault) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  ASSERT_TRUE(options.allow_obs_text);
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"name", "val\xa1ue"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "name", "val\xa1ue"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, HeaderValuesWithObsTextDisallowed) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.allow_obs_text = false;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"name", "val\xa1ue"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, RequestPathWithSpaceOrTab) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.allow_obs_text = false;
  options.perspective = Perspective::kServer;
  ASSERT_EQ(false, options.validate_path);
  options.validate_path = true;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/ fragment"}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/\tfragment2"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  // Stream 3
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, RequestPathWithSpaceOrTabNoPathValidation) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.allow_obs_text = false;
  options.perspective = Perspective::kServer;
  ASSERT_EQ(false, options.validate_path);
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/ fragment"}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/\tfragment2"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/ fragment"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  // Stream 3
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/\tfragment2"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, InitialSettingsNoExtendedConnect) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options client_options;
  client_options.perspective = Perspective::kClient;
  client_options.max_header_list_bytes = 42;
  client_options.allow_extended_connect = false;
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);

  TestVisitor server_visitor;
  OgHttp2Adapter::Options server_options;
  server_options.perspective = Perspective::kServer;
  server_options.allow_extended_connect = false;
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  testing::InSequence s;

  // Client sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, 12, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, 12, 0x0, 0));
  {
    int result = client_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = client_visitor.data();
    EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
    data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Server sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(server_visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(server_visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  {
    int result = server_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = server_visitor.data();
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Client processes the server's initial bytes, including initial SETTINGS.
  EXPECT_CALL(client_visitor, OnFrameHeader(0, 0, SETTINGS, 0x0));
  EXPECT_CALL(client_visitor, OnSettingsStart());
  EXPECT_CALL(client_visitor, OnSettingsEnd());
  {
    const int64_t result = client_adapter->ProcessBytes(server_visitor.data());
    EXPECT_EQ(server_visitor.data().size(), static_cast<size_t>(result));
  }

  // Server processes the client's initial bytes, including initial SETTINGS.
  EXPECT_CALL(server_visitor, OnFrameHeader(0, 12, SETTINGS, 0x0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor,
              OnSetting(Http2Setting{Http2KnownSettingsId::ENABLE_PUSH, 0u}));
  EXPECT_CALL(
      server_visitor,
      OnSetting(Http2Setting{Http2KnownSettingsId::MAX_HEADER_LIST_SIZE, 42u}));
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  {
    const int64_t result = server_adapter->ProcessBytes(client_visitor.data());
    EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
  }
}

TEST(OgHttp2AdapterTest, InitialSettings) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options client_options;
  client_options.perspective = Perspective::kClient;
  client_options.max_header_list_bytes = 42;
  ASSERT_TRUE(client_options.allow_extended_connect);
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);

  TestVisitor server_visitor;
  OgHttp2Adapter::Options server_options;
  server_options.perspective = Perspective::kServer;
  ASSERT_TRUE(server_options.allow_extended_connect);
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  testing::InSequence s;

  // Client sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, 12, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, 12, 0x0, 0));
  {
    int result = client_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = client_visitor.data();
    EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
    data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Server sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(server_visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(server_visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  {
    int result = server_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = server_visitor.data();
    EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  }

  // Client processes the server's initial bytes, including initial SETTINGS.
  EXPECT_CALL(client_visitor, OnFrameHeader(0, 6, SETTINGS, 0x0));
  EXPECT_CALL(client_visitor, OnSettingsStart());
  EXPECT_CALL(client_visitor,
              OnSetting(Http2Setting{
                  Http2KnownSettingsId::ENABLE_CONNECT_PROTOCOL, 1u}));
  EXPECT_CALL(client_visitor, OnSettingsEnd());
  {
    const int64_t result = client_adapter->ProcessBytes(server_visitor.data());
    EXPECT_EQ(server_visitor.data().size(), static_cast<size_t>(result));
  }

  // Server processes the client's initial bytes, including initial SETTINGS.
  EXPECT_CALL(server_visitor, OnFrameHeader(0, 12, SETTINGS, 0x0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor,
              OnSetting(Http2Setting{Http2KnownSettingsId::ENABLE_PUSH, 0u}));
  EXPECT_CALL(
      server_visitor,
      OnSetting(Http2Setting{Http2KnownSettingsId::MAX_HEADER_LIST_SIZE, 42u}));
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  {
    const int64_t result = server_adapter->ProcessBytes(client_visitor.data());
    EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
  }
}

TEST(OgHttp2AdapterTest, AutomaticSettingsAndPingAcks) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface().Ping(42).Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // PING
  EXPECT_CALL(visitor, OnFrameHeader(0, _, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // PING ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::PING}));
}

TEST(OgHttp2AdapterTest, AutomaticPingAcksDisabled) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.auto_ping_ack = false;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface().Ping(42).Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // PING
  EXPECT_CALL(visitor, OnFrameHeader(0, _, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // No PING ack expected because automatic PING acks are disabled.

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, InvalidMaxFrameSizeSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface({{MAX_FRAME_SIZE, 3u}}).Serialize();
  testing::InSequence s;

  // Client preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, InvalidPushSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface({{ENABLE_PUSH, 3u}}).Serialize();
  testing::InSequence s;

  // Client preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, InvalidConnectProtocolSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface({{ENABLE_CONNECT_PROTOCOL, 3u}})
                                 .Serialize();
  testing::InSequence s;

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));

  auto adapter2 = OgHttp2Adapter::Create(visitor, options);
  const std::string frames2 = TestFrameSequence()
                                  .ClientPreface({{ENABLE_CONNECT_PROTOCOL, 1}})
                                  .Settings({{ENABLE_CONNECT_PROTOCOL, 0}})
                                  .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{ENABLE_CONNECT_PROTOCOL, 1u}));
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidSetting));

  read_result = adapter2->ProcessBytes(frames2);
  EXPECT_EQ(static_cast<size_t>(read_result), frames2.size());

  EXPECT_TRUE(adapter2->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  adapter2->Send();
}

TEST(OgHttp2AdapterTest, ClientSetsRemoteMaxStreamOption) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  // Set a lower-than-default initial remote max_concurrent_streams.
  options.remote_max_concurrent_streams = 3;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers = ToHeaders({{":method", "GET"},
                                                 {":scheme", "http"},
                                                 {":authority", "example.com"},
                                                 {":path", "/"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  const int32_t stream_id2 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  const int32_t stream_id3 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  const int32_t stream_id4 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id3, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id3, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  // The fourth stream is buffered, since only 3 can be in flight to the server.

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(stream_id1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(stream_id1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id1));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id1, ":status", "200"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(stream_id1, "server", "my-fake-server"));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id1, "date",
                                         "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id1));
  EXPECT_CALL(visitor, OnEndStream(stream_id1));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  ASSERT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  // The fourth stream will be started, since the first has completed.
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id4, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id4, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  result = adapter->Send();
  EXPECT_EQ(0, result);
}

TEST(OgHttp2AdapterTest, ClientHandles100Headers) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}},
                   /*fin=*/false)
          .Ping(101)
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(101, false));

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
}

TEST(OgHttp2AdapterTest, QueuingWindowUpdateAffectsWindow) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(adapter->GetReceiveWindowSize(), kInitialFlowControlWindowSize);
  adapter->SubmitWindowUpdate(0, 10000);
  EXPECT_EQ(adapter->GetReceiveWindowSize(),
            kInitialFlowControlWindowSize + 10000);

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id),
            kInitialFlowControlWindowSize);
  adapter->SubmitWindowUpdate(1, 20000);
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id),
            kInitialFlowControlWindowSize + 20000);
}

TEST(OgHttp2AdapterTest, AckOfSettingInitialWindowSizeAffectsWindow) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers =
```