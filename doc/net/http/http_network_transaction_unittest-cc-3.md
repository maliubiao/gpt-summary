Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a unit test file for Chromium's network stack. I need to analyze the code and identify its key test scenarios.

The code seems to be testing the `HttpNetworkTransaction` class, focusing on:

1. **Error Handling:** Specifically, `ERR_CONTENT_LENGTH_MISMATCH`.
2. **Keep-Alive Connections:**  Testing the reuse of connections when the response body is not fully read.
3. **Handling Extra Data on Keep-Alive Connections:** Verifying that connections with unread data after a complete response are not reused.
4. **Authentication (Basic Auth):** Testing the challenge-response flow for basic authentication, including retries and scenarios where the server keeps requesting authentication.
5. **Disabling Authentication:** Testing the behavior when authentication is skipped due to privacy settings.
6. **Keep-Alive with Authentication:** Combining keep-alive connections with the basic authentication flow.

I will structure the summary based on these identified functionalities. I'll also consider the user's requests regarding JavaScript relevance, logical inference, common usage errors, and debugging.
```c++
#include "net/http/http_network_transaction.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/callback.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/strings/string_piece.h"
#include "base/test/bind.h"
#include "base/test/mock_callback.h"
#include "net/base/auth_credentials.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_server_bound_cert_store.h"
#include "net/base/test_socket_factory.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/socket_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_params.h"
#include "net/traffic_annotation/network_traffic_annotation_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::ContainsRegex;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::IsOk;
using ::testing::Not;

namespace net {
namespace {

const char kFoo[] = "foo";
const char kBar[] = "bar";

bool CheckBasicServerAuth(const absl::optional<HttpAuthChallenge>& challenge) {
  return challenge.has_value() && challenge->scheme == "basic";
}

int ReadTransaction(HttpNetworkTransaction* trans, std::string* data) {
  const int kSize = 4096;
  scoped_refptr<IOBuffer> buf(base::MakeRefCounted<IOBuffer>(kSize));
  int bytes_read = 0;
  int rv = 0;
  do {
    rv = trans->Read(buf.get(), kSize, TestCompletionCallback().callback());
    if (rv > 0) {
      data->append(buf->data(), rv);
      bytes_read += rv;
    }
  } while (rv > 0);
  return rv < 0 ? rv : OK;
}

int GetIdleSocketCountInTransportSocketPool(HttpNetworkSession* session) {
  TransportSocketPool* pool = session->GetTransportSocketPoolForTesting();
  return pool->IdleSocketCount();
}

int CountWriteBytes(const MockWrite writes[]) {
  int count = 0;
  for (int i = 0; writes[i].data() != nullptr; ++i) {
    count += writes[i].len();
  }
  return count;
}

int CountReadBytes(const MockRead reads[]) {
  int count = 0;
  for (int i = 0; reads[i].data() != nullptr; ++i) {
    if (reads[i].len() > 0)
      count += reads[i].len();
  }
  return count;
}

}  // namespace

class HttpNetworkTransactionTest : public ::testing::TestWithParam<bool> {
 public:
  HttpNetworkTransactionTest() : session_deps_(GetParam()) {}

  void TestLoadTimingNotReused(const LoadTimingInfo& load_timing_info,
                              int expected_connection_timing_fields) {
    EXPECT_FALSE(load_timing_info.socket_reused);
    EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);
    EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.connect_timing.dns_start);
    EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.connect_timing.dns_end);
    if (expected_connection_timing_fields >= CONNECT_TIMING_HAS_CONNECT_TIMES) {
      EXPECT_NE(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.connect_start);
      EXPECT_NE(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.connect_end);
    } else {
      EXPECT_EQ(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.connect_start);
      EXPECT_EQ(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.connect_end);
    }
    if (expected_connection_timing_fields >=
        CONNECT_TIMING_HAS_SSL_CONNECT_TIMES) {
      EXPECT_NE(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.ssl_start);
      EXPECT_NE(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.ssl_end);
    } else {
      EXPECT_EQ(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.ssl_start);
      EXPECT_EQ(NetLogSource::kInvalidId,
                load_timing_info.connect_timing.ssl_end);
    }
  }

  void TestLoadTimingReused(const LoadTimingInfo& load_timing_info) {
    EXPECT_TRUE(load_timing_info.socket_reused);
    EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);
    EXPECT_EQ(NetLogSource::kInvalidId, load_timing_info.connect_timing.dns_start);
    EXPECT_EQ(NetLogSource::kInvalidId, load_timing_info.connect_timing.dns_end);
    EXPECT_EQ(NetLogSource::kInvalidId,
              load_timing_info.connect_timing.connect_start);
    EXPECT_EQ(NetLogSource::kInvalidId,
              load_timing_info.connect_timing.connect_end);
    EXPECT_EQ(NetLogSource::kInvalidId, load_timing_info.connect_timing.ssl_start);
    EXPECT_EQ(NetLogSource::kInvalidId, load_timing_info.connect_timing.ssl_end);
  }

  std::unique_ptr<HttpNetworkSession> CreateSession(
      HttpNetworkSession::Params* params) {
    return std::make_unique<HttpNetworkSession>(*params);
  }

 protected:
  HttpNetworkSession::Params session_deps_;
};

INSTANTIATE_TEST_SUITE_P(HttpNetworkTransactionTestSuite,
                         HttpNetworkTransactionTest,
                         ::testing::Bool());

// Test that if the content-length doesn't match, we get an error when reading.
TEST_P(HttpNetworkTransactionTest, ContentLengthMismatch) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Connection: keep-alive\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, 0),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  scoped_refptr<IOBufferWithSize> io_buf(
      base::MakeRefCounted<IOBufferWithSize>(100));
  rv = trans->Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_THAT(rv, IsError(ERR_CONTENT_LENGTH_MISMATCH));

  trans.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test that we correctly reuse a keep-alive connection after not explicitly
// reading the body.
TEST_P(HttpNetworkTransactionTest, KeepAliveAfterUnreadBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const char kRequestData[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.foo.com\r\n"
      "Connection: keep-alive\r\n\r\n";
  MockWrite data_writes[] = {
      MockWrite(ASYNC, 0, kRequestData),  MockWrite(ASYNC, 2, kRequestData),
      MockWrite(ASYNC, 4, kRequestData),  MockWrite(ASYNC, 6, kRequestData),
      MockWrite(ASYNC, 8, kRequestData),  MockWrite(ASYNC, 10, kRequestData),
      MockWrite(ASYNC, 12, kRequestData), MockWrite(ASYNC, 14, kRequestData),
      MockWrite(ASYNC, 17, kRequestData), MockWrite(ASYNC, 20, kRequestData),
  };

  // Note that because all these reads happen in the same
  // StaticSocketDataProvider, it shows that the same socket is being reused for
  // all transactions.
  MockRead data_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 204 No Content\r\n\r\n"),
      MockRead(ASYNC, 3, "HTTP/1.1 205 Reset Content\r\n\r\n"),
      MockRead(ASYNC, 5, "HTTP/1.1 304 Not Modified\r\n\r\n"),
      MockRead(ASYNC, 7,
               "HTTP/1.1 302 Found\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead(ASYNC, 9,
               "HTTP/1.1 302 Found\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
      MockRead(ASYNC, 11,
               "HTTP/1.1 301 Moved Permanently\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead(ASYNC, 13,
               "HTTP/1.1 301 Moved Permanently\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),

      // In the next two rounds, IsConnectedAndIdle returns false, due to
      // the set_busy_before_sync_reads(true) call, while the
      // HttpNetworkTransaction is being shut down, but the socket is still
      // reuseable. See http://crbug.com/544255.
      MockRead(ASYNC, 15,
               "HTTP/1.1 200 Hunky-Dory\r\n"
               "Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, 16, "hello"),

      MockRead(ASYNC, 18,
               "HTTP/1.1 200 Hunky-Dory\r\n"
               "Content-Length: 5\r\n\r\n"
               "he"),
      MockRead(SYNCHRONOUS, 19, "llo"),

      // The body of the final request is actually read.
      MockRead(ASYNC, 21, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead(ASYNC, 22, "hello"),
  };
  SequencedSocketData data(data_reads, data_writes);
  data.set_busy_before_sync_reads(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  const int kNumUnreadBodies = std::size(data_writes) - 1;
  std::string response_lines[kNumUnreadBodies];

  uint32_t first_socket_log_id = NetLogSource::kInvalidId;
  for (size_t i = 0; i < kNumUnreadBodies; ++i) {
    TestCompletionCallback callback;

    auto trans = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                          session.get());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    LoadTimingInfo load_timing_info;
    EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
    if (i == 0) {
      TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
      first_socket_log_id = load_timing_info.socket_log_id;
    } else {
      TestLoadTimingReused(load_timing_info);
      EXPECT_EQ(first_socket_log_id, load_timing_info.socket_log_id);
    }

    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response);

    ASSERT_TRUE(response->headers);
    response_lines[i] = response->headers->GetStatusLine();

    // Delete the transaction without reading the response bodies. Then spin
    // the message loop, so the response bodies are drained.
    trans.reset();
    base::RunLoop().RunUntilIdle();
  }

  const char* const kStatusLines[] = {
      "HTTP/1.1 204 No Content",
      "HTTP/1.1 205 Reset Content",
      "HTTP/1.1 304 Not Modified",
      "HTTP/1.1 302 Found",
      "HTTP/1.1 302 Found",
      "HTTP/1.1 301 Moved Permanently",
      "HTTP/1.1 301 Moved Permanently",
      "HTTP/1.1 200 Hunky-Dory",
      "HTTP/1.1 200 Hunky-Dory",
  };

  static_assert(kNumUnreadBodies == std::size(kStatusLines),
                "forgot to update kStatusLines");

  for (int i = 0; i < kNumUnreadBodies; ++i) {
    EXPECT_EQ(kStatusLines[i], response_lines[i]);
  }

  TestCompletionCallback callback;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello", response_data);
}

// Sockets that receive extra data after a response is complete should not be
// reused.
TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData1) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("HEAD / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 22\r\n\r\n"
               "This server is borked."),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "HEAD";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData2) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 22\r\n\r\n"
               "This server is borked."
               "Bonus data!"),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("This server is borked.", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData3) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Transfer-Encoding: chunked\r\n\r\n"),
      MockRead("16\r\nThis server is borked.\r\n"),
      MockRead("0\r\n\r\nBonus data!"),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("This server is borked.", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

// This is a little different from the others - it tests the case that the
// HttpStreamParser doesn't know if there's extra data on a socket or not when
// the HttpNetworkTransaction is torn down, because the response body hasn't
// been read from yet, but the request goes through the HttpResponseBodyDrainer.
TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData4) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Transfer-Encoding: chunked\r\n\r\n"),
      MockRead("16\r\nThis server is borked.\r\n"),
      MockRead("0\r\n\r\nBonus data!"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  // Deleting the transaction creates an HttpResponseBodyDrainer to read the
  // response body.
  trans.reset();

  // Let the HttpResponseBodyDrainer drain the socket. It should determine the
  // socket can't be reused, rather than returning it to the socket pool.
  base::RunLoop().RunUntilIdle();

  // There should be no idle sockets in the pool.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test the request-challenge-retry sequence for basic auth.
// (basic auth is the easiest to mock, because it has no randomness).
TEST_P(HttpNetworkTransactionTest, BasicAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      // Give a couple authenticate options (only the middle one is actually
      // supported).
      MockRead("WWW-Authenticate: Basic invalid\r\n"),  // Malformed.
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("WWW-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans->RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] =
Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共34部分，请归纳一下它的功能

"""
ion(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Connection: keep-alive\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, 0),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  scoped_refptr<IOBufferWithSize> io_buf(
      base::MakeRefCounted<IOBufferWithSize>(100));
  rv = trans->Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_THAT(rv, IsError(ERR_CONTENT_LENGTH_MISMATCH));

  trans.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test that we correctly reuse a keep-alive connection after not explicitly
// reading the body.
TEST_P(HttpNetworkTransactionTest, KeepAliveAfterUnreadBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const char kRequestData[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.foo.com\r\n"
      "Connection: keep-alive\r\n\r\n";
  MockWrite data_writes[] = {
      MockWrite(ASYNC, 0, kRequestData),  MockWrite(ASYNC, 2, kRequestData),
      MockWrite(ASYNC, 4, kRequestData),  MockWrite(ASYNC, 6, kRequestData),
      MockWrite(ASYNC, 8, kRequestData),  MockWrite(ASYNC, 10, kRequestData),
      MockWrite(ASYNC, 12, kRequestData), MockWrite(ASYNC, 14, kRequestData),
      MockWrite(ASYNC, 17, kRequestData), MockWrite(ASYNC, 20, kRequestData),
  };

  // Note that because all these reads happen in the same
  // StaticSocketDataProvider, it shows that the same socket is being reused for
  // all transactions.
  MockRead data_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 204 No Content\r\n\r\n"),
      MockRead(ASYNC, 3, "HTTP/1.1 205 Reset Content\r\n\r\n"),
      MockRead(ASYNC, 5, "HTTP/1.1 304 Not Modified\r\n\r\n"),
      MockRead(ASYNC, 7,
               "HTTP/1.1 302 Found\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead(ASYNC, 9,
               "HTTP/1.1 302 Found\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
      MockRead(ASYNC, 11,
               "HTTP/1.1 301 Moved Permanently\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead(ASYNC, 13,
               "HTTP/1.1 301 Moved Permanently\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),

      // In the next two rounds, IsConnectedAndIdle returns false, due to
      // the set_busy_before_sync_reads(true) call, while the
      // HttpNetworkTransaction is being shut down, but the socket is still
      // reuseable.  See http://crbug.com/544255.
      MockRead(ASYNC, 15,
               "HTTP/1.1 200 Hunky-Dory\r\n"
               "Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, 16, "hello"),

      MockRead(ASYNC, 18,
               "HTTP/1.1 200 Hunky-Dory\r\n"
               "Content-Length: 5\r\n\r\n"
               "he"),
      MockRead(SYNCHRONOUS, 19, "llo"),

      // The body of the final request is actually read.
      MockRead(ASYNC, 21, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead(ASYNC, 22, "hello"),
  };
  SequencedSocketData data(data_reads, data_writes);
  data.set_busy_before_sync_reads(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  const int kNumUnreadBodies = std::size(data_writes) - 1;
  std::string response_lines[kNumUnreadBodies];

  uint32_t first_socket_log_id = NetLogSource::kInvalidId;
  for (size_t i = 0; i < kNumUnreadBodies; ++i) {
    TestCompletionCallback callback;

    auto trans = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                          session.get());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    LoadTimingInfo load_timing_info;
    EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
    if (i == 0) {
      TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
      first_socket_log_id = load_timing_info.socket_log_id;
    } else {
      TestLoadTimingReused(load_timing_info);
      EXPECT_EQ(first_socket_log_id, load_timing_info.socket_log_id);
    }

    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response);

    ASSERT_TRUE(response->headers);
    response_lines[i] = response->headers->GetStatusLine();

    // Delete the transaction without reading the response bodies.  Then spin
    // the message loop, so the response bodies are drained.
    trans.reset();
    base::RunLoop().RunUntilIdle();
  }

  const char* const kStatusLines[] = {
      "HTTP/1.1 204 No Content",
      "HTTP/1.1 205 Reset Content",
      "HTTP/1.1 304 Not Modified",
      "HTTP/1.1 302 Found",
      "HTTP/1.1 302 Found",
      "HTTP/1.1 301 Moved Permanently",
      "HTTP/1.1 301 Moved Permanently",
      "HTTP/1.1 200 Hunky-Dory",
      "HTTP/1.1 200 Hunky-Dory",
  };

  static_assert(kNumUnreadBodies == std::size(kStatusLines),
                "forgot to update kStatusLines");

  for (int i = 0; i < kNumUnreadBodies; ++i) {
    EXPECT_EQ(kStatusLines[i], response_lines[i]);
  }

  TestCompletionCallback callback;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello", response_data);
}

// Sockets that receive extra data after a response is complete should not be
// reused.
TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData1) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("HEAD / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 22\r\n\r\n"
               "This server is borked."),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "HEAD";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData2) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 22\r\n\r\n"
               "This server is borked."
               "Bonus data!"),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("This server is borked.", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData3) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Transfer-Encoding: chunked\r\n\r\n"),
      MockRead("16\r\nThis server is borked.\r\n"),
      MockRead("0\r\n\r\nBonus data!"),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("This server is borked.", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

// This is a little different from the others - it tests the case that the
// HttpStreamParser doesn't know if there's extra data on a socket or not when
// the HttpNetworkTransaction is torn down, because the response body hasn't
// been read from yet, but the request goes through the HttpResponseBodyDrainer.
TEST_P(HttpNetworkTransactionTest, KeepAliveWithUnusedData4) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Transfer-Encoding: chunked\r\n\r\n"),
      MockRead("16\r\nThis server is borked.\r\n"),
      MockRead("0\r\n\r\nBonus data!"),
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  // Deleting the transaction creates an HttpResponseBodyDrainer to read the
  // response body.
  trans.reset();

  // Let the HttpResponseBodyDrainer drain the socket.  It should determine the
  // socket can't be reused, rather than returning it to the socket pool.
  base::RunLoop().RunUntilIdle();

  // There should be no idle sockets in the pool.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test the request-challenge-retry sequence for basic auth.
// (basic auth is the easiest to mock, because it has no randomness).
TEST_P(HttpNetworkTransactionTest, BasicAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      // Give a couple authenticate options (only the middle one is actually
      // supported).
      MockRead("WWW-Authenticate: Basic invalid\r\n"),  // Malformed.
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("WWW-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans->RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_DNS_TIMES);

  int64_t writes_size1 = CountWriteBytes(data_writes1);
  EXPECT_EQ(writes_size1, trans.GetTotalSentBytes());
  int64_t reads_size1 = CountReadBytes(data_reads1);
  EXPECT_EQ(reads_size1, trans.GetTotalReceivedBytes());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingNotReused(load_timing_info2, CONNECT_TIMING_HAS_DNS_TIMES);
  // The load timing after restart should have a new socket ID, and times after
  // those of the first load timing.
  EXPECT_LE(load_timing_info1.receive_headers_end,
            load_timing_info2.connect_timing.connect_start);
  EXPECT_NE(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  int64_t writes_size2 = CountWriteBytes(data_writes2);
  EXPECT_EQ(writes_size1 + writes_size2, trans.GetTotalSentBytes());
  int64_t reads_size2 = CountReadBytes(data_reads2);
  EXPECT_EQ(reads_size1 + reads_size2, trans.GetTotalReceivedBytes());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth.
// (basic auth is the easiest to mock, because it has no randomness).
TEST_P(HttpNetworkTransactionTest, BasicAuthWithAddressChange) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto resolver = std::make_unique<MockHostResolver>();
  auto* resolver_ptr = resolver.get();
  session_deps_.net_log = NetLog::Get();
  session_deps_.host_resolver = std::move(resolver);
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  resolver_ptr->rules()->ClearRules();
  resolver_ptr->rules()->AddRule("www.example.org", "127.0.0.1");

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      // Give a couple authenticate options (only the middle one is actually
      // supported).
      MockRead("WWW-Authenticate: Basic invalid\r\n"),  // Malformed.
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("WWW-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans->RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  EXPECT_EQ(OK, callback1.GetResult(trans.Start(&request, callback1.callback(),
                                                NetLogWithSource())));

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_DNS_TIMES);

  int64_t writes_size1 = CountWriteBytes(data_writes1);
  EXPECT_EQ(writes_size1, trans.GetTotalSentBytes());
  int64_t reads_size1 = CountReadBytes(data_reads1);
  EXPECT_EQ(reads_size1, trans.GetTotalReceivedBytes());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  ASSERT_FALSE(endpoint.address().empty());
  EXPECT_EQ("127.0.0.1:80", endpoint.ToString());

  resolver_ptr->rules()->ClearRules();
  resolver_ptr->rules()->AddRule("www.example.org", "127.0.0.2");

  TestCompletionCallback callback2;

  EXPECT_EQ(OK, callback2.GetResult(trans.RestartWithAuth(
                    AuthCredentials(kFoo, kBar), callback2.callback())));

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingNotReused(load_timing_info2, CONNECT_TIMING_HAS_DNS_TIMES);
  // The load timing after restart should have a new socket ID, and times after
  // those of the first load timing.
  EXPECT_LE(load_timing_info1.receive_headers_end,
            load_timing_info2.connect_timing.connect_start);
  EXPECT_NE(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  int64_t writes_size2 = CountWriteBytes(data_writes2);
  EXPECT_EQ(writes_size1 + writes_size2, trans.GetTotalSentBytes());
  int64_t reads_size2 = CountReadBytes(data_reads2);
  EXPECT_EQ(reads_size1 + reads_size2, trans.GetTotalReceivedBytes());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(100, response->headers->GetContentLength());

  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  ASSERT_FALSE(endpoint.address().empty());
  EXPECT_EQ("127.0.0.2:80", endpoint.ToString());
}

// Test that, if the server requests auth indefinitely, HttpNetworkTransaction
// will eventually give up.
TEST_P(HttpNetworkTransactionTest, BasicAuthForever) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      // Give a couple authenticate options (only the middle one is actually
      // supported).
      MockRead("WWW-Authenticate: Basic invalid\r\n"),  // Malformed.
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("WWW-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans->RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes_restart[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;
  int rv = callback.GetResult(
      trans.Start(&request, callback.callback(), NetLogWithSource()));

  std::vector<std::unique_ptr<StaticSocketDataProvider>> data_restarts;
  for (int i = 0; i < 32; i++) {
    // Check the previous response was a 401.
    EXPECT_THAT(rv, IsOk());
    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

    data_restarts.push_back(std::make_unique<StaticSocketDataProvider>(
        data_reads, data_writes_restart));
    session_deps_.socket_factory->AddSocketDataProvider(
        data_restarts.back().get());
    rv = callback.GetResult(trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                                                  callback.callback()));
  }

  // After too many tries, the transaction should have given up.
  EXPECT_THAT(rv, IsError(ERR_TOO_MANY_RETRIES));
}

TEST_P(HttpNetworkTransactionTest, DoNotSendAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_EQ(0, rv);

  int64_t writes_size = CountWriteBytes(data_writes);
  EXPECT_EQ(writes_size, trans.GetTotalSentBytes());
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, trans.GetTotalReceivedBytes());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection.
TEST_P(HttpNetworkTransactionTest, BasicAuthKeepAlive) {
  // On the second pass, the body read of the auth challenge is synchronous, so
  // IsConnectedAndIdle returns false.  The socket should still be drained and
  // reused.  See http://crbug.com/544255.
  for (int i = 0; i < 2; ++i) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    session_deps_.net_log = NetLog::Get();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    MockWrite data_writes[] = {
        MockWrite(ASYNC, 0,
                  "GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),

        // After calling trans.RestartWithAuth(), this is the request we should
        // be issuing -- the final header line contains the credentials.
        MockWrite(ASYNC, 6,
                  "GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    MockRead data_reads[] = {
        MockRead(ASYNC, 1, "HTTP/1.1 401 Unauthorized\r\n"),
        MockRead(ASYNC, 2, "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
        MockRead(ASYNC, 3, "Content-Type: text/html; charset=iso-8859-1\r\n"),
        MockRead(ASYNC, 4, "Content-Length: 14\r\n\r\n"),
        MockRead(i == 0 ? ASYNC : SYNCHRONOUS, 5, "Unauthorized\r\n"),

        // Lastly, the server responds with the actual content.
        MockRead(ASYNC, 7, "HTTP/1.1 200 OK\r\n"),
        MockRead(ASYNC, 8, "Content-Type: text/html; charset=iso-8859-1\r\n"),
        MockRead(ASYNC, 9, "Content-Length: 5\r\n\r\n"),
        MockRead(ASYNC, 10, "Hello"),
    };

    SequencedSocketData data(data_reads, data_writes);
    data.set_busy_before_sync_reads(true);
    session_deps_.socket_factory->AddSocketDataProvider(&data);

    TestCompletionCallback callback1;

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    ASS
"""


```