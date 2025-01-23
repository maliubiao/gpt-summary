Response:
The user wants a summary of the functionality of the provided C++ code, which is part of the Chromium network stack and specifically focuses on testing the SPDY framer. I need to identify the main purpose of the tests, any connections to JavaScript, analyze any logical deductions, pinpoint potential user errors, describe how a user might end up running this code, and finally summarize the functionality of this specific part (part 6 of 7).

Here's a breakdown of the code's functionality:

1. **Error Handling Tests**: The code tests how the SPDY framer handles various error conditions during the decoding of HTTP/2 frames. It checks specific error codes and the framer's state after encountering errors.
2. **Frame Flag Tests**:  A significant portion of the code iterates through all possible flag combinations for different HTTP/2 frame types (DATA, RST_STREAM, SETTINGS, GOAWAY, HEADERS, PING, WINDOW_UPDATE, PUSH_PROMISE, CONTINUATION, ALTSVC, PRIORITY_UPDATE). For each combination, it verifies that the framer correctly parses the flags and calls the appropriate methods on the `SpdyFramerVisitor`. It also checks for errors when invalid flag combinations are used.
3. **Status and Stream ID Bounds Tests**: The code checks how the framer handles out-of-bounds status codes in RST_STREAM and GOAWAY frames, as well as out-of-bounds stream IDs in GOAWAY frames.
4. **ALTSVC Frame Tests**: There are specific tests for the ALTSVC frame, including cases with and without an origin, handling of empty protocol IDs, incorrect lengths, chunked delivery, and handling of invalid Alt-Svc-Field-Values.
5. **PRIORITY_UPDATE Frame Tests**: The code includes tests for the newly introduced PRIORITY_UPDATE frame, verifying its parsing, handling of empty priority field values, and checking for errors with empty or short payloads, as well as incorrect stream IDs.

Relationship to JavaScript:  SPDY and HTTP/2 are underlying protocols used by web browsers to communicate with servers. JavaScript running in a browser makes requests that eventually are encoded and decoded using this type of code.

Logical Deductions: The code uses assertions and mock objects to verify the expected behavior of the framer. The `EXPECT_CALL` statements define the expected interactions with the `SpdyFramerVisitor` based on the input frame and flags.

User/Programming Errors: The tests implicitly cover many common programming errors when implementing HTTP/2, such as setting incorrect frame lengths, using invalid flag combinations, or providing incorrect data for specific frame types.

User Journey/Debugging:  A developer working on network code in Chromium, especially when dealing with HTTP/2 or QUIC (which uses parts of this codebase), might encounter these tests failing if there's a bug in the SPDY framer implementation.

Summary of Part 6: This section primarily focuses on thoroughly testing the handling of frame flags for various HTTP/2 frame types. It systematically checks all possible flag combinations and verifies the framer's behavior, including error detection for invalid flag settings. It also includes tests for the ALTSVC and PRIORITY_UPDATE frames.
```cpp
ROL_FRAME_SIZE));
  EXPECT_STREQ("OVERSIZED_PAYLOAD",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_OVERSIZED_PAYLOAD));
  EXPECT_STREQ("UNKNOWN_ERROR", Http2DecoderAdapter::SpdyFramerErrorToString(
                                    Http2DecoderAdapter::LAST_ERROR));
  EXPECT_STREQ("UNKNOWN_ERROR",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   static_cast<Http2DecoderAdapter::SpdyFramerError>(
                       Http2DecoderAdapter::LAST_ERROR + 1)));
}

TEST_P(SpdyFramerTest, DataFrameFlagsV4) {
  uint8_t valid_data_flags = DATA_FLAG_FIN | DATA_FLAG_PADDED;

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

    deframer_->set_visitor(&visitor);

    SpdyDataIR data_ir(/* stream_id = */ 1, "hello");
    SpdySerializedFrame frame(framer_.SerializeData(data_ir));
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(1, 5, 0x0, flags));
    if (flags & ~valid_data_flags) {
      EXPECT_CALL(visitor, OnError(_, _));
    } else {
      EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, flags & DATA_FLAG_FIN));
      if (flags & DATA_FLAG_PADDED) {
        // The first byte of payload is parsed as padding length, but 'h'
        // (0x68) is too large a padding length for a 5 byte payload.
        EXPECT_CALL(visitor, OnStreamPadding(_, 1));
        // Expect Error since the frame ends prematurely.
        EXPECT_CALL(visitor, OnError(_, _));
      } else {
        EXPECT_CALL(visitor, OnStreamFrameData(_, _, 5));
        if (flags & DATA_FLAG_FIN) {
          EXPECT_CALL(visitor, OnStreamEnd(_));
        }
      }
    }

    deframer_->ProcessInput(frame.data(), frame.size());
    if (flags & ~valid_data_flags) {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_DATA_FRAME_FLAGS,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    } else if (flags & DATA_FLAG_PADDED) {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_PADDING,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    } else {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    }
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, RstStreamFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    deframer_->set_visitor(&visitor);

    SpdyRstStreamIR rst_stream(/* stream_id = */ 13, ERROR_CODE_CANCEL);
    SpdySerializedFrame frame(framer_.SerializeRstStream(rst_stream));
    if (use_output_) {
      output_.Reset();
      ASSERT_TRUE(framer_.SerializeRstStream(rst_stream, &output_));
      frame = MakeSerializedFrame(output_.Begin(), output_.Size());
    }
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(13, 4, 0x3, flags));
    EXPECT_CALL(visitor, OnRstStream(13, ERROR_CODE_CANCEL));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, SettingsFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    deframer_->set_visitor(&visitor);

    SpdySettingsIR settings_ir;
    settings_ir.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, 16);
    SpdySerializedFrame frame(framer_.SerializeSettings(settings_ir));
    if (use_output_) {
      output_.Reset();
      ASSERT_TRUE(framer_.SerializeSettings(settings_ir, &output_));
      frame = MakeSerializedFrame(output_.Begin(), output_.Size());
    }
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(0, 6, 0x4, flags));
    if (flags & SETTINGS_FLAG_ACK) {
      EXPECT_CALL(visitor, OnError(_, _));
    } else {
      EXPECT_CALL(visitor, OnSettings());
      EXPECT_CALL(visitor, OnSetting(SETTINGS_INITIAL_WINDOW_SIZE, 16));
      EXPECT_CALL(visitor, OnSettingsEnd());
    }

    deframer_->ProcessInput(frame.data(), frame.size());
    if (flags & SETTINGS_FLAG_ACK) {
      // The frame is invalid because ACK frames should have no payload.
      EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    } else {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    }
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, GoawayFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

    deframer_->set_visitor(&visitor);

    SpdyGoAwayIR goaway_ir(/* last_good_stream_id = */ 97, ERROR_CODE_NO_ERROR,
                           "test");
    SpdySerializedFrame frame(framer_.SerializeGoAway(goaway_ir));
    if (use_output_) {
      output_.Reset();
      ASSERT_TRUE(framer_.SerializeGoAway(goaway_ir, &output_));
      frame = MakeSerializedFrame(output_.Begin(), output_.Size());
    }
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x7, flags));
    EXPECT_CALL(visitor, OnGoAway(97, ERROR_CODE_NO_ERROR));
    EXPECT_CALL(visitor, OnGoAwayFrameData)
        .WillRepeatedly(testing::Return(true));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, HeadersFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
    Http2DecoderAdapter deframer;
    deframer.set_visitor(&visitor);

    SpdyHeadersIR headers_ir(/* stream_id = */ 57);
    if (flags & HEADERS_FLAG_PRIORITY) {
      headers_ir.set_weight(3);
      headers_ir.set_has_priority(true);
      headers_ir.set_parent_stream_id(5);
      headers_ir.set_exclusive(true);
    }
    headers_ir.SetHeader("foo", "bar");
    SpdySerializedFrame frame(SpdyFramerPeer::SerializeHeaders(
        &framer, headers_ir, use_output_ ? &output_ : nullptr));
    uint8_t set_flags = flags & ~HEADERS_FLAG_PADDED;
    SetFrameFlags(&frame, set_flags);

    // Expected callback values
    SpdyStreamId stream_id = 57;
    bool has_priority = false;
    int weight = 0;
    SpdyStreamId parent_stream_id = 0;
    bool exclusive = false;
    bool fin = flags & CONTROL_FLAG_FIN;
    bool end = flags & HEADERS_FLAG_END_HEADERS;
    if (flags & HEADERS_FLAG_PRIORITY) {
      has_priority = true;
      weight = 3;
      parent_stream_id = 5;
      exclusive = true;
    }
    EXPECT_CALL(visitor, OnCommonHeader(stream_id, _, 0x1, set_flags));
    EXPECT_CALL(visitor, OnHeaders(stream_id, _, has_priority, weight,
                                   parent_stream_id, exclusive, fin, end));
    EXPECT_CALL(visitor, OnHeaderFrameStart(57)).Times(1);
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(57)).Times(1);
    }
    if (flags & DATA_FLAG_FIN && end) {
      EXPECT_CALL(visitor, OnStreamEnd(_));
    } else {
      // Do not close the stream if we are expecting a CONTINUATION frame.
      EXPECT_CALL(visitor, OnStreamEnd(_)).Times(0);
    }

    deframer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer.state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer.spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer.spdy_framer_error());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, PingFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    deframer_->set_visitor(&visitor);

    SpdySerializedFrame frame(framer_.SerializePing(SpdyPingIR(42)));
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(0, 8, 0x6, flags));
    EXPECT_CALL(visitor, OnPing(42, flags & PING_FLAG_ACK));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, WindowUpdateFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

    deframer_->set_visitor(&visitor);

    SpdySerializedFrame frame(framer_.SerializeWindowUpdate(
        SpdyWindowUpdateIR(/* stream_id = */ 4, /* delta = */ 1024)));
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(4, 4, 0x8, flags));
    EXPECT_CALL(visitor, OnWindowUpdate(4, 1024));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, PushPromiseFrameFlags) {
  const SpdyStreamId client_id = 123;   // Must be odd.
  const SpdyStreamId promised_id = 22;  // Must be even.
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    testing::StrictMock<test::MockDebugVisitor> debug_visitor;
    SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
    Http2DecoderAdapter deframer;
    deframer.set_visitor(&visitor);
    deframer.set_debug_visitor(&debug_visitor);
    framer.set_debug_visitor(&debug_visitor);

    EXPECT_CALL(
        debug_visitor,
        OnSendCompressedFrame(client_id, SpdyFrameType::PUSH_PROMISE, _, _));

    SpdyPushPromiseIR push_promise(client_id, promised_id);
    push_promise.SetHeader("foo", "bar");
    SpdySerializedFrame frame(SpdyFramerPeer::SerializePushPromise(
        &framer, push_promise, use_output_ ? &output_ : nullptr));
    // TODO(jgraettinger): Add padding to SpdyPushPromiseIR,
    // and implement framing.
    SetFrameFlags(&frame, flags & ~HEADERS_FLAG_PADDED);

    bool end = flags & PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
    EXPECT_CALL(debug_visitor, OnReceiveCompressedFrame(
                                   client_id, SpdyFrameType::PUSH_PROMISE, _));
    EXPECT_CALL(visitor, OnCommonHeader(client_id, _, 0x5,
                                        flags & ~HEADERS_FLAG_PADDED));
    EXPECT_CALL(visitor, OnPushPromise(client_id, promised_id, end));
    EXPECT_CALL(visitor, OnHeaderFrameStart(client_id)).Times(1);
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(client_id)).Times(1);
    }

    deframer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer.state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer.spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer.spdy_framer_error());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, ContinuationFrameFlags) {
  uint8_t flags = 0;
  do {
    if (use_output_) {
      output_.Reset();
    }
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    testing::StrictMock<test::MockDebugVisitor> debug_visitor;
    SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
    Http2DecoderAdapter deframer;
    deframer.set_visitor(&visitor);
    deframer.set_debug_visitor(&debug_visitor);
    framer.set_debug_visitor(&debug_visitor);

    EXPECT_CALL(debug_visitor,
                OnSendCompressedFrame(42, SpdyFrameType::HEADERS, _, _));
    EXPECT_CALL(debug_visitor,
                OnReceiveCompressedFrame(42, SpdyFrameType::HEADERS, _));
    EXPECT_CALL(visitor, OnCommonHeader(42, _, 0x1, 0));
    EXPECT_CALL(visitor, OnHeaders(42, _, false, 0, 0, false, false, false));
    EXPECT_CALL(visitor, OnHeaderFrameStart(42)).Times(1);

    SpdyHeadersIR headers_ir(/* stream_id = */ 42);
    headers_ir.SetHeader("foo", "bar");
    SpdySerializedFrame frame0;
    if (use_output_) {
      EXPECT_TRUE(framer.SerializeHeaders(headers_ir, &output_));
      frame0 = MakeSerializedFrame(output_.Begin(), output_.Size());
    } else {
      frame0 = framer.SerializeHeaders(headers_ir);
    }
    SetFrameFlags(&frame0, 0);

    SpdyContinuationIR continuation(/* stream_id = */ 42);
    SpdySerializedFrame frame1;
    if (use_output_) {
      char* begin = output_.Begin() + output_.Size();
      ASSERT_TRUE(framer.SerializeContinuation(continuation, &output_));
      frame1 = MakeSerializedFrame(begin, output_.Size() - frame0.size());
    } else {
      frame1 = framer.SerializeContinuation(continuation);
    }
    SetFrameFlags(&frame1, flags);

    EXPECT_CALL(debug_visitor,
                OnReceiveCompressedFrame(42, SpdyFrameType::CONTINUATION, _));
    EXPECT_CALL(visitor, OnCommonHeader(42, _, 0x9, flags));
    EXPECT_CALL(visitor,
                OnContinuation(42, _, flags & HEADERS_FLAG_END_HEADERS));
    bool end = flags & HEADERS_FLAG_END_HEADERS;
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(42)).Times(1);
    }

    deframer.ProcessInput(frame0.data(), frame0.size());
    deframer.ProcessInput(frame1.data(), frame1.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer.state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer.spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer.spdy_framer_error());
  } while (++flags != 0);
}

// TODO(mlavan): Add TEST_P(SpdyFramerTest, AltSvcFrameFlags)

// Test handling of a RST_STREAM with out-of-bounds status codes.
TEST_P(SpdyFramerTest, RstStreamStatusBounds) {
  const unsigned char kH2RstStreamInvalid[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
  };
  const unsigned char kH2RstStreamNumStatusCodes[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0xff,  //  Error: 255
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(1, 4, 0x3, 0x0));
  EXPECT_CALL(visitor, OnRstStream(1, ERROR_CODE_NO_ERROR));
  deframer_->ProcessInput(reinterpret_cast<const char*>(kH2RstStreamInvalid),
                          ABSL_ARRAYSIZE(kH2RstStreamInvalid));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
  deframer_ = std::make_unique<Http2DecoderAdapter>();
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(1, 4, 0x3, 0x0));
  EXPECT_CALL(visitor, OnRstStream(1, ERROR_CODE_INTERNAL_ERROR));
  deframer_->ProcessInput(
      reinterpret_cast<const char*>(kH2RstStreamNumStatusCodes),
      ABSL_ARRAYSIZE(kH2RstStreamNumStatusCodes));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test handling of GOAWAY frames with out-of-bounds status code.
TEST_P(SpdyFramerTest, GoAwayStatusBounds) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x0a,        // Length: 10
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x00, 0x00, 0x01,  //   Last: 1
      0xff, 0xff, 0xff, 0xff,  //  Error: 0xffffffff
      0x47, 0x41,              // Description
  };
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 10, 0x7, 0x0));
  EXPECT_CALL(visitor, OnGoAway(1, ERROR_CODE_INTERNAL_ERROR));
  EXPECT_CALL(visitor, OnGoAwayFrameData).WillRepeatedly(testing::Return(true));
  deframer_->ProcessInput(reinterpret_cast<const char*>(kH2FrameData),
                          ABSL_ARRAYSIZE(kH2FrameData));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Tests handling of a GOAWAY frame with out-of-bounds stream ID.
TEST_P(SpdyFramerTest, GoAwayStreamIdBounds) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x08,        // Length: 8
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0xff, 0xff, 0xff, 0xff,  //   Last: 0x7fffffff (R-bit set)
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 8, 0x7, 0x0));
  EXPECT_CALL(visitor, OnGoAway(0x7fffffff, ERROR_CODE_NO_ERROR));
  EXPECT_CALL(visitor, OnGoAwayFrameData).WillRepeatedly(testing::Return(true));
  deframer_->ProcessInput(reinterpret_cast<const char*>(kH2FrameData),
                          ABSL_ARRAYSIZE(kH2FrameData));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, OnAltSvcWithOrigin) {
  const SpdyStreamId kStreamId = 0;  // Stream id must be zero if origin given.

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc1);
  altsvc_vector.push_back(altsvc2);
  EXPECT_CALL(visitor, OnCommonHeader(kStreamId, _, 0x0A, 0x0));
  EXPECT_CALL(visitor,
              OnAltSvc(kStreamId, absl::string_view("o_r|g!n"), altsvc_vector));

  SpdyAltSvcIR altsvc_ir(kStreamId);
  altsvc_ir.set_origin("o_r|g!n");
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);
  SpdySerializedFrame frame(framer_.SerializeFrame(altsvc_ir));
  if (use_output_) {
    output_.Reset();
    EXPECT_EQ(framer_.SerializeFrame(altsvc_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  deframer_->ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, OnAltSvcNoOrigin) {
  const SpdyStreamId kStreamId = 1;

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc1);
  altsvc_vector.push_back(altsvc2);
  EXPECT_CALL(visitor, OnCommonHeader(kStreamId, _, 0x0A, 0x0));
  EXPECT_CALL(visitor,
              OnAltSvc(kStreamId, absl::string_view(""), altsvc_vector));

  SpdyAltSvcIR altsvc_ir(kStreamId);
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2
### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
ROL_FRAME_SIZE));
  EXPECT_STREQ("OVERSIZED_PAYLOAD",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_OVERSIZED_PAYLOAD));
  EXPECT_STREQ("UNKNOWN_ERROR", Http2DecoderAdapter::SpdyFramerErrorToString(
                                    Http2DecoderAdapter::LAST_ERROR));
  EXPECT_STREQ("UNKNOWN_ERROR",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   static_cast<Http2DecoderAdapter::SpdyFramerError>(
                       Http2DecoderAdapter::LAST_ERROR + 1)));
}

TEST_P(SpdyFramerTest, DataFrameFlagsV4) {
  uint8_t valid_data_flags = DATA_FLAG_FIN | DATA_FLAG_PADDED;

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

    deframer_->set_visitor(&visitor);

    SpdyDataIR data_ir(/* stream_id = */ 1, "hello");
    SpdySerializedFrame frame(framer_.SerializeData(data_ir));
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(1, 5, 0x0, flags));
    if (flags & ~valid_data_flags) {
      EXPECT_CALL(visitor, OnError(_, _));
    } else {
      EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, flags & DATA_FLAG_FIN));
      if (flags & DATA_FLAG_PADDED) {
        // The first byte of payload is parsed as padding length, but 'h'
        // (0x68) is too large a padding length for a 5 byte payload.
        EXPECT_CALL(visitor, OnStreamPadding(_, 1));
        // Expect Error since the frame ends prematurely.
        EXPECT_CALL(visitor, OnError(_, _));
      } else {
        EXPECT_CALL(visitor, OnStreamFrameData(_, _, 5));
        if (flags & DATA_FLAG_FIN) {
          EXPECT_CALL(visitor, OnStreamEnd(_));
        }
      }
    }

    deframer_->ProcessInput(frame.data(), frame.size());
    if (flags & ~valid_data_flags) {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_DATA_FRAME_FLAGS,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    } else if (flags & DATA_FLAG_PADDED) {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_PADDING,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    } else {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    }
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, RstStreamFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    deframer_->set_visitor(&visitor);

    SpdyRstStreamIR rst_stream(/* stream_id = */ 13, ERROR_CODE_CANCEL);
    SpdySerializedFrame frame(framer_.SerializeRstStream(rst_stream));
    if (use_output_) {
      output_.Reset();
      ASSERT_TRUE(framer_.SerializeRstStream(rst_stream, &output_));
      frame = MakeSerializedFrame(output_.Begin(), output_.Size());
    }
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(13, 4, 0x3, flags));
    EXPECT_CALL(visitor, OnRstStream(13, ERROR_CODE_CANCEL));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, SettingsFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    deframer_->set_visitor(&visitor);

    SpdySettingsIR settings_ir;
    settings_ir.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, 16);
    SpdySerializedFrame frame(framer_.SerializeSettings(settings_ir));
    if (use_output_) {
      output_.Reset();
      ASSERT_TRUE(framer_.SerializeSettings(settings_ir, &output_));
      frame = MakeSerializedFrame(output_.Begin(), output_.Size());
    }
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(0, 6, 0x4, flags));
    if (flags & SETTINGS_FLAG_ACK) {
      EXPECT_CALL(visitor, OnError(_, _));
    } else {
      EXPECT_CALL(visitor, OnSettings());
      EXPECT_CALL(visitor, OnSetting(SETTINGS_INITIAL_WINDOW_SIZE, 16));
      EXPECT_CALL(visitor, OnSettingsEnd());
    }

    deframer_->ProcessInput(frame.data(), frame.size());
    if (flags & SETTINGS_FLAG_ACK) {
      // The frame is invalid because ACK frames should have no payload.
      EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    } else {
      EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
      EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
                deframer_->spdy_framer_error())
          << Http2DecoderAdapter::SpdyFramerErrorToString(
                 deframer_->spdy_framer_error());
    }
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, GoawayFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

    deframer_->set_visitor(&visitor);

    SpdyGoAwayIR goaway_ir(/* last_good_stream_id = */ 97, ERROR_CODE_NO_ERROR,
                           "test");
    SpdySerializedFrame frame(framer_.SerializeGoAway(goaway_ir));
    if (use_output_) {
      output_.Reset();
      ASSERT_TRUE(framer_.SerializeGoAway(goaway_ir, &output_));
      frame = MakeSerializedFrame(output_.Begin(), output_.Size());
    }
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x7, flags));
    EXPECT_CALL(visitor, OnGoAway(97, ERROR_CODE_NO_ERROR));
    EXPECT_CALL(visitor, OnGoAwayFrameData)
        .WillRepeatedly(testing::Return(true));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, HeadersFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
    Http2DecoderAdapter deframer;
    deframer.set_visitor(&visitor);

    SpdyHeadersIR headers_ir(/* stream_id = */ 57);
    if (flags & HEADERS_FLAG_PRIORITY) {
      headers_ir.set_weight(3);
      headers_ir.set_has_priority(true);
      headers_ir.set_parent_stream_id(5);
      headers_ir.set_exclusive(true);
    }
    headers_ir.SetHeader("foo", "bar");
    SpdySerializedFrame frame(SpdyFramerPeer::SerializeHeaders(
        &framer, headers_ir, use_output_ ? &output_ : nullptr));
    uint8_t set_flags = flags & ~HEADERS_FLAG_PADDED;
    SetFrameFlags(&frame, set_flags);

    // Expected callback values
    SpdyStreamId stream_id = 57;
    bool has_priority = false;
    int weight = 0;
    SpdyStreamId parent_stream_id = 0;
    bool exclusive = false;
    bool fin = flags & CONTROL_FLAG_FIN;
    bool end = flags & HEADERS_FLAG_END_HEADERS;
    if (flags & HEADERS_FLAG_PRIORITY) {
      has_priority = true;
      weight = 3;
      parent_stream_id = 5;
      exclusive = true;
    }
    EXPECT_CALL(visitor, OnCommonHeader(stream_id, _, 0x1, set_flags));
    EXPECT_CALL(visitor, OnHeaders(stream_id, _, has_priority, weight,
                                   parent_stream_id, exclusive, fin, end));
    EXPECT_CALL(visitor, OnHeaderFrameStart(57)).Times(1);
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(57)).Times(1);
    }
    if (flags & DATA_FLAG_FIN && end) {
      EXPECT_CALL(visitor, OnStreamEnd(_));
    } else {
      // Do not close the stream if we are expecting a CONTINUATION frame.
      EXPECT_CALL(visitor, OnStreamEnd(_)).Times(0);
    }

    deframer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer.state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer.spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer.spdy_framer_error());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, PingFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    deframer_->set_visitor(&visitor);

    SpdySerializedFrame frame(framer_.SerializePing(SpdyPingIR(42)));
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(0, 8, 0x6, flags));
    EXPECT_CALL(visitor, OnPing(42, flags & PING_FLAG_ACK));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, WindowUpdateFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

    deframer_->set_visitor(&visitor);

    SpdySerializedFrame frame(framer_.SerializeWindowUpdate(
        SpdyWindowUpdateIR(/* stream_id = */ 4, /* delta = */ 1024)));
    SetFrameFlags(&frame, flags);

    EXPECT_CALL(visitor, OnCommonHeader(4, 4, 0x8, flags));
    EXPECT_CALL(visitor, OnWindowUpdate(4, 1024));

    deframer_->ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
    deframer_ = std::make_unique<Http2DecoderAdapter>();
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, PushPromiseFrameFlags) {
  const SpdyStreamId client_id = 123;   // Must be odd.
  const SpdyStreamId promised_id = 22;  // Must be even.
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    testing::StrictMock<test::MockDebugVisitor> debug_visitor;
    SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
    Http2DecoderAdapter deframer;
    deframer.set_visitor(&visitor);
    deframer.set_debug_visitor(&debug_visitor);
    framer.set_debug_visitor(&debug_visitor);

    EXPECT_CALL(
        debug_visitor,
        OnSendCompressedFrame(client_id, SpdyFrameType::PUSH_PROMISE, _, _));

    SpdyPushPromiseIR push_promise(client_id, promised_id);
    push_promise.SetHeader("foo", "bar");
    SpdySerializedFrame frame(SpdyFramerPeer::SerializePushPromise(
        &framer, push_promise, use_output_ ? &output_ : nullptr));
    // TODO(jgraettinger): Add padding to SpdyPushPromiseIR,
    // and implement framing.
    SetFrameFlags(&frame, flags & ~HEADERS_FLAG_PADDED);

    bool end = flags & PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
    EXPECT_CALL(debug_visitor, OnReceiveCompressedFrame(
                                   client_id, SpdyFrameType::PUSH_PROMISE, _));
    EXPECT_CALL(visitor, OnCommonHeader(client_id, _, 0x5,
                                        flags & ~HEADERS_FLAG_PADDED));
    EXPECT_CALL(visitor, OnPushPromise(client_id, promised_id, end));
    EXPECT_CALL(visitor, OnHeaderFrameStart(client_id)).Times(1);
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(client_id)).Times(1);
    }

    deframer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer.state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer.spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer.spdy_framer_error());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, ContinuationFrameFlags) {
  uint8_t flags = 0;
  do {
    if (use_output_) {
      output_.Reset();
    }
    SCOPED_TRACE(testing::Message()
                 << "Flags " << std::hex << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    testing::StrictMock<test::MockDebugVisitor> debug_visitor;
    SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
    Http2DecoderAdapter deframer;
    deframer.set_visitor(&visitor);
    deframer.set_debug_visitor(&debug_visitor);
    framer.set_debug_visitor(&debug_visitor);

    EXPECT_CALL(debug_visitor,
                OnSendCompressedFrame(42, SpdyFrameType::HEADERS, _, _));
    EXPECT_CALL(debug_visitor,
                OnReceiveCompressedFrame(42, SpdyFrameType::HEADERS, _));
    EXPECT_CALL(visitor, OnCommonHeader(42, _, 0x1, 0));
    EXPECT_CALL(visitor, OnHeaders(42, _, false, 0, 0, false, false, false));
    EXPECT_CALL(visitor, OnHeaderFrameStart(42)).Times(1);

    SpdyHeadersIR headers_ir(/* stream_id = */ 42);
    headers_ir.SetHeader("foo", "bar");
    SpdySerializedFrame frame0;
    if (use_output_) {
      EXPECT_TRUE(framer.SerializeHeaders(headers_ir, &output_));
      frame0 = MakeSerializedFrame(output_.Begin(), output_.Size());
    } else {
      frame0 = framer.SerializeHeaders(headers_ir);
    }
    SetFrameFlags(&frame0, 0);

    SpdyContinuationIR continuation(/* stream_id = */ 42);
    SpdySerializedFrame frame1;
    if (use_output_) {
      char* begin = output_.Begin() + output_.Size();
      ASSERT_TRUE(framer.SerializeContinuation(continuation, &output_));
      frame1 = MakeSerializedFrame(begin, output_.Size() - frame0.size());
    } else {
      frame1 = framer.SerializeContinuation(continuation);
    }
    SetFrameFlags(&frame1, flags);

    EXPECT_CALL(debug_visitor,
                OnReceiveCompressedFrame(42, SpdyFrameType::CONTINUATION, _));
    EXPECT_CALL(visitor, OnCommonHeader(42, _, 0x9, flags));
    EXPECT_CALL(visitor,
                OnContinuation(42, _, flags & HEADERS_FLAG_END_HEADERS));
    bool end = flags & HEADERS_FLAG_END_HEADERS;
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(42)).Times(1);
    }

    deframer.ProcessInput(frame0.data(), frame0.size());
    deframer.ProcessInput(frame1.data(), frame1.size());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer.state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer.spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer.spdy_framer_error());
  } while (++flags != 0);
}

// TODO(mlavan): Add TEST_P(SpdyFramerTest, AltSvcFrameFlags)

// Test handling of a RST_STREAM with out-of-bounds status codes.
TEST_P(SpdyFramerTest, RstStreamStatusBounds) {
  const unsigned char kH2RstStreamInvalid[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
  };
  const unsigned char kH2RstStreamNumStatusCodes[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0xff,  //  Error: 255
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(1, 4, 0x3, 0x0));
  EXPECT_CALL(visitor, OnRstStream(1, ERROR_CODE_NO_ERROR));
  deframer_->ProcessInput(reinterpret_cast<const char*>(kH2RstStreamInvalid),
                          ABSL_ARRAYSIZE(kH2RstStreamInvalid));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
  deframer_ = std::make_unique<Http2DecoderAdapter>();
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(1, 4, 0x3, 0x0));
  EXPECT_CALL(visitor, OnRstStream(1, ERROR_CODE_INTERNAL_ERROR));
  deframer_->ProcessInput(
      reinterpret_cast<const char*>(kH2RstStreamNumStatusCodes),
      ABSL_ARRAYSIZE(kH2RstStreamNumStatusCodes));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test handling of GOAWAY frames with out-of-bounds status code.
TEST_P(SpdyFramerTest, GoAwayStatusBounds) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x0a,        // Length: 10
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x00, 0x00, 0x01,  //   Last: 1
      0xff, 0xff, 0xff, 0xff,  //  Error: 0xffffffff
      0x47, 0x41,              // Description
  };
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 10, 0x7, 0x0));
  EXPECT_CALL(visitor, OnGoAway(1, ERROR_CODE_INTERNAL_ERROR));
  EXPECT_CALL(visitor, OnGoAwayFrameData).WillRepeatedly(testing::Return(true));
  deframer_->ProcessInput(reinterpret_cast<const char*>(kH2FrameData),
                          ABSL_ARRAYSIZE(kH2FrameData));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Tests handling of a GOAWAY frame with out-of-bounds stream ID.
TEST_P(SpdyFramerTest, GoAwayStreamIdBounds) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x08,        // Length: 8
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0xff, 0xff, 0xff, 0xff,  //   Last: 0x7fffffff (R-bit set)
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 8, 0x7, 0x0));
  EXPECT_CALL(visitor, OnGoAway(0x7fffffff, ERROR_CODE_NO_ERROR));
  EXPECT_CALL(visitor, OnGoAwayFrameData).WillRepeatedly(testing::Return(true));
  deframer_->ProcessInput(reinterpret_cast<const char*>(kH2FrameData),
                          ABSL_ARRAYSIZE(kH2FrameData));
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, OnAltSvcWithOrigin) {
  const SpdyStreamId kStreamId = 0;  // Stream id must be zero if origin given.

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc1);
  altsvc_vector.push_back(altsvc2);
  EXPECT_CALL(visitor, OnCommonHeader(kStreamId, _, 0x0A, 0x0));
  EXPECT_CALL(visitor,
              OnAltSvc(kStreamId, absl::string_view("o_r|g!n"), altsvc_vector));

  SpdyAltSvcIR altsvc_ir(kStreamId);
  altsvc_ir.set_origin("o_r|g!n");
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);
  SpdySerializedFrame frame(framer_.SerializeFrame(altsvc_ir));
  if (use_output_) {
    output_.Reset();
    EXPECT_EQ(framer_.SerializeFrame(altsvc_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  deframer_->ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, OnAltSvcNoOrigin) {
  const SpdyStreamId kStreamId = 1;

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc1);
  altsvc_vector.push_back(altsvc2);
  EXPECT_CALL(visitor, OnCommonHeader(kStreamId, _, 0x0A, 0x0));
  EXPECT_CALL(visitor,
              OnAltSvc(kStreamId, absl::string_view(""), altsvc_vector));

  SpdyAltSvcIR altsvc_ir(kStreamId);
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);
  SpdySerializedFrame frame(framer_.SerializeFrame(altsvc_ir));
  deframer_->ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, OnAltSvcEmptyProtocolId) {
  const SpdyStreamId kStreamId = 0;  // Stream id must be zero if origin given.

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(kStreamId, _, 0x0A, 0x0));
  EXPECT_CALL(visitor,
              OnError(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME, _));

  SpdyAltSvcIR altsvc_ir(kStreamId);
  altsvc_ir.set_origin("o1");
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector()));
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "", "h1", 443, 10, SpdyAltSvcWireFormat::VersionVector()));
  SpdySerializedFrame frame(framer_.SerializeFrame(altsvc_ir));
  if (use_output_) {
    output_.Reset();
    EXPECT_EQ(framer_.SerializeFrame(altsvc_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  deframer_->ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, OnAltSvcBadLengths) {
  const unsigned char kType = SerializeFrameType(SpdyFrameType::ALTSVC);
  const unsigned char kFrameDataOriginLenLargerThanFrame[] = {
      0x00, 0x00, 0x05, kType, 0x00, 0x00, 0x00,
      0x00, 0x03, 0x42, 0x42,  'f',  'o',  'o',
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);

  deframer_->set_visitor(&visitor);
  visitor.SimulateInFramer(kFrameDataOriginLenLargerThanFrame,
                           sizeof(kFrameDataOriginLenLargerThanFrame));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME,
            visitor.deframer_.spdy_framer_error());
}

// Tests handling of ALTSVC frames delivered in small chunks.
TEST_P(SpdyFramerTest, ReadChunkedAltSvcFrame) {
  SpdyAltSvcIR altsvc_ir(/* stream_id = */ 1);
  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);

  SpdySerializedFrame control_frame(framer_.SerializeAltSvc(altsvc_ir));
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);

  // Read data in small chunks.
  size_t framed_data = 0;
  size_t unframed_data = control_frame.size();
  size_t kReadChunkSize = 5;  // Read five bytes at a time.
  while (unframed_data > 0) {
    size_t to_read = std::min(kReadChunkSize, unframed_data);
    visitor.SimulateInFramer(
        reinterpret_cast<unsigned char*>(control_frame.data() + framed_data),
        to_read);
    unframed_data -= to_read;
    framed_data += to_read;
  }
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.altsvc_count_);
  ASSERT_NE(nullptr, visitor.test_altsvc_ir_);
  ASSERT_EQ(2u, visitor.test_altsvc_ir_->altsvc_vector().size());
  EXPECT_TRUE(visitor.test_altsvc_ir_->altsvc_vector()[0] == altsvc1);
  EXPECT_TRUE(visitor.test_altsvc_ir_->altsvc_vector()[1] == altsvc2);
}

// While RFC7838 Section 4 says that an ALTSVC frame on stream 0 with empty
// origin MUST be ignored, it is not implemented at the framer level: instead,
// such frames are passed on to the consumer.
TEST_P(SpdyFramerTest, ReadAltSvcFrame) {
  constexpr struct {
    uint32_t stream_id;
    const char* origin;
  } test_cases[] = {{0, ""},
                    {1, ""},
                    {0, "https://www.example.com"},
                    {1, "https://www.example.com"}};
  for (const auto& test_case : test_cases) {
    SpdyAltSvcIR altsvc_ir(test_case.stream_id);
    SpdyAltSvcWireFormat::AlternativeService altsvc(
        "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
    altsvc_ir.add_altsvc(altsvc);
    altsvc_ir.set_origin(test_case.origin);
    SpdySerializedFrame frame(framer_.SerializeAltSvc(altsvc_ir));

    TestSpdyVisitor visitor(SpdyFramer::ENABLE_COMPRESSION);
    deframer_->set_visitor(&visitor);
    deframer_->ProcessInput(frame.data(), frame.size());

    EXPECT_EQ(0, visitor.error_count_);
    EXPECT_EQ(1, visitor.altsvc_count_);
    EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
    EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR,
              deframer_->spdy_framer_error())
        << Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());
  }
}

// An ALTSVC frame with invalid Alt-Svc-Field-Value results in an error.
TEST_P(SpdyFramerTest, ErrorOnAltSvcFrameWithInvalidValue) {
  // Alt-Svc-Field-Value must be "clear" or must contain an "=" character
  // per RFC7838 Section 3.
  const char kFrameData[] = {
      0x00, 0x00, 0x16,        //     Length: 22
      0x0a,                    //       Type: ALTSVC
      0x00,                    //      Flags: none
      0x00, 0x00, 0x00, 0x01,  //     Stream: 1
      0x00, 0x00,              // Origin-Len: 0
      0x74, 0x68, 0x69, 0x73,  // thisisnotavalidvalue
      0x69, 0x73, 0x6e, 0x6f, 0x74, 0x61, 0x76, 0x61,
      0x6c, 0x69, 0x64, 0x76, 0x61, 0x6c, 0x75, 0x65,
  };

  TestSpdyVisitor visitor(SpdyFramer::ENABLE_COMPRESSION);
  deframer_->set_visitor(&visitor);
  deframer_->ProcessInput(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(0, visitor.altsvc_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, ReadPriorityUpdateFrame) {
  const char kFrameData[] = {
      0x00, 0x00, 0x07,        // payload length
      0x10,                    // frame type PRIORITY_UPDATE
      0x00,                    // flags
      0x00, 0x00, 0x00, 0x00,  // stream ID, must be 0
      0x00, 0x00, 0x00, 0x03,  // prioritized stream ID, must not be zero
      'f',  'o',  'o'          // priority field value
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 7, 0x10, 0x0));
  EXPECT_CALL(visitor, OnPriorityUpdate(3, "foo"));
  deframer_->ProcessInput(kFrameData, sizeof(kFrameData));
  EXPECT_FALSE(deframer_->HasError());
}

TEST_P(SpdyFramerTest, ReadPriorityUpdateFrameWithEmptyPriorityFieldValue) {
  const char kFrameData[] = {
      0x00, 0x00, 0x04,        // payload length
      0x10,                    // frame type PRIORITY_UPDATE
      0x00,                    // flags
      0x00, 0x00, 0x00, 0x00,  // stream ID, must be 0
      0x00, 0x00, 0x00, 0x03   // prioritized stream ID, must not be zero
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 4, 0x10, 0x0));
  EXPECT_CALL(visitor, OnPriorityUpdate(3, ""));
  deframer_->ProcessInput(kFrameData, sizeof(kFrameData));
  EXPECT_FALSE(deframer_->HasError());
}

TEST_P(SpdyFramerTest, PriorityUpdateFrameWithEmptyPayload) {
  const char kFrameData[] = {
      0x00, 0x00, 0x00,        // payload length
      0x10,                    // frame type PRIORITY_UPDATE
      0x00,                    // flags
      0x00, 0x00, 0x00, 0x00,  // stream ID, must be 0
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 0, 0x10, 0x0));
  EXPECT_CALL(visitor,
              OnError(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE, _));
  deframer_->ProcessInput(kFrameData, sizeof(kFrameData));
  EXPECT_TRUE(deframer_->HasError());
}

TEST_P(SpdyFramerTest, PriorityUpdateFrameWithShortPayload) {
  const char kFrameData[] = {
      0x00, 0x00, 0x02,        // payload length
      0x10,                    // frame type PRIORITY_UPDATE
      0x00,                    // flags
      0x00, 0x00, 0x00, 0x00,  // stream ID, must be 0
      0x00, 0x01  // payload not long enough to hold 32 bits of prioritized
                  // stream ID
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 2, 0x10, 0x0));
  EXPECT_CALL(visitor,
              OnError(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE, _));
  deframer_->ProcessInput(kFrameData, sizeof(kFrameData));
  EXPECT_TRUE(deframer_->HasError());
}

TEST_P(SpdyFramerTest, PriorityUpdateFrameOnIncorrectStream) {
  const char kFrameData[] = {
      0x00, 0x00, 0x04,        // payload length
      0x10,                    // frame type PRIORITY_UPDATE
      0x00,                    // flags
      0x00, 0x00, 0x00, 0x01,  // invalid stream ID, must be 0
      0x00, 0x00, 0x00, 0x01,  // prioritized stream ID, must not be zero
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(1, 4, 0x10, 0x0));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  deframer_->ProcessInput(kFrameData, sizeof(kFrameData));
  EXPECT_TRUE(deframer_->HasError());
}

TEST_P(SpdyFramerTest, PriorityUpdateFramePrioritizingIncorrectStream) {
  const char kFrameData[] = {
      0x00, 0x00, 0x04,        // payload length
      0x10,
```