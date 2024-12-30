Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided C++ file (`qpack_offline_decoder.cc`) within the Chromium networking stack. The prompt also asks for connections to JavaScript, examples of logical reasoning (with inputs/outputs), common usage errors, and how a user might reach this code.

**2. Initial Skim and Keyword Spotting:**

A quick read-through highlights key terms and concepts:

* `Decoder`:  This immediately suggests the code's purpose is to reverse some encoding process.
* `QPACK`: This is a specific header compression algorithm for HTTP/3.
* `Offline Interop`:  Indicates this tool is for testing interoperability between different QPACK implementations *offline*, not in a live connection.
* `Test Corpus`, `Test Data`, `Encoded Data`, `Expected Headers`: These terms strongly suggest this is a testing utility.
* `Input Filename`, `Expected Headers Filename`: The code takes file paths as input.
* `DecodeHeaderBlocksFromFile`, `VerifyDecodedHeaderLists`: These are core function names indicating the main actions.
* `Encoder Stream`, `Decoder Stream`:  QPACK uses separate streams for encoding/decoding metadata.
* `Stream ID`:  A fundamental concept in HTTP/2 and HTTP/3.
* `Dynamic Table Capacity`, `Max Blocked Streams`: Parameters related to QPACK's state management.
* `JavaScript`:  A specific connection to explore.

**3. Deeper Dive into Functionality:**

Now, let's analyze the key functions:

* **`QpackOfflineDecoder::QpackOfflineDecoder()`:**  The constructor. It initializes a flag for encoder stream errors.
* **`DecodeAndVerifyOfflineData()`:**  The main entry point. It orchestrates the process: parsing the input filename, decoding, and then verifying against expected headers.
* **`ParseInputFilename()`:**  Crucial for understanding how the tool is configured. It extracts parameters like maximum dynamic table capacity and max blocked streams from the input filename. *This is a key area for understanding configuration and potential errors.*
* **`DecodeHeaderBlocksFromFile()`:**  Reads encoded header blocks from a file. It handles data from the encoder stream (stream ID 0) and regular data streams. It uses a `QpackDecoder` object for the actual decoding. It also deals with asynchronous decoding.
* **`VerifyDecodedHeaderLists()`:** Compares the decoded headers with the expected headers from another file. It handles a specific quirk of the `h2o` decoder. *This is a critical part of the testing process.*
* **`ReadNextExpectedHeaderList()`:** Parses the expected headers file, which has a specific format (key-value pairs separated by tabs, header blocks separated by empty lines). *Understanding this format is crucial for creating test data.*
* **`CompareHeaderBlocks()`:**  Performs the actual comparison of header blocks, with the `h2o` decoder workaround.
* **`OnEncoderStreamError()`:** Handles errors reported by the `QpackDecoder`.

**4. Identifying JavaScript Connections:**

The prompt specifically asks about JavaScript. Consider how this C++ code relates to web browsers (which heavily use JavaScript):

* **Browser Implementation:** This code is part of Chromium's networking stack. Browsers implement HTTP/3 and QPACK. Therefore, while this *specific file* isn't directly running JavaScript, the *functionality* it tests (QPACK decoding) is essential for how browsers handle web requests and responses initiated by JavaScript.
* **`fetch()` API:**  JavaScript's `fetch()` API is the modern way to make network requests. When a browser using Chromium's networking stack (like Chrome or Edge) makes a `fetch()` request, and the server uses HTTP/3 with QPACK, the browser's C++ QPACK decoder (potentially involving code like this) will process the compressed headers.

**5. Logical Reasoning and Examples:**

Think about the flow of data and the conditions under which different outcomes occur.

* **Assumption:** We have correctly encoded QPACK data in an input file and corresponding expected headers in another file.
* **Input:**  `input.qifencoded`, `expected.qif`
* **Output (Successful Decode and Verification):** The program exits successfully (returns 0). Logs would indicate successful parsing, decoding, and verification.
* **Output (Decoding Error):** If the input data is corrupted or doesn't conform to QPACK, the `QpackDecoder` might report an error, leading to the `DecodeHeaderBlocksFromFile()` function returning `false`. Error logs would detail the problem.
* **Output (Verification Failure):** If the decoded headers don't match the expected headers, `VerifyDecodedHeaderLists()` would return `false`. Error logs would indicate the mismatch.

**6. Common Usage Errors:**

Consider how someone using this tool might make mistakes:

* **Incorrect Filename Format:**  The `ParseInputFilename()` function is strict. Incorrect order or format of the numeric parts of the filename will cause errors.
* **Mismatched Input and Expected Files:** If the `expected.qif` file doesn't correspond to the encoding in `input.qifencoded`, the verification will fail.
* **Incorrect `expected.qif` Format:**  The expected headers file has a specific tab-separated format. Errors in this format will cause parsing failures.
* **Providing Non-Existent Files:** Basic file I/O errors.

**7. Debugging Scenario:**

Imagine a developer working on QPACK implementation:

1. **Problem:** A website using HTTP/3 isn't loading correctly in their Chromium-based browser. They suspect a QPACK decoding issue.
2. **Gathering Data:** They might capture the raw network traffic, specifically the QPACK-encoded header blocks.
3. **Offline Testing:**  To isolate the problem, they would use a tool like `qpack_offline_decoder`.
4. **Creating Input Files:** They'd create an `input.qifencoded` file containing the captured QPACK data and a `expected.qif` file with the headers they *expect* to be decoded (perhaps by manually inspecting the HTTP/1.1 equivalent or using another tool).
5. **Running the Decoder:** They would run `qpack_offline_decoder input.qifencoded expected.qif`.
6. **Analyzing Output:**
   * **Success:** If the decoder succeeds, it suggests the decoding logic in their browser is likely correct, and the problem lies elsewhere.
   * **Failure:** If the decoder fails, the error messages from `qpack_offline_decoder` provide valuable clues about the nature of the decoding problem. They might see errors in the encoder stream, individual header blocks, or verification mismatches.

**8. Structuring the Answer:**

Finally, organize the information logically according to the prompt's requirements: functionality, JavaScript connections, logical reasoning, usage errors, and debugging scenarios. Use clear and concise language. Code snippets from the original file can be helpful for illustrating points.
This C++ file, `qpack_offline_decoder.cc`, is a command-line tool within the Chromium networking stack specifically designed for **offline testing and verification of QPACK (QPACK Header Compression for HTTP/3) implementations.**  It's not directly part of the live browser runtime but is used by developers and testers to ensure different QPACK encoders and decoders can interoperate correctly.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Decoding QPACK Encoded Header Blocks:**  The primary function is to read QPACK-encoded header blocks from a file. These files represent the output of a QPACK encoder.
2. **Simulating QPACK Stream Processing:** It simulates the encoder and decoder streams defined in the QPACK specification. It can handle data destined for the encoder stream (stream ID 0) and data for regular header blocks associated with specific stream IDs.
3. **Verifying Decoded Headers:** It compares the decoded header lists against expected header lists read from another file. This ensures that the decoding process yields the correct results.
4. **Handling Offline Interoperability Test Data:**  It's designed to work with a specific format of test data commonly used for QPACK offline interoperability testing. This format is described in the comments and involves specific filename conventions and file structures.
5. **Reporting Errors:** It provides error logging if decoding fails, verification fails, or if there are issues parsing the input files.

**Relationship with JavaScript Functionality:**

While this C++ file itself doesn't execute JavaScript code, it plays a crucial role in ensuring the correct functioning of web browsers and web applications that rely on HTTP/3 and QPACK.

* **Browser's Network Stack:**  This code resides within Chromium's network stack. When a browser (like Chrome or Edge) makes an HTTP/3 request initiated by JavaScript (e.g., using the `fetch()` API), the browser's internal QPACK decoder (a related but different piece of code) will use logic similar to this to decompress the HTTP headers.
* **Testing Browser Implementation:** This offline decoder is used to test the correctness of the QPACK decoding implementation within the browser. By comparing the output of various encoders against the browser's decoder (or vice-versa), developers can identify and fix interoperability issues.

**Example illustrating the connection:**

Imagine a JavaScript application making a `fetch()` request to a server using HTTP/3.

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

When this request is sent:

1. **JavaScript initiates the request.**
2. **The browser's network stack (C++ code, including QPACK logic) handles the HTTP/3 negotiation and request sending.**
3. **The server responds with QPACK-encoded headers.**
4. **The browser's QPACK decoder (similar in concept to this offline decoder) processes the compressed headers.**
5. **The decompressed headers are then used to construct the `Response` object that the JavaScript code receives.**

This `qpack_offline_decoder.cc` tool helps ensure that step 4 works correctly for various QPACK encoder implementations, guaranteeing a seamless experience for the JavaScript application.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

**Scenario 1: Successful Decoding and Verification**

* **Assumption:** We have a valid QPACK-encoded file (`encoded_headers.out`) and a corresponding file with the expected decoded headers (`expected_headers.txt`).
* **Input (Command Line):** `$BIN/qpack_offline_decoder encoded_headers.out expected_headers.txt`
* **Input (`encoded_headers.out`):**  Contains a sequence of bytes representing QPACK-encoded header blocks, including stream IDs and lengths. For example:
    ```
    000000000000000000000004 <encoder stream data length=4> <encoder stream data>
    00000000000000010000000a <stream ID=1, header block length=10> <header block data>
    ```
* **Input (`expected_headers.txt`):** Contains the expected decoded headers in a specific format (key-value pairs separated by tabs, header blocks separated by empty lines):
    ```
    :status	200
    content-type	application/json

    content-length	123
    ```
* **Output:** The program exits successfully (typically with a return code of 0). Log messages might indicate successful parsing, decoding, and verification.

**Scenario 2: Decoding Error**

* **Assumption:** The `encoded_headers.out` file contains malformed QPACK data.
* **Input (Command Line):** `$BIN/qpack_offline_decoder malformed_headers.out expected_headers.txt`
* **Input (`malformed_headers.out`):** Contains QPACK data that violates the QPACK specification (e.g., truncated encoding, invalid integer encoding).
* **Output:** The program will likely exit with an error code. Log messages will indicate the decoding error encountered by the `QpackDecoder`. For example: `ERROR:quiche/quic/test_tools/qpack/qpack_offline_decoder.cc(120): Error detected on encoder stream.` or `ERROR:quiche/quic/test_tools/qpack/qpack_offline_decoder.cc(135): Sync decoding error on stream 1: Invalid prefix.`

**Scenario 3: Verification Failure**

* **Assumption:** The decoded headers do not match the expected headers in `expected_headers.txt`.
* **Input (Command Line):** `$BIN/qpack_offline_decoder valid_headers.out incorrect_expected_headers.txt`
* **Input (`valid_headers.out`):** Contains valid QPACK-encoded headers.
* **Input (`incorrect_expected_headers.txt`):** Contains header lists that differ from the actual decoded headers.
* **Output:** The program will exit with an error code. Log messages will indicate the verification failure and highlight the discrepancy. For example: `ERROR:quiche/quic/test_tools/qpack/qpack_offline_decoder.cc(212): Decoded header does not match expected header.`

**Common User or Programming Usage Errors:**

1. **Incorrect Filename Order:**  Providing the expected headers file before the encoded data file on the command line. The tool expects the encoded data filename first.
   * **Example:** `$BIN/qpack_offline_decoder expected_headers.txt encoded_headers.out` will likely lead to parsing errors as the tool tries to interpret the expected headers file as the encoded data.

2. **Incorrect Format of Expected Headers File:** The `expected_headers.txt` file must adhere to the tab-separated key-value pairs format, with empty lines separating header blocks. Incorrect formatting will cause parsing errors.
   * **Example:**  Using spaces instead of tabs, or not separating header blocks with empty lines.

3. **Mismatched Encoded and Expected Data:** If the `expected_headers.txt` file doesn't correspond to the actual encoded data in the input file, the verification step will fail. This is a logical error in test setup.

4. **Providing Incorrectly Formatted Encoded Data Filename:** The tool parses information (like maximum dynamic table capacity) from the encoded data filename based on a specific convention (splitting by periods). Deviating from this convention will cause parsing errors in the filename.
   * **Example:**  `$BIN/qpack_offline_decoder my_encoded_data expected_headers.txt` where `my_encoded_data` doesn't have the expected numeric fields separated by periods. The log will show errors like "Not enough fields in input filename".

**User Operation Steps to Reach This Code (as a debugging scenario):**

Let's say a developer is working on a new QPACK encoder and wants to ensure it's interoperable with Chromium's QPACK decoder. Here's how they might use this tool:

1. **Generate Encoded Data:** The developer uses their QPACK encoder implementation to encode a set of HTTP headers. This results in a binary output file (e.g., `my_encoded_headers.out`).

2. **Create Expected Headers:** The developer knows the original HTTP headers they encoded. They manually create a `expected_headers.txt` file in the required format, representing the expected decoded output.

3. **Run the Offline Decoder:** The developer navigates to the directory containing the `qpack_offline_decoder` executable (likely after building Chromium). They then run the decoder with the generated encoded data and the expected headers:
   ```bash
   cd out/Default  # Or the relevant build output directory
   ./net/third_party/quiche/src/quiche/quic/test_tools/qpack/qpack_offline_decoder \
       my_encoded_headers.out expected_headers.txt
   ```

4. **Analyze the Output:**
   * **Success:** If the program exits without errors, the developer has confirmation that their encoder's output can be correctly decoded by Chromium's QPACK decoder.
   * **Failure:** If the program reports errors, the developer can examine the error messages to pinpoint the interoperability issue. This might involve looking at the encoder stream data, specific header blocks that failed to decode, or discrepancies during the verification step.

5. **Iterative Debugging:** Based on the error messages, the developer can go back to their encoder implementation, identify the bug, fix it, regenerate the encoded data, and rerun the offline decoder until it succeeds.

This tool provides a valuable offline testing mechanism, allowing developers to isolate and fix QPACK encoding and decoding issues without needing a live HTTP/3 connection. It's a crucial part of ensuring the robustness and interoperability of the QPACK implementation within the Chromium network stack.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/qpack/qpack_offline_decoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Decoder to test QPACK Offline Interop corpus
//
// See https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop for
// description of test data format.
//
// Example usage
//
//  cd $TEST_DATA
//  git clone https://github.com/qpackers/qifs.git
//  TEST_ENCODED_DATA=$TEST_DATA/qifs/encoded/qpack-06
//  TEST_QIF_DATA=$TEST_DATA/qifs/qifs
//  $BIN/qpack_offline_decoder \
//      $TEST_ENCODED_DATA/f5/fb-req.qifencoded.4096.100.0 \
//      $TEST_QIF_DATA/fb-req.qif
//      $TEST_ENCODED_DATA/h2o/fb-req-hq.out.512.0.1 \
//      $TEST_QIF_DATA/fb-req-hq.qif
//      $TEST_ENCODED_DATA/ls-qpack/fb-resp-hq.out.0.0.0 \
//      $TEST_QIF_DATA/fb-resp-hq.qif
//      $TEST_ENCODED_DATA/proxygen/netbsd.qif.proxygen.out.4096.0.0 \
//      $TEST_QIF_DATA/netbsd.qif
//

#include "quiche/quic/test_tools/qpack/qpack_offline_decoder.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/test_tools/qpack/qpack_test_utils.h"
#include "quiche/common/platform/api/quiche_file_utils.h"
#include "quiche/common/quiche_endian.h"

namespace quic {

QpackOfflineDecoder::QpackOfflineDecoder()
    : encoder_stream_error_detected_(false) {}

bool QpackOfflineDecoder::DecodeAndVerifyOfflineData(
    absl::string_view input_filename,
    absl::string_view expected_headers_filename) {
  if (!ParseInputFilename(input_filename)) {
    QUIC_LOG(ERROR) << "Error parsing input filename " << input_filename;
    return false;
  }

  if (!DecodeHeaderBlocksFromFile(input_filename)) {
    QUIC_LOG(ERROR) << "Error decoding header blocks in " << input_filename;
    return false;
  }

  if (!VerifyDecodedHeaderLists(expected_headers_filename)) {
    QUIC_LOG(ERROR) << "Header lists decoded from " << input_filename
                    << " to not match expected headers parsed from "
                    << expected_headers_filename;
    return false;
  }

  return true;
}

void QpackOfflineDecoder::OnEncoderStreamError(
    QuicErrorCode error_code, absl::string_view error_message) {
  QUIC_LOG(ERROR) << "Encoder stream error: "
                  << QuicErrorCodeToString(error_code) << " " << error_message;
  encoder_stream_error_detected_ = true;
}

bool QpackOfflineDecoder::ParseInputFilename(absl::string_view input_filename) {
  std::vector<absl::string_view> pieces = absl::StrSplit(input_filename, '.');

  if (pieces.size() < 3) {
    QUIC_LOG(ERROR) << "Not enough fields in input filename " << input_filename;
    return false;
  }

  auto piece_it = pieces.rbegin();

  // Acknowledgement mode: 1 for immediate, 0 for none.
  if (*piece_it != "0" && *piece_it != "1") {
    QUIC_LOG(ERROR)
        << "Header acknowledgement field must be 0 or 1 in input filename "
        << input_filename;
    return false;
  }

  ++piece_it;

  // Maximum allowed number of blocked streams.
  uint64_t max_blocked_streams = 0;
  if (!absl::SimpleAtoi(*piece_it, &max_blocked_streams)) {
    QUIC_LOG(ERROR) << "Error parsing part of input filename \"" << *piece_it
                    << "\" as an integer.";
    return false;
  }

  ++piece_it;

  // Maximum Dynamic Table Capacity in bytes
  uint64_t maximum_dynamic_table_capacity = 0;
  if (!absl::SimpleAtoi(*piece_it, &maximum_dynamic_table_capacity)) {
    QUIC_LOG(ERROR) << "Error parsing part of input filename \"" << *piece_it
                    << "\" as an integer.";
    return false;
  }
  qpack_decoder_ = std::make_unique<QpackDecoder>(
      maximum_dynamic_table_capacity, max_blocked_streams, this);
  qpack_decoder_->set_qpack_stream_sender_delegate(
      &decoder_stream_sender_delegate_);

  // The initial dynamic table capacity is zero according to
  // https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#eviction.
  // However, for historical reasons, offline interop encoders use
  // |maximum_dynamic_table_capacity| as initial capacity.
  qpack_decoder_->OnSetDynamicTableCapacity(maximum_dynamic_table_capacity);

  return true;
}

bool QpackOfflineDecoder::DecodeHeaderBlocksFromFile(
    absl::string_view input_filename) {
  // Store data in |input_data_storage|; use a absl::string_view to
  // efficiently keep track of remaining portion yet to be decoded.
  std::optional<std::string> input_data_storage =
      quiche::ReadFileContents(input_filename);
  QUICHE_DCHECK(input_data_storage.has_value());
  absl::string_view input_data(*input_data_storage);

  while (!input_data.empty()) {
    // Parse stream_id and length.
    if (input_data.size() < sizeof(uint64_t) + sizeof(uint32_t)) {
      QUIC_LOG(ERROR) << "Unexpected end of input file.";
      return false;
    }

    uint64_t stream_id = quiche::QuicheEndian::NetToHost64(
        *reinterpret_cast<const uint64_t*>(input_data.data()));
    input_data = input_data.substr(sizeof(uint64_t));

    uint32_t length = quiche::QuicheEndian::NetToHost32(
        *reinterpret_cast<const uint32_t*>(input_data.data()));
    input_data = input_data.substr(sizeof(uint32_t));

    if (input_data.size() < length) {
      QUIC_LOG(ERROR) << "Unexpected end of input file.";
      return false;
    }

    // Parse data.
    absl::string_view data = input_data.substr(0, length);
    input_data = input_data.substr(length);

    // Process data.
    if (stream_id == 0) {
      qpack_decoder_->encoder_stream_receiver()->Decode(data);

      if (encoder_stream_error_detected_) {
        QUIC_LOG(ERROR) << "Error detected on encoder stream.";
        return false;
      }
    } else {
      auto headers_handler = std::make_unique<test::TestHeadersHandler>();
      auto progressive_decoder = qpack_decoder_->CreateProgressiveDecoder(
          stream_id, headers_handler.get());

      progressive_decoder->Decode(data);
      progressive_decoder->EndHeaderBlock();

      if (headers_handler->decoding_error_detected()) {
        QUIC_LOG(ERROR) << "Sync decoding error on stream " << stream_id << ": "
                        << headers_handler->error_message();
        return false;
      }

      decoders_.push_back({std::move(headers_handler),
                           std::move(progressive_decoder), stream_id});
    }

    // Move decoded header lists from TestHeadersHandlers and append them to
    // |decoded_header_lists_| while preserving the order in |decoders_|.
    while (!decoders_.empty() &&
           decoders_.front().headers_handler->decoding_completed()) {
      Decoder* decoder = &decoders_.front();

      if (decoder->headers_handler->decoding_error_detected()) {
        QUIC_LOG(ERROR) << "Async decoding error on stream "
                        << decoder->stream_id << ": "
                        << decoder->headers_handler->error_message();
        return false;
      }

      if (!decoder->headers_handler->decoding_completed()) {
        QUIC_LOG(ERROR) << "Decoding incomplete after reading entire"
                           " file, on stream "
                        << decoder->stream_id;
        return false;
      }

      decoded_header_lists_.push_back(
          decoder->headers_handler->ReleaseHeaderList());
      decoders_.pop_front();
    }
  }

  if (!decoders_.empty()) {
    QUICHE_DCHECK(!decoders_.front().headers_handler->decoding_completed());

    QUIC_LOG(ERROR) << "Blocked decoding uncomplete after reading entire"
                       " file, on stream "
                    << decoders_.front().stream_id;
    return false;
  }

  return true;
}

bool QpackOfflineDecoder::VerifyDecodedHeaderLists(
    absl::string_view expected_headers_filename) {
  // Store data in |expected_headers_data_storage|; use a
  // absl::string_view to efficiently keep track of remaining portion
  // yet to be decoded.
  std::optional<std::string> expected_headers_data_storage =
      quiche::ReadFileContents(expected_headers_filename);
  QUICHE_DCHECK(expected_headers_data_storage.has_value());
  absl::string_view expected_headers_data(*expected_headers_data_storage);

  while (!decoded_header_lists_.empty()) {
    quiche::HttpHeaderBlock decoded_header_list =
        std::move(decoded_header_lists_.front());
    decoded_header_lists_.pop_front();

    quiche::HttpHeaderBlock expected_header_list;
    if (!ReadNextExpectedHeaderList(&expected_headers_data,
                                    &expected_header_list)) {
      QUIC_LOG(ERROR)
          << "Error parsing expected header list to match next decoded "
             "header list.";
      return false;
    }

    if (!CompareHeaderBlocks(std::move(decoded_header_list),
                             std::move(expected_header_list))) {
      QUIC_LOG(ERROR) << "Decoded header does not match expected header.";
      return false;
    }
  }

  if (!expected_headers_data.empty()) {
    QUIC_LOG(ERROR)
        << "Not enough encoded header lists to match expected ones.";
    return false;
  }

  return true;
}

bool QpackOfflineDecoder::ReadNextExpectedHeaderList(
    absl::string_view* expected_headers_data,
    quiche::HttpHeaderBlock* expected_header_list) {
  while (true) {
    absl::string_view::size_type endline = expected_headers_data->find('\n');

    // Even last header list must be followed by an empty line.
    if (endline == absl::string_view::npos) {
      QUIC_LOG(ERROR) << "Unexpected end of expected header list file.";
      return false;
    }

    if (endline == 0) {
      // Empty line indicates end of header list.
      *expected_headers_data = expected_headers_data->substr(1);
      return true;
    }

    absl::string_view header_field = expected_headers_data->substr(0, endline);
    std::vector<absl::string_view> pieces = absl::StrSplit(header_field, '\t');

    if (pieces.size() != 2) {
      QUIC_LOG(ERROR) << "Header key and value must be separated by TAB.";
      return false;
    }

    expected_header_list->AppendValueOrAddHeader(pieces[0], pieces[1]);

    *expected_headers_data = expected_headers_data->substr(endline + 1);
  }
}

bool QpackOfflineDecoder::CompareHeaderBlocks(
    quiche::HttpHeaderBlock decoded_header_list,
    quiche::HttpHeaderBlock expected_header_list) {
  if (decoded_header_list == expected_header_list) {
    return true;
  }

  // The h2o decoder reshuffles the "content-length" header and pseudo-headers,
  // see
  // https://github.com/qpackers/qifs/blob/master/encoded/qpack-03/h2o/README.md.
  // Remove such headers one by one if they match.
  const char* kContentLength = "content-length";
  const char* kPseudoHeaderPrefix = ":";
  for (quiche::HttpHeaderBlock::iterator decoded_it =
           decoded_header_list.begin();
       decoded_it != decoded_header_list.end();) {
    const absl::string_view key = decoded_it->first;
    if (key != kContentLength && !absl::StartsWith(key, kPseudoHeaderPrefix)) {
      ++decoded_it;
      continue;
    }
    quiche::HttpHeaderBlock::iterator expected_it =
        expected_header_list.find(key);
    if (expected_it == expected_header_list.end() ||
        decoded_it->second != expected_it->second) {
      ++decoded_it;
      continue;
    }
    // Http2HeaderBlock does not support erasing by iterator, only by key.
    ++decoded_it;
    expected_header_list.erase(key);
    // This will invalidate |key|.
    decoded_header_list.erase(key);
  }

  return decoded_header_list == expected_header_list;
}

}  // namespace quic

"""

```