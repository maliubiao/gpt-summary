Response:
The user wants a summary of the provided C++ code file `net/dns/mdns_client_unittest.cc` from the Chromium project.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Function:** The filename `mdns_client_unittest.cc` immediately suggests that this file contains unit tests for the `MDnsClient` functionality. This is the central theme.

2. **Analyze Includes:** The `#include` directives provide clues about the functionalities being tested:
    * `net/dns/mdns_client_impl.h`: Indicates the testing of the concrete implementation of the MDNS client.
    * `net/dns/mock_mdns_socket_factory.h`: Suggests mocking of the underlying socket layer for controlled testing.
    * `net/dns/record_rdata.h`: Implies testing the handling of DNS record data.
    * `net/socket/udp_client_socket.h`:  Shows interaction with UDP sockets.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`: Confirms this is a unit test file using Google Test and Google Mock frameworks.
    * Various `base/` includes: Points to the usage of Chromium's base library for functionalities like time management, task running, and memory management.

3. **Examine Test Cases (Functions starting with `TEST_F`):**  Scanning the `TEST_F` functions reveals the specific functionalities being tested:
    * `PassiveListeners`: Testing how the client reacts to passively received MDNS responses and updates listeners.
    * `PassiveListenersWithCapitalization`: Verifying case-insensitivity in MDNS name matching.
    * `PassiveListenersCacheCleanup`:  Testing the automatic removal of expired records from the cache.
    * `CacheCleanupWithShortTTL`: More detailed testing of cache cleanup timing.
    * `StopListening`: Testing the ability to stop and start the MDNS client.
    * `StopListening_CacheCleanupScheduled`:  Ensuring that stopping the client cancels scheduled cleanup tasks.
    * `MalformedPacket`: Checking how the client handles invalid or corrupted MDNS packets.
    * `TransactionWithEmptyCache`: Testing query transactions when the cache is empty.
    * `TransactionWithEmptyCacheAndCapitalization`:  Testing query transactions with case-insensitivity.
    * `TransactionCacheOnlyNoResult`: Verifying behavior for cache-only queries when no results are present.
    * `TransactionWithCache`: Testing query transactions when the cache has relevant data.
    * `AdditionalRecords`:  Examining how additional records in a response are handled (though incomplete in the provided snippet).

4. **Identify Mock Objects and Helpers:**  The code defines mock classes like `MockClock`, `MockTimer`, and `MockListenerDelegate`. It also has helper classes like `PtrRecordCopyContainer` to facilitate testing and verification. These are key for isolating and controlling the tested components.

5. **Look for Sample Data:** The `kSamplePacket...` arrays are raw byte representations of MDNS packets used for simulating network traffic. Analyzing these helps understand the specific scenarios being tested (e.g., different record types, TTLs, corrupted data).

6. **Infer Overall Purpose:** Based on the above points, the primary goal of this file is to thoroughly test the `MDnsClientImpl` class. This includes:
    * Parsing and processing MDNS response packets.
    * Maintaining an internal cache of MDNS records.
    * Notifying listeners about record updates (additions, removals).
    * Handling different types of MDNS queries and responses.
    * Robustness against malformed packets.
    * Correct timing of cache cleanup.
    * Proper handling of case-insensitivity in names.

7. **Consider JavaScript Relevance:** MDNS is often used for service discovery on local networks. In a web browser context, JavaScript might interact with the MDNS client indirectly through higher-level APIs to discover devices or services (e.g., for printing, casting). The tests here ensure the underlying MDNS client is working correctly, which is crucial for the reliability of these JavaScript-driven features.

8. **Formulate the Summary:** Combine the identified functionalities into a concise summary. Highlight the core purpose (unit testing), the components being tested (`MDnsClientImpl`), and the key aspects covered (packet parsing, caching, listeners, queries, error handling).

9. **Address Specific Questions (even if the prompt only asks for a summary):**  Mentally note potential answers to the other parts of the user's prompt (JavaScript relevance, logic reasoning, usage errors, debugging) as these might be needed in subsequent parts of the request. For instance, the existence of sample packets provides a basis for demonstrating logic reasoning. The tests themselves implicitly reveal how developers *should* use the MDNS client.

10. **Refine and Organize:** Ensure the summary is clear, concise, and addresses the main points effectively.

By following these steps, we can generate a comprehensive and accurate summary of the provided C++ code snippet. The detailed analysis of the code's components and test cases is crucial for understanding its overall purpose and the specific functionalities being verified.
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/simple_test_clock.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "base/timer/mock_timer.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/completion_repeating_callback.h"
#include "net/base/ip_address.h"
#include "net/base/rand_callback.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mdns_client_impl.h"
#include "net/dns/mock_mdns_socket_factory.h"
#include "net/dns/record_rdata.h"
#include "net/log/net_log.h"
#include "net/socket/udp_client_socket.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Assign;
using ::testing::AtMost;
using ::testing::DoAll;
using ::testing::Exactly;
using ::testing::IgnoreResult;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace net {

namespace {

const uint8_t kSamplePacket1[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 1 second;
    0x00, 0x01, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kSamplePacket1WithCapitalization[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 'T', 'C', 'P', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 1 second;
    0x00, 0x01, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'P', 'r', 'i', 'n', 't', 'e', 'R', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kCorruptedPacketBadQuestion[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x01,  // One question
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question is corrupted and cannot be read.
    0x99, 'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00, 0x00, 0x00,

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x99,  // RDLENGTH is impossible
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r',  // Useless trailing data.
};

const uint8_t kCorruptedPacketUnsalvagable[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x99,  // RDLENGTH is impossible
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r',  // Useless trailing data.
};

const uint8_t kCorruptedPacketDoubleRecord[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x06, 'p', 'r', 'i', 'v', 'e', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x01,  // TYPE is A.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x04,  // RDLENGTH is 4
    0x05, 0x03, 0xc0, 0x0c,

    // Answer 2 -- Same key
    0x06, 'p', 'r', 'i', 'v', 'e', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x01,  // TYPE is A.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x04,  // RDLENGTH is 4
    0x02, 0x03, 0x04, 0x05,
};

const uint8_t kCorruptedPacketSalvagable[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,         // RDLENGTH is 8 bytes.
    0x99, 'h', 'e', 'l', 'l', 'o',  // Bad RDATA format.
    0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kSamplePacket2[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x32};

const uint8_t kSamplePacket3[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't',  //
    0x04, '_', 't', 'c', 'p',                 //
    0x05, 'l', 'o', 'c', 'a', 'l',            //
    0x00, 0x00, 0x0c,                         // TYPE is PTR.
    0x00, 0x01,                               // CLASS is IN.
    0x00, 0x00,                               // TTL (4 bytes) is 1 second;
    0x00, 0x01,                               //
    0x00, 0x08,                               // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o',            //
    0xc0, 0x0c,                               //

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r',  //
    0xc0, 0x14,                                    // Pointer to "._tcp.local"
    0x00, 0x0c,                                    // TYPE is PTR.
    0x00, 0x01,                                    // CLASS is IN.
    0x00, 0x00,                     // TTL (4 bytes) is 3 seconds.
    0x00, 0x03,                     //
    0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o',  //
    0xc0, 0x32};

const uint8_t kQueryPacketPrivet[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kQueryPacketPrivetWithCapitalization[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'P', 'R', 'I', 'V', 'E', 'T', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kQueryPacketPrivetA[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kSamplePacketAdditionalOnly[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x00,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x01,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,
};

const uint8_t kSamplePacketNsec[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x2f,  // TYPE is NSEC.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x06,             // RDLENGTH is 6 bytes.
    0xc0, 0x0c, 0x00, 0x02, 0x00, 0x08  // Only A record present
};

const uint8_t kSamplePacketAPrivet[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 5 seconds
    0x00, 0x05, 0x00, 0x04,                     // RDLENGTH is 4 bytes.
    0xc0, 0x0c, 0x00, 0x02,
};

const uint8_t kSamplePacketGoodbye[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is zero;
    0x00, 0x00, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x0c,
};

std::string MakeString(const uint8_t* data, unsigned size) {
  return std::string(reinterpret_cast<const char*>(data), size);
}

class PtrRecordCopyContainer {
 public:
  PtrRecordCopyContainer() = default;
  ~Ptr
Prompt: 
```
这是目录为net/dns/mdns_client_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/simple_test_clock.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "base/timer/mock_timer.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/completion_repeating_callback.h"
#include "net/base/ip_address.h"
#include "net/base/rand_callback.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mdns_client_impl.h"
#include "net/dns/mock_mdns_socket_factory.h"
#include "net/dns/record_rdata.h"
#include "net/log/net_log.h"
#include "net/socket/udp_client_socket.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Assign;
using ::testing::AtMost;
using ::testing::DoAll;
using ::testing::Exactly;
using ::testing::IgnoreResult;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace net {

namespace {

const uint8_t kSamplePacket1[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 1 second;
    0x00, 0x01, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kSamplePacket1WithCapitalization[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 'T', 'C', 'P', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 1 second;
    0x00, 0x01, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'P', 'r', 'i', 'n', 't', 'e', 'R', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kCorruptedPacketBadQuestion[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x01,  // One question
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question is corrupted and cannot be read.
    0x99, 'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00, 0x00, 0x00,

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x99,  // RDLENGTH is impossible
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r',  // Useless trailing data.
};

const uint8_t kCorruptedPacketUnsalvagable[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x99,  // RDLENGTH is impossible
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r',  // Useless trailing data.
};

const uint8_t kCorruptedPacketDoubleRecord[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x06, 'p', 'r', 'i', 'v', 'e', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x01,  // TYPE is A.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x04,  // RDLENGTH is 4
    0x05, 0x03, 0xc0, 0x0c,

    // Answer 2 -- Same key
    0x06, 'p', 'r', 'i', 'v', 'e', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x01,  // TYPE is A.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x04,  // RDLENGTH is 4
    0x02, 0x03, 0x04, 0x05,
};

const uint8_t kCorruptedPacketSalvagable[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,         // RDLENGTH is 8 bytes.
    0x99, 'h', 'e', 'l', 'l', 'o',  // Bad RDATA format.
    0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kSamplePacket2[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x32};

const uint8_t kSamplePacket3[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't',  //
    0x04, '_', 't', 'c', 'p',                 //
    0x05, 'l', 'o', 'c', 'a', 'l',            //
    0x00, 0x00, 0x0c,                         // TYPE is PTR.
    0x00, 0x01,                               // CLASS is IN.
    0x00, 0x00,                               // TTL (4 bytes) is 1 second;
    0x00, 0x01,                               //
    0x00, 0x08,                               // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o',            //
    0xc0, 0x0c,                               //

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r',  //
    0xc0, 0x14,                                    // Pointer to "._tcp.local"
    0x00, 0x0c,                                    // TYPE is PTR.
    0x00, 0x01,                                    // CLASS is IN.
    0x00, 0x00,                     // TTL (4 bytes) is 3 seconds.
    0x00, 0x03,                     //
    0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o',  //
    0xc0, 0x32};

const uint8_t kQueryPacketPrivet[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kQueryPacketPrivetWithCapitalization[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'P', 'R', 'I', 'V', 'E', 'T', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kQueryPacketPrivetA[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kSamplePacketAdditionalOnly[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x00,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x01,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,
};

const uint8_t kSamplePacketNsec[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x2f,  // TYPE is NSEC.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x06,             // RDLENGTH is 6 bytes.
    0xc0, 0x0c, 0x00, 0x02, 0x00, 0x08  // Only A record present
};

const uint8_t kSamplePacketAPrivet[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 5 seconds
    0x00, 0x05, 0x00, 0x04,                     // RDLENGTH is 4 bytes.
    0xc0, 0x0c, 0x00, 0x02,
};

const uint8_t kSamplePacketGoodbye[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is zero;
    0x00, 0x00, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x0c,
};

std::string MakeString(const uint8_t* data, unsigned size) {
  return std::string(reinterpret_cast<const char*>(data), size);
}

class PtrRecordCopyContainer {
 public:
  PtrRecordCopyContainer() = default;
  ~PtrRecordCopyContainer() = default;

  bool is_set() const { return set_; }

  void SaveWithDummyArg(int unused, const RecordParsed* value) {
    Save(value);
  }

  void Save(const RecordParsed* value) {
    set_ = true;
    name_ = value->name();
    ptrdomain_ = value->rdata<PtrRecordRdata>()->ptrdomain();
    ttl_ = value->ttl();
  }

  bool IsRecordWith(const std::string& name, const std::string& ptrdomain) {
    return set_ && name_ == name && ptrdomain_ == ptrdomain;
  }

  const std::string& name() { return name_; }
  const std::string& ptrdomain() { return ptrdomain_; }
  int ttl() { return ttl_; }

 private:
  bool set_;
  std::string name_;
  std::string ptrdomain_;
  int ttl_;
};

class MockClock : public base::Clock {
 public:
  MockClock() = default;

  MockClock(const MockClock&) = delete;
  MockClock& operator=(const MockClock&) = delete;

  ~MockClock() override = default;

  MOCK_CONST_METHOD0(Now, base::Time());
};

class MockTimer : public base::MockOneShotTimer {
 public:
  MockTimer() = default;

  MockTimer(const MockTimer&) = delete;
  MockTimer& operator=(const MockTimer&) = delete;

  ~MockTimer() override = default;

  void Start(const base::Location& posted_from,
             base::TimeDelta delay,
             base::OnceClosure user_task) override {
    StartObserver(posted_from, delay);
    base::MockOneShotTimer::Start(posted_from, delay, std::move(user_task));
  }

  // StartObserver is invoked when MockTimer::Start() is called.
  // Does not replace the behavior of MockTimer::Start().
  MOCK_METHOD2(StartObserver,
               void(const base::Location& posted_from, base::TimeDelta delay));
};

}  // namespace

class MDnsTest : public TestWithTaskEnvironment {
 public:
  void SetUp() override;
  void DeleteTransaction();
  void DeleteBothListeners();
  void RunFor(base::TimeDelta time_period);
  void Stop();

  MOCK_METHOD2(MockableRecordCallback, void(MDnsTransaction::Result result,
                                            const RecordParsed* record));

  MOCK_METHOD2(MockableRecordCallback2, void(MDnsTransaction::Result result,
                                             const RecordParsed* record));

 protected:
  void ExpectPacket(const uint8_t* packet, unsigned size);
  void SimulatePacketReceive(const uint8_t* packet, unsigned size);

  std::unique_ptr<base::Clock> test_clock_;  // Must outlive `test_client_`.
  std::unique_ptr<MDnsClientImpl> test_client_;
  IPEndPoint mdns_ipv4_endpoint_;
  StrictMock<MockMDnsSocketFactory> socket_factory_;

  // Transactions and listeners that can be deleted by class methods for
  // reentrancy tests.
  std::unique_ptr<MDnsTransaction> transaction_;
  std::unique_ptr<MDnsListener> listener1_;
  std::unique_ptr<MDnsListener> listener2_;
  base::RunLoop loop_;
};

class MockListenerDelegate : public MDnsListener::Delegate {
 public:
  MOCK_METHOD2(OnRecordUpdate,
               void(MDnsListener::UpdateType update,
                    const RecordParsed* records));
  MOCK_METHOD2(OnNsecRecord, void(const std::string&, unsigned));
  MOCK_METHOD0(OnCachePurged, void());
};

void MDnsTest::SetUp() {
  test_client_ = std::make_unique<MDnsClientImpl>();
  ASSERT_THAT(test_client_->StartListening(&socket_factory_), test::IsOk());
}

void MDnsTest::SimulatePacketReceive(const uint8_t* packet, unsigned size) {
  socket_factory_.SimulateReceive(packet, size);
}

void MDnsTest::ExpectPacket(const uint8_t* packet, unsigned size) {
  EXPECT_CALL(socket_factory_, OnSendTo(MakeString(packet, size)))
      .Times(2);
}

void MDnsTest::DeleteTransaction() {
  transaction_.reset();
}

void MDnsTest::DeleteBothListeners() {
  listener1_.reset();
  listener2_.reset();
}

void MDnsTest::RunFor(base::TimeDelta time_period) {
  base::CancelableOnceCallback<void()> callback(
      base::BindOnce(&MDnsTest::Stop, base::Unretained(this)));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, callback.callback(), time_period);

  loop_.Run();
  callback.Cancel();
}

void MDnsTest::Stop() {
  loop_.QuitWhenIdle();
}

TEST_F(MDnsTest, PassiveListeners) {
  StrictMock<MockListenerDelegate> delegate_privet;
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_printer._tcp.local", &delegate_printer);

  ASSERT_TRUE(listener_privet->Start());
  ASSERT_TRUE(listener_printer->Start());

  // Send the same packet twice to ensure no records are double-counted.

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_privet,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_printer,
          &PtrRecordCopyContainer::SaveWithDummyArg));


  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));
  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));

  EXPECT_TRUE(record_printer.IsRecordWith("_printer._tcp.local",
                                          "hello._printer._tcp.local"));

  listener_privet.reset();
  listener_printer.reset();
}

TEST_F(MDnsTest, PassiveListenersWithCapitalization) {
  StrictMock<MockListenerDelegate> delegate_privet;
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.LOCAL", &delegate_privet);
  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_prinTER._Tcp.Local", &delegate_printer);

  ASSERT_TRUE(listener_privet->Start());
  ASSERT_TRUE(listener_printer->Start());

  // Send the same packet twice to ensure no records are double-counted.

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(
          Invoke(&record_privet, &PtrRecordCopyContainer::SaveWithDummyArg));

  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(
          Invoke(&record_printer, &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1WithCapitalization,
                        sizeof(kSamplePacket1WithCapitalization));
  SimulatePacketReceive(kSamplePacket1WithCapitalization,
                        sizeof(kSamplePacket1WithCapitalization));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._TCP.local",
                                         "hello._privet._TCP.local"));

  EXPECT_TRUE(record_printer.IsRecordWith("_PrinteR._TCP.local",
                                          "hello._PrinteR._TCP.local"));

  listener_privet.reset();
  listener_printer.reset();
}

TEST_F(MDnsTest, PassiveListenersCacheCleanup) {
  StrictMock<MockListenerDelegate> delegate_privet;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_privet2;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_privet,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));

  // Expect record is removed when its TTL expires.
  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .Times(Exactly(1))
      .WillOnce(DoAll(InvokeWithoutArgs(this, &MDnsTest::Stop),
                      Invoke(&record_privet2,
                             &PtrRecordCopyContainer::SaveWithDummyArg)));

  RunFor(base::Seconds(record_privet.ttl() + 1));

  EXPECT_TRUE(record_privet2.IsRecordWith("_privet._tcp.local",
                                          "hello._privet._tcp.local"));
}

// Ensure that the cleanup task scheduler won't schedule cleanup tasks in the
// past if the system clock creeps past the expiration time while in the
// cleanup dispatcher.
TEST_F(MDnsTest, CacheCleanupWithShortTTL) {
  // Use a nonzero starting time as a base.
  base::Time start_time = base::Time() + base::Seconds(1);

  auto timer = std::make_unique<MockTimer>();
  MockTimer* timer_ptr = timer.get();

  auto owned_clock = std::make_unique<MockClock>();
  MockClock* clock = owned_clock.get();
  test_clock_ = std::move(owned_clock);
  test_client_ = std::make_unique<MDnsClientImpl>(clock, std::move(timer));
  ASSERT_THAT(test_client_->StartListening(&socket_factory_), test::IsOk());

  EXPECT_CALL(*timer_ptr, StartObserver(_, _)).Times(1);
  EXPECT_CALL(*clock, Now())
      .Times(3)
      .WillRepeatedly(Return(start_time))
      .RetiresOnSaturation();

  // Receive two records with different TTL values.
  // TTL(privet)=1.0s
  // TTL(printer)=3.0s
  StrictMock<MockListenerDelegate> delegate_privet;
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_printer._tcp.local", &delegate_printer);

  ASSERT_TRUE(listener_privet->Start());
  ASSERT_TRUE(listener_printer->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1));
  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1));

  SimulatePacketReceive(kSamplePacket3, sizeof(kSamplePacket3));

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .Times(Exactly(1));

  // Set the clock to 2.0s, which should clean up the 'privet' record, but not
  // the printer. The mock clock will change Now() mid-execution from 2s to 4s.
  // Note: expectations are FILO-ordered -- t+2 seconds is returned, then t+4.
  EXPECT_CALL(*clock, Now())
      .WillOnce(Return(start_time + base::Seconds(4)))
      .RetiresOnSaturation();
  EXPECT_CALL(*clock, Now())
      .WillOnce(Return(start_time + base::Seconds(2)))
      .RetiresOnSaturation();

  EXPECT_CALL(*timer_ptr, StartObserver(_, base::TimeDelta()));

  timer_ptr->Fire();
}

TEST_F(MDnsTest, StopListening) {
  ASSERT_TRUE(test_client_->IsListening());

  test_client_->StopListening();
  EXPECT_FALSE(test_client_->IsListening());
}

TEST_F(MDnsTest, StopListening_CacheCleanupScheduled) {
  auto owned_clock = std::make_unique<base::SimpleTestClock>();
  base::SimpleTestClock* clock = owned_clock.get();
  test_clock_ = std::move(owned_clock);

  // Use a nonzero starting time as a base.
  clock->SetNow(base::Time() + base::Seconds(1));
  auto cleanup_timer = std::make_unique<base::MockOneShotTimer>();
  base::OneShotTimer* cleanup_timer_ptr = cleanup_timer.get();

  test_client_ =
      std::make_unique<MDnsClientImpl>(clock, std::move(cleanup_timer));
  ASSERT_THAT(test_client_->StartListening(&socket_factory_), test::IsOk());
  ASSERT_TRUE(test_client_->IsListening());

  // Receive one record (privet) with TTL=1s to schedule cleanup.
  SimulatePacketReceive(kSamplePacket3, sizeof(kSamplePacket3));
  ASSERT_TRUE(cleanup_timer_ptr->IsRunning());

  test_client_->StopListening();
  EXPECT_FALSE(test_client_->IsListening());

  // Expect cleanup unscheduled.
  EXPECT_FALSE(cleanup_timer_ptr->IsRunning());
}

TEST_F(MDnsTest, MalformedPacket) {
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_printer._tcp.local", &delegate_printer);

  ASSERT_TRUE(listener_printer->Start());

  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_printer,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  // First, send unsalvagable packet to ensure we can deal with it.
  SimulatePacketReceive(kCorruptedPacketUnsalvagable,
                        sizeof(kCorruptedPacketUnsalvagable));

  // Regression test: send a packet where the question cannot be read.
  SimulatePacketReceive(kCorruptedPacketBadQuestion,
                        sizeof(kCorruptedPacketBadQuestion));

  // Then send salvagable packet to ensure we can extract useful records.
  SimulatePacketReceive(kCorruptedPacketSalvagable,
                        sizeof(kCorruptedPacketSalvagable));

  EXPECT_TRUE(record_printer.IsRecordWith("_printer._tcp.local",
                                          "hello._printer._tcp.local"));
}

TEST_F(MDnsTest, TransactionWithEmptyCache) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  PtrRecordCopyContainer record_privet;

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(&record_privet,
                       &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));
}

TEST_F(MDnsTest, TransactionWithEmptyCacheAndCapitalization) {
  ExpectPacket(kQueryPacketPrivetWithCapitalization,
               sizeof(kQueryPacketPrivetWithCapitalization));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_PRIVET._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  PtrRecordCopyContainer record_privet;

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .Times(Exactly(1))
      .WillOnce(
          Invoke(&record_privet, &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1WithCapitalization,
                        sizeof(kSamplePacket1WithCapitalization));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._TCP.local",
                                         "hello._privet._TCP.local"));
}

TEST_F(MDnsTest, TransactionCacheOnlyNoResult) {
  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_CACHE | MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_NO_RESULTS, _))
      .Times(Exactly(1));

  ASSERT_TRUE(transaction_privet->Start());
}

TEST_F(MDnsTest, TransactionWithCache) {
  // Listener to force the client to listen
  StrictMock<MockListenerDelegate> delegate_irrelevant;
  std::unique_ptr<MDnsListener> listener_irrelevant =
      test_client_->CreateListener(dns_protocol::kTypeA,
                                   "codereview.chromium.local",
                                   &delegate_irrelevant);

  ASSERT_TRUE(listener_irrelevant->Start());

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));


  PtrRecordCopyContainer record_privet;

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .WillOnce(Invoke(&record_privet,
                       &PtrRecordCopyContainer::SaveWithDummyArg));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));
}

TEST_F(MDnsTest, AdditionalRecords) {
  StrictMock<MockListenerDelegate> delegate_privet;

  PtrRecordCopyContainer record_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_privet,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacketAdditionalOnly,
         
"""


```