Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Functionality:** The filename `web_transport_priority_scheduler_test.cc` and the included header `web_transport_priority_scheduler.h` immediately suggest that this file is testing the `WebTransportPriorityScheduler` class. The name strongly implies the scheduler manages the priority of WebTransport streams.

2. **Examine the Includes:** The included headers provide clues about the broader context:
    * `<optional>` and `<vector>`: Standard C++ containers, indicating data storage and manipulation.
    * `"absl/status/status.h"` and `"absl/status/statusor.h"`:  Indicate the use of Abseil's error handling mechanisms, suggesting that operations might succeed or fail.
    * `"absl/types/span.h"`:  Likely used for efficient passing of contiguous data.
    * `"quiche/common/platform/api/quiche_test.h"` and `"quiche/common/test_tools/quiche_test_utils.h"`: Confirm this is a test file within the QUICHE library, using its testing framework.
    * `"quiche/web_transport/web_transport.h"`:  Places the scheduler within the WebTransport context. We can infer that this scheduler is specific to WebTransport streams.

3. **Analyze Helper Functions:** The file starts with two helper functions:
    * `ScheduleIds`: This function takes a `PriorityScheduler` and a span of `StreamId`s and calls the `Schedule` method for each ID. This suggests the `Schedule` method is a core function of the scheduler.
    * `PopAll`:  This function repeatedly calls `PopFront` on the scheduler until it returns a "not found" error. This implies `PopFront` retrieves the next stream to be processed based on priority, and the "not found" error signifies an empty queue.

4. **Examine Individual Tests:** Each `TEST` function focuses on a specific aspect of the `PriorityScheduler`. Let's analyze a few key ones:
    * `Register`: Tests the `Register` method, ensuring that registering new streams works and that attempting to register the same stream ID twice fails with an "already exists" error. This confirms the scheduler keeps track of registered streams.
    * `Unregister`: Tests the `Unregister` method, confirming that streams can be removed. It also checks the `HasRegistered` and `HasScheduled` methods, indicating the scheduler maintains state about registered and scheduled streams.
    * `UpdatePriority`: Tests the ability to modify a stream's priority after registration using `UpdateSendGroup` and `UpdateSendOrder`. It also checks error handling for attempting to update the priority of a non-existent stream. The `GetPriorityFor` method is also examined.
    * `Schedule`:  Focuses on the `Schedule` method, verifying that it marks a stream as scheduled and handles attempts to schedule already scheduled or non-existent streams. The `IsScheduled` method is used for verification.
    * `SamePriority`: Tests the behavior when multiple streams have the same priority. The `PopAll` function helps see the order in which streams are popped. The implication is that with equal priority, they are likely processed in the order they were scheduled.
    * `SingleBucketOrdered`:  Tests the behavior within a single priority group (bucket) when `send_order` differs. The streams are popped in reverse order of their `send_order`.
    * `EveryStreamInItsOwnBucket`: Tests the scenario where each stream has a unique priority group. The popping order matches the scheduling order, indicating priority groups are processed in order.
    * `TwoBucketsNoSendOrder` and `TwoBucketsWithSendOrder`: These tests explore the interaction between priority groups (`send_group`) and the ordering within a group (`send_order`). They demonstrate how the scheduler prioritizes streams from different groups and then uses the `send_order` within each group.
    * `ShouldYield`: Tests the `ShouldYield` method. This method likely indicates whether a currently processed stream should yield its turn to another stream based on priority.
    * `UpdatePriorityWhileScheduled`:  Confirms that updating a stream's priority while it's scheduled affects the order in which it's processed.

5. **Infer Functionality:** Based on the tests, we can deduce the core functionalities of the `WebTransportPriorityScheduler`:
    * Registering and unregistering WebTransport streams.
    * Assigning and updating priorities to streams, consisting of a group and an order within the group.
    * Scheduling streams for processing.
    * Retrieving the next stream to process based on priority.
    * Determining if a stream should yield to another.

6. **Relate to JavaScript (Conceptual):** While the C++ code itself isn't directly executed in JavaScript, the *concepts* it embodies are relevant to how a web browser might manage WebTransport streams initiated by JavaScript. JavaScript code using the WebTransport API might conceptually influence the priority of streams it creates. For example, a user-initiated action might lead to a higher priority stream than a background data fetch.

7. **Construct Example Scenarios (Hypothetical):** To illustrate the logic, imagine a scenario where a webpage uses WebTransport:
    * The user clicks a button to load a high-priority image (Stream A).
    * The page is also fetching analytics data in the background (Stream B).
    * The scheduler would likely prioritize Stream A (higher `send_group` or `send_order`) so the image loads quickly, even if Stream B was initiated earlier.

8. **Identify Potential User/Programming Errors:**  Consider how developers might misuse this system:
    * Forgetting to register a stream before scheduling it.
    * Attempting to schedule a stream multiple times without a clear reason.
    * Not understanding the impact of `send_group` vs. `send_order` and setting priorities incorrectly.

9. **Trace User Actions (Debugging):**  Think about how a user's actions could lead to the execution of this code:
    * A user opens a webpage that uses WebTransport.
    * The JavaScript on the page opens one or more WebTransport sessions.
    * The JavaScript then creates streams within those sessions, potentially setting priority hints.
    * The browser's network stack (where this C++ code resides) uses the `WebTransportPriorityScheduler` to manage the order in which these streams send data.

By following these steps, we can systematically understand the purpose, functionality, and implications of this C++ test file within the context of the Chromium network stack and WebTransport.
This C++ source file, `web_transport_priority_scheduler_test.cc`, contains unit tests for the `WebTransportPriorityScheduler` class in Chromium's network stack. Let's break down its functionalities and answer your questions:

**Core Functionalities of `WebTransportPrioritySchedulerTest.cc`:**

The primary function of this file is to **thoroughly test the `WebTransportPriorityScheduler` class**. This involves verifying that the scheduler correctly manages the priority of WebTransport streams and determines the order in which they should be processed or allowed to send data. The tests cover various scenarios, including:

* **Registration and Unregistration:** Ensuring streams can be added and removed from the scheduler.
* **Priority Assignment and Updates:**  Testing how priorities are set, retrieved, and updated for streams. This includes both the priority group (`send_group`) and the order within the group (`send_order`).
* **Scheduling:** Verifying that streams can be marked as ready for processing (scheduled).
* **Popping (Retrieving):**  Testing the logic for retrieving the highest priority scheduled stream.
* **Handling Streams with the Same Priority:**  Ensuring fair handling of streams within the same priority level.
* **Prioritization Logic:** Validating the scheduler's behavior in different priority scenarios, including single and multiple priority groups, and the impact of `send_order`.
* **Yielding:** Testing the mechanism by which a stream can be asked to temporarily yield its turn to other streams.
* **Updating Priority of Scheduled Streams:**  Checking if priority changes are correctly applied even after a stream is already scheduled.

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it plays a crucial role in how WebTransport streams initiated by JavaScript are handled by the browser.

* **JavaScript's Role:** When a JavaScript application uses the WebTransport API to establish a connection and create streams, it can often provide hints or requests regarding the priority of those streams. This might be done implicitly through the order of operations or explicitly through API calls (though the exact API for setting priority might evolve).
* **C++ Scheduler's Role:** The `WebTransportPriorityScheduler` in the browser's network stack receives these priority hints (or default priorities if none are provided) and uses its internal logic to manage the transmission of data on these streams. It ensures that higher priority streams get preference in using the underlying QUIC connection's bandwidth.

**Example:**

Imagine a JavaScript application that fetches both a critical image and some less important analytics data over WebTransport:

```javascript
// JavaScript (Conceptual Example - exact API might vary)

const transport = new WebTransport("https://example.com/webtransport");
await transport.ready;

// Stream for a critical image (user-facing, high priority)
const imageStream = await transport.createUnidirectionalStream({ priority: 'high' });
const imageWriter = imageStream.writable.getWriter();
imageWriter.write(imageBlob);
imageWriter.close();

// Stream for analytics data (background, low priority)
const analyticsStream = await transport.createUnidirectionalStream({ priority: 'low' });
const analyticsWriter = analyticsStream.writable.getWriter();
analyticsWriter.write(analyticsData);
analyticsWriter.close();
```

In this scenario, when the browser's network stack receives these streams, the `WebTransportPriorityScheduler` (the C++ class being tested here) would use its logic to ensure that the `imageStream`'s data is sent before the `analyticsStream`'s data, even if the `analyticsStream` was created slightly earlier. The JavaScript's priority hints (in this conceptual example) influence the parameters used by the C++ scheduler.

**Logical Reasoning: Assumptions, Inputs, and Outputs**

Let's take one of the test cases, `TwoBucketsWithSendOrder`, as an example of logical reasoning:

**Assumptions:**

* Streams are registered with specific priority groups (`send_group`) and orders within those groups (`send_order`). Lower `send_group` values have higher priority. Lower `send_order` values within a group have higher priority.
* The `ScheduleIds` function adds the given stream IDs to the scheduler's ready queue.
* The `PopAll` function retrieves all scheduled streams in the order determined by the priority scheduler.

**Input:**

1. Register streams with the following priorities:
   * Stream 0: `{0, 0}`
   * Stream 1: `{0, 10}`
   * Stream 2: `{1, 20}`
   * Stream 3: `{1, 30}`
2. Schedule streams in the order: 0, 1, 2, 3.
3. Call `PopAll`.

**Output:**

The expected output of `PopAll` is: `ElementsAre(1, 3, 0, 2)`.

**Reasoning:**

* **Priority Group First:** Streams in `send_group` 0 have higher priority than streams in `send_group` 1. Therefore, streams 0 and 1 will be processed before streams 2 and 3.
* **Order Within Group:**
    * Within `send_group` 0, Stream 0 has `send_order` 0 and Stream 1 has `send_order` 10. Stream 0 has higher priority within this group.
    * Within `send_group` 1, Stream 2 has `send_order` 20 and Stream 3 has `send_order` 30. Stream 2 has higher priority within this group.
* **Interleaving:** The scheduler processes one stream from the highest priority group, then moves to the next highest priority group if there are scheduled streams there.

Let's analyze the popping order step-by-step:

1. **Initial Schedule (0, 1, 2, 3):**
2. **Pop:** The scheduler looks for the highest priority scheduled stream.
   * Group 0 has streams 0 and 1. Stream 0 has `send_order` 0, Stream 1 has `send_order` 10. Stream 0 is the highest priority in group 0.
   * Group 1 has streams 2 and 3. Stream 2 has `send_order` 20, Stream 3 has `send_order` 30. Stream 2 is the highest priority in group 1.
   * The scheduler prioritizes group 0.
3. **Pop again:**
   * Group 0 still has Stream 1 scheduled.
   * Group 1 has Stream 2 scheduled.
   * The scheduler prioritizes group 0.
4. **Pop again:**
   * Group 0 is empty.
   * Group 1 has Stream 2 scheduled.
   * The scheduler processes group 1.
5. **Pop again:**
   * Group 1 has Stream 3 scheduled.
   * The scheduler processes group 1.

This step-by-step breakdown confirms why the expected output is `ElementsAre(1, 3, 0, 2)`. The scheduler processes streams from higher priority groups first, and within each group, it processes streams with lower `send_order` values first.

**User or Programming Common Usage Errors:**

1. **Forgetting to Register a Stream:**
   ```c++
   PriorityScheduler scheduler;
   // Oops, forgot to register stream 0!
   EXPECT_THAT(scheduler.Schedule(0), StatusIs(absl::StatusCode::kNotFound));
   ```
   **User Action to Reach Here:** A developer writing the WebTransport implementation might forget to call the registration function before attempting to schedule a stream.

2. **Attempting to Schedule a Non-Existent Stream:**
   ```c++
   PriorityScheduler scheduler;
   QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
   EXPECT_THAT(scheduler.Schedule(1), StatusIs(absl::StatusCode::kNotFound));
   ```
   **User Action to Reach Here:** Similar to the above, a developer might have a logic error where they try to schedule a stream ID that hasn't been properly associated with the scheduler.

3. **Incorrectly Updating Priorities:**
   ```c++
   PriorityScheduler scheduler;
   QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
   // Intending to update stream 0's group, but using the wrong ID
   EXPECT_THAT(scheduler.UpdateSendGroup(1, 1), StatusIs(absl::StatusCode::kNotFound));
   ```
   **User Action to Reach Here:** A developer might have a bug in their code that calculates or passes the wrong stream ID when trying to update a stream's priority.

4. **Not Understanding Priority Inversion (Though not directly tested here, it's a common concept):**  A lower priority stream might block a higher priority stream if the lower priority stream holds a resource needed by the higher priority stream. While the scheduler aims to prioritize, it operates within the constraints of the underlying transport and resource management.

**User Operation Steps to Reach This Code (Debugging Context):**

1. **User Interaction in a Web Browser:** A user might interact with a web page that utilizes the WebTransport API. This interaction could trigger the creation of WebTransport streams (e.g., clicking a button, loading an image, sending data).
2. **JavaScript WebTransport API Usage:** The JavaScript code on the page uses the `WebTransport` API to establish connections and create streams, potentially setting priority hints.
3. **Browser's Network Stack Involvement:** When data needs to be sent on these WebTransport streams, the browser's network stack comes into play.
4. **`WebTransportPriorityScheduler` Invocation:** The network stack uses the `WebTransportPriorityScheduler` to determine the order in which data from different streams should be sent over the underlying QUIC connection.
5. **Potential Issue Triggering Debugging:** If there's an issue with the prioritization logic (e.g., a high-priority stream is not being sent promptly, or the order seems incorrect), developers might investigate the `WebTransportPriorityScheduler`.
6. **Debugging Tools and Breakpoints:** Developers might use debugging tools (like those in Chromium's source code or network inspection tools) to step through the code in `web_transport_priority_scheduler_test.cc` (or the actual `WebTransportPriorityScheduler.cc`) to understand how the priorities are being managed and identify the root cause of the issue. They might set breakpoints within the `Schedule`, `PopFront`, or priority update functions to observe the state of the scheduler and the stream priorities.

In essence, this test file ensures the correctness of a critical component responsible for managing the flow of data in WebTransport connections, which directly impacts the performance and user experience of web applications utilizing this technology.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/web_transport/web_transport_priority_scheduler_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/web_transport/web_transport_priority_scheduler.h"

#include <optional>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/web_transport.h"

namespace webtransport {
namespace {

using ::quiche::test::IsOkAndHolds;
using ::quiche::test::StatusIs;
using ::testing::ElementsAre;

void ScheduleIds(PriorityScheduler& scheduler, absl::Span<const StreamId> ids) {
  for (StreamId id : ids) {
    QUICHE_EXPECT_OK(scheduler.Schedule(id));
  }
}

std::vector<StreamId> PopAll(PriorityScheduler& scheduler) {
  std::vector<StreamId> result;
  result.reserve(scheduler.NumScheduled());
  for (;;) {
    absl::StatusOr<StreamId> id = scheduler.PopFront();
    if (!id.ok()) {
      EXPECT_THAT(id, StatusIs(absl::StatusCode::kNotFound));
      break;
    }
    result.push_back(*id);
  }
  return result;
}

TEST(WebTransportSchedulerTest, Register) {
  PriorityScheduler scheduler;

  // Register two streams in the same group.
  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{1, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{1, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(4, StreamPriority{0, 0}));

  // Attempt re-registering.
  EXPECT_THAT(scheduler.Register(4, StreamPriority{0, 0}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(scheduler.Register(4, StreamPriority{1, 0}),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(WebTransportSchedulerTest, Unregister) {
  PriorityScheduler scheduler;

  EXPECT_FALSE(scheduler.HasRegistered());
  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));

  EXPECT_TRUE(scheduler.HasRegistered());
  QUICHE_EXPECT_OK(scheduler.Unregister(1));
  EXPECT_TRUE(scheduler.HasRegistered());
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));

  ScheduleIds(scheduler, {0, 1});
  QUICHE_EXPECT_OK(scheduler.Unregister(0));
  QUICHE_EXPECT_OK(scheduler.Unregister(1));
  EXPECT_FALSE(scheduler.HasRegistered());
  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));
  EXPECT_TRUE(scheduler.HasRegistered());
  EXPECT_FALSE(scheduler.HasScheduled());
}

TEST(WebTransportSchedulerTest, UpdatePriority) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 10}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 20}));
  EXPECT_EQ(scheduler.GetPriorityFor(0), (StreamPriority{0, 10}));
  EXPECT_EQ(scheduler.GetPriorityFor(1), (StreamPriority{0, 20}));

  QUICHE_EXPECT_OK(scheduler.UpdateSendGroup(0, 1));
  QUICHE_EXPECT_OK(scheduler.UpdateSendOrder(1, 40));
  EXPECT_EQ(scheduler.GetPriorityFor(0), (StreamPriority{1, 10}));
  EXPECT_EQ(scheduler.GetPriorityFor(1), (StreamPriority{0, 40}));

  EXPECT_THAT(scheduler.UpdateSendGroup(1000, 1),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(scheduler.UpdateSendOrder(1000, 1),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_EQ(scheduler.GetPriorityFor(1000), std::nullopt);
}

TEST(WebTransportSchedulerTest, Schedule) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));

  EXPECT_FALSE(scheduler.IsScheduled(0));
  EXPECT_FALSE(scheduler.IsScheduled(1));
  EXPECT_FALSE(scheduler.IsScheduled(1000));

  QUICHE_EXPECT_OK(scheduler.Schedule(0));
  EXPECT_TRUE(scheduler.IsScheduled(0));
  EXPECT_FALSE(scheduler.IsScheduled(1));

  QUICHE_EXPECT_OK(scheduler.Schedule(1));
  EXPECT_TRUE(scheduler.IsScheduled(0));
  EXPECT_TRUE(scheduler.IsScheduled(1));

  EXPECT_THAT(scheduler.Schedule(0), StatusIs(absl::StatusCode::kOk));
  EXPECT_THAT(scheduler.Schedule(2), StatusIs(absl::StatusCode::kNotFound));
}

TEST(WebTransportSchedulerTest, SamePriority) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{0, 0}));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  EXPECT_EQ(scheduler.NumScheduled(), 4);
  EXPECT_THAT(PopAll(scheduler), ElementsAre(0, 1, 2, 3));
  ScheduleIds(scheduler, {3, 1, 2});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(3, 1, 2));
}

TEST(WebTransportSchedulerTest, SingleBucketOrdered) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 1}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{0, 2}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{0, 3}));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(3, 2, 1, 0));
  ScheduleIds(scheduler, {3, 1, 2, 0});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(3, 2, 1, 0));
}

TEST(WebTransportSchedulerTest, EveryStreamInItsOwnBucket) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{1, 1}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{2, 2}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{3, 3}));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(0, 1, 2, 3));
  ScheduleIds(scheduler, {3, 1, 2});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(3, 1, 2));
}

TEST(WebTransportSchedulerTest, TwoBucketsNoSendOrder) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{1, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{1, 0}));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(0, 2, 1, 3));
  ScheduleIds(scheduler, {0, 2, 1, 3});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(0, 2, 1, 3));
  ScheduleIds(scheduler, {3, 2, 1, 0});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(3, 1, 2, 0));

  ScheduleIds(scheduler, {0, 2});
  EXPECT_THAT(scheduler.PopFront(), IsOkAndHolds(0));
  ScheduleIds(scheduler, {1, 3, 0});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(2, 1, 3, 0));
}

TEST(WebTransportSchedulerTest, TwoBucketsWithSendOrder) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 10}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{1, 20}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{1, 30}));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(1, 3, 0, 2));
  ScheduleIds(scheduler, {3, 2, 1, 0});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(3, 1, 2, 0));
}

TEST(WebTransportSchedulerTest, ShouldYield) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{0, 10}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{1, 0}));

  EXPECT_THAT(scheduler.ShouldYield(0), IsOkAndHolds(false));
  EXPECT_THAT(scheduler.ShouldYield(1), IsOkAndHolds(false));
  EXPECT_THAT(scheduler.ShouldYield(2), IsOkAndHolds(false));
  EXPECT_THAT(scheduler.ShouldYield(3), IsOkAndHolds(false));
  EXPECT_THAT(scheduler.ShouldYield(4), StatusIs(absl::StatusCode::kNotFound));

  QUICHE_EXPECT_OK(scheduler.Schedule(0));
  EXPECT_THAT(scheduler.ShouldYield(0), IsOkAndHolds(false));
  EXPECT_THAT(scheduler.ShouldYield(1), IsOkAndHolds(true));
  EXPECT_THAT(scheduler.ShouldYield(2), IsOkAndHolds(false));
  EXPECT_THAT(scheduler.ShouldYield(3), IsOkAndHolds(true));
  PopAll(scheduler);

  QUICHE_EXPECT_OK(scheduler.Schedule(2));
  EXPECT_THAT(scheduler.ShouldYield(0), IsOkAndHolds(true));
  EXPECT_THAT(scheduler.ShouldYield(1), IsOkAndHolds(true));
  EXPECT_THAT(scheduler.ShouldYield(2), IsOkAndHolds(false));
  EXPECT_THAT(scheduler.ShouldYield(3), IsOkAndHolds(true));
  PopAll(scheduler);

  QUICHE_EXPECT_OK(scheduler.Schedule(3));
  EXPECT_THAT(scheduler.ShouldYield(0), IsOkAndHolds(true));
  EXPECT_THAT(scheduler.ShouldYield(1), IsOkAndHolds(true));
  EXPECT_THAT(scheduler.ShouldYield(2), IsOkAndHolds(true));
  EXPECT_THAT(scheduler.ShouldYield(3), IsOkAndHolds(false));
  PopAll(scheduler);
}

TEST(WebTransportSchedulerTest, UpdatePriorityWhileScheduled) {
  PriorityScheduler scheduler;

  QUICHE_EXPECT_OK(scheduler.Register(0, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(1, StreamPriority{0, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(2, StreamPriority{1, 0}));
  QUICHE_EXPECT_OK(scheduler.Register(3, StreamPriority{1, 0}));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  EXPECT_THAT(PopAll(scheduler), ElementsAre(0, 2, 1, 3));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  QUICHE_EXPECT_OK(scheduler.UpdateSendOrder(1, 10));
  EXPECT_THAT(PopAll(scheduler), ElementsAre(1, 2, 0, 3));

  ScheduleIds(scheduler, {0, 1, 2, 3});
  QUICHE_EXPECT_OK(scheduler.UpdateSendGroup(1, 1));
  EXPECT_THAT(PopAll(scheduler), ElementsAre(0, 1, 2, 3));
}

}  // namespace
}  // namespace webtransport
```