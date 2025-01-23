Response:
The user wants a summary of the `SQLTransactionBackend.cc` file. I need to extract the main functionalities of this class and its relationships with other components. The user also asked for specific examples related to Javascript, HTML, CSS, logical reasoning, common errors, and debugging.

Here's a plan:
1. **Identify the core purpose of `SQLTransactionBackend`:** Based on the code and comments, it manages the backend execution of SQL transactions in the web database API.
2. **List its key responsibilities:**  This includes managing the transaction lifecycle, interacting with the SQLite database, handling statement execution, and coordinating with the frontend (`SQLTransaction`).
3. **Explain the frontend-backend interaction:**  Highlight the asynchronous nature and the use of state transitions.
4. **Address the Javascript/HTML/CSS relationship:** While not directly interacting with these, explain how Javascript uses the Web SQL API, which relies on this backend.
5. **Demonstrate logical reasoning:**  Provide a simple example of how the state machine progresses.
6. **Illustrate common user errors:**  Focus on incorrect SQL syntax or quota issues.
7. **Explain the debugging path:** Trace a user action from Javascript to this backend.
8. **Summarize the functionalities for Part 1.**
```
功能列表：
1. **管理 SQL 事务的后端生命周期：**  `SQLTransactionBackend` 负责处理 SQL 事务在数据库线程上的执行，包括事务的开始、语句的执行、提交或回滚，以及事务的清理和终止。它维护事务的状态，并根据状态转换图执行相应的操作。

2. **与 SQLite 数据库交互：**  该类直接与底层的 SQLite 数据库交互，负责开启和关闭 SQLite 事务，执行 SQL 语句，并处理 SQLite 返回的错误。

3. **处理 SQL 语句队列：**  它维护一个待执行的 SQL 语句队列 (`statement_queue_`)，并按顺序执行这些语句。

4. **与前端 `SQLTransaction` 对象协调：**  `SQLTransactionBackend` 与前端的 `SQLTransaction` 对象紧密关联，通过状态转换机制进行通信，例如，当后端完成某些操作后，会通知前端执行相应的回调函数。

5. **处理事务回调函数：**  根据前端提供的回调函数（如 `transactionCallback`, `errorCallback`, `successCallback`），在合适的时机调用这些函数。

6. **处理语句回调函数：**  如果 SQL 语句执行后有相关的回调函数，`SQLTransactionBackend` 会在语句执行完成后，通知前端执行这些回调。

7. **处理数据库配额增加请求：**  当 SQL 语句执行因为超出数据库配额而失败时，`SQLTransactionBackend` 会通知前端，允许用户请求增加配额。

8. **处理事务的提交和回滚：**  根据事务的执行结果，`SQLTransactionBackend` 负责提交事务（如果所有语句都成功执行）或回滚事务（如果发生错误）。

9. **管理数据库锁：**  在执行事务之前，`SQLTransactionBackend` 会尝试获取数据库锁，以保证事务的原子性和隔离性。

10. **处理版本不匹配：**  当事务开始时，会检查预期的数据库版本与实际版本是否匹配，如果不匹配，会进行相应的处理。

11. **清理资源：**  在事务结束时，`SQLTransactionBackend` 会清理相关的资源，例如关闭 SQLite 事务，释放数据库锁等。

与 javascript, html, css 的功能关系及举例说明：

`SQLTransactionBackend` 是 Web SQL Database API 的一部分，这个 API 允许 JavaScript 代码在客户端浏览器中操作本地数据库。

* **JavaScript:**  JavaScript 代码使用 `openDatabase` 函数打开数据库，然后通过 `transaction` 或 `readTransaction` 方法创建一个 `SQLTransaction` 对象。在这个 `transaction` 方法中，可以传入一个回调函数，该回调函数接收一个 `SQLTransaction` 对象作为参数。在这个回调函数中，可以使用 `executeSql` 方法执行 SQL 语句。`SQLTransactionBackend` 的主要职责就是处理这些由 JavaScript 发起的 SQL 事务。

   **举例：**

   ```javascript
   var db = openDatabase('mydb', '1.0', 'Test DB', 2 * 1024 * 1024);
   db.transaction(function (tx) { // 这里创建了一个 SQLTransaction，对应的后端是 SQLTransactionBackend
     tx.executeSql('CREATE TABLE IF NOT EXISTS LOGS (id unique, log)');
     tx.executeSql('INSERT INTO LOGS (id, log) VALUES (?, ?)', [1, '记录信息']);
   }, function(error) { // transaction 的 errorCallback 会被 DeliverTransactionErrorCallback 触发
     console.log('Transaction ERROR: ' + error.message);
   }, function() { // transaction 的 successCallback 会被 DeliverSuccessCallback 触发
     console.log('Transaction success!');
   });
   ```

* **HTML:** HTML 提供了用户界面，用户在网页上的操作（例如点击按钮）可能会触发 JavaScript 代码执行数据库操作。

   **举例：**  一个按钮的 `onclick` 事件触发一个 JavaScript 函数，该函数执行上述的数据库插入操作。

   ```html
   <button onclick="insertLog()">插入日志</button>
   <script>
   function insertLog() {
     var db = openDatabase('mydb', '1.0', 'Test DB', 2 * 1024 * 1024);
     db.transaction(function (tx) {
       tx.executeSql('INSERT INTO LOGS (id, log) VALUES (?, ?)', [Date.now(), '按钮点击事件']);
     });
   }
   </script>
   ```

* **CSS:** CSS 负责页面的样式，与数据库操作本身没有直接关系。但 CSS 可以用来呈现从数据库中读取的数据。

   **举例：**  虽然 CSS 不直接影响 `SQLTransactionBackend`，但是可以通过 JavaScript 从数据库中读取数据，然后动态生成 HTML 元素，并使用 CSS 进行样式化展示。

逻辑推理的假设输入与输出：

**假设输入：**

1. JavaScript 代码调用 `db.transaction()` 创建了一个事务，并执行了两个 `executeSql` 语句：创建一个表和一个插入语句。
2. 假设数据库之前不存在，因此第一个语句会创建表。
3. 假设插入语句的参数是有效的。

**输出：**

1. `SQLTransactionBackend` 的状态会依次经历 `AcquireLock`, `OpenTransactionAndPreflight`, `RunStatements` 等状态。
2. 在 `RunStatements` 状态，第一个 `executeSql` 语句（创建表）会被执行成功。
3. 紧接着，第二个 `executeSql` 语句（插入数据）会被执行成功。
4. 如果没有错误发生，事务最终会进入 `PostflightAndCommit` 状态，并提交事务。
5. 如果提供了 `successCallback`，则会执行 `DeliverSuccessCallback`，调用 JavaScript 中 `transaction` 方法的成功回调函数。

用户或编程常见的使用错误举例说明：

1. **SQL 语法错误：** 用户在 `executeSql` 中提供的 SQL 语句存在语法错误。

    **举例：** `tx.executeSql('INSERT INTO LOGS (id log) VALUES (?, ?)', [1, 'error']);`  （缺少逗号）

    在这种情况下，`SQLTransactionBackend` 在执行 `RunStatements` 状态时，会调用 SQLite 执行 SQL 语句，SQLite 会返回错误，`SQLTransactionBackend` 会捕获这个错误，并将事务状态转移到 `DeliverTransactionErrorCallback`，最终调用 JavaScript 中 `transaction` 方法的错误回调函数。

2. **数据库不存在或权限问题：**  `openDatabase` 调用的数据库名称错误，或者浏览器没有访问数据库的权限。

    **举例：** `openDatabase('non_existent_db', ...)`

    在这种情况下，数据库打开失败，可能在 `AcquireLock` 之前的某个阶段就会发生错误，或者在 `OpenTransactionAndPreflight` 尝试开启事务时失败，最终导致 `DeliverTransactionErrorCallback` 被调用。

3. **数据类型不匹配：**  在 `executeSql` 中提供的参数类型与数据库表结构不匹配。

    **举例：** 如果 `LOGS` 表的 `id` 列是 INTEGER 类型，但 JavaScript 传递了一个字符串： `tx.executeSql('INSERT INTO LOGS (id, log) VALUES (?, ?)', ['abc', 'log']);`

    这可能会导致 SQLite 执行错误，`SQLTransactionBackend` 会将事务状态转移到错误处理流程。

4. **超出数据库配额：**  尝试插入大量数据导致超出浏览器为该网站分配的数据库存储空间。

    在这种情况下，在 `RunStatements` 状态执行插入语句时，SQLite 会返回配额超出的错误。`SQLTransactionBackend` 可能会先尝试调用 `DeliverQuotaIncreaseCallback` 允许用户增加配额，如果用户没有增加或者增加后仍然不够，则会将事务状态转移到 `DeliverTransactionErrorCallback`。

用户操作如何一步步的到达这里，作为调试线索：

1. **用户在网页上执行某些操作** (例如点击按钮，提交表单)。
2. **该操作触发了网页上的 JavaScript 代码**。
3. **JavaScript 代码调用了 `openDatabase` 获取数据库对象**。
4. **JavaScript 代码调用了数据库对象的 `transaction` 或 `readTransaction` 方法**，并传入了事务处理的回调函数。这会在浏览器内部创建一个 `SQLTransaction` 对象，并关联一个 `SQLTransactionBackend` 对象。
5. **在 `transaction` 方法的回调函数中，JavaScript 代码调用了 `SQLTransaction` 对象的 `executeSql` 方法**，提交需要执行的 SQL 语句和参数。这些语句会被添加到 `SQLTransactionBackend` 的 `statement_queue_` 中。
6. **浏览器将这个事务任务调度到数据库线程**。
7. **数据库线程执行 `SQLTransactionBackend` 的 `PerformNextStep` 方法**，开始事务的状态机执行。
8. **`SQLTransactionBackend` 首先尝试 `AcquireLock`** 获取数据库锁。
9. **获取锁成功后，进入 `OpenTransactionAndPreflight` 状态**，开启 SQLite 事务。
10. **接着进入 `RunStatements` 状态**，从 `statement_queue_` 中取出 SQL 语句，调用 SQLite 执行。
11. **如果 SQL 语句执行成功，并且有语句回调，则进入 `DeliverStatementCallback` 状态**，通知前端执行 JavaScript 的语句回调函数。
12. **如果 SQL 语句执行失败，则根据错误类型可能进入 `DeliverQuotaIncreaseCallback` 或 `DeliverTransactionErrorCallback` 状态**。
13. **当所有语句执行完毕，且没有错误，进入 `PostflightAndCommit` 状态**，提交 SQLite 事务。
14. **最后，根据事务是否成功，分别进入 `DeliverSuccessCallback` 或 `CleanupAfterTransactionErrorCallback` 状态**，通知前端事务的结果，并进行资源清理。

作为调试线索，可以关注以下几点：

*   在哪个 JavaScript 函数中调用了 `transaction` 和 `executeSql`。
*   传递给 `executeSql` 的 SQL 语句和参数是否正确。
*   `transaction` 方法的回调函数是否正确处理了成功和失败的情况。
*   浏览器开发者工具的 "Application" 或 "Resources" 面板中是否有关于数据库错误的提示。

归纳一下它的功能 (第1部分)：

`SQLTransactionBackend` 的主要功能是**在 Chromium Blink 引擎的数据库线程上，负责执行由 JavaScript Web SQL API 发起的 SQL 事务**。它作为一个状态机，管理事务的生命周期，包括获取数据库锁、开启 SQLite 事务、执行 SQL 语句队列、处理事务和语句的回调、处理错误和配额问题，并最终提交或回滚事务，以及清理相关资源。它扮演着前端 JavaScript 代码与后端 SQLite 数据库之间的桥梁角色。
```
### 提示词
```
这是目录为blink/renderer/modules/webdatabase/sql_transaction_backend.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2007, 2008, 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webdatabase/sql_transaction_backend.h"

#include <memory>

#include "third_party/blink/renderer/modules/webdatabase/database.h"
#include "third_party/blink/renderer/modules/webdatabase/database_authorizer.h"
#include "third_party/blink/renderer/modules/webdatabase/database_context.h"
#include "third_party/blink/renderer/modules/webdatabase/database_thread.h"
#include "third_party/blink/renderer/modules/webdatabase/database_tracker.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_error.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_statement_backend.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_transaction.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_transaction_client.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_transaction_coordinator.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sql_value.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sqlite_transaction.h"
#include "third_party/blink/renderer/modules/webdatabase/storage_log.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

// How does a SQLTransaction work?
// ==============================
// The SQLTransaction is a state machine that executes a series of states /
// steps.
//
// The work of the transaction states are defined in section of 4.3.2 of the
// webdatabase spec: http://dev.w3.org/html5/webdatabase/#processing-model
//
// the State Transition Graph at a glance:
// ======================================
//
//     Backend                        .   Frontend
//     (works with SQLiteDatabase)    .   (works with Script)
//     ===========================    .   ===================
//                                    .
//     1. Idle                        .
//         v                          .
//     2. AcquireLock                 .
//         v                          .
//     3. OpenTransactionAndPreflight -----------------------------------.
//         |                        .                                    |
//         `-------------------------> 8. DeliverTransactionCallback --. |
//                                  .     |                           v v
//         ,------------------------------' 9. DeliverTransactionErrorCallback +
//         |                        .                                  ^ ^ ^   |
//         v                        .                                  | | |   |
//     4. RunStatements -----------------------------------------------' | |   |
//         |        ^  ^ |  ^ |     .                                    | |   |
//         |--------'  | |  | `------> 10. DeliverStatementCallback +----' |   |
//         |           | |  `---------------------------------------'      |   |
//         |           | `-----------> 11. DeliverQuotaIncreaseCallback +  |   |
//         |            `-----------------------------------------------'  |   |
//         v                        .                                      |   |
//     5. PostflightAndCommit --+------------------------------------------'   |
//                              |----> 12. DeliverSuccessCallback +            |
//         ,--------------------'   .                             |            |
//         v                        .                             |            |
//     6. CleanupAndTerminate <-----------------------------------'            |
//         v           ^            .                                          |
//     0. End          |            .                                          |
//                     |            .                                          |
//                7: CleanupAfterTransactionErrorCallback <--------------------'
//                                  .
//
// the States and State Transitions:
// ================================
//     0. SQLTransactionState::End
//         - the end state.
//
//     1. SQLTransactionState::Idle
//         - placeholder state while waiting on frontend/backend, etc. See
//           comment on "State transitions between SQLTransaction and
//           SQLTransactionBackend" below.
//
//     2. SQLTransactionState::AcquireLock (runs in backend)
//         - this is the start state.
//         - acquire the "lock".
//         - on "lock" acquisition, goto
//           SQLTransactionState::OpenTransactionAndPreflight.
//
//     3. SQLTransactionState::openTransactionAndPreflight (runs in backend)
//         - Sets up an SQLiteTransaction.
//         - begin the SQLiteTransaction.
//         - call the SQLTransactionWrapper preflight if available.
//         - schedule script callback.
//         - on error, goto
//           SQLTransactionState::DeliverTransactionErrorCallback.
//         - goto SQLTransactionState::DeliverTransactionCallback.
//
//     4. SQLTransactionState::DeliverTransactionCallback (runs in frontend)
//         - invoke the script function callback() if available.
//         - on error, goto
//           SQLTransactionState::DeliverTransactionErrorCallback.
//         - goto SQLTransactionState::RunStatements.
//
//     5. SQLTransactionState::DeliverTransactionErrorCallback (runs in
//        frontend)
//         - invoke the script function errorCallback if available.
//         - goto SQLTransactionState::CleanupAfterTransactionErrorCallback.
//
//     6. SQLTransactionState::RunStatements (runs in backend)
//         - while there are statements {
//             - run a statement.
//             - if statementCallback is available, goto
//               SQLTransactionState::DeliverStatementCallback.
//             - on error,
//               goto SQLTransactionState::DeliverQuotaIncreaseCallback, or
//               goto SQLTransactionState::DeliverStatementCallback, or
//               goto SQLTransactionState::deliverTransactionErrorCallback.
//           }
//         - goto SQLTransactionState::PostflightAndCommit.
//
//     7. SQLTransactionState::DeliverStatementCallback (runs in frontend)
//         - invoke script statement callback (assume available).
//         - on error, goto
//           SQLTransactionState::DeliverTransactionErrorCallback.
//         - goto SQLTransactionState::RunStatements.
//
//     8. SQLTransactionState::DeliverQuotaIncreaseCallback (runs in frontend)
//         - give client a chance to increase the quota.
//         - goto SQLTransactionState::RunStatements.
//
//     9. SQLTransactionState::PostflightAndCommit (runs in backend)
//         - call the SQLTransactionWrapper postflight if available.
//         - commit the SQLiteTansaction.
//         - on error, goto
//           SQLTransactionState::DeliverTransactionErrorCallback.
//         - if successCallback is available, goto
//           SQLTransactionState::DeliverSuccessCallback.
//           else goto SQLTransactionState::CleanupAndTerminate.
//
//     10. SQLTransactionState::DeliverSuccessCallback (runs in frontend)
//         - invoke the script function successCallback() if available.
//         - goto SQLTransactionState::CleanupAndTerminate.
//
//     11. SQLTransactionState::CleanupAndTerminate (runs in backend)
//         - stop and clear the SQLiteTransaction.
//         - release the "lock".
//         - goto SQLTransactionState::End.
//
//     12. SQLTransactionState::CleanupAfterTransactionErrorCallback (runs in
//         backend)
//         - rollback the SQLiteTransaction.
//         - goto SQLTransactionState::CleanupAndTerminate.
//
// State transitions between SQLTransaction and SQLTransactionBackend
// ==================================================================
// As shown above, there are state transitions that crosses the boundary between
// the frontend and backend. For example,
//
//     OpenTransactionAndPreflight (state 3 in the backend)
//     transitions to DeliverTransactionCallback (state 8 in the frontend),
//     which in turn transitions to RunStatements (state 4 in the backend).
//
// This cross boundary transition is done by posting transition requests to the
// other side and letting the other side's state machine execute the state
// transition in the appropriate thread (i.e. the script thread for the
// frontend, and the database thread for the backend).
//
// Logically, the state transitions work as shown in the graph above. But
// physically, the transition mechanism uses the Idle state (both in the
// frontend and backend) as a waiting state for further activity. For example,
// taking a closer look at the 3 state transition example above, what actually
// happens is as follows:
//
//     Step 1:
//     ======
//     In the frontend thread:
//     - waiting quietly is Idle. Not doing any work.
//
//     In the backend:
//     - is in OpenTransactionAndPreflight, and doing its work.
//     - when done, it transits to the backend DeliverTransactionCallback.
//     - the backend DeliverTransactionCallback sends a request to the frontend
//       to transit to DeliverTransactionCallback, and then itself transits to
//       Idle.
//
//     Step 2:
//     ======
//     In the frontend thread:
//     - transits to DeliverTransactionCallback and does its work.
//     - when done, it transits to the frontend RunStatements.
//     - the frontend RunStatements sends a request to the backend to transit
//       to RunStatements, and then itself transits to Idle.
//
//     In the backend:
//     - waiting quietly in Idle.
//
//     Step 3:
//     ======
//     In the frontend thread:
//     - waiting quietly is Idle. Not doing any work.
//
//     In the backend:
//     - transits to RunStatements, and does its work.
//        ...
//
// So, when the frontend or backend are not active, they will park themselves in
// their Idle states. This means their m_nextState is set to Idle, but they
// never actually run the corresponding state function. Note: for both the
// frontend and backend, the state function for Idle is unreachableState().
//
// The states that send a request to their peer across the front/back boundary
// are implemented with just 2 functions: SQLTransaction::sendToBackendState()
// and SQLTransactionBackend::sendToFrontendState(). These state functions do
// nothing but sends a request to the other side to transit to the current
// state (indicated by m_nextState), and then transits itself to the Idle state
// to wait for further action.

// The Life-Cycle of a SQLTransaction i.e. Who's keeping the SQLTransaction
// alive?
// ==============================================================================
// The RefPtr chain goes something like this:
//
//     At birth (in Database::runTransaction()):
//     ====================================================
//     Database
//         // HeapDeque<Member<SQLTransactionBackend>> m_transactionQueue
//         // points to ...
//     --> SQLTransactionBackend
//         // Member<SQLTransaction> m_frontend points to ...
//     --> SQLTransaction
//         // Member<SQLTransactionBackend> m_backend points to ...
//     --> SQLTransactionBackend  // which is a circular reference.
//
//     Note: there's a circular reference between the SQLTransaction front-end
//     and back-end. This circular reference is established in the constructor
//     of the SQLTransactionBackend. The circular reference will be broken by
//     calling doCleanup() to nullify m_frontend. This is done at the end of the
//     transaction's clean up state (i.e. when the transaction should no longer
//     be in use thereafter), or if the database was interrupted. See comments
//     on "What happens if a transaction is interrupted?" below for details.
//
//     After scheduling the transaction with the DatabaseThread
//     (Database::scheduleTransaction()):
//     ======================================================================================================
//     DatabaseThread
//         // MessageQueue<DatabaseTask> m_queue points to ...
//     --> DatabaseTransactionTask
//         // Member<SQLTransactionBackend> m_transaction points to ...
//     --> SQLTransactionBackend
//         // Member<SQLTransaction> m_frontend points to ...
//     --> SQLTransaction
//         // Member<SQLTransactionBackend> m_backend points to ...
//     --> SQLTransactionBackend  // which is a circular reference.
//
//     When executing the transaction (in DatabaseThread::databaseThread()):
//     ====================================================================
//     std::unique_ptr<DatabaseTask> task;
//         // points to ...
//     --> DatabaseTransactionTask
//         // Member<SQLTransactionBackend> m_transaction points to ...
//     --> SQLTransactionBackend
//         // Member<SQLTransaction> m_frontend;
//     --> SQLTransaction
//         // Member<SQLTransactionBackend> m_backend points to ...
//     --> SQLTransactionBackend  // which is a circular reference.
//
//     At the end of cleanupAndTerminate():
//     ===================================
//     At the end of the cleanup state, the SQLTransactionBackend::m_frontend is
//     nullified.  If by then, a JSObject wrapper is referring to the
//     SQLTransaction, then the reference chain looks like this:
//
//     JSObjectWrapper
//     --> SQLTransaction
//         // in Member<SQLTransactionBackend> m_backend points to ...
//     --> SQLTransactionBackend
//         // which no longer points back to its SQLTransaction.
//
//     When the GC collects the corresponding JSObject, the above chain will be
//     cleaned up and deleted.
//
//     If there is no JSObject wrapper referring to the SQLTransaction when the
//     cleanup states nullify SQLTransactionBackend::m_frontend, the
//     SQLTransaction will deleted then.  However, there will still be a
//     DatabaseTask pointing to the SQLTransactionBackend (see the "When
//     executing the transaction" chain above). This will keep the
//     SQLTransactionBackend alive until DatabaseThread::databaseThread()
//     releases its task std::unique_ptr.
//
//     What happens if a transaction is interrupted?
//     ============================================
//     If the transaction is interrupted half way, it won't get to run to state
//     CleanupAndTerminate, and hence, would not have called
//     SQLTransactionBackend's doCleanup(). doCleanup() is where we nullify
//     SQLTransactionBackend::m_frontend to break the reference cycle between
//     the frontend and backend. Hence, we need to cleanup the transaction by
//     other means.
//
//     Note: calling SQLTransactionBackend::notifyDatabaseThreadIsShuttingDown()
//     is effectively the same as calling SQLTransactionBackend::doClean().
//
//     In terms of who needs to call doCleanup(), there are 5 phases in the
//     SQLTransactionBackend life-cycle. These are the phases and how the clean
//     up is done:
//
//     Phase 1. After Birth, before scheduling
//
//     - To clean up, DatabaseThread::databaseThread() will call
//       Database::close() during its shutdown.
//     - Database::close() will iterate
//       Database::m_transactionQueue and call
//       notifyDatabaseThreadIsShuttingDown() on each transaction there.
//
//     Phase 2. After scheduling, before state AcquireLock
//
//     - If the interruption occures before the DatabaseTransactionTask is
//       scheduled in DatabaseThread::m_queue but hasn't gotten to execute
//       (i.e. DatabaseTransactionTask::performTask() has not been called),
//       then the DatabaseTransactionTask may get destructed before it ever
//       gets to execute.
//     - To clean up, the destructor will check if the task's m_wasExecuted is
//       set. If not, it will call notifyDatabaseThreadIsShuttingDown() on
//       the task's transaction.
//
//     Phase 3. After state AcquireLock, before "lockAcquired"
//
//     - In this phase, the transaction would have been added to the
//       SQLTransactionCoordinator's CoordinationInfo's pendingTransactions.
//     - To clean up, during shutdown, DatabaseThread::databaseThread() calls
//       SQLTransactionCoordinator::shutdown(), which calls
//       notifyDatabaseThreadIsShuttingDown().
//
//     Phase 4: After "lockAcquired", before state CleanupAndTerminate
//
//     - In this phase, the transaction would have been added either to the
//       SQLTransactionCoordinator's CoordinationInfo's activeWriteTransaction
//       or activeReadTransactions.
//     - To clean up, during shutdown, DatabaseThread::databaseThread() calls
//       SQLTransactionCoordinator::shutdown(), which calls
//       notifyDatabaseThreadIsShuttingDown().
//
//     Phase 5: After state CleanupAndTerminate
//
//     - This is how a transaction ends normally.
//     - state CleanupAndTerminate calls doCleanup().

namespace blink {

SQLTransactionBackend::SQLTransactionBackend(Database* db,
                                             SQLTransaction* frontend,
                                             SQLTransactionWrapper* wrapper,
                                             bool read_only)
    : frontend_(frontend),
      database_(db),
      wrapper_(wrapper),
      has_callback_(frontend_->HasCallback()),
      has_success_callback_(frontend_->HasSuccessCallback()),
      has_error_callback_(frontend_->HasErrorCallback()),
      should_retry_current_statement_(false),
      modified_database_(false),
      lock_acquired_(false),
      read_only_(read_only),
      has_version_mismatch_(false) {
  DCHECK(IsMainThread());
  DCHECK(database_);
  frontend_->SetBackend(this);
  requested_state_ = SQLTransactionState::kAcquireLock;
}

SQLTransactionBackend::~SQLTransactionBackend() {
  DCHECK(!sqlite_transaction_);
}

void SQLTransactionBackend::Trace(Visitor* visitor) const {
  visitor->Trace(wrapper_);
}

void SQLTransactionBackend::DoCleanup() {
  if (!frontend_)
    return;
  // Break the reference cycle. See comment about the life-cycle above.
  frontend_ = nullptr;

  DCHECK(GetDatabase()
             ->GetDatabaseContext()
             ->GetDatabaseThread()
             ->IsDatabaseThread());

  base::AutoLock locker(statement_lock_);
  statement_queue_.clear();

  if (sqlite_transaction_) {
    // In the event we got here because of an interruption or error (i.e. if
    // the transaction is in progress), we should roll it back here. Clearing
    // m_sqliteTransaction invokes SQLiteTransaction's destructor which does
    // just that. We might as well do this unconditionally and free up its
    // resources because we're already terminating.
    sqlite_transaction_.reset();
  }

  // Release the lock on this database
  if (lock_acquired_)
    database_->TransactionCoordinator()->ReleaseLock(this);

  // Do some aggresive clean up here except for m_database.
  //
  // We can't clear m_database here because the frontend may asynchronously
  // invoke SQLTransactionBackend::requestTransitToState(), and that function
  // uses m_database to schedule a state transition. This may occur because
  // the frontend (being in another thread) may already be on the way to
  // requesting our next state before it detects an interruption.
  //
  // There is no harm in letting it finish making the request. It'll set
  // m_requestedState, but we won't execute a transition to that state because
  // we've already shut down the transaction.
  //
  // We also can't clear m_currentStatementBackend and m_transactionError.
  // m_currentStatementBackend may be accessed asynchronously by the
  // frontend's deliverStatementCallback() state. Similarly,
  // m_transactionError may be accessed by deliverTransactionErrorCallback().
  // This occurs if requests for transition to those states have already been
  // registered with the frontend just prior to a clean up request arriving.
  //
  // So instead, let our destructor handle their clean up since this
  // SQLTransactionBackend is guaranteed to not destruct until the frontend
  // is also destructing.

  wrapper_ = nullptr;
}

SQLStatement* SQLTransactionBackend::CurrentStatement() {
  return current_statement_backend_->GetFrontend();
}

SQLErrorData* SQLTransactionBackend::TransactionError() {
  return transaction_error_.get();
}

void SQLTransactionBackend::SetShouldRetryCurrentStatement(bool should_retry) {
  DCHECK(!should_retry_current_statement_);
  should_retry_current_statement_ = should_retry;
}

SQLTransactionBackend::StateFunction SQLTransactionBackend::StateFunctionFor(
    SQLTransactionState state) {
  static const StateFunction kStateFunctions[] = {
      &SQLTransactionBackend::UnreachableState,                      // 0. end
      &SQLTransactionBackend::UnreachableState,                      // 1. idle
      &SQLTransactionBackend::AcquireLock,                           // 2.
      &SQLTransactionBackend::OpenTransactionAndPreflight,           // 3.
      &SQLTransactionBackend::RunStatements,                         // 4.
      &SQLTransactionBackend::PostflightAndCommit,                   // 5.
      &SQLTransactionBackend::CleanupAndTerminate,                   // 6.
      &SQLTransactionBackend::CleanupAfterTransactionErrorCallback,  // 7.
      // 8. deliverTransactionCallback
      &SQLTransactionBackend::SendToFrontendState,
      // 9. deliverTransactionErrorCallback
      &SQLTransactionBackend::SendToFrontendState,
      // 10.  deliverStatementCallback
      &SQLTransactionBackend::SendToFrontendState,
      // 11. deliverQuotaIncreaseCallback
      &SQLTransactionBackend::SendToFrontendState,
      // 12. deliverSuccessCallback
      &SQLTransactionBackend::SendToFrontendState,
  };

  DCHECK(std::size(kStateFunctions) ==
         static_cast<int>(SQLTransactionState::kNumberOfStates));
  DCHECK_LT(state, SQLTransactionState::kNumberOfStates);

  return kStateFunctions[static_cast<int>(state)];
}

void SQLTransactionBackend::EnqueueStatementBackend(
    SQLStatementBackend* statement_backend) {
  DCHECK(IsMainThread());
  base::AutoLock locker(statement_lock_);
  statement_queue_.push_back(statement_backend);
}

void SQLTransactionBackend::ComputeNextStateAndCleanupIfNeeded() {
  DCHECK(GetDatabase()
             ->GetDatabaseContext()
             ->GetDatabaseThread()
             ->IsDatabaseThread());
  // Only honor the requested state transition if we're not supposed to be
  // cleaning up and shutting down:
  if (database_->Opened()) {
    SetStateToRequestedState();
    DCHECK(next_state_ == SQLTransactionState::kAcquireLock ||
           next_state_ == SQLTransactionState::kOpenTransactionAndPreflight ||
           next_state_ == SQLTransactionState::kRunStatements ||
           next_state_ == SQLTransactionState::kPostflightAndCommit ||
           next_state_ == SQLTransactionState::kCleanupAndTerminate ||
           next_state_ ==
               SQLTransactionState::kCleanupAfterTransactionErrorCallback);
#if DCHECK_IS_ON()
    STORAGE_DVLOG(1) << "State " << NameForSQLTransactionState(next_state_);
#endif
    return;
  }

  // If we get here, then we should be shutting down. Do clean up if needed:
  if (next_state_ == SQLTransactionState::kEnd)
    return;
  next_state_ = SQLTransactionState::kEnd;

  // If the database was stopped, don't do anything and cancel queued work
  STORAGE_DVLOG(1) << "Database was stopped or interrupted - cancelling work "
                      "for this transaction";

  // The current SQLite transaction should be stopped, as well
  if (sqlite_transaction_) {
    sqlite_transaction_->Stop();
    sqlite_transaction_.reset();
  }

  // Terminate the frontend state machine. This also gets the frontend to
  // call computeNextStateAndCleanupIfNeeded() and clear its wrappers
  // if needed.
  frontend_->RequestTransitToState(SQLTransactionState::kEnd);

  // Redirect to the end state to abort, clean up, and end the transaction.
  DoCleanup();
}

void SQLTransactionBackend::PerformNextStep() {
  ComputeNextStateAndCleanupIfNeeded();
  RunStateMachine();
}

void SQLTransactionBackend::ExecuteSQL(SQLStatement* statement,
                                       const String& sql_statement,
                                       const Vector<SQLValue>& arguments,
                                       int permissions) {
  DCHECK(IsMainThread());
  EnqueueStatementBackend(MakeGarbageCollected<SQLStatementBackend>(
      statement, sql_statement, arguments, permissions));
}

void SQLTransactionBackend::NotifyDatabaseThreadIsShuttingDown() {
  DCHECK(GetDatabase()
             ->GetDatabaseContext()
             ->GetDatabaseThread()
             ->IsDatabaseThread());

  // If the transaction is in progress, we should roll it back here, since this
  // is our last opportunity to do something related to this transaction on the
  // DB thread. Amongst other work, doCleanup() will clear m_sqliteTransaction
  // which invokes SQLiteTransaction's destructor, which will do the roll back
  // if necessary.
  DoCleanup();
}

SQLTransactionState SQLTransactionBackend::AcquireLock() {
  database_->TransactionCoordinator()->AcquireLock(this);
  return SQLTransactionState::kIdle;
}

void SQLTransactionBackend::LockAcquired() {
  lock_acquired_ = true;
  RequestTransitToState(SQLTransactionState::kOpenTransactionAndPreflight);
}

SQLTransactionState SQLTransactionBackend::OpenTransactionAndPreflight() {
  DCHECK(GetDatabase()
             ->GetDatabaseContext()
             ->GetDatabaseThread()
             ->IsDatabaseThread());
  DCHECK(!database_->SqliteDatabase().TransactionInProgress());
  DCHECK(lock_acquired_);

  STORAGE_DVLOG(1) << "Opening and preflighting transaction " << this;

  // Set the maximum usage for this transaction if this transactions is not
  // read-only.
  if (!read_only_)
    database_->SqliteDatabase().SetMaximumSize(database_->MaximumSize());

  DCHECK(!sqlite_transaction_);
  sqlite_transaction_ = std::make_unique<SQLiteTransaction>(
      database_->SqliteDatabase(), read_only_);

  database_->ResetDeletes();
  database_->DisableAuthorizer();
  sqlite_transaction_->begin();
  database_->EnableAuthorizer();

  // Spec 4.3.2.1+2: Open a transaction to the database, jumping to the error
  // callback if that fails.
  if (!sqlite_transaction_->InProgress()) {
    DCHECK(!database_->SqliteDatabase().TransactionInProgress());
    database_->ReportSqliteError(database_->SqliteDatabase().LastError());
    transaction_error_ = SQLErrorData::Create(
        SQLError::kDatabaseErr, "unable to begin transaction",
        database_->SqliteDatabase().LastError(),
        database_->SqliteDatabase().LastErrorMsg());
    sqlite_transaction_.reset();
    return NextStateForTransactionError();
  }

  // Note: We intentionally retrieve the actual version even with an empty
  // expected version.  In multi-process browsers, we take this opportunity to
  // update the cached value for the actual version. In single-process browsers,
  // this is just a map lookup.
  String actual_version;
  if (!database_->GetActualVersionForTransaction(actual_version)) {
    database_->ReportSqliteError(database_->SqliteDatabase().LastError());
    transaction_error_ =
        SQLErrorData::Create(SQLError::kDatabaseErr, "unable to read version",
                             database_->SqliteDatabase().LastError(),
                             database_->SqliteDatabase().LastErrorMsg());
    database_->DisableAuthorizer();
    sqlite_transaction_.reset();
    database_->EnableAuthorizer();
    return NextStateForTransactionError();
  }
  has_version_mismatch_ = !database_->ExpectedVersion().empty() &&
                          (database_->ExpectedVersion() != actual_version);

  // Spec 4.3.2.3: Perform preflight steps, jumping to the error callback if
  // they fail.
  if (wrapper_ && !wrapper_->PerformPreflight(this)) {
    database_->DisableAuthorizer();
    sqlite_transaction_.reset();
    database_->EnableAuthorizer();
    if (wrapper_->SqlError()) {
      transaction_error_ =
          std::make_unique<SQLErrorData>(*wrapper_->SqlError());
    } else {
      transaction_error_ = std::make_unique<SQLErrorData>(
          SQLError::kUnknownErr,
          "unknown error occurred during transaction preflight");
    }
    return NextStateForTransactionError();
  }

  // Spec 4.3.2.4: Invoke the transaction callback with the new SQLTransaction
  // object.
  if (has_callback_)
    return SQLTransactionState::kDeliverTransactionCallback;

  // If we have no callback to make, skip pass to the state after:
  return SQLTransactionState::kRunStatements;
}

SQLTransactionState SQLTransactionBackend::RunStatements() {
  DCHECK(GetDatabase()
             ->GetDatabaseContext()
             ->GetDatabaseThread()
             ->IsDatabaseThread());
  DCHECK(lock_acquired_);
  SQLTransactionState next_state;

  // If there is a series of statements queued up that are all successful and
  // have no associated SQLStatementCallback objects, then we can burn through
  // the queue.
  do {
    if (should_retry_current_statement_ &&
        !sqlite_transaction_->WasRolledBackBySqlite()) {
      should_retry_current_statement_ = false;
      // FIXME - Another place that needs fixing up after
      // <rdar://problem/5628468> is addressed.
      // See ::openTransactionAndPreflight() for discussion

      // Reset the maximum size here, as it was increased to allow us to retry
      // this statement.  m_shouldRetryCurrentStatement is set to true only when
      // a statement exceeds the quota, which can happen only in a read-write
      // transaction.  Therefore, there is no need to check here if the
      // transaction is read-write.
      database_->SqliteDatabase().SetMaximumSize(database_->MaximumSize());
    } else {
      // If the current statement has already been run, failed due to quota
      // constraints, and we're not retrying it, that means it ended in an
      // error. Handle it now.
      if (current_statement_backend_ &&
          current_statement_backend_->LastExecutionFailedDueToQuota()) {
        return NextStateForCurrentStatementError();
      }

      // Otherwise, advance to the next statement
      GetNextStatement();
    }
    next_state = RunCurrentStatementAndGetNextState();
  } while (next_state == SQLTransactionState::kRunStatements);

  return next_state;
}

void SQLTransactionBackend::GetNextStatement() {
  DCHECK(GetDatabase()
             ->GetDatabaseContext()
             ->GetDatabaseThread()
             ->IsDatabaseThread());
  current_statement_backend_ = nullptr;

  base::AutoLock locker(statement_lock_);
  if (!statement_queue_.empty())
    current_statement_backend_ = statement_queue_.TakeFirst();
}

SQLTransactionState
SQLTransactionBackend::RunCurrentStatementAndGetNextState() {
  if (!current_statement_backend_) {
    // No more statements to run. So move on to the next state.
    return SQLTransactionState::kPostflightAndCommit;
  }

  database_->ResetAuthorizer();

  if (has_version_mismatch_)
    current_statement_backend_->SetVersi
```