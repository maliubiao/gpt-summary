Response:
My thought process to arrive at the summary of the provided Go code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code, which is a part of the `database/sql` package's test file (`sql_test.go`). Specifically, it's part 3 of 4.

2. **Scan for Key Components and Actions:** I'll read through the code, looking for the main actors (like `db`, `stmt`, `tx`, `conn`, `rows`) and the actions performed on them (like `Prepare`, `Query`, `Exec`, `Close`, `BeginTx`, `Rollback`, `Commit`, `Ping`, `Conn`). I'll also pay attention to any setup functions (like `newTestDB`, `manyErrBadConnSetup`) and helper functions (like `closeDB`).

3. **Group Related Tests:**  I'll try to group the code into logical blocks based on the functionality being tested. For example, sections dealing with `Stmt` operations, `Tx` operations, connection management, and concurrency.

4. **Identify the Purpose of Each Block:** For each identified block, I'll try to articulate what it's testing. I'll look for assertions (`if err != nil { t.Fatal(err) }`, `if g, w := ...; g != w { ... }`), specific error checks (`errors.Is(err, driver.ErrBadConn)`), and comments (like "// Issue ..."). The "Issue" comments are particularly helpful as they directly state the bug or problem being addressed.

5. **Extract Key Concepts and Scenarios:** Within each test function, I'll note the specific scenarios being tested. For example, in the `TestTxCannotCommitAfterRollback` function, the key scenario is attempting to commit a transaction after it has been rolled back. In `TestConnExpiresFreshOutOfPool`, the scenario is a connection expiring immediately after being retrieved from the pool.

6. **Look for Patterns and Common Themes:**  I'll see if there are recurring themes, such as testing behavior with bad connections (`manyErrBadConnSetup`, simulating broken connections), testing context cancellation, and testing concurrent operations.

7. **Focus on the "Why":**  It's not enough to just say "it tests `stmt.Query`". I need to understand *why* it's testing `stmt.Query`. Is it testing error handling?  Concurrency? Behavior after a connection error?

8. **Consider the Context of `sql_test.go`:**  This file is for testing the `database/sql` package. Therefore, the tests are focused on verifying the correct behavior of the public API of this package, especially how it interacts with underlying database drivers.

9. **Synthesize a Summary:** Based on the above steps, I'll write a concise summary that highlights the main functionalities being tested in this code snippet. I'll use clear and concise language, focusing on the user-facing aspects of the `database/sql` package. I will also mention any specific issues being addressed.

10. **Review and Refine:** I'll reread the summary and the code to ensure accuracy and completeness. I'll check if the summary captures the essence of the code and is easy to understand. I'll make sure the summary addresses the "functionality" aspect of the request.

Applying this process to the provided code leads to the following observations and ultimately the summary:

* **Statement Operations:** Tests involving `stmt.Close()` and `stmt.Query()` after potentially encountering bad connections.
* **Connection Management:** Tests using `db.Conn()` and `db.PingContext()` and handling potential errors.
* **Transaction Behavior:** Several tests focus on transaction lifecycle (`BeginTx`, `Rollback`, `Commit`), including scenarios with context cancellation (`TestTxCannotCommitAfterRollback`, `TestTxStmtDeadlock`), and ensuring proper behavior after rollback.
* **Connection Pooling and Lifetime:** `TestConnExpiresFreshOutOfPool` explicitly deals with connection expiration and how the pool handles it.
* **Concurrency Issues:** Tests like `TestIssue20575` and `TestIssue20622` are about race conditions and proper resource management within transactions. The later parts of the snippet (`TestConcurrency`) explicitly test various database operations concurrently.
* **Bad Connection Handling:**  A significant portion deals with simulating and testing how the `sql` package recovers from bad database connections during various operations (`db.Exec`, `db.Query`, `stmt.Exec`, `stmt.Query`, transaction commit/rollback).
* **Context Cancellation:**  Several tests use `context.WithCancel` and `context.WithTimeout` to simulate scenarios where database operations are interrupted, and the tests verify the correct error handling and resource cleanup.
* **Named Value Check:** The `TestNamedValueChecker` and `TestNamedValueCheckerSkip` sections specifically test the `driver.NamedValueChecker` interface, which allows drivers to inspect and potentially modify or reject named parameters in queries.
* **Connector Interface:** `TestOpenConnector` checks the behavior of the `Connector` interface.
* **Statistics:** Tests like `TestStatsMaxIdleClosedZero` and `TestStatsMaxIdleClosedTen` verify the correctness of the `DBStats` related to closed idle connections.
* **Max Idle Time:** `TestMaxIdleTime` focuses on the `SetConnMaxIdleTime` functionality and how connections are closed based on their idle time.

By identifying these key areas and the purpose of each test, I can then synthesize a concise and informative summary as provided in the initial example. The grouping by functionality (Stmt, Conn, Tx, etc.) makes the summary easier to understand. Highlighting the focus on error handling, concurrency, and specific issues makes the summary more meaningful.
这段代码是 `go/src/database/sql/sql_test.go` 文件的一部分，主要集中在测试 `database/sql` 包中关于 **Statement (Stmt), Connection (Conn), Transaction (Tx)** 以及它们在并发场景下的正确性和健壮性。

以下是更详细的功能归纳：

**1. 测试 Statement 的行为和错误处理:**

*   **`Stmt.Close()`:** 验证关闭 Statement 是否会产生错误。
*   **`Stmt.Query()`:** 测试在 `Stmt` 上执行查询操作，尤其是在数据库连接可能出现错误的情况下，比如 `manyErrBadConnSetup` 模拟多次连接失败的情况。

**2. 测试 Connection 的获取和关闭:**

*   **`db.Conn(ctx)`:**  测试从 `DB` 对象获取 `Conn` 对象，并使用带有取消功能的 `context`，然后验证关闭连接是否会产生错误。
*   **`db.PingContext(ctx)`:** 测试 `PingContext` 方法，用于检查数据库连接是否仍然有效。

**3. 测试 Transaction 的行为和错误处理 (重点):**

*   **`db.BeginTx(ctx, nil)`:** 测试开启事务，并使用带有取消功能的 `context`。
*   **`tx.Rollback()`:**  测试事务回滚操作。
*   **`tx.Commit()`:** （虽然这段代码没有直接的 `tx.Commit()`，但在 `TestTxCannotCommitAfterRollback` 中测试了在 `Rollback` 之后 `Commit` 的行为）。
*   **防止在回滚后提交事务 (`TestTxCannotCommitAfterRollback`)**:  这是一个重要的测试用例，确保事务在被回滚后无法再次提交，防止数据不一致。  它模拟了并发场景，在执行查询的同时取消了上下文，触发事务回滚，然后尝试提交事务，验证是否会失败。
    *   **假设输入:**  一个已经开启但即将被回滚的事务。
    *   **预期输出:**  尝试提交事务会失败。
*   **解决事务语句死锁问题 (`TestTxStmtDeadlock`)**:  测试在高并发取消上下文的情况下，事务中的预处理语句 (`Stmt`) 是否会发生死锁。它创建了一个事务，预处理了一个查询语句，然后立即取消上下文，并在循环中多次执行查询，以复现可能出现的死锁情况。
    *   **假设输入:** 一个已开启事务并预处理了语句，随后上下文被取消。
    *   **预期输出:**  循环执行 `stmt.Query` 会因为上下文取消而报错，但不会发生死锁。

**4. 测试连接池的行为和连接过期 (`TestConnExpiresFreshOutOfPool`)**:

*   测试连接从连接池中取出后，如果恰好过期会发生什么情况。
*   它模拟了连接过期和连接重置失败两种情况，验证在这些情况下获取连接和放回连接的行为是否正确。
    *   **命令行参数:**  虽然代码本身没有直接处理命令行参数，但 `testing.Short()` 会影响测试的并发量和请求次数，这可以被视为一种广义上的命令行控制。

**5. 测试在事务关闭时正确处理未关闭的 Rows (`TestIssue20575`, `TestIssue20622`)**:

*   **`TestIssue20575`:**  确保在事务回滚时，即使 `QueryContext` 返回的 `Rows` 没有被显式关闭，事务也能正确回滚，不会阻塞。
*   **`TestIssue20622`:** 测试在 `Rows` 未关闭的情况下关闭事务是否会导致 race condition（需要 race detector）。

**6. 测试 `ErrBadConn` 的重连机制 (`TestErrBadConnReconnect`)**:

*   模拟在执行 `db.Exec`, `db.Query`, `db.Prepare`, `stmt.Exec`, `stmt.Query` 等操作时遇到 `driver.ErrBadConn` 的情况，验证 `database/sql` 包是否能够正确地重试连接和操作。
*   它通过设置 hook 函数 `hookPrepareBadConn`, `hookExecBadConn`, `hookQueryBadConn` 来模拟连接错误。

**7. 测试事务结束时遇到 `ErrBadConn` 的处理 (`TestTxEndBadConn`)**:

*   模拟在事务 `Commit` 或 `Rollback` 阶段遇到 `driver.ErrBadConn` 的情况，验证是否能正确处理。

**8. 并发测试 (`TestConcurrency` 以及 `concurrent*Test` 结构体和 `doConcurrentTest` 函数):**

*   定义了一系列结构体 (`concurrentDBQueryTest`, `concurrentDBExecTest`, 等) 来表示不同场景下的并发测试用例，包括在 `DB`, `Stmt`, `Tx` 上执行查询和执行操作。
*   `doConcurrentTest` 函数用于执行这些并发测试，它会创建多个 goroutine 并发地执行数据库操作。
*   **假设输入:**  多个并发的数据库操作请求。
*   **预期输出:**  所有操作都能正确完成，没有数据竞争或死锁。

**9. 测试连接泄漏 (`TestConnectionLeak`)**:

*   测试在高并发场景下，连接是否会被正确释放，避免连接泄漏。

**10. 测试连接统计信息 (`TestStatsMaxIdleClosedZero`, `TestStatsMaxIdleClosedTen`)**:

*   测试 `DBStats` 中关于因达到最大空闲时间而被关闭的连接数的统计是否正确。

**11. 测试最大空闲时间 (`TestMaxIdleTime`)**:

*   测试 `SetConnMaxIdleTime` 功能，验证连接在空闲时间超过设定值后是否会被正确关闭。

**12. 测试 `driver.NamedValueChecker` 接口 (`TestNamedValueChecker`, `TestNamedValueCheckerSkip`)**:

*   测试驱动程序实现的 `NamedValueChecker` 接口是否能正确地检查和处理命名的参数。
*   `TestNamedValueChecker` 测试正常情况下的参数检查和处理。
*   `TestNamedValueCheckerSkip` 测试驱动程序可以选择跳过参数检查的情况。

**13. 测试 `OpenConnector` (`TestOpenConnector`)**:

*   测试使用 `Open` 函数打开数据库连接时，是否使用了 `Connector` 接口。

**14. 测试只支持 Context 的 Driver (`TestOpenConnector`)**:

*   测试当 Driver 只实现了带有 Context 的接口（如 `QueryerContext`, `ExecerContext`）时的行为。

**总结这段代码的功能:**

这段代码主要负责测试 `database/sql` 包中关于 **Statement, Connection, Transaction** 的核心功能，特别是关注以下几个方面：

*   **基本操作的正确性:**  例如，`Query`, `Exec`, `Prepare`, `Close`, `BeginTx`, `Rollback` 等操作是否按预期工作。
*   **错误处理:**  特别是当遇到数据库连接错误 (`ErrBadConn`) 或上下文取消时，`database/sql` 包是否能正确处理并尝试恢复。
*   **并发安全性:**  在高并发场景下，`database/sql` 包是否能保证数据的一致性和避免竞态条件和死锁。
*   **连接池管理:**  测试连接的创建、复用、过期和清理机制是否正常工作，防止连接泄漏。
*   **与 Driver 接口的交互:**  测试 `database/sql` 包如何与底层的数据库 Driver 交互，例如通过 `driver.NamedValueChecker` 接口进行参数检查。

总而言之，这段代码是 `database/sql` 包健壮性和正确性的重要保障，覆盖了各种正常和异常场景，以确保开发者可以安全可靠地使用 Go 语言的 `database/sql` 包进行数据库操作。

Prompt: 
```
这是路径为go/src/database/sql/sql_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
err = stmt.Close(); err != nil {
		t.Fatal(err)
	}

	// Stmt.Query
	db = manyErrBadConnSetup(func(db *DB) {
		stmt, err = db.Prepare("SELECT|people|age,name|")
		if err != nil {
			t.Fatal(err)
		}
	})
	defer closeDB(t, db)
	rows, err = stmt.Query()
	if err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err = stmt.Close(); err != nil {
		t.Fatal(err)
	}

	// Conn
	db = manyErrBadConnSetup()
	defer closeDB(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn.dc.ci.(*fakeConn).skipDirtySession = true
	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Ping
	db = manyErrBadConnSetup()
	defer closeDB(t, db)
	err = db.PingContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

// Issue 34775: Ensure that a Tx cannot commit after a rollback.
func TestTxCannotCommitAfterRollback(t *testing.T) {
	db := newTestDB(t, "tx_status")
	defer closeDB(t, db)

	// First check query reporting is correct.
	var txStatus string
	err := db.QueryRow("SELECT|tx_status|tx_status|").Scan(&txStatus)
	if err != nil {
		t.Fatal(err)
	}
	if g, w := txStatus, "autocommit"; g != w {
		t.Fatalf("tx_status=%q, wanted %q", g, w)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Ignore dirty session for this test.
	// A failing test should trigger the dirty session flag as well,
	// but that isn't exactly what this should test for.
	tx.txi.(*fakeTx).c.skipDirtySession = true

	defer tx.Rollback()

	err = tx.QueryRow("SELECT|tx_status|tx_status|").Scan(&txStatus)
	if err != nil {
		t.Fatal(err)
	}
	if g, w := txStatus, "transaction"; g != w {
		t.Fatalf("tx_status=%q, wanted %q", g, w)
	}

	// 1. Begin a transaction.
	// 2. (A) Start a query, (B) begin Tx rollback through a ctx cancel.
	// 3. Check if 2.A has committed in Tx (pass) or outside of Tx (fail).
	sendQuery := make(chan struct{})
	// The Tx status is returned through the row results, ensure
	// that the rows results are not canceled.
	bypassRowsAwaitDone = true
	hookTxGrabConn = func() {
		cancel()
		<-sendQuery
	}
	rollbackHook = func() {
		close(sendQuery)
	}
	defer func() {
		hookTxGrabConn = nil
		rollbackHook = nil
		bypassRowsAwaitDone = false
	}()

	err = tx.QueryRow("SELECT|tx_status|tx_status|").Scan(&txStatus)
	if err != nil {
		// A failure here would be expected if skipDirtySession was not set to true above.
		t.Fatal(err)
	}
	if g, w := txStatus, "transaction"; g != w {
		t.Fatalf("tx_status=%q, wanted %q", g, w)
	}
}

// Issue 40985 transaction statement deadlock while context cancel.
func TestTxStmtDeadlock(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	stmt, err := tx.Prepare("SELECT|people|name,age|age=?")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	// Run number of stmt queries to reproduce deadlock from context cancel
	for i := 0; i < 1e3; i++ {
		// Encounter any close related errors (e.g. ErrTxDone, stmt is closed)
		// is expected due to context cancel.
		_, err = stmt.Query(1)
		if err != nil {
			break
		}
	}
	_ = tx.Rollback()
}

// Issue32530 encounters an issue where a connection may
// expire right after it comes out of a used connection pool
// even when a new connection is requested.
func TestConnExpiresFreshOutOfPool(t *testing.T) {
	execCases := []struct {
		expired  bool
		badReset bool
	}{
		{false, false},
		{true, false},
		{false, true},
	}

	t0 := time.Unix(1000000, 0)
	offset := time.Duration(0)
	offsetMu := sync.RWMutex{}

	nowFunc = func() time.Time {
		offsetMu.RLock()
		defer offsetMu.RUnlock()
		return t0.Add(offset)
	}
	defer func() { nowFunc = time.Now }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db := newTestDB(t, "magicquery")
	defer closeDB(t, db)

	db.SetMaxOpenConns(1)

	for _, ec := range execCases {
		ec := ec
		name := fmt.Sprintf("expired=%t,badReset=%t", ec.expired, ec.badReset)
		t.Run(name, func(t *testing.T) {
			db.clearAllConns(t)

			db.SetMaxIdleConns(1)
			db.SetConnMaxLifetime(10 * time.Second)

			conn, err := db.conn(ctx, alwaysNewConn)
			if err != nil {
				t.Fatal(err)
			}

			afterPutConn := make(chan struct{})
			waitingForConn := make(chan struct{})

			go func() {
				defer close(afterPutConn)

				conn, err := db.conn(ctx, alwaysNewConn)
				if err == nil {
					db.putConn(conn, err, false)
				} else {
					t.Errorf("db.conn: %v", err)
				}
			}()
			go func() {
				defer close(waitingForConn)

				for {
					if t.Failed() {
						return
					}
					db.mu.Lock()
					ct := db.connRequests.Len()
					db.mu.Unlock()
					if ct > 0 {
						return
					}
					time.Sleep(pollDuration)
				}
			}()

			<-waitingForConn

			if t.Failed() {
				return
			}

			offsetMu.Lock()
			if ec.expired {
				offset = 11 * time.Second
			} else {
				offset = time.Duration(0)
			}
			offsetMu.Unlock()

			conn.ci.(*fakeConn).stickyBad = ec.badReset

			db.putConn(conn, err, true)

			<-afterPutConn
		})
	}
}

// TestIssue20575 ensures the Rows from query does not block
// closing a transaction. Ensure Rows is closed while closing a transaction.
func TestIssue20575(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = tx.QueryContext(ctx, "SELECT|people|age,name|")
	if err != nil {
		t.Fatal(err)
	}
	// Do not close Rows from QueryContext.
	err = tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	select {
	default:
	case <-ctx.Done():
		t.Fatal("timeout: failed to rollback query without closing rows:", ctx.Err())
	}
}

// TestIssue20622 tests closing the transaction before rows is closed, requires
// the race detector to fail.
func TestIssue20622(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := tx.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for rows.Next() {
		count++
		var age int
		var name string
		if err := rows.Scan(&age, &name); err != nil {
			t.Fatal("scan failed", err)
		}

		if count == 1 {
			cancel()
		}
		time.Sleep(100 * time.Millisecond)
	}
	rows.Close()
	tx.Commit()
}

// golang.org/issue/5718
func TestErrBadConnReconnect(t *testing.T) {
	db := newTestDB(t, "foo")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")

	simulateBadConn := func(name string, hook *func() bool, op func() error) {
		broken, retried := false, false
		numOpen := db.numOpen

		// simulate a broken connection on the first try
		*hook = func() bool {
			if !broken {
				broken = true
				return true
			}
			retried = true
			return false
		}

		if err := op(); err != nil {
			t.Errorf(name+": %v", err)
			return
		}

		if !broken || !retried {
			t.Error(name + ": Failed to simulate broken connection")
		}
		*hook = nil

		if numOpen != db.numOpen {
			t.Errorf(name+": leaked %d connection(s)!", db.numOpen-numOpen)
			numOpen = db.numOpen
		}
	}

	// db.Exec
	dbExec := func() error {
		_, err := db.Exec("INSERT|t1|name=?,age=?,dead=?", "Gordon", 3, true)
		return err
	}
	simulateBadConn("db.Exec prepare", &hookPrepareBadConn, dbExec)
	simulateBadConn("db.Exec exec", &hookExecBadConn, dbExec)

	// db.Query
	dbQuery := func() error {
		rows, err := db.Query("SELECT|t1|age,name|")
		if err == nil {
			err = rows.Close()
		}
		return err
	}
	simulateBadConn("db.Query prepare", &hookPrepareBadConn, dbQuery)
	simulateBadConn("db.Query query", &hookQueryBadConn, dbQuery)

	// db.Prepare
	simulateBadConn("db.Prepare", &hookPrepareBadConn, func() error {
		stmt, err := db.Prepare("INSERT|t1|name=?,age=?,dead=?")
		if err != nil {
			return err
		}
		stmt.Close()
		return nil
	})

	// Provide a way to force a re-prepare of a statement on next execution
	forcePrepare := func(stmt *Stmt) {
		stmt.css = nil
	}

	// stmt.Exec
	stmt1, err := db.Prepare("INSERT|t1|name=?,age=?,dead=?")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt1.Close()
	// make sure we must prepare the stmt first
	forcePrepare(stmt1)

	stmtExec := func() error {
		_, err := stmt1.Exec("Gopher", 3, false)
		return err
	}
	simulateBadConn("stmt.Exec prepare", &hookPrepareBadConn, stmtExec)
	simulateBadConn("stmt.Exec exec", &hookExecBadConn, stmtExec)

	// stmt.Query
	stmt2, err := db.Prepare("SELECT|t1|age,name|")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt2.Close()
	// make sure we must prepare the stmt first
	forcePrepare(stmt2)

	stmtQuery := func() error {
		rows, err := stmt2.Query()
		if err == nil {
			err = rows.Close()
		}
		return err
	}
	simulateBadConn("stmt.Query prepare", &hookPrepareBadConn, stmtQuery)
	simulateBadConn("stmt.Query exec", &hookQueryBadConn, stmtQuery)
}

// golang.org/issue/11264
func TestTxEndBadConn(t *testing.T) {
	db := newTestDB(t, "foo")
	defer closeDB(t, db)
	db.SetMaxIdleConns(0)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")
	db.SetMaxIdleConns(1)

	simulateBadConn := func(name string, hook *func() bool, op func() error) {
		broken := false
		numOpen := db.numOpen

		*hook = func() bool {
			if !broken {
				broken = true
			}
			return broken
		}

		if err := op(); !errors.Is(err, driver.ErrBadConn) {
			t.Errorf(name+": %v", err)
			return
		}

		if !broken {
			t.Error(name + ": Failed to simulate broken connection")
		}
		*hook = nil

		if numOpen != db.numOpen {
			t.Errorf(name+": leaked %d connection(s)!", db.numOpen-numOpen)
		}
	}

	// db.Exec
	dbExec := func(endTx func(tx *Tx) error) func() error {
		return func() error {
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			_, err = tx.Exec("INSERT|t1|name=?,age=?,dead=?", "Gordon", 3, true)
			if err != nil {
				return err
			}
			return endTx(tx)
		}
	}
	simulateBadConn("db.Tx.Exec commit", &hookCommitBadConn, dbExec((*Tx).Commit))
	simulateBadConn("db.Tx.Exec rollback", &hookRollbackBadConn, dbExec((*Tx).Rollback))

	// db.Query
	dbQuery := func(endTx func(tx *Tx) error) func() error {
		return func() error {
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			rows, err := tx.Query("SELECT|t1|age,name|")
			if err == nil {
				err = rows.Close()
			} else {
				return err
			}
			return endTx(tx)
		}
	}
	simulateBadConn("db.Tx.Query commit", &hookCommitBadConn, dbQuery((*Tx).Commit))
	simulateBadConn("db.Tx.Query rollback", &hookRollbackBadConn, dbQuery((*Tx).Rollback))
}

type concurrentTest interface {
	init(t testing.TB, db *DB)
	finish(t testing.TB)
	test(t testing.TB) error
}

type concurrentDBQueryTest struct {
	db *DB
}

func (c *concurrentDBQueryTest) init(t testing.TB, db *DB) {
	c.db = db
}

func (c *concurrentDBQueryTest) finish(t testing.TB) {
	c.db = nil
}

func (c *concurrentDBQueryTest) test(t testing.TB) error {
	rows, err := c.db.Query("SELECT|people|name|")
	if err != nil {
		t.Error(err)
		return err
	}
	var name string
	for rows.Next() {
		rows.Scan(&name)
	}
	rows.Close()
	return nil
}

type concurrentDBExecTest struct {
	db *DB
}

func (c *concurrentDBExecTest) init(t testing.TB, db *DB) {
	c.db = db
}

func (c *concurrentDBExecTest) finish(t testing.TB) {
	c.db = nil
}

func (c *concurrentDBExecTest) test(t testing.TB) error {
	_, err := c.db.Exec("NOSERT|people|name=Chris,age=?,photo=CPHOTO,bdate=?", 3, chrisBirthday)
	if err != nil {
		t.Error(err)
		return err
	}
	return nil
}

type concurrentStmtQueryTest struct {
	db   *DB
	stmt *Stmt
}

func (c *concurrentStmtQueryTest) init(t testing.TB, db *DB) {
	c.db = db
	var err error
	c.stmt, err = db.Prepare("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
}

func (c *concurrentStmtQueryTest) finish(t testing.TB) {
	if c.stmt != nil {
		c.stmt.Close()
		c.stmt = nil
	}
	c.db = nil
}

func (c *concurrentStmtQueryTest) test(t testing.TB) error {
	rows, err := c.stmt.Query()
	if err != nil {
		t.Errorf("error on query:  %v", err)
		return err
	}

	var name string
	for rows.Next() {
		rows.Scan(&name)
	}
	rows.Close()
	return nil
}

type concurrentStmtExecTest struct {
	db   *DB
	stmt *Stmt
}

func (c *concurrentStmtExecTest) init(t testing.TB, db *DB) {
	c.db = db
	var err error
	c.stmt, err = db.Prepare("NOSERT|people|name=Chris,age=?,photo=CPHOTO,bdate=?")
	if err != nil {
		t.Fatal(err)
	}
}

func (c *concurrentStmtExecTest) finish(t testing.TB) {
	if c.stmt != nil {
		c.stmt.Close()
		c.stmt = nil
	}
	c.db = nil
}

func (c *concurrentStmtExecTest) test(t testing.TB) error {
	_, err := c.stmt.Exec(3, chrisBirthday)
	if err != nil {
		t.Errorf("error on exec:  %v", err)
		return err
	}
	return nil
}

type concurrentTxQueryTest struct {
	db *DB
	tx *Tx
}

func (c *concurrentTxQueryTest) init(t testing.TB, db *DB) {
	c.db = db
	var err error
	c.tx, err = c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
}

func (c *concurrentTxQueryTest) finish(t testing.TB) {
	if c.tx != nil {
		c.tx.Rollback()
		c.tx = nil
	}
	c.db = nil
}

func (c *concurrentTxQueryTest) test(t testing.TB) error {
	rows, err := c.db.Query("SELECT|people|name|")
	if err != nil {
		t.Error(err)
		return err
	}
	var name string
	for rows.Next() {
		rows.Scan(&name)
	}
	rows.Close()
	return nil
}

type concurrentTxExecTest struct {
	db *DB
	tx *Tx
}

func (c *concurrentTxExecTest) init(t testing.TB, db *DB) {
	c.db = db
	var err error
	c.tx, err = c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
}

func (c *concurrentTxExecTest) finish(t testing.TB) {
	if c.tx != nil {
		c.tx.Rollback()
		c.tx = nil
	}
	c.db = nil
}

func (c *concurrentTxExecTest) test(t testing.TB) error {
	_, err := c.tx.Exec("NOSERT|people|name=Chris,age=?,photo=CPHOTO,bdate=?", 3, chrisBirthday)
	if err != nil {
		t.Error(err)
		return err
	}
	return nil
}

type concurrentTxStmtQueryTest struct {
	db   *DB
	tx   *Tx
	stmt *Stmt
}

func (c *concurrentTxStmtQueryTest) init(t testing.TB, db *DB) {
	c.db = db
	var err error
	c.tx, err = c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	c.stmt, err = c.tx.Prepare("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
}

func (c *concurrentTxStmtQueryTest) finish(t testing.TB) {
	if c.stmt != nil {
		c.stmt.Close()
		c.stmt = nil
	}
	if c.tx != nil {
		c.tx.Rollback()
		c.tx = nil
	}
	c.db = nil
}

func (c *concurrentTxStmtQueryTest) test(t testing.TB) error {
	rows, err := c.stmt.Query()
	if err != nil {
		t.Errorf("error on query:  %v", err)
		return err
	}

	var name string
	for rows.Next() {
		rows.Scan(&name)
	}
	rows.Close()
	return nil
}

type concurrentTxStmtExecTest struct {
	db   *DB
	tx   *Tx
	stmt *Stmt
}

func (c *concurrentTxStmtExecTest) init(t testing.TB, db *DB) {
	c.db = db
	var err error
	c.tx, err = c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	c.stmt, err = c.tx.Prepare("NOSERT|people|name=Chris,age=?,photo=CPHOTO,bdate=?")
	if err != nil {
		t.Fatal(err)
	}
}

func (c *concurrentTxStmtExecTest) finish(t testing.TB) {
	if c.stmt != nil {
		c.stmt.Close()
		c.stmt = nil
	}
	if c.tx != nil {
		c.tx.Rollback()
		c.tx = nil
	}
	c.db = nil
}

func (c *concurrentTxStmtExecTest) test(t testing.TB) error {
	_, err := c.stmt.Exec(3, chrisBirthday)
	if err != nil {
		t.Errorf("error on exec:  %v", err)
		return err
	}
	return nil
}

type concurrentRandomTest struct {
	tests []concurrentTest
}

func (c *concurrentRandomTest) init(t testing.TB, db *DB) {
	c.tests = []concurrentTest{
		new(concurrentDBQueryTest),
		new(concurrentDBExecTest),
		new(concurrentStmtQueryTest),
		new(concurrentStmtExecTest),
		new(concurrentTxQueryTest),
		new(concurrentTxExecTest),
		new(concurrentTxStmtQueryTest),
		new(concurrentTxStmtExecTest),
	}
	for _, ct := range c.tests {
		ct.init(t, db)
	}
}

func (c *concurrentRandomTest) finish(t testing.TB) {
	for _, ct := range c.tests {
		ct.finish(t)
	}
}

func (c *concurrentRandomTest) test(t testing.TB) error {
	ct := c.tests[rand.Intn(len(c.tests))]
	return ct.test(t)
}

func doConcurrentTest(t testing.TB, ct concurrentTest) {
	maxProcs, numReqs := 1, 500
	if testing.Short() {
		maxProcs, numReqs = 4, 50
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(maxProcs))

	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ct.init(t, db)
	defer ct.finish(t)

	var wg sync.WaitGroup
	wg.Add(numReqs)

	reqs := make(chan bool)
	defer close(reqs)

	for i := 0; i < maxProcs*2; i++ {
		go func() {
			for range reqs {
				err := ct.test(t)
				if err != nil {
					wg.Done()
					continue
				}
				wg.Done()
			}
		}()
	}

	for i := 0; i < numReqs; i++ {
		reqs <- true
	}

	wg.Wait()
}

func TestIssue6081(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	drv := db.Driver().(*fakeDriver)
	drv.mu.Lock()
	opens0 := drv.openCount
	closes0 := drv.closeCount
	drv.mu.Unlock()

	stmt, err := db.Prepare("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	setRowsCloseHook(func(rows *Rows, err *error) {
		*err = driver.ErrBadConn
	})
	defer setRowsCloseHook(nil)
	for i := 0; i < 10; i++ {
		rows, err := stmt.Query()
		if err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	if n := len(stmt.css); n > 1 {
		t.Errorf("len(css slice) = %d; want <= 1", n)
	}
	stmt.Close()
	if n := len(stmt.css); n != 0 {
		t.Errorf("len(css slice) after Close = %d; want 0", n)
	}

	drv.mu.Lock()
	opens := drv.openCount - opens0
	closes := drv.closeCount - closes0
	drv.mu.Unlock()
	if opens < 9 {
		t.Errorf("opens = %d; want >= 9", opens)
	}
	if closes < 9 {
		t.Errorf("closes = %d; want >= 9", closes)
	}
}

// TestIssue18429 attempts to stress rolling back the transaction from a
// context cancel while simultaneously calling Tx.Rollback. Rolling back from a
// context happens concurrently so tx.rollback and tx.Commit must guard against
// double entry.
//
// In the test, a context is canceled while the query is in process so
// the internal rollback will run concurrently with the explicitly called
// Tx.Rollback.
//
// The addition of calling rows.Next also tests
// Issue 21117.
func TestIssue18429(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx := context.Background()
	sem := make(chan bool, 20)
	var wg sync.WaitGroup

	const milliWait = 30

	for i := 0; i < 100; i++ {
		sem <- true
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			qwait := (time.Duration(rand.Intn(milliWait)) * time.Millisecond).String()

			ctx, cancel := context.WithTimeout(ctx, time.Duration(rand.Intn(milliWait))*time.Millisecond)
			defer cancel()

			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return
			}
			// This is expected to give a cancel error most, but not all the time.
			// Test failure will happen with a panic or other race condition being
			// reported.
			rows, _ := tx.QueryContext(ctx, "WAIT|"+qwait+"|SELECT|people|name|")
			if rows != nil {
				var name string
				// Call Next to test Issue 21117 and check for races.
				for rows.Next() {
					// Scan the buffer so it is read and checked for races.
					rows.Scan(&name)
				}
				rows.Close()
			}
			// This call will race with the context cancel rollback to complete
			// if the rollback itself isn't guarded.
			tx.Rollback()
		}()
	}
	wg.Wait()
}

// TestIssue20160 attempts to test a short context life on a stmt Query.
func TestIssue20160(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx := context.Background()
	sem := make(chan bool, 20)
	var wg sync.WaitGroup

	const milliWait = 30

	stmt, err := db.PrepareContext(ctx, "SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()

	for i := 0; i < 100; i++ {
		sem <- true
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			ctx, cancel := context.WithTimeout(ctx, time.Duration(rand.Intn(milliWait))*time.Millisecond)
			defer cancel()

			// This is expected to give a cancel error most, but not all the time.
			// Test failure will happen with a panic or other race condition being
			// reported.
			rows, _ := stmt.QueryContext(ctx)
			if rows != nil {
				rows.Close()
			}
		}()
	}
	wg.Wait()
}

// TestIssue18719 closes the context right before use. The sql.driverConn
// will nil out the ci on close in a lock, but if another process uses it right after
// it will panic with on the nil ref.
//
// See https://golang.org/cl/35550 .
func TestIssue18719(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	hookTxGrabConn = func() {
		cancel()

		// Wait for the context to cancel and tx to rollback.
		for !tx.isDone() {
			time.Sleep(pollDuration)
		}
	}
	defer func() { hookTxGrabConn = nil }()

	// This call will grab the connection and cancel the context
	// after it has done so. Code after must deal with the canceled state.
	_, err = tx.QueryContext(ctx, "SELECT|people|name|")
	if err != nil {
		t.Fatalf("expected error %v but got %v", nil, err)
	}

	// Rows may be ignored because it will be closed when the context is canceled.

	// Do not explicitly rollback. The rollback will happen from the
	// canceled context.

	cancel()
}

func TestIssue20647(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn.dc.ci.(*fakeConn).skipDirtySession = true
	defer conn.Close()

	stmt, err := conn.PrepareContext(ctx, "SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()

	rows1, err := stmt.QueryContext(ctx)
	if err != nil {
		t.Fatal("rows1", err)
	}
	defer rows1.Close()

	rows2, err := stmt.QueryContext(ctx)
	if err != nil {
		t.Fatal("rows2", err)
	}
	defer rows2.Close()

	if rows1.dc != rows2.dc {
		t.Fatal("stmt prepared on Conn does not use same connection")
	}
}

func TestConcurrency(t *testing.T) {
	list := []struct {
		name string
		ct   concurrentTest
	}{
		{"Query", new(concurrentDBQueryTest)},
		{"Exec", new(concurrentDBExecTest)},
		{"StmtQuery", new(concurrentStmtQueryTest)},
		{"StmtExec", new(concurrentStmtExecTest)},
		{"TxQuery", new(concurrentTxQueryTest)},
		{"TxExec", new(concurrentTxExecTest)},
		{"TxStmtQuery", new(concurrentTxStmtQueryTest)},
		{"TxStmtExec", new(concurrentTxStmtExecTest)},
		{"Random", new(concurrentRandomTest)},
	}
	for _, item := range list {
		t.Run(item.name, func(t *testing.T) {
			doConcurrentTest(t, item.ct)
		})
	}
}

func TestConnectionLeak(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	// Start by opening defaultMaxIdleConns
	rows := make([]*Rows, defaultMaxIdleConns)
	// We need to SetMaxOpenConns > MaxIdleConns, so the DB can open
	// a new connection and we can fill the idle queue with the released
	// connections.
	db.SetMaxOpenConns(len(rows) + 1)
	for ii := range rows {
		r, err := db.Query("SELECT|people|name|")
		if err != nil {
			t.Fatal(err)
		}
		r.Next()
		if err := r.Err(); err != nil {
			t.Fatal(err)
		}
		rows[ii] = r
	}
	// Now we have defaultMaxIdleConns busy connections. Open
	// a new one, but wait until the busy connections are released
	// before returning control to DB.
	drv := db.Driver().(*fakeDriver)
	drv.waitCh = make(chan struct{}, 1)
	drv.waitingCh = make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		r, err := db.Query("SELECT|people|name|")
		if err != nil {
			t.Error(err)
			return
		}
		r.Close()
		wg.Done()
	}()
	// Wait until the goroutine we've just created has started waiting.
	<-drv.waitingCh
	// Now close the busy connections. This provides a connection for
	// the blocked goroutine and then fills up the idle queue.
	for _, v := range rows {
		v.Close()
	}
	// At this point we give the new connection to DB. This connection is
	// now useless, since the idle queue is full and there are no pending
	// requests. DB should deal with this situation without leaking the
	// connection.
	drv.waitCh <- struct{}{}
	wg.Wait()
}

func TestStatsMaxIdleClosedZero(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	preMaxIdleClosed := db.Stats().MaxIdleClosed

	for i := 0; i < 10; i++ {
		rows, err := db.Query("SELECT|people|name|")
		if err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}

	st := db.Stats()
	maxIdleClosed := st.MaxIdleClosed - preMaxIdleClosed
	t.Logf("MaxIdleClosed: %d", maxIdleClosed)
	if maxIdleClosed != 0 {
		t.Fatal("expected 0 max idle closed conns, got: ", maxIdleClosed)
	}
}

func TestStatsMaxIdleClosedTen(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	db.SetConnMaxLifetime(0)

	preMaxIdleClosed := db.Stats().MaxIdleClosed

	for i := 0; i < 10; i++ {
		rows, err := db.Query("SELECT|people|name|")
		if err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}

	st := db.Stats()
	maxIdleClosed := st.MaxIdleClosed - preMaxIdleClosed
	t.Logf("MaxIdleClosed: %d", maxIdleClosed)
	if maxIdleClosed != 10 {
		t.Fatal("expected 0 max idle closed conns, got: ", maxIdleClosed)
	}
}

// testUseConns uses count concurrent connections with 1 nanosecond apart.
// Returns the returnedAt time of the final connection.
func testUseConns(t *testing.T, count int, tm time.Time, db *DB) time.Time {
	conns := make([]*Conn, count)
	ctx := context.Background()
	for i := range conns {
		tm = tm.Add(time.Nanosecond)
		nowFunc = func() time.Time {
			return tm
		}
		c, err := db.Conn(ctx)
		if err != nil {
			t.Error(err)
		}
		conns[i] = c
	}

	for i := len(conns) - 1; i >= 0; i-- {
		tm = tm.Add(time.Nanosecond)
		nowFunc = func() time.Time {
			return tm
		}
		if err := conns[i].Close(); err != nil {
			t.Error(err)
		}
	}

	return tm
}

func TestMaxIdleTime(t *testing.T) {
	usedConns := 5
	reusedConns := 2
	list := []struct {
		wantMaxIdleTime   time.Duration
		wantMaxLifetime   time.Duration
		wantNextCheck     time.Duration
		wantIdleClosed    int64
		wantMaxIdleClosed int64
		timeOffset        time.Duration
		secondTimeOffset  time.Duration
	}{
		{
			time.Millisecond,
			0,
			time.Millisecond - time.Nanosecond,
			int64(usedConns - reusedConns),
			int64(usedConns - reusedConns),
			10 * time.Millisecond,
			0,
		},
		{
			// Want to close some connections via max idle time and one by max lifetime.
			time.Millisecond,
			// nowFunc() - MaxLifetime should be 1 * time.Nanosecond in connectionCleanerRunLocked.
			// This guarantees that first opened connection is to be closed.
			// Thus it is timeOffset + secondTimeOffset + 3 (+2 for Close while reusing conns and +1 for Conn).
			10*time.Millisecond + 100*time.Nanosecond + 3*time.Nanosecond,
			time.Nanosecond,
			// Closed all not reused connections and extra one by max lifetime.
			int64(usedConns - reusedConns + 1),
			int64(usedConns - reusedConns),
			10 * time.Millisecond,
			// Add second offset because otherwise connections are expired via max lifetime in Close.
			100 * time.Nanosecond,
		},
		{
			time.Hour,
			0,
			time.Second,
			0,
			0,
			10 * time.Millisecond,
			0},
	}
	baseTime := time.Unix(0, 0)
	defer func() {
		nowFunc = time.Now
	}()
	for _, item := range list {
		nowFunc = func() time.Time {
			return baseTime
		}
		t.Run(fmt.Sprintf("%v", item.wantMaxIdleTime), func(t *testing.T) {
			db := newTestDB(t, "people")
			defer closeDB(t, db)

			db.SetMaxOpenConns(usedConns)
			db.SetMaxIdleConns(usedConns)
			db.SetConnMaxIdleTime(item.wantMaxIdleTime)
			db.SetConnMaxLifetime(item.wantMaxLifetime)

			preMaxIdleClosed := db.Stats().MaxIdleTimeClosed

			// Busy usedConns.
			testUseConns(t, usedConns, baseTime, db)

			tm := baseTime.Add(item.timeOffset)

			// Reuse connections which should never be considered idle
			// and exercises the sorting for issue 39471.
			tm = testUseConns(t, reusedConns, tm, db)

			tm = tm.Add(item.secondTimeOffset)
			nowFunc = func() time.Time {
				return tm
			}

			db.mu.Lock()
			nc, closing := db.connectionCleanerRunLocked(time.Second)
			if nc != item.wantNextCheck {
				t.Errorf("got %v; want %v next check duration", nc, item.wantNextCheck)
			}

			// Validate freeConn order.
			var last time.Time
			for _, c := range db.freeConn {
				if last.After(c.returnedAt) {
					t.Error("freeConn is not ordered by returnedAt")
					break
				}
				last = c.returnedAt
			}

			db.mu.Unlock()
			for _, c := range closing {
				c.Close()
			}
			if g, w := int64(len(closing)), item.wantIdleClosed; g != w {
				t.Errorf("got: %d; want %d closed conns", g, w)
			}

			st := db.Stats()
			maxIdleClosed := st.MaxIdleTimeClosed - preMaxIdleClosed
			if g, w := maxIdleClosed, item.wantMaxIdleClosed; g != w {
				t.Errorf("got: %d; want %d max idle closed conns", g, w)
			}
		})
	}
}

type nvcDriver struct {
	fakeDriver
	skipNamedValueCheck bool
}

func (d *nvcDriver) Open(dsn string) (driver.Conn, error) {
	c, err := d.fakeDriver.Open(dsn)
	fc := c.(*fakeConn)
	fc.db.allowAny = true
	return &nvcConn{fc, d.skipNamedValueCheck}, err
}

type nvcConn struct {
	*fakeConn
	skipNamedValueCheck bool
}

type decimalInt struct {
	value int
}

type doNotInclude struct{}

var _ driver.NamedValueChecker = &nvcConn{}

func (c *nvcConn) CheckNamedValue(nv *driver.NamedValue) error {
	if c.skipNamedValueCheck {
		return driver.ErrSkip
	}
	switch v := nv.Value.(type) {
	default:
		return driver.ErrSkip
	case Out:
		switch ov := v.Dest.(type) {
		default:
			return errors.New("unknown NameValueCheck OUTPUT type")
		case *string:
			*ov = "from-server"
			nv.Value = "OUT:*string"
		}
		return nil
	case decimalInt, []int64:
		return nil
	case doNotInclude:
		return driver.ErrRemoveArgument
	}
}

func TestNamedValueChecker(t *testing.T) {
	Register("NamedValueCheck", &nvcDriver{})
	db, err := Open("NamedValueCheck", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err = db.ExecContext(ctx, "WIPE")
	if err != nil {
		t.Fatal("exec wipe", err)
	}

	_, err = db.ExecContext(ctx, "CREATE|keys|dec1=any,str1=string,out1=string,array1=any")
	if err != nil {
		t.Fatal("exec create", err)
	}

	o1 := ""
	_, err = db.ExecContext(ctx, "INSERT|keys|dec1=?A,str1=?,out1=?O1,array1=?", Named("A", decimalInt{123}), "hello", Named("O1", Out{Dest: &o1}), []int64{42, 128, 707}, doNotInclude{})
	if err != nil {
		t.Fatal("exec insert", err)
	}
	var (
		str1 string
		dec1 decimalInt
		arr1 []int64
	)
	err = db.QueryRowContext(ctx, "SELECT|keys|dec1,str1,array1|").Scan(&dec1, &str1, &arr1)
	if err != nil {
		t.Fatal("select", err)
	}

	list := []struct{ got, want any }{
		{o1, "from-server"},
		{dec1, decimalInt{123}},
		{str1, "hello"},
		{arr1, []int64{42, 128, 707}},
	}

	for index, item := range list {
		if !reflect.DeepEqual(item.got, item.want) {
			t.Errorf("got %#v wanted %#v for index %d", item.got, item.want, index)
		}
	}
}

func TestNamedValueCheckerSkip(t *testing.T) {
	Register("NamedValueCheckSkip", &nvcDriver{skipNamedValueCheck: true})
	db, err := Open("NamedValueCheckSkip", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err = db.ExecContext(ctx, "WIPE")
	if err != nil {
		t.Fatal("exec wipe", err)
	}

	_, err = db.ExecContext(ctx, "CREATE|keys|dec1=any")
	if err != nil {
		t.Fatal("exec create", err)
	}

	_, err = db.ExecContext(ctx, "INSERT|keys|dec1=?A", Named("A", decimalInt{123}))
	if err == nil {
		t.Fatalf("expected error with bad argument, got %v", err)
	}
}

func TestOpenConnector(t *testing.T) {
	Register("testctx", &fakeDriverCtx{})
	db, err := Open("testctx", "people")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	c, ok := db.connector.(*fakeConnector)
	if !ok {
		t.Fatal("not using *fakeConnector")
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if !c.closed {
		t.Fatal("connector is not closed")
	}
}

type ctxOnlyDriver struct {
	fakeDriver
}

func (d *ctxOnlyDriver) Open(dsn string) (driver.Conn, error) {
	conn, err := d.fakeDriver.Open(dsn)
	if err != nil {
		return nil, err
	}
	return &ctxOnlyConn{fc: conn.(*fakeConn)}, nil
}

var (
	_ driver.Conn           = &ctxOnlyConn{}
	_ driver.QueryerContext = &ctxOnlyConn{}
	_ driver.ExecerContext  = &ctxOnlyConn{}
)

type ctxOnlyConn struct {
	fc *fakeConn

	queryCtxCalled bool
	execCtxCalled  bool
}

func (c *ctxOnlyConn) Begin() (driver.Tx, error) {
	return c.fc.Begin()
}

func (c *ctxOnlyConn)
"""




```