Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `sql_test.go` file in the `database/sql` package. This snippet seems to cover various aspects of database interactions, especially focusing on error handling, concurrency, and edge cases.

Here's a breakdown of the thought process to achieve the requested summary:

1. **Identify the Core Functionality:**  The code deals with testing different functionalities of the `database/sql` package. The names of the test functions (e.g., `TestStmtClose`, `TestTxCannotCommitAfterRollback`, `TestConnExpiresFreshOutOfPool`) are excellent clues.

2. **Categorize the Tests:** Group similar tests together to create a more structured summary. Obvious categories emerge:
    * Statement operations (`Stmt.Close`, `Stmt.Query`)
    * Connection management (`Conn`, `Ping`, connection expiration)
    * Transaction handling (committing, rolling back, deadlocks)
    * Concurrency testing (various combinations of DB, Stmt, and Tx operations)
    * Error handling (bad connections, context cancellation)
    * Specific issue reproductions (using `Issue` in the test name)
    * Performance benchmarking.

3. **Summarize Each Category:**  For each category, briefly describe what the tests are validating.

4. **Highlight Key Go Features:**  Note which Go language features are being tested or demonstrated. This includes:
    * Context usage (`context.WithCancel`, `context.WithTimeout`, `PingContext`)
    * Concurrency primitives (`sync.WaitGroup`, `chan`, `runtime.GOMAXPROCS`)
    * Error handling (`errors.Is`, `driver.ErrBadConn`)
    * Time manipulation (`time.Sleep`, `time.Duration`, custom `nowFunc`).
    * Reflection (`reflect.DeepEqual`).
    * Benchmarking (`testing.B`).

5. **Explain Code Examples (where applicable):**  For more complex or illustrative tests, provide simplified Go code snippets that demonstrate the functionality being tested. This is especially relevant for understanding how different methods on `DB`, `Tx`, and `Stmt` are used. Include potential input and output to clarify the example.

6. **Address Potential Pitfalls:** Based on the test cases, identify common mistakes users might make when interacting with the `database/sql` package. For instance, forgetting to close `Rows` or attempting to commit after a rollback are good examples.

7. **Summarize Overall Functionality:** Combine the category summaries into a concise overview of what the code snippet achieves.

8. **Review and Refine:**  Read through the entire summary to ensure accuracy, clarity, and completeness. Check for any redundancy or areas that could be explained more effectively. Make sure the language is consistent and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Just list the individual test function names and briefly describe them.
* **Correction:** This would be too granular and lack a higher-level understanding. Grouping the tests by functionality makes the summary more useful.
* **Initial thought:** Focus only on the `database/sql` API.
* **Correction:**  Recognize the importance of highlighting the Go language features being used within the tests, as this provides context and shows how these features interact with database operations.
* **Initial thought:**  Provide very detailed code examples for every test.
* **Correction:**  Focus on the core idea of each test with simplified examples. Too much detail would make the summary overwhelming. Only provide code examples where it significantly clarifies the functionality.
* **Initial thought:** Not explicitly mention the "Part 2" nature of the input.
* **Correction:**  Include this information in the final summary to provide context.

By following these steps and iteratively refining the summary, a comprehensive and informative response can be generated.
这是 Go 语言标准库 `database/sql` 包中 `sql_test.go` 文件的一部分，主要用于测试 `database/sql` 包提供的各种数据库操作功能。这是第 2 部分，因此我们需要在前一部分的基础上继续归纳其功能。

**归纳其功能：**

这部分代码延续了上一部分的功能，继续对 `database/sql` 包的各种功能进行细致的测试，尤其侧重于以下几个方面：

1. **语句（Stmt）操作的测试:**
   - 测试 `Stmt.Close()` 的功能，确保语句可以正确关闭。
   - 测试在存在多个错误连接的情况下，`Stmt.Query()` 的行为，模拟连接故障时的处理。

2. **连接（Conn）操作的测试:**
   - 测试 `db.Conn()` 方法获取连接的功能，并测试连接的 `Close()` 方法。
   - 测试在连接上设置跳过脏会话标志 (`skipDirtySession`) 的行为。
   - 测试 `db.PingContext()` 方法，验证数据库连接的连通性。

3. **事务（Tx）操作的深入测试:**
   - **事务状态的验证:** 测试在事务的不同阶段（自动提交、事务中）查询事务状态是否正确。
   - **回滚后禁止提交:** 重点测试在事务回滚 (`Rollback`) 后，是否无法再次提交 (`Commit`)，以确保事务的一致性。
   - **上下文取消时的事务行为:** 测试在事务执行过程中，通过上下文取消 (`context.Cancel`) 来触发回滚的情况，并验证事务是否正确回滚。
   - **事务语句的死锁问题:**  模拟在事务中使用预处理语句 (`Prepare`) 并通过上下文取消来测试可能出现的死锁情况。

4. **连接池管理和连接生命周期的测试:**
   - **连接从连接池中取出后立即过期的问题:**  模拟连接在刚从连接池取出后就因为过期而失效的情况，并验证 `database/sql` 包的处理机制。
   - **`ConnMaxLifetime` 和 `ConnMaxIdleTime` 的测试:**  测试连接的最大生存时间和最大空闲时间设置对连接回收的影响，并验证相关的统计信息是否正确。

5. **并发场景下的测试:**
   - 提供了多种并发测试用例 (`concurrentDBQueryTest`, `concurrentDBExecTest` 等)，模拟多个 goroutine 并发执行数据库操作（查询、执行、事务操作等），以验证 `database/sql` 包在并发环境下的稳定性和正确性。
   - 使用 `doConcurrentTest` 函数来执行这些并发测试，并设置了 `GOMAXPROCS` 来控制并发度。
   - 引入随机并发测试 (`concurrentRandomTest`)，随机选择不同的数据库操作进行并发测试，增加测试覆盖率。

6. **错误处理和连接重连机制的测试:**
   - **模拟连接错误 (`driver.ErrBadConn`) 的场景:**  通过设置 hook 函数（如 `hookPrepareBadConn`, `hookExecBadConn`）来模拟连接在不同阶段发生错误，并验证 `database/sql` 包是否能够正确地重连。
   - **测试事务结束时遇到坏连接的处理:** 模拟在事务提交或回滚时连接断开的情况，验证 `database/sql` 包的错误处理。

7. **特定 Issue 的复现和修复验证:**
   - 包含了针对特定 issue 的测试用例，例如 `TestIssue34775`, `TestIssue40985`, `TestIssue32530` 等，用于验证这些 issue 是否已得到修复。这些测试用例通常会模拟导致 issue 发生的特定场景。

8. **与 `context` 包的集成测试:**
   - 大量使用了 `context` 包，测试在各种数据库操作中使用 `context` 进行超时控制、取消操作等的行为。

9. **驱动程序接口的测试:**
   - 测试了自定义的驱动程序 (`nvcDriver`, `ctxOnlyDriver`, `badDriver`, `pingDriver`) 与 `database/sql` 包的交互，例如 `driver.NamedValueChecker`, `driver.QueryerContext`, `driver.ExecerContext`, `driver.Pinger` 等接口的实现。

10. **RawBytes 的使用和测试:**
    - 测试了 `RawBytes` 类型在 `Scan` 操作中的行为，特别关注了在上下文取消时以及跨查询复用 `RawBytes` 时的内存管理和数据一致性问题。

11. **错误包装的测试:**
    - 验证了 `Rows.Scan` 以及 `Stmt.Exec` 和 `Stmt.Query` 在底层驱动返回错误时是否正确地包装了这些错误，以便用户可以使用 `errors.Is` 等方法进行判断。

12. **性能基准测试:**
    - 提供了一些基准测试 (`BenchmarkConcurrentDBExec`, `BenchmarkConcurrentStmtQuery` 等)，用于评估并发场景下不同数据库操作的性能。

**总结来说，这部分代码主要关注于 `database/sql` 包在更复杂和边缘场景下的行为，包括错误处理、并发控制、连接管理和与 `context` 包的集成。它通过大量的测试用例，力求保证 `database/sql` 包的健壮性和可靠性。**

### 提示词
```
这是路径为go/src/database/sql/sql_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
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

func (c *ctxOnlyConn) Close() error {
	return c.fc.Close()
}

// Prepare is still part of the Conn interface, so while it isn't used
// must be defined for compatibility.
func (c *ctxOnlyConn) Prepare(q string) (driver.Stmt, error) {
	panic("not used")
}

func (c *ctxOnlyConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.fc.PrepareContext(ctx, q)
}

func (c *ctxOnlyConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.queryCtxCalled = true
	return c.fc.QueryContext(ctx, q, args)
}

func (c *ctxOnlyConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.execCtxCalled = true
	return c.fc.ExecContext(ctx, q, args)
}

// TestQueryExecContextOnly ensures drivers only need to implement QueryContext
// and ExecContext methods.
func TestQueryExecContextOnly(t *testing.T) {
	// Ensure connection does not implement non-context interfaces.
	var connType driver.Conn = &ctxOnlyConn{}
	if _, ok := connType.(driver.Execer); ok {
		t.Fatalf("%T must not implement driver.Execer", connType)
	}
	if _, ok := connType.(driver.Queryer); ok {
		t.Fatalf("%T must not implement driver.Queryer", connType)
	}

	Register("ContextOnly", &ctxOnlyDriver{})
	db, err := Open("ContextOnly", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal("db.Conn", err)
	}
	defer conn.Close()
	coc := conn.dc.ci.(*ctxOnlyConn)
	coc.fc.skipDirtySession = true

	_, err = conn.ExecContext(ctx, "WIPE")
	if err != nil {
		t.Fatal("exec wipe", err)
	}

	_, err = conn.ExecContext(ctx, "CREATE|keys|v1=string")
	if err != nil {
		t.Fatal("exec create", err)
	}
	expectedValue := "value1"
	_, err = conn.ExecContext(ctx, "INSERT|keys|v1=?", expectedValue)
	if err != nil {
		t.Fatal("exec insert", err)
	}
	rows, err := conn.QueryContext(ctx, "SELECT|keys|v1|")
	if err != nil {
		t.Fatal("query select", err)
	}
	v1 := ""
	for rows.Next() {
		err = rows.Scan(&v1)
		if err != nil {
			t.Fatal("rows scan", err)
		}
	}
	rows.Close()

	if v1 != expectedValue {
		t.Fatalf("expected %q, got %q", expectedValue, v1)
	}

	if !coc.execCtxCalled {
		t.Error("ExecContext not called")
	}
	if !coc.queryCtxCalled {
		t.Error("QueryContext not called")
	}
}

type alwaysErrScanner struct{}

var errTestScanWrap = errors.New("errTestScanWrap")

func (alwaysErrScanner) Scan(any) error {
	return errTestScanWrap
}

// Issue 38099: Ensure that Rows.Scan properly wraps underlying errors.
func TestRowsScanProperlyWrapsErrors(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	rows, err := db.Query("SELECT|people|age|")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	var res alwaysErrScanner

	for rows.Next() {
		err = rows.Scan(&res)
		if err == nil {
			t.Fatal("expecting back an error")
		}
		if !errors.Is(err, errTestScanWrap) {
			t.Fatalf("errors.Is mismatch\n%v\nWant: %v", err, errTestScanWrap)
		}
		// Ensure that error substring matching still correctly works.
		if !strings.Contains(err.Error(), errTestScanWrap.Error()) {
			t.Fatalf("Error %v does not contain %v", err, errTestScanWrap)
		}
	}
}

type alwaysErrValuer struct{}

// errEmpty is returned when an empty value is found
var errEmpty = errors.New("empty value")

func (v alwaysErrValuer) Value() (driver.Value, error) {
	return nil, errEmpty
}

// Issue 64707: Ensure that Stmt.Exec and Stmt.Query properly wraps underlying errors.
func TestDriverArgsWrapsErrors(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	t.Run("exec", func(t *testing.T) {
		_, err := db.Exec("INSERT|keys|dec1=?", alwaysErrValuer{})
		if err == nil {
			t.Fatal("expecting back an error")
		}
		if !errors.Is(err, errEmpty) {
			t.Fatalf("errors.Is mismatch\n%v\nWant: %v", err, errEmpty)
		}
		// Ensure that error substring matching still correctly works.
		if !strings.Contains(err.Error(), errEmpty.Error()) {
			t.Fatalf("Error %v does not contain %v", err, errEmpty)
		}
	})

	t.Run("query", func(t *testing.T) {
		_, err := db.Query("INSERT|keys|dec1=?", alwaysErrValuer{})
		if err == nil {
			t.Fatal("expecting back an error")
		}
		if !errors.Is(err, errEmpty) {
			t.Fatalf("errors.Is mismatch\n%v\nWant: %v", err, errEmpty)
		}
		// Ensure that error substring matching still correctly works.
		if !strings.Contains(err.Error(), errEmpty.Error()) {
			t.Fatalf("Error %v does not contain %v", err, errEmpty)
		}
	})
}

func TestContextCancelDuringRawBytesScan(t *testing.T) {
	for _, mode := range []string{"nocancel", "top", "bottom", "go"} {
		t.Run(mode, func(t *testing.T) {
			testContextCancelDuringRawBytesScan(t, mode)
		})
	}
}

// From go.dev/issue/60304
func testContextCancelDuringRawBytesScan(t *testing.T, mode string) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	if _, err := db.Exec("USE_RAWBYTES"); err != nil {
		t.Fatal(err)
	}

	// cancel used to call close asynchronously.
	// This test checks that it waits so as not to interfere with RawBytes.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r, err := db.QueryContext(ctx, "SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	numRows := 0
	var sink byte
	for r.Next() {
		if mode == "top" && numRows == 2 {
			// cancel between Next and Scan is observed by Scan as err = context.Canceled.
			// The sleep here is only to make it more likely that the cancel will be observed.
			// If not, the test should still pass, like in "go" mode.
			cancel()
			time.Sleep(100 * time.Millisecond)
		}
		numRows++
		var s RawBytes
		err = r.Scan(&s)
		if numRows == 3 && err == context.Canceled {
			if r.closemuScanHold {
				t.Errorf("expected closemu NOT to be held")
			}
			break
		}
		if !r.closemuScanHold {
			t.Errorf("expected closemu to be held")
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("read %q", s)
		if mode == "bottom" && numRows == 2 {
			// cancel before Next should be observed by Next, exiting the loop.
			// The sleep here is only to make it more likely that the cancel will be observed.
			// If not, the test should still pass, like in "go" mode.
			cancel()
			time.Sleep(100 * time.Millisecond)
		}
		if mode == "go" && numRows == 2 {
			// cancel at any future time, to catch other cases
			go cancel()
		}
		for _, b := range s { // some operation reading from the raw memory
			sink += b
		}
	}
	if r.closemuScanHold {
		t.Errorf("closemu held; should not be")
	}

	// There are 3 rows. We canceled after reading 2 so we expect either
	// 2 or 3 depending on how the awaitDone goroutine schedules.
	switch numRows {
	case 0, 1:
		t.Errorf("got %d rows; want 2+", numRows)
	case 2:
		if err := r.Err(); err != context.Canceled {
			t.Errorf("unexpected error: %v (%T)", err, err)
		}
	default:
		// Made it to the end. This is rare, but fine. Permit it.
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestContextCancelBetweenNextAndErr(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r, err := db.QueryContext(ctx, "SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
	}
	cancel()                          // wake up the awaitDone goroutine
	time.Sleep(10 * time.Millisecond) // increase odds of seeing failure
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestNilErrorAfterClose(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	// This WithCancel is important; Rows contains an optimization to avoid
	// spawning a goroutine when the query/transaction context cannot be
	// canceled, but this test tests a bug which is caused by said goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r, err := db.QueryContext(ctx, "SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond) // increase odds of seeing failure
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}
}

// Issue #65201.
//
// If a RawBytes is reused across multiple queries,
// subsequent queries shouldn't overwrite driver-owned memory from previous queries.
func TestRawBytesReuse(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	if _, err := db.Exec("USE_RAWBYTES"); err != nil {
		t.Fatal(err)
	}

	var raw RawBytes

	// The RawBytes in this query aliases driver-owned memory.
	rows, err := db.Query("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	rows.Next()
	rows.Scan(&raw) // now raw is pointing to driver-owned memory
	name1 := string(raw)
	rows.Close()

	// The RawBytes in this query does not alias driver-owned memory.
	rows, err = db.Query("SELECT|people|age|")
	if err != nil {
		t.Fatal(err)
	}
	rows.Next()
	rows.Scan(&raw) // this must not write to the driver-owned memory in raw
	rows.Close()

	// Repeat the first query. Nothing should have changed.
	rows, err = db.Query("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	rows.Next()
	rows.Scan(&raw) // raw points to driver-owned memory again
	name2 := string(raw)
	rows.Close()
	if name1 != name2 {
		t.Fatalf("Scan read name %q, want %q", name2, name1)
	}
}

// badConn implements a bad driver.Conn, for TestBadDriver.
// The Exec method panics.
type badConn struct{}

func (bc badConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("badConn Prepare")
}

func (bc badConn) Close() error {
	return nil
}

func (bc badConn) Begin() (driver.Tx, error) {
	return nil, errors.New("badConn Begin")
}

func (bc badConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	panic("badConn.Exec")
}

// badDriver is a driver.Driver that uses badConn.
type badDriver struct{}

func (bd badDriver) Open(name string) (driver.Conn, error) {
	return badConn{}, nil
}

// Issue 15901.
func TestBadDriver(t *testing.T) {
	Register("bad", badDriver{})
	db, err := Open("bad", "ignored")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		} else {
			if want := "badConn.Exec"; r.(string) != want {
				t.Errorf("panic was %v, expected %v", r, want)
			}
		}
	}()
	defer db.Close()
	db.Exec("ignored")
}

type pingDriver struct {
	fails bool
}

type pingConn struct {
	badConn
	driver *pingDriver
}

var pingError = errors.New("Ping failed")

func (pc pingConn) Ping(ctx context.Context) error {
	if pc.driver.fails {
		return pingError
	}
	return nil
}

var _ driver.Pinger = pingConn{}

func (pd *pingDriver) Open(name string) (driver.Conn, error) {
	return pingConn{driver: pd}, nil
}

func TestPing(t *testing.T) {
	driver := &pingDriver{}
	Register("ping", driver)

	db, err := Open("ping", "ignored")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		t.Errorf("err was %#v, expected nil", err)
		return
	}

	driver.fails = true
	if err := db.Ping(); err != pingError {
		t.Errorf("err was %#v, expected pingError", err)
	}
}

// Issue 18101.
func TestTypedString(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	type Str string
	var scanned Str

	err := db.QueryRow("SELECT|people|name|name=?", "Alice").Scan(&scanned)
	if err != nil {
		t.Fatal(err)
	}
	expected := Str("Alice")
	if scanned != expected {
		t.Errorf("expected %+v, got %+v", expected, scanned)
	}
}

func BenchmarkConcurrentDBExec(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentDBExecTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkConcurrentStmtQuery(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentStmtQueryTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkConcurrentStmtExec(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentStmtExecTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkConcurrentTxQuery(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentTxQueryTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkConcurrentTxExec(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentTxExecTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkConcurrentTxStmtQuery(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentTxStmtQueryTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkConcurrentTxStmtExec(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentTxStmtExecTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkConcurrentRandom(b *testing.B) {
	b.ReportAllocs()
	ct := new(concurrentRandomTest)
	for i := 0; i < b.N; i++ {
		doConcurrentTest(b, ct)
	}
}

func BenchmarkManyConcurrentQueries(b *testing.B) {
	b.ReportAllocs()
	// To see lock contention in Go 1.4, 16~ cores and 128~ goroutines are required.
	const parallelism = 16

	db := newTestDB(b, "magicquery")
	defer closeDB(b, db)
	db.SetMaxIdleConns(runtime.GOMAXPROCS(0) * parallelism)

	stmt, err := db.Prepare("SELECT|magicquery|op|op=?,millis=?")
	if err != nil {
		b.Fatal(err)
	}
	defer stmt.Close()

	b.SetParallelism(parallelism)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rows, err := stmt.Query("sleep", 1)
			if err != nil {
				b.Error(err)
				return
			}
			rows.Close()
		}
	})
}

func TestGrabConnAllocs(t *testing.T) {
	testenv.SkipIfOptimizationOff(t)
	if race.Enabled {
		t.Skip("skipping allocation test when using race detector")
	}
	c := new(Conn)
	ctx := context.Background()
	n := int(testing.AllocsPerRun(1000, func() {
		_, release, err := c.grabConn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		release(nil)
	}))
	if n > 0 {
		t.Fatalf("Conn.grabConn allocated %v objects; want 0", n)
	}
}

func BenchmarkGrabConn(b *testing.B) {
	b.ReportAllocs()
	c := new(Conn)
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		_, release, err := c.grabConn(ctx)
		if err != nil {
			b.Fatal(err)
		}
		release(nil)
	}
}

func TestConnRequestSet(t *testing.T) {
	var s connRequestSet
	wantLen := func(want int) {
		t.Helper()
		if got := s.Len(); got != want {
			t.Errorf("Len = %d; want %d", got, want)
		}
		if want == 0 && !t.Failed() {
			if _, ok := s.TakeRandom(); ok {
				t.Fatalf("TakeRandom returned result when empty")
			}
		}
	}
	reset := func() { s = connRequestSet{} }

	t.Run("add-delete", func(t *testing.T) {
		reset()
		wantLen(0)
		dh := s.Add(nil)
		wantLen(1)
		if !s.Delete(dh) {
			t.Fatal("failed to delete")
		}
		wantLen(0)
		if s.Delete(dh) {
			t.Error("delete worked twice")
		}
		wantLen(0)
	})
	t.Run("take-before-delete", func(t *testing.T) {
		reset()
		ch1 := make(chan connRequest)
		dh := s.Add(ch1)
		wantLen(1)
		if got, ok := s.TakeRandom(); !ok || got != ch1 {
			t.Fatalf("wrong take; ok=%v", ok)
		}
		wantLen(0)
		if s.Delete(dh) {
			t.Error("unexpected delete after take")
		}
	})
	t.Run("get-take-many", func(t *testing.T) {
		reset()
		m := map[chan connRequest]bool{}
		const N = 100
		var inOrder, backOut []chan connRequest
		for range N {
			c := make(chan connRequest)
			m[c] = true
			s.Add(c)
			inOrder = append(inOrder, c)
		}
		if s.Len() != N {
			t.Fatalf("Len = %v; want %v", s.Len(), N)
		}
		for s.Len() > 0 {
			c, ok := s.TakeRandom()
			if !ok {
				t.Fatal("failed to take when non-empty")
			}
			if !m[c] {
				t.Fatal("returned item not in remaining set")
			}
			delete(m, c)
			backOut = append(backOut, c)
		}
		if len(m) > 0 {
			t.Error("items remain in expected map")
		}
		if slices.Equal(inOrder, backOut) { // N! chance of flaking; N=100 is fine
			t.Error("wasn't random")
		}
	})
	t.Run("close-delete", func(t *testing.T) {
		reset()
		ch := make(chan connRequest)
		dh := s.Add(ch)
		wantLen(1)
		s.CloseAndRemoveAll()
		wantLen(0)
		if s.Delete(dh) {
			t.Error("unexpected delete after CloseAndRemoveAll")
		}
	})
}

func BenchmarkConnRequestSet(b *testing.B) {
	var s connRequestSet
	for range b.N {
		for range 16 {
			s.Add(nil)
		}
		for range 8 {
			if _, ok := s.TakeRandom(); !ok {
				b.Fatal("want ok")
			}
		}
		for range 8 {
			s.Add(nil)
		}
		for range 16 {
			if _, ok := s.TakeRandom(); !ok {
				b.Fatal("want ok")
			}
		}
		if _, ok := s.TakeRandom(); ok {
			b.Fatal("unexpected ok")
		}
	}
}

func TestIssue69837(t *testing.T) {
	u := Null[uint]{V: 1, Valid: true}
	val, err := driver.DefaultParameterConverter.ConvertValue(u)
	if err != nil {
		t.Errorf("ConvertValue() error = %v, want nil", err)
	}

	if v, ok := val.(int64); !ok {
		t.Errorf("val.(type): got %T, expected int64", val)
	} else if v != 1 {
		t.Errorf("val: got %d, expected 1", v)
	}
}

type issue69728Type struct {
	ID   int
	Name string
}

func (t issue69728Type) Value() (driver.Value, error) {
	return []byte(fmt.Sprintf("%d, %s", t.ID, t.Name)), nil
}

func TestIssue69728(t *testing.T) {
	forValue := Null[issue69728Type]{
		Valid: true,
		V: issue69728Type{
			ID:   42,
			Name: "foobar",
		},
	}

	v1, err := forValue.Value()
	if err != nil {
		t.Errorf("forValue.Value() error = %v, want nil", err)
	}

	v2, err := forValue.V.Value()
	if err != nil {
		t.Errorf("forValue.V.Value() error = %v, want nil", err)
	}

	if !reflect.DeepEqual(v1, v2) {
		t.Errorf("not equal; v1 = %v, v2 = %v", v1, v2)
	}
}
```