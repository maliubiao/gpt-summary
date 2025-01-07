Response:
Let's break down the thought process for analyzing the provided Go code snippet from `go/src/database/sql/sql_test.go`.

1. **Understanding the Goal:** The core request is to understand the *functionality* of this specific part of the test file. This means identifying what aspects of the `database/sql` package it's testing.

2. **Initial Scan and Identification of Key Elements:**  A quick skim reveals familiar testing patterns: `testing.T`, `newTestDB`, `defer closeDB`, and various `Test...` functions. This immediately tells us it's a unit test file. The `package sql` declaration confirms it's testing the `database/sql` package itself.

3. **`init()` Function Analysis:** The `init()` function stands out. It uses a mutex and maps to track freed connections. The comments strongly suggest this is for detecting double frees of database connections, a critical resource management issue. The `putConnHook` variable being set within `init` is a key clue.

4. **Helper Functions Examination:**  Functions like `newTestDB`, `newTestDBConnector`, `exec`, and `closeDB` are clearly helper functions for setting up and tearing down test environments. The database schemas created in `newTestDBConnector` (`people`, `magicquery`, `tx_status`) provide hints about the types of database operations being tested.

5. **Individual Test Function Analysis (Iterative Process):**

   * **`TestOpenDB`:**  Simple test to verify `OpenDB` returns the correct driver.
   * **`TestDriverPanic`:**  Crucial for testing the library's resilience to driver panics. It checks for deadlocks and proper error handling when the underlying driver misbehaves. The `expectPanic` helper confirms this.
   * **`exec`:** A small helper to simplify executing SQL and checking for errors.
   * **`closeDB`:**  Handles closing the database and performs checks for leaked statements. The `setHookpostCloseConn` is interesting – it suggests the ability to hook into the connection closing process for testing.
   * **`numPrepares`, `numDeps`, `numFreeConns`, `numOpenConns`, `clearAllConns`, `dumpDeps`, `dumpDep`:** These are utility functions to inspect the internal state of the `DB` object, particularly concerning connections and dependencies. This is common in thorough testing.
   * **`TestQuery`:**  A fundamental test for basic SQL query functionality. It checks data retrieval and verifies that the connection is closed after use.
   * **`TestQueryContext`:** Tests context cancellation during query execution, a vital feature for managing long-running operations.
   * **`waitCondition`, `waitForFree`, `waitForRowsClose`:**  Helper functions for asynchronous testing, waiting for specific conditions to be met within a timeout.
   * **`TestQueryContextWait`:** Specifically tests context cancellation during the `Prepare` phase, showing a more in-depth look at context handling.
   * **`TestTxContextWait`, `TestTxContextWaitNoDiscard`, `testContextWait`:** These focus on transaction context cancellation, with variations for rollback behavior.
   * **`TestUnsupportedOptions`:** Tests the handling of unsupported transaction options.
   * **`TestMultiResultSetQuery`:** Checks support for queries returning multiple result sets.
   * **`TestQueryNamedArg`:** Tests the use of named arguments in queries.
   * **`TestPoolExhaustOnCancel`:** A more complex test involving connection pool exhaustion and context cancellation under load.
   * **`TestRowsColumns`, `TestRowsColumnTypes`:**  Tests retrieving column information from `Rows`.
   * **`TestQueryRow`:** Tests the `QueryRow` method for retrieving single rows.
   * **`TestRowErr`:** Specifically tests error handling with `QueryRow` and context cancellation.
   * **`TestTxRollbackCommitErr`:** Tests the behavior of `Rollback` and `Commit` on transactions.
   * **`TestStatementErrorAfterClose`:** Verifies errors when using a closed statement.
   * **`TestStatementQueryRow`:** Tests `QueryRow` with prepared statements.
   * **`TestStatementClose`:**  Tests error propagation from the underlying driver when closing a statement.
   * **`TestStatementQueryRowConcurrent`:** Tests concurrent use of `QueryRow` with a prepared statement.
   * **`TestBogusPreboundParameters`:** Tests how invalid parameter conversions are handled in prepared statements.
   * **`TestExec`:** Tests the `Exec` method for executing SQL statements.
   * **`TestTxPrepare`, `TestTxStmt`, `TestTxStmtPreparedOnce`, `TestTxStmtClosedRePrepares`, `TestParentStmtOutlivesTxStmt`, `TestTxStmtFromTxStmtRePrepares`:** A series of tests focusing on prepared statements and transactions, exploring their interactions and lifecycle.
   * **`TestTxQuery`, `TestTxQueryInvalid`:** Tests querying within a transaction, including error cases.
   * **`TestTxErrBadConn`:** Tests transaction handling when the connection is bad.
   * **`TestConnQuery`, `TestConnRaw`, `TestCursorFake`, `TestInvalidNilValues`, `TestConnTx`, `TestConnIsValid`:** These tests cover operations on `Conn` objects, including raw access, cursors (in the fake driver context), handling of nil values, and connection validity.
   * **`TestIssue2542Deadlock`:** A specific test to prevent a known deadlock scenario.
   * **`TestCloseStmtBeforeRows`:** Tests the order of closing statements and rows.
   * **`TestNullByteSlice`, `TestPointerParamsAndScans`:** Tests handling of null values and pointers in parameters and scans.
   * **`TestQueryRowClosingStmt`:** Checks if `QueryRow` properly closes statements.
   * **`TestIssue6651`:** Tests error handling during row iteration and closing.
   * **`TestNullStringParam` through `TestNullTimeParam`, `nullTestRun`:** Comprehensive tests for handling various `sql.Null...` types as parameters and scan destinations.
   * **`TestQueryRowNilScanDest`:** Tests error handling when scanning into a nil pointer.
   * **`TestIssue4902`:**  Focuses on connection reuse with prepared statements.
   * **`TestSimultaneousQueries`:** Tests concurrent queries within a transaction.
   * **`TestMaxIdleConns`, `TestMaxOpenConns`, `TestMaxOpenConnsOnBusy`, `TestPendingConnsAfterErr`, `TestSingleOpenConn`, `TestStats`, `TestConnMaxLifetime`, `TestStmtCloseDeps`, `TestCloseConnBeforeStmts`, `TestRowsCloseOrder`, `TestRowsImplicitClose`, `TestRowsCloseError`, `TestStmtCloseOrder`, `TestManyErrBadConn`,  `TestIssue4902` (again, likely a copy-paste error), `TestSimultaneousQueries` (again), `TestMaxIdleConns` (again), `TestMaxOpenConns` (again), `TestMaxOpenConnsOnBusy` (again), `TestPendingConnsAfterErr` (again), `TestSingleOpenConn` (again), `TestStats` (again), `TestConnMaxLifetime` (again), `TestStmtCloseDeps` (again), `TestCloseConnBeforeStmts` (again), `TestRowsCloseOrder` (again), `TestRowsImplicitClose` (again), `TestRowsCloseError` (again), `TestStmtCloseOrder` (again), `TestManyErrBadConn` (again):**  These test various aspects of connection pooling, including maximum idle connections, maximum open connections, connection lifetime, and handling of bad connections. The repetitions likely indicate the extent of connection management testing.

6. **Identifying the Core Functionality Tested:** Based on the analysis of individual test functions, the code primarily focuses on testing the following aspects of the `database/sql` package:

   * **Basic Querying and Execution:**  Verifying `Query`, `QueryRow`, and `Exec` for basic SQL operations.
   * **Prepared Statements:** Testing `Prepare`, `Stmt.QueryRow`, `Stmt.Exec`, and the lifecycle of prepared statements, including closing and re-preparing.
   * **Transactions:**  Testing `Begin`, `Commit`, `Rollback`, and interactions between transactions and statements (`Tx.Stmt`).
   * **Connection Management:**  Comprehensive testing of connection pooling, including `SetMaxIdleConns`, `SetMaxOpenConns`, `SetConnMaxLifetime`, and how the library handles bad connections.
   * **Context Handling:** Testing the use of `context.Context` for timeouts and cancellations in queries, executions, and transactions.
   * **Error Handling:**  Verifying how the library handles errors from the driver (including panics), incorrect SQL, and closed connections/statements.
   * **Null Values:**  Testing how `sql.Null...` types are handled as parameters and scan destinations.
   * **Concurrency:**  Testing concurrent access to the database and prepared statements.
   * **Connection Objects:**  Testing operations directly on `Conn` objects, including `Raw` access.
   * **Result Sets (`Rows`):**  Testing iteration, scanning, closing, and error handling with `Rows`.
   * **Metadata:** Testing retrieval of column names and types.

7. **Synthesizing the Summary:** Finally, we consolidate the identified functionalities into a concise summary, highlighting the key areas covered by the provided code snippet. Emphasize that it's a unit test file specifically designed to rigorously test the `database/sql` package.这段Go语言代码是 `database/sql` 包的一部分，专门用于对 `database/sql` 包进行单元测试。它涵盖了 `sql` 包中多种核心功能的测试用例。以下是这段代码的主要功能归纳：

**主要功能归纳:**

这段代码主要用于测试 `database/sql` 包提供的与数据库操作相关的核心功能，包括但不限于：

* **数据库连接和管理:** 测试数据库的打开、关闭，连接池的管理（最大空闲连接数、最大打开连接数、连接的最大生命周期）。
* **基本的SQL操作:** 测试 `Query`（查询多行数据）、`QueryRow`（查询单行数据）、`Exec`（执行SQL命令，如INSERT、UPDATE、DELETE）等基本SQL操作的正确性。
* **预处理语句 (Prepared Statements):** 测试 `Prepare` 方法创建预处理语句，以及预处理语句的执行、关闭，以及在事务中的使用。
* **事务 (Transactions):** 测试事务的开始 (`Begin`)、提交 (`Commit`)、回滚 (`Rollback`) 操作，以及在事务中执行查询和命令。
* **上下文 (Context):** 测试如何使用 `context.Context` 来控制数据库操作的生命周期，例如设置超时、取消操作。
* **错误处理:** 测试各种错误场景下的处理，例如驱动程序 panic、SQL 错误、连接错误等。
* **结果集 (Rows):** 测试结果集的遍历 (`Next`)、数据扫描 (`Scan`)、关闭 (`Close`) 以及错误处理。
* **命名参数:** 测试在查询中使用命名参数的功能。
* **Null 值处理:** 测试如何处理数据库中的 NULL 值，以及 `sql.NullString`、`sql.NullInt64` 等类型的正确使用。
* **并发安全:** 测试在并发场景下使用 `database/sql` 的安全性。
* **驱动程序集成:**  通过使用一个简单的 `fakeConnector` 和 `fakeDriver` 来模拟实际的数据库驱动，从而测试 `database/sql` 包与驱动程序的交互。

**更详细的功能点:**

1. **连接池管理测试:**  测试了 `SetMaxIdleConns` 和 `SetMaxOpenConns` 方法对连接池行为的影响，例如连接的创建、复用和释放。
2. **连接生命周期测试:**  测试了 `SetConnMaxLifetime` 方法，验证了连接在达到最大生命周期后会被正确关闭和重新创建。
3. **驱动程序 Panic 恢复测试:** 确保当底层的数据库驱动程序发生 panic 时，`database/sql` 包能够正确捕获并避免死锁。
4. **事务的各种场景测试:**  包括在事务中执行查询、执行命令，以及测试事务的提交和回滚操作，以及在事务中使用预处理语句。
5. **上下文控制的测试:**  验证了使用 `context.Context` 可以正确地取消或超时数据库操作。
6. **结果集的正确关闭:**  确保在查询完成后，结果集和相关的数据库连接能够被正确关闭，防止资源泄露。
7. **预处理语句在事务中的行为:**  测试了在事务中创建的预处理语句的生命周期和行为。
8. **空值 (NULL) 的处理:**  测试了如何将 `sql.NullString`、`sql.NullInt64` 等类型作为参数传递给 SQL 查询，以及如何从数据库中扫描 NULL 值到这些类型。
9. **并发查询测试:**  模拟了多个并发的查询操作，以验证 `database/sql` 的并发安全性。

**Go 代码示例说明功能:**

**1. 测试基本的 Query 操作:**

```go
func TestQueryExample(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	rows, err := db.Query("SELECT|people|name,age|") // 假设 people 表有 name 和 age 列
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var age int
		if err := rows.Scan(&name, &age); err != nil {
			t.Fatalf("Scan failed: %v", err)
		}
		// 验证查询结果
		t.Logf("Name: %s, Age: %d", name, age)
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("Rows error: %v", err)
	}
}
```

**假设输入与输出:**

* **假设输入:**  `people` 表中存在数据，例如：`{name: "Alice", age: 30}`, `{name: "Bob", age: 25}`。
* **预期输出:**  `t.Logf` 会输出类似 `Name: Alice, Age: 30` 和 `Name: Bob, Age: 25` 的日志。

**2. 测试预处理语句 (Prepared Statement):**

```go
func TestPrepareExample(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	stmt, err := db.Prepare("SELECT|people|age|name=?") // 预处理查询特定名字的人的年龄
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	defer stmt.Close()

	var age int
	err = stmt.QueryRow("Alice").Scan(&age) // 查询 Alice 的年龄
	if err != nil {
		t.Fatalf("QueryRow failed: %v", err)
	}
	t.Logf("Alice's age: %d", age)

	err = stmt.QueryRow("Bob").Scan(&age) // 查询 Bob 的年龄
	if err != nil {
		t.Fatalf("QueryRow failed: %v", err)
	}
	t.Logf("Bob's age: %d", age)
}
```

**假设输入与输出:**

* **假设输入:** `people` 表中存在 `name` 为 "Alice" 和 "Bob" 的记录，对应的 `age` 分别为 30 和 25。
* **预期输出:** `t.Logf` 会输出类似 `Alice's age: 30` 和 `Bob's age: 25` 的日志。

**3. 测试事务 (Transaction):**

```go
func TestTransactionExample(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	defer tx.Rollback() // 确保在测试失败时回滚

	_, err = tx.Exec("INSERT|people|name=?,age=?", "Charlie", 28)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}

	var count int
	err = tx.QueryRow("SELECT count(*) FROM people WHERE name=?", "Charlie").Scan(&count)
	if err != nil {
		t.Fatalf("QueryRow failed: %v", err)
	}
	t.Logf("Number of Charlies: %d", count)

	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// 验证数据是否已提交
	err = db.QueryRow("SELECT count(*) FROM people WHERE name=?", "Charlie").Scan(&count)
	if err != nil {
		t.Fatalf("QueryRow after commit failed: %v", err)
	}
	t.Logf("Number of Charlies after commit: %d", count)
}
```

**假设输入与输出:**

* **假设输入:** `people` 表初始状态可能没有 "Charlie" 的记录。
* **预期输出:**  `t.Logf` 会先输出类似 `Number of Charlies: 1`（在事务中插入后），然后输出类似 `Number of Charlies after commit: 1`（事务提交后）。

**命令行参数的具体处理:**

这段代码本身是单元测试代码，通常不涉及直接处理命令行参数。它依赖于 Go 的 `testing` 包提供的功能来运行测试。你可以使用 `go test` 命令来运行这些测试。例如：

```bash
go test -v ./go/src/database/sql
```

`-v` 参数表示输出更详细的测试信息。

**使用者易犯错的点:**

在实际使用 `database/sql` 包时，使用者容易犯以下错误，而这些错误也可能是这段测试代码覆盖的场景：

1. **忘记关闭 `Rows` 或 `Stmt`:**  这会导致数据库连接无法及时释放，最终可能导致连接池耗尽。
   ```go
   // 错误示例：忘记关闭 Rows
   rows, _ := db.Query("SELECT * FROM users")
   // ... 使用 rows，但忘记 rows.Close()
   ```

2. **在事务中使用完 `Stmt` 后忘记关闭:** 事务中的 `Stmt` 需要在事务结束前关闭。
   ```go
   tx, _ := db.Begin()
   stmt, _ := tx.Prepare("INSERT INTO users (...) VALUES (...)")
   // ... 使用 stmt
   // 错误示例：忘记 stmt.Close()
   tx.Commit()
   ```

3. **不正确地处理 `error`:**  忽略数据库操作返回的错误可能导致程序行为不符合预期甚至崩溃。
   ```go
   _, err := db.Exec("INSERT ...")
   // 错误示例：没有检查 err
   ```

4. **在高并发场景下不合理地配置连接池:**  例如，`MaxIdleConns` 和 `MaxOpenConns` 的配置不当可能导致性能问题或连接耗尽。

5. **没有正确使用 `context.Context` 进行超时控制:**  对于可能耗时较长的数据库操作，没有设置超时可能导致程序长时间阻塞。

这段测试代码通过模拟各种场景，帮助开发者理解和避免这些常见的错误。

Prompt: 
```
这是路径为go/src/database/sql/sql_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sql

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"internal/race"
	"internal/testenv"
	"math/rand"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	type dbConn struct {
		db *DB
		c  *driverConn
	}
	freedFrom := make(map[dbConn]string)
	var mu sync.Mutex
	getFreedFrom := func(c dbConn) string {
		mu.Lock()
		defer mu.Unlock()
		return freedFrom[c]
	}
	setFreedFrom := func(c dbConn, s string) {
		mu.Lock()
		defer mu.Unlock()
		freedFrom[c] = s
	}
	putConnHook = func(db *DB, c *driverConn) {
		if slices.Contains(db.freeConn, c) {
			// print before panic, as panic may get lost due to conflicting panic
			// (all goroutines asleep) elsewhere, since we might not unlock
			// the mutex in freeConn here.
			println("double free of conn. conflicts are:\nA) " + getFreedFrom(dbConn{db, c}) + "\n\nand\nB) " + stack())
			panic("double free of conn.")
		}
		setFreedFrom(dbConn{db, c}, stack())
	}
}

// pollDuration is an arbitrary interval to wait between checks when polling for
// a condition to occur.
const pollDuration = 5 * time.Millisecond

const fakeDBName = "foo"

var chrisBirthday = time.Unix(123456789, 0)

func newTestDB(t testing.TB, name string) *DB {
	return newTestDBConnector(t, &fakeConnector{name: fakeDBName}, name)
}

func newTestDBConnector(t testing.TB, fc *fakeConnector, name string) *DB {
	fc.name = fakeDBName
	db := OpenDB(fc)
	if _, err := db.Exec("WIPE"); err != nil {
		t.Fatalf("exec wipe: %v", err)
	}
	if name == "people" {
		exec(t, db, "CREATE|people|name=string,age=int32,photo=blob,dead=bool,bdate=datetime")
		exec(t, db, "INSERT|people|name=Alice,age=?,photo=APHOTO", 1)
		exec(t, db, "INSERT|people|name=Bob,age=?,photo=BPHOTO", 2)
		exec(t, db, "INSERT|people|name=Chris,age=?,photo=CPHOTO,bdate=?", 3, chrisBirthday)
	}
	if name == "magicquery" {
		// Magic table name and column, known by fakedb_test.go.
		exec(t, db, "CREATE|magicquery|op=string,millis=int32")
		exec(t, db, "INSERT|magicquery|op=sleep,millis=10")
	}
	if name == "tx_status" {
		// Magic table name and column, known by fakedb_test.go.
		exec(t, db, "CREATE|tx_status|tx_status=string")
		exec(t, db, "INSERT|tx_status|tx_status=invalid")
	}
	return db
}

func TestOpenDB(t *testing.T) {
	db := OpenDB(dsnConnector{dsn: fakeDBName, driver: fdriver})
	if db.Driver() != fdriver {
		t.Fatalf("OpenDB should return the driver of the Connector")
	}
}

func TestDriverPanic(t *testing.T) {
	// Test that if driver panics, database/sql does not deadlock.
	db, err := Open("test", fakeDBName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	expectPanic := func(name string, f func()) {
		defer func() {
			err := recover()
			if err == nil {
				t.Fatalf("%s did not panic", name)
			}
		}()
		f()
	}

	expectPanic("Exec Exec", func() { db.Exec("PANIC|Exec|WIPE") })
	exec(t, db, "WIPE") // check not deadlocked
	expectPanic("Exec NumInput", func() { db.Exec("PANIC|NumInput|WIPE") })
	exec(t, db, "WIPE") // check not deadlocked
	expectPanic("Exec Close", func() { db.Exec("PANIC|Close|WIPE") })
	exec(t, db, "WIPE")             // check not deadlocked
	exec(t, db, "PANIC|Query|WIPE") // should run successfully: Exec does not call Query
	exec(t, db, "WIPE")             // check not deadlocked

	exec(t, db, "CREATE|people|name=string,age=int32,photo=blob,dead=bool,bdate=datetime")

	expectPanic("Query Query", func() { db.Query("PANIC|Query|SELECT|people|age,name|") })
	expectPanic("Query NumInput", func() { db.Query("PANIC|NumInput|SELECT|people|age,name|") })
	expectPanic("Query Close", func() {
		rows, err := db.Query("PANIC|Close|SELECT|people|age,name|")
		if err != nil {
			t.Fatal(err)
		}
		rows.Close()
	})
	db.Query("PANIC|Exec|SELECT|people|age,name|") // should run successfully: Query does not call Exec
	exec(t, db, "WIPE")                            // check not deadlocked
}

func exec(t testing.TB, db *DB, query string, args ...any) {
	t.Helper()
	_, err := db.Exec(query, args...)
	if err != nil {
		t.Fatalf("Exec of %q: %v", query, err)
	}
}

func closeDB(t testing.TB, db *DB) {
	if e := recover(); e != nil {
		fmt.Printf("Panic: %v\n", e)
		panic(e)
	}
	defer setHookpostCloseConn(nil)
	setHookpostCloseConn(func(_ *fakeConn, err error) {
		if err != nil {
			t.Errorf("Error closing fakeConn: %v", err)
		}
	})
	db.mu.Lock()
	for i, dc := range db.freeConn {
		if n := len(dc.openStmt); n > 0 {
			// Just a sanity check. This is legal in
			// general, but if we make the tests clean up
			// their statements first, then we can safely
			// verify this is always zero here, and any
			// other value is a leak.
			t.Errorf("while closing db, freeConn %d/%d had %d open stmts; want 0", i, len(db.freeConn), n)
		}
	}
	db.mu.Unlock()

	err := db.Close()
	if err != nil {
		t.Fatalf("error closing DB: %v", err)
	}

	var numOpen int
	if !waitCondition(t, func() bool {
		numOpen = db.numOpenConns()
		return numOpen == 0
	}) {
		t.Fatalf("%d connections still open after closing DB", numOpen)
	}
}

// numPrepares assumes that db has exactly 1 idle conn and returns
// its count of calls to Prepare
func numPrepares(t *testing.T, db *DB) int {
	if n := len(db.freeConn); n != 1 {
		t.Fatalf("free conns = %d; want 1", n)
	}
	return db.freeConn[0].ci.(*fakeConn).numPrepare
}

func (db *DB) numDeps() int {
	db.mu.Lock()
	defer db.mu.Unlock()
	return len(db.dep)
}

// Dependencies are closed via a goroutine, so this polls waiting for
// numDeps to fall to want, waiting up to nearly the test's deadline.
func (db *DB) numDepsPoll(t *testing.T, want int) int {
	var n int
	waitCondition(t, func() bool {
		n = db.numDeps()
		return n <= want
	})
	return n
}

func (db *DB) numFreeConns() int {
	db.mu.Lock()
	defer db.mu.Unlock()
	return len(db.freeConn)
}

func (db *DB) numOpenConns() int {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.numOpen
}

// clearAllConns closes all connections in db.
func (db *DB) clearAllConns(t *testing.T) {
	db.SetMaxIdleConns(0)

	if g, w := db.numFreeConns(), 0; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	if n := db.numDepsPoll(t, 0); n > 0 {
		t.Errorf("number of dependencies = %d; expected 0", n)
		db.dumpDeps(t)
	}
}

func (db *DB) dumpDeps(t *testing.T) {
	for fc := range db.dep {
		db.dumpDep(t, 0, fc, map[finalCloser]bool{})
	}
}

func (db *DB) dumpDep(t *testing.T, depth int, dep finalCloser, seen map[finalCloser]bool) {
	seen[dep] = true
	indent := strings.Repeat("  ", depth)
	ds := db.dep[dep]
	for k := range ds {
		t.Logf("%s%T (%p) waiting for -> %T (%p)", indent, dep, dep, k, k)
		if fc, ok := k.(finalCloser); ok {
			if !seen[fc] {
				db.dumpDep(t, depth+1, fc, seen)
			}
		}
	}
}

func TestQuery(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	prepares0 := numPrepares(t, db)
	rows, err := db.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()
	type row struct {
		age  int
		name string
	}
	got := []row{}
	for rows.Next() {
		var r row
		err = rows.Scan(&r.age, &r.name)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, r)
	}
	err = rows.Err()
	if err != nil {
		t.Fatalf("Err: %v", err)
	}
	want := []row{
		{age: 1, name: "Alice"},
		{age: 2, name: "Bob"},
		{age: 3, name: "Chris"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("mismatch.\n got: %#v\nwant: %#v", got, want)
	}

	// And verify that the final rows.Next() call, which hit EOF,
	// also closed the rows connection.
	if n := db.numFreeConns(); n != 1 {
		t.Fatalf("free conns after query hitting EOF = %d; want 1", n)
	}
	if prepares := numPrepares(t, db) - prepares0; prepares != 1 {
		t.Errorf("executed %d Prepare statements; want 1", prepares)
	}
}

// TestQueryContext tests canceling the context while scanning the rows.
func TestQueryContext(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	prepares0 := numPrepares(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rows, err := db.QueryContext(ctx, "SELECT|people|age,name|")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	type row struct {
		age  int
		name string
	}
	got := []row{}
	index := 0
	for rows.Next() {
		if index == 2 {
			cancel()
			waitForRowsClose(t, rows)
		}
		var r row
		err = rows.Scan(&r.age, &r.name)
		if err != nil {
			if index == 2 {
				break
			}
			t.Fatalf("Scan: %v", err)
		}
		if index == 2 && err != context.Canceled {
			t.Fatalf("Scan: %v; want context.Canceled", err)
		}
		got = append(got, r)
		index++
	}
	select {
	case <-ctx.Done():
		if err := ctx.Err(); err != context.Canceled {
			t.Fatalf("context err = %v; want context.Canceled", err)
		}
	default:
		t.Fatalf("context err = nil; want context.Canceled")
	}
	want := []row{
		{age: 1, name: "Alice"},
		{age: 2, name: "Bob"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("mismatch.\n got: %#v\nwant: %#v", got, want)
	}

	// And verify that the final rows.Next() call, which hit EOF,
	// also closed the rows connection.
	waitForRowsClose(t, rows)
	waitForFree(t, db, 1)
	if prepares := numPrepares(t, db) - prepares0; prepares != 1 {
		t.Errorf("executed %d Prepare statements; want 1", prepares)
	}
}

func waitCondition(t testing.TB, fn func() bool) bool {
	timeout := 5 * time.Second

	type deadliner interface {
		Deadline() (time.Time, bool)
	}
	if td, ok := t.(deadliner); ok {
		if deadline, ok := td.Deadline(); ok {
			timeout = time.Until(deadline)
			timeout = timeout * 19 / 20 // Give 5% headroom for cleanup and error-reporting.
		}
	}

	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return true
		}
		if time.Until(deadline) < pollDuration {
			return false
		}
		time.Sleep(pollDuration)
	}
}

// waitForFree checks db.numFreeConns until either it equals want or
// the maxWait time elapses.
func waitForFree(t *testing.T, db *DB, want int) {
	var numFree int
	if !waitCondition(t, func() bool {
		numFree = db.numFreeConns()
		return numFree == want
	}) {
		t.Fatalf("free conns after hitting EOF = %d; want %d", numFree, want)
	}
}

func waitForRowsClose(t *testing.T, rows *Rows) {
	if !waitCondition(t, func() bool {
		rows.closemu.RLock()
		defer rows.closemu.RUnlock()
		return rows.closed
	}) {
		t.Fatal("failed to close rows")
	}
}

// TestQueryContextWait ensures that rows and all internal statements are closed when
// a query context is closed during execution.
func TestQueryContextWait(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	prepares0 := numPrepares(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// This will trigger the *fakeConn.Prepare method which will take time
	// performing the query. The ctxDriverPrepare func will check the context
	// after this and close the rows and return an error.
	c, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}

	c.dc.ci.(*fakeConn).waiter = func(c context.Context) {
		cancel()
		<-ctx.Done()
	}
	_, err = c.QueryContext(ctx, "SELECT|people|age,name|")
	c.Close()
	if err != context.Canceled {
		t.Fatalf("expected QueryContext to error with context deadline exceeded but returned %v", err)
	}

	// Verify closed rows connection after error condition.
	waitForFree(t, db, 1)
	if prepares := numPrepares(t, db) - prepares0; prepares != 1 {
		t.Fatalf("executed %d Prepare statements; want 1", prepares)
	}
}

// TestTxContextWait tests the transaction behavior when the tx context is canceled
// during execution of the query.
func TestTxContextWait(t *testing.T) {
	testContextWait(t, false)
}

// TestTxContextWaitNoDiscard is the same as TestTxContextWait, but should not discard
// the final connection.
func TestTxContextWaitNoDiscard(t *testing.T) {
	testContextWait(t, true)
}

func testContextWait(t *testing.T, keepConnOnRollback bool) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx, cancel := context.WithCancel(context.Background())

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx.keepConnOnRollback = keepConnOnRollback

	tx.dc.ci.(*fakeConn).waiter = func(c context.Context) {
		cancel()
		<-ctx.Done()
	}
	// This will trigger the *fakeConn.Prepare method which will take time
	// performing the query. The ctxDriverPrepare func will check the context
	// after this and close the rows and return an error.
	_, err = tx.QueryContext(ctx, "SELECT|people|age,name|")
	if err != context.Canceled {
		t.Fatalf("expected QueryContext to error with context canceled but returned %v", err)
	}

	if keepConnOnRollback {
		waitForFree(t, db, 1)
	} else {
		waitForFree(t, db, 0)
	}
}

// TestUnsupportedOptions checks that the database fails when a driver that
// doesn't implement ConnBeginTx is used with non-default options and an
// un-cancellable context.
func TestUnsupportedOptions(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	_, err := db.BeginTx(context.Background(), &TxOptions{
		Isolation: LevelSerializable, ReadOnly: true,
	})
	if err == nil {
		t.Fatal("expected error when using unsupported options, got nil")
	}
}

func TestMultiResultSetQuery(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	prepares0 := numPrepares(t, db)
	rows, err := db.Query("SELECT|people|age,name|;SELECT|people|name|")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	type row1 struct {
		age  int
		name string
	}
	type row2 struct {
		name string
	}
	got1 := []row1{}
	for rows.Next() {
		var r row1
		err = rows.Scan(&r.age, &r.name)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got1 = append(got1, r)
	}
	err = rows.Err()
	if err != nil {
		t.Fatalf("Err: %v", err)
	}
	want1 := []row1{
		{age: 1, name: "Alice"},
		{age: 2, name: "Bob"},
		{age: 3, name: "Chris"},
	}
	if !slices.Equal(got1, want1) {
		t.Errorf("mismatch.\n got1: %#v\nwant: %#v", got1, want1)
	}

	if !rows.NextResultSet() {
		t.Errorf("expected another result set")
	}

	got2 := []row2{}
	for rows.Next() {
		var r row2
		err = rows.Scan(&r.name)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got2 = append(got2, r)
	}
	err = rows.Err()
	if err != nil {
		t.Fatalf("Err: %v", err)
	}
	want2 := []row2{
		{name: "Alice"},
		{name: "Bob"},
		{name: "Chris"},
	}
	if !slices.Equal(got2, want2) {
		t.Errorf("mismatch.\n got: %#v\nwant: %#v", got2, want2)
	}
	if rows.NextResultSet() {
		t.Errorf("expected no more result sets")
	}

	// And verify that the final rows.Next() call, which hit EOF,
	// also closed the rows connection.
	waitForFree(t, db, 1)
	if prepares := numPrepares(t, db) - prepares0; prepares != 1 {
		t.Errorf("executed %d Prepare statements; want 1", prepares)
	}
}

func TestQueryNamedArg(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	prepares0 := numPrepares(t, db)
	rows, err := db.Query(
		// Ensure the name and age parameters only match on placeholder name, not position.
		"SELECT|people|age,name|name=?name,age=?age",
		Named("age", 2),
		Named("name", "Bob"),
	)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	type row struct {
		age  int
		name string
	}
	got := []row{}
	for rows.Next() {
		var r row
		err = rows.Scan(&r.age, &r.name)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, r)
	}
	err = rows.Err()
	if err != nil {
		t.Fatalf("Err: %v", err)
	}
	want := []row{
		{age: 2, name: "Bob"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("mismatch.\n got: %#v\nwant: %#v", got, want)
	}

	// And verify that the final rows.Next() call, which hit EOF,
	// also closed the rows connection.
	if n := db.numFreeConns(); n != 1 {
		t.Fatalf("free conns after query hitting EOF = %d; want 1", n)
	}
	if prepares := numPrepares(t, db) - prepares0; prepares != 1 {
		t.Errorf("executed %d Prepare statements; want 1", prepares)
	}
}

func TestPoolExhaustOnCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("long test")
	}

	max := 3
	var saturate, saturateDone sync.WaitGroup
	saturate.Add(max)
	saturateDone.Add(max)

	donePing := make(chan bool)
	state := 0

	// waiter will be called for all queries, including
	// initial setup queries. The state is only assigned when
	// no queries are made.
	//
	// Only allow the first batch of queries to finish once the
	// second batch of Ping queries have finished.
	waiter := func(ctx context.Context) {
		switch state {
		case 0:
			// Nothing. Initial database setup.
		case 1:
			saturate.Done()
			select {
			case <-ctx.Done():
			case <-donePing:
			}
		case 2:
		}
	}
	db := newTestDBConnector(t, &fakeConnector{waiter: waiter}, "people")
	defer closeDB(t, db)

	db.SetMaxOpenConns(max)

	// First saturate the connection pool.
	// Then start new requests for a connection that is canceled after it is requested.

	state = 1
	for i := 0; i < max; i++ {
		go func() {
			rows, err := db.Query("SELECT|people|name,photo|")
			if err != nil {
				t.Errorf("Query: %v", err)
				return
			}
			rows.Close()
			saturateDone.Done()
		}()
	}

	saturate.Wait()
	if t.Failed() {
		t.FailNow()
	}
	state = 2

	// Now cancel the request while it is waiting.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for i := 0; i < max; i++ {
		ctxReq, cancelReq := context.WithCancel(ctx)
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancelReq()
		}()
		err := db.PingContext(ctxReq)
		if err != context.Canceled {
			t.Fatalf("PingContext (Exhaust): %v", err)
		}
	}
	close(donePing)
	saturateDone.Wait()

	// Now try to open a normal connection.
	err := db.PingContext(ctx)
	if err != nil {
		t.Fatalf("PingContext (Normal): %v", err)
	}
}

func TestRowsColumns(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	rows, err := db.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("Columns: %v", err)
	}
	want := []string{"age", "name"}
	if !slices.Equal(cols, want) {
		t.Errorf("got %#v; want %#v", cols, want)
	}
	if err := rows.Close(); err != nil {
		t.Errorf("error closing rows: %s", err)
	}
}

func TestRowsColumnTypes(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	rows, err := db.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	tt, err := rows.ColumnTypes()
	if err != nil {
		t.Fatalf("ColumnTypes: %v", err)
	}

	types := make([]reflect.Type, len(tt))
	for i, tp := range tt {
		st := tp.ScanType()
		if st == nil {
			t.Errorf("scantype is null for column %q", tp.Name())
			continue
		}
		types[i] = st
	}
	values := make([]any, len(tt))
	for i := range values {
		values[i] = reflect.New(types[i]).Interface()
	}
	ct := 0
	for rows.Next() {
		err = rows.Scan(values...)
		if err != nil {
			t.Fatalf("failed to scan values in %v", err)
		}
		if ct == 1 {
			if age := *values[0].(*int32); age != 2 {
				t.Errorf("Expected 2, got %v", age)
			}
			if name := *values[1].(*string); name != "Bob" {
				t.Errorf("Expected Bob, got %v", name)
			}
		}
		ct++
	}
	if ct != 3 {
		t.Errorf("expected 3 rows, got %d", ct)
	}

	if err := rows.Close(); err != nil {
		t.Errorf("error closing rows: %s", err)
	}
}

func TestQueryRow(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	var name string
	var age int
	var birthday time.Time

	err := db.QueryRow("SELECT|people|age,name|age=?", 3).Scan(&age)
	if err == nil || !strings.Contains(err.Error(), "expected 2 destination arguments") {
		t.Errorf("expected error from wrong number of arguments; actually got: %v", err)
	}

	err = db.QueryRow("SELECT|people|bdate|age=?", 3).Scan(&birthday)
	if err != nil || !birthday.Equal(chrisBirthday) {
		t.Errorf("chris birthday = %v, err = %v; want %v", birthday, err, chrisBirthday)
	}

	err = db.QueryRow("SELECT|people|age,name|age=?", 2).Scan(&age, &name)
	if err != nil {
		t.Fatalf("age QueryRow+Scan: %v", err)
	}
	if name != "Bob" {
		t.Errorf("expected name Bob, got %q", name)
	}
	if age != 2 {
		t.Errorf("expected age 2, got %d", age)
	}

	err = db.QueryRow("SELECT|people|age,name|name=?", "Alice").Scan(&age, &name)
	if err != nil {
		t.Fatalf("name QueryRow+Scan: %v", err)
	}
	if name != "Alice" {
		t.Errorf("expected name Alice, got %q", name)
	}
	if age != 1 {
		t.Errorf("expected age 1, got %d", age)
	}

	var photo []byte
	err = db.QueryRow("SELECT|people|photo|name=?", "Alice").Scan(&photo)
	if err != nil {
		t.Fatalf("photo QueryRow+Scan: %v", err)
	}
	want := []byte("APHOTO")
	if !slices.Equal(photo, want) {
		t.Errorf("photo = %q; want %q", photo, want)
	}
}

func TestRowErr(t *testing.T) {
	db := newTestDB(t, "people")

	err := db.QueryRowContext(context.Background(), "SELECT|people|bdate|age=?", 3).Err()
	if err != nil {
		t.Errorf("Unexpected err = %v; want %v", err, nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = db.QueryRowContext(ctx, "SELECT|people|bdate|age=?", 3).Err()
	exp := "context canceled"
	if err == nil || !strings.Contains(err.Error(), exp) {
		t.Errorf("Expected err = %v; got %v", exp, err)
	}
}

func TestTxRollbackCommitErr(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Rollback()
	if err != nil {
		t.Errorf("expected nil error from Rollback; got %v", err)
	}
	err = tx.Commit()
	if err != ErrTxDone {
		t.Errorf("expected %q from Commit; got %q", ErrTxDone, err)
	}

	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Commit()
	if err != nil {
		t.Errorf("expected nil error from Commit; got %v", err)
	}
	err = tx.Rollback()
	if err != ErrTxDone {
		t.Errorf("expected %q from Rollback; got %q", ErrTxDone, err)
	}
}

func TestStatementErrorAfterClose(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	stmt, err := db.Prepare("SELECT|people|age|name=?")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	err = stmt.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	var name string
	err = stmt.QueryRow("foo").Scan(&name)
	if err == nil {
		t.Errorf("expected error from QueryRow.Scan after Stmt.Close")
	}
}

func TestStatementQueryRow(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	stmt, err := db.Prepare("SELECT|people|age|name=?")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()
	var age int
	for n, tt := range []struct {
		name string
		want int
	}{
		{"Alice", 1},
		{"Bob", 2},
		{"Chris", 3},
	} {
		if err := stmt.QueryRow(tt.name).Scan(&age); err != nil {
			t.Errorf("%d: on %q, QueryRow/Scan: %v", n, tt.name, err)
		} else if age != tt.want {
			t.Errorf("%d: age=%d, want %d", n, age, tt.want)
		}
	}
}

type stubDriverStmt struct {
	err error
}

func (s stubDriverStmt) Close() error {
	return s.err
}

func (s stubDriverStmt) NumInput() int {
	return -1
}

func (s stubDriverStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, nil
}

func (s stubDriverStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, nil
}

// golang.org/issue/12798
func TestStatementClose(t *testing.T) {
	want := errors.New("STMT ERROR")

	tests := []struct {
		stmt *Stmt
		msg  string
	}{
		{&Stmt{stickyErr: want}, "stickyErr not propagated"},
		{&Stmt{cg: &Tx{}, cgds: &driverStmt{Locker: &sync.Mutex{}, si: stubDriverStmt{want}}}, "driverStmt.Close() error not propagated"},
	}
	for _, test := range tests {
		if err := test.stmt.Close(); err != want {
			t.Errorf("%s. Got stmt.Close() = %v, want = %v", test.msg, err, want)
		}
	}
}

// golang.org/issue/3734
func TestStatementQueryRowConcurrent(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	stmt, err := db.Prepare("SELECT|people|age|name=?")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	const n = 10
	ch := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			var age int
			err := stmt.QueryRow("Alice").Scan(&age)
			if err == nil && age != 1 {
				err = fmt.Errorf("unexpected age %d", age)
			}
			ch <- err
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-ch; err != nil {
			t.Error(err)
		}
	}
}

// just a test of fakedb itself
func TestBogusPreboundParameters(t *testing.T) {
	db := newTestDB(t, "foo")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")
	_, err := db.Prepare("INSERT|t1|name=?,age=bogusconversion")
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != `fakedb: invalid conversion to int32 from "bogusconversion"` {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExec(t *testing.T) {
	db := newTestDB(t, "foo")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")
	stmt, err := db.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Errorf("Stmt, err = %v, %v", stmt, err)
	}
	defer stmt.Close()

	type execTest struct {
		args    []any
		wantErr string
	}
	execTests := []execTest{
		// Okay:
		{[]any{"Brad", 31}, ""},
		{[]any{"Brad", int64(31)}, ""},
		{[]any{"Bob", "32"}, ""},
		{[]any{7, 9}, ""},

		// Invalid conversions:
		{[]any{"Brad", int64(0xFFFFFFFF)}, "sql: converting argument $2 type: sql/driver: value 4294967295 overflows int32"},
		{[]any{"Brad", "strconv fail"}, `sql: converting argument $2 type: sql/driver: value "strconv fail" can't be converted to int32`},

		// Wrong number of args:
		{[]any{}, "sql: expected 2 arguments, got 0"},
		{[]any{1, 2, 3}, "sql: expected 2 arguments, got 3"},
	}
	for n, et := range execTests {
		_, err := stmt.Exec(et.args...)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		if errStr != et.wantErr {
			t.Errorf("stmt.Execute #%d: for %v, got error %q, want error %q",
				n, et.args, errStr, et.wantErr)
		}
	}
}

func TestTxPrepare(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin = %v", err)
	}
	stmt, err := tx.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Fatalf("Stmt, err = %v, %v", stmt, err)
	}
	defer stmt.Close()
	_, err = stmt.Exec("Bobby", 7)
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}
	// Commit() should have closed the statement
	if !stmt.closed {
		t.Fatal("Stmt not closed after Commit")
	}
}

func TestTxStmt(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")
	stmt, err := db.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Fatalf("Stmt, err = %v, %v", stmt, err)
	}
	defer stmt.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin = %v", err)
	}
	txs := tx.Stmt(stmt)
	defer txs.Close()
	_, err = txs.Exec("Bobby", 7)
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}
	// Commit() should have closed the statement
	if !txs.closed {
		t.Fatal("Stmt not closed after Commit")
	}
}

func TestTxStmtPreparedOnce(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32")

	prepares0 := numPrepares(t, db)

	// db.Prepare increments numPrepares.
	stmt, err := db.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Fatalf("Stmt, err = %v, %v", stmt, err)
	}
	defer stmt.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin = %v", err)
	}

	txs1 := tx.Stmt(stmt)
	txs2 := tx.Stmt(stmt)

	_, err = txs1.Exec("Go", 7)
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	txs1.Close()

	_, err = txs2.Exec("Gopher", 8)
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	txs2.Close()

	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}

	if prepares := numPrepares(t, db) - prepares0; prepares != 1 {
		t.Errorf("executed %d Prepare statements; want 1", prepares)
	}
}

func TestTxStmtClosedRePrepares(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32")

	prepares0 := numPrepares(t, db)

	// db.Prepare increments numPrepares.
	stmt, err := db.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Fatalf("Stmt, err = %v, %v", stmt, err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin = %v", err)
	}
	err = stmt.Close()
	if err != nil {
		t.Fatalf("stmt.Close() = %v", err)
	}
	// tx.Stmt increments numPrepares because stmt is closed.
	txs := tx.Stmt(stmt)
	if txs.stickyErr != nil {
		t.Fatal(txs.stickyErr)
	}
	if txs.parentStmt != nil {
		t.Fatal("expected nil parentStmt")
	}
	_, err = txs.Exec(`Eric`, 82)
	if err != nil {
		t.Fatalf("txs.Exec = %v", err)
	}

	err = txs.Close()
	if err != nil {
		t.Fatalf("txs.Close = %v", err)
	}

	tx.Rollback()

	if prepares := numPrepares(t, db) - prepares0; prepares != 2 {
		t.Errorf("executed %d Prepare statements; want 2", prepares)
	}
}

func TestParentStmtOutlivesTxStmt(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32")

	// Make sure everything happens on the same connection.
	db.SetMaxOpenConns(1)

	prepares0 := numPrepares(t, db)

	// db.Prepare increments numPrepares.
	stmt, err := db.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Fatalf("Stmt, err = %v, %v", stmt, err)
	}
	defer stmt.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin = %v", err)
	}
	txs := tx.Stmt(stmt)
	if len(stmt.css) != 1 {
		t.Fatalf("len(stmt.css) = %v; want 1", len(stmt.css))
	}
	err = txs.Close()
	if err != nil {
		t.Fatalf("txs.Close() = %v", err)
	}
	err = tx.Rollback()
	if err != nil {
		t.Fatalf("tx.Rollback() = %v", err)
	}
	// txs must not be valid.
	_, err = txs.Exec("Suzan", 30)
	if err == nil {
		t.Fatalf("txs.Exec(), expected err")
	}
	// Stmt must still be valid.
	_, err = stmt.Exec("Janina", 25)
	if err != nil {
		t.Fatalf("stmt.Exec() = %v", err)
	}

	if prepares := numPrepares(t, db) - prepares0; prepares != 1 {
		t.Errorf("executed %d Prepare statements; want 1", prepares)
	}
}

// Test that tx.Stmt called with a statement already
// associated with tx as argument re-prepares the same
// statement again.
func TestTxStmtFromTxStmtRePrepares(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32")
	prepares0 := numPrepares(t, db)
	// db.Prepare increments numPrepares.
	stmt, err := db.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Fatalf("Stmt, err = %v, %v", stmt, err)
	}
	defer stmt.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin = %v", err)
	}
	txs1 := tx.Stmt(stmt)

	// tx.Stmt(txs1) increments numPrepares because txs1 already
	// belongs to a transaction (albeit the same transaction).
	txs2 := tx.Stmt(txs1)
	if txs2.stickyErr != nil {
		t.Fatal(txs2.stickyErr)
	}
	if txs2.parentStmt != nil {
		t.Fatal("expected nil parentStmt")
	}
	_, err = txs2.Exec(`Eric`, 82)
	if err != nil {
		t.Fatal(err)
	}

	err = txs1.Close()
	if err != nil {
		t.Fatalf("txs1.Close = %v", err)
	}
	err = txs2.Close()
	if err != nil {
		t.Fatalf("txs1.Close = %v", err)
	}
	err = tx.Rollback()
	if err != nil {
		t.Fatalf("tx.Rollback = %v", err)
	}

	if prepares := numPrepares(t, db) - prepares0; prepares != 2 {
		t.Errorf("executed %d Prepare statements; want 2", prepares)
	}
}

// Issue: https://golang.org/issue/2784
// This test didn't fail before because we got lucky with the fakedb driver.
// It was failing, and now not, in github.com/bradfitz/go-sql-test
func TestTxQuery(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")
	exec(t, db, "INSERT|t1|name=Alice")

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	r, err := tx.Query("SELECT|t1|name|")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if !r.Next() {
		if r.Err() != nil {
			t.Fatal(r.Err())
		}
		t.Fatal("expected one row")
	}

	var x string
	err = r.Scan(&x)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTxQueryInvalid(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	_, err = tx.Query("SELECT|t1|name|")
	if err == nil {
		t.Fatal("Error expected")
	}
}

// Tests fix for issue 4433, that retries in Begin happen when
// conn.Begin() returns ErrBadConn
func TestTxErrBadConn(t *testing.T) {
	db, err := Open("test", fakeDBName+";badConn")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := db.Exec("WIPE"); err != nil {
		t.Fatalf("exec wipe: %v", err)
	}
	defer closeDB(t, db)
	exec(t, db, "CREATE|t1|name=string,age=int32,dead=bool")
	stmt, err := db.Prepare("INSERT|t1|name=?,age=?")
	if err != nil {
		t.Fatalf("Stmt, err = %v, %v", stmt, err)
	}
	defer stmt.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin = %v", err)
	}
	txs := tx.Stmt(stmt)
	defer txs.Close()
	_, err = txs.Exec("Bobby", 7)
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}
}

func TestConnQuery(t *testing.T) {
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

	var name string
	err = conn.QueryRowContext(ctx, "SELECT|people|name|age=?", 3).Scan(&name)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Chris" {
		t.Fatalf("unexpected result, got %q want Chris", name)
	}

	err = conn.PingContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func TestConnRaw(t *testing.T) {
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

	sawFunc := false
	err = conn.Raw(func(dc any) error {
		sawFunc = true
		if _, ok := dc.(*fakeConn); !ok {
			return fmt.Errorf("got %T want *fakeConn", dc)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawFunc {
		t.Fatal("Raw func not called")
	}

	func() {
		defer func() {
			x := recover()
			if x == nil {
				t.Fatal("expected panic")
			}
			conn.closemu.Lock()
			closed := conn.dc == nil
			conn.closemu.Unlock()
			if !closed {
				t.Fatal("expected connection to be closed after panic")
			}
		}()
		err = conn.Raw(func(dc any) error {
			panic("Conn.Raw panic should return an error")
		})
		t.Fatal("expected panic from Raw func")
	}()
}

func TestCursorFake(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	exec(t, db, "CREATE|peoplecursor|list=table")
	exec(t, db, "INSERT|peoplecursor|list=people!name!age")

	rows, err := db.QueryContext(ctx, `SELECT|peoplecursor|list|`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatal("no rows")
	}
	var cursor = &Rows{}
	err = rows.Scan(cursor)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close()

	const expectedRows = 3
	var currentRow int64

	var n int64
	var s string
	for cursor.Next() {
		currentRow++
		err = cursor.Scan(&s, &n)
		if err != nil {
			t.Fatal(err)
		}
		if n != currentRow {
			t.Errorf("expected number(Age)=%d, got %d", currentRow, n)
		}
	}
	if currentRow != expectedRows {
		t.Errorf("expected %d rows, got %d rows", expectedRows, currentRow)
	}
}

func TestInvalidNilValues(t *testing.T) {
	var date1 time.Time
	var date2 int

	tests := []struct {
		name          string
		input         any
		expectedError string
	}{
		{
			name:          "time.Time",
			input:         &date1,
			expectedError: `sql: Scan error on column index 0, name "bdate": unsupported Scan, storing driver.Value type <nil> into type *time.Time`,
		},
		{
			name:          "int",
			input:         &date2,
			expectedError: `sql: Scan error on column index 0, name "bdate": converting NULL to int is unsupported`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			err = conn.QueryRowContext(ctx, "SELECT|people|bdate|age=?", 1).Scan(tt.input)
			if err == nil {
				t.Fatal("expected error when querying nil column, but succeeded")
			}
			if err.Error() != tt.expectedError {
				t.Fatalf("Expected error: %s\nReceived: %s", tt.expectedError, err.Error())
			}

			err = conn.PingContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConnTx(t *testing.T) {
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

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	insertName, insertAge := "Nancy", 33
	_, err = tx.ExecContext(ctx, "INSERT|people|name=?,age=?,photo=APHOTO", insertName, insertAge)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}

	var selectName string
	err = conn.QueryRowContext(ctx, "SELECT|people|name|age=?", insertAge).Scan(&selectName)
	if err != nil {
		t.Fatal(err)
	}
	if selectName != insertName {
		t.Fatalf("got %q want %q", selectName, insertName)
	}
}

// TestConnIsValid verifies that a database connection that should be discarded,
// is actually discarded and does not re-enter the connection pool.
// If the IsValid method from *fakeConn is removed, this test will fail.
func TestConnIsValid(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	db.SetMaxOpenConns(1)

	ctx := context.Background()

	c, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = c.Raw(func(raw any) error {
		dc := raw.(*fakeConn)
		dc.stickyBad = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	if len(db.freeConn) > 0 && db.freeConn[0].ci.(*fakeConn).stickyBad {
		t.Fatal("bad connection returned to pool; expected bad connection to be discarded")
	}
}

// Tests fix for issue 2542, that we release a lock when querying on
// a closed connection.
func TestIssue2542Deadlock(t *testing.T) {
	db := newTestDB(t, "people")
	closeDB(t, db)
	for i := 0; i < 2; i++ {
		_, err := db.Query("SELECT|people|age,name|")
		if err == nil {
			t.Fatalf("expected error")
		}
	}
}

// From golang.org/issue/3865
func TestCloseStmtBeforeRows(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	s, err := db.Prepare("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}

	r, err := s.Query()
	if err != nil {
		s.Close()
		t.Fatal(err)
	}

	err = s.Close()
	if err != nil {
		t.Fatal(err)
	}

	r.Close()
}

// Tests fix for issue 2788, that we bind nil to a []byte if the
// value in the column is sql null
func TestNullByteSlice(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t|id=int32,name=nullstring")
	exec(t, db, "INSERT|t|id=10,name=?", nil)

	var name []byte

	err := db.QueryRow("SELECT|t|name|id=?", 10).Scan(&name)
	if err != nil {
		t.Fatal(err)
	}
	if name != nil {
		t.Fatalf("name []byte should be nil for null column value, got: %#v", name)
	}

	exec(t, db, "INSERT|t|id=11,name=?", "bob")
	err = db.QueryRow("SELECT|t|name|id=?", 11).Scan(&name)
	if err != nil {
		t.Fatal(err)
	}
	if string(name) != "bob" {
		t.Fatalf("name []byte should be bob, got: %q", string(name))
	}
}

func TestPointerParamsAndScans(t *testing.T) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, "CREATE|t|id=int32,name=nullstring")

	bob := "bob"
	var name *string

	name = &bob
	exec(t, db, "INSERT|t|id=10,name=?", name)
	name = nil
	exec(t, db, "INSERT|t|id=20,name=?", name)

	err := db.QueryRow("SELECT|t|name|id=?", 10).Scan(&name)
	if err != nil {
		t.Fatalf("querying id 10: %v", err)
	}
	if name == nil {
		t.Errorf("id 10's name = nil; want bob")
	} else if *name != "bob" {
		t.Errorf("id 10's name = %q; want bob", *name)
	}

	err = db.QueryRow("SELECT|t|name|id=?", 20).Scan(&name)
	if err != nil {
		t.Fatalf("querying id 20: %v", err)
	}
	if name != nil {
		t.Errorf("id 20 = %q; want nil", *name)
	}
}

func TestQueryRowClosingStmt(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	var name string
	var age int
	err := db.QueryRow("SELECT|people|age,name|age=?", 3).Scan(&age, &name)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.freeConn) != 1 {
		t.Fatalf("expected 1 free conn")
	}
	fakeConn := db.freeConn[0].ci.(*fakeConn)
	if made, closed := fakeConn.stmtsMade, fakeConn.stmtsClosed; made != closed {
		t.Errorf("statement close mismatch: made %d, closed %d", made, closed)
	}
}

var atomicRowsCloseHook atomic.Value // of func(*Rows, *error)

func init() {
	rowsCloseHook = func() func(*Rows, *error) {
		fn, _ := atomicRowsCloseHook.Load().(func(*Rows, *error))
		return fn
	}
}

func setRowsCloseHook(fn func(*Rows, *error)) {
	if fn == nil {
		// Can't change an atomic.Value back to nil, so set it to this
		// no-op func instead.
		fn = func(*Rows, *error) {}
	}
	atomicRowsCloseHook.Store(fn)
}

// Test issue 6651
func TestIssue6651(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	var v string

	want := "error in rows.Next"
	rowsCursorNextHook = func(dest []driver.Value) error {
		return errors.New(want)
	}
	defer func() { rowsCursorNextHook = nil }()

	err := db.QueryRow("SELECT|people|name|").Scan(&v)
	if err == nil || err.Error() != want {
		t.Errorf("error = %q; want %q", err, want)
	}
	rowsCursorNextHook = nil

	want = "error in rows.Close"
	setRowsCloseHook(func(rows *Rows, err *error) {
		*err = errors.New(want)
	})
	defer setRowsCloseHook(nil)
	err = db.QueryRow("SELECT|people|name|").Scan(&v)
	if err == nil || err.Error() != want {
		t.Errorf("error = %q; want %q", err, want)
	}
}

type nullTestRow struct {
	nullParam    any
	notNullParam any
	scanNullVal  any
}

type nullTestSpec struct {
	nullType    string
	notNullType string
	rows        [6]nullTestRow
}

func TestNullStringParam(t *testing.T) {
	spec := nullTestSpec{"nullstring", "string", [6]nullTestRow{
		{NullString{"aqua", true}, "", NullString{"aqua", true}},
		{NullString{"brown", false}, "", NullString{"", false}},
		{"chartreuse", "", NullString{"chartreuse", true}},
		{NullString{"darkred", true}, "", NullString{"darkred", true}},
		{NullString{"eel", false}, "", NullString{"", false}},
		{"foo", NullString{"black", false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestGenericNullStringParam(t *testing.T) {
	spec := nullTestSpec{"nullstring", "string", [6]nullTestRow{
		{Null[string]{"aqua", true}, "", Null[string]{"aqua", true}},
		{Null[string]{"brown", false}, "", Null[string]{"", false}},
		{"chartreuse", "", Null[string]{"chartreuse", true}},
		{Null[string]{"darkred", true}, "", Null[string]{"darkred", true}},
		{Null[string]{"eel", false}, "", Null[string]{"", false}},
		{"foo", Null[string]{"black", false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestNullInt64Param(t *testing.T) {
	spec := nullTestSpec{"nullint64", "int64", [6]nullTestRow{
		{NullInt64{31, true}, 1, NullInt64{31, true}},
		{NullInt64{-22, false}, 1, NullInt64{0, false}},
		{22, 1, NullInt64{22, true}},
		{NullInt64{33, true}, 1, NullInt64{33, true}},
		{NullInt64{222, false}, 1, NullInt64{0, false}},
		{0, NullInt64{31, false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestNullInt32Param(t *testing.T) {
	spec := nullTestSpec{"nullint32", "int32", [6]nullTestRow{
		{NullInt32{31, true}, 1, NullInt32{31, true}},
		{NullInt32{-22, false}, 1, NullInt32{0, false}},
		{22, 1, NullInt32{22, true}},
		{NullInt32{33, true}, 1, NullInt32{33, true}},
		{NullInt32{222, false}, 1, NullInt32{0, false}},
		{0, NullInt32{31, false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestNullInt16Param(t *testing.T) {
	spec := nullTestSpec{"nullint16", "int16", [6]nullTestRow{
		{NullInt16{31, true}, 1, NullInt16{31, true}},
		{NullInt16{-22, false}, 1, NullInt16{0, false}},
		{22, 1, NullInt16{22, true}},
		{NullInt16{33, true}, 1, NullInt16{33, true}},
		{NullInt16{222, false}, 1, NullInt16{0, false}},
		{0, NullInt16{31, false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestNullByteParam(t *testing.T) {
	spec := nullTestSpec{"nullbyte", "byte", [6]nullTestRow{
		{NullByte{31, true}, 1, NullByte{31, true}},
		{NullByte{0, false}, 1, NullByte{0, false}},
		{22, 1, NullByte{22, true}},
		{NullByte{33, true}, 1, NullByte{33, true}},
		{NullByte{222, false}, 1, NullByte{0, false}},
		{0, NullByte{31, false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestNullFloat64Param(t *testing.T) {
	spec := nullTestSpec{"nullfloat64", "float64", [6]nullTestRow{
		{NullFloat64{31.2, true}, 1, NullFloat64{31.2, true}},
		{NullFloat64{13.1, false}, 1, NullFloat64{0, false}},
		{-22.9, 1, NullFloat64{-22.9, true}},
		{NullFloat64{33.81, true}, 1, NullFloat64{33.81, true}},
		{NullFloat64{222, false}, 1, NullFloat64{0, false}},
		{10, NullFloat64{31.2, false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestNullBoolParam(t *testing.T) {
	spec := nullTestSpec{"nullbool", "bool", [6]nullTestRow{
		{NullBool{false, true}, true, NullBool{false, true}},
		{NullBool{true, false}, false, NullBool{false, false}},
		{true, true, NullBool{true, true}},
		{NullBool{true, true}, false, NullBool{true, true}},
		{NullBool{true, false}, true, NullBool{false, false}},
		{true, NullBool{true, false}, nil},
	}}
	nullTestRun(t, spec)
}

func TestNullTimeParam(t *testing.T) {
	t0 := time.Time{}
	t1 := time.Date(2000, 1, 1, 8, 9, 10, 11, time.UTC)
	t2 := time.Date(2010, 1, 1, 8, 9, 10, 11, time.UTC)
	spec := nullTestSpec{"nulldatetime", "datetime", [6]nullTestRow{
		{NullTime{t1, true}, t2, NullTime{t1, true}},
		{NullTime{t1, false}, t2, NullTime{t0, false}},
		{t1, t2, NullTime{t1, true}},
		{NullTime{t1, true}, t2, NullTime{t1, true}},
		{NullTime{t1, false}, t2, NullTime{t0, false}},
		{t2, NullTime{t1, false}, nil},
	}}
	nullTestRun(t, spec)
}

func nullTestRun(t *testing.T, spec nullTestSpec) {
	db := newTestDB(t, "")
	defer closeDB(t, db)
	exec(t, db, fmt.Sprintf("CREATE|t|id=int32,name=string,nullf=%s,notnullf=%s", spec.nullType, spec.notNullType))

	// Inserts with db.Exec:
	exec(t, db, "INSERT|t|id=?,name=?,nullf=?,notnullf=?", 1, "alice", spec.rows[0].nullParam, spec.rows[0].notNullParam)
	exec(t, db, "INSERT|t|id=?,name=?,nullf=?,notnullf=?", 2, "bob", spec.rows[1].nullParam, spec.rows[1].notNullParam)

	// Inserts with a prepared statement:
	stmt, err := db.Prepare("INSERT|t|id=?,name=?,nullf=?,notnullf=?")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt.Close()
	if _, err := stmt.Exec(3, "chris", spec.rows[2].nullParam, spec.rows[2].notNullParam); err != nil {
		t.Errorf("exec insert chris: %v", err)
	}
	if _, err := stmt.Exec(4, "dave", spec.rows[3].nullParam, spec.rows[3].notNullParam); err != nil {
		t.Errorf("exec insert dave: %v", err)
	}
	if _, err := stmt.Exec(5, "eleanor", spec.rows[4].nullParam, spec.rows[4].notNullParam); err != nil {
		t.Errorf("exec insert eleanor: %v", err)
	}

	// Can't put null val into non-null col
	row5 := spec.rows[5]
	if _, err := stmt.Exec(6, "bob", row5.nullParam, row5.notNullParam); err == nil {
		t.Errorf("expected error inserting nil val with prepared statement Exec: NULL=%#v, NOT-NULL=%#v", row5.nullParam, row5.notNullParam)
	}

	_, err = db.Exec("INSERT|t|id=?,name=?,nullf=?", 999, nil, nil)
	if err == nil {
		// TODO: this test fails, but it's just because
		// fakeConn implements the optional Execer interface,
		// so arguably this is the correct behavior. But
		// maybe I should flesh out the fakeConn.Exec
		// implementation so this properly fails.
		// t.Errorf("expected error inserting nil name with Exec")
	}

	paramtype := reflect.TypeOf(spec.rows[0].nullParam)
	bindVal := reflect.New(paramtype).Interface()

	for i := 0; i < 5; i++ {
		id := i + 1
		if err := db.QueryRow("SELECT|t|nullf|id=?", id).Scan(bindVal); err != nil {
			t.Errorf("id=%d Scan: %v", id, err)
		}
		bindValDeref := reflect.ValueOf(bindVal).Elem().Interface()
		if !reflect.DeepEqual(bindValDeref, spec.rows[i].scanNullVal) {
			t.Errorf("id=%d got %#v, want %#v", id, bindValDeref, spec.rows[i].scanNullVal)
		}
	}
}

// golang.org/issue/4859
func TestQueryRowNilScanDest(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)
	var name *string // nil pointer
	err := db.QueryRow("SELECT|people|name|").Scan(name)
	want := `sql: Scan error on column index 0, name "name": destination pointer is nil`
	if err == nil || err.Error() != want {
		t.Errorf("error = %q; want %q", err.Error(), want)
	}
}

func TestIssue4902(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	driver := db.Driver().(*fakeDriver)
	opens0 := driver.openCount

	var stmt *Stmt
	var err error
	for i := 0; i < 10; i++ {
		stmt, err = db.Prepare("SELECT|people|name|")
		if err != nil {
			t.Fatal(err)
		}
		err = stmt.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	opens := driver.openCount - opens0
	if opens > 1 {
		t.Errorf("opens = %d; want <= 1", opens)
		t.Logf("db = %#v", db)
		t.Logf("driver = %#v", driver)
		t.Logf("stmt = %#v", stmt)
	}
}

// Issue 3857
// This used to deadlock.
func TestSimultaneousQueries(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	r1, err := tx.Query("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()

	r2, err := tx.Query("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
}

func TestMaxIdleConns(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit()
	if got := len(db.freeConn); got != 1 {
		t.Errorf("freeConns = %d; want 1", got)
	}

	db.SetMaxIdleConns(0)

	if got := len(db.freeConn); got != 0 {
		t.Errorf("freeConns after set to zero = %d; want 0", got)
	}

	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit()
	if got := len(db.freeConn); got != 0 {
		t.Errorf("freeConns = %d; want 0", got)
	}
}

func TestMaxOpenConns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer setHookpostCloseConn(nil)
	setHookpostCloseConn(func(_ *fakeConn, err error) {
		if err != nil {
			t.Errorf("Error closing fakeConn: %v", err)
		}
	})

	db := newTestDB(t, "magicquery")
	defer closeDB(t, db)

	driver := db.Driver().(*fakeDriver)

	// Force the number of open connections to 0 so we can get an accurate
	// count for the test
	db.clearAllConns(t)

	driver.mu.Lock()
	opens0 := driver.openCount
	closes0 := driver.closeCount
	driver.mu.Unlock()

	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(10)

	stmt, err := db.Prepare("SELECT|magicquery|op|op=?,millis=?")
	if err != nil {
		t.Fatal(err)
	}

	// Start 50 parallel slow queries.
	const (
		nquery      = 50
		sleepMillis = 25
		nbatch      = 2
	)
	var wg sync.WaitGroup
	for batch := 0; batch < nbatch; batch++ {
		for i := 0; i < nquery; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var op string
				if err := stmt.QueryRow("sleep", sleepMillis).Scan(&op); err != nil && err != ErrNoRows {
					t.Error(err)
				}
			}()
		}
		// Wait for the batch of queries above to finish before starting the next round.
		wg.Wait()
	}

	if g, w := db.numFreeConns(), 10; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	if n := db.numDepsPoll(t, 20); n > 20 {
		t.Errorf("number of dependencies = %d; expected <= 20", n)
		db.dumpDeps(t)
	}

	driver.mu.Lock()
	opens := driver.openCount - opens0
	closes := driver.closeCount - closes0
	driver.mu.Unlock()

	if opens > 10 {
		t.Logf("open calls = %d", opens)
		t.Logf("close calls = %d", closes)
		t.Errorf("db connections opened = %d; want <= 10", opens)
		db.dumpDeps(t)
	}

	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}

	if g, w := db.numFreeConns(), 10; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	if n := db.numDepsPoll(t, 10); n > 10 {
		t.Errorf("number of dependencies = %d; expected <= 10", n)
		db.dumpDeps(t)
	}

	db.SetMaxOpenConns(5)

	if g, w := db.numFreeConns(), 5; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	if n := db.numDepsPoll(t, 5); n > 5 {
		t.Errorf("number of dependencies = %d; expected 0", n)
		db.dumpDeps(t)
	}

	db.SetMaxOpenConns(0)

	if g, w := db.numFreeConns(), 5; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	if n := db.numDepsPoll(t, 5); n > 5 {
		t.Errorf("number of dependencies = %d; expected 0", n)
		db.dumpDeps(t)
	}

	db.clearAllConns(t)
}

// Issue 9453: tests that SetMaxOpenConns can be lowered at runtime
// and affects the subsequent release of connections.
func TestMaxOpenConnsOnBusy(t *testing.T) {
	defer setHookpostCloseConn(nil)
	setHookpostCloseConn(func(_ *fakeConn, err error) {
		if err != nil {
			t.Errorf("Error closing fakeConn: %v", err)
		}
	})

	db := newTestDB(t, "magicquery")
	defer closeDB(t, db)

	db.SetMaxOpenConns(3)

	ctx := context.Background()

	conn0, err := db.conn(ctx, cachedOrNewConn)
	if err != nil {
		t.Fatalf("db open conn fail: %v", err)
	}

	conn1, err := db.conn(ctx, cachedOrNewConn)
	if err != nil {
		t.Fatalf("db open conn fail: %v", err)
	}

	conn2, err := db.conn(ctx, cachedOrNewConn)
	if err != nil {
		t.Fatalf("db open conn fail: %v", err)
	}

	if g, w := db.numOpen, 3; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	db.SetMaxOpenConns(2)
	if g, w := db.numOpen, 3; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	conn0.releaseConn(nil)
	conn1.releaseConn(nil)
	if g, w := db.numOpen, 2; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	conn2.releaseConn(nil)
	if g, w := db.numOpen, 2; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}
}

// Issue 10886: tests that all connection attempts return when more than
// DB.maxOpen connections are in flight and the first DB.maxOpen fail.
func TestPendingConnsAfterErr(t *testing.T) {
	const (
		maxOpen = 2
		tryOpen = maxOpen*2 + 2
	)

	// No queries will be run.
	db, err := Open("test", fakeDBName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer closeDB(t, db)
	defer func() {
		for k, v := range db.lastPut {
			t.Logf("%p: %v", k, v)
		}
	}()

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(0)

	errOffline := errors.New("db offline")

	defer func() { setHookOpenErr(nil) }()

	errs := make(chan error, tryOpen)

	var opening sync.WaitGroup
	opening.Add(tryOpen)

	setHookOpenErr(func() error {
		// Wait for all connections to enqueue.
		opening.Wait()
		return errOffline
	})

	for i := 0; i < tryOpen; i++ {
		go func() {
			opening.Done() // signal one connection is in flight
			_, err := db.Exec("will never run")
			errs <- err
		}()
	}

	opening.Wait() // wait for all workers to begin running

	const timeout = 5 * time.Second
	to := time.NewTimer(timeout)
	defer to.Stop()

	// check that all connections fail without deadlock
	for i := 0; i < tryOpen; i++ {
		select {
		case err := <-errs:
			if got, want := err, errOffline; got != want {
				t.Errorf("unexpected err: got %v, want %v", got, want)
			}
		case <-to.C:
			t.Fatalf("orphaned connection request(s), still waiting after %v", timeout)
		}
	}

	// Wait a reasonable time for the database to close all connections.
	tick := time.NewTicker(3 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			db.mu.Lock()
			if db.numOpen == 0 {
				db.mu.Unlock()
				return
			}
			db.mu.Unlock()
		case <-to.C:
			// Closing the database will check for numOpen and fail the test.
			return
		}
	}
}

func TestSingleOpenConn(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	db.SetMaxOpenConns(1)

	rows, err := db.Query("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	// shouldn't deadlock
	rows, err = db.Query("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStats(t *testing.T) {
	db := newTestDB(t, "people")
	stats := db.Stats()
	if got := stats.OpenConnections; got != 1 {
		t.Errorf("stats.OpenConnections = %d; want 1", got)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit()

	closeDB(t, db)
	stats = db.Stats()
	if got := stats.OpenConnections; got != 0 {
		t.Errorf("stats.OpenConnections = %d; want 0", got)
	}
}

func TestConnMaxLifetime(t *testing.T) {
	t0 := time.Unix(1000000, 0)
	offset := time.Duration(0)

	nowFunc = func() time.Time { return t0.Add(offset) }
	defer func() { nowFunc = time.Now }()

	db := newTestDB(t, "magicquery")
	defer closeDB(t, db)

	driver := db.Driver().(*fakeDriver)

	// Force the number of open connections to 0 so we can get an accurate
	// count for the test
	db.clearAllConns(t)

	driver.mu.Lock()
	opens0 := driver.openCount
	closes0 := driver.closeCount
	driver.mu.Unlock()

	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(10)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}

	offset = time.Second
	tx2, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}

	tx.Commit()
	tx2.Commit()

	driver.mu.Lock()
	opens := driver.openCount - opens0
	closes := driver.closeCount - closes0
	driver.mu.Unlock()

	if opens != 2 {
		t.Errorf("opens = %d; want 2", opens)
	}
	if closes != 0 {
		t.Errorf("closes = %d; want 0", closes)
	}
	if g, w := db.numFreeConns(), 2; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	// Expire first conn
	offset = 11 * time.Second
	db.SetConnMaxLifetime(10 * time.Second)

	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	tx2, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit()
	tx2.Commit()

	// Give connectionCleaner chance to run.
	waitCondition(t, func() bool {
		driver.mu.Lock()
		opens = driver.openCount - opens0
		closes = driver.closeCount - closes0
		driver.mu.Unlock()

		return closes == 1
	})

	if opens != 3 {
		t.Errorf("opens = %d; want 3", opens)
	}
	if closes != 1 {
		t.Errorf("closes = %d; want 1", closes)
	}

	if s := db.Stats(); s.MaxLifetimeClosed != 1 {
		t.Errorf("MaxLifetimeClosed = %d; want 1 %#v", s.MaxLifetimeClosed, s)
	}
}

// golang.org/issue/5323
func TestStmtCloseDeps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer setHookpostCloseConn(nil)
	setHookpostCloseConn(func(_ *fakeConn, err error) {
		if err != nil {
			t.Errorf("Error closing fakeConn: %v", err)
		}
	})

	db := newTestDB(t, "magicquery")
	defer closeDB(t, db)

	driver := db.Driver().(*fakeDriver)

	driver.mu.Lock()
	opens0 := driver.openCount
	closes0 := driver.closeCount
	driver.mu.Unlock()
	openDelta0 := opens0 - closes0

	stmt, err := db.Prepare("SELECT|magicquery|op|op=?,millis=?")
	if err != nil {
		t.Fatal(err)
	}

	// Start 50 parallel slow queries.
	const (
		nquery      = 50
		sleepMillis = 25
		nbatch      = 2
	)
	var wg sync.WaitGroup
	for batch := 0; batch < nbatch; batch++ {
		for i := 0; i < nquery; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var op string
				if err := stmt.QueryRow("sleep", sleepMillis).Scan(&op); err != nil && err != ErrNoRows {
					t.Error(err)
				}
			}()
		}
		// Wait for the batch of queries above to finish before starting the next round.
		wg.Wait()
	}

	if g, w := db.numFreeConns(), 2; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	if n := db.numDepsPoll(t, 4); n > 4 {
		t.Errorf("number of dependencies = %d; expected <= 4", n)
		db.dumpDeps(t)
	}

	driver.mu.Lock()
	opens := driver.openCount - opens0
	closes := driver.closeCount - closes0
	openDelta := (driver.openCount - driver.closeCount) - openDelta0
	driver.mu.Unlock()

	if openDelta > 2 {
		t.Logf("open calls = %d", opens)
		t.Logf("close calls = %d", closes)
		t.Logf("open delta = %d", openDelta)
		t.Errorf("db connections opened = %d; want <= 2", openDelta)
		db.dumpDeps(t)
	}

	if !waitCondition(t, func() bool {
		return len(stmt.css) <= nquery
	}) {
		t.Errorf("len(stmt.css) = %d; want <= %d", len(stmt.css), nquery)
	}

	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}

	if g, w := db.numFreeConns(), 2; g != w {
		t.Errorf("free conns = %d; want %d", g, w)
	}

	if n := db.numDepsPoll(t, 2); n > 2 {
		t.Errorf("number of dependencies = %d; expected <= 2", n)
		db.dumpDeps(t)
	}

	db.clearAllConns(t)
}

// golang.org/issue/5046
func TestCloseConnBeforeStmts(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	defer setHookpostCloseConn(nil)
	setHookpostCloseConn(func(_ *fakeConn, err error) {
		if err != nil {
			t.Errorf("Error closing fakeConn: %v; from %s", err, stack())
			db.dumpDeps(t)
			t.Errorf("DB = %#v", db)
		}
	})

	stmt, err := db.Prepare("SELECT|people|name|")
	if err != nil {
		t.Fatal(err)
	}

	if len(db.freeConn) != 1 {
		t.Fatalf("expected 1 freeConn; got %d", len(db.freeConn))
	}
	dc := db.freeConn[0]
	if dc.closed {
		t.Errorf("conn shouldn't be closed")
	}

	if n := len(dc.openStmt); n != 1 {
		t.Errorf("driverConn num openStmt = %d; want 1", n)
	}
	err = db.Close()
	if err != nil {
		t.Errorf("db Close = %v", err)
	}
	if !dc.closed {
		t.Errorf("after db.Close, driverConn should be closed")
	}
	if n := len(dc.openStmt); n != 0 {
		t.Errorf("driverConn num openStmt = %d; want 0", n)
	}

	err = stmt.Close()
	if err != nil {
		t.Errorf("Stmt close = %v", err)
	}

	if !dc.closed {
		t.Errorf("conn should be closed")
	}
	if dc.ci != nil {
		t.Errorf("after Stmt Close, driverConn's Conn interface should be nil")
	}
}

// golang.org/issue/5283: don't release the Rows' connection in Close
// before calling Stmt.Close.
func TestRowsCloseOrder(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	db.SetMaxIdleConns(0)
	setStrictFakeConnClose(t)
	defer setStrictFakeConnClose(nil)

	rows, err := db.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatal(err)
	}
	err = rows.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRowsImplicitClose(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	rows, err := db.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatal(err)
	}

	want, fail := 2, errors.New("fail")
	r := rows.rowsi.(*rowsCursor)
	r.errPos, r.err = want, fail

	got := 0
	for rows.Next() {
		got++
	}
	if got != want {
		t.Errorf("got %d rows, want %d", got, want)
	}
	if err := rows.Err(); err != fail {
		t.Errorf("got error %v, want %v", err, fail)
	}
	if !r.closed {
		t.Errorf("r.closed is false, want true")
	}
}

func TestRowsCloseError(t *testing.T) {
	db := newTestDB(t, "people")
	defer db.Close()
	rows, err := db.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	type row struct {
		age  int
		name string
	}
	got := []row{}

	rc, ok := rows.rowsi.(*rowsCursor)
	if !ok {
		t.Fatal("not using *rowsCursor")
	}
	rc.closeErr = errors.New("rowsCursor: failed to close")

	for rows.Next() {
		var r row
		err = rows.Scan(&r.age, &r.name)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, r)
	}
	err = rows.Err()
	if err != rc.closeErr {
		t.Fatalf("unexpected err: got %v, want %v", err, rc.closeErr)
	}
}

func TestStmtCloseOrder(t *testing.T) {
	db := newTestDB(t, "people")
	defer closeDB(t, db)

	db.SetMaxIdleConns(0)
	setStrictFakeConnClose(t)
	defer setStrictFakeConnClose(nil)

	_, err := db.Query("SELECT|non_existent|name|")
	if err == nil {
		t.Fatal("Querying non-existent table should fail")
	}
}

// Test cases where there's more than maxBadConnRetries bad connections in the
// pool (issue 8834)
func TestManyErrBadConn(t *testing.T) {
	manyErrBadConnSetup := func(first ...func(db *DB)) *DB {
		db := newTestDB(t, "people")

		for _, f := range first {
			f(db)
		}

		nconn := maxBadConnRetries + 1
		db.SetMaxIdleConns(nconn)
		db.SetMaxOpenConns(nconn)
		// open enough connections
		func() {
			for i := 0; i < nconn; i++ {
				rows, err := db.Query("SELECT|people|age,name|")
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
			}
		}()

		db.mu.Lock()
		defer db.mu.Unlock()
		if db.numOpen != nconn {
			t.Fatalf("unexpected numOpen %d (was expecting %d)", db.numOpen, nconn)
		} else if len(db.freeConn) != nconn {
			t.Fatalf("unexpected len(db.freeConn) %d (was expecting %d)", len(db.freeConn), nconn)
		}
		for _, conn := range db.freeConn {
			conn.Lock()
			conn.ci.(*fakeConn).stickyBad = true
			conn.Unlock()
		}
		return db
	}

	// Query
	db := manyErrBadConnSetup()
	defer closeDB(t, db)
	rows, err := db.Query("SELECT|people|age,name|")
	if err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}

	// Exec
	db = manyErrBadConnSetup()
	defer closeDB(t, db)
	_, err = db.Exec("INSERT|people|name=Julia,age=19")
	if err != nil {
		t.Fatal(err)
	}

	// Begin
	db = manyErrBadConnSetup()
	defer closeDB(t, db)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	// Prepare
	db = manyErrBadConnSetup()
	defer closeDB(t, db)
	stmt, err := db.Prepare("SELECT|people|age,name|")
	if err != nil {
		t.Fatal(err)
	}
	if err = stmt.Close(); err != nil {
		t.Fatal(err)
	}

	// Stmt.Exec
	db = manyErrBadConnSetup(func(db *DB) {
		stmt, err = db.Prepare("INSERT|people|name=Julia,age=19")
		if err != nil {
			t.Fatal(err)
		}
	})
	defer closeDB(t, db)
	_, err = stmt.Exec()
	if err != nil {
		t.Fatal(err)
	}
	if 
"""




```