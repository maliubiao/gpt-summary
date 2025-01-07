Response:
Let's break down the thought process to arrive at the summary of the provided Go code.

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code snippet, which is a part of `go/src/database/sql/sql_test.go`. It also asks for connections to specific Go features and examples where possible. Crucially, it's labeled as "Part 4 of 4", implying this is the concluding part and a general summary of the overall file's purpose is needed.

2. **Initial Scan and Identification of Key Structures:**  Quickly skim the code, looking for keywords, type definitions, and function names. I see:
    * `ctxOnlyConn`, `ctxOnlyDriver`:  Suggests testing scenarios focusing on context-aware operations.
    * `TestQueryExecContextOnly`: Explicitly tests the requirement for only context-based methods.
    * `alwaysErrScanner`, `alwaysErrValuer`:  Clearly related to error handling in `Scan` and `Value` methods.
    * `TestRowsScanProperlyWrapsErrors`, `TestDriverArgsWrapsErrors`: Explicitly test error wrapping.
    * `TestContextCancelDuringRawBytesScan`, `TestContextCancelBetweenNextAndErr`, `TestNilErrorAfterClose`:  Focus on context cancellation and related error handling during `Rows` iteration.
    * `TestRawBytesReuse`:  Tests the behavior of `RawBytes` across multiple queries.
    * `badConn`, `badDriver`, `TestBadDriver`:  Deals with testing error scenarios when a driver misbehaves.
    * `pingDriver`, `pingConn`, `TestPing`: Tests the `Pinger` interface.
    * `TestTypedString`: Tests scanning into custom string types.
    * `Benchmark...`:  Indicates performance benchmarks.
    * `TestGrabConnAllocs`, `BenchmarkGrabConn`: Tests and benchmarks connection grabbing.
    * `TestConnRequestSet`, `BenchmarkConnRequestSet`: Tests and benchmarks a custom connection request set.
    * `TestIssue69837`, `TestIssue69728`:  Tests specific reported issues, often related to data type handling.

3. **Grouping by Functionality:** Based on the identified structures and test names, group related code blocks together:
    * **Context Handling:** `ctxOnlyConn`, `ctxOnlyDriver`, `TestQueryExecContextOnly`, `TestContextCancelDuringRawBytesScan`, `TestContextCancelBetweenNextAndErr`, `TestNilErrorAfterClose`.
    * **Error Handling:** `alwaysErrScanner`, `alwaysErrValuer`, `TestRowsScanProperlyWrapsErrors`, `TestDriverArgsWrapsErrors`, `TestBadDriver`.
    * **Data Handling & Type Conversion:** `TestTypedString`, `TestRawBytesReuse`, `TestIssue69837`, `TestIssue69728`.
    * **Connection Management:** `TestGrabConnAllocs`, `BenchmarkGrabConn`, `TestConnRequestSet`, `BenchmarkConnRequestSet`.
    * **Driver Interface Testing:** `badConn`, `badDriver`, `pingDriver`, `pingConn`, `TestPing`.
    * **Performance Benchmarking:**  All the `Benchmark...` functions.

4. **Synthesize Functionality within Each Group:** Describe the purpose of each group. For example, the "Context Handling" group is about ensuring the `database/sql` package correctly handles contexts for operations like queries and executions, and handles cancellation gracefully.

5. **Infer Go Features Illustrated:** Connect the observed code patterns to specific Go language features:
    * **Interfaces:** The use of `driver.Conn`, `driver.Stmt`, `driver.Rows`, `driver.Execer`, `driver.Queryer`, `driver.Pinger` clearly demonstrates interface implementation and testing.
    * **Contexts:** The `context` package is heavily used, illustrating its role in managing timeouts and cancellations.
    * **Error Handling:**  The `errors` package and the `errors.Is` function are used for robust error checking. The custom error types demonstrate good practices.
    * **Testing:** The `testing` package is used extensively, showing standard Go testing practices, including `t.Fatalf`, `t.Errorf`, and benchmarks.
    * **Concurrency:** The benchmark functions and the `TestContextCancelDuringRawBytesScan` involving goroutines touch upon concurrency.
    * **Generics:** The `Null[T]` type and its usage in `TestIssue69837` demonstrates the use of generics.
    * **Reflection:** While not explicitly a major focus, the `reflect.DeepEqual` in `TestIssue69728` shows basic reflection.

6. **Construct Examples (Where Applicable):** For key features like context handling and error wrapping, create simplified Go code examples to illustrate the concepts. This helps solidify understanding. Include hypothetical inputs and outputs to make the examples concrete.

7. **Address Command-Line Arguments (If Any):**  In this specific code snippet, there are no direct command-line argument parsing. So, explicitly state this.

8. **Identify Potential User Errors:** Think about common mistakes developers might make when working with `database/sql` based on the tests. For example, forgetting to close `Rows`, not properly handling context cancellation, or making assumptions about the underlying driver implementation.

9. **Formulate the Overall Summary:**  Synthesize the information from the individual groups to provide a high-level overview of the code's purpose. Emphasize that it's a test file for the `database/sql` package, focusing on driver compatibility, error handling, context management, concurrency safety, and performance.

10. **Review and Refine:** Read through the generated summary and examples to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or missing information. Ensure the language is clear and uses appropriate technical terms. Given the "Part 4 of 4" instruction, explicitly call out that it complements previous parts in testing the `database/sql` package.

This structured approach allows for a systematic analysis of the code, leading to a comprehensive and informative summary that addresses all aspects of the request.
这是 `go/src/database/sql/sql_test.go` 文件的一部分，主要集中在测试 `database/sql` 包在特定场景下的行为，特别是关于上下文（Context）、错误处理和与底层数据库驱动交互的细节。

**功能归纳:**

这部分代码主要测试了以下功能：

1. **仅支持 Context 的连接 (Context-Only Connection):**  测试了当数据库连接只实现 `*Context` 版本的方法（例如 `QueryContext`, `ExecContext`）时，`database/sql` 包的行为是否正确。这确保了驱动开发者只需要实现基于 Context 的接口，而无需实现旧的非 Context 版本。

2. **`Rows.Scan` 的错误包装:**  测试了从 `Rows` 中扫描数据时，如果底层的扫描方法返回错误，`database/sql` 包是否正确地包装了这些错误，使得用户可以使用 `errors.Is` 和字符串匹配等方式来判断具体的错误类型。

3. **`Stmt.Exec` 和 `Stmt.Query` 的参数错误包装:**  测试了在使用预编译语句执行查询或命令时，如果作为参数传入的值实现了 `driver.Valuer` 接口并且其 `Value()` 方法返回错误，`database/sql` 包是否正确地包装了这些错误。

4. **在 `Rows.Scan` 期间取消 Context 的处理:**  测试了在调用 `Rows.Next()` 和 `Rows.Scan()` 之间取消 Context 时，`database/sql` 包是否能够正确处理，并返回 `context.Canceled` 错误。特别关注了在处理 `RawBytes` 类型时 Context 取消的影响。

5. **在 `Rows.Next()` 和 `Rows.Err()` 之间取消 Context 的处理:** 测试了在 `Rows` 迭代过程中，调用 `Next()` 后但在调用 `Err()` 前取消 Context 的情况。

6. **`Rows.Close()` 后的 `Err()` 返回 nil:**  测试了在 `Rows.Close()` 被调用后，再次调用 `Rows.Err()` 是否返回 `nil`，以确保资源被正确释放且没有遗留错误。

7. **`RawBytes` 的重用:**  测试了在多次查询中重用 `RawBytes` 变量时，`database/sql` 包是否能正确处理底层驱动的内存管理，避免数据被意外覆盖。

8. **处理错误的 Driver 实现:**  测试了当注册的数据库驱动的连接（`driver.Conn`）实现存在缺陷（例如 `Exec` 方法会 panic）时，`database/sql` 包是否能够捕获并处理这些错误，避免程序崩溃。

9. **`driver.Pinger` 接口的测试:**  测试了实现了 `driver.Pinger` 接口的驱动，`db.Ping()` 方法是否能够正确调用底层的 `Ping` 方法，并处理成功和失败的情况。

10. **扫描到自定义字符串类型:** 测试了是否可以将数据库中的字符串类型数据扫描到自定义的字符串类型（例如 `type Str string`）。

11. **并发性能测试:**  包含了一系列基准测试（Benchmark），用于衡量在并发场景下，使用 `db.Exec`, `stmt.Query`, `stmt.Exec`, `tx.Query`, `tx.Exec`, `txStmt.Query`, `txStmt.Exec` 等操作的性能。同时也包含了对随机并发操作的基准测试。

12. **连接获取的性能和内存分配测试:**  测试了 `Conn.grabConn` 方法的内存分配情况和性能。

13. **`connRequestSet` 的测试:**  测试了一个自定义的连接请求集合数据结构的功能，包括添加、删除、随机获取和关闭并移除所有请求。

14. **处理 `Null` 类型的参数转换:** 测试了 `Null[T]` 类型（例如 `Null[uint]`) 作为参数传递给数据库驱动时，默认的参数转换器是否能正确处理。

15. **自定义 `driver.Valuer` 类型的处理:** 测试了当 `Null[T]` 中的 `T` 实现了 `driver.Valuer` 接口时，其 `Value()` 方法是否会被正确调用。

**Go 语言功能实现示例:**

**1. 仅支持 Context 的连接:**

```go
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
)

type ctxOnlyDriver struct{}

type ctxOnlyConn struct {
	fc fakeConn
}

func (ctxOnlyDriver) Open(name string) (driver.Conn, error) {
	return &ctxOnlyConn{fc: fakeConn{}}, nil
}

func (c *ctxOnlyConn) Close() error {
	return c.fc.Close()
}

func (c *ctxOnlyConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	fmt.Println("PrepareContext called")
	return nil, nil
}

func (c *ctxOnlyConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	fmt.Println("QueryContext called")
	return nil, nil
}

func (c *ctxOnlyConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	fmt.Println("ExecContext called")
	return nil, nil
}

type fakeConn struct{}

func (fakeConn) Close() error { return nil }

func main() {
	sql.Register("ctxonly", &ctxOnlyDriver{})
	db, err := sql.Open("ctxonly", "")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, err = db.QueryContext(ctx, "SELECT * FROM users")
	if err != nil {
		log.Println(err)
	}
	_, err = db.ExecContext(ctx, "UPDATE users SET name = ? WHERE id = ?", "new name", 1)
	if err != nil {
		log.Println(err)
	}
}
```

**假设输入与输出:**

在上面的例子中，我们注册了一个名为 "ctxonly" 的驱动，它只实现了带 Context 的方法。当我们使用 `db.QueryContext` 和 `db.ExecContext` 时，会调用到 `ctxOnlyConn` 相应的 Context 方法，并在控制台输出 "QueryContext called" 和 "ExecContext called"。 如果我们尝试调用 `db.Query` (没有 Context)，则会因为驱动没有实现 `driver.Queryer` 接口而报错。

**2. `Rows.Scan` 的错误包装:**

```go
package main

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
)

type alwaysErrorScanner struct{}

var errScan = errors.New("scan error")

func (alwaysErrorScanner) Scan(dest ...any) error {
	return errScan
}

type errorScannerDriver struct{}

type errorScannerConn struct{}

func (errorScannerDriver) Open(name string) (driver.Conn, error) {
	return errorScannerConn{}, nil
}

func (errorScannerConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

func (errorScannerConn) Close() error {
	return nil
}

func (errorScannerConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

type errorScannerStmt struct{}

func (errorScannerStmt) Close() error {
	return nil
}

func (errorScannerStmt) NumInput() int {
	return 0
}

func (errorScannerStmt) Query(args []driver.Value) (driver.Rows, error) {
	return alwaysErrorScanner{}, nil
}

func (errorScannerStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, errors.New("not implemented")
}

func main() {
	sql.Register("errscan", errorScannerDriver{})
	db, err := sql.Open("errscan", "")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		err = rows.Scan(&id)
		if err != nil {
			if errors.Is(err, errScan) {
				fmt.Println("扫描时发生了预期的错误:", err)
			} else {
				log.Fatalf("扫描时发生意外错误: %v", err)
			}
			return
		}
	}
}
```

**假设输入与输出:**

在这个例子中，`errorScannerDriver` 返回的 `Rows` 在 `Scan` 时总是返回 `errScan`。当我们执行查询并尝试扫描结果时，`errors.Is(err, errScan)` 会返回 `true`，控制台会输出 "扫描时发生了预期的错误: scan error"。

**命令行参数处理:**

这段代码本身没有直接处理命令行参数。它是一个测试文件，主要通过 Go 的 `testing` 包来运行测试用例和基准测试。

**使用者易犯错的点 (基于代码推理):**

1. **忘记调用 `Rows.Close()`:**  如果在循环中使用 `Rows`，忘记在循环结束或者发生错误时调用 `rows.Close()`，可能会导致数据库连接资源泄露。

   ```go
   rows, err := db.Query("SELECT * FROM users")
   if err != nil {
       log.Fatal(err)
   }
   defer rows.Close() // 应该始终调用

   for rows.Next() {
       // ...
   }
   if err := rows.Err(); err != nil {
       log.Println(err)
   }
   // 如果没有 defer rows.Close()，这里忘记调用可能会导致问题
   ```

2. **不正确地处理 Context 取消:**  如果在执行数据库操作时使用了 Context，但没有正确地检查和处理 Context 的取消信号，可能会导致操作无限期地等待，或者在取消后继续执行不必要的操作。

   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
   defer cancel()

   rows, err := db.QueryContext(ctx, "SELECT * FROM very_large_table")
   if err != nil {
       if errors.Is(err, context.DeadlineExceeded) {
           fmt.Println("查询超时")
       } else {
           log.Fatal(err)
       }
       return
   }
   defer rows.Close()
   // ...
   ```

**总结一下它的功能 (作为第 4 部分):**

作为 `go/src/database/sql/sql_test.go` 的第四部分，这部分代码主要专注于测试 `database/sql` 包在与底层数据库驱动交互时，在 **上下文管理、错误处理、数据类型转换、并发安全性和性能** 等方面的正确性和健壮性。它通过模拟各种场景，包括仅支持 Context 的驱动、返回错误的驱动方法、以及在操作过程中取消 Context 等情况，来验证 `database/sql` 包的行为是否符合预期。此外，还包含了对关键操作的性能基准测试，以确保在高并发场景下的性能表现。  总而言之，这部分测试是确保 `database/sql` 包作为一个稳定可靠的数据库访问接口的关键组成部分。

Prompt: 
```
这是路径为go/src/database/sql/sql_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共4部分，请归纳一下它的功能

"""
 Close() error {
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

"""




```