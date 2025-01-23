Response:
Let's break down the thought process for analyzing the `driver.go` file and generating the explanation.

**1. Understanding the Request:**

The request asks for a breakdown of the `driver.go` file's functionality, focusing on:

* **Listing Functionality:** What are the different parts doing?
* **Inferring Go Language Feature Implementation:** Which broader Go concepts does this code facilitate?
* **Go Code Examples:** How are these features used in practice?  (Crucially, with assumptions for input/output where applicable).
* **Command-Line Arguments:**  Are there any relevant command-line aspects?
* **Common Mistakes:** What are potential pitfalls for users?
* **Language:**  The answer should be in Chinese.

**2. Initial Reading and Keyword Identification:**

The first step is to read through the code, paying attention to comments and interface definitions. Key terms and concepts jump out:

* `package driver`: This immediately tells us it's about defining interfaces for database drivers.
* `database/sql`:  This signifies the relationship to the higher-level `sql` package. The `driver` package is the layer *underneath*.
* `interface`:  The code is full of interfaces (`Driver`, `Conn`, `Stmt`, `Rows`, `Tx`, etc.). This is a core Go concept for abstraction and polymorphism.
* `Connector`, `DriverContext`: These are newer interfaces for managing connections more efficiently.
* `Value`, `NamedValue`:  Representing data being passed to and from the database.
* `Context`: The use of `context.Context` indicates support for cancellation and timeouts.
* `ErrBadConn`, `ErrSkip`, `ErrRemoveArgument`:  Specific error types with special meaning within the `sql` package.
* `Pinger`, `SessionResetter`, `Validator`: Interfaces for connection health management.
* `Execer`, `Queryer`, `Prepare`: Core database operations.
* `TxOptions`, `IsolationLevel`: Transaction-related settings.
* `RowsColumnType...`: Interfaces for describing the schema of query results.

**3. Grouping Functionality by Interface:**

A logical way to organize the explanation is to group related functionalities around the key interfaces. This helps in understanding the responsibilities of each component:

* **Driver and Connector:** How connections are created and managed.
* **Conn:** Represents an active database connection and its core operations (prepare, close, begin transaction).
* **Stmt:** Represents a prepared statement.
* **Rows:** Iterating through query results.
* **Tx:**  Managing transactions (commit, rollback).
* **Result:**  Information about the outcome of non-query operations.
* **Error Handling:**  Special error types and their significance.
* **Optional Interfaces:**  Features that drivers can optionally implement to provide more advanced functionality.
* **Data Handling:** The `Value` and `NamedValue` types.

**4. Inferring Go Language Features:**

Based on the code and identified keywords, we can infer the underlying Go language features being implemented:

* **Interfaces:** The entire package revolves around defining interfaces, a fundamental concept in Go for achieving polymorphism and decoupling.
* **Error Handling:** The use of the `error` interface and specific error types like `ErrBadConn` demonstrates Go's standard error handling mechanism.
* **Context:** The `context.Context` type highlights Go's built-in support for managing operation lifecycles, timeouts, and cancellations.
* **Reflection:** The `reflect` package is implicitly involved in the `RowsColumnTypeScanType` interface, as it deals with obtaining the underlying Go type of database columns.
* **Type System:** The strict typing of Go is evident in the definitions of `Value` and the various interfaces.

**5. Crafting Go Code Examples:**

For each inferred Go language feature, it's crucial to provide concrete examples. This requires making *reasonable assumptions* about how a database driver might implement these interfaces. The examples should illustrate the core concepts. For instance:

* **Interfaces:** Show a simple driver implementing the `Driver` interface and the `Open` method.
* **Error Handling:** Demonstrate checking for `ErrBadConn`.
* **Context:**  Show passing a context to `ExecContext` and how a driver might honor it.
* **NamedValueChecker:**  Illustrate how a driver might use this to handle custom types.
* **Rows:** Show iterating through the rows and accessing column values.

**Important Note for Examples:** The examples don't need to be fully functional database drivers. The goal is to illustrate the *usage* of the interfaces defined in `driver.go`.

**6. Addressing Command-Line Arguments:**

The `driver.go` file itself doesn't deal directly with command-line arguments. However, when using a specific database driver (e.g., MySQL, PostgreSQL), the connection string passed to `sql.Open` often contains connection parameters. This is the relevant link to command-line arguments (or configuration).

**7. Identifying Common Mistakes:**

Think about the common pitfalls when working with database drivers and the `database/sql` package:

* **Not handling `ErrBadConn`:**  This is a critical error for connection pool management.
* **Incorrectly implementing optional interfaces:**  Understanding the nuances of when to return `ErrSkip`.
* **Not respecting context timeouts:** A common issue in concurrent programming.
* **Resource leaks (not closing connections/statements/rows):**  A general programming best practice that's important with database connections.

**8. Structuring the Answer in Chinese:**

The final step is to organize the information logically and present it clearly in Chinese. Use appropriate terminology and ensure the explanations are accurate and easy to understand. Using headings and bullet points makes the information more digestible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on specific database implementations. **Correction:** Shift focus to the *generic* interfaces defined in `driver.go`.
* **Initial thought:** Providing overly complex code examples. **Correction:** Simplify examples to illustrate the core concepts without unnecessary details.
* **Realization:** The connection string in `sql.Open` is the closest link to command-line arguments for driver configuration.
* **Emphasis:**  Highlight the importance of handling `ErrBadConn` and understanding the purpose of the optional interfaces.

By following this structured approach, combining code analysis, conceptual understanding, and practical examples, we can generate a comprehensive and accurate explanation of the `driver.go` file's functionality.这段代码是 Go 语言标准库中 `database/sql/driver` 包的一部分，它定义了数据库驱动需要实现的接口。 它的主要功能是为 Go 的 `database/sql` 包提供了一个标准化的接口，允许不同的数据库系统以统一的方式被访问。

**主要功能列举:**

1. **定义了 `Driver` 接口:** 这是所有数据库驱动必须实现的核心接口，它只有一个方法 `Open`，用于建立与数据库的连接。
2. **定义了 `Conn` 接口:**  表示一个数据库连接，包含了执行 SQL 命令、开始事务、准备语句和关闭连接等方法。
3. **定义了 `Stmt` 接口:**  表示一个预编译的 SQL 语句，可以被多次执行以提高效率。
4. **定义了 `Result` 接口:**  表示执行非查询 SQL 命令（如 INSERT, UPDATE, DELETE）的结果，包含获取最后插入 ID 和影响行数的方法。
5. **定义了 `Rows` 接口:**  表示查询操作返回的结果集，可以迭代访问每一行数据。
6. **定义了 `Tx` 接口:**  表示一个数据库事务，允许将多个操作作为一个原子单元提交或回滚。
7. **定义了 `Value` 类型:**  表示数据库中可以存储和传递的数据类型。
8. **定义了 `NamedValue` 类型:**  用于在执行语句或查询时传递带名称或位置的参数。
9. **定义了 `Connector` 和 `DriverContext` 接口:**  用于更精细地控制连接的创建和复用，以及减少驱动配置的重复解析。
10. **定义了可选的接口，用于增强驱动的功能:** 例如 `Pinger`（用于检测连接是否有效）, `ExecerContext`, `QueryerContext` (支持带上下文的执行和查询), `ConnBeginTx` (支持带选项的事务), `SessionResetter` (用于重置连接状态), `Validator` (用于校验连接是否有效), `NamedValueChecker` (用于自定义参数处理), `RowsNextResultSet` (支持多结果集) 等。
11. **定义了特殊的错误类型:** 例如 `ErrBadConn` (表示连接已失效，需要重建) 和 `ErrSkip` (表示驱动选择跳过某种优化路径)。

**它是什么 Go 语言功能的实现？**

这个包主要实现了 **接口 (Interfaces)** 和 **类型定义 (Type Definitions)**，是 Go 语言中实现抽象和多态性的关键机制。 通过定义接口，`database/sql/driver` 包规定了数据库驱动需要提供的功能，而具体的数据库驱动则通过实现这些接口来提供特定的数据库访问能力。

**Go 代码举例说明:**

假设我们有一个简单的数据库驱动，用于连接一个名为 "mydatabase" 的内存数据库。

```go
package mydriver

import (
	"context"
	"database/sql/driver"
	"errors"
)

// MyDriver 是我们自定义的数据库驱动
type MyDriver struct{}

// Open 实现了 driver.Driver 接口的 Open 方法
func (d MyDriver) Open(name string) (driver.Conn, error) {
	if name != "mydatabase" {
		return nil, errors.New("invalid database name")
	}
	return &MyConn{}, nil
}

// MyConn 是我们的数据库连接
type MyConn struct{}

// Prepare 实现了 driver.Conn 接口的 Prepare 方法
func (c *MyConn) Prepare(query string) (driver.Stmt, error) {
	// 简单的示例，实际实现会更复杂
	return &MyStmt{query: query}, nil
}

// Close 实现了 driver.Conn 接口的 Close 方法
func (c *MyConn) Close() error {
	println("关闭连接")
	return nil
}

// Begin 实现了 driver.Conn 接口的 Begin 方法
func (c *MyConn) Begin() (driver.Tx, error) {
	println("开始事务")
	return &MyTx{}, nil
}

// MyStmt 是我们的预编译语句
type MyStmt struct {
	query string
}

// Close 实现了 driver.Stmt 接口的 Close 方法
func (s *MyStmt) Close() error {
	println("关闭语句")
	return nil
}

// NumInput 实现 driver.Stmt 接口的 NumInput 方法
func (s *MyStmt) NumInput() int {
	// 假设不支持参数
	return 0
}

// Exec 实现 driver.Stmt 接口的 Exec 方法
func (s *MyStmt) Exec(args []driver.Value) (driver.Result, error) {
	println("执行语句:", s.query)
	return driver.RowsAffected(1), nil // 假设影响了一行
}

// Query 实现 driver.Stmt 接口的 Query 方法
func (s *MyStmt) Query(args []driver.Value) (driver.Rows, error) {
	println("执行查询:", s.query)
	return &MyRows{}, nil
}

// MyTx 是我们的事务
type MyTx struct{}

// Commit 实现 driver.Tx 接口的 Commit 方法
func (tx *MyTx) Commit() error {
	println("提交事务")
	return nil
}

// Rollback 实现 driver.Tx 接口的 Rollback 方法
func (tx *MyTx) Rollback() error {
	println("回滚事务")
	return nil
}

// MyRows 是我们的结果集
type MyRows struct {
	currentRow int
	data       [][]driver.Value
}

// Columns 实现 driver.Rows 接口的 Columns 方法
func (r *MyRows) Columns() []string {
	return []string{"id", "name"}
}

// Close 实现 driver.Rows 接口的 Close 方法
func (r *MyRows) Close() error {
	println("关闭结果集")
	return nil
}

// Next 实现 driver.Rows 接口的 Next 方法
func (r *MyRows) Next(dest []driver.Value) error {
	if r.currentRow >= len(r.data) {
		return errors.New("EOF") // 模拟 io.EOF
	}
	dest[0] = r.data[r.currentRow][0]
	dest[1] = r.data[r.currentRow][1]
	r.currentRow++
	return nil
}

func init() {
	// 注册我们的驱动
	driver.Register("mydriver", MyDriver{})
}
```

**假设的输入与输出:**

现在，在你的应用程序中，你可以使用 `database/sql` 包来连接和使用这个自定义驱动：

```go
package main

import (
	"database/sql"
	"fmt"
	"log"
	"mydriver" // 引入我们自定义的驱动
	"os"
)

func main() {
	// 假设注册了名为 "mydriver" 的驱动
	db, err := sql.Open("mydriver", "mydatabase")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 执行非查询语句
	result, err := db.Exec("CREATE TABLE users (id INT, name TEXT)")
	if err != nil {
		log.Fatal(err)
	}
	rowsAffected, _ := result.RowsAffected()
	fmt.Println("影响行数:", rowsAffected) // 输出: 影响行数: 1 (根据 MyStmt.Exec 的假设)

	// 执行查询语句
	rows, err := db.Query("SELECT id, name FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	fmt.Println("列名:", columns) // 输出: 列名: [id name]

	// 模拟数据
	mydriver.MyRows{data: [][]driver.Value{{1, "Alice"}, {2, "Bob"}}}.Next(make([]driver.Value, 2))
	mydriver.MyRows{data: [][]driver.Value{{1, "Alice"}, {2, "Bob"}}}.Next(make([]driver.Value, 2))

	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("ID: %d, Name: %s\n", id, name)
		// 由于 MyRows.Next 的简单实现，这里不会实际输出数据，但会调用到 MyRows 的方法
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
```

**代码推理:**

* `sql.Open("mydriver", "mydatabase")`：  `sql` 包会查找已注册的名为 "mydriver" 的驱动，并调用其 `Open` 方法，传入 "mydatabase" 作为连接字符串。
* `mydriver.MyDriver{}.Open("mydatabase")`：  我们的自定义驱动的 `Open` 方法会被调用，如果连接字符串正确，它会返回一个 `mydriver.MyConn` 类型的连接。
* `db.Exec(...)`：  `sql` 包会调用 `MyConn` 的 `Prepare` 方法来准备语句，然后调用 `MyStmt` 的 `Exec` 方法来执行。
* `db.Query(...)`：  类似地，`sql` 包会调用 `Prepare` 和 `Query` 方法。
* `rows.Next()` 和 `rows.Scan()`：  `sql` 包会调用 `MyRows` 的 `Next` 方法来获取下一行数据，并使用 `Scan` 将 `driver.Value` 转换为 Go 的具体类型。

**命令行参数的具体处理:**

`database/sql/driver` 包本身不直接处理命令行参数。 数据库驱动通常会在其 `Open` 方法中解析连接字符串 (`name` 参数)，而连接字符串的内容可以来自配置文件、环境变量或者命令行参数。

例如，如果你的数据库驱动需要用户名和密码，连接字符串可能是这样的：`"user=myuser password=mypassword@tcp(127.0.0.1:3306)/mydatabase"`。 驱动的 `Open` 方法需要解析这个字符串来提取用户名、密码、主机和数据库名等信息。

**使用者易犯错的点:**

1. **不正确地处理 `ErrBadConn`:**  当数据库连接失效时，驱动应该返回 `ErrBadConn`。 使用者需要理解这个错误的含义，并让 `database/sql` 包能够自动重试或重建连接。  如果驱动没有正确返回 `ErrBadConn`，连接池可能不会正确地管理失效的连接。

   **错误示例:** 驱动在连接断开时返回一个通用的错误，而不是 `driver.ErrBadConn`。

   ```go
   // 错误的实现
   func (c *MyConn) Ping(ctx context.Context) error {
       // 假设连接已断开
       return errors.New("connection lost")
   }
   ```

   **正确做法:**

   ```go
   import "database/sql/driver"

   func (c *MyConn) Ping(ctx context.Context) error {
       // 假设连接已断开
       return driver.ErrBadConn
   }
   ```

2. **在应该实现可选接口时没有实现:**  例如，如果驱动支持上下文，但没有实现 `ExecerContext` 或 `QueryerContext`，那么在使用 `database/sql` 包的 `ExecContext` 或 `QueryContext` 方法时，性能可能不会最优，因为 `database/sql` 包会退回到先 `Prepare` 再 `Exec/Query` 的方式。

3. **没有正确实现 `Close` 方法:** `Conn`、`Stmt` 和 `Rows` 的 `Close` 方法应该释放相关的资源，例如关闭数据库连接或网络连接。 如果 `Close` 方法没有正确实现，可能会导致资源泄漏。

4. **假设 `Conn` 可以被并发安全地访问:** `Conn` 接口的文档明确指出，返回的连接只被一个 goroutine 同时使用。 使用者不应该在多个 goroutine 中共享同一个 `Conn` 实例。

总而言之，`go/src/database/sql/driver/driver.go` 定义了 Go 语言访问各种 SQL 数据库的桥梁，它通过接口规范了数据库驱动的行为，使得上层的 `database/sql` 包能够以统一的方式操作不同的数据库。 理解这些接口的功能和正确实现方式对于开发高质量的 Go 数据库驱动至关重要。

### 提示词
```
这是路径为go/src/database/sql/driver/driver.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package driver defines interfaces to be implemented by database
// drivers as used by package sql.
//
// Most code should use the [database/sql] package.
//
// The driver interface has evolved over time. Drivers should implement
// [Connector] and [DriverContext] interfaces.
// The Connector.Connect and Driver.Open methods should never return [ErrBadConn].
// [ErrBadConn] should only be returned from [Validator], [SessionResetter], or
// a query method if the connection is already in an invalid (e.g. closed) state.
//
// All [Conn] implementations should implement the following interfaces:
// [Pinger], [SessionResetter], and [Validator].
//
// If named parameters or context are supported, the driver's [Conn] should implement:
// [ExecerContext], [QueryerContext], [ConnPrepareContext], and [ConnBeginTx].
//
// To support custom data types, implement [NamedValueChecker]. [NamedValueChecker]
// also allows queries to accept per-query options as a parameter by returning
// [ErrRemoveArgument] from CheckNamedValue.
//
// If multiple result sets are supported, [Rows] should implement [RowsNextResultSet].
// If the driver knows how to describe the types present in the returned result
// it should implement the following interfaces: [RowsColumnTypeScanType],
// [RowsColumnTypeDatabaseTypeName], [RowsColumnTypeLength], [RowsColumnTypeNullable],
// and [RowsColumnTypePrecisionScale]. A given row value may also return a [Rows]
// type, which may represent a database cursor value.
//
// If a [Conn] implements [Validator], then the IsValid method is called
// before returning the connection to the connection pool. If an entry in the
// connection pool implements [SessionResetter], then ResetSession
// is called before reusing the connection for another query. If a connection is
// never returned to the connection pool but is immediately reused, then
// ResetSession is called prior to reuse but IsValid is not called.
package driver

import (
	"context"
	"errors"
	"reflect"
)

// Value is a value that drivers must be able to handle.
// It is either nil, a type handled by a database driver's [NamedValueChecker]
// interface, or an instance of one of these types:
//
//	int64
//	float64
//	bool
//	[]byte
//	string
//	time.Time
//
// If the driver supports cursors, a returned Value may also implement the [Rows] interface
// in this package. This is used, for example, when a user selects a cursor
// such as "select cursor(select * from my_table) from dual". If the [Rows]
// from the select is closed, the cursor [Rows] will also be closed.
type Value any

// NamedValue holds both the value name and value.
type NamedValue struct {
	// If the Name is not empty it should be used for the parameter identifier and
	// not the ordinal position.
	//
	// Name will not have a symbol prefix.
	Name string

	// Ordinal position of the parameter starting from one and is always set.
	Ordinal int

	// Value is the parameter value.
	Value Value
}

// Driver is the interface that must be implemented by a database
// driver.
//
// Database drivers may implement [DriverContext] for access
// to contexts and to parse the name only once for a pool of connections,
// instead of once per connection.
type Driver interface {
	// Open returns a new connection to the database.
	// The name is a string in a driver-specific format.
	//
	// Open may return a cached connection (one previously
	// closed), but doing so is unnecessary; the sql package
	// maintains a pool of idle connections for efficient re-use.
	//
	// The returned connection is only used by one goroutine at a
	// time.
	Open(name string) (Conn, error)
}

// If a [Driver] implements DriverContext, then [database/sql.DB] will call
// OpenConnector to obtain a [Connector] and then invoke
// that [Connector]'s Connect method to obtain each needed connection,
// instead of invoking the [Driver]'s Open method for each connection.
// The two-step sequence allows drivers to parse the name just once
// and also provides access to per-[Conn] contexts.
type DriverContext interface {
	// OpenConnector must parse the name in the same format that Driver.Open
	// parses the name parameter.
	OpenConnector(name string) (Connector, error)
}

// A Connector represents a driver in a fixed configuration
// and can create any number of equivalent Conns for use
// by multiple goroutines.
//
// A Connector can be passed to [database/sql.OpenDB], to allow drivers
// to implement their own [database/sql.DB] constructors, or returned by
// [DriverContext]'s OpenConnector method, to allow drivers
// access to context and to avoid repeated parsing of driver
// configuration.
//
// If a Connector implements [io.Closer], the [database/sql.DB.Close]
// method will call the Close method and return error (if any).
type Connector interface {
	// Connect returns a connection to the database.
	// Connect may return a cached connection (one previously
	// closed), but doing so is unnecessary; the sql package
	// maintains a pool of idle connections for efficient re-use.
	//
	// The provided context.Context is for dialing purposes only
	// (see net.DialContext) and should not be stored or used for
	// other purposes. A default timeout should still be used
	// when dialing as a connection pool may call Connect
	// asynchronously to any query.
	//
	// The returned connection is only used by one goroutine at a
	// time.
	Connect(context.Context) (Conn, error)

	// Driver returns the underlying Driver of the Connector,
	// mainly to maintain compatibility with the Driver method
	// on sql.DB.
	Driver() Driver
}

// ErrSkip may be returned by some optional interfaces' methods to
// indicate at runtime that the fast path is unavailable and the sql
// package should continue as if the optional interface was not
// implemented. ErrSkip is only supported where explicitly
// documented.
var ErrSkip = errors.New("driver: skip fast-path; continue as if unimplemented")

// ErrBadConn should be returned by a driver to signal to the [database/sql]
// package that a driver.[Conn] is in a bad state (such as the server
// having earlier closed the connection) and the [database/sql] package should
// retry on a new connection.
//
// To prevent duplicate operations, ErrBadConn should NOT be returned
// if there's a possibility that the database server might have
// performed the operation. Even if the server sends back an error,
// you shouldn't return ErrBadConn.
//
// Errors will be checked using [errors.Is]. An error may
// wrap ErrBadConn or implement the Is(error) bool method.
var ErrBadConn = errors.New("driver: bad connection")

// Pinger is an optional interface that may be implemented by a [Conn].
//
// If a [Conn] does not implement Pinger, the [database/sql.DB.Ping] and
// [database/sql.DB.PingContext] will check if there is at least one [Conn] available.
//
// If Conn.Ping returns [ErrBadConn], [database/sql.DB.Ping] and [database/sql.DB.PingContext] will remove
// the [Conn] from pool.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Execer is an optional interface that may be implemented by a [Conn].
//
// If a [Conn] implements neither [ExecerContext] nor [Execer],
// the [database/sql.DB.Exec] will first prepare a query, execute the statement,
// and then close the statement.
//
// Exec may return [ErrSkip].
//
// Deprecated: Drivers should implement [ExecerContext] instead.
type Execer interface {
	Exec(query string, args []Value) (Result, error)
}

// ExecerContext is an optional interface that may be implemented by a [Conn].
//
// If a [Conn] does not implement [ExecerContext], the [database/sql.DB.Exec]
// will fall back to [Execer]; if the Conn does not implement Execer either,
// [database/sql.DB.Exec] will first prepare a query, execute the statement, and then
// close the statement.
//
// ExecContext may return [ErrSkip].
//
// ExecContext must honor the context timeout and return when the context is canceled.
type ExecerContext interface {
	ExecContext(ctx context.Context, query string, args []NamedValue) (Result, error)
}

// Queryer is an optional interface that may be implemented by a [Conn].
//
// If a [Conn] implements neither [QueryerContext] nor [Queryer],
// the [database/sql.DB.Query] will first prepare a query, execute the statement,
// and then close the statement.
//
// Query may return [ErrSkip].
//
// Deprecated: Drivers should implement [QueryerContext] instead.
type Queryer interface {
	Query(query string, args []Value) (Rows, error)
}

// QueryerContext is an optional interface that may be implemented by a [Conn].
//
// If a [Conn] does not implement QueryerContext, the [database/sql.DB.Query]
// will fall back to [Queryer]; if the [Conn] does not implement [Queryer] either,
// [database/sql.DB.Query] will first prepare a query, execute the statement, and then
// close the statement.
//
// QueryContext may return [ErrSkip].
//
// QueryContext must honor the context timeout and return when the context is canceled.
type QueryerContext interface {
	QueryContext(ctx context.Context, query string, args []NamedValue) (Rows, error)
}

// Conn is a connection to a database. It is not used concurrently
// by multiple goroutines.
//
// Conn is assumed to be stateful.
type Conn interface {
	// Prepare returns a prepared statement, bound to this connection.
	Prepare(query string) (Stmt, error)

	// Close invalidates and potentially stops any current
	// prepared statements and transactions, marking this
	// connection as no longer in use.
	//
	// Because the sql package maintains a free pool of
	// connections and only calls Close when there's a surplus of
	// idle connections, it shouldn't be necessary for drivers to
	// do their own connection caching.
	//
	// Drivers must ensure all network calls made by Close
	// do not block indefinitely (e.g. apply a timeout).
	Close() error

	// Begin starts and returns a new transaction.
	//
	// Deprecated: Drivers should implement ConnBeginTx instead (or additionally).
	Begin() (Tx, error)
}

// ConnPrepareContext enhances the [Conn] interface with context.
type ConnPrepareContext interface {
	// PrepareContext returns a prepared statement, bound to this connection.
	// context is for the preparation of the statement,
	// it must not store the context within the statement itself.
	PrepareContext(ctx context.Context, query string) (Stmt, error)
}

// IsolationLevel is the transaction isolation level stored in [TxOptions].
//
// This type should be considered identical to [database/sql.IsolationLevel] along
// with any values defined on it.
type IsolationLevel int

// TxOptions holds the transaction options.
//
// This type should be considered identical to [database/sql.TxOptions].
type TxOptions struct {
	Isolation IsolationLevel
	ReadOnly  bool
}

// ConnBeginTx enhances the [Conn] interface with context and [TxOptions].
type ConnBeginTx interface {
	// BeginTx starts and returns a new transaction.
	// If the context is canceled by the user the sql package will
	// call Tx.Rollback before discarding and closing the connection.
	//
	// This must check opts.Isolation to determine if there is a set
	// isolation level. If the driver does not support a non-default
	// level and one is set or if there is a non-default isolation level
	// that is not supported, an error must be returned.
	//
	// This must also check opts.ReadOnly to determine if the read-only
	// value is true to either set the read-only transaction property if supported
	// or return an error if it is not supported.
	BeginTx(ctx context.Context, opts TxOptions) (Tx, error)
}

// SessionResetter may be implemented by [Conn] to allow drivers to reset the
// session state associated with the connection and to signal a bad connection.
type SessionResetter interface {
	// ResetSession is called prior to executing a query on the connection
	// if the connection has been used before. If the driver returns ErrBadConn
	// the connection is discarded.
	ResetSession(ctx context.Context) error
}

// Validator may be implemented by [Conn] to allow drivers to
// signal if a connection is valid or if it should be discarded.
//
// If implemented, drivers may return the underlying error from queries,
// even if the connection should be discarded by the connection pool.
type Validator interface {
	// IsValid is called prior to placing the connection into the
	// connection pool. The connection will be discarded if false is returned.
	IsValid() bool
}

// Result is the result of a query execution.
type Result interface {
	// LastInsertId returns the database's auto-generated ID
	// after, for example, an INSERT into a table with primary
	// key.
	LastInsertId() (int64, error)

	// RowsAffected returns the number of rows affected by the
	// query.
	RowsAffected() (int64, error)
}

// Stmt is a prepared statement. It is bound to a [Conn] and not
// used by multiple goroutines concurrently.
type Stmt interface {
	// Close closes the statement.
	//
	// As of Go 1.1, a Stmt will not be closed if it's in use
	// by any queries.
	//
	// Drivers must ensure all network calls made by Close
	// do not block indefinitely (e.g. apply a timeout).
	Close() error

	// NumInput returns the number of placeholder parameters.
	//
	// If NumInput returns >= 0, the sql package will sanity check
	// argument counts from callers and return errors to the caller
	// before the statement's Exec or Query methods are called.
	//
	// NumInput may also return -1, if the driver doesn't know
	// its number of placeholders. In that case, the sql package
	// will not sanity check Exec or Query argument counts.
	NumInput() int

	// Exec executes a query that doesn't return rows, such
	// as an INSERT or UPDATE.
	//
	// Deprecated: Drivers should implement StmtExecContext instead (or additionally).
	Exec(args []Value) (Result, error)

	// Query executes a query that may return rows, such as a
	// SELECT.
	//
	// Deprecated: Drivers should implement StmtQueryContext instead (or additionally).
	Query(args []Value) (Rows, error)
}

// StmtExecContext enhances the [Stmt] interface by providing Exec with context.
type StmtExecContext interface {
	// ExecContext executes a query that doesn't return rows, such
	// as an INSERT or UPDATE.
	//
	// ExecContext must honor the context timeout and return when it is canceled.
	ExecContext(ctx context.Context, args []NamedValue) (Result, error)
}

// StmtQueryContext enhances the [Stmt] interface by providing Query with context.
type StmtQueryContext interface {
	// QueryContext executes a query that may return rows, such as a
	// SELECT.
	//
	// QueryContext must honor the context timeout and return when it is canceled.
	QueryContext(ctx context.Context, args []NamedValue) (Rows, error)
}

// ErrRemoveArgument may be returned from [NamedValueChecker] to instruct the
// [database/sql] package to not pass the argument to the driver query interface.
// Return when accepting query specific options or structures that aren't
// SQL query arguments.
var ErrRemoveArgument = errors.New("driver: remove argument from query")

// NamedValueChecker may be optionally implemented by [Conn] or [Stmt]. It provides
// the driver more control to handle Go and database types beyond the default
// [Value] types allowed.
//
// The [database/sql] package checks for value checkers in the following order,
// stopping at the first found match: Stmt.NamedValueChecker, Conn.NamedValueChecker,
// Stmt.ColumnConverter, [DefaultParameterConverter].
//
// If CheckNamedValue returns [ErrRemoveArgument], the [NamedValue] will not be included in
// the final query arguments. This may be used to pass special options to
// the query itself.
//
// If [ErrSkip] is returned the column converter error checking
// path is used for the argument. Drivers may wish to return [ErrSkip] after
// they have exhausted their own special cases.
type NamedValueChecker interface {
	// CheckNamedValue is called before passing arguments to the driver
	// and is called in place of any ColumnConverter. CheckNamedValue must do type
	// validation and conversion as appropriate for the driver.
	CheckNamedValue(*NamedValue) error
}

// ColumnConverter may be optionally implemented by [Stmt] if the
// statement is aware of its own columns' types and can convert from
// any type to a driver [Value].
//
// Deprecated: Drivers should implement [NamedValueChecker].
type ColumnConverter interface {
	// ColumnConverter returns a ValueConverter for the provided
	// column index. If the type of a specific column isn't known
	// or shouldn't be handled specially, [DefaultParameterConverter]
	// can be returned.
	ColumnConverter(idx int) ValueConverter
}

// Rows is an iterator over an executed query's results.
type Rows interface {
	// Columns returns the names of the columns. The number of
	// columns of the result is inferred from the length of the
	// slice. If a particular column name isn't known, an empty
	// string should be returned for that entry.
	Columns() []string

	// Close closes the rows iterator.
	Close() error

	// Next is called to populate the next row of data into
	// the provided slice. The provided slice will be the same
	// size as the Columns() are wide.
	//
	// Next should return io.EOF when there are no more rows.
	//
	// The dest should not be written to outside of Next. Care
	// should be taken when closing Rows not to modify
	// a buffer held in dest.
	Next(dest []Value) error
}

// RowsNextResultSet extends the [Rows] interface by providing a way to signal
// the driver to advance to the next result set.
type RowsNextResultSet interface {
	Rows

	// HasNextResultSet is called at the end of the current result set and
	// reports whether there is another result set after the current one.
	HasNextResultSet() bool

	// NextResultSet advances the driver to the next result set even
	// if there are remaining rows in the current result set.
	//
	// NextResultSet should return io.EOF when there are no more result sets.
	NextResultSet() error
}

// RowsColumnTypeScanType may be implemented by [Rows]. It should return
// the value type that can be used to scan types into. For example, the database
// column type "bigint" this should return "[reflect.TypeOf](int64(0))".
type RowsColumnTypeScanType interface {
	Rows
	ColumnTypeScanType(index int) reflect.Type
}

// RowsColumnTypeDatabaseTypeName may be implemented by [Rows]. It should return the
// database system type name without the length. Type names should be uppercase.
// Examples of returned types: "VARCHAR", "NVARCHAR", "VARCHAR2", "CHAR", "TEXT",
// "DECIMAL", "SMALLINT", "INT", "BIGINT", "BOOL", "[]BIGINT", "JSONB", "XML",
// "TIMESTAMP".
type RowsColumnTypeDatabaseTypeName interface {
	Rows
	ColumnTypeDatabaseTypeName(index int) string
}

// RowsColumnTypeLength may be implemented by [Rows]. It should return the length
// of the column type if the column is a variable length type. If the column is
// not a variable length type ok should return false.
// If length is not limited other than system limits, it should return [math.MaxInt64].
// The following are examples of returned values for various types:
//
//	TEXT          (math.MaxInt64, true)
//	varchar(10)   (10, true)
//	nvarchar(10)  (10, true)
//	decimal       (0, false)
//	int           (0, false)
//	bytea(30)     (30, true)
type RowsColumnTypeLength interface {
	Rows
	ColumnTypeLength(index int) (length int64, ok bool)
}

// RowsColumnTypeNullable may be implemented by [Rows]. The nullable value should
// be true if it is known the column may be null, or false if the column is known
// to be not nullable.
// If the column nullability is unknown, ok should be false.
type RowsColumnTypeNullable interface {
	Rows
	ColumnTypeNullable(index int) (nullable, ok bool)
}

// RowsColumnTypePrecisionScale may be implemented by [Rows]. It should return
// the precision and scale for decimal types. If not applicable, ok should be false.
// The following are examples of returned values for various types:
//
//	decimal(38, 4)    (38, 4, true)
//	int               (0, 0, false)
//	decimal           (math.MaxInt64, math.MaxInt64, true)
type RowsColumnTypePrecisionScale interface {
	Rows
	ColumnTypePrecisionScale(index int) (precision, scale int64, ok bool)
}

// Tx is a transaction.
type Tx interface {
	Commit() error
	Rollback() error
}

// RowsAffected implements [Result] for an INSERT or UPDATE operation
// which mutates a number of rows.
type RowsAffected int64

var _ Result = RowsAffected(0)

func (RowsAffected) LastInsertId() (int64, error) {
	return 0, errors.New("LastInsertId is not supported by this driver")
}

func (v RowsAffected) RowsAffected() (int64, error) {
	return int64(v), nil
}

// ResultNoRows is a pre-defined [Result] for drivers to return when a DDL
// command (such as a CREATE TABLE) succeeds. It returns an error for both
// LastInsertId and [RowsAffected].
var ResultNoRows noRows

type noRows struct{}

var _ Result = noRows{}

func (noRows) LastInsertId() (int64, error) {
	return 0, errors.New("no LastInsertId available after DDL statement")
}

func (noRows) RowsAffected() (int64, error) {
	return 0, errors.New("no RowsAffected available after DDL statement")
}
```