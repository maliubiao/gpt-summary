Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `database/sql` package. I need to identify the key features and purpose of this code.

Based on the imports and the structure, this section seems to be responsible for:

1. **Driver Management:**  Registering and managing database drivers.
2. **Connection Pooling:**  Handling the creation, reuse, and closing of database connections.
3. **Transaction Management:**  Defining structures and mechanisms for database transactions.
4. **Data Handling:** Providing types for handling potentially null values and named arguments.
5. **Error Handling:** Defining common errors like `ErrNoRows` and `ErrTxDone`.
这是Go语言 `database/sql` 包的一部分，主要负责以下功能：

1. **数据库驱动管理:**
    *   维护已注册的数据库驱动列表 (`drivers` map)。
    *   提供 `Register` 函数用于注册新的数据库驱动。
    *   提供 `Drivers` 函数返回已注册驱动的名称列表。

2. **数据库连接管理:**
    *   定义了 `DB` 结构体，作为数据库连接池的句柄。
    *   实现了连接的获取 (`conn`)、释放 (`putConn`) 和关闭 (`Close`)。
    *   维护空闲连接池 (`freeConn`)，并根据配置（如 `MaxIdleConns`，`MaxOpenConns`，`MaxLifetime`，`MaxIdleTime`) 管理连接的生命周期。
    *   使用 `driverConn` 结构体封装底层的 `driver.Conn`，并添加了锁和其他状态管理。
    *   实现了连接的健康检查 (`PingContext`)。
    *   通过 `connectionOpener` goroutine 异步创建新的数据库连接。

3. **事务管理:**
    *   定义了 `TxOptions` 结构体，用于指定事务的隔离级别和只读属性。
    *   提供了 `BeginTx` 函数来启动一个新的事务，并返回 `Tx` 结构体。
    *   `Tx` 结构体封装了底层的 `driver.Tx`，并负责事务的提交 (`Commit`) 和回滚 (`Rollback`)。

4. **SQL操作的基础结构:**
    *   定义了 `Stmt` 结构体，表示预编译的 SQL 语句。
    *   定义了 `Rows` 结构体，用于迭代查询结果集。
    *   定义了 `Result` 接口，表示执行 SQL 命令（如 INSERT，UPDATE，DELETE）的结果。
    *   提供了 `ExecContext` 和 `QueryContext` 函数用于执行 SQL 命令和查询。
    *   提供了 `QueryRowContext` 函数用于执行预期返回单行的查询。

5. **参数化查询支持:**
    *   定义了 `NamedArg` 结构体，用于支持具名参数的 SQL 查询。
    *   提供了 `Named` 函数，方便创建 `NamedArg` 实例。

6. **处理NULL值:**
    *   定义了一系列 `Null` 类型（如 `NullString`, `NullInt64`, `NullBool` 等），用于表示可能为 NULL 的数据库字段，并实现了 `Scanner` 和 `driver.Valuer` 接口，方便数据库扫描和参数绑定。

7. **输出参数支持:**
    *   定义了 `Out` 结构体，用于支持存储过程的输出参数。

8. **错误类型定义:**
    *   定义了 `ErrNoRows`，表示查询没有返回任何行。
    *   定义了 `ErrTxDone`，表示事务已经完成（提交或回滚）。
    *   定义了 `ErrConnDone`，表示连接已经关闭。

**它是什么go语言功能的实现：**

这部分代码是 Go 语言标准库中 `database/sql` 包的核心组成部分，它实现了 **数据库的通用接口**。 `database/sql` 本身并不包含任何特定的数据库驱动，而是定义了一组标准接口，允许不同的数据库驱动程序实现这些接口，从而使 Go 程序可以使用统一的方式访问各种 SQL 或类 SQL 数据库。

**Go 代码举例说明（假设输入与输出）：**

假设我们已经注册了一个名为 "mysql" 的 MySQL 驱动。

```go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql" // 导入 MySQL 驱动
)

func main() {
	db, err := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/dbname")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()

	// 查询操作
	var name string
	err = db.QueryRowContext(ctx, "SELECT name FROM users WHERE id = ?", 1).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("没有找到用户") // 假设 id=1 的用户不存在
			// 输出: 没有找到用户
		} else {
			log.Fatal(err)
		}
		return
	}
	fmt.Println("用户名:", name) // 假设 id=1 的用户名为 "Alice"
	// 输出: 用户名: Alice

	// 执行操作
	result, err := db.ExecContext(ctx, "UPDATE users SET name = ? WHERE id = ?", "Bob", 1)
	if err != nil {
		log.Fatal(err)
	}
	rowsAffected, _ := result.RowsAffected()
	fmt.Println("更新的行数:", rowsAffected) // 输出: 更新的行数: 1

	// 事务操作
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, "UPDATE users SET balance = balance - ? WHERE id = ?", 100, 1)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}
	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("事务已提交") // 输出: 事务已提交
}
```

**假设的输入与输出:**

*   **输入 (QueryRowContext):** SQL 查询 "SELECT name FROM users WHERE id = ?" 和参数 `1`。
*   **假设输入数据:** `users` 表中 `id = 1` 的记录的 `name` 字段值为 "Alice"。
*   **输出 (QueryRowContext):**  变量 `name` 的值为 "Alice"。 如果数据库中不存在 `id = 1` 的用户，则会输出 "没有找到用户"。

*   **输入 (ExecContext):** SQL 更新语句 "UPDATE users SET name = ? WHERE id = ?" 和参数 `"Bob"`，`1`。
*   **假设输入数据:** `users` 表中 `id = 1` 的记录存在。
*   **输出 (ExecContext):**  `rowsAffected` 的值为 `1`。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。连接数据库所需的参数（如用户名、密码、主机名、数据库名）通常通过 `sql.Open` 函数的 `dataSourceName` 字符串传递。这个字符串的格式是数据库驱动特定的。

**归纳一下它的功能:**

总而言之，这段 `go/src/database/sql/sql.go` 的代码是 Go 语言 `database/sql` 包的基础核心，它定义了与各种 SQL 数据库进行交互的通用接口和核心机制，包括驱动管理、连接池管理、事务处理、SQL 操作执行以及对 NULL 值和参数化查询的支持。它为 Go 程序提供了一个抽象层，使得开发者可以使用统一的 API 操作不同的数据库，而无需关心底层数据库的具体实现细节。

Prompt: 
```
这是路径为go/src/database/sql/sql.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package sql provides a generic interface around SQL (or SQL-like)
// databases.
//
// The sql package must be used in conjunction with a database driver.
// See https://golang.org/s/sqldrivers for a list of drivers.
//
// Drivers that do not support context cancellation will not return until
// after the query is completed.
//
// For usage examples, see the wiki page at
// https://golang.org/s/sqlwiki.
package sql

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"
)

var driversMu sync.RWMutex

// drivers should be an internal detail,
// but widely used packages access it using linkname.
// (It is extra wrong that they linkname drivers but not driversMu.)
// Notable members of the hall of shame include:
//   - github.com/instana/go-sensor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname drivers
var drivers = make(map[string]driver.Driver)

// nowFunc returns the current time; it's overridden in tests.
var nowFunc = time.Now

// Register makes a database driver available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func Register(name string, driver driver.Driver) {
	driversMu.Lock()
	defer driversMu.Unlock()
	if driver == nil {
		panic("sql: Register driver is nil")
	}
	if _, dup := drivers[name]; dup {
		panic("sql: Register called twice for driver " + name)
	}
	drivers[name] = driver
}

func unregisterAllDrivers() {
	driversMu.Lock()
	defer driversMu.Unlock()
	// For tests.
	drivers = make(map[string]driver.Driver)
}

// Drivers returns a sorted list of the names of the registered drivers.
func Drivers() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()
	return slices.Sorted(maps.Keys(drivers))
}

// A NamedArg is a named argument. NamedArg values may be used as
// arguments to [DB.Query] or [DB.Exec] and bind to the corresponding named
// parameter in the SQL statement.
//
// For a more concise way to create NamedArg values, see
// the [Named] function.
type NamedArg struct {
	_NamedFieldsRequired struct{}

	// Name is the name of the parameter placeholder.
	//
	// If empty, the ordinal position in the argument list will be
	// used.
	//
	// Name must omit any symbol prefix.
	Name string

	// Value is the value of the parameter.
	// It may be assigned the same value types as the query
	// arguments.
	Value any
}

// Named provides a more concise way to create [NamedArg] values.
//
// Example usage:
//
//	db.ExecContext(ctx, `
//	    delete from Invoice
//	    where
//	        TimeCreated < @end
//	        and TimeCreated >= @start;`,
//	    sql.Named("start", startTime),
//	    sql.Named("end", endTime),
//	)
func Named(name string, value any) NamedArg {
	// This method exists because the go1compat promise
	// doesn't guarantee that structs don't grow more fields,
	// so unkeyed struct literals are a vet error. Thus, we don't
	// want to allow sql.NamedArg{name, value}.
	return NamedArg{Name: name, Value: value}
}

// IsolationLevel is the transaction isolation level used in [TxOptions].
type IsolationLevel int

// Various isolation levels that drivers may support in [DB.BeginTx].
// If a driver does not support a given isolation level an error may be returned.
//
// See https://en.wikipedia.org/wiki/Isolation_(database_systems)#Isolation_levels.
const (
	LevelDefault IsolationLevel = iota
	LevelReadUncommitted
	LevelReadCommitted
	LevelWriteCommitted
	LevelRepeatableRead
	LevelSnapshot
	LevelSerializable
	LevelLinearizable
)

// String returns the name of the transaction isolation level.
func (i IsolationLevel) String() string {
	switch i {
	case LevelDefault:
		return "Default"
	case LevelReadUncommitted:
		return "Read Uncommitted"
	case LevelReadCommitted:
		return "Read Committed"
	case LevelWriteCommitted:
		return "Write Committed"
	case LevelRepeatableRead:
		return "Repeatable Read"
	case LevelSnapshot:
		return "Snapshot"
	case LevelSerializable:
		return "Serializable"
	case LevelLinearizable:
		return "Linearizable"
	default:
		return "IsolationLevel(" + strconv.Itoa(int(i)) + ")"
	}
}

var _ fmt.Stringer = LevelDefault

// TxOptions holds the transaction options to be used in [DB.BeginTx].
type TxOptions struct {
	// Isolation is the transaction isolation level.
	// If zero, the driver or database's default level is used.
	Isolation IsolationLevel
	ReadOnly  bool
}

// RawBytes is a byte slice that holds a reference to memory owned by
// the database itself. After a [Rows.Scan] into a RawBytes, the slice is only
// valid until the next call to [Rows.Next], [Rows.Scan], or [Rows.Close].
type RawBytes []byte

// NullString represents a string that may be null.
// NullString implements the [Scanner] interface so
// it can be used as a scan destination:
//
//	var s NullString
//	err := db.QueryRow("SELECT name FROM foo WHERE id=?", id).Scan(&s)
//	...
//	if s.Valid {
//	   // use s.String
//	} else {
//	   // NULL value
//	}
type NullString struct {
	String string
	Valid  bool // Valid is true if String is not NULL
}

// Scan implements the [Scanner] interface.
func (ns *NullString) Scan(value any) error {
	if value == nil {
		ns.String, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return convertAssign(&ns.String, value)
}

// Value implements the [driver.Valuer] interface.
func (ns NullString) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return ns.String, nil
}

// NullInt64 represents an int64 that may be null.
// NullInt64 implements the [Scanner] interface so
// it can be used as a scan destination, similar to [NullString].
type NullInt64 struct {
	Int64 int64
	Valid bool // Valid is true if Int64 is not NULL
}

// Scan implements the [Scanner] interface.
func (n *NullInt64) Scan(value any) error {
	if value == nil {
		n.Int64, n.Valid = 0, false
		return nil
	}
	n.Valid = true
	return convertAssign(&n.Int64, value)
}

// Value implements the [driver.Valuer] interface.
func (n NullInt64) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return n.Int64, nil
}

// NullInt32 represents an int32 that may be null.
// NullInt32 implements the [Scanner] interface so
// it can be used as a scan destination, similar to [NullString].
type NullInt32 struct {
	Int32 int32
	Valid bool // Valid is true if Int32 is not NULL
}

// Scan implements the [Scanner] interface.
func (n *NullInt32) Scan(value any) error {
	if value == nil {
		n.Int32, n.Valid = 0, false
		return nil
	}
	n.Valid = true
	return convertAssign(&n.Int32, value)
}

// Value implements the [driver.Valuer] interface.
func (n NullInt32) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return int64(n.Int32), nil
}

// NullInt16 represents an int16 that may be null.
// NullInt16 implements the [Scanner] interface so
// it can be used as a scan destination, similar to [NullString].
type NullInt16 struct {
	Int16 int16
	Valid bool // Valid is true if Int16 is not NULL
}

// Scan implements the [Scanner] interface.
func (n *NullInt16) Scan(value any) error {
	if value == nil {
		n.Int16, n.Valid = 0, false
		return nil
	}
	err := convertAssign(&n.Int16, value)
	n.Valid = err == nil
	return err
}

// Value implements the [driver.Valuer] interface.
func (n NullInt16) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return int64(n.Int16), nil
}

// NullByte represents a byte that may be null.
// NullByte implements the [Scanner] interface so
// it can be used as a scan destination, similar to [NullString].
type NullByte struct {
	Byte  byte
	Valid bool // Valid is true if Byte is not NULL
}

// Scan implements the [Scanner] interface.
func (n *NullByte) Scan(value any) error {
	if value == nil {
		n.Byte, n.Valid = 0, false
		return nil
	}
	err := convertAssign(&n.Byte, value)
	n.Valid = err == nil
	return err
}

// Value implements the [driver.Valuer] interface.
func (n NullByte) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return int64(n.Byte), nil
}

// NullFloat64 represents a float64 that may be null.
// NullFloat64 implements the [Scanner] interface so
// it can be used as a scan destination, similar to [NullString].
type NullFloat64 struct {
	Float64 float64
	Valid   bool // Valid is true if Float64 is not NULL
}

// Scan implements the [Scanner] interface.
func (n *NullFloat64) Scan(value any) error {
	if value == nil {
		n.Float64, n.Valid = 0, false
		return nil
	}
	n.Valid = true
	return convertAssign(&n.Float64, value)
}

// Value implements the [driver.Valuer] interface.
func (n NullFloat64) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return n.Float64, nil
}

// NullBool represents a bool that may be null.
// NullBool implements the [Scanner] interface so
// it can be used as a scan destination, similar to [NullString].
type NullBool struct {
	Bool  bool
	Valid bool // Valid is true if Bool is not NULL
}

// Scan implements the [Scanner] interface.
func (n *NullBool) Scan(value any) error {
	if value == nil {
		n.Bool, n.Valid = false, false
		return nil
	}
	n.Valid = true
	return convertAssign(&n.Bool, value)
}

// Value implements the [driver.Valuer] interface.
func (n NullBool) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return n.Bool, nil
}

// NullTime represents a [time.Time] that may be null.
// NullTime implements the [Scanner] interface so
// it can be used as a scan destination, similar to [NullString].
type NullTime struct {
	Time  time.Time
	Valid bool // Valid is true if Time is not NULL
}

// Scan implements the [Scanner] interface.
func (n *NullTime) Scan(value any) error {
	if value == nil {
		n.Time, n.Valid = time.Time{}, false
		return nil
	}
	n.Valid = true
	return convertAssign(&n.Time, value)
}

// Value implements the [driver.Valuer] interface.
func (n NullTime) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return n.Time, nil
}

// Null represents a value that may be null.
// Null implements the [Scanner] interface so
// it can be used as a scan destination:
//
//	var s Null[string]
//	err := db.QueryRow("SELECT name FROM foo WHERE id=?", id).Scan(&s)
//	...
//	if s.Valid {
//	   // use s.V
//	} else {
//	   // NULL value
//	}
//
// T should be one of the types accepted by [driver.Value].
type Null[T any] struct {
	V     T
	Valid bool
}

func (n *Null[T]) Scan(value any) error {
	if value == nil {
		n.V, n.Valid = *new(T), false
		return nil
	}
	n.Valid = true
	return convertAssign(&n.V, value)
}

func (n Null[T]) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	v := any(n.V)
	// See issue 69728.
	if valuer, ok := v.(driver.Valuer); ok {
		val, err := callValuerValue(valuer)
		if err != nil {
			return val, err
		}
		v = val
	}
	// See issue 69837.
	return driver.DefaultParameterConverter.ConvertValue(v)
}

// Scanner is an interface used by [Rows.Scan].
type Scanner interface {
	// Scan assigns a value from a database driver.
	//
	// The src value will be of one of the following types:
	//
	//    int64
	//    float64
	//    bool
	//    []byte
	//    string
	//    time.Time
	//    nil - for NULL values
	//
	// An error should be returned if the value cannot be stored
	// without loss of information.
	//
	// Reference types such as []byte are only valid until the next call to Scan
	// and should not be retained. Their underlying memory is owned by the driver.
	// If retention is necessary, copy their values before the next call to Scan.
	Scan(src any) error
}

// Out may be used to retrieve OUTPUT value parameters from stored procedures.
//
// Not all drivers and databases support OUTPUT value parameters.
//
// Example usage:
//
//	var outArg string
//	_, err := db.ExecContext(ctx, "ProcName", sql.Named("Arg1", sql.Out{Dest: &outArg}))
type Out struct {
	_NamedFieldsRequired struct{}

	// Dest is a pointer to the value that will be set to the result of the
	// stored procedure's OUTPUT parameter.
	Dest any

	// In is whether the parameter is an INOUT parameter. If so, the input value to the stored
	// procedure is the dereferenced value of Dest's pointer, which is then replaced with
	// the output value.
	In bool
}

// ErrNoRows is returned by [Row.Scan] when [DB.QueryRow] doesn't return a
// row. In such a case, QueryRow returns a placeholder [*Row] value that
// defers this error until a Scan.
var ErrNoRows = errors.New("sql: no rows in result set")

// DB is a database handle representing a pool of zero or more
// underlying connections. It's safe for concurrent use by multiple
// goroutines.
//
// The sql package creates and frees connections automatically; it
// also maintains a free pool of idle connections. If the database has
// a concept of per-connection state, such state can be reliably observed
// within a transaction ([Tx]) or connection ([Conn]). Once [DB.Begin] is called, the
// returned [Tx] is bound to a single connection. Once [Tx.Commit] or
// [Tx.Rollback] is called on the transaction, that transaction's
// connection is returned to [DB]'s idle connection pool. The pool size
// can be controlled with [DB.SetMaxIdleConns].
type DB struct {
	// Total time waited for new connections.
	waitDuration atomic.Int64

	connector driver.Connector
	// numClosed is an atomic counter which represents a total number of
	// closed connections. Stmt.openStmt checks it before cleaning closed
	// connections in Stmt.css.
	numClosed atomic.Uint64

	mu           sync.Mutex    // protects following fields
	freeConn     []*driverConn // free connections ordered by returnedAt oldest to newest
	connRequests connRequestSet
	numOpen      int // number of opened and pending open connections
	// Used to signal the need for new connections
	// a goroutine running connectionOpener() reads on this chan and
	// maybeOpenNewConnections sends on the chan (one send per needed connection)
	// It is closed during db.Close(). The close tells the connectionOpener
	// goroutine to exit.
	openerCh          chan struct{}
	closed            bool
	dep               map[finalCloser]depSet
	lastPut           map[*driverConn]string // stacktrace of last conn's put; debug only
	maxIdleCount      int                    // zero means defaultMaxIdleConns; negative means 0
	maxOpen           int                    // <= 0 means unlimited
	maxLifetime       time.Duration          // maximum amount of time a connection may be reused
	maxIdleTime       time.Duration          // maximum amount of time a connection may be idle before being closed
	cleanerCh         chan struct{}
	waitCount         int64 // Total number of connections waited for.
	maxIdleClosed     int64 // Total number of connections closed due to idle count.
	maxIdleTimeClosed int64 // Total number of connections closed due to idle time.
	maxLifetimeClosed int64 // Total number of connections closed due to max connection lifetime limit.

	stop func() // stop cancels the connection opener.
}

// connReuseStrategy determines how (*DB).conn returns database connections.
type connReuseStrategy uint8

const (
	// alwaysNewConn forces a new connection to the database.
	alwaysNewConn connReuseStrategy = iota
	// cachedOrNewConn returns a cached connection, if available, else waits
	// for one to become available (if MaxOpenConns has been reached) or
	// creates a new database connection.
	cachedOrNewConn
)

// driverConn wraps a driver.Conn with a mutex, to
// be held during all calls into the Conn. (including any calls onto
// interfaces returned via that Conn, such as calls on Tx, Stmt,
// Result, Rows)
type driverConn struct {
	db        *DB
	createdAt time.Time

	sync.Mutex  // guards following
	ci          driver.Conn
	needReset   bool // The connection session should be reset before use if true.
	closed      bool
	finalClosed bool // ci.Close has been called
	openStmt    map[*driverStmt]bool

	// guarded by db.mu
	inUse      bool
	dbmuClosed bool      // same as closed, but guarded by db.mu, for removeClosedStmtLocked
	returnedAt time.Time // Time the connection was created or returned.
	onPut      []func()  // code (with db.mu held) run when conn is next returned
}

func (dc *driverConn) releaseConn(err error) {
	dc.db.putConn(dc, err, true)
}

func (dc *driverConn) removeOpenStmt(ds *driverStmt) {
	dc.Lock()
	defer dc.Unlock()
	delete(dc.openStmt, ds)
}

func (dc *driverConn) expired(timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	return dc.createdAt.Add(timeout).Before(nowFunc())
}

// resetSession checks if the driver connection needs the
// session to be reset and if required, resets it.
func (dc *driverConn) resetSession(ctx context.Context) error {
	dc.Lock()
	defer dc.Unlock()

	if !dc.needReset {
		return nil
	}
	if cr, ok := dc.ci.(driver.SessionResetter); ok {
		return cr.ResetSession(ctx)
	}
	return nil
}

// validateConnection checks if the connection is valid and can
// still be used. It also marks the session for reset if required.
func (dc *driverConn) validateConnection(needsReset bool) bool {
	dc.Lock()
	defer dc.Unlock()

	if needsReset {
		dc.needReset = true
	}
	if cv, ok := dc.ci.(driver.Validator); ok {
		return cv.IsValid()
	}
	return true
}

// prepareLocked prepares the query on dc. When cg == nil the dc must keep track of
// the prepared statements in a pool.
func (dc *driverConn) prepareLocked(ctx context.Context, cg stmtConnGrabber, query string) (*driverStmt, error) {
	si, err := ctxDriverPrepare(ctx, dc.ci, query)
	if err != nil {
		return nil, err
	}
	ds := &driverStmt{Locker: dc, si: si}

	// No need to manage open statements if there is a single connection grabber.
	if cg != nil {
		return ds, nil
	}

	// Track each driverConn's open statements, so we can close them
	// before closing the conn.
	//
	// Wrap all driver.Stmt is *driverStmt to ensure they are only closed once.
	if dc.openStmt == nil {
		dc.openStmt = make(map[*driverStmt]bool)
	}
	dc.openStmt[ds] = true
	return ds, nil
}

// the dc.db's Mutex is held.
func (dc *driverConn) closeDBLocked() func() error {
	dc.Lock()
	defer dc.Unlock()
	if dc.closed {
		return func() error { return errors.New("sql: duplicate driverConn close") }
	}
	dc.closed = true
	return dc.db.removeDepLocked(dc, dc)
}

func (dc *driverConn) Close() error {
	dc.Lock()
	if dc.closed {
		dc.Unlock()
		return errors.New("sql: duplicate driverConn close")
	}
	dc.closed = true
	dc.Unlock() // not defer; removeDep finalClose calls may need to lock

	// And now updates that require holding dc.mu.Lock.
	dc.db.mu.Lock()
	dc.dbmuClosed = true
	fn := dc.db.removeDepLocked(dc, dc)
	dc.db.mu.Unlock()
	return fn()
}

func (dc *driverConn) finalClose() error {
	var err error

	// Each *driverStmt has a lock to the dc. Copy the list out of the dc
	// before calling close on each stmt.
	var openStmt []*driverStmt
	withLock(dc, func() {
		openStmt = make([]*driverStmt, 0, len(dc.openStmt))
		for ds := range dc.openStmt {
			openStmt = append(openStmt, ds)
		}
		dc.openStmt = nil
	})
	for _, ds := range openStmt {
		ds.Close()
	}
	withLock(dc, func() {
		dc.finalClosed = true
		err = dc.ci.Close()
		dc.ci = nil
	})

	dc.db.mu.Lock()
	dc.db.numOpen--
	dc.db.maybeOpenNewConnections()
	dc.db.mu.Unlock()

	dc.db.numClosed.Add(1)
	return err
}

// driverStmt associates a driver.Stmt with the
// *driverConn from which it came, so the driverConn's lock can be
// held during calls.
type driverStmt struct {
	sync.Locker // the *driverConn
	si          driver.Stmt
	closed      bool
	closeErr    error // return value of previous Close call
}

// Close ensures driver.Stmt is only closed once and always returns the same
// result.
func (ds *driverStmt) Close() error {
	ds.Lock()
	defer ds.Unlock()
	if ds.closed {
		return ds.closeErr
	}
	ds.closed = true
	ds.closeErr = ds.si.Close()
	return ds.closeErr
}

// depSet is a finalCloser's outstanding dependencies
type depSet map[any]bool // set of true bools

// The finalCloser interface is used by (*DB).addDep and related
// dependency reference counting.
type finalCloser interface {
	// finalClose is called when the reference count of an object
	// goes to zero. (*DB).mu is not held while calling it.
	finalClose() error
}

// addDep notes that x now depends on dep, and x's finalClose won't be
// called until all of x's dependencies are removed with removeDep.
func (db *DB) addDep(x finalCloser, dep any) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.addDepLocked(x, dep)
}

func (db *DB) addDepLocked(x finalCloser, dep any) {
	if db.dep == nil {
		db.dep = make(map[finalCloser]depSet)
	}
	xdep := db.dep[x]
	if xdep == nil {
		xdep = make(depSet)
		db.dep[x] = xdep
	}
	xdep[dep] = true
}

// removeDep notes that x no longer depends on dep.
// If x still has dependencies, nil is returned.
// If x no longer has any dependencies, its finalClose method will be
// called and its error value will be returned.
func (db *DB) removeDep(x finalCloser, dep any) error {
	db.mu.Lock()
	fn := db.removeDepLocked(x, dep)
	db.mu.Unlock()
	return fn()
}

func (db *DB) removeDepLocked(x finalCloser, dep any) func() error {
	xdep, ok := db.dep[x]
	if !ok {
		panic(fmt.Sprintf("unpaired removeDep: no deps for %T", x))
	}

	l0 := len(xdep)
	delete(xdep, dep)

	switch len(xdep) {
	case l0:
		// Nothing removed. Shouldn't happen.
		panic(fmt.Sprintf("unpaired removeDep: no %T dep on %T", dep, x))
	case 0:
		// No more dependencies.
		delete(db.dep, x)
		return x.finalClose
	default:
		// Dependencies remain.
		return func() error { return nil }
	}
}

// This is the size of the connectionOpener request chan (DB.openerCh).
// This value should be larger than the maximum typical value
// used for DB.maxOpen. If maxOpen is significantly larger than
// connectionRequestQueueSize then it is possible for ALL calls into the *DB
// to block until the connectionOpener can satisfy the backlog of requests.
var connectionRequestQueueSize = 1000000

type dsnConnector struct {
	dsn    string
	driver driver.Driver
}

func (t dsnConnector) Connect(_ context.Context) (driver.Conn, error) {
	return t.driver.Open(t.dsn)
}

func (t dsnConnector) Driver() driver.Driver {
	return t.driver
}

// OpenDB opens a database using a [driver.Connector], allowing drivers to
// bypass a string based data source name.
//
// Most users will open a database via a driver-specific connection
// helper function that returns a [*DB]. No database drivers are included
// in the Go standard library. See https://golang.org/s/sqldrivers for
// a list of third-party drivers.
//
// OpenDB may just validate its arguments without creating a connection
// to the database. To verify that the data source name is valid, call
// [DB.Ping].
//
// The returned [DB] is safe for concurrent use by multiple goroutines
// and maintains its own pool of idle connections. Thus, the OpenDB
// function should be called just once. It is rarely necessary to
// close a [DB].
func OpenDB(c driver.Connector) *DB {
	ctx, cancel := context.WithCancel(context.Background())
	db := &DB{
		connector: c,
		openerCh:  make(chan struct{}, connectionRequestQueueSize),
		lastPut:   make(map[*driverConn]string),
		stop:      cancel,
	}

	go db.connectionOpener(ctx)

	return db
}

// Open opens a database specified by its database driver name and a
// driver-specific data source name, usually consisting of at least a
// database name and connection information.
//
// Most users will open a database via a driver-specific connection
// helper function that returns a [*DB]. No database drivers are included
// in the Go standard library. See https://golang.org/s/sqldrivers for
// a list of third-party drivers.
//
// Open may just validate its arguments without creating a connection
// to the database. To verify that the data source name is valid, call
// [DB.Ping].
//
// The returned [DB] is safe for concurrent use by multiple goroutines
// and maintains its own pool of idle connections. Thus, the Open
// function should be called just once. It is rarely necessary to
// close a [DB].
func Open(driverName, dataSourceName string) (*DB, error) {
	driversMu.RLock()
	driveri, ok := drivers[driverName]
	driversMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("sql: unknown driver %q (forgotten import?)", driverName)
	}

	if driverCtx, ok := driveri.(driver.DriverContext); ok {
		connector, err := driverCtx.OpenConnector(dataSourceName)
		if err != nil {
			return nil, err
		}
		return OpenDB(connector), nil
	}

	return OpenDB(dsnConnector{dsn: dataSourceName, driver: driveri}), nil
}

func (db *DB) pingDC(ctx context.Context, dc *driverConn, release func(error)) error {
	var err error
	if pinger, ok := dc.ci.(driver.Pinger); ok {
		withLock(dc, func() {
			err = pinger.Ping(ctx)
		})
	}
	release(err)
	return err
}

// PingContext verifies a connection to the database is still alive,
// establishing a connection if necessary.
func (db *DB) PingContext(ctx context.Context) error {
	var dc *driverConn
	var err error

	err = db.retry(func(strategy connReuseStrategy) error {
		dc, err = db.conn(ctx, strategy)
		return err
	})

	if err != nil {
		return err
	}

	return db.pingDC(ctx, dc, dc.releaseConn)
}

// Ping verifies a connection to the database is still alive,
// establishing a connection if necessary.
//
// Ping uses [context.Background] internally; to specify the context, use
// [DB.PingContext].
func (db *DB) Ping() error {
	return db.PingContext(context.Background())
}

// Close closes the database and prevents new queries from starting.
// Close then waits for all queries that have started processing on the server
// to finish.
//
// It is rare to Close a [DB], as the [DB] handle is meant to be
// long-lived and shared between many goroutines.
func (db *DB) Close() error {
	db.mu.Lock()
	if db.closed { // Make DB.Close idempotent
		db.mu.Unlock()
		return nil
	}
	if db.cleanerCh != nil {
		close(db.cleanerCh)
	}
	var err error
	fns := make([]func() error, 0, len(db.freeConn))
	for _, dc := range db.freeConn {
		fns = append(fns, dc.closeDBLocked())
	}
	db.freeConn = nil
	db.closed = true
	db.connRequests.CloseAndRemoveAll()
	db.mu.Unlock()
	for _, fn := range fns {
		err1 := fn()
		if err1 != nil {
			err = err1
		}
	}
	db.stop()
	if c, ok := db.connector.(io.Closer); ok {
		err1 := c.Close()
		if err1 != nil {
			err = err1
		}
	}
	return err
}

const defaultMaxIdleConns = 2

func (db *DB) maxIdleConnsLocked() int {
	n := db.maxIdleCount
	switch {
	case n == 0:
		// TODO(bradfitz): ask driver, if supported, for its default preference
		return defaultMaxIdleConns
	case n < 0:
		return 0
	default:
		return n
	}
}

func (db *DB) shortestIdleTimeLocked() time.Duration {
	if db.maxIdleTime <= 0 {
		return db.maxLifetime
	}
	if db.maxLifetime <= 0 {
		return db.maxIdleTime
	}
	return min(db.maxIdleTime, db.maxLifetime)
}

// SetMaxIdleConns sets the maximum number of connections in the idle
// connection pool.
//
// If MaxOpenConns is greater than 0 but less than the new MaxIdleConns,
// then the new MaxIdleConns will be reduced to match the MaxOpenConns limit.
//
// If n <= 0, no idle connections are retained.
//
// The default max idle connections is currently 2. This may change in
// a future release.
func (db *DB) SetMaxIdleConns(n int) {
	db.mu.Lock()
	if n > 0 {
		db.maxIdleCount = n
	} else {
		// No idle connections.
		db.maxIdleCount = -1
	}
	// Make sure maxIdle doesn't exceed maxOpen
	if db.maxOpen > 0 && db.maxIdleConnsLocked() > db.maxOpen {
		db.maxIdleCount = db.maxOpen
	}
	var closing []*driverConn
	idleCount := len(db.freeConn)
	maxIdle := db.maxIdleConnsLocked()
	if idleCount > maxIdle {
		closing = db.freeConn[maxIdle:]
		db.freeConn = db.freeConn[:maxIdle]
	}
	db.maxIdleClosed += int64(len(closing))
	db.mu.Unlock()
	for _, c := range closing {
		c.Close()
	}
}

// SetMaxOpenConns sets the maximum number of open connections to the database.
//
// If MaxIdleConns is greater than 0 and the new MaxOpenConns is less than
// MaxIdleConns, then MaxIdleConns will be reduced to match the new
// MaxOpenConns limit.
//
// If n <= 0, then there is no limit on the number of open connections.
// The default is 0 (unlimited).
func (db *DB) SetMaxOpenConns(n int) {
	db.mu.Lock()
	db.maxOpen = n
	if n < 0 {
		db.maxOpen = 0
	}
	syncMaxIdle := db.maxOpen > 0 && db.maxIdleConnsLocked() > db.maxOpen
	db.mu.Unlock()
	if syncMaxIdle {
		db.SetMaxIdleConns(n)
	}
}

// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
//
// Expired connections may be closed lazily before reuse.
//
// If d <= 0, connections are not closed due to a connection's age.
func (db *DB) SetConnMaxLifetime(d time.Duration) {
	if d < 0 {
		d = 0
	}
	db.mu.Lock()
	// Wake cleaner up when lifetime is shortened.
	if d > 0 && d < db.maxLifetime && db.cleanerCh != nil {
		select {
		case db.cleanerCh <- struct{}{}:
		default:
		}
	}
	db.maxLifetime = d
	db.startCleanerLocked()
	db.mu.Unlock()
}

// SetConnMaxIdleTime sets the maximum amount of time a connection may be idle.
//
// Expired connections may be closed lazily before reuse.
//
// If d <= 0, connections are not closed due to a connection's idle time.
func (db *DB) SetConnMaxIdleTime(d time.Duration) {
	if d < 0 {
		d = 0
	}
	db.mu.Lock()
	defer db.mu.Unlock()

	// Wake cleaner up when idle time is shortened.
	if d > 0 && d < db.maxIdleTime && db.cleanerCh != nil {
		select {
		case db.cleanerCh <- struct{}{}:
		default:
		}
	}
	db.maxIdleTime = d
	db.startCleanerLocked()
}

// startCleanerLocked starts connectionCleaner if needed.
func (db *DB) startCleanerLocked() {
	if (db.maxLifetime > 0 || db.maxIdleTime > 0) && db.numOpen > 0 && db.cleanerCh == nil {
		db.cleanerCh = make(chan struct{}, 1)
		go db.connectionCleaner(db.shortestIdleTimeLocked())
	}
}

func (db *DB) connectionCleaner(d time.Duration) {
	const minInterval = time.Second

	if d < minInterval {
		d = minInterval
	}
	t := time.NewTimer(d)

	for {
		select {
		case <-t.C:
		case <-db.cleanerCh: // maxLifetime was changed or db was closed.
		}

		db.mu.Lock()

		d = db.shortestIdleTimeLocked()
		if db.closed || db.numOpen == 0 || d <= 0 {
			db.cleanerCh = nil
			db.mu.Unlock()
			return
		}

		d, closing := db.connectionCleanerRunLocked(d)
		db.mu.Unlock()
		for _, c := range closing {
			c.Close()
		}

		if d < minInterval {
			d = minInterval
		}

		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(d)
	}
}

// connectionCleanerRunLocked removes connections that should be closed from
// freeConn and returns them along side an updated duration to the next check
// if a quicker check is required to ensure connections are checked appropriately.
func (db *DB) connectionCleanerRunLocked(d time.Duration) (time.Duration, []*driverConn) {
	var idleClosing int64
	var closing []*driverConn
	if db.maxIdleTime > 0 {
		// As freeConn is ordered by returnedAt process
		// in reverse order to minimise the work needed.
		idleSince := nowFunc().Add(-db.maxIdleTime)
		last := len(db.freeConn) - 1
		for i := last; i >= 0; i-- {
			c := db.freeConn[i]
			if c.returnedAt.Before(idleSince) {
				i++
				closing = db.freeConn[:i:i]
				db.freeConn = db.freeConn[i:]
				idleClosing = int64(len(closing))
				db.maxIdleTimeClosed += idleClosing
				break
			}
		}

		if len(db.freeConn) > 0 {
			c := db.freeConn[0]
			if d2 := c.returnedAt.Sub(idleSince); d2 < d {
				// Ensure idle connections are cleaned up as soon as
				// possible.
				d = d2
			}
		}
	}

	if db.maxLifetime > 0 {
		expiredSince := nowFunc().Add(-db.maxLifetime)
		for i := 0; i < len(db.freeConn); i++ {
			c := db.freeConn[i]
			if c.createdAt.Before(expiredSince) {
				closing = append(closing, c)

				last := len(db.freeConn) - 1
				// Use slow delete as order is required to ensure
				// connections are reused least idle time first.
				copy(db.freeConn[i:], db.freeConn[i+1:])
				db.freeConn[last] = nil
				db.freeConn = db.freeConn[:last]
				i--
			} else if d2 := c.createdAt.Sub(expiredSince); d2 < d {
				// Prevent connections sitting the freeConn when they
				// have expired by updating our next deadline d.
				d = d2
			}
		}
		db.maxLifetimeClosed += int64(len(closing)) - idleClosing
	}

	return d, closing
}

// DBStats contains database statistics.
type DBStats struct {
	MaxOpenConnections int // Maximum number of open connections to the database.

	// Pool Status
	OpenConnections int // The number of established connections both in use and idle.
	InUse           int // The number of connections currently in use.
	Idle            int // The number of idle connections.

	// Counters
	WaitCount         int64         // The total number of connections waited for.
	WaitDuration      time.Duration // The total time blocked waiting for a new connection.
	MaxIdleClosed     int64         // The total number of connections closed due to SetMaxIdleConns.
	MaxIdleTimeClosed int64         // The total number of connections closed due to SetConnMaxIdleTime.
	MaxLifetimeClosed int64         // The total number of connections closed due to SetConnMaxLifetime.
}

// Stats returns database statistics.
func (db *DB) Stats() DBStats {
	wait := db.waitDuration.Load()

	db.mu.Lock()
	defer db.mu.Unlock()

	stats := DBStats{
		MaxOpenConnections: db.maxOpen,

		Idle:            len(db.freeConn),
		OpenConnections: db.numOpen,
		InUse:           db.numOpen - len(db.freeConn),

		WaitCount:         db.waitCount,
		WaitDuration:      time.Duration(wait),
		MaxIdleClosed:     db.maxIdleClosed,
		MaxIdleTimeClosed: db.maxIdleTimeClosed,
		MaxLifetimeClosed: db.maxLifetimeClosed,
	}
	return stats
}

// Assumes db.mu is locked.
// If there are connRequests and the connection limit hasn't been reached,
// then tell the connectionOpener to open new connections.
func (db *DB) maybeOpenNewConnections() {
	numRequests := db.connRequests.Len()
	if db.maxOpen > 0 {
		numCanOpen := db.maxOpen - db.numOpen
		if numRequests > numCanOpen {
			numRequests = numCanOpen
		}
	}
	for numRequests > 0 {
		db.numOpen++ // optimistically
		numRequests--
		if db.closed {
			return
		}
		db.openerCh <- struct{}{}
	}
}

// Runs in a separate goroutine, opens new connections when requested.
func (db *DB) connectionOpener(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-db.openerCh:
			db.openNewConnection(ctx)
		}
	}
}

// Open one new connection
func (db *DB) openNewConnection(ctx context.Context) {
	// maybeOpenNewConnections has already executed db.numOpen++ before it sent
	// on db.openerCh. This function must execute db.numOpen-- if the
	// connection fails or is closed before returning.
	ci, err := db.connector.Connect(ctx)
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		if err == nil {
			ci.Close()
		}
		db.numOpen--
		return
	}
	if err != nil {
		db.numOpen--
		db.putConnDBLocked(nil, err)
		db.maybeOpenNewConnections()
		return
	}
	dc := &driverConn{
		db:         db,
		createdAt:  nowFunc(),
		returnedAt: nowFunc(),
		ci:         ci,
	}
	if db.putConnDBLocked(dc, err) {
		db.addDepLocked(dc, dc)
	} else {
		db.numOpen--
		ci.Close()
	}
}

// connRequest represents one request for a new connection
// When there are no idle connections available, DB.conn will create
// a new connRequest and put it on the db.connRequests list.
type connRequest struct {
	conn *driverConn
	err  error
}

var errDBClosed = errors.New("sql: database is closed")

// conn returns a newly-opened or cached *driverConn.
func (db *DB) conn(ctx context.Context, strategy connReuseStrategy) (*driverConn, error) {
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		return nil, errDBClosed
	}
	// Check if the context is expired.
	select {
	default:
	case <-ctx.Done():
		db.mu.Unlock()
		return nil, ctx.Err()
	}
	lifetime := db.maxLifetime

	// Prefer a free connection, if possible.
	last := len(db.freeConn) - 1
	if strategy == cachedOrNewConn && last >= 0 {
		// Reuse the lowest idle time connection so we can close
		// connections which remain idle as soon as possible.
		conn := db.freeConn[last]
		db.freeConn = db.freeConn[:last]
		conn.inUse = true
		if conn.expired(lifetime) {
			db.maxLifetimeClosed++
			db.mu.Unlock()
			conn.Close()
			return nil, driver.ErrBadConn
		}
		db.mu.Unlock()

		// Reset the session if required.
		if err := conn.resetSession(ctx); errors.Is(err, driver.ErrBadConn) {
			conn.Close()
			return nil, err
		}

		return conn, nil
	}

	// Out of free connections or we were asked not to use one. If we're not
	// allowed to open any more connections, make a request and wait.
	if db.maxOpen > 0 && db.numOpen >= db.maxOpen {
		// Make the connRequest channel. It's buffered so that the
		// connectionOpener doesn't block while waiting for the req to be read.
		req := make(chan connRequest, 1)
		delHandle := db.connRequests.Add(req)
		db.waitCount++
		db.mu.Unlock()

		waitStart := nowFunc()

		// Timeout the connection request with the context.
		select {
		case <-ctx.Done():
			// Remove the connection request and ensure no value has been sent
			// on it after removing.
			db.mu.Lock()
			deleted := db.connRequests.Delete(delHandle)
			db.mu.Unlock()

			db.waitDuration.Add(int64(time.Since(waitStart)))

			// If we failed to delete it, that means either the DB was closed or
			// something else grabbed it and is about to send on it.
			if !deleted {
				// TODO(bradfitz): rather than this best effort select, we
				// should probably start a goroutine to read from req. This best
				// effort select existed before the change to check 'deleted'.
				// But if we know for sure it wasn't deleted and a sender is
				// outstanding, we should probably block on req (in a new
				// goroutine) to get the connection back.
				select {
				default:
				case ret, ok := <-req:
					if ok && ret.conn != nil {
						db.putConn(ret.conn, ret.err, false)
					}
				}
			}
			return nil, ctx.Err()
		case ret, ok := <-req:
			db.waitDuration.Add(int64(time.Since(waitStart)))

			if !ok {
				return nil, errDBClosed
			}
			// Only check if the connection is expired if the strategy is cachedOrNewConns.
			// If we require a new connection, just re-use the connection without looking
			// at the expiry time. If it is expired, it will be checked when it is placed
			// back into the connection pool.
			// This prioritizes giving a valid connection to a client over the exact connection
			// lifetime, which could expire exactly after this point anyway.
			if strategy == cachedOrNewConn && ret.err == nil && ret.conn.expired(lifetime) {
				db.mu.Lock()
				db.maxLifetimeClosed++
				db.mu.Unlock()
				ret.conn.Close()
				return nil, driver.ErrBadConn
			}
			if ret.conn == nil {
				return nil, ret.err
			}

			// Reset the session if required.
			if err := ret.conn.resetSession(ctx); errors.Is(err, driver.ErrBadConn) {
				ret.conn.Close()
				return nil, err
			}
			return ret.conn, ret.err
		}
	}

	db.numOpen++ // optimistically
	db.mu.Unlock()
	ci, err := db.connector.Connect(ctx)
	if err != nil {
		db.mu.Lock()
		db.numOpen-- // correct for earlier optimism
		db.maybeOpenNewConnections()
		db.mu.Unlock()
		return nil, err
	}
	db.mu.Lock()
	dc := &driverConn{
		db:         db,
		createdAt:  nowFunc(),
		returnedAt: nowFunc(),
		ci:         ci,
		inUse:      true,
	}
	db.addDepLocked(dc, dc)
	db.mu.Unlock()
	return dc, nil
}

// putConnHook is a hook for testing.
var putConnHook func(*DB, *driverConn)

// noteUnusedDriverStatement notes that ds is no longer used and should
// be closed whenever possible (when c is next not in use), unless c is
// already closed.
func (db *DB) noteUnusedDriverStatement(c *driverConn, ds *driverStmt) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if c.inUse {
		c.onPut = append(c.onPut, func() {
			ds.Close()
		})
	} else {
		c.Lock()
		fc := c.finalClosed
		c.Unlock()
		if !fc {
			ds.Close()
		}
	}
}

// debugGetPut determines whether getConn & putConn calls' stack traces
// are returned for more verbose crashes.
const debugGetPut = false

// putConn adds a connection to the db's free pool.
// err is optionally the last error that occurred on this connection.
func (db *DB) putConn(dc *driverConn, err error, resetSession bool) {
	if !errors.Is(err, driver.ErrBadConn) {
		if !dc.validateConnection(resetSession) {
			err = driver.ErrBadConn
		}
	}
	db.mu.Lock()
	if !dc.inUse {
		db.mu.Unlock()
		if debugGetPut {
			fmt.Printf("putConn(%v) DUPLICATE was: %s\n\nPREVIOUS was: %s", dc, stack(), db.lastPut[dc])
		}
		panic("sql: connection returned that was never out")
	}

	if !errors.Is(err, driver.ErrBadConn) && dc.expired(db.maxLifetime) {
		db.maxLifetimeClosed++
		err = driver.ErrBadConn
	}
	if debugGetPut {
		db.lastPut[dc] = stack()
	}
	dc.inUse = false
	dc.returnedAt = nowFunc()

	for _, fn := range dc.onPut {
		fn()
	}
	dc.onPut = nil

	if errors.Is(err, driver.ErrBadConn) {
		// Don't reuse bad connections.
		// Since the conn is considered bad and is being discarded, treat it
		// as closed. Don't decrement the open count here, finalClose will
		// take care of that.
		db.maybeOpenNewConnections()
		db.mu.Unlock()
		dc.Close()
		return
	}
	if putConnHook != nil {
		putConnHook(db, dc)
	}
	added := db.putConnDBLocked(dc, nil)
	db.mu.Unlock()

	if !added {
		dc.Close()
		return
	}
}

// Satisfy a connRequest or put the driverConn in the idle pool and return true
// or return false.
// putConnDBLocked will satisfy a connRequest if there is one, or it will
// return the *driverConn to the freeConn list if err == nil and the idle
// connection limit will not be exceeded.
// If err != nil, the value of dc is ignored.
// If err == nil, then dc must not equal nil.
// If a connRequest was fulfilled or the *driverConn was placed in the
// freeConn list, then true is returned, otherwise false is returned.
func (db *DB) putConnDBLocked(dc *driverConn, err error) bool {
	if db.closed {
		return false
	}
	if db.maxOpen > 0 && db.numOpen > db.maxOpen {
		return false
	}
	if req, ok := db.connRequests.TakeRandom(); ok {
		if err == nil {
			dc.inUse = true
		}
		req <- connRequest{
			conn: dc,
			err:  err,
		}
		return true
	} else if err == nil && !db.closed {
		if db.maxIdleConnsLocked() > len(db.freeConn) {
			db.freeConn = append(db.freeConn, dc)
			db.startCleanerLocked()
			return true
		}
		db.maxIdleClosed++
	}
	return false
}

// maxBadConnRetries is the number of maximum retries if the driver returns
// driver.ErrBadConn to signal a broken connection before forcing a new
// connection to be opened.
const maxBadConnRetries = 2

func (db *DB) retry(fn func(strategy connReuseStrategy) error) error {
	for i := int64(0); i < maxBadConnRetries; i++ {
		err := fn(cachedOrNewConn)
		// retry if err is driver.ErrBadConn
		if err == nil || !errors.Is(err, driver.ErrBadConn) {
			return err
		}
	}

	return fn(alwaysNewConn)
}

// PrepareContext creates a prepared statement for later queries or executions.
// Multiple queries or executions may be run concurrently from the
// returned statement.
// The caller must call the statement's [*Stmt.Close] method
// when the statement is no longer needed.
//
// The provided context is used for the preparation of the statement, not for the
// execution of the statement.
func (db *DB) PrepareContext(ctx context.Context, query string) (*Stmt, error) {
	var stmt *Stmt
	var err error

	err = db.retry(func(strategy connReuseStrategy) error {
		stmt, err = db.prepare(ctx, query, strategy)
		return err
	})

	return stmt, err
}

// Prepare creates a prepared statement for later queries or executions.
// Multiple queries or executions may be run concurrently from the
// returned statement.
// The caller must call the statement's [*Stmt.Close] method
// when the statement is no longer needed.
//
// Prepare uses [context.Background] internally; to specify the context, use
// [DB.PrepareContext].
func (db *DB) Prepare(query string) (*Stmt, error) {
	return db.PrepareContext(context.Background(), query)
}

func (db *DB) prepare(ctx context.Context, query string, strategy connReuseStrategy) (*Stmt, error) {
	// TODO: check if db.driver supports an optional
	// driver.Preparer interface and call that instead, if so,
	// otherwise we make a prepared statement that's bound
	// to a connection, and to execute this prepared statement
	// we either need to use this connection (if it's free), else
	// get a new connection + re-prepare + execute on that one.
	dc, err := db.conn(ctx, strategy)
	if err != nil {
		return nil, err
	}
	return db.prepareDC(ctx, dc, dc.releaseConn, nil, query)
}

// prepareDC prepares a query on the driverConn and calls release before
// returning. When cg == nil it implies that a connection pool is used, and
// when cg != nil only a single driver connection is used.
func (db *DB) prepareDC(ctx context.Context, dc *driverConn, release func(error), cg stmtConnGrabber, query string) (*Stmt, error) {
	var ds *driverStmt
	var err error
	defer func() {
		release(err)
	}()
	withLock(dc, func() {
		ds, err = dc.prepareLocked(ctx, cg, query)
	})
	if err != nil {
		return nil, err
	}
	stmt := &Stmt{
		db:    db,
		query: query,
		cg:    cg,
		cgds:  ds,
	}

	// When cg == nil this statement will need to keep track of various
	// connections they are prepared on and record the stmt dependency on
	// the DB.
	if cg == nil {
		stmt.css = []connStmt{{dc, ds}}
		stmt.lastNumClosed = db.numClosed.Load()
		db.addDep(stmt, stmt)
	}
	return stmt, nil
}

// ExecContext executes a query without returning any rows.
// The args are for any placeholder parameters in the query.
func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (Result, error) {
	var res Result
	var err error

	err = db.retry(func(strategy connReuseStrategy) error {
		res, err = db.exec(ctx, query, args, strategy)
		return err
	})

	return res, err
}

// Exec executes a query without returning any rows.
// The args are for any placeholder parameters in the query.
//
// Exec uses [context.Background] internally; to specify the context, use
// [DB.ExecContext].
func (db *DB) Exec(query string, args ...any) (Result, error) {
	return db.ExecContext(context.Background(), query, args...)
}

func (db *DB) exec(ctx context.Context, query string, args []any, strategy connReuseStrategy) (Result, error) {
	dc, err := db.conn(ctx, strategy)
	if err != nil {
		return nil, err
	}
	return db.execDC(ctx, dc, dc.releaseConn, query, args)
}

func (db *DB) execDC(ctx context.Context, dc *driverConn, release func(error), query string, args []any) (res Result, err error) {
	defer func() {
		release(err)
	}()
	execerCtx, ok := dc.ci.(driver.ExecerContext)
	var execer driver.Execer
	if !ok {
		execer, ok = dc.ci.(driver.Execer)
	}
	if ok {
		var nvdargs []driver.NamedValue
		var resi driver.Result
		withLock(dc, func() {
			nvdargs, err = driverArgsConnLocked(dc.ci, nil, args)
			if err != nil {
				return
			}
			resi, err = ctxDriverExec(ctx, execerCtx, execer, query, nvdargs)
		})
		if err != driver.ErrSkip {
			if err != nil {
				return nil, err
			}
			return driverResult{dc, resi}, nil
		}
	}

	var si driver.Stmt
	withLock(dc, func() {
		si, err = ctxDriverPrepare(ctx, dc.ci, query)
	})
	if err != nil {
		return nil, err
	}
	ds := &driverStmt{Locker: dc, si: si}
	defer ds.Close()
	return resultFromStatement(ctx, dc.ci, ds, args...)
}

// QueryContext executes a query that returns rows, typically a SELECT.
// The args are for any placeholder parameters in the query.
func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*Rows, error) {
	var rows *Rows
	var err error

	err = db.retry(func(strategy connReuseStrategy) error {
		rows, err = db.query(ctx, query, args, strategy)
		return err
	})

	return rows, err
}

// Query executes a query that returns rows, typically a SELECT.
// The args are for any placeholder parameters in the query.
//
// Query uses [context.Background] internally; to specify the context, use
// [DB.QueryContext].
func (db *DB) Query(query string, args ...any) (*Rows, error) {
	return db.QueryContext(context.Background(), query, args...)
}

func (db *DB) query(ctx context.Context, query string, args []any, strategy connReuseStrategy) (*Rows, error) {
	dc, err := db.conn(ctx, strategy)
	if err != nil {
		return nil, err
	}

	return db.queryDC(ctx, nil, dc, dc.releaseConn, query, args)
}

// queryDC executes a query on the given connection.
// The connection gets released by the releaseConn function.
// The ctx context is from a query method and the txctx context is from an
// optional transaction context.
func (db *DB) queryDC(ctx, txctx context.Context, dc *driverConn, releaseConn func(error), query string, args []any) (*Rows, error) {
	queryerCtx, ok := dc.ci.(driver.QueryerContext)
	var queryer driver.Queryer
	if !ok {
		queryer, ok = dc.ci.(driver.Queryer)
	}
	if ok {
		var nvdargs []driver.NamedValue
		var rowsi driver.Rows
		var err error
		withLock(dc, func() {
			nvdargs, err = driverArgsConnLocked(dc.ci, nil, args)
			if err != nil {
				return
			}
			rowsi, err = ctxDriverQuery(ctx, queryerCtx, queryer, query, nvdargs)
		})
		if err != driver.ErrSkip {
			if err != nil {
				releaseConn(err)
				return nil, err
			}
			// Note: ownership of dc passes to the *Rows, to be freed
			// with releaseConn.
			rows := &Rows{
				dc:          dc,
				releaseConn: releaseConn,
				rowsi:       rowsi,
			}
			rows.initContextClose(ctx, txctx)
			return rows, nil
		}
	}

	var si driver.Stmt
	var err error
	withLock(dc, func() {
		si, err = ctxDriverPrepare(ctx, dc.ci, query)
	})
	if err != nil {
		releaseConn(err)
		return nil, err
	}

	ds := &driverStmt{Locker: dc, si: si}
	rowsi, err := rowsiFromStatement(ctx, dc.ci, ds, args...)
	if err != nil {
		ds.Close()
		releaseConn(err)
		return nil, err
	}

	// Note: ownership of ci passes to the *Rows, to be freed
	// with releaseConn.
	rows := &Rows{
		dc:          dc,
		releaseConn: releaseConn,
		rowsi:       rowsi,
		closeStmt:   ds,
	}
	rows.initContextClose(ctx, txctx)
	return rows, nil
}

// QueryRowContext executes a query that is expected to return at most one row.
// QueryRowContext always returns a non-nil value. Errors are deferred until
// [Row]'s Scan method is called.
// If the query selects no rows, the [*Row.Scan] will return [ErrNoRows].
// Otherwise, [*Row.Scan] scans the first selected row and discards
// the rest.
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...any) *Row {
	rows, err := db.QueryContext(ctx, query, args...)
	return &Row{rows: rows, err: err}
}

// QueryRow executes a query that is expected to return at most one row.
// QueryRow always returns a non-nil value. Errors are deferred until
// [Row]'s Scan method is called.
// If the query selects no rows, the [*Row.Scan] will return [ErrNoRows].
// Otherwise, [*Row.Scan] scans the first selected row and discards
// the rest.
//
// QueryRow uses [context.Background] internally; to specify the context, use
// [DB.QueryRowContext].
func (db *DB) QueryRow(query string, args ...any) *Row {
	return db.QueryRowContext(context.Background(), query, args...)
}

// BeginTx starts a transaction.
//
// The provided context is used until the transaction is committed or rolled back.
// If the context is canceled, the sql package will roll back
// the transaction. [Tx.Commit] will return an error if the context provided to
// BeginTx is canceled.
//
// The provided [TxOptions] is optional and may be nil if defaults should be used.
// If a non-default isolation level is used that the driver doesn't support,
// an error will be returned.
func (db *DB) BeginTx(ctx context.Context, opts *TxOptions) (*Tx, error) {
	var tx *Tx
	var err error

	err = db.retry(func(strategy connReuseStrategy) error {
		tx, err = db.begin(ctx, opts, strategy)
		return err
	})

	return tx, err
}

// Begin starts a transaction. The default isolation level is dependent on
// the driver.
//
// Begin uses [context.Background] internally; to specify the context, use
// [DB.BeginTx].
func (db *DB) Begin() (*Tx, error) {
	return db.BeginTx(context.Background(), nil)
}

func (db *DB) begin(ctx context.Context, opts *TxOptions, strategy connReuseStrategy) (tx *Tx, err error) {
	dc, err := db.conn(ctx, strategy)
	if err != nil {
		return nil, err
	}
	return db.beginDC(ctx, dc, dc.releaseConn, opts)
}

// beginDC starts a transaction. The provided dc must be valid and ready to use.
func (db *DB) beginDC(ctx context.Context, dc *driverConn, release func(error), opts *TxOptions) (tx *Tx, err error) {
	var txi driver.Tx
	keepConnOnRollback := false
	withLock(dc, func() {
		_, hasSessionResetter := dc.ci.(driver.SessionResetter)
		_, hasConnectionValidator := dc.ci.(driver.Validator)
		keepConnOnRollback = hasSessionResetter && hasConnectionValidator
		txi, err = ctxDriverBegin(ctx, opts, dc.ci)
	})
	if err != nil {
		release(err)
		return nil, err
	}

	// Schedule the transaction to rollback when the context is canceled.
	// The cancel function in Tx will be called after done is set to true.
	ctx, cancel := context.WithCancel(ctx)
	tx = &Tx{
		db:                 db,
		dc:                 dc,
		releaseConn:        release,
		txi:                txi,
		cancel:             cancel,
		keepConnOnRollback: keepConnOnRollback,
		ctx:                ctx,
	}
	go tx.awaitDone()
	return tx, nil
}

// Driver returns the database's underlying driver.
func (db *DB) Driver() driver.Driver {
	return db.connector.Driver()
}

// ErrConnDone is returned by any operation that is performed on a connection
// that has already been returned to the connection pool.
var ErrConnDone = errors.New("sql: connection is already closed")

// Conn returns a single connection by either opening a new connection
// or returning an existing connection from the connection pool. Conn will
// block until either a connection is returned or ctx is canceled.
// Queries run on the same Conn will be run in the same database session.
//
// Every Conn must be returned to the database pool after use by
// calling [Conn.Close].
func (db *DB) Conn(ctx context.Context) (*Conn, error) {
	var dc *driverConn
	var err error

	err = db.retry(func(strategy connReuseStrategy) error {
		dc, err = db.conn(ctx, strategy)
		return err
	})

	if err != nil {
		return nil, err
	}

	conn := &Conn{
		db: db,
		dc: dc,
	}
	return conn, nil
}

type releaseConn func(error)

// Conn represents a single database connection rather than a pool of database
// connections. Prefer running queries from [DB] unless there is a specific
// need for a continuous single database connection.
//
// A Conn must call [Conn.Close] to return the connection to the database pool
// and may do so concurrently with a running query.
//
// After a call to [Conn.Close], all operations on the
// connection fail with [ErrConnDone].
type Conn struct {
	db *DB

	// closemu prevents the connection from closing while there
	// is an active query. It is held for read during queries
	// and exclusively during close.
	closemu sync.RWMutex

	// dc is owned until close, at which point
	// it's returned to the connection pool.
	dc *driverConn

	// done transitions from false to true exactly once, on close.
	// Once done, all operations fail with ErrConnDone.
	done atomic.Bool

	releaseConnOnce sync.Once
	// releaseConnCache is a cache of c.closemuRUnlockCondReleaseConn
	// to save allocations in a call to grabConn.
	releaseConnCache releaseConn
}

// grabConn takes a context to implement stmtConnGrabber
// but the context is not used.
func (c *Conn) grabConn(context.Context) (*driverConn, releaseConn, error) {
	if c.done.Load() {
		return nil, nil, ErrConnDone
	}
	c.releaseConnOnce.Do(func() {
		c.releaseConnCache = c.closemuRUnlockCondReleaseConn
	})
	c.closemu.RLock()
	return c.dc, c.releaseConnCache, nil
}

// PingContext verifies the connection to the database is still alive.
func (c *Conn) PingContext(ctx context.Context) error {
	dc, release, err := c.grabConn(ctx)
	if err != nil {
		return err
	}
	return c.db.pingDC(ctx, dc, release)
}

// ExecContext executes a query without returning any rows.
// The args are for any placeholder parameters in the query.
func (c *Conn) ExecContext(ctx context.Context, query string, args ...any) (Result, error) {
	dc, release, err := c.grabConn(ctx)
	if err != nil {
		return nil, err
	}
	return c.db.execDC(ctx, dc, release, query, args)
}

// QueryContext executes a query that returns rows, typically a SELECT.
// The args are for any placeholder parameters in the query.
func (c *Conn) QueryContext(ctx context.Context, query string, args ...any) (*Rows, error) {
	dc, release, err := c.grabConn(ctx)
	if err != nil {
		return nil, err
	}
	return c.db.queryDC(ctx, nil, dc, release, query, args)
}

// QueryRowContext executes a query that is expected to return at most one row.
// QueryRowContext always returns a non-nil value. Errors are deferred until
// the [*Row.Scan] method is called.
// If the query selects no rows, the [*Row.Scan] will return [ErrNoRows].
// Otherwise, the [*Row.Scan] scans the first selected row and discards
// the rest.
func (c *Conn) QueryRowContext(ctx context.Context, query string, args ...any) *Row {
	rows, err := c.QueryContext(ctx, query, args...)
	return &Row{rows: rows, err: err}
}

// PrepareContext creates a prepared statement for later queries or executions.
// Multiple queries or executions may be run concurrently from the
// returned statement.
// The caller must call the statement's [*Stmt.Close] method
// when the statement is no longer needed.
//
// The provided context is used for the preparation of the statement, not for the
// execution of the statement.
func (c *Conn) PrepareContext(ctx context.Context, query string) (*Stmt, error) {
	dc, release, err := c.grabConn(ctx)
	if err != nil {
		return nil, err
	}
	return c.db.prepareDC(ctx, dc, release, c, query)
}

// Raw executes f exposing the underlying driver connection for the
// duration of f. The driverConn must not be used outside of f.
//
// Once f returns and err is not [driver.ErrBadConn], the [Conn] will continue to be usable
// until [Conn.Close] is called.
func (c *Conn) Raw(f func(driverConn any) error) (err error) {
	var dc *driverConn
	var release releaseConn

	// grabConn takes a context to implement stmtConnGrabber, but the context is not used.
	dc, release, err = c.grabConn(nil)
	if err != nil {
		return
	}
	fPanic := true
	dc.Mutex.Lock()
	defer func() {
		dc.Mutex.Unlock()

		// If f panics fPanic will remain true.
		// Ensure an error is passed to release so the connection
		// may be discarded.
		if fPanic {
			err = driver.ErrBadConn
		}
		release(err)
	}()
	err = f(dc.ci)
	fPanic = false

	return
}

// BeginTx starts a transaction.
//
// The provided context is used until the transaction is committed or rolled back.
// If the context is canceled, the sql package will roll back
// the transaction. [Tx.Commit] will return an error if the context provided to
// BeginTx is canceled.
//
// The provided [TxOptions] is optional and may be nil if defaults should be used.
// If a non-default isolation level is used that the driver doesn't support,
// an error will be returned.
func (c *Conn) BeginTx(ctx context.Context, opts *TxOptions) (*Tx, error) {
	dc, release, err := c.grabConn(ctx)
	if err != nil {
		return nil, err
	}
	return c.db.beginDC(ctx, dc, release, opts)
}

// closemuRUnlockCondReleaseConn read unlocks closemu
// as the sql operation is done with the dc.
func (c *Conn) closemuRUnlockCondReleaseConn(err error) {
	c.closemu.RUnlock()
	if errors.Is(err, driver.ErrBadConn) {
		c.close(err)
	}
}

func (c *Conn) txCtx() context.Context {
	return nil
}

func (c *Conn) close(err error) error {
	if !c.done.CompareAndSwap(false, true) {
		return ErrConnDone
	}

	// Lock around releasing the driver connection
	// to ensure all queries have been stopped before doing so.
	c.closemu.Lock()
	defer c.closemu.Unlock()

	c.dc.releaseConn(err)
	c.dc = nil
	c.db = nil
	return err
}

// Close returns the connection to the connection pool.
// All operations after a Close will return with [ErrConnDone].
// Close is safe to call concurrently with other operations and will
// block until all other operations finish. It may be useful to first
// cancel any used context and then call close directly after.
func (c *Conn) Close() error {
	return c.close(nil)
}

// Tx is an in-progress database transaction.
//
// A transaction must end with a call to [Tx.Commit] or [Tx.Rollback].
//
// After a call to [Tx.Commit] or [Tx.Rollback], all operations on the
// transaction fail with [ErrTxDone].
//
// The statements prepared for a transaction by calling
// the transaction's [Tx.Prepare] or [Tx.Stmt] methods are closed
// by the call to [Tx.Commit] or [Tx.Rollback].
type Tx struct {
	db *DB

	// closemu prevents the transaction from closing while there
	// is an active query. It is held for read during queries
	// and exclusively during close.
	closemu sync.RWMutex

	// dc is owned exclusively until Commit or Rollback, at which point
	// it's returned with putConn.
	dc  *driverConn
	txi driver.Tx

	// releaseConn is called once the Tx is closed to release
	// any held driverConn back to the pool.
	releaseConn func(error)

	// done transitions from false to true exactly once, on Commit
	// or Rollback. once done, all operations fail with
	// ErrTxDone.
	done atomic.Bool

	// keepConnOnRollback is true if the driver knows
	// how to reset the connection's session and if need be discard
	// the connection.
	keepConnOnRollback bool

	// All Stmts prepared for this transaction. These will be closed after the
	// transaction has been committed or rolled back.
	stmts struct {
		sync.Mutex
		v []*Stmt
	}

	// cancel is called after done transitions from 0 to 1.
	cancel func()

	// ctx lives for the life of the transaction.
	ctx context.Context
}

// awaitDone blocks until the context in Tx is canceled and rolls back
// the transaction if it's not already done.
func (tx *Tx) awaitDone() {
	// Wait for either the transaction to be committed or rolled
	// back, or for the associated context to be closed.
	<-tx.ctx.Done()

	// Discard and close the connection used to ensure the
	// transaction is closed and the resources are released.  This
	// rollback does nothing if the transaction has already been
	// committed or rolled back.
	// Do not discard the connection if the connection knows
	// how to reset the session.
	discardConnection := !tx.keepConnOnRollback
	tx.rollback(discardConnection)
}

func (tx *Tx) isDone() bool {
	return tx.done.Load()
}

// ErrTxDone is returned by any operation that is performed on a transaction
// that has already been committed or rolled back.
var ErrTxDone = errors.New("sql: transaction has already been committed or rolled back")

// close returns the connection to the pool and
// must only be called by Tx.rollback or Tx.Commit while
// tx is already canceled and won't be executed concurrently.
func (tx *Tx) close(err error) {
	tx.releaseConn(err)
	tx.dc = nil
	tx.txi = nil
}

// hookTxGrabConn specifies an optional hook to be called on
// a successful call to (*Tx).grabConn. For tests.
var hookTxGrabConn func()

func (tx *Tx) grabConn(ctx context.Context) (*driverConn, releaseConn, error) {
	select {
	default:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	// closemu.RLock must come before the check for isDone to prevent the Tx from
	// closing while a query is executing.
	tx.closemu.RLock()
	if tx.isDone() {
		tx.closemu.RUnlock()
		return nil, nil, ErrTxDone
	}
	if hookTxGrabConn != nil { // test hook
		hookTxGrabConn()
	}
	return tx.dc, tx.closemuRUnlockRelease, nil
}

func (tx *Tx) txCtx() context.Context {
	return tx.ctx
}

// closemuRUnlockRelease is used as a func(error) method value in
// [DB.ExecContext] and [DB.QueryContext]. Unlocking in the releaseConn keeps
// the driver conn from being returned to the connection pool until
// the Rows has been closed.
func (tx *Tx) closemuRUnlockRelease(error) {
	tx.closemu.RUnlock()
}

// Closes all Stmts prepared for this transaction.
func (tx *Tx) closePrepared() {
	tx.stmts.Lock()
	defer tx.stmts.Unlock()
	for _, stmt := range tx.stmts.v {
		stmt.Close()
	}
}

// Commit commits the transaction.
func (tx *Tx) Commit() error {
	// Check context first to avoid transaction leak.
	// If put it behind tx.done CompareAndSwap statement, we can't ensure
	// the consistency between tx.done and the real COMMIT operation.
	select {
	default:
	case <-tx.ctx.Done():
		if tx.done.Load() {
			return ErrTxDone
		}
		return tx.ctx.Err()
	}
	if !tx.done.CompareAndSwap(false, true) {
		return ErrTxDone
	}

	// Cancel the Tx to release any active R-closemu locks.
	// This is safe to do because tx.done has already transitioned
	// from 0 to 1. Hold the W-closemu lock prior to rollback
	// to ensure no other connection has an active query.
	tx.cancel()
	tx.closemu.Lock()
	tx.closemu.Unlock()

	var err error
	withLock(tx.dc, func() {
		err = tx.txi.Commit()
	})
	if !errors.Is(err, driver.ErrBadConn) {
		tx.closePrepared()
	}
	tx.close(err)
	return err
}

var rollbackHook func()

// rollback aborts the transaction and optionally forces the pool to discard
// the connection.
func (tx *Tx) rollback(discardConn bool) error {
	if !tx.done.CompareAndSwap(false, true) {
		return ErrTxDone
	}


"""




```