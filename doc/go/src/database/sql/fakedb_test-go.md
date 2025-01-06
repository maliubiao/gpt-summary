Response:
Let's break down the thought process for analyzing this Go code and answering the request.

**1. Initial Understanding - The Big Picture**

The very first lines, the comment block at the top, are crucial. It explicitly states: "fakeDriver is a fake database that implements Go's driver.Driver interface, just for testing." This immediately tells us the primary purpose: *testing*. It's not a real database, but a simulation. The comment also outlines its simplified query language, which is the key to understanding its functionality.

**2. Deconstructing the `fakeDriver` and Related Structures**

I'll start by looking at the core data structures:

* **`fakeDriver`:**  This is the main entry point. It manages connections (`openCount`, `closeCount`), a way to simulate waiting (`waitCh`, `waitingCh`), and the actual in-memory databases (`dbs`).
* **`fakeConnector`:** This is part of the `driver.DriverContext` interface, handling the creation of connections. It doesn't add much functional logic in this case beyond using the `fakeDriver`'s `Open` method.
* **`fakeDB`:** Represents a single in-memory database instance. It holds the tables (`tables`) and some flags like `badConn` for simulating connection issues.
* **`table`:** Represents a table within a `fakeDB`. It stores column names, types, and the actual rows of data.
* **`row`:**  A simple struct representing a row in a table.
* **`fakeConn`:** Represents a connection to a `fakeDB`. It manages transactions, keeps track of prepared statements, and can simulate bad connections.
* **`fakeTx`:** Represents a transaction. It's relatively simple in this fake implementation.
* **`fakeStmt`:**  Represents a prepared statement. This is where the query parsing and execution logic lives. It holds the parsed command, table name, parameters, etc.
* **`rowsCursor`:**  Represents the result set of a query. It iterates over the rows.

**3. Analyzing the Query Language**

The comment block within `fakeDriver`'s definition provides the syntax for its query language. This is critical for understanding its capabilities. I'll extract the commands and their structures:

* **`WIPE`:** Empties the database.
* **`CREATE|<tablename>|<col>=<type>,<col>=<type>,...`:** Creates a table with specified columns and types. The allowed types are important to note.
* **`INSERT|<tablename>|col=val,col2=val2,col3=?`:** Inserts a row into a table. Values can be literal or placeholders (`?`).
* **`SELECT|<tablename>|projectcol1,projectcol2|filtercol=?,filtercol2=?`  and `SELECT|<tablename>|projectcol1,projectcol2|filtercol=?param1,filtercol2=?param2`:**  Selects data from a table, specifying columns to project and filters with placeholders (either numbered or named).
* **`PANIC|<method>|...`:**  Causes a specific method on `fakeStmt` to panic (for testing error handling).
* **`WAIT|<duration>|...`:** Causes a delay (for testing timeouts or concurrency).
* **Multiple statements:** Can be combined with semicolons.

**4. Tracing the Execution Flow (Key Methods)**

To understand how this fake database works, I'll trace the execution flow of some core methods:

* **`fakeDriver.Open(dsn string)`:**  Handles opening a connection. It parses the DSN, retrieves or creates a `fakeDB`, and creates a `fakeConn`. The `badConn` option in the DSN is a specific feature for testing.
* **`fakeConn.PrepareContext(ctx context.Context, query string)`:**  Parses the query string, breaks it into individual statements, and creates `fakeStmt` objects for each. It handles the `PANIC` and `WAIT` prefixes. Crucially, it parses the command type (`CREATE`, `INSERT`, `SELECT`) and extracts relevant information.
* **`fakeStmt.ExecContext(ctx context.Context, args []driver.NamedValue)`:**  Executes "write" operations (`WIPE`, `CREATE`, `INSERT`). For `INSERT`, it retrieves the table, validates column names, and adds the row to the in-memory `table`.
* **`fakeStmt.QueryContext(ctx context.Context, args []driver.NamedValue)`:** Executes "read" operations (`SELECT`). It retrieves the table, applies the filter conditions based on the `whereCol` and provided arguments, and constructs a `rowsCursor` to return the results.
* **`rowsCursor.Next(dest []driver.Value)`:**  Iterates through the rows of the result set and copies the data into the provided `dest` slice.

**5. Identifying Go Feature Implementations**

Based on the code and its purpose, I can identify several Go features being demonstrated:

* **`database/sql/driver` interface implementation:** The core purpose of this code. It shows how to create a custom database driver by implementing interfaces like `driver.Driver`, `driver.Conn`, `driver.Stmt`, `driver.Tx`, and `driver.Rows`.
* **In-memory data storage:**  The `fakeDB` and `table` structures demonstrate a simple in-memory data storage mechanism using Go's built-in data structures (maps and slices).
* **String manipulation:**  The code heavily uses `strings.Split` and `strings.HasPrefix` for parsing the custom query language.
* **Error handling:**  The code uses `errors.New` and custom error types like `fakeError` for managing and propagating errors.
* **Synchronization:**  The use of `sync.Mutex` protects shared resources like the `dbs` map and the `tables` within a `fakeDB` from race conditions. `sync/atomic` is used for the `useRawBytes` flag.
* **Context:**  The code uses `context.Context` for managing timeouts and cancellations, especially in `PrepareContext` and `ExecContext`/`QueryContext`.
* **Reflection (Indirectly):**  While not explicitly using `reflect` for complex operations, the `colTypeToReflectType` function demonstrates basic mapping of string type names to `reflect.Type`.
* **Testing utilities:**  The code itself is a testing tool, showcasing how to create mocks or stubs for external dependencies (in this case, a database).

**6. Code Examples and Reasoning**

Now, I can construct the Go code examples based on the identified functionalities and the query language syntax. I'll think of simple scenarios for each command.

**7. Considering Edge Cases and Potential Errors**

I'll go through the code and think about what could go wrong or what a user might do incorrectly. The DSN parsing is a potential area for errors. The simplified query language has its own syntax constraints that users need to be aware of. The interaction with placeholders (`?`) is another area to consider.

**8. Structuring the Answer**

Finally, I'll organize the findings into the requested sections: functionalities, Go feature implementations with examples, input/output reasoning, and common mistakes. Using clear headings and formatting will make the answer easier to understand.

This step-by-step approach, from understanding the high-level purpose to dissecting the code details and considering potential issues, allows for a comprehensive and accurate analysis of the provided Go code.
这段Go语言代码实现了一个名为 `fakedb` 的 **内存数据库**，主要用于 **测试** Go 语言的 `database/sql` 包。它模拟了 `database/sql/driver` 包中的接口，允许开发者在不依赖真实数据库的情况下测试数据库操作。

**主要功能：**

1. **模拟 `driver.Driver` 接口:**  `fakeDriver` 结构体实现了 `driver.Driver` 接口，可以被 `sql.Open` 函数注册和使用。

2. **内存数据存储:** 所有的数据（数据库、表、行）都存储在内存中，这意味着数据不会持久化。

3. **自定义查询语言:**  `fakedb` 不使用标准的 SQL，而是定义了一种简化的、基于文本的查询语言。这种语言的语法如下：
   - `WIPE`: 清空数据库，删除所有表。
   - `CREATE|<tablename>|<col>=<type>,<col>=<type>,...`: 创建一个表，指定列名和类型（`string`, `uint8`, `int16`, `int32`, `int64`, `bool`）。
   - `INSERT|<tablename>|col=val,col2=val2,col3=?`: 向指定表插入一行数据。值可以是直接的值，也可以是占位符 `?`。
   - `SELECT|<tablename>|projectcol1,projectcol2|filtercol=?,filtercol2=?`: 从指定表选择数据，指定要返回的列和过滤条件。过滤条件使用占位符 `?`。
   - `SELECT|<tablename>|projectcol1,projectcol2|filtercol=?param1,filtercol2=?param2`:  与上面类似，但可以使用命名的占位符。
   - **前缀命令:**
     - `PANIC|<method>|`:  在 `fakeStmt` 的指定方法中触发 `panic`，用于测试错误处理。
     - `WAIT|<duration>|`:  让 `fakeStmt` 的指定方法休眠一段时间，用于测试超时或并发场景。
   - **多语句:** 可以使用分号 `;` 分隔多个语句。

4. **支持事务:** `fakeConn` 和 `fakeTx` 结构体模拟了事务的开始 (`Begin`)、提交 (`Commit`) 和回滚 (`Rollback`) 操作。

5. **支持预处理语句:** `fakeConn` 的 `PrepareContext` 方法用于解析查询语句并创建 `fakeStmt` 预处理语句对象。

6. **模拟连接错误:** 可以通过 DSN 选项 (`badConn`) 或全局钩子来模拟连接错误 (`driver.ErrBadConn`)。

7. **模拟查询参数绑定:** `INSERT` 和 `SELECT` 语句支持使用占位符 `?` 来绑定参数。

8. **支持查询结果迭代:** `rowsCursor` 结构体实现了 `driver.Rows` 接口，用于迭代查询结果。

9. **支持 `driver.DriverContext` 接口:** `fakeDriverCtx` 实现了 `driver.DriverContext` 接口，用于创建连接器 (`driver.Connector`)。

10. **支持会话重置:** `fakeConn` 实现了 `driver.Validator` 接口，并提供了 `ResetSession` 方法来重置会话状态。

**Go 语言功能实现举例：**

**1. 注册和使用 `fakedb` 驱动:**

```go
package main

import (
	"database/sql"
	"fmt"
	_ "database/sql/fakedb" // 导入 fakedb 驱动
)

func main() {
	db, err := sql.Open("test", "mydatabase") // 使用 "test" 作为驱动名打开 fakedb
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	// ... 后续的数据库操作
}
```

**2. 创建表和插入数据:**

**假设输入查询语句:**

```
CREATE|users|id=int,name=string,age=int;INSERT|users|id=1,name=Alice,age=30;INSERT|users|id=2,name=Bob,age=25
```

**对应的 Go 代码:**

```go
package main

import (
	"database/sql"
	"fmt"
	_ "database/sql/fakedb"
)

func main() {
	db, err := sql.Open("test", "mydatabase")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	query := "CREATE|users|id=int,name=string,age=int;INSERT|users|id=1,name=Alice,age=30;INSERT|users|id=2,name=Bob,age=25"
	_, err = db.Exec(query)
	if err != nil {
		fmt.Println("Error executing query:", err)
		return
	}

	fmt.Println("Table 'users' created and data inserted.")
}
```

**输出:**  没有直接的输出，但执行成功后，`fakedb` 的内存中会存在一个名为 `users` 的表，包含两行数据。

**3. 查询数据 (带占位符):**

**假设输入查询语句:**

```
SELECT|users|name,age|id=?
```

**对应的 Go 代码:**

```go
package main

import (
	"database/sql"
	"fmt"
	_ "database/sql/fakedb"
)

func main() {
	db, err := sql.Open("test", "mydatabase")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	// 假设已经创建了 'users' 表并插入了数据

	rows, err := db.Query("SELECT|users|name,age|id=?", 1)
	if err != nil {
		fmt.Println("Error querying database:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var age int
		if err := rows.Scan(&name, &age); err != nil {
			fmt.Println("Error scanning row:", err)
			return
		}
		fmt.Printf("Name: %s, Age: %d\n", name, age)
	}

	if err := rows.Err(); err != nil {
		fmt.Println("Error iterating rows:", err)
	}
}
```

**输出:**

```
Name: Alice, Age: 30
```

**4. 使用命名占位符查询:**

**假设输入查询语句:**

```
SELECT|users|name,age|id=?userId
```

**对应的 Go 代码:**

```go
package main

import (
	"database/sql"
	"fmt"
	_ "database/sql/fakedb"
)

func main() {
	db, err := sql.Open("test", "mydatabase")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	// 假设已经创建了 'users' 表并插入了数据

	rows, err := db.Query("SELECT|users|name,age|id=?userId", sql.Named("userId", 1))
	if err != nil {
		fmt.Println("Error querying database:", err)
		return
	}
	defer rows.Close()

	// ... (与上面的代码相同，用于处理查询结果)
}
```

**命令行参数的具体处理:**

`fakedb` 本身作为一个测试用的内存数据库，并不直接处理命令行参数。它的行为由传递给 `sql.Open` 函数的 **数据源名称 (DSN, Data Source Name)** 控制。

在 `fakeDriver` 的 `Open` 方法中，可以看到对 DSN 的处理：

```go
func (d *fakeDriver) Open(dsn string) (driver.Conn, error) {
	// ...
	parts := strings.Split(dsn, ";")
	if len(parts) < 1 {
		return nil, errors.New("fakedb: no database name")
	}
	name := parts[0]

	db := d.getDB(name)

	// ...

	if len(parts) >= 2 && parts[1] == "badConn" {
		conn.bad = true
	}
	// ...
	return conn, nil
}
```

- DSN 的第一部分 (`parts[0]`) 被认为是数据库的名称。
- DSN 的后续部分可以使用分号 `;` 分隔，用于传递特定的选项。目前 `fakedb` 只支持一个选项：
    - `badConn`:  如果 DSN 中包含 `;badConn`，则会在每次调用 `conn.Begin()` 时交替返回 `driver.ErrBadConn` 错误，用于模拟连接问题。

**例如：**

- `sql.Open("test", "mydatabase")`:  连接到名为 "mydatabase" 的 `fakedb` 实例。
- `sql.Open("test", "anotherdb;badConn")`: 连接到名为 "anotherdb" 的 `fakedb` 实例，并且此连接会模拟连接错误。

**使用者易犯错的点：**

1. **混淆查询语言与 SQL:** 最容易犯的错误是尝试使用标准的 SQL 语句，`fakedb` 的查询语言与 SQL 完全不同，语法更简单。例如，尝试使用 `SELECT * FROM users` 会导致错误，应该使用 `SELECT|users|id,name,age|` (如果不需要过滤)。

2. **不了解支持的数据类型:** 在 `CREATE` 语句中，只能使用 `fakedb` 定义的类型 (`string`, `uint8`, `int16`, `int32`, `int64`, `bool`)，使用其他类型会报错。

3. **占位符使用不当:**  在 `INSERT` 和 `SELECT` 语句中使用占位符时，需要确保提供的参数数量和类型与占位符匹配。对于命名占位符，需要使用 `sql.Named` 函数传递参数。

4. **依赖持久化:**  由于 `fakedb` 是内存数据库，程序退出后所有数据都会丢失。如果期望数据持久化，则需要使用真正的数据库。

5. **错误处理不当:**  虽然 `fakedb` 用于测试，但仍然需要正确处理数据库操作可能返回的错误，例如连接错误、查询错误等。

**总结:**

`go/src/database/sql/fakedb_test.go`  实现了一个轻量级的内存数据库，用于测试 `database/sql` 包的功能。它使用自定义的查询语言，并提供了一些模拟错误和延迟的机制，方便开发者在隔离的环境中测试数据库相关的代码。理解其查询语言和限制是正确使用它的关键。

Prompt: 
```
这是路径为go/src/database/sql/fakedb_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

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
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDriver is a fake database that implements Go's driver.Driver
// interface, just for testing.
//
// It speaks a query language that's semantically similar to but
// syntactically different and simpler than SQL.  The syntax is as
// follows:
//
//	WIPE
//	CREATE|<tablename>|<col>=<type>,<col>=<type>,...
//	  where types are: "string", [u]int{8,16,32,64}, "bool"
//	INSERT|<tablename>|col=val,col2=val2,col3=?
//	SELECT|<tablename>|projectcol1,projectcol2|filtercol=?,filtercol2=?
//	SELECT|<tablename>|projectcol1,projectcol2|filtercol=?param1,filtercol2=?param2
//
// Any of these can be preceded by PANIC|<method>|, to cause the
// named method on fakeStmt to panic.
//
// Any of these can be proceeded by WAIT|<duration>|, to cause the
// named method on fakeStmt to sleep for the specified duration.
//
// Multiple of these can be combined when separated with a semicolon.
//
// When opening a fakeDriver's database, it starts empty with no
// tables. All tables and data are stored in memory only.
type fakeDriver struct {
	mu         sync.Mutex // guards 3 following fields
	openCount  int        // conn opens
	closeCount int        // conn closes
	waitCh     chan struct{}
	waitingCh  chan struct{}
	dbs        map[string]*fakeDB
}

type fakeConnector struct {
	name string

	waiter func(context.Context)
	closed bool
}

func (c *fakeConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := fdriver.Open(c.name)
	conn.(*fakeConn).waiter = c.waiter
	return conn, err
}

func (c *fakeConnector) Driver() driver.Driver {
	return fdriver
}

func (c *fakeConnector) Close() error {
	if c.closed {
		return errors.New("fakedb: connector is closed")
	}
	c.closed = true
	return nil
}

type fakeDriverCtx struct {
	fakeDriver
}

var _ driver.DriverContext = &fakeDriverCtx{}

func (cc *fakeDriverCtx) OpenConnector(name string) (driver.Connector, error) {
	return &fakeConnector{name: name}, nil
}

type fakeDB struct {
	name string

	useRawBytes atomic.Bool

	mu       sync.Mutex
	tables   map[string]*table
	badConn  bool
	allowAny bool
}

type fakeError struct {
	Message string
	Wrapped error
}

func (err fakeError) Error() string {
	return err.Message
}

func (err fakeError) Unwrap() error {
	return err.Wrapped
}

type table struct {
	mu      sync.Mutex
	colname []string
	coltype []string
	rows    []*row
}

func (t *table) columnIndex(name string) int {
	return slices.Index(t.colname, name)
}

type row struct {
	cols []any // must be same size as its table colname + coltype
}

type memToucher interface {
	// touchMem reads & writes some memory, to help find data races.
	touchMem()
}

type fakeConn struct {
	db *fakeDB // where to return ourselves to

	currTx *fakeTx

	// Every operation writes to line to enable the race detector
	// check for data races.
	line int64

	// Stats for tests:
	mu          sync.Mutex
	stmtsMade   int
	stmtsClosed int
	numPrepare  int

	// bad connection tests; see isBad()
	bad       bool
	stickyBad bool

	skipDirtySession bool // tests that use Conn should set this to true.

	// dirtySession tests ResetSession, true if a query has executed
	// until ResetSession is called.
	dirtySession bool

	// The waiter is called before each query. May be used in place of the "WAIT"
	// directive.
	waiter func(context.Context)
}

func (c *fakeConn) touchMem() {
	c.line++
}

func (c *fakeConn) incrStat(v *int) {
	c.mu.Lock()
	*v++
	c.mu.Unlock()
}

type fakeTx struct {
	c *fakeConn
}

type boundCol struct {
	Column      string
	Placeholder string
	Ordinal     int
}

type fakeStmt struct {
	memToucher
	c *fakeConn
	q string // just for debugging

	cmd   string
	table string
	panic string
	wait  time.Duration

	next *fakeStmt // used for returning multiple results.

	closed bool

	colName      []string // used by CREATE, INSERT, SELECT (selected columns)
	colType      []string // used by CREATE
	colValue     []any    // used by INSERT (mix of strings and "?" for bound params)
	placeholders int      // used by INSERT/SELECT: number of ? params

	whereCol []boundCol // used by SELECT (all placeholders)

	placeholderConverter []driver.ValueConverter // used by INSERT
}

var fdriver driver.Driver = &fakeDriver{}

func init() {
	Register("test", fdriver)
}

type Dummy struct {
	driver.Driver
}

func TestDrivers(t *testing.T) {
	unregisterAllDrivers()
	Register("test", fdriver)
	Register("invalid", Dummy{})
	all := Drivers()
	if len(all) < 2 || !slices.IsSorted(all) || !slices.Contains(all, "test") || !slices.Contains(all, "invalid") {
		t.Fatalf("Drivers = %v, want sorted list with at least [invalid, test]", all)
	}
}

// hook to simulate connection failures
var hookOpenErr struct {
	sync.Mutex
	fn func() error
}

func setHookOpenErr(fn func() error) {
	hookOpenErr.Lock()
	defer hookOpenErr.Unlock()
	hookOpenErr.fn = fn
}

// Supports dsn forms:
//
//	<dbname>
//	<dbname>;<opts>  (only currently supported option is `badConn`,
//	                  which causes driver.ErrBadConn to be returned on
//	                  every other conn.Begin())
func (d *fakeDriver) Open(dsn string) (driver.Conn, error) {
	hookOpenErr.Lock()
	fn := hookOpenErr.fn
	hookOpenErr.Unlock()
	if fn != nil {
		if err := fn(); err != nil {
			return nil, err
		}
	}
	parts := strings.Split(dsn, ";")
	if len(parts) < 1 {
		return nil, errors.New("fakedb: no database name")
	}
	name := parts[0]

	db := d.getDB(name)

	d.mu.Lock()
	d.openCount++
	d.mu.Unlock()
	conn := &fakeConn{db: db}

	if len(parts) >= 2 && parts[1] == "badConn" {
		conn.bad = true
	}
	if d.waitCh != nil {
		d.waitingCh <- struct{}{}
		<-d.waitCh
		d.waitCh = nil
		d.waitingCh = nil
	}
	return conn, nil
}

func (d *fakeDriver) getDB(name string) *fakeDB {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dbs == nil {
		d.dbs = make(map[string]*fakeDB)
	}
	db, ok := d.dbs[name]
	if !ok {
		db = &fakeDB{name: name}
		d.dbs[name] = db
	}
	return db
}

func (db *fakeDB) wipe() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.tables = nil
}

func (db *fakeDB) createTable(name string, columnNames, columnTypes []string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.tables == nil {
		db.tables = make(map[string]*table)
	}
	if _, exist := db.tables[name]; exist {
		return fmt.Errorf("fakedb: table %q already exists", name)
	}
	if len(columnNames) != len(columnTypes) {
		return fmt.Errorf("fakedb: create table of %q len(names) != len(types): %d vs %d",
			name, len(columnNames), len(columnTypes))
	}
	db.tables[name] = &table{colname: columnNames, coltype: columnTypes}
	return nil
}

// must be called with db.mu lock held
func (db *fakeDB) table(table string) (*table, bool) {
	if db.tables == nil {
		return nil, false
	}
	t, ok := db.tables[table]
	return t, ok
}

func (db *fakeDB) columnType(table, column string) (typ string, ok bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	t, ok := db.table(table)
	if !ok {
		return
	}
	if i := slices.Index(t.colname, column); i != -1 {
		return t.coltype[i], true
	}
	return "", false
}

func (c *fakeConn) isBad() bool {
	if c.stickyBad {
		return true
	} else if c.bad {
		if c.db == nil {
			return false
		}
		// alternate between bad conn and not bad conn
		c.db.badConn = !c.db.badConn
		return c.db.badConn
	} else {
		return false
	}
}

func (c *fakeConn) isDirtyAndMark() bool {
	if c.skipDirtySession {
		return false
	}
	if c.currTx != nil {
		c.dirtySession = true
		return false
	}
	if c.dirtySession {
		return true
	}
	c.dirtySession = true
	return false
}

func (c *fakeConn) Begin() (driver.Tx, error) {
	if c.isBad() {
		return nil, fakeError{Wrapped: driver.ErrBadConn}
	}
	if c.currTx != nil {
		return nil, errors.New("fakedb: already in a transaction")
	}
	c.touchMem()
	c.currTx = &fakeTx{c: c}
	return c.currTx, nil
}

var hookPostCloseConn struct {
	sync.Mutex
	fn func(*fakeConn, error)
}

func setHookpostCloseConn(fn func(*fakeConn, error)) {
	hookPostCloseConn.Lock()
	defer hookPostCloseConn.Unlock()
	hookPostCloseConn.fn = fn
}

var testStrictClose *testing.T

// setStrictFakeConnClose sets the t to Errorf on when fakeConn.Close
// fails to close. If nil, the check is disabled.
func setStrictFakeConnClose(t *testing.T) {
	testStrictClose = t
}

func (c *fakeConn) ResetSession(ctx context.Context) error {
	c.dirtySession = false
	c.currTx = nil
	if c.isBad() {
		return fakeError{Message: "Reset Session: bad conn", Wrapped: driver.ErrBadConn}
	}
	return nil
}

var _ driver.Validator = (*fakeConn)(nil)

func (c *fakeConn) IsValid() bool {
	return !c.isBad()
}

func (c *fakeConn) Close() (err error) {
	drv := fdriver.(*fakeDriver)
	defer func() {
		if err != nil && testStrictClose != nil {
			testStrictClose.Errorf("failed to close a test fakeConn: %v", err)
		}
		hookPostCloseConn.Lock()
		fn := hookPostCloseConn.fn
		hookPostCloseConn.Unlock()
		if fn != nil {
			fn(c, err)
		}
		if err == nil {
			drv.mu.Lock()
			drv.closeCount++
			drv.mu.Unlock()
		}
	}()
	c.touchMem()
	if c.currTx != nil {
		return errors.New("fakedb: can't close fakeConn; in a Transaction")
	}
	if c.db == nil {
		return errors.New("fakedb: can't close fakeConn; already closed")
	}
	if c.stmtsMade > c.stmtsClosed {
		return errors.New("fakedb: can't close; dangling statement(s)")
	}
	c.db = nil
	return nil
}

func checkSubsetTypes(allowAny bool, args []driver.NamedValue) error {
	for _, arg := range args {
		switch arg.Value.(type) {
		case int64, float64, bool, nil, []byte, string, time.Time:
		default:
			if !allowAny {
				return fmt.Errorf("fakedb: invalid argument ordinal %[1]d: %[2]v, type %[2]T", arg.Ordinal, arg.Value)
			}
		}
	}
	return nil
}

func (c *fakeConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	// Ensure that ExecContext is called if available.
	panic("ExecContext was not called.")
}

func (c *fakeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	// This is an optional interface, but it's implemented here
	// just to check that all the args are of the proper types.
	// ErrSkip is returned so the caller acts as if we didn't
	// implement this at all.
	err := checkSubsetTypes(c.db.allowAny, args)
	if err != nil {
		return nil, err
	}
	return nil, driver.ErrSkip
}

func (c *fakeConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	// Ensure that ExecContext is called if available.
	panic("QueryContext was not called.")
}

func (c *fakeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	// This is an optional interface, but it's implemented here
	// just to check that all the args are of the proper types.
	// ErrSkip is returned so the caller acts as if we didn't
	// implement this at all.
	err := checkSubsetTypes(c.db.allowAny, args)
	if err != nil {
		return nil, err
	}
	return nil, driver.ErrSkip
}

func errf(msg string, args ...any) error {
	return errors.New("fakedb: " + fmt.Sprintf(msg, args...))
}

// parts are table|selectCol1,selectCol2|whereCol=?,whereCol2=?
// (note that where columns must always contain ? marks,
// just a limitation for fakedb)
func (c *fakeConn) prepareSelect(stmt *fakeStmt, parts []string) (*fakeStmt, error) {
	if len(parts) != 3 {
		stmt.Close()
		return nil, errf("invalid SELECT syntax with %d parts; want 3", len(parts))
	}
	stmt.table = parts[0]

	stmt.colName = strings.Split(parts[1], ",")
	for n, colspec := range strings.Split(parts[2], ",") {
		if colspec == "" {
			continue
		}
		nameVal := strings.Split(colspec, "=")
		if len(nameVal) != 2 {
			stmt.Close()
			return nil, errf("SELECT on table %q has invalid column spec of %q (index %d)", stmt.table, colspec, n)
		}
		column, value := nameVal[0], nameVal[1]
		_, ok := c.db.columnType(stmt.table, column)
		if !ok {
			stmt.Close()
			return nil, errf("SELECT on table %q references non-existent column %q", stmt.table, column)
		}
		if !strings.HasPrefix(value, "?") {
			stmt.Close()
			return nil, errf("SELECT on table %q has pre-bound value for where column %q; need a question mark",
				stmt.table, column)
		}
		stmt.placeholders++
		stmt.whereCol = append(stmt.whereCol, boundCol{Column: column, Placeholder: value, Ordinal: stmt.placeholders})
	}
	return stmt, nil
}

// parts are table|col=type,col2=type2
func (c *fakeConn) prepareCreate(stmt *fakeStmt, parts []string) (*fakeStmt, error) {
	if len(parts) != 2 {
		stmt.Close()
		return nil, errf("invalid CREATE syntax with %d parts; want 2", len(parts))
	}
	stmt.table = parts[0]
	for n, colspec := range strings.Split(parts[1], ",") {
		nameType := strings.Split(colspec, "=")
		if len(nameType) != 2 {
			stmt.Close()
			return nil, errf("CREATE table %q has invalid column spec of %q (index %d)", stmt.table, colspec, n)
		}
		stmt.colName = append(stmt.colName, nameType[0])
		stmt.colType = append(stmt.colType, nameType[1])
	}
	return stmt, nil
}

// parts are table|col=?,col2=val
func (c *fakeConn) prepareInsert(ctx context.Context, stmt *fakeStmt, parts []string) (*fakeStmt, error) {
	if len(parts) != 2 {
		stmt.Close()
		return nil, errf("invalid INSERT syntax with %d parts; want 2", len(parts))
	}
	stmt.table = parts[0]
	for n, colspec := range strings.Split(parts[1], ",") {
		nameVal := strings.Split(colspec, "=")
		if len(nameVal) != 2 {
			stmt.Close()
			return nil, errf("INSERT table %q has invalid column spec of %q (index %d)", stmt.table, colspec, n)
		}
		column, value := nameVal[0], nameVal[1]
		ctype, ok := c.db.columnType(stmt.table, column)
		if !ok {
			stmt.Close()
			return nil, errf("INSERT table %q references non-existent column %q", stmt.table, column)
		}
		stmt.colName = append(stmt.colName, column)

		if !strings.HasPrefix(value, "?") {
			var subsetVal any
			// Convert to driver subset type
			switch ctype {
			case "string":
				subsetVal = []byte(value)
			case "blob":
				subsetVal = []byte(value)
			case "int32":
				i, err := strconv.Atoi(value)
				if err != nil {
					stmt.Close()
					return nil, errf("invalid conversion to int32 from %q", value)
				}
				subsetVal = int64(i) // int64 is a subset type, but not int32
			case "table": // For testing cursor reads.
				c.skipDirtySession = true
				vparts := strings.Split(value, "!")

				substmt, err := c.PrepareContext(ctx, fmt.Sprintf("SELECT|%s|%s|", vparts[0], strings.Join(vparts[1:], ",")))
				if err != nil {
					return nil, err
				}
				cursor, err := (substmt.(driver.StmtQueryContext)).QueryContext(ctx, []driver.NamedValue{})
				substmt.Close()
				if err != nil {
					return nil, err
				}
				subsetVal = cursor
			default:
				stmt.Close()
				return nil, errf("unsupported conversion for pre-bound parameter %q to type %q", value, ctype)
			}
			stmt.colValue = append(stmt.colValue, subsetVal)
		} else {
			stmt.placeholders++
			stmt.placeholderConverter = append(stmt.placeholderConverter, converterForType(ctype))
			stmt.colValue = append(stmt.colValue, value)
		}
	}
	return stmt, nil
}

// hook to simulate broken connections
var hookPrepareBadConn func() bool

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	panic("use PrepareContext")
}

func (c *fakeConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	c.numPrepare++
	if c.db == nil {
		panic("nil c.db; conn = " + fmt.Sprintf("%#v", c))
	}

	if c.stickyBad || (hookPrepareBadConn != nil && hookPrepareBadConn()) {
		return nil, fakeError{Message: "Prepare: Sticky Bad", Wrapped: driver.ErrBadConn}
	}

	c.touchMem()
	var firstStmt, prev *fakeStmt
	for _, query := range strings.Split(query, ";") {
		parts := strings.Split(query, "|")
		if len(parts) < 1 {
			return nil, errf("empty query")
		}
		stmt := &fakeStmt{q: query, c: c, memToucher: c}
		if firstStmt == nil {
			firstStmt = stmt
		}
		if len(parts) >= 3 {
			switch parts[0] {
			case "PANIC":
				stmt.panic = parts[1]
				parts = parts[2:]
			case "WAIT":
				wait, err := time.ParseDuration(parts[1])
				if err != nil {
					return nil, errf("expected section after WAIT to be a duration, got %q %v", parts[1], err)
				}
				parts = parts[2:]
				stmt.wait = wait
			}
		}
		cmd := parts[0]
		stmt.cmd = cmd
		parts = parts[1:]

		if c.waiter != nil {
			c.waiter(ctx)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		if stmt.wait > 0 {
			wait := time.NewTimer(stmt.wait)
			select {
			case <-wait.C:
			case <-ctx.Done():
				wait.Stop()
				return nil, ctx.Err()
			}
		}

		c.incrStat(&c.stmtsMade)
		var err error
		switch cmd {
		case "WIPE":
			// Nothing
		case "USE_RAWBYTES":
			c.db.useRawBytes.Store(true)
		case "SELECT":
			stmt, err = c.prepareSelect(stmt, parts)
		case "CREATE":
			stmt, err = c.prepareCreate(stmt, parts)
		case "INSERT":
			stmt, err = c.prepareInsert(ctx, stmt, parts)
		case "NOSERT":
			// Do all the prep-work like for an INSERT but don't actually insert the row.
			// Used for some of the concurrent tests.
			stmt, err = c.prepareInsert(ctx, stmt, parts)
		default:
			stmt.Close()
			return nil, errf("unsupported command type %q", cmd)
		}
		if err != nil {
			return nil, err
		}
		if prev != nil {
			prev.next = stmt
		}
		prev = stmt
	}
	return firstStmt, nil
}

func (s *fakeStmt) ColumnConverter(idx int) driver.ValueConverter {
	if s.panic == "ColumnConverter" {
		panic(s.panic)
	}
	if len(s.placeholderConverter) == 0 {
		return driver.DefaultParameterConverter
	}
	return s.placeholderConverter[idx]
}

func (s *fakeStmt) Close() error {
	if s.panic == "Close" {
		panic(s.panic)
	}
	if s.c == nil {
		panic("nil conn in fakeStmt.Close")
	}
	if s.c.db == nil {
		panic("in fakeStmt.Close, conn's db is nil (already closed)")
	}
	s.touchMem()
	if !s.closed {
		s.c.incrStat(&s.c.stmtsClosed)
		s.closed = true
	}
	if s.next != nil {
		s.next.Close()
	}
	return nil
}

var errClosed = errors.New("fakedb: statement has been closed")

// hook to simulate broken connections
var hookExecBadConn func() bool

func (s *fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	panic("Using ExecContext")
}

var errFakeConnSessionDirty = errors.New("fakedb: session is dirty")

func (s *fakeStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if s.panic == "Exec" {
		panic(s.panic)
	}
	if s.closed {
		return nil, errClosed
	}

	if s.c.stickyBad || (hookExecBadConn != nil && hookExecBadConn()) {
		return nil, fakeError{Message: "Exec: Sticky Bad", Wrapped: driver.ErrBadConn}
	}
	if s.c.isDirtyAndMark() {
		return nil, errFakeConnSessionDirty
	}

	err := checkSubsetTypes(s.c.db.allowAny, args)
	if err != nil {
		return nil, err
	}
	s.touchMem()

	if s.wait > 0 {
		time.Sleep(s.wait)
	}

	select {
	default:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	db := s.c.db
	switch s.cmd {
	case "WIPE":
		db.wipe()
		return driver.ResultNoRows, nil
	case "USE_RAWBYTES":
		s.c.db.useRawBytes.Store(true)
		return driver.ResultNoRows, nil
	case "CREATE":
		if err := db.createTable(s.table, s.colName, s.colType); err != nil {
			return nil, err
		}
		return driver.ResultNoRows, nil
	case "INSERT":
		return s.execInsert(args, true)
	case "NOSERT":
		// Do all the prep-work like for an INSERT but don't actually insert the row.
		// Used for some of the concurrent tests.
		return s.execInsert(args, false)
	}
	return nil, fmt.Errorf("fakedb: unimplemented statement Exec command type of %q", s.cmd)
}

func valueFromPlaceholderName(args []driver.NamedValue, name string) driver.Value {
	for i := range args {
		if args[i].Name == name {
			return args[i].Value
		}
	}
	return nil
}

// When doInsert is true, add the row to the table.
// When doInsert is false do prep-work and error checking, but don't
// actually add the row to the table.
func (s *fakeStmt) execInsert(args []driver.NamedValue, doInsert bool) (driver.Result, error) {
	db := s.c.db
	if len(args) != s.placeholders {
		panic("error in pkg db; should only get here if size is correct")
	}
	db.mu.Lock()
	t, ok := db.table(s.table)
	db.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("fakedb: table %q doesn't exist", s.table)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var cols []any
	if doInsert {
		cols = make([]any, len(t.colname))
	}
	argPos := 0
	for n, colname := range s.colName {
		colidx := t.columnIndex(colname)
		if colidx == -1 {
			return nil, fmt.Errorf("fakedb: column %q doesn't exist or dropped since prepared statement was created", colname)
		}
		var val any
		if strvalue, ok := s.colValue[n].(string); ok && strings.HasPrefix(strvalue, "?") {
			if strvalue == "?" {
				val = args[argPos].Value
			} else {
				// Assign value from argument placeholder name.
				if v := valueFromPlaceholderName(args, strvalue[1:]); v != nil {
					val = v
				}
			}
			argPos++
		} else {
			val = s.colValue[n]
		}
		if doInsert {
			cols[colidx] = val
		}
	}

	if doInsert {
		t.rows = append(t.rows, &row{cols: cols})
	}
	return driver.RowsAffected(1), nil
}

// hook to simulate broken connections
var hookQueryBadConn func() bool

func (s *fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	panic("Use QueryContext")
}

func (s *fakeStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if s.panic == "Query" {
		panic(s.panic)
	}
	if s.closed {
		return nil, errClosed
	}

	if s.c.stickyBad || (hookQueryBadConn != nil && hookQueryBadConn()) {
		return nil, fakeError{Message: "Query: Sticky Bad", Wrapped: driver.ErrBadConn}
	}
	if s.c.isDirtyAndMark() {
		return nil, errFakeConnSessionDirty
	}

	err := checkSubsetTypes(s.c.db.allowAny, args)
	if err != nil {
		return nil, err
	}

	s.touchMem()
	db := s.c.db
	if len(args) != s.placeholders {
		panic("error in pkg db; should only get here if size is correct")
	}

	setMRows := make([][]*row, 0, 1)
	setColumns := make([][]string, 0, 1)
	setColType := make([][]string, 0, 1)

	for {
		db.mu.Lock()
		t, ok := db.table(s.table)
		db.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("fakedb: table %q doesn't exist", s.table)
		}

		if s.table == "magicquery" {
			if len(s.whereCol) == 2 && s.whereCol[0].Column == "op" && s.whereCol[1].Column == "millis" {
				if args[0].Value == "sleep" {
					time.Sleep(time.Duration(args[1].Value.(int64)) * time.Millisecond)
				}
			}
		}
		if s.table == "tx_status" && s.colName[0] == "tx_status" {
			txStatus := "autocommit"
			if s.c.currTx != nil {
				txStatus = "transaction"
			}
			cursor := &rowsCursor{
				db:        s.c.db,
				parentMem: s.c,
				posRow:    -1,
				rows: [][]*row{
					{
						{
							cols: []any{
								txStatus,
							},
						},
					},
				},
				cols: [][]string{
					{
						"tx_status",
					},
				},
				colType: [][]string{
					{
						"string",
					},
				},
				errPos: -1,
			}
			return cursor, nil
		}

		t.mu.Lock()

		colIdx := make(map[string]int) // select column name -> column index in table
		for _, name := range s.colName {
			idx := t.columnIndex(name)
			if idx == -1 {
				t.mu.Unlock()
				return nil, fmt.Errorf("fakedb: unknown column name %q", name)
			}
			colIdx[name] = idx
		}

		mrows := []*row{}
	rows:
		for _, trow := range t.rows {
			// Process the where clause, skipping non-match rows. This is lazy
			// and just uses fmt.Sprintf("%v") to test equality. Good enough
			// for test code.
			for _, wcol := range s.whereCol {
				idx := t.columnIndex(wcol.Column)
				if idx == -1 {
					t.mu.Unlock()
					return nil, fmt.Errorf("fakedb: invalid where clause column %q", wcol)
				}
				tcol := trow.cols[idx]
				if bs, ok := tcol.([]byte); ok {
					// lazy hack to avoid sprintf %v on a []byte
					tcol = string(bs)
				}
				var argValue any
				if wcol.Placeholder == "?" {
					argValue = args[wcol.Ordinal-1].Value
				} else {
					if v := valueFromPlaceholderName(args, wcol.Placeholder[1:]); v != nil {
						argValue = v
					}
				}
				if fmt.Sprintf("%v", tcol) != fmt.Sprintf("%v", argValue) {
					continue rows
				}
			}
			mrow := &row{cols: make([]any, len(s.colName))}
			for seli, name := range s.colName {
				mrow.cols[seli] = trow.cols[colIdx[name]]
			}
			mrows = append(mrows, mrow)
		}

		var colType []string
		for _, column := range s.colName {
			colType = append(colType, t.coltype[t.columnIndex(column)])
		}

		t.mu.Unlock()

		setMRows = append(setMRows, mrows)
		setColumns = append(setColumns, s.colName)
		setColType = append(setColType, colType)

		if s.next == nil {
			break
		}
		s = s.next
	}

	cursor := &rowsCursor{
		db:        s.c.db,
		parentMem: s.c,
		posRow:    -1,
		rows:      setMRows,
		cols:      setColumns,
		colType:   setColType,
		errPos:    -1,
	}
	return cursor, nil
}

func (s *fakeStmt) NumInput() int {
	if s.panic == "NumInput" {
		panic(s.panic)
	}
	return s.placeholders
}

// hook to simulate broken connections
var hookCommitBadConn func() bool

func (tx *fakeTx) Commit() error {
	tx.c.currTx = nil
	if hookCommitBadConn != nil && hookCommitBadConn() {
		return fakeError{Message: "Commit: Hook Bad Conn", Wrapped: driver.ErrBadConn}
	}
	tx.c.touchMem()
	return nil
}

// hook to simulate broken connections
var hookRollbackBadConn func() bool

func (tx *fakeTx) Rollback() error {
	tx.c.currTx = nil
	if hookRollbackBadConn != nil && hookRollbackBadConn() {
		return fakeError{Message: "Rollback: Hook Bad Conn", Wrapped: driver.ErrBadConn}
	}
	tx.c.touchMem()
	return nil
}

type rowsCursor struct {
	db        *fakeDB
	parentMem memToucher
	cols      [][]string
	colType   [][]string
	posSet    int
	posRow    int
	rows      [][]*row
	closed    bool

	// errPos and err are for making Next return early with error.
	errPos int
	err    error

	// a clone of slices to give out to clients, indexed by the
	// original slice's first byte address.  we clone them
	// just so we're able to corrupt them on close.
	bytesClone map[*byte][]byte

	// Every operation writes to line to enable the race detector
	// check for data races.
	// This is separate from the fakeConn.line to allow for drivers that
	// can start multiple queries on the same transaction at the same time.
	line int64

	// closeErr is returned when rowsCursor.Close
	closeErr error
}

func (rc *rowsCursor) touchMem() {
	rc.parentMem.touchMem()
	rc.line++
}

func (rc *rowsCursor) Close() error {
	rc.touchMem()
	rc.parentMem.touchMem()
	rc.closed = true
	return rc.closeErr
}

func (rc *rowsCursor) Columns() []string {
	return rc.cols[rc.posSet]
}

func (rc *rowsCursor) ColumnTypeScanType(index int) reflect.Type {
	return colTypeToReflectType(rc.colType[rc.posSet][index])
}

var rowsCursorNextHook func(dest []driver.Value) error

func (rc *rowsCursor) Next(dest []driver.Value) error {
	if rowsCursorNextHook != nil {
		return rowsCursorNextHook(dest)
	}

	if rc.closed {
		return errors.New("fakedb: cursor is closed")
	}
	rc.touchMem()
	rc.posRow++
	if rc.posRow == rc.errPos {
		return rc.err
	}
	if rc.posRow >= len(rc.rows[rc.posSet]) {
		return io.EOF // per interface spec
	}
	for i, v := range rc.rows[rc.posSet][rc.posRow].cols {
		// TODO(bradfitz): convert to subset types? naah, I
		// think the subset types should only be input to
		// driver, but the sql package should be able to handle
		// a wider range of types coming out of drivers. all
		// for ease of drivers, and to prevent drivers from
		// messing up conversions or doing them differently.
		dest[i] = v

		if bs, ok := v.([]byte); ok && !rc.db.useRawBytes.Load() {
			if rc.bytesClone == nil {
				rc.bytesClone = make(map[*byte][]byte)
			}
			clone, ok := rc.bytesClone[&bs[0]]
			if !ok {
				clone = make([]byte, len(bs))
				copy(clone, bs)
				rc.bytesClone[&bs[0]] = clone
			}
			dest[i] = clone
		}
	}
	return nil
}

func (rc *rowsCursor) HasNextResultSet() bool {
	rc.touchMem()
	return rc.posSet < len(rc.rows)-1
}

func (rc *rowsCursor) NextResultSet() error {
	rc.touchMem()
	if rc.HasNextResultSet() {
		rc.posSet++
		rc.posRow = -1
		return nil
	}
	return io.EOF // Per interface spec.
}

// fakeDriverString is like driver.String, but indirects pointers like
// DefaultValueConverter.
//
// This could be surprising behavior to retroactively apply to
// driver.String now that Go1 is out, but this is convenient for
// our TestPointerParamsAndScans.
type fakeDriverString struct{}

func (fakeDriverString) ConvertValue(v any) (driver.Value, error) {
	switch c := v.(type) {
	case string, []byte:
		return v, nil
	case *string:
		if c == nil {
			return nil, nil
		}
		return *c, nil
	}
	return fmt.Sprintf("%v", v), nil
}

type anyTypeConverter struct{}

func (anyTypeConverter) ConvertValue(v any) (driver.Value, error) {
	return v, nil
}

func converterForType(typ string) driver.ValueConverter {
	switch typ {
	case "bool":
		return driver.Bool
	case "nullbool":
		return driver.Null{Converter: driver.Bool}
	case "byte", "int16":
		return driver.NotNull{Converter: driver.DefaultParameterConverter}
	case "int32":
		return driver.Int32
	case "nullbyte", "nullint32", "nullint16":
		return driver.Null{Converter: driver.DefaultParameterConverter}
	case "string":
		return driver.NotNull{Converter: fakeDriverString{}}
	case "nullstring":
		return driver.Null{Converter: fakeDriverString{}}
	case "int64":
		// TODO(coopernurse): add type-specific converter
		return driver.NotNull{Converter: driver.DefaultParameterConverter}
	case "nullint64":
		// TODO(coopernurse): add type-specific converter
		return driver.Null{Converter: driver.DefaultParameterConverter}
	case "float64":
		// TODO(coopernurse): add type-specific converter
		return driver.NotNull{Converter: driver.DefaultParameterConverter}
	case "nullfloat64":
		// TODO(coopernurse): add type-specific converter
		return driver.Null{Converter: driver.DefaultParameterConverter}
	case "datetime":
		return driver.NotNull{Converter: driver.DefaultParameterConverter}
	case "nulldatetime":
		return driver.Null{Converter: driver.DefaultParameterConverter}
	case "any":
		return anyTypeConverter{}
	}
	panic("invalid fakedb column type of " + typ)
}

func colTypeToReflectType(typ string) reflect.Type {
	switch typ {
	case "bool":
		return reflect.TypeFor[bool]()
	case "nullbool":
		return reflect.TypeFor[NullBool]()
	case "int16":
		return reflect.TypeFor[int16]()
	case "nullint16":
		return reflect.TypeFor[NullInt16]()
	case "int32":
		return reflect.TypeFor[int32]()
	case "nullint32":
		return reflect.TypeFor[NullInt32]()
	case "string":
		return reflect.TypeFor[string]()
	case "nullstring":
		return reflect.TypeFor[NullString]()
	case "int64":
		return reflect.TypeFor[int64]()
	case "nullint64":
		return reflect.TypeFor[NullInt64]()
	case "float64":
		return reflect.TypeFor[float64]()
	case "nullfloat64":
		return reflect.TypeFor[NullFloat64]()
	case "datetime":
		return reflect.TypeFor[time.Time]()
	case "any":
		return reflect.TypeFor[any]()
	}
	panic("invalid fakedb column type of " + typ)
}

"""



```