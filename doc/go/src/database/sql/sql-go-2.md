Response:
The user wants a summary of the functionality of the provided Go code snippet. This snippet is the third part of a four-part implementation of `go/src/database/sql/sql.go`.

Based on the code, the main functionalities seem to be related to:

1. **Transaction Management (within `Tx` struct):**
    *   `Rollback`: Aborting a transaction.
    *   `PrepareContext`/`Prepare`: Creating prepared statements within a transaction.
    *   `StmtContext`/`Stmt`:  Obtaining a transaction-specific prepared statement from an existing one.
    *   `ExecContext`/`Exec`: Executing queries that don't return rows within a transaction.
    *   `QueryContext`/`Query`: Executing queries that return rows within a transaction.
    *   `QueryRowContext`/`QueryRow`: Executing queries that return at most one row within a transaction.

2. **Prepared Statements (`Stmt` struct):**
    *   `ExecContext`/`Exec`: Executing a prepared statement.
    *   `QueryContext`/`Query`: Executing a prepared query statement.
    *   `QueryRowContext`/`QueryRow`: Executing a prepared query statement expecting a single row.
    *   `Close`: Closing a prepared statement.

3. **Result Sets (`Rows` struct):**
    *   `Next`: Moving to the next row in the result set.
    *   `NextResultSet`: Moving to the next result set in a multi-result set query.
    *   `Err`: Getting any error encountered during iteration.
    *   `Columns`: Getting the column names.
    *   `ColumnTypes`: Getting the column types.
    *   `Scan`: Copying the values from the current row into provided variables.
    *   `Close`: Closing the result set.

I need to synthesize these points into a concise summary.
这是 `go/src/database/sql/sql.go` 文件实现的第三部分，主要集中在以下两个核心功能上：

1. **事务操作 (`Tx` 结构体的方法):** 这部分代码实现了数据库事务的回滚（`Rollback`），以及在事务中进行预处理语句的创建和使用（`PrepareContext`，`Prepare`，`StmtContext`，`Stmt`），以及执行查询（`ExecContext`，`Exec`，`QueryContext`，`Query`，`QueryRowContext`，`QueryRow`）。这些方法确保了在事务上下文中的所有数据库操作要么全部成功，要么全部失败。

2. **预处理语句 (`Stmt` 结构体):** 这部分代码定义了预处理语句的结构体和相关操作。预处理语句可以提高数据库操作的效率，并防止SQL注入攻击。主要功能包括执行预处理语句（`ExecContext`，`Exec`，`QueryContext`，`Query`，`QueryRowContext`，`QueryRow`）和关闭预处理语句（`Close`）。

3. **结果集 (`Rows` 结构体):** 这部分代码定义了查询结果集的结构体和相关操作。主要功能包括遍历结果集（`Next`，`NextResultSet`），获取错误信息（`Err`），获取列名（`Columns`），获取列类型信息（`ColumnTypes`）以及将当前行的数据扫描到指定的变量中（`Scan`）。

**总结来说，这部分代码主要实现了在 Go 语言中使用 `database/sql` 包进行数据库事务管理、预处理语句操作以及处理查询结果集的核心功能。**

### 提示词
```
这是路径为go/src/database/sql/sql.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
if rollbackHook != nil {
		rollbackHook()
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
		err = tx.txi.Rollback()
	})
	if !errors.Is(err, driver.ErrBadConn) {
		tx.closePrepared()
	}
	if discardConn {
		err = driver.ErrBadConn
	}
	tx.close(err)
	return err
}

// Rollback aborts the transaction.
func (tx *Tx) Rollback() error {
	return tx.rollback(false)
}

// PrepareContext creates a prepared statement for use within a transaction.
//
// The returned statement operates within the transaction and will be closed
// when the transaction has been committed or rolled back.
//
// To use an existing prepared statement on this transaction, see [Tx.Stmt].
//
// The provided context will be used for the preparation of the context, not
// for the execution of the returned statement. The returned statement
// will run in the transaction context.
func (tx *Tx) PrepareContext(ctx context.Context, query string) (*Stmt, error) {
	dc, release, err := tx.grabConn(ctx)
	if err != nil {
		return nil, err
	}

	stmt, err := tx.db.prepareDC(ctx, dc, release, tx, query)
	if err != nil {
		return nil, err
	}
	tx.stmts.Lock()
	tx.stmts.v = append(tx.stmts.v, stmt)
	tx.stmts.Unlock()
	return stmt, nil
}

// Prepare creates a prepared statement for use within a transaction.
//
// The returned statement operates within the transaction and will be closed
// when the transaction has been committed or rolled back.
//
// To use an existing prepared statement on this transaction, see [Tx.Stmt].
//
// Prepare uses [context.Background] internally; to specify the context, use
// [Tx.PrepareContext].
func (tx *Tx) Prepare(query string) (*Stmt, error) {
	return tx.PrepareContext(context.Background(), query)
}

// StmtContext returns a transaction-specific prepared statement from
// an existing statement.
//
// Example:
//
//	updateMoney, err := db.Prepare("UPDATE balance SET money=money+? WHERE id=?")
//	...
//	tx, err := db.Begin()
//	...
//	res, err := tx.StmtContext(ctx, updateMoney).Exec(123.45, 98293203)
//
// The provided context is used for the preparation of the statement, not for the
// execution of the statement.
//
// The returned statement operates within the transaction and will be closed
// when the transaction has been committed or rolled back.
func (tx *Tx) StmtContext(ctx context.Context, stmt *Stmt) *Stmt {
	dc, release, err := tx.grabConn(ctx)
	if err != nil {
		return &Stmt{stickyErr: err}
	}
	defer release(nil)

	if tx.db != stmt.db {
		return &Stmt{stickyErr: errors.New("sql: Tx.Stmt: statement from different database used")}
	}
	var si driver.Stmt
	var parentStmt *Stmt
	stmt.mu.Lock()
	if stmt.closed || stmt.cg != nil {
		// If the statement has been closed or already belongs to a
		// transaction, we can't reuse it in this connection.
		// Since tx.StmtContext should never need to be called with a
		// Stmt already belonging to tx, we ignore this edge case and
		// re-prepare the statement in this case. No need to add
		// code-complexity for this.
		stmt.mu.Unlock()
		withLock(dc, func() {
			si, err = ctxDriverPrepare(ctx, dc.ci, stmt.query)
		})
		if err != nil {
			return &Stmt{stickyErr: err}
		}
	} else {
		stmt.removeClosedStmtLocked()
		// See if the statement has already been prepared on this connection,
		// and reuse it if possible.
		for _, v := range stmt.css {
			if v.dc == dc {
				si = v.ds.si
				break
			}
		}

		stmt.mu.Unlock()

		if si == nil {
			var ds *driverStmt
			withLock(dc, func() {
				ds, err = stmt.prepareOnConnLocked(ctx, dc)
			})
			if err != nil {
				return &Stmt{stickyErr: err}
			}
			si = ds.si
		}
		parentStmt = stmt
	}

	txs := &Stmt{
		db: tx.db,
		cg: tx,
		cgds: &driverStmt{
			Locker: dc,
			si:     si,
		},
		parentStmt: parentStmt,
		query:      stmt.query,
	}
	if parentStmt != nil {
		tx.db.addDep(parentStmt, txs)
	}
	tx.stmts.Lock()
	tx.stmts.v = append(tx.stmts.v, txs)
	tx.stmts.Unlock()
	return txs
}

// Stmt returns a transaction-specific prepared statement from
// an existing statement.
//
// Example:
//
//	updateMoney, err := db.Prepare("UPDATE balance SET money=money+? WHERE id=?")
//	...
//	tx, err := db.Begin()
//	...
//	res, err := tx.Stmt(updateMoney).Exec(123.45, 98293203)
//
// The returned statement operates within the transaction and will be closed
// when the transaction has been committed or rolled back.
//
// Stmt uses [context.Background] internally; to specify the context, use
// [Tx.StmtContext].
func (tx *Tx) Stmt(stmt *Stmt) *Stmt {
	return tx.StmtContext(context.Background(), stmt)
}

// ExecContext executes a query that doesn't return rows.
// For example: an INSERT and UPDATE.
func (tx *Tx) ExecContext(ctx context.Context, query string, args ...any) (Result, error) {
	dc, release, err := tx.grabConn(ctx)
	if err != nil {
		return nil, err
	}
	return tx.db.execDC(ctx, dc, release, query, args)
}

// Exec executes a query that doesn't return rows.
// For example: an INSERT and UPDATE.
//
// Exec uses [context.Background] internally; to specify the context, use
// [Tx.ExecContext].
func (tx *Tx) Exec(query string, args ...any) (Result, error) {
	return tx.ExecContext(context.Background(), query, args...)
}

// QueryContext executes a query that returns rows, typically a SELECT.
func (tx *Tx) QueryContext(ctx context.Context, query string, args ...any) (*Rows, error) {
	dc, release, err := tx.grabConn(ctx)
	if err != nil {
		return nil, err
	}

	return tx.db.queryDC(ctx, tx.ctx, dc, release, query, args)
}

// Query executes a query that returns rows, typically a SELECT.
//
// Query uses [context.Background] internally; to specify the context, use
// [Tx.QueryContext].
func (tx *Tx) Query(query string, args ...any) (*Rows, error) {
	return tx.QueryContext(context.Background(), query, args...)
}

// QueryRowContext executes a query that is expected to return at most one row.
// QueryRowContext always returns a non-nil value. Errors are deferred until
// [Row]'s Scan method is called.
// If the query selects no rows, the [*Row.Scan] will return [ErrNoRows].
// Otherwise, the [*Row.Scan] scans the first selected row and discards
// the rest.
func (tx *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *Row {
	rows, err := tx.QueryContext(ctx, query, args...)
	return &Row{rows: rows, err: err}
}

// QueryRow executes a query that is expected to return at most one row.
// QueryRow always returns a non-nil value. Errors are deferred until
// [Row]'s Scan method is called.
// If the query selects no rows, the [*Row.Scan] will return [ErrNoRows].
// Otherwise, the [*Row.Scan] scans the first selected row and discards
// the rest.
//
// QueryRow uses [context.Background] internally; to specify the context, use
// [Tx.QueryRowContext].
func (tx *Tx) QueryRow(query string, args ...any) *Row {
	return tx.QueryRowContext(context.Background(), query, args...)
}

// connStmt is a prepared statement on a particular connection.
type connStmt struct {
	dc *driverConn
	ds *driverStmt
}

// stmtConnGrabber represents a Tx or Conn that will return the underlying
// driverConn and release function.
type stmtConnGrabber interface {
	// grabConn returns the driverConn and the associated release function
	// that must be called when the operation completes.
	grabConn(context.Context) (*driverConn, releaseConn, error)

	// txCtx returns the transaction context if available.
	// The returned context should be selected on along with
	// any query context when awaiting a cancel.
	txCtx() context.Context
}

var (
	_ stmtConnGrabber = &Tx{}
	_ stmtConnGrabber = &Conn{}
)

// Stmt is a prepared statement.
// A Stmt is safe for concurrent use by multiple goroutines.
//
// If a Stmt is prepared on a [Tx] or [Conn], it will be bound to a single
// underlying connection forever. If the [Tx] or [Conn] closes, the Stmt will
// become unusable and all operations will return an error.
// If a Stmt is prepared on a [DB], it will remain usable for the lifetime of the
// [DB]. When the Stmt needs to execute on a new underlying connection, it will
// prepare itself on the new connection automatically.
type Stmt struct {
	// Immutable:
	db        *DB    // where we came from
	query     string // that created the Stmt
	stickyErr error  // if non-nil, this error is returned for all operations

	closemu sync.RWMutex // held exclusively during close, for read otherwise.

	// If Stmt is prepared on a Tx or Conn then cg is present and will
	// only ever grab a connection from cg.
	// If cg is nil then the Stmt must grab an arbitrary connection
	// from db and determine if it must prepare the stmt again by
	// inspecting css.
	cg   stmtConnGrabber
	cgds *driverStmt

	// parentStmt is set when a transaction-specific statement
	// is requested from an identical statement prepared on the same
	// conn. parentStmt is used to track the dependency of this statement
	// on its originating ("parent") statement so that parentStmt may
	// be closed by the user without them having to know whether or not
	// any transactions are still using it.
	parentStmt *Stmt

	mu     sync.Mutex // protects the rest of the fields
	closed bool

	// css is a list of underlying driver statement interfaces
	// that are valid on particular connections. This is only
	// used if cg == nil and one is found that has idle
	// connections. If cg != nil, cgds is always used.
	css []connStmt

	// lastNumClosed is copied from db.numClosed when Stmt is created
	// without tx and closed connections in css are removed.
	lastNumClosed uint64
}

// ExecContext executes a prepared statement with the given arguments and
// returns a [Result] summarizing the effect of the statement.
func (s *Stmt) ExecContext(ctx context.Context, args ...any) (Result, error) {
	s.closemu.RLock()
	defer s.closemu.RUnlock()

	var res Result
	err := s.db.retry(func(strategy connReuseStrategy) error {
		dc, releaseConn, ds, err := s.connStmt(ctx, strategy)
		if err != nil {
			return err
		}

		res, err = resultFromStatement(ctx, dc.ci, ds, args...)
		releaseConn(err)
		return err
	})

	return res, err
}

// Exec executes a prepared statement with the given arguments and
// returns a [Result] summarizing the effect of the statement.
//
// Exec uses [context.Background] internally; to specify the context, use
// [Stmt.ExecContext].
func (s *Stmt) Exec(args ...any) (Result, error) {
	return s.ExecContext(context.Background(), args...)
}

func resultFromStatement(ctx context.Context, ci driver.Conn, ds *driverStmt, args ...any) (Result, error) {
	ds.Lock()
	defer ds.Unlock()

	dargs, err := driverArgsConnLocked(ci, ds, args)
	if err != nil {
		return nil, err
	}

	resi, err := ctxDriverStmtExec(ctx, ds.si, dargs)
	if err != nil {
		return nil, err
	}
	return driverResult{ds.Locker, resi}, nil
}

// removeClosedStmtLocked removes closed conns in s.css.
//
// To avoid lock contention on DB.mu, we do it only when
// s.db.numClosed - s.lastNum is large enough.
func (s *Stmt) removeClosedStmtLocked() {
	t := len(s.css)/2 + 1
	if t > 10 {
		t = 10
	}
	dbClosed := s.db.numClosed.Load()
	if dbClosed-s.lastNumClosed < uint64(t) {
		return
	}

	s.db.mu.Lock()
	for i := 0; i < len(s.css); i++ {
		if s.css[i].dc.dbmuClosed {
			s.css[i] = s.css[len(s.css)-1]
			// Zero out the last element (for GC) before shrinking the slice.
			s.css[len(s.css)-1] = connStmt{}
			s.css = s.css[:len(s.css)-1]
			i--
		}
	}
	s.db.mu.Unlock()
	s.lastNumClosed = dbClosed
}

// connStmt returns a free driver connection on which to execute the
// statement, a function to call to release the connection, and a
// statement bound to that connection.
func (s *Stmt) connStmt(ctx context.Context, strategy connReuseStrategy) (dc *driverConn, releaseConn func(error), ds *driverStmt, err error) {
	if err = s.stickyErr; err != nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		err = errors.New("sql: statement is closed")
		return
	}

	// In a transaction or connection, we always use the connection that the
	// stmt was created on.
	if s.cg != nil {
		s.mu.Unlock()
		dc, releaseConn, err = s.cg.grabConn(ctx) // blocks, waiting for the connection.
		if err != nil {
			return
		}
		return dc, releaseConn, s.cgds, nil
	}

	s.removeClosedStmtLocked()
	s.mu.Unlock()

	dc, err = s.db.conn(ctx, strategy)
	if err != nil {
		return nil, nil, nil, err
	}

	s.mu.Lock()
	for _, v := range s.css {
		if v.dc == dc {
			s.mu.Unlock()
			return dc, dc.releaseConn, v.ds, nil
		}
	}
	s.mu.Unlock()

	// No luck; we need to prepare the statement on this connection
	withLock(dc, func() {
		ds, err = s.prepareOnConnLocked(ctx, dc)
	})
	if err != nil {
		dc.releaseConn(err)
		return nil, nil, nil, err
	}

	return dc, dc.releaseConn, ds, nil
}

// prepareOnConnLocked prepares the query in Stmt s on dc and adds it to the list of
// open connStmt on the statement. It assumes the caller is holding the lock on dc.
func (s *Stmt) prepareOnConnLocked(ctx context.Context, dc *driverConn) (*driverStmt, error) {
	si, err := dc.prepareLocked(ctx, s.cg, s.query)
	if err != nil {
		return nil, err
	}
	cs := connStmt{dc, si}
	s.mu.Lock()
	s.css = append(s.css, cs)
	s.mu.Unlock()
	return cs.ds, nil
}

// QueryContext executes a prepared query statement with the given arguments
// and returns the query results as a [*Rows].
func (s *Stmt) QueryContext(ctx context.Context, args ...any) (*Rows, error) {
	s.closemu.RLock()
	defer s.closemu.RUnlock()

	var rowsi driver.Rows
	var rows *Rows

	err := s.db.retry(func(strategy connReuseStrategy) error {
		dc, releaseConn, ds, err := s.connStmt(ctx, strategy)
		if err != nil {
			return err
		}

		rowsi, err = rowsiFromStatement(ctx, dc.ci, ds, args...)
		if err == nil {
			// Note: ownership of ci passes to the *Rows, to be freed
			// with releaseConn.
			rows = &Rows{
				dc:    dc,
				rowsi: rowsi,
				// releaseConn set below
			}
			// addDep must be added before initContextClose or it could attempt
			// to removeDep before it has been added.
			s.db.addDep(s, rows)

			// releaseConn must be set before initContextClose or it could
			// release the connection before it is set.
			rows.releaseConn = func(err error) {
				releaseConn(err)
				s.db.removeDep(s, rows)
			}
			var txctx context.Context
			if s.cg != nil {
				txctx = s.cg.txCtx()
			}
			rows.initContextClose(ctx, txctx)
			return nil
		}

		releaseConn(err)
		return err
	})

	return rows, err
}

// Query executes a prepared query statement with the given arguments
// and returns the query results as a *Rows.
//
// Query uses [context.Background] internally; to specify the context, use
// [Stmt.QueryContext].
func (s *Stmt) Query(args ...any) (*Rows, error) {
	return s.QueryContext(context.Background(), args...)
}

func rowsiFromStatement(ctx context.Context, ci driver.Conn, ds *driverStmt, args ...any) (driver.Rows, error) {
	ds.Lock()
	defer ds.Unlock()
	dargs, err := driverArgsConnLocked(ci, ds, args)
	if err != nil {
		return nil, err
	}
	return ctxDriverStmtQuery(ctx, ds.si, dargs)
}

// QueryRowContext executes a prepared query statement with the given arguments.
// If an error occurs during the execution of the statement, that error will
// be returned by a call to Scan on the returned [*Row], which is always non-nil.
// If the query selects no rows, the [*Row.Scan] will return [ErrNoRows].
// Otherwise, the [*Row.Scan] scans the first selected row and discards
// the rest.
func (s *Stmt) QueryRowContext(ctx context.Context, args ...any) *Row {
	rows, err := s.QueryContext(ctx, args...)
	if err != nil {
		return &Row{err: err}
	}
	return &Row{rows: rows}
}

// QueryRow executes a prepared query statement with the given arguments.
// If an error occurs during the execution of the statement, that error will
// be returned by a call to Scan on the returned [*Row], which is always non-nil.
// If the query selects no rows, the [*Row.Scan] will return [ErrNoRows].
// Otherwise, the [*Row.Scan] scans the first selected row and discards
// the rest.
//
// Example usage:
//
//	var name string
//	err := nameByUseridStmt.QueryRow(id).Scan(&name)
//
// QueryRow uses [context.Background] internally; to specify the context, use
// [Stmt.QueryRowContext].
func (s *Stmt) QueryRow(args ...any) *Row {
	return s.QueryRowContext(context.Background(), args...)
}

// Close closes the statement.
func (s *Stmt) Close() error {
	s.closemu.Lock()
	defer s.closemu.Unlock()

	if s.stickyErr != nil {
		return s.stickyErr
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	txds := s.cgds
	s.cgds = nil

	s.mu.Unlock()

	if s.cg == nil {
		return s.db.removeDep(s, s)
	}

	if s.parentStmt != nil {
		// If parentStmt is set, we must not close s.txds since it's stored
		// in the css array of the parentStmt.
		return s.db.removeDep(s.parentStmt, s)
	}
	return txds.Close()
}

func (s *Stmt) finalClose() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.css != nil {
		for _, v := range s.css {
			s.db.noteUnusedDriverStatement(v.dc, v.ds)
			v.dc.removeOpenStmt(v.ds)
		}
		s.css = nil
	}
	return nil
}

// Rows is the result of a query. Its cursor starts before the first row
// of the result set. Use [Rows.Next] to advance from row to row.
type Rows struct {
	dc          *driverConn // owned; must call releaseConn when closed to release
	releaseConn func(error)
	rowsi       driver.Rows
	cancel      func()      // called when Rows is closed, may be nil.
	closeStmt   *driverStmt // if non-nil, statement to Close on close

	contextDone atomic.Pointer[error] // error that awaitDone saw; set before close attempt

	// closemu prevents Rows from closing while there
	// is an active streaming result. It is held for read during non-close operations
	// and exclusively during close.
	//
	// closemu guards lasterr and closed.
	closemu sync.RWMutex
	lasterr error // non-nil only if closed is true
	closed  bool

	// closemuScanHold is whether the previous call to Scan kept closemu RLock'ed
	// without unlocking it. It does that when the user passes a *RawBytes scan
	// target. In that case, we need to prevent awaitDone from closing the Rows
	// while the user's still using the memory. See go.dev/issue/60304.
	//
	// It is only used by Scan, Next, and NextResultSet which are expected
	// not to be called concurrently.
	closemuScanHold bool

	// hitEOF is whether Next hit the end of the rows without
	// encountering an error. It's set in Next before
	// returning. It's only used by Next and Err which are
	// expected not to be called concurrently.
	hitEOF bool

	// lastcols is only used in Scan, Next, and NextResultSet which are expected
	// not to be called concurrently.
	lastcols []driver.Value

	// raw is a buffer for RawBytes that persists between Scan calls.
	// This is used when the driver returns a mismatched type that requires
	// a cloning allocation. For example, if the driver returns a *string and
	// the user is scanning into a *RawBytes, we need to copy the string.
	// The raw buffer here lets us reuse the memory for that copy across Scan calls.
	raw []byte
}

// lasterrOrErrLocked returns either lasterr or the provided err.
// rs.closemu must be read-locked.
func (rs *Rows) lasterrOrErrLocked(err error) error {
	if rs.lasterr != nil && rs.lasterr != io.EOF {
		return rs.lasterr
	}
	return err
}

// bypassRowsAwaitDone is only used for testing.
// If true, it will not close the Rows automatically from the context.
var bypassRowsAwaitDone = false

func (rs *Rows) initContextClose(ctx, txctx context.Context) {
	if ctx.Done() == nil && (txctx == nil || txctx.Done() == nil) {
		return
	}
	if bypassRowsAwaitDone {
		return
	}
	closectx, cancel := context.WithCancel(ctx)
	rs.cancel = cancel
	go rs.awaitDone(ctx, txctx, closectx)
}

// awaitDone blocks until ctx, txctx, or closectx is canceled.
// The ctx is provided from the query context.
// If the query was issued in a transaction, the transaction's context
// is also provided in txctx, to ensure Rows is closed if the Tx is closed.
// The closectx is closed by an explicit call to rs.Close.
func (rs *Rows) awaitDone(ctx, txctx, closectx context.Context) {
	var txctxDone <-chan struct{}
	if txctx != nil {
		txctxDone = txctx.Done()
	}
	select {
	case <-ctx.Done():
		err := ctx.Err()
		rs.contextDone.Store(&err)
	case <-txctxDone:
		err := txctx.Err()
		rs.contextDone.Store(&err)
	case <-closectx.Done():
		// rs.cancel was called via Close(); don't store this into contextDone
		// to ensure Err() is unaffected.
	}
	rs.close(ctx.Err())
}

// Next prepares the next result row for reading with the [Rows.Scan] method. It
// returns true on success, or false if there is no next result row or an error
// happened while preparing it. [Rows.Err] should be consulted to distinguish between
// the two cases.
//
// Every call to [Rows.Scan], even the first one, must be preceded by a call to [Rows.Next].
func (rs *Rows) Next() bool {
	// If the user's calling Next, they're done with their previous row's Scan
	// results (any RawBytes memory), so we can release the read lock that would
	// be preventing awaitDone from calling close.
	rs.closemuRUnlockIfHeldByScan()

	if rs.contextDone.Load() != nil {
		return false
	}

	var doClose, ok bool
	withLock(rs.closemu.RLocker(), func() {
		doClose, ok = rs.nextLocked()
	})
	if doClose {
		rs.Close()
	}
	if doClose && !ok {
		rs.hitEOF = true
	}
	return ok
}

func (rs *Rows) nextLocked() (doClose, ok bool) {
	if rs.closed {
		return false, false
	}

	// Lock the driver connection before calling the driver interface
	// rowsi to prevent a Tx from rolling back the connection at the same time.
	rs.dc.Lock()
	defer rs.dc.Unlock()

	if rs.lastcols == nil {
		rs.lastcols = make([]driver.Value, len(rs.rowsi.Columns()))
	}

	rs.lasterr = rs.rowsi.Next(rs.lastcols)
	if rs.lasterr != nil {
		// Close the connection if there is a driver error.
		if rs.lasterr != io.EOF {
			return true, false
		}
		nextResultSet, ok := rs.rowsi.(driver.RowsNextResultSet)
		if !ok {
			return true, false
		}
		// The driver is at the end of the current result set.
		// Test to see if there is another result set after the current one.
		// Only close Rows if there is no further result sets to read.
		if !nextResultSet.HasNextResultSet() {
			doClose = true
		}
		return doClose, false
	}
	return false, true
}

// NextResultSet prepares the next result set for reading. It reports whether
// there is further result sets, or false if there is no further result set
// or if there is an error advancing to it. The [Rows.Err] method should be consulted
// to distinguish between the two cases.
//
// After calling NextResultSet, the [Rows.Next] method should always be called before
// scanning. If there are further result sets they may not have rows in the result
// set.
func (rs *Rows) NextResultSet() bool {
	// If the user's calling NextResultSet, they're done with their previous
	// row's Scan results (any RawBytes memory), so we can release the read lock
	// that would be preventing awaitDone from calling close.
	rs.closemuRUnlockIfHeldByScan()

	var doClose bool
	defer func() {
		if doClose {
			rs.Close()
		}
	}()
	rs.closemu.RLock()
	defer rs.closemu.RUnlock()

	if rs.closed {
		return false
	}

	rs.lastcols = nil
	nextResultSet, ok := rs.rowsi.(driver.RowsNextResultSet)
	if !ok {
		doClose = true
		return false
	}

	// Lock the driver connection before calling the driver interface
	// rowsi to prevent a Tx from rolling back the connection at the same time.
	rs.dc.Lock()
	defer rs.dc.Unlock()

	rs.lasterr = nextResultSet.NextResultSet()
	if rs.lasterr != nil {
		doClose = true
		return false
	}
	return true
}

// Err returns the error, if any, that was encountered during iteration.
// Err may be called after an explicit or implicit [Rows.Close].
func (rs *Rows) Err() error {
	// Return any context error that might've happened during row iteration,
	// but only if we haven't reported the final Next() = false after rows
	// are done, in which case the user might've canceled their own context
	// before calling Rows.Err.
	if !rs.hitEOF {
		if errp := rs.contextDone.Load(); errp != nil {
			return *errp
		}
	}

	rs.closemu.RLock()
	defer rs.closemu.RUnlock()
	return rs.lasterrOrErrLocked(nil)
}

// rawbuf returns the buffer to append RawBytes values to.
// This buffer is reused across calls to Rows.Scan.
//
// Usage:
//
//	rawBytes = rows.setrawbuf(append(rows.rawbuf(), value...))
func (rs *Rows) rawbuf() []byte {
	if rs == nil {
		// convertAssignRows can take a nil *Rows; for simplicity handle it here
		return nil
	}
	return rs.raw
}

// setrawbuf updates the RawBytes buffer with the result of appending a new value to it.
// It returns the new value.
func (rs *Rows) setrawbuf(b []byte) RawBytes {
	if rs == nil {
		// convertAssignRows can take a nil *Rows; for simplicity handle it here
		return RawBytes(b)
	}
	off := len(rs.raw)
	rs.raw = b
	return RawBytes(rs.raw[off:])
}

var errRowsClosed = errors.New("sql: Rows are closed")
var errNoRows = errors.New("sql: no Rows available")

// Columns returns the column names.
// Columns returns an error if the rows are closed.
func (rs *Rows) Columns() ([]string, error) {
	rs.closemu.RLock()
	defer rs.closemu.RUnlock()
	if rs.closed {
		return nil, rs.lasterrOrErrLocked(errRowsClosed)
	}
	if rs.rowsi == nil {
		return nil, rs.lasterrOrErrLocked(errNoRows)
	}
	rs.dc.Lock()
	defer rs.dc.Unlock()

	return rs.rowsi.Columns(), nil
}

// ColumnTypes returns column information such as column type, length,
// and nullable. Some information may not be available from some drivers.
func (rs *Rows) ColumnTypes() ([]*ColumnType, error) {
	rs.closemu.RLock()
	defer rs.closemu.RUnlock()
	if rs.closed {
		return nil, rs.lasterrOrErrLocked(errRowsClosed)
	}
	if rs.rowsi == nil {
		return nil, rs.lasterrOrErrLocked(errNoRows)
	}
	rs.dc.Lock()
	defer rs.dc.Unlock()

	return rowsColumnInfoSetupConnLocked(rs.rowsi), nil
}

// ColumnType contains the name and type of a column.
type ColumnType struct {
	name string

	hasNullable       bool
	hasLength         bool
	hasPrecisionScale bool

	nullable     bool
	length       int64
	databaseType string
	precision    int64
	scale        int64
	scanType     reflect.Type
}

// Name returns the name or alias of the column.
func (ci *ColumnType) Name() string {
	return ci.name
}

// Length returns the column type length for variable length column types such
// as text and binary field types. If the type length is unbounded the value will
// be [math.MaxInt64] (any database limits will still apply).
// If the column type is not variable length, such as an int, or if not supported
// by the driver ok is false.
func (ci *ColumnType) Length() (length int64, ok bool) {
	return ci.length, ci.hasLength
}

// DecimalSize returns the scale and precision of a decimal type.
// If not applicable or if not supported ok is false.
func (ci *ColumnType) DecimalSize() (precision, scale int64, ok bool) {
	return ci.precision, ci.scale, ci.hasPrecisionScale
}

// ScanType returns a Go type suitable for scanning into using [Rows.Scan].
// If a driver does not support this property ScanType will return
// the type of an empty interface.
func (ci *ColumnType) ScanType() reflect.Type {
	return ci.scanType
}

// Nullable reports whether the column may be null.
// If a driver does not support this property ok will be false.
func (ci *ColumnType) Nullable() (nullable, ok bool) {
	return ci.nullable, ci.hasNullable
}

// DatabaseTypeName returns the database system name of the column type. If an empty
// string is returned, then the driver type name is not supported.
// Consult your driver documentation for a list of driver data types. [ColumnType.Length] specifiers
// are not included.
// Common type names include "VARCHAR", "TEXT", "NVARCHAR", "DECIMAL", "BOOL",
// "INT", and "BIGINT".
func (ci *ColumnType) DatabaseTypeName() string {
	return ci.databaseType
}

func rowsColumnInfoSetupConnLocked(rowsi driver.Rows) []*ColumnType {
	names := rowsi.Columns()

	list := make([]*ColumnType, len(names))
	for i := range list {
		ci := &ColumnType{
			name: names[i],
		}
		list[i] = ci

		if prop, ok := rowsi.(driver.RowsColumnTypeScanType); ok {
			ci.scanType = prop.ColumnTypeScanType(i)
		} else {
			ci.scanType = reflect.TypeFor[any]()
		}
		if prop, ok := rowsi.(driver.RowsColumnTypeDatabaseTypeName); ok {
			ci.databaseType = prop.ColumnTypeDatabaseTypeName(i)
		}
		if prop, ok := rowsi.(driver.RowsColumnTypeLength); ok {
			ci.length, ci.hasLength = prop.ColumnTypeLength(i)
		}
		if prop, ok := rowsi.(driver.RowsColumnTypeNullable); ok {
			ci.nullable, ci.hasNullable = prop.ColumnTypeNullable(i)
		}
		if prop, ok := rowsi.(driver.RowsColumnTypePrecisionScale); ok {
			ci.precision, ci.scale, ci.hasPrecisionScale = prop.ColumnTypePrecisionScale(i)
		}
	}
	return list
}

// Scan copies the columns in the current row into the values pointed
// at by dest. The number of values in dest must be the same as the
// number of columns in [Rows].
//
// Scan converts columns read from the database into the following
// common Go types and special types provided by the sql package:
//
//	*string
//	*[]byte
//	*int, *int8, *int16, *int32, *int64
//	*uint, *uint8, *uint16, *uint32, *uint64
//	*bool
//	*float32, *float64
//	*interface{}
//	*RawBytes
//	*Rows (cursor value)
//	any type implementing Scanner (see Scanner docs)
//
// In the most simple case, if the type of the value from the source
// column is an integer, bool or string type T and dest is of type *T,
// Scan simply assigns the value through the pointer.
//
// Scan also converts between string and numeric types, as long as no
// information would be lost. While Scan stringifies all numbers
// scanned from numeric database columns into *string, scans into
// numeric types are checked for overflow. For example, a float64 with
// value 300 or a string with value "300" can scan into a uint16, but
// not into a uint8, though float64(255) or "255" can scan into a
// uint8. One exception is that scans of some float64 numbers to
// strings may lose information when stringifying. In general, scan
// floating point columns into *float64.
//
// If a dest argument has type *[]byte, Scan saves in that argument a
// copy of the corresponding data. The copy is owned by the caller and
// can be modified and held indefinitely. The copy can be avoided by
// using an argument of type [*RawBytes] instead; see the documentation
// for [RawBytes] for restrictions on its use.
//
// If an argument has type *interface{}, Scan copies the value
// provided by the underlying driver without conversion. When scanning
// from a source value of type []byte to *interface{}, a copy of the
// slice is made and the caller owns the result.
//
// Source values of type [time.Time] may be scanned into values of type
// *time.Time, *interface{}, *string, or *[]byte. When converting to
// the latter two, [time.RFC3339Nano] is used.
//
// Source values of type bool may be scanned into types *bool,
// *interface{}, *string, *[]byte, or [*RawBytes].
//
// For scanning into *bool, the source may be true, false, 1, 0, or
// string inputs parseable by [strconv.ParseBool].
//
// Scan can also convert a cursor returned from a query, such as
// "select cursor(select * from my_table) from dual", into a
// [*Rows] value that can itself be scanned from. The parent
// select query will close any cursor [*Rows] if the parent [*Rows] is closed.
//
// If any of the first arguments implementing [Scanner] returns an error,
// that error will be wrapped in the returned error.
func (rs *Rows) Scan(dest ...any) error {
	if rs.closemuScanHold {
		// This should only be possible if the user calls Scan twice in a row
		// without calling Next.
		return fmt.Errorf("sql: Scan called without calling Next (closemuScanHold)")
	}
	rs.closemu.RLock()

	if rs.lasterr != nil && rs.lasterr != io.EOF {
		rs.closemu.RUnlock()
		return rs.lasterr
	}
	if rs.closed {
		err := rs.lasterrOrErrLocked(errRowsClosed)
		rs.closemu.RUnlock()
		return err
	}

	if scanArgsContainRawBytes(dest) {
		rs.closemuScanHold = true
		rs.raw = rs.raw[:0]
	} else {
		rs.closemu.RUnlock()
	}

	if rs.lastcols == nil {
		rs.closemuRUnlockIfHeldByScan()
		return errors.New("sql: Scan called without calling Next")
	}
	if len(dest) != len(rs.lastcols) {
		rs.closemuRUnlockIfHeldByScan()
		return fmt.Errorf("sql: expected %d destination arguments in Scan, not %d", len(rs.lastcols), len(dest))
	}

	for i, sv := range rs.lastcols {
		err := convertAssi
```