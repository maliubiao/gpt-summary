Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for the functionalities demonstrated in the `example_test.go` file. It specifically mentions identifying the Go features being illustrated and providing code examples. Key elements include: listing functionalities, explaining Go feature implementations, providing example code with input/output, discussing command-line arguments (though none are present here), and highlighting common mistakes.

**2. Initial Code Scan and Pattern Recognition:**

I'll first quickly scan the code, looking for familiar Go idioms and function names. I notice:

* **`package sql_test`:**  This tells me it's a test file within the `database/sql` package, focused on demonstrating usage.
* **`import` statements:**  These indicate the dependencies. `database/sql`, `fmt`, `log`, `strings`, and `time` are core libraries for database interaction, formatting, logging, string manipulation, and time handling. The `context` package is also present, suggesting asynchronous or timeout-aware operations.
* **Function names starting with `Example`:** This is a strong indicator of Go example functions, designed to be run by `go test` and often used in documentation. Each `Example` function likely showcases a specific `database/sql` functionality.
* **Variables `ctx` and `db`:** These seem to be globally scoped, suggesting a shared context and database connection for the examples. While not explicitly initialized in this snippet, their presence is important.
* **Common `database/sql` types and methods:** `DB`, `Rows`, `Row`, `Stmt`, `Tx`, `Conn`, and methods like `QueryContext`, `QueryRowContext`, `ExecContext`, `PrepareContext`, `BeginTx`, `Commit`, `Rollback`, `Scan`, `Close`, `Next`, `Err`, `RowsAffected`, `PingContext`. These are the building blocks of database interactions in Go.

**3. Analyzing Each `Example` Function:**

Now, I'll go through each `Example` function systematically and identify its purpose:

* **`ExampleDB_QueryContext`:**  The name suggests querying the database with a context. The code selects names from a `users` table based on age. It iterates through the rows, scans the results, and handles potential errors during scanning and closing the rows. This clearly demonstrates basic data retrieval with parameters.

* **`ExampleDB_QueryRowContext`:** Similar to the above, but it expects a single row as a result. It handles the `sql.ErrNoRows` case specifically. This showcases fetching a single record.

* **`ExampleDB_ExecContext`:** This function updates data in the database. It shows how to execute non-query statements (like `UPDATE`) and retrieve the number of affected rows.

* **`ExampleDB_Query_multipleResultSets`:** This is more complex. The SQL query creates a temporary table, inserts data, and then performs two separate `SELECT` queries. The Go code then iterates through both result sets using `rows.Next()` and `rows.NextResultSet()`. This highlights handling multiple result sets from a single query.

* **`ExampleDB_PingContext`:**  The name and comments clearly indicate this demonstrates checking the database connection. It uses a timeout and reports the status.

* **`ExampleDB_Prepare`:** This shows how to use prepared statements for inserting multiple records efficiently. It prepares the statement once and then executes it multiple times with different parameters.

* **`ExampleTx_Prepare`:** Similar to the above, but this prepares the statement within a transaction. This highlights the use of prepared statements within transactional contexts.

* **`ExampleDB_BeginTx`:** This demonstrates initiating a transaction using `BeginTx` and specifies the isolation level. It shows a simple `UPDATE` operation within a transaction and handles potential rollback.

* **`ExampleConn_ExecContext`:**  This illustrates obtaining a single connection from the pool using `db.Conn()` and executing a query on it. This is useful for ensuring operations happen on the same connection.

* **`ExampleTx_ExecContext`:**  This is another example of executing a statement within a transaction, with more robust error handling for rollback scenarios.

* **`ExampleTx_Rollback`:** This focuses on demonstrating how to explicitly rollback a transaction in case of errors.

* **`ExampleStmt` and `ExampleStmt_QueryRowContext`:** These are very similar and emphasize the lifecycle of a prepared statement: preparing it once and then executing it multiple times.

* **`ExampleRows`:** This provides a more basic example of iterating through rows returned by a query and checking for errors during iteration.

**4. Identifying Go Features:**

While analyzing each example, I'm also noting the specific Go features being used:

* **Context:**  Used for managing deadlines and cancellation (`context.Context`, `context.WithTimeout`).
* **Error Handling:**  Consistent checking of `err` after database operations. Use of `log.Fatal` and `log.Printf`.
* **Deferred Operations:** `defer rows.Close()`, `defer stmt.Close()`, `defer tx.Rollback()`, `defer conn.Close()`. This ensures resources are released correctly.
* **Data Structures:**  Slices (`[]string`), maps (`map[int64]string`).
* **String Manipulation:** `strings.Join`.
* **Time Handling:** `time.Time`.
* **Switch Statement:** Handling different error conditions in `ExampleDB_QueryRowContext`.
* **Structs:** Defining data structures for the `projects` slice.
* **Pointers:**  Passing the address of variables to `rows.Scan()`.
* **Variadic Arguments:**  Used in `fmt.Printf` and potentially in the database driver's query execution.

**5. Constructing Example Code and Identifying Inputs/Outputs:**

For each functionality, I consider what a minimal, self-contained example would look like. This involves:

* **Setting up a mock `db`:**  Since the provided code doesn't initialize the database connection, I need to acknowledge this dependency and explain that the examples assume a working `db` connection. I could even sketch a basic initialization if needed, though the prompt doesn't require it.
* **Defining example data:**  Creating sample data for `users`, `balances`, `user_roles`, and `projects` tables to make the examples runnable conceptually.
* **Predicting outputs:** Based on the example queries and data, I can infer what the `fmt.Printf` or `log.Printf` statements would output.

**6. Addressing Command-Line Arguments:**

I carefully read the code and realize there are no direct uses of `os.Args` or the `flag` package. Therefore, I can state that no command-line arguments are processed in this specific snippet.

**7. Identifying Common Mistakes:**

I think about common pitfalls when working with databases in Go:

* **Forgetting to close `Rows`:** Leading to resource leaks.
* **Not checking `rows.Err()`:** Missing potential errors during row iteration.
* **Not handling `sql.ErrNoRows`:** Incorrectly assuming a row will always be returned by `QueryRowContext`.
* **Not rolling back transactions on error:** Leaving the database in an inconsistent state.
* **Not closing prepared statements:**  Hogging server resources.
* **Ignoring errors from `tx.Commit()` and `tx.Rollback()`:** These operations can fail.

**8. Structuring the Answer:**

Finally, I organize my findings into a clear and structured answer, using headings and bullet points for readability. I ensure to address all parts of the original request. I try to use precise language and provide specific code examples where requested.

By following this systematic approach, I can comprehensively analyze the given Go code snippet and provide a detailed and accurate response to the prompt.
这段代码是 Go 语言标准库 `database/sql` 包的示例代码，用于演示如何使用该包进行数据库操作。它涵盖了多个常见的数据库操作场景，展示了 `database/sql` 包提供的各种 API 的用法。

以下是它包含的功能的详细列表：

1. **执行查询并处理多行结果 (`ExampleDB_QueryContext`)**:
    *   展示了使用 `db.QueryContext` 执行 SELECT 查询的方法。
    *   演示了如何迭代 `sql.Rows` 类型的结果集。
    *   强调了使用 `defer rows.Close()` 关闭结果集的重要性，以释放资源。
    *   说明了在迭代过程中使用 `rows.Scan()` 将数据扫描到变量中。
    *   提到了检查 `rows.Err()` 以捕获迭代过程中的错误。
    *   强调了在数据库写入操作后检查 `rows.Close()` 返回的错误，以确保事务的完整性。

2. **执行查询并处理单行结果 (`ExampleDB_QueryRowContext`)**:
    *   展示了使用 `db.QueryRowContext` 执行预期返回单行的 SELECT 查询的方法。
    *   演示了直接使用 `.Scan()` 将结果扫描到变量中。
    *   说明了如何处理 `sql.ErrNoRows` 错误，表示没有找到匹配的行。

3. **执行非查询语句 (`ExampleDB_ExecContext`)**:
    *   展示了使用 `db.ExecContext` 执行 UPDATE、INSERT、DELETE 等非查询语句的方法。
    *   演示了如何使用 `result.RowsAffected()` 获取受影响的行数。

4. **处理包含多个结果集的查询 (`ExampleDB_Query_multipleResultSets`)**:
    *   展示了如何执行返回多个结果集的 SQL 查询。
    *   演示了使用 `rows.NextResultSet()` 移动到下一个结果集。
    *   强调了在预期有多个结果集时检查 `rows.NextResultSet()` 的返回值和 `rows.Err()`。

5. **检查数据库连接状态 (`ExampleDB_PingContext`)**:
    *   展示了使用 `db.PingContext` 测试与数据库服务器连接是否正常的方法。
    *   说明了 `PingContext` 在命令行应用和长期运行服务中的用途（例如健康检查）。
    *   演示了使用 `context.WithTimeout` 设置超时时间。

6. **使用预编译语句 (`ExampleDB_Prepare` 和 `ExampleTx_Prepare`)**:
    *   展示了使用 `db.Prepare` (或 `tx.Prepare` 在事务中) 创建预编译语句的方法。
    *   说明了预编译语句可以提高性能，特别是对于重复执行的相似查询。
    *   演示了使用 `stmt.Exec` 执行预编译语句并传递参数。
    *   强调了使用 `defer stmt.Close()` 关闭预编译语句以释放服务器资源。

7. **使用事务 (`ExampleDB_BeginTx`, `ExampleConn_ExecContext`, `ExampleTx_ExecContext`, `ExampleTx_Rollback`)**:
    *   展示了使用 `db.BeginTx` 开启事务的方法，并可以指定事务隔离级别。
    *   演示了在事务中执行多个数据库操作。
    *   说明了在事务中发生错误时使用 `tx.Rollback()` 回滚事务。
    *   演示了在所有操作成功后使用 `tx.Commit()` 提交事务。
    *   展示了使用 `db.Conn(ctx)` 获取一个独立的数据库连接，并在该连接上执行操作，这可以用于需要确保某些操作在同一个连接上执行的场景。
    *   演示了如何在 `Tx.ExecContext` 中处理错误并进行回滚。

8. **使用预编译语句对象 (`ExampleStmt` 和 `ExampleStmt_QueryRowContext`)**:
    *   进一步强调了预编译语句的使用。
    *   展示了先使用 `db.PrepareContext` 创建 `Stmt` 对象，然后多次使用 `stmt.QueryRowContext` 执行查询。

9. **直接使用 `sql.Rows` 对象 (`ExampleRows`)**:
    *   提供了一个更简洁的迭代 `sql.Rows` 的示例，强调了在迭代结束后检查 `rows.Err()` 的重要性。

**它是什么 Go 语言功能的实现？**

这段代码主要演示了 Go 语言标准库中 `database/sql` 包提供的用于数据库操作的功能。  具体来说，它展示了以下核心概念和类型的使用：

*   **`database/sql.DB`**:  代表一个数据库连接池。
*   **`context.Context`**: 用于传递请求的截止时间、取消信号和其他请求范围的值。
*   **`database/sql.Rows`**:  代表查询返回的多行结果集。
*   **`database/sql.Row`**: 代表查询返回的单行结果。
*   **`database/sql.Stmt`**: 代表一个预编译的 SQL 语句。
*   **`database/sql.Tx`**: 代表一个数据库事务。
*   **`database/sql.Conn`**: 代表一个独立的数据库连接。
*   **错误处理**:  通过检查函数返回值中的 `error` 类型来处理数据库操作可能发生的错误。
*   **`defer` 语句**: 用于确保资源（如 `Rows`、`Stmt`、`Tx`、`Conn`) 在函数退出时被释放。

**Go 代码举例说明 (`ExampleDB_QueryContext` 功能):**

假设我们有一个名为 `users` 的数据库表，结构如下：

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT,
    age INTEGER
);

INSERT INTO users (id, name, age) VALUES (1, 'Alice', 27);
INSERT INTO users (id, name, age) VALUES (2, 'Bob', 27);
INSERT INTO users (id, name, age) VALUES (3, 'Charlie', 30);
```

运行 `ExampleDB_QueryContext` 函数，假设 `db` 已经成功连接到数据库。

**假设的输入:**

*   数据库连接 `db` 已建立。
*   `ctx` 是一个有效的 `context.Context`。
*   `users` 表中存在年龄为 27 的用户 'Alice' 和 'Bob'。

**输出:**

```
Alice, Bob are 27 years old
```

**代码推理 (以 `ExampleDB_Query_multipleResultSets` 为例):**

假设数据库中 `users` 表的数据如上所示，并且 `user_roles` 表有以下数据：

```sql
CREATE TABLE user_roles (
    user INTEGER,
    role INTEGER
);

INSERT INTO user_roles (user, role) VALUES (1, 1); -- Alice: user
INSERT INTO user_roles (user, role) VALUES (2, 2); -- Bob: admin
```

运行 `ExampleDB_Query_multipleResultSets` 函数，`age` 设置为 28。

**假设的输入:**

*   数据库连接 `db` 已建立。
*   `ctx` 是一个有效的 `context.Context`。
*   `users` 表和 `user_roles` 表存在并包含上述数据。
*   `age` 变量的值为 `28`。

**输出:**

```
id 1 name is Alice
id 2 name is Bob
id 1 has role user
id 2 has role admin
```

**推理过程:**

1. **临时表创建和数据插入:**  SQL 查询首先创建一个名为 `uid` 的临时表，并将 `users` 表中 `age` 小于 28 的用户的 `id` 插入到该表中。在这个例子中，只有 Alice (age 27) 和 Bob (age 27) 的 id 会被插入。

2. **第一个结果集:**  查询连接 `users` 表和 `uid` 表，返回 `users` 表中 `id` 存在于 `uid` 表中的用户的 `id` 和 `name`。因此，会返回 Alice 和 Bob 的 id 和 name。

3. **第二个结果集:** 查询连接 `user_roles` 表和 `uid` 表，返回 `user_roles` 表中 `user` (即用户 ID) 存在于 `uid` 表中的用户的 `user` 和 `role`。因此，会返回 Alice 和 Bob 的 user 和 role。

4. **Go 代码处理:** Go 代码使用 `rows.Next()` 遍历第一个结果集，并使用 `rows.Scan()` 将 `id` 和 `name` 扫描到变量中并打印。然后，使用 `rows.NextResultSet()` 移动到第二个结果集，再次使用 `rows.Next()` 和 `rows.Scan()` 遍历并打印 `id` 和对应的角色（从 `roleMap` 中获取）。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个测试文件，用于演示 `database/sql` 包的功能。命令行参数通常在应用程序的主入口点 (`main` 函数) 中使用 `flag` 包或类似的库进行解析。

**使用者易犯错的点:**

1. **忘记关闭 `sql.Rows`**:  如果不使用 `defer rows.Close()` 关闭 `sql.Rows`，可能会导致数据库连接泄漏，最终耗尽资源。

    ```go
    func badExample() {
        rows, err := db.QueryContext(ctx, "SELECT name FROM users")
        if err != nil {
            log.Fatal(err)
        }
        // 忘记 defer rows.Close()
        for rows.Next() {
            var name string
            if err := rows.Scan(&name); err != nil {
                log.Fatal(err)
            }
            fmt.Println(name)
        }
        if err := rows.Err(); err != nil {
            log.Fatal(err)
        }
    }
    ```

2. **不检查 `rows.Err()`**: 在迭代 `sql.Rows` 后，应该检查 `rows.Err()` 以捕获在迭代过程中可能发生的错误。

    ```go
    func badExample() {
        rows, err := db.QueryContext(ctx, "SELECT name FROM users")
        if err != nil {
            log.Fatal(err)
        }
        defer rows.Close()
        for rows.Next() {
            var name string
            if err := rows.Scan(&name); err != nil {
                log.Fatal(err)
            }
            fmt.Println(name)
        }
        // 忘记检查 rows.Err()
    }
    ```

3. **在事务中不处理错误或忘记回滚**: 如果在事务中的某个操作失败，应该进行回滚以保持数据一致性。

    ```go
    func badExample() {
        tx, err := db.BeginTx(ctx, nil)
        if err != nil {
            log.Fatal(err)
        }
        _, err = tx.ExecContext(ctx, "UPDATE accounts SET balance = balance - 100 WHERE id = 1")
        if err != nil {
            log.Println("扣款失败:", err)
            // 忘记回滚事务
            return
        }
        _, err = tx.ExecContext(ctx, "UPDATE accounts SET balance = balance + 100 WHERE id = 2")
        if err != nil {
            log.Println("加款失败:", err)
            // 忘记回滚事务
            return
        }
        if err := tx.Commit(); err != nil {
            log.Fatal(err)
        }
    }
    ```

4. **忘记关闭预编译语句 `sql.Stmt`**:  预编译语句会占用数据库服务器的资源，使用完毕后应该关闭。

    ```go
    func badExample() {
        stmt, err := db.PrepareContext(ctx, "SELECT username FROM users WHERE id = ?")
        if err != nil {
            log.Fatal(err)
        }
        // 忘记 defer stmt.Close()
        var username string
        err = stmt.QueryRowContext(ctx, 1).Scan(&username)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println(username)
    }
    ```

这些例子展示了 `go/src/database/sql/example_test.go` 文件中代码的功能，以及在使用 `database/sql` 包时需要注意的关键点。

### 提示词
```
这是路径为go/src/database/sql/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sql_test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

var (
	ctx context.Context
	db  *sql.DB
)

func ExampleDB_QueryContext() {
	age := 27
	rows, err := db.QueryContext(ctx, "SELECT name FROM users WHERE age=?", age)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	names := make([]string, 0)

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			// Check for a scan error.
			// Query rows will be closed with defer.
			log.Fatal(err)
		}
		names = append(names, name)
	}
	// If the database is being written to ensure to check for Close
	// errors that may be returned from the driver. The query may
	// encounter an auto-commit error and be forced to rollback changes.
	rerr := rows.Close()
	if rerr != nil {
		log.Fatal(rerr)
	}

	// Rows.Err will report the last error encountered by Rows.Scan.
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s are %d years old", strings.Join(names, ", "), age)
}

func ExampleDB_QueryRowContext() {
	id := 123
	var username string
	var created time.Time
	err := db.QueryRowContext(ctx, "SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("no user with id %d\n", id)
	case err != nil:
		log.Fatalf("query error: %v\n", err)
	default:
		log.Printf("username is %q, account created on %s\n", username, created)
	}
}

func ExampleDB_ExecContext() {
	id := 47
	result, err := db.ExecContext(ctx, "UPDATE balances SET balance = balance + 10 WHERE user_id = ?", id)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}
	if rows != 1 {
		log.Fatalf("expected to affect 1 row, affected %d", rows)
	}
}

func ExampleDB_Query_multipleResultSets() {
	age := 27
	q := `
create temp table uid (id bigint); -- Create temp table for queries.
insert into uid
select id from users where age < ?; -- Populate temp table.

-- First result set.
select
	users.id, name
from
	users
	join uid on users.id = uid.id
;

-- Second result set.
select 
	ur.user, ur.role
from
	user_roles as ur
	join uid on uid.id = ur.user
;
	`
	rows, err := db.Query(q, age)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id   int64
			name string
		)
		if err := rows.Scan(&id, &name); err != nil {
			log.Fatal(err)
		}
		log.Printf("id %d name is %s\n", id, name)
	}
	if !rows.NextResultSet() {
		log.Fatalf("expected more result sets: %v", rows.Err())
	}
	var roleMap = map[int64]string{
		1: "user",
		2: "admin",
		3: "gopher",
	}
	for rows.Next() {
		var (
			id   int64
			role int64
		)
		if err := rows.Scan(&id, &role); err != nil {
			log.Fatal(err)
		}
		log.Printf("id %d has role %s\n", id, roleMap[role])
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}

func ExampleDB_PingContext() {
	// Ping and PingContext may be used to determine if communication with
	// the database server is still possible.
	//
	// When used in a command line application Ping may be used to establish
	// that further queries are possible; that the provided DSN is valid.
	//
	// When used in long running service Ping may be part of the health
	// checking system.

	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	status := "up"
	if err := db.PingContext(ctx); err != nil {
		status = "down"
	}
	log.Println(status)
}

func ExampleDB_Prepare() {
	projects := []struct {
		mascot  string
		release int
	}{
		{"tux", 1991},
		{"duke", 1996},
		{"gopher", 2009},
		{"moby dock", 2013},
	}

	stmt, err := db.Prepare("INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if _, err := stmt.Exec(id+1, project.mascot, project.release, "open source"); err != nil {
			log.Fatal(err)
		}
	}
}

func ExampleTx_Prepare() {
	projects := []struct {
		mascot  string
		release int
	}{
		{"tux", 1991},
		{"duke", 1996},
		{"gopher", 2009},
		{"moby dock", 2013},
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback() // The rollback will be ignored if the tx has been committed later in the function.

	stmt, err := tx.Prepare("INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if _, err := stmt.Exec(id+1, project.mascot, project.release, "open source"); err != nil {
			log.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func ExampleDB_BeginTx() {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}
	id := 37
	_, execErr := tx.Exec(`UPDATE users SET status = ? WHERE id = ?`, "paid", id)
	if execErr != nil {
		_ = tx.Rollback()
		log.Fatal(execErr)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func ExampleConn_ExecContext() {
	// A *DB is a pool of connections. Call Conn to reserve a connection for
	// exclusive use.
	conn, err := db.Conn(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close() // Return the connection to the pool.
	id := 41
	result, err := conn.ExecContext(ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`, id)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}
	if rows != 1 {
		log.Fatalf("expected single row affected, got %d rows affected", rows)
	}
}

func ExampleTx_ExecContext() {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}
	id := 37
	_, execErr := tx.ExecContext(ctx, "UPDATE users SET status = ? WHERE id = ?", "paid", id)
	if execErr != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			log.Fatalf("update failed: %v, unable to rollback: %v\n", execErr, rollbackErr)
		}
		log.Fatalf("update failed: %v", execErr)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func ExampleTx_Rollback() {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}
	id := 53
	_, err = tx.ExecContext(ctx, "UPDATE drivers SET status = ? WHERE id = ?;", "assigned", id)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			log.Fatalf("update drivers: unable to rollback: %v", rollbackErr)
		}
		log.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, "UPDATE pickups SET driver_id = $1;", id)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			log.Fatalf("update failed: %v, unable to back: %v", err, rollbackErr)
		}
		log.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func ExampleStmt() {
	// In normal use, create one Stmt when your process starts.
	stmt, err := db.PrepareContext(ctx, "SELECT username FROM users WHERE id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	// Then reuse it each time you need to issue the query.
	id := 43
	var username string
	err = stmt.QueryRowContext(ctx, id).Scan(&username)
	switch {
	case err == sql.ErrNoRows:
		log.Fatalf("no user with id %d", id)
	case err != nil:
		log.Fatal(err)
	default:
		log.Printf("username is %s\n", username)
	}
}

func ExampleStmt_QueryRowContext() {
	// In normal use, create one Stmt when your process starts.
	stmt, err := db.PrepareContext(ctx, "SELECT username FROM users WHERE id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	// Then reuse it each time you need to issue the query.
	id := 43
	var username string
	err = stmt.QueryRowContext(ctx, id).Scan(&username)
	switch {
	case err == sql.ErrNoRows:
		log.Fatalf("no user with id %d", id)
	case err != nil:
		log.Fatal(err)
	default:
		log.Printf("username is %s\n", username)
	}
}

func ExampleRows() {
	age := 27
	rows, err := db.QueryContext(ctx, "SELECT name FROM users WHERE age=?", age)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Fatal(err)
		}
		names = append(names, name)
	}
	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	log.Printf("%s are %d years old", strings.Join(names, ", "), age)
}
```