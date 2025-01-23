Response:
Let's break down the thought process for analyzing the `convert.go` file.

1. **Understand the Context:** The file path `go/src/database/sql/convert.go` immediately tells us this is part of the standard Go library, specifically the `database/sql` package, and deals with data type conversion. The package comment `// Type conversions for Scan.` reinforces this.

2. **Initial Skim for Key Functions and Types:** Read through the code, paying attention to function names, type definitions, and prominent comments. This helps to get a high-level understanding of the file's purpose. We can identify functions like `convertAssign`, `convertAssignRows`, `driverArgsConnLocked`, and types like `ccChecker`.

3. **Analyze Function by Function:** Go through each function, understanding its inputs, outputs, and what it does.

    * **`describeNamedValue` and `validateNamedValueName`:** These seem related to handling named parameters in SQL queries. The naming convention is a clue.

    * **`ccChecker`:**  The comment clearly states it's about adapting `driver.ColumnConverter` to `driver.NamedValueChecker`. This hints at different ways drivers can handle argument conversion.

    * **`defaultCheckNamedValue`:** This appears to be a fallback mechanism using `driver.DefaultParameterConverter`.

    * **`driverArgsConnLocked`:** This function is crucial. The name suggests it's involved in preparing arguments for the driver. The comment about `Stmt.Exec` and `Stmt.Query` confirms this. The logic involving `NamedValueChecker` and `ColumnConverter` is important to understand.

    * **`convertAssign` and `convertAssignRows`:** The names and comments clearly indicate these functions handle converting database values to Go types during `Scan`. The extensive `switch` statements suggest handling of various common types. The mention of `linkname` and `ariga.io/entcache` is a noteworthy detail about external usage.

    * **Helper functions like `strconvErr`, `asString`, `asBytes`, `callValuerValue`:** These are smaller utility functions used within the main conversion logic. Understanding their purpose helps clarify the details of the conversions.

    * **`decimal`, `decimalDecompose`, `decimalCompose`:** The comments clearly mark this as an experimental interface for handling decimal types.

4. **Identify Core Functionality:** Based on the function analysis, we can group the functionalities:

    * **Parameter Conversion:**  Preparing arguments for SQL queries (`driverArgsConnLocked`, related checkers).
    * **Result Set Conversion (Scanning):** Converting database values to Go types (`convertAssign`, `convertAssignRows`).
    * **Helper Utilities:**  Supporting the core conversion logic.
    * **Experimental Decimal Handling:** A specific area for decimal data types.

5. **Infer Go Language Features:** Based on the code, identify the Go features being used:

    * **Interfaces:** `driver.Valuer`, `driver.NamedValueChecker`, `driver.ColumnConverter`, `Scanner`, `decimal`, `decimalDecompose`, `decimalCompose`. These are key to the flexibility of the `database/sql` package, allowing different drivers to implement specific behaviors.
    * **Reflection:** Used extensively in `convertAssignRows` for handling type conversions when direct type assertions aren't possible.
    * **Type Assertions:** Used frequently in `convertAssignRows` to handle common type conversions efficiently.
    * **Error Handling:** The consistent use of `error` return values.
    * **String Conversions:** The use of `strconv` package for converting between strings and numeric types.
    * **Slices and Byte Arrays:** Handling of `[]byte` for binary data.
    * **Time Handling:** Use of the `time` package for date and time values.
    * **`unsafe` (via `linkname`):**  Indicates some external packages are bypassing the intended public API.

6. **Construct Code Examples:**  For the core functionalities, create illustrative Go code examples.

    * **Parameter Conversion:** Show how named and positional arguments are handled, and how a driver might implement `NamedValueChecker` or `ColumnConverter`.
    * **Result Set Conversion:** Demonstrate scanning database values into different Go types (string, int, time, etc.). Include cases where conversion is straightforward and where reflection might be used.

7. **Consider Edge Cases and Potential Errors:** Think about situations where things might go wrong for users.

    * **Nil Pointers:**  The `errNilPtr` constant highlights this.
    * **Type Mismatches:** Trying to scan a string into an integer without proper conversion.
    * **Loss of Precision:** Converting a large integer to a smaller integer type.
    * **Incorrect `Scan` Destination:**  Passing a non-pointer to `Scan`.
    * **Null Values:** How null values from the database are handled.

8. **Address Specific Questions from the Prompt:**  Ensure all parts of the prompt are addressed: functionality, Go feature implementation with examples, code inference with assumptions, command-line argument handling (if applicable, which it isn't much in this file), and common mistakes.

9. **Review and Refine:**  Read through the generated explanation, ensuring clarity, accuracy, and completeness. Check for any inconsistencies or areas that need further explanation. For example, ensure the examples are clear and easy to understand.

This systematic approach allows for a comprehensive understanding of the code and a well-structured answer to the prompt. The key is to break down the problem into smaller, manageable parts and then synthesize the findings into a coherent explanation.
这段代码是 Go 语言标准库 `database/sql` 包中 `convert.go` 文件的一部分，主要负责 **数据库操作中的类型转换**。它处理了以下几个核心功能：

**1. 将 Go 语言的值转换为数据库驱动程序可以理解的值 (参数转换):**

   -  `driverArgsConnLocked` 函数负责将 `Stmt.Exec` 和 `Stmt.Query` 等方法接收的 Go 语言参数转换为 `driver.NamedValue` 类型，这是数据库驱动程序期望的参数格式。
   - 它会检查参数是否实现了 `driver.NamedValueChecker` 或 `driver.ColumnConverter` 接口，以便驱动程序可以自定义参数的验证和转换逻辑。
   - 如果驱动程序没有实现这些接口，则使用默认的转换器 `driver.DefaultParameterConverter`。
   - 它还处理了命名参数 (`NamedArg`) 的情况。

   **Go 代码示例 (参数转换):**

   ```go
   package main

   import (
       "database/sql"
       "fmt"
       _ "github.com/mattn/go-sqlite3" // 导入 SQLite 驱动
   )

   func main() {
       db, err := sql.Open("sqlite3", ":memory:")
       if err != nil {
           panic(err)
       }
       defer db.Close()

       _, err = db.Exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
       if err != nil {
           panic(err)
       }

       // 假设我们想插入一条记录，参数是 Go 语言的字符串
       name := "Alice"
       result, err := db.Exec("INSERT INTO users (name) VALUES (?)", name)
       if err != nil {
           panic(err)
       }

       rowsAffected, _ := result.RowsAffected()
       fmt.Println("Rows affected:", rowsAffected) // 输出: Rows affected: 1
   }
   ```

   **代码推理:**

   - **假设输入:**  `db.Exec` 函数接收一个 SQL 语句 `"INSERT INTO users (name) VALUES (?)"` 和一个 Go 字符串 `"Alice"`。
   - **`driverArgsConnLocked` 的作用:**  `convert.go` 中的 `driverArgsConnLocked` 函数会将 Go 字符串 `"Alice"` 转换为 `driver.NamedValue` 类型，以便 SQLite 驱动程序能够理解并安全地插入到数据库中。它会使用默认的转换器，因为通常 Go 的基本类型可以很好地映射到数据库类型。
   - **输出:**  `db.Exec` 执行成功，返回的 `result` 中 `RowsAffected()` 为 1。

**2. 将数据库驱动程序返回的值转换为 Go 语言的值 (结果扫描):**

   - `convertAssign` 和 `convertAssignRows` 函数负责将数据库驱动程序返回的值 (通常是 `driver.Value`) 转换为 Go 语言的类型，以便存储到 `Scan` 方法的目标变量中。
   - 它包含了大量的 `switch` 语句来处理各种常见的类型转换，例如将数据库中的字符串转换为 Go 的 `string` 或 `[]byte`，将时间类型转换为 `time.Time` 等。
   - 它还使用了反射来处理更复杂的类型转换，以及支持实现了 `Scanner` 接口的自定义类型。

   **Go 代码示例 (结果扫描):**

   ```go
   package main

   import (
       "database/sql"
       "fmt"
       _ "github.com/mattn/go-sqlite3"
       "time"
   )

   func main() {
       db, err := sql.Open("sqlite3", ":memory:")
       if err != nil {
           panic(err)
       }
       defer db.Close()

       _, err = db.Exec("CREATE TABLE data (value TEXT, ts DATETIME)")
       if err != nil {
           panic(err)
       }

       _, err = db.Exec("INSERT INTO data (value, ts) VALUES (?, ?)", "example", "2023-10-27 10:00:00")
       if err != nil {
           panic(err)
       }

       var value string
       var ts time.Time
       err = db.QueryRow("SELECT value, ts FROM data").Scan(&value, &ts)
       if err != nil {
           panic(err)
       }

       fmt.Println("Value:", value) // 输出: Value: example
       fmt.Println("Timestamp:", ts) // 输出: Timestamp: 2023-10-27 10:00:00 +0000 UTC
   }
   ```

   **代码推理:**

   - **假设输入:** `db.QueryRow` 执行后，数据库返回一行数据，其中 `value` 列是字符串 `"example"`，`ts` 列是日期时间值 `"2023-10-27 10:00:00"`。
   - **`convertAssignRows` 的作用:** 当调用 `Scan(&value, &ts)` 时，`convert.go` 中的 `convertAssignRows` 函数会：
     - 将数据库返回的 `"example"` 字符串转换为 Go 的 `string` 类型，并赋值给 `value` 变量。
     - 将数据库返回的 `"2023-10-27 10:00:00"` 字符串转换为 Go 的 `time.Time` 类型，并赋值给 `ts` 变量。这里会涉及到字符串到 `time.Time` 的解析。
   - **输出:**  `Scan` 方法执行成功，`value` 变量的值为 `"example"`，`ts` 变量的值为 `2023-10-27 10:00:00 +0000 UTC`。

**3. 处理命名参数:**

   - `describeNamedValue` 函数用于生成命名参数的描述信息，用于错误消息中。
   - `validateNamedValueName` 函数用于验证命名参数的名称是否合法（必须以字母开头）。

**4. `ccChecker` 结构体:**

   -  这是一个适配器，允许将实现了 `driver.ColumnConverter` 接口的驱动程序，像实现了 `driver.NamedValueChecker` 接口一样使用。这提供了一种灵活的方式来让驱动程序控制参数的转换和验证。

**涉及的 Go 语言功能实现:**

- **接口 (Interfaces):**  `driver.Valuer`, `driver.NamedValueChecker`, `driver.ColumnConverter`, `Scanner`, `decimal`, `decimalDecompose`, `decimalCompose` 等接口是 `database/sql` 包实现数据库抽象的关键，允许不同的数据库驱动程序提供自己的实现。
- **反射 (Reflection):**  `convertAssignRows` 大量使用了 `reflect` 包，用于在运行时检查和操作变量的类型，从而实现通用的类型转换。
- **类型断言 (Type Assertion):**  在 `convertAssignRows` 中使用了类型断言来快速处理常见的类型转换。
- **错误处理 (Error Handling):** 代码中大量使用了 `error` 类型来处理转换过程中可能出现的错误。
- **字符串转换 (String Conversion):** 使用 `strconv` 包进行字符串和数值类型之间的转换。
- **切片和字节数组 (Slices and Byte Arrays):** 处理字符串和二进制数据时使用了切片和字节数组。
- **时间处理 (Time Handling):** 使用 `time` 包处理日期和时间类型。
- **`unsafe` 包 (通过 `linkname`):**  `//go:linkname convertAssign` 注释表明一些外部包 (如 `ariga.io/entcache`) 使用了 `unsafe` 包的特性，直接链接到 `convertAssign` 函数，这是一种绕过 Go 语言常规访问控制的方式。

**命令行参数的具体处理:**

这段代码本身 **不涉及** 命令行参数的具体处理。命令行参数的处理通常发生在应用程序的 `main` 函数中，使用 `os.Args` 或 `flag` 包来解析。 `convert.go` 主要关注数据库操作过程中的数据类型转换。

**使用者易犯错的点 (针对 `convertAssign` 和 `Scan` 方法):**

1. **目标变量不是指针:**  `Scan` 方法需要将数据库返回的值赋值给目标变量，因此目标变量必须是指针。如果传递的是非指针类型，会导致运行时错误。

   ```go
   var value string
   err := db.QueryRow("SELECT value FROM data").Scan(value) // 错误：Scan 的参数必须是指针
   ```

2. **类型不匹配:**  尝试将数据库返回的值扫描到不兼容的 Go 类型中。例如，将一个字符串类型的列扫描到 `int` 类型的变量中，可能会导致转换错误。

   ```go
   var count int
   err := db.QueryRow("SELECT value FROM data").Scan(&count) // 错误：如果 value 列是字符串，则无法转换为 int
   ```

3. **扫描 `NULL` 值到非指针类型的基本类型:**  如果数据库返回的列值为 `NULL`，并且 `Scan` 的目标变量是非指针的基本类型 (如 `int`, `string`, `bool`)，则会发生错误，因为 `NULL` 无法直接赋值给这些类型。应该使用指针类型，例如 `*int`, `*string`, `*bool`，或者使用可以表示 `NULL` 的类型，如 `sql.NullString`, `sql.NullInt64` 等。

   ```go
   var value string
   err := db.QueryRow("SELECT value FROM data WHERE id = 999").Scan(&value) // 如果查询结果为空，value 将保持其初始值，但不会报错

   var nullableValue sql.NullString
   err := db.QueryRow("SELECT value FROM data WHERE id = 999").Scan(&nullableValue)
   if nullableValue.Valid {
       fmt.Println("Value:", nullableValue.String)
   } else {
       fmt.Println("Value is NULL")
   }
   ```

4. **忽略 `Scan` 返回的错误:**  `Scan` 方法可能会返回错误，例如类型转换失败或列数不匹配。忽略这些错误可能会导致程序出现未预期的行为。

   ```go
   var value string
   var ts time.Time
   db.QueryRow("SELECT value, ts FROM data").Scan(&value, &ts) // 应该检查 Scan 的返回值 err
   fmt.Println(value, ts) // 如果 Scan 出错，value 和 ts 的值可能是不正确的
   ```

总而言之，`go/src/database/sql/convert.go` 是 `database/sql` 包中至关重要的组成部分，它负责在 Go 语言和数据库驱动程序之间进行数据类型的桥接，确保数据的正确传输和解析。理解其功能有助于更好地使用 Go 语言进行数据库编程。

### 提示词
```
这是路径为go/src/database/sql/convert.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Type conversions for Scan.

package sql

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
	_ "unsafe" // for linkname
)

var errNilPtr = errors.New("destination pointer is nil") // embedded in descriptive error

func describeNamedValue(nv *driver.NamedValue) string {
	if len(nv.Name) == 0 {
		return fmt.Sprintf("$%d", nv.Ordinal)
	}
	return fmt.Sprintf("with name %q", nv.Name)
}

func validateNamedValueName(name string) error {
	if len(name) == 0 {
		return nil
	}
	r, _ := utf8.DecodeRuneInString(name)
	if unicode.IsLetter(r) {
		return nil
	}
	return fmt.Errorf("name %q does not begin with a letter", name)
}

// ccChecker wraps the driver.ColumnConverter and allows it to be used
// as if it were a NamedValueChecker. If the driver ColumnConverter
// is not present then the NamedValueChecker will return driver.ErrSkip.
type ccChecker struct {
	cci  driver.ColumnConverter
	want int
}

func (c ccChecker) CheckNamedValue(nv *driver.NamedValue) error {
	if c.cci == nil {
		return driver.ErrSkip
	}
	// The column converter shouldn't be called on any index
	// it isn't expecting. The final error will be thrown
	// in the argument converter loop.
	index := nv.Ordinal - 1
	if c.want <= index {
		return nil
	}

	// First, see if the value itself knows how to convert
	// itself to a driver type. For example, a NullString
	// struct changing into a string or nil.
	if vr, ok := nv.Value.(driver.Valuer); ok {
		sv, err := callValuerValue(vr)
		if err != nil {
			return err
		}
		if !driver.IsValue(sv) {
			return fmt.Errorf("non-subset type %T returned from Value", sv)
		}
		nv.Value = sv
	}

	// Second, ask the column to sanity check itself. For
	// example, drivers might use this to make sure that
	// an int64 values being inserted into a 16-bit
	// integer field is in range (before getting
	// truncated), or that a nil can't go into a NOT NULL
	// column before going across the network to get the
	// same error.
	var err error
	arg := nv.Value
	nv.Value, err = c.cci.ColumnConverter(index).ConvertValue(arg)
	if err != nil {
		return err
	}
	if !driver.IsValue(nv.Value) {
		return fmt.Errorf("driver ColumnConverter error converted %T to unsupported type %T", arg, nv.Value)
	}
	return nil
}

// defaultCheckNamedValue wraps the default ColumnConverter to have the same
// function signature as the CheckNamedValue in the driver.NamedValueChecker
// interface.
func defaultCheckNamedValue(nv *driver.NamedValue) (err error) {
	nv.Value, err = driver.DefaultParameterConverter.ConvertValue(nv.Value)
	return err
}

// driverArgsConnLocked converts arguments from callers of Stmt.Exec and
// Stmt.Query into driver Values.
//
// The statement ds may be nil, if no statement is available.
//
// ci must be locked.
func driverArgsConnLocked(ci driver.Conn, ds *driverStmt, args []any) ([]driver.NamedValue, error) {
	nvargs := make([]driver.NamedValue, len(args))

	// -1 means the driver doesn't know how to count the number of
	// placeholders, so we won't sanity check input here and instead let the
	// driver deal with errors.
	want := -1

	var si driver.Stmt
	var cc ccChecker
	if ds != nil {
		si = ds.si
		want = ds.si.NumInput()
		cc.want = want
	}

	// Check all types of interfaces from the start.
	// Drivers may opt to use the NamedValueChecker for special
	// argument types, then return driver.ErrSkip to pass it along
	// to the column converter.
	nvc, ok := si.(driver.NamedValueChecker)
	if !ok {
		nvc, _ = ci.(driver.NamedValueChecker)
	}
	cci, ok := si.(driver.ColumnConverter)
	if ok {
		cc.cci = cci
	}

	// Loop through all the arguments, checking each one.
	// If no error is returned simply increment the index
	// and continue. However, if driver.ErrRemoveArgument
	// is returned the argument is not included in the query
	// argument list.
	var err error
	var n int
	for _, arg := range args {
		nv := &nvargs[n]
		if np, ok := arg.(NamedArg); ok {
			if err = validateNamedValueName(np.Name); err != nil {
				return nil, err
			}
			arg = np.Value
			nv.Name = np.Name
		}
		nv.Ordinal = n + 1
		nv.Value = arg

		// Checking sequence has four routes:
		// A: 1. Default
		// B: 1. NamedValueChecker 2. Column Converter 3. Default
		// C: 1. NamedValueChecker 3. Default
		// D: 1. Column Converter 2. Default
		//
		// The only time a Column Converter is called is first
		// or after NamedValueConverter. If first it is handled before
		// the nextCheck label. Thus for repeats tries only when the
		// NamedValueConverter is selected should the Column Converter
		// be used in the retry.
		checker := defaultCheckNamedValue
		nextCC := false
		switch {
		case nvc != nil:
			nextCC = cci != nil
			checker = nvc.CheckNamedValue
		case cci != nil:
			checker = cc.CheckNamedValue
		}

	nextCheck:
		err = checker(nv)
		switch err {
		case nil:
			n++
			continue
		case driver.ErrRemoveArgument:
			nvargs = nvargs[:len(nvargs)-1]
			continue
		case driver.ErrSkip:
			if nextCC {
				nextCC = false
				checker = cc.CheckNamedValue
			} else {
				checker = defaultCheckNamedValue
			}
			goto nextCheck
		default:
			return nil, fmt.Errorf("sql: converting argument %s type: %w", describeNamedValue(nv), err)
		}
	}

	// Check the length of arguments after conversion to allow for omitted
	// arguments.
	if want != -1 && len(nvargs) != want {
		return nil, fmt.Errorf("sql: expected %d arguments, got %d", want, len(nvargs))
	}

	return nvargs, nil
}

// convertAssign is the same as convertAssignRows, but without the optional
// rows argument.
//
// convertAssign should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - ariga.io/entcache
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname convertAssign
func convertAssign(dest, src any) error {
	return convertAssignRows(dest, src, nil)
}

// convertAssignRows copies to dest the value in src, converting it if possible.
// An error is returned if the copy would result in loss of information.
// dest should be a pointer type. If rows is passed in, the rows will
// be used as the parent for any cursor values converted from a
// driver.Rows to a *Rows.
func convertAssignRows(dest, src any, rows *Rows) error {
	// Common cases, without reflect.
	switch s := src.(type) {
	case string:
		switch d := dest.(type) {
		case *string:
			if d == nil {
				return errNilPtr
			}
			*d = s
			return nil
		case *[]byte:
			if d == nil {
				return errNilPtr
			}
			*d = []byte(s)
			return nil
		case *RawBytes:
			if d == nil {
				return errNilPtr
			}
			*d = rows.setrawbuf(append(rows.rawbuf(), s...))
			return nil
		}
	case []byte:
		switch d := dest.(type) {
		case *string:
			if d == nil {
				return errNilPtr
			}
			*d = string(s)
			return nil
		case *any:
			if d == nil {
				return errNilPtr
			}
			*d = bytes.Clone(s)
			return nil
		case *[]byte:
			if d == nil {
				return errNilPtr
			}
			*d = bytes.Clone(s)
			return nil
		case *RawBytes:
			if d == nil {
				return errNilPtr
			}
			*d = s
			return nil
		}
	case time.Time:
		switch d := dest.(type) {
		case *time.Time:
			*d = s
			return nil
		case *string:
			*d = s.Format(time.RFC3339Nano)
			return nil
		case *[]byte:
			if d == nil {
				return errNilPtr
			}
			*d = s.AppendFormat(make([]byte, 0, len(time.RFC3339Nano)), time.RFC3339Nano)
			return nil
		case *RawBytes:
			if d == nil {
				return errNilPtr
			}
			*d = rows.setrawbuf(s.AppendFormat(rows.rawbuf(), time.RFC3339Nano))
			return nil
		}
	case decimalDecompose:
		switch d := dest.(type) {
		case decimalCompose:
			return d.Compose(s.Decompose(nil))
		}
	case nil:
		switch d := dest.(type) {
		case *any:
			if d == nil {
				return errNilPtr
			}
			*d = nil
			return nil
		case *[]byte:
			if d == nil {
				return errNilPtr
			}
			*d = nil
			return nil
		case *RawBytes:
			if d == nil {
				return errNilPtr
			}
			*d = nil
			return nil
		}
	// The driver is returning a cursor the client may iterate over.
	case driver.Rows:
		switch d := dest.(type) {
		case *Rows:
			if d == nil {
				return errNilPtr
			}
			if rows == nil {
				return errors.New("invalid context to convert cursor rows, missing parent *Rows")
			}
			rows.closemu.Lock()
			*d = Rows{
				dc:          rows.dc,
				releaseConn: func(error) {},
				rowsi:       s,
			}
			// Chain the cancel function.
			parentCancel := rows.cancel
			rows.cancel = func() {
				// When Rows.cancel is called, the closemu will be locked as well.
				// So we can access rs.lasterr.
				d.close(rows.lasterr)
				if parentCancel != nil {
					parentCancel()
				}
			}
			rows.closemu.Unlock()
			return nil
		}
	}

	var sv reflect.Value

	switch d := dest.(type) {
	case *string:
		sv = reflect.ValueOf(src)
		switch sv.Kind() {
		case reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			*d = asString(src)
			return nil
		}
	case *[]byte:
		sv = reflect.ValueOf(src)
		if b, ok := asBytes(nil, sv); ok {
			*d = b
			return nil
		}
	case *RawBytes:
		sv = reflect.ValueOf(src)
		if b, ok := asBytes(rows.rawbuf(), sv); ok {
			*d = rows.setrawbuf(b)
			return nil
		}
	case *bool:
		bv, err := driver.Bool.ConvertValue(src)
		if err == nil {
			*d = bv.(bool)
		}
		return err
	case *any:
		*d = src
		return nil
	}

	if scanner, ok := dest.(Scanner); ok {
		return scanner.Scan(src)
	}

	dpv := reflect.ValueOf(dest)
	if dpv.Kind() != reflect.Pointer {
		return errors.New("destination not a pointer")
	}
	if dpv.IsNil() {
		return errNilPtr
	}

	if !sv.IsValid() {
		sv = reflect.ValueOf(src)
	}

	dv := reflect.Indirect(dpv)
	if sv.IsValid() && sv.Type().AssignableTo(dv.Type()) {
		switch b := src.(type) {
		case []byte:
			dv.Set(reflect.ValueOf(bytes.Clone(b)))
		default:
			dv.Set(sv)
		}
		return nil
	}

	if dv.Kind() == sv.Kind() && sv.Type().ConvertibleTo(dv.Type()) {
		dv.Set(sv.Convert(dv.Type()))
		return nil
	}

	// The following conversions use a string value as an intermediate representation
	// to convert between various numeric types.
	//
	// This also allows scanning into user defined types such as "type Int int64".
	// For symmetry, also check for string destination types.
	switch dv.Kind() {
	case reflect.Pointer:
		if src == nil {
			dv.SetZero()
			return nil
		}
		dv.Set(reflect.New(dv.Type().Elem()))
		return convertAssignRows(dv.Interface(), src, rows)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if src == nil {
			return fmt.Errorf("converting NULL to %s is unsupported", dv.Kind())
		}
		s := asString(src)
		i64, err := strconv.ParseInt(s, 10, dv.Type().Bits())
		if err != nil {
			err = strconvErr(err)
			return fmt.Errorf("converting driver.Value type %T (%q) to a %s: %v", src, s, dv.Kind(), err)
		}
		dv.SetInt(i64)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if src == nil {
			return fmt.Errorf("converting NULL to %s is unsupported", dv.Kind())
		}
		s := asString(src)
		u64, err := strconv.ParseUint(s, 10, dv.Type().Bits())
		if err != nil {
			err = strconvErr(err)
			return fmt.Errorf("converting driver.Value type %T (%q) to a %s: %v", src, s, dv.Kind(), err)
		}
		dv.SetUint(u64)
		return nil
	case reflect.Float32, reflect.Float64:
		if src == nil {
			return fmt.Errorf("converting NULL to %s is unsupported", dv.Kind())
		}
		s := asString(src)
		f64, err := strconv.ParseFloat(s, dv.Type().Bits())
		if err != nil {
			err = strconvErr(err)
			return fmt.Errorf("converting driver.Value type %T (%q) to a %s: %v", src, s, dv.Kind(), err)
		}
		dv.SetFloat(f64)
		return nil
	case reflect.String:
		if src == nil {
			return fmt.Errorf("converting NULL to %s is unsupported", dv.Kind())
		}
		switch v := src.(type) {
		case string:
			dv.SetString(v)
			return nil
		case []byte:
			dv.SetString(string(v))
			return nil
		}
	}

	return fmt.Errorf("unsupported Scan, storing driver.Value type %T into type %T", src, dest)
}

func strconvErr(err error) error {
	if ne, ok := err.(*strconv.NumError); ok {
		return ne.Err
	}
	return err
}

func asString(src any) string {
	switch v := src.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	}
	rv := reflect.ValueOf(src)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10)
	case reflect.Float64:
		return strconv.FormatFloat(rv.Float(), 'g', -1, 64)
	case reflect.Float32:
		return strconv.FormatFloat(rv.Float(), 'g', -1, 32)
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool())
	}
	return fmt.Sprintf("%v", src)
}

func asBytes(buf []byte, rv reflect.Value) (b []byte, ok bool) {
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.AppendInt(buf, rv.Int(), 10), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.AppendUint(buf, rv.Uint(), 10), true
	case reflect.Float32:
		return strconv.AppendFloat(buf, rv.Float(), 'g', -1, 32), true
	case reflect.Float64:
		return strconv.AppendFloat(buf, rv.Float(), 'g', -1, 64), true
	case reflect.Bool:
		return strconv.AppendBool(buf, rv.Bool()), true
	case reflect.String:
		s := rv.String()
		return append(buf, s...), true
	}
	return
}

var valuerReflectType = reflect.TypeFor[driver.Valuer]()

// callValuerValue returns vr.Value(), with one exception:
// If vr.Value is an auto-generated method on a pointer type and the
// pointer is nil, it would panic at runtime in the panicwrap
// method. Treat it like nil instead.
// Issue 8415.
//
// This is so people can implement driver.Value on value types and
// still use nil pointers to those types to mean nil/NULL, just like
// string/*string.
//
// This function is mirrored in the database/sql/driver package.
func callValuerValue(vr driver.Valuer) (v driver.Value, err error) {
	if rv := reflect.ValueOf(vr); rv.Kind() == reflect.Pointer &&
		rv.IsNil() &&
		rv.Type().Elem().Implements(valuerReflectType) {
		return nil, nil
	}
	return vr.Value()
}

// decimal composes or decomposes a decimal value to and from individual parts.
// There are four parts: a boolean negative flag, a form byte with three possible states
// (finite=0, infinite=1, NaN=2), a base-2 big-endian integer
// coefficient (also known as a significand) as a []byte, and an int32 exponent.
// These are composed into a final value as "decimal = (neg) (form=finite) coefficient * 10 ^ exponent".
// A zero length coefficient is a zero value.
// The big-endian integer coefficient stores the most significant byte first (at coefficient[0]).
// If the form is not finite the coefficient and exponent should be ignored.
// The negative parameter may be set to true for any form, although implementations are not required
// to respect the negative parameter in the non-finite form.
//
// Implementations may choose to set the negative parameter to true on a zero or NaN value,
// but implementations that do not differentiate between negative and positive
// zero or NaN values should ignore the negative parameter without error.
// If an implementation does not support Infinity it may be converted into a NaN without error.
// If a value is set that is larger than what is supported by an implementation,
// an error must be returned.
// Implementations must return an error if a NaN or Infinity is attempted to be set while neither
// are supported.
//
// NOTE(kardianos): This is an experimental interface. See https://golang.org/issue/30870
type decimal interface {
	decimalDecompose
	decimalCompose
}

type decimalDecompose interface {
	// Decompose returns the internal decimal state in parts.
	// If the provided buf has sufficient capacity, buf may be returned as the coefficient with
	// the value set and length set as appropriate.
	Decompose(buf []byte) (form byte, negative bool, coefficient []byte, exponent int32)
}

type decimalCompose interface {
	// Compose sets the internal decimal value from parts. If the value cannot be
	// represented then an error should be returned.
	Compose(form byte, negative bool, coefficient []byte, exponent int32) error
}
```