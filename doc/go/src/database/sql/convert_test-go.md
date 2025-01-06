Response:
Let's break down the thought process for analyzing the given Go code snippet.

1. **Understanding the Goal:** The first step is to grasp the overall purpose of the code. The file name `convert_test.go` and the package `sql` strongly suggest this code is for testing data type conversion within the `database/sql` package in Go. Specifically, it's likely testing how values retrieved from a database (which have a `driver.Value` type) are converted to Go types.

2. **Identifying Key Structures:** Look for the main data structures and types defined in the code. The `conversionTest` struct stands out immediately. Its fields (`s`, `d`, `want...`) clearly indicate a structure for defining test cases. `s` seems to be the source value, `d` the destination (a pointer to a variable), and the `want` fields represent the expected outcome after the conversion. The various `scan...` variables are also important; they serve as the target variables for the conversions.

3. **Analyzing the Test Cases (`conversionTests` function):**  This function is crucial. It provides concrete examples of the conversions being tested. Go through the test cases and categorize them:
    * **Exact Conversions:**  Where the source and destination types match.
    * **Conversions to String:**  Testing how different types are converted to strings. Notice the handling of `time.Time`.
    * **Conversions to `[]byte`:** Similar to string conversions.
    * **Conversions to `RawBytes`:**  A specific type within `database/sql` for holding raw bytes.
    * **String to Integer Conversions:** Testing parsing strings into integer types and handling errors.
    * **Integer to Smaller Integer Conversions:** Testing range limitations.
    * **Boolean Conversions:**  Testing various representations of true and false.
    * **Float Conversions:**  Testing conversions to `float32` and `float64`.
    * **Pointer Conversions:** Testing handling of `nil` and non-`nil` pointers.
    * **Conversions to `interface{}`:**  Testing storing values in empty interfaces.
    * **Conversions to User-Defined Types:**  Testing if conversion works for custom types.
    * **Error Cases:**  Explicitly testing scenarios that should result in errors.

4. **Identifying the Core Conversion Function (`convertAssign`):** The `TestConversions` function iterates through the `conversionTests` and calls `convertAssign(ct.d, ct.s)`. This is the function under test. Its purpose is to take a source value (`ct.s`) and assign it to the destination variable pointed to by `ct.d`.

5. **Understanding the Testing Logic (`TestConversions` function):** The test function iterates through the test cases, performs the conversion, checks for expected errors, and then compares the actual value in the destination variable with the expected value (using the `want...` fields). The `errf` helper function is used for consistent error reporting. Pay attention to how different `want...` fields are checked based on the destination type.

6. **Looking for Specific Features (`NullString`, `ValueConverter`, `RawBytes` Allocations, `DriverArgs`, `Decimal`):**  The code includes separate test functions for `NullString`, value converters, `RawBytes` allocations, driver arguments, and decimal types. Analyze each of these sections individually to understand their purpose:
    * **`NullString`:** Represents a string that can be `NULL` in the database.
    * **Value Converters:**  Functions responsible for converting Go types to `driver.Value` (used when passing parameters to SQL queries).
    * **`RawBytes` Allocations:**  Testing for memory efficiency when assigning to `RawBytes`.
    * **`DriverArgs`:**  Testing how Go values are converted to `driver.NamedValue` for passing to database drivers. This involves the `driver.Valuer` interface.
    * **`Decimal`:** Testing custom types that implement `driver.DecimalComposer` and `driver.DecimalDecomposer` for handling decimal values.

7. **Inferring Go Language Features:** Based on the code, identify the Go language features being demonstrated:
    * **Pointers:**  Used extensively for modifying values in place during conversion.
    * **Reflection:**  While not explicitly used in the `convertAssign` function *in this snippet*, the structure of the tests and the need to handle various types suggest that `convertAssign` internally likely uses reflection (`reflect` package) to inspect types and perform conversions.
    * **Interfaces:**  The use of `driver.Value`, `driver.ValueConverter`, `driver.Valuer`, `driver.DecimalComposer`, and `driver.DecimalDecomposer` demonstrates interface usage for defining contracts.
    * **Type Assertions and Type Switches:**  Likely used within `convertAssign` to handle different source and destination types.
    * **Error Handling:** The `error` type and checking for `wanterr` in tests.
    * **Structs:**  `conversionTest`, `NullString`, etc.
    * **Slices and Byte Arrays:**  Handling of `[]byte` and `RawBytes`.
    * **Time Package:**  Working with `time.Time`.

8. **Considering Potential Mistakes:**  Think about common errors developers might make when working with database conversions based on the patterns observed in the tests:
    * **Incorrect Type Assumptions:** Assuming a database value will always map directly to a specific Go type without checking.
    * **Ignoring Potential `NULL` Values:**  Not using types like `NullString` when dealing with nullable database columns.
    * **Forgetting to Implement `driver.Valuer`:** When using custom types as query parameters.
    * **Range Errors:**  Trying to convert a database value to a Go integer type that's too small.
    * **Incorrect Boolean Representations:**  Assuming only `true`/`false` are possible boolean values.

9. **Structuring the Answer:** Organize the findings into a clear and structured answer, covering the requested points: functionality, implemented Go features, code examples, assumptions, command-line arguments (if applicable, though not in this snippet), and common mistakes. Use clear and concise language.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This is just about basic type conversions."  **Correction:**  Realized it goes deeper, covering `NULL` values, custom types, and the `driver` interface.
* **Focusing too much on individual test cases:** **Correction:** Stepped back to understand the overall structure and the role of `convertAssign`.
* **Not explicitly stating the likely use of reflection:** **Correction:** Added this as a likely internal implementation detail of `convertAssign`.
* **Missing the connection between `driver.Valuer` and query parameters:** **Correction:** Recognized this when analyzing the `TestDriverArgs` function.

By following these steps, the detailed and comprehensive answer provided earlier can be constructed. The key is to systematically analyze the code, identify its core components, and relate them to the broader context of database interaction in Go.
这段Go语言代码是 `database/sql` 包中 `convert_test.go` 文件的一部分，它的主要功能是**测试数据库查询结果到Go语言类型的转换（也称为扫描，Scan）以及Go语言类型到数据库驱动程序可以理解的参数类型的转换（也称为赋值，Assign）。**

具体来说，它测试了 `database/sql` 包中的 `convertAssign` 函数，该函数负责将从数据库驱动返回的 `driver.Value` 类型的值转换为Go语言的各种数据类型。

以下是更详细的功能点：

1. **测试各种数据类型的转换:** 代码中定义了一个 `conversionTest` 结构体，它包含了源数据 (`s`)，目标变量的指针 (`d`) 以及期望的转换结果 (`want...` 系列字段)。`conversionTests` 函数返回一个包含多个 `conversionTest` 实例的切片，每个实例代表一个具体的转换测试用例。这些测试用例涵盖了字符串、整数、浮点数、布尔值、时间、字节切片、`RawBytes` 以及 `interface{}` 等多种数据类型之间的转换。

2. **测试正确的转换结果:** 每个 `conversionTest` 实例都定义了期望的转换结果。`TestConversions` 函数遍历这些测试用例，调用 `convertAssign` 函数进行转换，并将实际转换结果与期望结果进行比较，以验证转换是否正确。

3. **测试错误处理:** 部分 `conversionTest` 实例定义了 `wanterr` 字段，用于指定期望的错误信息。`TestConversions` 函数会检查 `convertAssign` 函数是否返回了预期的错误。

4. **测试 `NullString` 类型:** `TestNullString` 函数专门测试了 `NullString` 类型的转换。`NullString` 用于表示可能为 `NULL` 的字符串数据库字段。

5. **测试 `ValueConverter` 接口:** `TestValueConverters` 函数测试了实现了 `driver.ValueConverter` 接口的类型到 `driver.Value` 的转换。这涉及到将Go语言的值转换为数据库驱动可以理解的值，通常用于预处理查询参数。

6. **测试 `RawBytes` 的内存分配:** `TestRawBytesAllocs` 函数测试了将数据库值赋值给 `RawBytes` 类型时是否会产生不必要的内存分配。`RawBytes` 旨在提供一种零拷贝的方式来访问数据库返回的原始字节数据。

7. **测试用户自定义类型:** 代码中定义了 `userDefined`、`userDefinedSlice` 和 `userDefinedString` 等用户自定义类型，并测试了这些类型与数据库值之间的转换。

8. **测试 `driver.Valuer` 接口:** `TestDriverArgs` 函数测试了实现了 `driver.Valuer` 接口的类型作为 SQL 查询参数时的处理。实现了 `driver.Valuer` 接口的类型可以自定义如何将其值转换为 `driver.Value`。

9. **测试 `driver.DecimalComposer` 和 `driver.DecimalDecomposer` 接口:** `TestDecimal` 函数测试了实现了 `driver.DecimalComposer` 和 `driver.DecimalDecomposer` 接口的类型与数据库 decimal 类型之间的转换。

**它可以推理出这是 `database/sql` 包中用于测试数据类型转换功能的实现。**

**Go 代码举例说明：**

假设我们有一个数据库表 `users`，其中包含 `id` (INT) 和 `name` (VARCHAR) 两个字段。我们想要从数据库中查询一条记录，并将结果扫描到 Go 语言的变量中。

```go
package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3" // 导入 SQLite 驱动
	"log"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:") // 使用内存数据库进行演示
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec("CREATE TABLE users (id INTEGER, name TEXT)")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO users (id, name) VALUES (1, 'Alice')")
	if err != nil {
		log.Fatal(err)
	}

	var id int
	var name string

	row := db.QueryRow("SELECT id, name FROM users WHERE id = ?", 1)
	err = row.Scan(&id, &name) // 关键：将数据库结果扫描到 Go 变量
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ID: %d, Name: %s\n", id, name) // 输出: ID: 1, Name: Alice
}
```

在这个例子中，`row.Scan(&id, &name)` 就使用了 `database/sql` 包的扫描功能，将数据库查询结果的 `id` 列的值转换为 `int` 类型的 `id` 变量，将 `name` 列的值转换为 `string` 类型的 `name` 变量。  `convert_test.go` 中的测试用例正是为了验证 `Scan` 方法背后的转换逻辑 (`convertAssign` 函数) 的正确性。

**代码推理与假设的输入与输出：**

以下是一个基于 `convert_test.go` 中 `conversionTests` 函数的测试用例的推理：

**假设输入:**

*   源数据 (`ct.s`): 字符串 `"123"` (类型为 `string`)
*   目标变量 (`ct.d`): 指向 `int` 类型变量 `scanint` 的指针 (`&scanint`)

**预期输出 (基于 `wantint`):**

*   `scanint` 的值应为 `123` (类型为 `int`)
*   `convertAssign` 函数执行成功，不返回错误。

**相关 `conversionTest` 结构体实例：**

```go
{s: "123", d: &scanint, wantint: 123}
```

**`TestConversions` 函数会执行类似以下的操作：**

```go
err := convertAssign(&scanint, "123")
if err != nil {
    // 处理错误
}
if scanint != 123 {
    // 报告错误
}
```

**涉及命令行参数的具体处理：**

这段代码是测试代码，它本身不直接处理命令行参数。`go test` 命令会执行这些测试用例，可以通过 `go test` 的各种标志（例如 `-v` 显示详细输出，`-run` 指定运行的测试用例）来控制测试的执行。

**使用者易犯错的点：**

1. **类型不匹配:**  尝试将数据库的某种类型的值扫描到不兼容的 Go 语言类型中会导致错误。例如，尝试将一个包含非数字字符的字符串扫描到 `int` 类型的变量中。

    ```go
    var id int
    row := db.QueryRow("SELECT name FROM users WHERE id = ?", 1) // 注意这里查询的是 name
    err := row.Scan(&id) // 错误：尝试将字符串扫描到 int
    if err != nil {
        fmt.Println(err) // 输出类似：sql: Scan error on column index 0, name: converting driver.Value type string ("Alice") to a int: invalid syntax
    }
    ```

2. **忽略 `NULL` 值:**  如果数据库字段可能为 `NULL`，而你直接扫描到 Go 语言的基本类型（如 `int`，`string`），则可能会遇到错误。应该使用 `sql.NullString`、`sql.NullInt64` 等类型来处理可能为 `NULL` 的值。

    ```go
    // 假设 users 表有一个可选的 email 字段 (允许 NULL)
    var email string
    row := db.QueryRow("SELECT email FROM users WHERE id = ?", 1)
    err := row.Scan(&email)
    if err != nil {
        fmt.Println(err) // 如果 email 是 NULL，可能会报错
    }

    var nullEmail sql.NullString
    row = db.QueryRow("SELECT email FROM users WHERE id = ?", 1)
    err = row.Scan(&nullEmail)
    if err != nil {
        fmt.Println(err)
    }
    if nullEmail.Valid {
        fmt.Println("Email:", nullEmail.String)
    } else {
        fmt.Println("Email is NULL")
    }
    ```

3. **假设所有数据库驱动行为一致:**  不同的数据库驱动可能对某些数据类型的处理方式略有不同。虽然 `database/sql` 提供了统一的接口，但在某些边缘情况下，驱动程序的实现细节可能会影响转换结果。

总而言之，这段代码是 `database/sql` 包的核心测试部分，确保了 Go 语言与各种数据库之间的数据类型转换的正确性和健壮性。理解这段代码有助于我们更好地理解 `database/sql` 包的工作原理，并避免在使用数据库操作时常犯的错误。

Prompt: 
```
这是路径为go/src/database/sql/convert_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"database/sql/driver"
	"fmt"
	"internal/asan"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var someTime = time.Unix(123, 0)
var answer int64 = 42

type (
	userDefined       float64
	userDefinedSlice  []int
	userDefinedString string
)

type conversionTest struct {
	s, d any // source and destination

	// following are used if they're non-zero
	wantint    int64
	wantuint   uint64
	wantstr    string
	wantbytes  []byte
	wantraw    RawBytes
	wantf32    float32
	wantf64    float64
	wanttime   time.Time
	wantbool   bool // used if d is of type *bool
	wanterr    string
	wantiface  any
	wantptr    *int64 // if non-nil, *d's pointed value must be equal to *wantptr
	wantnil    bool   // if true, *d must be *int64(nil)
	wantusrdef userDefined
	wantusrstr userDefinedString
}

// Target variables for scanning into.
var (
	scanstr    string
	scanbytes  []byte
	scanraw    RawBytes
	scanint    int
	scanuint8  uint8
	scanuint16 uint16
	scanbool   bool
	scanf32    float32
	scanf64    float64
	scantime   time.Time
	scanptr    *int64
	scaniface  any
)

func conversionTests() []conversionTest {
	// Return a fresh instance to test so "go test -count 2" works correctly.
	return []conversionTest{
		// Exact conversions (destination pointer type matches source type)
		{s: "foo", d: &scanstr, wantstr: "foo"},
		{s: 123, d: &scanint, wantint: 123},
		{s: someTime, d: &scantime, wanttime: someTime},

		// To strings
		{s: "string", d: &scanstr, wantstr: "string"},
		{s: []byte("byteslice"), d: &scanstr, wantstr: "byteslice"},
		{s: 123, d: &scanstr, wantstr: "123"},
		{s: int8(123), d: &scanstr, wantstr: "123"},
		{s: int64(123), d: &scanstr, wantstr: "123"},
		{s: uint8(123), d: &scanstr, wantstr: "123"},
		{s: uint16(123), d: &scanstr, wantstr: "123"},
		{s: uint32(123), d: &scanstr, wantstr: "123"},
		{s: uint64(123), d: &scanstr, wantstr: "123"},
		{s: 1.5, d: &scanstr, wantstr: "1.5"},

		// From time.Time:
		{s: time.Unix(1, 0).UTC(), d: &scanstr, wantstr: "1970-01-01T00:00:01Z"},
		{s: time.Unix(1453874597, 0).In(time.FixedZone("here", -3600*8)), d: &scanstr, wantstr: "2016-01-26T22:03:17-08:00"},
		{s: time.Unix(1, 2).UTC(), d: &scanstr, wantstr: "1970-01-01T00:00:01.000000002Z"},
		{s: time.Time{}, d: &scanstr, wantstr: "0001-01-01T00:00:00Z"},
		{s: time.Unix(1, 2).UTC(), d: &scanbytes, wantbytes: []byte("1970-01-01T00:00:01.000000002Z")},
		{s: time.Unix(1, 2).UTC(), d: &scaniface, wantiface: time.Unix(1, 2).UTC()},

		// To []byte
		{s: nil, d: &scanbytes, wantbytes: nil},
		{s: "string", d: &scanbytes, wantbytes: []byte("string")},
		{s: []byte("byteslice"), d: &scanbytes, wantbytes: []byte("byteslice")},
		{s: 123, d: &scanbytes, wantbytes: []byte("123")},
		{s: int8(123), d: &scanbytes, wantbytes: []byte("123")},
		{s: int64(123), d: &scanbytes, wantbytes: []byte("123")},
		{s: uint8(123), d: &scanbytes, wantbytes: []byte("123")},
		{s: uint16(123), d: &scanbytes, wantbytes: []byte("123")},
		{s: uint32(123), d: &scanbytes, wantbytes: []byte("123")},
		{s: uint64(123), d: &scanbytes, wantbytes: []byte("123")},
		{s: 1.5, d: &scanbytes, wantbytes: []byte("1.5")},

		// To RawBytes
		{s: nil, d: &scanraw, wantraw: nil},
		{s: []byte("byteslice"), d: &scanraw, wantraw: RawBytes("byteslice")},
		{s: "string", d: &scanraw, wantraw: RawBytes("string")},
		{s: 123, d: &scanraw, wantraw: RawBytes("123")},
		{s: int8(123), d: &scanraw, wantraw: RawBytes("123")},
		{s: int64(123), d: &scanraw, wantraw: RawBytes("123")},
		{s: uint8(123), d: &scanraw, wantraw: RawBytes("123")},
		{s: uint16(123), d: &scanraw, wantraw: RawBytes("123")},
		{s: uint32(123), d: &scanraw, wantraw: RawBytes("123")},
		{s: uint64(123), d: &scanraw, wantraw: RawBytes("123")},
		{s: 1.5, d: &scanraw, wantraw: RawBytes("1.5")},
		// time.Time has been placed here to check that the RawBytes slice gets
		// correctly reset when calling time.Time.AppendFormat.
		{s: time.Unix(2, 5).UTC(), d: &scanraw, wantraw: RawBytes("1970-01-01T00:00:02.000000005Z")},

		// Strings to integers
		{s: "255", d: &scanuint8, wantuint: 255},
		{s: "256", d: &scanuint8, wanterr: "converting driver.Value type string (\"256\") to a uint8: value out of range"},
		{s: "256", d: &scanuint16, wantuint: 256},
		{s: "-1", d: &scanint, wantint: -1},
		{s: "foo", d: &scanint, wanterr: "converting driver.Value type string (\"foo\") to a int: invalid syntax"},

		// int64 to smaller integers
		{s: int64(5), d: &scanuint8, wantuint: 5},
		{s: int64(256), d: &scanuint8, wanterr: "converting driver.Value type int64 (\"256\") to a uint8: value out of range"},
		{s: int64(256), d: &scanuint16, wantuint: 256},
		{s: int64(65536), d: &scanuint16, wanterr: "converting driver.Value type int64 (\"65536\") to a uint16: value out of range"},

		// True bools
		{s: true, d: &scanbool, wantbool: true},
		{s: "True", d: &scanbool, wantbool: true},
		{s: "TRUE", d: &scanbool, wantbool: true},
		{s: "1", d: &scanbool, wantbool: true},
		{s: 1, d: &scanbool, wantbool: true},
		{s: int64(1), d: &scanbool, wantbool: true},
		{s: uint16(1), d: &scanbool, wantbool: true},

		// False bools
		{s: false, d: &scanbool, wantbool: false},
		{s: "false", d: &scanbool, wantbool: false},
		{s: "FALSE", d: &scanbool, wantbool: false},
		{s: "0", d: &scanbool, wantbool: false},
		{s: 0, d: &scanbool, wantbool: false},
		{s: int64(0), d: &scanbool, wantbool: false},
		{s: uint16(0), d: &scanbool, wantbool: false},

		// Not bools
		{s: "yup", d: &scanbool, wanterr: `sql/driver: couldn't convert "yup" into type bool`},
		{s: 2, d: &scanbool, wanterr: `sql/driver: couldn't convert 2 into type bool`},

		// Floats
		{s: float64(1.5), d: &scanf64, wantf64: float64(1.5)},
		{s: int64(1), d: &scanf64, wantf64: float64(1)},
		{s: float64(1.5), d: &scanf32, wantf32: float32(1.5)},
		{s: "1.5", d: &scanf32, wantf32: float32(1.5)},
		{s: "1.5", d: &scanf64, wantf64: float64(1.5)},

		// Pointers
		{s: any(nil), d: &scanptr, wantnil: true},
		{s: int64(42), d: &scanptr, wantptr: &answer},

		// To interface{}
		{s: float64(1.5), d: &scaniface, wantiface: float64(1.5)},
		{s: int64(1), d: &scaniface, wantiface: int64(1)},
		{s: "str", d: &scaniface, wantiface: "str"},
		{s: []byte("byteslice"), d: &scaniface, wantiface: []byte("byteslice")},
		{s: true, d: &scaniface, wantiface: true},
		{s: nil, d: &scaniface},
		{s: []byte(nil), d: &scaniface, wantiface: []byte(nil)},

		// To a user-defined type
		{s: 1.5, d: new(userDefined), wantusrdef: 1.5},
		{s: int64(123), d: new(userDefined), wantusrdef: 123},
		{s: "1.5", d: new(userDefined), wantusrdef: 1.5},
		{s: []byte{1, 2, 3}, d: new(userDefinedSlice), wanterr: `unsupported Scan, storing driver.Value type []uint8 into type *sql.userDefinedSlice`},
		{s: "str", d: new(userDefinedString), wantusrstr: "str"},

		// Other errors
		{s: complex(1, 2), d: &scanstr, wanterr: `unsupported Scan, storing driver.Value type complex128 into type *string`},
	}
}

func intPtrValue(intptr any) any {
	return reflect.Indirect(reflect.Indirect(reflect.ValueOf(intptr))).Int()
}

func intValue(intptr any) int64 {
	return reflect.Indirect(reflect.ValueOf(intptr)).Int()
}

func uintValue(intptr any) uint64 {
	return reflect.Indirect(reflect.ValueOf(intptr)).Uint()
}

func float64Value(ptr any) float64 {
	return *(ptr.(*float64))
}

func float32Value(ptr any) float32 {
	return *(ptr.(*float32))
}

func timeValue(ptr any) time.Time {
	return *(ptr.(*time.Time))
}

func TestConversions(t *testing.T) {
	for n, ct := range conversionTests() {
		err := convertAssign(ct.d, ct.s)
		errstr := ""
		if err != nil {
			errstr = err.Error()
		}
		errf := func(format string, args ...any) {
			base := fmt.Sprintf("convertAssign #%d: for %v (%T) -> %T, ", n, ct.s, ct.s, ct.d)
			t.Errorf(base+format, args...)
		}
		if errstr != ct.wanterr {
			errf("got error %q, want error %q", errstr, ct.wanterr)
		}
		if ct.wantstr != "" && ct.wantstr != scanstr {
			errf("want string %q, got %q", ct.wantstr, scanstr)
		}
		if ct.wantbytes != nil && string(ct.wantbytes) != string(scanbytes) {
			errf("want byte %q, got %q", ct.wantbytes, scanbytes)
		}
		if ct.wantraw != nil && string(ct.wantraw) != string(scanraw) {
			errf("want RawBytes %q, got %q", ct.wantraw, scanraw)
		}
		if ct.wantint != 0 && ct.wantint != intValue(ct.d) {
			errf("want int %d, got %d", ct.wantint, intValue(ct.d))
		}
		if ct.wantuint != 0 && ct.wantuint != uintValue(ct.d) {
			errf("want uint %d, got %d", ct.wantuint, uintValue(ct.d))
		}
		if ct.wantf32 != 0 && ct.wantf32 != float32Value(ct.d) {
			errf("want float32 %v, got %v", ct.wantf32, float32Value(ct.d))
		}
		if ct.wantf64 != 0 && ct.wantf64 != float64Value(ct.d) {
			errf("want float32 %v, got %v", ct.wantf64, float64Value(ct.d))
		}
		if bp, boolTest := ct.d.(*bool); boolTest && *bp != ct.wantbool && ct.wanterr == "" {
			errf("want bool %v, got %v", ct.wantbool, *bp)
		}
		if !ct.wanttime.IsZero() && !ct.wanttime.Equal(timeValue(ct.d)) {
			errf("want time %v, got %v", ct.wanttime, timeValue(ct.d))
		}
		if ct.wantnil && *ct.d.(**int64) != nil {
			errf("want nil, got %v", intPtrValue(ct.d))
		}
		if ct.wantptr != nil {
			if *ct.d.(**int64) == nil {
				errf("want pointer to %v, got nil", *ct.wantptr)
			} else if *ct.wantptr != intPtrValue(ct.d) {
				errf("want pointer to %v, got %v", *ct.wantptr, intPtrValue(ct.d))
			}
		}
		if ifptr, ok := ct.d.(*any); ok {
			if !reflect.DeepEqual(ct.wantiface, scaniface) {
				errf("want interface %#v, got %#v", ct.wantiface, scaniface)
				continue
			}
			if srcBytes, ok := ct.s.([]byte); ok {
				dstBytes := (*ifptr).([]byte)
				if len(srcBytes) > 0 && &dstBytes[0] == &srcBytes[0] {
					errf("copy into interface{} didn't copy []byte data")
				}
			}
		}
		if ct.wantusrdef != 0 && ct.wantusrdef != *ct.d.(*userDefined) {
			errf("want userDefined %f, got %f", ct.wantusrdef, *ct.d.(*userDefined))
		}
		if len(ct.wantusrstr) != 0 && ct.wantusrstr != *ct.d.(*userDefinedString) {
			errf("want userDefined %q, got %q", ct.wantusrstr, *ct.d.(*userDefinedString))
		}
	}
}

func TestNullString(t *testing.T) {
	var ns NullString
	convertAssign(&ns, []byte("foo"))
	if !ns.Valid {
		t.Errorf("expecting not null")
	}
	if ns.String != "foo" {
		t.Errorf("expecting foo; got %q", ns.String)
	}
	convertAssign(&ns, nil)
	if ns.Valid {
		t.Errorf("expecting null on nil")
	}
	if ns.String != "" {
		t.Errorf("expecting blank on nil; got %q", ns.String)
	}
}

type valueConverterTest struct {
	c       driver.ValueConverter
	in, out any
	err     string
}

var valueConverterTests = []valueConverterTest{
	{driver.DefaultParameterConverter, NullString{"hi", true}, "hi", ""},
	{driver.DefaultParameterConverter, NullString{"", false}, nil, ""},
}

func TestValueConverters(t *testing.T) {
	for i, tt := range valueConverterTests {
		out, err := tt.c.ConvertValue(tt.in)
		goterr := ""
		if err != nil {
			goterr = err.Error()
		}
		if goterr != tt.err {
			t.Errorf("test %d: %T(%T(%v)) error = %q; want error = %q",
				i, tt.c, tt.in, tt.in, goterr, tt.err)
		}
		if tt.err != "" {
			continue
		}
		if !reflect.DeepEqual(out, tt.out) {
			t.Errorf("test %d: %T(%T(%v)) = %v (%T); want %v (%T)",
				i, tt.c, tt.in, tt.in, out, out, tt.out, tt.out)
		}
	}
}

// Tests that assigning to RawBytes doesn't allocate (and also works).
func TestRawBytesAllocs(t *testing.T) {
	var tests = []struct {
		name string
		in   any
		want string
	}{
		{"uint64", uint64(12345678), "12345678"},
		{"uint32", uint32(1234), "1234"},
		{"uint16", uint16(12), "12"},
		{"uint8", uint8(1), "1"},
		{"uint", uint(123), "123"},
		{"int", int(123), "123"},
		{"int8", int8(1), "1"},
		{"int16", int16(12), "12"},
		{"int32", int32(1234), "1234"},
		{"int64", int64(12345678), "12345678"},
		{"float32", float32(1.5), "1.5"},
		{"float64", float64(64), "64"},
		{"bool", false, "false"},
		{"time", time.Unix(2, 5).UTC(), "1970-01-01T00:00:02.000000005Z"},
	}
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}

	var buf RawBytes
	rows := &Rows{}
	test := func(name string, in any, want string) {
		if err := convertAssignRows(&buf, in, rows); err != nil {
			t.Fatalf("%s: convertAssign = %v", name, err)
		}
		match := len(buf) == len(want)
		if match {
			for i, b := range buf {
				if want[i] != b {
					match = false
					break
				}
			}
		}
		if !match {
			t.Fatalf("%s: got %q (len %d); want %q (len %d)", name, buf, len(buf), want, len(want))
		}
	}

	n := testing.AllocsPerRun(100, func() {
		for _, tt := range tests {
			rows.raw = rows.raw[:0]
			test(tt.name, tt.in, tt.want)
		}
	})

	// The numbers below are only valid for 64-bit interface word sizes,
	// and gc. With 32-bit words there are more convT2E allocs, and
	// with gccgo, only pointers currently go in interface data.
	// So only care on amd64 gc for now.
	measureAllocs := false
	switch runtime.GOARCH {
	case "amd64", "arm64":
		measureAllocs = runtime.Compiler == "gc"
	}

	if n > 0.5 && measureAllocs {
		t.Fatalf("allocs = %v; want 0", n)
	}

	// This one involves a convT2E allocation, string -> interface{}
	n = testing.AllocsPerRun(100, func() {
		test("string", "foo", "foo")
	})
	if n > 1.5 && measureAllocs {
		t.Fatalf("allocs = %v; want max 1", n)
	}
}

// https://golang.org/issues/13905
func TestUserDefinedBytes(t *testing.T) {
	type userDefinedBytes []byte
	var u userDefinedBytes
	v := []byte("foo")

	convertAssign(&u, v)
	if &u[0] == &v[0] {
		t.Fatal("userDefinedBytes got potentially dirty driver memory")
	}
}

type Valuer_V string

func (v Valuer_V) Value() (driver.Value, error) {
	return strings.ToUpper(string(v)), nil
}

type Valuer_P string

func (p *Valuer_P) Value() (driver.Value, error) {
	if p == nil {
		return "nil-to-str", nil
	}
	return strings.ToUpper(string(*p)), nil
}

func TestDriverArgs(t *testing.T) {
	var nilValuerVPtr *Valuer_V
	var nilValuerPPtr *Valuer_P
	var nilStrPtr *string
	tests := []struct {
		args []any
		want []driver.NamedValue
	}{
		0: {
			args: []any{Valuer_V("foo")},
			want: []driver.NamedValue{
				{
					Ordinal: 1,
					Value:   "FOO",
				},
			},
		},
		1: {
			args: []any{nilValuerVPtr},
			want: []driver.NamedValue{
				{
					Ordinal: 1,
					Value:   nil,
				},
			},
		},
		2: {
			args: []any{nilValuerPPtr},
			want: []driver.NamedValue{
				{
					Ordinal: 1,
					Value:   "nil-to-str",
				},
			},
		},
		3: {
			args: []any{"plain-str"},
			want: []driver.NamedValue{
				{
					Ordinal: 1,
					Value:   "plain-str",
				},
			},
		},
		4: {
			args: []any{nilStrPtr},
			want: []driver.NamedValue{
				{
					Ordinal: 1,
					Value:   nil,
				},
			},
		},
	}
	for i, tt := range tests {
		ds := &driverStmt{Locker: &sync.Mutex{}, si: stubDriverStmt{nil}}
		got, err := driverArgsConnLocked(nil, ds, tt.args)
		if err != nil {
			t.Errorf("test[%d]: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("test[%d]: got %v, want %v", i, got, tt.want)
		}
	}
}

type dec struct {
	form        byte
	neg         bool
	coefficient [16]byte
	exponent    int32
}

func (d dec) Decompose(buf []byte) (form byte, negative bool, coefficient []byte, exponent int32) {
	coef := make([]byte, 16)
	copy(coef, d.coefficient[:])
	return d.form, d.neg, coef, d.exponent
}

func (d *dec) Compose(form byte, negative bool, coefficient []byte, exponent int32) error {
	switch form {
	default:
		return fmt.Errorf("unknown form %d", form)
	case 1, 2:
		d.form = form
		d.neg = negative
		return nil
	case 0:
	}
	d.form = form
	d.neg = negative
	d.exponent = exponent

	// This isn't strictly correct, as the extra bytes could be all zero,
	// ignore this for this test.
	if len(coefficient) > 16 {
		return fmt.Errorf("coefficient too large")
	}
	copy(d.coefficient[:], coefficient)

	return nil
}

type decFinite struct {
	neg         bool
	coefficient [16]byte
	exponent    int32
}

func (d decFinite) Decompose(buf []byte) (form byte, negative bool, coefficient []byte, exponent int32) {
	coef := make([]byte, 16)
	copy(coef, d.coefficient[:])
	return 0, d.neg, coef, d.exponent
}

func (d *decFinite) Compose(form byte, negative bool, coefficient []byte, exponent int32) error {
	switch form {
	default:
		return fmt.Errorf("unknown form %d", form)
	case 1, 2:
		return fmt.Errorf("unsupported form %d", form)
	case 0:
	}
	d.neg = negative
	d.exponent = exponent

	// This isn't strictly correct, as the extra bytes could be all zero,
	// ignore this for this test.
	if len(coefficient) > 16 {
		return fmt.Errorf("coefficient too large")
	}
	copy(d.coefficient[:], coefficient)

	return nil
}

func TestDecimal(t *testing.T) {
	list := []struct {
		name string
		in   decimalDecompose
		out  dec
		err  bool
	}{
		{name: "same", in: dec{exponent: -6}, out: dec{exponent: -6}},

		// Ensure reflection is not used to assign the value by using different types.
		{name: "diff", in: decFinite{exponent: -6}, out: dec{exponent: -6}},

		{name: "bad-form", in: dec{form: 200}, err: true},
	}
	for _, item := range list {
		t.Run(item.name, func(t *testing.T) {
			out := dec{}
			err := convertAssign(&out, item.in)
			if item.err {
				if err == nil {
					t.Fatalf("unexpected nil error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(out, item.out) {
				t.Fatalf("got %#v want %#v", out, item.out)
			}
		})
	}
}

"""



```