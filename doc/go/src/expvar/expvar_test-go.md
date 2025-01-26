Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first line `package expvar` is a huge clue. It immediately tells us this code belongs to the `expvar` standard library package in Go. Knowing this is a standard library package hints at its likely purpose: providing a standardized way to expose runtime metrics.

2. **Scan for Key Data Structures and Functions:** Quickly read through the code, looking for capitalized names (likely types or exported functions) and keywords like `func`, `type`, and `struct`. This gives a high-level overview. I see:
    * `RemoveAll()`
    * `TestNil`, `TestInt`, `TestFloat`, `TestString`, `TestMapInit`, etc. These clearly indicate this is a *testing* file for the `expvar` package.
    * `Benchmark...` functions confirm performance testing is also present.
    * `NewInt`, `NewFloat`, `NewString`, `NewMap`, `Func`. These look like constructors for different types of exported variables.
    * `Get()`, `Add()`, `Set()`, `Value()`, `String()`, `Do()`, `Delete()`, `Init()`. These are methods on the exported variable types.
    * `Handler()`, `expvarHandler()`. This strongly suggests a mechanism for serving these variables over HTTP.

3. **Analyze Individual Tests:**  Now, go through each `Test...` function. The names are quite descriptive.
    * `TestNil`: Checks if getting a non-existent variable returns `nil`.
    * `TestInt`:  Focuses on the `Int` type, testing `Value()`, `Get()`, `Add()`, `String()`, and `Set()`. Notice the use of `t.Errorf` for reporting failures.
    * `TestFloat`: Similar to `TestInt`, but for the `Float` type.
    * `TestString`: Tests the `String` type, paying attention to JSON encoding of special characters.
    * `TestMapInit`, `TestMapDelete`, `TestMapCounter`, `TestMapNil`: Thoroughly tests the `Map` type, covering initialization, deletion, adding different types of values, and handling `nil` values.
    * `TestFunc`: Tests the `Func` type, where the value is computed by a provided function.
    * `TestHandler`: Verifies that the HTTP handler serves the exported variables in JSON format.
    * `TestAppendJSONQuote`:  Tests a utility function for properly quoting strings in JSON.

4. **Analyze Benchmarks:** The `Benchmark...` functions provide insights into the performance of different operations, particularly concurrency using `b.RunParallel`.

5. **Infer the Core Functionality:** Based on the tests, I can deduce the following about the `expvar` package:
    * It provides a way to register and retrieve named variables.
    * It supports different variable types: `Int`, `Float`, `String`, and `Map`.
    * It allows atomic operations on numeric types (`Add`).
    * It offers methods to get the current value and a JSON string representation of the variable.
    * The `Map` type allows storing key-value pairs where values are also `expvar` types.
    * There's a way to expose these variables via an HTTP handler.

6. **Construct Example Code:**  Now, try to create a simple example demonstrating how to use `expvar`. Start with importing the package, creating variables of different types, modifying their values, and then using the HTTP handler.

7. **Infer HTTP Handling (Based on `TestHandler`):**  The `TestHandler` function is key here. It uses `httptest.NewRecorder()` and calls `expvarHandler()`. This strongly suggests that `expvar` registers its handler on the default HTTP server. Therefore, accessing `/debug/vars` would likely expose the variables.

8. **Identify Potential Pitfalls:** Consider common errors developers might make when using such a package. For example:
    * **Type Assertions:** Getting a variable using `Get()` returns an `Var` interface, so you need to type assert it to the correct concrete type. This can lead to panics if the type is incorrect.
    * **Concurrency (Less obvious from *this* snippet, but generally relevant to metrics):** While this specific snippet shows atomic operations on `Int` and `Float`,  in real-world usage, concurrent access to more complex structures within a `Func` or a manually managed variable might require additional synchronization. *However, this wasn't strongly emphasized by this particular code snippet, so focusing on type assertions is more direct.*

9. **Review and Refine:** Go back through the analysis and the example code to ensure accuracy and clarity. Ensure the language used in the explanation is clear and concise. Double-check that the example code compiles and works as expected (mentally, if not actually running it at this stage).

This systematic approach, starting with the package name and drilling down into the tests and function signatures, is crucial for understanding the purpose and functionality of unfamiliar code. The testing code itself is a valuable form of documentation and examples.
这段代码是 Go 语言标准库 `expvar` 包的一部分，它的功能是 **提供一种标准的、易于使用的方式来导出和展示运行时的程序变量（public variables）**。这些变量通常用于监控和诊断。

更具体地说，这段代码包含了对 `expvar` 包中几个核心类型的测试：`Int`，`Float`，`String` 和 `Map`，以及一个用于处理 HTTP 请求的 Handler。

以下是它的主要功能点：

1. **变量的创建和获取:**
   - `NewInt(name string) *Int`: 创建一个新的名为 `name` 的整数类型的可导出变量。
   - `NewFloat(name string) *Float`: 创建一个新的名为 `name` 的浮点数类型的可导出变量。
   - `NewString(name string) *String`: 创建一个新的名为 `name` 的字符串类型的可导出变量。
   - `NewMap(name string) *Map`: 创建一个新的名为 `name` 的 Map 类型的可导出变量。
   - `Get(name string) Var`:  根据名称获取已导出的变量。如果变量不存在，则返回 `nil`。

2. **基本类型的操作:**
   - `Int`:
     - `Value() int64`: 获取当前的整数值。
     - `Add(delta int64)`: 原子地增加整数值。
     - `Set(value int64)`: 设置整数值。
     - `String() string`: 返回整数值的字符串表示。
   - `Float`:
     - `Value() float64`: 获取当前的浮点数值。
     - `Add(delta float64)`: 原子地增加浮点数值。
     - `String() string`: 返回浮点数值的字符串表示。
   - `String`:
     - `Value() string`: 获取当前的字符串值。
     - `Set(value string)`: 设置字符串值。
     - `String() string`: 返回字符串值的 JSON 格式的字符串表示（会对特殊字符进行转义）。

3. **Map 类型的操作:**
   - `Map`:
     - `Init() *Map`: 初始化 Map。
     - `Set(key string, av Var)`: 设置 Map 中指定键的值。
     - `Add(key string, delta int64)`: 原子地增加 Map 中指定键的整数值。如果键不存在，则创建一个新的 `Int` 类型的变量。
     - `AddFloat(key string, delta float64)`: 原子地增加 Map 中指定键的浮点数值。如果键不存在，则创建一个新的 `Float` 类型的变量。
     - `Get(key string) Var`: 获取 Map 中指定键的值。
     - `Delete(key string)`: 删除 Map 中指定的键。
     - `Do(f func(KeyValue))`: 遍历 Map 中的所有键值对。
     - `String() string`: 返回 Map 内容的 JSON 格式的字符串表示。

4. **Func 类型:**
   - `Func(f func() any) Var`: 创建一个 `Func` 类型的变量，它的值由提供的函数 `f` 动态计算。每次获取其字符串表示或值时，都会调用该函数。

5. **HTTP Handler:**
   - `Handler() http.Handler`: 返回一个 HTTP Handler，用于将所有已导出的变量以 JSON 格式输出。通常，这个 Handler 会被注册到 `/debug/vars` 路径下，以便通过 HTTP 访问。

**`expvar` 是 Go 语言提供的用于暴露程序内部状态的轻量级机制。**  它可以方便地监控程序的运行状况，例如请求计数、内存使用情况等。

**Go 代码示例:**

假设我们想使用 `expvar` 监控 HTTP 请求的数量：

```go
package main

import (
	"expvar"
	"fmt"
	"net/http"
)

var requests = expvar.NewInt("http_requests_total")

func handler(w http.ResponseWriter, r *http.Request) {
	requests.Add(1)
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	http.HandleFunc("/", handler)

	// 将 expvar 的 Handler 注册到 /debug/vars 路径
	http.Handle("/debug/vars", expvar.Handler())

	fmt.Println("Server listening on :8080")
	http.ListenAndServe(":8080", nil)
}
```

**假设的输入与输出:**

1. **启动程序并访问几次 `/`:**  每次访问根路径 `/`，`requests` 变量的值都会增加。

2. **访问 `/debug/vars`:**  在浏览器中访问 `http://localhost:8080/debug/vars`，你将会看到类似以下的 JSON 输出：

   ```json
   {
     "http_requests_total": 3
   }
   ```

   （假设你访问了三次 `/` 路径）

**命令行参数:**

`expvar` 包本身不直接处理命令行参数。它的主要作用是提供一个编程接口来导出变量。如何将这些导出的变量暴露出来，例如通过 HTTP，则需要在你的应用程序中进行配置和处理。在上面的例子中，我们使用了 `net/http` 包来创建 HTTP 服务器，并将 `expvar.Handler()` 注册到特定的路径。

**使用者易犯错的点:**

1. **类型断言错误:**  `expvar.Get()` 返回的是 `expvar.Var` 接口，你需要将其断言为具体的类型才能使用其特定方法。如果类型断言错误，会导致 panic。

   ```go
   // 假设 "my_int" 是一个 Int 类型的 expvar
   myIntVar := expvar.Get("my_int")
   if myIntVar != nil {
       // 错误的做法，直接当做 *expvar.Int 使用
       // myIntVar.Add(1) // 编译错误

       // 正确的做法，进行类型断言
       intVar, ok := myIntVar.(*expvar.Int)
       if ok {
           intVar.Add(1)
       } else {
           fmt.Println("my_int is not an Int type")
       }
   }
   ```

2. **并发安全:** `expvar` 包中的 `Int` 和 `Float` 类型使用了原子操作，因此对于单个变量的增加操作是并发安全的。但是，对于更复杂的操作，例如在 `Map` 中同时更新多个键，或者在 `Func` 中访问共享状态，仍然需要开发者自己保证并发安全。

这段测试代码非常全面地覆盖了 `expvar` 包中主要类型的功能和用法，是理解该包工作原理的很好的入口。

Prompt: 
```
这是路径为go/src/expvar/expvar_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package expvar

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// RemoveAll removes all exported variables.
// This is for tests only.
func RemoveAll() {
	vars.keysMu.Lock()
	defer vars.keysMu.Unlock()
	for _, k := range vars.keys {
		vars.m.Delete(k)
	}
	vars.keys = nil
}

func TestNil(t *testing.T) {
	RemoveAll()
	val := Get("missing")
	if val != nil {
		t.Errorf("got %v, want nil", val)
	}
}

func TestInt(t *testing.T) {
	RemoveAll()
	reqs := NewInt("requests")
	if i := reqs.Value(); i != 0 {
		t.Errorf("reqs.Value() = %v, want 0", i)
	}
	if reqs != Get("requests").(*Int) {
		t.Errorf("Get() failed.")
	}

	reqs.Add(1)
	reqs.Add(3)
	if i := reqs.Value(); i != 4 {
		t.Errorf("reqs.Value() = %v, want 4", i)
	}

	if s := reqs.String(); s != "4" {
		t.Errorf("reqs.String() = %q, want \"4\"", s)
	}

	reqs.Set(-2)
	if i := reqs.Value(); i != -2 {
		t.Errorf("reqs.Value() = %v, want -2", i)
	}
}

func BenchmarkIntAdd(b *testing.B) {
	var v Int

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			v.Add(1)
		}
	})
}

func BenchmarkIntSet(b *testing.B) {
	var v Int

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			v.Set(1)
		}
	})
}

func TestFloat(t *testing.T) {
	RemoveAll()
	reqs := NewFloat("requests-float")
	if reqs.f.Load() != 0.0 {
		t.Errorf("reqs.f = %v, want 0", reqs.f.Load())
	}
	if reqs != Get("requests-float").(*Float) {
		t.Errorf("Get() failed.")
	}

	reqs.Add(1.5)
	reqs.Add(1.25)
	if v := reqs.Value(); v != 2.75 {
		t.Errorf("reqs.Value() = %v, want 2.75", v)
	}

	if s := reqs.String(); s != "2.75" {
		t.Errorf("reqs.String() = %q, want \"4.64\"", s)
	}

	reqs.Add(-2)
	if v := reqs.Value(); v != 0.75 {
		t.Errorf("reqs.Value() = %v, want 0.75", v)
	}
}

func BenchmarkFloatAdd(b *testing.B) {
	var f Float

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			f.Add(1.0)
		}
	})
}

func BenchmarkFloatSet(b *testing.B) {
	var f Float

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			f.Set(1.0)
		}
	})
}

func TestString(t *testing.T) {
	RemoveAll()
	name := NewString("my-name")
	if s := name.Value(); s != "" {
		t.Errorf(`NewString("my-name").Value() = %q, want ""`, s)
	}

	name.Set("Mike")
	if s, want := name.String(), `"Mike"`; s != want {
		t.Errorf(`after name.Set("Mike"), name.String() = %q, want %q`, s, want)
	}
	if s, want := name.Value(), "Mike"; s != want {
		t.Errorf(`after name.Set("Mike"), name.Value() = %q, want %q`, s, want)
	}

	// Make sure we produce safe JSON output.
	name.Set("<")
	if s, want := name.String(), "\"\\u003c\""; s != want {
		t.Errorf(`after name.Set("<"), name.String() = %q, want %q`, s, want)
	}
}

func BenchmarkStringSet(b *testing.B) {
	var s String

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Set("red")
		}
	})
}

func TestMapInit(t *testing.T) {
	RemoveAll()
	colors := NewMap("bike-shed-colors")
	colors.Add("red", 1)
	colors.Add("blue", 1)
	colors.Add("chartreuse", 1)

	n := 0
	colors.Do(func(KeyValue) { n++ })
	if n != 3 {
		t.Errorf("after three Add calls with distinct keys, Do should invoke f 3 times; got %v", n)
	}

	colors.Init()

	n = 0
	colors.Do(func(KeyValue) { n++ })
	if n != 0 {
		t.Errorf("after Init, Do should invoke f 0 times; got %v", n)
	}
}

func TestMapDelete(t *testing.T) {
	RemoveAll()
	colors := NewMap("bike-shed-colors")

	colors.Add("red", 1)
	colors.Add("red", 2)
	colors.Add("blue", 4)

	n := 0
	colors.Do(func(KeyValue) { n++ })
	if n != 2 {
		t.Errorf("after two Add calls with distinct keys, Do should invoke f 2 times; got %v", n)
	}

	colors.Delete("red")
	if v := colors.Get("red"); v != nil {
		t.Errorf("removed red, Get should return nil; got %v", v)
	}
	n = 0
	colors.Do(func(KeyValue) { n++ })
	if n != 1 {
		t.Errorf("removed red, Do should invoke f 1 times; got %v", n)
	}

	colors.Delete("notfound")
	n = 0
	colors.Do(func(KeyValue) { n++ })
	if n != 1 {
		t.Errorf("attempted to remove notfound, Do should invoke f 1 times; got %v", n)
	}

	colors.Delete("blue")
	colors.Delete("blue")
	if v := colors.Get("blue"); v != nil {
		t.Errorf("removed blue, Get should return nil; got %v", v)
	}
	n = 0
	colors.Do(func(KeyValue) { n++ })
	if n != 0 {
		t.Errorf("all keys removed, Do should invoke f 0 times; got %v", n)
	}
}

func TestMapCounter(t *testing.T) {
	RemoveAll()
	colors := NewMap("bike-shed-colors")

	colors.Add("red", 1)
	colors.Add("red", 2)
	colors.Add("blue", 4)
	colors.AddFloat(`green "midori"`, 4.125)
	if x := colors.Get("red").(*Int).Value(); x != 3 {
		t.Errorf("colors.m[\"red\"] = %v, want 3", x)
	}
	if x := colors.Get("blue").(*Int).Value(); x != 4 {
		t.Errorf("colors.m[\"blue\"] = %v, want 4", x)
	}
	if x := colors.Get(`green "midori"`).(*Float).Value(); x != 4.125 {
		t.Errorf("colors.m[`green \"midori\"] = %v, want 4.125", x)
	}

	// colors.String() should be '{"red":3, "blue":4}',
	// though the order of red and blue could vary.
	s := colors.String()
	var j any
	err := json.Unmarshal([]byte(s), &j)
	if err != nil {
		t.Errorf("colors.String() isn't valid JSON: %v", err)
	}
	m, ok := j.(map[string]any)
	if !ok {
		t.Error("colors.String() didn't produce a map.")
	}
	red := m["red"]
	x, ok := red.(float64)
	if !ok {
		t.Error("red.Kind() is not a number.")
	}
	if x != 3 {
		t.Errorf("red = %v, want 3", x)
	}
}

func TestMapNil(t *testing.T) {
	RemoveAll()
	const key = "key"
	m := NewMap("issue527719")
	m.Set(key, nil)
	s := m.String()
	var j any
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		t.Fatalf("m.String() == %q isn't valid JSON: %v", s, err)
	}
	m2, ok := j.(map[string]any)
	if !ok {
		t.Fatalf("m.String() produced %T, wanted a map", j)
	}
	v, ok := m2[key]
	if !ok {
		t.Fatalf("missing %q in %v", key, m2)
	}
	if v != nil {
		t.Fatalf("m[%q] = %v, want nil", key, v)
	}
}

func BenchmarkMapSet(b *testing.B) {
	m := new(Map).Init()

	v := new(Int)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Set("red", v)
		}
	})
}

func BenchmarkMapSetDifferent(b *testing.B) {
	procKeys := make([][]string, runtime.GOMAXPROCS(0))
	for i := range procKeys {
		keys := make([]string, 4)
		for j := range keys {
			keys[j] = fmt.Sprint(i, j)
		}
		procKeys[i] = keys
	}

	m := new(Map).Init()
	v := new(Int)
	b.ResetTimer()

	var n int32
	b.RunParallel(func(pb *testing.PB) {
		i := int(atomic.AddInt32(&n, 1)-1) % len(procKeys)
		keys := procKeys[i]

		for pb.Next() {
			for _, k := range keys {
				m.Set(k, v)
			}
		}
	})
}

// BenchmarkMapSetDifferentRandom simulates such a case where the concerned
// keys of Map.Set are generated dynamically and as a result insertion is
// out of order and the number of the keys may be large.
func BenchmarkMapSetDifferentRandom(b *testing.B) {
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprint(i))))
	}

	v := new(Int)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m := new(Map).Init()
		for _, k := range keys {
			m.Set(k, v)
		}
	}
}

func BenchmarkMapSetString(b *testing.B) {
	m := new(Map).Init()

	v := new(String)
	v.Set("Hello, !")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Set("red", v)
		}
	})
}

func BenchmarkMapAddSame(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m := new(Map).Init()
			m.Add("red", 1)
			m.Add("red", 1)
			m.Add("red", 1)
			m.Add("red", 1)
		}
	})
}

func BenchmarkMapAddDifferent(b *testing.B) {
	procKeys := make([][]string, runtime.GOMAXPROCS(0))
	for i := range procKeys {
		keys := make([]string, 4)
		for j := range keys {
			keys[j] = fmt.Sprint(i, j)
		}
		procKeys[i] = keys
	}

	b.ResetTimer()

	var n int32
	b.RunParallel(func(pb *testing.PB) {
		i := int(atomic.AddInt32(&n, 1)-1) % len(procKeys)
		keys := procKeys[i]

		for pb.Next() {
			m := new(Map).Init()
			for _, k := range keys {
				m.Add(k, 1)
			}
		}
	})
}

// BenchmarkMapAddDifferentRandom simulates such a case where that the concerned
// keys of Map.Add are generated dynamically and as a result insertion is out of
// order and the number of the keys may be large.
func BenchmarkMapAddDifferentRandom(b *testing.B) {
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprint(i))))
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m := new(Map).Init()
		for _, k := range keys {
			m.Add(k, 1)
		}
	}
}

func BenchmarkMapAddSameSteadyState(b *testing.B) {
	m := new(Map).Init()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Add("red", 1)
		}
	})
}

func BenchmarkMapAddDifferentSteadyState(b *testing.B) {
	procKeys := make([][]string, runtime.GOMAXPROCS(0))
	for i := range procKeys {
		keys := make([]string, 4)
		for j := range keys {
			keys[j] = fmt.Sprint(i, j)
		}
		procKeys[i] = keys
	}

	m := new(Map).Init()
	b.ResetTimer()

	var n int32
	b.RunParallel(func(pb *testing.PB) {
		i := int(atomic.AddInt32(&n, 1)-1) % len(procKeys)
		keys := procKeys[i]

		for pb.Next() {
			for _, k := range keys {
				m.Add(k, 1)
			}
		}
	})
}

func TestFunc(t *testing.T) {
	RemoveAll()
	var x any = []string{"a", "b"}
	f := Func(func() any { return x })
	if s, exp := f.String(), `["a","b"]`; s != exp {
		t.Errorf(`f.String() = %q, want %q`, s, exp)
	}
	if v := f.Value(); !reflect.DeepEqual(v, x) {
		t.Errorf(`f.Value() = %q, want %q`, v, x)
	}

	x = 17
	if s, exp := f.String(), `17`; s != exp {
		t.Errorf(`f.String() = %q, want %q`, s, exp)
	}
}

func TestHandler(t *testing.T) {
	RemoveAll()
	m := NewMap("map1")
	m.Add("a", 1)
	m.Add("z", 2)
	m2 := NewMap("map2")
	for i := 0; i < 9; i++ {
		m2.Add(strconv.Itoa(i), int64(i))
	}
	rr := httptest.NewRecorder()
	rr.Body = new(bytes.Buffer)
	expvarHandler(rr, nil)
	want := `{
"map1": {"a": 1, "z": 2},
"map2": {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8}
}
`
	if got := rr.Body.String(); got != want {
		t.Errorf("HTTP handler wrote:\n%s\nWant:\n%s", got, want)
	}
}

func BenchmarkMapString(b *testing.B) {
	var m, m1, m2 Map
	m.Set("map1", &m1)
	m1.Add("a", 1)
	m1.Add("z", 2)
	m.Set("map2", &m2)
	for i := 0; i < 9; i++ {
		m2.Add(strconv.Itoa(i), int64(i))
	}
	var s1, s2 String
	m.Set("str1", &s1)
	s1.Set("hello, world!")
	m.Set("str2", &s2)
	s2.Set("fizz buzz")
	b.ResetTimer()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.String()
	}
}

func BenchmarkRealworldExpvarUsage(b *testing.B) {
	var (
		bytesSent Int
		bytesRead Int
	)

	// The benchmark creates GOMAXPROCS client/server pairs.
	// Each pair creates 4 goroutines: client reader/writer and server reader/writer.
	// The benchmark stresses concurrent reading and writing to the same connection.
	// Such pattern is used in net/http and net/rpc.

	b.StopTimer()

	P := runtime.GOMAXPROCS(0)
	N := b.N / P
	W := 1000

	// Setup P client/server connections.
	clients := make([]net.Conn, P)
	servers := make([]net.Conn, P)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()
	done := make(chan bool, 1)
	go func() {
		for p := 0; p < P; p++ {
			s, err := ln.Accept()
			if err != nil {
				b.Errorf("Accept failed: %v", err)
				done <- false
				return
			}
			servers[p] = s
		}
		done <- true
	}()
	for p := 0; p < P; p++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			<-done
			b.Fatalf("Dial failed: %v", err)
		}
		clients[p] = c
	}
	if !<-done {
		b.FailNow()
	}

	b.StartTimer()

	var wg sync.WaitGroup
	wg.Add(4 * P)
	for p := 0; p < P; p++ {
		// Client writer.
		go func(c net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				v := byte(i)
				for w := 0; w < W; w++ {
					v *= v
				}
				buf[0] = v
				n, err := c.Write(buf[:])
				if err != nil {
					b.Errorf("Write failed: %v", err)
					return
				}

				bytesSent.Add(int64(n))
			}
		}(clients[p])

		// Pipe between server reader and server writer.
		pipe := make(chan byte, 128)

		// Server reader.
		go func(s net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				n, err := s.Read(buf[:])

				if err != nil {
					b.Errorf("Read failed: %v", err)
					return
				}

				bytesRead.Add(int64(n))
				pipe <- buf[0]
			}
		}(servers[p])

		// Server writer.
		go func(s net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				v := <-pipe
				for w := 0; w < W; w++ {
					v *= v
				}
				buf[0] = v
				n, err := s.Write(buf[:])
				if err != nil {
					b.Errorf("Write failed: %v", err)
					return
				}

				bytesSent.Add(int64(n))
			}
			s.Close()
		}(servers[p])

		// Client reader.
		go func(c net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				n, err := c.Read(buf[:])

				if err != nil {
					b.Errorf("Read failed: %v", err)
					return
				}

				bytesRead.Add(int64(n))
			}
			c.Close()
		}(clients[p])
	}
	wg.Wait()
}

func TestAppendJSONQuote(t *testing.T) {
	var b []byte
	for i := 0; i < 128; i++ {
		b = append(b, byte(i))
	}
	b = append(b, "\u2028\u2029"...)
	got := string(appendJSONQuote(nil, string(b[:])))
	want := `"` +
		`\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\t\n\u000b\u000c\r\u000e\u000f` +
		`\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f` +
		` !\"#$%\u0026'()*+,-./0123456789:;\u003c=\u003e?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_` +
		"`" + `abcdefghijklmnopqrstuvwxyz{|}~` + "\x7f" + `\u2028\u2029"`
	if got != want {
		t.Errorf("appendJSONQuote mismatch:\ngot  %v\nwant %v", got, want)
	}
}

"""



```