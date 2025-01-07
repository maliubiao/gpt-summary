Response:
Let's break down the thought process to analyze the given Go code snippet.

**1. Initial Understanding: Context and Purpose**

The first few lines clearly indicate this is part of the `encoding/json` package in Go and the file is `bench_test.go`. The comments state its purpose: "Large data benchmark."  This immediately tells us this code is *not* about the core logic of JSON encoding/decoding, but rather about measuring its performance under various scenarios.

**2. Identifying Key Structures and Data**

The code defines two important structs: `codeResponse` and `codeNode`. These represent the data structures used for the benchmark. The `json:""` tags are crucial; they indicate how these structs are intended to be serialized to and deserialized from JSON. We also see global variables `codeJSON` (a byte slice) and `codeStruct` (a `codeResponse`). The `codeInit()` function is likely responsible for initializing these variables.

**3. Analyzing the `codeInit()` Function**

This function is critical. It performs the following steps:

* **Opens a file:** `os.Open("testdata/code.json.gz")` suggests it's loading a compressed JSON file.
* **Handles errors:** There are `panic()` calls for error handling during file opening and gzip reading. This indicates that the benchmark *requires* this file to be present and readable.
* **Reads the data:** `gzip.NewReader` and `io.ReadAll` are used to decompress and read the JSON data.
* **Unmarshals the JSON:** `Unmarshal(codeJSON, &codeStruct)` converts the JSON data into the Go struct.
* **Marshals back to JSON:** `Marshal(&codeStruct)` converts the Go struct back into JSON.
* **Compares the results:** It checks if the re-marshaled JSON is identical to the original. This serves as a basic sanity check to ensure the marshaling/unmarshaling process is consistent.

**4. Examining the Benchmark Functions (Naming Conventions and Patterns)**

The code contains many functions starting with `Benchmark`. This is the standard Go testing/benchmarking convention. Key observations:

* **`BenchmarkCode...`:**  These benchmarks are focused on the `codeJSON` data and the `codeStruct`. They test different aspects of encoding and decoding (e.g., using `Encoder` vs. `Marshal`, `Decoder` vs. `Unmarshal`).
* **`Benchmark...Error`:**  These variants specifically test error handling, particularly for cyclic data structures which JSON cannot directly represent.
* **`BenchmarkMarshalBytes`:** These benchmarks focus on marshaling byte slices of different sizes, highlighting potential performance variations based on data size.
* **`BenchmarkUnmarshal...`:** These test unmarshaling various basic Go types (string, float64, int64, map).
* **Parallelism:** Many benchmarks use `b.RunParallel`, indicating they are designed to measure performance under concurrent conditions.
* **Resource Management:**  `b.ReportAllocs()` is used to track memory allocations during the benchmark. `b.StopTimer()` and `b.StartTimer()` are used to exclude setup time from the benchmark measurements. `b.SetBytes()` sets the amount of data processed per operation.

**5. Inferring Go Features Being Benchmarked**

Based on the function names and the operations performed, we can infer the Go features being tested:

* **`json.Marshal()`:**  Converting Go data structures to JSON.
* **`json.Unmarshal()`:** Converting JSON data to Go data structures.
* **`json.NewEncoder()` and `enc.Encode()`:**  Using an `Encoder` for potentially more efficient streaming or when writing to an `io.Writer`.
* **`json.NewDecoder()` and `dec.Decode()`:**  Using a `Decoder` for potentially more efficient streaming or when reading from an `io.Reader`.
* **Handling of different data types:**  Strings, numbers, maps, structs, byte slices.
* **Error handling:**  Specifically for cases like cyclic data structures.
* **Performance with large datasets:** The "Large data benchmark" comment reinforces this.
* **Performance with concurrency:**  `b.RunParallel`.
* **Caching (Type Fields Cache):**  The `BenchmarkTypeFieldsCache` explicitly tests the performance of the internal caching mechanism for struct field information.

**6. Constructing Example Code (Based on Inference)**

Based on the identified functions, it's possible to construct example usage scenarios for `Marshal` and `Unmarshal`. The key is to use the defined `codeResponse` struct and provide sample JSON data (or the `codeJSON` variable if we had access to the `testdata/code.json.gz` file).

**7. Identifying Potential User Errors**

Considering how these functions are used, potential errors could include:

* **Incorrect struct tags:**  Mismatched or missing `json:""` tags can lead to incorrect serialization/deserialization.
* **Type mismatches:** Trying to unmarshal JSON data into a Go variable of an incompatible type will result in errors.
* **Handling of errors:**  Forgetting to check the error return values of `Marshal` and `Unmarshal`.
* **Performance considerations:** Not understanding the performance implications of using `Encoder`/`Decoder` vs. `Marshal`/`Unmarshal` for streaming data.

**8. Command-Line Arguments (Analysis)**

While the code itself doesn't directly process command-line arguments, Go's benchmarking tool (`go test -bench=.`) is used to run these benchmarks. The `-bench` flag is the primary way to control which benchmarks are executed.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the specific data structures (`codeResponse`, `codeNode`). Realizing the broader purpose of benchmarking shifts the focus to the `json` package's functions.
* I might have initially overlooked the error handling benchmarks. Recognizing the `...Error` suffix highlights this important aspect.
* When constructing the example code, I need to ensure it aligns with the types defined in the benchmark. Using a different struct wouldn't be a relevant example.

By following these steps, combining code analysis with understanding the purpose of benchmarks and Go's testing conventions, we can effectively analyze the provided code snippet and extract the required information.
这个 `bench_test.go` 文件是 Go 语言 `encoding/json` 标准库的一部分，专门用于**测试和衡量 JSON 编码和解码的性能**。它通过创建各种基准测试（benchmarks）来评估不同场景下 `encoding/json` 包的效率。

以下是它的主要功能：

1. **基准测试 `Marshal` 和 `Unmarshal` 函数的性能:**  它衡量了将 Go 数据结构编码成 JSON 字符串 (`Marshal`) 以及将 JSON 字符串解码成 Go 数据结构 (`Unmarshal`) 的速度和内存分配情况。

2. **针对不同数据结构的基准测试:**  代码中定义了 `codeResponse` 和 `codeNode` 结构体，并加载了一个大型的 JSON 数据文件 `code.json.gz`。这些基准测试使用这些复杂的数据结构来模拟实际应用场景，评估处理复杂 JSON 数据的性能。

3. **使用 `Encoder` 和 `Decoder` 的基准测试:** 除了 `Marshal` 和 `Unmarshal`，它还测试了 `Encoder` 和 `Decoder` 类型，它们提供了流式编码和解码的能力，可以更高效地处理大型 JSON 数据。

4. **错误处理的基准测试:**  一些基准测试（例如 `BenchmarkCodeEncoderError` 和 `BenchmarkCodeMarshalError`）专门测试在编码过程中遇到错误（例如循环引用）时的性能。

5. **针对特定数据类型和场景的基准测试:**  代码中包含针对不同 Go 数据类型（如字符串、浮点数、整数、map 和 byte slice）以及特定场景（如包含 Unicode 字符的字符串）的基准测试。

6. **内存分配的跟踪:**  每个基准测试都调用了 `b.ReportAllocs()`，这会报告在测试过程中分配的内存数量，帮助开发者了解内存使用情况。

7. **并行执行的基准测试:**  许多基准测试使用了 `b.RunParallel`，这意味着它们会在多个 Goroutine 中并行运行，以模拟高并发场景下的性能。

8. **缓存机制的基准测试:** `BenchmarkTypeFieldsCache` 专门测试了 `encoding/json` 包内部用于缓存类型字段信息的机制的性能。

**它是什么 Go 语言功能的实现？**

这个文件主要是对 Go 语言标准库中 `encoding/json` 包提供的 JSON 序列化和反序列化功能的性能测试。它不是功能的具体实现，而是用来评估这些功能在不同情况下的效率。

**Go 代码举例说明:**

假设我们想了解 `Marshal` 函数将 `codeResponse` 结构体编码成 JSON 的性能。`BenchmarkCodeMarshal` 函数就是用来做这个的。

```go
package json_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

type codeResponse struct {
	Tree     *codeNode `json:"tree"`
	Username string    `json:"username"`
}

type codeNode struct {
	Name     string      `json:"name"`
	Kids     []*codeNode `json:"kids"`
	CLWeight float64     `json:"cl_weight"`
	Touches  int         `json:"touches"`
	MinT     int64       `json:"min_t"`
	MaxT     int64       `max_t"`
	MeanT    int64       `json:"mean_t"`
}

var codeStruct = codeResponse{
	Username: "agl",
	Tree: &codeNode{
		Name: "root",
		Kids: []*codeNode{
			{Name: "child1", Touches: 10},
			{Name: "child2", Touches: 20},
		},
	},
}

func BenchmarkMarshalExample(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(&codeStruct)
		if err != nil {
			b.Fatalf("Marshal error: %v", err)
		}
	}
}

func ExampleMarshal() {
	data, err := json.Marshal(codeStruct)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(string(data))
	// Output: {"tree":{"name":"root","kids":[{"name":"child1","kids":null,"cl_weight":0,"touches":10,"min_t":0,"max_t":0,"mean_t":0},{"name":"child2","kids":null,"cl_weight":0,"touches":20,"min_t":0,"max_t":0,"mean_t":0}],"cl_weight":0,"touches":0,"min_t":0,"max_t":0,"mean_t":0},"username":"agl"}
}
```

**假设的输入与输出 (针对 `ExampleMarshal`):**

* **输入 (Go 结构体 `codeStruct`):**
  ```go
  codeResponse{
      Username: "agl",
      Tree: &codeNode{
          Name: "root",
          Kids: []*codeNode{
              {Name: "child1", Touches: 10},
              {Name: "child2", Touches: 20},
          },
      },
  }
  ```

* **输出 (JSON 字符串):**
  ```json
  {"tree":{"name":"root","kids":[{"name":"child1","kids":null,"cl_weight":0,"touches":10,"min_t":0,"max_t":0,"mean_t":0},{"name":"child2","kids":null,"cl_weight":0,"touches":20,"min_t":0,"max_t":0,"mean_t":0}],"cl_weight":0,"touches":0,"min_t":0,"max_t":0,"mean_t":0},"username":"agl"}
  ```

**命令行参数的具体处理:**

这个 `bench_test.go` 文件本身不处理命令行参数。 它的作用是提供可执行的基准测试。 这些测试通常通过 Go 的 `testing` 包来运行，使用的命令行工具是 `go test`。

要运行这些基准测试，你需要在包含此文件的目录下打开终端，然后执行以下命令：

```bash
go test -bench=. ./encoding/json
```

* **`-bench=.`**:  这个标志告诉 `go test` 运行当前目录及其子目录下的所有基准测试函数（函数名以 `Benchmark` 开头）。你可以用更具体的正则表达式来选择要运行的基准测试，例如 `-bench=BenchmarkCodeMarshal` 只运行 `BenchmarkCodeMarshal` 函数。
* **`./encoding/json`**:  指定要测试的包的路径。

`go test` 命令会执行这些基准测试，并输出每个测试的执行次数和每次操作的平均耗时等信息。例如：

```
goos: linux
goarch: amd64
pkg: encoding/json
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkCodeEncoder-20         15609             76133 ns/op          9047 B/op        123 allocs/op
BenchmarkCodeEncoderError-20    11542            103483 ns/op          9047 B/op        123 allocs/op
BenchmarkCodeMarshal-20         16979             70460 ns/op          9031 B/op        122 allocs/op
BenchmarkCodeMarshalError-20    12265             97141 ns/op          9031 B/op        122 allocs/op
...
PASS
ok      encoding/json 11.952s
```

这些输出信息可以帮助开发者了解 `encoding/json` 包的性能瓶颈，并在进行优化时提供数据支持。

**使用者易犯错的点:**

虽然这个文件是测试代码，但理解其内容可以帮助使用者避免在使用 `encoding/json` 包时犯一些错误：

1. **不必要的内存分配:**  观察基准测试的内存分配情况 (`B/op` 和 `allocs/op`) 可以帮助使用者理解哪些操作会产生更多的内存分配。例如，频繁地 `Marshal` 和 `Unmarshal` 小对象可能会带来不小的开销。可以考虑使用 `Encoder` 和 `Decoder` 来处理流式数据，减少内存分配。

2. **性能瓶颈:**  运行这些基准测试可以帮助开发者识别在特定场景下 `encoding/json` 的性能瓶颈。例如，处理包含大量数字或者非常深的嵌套结构的 JSON 数据时，性能可能会下降。

3. **不正确的结构体标签 (`json:""`)**:  虽然基准测试本身不涉及结构体标签的错误使用，但是理解测试中结构体的定义和标签可以帮助使用者正确地定义自己的结构体，以确保 JSON 的正确序列化和反序列化。如果标签不正确，会导致字段无法被正确编码或解码。

   **例子:**

   ```go
   type User struct {
       Name string `json:"username"` // 正确: JSON 字段名为 "username"
       Age  int    // 错误: 没有 json 标签，默认不会被编码或解码
   }

   data := `{"username": "Alice", "Age": 30}`
   var user User
   err := json.Unmarshal([]byte(data), &user)
   if err != nil {
       panic(err)
   }
   fmt.Printf("%+v\n", user) // 输出: {Name:Alice Age:0}  Age 没有被正确反序列化
   ```

   **正确的方式:**

   ```go
   type User struct {
       Name string `json:"username"`
       Age  int    `json:"age"` // 添加 json 标签
   }
   ```

4. **忽略错误处理:**  基准测试中会检查 `Marshal` 和 `Unmarshal` 的返回值，确保没有错误发生。使用者也应该在实际代码中始终检查这些函数的错误返回值，以避免程序出现意外行为。

   **例子:**

   ```go
   data := `invalid json`
   var user User
   err := json.Unmarshal([]byte(data), &user)
   if err != nil {
       fmt.Println("JSON 解析错误:", err) // 应该处理错误
   }
   ```

总而言之，`go/src/encoding/json/bench_test.go` 是一个重要的性能测试文件，它通过各种基准测试来衡量 `encoding/json` 包的效率，并为开发者提供优化 JSON 处理代码的参考。理解其内容可以帮助使用者更好地理解 `encoding/json` 包的工作原理和性能特性，从而避免一些常见的错误。

Prompt: 
```
这是路径为go/src/encoding/json/bench_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Large data benchmark.
// The JSON data is a summary of agl's changes in the
// go, webkit, and chromium open source projects.
// We benchmark converting between the JSON form
// and in-memory data structures.

package json

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type codeResponse struct {
	Tree     *codeNode `json:"tree"`
	Username string    `json:"username"`
}

type codeNode struct {
	Name     string      `json:"name"`
	Kids     []*codeNode `json:"kids"`
	CLWeight float64     `json:"cl_weight"`
	Touches  int         `json:"touches"`
	MinT     int64       `json:"min_t"`
	MaxT     int64       `json:"max_t"`
	MeanT    int64       `json:"mean_t"`
}

var codeJSON []byte
var codeStruct codeResponse

func codeInit() {
	f, err := os.Open("testdata/code.json.gz")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		panic(err)
	}
	data, err := io.ReadAll(gz)
	if err != nil {
		panic(err)
	}

	codeJSON = data

	if err := Unmarshal(codeJSON, &codeStruct); err != nil {
		panic("unmarshal code.json: " + err.Error())
	}

	if data, err = Marshal(&codeStruct); err != nil {
		panic("marshal code.json: " + err.Error())
	}

	if !bytes.Equal(data, codeJSON) {
		println("different lengths", len(data), len(codeJSON))
		for i := 0; i < len(data) && i < len(codeJSON); i++ {
			if data[i] != codeJSON[i] {
				println("re-marshal: changed at byte", i)
				println("orig: ", string(codeJSON[i-10:i+10]))
				println("new: ", string(data[i-10:i+10]))
				break
			}
		}
		panic("re-marshal code.json: different result")
	}
}

func BenchmarkCodeEncoder(b *testing.B) {
	b.ReportAllocs()
	if codeJSON == nil {
		b.StopTimer()
		codeInit()
		b.StartTimer()
	}
	b.RunParallel(func(pb *testing.PB) {
		enc := NewEncoder(io.Discard)
		for pb.Next() {
			if err := enc.Encode(&codeStruct); err != nil {
				b.Fatalf("Encode error: %v", err)
			}
		}
	})
	b.SetBytes(int64(len(codeJSON)))
}

func BenchmarkCodeEncoderError(b *testing.B) {
	b.ReportAllocs()
	if codeJSON == nil {
		b.StopTimer()
		codeInit()
		b.StartTimer()
	}

	// Trigger an error in Marshal with cyclic data.
	type Dummy struct {
		Name string
		Next *Dummy
	}
	dummy := Dummy{Name: "Dummy"}
	dummy.Next = &dummy

	b.RunParallel(func(pb *testing.PB) {
		enc := NewEncoder(io.Discard)
		for pb.Next() {
			if err := enc.Encode(&codeStruct); err != nil {
				b.Fatalf("Encode error: %v", err)
			}
			if _, err := Marshal(dummy); err == nil {
				b.Fatal("Marshal error: got nil, want non-nil")
			}
		}
	})
	b.SetBytes(int64(len(codeJSON)))
}

func BenchmarkCodeMarshal(b *testing.B) {
	b.ReportAllocs()
	if codeJSON == nil {
		b.StopTimer()
		codeInit()
		b.StartTimer()
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Marshal(&codeStruct); err != nil {
				b.Fatalf("Marshal error: %v", err)
			}
		}
	})
	b.SetBytes(int64(len(codeJSON)))
}

func BenchmarkCodeMarshalError(b *testing.B) {
	b.ReportAllocs()
	if codeJSON == nil {
		b.StopTimer()
		codeInit()
		b.StartTimer()
	}

	// Trigger an error in Marshal with cyclic data.
	type Dummy struct {
		Name string
		Next *Dummy
	}
	dummy := Dummy{Name: "Dummy"}
	dummy.Next = &dummy

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Marshal(&codeStruct); err != nil {
				b.Fatalf("Marshal error: %v", err)
			}
			if _, err := Marshal(dummy); err == nil {
				b.Fatal("Marshal error: got nil, want non-nil")
			}
		}
	})
	b.SetBytes(int64(len(codeJSON)))
}

func benchMarshalBytes(n int) func(*testing.B) {
	sample := []byte("hello world")
	// Use a struct pointer, to avoid an allocation when passing it as an
	// interface parameter to Marshal.
	v := &struct {
		Bytes []byte
	}{
		bytes.Repeat(sample, (n/len(sample))+1)[:n],
	}
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := Marshal(v); err != nil {
				b.Fatalf("Marshal error: %v", err)
			}
		}
	}
}

func benchMarshalBytesError(n int) func(*testing.B) {
	sample := []byte("hello world")
	// Use a struct pointer, to avoid an allocation when passing it as an
	// interface parameter to Marshal.
	v := &struct {
		Bytes []byte
	}{
		bytes.Repeat(sample, (n/len(sample))+1)[:n],
	}

	// Trigger an error in Marshal with cyclic data.
	type Dummy struct {
		Name string
		Next *Dummy
	}
	dummy := Dummy{Name: "Dummy"}
	dummy.Next = &dummy

	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := Marshal(v); err != nil {
				b.Fatalf("Marshal error: %v", err)
			}
			if _, err := Marshal(dummy); err == nil {
				b.Fatal("Marshal error: got nil, want non-nil")
			}
		}
	}
}

func BenchmarkMarshalBytes(b *testing.B) {
	b.ReportAllocs()
	// 32 fits within encodeState.scratch.
	b.Run("32", benchMarshalBytes(32))
	// 256 doesn't fit in encodeState.scratch, but is small enough to
	// allocate and avoid the slower base64.NewEncoder.
	b.Run("256", benchMarshalBytes(256))
	// 4096 is large enough that we want to avoid allocating for it.
	b.Run("4096", benchMarshalBytes(4096))
}

func BenchmarkMarshalBytesError(b *testing.B) {
	b.ReportAllocs()
	// 32 fits within encodeState.scratch.
	b.Run("32", benchMarshalBytesError(32))
	// 256 doesn't fit in encodeState.scratch, but is small enough to
	// allocate and avoid the slower base64.NewEncoder.
	b.Run("256", benchMarshalBytesError(256))
	// 4096 is large enough that we want to avoid allocating for it.
	b.Run("4096", benchMarshalBytesError(4096))
}

func BenchmarkMarshalMap(b *testing.B) {
	b.ReportAllocs()
	m := map[string]int{
		"key3": 3,
		"key2": 2,
		"key1": 1,
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Marshal(m); err != nil {
				b.Fatal("Marshal:", err)
			}
		}
	})
}

func BenchmarkCodeDecoder(b *testing.B) {
	b.ReportAllocs()
	if codeJSON == nil {
		b.StopTimer()
		codeInit()
		b.StartTimer()
	}
	b.RunParallel(func(pb *testing.PB) {
		var buf bytes.Buffer
		dec := NewDecoder(&buf)
		var r codeResponse
		for pb.Next() {
			buf.Write(codeJSON)
			// hide EOF
			buf.WriteByte('\n')
			buf.WriteByte('\n')
			buf.WriteByte('\n')
			if err := dec.Decode(&r); err != nil {
				b.Fatalf("Decode error: %v", err)
			}
		}
	})
	b.SetBytes(int64(len(codeJSON)))
}

func BenchmarkUnicodeDecoder(b *testing.B) {
	b.ReportAllocs()
	j := []byte(`"\uD83D\uDE01"`)
	b.SetBytes(int64(len(j)))
	r := bytes.NewReader(j)
	dec := NewDecoder(r)
	var out string
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := dec.Decode(&out); err != nil {
			b.Fatalf("Decode error: %v", err)
		}
		r.Seek(0, 0)
	}
}

func BenchmarkDecoderStream(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	var buf bytes.Buffer
	dec := NewDecoder(&buf)
	buf.WriteString(`"` + strings.Repeat("x", 1000000) + `"` + "\n\n\n")
	var x any
	if err := dec.Decode(&x); err != nil {
		b.Fatalf("Decode error: %v", err)
	}
	ones := strings.Repeat(" 1\n", 300000) + "\n\n\n"
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if i%300000 == 0 {
			buf.WriteString(ones)
		}
		x = nil
		switch err := dec.Decode(&x); {
		case err != nil:
			b.Fatalf("Decode error: %v", err)
		case x != 1.0:
			b.Fatalf("Decode: got %v want 1.0", i)
		}
	}
}

func BenchmarkCodeUnmarshal(b *testing.B) {
	b.ReportAllocs()
	if codeJSON == nil {
		b.StopTimer()
		codeInit()
		b.StartTimer()
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var r codeResponse
			if err := Unmarshal(codeJSON, &r); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
	b.SetBytes(int64(len(codeJSON)))
}

func BenchmarkCodeUnmarshalReuse(b *testing.B) {
	b.ReportAllocs()
	if codeJSON == nil {
		b.StopTimer()
		codeInit()
		b.StartTimer()
	}
	b.RunParallel(func(pb *testing.PB) {
		var r codeResponse
		for pb.Next() {
			if err := Unmarshal(codeJSON, &r); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
	b.SetBytes(int64(len(codeJSON)))
}

func BenchmarkUnmarshalString(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`"hello, world"`)
	b.RunParallel(func(pb *testing.PB) {
		var s string
		for pb.Next() {
			if err := Unmarshal(data, &s); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
}

func BenchmarkUnmarshalFloat64(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`3.14`)
	b.RunParallel(func(pb *testing.PB) {
		var f float64
		for pb.Next() {
			if err := Unmarshal(data, &f); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
}

func BenchmarkUnmarshalInt64(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`3`)
	b.RunParallel(func(pb *testing.PB) {
		var x int64
		for pb.Next() {
			if err := Unmarshal(data, &x); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
}

func BenchmarkUnmarshalMap(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`{"key1":"value1","key2":"value2","key3":"value3"}`)
	b.RunParallel(func(pb *testing.PB) {
		x := make(map[string]string, 3)
		for pb.Next() {
			if err := Unmarshal(data, &x); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
}

func BenchmarkIssue10335(b *testing.B) {
	b.ReportAllocs()
	j := []byte(`{"a":{ }}`)
	b.RunParallel(func(pb *testing.PB) {
		var s struct{}
		for pb.Next() {
			if err := Unmarshal(j, &s); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
}

func BenchmarkIssue34127(b *testing.B) {
	b.ReportAllocs()
	j := struct {
		Bar string `json:"bar,string"`
	}{
		Bar: `foobar`,
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Marshal(&j); err != nil {
				b.Fatalf("Marshal error: %v", err)
			}
		}
	})
}

func BenchmarkUnmapped(b *testing.B) {
	b.ReportAllocs()
	j := []byte(`{"s": "hello", "y": 2, "o": {"x": 0}, "a": [1, 99, {"x": 1}]}`)
	b.RunParallel(func(pb *testing.PB) {
		var s struct{}
		for pb.Next() {
			if err := Unmarshal(j, &s); err != nil {
				b.Fatalf("Unmarshal error: %v", err)
			}
		}
	})
}

func BenchmarkTypeFieldsCache(b *testing.B) {
	b.ReportAllocs()
	var maxTypes int = 1e6
	if testenv.Builder() != "" {
		maxTypes = 1e3 // restrict cache sizes on builders
	}

	// Dynamically generate many new types.
	types := make([]reflect.Type, maxTypes)
	fs := []reflect.StructField{{
		Type:  reflect.TypeFor[string](),
		Index: []int{0},
	}}
	for i := range types {
		fs[0].Name = fmt.Sprintf("TypeFieldsCache%d", i)
		types[i] = reflect.StructOf(fs)
	}

	// clearClear clears the cache. Other JSON operations, must not be running.
	clearCache := func() {
		fieldCache = sync.Map{}
	}

	// MissTypes tests the performance of repeated cache misses.
	// This measures the time to rebuild a cache of size nt.
	for nt := 1; nt <= maxTypes; nt *= 10 {
		ts := types[:nt]
		b.Run(fmt.Sprintf("MissTypes%d", nt), func(b *testing.B) {
			nc := runtime.GOMAXPROCS(0)
			for i := 0; i < b.N; i++ {
				clearCache()
				var wg sync.WaitGroup
				for j := 0; j < nc; j++ {
					wg.Add(1)
					go func(j int) {
						for _, t := range ts[(j*len(ts))/nc : ((j+1)*len(ts))/nc] {
							cachedTypeFields(t)
						}
						wg.Done()
					}(j)
				}
				wg.Wait()
			}
		})
	}

	// HitTypes tests the performance of repeated cache hits.
	// This measures the average time of each cache lookup.
	for nt := 1; nt <= maxTypes; nt *= 10 {
		// Pre-warm a cache of size nt.
		clearCache()
		for _, t := range types[:nt] {
			cachedTypeFields(t)
		}
		b.Run(fmt.Sprintf("HitTypes%d", nt), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					cachedTypeFields(types[0])
				}
			})
		})
	}
}

func BenchmarkEncodeMarshaler(b *testing.B) {
	b.ReportAllocs()

	m := struct {
		A int
		B RawMessage
	}{}

	b.RunParallel(func(pb *testing.PB) {
		enc := NewEncoder(io.Discard)

		for pb.Next() {
			if err := enc.Encode(&m); err != nil {
				b.Fatalf("Encode error: %v", err)
			}
		}
	})
}

func BenchmarkEncoderEncode(b *testing.B) {
	b.ReportAllocs()
	type T struct {
		X, Y string
	}
	v := &T{"foo", "bar"}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := NewEncoder(io.Discard).Encode(v); err != nil {
				b.Fatalf("Encode error: %v", err)
			}
		}
	})
}

func BenchmarkNumberIsValid(b *testing.B) {
	s := "-61657.61667E+61673"
	for i := 0; i < b.N; i++ {
		isValidNumber(s)
	}
}

func BenchmarkNumberIsValidRegexp(b *testing.B) {
	var jsonNumberRegexp = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`)
	s := "-61657.61667E+61673"
	for i := 0; i < b.N; i++ {
		jsonNumberRegexp.MatchString(s)
	}
}

func BenchmarkUnmarshalNumber(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`"-61657.61667E+61673"`)
	var number Number
	for i := 0; i < b.N; i++ {
		if err := Unmarshal(data, &number); err != nil {
			b.Fatal("Unmarshal:", err)
		}
	}
}

"""



```