Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The core task is to analyze a Go file (`example_test.go` within the `encoding/json` package) and explain its functionality. This means identifying what each function does, how it's used, and potential pitfalls for users.

2. **Initial Scan and Categorization:**  Quickly read through the code, noting the function names starting with `Example`. In Go's testing framework, functions prefixed with `Example` serve as executable documentation. This immediately tells us the purpose: to demonstrate how to use different parts of the `encoding/json` package. We can categorize the examples based on the core `encoding/json` functionalities they illustrate:

    * **Marshalling (Serialization):** Converting Go data structures to JSON. Look for functions involving `json.Marshal` and `json.MarshalIndent`.
    * **Unmarshalling (Deserialization):** Converting JSON to Go data structures. Look for functions involving `json.Unmarshal`.
    * **Streaming Decoding:** Handling JSON data as a stream rather than a single block. Look for `json.NewDecoder`.
    * **Raw JSON Handling:**  Dealing with parts of JSON without immediately parsing them. Look for `json.RawMessage`.
    * **Formatting:**  Controlling the visual representation of JSON. Look for `json.Indent` and `json.MarshalIndent`.
    * **Validation:** Checking if a string is valid JSON. Look for `json.Valid`.
    * **HTML Escaping:**  Handling potentially unsafe HTML characters in JSON. Look for `json.HTMLEscape`.

3. **Detailed Analysis of Each Example Function:**  Go through each `Example` function individually.

    * **`ExampleMarshal()`:**  Observe the creation of a `ColorGroup` struct and the use of `json.Marshal`. The `// Output:` comment is crucial – it shows the expected JSON output. This demonstrates basic struct-to-JSON conversion.

    * **`ExampleUnmarshal()`:** Note the pre-defined JSON string (`jsonBlob`) and the `Animal` struct. `json.Unmarshal` is used to populate a slice of `Animal` structs. The `// Output:` shows the resulting Go struct values. This demonstrates basic JSON-to-struct conversion.

    * **`ExampleDecoder()`:**  The `jsonStream` contains multiple JSON objects separated by newlines. `json.NewDecoder` creates a decoder, and the `for` loop with `dec.Decode(&m)` processes each object. This highlights streaming JSON decoding where multiple independent JSON values exist in a single input.

    * **`ExampleDecoder_Token()`:**  This example uses `dec.Token()` to iterate through the individual tokens (delimiters, strings, numbers, null) in a JSON string. The `dec.More()` call checks if there are more tokens in the current structure. This demonstrates low-level access to the JSON structure.

    * **`ExampleDecoder_Decode_stream()`:** The `jsonStream` is a JSON array of objects. The example manually reads the opening bracket with `dec.Token()`, then uses a `for dec.More()` loop to decode each object in the array, and finally reads the closing bracket. This showcases how to handle streaming *arrays* of JSON objects.

    * **`ExampleRawMessage_unmarshal()`:** This demonstrates the use of `json.RawMessage`. The `Point` field in the `Color` struct is a `json.RawMessage`, allowing the program to defer parsing the `Point` data until the `Space` field is known. A `switch` statement then handles unmarshalling the `Point` based on the `Space`.

    * **`ExampleRawMessage_marshal()`:**  Here, `json.RawMessage` is used to insert pre-computed JSON directly into the output when marshalling. This is useful for including pre-formatted JSON or avoiding re-serialization.

    * **`ExampleIndent()`:**  This uses the `json.Indent` function to format an already marshalled JSON byte slice. It adds a prefix and indent string. This shows how to format existing JSON data.

    * **`ExampleMarshalIndent()`:**  `json.MarshalIndent` combines marshalling and indenting in one step. It takes prefix and indent strings as arguments. This is a more direct way to get formatted JSON output.

    * **`ExampleValid()`:** This simple example uses `json.Valid` to check if a given byte slice represents valid JSON.

    * **`ExampleHTMLEscape()`:**  `json.HTMLEscape` demonstrates how to escape HTML characters within a JSON string to prevent potential security issues when the JSON is used in a web context.

4. **Synthesize Functionality and Purpose:** Based on the individual example analysis, summarize the overall functionalities demonstrated by the code. This will involve stating that it showcases common JSON encoding and decoding operations, streaming, raw message handling, formatting, and validation. Also, state the main purpose is to provide usage examples for the `encoding/json` package.

5. **Infer Go Language Features:** Identify the core Go features being demonstrated. This includes:

    * **Structs and Data Structures:** How Go structs map to JSON objects.
    * **Slices:** How Go slices map to JSON arrays.
    * **Interfaces:**  Implicitly used with `io.Reader` in `json.NewDecoder`.
    * **Pointers:** Used extensively with `json.Unmarshal` and `json.Decode` to modify the underlying data.
    * **Error Handling:** The consistent use of `if err != nil`.
    * **Type Switching:**  Used in `ExampleRawMessage_unmarshal`.

6. **Provide Code Examples (if applicable):** For the core functionalities like marshalling and unmarshalling, provide simple, illustrative Go code examples, including input data and expected output. This reinforces understanding.

7. **Address Command-Line Arguments:** In this specific code, there are *no* command-line arguments being processed. It's important to explicitly state this.

8. **Identify Common User Errors:**  Think about the common mistakes developers might make when using the `encoding/json` package. Examples include:

    * **Incorrect struct field tags:** Leading to fields not being serialized/deserialized.
    * **Case sensitivity:** Go's JSON marshalling is case-sensitive by default.
    * **Forgetting to pass a pointer to `Unmarshal` and `Decode`:** Resulting in no changes to the target variable.
    * **Incorrectly handling streaming data:** Not checking for `io.EOF`.

9. **Structure the Answer:** Organize the information logically with clear headings and bullet points for readability. Use Chinese as requested.

10. **Review and Refine:** Read through the entire answer to ensure accuracy, clarity, and completeness. Make sure the code examples are correct and the explanations are easy to understand. Check for any missed details or potential ambiguities.
这段代码是 Go 语言标准库 `encoding/json` 包的一部分，具体来说是 `example_test.go` 文件，它包含了一系列示例函数（以 `Example` 开头），用于演示 `encoding/json` 包的各种功能。

以下是它所展示的主要功能：

1. **JSON 序列化 (Marshalling):** 将 Go 语言的数据结构（如结构体、切片、Map 等）转换为 JSON 格式的字符串。
   - `ExampleMarshal()` 展示了如何使用 `json.Marshal()` 函数将一个 `ColorGroup` 结构体序列化为 JSON 字符串。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   type ColorGroup struct {
       ID     int    `json:"ID"`
       Name   string `json:"Name"`
       Colors []string `json:"Colors"`
   }

   func main() {
       group := ColorGroup{
           ID:     1,
           Name:   "Reds",
           Colors: []string{"Crimson", "Red", "Ruby", "Maroon"},
       }
       b, err := json.Marshal(group)
       if err != nil {
           fmt.Println("error:", err)
           return
       }
       fmt.Println(string(b))
       // 假设输入如上 group， 输出将会是:
       // {"ID":1,"Name":"Reds","Colors":["Crimson","Red","Ruby","Maroon"]}
   }
   ```

2. **JSON 反序列化 (Unmarshalling):** 将 JSON 格式的字符串转换为 Go 语言的数据结构。
   - `ExampleUnmarshal()` 展示了如何使用 `json.Unmarshal()` 函数将一个 JSON 字符串切片反序列化为一个 `Animal` 结构体的切片。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   type Animal struct {
       Name  string `json:"Name"`
       Order string `json:"Order"`
   }

   func main() {
       var jsonBlob = []byte(`[
           {"Name": "Platypus", "Order": "Monotremata"},
           {"Name": "Quoll",    "Order": "Dasyuromorphia"}
       ]`)
       var animals []Animal
       err := json.Unmarshal(jsonBlob, &animals)
       if err != nil {
           fmt.Println("error:", err)
           return
       }
       fmt.Printf("%+v\n", animals)
       // 假设输入如上 jsonBlob， 输出将会是:
       // [{Name:Platypus Order:Monotremata} {Name:Quoll Order:Dasyuromorphia}]
   }
   ```

3. **JSON 流式解码 (Decoder):**  使用 `json.NewDecoder` 处理 JSON 数据流，可以逐个解码多个 JSON 对象。
   - `ExampleDecoder()` 展示了如何使用 `json.NewDecoder` 从一个包含多个 JSON 对象的字符串读取器中逐个解码 `Message` 结构体。
   - `ExampleDecoder_Token()` 展示了如何使用 `json.NewDecoder` 的 `Token()` 方法逐个读取 JSON 数据流中的 Token (例如: `}`, `{`, `[`, `]`, 字符串, 数字, `null`)。
   - `ExampleDecoder_Decode_stream()` 展示了如何使用 `json.NewDecoder` 解码一个 JSON 数组流，其中数组的每个元素都是一个 JSON 对象。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
       "log"
       "strings"
   )

   type Message struct {
       Name string `json:"Name"`
       Text string `json:"Text"`
   }

   func main() {
       const jsonStream = `
           {"Name": "Ed", "Text": "Knock knock."}
           {"Name": "Sam", "Text": "Who's there?"}
       `
       dec := json.NewDecoder(strings.NewReader(jsonStream))
       for {
           var m Message
           if err := dec.Decode(&m); err != nil {
               if err.Error() == "EOF" {
                   break
               }
               log.Fatal(err)
           }
           fmt.Printf("%s: %s\n", m.Name, m.Text)
       }
       // 假设输入如上 jsonStream， 输出将会是:
       // Ed: Knock knock.
       // Sam: Who's there?
   }
   ```

4. **`json.RawMessage` 的使用:**  用于延迟解析部分 JSON 数据，或者在序列化时插入预先计算好的 JSON 片段。
   - `ExampleRawMessage_unmarshal()` 展示了如何使用 `json.RawMessage` 延迟解析 JSON 数据中的一部分，直到确定了需要解析成的具体类型。
   - `ExampleRawMessage_marshal()` 展示了如何在序列化时使用 `json.RawMessage` 插入预先计算好的 JSON 数据。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
       "log"
   )

   type Color struct {
       Space string          `json:"Space"`
       Point json.RawMessage `json:"Point"` // 延迟解析
   }
   type RGB struct {
       R uint8 `json:"R"`
       G uint8 `json:"G"`
       B uint8 `json:"B"`
   }

   func main() {
       var j = []byte(`{"Space": "RGB", "Point": {"R": 100, "G": 200, "B": 250}}`)
       var color Color
       err := json.Unmarshal(j, &color)
       if err != nil {
           log.Fatalln("error:", err)
       }

       var rgb RGB
       err = json.Unmarshal(color.Point, &rgb)
       if err != nil {
           log.Fatalln("error:", err)
       }
       fmt.Printf("%+v\n", rgb)
       // 假设输入如上 j， 输出将会是:
       // {R:100 G:200 B:250}
   }
   ```

5. **JSON 格式化 (Indentation):**  使用 `json.Indent` 和 `json.MarshalIndent` 函数格式化 JSON 输出，使其更易读。
   - `ExampleIndent()` 展示了如何使用 `json.Indent()` 函数对已有的 JSON 数据进行缩进格式化。
   - `ExampleMarshalIndent()` 展示了如何使用 `json.MarshalIndent()` 函数在序列化时直接生成带缩进的 JSON 数据。

   ```go
   package main

   import (
       "bytes"
       "encoding/json"
       "fmt"
       "log"
   )

   type Road struct {
       Name   string `json:"Name"`
       Number int    `json:"Number"`
   }

   func main() {
       roads := []Road{
           {"Diamond Fork", 29},
           {"Sheep Creek", 51},
       }

       b, err := json.Marshal(roads)
       if err != nil {
           log.Fatal(err)
       }

       var out bytes.Buffer
       json.Indent(&out, b, "", "  ") // 使用两个空格缩进
       fmt.Println(out.String())
       // 假设输入如上 roads， 输出将会是:
       // [
       //   {
       //     "Name": "Diamond Fork",
       //     "Number": 29
       //   },
       //   {
       //     "Name": "Sheep Creek",
       //     "Number": 51
       //   }
       // ]
   }
   ```

6. **JSON 有效性验证 (Validation):** 使用 `json.Valid` 函数检查给定的字节切片是否是有效的 JSON 数据。
   - `ExampleValid()` 展示了如何使用 `json.Valid()` 函数检查 JSON 字符串的有效性。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   func main() {
       goodJSON := `{"example": 1}`
       badJSON := `{"example":2:]}}`

       fmt.Println(json.Valid([]byte(goodJSON)), json.Valid([]byte(badJSON)))
       // 输出将会是:
       // true false
   }
   ```

7. **HTML 转义 (HTMLEscape):** 使用 `json.HTMLEscape` 函数转义 JSON 字符串中的 HTML 特殊字符，以防止安全问题。
   - `ExampleHTMLEscape()` 展示了如何使用 `json.HTMLEscape()` 函数转义 JSON 字符串中的 HTML 标签。

   ```go
   package main

   import (
       "bytes"
       "encoding/json"
       "fmt"
   )

   func main() {
       var out bytes.Buffer
       json.HTMLEscape(&out, []byte(`{"Name":"<b>危险内容</b>"}`))
       fmt.Println(out.String())
       // 输出将会是:
       // {"Name":"\u003cb\u003e危险内容\u003c/b\u003e"}
   }
   ```

**代码推理出的 Go 语言功能实现:**

这个文件主要是演示了 `encoding/json` 包的核心功能，包括将 Go 数据结构编码成 JSON 格式以及将 JSON 数据解码成 Go 数据结构。 它展示了如何处理简单的对象、数组、以及更复杂的流式数据。

**命令行参数处理:**

这个示例代码本身并没有涉及到任何命令行参数的处理。它主要是在 Go 的测试环境中运行，通过 `go test` 命令执行。

**使用者易犯错的点:**

1. **结构体字段的导出 (Exported Fields):**  只有导出的字段（首字母大写）才能被 `json.Marshal` 序列化，也只有导出的字段才能被 `json.Unmarshal` 反序列化并赋值。  如果结构体字段是小写字母开头，`encoding/json` 包会忽略这些字段。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   type User struct {
       name string `json:"name"` // 未导出的字段
       Age  int    `json:"age"`  // 导出的字段
   }

   func main() {
       user := User{"Alice", 30}
       b, _ := json.Marshal(user)
       fmt.Println(string(b)) // 输出: {"age":30}， "name" 字段被忽略了

       var newUser User
       jsonString := `{"name": "Bob", "age": 25}`
       json.Unmarshal([]byte(jsonString), &newUser)
       fmt.Printf("%+v\n", newUser) // 输出: {name: Age:25}， "name" 字段没有被赋值
   }
   ```

2. **JSON 标签 (Struct Tags):**  `encoding/json` 包使用结构体标签来自定义 JSON 字段的名称。如果结构体字段没有标签，默认使用字段名作为 JSON 字段名。  容易犯错的是标签拼写错误或格式不正确。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   type Product struct {
       ID    int    `json:"productId"` // 正确的标签
       Name  string `json:"nmae"`      // 错误的标签拼写
       Price float64 `json:"price"`
   }

   func main() {
       product := Product{ID: 1, Name: "Laptop", Price: 1200.00}
       b, _ := json.Marshal(product)
       fmt.Println(string(b)) // 输出: {"productId":1,"nmae":"Laptop","price":1200}， 注意 "nmae"

       var newProduct Product
       jsonString := `{"productId": 2, "Name": "Tablet", "price": 300}`
       json.Unmarshal([]byte(jsonString), &newProduct)
       fmt.Printf("%+v\n", newProduct) // 输出: {ID:2 Name: Price:300}， "Name" 字段没有被反序列化，因为它和标签 "nmae" 不匹配
   }
   ```

3. **`Unmarshal` 的参数必须是指针:**  `json.Unmarshal` 函数的第二个参数必须是指向要填充的 Go 数据结构的指针。如果传递的是值类型，反序列化不会生效。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   type Person struct {
       Name string `json:"name"`
       Age  int    `json:"age"`
   }

   func main() {
       var person Person // 注意这里不是指针
       jsonString := `{"name": "Charlie", "age": 35}`
       err := json.Unmarshal([]byte(jsonString), person) // 错误用法，应该传递 &person
       if err != nil {
           fmt.Println("Error:", err)
       }
       fmt.Printf("%+v\n", person) // 输出: {Name: Age:0}， person 没有被修改
   }
   ```

总而言之，这个 `example_test.go` 文件通过一系列清晰的示例，详细地展示了 `encoding/json` 包在 Go 语言中进行 JSON 数据处理的各种常见用法。

### 提示词
```
这是路径为go/src/encoding/json/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package json_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func ExampleMarshal() {
	type ColorGroup struct {
		ID     int
		Name   string
		Colors []string
	}
	group := ColorGroup{
		ID:     1,
		Name:   "Reds",
		Colors: []string{"Crimson", "Red", "Ruby", "Maroon"},
	}
	b, err := json.Marshal(group)
	if err != nil {
		fmt.Println("error:", err)
	}
	os.Stdout.Write(b)
	// Output:
	// {"ID":1,"Name":"Reds","Colors":["Crimson","Red","Ruby","Maroon"]}
}

func ExampleUnmarshal() {
	var jsonBlob = []byte(`[
	{"Name": "Platypus", "Order": "Monotremata"},
	{"Name": "Quoll",    "Order": "Dasyuromorphia"}
]`)
	type Animal struct {
		Name  string
		Order string
	}
	var animals []Animal
	err := json.Unmarshal(jsonBlob, &animals)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Printf("%+v", animals)
	// Output:
	// [{Name:Platypus Order:Monotremata} {Name:Quoll Order:Dasyuromorphia}]
}

// This example uses a Decoder to decode a stream of distinct JSON values.
func ExampleDecoder() {
	const jsonStream = `
	{"Name": "Ed", "Text": "Knock knock."}
	{"Name": "Sam", "Text": "Who's there?"}
	{"Name": "Ed", "Text": "Go fmt."}
	{"Name": "Sam", "Text": "Go fmt who?"}
	{"Name": "Ed", "Text": "Go fmt yourself!"}
`
	type Message struct {
		Name, Text string
	}
	dec := json.NewDecoder(strings.NewReader(jsonStream))
	for {
		var m Message
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %s\n", m.Name, m.Text)
	}
	// Output:
	// Ed: Knock knock.
	// Sam: Who's there?
	// Ed: Go fmt.
	// Sam: Go fmt who?
	// Ed: Go fmt yourself!
}

// This example uses a Decoder to decode a stream of distinct JSON values.
func ExampleDecoder_Token() {
	const jsonStream = `
	{"Message": "Hello", "Array": [1, 2, 3], "Null": null, "Number": 1.234}
`
	dec := json.NewDecoder(strings.NewReader(jsonStream))
	for {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%T: %v", t, t)
		if dec.More() {
			fmt.Printf(" (more)")
		}
		fmt.Printf("\n")
	}
	// Output:
	// json.Delim: { (more)
	// string: Message (more)
	// string: Hello (more)
	// string: Array (more)
	// json.Delim: [ (more)
	// float64: 1 (more)
	// float64: 2 (more)
	// float64: 3
	// json.Delim: ] (more)
	// string: Null (more)
	// <nil>: <nil> (more)
	// string: Number (more)
	// float64: 1.234
	// json.Delim: }
}

// This example uses a Decoder to decode a streaming array of JSON objects.
func ExampleDecoder_Decode_stream() {
	const jsonStream = `
	[
		{"Name": "Ed", "Text": "Knock knock."},
		{"Name": "Sam", "Text": "Who's there?"},
		{"Name": "Ed", "Text": "Go fmt."},
		{"Name": "Sam", "Text": "Go fmt who?"},
		{"Name": "Ed", "Text": "Go fmt yourself!"}
	]
`
	type Message struct {
		Name, Text string
	}
	dec := json.NewDecoder(strings.NewReader(jsonStream))

	// read open bracket
	t, err := dec.Token()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%T: %v\n", t, t)

	// while the array contains values
	for dec.More() {
		var m Message
		// decode an array value (Message)
		err := dec.Decode(&m)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%v: %v\n", m.Name, m.Text)
	}

	// read closing bracket
	t, err = dec.Token()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%T: %v\n", t, t)

	// Output:
	// json.Delim: [
	// Ed: Knock knock.
	// Sam: Who's there?
	// Ed: Go fmt.
	// Sam: Go fmt who?
	// Ed: Go fmt yourself!
	// json.Delim: ]
}

// This example uses RawMessage to delay parsing part of a JSON message.
func ExampleRawMessage_unmarshal() {
	type Color struct {
		Space string
		Point json.RawMessage // delay parsing until we know the color space
	}
	type RGB struct {
		R uint8
		G uint8
		B uint8
	}
	type YCbCr struct {
		Y  uint8
		Cb int8
		Cr int8
	}

	var j = []byte(`[
	{"Space": "YCbCr", "Point": {"Y": 255, "Cb": 0, "Cr": -10}},
	{"Space": "RGB",   "Point": {"R": 98, "G": 218, "B": 255}}
]`)
	var colors []Color
	err := json.Unmarshal(j, &colors)
	if err != nil {
		log.Fatalln("error:", err)
	}

	for _, c := range colors {
		var dst any
		switch c.Space {
		case "RGB":
			dst = new(RGB)
		case "YCbCr":
			dst = new(YCbCr)
		}
		err := json.Unmarshal(c.Point, dst)
		if err != nil {
			log.Fatalln("error:", err)
		}
		fmt.Println(c.Space, dst)
	}
	// Output:
	// YCbCr &{255 0 -10}
	// RGB &{98 218 255}
}

// This example uses RawMessage to use a precomputed JSON during marshal.
func ExampleRawMessage_marshal() {
	h := json.RawMessage(`{"precomputed": true}`)

	c := struct {
		Header *json.RawMessage `json:"header"`
		Body   string           `json:"body"`
	}{Header: &h, Body: "Hello Gophers!"}

	b, err := json.MarshalIndent(&c, "", "\t")
	if err != nil {
		fmt.Println("error:", err)
	}
	os.Stdout.Write(b)

	// Output:
	// {
	// 	"header": {
	// 		"precomputed": true
	// 	},
	// 	"body": "Hello Gophers!"
	// }
}

func ExampleIndent() {
	type Road struct {
		Name   string
		Number int
	}
	roads := []Road{
		{"Diamond Fork", 29},
		{"Sheep Creek", 51},
	}

	b, err := json.Marshal(roads)
	if err != nil {
		log.Fatal(err)
	}

	var out bytes.Buffer
	json.Indent(&out, b, "=", "\t")
	out.WriteTo(os.Stdout)
	// Output:
	// [
	// =	{
	// =		"Name": "Diamond Fork",
	// =		"Number": 29
	// =	},
	// =	{
	// =		"Name": "Sheep Creek",
	// =		"Number": 51
	// =	}
	// =]
}

func ExampleMarshalIndent() {
	data := map[string]int{
		"a": 1,
		"b": 2,
	}

	b, err := json.MarshalIndent(data, "<prefix>", "<indent>")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
	// Output:
	// {
	// <prefix><indent>"a": 1,
	// <prefix><indent>"b": 2
	// <prefix>}
}

func ExampleValid() {
	goodJSON := `{"example": 1}`
	badJSON := `{"example":2:]}}`

	fmt.Println(json.Valid([]byte(goodJSON)), json.Valid([]byte(badJSON)))
	// Output:
	// true false
}

func ExampleHTMLEscape() {
	var out bytes.Buffer
	json.HTMLEscape(&out, []byte(`{"Name":"<b>HTML content</b>"}`))
	out.WriteTo(os.Stdout)
	// Output:
	//{"Name":"\u003cb\u003eHTML content\u003c/b\u003e"}
}
```