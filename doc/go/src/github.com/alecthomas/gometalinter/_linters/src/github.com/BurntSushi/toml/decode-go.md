Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - What is the Goal?**

The first step is to quickly read through the code and understand its purpose within the larger context of TOML processing. The package name `toml` and the function names like `Unmarshal`, `Decode`, `DecodeFile`, `DecodeReader`, `PrimitiveDecode` strongly suggest this code is responsible for *decoding* TOML data into Go data structures.

**2. Identifying Core Functionalities:**

Next, focus on the key functions and types defined in the snippet:

* **`Unmarshal`**:  This seems like a high-level function for decoding TOML from a byte slice.
* **`Decode`**:  Similar to `Unmarshal`, but takes a string as input and returns `MetaData`. This suggests it's the core decoding logic.
* **`DecodeFile`**: Decodes TOML from a file.
* **`DecodeReader`**: Decodes TOML from an `io.Reader`.
* **`Primitive`**:  This is interesting. It seems to be a way to hold TOML values without immediately decoding them. The comments hint at optimization and runtime type determination.
* **`PrimitiveDecode`**:  A way to decode a `Primitive` value into a Go type.
* **`MetaData`**:  This struct appears to hold information about the decoding process, potentially about which keys were decoded.
* **`Unmarshaler`**: An interface that allows custom decoding logic for specific Go types.
* **Helper functions**:  `e`, `rvalue`, `indirect`, `isUnifiable`, `badtype`. These support the main decoding functions.
* **`unify...` functions**:  These functions (e.g., `unifyStruct`, `unifyMap`, `unifyString`) seem to handle the actual conversion of TOML data to different Go types.

**3. Dissecting Key Functions - How do they work?**

Now, let's analyze the more complex functions in detail:

* **`Unmarshal`**: It simply calls `Decode` after converting the byte slice to a string. It's a convenience function.
* **`Decode`**:
    * Takes TOML `data` (string) and a pointer `v` to the Go data structure.
    * Performs basic error checking (pointer, nil).
    * Calls `parse(data)` (not shown in the snippet, but we can infer it parses the TOML string into an intermediate representation).
    * Creates a `MetaData` struct.
    * Calls `md.unify(p.mapping, indirect(rv))` - This is the core decoding logic, attempting to "unify" the parsed TOML data with the structure of the Go value.
* **`Primitive` and `PrimitiveDecode`**:  The comments are crucial here. `Primitive` holds undecoded data. `PrimitiveDecode` takes a `Primitive` and a Go value and tries to decode the stored data into it. The `MetaData` interaction is important – it tracks which keys are decoded.
* **`DecodeFile` and `DecodeReader`**: They are wrappers around `Decode` that handle reading the TOML data from a file or reader.
* **`unify`**: This is the heart of the decoding. It uses a `switch` statement on the kind of the Go value (`rv.Kind()`) to determine how to handle the TOML data. It also handles special cases like `Primitive`, `Unmarshaler`, and `TextUnmarshaler`. The recursive calls within `unify` (e.g., for nested structs or maps) are important to note.

**4. Inferring Go Language Features:**

Based on the code, we can identify the Go features being used:

* **Reflection (`reflect` package)**: Used extensively to inspect the type and structure of the Go values at runtime. This is essential for generic decoding.
* **Interfaces (`Unmarshaler`, `TextUnmarshaler`)**:  Allow custom decoding behavior.
* **Pointers**: Used to modify the passed-in Go value in the `Decode` functions.
* **Error handling (`error` interface)**:  Standard Go error handling is used throughout.
* **String manipulation (`strings` package)**: Used for case-insensitive field matching.
* **Time handling (`time` package)**:  Specific support for decoding TOML datetimes.
* **Input/Output (`io` package, `ioutil` package)**: For reading TOML data from files and readers.

**5. Constructing Examples and Scenarios:**

To illustrate the functionality, create simple Go structs and corresponding TOML examples:

* **Basic Struct**: Show how a TOML table maps to a Go struct.
* **Nested Struct**: Demonstrate handling of nested tables.
* **Array of Tables**: Show mapping to a slice of structs.
* **Primitive**: Illustrate how to use `Primitive` to delay decoding.
* **Unmarshaler**: Create a custom type that implements `Unmarshaler`.

**6. Identifying Potential Pitfalls:**

Think about common mistakes users might make:

* **Passing a non-pointer to `Decode`**: The code explicitly checks for this.
* **Case sensitivity of struct fields**: While case-insensitive matching is present, it's good to point out the preference for exact matches.
* **Unexported fields**:  TOML cannot be decoded into unexported struct fields.
* **Type mismatches**:  Trying to decode a TOML string into a Go integer, for example.
* **Understanding `Primitive`**: Users might misunderstand that `Primitive` just *holds* the data and needs to be explicitly decoded later.

**7. Considering Command-Line Arguments (If Applicable):**

In *this specific snippet*, there's no direct handling of command-line arguments. The `DecodeFile` function takes a file path, but that's a file path, not a command-line argument. If the larger `gometalinter` tool used this, it would handle command-line arguments separately to specify the TOML configuration file.

**8. Structuring the Answer:**

Finally, organize the information into a clear and logical structure using the requested headings (Functionality, Go Feature Implementation, Code Examples, Command-Line Arguments, Common Mistakes). Use clear and concise language, and provide illustrative code examples.

This systematic approach allows for a comprehensive understanding of the code snippet and the ability to answer the user's request effectively. The key is to start with a high-level understanding and then progressively drill down into the details of each function and concept.
这段代码是 Go 语言 TOML 解析库 `BurntSushi/toml` 中负责**将 TOML 数据解码到 Go 语言数据结构**的核心部分。它实现了将 TOML 格式的字符串、文件或 `io.Reader` 中的数据解析并填充到用户提供的 Go 变量中。

以下是它的主要功能：

1. **将 TOML 数据解码到 Go 结构体或 Map:**
   - `Unmarshal(p []byte, v interface{}) error`:  接收一个字节切片 `p` (包含 TOML 数据) 和一个指向 Go 变量的指针 `v`，将 TOML 数据解码到 `v` 指向的结构体或 Map 中。
   - `Decode(data string, v interface{}) (MetaData, error)`: 接收一个 TOML 格式的字符串 `data` 和一个指向 Go 变量的指针 `v`，执行解码操作，并返回包含解码元数据的 `MetaData` 结构体和可能发生的错误。
   - `DecodeFile(fpath string, v interface{}) (MetaData, error)`:  接收一个文件路径 `fpath` 和一个指向 Go 变量的指针 `v`，读取文件内容并将其作为 TOML 数据进行解码。
   - `DecodeReader(r io.Reader, v interface{}) (MetaData, error)`: 接收一个 `io.Reader` 接口 `r` 和一个指向 Go 变量的指针 `v`，从 `reader` 中读取所有数据并将其作为 TOML 数据进行解码。

2. **支持 `Unmarshaler` 接口:** 如果 Go 变量实现了 `Unmarshaler` 接口，解码器会调用其 `UnmarshalTOML` 方法来执行自定义的解码逻辑。

3. **支持 `Primitive` 类型延迟解码:**
   - 提供了 `Primitive` 结构体，允许将 TOML 值暂时存储为未解码的原始形式。
   - `PrimitiveDecode(primValue Primitive, v interface{}) error` 和 `(md *MetaData).PrimitiveDecode(primValue Primitive, v interface{}) error` 用于将 `Primitive` 类型的值解码到指定的 Go 变量。这在需要运行时确定 TOML 数据类型的情况下很有用。

4. **处理不同的 TOML 数据类型到 Go 类型的映射:**
   - TOML 的哈希表 (table) 映射到 Go 的结构体或 Map。
   - TOML 的数组表格 (array of tables) 映射到 Go 的结构体切片或 Map 切片。
   - TOML 的日期时间映射到 Go 的 `time.Time` 类型。
   - 其他 TOML 类型（浮点数、字符串、整数、布尔值和数组）映射到相应的 Go 类型。

5. **支持结构体标签 (struct tag) `toml`:**  可以使用 `toml` 标签来指定 TOML 键与结构体字段的映射关系，允许字段名与 TOML 键名不完全一致。

6. **提供元数据 (MetaData):**  `Decode` 系列函数返回 `MetaData` 结构体，其中包含了解码过程的元信息，例如哪些键被解码了，哪些键未被解码。

7. **处理实现了 `encoding.TextUnmarshaler` 接口的类型:** 如果 Go 类型实现了 `encoding.TextUnmarshaler` 接口，TOML 的基本类型（字符串、数字、布尔值、日期时间）会被转换为字节切片并传递给该类型的 `UnmarshalText` 方法。

8. **类型统一 (Unification):**  `unify` 系列函数负责将 TOML 的数据类型与 Go 的数据类型进行匹配和转换，确保类型兼容。

**Go 语言功能实现举例：**

```go
package main

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Title   string
	Owner   OwnerInfo
	Servers map[string]Server
	Ports   []int
	Created time.Time
}

type OwnerInfo struct {
	Name string
	Dob  time.Time
}

type Server struct {
	IP string
	DC string
}

func main() {
	tomlData := `
title = "TOML Example"

[owner]
name = "Tom Preston-Werner"
dob = 1979-05-27T07:32:00Z

[servers]
  [servers.alpha]
  ip = "10.0.0.1"
  dc = "eqdc10"

  [servers.beta]
  ip = "10.0.0.2"
  dc = "eqdc11"

ports = [ 8001, 8001, 8002 ]

created = 2023-10-27T10:00:00Z
`

	var config Config
	_, err := toml.Decode(tomlData, &config)
	if err != nil {
		fmt.Println("Error decoding TOML:", err)
		return
	}

	fmt.Printf("Title: %s\n", config.Title)
	fmt.Printf("Owner Name: %s\n", config.Owner.Name)
	fmt.Printf("Server Alpha IP: %s\n", config.Servers["alpha"].IP)
	fmt.Printf("Ports: %v\n", config.Ports)
	fmt.Printf("Created At: %v\n", config.Created)
}
```

**假设的输入与输出：**

**输入 (tomlData):**

```toml
title = "TOML Example"

[owner]
name = "Tom Preston-Werner"
dob = 1979-05-27T07:32:00Z

[servers]
  [servers.alpha]
  ip = "10.0.0.1"
  dc = "eqdc10"

  [servers.beta]
  ip = "10.0.0.2"
  dc = "eqdc11"

ports = [ 8001, 8001, 8002 ]

created = 2023-10-27T10:00:00Z
```

**输出 (通过 `fmt.Printf` 打印到控制台):**

```
Title: TOML Example
Owner Name: Tom Preston-Werner
Server Alpha IP: 10.0.0.1
Ports: [8001 8001 8002]
Created At: 2023-10-27 10:00:00 +0000 UTC
```

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。它专注于 TOML 数据的解码。如果需要在命令行中使用 TOML 配置文件，通常会在应用程序的主入口函数中使用 `flag` 包或其他命令行参数解析库来接收文件路径，然后调用 `toml.DecodeFile` 来加载和解析配置文件。

例如：

```go
package main

import (
	"flag"
	"fmt"

	"github.com/BurntSushi/toml"
)

// ... (Config 和其他结构体定义同上)

func main() {
	configFile := flag.String("config", "config.toml", "Path to the TOML configuration file")
	flag.Parse()

	var config Config
	_, err := toml.DecodeFile(*configFile, &config)
	if err != nil {
		fmt.Println("Error decoding TOML file:", err)
		return
	}

	// ... (使用 config 的代码)
	fmt.Println("Loaded configuration from:", *configFile)
	fmt.Println("Title:", config.Title)
}
```

在这个例子中，`-config` 是一个命令行参数，用户可以使用 `go run main.go -config myconfig.toml` 来指定不同的配置文件。`flag.String` 用于定义这个参数，`flag.Parse()` 解析命令行参数，然后 `toml.DecodeFile(*configFile, &config)` 使用解析后的文件路径加载 TOML 数据。

**使用者易犯错的点：**

1. **传递非指针类型的变量给 `Decode` 函数:**  `Decode` 函数的第二个参数需要是指向 Go 变量的指针，这样才能修改变量的值。如果传递的是非指针类型，`Decode` 函数会返回错误。

   ```go
   var config Config
   _, err := toml.Decode(tomlData, config) // 错误：config 是 Config 类型，需要 &config
   if err != nil {
       // ...
   }
   ```

2. **TOML 键名与结构体字段名不匹配:**  默认情况下，`toml` 库会尝试将 TOML 键名与结构体字段名进行精确匹配。如果不匹配，可以使用 `toml` 标签来指定映射关系。

   ```go
   type MyConfig struct {
       MyTitle string `toml:"title"` // 使用标签将 TOML 的 "title" 映射到 MyTitle 字段
   }
   ```

3. **尝试解码到无法导出的结构体字段:**  Go 语言中，只有导出的 (首字母大写) 的结构体字段才能被外部包访问和修改。尝试将 TOML 数据解码到未导出的字段将会失败。

   ```go
   type MyConfig struct {
       title string // 未导出的字段
   }

   var config MyConfig
   _, err := toml.Decode(tomlData, &config) // 可能会因为 title 字段无法设置而出现问题
   ```

4. **类型不匹配:**  如果 TOML 中的数据类型与 Go 结构体中字段的类型不兼容，解码会失败。例如，尝试将 TOML 字符串解码到 Go 的 `int` 字段。

5. **忽略 `MetaData` 的返回值:** `Decode` 系列函数返回 `MetaData`，其中包含了有关解码过程的信息，例如哪些键被成功解码，哪些键未被解码。忽略这个返回值可能会导致用户没有充分了解 TOML 文件的结构。

希望以上解释能够帮助你理解这段 Go 代码的功能和使用方式。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/BurntSushi/toml/decode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package toml

import (
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"reflect"
	"strings"
	"time"
)

func e(format string, args ...interface{}) error {
	return fmt.Errorf("toml: "+format, args...)
}

// Unmarshaler is the interface implemented by objects that can unmarshal a
// TOML description of themselves.
type Unmarshaler interface {
	UnmarshalTOML(interface{}) error
}

// Unmarshal decodes the contents of `p` in TOML format into a pointer `v`.
func Unmarshal(p []byte, v interface{}) error {
	_, err := Decode(string(p), v)
	return err
}

// Primitive is a TOML value that hasn't been decoded into a Go value.
// When using the various `Decode*` functions, the type `Primitive` may
// be given to any value, and its decoding will be delayed.
//
// A `Primitive` value can be decoded using the `PrimitiveDecode` function.
//
// The underlying representation of a `Primitive` value is subject to change.
// Do not rely on it.
//
// N.B. Primitive values are still parsed, so using them will only avoid
// the overhead of reflection. They can be useful when you don't know the
// exact type of TOML data until run time.
type Primitive struct {
	undecoded interface{}
	context   Key
}

// DEPRECATED!
//
// Use MetaData.PrimitiveDecode instead.
func PrimitiveDecode(primValue Primitive, v interface{}) error {
	md := MetaData{decoded: make(map[string]bool)}
	return md.unify(primValue.undecoded, rvalue(v))
}

// PrimitiveDecode is just like the other `Decode*` functions, except it
// decodes a TOML value that has already been parsed. Valid primitive values
// can *only* be obtained from values filled by the decoder functions,
// including this method. (i.e., `v` may contain more `Primitive`
// values.)
//
// Meta data for primitive values is included in the meta data returned by
// the `Decode*` functions with one exception: keys returned by the Undecoded
// method will only reflect keys that were decoded. Namely, any keys hidden
// behind a Primitive will be considered undecoded. Executing this method will
// update the undecoded keys in the meta data. (See the example.)
func (md *MetaData) PrimitiveDecode(primValue Primitive, v interface{}) error {
	md.context = primValue.context
	defer func() { md.context = nil }()
	return md.unify(primValue.undecoded, rvalue(v))
}

// Decode will decode the contents of `data` in TOML format into a pointer
// `v`.
//
// TOML hashes correspond to Go structs or maps. (Dealer's choice. They can be
// used interchangeably.)
//
// TOML arrays of tables correspond to either a slice of structs or a slice
// of maps.
//
// TOML datetimes correspond to Go `time.Time` values.
//
// All other TOML types (float, string, int, bool and array) correspond
// to the obvious Go types.
//
// An exception to the above rules is if a type implements the
// encoding.TextUnmarshaler interface. In this case, any primitive TOML value
// (floats, strings, integers, booleans and datetimes) will be converted to
// a byte string and given to the value's UnmarshalText method. See the
// Unmarshaler example for a demonstration with time duration strings.
//
// Key mapping
//
// TOML keys can map to either keys in a Go map or field names in a Go
// struct. The special `toml` struct tag may be used to map TOML keys to
// struct fields that don't match the key name exactly. (See the example.)
// A case insensitive match to struct names will be tried if an exact match
// can't be found.
//
// The mapping between TOML values and Go values is loose. That is, there
// may exist TOML values that cannot be placed into your representation, and
// there may be parts of your representation that do not correspond to
// TOML values. This loose mapping can be made stricter by using the IsDefined
// and/or Undecoded methods on the MetaData returned.
//
// This decoder will not handle cyclic types. If a cyclic type is passed,
// `Decode` will not terminate.
func Decode(data string, v interface{}) (MetaData, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return MetaData{}, e("Decode of non-pointer %s", reflect.TypeOf(v))
	}
	if rv.IsNil() {
		return MetaData{}, e("Decode of nil %s", reflect.TypeOf(v))
	}
	p, err := parse(data)
	if err != nil {
		return MetaData{}, err
	}
	md := MetaData{
		p.mapping, p.types, p.ordered,
		make(map[string]bool, len(p.ordered)), nil,
	}
	return md, md.unify(p.mapping, indirect(rv))
}

// DecodeFile is just like Decode, except it will automatically read the
// contents of the file at `fpath` and decode it for you.
func DecodeFile(fpath string, v interface{}) (MetaData, error) {
	bs, err := ioutil.ReadFile(fpath)
	if err != nil {
		return MetaData{}, err
	}
	return Decode(string(bs), v)
}

// DecodeReader is just like Decode, except it will consume all bytes
// from the reader and decode it for you.
func DecodeReader(r io.Reader, v interface{}) (MetaData, error) {
	bs, err := ioutil.ReadAll(r)
	if err != nil {
		return MetaData{}, err
	}
	return Decode(string(bs), v)
}

// unify performs a sort of type unification based on the structure of `rv`,
// which is the client representation.
//
// Any type mismatch produces an error. Finding a type that we don't know
// how to handle produces an unsupported type error.
func (md *MetaData) unify(data interface{}, rv reflect.Value) error {

	// Special case. Look for a `Primitive` value.
	if rv.Type() == reflect.TypeOf((*Primitive)(nil)).Elem() {
		// Save the undecoded data and the key context into the primitive
		// value.
		context := make(Key, len(md.context))
		copy(context, md.context)
		rv.Set(reflect.ValueOf(Primitive{
			undecoded: data,
			context:   context,
		}))
		return nil
	}

	// Special case. Unmarshaler Interface support.
	if rv.CanAddr() {
		if v, ok := rv.Addr().Interface().(Unmarshaler); ok {
			return v.UnmarshalTOML(data)
		}
	}

	// Special case. Handle time.Time values specifically.
	// TODO: Remove this code when we decide to drop support for Go 1.1.
	// This isn't necessary in Go 1.2 because time.Time satisfies the encoding
	// interfaces.
	if rv.Type().AssignableTo(rvalue(time.Time{}).Type()) {
		return md.unifyDatetime(data, rv)
	}

	// Special case. Look for a value satisfying the TextUnmarshaler interface.
	if v, ok := rv.Interface().(TextUnmarshaler); ok {
		return md.unifyText(data, v)
	}
	// BUG(burntsushi)
	// The behavior here is incorrect whenever a Go type satisfies the
	// encoding.TextUnmarshaler interface but also corresponds to a TOML
	// hash or array. In particular, the unmarshaler should only be applied
	// to primitive TOML values. But at this point, it will be applied to
	// all kinds of values and produce an incorrect error whenever those values
	// are hashes or arrays (including arrays of tables).

	k := rv.Kind()

	// laziness
	if k >= reflect.Int && k <= reflect.Uint64 {
		return md.unifyInt(data, rv)
	}
	switch k {
	case reflect.Ptr:
		elem := reflect.New(rv.Type().Elem())
		err := md.unify(data, reflect.Indirect(elem))
		if err != nil {
			return err
		}
		rv.Set(elem)
		return nil
	case reflect.Struct:
		return md.unifyStruct(data, rv)
	case reflect.Map:
		return md.unifyMap(data, rv)
	case reflect.Array:
		return md.unifyArray(data, rv)
	case reflect.Slice:
		return md.unifySlice(data, rv)
	case reflect.String:
		return md.unifyString(data, rv)
	case reflect.Bool:
		return md.unifyBool(data, rv)
	case reflect.Interface:
		// we only support empty interfaces.
		if rv.NumMethod() > 0 {
			return e("unsupported type %s", rv.Type())
		}
		return md.unifyAnything(data, rv)
	case reflect.Float32:
		fallthrough
	case reflect.Float64:
		return md.unifyFloat64(data, rv)
	}
	return e("unsupported type %s", rv.Kind())
}

func (md *MetaData) unifyStruct(mapping interface{}, rv reflect.Value) error {
	tmap, ok := mapping.(map[string]interface{})
	if !ok {
		if mapping == nil {
			return nil
		}
		return e("type mismatch for %s: expected table but found %T",
			rv.Type().String(), mapping)
	}

	for key, datum := range tmap {
		var f *field
		fields := cachedTypeFields(rv.Type())
		for i := range fields {
			ff := &fields[i]
			if ff.name == key {
				f = ff
				break
			}
			if f == nil && strings.EqualFold(ff.name, key) {
				f = ff
			}
		}
		if f != nil {
			subv := rv
			for _, i := range f.index {
				subv = indirect(subv.Field(i))
			}
			if isUnifiable(subv) {
				md.decoded[md.context.add(key).String()] = true
				md.context = append(md.context, key)
				if err := md.unify(datum, subv); err != nil {
					return err
				}
				md.context = md.context[0 : len(md.context)-1]
			} else if f.name != "" {
				// Bad user! No soup for you!
				return e("cannot write unexported field %s.%s",
					rv.Type().String(), f.name)
			}
		}
	}
	return nil
}

func (md *MetaData) unifyMap(mapping interface{}, rv reflect.Value) error {
	tmap, ok := mapping.(map[string]interface{})
	if !ok {
		if tmap == nil {
			return nil
		}
		return badtype("map", mapping)
	}
	if rv.IsNil() {
		rv.Set(reflect.MakeMap(rv.Type()))
	}
	for k, v := range tmap {
		md.decoded[md.context.add(k).String()] = true
		md.context = append(md.context, k)

		rvkey := indirect(reflect.New(rv.Type().Key()))
		rvval := reflect.Indirect(reflect.New(rv.Type().Elem()))
		if err := md.unify(v, rvval); err != nil {
			return err
		}
		md.context = md.context[0 : len(md.context)-1]

		rvkey.SetString(k)
		rv.SetMapIndex(rvkey, rvval)
	}
	return nil
}

func (md *MetaData) unifyArray(data interface{}, rv reflect.Value) error {
	datav := reflect.ValueOf(data)
	if datav.Kind() != reflect.Slice {
		if !datav.IsValid() {
			return nil
		}
		return badtype("slice", data)
	}
	sliceLen := datav.Len()
	if sliceLen != rv.Len() {
		return e("expected array length %d; got TOML array of length %d",
			rv.Len(), sliceLen)
	}
	return md.unifySliceArray(datav, rv)
}

func (md *MetaData) unifySlice(data interface{}, rv reflect.Value) error {
	datav := reflect.ValueOf(data)
	if datav.Kind() != reflect.Slice {
		if !datav.IsValid() {
			return nil
		}
		return badtype("slice", data)
	}
	n := datav.Len()
	if rv.IsNil() || rv.Cap() < n {
		rv.Set(reflect.MakeSlice(rv.Type(), n, n))
	}
	rv.SetLen(n)
	return md.unifySliceArray(datav, rv)
}

func (md *MetaData) unifySliceArray(data, rv reflect.Value) error {
	sliceLen := data.Len()
	for i := 0; i < sliceLen; i++ {
		v := data.Index(i).Interface()
		sliceval := indirect(rv.Index(i))
		if err := md.unify(v, sliceval); err != nil {
			return err
		}
	}
	return nil
}

func (md *MetaData) unifyDatetime(data interface{}, rv reflect.Value) error {
	if _, ok := data.(time.Time); ok {
		rv.Set(reflect.ValueOf(data))
		return nil
	}
	return badtype("time.Time", data)
}

func (md *MetaData) unifyString(data interface{}, rv reflect.Value) error {
	if s, ok := data.(string); ok {
		rv.SetString(s)
		return nil
	}
	return badtype("string", data)
}

func (md *MetaData) unifyFloat64(data interface{}, rv reflect.Value) error {
	if num, ok := data.(float64); ok {
		switch rv.Kind() {
		case reflect.Float32:
			fallthrough
		case reflect.Float64:
			rv.SetFloat(num)
		default:
			panic("bug")
		}
		return nil
	}
	return badtype("float", data)
}

func (md *MetaData) unifyInt(data interface{}, rv reflect.Value) error {
	if num, ok := data.(int64); ok {
		if rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64 {
			switch rv.Kind() {
			case reflect.Int, reflect.Int64:
				// No bounds checking necessary.
			case reflect.Int8:
				if num < math.MinInt8 || num > math.MaxInt8 {
					return e("value %d is out of range for int8", num)
				}
			case reflect.Int16:
				if num < math.MinInt16 || num > math.MaxInt16 {
					return e("value %d is out of range for int16", num)
				}
			case reflect.Int32:
				if num < math.MinInt32 || num > math.MaxInt32 {
					return e("value %d is out of range for int32", num)
				}
			}
			rv.SetInt(num)
		} else if rv.Kind() >= reflect.Uint && rv.Kind() <= reflect.Uint64 {
			unum := uint64(num)
			switch rv.Kind() {
			case reflect.Uint, reflect.Uint64:
				// No bounds checking necessary.
			case reflect.Uint8:
				if num < 0 || unum > math.MaxUint8 {
					return e("value %d is out of range for uint8", num)
				}
			case reflect.Uint16:
				if num < 0 || unum > math.MaxUint16 {
					return e("value %d is out of range for uint16", num)
				}
			case reflect.Uint32:
				if num < 0 || unum > math.MaxUint32 {
					return e("value %d is out of range for uint32", num)
				}
			}
			rv.SetUint(unum)
		} else {
			panic("unreachable")
		}
		return nil
	}
	return badtype("integer", data)
}

func (md *MetaData) unifyBool(data interface{}, rv reflect.Value) error {
	if b, ok := data.(bool); ok {
		rv.SetBool(b)
		return nil
	}
	return badtype("boolean", data)
}

func (md *MetaData) unifyAnything(data interface{}, rv reflect.Value) error {
	rv.Set(reflect.ValueOf(data))
	return nil
}

func (md *MetaData) unifyText(data interface{}, v TextUnmarshaler) error {
	var s string
	switch sdata := data.(type) {
	case TextMarshaler:
		text, err := sdata.MarshalText()
		if err != nil {
			return err
		}
		s = string(text)
	case fmt.Stringer:
		s = sdata.String()
	case string:
		s = sdata
	case bool:
		s = fmt.Sprintf("%v", sdata)
	case int64:
		s = fmt.Sprintf("%d", sdata)
	case float64:
		s = fmt.Sprintf("%f", sdata)
	default:
		return badtype("primitive (string-like)", data)
	}
	if err := v.UnmarshalText([]byte(s)); err != nil {
		return err
	}
	return nil
}

// rvalue returns a reflect.Value of `v`. All pointers are resolved.
func rvalue(v interface{}) reflect.Value {
	return indirect(reflect.ValueOf(v))
}

// indirect returns the value pointed to by a pointer.
// Pointers are followed until the value is not a pointer.
// New values are allocated for each nil pointer.
//
// An exception to this rule is if the value satisfies an interface of
// interest to us (like encoding.TextUnmarshaler).
func indirect(v reflect.Value) reflect.Value {
	if v.Kind() != reflect.Ptr {
		if v.CanSet() {
			pv := v.Addr()
			if _, ok := pv.Interface().(TextUnmarshaler); ok {
				return pv
			}
		}
		return v
	}
	if v.IsNil() {
		v.Set(reflect.New(v.Type().Elem()))
	}
	return indirect(reflect.Indirect(v))
}

func isUnifiable(rv reflect.Value) bool {
	if rv.CanSet() {
		return true
	}
	if _, ok := rv.Interface().(TextUnmarshaler); ok {
		return true
	}
	return false
}

func badtype(expected string, data interface{}) error {
	return e("cannot load TOML value of type %T into a Go %s", data, expected)
}

"""



```