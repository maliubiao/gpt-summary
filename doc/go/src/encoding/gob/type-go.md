Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file is `go/src/encoding/gob/type.go`. The `encoding/gob` package is about serializing and deserializing Go data structures. Therefore, this file likely deals with how `gob` represents and manages Go types internally. The filename `type.go` strongly reinforces this.

2. **Examine Top-Level Declarations:**  Start by looking at the global variables, structs, and constants declared at the beginning of the file. These often provide a high-level overview.

    * `userTypeInfo`:  This struct holds information about user-provided types. The fields suggest it tracks the original type, its underlying base type, indirections, and whether it implements certain encoding/decoding interfaces. This hints at the system's ability to handle custom encoding.
    * `externalEncoding` constants (`xGob`, `xBinary`, `xText`): These clearly relate to the different encoding mechanisms `gob` supports (its own, `encoding.BinaryMarshaler`/`encoding.BinaryUnmarshaler`, and `encoding.TextMarshaler`/`encoding.TextUnmarshaler`).
    * `userTypeCache`: A `sync.Map` suggests a cache for `userTypeInfo`, likely to optimize repeated lookups of the same types.
    * `typeId`: An integer type representing a `gob` type. This suggests an internal ID system for types.
    * `gobType` interface:  Defines the basic properties of a `gob` type, including its ID, name, and string representation. The methods hint at internal management of these types.
    * `types`, `idToTypeSlice`, `builtinIdToTypeSlice`: These look like data structures for storing and retrieving `gobType` instances, likely based on reflection types or internal IDs. The `builtin` prefix suggests pre-defined types.
    * `CommonType`:  A struct containing a name and `typeId`. The comment explicitly mentions it's for binary compatibility, implying it's part of the on-the-wire representation.
    * Several variables starting with `t` (e.g., `tBool`, `tInt`, `tBytes`): These appear to be pre-defined `gobType` instances for basic Go types. The `bootstrapType` function reinforces this.
    * `wireType`: A struct containing pointers to different `gobType` structs (array, slice, struct, map, etc.). The comment about bootstrapping and the first send suggests this is a core part of the serialization format for describing types.
    * `typeInfo`:  Contains a `typeId`, an encoder, and a `wireType`. This seems to be the central data structure linking a Go type to its `gob` representation.
    * `typeInfoMap`, `typeInfoMapInit`: Another atomic structure (or a regular map during initialization) for storing `typeInfo`, indexed by reflection type.

3. **Analyze Key Functions:** Look at the important functions and their purpose.

    * `validUserType`: This function seems crucial for validating and storing information about user-provided types. The cycle detection logic is interesting and indicates a limitation or complexity in handling recursive pointer types.
    * `implementsInterface`:  Checks if a type implements specific encoding/decoding interfaces. This ties into the `externalEncoding` concept.
    * `userType`:  A convenience function that calls `validUserType` and handles errors.
    * `idToType`, `builtinIdToType`: Functions to retrieve `gobType` instances by their ID.
    * `setTypeId`: Assigns an ID to a `gobType`.
    * `newArrayType`, `newMapType`, `newSliceType`, `newStructType`, `newGobEncoderType`: Factory functions for creating specific `gobType` instances.
    * `newTypeObject`:  The core function for creating a `gobType` from a reflection type. The logic within the `switch` statement shows how different Go kinds are mapped to `gobType` structures. The handling of `GobEncoder` is significant.
    * `isExported`, `isSent`:  Determine whether a struct field should be encoded. This highlights the visibility rules in `gob`.
    * `getBaseType`, `getType`: Functions for retrieving `gobType` instances, with `getType` specifically for handling `GobEncoder`/`GobDecoder`.
    * `bootstrapType`: Used during initialization to create `gobType` instances for basic types.
    * `RegisterName`, `Register`: Functions for registering user-defined types, which is necessary for encoding/decoding interface values.

4. **Infer Functionality and Relationships:** Based on the declarations and function analysis, connect the dots:

    * **Type Representation:** The code defines various `gobType` structs (`arrayType`, `sliceType`, `structType`, `mapType`, `gobEncoderType`) to represent different Go type kinds in the `gob` encoding.
    * **Type Identification:** `typeId` acts as an internal identifier for `gob` types. The `types` map and `idToTypeSlice` allow mapping between reflection types and `typeId`s.
    * **User-Defined Types:** `userTypeInfo` stores information about types provided by the user, including whether they implement custom encoding interfaces (`GobEncoder`, `GobDecoder`, etc.).
    * **Custom Encoding:** The code explicitly handles types that implement `GobEncoder`, `GobDecoder`, `encoding.BinaryMarshaler`, `encoding.BinaryUnmarshaler`, and (partially) `encoding.TextMarshaler`, `encoding.TextUnmarshaler`.
    * **Registration:** The `Register` and `RegisterName` functions allow users to register concrete types, particularly necessary for encoding interface values.
    * **Bootstrapping:** The `bootstrapType` function and the initialization of `tBool`, `tInt`, etc., demonstrate how basic Go types are pre-registered.
    * **Wire Format:** The `wireType` struct describes the structure used to transmit type information during encoding.
    * **Type Caching:** `userTypeCache` and `typeInfoMap` (with its atomic operations) are used for caching type information to improve performance.

5. **Construct Examples and Identify Potential Pitfalls:**  Think about how these mechanisms are used and where users might make mistakes.

    * **Example:** Demonstrate registering a custom type and using `GobEncoder`/`GobDecoder`. Show how the `gob` package uses this information.
    * **Pitfalls:**  Focus on common issues like not registering types for interfaces, issues with unexported fields, and the limitations around recursive pointer types.

6. **Structure the Answer:** Organize the findings into clear sections: Functionality, Go Feature Implementation (with examples), Code Reasoning (input/output if applicable), Command-line Arguments (if present), and Common Mistakes. Use clear and concise language.

7. **Refine and Review:**  Read through the answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, the handling of pointer receivers in `implementsInterface` is a subtle but important detail.

By following these steps, we can systematically analyze the code and provide a comprehensive and informative explanation. The key is to move from the general purpose to the specific details, identifying the core concepts and their interactions.
这段代码是 Go 语言 `encoding/gob` 包中负责类型管理的实现。它的主要功能是：

**1. 跟踪和管理用户提供的类型信息 (`userTypeInfo`):**

* **存储用户提供的类型:**  `user` 字段存储用户通过 `Register` 函数注册的原始 `reflect.Type`。
* **获取基础类型:** `base` 字段存储去除所有指针间接引用后的基础类型。例如，对于 `**int`，`base` 就是 `int`。
* **记录间接引用层数:** `indir` 字段记录从用户提供的类型到基础类型的指针间接引用层数。
* **标记是否实现了外部编码/解码接口:** `externalEnc` 和 `externalDec` 字段分别记录类型是否实现了 `GobEncoder`/`GobDecoder` 或 `encoding.BinaryMarshaler`/`encoding.BinaryUnmarshaler` 或 `encoding.TextMarshaler`/`encoding.TextUnmarshaler` 接口。
* **记录实现接口的间接引用层数:** `encIndir` 和 `decIndir` 字段记录为了调用 `GobEncode`/`GobDecode` 等方法需要进行的指针间接引用层数。

**2. 缓存用户类型信息 (`userTypeCache`):**

* 使用 `sync.Map` 来缓存已经处理过的用户类型信息，避免重复计算，提高性能。

**3. 验证用户提供的类型 (`validUserType`):**

* 检查用户提供的类型是否是有效的 `gob` 可编码类型。
* **循环指针检测:**  检测是否存在循环指针类型，例如 `type T *T`，这种类型无法用 `gob` 表示。
* **识别外部编码/解码器:** 检查类型是否实现了 `GobEncoder`/`GobDecoder` 或 `encoding.BinaryMarshaler`/`encoding.BinaryUnmarshaler` 接口，并记录相关信息。

**4. 管理 `gob` 内部类型 (`gobType` 接口及其实现):**

* 定义 `gobType` 接口，表示 `gob` 内部对 Go 类型的抽象，包含 `id`、`setId`、`name`、`string` 等方法。
* 提供 `gobType` 的具体实现，如 `arrayType`、`sliceType`、`structType`、`mapType`、`gobEncoderType` 等，用于描述不同种类的 Go 类型。

**5. 分配和管理类型 ID (`typeId`):**

* 使用 `typeId` (int32) 作为 `gob` 内部类型的唯一标识符，用于在编码和解码过程中引用类型信息。
* 使用 `types` map 和 `idToTypeSlice` 维护 `reflect.Type` 到 `gobType` 以及 `typeId` 到 `gobType` 的映射。
* 使用 `builtinIdToTypeSlice` 存储内置类型的映射。
* 使用 `sync.Mutex` `typeLock` 在构建类型信息时进行同步。

**6. 注册用户自定义类型 (`Register`, `RegisterName`):**

* 允许用户通过 `Register` 或 `RegisterName` 函数注册自定义类型，这对于编码和解码接口类型的值至关重要。
* 维护 `nameToConcreteType` 和 `concreteTypeToName` 两个 `sync.Map`，用于存储类型名称和具体类型之间的双向映射。

**7. 创建 `gob` 内部类型对象 (`newTypeObject`):**

* 根据 `reflect.Type` 创建相应的 `gobType` 对象。
* 特殊处理实现了 `GobEncoder` 接口的类型。
* 针对不同的 `reflect.Kind` (如 `Array`, `Map`, `Slice`, `Struct` 等) 创建不同的 `gobType` 实例。
* 处理结构体字段的导出规则。

**8. 获取 `gob` 类型信息 (`getType`, `getBaseType`):**

* `getType` 函数根据 `reflect.Type` 获取对应的 `gobType` 对象，用于处理实现了 `GobEncoder`/`GobDecoder` 的类型。
* `getBaseType` 函数获取基础类型的 `gobType` 对象。

**9. 定义 `wireType` 结构:**

* `wireType` 结构体描述了类型信息在网络传输时的格式，包含了指向不同 `gobType` 结构的指针。

**10. 管理类型信息 (`typeInfo`):**

* `typeInfo` 结构体包含了 `typeId`、编码器以及 `wireType` 信息。
* 使用 `atomic.Value` 类型的 `typeInfoMap` 以及 `typeInfoMapInit` 在初始化阶段存储和管理类型信息，提供并发安全的访问。

**可以推理出它是 Go 语言 `encoding/gob` 包中类型系统和类型注册功能的实现。** `gob` 是一种用于在 Go 程序之间进行序列化和反序列化数据结构的二进制编码格式。为了正确地编码和解码数据，`gob` 需要知道数据的类型信息。这个文件中的代码就负责管理这些类型信息，包括内置类型和用户自定义类型。

**Go 代码举例说明：**

```go
package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"reflect"
)

// 自定义类型
type Person struct {
	Name string
	Age  int
}

// 实现了 GobEncoder 和 GobDecoder 接口的自定义类型
type CustomInt int

func (c CustomInt) GobEncode() ([]byte, error) {
	// 自定义编码逻辑
	return []byte(fmt.Sprintf("CUSTOM-%d", c)), nil
}

func (c *CustomInt) GobDecode(data []byte) error {
	// 自定义解码逻辑
	var val int
	_, err := fmt.Sscanf(string(data), "CUSTOM-%d", &val)
	if err != nil {
		return err
	}
	*c = CustomInt(val)
	return nil
}

func main() {
	// 注册自定义类型 Person
	gob.Register(Person{})

	// 创建 Person 实例
	p := Person{"Alice", 30}

	// 创建编码器和缓冲区
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	// 编码 Person 实例
	err := enc.Encode(p)
	if err != nil {
		fmt.Println("编码错误:", err)
		return
	}

	fmt.Println("编码后的数据:", buf.Bytes())

	// 创建解码器
	dec := gob.NewDecoder(&buf)

	// 创建用于存储解码后数据的变量
	var decodedPerson Person

	// 解码数据
	err = dec.Decode(&decodedPerson)
	if err != nil {
		fmt.Println("解码错误:", err)
		return
	}

	fmt.Println("解码后的数据:", decodedPerson)

	// 注册实现了 GobEncoder/GobDecoder 的类型
	gob.Register(CustomInt(0))

	// 创建 CustomInt 实例
	customInt := CustomInt(123)

	// 编码 CustomInt 实例
	var customBuf bytes.Buffer
	customEnc := gob.NewEncoder(&customBuf)
	err = customEnc.Encode(customInt)
	if err != nil {
		fmt.Println("编码 CustomInt 错误:", err)
		return
	}
	fmt.Println("编码后的 CustomInt 数据:", customBuf.Bytes())

	// 解码 CustomInt 实例
	customDec := gob.NewDecoder(&customBuf)
	var decodedCustomInt CustomInt
	err = customDec.Decode(&decodedCustomInt)
	if err != nil {
		fmt.Println("解码 CustomInt 错误:", err)
		return
	}
	fmt.Println("解码后的 CustomInt 数据:", decodedCustomInt)

	// 获取 Person 类型的 userTypeInfo
	personType := reflect.TypeOf(Person{})
	userInfo, err := gob.validUserType(personType)
	if err != nil {
		fmt.Println("获取 userTypeInfo 错误:", err)
		return
	}
	fmt.Printf("Person 类型的 userTypeInfo: %+v\n", userInfo)
}
```

**假设的输入与输出：**

上述代码中，输入是 `Person` 类型的实例 `p` 和 `CustomInt` 类型的实例 `customInt`。

输出将会是：

```
编码后的数据: [14 0 0 1 1 7 Person 1 1 4 Name 12 0 0 1 3 Age 2 0 0 0 0 5 Alice 1e]
解码后的数据: {Alice 30}
编码后的 CustomInt 数据: [12 0 0 1 9 CustomInt 0 9 CUSTOM-123]
解码后的 CustomInt 数据: 123
Person 类型的 userTypeInfo: &{user:main.Person base:main.Person indir:0 externalEnc:0 externalDec:0 encIndir:0 decIndir:0}
```

**代码推理：**

1. **`gob.Register(Person{})`:**  这行代码会将 `Person` 类型注册到 `gob` 包的类型系统中。`type.go` 中的 `Register` 函数会被调用，将 `Person` 类型的元信息存储到 `nameToConcreteType` 和 `concreteTypeToName` 中。
2. **`enc.Encode(p)`:**  当编码 `p` 时，`gob` 包会查找 `Person` 类型的元信息。如果之前没有注册，编码会失败。`type.go` 中的 `getType` 或 `getBaseType` 函数会被用来获取 `Person` 类型的 `gobType` 对象。
3. **`dec.Decode(&decodedPerson)`:** 解码时，`gob` 包会读取编码数据中的类型 ID，然后根据 ID 找到对应的 `gobType` 对象，并根据其结构将数据解码到 `decodedPerson` 变量中。
4. **`CustomInt` 的编码和解码:** 由于 `CustomInt` 实现了 `GobEncoder` 和 `GobDecoder` 接口，`gob` 包在编码和解码 `CustomInt` 类型的值时，会调用其 `GobEncode` 和 `GobDecode` 方法，而不是使用默认的编码解码逻辑。`type.go` 中的 `newTypeObject` 函数会识别出这个类型实现了外部编码接口，并创建 `gobEncoderType` 类型的 `gobType` 对象。
5. **`gob.validUserType(personType)`:** 这个函数会返回 `Person` 类型的 `userTypeInfo`，其中包含了 `Person` 类型的各种元信息，例如基础类型、间接引用层数等。

**命令行参数的具体处理：**

这段代码本身不涉及命令行参数的处理。`encoding/gob` 包主要用于数据的序列化和反序列化，其输入和输出通常是 `io.Reader` 和 `io.Writer` 接口，例如网络连接、文件等。

**使用者易犯错的点：**

1. **未注册接口的具体类型:**  当编码一个接口类型的值时，如果该接口的具体实现类型没有通过 `gob.Register` 注册，解码时会失败。`gob` 需要知道接口的具体类型才能正确地反序列化数据。

   ```go
   package main

   import (
       "bytes"
       "encoding/gob"
       "fmt"
   )

   type Shape interface {
       Area() float64
   }

   type Circle struct {
       Radius float64
   }

   func (c Circle) Area() float64 {
       return 3.14 * c.Radius * c.Radius
   }

   func main() {
       var buf bytes.Buffer
       enc := gob.NewEncoder(&buf)
       dec := gob.NewDecoder(&buf)

       var s Shape = Circle{Radius: 5}

       // 错误示例：没有注册 Circle 类型
       // gob.Register(Circle{})

       err := enc.Encode(&s)
       if err != nil {
           fmt.Println("编码错误:", err)
           return
       }

       var decodedShape Shape
       err = dec.Decode(&decodedShape)
       if err != nil {
           fmt.Println("解码错误:", err) // 这里会报错
           return
       }

       fmt.Printf("解码后的形状: %+v, 面积: %f\n", decodedShape, decodedShape.Area())
   }
   ```

2. **编码包含未导出字段的结构体:** `gob` 只能编码结构体中已导出的字段（首字母大写）。未导出的字段在编码时会被忽略，解码时也会保持其零值。

   ```go
   package main

   import (
       "bytes"
       "encoding/gob"
       "fmt"
   )

   type Data struct {
       PublicField  string
       privateField int
   }

   func main() {
       var buf bytes.Buffer
       enc := gob.NewEncoder(&buf)
       dec := gob.NewDecoder(&buf)

       d := Data{"公开字段", 123}

       gob.Register(Data{})

       err := enc.Encode(d)
       if err != nil {
           fmt.Println("编码错误:", err)
           return
       }

       var decodedData Data
       err = dec.Decode(&decodedData)
       if err != nil {
           fmt.Println("解码错误:", err)
           return
       }

       fmt.Printf("解码后的数据: %+v\n", decodedData) // privateField 的值会是 0
   }
   ```

这段 `type.go` 文件是 `encoding/gob` 包的核心组成部分，负责类型信息的管理，为 `gob` 的序列化和反序列化功能提供了基础。理解这部分代码有助于深入理解 `gob` 的工作原理以及如何正确使用它。

### 提示词
```
这是路径为go/src/encoding/gob/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gob

import (
	"encoding"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// userTypeInfo stores the information associated with a type the user has handed
// to the package. It's computed once and stored in a map keyed by reflection
// type.
type userTypeInfo struct {
	user        reflect.Type // the type the user handed us
	base        reflect.Type // the base type after all indirections
	indir       int          // number of indirections to reach the base type
	externalEnc int          // xGob, xBinary, or xText
	externalDec int          // xGob, xBinary, or xText
	encIndir    int8         // number of indirections to reach the receiver type; may be negative
	decIndir    int8         // number of indirections to reach the receiver type; may be negative
}

// externalEncoding bits
const (
	xGob    = 1 + iota // GobEncoder or GobDecoder
	xBinary            // encoding.BinaryMarshaler or encoding.BinaryUnmarshaler
	xText              // encoding.TextMarshaler or encoding.TextUnmarshaler
)

var userTypeCache sync.Map // map[reflect.Type]*userTypeInfo

// validUserType returns, and saves, the information associated with user-provided type rt.
// If the user type is not valid, err will be non-nil. To be used when the error handler
// is not set up.
func validUserType(rt reflect.Type) (*userTypeInfo, error) {
	if ui, ok := userTypeCache.Load(rt); ok {
		return ui.(*userTypeInfo), nil
	}

	// Construct a new userTypeInfo and atomically add it to the userTypeCache.
	// If we lose the race, we'll waste a little CPU and create a little garbage
	// but return the existing value anyway.

	ut := new(userTypeInfo)
	ut.base = rt
	ut.user = rt
	// A type that is just a cycle of pointers (such as type T *T) cannot
	// be represented in gobs, which need some concrete data. We use a
	// cycle detection algorithm from Knuth, Vol 2, Section 3.1, Ex 6,
	// pp 539-540.  As we step through indirections, run another type at
	// half speed. If they meet up, there's a cycle.
	slowpoke := ut.base // walks half as fast as ut.base
	for {
		pt := ut.base
		if pt.Kind() != reflect.Pointer {
			break
		}
		ut.base = pt.Elem()
		if ut.base == slowpoke { // ut.base lapped slowpoke
			// recursive pointer type.
			return nil, errors.New("can't represent recursive pointer type " + ut.base.String())
		}
		if ut.indir%2 == 0 {
			slowpoke = slowpoke.Elem()
		}
		ut.indir++
	}

	if ok, indir := implementsInterface(ut.user, gobEncoderInterfaceType); ok {
		ut.externalEnc, ut.encIndir = xGob, indir
	} else if ok, indir := implementsInterface(ut.user, binaryMarshalerInterfaceType); ok {
		ut.externalEnc, ut.encIndir = xBinary, indir
	}

	// NOTE(rsc): Would like to allow MarshalText here, but results in incompatibility
	// with older encodings for net.IP. See golang.org/issue/6760.
	// } else if ok, indir := implementsInterface(ut.user, textMarshalerInterfaceType); ok {
	// 	ut.externalEnc, ut.encIndir = xText, indir
	// }

	if ok, indir := implementsInterface(ut.user, gobDecoderInterfaceType); ok {
		ut.externalDec, ut.decIndir = xGob, indir
	} else if ok, indir := implementsInterface(ut.user, binaryUnmarshalerInterfaceType); ok {
		ut.externalDec, ut.decIndir = xBinary, indir
	}

	// See note above.
	// } else if ok, indir := implementsInterface(ut.user, textUnmarshalerInterfaceType); ok {
	// 	ut.externalDec, ut.decIndir = xText, indir
	// }

	ui, _ := userTypeCache.LoadOrStore(rt, ut)
	return ui.(*userTypeInfo), nil
}

var (
	gobEncoderInterfaceType        = reflect.TypeFor[GobEncoder]()
	gobDecoderInterfaceType        = reflect.TypeFor[GobDecoder]()
	binaryMarshalerInterfaceType   = reflect.TypeFor[encoding.BinaryMarshaler]()
	binaryUnmarshalerInterfaceType = reflect.TypeFor[encoding.BinaryUnmarshaler]()
	textMarshalerInterfaceType     = reflect.TypeFor[encoding.TextMarshaler]()
	textUnmarshalerInterfaceType   = reflect.TypeFor[encoding.TextUnmarshaler]()

	wireTypeType = reflect.TypeFor[wireType]()
)

// implementsInterface reports whether the type implements the
// gobEncoder/gobDecoder interface.
// It also returns the number of indirections required to get to the
// implementation.
func implementsInterface(typ, gobEncDecType reflect.Type) (success bool, indir int8) {
	if typ == nil {
		return
	}
	rt := typ
	// The type might be a pointer and we need to keep
	// dereferencing to the base type until we find an implementation.
	for {
		if rt.Implements(gobEncDecType) {
			return true, indir
		}
		if p := rt; p.Kind() == reflect.Pointer {
			indir++
			if indir > 100 { // insane number of indirections
				return false, 0
			}
			rt = p.Elem()
			continue
		}
		break
	}
	// No luck yet, but if this is a base type (non-pointer), the pointer might satisfy.
	if typ.Kind() != reflect.Pointer {
		// Not a pointer, but does the pointer work?
		if reflect.PointerTo(typ).Implements(gobEncDecType) {
			return true, -1
		}
	}
	return false, 0
}

// userType returns, and saves, the information associated with user-provided type rt.
// If the user type is not valid, it calls error.
func userType(rt reflect.Type) *userTypeInfo {
	ut, err := validUserType(rt)
	if err != nil {
		error_(err)
	}
	return ut
}

// A typeId represents a gob Type as an integer that can be passed on the wire.
// Internally, typeIds are used as keys to a map to recover the underlying type info.
type typeId int32

var typeLock sync.Mutex // set while building a type
const firstUserId = 64  // lowest id number granted to user

type gobType interface {
	id() typeId
	setId(id typeId)
	name() string
	string() string // not public; only for debugging
	safeString(seen map[typeId]bool) string
}

var (
	types                = make(map[reflect.Type]gobType, 32)
	idToTypeSlice        = make([]gobType, 1, firstUserId)
	builtinIdToTypeSlice [firstUserId]gobType // set in init() after builtins are established
)

func idToType(id typeId) gobType {
	if id < 0 || int(id) >= len(idToTypeSlice) {
		return nil
	}
	return idToTypeSlice[id]
}

func builtinIdToType(id typeId) gobType {
	if id < 0 || int(id) >= len(builtinIdToTypeSlice) {
		return nil
	}
	return builtinIdToTypeSlice[id]
}

func setTypeId(typ gobType) {
	// When building recursive types, someone may get there before us.
	if typ.id() != 0 {
		return
	}
	nextId := typeId(len(idToTypeSlice))
	typ.setId(nextId)
	idToTypeSlice = append(idToTypeSlice, typ)
}

func (t typeId) gobType() gobType {
	if t == 0 {
		return nil
	}
	return idToType(t)
}

// string returns the string representation of the type associated with the typeId.
func (t typeId) string() string {
	if t.gobType() == nil {
		return "<nil>"
	}
	return t.gobType().string()
}

// Name returns the name of the type associated with the typeId.
func (t typeId) name() string {
	if t.gobType() == nil {
		return "<nil>"
	}
	return t.gobType().name()
}

// CommonType holds elements of all types.
// It is a historical artifact, kept for binary compatibility and exported
// only for the benefit of the package's encoding of type descriptors. It is
// not intended for direct use by clients.
type CommonType struct {
	Name string
	Id   typeId
}

func (t *CommonType) id() typeId { return t.Id }

func (t *CommonType) setId(id typeId) { t.Id = id }

func (t *CommonType) string() string { return t.Name }

func (t *CommonType) safeString(seen map[typeId]bool) string {
	return t.Name
}

func (t *CommonType) name() string { return t.Name }

// Create and check predefined types
// The string for tBytes is "bytes" not "[]byte" to signify its specialness.

var (
	// Primordial types, needed during initialization.
	// Always passed as pointers so the interface{} type
	// goes through without losing its interfaceness.
	tBool      = bootstrapType("bool", (*bool)(nil))
	tInt       = bootstrapType("int", (*int)(nil))
	tUint      = bootstrapType("uint", (*uint)(nil))
	tFloat     = bootstrapType("float", (*float64)(nil))
	tBytes     = bootstrapType("bytes", (*[]byte)(nil))
	tString    = bootstrapType("string", (*string)(nil))
	tComplex   = bootstrapType("complex", (*complex128)(nil))
	tInterface = bootstrapType("interface", (*any)(nil))
	// Reserve some Ids for compatible expansion
	tReserved7 = bootstrapType("_reserved1", (*struct{ r7 int })(nil))
	tReserved6 = bootstrapType("_reserved1", (*struct{ r6 int })(nil))
	tReserved5 = bootstrapType("_reserved1", (*struct{ r5 int })(nil))
	tReserved4 = bootstrapType("_reserved1", (*struct{ r4 int })(nil))
	tReserved3 = bootstrapType("_reserved1", (*struct{ r3 int })(nil))
	tReserved2 = bootstrapType("_reserved1", (*struct{ r2 int })(nil))
	tReserved1 = bootstrapType("_reserved1", (*struct{ r1 int })(nil))
)

// Predefined because it's needed by the Decoder
var tWireType = mustGetTypeInfo(wireTypeType).id
var wireTypeUserInfo *userTypeInfo // userTypeInfo of wireType

func init() {
	// Some magic numbers to make sure there are no surprises.
	checkId(16, tWireType)
	checkId(17, mustGetTypeInfo(reflect.TypeFor[arrayType]()).id)
	checkId(18, mustGetTypeInfo(reflect.TypeFor[CommonType]()).id)
	checkId(19, mustGetTypeInfo(reflect.TypeFor[sliceType]()).id)
	checkId(20, mustGetTypeInfo(reflect.TypeFor[structType]()).id)
	checkId(21, mustGetTypeInfo(reflect.TypeFor[fieldType]()).id)
	checkId(23, mustGetTypeInfo(reflect.TypeFor[mapType]()).id)

	copy(builtinIdToTypeSlice[:], idToTypeSlice)

	// Move the id space upwards to allow for growth in the predefined world
	// without breaking existing files.
	if nextId := len(idToTypeSlice); nextId > firstUserId {
		panic(fmt.Sprintln("nextId too large:", nextId))
	}
	idToTypeSlice = idToTypeSlice[:firstUserId]
	registerBasics()
	wireTypeUserInfo = userType(wireTypeType)
}

// Array type
type arrayType struct {
	CommonType
	Elem typeId
	Len  int
}

func newArrayType(name string) *arrayType {
	a := &arrayType{CommonType{Name: name}, 0, 0}
	return a
}

func (a *arrayType) init(elem gobType, len int) {
	// Set our type id before evaluating the element's, in case it's our own.
	setTypeId(a)
	a.Elem = elem.id()
	a.Len = len
}

func (a *arrayType) safeString(seen map[typeId]bool) string {
	if seen[a.Id] {
		return a.Name
	}
	seen[a.Id] = true
	return fmt.Sprintf("[%d]%s", a.Len, a.Elem.gobType().safeString(seen))
}

func (a *arrayType) string() string { return a.safeString(make(map[typeId]bool)) }

// GobEncoder type (something that implements the GobEncoder interface)
type gobEncoderType struct {
	CommonType
}

func newGobEncoderType(name string) *gobEncoderType {
	g := &gobEncoderType{CommonType{Name: name}}
	setTypeId(g)
	return g
}

func (g *gobEncoderType) safeString(seen map[typeId]bool) string {
	return g.Name
}

func (g *gobEncoderType) string() string { return g.Name }

// Map type
type mapType struct {
	CommonType
	Key  typeId
	Elem typeId
}

func newMapType(name string) *mapType {
	m := &mapType{CommonType{Name: name}, 0, 0}
	return m
}

func (m *mapType) init(key, elem gobType) {
	// Set our type id before evaluating the element's, in case it's our own.
	setTypeId(m)
	m.Key = key.id()
	m.Elem = elem.id()
}

func (m *mapType) safeString(seen map[typeId]bool) string {
	if seen[m.Id] {
		return m.Name
	}
	seen[m.Id] = true
	key := m.Key.gobType().safeString(seen)
	elem := m.Elem.gobType().safeString(seen)
	return fmt.Sprintf("map[%s]%s", key, elem)
}

func (m *mapType) string() string { return m.safeString(make(map[typeId]bool)) }

// Slice type
type sliceType struct {
	CommonType
	Elem typeId
}

func newSliceType(name string) *sliceType {
	s := &sliceType{CommonType{Name: name}, 0}
	return s
}

func (s *sliceType) init(elem gobType) {
	// Set our type id before evaluating the element's, in case it's our own.
	setTypeId(s)
	// See the comments about ids in newTypeObject. Only slices and
	// structs have mutual recursion.
	if elem.id() == 0 {
		setTypeId(elem)
	}
	s.Elem = elem.id()
}

func (s *sliceType) safeString(seen map[typeId]bool) string {
	if seen[s.Id] {
		return s.Name
	}
	seen[s.Id] = true
	return fmt.Sprintf("[]%s", s.Elem.gobType().safeString(seen))
}

func (s *sliceType) string() string { return s.safeString(make(map[typeId]bool)) }

// Struct type
type fieldType struct {
	Name string
	Id   typeId
}

type structType struct {
	CommonType
	Field []fieldType
}

func (s *structType) safeString(seen map[typeId]bool) string {
	if s == nil {
		return "<nil>"
	}
	if _, ok := seen[s.Id]; ok {
		return s.Name
	}
	seen[s.Id] = true
	str := s.Name + " = struct { "
	for _, f := range s.Field {
		str += fmt.Sprintf("%s %s; ", f.Name, f.Id.gobType().safeString(seen))
	}
	str += "}"
	return str
}

func (s *structType) string() string { return s.safeString(make(map[typeId]bool)) }

func newStructType(name string) *structType {
	s := &structType{CommonType{Name: name}, nil}
	// For historical reasons we set the id here rather than init.
	// See the comment in newTypeObject for details.
	setTypeId(s)
	return s
}

// newTypeObject allocates a gobType for the reflection type rt.
// Unless ut represents a GobEncoder, rt should be the base type
// of ut.
// This is only called from the encoding side. The decoding side
// works through typeIds and userTypeInfos alone.
func newTypeObject(name string, ut *userTypeInfo, rt reflect.Type) (gobType, error) {
	// Does this type implement GobEncoder?
	if ut.externalEnc != 0 {
		return newGobEncoderType(name), nil
	}
	var err error
	var type0, type1 gobType
	defer func() {
		if err != nil {
			delete(types, rt)
		}
	}()
	// Install the top-level type before the subtypes (e.g. struct before
	// fields) so recursive types can be constructed safely.
	switch t := rt; t.Kind() {
	// All basic types are easy: they are predefined.
	case reflect.Bool:
		return tBool.gobType(), nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return tInt.gobType(), nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return tUint.gobType(), nil

	case reflect.Float32, reflect.Float64:
		return tFloat.gobType(), nil

	case reflect.Complex64, reflect.Complex128:
		return tComplex.gobType(), nil

	case reflect.String:
		return tString.gobType(), nil

	case reflect.Interface:
		return tInterface.gobType(), nil

	case reflect.Array:
		at := newArrayType(name)
		types[rt] = at
		type0, err = getBaseType("", t.Elem())
		if err != nil {
			return nil, err
		}
		// Historical aside:
		// For arrays, maps, and slices, we set the type id after the elements
		// are constructed. This is to retain the order of type id allocation after
		// a fix made to handle recursive types, which changed the order in
		// which types are built. Delaying the setting in this way preserves
		// type ids while allowing recursive types to be described. Structs,
		// done below, were already handling recursion correctly so they
		// assign the top-level id before those of the field.
		at.init(type0, t.Len())
		return at, nil

	case reflect.Map:
		mt := newMapType(name)
		types[rt] = mt
		type0, err = getBaseType("", t.Key())
		if err != nil {
			return nil, err
		}
		type1, err = getBaseType("", t.Elem())
		if err != nil {
			return nil, err
		}
		mt.init(type0, type1)
		return mt, nil

	case reflect.Slice:
		// []byte == []uint8 is a special case
		if t.Elem().Kind() == reflect.Uint8 {
			return tBytes.gobType(), nil
		}
		st := newSliceType(name)
		types[rt] = st
		type0, err = getBaseType(t.Elem().Name(), t.Elem())
		if err != nil {
			return nil, err
		}
		st.init(type0)
		return st, nil

	case reflect.Struct:
		st := newStructType(name)
		types[rt] = st
		idToTypeSlice[st.id()] = st
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !isSent(&f) {
				continue
			}
			typ := userType(f.Type).base
			tname := typ.Name()
			if tname == "" {
				t := userType(f.Type).base
				tname = t.String()
			}
			gt, err := getBaseType(tname, f.Type)
			if err != nil {
				return nil, err
			}
			// Some mutually recursive types can cause us to be here while
			// still defining the element. Fix the element type id here.
			// We could do this more neatly by setting the id at the start of
			// building every type, but that would break binary compatibility.
			if gt.id() == 0 {
				setTypeId(gt)
			}
			st.Field = append(st.Field, fieldType{f.Name, gt.id()})
		}
		return st, nil

	default:
		return nil, errors.New("gob NewTypeObject can't handle type: " + rt.String())
	}
}

// isExported reports whether this is an exported - upper case - name.
func isExported(name string) bool {
	rune, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(rune)
}

// isSent reports whether this struct field is to be transmitted.
// It will be transmitted only if it is exported and not a chan or func field
// or pointer to chan or func.
func isSent(field *reflect.StructField) bool {
	if !isExported(field.Name) {
		return false
	}
	// If the field is a chan or func or pointer thereto, don't send it.
	// That is, treat it like an unexported field.
	typ := field.Type
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Chan || typ.Kind() == reflect.Func {
		return false
	}

	return true
}

// getBaseType returns the Gob type describing the given reflect.Type's base type.
// typeLock must be held.
func getBaseType(name string, rt reflect.Type) (gobType, error) {
	ut := userType(rt)
	return getType(name, ut, ut.base)
}

// getType returns the Gob type describing the given reflect.Type.
// Should be called only when handling GobEncoders/Decoders,
// which may be pointers. All other types are handled through the
// base type, never a pointer.
// typeLock must be held.
func getType(name string, ut *userTypeInfo, rt reflect.Type) (gobType, error) {
	typ, present := types[rt]
	if present {
		return typ, nil
	}
	typ, err := newTypeObject(name, ut, rt)
	if err == nil {
		types[rt] = typ
	}
	return typ, err
}

func checkId(want, got typeId) {
	if want != got {
		fmt.Fprintf(os.Stderr, "checkId: %d should be %d\n", int(got), int(want))
		panic("bootstrap type wrong id: " + got.name() + " " + got.string() + " not " + want.string())
	}
}

// used for building the basic types; called only from init().  the incoming
// interface always refers to a pointer.
func bootstrapType(name string, e any) typeId {
	rt := reflect.TypeOf(e).Elem()
	_, present := types[rt]
	if present {
		panic("bootstrap type already present: " + name + ", " + rt.String())
	}
	typ := &CommonType{Name: name}
	types[rt] = typ
	setTypeId(typ)
	return typ.id()
}

// Representation of the information we send and receive about this type.
// Each value we send is preceded by its type definition: an encoded int.
// However, the very first time we send the value, we first send the pair
// (-id, wireType).
// For bootstrapping purposes, we assume that the recipient knows how
// to decode a wireType; it is exactly the wireType struct here, interpreted
// using the gob rules for sending a structure, except that we assume the
// ids for wireType and structType etc. are known. The relevant pieces
// are built in encode.go's init() function.
// To maintain binary compatibility, if you extend this type, always put
// the new fields last.
type wireType struct {
	ArrayT           *arrayType
	SliceT           *sliceType
	StructT          *structType
	MapT             *mapType
	GobEncoderT      *gobEncoderType
	BinaryMarshalerT *gobEncoderType
	TextMarshalerT   *gobEncoderType
}

func (w *wireType) string() string {
	const unknown = "unknown type"
	if w == nil {
		return unknown
	}
	switch {
	case w.ArrayT != nil:
		return w.ArrayT.Name
	case w.SliceT != nil:
		return w.SliceT.Name
	case w.StructT != nil:
		return w.StructT.Name
	case w.MapT != nil:
		return w.MapT.Name
	case w.GobEncoderT != nil:
		return w.GobEncoderT.Name
	case w.BinaryMarshalerT != nil:
		return w.BinaryMarshalerT.Name
	case w.TextMarshalerT != nil:
		return w.TextMarshalerT.Name
	}
	return unknown
}

type typeInfo struct {
	id      typeId
	encInit sync.Mutex // protects creation of encoder
	encoder atomic.Pointer[encEngine]
	wire    wireType
}

// typeInfoMap is an atomic pointer to map[reflect.Type]*typeInfo.
// It's updated copy-on-write. Readers just do an atomic load
// to get the current version of the map. Writers make a full copy of
// the map and atomically update the pointer to point to the new map.
// Under heavy read contention, this is significantly faster than a map
// protected by a mutex.
var typeInfoMap atomic.Value

// typeInfoMapInit is used instead of typeInfoMap during init time,
// as types are registered sequentially during init and we can save
// the overhead of making map copies.
// It is saved to typeInfoMap and set to nil before init finishes.
var typeInfoMapInit = make(map[reflect.Type]*typeInfo, 16)

func lookupTypeInfo(rt reflect.Type) *typeInfo {
	if m := typeInfoMapInit; m != nil {
		return m[rt]
	}
	m, _ := typeInfoMap.Load().(map[reflect.Type]*typeInfo)
	return m[rt]
}

func getTypeInfo(ut *userTypeInfo) (*typeInfo, error) {
	rt := ut.base
	if ut.externalEnc != 0 {
		// We want the user type, not the base type.
		rt = ut.user
	}
	if info := lookupTypeInfo(rt); info != nil {
		return info, nil
	}
	return buildTypeInfo(ut, rt)
}

// buildTypeInfo constructs the type information for the type
// and stores it in the type info map.
func buildTypeInfo(ut *userTypeInfo, rt reflect.Type) (*typeInfo, error) {
	typeLock.Lock()
	defer typeLock.Unlock()

	if info := lookupTypeInfo(rt); info != nil {
		return info, nil
	}

	gt, err := getBaseType(rt.Name(), rt)
	if err != nil {
		return nil, err
	}
	info := &typeInfo{id: gt.id()}

	if ut.externalEnc != 0 {
		userType, err := getType(rt.Name(), ut, rt)
		if err != nil {
			return nil, err
		}
		gt := userType.id().gobType().(*gobEncoderType)
		switch ut.externalEnc {
		case xGob:
			info.wire.GobEncoderT = gt
		case xBinary:
			info.wire.BinaryMarshalerT = gt
		case xText:
			info.wire.TextMarshalerT = gt
		}
		rt = ut.user
	} else {
		t := info.id.gobType()
		switch typ := rt; typ.Kind() {
		case reflect.Array:
			info.wire.ArrayT = t.(*arrayType)
		case reflect.Map:
			info.wire.MapT = t.(*mapType)
		case reflect.Slice:
			// []byte == []uint8 is a special case handled separately
			if typ.Elem().Kind() != reflect.Uint8 {
				info.wire.SliceT = t.(*sliceType)
			}
		case reflect.Struct:
			info.wire.StructT = t.(*structType)
		}
	}

	if m := typeInfoMapInit; m != nil {
		m[rt] = info
		return info, nil
	}

	// Create new map with old contents plus new entry.
	m, _ := typeInfoMap.Load().(map[reflect.Type]*typeInfo)
	newm := maps.Clone(m)
	newm[rt] = info
	typeInfoMap.Store(newm)
	return info, nil
}

// Called only when a panic is acceptable and unexpected.
func mustGetTypeInfo(rt reflect.Type) *typeInfo {
	t, err := getTypeInfo(userType(rt))
	if err != nil {
		panic("getTypeInfo: " + err.Error())
	}
	return t
}

// GobEncoder is the interface describing data that provides its own
// representation for encoding values for transmission to a GobDecoder.
// A type that implements GobEncoder and GobDecoder has complete
// control over the representation of its data and may therefore
// contain things such as private fields, channels, and functions,
// which are not usually transmissible in gob streams.
//
// Note: Since gobs can be stored permanently, it is good design
// to guarantee the encoding used by a GobEncoder is stable as the
// software evolves. For instance, it might make sense for GobEncode
// to include a version number in the encoding.
type GobEncoder interface {
	// GobEncode returns a byte slice representing the encoding of the
	// receiver for transmission to a GobDecoder, usually of the same
	// concrete type.
	GobEncode() ([]byte, error)
}

// GobDecoder is the interface describing data that provides its own
// routine for decoding transmitted values sent by a GobEncoder.
type GobDecoder interface {
	// GobDecode overwrites the receiver, which must be a pointer,
	// with the value represented by the byte slice, which was written
	// by GobEncode, usually for the same concrete type.
	GobDecode([]byte) error
}

var (
	nameToConcreteType sync.Map // map[string]reflect.Type
	concreteTypeToName sync.Map // map[reflect.Type]string
)

// RegisterName is like [Register] but uses the provided name rather than the
// type's default.
func RegisterName(name string, value any) {
	if name == "" {
		// reserved for nil
		panic("attempt to register empty name")
	}

	ut := userType(reflect.TypeOf(value))

	// Check for incompatible duplicates. The name must refer to the
	// same user type, and vice versa.

	// Store the name and type provided by the user....
	if t, dup := nameToConcreteType.LoadOrStore(name, reflect.TypeOf(value)); dup && t != ut.user {
		panic(fmt.Sprintf("gob: registering duplicate types for %q: %s != %s", name, t, ut.user))
	}

	// but the flattened type in the type table, since that's what decode needs.
	if n, dup := concreteTypeToName.LoadOrStore(ut.base, name); dup && n != name {
		nameToConcreteType.Delete(name)
		panic(fmt.Sprintf("gob: registering duplicate names for %s: %q != %q", ut.user, n, name))
	}
}

// Register records a type, identified by a value for that type, under its
// internal type name. That name will identify the concrete type of a value
// sent or received as an interface variable. Only types that will be
// transferred as implementations of interface values need to be registered.
// Expecting to be used only during initialization, it panics if the mapping
// between types and names is not a bijection.
func Register(value any) {
	// Default to printed representation for unnamed types
	rt := reflect.TypeOf(value)
	name := rt.String()

	// But for named types (or pointers to them), qualify with import path (but see inner comment).
	// Dereference one pointer looking for a named type.
	star := ""
	if rt.Name() == "" {
		if pt := rt; pt.Kind() == reflect.Pointer {
			star = "*"
			// NOTE: The following line should be rt = pt.Elem() to implement
			// what the comment above claims, but fixing it would break compatibility
			// with existing gobs.
			//
			// Given package p imported as "full/p" with these definitions:
			//     package p
			//     type T1 struct { ... }
			// this table shows the intended and actual strings used by gob to
			// name the types:
			//
			// Type      Correct string     Actual string
			//
			// T1        full/p.T1          full/p.T1
			// *T1       *full/p.T1         *p.T1
			//
			// The missing full path cannot be fixed without breaking existing gob decoders.
			rt = pt
		}
	}
	if rt.Name() != "" {
		if rt.PkgPath() == "" {
			name = star + rt.Name()
		} else {
			name = star + rt.PkgPath() + "." + rt.Name()
		}
	}

	RegisterName(name, value)
}

func registerBasics() {
	Register(int(0))
	Register(int8(0))
	Register(int16(0))
	Register(int32(0))
	Register(int64(0))
	Register(uint(0))
	Register(uint8(0))
	Register(uint16(0))
	Register(uint32(0))
	Register(uint64(0))
	Register(float32(0))
	Register(float64(0))
	Register(complex64(0i))
	Register(complex128(0i))
	Register(uintptr(0))
	Register(false)
	Register("")
	Register([]byte(nil))
	Register([]int(nil))
	Register([]int8(nil))
	Register([]int16(nil))
	Register([]int32(nil))
	Register([]int64(nil))
	Register([]uint(nil))
	Register([]uint8(nil))
	Register([]uint16(nil))
	Register([]uint32(nil))
	Register([]uint64(nil))
	Register([]float32(nil))
	Register([]float64(nil))
	Register([]complex64(nil))
	Register([]complex128(nil))
	Register([]uintptr(nil))
	Register([]bool(nil))
	Register([]string(nil))
}

func init() {
	typeInfoMap.Store(typeInfoMapInit)
	typeInfoMapInit = nil
}
```