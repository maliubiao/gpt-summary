Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Understanding the Context:**

* **File Path:** `go/src/internal/syscall/windows/registry/registry_test.go`. This immediately tells us it's a test file within the `internal` package related to Windows syscalls and registry operations. The `_test.go` suffix confirms it's a test suite.
* **Package Declaration:** `package registry_test`. This reinforces the idea that these are tests for the `registry` package in the directory above.
* **Imports:**  `bytes`, `crypto/rand`, `os`, `syscall`, `testing`, `unsafe`, and `internal/syscall/windows/registry`. These imports give clues about the functionality being tested:
    * `crypto/rand`:  Likely used for generating random data, often for test key names.
    * `os`:  Potentially used for interacting with the operating system environment, like getting environment variables.
    * `syscall`:  Core package for making system calls, which is expected for registry interaction.
    * `testing`:  The standard Go testing package.
    * `unsafe`:  Indicates potential low-level memory manipulation, which makes sense for interacting with the Windows API.
    * `internal/syscall/windows/registry`:  This confirms the tests are for this specific registry package.

**2. Analyzing Individual Test Functions:**

I would go through each test function (`TestReadSubKeyNames`, `TestCreateOpenDeleteKey`, `TestValues`, `TestExpandString`, `TestInvalidValues`, `TestGetMUIStringValue`) and try to understand its purpose:

* **`TestReadSubKeyNames`:**
    * Opens a specific key (`CLASSES_ROOT\TypeLib`).
    * Reads the subkey names.
    * Asserts that a known subkey (`{00020430-0000-0000-C000-000000000046}`) exists.
    * **Functionality:** Verifies the ability to read subkey names.

* **`TestCreateOpenDeleteKey`:**
    * Opens a key (`CURRENT_USER\Software`).
    * Creates a new subkey with a random name.
    * Verifies that the creation succeeds and the "exists" flag is handled correctly.
    * Opens the created key.
    * Deletes the key.
    * Verifies that the deletion is successful.
    * **Functionality:** Tests the creation, opening, and deletion of registry keys.

* **`TestValues`:** This is a more complex one, I would look for helper functions and the main logic:
    * `setValues`: Sets various types of registry values (string, expand string, binary, DWORD, QWORD, multi-string).
    * `enumerateValues`: Checks if the set values are present when enumerating.
    * `testValues`: Reads and verifies the values that were set.
    * `testStat`: Checks the statistics of a key (subkey count, value count, etc.).
    * `deleteValues`: Deletes the values that were created.
    * **Functionality:**  Comprehensive testing of setting, reading, enumerating, and deleting different types of registry values, as well as retrieving key statistics.

* **`TestExpandString`:**
    * Expands an environment variable string (`%PATH%`).
    * Compares the result with the actual environment variable.
    * **Functionality:** Tests the ability to expand environment variables within registry strings.

* **`TestInvalidValues`:**
    * Creates a key.
    * Attempts to set invalid data for specific value types (e.g., wrong size for DWORD/QWORD, malformed multi-string).
    * Checks if getting these values returns errors or unexpected data.
    * **Functionality:** Tests how the registry implementation handles invalid data when setting values.

* **`TestGetMUIStringValue`:**
    * Retrieves the current timezone key name.
    * Opens the timezone key.
    * Attempts to get MUI (Multilingual User Interface) string values.
    * **Functionality:** Tests the ability to read MUI string values, which can be localized. The reliance on `GetDynamicTimeZoneInformation` suggests it's testing how localized strings in the registry are handled.

**3. Identifying Core Functionality and Providing Go Code Examples:**

Based on the analysis of the test functions, the core functionalities being tested are:

* **Key Management:** Creating, opening, deleting registry keys.
* **Value Management:** Setting, getting, enumerating, and deleting various types of registry values (string, expand string, binary, DWORD, QWORD, multi-string, MUI string).
* **Key Information:** Getting key statistics (subkey count, value count, etc.).
* **String Expansion:** Expanding environment variables in registry strings.

I would then create simple Go code examples demonstrating these functionalities using the `registry` package. These examples would be basic and illustrate the primary use cases.

**4. Inferring Go Language Features:**

The code uses standard Go features like:

* **Functions and methods:**  Clear function definitions and method calls on `registry.Key`.
* **Error handling:**  Consistent use of `if err != nil` for error checking.
* **Deferred function calls (`defer`)**: For resource cleanup (closing registry keys).
* **Data structures:**  Structs (`ValueTest`, `DynamicTimezoneinformation`).
* **Slices and maps:**  Used for storing and iterating over values and names.
* **Type assertions:**  Used to work with the `any` type in `ValueTest`.
* **String manipulation:**  Basic string operations.
* **Testing framework:**  Using `testing.T` for test functions and assertions.
* **Build constraints:** `//go:build windows` indicates platform-specific code.
* **Unsafe package:** Used for interacting with low-level Windows API structures.

**5. Considering Assumptions, Inputs, and Outputs:**

For the code examples, I'd make reasonable assumptions about the registry structure and provide sample inputs and expected outputs. For instance, when creating a key, I'd assume the user has permissions to create keys in the specified location.

**6. Identifying Potential Pitfalls:**

I'd think about common mistakes developers might make when working with the registry, such as:

* **Incorrect permissions:**  Not having the necessary permissions to access or modify registry keys.
* **Resource leaks:**  Forgetting to close registry keys.
* **Incorrect data types:**  Trying to set a value with the wrong type.
* **Handling errors:**  Not properly checking for errors returned by registry functions.

**7. Structuring the Answer in Chinese:**

Finally, I'd organize the information clearly in Chinese, following the prompt's requirements:

* List the functionalities.
* Provide Go code examples.
* Explain the inferred Go features.
* Describe assumptions, inputs, and outputs for the code examples.
* Detail command-line argument handling (if any – in this case, none are apparent).
* Point out common mistakes.

This structured approach ensures a comprehensive and accurate answer that addresses all aspects of the prompt.
这段Go语言代码是 `internal/syscall/windows/registry` 包的测试文件，用于测试在Windows系统上操作注册表的功能。它涵盖了注册表键和值的各种操作。

**主要功能列表:**

1. **读取子键名称:** 测试读取指定注册表键下的所有子键名称的功能。
2. **创建、打开和删除键:** 测试创建新的注册表键，打开已存在的键，以及删除键的功能。
3. **设置不同类型的注册表值:**  测试设置各种类型的注册表值，包括：
    * 字符串 (REG_SZ)
    * 可扩展字符串 (REG_EXPAND_SZ)
    * 二进制数据 (REG_BINARY)
    * DWORD (32位整数) (REG_DWORD)
    * QWORD (64位整数) (REG_QWORD)
    * 多字符串 (REG_MULTI_SZ)
4. **读取不同类型的注册表值:** 测试读取以上各种类型的注册表值，并验证读取到的值是否正确。
5. **枚举注册表值名称:** 测试读取指定注册表键下的所有值名称的功能。
6. **获取注册表键的统计信息:** 测试获取注册表键的子键数量、最大子键名称长度、值数量、最大值名称长度和最大值长度等统计信息的功能。
7. **删除注册表值:** 测试删除指定注册表键下的某个值的功能。
8. **扩展字符串中的环境变量:** 测试 `ExpandString` 函数，用于扩展注册表字符串值中包含的环境变量。
9. **处理无效的注册表值数据:** 测试当尝试设置或读取无效的注册表值数据时，程序的处理情况。
10. **获取 MUI (Multilingual User Interface) 字符串值:** 测试获取注册表中本地化字符串值的功能。

**推理的 Go 语言功能实现 (以创建和读取字符串值为例):**

假设 `internal/syscall/windows/registry` 包提供了以下函数：

* `OpenKey(key registry.Key, subkey string, access uint32) (Key, error)`:  打开一个注册表键。
* `CreateKey(key registry.Key, subkey string, access uint32) (Key, bool, error)`: 创建一个新的注册表键，并返回一个布尔值指示键是否已存在。
* `SetStringValue(name string, value string) error`: 设置字符串值。
* `GetStringValue(name string) (string, uint32, error)`: 获取字符串值及其类型。
* `Close() error`: 关闭注册表键。
* `DeleteKey(key registry.Key, subkey string) error`: 删除子键。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/syscall/windows/registry"
	"log"
)

func main() {
	// 打开 HKEY_CURRENT_USER\Software 键
	key, err := registry.OpenKey(registry.CURRENT_USER, "Software", registry.CREATE_SUB_KEY|registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	subkeyName := "MyTestKey"
	valueName := "MyStringValue"
	stringValue := "Hello, Registry!"

	// 创建子键
	subkey, created, err := registry.CreateKey(key, subkeyName, registry.CREATE_SUB_KEY|registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	defer subkey.Close()

	if created {
		fmt.Println("子键", subkeyName, "已创建")
	} else {
		fmt.Println("子键", subkeyName, "已存在")
	}

	// 设置字符串值
	err = subkey.SetStringValue(valueName, stringValue)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("已设置值:", valueName, "=", stringValue)

	// 读取字符串值
	readString, valueType, err := subkey.GetStringValue(valueName)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("读取到的值: %s = %q, 类型: %d\n", valueName, readString, valueType)

	// 清理: 删除子键
	err = registry.DeleteKey(key, subkeyName)
	if err != nil {
		log.Println("删除子键失败:", err)
	} else {
		fmt.Println("子键", subkeyName, "已删除")
	}
}
```

**假设的输入与输出:**

* **假设:** 用户具有创建和修改 `HKEY_CURRENT_USER\Software` 下子键的权限。
* **输入:**  无特定的命令行输入，程序内部定义了键名、值名和值。
* **输出:**
    ```
    子键 MyTestKey 已创建  // 或者 子键 MyTestKey 已存在
    已设置值: MyStringValue = Hello, Registry!
    读取到的值: MyStringValue = "Hello, Registry!", 类型: 1
    子键 MyTestKey 已删除
    ```

**命令行参数的具体处理:**

这段代码本身是一个测试文件，不涉及命令行参数的处理。`go test` 命令会运行这些测试用例，但它处理的是测试框架的参数，而不是被测试代码的参数。

**使用者易犯错的点 (示例):**

* **忘记关闭 Key:**  在操作注册表后，必须调用 `Close()` 方法关闭 `registry.Key`，否则可能导致资源泄漏。

  ```go
  key, err := registry.OpenKey(registry.CURRENT_USER, "Software", registry.QUERY_VALUE)
  if err != nil {
      log.Fatal(err)
  }
  // 忘记调用 key.Close()
  // ... 后续操作
  ```

* **权限不足:**  尝试访问或修改需要管理员权限的注册表键时，会遇到错误。

  ```go
  // 尝试写入 HKEY_LOCAL_MACHINE 而没有管理员权限
  key, err := registry.OpenKey(registry.LOCAL_MACHINE, "System\\CurrentControlSet\\Control", registry.SET_VALUE)
  if err != nil {
      log.Println("打开 Key 失败:", err) // 可能会因为权限不足而失败
  }
  ```

* **类型不匹配:**  尝试用错误的类型读取注册表值会导致错误。

  ```go
  // 假设 "MyDWordValue" 是一个 DWORD 值
  strValue, _, err := key.GetStringValue("MyDWordValue") // 尝试用 GetStringValue 读取 DWORD 值
  if err != nil {
      log.Println("读取值失败:", err) // 可能会返回类型不匹配的错误
  }
  ```

总而言之，这个测试文件全面地测试了 `internal/syscall/windows/registry` 包在 Windows 系统上操作注册表的各种功能，包括键的创建、打开、删除，以及不同类型值的设置、读取、枚举和删除。它也涵盖了错误处理和一些边界情况的测试。

Prompt: 
```
这是路径为go/src/internal/syscall/windows/registry/registry_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package registry_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"internal/syscall/windows/registry"
)

func randKeyName(prefix string) string {
	const numbers = "0123456789"
	buf := make([]byte, 10)
	rand.Read(buf)
	for i, b := range buf {
		buf[i] = numbers[b%byte(len(numbers))]
	}
	return prefix + string(buf)
}

func TestReadSubKeyNames(t *testing.T) {
	k, err := registry.OpenKey(registry.CLASSES_ROOT, "TypeLib", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames()
	if err != nil {
		t.Fatal(err)
	}
	var foundStdOle bool
	for _, name := range names {
		// Every PC has "stdole 2.0 OLE Automation" library installed.
		if name == "{00020430-0000-0000-C000-000000000046}" {
			foundStdOle = true
		}
	}
	if !foundStdOle {
		t.Fatal("could not find stdole 2.0 OLE Automation")
	}
}

func TestCreateOpenDeleteKey(t *testing.T) {
	k, err := registry.OpenKey(registry.CURRENT_USER, "Software", registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	testKName := randKeyName("TestCreateOpenDeleteKey_")

	testK, exist, err := registry.CreateKey(k, testKName, registry.CREATE_SUB_KEY)
	if err != nil {
		t.Fatal(err)
	}
	defer testK.Close()

	if exist {
		t.Fatalf("key %q already exists", testKName)
	}

	testKAgain, exist, err := registry.CreateKey(k, testKName, registry.CREATE_SUB_KEY)
	if err != nil {
		t.Fatal(err)
	}
	defer testKAgain.Close()

	if !exist {
		t.Fatalf("key %q should already exist", testKName)
	}

	testKOpened, err := registry.OpenKey(k, testKName, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		t.Fatal(err)
	}
	defer testKOpened.Close()

	err = registry.DeleteKey(k, testKName)
	if err != nil {
		t.Fatal(err)
	}

	testKOpenedAgain, err := registry.OpenKey(k, testKName, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer testKOpenedAgain.Close()
		t.Fatalf("key %q should already been deleted", testKName)
	}
	if err != registry.ErrNotExist {
		t.Fatalf(`unexpected error ("not exist" expected): %v`, err)
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if a == nil {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type ValueTest struct {
	Type     uint32
	Name     string
	Value    any
	WillFail bool
}

var ValueTests = []ValueTest{
	{Type: registry.SZ, Name: "String1", Value: ""},
	{Type: registry.SZ, Name: "String2", Value: "\000", WillFail: true},
	{Type: registry.SZ, Name: "String3", Value: "Hello World"},
	{Type: registry.SZ, Name: "String4", Value: "Hello World\000", WillFail: true},
	{Type: registry.EXPAND_SZ, Name: "ExpString1", Value: ""},
	{Type: registry.EXPAND_SZ, Name: "ExpString2", Value: "\000", WillFail: true},
	{Type: registry.EXPAND_SZ, Name: "ExpString3", Value: "Hello World"},
	{Type: registry.EXPAND_SZ, Name: "ExpString4", Value: "Hello\000World", WillFail: true},
	{Type: registry.EXPAND_SZ, Name: "ExpString5", Value: "%PATH%"},
	{Type: registry.EXPAND_SZ, Name: "ExpString6", Value: "%NO_SUCH_VARIABLE%"},
	{Type: registry.EXPAND_SZ, Name: "ExpString7", Value: "%PATH%;."},
	{Type: registry.BINARY, Name: "Binary1", Value: []byte{}},
	{Type: registry.BINARY, Name: "Binary2", Value: []byte{1, 2, 3}},
	{Type: registry.BINARY, Name: "Binary3", Value: []byte{3, 2, 1, 0, 1, 2, 3}},
	{Type: registry.DWORD, Name: "Dword1", Value: uint64(0)},
	{Type: registry.DWORD, Name: "Dword2", Value: uint64(1)},
	{Type: registry.DWORD, Name: "Dword3", Value: uint64(0xff)},
	{Type: registry.DWORD, Name: "Dword4", Value: uint64(0xffff)},
	{Type: registry.QWORD, Name: "Qword1", Value: uint64(0)},
	{Type: registry.QWORD, Name: "Qword2", Value: uint64(1)},
	{Type: registry.QWORD, Name: "Qword3", Value: uint64(0xff)},
	{Type: registry.QWORD, Name: "Qword4", Value: uint64(0xffff)},
	{Type: registry.QWORD, Name: "Qword5", Value: uint64(0xffffff)},
	{Type: registry.QWORD, Name: "Qword6", Value: uint64(0xffffffff)},
	{Type: registry.MULTI_SZ, Name: "MultiString1", Value: []string{"a", "b", "c"}},
	{Type: registry.MULTI_SZ, Name: "MultiString2", Value: []string{"abc", "", "cba"}},
	{Type: registry.MULTI_SZ, Name: "MultiString3", Value: []string{""}},
	{Type: registry.MULTI_SZ, Name: "MultiString4", Value: []string{"abcdef"}},
	{Type: registry.MULTI_SZ, Name: "MultiString5", Value: []string{"\000"}, WillFail: true},
	{Type: registry.MULTI_SZ, Name: "MultiString6", Value: []string{"a\000b"}, WillFail: true},
	{Type: registry.MULTI_SZ, Name: "MultiString7", Value: []string{"ab", "\000", "cd"}, WillFail: true},
	{Type: registry.MULTI_SZ, Name: "MultiString8", Value: []string{"\000", "cd"}, WillFail: true},
	{Type: registry.MULTI_SZ, Name: "MultiString9", Value: []string{"ab", "\000"}, WillFail: true},
}

func setValues(t *testing.T, k registry.Key) {
	for _, test := range ValueTests {
		var err error
		switch test.Type {
		case registry.SZ:
			err = k.SetStringValue(test.Name, test.Value.(string))
		case registry.EXPAND_SZ:
			err = k.SetExpandStringValue(test.Name, test.Value.(string))
		case registry.MULTI_SZ:
			err = k.SetStringsValue(test.Name, test.Value.([]string))
		case registry.BINARY:
			err = k.SetBinaryValue(test.Name, test.Value.([]byte))
		case registry.DWORD:
			err = k.SetDWordValue(test.Name, uint32(test.Value.(uint64)))
		case registry.QWORD:
			err = k.SetQWordValue(test.Name, test.Value.(uint64))
		default:
			t.Fatalf("unsupported type %d for %s value", test.Type, test.Name)
		}
		if test.WillFail {
			if err == nil {
				t.Fatalf("setting %s value %q should fail, but succeeded", test.Name, test.Value)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func enumerateValues(t *testing.T, k registry.Key) {
	names, err := k.ReadValueNames()
	if err != nil {
		t.Error(err)
		return
	}
	haveNames := make(map[string]bool)
	for _, n := range names {
		haveNames[n] = false
	}
	for _, test := range ValueTests {
		wantFound := !test.WillFail
		_, haveFound := haveNames[test.Name]
		if wantFound && !haveFound {
			t.Errorf("value %s is not found while enumerating", test.Name)
		}
		if haveFound && !wantFound {
			t.Errorf("value %s is found while enumerating, but expected to fail", test.Name)
		}
		if haveFound {
			delete(haveNames, test.Name)
		}
	}
	for n, v := range haveNames {
		t.Errorf("value %s (%v) is found while enumerating, but has not been created", n, v)
	}
}

func testErrNotExist(t *testing.T, name string, err error) {
	if err == nil {
		t.Errorf("%s value should not exist", name)
		return
	}
	if err != registry.ErrNotExist {
		t.Errorf("reading %s value should return 'not exist' error, but got: %s", name, err)
		return
	}
}

func testErrUnexpectedType(t *testing.T, test ValueTest, gottype uint32, err error) {
	if err == nil {
		t.Errorf("GetXValue(%q) should not succeed", test.Name)
		return
	}
	if err != registry.ErrUnexpectedType {
		t.Errorf("reading %s value should return 'unexpected key value type' error, but got: %s", test.Name, err)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetStringValue(t *testing.T, k registry.Key, test ValueTest) {
	got, gottype, err := k.GetStringValue(test.Name)
	if err != nil {
		t.Errorf("GetStringValue(%s) failed: %v", test.Name, err)
		return
	}
	if got != test.Value {
		t.Errorf("want %s value %q, got %q", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	if gottype == registry.EXPAND_SZ {
		_, err = registry.ExpandString(got)
		if err != nil {
			t.Errorf("ExpandString(%s) failed: %v", got, err)
			return
		}
	}
}

func testGetIntegerValue(t *testing.T, k registry.Key, test ValueTest) {
	got, gottype, err := k.GetIntegerValue(test.Name)
	if err != nil {
		t.Errorf("GetIntegerValue(%s) failed: %v", test.Name, err)
		return
	}
	if got != test.Value.(uint64) {
		t.Errorf("want %s value %v, got %v", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetBinaryValue(t *testing.T, k registry.Key, test ValueTest) {
	got, gottype, err := k.GetBinaryValue(test.Name)
	if err != nil {
		t.Errorf("GetBinaryValue(%s) failed: %v", test.Name, err)
		return
	}
	if !bytes.Equal(got, test.Value.([]byte)) {
		t.Errorf("want %s value %v, got %v", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetStringsValue(t *testing.T, k registry.Key, test ValueTest) {
	got, gottype, err := k.GetStringsValue(test.Name)
	if err != nil {
		t.Errorf("GetStringsValue(%s) failed: %v", test.Name, err)
		return
	}
	if !equalStringSlice(got, test.Value.([]string)) {
		t.Errorf("want %s value %#v, got %#v", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetValue(t *testing.T, k registry.Key, test ValueTest, size int) {
	if size <= 0 {
		return
	}
	// read data with no buffer
	gotsize, gottype, err := k.GetValue(test.Name, nil)
	if err != nil {
		t.Errorf("GetValue(%s, [%d]byte) failed: %v", test.Name, size, err)
		return
	}
	if gotsize != size {
		t.Errorf("want %s value size of %d, got %v", test.Name, size, gotsize)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	// read data with short buffer
	gotsize, gottype, err = k.GetValue(test.Name, make([]byte, size-1))
	if err == nil {
		t.Errorf("GetValue(%s, [%d]byte) should fail, but succeeded", test.Name, size-1)
		return
	}
	if err != registry.ErrShortBuffer {
		t.Errorf("reading %s value should return 'short buffer' error, but got: %s", test.Name, err)
		return
	}
	if gotsize != size {
		t.Errorf("want %s value size of %d, got %v", test.Name, size, gotsize)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	// read full data
	gotsize, gottype, err = k.GetValue(test.Name, make([]byte, size))
	if err != nil {
		t.Errorf("GetValue(%s, [%d]byte) failed: %v", test.Name, size, err)
		return
	}
	if gotsize != size {
		t.Errorf("want %s value size of %d, got %v", test.Name, size, gotsize)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	// check GetValue returns ErrNotExist as required
	_, _, err = k.GetValue(test.Name+"_not_there", make([]byte, size))
	if err == nil {
		t.Errorf("GetValue(%q) should not succeed", test.Name)
		return
	}
	if err != registry.ErrNotExist {
		t.Errorf("GetValue(%q) should return 'not exist' error, but got: %s", test.Name, err)
		return
	}
}

func testValues(t *testing.T, k registry.Key) {
	for _, test := range ValueTests {
		switch test.Type {
		case registry.SZ, registry.EXPAND_SZ:
			if test.WillFail {
				_, _, err := k.GetStringValue(test.Name)
				testErrNotExist(t, test.Name, err)
			} else {
				testGetStringValue(t, k, test)
				_, gottype, err := k.GetIntegerValue(test.Name)
				testErrUnexpectedType(t, test, gottype, err)
				// Size of utf16 string in bytes is not perfect,
				// but correct for current test values.
				// Size also includes terminating 0.
				testGetValue(t, k, test, (len(test.Value.(string))+1)*2)
			}
			_, _, err := k.GetStringValue(test.Name + "_string_not_created")
			testErrNotExist(t, test.Name+"_string_not_created", err)
		case registry.DWORD, registry.QWORD:
			testGetIntegerValue(t, k, test)
			_, gottype, err := k.GetBinaryValue(test.Name)
			testErrUnexpectedType(t, test, gottype, err)
			_, _, err = k.GetIntegerValue(test.Name + "_int_not_created")
			testErrNotExist(t, test.Name+"_int_not_created", err)
			size := 8
			if test.Type == registry.DWORD {
				size = 4
			}
			testGetValue(t, k, test, size)
		case registry.BINARY:
			testGetBinaryValue(t, k, test)
			_, gottype, err := k.GetStringsValue(test.Name)
			testErrUnexpectedType(t, test, gottype, err)
			_, _, err = k.GetBinaryValue(test.Name + "_byte_not_created")
			testErrNotExist(t, test.Name+"_byte_not_created", err)
			testGetValue(t, k, test, len(test.Value.([]byte)))
		case registry.MULTI_SZ:
			if test.WillFail {
				_, _, err := k.GetStringsValue(test.Name)
				testErrNotExist(t, test.Name, err)
			} else {
				testGetStringsValue(t, k, test)
				_, gottype, err := k.GetStringValue(test.Name)
				testErrUnexpectedType(t, test, gottype, err)
				size := 0
				for _, s := range test.Value.([]string) {
					size += len(s) + 1 // nil terminated
				}
				size += 1 // extra nil at the end
				size *= 2 // count bytes, not uint16
				testGetValue(t, k, test, size)
			}
			_, _, err := k.GetStringsValue(test.Name + "_strings_not_created")
			testErrNotExist(t, test.Name+"_strings_not_created", err)
		default:
			t.Errorf("unsupported type %d for %s value", test.Type, test.Name)
			continue
		}
	}
}

func testStat(t *testing.T, k registry.Key) {
	subk, _, err := registry.CreateKey(k, "subkey", registry.CREATE_SUB_KEY)
	if err != nil {
		t.Error(err)
		return
	}
	defer subk.Close()

	defer registry.DeleteKey(k, "subkey")

	ki, err := k.Stat()
	if err != nil {
		t.Error(err)
		return
	}
	if ki.SubKeyCount != 1 {
		t.Error("key must have 1 subkey")
	}
	if ki.MaxSubKeyLen != 6 {
		t.Error("key max subkey name length must be 6")
	}
	if ki.ValueCount != 24 {
		t.Errorf("key must have 24 values, but is %d", ki.ValueCount)
	}
	if ki.MaxValueNameLen != 12 {
		t.Errorf("key max value name length must be 10, but is %d", ki.MaxValueNameLen)
	}
	if ki.MaxValueLen != 38 {
		t.Errorf("key max value length must be 38, but is %d", ki.MaxValueLen)
	}
}

func deleteValues(t *testing.T, k registry.Key) {
	for _, test := range ValueTests {
		if test.WillFail {
			continue
		}
		err := k.DeleteValue(test.Name)
		if err != nil {
			t.Error(err)
			continue
		}
	}
	names, err := k.ReadValueNames()
	if err != nil {
		t.Error(err)
		return
	}
	if len(names) != 0 {
		t.Errorf("some values remain after deletion: %v", names)
	}
}

func TestValues(t *testing.T) {
	softwareK, err := registry.OpenKey(registry.CURRENT_USER, "Software", registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer softwareK.Close()

	testKName := randKeyName("TestValues_")

	k, exist, err := registry.CreateKey(softwareK, testKName, registry.CREATE_SUB_KEY|registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	if exist {
		t.Fatalf("key %q already exists", testKName)
	}

	defer registry.DeleteKey(softwareK, testKName)

	setValues(t, k)

	enumerateValues(t, k)

	testValues(t, k)

	testStat(t, k)

	deleteValues(t, k)
}

func TestExpandString(t *testing.T) {
	got, err := registry.ExpandString("%PATH%")
	if err != nil {
		t.Fatal(err)
	}
	want := os.Getenv("PATH")
	if got != want {
		t.Errorf("want %q string expanded, got %q", want, got)
	}
}

func TestInvalidValues(t *testing.T) {
	softwareK, err := registry.OpenKey(registry.CURRENT_USER, "Software", registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer softwareK.Close()

	testKName := randKeyName("TestInvalidValues_")

	k, exist, err := registry.CreateKey(softwareK, testKName, registry.CREATE_SUB_KEY|registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	if exist {
		t.Fatalf("key %q already exists", testKName)
	}

	defer registry.DeleteKey(softwareK, testKName)

	var tests = []struct {
		Type uint32
		Name string
		Data []byte
	}{
		{registry.DWORD, "Dword1", nil},
		{registry.DWORD, "Dword2", []byte{1, 2, 3}},
		{registry.QWORD, "Qword1", nil},
		{registry.QWORD, "Qword2", []byte{1, 2, 3}},
		{registry.QWORD, "Qword3", []byte{1, 2, 3, 4, 5, 6, 7}},
		{registry.MULTI_SZ, "MultiString1", nil},
		{registry.MULTI_SZ, "MultiString2", []byte{0}},
		{registry.MULTI_SZ, "MultiString3", []byte{'a', 'b', 0}},
		{registry.MULTI_SZ, "MultiString4", []byte{'a', 0, 0, 'b', 0}},
		{registry.MULTI_SZ, "MultiString5", []byte{'a', 0, 0}},
	}

	for _, test := range tests {
		err := k.SetValue(test.Name, test.Type, test.Data)
		if err != nil {
			t.Fatalf("SetValue for %q failed: %v", test.Name, err)
		}
	}

	for _, test := range tests {
		switch test.Type {
		case registry.DWORD, registry.QWORD:
			value, valType, err := k.GetIntegerValue(test.Name)
			if err == nil {
				t.Errorf("GetIntegerValue(%q) succeeded. Returns type=%d value=%v", test.Name, valType, value)
			}
		case registry.MULTI_SZ:
			value, valType, err := k.GetStringsValue(test.Name)
			if err == nil {
				if len(value) != 0 {
					t.Errorf("GetStringsValue(%q) succeeded. Returns type=%d value=%v", test.Name, valType, value)
				}
			}
		default:
			t.Errorf("unsupported type %d for %s value", test.Type, test.Name)
		}
	}
}

func TestGetMUIStringValue(t *testing.T) {
	var dtzi DynamicTimezoneinformation
	if _, err := GetDynamicTimeZoneInformation(&dtzi); err != nil {
		t.Fatal(err)
	}
	tzKeyName := syscall.UTF16ToString(dtzi.TimeZoneKeyName[:])
	timezoneK, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\`+tzKeyName, registry.READ)
	if err != nil {
		t.Fatal(err)
	}
	defer timezoneK.Close()

	type testType struct {
		name string
		want string
	}
	var tests = []testType{
		{"MUI_Std", syscall.UTF16ToString(dtzi.StandardName[:])},
	}
	if dtzi.DynamicDaylightTimeDisabled == 0 {
		tests = append(tests, testType{"MUI_Dlt", syscall.UTF16ToString(dtzi.DaylightName[:])})
	}

	for _, test := range tests {
		got, err := timezoneK.GetMUIStringValue(test.name)
		if err != nil {
			t.Error("GetMUIStringValue:", err)
		}

		if got != test.want {
			t.Errorf("GetMUIStringValue: %s: Got %q, want %q", test.name, got, test.want)
		}
	}
}

type DynamicTimezoneinformation struct {
	Bias                        int32
	StandardName                [32]uint16
	StandardDate                syscall.Systemtime
	StandardBias                int32
	DaylightName                [32]uint16
	DaylightDate                syscall.Systemtime
	DaylightBias                int32
	TimeZoneKeyName             [128]uint16
	DynamicDaylightTimeDisabled uint8
}

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetDynamicTimeZoneInformation = modkernel32.NewProc("GetDynamicTimeZoneInformation")
)

func GetDynamicTimeZoneInformation(dtzi *DynamicTimezoneinformation) (rc uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetDynamicTimeZoneInformation.Addr(), 1, uintptr(unsafe.Pointer(dtzi)), 0, 0)
	rc = uint32(r0)
	if rc == 0xffffffff {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

"""



```