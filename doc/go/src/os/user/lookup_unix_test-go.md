Response:
Let's break down the thought process for analyzing the Go test code.

1. **Identify the Core Purpose:** The filename `lookup_unix_test.go` and the package `user` strongly suggest this code is testing functions related to looking up user and group information on Unix-like systems. The `_test.go` suffix confirms it's a test file.

2. **Examine the Imports:** The `import` statement reveals the dependencies:
    * `reflect`:  Used for deep comparison of data structures (important for verifying the correctness of the lookup functions).
    * `strings`: Used for manipulating strings, specifically creating `io.Reader` instances from test data.
    * `testing`: The standard Go testing library.

3. **Analyze the Test Structure:** The code is organized into several test functions, each targeting specific aspects of user/group lookup. The naming convention is `Test<FunctionName>`. This makes it easy to identify what each test is about.

4. **Focus on the Data Structures:** The code defines several `struct` types to hold test data:
    * `groupTests`:  Tests for `findGroupName`. It contains the input group file content (`in`), the group name to search for (`name`), and the expected GID (`gid`).
    * `groupIdTests`: Tests for `findGroupId`. It contains the input group file content (`in`), the GID to search for (`gid`), and the expected group name (`name`).
    * `userIdTests`: Tests for `findUserId`. It contains the input user file content (`in`), the UID to search for (`uid`), and the expected username (`name`).
    * `userTests`: Tests for `findUsername`. It contains the input user file content (`in`), the username to search for (`name`), and the expected UID (`uid`).

5. **Deconstruct Individual Tests:**  Let's take `TestFindGroupName` as an example:
    * It iterates through the `groupTests` slice.
    * For each test case, it calls `findGroupName` (the function being tested) with a specific group name and a simulated group file content.
    * It then checks the result:
        * If the expected GID is empty (`""`), it verifies that an error of type `UnknownGroupError` is returned and that the error message is correct.
        * If the expected GID is not empty, it verifies that no error is returned and that the returned `Group` struct has the correct GID and name.

6. **Identify the Tested Functions (Inferred):** Based on the test names and the logic within the tests, we can infer the existence of functions like:
    * `findGroupName(name string, r io.Reader) (*Group, error)`
    * `findGroupId(gid string, r io.Reader) (*Group, error)`
    * `findUserId(uid string, r io.Reader) (*User, error)`
    * `findUsername(username string, r io.Reader) (*User, error)`

7. **Infer Functionality:** The tests demonstrate that these functions are responsible for:
    * Parsing the `/etc/group` and `/etc/passwd` (or similar) files.
    * Finding group information by name.
    * Finding group information by GID.
    * Finding user information by UID.
    * Finding user information by username.
    * Handling cases where the user or group is not found.
    * Handling malformed lines in the files.

8. **Code Example Construction:** To illustrate the usage, we can create example Go code that calls these inferred functions. We need to provide input data (like the `testGroupFile` and `testUserFile` content) and demonstrate successful lookups and error handling.

9. **Command Line Arguments (Absence):** The test code itself doesn't directly handle command-line arguments. It's testing the *internal logic* of the user lookup functions. The actual system calls and file reading would likely be handled in the non-test code.

10. **Common Mistakes (Based on Test Cases):**  The test cases highlight potential pitfalls:
    * Incorrectly assuming a user or group exists.
    * Not handling errors when a user or group is not found.
    * Misinterpreting the format of `/etc/passwd` and `/etc/group` (e.g., handling comments, blank lines, etc.).

11. **Refine and Structure the Answer:**  Organize the findings into logical sections (functionality, implementation, examples, etc.) and use clear, concise language. Provide code snippets and explain the assumptions and inputs.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe these functions directly interact with the operating system.
* **Correction:** The presence of `strings.NewReader` suggests the tests are working with in-memory representations of the files, allowing for isolated testing without relying on the actual system files. This makes the tests more portable and reliable.
* **Further refinement:** The `//go:build ...` constraint indicates that this specific test file is designed for certain Unix-like systems *without* cgo (C interop) or specific platforms like Android and Darwin (macOS). This hints at a pure Go implementation for these specific environments.

By following this systematic approach, combining code analysis with logical reasoning, and paying attention to details like imports and test structure, we can effectively understand the functionality of the provided Go test code.
这段代码是Go语言标准库中 `os/user` 包的一部分，专门用于在 **非CGO、非Android、非Darwin（macOS）的Unix系统** 上测试用户和组信息的查找功能。

更具体地说，它测试了在这些特定平台上，如何通过解析 `/etc/group` 和 `/etc/passwd` 文件（或类似的系统文件）来查找用户和组信息。

以下是其主要功能点：

1. **测试通过组名查找 GID 的功能 (`TestFindGroupName`)**:
   - 它定义了一系列测试用例 (`groupTests`)，每个用例包含一个模拟的 `/etc/group` 文件内容 (`in`)，一个要查找的组名 (`name`)，以及期望返回的 GID (`gid`)。
   - 它调用 `findGroupName` 函数（这是被测试的函数，虽然代码中没有直接定义，但可以推断出它的存在和作用），并将模拟的文件内容和组名作为输入。
   - 它断言返回值是否符合预期：
     - 如果期望的 GID 为空，则断言返回 `UnknownGroupError` 类型的错误，并且错误信息包含正确的组名。
     - 如果期望的 GID 不为空，则断言没有错误发生，并且返回的 `Group` 结构体中的 GID 和 Name 与预期一致。

2. **测试通过 GID 查找组名的功能 (`TestFindGroupId`)**:
   - 类似于 `TestFindGroupName`，它定义了 `groupIdTests` 来测试 `findGroupId` 函数。
   - 每个用例包含模拟的 `/etc/group` 文件内容、要查找的 GID 和期望返回的组名。
   - 它断言返回值和错误是否符合预期。

3. **测试通过用户名查找 UID 的功能 (`TestLookupUser`)**:
   - 它定义了 `userTests` 来测试 `findUsername` 函数（同样是被测试的函数）。
   - 每个用例包含模拟的 `/etc/passwd` 文件内容 (`in`)，要查找的用户名 (`name`)，以及期望返回的 UID (`uid`)。
   - 它断言返回值和错误是否符合预期。

4. **测试通过 UID 查找用户名的功能 (`TestLookupUserId`)**:
   - 它定义了 `userIdTests` 来测试 `findUserId` 函数。
   - 每个用例包含模拟的 `/etc/passwd` 文件内容、要查找的 UID 和期望返回的用户名。
   - 它断言返回值和错误是否符合预期。
   - 包含一个 `TestInvalidUserId` 测试用例，专门测试当传入无效的 UID 字符串时，`findUserId` 是否返回正确的错误。

5. **测试查找用户时是否填充所有字段 (`TestLookupUserPopulatesAllFields`)**:
   - 这个测试用例更具体地验证了当通过用户名查找用户时，返回的 `User` 结构体是否正确填充了所有的字段，例如 `Username`, `Uid`, `Gid`, `Name`, 和 `HomeDir`。

**推理 Go 语言功能的实现并举例说明:**

这段测试代码主要测试了 `os/user` 包中用于查找用户和组信息的底层功能。  我们可以推断出，在 `lookup_unix_test.go` 同级目录下的其他源文件中，肯定存在 `findGroupName`, `findGroupId`, `findUsername`, `findUserId` 这些函数的具体实现。

这些函数的实现很可能读取并解析 `/etc/group` 和 `/etc/passwd` 文件（或者通过系统调用获取信息），然后根据传入的组名、GID、用户名或 UID 进行查找。

**Go 代码举例说明 (假设的实现):**

```go
package user

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Group represents a group account.
type Group struct {
	Name string
	Gid  string
}

// User represents a user account.
type User struct {
	Username string
	Uid      string
	Gid      string
	Name     string
	HomeDir  string
}

type UnknownGroupError string

func (e UnknownGroupError) Error() string {
	return "group: unknown group " + string(e)
}

type UnknownGroupIdError string

func (e UnknownGroupIdError) Error() string {
	return "group: unknown groupid " + string(e)
}

type UnknownUserError string

func (e UnknownUserError) Error() string {
	return "user: unknown user " + string(e)
}

type UnknownUserIdError string

func (e UnknownUserIdError) Error() string {
	return "user: unknown userid " + string(e)
}

func findGroupName(name string, r io.Reader) (*Group, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == name {
			return &Group{Name: fields[0], Gid: fields[2]}, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, UnknownGroupError(name)
}

func findGroupId(gid string, r io.Reader) (*Group, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == gid {
			return &Group{Name: fields[0], Gid: fields[2]}, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, UnknownGroupIdError(gid)
}

func findUsername(username string, r io.Reader) (*User, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == username {
			return &User{Username: fields[0], Uid: fields[2], Gid: fields[3], Name: fields[4], HomeDir: fields[5]}, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, UnknownUserError(username)
}

func findUserId(uid string, r io.Reader) (*User, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[2] == uid {
			return &User{Username: fields[0], Uid: fields[2], Gid: fields[3], Name: fields[4], HomeDir: fields[5]}, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, UnknownUserIdError(uid)
}

func main() {
	groupFileContent := `nobody:x:-2:
kmem:x:2:
testgroup:x:1000:user1,user2
`
	reader := strings.NewReader(groupFileContent)
	group, err := findGroupName("kmem", reader)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Group Name: %s, GID: %s\n", group.Name, group.Gid) // Output: Group Name: kmem, GID: 2
	}

	reader = strings.NewReader(groupFileContent)
	group, err = findGroupId("1000", reader)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Group Name: %s, GID: %s\n", group.Name, group.Gid) // Output: Group Name: testgroup, GID: 1000
	}

	userFileContent := `root:x:0:0:root:/root:/bin/bash
testuser:x:1000:1000:Test User:/home/testuser:/bin/zsh
`
	reader = strings.NewReader(userFileContent)
	user, err := findUsername("testuser", reader)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Username: %s, UID: %s\n", user.Username, user.Uid) // Output: Username: testuser, UID: 1000
	}

	reader = strings.NewReader(userFileContent)
	user, err = findUserId("0", reader)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Username: %s, UID: %s\n", user.Username, user.Uid) // Output: Username: root, UID: 0
	}
}
```

**假设的输入与输出 (基于测试用例):**

以 `TestFindGroupName` 中的一个用例为例：

**假设输入:**

- `tt.in`:  `testGroupFile` 的内容，例如:
  ```
  nobody:x:-2:
  kmem:x:2:
  notinthefile:x:1000:
  # comment:x:1001:
  +plussign:x:1002:
  -minussign:x:1003:
  emptyid:x::
  invalidgid:x:abc:
  indented :x:7:
  # comment line
  largegroup:x:1000:user1,user2,user3
  manymembers:x:777:userA,userB,userC,userD
  ```
- `tt.name`: `"kmem"`

**预期输出:**

- `got`:  一个 `Group` 结构体，其 `Name` 为 `"kmem"`， `Gid` 为 `"2"`。
- `err`: `nil`

再以一个会产生错误的用例为例：

**假设输入:**

- `tt.in`: `testGroupFile` 的内容（同上）
- `tt.name`: `"notinthefile"`

**预期输出:**

- `got`: `nil`
- `err`: 一个 `UnknownGroupError` 类型的错误，其 `Error()` 方法返回 `"group: unknown group notinthefile"`。

**命令行参数的具体处理:**

这段测试代码本身 **不涉及** 命令行参数的处理。它专注于测试内部函数的逻辑，这些函数最终会被 `user.LookupGroup`, `user.LookupGroupId`, `user.Lookup`, `user.LookupId` 等更高级别的函数调用，而那些更高级别的函数可能会被使用命令行工具的程序调用。

例如，一个使用 `user.Lookup` 的命令行工具可能像这样：

```go
package main

import (
	"fmt"
	"os"
	"os/user"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: lookupuser <username>")
		return
	}
	username := os.Args[1]
	usr, err := user.Lookup(username)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Username: %s\n", usr.Username)
	fmt.Printf("UID: %s\n", usr.Uid)
	fmt.Printf("GID: %s\n", usr.Gid)
	fmt.Printf("Home Directory: %s\n", usr.HomeDir)
}
```

在这个例子中，命令行参数 `<username>` 会被 `os.Args[1]` 获取，然后传递给 `user.Lookup` 函数。

**使用者易犯错的点:**

1. **假设用户或组一定存在:** 使用者可能会直接调用 `user.Lookup` 或 `user.LookupId` 而不检查返回的错误。如果用户或组不存在，这些函数会返回错误，如果不处理，程序可能会崩溃或行为异常。

   ```go
   // 错误的做法
   usr, _ := user.Lookup("nonexistentuser")
   fmt.Println(usr.Username) // 如果用户不存在，usr 是 nil，会引发 panic

   // 正确的做法
   usr, err := user.Lookup("nonexistentuser")
   if err != nil {
       fmt.Println("Error looking up user:", err)
   } else {
       fmt.Println(usr.Username)
   }
   ```

2. **错误地处理数字类型的 ID:**  `user.LookupId` 和 `user.LookupGroupId` 接收的是字符串类型的 ID。使用者可能会错误地传递整数类型的 ID，导致编译错误或运行时错误（如果尝试将整数转换为字符串时出错）。

   ```go
   // 错误的做法
   uid := 1000
   usr, err := user.LookupId(uid) // 编译错误：cannot use uid (variable of type int) as type string in argument to user.LookupId

   // 正确的做法
   uidStr := "1000"
   usr, err := user.LookupId(uidStr)
   // ...
   ```

3. **依赖于特定的文件格式:** 虽然 `os/user` 包会处理 `/etc/passwd` 和 `/etc/group` 的常见格式，但使用者不应该假设所有 Unix 系统的这些文件都完全相同，特别是当涉及到非标准的配置或使用 NIS/LDAP 等服务时。在这些情况下，`os/user` 包的行为可能会有所不同。

总而言之，这段测试代码是 `os/user` 包在特定 Unix 系统上的单元测试，用于验证其查找用户和组信息的功能的正确性。它通过模拟文件内容和断言返回值来确保底层的查找函数能够按照预期工作。

Prompt: 
```
这是路径为go/src/os/user/lookup_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix && !android && !cgo && !darwin

package user

import (
	"reflect"
	"strings"
	"testing"
)

var groupTests = []struct {
	in   string
	name string
	gid  string
}{
	{testGroupFile, "nobody", "-2"},
	{testGroupFile, "kmem", "2"},
	{testGroupFile, "notinthefile", ""},
	{testGroupFile, "comment", ""},
	{testGroupFile, "plussign", ""},
	{testGroupFile, "+plussign", ""},
	{testGroupFile, "-minussign", ""},
	{testGroupFile, "minussign", ""},
	{testGroupFile, "emptyid", ""},
	{testGroupFile, "invalidgid", ""},
	{testGroupFile, "indented", "7"},
	{testGroupFile, "# comment", ""},
	{testGroupFile, "largegroup", "1000"},
	{testGroupFile, "manymembers", "777"},
	{"", "emptyfile", ""},
}

func TestFindGroupName(t *testing.T) {
	for _, tt := range groupTests {
		got, err := findGroupName(tt.name, strings.NewReader(tt.in))
		if tt.gid == "" {
			if err == nil {
				t.Errorf("findGroupName(%s): got nil error, expected err", tt.name)
				continue
			}
			switch terr := err.(type) {
			case UnknownGroupError:
				if terr.Error() != "group: unknown group "+tt.name {
					t.Errorf("findGroupName(%s): got %v, want %v", tt.name, terr, tt.name)
				}
			default:
				t.Errorf("findGroupName(%s): got unexpected error %v", tt.name, terr)
			}
		} else {
			if err != nil {
				t.Fatalf("findGroupName(%s): got unexpected error %v", tt.name, err)
			}
			if got.Gid != tt.gid {
				t.Errorf("findGroupName(%s): got gid %v, want %s", tt.name, got.Gid, tt.gid)
			}
			if got.Name != tt.name {
				t.Errorf("findGroupName(%s): got name %s, want %s", tt.name, got.Name, tt.name)
			}
		}
	}
}

var groupIdTests = []struct {
	in   string
	gid  string
	name string
}{
	{testGroupFile, "-2", "nobody"},
	{testGroupFile, "2", "kmem"},
	{testGroupFile, "notinthefile", ""},
	{testGroupFile, "comment", ""},
	{testGroupFile, "7", "indented"},
	{testGroupFile, "4", ""},
	{testGroupFile, "20", ""}, // row starts with a plus
	{testGroupFile, "21", ""}, // row starts with a minus
	{"", "emptyfile", ""},
}

func TestFindGroupId(t *testing.T) {
	for _, tt := range groupIdTests {
		got, err := findGroupId(tt.gid, strings.NewReader(tt.in))
		if tt.name == "" {
			if err == nil {
				t.Errorf("findGroupId(%s): got nil error, expected err", tt.gid)
				continue
			}
			switch terr := err.(type) {
			case UnknownGroupIdError:
				if terr.Error() != "group: unknown groupid "+tt.gid {
					t.Errorf("findGroupId(%s): got %v, want %v", tt.name, terr, tt.name)
				}
			default:
				t.Errorf("findGroupId(%s): got unexpected error %v", tt.name, terr)
			}
		} else {
			if err != nil {
				t.Fatalf("findGroupId(%s): got unexpected error %v", tt.name, err)
			}
			if got.Gid != tt.gid {
				t.Errorf("findGroupId(%s): got gid %v, want %s", tt.name, got.Gid, tt.gid)
			}
			if got.Name != tt.name {
				t.Errorf("findGroupId(%s): got name %s, want %s", tt.name, got.Name, tt.name)
			}
		}
	}
}

const testUserFile = `   # Example user file
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:3:bin:/bin:/usr/sbin/nologin
     indented:x:3:3:indented:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
negative:x:-5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
allfields:x:6:12:mansplit,man2,man3,man4:/home/allfields:/usr/sbin/nologin
+plussign:x:8:10:man:/var/cache/man:/usr/sbin/nologin
-minussign:x:9:10:man:/var/cache/man:/usr/sbin/nologin

malformed:x:27:12 # more:colons:after:comment

struid:x:notanumber:12 # more:colons:after:comment

# commented:x:28:12:commented:/var/cache/man:/usr/sbin/nologin
      # commentindented:x:29:12:commentindented:/var/cache/man:/usr/sbin/nologin

struid2:x:30:badgid:struid2name:/home/struid:/usr/sbin/nologin
`

var userIdTests = []struct {
	in   string
	uid  string
	name string
}{
	{testUserFile, "-5", "negative"},
	{testUserFile, "2", "bin"},
	{testUserFile, "100", ""}, // not in the file
	{testUserFile, "8", ""},   // plus sign, glibc doesn't find it
	{testUserFile, "9", ""},   // minus sign, glibc doesn't find it
	{testUserFile, "27", ""},  // malformed
	{testUserFile, "28", ""},  // commented out
	{testUserFile, "29", ""},  // commented out, indented
	{testUserFile, "3", "indented"},
	{testUserFile, "30", ""}, // the Gid is not valid, shouldn't match
	{"", "1", ""},
}

func TestInvalidUserId(t *testing.T) {
	_, err := findUserId("notanumber", strings.NewReader(""))
	if err == nil {
		t.Fatalf("findUserId('notanumber'): got nil error")
	}
	if want := "user: invalid userid notanumber"; err.Error() != want {
		t.Errorf("findUserId('notanumber'): got %v, want %s", err, want)
	}
}

func TestLookupUserId(t *testing.T) {
	for _, tt := range userIdTests {
		got, err := findUserId(tt.uid, strings.NewReader(tt.in))
		if tt.name == "" {
			if err == nil {
				t.Errorf("findUserId(%s): got nil error, expected err", tt.uid)
				continue
			}
			switch terr := err.(type) {
			case UnknownUserIdError:
				if want := "user: unknown userid " + tt.uid; terr.Error() != want {
					t.Errorf("findUserId(%s): got %v, want %v", tt.name, terr, want)
				}
			default:
				t.Errorf("findUserId(%s): got unexpected error %v", tt.name, terr)
			}
		} else {
			if err != nil {
				t.Fatalf("findUserId(%s): got unexpected error %v", tt.name, err)
			}
			if got.Uid != tt.uid {
				t.Errorf("findUserId(%s): got uid %v, want %s", tt.name, got.Uid, tt.uid)
			}
			if got.Username != tt.name {
				t.Errorf("findUserId(%s): got name %s, want %s", tt.name, got.Username, tt.name)
			}
		}
	}
}

func TestLookupUserPopulatesAllFields(t *testing.T) {
	u, err := findUsername("allfields", strings.NewReader(testUserFile))
	if err != nil {
		t.Fatal(err)
	}
	want := &User{
		Username: "allfields",
		Uid:      "6",
		Gid:      "12",
		Name:     "mansplit",
		HomeDir:  "/home/allfields",
	}
	if !reflect.DeepEqual(u, want) {
		t.Errorf("findUsername: got %#v, want %#v", u, want)
	}
}

var userTests = []struct {
	in   string
	name string
	uid  string
}{
	{testUserFile, "negative", "-5"},
	{testUserFile, "bin", "2"},
	{testUserFile, "notinthefile", ""},
	{testUserFile, "indented", "3"},
	{testUserFile, "plussign", ""},
	{testUserFile, "+plussign", ""},
	{testUserFile, "minussign", ""},
	{testUserFile, "-minussign", ""},
	{testUserFile, "   indented", ""},
	{testUserFile, "commented", ""},
	{testUserFile, "commentindented", ""},
	{testUserFile, "malformed", ""},
	{testUserFile, "# commented", ""},
	{"", "emptyfile", ""},
}

func TestLookupUser(t *testing.T) {
	for _, tt := range userTests {
		got, err := findUsername(tt.name, strings.NewReader(tt.in))
		if tt.uid == "" {
			if err == nil {
				t.Errorf("lookupUser(%s): got nil error, expected err", tt.uid)
				continue
			}
			switch terr := err.(type) {
			case UnknownUserError:
				if want := "user: unknown user " + tt.name; terr.Error() != want {
					t.Errorf("lookupUser(%s): got %v, want %v", tt.name, terr, want)
				}
			default:
				t.Errorf("lookupUser(%s): got unexpected error %v", tt.name, terr)
			}
		} else {
			if err != nil {
				t.Fatalf("lookupUser(%s): got unexpected error %v", tt.name, err)
			}
			if got.Uid != tt.uid {
				t.Errorf("lookupUser(%s): got uid %v, want %s", tt.name, got.Uid, tt.uid)
			}
			if got.Username != tt.name {
				t.Errorf("lookupUser(%s): got name %s, want %s", tt.name, got.Username, tt.name)
			}
		}
	}
}

"""



```