Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first thing I notice is the `package user` declaration and the filename `lookup_windows.go`. This immediately suggests that this code deals with user and group information retrieval specifically on Windows systems within the Go `os/user` package.

2. **Scan for Key Functionalities:** I'll quickly scan the function names to get a high-level understanding of what the code does. Keywords like "lookup," "is," "get," and "list" are helpful. I see functions related to:
    * Domain membership (`isDomainJoined`)
    * Full name retrieval (`lookupFullName*`)
    * Profile directory (`getProfilesDirectory`)
    * Service accounts (`isServiceAccount`)
    * Account type validation (`isValidUserAccountType`, `isValidGroupAccountType`)
    * Username and domain lookup by SID (`lookupUsernameAndDomain`)
    * Home directory retrieval from the registry (`findHomeDirInRegistry`)
    * Group name lookup (`lookupGroupName`)
    * Listing groups for a user (`listGroupsForUsernameAndDomain`)
    * Creating `User` objects (`newUser`, `newUserFromSid`)
    * Retrieving the current user (`current`)
    * Handling impersonation (`runAsProcessOwner`, `getCurrentToken`)
    * Looking up user primary group (`lookupUserPrimaryGroup`)
    * Looking up users and groups by name and ID (`lookupUser`, `lookupUserId`, `lookupGroup`, `lookupGroupId`)
    * Listing groups a user belongs to (`listGroups`)

3. **Group Related Functions:** I'll group related functions to understand larger features. For instance, all the `lookupFullName*` functions seem to be about getting a user's full name, potentially using different approaches (domain, server). The `isValid*AccountType` functions are clearly related to validating account types.

4. **Identify Key Windows APIs:** I'll look for calls to the `syscall` and `internal/syscall/windows` packages. This is a strong indicator of interaction with the Windows API. I see calls like `syscall.NetGetJoinInformation`, `syscall.TranslateAccountName`, `syscall.NetUserGetInfo`, `windows.GetProfilesDirectory`, `windows.IsValidSid`, `syscall.LookupSID`, `windows.NetUserGetLocalGroups`, `syscall.OpenCurrentProcessToken`, `windows.GetUserName`, `windows.RevertToSelf`, `windows.ImpersonateLoggedOnUser`, `windows.OpenThreadToken`, `windows.GetTokenGroups`. Recognizing these APIs helps confirm the code's purpose and provides clues about its internal workings.

5. **Analyze Individual Functions (Deeper Dive):** Now I'll pick a few functions and analyze them in more detail.

    * **`isDomainJoined`:** This function is straightforward. It uses `syscall.NetGetJoinInformation` to check if the machine is joined to a domain. The return value of `status` is compared with `syscall.NetSetupDomainName`.

    * **`lookupFullName`:** This function demonstrates a fallback mechanism. It tries to get the full name from the domain first, then from a server, and finally defaults to the username. This suggests handling different scenarios or potential failures.

    * **`getProfilesDirectory`:** This function uses a loop and `windows.GetProfilesDirectory` with a growing buffer. This is a common pattern in Windows API programming to handle cases where the initial buffer is too small.

    * **`current`:** This is a crucial function. It uses `runAsProcessOwner` to handle potential impersonation issues. Inside the `runAsProcessOwner` block, it retrieves various user attributes (UID, GID, username, display name, home directory) using Windows API calls.

    * **`lookupUserPrimaryGroup`:** This function is interesting because it handles both domain-joined and non-domain-joined scenarios differently. For domain users, it assumes the primary group is "Domain Users." For others, it uses `syscall.NetUserGetInfo`.

6. **Infer Go Language Features:** Based on the code, I can infer the use of several Go features:
    * **Packages:** `package user`, `import` statements.
    * **Functions:**  Clearly defined functions with parameters and return values.
    * **Error Handling:**  Returning `error` values and checking for `nil`.
    * **String Manipulation:**  Using `syscall.UTF16PtrFromString` and `windows.UTF16PtrToString` for interacting with Windows APIs that use UTF-16 encoding.
    * **Unsafe Pointers:**  Using `unsafe.Pointer` for interacting with raw memory addresses returned by Windows API calls. This is often necessary when dealing with C-style APIs.
    * **Defer Statements:**  Ensuring resources (like allocated memory using `syscall.NetApiBufferFree` and handles using `Close()`) are released.
    * **Structs:**  Likely used in the `syscall` and `windows` packages to represent Windows data structures. The code uses type assertions like `(*syscall.UserInfo10)(unsafe.Pointer(p))`.
    * **Control Flow:** `if`, `else`, `switch`, `for` loops.
    * **Concurrency (Implicit):** The use of `runtime.LockOSThread` and `runtime.UnlockOSThread` in `runAsProcessOwner` hints at dealing with thread-specific resources, although explicit concurrency constructs like goroutines and channels are not present in this snippet.

7. **Construct Examples:**  With a good understanding of the functionality, I can now create example Go code to demonstrate how to use some of the inferred features (like `lookupUser`, `lookupUserId`). I'll also consider potential inputs and outputs to make the examples concrete.

8. **Identify Potential Pitfalls:**  Thinking about how a developer might misuse this code, I consider:
    * **Error Handling:**  Forgetting to check errors returned by the functions.
    * **Platform Specificity:**  Assuming this code works on non-Windows systems.
    * **Impersonation Issues:**  Not understanding the implications of running under different user contexts.

9. **Structure the Answer:** Finally, I'll organize my findings into a clear and structured answer, addressing each of the prompt's points: functionality, Go features with examples, code reasoning with inputs/outputs, and potential pitfalls. I'll use clear, concise language and provide specific code examples where applicable. I'll ensure the answer is in Chinese as requested.
这段代码是 Go 语言标准库 `os/user` 包在 Windows 平台下的实现部分，主要负责**查找和获取用户信息以及用户组信息**。

下面列举其主要功能：

1. **判断是否加入域 (Domain Joined):** `isDomainJoined()` 函数用于检查当前计算机是否加入了 Windows 域。
2. **查找用户的全名 (Full Name):**  `lookupFullNameDomain()`, `lookupFullNameServer()`, `lookupFullName()` 函数用于根据用户名和域信息查找用户的完整显示名称。它会尝试先从域中查找，如果失败则尝试从本地服务器查找，最后如果都失败，则返回用户名本身。
3. **获取用户配置文件的目录 (Profiles Directory):** `getProfilesDirectory()` 函数用于获取所有用户配置文件的根目录路径 (例如: `C:\Users`).
4. **判断是否为服务账户 (Service Account):** `isServiceAccount()` 函数判断给定的安全标识符 (SID) 是否属于预定义的系统服务账户 (例如: LocalSystem, LocalService, NetworkService)。
5. **校验账户类型 (Account Type):** `isValidUserAccountType()` 和 `isValidGroupAccountType()` 函数用于校验给定的 SID 类型是否是合法的用户账户类型或组账户类型。
6. **查找用户名和域名 (Username and Domain):** `lookupUsernameAndDomain()` 函数根据用户的 SID 查找其用户名和域名。
7. **在注册表中查找用户主目录 (Home Directory):** `findHomeDirInRegistry()` 函数尝试从 Windows 注册表中读取指定用户的 Home 目录路径。
8. **查找组名 (Group Name):** `lookupGroupName()` 函数根据组名查找其对应的 SID。
9. **列出用户所属的本地组 (Local Groups):** `listGroupsForUsernameAndDomain()` 函数根据用户名和域名列出该用户所属的本地组的 SID 列表。
10. **创建用户对象 (User Object):** `newUser()` 函数根据提供的用户信息创建一个 `User` 类型的对象。
11. **获取当前用户信息 (Current User Info):** `current()` 函数获取当前正在运行进程的用户信息。它使用 `runAsProcessOwner` 来确保在可能存在用户模拟的情况下也能正确获取进程所有者的信息。
12. **在进程所有者上下文中运行函数 (Run as Process Owner):** `runAsProcessOwner()` 函数允许在一个没有用户模拟的环境下执行给定的函数，并在执行完毕后恢复之前的用户模拟状态。这对于获取进程级别的安全上下文信息非常重要。
13. **获取当前令牌 (Current Token):** `getCurrentToken()` 函数获取当前线程的访问令牌，如果当前线程没有令牌，则获取进程的访问令牌。
14. **查找用户的主组 (Primary Group):** `lookupUserPrimaryGroup()` 函数根据用户名和域名查找用户的主组 SID。对于域用户，它通常是 "Domain Users" 组。
15. **根据 SID 创建用户对象 (User Object from SID):** `newUserFromSid()` 函数根据用户的 SID 创建一个 `User` 类型的对象。
16. **根据用户名查找用户 (Lookup User by Name):** `lookupUser()` 函数根据用户名查找用户信息。
17. **根据用户 ID 查找用户 (Lookup User by ID):** `lookupUserId()` 函数根据用户 SID 字符串查找用户信息。
18. **根据组名查找组 (Lookup Group by Name):** `lookupGroup()` 函数根据组名查找组信息。
19. **根据组 ID 查找组 (Lookup Group by ID):** `lookupGroupId()` 函数根据组 SID 字符串查找组信息。
20. **列出用户所属的所有组 (List Groups):** `listGroups()` 函数列出一个用户所属的所有组的 SID 列表，包括主组。对于当前用户，它会尝试直接从进程令牌中获取组信息以提高效率和可靠性。

**Go 语言功能的实现 (示例):**

这段代码主要实现了 Go 语言中 `os/user` 包提供的用户和组信息查询功能。例如，`user.Current()` 函数的实现就在这段代码的 `current()` 函数中。

```go
package main

import (
	"fmt"
	"os/user"
)

func main() {
	// 获取当前用户信息
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error getting current user:", err)
		return
	}
	fmt.Println("Current User:")
	fmt.Println("  Username:", currentUser.Username)
	fmt.Println("  Name:", currentUser.Name)
	fmt.Println("  UID:", currentUser.Uid)
	fmt.Println("  GID:", currentUser.Gid)
	fmt.Println("  HomeDir:", currentUser.HomeDir)

	// 根据用户名查找用户信息
	lookedUpUser, err := user.Lookup("Administrator") // 假设存在 Administrator 用户
	if err != nil {
		fmt.Println("Error looking up user:", err)
		return
	}
	fmt.Println("\nLooked Up User (Administrator):")
	fmt.Println("  Username:", lookedUpUser.Username)
	fmt.Println("  Name:", lookedUpUser.Name)
	fmt.Println("  UID:", lookedUpUser.Uid)
	fmt.Println("  GID:", lookedUpUser.Gid)
	fmt.Println("  HomeDir:", lookedUpUser.HomeDir)

	// 根据组名查找组信息
	lookedUpGroup, err := user.LookupGroup("Administrators") // 假设存在 Administrators 组
	if err != nil {
		fmt.Println("Error looking up group:", err)
		return
	}
	fmt.Println("\nLooked Up Group (Administrators):")
	fmt.Println("  Name:", lookedUpGroup.Name)
	fmt.Println("  Gid:", lookedUpGroup.Gid)

	// 列出当前用户所属的组
	groups, err := user.Current()
	if err != nil {
		fmt.Println("Error getting current user for group listing:", err)
		return
	}
	groupIDs, err := user.ListGroups(groups)
	if err != nil {
		fmt.Println("Error listing groups:", err)
		return
	}
	fmt.Println("\nCurrent User's Groups:")
	for _, gid := range groupIDs {
		fmt.Println("  GID:", gid)
	}
}
```

**假设的输入与输出：**

假设当前用户是 "testuser" 且属于 "Users" 组，且存在 "Administrator" 用户和 "Administrators" 组。

**输出：**

```
Current User:
  Username: TEST-PC\testuser
  Name: Test User  (假设的完整名称)
  UID: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-1001 (假设的 UID)
  GID: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-513 (假设的 GID，通常是 Domain Users 或 Users)
  HomeDir: C:\Users\testuser

Looked Up User (Administrator):
  Username: TEST-PC\Administrator
  Name: Administrator (内置账户)
  UID: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-500 (假设的 UID)
  GID: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-513 (假设的 GID)
  HomeDir: C:\Users\Administrator

Looked Up Group (Administrators):
  Name: Administrators
  Gid: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-544 (假设的 GID)

Current User's Groups:
  GID: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-513
  GID: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-545 (假设的 Users 组)
  ... (其他所属组的 GID)
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它主要通过调用 Windows API 来获取用户信息。  `os/user` 包提供的函数，如 `user.Lookup()` 和 `user.LookupGroup()`,  接收的是用户名或组名字符串作为参数，但这些参数不是从命令行直接传入的，而是由调用 `os/user` 包的代码提供的。

**使用者易犯错的点：**

1. **平台依赖性:**  这段代码是 Windows 特定的实现。如果你的代码需要在不同的操作系统上运行，你需要考虑使用 `os/user` 包提供的通用接口，Go 会根据不同的平台选择相应的实现。直接使用这段代码中的特定函数（如 `lookupFullNameServer`）会限制代码的可移植性。

   **错误示例:**

   ```go
   import "os/user"

   func main() {
       // 假设这段代码在 Linux 上运行
       fullName, err := user.lookupFullNameServer("server", "username") // 这在 Linux 上会出错
       if err != nil {
           // ...
       }
       // ...
   }
   ```

2. **错误处理:** 在调用 `os/user` 包的函数时，务必检查返回的 `error` 值。例如，如果尝试查找一个不存在的用户或组，`user.Lookup()` 或 `user.LookupGroup()` 会返回一个错误。

   **错误示例:**

   ```go
   import "os/user"
   import "fmt"

   func main() {
       u, _ := user.Lookup("nonexistentuser") // 忽略了错误
       fmt.Println(u.Username) // 可能会导致空指针解引用或其他未定义行为
   }
   ```

   **正确示例:**

   ```go
   import "os/user"
   import "fmt"

   func main() {
       u, err := user.Lookup("nonexistentuser")
       if err != nil {
           fmt.Println("Error looking up user:", err)
           return
       }
       fmt.Println(u.Username)
   }
   ```

3. **权限问题:** 某些操作，例如获取所有用户的列表或某些用户的详细信息，可能需要管理员权限。如果程序没有足够的权限，可能会导致错误。这段代码中 `runAsProcessOwner` 的使用就是为了在获取当前用户信息时处理潜在的权限问题。

这段代码是 `os/user` 包在 Windows 平台上的核心实现，它通过调用 Windows API 提供了获取用户和组信息的关键功能。理解其内部工作原理有助于更好地使用 Go 语言进行跨平台的用户管理操作。

Prompt: 
```
这是路径为go/src/os/user/lookup_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package user

import (
	"errors"
	"fmt"
	"internal/syscall/windows"
	"internal/syscall/windows/registry"
	"runtime"
	"syscall"
	"unsafe"
)

func isDomainJoined() (bool, error) {
	var domain *uint16
	var status uint32
	err := syscall.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		return false, err
	}
	syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))
	return status == syscall.NetSetupDomainName, nil
}

func lookupFullNameDomain(domainAndUser string) (string, error) {
	return syscall.TranslateAccountName(domainAndUser,
		syscall.NameSamCompatible, syscall.NameDisplay, 50)
}

func lookupFullNameServer(servername, username string) (string, error) {
	s, e := syscall.UTF16PtrFromString(servername)
	if e != nil {
		return "", e
	}
	u, e := syscall.UTF16PtrFromString(username)
	if e != nil {
		return "", e
	}
	var p *byte
	e = syscall.NetUserGetInfo(s, u, 10, &p)
	if e != nil {
		return "", e
	}
	defer syscall.NetApiBufferFree(p)
	i := (*syscall.UserInfo10)(unsafe.Pointer(p))
	return windows.UTF16PtrToString(i.FullName), nil
}

func lookupFullName(domain, username, domainAndUser string) (string, error) {
	joined, err := isDomainJoined()
	if err == nil && joined {
		name, err := lookupFullNameDomain(domainAndUser)
		if err == nil {
			return name, nil
		}
	}
	name, err := lookupFullNameServer(domain, username)
	if err == nil {
		return name, nil
	}
	// domain worked neither as a domain nor as a server
	// could be domain server unavailable
	// pretend username is fullname
	return username, nil
}

// getProfilesDirectory retrieves the path to the root directory
// where user profiles are stored.
func getProfilesDirectory() (string, error) {
	n := uint32(100)
	for {
		b := make([]uint16, n)
		e := windows.GetProfilesDirectory(&b[0], &n)
		if e == nil {
			return syscall.UTF16ToString(b), nil
		}
		if e != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", e
		}
		if n <= uint32(len(b)) {
			return "", e
		}
	}
}

func isServiceAccount(sid *syscall.SID) bool {
	if !windows.IsValidSid(sid) {
		// We don't accept SIDs from the public API, so this should never happen.
		// Better be on the safe side and validate anyway.
		return false
	}
	// The following RIDs are considered service user accounts as per
	// https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids and
	// https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts:
	// - "S-1-5-18": LocalSystem
	// - "S-1-5-19": LocalService
	// - "S-1-5-20": NetworkService
	if windows.GetSidSubAuthorityCount(sid) != windows.SID_REVISION ||
		windows.GetSidIdentifierAuthority(sid) != windows.SECURITY_NT_AUTHORITY {
		return false
	}
	switch windows.GetSidSubAuthority(sid, 0) {
	case windows.SECURITY_LOCAL_SYSTEM_RID,
		windows.SECURITY_LOCAL_SERVICE_RID,
		windows.SECURITY_NETWORK_SERVICE_RID:
		return true
	}
	return false
}

func isValidUserAccountType(sid *syscall.SID, sidType uint32) bool {
	switch sidType {
	case syscall.SidTypeUser:
		return true
	case syscall.SidTypeWellKnownGroup:
		return isServiceAccount(sid)
	}
	return false
}

func isValidGroupAccountType(sidType uint32) bool {
	switch sidType {
	case syscall.SidTypeGroup:
		return true
	case syscall.SidTypeWellKnownGroup:
		// Some well-known groups are also considered service accounts,
		// so isValidUserAccountType would return true for them.
		// We have historically allowed them in LookupGroup and LookupGroupId,
		// so don't treat them as invalid here.
		return true
	case syscall.SidTypeAlias:
		// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/7b2aeb27-92fc-41f6-8437-deb65d950921#gt_0387e636-5654-4910-9519-1f8326cf5ec0
		// SidTypeAlias should also be treated as a group type next to SidTypeGroup
		// and SidTypeWellKnownGroup:
		// "alias object -> resource group: A group object..."
		//
		// Tests show that "Administrators" can be considered of type SidTypeAlias.
		return true
	}
	return false
}

// lookupUsernameAndDomain obtains the username and domain for usid.
func lookupUsernameAndDomain(usid *syscall.SID) (username, domain string, sidType uint32, e error) {
	username, domain, sidType, e = usid.LookupAccount("")
	if e != nil {
		return "", "", 0, e
	}
	if !isValidUserAccountType(usid, sidType) {
		return "", "", 0, fmt.Errorf("user: should be user account type, not %d", sidType)
	}
	return username, domain, sidType, nil
}

// findHomeDirInRegistry finds the user home path based on the uid.
func findHomeDirInRegistry(uid string) (dir string, e error) {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+uid, registry.QUERY_VALUE)
	if e != nil {
		return "", e
	}
	defer k.Close()
	dir, _, e = k.GetStringValue("ProfileImagePath")
	if e != nil {
		return "", e
	}
	return dir, nil
}

// lookupGroupName accepts the name of a group and retrieves the group SID.
func lookupGroupName(groupname string) (string, error) {
	sid, _, t, e := syscall.LookupSID("", groupname)
	if e != nil {
		return "", e
	}
	if !isValidGroupAccountType(t) {
		return "", fmt.Errorf("lookupGroupName: should be group account type, not %d", t)
	}
	return sid.String()
}

// listGroupsForUsernameAndDomain accepts username and domain and retrieves
// a SID list of the local groups where this user is a member.
func listGroupsForUsernameAndDomain(username, domain string) ([]string, error) {
	// Check if both the domain name and user should be used.
	var query string
	joined, err := isDomainJoined()
	if err == nil && joined && len(domain) != 0 {
		query = domain + `\` + username
	} else {
		query = username
	}
	q, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		return nil, err
	}
	var p0 *byte
	var entriesRead, totalEntries uint32
	// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetlocalgroups
	// NetUserGetLocalGroups() would return a list of LocalGroupUserInfo0
	// elements which hold the names of local groups where the user participates.
	// The list does not follow any sorting order.
	err = windows.NetUserGetLocalGroups(nil, q, 0, windows.LG_INCLUDE_INDIRECT, &p0, windows.MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries)
	if err != nil {
		return nil, err
	}
	defer syscall.NetApiBufferFree(p0)
	if entriesRead == 0 {
		return nil, nil
	}
	entries := (*[1024]windows.LocalGroupUserInfo0)(unsafe.Pointer(p0))[:entriesRead:entriesRead]
	var sids []string
	for _, entry := range entries {
		if entry.Name == nil {
			continue
		}
		sid, err := lookupGroupName(windows.UTF16PtrToString(entry.Name))
		if err != nil {
			return nil, err
		}
		sids = append(sids, sid)
	}
	return sids, nil
}

func newUser(uid, gid, dir, username, domain string) (*User, error) {
	domainAndUser := domain + `\` + username
	name, e := lookupFullName(domain, username, domainAndUser)
	if e != nil {
		return nil, e
	}
	u := &User{
		Uid:      uid,
		Gid:      gid,
		Username: domainAndUser,
		Name:     name,
		HomeDir:  dir,
	}
	return u, nil
}

var (
	// unused variables (in this implementation)
	// modified during test to exercise code paths in the cgo implementation.
	userBuffer  = 0
	groupBuffer = 0
)

func current() (*User, error) {
	// Use runAsProcessOwner to ensure that we can access the process token
	// when calling syscall.OpenCurrentProcessToken if the current thread
	// is impersonating a different user. See https://go.dev/issue/68647.
	var usr *User
	err := runAsProcessOwner(func() error {
		t, e := syscall.OpenCurrentProcessToken()
		if e != nil {
			return e
		}
		defer t.Close()
		u, e := t.GetTokenUser()
		if e != nil {
			return e
		}
		pg, e := t.GetTokenPrimaryGroup()
		if e != nil {
			return e
		}
		uid, e := u.User.Sid.String()
		if e != nil {
			return e
		}
		gid, e := pg.PrimaryGroup.String()
		if e != nil {
			return e
		}
		dir, e := t.GetUserProfileDirectory()
		if e != nil {
			return e
		}
		username, e := windows.GetUserName(syscall.NameSamCompatible)
		if e != nil {
			return e
		}
		displayName, e := windows.GetUserName(syscall.NameDisplay)
		if e != nil {
			// Historically, the username is used as fallback
			// when the display name can't be retrieved.
			displayName = username
		}
		usr = &User{
			Uid:      uid,
			Gid:      gid,
			Username: username,
			Name:     displayName,
			HomeDir:  dir,
		}
		return nil
	})
	return usr, err
}

// runAsProcessOwner runs f in the context of the current process owner,
// that is, removing any impersonation that may be in effect before calling f,
// and restoring the impersonation afterwards.
func runAsProcessOwner(f func() error) error {
	var impersonationRollbackErr error
	runtime.LockOSThread()
	defer func() {
		// If impersonation failed, the thread is running with the wrong token,
		// so it's better to terminate it.
		// This is achieved by not calling runtime.UnlockOSThread.
		if impersonationRollbackErr != nil {
			println("os/user: failed to revert to previous token:", impersonationRollbackErr.Error())
			runtime.Goexit()
		} else {
			runtime.UnlockOSThread()
		}
	}()
	prevToken, isProcessToken, err := getCurrentToken()
	if err != nil {
		return fmt.Errorf("os/user: failed to get current token: %w", err)
	}
	defer prevToken.Close()
	if !isProcessToken {
		if err = windows.RevertToSelf(); err != nil {
			return fmt.Errorf("os/user: failed to revert to self: %w", err)
		}
		defer func() {
			impersonationRollbackErr = windows.ImpersonateLoggedOnUser(prevToken)
		}()
	}
	return f()
}

// getCurrentToken returns the current thread token, or
// the process token if the thread doesn't have a token.
func getCurrentToken() (t syscall.Token, isProcessToken bool, err error) {
	thread, _ := windows.GetCurrentThread()
	// Need TOKEN_DUPLICATE and TOKEN_IMPERSONATE to use the token in ImpersonateLoggedOnUser.
	err = windows.OpenThreadToken(thread, syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE|syscall.TOKEN_IMPERSONATE, true, &t)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		// Not impersonating, use the process token.
		isProcessToken = true
		t, err = syscall.OpenCurrentProcessToken()
	}
	return t, isProcessToken, err
}

// lookupUserPrimaryGroup obtains the primary group SID for a user using this method:
// https://support.microsoft.com/en-us/help/297951/how-to-use-the-primarygroupid-attribute-to-find-the-primary-group-for
// The method follows this formula: domainRID + "-" + primaryGroupRID
func lookupUserPrimaryGroup(username, domain string) (string, error) {
	// get the domain RID
	sid, _, t, e := syscall.LookupSID("", domain)
	if e != nil {
		return "", e
	}
	if t != syscall.SidTypeDomain {
		return "", fmt.Errorf("lookupUserPrimaryGroup: should be domain account type, not %d", t)
	}
	domainRID, e := sid.String()
	if e != nil {
		return "", e
	}
	// If the user has joined a domain use the RID of the default primary group
	// called "Domain Users":
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	// SID: S-1-5-21domain-513
	//
	// The correct way to obtain the primary group of a domain user is
	// probing the user primaryGroupID attribute in the server Active Directory:
	// https://learn.microsoft.com/en-us/windows/win32/adschema/a-primarygroupid
	//
	// Note that the primary group of domain users should not be modified
	// on Windows for performance reasons, even if it's possible to do that.
	// The .NET Developer's Guide to Directory Services Programming - Page 409
	// https://books.google.bg/books?id=kGApqjobEfsC&lpg=PA410&ots=p7oo-eOQL7&dq=primary%20group%20RID&hl=bg&pg=PA409#v=onepage&q&f=false
	joined, err := isDomainJoined()
	if err == nil && joined {
		return domainRID + "-513", nil
	}
	// For non-domain users call NetUserGetInfo() with level 4, which
	// in this case would not have any network overhead.
	// The primary group should not change from RID 513 here either
	// but the group will be called "None" instead:
	// https://www.adampalmer.me/iodigitalsec/2013/08/10/windows-null-session-enumeration/
	// "Group 'None' (RID: 513)"
	u, e := syscall.UTF16PtrFromString(username)
	if e != nil {
		return "", e
	}
	d, e := syscall.UTF16PtrFromString(domain)
	if e != nil {
		return "", e
	}
	var p *byte
	e = syscall.NetUserGetInfo(d, u, 4, &p)
	if e != nil {
		return "", e
	}
	defer syscall.NetApiBufferFree(p)
	i := (*windows.UserInfo4)(unsafe.Pointer(p))
	return fmt.Sprintf("%s-%d", domainRID, i.PrimaryGroupID), nil
}

func newUserFromSid(usid *syscall.SID) (*User, error) {
	username, domain, sidType, e := lookupUsernameAndDomain(usid)
	if e != nil {
		return nil, e
	}
	uid, e := usid.String()
	if e != nil {
		return nil, e
	}
	var gid string
	if sidType == syscall.SidTypeWellKnownGroup {
		// The SID does not contain a domain; this function's domain variable has
		// been populated with the SID's identifier authority. This happens with
		// special service user accounts such as "NT AUTHORITY\LocalSystem".
		// In this case, gid is the same as the user SID.
		gid = uid
	} else {
		gid, e = lookupUserPrimaryGroup(username, domain)
		if e != nil {
			return nil, e
		}
	}
	// If this user has logged in at least once their home path should be stored
	// in the registry under the specified SID. References:
	// https://social.technet.microsoft.com/wiki/contents/articles/13895.how-to-remove-a-corrupted-user-profile-from-the-registry.aspx
	// https://support.asperasoft.com/hc/en-us/articles/216127438-How-to-delete-Windows-user-profiles
	//
	// The registry is the most reliable way to find the home path as the user
	// might have decided to move it outside of the default location,
	// (e.g. C:\users). Reference:
	// https://answers.microsoft.com/en-us/windows/forum/windows_7-security/how-do-i-set-a-home-directory-outside-cusers-for-a/aed68262-1bf4-4a4d-93dc-7495193a440f
	dir, e := findHomeDirInRegistry(uid)
	if e != nil {
		// If the home path does not exist in the registry, the user might
		// have not logged in yet; fall back to using getProfilesDirectory().
		// Find the username based on a SID and append that to the result of
		// getProfilesDirectory(). The domain is not relevant here.
		dir, e = getProfilesDirectory()
		if e != nil {
			return nil, e
		}
		dir += `\` + username
	}
	return newUser(uid, gid, dir, username, domain)
}

func lookupUser(username string) (*User, error) {
	sid, _, t, e := syscall.LookupSID("", username)
	if e != nil {
		return nil, e
	}
	if !isValidUserAccountType(sid, t) {
		return nil, fmt.Errorf("user: should be user account type, not %d", t)
	}
	return newUserFromSid(sid)
}

func lookupUserId(uid string) (*User, error) {
	sid, e := syscall.StringToSid(uid)
	if e != nil {
		return nil, e
	}
	return newUserFromSid(sid)
}

func lookupGroup(groupname string) (*Group, error) {
	sid, err := lookupGroupName(groupname)
	if err != nil {
		return nil, err
	}
	return &Group{Name: groupname, Gid: sid}, nil
}

func lookupGroupId(gid string) (*Group, error) {
	sid, err := syscall.StringToSid(gid)
	if err != nil {
		return nil, err
	}
	groupname, _, t, err := sid.LookupAccount("")
	if err != nil {
		return nil, err
	}
	if !isValidGroupAccountType(t) {
		return nil, fmt.Errorf("lookupGroupId: should be group account type, not %d", t)
	}
	return &Group{Name: groupname, Gid: gid}, nil
}

func listGroups(user *User) ([]string, error) {
	var sids []string
	if u, err := Current(); err == nil && u.Uid == user.Uid {
		// It is faster and more reliable to get the groups
		// of the current user from the current process token.
		err := runAsProcessOwner(func() error {
			t, err := syscall.OpenCurrentProcessToken()
			if err != nil {
				return err
			}
			defer t.Close()
			groups, err := windows.GetTokenGroups(t)
			if err != nil {
				return err
			}
			for _, g := range groups.AllGroups() {
				sid, err := g.Sid.String()
				if err != nil {
					return err
				}
				sids = append(sids, sid)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		sid, err := syscall.StringToSid(user.Uid)
		if err != nil {
			return nil, err
		}
		username, domain, _, err := lookupUsernameAndDomain(sid)
		if err != nil {
			return nil, err
		}
		sids, err = listGroupsForUsernameAndDomain(username, domain)
		if err != nil {
			return nil, err
		}
	}
	// Add the primary group of the user to the list if it is not already there.
	// This is done only to comply with the POSIX concept of a primary group.
	for _, sid := range sids {
		if sid == user.Gid {
			return sids, nil
		}
	}
	return append(sids, user.Gid), nil
}

"""



```