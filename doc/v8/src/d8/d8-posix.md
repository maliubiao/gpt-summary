Response: Let's break down the thought process for analyzing this C++ file and explaining its functionality and relation to JavaScript.

1. **Understand the Goal:** The primary goal is to summarize the functionality of the C++ file `d8-posix.cc` and illustrate its connection to JavaScript using examples. The filename itself gives a strong hint: "d8" is the name of V8's command-line shell, and "posix" suggests operating system interactions.

2. **Initial Scan for Key Functionalities:** Read through the file, paying attention to function names, included headers, and comments. Look for patterns and recurring themes. Keywords like `system`, `chdir`, `mkdir`, `setenv`, `socket`, etc., stand out.

3. **Identify Core Modules:** Notice the `#include` directives. These reveal the core POSIX APIs being used:
    * `<unistd.h>`: Basic system calls like `fork`, `execvp`, `pipe`, `close`, `chdir`, `rmdir`.
    * `<sys/wait.h>`:  Process management, `waitpid`.
    * `<sys/socket.h>` and `<netinet/ip.h>`: Network communication (specifically TCP).
    * `<sys/stat.h>`: File system information, `stat`, `mkdir`.
    * `<stdlib.h>`: General utilities, `getenv`, `setenv`, `unsetenv`.
    * `<signal.h>`: Signal handling, `kill`.
    * `<fcntl.h>`: File control, `fcntl`.
    * `<errno.h>`: Error reporting.
    * `<string.h>`: String manipulation, `strlen`, `memcpy`.
    * `<sys/time.h>` and `<sys/select.h>`: Time and I/O multiplexing.

4. **Group Functionalities:** Based on the included headers and function names, group the functionalities into logical categories:
    * **Process Execution:**  The `System` function is clearly the central piece here, involving `fork`, `execvp`, `pipe`, and managing child processes.
    * **File System Operations:** `ChangeDirectory`, `MakeDirectory`, `RemoveDirectory` directly map to file system manipulations.
    * **Environment Variables:** `SetEnvironment`, `UnsetEnvironment` are related to OS environment variables.
    * **Permissions:** `SetUMask` is about setting file creation masks.
    * **Network Communication:** `ReadCharsFromTcpPort` clearly deals with network requests.
    * **Utilities:**  Helper functions like `LengthWithoutIncompleteUtf8`, `WaitOnFD`, `TimeIsOut`, `v8_strerror` support the main functionalities.

5. **Analyze Key Functions in Detail:**  For the most important functions like `System`, examine the code flow:
    * **Argument Parsing:** How does it get the command and arguments?  Look for `info.GetIsolate()`, `info[i]`.
    * **Process Creation:** The `fork()` call is the key.
    * **Child Execution:**  `ExecSubprocess` shows the use of `execvp` to run the external program. Pipes are used for communication.
    * **Parent Monitoring:**  The parent process waits for the child and handles output. Look for `waitpid` or `waitid`.
    * **Error Handling:** How are errors from system calls reported back to the JavaScript environment?  `isolate->ThrowError`.
    * **Timeouts:** Notice the handling of `read_timeout` and `total_timeout`.

6. **Connect to JavaScript:**  Think about *why* these functionalities are in V8. The `d8` shell is a JavaScript environment. This C++ code provides a bridge between JavaScript and the underlying operating system. The `Shell::AddOSMethods` function explicitly registers these C++ functions as methods on a JavaScript object (likely `os`).

7. **Create JavaScript Examples:** For each major C++ function, devise a simple JavaScript example that demonstrates its use within the `d8` shell. Focus on clarity and showing the direct correlation. For `os.system`, show executing a simple command and capturing its output. For `os.chdir`, show changing the current directory.

8. **Structure the Explanation:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the major functionalities, explaining what each part does in C++.
    * Clearly state the relationship to JavaScript (bridging the gap to OS).
    * Provide concrete JavaScript examples for each key function.
    * Briefly mention the supporting utility functions.

9. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation. Ensure the JavaScript examples are correct and easy to understand. Make sure the connection between C++ and JavaScript is explicitly stated. For instance, explicitly mention how `Shell::System` becomes `os.system` in JavaScript.

Self-Correction Example during the process:

* **Initial thought:** "This file is just about running external commands."
* **Correction:**  A closer look reveals functions like `chdir`, `mkdir`, `setenv`. The file provides a broader set of OS interaction capabilities, not just command execution. Adjust the initial summary accordingly.

By following these steps, you can systematically analyze the C++ code and generate a comprehensive and understandable explanation of its functionality and its link to JavaScript within the V8 `d8` environment.
这个 C++ 源代码文件 `d8-posix.cc` 的主要功能是 **为 V8 的命令行工具 `d8` 提供与 POSIX 兼容操作系统进行交互的功能**。  它封装了一些常用的 POSIX 系统调用，并将其暴露给 JavaScript 环境，使得在 `d8` shell 中运行的 JavaScript 代码能够执行一些操作系统级别的操作。

**具体功能归纳:**

1. **执行外部命令 (`os.system`)**:  允许 JavaScript 代码执行操作系统命令，并可以获取命令的输出、返回值和超时控制。
2. **文件系统操作**:
    * **改变当前工作目录 (`os.chdir`)**: 允许 JavaScript 代码改变 `d8` 进程的当前工作目录。
    * **创建目录 (`os.mkdirp`)**:  允许 JavaScript 代码创建目录，如果父目录不存在，则会递归创建。
    * **删除目录 (`os.rmdir`)**: 允许 JavaScript 代码删除空目录。
3. **环境变量操作**:
    * **设置环境变量 (`os.setenv`)**: 允许 JavaScript 代码设置或修改环境变量。
    * **取消设置环境变量 (`os.unsetenv`)**: 允许 JavaScript 代码取消设置环境变量。
4. **权限控制**:
    * **设置文件创建掩码 (`os.umask`)**: 允许 JavaScript 代码设置 `d8` 进程的文件创建掩码。
5. **网络通信 (读取 TCP 端口)**:
    * **`ReadCharsFromTcpPort`**:  虽然不是直接通过 JavaScript 暴露，但它提供了一个从指定的 TCP 端口读取数据的功能。这通常用于测试或集成目的，例如从一个服务器读取文件内容。
6. **辅助功能**:
    * **`LengthWithoutIncompleteUtf8`**:  处理 UTF-8 编码的字符串，确保读取的字符串不会在 UTF-8 序列的中间截断。
    * **`WaitOnFD`**:  等待文件描述符可读，并支持超时。
    * **`TimeIsOut`**:  检查是否超时。
    * **`ZombieProtector`**:  防止子进程变成僵尸进程。
    * **`ExecArgs`**:  辅助构建传递给 `execvp` 的参数数组。

**它与 JavaScript 的功能关系，以及 JavaScript 举例说明:**

`d8-posix.cc` 中定义的 C++ 函数，通过 `Shell::AddOSMethods` 函数被注册到 JavaScript 的 `os` 对象上，使得 JavaScript 代码可以调用这些功能。

**JavaScript 示例:**

```javascript
// 假设在 d8 shell 中运行

// 执行外部命令并获取输出
let result = os.system('ls -l');
print(result);

// 执行带有参数的命令
let files = os.system('find', ['.', '-name', '*.js']);
print(files);

// 改变当前工作目录
print('Current directory:', os.system('pwd'));
os.chdir('/tmp');
print('Current directory after chdir:', os.system('pwd'));
os.chdir('-'); // 假设 "-" 代表回到之前的目录，实际可能需要记录

// 创建目录
os.mkdirp('/tmp/my_new_dir');

// 设置环境变量
os.setenv('MY_VAR', 'my_value');
print('Environment variable MY_VAR:', os.system('echo $MY_VAR'));

// 取消设置环境变量
os.unsetenv('MY_VAR');
print('Environment variable MY_VAR after unset:', os.system('echo $MY_VAR'));

// 设置 umask (注意 umask 返回的是之前的掩码)
let old_umask = os.umask(0022);
print('Old umask:', old_umask.toString(8)); // 以八进制显示
os.umask(old_umask); // 恢复之前的 umask
```

**代码逻辑简述:**

* **`Shell::System`**:  这个函数是 `os.system()` 的 C++ 实现。它使用 `fork()` 创建一个子进程，然后在子进程中使用 `execvp()` 执行指定的命令。父进程会等待子进程结束，并读取子进程的标准输出。  它还处理超时机制。
* **`Shell::ChangeDirectory`**:  这个函数是 `os.chdir()` 的 C++ 实现，直接调用了 POSIX 的 `chdir()` 系统调用。
* **`Shell::MakeDirectory`**:  这个函数是 `os.mkdirp()` 的 C++ 实现，它会调用 `mkdir()` 创建目录，并在父目录不存在时递归创建。
* **`Shell::SetEnvironment` 和 `Shell::UnsetEnvironment`**:  分别对应 `os.setenv()` 和 `os.unsetenv()`，它们调用 POSIX 的 `setenv()` 和 `unsetenv()` 系统调用。
* **`Shell::SetUMask`**:  对应 `os.umask()`，调用 POSIX 的 `umask()` 系统调用。
* **`ReadCharsFromTcpPort`**:  创建一个 socket 连接到指定的 TCP 端口，发送文件名，并接收文件内容。

**总结:**

`d8-posix.cc` 文件是 `d8` 工具与操作系统交互的关键桥梁，它通过封装 POSIX 系统调用，为 JavaScript 提供了执行系统级任务的能力，这在编写脚本、进行系统管理或测试时非常有用。它体现了 V8 引擎为了提供更全面的功能而与底层操作系统进行集成的设计思想。

### 提示词
```
这是目录为v8/src/d8/d8-posix.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2009 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <fcntl.h>

#include "src/d8/d8.h"

#ifndef V8_OS_ZOS
#include <netinet/ip.h>
#endif
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "include/v8-container.h"
#include "include/v8-template.h"

namespace v8 {

// If the buffer ends in the middle of a UTF-8 sequence then we return
// the length of the string up to but not including the incomplete UTF-8
// sequence.  If the buffer ends with a valid UTF-8 sequence then we
// return the whole buffer.
static int LengthWithoutIncompleteUtf8(char* buffer, int len) {
  int answer = len;
  // 1-byte encoding.
  static const int kUtf8SingleByteMask = 0x80;
  static const int kUtf8SingleByteValue = 0x00;
  // 2-byte encoding.
  static const int kUtf8TwoByteMask = 0xE0;
  static const int kUtf8TwoByteValue = 0xC0;
  // 3-byte encoding.
  static const int kUtf8ThreeByteMask = 0xF0;
  static const int kUtf8ThreeByteValue = 0xE0;
  // 4-byte encoding.
  static const int kUtf8FourByteMask = 0xF8;
  static const int kUtf8FourByteValue = 0xF0;
  // Subsequent bytes of a multi-byte encoding.
  static const int kMultiByteMask = 0xC0;
  static const int kMultiByteValue = 0x80;
  int multi_byte_bytes_seen = 0;
  while (answer > 0) {
    int c = buffer[answer - 1];
    // Ends in valid single-byte sequence?
    if ((c & kUtf8SingleByteMask) == kUtf8SingleByteValue) return answer;
    // Ends in one or more subsequent bytes of a multi-byte value?
    if ((c & kMultiByteMask) == kMultiByteValue) {
      multi_byte_bytes_seen++;
      answer--;
    } else {
      if ((c & kUtf8TwoByteMask) == kUtf8TwoByteValue) {
        if (multi_byte_bytes_seen >= 1) {
          return answer + 2;
        }
        return answer - 1;
      } else if ((c & kUtf8ThreeByteMask) == kUtf8ThreeByteValue) {
        if (multi_byte_bytes_seen >= 2) {
          return answer + 3;
        }
        return answer - 1;
      } else if ((c & kUtf8FourByteMask) == kUtf8FourByteValue) {
        if (multi_byte_bytes_seen >= 3) {
          return answer + 4;
        }
        return answer - 1;
      } else {
        return answer;  // Malformed UTF-8.
      }
    }
  }
  return 0;
}

// Suspends the thread until there is data available from the child process.
// Returns false on timeout, true on data ready.
static bool WaitOnFD(int fd, int read_timeout, int total_timeout,
                     const struct timeval& start_time) {
  fd_set readfds, writefds, exceptfds;
  struct timeval timeout;
  int gone = 0;
  if (total_timeout != -1) {
    struct timeval time_now;
    gettimeofday(&time_now, nullptr);
    time_t seconds = time_now.tv_sec - start_time.tv_sec;
    gone = static_cast<int>(seconds * 1000 +
                            (time_now.tv_usec - start_time.tv_usec) / 1000);
    if (gone >= total_timeout) return false;
  }
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_ZERO(&exceptfds);
  FD_SET(fd, &readfds);
  FD_SET(fd, &exceptfds);
  if (read_timeout == -1 ||
      (total_timeout != -1 && total_timeout - gone < read_timeout)) {
    read_timeout = total_timeout - gone;
  }
  timeout.tv_usec = (read_timeout % 1000) * 1000;
  timeout.tv_sec = read_timeout / 1000;
  int number_of_fds_ready = select(fd + 1, &readfds, &writefds, &exceptfds,
                                   read_timeout != -1 ? &timeout : nullptr);
  return number_of_fds_ready == 1;
}

// Checks whether we ran out of time on the timeout.  Returns true if we ran out
// of time, false if we still have time.
static bool TimeIsOut(const struct timeval& start_time, const int& total_time) {
  if (total_time == -1) return false;
  struct timeval time_now;
  gettimeofday(&time_now, nullptr);
  // Careful about overflow.
  int seconds = static_cast<int>(time_now.tv_sec - start_time.tv_sec);
  if (seconds > 100) {
    if (seconds * 1000 > total_time) return true;
    return false;
  }
  int useconds = static_cast<int>(time_now.tv_usec - start_time.tv_usec);
  if (seconds * 1000000 + useconds > total_time * 1000) {
    return true;
  }
  return false;
}

// A utility class that does a non-hanging waitpid on the child process if we
// bail out of the System() function early.  If you don't ever do a waitpid on
// a subprocess then it turns into one of those annoying 'zombie processes'.
class ZombieProtector {
 public:
  explicit ZombieProtector(int pid) : pid_(pid) {}
  ~ZombieProtector() {
    if (pid_ != 0) waitpid(pid_, nullptr, 0);
  }
  void ChildIsDeadNow() { pid_ = 0; }

 private:
  int pid_;
};

// A utility class that closes a file descriptor when it goes out of scope.
class OpenFDCloser {
 public:
  explicit OpenFDCloser(int fd) : fd_(fd) {}
  ~OpenFDCloser() { close(fd_); }

 private:
  int fd_;
};

// A utility class that takes the array of command arguments and puts then in an
// array of new[]ed UTF-8 C strings.  Deallocates them again when it goes out of
// scope.
class ExecArgs {
 public:
  ExecArgs() { exec_args_[0] = nullptr; }
  bool Init(Isolate* isolate, Local<Value> arg0, Local<Array> command_args) {
    String::Utf8Value prog(isolate, arg0);
    if (*prog == nullptr) {
      isolate->ThrowError(
          "os.system(): String conversion of program name failed");
      return false;
    }
    {
      size_t len = prog.length() + 3;
      char* c_arg = new char[len];
      snprintf(c_arg, len, "%s", *prog);
      exec_args_[0] = c_arg;
    }
    int i = 1;
    for (unsigned j = 0; j < command_args->Length(); i++, j++) {
      Local<Value> arg(
          command_args
              ->Get(isolate->GetCurrentContext(), Integer::New(isolate, j))
              .ToLocalChecked());
      String::Utf8Value utf8_arg(isolate, arg);
      if (*utf8_arg == nullptr) {
        exec_args_[i] = nullptr;  // Consistent state for destructor.
        isolate->ThrowError(
            "os.system(): String conversion of argument failed.");
        return false;
      }
      size_t len = utf8_arg.length() + 1;
      char* c_arg = new char[len];
      snprintf(c_arg, len, "%s", *utf8_arg);
      exec_args_[i] = c_arg;
    }
    exec_args_[i] = nullptr;
    return true;
  }
  ~ExecArgs() {
    for (unsigned i = 0; i < kMaxArgs; i++) {
      if (exec_args_[i] == nullptr) {
        return;
      }
      delete[] exec_args_[i];
      exec_args_[i] = nullptr;
    }
  }
  static const unsigned kMaxArgs = 1000;
  char* const* arg_array() const { return exec_args_; }
  const char* arg0() const { return exec_args_[0]; }

 private:
  char* exec_args_[kMaxArgs + 1];
};

// Gets the optional timeouts from the arguments to the system() call.
static bool GetTimeouts(const v8::FunctionCallbackInfo<v8::Value>& info,
                        int* read_timeout, int* total_timeout) {
  if (info.Length() > 3) {
    if (info[3]->IsNumber()) {
      *total_timeout = info[3]
                           ->Int32Value(info.GetIsolate()->GetCurrentContext())
                           .FromJust();
    } else {
      info.GetIsolate()->ThrowError("system: Argument 4 must be a number");
      return false;
    }
  }
  if (info.Length() > 2) {
    if (info[2]->IsNumber()) {
      *read_timeout = info[2]
                          ->Int32Value(info.GetIsolate()->GetCurrentContext())
                          .FromJust();
    } else {
      info.GetIsolate()->ThrowError("system: Argument 3 must be a number");
      return false;
    }
  }
  return true;
}

namespace {
v8::Local<v8::String> v8_strerror(v8::Isolate* isolate, int err) {
  return v8::String::NewFromUtf8(isolate, strerror(err)).ToLocalChecked();
}
}  // namespace

static const int kReadFD = 0;
static const int kWriteFD = 1;

// This is run in the child process after fork() but before exec().  It normally
// ends with the child process being replaced with the desired child program.
// It only returns if an error occurred.
static void ExecSubprocess(int* exec_error_fds, int* stdout_fds,
                           const ExecArgs& exec_args) {
  close(exec_error_fds[kReadFD]);  // Don't need this in the child.
  close(stdout_fds[kReadFD]);      // Don't need this in the child.
  close(1);                        // Close stdout.
  dup2(stdout_fds[kWriteFD], 1);   // Dup pipe fd to stdout.
  close(stdout_fds[kWriteFD]);     // Don't need the original fd now.
  fcntl(exec_error_fds[kWriteFD], F_SETFD, FD_CLOEXEC);
  execvp(exec_args.arg0(), exec_args.arg_array());
  // Only get here if the exec failed.  Write errno to the parent to tell
  // them it went wrong.  If it went well the pipe is closed.
  int err = errno;
  ssize_t bytes_written;
  do {
    bytes_written = write(exec_error_fds[kWriteFD], &err, sizeof(err));
  } while (bytes_written == -1 && errno == EINTR);
  // Return (and exit child process).
}

// Runs in the parent process.  Checks that the child was able to exec (closing
// the file desriptor), or reports an error if it failed.
static bool ChildLaunchedOK(Isolate* isolate, int* exec_error_fds) {
  ssize_t bytes_read;
  int err;
  do {
    bytes_read = read(exec_error_fds[kReadFD], &err, sizeof(err));
  } while (bytes_read == -1 && errno == EINTR);
  if (bytes_read != 0) {
    isolate->ThrowError(v8_strerror(isolate, err));
    return false;
  }
  return true;
}

// Accumulates the output from the child in a string handle.  Returns true if it
// succeeded or false if an exception was thrown.
static Local<Value> GetStdout(Isolate* isolate, int child_fd,
                              const struct timeval& start_time,
                              int read_timeout, int total_timeout) {
  Local<String> accumulator = String::Empty(isolate);

  int fullness = 0;
  static const int kStdoutReadBufferSize = 4096;
  char buffer[kStdoutReadBufferSize];

  if (fcntl(child_fd, F_SETFL, O_NONBLOCK) != 0) {
    return isolate->ThrowError(v8_strerror(isolate, errno));
  }

  int bytes_read;
  do {
    bytes_read = static_cast<int>(
        read(child_fd, buffer + fullness, kStdoutReadBufferSize - fullness));
    if (bytes_read == -1) {
      if (errno == EAGAIN) {
        if (!WaitOnFD(child_fd, read_timeout, total_timeout, start_time) ||
            (TimeIsOut(start_time, total_timeout))) {
          return isolate->ThrowError("Timed out waiting for output");
        }
        continue;
      } else if (errno == EINTR) {
        continue;
      } else {
        break;
      }
    }
    if (bytes_read + fullness > 0) {
      int length = bytes_read == 0 ? bytes_read + fullness
                                   : LengthWithoutIncompleteUtf8(
                                         buffer, bytes_read + fullness);
      Local<String> addition =
          String::NewFromUtf8(isolate, buffer, NewStringType::kNormal, length)
              .ToLocalChecked();
      accumulator = String::Concat(isolate, accumulator, addition);
      fullness = bytes_read + fullness - length;
      memcpy(buffer, buffer + length, fullness);
    }
  } while (bytes_read != 0);
  return accumulator;
}

// Modern Linux has the waitid call, which is like waitpid, but more useful
// if you want a timeout.  If we don't have waitid we can't limit the time
// waiting for the process to exit without losing the information about
// whether it exited normally.  In the common case this doesn't matter because
// we don't get here before the child has closed stdout and most programs don't
// do that before they exit.
//
// We're disabling usage of waitid in Mac OS X because it doesn't work for us:
// a parent process hangs on waiting while a child process is already a zombie.
// See http://code.google.com/p/v8/issues/detail?id=401.
#if defined(WNOWAIT) && !defined(ANDROID) && !defined(__APPLE__) && \
    !defined(__NetBSD__) && !defined(__Fuchsia__)
#if !defined(__FreeBSD__)
#define HAS_WAITID 1
#endif
#endif

// Get exit status of child.
static bool WaitForChild(Isolate* isolate, int pid,
                         ZombieProtector& child_waiter,
                         const struct timeval& start_time, int read_timeout,
                         int total_timeout) {
#ifdef HAS_WAITID

  siginfo_t child_info;
  child_info.si_pid = 0;
  int useconds = 1;
  // Wait for child to exit.
  while (child_info.si_pid == 0) {
    waitid(P_PID, pid, &child_info, WEXITED | WNOHANG | WNOWAIT);
    usleep(useconds);
    if (useconds < 1000000) useconds <<= 1;
    if ((read_timeout != -1 && useconds / 1000 > read_timeout) ||
        (TimeIsOut(start_time, total_timeout))) {
      isolate->ThrowError("Timed out waiting for process to terminate");
      kill(pid, SIGINT);
      return false;
    }
  }
  if (child_info.si_code == CLD_KILLED) {
    char message[999];
    snprintf(message, sizeof(message), "Child killed by signal %d",
             child_info.si_status);
    isolate->ThrowError(message);
    return false;
  }
  if (child_info.si_code == CLD_EXITED && child_info.si_status != 0) {
    char message[999];
    snprintf(message, sizeof(message), "Child exited with status %d",
             child_info.si_status);
    isolate->ThrowError(message);
    return false;
  }

#else  // No waitid call.

  int child_status;
  waitpid(pid, &child_status, 0);  // We hang here if the child doesn't exit.
  child_waiter.ChildIsDeadNow();
  if (WIFSIGNALED(child_status)) {
    char message[999];
    snprintf(message, sizeof(message), "Child killed by signal %d",
             WTERMSIG(child_status));
    isolate->ThrowError(message);
    return false;
  }
  if (WEXITSTATUS(child_status) != 0) {
    char message[999];
    int exit_status = WEXITSTATUS(child_status);
    snprintf(message, sizeof(message), "Child exited with status %d",
             exit_status);
    isolate->ThrowError(message);
    return false;
  }

#endif  // No waitid call.

  return true;
}

#undef HAS_WAITID

// Implementation of the system() function (see d8.h for details).
void Shell::System(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  HandleScope scope(info.GetIsolate());
  int read_timeout = -1;
  int total_timeout = -1;
  if (!GetTimeouts(info, &read_timeout, &total_timeout)) return;
  Local<Array> command_args;
  if (info.Length() > 1) {
    if (!info[1]->IsArray()) {
      info.GetIsolate()->ThrowError("system: Argument 2 must be an array");
      return;
    }
    command_args = info[1].As<Array>();
  } else {
    command_args = Array::New(info.GetIsolate(), 0);
  }
  if (command_args->Length() > ExecArgs::kMaxArgs) {
    info.GetIsolate()->ThrowError("Too many arguments to system()");
    return;
  }
  if (info.Length() < 1) {
    info.GetIsolate()->ThrowError("Too few arguments to system()");
    return;
  }

  struct timeval start_time;
  gettimeofday(&start_time, nullptr);

  ExecArgs exec_args;
  if (!exec_args.Init(info.GetIsolate(), info[0], command_args)) {
    return;
  }
  int exec_error_fds[2];
  int stdout_fds[2];

  if (pipe(exec_error_fds) != 0) {
    info.GetIsolate()->ThrowError("pipe syscall failed.");
    return;
  }
  if (pipe(stdout_fds) != 0) {
    info.GetIsolate()->ThrowError("pipe syscall failed.");
    return;
  }

  pid_t pid = fork();
  if (pid == 0) {  // Child process.
    ExecSubprocess(exec_error_fds, stdout_fds, exec_args);
    exit(1);
  }

  // Parent process.  Ensure that we clean up if we exit this function early.
  ZombieProtector child_waiter(pid);
  close(exec_error_fds[kWriteFD]);
  close(stdout_fds[kWriteFD]);
  OpenFDCloser error_read_closer(exec_error_fds[kReadFD]);
  OpenFDCloser stdout_read_closer(stdout_fds[kReadFD]);

  Isolate* isolate = info.GetIsolate();
  if (!ChildLaunchedOK(isolate, exec_error_fds)) return;

  Local<Value> accumulator = GetStdout(isolate, stdout_fds[kReadFD], start_time,
                                       read_timeout, total_timeout);
  if (accumulator->IsUndefined()) {
    kill(pid, SIGINT);  // On timeout, kill the subprocess.
    info.GetReturnValue().Set(accumulator);
    return;
  }

  if (!WaitForChild(isolate, pid, child_waiter, start_time, read_timeout,
                    total_timeout)) {
    return;
  }

  info.GetReturnValue().Set(accumulator);
}

void Shell::ChangeDirectory(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  if (info.Length() != 1) {
    info.GetIsolate()->ThrowError("chdir() takes one argument");
    return;
  }
  String::Utf8Value directory(info.GetIsolate(), info[0]);
  if (*directory == nullptr) {
    info.GetIsolate()->ThrowError(
        "os.chdir(): String conversion of argument failed.");
    return;
  }
  if (chdir(*directory) != 0) {
    info.GetIsolate()->ThrowError(v8_strerror(info.GetIsolate(), errno));
    return;
  }
}

void Shell::SetUMask(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  if (info.Length() != 1) {
    info.GetIsolate()->ThrowError("umask() takes one argument");
    return;
  }
  if (info[0]->IsNumber()) {
    int previous = umask(
        info[0]->Int32Value(info.GetIsolate()->GetCurrentContext()).FromJust());
    info.GetReturnValue().Set(previous);
    return;
  } else {
    info.GetIsolate()->ThrowError("umask() argument must be numeric");
    return;
  }
}

static bool CheckItsADirectory(Isolate* isolate, char* directory) {
  struct stat stat_buf;
  int stat_result = stat(directory, &stat_buf);
  if (stat_result != 0) {
    isolate->ThrowError(v8_strerror(isolate, errno));
    return false;
  }
  if ((stat_buf.st_mode & S_IFDIR) != 0) return true;
  isolate->ThrowError(v8_strerror(isolate, EEXIST));
  return false;
}

// Returns true for success.  Creates intermediate directories as needed.  No
// error if the directory exists already.
static bool mkdirp(Isolate* isolate, char* directory, mode_t mask) {
  int result = mkdir(directory, mask);
  if (result == 0) return true;
  if (errno == EEXIST) {
    return CheckItsADirectory(isolate, directory);
  } else if (errno == ENOENT) {  // Intermediate path element is missing.
    char* last_slash = strrchr(directory, '/');
    if (last_slash == nullptr) {
      isolate->ThrowError(v8_strerror(isolate, errno));
      return false;
    }
    *last_slash = 0;
    if (!mkdirp(isolate, directory, mask)) return false;
    *last_slash = '/';
    result = mkdir(directory, mask);
    if (result == 0) return true;
    if (errno == EEXIST) {
      return CheckItsADirectory(isolate, directory);
    }
    isolate->ThrowError(v8_strerror(isolate, errno));
    return false;
  } else {
    isolate->ThrowError(v8_strerror(isolate, errno));
    return false;
  }
}

void Shell::MakeDirectory(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  mode_t mask = 0777;
  if (info.Length() == 2) {
    if (info[1]->IsNumber()) {
      mask = info[1]
                 ->Int32Value(info.GetIsolate()->GetCurrentContext())
                 .FromJust();
    } else {
      info.GetIsolate()->ThrowError("mkdirp() second argument must be numeric");
      return;
    }
  } else if (info.Length() != 1) {
    info.GetIsolate()->ThrowError("mkdirp() takes one or two arguments");
    return;
  }
  String::Utf8Value directory(info.GetIsolate(), info[0]);
  if (*directory == nullptr) {
    info.GetIsolate()->ThrowError(
        "os.mkdirp(): String conversion of argument failed.");
    return;
  }
  mkdirp(info.GetIsolate(), *directory, mask);
}

void Shell::RemoveDirectory(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  if (info.Length() != 1) {
    info.GetIsolate()->ThrowError("rmdir() takes one arguments");
    return;
  }
  String::Utf8Value directory(info.GetIsolate(), info[0]);
  if (*directory == nullptr) {
    info.GetIsolate()->ThrowError(
        "os.rmdir(): String conversion of argument failed.");
    return;
  }
  rmdir(*directory);
}

void Shell::SetEnvironment(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  if (info.Length() != 2) {
    info.GetIsolate()->ThrowError("setenv() takes two arguments");
    return;
  }
  String::Utf8Value var(info.GetIsolate(), info[0]);
  String::Utf8Value value(info.GetIsolate(), info[1]);
  if (*var == nullptr) {
    info.GetIsolate()->ThrowError(
        "os.setenv(): String conversion of variable name failed.");
    return;
  }
  if (*value == nullptr) {
    info.GetIsolate()->ThrowError(
        "os.setenv(): String conversion of variable contents failed.");
    return;
  }
  setenv(*var, *value, 1);
}

void Shell::UnsetEnvironment(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  if (info.Length() != 1) {
    info.GetIsolate()->ThrowError("unsetenv() takes one argument");
    return;
  }
  String::Utf8Value var(info.GetIsolate(), info[0]);
  if (*var == nullptr) {
    info.GetIsolate()->ThrowError(
        "os.setenv(): String conversion of variable name failed.");
    return;
  }
  unsetenv(*var);
}

char* Shell::ReadCharsFromTcpPort(const char* name, int* size_out) {
  DCHECK_GE(Shell::options.read_from_tcp_port, 0);

  int sockfd = socket(PF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Failed to create IPv4 socket\n");
    return nullptr;
  }

  // Create an address for localhost:PORT where PORT is specified by the shell
  // option --read-from-tcp-port.
  sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(sockaddr_in));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  serv_addr.sin_port = htons(Shell::options.read_from_tcp_port);

  if (connect(sockfd, reinterpret_cast<sockaddr*>(&serv_addr),
              sizeof(serv_addr)) < 0) {
    fprintf(stderr, "Failed to connect to localhost:%d\n",
            Shell::options.read_from_tcp_port.get());
    close(sockfd);
    return nullptr;
  }

  // The file server follows the simple protocol for requesting and receiving
  // a file with a given filename:
  //
  //   REQUEST client -> server: {filename}"\0"
  //   RESPONSE server -> client: {4-byte file-length}{file contents}
  //
  // i.e. the request sends the filename with a null terminator, and response
  // sends the file contents by sending the length (as a 4-byte big-endian
  // value) and the contents.

  // If the file length is <0, there was an error sending the file, and the
  // rest of the response is undefined (and may, in the future, contain an error
  // message). The socket should be closed to avoid trying to interpret the
  // undefined data.

  // REQUEST
  // Send the filename.
  size_t sent_len = 0;
  size_t name_len = strlen(name) + 1;  // Includes the null terminator
  while (sent_len < name_len) {
    ssize_t sent_now = send(sockfd, name + sent_len, name_len - sent_len, 0);
    if (sent_now < 0) {
      fprintf(stderr, "Failed to send %s to localhost:%d\n", name,
              Shell::options.read_from_tcp_port.get());
      close(sockfd);
      return nullptr;
    }
    sent_len += sent_now;
  }

  // RESPONSE
  // Receive the file.
  ssize_t received = 0;

  // First, read the (zero-terminated) file length.
  uint32_t big_endian_file_length;
  received = recv(sockfd, &big_endian_file_length, 4, 0);
  // We need those 4 bytes to read off the file length.
  if (received < 4) {
    fprintf(stderr, "Failed to receive %s's length from localhost:%d\n", name,
            Shell::options.read_from_tcp_port.get());
    close(sockfd);
    return nullptr;
  }
  // Reinterpretet the received file length as a signed big-endian integer.
  int32_t file_length = base::bit_cast<int32_t>(htonl(big_endian_file_length));

  if (file_length < 0) {
    fprintf(stderr, "Received length %d for %s from localhost:%d\n",
            file_length, name, Shell::options.read_from_tcp_port.get());
    close(sockfd);
    return nullptr;
  }

  // Allocate the output array.
  char* chars = new char[file_length];

  // Now keep receiving and copying until the whole file is received.
  ssize_t total_received = 0;
  while (total_received < file_length) {
    received =
        recv(sockfd, chars + total_received, file_length - total_received, 0);
    if (received < 0) {
      fprintf(stderr, "Failed to receive %s from localhost:%d\n", name,
              Shell::options.read_from_tcp_port.get());
      close(sockfd);
      delete[] chars;
      return nullptr;
    }
    total_received += received;
  }

  close(sockfd);
  *size_out = file_length;
  return chars;
}

void Shell::AddOSMethods(Isolate* isolate, Local<ObjectTemplate> os_templ) {
  if (options.enable_os_system) {
    os_templ->Set(isolate, "system", FunctionTemplate::New(isolate, System));
  }
  os_templ->Set(isolate, "chdir",
                FunctionTemplate::New(isolate, ChangeDirectory));
  os_templ->Set(isolate, "setenv",
                FunctionTemplate::New(isolate, SetEnvironment));
  os_templ->Set(isolate, "unsetenv",
                FunctionTemplate::New(isolate, UnsetEnvironment));
  os_templ->Set(isolate, "umask", FunctionTemplate::New(isolate, SetUMask));
  os_templ->Set(isolate, "mkdirp",
                FunctionTemplate::New(isolate, MakeDirectory));
  os_templ->Set(isolate, "rmdir",
                FunctionTemplate::New(isolate, RemoveDirectory));
}

}  // namespace v8
```