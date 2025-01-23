Response:
### 功能归纳

`test-host-session.vala` 是 Frida 动态插桩工具的核心测试文件之一，主要用于测试 Frida 的 `HostSession` 功能。`HostSession` 是 Frida 的核心组件之一，负责与目标进程进行交互，包括进程的注入、脚本的执行、调试等功能。该文件通过一系列的测试用例，验证了 Frida 在不同平台（如 Linux、Darwin、Windows 等）和不同后端（如 Local、Fruity、Droidy 等）下的行为。

以下是该文件的主要功能归纳：

1. **服务提供者测试**：
   - 测试服务提供者的可用性和不可用性。例如，`provider-available` 和 `provider-unavailable` 测试用例分别验证了服务提供者在启用和禁用时的行为。

2. **手动测试**：
   - 提供了一系列手动测试用例，用于验证 Frida 的核心功能，如进程注入、调试、性能测试等。例如，`full-cycle` 测试用例模拟了从进程注入到脚本执行的全流程。

3. **平台特定测试**：
   - 针对不同平台（如 Linux、Darwin、Windows 等）进行了特定的测试。例如，Linux 平台下的 `fork` 和 `exec` 系列测试用例验证了进程创建和执行的行为。

4. **子进程管理测试**：
   - 测试了子进程的管理功能，如 `fork`、`exec`、`spawn` 等。例如，`ChildGating/fork` 测试用例验证了在子进程创建时的行为。

5. **性能测试**：
   - 提供了性能测试用例，验证 Frida 在高负载下的表现。例如，`performance` 测试用例模拟了多次注入和脚本执行的过程，以测试系统的性能。

6. **错误反馈测试**：
   - 测试了 Frida 在遇到错误时的反馈机制。例如，`error-feedback` 测试用例验证了在注入失败或进程不存在时的错误提示。

7. **资源泄漏测试**：
   - 测试了 Frida 在多次注入和脚本执行后是否存在资源泄漏。例如，`resource-leaks` 测试用例通过对比资源使用情况来检测是否存在泄漏。

8. **连接性测试**：
   - 测试了 Frida 在不同网络策略下的连接性。例如，`flawless` 测试用例验证了在无干扰情况下的连接稳定性。

### 涉及二进制底层和 Linux 内核的示例

在 Linux 平台下，Frida 通过 `ptrace` 系统调用与目标进程进行交互。例如，`Linux/spawn` 测试用例会使用 `ptrace` 来注入代码并控制目标进程的执行。以下是一个简单的 `ptrace` 使用示例：

```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    pid_t child = fork();
    if (child == 0) {
        // 子进程
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    } else {
        // 父进程
        wait(NULL);
        printf("Child process is being traced.\n");
        ptrace(PTRACE_CONT, child, NULL, NULL);
    }
    return 0;
}
```

### 使用 LLDB 复刻调试功能的示例

假设我们想要复刻 `Linux/spawn` 测试用例中的调试功能，可以使用 LLDB 来调试目标进程。以下是一个简单的 LLDB Python 脚本示例，用于附加到目标进程并设置断点：

```python
import lldb

def attach_and_debug(pid):
    # 初始化 LLDB
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(True)
    
    # 附加到目标进程
    target = debugger.CreateTarget("")
    process = target.AttachToProcessWithID(lldb.SBListener(), pid)
    
    if process.IsValid():
        print(f"Attached to process {pid}")
        
        # 设置断点
        breakpoint = target.BreakpointCreateByName("main")
        if breakpoint.IsValid():
            print("Breakpoint set at 'main'")
        
        # 继续执行
        process.Continue()
    else:
        print(f"Failed to attach to process {pid}")

# 使用 PID 1234 进行调试
attach_and_debug(1234)
```

### 假设输入与输出

假设我们在 `Linux/spawn` 测试用例中注入了一个简单的脚本，该脚本会在目标进程中打印 "Hello, World!"。以下是假设的输入与输出：

- **输入**：目标进程的 PID 为 1234，注入的脚本为 `console.log("Hello, World!");`。
- **输出**：目标进程的控制台输出 "Hello, World!"。

### 用户常见的使用错误

1. **PID 错误**：用户可能输入了错误的 PID，导致无法附加到目标进程。例如，输入了一个不存在的 PID 或没有权限访问的 PID。
   - **错误示例**：`Error: Unable to find process with pid 9999`
   - **解决方法**：确保输入的 PID 是正确的，并且当前用户有权限访问该进程。

2. **脚本语法错误**：用户可能编写了错误的脚本语法，导致脚本无法正确执行。
   - **错误示例**：`SyntaxError: Unexpected token ';'`
   - **解决方法**：检查脚本语法，确保没有语法错误。

3. **资源泄漏**：用户可能没有正确释放资源，导致系统资源泄漏。
   - **错误示例**：系统内存使用量不断增加，最终导致系统崩溃。
   - **解决方法**：确保在使用完资源后正确释放，例如调用 `script.unload()` 和 `session.detach()`。

### 用户操作如何一步步到达这里

1. **启动 Frida**：用户启动 Frida 并选择目标进程。
2. **注入脚本**：用户编写并注入脚本到目标进程中。
3. **执行脚本**：脚本在目标进程中执行，用户观察输出或调试信息。
4. **调试与监控**：用户使用 Frida 的调试功能监控目标进程的行为，并根据需要进行调整。
5. **结束调试**：用户结束调试并释放资源，确保系统资源不被泄漏。

通过以上步骤，用户可以逐步使用 Frida 进行动态插桩和调试，最终到达 `test-host-session.vala` 中所描述的测试场景。
### 提示词
```
这是目录为frida/subprojects/frida-core/tests/test-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
namespace Frida.HostSessionTest {
	public static void add_tests () {
		GLib.Test.add_func ("/HostSession/Service/provider-available", () => {
			var h = new Harness ((h) => Service.provider_available.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Service/provider-unavailable", () => {
			var h = new Harness ((h) => Service.provider_unavailable.begin (h as Harness));
			h.run ();
		});

#if HAVE_LOCAL_BACKEND
		GLib.Test.add_func ("/HostSession/Manual/full-cycle", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.full_cycle.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/spawn-gating", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.spawn_gating.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/error-feedback", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.error_feedback.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/performance", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.performance.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/torture", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.torture.begin (h as Harness));
			h.run ();
		});
#endif

#if HAVE_FRUITY_BACKEND
		GLib.Test.add_func ("/HostSession/Fruity/Plist/can-construct-from-xml-document", () => {
			Fruity.Plist.can_construct_from_xml_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/Plist/to-xml-yields-complete-document", () => {
			Fruity.Plist.to_xml_yields_complete_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/backend", () => {
			var h = new Harness ((h) => Fruity.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/large-messages", () => {
			var h = new Harness ((h) => Fruity.large_messages.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/Manual/lockdown", () => {
			var h = new Harness ((h) => Fruity.Manual.lockdown.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/Manual/Xpc/list", () => {
			var h = new Harness ((h) => Fruity.Manual.Xpc.list.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/Manual/Xpc/launch", () => {
			var h = new Harness ((h) => Fruity.Manual.Xpc.launch.begin (h as Harness));
			h.run ();
		});
#endif

#if HAVE_DROIDY_BACKEND
		GLib.Test.add_func ("/HostSession/Droidy/backend", () => {
			var h = new Harness ((h) => Droidy.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Droidy/injector", () => {
			var h = new Harness ((h) => Droidy.injector.begin (h as Harness));
			h.run ();
		});
#endif

#if HAVE_LOCAL_BACKEND
#if LINUX
		GLib.Test.add_func ("/HostSession/Linux/backend", () => {
			var h = new Harness ((h) => Linux.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Linux/spawn", () => {
			var h = new Harness ((h) => Linux.spawn.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Linux/ChildGating/fork", () => {
			var h = new Harness ((h) => Linux.fork.begin (h as Harness));
			h.run ();
		});

		var fork_symbol_names = new string[] {
			"fork",
			"vfork",
		};
		var exec_symbol_names = new string[] {
			"execl",
			"execlp",
			"execle",
			"execv",
			"execvp",
			"execve",
		};
		if (Gum.Module.find_export_by_name (null, "execvpe") != 0) {
			exec_symbol_names += "execvpe";
		}
		foreach (var fork_symbol_name in fork_symbol_names) {
			foreach (var exec_symbol_name in exec_symbol_names) {
				var method = "%s+%s".printf (fork_symbol_name, exec_symbol_name);
				GLib.Test.add_data_func ("/HostSession/Linux/ChildGating/" + method, () => {
					var h = new Harness ((h) => Linux.fork_plus_exec.begin (h as Harness, method));
					h.run ();
				});
			}
		}

		GLib.Test.add_func ("/HostSession/Linux/ChildGating/bad-exec", () => {
			var h = new Harness ((h) => Linux.bad_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Linux/ChildGating/bad-then-good-exec", () => {
			var h = new Harness ((h) => Linux.bad_then_good_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Linux/Manual/spawn-android-app", () => {
			var h = new Harness ((h) => Linux.Manual.spawn_android_app.begin (h as Harness));
			h.run ();
		});
#endif

#if DARWIN
		GLib.Test.add_func ("/HostSession/Darwin/backend", () => {
			var h = new Harness ((h) => Darwin.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/spawn-native", () => {
			var h = new Harness ((h) => Darwin.spawn_native.begin (h as Harness));
			h.run ();
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/HostSession/Darwin/spawn-other", () => {
				var h = new Harness ((h) => Darwin.spawn_other.begin (h as Harness));
				h.run ();
			});
		}

		GLib.Test.add_func ("/HostSession/Darwin/spawn-without-attach-native", () => {
			var h = new Harness ((h) => Darwin.spawn_without_attach_native.begin (h as Harness));
			h.run ();
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/HostSession/Darwin/spawn-without-attach-other", () => {
				var h = new Harness ((h) => Darwin.spawn_without_attach_other.begin (h as Harness));
				h.run ();
			});
		}

		GLib.Test.add_func ("/HostSession/Darwin/own-memory-ranges-should-be-cloaked", () => {
			var h = new Harness ((h) => Darwin.own_memory_ranges_should_be_cloaked.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ExitMonitor/abort-from-js-thread-should-not-deadlock", () => {
			var h = new Harness ((h) => Darwin.ExitMonitor.abort_from_js_thread_should_not_deadlock.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/UnwindSitter/exceptions-on-swizzled-objc-methods-should-be-caught", () => {
			var h = new Harness ((h) =>
				Darwin.UnwindSitter.exceptions_on_swizzled_objc_methods_should_be_caught.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/UnwindSitter/exceptions-on-intercepted-objc-methods-should-be-caught", () => {
			var h = new Harness ((h) =>
				Darwin.UnwindSitter.exceptions_on_intercepted_objc_methods_should_be_caught.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/fork-native", () => {
			var h = new Harness ((h) => Darwin.fork_native.begin (h as Harness));
			h.run ();
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/HostSession/Darwin/ChildGating/fork-other", () => {
				var h = new Harness ((h) => Darwin.fork_other.begin (h as Harness));
				h.run ();
			});
		}

		var fork_symbol_names = new string[] {
			"fork",
			"vfork",
		};
		var exec_symbol_names = new string[] {
			"execl",
			"execlp",
			"execle",
			"execv",
			"execvp",
			"execve",
		};
		foreach (var fork_symbol_name in fork_symbol_names) {
			foreach (var exec_symbol_name in exec_symbol_names) {
				var method = "%s+%s".printf (fork_symbol_name, exec_symbol_name);
				GLib.Test.add_data_func ("/HostSession/Darwin/ChildGating/" + method, () => {
					var h = new Harness ((h) => Darwin.fork_plus_exec.begin (h as Harness, method));
					h.run ();
				});
			}
		}

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/bad-exec", () => {
			var h = new Harness ((h) => Darwin.bad_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/bad-then-good-exec", () => {
			var h = new Harness ((h) => Darwin.bad_then_good_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/posix-spawn", () => {
			var h = new Harness ((h) => Darwin.posix_spawn.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/posix-spawn+setexec", () => {
			var h = new Harness ((h) => Darwin.posix_spawn_plus_setexec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/Manual/cross-arch", () => {
			var h = new Harness ((h) => Darwin.Manual.cross_arch.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/Manual/spawn-ios-app", () => {
			var h = new Harness ((h) => Darwin.Manual.spawn_ios_app.begin (h as Harness));
			h.run ();
		});
#endif

#if FREEBSD
		GLib.Test.add_func ("/HostSession/FreeBSD/backend", () => {
			var h = new Harness ((h) => FreeBSD.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/FreeBSD/spawn", () => {
			var h = new Harness ((h) => FreeBSD.spawn.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/FreeBSD/ChildGating/fork", () => {
			var h = new Harness ((h) => FreeBSD.fork.begin (h as Harness));
			h.run ();
		});

		var fork_symbol_names = new string[] {
			"fork",
			"vfork",
		};
		var exec_symbol_names = new string[] {
			"execl",
			"execlp",
			"execle",
			"execv",
			"execvp",
			"execve",
		};
		foreach (var fork_symbol_name in fork_symbol_names) {
			foreach (var exec_symbol_name in exec_symbol_names) {
				var method = "%s+%s".printf (fork_symbol_name, exec_symbol_name);
				GLib.Test.add_data_func ("/HostSession/FreeBSD/ChildGating/" + method, () => {
					var h = new Harness ((h) => FreeBSD.fork_plus_exec.begin (h as Harness, method));
					h.run ();
				});
			}
		}

		GLib.Test.add_func ("/HostSession/FreeBSD/ChildGating/bad-exec", () => {
			var h = new Harness ((h) => FreeBSD.bad_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/FreeBSD/ChildGating/bad-then-good-exec", () => {
			var h = new Harness ((h) => FreeBSD.bad_then_good_exec.begin (h as Harness));
			h.run ();
		});
#endif

#if WINDOWS
		GLib.Test.add_func ("/HostSession/Windows/backend", () => {
			var h = new Harness ((h) => Windows.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Windows/spawn", () => {
			var h = new Harness ((h) => Windows.spawn.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Windows/ChildGating/create-process", () => {
			var h = new Harness ((h) => Windows.create_process.begin (h as Harness));
			h.run ();
		});
#endif

		GLib.Test.add_func ("/HostSession/resource-leaks", () => {
			var h = new Harness ((h) => resource_leaks.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Local/latency-should-be-nominal", () => {
			var h = new Harness ((h) => Local.latency_should_be_nominal.begin (h as Harness));
			h.run ();
		});
#endif // HAVE_LOCAL_BACKEND

		GLib.Test.add_func ("/HostSession/start-stop-fast", () => {
			var h = new Harness ((h) => start_stop_fast.begin (h as Harness));
			h.run ();
		});

#if HAVE_LOCAL_BACKEND && HAVE_SOCKET_BACKEND && !ANDROID
		Connectivity.Strategy[] strategies = new Connectivity.Strategy[] {
			SERVER,
		};
		if (GLib.Test.slow ())
			strategies += Connectivity.Strategy.PEER;

		foreach (var strategy in strategies) {
			string prefix = "/HostSession/Connectivity/" + ((strategy == SERVER) ? "Server" : "Peer");

			GLib.Test.add_data_func (prefix + "/flawless", () => {
				var h = new Harness ((h) => Connectivity.flawless.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/rx-without-ack", () => {
				var h = new Harness ((h) => Connectivity.rx_without_ack.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/tx-not-sent", () => {
				var h = new Harness ((h) => Connectivity.tx_not_sent.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/tx-without-ack", () => {
				var h = new Harness ((h) => Connectivity.tx_without_ack.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/latency-should-be-nominal", () => {
				var h = new Harness ((h) => Connectivity.latency_should_be_nominal.begin (h as Harness, strategy));
				h.run ();
			});
		}
#endif
	}

	namespace Service {

		private static async void provider_available (Harness h) {
			try {
				h.assert_no_providers_available ();
				var backend = new StubBackend ();
				h.service.add_backend (backend);
				yield h.process_events ();
				h.assert_no_providers_available ();

				yield h.service.start ();
				yield h.process_events ();
				h.assert_n_providers_available (1);

				yield h.service.stop ();
				h.service.remove_backend (backend);
			} catch (IOError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void provider_unavailable (Harness h) {
			try {
				var backend = new StubBackend ();
				h.service.add_backend (backend);
				yield h.service.start ();
				yield h.process_events ();
				h.assert_n_providers_available (1);

				backend.disable_provider ();
				h.assert_n_providers_available (0);

				yield h.service.stop ();
				h.service.remove_backend (backend);
			} catch (IOError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private class StubBackend : Object, HostSessionBackend {
			private StubProvider provider = new StubProvider ();

			public async void start (Cancellable? cancellable) {
				var source = new IdleSource ();
				source.set_callback (() => {
					provider_available (provider);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}

			public async void stop (Cancellable? cancellable) {
			}

			public void disable_provider () {
				provider_unavailable (provider);
			}
		}

		private class StubProvider : Object, HostSessionProvider {
			public string id {
				get { return "stub"; }
			}

			public string name {
				get { return "Stub"; }
			}

			public Variant? icon {
				get { return null; }
			}

			public HostSessionProviderKind kind {
				get { return HostSessionProviderKind.LOCAL; }
			}

			public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}

			public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}

			public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
					Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}
		}

#if HAVE_LOCAL_BACKEND
		namespace Manual {

			private static async void full_cycle (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					print ("\n\nUsing \"%s\"\n", device.name);

					var process = yield device.find_process_by_name ("Twitter");

					uint pid;
					if (process != null) {
						pid = process.pid;
					} else {
						var raw_pid = prompt ("Enter PID:");
						pid = (uint) int.parse (raw_pid);
					}

					print ("Attaching to pid %u...\n", pid);
					var session = yield device.attach (pid);

					var scripts = new Gee.ArrayList<Script> ();
					var done = false;

					new Thread<bool> ("input-worker", () => {
						while (true) {
							print (
								"1. Add script\n" +
								"2. Load script\n" +
								"3. Remove script\n" +
								"4. Enable debugger\n" +
								"5. Disable debugger\n"
							);

							var command = prompt (">");
							if (command == null)
								break;
							var choice = int.parse (command);

							switch (choice) {
								case 1:
									Idle.add (() => {
										add_script.begin (scripts, session);
										return false;
									});
									break;
								case 2:
								case 3:
								case 4:
								case 5: {
									var tokens = command.split(" ");
									if (tokens.length < 2) {
										printerr ("Missing argument\n");
										continue;
									}

									int64 raw_script_index;
									if (!int64.try_parse (tokens[1], out raw_script_index)) {
										printerr ("Invalid script index\n");
										continue;
									}
									var script_index = (int) raw_script_index;

									Idle.add (() => {
										switch (choice) {
											case 2:
												load_script.begin (script_index, scripts);
												break;
											case 3:
												remove_script.begin (script_index, scripts);
												break;
											case 4:
												enable_debugger.begin (script_index,
													scripts);
												break;
											case 5:
												disable_debugger.begin (script_index,
													scripts);
												break;
											default:
												assert_not_reached ();
										}
										return false;
									});
									break;
								}
								default:
									break;
							}
						}

						print ("\n\n");

						Idle.add (() => {
							done = true;
							return false;
						});

						return true;
					});

					while (!done)
						yield h.process_events ();

					h.done ();
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async Script? add_script (Gee.ArrayList<Script> container, Session session) {
				Script script;

				try {
					script = yield session.create_script ("""
						const puts = new NativeFunction(Module.getExportByName(null, 'puts'), 'int', ['pointer']);
						let i = 1;
						setInterval(() => {
						  puts(Memory.allocUtf8String('hello' + i++));
						}, 1000);
						""");

					script.message.connect ((message, data) => {
						print ("Got message: %s\n", message);
					});
				} catch (GLib.Error e) {
					printerr ("Unable to add script: %s\n", e.message);
					return null;
				}

				container.add (script);

				return script;
			}

			private static async void load_script (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				try {
					yield script.load ();
				} catch (GLib.Error e) {
					printerr ("Unable to remove script: %s\n", e.message);
				}
			}

			private static async void remove_script (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				container.remove_at (index);

				try {
					yield script.unload ();
				} catch (GLib.Error e) {
					printerr ("Unable to remove script: %s\n", e.message);
				}
			}

			private static async void enable_debugger (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				try {
					yield script.enable_debugger (5858);
				} catch (GLib.Error e) {
					printerr ("Unable to enable debugger: %s\n", e.message);
				}
			}

			private static async void disable_debugger (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				try {
					yield script.disable_debugger ();
				} catch (GLib.Error e) {
					printerr ("Unable to disable debugger: %s\n", e.message);
				}
			}

			private static bool get_script (int index, Gee.ArrayList<Script> container, out Script? script) {
				if (index < 0 || index >= container.size) {
					printerr ("Invalid script index\n");
					script = null;
					return false;
				}

				script = container[index];
				return true;
			}

			private static string prompt (string message) {
				stdout.printf ("%s ", message);
				stdout.flush ();
				return stdin.read_line ();
			}

			private static async void spawn_gating (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on an iOS or Android system> ");
					h.done ();
					return;
				}

				h.disable_timeout ();

				try {
					var main_loop = new MainLoop ();

					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var spawn_added_handler = device.spawn_added.connect ((spawn) => {
						print ("spawn-added: pid=%u identifier=%s\n", spawn.pid, spawn.identifier);
						perform_resume.begin (device, spawn.pid);
					});
					var timer = new Timer ();
					yield device.enable_spawn_gating ();
					print ("spawn gating enabled in %u ms\n", (uint) (timer.elapsed () * 1000.0));

					install_signal_handlers (main_loop);

					main_loop.run ();

					device.disconnect (spawn_added_handler);

					timer.reset ();
					yield device.disable_spawn_gating ();
					print ("spawn gating disabled in %u ms\n", (uint) (timer.elapsed () * 1000.0));

					timer.reset ();
					yield device_manager.close ();
					print ("manager closed in %u ms\n", (uint) (timer.elapsed () * 1000.0));

					h.done ();
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async void perform_resume (Device device, uint pid) {
				try {
					yield device.resume (pid);
				} catch (GLib.Error e) {
					printerr ("perform_resume(%u) failed: %s\n", pid, e.message);
				}
			}

#if WINDOWS
			private static void install_signal_handlers (MainLoop loop) {
			}
#else
			private static MainLoop current_main_loop = null;

			private static void install_signal_handlers (MainLoop loop) {
				current_main_loop = loop;
				Posix.signal (Posix.Signal.INT, on_stop_signal);
				Posix.signal (Posix.Signal.TERM, on_stop_signal);
			}

			private static void on_stop_signal (int sig) {
				stdout.flush ();
				Idle.add (() => {
					current_main_loop.quit ();
					return false;
				});
			}
#endif

			private static async void error_feedback (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					stdout.printf ("\n\nEnter an absolute path that does not exist: ");
					stdout.flush ();
					var inexistent_path = stdin.read_line ();
					try {
						stdout.printf ("Trying to spawn program at inexistent path '%s'...", inexistent_path);
						yield device.spawn (inexistent_path);
						assert_not_reached ();
					} catch (GLib.Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert_true (e is Error.EXECUTABLE_NOT_FOUND);
						assert_true (e.message == "Unable to find executable at '%s'".printf (inexistent_path));
					}

					stdout.printf ("\nEnter an absolute path that exists but is not a valid executable: ");
					stdout.flush ();
					var nonexec_path = stdin.read_line ();
					try {
						stdout.printf ("Trying to spawn program at non-executable path '%s'...", nonexec_path);
						yield device.spawn (nonexec_path);
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert_true (e is Error.EXECUTABLE_NOT_SUPPORTED);
						assert_true (e.message == "Unable to spawn executable at '%s': unsupported file format".printf (nonexec_path));
					}

					var processes = yield device.enumerate_processes ();
					uint inexistent_pid = 100000;
					bool exists = false;
					do {
						exists = false;
						var num_processes = processes.size ();
						for (var i = 0; i != num_processes && !exists; i++) {
							var process = processes.get (i);
							if (process.pid == inexistent_pid) {
								exists = true;
								inexistent_pid++;
							}
						}
					} while (exists);

					try {
						stdout.printf ("\nTrying to attach to inexistent pid %u...", inexistent_pid);
						stdout.flush ();
						yield device.attach (inexistent_pid);
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert_true (e is Error.PROCESS_NOT_FOUND);
						assert_true (e.message == "Unable to find process with pid %u".printf (inexistent_pid));
					}

					stdout.printf ("\nEnter PID of a process that you don't have access to: ");
					stdout.flush ();
					uint privileged_pid = (uint) int.parse (stdin.read_line ());

					try {
						stdout.printf ("Trying to attach to %u...", privileged_pid);
						stdout.flush ();
						yield device.attach (privileged_pid);
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n\n", e.message);
						assert_true (e is Error.PERMISSION_DENIED);
						assert_true (e.message == "Unable to access process with pid %u from the current user account".printf (privileged_pid));
					}

					yield device_manager.close ();

					h.done ();
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async void performance (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var process = yield device.get_process_by_name ("loop64");
					var pid = process.pid;

					var timer = new Timer ();

					stdout.printf ("\n");
					var num_iterations = 3;
					for (var i = 0; i != num_iterations; i++) {
						stdout.printf ("%u of %u\n", i + 1, num_iterations);
						stdout.flush ();

						timer.reset ();
						var session = yield device.attach (pid);
						print ("attach took %u ms\n", (uint) (timer.elapsed () * 1000.0));
						var script = yield session.create_script ("true;");
						yield script.load ();

						yield script.unload ();
						yield session.detach ();

						Timeout.add (250, performance.callback);
						yield;
					}

					yield device_manager.close ();

					h.done ();
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async void torture (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					stdout.printf ("\n\nUsing \"%s\"\n", device.name);

					var process = yield device.find_process_by_name ("SpringBoard");

					uint pid;
					if (process != null) {
						pid = process.pid;
					} else {
						stdout.printf ("Enter PID: ");
						stdout.flush ();
						pid = (uint) int.parse (stdin.read_line ());
					}

					stdout.printf ("\n");
					var num_iterations = 100;
					for (var i = 0; i != num_iterations; i++) {
						stdout.printf ("%u of %u\n", i + 1, num_iterations);
						stdout.flush ();
						var session = yield device.attach (pid);
						yield session.detach ();
					}

					yield device_manager.close ();

					h.done ();
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

		}
#endif // HAVE_LOCAL_BACKEND

	}

#if HAVE_LOCAL_BACKEND
	private static async void resource_leaks (Harness h) {
		try {
			var device_manager = new DeviceManager ();
			var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
			var process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable ("sleeper"));

			/* TODO: improve injectors to handle injection into a process that hasn't yet finished initializing */
			Thread.usleep (50000);

			/* Warm up static allocations */
			for (int i = 0; i != 2; i++) {
				var session = yield device.attach (process.id);
				var script = yield session.create_script ("true;");
				yield script.load ();
				yield script.unload ();
				script = null;
				yield detach_and_wait_for_cleanup (session);
				session = null;
			}

			var usage_before = process.snapshot_resource_usage ();

			for (var i = 0; i != 1; i++) {
				var session = yield device.attach (process.id);
				var script = yield session.create_script ("true;");
				yield script.load ();
				yield script.unload ();
				script = null;
				yield detach_and_wait_for_cleanup (session);
				session = null;

				var usage_after = process.snapshot_resource_usage ();

				usage_after.assert_equals (usage_before);
			}

			yield device_manager.close ();

			h.done ();
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		}
	}

	private static async void detach_and_wait_for_cleanup (Session session) throws Error, IOError {
		yield session.detach ();

		/* The Darwin injector does cleanup 50ms after detecting that the remote thread is dead */
		Timeout.add (100, detach_and_wait_for_cleanup.callback);
		yield;
	}

	namespace Local {

		private static async void latency_should_be_nominal (Harness h) {
			h.disable_timeout ();

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				yield Connectivity.measure_latency (h, device, SERVER);

				yield device_manager.close ();
			} catch (GLib.Error e) {
				printerr ("Oops: %s\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

	}
#endif // HAVE_LOCAL_BACKEND

	private static async void start_stop_fast (Harness h) {
		var device_manager = new DeviceManager ();
		device_manager.enumerate_devices.begin ();

		var timer = new Timer ();
		try {
			yield device_manager.close ();
		} catch (IOError e) {
			assert_not_reached ();
		}
		if (GLib.Test.verbose ()) {
			printerr ("close() took %u ms\n", (uint) (timer.elapsed () * 1000.0));
		}

		h.done ();
	}

#if HAVE_LOCAL_BACKEND
	namespace Connectivity {
		private enum Strategy {
			SERVER,
			PEER
		}

#if HAVE_SOCKET_BACKEND && !ANDROID
		private static async void flawless (Harness h, Strategy strategy) {
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => FORWARD, out seen_disruptions);
			assert (seen_disruptions == 0);
		}

		private static async void rx_without_ack (Harness h, Strategy strategy) {
			bool disrupted = false;
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => {
				if (message.get_message_type () == METHOD_CALL && message.get_member () == "PostMessages" &&
						direction == IN && !disrupted) {
					disrupted = true;
					return FORWARD_THEN_DISRUPT;
				}
				return FORWARD;
			}, out seen_disruptions);
			assert (seen_disruptions == 1);
		}

		private static async void tx_not_sent (Harness h, Strategy strategy) {
			bool disrupted = false;
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => {
				if (message.get_message_type () == METHOD_CALL && message.get_member () == "PostMessages" &&
						direction == OUT && !disrupted) {
					disrupted = true;
					return DISRUPT;
				}
				return FORWARD;
			}, out seen_disruptions);
			assert (seen_disruptions == 1);
		}

		private static async void tx_without_ack (Harness h, Strategy strategy) {
			bool disrupted = false;
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => {
				if (message.get_message_type () == METHOD_CALL && message.get_member () == "PostMessages" &&
						direction == OUT && !disrupted) {
					disrupted = true;
					return FORWARD_THEN_DISRUPT;
				}
				return FORWARD;
			}, out seen_disruptions);
			assert (seen_disruptions == 1);
		}

		private static async void run_reliability_scenario (Harness h, Strategy strategy, owned ChaosProxy.Inducer on_message,
				out uint seen_disruptions) {
			try {
				uint seen_detaches = 0;
				uint seen_messages = 0;
				var messages_summary = new StringBuilder ();
				bool waiting = false;

				ControlService control_service;
				uint16 control_port = 27042;
				while (true) {
					var ep = new EndpointParameters ("127.0.0.1", control_port);
					control_service = new ControlService (ep);
					try {
						yield control_service.start ();
						break;
					} catch (Error e) {
						if (e is Error.ADDRESS_IN_USE) {
							control_port++;
							continue;
						}
						throw e;
					}
				}

				var proxy = new ChaosProxy (control_port, (owned) on_message);
				yield proxy.start ();

				var device_manager = new DeviceManager ();
				var device = yield device_manager.add_remote_device ("127.0.0.1:%u".printf (proxy.proxy_port));

				var process = Frida.Test.Process.create (Frida.Test.Labrats.path_to_executable ("sleeper"));

				var options = new SessionOptions ();
				options.persist_timeout = 5
```