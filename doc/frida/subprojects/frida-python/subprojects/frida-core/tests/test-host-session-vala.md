Response:
### 功能归纳

该源代码文件是Frida动态插桩工具的一部分，主要用于测试Frida的`HostSession`功能。`HostSession`是Frida的核心组件之一，负责与目标进程进行交互，包括进程的附加、脚本注入、调试等功能。该文件通过一系列的测试用例来验证`HostSession`在不同场景下的行为，确保其功能的正确性和稳定性。

#### 主要功能模块

1. **服务提供者测试**：
   - `provider_available`：测试服务提供者是否可用。
   - `provider_unavailable`：测试服务提供者不可用时的行为。

2. **本地后端测试**：
   - `full-cycle`：测试完整的生命周期，包括进程的附加、脚本的创建、加载、卸载等。
   - `spawn-gating`：测试进程生成拦截功能。
   - `error-feedback`：测试错误反馈机制，确保在错误情况下能够正确返回错误信息。
   - `performance`：测试性能，确保在高负载情况下仍能正常工作。
   - `torture`：压力测试，确保在多次重复操作后系统仍然稳定。

3. **Fruity后端测试**：
   - `Plist`：测试Plist（属性列表）的构造和XML文档的转换。
   - `backend`：测试Fruity后端的功能。
   - `large-messages`：测试大消息的处理能力。
   - `Manual/lockdown`：手动测试iOS设备的锁定功能。
   - `Manual/Xpc/list` 和 `Manual/Xpc/launch`：测试XPC服务的列表和启动功能。

4. **Droidy后端测试**：
   - `backend`：测试Droidy后端的功能。
   - `injector`：测试Droidy注入器的功能。

5. **Linux后端测试**：
   - `backend`：测试Linux后端的功能。
   - `spawn`：测试进程生成功能。
   - `ChildGating`：测试子进程拦截功能，包括`fork`和`exec`系列函数的拦截。
   - `bad-exec` 和 `bad-then-good-exec`：测试错误执行路径的处理。

6. **Darwin后端测试**：
   - `backend`：测试Darwin（macOS/iOS）后端的功能。
   - `spawn-native` 和 `spawn-other`：测试本地和其他架构的进程生成功能。
   - `own-memory-ranges-should-be-cloaked`：测试内存范围的隐藏功能。
   - `ExitMonitor`：测试退出监控功能，确保不会死锁。
   - `UnwindSitter`：测试异常捕获功能，确保在Objective-C方法交换时能够捕获异常。
   - `ChildGating`：测试子进程拦截功能，包括`fork`和`exec`系列函数的拦截。

7. **FreeBSD后端测试**：
   - `backend`：测试FreeBSD后端的功能。
   - `spawn`：测试进程生成功能。
   - `ChildGating`：测试子进程拦截功能。

8. **Windows后端测试**：
   - `backend`：测试Windows后端的功能。
   - `spawn`：测试进程生成功能。
   - `ChildGating`：测试子进程拦截功能。

9. **资源泄漏测试**：
   - `resource-leaks`：测试资源泄漏，确保在多次操作后没有资源泄漏。

10. **连接性测试**：
    - `flawless`：测试无故障情况下的连接性。
    - `rx-without-ack`：测试接收消息但未确认的情况。
    - `tx-not-sent`：测试消息未发送的情况。
    - `tx-without-ack`：测试发送消息但未确认的情况。
    - `latency-should-be-nominal`：测试延迟是否在正常范围内。

11. **快速启动停止测试**：
    - `start-stop-fast`：测试快速启动和停止设备管理器的功能。

### 涉及二进制底层和Linux内核的举例

1. **Linux后端测试**：
   - `fork` 和 `exec` 系列函数的拦截：这些函数是Linux内核提供的系统调用，用于创建新进程和执行新程序。Frida通过拦截这些系统调用来实现子进程的拦截和控制。
   - `spawn`：测试进程生成功能，涉及Linux内核的`fork`和`execve`系统调用。

2. **Darwin后端测试**：
   - `posix_spawn`：这是macOS/iOS上的一个系统调用，用于创建新进程。Frida通过拦截这个系统调用来实现进程生成的控制。

### 使用LLDB复刻调试功能的示例

假设我们要复刻`Linux/spawn`测试用例的功能，可以使用LLDB来调试一个简单的进程生成过程。以下是一个使用LLDB的Python脚本示例：

```python
import lldb

def spawn_process(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.LaunchSimple(None, None, None)
    if process:
        print(f"Process spawned with PID: {process.GetProcessID()}")
    else:
        print("Failed to spawn process")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.spawn_process spawn')
    print('The "spawn" command has been installed.')

if __name__ == "__main__":
    debugger = lldb.SBDebugger.Create()
    __lldb_init_module(debugger, {})
```

这个脚本定义了一个`spawn`命令，用于启动一个进程并打印其PID。可以通过LLDB的Python接口来执行这个脚本，并观察进程的生成过程。

### 逻辑推理与假设输入输出

1. **`provider_available`测试**：
   - **输入**：无。
   - **输出**：断言服务提供者可用，且能够正确启动和停止。

2. **`error-feedback`测试**：
   - **输入**：一个不存在的路径或不可执行的文件路径。
   - **输出**：断言返回正确的错误信息，如“无法找到可执行文件”或“不支持的文件格式”。

3. **`performance`测试**：
   - **输入**：一个目标进程（如`loop64`）。
   - **输出**：断言附加、脚本加载和卸载的时间在合理范围内。

### 用户操作与调试线索

1. **用户操作**：
   - 用户启动Frida工具，并选择目标进程进行附加。
   - 用户注入脚本并观察输出。
   - 用户尝试生成新进程并拦截其执行。

2. **调试线索**：
   - 如果附加失败，可以检查目标进程是否存在，或者是否有权限附加。
   - 如果脚本注入失败，可以检查脚本语法是否正确，或者目标进程是否支持脚本注入。
   - 如果进程生成失败，可以检查系统调用是否被正确拦截，或者是否有权限生成新进程。

### 常见使用错误

1. **权限不足**：
   - 用户尝试附加到一个需要更高权限的进程时，可能会遇到权限不足的错误。例如，尝试附加到`root`用户运行的进程时，普通用户可能会失败。

2. **目标进程不存在**：
   - 用户尝试附加到一个不存在的进程时，会收到“进程未找到”的错误。

3. **脚本语法错误**：
   - 用户在注入脚本时，如果脚本语法错误，可能会导致脚本加载失败。

### 总结

该文件是Frida工具的核心测试文件之一，涵盖了从服务提供者到进程生成、脚本注入、错误处理等多个方面的测试。通过这些测试用例，Frida能够确保其在不同平台和场景下的稳定性和正确性。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/tests/test-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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