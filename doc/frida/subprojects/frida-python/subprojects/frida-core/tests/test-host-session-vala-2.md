Response:
### 功能归纳

该文件是 Frida 动态插桩工具的一部分，主要用于测试 Frida 的核心功能，特别是与进程管理、插桩、调试相关的功能。以下是该文件的主要功能归纳：

1. **进程管理与调试**：
   - 该文件包含了多个测试用例，用于验证 Frida 在不同操作系统（如 macOS、iOS、FreeBSD、Windows 等）上的进程管理功能。这些功能包括进程的创建、挂起、恢复、终止等。
   - 通过 `Interceptor.attach` 方法，Frida 可以在目标进程的特定函数调用时插入自定义代码，从而实现动态插桩和调试。

2. **进程间通信与消息传递**：
   - 该文件测试了 Frida 的进程间通信机制，特别是通过 `send` 和 `message` 事件在脚本和宿主之间传递消息的功能。
   - 例如，`script.message.connect` 用于监听脚本发送的消息，并在接收到消息时触发回调函数。

3. **子进程管理**：
   - 该文件测试了 Frida 对子进程的管理能力，特别是 `fork` 和 `exec` 系统调用的处理。Frida 能够捕获子进程的创建事件，并在子进程中执行插桩操作。
   - 例如，`device.child_added.connect` 用于监听子进程的创建事件，并在子进程创建时触发回调函数。

4. **异常处理与进程终止**：
   - 该文件测试了 Frida 在进程异常终止时的处理能力。例如，当进程调用 `abort` 或 `exit` 时，Frida 能够捕获这些事件并执行相应的处理逻辑。
   - 例如，`Interceptor.attach(Module.getExportByName(null, 'abort'))` 用于捕获 `abort` 函数的调用，并在调用时发送消息。

5. **跨架构调试**：
   - 该文件还测试了 Frida 在跨架构调试场景下的表现。例如，在 macOS 上调试 iOS 应用程序时，Frida 能够正确处理跨架构的调试请求。

### 二进制底层与 Linux 内核相关

该文件涉及到的二进制底层操作和 Linux 内核相关的功能主要包括：

1. **系统调用拦截**：
   - 通过 `Interceptor.attach`，Frida 能够拦截目标进程中的系统调用（如 `abort`、`exit` 等），并在调用时执行自定义代码。这种功能依赖于对目标进程的内存空间的直接操作，通常需要与操作系统内核进行交互。

2. **进程创建与终止**：
   - Frida 能够捕获进程的创建和终止事件，特别是通过 `fork` 和 `exec` 系统调用创建的子进程。这些操作涉及到操作系统的进程管理机制，Frida 通过内核提供的接口（如 `ptrace`）来实现对这些事件的捕获。

3. **内存操作**：
   - Frida 能够直接操作目标进程的内存空间，例如通过 `Module.getExportByName` 获取函数地址，并通过 `Interceptor.attach` 在函数调用时插入自定义代码。这种操作需要对目标进程的内存布局有深入的了解，并且需要与操作系统的内存管理机制进行交互。

### LLDB 调试示例

假设我们想要使用 LLDB 来复现 Frida 的调试功能，以下是一个简单的 LLDB Python 脚本示例，用于在目标进程中拦截 `abort` 函数的调用：

```python
import lldb

def intercept_abort(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    
    # 获取 abort 函数的地址
    abort_symbol = target.FindSymbols('abort').GetSymbolAtIndex(0)
    abort_address = abort_symbol.GetStartAddress()
    
    # 在 abort 函数上设置断点
    breakpoint = target.BreakpointCreateByAddress(abort_address.GetLoadAddress(target))
    breakpoint.SetScriptCallbackFunction("intercept_abort_callback")
    
    print(f"Breakpoint set at abort function: {abort_address}")

def intercept_abort_callback(frame, bp_loc, dict):
    print("abort function called!")
    # 在这里可以执行自定义的逻辑，例如修改寄存器或内存
    return False

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f intercept_abort.intercept_abort intercept_abort')
    print("The 'intercept_abort' command has been installed.")
```

### 假设输入与输出

假设我们有一个简单的 C 程序，调用了 `abort` 函数：

```c
#include <stdlib.h>

int main() {
    abort();
    return 0;
}
```

使用上述 LLDB 脚本进行调试时，假设输入和输出如下：

- **输入**：运行 LLDB 并加载目标程序，执行 `intercept_abort` 命令。
- **输出**：当程序调用 `abort` 函数时，LLDB 会打印 "abort function called!"，并且可以在回调函数中执行自定义逻辑。

### 用户常见错误

1. **权限不足**：
   - 用户可能在没有足够权限的情况下尝试调试系统进程或受保护的进程，导致调试失败。例如，尝试调试 `Safari` 或 `System` 进程时，可能需要以 root 权限运行 Frida 或 LLDB。

2. **目标进程未启动**：
   - 用户可能尝试调试一个尚未启动的进程，导致调试失败。例如，在调试 iOS 应用程序时，用户需要确保目标应用程序已经在设备上运行。

3. **跨架构调试问题**：
   - 在跨架构调试时（如在 x86 机器上调试 ARM 程序），用户可能遇到架构不匹配的问题。Frida 和 LLDB 都支持跨架构调试，但需要正确配置调试环境。

### 用户操作步骤

1. **启动目标进程**：
   - 用户首先需要启动目标进程，例如通过命令行运行一个可执行文件，或者在 iOS 设备上启动一个应用程序。

2. **附加调试器**：
   - 用户使用 Frida 或 LLDB 附加到目标进程。例如，使用 Frida 的 `frida-trace` 工具或 LLDB 的 `attach` 命令。

3. **设置断点或插桩**：
   - 用户在目标进程中设置断点或插桩点，例如通过 `Interceptor.attach` 或 LLDB 的 `breakpoint set` 命令。

4. **监控进程行为**：
   - 用户监控目标进程的行为，例如通过 Frida 的 `send` 和 `message` 事件，或通过 LLDB 的 `print` 命令查看变量和寄存器状态。

5. **处理异常或终止事件**：
   - 当目标进程发生异常或终止时，用户可以通过 Frida 或 LLDB 捕获这些事件，并执行相应的处理逻辑。

### 总结

该文件主要测试了 Frida 在进程管理、插桩、调试等方面的功能，特别是在处理 `fork`、`exec`、`abort` 等系统调用时的表现。通过 LLDB 或 Frida，用户可以复现这些调试功能，并在目标进程中执行自定义的调试逻辑。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/tests/test-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
args[2] = NULL;
						  }
						});
						Interceptor.attach(methInner.implementation, {
						  onEnter(args) {
						    args[2] = NULL;
						  }
						});
						Interceptor.attach(Module.getExportByName(null, 'abort'), function () {
						  send('abort');
						  Thread.sleep(1);
						});
						Interceptor.attach(Module.getExportByName(null, '__exit'), function (args) {
						  send(`exit(${args[0].toUInt32()})`);
						  Thread.sleep(1);
						});
						""");

					string? detach_reason = null;
					string? received_message = null;
					bool waiting = false;
					session.detached.connect (reason => {
						detach_reason = reason.to_string ();
						if (waiting)
							exceptions_on_intercepted_objc_methods_should_be_caught.callback ();
					});
					script.message.connect ((message, data) => {
						assert_null (received_message);
						received_message = message;
						if (waiting)
							exceptions_on_intercepted_objc_methods_should_be_caught.callback ();
					});

					yield script.load ();
					yield device.resume (process.id);

					while (received_message == null || detach_reason == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"exit(0)\"}");
					assert_true (detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

					h.done ();
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
				}
			}
		}

		private static async void fork_native (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_file (target_name_of_native ("forker")));
		}

		private static async void fork_other (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_file (target_name_of_other ("forker")));
		}

		private static async void fork_plus_exec (Harness h, string method) {
			yield Unix.run_fork_plus_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), method);
		}

		private static async void bad_exec (Harness h) {
			yield Unix.run_bad_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "execv");
		}

		private static async void bad_then_good_exec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn-bad-then-good-path", "execv");
		}

		private static async void posix_spawn (Harness h) {
			yield Unix.run_posix_spawn_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"));
		}

		private static async void posix_spawn_plus_setexec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn", "posix_spawn+setexec");
		}

		private static string target_name_of_native (string name) {
			string suffix;
			switch (Frida.Test.os ())
			{
				case Frida.Test.OS.MACOS:
					if (Frida.Test.cpu () == ARM_64)
						suffix = (Gum.query_ptrauth_support () == SUPPORTED) ? "macos-arm64e" : "macos";
					else
						suffix = "macos";
					break;
				case Frida.Test.OS.TVOS:
					suffix = "tvos";
					break;
				default:
					suffix = "ios";
					break;
			}

			return name + "-" + suffix;
		}

		private static string target_name_of_other (string name) {
			string suffix;
			if (Frida.Test.os () == Frida.Test.OS.MACOS) {
				if (Frida.Test.cpu () == ARM_64)
					suffix = (Gum.query_ptrauth_support () == SUPPORTED) ? "macos" : "macos-arm64e";
				else
					suffix = "macos32";
			} else {
				suffix = (Gum.query_ptrauth_support () == SUPPORTED) ? "ios64" : "ios32";
			}

			return name + "-" + suffix;
		}

		namespace Manual {

			private static async void cross_arch (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				uint pid;

				try {
					string pgrep_output;
					GLib.Process.spawn_sync (null, new string[] { "/usr/bin/pgrep", "Safari" }, null, 0, null,
						out pgrep_output, null, null);
					pid = (uint) int.parse (pgrep_output);
				} catch (SpawnError spawn_error) {
					printerr ("ERROR: %s\n", spawn_error.message);
					assert_not_reached ();
				}

				var backend = new DarwinHostSessionBackend ();

				var prov = yield h.setup_local_backend (backend);

				try {
					Cancellable? cancellable = null;

					var host_session = yield prov.create (null, cancellable);

					var id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
					var session = yield prov.link_agent_session (host_session, id, h, cancellable);

					string received_message = null;
					bool waiting = false;
					var message_handler = h.message_from_script.connect ((script_id, message, data) => {
						received_message = message;
						if (waiting)
							cross_arch.callback ();
					});

					var script_id = yield session.create_script ("send('hello');", make_parameters_dict (),
						cancellable);
					yield session.load_script (script_id, cancellable);

					if (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}

					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"hello\"}");

					h.disconnect (message_handler);
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}

				yield h.teardown_backend (backend);

				h.done ();
			}

			private static async void spawn_ios_app (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on iOS device> ");
					h.done ();
					return;
				}

				h.disable_timeout (); /* this is a manual test after all */

				var device_manager = new DeviceManager ();

				try {
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});

					/*
					string app_id = "com.apple.mobilesafari";
					string? url = "https://www.frida.re/docs/ios/";
					*/

					string app_id = "com.atebits.Tweetie2";
					string? url = null;

					string received_message = null;
					bool waiting = false;

					var options = new SpawnOptions ();
					// options.argv = { app_id, "hey", "you" };
					options.envp = { "OS_ACTIVITY_DT_MODE=YES", "NSUnbufferedIO=YES" };
					options.stdio = PIPE;
					if (url != null)
						options.aux["url"] = new Variant.string (url);
					// options.aux["aslr"] = new Variant.string ("disable");

					printerr ("device.spawn(\"%s\")\n", app_id);
					var pid = yield device.spawn (app_id, options);

					printerr ("device.attach(%u)\n", pid);
					var session = yield device.attach (pid);

					printerr ("session.create_script()\n");
					var script = yield session.create_script ("""
						Interceptor.attach(Module.getExportByName('UIKit', 'UIApplicationMain'), () => {
						  send('UIApplicationMain');
						});
						""");
					script.message.connect ((message, data) => {
						received_message = message;
						if (waiting)
							spawn_ios_app.callback ();
					});

					printerr ("script.load()\n");
					yield script.load ();

					printerr ("device.resume(%u)\n", pid);
					yield device.resume (pid);

					printerr ("await_message()\n");
					while (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					printerr ("received_message: %s\n", received_message);
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"UIApplicationMain\"}");
					received_message = null;
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
				}

				yield h.prompt_for_key ("Hit a key to exit: ");

				try {
					yield device_manager.close ();
				} catch (IOError e) {
					assert_not_reached ();
				}

				h.done ();
			}

		}

	}
#endif

#if FREEBSD
	namespace FreeBSD {

		private static async void backend (Harness h) {
			var backend = new FreebsdHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("ERROR: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn (Harness h) {
			var backend = new FreebsdHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_executable ("sleeper"), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, message, data) => {
					received_message = message;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("""
					var write = new NativeFunction(Module.getExportByName(null, 'write'), 'int', ['int', 'pointer', 'int']);
					var message = Memory.allocUtf8String('Hello stdout');
					write(1, message, 12);
					for (const m of Process.enumerateModules()) {
					  if (m.name.startsWith('libc')) {
					    Interceptor.attach (Module.getExportByName(m.name, 'sleep'), {
					      onEnter(args) {
					        send({ seconds: args[0].toInt32() });
					      }
					    });
					    break;
					  }
					}
					""", make_parameters_dict (), cancellable);
				yield session.load_script (script_id, cancellable);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid, cancellable);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60}}");
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void fork (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_executable ("forker"));
		}

		private static async void fork_plus_exec (Harness h, string method) {
			yield Unix.run_fork_plus_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), method);
		}

		private static async void bad_exec (Harness h) {
			yield Unix.run_bad_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "execv");
		}

		private static async void bad_then_good_exec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn-bad-then-good-path", "execv");
		}

	}
#endif

#if !WINDOWS
	namespace Unix {

		public static async void run_fork_scenario (Harness h, string target_path) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_detach_reason = null;
				var parent_messages = new Gee.ArrayList<string> ();
				var child_messages = new Gee.ArrayList<string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_fork_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();
				var parent_script = yield parent_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send('[PARENT] ' + args[0].readUtf8String());
					  }
					});
					""");
				parent_script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from parent: %s\n", message);
					parent_messages.add (message);
					if (waiting)
						run_fork_scenario.callback ();
				});
				yield parent_script.load ();
				yield device.resume (parent_pid);
				while (parent_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_messages.size == 1);
				assert_true (parse_string_message_payload (parent_messages[0]) == "[PARENT] Parent speaking");

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid != parent_pid);
				assert_true (child.parent_pid == parent_pid);
				assert_true (child.origin == FORK);
				assert_null (child.identifier);
				assert_null (child.path);
				assert_null (child.argv);
				assert_null (child.envp);
				var child_session = yield device.attach (child.pid);
				child_session.detached.connect (reason => {
					child_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_scenario.callback ();
				});
				var child_script = yield child_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send('[CHILD] ' + args[0].readUtf8String());
					  }
					});
					""");
				child_script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						run_fork_scenario.callback ();
				});
				yield child_script.load ();
				yield device.resume (child.pid);
				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == "[CHILD] Child speaking");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (child_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (parent_messages.size == 1);
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_fork_plus_exec_scenario (Harness h, string target_path, string method) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_pre_exec_detach_reason = null;
				string child_post_exec_detach_reason = null;
				var child_messages = new Gee.ArrayList<string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child_pre_exec = the_child;
				the_child = null;
				assert_true (child_pre_exec.pid != parent_pid);
				assert_true (child_pre_exec.parent_pid == parent_pid);
				assert_true (child_pre_exec.origin == FORK);
				assert_null (child_pre_exec.identifier);
				assert_null (child_pre_exec.path);
				assert_null (child_pre_exec.argv);
				assert_null (child_pre_exec.envp);

				var child_session_pre_exec = yield device.attach (child_pre_exec.pid);
				yield child_session_pre_exec.enable_child_gating ();
				child_session_pre_exec.detached.connect (reason => {
					child_pre_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});

				yield device.resume (child_pre_exec.pid);

				while (child_pre_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_pre_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED");

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child_post_exec = the_child;
				the_child = null;
				assert_true (child_post_exec.pid == child_pre_exec.pid);
				assert_true (child_post_exec.parent_pid == child_post_exec.pid);
				assert_true (child_post_exec.origin == EXEC);
				assert_null (child_post_exec.identifier);
				assert_nonnull (child_post_exec.path);
				assert_nonnull (child_post_exec.argv);
				assert_nonnull (child_post_exec.envp);

				var child_session_post_exec = yield device.attach (child_post_exec.pid);
				child_session_post_exec.detached.connect (reason => {
					child_post_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});
				var script = yield child_session_post_exec.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send(args[0].readUtf8String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});
				yield script.load ();

				yield device.resume (child_post_exec.pid);

				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == method);

				while (child_post_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_post_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_exec_scenario (Harness h, string target_path, string operation, string method) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string pre_exec_detach_reason = null;
				string post_exec_detach_reason = null;
				var messages = new Gee.ArrayList<string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_exec_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, operation, method };
				options.stdio = PIPE;
				var pre_exec_pid = yield device.spawn (target_path, options);
				var pre_exec_session = yield device.attach (pre_exec_pid);
				pre_exec_session.detached.connect (reason => {
					pre_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_exec_scenario.callback ();
				});
				yield pre_exec_session.enable_child_gating ();

				yield device.resume (pre_exec_pid);

				while (pre_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (pre_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED");

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid == pre_exec_pid);
				assert_true (child.parent_pid == pre_exec_pid);
				assert_true (child.origin == EXEC);
				assert_null (child.identifier);
				assert_nonnull (child.path);
				assert_true (Path.get_basename (child.path).has_prefix ("spawner-"));
				assert_nonnull (child.argv);
				assert_nonnull (child.envp);

				var post_exec_session = yield device.attach (child.pid);
				post_exec_session.detached.connect (reason => {
					post_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_exec_scenario.callback ();
				});
				var script = yield post_exec_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send(args[0].readUtf8String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message: %s\n", message);
					messages.add (message);
					if (waiting)
						run_exec_scenario.callback ();
				});
				yield script.load ();

				yield device.resume (child.pid);

				while (messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (messages.size == 1);
				assert_true (parse_string_message_payload (messages[0]) == method);

				while (post_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (post_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_bad_exec_scenario (Harness h, string target_path, string method) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string detach_reason = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					assert_not_reached ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn-bad-path", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					detach_reason = reason.to_string ();
					if (waiting)
						run_bad_exec_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_posix_spawn_scenario (Harness h, string target_path) {
			var method = "posix_spawn";

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_detach_reason = null;
				var child_messages = new Gee.ArrayList<string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid != parent_pid);
				assert_true (child.parent_pid == parent_pid);
				assert_true (child.origin == SPAWN);
				assert_null (child.identifier);
				assert_nonnull (child.path);
				assert_true (Path.get_basename (child.path).has_prefix ("spawner-"));
				assert_nonnull (child.argv);
				assert_nonnull (child.envp);

				assert_null (parent_detach_reason);

				var child_session = yield device.attach (child.pid);
				child_session.detached.connect (reason => {
					child_detach_reason = reason.to_string ();
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});
				var script = yield child_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send(args[0].readUtf8String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});
				yield script.load ();

				yield device.resume (child.pid);

				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == method);

				while (child_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

	}
#endif

#if WINDOWS
	namespace Windows {

		private static async void backend (Harness h) {
			var backend = new WindowsHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			Variant? icon = prov.icon;
			assert_nonnull (icon);
			var dict = new VariantDict (icon);
			int64 width, height;
			assert_true (dict.lookup ("width", "x", out width));
			assert_true (dict.lookup ("height", "x", out height));
			assert_true (width == 16);
			assert_true (height == 16);
			VariantIter image;
			assert_true (dict.lookup ("image", "ay", out image));
			assert_true (image.n_children () == width * height * 4);

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn (Harness h) {
			var backend = new WindowsHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_executable ("sleeper"), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, json, data) => {
					received_message = json;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("""
					const STD_O
```