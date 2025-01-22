Response:
### 功能归纳

`test-host-session.vala` 是 Frida 动态插桩工具的核心测试文件之一，主要用于测试 Frida 在不同操作系统（如 Linux、macOS、FreeBSD、Windows 等）上的进程管理、插桩、调试等功能。以下是该文件的主要功能归纳：

1. **进程管理与调试**：
   - 测试 Frida 在不同操作系统上对进程的创建、附加、恢复、终止等操作。
   - 通过 `spawn`、`attach`、`resume`、`kill` 等函数，模拟进程的启动和调试过程。
   - 支持对进程的标准输入输出（`stdio`）进行捕获和验证。

2. **插桩与拦截**：
   - 使用 `Interceptor.attach` 对目标进程中的函数进行插桩，拦截函数调用并修改参数或返回值。
   - 例如，拦截 `puts` 函数并发送消息到 Frida 脚本，验证插桩是否成功。
   - 支持对系统调用（如 `abort`、`exit` 等）进行拦截，验证进程的退出行为。

3. **多进程与子进程管理**：
   - 测试 `fork`、`exec` 等多进程操作，验证 Frida 对子进程的跟踪和管理能力。
   - 通过 `enable_child_gating` 启用子进程管理，确保 Frida 能够正确处理子进程的创建和退出。
   - 验证父进程和子进程的分离（`detach`）原因，如进程终止或被替换。

4. **跨架构调试**：
   - 测试 Frida 在不同架构（如 ARM64、x86_64）上的调试能力。
   - 例如，在 macOS 上调试 iOS 应用程序，验证跨架构调试的功能。

5. **错误处理与异常捕获**：
   - 测试 Frida 在进程执行失败（如 `bad_exec`）时的错误处理能力。
   - 验证 Frida 是否能够正确捕获并处理异常情况，如进程崩溃或非法操作。

6. **平台特定功能**：
   - 针对不同操作系统（如 macOS、FreeBSD、Windows）实现特定的测试用例。
   - 例如，在 macOS 上测试 `posix_spawn` 系统调用，验证其行为是否符合预期。

---

### 二进制底层与 Linux 内核相关示例

1. **函数拦截与修改**：
   - 在 Linux 系统中，Frida 使用 `ptrace` 或 `LD_PRELOAD` 等技术实现对目标进程的插桩。
   - 例如，拦截 `puts` 函数的调用并修改其参数：
     ```c
     Interceptor.attach(Module.getExportByName(null, 'puts'), {
       onEnter(args) {
         args[0] = Memory.allocUtf8String("Modified output");
       }
     });
     ```
   - 在底层，Frida 会通过修改目标进程的内存或寄存器来实现对函数的拦截和修改。

2. **进程管理与调试**：
   - Frida 使用 `ptrace` 系统调用在 Linux 上实现对目标进程的附加和调试。
   - 例如，通过 `ptrace(PTRACE_ATTACH, pid, NULL, NULL)` 附加到目标进程，然后通过 `ptrace(PTRACE_CONT, pid, NULL, NULL)` 恢复进程执行。

---

### LLDB 调试示例

假设我们想要使用 LLDB 复刻 Frida 的调试功能，以下是一个简单的 LLDB Python 脚本示例，用于拦截 `puts` 函数并修改其输出：

```python
import lldb

def intercept_puts(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取 puts 函数的地址
    puts_symbol = target.FindSymbols("puts").GetSymbolAtIndex(0)
    puts_address = puts_symbol.GetStartAddress().GetLoadAddress(target)

    # 设置断点
    breakpoint = target.BreakpointCreateByAddress(puts_address)
    breakpoint.SetScriptCallbackFunction("intercept_puts_callback")

def intercept_puts_callback(frame, bp_loc, dict):
    # 修改 puts 的参数
    arg0 = frame.FindVariable("arg0")
    arg0.SetValueFromCString("Modified output")

    # 继续执行
    frame.GetThread().GetProcess().Continue()

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f intercept_puts.intercept_puts intercept_puts')
```

使用方法：
1. 启动 LLDB 并加载目标进程。
2. 运行 `intercept_puts` 命令，设置断点并注册回调函数。
3. 当 `puts` 函数被调用时，LLDB 会执行回调函数并修改输出。

---

### 假设输入与输出

1. **输入**：
   - 目标进程调用 `puts("Hello, world!")`。
   - Frida 脚本拦截 `puts` 函数并修改参数为 `"Modified output"`。

2. **输出**：
   - 目标进程输出 `"Modified output"` 而不是 `"Hello, world!"`。

---

### 常见使用错误

1. **未启用子进程管理**：
   - 用户在使用 `fork` 或 `exec` 时，忘记调用 `enable_child_gating`，导致 Frida 无法正确跟踪子进程。
   - 解决方法：确保在附加到父进程后调用 `enable_child_gating`。

2. **跨架构调试失败**：
   - 用户尝试在 x86_64 系统上调试 ARM64 应用程序，但未正确配置 Frida 的跨架构支持。
   - 解决方法：确保目标设备和 Frida 版本支持跨架构调试。

3. **插桩函数未找到**：
   - 用户尝试拦截不存在的函数（如拼写错误），导致插桩失败。
   - 解决方法：使用 `Module.getExportByName` 验证函数是否存在。

---

### 用户操作路径

1. **启动目标进程**：
   - 用户通过 `spawn` 或 `attach` 启动或附加到目标进程。

2. **加载 Frida 脚本**：
   - 用户编写 Frida 脚本并加载到目标进程中，设置插桩点和回调函数。

3. **验证调试功能**：
   - 用户观察目标进程的行为，验证插桩和调试功能是否按预期工作。

4. **处理异常情况**：
   - 如果目标进程崩溃或行为异常，用户通过 Frida 的日志和错误信息进行排查。

---

### 总结

`test-host-session.vala` 是 Frida 的核心测试文件，涵盖了进程管理、插桩、调试、跨架构支持等功能。通过该文件，开发者可以验证 Frida 在不同操作系统和场景下的行为是否符合预期。
Prompt: 
```
这是目录为frida/subprojects/frida-core/tests/test-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共4部分，请归纳一下它的功能

"""
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
"""


```