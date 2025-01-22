Response:
### 功能概述

`test-injector.vala` 是 Frida 动态插桩工具的核心测试文件，主要用于测试 Frida 的注入功能。它通过创建不同的测试用例来验证 Frida 在不同架构和操作系统下的动态注入、常驻注入、资源泄漏检测等功能。以下是该文件的主要功能：

1. **动态注入测试** (`test_dynamic_injection`)：
   - 测试 Frida 在当前架构和其他架构下的动态注入功能。
   - 通过注入一个简单的代理（`simple-agent`）到目标进程（`sleeper`）中，验证注入是否成功，并检查日志文件的内容是否符合预期。
   - 测试不同操作系统（如 macOS、iOS、Linux 等）下的行为差异。

2. **常驻注入测试** (`test_resident_injection`)：
   - 测试 Frida 在当前架构下的常驻注入功能。
   - 注入一个常驻代理（`resident-agent`）到目标进程中，验证注入是否成功，并检查日志文件的内容是否符合预期。

3. **资源泄漏测试** (`test_resource_leaks`)：
   - 测试 Frida 在多次注入和卸载后是否存在资源泄漏。
   - 通过比较注入前后的资源使用情况，确保没有资源泄漏。

4. **挂起注入测试** (`test_suspended_injection`)：
   - 仅在 macOS 系统下测试挂起状态下的注入功能。
   - 在目标进程挂起时注入代理，验证注入是否成功，并检查日志文件的内容是否符合预期。

### 二进制底层与 Linux 内核相关

- **动态注入**：Frida 的动态注入功能涉及到操作系统的进程管理、内存管理和线程调度等底层机制。例如，在 Linux 系统下，Frida 可能会使用 `ptrace` 系统调用来附加到目标进程，并通过 `mmap` 和 `mprotect` 等系统调用来修改目标进程的内存布局。
  
- **常驻注入**：常驻注入通常涉及到在目标进程中创建一个新的线程或修改现有的线程，以便在目标进程中持续运行注入的代码。这可能需要操作系统的线程管理机制，如 `pthread_create` 或 `clone` 系统调用。

- **挂起注入**：在挂起状态下注入代码通常涉及到操作系统的进程控制机制，如 `SIGSTOP` 和 `SIGCONT` 信号的使用，以及 `ptrace` 系统调用来控制目标进程的执行。

### LLDB 调试示例

假设我们想要使用 LLDB 来调试 Frida 的动态注入功能，以下是一个简单的 LLDB Python 脚本示例，用于复刻 `test_dynamic_injection` 的功能：

```python
import lldb

def inject_agent(process, agent_path, data):
    # 加载代理库
    error = lldb.SBError()
    agent_module = process.LoadImage(lldb.SBFileSpec(agent_path), error)
    if not error.Success():
        print(f"Failed to load agent: {error}")
        return

    # 查找代理入口点
    entry_point = agent_module.FindSymbol("frida_agent_main")
    if not entry_point.IsValid():
        print("Failed to find entry point")
        return

    # 调用代理入口点
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    result = frame.EvaluateExpression(f"frida_agent_main({data})")
    if not result.GetError().Success():
        print(f"Failed to call agent: {result.GetError()}")

def main():
    # 启动目标进程
    debugger = lldb.SBDebugger.Create()
    target = debugger.CreateTarget("sleeper")
    if not target:
        print("Failed to create target")
        return

    # 启动进程
    process = target.LaunchSimple(None, None, os.getcwd())
    if not process:
        print("Failed to launch process")
        return

    # 注入代理
    inject_agent(process, "simple-agent.so", "43")

    # 等待进程退出
    process.GetState() == lldb.eStateExited
    print(f"Process exited with code {process.GetExitStatus()}")

if __name__ == "__main__":
    main()
```

### 假设输入与输出

- **输入**：目标进程 `sleeper` 和代理库 `simple-agent.so`。
- **输出**：目标进程退出，并返回指定的退出码（如 43）。

### 常见使用错误

1. **目标进程未启动**：如果目标进程未启动或启动失败，注入操作将无法进行。用户需要确保目标进程已正确启动。
2. **代理库路径错误**：如果代理库路径错误或不存在，注入操作将失败。用户需要确保代理库路径正确。
3. **权限不足**：在某些操作系统下，注入操作可能需要 root 权限。如果权限不足，注入操作将失败。

### 用户操作步骤

1. **启动目标进程**：用户首先需要启动目标进程（如 `sleeper`）。
2. **注入代理**：用户调用 Frida 的注入功能，将代理库（如 `simple-agent.so`）注入到目标进程中。
3. **验证注入结果**：用户通过检查日志文件或目标进程的行为，验证注入是否成功。
4. **等待进程退出**：用户等待目标进程退出，并检查退出码是否符合预期。

### 调试线索

- **日志文件**：用户可以通过检查日志文件（如 `dynamic-injection.log`）来获取注入过程中的详细信息。
- **进程状态**：用户可以通过调试器（如 LLDB）查看目标进程的状态，确保注入操作正确执行。
- **资源使用情况**：用户可以通过检查资源使用情况，确保没有资源泄漏。

通过这些步骤和调试线索，用户可以逐步排查和解决注入过程中可能遇到的问题。
Prompt: 
```
这是目录为frida/subprojects/frida-core/tests/test-injector.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
namespace Frida.InjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Injector/inject-dynamic-current-arch", () => {
			test_dynamic_injection (Frida.Test.Arch.CURRENT);
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/Injector/inject-dynamic-other-arch", () => {
				test_dynamic_injection (Frida.Test.Arch.OTHER);
			});
		}

		GLib.Test.add_func ("/Injector/inject-resident-current-arch", () => {
			test_resident_injection (Frida.Test.Arch.CURRENT);
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/Injector/inject-resident-other-arch", () => {
				test_resident_injection (Frida.Test.Arch.OTHER);
			});
		}

		GLib.Test.add_func ("/Injector/resource-leaks", test_resource_leaks);

#if DARWIN
		GLib.Test.add_func ("/Injector/suspended-injection-current-arch", () => {
			test_suspended_injection (Frida.Test.Arch.CURRENT);
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/Injector/suspended-injection-other-arch", () => {
				test_suspended_injection (Frida.Test.Arch.OTHER);
			});
		}
#endif
	}

	private static void test_dynamic_injection (Frida.Test.Arch arch) {
		var logfile = File.new_for_path (Frida.Test.path_to_temporary_file ("dynamic-injection.log"));
		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
		}
		var envp = new string[] {
			"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
		};

		var rat = new Labrat ("sleeper", envp, arch);

		rat.inject ("simple-agent", "", arch);
		rat.wait_for_uninject ();
		assert_true (content_of (logfile) == ">m<");

		var requested_exit_code = 43;
		rat.inject ("simple-agent", requested_exit_code.to_string (), arch);
		rat.wait_for_uninject ();

		switch (Frida.Test.os ()) {
			case Frida.Test.OS.MACOS:   // Gum.Darwin.Mapper
			case Frida.Test.OS.IOS:     // Gum.Darwin.Mapper
			case Frida.Test.OS.TVOS:    // Gum.Darwin.Mapper
			case Frida.Test.OS.ANDROID: // Bionic's behavior
				assert_true (content_of (logfile) == ">m<>m");
				break;
			case Frida.Test.OS.LINUX:
				if (Frida.Test.libc () == Frida.Test.Libc.UCLIBC) {
					assert_true (content_of (logfile) == ">m<>m");
				} else {
					assert_true (content_of (logfile) == ">m<>m<");
				}
				break;
			default:
				assert_true (content_of (logfile) == ">m<>m<");
				break;
		}

		var exit_code = rat.wait_for_process_to_exit ();
		assert_true (exit_code == requested_exit_code);

		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
			assert_not_reached ();
		}

		rat.close ();
	}

	private static void test_resident_injection (Frida.Test.Arch arch) {
		var logfile = File.new_for_path (Frida.Test.path_to_temporary_file ("resident-injection.log"));
		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
		}
		var envp = new string[] {
			"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
		};

		var rat = new Labrat ("sleeper", envp, arch);

		rat.inject ("resident-agent", "", arch);
		rat.wait_for_uninject ();
		assert_true (content_of (logfile) == ">m");

		try {
			rat.process.kill ();

			logfile.delete ();
		} catch (GLib.Error e) {
			assert_not_reached ();
		}

		rat.close ();
	}

	private static void test_resource_leaks () {
		var logfile = File.new_for_path (Frida.Test.path_to_temporary_file ("leaks.log"));
		var envp = new string[] {
			"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
		};

		var rat = new Labrat ("sleeper", envp);

		/* Warm up static allocations */
		for (int i = 0; i != 2; i++) {
			rat.inject ("simple-agent", "");
			rat.wait_for_uninject ();
			rat.wait_for_cleanup ();
		}

		var usage_before = rat.process.snapshot_resource_usage ();

		rat.inject ("simple-agent", "");
		rat.wait_for_uninject ();
		rat.wait_for_cleanup ();

		var usage_after = rat.process.snapshot_resource_usage ();

		usage_after.assert_equals (usage_before);

		rat.inject ("simple-agent", "0");
		rat.wait_for_uninject ();
		rat.wait_for_process_to_exit ();

		rat.close ();
	}

#if DARWIN
	private static void test_suspended_injection (Frida.Test.Arch arch) {
		var logfile = File.new_for_path (Frida.Test.path_to_temporary_file ("suspended-injection.log"));
		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
		}
		var envp = new string[] {
			"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
		};

		var rat = new Labrat.suspended ("sleeper", envp, arch);

		rat.inject ("simple-agent", "", arch);
		rat.wait_for_uninject ();
		assert_true (content_of (logfile) == ">m<");

		rat.close ();
	}
#endif

	private static string content_of (File file) {
		try {
			uint8[] contents;
			file.load_contents (null, out contents, null);
			unowned string str = (string) contents;
			return str;
		} catch (GLib.Error load_error) {
			stderr.printf ("%s: %s\n", file.get_path (), load_error.message);
			assert_not_reached ();
		}
	}

	private class Labrat {
		public Frida.Test.Process? process {
			get;
			private set;
		}

		private Injector? injector;
		private Gee.Queue<uint> uninjections = new Gee.ArrayQueue<uint> ();
		private PendingUninject? pending_uninject;

		public Labrat (string name, string[] envp, Frida.Test.Arch arch = Frida.Test.Arch.CURRENT) {
			try {
				process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable (name), null, envp, arch);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

#if !WINDOWS
			/* TODO: improve injectors to handle injection into a process that hasn't yet finished initializing */
			Thread.usleep (50000);
#endif
		}

		public Labrat.suspended (string name, string[] envp, Frida.Test.Arch arch = Frida.Test.Arch.CURRENT) {
			try {
				process = Frida.Test.Process.create (Frida.Test.Labrats.path_to_executable (name), null, envp, arch);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public void close () {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_close.begin (loop);
				return false;
			});
			loop.run ();
		}

		private async void do_close (MainLoop loop) {
			if (injector != null) {
				try {
					yield injector.close ();
				} catch (IOError e) {
					assert_not_reached ();
				}
				injector.uninjected.disconnect (on_uninjected);
				injector = null;
			}
			process = null;

			/* Queue an idle handler, allowing MainContext to perform any outstanding completions, in turn cleaning up resources */
			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		public void inject (string name, string data, Frida.Test.Arch arch = Frida.Test.Arch.CURRENT) {
			var loop = new MainLoop ();
			Idle.add (() => {
				perform_injection.begin (name, data, arch, loop);
				return false;
			});
			loop.run ();
		}

		private async void perform_injection (string name, string data, Frida.Test.Arch arch, MainLoop loop) {
			if (injector == null) {
				injector = Injector.new ();
				injector.uninjected.connect (on_uninjected);
			}

			try {
				var path = Frida.Test.Labrats.path_to_library (name, arch);
				assert_true (FileUtils.test (path, FileTest.EXISTS));

				yield injector.inject_library_file (process.id, path, "frida_agent_main", data);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			loop.quit ();
		}

		public void wait_for_uninject () {
			var success = try_wait_for_uninject (5000);
			assert_true (success);
		}

		public bool try_wait_for_uninject (uint timeout) {
			if (!uninjections.is_empty) {
				uninjections.poll ();
				return true;
			}

			var loop = new MainLoop ();

			assert (pending_uninject == null);
			pending_uninject = new PendingUninject (loop);

			bool timed_out = false;
			var timeout_id = Timeout.add (timeout, () => {
				timed_out = true;
				loop.quit ();
				return false;
			});

			loop.run ();

			if (!timed_out) {
				uninjections.poll ();

				Source.remove (timeout_id);
			}

			pending_uninject = null;

			return !timed_out;
		}

		public void wait_for_cleanup () {
			var loop = new MainLoop ();

			/* The Darwin injector does cleanup 50ms after detecting that the remote thread is dead */
			Timeout.add (100, () => {
				loop.quit ();
				return false;
			});

			loop.run ();
		}

		public int wait_for_process_to_exit () {
			int exitcode = -1;

			try {
				exitcode = process.join (1000);
			} catch (Error e) {
				stdout.printf ("\n\nunexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			return exitcode;
		}

		private void on_uninjected (uint id) {
			uninjections.offer (id);

			if (pending_uninject != null)
				pending_uninject.complete ();
		}

		private class PendingUninject {
			private MainLoop loop;

			public PendingUninject (MainLoop loop) {
				this.loop = loop;
			}

			public void complete () {
				loop.quit ();
			}
		}
	}
}

"""

```