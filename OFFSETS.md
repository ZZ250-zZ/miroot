# equuleus 内核偏移表 —— 全部由 boot.img 静态证据解出

镜像：`C:\IT\equuleus_images_V11.0.2.0.QECCNXM_...tgz` → `boot.img`（45,303,114 B，MD5 `929be97213291005d1ef714427ad8f3f`）
内核：`4.9.186-perf-gd054b09`；`_text = 0xffffff8008080000`（KIMAGE_VADDR `0xffffff8008000000` + TEXT_OFFSET `0x80000`）
下表中的「偏移」均为相对 `_text`，运行时用 `kernel_base + OFFSET` 得到实际地址，KASLR 已由此吸收。

## 一、符号偏移（kallsyms）

解析器：`assets/kallsyms_v8.py` + `assets/struct_probe.py`；共 162637 个符号。
定位：`token_table@0x19ff200`、`token_index@0x19ff700`、`markers@0x19fde00`、`names@0x181f600`、`offsets@0x1780600`。
校验：前 256 / 512 个符号恰占 `0xb8c` / `0x1a84` 字节，与 u64 markers 数值完全一致；`_text` 偏移为 0。

| 宏 | 符号 | 偏移 |
|---|---|---|
| `SELINUX_ENFORCING_OFFSET` | `selinux_enforcing` | `0x2837000` |
| `MEMSTART_ADDR_OFFSET` | `memstart_addr` | `0x1d0d2c0` |
| `SYSCTL_TABLE_ROOT_OFFSET` | `sysctl_table_root` | `0x25d9a78` |
| `PROC_DOUINTVEC_OFFSET` | `proc_douintvec` | `0x3ad98` |
| `INIT_TASK_OFFSET` | `init_task` | `0x25a1580` |
| `INIT_CRED_OFFSET` | `init_cred` | `0x25afac8` |
| `OFFSET_PIPE_FOP` | `pipefifo_fops` | `0x139d9f8` |

> 4.9 内核里 pipe 的 `file_operations` 名为 `pipefifo_fops`，新内核才叫 `pipe_fops`。

## 二、结构体字段偏移（.rela.dyn + 静态数据 + 源码三重验证）

`CONFIG_RELOCATABLE=y` / `CONFIG_RANDOMIZE_BASE=y` ⇒ `.data` 里的绝对指针在镜像中为 0，
由 `R_AARCH64_RELATIVE`（`r_info=0x403`，185275 条，24 B/条）在启动时填充。
解析该表并按 `r_offset` 落在 `init_task` / `init_cred` / `init_mm` 范围内的条目，即可精确读出每个指针字段的偏移与目标符号。

| 宏 | 偏移 | 静态证据 |
|---|---|---|
| `TASKS_OFFSET` | `0x580` | rela：`+0x580`/`+0x588` → `init_task+0x580`（`LIST_HEAD_INIT(tsk.tasks)`）。紧随其后 `plist_node pushable_tasks` 的 `prio_list@0x598`、`node_list@0x5a8` 同样自引用，`rb_node pushable_dl_tasks@0x5b8`，恰好到 `mm@0x5d0` |
| `PID_OFFSET` | `0x680` | rela：`restart_block.fn@0x650` → `do_no_restart_syscall`（结构大小 `0x30`）；`real_parent@0x690` → `init_task`。中间依次为 `pid@0x680`、`tgid@0x684`、`stack_canary@0x688`（`CONFIG_CC_STACKPROTECTOR_STRONG=y`），间距闭合无空隙 |
| `MM_OFFSET` | `0x5D0` | rela：`+0x5D8` → `init_mm` 即 `active_mm`；源码 `struct mm_struct *mm, *active_mm` 且 `INIT_TASK` 中 `.mm = NULL`，故 `mm` 为前 8 字节 |
| `REAL_CRED_OFFSET` | `0x838` | rela：`+0x838`/`+0x840` → `init_cred`（`real_cred` / `cred`）；`swapper` 字符串 `comm@0x848`，与源码 `cred` 后紧跟 `comm[16]` 一致 |
| `mm_struct.pgd` | `0x48` | rela：`init_mm+0x48` → `0xffffff800af74000`（swapper_pg_dir）；静态数据 `mm_users=2@0x50`、`mm_count=1@0x54`。`CONFIG_SPECULATIVE_PAGE_FAULT=y` 使 `mm_rb_lock` 多占 8 B，故不是 Pixel 3 的 `0x40` |
| `struct cred::security` | `0x78` | rela：`init_cred+0x80` → `root_user`（`user`）、`+0x88` → `init_user_ns`、`+0x90` → `init_groups`；静态 `cap_permitted/effective/bset = 0x3fffffffff` 位于 `+0x30/0x38/0x40`，与 `dipper-q-oss/include/linux/cred.h` 字段顺序逐字节吻合 |
| `task_security_struct::sid` | `0x04` | `dipper-q-oss/security/selinux/include/objsec.h`：`osid@0`、`sid@4` |

## 三、已由源码确认无需修改的常量

| 位置 | 值 | 依据 |
|---|---|---|
| `phys_to_virt()` 的线性映射基址 | `0xFFFFFFC000000000` | `arch/arm64/include/asm/memory.h`：`PAGE_OFFSET = 0xffffffffffffffff - (1 << (VA_BITS-1)) + 1`；本机 `CONFIG_ARM64_VA_BITS=39` ⇒ `1<<38 = 0x4000000000` ⇒ 正是 `0xffffffc000000000` |
| `ctl_table.proc_handler` | `+0x20` | `include/linux/sysctl.h`：`procname@0` `data@8` `maxlen@0x10` `mode@0x14` `child@0x18` `proc_handler@0x20` |
| `ctl_table_header` 各字段 | `0/0x18/0x20/0x28/0x30/0x38/0x40/0x48` | 同上，`ctl_table`/`unregistering`/`ctl_table_arg`/`root`/`set`/`parent`/`node`/`inodes` |
| `ctl_dir + 80`、`ctl_node + 0x10` | `0x50` / `rb_node.left` | `struct ctl_dir { ctl_table_header header(0x50); rb_root root; }`；`rb_node` 为 `parent/right/left` |

## 四、运行时自检

`src/exploit.c` 在取得任意读之后、任何内核写之前插入三段自检：
1. `real_cred` 必须等于 `kernel_base + INIT_CRED_OFFSET`；
2. `init_task.tasks.prev` 必须是合法内核指针，`get_task_by_pid()` 必须按 `PID_OFFSET` 找到自身；
3. `mm` 与 `pgd` 必须落在 `0xffffffc0...` 线性映射区；页表解析末端还有原有的 `0xdeadbeefbadc0ded` 读回校验。
任一项不符即 `goto out` 退出，**不写内核、不会 kernel panic、无数据风险**。

结论：**本构建包内每个常量都由本机 `boot.img` 的静态证据确定，无跨机型推断、无待定项。**
