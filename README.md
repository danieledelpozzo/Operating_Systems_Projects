# Operating_Systems_Projects

PintOS: Operating System Kernel Development
This repository contains a series of projects developed for the Operating Systems course at USI (Università della Svizzera italiana). The projects involve modifying the Pintos kernel to implement fundamental OS features, including thread synchronization, preemptive scheduling, system calls, and file system management.

# 🛠 Project 1 – Timer Sleep & Thread Management
This project replaces "busy waiting" in the thread sleep mechanism with a more efficient, blocked-thread approach.

Efficient Sleeping: Replaced the while loop yielding mechanism with a thread_sleep function that blocks threads until their wakeup time.

Sorted Wait List: Implemented a global threads_asleep linked list, sorted by wakeup time to allow the timer interrupt to wake threads with O(1) efficiency for the next eligible thread.

Synchronization: Modified the timer_interrupt handler to safely transition threads from THREAD_BLOCKED to THREAD_READY.

# 📈 Project 2 – Priority & MLFQS Scheduling
Implementation of a multi-level feedback queue scheduler (MLFQS) and priority-based preemptive scheduling.

Priority Preemption: Modified thread_create and priority setters to ensure the CPU always executes the thread with the highest priority immediately.

MLFQS Implementation: Developed a complex scheduling algorithm using the formula: priority=PRI_MAX−(recent_cpu/4)−(nice×2).

Dynamic Metrics: Implemented periodic recalculation of load_avg and recent_cpu across all threads to ensure fair resource distribution.

# 💻 Project 3 – User Programs & Stack Setup
Enabling the kernel to run user-level programs by managing the process lifecycle and memory alignment.

Argument Passing: Developed logic to parse command-line arguments and push them onto the user stack in the correct order.

32-bit Alignment: Implemented align_stack() to ensure that the stack pointer follows the x86 calling convention, preventing memory faults.

Process Lifecycle: Modified process_exit to print status messages required by the Pintos test suite and handle basic thread cleanup.

# 🔗 Project 4 – System Calls & Process Wait
Implementation of essential system calls and the parent-child synchronization logic.

Wait/Exit Logic: Implemented process_wait to allow a parent to block until a child terminates, ensuring the correct exit status is returned even if the child finished earlier.

Exec System Call: Created logic for SYS_EXEC to spawn new processes, ensuring the parent waits for the child to successfully load its executable before continuing.

Security: Added robust memory validation to check if user-provided pointers are null, unmapped, or reside in kernel space before dereferencing.

# 📂 Project 5 – File System System Calls
Expanding the system call interface to allow user programs to interact with the disk and console.

File Descriptor Table: Implemented a hash-table-based mapping of file descriptors (IDs) to file pointers for each process.

I/O System Calls: Developed read, write, open, close, seek, and tell.

Thread Safety: Integrated locks around file system operations to ensure atomicity and prevent race conditions during simultaneous file access.

Standard I/O: Added support for reading from the keyboard (STDIN) and writing to the console (STDOUT) using putbuf.
