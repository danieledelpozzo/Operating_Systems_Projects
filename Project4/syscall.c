#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "user/syscall.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);

typedef void (*handler) (struct intr_frame *);
static void syscall_exit (struct intr_frame *f);
static void syscall_write (struct intr_frame *f);
static void syscall_exec (struct intr_frame *f);
static void syscall_wait (struct intr_frame *f);

#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Any syscall not registered here should be NULL (0) in the call array. */
  memset(call, 0, SYSCALL_MAX_CODE + 1);

  /* Check file lib/syscall-nr.h for all the syscall codes and file
   * lib/user/syscall.c for a short explanation of each system call. */
  call[SYS_EXIT]  = syscall_exit;   // Terminate this process.
  call[SYS_WRITE] = syscall_write;  // Write to a file.
  call[SYS_EXEC] = syscall_exec;   // Execute a program from a file.
  call[SYS_WAIT] = syscall_wait;   // Wait for the completion of a child process.
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_code = *((int*)f->esp);
  call[syscall_code](f);
}

static void
syscall_exit (struct intr_frame *f)
{
  int *stack = f->esp;
  struct thread* t = thread_current ();
  t->exit_status = *(stack+1);
  thread_exit ();
}

static void
syscall_write (struct intr_frame *f)
{
  int *stack = f->esp;
  ASSERT (*(stack+1) == 1); // fd 1
  char * buffer = *(char**)(stack+2);
  int    length = *(stack+3);
  putbuf (buffer, length);
  f->eax = length;
}

static void
syscall_exec (struct intr_frame *f)
{
  int *stack = f->esp;
  const char *cmd_line = *(const char**)(stack + 1);
  tid_t pid = 0;

  // Check if the command line pointer is valid
  // If it's NULL, it is invalid
  if (cmd_line == NULL)
    pid = -1;

  // Check if the command line pointer points to kernel space
  if (is_kernel_vaddr(cmd_line))
    pid = -1;

  // Ensure the command line is within the valid user space address
  uint32_t *pd = thread_current()->pagedir;
  if (pagedir_get_page(pd, cmd_line) == NULL)
    pid = -1;

  // If the command line pointer is valid, attempt to execute the process
  if (pid != -1) {
    // Execute the process and retrieve the child process's pid
    pid = process_execute(cmd_line);
  }

  // Return the pid of the newly created process or -1 if execution failed
  f->eax = pid;
}

// The syscall_wait function is used by a process to wait for a child process to terminate
//
// If the child process is still running, it blocks the parent until the child exits.
// Once the child terminates, the parent's wait syscall returns the child's exit status.
//
static void
syscall_wait (struct intr_frame *f)
{
  int *stack = f->esp;
  pid_t pid = (pid_t) *(stack + 1);

  // Call process_wait to wait for the child to finish and get its exit status
  int status = process_wait(pid);

  // Return the exit status of the child process:
  // - If the child finished before the wait was called, return the exit status.
  // - If the child was killed or if the pid does not refer to a valid child process,
  //   return -1.
  // Cases such as the parent having already waited for the child are handled in process_wait.
  f->eax = status;
}
