#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int * sp = (int *) (f->esp);

  if (*sp == SYS_EXIT) {
    int status = *(sp + 1);
    /* 
    Since the system calls handled in this function are very basic,
    and given relatevely simple user programs, there is no check implemented
    to ensure that the value tooked from the stack poimter are actually valid
    */
    struct thread* t = thread_current ();
    t->proc_status = status;

    f->eax = status;
    thread_exit ();
  } else if (*sp == SYS_WRITE) {
    /* arguments needed for write */
    int fd = *(sp + 1);
    char *buff = (char *) *(sp + 2);
    unsigned m_length = *(sp + 3);

    if (fd == 1) {
      putbuf (buff, m_length);
      /* return length of message */
      f->eax = m_length;
    } else { /* in case of invalid descriptor */
      f->eax = -1; 
    }
  } else {
    thread_exit ();
  }
}
