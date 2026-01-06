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
// proj5
#include "threads/malloc.h"
#include "lib/kernel/hash.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

typedef void (*handler) (struct intr_frame *);
static void syscall_exit (struct intr_frame *);
static void syscall_exec (struct intr_frame *);
static void syscall_wait (struct intr_frame *);
static void syscall_write (struct intr_frame *);
static bool check_user_address (void *);

// proj5
// Function declarations for handling each system call
static void syscall_create (struct intr_frame *f);
static void syscall_remove (struct intr_frame *f);
static void syscall_read (struct intr_frame *f);
static void syscall_filesize (struct intr_frame *f);
static void syscall_open (struct intr_frame *f);
static void syscall_close (struct intr_frame *f);
static void syscall_halt (struct intr_frame *f);
static void syscall_seek (struct intr_frame *f);
static void syscall_tell (struct intr_frame *f);

#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];

// proj5
// Function prototypes for hash operations and file descriptor lookup
unsigned hash_file_item (const struct hash_elem * e, void * aux);
bool compare_item (const struct hash_elem * a, const struct hash_elem * b, void * aux);
struct file_item * find_file_item(tid_t tid, int fd);

// File descriptors start from 3 (0, 1, 2 are reserved for stdin, stdout, stderr)
#define FD_START 3

// proj5
// Global lock to synchronize access to the file system and the file descriptors hash table
struct lock file_lock;

// Entry structure for the file descriptor hash table
struct file_item {
  struct hash_elem elem;  // Element for hash table linkage

  // Hash key components
  tid_t owner;            // Thread ID of the owner
  int fd;                 // File descriptor associated with the file

  // Associated file pointer
  struct file *file;
};


// Hash table for managing file descriptors
struct hash files_table;

// Hash function for file_item entries
unsigned hash_file_item (const struct hash_elem * e, void * aux UNUSED) {
  struct file_item *i = hash_entry(e, struct file_item, elem);
  // Generate hash using a combination of file descriptor and thread ID
  return hash_int(i->fd ^ i->owner);
}

bool compare_item (const struct hash_elem * a, const struct hash_elem * b, void * aux UNUSED) {
  struct file_item * i_a = hash_entry(a, struct file_item, elem);
  struct file_item * i_b = hash_entry(b, struct file_item, elem);
  // Order items first by thread ID (owner), then by file descriptor
  if (i_a->owner != i_b->owner)
    return i_a->owner < i_b->owner;
  else
    return i_a->fd < i_b->fd;
}

// Looks up a file_item in files_table for the given thread ID and file descriptor.
// This function should only be called while holding file_lock.
struct file_item *find_file_item(tid_t tid, int fd) {
  struct file_item fi;

  fi.owner = tid;
  fi.fd = fd;

  struct file_item * entry = NULL;
  struct hash_elem * e = NULL;
  // Get the file
  e = hash_find(&files_table, &fi.elem);

  if (e != NULL) {
    // Cast
    entry = hash_entry(e, struct file_item, elem);
  }

  return entry;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Any syscall not registered here should be NULL (0) in the call array. */
  memset(call, 0, SYSCALL_MAX_CODE + 1);

  // proj5
  // Initialize file system lock and file descriptor hash table
  lock_init(&file_lock); // Protects access to files_table
  hash_init(&files_table, hash_file_item, compare_item, NULL); // Maps (tid, fd) -> file*

  /* Check file lib/syscall-nr.h for all the syscall codes and file
   * lib/user/syscall.c for a short explanation of each system call. */
  call[SYS_EXIT]  = syscall_exit;   /* Terminate this process. */
  call[SYS_WRITE] = syscall_write;  /* Write to a file. */
  call[SYS_WAIT]  = syscall_wait;   /* Wait for a child process to die. */
  call[SYS_EXEC]  = syscall_exec;   /* Start another process. */

  // proj5
  // Register system call handlers related to file operations
  call[SYS_CREATE] = syscall_create;
  call[SYS_REMOVE] = syscall_remove;
  call[SYS_OPEN] = syscall_open;
  call[SYS_CLOSE] = syscall_close;
  call[SYS_READ] = syscall_read;
  call[SYS_SEEK] = syscall_seek;
  call[SYS_TELL] = syscall_tell;
  call[SYS_HALT] = syscall_halt;
  call[SYS_FILESIZE] = syscall_filesize;
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
  thread_get_child_data(t->parent, t->tid)->exit_status = t->exit_status;
  thread_exit ();
}

static void
syscall_exec (struct intr_frame * f)
{
  int * stackpointer = f->esp;
  char * command = (char *) *(stackpointer + 1);

  if (check_user_address (command))
    f->eax = process_execute (command);
  else
    f->eax = -1;
}

static void
syscall_wait (struct intr_frame * f)
{
  int * stackpointer = (void *) f->esp;
  tid_t child_tid = *(stackpointer + 1);
  f->eax = process_wait (child_tid);
}

// proj5
// Handles the WRITE system call.
// Writes `length` bytes from `buffer` to the file identified by `fd`.
// Returns the number of bytes actually written.
//
// If writing to fd 1 (STDOUT), the buffer is output to the console using putbuf().
// For large buffers, it is reasonable to split them to avoid interleaved output.
//
// If writing to a file (fd > 1), the corresponding file_item is retrieved from the hash table
// while holding file_lock. If found, the data is written using file_write().
//
// Proper user address validation is performed for all pointers. If any pointer is invalid,
// the process exits with status -1.
static void
syscall_write (struct intr_frame *f)
{
  int *stack = f->esp;
  int wrote = 0;

  // Validate argument addresses
  if (!check_user_address(stack + 1) || !check_user_address(stack + 2) || !check_user_address(stack + 3)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  int    fd     = * (stack+1);
  char * buffer = * (char**)(stack+2);
  int    length = * (stack+3);

  // Validate buffer range
  if (!check_user_address(buffer) || !check_user_address(buffer + length - 1)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  if (fd == STDOUT_FILENO) {
    // Write buffer to the console
    putbuf(buffer, length);
    wrote = length;
  } else {
    // Write buffer to a file
    lock_acquire(&file_lock);
    struct file_item *fi = find_file_item(thread_current()->tid, fd);
    if (fi != NULL) {
      wrote = file_write(fi->file, buffer, length);
    }
    lock_release(&file_lock);
  }

  // Store return value in eax
  f->eax = wrote;
}

static bool check_user_address (void * ptr) {
  return ptr != NULL && is_user_vaddr (ptr) && pagedir_get_page (thread_current ()->pagedir, ptr);
}

// Handles the CREATE system call.
// Attempts to create a new file named `file_name` with an initial size of `file_size` bytes.
// Returns true if the file was successfully created, false otherwise.
// This does not open the newly created file; an OPEN system call is required to do that.
static void syscall_create (struct intr_frame *f) {
  int *stack = f->esp;
  bool success = false;

  // Validate the user addresses of the file name and size arguments
  if (!check_user_address(stack + 1) || !check_user_address(stack + 2)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  const char *file_name = * (const char**)(stack + 1);
  unsigned file_size    = * (unsigned *)  (stack + 2);

  // Validate the user-provided file name string
  if (!check_user_address((void *) file_name)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  // Acquire file system lock before attempting to create the file
  lock_acquire(&file_lock);
  success = filesys_create(file_name, file_size);
  lock_release(&file_lock);

  // Store the result in eax to return to the user program
  f->eax = success;
}

// Handles the REMOVE system call.
// Attempts to delete the file named `file_name`.
// Returns true if the file was successfully removed, false otherwise.
// A file can be removed whether it is open or closed.
// Removing an open file does not close it.
static void syscall_remove (struct intr_frame *f) {
  int *stack = f->esp;
  bool success = false;

  // Validate the user address of the argument (file name)
  if (!check_user_address(stack + 1)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  const char *file_name = * (const char**)(stack + 1);

  // Validate the user-provided file name string
  if (!check_user_address((void *) file_name)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  // Acquire file system lock before removing the file
  lock_acquire(&file_lock);
  success = filesys_remove(file_name);
  lock_release(&file_lock);

  // Store the result in eax to return to the user program
  f->eax = success;
}

// Handles the OPEN system call.
// Attempts to open the file named `file_name`.
// Returns a non-negative file descriptor (fd) if successful, or -1 on failure.
//
// Notes:
// - File descriptors 0 and 1 are reserved for console I/O (stdin/stdout) and will never
//   be returned by this function.
// - Each process has its own independent set of file descriptors.
// - File descriptors are not inherited by child processes.
// - Multiple opens of the same file (even by the same process) yield different fds.
// - Each file descriptor maintains its own file position and must be closed independently.
static void syscall_open (struct intr_frame *f) {
  int *stack = f->esp;
  struct thread* curr = thread_current();
  int fd = -1;

  // Validate pointer to file name
  if (!check_user_address(stack + 1)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  const char *file_name = * (const char**)(stack + 1);

  // Validate actual file name address
  if (!check_user_address((void *) file_name)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }

  lock_acquire(&file_lock);
  struct file *file = filesys_open(file_name);
  
  if (file != NULL) {
    // Allocate and initialize a file_item for the opened file
    struct file_item *fi = malloc(sizeof(struct file_item));
    
    if (fi != NULL) {
      tid_t owner = curr->tid;

      // Find the first available file descriptor for this thread
      unsigned i = FD_START;
      struct file_item * iterator = NULL;
      while ((iterator = find_file_item(owner, i)) != NULL) {
        i++;
      }
      fd = i;
      
      fi->owner = owner;
      fi->fd = fd;
      fi->file = file;

      // Insert the file_item into the global files_table
      hash_insert(&files_table, &fi->elem);
    } else {
      // If memory allocation fails, close the file to avoid a leak
      file_close(file);
    }
  }
  lock_release(&file_lock);

  // Return the file descriptor to the user program
  f->eax = fd;
}

// Handles the CLOSE system call.
// Closes the file associated with the given file descriptor `fd`.
// If the file is open by this process, it is closed, its entry is removed from the
// files_table, and its resources are freed.
//
// Notes:
// - This function does nothing if the file descriptor is invalid or not found.
// - When a process exits or is terminated, all its open file descriptors are
//   automatically closed as if this function were called for each one.
static void syscall_close (struct intr_frame *f) {
  int *stack = f->esp;
  struct thread *curr = thread_current();
  
  // Validate user-provided file descriptor address
  if (!check_user_address(stack + 1)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }
  
  int fd = * (stack + 1);
  
  lock_acquire(&file_lock);
  struct file_item *fi = find_file_item(curr->tid, fd);

  if (fi != NULL) {
    // Close the file, remove it from the hash table, and free its memory
    file_close(fi->file);
    hash_delete(&files_table, &fi->elem);
    free(fi);
  }
  lock_release(&file_lock);
}

// Handles the READ system call.
// Reads `size` bytes from the file descriptor `fd` into `buffer`.
// Returns the number of bytes actually read:
// - 0 if at end-of-file,
// - -1 if an error occurred (e.g., invalid fd, invalid address),
// - or the actual number of bytes read.
//
// Note:
// - Reading from fd 0 reads from the keyboard using input_getc().
// - For other fds, it looks up the open file and reads from it.
static void syscall_read (struct intr_frame *f) {
  int *stack = f->esp;
  struct thread *curr = thread_current();
  int bytes_read = 0;
  
  // Check that all syscall arguments are valid user addresses
  if (!check_user_address(stack + 1) || !check_user_address(stack + 2) || !check_user_address(stack + 3)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }
  
  int fd        = *             (stack + 1);
  char *buffer  = * (char **)   (stack + 2);
  unsigned size = * (unsigned *)(stack + 3);
  
  // Check if buffer range is in valid user memory
  if (!check_user_address(buffer) || !check_user_address(buffer + size - 1)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }
  
  lock_acquire(&file_lock);
  if (fd == STDIN_FILENO) {
    // Read from standard input (keyboard)
    unsigned i;
    for (i = 0; i < size; i++) {
      buffer[i] = input_getc(); // Read one character at a time
    }

    bytes_read = size;
  } else {
    // Read from a regular file
    struct file_item *fi = find_file_item(curr->tid, fd);
    
    if (fi != NULL) {
      bytes_read = file_read(fi->file, buffer, size);
    }
  }
  lock_release(&file_lock);
  
  // Store the number of bytes actually read in eax
  f->eax = bytes_read;
}

// Handles the SEEK system call.
// Changes the next read/write position of file descriptor `fd` to `position` bytes from the start.
// - A seek past the end is allowed.
// - If the fd is invalid or the file is not open, nothing happens.
static void syscall_seek (struct intr_frame *f) {
  int *stack = f->esp;
  struct thread *curr = thread_current();
  
  // Validate syscall arguments: file descriptor and position
  if (!check_user_address(stack + 1) || !check_user_address(stack + 2)) {
    *(stack+1) = -1; // Set return value to -1
    syscall_exit(f); // Exit process
  }
  
  int fd = * (stack + 1); // File descriptor
  unsigned position = * (unsigned *)(stack + 2); // New position to seek to
  
  lock_acquire(&file_lock);

  // Look up the file corresponding to the file descriptor for this thread
  struct file_item *fi = find_file_item(curr->tid, fd);
  
  if (fi != NULL) {
    // Move the file's read/write position
    file_seek(fi->file, position);
  }
  lock_release(&file_lock);
}

// Returns the current position of the next byte to be read or written in the open file fd.
// The position is measured in bytes from the beginning of the file.
static void syscall_tell (struct intr_frame *f) {
  int *stack = f->esp;
  struct thread *curr = thread_current();
  int position = 0;
  
  // Validate the user-provided address for the file descriptor
  if (!check_user_address(stack + 1)) {
    *(stack+1) = -1; // Return error if address is invalid
    syscall_exit(f); // Exit the system call
  }
  
  int fd = * (stack + 1); // Retrieve the file descriptor from the stack
  
  lock_acquire(&file_lock); // Acquire lock to ensure thread-safe access to the file system
  struct file_item *fi = find_file_item(curr->tid, fd); // Find the file item for the given file descriptor
  
  if (fi != NULL) {
    position = file_tell(fi->file); // Get the current read/write position of the file
  }
  lock_release(&file_lock); // Release the file system lock
  
  f->eax = position; // Return the current file position to the caller
}

// Terminates the Pintos system by calling shutdown_power_off().
// This system call shuts down the system completely, which is typically used
// to power off the machine. It should be used sparingly, as it prevents
// the system from collecting additional information about potential issues
// like deadlocks or other debugging insights.
static void syscall_halt (struct intr_frame *f UNUSED) {
  shutdown_power_off(); // Power off the system
}

// Returns the size of the file associated with the given file descriptor (fd),
// expressed in bytes. If the file descriptor is invalid or the file cannot
// be found, it returns -1. The size refers to the total length of the file.
static void syscall_filesize (struct intr_frame *f) {
  int *stack = f->esp;
  struct thread *curr = thread_current();
  int size = -1;
  
  // Check if user address is valid for file descriptor
  if (!check_user_address(stack + 1)) {
    *(stack+1) = -1;
    syscall_exit(f);
  }
  
  int fd = * (stack + 1);
  
  lock_acquire(&file_lock);
  struct file_item *fi = find_file_item(curr->tid, fd);
  
  // If the file exists, retrieve its size
  if (fi != NULL) {
    size = file_length(fi->file);
  }
  lock_release(&file_lock);
  
  f->eax = size;
}
