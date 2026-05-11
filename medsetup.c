#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

static void
makedir(char *path)
{
  struct stat st;
  if(stat(path, &st) < 0)
    mkdir(path);
}

static void
makefile(char *path, int uid, int mode, char *content)
{
  struct stat st;
  int fd;
  if(stat(path, &st) < 0){
    fd = open(path, O_CREATE | O_RDWR);
    if(fd >= 0){
      if(content) write(fd, content, strlen(content));
      close(fd);
    }
  }
  chown(path, uid);
  chmod(path, mode);
}

int
main(void)
{
  // Create directories
  makedir("/patient");
  makedir("/dosage");
  makedir("/device");
  makedir("/audit");

  // /patient/records  -> uid=1 (patient), read-only for owner+other-read
  makefile("/patient/records",  1, 0440, "Patient Record: John Doe\nDOB: 1990-01-01\n");

  // /dosage/insulin.log -> uid=2 (doctor) write, uid=1 (patient) read
  makefile("/dosage/insulin.log", 2, 0640, "Insulin Log\n");

  // /device/config -> uid=0 (admin only)
  makefile("/device/config",   0, 0600, "device=insulin_pump\nfw=1.0\n");

  // /audit/syscall.log -> uid=0 (admin only)
  makefile("/audit/syscall.log", 0, 0600, "");

  printf(1, "Medical filesystem initialized.\n");
  exit();
}
