#include "types.h"
#include "stat.h"
#include "user.h"

static char buf[4096];

int
main(void)
{
  int  n;

  n = auditread(buf, sizeof(buf));
  if(n < 0){
    printf(2, "auditlog: permission denied (admin only)\n");
    exit();
  }
  if(n == 0){
    printf(1, "auditlog: no entries yet\n");
    exit();
  }
  printf(1, "=== Syscall Audit Log ===\n");
  write(1, buf, n);
  exit();
}
