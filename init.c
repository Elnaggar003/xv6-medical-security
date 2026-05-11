// init: The initial user-level program
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

char *loginargv[] = { "login", 0 };

int
main(void)
{
  int pid, wpid;

  if(open("console", O_RDWR) < 0){
    mknod("console", 1, 1);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr

  // Run medical filesystem setup once
  pid = fork();
  if(pid == 0){
    char *margs[] = { "medsetup", 0 };
    exec("medsetup", margs);
    printf(1, "init: exec medsetup failed\n");
    exit();
  }
  if(pid > 0) wait();

  for(;;){
    printf(1, "init: starting login\n");
    pid = fork();
    if(pid < 0){
      printf(1, "init: fork failed\n");
      exit();
    }
    if(pid == 0){
      exec("login", loginargv);
      printf(1, "init: exec login failed\n");
      exit();
    }
    while((wpid=wait()) >= 0 && wpid != pid)
      printf(1, "zombie!\n");
  }
}
