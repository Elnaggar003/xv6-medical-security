#include "types.h"
#include "stat.h"
#include "user.h"

#define MAX_INPUT 64

static void
getinput(char *buf, int max)
{
  int i = 0;
  char c;
  while(i < max - 1){
    if(read(0, &c, 1) != 1) break;
    if(c == '\n' || c == '\r') break;
    buf[i++] = c;
  }
  buf[i] = '\0';
}

int
main(void)
{
  char username[MAX_INPUT];
  char password[MAX_INPUT];
  int  uid;

  while(1){
    printf(1, "\n=== xv6 Medical Device Login ===\n");
    printf(1, "Username: ");
    getinput(username, MAX_INPUT);

    printf(1, "Password: ");
    getinput(password, MAX_INPUT);

    uid = login(username, password);
    if(uid < 0){
      printf(1, "Login failed. Try again.\n");
      continue;
    }

    if(uid == 0)      printf(1, "Welcome, ADMIN!\n");
    else if(uid == 1) printf(1, "Welcome, PATIENT!\n");
    else if(uid == 2) printf(1, "Welcome, DOCTOR!\n");
    else              printf(1, "Welcome!\n");

    // Launch shell after successful login
    char *argv[] = { "sh", 0 };
    exec("sh", argv);
    printf(1, "exec sh failed\n");
    exit();
  }
  exit();
}
