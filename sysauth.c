#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "spinlock.h"

// Simple djb2 hash for passwords
static uint
hashpass(char *str)
{
  uint hash = 5381;
  int c;
  while((c = (unsigned char)*str++) != 0)
    hash = ((hash << 5) + hash) + c;
  return hash;
}

// User table (like /etc/passwd)
#define MAX_USERS 8
#define MAX_UNAME 16
#define MAX_PASS  32

struct user {
  char  name[MAX_UNAME];
  uint  passhash;
  int   uid;
  int   active;
};

static struct user usertable[MAX_USERS];
static int nusers = 0;
static struct spinlock userlock;
static int auth_initialized = 0;

void
authinit(void)
{
  initlock(&userlock, "userlock");
  // Seed default users: admin, patient, doctor
  strncpy(usertable[0].name, "admin",   MAX_UNAME);
  usertable[0].passhash = hashpass("admin123");
  usertable[0].uid      = 0;
  usertable[0].active   = 1;

  strncpy(usertable[1].name, "patient", MAX_UNAME);
  usertable[1].passhash = hashpass("patient123");
  usertable[1].uid      = 1;
  usertable[1].active   = 1;

  strncpy(usertable[2].name, "doctor",  MAX_UNAME);
  usertable[2].passhash = hashpass("doctor123");
  usertable[2].uid      = 2;
  usertable[2].active   = 1;

  nusers = 3;
  auth_initialized = 1;
}

// Returns uid on success, -1 on failure
int
authlogin(char *username, char *password)
{
  int i;
  uint h = hashpass(password);
  acquire(&userlock);
  for(i = 0; i < nusers; i++){
    if(usertable[i].active &&
       strncmp(usertable[i].name, username, MAX_UNAME) == 0 &&
       usertable[i].passhash == h){
      release(&userlock);
      return usertable[i].uid;
    }
  }
  release(&userlock);
  return -1;
}

// sys_login(username, password) -> sets proc->uid, returns 0 or -1
int
sys_login(void)
{
  char *username, *password;
  if(argstr(0, &username) < 0 || argstr(1, &password) < 0)
    return -1;
  int uid = authlogin(username, password);
  if(uid < 0)
    return -1;
  myproc()->uid = uid;
  return uid;
}

// sys_whoami() -> returns uid of current process
int
sys_whoami(void)
{
  return myproc()->uid;
}

// sys_useradd(username, password, uid) -> 0 or -1
int
sys_useradd(void)
{
  char *username, *password;
  int  uid;
  if(argstr(0, &username) < 0 || argstr(1, &password) < 0 || argint(2, &uid) < 0)
    return -1;
  if(myproc()->uid != 0)   // admin only
    return -1;
  acquire(&userlock);
  if(nusers >= MAX_USERS){ release(&userlock); return -1; }
  strncpy(usertable[nusers].name, username, MAX_UNAME);
  usertable[nusers].passhash = hashpass(password);
  usertable[nusers].uid      = uid;
  usertable[nusers].active   = 1;
  nusers++;
  release(&userlock);
  return 0;
}

// sys_userdel(username) -> 0 or -1
int
sys_userdel(void)
{
  char *username;
  if(argstr(0, &username) < 0)
    return -1;
  if(myproc()->uid != 0)
    return -1;
  int i;
  acquire(&userlock);
  for(i = 0; i < nusers; i++){
    if(usertable[i].active &&
       strncmp(usertable[i].name, username, MAX_UNAME) == 0){
      usertable[i].active = 0;
      release(&userlock);
      return 0;
    }
  }
  release(&userlock);
  return -1;
}

// sys_passwd(username, newpass) -> 0 or -1
int
sys_passwd(void)
{
  char *username, *newpass;
  if(argstr(0, &username) < 0 || argstr(1, &newpass) < 0)
    return -1;
  // admin can change any; others only their own
  struct proc *p = myproc();
  int i;
  acquire(&userlock);
  for(i = 0; i < nusers; i++){
    if(usertable[i].active &&
       strncmp(usertable[i].name, username, MAX_UNAME) == 0){
      if(p->uid != 0 && p->uid != usertable[i].uid){
        release(&userlock);
        return -1;
      }
      usertable[i].passhash = hashpass(newpass);
      release(&userlock);
      return 0;
    }
  }
  release(&userlock);
  return -1;
}
