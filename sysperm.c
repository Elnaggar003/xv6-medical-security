#include "types.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"
#include "x86.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"
#include "proc.h"

// sys_chmod(path, mode)
int
sys_chmod(void)
{
  char *path;
  int   mode;
  struct inode *ip;

  if(argstr(0, &path) < 0 || argint(1, &mode) < 0)
    return -1;

  begin_op();
  if((ip = namei(path)) == 0){ end_op(); return -1; }
  ilock(ip);

  // only owner or admin can chmod
  if(myproc()->uid != 0 && myproc()->uid != ip->uid){
    iunlockput(ip); end_op(); return -1;
  }

  ip->mode = (short)mode;
  iupdate(ip);
  iunlockput(ip);
  end_op();
  return 0;
}

// sys_chown(path, uid)
int
sys_chown(void)
{
  char *path;
  int   uid;
  struct inode *ip;

  if(argstr(0, &path) < 0 || argint(1, &uid) < 0)
    return -1;

  // only admin can chown
  if(myproc()->uid != 0)
    return -1;

  begin_op();
  if((ip = namei(path)) == 0){ end_op(); return -1; }
  ilock(ip);
  ip->uid = (short)uid;
  iupdate(ip);
  iunlockput(ip);
  end_op();
  return 0;
}
