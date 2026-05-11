#include "types.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"
#include "x86.h"
#include "spinlock.h"
#include "proc.h"

#define AUDIT_SIZE 128

struct audit_entry {
  int  pid;
  int  uid;
  int  syscall_no;
  uint tick;
  char note[16];
};

static struct audit_entry auditbuf[AUDIT_SIZE];
static int audit_head  = 0;
static int audit_count = 0;
static struct spinlock auditlock;
static int audit_ready = 0;

void auditinit(void) {
  initlock(&auditlock, "auditlock");
  audit_ready = 1;
}

void audit_log(int pid, int uid, int syscall_no, char *note) {
  if(!audit_ready) return;
  acquire(&auditlock);
  struct audit_entry *e = &auditbuf[audit_head % AUDIT_SIZE];
  e->pid = pid; e->uid = uid; e->syscall_no = syscall_no; e->tick = ticks;
  if(note){ int i=0; while(i<15&&note[i]){e->note[i]=note[i];i++;} e->note[i]=0; }
  else e->note[0]=0;
  audit_head++;
  if(audit_count < AUDIT_SIZE) audit_count++;
  release(&auditlock);
}

static int itoa(int v, char *buf) {
  char tmp[12]; int i=0,neg=0,len=0;
  if(v<0){neg=1;v=-v;}
  if(v==0){buf[0]='0';return 1;}
  while(v){tmp[i++]='0'+v%10;v/=10;}
  if(neg)buf[len++]='-';
  while(i--)buf[len++]=tmp[i];
  return len;
}

int sys_auditread(void) {
  char *ubuf; int size;
  if(argptr(0,&ubuf,1)<0||argint(1,&size)<0) return -1;
  if(myproc()->uid!=0) return -1;

  acquire(&auditlock);
  int start = (audit_count<AUDIT_SIZE)?0:audit_head%AUDIT_SIZE;
  int n=audit_count, written=0;
  char line[96];

  for(int i=0;i<n;i++){
    struct audit_entry *e=&auditbuf[(start+i)%AUDIT_SIZE];
    int len=0;
    char num[12]; int k;
    // "tick=T pid=P uid=U sys=S note\n"
    char *s="tick="; while(*s)line[len++]=*s++;
    k=itoa(e->tick,num); for(int j=0;j<k;j++)line[len++]=num[j];
    s=" pid="; while(*s)line[len++]=*s++;
    k=itoa(e->pid,num);  for(int j=0;j<k;j++)line[len++]=num[j];
    s=" uid="; while(*s)line[len++]=*s++;
    k=itoa(e->uid,num);  for(int j=0;j<k;j++)line[len++]=num[j];
    s=" sys="; while(*s)line[len++]=*s++;
    k=itoa(e->syscall_no,num); for(int j=0;j<k;j++)line[len++]=num[j];
    if(e->note[0]){line[len++]=' '; s=e->note; while(*s)line[len++]=*s++;}
    line[len++]='\n';
    if(written+len>=size) break;
    if(copyout(myproc()->pgdir,(uint)(ubuf+written),line,len)<0) break;
    written+=len;
  }
  release(&auditlock);
  return written;
}
