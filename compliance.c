#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

static int passed = 0;
static int failed = 0;

static void
check(char *name, int condition)
{
  if(condition){
    printf(1, "  [PASS] %s\n", name);
    passed++;
  } else {
    printf(1, "  [FAIL] %s\n", name);
    failed++;
  }
}

// ---- Phase 1: Authentication ----
static void
test_auth(void)
{
  printf(1, "\n=== Phase 1: Authentication ===\n");

  // T1.1: valid admin login
  int r = login("admin", "admin123");
  check("T1.1 admin login succeeds", r == 0);

  // T1.2: whoami returns 0 for admin
  check("T1.2 whoami=0 after admin login", whoami() == 0);

  // T1.3: wrong password fails
  r = login("admin", "wrongpass");
  check("T1.3 wrong password rejected", r == -1);

  // T1.4: valid patient login
  r = login("patient", "patient123");
  check("T1.4 patient login succeeds", r == 1);

  // T1.5: whoami returns 1 for patient
  check("T1.5 whoami=1 after patient login", whoami() == 1);

  // T1.6: valid doctor login
  r = login("doctor", "doctor123");
  check("T1.6 doctor login succeeds", r == 2);

  // T1.7: whoami returns 2 for doctor
  check("T1.7 whoami=2 after doctor login", whoami() == 2);

  // T1.8: unknown user fails
  r = login("hacker", "pass");
  check("T1.8 unknown user rejected", r == -1);

  // restore admin
  login("admin", "admin123");
}

// ---- Phase 2: File Permissions ----
static void
test_permissions(void)
{
  printf(1, "\n=== Phase 2: File Permissions ===\n");
  int fd;

  // As admin (uid=0): full access
  login("admin", "admin123");

  fd = open("/device/config", O_RDONLY);
  check("T2.1  admin reads /device/config", fd >= 0);
  if(fd>=0) close(fd);

  fd = open("/audit/syscall.log", O_RDONLY);
  check("T2.2  admin reads /audit/syscall.log", fd >= 0);
  if(fd>=0) close(fd);

  // As patient (uid=1)
  login("patient", "patient123");

  fd = open("/patient/records", O_RDONLY);
  check("T2.3  patient reads /patient/records", fd >= 0);
  if(fd>=0) close(fd);

  fd = open("/dosage/insulin.log", O_RDONLY);
  check("T2.4  patient reads /dosage/insulin.log", fd >= 0);
  if(fd>=0) close(fd);

  fd = open("/device/config", O_RDONLY);
  check("T2.5  patient BLOCKED from /device/config", fd < 0);
  if(fd>=0) close(fd);

  fd = open("/audit/syscall.log", O_RDONLY);
  check("T2.6  patient BLOCKED from /audit/syscall.log", fd < 0);
  if(fd>=0) close(fd);

  fd = open("/patient/records", O_RDWR);
  check("T2.7  patient BLOCKED from writing /patient/records", fd < 0);
  if(fd>=0) close(fd);

  // As doctor (uid=2)
  login("doctor", "doctor123");

  fd = open("/dosage/insulin.log", O_RDWR);
  check("T2.8  doctor writes /dosage/insulin.log", fd >= 0);
  if(fd>=0){ write(fd,"dose=5u\n",8); close(fd); }

  fd = open("/patient/records", O_RDONLY);
  check("T2.9  doctor reads /patient/records", fd >= 0);
  if(fd>=0) close(fd);

  fd = open("/device/config", O_RDONLY);
  check("T2.10 doctor BLOCKED from /device/config", fd < 0);
  if(fd>=0) close(fd);

  // restore admin
  login("admin", "admin123");
}

// ---- Phase 3: Audit Log ----
static void
test_audit(void)
{
  printf(1, "\n=== Phase 3: Audit Log ===\n");
  static char buf[2048];
  int n;

  // T3.1: admin can read audit log
  login("admin", "admin123");
  n = auditread(buf, sizeof(buf));
  check("T3.1 admin reads audit log", n > 0);

  // T3.2: patient cannot read audit log
  login("patient", "patient123");
  n = auditread(buf, sizeof(buf));
  check("T3.2 patient BLOCKED from audit log", n == -1);

  // T3.3: doctor cannot read audit log
  login("doctor", "doctor123");
  n = auditread(buf, sizeof(buf));
  check("T3.3 doctor BLOCKED from audit log", n == -1);

  // T3.4: audit log contains entries
  login("admin", "admin123");
  n = auditread(buf, sizeof(buf));
  check("T3.4 audit log has entries", n > 0);

  login("admin", "admin123");
}

int
main(void)
{
  printf(1, "\n");
  printf(1, "╔══════════════════════════════════════╗\n");
  printf(1, "║  xv6 Medical Device Compliance Test  ║\n");
  printf(1, "║  FDA / IEC 62443 Security Validation ║\n");
  printf(1, "╚══════════════════════════════════════╝\n");

  test_auth();
  test_permissions();
  test_audit();

  printf(1, "\n=== Results ===\n");
  printf(1, "  Passed: %d\n", passed);
  printf(1, "  Failed: %d\n", failed);
  printf(1, "  Total:  %d\n", passed+failed);

  if(failed == 0)
    printf(1, "\n  COMPLIANCE STATUS: PASS\n");
  else
    printf(1, "\n  COMPLIANCE STATUS: FAIL\n");

  exit();
}
