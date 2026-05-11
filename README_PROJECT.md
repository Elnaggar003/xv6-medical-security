# xv6 Medical Device Security

**University:** Arab Academy for Science, Technology and Maritime Transport  
**Course:** Operating Systems Security - CCY4304  
**Lecturer:** Prof. Dr. Ayman Adel  
**TA:** Abdelrahman Solyman  

## Project Overview
Extended xv6 kernel with three security layers simulating FDA/IEC 62443 requirements for life-critical medical devices.

## Phases Implemented
- **Phase 1:** Role-based user authentication (admin/patient/doctor)
- **Phase 2:** UNIX-style file permissions with medical file protection
- **Phase 3:** Kernel-level syscall audit log (admin-only access)
- **Bonus:** Automated compliance testing (22/22 tests pass)

## How to Run
```bash
make qemu-nox
```
Login with: admin/admin123, patient/patient123, doctor/doctor123

## Run Compliance Tests
Login as admin and run: `compliance`
