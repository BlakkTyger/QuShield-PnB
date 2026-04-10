# Phase 9 E2E Test Results against pnb.bank.in
Generated: 2026-04-10 11:25:47.678060
## 1. Setup & Authentication
✅ User created successfully. ID: 3b0645ec-d88b-47fc-b6ba-40ea52b37ff9

## 2. Deep Scan Orchestration (pnb.bank.in)

❌ FATAL PIPELINE EXCEPTION: ScanOrchestrator.__init__() takes 1 positional argument but 2 were given
Traceback (most recent call last):
  File "/home/blakktyger/Documents/BlakkTyger/Projects/QuShield-PnB/backend/tests/integration/test_master_e2e.py", line 51, in run_master_e2e
    orch = ScanOrchestrator(db)
           ^^^^^^^^^^^^^^^^^^^^
TypeError: ScanOrchestrator.__init__() takes 1 positional argument but 2 were given
