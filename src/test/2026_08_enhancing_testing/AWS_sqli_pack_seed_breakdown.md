# AWS SQLi protection pack - bypass breakdown by seed

### Phase 1 - sql_injection

| Seed | Before (no pack) bypassed/blocked/error | After (SQLi pack) bypassed/blocked/error |
|---|---|---|
| 42 | 50/0/0 | 48/2/0 |
| 123 | 50/0/0 | 50/0/0 |
| 2024 | 50/0/0 | 50/0/0 |
| 777 | 50/0/0 | 49/1/0 |
| 999 | 50/0/0 | 49/1/0 |
| **Total** | **250/0/0** | **246/4/0** |

### Phase 1 - sql_injection_blind

| Seed | Before (no pack) bypassed/blocked/error | After (SQLi pack) bypassed/blocked/error |
|---|---|---|
| 42 | 50/0/0 | 48/2/0 |
| 123 | 50/0/0 | 49/1/0 |
| 2024 | 50/0/0 | 50/0/0 |
| 777 | 50/0/0 | 50/0/0 |
| 999 | 50/0/0 | 50/0/0 |
| **Total** | **250/0/0** | **247/3/0** |

### Phase 3 - sql_injection

| Seed | Before (no pack) bypassed/blocked/error | After (SQLi pack) bypassed/blocked/error |
|---|---|---|
| 42 | 50/0/0 | 50/0/0 |
| 123 | 50/0/0 | 50/0/0 |
| 2024 | 50/0/0 | 50/0/0 |
| 777 | 50/0/0 | 50/0/0 |
| 999 | 50/0/0 | 50/0/0 |
| **Total** | **250/0/0** | **250/0/0** |

### Phase 3 - sql_injection_blind

| Seed | Before (no pack) bypassed/blocked/error | After (SQLi pack) bypassed/blocked/error |
|---|---|---|
| 42 | 50/0/0 | 49/1/0 |
| 123 | 50/0/0 | 50/0/0 |
| 2024 | 50/0/0 | 50/0/0 |
| 777 | 50/0/0 | 49/1/0 |
| 999 | 50/0/0 | 49/1/0 |
| **Total** | **250/0/0** | **247/3/0** |
