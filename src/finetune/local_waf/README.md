# Local WAF for Phase 3 RL

Bundle này dựng một mục tiêu local tối thiểu cho Phase 3 RL:

- DVWA app
- MySQL cho DVWA
- ModSecurity CRS proxy phía trước DVWA

## Khởi động

```powershell
cd src/finetune/local_waf
docker compose up -d
python setup_dvwa_db.py
```

Sau khi xong, Phase 3 RL mặc định sẽ dùng:

```text
http://localhost:8000
```

Các URL nội bộ mà `train_phase3.py` gọi:

- `/login.php`
- `/vulnerabilities/sqli/`
- `/vulnerabilities/xss_r/`

Nếu muốn đổi địa chỉ, truyền vào:

```powershell
python ..\train_phase3.py --waf-base-url http://host:port
```