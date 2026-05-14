# LLM4WAF

LLM4WAF là một hệ thống thử nghiệm hỗ trợ hai hướng xử lý chính cho bài toán Web Application Firewall:

- `attack`: phát hiện WAF, sinh payload tấn công né WAF, và kiểm tra payload trên mục tiêu.
- `defend`: gom cụm các payload đã bypass, truy hồi tri thức qua RAG, sinh rule phòng thủ, kiểm tra cú pháp rule, sửa rule lỗi, và refine rule cuối cùng.

Repo này tổ chức phần lõi xử lý trong `src/core`, sau đó tái sử dụng cùng logic đó cho `src/cli`, `src/web`, và các kịch bản trong `src/test`.

## Mục tiêu của repo

- Tập trung logic nghiệp vụ vào một lõi dùng chung.
- Dùng LLM để sinh payload tấn công thích ứng với WAF.
- Dùng LLM + RAG + LLM-API-Services + rule validation để đề xuất rule phòng thủ.
- Cung cấp nhiều cách vận hành trên cùng một pipeline: CLI, Web API, giao diện frontend, và test scripts.

## Cấu trúc dự án

```text
LLM4WAF/
├─ requirements.txt
├─ src/
│  ├─ cli/
│  │  ├─ main.py
│  │  ├─ outputs_index.json
│  │  ├─ outputs/
│  │  └─ modules/
│  ├─ core/
│  │  ├─ attack_pipeline.py
│  │  ├─ defend_pipeline.py
│  │  ├─ config/
│  │  ├─ external_services/
│  │  ├─ models/
│  │  ├─ services/
│  │  └─ utils/
│  ├─ web/
│  │  ├─ backend/
│  │  └─ frontend/
│  └─ test/
└─ venv/
```

## Thành phần quan trọng

### 1. `src/core`

Đây là trung tâm của hệ thống. Hầu hết logic nghiệp vụ nằm ở đây.

Sau refactor, `core` được tổ chức để làm nổi bật hai pipeline cấp cao nhất ngay tại top-level:

- `attack_pipeline.py`: pipeline tấn công.
  - `_1_detect_waf(domain)`: nhận diện WAF bằng `wafw00f`.
  - `_2_generate_payload(...)`: sinh payload theo Phase 1 (Random Payload) hoặc Phase 3 (Adaptive Payload) tùy có probe history hay không.
  - `_3_test_attack(...)`: kiểm tra payload với DVWA/WAF thật và đánh giá harmfulness.
- `defend_pipeline.py`: pipeline phòng thủ.
  - `_1_clustering(...)`: gom cụm payload bypass.
  - `_2_rag_retrieve(...)`: lấy tri thức từ LLMShield/RAG.
  - `_3_generate_rules(...)`: sinh rule phòng thủ bằng LLM.
  - `_4_validate_rules_syntax(...)`: kiểm tra cú pháp rule theo từng WAF.
  - `_5_retry_invalid_rules(...)`: thử sửa rule lỗi.
  - `_6_refine_rules(...)`: cải tiến rule cuối cùng, có thể kết hợp với existing rules để đồng bộ với rules hiện hành.

Hai file này là layer nghiệp vụ cao nhất trong `core`, còn các thư mục còn lại chủ yếu đóng vai trò phụ trợ cho chúng.

#### `src/core/services`

- `generator.py`: sinh payload cho attack flow.
  - Phase 1: sinh payload từ các kỹ thuật obfuscation ngẫu nhiên.
  - Phase 3: sinh payload thích ứng từ probe history.
- `clustering.py`: gom cụm payload bằng TF-IDF + giảm chiều + HDBSCAN/HAC.
- `sql_harmfulness_validator.py`: đánh giá độ nguy hại của payload SQL.
- `rule_syntax_validator/`: validate cú pháp rule cho các WAF như ModSecurity, AWS WAF, Cloudflare, Naxsi.

#### `src/core/utils`

- `utils.py`: chứa các hàm tiện ích dùng chung ở mức lõi, hiện tập trung vào normalize và decode payload qua nhiều lớp mã hóa/obfuscation.

#### `src/core/external_services`

Đây là lớp giao tiếp với các hệ thống bên ngoài:

- `llmshield.py`: gọi LLMShield để build prompt, generate payload, và RAG retrieve.
- `llm_api.py`: gọi OpenAI và Claude để sinh/sửa/refine rule.
- `xss_harmfulness_validator.py`: gọi service đánh giá độ nguy hại của payload XSS.
- `dvwa.py`: đăng nhập DVWA và gửi payload vào các endpoint test tương ứng.

#### `src/core/models`

- `dtos.py`: định nghĩa các DTO và kiểu dữ liệu dùng chung.

Ví dụ:

- `PayloadResult`
- `AttackResult`
- `ValidationResult`
- `WAFType`

#### `src/core/config`

- `prompts.py`: chứa các prompt và prompt-builder phục vụ cho rule generation, retry, refine, và các bước phòng thủ.
- `settings.py`: đọc cấu hình môi trường từ `src/core/.env`.

Các biến môi trường quan trọng gồm:

- `OPENAI_API_KEY`
- `CLAUDE_API_KEY`
- `LLMSHIELD_ENDPOINT`
- `XSS_HARMNESS_VALIDATOR_ENDPOINT`

### 2. `src/cli`

Đây là giao diện dòng lệnh để chạy các bước của hệ thống bằng command tương tác.

- `main.py`: entry point của CLI.
- `modules/command_builder.py`: định nghĩa cây lệnh và cơ chế hỏi bổ sung tham số nếu thiếu.
- `modules/handlers.py`: ánh xạ từng command sang các pipeline tương ứng trong `core`.
- `modules/file_manager.py`: lưu kết quả từng bước vào `outputs/` và quản lý chỉ mục qua `outputs_index.json`.

CLI không tự chứa logic riêng. Nó chủ yếu gọi lại `core`, sau đó lưu kết quả từng bước thành file JSON để tái sử dụng cho các bước tiếp theo.

### 3. `src/web`

#### `src/web/backend`

Backend dùng Flask và expose API cho các bước attack/defend.

Các nhóm endpoint chính:

- `/api/attack/1-detect-waf`
- `/api/attack/2-generate-payload`
- `/api/attack/3-test`
- `/api/defend/1-clustering`
- `/api/defend/2-rag-retrieve`
- `/api/defend/3-generate-rules`
- `/api/defend/4-validate-rules`
- `/api/defend/5-retry-invalid-rules`
- `/api/defend/6-refine-rules`

Backend cũng không tái cài đặt nghiệp vụ, mà chỉ wrap lại `core.attack_pipeline` và `core.defend_pipeline`.

#### `src/web/frontend`

Frontend là ứng dụng React dùng để thao tác với backend qua HTTP API. Phần này phù hợp khi cần chạy demo hoặc thao tác trực quan thay vì đi qua CLI.

### 4. `src/test`

Đây là thư mục chứa các nhóm test/kịch bản thử nghiệm hệ thống cho những mục đích riêng. Về bản chất, các thư mục con ở đây nhúng lại logic từ `core` để kiểm tra hành vi hệ thống theo từng bài toán đánh giá. Không cần xem đây là một test framework thống nhất; nên hiểu đơn giản đây là nơi chứa các script và artefacts phục vụ test hệ thống.

## Luồng hoạt động tổng quan

### Attack flow

1. Phát hiện WAF từ domain mục tiêu.
2. Sinh payload né WAF.
3. Kiểm tra payload với mục tiêu thật, xem payload có bypass WAF hay không, đánh giá xem payload có harmful hay không.

### Defend flow

Initial: các payload đã bypass và harmful sau khi test ở bước attack
1. Gom cụm để tìm nhóm hành vi tương tự.
2. Gọi RAG để lấy tri thức liên quan tới WAF và kiểu tấn công.
3. Dùng LLM sinh các rule đề xuất.
4. Validate cú pháp rule.
5. Retry các rule lỗi.
6. Refine rule cuối cùng, có thể kết hợp với existing rules.

## Giả định vận hành đối với external services

LLM4WAF/core phụ thuộc trực tiếp vào một số dịch vụ bên ngoài. Khi viết tài liệu sử dụng repo này, nên xem đây là điều kiện tiên quyết:

- `llmshield` phải hoạt động ổn định để phục vụ generate payload và RAG retrieve.
- `llm_api` phải truy cập được các model ngoài như OpenAI và Claude để phục vụ generate/retry/refine rule.
- `xss_harmness_validator` phải hoạt động ổn định để đánh giá payload XSS.
- `dvwa` và môi trường WAF mục tiêu phải sẵn sàng để test payload thật.

Nói ngắn gọn: các external services cần hoạt động ổn định để đảm bảo hoạt động của `LLM4WAF/core`, từ đó mới đảm bảo các lớp sử dụng lại `core` như `cli`, `web`, và `test` vận hành đúng.

## Yêu cầu môi trường

### Python

Các dependency Python chính trong `requirements.txt`.

Cài đặt:

```powershell
cd LLM4WAF
python -m venv venv

# Windows
venv\Scripts\activate
# MacOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### Node.js cho frontend

Frontend dùng React. Cài dependencies bằng:

```powershell
cd src/web/frontend
npm install
```

## Cấu hình môi trường

Tạo file `src/core/.env` với các biến tối thiểu dựa trên `src/core/.env.example`:

Tạo thêm file `.env` trong `src/web/frontend` dựa trên `src/web/frontend/.env.example`:

## Hướng dẫn sử dụng


### 1. Chạy CLI

Từ root repo:

```powershell
cd src/cli
python main.py
```

CLI sẽ chạy theo kiểu tương tác. Nếu chưa nhập đủ tham số, hệ thống sẽ hỏi tiếp ở terminal.

#### Các command chính:

```text
attack detect <domain>
attack generate <waf_name> <attack_type> <num> [tested_file]
attack test <domain> <generate_file>
attack auto <domain> <attack_type> <num> <num_adaptive>

defend cluster <bypassed_file>
defend rag <waf_name> <attack_type> <bypassed_file>
defend genrule <waf_name> <cluster_file> [rag_file]
defend validate <genrule_file>
defend retry <waf_name> <invalidrule_file>
defend refine <waf_name> <validrule_file> [fixedrule_file] [existing_rule_file_path]
defend auto <waf_name> <attack_type> <bypassed_file> [existing_rule_file_path]

files all
files view <file_id>
files remove <file_id>
exit
```

Kết quả mỗi bước sẽ được lưu tại:

- `src/cli/outputs/`
- `src/cli/outputs_index.json`

Điều này cho phép lấy output của bước trước làm input cho bước sau hoặc dùng các command auto để tự động hóa toàn bộ pipeline.

#### 1.1 Chạy tự động toàn bộ pipeline attack

Chỉ cần nhập domain, attack_type, số lượng payload random ban đầu, và số lượng payload adaptive muốn sinh thêm ở vòng hai:

```text
attack auto example.com sql_injection 5 3
```

Hệ thống sẽ tự động:

1. detect WAF từ domain,
2. generate payload random,
3. test payload random,
4. nếu `num_adaptive > 0` thì generate thêm payload adaptive dựa trên kết quả test,
5. test payload adaptive,
6. lưu riêng từng output và lưu thêm file test gộp giữa RANDOM và ADAPTIVE.

#### 1.2 Chạy tự động toàn bộ pipeline defend

Sau khi đã có file test output, chỉ cần nhập `waf_name`, `attack_type`, và `bypassed_file`. Có thể truyền thêm `existing_rule_file_path` nếu muốn refine dựa trên bộ rule sẵn có:

```text
defend auto ModSecurity sql_injection test0
```

Ví dụ có existing rules:

```text
defend auto ModSecurity sql_injection test0 C:\rules\modsecurity.conf
```

Hệ thống sẽ dùng chính `bypassed_file` được chỉ định để cluster, rag, generate rule, validate, retry (nếu có), refine và lưu output từng bước.

#### 1.3 Chạy từng bước thủ công (nâng cao)

Bạn vẫn có thể chạy từng bước như trước:

```text
attack detect example.com
attack generate ModSecurity sql_injection 5
attack test http://modsec.llmshield.click genpayload0

defend cluster test0
defend rag ModSecurity sql_injection test0
defend genrule ModSecurity cluster0 rag0
defend validate genrule0
defend retry ModSecurity invalidrule0
defend refine ModSecurity validrule0 fixedrule0
defend refine ModSecurity validrule0 fixedrule0 C:\rules\modsecurity.conf
```


### 2. Chạy Web

#### 2.1 Chạy backend

```powershell
cd src/web/backend
python app.py
```

Backend mặc định chạy tại:

```text
http://0.0.0.0:5000
```

Các API thực tế có prefix `/api`.

#### 2.2. Chạy Frontend

```powershell
cd src/web/frontend
npm install
npm start
```

Frontend sẽ gọi sang backend qua `REACT_APP_API_URL`.

Frontend cung cấp giao diện Web ở http://127.0.0.1:3000 với đầy đủ chức năng từ attack đến defend tương tự như CLI nhưng trực quan và đẹp hơn để sử dụng

# the end
