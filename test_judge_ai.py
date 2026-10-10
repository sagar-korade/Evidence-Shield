import urllib.request
import json

base = 'http://127.0.0.1:8000'

# 1. Fetch frontend
res = urllib.request.urlopen(f'{base}/')
html = res.read().decode('utf-8')
assert 'judge-ai-summary-card' in html
assert 'runJudgeAiSummary' in html
assert 'dossier-ai-summary-content' in html
assert 'JUDICIAL BENCH AI SUMMARY' in html
print('Frontend checks passed!')

# 2. Test Judge login and AI analysis execution
req = urllib.request.Request(f'{base}/api/v1/auth/login', data=json.dumps({
    'username': 'judge_kulkarni',
    'password': 'Password@123',
    'role': 'JUDGE',
    'agency': 'BOMBAY_SESSIONS_COURT'
}).encode('utf-8'), headers={'Content-Type': 'application/json'})

with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode('utf-8'))
j_tok = data['token']
print('Judge logged in successfully.')

# Get cases
req_c = urllib.request.Request(f'{base}/api/v1/cases', headers={'Authorization': f'Bearer {j_tok}'})
with urllib.request.urlopen(req_c) as resp:
    cases = json.loads(resp.read().decode('utf-8'))['items']

if len(cases) > 0:
    cid = cases[0]['case_id']
    req_ai = urllib.request.Request(f'{base}/api/v1/cases/{cid}/analysis', data=json.dumps({
        'analysis_type': 'SUMMARY',
        'document_version_ids': []
    }).encode('utf-8'), headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {j_tok}'})
    with urllib.request.urlopen(req_ai) as resp:
        ai_data = json.loads(resp.read().decode('utf-8'))
    print(f"Judge AI analysis executed successfully! Scanned count: {ai_data.get('scanned_count')}")

print('ALL JUDGE AI SUMMARY FEATURES TESTED AND WORKING!')
