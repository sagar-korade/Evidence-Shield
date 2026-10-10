import urllib.request
import json
import time

base = 'http://127.0.0.1:8000/api/v1'

def post_json(url, data, token=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
    if token: req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))

def get_json(url, token=None):
    req = urllib.request.Request(url)
    if token: req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))

print('=== 1. Login Police IO ===')
p_login = post_json(f'{base}/auth/login', {'username': 'officer_sharma', 'password': 'Password@123', 'role': 'POLICE', 'agency': 'MUMBAI_CRIME_BRANCH'})
p_tok = p_login['token']
print('Police token acquired successfully.')

print('=== 2. Register FIR Docket ===')
fir_num = f'FIR-2026-MUM-{int(time.time()) % 10000}'
case_res = post_json(f'{base}/cases', {'case_number': fir_num, 'title': 'State of Maharashtra v. Corporate Syndicate', 'agency': 'MUMBAI_CRIME_BRANCH', 'description': 'Economic Offence & Corporate Cyber Intrusion'}, token=p_tok)
case_id = case_res['case_id']
print(f'Case created: {fir_num} (ID: {case_id})')

print('=== 3. Upload Document to Case ===')
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
lines = [
    f'--{boundary}',
    'Content-Disposition: form-data; name="classification"',
    '',
    'RESTRICTED',
    f'--{boundary}',
    'Content-Disposition: form-data; name="file"; filename="cctv_corridor_log.txt"',
    'Content-Type: text/plain',
    '',
    'CCTV LOG REPORT: Camera 04 recorded suspect entering via North Gate at 22:14:02 IST. Vehicle Observed: MH-01-AB-1234 Dark Sedan parked outside perimeter.',
    f'--{boundary}--',
    ''
]
body = '\r\n'.join(lines).encode('utf-8')
req = urllib.request.Request(f'{base}/cases/{case_id}/documents/upload-direct', data=body, headers={
    'Content-Type': f'multipart/form-data; boundary={boundary}',
    'Authorization': f'Bearer {p_tok}'
})
with urllib.request.urlopen(req) as resp:
    doc_ver = json.loads(resp.read().decode('utf-8'))
version_id = doc_ver['version_id']
print(f'Document uploaded! Version ID: {version_id}, SHA-256 Digest: {doc_ver["digest"][:20]}...')

print('=== 4. Police Hands Over to CFSL Forensic Lab ===')
t1 = post_json(f'{base}/versions/{version_id}/transfers', {
    'recipient_id': 'analyst_roy',
    'recipient_agency': 'CFSL_MUMBAI',
    'reason': 'Forensic verification of electronic perimeter logs'
}, token=p_tok)
t1_id = t1['transfer_id']
print(f'Transfer to CFSL initiated: {t1_id}')

print('=== 5. Login CFSL Scientist & Accept Handover ===')
f_login = post_json(f'{base}/auth/login', {'username': 'analyst_roy', 'password': 'Password@123', 'role': 'FORENSIC_EXAMINER', 'agency': 'CFSL_MUMBAI'})
f_tok = f_login['token']
accept1 = post_json(f'{base}/transfers/{t1_id}/accept', {'notes': 'Accepted exhibit into CFSL clean room'}, token=f_tok)
print(f'Custody accepted by CFSL: state = {accept1["state"]}')

print('=== 6. CFSL Runs AI Intelligence Scan ===')
ai_res = post_json(f'{base}/cases/{case_id}/analysis', {'analysis_type': 'SUMMARY', 'document_version_ids': [version_id]}, token=f_tok)
print(f'AI Findings returned: Scanned {ai_res["scanned_count"]} exhibits. Corroborations count: {len(ai_res["corroborations"])}')

print('=== 7. CFSL Hands Over to Public Prosecutor ===')
t2 = post_json(f'{base}/versions/{version_id}/transfers', {
    'recipient_id': 'prosecutor_iyer',
    'recipient_agency': 'MUMBAI_PROSECUTION',
    'reason': 'CFSL analysis complete; ready for court docket compilation'
}, token=f_tok)
t2_id = t2['transfer_id']
print(f'Transfer to Prosecutor initiated: {t2_id}')

print('=== 8. Login Prosecutor & Accept Handover ===')
pr_login = post_json(f'{base}/auth/login', {'username': 'prosecutor_iyer', 'password': 'Password@123', 'role': 'PROSECUTOR', 'agency': 'MUMBAI_PROSECUTION'})
pr_tok = pr_login['token']
accept2 = post_json(f'{base}/transfers/{t2_id}/accept', {'notes': 'Accepted for trial filing'}, token=pr_tok)
print(f'Custody accepted by Prosecutor: state = {accept2["state"]}')

print('=== 9. Prosecutor Submits to Hon. Sessions Judge ===')
t3 = post_json(f'{base}/versions/{version_id}/transfers', {
    'recipient_id': 'judge_kulkarni',
    'recipient_agency': 'BOMBAY_SESSIONS_COURT',
    'reason': 'Tendered in evidence under Section 63 BSA 2023'
}, token=pr_tok)
t3_id = t3['transfer_id']
print(f'Submission to Judge initiated: {t3_id}')

print('=== 10. Login Judge & Accept Handover ===')
j_login = post_json(f'{base}/auth/login', {'username': 'judge_kulkarni', 'password': 'Password@123', 'role': 'JUDGE', 'agency': 'BOMBAY_SESSIONS_COURT'})
j_tok = j_login['token']
accept3 = post_json(f'{base}/transfers/{t3_id}/accept', {'notes': 'Admitted to judicial record'}, token=j_tok)
print(f'Custody accepted by Judge: state = {accept3["state"]}')

print('=== 11. Unauthorized Bit-Level Tampering Simulation ===')
u_login = post_json(f'{base}/auth/login', {'username': 'suspect_malicious', 'password': 'Password@123', 'role': 'UNAUTHORIZED', 'agency': 'EXTERNAL'})
u_tok = u_login['token']
tamper_res = post_json(f'{base}/versions/{version_id}/tamper', {'tamper_mode': 'BYTE_CORRUPTION'}, token=u_tok)
print(f'Tamper executed! Status: {tamper_res["status"]}, Message: {tamper_res["message"]}')

print('=== 12. Judge Inspects Evidence & Detects Tampering ===')
inspect_tampered = get_json(f'{base}/versions/{version_id}/inspect', token=j_tok)
print(f'Judge Inspection: is_valid = {inspect_tampered["is_valid"]}, state = {inspect_tampered["state"]}, hash_match = {inspect_tampered["hash_match"]}')
assert inspect_tampered['is_valid'] == False
assert inspect_tampered['state'] == 'QUARANTINED'

print('=== 13. Judge Retrieves Original Evidence Using Original Hash ===')
restore_res = post_json(f'{base}/versions/{version_id}/restore', {}, token=j_tok)
print(f'Judge Restore: state = {restore_res["state"]}')

print('=== 14. Judge Re-Inspects Evidence Post-Restoration ===')
inspect_restored = get_json(f'{base}/versions/{version_id}/inspect', token=j_tok)
print(f'Judge Inspection Restored: is_valid = {inspect_restored["is_valid"]}, state = {inspect_restored["state"]}')
assert inspect_restored['is_valid'] == True
assert inspect_restored['state'] in ['SEALED', 'READY_PENDING_ANCHOR']

print('ALL MULTI-AUTHORITY LIFECYCLE TESTS PASSED 100% PERFECTLY!')
