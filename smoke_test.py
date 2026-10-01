import urllib.request
import urllib.parse
import json
import sys

BASE = 'http://localhost:8000'

def req(method, path, body=None, token=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

print('=' * 60)
print('SMOKE TEST - 4 MECANISMOS DE SEGURANCA')
print('=' * 60)

# Health check
s, d = req('GET', '/health')
print(f'\n[SISTEMA] Health: {s} -> {d["status"]}')

# Registro de usuarios
print('\n--- AUTENTICACAO ---')
s, alice = req('POST', '/auth/register', {'username': 'alice_test', 'password': 'senha12345'})
print(f'[AUTH] Registro alice: {s} -> user_id={alice.get("user_id","ERR")}')

s, bob = req('POST', '/auth/register', {'username': 'bob_test', 'password': 'senha12345'})
print(f'[AUTH] Registro bob:   {s} -> user_id={bob.get("user_id","ERR")}')

token_alice = alice.get('access_token')
token_bob   = bob.get('access_token')

# [MECANISMO 1] Criar registro com cifragem
print('\n--- [MECANISMO 1] ENVELOPE ENCRYPTION ---')
s, rec = req('POST', '/records', {'nome': 'Alice Souza', 'cpf': '123.456.789-00', 'valor': 15750.00}, token_alice)
print(f'[M1] POST /records: HTTP {s}')
print(f'     cpf_mascarado = {rec.get("cpf_mascarado")} (CPF real cifrado no banco)')
print(f'     valor         = R${rec.get("valor")}')
rec_id = rec.get('id')

# [MECANISMO 2] RLS - Bob NAO deve ver registros de Alice
print('\n--- [MECANISMO 2] ROW-LEVEL SECURITY ---')
s, bob_records = req('GET', '/records', token=token_bob)
print(f'[M2] Bob tenta GET /records (deve ser vazio): HTTP {s} -> {len(bob_records)} registros')
s, bob_one = req('GET', f'/records/{rec_id}', token=token_bob)
print(f'[M2] Bob tenta GET /records/id_alice:         HTTP {s} -> {bob_one.get("detail","OK")}')
s, alice_records = req('GET', '/records', token=token_alice)
print(f'[M2] Alice GET /records (deve ter 1):         HTTP {s} -> {len(alice_records)} registro(s)')

# [MECANISMO 4] View mascarada
print('\n--- [MECANISMO 4] MASCARAMENTO DINAMICO ---')
s, masked = req('GET', '/records/masked', token=token_alice)
print(f'[M4] GET /records/masked: HTTP {s} -> {len(masked)} registro(s)')
if masked:
    m = masked[0]
    print(f'     nome_mascarado  = {m["nome_mascarado"]}')
    print(f'     cpf_mascarado   = {m["cpf_mascarado"]}')
    print(f'     valor_mascarado = {m["valor_mascarado"]}')
    print(f'     dek_status      = {m["dek_status"]}')

# [MECANISMO 3] Audit logs + hash chain
print('\n--- [MECANISMO 3] AUDIT HASH CHAIN ---')
s, logs = req('GET', '/audit/logs', token=token_alice)
print(f'[M3] GET /audit/logs: HTTP {s} -> {len(logs)} entradas')
if logs:
    L = logs[0]
    print(f'     Operacao:  {L["operation"]}')
    print(f'     row_hash:  {L["row_hash"][:40]}...')
    prev = L["prev_hash"]
    prev_str = prev[:20] if prev else "GENESIS (primeiro registro)"
    print(f'     prev_hash: {prev_str}')

s, verify = req('GET', '/audit/verify', token=token_alice)
print(f'[M3] GET /audit/verify: HTTP {s} -> {len(verify)} entradas verificadas')
all_valid = all(v['is_valid'] for v in verify)
status_str = "OK - Cadeia integra!" if all_valid else "FALHA na cadeia!"
print(f'     Resultado: {status_str}')

print('\n' + '=' * 60)
if all_valid:
    print('TODOS OS 4 MECANISMOS FUNCIONANDO CORRETAMENTE!')
else:
    print('ATENCAO: Verifique os logs dos containers')
print('Swagger: http://localhost:8000/docs')
print('=' * 60)
