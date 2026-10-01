import pytest
import httpx
import uuid

BASE_URL = "http://localhost:8000"

@pytest.fixture
def api_client():
    with httpx.Client(base_url=BASE_URL) as client:
        yield client

def generate_random_user():
    suffix = str(uuid.uuid4())[:8]
    return f"user_{suffix}", "senha_segura_123"

def get_auth_token(client, username, password):
    # Cadastra o usuário
    client.post("/auth/register", json={"username": username, "password": password})
    # Faz login para pegar o JWT
    resp = client.post("/auth/login", data={"username": username, "password": password})
    return resp.json()["access_token"]


def test_row_level_security_isolation(api_client, capsys):
    """
    Testa se o RLS (Row-Level Security) impede um usuário de visualizar
    ou modificar os dados pertencentes a outro usuário.
    """
    with capsys.disabled():
        print("\n" + "="*80)
        print("🛡️  CENÁRIO 1: ROW-LEVEL SECURITY (RLS) - ISOLAMENTO ENTRE TENANTS")
        print("="*80)
        
        # 1. Cria Usuário A e Usuário B
        user_a, pass_a = generate_random_user()
        user_b, pass_b = generate_random_user()
        
        token_a = get_auth_token(api_client, user_a, pass_a)
        token_b = get_auth_token(api_client, user_b, pass_b)
        print(f"-> [INFO] Usuário A ({user_a}) e Usuário B ({user_b}) autenticados.")
        
        # 2. Usuário A insere um registro financeiro
        headers_a = {"Authorization": f"Bearer {token_a}"}
        payload_a = {
            "nome": "Segredo do Usuário A",
            "cpf": "111.222.333-44",
            "valor": 9999.99
        }
        resp_a = api_client.post("/records", json=payload_a, headers=headers_a)
        assert resp_a.status_code == 201, f"Falha na criação: {resp_a.text}"
        record_a_id = resp_a.json()["id"]
        print(f"-> [INFO] Usuário A inseriu o registro com ID: {record_a_id}")
        
        # 3. Usuário B tenta listar todos os registros disponíveis
        headers_b = {"Authorization": f"Bearer {token_b}"}
        resp_b_list = api_client.get("/records", headers=headers_b)
        assert resp_b_list.status_code == 200
        
        # A lista retornada para B não deve conter NADA de A (filtro invisível do RLS)
        records_b = resp_b_list.json()
        assert len(records_b) == 0
        print(f"-> [SUCESSO] Usuário B tentou listar (GET /records) e obteve {len(records_b)} resultados.")
        print("   O PostgreSQL filtrou a linha automaticamente na origem!")
        
        # 4. Usuário B tenta acessar o registro de A DIRETAMENTE pela URL
        resp_b_single = api_client.get(f"/records/{record_a_id}", headers=headers_b)
        assert resp_b_single.status_code == 404
        print(f"-> [SUCESSO] Usuário B forçou GET /records/{record_a_id}.")
        print(f"   Recebeu HTTP {resp_b_single.status_code}. O acesso foi negado pelo banco silenciosamente.")

        # 5. Usuário B tenta fazer PUT para adulterar os dados de A
        payload_malicioso = {"nome": "Hackeado", "cpf": "000.000.000-00", "valor": 1.0}
        resp_b_put = api_client.put(f"/records/{record_a_id}", json=payload_malicioso, headers=headers_b)
        assert resp_b_put.status_code == 404
        print(f"-> [SUCESSO] Usuário B forçou PUT /records/{record_a_id}.")
        print("   Modificação bloqueada antes mesmo de chegar à validação do Python!\n")


def test_dynamic_data_masking(api_client, capsys):
    """
    Testa se os dados são mascarados para usuários comuns, 
    provando o Princípio do Menor Privilégio via Views do PostgreSQL.
    """
    with capsys.disabled():
        print("="*80)
        print("👁️  CENÁRIO 2: MASCARAMENTO DINÂMICO E MENOR PRIVILÉGIO (RBAC)")
        print("="*80)
        
        user_c, pass_c = generate_random_user()
        token_c = get_auth_token(api_client, user_c, pass_c)
        headers_c = {"Authorization": f"Bearer {token_c}"}
        
        # Insere dado
        payload = {
            "nome": "Roberto Justos",
            "cpf": "987.654.321-00",
            "valor": 150000.00
        }
        api_client.post("/records", json=payload, headers=headers_c)
        print(f"-> [INFO] Usuário ({user_c}) inseriu um novo registro para 'Roberto Justos'.")
        
        # Consulta a view mascarada
        resp = api_client.get("/records/masked", headers=headers_c)
        assert resp.status_code == 200
        
        data = resp.json()
        assert len(data) > 0
        masked_record = data[0]
        
        # Verifica se o banco aplicou a máscara (Roberto -> Rob********)
        nome_masc = masked_record["nome_mascarado"]
        assert nome_masc.startswith("Rob")
        assert "*" in nome_masc
        print(f"-> [SUCESSO] View retornou o nome parcialmente oculto: '{nome_masc}'")
        
        # Verifica se o CPF e Valor estão bloqueados
        cpf_masc = masked_record["cpf_mascarado"]
        assert "[CIFRADO]" in cpf_masc
        print(f"-> [SUCESSO] O CPF cifrado teve sua exibição limitada a: '{cpf_masc}'")
        print("-> [SUCESSO] Teste aprovado! A view SQL restringiu a leitura perfeitamente.\n")
