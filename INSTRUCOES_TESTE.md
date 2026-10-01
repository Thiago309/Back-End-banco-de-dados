# 🧪 Roteiro de Testes e Prova de Segurança (Apresentação)

Este é o roteiro exato para você apresentar o projeto ao avaliador. Ele executa testes ponta-a-ponta na API e provas diretas dentro do banco de dados, confirmando a robustez dos 4 mecanismos.

## 1. Instalação das Dependências de Teste

Abra um terminal na pasta raiz do projeto (`Back-End-banco-de-dados`) e certifique-se de que os containers do Docker estão rodando (banco e API). 

Em seguida, instale os pacotes de teste no seu ambiente Python local:

```bash
pip install pytest httpx psycopg2-binary
```

## 2. Testando pela API: RLS e Mascaramento

O script `test_security.py` vai atuar como dois clientes legítimos usando a API. Ele tentará hackear o isolamento dos dados e testar as restrições da visualização.

Para executar com saída didática no console, rode:

```bash
pytest test_security.py -s
```

**O que você apresentará nesta etapa:**
1. **RLS:** Você provará que quando o Usuário A cria um dado, o banco de dados (mesmo sem restrições explícitas no backend Python) filtra e bloqueia invisivelmente a tentativa de leitura e alteração do Usuário B.
2. **Mascaramento:** Você mostrará a resposta JSON oficial da view, onde o nome e CPF do titular vêm ofuscados (`Rob********`, `[CIFRADO]`), comprovando a defesa em profundidade com o Princípio do Menor Privilégio.

## 3. Prova Bypass: Criptografia e Hash Chaining

Agora, a cartada final. O script `prove_security.py` pula a API, não usa credenciais de usuário comum e **se conecta direto ao PostgreSQL como o Administrador Root (DBA)**.

Rode o script:

```bash
python prove_security.py
```

**O que você apresentará nesta etapa:**
1. **Envelope Encryption:** O script listará a tabela bruta. Você vai mostrar ao avaliador que o DBA vê nomes em claro, mas os CPFs e Valores estão totalmente ofuscados e ilegíveis (como hashes hexadecimais ininteligíveis), pois a API criptografou antes.
2. **Hash Chaining:** O script baixará os logs da trilha de auditoria e, em código puro Python, recalculará a matemática SHA-256 para cada linha baseando-se no log anterior. Quando os prints mostrarem os "Hashes idênticos", você provará de forma inquestionável que a estrutura no banco não foi adulterada retroativamente!

## 4. Bônus: Verificação Manual via Bash (Terminal Interativo)

Caso o avaliador peça para ver os dados "com os próprios olhos" no banco, sem depender do Python, você pode usar os comandos bash abaixo para rodar SQLs diretamente no container do PostgreSQL:

**Comando para provar o Envelope Encryption (Criptografia):**
```bash
docker exec -it secure_db psql -U postgres -d securedb -c "SELECT id, nome, left(cpf_enc, 25) AS cpf_cifrado, left(dek_enc, 25) AS dek_cifrada FROM financial_records;"
```
*(Você mostrará que, mesmo logado no banco como Super Administrador `postgres`, os dados sensíveis e as chaves DEK estão ilegíveis em Base64).*

**Comando para provar o Hash Chaining (Auditoria):**
```bash
docker exec -it secure_db psql -U postgres -d securedb -c "SELECT id, operation, row_hash, prev_hash FROM audit_log ORDER BY id ASC;"
```
*(Você mostrará a tabela de auditoria real gravada no disco, com a cadeia de hashes interligada).*

**Comando para provar o Mascaramento e Menor Privilégio (RBAC):**
```bash
docker exec -it secure_db psql -U api_user -d securedb -c "SELECT nome_mascarado, cpf_mascarado, dek_status FROM financial_records_masked;"
```
*(Você mostrará a view SQL conectando com o usuário restrito da API `api_user`, retornando diretamente os asteriscos e as flags `[CIFRADO]`).*
