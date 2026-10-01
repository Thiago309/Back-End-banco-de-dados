-- =============================================================================
-- init.sql
-- Script de inicialização do banco de dados PostgreSQL.
-- Executado automaticamente no primeiro start do container.
--
-- Implementa:
--   [MECANISMO 2] Row-Level Security (RLS)
--   [MECANISMO 3] Trilha de Auditoria com Hash Chaining
--   [MECANISMO 4] RBAC e View Mascarada (Menor Privilégio)
-- =============================================================================


-- =============================================================================
-- SEÇÃO 1: EXTENSÕES
-- =============================================================================

-- pgcrypto: fornece funções criptográficas nativas ao PostgreSQL,
-- usadas para calcular SHA-256 no hash chaining (Mecanismo 3).
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- =============================================================================
-- SEÇÃO 2: [MECANISMO 4 - MENOR PRIVILÉGIO / RBAC]
-- Criação de roles com permissões mínimas necessárias.
-- =============================================================================

-- Role de leitura (somente SELECT)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'readonly_role') THEN
    CREATE ROLE readonly_role NOLOGIN;
  END IF;
END
$$;

-- Role de operação da API (DML: SELECT, INSERT, UPDATE, DELETE)
-- Esta role NÃO tem permissão de DDL (CREATE, DROP, ALTER, etc.)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_role') THEN
    CREATE ROLE api_role NOLOGIN;
  END IF;
END
$$;

-- Usuário concreto que a API usa para conectar ao banco.
-- Recebe apenas o mínimo necessário via api_role.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_user') THEN
    CREATE USER api_user WITH PASSWORD 'ApiUserPass456!';
  END IF;
END
$$;

-- Atribui a role de API ao usuário da aplicação
GRANT api_role TO api_user;

-- Permite que api_user defina parâmetros de sessão locais
-- (necessário para injetar o current_user_id no RLS - Mecanismo 2)
ALTER USER api_user SET search_path = public;


-- =============================================================================
-- SEÇÃO 3: SCHEMA PRINCIPAL - TABELA DE REGISTROS FINANCEIROS
-- =============================================================================

-- Tabela principal que armazena os dados (parcialmente cifrados no app).
-- Os campos cpf_enc e valor_enc são ciphertext AES-256-GCM gerados pelo Python.
-- A DEK cifrada (dek_enc) também é armazenada aqui (Envelope Encryption).
CREATE TABLE IF NOT EXISTS financial_records (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ID do tenant/usuário dono do registro.
    -- [MECANISMO 2 - RLS] Usado pela política de segurança em nível de linha.
    owner_id        UUID        NOT NULL,

    -- Nome do titular (armazenado em claro para demonstração de mascaramento)
    nome            TEXT        NOT NULL,

    -- [MECANISMO 1 - ENVELOPE ENCRYPTION]
    -- Ciphertext do CPF cifrado com AES-256-GCM (DEK) + codificado em base64
    cpf_enc         TEXT        NOT NULL,

    -- [MECANISMO 1 - ENVELOPE ENCRYPTION]
    -- Ciphertext do valor financeiro cifrado com AES-256-GCM
    valor_enc       TEXT        NOT NULL,

    -- [MECANISMO 1 - ENVELOPE ENCRYPTION]
    -- A DEK (Data Encryption Key) cifrada com a KEK (Key Encryption Key).
    -- Cada registro tem sua própria DEK - princípio de isolamento de chaves.
    dek_enc         TEXT        NOT NULL,

    -- Metadados de auditoria básica (complementa o hash chain)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =============================================================================
-- SEÇÃO 4: [MECANISMO 2 - ROW-LEVEL SECURITY (RLS)]
-- =============================================================================

-- Ativa o RLS na tabela principal.
-- Sem uma política ativa, NENHUMA linha é retornada (default-deny).
ALTER TABLE financial_records ENABLE ROW LEVEL SECURITY;

-- Força o RLS mesmo para o owner da tabela (exceto superusuários).
-- IMPORTANTE: sem FORCE, o owner da tabela burla as políticas.
ALTER TABLE financial_records FORCE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------
-- POLÍTICA RLS: Um tenant só pode ver e modificar suas próprias linhas.
--
-- Como funciona:
--   1. O Python injeta no início de cada transação:
--      SET LOCAL app.current_user_id = '<uuid-do-usuario-autenticado>';
--   2. A política abaixo compara owner_id com esse parâmetro de sessão.
--   3. Se não bater, a linha é invisível para SELECT/UPDATE/DELETE.
-- -----------------------------------------------------------------------
DROP POLICY IF EXISTS tenant_isolation_policy ON financial_records;

CREATE POLICY tenant_isolation_policy
    ON financial_records
    -- Aplica para todas as operações DML
    FOR ALL
    -- Aplica para a role da API
    TO api_role
    -- Expressão USING: filtra linhas na leitura (SELECT, UPDATE, DELETE)
    USING (
        owner_id = current_setting('app.current_user_id', TRUE)::UUID
    )
    -- Expressão WITH CHECK: valida linhas no write (INSERT, UPDATE)
    WITH CHECK (
        owner_id = current_setting('app.current_user_id', TRUE)::UUID
    );


-- =============================================================================
-- SEÇÃO 5: [MECANISMO 3 - TRILHA DE AUDITORIA COM HASH CHAINING]
-- =============================================================================

-- Tabela de auditoria imutável.
-- Cada evento de mudança gera um registro com hash encadeado.
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL   PRIMARY KEY,

    -- Referência ao registro afetado
    record_id       UUID        NOT NULL,

    -- Tipo de operação: INSERT, UPDATE, DELETE
    operation       TEXT        NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),

    -- ID do usuário da sessão (extraído do parâmetro RLS)
    performed_by    TEXT,

    -- Snapshot dos dados ANTES da operação (NULL em INSERT)
    old_data        JSONB,

    -- Snapshot dos dados DEPOIS da operação (NULL em DELETE)
    new_data        JSONB,

    -- Timestamp do evento
    event_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- [MECANISMO 3 - HASH CHAINING]
    -- Hash SHA-256 do conteúdo desta linha + hash da linha ANTERIOR.
    -- Cria uma cadeia: qualquer adulteração retroativa quebra todos os hashes seguintes.
    row_hash        TEXT        NOT NULL,

    -- Hash da linha anterior (NULL apenas para o primeiro registro).
    -- Armazenado para facilitar verificação da cadeia.
    prev_hash       TEXT
);

-- A tabela de auditoria NÃO tem RLS — todos os logs são preservados integralmente.
-- O api_user só pode fazer INSERT nela (sem UPDATE/DELETE para proteção da trilha).
-- (Permissões concedidas na Seção 6)


-- -----------------------------------------------------------------------
-- FUNÇÃO: Calcula o hash SHA-256 de uma linha de auditoria + hash anterior
--
-- [MECANISMO 3 - HASH CHAINING]
-- O hash é calculado sobre a concatenação de:
--   record_id | operation | performed_by | old_data | new_data | event_at | prev_hash
--
-- Isso garante que cada entrada depende do conteúdo completo da entrada
-- atual E do hash imediatamente anterior — formando a cadeia.
-- -----------------------------------------------------------------------
CREATE OR REPLACE FUNCTION compute_audit_hash(
    p_record_id   UUID,
    p_operation   TEXT,
    p_performed_by TEXT,
    p_old_data    JSONB,
    p_new_data    JSONB,
    p_event_at    TIMESTAMPTZ,
    p_prev_hash   TEXT
) RETURNS TEXT AS $$
DECLARE
    raw_data TEXT;
BEGIN
    -- Concatena todos os campos relevantes em uma string canônica.
    -- COALESCE garante que NULLs virem string vazia, não quebrem a concatenação.
    raw_data := COALESCE(p_record_id::TEXT, '')
             || '|' || COALESCE(p_operation, '')
             || '|' || COALESCE(p_performed_by, '')
             || '|' || COALESCE(p_old_data::TEXT, 'null')
             || '|' || COALESCE(p_new_data::TEXT, 'null')
             || '|' || COALESCE(p_event_at::TEXT, '')
             || '|' || COALESCE(p_prev_hash, 'GENESIS');  -- 'GENESIS' para o 1º registro

    -- digest() é da extensão pgcrypto — retorna bytes; encode() converte para hex
    RETURN encode(digest(raw_data, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql;


-- -----------------------------------------------------------------------
-- FUNÇÃO TRIGGER: Executada em cada INSERT/UPDATE/DELETE em financial_records
--
-- [MECANISMO 3 - HASH CHAINING]
-- 1. Busca o hash da última linha de auditoria (prev_hash).
-- 2. Calcula o novo hash com compute_audit_hash().
-- 3. Insere o novo registro na audit_log com o hash encadeado.
-- -----------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_trigger() RETURNS TRIGGER AS $$
DECLARE
    v_prev_hash   TEXT;
    v_new_hash    TEXT;
    v_record_id   UUID;
    v_old_data    JSONB;
    v_new_data    JSONB;
    v_operation   TEXT;
    v_performed_by TEXT;
    v_event_at    TIMESTAMPTZ;
BEGIN
    v_event_at    := NOW();
    v_operation   := TG_OP;  -- 'INSERT', 'UPDATE' ou 'DELETE'

    -- Captura o ID do usuário autenticado injetado pelo Python via SET LOCAL
    v_performed_by := current_setting('app.current_user_id', TRUE);

    -- Determina o record_id e os dados old/new conforme a operação
    IF TG_OP = 'DELETE' THEN
        v_record_id := OLD.id;
        v_old_data  := to_jsonb(OLD);
        v_new_data  := NULL;
    ELSIF TG_OP = 'INSERT' THEN
        v_record_id := NEW.id;
        v_old_data  := NULL;
        v_new_data  := to_jsonb(NEW);
    ELSE  -- UPDATE
        v_record_id := NEW.id;
        v_old_data  := to_jsonb(OLD);
        v_new_data  := to_jsonb(NEW);
    END IF;

    -- [HASH CHAINING] Busca o hash do registro mais recente da cadeia
    SELECT row_hash INTO v_prev_hash
    FROM   audit_log
    ORDER  BY id DESC
    LIMIT  1;
    -- Se não houver registro anterior, v_prev_hash fica NULL (tratado como GENESIS)

    -- Calcula o novo hash encadeado
    v_new_hash := compute_audit_hash(
        v_record_id,
        v_operation,
        v_performed_by,
        v_old_data,
        v_new_data,
        v_event_at,
        v_prev_hash
    );

    -- Insere o registro de auditoria com o hash calculado
    INSERT INTO audit_log (
        record_id, operation, performed_by,
        old_data, new_data, event_at,
        row_hash, prev_hash
    ) VALUES (
        v_record_id, v_operation, v_performed_by,
        v_old_data, v_new_data, v_event_at,
        v_new_hash, v_prev_hash
    );

    -- Retorno obrigatório para triggers AFTER
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql
   -- SECURITY DEFINER: executa com permissões do criador (postgres),
   -- permitindo que api_user faça INSERT em audit_log sem permissão direta de escrita
   SECURITY DEFINER;


-- -----------------------------------------------------------------------
-- TRIGGER: Dispara a função de auditoria após cada operação DML
--
-- [MECANISMO 3 - HASH CHAINING]
-- AFTER: garante que o dado já foi persistido antes do log.
-- FOR EACH ROW: um evento de auditoria por linha afetada.
-- -----------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_financial_audit ON financial_records;

CREATE TRIGGER trg_financial_audit
    AFTER INSERT OR UPDATE OR DELETE
    ON financial_records
    FOR EACH ROW
    EXECUTE FUNCTION fn_audit_trigger();


-- =============================================================================
-- SEÇÃO 6: [MECANISMO 4 - MASCARAMENTO DINÂMICO]
-- View que mascara dados sensíveis para leitura padrão.
-- =============================================================================

-- -----------------------------------------------------------------------
-- VIEW MASCARADA: financial_records_masked
--
-- [MECANISMO 4 - MASCARAMENTO DINÂMICO]
-- Expõe apenas os 4 últimos dígitos do CPF (após decifrado e mascarado).
-- Na prática, como o CPF está cifrado (base64), o mascaramento é feito
-- pela API após decifrar. Esta view demonstra o padrão SQL de mascaramento
-- aplicado a um campo de texto em claro como o 'nome'.
--
-- Para o CPF cifrado: a view retorna apenas um prefixo do ciphertext,
-- indicando que o dado existe mas está protegido. A decifração completa
-- é feita pela API somente para usuários autorizados com a devida DEK.
-- -----------------------------------------------------------------------
CREATE OR REPLACE VIEW financial_records_masked AS
SELECT
    id,
    owner_id,

    -- Mascaramento do nome: exibe apenas as 3 primeiras letras + asteriscos
    -- Exemplo: "João Silva" → "Joã*******"
    CASE
        WHEN length(nome) > 3
        THEN left(nome, 3) || repeat('*', length(nome) - 3)
        ELSE repeat('*', length(nome))
    END AS nome_mascarado,

    -- [MECANISMO 4 - MASCARAMENTO DINÂMICO]
    -- O CPF está cifrado (base64). A view expõe apenas os primeiros 8 chars
    -- do ciphertext para confirmar que o campo tem dado, sem revelar conteúdo.
    -- A API decifra o valor completo apenas após autenticação.
    left(cpf_enc, 8) || '...[CIFRADO]' AS cpf_mascarado,

    -- O valor financeiro também está cifrado; mesma lógica de mascaramento
    left(valor_enc, 8) || '...[CIFRADO]' AS valor_mascarado,

    -- A DEK cifrada nunca é exposta diretamente via view
    '[PROTEGIDO]' AS dek_status,

    created_at,
    updated_at
FROM
    financial_records;

-- A view herda automaticamente as políticas RLS da tabela base.
-- api_user só verá linhas onde owner_id = app.current_user_id


-- =============================================================================
-- SEÇÃO 7: CONCESSÃO DE PERMISSÕES (RBAC)
--
-- [MECANISMO 4 - MENOR PRIVILÉGIO]
-- Concede apenas o mínimo necessário a cada role.
-- =============================================================================

-- Revoga permissões padrão públicas (boa prática de segurança)
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- api_role: DML na tabela principal e SELECT na view mascarada
GRANT USAGE ON SCHEMA public TO api_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON financial_records TO api_role;
GRANT SELECT ON financial_records_masked TO api_role;

-- api_role: SELECT na audit_log (para o endpoint de consulta de logs)
-- INSERT é feito via função SECURITY DEFINER, sem precisar de permissão direta
GRANT SELECT ON audit_log TO api_role;

-- Permite uso da sequência do audit_log (necessário para SECURITY DEFINER INSERT)
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO api_role;

-- readonly_role: apenas SELECT nas views mascaradas (sem acesso à tabela raw)
GRANT USAGE ON SCHEMA public TO readonly_role;
GRANT SELECT ON financial_records_masked TO readonly_role;
GRANT SELECT ON audit_log TO readonly_role;

-- Garante que futuras tabelas também sejam protegidas
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON TABLES FROM PUBLIC;


-- =============================================================================
-- SEÇÃO 8: TABELA DE USUÁRIOS DA APLICAÇÃO (Para autenticação JWT)
-- =============================================================================

-- Tabela simples de usuários para simular autenticação.
-- Em produção, usaria um IdP externo (Keycloak, Auth0, etc.)
CREATE TABLE IF NOT EXISTS app_users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT        UNIQUE NOT NULL,
    -- Senha armazenada como hash bcrypt (nunca em texto claro!)
    hashed_password TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- api_role pode inserir e consultar usuários
GRANT SELECT, INSERT ON app_users TO api_role;

-- Insere dois usuários de teste
-- Senhas: alice_secure_pwd e bob_secure_pwd (hash bcrypt pré-computado)
INSERT INTO app_users (username, hashed_password)
VALUES
    ('alice', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lfD9P4cZ4N.YgcZ.6'),
    ('bob',   '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC1/9L6HL1bS2mVlIcKi')
ON CONFLICT (username) DO NOTHING;

-- Comentário: os hashes acima são placeholders; o endpoint /register
-- gera hashes bcrypt corretos via Python.


-- =============================================================================
-- FUNÇÃO: Verifica integridade da cadeia de auditoria
--
-- [MECANISMO 3 - HASH CHAINING]
-- Recalcula todos os hashes e compara com os armazenados.
-- Retorna TRUE se a cadeia estiver íntegra, FALSE se houver adulteração.
-- =============================================================================
CREATE OR REPLACE FUNCTION verify_audit_chain() RETURNS TABLE (
    log_id          BIGINT,
    is_valid        BOOLEAN,
    stored_hash     TEXT,
    computed_hash   TEXT
) AS $$
DECLARE
    rec         RECORD;
    v_prev_hash TEXT := NULL;
    v_computed  TEXT;
BEGIN
    FOR rec IN
        SELECT * FROM audit_log ORDER BY id ASC
    LOOP
        -- Recalcula o hash esperado para esta linha
        v_computed := compute_audit_hash(
            rec.record_id,
            rec.operation,
            rec.performed_by,
            rec.old_data,
            rec.new_data,
            rec.event_at,
            v_prev_hash  -- usa o hash calculado da linha anterior (não o armazenado)
        );

        log_id        := rec.id;
        stored_hash   := rec.row_hash;
        computed_hash := v_computed;
        is_valid      := (rec.row_hash = v_computed);

        RETURN NEXT;

        -- Avança a cadeia com o hash desta linha (calculado, não armazenado)
        v_prev_hash := v_computed;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Concede execução da função de verificação ao api_role
GRANT EXECUTE ON FUNCTION verify_audit_chain() TO api_role;
GRANT EXECUTE ON FUNCTION compute_audit_hash(UUID, TEXT, TEXT, JSONB, JSONB, TIMESTAMPTZ, TEXT) TO api_role;
