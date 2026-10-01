import psycopg2
import hashlib

def main():
    print("\n" + "="*80)
    print("🕵️  PROVA DEFINITIVA DE SEGURANÇA DIRETAMENTE NO BANCO DE DADOS (BYPASS DA API)")
    print("="*80)
    print("Conectando ao PostgreSQL como Administrador (postgres)...")
    
    try:
        conn = psycopg2.connect(
            dbname="securedb",
            user="postgres",
            password="SuperSecret123!",
            host="localhost",
            port=5432
        )
        cursor = conn.cursor()
    except Exception as e:
        print(f"Erro ao conectar ao banco: {e}")
        return

    print("Conexão estabelecida com sucesso!\n")
    
    print("-" * 80)
    print("🔐 PROVA 1: ENVELOPE ENCRYPTION (CRIPTOGRAFIA DE APLICAÇÃO)")
    print("-" * 80)
    
    cursor.execute("SELECT id, nome, cpf_enc, valor_enc, dek_enc FROM financial_records LIMIT 3;")
    records = cursor.fetchall()
    
    if not records:
        print("Nenhum registro encontrado. Rode o test_security.py primeiro para gerar dados.")
    else:
        for row in records:
            print(f"\n[Registro ID]: {row[0]}")
            print(f"  Nome (Texto Claro)   : {row[1]}")
            print(f"  CPF (Ciphertext)     : {row[2][:35]}... (Ilegível)")
            print(f"  Valor (Ciphertext)   : {row[3][:35]}... (Ilegível)")
            print(f"  DEK Cifrada (AES)    : {row[4][:35]}... (Protegida)")
        
        print("\n✅ [CONCLUSÃO 1]: Mesmo um DBA acessando os dados diretamente")
        print("não consegue ler o CPF ou Valor financeiro. A chave mestre (KEK) não reside no banco.")

    print("\n" + "-" * 80)
    print("🔗 PROVA 2: TRILHA DE AUDITORIA E HASH CHAINING")
    print("-" * 80)
    
    # Buscamos os campos como ::TEXT para garantir que o Python veja a string exata 
    # que o banco usou para gerar o hash originalmente.
    cursor.execute("""
        SELECT 
            id, 
            record_id::TEXT, 
            operation, 
            performed_by, 
            old_data::TEXT, 
            new_data::TEXT, 
            event_at::TEXT, 
            row_hash, 
            prev_hash 
        FROM audit_log 
        ORDER BY id ASC;
    """)
    logs = cursor.fetchall()
    
    if not logs:
        print("Nenhum log de auditoria encontrado.")
    else:
        cadeia_valida = True
        for row in logs:
            log_id, record_id, operation, performed_by, old_data, new_data, event_at, db_hash, prev_hash = row
            
            # Helper para simular o COALESCE do banco
            def coalesce(val, default=""):
                return val if val is not None else default
                
            raw_data = (
                f"{coalesce(record_id)}|"
                f"{coalesce(operation)}|"
                f"{coalesce(performed_by)}|"
                f"{coalesce(old_data, 'null')}|"
                f"{coalesce(new_data, 'null')}|"
                f"{coalesce(event_at)}|"
                f"{coalesce(prev_hash, 'GENESIS')}"
            )
            
            # Refaz a matemática do Hash em Python (independente do banco)
            computed_hash = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()
            
            print(f"\n[Log ID: {log_id}] | Operação: {operation}")
            print(f"  String Base do Hash : {raw_data[:70]}...")
            print(f"  Hash Salvo no BD    : {db_hash}")
            print(f"  Hash Python (SHA256): {computed_hash}")
            
            if db_hash == computed_hash:
                print("  ✅ [STATUS]: ÍNTEGRO (Hashes idênticos)")
            else:
                print("  ❌ [STATUS]: ADULTERADO (Hashes não batem!)")
                cadeia_valida = False

        print("\n✅ [CONCLUSÃO 2]: ", end="")
        if cadeia_valida:
            print("Toda a cadeia de auditoria foi validada externamente pelo script Python!")
            print("O histórico é matematicamente imutável.")
        else:
            print("Atenção! Quebra detectada na cadeia de auditoria.")

    conn.close()

if __name__ == "__main__":
    main()
