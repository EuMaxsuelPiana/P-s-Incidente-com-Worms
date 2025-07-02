#!/bin/bash

# ==============================================================================
# Script de Resposta a Incidentes - Detecção de Worm Metamórfico
#
# DESCRIÇÃO:
# Este script automatiza as primeiras ações de resposta a um incidente após a
# detecção de um possível worm com capacidade de metamorfismo.
#
# AVISO:
# Este script realiza ações destrutivas (como deletar arquivos).
# Execute-o com cuidado e apenas em máquinas comprovadamente comprometidas.
# É obrigatório executar como root (ou com sudo) para total funcionalidade.
#
# USO:
# sudo ./vh-incident-response.sh.sh
# ==============================================================================

# --- Verificação de Privilégios ---
if [[ $EUID -ne 0 ]]; then
   echo "ERRO: Este script precisa ser executado como root."
   echo "Use: sudo $0"
   exit 1
fi

# --- Variáveis Globais ---
LOG_FILE="/tmp/incident_report.txt"
BACKUP_DIR="/tmp/incident_backups_$(date +%Y%m%d_%H%M%S)"
SEARCH_PATH="/" # Iniciar a busca a partir da raiz. Mude para /home ou outro se preferir.

# --- Funções Auxiliares ---

# Função para registrar mensagens no console e no arquivo de log
log_action() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] - $1" | tee -a "$LOG_FILE"
}

# --- Início do Script ---

# Limpa o log anterior, se existir, e inicia um novo
echo "==================================================" > "$LOG_FILE"
log_action "Iniciando Script de Resposta a Incidentes."
echo "==================================================" >> "$LOG_FILE"
log_action "Data do Incidente: $(date)"
log_action "Host: $(hostname)"
log_action "Usuário: $(whoami)"
echo "" >> "$LOG_FILE"


# 1. Desconectar a máquina da rede
log_action "Tentando desconectar a máquina da rede..."
# A forma mais robusta é usar 'nmcli', que funciona na maioria dos sistemas modernos.
if command -v nmcli &> /dev/null; then
    nmcli networking off
    log_action "Conexões de rede desativadas com 'nmcli'."
    nmcli general status | tee -a "$LOG_FILE"
else
    # Método alternativo para sistemas mais antigos
    for iface in $(ip -o link show | awk -F': ' '{print $2}'); do
        if [[ "$iface" != "lo" ]]; then
            ip link set "$iface" down
            log_action "Interface '$iface' desativada com 'ip link'."
        fi
    done
fi
echo "" >> "$LOG_FILE"


# 2. Identificar arquivos maliciosos
log_action "Procurando por arquivos suspeitos (worm_*.py, *.py.enc)..."
# Usamos 'find' para procurar arquivos com os padrões especificados.
# O '-o' funciona como um 'OU' na busca.
FOUND_FILES=$(find "$SEARCH_PATH" -type f \( -name "worm_*.py" -o -name "*.py.enc" -o -name "*.txt.enc" \) 2>/dev/null)

if [ -z "$FOUND_FILES" ]; then
    log_action "Nenhum arquivo suspeito encontrado com os padrões definidos."
else
    log_action "Arquivos suspeitos encontrados:"
    echo "$FOUND_FILES" | while IFS= read -r file; do
        echo "  - $file" >> "$LOG_FILE"
    done
    echo "" >> "$LOG_FILE"

    # 3, 4, 5 & 8. Analisar, fazer backup e deletar arquivos encontrados
    log_action "Analisando e processando cada arquivo encontrado..."
    echo "$FOUND_FILES" | while IFS= read -r file; do
        echo "--------------------------------------------------" >> "$LOG_FILE"
        log_action "Analisando: $file"

        # 3. Calcular hash SHA256 e mostrar timestamp
        HASH=$(sha256sum "$file")
        TIMESTAMP=$(stat -c %y "$file")
        log_action "  Hash SHA256: $HASH"
        log_action "  Timestamp (Modificação): $TIMESTAMP"

        # 4. Exibir o proprietário do arquivo
        OWNER=$(stat -c '%U:%G' "$file")
        log_action "  Proprietário: $OWNER"

        # 5. Procurar por padrões de conteúdo (ex: 'import socket', 'eval')
        log_action "  Verificando conteúdo por padrões suspeitos (grep):"
        grep -E -i 'import socket|import os|eval\(|exec\(|subprocess|base64' "$file" >> "$LOG_FILE" 2>&1 || log_action "    Nenhum padrão comum encontrado."

        # 8. Criar backup de arquivos .txt.enc antes de excluir
        if [[ "$file" == *.txt.enc ]]; then
            log_action "  Arquivo .txt.enc detectado. Realizando backup..."
            mkdir -p "$BACKUP_DIR"
            cp -p "$file" "$BACKUP_DIR/"
            log_action "  Backup criado em: $BACKUP_DIR/$(basename "$file")"
        fi

        # 7. Deletar o arquivo detectado
        log_action "  DELETANDO arquivo: $file"
        rm -f "$file"
        if [ $? -eq 0 ]; then
            log_action "  Arquivo deletado com sucesso."
        else
            log_action "  ERRO ao deletar o arquivo $file."
        fi
        echo "--------------------------------------------------" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
    done
fi


# 6. Verificar logs do sistema
log_action "Verificando logs do sistema..."
log_action "Analisando /var/log/syslog e /var/log/auth.log por atividades suspeitas..."
grep -E -i 'worm|python|exploit|failed password' /var/log/syslog /var/log/auth.log >> "$LOG_FILE" 2>/dev/null

log_action "Verificando histórico do Bash (~/.bash_history)..."
if [ -f ~/.bash_history ]; then
    grep -E -i 'worm_|\.py\.enc' ~/.bash_history >> "$LOG_FILE" 2>/dev/null
fi

log_action "Verificando logs do auditd (se ativo)..."
if command -v ausearch &> /dev/null && systemctl is-active --quiet auditd; then
    ausearch -k python_execution >> "$LOG_FILE" 2>/dev/null
else
    log_action "  auditd não está ativo ou 'ausearch' não foi encontrado."
fi
echo "" >> "$LOG_FILE"


# 9. Ativar monitoramento com inotifywait
log_action "Configurando monitoramento de arquivos com 'inotifywait'..."
if command -v inotifywait &> /dev/null; then
    log_action "  'inotifywait' encontrado. Iniciando monitoramento em background."
    # Monitora a criação e modificação de arquivos .py em todo o sistema
    nohup inotifywait -r -m -e create,modify --format '%w%f %e' / -o /tmp/inotify_monitor.log --exclude '/(proc|sys)' &
    log_action "  Monitoramento ativo. Logs em /tmp/inotify_monitor.log"
else
    log_action "  Comando 'inotifywait' não encontrado. Pule esta etapa."
    log_action "  Para instalar: sudo apt-get install inotify-tools (Debian/Ubuntu) ou sudo dnf install inotify-tools (Fedora/CentOS)"
fi
echo "" >> "$LOG_FILE"


# 10. Bloquear execução de novos arquivos .py
log_action "Implementando bloqueio de execução para arquivos .py..."
# Uma abordagem simples e eficaz é usar chmod para remover a permissão de execução.
# Isso não impede 'python script.py', mas impede './script.py'.
# Para um bloqueio mais forte, AppArmor ou SELinux seriam necessários.
log_action "  Removendo permissão de execução de todos os arquivos .py existentes."
find / -name "*.py" -type f -exec chmod a-x {} \; 2>/dev/null
log_action "  Permissão de execução (x) removida de arquivos .py."
# A regra do inotify acima ajudará a detectar a criação de novos arquivos.
echo "" >> "$LOG_FILE"


# --- Finalização ---
log_action "Script de Resposta a Incidentes concluído."
log_action "Relatório completo salvo em: $LOG_FILE"
if [ -d "$BACKUP_DIR" ]; then
    log_action "Backups de arquivos .txt.enc salvos em: $BACKUP_DIR"
fi
echo "==================================================" >> "$LOG_FILE"

echo ""
echo "Processo finalizado. Verifique o relatório em $LOG_FILE"
