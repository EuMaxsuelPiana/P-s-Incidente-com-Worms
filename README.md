# 🐺 VoidHound Incident Response

Ferramenta de resposta rápida a incidentes causada por worms com capacidade de metamorfismo.

> Desenvolvido por [VoidCybersecurity](https://github.com/EuMaxsuelPiana) como parte do projeto educacional **VoidHound Hunter** 🐺.

---

## ⚠️ O que este script faz

Este script automatiza as principais ações defensivas após detectar um **worm mutante** em sistemas Linux. Ideal para uso em **laboratórios de cibersegurança**, **cenários de estudo forense**, ou testes com worms educacionais.

---

## 📌 Funcionalidades

- 🔐 Verifica se está rodando como root
- 🌐 Desconecta a máquina da rede (usando `nmcli` ou `ip link`)
- 🔍 Busca arquivos com padrões:
  - `worm_*.py`
  - `*.py.enc`, `*.txt.enc`
- 🔬 Coleta:
  - Hash SHA256
  - Timestamps
  - Proprietário do arquivo
  - Padrões de código malicioso (`grep`)
- 💾 Faz backup automático de arquivos `.txt.enc`
- 🗑️ Deleta arquivos infectados (com aviso e log)
- 📖 Gera relatório detalhado em `/tmp/incident_report.txt`
- 🕵️ Verifica:
  - `~/.bash_history`
  - `/var/log/syslog`, `/var/log/auth.log`
  - `auditd` (se ativo)
- 👀 Monitora criação/modificação de arquivos com `inotifywait`
- 🚫 Remove permissão de execução de todos os arquivos `.py`

---

## 🧪 Exemplo de uso

```bash
chmod +x vh-incident-response.sh
sudo ./vh-incident-response.sh


    ⚠️ AVISO: Este script executa ações destrutivas (como exclusão de arquivos e desativação da rede).
    Use apenas em ambientes de teste ou se souber o que está fazendo.
