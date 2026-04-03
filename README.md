# clyrolabs-vibesecurity

🔒 **Servidor MCP de Segurança por Design** — Análise estática, auditoria, anti-tampering e conformidade OWASP/LGPD.

11 tools MCP disponíveis via **Stdio** (VS Code, Antigravity, Claude Desktop) e **HTTP** (Lovable, Cursor, qualquer cliente MCP remoto).

---

## 🚀 Instalação Rápida

### NPM (global)
```bash
npm install -g clyrolabs-vibesecurity
```

### NPX (sem instalar)
```bash
npx clyrolabs-vibesecurity /caminho/do/projeto
```

### Docker
```bash
docker build -t vibesecurity .
docker run -p 3333:3333 \
  -e VIBESECURITY_KEY=sua-chave-secreta \
  -v /seu/projeto:/workspace \
  vibesecurity
```

---

## 🛠️ Modos de Uso

### Modo Stdio (VS Code / Antigravity / Claude Desktop)
```bash
vibesecurity /caminho/do/projeto
```

**Configuração no VS Code (`.vscode/mcp.json`):**
```json
{
  "servers": {
    "vibesecurity": {
      "command": "npx",
      "args": ["-y", "clyrolabs-vibesecurity", "${workspaceFolder}"]
    }
  }
}
```

**Configuração no Claude Desktop:**
```json
{
  "mcpServers": {
    "vibesecurity": {
      "command": "npx",
      "args": ["-y", "clyrolabs-vibesecurity", "/caminho/do/projeto"]
    }
  }
}
```

### Modo HTTP (Lovable / Cursor / Remoto)
```bash
# Variáveis de ambiente
export VIBESECURITY_DIR=/caminho/do/projeto
export VIBESECURITY_KEY=sua-chave-secreta
export PORT=3333

# Iniciar servidor
vibesecurity-http
# ou: node dist/server-http.js
```

**Configuração no Lovable:**
1. Settings → Connections → MCP Access → Add Server
2. URL: `https://seu-dominio.railway.app/mcp`
3. Header: `Authorization: Bearer sua-chave-secreta`

---

## ☁️ Deploy no Railway

Veja o [Guia completo de deploy](./DEPLOY-RAILWAY.md).

**Resumo rápido:**
```bash
# 1. Push para GitHub
git push origin main

# 2. No Railway Dashboard: New Project → Deploy from GitHub
# 3. Adicionar variáveis de ambiente:
#    VIBESECURITY_KEY = sua-chave-secreta
#    VIBESECURITY_DIR = /workspace

# 4. URL gerada: https://vibesecurity-xxx.up.railway.app
# 5. Conectar no Lovable: URL + /mcp
```

---

## 🛡️ Tools Disponíveis (11)

### Base (3)
| Tool | Descrição |
|---|---|
| `ler_arquivo_seguro` | Lê arquivo com proteção contra Path Traversal |
| `rodar_scan_trivy` | Scan de vulnerabilidades com Trivy |
| `propor_correcao_patch` | Gera patches Unified Diff |

### Segurança Avançada (8)
| Tool | Descrição |
|---|---|
| **`blindar_projeto`** | 🛡️ **Wizard visual** — executa todas as análises com relatório ✅/⚠️/❌ |
| `auditar_seguranca_api` | Analisa auth, inputs, CORS, rate limiting |
| `detectar_vulnerabilidades` | SQLi, XSS, eval, secrets (SAST leve) |
| `verificar_integridade` | SHA-256 anti-tampering + debugger detection |
| `gerar_relatorio_conformidade` | OWASP Top 10 + LGPD/GDPR score |
| `configurar_protecao` | Gera `.vibesecurity/config.json` |
| `analisar_dependencias` | CVEs em dependências via Trivy |
| `gerar_politica_seguranca` | Gera SECURITY.md modelo |

---

## 🔑 Variáveis de Ambiente

| Variável | Obrigatória | Padrão | Descrição |
|---|---|---|---|
| `VIBESECURITY_KEY` | Sim (produção) | `""` | API Key para Bearer auth |
| `VIBESECURITY_DIR` | Não | `process.cwd()` | Diretório raiz protegido |
| `PORT` | Não | `3333` | Porta HTTP |

---

## 📦 Distribuição

### NPM Registry
```bash
npm publish --access public
```

### GitHub Releases
Faça upload do `.tgz` como asset de release no GitHub.

### Instalação via URL direta
```bash
npm install https://github.com/clyrolabs/vibesecurity/releases/download/v2.0.0/clyrolabs-vibesecurity-2.0.0.tgz
```

---

## 📄 Licença

MIT — Clyro Labs AI
