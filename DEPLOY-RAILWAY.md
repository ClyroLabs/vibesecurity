# Deploy VibeSecurity no Railway — Guia Completo

## Pré-requisitos

- Conta no [Railway](https://railway.app) (plano Starter grátis ou superior)
- Repositório GitHub com o código do VibeSecurity
- (Opcional) Conta no Lovable para conectar o MCP

---

## Passo 1: Preparar o Repositório

O projeto já contém os arquivos necessários:
- `Dockerfile` — build multi-stage com Node 20 Alpine + Trivy
- `railway.json` — configuração de deploy
- `.dockerignore` — exclui arquivos desnecessários

Certifique-se de que tudo está commitado:
```bash
git add -A
git commit -m "feat: VibeSecurity v2.0.0 - security module + HTTP wrapper"
git push origin main
```

---

## Passo 2: Criar Projeto no Railway

1. Acesse [railway.app/dashboard](https://railway.app/dashboard)
2. Clique em **"New Project"**
3. Selecione **"Deploy from GitHub repo"**
4. Autorize o acesso ao GitHub e selecione o repositório `vibesecurity`
5. Railway detectará o `Dockerfile` automaticamente

---

## Passo 3: Configurar Variáveis de Ambiente

No painel do projeto Railway, vá em **Variables** e adicione:

| Variável | Valor | Obrigatória |
|---|---|---|
| `VIBESECURITY_KEY` | `gere-uma-chave-forte-aqui` | ✅ Sim |
| `VIBESECURITY_DIR` | `/workspace` | ✅ Sim |
| `PORT` | `3333` | Não (Railway define via `$PORT`) |
| `NODE_ENV` | `production` | Não (já definido no Dockerfile) |

> **💡 Dica:** Para gerar uma chave forte, use:
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```

---

## Passo 4: Configurar Networking

1. No painel Railway, vá na aba **Settings → Networking**
2. Clique em **"Generate Domain"** para criar uma URL pública
3. Você receberá algo como: `vibesecurity-production-xxxx.up.railway.app`
4. (Opcional) Configure um domínio customizado: `mcp.seudominio.com`

---

## Passo 5: Verificar Deploy

Após o deploy (2-3 minutos), teste:

```bash
# Health check
curl https://vibesecurity-production-xxxx.up.railway.app/health

# Resposta esperada:
# {"status":"ok","server":"VibeSecurity MCP","version":"2.0.0","modulos":{"totalTools":11}}

# Teste de autenticação (deve retornar 401)
curl -X POST https://vibesecurity-production-xxxx.up.railway.app/mcp \
  -H "Content-Type: application/json" \
  -d '{}'

# Teste com auth correta
curl -X POST https://vibesecurity-production-xxxx.up.railway.app/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer SUA_CHAVE_AQUI" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

---

## Passo 6: Conectar no Lovable

1. Acesse seu projeto no [Lovable](https://lovable.dev)
2. Vá em **Settings → Connections → MCP Access**
3. Clique em **"Add Server"**
4. Configure:
   - **Name:** VibeSecurity
   - **URL:** `https://vibesecurity-production-xxxx.up.railway.app/mcp`
   - **Headers:**
     ```
     Authorization: Bearer SUA_CHAVE_AQUI
     ```
5. Clique em **Save**

Agora as 11 tools estarão disponíveis no chat do Lovable! Use `blindar_projeto` para ver o wizard visual completo.

---

## Passo 7: Monitoramento

### Logs no Railway
- No painel do projeto, clique em **"Deployments"** → **"View Logs"**
- Todos os eventos de segurança são logados no audit trail

### Health Check
- Railway faz ping automático em `GET /health` a cada 30s
- Se o servidor ficar fora, Railway reinicia automaticamente (até 5 tentativas)

### Métricas
- `GET /health` retorna:
  - Sessões ativas
  - Sessões monitoradas pelo rate limiter
  - Contagem de tools

---

## Troubleshooting

| Problema | Solução |
|---|---|
| Deploy falha no Dockerfile | Verifique se `npm run build` roda localmente sem erros |
| 401 no Lovable | Confirme que o header `Authorization: Bearer ...` está correto |
| Trivy não funciona | Normal se Railway não tem acesso ao filesystem do seu projeto. Para scan remoto, use a tool `detectar_vulnerabilidades` (análise estática, sem Trivy) |
| 429 Too Many Requests | Rate limiting ativo (30 req/min). Aguarde ou aumente em `.vibesecurity/config.json` |
| Health check falha | Verifique se a porta está correta (Railway define via env `PORT`) |

### Nota sobre `VIBESECURITY_DIR` no Railway

No Railway, o container não tem acesso ao seu filesystem local. O diretório `/workspace` é um diretório vazio no container. Para analisar projetos remotamente:

1. **Suba os arquivos do projeto via volume** (Railway Private Networking)
2. **Ou use as tools de análise estática** (`detectar_vulnerabilidades`, `auditar_seguranca_api`) que funcionam com código injetado via MCP
3. **Para uso completo**, hospede um volume persistente com o código a ser analisado

---

## Custo Estimado (Railway)

| Plano | Custo | Inclui |
|---|---|---|
| Trial | $0 (500h) | Suficiente para testes |
| Hobby | $5/mês | 512MB RAM, custom domains |
| Pro | $20/mês | Auto-scaling, mais recursos |

O VibeSecurity consome ~50MB de RAM em idle. O plano Hobby é suficiente para uso pessoal.
