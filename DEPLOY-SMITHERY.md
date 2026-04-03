# Deploy VibeSecurity no Smithery.ai — Guia Rápido

[Smithery.ai](https://smithery.ai) é a plataforma (registry público) onde usuários podem descobrir e instalar servidores MCP facilmente em clientes como o Claude Desktop e Cursor.

Como o VibeSecurity já possui o arquivo `smithery.yaml` configurado, o processo é 100% automatizado, você só precisa registrar o link do seu GitHub.

---

## Como registrar o VibeSecurity:

### 1. Preparação
1. Certifique-se de que o projeto foi "pushado" para o seu repositório no GitHub:
   -> [https://github.com/ClyroLabs/vibesecurity](https://github.com/ClyroLabs/vibesecurity)
2. Garanta que o repositório está marcado como **Público**.

### 2. Cadastrando na Plataforma
1. Acesse: [https://smithery.ai/](https://smithery.ai/)
2. Logue-se usando sua conta do GitHub.
3. No painel, clique no botão para **Add Server** ou **Publish**.
4. Quando solicitado a fonte (source), cole a URL do seu repositório GitHub:
   ```text
   https://github.com/ClyroLabs/vibesecurity
   ```
5. O Smithery iniciará uma varredura (build) do repositório. Ele utilizará o arquivo `smithery.yaml` e o `Dockerfile` automaticamente.

### 3. Vantagens do registro no Smithery
- **Instalação em 1 Clique:** Após o registro, a página do VibeSecurity terá botões de instalação direta no Claude Desktop.
- **Distribuição Nativa:** Outros desenvolvedores podem instalar seu MCP facilmente usando a Command Line da Smithery:
  ```bash
  npx @smithery/cli install @clyrolabs/vibesecurity --client claude
  ```
- **Visibilidade:** Você aparecerá na principal vitrine pública de ferramentas MCP globais.

### Configurando credenciais durante a instalação (ConfigSchema)
Durante a instalação, The Smithery CLI perguntará automaticamente as informações definidas no `smithery.yaml`, no seu caso:
- `VIBESECURITY_DIR`: Opcional, onde a análise irá rodar.
- `VIBESECURITY_KEY`: Opcional para Stdio.

---
🚀 Pronto! Assim que concluir, seu painel do Smithery exibirá sua página pública oficial.
