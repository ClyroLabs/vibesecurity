# Use Node 20 Alpine para imagem leve
FROM node:20-alpine AS builder

WORKDIR /app

# Instala dependências
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# Copia código e compila
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ─── Imagem de produção ───────────────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Instala Trivy para scans de vulnerabilidade
RUN apk add --no-cache curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Copia apenas o necessário
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=builder /app/dist/ ./dist/

# Cria diretório para projetos analisados
RUN mkdir -p /workspace

# Variáveis de ambiente
ENV NODE_ENV=production
ENV PORT=3333
ENV VIBESECURITY_DIR=/workspace

# Expõe porta
EXPOSE 3333

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:3333/health || exit 1

# Inicia o servidor HTTP
CMD ["node", "dist/server-http.js"]
