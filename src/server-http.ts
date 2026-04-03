#!/usr/bin/env node
/**
 * VibeSecurity MCP v2.0.0 — HTTP Wrapper (Streamable HTTP Transport)
 *
 * Compatível com Lovable, Cursor e qualquer cliente MCP remoto.
 * Inclui: auth por Bearer token, rate limiting, audit logging, CORS.
 *
 * Variáveis de ambiente:
 *   VIBESECURITY_DIR  — Diretório raiz protegido (default: process.cwd())
 *   VIBESECURITY_KEY  — API Key secreta (obrigatória em produção)
 *   PORT              — Porta HTTP (default: 3333)
 */

import express, { Request, Response, NextFunction } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import fs from "fs/promises";
import path from "path";
import { randomUUID } from "node:crypto";
import { getAuditLogger } from "./security/audit-logger.js";
import { IntegrityChecker } from "./security/integrity.js";
import { RateLimiter } from "./security/rate-limiter.js";
import { registerBaseTools } from "./tools/base-tools.js";
import { registerSecurityTools } from "./tools/security-module.js";

// ─── Configuração ─────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? "3333", 10);
const API_KEY = process.env.VIBESECURITY_KEY ?? "";
const DIRETORIO_PERMITIDO = path.normalize(
    process.env.VIBESECURITY_DIR
        ? path.resolve(process.env.VIBESECURITY_DIR)
        : process.cwd()
);

// ─── MCP Server Factory ──────────────────────────────────────────────────────

function criarMcpServer(): McpServer {
    const server = new McpServer({
        name: "VibeSecurity",
        version: "2.0.0",
    });

    registerBaseTools(server, DIRETORIO_PERMITIDO);
    registerSecurityTools(server, DIRETORIO_PERMITIDO);

    return server;
}

// ─── Express App ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// CORS — permite Lovable e outros clientes browser
app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
    // Security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    if (req.method === "OPTIONS") {
        res.sendStatus(204);
        return;
    }
    next();
});

// Middleware de autenticação por API Key
function autenticar(req: Request, res: Response, next: NextFunction): void {
    if (!API_KEY) {
        console.warn("⚠️  VIBESECURITY_KEY não configurada — servidor em modo INSEGURO!");
        next();
        return;
    }

    const authHeader = req.headers["authorization"] ?? "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

    if (token !== API_KEY) {
        const logger = getAuditLogger();
        logger.log("ALERT", "http.auth.falha", {
            resultado: "BLOQUEADO",
            ip: req.ip ?? req.socket.remoteAddress,
            details: { method: req.method, path: req.path },
        });
        res.status(401).json({ error: "Unauthorized: API Key inválida ou ausente." });
        return;
    }
    next();
}

// ─── Rate Limiting Middleware ──────────────────────────────────────────────────

const rateLimiter = new RateLimiter();

async function limitarRequisicoes(req: Request, res: Response, next: NextFunction): Promise<void> {
    const sessionId = (req.headers["mcp-session-id"] as string) ?? req.ip ?? "unknown";
    const resultado = await rateLimiter.consumir(sessionId);

    if (!resultado.permitido) {
        res.setHeader("Retry-After", Math.ceil((resultado.retryAfterMs ?? 2000) / 1000).toString());
        res.status(429).json({
            error: resultado.motivo,
            retryAfterMs: resultado.retryAfterMs,
        });
        return;
    }

    res.setHeader("X-RateLimit-Remaining", resultado.tokensRestantes.toString());
    next();
}

// ─── Gerenciamento de sessões ─────────────────────────────────────────────────

const sessoes = new Map<string, StreamableHTTPServerTransport>();

// ─── Endpoints MCP ────────────────────────────────────────────────────────────

app.post("/mcp", autenticar, limitarRequisicoes, async (req: Request, res: Response) => {
    const sessionId = (req.headers["mcp-session-id"] as string | undefined) ?? randomUUID();
    let transport = sessoes.get(sessionId);

    if (!transport) {
        transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => sessionId,
            onsessioninitialized: (id) => {
                sessoes.set(id, transport!);
                const logger = getAuditLogger();
                logger.log("INFO", "http.sessao.nova", {
                    sessionId: id,
                    ip: req.ip ?? req.socket.remoteAddress,
                });
            },
        });

        transport.onclose = () => {
            sessoes.delete(sessionId);
            const logger = getAuditLogger();
            logger.log("INFO", "http.sessao.encerrada", { sessionId });
        };

        const server = criarMcpServer();
        await server.connect(transport);
    }

    await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", autenticar, async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    const transport = sessionId ? sessoes.get(sessionId) : undefined;

    if (!transport) {
        res.status(404).json({ error: "Sessão MCP não encontrada. Faça um POST /mcp primeiro." });
        return;
    }

    await transport.handleRequest(req, res);
});

app.delete("/mcp", autenticar, async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    const transport = sessionId ? sessoes.get(sessionId) : undefined;

    if (transport) {
        await transport.handleRequest(req, res);
    } else {
        res.status(404).json({ error: "Sessão não encontrada." });
    }
});

// Health check (sem auth — para uptime monitors)
app.get("/health", (_req: Request, res: Response) => {
    const rlStats = rateLimiter.getStats();
    res.json({
        status: "ok",
        server: "VibeSecurity MCP",
        version: "2.0.0",
        dirProtegido: DIRETORIO_PERMITIDO,
        autenticacao: API_KEY ? "API Key ativa" : "⚠️ Desativada (modo dev)",
        sessoesAtivas: sessoes.size,
        rateLimiter: { sessoesMonitoradas: rlStats.totalSessions },
        modulos: {
            baseTools: 3,
            securityTools: 8,
            totalTools: 11,
        },
    });
});

// ─── Startup ──────────────────────────────────────────────────────────────────

async function iniciar() {
    // Valida diretório
    try {
        const stat = await fs.stat(DIRETORIO_PERMITIDO);
        if (!stat.isDirectory()) {
            console.error(`❌ ERRO: "${DIRETORIO_PERMITIDO}" não é um diretório válido.`);
            process.exit(1);
        }
    } catch {
        console.error(`❌ ERRO: Diretório "${DIRETORIO_PERMITIDO}" não encontrado.`);
        process.exit(1);
    }

    // Inicializa infraestrutura de segurança
    const logger = getAuditLogger(DIRETORIO_PERMITIDO);
    await logger.iniciar();

    const integrity = new IntegrityChecker(DIRETORIO_PERMITIDO);
    await integrity.iniciar();

    rateLimiter.iniciar();

    app.listen(PORT, () => {
        console.error(`🔒 VibeSecurity MCP HTTP Server v2.0.0`);
        console.error(`📁 Diretório protegido : ${DIRETORIO_PERMITIDO}`);
        console.error(`🌐 Endpoint MCP        : http://localhost:${PORT}/mcp`);
        console.error(`❤️  Health check        : http://localhost:${PORT}/health`);
        console.error(`🔑 Autenticação        : ${API_KEY ? "API Key ativa" : "⚠️  DESATIVADA (defina VIBESECURITY_KEY)"}`);
        console.error(`🛡️  Módulo segurança    : 11 tools ativas (3 base + 8 security)`);
        console.error(`⚡ Rate limiting       : 30 req/min, 5 req/s burst`);
    });

    // Cleanup on exit
    process.on("SIGINT", async () => {
        await integrity.parar();
        await logger.parar();
        rateLimiter.parar();
        process.exit(0);
    });
}

iniciar().catch(console.error);
