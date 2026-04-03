#!/usr/bin/env node
/**
 * VibeSecurity MCP Server v2.0.0 — Transporte Stdio
 *
 * Compatível com VS Code, Antigravity, Claude Desktop.
 * Registra todas as tools (base + segurança) e inicializa infraestrutura.
 *
 * Uso: node dist/index.js <caminho_do_projeto>
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "fs/promises";
import path from "path";
import { getAuditLogger } from "./security/audit-logger.js";
import { IntegrityChecker } from "./security/integrity.js";
import { registerBaseTools } from "./tools/base-tools.js";
import { registerSecurityTools } from "./tools/security-module.js";

// ─── Configuração ─────────────────────────────────────────────────────────────

const argDiretorio = process.argv[2];
const DIRETORIO_PERMITIDO = path.normalize(
    argDiretorio ? path.resolve(argDiretorio) : process.cwd()
);

// ─── Inicialização ────────────────────────────────────────────────────────────

async function iniciar() {
    // Valida se o diretório existe
    try {
        const stat = await fs.stat(DIRETORIO_PERMITIDO);
        if (!stat.isDirectory()) {
            console.error(`❌ ERRO: "${DIRETORIO_PERMITIDO}" não é um diretório válido.`);
            process.exit(1);
        }
    } catch {
        console.error(`❌ ERRO: Diretório "${DIRETORIO_PERMITIDO}" não encontrado.`);
        console.error(`   Uso: node dist/index.js <caminho_do_projeto>`);
        process.exit(1);
    }

    // Inicializa infraestrutura de segurança
    const logger = getAuditLogger(DIRETORIO_PERMITIDO);
    await logger.iniciar();

    // Inicializa verificação de integridade (silenciosa)
    const integrity = new IntegrityChecker(DIRETORIO_PERMITIDO);
    await integrity.iniciar();

    // Cria MCP Server e registra todas as tools
    const server = new McpServer({
        name: "VibeSecurity",
        version: "2.0.0",
    });

    registerBaseTools(server, DIRETORIO_PERMITIDO);
    registerSecurityTools(server, DIRETORIO_PERMITIDO);

    console.error(`🔒 VibeSecurity MCP Server v2.0.0`);
    console.error(`📁 Diretório protegido: ${DIRETORIO_PERMITIDO}`);
    console.error(`🛡️  Módulo de segurança: 11 tools ativas`);

    const transport = new StdioServerTransport();
    await server.connect(transport);

    // Cleanup on exit
    process.on("SIGINT", async () => {
        await integrity.parar();
        await logger.parar();
        process.exit(0);
    });
}

iniciar().catch(console.error);
