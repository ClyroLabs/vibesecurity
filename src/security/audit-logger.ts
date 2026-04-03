/**
 * VibeSecurity — Sistema de Auditoria e Logging Seguro
 *
 * Logging estruturado JSON para todas as atividades do MCP.
 * - Níveis: INFO, WARN, ALERT, CRITICAL
 * - Saída: stderr + arquivo rotacional
 * - Sanitização automática de dados sensíveis
 * - Conformidade LGPD/GDPR (não logga conteúdo de arquivos)
 */

import fs from "fs/promises";
import path from "path";

// ─── Tipos ────────────────────────────────────────────────────────────────────

export type LogLevel = "INFO" | "WARN" | "ALERT" | "CRITICAL";

export interface AuditEntry {
    timestamp: string;
    level: LogLevel;
    event: string;
    toolName?: string;
    sessionId?: string;
    ip?: string;
    details?: Record<string, unknown>;
    resultado?: "SUCESSO" | "FALHA" | "BLOQUEADO";
}

// ─── Padrões sensíveis para sanitização ───────────────────────────────────────

const SENSITIVE_PATTERNS: Array<{ regex: RegExp; replacement: string }> = [
    { regex: /(?:password|senha|secret|token|api[_-]?key)\s*[:=]\s*["']?[^\s"',;]+/gi, replacement: "[REDACTED]" },
    { regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, replacement: "Bearer [REDACTED]" },
    { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: "[EMAIL_REDACTED]" },
    { regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, replacement: "[CPF_REDACTED]" },
    { regex: /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g, replacement: "[CNPJ_REDACTED]" },
];

function sanitizar(texto: string): string {
    let resultado = texto;
    for (const pattern of SENSITIVE_PATTERNS) {
        resultado = resultado.replace(pattern.regex, pattern.replacement);
    }
    return resultado;
}

// ─── Classe AuditLogger ───────────────────────────────────────────────────────

export class AuditLogger {
    private logDir: string;
    private logFile: string;
    private buffer: string[] = [];
    private flushInterval: ReturnType<typeof setInterval> | null = null;
    private maxFileSize = 5 * 1024 * 1024; // 5MB por arquivo

    constructor(baseDir: string) {
        this.logDir = path.join(baseDir, ".vibesecurity", "logs");
        this.logFile = path.join(this.logDir, "audit.jsonl");
    }

    async iniciar(): Promise<void> {
        await fs.mkdir(this.logDir, { recursive: true });
        this.flushInterval = setInterval(() => this.flush(), 5000);
        await this.log("INFO", "audit.iniciado", {
            details: { mensagem: "Sistema de auditoria iniciado" },
        });
    }

    async parar(): Promise<void> {
        if (this.flushInterval) {
            clearInterval(this.flushInterval);
            this.flushInterval = null;
        }
        await this.flush();
    }

    async log(
        level: LogLevel,
        event: string,
        opts: Partial<Omit<AuditEntry, "timestamp" | "level" | "event">> = {}
    ): Promise<void> {
        const entry: AuditEntry = {
            timestamp: new Date().toISOString(),
            level,
            event,
            ...opts,
        };

        // Sanitiza detalhes antes de loggar
        if (entry.details) {
            const sanitizedDetails: Record<string, unknown> = {};
            for (const [key, value] of Object.entries(entry.details)) {
                sanitizedDetails[key] = typeof value === "string" ? sanitizar(value) : value;
            }
            entry.details = sanitizedDetails;
        }

        const linha = JSON.stringify(entry);

        // Sempre emite em stderr (disponível imediatamente)
        if (level === "CRITICAL" || level === "ALERT") {
            console.error(`🚨 [${level}] ${event}: ${JSON.stringify(entry.details ?? {})}`);
        }

        this.buffer.push(linha);

        // Flush imediato para eventos críticos
        if (level === "CRITICAL" || level === "ALERT") {
            await this.flush();
        }
    }

    private async flush(): Promise<void> {
        if (this.buffer.length === 0) return;

        const linhas = this.buffer.splice(0);
        const conteudo = linhas.join("\n") + "\n";

        try {
            // Verifica rotação
            await this.rotacionarSeNecessario();
            await fs.appendFile(this.logFile, conteudo, "utf-8");
        } catch {
            // Em caso de erro de I/O, re-insere no buffer
            this.buffer.unshift(...linhas);
        }
    }

    private async rotacionarSeNecessario(): Promise<void> {
        try {
            const stat = await fs.stat(this.logFile);
            if (stat.size >= this.maxFileSize) {
                const rotatedName = `audit-${Date.now()}.jsonl`;
                await fs.rename(this.logFile, path.join(this.logDir, rotatedName));
            }
        } catch {
            // arquivo ainda não existe — ok
        }
    }

    /**
     * Retorna as últimas N entradas do log de auditoria.
     */
    async obterUltimasEntradas(n: number = 50): Promise<AuditEntry[]> {
        try {
            const conteudo = await fs.readFile(this.logFile, "utf-8");
            const linhas = conteudo.trim().split("\n").filter(Boolean);
            return linhas.slice(-n).map((l) => JSON.parse(l) as AuditEntry);
        } catch {
            return [];
        }
    }
}

// ─── Singleton global ─────────────────────────────────────────────────────────

let _instance: AuditLogger | null = null;

export function getAuditLogger(baseDir?: string): AuditLogger {
    if (!_instance) {
        if (!baseDir) throw new Error("AuditLogger precisa de baseDir na primeira inicialização");
        _instance = new AuditLogger(baseDir);
    }
    return _instance;
}
