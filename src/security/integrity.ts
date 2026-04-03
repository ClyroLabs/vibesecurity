/**
 * VibeSecurity — Anti-Tampering & Verificação de Integridade
 *
 * - Hash SHA-256 de módulos fonte na inicialização
 * - Verificação periódica contra adulteração
 * - Detecção de debugger (Node.js inspect mode)
 * - Reações defensivas: encerrar processo + alerta
 */

import { createHash } from "node:crypto";
import fs from "fs/promises";
import path from "path";
import { getAuditLogger } from "./audit-logger.js";

// ─── Tipos ────────────────────────────────────────────────────────────────────

export interface IntegritySnapshot {
    timestamp: string;
    hashes: Record<string, string>;
    totalModules: number;
}

export interface IntegrityCheckResult {
    valido: boolean;
    modulosVerificados: number;
    modulosAdulterados: string[];
    debuggerDetectado: boolean;
    timingAnomalia: boolean;
    snapshot: IntegritySnapshot;
}

// ─── Funções de Hash ──────────────────────────────────────────────────────────

async function hashArquivo(caminho: string): Promise<string> {
    const conteudo = await fs.readFile(caminho);
    return createHash("sha256").update(conteudo).digest("hex");
}

async function coletarHashes(diretorio: string): Promise<Record<string, string>> {
    const hashes: Record<string, string> = {};
    const extensoes = [".js", ".ts", ".mjs", ".cjs"];

    async function varrer(dir: string): Promise<void> {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith(".") && entry.name !== "node_modules") {
                await varrer(fullPath);
            } else if (entry.isFile() && extensoes.includes(path.extname(entry.name))) {
                const rel = path.relative(diretorio, fullPath);
                hashes[rel] = await hashArquivo(fullPath);
            }
        }
    }

    await varrer(diretorio);
    return hashes;
}

// ─── Detecção de Debugger ─────────────────────────────────────────────────────

function detectarDebugger(): boolean {
    // Verifica se node foi iniciado com --inspect ou --inspect-brk
    const nodeOptions = process.env.NODE_OPTIONS ?? "";
    const execArgv = process.execArgv.join(" ");

    const inspectPatterns = ["--inspect", "--inspect-brk", "--debug", "--debug-brk"];
    const detected = inspectPatterns.some(
        (p) => execArgv.includes(p) || nodeOptions.includes(p)
    );

    return detected;
}

// ─── Detecção de anomalia de timing ───────────────────────────────────────────

function detectarTimingAnomalia(): boolean {
    // Mede o tempo de uma operação trivial
    // Se estiver sob debugger com breakpoints, vai ser muito lento
    const start = process.hrtime.bigint();

    // Operação determinística leve
    let acc = 0;
    for (let i = 0; i < 10_000; i++) {
        acc += i * i;
    }

    const elapsed = Number(process.hrtime.bigint() - start);

    // Se levou mais de 50ms para 10k iterações, algo está errado
    // (normal: < 1ms; debugger com breakpoints: > 100ms)
    return elapsed > 50_000_000 && acc > 0;
}

// ─── Classe IntegrityChecker ──────────────────────────────────────────────────

export class IntegrityChecker {
    private baselineHashes: Record<string, string> = {};
    private diretorioProtegido: string;
    private intervalo: ReturnType<typeof setInterval> | null = null;
    private checkIntervalMs: number;

    constructor(diretorioProtegido: string, checkIntervalMs: number = 60_000) {
        this.diretorioProtegido = diretorioProtegido;
        this.checkIntervalMs = checkIntervalMs;
    }

    /**
     * Calcula hashes iniciais e inicia monitoramento periódico.
     */
    async iniciar(): Promise<IntegritySnapshot> {
        this.baselineHashes = await coletarHashes(this.diretorioProtegido);

        const snapshot: IntegritySnapshot = {
            timestamp: new Date().toISOString(),
            hashes: { ...this.baselineHashes },
            totalModules: Object.keys(this.baselineHashes).length,
        };

        // Inicia verificação periódica
        this.intervalo = setInterval(() => this.verificarIntegridade(true), this.checkIntervalMs);

        const logger = getAuditLogger();
        await logger.log("INFO", "integrity.baseline", {
            details: { totalModules: snapshot.totalModules },
        });

        return snapshot;
    }

    async parar(): Promise<void> {
        if (this.intervalo) {
            clearInterval(this.intervalo);
            this.intervalo = null;
        }
    }

    /**
     * Verifica integridade sob demanda.
     */
    async verificarIntegridade(silencioso: boolean = false): Promise<IntegrityCheckResult> {
        const hashesAtuais = await coletarHashes(this.diretorioProtegido);
        const adulterados: string[] = [];

        // Compara com baseline
        for (const [arquivo, hashOriginal] of Object.entries(this.baselineHashes)) {
            const hashAtual = hashesAtuais[arquivo];
            if (!hashAtual) {
                adulterados.push(`${arquivo} (REMOVIDO)`);
            } else if (hashAtual !== hashOriginal) {
                adulterados.push(`${arquivo} (MODIFICADO)`);
            }
        }

        // Detecta novos arquivos
        for (const arquivo of Object.keys(hashesAtuais)) {
            if (!(arquivo in this.baselineHashes)) {
                adulterados.push(`${arquivo} (NOVO — não estava no baseline)`);
            }
        }

        const debuggerDetectado = detectarDebugger();
        const timingAnomalia = detectarTimingAnomalia();

        const resultado: IntegrityCheckResult = {
            valido: adulterados.length === 0 && !debuggerDetectado,
            modulosVerificados: Object.keys(hashesAtuais).length,
            modulosAdulterados: adulterados,
            debuggerDetectado,
            timingAnomalia,
            snapshot: {
                timestamp: new Date().toISOString(),
                hashes: hashesAtuais,
                totalModules: Object.keys(hashesAtuais).length,
            },
        };

        // Log de auditoria
        const logger = getAuditLogger();
        if (adulterados.length > 0) {
            await logger.log("CRITICAL", "integrity.tampering_detectado", {
                resultado: "BLOQUEADO",
                details: { adulterados, totalVerificados: resultado.modulosVerificados },
            });
        }

        if (debuggerDetectado) {
            await logger.log("ALERT", "integrity.debugger_detectado", {
                resultado: "BLOQUEADO",
                details: { execArgv: process.execArgv, nodeOptions: process.env.NODE_OPTIONS },
            });

            // Reação defensiva: em produção, encerrar processo
            if (process.env.NODE_ENV === "production" && !silencioso) {
                console.error("🚨 CRITICAL: Debugger detectado em produção. Encerrando processo.");
                process.exit(1);
            }
        }

        if (timingAnomalia && !silencioso) {
            await logger.log("WARN", "integrity.timing_anomalia", {
                details: { mensagem: "Possível depuração ou instrumentação detectada via timing" },
            });
        }

        return resultado;
    }

    /**
     * Recalcula o baseline (após updates legítimos).
     */
    async recalcularBaseline(): Promise<IntegritySnapshot> {
        this.baselineHashes = await coletarHashes(this.diretorioProtegido);
        const snapshot: IntegritySnapshot = {
            timestamp: new Date().toISOString(),
            hashes: { ...this.baselineHashes },
            totalModules: Object.keys(this.baselineHashes).length,
        };
        const logger = getAuditLogger();
        await logger.log("INFO", "integrity.baseline_recalculado", {
            details: { totalModules: snapshot.totalModules },
        });
        return snapshot;
    }
}
