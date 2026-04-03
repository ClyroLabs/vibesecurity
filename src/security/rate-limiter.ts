/**
 * VibeSecurity — Rate Limiter (Token Bucket in-memory)
 *
 * Proteção contra força bruta e DDoS:
 * - 30 requisições/minuto por sessionId
 * - 5 req/s burst máximo
 * - Cleanup automático de buckets expirados
 * - Header Retry-After no 429
 */

import { getAuditLogger } from "./audit-logger.js";

// ─── Tipos ────────────────────────────────────────────────────────────────────

export interface RateLimitConfig {
    maxTokens: number;       // Capacidade máxima do bucket
    refillRate: number;      // Tokens restaurados por segundo
    burstLimit: number;      // Máx requisições por segundo (burst)
    cleanupIntervalMs: number;
    bucketTtlMs: number;     // Tempo de vida de um bucket inativo
}

interface Bucket {
    tokens: number;
    lastRefill: number;
    lastRequest: number;
    requestsThisSecond: number;
    secondStart: number;
    blocked: boolean;
}

export interface RateLimitResult {
    permitido: boolean;
    tokensRestantes: number;
    retryAfterMs?: number;
    motivo?: string;
}

// ─── Configuração padrão ──────────────────────────────────────────────────────

const DEFAULT_CONFIG: RateLimitConfig = {
    maxTokens: 30,             // 30 tokens = 30 req/min
    refillRate: 0.5,           // 0.5 tokens/s = 30 tokens/min
    burstLimit: 5,             // 5 req/s máximo
    cleanupIntervalMs: 60_000, // cleanup a cada 60s
    bucketTtlMs: 300_000,      // buckets expiram após 5min sem uso
};

// ─── Classe RateLimiter ───────────────────────────────────────────────────────

export class RateLimiter {
    private buckets = new Map<string, Bucket>();
    private config: RateLimitConfig;
    private cleanupTimer: ReturnType<typeof setInterval> | null = null;

    constructor(config: Partial<RateLimitConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    iniciar(): void {
        this.cleanupTimer = setInterval(
            () => this.cleanup(),
            this.config.cleanupIntervalMs
        );
    }

    parar(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
        }
        this.buckets.clear();
    }

    /**
     * Verifica se a requisição é permitida.
     * Consome 1 token se permitido.
     */
    async consumir(sessionId: string): Promise<RateLimitResult> {
        const agora = Date.now();
        let bucket = this.buckets.get(sessionId);

        if (!bucket) {
            bucket = {
                tokens: this.config.maxTokens,
                lastRefill: agora,
                lastRequest: agora,
                requestsThisSecond: 0,
                secondStart: agora,
                blocked: false,
            };
            this.buckets.set(sessionId, bucket);
        }

        // Recarrega tokens baseado no tempo passado
        const deltaMs = agora - bucket.lastRefill;
        const tokensToAdd = (deltaMs / 1000) * this.config.refillRate;
        bucket.tokens = Math.min(this.config.maxTokens, bucket.tokens + tokensToAdd);
        bucket.lastRefill = agora;

        // Verifica burst (req/s)
        if (agora - bucket.secondStart >= 1000) {
            bucket.requestsThisSecond = 0;
            bucket.secondStart = agora;
        }

        if (bucket.requestsThisSecond >= this.config.burstLimit) {
            const retryAfterMs = 1000 - (agora - bucket.secondStart);
            const logger = getAuditLogger();
            await logger.log("WARN", "ratelimit.burst_excedido", {
                sessionId,
                resultado: "BLOQUEADO",
                details: { burstLimit: this.config.burstLimit, retryAfterMs },
            });
            return {
                permitido: false,
                tokensRestantes: Math.floor(bucket.tokens),
                retryAfterMs,
                motivo: `Burst limit excedido (${this.config.burstLimit} req/s)`,
            };
        }

        // Verifica tokens disponíveis
        if (bucket.tokens < 1) {
            const retryAfterMs = Math.ceil((1 / this.config.refillRate) * 1000);
            const logger = getAuditLogger();
            await logger.log("ALERT", "ratelimit.tokens_esgotados", {
                sessionId,
                resultado: "BLOQUEADO",
                details: { maxTokens: this.config.maxTokens, retryAfterMs },
            });
            return {
                permitido: false,
                tokensRestantes: 0,
                retryAfterMs,
                motivo: `Rate limit excedido (${this.config.maxTokens} req/min)`,
            };
        }

        // Consome 1 token
        bucket.tokens -= 1;
        bucket.requestsThisSecond += 1;
        bucket.lastRequest = agora;

        return {
            permitido: true,
            tokensRestantes: Math.floor(bucket.tokens),
        };
    }

    /**
     * Remove buckets expirados para liberar memória.
     */
    private cleanup(): void {
        const agora = Date.now();
        for (const [id, bucket] of this.buckets) {
            if (agora - bucket.lastRequest > this.config.bucketTtlMs) {
                this.buckets.delete(id);
            }
        }
    }

    /**
     * Retorna estatísticas do rate limiter.
     */
    getStats(): { totalSessions: number; config: RateLimitConfig } {
        return {
            totalSessions: this.buckets.size,
            config: this.config,
        };
    }
}
