/**
 * VibeSecurity — Motor de Análise Estática Leve
 *
 * Detecta vulnerabilidades comuns via regex patterns:
 * - SQL Injection (queries não parametrizadas)
 * - XSS (innerHTML, eval, document.write, dangerouslySetInnerHTML)
 * - Secrets hardcoded (API keys, tokens, passwords)
 * - OWASP Top 10 coverage check
 * - Segurança de API (auth, rate limiting, validação)
 *
 * Cada finding inclui: severidade, localização, recomendação.
 */

import fs from "fs/promises";
import path from "path";

// ─── Tipos ────────────────────────────────────────────────────────────────────

export type Severidade = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Finding {
    id: string;
    categoria: string;
    severidade: Severidade;
    arquivo: string;
    linha: number;
    codigo: string;
    descricao: string;
    recomendacao: string;
    owaspRef?: string;
}

export interface AnalysisResult {
    totalArquivos: number;
    totalFindings: number;
    findings: Finding[];
    porSeveridade: Record<Severidade, number>;
    porCategoria: Record<string, number>;
    score: number; // 0-100
}

// ─── Patterns de detecção ─────────────────────────────────────────────────────

interface DetectionPattern {
    id: string;
    categoria: string;
    severidade: Severidade;
    regex: RegExp;
    descricao: string;
    recomendacao: string;
    owaspRef?: string;
    extensoes?: string[];
}

const PATTERNS: DetectionPattern[] = [
    // ─── SQL Injection ────────────────────────────────────────────────
    {
        id: "SQLI-001",
        categoria: "SQL Injection",
        severidade: "CRITICAL",
        regex: /(?:query|execute|exec|raw)\s*\(\s*[`"'].*?\$\{/gi,
        descricao: "Query SQL com interpolação de string (template literal). Vulnerável a SQL Injection.",
        recomendacao: "Use queries parametrizadas: query('SELECT * FROM t WHERE id = $1', [id])",
        owaspRef: "A03:2021 - Injection",
    },
    {
        id: "SQLI-002",
        categoria: "SQL Injection",
        severidade: "CRITICAL",
        regex: /(?:query|execute|exec)\s*\(\s*["'].*?\+\s*\w/gi,
        descricao: "Query SQL com concatenação de string. Vulnerável a SQL Injection.",
        recomendacao: "Use queries parametrizadas ao invés de concatenação.",
        owaspRef: "A03:2021 - Injection",
    },
    {
        id: "SQLI-003",
        categoria: "SQL Injection",
        severidade: "HIGH",
        regex: /\.raw\s*\(\s*[`"'].*?\$\{/gi,
        descricao: "Uso de .raw() com interpolação — risco de SQL injection.",
        recomendacao: "Substitua por métodos parametrizados do ORM.",
        owaspRef: "A03:2021 - Injection",
    },

    // ─── XSS ──────────────────────────────────────────────────────────
    {
        id: "XSS-001",
        categoria: "XSS",
        severidade: "HIGH",
        regex: /\.innerHTML\s*=/gi,
        descricao: "Atribuição direta a innerHTML — risco de XSS.",
        recomendacao: "Use textContent ou sanitize com DOMPurify.",
        owaspRef: "A03:2021 - Injection",
        extensoes: [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        id: "XSS-002",
        categoria: "XSS",
        severidade: "CRITICAL",
        regex: /\beval\s*\(/gi,
        descricao: "Uso de eval() — permite execução de código arbitrário.",
        recomendacao: "Remova eval(). Use JSON.parse() para dados ou Function() controlada.",
        owaspRef: "A03:2021 - Injection",
    },
    {
        id: "XSS-003",
        categoria: "XSS",
        severidade: "HIGH",
        regex: /document\.write\s*\(/gi,
        descricao: "Uso de document.write() — risco de XSS e performance.",
        recomendacao: "Use manipulação segura do DOM (createElement, appendChild).",
        owaspRef: "A03:2021 - Injection",
        extensoes: [".js", ".ts", ".jsx", ".tsx", ".html"],
    },
    {
        id: "XSS-004",
        categoria: "XSS",
        severidade: "HIGH",
        regex: /dangerouslySetInnerHTML/gi,
        descricao: "Uso de dangerouslySetInnerHTML em React — XSS se input não sanitizado.",
        recomendacao: "Sanitize o conteúdo com DOMPurify antes de passar para dangerouslySetInnerHTML.",
        owaspRef: "A03:2021 - Injection",
        extensoes: [".jsx", ".tsx"],
    },

    // ─── Secrets Hardcoded ────────────────────────────────────────────
    {
        id: "SEC-001",
        categoria: "Secrets",
        severidade: "CRITICAL",
        regex: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*["'][A-Za-z0-9\-._~+/]{8,}/gi,
        descricao: "Possível secret/API key hardcoded no código-fonte.",
        recomendacao: "Mova para variável de ambiente (.env) e use process.env.VARIABLE.",
        owaspRef: "A02:2021 - Cryptographic Failures",
    },
    {
        id: "SEC-002",
        categoria: "Secrets",
        severidade: "HIGH",
        regex: /(?:password|senha|passwd)\s*[:=]\s*["'][^"']{4,}/gi,
        descricao: "Password/senha hardcoded no código.",
        recomendacao: "Use variáveis de ambiente ou gerenciador de segredos (Vault, AWS Secrets).",
        owaspRef: "A02:2021 - Cryptographic Failures",
    },
    {
        id: "SEC-003",
        categoria: "Secrets",
        severidade: "CRITICAL",
        regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
        descricao: "Chave privada RSA/SSH embutida no código-fonte.",
        recomendacao: "Remova imediatamente. Use key vault ou variável de ambiente.",
        owaspRef: "A02:2021 - Cryptographic Failures",
    },

    // ─── Auth/Segurança de API ────────────────────────────────────────
    {
        id: "AUTH-001",
        categoria: "API Security",
        severidade: "MEDIUM",
        regex: /app\.(get|post|put|delete|patch)\s*\(\s*["'][^"']+["']\s*,\s*(?:async\s+)?\(/gi,
        descricao: "Endpoint de API sem middleware de autenticação visível.",
        recomendacao: "Adicione middleware de autenticação antes do handler: app.post('/api', auth, handler).",
        owaspRef: "A01:2021 - Broken Access Control",
    },
    {
        id: "AUTH-002",
        categoria: "API Security",
        severidade: "MEDIUM",
        regex: /cors\(\s*\{\s*origin:\s*["']\*["']/gi,
        descricao: "CORS com origin '*' — permite requisições de qualquer domínio.",
        recomendacao: "Restrinja para domínios específicos em produção.",
        owaspRef: "A05:2021 - Security Misconfiguration",
    },

    // ─── Misc vulnerabilidades ────────────────────────────────────────
    {
        id: "MISC-001",
        categoria: "Insecure Deserialization",
        severidade: "HIGH",
        regex: /JSON\.parse\s*\(\s*(?:req\.body|request\.body|input|data|payload)/gi,
        descricao: "Parsing de JSON sem validação de schema — risco de object injection.",
        recomendacao: "Valide com Zod/Joi antes de processar: schema.parse(JSON.parse(data)).",
        owaspRef: "A08:2021 - Software and Data Integrity Failures",
    },
    {
        id: "MISC-002",
        categoria: "Error Handling",
        severidade: "MEDIUM",
        regex: /res\.(?:json|send)\s*\(\s*(?:err|error|e)(?:\.|\.message|\s*\))/gi,
        descricao: "Stack trace ou detalhes de erro expostos ao cliente.",
        recomendacao: "Retorne mensagem genérica ao cliente. Logge detalhes apenas internamente.",
        owaspRef: "A04:2021 - Insecure Design",
    },
    {
        id: "MISC-003",
        categoria: "Security Headers",
        severidade: "LOW",
        regex: /app\.disable\s*\(\s*["']x-powered-by["']\s*\)/gi,
        descricao: "Boa prática: x-powered-by desabilitado.",
        recomendacao: "Use helmet() para configurar todos os headers de segurança de uma vez.",
        owaspRef: "A05:2021 - Security Misconfiguration",
    },
];

// ─── Funções de análise ───────────────────────────────────────────────────────

const EXTENSOES_ANALISAVEIS = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".php", ".java"];

async function coletarArquivos(diretorio: string): Promise<string[]> {
    const arquivos: string[] = [];
    const ignorar = ["node_modules", ".git", "dist", "build", ".next", "__pycache__", ".vibesecurity"];

    async function varrer(dir: string): Promise<void> {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
            if (ignorar.includes(entry.name) || entry.name.startsWith(".")) continue;
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                await varrer(fullPath);
            } else if (EXTENSOES_ANALISAVEIS.includes(path.extname(entry.name))) {
                arquivos.push(fullPath);
            }
        }
    }

    await varrer(diretorio);
    return arquivos;
}

/**
 * Analisa um único arquivo contra todos os patterns.
 */
async function analisarArquivo(
    caminhoAbsoluto: string,
    diretorioBase: string,
    patterns: DetectionPattern[]
): Promise<Finding[]> {
    const conteudo = await fs.readFile(caminhoAbsoluto, "utf-8");
    const linhas = conteudo.split("\n");
    const ext = path.extname(caminhoAbsoluto);
    const relativo = path.relative(diretorioBase, caminhoAbsoluto);
    const findings: Finding[] = [];

    for (const pattern of patterns) {
        // Filtro por extensão se definido
        if (pattern.extensoes && !pattern.extensoes.includes(ext)) continue;

        for (let i = 0; i < linhas.length; i++) {
            const linha = linhas[i];
            // Reset regex para cada linha
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(linha)) {
                findings.push({
                    id: pattern.id,
                    categoria: pattern.categoria,
                    severidade: pattern.severidade,
                    arquivo: relativo,
                    linha: i + 1,
                    codigo: linha.trim().substring(0, 120),
                    descricao: pattern.descricao,
                    recomendacao: pattern.recomendacao,
                    owaspRef: pattern.owaspRef,
                });
            }
        }
    }

    return findings;
}

/**
 * Calcula score de segurança (0-100).
 * Penalidades: CRITICAL=-15, HIGH=-10, MEDIUM=-5, LOW=-2
 */
function calcularScore(findings: Finding[]): number {
    let score = 100;
    const penalidades: Record<Severidade, number> = {
        CRITICAL: 15,
        HIGH: 10,
        MEDIUM: 5,
        LOW: 2,
    };

    for (const f of findings) {
        score -= penalidades[f.severidade];
    }

    return Math.max(0, Math.min(100, score));
}

// ─── API Pública ──────────────────────────────────────────────────────────────

/**
 * Executa análise completa do projeto.
 */
export async function analisarProjeto(diretorio: string): Promise<AnalysisResult> {
    const arquivos = await coletarArquivos(diretorio);
    const allFindings: Finding[] = [];

    for (const arquivo of arquivos) {
        try {
            const findings = await analisarArquivo(arquivo, diretorio, PATTERNS);
            allFindings.push(...findings);
        } catch {
            // Ignora arquivos que não podem ser lidos
        }
    }

    const porSeveridade: Record<Severidade, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    const porCategoria: Record<string, number> = {};

    for (const f of allFindings) {
        porSeveridade[f.severidade]++;
        porCategoria[f.categoria] = (porCategoria[f.categoria] ?? 0) + 1;
    }

    return {
        totalArquivos: arquivos.length,
        totalFindings: allFindings.length,
        findings: allFindings,
        porSeveridade,
        porCategoria,
        score: calcularScore(allFindings),
    };
}

/**
 * Analisa apenas vulnerabilidades de API (auth, CORS, rate limiting).
 */
export async function analisarAPI(diretorio: string): Promise<AnalysisResult> {
    const arquivos = await coletarArquivos(diretorio);
    const apiPatterns = PATTERNS.filter((p) =>
        ["API Security", "Error Handling", "Security Headers"].includes(p.categoria)
    );
    const allFindings: Finding[] = [];

    for (const arquivo of arquivos) {
        try {
            const findings = await analisarArquivo(arquivo, diretorio, apiPatterns);
            allFindings.push(...findings);
        } catch {}
    }

    // Verificações adicionais de API
    const apiFindings = await verificarAusenciaAuth(diretorio, arquivos);
    allFindings.push(...apiFindings);

    const porSeveridade: Record<Severidade, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    const porCategoria: Record<string, number> = {};
    for (const f of allFindings) {
        porSeveridade[f.severidade]++;
        porCategoria[f.categoria] = (porCategoria[f.categoria] ?? 0) + 1;
    }

    return {
        totalArquivos: arquivos.length,
        totalFindings: allFindings.length,
        findings: allFindings,
        porSeveridade,
        porCategoria,
        score: calcularScore(allFindings),
    };
}

/**
 * Verifica se arquivos de configuração de auth estão presentes.
 */
async function verificarAusenciaAuth(diretorio: string, arquivos: string[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    const nomes = arquivos.map((a) => path.basename(a).toLowerCase());

    // Verifica se tem algum middleware de auth
    const temAuth = nomes.some(
        (n) => n.includes("auth") || n.includes("middleware") || n.includes("guard")
    );

    if (!temAuth) {
        findings.push({
            id: "AUTH-003",
            categoria: "API Security",
            severidade: "HIGH",
            arquivo: "(projeto)",
            linha: 0,
            codigo: "",
            descricao: "Nenhum arquivo de autenticação/middleware detectado no projeto.",
            recomendacao: "Implemente autenticação (JWT, OAuth 2.0) com middleware dedicado.",
            owaspRef: "A01:2021 - Broken Access Control",
        });
    }

    // Verifica .env.example (gestão de segredos)
    try {
        await fs.access(path.join(diretorio, ".env.example"));
    } catch {
        try {
            await fs.access(path.join(diretorio, ".env"));
            findings.push({
                id: "SEC-004",
                categoria: "Secrets",
                severidade: "MEDIUM",
                arquivo: ".env",
                linha: 0,
                codigo: "",
                descricao: ".env existe mas .env.example não — dificuldade de onboarding e risco de exposição.",
                recomendacao: "Crie .env.example com variáveis sem valores reais. Adicione .env ao .gitignore.",
            });
        } catch {}
    }

    return findings;
}

/**
 * Gera relatório de conformidade OWASP Top 10.
 */
export function gerarRelatorioOWASP(findings: Finding[]): Record<string, { coberto: boolean; findings: number }> {
    const owaspCategories: Record<string, { coberto: boolean; findings: number }> = {
        "A01:2021 - Broken Access Control": { coberto: false, findings: 0 },
        "A02:2021 - Cryptographic Failures": { coberto: false, findings: 0 },
        "A03:2021 - Injection": { coberto: false, findings: 0 },
        "A04:2021 - Insecure Design": { coberto: false, findings: 0 },
        "A05:2021 - Security Misconfiguration": { coberto: false, findings: 0 },
        "A06:2021 - Vulnerable and Outdated Components": { coberto: false, findings: 0 },
        "A07:2021 - Identification and Authentication Failures": { coberto: false, findings: 0 },
        "A08:2021 - Software and Data Integrity Failures": { coberto: false, findings: 0 },
        "A09:2021 - Security Logging and Monitoring Failures": { coberto: false, findings: 0 },
        "A10:2021 - Server-Side Request Forgery": { coberto: false, findings: 0 },
    };

    for (const f of findings) {
        if (f.owaspRef && owaspCategories[f.owaspRef] !== undefined) {
            owaspCategories[f.owaspRef].coberto = true;
            owaspCategories[f.owaspRef].findings++;
        }
    }

    return owaspCategories;
}
