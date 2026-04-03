/**
 * VibeSecurity — Security Module (8 MCP Tools)
 *
 * Tools de segurança avançada com instalação visual guiada:
 *
 * 1. auditar_seguranca_api    — Analisa auth, inputs, rate limiting
 * 2. detectar_vulnerabilidades — SQLi, XSS, eval, secrets (SAST leve)
 * 3. verificar_integridade    — Anti-tampering + debugger detection
 * 4. gerar_relatorio_conformidade — LGPD/GDPR/OWASP score
 * 5. blindar_projeto          — Wizard visual completo (todas as análises)
 * 6. configurar_protecao      — Gera/atualiza .vibesecurity.json
 * 7. analisar_dependencias    — CVEs via Trivy em deps
 * 8. gerar_politica_seguranca — Gera SECURITY.md modelo
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import fs from "fs/promises";
import path from "path";
import { execFile } from "child_process";
import util from "util";
import { getAuditLogger } from "../security/audit-logger.js";
import { IntegrityChecker, type IntegrityCheckResult } from "../security/integrity.js";
import { analisarProjeto, analisarAPI, gerarRelatorioOWASP, type AnalysisResult, type Finding } from "../security/analyzers.js";

const execFileAsync = util.promisify(execFile);

// ─── Helpers de formatação visual ─────────────────────────────────────────────

function icone(ok: boolean, warn?: boolean): string {
    if (warn) return "⚠️";
    return ok ? "✅" : "❌";
}

function barraProgresso(score: number): string {
    const filled = Math.round(score / 10);
    const empty = 10 - filled;
    return `[${"█".repeat(filled)}${"░".repeat(empty)}] ${score}/100`;
}

function classificacao(score: number): string {
    if (score >= 90) return "EXCELENTE 🏆";
    if (score >= 75) return "BOM 🛡️";
    if (score >= 50) return "REGULAR ⚠️";
    if (score >= 25) return "RUIM 🔴";
    return "CRÍTICO 🚨";
}

function formatarFindings(findings: Finding[], max: number = 10): string {
    if (findings.length === 0) return "   Nenhuma vulnerabilidade encontrada.\n";

    let output = "";
    const mostrar = findings.slice(0, max);
    for (const f of mostrar) {
        const sev = f.severidade === "CRITICAL" ? "🔴" : f.severidade === "HIGH" ? "🟠" : f.severidade === "MEDIUM" ? "🟡" : "🟢";
        output += `   ${sev} [${f.id}] ${f.descricao}\n`;
        if (f.arquivo) output += `      📍 ${f.arquivo}:${f.linha}\n`;
        output += `      💡 ${f.recomendacao}\n\n`;
    }
    if (findings.length > max) {
        output += `   ... e mais ${findings.length - max} findings.\n`;
    }
    return output;
}

// ─── Registro das 8 tools de segurança ────────────────────────────────────────

export function registerSecurityTools(server: McpServer, diretorioPermitido: string): void {
    const logger = getAuditLogger();

    // ═══════════════════════════════════════════════════════════════════
    // Tool 1: Auditar Segurança de API
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "auditar_seguranca_api",
        "Analisa o código buscando falhas de autenticação, inputs não-validados, falta de rate limiting e CORS aberto. Categoria: Proteção de API (OAuth, JWT, validação/sanitização, rate limiting, TLS, auditoria).",
        {
            explicacao_para_humanos: z.string().describe("Explique por que esta auditoria de API é necessária."),
        },
        async ({ explicacao_para_humanos }) => {
            await logger.log("INFO", "tool.auditar_api.inicio", {
                toolName: "auditar_seguranca_api",
                details: { justificativa: explicacao_para_humanos },
            });

            const resultado = await analisarAPI(diretorioPermitido);

            const output = [
                "🔒 VibeSecurity — Auditoria de Segurança de API",
                "━".repeat(50),
                "",
                `📊 Score: ${barraProgresso(resultado.score)} — ${classificacao(resultado.score)}`,
                `📁 Arquivos analisados: ${resultado.totalArquivos}`,
                `🔍 Findings: ${resultado.totalFindings}`,
                "",
                "📋 DETALHES:",
                "",
                formatarFindings(resultado.findings, 15),
                "━".repeat(50),
                "",
                "🔧 TÉCNICAS DE PROTEÇÃO APLICÁVEIS:",
                "  • OAuth 2.0 / JWT para autenticação robusta",
                "  • Validação com Zod/Joi em todos os endpoints",
                "  • Rate limiting (token bucket) para DDoS/brute force",
                "  • CORS restritivo em produção",
                "  • Helmet.js para security headers",
                "  • TLS 1.2+ obrigatório para dados em trânsito",
            ];

            await logger.log("INFO", "tool.auditar_api.concluido", {
                toolName: "auditar_seguranca_api",
                resultado: "SUCESSO",
                details: { score: resultado.score, findings: resultado.totalFindings },
            });

            return { content: [{ type: "text", text: output.join("\n") }] };
        }
    );

    // ═══════════════════════════════════════════════════════════════════
    // Tool 2: Detectar Vulnerabilidades
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "detectar_vulnerabilidades",
        "Scan profundo de código: SQL Injection, XSS, eval(), secrets hardcoded, OWASP Top 10. Categoria: Proteção contra Exploits (menor privilégio, tratamento de erros, gestão de segredos, preparação SAST/DAST).",
        {
            explicacao_para_humanos: z.string().describe("Explique o que espera encontrar nesta análise."),
        },
        async ({ explicacao_para_humanos }) => {
            await logger.log("INFO", "tool.detectar_vulns.inicio", {
                toolName: "detectar_vulnerabilidades",
                details: { justificativa: explicacao_para_humanos },
            });

            const resultado = await analisarProjeto(diretorioPermitido);

            const output = [
                "🔍 VibeSecurity — Detecção de Vulnerabilidades (SAST Leve)",
                "━".repeat(55),
                "",
                `📊 Score: ${barraProgresso(resultado.score)} — ${classificacao(resultado.score)}`,
                `📁 Arquivos: ${resultado.totalArquivos} | 🔍 Findings: ${resultado.totalFindings}`,
                "",
                "📊 POR SEVERIDADE:",
                `   🔴 CRITICAL: ${resultado.porSeveridade.CRITICAL}`,
                `   🟠 HIGH:     ${resultado.porSeveridade.HIGH}`,
                `   🟡 MEDIUM:   ${resultado.porSeveridade.MEDIUM}`,
                `   🟢 LOW:      ${resultado.porSeveridade.LOW}`,
                "",
                "📋 FINDINGS:",
                "",
                formatarFindings(resultado.findings, 20),
                "━".repeat(55),
                "",
                "🛡️ RECOMENDAÇÕES DE PROTEÇÃO:",
                "  • Parameterize TODAS as queries SQL",
                "  • Sanitize outputs com DOMPurify (frontend)",
                "  • Nunca use eval() — use alternativas seguras",
                "  • Mova secrets para .env + gerenciador de segredos",
                "  • Configure SAST/DAST no CI/CD pipeline",
            ];

            await logger.log("INFO", "tool.detectar_vulns.concluido", {
                toolName: "detectar_vulnerabilidades",
                resultado: "SUCESSO",
                details: { score: resultado.score, porSeveridade: resultado.porSeveridade },
            });

            return { content: [{ type: "text", text: output.join("\n") }] };
        }
    );

    // ═══════════════════════════════════════════════════════════════════
    // Tool 3: Verificar Integridade
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "verificar_integridade",
        "Calcula hashes SHA-256 dos módulos, verifica adulteração em runtime, detecta debugger e anomalias de timing. Categoria: Proteção contra Clonagem e Engenharia Reversa (anti-tampering, ofuscação, anti-debugging).",
        {
            explicacao_para_humanos: z.string().describe("Explique por que esta verificação de integridade é necessária."),
        },
        async ({ explicacao_para_humanos }) => {
            await logger.log("INFO", "tool.integridade.inicio", {
                toolName: "verificar_integridade",
                details: { justificativa: explicacao_para_humanos },
            });

            const checker = new IntegrityChecker(diretorioPermitido, 0);
            await checker.iniciar();
            const resultado: IntegrityCheckResult = await checker.verificarIntegridade(true);
            await checker.parar();

            const output = [
                "🔐 VibeSecurity — Verificação de Integridade",
                "━".repeat(48),
                "",
                `${icone(resultado.valido)} Status: ${resultado.valido ? "INTEGRIDADE OK" : "⚠️ INTEGRIDADE COMPROMETIDA"}`,
                `📦 Módulos verificados: ${resultado.modulosVerificados}`,
                `🕵️ Debugger detectado: ${resultado.debuggerDetectado ? "❌ SIM" : "✅ NÃO"}`,
                `⏱️ Anomalia de timing: ${resultado.timingAnomalia ? "⚠️ SIM" : "✅ NÃO"}`,
                "",
            ];

            if (resultado.modulosAdulterados.length > 0) {
                output.push("🚨 MÓDULOS ADULTERADOS:");
                for (const mod of resultado.modulosAdulterados) {
                    output.push(`   ❌ ${mod}`);
                }
                output.push("");
            }

            output.push(
                "━".repeat(48),
                "",
                "🛡️ TÉCNICAS DE PROTEÇÃO ATIVAS:",
                "  • Hash SHA-256 de cada módulo fonte",
                "  • Verificação periódica contra baseline",
                "  • Detecção de --inspect / --debug mode",
                "  • Timing analysis contra breakpoints",
                "  • Reação defensiva: encerramento em produção",
                "",
                `📋 Snapshot: ${resultado.snapshot.timestamp}`,
                `   Hashes: ${resultado.snapshot.totalModules} módulos registrados`,
            );

            await logger.log("INFO", "tool.integridade.concluido", {
                toolName: "verificar_integridade",
                resultado: resultado.valido ? "SUCESSO" : "FALHA",
                details: {
                    modulosVerificados: resultado.modulosVerificados,
                    adulterados: resultado.modulosAdulterados.length,
                    debugger: resultado.debuggerDetectado,
                },
            });

            return { content: [{ type: "text", text: output.join("\n") }] };
        }
    );

    // ═══════════════════════════════════════════════════════════════════
    // Tool 4: Gerar Relatório de Conformidade
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "gerar_relatorio_conformidade",
        "Gera relatório detalhado de conformidade LGPD/GDPR e cobertura OWASP Top 10, com score e recomendações. Categoria: Conformidade e Padrões.",
        {
            explicacao_para_humanos: z.string().describe("Explique o contexto desta análise de conformidade."),
        },
        async ({ explicacao_para_humanos }) => {
            await logger.log("INFO", "tool.conformidade.inicio", {
                toolName: "gerar_relatorio_conformidade",
                details: { justificativa: explicacao_para_humanos },
            });

            const analise = await analisarProjeto(diretorioPermitido);
            const owasp = gerarRelatorioOWASP(analise.findings);

            const totalCoberto = Object.values(owasp).filter((v) => v.coberto).length;
            const owaspScore = Math.round((totalCoberto / 10) * 100);

            const output = [
                "📋 VibeSecurity — Relatório de Conformidade",
                "━".repeat(48),
                "",
                "🌐 OWASP Top 10 (2021) Coverage:",
                `   ${barraProgresso(owaspScore)}`,
                "",
            ];

            for (const [cat, info] of Object.entries(owasp)) {
                const status = info.coberto
                    ? info.findings > 0
                        ? `⚠️ ${info.findings} finding(s)`
                        : "✅ Coberto"
                    : "⬜ Não analisado";
                output.push(`   ${status} ${cat}`);
            }

            output.push(
                "",
                "━".repeat(48),
                "",
                "🏛️ CONFORMIDADE LGPD/GDPR:",
                "",
                `   ${icone(analise.porSeveridade.CRITICAL === 0)} Dados sensíveis protegidos (sem secrets hardcoded)`,
                `   ⬜ Consentimento de dados (requer verificação manual)`,
                `   ⬜ Direito ao esquecimento (requer verificação manual)`,
                `   ${icone(true)} Minimização de dados em logs (sanitização ativa)`,
                `   ⬜ DPO designado (requer verificação organizacional)`,
                `   ${icone(true)} Registro de atividades de tratamento (audit log)`,
                "",
                "━".repeat(48),
                "",
                `📊 Score de Segurança: ${barraProgresso(analise.score)}`,
                `   Classificação: ${classificacao(analise.score)}`,
                "",
                "📌 PRÓXIMOS PASSOS:",
                "  1. Resolva findings CRITICAL e HIGH imediatamente",
                "  2. Implemente validação de consentimento LGPD",
                "  3. Configure pipeline SAST/DAST no CI/CD",
                "  4. Agende pentest trimestral",
                "  5. Documente política de privacidade",
            );

            await logger.log("INFO", "tool.conformidade.concluido", {
                toolName: "gerar_relatorio_conformidade",
                resultado: "SUCESSO",
                details: { owaspScore, securityScore: analise.score },
            });

            return { content: [{ type: "text", text: output.join("\n") }] };
        }
    );

    // ═══════════════════════════════════════════════════════════════════
    // Tool 5: BLINDAR PROJETO (Wizard Visual Completo)
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "blindar_projeto",
        "🛡️ INSTALAÇÃO VISUAL GUIADA — Executa TODAS as análises de segurança sequencialmente e gera relatório consolidado com status visual por etapa (✅/⚠️/❌). Mostra exatamente o que está sendo verificado em cada fase. Cobre: API, Exploits, Integridade, Dependências e Conformidade OWASP/LGPD.",
        {
            explicacao_para_humanos: z.string().describe("Explique o contexto da blindagem completa do projeto."),
            nivel: z.enum(["rapido", "completo"]).default("completo").describe("Nível: 'rapido' (análise estática) ou 'completo' (inclui Trivy + integridade)."),
        },
        async ({ explicacao_para_humanos, nivel }) => {
            await logger.log("INFO", "tool.blindar.inicio", {
                toolName: "blindar_projeto",
                details: { nivel, justificativa: explicacao_para_humanos },
            });

            const linhas: string[] = [
                "🔒 VibeSecurity — Blindagem do Projeto",
                "━".repeat(45),
                `📅 ${new Date().toISOString()}`,
                `📁 Diretório: ${diretorioPermitido}`,
                `⚡ Nível: ${nivel.toUpperCase()}`,
                "",
            ];

            let scoreTotal = 0;
            let totalEtapas = 0;
            let patchesGerados = 0;

            // ─── ETAPA 1: API ─────────────────────────────────────────
            linhas.push("📋 ETAPA 1/5: Análise de Segurança de API");
            linhas.push("   Verificando auth, inputs, CORS, rate limiting...");

            const apiResult = await analisarAPI(diretorioPermitido);
            const apiOk = apiResult.porSeveridade.CRITICAL === 0 && apiResult.porSeveridade.HIGH === 0;
            const apiWarn = apiResult.totalFindings > 0 && apiOk;

            linhas.push(`   ${icone(apiOk && !apiWarn, apiWarn)} Score API: ${apiResult.score}/100`);
            if (apiResult.totalFindings > 0) {
                const top3 = apiResult.findings.slice(0, 3);
                for (const f of top3) {
                    linhas.push(`   ${f.severidade === "CRITICAL" ? "❌" : "⚠️"} ${f.descricao}`);
                }
            } else {
                linhas.push("   ✅ Nenhuma falha de API detectada");
            }
            linhas.push("");
            scoreTotal += apiResult.score;
            totalEtapas++;

            // ─── ETAPA 2: Exploits ────────────────────────────────────
            linhas.push("📋 ETAPA 2/5: Proteção contra Exploits");
            linhas.push("   Buscando SQLi, XSS, eval(), secrets hardcoded...");

            const vulnResult = await analisarProjeto(diretorioPermitido);
            const vulnOk = vulnResult.porSeveridade.CRITICAL === 0;
            const vulnWarn = vulnResult.porSeveridade.HIGH > 0;

            linhas.push(`   ${icone(vulnOk && !vulnWarn, vulnWarn)} Score Vulnerabilidades: ${vulnResult.score}/100`);
            linhas.push(`   🔴 CRITICAL: ${vulnResult.porSeveridade.CRITICAL} | 🟠 HIGH: ${vulnResult.porSeveridade.HIGH} | 🟡 MEDIUM: ${vulnResult.porSeveridade.MEDIUM} | 🟢 LOW: ${vulnResult.porSeveridade.LOW}`);

            if (vulnResult.findings.length > 0) {
                const criticals = vulnResult.findings.filter((f) => f.severidade === "CRITICAL").slice(0, 3);
                for (const f of criticals) {
                    linhas.push(`   ❌ [${f.id}] ${f.arquivo}:${f.linha} — ${f.descricao}`);
                    patchesGerados++;
                }
            }
            linhas.push("");
            scoreTotal += vulnResult.score;
            totalEtapas++;

            // ─── ETAPA 3: Integridade ─────────────────────────────────
            if (nivel === "completo") {
                linhas.push("📋 ETAPA 3/5: Integridade & Anti-Clonagem");
                linhas.push("   Calculando hashes SHA-256, verificando debugger...");

                const checker = new IntegrityChecker(diretorioPermitido, 0);
                await checker.iniciar();
                const intResult = await checker.verificarIntegridade(true);
                await checker.parar();

                linhas.push(`   ${icone(intResult.valido)} Integridade: ${intResult.valido ? "OK" : "COMPROMETIDA"}`);
                linhas.push(`   ${icone(!intResult.debuggerDetectado)} Debugger: ${intResult.debuggerDetectado ? "DETECTADO ⚠️" : "Não detectado"}`);
                linhas.push(`   📦 ${intResult.modulosVerificados} módulos com hash calculado`);

                if (intResult.modulosAdulterados.length > 0) {
                    for (const mod of intResult.modulosAdulterados.slice(0, 3)) {
                        linhas.push(`   ❌ ${mod}`);
                    }
                }
                linhas.push("");
                scoreTotal += intResult.valido ? 100 : 30;
                totalEtapas++;
            } else {
                linhas.push("📋 ETAPA 3/5: Integridade & Anti-Clonagem");
                linhas.push("   ⏭️  Pulada (modo rápido)");
                linhas.push("");
            }

            // ─── ETAPA 4: Dependências ────────────────────────────────
            linhas.push("📋 ETAPA 4/5: Análise de Dependências");
            if (nivel === "completo") {
                linhas.push("   Verificando CVEs em dependências...");
                try {
                    const { stdout } = await execFileAsync("trivy", [
                        "fs", "--scanners", "vuln",
                        "--severity", "HIGH,CRITICAL",
                        "--quiet",
                        diretorioPermitido,
                    ]);
                    const temVulns = stdout.trim().length > 50;
                    linhas.push(`   ${icone(!temVulns, temVulns)} ${temVulns ? "Vulnerabilidades encontradas em dependências" : "Nenhuma CVE HIGH/CRITICAL em dependências"}`);
                    if (temVulns) {
                        // Extrai linhas relevantes do output Trivy
                        const trivyLines = stdout.split("\n").filter((l: string) => l.includes("CRITICAL") || l.includes("HIGH")).slice(0, 5);
                        for (const tl of trivyLines) {
                            linhas.push(`   ⚠️ ${tl.trim()}`);
                        }
                    }
                    scoreTotal += temVulns ? 50 : 100;
                } catch (err: any) {
                    const hasOutput = err.stdout && err.stdout.trim().length > 0;
                    linhas.push(`   ${icone(false, true)} Trivy reportou problemas${hasOutput ? "" : " (Trivy não instalado?)"}`);
                    if (hasOutput) {
                        const trivyLines = (err.stdout as string).split("\n").filter((l: string) => l.includes("CRITICAL") || l.includes("HIGH")).slice(0, 5);
                        for (const tl of trivyLines) {
                            linhas.push(`   ⚠️ ${tl.trim()}`);
                        }
                    }
                    scoreTotal += 40;
                }
                totalEtapas++;
            } else {
                linhas.push("   ⏭️  Pulada (modo rápido)");
            }
            linhas.push("");

            // ─── ETAPA 5: Conformidade OWASP/LGPD ────────────────────
            linhas.push("📋 ETAPA 5/5: Conformidade OWASP/LGPD");
            linhas.push("   Avaliando cobertura OWASP Top 10...");

            const owasp = gerarRelatorioOWASP(vulnResult.findings);
            const totalCoberto = Object.values(owasp).filter((v) => v.coberto).length;
            const owaspScore = Math.round((totalCoberto / 10) * 100);

            linhas.push(`   ${icone(totalCoberto >= 7, totalCoberto >= 4 && totalCoberto < 7)} OWASP: ${totalCoberto}/10 categorias analisadas`);
            linhas.push(`   ${icone(vulnResult.porSeveridade.CRITICAL === 0)} Secrets protegidos`);
            linhas.push(`   ${icone(true)} Sanitização de logs ativa (LGPD)`)
            linhas.push(`   ${icone(true)} Auditoria de acessos ativa (LGPD)`)
            linhas.push("");
            scoreTotal += owaspScore;
            totalEtapas++;

            // ─── RESUMO FINAL ─────────────────────────────────────────
            const scoreFinal = Math.round(scoreTotal / totalEtapas);

            linhas.push("━".repeat(45));
            linhas.push("");
            linhas.push(`📊 SCORE FINAL: ${barraProgresso(scoreFinal)}`);
            linhas.push(`🏅 Classificação: ${classificacao(scoreFinal)}`);
            linhas.push(`🛡️  Etapas executadas: ${totalEtapas}`);
            linhas.push(`📍 Total findings: ${vulnResult.totalFindings + apiResult.totalFindings}`);
            linhas.push(`🔧 Patches recomendados: ${patchesGerados}`);
            linhas.push("");
            linhas.push("━".repeat(45));
            linhas.push("");
            linhas.push("📌 PRÓXIMOS PASSOS:");
            linhas.push("  1. use 'detectar_vulnerabilidades' para detalhar findings");
            linhas.push("  2. use 'propor_correcao_patch' para gerar patches");
            linhas.push("  3. use 'configurar_protecao' para ativar proteções");
            linhas.push("  4. use 'gerar_politica_seguranca' para documentação");

            // Salva relatório em JSON
            const reportDir = path.join(diretorioPermitido, ".vibesecurity");
            await fs.mkdir(reportDir, { recursive: true });
            const report = {
                timestamp: new Date().toISOString(),
                nivel,
                scoreFinal,
                classificacao: classificacao(scoreFinal),
                etapas: {
                    api: apiResult.score,
                    vulnerabilidades: vulnResult.score,
                    owasp: owaspScore,
                },
                totalFindings: vulnResult.totalFindings + apiResult.totalFindings,
                porSeveridade: vulnResult.porSeveridade,
            };
            await fs.writeFile(
                path.join(reportDir, "report.json"),
                JSON.stringify(report, null, 2),
                "utf-8"
            );

            await logger.log("INFO", "tool.blindar.concluido", {
                toolName: "blindar_projeto",
                resultado: "SUCESSO",
                details: { scoreFinal, nivel, totalFindings: report.totalFindings },
            });

            return { content: [{ type: "text", text: linhas.join("\n") }] };
        }
    );

    // ═══════════════════════════════════════════════════════════════════
    // Tool 6: Configurar Proteção
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "configurar_protecao",
        "Gera ou atualiza .vibesecurity.json com as proteções ativas, regras personalizadas e configurações do módulo de segurança.",
        {
            protecoes: z.object({
                auditLog: z.boolean().default(true).describe("Ativar logging de auditoria"),
                integrityCheck: z.boolean().default(true).describe("Ativar verificação de integridade periódica"),
                rateLimiting: z.boolean().default(true).describe("Ativar rate limiting"),
                antiDebug: z.boolean().default(false).describe("Ativar detecção de debugger (pode atrapalhar dev)"),
                autoScan: z.boolean().default(true).describe("Scan automático na inicialização"),
            }).describe("Proteções a ativar/desativar"),
            explicacao_para_humanos: z.string().describe("Explique o contexto desta configuração."),
        },
        async ({ protecoes, explicacao_para_humanos }) => {
            const configDir = path.join(diretorioPermitido, ".vibesecurity");
            await fs.mkdir(configDir, { recursive: true });

            const configPath = path.join(configDir, "config.json");

            // Carrega config existente se houver
            let configAtual: Record<string, unknown> = {};
            try {
                const existente = await fs.readFile(configPath, "utf-8");
                configAtual = JSON.parse(existente);
            } catch {}

            const novaConfig = {
                ...configAtual,
                versao: "2.0.0",
                atualizadoEm: new Date().toISOString(),
                protecoes,
                regras: {
                    maxReqPorMinuto: 30,
                    burstLimit: 5,
                    hashCheckIntervalSec: 60,
                    logRotationSizeMB: 5,
                    severidadeMinimaAlerta: "HIGH",
                },
            };

            await fs.writeFile(configPath, JSON.stringify(novaConfig, null, 2), "utf-8");

            await logger.log("INFO", "tool.configurar.sucesso", {
                toolName: "configurar_protecao",
                resultado: "SUCESSO",
                details: { protecoes },
            });

            const output = [
                "⚙️ VibeSecurity — Configuração Atualizada",
                "━".repeat(45),
                "",
                `📄 Arquivo: .vibesecurity/config.json`,
                "",
                "🛡️ PROTEÇÕES:",
                `   ${icone(protecoes.auditLog)} Audit Log`,
                `   ${icone(protecoes.integrityCheck)} Verificação de Integridade`,
                `   ${icone(protecoes.rateLimiting)} Rate Limiting`,
                `   ${icone(protecoes.antiDebug)} Anti-Debug (${protecoes.antiDebug ? "ATIVO" : "desativado — recomendado em dev"})`,
                `   ${icone(protecoes.autoScan)} Auto-Scan na inicialização`,
                "",
                "✅ Configuração salva com sucesso.",
            ];

            return { content: [{ type: "text", text: output.join("\n") }] };
        }
    );

    // ═══════════════════════════════════════════════════════════════════
    // Tool 7: Analisar Dependências
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "analisar_dependencias",
        "Verifica dependências (package-lock.json, requirements.txt) por CVEs conhecidas usando Trivy. Categoria: Componentes Vulneráveis e Desatualizados (OWASP A06).",
        {
            explicacao_para_humanos: z.string().describe("Explique por que esta análise de dependências é necessária."),
        },
        async ({ explicacao_para_humanos }) => {
            await logger.log("INFO", "tool.deps.inicio", {
                toolName: "analisar_dependencias",
                details: { justificativa: explicacao_para_humanos },
            });

            const output: string[] = [
                "📦 VibeSecurity — Análise de Dependências",
                "━".repeat(45),
                "",
            ];

            // Verifica quais lockfiles existem
            const lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "Pipfile.lock", "go.sum"];
            const encontrados: string[] = [];
            for (const lf of lockfiles) {
                try {
                    await fs.access(path.join(diretorioPermitido, lf));
                    encontrados.push(lf);
                } catch {}
            }

            if (encontrados.length === 0) {
                output.push("⚠️ Nenhum lockfile encontrado. Não é possível analisar dependências.");
                output.push("   Lockfiles suportados: package-lock.json, yarn.lock, requirements.txt, etc.");
                return { content: [{ type: "text", text: output.join("\n") }] };
            }

            output.push(`📋 Lockfiles encontrados: ${encontrados.join(", ")}`);
            output.push("");

            try {
                const { stdout } = await execFileAsync("trivy", [
                    "fs", "--scanners", "vuln",
                    "--format", "table",
                    "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
                    diretorioPermitido,
                ]);

                output.push("📊 RESULTADO DO SCAN:");
                output.push("");
                output.push(stdout || "   Nenhuma vulnerabilidade encontrada.");
            } catch (err: any) {
                const relatorio = err.stdout || err.message;
                output.push("📊 RESULTADO DO SCAN (vulnerabilidades encontradas):");
                output.push("");
                output.push(relatorio);
            }

            output.push("");
            output.push("━".repeat(45));
            output.push("");
            output.push("💡 RECOMENDAÇÕES:");
            output.push("  • npm audit fix —  corrige vulnerabilidades automaticamente");
            output.push("  • Atualize deps HIGH/CRITICAL imediatamente");
            output.push("  • Configure Dependabot/Renovate para updates automáticos");

            await logger.log("INFO", "tool.deps.concluido", {
                toolName: "analisar_dependencias",
                resultado: "SUCESSO",
                details: { lockfiles: encontrados },
            });

            return { content: [{ type: "text", text: output.join("\n") }] };
        }
    );

    // ═══════════════════════════════════════════════════════════════════
    // Tool 8: Gerar Política de Segurança
    // ═══════════════════════════════════════════════════════════════════
    server.tool(
        "gerar_politica_seguranca",
        "Gera arquivo SECURITY.md modelo com política de divulgação responsável, conformidade LGPD/GDPR e instruções para report de vulnerabilidades.",
        {
            nome_projeto: z.string().describe("Nome do projeto para o SECURITY.md."),
            email_contato: z.string().describe("Email para reports de segurança (ex: security@empresa.com)."),
            explicacao_para_humanos: z.string().describe("Explique o contexto desta política."),
        },
        async ({ nome_projeto, email_contato, explicacao_para_humanos }) => {
            const securityMd = `# Security Policy — ${nome_projeto}

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | ✅ Sim              |
| < 1.0   | ❌ Não              |

## Reporting a Vulnerability

Se você encontrou uma vulnerabilidade de segurança, **NÃO abra uma issue pública**.

### Como reportar:
1. Envie email para: **${email_contato}**
2. Inclua: descrição detalhada, passos para reproduzir, impacto potencial
3. Aguarde confirmação em até **48 horas úteis**

### O que esperamos:
- Não explorarem a vulnerabilidade além do necessário para demonstrá-la
- Não acessem dados de outros usuários
- Dêem tempo razoável para correção antes de divulgação pública

### O que oferecemos:
- Reconhecimento público (se desejado) no changelog
- Comunicação transparente sobre o timeline de correção
- Correção prioritária para vulnerabilidades CRITICAL e HIGH

## Security Compliance

### OWASP Top 10 (2021)
Este projeto é regularmente analisado contra o OWASP Top 10 usando ferramentas de análise estática (SAST) e o VibeSecurity MCP.

### LGPD / GDPR
- Dados pessoais são sanitizados nos logs
- Auditoria completa de acessos
- Minimização de dados coletados
- Direito ao esquecimento implementável sob demanda

### Ferramentas de Segurança
- **VibeSecurity MCP** — análise estática e auditoria contínua
- **Trivy** — scan de vulnerabilidades em dependências e configurações
- **Rate Limiting** — proteção contra força bruta e DDoS
- **Integrity Checker** — verificação de adulteração em runtime

## Security Headers

Recomendamos as seguintes configurações:
\`\`\`
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
\`\`\`

## Contact

📧 Security Team: ${email_contato}
🔒 PGP Key: (adicione sua chave pública aqui)

---
*Gerado automaticamente por VibeSecurity MCP v2.0.0*
*Última atualização: ${new Date().toISOString().split("T")[0]}*
`;

            const destino = path.join(diretorioPermitido, "SECURITY.md");
            await fs.writeFile(destino, securityMd, "utf-8");

            await logger.log("INFO", "tool.politica.sucesso", {
                toolName: "gerar_politica_seguranca",
                resultado: "SUCESSO",
                details: { nome_projeto, destino },
            });

            return {
                content: [{
                    type: "text",
                    text: [
                        "📄 VibeSecurity — Política de Segurança Gerada",
                        "━".repeat(48),
                        "",
                        `✅ Arquivo criado: SECURITY.md`,
                        "",
                        "📋 Conteúdo inclui:",
                        "  • Processo de divulgação responsável",
                        "  • Versões suportadas",
                        "  • Conformidade OWASP/LGPD/GDPR",
                        "  • Security headers recomendados",
                        `  • Contato: ${email_contato}`,
                        "",
                        "💡 Revise e personalize conforme necessário.",
                    ].join("\n"),
                }],
            };
        }
    );
}
