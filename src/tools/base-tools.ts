/**
 * VibeSecurity — Base Tools (Tools originais refatoradas)
 *
 * Registra as 3 tools base no McpServer:
 * - ler_arquivo_seguro
 * - rodar_scan_trivy
 * - propor_correcao_patch
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import fs from "fs/promises";
import path from "path";
import { execFile } from "child_process";
import util from "util";
import { getAuditLogger } from "../security/audit-logger.js";

const execFileAsync = util.promisify(execFile);

// ─── Helper de caminho seguro ─────────────────────────────────────────────────

export async function resolverCaminhoSeguro(
    diretorioPermitido: string,
    caminhoRelativo: string
): Promise<string | null> {
    const resolvido = path.resolve(diretorioPermitido, caminhoRelativo);
    const real = await fs.realpath(resolvido).catch(() => resolvido);
    if (!real.startsWith(diretorioPermitido)) return null;
    return real;
}

// ─── Registro de tools ────────────────────────────────────────────────────────

export function registerBaseTools(server: McpServer, diretorioPermitido: string): void {
    const logger = getAuditLogger();

    // Tool 1: Ler arquivo seguro
    server.tool(
        "ler_arquivo_seguro",
        "Lê o conteúdo de um arquivo específico após apresentar justificativa para o usuário.",
        {
            caminho_arquivo: z.string().describe("O caminho relativo do arquivo que precisa ser lido (ex: src/app.js)."),
            explicacao_para_humanos: z.string().describe("OBRIGATÓRIO: Explique em português claro, sem jargões, por que você precisa ler este arquivo e qual vulnerabilidade está procurando."),
        },
        async ({ caminho_arquivo, explicacao_para_humanos }) => {
            const caminhoReal = await resolverCaminhoSeguro(diretorioPermitido, caminho_arquivo);

            if (!caminhoReal) {
                await logger.log("ALERT", "tool.ler_arquivo.path_traversal", {
                    toolName: "ler_arquivo_seguro",
                    resultado: "BLOQUEADO",
                    details: { caminho_arquivo, justificativa: explicacao_para_humanos },
                });
                return { content: [{ type: "text", text: "🚨 ALERTA: Acesso negado. Tentativa de Path Traversal." }] };
            }

            try {
                const conteudo = await fs.readFile(caminhoReal, "utf-8");
                await logger.log("INFO", "tool.ler_arquivo.sucesso", {
                    toolName: "ler_arquivo_seguro",
                    resultado: "SUCESSO",
                    details: { caminho_arquivo, tamanho: conteudo.length },
                });
                return { content: [{ type: "text", text: `Conteúdo de ${caminho_arquivo}:\n\n${conteudo}` }] };
            } catch (erro) {
                await logger.log("WARN", "tool.ler_arquivo.erro", {
                    toolName: "ler_arquivo_seguro",
                    resultado: "FALHA",
                    details: { caminho_arquivo, erro: erro instanceof Error ? erro.message : String(erro) },
                });
                return { content: [{ type: "text", text: `Erro ao ler arquivo: ${erro instanceof Error ? erro.message : String(erro)}` }] };
            }
        }
    );

    // Tool 2: Scan com Trivy
    server.tool(
        "rodar_scan_trivy",
        "Executa o scanner Trivy em um arquivo ou diretório local.",
        {
            alvo: z.string().describe("Caminho relativo da pasta ou arquivo a ser escaneado (ex: . para a pasta atual)."),
            explicacao_para_humanos: z.string().describe("OBRIGATÓRIO: Explique em português por que este scan é necessário e o que está buscando."),
        },
        async ({ alvo, explicacao_para_humanos }) => {
            const caminhoReal = await resolverCaminhoSeguro(diretorioPermitido, alvo);

            if (!caminhoReal) {
                await logger.log("ALERT", "tool.trivy.path_traversal", {
                    toolName: "rodar_scan_trivy",
                    resultado: "BLOQUEADO",
                    details: { alvo },
                });
                return { content: [{ type: "text", text: "🚨 ALERTA: Tentativa de scan fora do diretório permitido." }] };
            }

            try {
                const { stdout } = await execFileAsync("trivy", ["fs", "--scanners", "vuln,secret,config", caminhoReal]);
                await logger.log("INFO", "tool.trivy.sucesso", {
                    toolName: "rodar_scan_trivy",
                    resultado: "SUCESSO",
                    details: { alvo, justificativa: explicacao_para_humanos },
                });
                return { content: [{ type: "text", text: `Scan concluído. Nenhuma vulnerabilidade crítica:\n\n${stdout}` }] };
            } catch (erro: any) {
                const relatorio = erro.stdout ? erro.stdout : erro.message;
                await logger.log("WARN", "tool.trivy.vulnerabilidades", {
                    toolName: "rodar_scan_trivy",
                    resultado: "SUCESSO",
                    details: { alvo, temVulnerabilidades: true },
                });
                return { content: [{ type: "text", text: `Scan concluído (Vulnerabilidades Encontradas!):\n\n${relatorio}` }] };
            }
        }
    );

    // Tool 3: Propor correção (patch)
    server.tool(
        "propor_correcao_patch",
        "Gera um arquivo .patch com a proposta de correção para um código vulnerável.",
        {
            caminho_arquivo: z.string().describe("Caminho relativo do arquivo original."),
            conteudo_patch: z.string().describe("Conteúdo da correção formatado estritamente como Unified Diff."),
            explicacao_para_humanos: z.string().describe("OBRIGATÓRIO: Explique o que esta correção faz e por que é segura."),
        },
        async ({ caminho_arquivo, conteudo_patch, explicacao_para_humanos }) => {
            const caminhoReal = await resolverCaminhoSeguro(diretorioPermitido, caminho_arquivo);

            if (!caminhoReal) {
                await logger.log("ALERT", "tool.patch.path_traversal", {
                    toolName: "propor_correcao_patch",
                    resultado: "BLOQUEADO",
                    details: { caminho_arquivo },
                });
                return { content: [{ type: "text", text: "🚨 ALERTA: Tentativa de escrever fora do diretório permitido." }] };
            }

            const caminhoPatch = `${caminhoReal}.patch`;
            try {
                await fs.writeFile(caminhoPatch, conteudo_patch, "utf-8");
                await logger.log("INFO", "tool.patch.sucesso", {
                    toolName: "propor_correcao_patch",
                    resultado: "SUCESSO",
                    details: { caminho_arquivo, justificativa: explicacao_para_humanos },
                });
                return { content: [{ type: "text", text: `✅ Patch gerado com sucesso em: ${caminho_arquivo}.patch\nRevise e aplique usando 'git apply ${caminho_arquivo}.patch'.` }] };
            } catch (erro) {
                await logger.log("WARN", "tool.patch.erro", {
                    toolName: "propor_correcao_patch",
                    resultado: "FALHA",
                    details: { caminho_arquivo, erro: erro instanceof Error ? erro.message : String(erro) },
                });
                return { content: [{ type: "text", text: `Erro ao gerar patch: ${erro instanceof Error ? erro.message : String(erro)}` }] };
            }
        }
    );
}
