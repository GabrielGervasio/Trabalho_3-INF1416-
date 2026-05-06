package br.pucrio.cofredigital.crypto;

import br.pucrio.cofredigital.totp.Base32;
import br.pucrio.cofredigital.totp.TOTP;
import br.pucrio.cofredigital.totp.TotpUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.nio.file.*;

/**
 * Teste com os arquivos REAIS fornecidos pelo professor.
 *
 * Estrutura esperada de pastas (ajuste BASE_PATH se necessário):
 *
 *   Keys/
 *     admin-pkcs8-aes.key
 *     admin-x509.crt         (ou .pem — ajuste EXTENSAO_CERT)
 *     user01-pkcs8-aes.key
 *     user01-x509.crt
 *     user02-pkcs8-aes.key
 *     user02-x509.crt
 *
 *   Files/
 *     index.enc
 *     index.env
 *     index.asd
 *     XXYYZZ00.enc
 *     XXYYZZ00.env
 *     XXYYZZ00.asd
 *     XXYYZZ11.enc
 *     XXYYZZ11.env
 *     XXYYZZ11.asd
 *     XXYYZZ22.enc
 *     XXYYZZ22.env
 *     XXYYZZ22.asd
 *
 * Compilar (na pasta CofreDigital/):
 *   Windows:
 *     javac -cp "lib/bcprov-jdk18on-1.84.jar" -d . ^
 *       src/br/pucrio/cofredigital/totp/Base32.java ^
 *       src/br/pucrio/cofredigital/totp/TOTP.java ^
 *       src/br/pucrio/cofredigital/totp/TotpUtils.java ^
 *       src/br/pucrio/cofredigital/crypto/BcryptUtils.java ^
 *       src/br/pucrio/cofredigital/crypto/CertificadoUtils.java ^
 *       src/br/pucrio/cofredigital/crypto/CryptoUtils.java ^
 *       src/br/pucrio/cofredigital/crypto/EnvelopeDigital.java ^
 *       src/br/pucrio/cofredigital/crypto/TesteArquivosReais.java
 *
 * Executar:
 *   Windows: java -cp ".;lib/bcprov-jdk18on-1.84.jar" br.pucrio.cofredigital.crypto.TesteArquivosReais
 *   Linux:   java -cp ".:lib/bcprov-jdk18on-1.84.jar" br.pucrio.cofredigital.crypto.TesteArquivosReais
 */
public class TesteArquivosReais {

    // =========================================================================
    // CONFIGURAÇÃO — ajuste esses caminhos para onde você salvou os arquivos
    // =========================================================================

    // Caminho das pastas do professor (use / ou \\ no Windows)
    static final String KEYS_PATH  = "C:\\Users\\Gabriel\\Documents\\vscode\\Trab3\\CofreDigital\\src\\br\\pucrio\\cofredigital\\Keys";
    static final String FILES_PATH = "C:\\Users\\Gabriel\\Documents\\vscode\\Trab3\\CofreDigital\\src\\br\\pucrio\\cofredigital\\Files";

    // Frases secretas fornecidas pelo professor
    static final String FRASE_ADMIN  = "admin";
    static final String FRASE_USER01 = "user01";
    static final String FRASE_USER02 = "user02";

    // Nomes dos arquivos de certificado — tente .crt primeiro, depois .pem
    static final String[] EXTENSOES_CERT = {".crt", ".pem", ""};

    // Nomes código dos arquivos secretos (conforme imagem do professor)
    static final String[] ARQUIVOS_SECRETOS = {"XXYYZZ00", "XXYYZZ11", "XXYYZZ22"};

    // =========================================================================
    // Contadores
    // =========================================================================
    static int totalOk    = 0;
    static int totalFalha = 0;

    // =========================================================================
    // MAIN
    // =========================================================================
    public static void main(String[] args) {
        cabecalho("TESTE COM ARQUIVOS REAIS DO PROFESSOR");

        // Carregar chaves e certificados
        X509Certificate certAdmin  = null;
        X509Certificate certUser01 = null;
        X509Certificate certUser02 = null;
        PrivateKey      chavAdmin  = null;
        PrivateKey      chavUser01 = null;
        PrivateKey      chavUser02 = null;

        secao("1. LEITURA DAS CHAVES E CERTIFICADOS");

        // --- Admin ---
        certAdmin = carregarCertificado("admin");
        if (certAdmin != null) {
            info("  Subject admin:  " + certAdmin.getSubjectX500Principal().getName());
            info("  Email admin:    " + CertificadoUtils.extrairEmail(certAdmin));
            info("  Nome admin:     " + CertificadoUtils.extrairNome(certAdmin));
            ok("Certificado admin carregado");
        } else {
            falha("Certificado admin NAO encontrado");
        }

        chavAdmin = carregarChavePrivada("admin", FRASE_ADMIN);
        if (chavAdmin != null) ok("Chave privada admin decriptada com frase '" + FRASE_ADMIN + "'");
        else falha("Chave privada admin FALHOU");

        // --- User01 ---
        certUser01 = carregarCertificado("user01");
        if (certUser01 != null) {
            info("  Subject user01: " + certUser01.getSubjectX500Principal().getName());
            info("  Email user01:   " + CertificadoUtils.extrairEmail(certUser01));
            ok("Certificado user01 carregado");
        } else {
            falha("Certificado user01 NAO encontrado");
        }

        chavUser01 = carregarChavePrivada("user01", FRASE_USER01);
        if (chavUser01 != null) ok("Chave privada user01 decriptada com frase '" + FRASE_USER01 + "'");
        else falha("Chave privada user01 FALHOU");

        // --- User02 ---
        certUser02 = carregarCertificado("user02");
        if (certUser02 != null) {
            info("  Subject user02: " + certUser02.getSubjectX500Principal().getName());
            info("  Email user02:   " + CertificadoUtils.extrairEmail(certUser02));
            ok("Certificado user02 carregado");
        } else {
            falha("Certificado user02 NAO encontrado");
        }

        chavUser02 = carregarChavePrivada("user02", FRASE_USER02);
        if (chavUser02 != null) ok("Chave privada user02 decriptada com frase '" + FRASE_USER02 + "'");
        else falha("Chave privada user02 FALHOU");

        // =====================================================================
        secao("2. VALIDACAO DAS CHAVES PRIVADAS (assinar 9216 bytes)");
        // =====================================================================

        validarChave("admin",  chavAdmin,  certAdmin);
        validarChave("user01", chavUser01, certUser01);
        validarChave("user02", chavUser02, certUser02);

        // =====================================================================
        secao("3. FRASE SECRETA ERRADA DEVE SER REJEITADA");
        // =====================================================================

        testar("Admin com frase 'errada' deve falhar",
               carregarChavePrivada("admin", "errada") == null);
        testar("User01 com frase 'errada' deve falhar",
               carregarChavePrivada("user01", "errada") == null);

        // =====================================================================
        secao("4. DECRIPTACAO DO INDICE DA PASTA (index.enc/.env/.asd)");
        // =====================================================================

        if (certAdmin != null && chavAdmin != null) {
            String encPath = FILES_PATH + "/index.enc";
            String envPath = FILES_PATH + "/index.env";
            String asdPath = FILES_PATH + "/index.asd";

            testar("Arquivos do indice existem no disco",
                   Files.exists(Paths.get(encPath)) &&
                   Files.exists(Paths.get(envPath)) &&
                   Files.exists(Paths.get(asdPath)));

            EnvelopeDigital.ResultadoDecriptacao res =
                EnvelopeDigital.decriptarArquivo(
                    encPath, envPath, asdPath,
                    chavAdmin, certAdmin.getPublicKey());

            testar("index.enc decriptado com sucesso", res.decriptacaoOk);
            testar("index.asd assinatura verificada (integridade e autenticidade)", res.assinaturaOk);

            if (res.tudoOk() && res.conteudo != null) {
                String conteudo = new String(res.conteudo, java.nio.charset.StandardCharsets.UTF_8);
                secao("  CONTEUDO DO INDEX.ENC:");
                System.out.println(conteudo);

                // Parsear as linhas do índice
                info("  Arquivos no indice:");
                for (String linha : conteudo.split("\n")) {
                    linha = linha.trim();
                    if (linha.isEmpty()) continue;
                    String[] partes = linha.split(" ");
                    if (partes.length >= 4) {
                        info(String.format("    codigo=%-12s nome=%-20s dono=%-10s grupo=%s",
                            partes[0], partes[1], partes[2], partes[3]));
                    }
                }
            } else if (res.mensagemErro != null) {
                info("  Erro: " + res.mensagemErro);
            }
        } else {
            info("  [PULADO] — admin nao foi carregado");
        }

        // =====================================================================
        secao("5. DECRIPTACAO DOS ARQUIVOS SECRETOS");
        // =====================================================================

        // Mapear qual usuário é dono de cada arquivo (vem do índice)
        // Para o teste, tentamos decriptar cada arquivo com cada usuário
        // e verificamos qual consegue (política: só o dono consegue)
        if (chavAdmin != null && certAdmin != null) {
            for (String nomeArq : ARQUIVOS_SECRETOS) {
                secao("  Arquivo: " + nomeArq);

                String encPath = FILES_PATH + "/" + nomeArq + ".enc";
                String envPath = FILES_PATH + "/" + nomeArq + ".env";
                String asdPath = FILES_PATH + "/" + nomeArq + ".asd";

                if (!Files.exists(Paths.get(encPath))) {
                    info("  [PULADO] arquivo nao encontrado: " + encPath);
                    continue;
                }

                // Tentar com cada usuário
                tentarDecriptar(nomeArq, encPath, envPath, asdPath,
                    "admin",  chavAdmin,  certAdmin);
                tentarDecriptar(nomeArq, encPath, envPath, asdPath,
                    "user01", chavUser01, certUser01);
                tentarDecriptar(nomeArq, encPath, envPath, asdPath,
                    "user02", chavUser02, certUser02);
            }
        } else {
            info("  [PULADO] — admin nao carregado");
        }

        // =====================================================================
        secao("6. DADOS DOS CERTIFICADOS (tela de confirmacao de cadastro)");
        // =====================================================================

        mostrarDadosCert("admin",  certAdmin);
        mostrarDadosCert("user01", certUser01);
        mostrarDadosCert("user02", certUser02);

        // =====================================================================
        rodape();
        // =====================================================================
    }

    // =========================================================================
    // HELPERS DE TESTE
    // =========================================================================

    static void validarChave(String nome, PrivateKey chav, X509Certificate cert) {
        if (chav == null || cert == null) {
            info("  [PULADO] " + nome + " — chave ou cert nao disponivel");
            return;
        }
        try {
            boolean valida = CryptoUtils.validarChavePrivada(
                chav, cert.getPublicKey(), 9216);
            testar("Chave privada " + nome + " valida (assina e verifica 9216 bytes)", valida);
        } catch (Exception e) {
            falha("Erro ao validar chave " + nome + ": " + e.getMessage());
        }
    }

    static void tentarDecriptar(String nomeArq, String enc, String env, String asd,
                                 String nomeUsuario, PrivateKey chav, X509Certificate cert) {
        if (chav == null || cert == null) {
            info("    [PULADO] " + nomeUsuario + " — chave nao disponivel");
            return;
        }
        try {
            EnvelopeDigital.ResultadoDecriptacao res =
                EnvelopeDigital.decriptarArquivo(enc, env, asd,
                    chav, cert.getPublicKey());

            String status;
            if (res.tudoOk()) {
                // Mostrar primeiros 100 chars do conteúdo
                String preview = new String(res.conteudo,
                    java.nio.charset.StandardCharsets.UTF_8);
                if (preview.length() > 100) preview = preview.substring(0, 100) + "...";
                status = "DECRIPTOU + ASSINATURA OK | preview: " + preview.replaceAll("\\n", " ");
            } else if (res.decriptacaoOk && !res.assinaturaOk) {
                status = "decriptou mas assinatura INVALIDA (nao e o dono esperado)";
            } else {
                status = "nao conseguiu decriptar (nao e o dono do envelope)";
            }
            info(String.format("    %s -> %s", nomeUsuario, status));

        } catch (Exception e) {
            info("    " + nomeUsuario + " -> excecao: " + e.getMessage());
        }
    }

    static void mostrarDadosCert(String nome, X509Certificate cert) {
        if (cert == null) return;
        info("  [" + nome + "]");
        info("    Versao:     " + CertificadoUtils.extrairVersao(cert));
        info("    Serie:      " + CertificadoUtils.extrairSerie(cert));
        info("    Validade:   " + CertificadoUtils.extrairValidade(cert));
        info("    Assinatura: " + CertificadoUtils.extrairTipoAssinatura(cert));
        info("    Emissor:    " + CertificadoUtils.extrairEmissor(cert));
        info("    Subject:    " + CertificadoUtils.extrairSubject(cert));
        info("    Email:      " + CertificadoUtils.extrairEmail(cert));
        System.out.println();
    }

    // =========================================================================
    // HELPERS DE CARREGAMENTO
    // =========================================================================

    /**
     * Tenta carregar o certificado com várias extensões (.crt, .pem, sem extensão).
     */
    static X509Certificate carregarCertificado(String nomeBase) {
        for (String ext : EXTENSOES_CERT) {
            String caminho = KEYS_PATH + "/" + nomeBase + "-x509" + ext;
            try {
                X509Certificate cert = CryptoUtils.lerCertificado(caminho);
                info("  Certificado encontrado em: " + caminho);
                return cert;
            } catch (Exception ignored) {}
        }
        // Tentar sem sufixo -x509
        for (String ext : EXTENSOES_CERT) {
            String caminho = KEYS_PATH + "/" + nomeBase + ext;
            try {
                X509Certificate cert = CryptoUtils.lerCertificado(caminho);
                info("  Certificado encontrado em: " + caminho);
                return cert;
            } catch (Exception ignored) {}
        }
        info("  [AVISO] Certificado nao encontrado para: " + nomeBase);
        return null;
    }

    /**
     * Tenta carregar a chave privada. Retorna null se frase errada ou arquivo não encontrado.
     */
    static PrivateKey carregarChavePrivada(String nomeBase, String frase) {
        String caminho = KEYS_PATH + "/" + nomeBase + "-pkcs8-aes.key";
        try {
            return CryptoUtils.lerChavePrivada(caminho, frase);
        } catch (java.io.FileNotFoundException e) {
            info("  [AVISO] Chave nao encontrada: " + caminho);
            return null;
        } catch (Exception e) {
            // BadPaddingException = frase errada, ou formato inválido
            return null;
        }
    }

    // =========================================================================
    // SAÍDA FORMATADA
    // =========================================================================

    static void cabecalho(String titulo) {
        System.out.println();
        System.out.println("=".repeat(65));
        System.out.println("  " + titulo);
        System.out.println("=".repeat(65));
        System.out.println();
    }

    static void secao(String nome) {
        System.out.println();
        System.out.println("-".repeat(55));
        System.out.println("  " + nome);
        System.out.println("-".repeat(55));
    }

    static void testar(String desc, boolean resultado) {
        if (resultado) { totalOk++;    System.out.printf("  [OK]    %s%n", desc); }
        else           { totalFalha++; System.out.printf("  [FALHA] %s%n", desc); }
    }

    static void ok(String msg)    { totalOk++;    System.out.println("  [OK]    " + msg); }
    static void falha(String msg) { totalFalha++; System.out.println("  [FALHA] " + msg); }
    static void info(String msg)  { System.out.println(msg); }

    static void rodape() {
        System.out.println();
        System.out.println("=".repeat(65));
        if (totalFalha == 0)
            System.out.printf("  RESULTADO: %d passaram | TUDO OK!%n", totalOk);
        else
            System.out.printf("  RESULTADO: %d passaram | %d FALHARAM%n", totalOk, totalFalha);
        System.out.println("=".repeat(65));
        System.out.println();
    }
}
