package br.pucrio.logview;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.sql.*;
import java.util.Base64;

/**
 * LogView — Programa de Auditoria do Cofre Digital.
 *
 * Programa SEPARADO do Cofre Digital, conforme exigido pelo enunciado.
 * Apenas o administrador pode executar.
 *
 * Uso:
 *   java -cp ".;lib/sqlite-jdbc-3.42.0.0.jar;lib/bcprov-jdk18on-1.84.jar" ^
 *        br.pucrio.logview.Main <caminho_da_chave_privada>
 *
 * Exemplo:
 *   java -cp ".;lib/sqlite-jdbc-3.42.0.0.jar;lib/bcprov-jdk18on-1.84.jar" ^
 *        br.pucrio.logview.Main C:\Keys\admin-pkcs8-aes.key
 *
 * Fluxo:
 *   1. Recebe caminho da chave privada na linha de comando
 *   2. Pede frase secreta via teclado sem eco
 *   3. Decripta a chave privada (AES + SHA1PRNG)
 *   4. Valida a chave privada (assina 2048 bytes e verifica com cert do banco)
 *   5. Se inválida: encerra
 *   6. Se válida: exibe todos os registros em ordem cronológica
 *
 * ATENÇÃO: O banco meubanco.db deve estar acessível.
 * Ajuste DB_PATH para o caminho correto.
 */
public class Main {

    // ── Ajuste este caminho para onde está o banco do CofreDigital ───────────
    private static final String DB_PATH =
        "C:/Users/Gabriel/Documents/vscode/Trab3/CofreDigital/meubanco.db";

    public static void main(String[] args) {
        // ── 1. Verificar argumento da linha de comando ────────────────────────
        if (args.length < 1) {
            System.err.println("Uso: logview <caminho_da_chave_privada>");
            System.err.println("Exemplo: logview C:\\Keys\\admin-pkcs8-aes.key");
            System.exit(1);
        }

        String caminhoChave = args[0];

        // Verificar se o arquivo existe
        if (!new File(caminhoChave).exists()) {
            System.err.println("Erro: arquivo de chave privada não encontrado: " + caminhoChave);
            System.exit(1);
        }

        // ── 2. Pedir frase secreta sem eco ────────────────────────────────────
        String fraseSecreta = lerFraseSemEco("Frase secreta da chave privada do administrador: ");
        if (fraseSecreta == null || fraseSecreta.trim().isEmpty()) {
            System.err.println("Erro: frase secreta não pode ser vazia.");
            System.exit(1);
        }

        // ── 3. Decriptar a chave privada ──────────────────────────────────────
        PrivateKey chavePrivada;
        try {
            chavePrivada = lerChavePrivada(caminhoChave, fraseSecreta);
        } catch (Exception e) {
            System.err.println("Erro: frase secreta inválida ou arquivo corrompido.");
            System.exit(1);
            return;
        }

        // ── 4. Buscar certificado do admin no banco e validar chave ───────────
        try (Connection conn = conectarBanco()) {

            // Buscar certificado PEM do admin (GID = 1)
            String certPEM = buscarCertAdmin(conn);
            if (certPEM == null) {
                System.err.println("Erro: administrador não encontrado no banco.");
                System.exit(1);
            }

            // Reconstruir certificado X.509
            X509Certificate cert = certificadoDePEM(certPEM);

            // Validar chave privada: assinar 2048 bytes e verificar
            boolean valida = validarChavePrivada(chavePrivada, cert.getPublicKey(), 2048);
            if (!valida) {
                System.err.println("Erro: validação da chave privada negativa. Acesso negado.");
                System.exit(1);
            }

            System.out.println("Autenticação bem-sucedida.\n");

            // ── 5. Exibir registros em ordem cronológica ──────────────────────
            exibirLogs(conn);

        } catch (Exception e) {
            System.err.println("Erro ao acessar banco de dados: " + e.getMessage());
            System.exit(1);
        }
    }

    // =========================================================================
    // LEITURA DA FRASE SECRETA SEM ECO
    // =========================================================================

    /**
     * Lê a frase secreta do terminal sem exibir os caracteres digitados.
     * Usa Console.readPassword() conforme exigido pelo enunciado.
     */
    private static String lerFraseSemEco(String prompt) {
        Console console = System.console();
        if (console != null) {
            // Terminal real — sem eco (seguro)
            char[] chars = console.readPassword(prompt);
            if (chars == null) return null;
            return new String(chars);
        } else {
            // IDE sem console — lê com eco (só para desenvolvimento)
            System.err.println("[AVISO] Console não disponível — entrada visível.");
            System.out.print(prompt);
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                return br.readLine();
            } catch (IOException e) {
                return null;
            }
        }
    }

    // =========================================================================
    // DECRIPTAÇÃO DA CHAVE PRIVADA
    // =========================================================================

    /**
     * Lê e decripta a chave privada do arquivo.
     * Mesmo processo do CryptoUtils do CofreDigital.
     */
    private static PrivateKey lerChavePrivada(String caminho,
                                               String fraseSecreta) throws Exception {
        // Ler arquivo cifrado
        byte[] cifrado = Files.readAllBytes(Paths.get(caminho));

        // Gerar chave AES via SHA1PRNG
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(fraseSecreta.getBytes("UTF-8"));
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);
        SecretKey chaveAES = kg.generateKey();

        // Decriptar AES/ECB/PKCS5
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, chaveAES);
        byte[] pemBytes = cipher.doFinal(cifrado);

        // Remover header/footer PEM e decodificar Base64
        String pem = new String(pemBytes, "UTF-8");
        String base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");

        byte[] pkcs8Bytes = Base64.getDecoder().decode(base64);

        // Reconstruir PrivateKey
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // =========================================================================
    // VALIDAÇÃO DA CHAVE PRIVADA
    // =========================================================================

    /**
     * Valida a chave privada assinando 2048 bytes aleatórios e verificando
     * com a chave pública do certificado.
     */
    private static boolean validarChavePrivada(PrivateKey chavePrivada,
                                                PublicKey chavePublica,
                                                int tamanho) throws Exception {
        byte[] dados = new byte[tamanho];
        new SecureRandom().nextBytes(dados);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(chavePrivada);
        sig.update(dados);
        byte[] assinatura = sig.sign();

        sig.initVerify(chavePublica);
        sig.update(dados);
        return sig.verify(assinatura);
    }

    // =========================================================================
    // BANCO DE DADOS
    // =========================================================================

    private static Connection conectarBanco() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
    }

    /**
     * Busca o certificado PEM do administrador (GID = 1) no banco.
     */
    private static String buscarCertAdmin(Connection conn) throws SQLException {
        String sql =
            "SELECT c.cert_pem FROM Chaveiro c " +
            "JOIN Usuarios u ON c.KID = u.KID " +
            "WHERE u.GID = 1 LIMIT 1";

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) return rs.getString("cert_pem");
            return null;
        }
    }

    /**
     * Reconstrói X509Certificate a partir de String PEM.
     */
    private static X509Certificate certificadoDePEM(String pem) throws Exception {
        byte[] bytes = Base64.getMimeDecoder().decode(
            pem.replace("-----BEGIN CERTIFICATE-----", "")
               .replace("-----END CERTIFICATE-----", "")
               .replaceAll("\\s+", "")
        );
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(bytes)
        );
    }

    // =========================================================================
    // EXIBIR LOGS
    // =========================================================================

    /**
     * Exibe todos os registros em ordem cronológica.
     *
     * JOIN entre Registros e Mensagens para substituir os placeholders:
     *   <login_name> → login do usuário relacionado ao registro
     *   <arq_name>   → nome do arquivo (quando houver)
     *
     * Conforme enunciado: exibe data, hora e código da mensagem.
     */
    private static void exibirLogs(Connection conn) throws SQLException {
        String sql =
            "SELECT r.RID, r.data_hora, r.MID, m.texto_mensagem, " +
            "       u.login_name, r.arq_name " +
            "FROM Registros r " +
            "JOIN Mensagens m ON r.MID = m.MID " +
            "LEFT JOIN Usuarios u ON r.UID = u.UID " +
            "ORDER BY r.data_hora ASC, r.RID ASC";

        System.out.println("=".repeat(80));
        System.out.println("  REGISTROS DO COFRE DIGITAL — ORDEM CRONOLÓGICA");
        System.out.println("=".repeat(80));
        System.out.printf("%-25s  %-6s  %s%n", "DATA/HORA", "CÓD", "MENSAGEM");
        System.out.println("-".repeat(80));

        int total = 0;
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                String dataHora  = rs.getString("data_hora");
                int    mid       = rs.getInt("MID");
                String texto     = rs.getString("texto_mensagem");
                String login     = rs.getString("login_name");
                String arqName   = rs.getString("arq_name");

                // Substituir placeholders da mensagem
                if (login   != null) texto = texto.replace("<login_name>", login);
                if (arqName != null) texto = texto.replace("<arq_name>",   arqName);

                // Remover placeholders não substituídos (ex: campos nulos)
                texto = texto.replace("<login_name>", "-")
                             .replace("<arq_name>",   "-");

                System.out.printf("%-25s  %-6d  %s%n", dataHora, mid, texto);
                total++;
            }
        }

        System.out.println("-".repeat(80));
        System.out.println("Total de registros: " + total);
        System.out.println("=".repeat(80));
    }
}
