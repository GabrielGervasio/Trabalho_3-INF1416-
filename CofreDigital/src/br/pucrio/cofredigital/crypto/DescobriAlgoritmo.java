package br.pucrio.cofredigital.crypto;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.Signature;
import java.nio.file.*;

/**
 * Descobre qual algoritmo de assinatura o professor usou nos arquivos .asd
 *
 * Compilar e rodar igual ao TesteArquivosReais.
 */
public class DescobriAlgoritmo {

    static final String KEYS_PATH  = "C:/Users/Gabriel/Documents/vscode/Trab3/CofreDigital/src/br/pucrio/cofredigital/Keys";
    static final String FILES_PATH = "C:/Users/Gabriel/Documents/vscode/Trab3/CofreDigital/src/br/pucrio/cofredigital/Files";

    // Todos os algoritmos de assinatura RSA que o Java suporta
    static final String[] ALGORITMOS = {
        "SHA1withRSA",
        "SHA256withRSA",
        "SHA384withRSA",
        "SHA512withRSA",
        "MD5withRSA",
        "MD2withRSA",
        "NONEwithRSA",
        "SHA256withRSAandMGF1",
        "SHA1withRSA/PSS",
        "SHA256withRSA/PSS",
    };

    public static void main(String[] args) throws Exception {
        System.out.println("=== DESCOBRINDO ALGORITMO DE ASSINATURA ===\n");

        // Carregar admin
        X509Certificate certAdmin = CryptoUtils.lerCertificado(KEYS_PATH + "/admin-x509.crt");
        PrivateKey chavAdmin = CryptoUtils.lerChavePrivada(KEYS_PATH + "/admin-pkcs8-aes.key", "admin");
        PublicKey chavePublicaAdmin = certAdmin.getPublicKey();

        // Carregar index
        byte[] envelopeCifrado = Files.readAllBytes(Paths.get(FILES_PATH + "/index.env"));
        byte[] semente = EnvelopeDigital.abrirEnvelope(envelopeCifrado, chavAdmin);
        javax.crypto.SecretKey chaveAES = CryptoUtils.gerarChaveAESDeSemente(semente);
        byte[] conteudoCifrado = Files.readAllBytes(Paths.get(FILES_PATH + "/index.enc"));
        byte[] textoplano = CryptoUtils.decifrarAES(conteudoCifrado, chaveAES);
        byte[] assinatura = Files.readAllBytes(Paths.get(FILES_PATH + "/index.asd"));

        System.out.println("Conteudo do index decriptado:");
        System.out.println(new String(textoplano));
        System.out.println("Tamanho assinatura .asd: " + assinatura.length + " bytes\n");

        System.out.println("Testando algoritmos com chave publica do ADMIN:");
        System.out.println("-".repeat(50));
        for (String alg : ALGORITMOS) {
            try {
                Signature sig = Signature.getInstance(alg);
                sig.initVerify(chavePublicaAdmin);
                sig.update(textoplano);
                boolean ok = sig.verify(assinatura);
                System.out.printf("  %-30s -> %s%n", alg, ok ? "✅ FUNCIONOU!" : "❌ nao");
            } catch (Exception e) {
                System.out.printf("  %-30s -> erro: %s%n", alg, e.getMessage());
            }
        }

        // Tentar tambem com chave publica do user01 e user02
        // (talvez o índice seja assinado por outro usuário)
        X509Certificate certUser01 = CryptoUtils.lerCertificado(KEYS_PATH + "/user01-x509.crt");
        X509Certificate certUser02 = CryptoUtils.lerCertificado(KEYS_PATH + "/user02-x509.crt");

        System.out.println("\nTestando SHA256withRSA com chave publica do USER01:");
        testarAlgoritmo("SHA256withRSA", textoplano, assinatura, certUser01.getPublicKey());

        System.out.println("Testando SHA256withRSA com chave publica do USER02:");
        testarAlgoritmo("SHA256withRSA", textoplano, assinatura, certUser02.getPublicKey());

        System.out.println("\nTestando SHA1withRSA com chave publica do USER01:");
        testarAlgoritmo("SHA1withRSA", textoplano, assinatura, certUser01.getPublicKey());

        System.out.println("Testando SHA1withRSA com chave publica do USER02:");
        testarAlgoritmo("SHA1withRSA", textoplano, assinatura, certUser02.getPublicKey());

        // Tambem testar os arquivos dos usuarios com seus proprios certificados
        System.out.println("\n=== TESTANDO ARQUIVOS XXYYZZ COM SEUS DONOS ===");
        testarArquivoUsuario("XXYYZZ00", chavAdmin, certAdmin);
        testarArquivoUsuario("XXYYZZ11",
            CryptoUtils.lerChavePrivada(KEYS_PATH + "/user01-pkcs8-aes.key", "user01"), certUser01);
        testarArquivoUsuario("XXYYZZ22",
            CryptoUtils.lerChavePrivada(KEYS_PATH + "/user02-pkcs8-aes.key", "user02"), certUser02);
    }

    static void testarArquivoUsuario(String nome, PrivateKey chav, X509Certificate cert) throws Exception {
        System.out.println("\nArquivo: " + nome);
        byte[] env = Files.readAllBytes(Paths.get(FILES_PATH + "/" + nome + ".env"));
        byte[] semente = EnvelopeDigital.abrirEnvelope(env, chav);
        javax.crypto.SecretKey chaveAES = CryptoUtils.gerarChaveAESDeSemente(semente);
        byte[] enc = Files.readAllBytes(Paths.get(FILES_PATH + "/" + nome + ".enc"));
        byte[] plain = CryptoUtils.decifrarAES(enc, chaveAES);
        byte[] asd = Files.readAllBytes(Paths.get(FILES_PATH + "/" + nome + ".asd"));

        System.out.println("  Primeiros 50 bytes decriptados: " +
            new String(plain, 0, Math.min(50, plain.length)));

        for (String alg : new String[]{"SHA1withRSA", "SHA256withRSA", "MD5withRSA"}) {
            testarAlgoritmo(alg, plain, asd, cert.getPublicKey());
        }
    }

    static void testarAlgoritmo(String alg, byte[] dados, byte[] assinatura,
                                  java.security.PublicKey pub) {
        try {
            Signature sig = Signature.getInstance(alg);
            sig.initVerify(pub);
            sig.update(dados);
            boolean ok = sig.verify(assinatura);
            System.out.printf("  %-30s -> %s%n", alg, ok ? "✅ FUNCIONOU!" : "❌ nao");
        } catch (Exception e) {
            System.out.printf("  %-30s -> erro: %s%n", alg, e.getMessage());
        }
    }
}
