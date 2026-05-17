// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.crypto;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;

/**
 * Utilitários gerais de criptografia.
 *
 * Responsabilidades:
 *  - Gerar chave AES-256 a partir de frase secreta (SHA1PRNG)
 *  - Ler e decriptar chave privada (arquivo binário AES/ECB/PKCS5)
 *  - Ler certificado digital X.509 (formato PEM)
 *  - Validar chave privada via assinatura digital
 *  - Cifrar/decifrar bytes com AES/ECB/PKCS5
 */
public class CryptoUtils {

    // -------------------------------------------------------------------------
    // GERAÇÃO DE CHAVE AES A PARTIR DE FRASE SECRETA
    // -------------------------------------------------------------------------

    /**
     * Gera uma chave AES-256 deterministicamente a partir de uma frase secreta.
     *
     * O professor exige SHA1PRNG. Se não setar explicitamente, a JVM pode usar
     * outro PRNG e a chave gerada será diferente — nada vai funcionar.
     *
     * @param fraseSecreta  texto fornecido pelo usuário
     * @return chave AES de 256 bits
     */
    public static SecretKey gerarChaveAES(String fraseSecreta) throws Exception {
        // Usar exatamente SHA1PRNG conforme exigido no trabalho
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(fraseSecreta.getBytes("UTF-8"));

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);

        return kg.generateKey();
    }

    /**
     * Gera uma chave AES-256 a partir de uma semente em bytes.
     * Usada para recuperar a chave simétrica que cifrou um arquivo
     * (a semente vem do envelope digital .env).
     *
     * @param semente  bytes aleatórios que foram usados na geração original
     * @return chave AES de 256 bits equivalente à original
     */
    public static SecretKey gerarChaveAESDeSemente(byte[] semente) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(semente);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);

        return kg.generateKey();
    }

    // -------------------------------------------------------------------------
    // LEITURA DA CHAVE PRIVADA
    // -------------------------------------------------------------------------

    /**
     * Lê e decripta a chave privada do usuário.
     *
     * O arquivo da chave privada no disco está:
     *   1. Em formato PKCS8, codificado em Base64 (PEM)
     *   2. Todo esse conteúdo PEM foi cifrado com AES/ECB/PKCS5
     *      usando uma chave AES derivada da frase secreta via SHA1PRNG
     *
     * Fluxo:
     *   arquivo binário cifrado
     *     → decriptar com AES (chave derivada da frase secreta)
     *     → obter bytes PEM ("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")
     *     → remover header/footer PEM
     *     → decodificar Base64 → array de bytes PKCS8
     *     → PKCS8EncodedKeySpec → KeyFactory → objeto PrivateKey
     *
     * @param caminho       caminho do arquivo .bin da chave privada
     * @param fraseSecreta  frase secreta do dono da chave
     * @return objeto PrivateKey pronto para uso
     * @throws Exception se o arquivo não existir, a frase secreta for errada
     *                   ou o formato for inválido
     */
    public static PrivateKey lerChavePrivada(String caminho, String fraseSecreta) throws Exception {
        // Passo 1: ler o arquivo binário cifrado do disco
        byte[] arquivoCifrado = Files.readAllBytes(Paths.get(caminho));

        // Passo 2: gerar a chave AES a partir da frase secreta (SHA1PRNG)
        SecretKey chaveAES = gerarChaveAES(fraseSecreta);

        // Passo 3: decriptar o arquivo com AES/ECB/PKCS5
        // Se a frase secreta estiver errada, aqui pode dar BadPaddingException
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, chaveAES);
        byte[] pemBytes = cipher.doFinal(arquivoCifrado);

        // Passo 4: converter bytes para String PEM e remover header/footer
        String pem = new String(pemBytes, "UTF-8");
        String base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", ""); // remove quebras de linha e espaços

        // Passo 5: decodificar Base64 → bytes PKCS8
        byte[] pkcs8Bytes = Base64.getDecoder().decode(base64);

        // Passo 6: criar objeto PrivateKey via PKCS8EncodedKeySpec + KeyFactory
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Lê e decripta a chave privada a partir de bytes já carregados (do banco).
     * Usado quando a chave vem do banco em vez de um arquivo no disco.
     */
    public static PrivateKey lerChavePrivadaDosBytes(byte[] bytesChaveCifrada,
                                                      String fraseSecreta) throws Exception {
        SecretKey chaveAES = gerarChaveAES(fraseSecreta);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, chaveAES);
        byte[] pemBytes = cipher.doFinal(bytesChaveCifrada);

        String pem = new String(pemBytes, "UTF-8");
        String base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");

        byte[] pkcs8Bytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // -------------------------------------------------------------------------
    // LEITURA DO CERTIFICADO DIGITAL
    // -------------------------------------------------------------------------

    /**
     * Lê um certificado digital X.509 em formato PEM do disco.
     *
     * O Java já entende o formato PEM diretamente via CertificateFactory,
     * sem precisar remover header/footer manualmente.
     *
     * @param caminho  caminho do arquivo .pem ou .crt
     * @return objeto X509Certificate com todos os dados do certificado
     */
    public static X509Certificate lerCertificado(String caminho) throws Exception {
        try (FileInputStream fis = new FileInputStream(caminho)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Converte um X509Certificate para String no formato PEM.
     * Usado para armazenar o certificado no banco de dados (tabela Chaveiro).
     *
     * @param cert  certificado a converter
     * @return String PEM do certificado
     */
    public static String certificadoParaPEM(X509Certificate cert) throws Exception {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'})
                              .encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----";
    }

    /**
     * Reconstrói um X509Certificate a partir de uma String PEM.
     * Usado para recuperar o certificado que foi salvo no banco.
     *
     * @param pem  String PEM do certificado
     * @return objeto X509Certificate
     */
    public static X509Certificate certificadoDePEM(String pem) throws Exception {
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

    // -------------------------------------------------------------------------
    // VALIDAÇÃO DA CHAVE PRIVADA
    // -------------------------------------------------------------------------

    /**
     * Valida se uma chave privada corresponde à chave pública do certificado.
     *
     * O processo:
     *   1. Gera um array de bytes aleatórios
     *   2. Assina com a chave privada
     *   3. Verifica a assinatura com a chave pública do certificado
     *   4. Se verificar → chave privada é válida e corresponde ao certificado
     *
     * @param chavePrivada  objeto PrivateKey a validar
     * @param chavePublica  chave pública extraída do certificado
     * @param tamanhoArray  tamanho do array aleatório (9216 no cadastro, 2048 no logView)
     * @return true se a chave privada for válida
     */
    public static boolean validarChavePrivada(PrivateKey chavePrivada,
                                              PublicKey chavePublica,
                                              int tamanhoArray) throws Exception {
        // Gerar dados aleatórios para assinar
        byte[] dados = new byte[tamanhoArray];
        new SecureRandom().nextBytes(dados);

        // Assinar com a chave privada
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(chavePrivada);
        sig.update(dados);
        byte[] assinatura = sig.sign();

        // Verificar com a chave pública
        sig.initVerify(chavePublica);
        sig.update(dados);
        return sig.verify(assinatura);
    }

    // -------------------------------------------------------------------------
    // CIFRAR / DECIFRAR COM AES
    // -------------------------------------------------------------------------

    /**
     * Cifra dados com AES/ECB/PKCS5Padding.
     *
     * @param dados  bytes a cifrar
     * @param chave  chave AES
     * @return bytes cifrados
     */
    public static byte[] cifrarAES(byte[] dados, SecretKey chave) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, chave);
        return cipher.doFinal(dados);
    }

    /**
     * Decifra dados com AES/ECB/PKCS5Padding.
     *
     * @param dados  bytes cifrados
     * @param chave  chave AES
     * @return bytes em texto plano
     */
    public static byte[] decifrarAES(byte[] dados, SecretKey chave) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, chave);
        return cipher.doFinal(dados);
    }
}
