package br.pucrio.cofredigital.crypto;

import br.pucrio.cofredigital.totp.Base32;
import br.pucrio.cofredigital.totp.TOTP;
import br.pucrio.cofredigital.totp.TotpUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Date;

/**
 * Teste em terminal para todos os módulos de criptografia do Cofre Digital.
 *
 * Não precisa de: JUnit, banco de dados, arquivos externos, keytool, openssl.
 * Gera o certificado X.509 de teste construindo o ASN.1/DER manualmente.
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
 *       src/br/pucrio/cofredigital/crypto/TesteCripto.java
 *
 *   Linux/Mac: mesmo comando com \ e : no -cp
 *
 * Executar:
 *   Windows: java -cp ".;lib/bcprov-jdk18on-1.84.jar" br.pucrio.cofredigital.crypto.TesteCripto
 *   Linux:   java -cp ".:lib/bcprov-jdk18on-1.84.jar" br.pucrio.cofredigital.crypto.TesteCripto
 */
public class TesteCripto {

    private static int totalTestes = 0;
    private static int totalOk     = 0;
    private static int totalFalha  = 0;

    // Par RSA gerado uma vez, reutilizado em todos os testes
    private static KeyPair parRSA;

    // Certificado autoassinado construído em memória (sem keytool/openssl)
    private static X509Certificate certEmMemoria;

    // ==========================================================================
    // MAIN
    // ==========================================================================
    public static void main(String[] args) {
        cabecalho("COFRE DIGITAL — TESTE DE MODULOS DE CRIPTOGRAFIA");

        try {
            parRSA = gerarParRSA();
            certEmMemoria = gerarCertificadoAutoAssinado(
                parRSA,
                "CN=Teste Usuario, EMAILADDRESS=teste@pucrio.br, O=PUC-Rio",
                "CN=Teste Usuario, EMAILADDRESS=teste@pucrio.br, O=PUC-Rio"
            );
            info("  Certificado gerado com sucesso.");
            info("  Subject: " + certEmMemoria.getSubjectX500Principal().getName());
        } catch (Exception e) {
            erro("Falha ao preparar par RSA / certificado: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        testarBase32();
        testarBcryptUtils();
        testarCryptoUtilsAES();
        testarCryptoUtilsRSA();
        testarCertificadoUtils();
        testarTOTP();
        testarTotpUtils();
        testarEnvelopeDigital();

        rodape();
    }

    // ==========================================================================
    // 1. BASE32
    // ==========================================================================
    static void testarBase32() {
        secao("1. Base32");

        Base32 b32 = new Base32(Base32.Alphabet.BASE32, false, false);

        // Round-trip bytes conhecidos
        byte[] original = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        String encoded  = b32.toString(original);
        byte[] decoded  = b32.fromString(encoded);
        testar("Round-trip bytes -> BASE32 -> bytes", Arrays.equals(original, decoded));

        // 20 bytes aleatórios (tamanho da chave TOTP)
        byte[] vinte = new byte[20];
        new SecureRandom().nextBytes(vinte);
        testar("Round-trip 20 bytes aleatorios (chave TOTP)",
               Arrays.equals(vinte, b32.fromString(b32.toString(vinte))));

        // Vetor do RFC 4648: "foobar" -> MZXW6YTBOI
        String encFoobar = b32.toString("foobar".getBytes());
        info("  'foobar' codificado: " + encFoobar + "  (esperado: MZXW6YTBOI)");
        testar("Codificacao de 'foobar' bate com RFC 4648",
               encFoobar.equalsIgnoreCase("MZXW6YTBOI"));

        // Entrada inválida retorna null
        testar("Decodificacao de '????' retorna null",
               b32.fromString("????") == null);
    }

    // ==========================================================================
    // 2. BCRYPT UTILS
    // ==========================================================================
    static void testarBcryptUtils() {
        secao("2. BcryptUtils");

        // senhaValida
        testar("'12345678' (8 dig) e valida",    BcryptUtils.senhaValida("12345678"));
        testar("'123456789' (9 dig) e valida",   BcryptUtils.senhaValida("123456789"));
        testar("'1234567890' (10 dig) e valida", BcryptUtils.senhaValida("1234567890"));
        testar("'1234567' (7 dig) e invalida",   !BcryptUtils.senhaValida("1234567"));
        testar("'12345678901' (11 dig) invalida", !BcryptUtils.senhaValida("12345678901"));
        testar("'11111111' (repeticao) invalida", !BcryptUtils.senhaValida("11111111"));
        testar("'abcd1234' (letras) invalida",    !BcryptUtils.senhaValida("abcd1234"));
        testar("null e invalida",                 !BcryptUtils.senhaValida(null));

        // gerarHash + verificar
        String senha = "87654321";
        String hash  = BcryptUtils.gerarHash(senha);
        info("  Hash gerado: " + hash);
        testar("Hash comeca com $2y$08$",   hash.startsWith("$2y$08$"));
        testar("Hash tem 60 caracteres",     hash.length() == 60);
        testar("verificar() true p/ senha correta",  BcryptUtils.verificar(hash, senha));
        testar("verificar() false p/ senha errada",  !BcryptUtils.verificar(hash, "00000000"));
        testar("Salt aleatorio: dois hashes diferentes",
               !BcryptUtils.gerarHash(senha).equals(BcryptUtils.gerarHash(senha)));
        testar("verificar() false p/ hash malformado",
               !BcryptUtils.verificar("hash_invalido", senha));
    }

    // ==========================================================================
    // 3. CRYPTO UTILS — AES
    // ==========================================================================
    static void testarCryptoUtilsAES() {
        secao("3. CryptoUtils — AES");
        try {
            // Determinismo do SHA1PRNG
            SecretKey k1 = CryptoUtils.gerarChaveAES("minha frase");
            SecretKey k2 = CryptoUtils.gerarChaveAES("minha frase");
            SecretKey k3 = CryptoUtils.gerarChaveAES("outra frase");
            testar("gerarChaveAES e deterministico",
                   Arrays.equals(k1.getEncoded(), k2.getEncoded()));
            testar("Frases diferentes -> chaves diferentes",
                   !Arrays.equals(k1.getEncoded(), k3.getEncoded()));
            testar("Chave AES tem 256 bits (32 bytes)",
                   k1.getEncoded().length == 32);

            // Round-trip cifrar/decifrar
            byte[] dados     = "mensagem supersecreta 1234!".getBytes("UTF-8");
            byte[] cifrado   = CryptoUtils.cifrarAES(dados, k1);
            byte[] decifrado = CryptoUtils.decifrarAES(cifrado, k1);
            testar("Round-trip cifrarAES / decifrarAES",
                   Arrays.equals(dados, decifrado));
            testar("Bytes cifrados sao diferentes do plaintext",
                   !Arrays.equals(dados, cifrado));

            // Chave errada lança exceção
            boolean lanouExcecao = false;
            try { CryptoUtils.decifrarAES(cifrado, k3); }
            catch (Exception ex) { lanouExcecao = true; }
            testar("Decifrar com chave errada lanca excecao", lanouExcecao);

            // gerarChaveAESDeSemente — determinístico
            byte[] semente = new byte[20];
            new SecureRandom().nextBytes(semente);
            SecretKey ks1 = CryptoUtils.gerarChaveAESDeSemente(semente);
            SecretKey ks2 = CryptoUtils.gerarChaveAESDeSemente(semente);
            testar("gerarChaveAESDeSemente e deterministico",
                   Arrays.equals(ks1.getEncoded(), ks2.getEncoded()));

        } catch (Exception e) {
            falha("Excecao inesperada em testarCryptoUtilsAES: " + e.getMessage());
        }
    }

    // ==========================================================================
    // 4. CRYPTO UTILS — RSA
    // ==========================================================================
    static void testarCryptoUtilsRSA() {
        secao("4. CryptoUtils — RSA (validacao de chave privada)");
        try {
            PrivateKey priv = parRSA.getPrivate();
            PublicKey  pub  = parRSA.getPublic();

            testar("validarChavePrivada com 9216 bytes (cadastro) retorna true",
                   CryptoUtils.validarChavePrivada(priv, pub, 9216));
            testar("validarChavePrivada com 2048 bytes (logView) retorna true",
                   CryptoUtils.validarChavePrivada(priv, pub, 2048));

            KeyPair outroPar = gerarParRSA();
            testar("validarChavePrivada com chave publica errada retorna false",
                   !CryptoUtils.validarChavePrivada(priv, outroPar.getPublic(), 9216));

            // PEM round-trip do certificado
            String pem = CryptoUtils.certificadoParaPEM(certEmMemoria);
            X509Certificate reconstruido = CryptoUtils.certificadoDePEM(pem);
            testar("certificadoParaPEM / certificadoDePEM round-trip",
                   Arrays.equals(certEmMemoria.getEncoded(), reconstruido.getEncoded()));
            testar("PEM comeca com -----BEGIN CERTIFICATE-----",
                   pem.startsWith("-----BEGIN CERTIFICATE-----"));

            // Chave privada reconstruída via PKCS8
            byte[] pkcs8 = priv.getEncoded();
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey reconstruida = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            testar("Chave privada reconstruida via PKCS8 e valida",
                   CryptoUtils.validarChavePrivada(reconstruida, pub, 512));

        } catch (Exception e) {
            falha("Excecao inesperada em testarCryptoUtilsRSA: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ==========================================================================
    // 5. CERTIFICADO UTILS
    // ==========================================================================
    static void testarCertificadoUtils() {
        secao("5. CertificadoUtils");

        String email = CertificadoUtils.extrairEmail(certEmMemoria);
        String nome  = CertificadoUtils.extrairNome(certEmMemoria);

        info("  Email extraido:  " + email);
        info("  Nome extraido:   " + nome);
        info("  Subject completo: " +
             certEmMemoria.getSubjectX500Principal().getName());

        testar("extrairEmail nao e null",          email != null);
        testar("extrairEmail contem '@'",
               email != null && email.contains("@"));
        testar("extrairEmail e 'teste@pucrio.br'",
               "teste@pucrio.br".equals(email));
        testar("extrairNome e 'Teste Usuario'",
               nome != null && nome.equalsIgnoreCase("Teste Usuario"));

        String versao     = CertificadoUtils.extrairVersao(certEmMemoria);
        String serie      = CertificadoUtils.extrairSerie(certEmMemoria);
        String validade   = CertificadoUtils.extrairValidade(certEmMemoria);
        String assinatura = CertificadoUtils.extrairTipoAssinatura(certEmMemoria);
        String emissor    = CertificadoUtils.extrairEmissor(certEmMemoria);
        String subject    = CertificadoUtils.extrairSubject(certEmMemoria);

        info("  Versao:     " + versao);
        info("  Serie:      " + serie);
        info("  Validade:   " + validade);
        info("  Assinatura: " + assinatura);
        info("  Emissor:    " + emissor);

        testar("extrairVersao retorna '3'",      "3".equals(versao));
        testar("extrairSerie nao e vazia",        serie != null && !serie.isEmpty());
        testar("extrairValidade comeca com 'De '",
               validade != null && validade.startsWith("De "));
        testar("extrairTipoAssinatura nao e null", assinatura != null);
        testar("extrairEmissor nao e null",        emissor != null);
        testar("extrairSubject nao e null",        subject != null);
    }

    // ==========================================================================
    // 6. TOTP
    // ==========================================================================
    static void testarTOTP() {
        secao("6. TOTP");
        try {
            byte[] chave = new byte[20];
            new SecureRandom().nextBytes(chave);
            Base32 b32 = new Base32(Base32.Alphabet.BASE32, false, false);
            String base32 = b32.toString(chave);

            TOTP totp = new TOTP(base32, 30);
            String codigo = totp.generateCode();
            info("  Codigo TOTP gerado: " + codigo);

            testar("Codigo tem 6 caracteres",  codigo != null && codigo.length() == 6);
            testar("Codigo e numerico",         codigo != null && codigo.matches("[0-9]{6}"));
            testar("validateCode aceita codigo recem-gerado", totp.validateCode(codigo));
            testar("validateCode rejeita null",          !totp.validateCode(null));
            testar("validateCode rejeita 5 digitos",     !totp.validateCode("12345"));
            testar("validateCode rejeita string vazia",  !totp.validateCode(""));

            // Dois objetos com mesma chave -> mesmo código
            TOTP totp2 = new TOTP(base32, 30);
            testar("Dois objetos com mesma chave geram mesmo codigo",
                   totp.generateCode().equals(totp2.generateCode()));

            // Chave inválida lança exceção
            boolean lanouExcecao = false;
            try { new TOTP("????INVALIDO????", 30); }
            catch (Exception ex) { lanouExcecao = true; }
            testar("Construtor TOTP com chave invalida lanca excecao", lanouExcecao);

        } catch (Exception e) {
            falha("Excecao inesperada em testarTOTP: " + e.getMessage());
        }
    }

    // ==========================================================================
    // 7. TOTP UTILS
    // ==========================================================================
    static void testarTotpUtils() {
        secao("7. TotpUtils");
        try {
            byte[] chave = TotpUtils.gerarChaveTotp();
            testar("gerarChaveTotp retorna 20 bytes",
                   chave != null && chave.length == 20);
            testar("Cada chamada gera chave diferente",
                   !Arrays.equals(chave, TotpUtils.gerarChaveTotp()));

            String base32 = TotpUtils.chaveParaBase32(chave);
            testar("chaveParaBase32 retorna string nao-vazia",
                   base32 != null && !base32.isEmpty());
            info("  Chave BASE32: " + base32);

            // Cifrar / decifrar round-trip
            String senha = "12345678";
            String enc   = TotpUtils.cifrarChaveTotp(chave, senha);
            testar("cifrarChaveTotp retorna string nao-vazia",
                   enc != null && !enc.isEmpty());
            testar("decifrarChaveTotp recupera chave original",
                   Arrays.equals(chave, TotpUtils.decifrarChaveTotp(enc, senha)));

            // Senha errada lança exceção
            boolean lanouExcecao = false;
            try { TotpUtils.decifrarChaveTotp(enc, "87654321"); }
            catch (Exception ex) { lanouExcecao = true; }
            testar("decifrarChaveTotp com senha errada lanca excecao", lanouExcecao);

            // criarTOTP funcional
            TOTP totpObj = TotpUtils.criarTOTP(enc, senha);
            String codigo = totpObj.generateCode();
            testar("criarTOTP retorna TOTP funcional (6 digitos)",
                   codigo != null && codigo.length() == 6);
            testar("Codigo do criarTOTP e valido",
                   totpObj.validateCode(codigo));

            // URI QR Code
            String uri = TotpUtils.montarUriQRCode("admin@puc.br", base32);
            testar("URI comeca com otpauth://totp/",  uri.startsWith("otpauth://totp/"));
            testar("URI contem o e-mail",             uri.contains("admin@puc.br"));
            testar("URI contem a chave BASE32",       uri.contains(base32));
            info("  URI QR Code: " + uri);

        } catch (Exception e) {
            falha("Excecao inesperada em testarTotpUtils: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ==========================================================================
    // 8. ENVELOPE DIGITAL
    // ==========================================================================
    static void testarEnvelopeDigital() {
        secao("8. EnvelopeDigital");
        try {
            PrivateKey priv = parRSA.getPrivate();
            PublicKey  pub  = parRSA.getPublic();

            // Semente
            byte[] semente = EnvelopeDigital.gerarSemente();
            testar("gerarSemente retorna 20 bytes",
                   semente != null && semente.length == 20);
            testar("Sementes sao diferentes a cada chamada",
                   !Arrays.equals(semente, EnvelopeDigital.gerarSemente()));

            // Envelope round-trip
            byte[] envelope      = EnvelopeDigital.criarEnvelope(semente, pub);
            byte[] sementeAberta = EnvelopeDigital.abrirEnvelope(envelope, priv);
            testar("criarEnvelope retorna bytes nao-nulos",
                   envelope != null && envelope.length > 0);
            testar("abrirEnvelope recupera a semente original",
                   Arrays.equals(semente, sementeAberta));

            // Chave errada lança exceção
            KeyPair outroPar = gerarParRSA();
            boolean lanouExcecao = false;
            try { EnvelopeDigital.abrirEnvelope(envelope, outroPar.getPrivate()); }
            catch (Exception ex) { lanouExcecao = true; }
            testar("abrirEnvelope com chave errada lanca excecao", lanouExcecao);

            // Assinatura digital
            byte[] conteudo   = "conteudo secreto do arquivo".getBytes("UTF-8");
            byte[] assinatura = assinarEmMemoria(conteudo, priv);
            testar("verificarAssinatura retorna true p/ assinatura valida",
                   EnvelopeDigital.verificarAssinatura(conteudo, assinatura, pub));
            testar("verificarAssinatura retorna false p/ conteudo alterado",
                   !EnvelopeDigital.verificarAssinatura(
                       "conteudo modificado".getBytes("UTF-8"), assinatura, pub));

            // Fluxo completo: enc + env + asd em arquivos temporários
            byte[] sementeFluxo = EnvelopeDigital.gerarSemente();
            SecretKey chaveAES  = CryptoUtils.gerarChaveAESDeSemente(sementeFluxo);
            byte[] plaintext    = "arquivo secreto completo ABC 123".getBytes("UTF-8");
            byte[] enc          = CryptoUtils.cifrarAES(plaintext, chaveAES);
            byte[] env          = EnvelopeDigital.criarEnvelope(sementeFluxo, pub);
            byte[] asd          = assinarEmMemoria(plaintext, priv);

            java.nio.file.Path tmpEnc = java.nio.file.Files.createTempFile("cofre", ".enc");
            java.nio.file.Path tmpEnv = java.nio.file.Files.createTempFile("cofre", ".env");
            java.nio.file.Path tmpAsd = java.nio.file.Files.createTempFile("cofre", ".asd");
            try {
                java.nio.file.Files.write(tmpEnc, enc);
                java.nio.file.Files.write(tmpEnv, env);
                java.nio.file.Files.write(tmpAsd, asd);

                EnvelopeDigital.ResultadoDecriptacao res =
                    EnvelopeDigital.decriptarArquivo(
                        tmpEnc.toString(), tmpEnv.toString(), tmpAsd.toString(),
                        priv, pub);

                testar("Fluxo completo: decriptacaoOk == true",  res.decriptacaoOk);
                testar("Fluxo completo: assinaturaOk == true",   res.assinaturaOk);
                testar("Fluxo completo: tudoOk() == true",       res.tudoOk());
                testar("Fluxo completo: conteudo recuperado bate com original",
                       Arrays.equals(plaintext, res.conteudo));

                // .asd corrompido
                byte[] corrompido = new byte[asd.length];
                new SecureRandom().nextBytes(corrompido);
                java.nio.file.Files.write(tmpAsd, corrompido);

                EnvelopeDigital.ResultadoDecriptacao resCorr =
                    EnvelopeDigital.decriptarArquivo(
                        tmpEnc.toString(), tmpEnv.toString(), tmpAsd.toString(),
                        priv, pub);
                testar("ASD corrompido: assinaturaOk == false", !resCorr.assinaturaOk);
                testar("ASD corrompido: erroAssinatura == true", resCorr.erroAssinatura);

            } finally {
                java.nio.file.Files.deleteIfExists(tmpEnc);
                java.nio.file.Files.deleteIfExists(tmpEnv);
                java.nio.file.Files.deleteIfExists(tmpAsd);
            }

        } catch (Exception e) {
            falha("Excecao inesperada em testarEnvelopeDigital: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ==========================================================================
    // HELPERS — geração de chaves e certificado em memória pura (sem keytool)
    // ==========================================================================

    static KeyPair gerarParRSA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /**
     * Gera certificado X.509 autoassinado construindo o ASN.1/DER manualmente.
     *
     * Não usa keytool, openssl, bcpkix nem APIs sun.* internas.
     * Usa apenas JCE padrão (KeyPairGenerator, Signature) + codificação DER manual.
     *
     * Estrutura DER de um X.509v1 simplificado:
     *   SEQUENCE {
     *     SEQUENCE {           <- TBSCertificate
     *       [0] INTEGER 2      <- version v3
     *       INTEGER serial
     *       SEQUENCE algId     <- SHA256withRSA
     *       SEQUENCE issuer    <- DN do emissor
     *       SEQUENCE validity  <- notBefore + notAfter
     *       SEQUENCE subject   <- DN do sujeito
     *       SEQUENCE spki      <- SubjectPublicKeyInfo (já em DER pela JCA)
     *     }
     *     SEQUENCE algId       <- SHA256withRSA
     *     BIT STRING signature <- assinatura sobre TBSCertificate
     *   }
     */
    static X509Certificate gerarCertificadoAutoAssinado(
            KeyPair par, String subjectDN, String issuerDN) throws Exception {

        byte[] spkiDer = par.getPublic().getEncoded(); // SubjectPublicKeyInfo já em DER

        // Campos temporais
        long agora   = System.currentTimeMillis();
        Date before  = new Date(agora - 1000L);
        Date after   = new Date(agora + 10L * 365 * 24 * 3600 * 1000);

        // Serial aleatório de 8 bytes
        byte[] serialBytes = new byte[8];
        new SecureRandom().nextBytes(serialBytes);
        // Garantir positivo: setar bit mais significativo para 0
        serialBytes[0] &= 0x7F;
        if (serialBytes[0] == 0) serialBytes[0] = 0x01;

        // --- Montar TBSCertificate ---
        ByteArrayOutputStream tbs = new ByteArrayOutputStream();

        // version [0] EXPLICIT INTEGER 2  (v3)
        tbs.write(derTagged(0, derInteger(new byte[]{0x02})));

        // serialNumber
        tbs.write(derInteger(serialBytes));

        // signature AlgorithmIdentifier (SHA256withRSA = OID 1.2.840.113549.1.1.11)
        tbs.write(algIdSHA256withRSA());

        // issuer Name
        tbs.write(derName(issuerDN));

        // validity
        byte[] validitySeq = concat(derUTCTime(before), derUTCTime(after));
        tbs.write(derSequence(validitySeq));

        // subject Name
        tbs.write(derName(subjectDN));

        // subjectPublicKeyInfo (já em DER, usa direto)
        tbs.write(spkiDer);

        byte[] tbsBytes = derSequence(tbs.toByteArray());

        // --- Assinar TBSCertificate ---
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(par.getPrivate());
        sig.update(tbsBytes);
        byte[] sigBytes = sig.sign();

        // --- Montar Certificate completo ---
        byte[] certSeq = derSequence(concat(
            tbsBytes,
            algIdSHA256withRSA(),
            derBitString(sigBytes)
        ));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(certSeq));
    }

    // ---------- Helpers ASN.1/DER ----------

    static byte[] derLength(int len) throws IOException {
        if (len < 128) return new byte[]{ (byte) len };
        if (len < 256) return new byte[]{ (byte) 0x81, (byte) len };
        return new byte[]{ (byte) 0x82,
            (byte)((len >> 8) & 0xFF), (byte)(len & 0xFF) };
    }

    static byte[] derTLV(int tag, byte[] value) throws IOException {
        byte[] lenBytes = derLength(value.length);
        byte[] out = new byte[1 + lenBytes.length + value.length];
        out[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, out, 1, lenBytes.length);
        System.arraycopy(value, 0, out, 1 + lenBytes.length, value.length);
        return out;
    }

    static byte[] derSequence(byte[] value) throws IOException {
        return derTLV(0x30, value);
    }

    static byte[] derInteger(byte[] value) throws IOException {
        // Garantir que não há interpretação negativa
        if ((value[0] & 0x80) != 0) {
            byte[] padded = new byte[value.length + 1];
            padded[0] = 0x00;
            System.arraycopy(value, 0, padded, 1, value.length);
            value = padded;
        }
        return derTLV(0x02, value);
    }

    static byte[] derBitString(byte[] value) throws IOException {
        // Prefixo 0x00 = sem bits de preenchimento
        byte[] wrapped = new byte[value.length + 1];
        wrapped[0] = 0x00;
        System.arraycopy(value, 0, wrapped, 1, value.length);
        return derTLV(0x03, wrapped);
    }

    static byte[] derOID(int[] oid) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(40 * oid[0] + oid[1]);
        for (int i = 2; i < oid.length; i++) {
            long val = oid[i];
            if (val < 128) {
                bos.write((int) val);
            } else {
                // Codificação multi-byte
                int nbytes = 0;
                long tmp = val;
                while (tmp > 0) { nbytes++; tmp >>= 7; }
                for (int j = nbytes - 1; j >= 0; j--) {
                    int b = (int)((val >> (7 * j)) & 0x7F);
                    if (j > 0) b |= 0x80;
                    bos.write(b);
                }
            }
        }
        return derTLV(0x06, bos.toByteArray());
    }

    static byte[] derNull() { return new byte[]{ 0x05, 0x00 }; }

    static byte[] algIdSHA256withRSA() throws IOException {
        // OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption) + NULL
        int[] oid = {1,2,840,113549,1,1,11};
        return derSequence(concat(derOID(oid), derNull()));
    }

    static byte[] derUTCTime(Date date) throws IOException {
        // Formato YYMMDDHHmmssZ
        java.text.SimpleDateFormat sdf =
            new java.text.SimpleDateFormat("yyMMddHHmmss");
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        String s = sdf.format(date) + "Z";
        return derTLV(0x17, s.getBytes("ASCII"));
    }

    static byte[] derTagged(int tagNum, byte[] value) throws IOException {
        // Context-specific, constructed, tag = tagNum
        return derTLV(0xA0 | tagNum, value);
    }

    /**
     * Converte um DN simplificado para ASN.1 DER Name.
     * Suporta os atributos: CN, O, OU, C, EMAILADDRESS (OID 1.2.840.113549.1.9.1)
     */
    static byte[] derName(String dn) throws IOException {
        // Parsear "CN=Valor, O=Valor, EMAILADDRESS=Valor"
        String[] parts = dn.split(",");
        ByteArrayOutputStream rdnSet = new ByteArrayOutputStream();
        for (String part : parts) {
            part = part.trim();
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            String attr  = part.substring(0, eq).trim().toUpperCase();
            String value = part.substring(eq + 1).trim();

            int[] attrOid = attrOID(attr);
            if (attrOid == null) continue;

            byte[] attrOidDer = derOID(attrOid);
            byte[] valueDer;
            if (attr.equals("EMAILADDRESS")) {
                valueDer = derTLV(0x16, value.getBytes("ASCII")); // IA5String
            } else {
                valueDer = derTLV(0x0C, value.getBytes("UTF-8")); // UTF8String
            }
            byte[] atavSeq = derSequence(concat(attrOidDer, valueDer));
            byte[] rdnSeq  = derTLV(0x31, atavSeq); // SET
            rdnSet.write(rdnSeq);
        }
        return derSequence(rdnSet.toByteArray());
    }

    static int[] attrOID(String attr) {
        switch (attr) {
            case "CN":           return new int[]{2,5,4,3};
            case "O":            return new int[]{2,5,4,10};
            case "OU":           return new int[]{2,5,4,11};
            case "C":            return new int[]{2,5,4,6};
            case "ST":           return new int[]{2,5,4,8};
            case "L":            return new int[]{2,5,4,7};
            case "EMAILADDRESS": return new int[]{1,2,840,113549,1,9,1};
            default:             return null;
        }
    }

    static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }

    // ---------- Assinatura em memória ----------

    static byte[] assinarEmMemoria(byte[] dados, PrivateKey chave) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(chave);
        sig.update(dados);
        return sig.sign();
    }

    // ==========================================================================
    // HELPERS — saída formatada
    // ==========================================================================

    static void cabecalho(String titulo) {
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("  " + titulo);
        System.out.println("=".repeat(60));
        System.out.println();
    }

    static void secao(String nome) {
        System.out.println();
        System.out.println("-".repeat(50));
        System.out.println("  " + nome);
        System.out.println("-".repeat(50));
    }

    static void testar(String descricao, boolean resultado) {
        totalTestes++;
        if (resultado) { totalOk++;    System.out.printf("  [OK]    %s%n", descricao); }
        else           { totalFalha++; System.out.printf("  [FALHA] %s%n", descricao); }
    }

    static void info(String msg)  { System.out.println(msg); }
    static void erro(String msg)  { System.out.println("[ERRO] " + msg); }
    static void falha(String msg) { totalFalha++; System.out.println("  [FALHA] " + msg); }

    static void rodape() {
        System.out.println();
        System.out.println("=".repeat(60));
        if (totalFalha == 0)
            System.out.printf("  RESULTADO: %d/%d testes passaram  |  TUDO OK!%n",
                              totalOk, totalTestes);
        else
            System.out.printf("  RESULTADO: %d/%d testes passaram  |  %d FALHA(S)%n",
                              totalOk, totalTestes, totalFalha);
        System.out.println("=".repeat(60));
        System.out.println();
    }
}
