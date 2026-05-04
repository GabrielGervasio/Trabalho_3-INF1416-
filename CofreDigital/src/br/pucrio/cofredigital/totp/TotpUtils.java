package br.pucrio.cofredigital.totp;

import br.pucrio.cofredigital.crypto.CryptoUtils;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

/**
 * Utilitários para geração e armazenamento seguro da chave TOTP.
 *
 * A chave TOTP de cada usuário:
 *   1. É gerada como 20 bytes aleatórios no momento do cadastro
 *   2. É codificada em BASE32 para configurar no Google Authenticator
 *   3. É cifrada com AES (chave derivada da senha pessoal) antes de ir ao banco
 *   4. É decifrada com a mesma senha quando necessário para validar o token
 *
 * Por que cifrar com a senha pessoal?
 *   Se o banco vazar, o atacante não tem acesso às chaves TOTP dos usuários.
 *   E mesmo que tenha a senha bcrypt, não consegue reverter para a senha original
 *   necessária para decifrar a chave TOTP — dupla proteção.
 */
public class TotpUtils {

    /** Instância Base32 com o alfabeto padrão RFC 4648 */
    private static final Base32 BASE32 = new Base32(Base32.Alphabet.BASE32, false, false);

    // -------------------------------------------------------------------------
    // GERAÇÃO DA CHAVE TOTP
    // -------------------------------------------------------------------------

    /**
     * Gera uma nova chave TOTP: 20 bytes aleatórios.
     *
     * @return array de 20 bytes aleatórios
     */
    public static byte[] gerarChaveTotp() {
        byte[] chave = new byte[20];
        new SecureRandom().nextBytes(chave);
        return chave;
    }

    /**
     * Codifica a chave TOTP em BASE32 para mostrar ao usuário
     * e configurar no Google Authenticator.
     *
     * @param chaveTotp  20 bytes da chave TOTP
     * @return String BASE32 (ex: "JXXMGK33L7S3H3JOYSGMUXC7G7ASJHTD")
     */
    public static String chaveParaBase32(byte[] chaveTotp) {
        return BASE32.toString(chaveTotp);
    }

    /**
     * Monta a URI para geração de QR Code do Google Authenticator.
     *
     * Formato:
     *   otpauth://totp/Cofre%20Digital:<email>?secret=<BASE32>
     *
     * @param email      login do usuário (e-mail)
     * @param base32Key  chave em BASE32
     * @return URI para o QR Code
     */
    public static String montarUriQRCode(String email, String base32Key) {
        return "otpauth://totp/Cofre%20Digital:" + email + "?secret=" + base32Key;
    }

    // -------------------------------------------------------------------------
    // CIFRAGEM DA CHAVE TOTP PARA O BANCO
    // -------------------------------------------------------------------------

    /**
     * Cifra a chave TOTP com AES para armazenar no banco de dados.
     *
     * A senha pessoal do usuário é usada como base para gerar a chave AES
     * (SHA1PRNG, igual ao processo de proteção da chave privada).
     *
     * @param chaveTotp     20 bytes da chave TOTP em texto plano
     * @param senhaUsuario  senha pessoal (8-10 dígitos)
     * @return bytes cifrados — o que vai para a coluna totp_enc do banco (como Base64)
     */
    public static String cifrarChaveTotp(byte[] chaveTotp, String senhaUsuario) throws Exception {
        SecretKey chaveAES = CryptoUtils.gerarChaveAES(senhaUsuario);
        byte[] cifrado = CryptoUtils.cifrarAES(chaveTotp, chaveAES);

        // Armazenar como Base64 no banco (campo VARCHAR/TEXT)
        return java.util.Base64.getEncoder().encodeToString(cifrado);
    }

    // -------------------------------------------------------------------------
    // DECIFRAR A CHAVE TOTP DO BANCO
    // -------------------------------------------------------------------------

    /**
     * Decifra a chave TOTP armazenada no banco.
     *
     * Chamado após o usuário passar a etapa 2 (senha correta via bcrypt).
     * Nesse momento já sabemos a senha em texto plano (foi digitada no teclado
     * virtual) e podemos usá-la para decifrar a chave TOTP.
     *
     * @param totpEncBase64  valor da coluna totp_enc do banco (Base64)
     * @param senhaUsuario   senha pessoal em texto plano (já validada na etapa 2)
     * @return 20 bytes da chave TOTP em texto plano
     */
    public static byte[] decifrarChaveTotp(String totpEncBase64, String senhaUsuario) throws Exception {
        byte[] cifrado = java.util.Base64.getDecoder().decode(totpEncBase64);
        SecretKey chaveAES = CryptoUtils.gerarChaveAES(senhaUsuario);
        return CryptoUtils.decifrarAES(cifrado, chaveAES);
    }

    // -------------------------------------------------------------------------
    // CRIAR OBJETO TOTP A PARTIR DO BANCO
    // -------------------------------------------------------------------------

    /**
     * Reconstrói o objeto TOTP a partir dos dados do banco,
     * após o usuário passar a etapa 2 com sucesso.
     *
     * @param totpEncBase64  valor da coluna totp_enc do banco
     * @param senhaUsuario   senha pessoal correta (validada na etapa 2)
     * @return objeto TOTP pronto para gerar/validar códigos
     */
    public static TOTP criarTOTP(String totpEncBase64, String senhaUsuario) throws Exception {
        // Decifrar a chave do banco
        byte[] chaveTotp = decifrarChaveTotp(totpEncBase64, senhaUsuario);

        // Converter para BASE32
        String base32 = chaveParaBase32(chaveTotp);

        // Criar e retornar o objeto TOTP com intervalo de 30 segundos
        return new TOTP(base32, 30);
    }
}
