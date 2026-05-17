// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

/**
 * Implementação da classe TOTP (Time-based One Time Password).
 *
 * Baseada nos RFCs:
 *   - RFC 6238: TOTP — define o contador de tempo (intervalos de 30s desde 01/01/1970)
 *   - RFC 4226: HOTP — define o algoritmo HMAC-SHA1 e o truncamento do hash
 *   - RFC 4648: BASE32 — codificação da chave secreta
 *
 * ATENÇÃO — ponto crítico explicado pelo professor na aula:
 *   O contador de intervalos fica em memória em little-endian,
 *   mas o padrão exige big-endian.
 *   Se não converter, o código NUNCA vai bater com o Google Authenticator.
 *
 * Restrição do trabalho:
 *   Usar APENAS: javax.crypto.Mac, javax.crypto.spec.SecretKeySpec,
 *                java.util.Date e a classe Base32 fornecida.
 *   NÃO usar bibliotecas de terceiros para TOTP.
 *
 * Estrutura do esqueleto fornecida pelo professor e implementada aqui.
 */
public class TOTP {

    /** Chave secreta em bytes (decodificada do BASE32) */
    private byte[] key = null;

    /** Intervalo de tempo em segundos (padrão = 30) */
    private long timeStepInSeconds = 30;

    // -------------------------------------------------------------------------
    // CONSTRUTOR
    // -------------------------------------------------------------------------

    /**
     * Constrói o TOTP a partir da chave secreta codificada em BASE32.
     *
     * @param base32EncodedSecret  chave secreta em BASE32 (ex: "JXXMGK33L7S3H3JO...")
     * @param timeStepInSeconds    intervalo de tempo (use 30)
     * @throws Exception se a chave BASE32 for inválida
     */
    public TOTP(String base32EncodedSecret, long timeStepInSeconds) throws Exception {
        this.timeStepInSeconds = timeStepInSeconds;

        // Decodificar a chave BASE32 → array de bytes
        // Usar o alfabeto padrão RFC 4648, sem padding, maiúsculas
        Base32 base32 = new Base32(Base32.Alphabet.BASE32, false, false);
        this.key = base32.fromString(base32EncodedSecret);

        if (this.key == null) {
            throw new Exception("Chave BASE32 inválida: não foi possível decodificar.");
        }
    }

    // -------------------------------------------------------------------------
    // MÉTODOS PRIVADOS AUXILIARES
    // -------------------------------------------------------------------------

    /**
     * Calcula o HMAC-SHA1 do contador usando a chave secreta.
     *
     * PONTO CRÍTICO — conversão little-endian → big-endian:
     *   A JVM armazena long em big-endian, mas precisamos garantir que o
     *   array de 8 bytes do contador esteja em big-endian (MSB primeiro).
     *   O loop abaixo faz isso explicitamente.
     *
     * @param counter      intervalo de tempo convertido para 8 bytes big-endian
     * @param keyByteArray chave secreta em bytes
     * @return hash HMAC-SHA1 de 20 bytes
     */
    private byte[] HMAC_SHA1(byte[] counter, byte[] keyByteArray) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(keyByteArray, "HmacSHA1"));
        return mac.doFinal(counter);
    }

    /**
     * Extrai o código TOTP de 6 dígitos do hash HMAC-SHA1.
     *
     * Algoritmo de truncamento dinâmico (RFC 4226, seção 5.3):
     *   1. offset = últimos 4 bits do último byte do hash
     *   2. Pegar 4 bytes a partir do offset
     *   3. Zerar o bit mais significativo (garantir número positivo)
     *   4. Calcular módulo 1.000.000
     *   5. Preencher com zeros à esquerda até 6 dígitos
     *
     * @param hash  resultado do HMAC-SHA1 (20 bytes)
     * @return código TOTP de 6 dígitos como String (com zeros à esquerda)
     */
    private String getTOTPCodeFromHash(byte[] hash) {
        // Passo 1: offset = últimos 4 bits do último byte
        int offset = hash[hash.length - 1] & 0x0F;

        // Passo 2 e 3: extrair 4 bytes e zerar o bit de sinal (AND com 0x7FFFFFFF)
        int binary =
            ((hash[offset]     & 0x7F) << 24) |  // 0x7F zera o bit de sinal
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8)  |
             (hash[offset + 3] & 0xFF);

        // Passo 4: módulo 1.000.000 → código de no máximo 6 dígitos
        int otp = binary % 1_000_000;

        // Passo 5: preencher com zeros à esquerda para garantir 6 dígitos
        return String.format("%06d", otp);
    }

    /**
     * Gera o código TOTP para um intervalo de tempo específico.
     *
     * CONVERSÃO BIG-ENDIAN (ponto crítico da aula):
     *   O timeInterval é um long (64 bits).
     *   Precisamos convertê-lo para um array de 8 bytes em big-endian
     *   (byte mais significativo primeiro — posição 0 do array).
     *
     *   Fazemos isso deslocando o valor à direita e pegando o byte menos
     *   significativo de cada vez, preenchendo o array de trás para frente.
     *
     * @param timeInterval  quantidade de intervalos de 30s desde 01/01/1970
     * @return código TOTP de 6 dígitos
     */
    private String TOTPCode(long timeInterval) throws Exception {
        // Converter o contador para array de 8 bytes em big-endian
        // (byte mais significativo no índice 0)
        byte[] counter = new byte[8];
        long temp = timeInterval;
        for (int i = 7; i >= 0; i--) {
            counter[i] = (byte)(temp & 0xFF);  // pega o byte menos significativo
            temp >>= 8;                          // desloca para pegar o próximo
        }

        // Calcular HMAC-SHA1 com o contador e a chave
        byte[] hash = HMAC_SHA1(counter, key);

        // Extrair o código de 6 dígitos do hash
        return getTOTPCodeFromHash(hash);
    }

    // -------------------------------------------------------------------------
    // MÉTODOS PÚBLICOS
    // -------------------------------------------------------------------------

    /**
     * Gera o código TOTP atual.
     *
     * O intervalo de tempo é calculado como:
     *   milissegundos_atuais / 1000 / timeStepInSeconds
     *
     * @return código TOTP de 6 dígitos para o momento atual
     */
    public String generateCode() throws Exception {
        // Calcular o intervalo atual (quantos blocos de 30s passaram desde 01/01/1970)
        long tempoAtualMs    = new Date().getTime();
        long intervaloAtual  = tempoAtualMs / 1000 / timeStepInSeconds;
        return TOTPCode(intervaloAtual);
    }

    /**
     * Valida um código TOTP fornecido pelo usuário.
     *
     * Aceita uma janela de ±30 segundos para tolerar pequenas diferenças
     * de relógio entre o servidor e o dispositivo do usuário.
     *
     * Calcula 3 valores:
     *   - intervalo - 1  (30 segundos atrás)
     *   - intervalo      (momento exato)
     *   - intervalo + 1  (30 segundos à frente)
     *
     * Se o inputTOTP bater com qualquer um dos três → válido.
     *
     * @param inputTOTP  código de 6 dígitos digitado pelo usuário
     * @return true se o código for válido dentro da janela de tolerância
     */
    public boolean validateCode(String inputTOTP) throws Exception {
        if (inputTOTP == null || inputTOTP.length() != 6) return false;

        // Calcular o intervalo atual
        long tempoAtualMs   = new Date().getTime();
        long intervaloAtual = tempoAtualMs / 1000 / timeStepInSeconds;

        // Verificar os 3 intervalos: anterior, atual e próximo
        for (long delta = -1; delta <= 1; delta++) {
            String codigoCalculado = TOTPCode(intervaloAtual + delta);
            if (codigoCalculado.equals(inputTOTP)) {
                return true;
            }
        }

        return false;
    }
}
