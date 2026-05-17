// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.crypto;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import java.security.SecureRandom;

/**
 * Utilitários para hash bcrypt usando BouncyCastle.
 *
 * Requisito do trabalho:
 *   - Versão:  2y
 *   - Custo:   8   (2^8 = 256 iterações — adequado para teclado sobrecarregado)
 *   - Formato: $2y$08$<22 chars salt em Base64>$<31 chars hash em Base64>
 *   - Total:   60 caracteres
 *
 * Exemplo:
 *   $2y$08$ajDZdV0XFoYiLRE0ZrSx6OmRbhhB5qM.Ap6c.0LqRu2cIY1jpytuO
 *
 * IMPORTANTE: o professor destacou que o custo 8 foi escolhido especificamente
 * porque o teclado sobrecarregado precisa testar VÁRIAS combinações de senha.
 * Com custo 12 (padrão de produção), ficaria muito lento.
 *
 * Dependência: bcprov-jdk18on-xxx.jar na pasta lib/
 * Baixe em: https://www.bouncycastle.org/download/bouncy-castle-java/
 */
public class BcryptUtils {

    /** Versão do bcrypt exigida pelo trabalho */
    private static final String VERSAO = "2y";

    /** Custo das iterações: 2^8 = 256 */
    private static final int CUSTO = 8;

    /** Tamanho do salt em bytes (16 bytes → 22 chars em Base64 do bcrypt) */
    private static final int TAMANHO_SALT = 16;

    // -------------------------------------------------------------------------
    // GERAR HASH
    // -------------------------------------------------------------------------

    /**
     * Gera o hash bcrypt de uma senha.
     *
     * Processo:
     *   1. Gera 16 bytes aleatórios como salt
     *   2. Passa para OpenBSDBCrypt.generate() com versão 2y e custo 8
     *   3. Retorna String de 60 caracteres no formato padrão
     *
     * @param senha  senha em texto plano (máx. 10 chars no trabalho)
     * @return String de 60 chars no formato $2y$08$...
     */
    public static String gerarHash(String senha) {
        // Gerar salt aleatório
        byte[] salt = new byte[TAMANHO_SALT];
        new SecureRandom().nextBytes(salt);

        // Gerar hash bcrypt
        // OpenBSDBCrypt.generate(versão, senha_como_chars, salt, custo)
        return OpenBSDBCrypt.generate(VERSAO, senha.toCharArray(), salt, CUSTO);
    }

    // -------------------------------------------------------------------------
    // VERIFICAR SENHA
    // -------------------------------------------------------------------------

    /**
     * Verifica se uma senha corresponde a um hash bcrypt armazenado.
     *
     * O salt já está embutido dentro do hash armazenado — não precisa
     * passar separadamente.
     *
     * @param hashArmazenado  String de 60 chars do banco de dados
     * @param senha           senha em texto plano fornecida pelo usuário
     * @return true se a senha corresponde ao hash
     */
    public static boolean verificar(String hashArmazenado, String senha) {
        try {
            return OpenBSDBCrypt.checkPassword(hashArmazenado, senha.toCharArray());
        } catch (Exception e) {
            // Se o hash estiver malformado ou ocorrer qualquer erro, nega acesso
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // VALIDAÇÃO DE SENHA ANTES DE ARMAZENAR
    // -------------------------------------------------------------------------

    /**
     * Valida se uma senha pessoal atende aos requisitos do trabalho:
     *   - Entre 8 e 10 caracteres
     *   - Apenas dígitos de 0 a 9
     *   - Sem sequências de números repetidos (ex: "11111111" é inválido)
     *
     * @param senha  senha a validar
     * @return true se a senha for válida
     */
    public static boolean senhaValida(String senha) {
        if (senha == null) return false;

        // Tamanho entre 8 e 10
        if (senha.length() < 8 || senha.length() > 10) return false;

        // Apenas dígitos
        if (!senha.matches("[0-9]+")) return false;

        // Sem todos os dígitos iguais (sequência repetida)
        // O enunciado diz "não podem ser aceitas sequências de números repetidos"
        // Interpretamos como: não pode ter todos os dígitos iguais
        char primeiro = senha.charAt(0);
        boolean todosIguais = true;
        for (char c : senha.toCharArray()) {
            if (c != primeiro) {
                todosIguais = false;
                break;
            }
        }
        if (todosIguais) return false;

        return true;
    }
}
