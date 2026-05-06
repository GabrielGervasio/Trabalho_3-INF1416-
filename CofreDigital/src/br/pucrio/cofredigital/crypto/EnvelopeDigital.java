package br.pucrio.cofredigital.crypto;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.nio.file.*;

/**
 * Operações de Envelope Digital e Assinatura Digital de arquivos.
 *
 * O que é um Envelope Digital?
 * ─────────────────────────────
 * É uma forma de proteger uma chave simétrica usando criptografia assimétrica.
 * Em vez de cifrar o arquivo inteiro com RSA (lento), a gente:
 *   1. Cifra o arquivo com AES (rápido)
 *   2. Cifra a SEMENTE que gerou a chave AES com RSA (só ciframos poucos bytes)
 *   3. Salva a semente cifrada no arquivo .env
 *
 * Para abrir o arquivo:
 *   1. Decifra o .env com RSA (chave privada) → recupera a semente
 *   2. Regenera a chave AES a partir da semente (SHA1PRNG)
 *   3. Decifra o arquivo .enc com essa chave AES
 *
 * Estrutura dos arquivos:
 *   arquivo.enc  → conteúdo do arquivo cifrado com AES
 *   arquivo.env  → semente AES cifrada com RSA (envelope digital)
 *   arquivo.asd  → assinatura digital do conteúdo plaintext (bytes)
 *
 * Quem cifra cada arquivo:
 *   index.enc/.env/.asd → chave do ADMINISTRADOR (ele é dono do índice)
 *   xx0001.enc/.env/.asd → chave do USUÁRIO dono do arquivo
 */
public class EnvelopeDigital {

    // -------------------------------------------------------------------------
    // CRIAÇÃO DO ENVELOPE (QUEM CRIPTOGRAFOU O ARQUIVO)
    // -------------------------------------------------------------------------

    /**
     * Gera uma semente aleatória de 20 bytes.
     * Essa semente será usada para gerar a chave AES do arquivo via SHA1PRNG.
     *
     * @return array de 20 bytes aleatórios
     */
    public static byte[] gerarSemente() {
        byte[] semente = new byte[20];
        new SecureRandom().nextBytes(semente);
        return semente;
    }

    /**
     * Cria o envelope digital: cifra a semente com a chave pública RSA.
     * O resultado é salvo no arquivo .env.
     *
     * Apenas quem tem a chave privada correspondente consegue abrir.
     *
     * @param semente      bytes aleatórios (a "chave" da chave AES)
     * @param chavePublica chave pública do dono do arquivo
     * @return bytes cifrados (conteúdo do arquivo .env)
     */
    public static byte[] criarEnvelope(byte[] semente, PublicKey chavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, chavePublica);
        return cipher.doFinal(semente);
    }

    /**
     * Abre o envelope digital: decifra o .env com a chave privada RSA.
     * Recupera a semente que foi usada para gerar a chave AES do arquivo.
     *
     * @param envelopeCifrado conteúdo do arquivo .env (bytes)
     * @param chavePrivada    chave privada do dono do arquivo
     * @return semente em bytes planos
     */
    public static byte[] abrirEnvelope(byte[] envelopeCifrado, PrivateKey chavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
        return cipher.doFinal(envelopeCifrado);
    }

    // -------------------------------------------------------------------------
    // ASSINATURA DIGITAL
    // -------------------------------------------------------------------------

    /**
     * Assina os dados com a chave privada e salva a assinatura no arquivo .asd.
     *
     * A assinatura garante INTEGRIDADE e AUTENTICIDADE:
     *   - Integridade: o arquivo não foi modificado
     *   - Autenticidade: foi gerado pelo dono da chave privada
     *
     * @param dados        bytes do conteúdo do arquivo (em texto plano, não cifrado)
     * @param chavePrivada chave privada do signatário
     * @param caminhoAsd   caminho onde salvar o arquivo .asd
     */
    public static void assinarEsalvar(byte[] dados, PrivateKey chavePrivada,
                                      String caminhoAsd) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(chavePrivada);
        sig.update(dados);
        byte[] assinatura = sig.sign();
        Files.write(Paths.get(caminhoAsd), assinatura);
    }

    /**
     * Verifica a assinatura digital de um arquivo.
     *
     * @param dados        bytes do conteúdo em texto plano
     * @param assinatura   bytes lidos do arquivo .asd
     * @param chavePublica chave pública do signatário
     * @return true se a assinatura for válida (íntegro e autêntico)
     */
    public static boolean verificarAssinatura(byte[] dados, byte[] assinatura,
                                              PublicKey chavePublica) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(chavePublica);
        sig.update(dados);
        return sig.verify(assinatura);
    }

    // -------------------------------------------------------------------------
    // DECRIPTAÇÃO COMPLETA DE UM ARQUIVO SECRETO
    // -------------------------------------------------------------------------

    /**
     * Decripta um arquivo secreto e verifica sua integridade/autenticidade.
     *
     * Fluxo completo conforme o professor explicou na aula:
     *   1. Carregar o .env → abrir o envelope com a chave privada → obter semente
     *   2. Regenerar a chave AES a partir da semente (SHA1PRNG)
     *   3. Carregar o .enc → decriptar com a chave AES → obter texto plano
     *   4. Carregar o .asd → verificar assinatura com a chave pública
     *   5. Retornar o resultado
     *
     * @param caminhoEnc    caminho do arquivo cifrado (.enc)
     * @param caminhoEnv    caminho do envelope digital (.env)
     * @param caminhoAsd    caminho da assinatura digital (.asd)
     * @param chavePrivada  chave privada do dono do arquivo (para abrir o envelope)
     * @param chavePublica  chave pública do signatário (para verificar a assinatura)
     * @return resultado com os bytes em texto plano e flags de status
     */
    public static ResultadoDecriptacao decriptarArquivo(String caminhoEnc,
                                                         String caminhoEnv,
                                                         String caminhoAsd,
                                                         PrivateKey chavePrivada,
                                                         PublicKey chavePublica) {
        ResultadoDecriptacao resultado = new ResultadoDecriptacao();

        // PASSO 1: Abrir o envelope digital (.env) para obter a semente AES
        byte[] semente;
        try {
            byte[] envelopeCifrado = Files.readAllBytes(Paths.get(caminhoEnv));
            semente = abrirEnvelope(envelopeCifrado, chavePrivada);
        } catch (Exception e) {
            resultado.erroDecriptacao = true;
            resultado.mensagemErro = "Falha ao abrir envelope digital: " + e.getMessage();
            return resultado;
        }

        // PASSO 2: Regenerar a chave AES a partir da semente
        javax.crypto.SecretKey chaveAES;
        try {
            chaveAES = CryptoUtils.gerarChaveAESDeSemente(semente);
        } catch (Exception e) {
            resultado.erroDecriptacao = true;
            resultado.mensagemErro = "Falha ao regenerar chave AES: " + e.getMessage();
            return resultado;
        }

        // PASSO 3: Decriptar o arquivo .enc com AES/ECB/PKCS5
        byte[] textoplano;
        try {
            byte[] conteudoCifrado = Files.readAllBytes(Paths.get(caminhoEnc));
            textoplano = CryptoUtils.decifrarAES(conteudoCifrado, chaveAES);
            resultado.decriptacaoOk = true;
        } catch (Exception e) {
            resultado.erroDecriptacao = true;
            resultado.mensagemErro = "Falha na decriptação AES: " + e.getMessage();
            return resultado;
        }

        // PASSO 4: Verificar assinatura digital (.asd)
        try {
            byte[] assinatura = Files.readAllBytes(Paths.get(caminhoAsd));
            boolean assinaturaValida = verificarAssinatura(textoplano, assinatura, chavePublica);

            if (assinaturaValida) {
                resultado.assinaturaOk = true;
                resultado.conteudo = textoplano;
            } else {
                resultado.erroAssinatura = true;
                resultado.mensagemErro = "Assinatura digital inválida — arquivo pode ter sido alterado.";
                // Mesmo com assinatura inválida, retorna o conteúdo para
                // que o sistema possa notificar o erro adequadamente
                resultado.conteudo = textoplano;
            }
        } catch (Exception e) {
            resultado.erroAssinatura = true;
            resultado.mensagemErro = "Falha ao verificar assinatura: " + e.getMessage();
            resultado.conteudo = textoplano;
        }

        return resultado;
    }

    // -------------------------------------------------------------------------
    // CLASSE DE RESULTADO
    // -------------------------------------------------------------------------

    /**
     * Encapsula o resultado de uma operação de decriptação.
     * Permite que o chamador saiba exatamente o que deu certo ou errado.
     */
    public static class ResultadoDecriptacao {
        /** true se a decriptação AES funcionou */
        public boolean decriptacaoOk = false;

        /** true se a assinatura digital foi verificada com sucesso */
        public boolean assinaturaOk = false;

        /** true se houve erro na decriptação */
        public boolean erroDecriptacao = false;

        /** true se houve erro na verificação da assinatura */
        public boolean erroAssinatura = false;

        /** bytes do conteúdo em texto plano (null se decriptação falhou) */
        public byte[] conteudo = null;

        /** mensagem de erro para exibir ao usuário */
        public String mensagemErro = null;

        /** tudo ok: decriptou e verificou com sucesso */
        public boolean tudoOk() {
            return decriptacaoOk && assinaturaOk;
        }
    }
}
