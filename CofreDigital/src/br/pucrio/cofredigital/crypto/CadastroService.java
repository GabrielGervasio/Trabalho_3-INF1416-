// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.crypto;

import br.pucrio.cofredigital.db.ChaveiroDAO;
import br.pucrio.cofredigital.db.UsuarioDAO;
import br.pucrio.cofredigital.model.Chaveiro;
import br.pucrio.cofredigital.model.Usuario;
import br.pucrio.cofredigital.totp.TotpUtils;

import java.security.cert.X509Certificate;
import java.security.PrivateKey;

/**
 * Orquestra o fluxo completo de cadastro de um novo usuário.
 *
 * Esse serviço une todas as peças de criptografia e banco de dados
 * na ordem correta exigida pelo trabalho.
 *
 * Fluxo de cadastro (conforme enunciado):
 *   1.  Ler e validar o certificado digital (X.509 PEM)
 *   2.  Extrair e-mail e nome do certificado
 *   3.  Verificar se o e-mail já existe no banco
 *   4.  Ler e decriptar a chave privada (AES + SHA1PRNG)
 *   5.  Validar a chave privada (assinar 9216 bytes e verificar)
 *   6.  Apresentar dados do certificado ao usuário para confirmação
 *   7.  Validar senha pessoal (8-10 dígitos, sem repetição)
 *   8.  Gerar hash bcrypt da senha
 *   9.  Gerar chave TOTP de 20 bytes aleatórios
 *   10. Cifrar chave TOTP com AES (senha como semente)
 *   11. Inserir na tabela Chaveiro (cert PEM + chave privada binária) → obter KID
 *   12. Inserir na tabela Usuarios com todos os dados
 */
public class CadastroService {

    private final UsuarioDAO usuarioDAO;
    private final ChaveiroDAO chaveiroDAO;

    public CadastroService() {
        this.usuarioDAO  = new UsuarioDAO();
        this.chaveiroDAO = new ChaveiroDAO();
    }

    // -------------------------------------------------------------------------
    // RESULTADO DO CADASTRO
    // -------------------------------------------------------------------------

    /**
     * Encapsula o resultado de uma tentativa de cadastro.
     * Permite que a UI saiba exatamente o que aconteceu.
     */
    public static class ResultadoCadastro {
        public boolean sucesso       = false;
        public String mensagemErro   = null;
        public String emailExtraido  = null;
        public String nomeExtraido   = null;

        // Dados do certificado para mostrar na tela de confirmação
        public String certVersao     = null;
        public String certSerie      = null;
        public String certValidade   = null;
        public String certAssinatura = null;
        public String certEmissor    = null;
        public String certSubject    = null;
        public String certEmail      = null;

        // Chave BASE32 para configurar no Google Authenticator
        public String totpBase32     = null;
        public String totpQRCodeUri  = null;
    }

    // -------------------------------------------------------------------------
    // ETAPA 1: VALIDAR DADOS ANTES DE CONFIRMAR
    // -------------------------------------------------------------------------

    /**
     * Valida todos os dados do formulário de cadastro ANTES de pedir confirmação.
     * Se tudo estiver ok, retorna os dados do certificado para o usuário confirmar.
     *
     * @param caminhoCert      caminho do arquivo .pem do certificado
     * @param caminhoChavePriv caminho do arquivo binário da chave privada
     * @param fraseSecreta     frase secreta da chave privada
     * @param senhaUsuario     senha pessoal do usuário (8-10 dígitos)
     * @param confirmacaoSenha confirmação da senha
     * @param gid              grupo do usuário (1=Admin, 2=Usuário)
     * @return ResultadoCadastro com sucesso=true e dados do cert, ou com mensagemErro
     */
    public ResultadoCadastro validarFormulario(String caminhoCert,
                                               String caminhoChavePriv,
                                               String fraseSecreta,
                                               String senhaUsuario,
                                               String confirmacaoSenha,
                                               int gid) {
        ResultadoCadastro resultado = new ResultadoCadastro();

        // --- Validar senha pessoal ---
        if (!BcryptUtils.senhaValida(senhaUsuario)) {
            resultado.mensagemErro = "Senha pessoal inválida. Deve ter 8 a 10 dígitos numéricos sem repetição.";
            return resultado;
        }

        if (!senhaUsuario.equals(confirmacaoSenha)) {
            resultado.mensagemErro = "Senha e confirmação não conferem.";
            return resultado;
        }

        // --- Ler o certificado digital ---
        X509Certificate cert;
        try {
            cert = CryptoUtils.lerCertificado(caminhoCert);
        } catch (Exception e) {
            resultado.mensagemErro = "Caminho do certificado inválido ou arquivo corrompido.";
            return resultado;
        }

        // --- Extrair e-mail e nome do certificado ---
        String email = CertificadoUtils.extrairEmail(cert);
        String nome  = CertificadoUtils.extrairNome(cert);

        if (email == null || email.isEmpty()) {
            resultado.mensagemErro = "Não foi possível extrair o e-mail do certificado.";
            return resultado;
        }

        // --- Verificar se o login já existe ---
        try {
            if (usuarioDAO.existsByLogin(email)) {
                resultado.mensagemErro = "Já existe um usuário cadastrado com o e-mail: " + email;
                return resultado;
            }
        } catch (Exception e) {
            resultado.mensagemErro = "Erro ao consultar banco de dados: " + e.getMessage();
            return resultado;
        }

        // --- Ler e decriptar a chave privada ---
        PrivateKey chavePrivada;
        try {
            chavePrivada = CryptoUtils.lerChavePrivada(caminhoChavePriv, fraseSecreta);
        } catch (java.io.FileNotFoundException e) {
            resultado.mensagemErro = "Arquivo da chave privada não encontrado.";
            return resultado;
        } catch (javax.crypto.BadPaddingException e) {
            // Frase secreta errada → erro de padding na decriptação AES
            resultado.mensagemErro = "Frase secreta inválida para a chave privada.";
            return resultado;
        } catch (Exception e) {
            resultado.mensagemErro = "Erro ao ler chave privada: " + e.getMessage();
            return resultado;
        }

        // --- Validar chave privada (assinar 9216 bytes conforme enunciado) ---
        try {
            boolean valida = CryptoUtils.validarChavePrivada(
                chavePrivada, cert.getPublicKey(), 9216
            );
            if (!valida) {
                resultado.mensagemErro = "Assinatura digital inválida — chave privada não corresponde ao certificado.";
                return resultado;
            }
        } catch (Exception e) {
            resultado.mensagemErro = "Erro ao validar chave privada: " + e.getMessage();
            return resultado;
        }

        // --- Preencher dados do certificado para confirmação ---
        resultado.emailExtraido  = email;
        resultado.nomeExtraido   = nome;
        resultado.certVersao     = CertificadoUtils.extrairVersao(cert);
        resultado.certSerie      = CertificadoUtils.extrairSerie(cert);
        resultado.certValidade   = CertificadoUtils.extrairValidade(cert);
        resultado.certAssinatura = CertificadoUtils.extrairTipoAssinatura(cert);
        resultado.certEmissor    = CertificadoUtils.extrairEmissor(cert);
        resultado.certSubject    = CertificadoUtils.extrairSubject(cert);
        resultado.certEmail      = email;
        resultado.sucesso        = true;

        return resultado;
    }

    // -------------------------------------------------------------------------
    // ETAPA 2: EFETIVAR O CADASTRO APÓS CONFIRMAÇÃO DO USUÁRIO
    // -------------------------------------------------------------------------

    /**
     * Efetiva o cadastro após o usuário confirmar os dados do certificado.
     *
     * Ordem obrigatória:
     *   1. Inserir no Chaveiro → obter KID
     *   2. Inserir no Usuarios com o KID obtido
     *
     * @param caminhoCert      caminho do certificado .pem
     * @param caminhoChavePriv caminho da chave privada binária
     * @param fraseSecreta     frase secreta (para ler a chave privada de novo)
     * @param senhaUsuario     senha pessoal em texto plano
     * @param gid              grupo (1=Admin, 2=Usuário)
     * @return ResultadoCadastro com sucesso e dados do TOTP para mostrar ao usuário
     */
    public ResultadoCadastro efetivarCadastro(String caminhoCert,
                                               String caminhoChavePriv,
                                               String fraseSecreta,
                                               String senhaUsuario,
                                               int gid) {
        ResultadoCadastro resultado = new ResultadoCadastro();

        try {
            // Re-ler certificado e chave privada
            X509Certificate cert = CryptoUtils.lerCertificado(caminhoCert);
            PrivateKey chavePrivada = CryptoUtils.lerChavePrivada(caminhoChavePriv, fraseSecreta);

            String email = CertificadoUtils.extrairEmail(cert);
            String nome  = CertificadoUtils.extrairNome(cert);

            // --- Gerar hash bcrypt da senha pessoal ---
            String senhaBcrypt = BcryptUtils.gerarHash(senhaUsuario);

            // --- Gerar chave TOTP (20 bytes aleatórios) ---
            byte[] chaveTotp = TotpUtils.gerarChaveTotp();
            String totpBase32 = TotpUtils.chaveParaBase32(chaveTotp);

            // --- Cifrar chave TOTP com AES (senha como semente) ---
            String totpEncBase64 = TotpUtils.cifrarChaveTotp(chaveTotp, senhaUsuario);

            // --- Preparar certificado PEM para armazenar no banco ---
            String certPEM = CryptoUtils.certificadoParaPEM(cert);

            // --- Ler a chave privada em binário (para armazenar no banco) ---
            // O arquivo no disco já está cifrado — armazenamos o binário cifrado diretamente
            byte[] chavePrivadaBin = java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get(caminhoChavePriv)
            );

            // --- Inserir na tabela Chaveiro PRIMEIRO (para obter o KID) ---
            Chaveiro chaveiro = new Chaveiro();
            chaveiro.setCertPem(certPEM);
            chaveiro.setChavePrivadaBin(chavePrivadaBin);
            // UID será atualizado depois de inserir o Usuario
            int kid = chaveiroDAO.insert(chaveiro);

            if (kid < 0) {
                resultado.mensagemErro = "Erro ao salvar chave/certificado no banco.";
                return resultado;
            }

            // --- Inserir na tabela Usuarios com o KID recém-obtido ---
            Usuario usuario = new Usuario();
            usuario.setLoginName(email);
            usuario.setNomeUsuario(nome != null ? nome : email);
            usuario.setSenhaBcrypt(senhaBcrypt);
            usuario.setTotpEnc(totpEncBase64);
            usuario.setKid(kid);
            usuario.setGid(gid);
            usuario.setTotalAcessos(0);

            int uid = usuarioDAO.insert(usuario);

            if (uid < 0) {
                resultado.mensagemErro = "Erro ao salvar usuário no banco.";
                return resultado;
            }

            // --- Atualizar o Chaveiro com o UID do usuário recém-criado ---
            chaveiro.setUid(uid);
            chaveiro.setKid(kid);
            chaveiroDAO.updateUid(kid, uid);

            // --- Preencher resultado com dados para a UI ---
            resultado.sucesso       = true;
            resultado.emailExtraido = email;
            resultado.nomeExtraido  = nome;
            resultado.totpBase32    = totpBase32;
            resultado.totpQRCodeUri = TotpUtils.montarUriQRCode(email, totpBase32);

        } catch (Exception e) {
            resultado.sucesso      = false;
            resultado.mensagemErro = "Erro inesperado ao efetivar cadastro: " + e.getMessage();
        }

        return resultado;
    }
}
