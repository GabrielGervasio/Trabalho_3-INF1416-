package br.pucrio.cofredigital.auth;

import br.pucrio.cofredigital.crypto.BcryptUtils;
import br.pucrio.cofredigital.crypto.CryptoUtils;
import br.pucrio.cofredigital.db.ChaveiroDAO;
import br.pucrio.cofredigital.db.RegistroDAO;
import br.pucrio.cofredigital.db.UsuarioDAO;
import br.pucrio.cofredigital.model.Chaveiro;
import br.pucrio.cofredigital.model.Usuario;
import br.pucrio.cofredigital.totp.TOTP;
import br.pucrio.cofredigital.totp.TotpUtils;

import java.sql.Timestamp;
import java.time.Instant;

/**
 * Controlador do processo de autenticação multifator em 3 etapas.
 *
 * ETAPA 1 — identificação por e-mail (login name)
 * ETAPA 2 — senha pessoal via teclado virtual sobrecarregado
 * ETAPA 3 — código TOTP via Google Authenticator
 *
 * Este controlador é chamado pela UI e devolve resultados que a UI
 * usa para decidir o que mostrar ao usuário.
 *
 * Controle de erros:
 *   - 3 erros consecutivos na etapa 2 → bloqueia usuário por 2 minutos
 *   - 3 erros consecutivos na etapa 3 → bloqueia usuário por 2 minutos
 *   - Contadores zerados quando há verificação positiva
 */
public class AuthController {

    private final UsuarioDAO  usuarioDAO;
    private final ChaveiroDAO chaveiroDAO;

    // Usuário identificado na etapa 1, usado nas etapas seguintes
    private Usuario usuarioAtual = null;

    // Contadores de erro por sessão de autenticação
    private int errosSenha = 0;
    private int errosTotp  = 0;

    // Senha em texto plano guardada temporariamente entre etapa 2 e 3
    // (necessária para decifrar a chave TOTP do banco na etapa 3)
    private String senhaTextoPlano = null;

    public AuthController() {
        this.usuarioDAO  = new UsuarioDAO();
        this.chaveiroDAO = new ChaveiroDAO();
    }

    // =========================================================================
    // ETAPA 1 — identificação por e-mail
    // =========================================================================

    /**
     * Resultado da etapa 1.
     */
    public enum ResultadoEtapa1 {
        /** E-mail encontrado e acesso liberado — seguir para etapa 2 */
        SUCESSO,
        /** E-mail não encontrado no banco */
        LOGIN_INVALIDO,
        /** E-mail encontrado mas usuário está bloqueado */
        ACESSO_BLOQUEADO
    }

    /**
     * Processa a etapa 1: verifica o login name (e-mail) no banco.
     *
     * Registros gerados:
     *   2001 — autenticação etapa 1 iniciada
     *   2003 — login identificado com acesso liberado
     *   2004 — login identificado com acesso bloqueado
     *   2005 — login não identificado
     *   2002 — autenticação etapa 1 encerrada
     *
     * @param loginName  e-mail digitado pelo usuário
     * @return resultado da verificação
     */
    public ResultadoEtapa1 verificarLogin(String loginName) {
        // Registrar início da etapa 1
        RegistroDAO.registrar(2001, null, null);

        // Resetar estado de autenticação anterior
        usuarioAtual    = null;
        errosSenha      = 0;
        errosTotp       = 0;
        senhaTextoPlano = null;

        try {
            Usuario usuario = usuarioDAO.findByLogin(loginName);

            if (usuario == null) {
                // Login não encontrado
                RegistroDAO.registrar(2005, null, null);
                RegistroDAO.registrar(2002, null, null);
                return ResultadoEtapa1.LOGIN_INVALIDO;
            }

            // Verificar se está bloqueado
            if (estaBloqueado(usuario)) {
                RegistroDAO.registrar(2004, usuario.getUid(), null);
                RegistroDAO.registrar(2002, usuario.getUid(), null);
                return ResultadoEtapa1.ACESSO_BLOQUEADO;
            }

            // Login válido e acesso liberado
            usuarioAtual = usuario;
            RegistroDAO.registrar(2003, usuario.getUid(), null);
            RegistroDAO.registrar(2002, usuario.getUid(), null);
            return ResultadoEtapa1.SUCESSO;

        } catch (Exception e) {
            System.err.println("Erro na etapa 1: " + e.getMessage());
            RegistroDAO.registrar(2002, null, null);
            return ResultadoEtapa1.LOGIN_INVALIDO;
        }
    }

    // =========================================================================
    // ETAPA 2 — senha pessoal via teclado virtual
    // =========================================================================

    /**
     * Resultado da etapa 2.
     */
    public enum ResultadoEtapa2 {
        /** Senha correta — seguir para etapa 3 */
        SUCESSO,
        /** Senha incorreta — ainda tem tentativas */
        SENHA_INCORRETA,
        /** Senha incorreta 3 vezes — usuário bloqueado */
        BLOQUEADO
    }

    /**
     * Processa a etapa 2: verifica a senha pessoal com bcrypt.
     *
     * Recebe a lista de combinações possíveis geradas pelo TecladoVirtual
     * e testa cada uma contra o hash bcrypt armazenado no banco.
     *
     * Por que várias combinações?
     *   O teclado sobrecarregado tem 2 dígitos por botão. Com 8-10 cliques,
     *   há 256 a 1024 combinações possíveis. O bcrypt com custo 8 foi
     *   escolhido pelo professor justamente para suportar esse volume.
     *
     * Registros gerados:
     *   3001 — etapa 2 iniciada
     *   3003 — senha verificada positivamente
     *   3004/3005/3006 — 1º/2º/3º erro
     *   3007 — usuário bloqueado
     *   3002 — etapa 2 encerrada
     *
     * @param combinacoes  lista gerada por TecladoVirtual.gerarCombinacoes()
     * @return resultado da verificação
     */
    public ResultadoEtapa2 verificarSenha(java.util.List<String> combinacoes) {
        if (usuarioAtual == null) {
            throw new IllegalStateException("Etapa 1 não foi concluída.");
        }

        RegistroDAO.registrar(3001, usuarioAtual.getUid(), null);

        // Testar cada combinação possível contra o hash bcrypt
        String senhaCorreta = null;
        for (String combinacao : combinacoes) {
            if (BcryptUtils.verificar(usuarioAtual.getSenhaBcrypt(), combinacao)) {
                senhaCorreta = combinacao;
                break;
            }
        }

        if (senhaCorreta != null) {
            // Guardar senha em texto plano para decifrar o TOTP na etapa 3
            senhaTextoPlano = senhaCorreta;
            errosSenha = 0;

            RegistroDAO.registrar(3003, usuarioAtual.getUid(), null);
            RegistroDAO.registrar(3002, usuarioAtual.getUid(), null);
            return ResultadoEtapa2.SUCESSO;
        }

        // Nenhuma combinação bateu — senha incorreta
        errosSenha++;
        int midErro = 3003 + errosSenha; // 3004, 3005, 3006
        RegistroDAO.registrar(midErro, usuarioAtual.getUid(), null);

        if (errosSenha >= 3) {
            bloquearUsuario();
            RegistroDAO.registrar(3007, usuarioAtual.getUid(), null);
            RegistroDAO.registrar(3002, usuarioAtual.getUid(), null);
            errosSenha = 0;
            return ResultadoEtapa2.BLOQUEADO;
        }

        RegistroDAO.registrar(3002, usuarioAtual.getUid(), null);
        return ResultadoEtapa2.SENHA_INCORRETA;
    }

    // =========================================================================
    // ETAPA 3 — código TOTP via Google Authenticator
    // =========================================================================

    /**
     * Resultado da etapa 3.
     */
    public enum ResultadoEtapa3 {
        /** TOTP correto — acesso liberado */
        SUCESSO,
        /** TOTP incorreto — ainda tem tentativas */
        TOKEN_INVALIDO,
        /** TOTP incorreto 3 vezes — usuário bloqueado */
        BLOQUEADO
    }

    /**
     * Processa a etapa 3: verifica o código TOTP de 6 dígitos.
     *
     * A chave TOTP está cifrada no banco com AES derivado da senha pessoal.
     * Como a senha correta foi guardada na etapa 2, conseguimos decifrar.
     *
     * Registros gerados:
     *   4001 — etapa 3 iniciada
     *   4003 — token verificado positivamente
     *   4004/4005/4006 — 1º/2º/3º erro
     *   4007 — usuário bloqueado
     *   4002 — etapa 3 encerrada
     *
     * @param codigoTotp  String de 6 dígitos do Google Authenticator
     * @return resultado da verificação
     */
    public ResultadoEtapa3 verificarTotp(String codigoTotp) {
        if (usuarioAtual == null || senhaTextoPlano == null) {
            throw new IllegalStateException("Etapa 2 não foi concluída.");
        }

        RegistroDAO.registrar(4001, usuarioAtual.getUid(), null);

        try {
            // Decifrar a chave TOTP do banco usando a senha da etapa 2
            TOTP totp = TotpUtils.criarTOTP(
                usuarioAtual.getTotpEnc(), senhaTextoPlano
            );

            boolean totpValido = totp.validateCode(codigoTotp);

            if (totpValido) {
                errosTotp = 0;
                RegistroDAO.registrar(4003, usuarioAtual.getUid(), null);
                RegistroDAO.registrar(4002, usuarioAtual.getUid(), null);

                // Autenticação completa — incrementar total de acessos
                usuarioDAO.incrementarAcessos(usuarioAtual.getUid());

                // Limpar senha da memória (não precisa mais)
                senhaTextoPlano = null;

                return ResultadoEtapa3.SUCESSO;
            }

            // Token inválido — contabilizar erro
            errosTotp++;
            int midErro = 4003 + errosTotp; // 4004, 4005, 4006
            RegistroDAO.registrar(midErro, usuarioAtual.getUid(), null);

            if (errosTotp >= 3) {
                bloquearUsuario();
                RegistroDAO.registrar(4007, usuarioAtual.getUid(), null);
                RegistroDAO.registrar(4002, usuarioAtual.getUid(), null);
                errosTotp = 0;
                senhaTextoPlano = null;
                return ResultadoEtapa3.BLOQUEADO;
            }

            RegistroDAO.registrar(4002, usuarioAtual.getUid(), null);
            return ResultadoEtapa3.TOKEN_INVALIDO;

        } catch (Exception e) {
            System.err.println("Erro na etapa 3: " + e.getMessage());
            RegistroDAO.registrar(4002, usuarioAtual.getUid(), null);
            return ResultadoEtapa3.TOKEN_INVALIDO;
        }
    }

    // =========================================================================
    // SESSÃO
    // =========================================================================

    /**
     * Retorna o usuário autenticado após as 3 etapas.
     * Usado pela UI para montar a tela principal.
     */
    public Usuario getUsuarioAutenticado() {
        return usuarioAtual;
    }

    /**
     * Encerra a sessão do usuário atual.
     * Registra msg 1004 e limpa o estado.
     */
    public void encerrarSessao() {
        if (usuarioAtual != null) {
            RegistroDAO.registrar(1004, usuarioAtual.getUid(), null);
        }
        usuarioAtual    = null;
        senhaTextoPlano = null;
        errosSenha      = 0;
        errosTotp       = 0;
    }

    /**
     * Registra início de sessão (msg 1003).
     * Chamado pela UI logo após autenticação positiva nas 3 etapas.
     */
    public void registrarInicioSessao() {
        if (usuarioAtual != null) {
            RegistroDAO.registrar(1003, usuarioAtual.getUid(), null);
        }
    }

    // =========================================================================
    // HELPERS INTERNOS
    // =========================================================================

    /**
     * Verifica se o usuário está bloqueado no momento atual.
     * Compara o campo bloqueado_ate com o horário atual.
     */
    private boolean estaBloqueado(Usuario usuario) {
        if (usuario.getBloqueadoAte() == null) return false;
        return usuario.getBloqueadoAte().after(Timestamp.from(Instant.now()));
    }

    /**
     * Bloqueia o usuário atual por 2 minutos.
     */
    private void bloquearUsuario() {
        try {
            usuarioDAO.bloquearUsuario(usuarioAtual.getUid(), 2);
        } catch (Exception e) {
            System.err.println("Erro ao bloquear usuário: " + e.getMessage());
        }
    }
}
