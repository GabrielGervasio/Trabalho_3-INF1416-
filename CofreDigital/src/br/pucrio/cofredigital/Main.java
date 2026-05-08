package br.pucrio.cofredigital;

import br.pucrio.cofredigital.crypto.*;
import br.pucrio.cofredigital.db.*;
import br.pucrio.cofredigital.model.*;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Ponto de entrada do sistema Cofre Digital.
 *
 * Lógica de partida conforme o enunciado:
 *
 * PRIMEIRA EXECUÇÃO (nenhum usuário no banco):
 *   → Registrar msg 1005
 *   → Entrar no fluxo de cadastro do administrador
 *   → Manter frase secreta do admin em memória
 *   → Iniciar autenticação de usuários
 *
 * SEGUNDA EXECUÇÃO EM DIANTE:
 *   → Registrar msg 1006
 *   → Pedir frase secreta da chave privada do admin
 *   → Validar (assinar 9216 bytes e verificar com chave pública do cert)
 *   → Se inválida: notificar e encerrar
 *   → Se válida: manter em memória e iniciar autenticação
 *
 * Ao encerrar: apagar chave privada da memória (msg 1002)
 */
public class Main {

    // Chave privada do admin mantida em memória durante a execução
    // Apagada quando o sistema encerrar
    private static PrivateKey chavePrivadaAdmin = null;
    private static String fraseSecretaAdmin     = null;

    public static void main(String[] args) {
        // ── 1. Inicializar banco de dados ─────────────────────────────────
        DatabaseConnection.initializeDatabase();
        DatabaseInitializer.initializeGroups();
        DatabaseInitializer.initializeMessages();

        // Registrar: sistema iniciado (msg 1001)
        RegistroDAO.registrar(1001, null, null);

        // ── 2. Detectar se é primeira execução ───────────────────────────
        boolean primeiraExecucao = false;
        try {
            primeiraExecucao = new UsuarioDAO().count() == 0;
        } catch (Exception e) {
            System.err.println("Erro ao verificar usuários: " + e.getMessage());
            encerrar(1);
        }

        // ── 3. Fluxo de partida ───────────────────────────────────────────
        if (primeiraExecucao) {
            // Registrar: partida para cadastro do admin (msg 1005)
            RegistroDAO.registrar(1005, null, null);
            iniciarCadastroAdmin();
        } else {
            // Registrar: partida para operação normal (msg 1006)
            RegistroDAO.registrar(1006, null, null);
            validarAdminEIniciar();
        }
    }

    // =========================================================================
    // PRIMEIRA EXECUÇÃO — cadastro do administrador
    // =========================================================================

    /**
     * Chamado somente na primeira execução, quando não há nenhum usuário no banco.
     * Abre a tela de cadastro já configurada para o grupo Administrador.
     * Após o cadastro, inicia a autenticação normalmente.
     */
    private static void iniciarCadastroAdmin() {
        System.out.println("[PARTIDA] Primeira execução — cadastro do administrador.");

        // TODO: abrir a TelaCadastro em modo "primeiro admin"
        // A tela de cadastro deve:
        //   1. Pedir: cert.pem, chave.key, frase secreta, senha pessoal
        //   2. Chamar CadastroService.validarFormulario(...)
        //   3. Mostrar dados do certificado para confirmação
        //   4. Chamar CadastroService.efetivarCadastro(...)
        //   5. Guardar a frase secreta em memória (fraseSecretaAdmin)
        //   6. Carregar a chave privada em memória (chavePrivadaAdmin)
        //   7. Chamar iniciarAutenticacao()
        //
        // Por enquanto, placeholder até a UI estar pronta:
        System.out.println("[TODO] Abrir TelaCadastroAdmin");
    }

    // =========================================================================
    // SEGUNDA EXECUÇÃO EM DIANTE — validar admin e iniciar
    // =========================================================================

    /**
     * Pedido da frase secreta do admin e validação da chave privada.
     * Conforme enunciado:
     *   - Pedir frase secreta
     *   - Validar (assinar 9216 bytes e verificar com chave pública do cert)
     *   - Se negativa: notificar e encerrar
     *   - Se positiva: manter em memória e iniciar autenticação
     */
    private static void validarAdminEIniciar() {
        System.out.println("[PARTIDA] Operação normal — validando administrador.");

        // Buscar o admin no banco (GID = 1)
        Usuario admin = null;
        try {
            admin = new UsuarioDAO().findAdmin();
        } catch (Exception e) {
            System.err.println("Erro ao buscar admin no banco: " + e.getMessage());
            encerrar(1);
        }

        if (admin == null) {
            System.err.println("Administrador não encontrado no banco.");
            encerrar(1);
        }

        // Buscar o chaveiro do admin (certificado + chave privada)
        Chaveiro chaveiro = null;
        try {
            chaveiro = new ChaveiroDAO().findByKid(admin.getKid());
        } catch (Exception e) {
            System.err.println("Erro ao buscar chaveiro do admin: " + e.getMessage());
            encerrar(1);
        }

        if (chaveiro == null) {
            System.err.println("Chaveiro do administrador não encontrado.");
            encerrar(1);
        }

        // TODO: quando a UI estiver pronta, a frase secreta virá de um
        //       JPasswordField na tela de partida.
        //       Por enquanto, lemos do console para testes.
        String frase = lerFraseSecretaConsole("Digite a frase secreta da chave privada do administrador: ");

        // Tentar decriptar a chave privada com a frase fornecida
        PrivateKey chavePrivada = null;
        try {
            // A chave privada está armazenada como bytes cifrados no banco
            // Precisamos salvá-la em um arquivo temporário ou adaptar o método
            // para receber bytes diretamente
            chavePrivada = CryptoUtils.lerChavePrivadaDosBytes(
                chaveiro.getChavePrivadaBin(), frase
            );
        } catch (Exception e) {
            // Frase errada ou chave corrompida
            System.err.println("Validação da chave privada negativa: " + e.getMessage());
            System.err.println("Sistema encerrado.");
            encerrar(1);
        }

        // Validar a chave privada: assinar 9216 bytes e verificar com cert
        try {
            X509Certificate cert = CryptoUtils.certificadoDePEM(chaveiro.getCertPem());
            boolean valida = CryptoUtils.validarChavePrivada(
                chavePrivada, cert.getPublicKey(), 9216
            );

            if (!valida) {
                System.err.println("Validação da chave privada negativa — assinatura inválida.");
                System.err.println("Sistema encerrado.");
                encerrar(1);
            }

        } catch (Exception e) {
            System.err.println("Erro na validação: " + e.getMessage());
            encerrar(1);
        }

        // Validação positiva — manter em memória
        chavePrivadaAdmin = chavePrivada;
        fraseSecretaAdmin = frase;

        System.out.println("[OK] Administrador validado. Iniciando autenticação...");

        // Iniciar o fluxo de autenticação de usuários
        iniciarAutenticacao();
    }

    // =========================================================================
    // INICIAR AUTENTICAÇÃO
    // =========================================================================

    /**
     * Ponto de entrada para o fluxo de autenticação.
     * Chamado após a partida do sistema (com ou sem cadastro inicial do admin).
     *
     * TODO: quando a UI estiver pronta, este método abre a TelaLogin.
     */
    private static void iniciarAutenticacao() {
        System.out.println("[SISTEMA] Iniciando fluxo de autenticação...");

        // TODO: abrir TelaLogin (etapa 1)
        // A TelaLogin vai:
        //   1. Pedir o e-mail (login name)
        //   2. Se válido → TelaKeyboard (etapa 2 — teclado virtual)
        //   3. Se senha ok → TelaTOTP (etapa 3 — Google Authenticator)
        //   4. Se TOTP ok → TelaPrincipal (menu admin ou usuário)
        System.out.println("[TODO] Abrir TelaLogin");
    }

    // =========================================================================
    // ENCERRAMENTO DO SISTEMA
    // =========================================================================

    /**
     * Encerra o sistema de forma segura:
     *   - Apaga a chave privada e frase secreta da memória
     *   - Registra msg 1002 (sistema encerrado)
     *   - Fecha conexão com o banco
     */
    public static void encerrar(int codigoSaida) {
        // Apagar chave privada da memória (requisito de segurança do enunciado)
        chavePrivadaAdmin = null;
        fraseSecretaAdmin = null;

        // Registrar: sistema encerrado (msg 1002)
        RegistroDAO.registrar(1002, null, null);

        DatabaseConnection.closeConnection();
        System.exit(codigoSaida);
    }

    // =========================================================================
    // GETTERS — para outros módulos acessarem a chave do admin em memória
    // =========================================================================

    /**
     * Retorna a chave privada do admin mantida em memória.
     * Usada pelo módulo de consulta de arquivos para abrir envelopes do índice.
     */
    public static PrivateKey getChavePrivadaAdmin() {
        return chavePrivadaAdmin;
    }

    /**
     * Define a chave privada do admin em memória.
     * Chamado após cadastro ou validação bem-sucedida.
     */
    public static void setChavePrivadaAdmin(PrivateKey chave, String frase) {
        chavePrivadaAdmin = chave;
        fraseSecretaAdmin = frase;
    }

    // =========================================================================
    // UTILITÁRIO — ler frase secreta do console (sem eco)
    // =========================================================================

    /**
     * Lê a frase secreta do console sem exibir os caracteres digitados.
     * Quando a UI estiver pronta, este método não será mais necessário.
     */
    private static String lerFraseSecretaConsole(String prompt) {
        System.out.print(prompt);
        java.io.Console console = System.console();
        if (console != null) {
            // Console real — lê sem eco (seguro)
            char[] chars = console.readPassword();
            return new String(chars);
        } else {
            // IDE ou ambiente sem console — lê com echo (só para desenvolvimento)
            System.out.println("[AVISO] Console não disponível — entrada visível (modo dev)");
            java.util.Scanner scanner = new java.util.Scanner(System.in);
            return scanner.nextLine();
        }
    }
}
