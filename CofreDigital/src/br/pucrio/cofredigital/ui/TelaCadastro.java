// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.ui;

import br.pucrio.cofredigital.auth.AuthController;
import br.pucrio.cofredigital.crypto.CadastroService;
import br.pucrio.cofredigital.crypto.CadastroService.ResultadoCadastro;
import br.pucrio.cofredigital.db.RegistroDAO;
import br.pucrio.cofredigital.model.Usuario;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Tela de Cadastro de Usuário.
 *
 * Usada em dois contextos:
 *   1. Primeira execução — cadastro do administrador (modoAdmin = true)
 *      → grupo fixo em Administrador, não pode mudar
 *      → após cadastro, salva chave em memória e abre TelaLogin
 *
 *   2. Admin cadastrando novo usuário (modoAdmin = false)
 *      → grupo selecionável (Admin ou Usuário)
 *      → após cadastro, volta ao menu principal
 *
 * Fluxo interno:
 *   Formulário → validarFormulario() → tela de confirmação → efetivarCadastro()
 *   → tela TOTP BASE32 → próxima tela
 */
public class TelaCadastro extends JFrame {

    private final AuthController auth;
    private final Usuario        usuarioLogado; // null se primeira execução
    private final boolean        modoAdmin;     // true = primeiro cadastro

    private final CadastroService cadastroService = new CadastroService();

    // Campos do formulário
    private JTextField     campoCertificado;
    private JTextField     campoChavePrivada;
    private JPasswordField campoFrase;
    private JPasswordField campoSenha;
    private JPasswordField campoConfirmacao;
    private JComboBox<String> comboGrupo;
    private JLabel         labelStatus;

    // Dados guardados entre as etapas (validação → confirmação → efetivação)
    private String caminhoCertSalvo;
    private String caminhoChaveSalvo;
    private String fraseSalva;
    private String senhaSalva;
    private int    gidSalvo;

    public TelaCadastro(AuthController auth, Usuario usuarioLogado, boolean modoAdmin) {
        this.auth          = auth;
        this.usuarioLogado = usuarioLogado;
        this.modoAdmin     = modoAdmin;
        configurarJanela();
        construirUI();

        // Registrar: tela de cadastro apresentada
        int uid = (usuarioLogado != null) ? usuarioLogado.getUid() : 0;
        RegistroDAO.registrar(6001, uid > 0 ? uid : null, null);
    }

    private void configurarJanela() {
        setTitle("Cofre Digital — Cadastro de Usuário");
        setSize(620, 520);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setResizable(false);
        getContentPane().setBackground(TelasAutenticacao.COR_FUNDO);
    }

    private void construirUI() {
        setLayout(new BorderLayout(0, 0));

        // ── Cabeçalho ────────────────────────────────────────────────────────
        String subtitulo = modoAdmin
            ? "CADASTRO DO ADMINISTRADOR"
            : "CADASTRO DE NOVO USUÁRIO";
        add(TelasAutenticacao.criarCabecalho("COFRE DIGITAL", subtitulo), BorderLayout.NORTH);

        // ── Corpo: cabeçalho do usuário logado (se houver) + formulário ──────
        JPanel corpo = new JPanel(new BorderLayout(0, 0));
        corpo.setBackground(TelasAutenticacao.COR_FUNDO);

        if (!modoAdmin && usuarioLogado != null) {
            corpo.add(criarInfoUsuario(), BorderLayout.NORTH);
        }

        corpo.add(criarFormulario(), BorderLayout.CENTER);
        add(corpo, BorderLayout.CENTER);

        // ── Rodapé com botões ────────────────────────────────────────────────
        add(criarBotoes(), BorderLayout.SOUTH);
    }

    // =========================================================================
    // INFO DO USUÁRIO LOGADO (cabeçalho interno, só quando não é modo admin)
    // =========================================================================

    private JPanel criarInfoUsuario() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 8));
        p.setBackground(TelasAutenticacao.COR_PAINEL);
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, TelasAutenticacao.COR_BORDA));

        p.add(labelInfo("Login: " + usuarioLogado.getLoginName()));
        p.add(labelInfo("Grupo: " + (usuarioLogado.getGid() == 1 ? "Administrador" : "Usuário")));
        p.add(labelInfo("Nome: "  + usuarioLogado.getNomeUsuario()));
        return p;
    }

    private JLabel labelInfo(String texto) {
        JLabel l = new JLabel(texto);
        l.setFont(TelasAutenticacao.FONTE_LABEL);
        l.setForeground(TelasAutenticacao.COR_TEXTO_DIM);
        return l;
    }

    // =========================================================================
    // FORMULÁRIO
    // =========================================================================

    private JPanel criarFormulario() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(TelasAutenticacao.COR_FUNDO);
        form.setBorder(BorderFactory.createEmptyBorder(16, 32, 8, 32));

        GridBagConstraints lbl = new GridBagConstraints();
        lbl.anchor = GridBagConstraints.WEST;
        lbl.insets = new Insets(6, 0, 2, 8);
        lbl.gridx = 0; lbl.gridy = 0;

        GridBagConstraints fld = new GridBagConstraints();
        fld.fill = GridBagConstraints.HORIZONTAL;
        fld.weightx = 1.0;
        fld.insets = new Insets(6, 0, 2, 0);
        fld.gridx = 1; fld.gridy = 0;

        GridBagConstraints btn = new GridBagConstraints();
        btn.insets = new Insets(6, 4, 2, 0);
        btn.gridx = 2; btn.gridy = 0;

        // ── Certificado digital ───────────────────────────────────────────────
        form.add(rotulo("Certificado digital (.crt):"), pos(lbl, 0));
        campoCertificado = campo(40);
        form.add(campoCertificado, pos(fld, 0));
        JButton btnCert = botaoNavegar("...");
        btnCert.addActionListener(e -> navegarArquivo(campoCertificado,
            "Certificado X.509", "crt", "pem"));
        form.add(btnCert, pos(btn, 0));

        // ── Chave privada ─────────────────────────────────────────────────────
        form.add(rotulo("Chave privada (.key):"), pos(lbl, 1));
        campoChavePrivada = campo(40);
        form.add(campoChavePrivada, pos(fld, 1));
        JButton btnChave = botaoNavegar("...");
        btnChave.addActionListener(e -> navegarArquivo(campoChavePrivada,
            "Chave Privada", "key"));
        form.add(btnChave, pos(btn, 1));

        // ── Frase secreta ─────────────────────────────────────────────────────
        form.add(rotulo("Frase secreta:"), pos(lbl, 2));
        campoFrase = campoSenha(40);
        form.add(campoFrase, pos(fld, 2));

        // ── Grupo ─────────────────────────────────────────────────────────────
        form.add(rotulo("Grupo:"), pos(lbl, 3));
        comboGrupo = new JComboBox<>(new String[]{"Administrador", "Usuário"});
        comboGrupo.setFont(TelasAutenticacao.FONTE_MONO);
        comboGrupo.setBackground(TelasAutenticacao.COR_PAINEL);
        comboGrupo.setForeground(TelasAutenticacao.COR_TEXTO);
        if (modoAdmin) {
            comboGrupo.setSelectedIndex(0);
            comboGrupo.setEnabled(false); // admin não pode mudar o grupo na 1ª execução
        }
        form.add(comboGrupo, pos(fld, 3));

        // ── Senha pessoal ─────────────────────────────────────────────────────
        form.add(rotulo("Senha pessoal (8-10 dígitos):"), pos(lbl, 4));
        campoSenha = campoSenha(40);
        form.add(campoSenha, pos(fld, 4));

        // ── Confirmação ───────────────────────────────────────────────────────
        form.add(rotulo("Confirmação da senha:"), pos(lbl, 5));
        campoConfirmacao = campoSenha(40);
        form.add(campoConfirmacao, pos(fld, 5));

        // ── Status ────────────────────────────────────────────────────────────
        labelStatus = new JLabel(" ");
        labelStatus.setFont(TelasAutenticacao.FONTE_LABEL);
        labelStatus.setForeground(TelasAutenticacao.COR_ERRO);
        GridBagConstraints statusGbc = new GridBagConstraints();
        statusGbc.gridx = 0; statusGbc.gridy = 6;
        statusGbc.gridwidth = 3;
        statusGbc.fill = GridBagConstraints.HORIZONTAL;
        statusGbc.insets = new Insets(10, 0, 0, 0);
        form.add(labelStatus, statusGbc);

        return form;
    }

    // =========================================================================
    // BOTÕES DO RODAPÉ
    // =========================================================================

    private JPanel criarBotoes() {
        JPanel p = new JPanel(new GridLayout(1, 2, 12, 0));
        p.setBackground(TelasAutenticacao.COR_FUNDO);
        p.setBorder(BorderFactory.createEmptyBorder(8, 32, 16, 32));

        JButton btnCadastrar = TelasAutenticacao.criarBotao("[ CADASTRAR ]");
        btnCadastrar.setForeground(TelasAutenticacao.COR_ACENTO);
        btnCadastrar.addActionListener(e -> processarCadastro());

        JButton btnVoltar = TelasAutenticacao.criarBotao("[ VOLTAR ]");
        btnVoltar.addActionListener(e -> voltar());

        if (modoAdmin) {
            btnVoltar.setEnabled(false); // não pode voltar na 1ª execução
        }

        p.add(btnCadastrar);
        p.add(btnVoltar);
        return p;
    }

    // =========================================================================
    // LÓGICA DE CADASTRO
    // =========================================================================

    private void processarCadastro() {
        String caminhoCert  = campoCertificado.getText().trim();
        String caminhoChave = campoChavePrivada.getText().trim();
        String frase        = new String(campoFrase.getPassword()).trim();
        String senha        = new String(campoSenha.getPassword());
        String confirmacao  = new String(campoConfirmacao.getPassword());
        int    gid          = comboGrupo.getSelectedIndex() == 0 ? 1 : 2;

        // Registrar: botão cadastrar pressionado
        Integer uid = (usuarioLogado != null) ? usuarioLogado.getUid() : null;
        RegistroDAO.registrar(6002, uid, null);

        // Validações básicas de campo vazio
        if (caminhoCert.isEmpty() || caminhoChave.isEmpty() || frase.isEmpty()
                || senha.isEmpty() || confirmacao.isEmpty()) {
            setStatus("Preencha todos os campos.", false);
            return;
        }

        setStatus("Validando dados...", true);

        // Chamar o CadastroService para validar
        ResultadoCadastro resultado = cadastroService.validarFormulario(
            caminhoCert, caminhoChave, frase, senha, confirmacao, gid
        );

        if (!resultado.sucesso) {
            // Registrar o tipo de erro
            registrarErroCadastro(resultado.mensagemErro, uid);
            setStatus(resultado.mensagemErro, false);
            return;
        }

        // Guardar dados para usar após confirmação
        caminhoCertSalvo  = caminhoCert;
        caminhoChaveSalvo = caminhoChave;
        fraseSalva        = frase;
        senhaSalva        = senha;
        gidSalvo          = gid;

        // Mostrar tela de confirmação dos dados do certificado
        mostrarConfirmacao(resultado);
    }

    private void registrarErroCadastro(String mensagem, Integer uid) {
        if (mensagem == null) return;
        if (mensagem.contains("senha") || mensagem.contains("Senha")) {
            RegistroDAO.registrar(6003, uid, null);
        } else if (mensagem.contains("certificado")) {
            RegistroDAO.registrar(6004, uid, null);
        } else if (mensagem.contains("caminho inválido")) {
            RegistroDAO.registrar(6005, uid, null);
        } else if (mensagem.contains("frase secreta") || mensagem.contains("Frase")) {
            RegistroDAO.registrar(6006, uid, null);
        } else if (mensagem.contains("Assinatura") || mensagem.contains("assinatura")) {
            RegistroDAO.registrar(6007, uid, null);
        }
    }

    // =========================================================================
    // TELA DE CONFIRMAÇÃO DOS DADOS DO CERTIFICADO
    // =========================================================================

    private void mostrarConfirmacao(ResultadoCadastro resultado) {
        String mensagem = String.format(
            "Confirme os dados do certificado:\n\n" +
            "  Versão:     %s\n" +
            "  Série:      %s\n" +
            "  Validade:   %s\n" +
            "  Assinatura: %s\n" +
            "  Emissor:    %s\n" +
            "  Subject:    %s\n" +
            "  E-mail:     %s\n\n" +
            "Deseja confirmar o cadastro?",
            resultado.certVersao,
            resultado.certSerie,
            resultado.certValidade,
            resultado.certAssinatura,
            resultado.certEmissor,
            resultado.certSubject,
            resultado.certEmail
        );

        int opcao = JOptionPane.showConfirmDialog(
            this, mensagem, "Confirmação de Dados",
            JOptionPane.YES_NO_OPTION, JOptionPane.PLAIN_MESSAGE
        );

        Integer uid = (usuarioLogado != null) ? usuarioLogado.getUid() : null;

        if (opcao == JOptionPane.YES_OPTION) {
            RegistroDAO.registrar(6008, uid, null);
            efetivarCadastro();
        } else {
            RegistroDAO.registrar(6009, uid, null);
            setStatus("Cadastro cancelado pelo usuário.", false);
        }
    }

    // =========================================================================
    // EFETIVAR O CADASTRO
    // =========================================================================

    private void efetivarCadastro() {
        setStatus("Cadastrando usuário...", true);

        ResultadoCadastro resultado = cadastroService.efetivarCadastro(
            caminhoCertSalvo, caminhoChaveSalvo, fraseSalva, senhaSalva, gidSalvo
        );

        if (!resultado.sucesso) {
            setStatus("Erro: " + resultado.mensagemErro, false);
            return;
        }

        // Cadastro realizado — mostrar chave TOTP para o Google Authenticator
        mostrarChaveTotp(resultado);
    }

    // =========================================================================
    // MOSTRAR CHAVE TOTP APÓS CADASTRO
    // =========================================================================

    private void mostrarChaveTotp(ResultadoCadastro resultado) {
        JPanel painelTotp = new JPanel(new BorderLayout(0, 12));
        painelTotp.setBackground(TelasAutenticacao.COR_FUNDO);

        JLabel lblTitulo = new JLabel("Cadastro realizado com sucesso!");
        lblTitulo.setFont(TelasAutenticacao.FONTE_TITULO);
        lblTitulo.setForeground(TelasAutenticacao.COR_ACENTO);
        painelTotp.add(lblTitulo, BorderLayout.NORTH);

        JTextArea txtArea = new JTextArea();
        txtArea.setEditable(false);
        txtArea.setFont(TelasAutenticacao.FONTE_MONO);
        txtArea.setBackground(TelasAutenticacao.COR_PAINEL);
        txtArea.setForeground(TelasAutenticacao.COR_TEXTO);
        txtArea.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        txtArea.setText(
            "Usuário: " + resultado.emailExtraido + "\n\n" +
            "Configure o Google Authenticator com a chave abaixo:\n\n" +
            "  " + resultado.totpBase32 + "\n\n" +
            "Ou use o URI para QR Code:\n" +
            resultado.totpQRCodeUri
        );
        painelTotp.add(new JScrollPane(txtArea), BorderLayout.CENTER);

        JButton btnCopiar = TelasAutenticacao.criarBotao("[ COPIAR CHAVE BASE32 ]");
        btnCopiar.addActionListener(e -> {
            StringSelection sel = new StringSelection(resultado.totpBase32);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
            btnCopiar.setText("[ COPIADO! ]");
        });
        painelTotp.add(btnCopiar, BorderLayout.SOUTH);

        JOptionPane.showMessageDialog(this, painelTotp,
            "Chave TOTP — Google Authenticator",
            JOptionPane.PLAIN_MESSAGE);

        // Pós-cadastro: decidir próxima tela
        if (modoAdmin) {
            // Primeira execução: guardar frase/chave do admin em memória e abrir login
            try {
                br.pucrio.cofredigital.crypto.CryptoUtils cv =
                    new br.pucrio.cofredigital.crypto.CryptoUtils();
                // Recarregar usuário do banco para pegar o UID
                br.pucrio.cofredigital.db.UsuarioDAO uDAO =
                    new br.pucrio.cofredigital.db.UsuarioDAO();
                br.pucrio.cofredigital.model.Usuario admin = uDAO.findAdmin();
                br.pucrio.cofredigital.db.ChaveiroDAO cDAO =
                    new br.pucrio.cofredigital.db.ChaveiroDAO();
                br.pucrio.cofredigital.model.Chaveiro chaveiro =
                    cDAO.findByKid(admin.getKid());

                java.security.PrivateKey chavePrivada =
                    br.pucrio.cofredigital.crypto.CryptoUtils.lerChavePrivadaDosBytes(
                        chaveiro.getChavePrivadaBin(), fraseSalva
                    );
                br.pucrio.cofredigital.Main.setChavePrivadaAdmin(chavePrivada, fraseSalva);
            } catch (Exception e) {
                System.err.println("Aviso: não foi possível carregar chave do admin: " + e.getMessage());
            }

            JOptionPane.showMessageDialog(this,
                "Cadastro do Administrador concluído!\n" +
                "Configure o Google Authenticator e faça login.",
                "Bem-vindo", JOptionPane.INFORMATION_MESSAGE);

            new TelasAutenticacao.TelaLogin(auth).setVisible(true);
            dispose();

        } else {
            // Admin cadastrando outro usuário: limpar formulário e continuar
            limparFormulario();
            setStatus("Usuário " + resultado.emailExtraido + " cadastrado com sucesso!", true);
        }
    }

    // =========================================================================
    // VOLTAR
    // =========================================================================

    private void voltar() {
        Integer uid = (usuarioLogado != null) ? usuarioLogado.getUid() : null;
        RegistroDAO.registrar(6010, uid, null);

        if (usuarioLogado != null) {
            new TelaPrincipal(auth, usuarioLogado).setVisible(true);
        }
        dispose();
    }

    // =========================================================================
    // UTILITÁRIOS DE UI
    // =========================================================================

    private void navegarArquivo(JTextField campo, String descricao, String... extensoes) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Selecionar " + descricao);
        fc.setFileFilter(new FileNameExtensionFilter(descricao, extensoes));
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            campo.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private void setStatus(String texto, boolean ok) {
        labelStatus.setText(texto);
        labelStatus.setForeground(ok ? TelasAutenticacao.COR_ACENTO : TelasAutenticacao.COR_ERRO);
    }

    private void limparFormulario() {
        campoCertificado.setText("");
        campoChavePrivada.setText("");
        campoFrase.setText("");
        campoSenha.setText("");
        campoConfirmacao.setText("");
        if (!modoAdmin) comboGrupo.setSelectedIndex(0);
        labelStatus.setText(" ");
    }

    // ── Helpers de componentes ────────────────────────────────────────────────

    private JLabel rotulo(String texto) {
        JLabel l = new JLabel(texto);
        l.setFont(TelasAutenticacao.FONTE_LABEL);
        l.setForeground(TelasAutenticacao.COR_TEXTO_DIM);
        return l;
    }

    private JTextField campo(int colunas) {
        JTextField f = new JTextField(colunas);
        TelasAutenticacao.estilizarCampo(f);
        return f;
    }

    private JPasswordField campoSenha(int colunas) {
        JPasswordField f = new JPasswordField(colunas);
        f.setFont(TelasAutenticacao.FONTE_MONO);
        f.setBackground(TelasAutenticacao.COR_PAINEL);
        f.setForeground(TelasAutenticacao.COR_TEXTO);
        f.setCaretColor(TelasAutenticacao.COR_ACENTO);
        f.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(TelasAutenticacao.COR_BORDA, 1),
            BorderFactory.createEmptyBorder(8, 12, 8, 12)
        ));
        return f;
    }

    private JButton botaoNavegar(String texto) {
        JButton b = new JButton(texto);
        b.setFont(TelasAutenticacao.FONTE_BOTAO);
        b.setBackground(TelasAutenticacao.COR_PAINEL);
        b.setForeground(TelasAutenticacao.COR_ACENTO);
        b.setFocusPainted(false);
        b.setPreferredSize(new Dimension(40, 34));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return b;
    }

    private GridBagConstraints pos(GridBagConstraints base, int linha) {
        GridBagConstraints c = (GridBagConstraints) base.clone();
        c.gridy = linha;
        return c;
    }
}
