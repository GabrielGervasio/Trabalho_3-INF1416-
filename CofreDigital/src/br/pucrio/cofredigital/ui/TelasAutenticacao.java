package br.pucrio.cofredigital.ui;

import br.pucrio.cofredigital.auth.AuthController;
import br.pucrio.cofredigital.auth.AuthController.ResultadoEtapa1;
import br.pucrio.cofredigital.auth.AuthController.ResultadoEtapa2;
import br.pucrio.cofredigital.auth.AuthController.ResultadoEtapa3;
import br.pucrio.cofredigital.auth.TecladoVirtual;
import br.pucrio.cofredigital.model.Usuario;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.RoundRectangle2D;
import java.util.List;

/**
 * Telas de autenticação do Cofre Digital.
 *
 * Contém três classes internas estáticas:
 *   - TelaLogin      → etapa 1 (e-mail)
 *   - TecladoUI      → etapa 2 (teclado virtual sobrecarregado)
 *   - TelaTOTP       → etapa 3 (código Google Authenticator)
 *
 * Estética: industrial/seguro — fundo escuro, detalhes em verde terminal,
 * tipografia monoespaçada, bordas nítidas. Transmite seriedade e controle.
 */
public class TelasAutenticacao {

    // ── Paleta de cores ───────────────────────────────────────────────────────
    static final Color COR_FUNDO       = new Color(0x0D0D0D);
    static final Color COR_PAINEL      = new Color(0x1A1A1A);
    static final Color COR_BORDA       = new Color(0x2A2A2A);
    static final Color COR_ACENTO      = new Color(0x00E676); // verde terminal
    static final Color COR_ACENTO2     = new Color(0x00897B); // verde escuro
    static final Color COR_TEXTO       = new Color(0xE0E0E0);
    static final Color COR_TEXTO_DIM   = new Color(0x757575);
    static final Color COR_ERRO        = new Color(0xFF5252);
    static final Color COR_BOTAO       = new Color(0x222222);
    static final Color COR_BOTAO_HOVER = new Color(0x2E7D32);

    // ── Fontes ────────────────────────────────────────────────────────────────
    static final Font FONTE_MONO    = new Font("Courier New", Font.PLAIN, 13);
    static final Font FONTE_TITULO  = new Font("Courier New", Font.BOLD,  18);
    static final Font FONTE_LABEL   = new Font("Courier New", Font.PLAIN, 12);
    static final Font FONTE_BOTAO   = new Font("Courier New", Font.BOLD,  13);
    static final Font FONTE_GRANDE  = new Font("Courier New", Font.BOLD,  28);

    // =========================================================================
    // ETAPA 1 — TelaLogin
    // =========================================================================

    public static class TelaLogin extends JFrame {

        private final AuthController auth;
        private JTextField campoEmail;
        private JLabel labelStatus;

        public TelaLogin(AuthController auth) {
            this.auth = auth;
            configurarJanela();
            construirUI();
        }

        private void configurarJanela() {
            setTitle("Cofre Digital — Autenticação");
            setSize(480, 340);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setResizable(false);
            getContentPane().setBackground(COR_FUNDO);
        }

        private void construirUI() {
            setLayout(new BorderLayout());

            // ── Cabeçalho ────────────────────────────────────────────────────
            JPanel cabecalho = criarCabecalho("COFRE DIGITAL", "ETAPA 1 DE 3 — IDENTIFICAÇÃO");
            add(cabecalho, BorderLayout.NORTH);

            // ── Corpo ────────────────────────────────────────────────────────
            JPanel corpo = new JPanel();
            corpo.setBackground(COR_FUNDO);
            corpo.setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(8, 40, 8, 40);
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.gridwidth = GridBagConstraints.REMAINDER;

            // Instrução
            JLabel instrucao = new JLabel("Digite seu e-mail de acesso:");
            instrucao.setFont(FONTE_LABEL);
            instrucao.setForeground(COR_TEXTO_DIM);
            corpo.add(instrucao, gbc);

            // Campo e-mail
            campoEmail = new JTextField(30);
            estilizarCampo(campoEmail);
            corpo.add(campoEmail, gbc);

            // Status
            labelStatus = new JLabel(" ");
            labelStatus.setFont(FONTE_LABEL);
            labelStatus.setForeground(COR_ERRO);
            labelStatus.setHorizontalAlignment(SwingConstants.CENTER);
            corpo.add(labelStatus, gbc);

            // Botão entrar
            JButton btnEntrar = criarBotao("[ CONFIRMAR ]");
            btnEntrar.addActionListener(e -> processarLogin());
            corpo.add(btnEntrar, gbc);

            add(corpo, BorderLayout.CENTER);

            // Enter no campo dispara o login
            campoEmail.addActionListener(e -> processarLogin());

            // ── Rodapé ───────────────────────────────────────────────────────
            add(criarRodape("INF1416 — Segurança da Informação | PUC-Rio"), BorderLayout.SOUTH);
        }

        private void processarLogin() {
            String email = campoEmail.getText().trim();

            if (email.isEmpty()) {
                labelStatus.setText("Informe o e-mail de acesso.");
                return;
            }

            ResultadoEtapa1 resultado = auth.verificarLogin(email);

            switch (resultado) {
                case SUCESSO:
                    labelStatus.setForeground(COR_ACENTO);
                    labelStatus.setText("Identificado. Prosseguindo...");
                    // Abrir etapa 2
                    SwingUtilities.invokeLater(() -> {
                        new TecladoUI(auth).setVisible(true);
                        dispose();
                    });
                    break;

                case LOGIN_INVALIDO:
                    labelStatus.setForeground(COR_ERRO);
                    labelStatus.setText("E-mail não encontrado no sistema.");
                    campoEmail.selectAll();
                    break;

                case ACESSO_BLOQUEADO:
                    labelStatus.setForeground(COR_ERRO);
                    labelStatus.setText("Acesso bloqueado. Aguarde 2 minutos.");
                    campoEmail.setText("");
                    break;
            }
        }
    }

    // =========================================================================
    // ETAPA 2 — TecladoUI (teclado virtual sobrecarregado)
    // =========================================================================

    public static class TecladoUI extends JFrame {

        private final AuthController  auth;
        private final TecladoVirtual  teclado;

        private JButton[]  botoesTeclado = new JButton[5];
        private JLabel     labelProgresso;
        private JLabel     labelStatus;
        private JLabel     labelContagem;

        public TecladoUI(AuthController auth) {
            this.auth    = auth;
            this.teclado = new TecladoVirtual();
            configurarJanela();
            construirUI();
        }

        private void configurarJanela() {
            setTitle("Cofre Digital — Senha Pessoal");
            setSize(520, 460);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setResizable(false);
            getContentPane().setBackground(COR_FUNDO);
        }

        private void construirUI() {
            setLayout(new BorderLayout(0, 0));

            // ── Cabeçalho ────────────────────────────────────────────────────
            add(criarCabecalho("COFRE DIGITAL", "ETAPA 2 DE 3 — SENHA PESSOAL"), BorderLayout.NORTH);

            // ── Corpo central ────────────────────────────────────────────────
            JPanel corpo = new JPanel(new BorderLayout(0, 12));
            corpo.setBackground(COR_FUNDO);
            corpo.setBorder(BorderFactory.createEmptyBorder(16, 40, 16, 40));

            // Instrução
            JLabel instrucao = new JLabel(
                "<html><center>Clique nos botões na ordem dos dígitos da sua senha.<br>" +
                "Cada botão contém dois dígitos possíveis.</center></html>"
            );
            instrucao.setFont(FONTE_LABEL);
            instrucao.setForeground(COR_TEXTO_DIM);
            instrucao.setHorizontalAlignment(SwingConstants.CENTER);
            corpo.add(instrucao, BorderLayout.NORTH);

            // Progresso (asteriscos)
            JPanel painelProgresso = new JPanel(new BorderLayout());
            painelProgresso.setBackground(COR_PAINEL);
            painelProgresso.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COR_BORDA, 1),
                BorderFactory.createEmptyBorder(10, 20, 10, 20)
            ));

            labelProgresso = new JLabel("________");
            labelProgresso.setFont(FONTE_GRANDE);
            labelProgresso.setForeground(COR_ACENTO);
            labelProgresso.setHorizontalAlignment(SwingConstants.CENTER);

            labelContagem = new JLabel("0 dígitos");
            labelContagem.setFont(FONTE_LABEL);
            labelContagem.setForeground(COR_TEXTO_DIM);
            labelContagem.setHorizontalAlignment(SwingConstants.CENTER);

            painelProgresso.add(labelProgresso, BorderLayout.CENTER);
            painelProgresso.add(labelContagem,  BorderLayout.SOUTH);
            corpo.add(painelProgresso, BorderLayout.CENTER);

            // Grade dos 5 botões do teclado
            JPanel painelBotoes = new JPanel(new GridLayout(1, 5, 8, 0));
            painelBotoes.setBackground(COR_FUNDO);

            for (int i = 0; i < 5; i++) {
                final int idx = i;
                botoesTeclado[i] = criarBotaoTeclado("", idx);
                botoesTeclado[i].addActionListener(e -> clicarBotao(idx));
                painelBotoes.add(botoesTeclado[i]);
            }
            corpo.add(painelBotoes, BorderLayout.SOUTH);

            add(corpo, BorderLayout.CENTER);

            // ── Rodapé com ações ─────────────────────────────────────────────
            JPanel rodape = new JPanel(new BorderLayout(12, 0));
            rodape.setBackground(COR_FUNDO);
            rodape.setBorder(BorderFactory.createEmptyBorder(0, 40, 16, 40));

            labelStatus = new JLabel(" ");
            labelStatus.setFont(FONTE_LABEL);
            labelStatus.setForeground(COR_ERRO);
            labelStatus.setHorizontalAlignment(SwingConstants.CENTER);

            JPanel acoes = new JPanel(new GridLayout(1, 3, 8, 0));
            acoes.setBackground(COR_FUNDO);

            JButton btnApagar = criarBotao("[ ← ]");
            btnApagar.addActionListener(e -> apagarUltimo());

            JButton btnLimpar = criarBotao("[ LIMPAR ]");
            btnLimpar.addActionListener(e -> limpar());

            JButton btnConfirmar = criarBotao("[ CONFIRMAR ]");
            btnConfirmar.setForeground(COR_ACENTO);
            btnConfirmar.addActionListener(e -> confirmarSenha());

            acoes.add(btnApagar);
            acoes.add(btnLimpar);
            acoes.add(btnConfirmar);

            rodape.add(labelStatus, BorderLayout.NORTH);
            rodape.add(acoes,       BorderLayout.CENTER);

            add(rodape, BorderLayout.SOUTH);

            // Atualizar labels dos botões com os dígitos iniciais
            atualizarBotoes();
        }

        private void clicarBotao(int indice) {
            teclado.clicarBotao(indice);
            atualizarProgresso();
            atualizarBotoes();
            labelStatus.setText(" ");
        }

        private void apagarUltimo() {
            teclado.removerUltimo();
            atualizarProgresso();
            atualizarBotoes();
        }

        private void limpar() {
            teclado.limpar();
            atualizarProgresso();
            atualizarBotoes();
        }

        private void confirmarSenha() {
            int qtd = teclado.getQuantidadeDigitada();
            if (qtd < 8 || qtd > 10) {
                labelStatus.setText("A senha deve ter 8, 9 ou 10 dígitos. (" + qtd + " digitados)");
                return;
            }

            List<String> combinacoes = teclado.gerarCombinacoes();
            ResultadoEtapa2 resultado = auth.verificarSenha(combinacoes);

            switch (resultado) {
                case SUCESSO:
                    labelStatus.setForeground(COR_ACENTO);
                    labelStatus.setText("Senha verificada. Prosseguindo...");
                    SwingUtilities.invokeLater(() -> {
                        new TelaTOTP(auth).setVisible(true);
                        dispose();
                    });
                    break;

                case SENHA_INCORRETA:
                    labelStatus.setForeground(COR_ERRO);
                    labelStatus.setText("Senha incorreta. Tentativas restantes: " + (3 - erroDaUI()));
                    teclado.limpar();
                    atualizarProgresso();
                    atualizarBotoes();
                    break;

                case BLOQUEADO:
                    labelStatus.setForeground(COR_ERRO);
                    labelStatus.setText("Acesso bloqueado por 2 minutos.");
                    Timer timer = new Timer(3000, e -> {
                        new TelaLogin(auth).setVisible(true);
                        dispose();
                    });
                    timer.setRepeats(false);
                    timer.start();
                    break;
            }
        }

        // Contagem de erros local para mostrar na UI (o AuthController controla o real)
        private int errosLocais = 0;
        private int erroDaUI() {
            errosLocais++;
            return errosLocais;
        }

        private void atualizarBotoes() {
            int[][] botoes = teclado.getBotoes();
            for (int i = 0; i < 5; i++) {
                botoesTeclado[i].setText("<html><center>" + botoes[i][0] + "<br>" + botoes[i][1] + "</center></html>");
            }
        }

        private void atualizarProgresso() {
            int qtd = teclado.getQuantidadeDigitada();
            String asteriscos = "*".repeat(qtd);
            // Preencher com underline até 10
            String display = asteriscos + "_".repeat(Math.max(0, 8 - qtd));
            labelProgresso.setText(display.isEmpty() ? "________" : display);
            labelContagem.setText(qtd + " dígito(s)");
        }

        private JButton criarBotaoTeclado(String texto, int indice) {
            JButton btn = new JButton(texto) {
                @Override
                protected void paintComponent(Graphics g) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                                        RenderingHints.VALUE_ANTIALIAS_ON);
                    if (getModel().isPressed()) {
                        g2.setColor(COR_ACENTO2);
                    } else if (getModel().isRollover()) {
                        g2.setColor(COR_BOTAO_HOVER);
                    } else {
                        g2.setColor(COR_PAINEL);
                    }
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                    g2.setColor(COR_ACENTO);
                    g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 8, 8);
                    g2.dispose();
                    super.paintComponent(g);
                }
            };
            btn.setFont(FONTE_BOTAO);
            btn.setForeground(COR_TEXTO);
            btn.setOpaque(false);
            btn.setContentAreaFilled(false);
            btn.setBorderPainted(false);
            btn.setFocusPainted(false);
            btn.setPreferredSize(new Dimension(80, 80));
            btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            return btn;
        }
    }

    // =========================================================================
    // ETAPA 3 — TelaTOTP
    // =========================================================================

    public static class TelaTOTP extends JFrame {

        private final AuthController auth;
        private JTextField campoTotp;
        private JLabel     labelStatus;

        public TelaTOTP(AuthController auth) {
            this.auth = auth;
            configurarJanela();
            construirUI();
        }

        private void configurarJanela() {
            setTitle("Cofre Digital — Token TOTP");
            setSize(460, 340);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setResizable(false);
            getContentPane().setBackground(COR_FUNDO);
        }

        private void construirUI() {
            setLayout(new BorderLayout());

            add(criarCabecalho("COFRE DIGITAL", "ETAPA 3 DE 3 — TOKEN TOTP"), BorderLayout.NORTH);

            JPanel corpo = new JPanel(new GridBagLayout());
            corpo.setBackground(COR_FUNDO);
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(8, 48, 8, 48);
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.gridwidth = GridBagConstraints.REMAINDER;

            // Instrução
            JLabel instrucao = new JLabel(
                "<html><center>Abra o Google Authenticator e digite<br>" +
                "o código de 6 dígitos gerado para <b>Cofre Digital</b>.</center></html>"
            );
            instrucao.setFont(FONTE_LABEL);
            instrucao.setForeground(COR_TEXTO_DIM);
            instrucao.setHorizontalAlignment(SwingConstants.CENTER);
            corpo.add(instrucao, gbc);

            // Campo TOTP
            campoTotp = new JTextField(10);
            campoTotp.setHorizontalAlignment(SwingConstants.CENTER);
            campoTotp.setFont(new Font("Courier New", Font.BOLD, 28));
            estilizarCampo(campoTotp);
            // Limitar a 6 dígitos numéricos
            campoTotp.addKeyListener(new KeyAdapter() {
                @Override
                public void keyTyped(KeyEvent e) {
                    String texto = campoTotp.getText();
                    if (texto.length() >= 6 || !Character.isDigit(e.getKeyChar())) {
                        e.consume();
                    }
                }
            });
            corpo.add(campoTotp, gbc);

            // Status
            labelStatus = new JLabel(" ");
            labelStatus.setFont(FONTE_LABEL);
            labelStatus.setForeground(COR_ERRO);
            labelStatus.setHorizontalAlignment(SwingConstants.CENTER);
            corpo.add(labelStatus, gbc);

            // Botão confirmar
            JButton btnConfirmar = criarBotao("[ VERIFICAR TOKEN ]");
            btnConfirmar.addActionListener(e -> verificarToken());
            corpo.add(btnConfirmar, gbc);

            add(corpo, BorderLayout.CENTER);
            add(criarRodape("O código muda a cada 30 segundos"), BorderLayout.SOUTH);

            // Enter confirma
            campoTotp.addActionListener(e -> verificarToken());
        }

        private void verificarToken() {
            String codigo = campoTotp.getText().trim();

            if (codigo.length() != 6 || !codigo.matches("[0-9]{6}")) {
                labelStatus.setText("Digite exatamente 6 dígitos numéricos.");
                return;
            }

            ResultadoEtapa3 resultado = auth.verificarTotp(codigo);

            switch (resultado) {
                case SUCESSO:
                    auth.registrarInicioSessao();
                    labelStatus.setForeground(COR_ACENTO);
                    labelStatus.setText("Token válido. Acessando sistema...");
                    Usuario usuario = auth.getUsuarioAutenticado();
                    SwingUtilities.invokeLater(() -> {
                        new TelaPrincipal(auth, usuario).setVisible(true);
                        dispose();
                    });
                    break;

                case TOKEN_INVALIDO:
                    labelStatus.setForeground(COR_ERRO);
                    labelStatus.setText("Token inválido. Verifique o Google Authenticator.");
                    campoTotp.setText("");
                    break;

                case BLOQUEADO:
                    labelStatus.setForeground(COR_ERRO);
                    labelStatus.setText("Acesso bloqueado por 2 minutos.");
                    Timer timer = new Timer(3000, e -> {
                        new TelaLogin(auth).setVisible(true);
                        dispose();
                    });
                    timer.setRepeats(false);
                    timer.start();
                    break;
            }
        }
    }

    // =========================================================================
    // COMPONENTES REUTILIZÁVEIS
    // =========================================================================

    static JPanel criarCabecalho(String titulo, String subtitulo) {
        JPanel painel = new JPanel(new BorderLayout());
        painel.setBackground(COR_PAINEL);
        painel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, COR_ACENTO),
            BorderFactory.createEmptyBorder(16, 24, 16, 24)
        ));

        JLabel lblTitulo = new JLabel("▶ " + titulo);
        lblTitulo.setFont(FONTE_TITULO);
        lblTitulo.setForeground(COR_ACENTO);

        JLabel lblSub = new JLabel(subtitulo);
        lblSub.setFont(FONTE_LABEL);
        lblSub.setForeground(COR_TEXTO_DIM);

        painel.add(lblTitulo, BorderLayout.NORTH);
        painel.add(lblSub,    BorderLayout.SOUTH);
        return painel;
    }

    static JPanel criarRodape(String texto) {
        JPanel painel = new JPanel();
        painel.setBackground(COR_PAINEL);
        painel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, COR_BORDA),
            BorderFactory.createEmptyBorder(8, 24, 8, 24)
        ));
        JLabel label = new JLabel(texto);
        label.setFont(FONTE_LABEL);
        label.setForeground(COR_TEXTO_DIM);
        painel.add(label);
        return painel;
    }

    static JButton criarBotao(String texto) {
        JButton btn = new JButton(texto) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                                    RenderingHints.VALUE_ANTIALIAS_ON);
                if (getModel().isPressed()) {
                    g2.setColor(COR_ACENTO2);
                } else if (getModel().isRollover()) {
                    g2.setColor(new Color(0x1B5E20));
                } else {
                    g2.setColor(COR_BOTAO);
                }
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 6, 6);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        btn.setFont(new Font("Courier New", Font.BOLD, 16));
        btn.setForeground(COR_TEXTO);
        btn.setOpaque(false);
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setPreferredSize(new Dimension(200, 38));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }

    static void estilizarCampo(JTextField campo) {
        campo.setFont(FONTE_MONO);
        campo.setBackground(COR_PAINEL);
        campo.setForeground(COR_TEXTO);
        campo.setCaretColor(COR_ACENTO);
        campo.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(COR_BORDA, 1),
            BorderFactory.createEmptyBorder(8, 12, 8, 12)
        ));
    }
}
