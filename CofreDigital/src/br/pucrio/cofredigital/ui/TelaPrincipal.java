// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.ui;

import br.pucrio.cofredigital.auth.AuthController;
import br.pucrio.cofredigital.model.Usuario;
import br.pucrio.cofredigital.db.RegistroDAO;
import br.pucrio.cofredigital.ui.TelaCadastro;
import br.pucrio.cofredigital.ui.TelaConsulta;

import javax.swing.*;
import java.awt.*;

/**
 * Tela Principal — exibida após autenticação bem-sucedida.
 *
 * Mostra menu diferente conforme o grupo do usuário:
 *   GID 1 (Administrador): opções 1, 2 e 3
 *   GID 2 (Usuário):       opções 2 e 3 apenas
 */
public class TelaPrincipal extends JFrame {

    private final AuthController auth;
    private final Usuario        usuario;

    public TelaPrincipal(AuthController auth, Usuario usuario) {
        this.auth    = auth;
        this.usuario = usuario;
        configurarJanela();
        construirUI();
        // Registrar msg 5001 — tela principal apresentada
        RegistroDAO.registrar(5001, usuario.getUid(), null);
    }

    private void configurarJanela() {
        setTitle("Cofre Digital — " + usuario.getLoginName());
        setSize(560, 460);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setResizable(false);
        getContentPane().setBackground(TelasAutenticacao.COR_FUNDO);

        // Ao fechar a janela, encerrar sessão
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                encerrarSistema();
            }
        });
    }

    private void construirUI() {
        setLayout(new BorderLayout(0, 0));

        // ── Cabeçalho ────────────────────────────────────────────────────────
        add(criarCabecalho(), BorderLayout.NORTH);

        // ── Corpo 1: total de acessos ─────────────────────────────────────
        JPanel corpo1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 24, 12));
        corpo1.setBackground(TelasAutenticacao.COR_PAINEL);
        corpo1.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0,
            TelasAutenticacao.COR_BORDA));
        JLabel lblAcessos = new JLabel(
            "Total de acessos do usuário: " + usuario.getTotalAcessos()
        );
        lblAcessos.setFont(TelasAutenticacao.FONTE_MONO);
        lblAcessos.setForeground(TelasAutenticacao.COR_TEXTO_DIM);
        corpo1.add(lblAcessos);
        add(corpo1, BorderLayout.CENTER);

        // ── Corpo 2: menu ────────────────────────────────────────────────────
        JPanel corpo2 = new JPanel();
        corpo2.setBackground(TelasAutenticacao.COR_FUNDO);
        corpo2.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 60, 6, 60);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = GridBagConstraints.REMAINDER;

        JLabel lblMenu = new JLabel("Menu Principal:");
        lblMenu.setFont(TelasAutenticacao.FONTE_TITULO);
        lblMenu.setForeground(TelasAutenticacao.COR_ACENTO);
        corpo2.add(lblMenu, gbc);

        boolean isAdmin = (usuario.getGid() == 1);

        // Opção 1 — só para admin
        if (isAdmin) {
            JButton btn1 = TelasAutenticacao.criarBotao("[ 1 ] Cadastrar novo usuário");
            btn1.addActionListener(e -> {
                RegistroDAO.registrar(5002, usuario.getUid(), null);
                new TelaCadastro(auth, usuario, false).setVisible(true);
                dispose();
            });
            corpo2.add(btn1, gbc);
        }

        // Opção 2 — para todos
        JButton btn2 = TelasAutenticacao.criarBotao("[ 2 ] Consultar pasta de arquivos");
        btn2.addActionListener(e -> {
            RegistroDAO.registrar(5003, usuario.getUid(), null);
            new TelaConsulta(auth, usuario).setVisible(true);
            dispose();
        });
        corpo2.add(btn2, gbc);

        // Opção 3 — para todos
        JButton btn3 = TelasAutenticacao.criarBotao("[ 3 ] Sair do sistema");
        btn3.addActionListener(e -> {
            RegistroDAO.registrar(5004, usuario.getUid(), null);
            abrirTelaSaida();
        });
        corpo2.add(btn3, gbc);

        // Usar BorderLayout.SOUTH para o menu não ficar colado em cima
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(TelasAutenticacao.COR_FUNDO);
        wrapper.add(corpo2, BorderLayout.NORTH);
        add(wrapper, BorderLayout.SOUTH);
    }

    private JPanel criarCabecalho() {
        JPanel painel = new JPanel(new GridLayout(4, 1, 0, 2));
        painel.setBackground(TelasAutenticacao.COR_PAINEL);
        painel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, TelasAutenticacao.COR_ACENTO),
            BorderFactory.createEmptyBorder(14, 24, 14, 24)
        ));

        painel.add(labelCabecalho("Login: " + usuario.getLoginName()));
        painel.add(labelCabecalho("Grupo: " + (usuario.getGid() == 1 ? "Administrador" : "Usuário")));
        painel.add(labelCabecalho("Nome:  " + usuario.getNomeUsuario()));
        return painel;
    }

    private JLabel labelCabecalho(String texto) {
        JLabel lbl = new JLabel(texto);
        lbl.setFont(TelasAutenticacao.FONTE_MONO);
        lbl.setForeground(TelasAutenticacao.COR_TEXTO);
        return lbl;
    }

    private void abrirTelaSaida() {
        RegistroDAO.registrar(8001, usuario.getUid(), null);

        int opcao = JOptionPane.showOptionDialog(
            this,
            "Pressione Encerrar Sessão ou Encerrar Sistema para confirmar.",
            "Saída do Sistema",
            JOptionPane.YES_NO_CANCEL_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            new String[]{"Encerrar Sessão", "Encerrar Sistema", "Voltar"},
            "Voltar"
        );

        switch (opcao) {
            case 0: // Encerrar Sessão
                RegistroDAO.registrar(8002, usuario.getUid(), null);
                auth.encerrarSessao();
                new TelasAutenticacao.TelaLogin(auth).setVisible(true);
                dispose();
                break;
            case 1: // Encerrar Sistema
                RegistroDAO.registrar(8003, usuario.getUid(), null);
                encerrarSistema();
                break;
            case 2: // Voltar
                RegistroDAO.registrar(8004, usuario.getUid(), null);
                break;
        }
    }

    private void encerrarSistema() {
        auth.encerrarSessao();
        RegistroDAO.registrar(1002, null, null);
        br.pucrio.cofredigital.db.DatabaseConnection.closeConnection();
        System.exit(0);
    }
}
