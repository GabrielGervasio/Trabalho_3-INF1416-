package br.pucrio.cofredigital.ui;

import br.pucrio.cofredigital.auth.AuthController;
import br.pucrio.cofredigital.crypto.CryptoUtils;
import br.pucrio.cofredigital.crypto.EnvelopeDigital;
import br.pucrio.cofredigital.crypto.EnvelopeDigital.ResultadoDecriptacao;
import br.pucrio.cofredigital.db.ChaveiroDAO;
import br.pucrio.cofredigital.db.RegistroDAO;
import br.pucrio.cofredigital.db.UsuarioDAO;
import br.pucrio.cofredigital.model.Chaveiro;
import br.pucrio.cofredigital.model.Usuario;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.File;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Tela de Consulta da Pasta de Arquivos Secretos.
 *
 * Fluxo conforme o enunciado:
 *   1. Usuário informa caminho da pasta e frase secreta
 *   2. Sistema valida a frase secreta (lerChavePrivada)
 *   3. Decripta index.enc usando index.env (envelope do admin)
 *   4. Verifica index.asd (assinatura do admin)
 *   5. Lista apenas arquivos cujo dono ou grupo é do usuário logado
 *   6. Usuário seleciona um arquivo → sistema verifica se é o dono
 *   7. Se dono: decripta e salva com o nome secreto na mesma pasta
 *   8. Se não dono: notifica acesso negado
 */
public class TelaConsulta extends JFrame {

    private final AuthController auth;
    private final Usuario        usuario;

    // Campos da tela
    private JTextField campoPath;
    private JPasswordField campoFrase;
    private JLabel     labelStatus;
    private JTable     tabelaArquivos;
    private DefaultTableModel modeloTabela;
    private JButton    btnDecriptar;

    // Dados do índice parseados
    private List<ArquivoIndex> arquivosDoIndex = new ArrayList<>();

    // Chave privada do usuário (carregada após validação da frase)
    private PrivateKey chavePrivadaUsuario = null;

    public TelaConsulta(AuthController auth, Usuario usuario) {
        this.auth    = auth;
        this.usuario = usuario;
        configurarJanela();
        construirUI();
        RegistroDAO.registrar(7001, usuario.getUid(), null);
    }

    // =========================================================================
    // CONFIGURAÇÃO DA JANELA
    // =========================================================================

    private void configurarJanela() {
        setTitle("Cofre Digital — Consulta de Arquivos Secretos");
        setSize(700, 560);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setResizable(false);
        getContentPane().setBackground(TelasAutenticacao.COR_FUNDO);
    }

    // =========================================================================
    // CONSTRUÇÃO DA UI
    // =========================================================================

    private void construirUI() {
        setLayout(new BorderLayout(0, 0));

        // ── Cabeçalho ────────────────────────────────────────────────────────
        add(TelasAutenticacao.criarCabecalho("COFRE DIGITAL",
            "CONSULTA DE ARQUIVOS SECRETOS"), BorderLayout.NORTH);

        // ── Info do usuário + total de consultas ──────────────────────────────
        add(criarInfoTopo(), BorderLayout.NORTH);

        // ── Corpo principal ───────────────────────────────────────────────────
        JPanel corpo = new JPanel(new BorderLayout(0, 10));
        corpo.setBackground(TelasAutenticacao.COR_FUNDO);
        corpo.setBorder(BorderFactory.createEmptyBorder(12, 24, 8, 24));

        corpo.add(criarPainelFormulario(), BorderLayout.NORTH);
        corpo.add(criarPainelTabela(),     BorderLayout.CENTER);
        corpo.add(criarPainelStatus(),     BorderLayout.SOUTH);

        add(corpo, BorderLayout.CENTER);

        // ── Rodapé com botões ─────────────────────────────────────────────────
        add(criarBotoes(), BorderLayout.SOUTH);
    }

    private JPanel criarInfoTopo() {
        JPanel painel = new JPanel(new BorderLayout());
        painel.setBackground(TelasAutenticacao.COR_PAINEL);
        painel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, TelasAutenticacao.COR_ACENTO),
            BorderFactory.createEmptyBorder(12, 24, 12, 24)
        ));

        JPanel cabecalho = new JPanel(new GridLayout(3, 1, 0, 2));
        cabecalho.setBackground(TelasAutenticacao.COR_PAINEL);
        cabecalho.add(labelCab("Login: " + usuario.getLoginName()));
        cabecalho.add(labelCab("Grupo: " + (usuario.getGid() == 1 ? "Administrador" : "Usuário")));
        cabecalho.add(labelCab("Nome:  " + usuario.getNomeUsuario()));
        painel.add(cabecalho, BorderLayout.WEST);

        // Total de consultas — conta registros MID=7001 para este usuário
        int totalConsultas = contarConsultas();
        JLabel lblConsultas = new JLabel("Total de consultas do usuário: " + totalConsultas);
        lblConsultas.setFont(TelasAutenticacao.FONTE_MONO);
        lblConsultas.setForeground(TelasAutenticacao.COR_TEXTO_DIM);
        lblConsultas.setHorizontalAlignment(SwingConstants.RIGHT);
        painel.add(lblConsultas, BorderLayout.EAST);

        return painel;
    }

    private JPanel criarPainelFormulario() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBackground(TelasAutenticacao.COR_FUNDO);

        GridBagConstraints lbl = new GridBagConstraints();
        lbl.anchor = GridBagConstraints.WEST;
        lbl.insets = new Insets(4, 0, 4, 10);
        lbl.gridx = 0;

        GridBagConstraints fld = new GridBagConstraints();
        fld.fill = GridBagConstraints.HORIZONTAL;
        fld.weightx = 1.0;
        fld.insets = new Insets(4, 0, 4, 8);
        fld.gridx = 1;

        GridBagConstraints btn = new GridBagConstraints();
        btn.insets = new Insets(4, 0, 4, 0);
        btn.gridx = 2;

        // Caminho da pasta
        lbl.gridy = 0; fld.gridy = 0; btn.gridy = 0;
        p.add(rotulo("Caminho da pasta:"), lbl);
        campoPath = new JTextField(40);
        TelasAutenticacao.estilizarCampo(campoPath);
        p.add(campoPath, fld);
        JButton btnNavegar = botaoPequeno("...");
        btnNavegar.addActionListener(e -> navegarPasta());
        p.add(btnNavegar, btn);

        // Frase secreta
        lbl.gridy = 1; fld.gridy = 1; btn.gridy = 1;
        p.add(rotulo("Frase secreta:"), lbl);
        campoFrase = new JPasswordField(40);
        campoFrase.setFont(TelasAutenticacao.FONTE_MONO);
        campoFrase.setBackground(TelasAutenticacao.COR_PAINEL);
        campoFrase.setForeground(TelasAutenticacao.COR_TEXTO);
        campoFrase.setCaretColor(TelasAutenticacao.COR_ACENTO);
        campoFrase.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(TelasAutenticacao.COR_BORDA, 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        p.add(campoFrase, fld);

        JButton btnListar = TelasAutenticacao.criarBotao("[ LISTAR ]");
        btnListar.setForeground(TelasAutenticacao.COR_ACENTO);
        btnListar.addActionListener(e -> listarArquivos());
        p.add(btnListar, btn);

        return p;
    }

    private JPanel criarPainelTabela() {
        // Colunas: Nome do Arquivo | Dono | Grupo
        String[] colunas = {"Nome do Arquivo", "Dono", "Grupo"};
        modeloTabela = new DefaultTableModel(colunas, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        tabelaArquivos = new JTable(modeloTabela);
        tabelaArquivos.setBackground(TelasAutenticacao.COR_PAINEL);
        tabelaArquivos.setForeground(TelasAutenticacao.COR_TEXTO);
        tabelaArquivos.setFont(TelasAutenticacao.FONTE_MONO);
        tabelaArquivos.setSelectionBackground(TelasAutenticacao.COR_ACENTO2);
        tabelaArquivos.setSelectionForeground(Color.WHITE);
        tabelaArquivos.setGridColor(TelasAutenticacao.COR_BORDA);
        tabelaArquivos.setRowHeight(28);
        tabelaArquivos.getTableHeader().setBackground(TelasAutenticacao.COR_PAINEL);
        tabelaArquivos.getTableHeader().setForeground(TelasAutenticacao.COR_ACENTO);
        tabelaArquivos.getTableHeader().setFont(TelasAutenticacao.FONTE_LABEL);
        tabelaArquivos.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Centralizar colunas Dono e Grupo
        DefaultTableCellRenderer center = new DefaultTableCellRenderer();
        center.setHorizontalAlignment(SwingConstants.CENTER);
        tabelaArquivos.getColumnModel().getColumn(1).setCellRenderer(center);
        tabelaArquivos.getColumnModel().getColumn(2).setCellRenderer(center);

        // Duplo clique na linha → decriptar
        tabelaArquivos.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    decriptarArquivoSelecionado();
                }
            }
        });

        JScrollPane scroll = new JScrollPane(tabelaArquivos);
        scroll.setBackground(TelasAutenticacao.COR_PAINEL);
        scroll.setBorder(BorderFactory.createLineBorder(TelasAutenticacao.COR_BORDA, 1));
        scroll.getViewport().setBackground(TelasAutenticacao.COR_PAINEL);

        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBackground(TelasAutenticacao.COR_FUNDO);

        // Instrução acima da tabela
        JLabel instrucao = new JLabel(
            "Dê duplo clique em um arquivo para decriptá-lo.");
        instrucao.setFont(TelasAutenticacao.FONTE_LABEL);
        instrucao.setForeground(TelasAutenticacao.COR_TEXTO_DIM);
        p.add(instrucao, BorderLayout.NORTH);
        p.add(scroll,    BorderLayout.CENTER);

        // Botão decriptar abaixo da tabela
        btnDecriptar = TelasAutenticacao.criarBotao("[ DECRIPTAR ARQUIVO SELECIONADO ]");
        btnDecriptar.setEnabled(false);
        btnDecriptar.addActionListener(e -> decriptarArquivoSelecionado());
        tabelaArquivos.getSelectionModel().addListSelectionListener(
            e -> btnDecriptar.setEnabled(tabelaArquivos.getSelectedRow() >= 0)
        );

        JPanel painelBtn = new JPanel(new FlowLayout(FlowLayout.CENTER));
        painelBtn.setBackground(TelasAutenticacao.COR_FUNDO);
        painelBtn.add(btnDecriptar);
        p.add(painelBtn, BorderLayout.SOUTH);

        return p;
    }

    private JPanel criarPainelStatus() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(TelasAutenticacao.COR_FUNDO);
        labelStatus = new JLabel(" ");
        labelStatus.setFont(TelasAutenticacao.FONTE_LABEL);
        labelStatus.setForeground(TelasAutenticacao.COR_ERRO);
        labelStatus.setHorizontalAlignment(SwingConstants.CENTER);
        p.add(labelStatus, BorderLayout.CENTER);
        return p;
    }

    private JPanel criarBotoes() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.RIGHT, 16, 10));
        p.setBackground(TelasAutenticacao.COR_PAINEL);
        p.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0,
            TelasAutenticacao.COR_BORDA));

        JButton btnVoltar = TelasAutenticacao.criarBotao("[ VOLTAR AO MENU ]");
        btnVoltar.addActionListener(e -> voltar());
        p.add(btnVoltar);
        return p;
    }

    // =========================================================================
    // LÓGICA: LISTAR ARQUIVOS
    // =========================================================================

    private void listarArquivos() {
        RegistroDAO.registrar(7003, usuario.getUid(), null);

        String caminhoPasta = campoPath.getText().trim();
        String frase        = new String(campoFrase.getPassword()).trim();

        // Validar caminho
        if (caminhoPasta.isEmpty()) {
            setStatus("Informe o caminho da pasta.", false);
            return;
        }
        File pasta = new File(caminhoPasta);
        if (!pasta.exists() || !pasta.isDirectory()) {
            RegistroDAO.registrar(7004, usuario.getUid(), null);
            setStatus("Caminho de pasta inválido ou não encontrado.", false);
            return;
        }
        if (frase.isEmpty()) {
            setStatus("Informe a frase secreta.", false);
            return;
        }

        // Validar frase secreta e carregar chave privada do usuário
        try {
            Chaveiro chaveiro = new ChaveiroDAO().findByKid(usuario.getKid());
            if (chaveiro == null) {
                setStatus("Chaveiro do usuário não encontrado.", false);
                return;
            }
            chavePrivadaUsuario = CryptoUtils.lerChavePrivadaDosBytes(
                chaveiro.getChavePrivadaBin(), frase
            );
        } catch (Exception e) {
            setStatus("Frase secreta inválida.", false);
            return;
        }

        // Caminhos dos arquivos do índice
        String encPath = caminhoPasta + File.separator + "index.enc";
        String envPath = caminhoPasta + File.separator + "index.env";
        String asdPath = caminhoPasta + File.separator + "index.asd";

        // Verificar existência dos arquivos de índice
        if (!new File(encPath).exists() || !new File(envPath).exists()
                || !new File(asdPath).exists()) {
            setStatus("Arquivos de índice não encontrados na pasta.", false);
            return;
        }

        // Buscar chave pública do admin para verificar assinatura do índice
        try {
            Usuario admin = new UsuarioDAO().findAdmin();
            Chaveiro chaveiroAdmin = new ChaveiroDAO().findByKid(admin.getKid());
            X509Certificate certAdmin = CryptoUtils.certificadoDePEM(
                chaveiroAdmin.getCertPem()
            );

            // Decriptar índice usando chave privada do ADMIN (envelope do admin)
            // O índice pertence ao admin — o .env foi cifrado com chave pública do admin
            // Por isso precisamos da chave privada do admin, que está em Main
            PrivateKey chaveAdmin = br.pucrio.cofredigital.Main.getChavePrivadaAdmin();
            if (chaveAdmin == null) {
                setStatus("Chave do administrador não disponível em memória.", false);
                return;
            }

            // Decriptar index.enc
            ResultadoDecriptacao resultado = EnvelopeDigital.decriptarArquivo(
                encPath, envPath, asdPath,
                chaveAdmin, certAdmin.getPublicKey()
            );

            if (!resultado.decriptacaoOk) {
                RegistroDAO.registrar(7007, usuario.getUid(), null);
                setStatus("Falha na decriptação do índice.", false);
                return;
            }
            RegistroDAO.registrar(7005, usuario.getUid(), null);

            if (!resultado.assinaturaOk) {
                RegistroDAO.registrar(7008, usuario.getUid(), null);
                setStatus("Falha na verificação de integridade/autenticidade do índice.", false);
                return;
            }
            RegistroDAO.registrar(7006, usuario.getUid(), null);

            // Parsear o conteúdo do índice
            String conteudo = new String(resultado.conteudo,
                java.nio.charset.StandardCharsets.UTF_8);
            arquivosDoIndex = parsearIndex(conteudo);

            // Filtrar: mostrar apenas arquivos do usuário ou do grupo dele
            String grupoUsuario = (usuario.getGid() == 1) ? "administrador" : "usuario";
            List<ArquivoIndex> visiveis = new ArrayList<>();
            for (ArquivoIndex arq : arquivosDoIndex) {
                if (arq.dono.equalsIgnoreCase(usuario.getLoginName())
                        || arq.grupo.equalsIgnoreCase(grupoUsuario)) {
                    visiveis.add(arq);
                }
            }

            // Preencher tabela
            modeloTabela.setRowCount(0);
            for (ArquivoIndex arq : visiveis) {
                modeloTabela.addRow(new Object[]{arq.nomeSecreto, arq.dono, arq.grupo});
            }
            // Guardar só os visíveis para referência no duplo clique
            arquivosDoIndex = visiveis;

            RegistroDAO.registrar(7009, usuario.getUid(), null);

            if (visiveis.isEmpty()) {
                setStatus("Nenhum arquivo acessível para este usuário.", true);
            } else {
                setStatus(visiveis.size() + " arquivo(s) encontrado(s). " +
                    "Dê duplo clique para decriptar.", true);
            }

        } catch (Exception e) {
            setStatus("Erro ao processar índice: " + e.getMessage(), false);
        }
    }

    // =========================================================================
    // LÓGICA: DECRIPTAR ARQUIVO SELECIONADO
    // =========================================================================

    private void decriptarArquivoSelecionado() {
        int linha = tabelaArquivos.getSelectedRow();
        if (linha < 0) {
            setStatus("Selecione um arquivo na tabela.", false);
            return;
        }

        ArquivoIndex arq = arquivosDoIndex.get(linha);
        String caminhoPasta = campoPath.getText().trim();

        RegistroDAO.registrar(7010, usuario.getUid(), arq.nomeSecreto);

        // Verificar política de acesso: só o dono pode acessar
        if (!arq.dono.equalsIgnoreCase(usuario.getLoginName())) {
            RegistroDAO.registrar(7012, usuario.getUid(), arq.nomeSecreto);
            setStatus("Acesso negado: você não é o dono do arquivo '" +
                arq.nomeSecreto + "'.", false);
            return;
        }

        RegistroDAO.registrar(7011, usuario.getUid(), arq.nomeSecreto);

        // Caminhos dos arquivos
        String encPath = caminhoPasta + File.separator + arq.nomeCodigo + ".enc";
        String envPath = caminhoPasta + File.separator + arq.nomeCodigo + ".env";
        String asdPath = caminhoPasta + File.separator + arq.nomeCodigo + ".asd";

        // Buscar chave pública do dono (o próprio usuário) para verificar assinatura
        try {
            Chaveiro chaveiro = new ChaveiroDAO().findByKid(usuario.getKid());
            X509Certificate cert = CryptoUtils.certificadoDePEM(chaveiro.getCertPem());

            // Decriptar o arquivo usando chave privada do usuário
            ResultadoDecriptacao resultado = EnvelopeDigital.decriptarArquivo(
                encPath, envPath, asdPath,
                chavePrivadaUsuario, cert.getPublicKey()
            );

            if (!resultado.decriptacaoOk) {
                RegistroDAO.registrar(7015, usuario.getUid(), arq.nomeSecreto);
                setStatus("Falha na decriptação do arquivo '" + arq.nomeSecreto + "'.", false);
                return;
            }
            RegistroDAO.registrar(7013, usuario.getUid(), arq.nomeSecreto);

            if (!resultado.assinaturaOk) {
                RegistroDAO.registrar(7016, usuario.getUid(), arq.nomeSecreto);
                setStatus("Arquivo decriptado mas assinatura inválida — " +
                    "integridade comprometida.", false);
                return;
            }
            RegistroDAO.registrar(7014, usuario.getUid(), arq.nomeSecreto);

            // Salvar na mesma pasta com o nome secreto
            String destino = caminhoPasta + File.separator + arq.nomeSecreto;
            Files.write(Paths.get(destino), resultado.conteudo);

            setStatus("Arquivo '" + arq.nomeSecreto +
                "' decriptado e salvo com sucesso!", true);

            JOptionPane.showMessageDialog(this,
                "Arquivo decriptado com sucesso!\n\nSalvo em:\n" + destino,
                "Sucesso", JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception e) {
            RegistroDAO.registrar(7015, usuario.getUid(), arq.nomeSecreto);
            setStatus("Erro ao decriptar: " + e.getMessage(), false);
        }
    }

    // =========================================================================
    // PARSEAR O ÍNDICE
    // =========================================================================

    /**
     * Parseia o conteúdo do index.enc.
     * Formato: NOME_CODIGO NOME_SECRETO DONO GRUPO
     */
    private List<ArquivoIndex> parsearIndex(String conteudo) {
        List<ArquivoIndex> lista = new ArrayList<>();
        for (String linha : conteudo.split("\n")) {
            linha = linha.trim();
            if (linha.isEmpty()) continue;
            String[] partes = linha.split("\\s+");
            if (partes.length >= 4) {
                lista.add(new ArquivoIndex(partes[0], partes[1], partes[2], partes[3]));
            }
        }
        return lista;
    }

    /** Representa uma entrada do arquivo de índice */
    private static class ArquivoIndex {
        String nomeCodigo;  // ex: XXYYZZ00
        String nomeSecreto; // ex: teste00.docx
        String dono;        // ex: admin@inf1416.puc-rio.br
        String grupo;       // ex: administrador

        ArquivoIndex(String nomeCodigo, String nomeSecreto, String dono, String grupo) {
            this.nomeCodigo  = nomeCodigo;
            this.nomeSecreto = nomeSecreto;
            this.dono        = dono;
            this.grupo       = grupo;
        }
    }

    // =========================================================================
    // UTILITÁRIOS
    // =========================================================================

    private void navegarPasta() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Selecionar pasta de arquivos secretos");
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            campoPath.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private void voltar() {
        RegistroDAO.registrar(7002, usuario.getUid(), null);
        new TelaPrincipal(auth, usuario).setVisible(true);
        dispose();
    }

    private void setStatus(String texto, boolean ok) {
        labelStatus.setText(texto);
        labelStatus.setForeground(ok
            ? TelasAutenticacao.COR_ACENTO
            : TelasAutenticacao.COR_ERRO);
    }

    private int contarConsultas() {
        try {
            return new RegistroDAO().findByMid(7001).stream()
                .filter(r -> r.getUid() != null && r.getUid() == usuario.getUid())
                .mapToInt(r -> 1).sum();
        } catch (Exception e) {
            return 0;
        }
    }

    private JLabel labelCab(String texto) {
        JLabel l = new JLabel(texto);
        l.setFont(TelasAutenticacao.FONTE_MONO);
        l.setForeground(TelasAutenticacao.COR_TEXTO);
        return l;
    }

    private JLabel rotulo(String texto) {
        JLabel l = new JLabel(texto);
        l.setFont(TelasAutenticacao.FONTE_LABEL);
        l.setForeground(TelasAutenticacao.COR_TEXTO_DIM);
        return l;
    }

    private JButton botaoPequeno(String texto) {
        JButton b = new JButton(texto);
        b.setFont(TelasAutenticacao.FONTE_BOTAO);
        b.setBackground(TelasAutenticacao.COR_PAINEL);
        b.setForeground(TelasAutenticacao.COR_ACENTO);
        b.setFocusPainted(false);
        b.setPreferredSize(new Dimension(48, 34));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return b;
    }
}
