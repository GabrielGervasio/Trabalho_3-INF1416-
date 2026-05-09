package br.pucrio.cofredigital;

import br.pucrio.cofredigital.auth.AuthController;
import br.pucrio.cofredigital.crypto.*;
import br.pucrio.cofredigital.db.*;
import br.pucrio.cofredigital.model.*;
import br.pucrio.cofredigital.ui.TelasAutenticacao;
import br.pucrio.cofredigital.ui.TelaCadastro;

import javax.swing.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Main {

    private static PrivateKey chavePrivadaAdmin = null;
    private static String     fraseSecretaAdmin = null;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}
            iniciar();
        });
    }

    private static void iniciar() {
        DatabaseConnection.initializeDatabase();
        DatabaseInitializer.initializeGroups();
        DatabaseInitializer.initializeMessages();
        RegistroDAO.registrar(1001, null, null);

        boolean primeiraExecucao = false;
        try {
            primeiraExecucao = new UsuarioDAO().count() == 0;
        } catch (Exception e) {
            mostrarErroFatal("Erro ao acessar banco de dados:\n" + e.getMessage());
            return;
        }

        if (primeiraExecucao) {
            RegistroDAO.registrar(1005, null, null);
            iniciarCadastroAdmin();
        } else {
            RegistroDAO.registrar(1006, null, null);
            validarAdminEIniciar();
        }
    }

    // ── Primeira execução: abrir TelaCadastro em modo admin ──────────────────
    private static void iniciarCadastroAdmin() {
        AuthController auth = new AuthController();
        new TelaCadastro(auth, null, true).setVisible(true);
    }

    // ── Segunda execução em diante: validar frase do admin ───────────────────
    private static void validarAdminEIniciar() {
        Usuario admin = null;
        Chaveiro chaveiro = null;
        try {
            admin    = new UsuarioDAO().findAdmin();
            if (admin != null)
                chaveiro = new ChaveiroDAO().findByKid(admin.getKid());
        } catch (Exception e) {
            mostrarErroFatal("Erro ao buscar administrador:\n" + e.getMessage());
            return;
        }

        if (admin == null || chaveiro == null) {
            mostrarErroFatal("Administrador não encontrado no banco de dados.");
            return;
        }

        JPasswordField campoFrase = new JPasswordField(30);
        campoFrase.setFont(new java.awt.Font("Courier New", java.awt.Font.PLAIN, 13));

        int opcao = JOptionPane.showConfirmDialog(null,
            new Object[]{"Digite a frase secreta da chave privada do Administrador:", campoFrase},
            "Cofre Digital — Partida do Sistema",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (opcao != JOptionPane.OK_OPTION) { encerrar(); return; }

        String frase = new String(campoFrase.getPassword()).trim();
        if (frase.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                "Frase secreta não pode ser vazia. Sistema encerrado.",
                "Erro", JOptionPane.ERROR_MESSAGE);
            encerrar(); return;
        }

        try {
            PrivateKey chavePrivada = CryptoUtils.lerChavePrivadaDosBytes(
                chaveiro.getChavePrivadaBin(), frase);
            X509Certificate cert = CryptoUtils.certificadoDePEM(chaveiro.getCertPem());
            boolean valida = CryptoUtils.validarChavePrivada(
                chavePrivada, cert.getPublicKey(), 9216);

            if (!valida) {
                JOptionPane.showMessageDialog(null,
                    "Validação da chave privada negativa.\nSistema encerrado.",
                    "Erro de autenticação", JOptionPane.ERROR_MESSAGE);
                encerrar(); return;
            }

            chavePrivadaAdmin = chavePrivada;
            fraseSecretaAdmin = frase;

        } catch (Exception e) {
            JOptionPane.showMessageDialog(null,
                "Frase secreta inválida ou chave corrompida.\nSistema encerrado.",
                "Erro de autenticação", JOptionPane.ERROR_MESSAGE);
            encerrar(); return;
        }

        AuthController auth = new AuthController();
        new TelasAutenticacao.TelaLogin(auth).setVisible(true);
    }

    public static PrivateKey getChavePrivadaAdmin() { return chavePrivadaAdmin; }

    public static void setChavePrivadaAdmin(PrivateKey chave, String frase) {
        chavePrivadaAdmin = chave;
        fraseSecretaAdmin = frase;
    }

    public static void encerrar() {
        chavePrivadaAdmin = null;
        fraseSecretaAdmin = null;
        RegistroDAO.registrar(1002, null, null);
        DatabaseConnection.closeConnection();
        System.exit(0);
    }

    private static void mostrarErroFatal(String msg) {
        JOptionPane.showMessageDialog(null, msg, "Erro Fatal", JOptionPane.ERROR_MESSAGE);
        encerrar();
    }
}