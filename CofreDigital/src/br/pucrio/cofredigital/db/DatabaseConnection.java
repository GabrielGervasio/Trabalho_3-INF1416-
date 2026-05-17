// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.db;

import java.sql.*;

public class DatabaseConnection {
    private static final String URL = "jdbc:sqlite:meubanco.db";
    private static Connection connection = null;

    public static Connection getConnection() throws SQLException {
        if (connection == null || connection.isClosed()) {
            connection = DriverManager.getConnection(URL);
        }
        return connection;
    }

    public static void initializeDatabase() {
        String sql = "CREATE TABLE IF NOT EXISTS Grupos (GID INTEGER PRIMARY KEY AUTOINCREMENT, nome_grupo VARCHAR(20) NOT NULL UNIQUE);" +
             "CREATE TABLE IF NOT EXISTS Mensagens (MID INTEGER PRIMARY KEY, texto_mensagem VARCHAR(255) NOT NULL);" +
             "CREATE TABLE IF NOT EXISTS Chaveiro (KID INTEGER PRIMARY KEY AUTOINCREMENT, UID INTEGER NOT NULL, cert_pem TEXT NOT NULL, chave_privada_bin BLOB NOT NULL);" +
             "CREATE TABLE IF NOT EXISTS Usuarios (UID INTEGER PRIMARY KEY AUTOINCREMENT, login_name VARCHAR(100) NOT NULL UNIQUE, nome_usuario VARCHAR(100) NOT NULL, senha_bcrypt VARCHAR(60) NOT NULL, totp_enc BLOB NOT NULL, KID INTEGER, GID INTEGER NOT NULL, bloqueado_ate TIMESTAMP, total_acessos INTEGER DEFAULT 0);" +
             "CREATE TABLE IF NOT EXISTS Registros (RID INTEGER PRIMARY KEY AUTOINCREMENT, data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP, MID INTEGER NOT NULL, UID INTEGER, arq_name VARCHAR(255));";
        
        try (Statement stmt = getConnection().createStatement()) {
            for (String s : sql.split(";")) {
                if (!s.trim().isEmpty()) {
                    stmt.execute(s);
                }
            }
            System.out.println("Banco de dados inicializado com sucesso!");
        } catch (SQLException e) {
            System.err.println("Erro ao inicializar banco: " + e.getMessage());
        }
    }

    public static void closeConnection() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            System.err.println("Erro ao fechar conexão: " + e.getMessage());
        }
    }
}