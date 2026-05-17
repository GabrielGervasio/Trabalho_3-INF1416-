// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.db;

import br.pucrio.cofredigital.model.Usuario;
import java.sql.*;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

public class UsuarioDAO {
    
    // CREATE - Inserir novo usuário
    public int insert(Usuario usuario) throws SQLException {
        String sql = "INSERT INTO Usuarios (login_name, nome_usuario, senha_bcrypt, totp_enc, KID, GID, total_acessos) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            
            pstmt.setString(1, usuario.getLoginName());
            pstmt.setString(2, usuario.getNomeUsuario());
            pstmt.setString(3, usuario.getSenhaBcrypt());
            pstmt.setString(4, usuario.getTotpEnc());
            pstmt.setInt(5, usuario.getKid());
            pstmt.setInt(6, usuario.getGid());
            pstmt.setInt(7, usuario.getTotalAcessos());
            
            int affectedRows = pstmt.executeUpdate();
            
            if (affectedRows > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        int uid = rs.getInt(1);
                        usuario.setUid(uid);
                        return uid;
                    }
                }
            }
            return -1;
        }
    }
    
    // READ - Buscar por UID
    public Usuario findByUid(int uid) throws SQLException {
        String sql = "SELECT * FROM Usuarios WHERE UID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, uid);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return extractUsuarioFromResultSet(rs);
            }
            return null;
        }
    }
    
    // READ - Buscar por login (e-mail)
    public Usuario findByLogin(String loginName) throws SQLException {
        String sql = "SELECT * FROM Usuarios WHERE login_name = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, loginName);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return extractUsuarioFromResultSet(rs);
            }
            return null;
        }
    }
    
    // READ - Listar todos os usuários
    public List<Usuario> findAll() throws SQLException {
        List<Usuario> usuarios = new ArrayList<>();
        String sql = "SELECT * FROM Usuarios ORDER BY UID";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                usuarios.add(extractUsuarioFromResultSet(rs));
            }
        }
        return usuarios;
    }
    
    // UPDATE - Atualizar dados do usuário
    public void update(Usuario usuario) throws SQLException {
        String sql = "UPDATE Usuarios SET login_name = ?, nome_usuario = ?, senha_bcrypt = ?, " +
                     "totp_enc = ?, KID = ?, GID = ?, bloqueado_ate = ?, total_acessos = ? " +
                     "WHERE UID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, usuario.getLoginName());
            pstmt.setString(2, usuario.getNomeUsuario());
            pstmt.setString(3, usuario.getSenhaBcrypt());
            pstmt.setString(4, usuario.getTotpEnc());
            pstmt.setInt(5, usuario.getKid());
            pstmt.setInt(6, usuario.getGid());
            pstmt.setTimestamp(7, usuario.getBloqueadoAte());
            pstmt.setInt(8, usuario.getTotalAcessos());
            pstmt.setInt(9, usuario.getUid());
            
            pstmt.executeUpdate();
        }
    }
    
    // UPDATE - Incrementar total de acessos
    public void incrementarAcessos(int uid) throws SQLException {
        String sql = "UPDATE Usuarios SET total_acessos = total_acessos + 1 WHERE UID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, uid);
            pstmt.executeUpdate();
        }
    }
    
    // UPDATE - Bloquear usuário por X minutos
    public void bloquearUsuario(int uid, int minutos) throws SQLException {
        String sql = "UPDATE Usuarios SET bloqueado_ate = ? WHERE UID = ?";

        Timestamp bloqueadoAte = new Timestamp(System.currentTimeMillis() + (long) minutos * 60L * 1000L);

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setTimestamp(1, bloqueadoAte);
            pstmt.setInt(2, uid);
            pstmt.executeUpdate();
        }
    }
    
    // DELETE - Remover usuário
    public void delete(int uid) throws SQLException {
        String sql = "DELETE FROM Usuarios WHERE UID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, uid);
            pstmt.executeUpdate();
        }
    }
    
    // Verificar se login já existe
    public boolean existsByLogin(String loginName) throws SQLException {
        String sql = "SELECT COUNT(*) FROM Usuarios WHERE login_name = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, loginName);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        }
    }
    
    // Contar total de usuários
    public int count() throws SQLException {
        String sql = "SELECT COUNT(*) FROM Usuarios";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }
    
    // Método auxiliar para extrair Usuario do ResultSet
    private Usuario extractUsuarioFromResultSet(ResultSet rs) throws SQLException {
        Usuario usuario = new Usuario();
        usuario.setUid(rs.getInt("UID"));
        usuario.setLoginName(rs.getString("login_name"));
        usuario.setNomeUsuario(rs.getString("nome_usuario"));
        usuario.setSenhaBcrypt(rs.getString("senha_bcrypt"));
        usuario.setTotpEnc(rs.getString("totp_enc"));
        usuario.setKid(rs.getInt("KID"));
        usuario.setGid(rs.getInt("GID"));
        usuario.setBloqueadoAte(rs.getTimestamp("bloqueado_ate"));
        usuario.setTotalAcessos(rs.getInt("total_acessos"));
        return usuario;
    }

    public Usuario findAdmin() throws SQLException {
        String sql = "SELECT * FROM Usuarios WHERE GID = 1 LIMIT 1";
        try (Connection conn = DatabaseConnection.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) return extractUsuarioFromResultSet(rs);
            return null;
        }
    }

    public boolean estaBloqueado(int uid) throws SQLException {
        String sql = "SELECT COUNT(*) FROM Usuarios WHERE UID = ? " +
                    "AND bloqueado_ate IS NOT NULL " +
                    "AND datetime(bloqueado_ate) > datetime('now')";
        try (Connection conn = DatabaseConnection.getConnection();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, uid);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        }
    }
    
}