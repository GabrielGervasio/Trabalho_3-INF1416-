package br.pucrio.cofredigital.db;

import br.pucrio.cofredigital.model.Chaveiro;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class ChaveiroDAO {
    
    // CREATE - Inserir par de chaves
    public int insert(Chaveiro chaveiro) throws SQLException {
        String sql = "INSERT INTO Chaveiro (UID, cert_pem, chave_privada_bin) VALUES (?, ?, ?)";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            
            pstmt.setInt(1, chaveiro.getUid());
            pstmt.setString(2, chaveiro.getCertPem());
            pstmt.setBytes(3, chaveiro.getChavePrivadaBin());
            
            int affectedRows = pstmt.executeUpdate();
            
            if (affectedRows > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        int kid = rs.getInt(1);
                        chaveiro.setKid(kid);
                        return kid;
                    }
                }
            }
            return -1;
        }
    }
    
    // READ - Buscar por KID
    public Chaveiro findByKid(int kid) throws SQLException {
        String sql = "SELECT * FROM Chaveiro WHERE KID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, kid);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return extractChaveiroFromResultSet(rs);
            }
            return null;
        }
    }
    
    // READ - Buscar por UID
    public Chaveiro findByUid(int uid) throws SQLException {
        String sql = "SELECT * FROM Chaveiro WHERE UID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, uid);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return extractChaveiroFromResultSet(rs);
            }
            return null;
        }
    }
    
    // READ - Listar todos
    public List<Chaveiro> findAll() throws SQLException {
        List<Chaveiro> lista = new ArrayList<>();
        String sql = "SELECT * FROM Chaveiro ORDER BY KID";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                lista.add(extractChaveiroFromResultSet(rs));
            }
        }
        return lista;
    }
    
    // UPDATE - Atualizar
    public void update(Chaveiro chaveiro) throws SQLException {
        String sql = "UPDATE Chaveiro SET UID = ?, cert_pem = ?, chave_privada_bin = ? WHERE KID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, chaveiro.getUid());
            pstmt.setString(2, chaveiro.getCertPem());
            pstmt.setBytes(3, chaveiro.getChavePrivadaBin());
            pstmt.setInt(4, chaveiro.getKid());
            
            pstmt.executeUpdate();
        }
    }
    
    // DELETE - Remover por KID
    public void delete(int kid) throws SQLException {
        String sql = "DELETE FROM Chaveiro WHERE KID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, kid);
            pstmt.executeUpdate();
        }
    }
    
    // DELETE - Remover por UID
    public void deleteByUid(int uid) throws SQLException {
        String sql = "DELETE FROM Chaveiro WHERE UID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, uid);
            pstmt.executeUpdate();
        }
    }
    
    // Método auxiliar
    private Chaveiro extractChaveiroFromResultSet(ResultSet rs) throws SQLException {
        Chaveiro chaveiro = new Chaveiro();
        chaveiro.setKid(rs.getInt("KID"));
        chaveiro.setUid(rs.getInt("UID"));
        chaveiro.setCertPem(rs.getString("cert_pem"));
        chaveiro.setChavePrivadaBin(rs.getBytes("chave_privada_bin"));
        return chaveiro;
    }
}