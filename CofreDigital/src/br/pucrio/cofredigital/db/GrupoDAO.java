// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.db;

import br.pucrio.cofredigital.model.Grupo;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class GrupoDAO {
    
    // READ - Buscar por GID
    public Grupo findByGid(int gid) throws SQLException {
        String sql = "SELECT * FROM Grupos WHERE GID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, gid);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return new Grupo(rs.getInt("GID"), rs.getString("nome_grupo"));
            }
            return null;
        }
    }
    
    // READ - Buscar por nome
    public Grupo findByNome(String nomeGrupo) throws SQLException {
        String sql = "SELECT * FROM Grupos WHERE nome_grupo = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, nomeGrupo);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return new Grupo(rs.getInt("GID"), rs.getString("nome_grupo"));
            }
            return null;
        }
    }
    
    // READ - Listar todos os grupos
    public List<Grupo> findAll() throws SQLException {
        List<Grupo> grupos = new ArrayList<>();
        String sql = "SELECT * FROM Grupos ORDER BY GID";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                grupos.add(new Grupo(rs.getInt("GID"), rs.getString("nome_grupo")));
            }
        }
        return grupos;
    }
}