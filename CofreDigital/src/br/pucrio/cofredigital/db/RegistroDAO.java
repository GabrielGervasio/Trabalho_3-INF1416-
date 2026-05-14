package br.pucrio.cofredigital.db;

import br.pucrio.cofredigital.model.Registro;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Date;

public class RegistroDAO {
    
    // CREATE - Inserir registro
    private int insert(Registro registro) throws SQLException {
        String sql = "INSERT INTO Registros (data_hora, MID, UID, arq_name) VALUES (?, ?, ?, ?)";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String dataHora = sdf.format(new Date());
            pstmt.setString(1, dataHora);
            pstmt.setInt(2, registro.getMid());
            
            if (registro.getUid() != null) {
                pstmt.setInt(3, registro.getUid());
            } else {
                pstmt.setNull(3, Types.INTEGER);
            }
            
            pstmt.setString(4, registro.getArqName());
            
            int affectedRows = pstmt.executeUpdate();
            
            if (affectedRows > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        int rid = rs.getInt(1);
                        registro.setRid(rid);
                        return rid;
                    }
                }
            }
            return -1;
        }
    }
    
    // Método de conveniência para inserir log sem arquivo
    public void log(int mid, Integer uid) throws SQLException {
        Registro registro = new Registro(mid, uid, null);
        insert(registro);
    }
    
    // Método de conveniência para inserir log com arquivo
    public void log(int mid, Integer uid, String arqName) throws SQLException {
        Registro registro = new Registro(mid, uid, arqName);
        insert(registro);
    }
    
    // READ - Buscar por RID
    public Registro findByRid(int rid) throws SQLException {
        String sql = "SELECT * FROM Registros WHERE RID = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, rid);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return extractRegistroFromResultSet(rs);
            }
            return null;
        }
    }
    
    // READ - Buscar logs por usuário
    public List<Registro> findByUid(int uid) throws SQLException {
        List<Registro> logs = new ArrayList<>();
        String sql = "SELECT * FROM Registros WHERE UID = ? ORDER BY data_hora DESC";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, uid);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                logs.add(extractRegistroFromResultSet(rs));
            }
        }
        return logs;
    }
    
    // READ - Buscar logs por código de mensagem
    public List<Registro> findByMid(int mid) throws SQLException {
        List<Registro> logs = new ArrayList<>();
        String sql = "SELECT * FROM Registros WHERE MID = ? ORDER BY data_hora DESC";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, mid);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                logs.add(extractRegistroFromResultSet(rs));
            }
        }
        return logs;
    }
    
    // READ - Buscar logs com JOIN com Mensagens (para logView)
    public List<String> findLogsComMensagens() throws SQLException {
        List<String> logs = new ArrayList<>();
        String sql = "SELECT r.data_hora, r.MID, m.texto_mensagem, r.arq_name " +
                     "FROM Registros r " +
                     "JOIN Mensagens m ON r.MID = m.MID " +
                     "ORDER BY r.data_hora";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                String log = String.format("[%s] %d - %s", 
                    rs.getTimestamp("data_hora"),
                    rs.getInt("MID"),
                    rs.getString("texto_mensagem"));
                
                if (rs.getString("arq_name") != null) {
                    log += " [arquivo: " + rs.getString("arq_name") + "]";
                }
                logs.add(log);
            }
        }
        return logs;
    }
    
    // READ - Listar todos os registros
    public List<Registro> findAll() throws SQLException {
        List<Registro> logs = new ArrayList<>();
        String sql = "SELECT * FROM Registros ORDER BY data_hora DESC";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                logs.add(extractRegistroFromResultSet(rs));
            }
        }
        return logs;
    }
    
    // DELETE - Remover registro antigos (opcional, para limpeza)
    public void deleteOldLogs(int dias) throws SQLException {
        String sql = "DELETE FROM Registros WHERE data_hora < datetime('now', '-' || ? || ' days')";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, dias);
            pstmt.executeUpdate();
        }
    }
    
    // Método auxiliar
    private Registro extractRegistroFromResultSet(ResultSet rs) throws SQLException {
        Registro registro = new Registro();
        registro.setRid(rs.getInt("RID"));
        registro.setDataHora(rs.getTimestamp("data_hora"));
        registro.setMid(rs.getInt("MID"));
        
        int uid = rs.getInt("UID");
        if (!rs.wasNull()) {
            registro.setUid(uid);
        }
        
        registro.setArqName(rs.getString("arq_name"));
        return registro;
    }

    public static void registrar(int mid, Integer uid, String arqName) {
        String sql = "INSERT INTO Registros (data_hora, MID, UID, arq_name) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseConnection.getConnection();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String dataHora = sdf.format(new Date());
            pstmt.setString(1, dataHora);
            pstmt.setInt(2, mid);
            
            if (uid != null) {
                pstmt.setInt(3, uid); 
            } else {
                pstmt.setNull(3, java.sql.Types.INTEGER);
            }
            
            pstmt.setString(4, arqName);
            pstmt.executeUpdate();
            
        } catch (SQLException e) {
            System.err.println("Erro ao registrar MID=" + mid + ": " + e.getMessage());
        }
    }
}