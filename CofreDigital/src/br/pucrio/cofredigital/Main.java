package br.pucrio.cofredigital;

import br.pucrio.cofredigital.db.*;
import br.pucrio.cofredigital.model.*;

public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("=== Teste DAO ===\n");
            
            // Inicializar banco
            DatabaseConnection.initializeDatabase();
            
            // POPULAR TABELAS (grupos e mensagens)
            DatabaseInitializer.initializeGroups();
            DatabaseInitializer.initializeMessages();
            
            // Testar GrupoDAO
            GrupoDAO grupoDAO = new GrupoDAO();
            System.out.println("Grupos disponíveis:");
            for (Grupo g : grupoDAO.findAll()) {
                System.out.println("  - " + g.getGid() + ": " + g.getNomeGrupo());
            }
            
            // Testar contagem de usuários
            UsuarioDAO usuarioDAO = new UsuarioDAO();
            System.out.println("\nTotal de usuários: " + usuarioDAO.count());
            
            // Testar RegistroDAO
            RegistroDAO registroDAO = new RegistroDAO();
            System.out.println("\nÚltimos logs:");
            for (Registro r : registroDAO.findAll()) {
                System.out.println("  - " + r.getDataHora() + " | MID: " + r.getMid());
            }
            
            System.out.println("\n✅ DAOs funcionando corretamente!");
            
            DatabaseConnection.closeConnection();
            
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
            e.printStackTrace();
        }
    }
}