package br.pucrio.cofredigital.model;

import java.sql.Timestamp;

public class Usuario {
    private int uid;
    private String loginName;
    private String nomeUsuario;
    private String senhaBcrypt;
    private String totpEnc;
    private int kid;
    private int gid;
    private Timestamp bloqueadoAte;
    private int totalAcessos;
    
    // Construtores
    public Usuario() {}
    
    public Usuario(String loginName, String nomeUsuario, String senhaBcrypt, 
                   String totpEnc, int kid, int gid) {
        this.loginName = loginName;
        this.nomeUsuario = nomeUsuario;
        this.senhaBcrypt = senhaBcrypt;
        this.totpEnc = totpEnc;
        this.kid = kid;
        this.gid = gid;
        this.totalAcessos = 0;
    }
    
    // Getters e Setters
    public int getUid() { return uid; }
    public void setUid(int uid) { this.uid = uid; }
    
    public String getLoginName() { return loginName; }
    public void setLoginName(String loginName) { this.loginName = loginName; }
    
    public String getNomeUsuario() { return nomeUsuario; }
    public void setNomeUsuario(String nomeUsuario) { this.nomeUsuario = nomeUsuario; }
    
    public String getSenhaBcrypt() { return senhaBcrypt; }
    public void setSenhaBcrypt(String senhaBcrypt) { this.senhaBcrypt = senhaBcrypt; }
    
    public String getTotpEnc() { return totpEnc; }
    public void setTotpEnc(String totpEnc) { this.totpEnc = totpEnc; }
    
    public int getKid() { return kid; }
    public void setKid(int kid) { this.kid = kid; }
    
    public int getGid() { return gid; }
    public void setGid(int gid) { this.gid = gid; }
    
    public Timestamp getBloqueadoAte() { return bloqueadoAte; }
    public void setBloqueadoAte(Timestamp bloqueadoAte) { this.bloqueadoAte = bloqueadoAte; }
    
    public int getTotalAcessos() { return totalAcessos; }
    public void setTotalAcessos(int totalAcessos) { this.totalAcessos = totalAcessos; }
    
    @Override
    public String toString() {
        return "Usuario{" +
                "uid=" + uid +
                ", loginName='" + loginName + '\'' +
                ", nomeUsuario='" + nomeUsuario + '\'' +
                ", gid=" + gid +
                '}';
    }
}