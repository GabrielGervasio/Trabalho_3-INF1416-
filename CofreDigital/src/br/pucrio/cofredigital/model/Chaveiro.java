// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.model;

public class Chaveiro {
    private int kid;
    private int uid;
    private String certPem;
    private byte[] chavePrivadaBin;
    
    // Construtores
    public Chaveiro() {}
    
    public Chaveiro(int uid, String certPem, byte[] chavePrivadaBin) {
        this.uid = uid;
        this.certPem = certPem;
        this.chavePrivadaBin = chavePrivadaBin;
    }
    
    // Getters e Setters
    public int getKid() { return kid; }
    public void setKid(int kid) { this.kid = kid; }
    
    public int getUid() { return uid; }
    public void setUid(int uid) { this.uid = uid; }
    
    public String getCertPem() { return certPem; }
    public void setCertPem(String certPem) { this.certPem = certPem; }
    
    public byte[] getChavePrivadaBin() { return chavePrivadaBin; }
    public void setChavePrivadaBin(byte[] chavePrivadaBin) { this.chavePrivadaBin = chavePrivadaBin; }
}