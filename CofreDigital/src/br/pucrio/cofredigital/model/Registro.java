// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.model;

import java.sql.Timestamp;

public class Registro {
    private int rid;
    private Timestamp dataHora;
    private int mid;
    private Integer uid;  // pode ser null
    private String arqName;  // pode ser null
    
    // Construtores
    public Registro() {}
    
    public Registro(int mid, Integer uid, String arqName) {
        this.mid = mid;
        this.uid = uid;
        this.arqName = arqName;
    }
    
    // Getters e Setters
    public int getRid() { return rid; }
    public void setRid(int rid) { this.rid = rid; }
    
    public Timestamp getDataHora() { return dataHora; }
    public void setDataHora(Timestamp dataHora) { this.dataHora = dataHora; }
    
    public int getMid() { return mid; }
    public void setMid(int mid) { this.mid = mid; }
    
    public Integer getUid() { return uid; }
    public void setUid(Integer uid) { this.uid = uid; }
    
    public String getArqName() { return arqName; }
    public void setArqName(String arqName) { this.arqName = arqName; }
}