// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.model;

public class Grupo {
    private int gid;
    private String nomeGrupo;
    
    public Grupo() {}
    
    public Grupo(int gid, String nomeGrupo) {
        this.gid = gid;
        this.nomeGrupo = nomeGrupo;
    }
    
    public int getGid() { return gid; }
    public void setGid(int gid) { this.gid = gid; }
    
    public String getNomeGrupo() { return nomeGrupo; }
    public void setNomeGrupo(String nomeGrupo) { this.nomeGrupo = nomeGrupo; }
}