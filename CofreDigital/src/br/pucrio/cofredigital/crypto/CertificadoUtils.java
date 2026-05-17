// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.crypto;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

/**
 * Extrai informações do certificado digital X.509.
 *
 * O campo Subject do certificado tem formato Distinguished Name (DN):
 *   CN=Nome Completo, emailAddress=usuario@email.com, O=Organização, ...
 *
 * Daqui a gente precisa extrair:
 *   - E-mail  → usado como login_name do usuário
 *   - Nome    → nome_usuario na tabela Usuarios
 */
public class CertificadoUtils {

    /**
     * Extrai o e-mail do campo Subject do certificado.
     *
     * O e-mail pode aparecer de várias formas dependendo da JVM e da ferramenta
     * que gerou o certificado:
     *   - EMAILADDRESS=usuario@dominio.com   (RFC1779 / formato legível)
     *   - E=usuario@dominio.com              (alias curto)
     *   - 1.2.840.113549.1.9.1=usuario@...  (RFC2253 com OID numérico + valor texto)
     *   - 1.2.840.113549.1.9.1=#160f...     (RFC2253 com OID + valor como hex DER)
     *
     * @param cert  certificado X.509
     * @return e-mail do usuário ou null se não encontrado
     */
    public static String extrairEmail(X509Certificate cert) {
        // --- Tentativa 1: RFC1779 expande mais aliases ---
        String dn1779 = cert.getSubjectX500Principal().getName(X500Principal.RFC1779);
        String email = extrairCampoDN(dn1779, "EMAILADDRESS");
        if (email == null) email = extrairCampoDN(dn1779, "E");

        // --- Tentativa 2: RFC2253 (padrão mais restrito) ---
        if (email == null) {
            String dn2253 = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
            email = extrairCampoDN(dn2253, "EMAILADDRESS");
            if (email == null) email = extrairCampoDN(dn2253, "E");
            if (email == null) email = extrairCampoDN(dn2253, "1.2.840.113549.1.9.1");

            // RFC2253 serializa IA5String de OIDs desconhecidos como #<hexDER>
            // Ex: "#160f74657374654070756372696f2e6272" → "teste@pucrio.br"
            if (email != null && email.startsWith("#")) {
                email = decodificarHexDER(email);
            }
        }

        // --- Tentativa 3: Subject Alternative Names (tipo 1 = rfc822Name) ---
        if (email == null) {
            try {
                var sans = cert.getSubjectAlternativeNames();
                if (sans != null) {
                    for (var san : sans) {
                        if (san.get(0).equals(1)) {
                            email = (String) san.get(1);
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                // ignorar — retorna null
            }
        }

        return email;
    }

    /**
     * Decodifica um valor no formato #<hexDER> retornado pelo RFC2253.
     *
     * O RFC2253 representa atributos com OIDs não reconhecidos cujo valor
     * é uma string ASN.1 como um blob hexadecimal prefixado com '#'.
     * Esta função extrai o conteúdo descartando tag e length do DER.
     *
     * Exemplo:
     *   "#160f74657374654070756372696f2e6272"
     *    ↑ tag=0x16 (IA5String), length=0x0f (15 bytes), restante = ASCII do e-mail
     *
     * @param hexDer  valor no formato #<hex> vindo do RFC2253
     * @return conteúdo decodificado como String, ou null se falhar
     */
    private static String decodificarHexDER(String hexDer) {
        try {
            String hex = hexDer.substring(1); // remover '#'
            if (hex.length() % 2 != 0) return null;

            byte[] der = new byte[hex.length() / 2];
            for (int i = 0; i < der.length; i++) {
                der[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }

            if (der.length < 2) return null;

            int tag = der[0] & 0xFF;
            // Suportar length < 128 (short form) e length < 256 (long form 1 byte)
            int contentStart;
            int length;
            if ((der[1] & 0xFF) < 128) {
                length = der[1] & 0xFF;
                contentStart = 2;
            } else if ((der[1] & 0xFF) == 0x81 && der.length > 2) {
                length = der[2] & 0xFF;
                contentStart = 3;
            } else {
                return null;
            }

            if (contentStart + length > der.length) return null;

            // Tags de string ASCII/UTF-8
            // 0x16 = IA5String, 0x0C = UTF8String,
            // 0x13 = PrintableString, 0x14 = TeletexString
            if (tag == 0x16 || tag == 0x0C || tag == 0x13 || tag == 0x14) {
                return new String(der, contentStart, length, "UTF-8");
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extrai o nome amigável (CN - Common Name) do Subject do certificado.
     *
     * @param cert  certificado X.509
     * @return nome do usuário ou null se não encontrado
     */
    public static String extrairNome(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
        return extrairCampoDN(dn, "CN");
    }

    /**
     * Retorna o Distinguished Name completo do Subject.
     *
     * @param cert  certificado X.509
     * @return String com o DN completo
     */
    public static String extrairSubject(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
    }

    /**
     * Retorna o Distinguished Name do Emissor (Issuer) do certificado.
     *
     * @param cert  certificado X.509
     * @return String com o DN do emissor
     */
    public static String extrairEmissor(X509Certificate cert) {
        return cert.getIssuerX500Principal().getName(X500Principal.RFC2253);
    }

    /**
     * Retorna o número de série do certificado em hexadecimal.
     *
     * @param cert  certificado X.509
     * @return String com o número de série em hex maiúsculo
     */
    public static String extrairSerie(X509Certificate cert) {
        return cert.getSerialNumber().toString(16).toUpperCase();
    }

    /**
     * Retorna a versão do certificado (geralmente "3").
     *
     * @param cert  certificado X.509
     * @return versão como String
     */
    public static String extrairVersao(X509Certificate cert) {
        return String.valueOf(cert.getVersion());
    }

    /**
     * Retorna o período de validade do certificado.
     *
     * @param cert  certificado X.509
     * @return String com "De <data> até <data>"
     */
    public static String extrairValidade(X509Certificate cert) {
        return "De " + cert.getNotBefore() + " até " + cert.getNotAfter();
    }

    /**
     * Retorna o algoritmo de assinatura do certificado.
     * Ex: "SHA256withRSA"
     *
     * @param cert  certificado X.509
     * @return nome do algoritmo de assinatura
     */
    public static String extrairTipoAssinatura(X509Certificate cert) {
        return cert.getSigAlgName();
    }

    // -------------------------------------------------------------------------
    // MÉTODO AUXILIAR INTERNO
    // -------------------------------------------------------------------------

    /**
     * Extrai o valor de um campo específico do Distinguished Name.
     *
     * O DN tem formato:  CAMPO1=valor1,CAMPO2=valor2,...
     * Valores com vírgula ficam entre aspas: CAMPO="valor,com,virgula"
     *
     * @param dn     Distinguished Name completo
     * @param campo  nome do campo a buscar (ex: "CN", "EMAILADDRESS")
     * @return valor do campo ou null se não encontrado
     */
    private static String extrairCampoDN(String dn, String campo) {
        String prefixo      = campo + "=";
        String prefixoLower = campo.toLowerCase() + "=";

        for (String parte : dn.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)")) {
            parte = parte.trim();
            String parteLower = parte.toLowerCase();

            if (parteLower.startsWith(prefixoLower)) {
                String valor = parte.substring(prefixo.length());
                // Remover aspas se houver
                if (valor.startsWith("\"") && valor.endsWith("\"")) {
                    valor = valor.substring(1, valor.length() - 1);
                }
                return valor;
            }
        }
        return null;
    }
}