// Benito Andre Pepe - 2311720
// Gabriel Gervasio de santana - 2312672

package br.pucrio.cofredigital.auth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Lógica do teclado virtual numérico sobrecarregado.
 *
 * Especificação do enunciado:
 *   - 5 botões, cada um com 2 dígitos
 *   - Dígitos distribuídos aleatoriamente e sem repetição
 *   - A cada clique em um botão, os dígitos são redistribuídos
 *   - A senha tem 8, 9 ou 10 dígitos
 *
 * Como funciona:
 *   1. Ao iniciar, embaralha os dígitos 0-9 e distribui 2 por botão
 *   2. Usuário clica em um botão → o sistema registra QUAL botão foi clicado
 *      (não qual dígito, pois são dois por botão)
 *   3. Após cada clique, redistribui os dígitos nos 5 botões
 *   4. Ao final, compara a senha real com todas as combinações possíveis
 *
 * Estratégia de verificação:
 *   Cada botão clicado representa um de dois possíveis dígitos.
 *   Com 8-10 cliques, há 2^8 a 2^10 combinações possíveis (256 a 1024).
 *   O bcrypt verifica cada combinação até encontrar a correta.
 *   É por isso que o professor escolheu custo 8 no bcrypt — balanceia
 *   segurança vs performance para esse volume de verificações.
 *
 * Uso pela UI:
 *   TecladoVirtual teclado = new TecladoVirtual();
 *   teclado.getBotoes()  → String[] com os 5 pares de dígitos ex: ["04","17","29","35","68"]
 *   teclado.clicarBotao(2) → registra clique no botão índice 2 e redistribui
 *   teclado.getSenhaPossivel() → retorna lista de combinações para o AuthController
 */
public class TecladoVirtual {

    /** Número de botões */
    private static final int NUM_BOTOES = 5;

    /** Dígitos por botão */
    private static final int DIGITOS_POR_BOTAO = 2;

    /**
     * Estado atual dos botões: cada posição tem 2 dígitos.
     * Ex: botoes[0] = {0, 4} → botão 1 mostra "0" e "4"
     */
    private int[][] botoes = new int[NUM_BOTOES][DIGITOS_POR_BOTAO];

    /**
     * Histórico de cliques: guarda o índice do botão clicado em cada passo.
     * Cada entrada é um índice 0-4.
     */
    private List<int[]> historicoCliques = new ArrayList<>();

    public TecladoVirtual() {
        redistribuir();
    }

    // =========================================================================
    // REDISTRIBUIÇÃO DOS DÍGITOS
    // =========================================================================

    /**
     * Embaralha os dígitos 0-9 aleatoriamente e distribui 2 por botão.
     * Chamado no início e após cada clique.
     */
    public void redistribuir() {
        // Criar lista [0,1,2,3,4,5,6,7,8,9] e embaralhar
        List<Integer> digitos = new ArrayList<>();
        for (int i = 0; i <= 9; i++) digitos.add(i);
        Collections.shuffle(digitos);

        // Distribuir 2 dígitos por botão
        for (int b = 0; b < NUM_BOTOES; b++) {
            botoes[b][0] = digitos.get(b * 2);
            botoes[b][1] = digitos.get(b * 2 + 1);
        }
    }

    // =========================================================================
    // CLIQUE EM BOTÃO
    // =========================================================================

    /**
     * Registra o clique em um botão e redistribui os dígitos.
     *
     * @param indiceBotao  índice do botão clicado (0 a 4)
     */
    public void clicarBotao(int indiceBotao) {
        if (indiceBotao < 0 || indiceBotao >= NUM_BOTOES) {
            throw new IllegalArgumentException("Índice de botão inválido: " + indiceBotao);
        }

        // Guardar os dois dígitos do botão clicado neste momento
        int[] digitosClicados = { botoes[indiceBotao][0], botoes[indiceBotao][1] };
        historicoCliques.add(digitosClicados);

        // Redistribuir para o próximo dígito
        redistribuir();
    }

    /**
     * Remove o último dígito digitado (backspace).
     */
    public void removerUltimo() {
        if (!historicoCliques.isEmpty()) {
            historicoCliques.remove(historicoCliques.size() - 1);
            redistribuir();
        }
    }

    /**
     * Limpa todos os dígitos digitados.
     */
    public void limpar() {
        historicoCliques.clear();
        redistribuir();
    }

    // =========================================================================
    // GETTERS PARA A UI
    // =========================================================================

    /**
     * Retorna os rótulos dos 5 botões para exibir na UI.
     * Cada rótulo tem os dois dígitos do botão, ex: "0 4"
     *
     * @return array de 5 Strings, uma por botão
     */
    public String[] getRotulosBotoes() {
        String[] rotulos = new String[NUM_BOTOES];
        for (int b = 0; b < NUM_BOTOES; b++) {
            rotulos[b] = botoes[b][0] + " ou " + botoes[b][1];
        }
        return rotulos;
    }

    /**
     * Retorna os pares de dígitos de cada botão (para a UI desenhar).
     * Ex: [[0,4], [1,7], [2,9], [3,5], [6,8]]
     */
    public int[][] getBotoes() {
        return botoes;
    }

    /**
     * Quantidade de dígitos já digitados.
     */
    public int getQuantidadeDigitada() {
        return historicoCliques.size();
    }

    /**
     * Retorna "*" repetido para mostrar progresso sem revelar a senha.
     */
    public String getMascaraProgresso() {
        return "*".repeat(historicoCliques.size());
    }

    // =========================================================================
    // GERAÇÃO DE COMBINAÇÕES PARA VERIFICAÇÃO
    // =========================================================================

    /**
     * Gera todas as combinações possíveis de senha a partir dos cliques registrados.
     *
     * Para cada posição, o usuário clicou em um botão com 2 dígitos possíveis.
     * Com N cliques, há 2^N combinações.
     *
     * Ex: clicou em botão[0,4] depois botão[1,7]:
     *   combinações: "01", "07", "41", "47"
     *
     * O AuthController passa essas combinações para o BcryptUtils.verificar()
     * até encontrar a que bate com o hash armazenado.
     *
     * @return lista de todas as senhas possíveis como String
     */
    public List<String> gerarCombinacoes() {
        List<String> combinacoes = new ArrayList<>();
        combinacoes.add(""); // começa com string vazia

        for (int[] digitosClicados : historicoCliques) {
            List<String> novasCombinacoes = new ArrayList<>();
            for (String combinacaoAtual : combinacoes) {
                // Para cada combinação existente, adicionar cada dígito possível
                novasCombinacoes.add(combinacaoAtual + digitosClicados[0]);
                novasCombinacoes.add(combinacaoAtual + digitosClicados[1]);
            }
            combinacoes = novasCombinacoes;
        }

        return combinacoes;
    }
}
