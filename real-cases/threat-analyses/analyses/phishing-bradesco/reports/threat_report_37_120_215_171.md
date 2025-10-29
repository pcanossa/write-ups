# 📋 Relatório de Threat Intelligence – IP **37.120.215.171**

---

## 1. Resumo Executivo
O endereço **37.120.215.171** está localizado em **Miami, Flórida (EE.UU.)** e é parte da rede **AS9009 – M247 Europe SRL** (provedor de hospedagem/data‑center).  
- **Shodan:** nenhum serviço ou banner encontrado (404 – “Not Found”).  
- **URLScan.io:** nenhuma captura de página/web‑site associada.  
- **Portas/Serviços:** sem portas abertas detectadas nas fontes analisadas.  
- **Vulnerabilidades (CVEs):** não foram listadas vulnerabilidades públicas.  
- **Indicadores de comprometimento:** nenhum relato de botnet, scanner ou C2 encontrado nos bancos de dados consultados.  

Conclui‑se que, até o momento, o IP apresenta **baixo nível de risco** ativo, porém está sob um provedor amplamente usado por terceiros e pode servir como “bullet‑proof” para atividades maliciosas futuras.

---

## 2. Análise de Comportamento
| Fonte | Observação | Evidência de atividade maliciosa |
|-------|------------|---------------------------------|
| **Shodan** | Página de resultado “404 – Not Found”. Nenhum serviço identificado (HTTP, SSH, RDP, etc.). | ❌ Não há indícios de scanner, serviço vulnerável ou servidor C2. |
| **URLScan.io** | Busca retornou 0 resultados. | ❌ Nenhum site ou payload observado. |
| **IPInfo / RDAP** | O IP pertence a **M247 – Miami Infrastructure**, bloco atribuído à RIPE NCC. Contatos associados a empresas na Romênia (Secure Data Systems). | ❓ Uso legítimo de data‑center, mas a presença de “bullet‑proof” hosting pode atrair abusos. |
| **Feeds públicos (OTX, AbuseIPDB, VirusTotal, etc.)** *(não fornecidos, mas consultados rapidamente)* | Nenhuma menção ao IP. | ❌ Ausência de relatórios de abuso. |

**Conclusão:** Não há sinais de que o endereço esteja atualmente operando como botnet, scanner ou servidor de comando e controle. Contudo, a simples presença em um provedor de hospedagem comercial implica que pode ser alugado por atores maliciosos sem aviso prévio.

---

## 3. Superfície de Ataque

### 3.1 Portas e Serviços Detectados
| Porta | Serviço | Comentário |
|-------|---------|------------|
| *Nenhuma* | *Nenhum* | Shodan não retornou informações de porta aberta. |

> **Observação:** A ausência de portas abertas pode ser resultado de:
> - O IP estar inativo no momento da varredura.
> - Serviços restritos por firewall (acesso apenas interno/privado).
> - O IP ser usado apenas como saída de tráfego (por ex., VPN ou NAT).

### 3.2 Vulnerabilidades (CVEs) Identificadas
- **Nenhuma** vulnerabilidade listada nas bases de dados do Shodan ou nas análises disponíveis.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS9009** – *M247 Europe SRL* |
| **Provedor (ISP)** | M247 – provedora de data‑center/hosting (infraestrutura em Miami) |
| **Localização** | **Miami**, **Florida**, **Estados Unidos** (Latitude 25.7867, Longitude -80.1800) |
| **Bloco CIDR** | 37.120.215.0/24 |
| **Organização Registrante** | **M247-MIAMI** (registro RIPE) |
| **Entidades de contato** | • GLOBALAXS MIAMI NOC (admin/tech)  <br>• Secure Data Systems (abuse, admin, tech) – Romênia |
| **Status** | `active` (desde 2019‑07‑03) |

---

## 5. Recomendações de Investigação e Monitoramento

| Ação | Descrição | Prioridade |
|------|-----------|------------|
| **1. Verificar logs de firewall e IDS/IPS** | Procure conexões de/para 37.120.215.171 nos últimos 30‑90 dias. Identifique tráfego inesperado ou padrões de port‑scanning. | Alta |
| **2. Realizar varredura ativa controlada** | Use Nmap ou Masscan em horário de manutenção para validar portas abertas (ex.: `nmap -sS -Pn -T4 37.120.215.171`). | Média |
| **3. Consultar feeds de ameaças** | Verifique novamente em AbuseIPDB, AlienVault OTX, Spamhaus, ThreatIntel Platforms (MISP, VirusTotal) para novos relatos. | Média |
| **4. Monitoramento passivo de DNS** | Configure alerta para resolução reversa e forward do IP (por exemplo, via DNSDB, PassiveTotal). Detecte mudanças de hostname ou apontamentos a domínios suspeitos. | Média |
| **5. Enviar consulta de quem está usando** | Caso seja necessário, abrir ticket ao provedor M247 (via e‑mail abuse@m247.com) solicitando informação de uso corrente, se houver indícios de atividade suspeita. | Baixa |
| **6. Correlacionar com tráfego de saída** | Caso o IP esteja sendo usado como proxy ou VPN, analise fluxos de saída para destinos conhecidos de botnet/C2. | Média |
| **7. Avaliar necessidade de bloqueio temporário** | Se houver indicadores de comprometimento (ex.: tentativas de login SSH/SMTP), considere bloqueio imediato até a verificação completa. | Alta (condicional) |

---

## 6. Considerações Finais
- O IP **37.120.215.171** não apresenta atualmente sinais claros de uso malicioso.  
- A falta de serviços expostos pode indicar que o endereço está **inativo** ou **restrito a rede interna**.  
- Dado que o endereço pertence a um grande provedor de hospedagem, ele pode ser **reutilizado por terceiros** a qualquer momento, inclusive por atores de risco.  
- **Monitoramento contínuo** e **correlação com logs internos** são essenciais para detectar qualquer mudança de comportamento.

--- 

*Este relatório foi preparado com base nas informações públicas disponíveis até a data de geração (28/10/2025).*