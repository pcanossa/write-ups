# Relatório de Threat Intelligence – Domínio **legalizarcpfonline.com**

> **Fonte dos dados**: WHOIS.com, urlscan.io, VirusTotal.  
> **Última coleta VirusTotal**: 18 de ago 2025 (timestamp 1760765957).  

---

## 1. Resumo Executivo
O domínio **legalizarcpfonline.com** foi registrado há poucos dias (19 ago 2025) através da GoDaddy e está apontado para o endereço IP **216.238.108.222**, pertencente à infraestrutura da **Vultr (AS20473 – US)**. O servidor responde com Apache 2.4.58 (Ubuntu) e apresenta um certificado Let’s Encrypt válido até 17 nov 2025. As análises do VirusTotal não detectaram componentes maliciosos (0 malicious, 0 suspicious, 34 undetected, 61 harmless). Contudo, o título da página exibida pelos scans indica um blog de cafés, que não tem relação com o nome do domínio (que sugere serviços de “legalização de CPF”). O scan do urlscan.io marcou o domínio como **suspect**. A combinação de registro recente, hospedagem em VPS de baixo custo, conteúdo aparentemente genérico e a nomenclatura potencialmente enganosa levanta suspeitas de uso para phishing ou outras fraudes direcionadas ao público brasileiro.

---

## 2. Análise de Comportamento
| Indicador | Evidência | Interpretação |
|-----------|-----------|----------------|
| **Data de registro** | 19 /08/2025 | Domínio recém‑criado, prática comum em campanhas de phishing/ scams. |
| **Infraestrutura** | IP 216.238.108.222 (Vultr, AS20473) | VPS de baixo custo, frequentemente utilizada por atores maliciosos por facilidade de criação e anonimato. |
| **Serviço web** | Apache 2.4.58 (Ubuntu) | Nenhum indício direto de compromise, porém padrão em servidores de teste/temporários. |
| **Conteúdo da página** | Título “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés” | Conteúdo irrelevante ao nome do domínio, típico de sites “parked” ou de *domain‑parking* que depois podem ser trocados por páginas de phishing. |
| **Tag “suspect”** (urlscan.io) | O scan HTTP / HTTPS recebeu a marcação “suspect”. | Indica que a comunidade de análise automática considerou o domínio suspeito, possivelmente por heurísticas de domínio recém‑criado + IP associado a atividade de abuso. |
| **Análises do VirusTotal** | 0 malicious, 0 suspicious, maioria “harmless”/“undetected”. | Ainda não há artefatos maliciosos conhecidos, mas a ausência de deteção não elimina risco – pode ser “zero‑day” ou ainda não catalogado. |
| **Certificado TLS** | Let’s Encrypt, validade 89 dias (expira 17 nov 2025) | Certificado legítimo, porém a disponibilidade de TLS não exclui uso malicioso; serve para dar aparência de legitimidade. |
| **Geolocalização** | País: Brasil (BR) – apontado pelos scans | Alvo provável de usuários brasileiros (CPF). |

**Conclusão comportamental:** Não há evidência de distribuição de malware ou de C2, mas o domínio apresenta os típicos *indícios de infraestrutura de phishing* (registro recente, VPS barato, conteúdo genérico, nomenclatura enganosas).  

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20473 – VULTR, US** |
| **Provedor (ISP)** | **Vultr, LLC** (provedor de cloud/VPS) |
| **IP associado** | **216.238.108.222** |
| **Localização** | **Brasil (BR)** – cidade não especificada; PTR → `216.238.108.222.vultrusercontent.com` |
| **Nome do host (PTR)** | `216.238.108.222.vultrusercontent.com` |
| **Servidor HTTP** | Apache/2.4.58 (Ubuntu) |
| **Portas abertas** | (informação não fornecida – requer varredura adicional) |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio apex** | `legalizarcpfonline.com` | Registrado 19 /08/2025 |
| **Subdomínio escaneado** | `www.legalizarcpfonline.com` | Resolvem ao mesmo IP |
| **IP** | `216.238.108.222` | Único endereço A record |
| **Nameservers** | `ns19.domaincontrol.com` / `ns20.domaincontrol.com` (GoDaddy) | Não apontam para servidores diferentes – controle de DNS ainda na GoDaddy. |
| **Domínios correlatos** | Nenhum encontrado em fontes públicas (não há relações explícitas com outros domínios). |

---

## 5. Recomendações de Investigação (Próximos Passos)
1. **Análise de conteúdo dinâmico**  
   - Executar um **crawl** completo da página (incluindo recursos JavaScript) para verificar scripts ocultos, redirecionamentos ou solicitações a destinos externos suspeitos.  
   - Verificar se há formulários de coleta de dados (CPF, dados bancários) que poderiam indicar phishing.

2. **Verificação em feeds de phishing e abuso**  
   - Consultar bancos de dados como PhishTank, APWG, OpenPhish, URLhaus, AbuseIPDB e o *Threat Intelligence Platform* da organização para buscar o domínio ou o IP `216.238.108.222`.  
   - Adicionar o domínio e o IP a um **watchlist** interno para monitoramento de futuras detecções.

3. **Varredura de portas e serviços**  
   - Realizar um **port scan** (ex.: nmap) no IP para identificar serviços adicionais (ex.: SSH, RDP, SMTP) que podem ser usados como vetor de ataque ou para exfiltração.

4. **Análise de certificados e revogação**  
   - Verificar a **revogação** do certificado Let’s Encrypt (CRL/OCSP). Caso seja revogado, pode indicar comprometimento.  

5. **Contatar o provedor**  
   - Caso haja indícios de uso malicioso, abrir um **ticket de abuso** junto à Vultr (abuse@vultr.com) e à GoDaddy (abuse@godaddy.com), fornecendo os detalhes dos scans e a marcação “suspect”.

6. **Monitoramento de DNS**  
   - Configurar alertas de **alteração de DNS** (ex.: mudança de registro A, adição de novos subdomínios). Mudanças repentinas podem indicar preparo para ataques.

7. **Correlacionar logs internos**  
   - Caso sua organização já tenha tráfego para esse domínio, analisar logs de firewall, proxy e IDS/IPS para detectar possíveis **tentativas de exfiltração** ou **login** a serviços externos.

8. **Inteligência adicional**  
   - Buscar a **impressão digital JARM** (`27d40d40d00040d00042d43d0000003d25bc6207ca8acd9652e99aa3724a08`) em repositórios de JARM para detectar se o mesmo fingerprint aparece em outros sites suspeitos.

---

## 6. Considerações Finais
Embora as plataformas de análise de malware ainda não classifiquem o domínio como malicioso, o conjunto de sinais (registro recente, uso de VPS barato, conteúdo não correspondente ao nome, marcação “suspect” e foco potencial no público brasileiro) indica **alto risco de uso para phishing ou scam**. A prudência recomenda monitoramento contínuo, inspeção de tráfego e, se necessário, bloqueio preventivo nas políticas de segurança da organização até que a intenção exata do domínio seja confirmada.