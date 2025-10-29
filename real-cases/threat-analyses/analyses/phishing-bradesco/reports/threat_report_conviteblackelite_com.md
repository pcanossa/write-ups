# Relatório de Threat Intelligence – Domínio **conviteblackelite.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 30 / 09 / 2025 (Unix timestamp 1759334610).  



## 1. Resumo Executivo
O domínio **conviteblackelite.com** foi registrado em **28 / 09 / 2025** por meio da GoDaddy, utilizando o serviço de privacidade *Domains By Proxy, LLC*. O domínio está apontado para o IP **191.252.227.30**, que pertence ao **ASN AS27715 – Locaweb Serviços de Internet SA (Brasil)** e resolve um site em Português que aparenta ser um blog de cafés (“Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”).  

A análise do VirusTotal indica **nenhuma detecção maliciosa** (0 malicious, 0 suspicious) e a maioria dos scanners classifica o domínio como **harmless** ou **undetected**. O certificado TLS foi emitido pela **Let’s Encrypt (R13)** e está válido por 89 dias. Não foram encontrados indicadores de comprometimento, C2, phishing ou distribuição de malware. O domínio possui poucos dias de existência e ainda não acumulou reputação suficiente para aparecer em listas de bloqueio públicas.

## 2. Análise de Comportamento
| Fonte | Indicador | Avaliação |
|-------|-----------|-----------|
| **URLScan.io** (2 submissões) | - Servidor Apache 2.4.52 (Ubuntu) <br> - País de origem BR <br> - 28 / 09 / 2025 – TLS válido por 89 dias | O servidor parece estar configurado corretamente e não há evidência de redirecionamentos maliciosos ou payloads. |
| **VirusTotal** | - 0 malicious, 0 suspicious, 61 harmless, 34 undetected <br> - Nenhum motor reportou phishing, C2 ou malware | O domínio não está presente em bases de dados de ameaças conhecidas. |
| **WHOIS** | - Registrado com privacidade <br> - Status: *client delete/renew/transfer/update prohibited* (configuração comum em domínios recém‑registrados) | Não indica atividade suspeita, apenas política de proteção do registrante. |
| **Certificado TLS** | - Emissor: Let’s Encrypt (R13) <br> - Valido de 28 /09 /2025 a 27 /12 /2025 | Certificado legítimo, padrão para sites novos. |
| **Conteúdo** | - Título: “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés” <br> - Texto em português, nenhuma página de login suspeita ou scripts de redirecionamento | O conteúdo parece legítimo (blog de café). Não há indícios de phishing ou entrega de malware. |

**Conclusão**: Não há indícios de que o domínio esteja sendo usado para atividades maliciosas (botnet, C2, phishing ou distribuição de malware). O tráfego observado está limitado a poucos IPs (3 uniq IPs) e dois países (Brasil e outro ainda não identificado), típico de um site recém‑lançado.

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS27715 – Locaweb Serviços de Internet SA** |
| **ISP / Provedor** | **Locaweb Serviços de Internet SA** (Brasil) |
| **IP** | **191.252.227.30** |
| **País** | **Brasil (BR)** |
| **Cidade / Região** | Não especificado (IP associado ao Brasil, provável São Paulo) |
| **Servidor Web** | Apache/2.4.52 (Ubuntu) |
| **Certificado TLS** | Let’s Encrypt (R13) – validade até 27 / 12 / 2025 |
| **Nome dos Nameservers** | ns77.domaincontrol.com, ns78.domaincontrol.com (GoDaddy) |
| **Data de Criação do Domínio** | 28 / 09 / 2025 |
| **Data de Expiração** | 28 / 09 / 2026 |
| **Status WHOIS** | client delete prohibited, client renew prohibited, client transfer prohibited, client update prohibited |

## 4. Domínios e IPs Relacionados
| Tipo | Valor |
|------|-------|
| **Domínio analisado** | conviteblackelite.com |
| **Nameservers** | ns77.domaincontrol.com, ns78.domaincontrol.com |
| **IP principal** | 191.252.227.30 (AS27715 – Locaweb) |
| **Domínios associados ao registrador / privacidade** | domainsbyproxy.com (serviço de privacidade), godaddy.com (registrar) |
| **Domínios “related” exibidos na página WHOIS** | verisign.com, godaddy.com, domaincontrol.com, icann.org, domainsbyproxy.com |
| **Outros IPs observados nas duas capturas do URLScan** | (não listados explicitamente, mas o relatório indica 3 IP s únicos – possivelmente endereços de CDN ou de resolução DNS) |

## 5. Recomendações (Próximos Passos de Investigação)

1. **Monitoramento Passivo DNS**  
   - Adicionar `conviteblackelite.com` a um feed de monitoramento de DNS (e.g., PassiveTotal, DNSDB) para detectar mudanças de IP, adição de novos registros (MX, TXT, CNAME) ou migração de provedor.

2. **Análise de Tráfego de Rede**  
   - Correlacionar logs de firewall/IDS com o IP 191.252.227.30 para identificar eventuais conexões incomuns (p.ex., conexões outbound em portas não‑padrão ou volume de requisições fora do padrão de um blog).

3. **Consulta a Feeds de Inteligência**  
   - Verificar o IP e o domínio em fontes como AbuseIPDB, AlienVault OTX, ThreatCrowd e VirusShare para confirmar que não haja relatos posteriores.

4. **Revalidação de Certificado TLS**  
   - Monitorar a renovação do certificado Let’s Encrypt (a cada 90 dias) para garantir que não seja substituído por um certificado auto‑assinado ou de baixa reputação.

5. **Verificação de Conteúdo Web**  
   - Realizar varredura periódica (e.g., URLhaus, Hybrid Analysis) dos recursos carregados pelo site (JS, imagens) para garantir que não sejam inseridos scripts maliciosos em atualizações futuras.

6. **Análise de Reputation de ASN**  
   - Revisar o histórico de **AS27715** em bases como **RiskIQ** ou **BGPKIT** para detectar se o ASN já esteve associado a campanhas de phishing ou botnets. Caso haja incidentes recentes, estabelecer alertas para novos domínios hospedados neste ASN.

7. **Alertas de WHOIS**  
   - Configurar notificações de alterações no registro WHOIS (por exemplo, mudança de contato, remoção da proteção de privacidade) que possam indicar venda ou mudança de propósito.

## 6. Conclusão
Com base nas evidências coletadas (WHOIS, URLScan.io e VirusTotal), **conviteblackelite.com** não apresenta indicadores de atividade maliciosa. O domínio está recém‑registrado, aponta para um IP brasileiro pertencente a um ISP reputado (Locaweb), e o site parece ser um blog de cafés legítimo. Não há detecções em bases de dados de ameaças conhecidas.  

Recomenda‑se manter vigilância de mudanças nos registros DNS, monitorar logs de rede e atualizar periodicamente a análise de reputação, especialmente caso o domínio mude de IP ou comece a servir conteúdo diferente do atualmente observado.  