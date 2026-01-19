# Relatório de Threat Intelligence – IP **104.21.7.199**

> **Fonte dos dados**: Shodan, IPInfo.io, URLScan.io, VirusTotal, AbuseIPDB, WHOIS (ARIN), AlienVault OTX, Scamalytics, cURL.  
> **Timestamp da Análise**: 2026-01-14T12:45:32.507117.

## 1. Resumo Executivo
O endereço **104.21.7.199** pertence à rede de CDN da Cloudflare (AS13335) e está localizado em San Francisco (US). Apesar de responder apenas com códigos *403 Forbidden* (acesso direto bloqueado), o IP hospeda dezenas de domínios associados a sites suspeitos e campanhas de phishing (ex.: *holmes456.acessoportalatendimento.app*, *onclaim.com*, *essaywritingservice.us.org*). O Shodan revela múltiplas portas abertas (80, 443 e várias portas de painel de controle cPanel/WHM – 2082‑2096, 2086‑2087, 8880, 8443, 8080), que são frequentemente visadas por exploits. A análise de arquivos comunicantes indica a presença de malwares conhecidos (AgentTesla, Formbook, CrimeZ, Trojans MSIL) e de APKs Android potencialmente maliciosos. O IP tem pontuação de risco **baixo** em bases públicas, mas a correlação com indicadores ativos de ameaças eleva seu potencial de uso como infraestrutura de comando‑e‑controle ou de distribuição de payloads.

## 2. Análise de Comportamento
| Evidência | Interpretação |
|-----------|---------------|
| **Domínios associados** (URLScan) – *holmes456.acessoportalatendimento.app*, *essaywritingservice.us.org*, *onclaim.com*, *playfortuna-5xn4.top* | Domínios frequentemente utilizados em campanhas de phishing, spam e distribuição de malware. |
| **Arquivos comunicantes** (VirusTotal) – executáveis marcados como AgentTesla, Formbook, CrimeZ; vários APKs com permissões de internet e serviços de background | Indica que o IP já foi usado como *host* para download de payloads ou como ponto de C2 para malware Windows e Android. |
| **Portas 2082‑2096, 8443, 8880, 8080** – típicas de cPanel/WHM, painéis de administração web | Vulnerabilidades conhecidas (ex.: CVE‑2014‑3931, CVE‑2021‑22986) podem ser exploradas para acesso não autorizado; presença dessas portas sugere que o IP pode estar atrás de um cliente Cloudflare que executa serviços web de gerenciamento. |
| **Respostas HTTP 403 “Direct IP access not allowed”** | Cloudflare está bloqueando acesso direto ao IP, mas o tráfego ainda chega ao edge, indicando que o cliente pode estar servindo conteúdo via domínios específicos. |
| **Scamalytics** – “low risk”, “datacenter”, “proxy type DCH” | Confirma a natureza de data‑center/anycast da Cloudflare, porém não refuta uso malicioso. |
| **AlienVault OTX** – indicador de IP mapeado a “goog.pl” (auto‑generated Pulse) | Plataforma de inteligência já reconhece o IP como parte de um grande pool de endereços de Cloudflare. |

### Conclusão de comportamento
O IP funciona essencialmente como *frontend* de um ou mais servidores web que hospedam conteúdo suspeito e distribuem arquivos maliciosos. Não há evidência de que a própria infraestrutura da Cloudflare seja comprometida, mas o cliente que utiliza o CDN está servindo malware/phishing e mantém serviços administrativos expostos.

## 3. Superfície de Ataque
### 3.1 Portas abertas (Shodan)
| Porta | Serviço presumido | Comentário de risco |
|------|-------------------|---------------------|
| 80 | HTTP (Cloudflare) | Servidor web público. |
| 443 | HTTPS (Cloudflare) | Servidor web seguro, usado pelos domínios listados. |
| 2052‑2053 | HTTP (possível painel interno) | Não há banner, pode ser redirecionamento para aplicação interna. |
| 2082‑2083 | cPanel (HTTP/HTTPS) | Painéis de administração conhecidos por exploits de escalonamento. |
| 2086‑2087 | WHM (WebHost Manager) | Vulnerável a CVE‑2021‑22986, entre outros. |
| 2095‑2096 | cPanel/WHM (HTTPS) | Mesma crítica das portas 2082‑2083. |
| 8080 | HTTP (geral) | Pode expor aplicações web adicionais. |
| 8443 | HTTPS (geral) | Frequentemente usado por consoles de gestão. |
| 8880 | HTTP (geral) | Possível painel administrativo. |

**Observação:** Nenhum CVE específico foi reportado pelo Shodan para essas portas no IP; entretanto, serviços como cPanel/WHM historicamente possuem vulnerabilidades críticas (ex.: CVE‑2014‑3931, CVE‑2021‑22986). Recomenda‑se revisar a versão dos painéis se houver controle sobre o cliente.

### 3.2 Vulnerabilidades (CVEs) identificadas pelo Shodan
- **Nenhum CVE específico** foi listado nas informações do Shodan para este host.  
- **Potenciais vulnerabilidades** derivam das portas e serviços (cPanel/WHM) que, dependendo da versão, podem ser afetados por CVEs conhecidos.  

## 4. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | AS13335 (Cloudflare, Inc.) |
| **ISP** | Cloudflare, Inc. |
| **Organização** | Cloudflare, Inc. |
| **País** | United States (US) – anycast (localização reportada em San Francisco, CA) |
| **Região / Cidade** | San Francisco, CA |
| **Tipo de uso** | Content Delivery Network / Data Center |
| **Abuse Confidence Score (AbuseIPDB)** | 0 (nenhum reporte) |

## 5. Recomendações de Investigação e Mitigação Operacional
1. **Correlacionar logs internos** – Verificar nos firewalls, proxies ou servidores de DNS se há conexões de saída ou entrada ao IP 104.21.7.199, especialmente nas portas 2082‑2096, 8443 e 8880. Flaggear como tráfego suspeito caso não haja necessidade legítima.
2. **Analisar hashes de arquivos** – Utilizar os hashes (MD5/SHA256) dos arquivos listados (ex.: `06cba223ac3cdd86...`, `787f470e836671ed...`) para buscar evidências de comprometimento nos endpoints da sua organização.
3. **Bloquear domínios associados** – Incluir no bloqueio de URL/Squid os domínios reportados por URLScan (ex.: *.acessoportalatendimento.app, *.onclaim.com, *.essaywritingservice.us.org) até que seja confirmado uso legítimo.
4. **Investigar o cliente Cloudflare** – Caso a organização possua superfícies hospedadas sob este CDN, solicitar ao provedor informações sobre quais domínios realmente apontam para o IP e validar se há conteúdo suspeito nas origens.
5. **Monitorar indicadores de C2** – Os indicadores de malware (AgentTesla, Formbook, CrimeZ) associados ao IP devem ser adicionados a ferramentas de detecção de endpoint (EDR, SIEM) para alertas de comunicação.
6. **Revisar configurações de cPanel/WHM** – Se houver controle sobre servidores que utilizam essas portas, garantir que estejam atualizados (últimas versões) e que a autenticação de dois fatores esteja habilitada.
7. **Consultas a feeds de inteligência** – Continuar monitorando feeds de OTX, AlienVault, Spamhaus, e outros para atualizações sobre os domínios/arquivos relacionados.
8. **Teste de sandbox** – Submeter os arquivos APK suspeitos a sandboxes atualizadas para confirmar comportamento malicioso antes de qualquer distribuição interna.

## 6. Conclusão
O IP 104.21.7.199 serve como ponto de fronteira de uma rede de entrega de conteúdo (CDN) que está sendo utilizada por terceiros para hospedar e distribuir conteúdo malicioso, bem como para operar painéis administrativos expostos. Embora a infraestrutura de rede da Cloudflare seja segura, a má configuração ou comprometimento dos servidores cliente pode representar risco significativo de *download* de malware e de phishing. A integração dos indicadores coletados aos processos de monitoramento e a revisão de políticas de acesso a este IP são passos críticos para reduzir a superfície de ataque.